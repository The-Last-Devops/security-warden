// Package mcp serves Security Warden to AI agents over the Model Context
// Protocol: JSON-RPC 2.0, one message per line on stdin/stdout. Only
// protocol messages go to stdout; logs go to the log writer (stderr).
//
// The server is dual-era: it answers the legacy initialize handshake
// (2025-11-25 and earlier) and modern requests that carry their protocol
// version in _meta (2026-07-28, with server/discover).
package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
)

// Protocol versions. Modern requests name theirs in _meta on every request;
// legacy clients pick one in initialize.
const (
	ModernVersion = "2026-07-28"
	LegacyVersion = "2025-11-25"
)

var legacyVersions = []string{LegacyVersion, "2025-06-18", "2025-03-26", "2024-11-05"}

// SupportedVersions lists every protocol version the server speaks.
func SupportedVersions() []string { return append([]string{ModernVersion}, legacyVersions...) }

const (
	metaVersion    = "io.modelcontextprotocol/protocolVersion"
	metaClientCaps = "io.modelcontextprotocol/clientCapabilities"
	metaServerInfo = "io.modelcontextprotocol/serverInfo"
)

// JSON-RPC and MCP error codes.
const (
	codeParse          = -32700
	codeInvalidRequest = -32600
	codeNoMethod       = -32601
	codeInvalidParams  = -32602
	codeInternal       = -32603
	codeBadVersion     = -32022
)

// maxLine bounds one incoming message.
const maxLine = 4 << 20

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func (e *rpcError) Error() string { return e.Message }

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// Serve reads requests from in and writes responses to out until in ends
// or ctx is done. Requests run concurrently; responses are written whole,
// one per line.
func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		wmu      sync.Mutex
		wg       sync.WaitGroup
		inflight sync.Map // id string -> context.CancelFunc
	)
	write := func(r response) {
		r.JSONRPC = "2.0"
		b, err := json.Marshal(r)
		if err != nil {
			b, _ = json.Marshal(response{JSONRPC: "2.0", ID: r.ID, Error: &rpcError{Code: codeInternal, Message: "cannot encode result"}})
		}
		wmu.Lock()
		defer wmu.Unlock()
		_, _ = out.Write(append(b, '\n'))
	}
	rd := bufio.NewReaderSize(in, 64<<10)
	for {
		line, err := readLine(rd)
		if errors.Is(err, errTooLong) {
			write(response{ID: json.RawMessage("null"), Error: &rpcError{Code: codeInvalidRequest, Message: "message too large"}})
			continue
		}
		if len(bytes.TrimSpace(line)) > 0 {
			s.dispatch(ctx, line, write, &wg, &inflight)
		}
		if err != nil {
			break
		}
		if ctx.Err() != nil {
			break
		}
	}
	wg.Wait()
	return nil
}

var errTooLong = errors.New("line too long")

// readLine returns one line without its newline; errTooLong after
// discarding a line longer than maxLine.
func readLine(r *bufio.Reader) ([]byte, error) {
	var buf []byte
	tooLong := false
	for {
		chunk, err := r.ReadSlice('\n')
		if !tooLong {
			if len(buf)+len(chunk) > maxLine {
				tooLong, buf = true, nil
			} else {
				buf = append(buf, chunk...)
			}
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if tooLong {
			if err != nil {
				return nil, err
			}
			return nil, errTooLong
		}
		return bytes.TrimRight(buf, "\r\n"), err
	}
}

func (s *Server) dispatch(ctx context.Context, line []byte, write func(response), wg *sync.WaitGroup, inflight *sync.Map) {
	trimmed := bytes.TrimSpace(line)
	if trimmed[0] == '[' {
		// Batches were removed from MCP in 2025-06-18.
		write(response{ID: json.RawMessage("null"), Error: &rpcError{Code: codeInvalidRequest, Message: "batches are not supported"}})
		return
	}
	var req request
	if err := json.Unmarshal(trimmed, &req); err != nil {
		write(response{ID: json.RawMessage("null"), Error: &rpcError{Code: codeParse, Message: "parse error"}})
		return
	}
	isNotification := len(req.ID) == 0
	if !isNotification && !validID(req.ID) {
		write(response{ID: json.RawMessage("null"), Error: &rpcError{Code: codeInvalidRequest, Message: "id must be a string or an integer"}})
		return
	}
	if req.JSONRPC != "2.0" || req.Method == "" {
		if !isNotification {
			write(response{ID: req.ID, Error: &rpcError{Code: codeInvalidRequest, Message: "invalid request"}})
		}
		return
	}
	if isNotification {
		s.notification(req, inflight)
		return
	}
	rctx, cancel := context.WithCancel(ctx)
	key := string(req.ID)
	inflight.Store(key, cancel)
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		defer inflight.Delete(key)
		res, rerr := s.handle(rctx, req)
		if rctx.Err() != nil && ctx.Err() == nil {
			return // cancelled by the client: no response
		}
		if rerr != nil {
			write(response{ID: req.ID, Error: rerr})
			return
		}
		write(response{ID: req.ID, Result: res})
	}()
}

func validID(id json.RawMessage) bool {
	var v any
	if json.Unmarshal(id, &v) != nil {
		return false
	}
	switch x := v.(type) {
	case string:
		return true
	case float64:
		return x == float64(int64(x))
	}
	return false
}

func (s *Server) notification(req request, inflight *sync.Map) {
	switch req.Method {
	case "notifications/cancelled":
		var p struct {
			RequestID json.RawMessage `json:"requestId"`
		}
		if json.Unmarshal(req.Params, &p) == nil && len(p.RequestID) > 0 {
			if c, ok := inflight.Load(string(p.RequestID)); ok {
				c.(context.CancelFunc)()
			}
		}
	case "notifications/initialized":
	default:
		s.logf("ignoring notification %s", req.Method)
	}
}

// handle answers one request. A result is a JSON object; every result says
// resultType "complete" and names the server in _meta (modern clients read
// them, legacy clients ignore them).
func (s *Server) handle(ctx context.Context, req request) (map[string]any, *rpcError) {
	var params map[string]json.RawMessage
	if len(req.Params) > 0 && string(req.Params) != "null" {
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return nil, &rpcError{Code: codeInvalidParams, Message: "params must be an object"}
		}
	}
	if req.Method != "initialize" {
		if err := checkMeta(params); err != nil {
			return nil, err
		}
	}
	var res map[string]any
	var rerr *rpcError
	switch req.Method {
	case "initialize":
		res = s.initialize(params)
	case "server/discover":
		res = map[string]any{
			"supportedVersions": SupportedVersions(),
			"capabilities":      s.capabilities(),
			"instructions":      instructions(s.cfg.AllowChanges),
		}
	case "ping":
		res = map[string]any{}
	case "tools/list":
		res = map[string]any{"tools": s.toolList()}
	case "tools/call":
		res, rerr = s.callTool(ctx, params)
	default:
		return nil, &rpcError{Code: codeNoMethod, Message: "method not found: " + clip(req.Method, 80)}
	}
	if rerr != nil {
		return nil, rerr
	}
	res["resultType"] = "complete"
	res["_meta"] = map[string]any{metaServerInfo: s.serverInfo()}
	return res, nil
}

// checkMeta validates the per-request fields of modern requests. Requests
// without a protocol version are legacy and served as such.
func checkMeta(params map[string]json.RawMessage) *rpcError {
	raw, ok := params["_meta"]
	if !ok {
		return nil
	}
	var meta map[string]json.RawMessage
	if json.Unmarshal(raw, &meta) != nil {
		return &rpcError{Code: codeInvalidParams, Message: "_meta must be an object"}
	}
	vraw, ok := meta[metaVersion]
	if !ok {
		return nil
	}
	var v string
	if json.Unmarshal(vraw, &v) != nil || v != ModernVersion {
		return &rpcError{Code: codeBadVersion, Message: "Unsupported protocol version",
			Data: map[string]any{"supported": SupportedVersions(), "requested": v}}
	}
	if _, ok := meta[metaClientCaps]; !ok {
		return &rpcError{Code: codeInvalidParams, Message: "missing _meta " + metaClientCaps}
	}
	return nil
}

func (s *Server) initialize(params map[string]json.RawMessage) map[string]any {
	var want string
	_ = json.Unmarshal(params["protocolVersion"], &want)
	version := LegacyVersion
	for _, v := range legacyVersions {
		if v == want {
			version = v
		}
	}
	return map[string]any{
		"protocolVersion": version,
		"capabilities":    s.capabilities(),
		"serverInfo":      s.serverInfo(),
		"instructions":    instructions(s.cfg.AllowChanges),
	}
}

func (s *Server) capabilities() map[string]any {
	return map[string]any{"tools": map[string]any{"listChanged": false}}
}

func (s *Server) serverInfo() map[string]any {
	return map[string]any{"name": "security-warden", "title": "Security Warden", "version": s.cfg.Version}
}

func instructions(changes bool) string {
	s := "Security Warden checks this machine and the code folders for security problems. " +
		"Scanning is safe: it only reads, needs no admin rights and sends nothing off the machine; run scan first, then get_fix for the problems to explain. " +
		"Never change anything without the user's explicit approval. " +
		"For leaked keys and tokens, tell the user to revoke or rotate the credential first: cleaning up files or Git history alone does not make a leaked secret safe."
	if changes {
		s += " Changing tools (apply_fix, undo_fix, hide, restore) are enabled: describe exactly what will change and wait for the user's yes before calling them."
	} else {
		s += " This server is read-only; to apply fixes the user runs `security-warden fix` themselves (or starts the server with --allow-changes)."
	}
	return s
}

func (s *Server) logf(format string, a ...any) {
	if s.cfg.Log != nil {
		fmt.Fprintf(s.cfg.Log, "security-warden mcp: "+format+"\n", a...)
	}
}

func clip(s string, n int) string {
	s = strings.ToValidUTF8(s, "")
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
