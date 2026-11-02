package vulndb

import (
	"archive/zip"
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// BaseURL is OSV's public bucket (https://google.github.io/osv.dev/data/).
// A variable so tests can point it at a local server.
var BaseURL = "https://osv-vulnerabilities.storage.googleapis.com/"

const (
	maxZipBytes    = 1 << 30  // all.zip of npm is ~220 MB, mostly malicious-package reports we skip
	maxRecordBytes = 8 << 20  // one advisory
	maxCSVBytes    = 64 << 20 // modified_id.csv; we stop reading early anyway
	maxIncremental = 2000     // more changed records than this: fetch the archive again
	fullEvery      = 30 * 24 * time.Hour
	userAgent      = "security-warden-vulndb"
)

var client = &http.Client{
	Transport: &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ResponseHeaderTimeout: 30 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
	},
	// Stay on HTTPS: a redirect elsewhere is refused.
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" || len(via) > 3 {
			return errors.New("refusing redirect")
		}
		return nil
	},
}

func get(ctx context.Context, rel string) (*http.Response, error) {
	u := BaseURL + rel
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, err
	}
	// Only a fixed User-Agent: no cookies, no machine details.
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s: %s", u, resp.Status)
	}
	return resp, nil
}

// Result tells what one update of one ecosystem did.
type Result struct {
	Ecosystem string
	Full      bool  // the whole archive was downloaded
	Changed   int   // records added, replaced or removed
	Vulns     int   // records in the index afterwards
	Bytes     int64 // index size on disk
	Err       error
}

// Update refreshes the index of one ecosystem: incrementally from
// modified_id.csv when an index exists, else from the full archive.
func Update(ctx context.Context, eco string) Result {
	res := Result{Ecosystem: eco}
	ix, err := readIndex(indexPath(eco))
	if err != nil || ix.Ecosystem != eco || time.Since(ix.FullAt) > fullEvery {
		ix, err = full(ctx, eco)
		res.Full = true
		if ix != nil {
			res.Changed = len(ix.Vulns)
		}
	} else {
		var n int
		n, err = incremental(ctx, ix)
		if errors.Is(err, errTooMany) {
			ix, err = full(ctx, eco)
			res.Full = true
			if ix != nil {
				n = len(ix.Vulns)
			}
		}
		res.Changed = n
	}
	if err != nil {
		res.Err = err
		return res
	}
	res.Vulns = len(ix.Vulns)
	res.Bytes, res.Err = writeIndex(ix)
	return res
}

var errTooMany = errors.New("too many changes")

// incremental reads modified_id.csv (newest first) only down to what the
// index already has, and fetches each changed record.
func incremental(ctx context.Context, ix *Index) (int, error) {
	resp, err := get(ctx, url.PathEscape(ix.Ecosystem)+"/modified_id.csv")
	if err != nil {
		return 0, err
	}
	type change struct {
		id string
		at time.Time
	}
	var changes []change
	newest := ix.Updated
	sc := bufio.NewScanner(io.LimitReader(resp.Body, maxCSVBytes))
	for sc.Scan() {
		ts, id, ok := strings.Cut(strings.TrimSpace(sc.Text()), ",")
		if !ok {
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			continue
		}
		if !at.After(ix.Updated) {
			break // sorted newest first: the rest is already in the index
		}
		if at.After(newest) {
			newest = at
		}
		if strings.HasPrefix(id, "MAL-") || !safeID(id) {
			continue
		}
		changes = append(changes, change{id, at})
		if len(changes) > maxIncremental {
			resp.Body.Close()
			return 0, errTooMany
		}
	}
	resp.Body.Close()
	if err := sc.Err(); err != nil {
		return 0, err
	}
	for _, c := range changes {
		r, err := get(ctx, url.PathEscape(ix.Ecosystem)+"/"+url.PathEscape(c.id)+".json")
		if err != nil {
			return 0, err
		}
		b, err := io.ReadAll(io.LimitReader(r.Body, maxRecordBytes+1))
		r.Body.Close()
		if err != nil {
			return 0, err
		}
		if len(b) > maxRecordBytes {
			continue
		}
		v, _, err := convert(ix.Ecosystem, b)
		if err != nil {
			continue
		}
		if v == nil {
			delete(ix.Vulns, c.id) // withdrawn, or no longer about this ecosystem
		} else {
			ix.Vulns[c.id] = v
		}
	}
	ix.Updated = newest
	return len(changes), nil
}

func safeID(id string) bool {
	if id == "" || len(id) > 100 {
		return false
	}
	for _, r := range id {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}

// full downloads <eco>/all.zip to a temporary file and indexes it.
func full(ctx context.Context, eco string) (*Index, error) {
	resp, err := get(ctx, url.PathEscape(eco)+"/all.zip")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.ContentLength > maxZipBytes {
		return nil, fmt.Errorf("%s/all.zip is %d bytes, over the %d limit", eco, resp.ContentLength, maxZipBytes)
	}
	if err := os.MkdirAll(Dir(), 0o700); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(Dir(), "download-*.zip")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	n, err := io.Copy(tmp, io.LimitReader(resp.Body, maxZipBytes+1))
	if err != nil {
		return nil, err
	}
	if n > maxZipBytes {
		return nil, fmt.Errorf("%s/all.zip is over the %d byte limit", eco, maxZipBytes)
	}
	return indexZip(eco, tmp, n)
}

func indexZip(eco string, r io.ReaderAt, size int64) (*Index, error) {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return nil, err
	}
	ix := &Index{Ecosystem: eco, Vulns: map[string]*Vuln{}, FullAt: time.Now()}
	for _, f := range zr.File {
		name := path.Base(f.Name)
		// Malicious-package reports are most of npm's archive; skip them
		// without reading.
		if !strings.HasSuffix(name, ".json") || strings.HasPrefix(name, "MAL-") || f.UncompressedSize64 > maxRecordBytes {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(rc, maxRecordBytes+1))
		rc.Close()
		if err != nil || len(b) > maxRecordBytes {
			continue
		}
		v, mod, err := convert(eco, b)
		if err != nil {
			continue
		}
		if mod.After(ix.Updated) {
			ix.Updated = mod
		}
		if v != nil {
			ix.Vulns[v.ID] = v
		}
	}
	if len(ix.Vulns) == 0 {
		return nil, fmt.Errorf("%s/all.zip has no usable records", eco)
	}
	return ix, nil
}

// Status describes the local index of one ecosystem.
type Status struct {
	Ecosystem string    `json:"ecosystem"`
	Updated   time.Time `json:"updated"`
	Vulns     int       `json:"vulns"`
	Packages  int       `json:"packages"`
	Bytes     int64     `json:"bytes"`
}

// Statuses lists the indexes on disk.
func Statuses() []Status {
	var out []Status
	loaded := Load()
	for _, eco := range Ecosystems {
		ix, ok := loaded[eco]
		if !ok {
			continue
		}
		st := Status{Ecosystem: eco, Updated: ix.Updated, Vulns: len(ix.Vulns), Packages: ix.Packages()}
		if fi, err := os.Stat(indexPath(eco)); err == nil {
			st.Bytes = fi.Size()
		}
		out = append(out, st)
	}
	return out
}

// Settings are kept in vulndb/settings.json. Updates are on by default.
type Settings struct {
	Off       bool      `json:"off"`
	Checked   time.Time `json:"checked"`
	LastError string    `json:"last_error,omitempty"`
}

func settingsPath() string { return filepath.Join(Dir(), "settings.json") }

// LoadSettings reads the settings.
func LoadSettings() Settings {
	var s Settings
	if b, err := os.ReadFile(settingsPath()); err == nil {
		_ = json.Unmarshal(b, &s)
	}
	return s
}

// SaveSettings writes the settings (0600).
func SaveSettings(s Settings) error {
	if err := os.MkdirAll(Dir(), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(s, "", "  ")
	tmp := settingsPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, settingsPath())
}

// UpdateAll refreshes every ecosystem and records the check.
func UpdateAll(ctx context.Context) []Result {
	var out []Result
	var errs []string
	for _, eco := range Ecosystems {
		r := Update(ctx, eco)
		if r.Err != nil {
			errs = append(errs, eco+": "+r.Err.Error())
		}
		out = append(out, r)
	}
	s := LoadSettings()
	s.Checked = time.Now()
	s.LastError = strings.Join(errs, "; ")
	_ = SaveSettings(s)
	return out
}
