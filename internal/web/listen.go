package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"syscall"
	"time"
)

// DefaultPort is where serve listens unless told otherwise: 7348 for
// releases (not claimed by any common app, below every OS's ephemeral port
// range, away from the usual dev ports), 7349 for development builds.
var DefaultPort = 7348

var (
	tailscaleV4 = netip.MustParsePrefix("100.64.0.0/10")
	tailscaleV6 = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
)

// Address kinds a listen address may have.
const (
	KindLoopback  = "loopback"
	KindTailscale = "tailscale"
	KindLAN       = "lan"
)

// ValidateListen accepts only one specific IP that is assigned to this
// machine: never 0.0.0.0, ::, an empty host or a hostname. LAN addresses
// need allowLAN. It returns the normalised "ip:port" and the address kind.
func ValidateListen(addr string, allowLAN bool, localIPs []netip.Addr) (string, string, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", "", fmt.Errorf("listen address must be IP:PORT, e.g. 127.0.0.1:7348: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", "", fmt.Errorf("bad port %q", portStr)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return "", "", fmt.Errorf("listen on an IP address, not a name: %q", host)
	}
	ip = ip.Unmap()
	if ip.IsUnspecified() {
		return "", "", fmt.Errorf("refusing %s: it would listen on every network. Use 127.0.0.1 or this machine's Tailscale IP", host)
	}
	if ip.Zone() != "" || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
		return "", "", fmt.Errorf("refusing %s: not a usable unicast address", host)
	}
	kind := KindLAN
	switch {
	case ip.IsLoopback():
		kind = KindLoopback
	case tailscaleV4.Contains(ip) || tailscaleV6.Contains(ip):
		kind = KindTailscale
	}
	if kind != KindLoopback {
		found := false
		for _, l := range localIPs {
			if l.Unmap() == ip {
				found = true
				break
			}
		}
		if !found {
			return "", "", fmt.Errorf("%s is not an address of this machine", host)
		}
	}
	if kind == KindLAN && !allowLAN {
		return "", "", fmt.Errorf("refusing %s: it is reachable by everyone on that network. Use 127.0.0.1 or a Tailscale IP, or pass --allow-lan if you really mean it", host)
	}
	return netip.AddrPortFrom(ip, uint16(port)).String(), kind, nil
}

// LocalIPs lists the addresses assigned to this machine's interfaces.
func LocalIPs() []netip.Addr {
	var out []netip.Addr
	ifs, _ := net.InterfaceAddrs()
	for _, a := range ifs {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			out = append(out, p.Addr())
		}
	}
	return out
}

// ErrInUse means the port is taken.
var ErrInUse = errors.New("port in use")

// Listen opens exactly addr: the address stays the same every time, so
// bookmarks and the app window keep working.
func Listen(addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if errors.Is(err, syscall.EADDRINUSE) {
		return nil, ErrInUse
	}
	return ln, err
}

// RunningHere reports whether a Security Warden server already answers on
// the loopback port, so a second launch can open it instead of failing.
func RunningHere(port int) bool {
	c := http.Client{Timeout: 800 * time.Millisecond}
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/api/passkey", port), nil)
	req.Host = fmt.Sprintf("localhost:%d", port)
	resp, err := c.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	var v map[string]any
	if json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&v) != nil {
		return false
	}
	_, ok := v["localhost"]
	return ok
}
