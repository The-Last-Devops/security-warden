package web

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"syscall"
)

// DefaultPort is where serve listens unless told otherwise. 7348 is not
// claimed by any common app, sits below every OS's ephemeral port range,
// and away from the usual dev ports (3000, 5000, 8000-8999, 9000).
const DefaultPort = 7348

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

// Listen opens addr. With fallback (the user did not pick a port), a busy
// port moves on to the next ten; an explicit port that is busy is an error
// that says so. It returns the address actually used.
func Listen(addr string, fallback bool) (net.Listener, string, error) {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return nil, "", err
	}
	tries := 1
	if fallback {
		tries = 11
	}
	var last error
	for i := 0; i < tries; i++ {
		a := netip.AddrPortFrom(ap.Addr(), ap.Port()+uint16(i)).String()
		ln, err := net.Listen("tcp", a)
		if err == nil {
			return ln, a, nil
		}
		last = err
		if !errors.Is(err, syscall.EADDRINUSE) {
			break
		}
	}
	if errors.Is(last, syscall.EADDRINUSE) {
		return nil, "", fmt.Errorf("port %d is already used by another program; pick another with --listen %s:PORT", ap.Port(), ap.Addr())
	}
	return nil, "", last
}
