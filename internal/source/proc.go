package source

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

// procExePaths reads pid -> executable from /proc (Linux).
func procExePaths() map[int]string {
	m := map[int]string{}
	dirs, _ := os.ReadDir("/proc")
	for _, d := range dirs {
		pid := atoi(d.Name())
		if pid <= 0 {
			continue
		}
		if exe, err := os.Readlink(filepath.Join("/proc", d.Name(), "exe")); err == nil {
			m[pid] = strings.TrimSuffix(exe, " (deleted)")
		} else if b, err := os.ReadFile(filepath.Join("/proc", d.Name(), "comm")); err == nil {
			// Other users' processes: no exe link without root, name only.
			m[pid] = strings.TrimSpace(string(b))
		}
	}
	return m
}

// procListeners lists listening TCP sockets from /proc/net/tcp{,6} and maps
// them to processes through /proc/<pid>/fd. Without root only the current
// user's sockets map to a process; the others are still listed.
func procListeners() ([]Item, error) {
	type sock struct {
		host string
		port int
	}
	socks := map[string]sock{} // inode -> address
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		file, err := os.Open(f)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(file)
		sc.Scan() // header
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 10 || fields[3] != "0A" { // 0A = LISTEN
				continue
			}
			host, port, err := parseProcAddr(fields[1])
			if err != nil {
				continue
			}
			socks[fields[9]] = sock{host, port}
		}
		file.Close()
	}
	if len(socks) == 0 {
		return nil, nil
	}

	owner := map[string]int{} // inode -> pid
	dirs, _ := os.ReadDir("/proc")
	for _, d := range dirs {
		pid := atoi(d.Name())
		if pid <= 0 {
			continue
		}
		fds, err := os.ReadDir(filepath.Join("/proc", d.Name(), "fd"))
		if err != nil {
			continue
		}
		for _, fd := range fds {
			l, err := os.Readlink(filepath.Join("/proc", d.Name(), "fd", fd.Name()))
			if err == nil && strings.HasPrefix(l, "socket:[") {
				owner[strings.TrimSuffix(strings.TrimPrefix(l, "socket:["), "]")] = pid
			}
		}
	}

	paths := processPaths()
	seen := map[string]bool{}
	var items []Item
	for inode, s := range socks {
		pid := owner[inode]
		loopback := isLoopback(s.host)
		key := fmt.Sprintf("%d|%d|%t", pid, s.port, loopback)
		if seen[key] {
			continue
		}
		seen[key] = true
		path := paths[pid]
		name := filepath.Base(path)
		if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid)); err == nil {
			name = strings.TrimSpace(string(b))
		}
		if pid == 0 {
			name, path = "", ""
		}
		service := ""
		if sv, ok := identify(path); ok {
			service = sv.product
		}
		items = append(items, Item{
			"service":        service,
			"process":        name,
			"pid":            pid,
			"user":           procUser(pid),
			"path":           path,
			"address":        s.host,
			"port":           s.port,
			"loopback":       loopback,
			"all_interfaces": s.host == "0.0.0.0" || s.host == "::",
			"reachable":      !loopback,
			"system_binary":  false,
		})
	}
	return items, nil
}

// parseProcAddr decodes "0100007F:1F90" (IPv4) or a 32-hex-digit IPv6
// address. The kernel prints each 32-bit word in host (little-endian) order.
func parseProcAddr(s string) (string, int, error) {
	h, p, ok := strings.Cut(s, ":")
	if !ok {
		return "", 0, fmt.Errorf("bad address %q", s)
	}
	port, err := strconv.ParseUint(p, 16, 16)
	if err != nil {
		return "", 0, err
	}
	raw, err := hex.DecodeString(h)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return "", 0, fmt.Errorf("bad address %q", s)
	}
	for i := 0; i < len(raw); i += 4 {
		raw[i], raw[i+1], raw[i+2], raw[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
	}
	ip := net.IP(raw)
	if v4 := ip.To4(); v4 != nil && len(raw) == 16 && !ip.IsUnspecified() {
		ip = v4
	}
	return ip.String(), int(port), nil
}

func procUser(pid int) string {
	if pid <= 0 {
		return ""
	}
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			f := strings.Fields(line)
			if len(f) > 1 {
				if u, err := user.LookupId(f[1]); err == nil {
					return u.Username
				}
				return f[1]
			}
		}
	}
	return ""
}
