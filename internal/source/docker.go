package source

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

type dockerContainer struct {
	Name   string
	Config struct {
		Image string
		User  string
		Env   []string
	}
	HostConfig struct {
		Privileged  bool
		NetworkMode string
		PidMode     string
		IpcMode     string
		CapAdd      []string
		SecurityOpt []string
		Devices     []struct{ PathOnHost string }
	}
	Mounts []struct {
		Type        string
		Source      string
		Destination string
		RW          bool
	}
	NetworkSettings struct {
		Ports map[string][]struct {
			HostIp   string
			HostPort string
		}
	}
}

// dockerBin finds the docker CLI even under launchd's short PATH.
func dockerBin() string {
	if p, err := exec.LookPath("docker"); err == nil {
		return p
	}
	for _, p := range []string{"/usr/local/bin/docker", "/opt/homebrew/bin/docker", filepath.Join(home(), ".docker/bin/docker"),
		"/Applications/Docker.app/Contents/Resources/bin/docker", "/usr/bin/docker"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "docker"
}

var dockerOnce = sync.OnceValues(load_dockerOnce)

func load_dockerOnce() ([]dockerContainer, error) {
	ctx := context.Background()
	bin := dockerBin()
	if _, err := run(ctx, bin, "version", "--format", "{{.Server.Version}}"); err != nil {
		return nil, Skip{"skip.docker"}
	}
	ids, err := run(ctx, bin, "ps", "-q")
	if err != nil {
		return nil, err
	}
	list := strings.Fields(ids)
	if len(list) == 0 {
		return nil, nil
	}
	out, err := run(ctx, bin, append([]string{"inspect", "--"}, list...)...)
	if err != nil {
		return nil, err
	}
	var cs []dockerContainer
	if err := json.Unmarshal([]byte(out), &cs); err != nil {
		return nil, err
	}
	return cs, nil
}

// dangerousCaps give a container power over the host kernel or network.
var dangerousCaps = map[string]bool{
	"ALL": true, "SYS_ADMIN": true, "SYS_MODULE": true, "SYS_PTRACE": true, "SYS_RAWIO": true,
	"NET_ADMIN": true, "DAC_READ_SEARCH": true, "SYS_BOOT": true, "SYS_TIME": true, "BPF": true, "PERFMON": true,
}

// riskyMount names a host path that gives a container the host itself or
// your credentials: /, /etc, /root, the home folder, or a credential folder.
func riskyMount(src string) string {
	h := home()
	clean := strings.TrimSuffix(src, "/")
	if clean == "" {
		clean = "/"
	}
	switch clean {
	case "/", "/etc", "/root", "/var/run", "/run", "/boot", "/dev", "/proc", "/sys", "/Users", "/home", h:
		return src
	}
	for _, d := range []string{".ssh", ".aws", ".kube", ".gnupg", ".docker", ".config/gcloud", ".azure", "Library/Keychains"} {
		p := filepath.Join(h, d)
		if clean == p || strings.HasPrefix(clean, p+"/") {
			return src
		}
	}
	return ""
}

var secretEnvKey = regexp.MustCompile(`(?i)(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_KEY|ACCESS_KEY|CREDENTIAL)`)

func dockerContainers(ctx context.Context) ([]Item, error) {
	cs, err := dockerOnce()
	if err != nil {
		return nil, err
	}
	var items []Item
	for _, c := range cs {
		sock, risky := false, ""
		for _, m := range c.Mounts {
			if strings.HasSuffix(m.Source, "docker.sock") || strings.HasSuffix(m.Destination, "docker.sock") {
				sock = true
				continue
			}
			if m.Type == "bind" && risky == "" {
				risky = riskyMount(m.Source)
			}
		}
		var caps []string
		for _, cp := range c.HostConfig.CapAdd {
			if dangerousCaps[strings.TrimPrefix(strings.ToUpper(cp), "CAP_")] {
				caps = append(caps, strings.TrimPrefix(strings.ToUpper(cp), "CAP_"))
			}
		}
		seccomp, apparmor := false, false
		for _, o := range c.HostConfig.SecurityOpt {
			o = strings.ToLower(strings.ReplaceAll(o, "=", ":"))
			seccomp = seccomp || o == "seccomp:unconfined"
			apparmor = apparmor || o == "apparmor:unconfined"
		}
		// Variable names only: values never leave this function.
		var secretKeys []string
		for _, e := range c.Config.Env {
			k, v, _ := strings.Cut(e, "=")
			if secretEnvKey.MatchString(k) && len(v) >= 8 && !strings.HasPrefix(v, "/run/secrets/") && !strings.HasSuffix(k, "_FILE") {
				secretKeys = append(secretKeys, k)
			}
		}
		user := c.Config.User
		items = append(items, Item{
			"container":           strings.TrimPrefix(c.Name, "/"),
			"image":               c.Config.Image,
			"privileged":          c.HostConfig.Privileged,
			"host_network":        c.HostConfig.NetworkMode == "host",
			"host_pid":            c.HostConfig.PidMode == "host",
			"host_ipc":            c.HostConfig.IpcMode == "host",
			"mounts_docker_sock":  sock,
			"risky_mount":         risky,
			"dangerous_caps":      strings.Join(caps, ", "),
			"seccomp_unconfined":  seccomp,
			"apparmor_unconfined": apparmor,
			"devices":             len(c.HostConfig.Devices),
			"secret_env":          strings.Join(secretKeys, ", "),
			"user":                user,
			"runs_as_root":        user == "" || user == "root" || user == "0" || strings.HasPrefix(user, "0:"),
		})
	}
	return items, nil
}

func dockerPorts(ctx context.Context) ([]Item, error) {
	cs, err := dockerOnce()
	if err != nil {
		return nil, err
	}
	var items []Item
	for _, c := range cs {
		for cport, binds := range c.NetworkSettings.Ports {
			seen := map[string]bool{}
			for _, b := range binds {
				if seen[b.HostPort] && (b.HostIp == "::" || b.HostIp == "") {
					continue // IPv6 twin of an IPv4 binding
				}
				seen[b.HostPort] = true
				hp, _ := strconv.Atoi(b.HostPort)
				items = append(items, Item{
					"container":      strings.TrimPrefix(c.Name, "/"),
					"image":          c.Config.Image,
					"container_port": cport,
					"host_ip":        b.HostIp,
					"host_port":      hp,
					"all_interfaces": b.HostIp == "" || b.HostIp == "0.0.0.0" || b.HostIp == "::",
				})
			}
		}
	}
	return items, nil
}
