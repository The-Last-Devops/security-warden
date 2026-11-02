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
	"time"
)

type dockerContainer struct {
	Name   string
	Image  string // image ID the container runs
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
	created         time.Time
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
	imageCreated(ctx, bin, cs)
	return cs, nil
}

// imageCreated fills each container's image build time with one
// "docker image inspect" call over the distinct image IDs.
func imageCreated(ctx context.Context, bin string, cs []dockerContainer) {
	seen := map[string]bool{}
	var ids []string
	for _, c := range cs {
		if c.Image != "" && !seen[c.Image] {
			seen[c.Image] = true
			ids = append(ids, c.Image)
		}
	}
	if len(ids) == 0 {
		return
	}
	out, _ := run(ctx, bin, append([]string{"image", "inspect", "--format", "{{.Id}} {{.Created}}", "--"}, ids...)...)
	created := map[string]time.Time{}
	for _, line := range strings.Split(out, "\n") {
		id, ts, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok {
			continue
		}
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			created[id] = t
		}
	}
	for i := range cs {
		cs[i].created = created[cs[i].Image]
	}
}

// imageAgeDays is how old the image build is, or -1 when unknown.
func imageAgeDays(t time.Time) int {
	if t.IsZero() || t.Year() < 2000 { // reproducible builds use the epoch
		return -1
	}
	return int(time.Since(t).Hours() / 24)
}

var hexID = regexp.MustCompile(`^[0-9a-f]{12,64}$`)

// latestTag reports an image reference with no tag or the "latest" tag,
// which can change under you. Digest-pinned references and image IDs never
// count.
func latestTag(ref string) bool {
	if ref == "" || strings.Contains(ref, "@") || strings.HasPrefix(ref, "sha256:") || hexID.MatchString(ref) {
		return false
	}
	last := ref[strings.LastIndex(ref, "/")+1:]
	_, tag, ok := strings.Cut(last, ":")
	return !ok || tag == "latest"
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
			"image_age_days":      imageAgeDays(c.created),
			"latest_tag":          latestTag(c.Config.Image),
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
