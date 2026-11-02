package source

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"sync"
)

type dockerContainer struct {
	Name   string
	Config struct {
		Image string
		User  string
	}
	HostConfig struct {
		Privileged  bool
		NetworkMode string
	}
	Mounts []struct {
		Source      string
		Destination string
	}
	NetworkSettings struct {
		Ports map[string][]struct {
			HostIp   string
			HostPort string
		}
	}
}

var dockerOnce = sync.OnceValues(func() ([]dockerContainer, error) {
	ctx := context.Background()
	if _, err := run(ctx, "docker", "version", "--format", "{{.Server.Version}}"); err != nil {
		return nil, Skip{"skip.docker"}
	}
	ids, err := run(ctx, "docker", "ps", "-q")
	if err != nil {
		return nil, err
	}
	list := strings.Fields(ids)
	if len(list) == 0 {
		return nil, nil
	}
	out, err := run(ctx, "docker", append([]string{"inspect"}, list...)...)
	if err != nil {
		return nil, err
	}
	var cs []dockerContainer
	if err := json.Unmarshal([]byte(out), &cs); err != nil {
		return nil, err
	}
	return cs, nil
})

func dockerContainers(ctx context.Context) ([]Item, error) {
	cs, err := dockerOnce()
	if err != nil {
		return nil, err
	}
	var items []Item
	for _, c := range cs {
		sock := false
		for _, m := range c.Mounts {
			if strings.HasSuffix(m.Source, "docker.sock") || strings.HasSuffix(m.Destination, "docker.sock") {
				sock = true
			}
		}
		user := c.Config.User
		items = append(items, Item{
			"container":         strings.TrimPrefix(c.Name, "/"),
			"image":             c.Config.Image,
			"privileged":        c.HostConfig.Privileged,
			"host_network":      c.HostConfig.NetworkMode == "host",
			"mounts_docker_sock": sock,
			"user":              user,
			"runs_as_root":      user == "" || user == "root" || user == "0" || strings.HasPrefix(user, "0:"),
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
