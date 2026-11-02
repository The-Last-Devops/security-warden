package source

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// knownServer describes a server program people often run directly on a
// dev machine that is better kept in a container bound to localhost.
type knownServer struct {
	product string
	kind    string // database, cache, search, queue, web, ai, storage
	image   string // official Docker image
	port    int    // default port, used in the compose hint
}

// servers is keyed by executable name; pathHints match JVM/Erlang servers
// whose executable is just "java" or "beam.smp".
var servers = map[string]knownServer{
	"postgres":          {"PostgreSQL", "database", "postgres:17", 5432},
	"mysqld":            {"MySQL", "database", "mysql:8.4", 3306},
	"mariadbd":          {"MariaDB", "database", "mariadb:11", 3306},
	"mongod":            {"MongoDB", "database", "mongo:8", 27017},
	"redis-server":      {"Redis", "cache", "redis:7", 6379},
	"valkey-server":     {"Valkey", "cache", "valkey/valkey:8", 6379},
	"memcached":         {"Memcached", "cache", "memcached:1.6", 11211},
	"clickhouse-server": {"ClickHouse", "database", "clickhouse/clickhouse-server", 8123},
	"influxd":           {"InfluxDB", "database", "influxdb:2", 8086},
	"etcd":              {"etcd", "database", "quay.io/coreos/etcd", 2379},
	"meilisearch":       {"Meilisearch", "search", "getmeili/meilisearch", 7700},
	"typesense-server":  {"Typesense", "search", "typesense/typesense", 8108},
	"qdrant":            {"Qdrant", "search", "qdrant/qdrant", 6333},
	"minio":             {"MinIO", "storage", "minio/minio", 9000},
	"nginx":             {"nginx", "web", "nginx:stable", 80},
	"httpd":             {"Apache httpd", "web", "httpd:2.4", 80},
	"caddy":             {"Caddy", "web", "caddy:2", 80},
	"php-fpm":           {"PHP-FPM", "web", "php:fpm", 9000},
	"ollama":            {"Ollama", "ai", "ollama/ollama", 11434},
	"consul":            {"Consul", "database", "hashicorp/consul", 8500},
	"vault":             {"Vault", "database", "hashicorp/vault", 8200},
	"nats-server":       {"NATS", "queue", "nats:2", 4222},
	"mosquitto":         {"Mosquitto", "queue", "eclipse-mosquitto:2", 1883},
}

var pathHints = []struct {
	substr string
	server knownServer
}{
	{"elasticsearch", knownServer{"Elasticsearch", "search", "elasticsearch:8.15.0", 9200}},
	{"opensearch", knownServer{"OpenSearch", "search", "opensearchproject/opensearch:2", 9200}},
	{"rabbitmq", knownServer{"RabbitMQ", "queue", "rabbitmq:3-management", 5672}},
	{"kafka", knownServer{"Kafka", "queue", "apache/kafka:3.8.0", 9092}},
	{"zookeeper", knownServer{"ZooKeeper", "queue", "zookeeper:3.9", 2181}},
	{"neo4j", knownServer{"Neo4j", "database", "neo4j:5", 7687}},
	{"couchdb", knownServer{"CouchDB", "database", "couchdb:3", 5984}},
	{"cassandra", knownServer{"Cassandra", "database", "cassandra:5", 9042}},
}

func identify(path string) (knownServer, bool) {
	if s, ok := servers[filepath.Base(path)]; ok {
		return s, true
	}
	lp := strings.ToLower(path)
	for _, h := range pathHints {
		if strings.Contains(lp, h.substr) {
			return h.server, true
		}
	}
	return knownServer{}, false
}

// homebrewFormula returns the formula and version from a Cellar path such as
// /opt/homebrew/Cellar/postgresql@16/16.4/bin/postgres.
func homebrewFormula(path string) (name, version string) {
	i := strings.Index(path, "/Cellar/")
	if i < 0 {
		return "", ""
	}
	parts := strings.Split(path[i+len("/Cellar/"):], "/")
	if len(parts) < 2 {
		return "", ""
	}
	return parts[0], parts[1]
}

func installedBy(path string) string {
	switch {
	case strings.Contains(path, "/Cellar/") || strings.HasPrefix(path, "/opt/homebrew/") || strings.HasPrefix(path, "/usr/local/opt/"):
		return "homebrew"
	case strings.Contains(path, ".app/Contents/"):
		return "app"
	case systemBinary(path):
		return "system"
	}
	return "other"
}

type brewOutdated struct {
	Formulae []struct {
		Name              string   `json:"name"`
		InstalledVersions []string `json:"installed_versions"`
		CurrentVersion    string   `json:"current_version"`
		Pinned            bool     `json:"pinned"`
	} `json:"formulae"`
	Casks []struct {
		Name              string   `json:"name"`
		InstalledVersions []string `json:"installed_versions"`
		CurrentVersion    string   `json:"current_version"`
	} `json:"casks"`
}

func brewBinary() string {
	if p, err := exec.LookPath("brew"); err == nil {
		return p
	}
	for _, p := range []string{"/opt/homebrew/bin/brew", "/usr/local/bin/brew"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// outdatedOnce asks Homebrew which packages have newer versions. It uses
// Homebrew's local cache (no auto-update), so it sends nothing new out.
var outdatedOnce = sync.OnceValues(func() (*brewOutdated, error) {
	bin := brewBinary()
	if bin == "" {
		return nil, Skip{"skip.homebrew"}
	}
	cmd := exec.Command(bin, "outdated", "--json=v2")
	cmd.Env = append(os.Environ(), "HOMEBREW_NO_AUTO_UPDATE=1", "HOMEBREW_NO_ANALYTICS=1", "HOMEBREW_NO_ENV_HINTS=1")
	out, err := cmd.Output()
	if len(out) == 0 && err != nil {
		return nil, err
	}
	var o brewOutdated
	if err := json.Unmarshal(out, &o); err != nil {
		return nil, err
	}
	return &o, nil
})

// services lists known server programs that are running, how they were
// installed, which ports they listen on, and whether they are out of date.
func services(ctx context.Context) ([]Item, error) {
	ports := map[int][]Item{}
	if ls, err := listeningPorts(ctx); err == nil {
		for _, it := range ls {
			pid, _ := it["pid"].(int)
			ports[pid] = append(ports[pid], it)
		}
	}
	old := map[string]string{}
	if o, err := outdatedOnce(); err == nil {
		for _, f := range o.Formulae {
			if !f.Pinned {
				old[f.Name] = f.CurrentVersion
			}
		}
	}

	seen := map[string]bool{}
	var items []Item
	for pid, path := range processPaths() {
		s, ok := identify(path)
		if !ok {
			continue
		}
		formula, version := homebrewFormula(path)
		reachable, port := false, 0
		for _, p := range ports[pid] {
			if r, _ := p["reachable"].(bool); r {
				reachable = true
			}
			if pp, _ := p["port"].(int); port == 0 || pp < port {
				port = pp
			}
		}
		// One item per product; a server with many workers counts once, but
		// keep the reachable one if any worker is.
		key := s.product
		if seen[key] && !reachable {
			continue
		}
		if seen[key] {
			for i, it := range items {
				if it["product"] == s.product {
					items = append(items[:i], items[i+1:]...)
					break
				}
			}
		}
		seen[key] = true
		if port == 0 {
			port = s.port
		}
		latest := old[formula]
		items = append(items, Item{
			"product":      s.product,
			"kind":         s.kind,
			"path":         path,
			"pid":          pid,
			"installed_by": installedBy(path),
			"formula":      formula,
			"version":      version,
			"outdated":     latest != "",
			"latest":       latest,
			"listening":    len(ports[pid]) > 0,
			"reachable":    reachable,
			"port":         port,
			"docker_image": s.image,
			"in_container": false,
		})
	}
	return items, nil
}

// outdatedRunning lists every running Homebrew program with a newer version
// available, plus one summary item with the total outdated count.
func outdatedSoftware(ctx context.Context) ([]Item, error) {
	o, err := outdatedOnce()
	if err != nil {
		return nil, err
	}
	latest := map[string]string{}
	for _, f := range o.Formulae {
		if !f.Pinned {
			latest[f.Name] = f.CurrentVersion
		}
	}
	reachable := map[int]bool{}
	listening := map[int]bool{}
	if ls, err := listeningPorts(ctx); err == nil {
		for _, it := range ls {
			pid, _ := it["pid"].(int)
			listening[pid] = true
			if r, _ := it["reachable"].(bool); r {
				reachable[pid] = true
			}
		}
	}
	seen := map[string]bool{}
	var items []Item
	for pid, path := range processPaths() {
		formula, version := homebrewFormula(path)
		cur, ok := latest[formula]
		if !ok || seen[formula] {
			continue
		}
		seen[formula] = true
		items = append(items, Item{
			"kind":      "running",
			"name":      formula,
			"version":   version,
			"latest":    cur,
			"path":      path,
			"listening": listening[pid],
			"reachable": reachable[pid],
		})
	}
	items = append(items, Item{
		"kind":     "summary",
		"formulae": len(o.Formulae),
		"casks":    len(o.Casks),
		"total":    len(o.Formulae) + len(o.Casks),
	})
	return items, nil
}
