package source

import (
	"context"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// knownMiners are executable names of common cryptocurrency miners.
var knownMiners = map[string]bool{
	"xmrig": true, "xmr-stak": true, "minerd": true, "cpuminer": true, "ethminer": true, "nbminer": true,
	"t-rex": true, "lolminer": true, "phoenixminer": true, "cgminer": true, "bfgminer": true, "nanominer": true,
	"gminer": true, "teamredminer": true, "ccminer": true, "srbminer": true,
}

// isMiner matches a process name against known miners, also catching
// builds such as "xmrig-notls" or "SRBMiner-MULTI".
func isMiner(name string) bool {
	n := strings.TrimSuffix(strings.ToLower(name), ".exe")
	if knownMiners[n] {
		return true
	}
	for m := range knownMiners {
		if strings.HasPrefix(n, m+"-") || strings.HasPrefix(n, m+"_") {
			return true
		}
	}
	return false
}

// tempDirs are world-writable folders where malware often drops and runs
// its payload.
var tempDirs = []string{"/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/", "/dev/shm/"}

// processes lists running programs that look out of place: known crypto
// miners, and programs started from a temp folder or from the downloads
// folder. Only paths are compared; no file is opened.
func processes(ctx context.Context) ([]Item, error) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		return nil, Skip{"skip.platform"}
	}
	byPath := map[string]Item{}
	for pid, path := range processPaths() {
		if path == "" || byPath[path] != nil {
			continue
		}
		it := processItem(pid, path)
		if it["from_temp"] == true || it["from_downloads"] == true || it["miner"] == true {
			byPath[path] = it
		}
	}
	var items []Item
	for _, it := range byPath {
		items = append(items, it)
	}
	sort.Slice(items, func(i, j int) bool { return items[i]["path"].(string) < items[j]["path"].(string) })
	return items, nil
}

func processItem(pid int, path string) Item {
	fromTemp := false
	for _, d := range tempDirs {
		if strings.HasPrefix(path, d) {
			fromTemp = true
		}
	}
	name := filepath.Base(path)
	return Item{
		"name":           name,
		"path":           path,
		"pid":            pid,
		"from_temp":      fromTemp,
		"from_downloads": underDownloads(path),
		"miner":          isMiner(name),
	}
}
