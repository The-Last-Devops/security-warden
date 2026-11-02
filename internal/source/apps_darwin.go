package source

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// apps checks the code signature of each app in /Applications (top level).
// codesign only reads the bundle's signature, never prompts and needs no
// rights. Apple's own apps, which are links into /System, are skipped.
func apps(ctx context.Context) ([]Item, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	paths, _ := filepath.Glob("/Applications/*.app")
	var todo []string
	for _, p := range paths {
		fi, err := os.Lstat(p)
		if err != nil || !fi.IsDir() { // symlinks (Safari) and odd files
			continue
		}
		todo = append(todo, p)
	}
	jobs := make(chan string)
	var mu sync.Mutex
	var items []Item
	var wg sync.WaitGroup
	for w := 0; w < 6; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				out, _ := runCombined(ctx, "codesign", "-dv", "--verbose=1", "--", p)
				if ctx.Err() != nil {
					continue
				}
				unsigned := strings.Contains(out, "is not signed at all")
				adhoc := strings.Contains(out, "Signature=adhoc")
				if !unsigned && !adhoc && !strings.Contains(out, "Executable=") {
					continue // unreadable or odd output: no verdict
				}
				mu.Lock()
				items = append(items, Item{"app": strings.TrimSuffix(filepath.Base(p), ".app"), "path": p,
					"unsigned": unsigned, "adhoc": adhoc})
				mu.Unlock()
			}
		}()
	}
	for _, p := range todo {
		if ctx.Err() != nil {
			break
		}
		jobs <- p
	}
	close(jobs)
	wg.Wait()
	sort.Slice(items, func(i, j int) bool { return items[i]["path"].(string) < items[j]["path"].(string) })
	return items, nil
}
