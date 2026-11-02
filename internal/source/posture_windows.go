package source

import "context"

// posture reads Windows security settings as a standard user. Settings
// Windows hides from non-administrators are left out, never guessed; rules
// guard them with has(item.x).
func posture(ctx context.Context) ([]Item, error) {
	out, err := runPS(ctx, winPostureScript)
	if err != nil && out == "" {
		return nil, err
	}
	it, err := parseWinPosture(out)
	if err != nil {
		return nil, err
	}
	return []Item{it}, nil
}
