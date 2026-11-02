package source

import "testing"

func TestParseRemotes(t *testing.T) {
	cfg := `[core]
	bare = false
[remote "origin"]
	url = https://alice:example-not-a-token@github.com/acme/app.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[remote "ssh"]
	url = git@github.com:acme/app.git
[remote "plain"]
	url = https://alice@gitlab.com/acme/app.git
[remote "empty"]
	url = https://alice:@gitlab.com/acme/app.git
[remote "tok"]
	url = https://ghp_exampleexampleexample@github.com/acme/app.git
[branch "main"]
	url = https://bob:pw@example.com/x
`
	got := parseRemotes(cfg)
	if len(got) != 2 || got[0] != [2]string{"origin", "github.com"} || got[1] != [2]string{"tok", "github.com"} {
		t.Errorf("parseRemotes = %v", got)
	}
}
