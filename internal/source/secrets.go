package source

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// home is overridable in tests.
var home = func() string { h, _ := os.UserHomeDir(); return h }

const maxRead = 256 << 10

func readSmall(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxRead))
}

func modeFields(it Item, fi os.FileInfo) {
	m := fi.Mode().Perm()
	it["mode"] = fmt.Sprintf("%04o", m)
	it["group_readable"] = m&0o040 != 0
	it["world_readable"] = m&0o004 != 0
}

// sshKeys lists private keys in ~/.ssh and whether they have a passphrase.
func sshKeys(ctx context.Context) ([]Item, error) {
	dir := filepath.Join(home(), ".ssh")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, Skip{"skip.no_ssh_dir"}
	}
	var items []Item
	for _, e := range entries {
		if e.IsDir() || strings.HasSuffix(e.Name(), ".pub") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		b, err := readSmall(path)
		if err != nil {
			continue
		}
		kind, encrypted, ok := classifyKey(b)
		if !ok {
			continue
		}
		fi, err := os.Stat(path)
		if err != nil {
			continue
		}
		it := Item{"name": e.Name(), "path": path, "format": kind, "encrypted": encrypted}
		modeFields(it, fi)
		items = append(items, it)
	}
	return items, nil
}

// classifyKey tells whether b is a private key and whether it is encrypted.
// It never keeps key material.
func classifyKey(b []byte) (kind string, encrypted, ok bool) {
	s := string(b)
	switch {
	case strings.Contains(s, "-----BEGIN OPENSSH PRIVATE KEY-----"):
		return "openssh", opensshEncrypted(s), true
	case strings.Contains(s, "-----BEGIN ENCRYPTED PRIVATE KEY-----"):
		return "pkcs8", true, true
	case strings.Contains(s, "-----BEGIN PRIVATE KEY-----"):
		return "pkcs8", false, true
	case strings.Contains(s, "PRIVATE KEY-----"): // RSA, EC, DSA (PEM)
		return "pem", strings.Contains(s, "Proc-Type: 4,ENCRYPTED"), true
	}
	return "", false, false
}

// opensshEncrypted reads the cipher name from an openssh-key-v1 blob.
func opensshEncrypted(s string) bool {
	start := strings.Index(s, "-----BEGIN OPENSSH PRIVATE KEY-----")
	end := strings.Index(s, "-----END OPENSSH PRIVATE KEY-----")
	if start < 0 || end < start {
		return false
	}
	body := strings.Join(strings.Fields(s[start+35:end]), "")
	raw, err := base64.StdEncoding.DecodeString(body)
	magic := []byte("openssh-key-v1\x00")
	if err != nil || !bytes.HasPrefix(raw, magic) {
		return false
	}
	rest := raw[len(magic):]
	if len(rest) < 4 {
		return false
	}
	n := binary.BigEndian.Uint32(rest)
	if int(n) > len(rest)-4 {
		return false
	}
	return string(rest[4:4+n]) != "none"
}

// credentialFile describes a well-known file that may hold credentials.
type credentialFile struct {
	kind string
	rel  string
	// secret matches content that is a usable credential stored in plain text.
	secret *regexp.Regexp
}

var credentialFiles_ = []credentialFile{
	{"aws", ".aws/credentials", regexp.MustCompile(`(?m)^\s*aws_secret_access_key\s*=\s*\S`)},
	{"kubeconfig", ".kube/config", regexp.MustCompile(`(?m)^\s*(token|client-key-data|password):\s*\S`)},
	{"docker", ".docker/config.json", regexp.MustCompile(`"auth"\s*:\s*"[^"]+"`)},
	{"npm", ".npmrc", regexp.MustCompile(`(?m)(_authToken|_auth|_password)\s*=\s*\S`)},
	{"netrc", ".netrc", regexp.MustCompile(`(?m)\bpassword\s+\S`)},
	{"git_credentials", ".git-credentials", regexp.MustCompile(`://[^:/\s]+:[^@\s]+@`)},
	{"pypi", ".pypirc", regexp.MustCompile(`(?m)^\s*password\s*[=:]\s*\S`)},
	{"github_cli", ".config/gh/hosts.yml", regexp.MustCompile(`(?m)^\s*oauth_token:\s*\S`)},
	{"terraform", ".terraform.d/credentials.tfrc.json", regexp.MustCompile(`"token"\s*:\s*"[^"]+"`)},
}

var awsLongTermKey = regexp.MustCompile(`(?m)^\s*aws_access_key_id\s*=\s*AKIA`)

// credentialFiles checks well-known credential files: do they hold plain
// text secrets, and who can read them.
func credentialFiles(ctx context.Context) ([]Item, error) {
	var items []Item
	for _, cf := range credentialFiles_ {
		path := filepath.Join(home(), cf.rel)
		fi, err := os.Stat(path)
		if err != nil || fi.IsDir() {
			continue
		}
		b, err := readSmall(path)
		if err != nil {
			continue
		}
		it := Item{
			"kind":              cf.kind,
			"path":              path,
			"plaintext_secret":  cf.secret.Match(b),
			"aws_long_term_key": cf.kind == "aws" && awsLongTermKey.Match(b),
		}
		modeFields(it, fi)
		items = append(items, it)
	}
	return items, nil
}
