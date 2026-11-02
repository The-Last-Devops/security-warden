package source

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"math/big"
	"strings"
)

// sshKeyStrength returns the algorithm and size of a private key from its
// .pub file, or else from the public half an OpenSSH private key file
// carries in clear. Unknown: "", 0.
func sshKeyStrength(path string, private []byte) (string, int) {
	if b, err := readSmallN(path+".pub", 64<<10); err == nil {
		if f := strings.Fields(string(b)); len(f) >= 2 {
			if blob, err := base64.StdEncoding.DecodeString(f[1]); err == nil {
				if t, n := pubKeyStrength(blob); t != "" {
					return t, n
				}
			}
		}
	}
	if blob := opensshPublicBlob(string(private)); blob != nil {
		return pubKeyStrength(blob)
	}
	return "", 0
}

// sshString reads one length-prefixed SSH wire string.
func sshString(b []byte) (s, rest []byte, ok bool) {
	if len(b) < 4 {
		return nil, nil, false
	}
	n := binary.BigEndian.Uint32(b)
	if uint64(n) > uint64(len(b)-4) {
		return nil, nil, false
	}
	return b[4 : 4+n], b[4+n:], true
}

// pubKeyStrength decodes an SSH public key blob.
func pubKeyStrength(blob []byte) (string, int) {
	typ, rest, ok := sshString(blob)
	if !ok {
		return "", 0
	}
	switch t := string(typ); {
	case t == "ssh-rsa":
		_, rest, ok = sshString(rest) // e
		if !ok {
			return "", 0
		}
		n, _, ok := sshString(rest)
		if !ok {
			return "", 0
		}
		return "rsa", new(big.Int).SetBytes(n).BitLen()
	case t == "ssh-dss":
		p, _, ok := sshString(rest)
		if !ok {
			return "dsa", 0
		}
		return "dsa", new(big.Int).SetBytes(p).BitLen()
	case t == "ssh-ed25519":
		return "ed25519", 256
	case t == "sk-ssh-ed25519@openssh.com":
		return "ed25519-sk", 256
	case t == "sk-ecdsa-sha2-nistp256@openssh.com":
		return "ecdsa-sk", 256
	case strings.HasPrefix(t, "ecdsa-sha2-nistp"):
		switch strings.TrimPrefix(t, "ecdsa-sha2-nistp") {
		case "256":
			return "ecdsa", 256
		case "384":
			return "ecdsa", 384
		case "521":
			return "ecdsa", 521
		}
		return "ecdsa", 0
	}
	return "", 0
}

// opensshPublicBlob returns the public key stored unencrypted in an
// openssh-key-v1 private key file (the private part is never decoded).
func opensshPublicBlob(s string) []byte {
	start := strings.Index(s, "-----BEGIN OPENSSH PRIVATE KEY-----")
	end := strings.Index(s, "-----END OPENSSH PRIVATE KEY-----")
	if start < 0 || end < start {
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s[start+35:end]), ""))
	magic := []byte("openssh-key-v1\x00")
	if err != nil || !bytes.HasPrefix(raw, magic) {
		return nil
	}
	rest := raw[len(magic):]
	ok := true
	for i := 0; i < 3 && ok; i++ { // cipher, kdf, kdf options
		_, rest, ok = sshString(rest)
	}
	if !ok {
		return nil
	}
	if len(rest) < 4 || binary.BigEndian.Uint32(rest) < 1 {
		return nil
	}
	pub, _, ok2 := sshString(rest[4:])
	if !ok2 {
		return nil
	}
	return pub
}
