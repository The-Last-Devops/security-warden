package source

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
)

// wire builds an SSH wire blob from length-prefixed strings.
func wire(parts ...[]byte) []byte {
	var b bytes.Buffer
	for _, p := range parts {
		binary.Write(&b, binary.BigEndian, uint32(len(p)))
		b.Write(p)
	}
	return b.Bytes()
}

func TestPubKeyStrength(t *testing.T) {
	mod := append([]byte{0x00, 0x80}, make([]byte, 255)...) // leading 0 + 2048-bit modulus
	cases := []struct {
		blob []byte
		typ  string
		bits int
	}{
		{wire([]byte("ssh-rsa"), []byte{1, 0, 1}, mod), "rsa", 2048},
		{wire([]byte("ssh-dss"), append([]byte{0x80}, make([]byte, 127)...)), "dsa", 1024},
		{wire([]byte("ssh-ed25519"), make([]byte, 32)), "ed25519", 256},
		{wire([]byte("ecdsa-sha2-nistp384"), []byte("nistp384"), make([]byte, 97)), "ecdsa", 384},
		{wire([]byte("ssh-rsa")), "", 0},
		{[]byte{0, 0, 9}, "", 0},
	}
	for _, c := range cases {
		if typ, bits := pubKeyStrength(c.blob); typ != c.typ || bits != c.bits {
			t.Errorf("got %s/%d, want %s/%d", typ, bits, c.typ, c.bits)
		}
	}

	// The public half an OpenSSH private key file carries in clear.
	pub := wire([]byte("ssh-ed25519"), make([]byte, 32))
	var raw bytes.Buffer
	raw.WriteString("openssh-key-v1\x00")
	raw.Write(wire([]byte("aes256-ctr"), []byte("bcrypt"), []byte("salt")))
	binary.Write(&raw, binary.BigEndian, uint32(1))
	raw.Write(wire(pub, []byte("encrypted-part")))
	pem := "-----BEGIN OPENSSH PRIVATE KEY-----\n" + base64.StdEncoding.EncodeToString(raw.Bytes()) + "\n-----END OPENSSH PRIVATE KEY-----\n"
	if typ, bits := pubKeyStrength(opensshPublicBlob(pem)); typ != "ed25519" || bits != 256 {
		t.Errorf("openssh private file: got %s/%d", typ, bits)
	}
	if opensshPublicBlob(strings.Replace(pem, "OPENSSH", "RSA", 2)) != nil {
		t.Error("non-openssh file decoded")
	}
}

func TestLatestTagAndMiner(t *testing.T) {
	for ref, want := range map[string]bool{
		"nginx": true, "nginx:latest": true, "localhost:5000/app": true, "ghcr.io/a/b:1.2": false,
		"redis@sha256:abc": false, "sha256:0123456789ab": false, "0123456789ab": false, "localhost:5000/app:2": false,
	} {
		if latestTag(ref) != want {
			t.Errorf("latestTag(%q) = %v", ref, !want)
		}
	}
	for name, want := range map[string]bool{"xmrig": true, "XMRig-notls": true, "t-rex": true, "SRBMiner-MULTI": true, "minerva": false, "node": false} {
		if isMiner(name) != want {
			t.Errorf("isMiner(%q) = %v", name, !want)
		}
	}
}

func TestKubeClientCert(t *testing.T) {
	kc := `clusters:
- name: local
  cluster: {server: "https://127.0.0.1:6443"}
- name: prod
  cluster: {server: "https://k8s.example.com"}
users:
- name: docker
  user: {client-certificate-data: AAAA}
- name: admin
  user: {client-certificate: /x/admin.crt}
- name: oidc
  user: {exec: {command: kubelogin}}
contexts:
- name: docker-desktop
  context: {cluster: local, user: docker}
- name: prod-oidc
  context: {cluster: prod, user: oidc}
- name: prod-admin
  context: {cluster: prod, user: admin}
`
	if got := kubeClientCertContext([]byte(kc)); got != "prod-admin" {
		t.Errorf("got %q", got)
	}
	if got := kubeClientCertContext([]byte(strings.Replace(kc, "user: admin}", "user: oidc}", 1))); got != "" {
		t.Errorf("local cert counted: %q", got)
	}
}
