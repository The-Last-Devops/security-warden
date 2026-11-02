package source

import "testing"

// Captured from ubuntu:noble-20240423 after `apt update`, as a regular user.
const aptSample = `Listing...
apt/noble-updates 2.8.3 arm64 [upgradable from: 2.7.14build2]
base-files/noble-updates 13ubuntu10.5 arm64 [upgradable from: 13ubuntu10]
bsdutils/noble-updates,noble-security 1:2.39.3-9ubuntu6.6 arm64 [upgradable from: 1:2.39.3-9ubuntu6]
coreutils/noble-updates,noble-security 9.4-3ubuntu6.3 arm64 [upgradable from: 9.4-3ubuntu6]
libssl3t64/stable-security 3.0.17-1~deb12u3 amd64 [upgradable from: 3.0.16-1~deb12u1]
`

func TestParseAptUpgradable(t *testing.T) {
	total, security := parseAptUpgradable(aptSample)
	if total != 5 || security != 3 {
		t.Errorf("got %d total, %d security; want 5, 3", total, security)
	}
	if total, _ := parseAptUpgradable("Listing...\n"); total != 0 {
		t.Errorf("empty list: %d", total)
	}
}

// dnf 5 (fedora:41) and dnf 4 (rockylinux:9) `check-update --cacheonly -q`.
const dnf5Sample = `xz.aarch64      1:5.8.1-4.fc41 updates
xz-libs.aarch64 1:5.8.1-4.fc41 updates
`

const dnf4Sample = `Last metadata expiration check: 0:00:01 ago on Mon Nov  2 16:25:10 2026.

alternatives.aarch64                   1.24-2.el9                         baseos
bash.aarch64                           5.1.8-9.el9                        baseos
kernel-core.x86_64                     5.14.0-503.el9                     baseos
Obsoleting Packages
grub2-tools.x86_64                     1:2.06-92.el9                      baseos
    grub2-tools.x86_64                 1:2.06-77.el9                      @anaconda
`

func TestParseDnfCheckUpdate(t *testing.T) {
	if n := parseDnfCheckUpdate(dnf5Sample); n != 2 {
		t.Errorf("dnf5: %d", n)
	}
	if n := parseDnfCheckUpdate(dnf4Sample); n != 3 {
		t.Errorf("dnf4: %d", n)
	}
	if n := parseDnfCheckUpdate("No security updates needed, but 2 update(s) available\n"); n != 0 {
		t.Errorf("security summary line counted: %d", n)
	}
}
