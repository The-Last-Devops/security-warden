//go:build !windows

package fix

import (
	"os"
	"syscall"
)

func ownedByUser(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Getuid()
}
