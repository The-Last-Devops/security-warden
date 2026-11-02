//go:build !windows

package source

import (
	"os"
	"syscall"
)

// owner returns a file's uid and gid.
func owner(fi os.FileInfo) (uid, gid uint32, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return st.Uid, st.Gid, true
}
