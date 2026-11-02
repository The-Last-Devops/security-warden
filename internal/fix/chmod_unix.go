//go:build !windows

package fix

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
)

// chmodNoFollow changes the mode of the file itself, never a symlink's
// target: the file is opened with O_NOFOLLOW and changed through the open
// descriptor, so it cannot be swapped between the check and the change.
func chmodNoFollow(path string, mode fs.FileMode) (fs.FileMode, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return 0, err
	}
	if !fi.Mode().IsRegular() {
		return 0, errors.New("not a regular file")
	}
	return fi.Mode().Perm(), f.Chmod(mode)
}
