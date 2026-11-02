package fix

import (
	"errors"
	"io/fs"
	"os"
)

func chmodNoFollow(path string, mode fs.FileMode) (fs.FileMode, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return 0, err
	}
	if !fi.Mode().IsRegular() {
		return 0, errors.New("not a regular file")
	}
	return fi.Mode().Perm(), os.Chmod(path, mode)
}
