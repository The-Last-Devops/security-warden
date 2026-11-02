package source

import "os"

// owner is not meaningful on Windows; ACLs are checked separately.
func owner(fi os.FileInfo) (uid, gid uint32, ok bool) { return 0, 0, false }

func openRegular(path string) (*os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		f.Close()
		return nil, os.ErrInvalid
	}
	return f, nil
}
