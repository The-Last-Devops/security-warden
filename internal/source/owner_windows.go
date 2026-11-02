package source

import "os"

// owner is not meaningful on Windows; ACLs are checked separately.
func owner(fi os.FileInfo) (uid, gid uint32, ok bool) { return 0, 0, false }
