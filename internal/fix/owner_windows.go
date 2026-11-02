package fix

import "os"

func ownedByUser(os.FileInfo) bool { return true }
