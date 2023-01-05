package internal

import (
	"log"
	"os"
	"os/user"
	"path/filepath"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/aws/smithy-go/ptr"
	"github.com/jedib0t/go-pretty/text"
)

func init() {
	text.EnableColors()
}

// This function returns ~/.cloudfox.
// If the folder does not exist the function creates it.
func GetLogDirPath() *string {
	user, _ := user.Current()
	dir := filepath.Join(user.HomeDir, globals.CLOUDFOX_LOG_FILE_DIR_NAME)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err = os.MkdirAll(dir, 0700)
		if err != nil {
			log.Fatalf("[-] Failed to read or create cloudfox directory")
		}
	}
	return ptr.String(dir)
}
