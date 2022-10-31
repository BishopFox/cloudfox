package utils

import (
	"io"
	"log"
	"os"
	"os/user"
	"path"
	"path/filepath"

	"github.com/BishopFox/cloudfox/constants"
	"github.com/aws/smithy-go/ptr"
	"github.com/jedib0t/go-pretty/text"
)

func init() {
	text.EnableColors()
}

// Initializes logging.
// Don't forget to use 'defer file.close()' after invoking this function.
func InitLogging() *os.File {
	// Use the commented line instead to print the file path of the called function
	// log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.SetFlags(log.LstdFlags)
	appDir := GetLogDirPath()
	logFile, err := os.OpenFile(path.Join(ptr.ToString(appDir), constants.CLOUDFOX_LOG_FILE_NAME), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("[-] Error opening log file: %s", err)
	}
	multiOutput := io.MultiWriter(os.Stdout, logFile)
	log.SetOutput(multiOutput)
	return logFile
}

// This function returns ~/.cloudfox.
// If the folder does not exist the function creates it.
func GetLogDirPath() *string {
	user, _ := user.Current()
	dir := filepath.Join(user.HomeDir, constants.CLOUDFOX_LOG_FILE_DIR_NAME)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err = os.MkdirAll(dir, 0700)
		if err != nil {
			log.Fatalf("[-] Failed to read or create cloudfox directory")
		}
	}
	return ptr.String(dir)
}
