package utils

import (
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"

	"github.com/BishopFox/cloudfox/constants"
	"github.com/aws/smithy-go/ptr"
	"github.com/jedib0t/go-pretty/text"
	"github.com/sirupsen/logrus"
)

func init() {
	text.EnableColors()
}

// txtLogger - Returns the txt logger
func TxtLogger() *logrus.Logger {
	txtLogger := logrus.New()
	txtFile, err := os.OpenFile(fmt.Sprintf("%s/cloudfox-error.log", ptr.ToString(GetLogDirPath())), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(fmt.Sprintf("Failed to open log file %v", err))
	}
	txtLogger.Out = txtFile
	txtLogger.SetLevel(logrus.InfoLevel)
	//txtLogger.SetReportCaller(true)

	return txtLogger
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
