package internal

import (
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/aws/smithy-go/ptr"
	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/text"
	"github.com/kyokomi/emoji"
	"github.com/sirupsen/logrus"
)

func init() {
	text.EnableColors()
}

// Note: clearln is defined in aws.go as "\r\x1b[2K" and is used to clear spinner status lines

// This function returns ~/.cloudfox.
// If the folder does not exist the function creates it.
func GetLogDirPath() *string {
	user, _ := user.Current()
	dir := filepath.Join(user.HomeDir, globals.CLOUDFOX_LOG_FILE_DIR_NAME)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err = os.MkdirAll(dir, 0700)
		if err != nil {
			log.Printf("[-] Failed to read or create cloudfox directory")
			dir, err = os.Getwd()
			return ptr.String(dir)
		}
	}
	return ptr.String(dir)
}

type Logger struct {
	version string
	txtLog  *logrus.Logger
}

func NewLogger() Logger {
	var logger = Logger{
		version: globals.CLOUDFOX_VERSION,
		txtLog:  TxtLog,
	}
	return logger
}

func (l *Logger) Info(text string) {
	l.InfoM(text, "config")
}

func (l *Logger) InfoM(text string, module string) {
	var cyan = color.New(color.FgCyan).SprintFunc()
	fmt.Printf(clearln+"[%s][%s] %s\n", cyan(emoji.Sprintf(":fox:cloudfox %s :fox:", l.version)), cyan(module), text)
}

func (l *Logger) Success(text string) {
	l.SuccessM(text, "config")
}
func (l *Logger) SuccessM(text string, module string) {
	var green = color.New(color.FgGreen).SprintFunc()
	fmt.Printf(clearln+"[%s][%s] %s\n", green(emoji.Sprintf(":fox:cloudfox %s :fox:", l.version)), green(module), text)
}

func (l *Logger) Warn(text string) {
	l.WarnM(text, "config")
}

func (l *Logger) WarnM(text string, module string) {
	var yellow = color.New(color.FgYellow).SprintFunc()
	fmt.Printf(clearln+"[%s][%s] ⚠️  %s\n", yellow(emoji.Sprintf(":fox:cloudfox %s :fox:", l.version)), yellow(module), text)
	if l.txtLog != nil {
		l.txtLog.Printf("[%s] WARNING: %s", module, text)
	}
}

func (l *Logger) Error(text string) {
	l.ErrorM(text, "config")
}

func (l *Logger) ErrorM(text string, module string) {
	var red = color.New(color.FgRed).SprintFunc()
	fmt.Printf(clearln+"[%s][%s] %s\n", red(emoji.Sprintf(":fox:cloudfox %s :fox:", l.version)), red(module), text)
	if l.txtLog != nil {
		l.txtLog.Printf("[%s] %s", module, text)
	}
}

func (l *Logger) Fatal(text string) {
	l.FatalM(text, "config")
}

func (l *Logger) FatalM(text string, module string) {
	var red = color.New(color.FgRed).SprintFunc()
	if l.txtLog != nil {
		l.txtLog.Printf("[%s] %s", module, text)
	}
	fmt.Printf(clearln+"[%s][%s] %s\n", red(emoji.Sprintf(":fox:cloudfox %s :fox:", l.version)), red(module), text)
	os.Exit(1)
}
