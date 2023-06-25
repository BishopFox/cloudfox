package internal

import (
	"log"
	"os"
	"fmt"
	"os/user"
	"path/filepath"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/aws/smithy-go/ptr"
	"github.com/jedib0t/go-pretty/text"
	"github.com/kyokomi/emoji"
	"github.com/fatih/color"
	"github.com/sirupsen/logrus"
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

type Logger struct {
	version string
	txtLog *logrus.Logger
}

func NewLogger() Logger {
	var logger = Logger{
		version: globals.CLOUDFOX_VERSION,
		txtLog: TxtLog,
	}
	return logger
}

func (l *Logger) Info(text string){
	l.InfoM(text, "config")
}

func (l *Logger) InfoM(text string, module string) {
	var cyan = color.New(color.FgCyan).SprintFunc()
	fmt.Printf("[%s][%s] %s\n", cyan(emoji.Sprintf(":fox:cloudfox %s :fox:", l.version)), cyan(module), text)
}

func (l *Logger) Success(text string){
	l.SuccessM(text, "config")
}
func (l *Logger) SuccessM(text string, module string) {
	var green = color.New(color.FgGreen).SprintFunc()
	fmt.Printf("[%s][%s] %s\n", green(emoji.Sprintf(":fox:cloudfox %s :fox:", l.version)), green(module), text)
}

func (l *Logger) Error(text string){
	l.ErrorM(text, "config")
}

func (l *Logger) ErrorM(text string, module string) {
	var red = color.New(color.FgRed).SprintFunc()
	fmt.Printf("[%s][%s] %s\n", red(emoji.Sprintf(":fox:cloudfox %s :fox:", l.version)), red(module), text)
	l.txtLog.Printf("[%s] %s", module, text)
}

func (l *Logger) Fatal(text string){
	l.FatalM(text, "config")
}

func (l *Logger) FatalM(text string, module string) {
	var red = color.New(color.FgRed).SprintFunc()
	l.txtLog.Printf("[%s] %s", module, text)
	fmt.Printf("[%s][%s] %s\n", red(emoji.Sprintf(":fox:cloudfox %s :fox:", l.version)), red(module), text)
	os.Exit(1)
}
