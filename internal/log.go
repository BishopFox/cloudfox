package internal

import (
	"log"
	"fmt"
	"os"
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
			log.Printf("[-] Failed to read or create cloudfox directory")
			dir, err = os.Getwd()
			return ptr.String(dir)
		}
	}
	return ptr.String(dir)
}

type Logger struct {
	version string
	module string
	txtLog *logrus.Logger
	Cyan func(...interface{}) string
	Red func(...interface{}) string
	Green func(...interface{}) string
	Yellow func(...interface{}) string
}

func NewLogger(module string) *Logger {
	lootLogger := logrus.New()
	logDirPath := GetLogDirPath()
	logFile, err := os.OpenFile(filepath.Join(*logDirPath, "cloudfox.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic("Could not initiate logger")
	}
	lootLogger.Out = logFile
	lootLogger.SetLevel(logrus.InfoLevel)
	var logger = Logger{
		version: globals.CLOUDFOX_VERSION,
		txtLog: lootLogger,
		module: module,
		Cyan: color.New(color.FgCyan).SprintFunc(),
		Red: color.New(color.FgRed).SprintFunc(),
		Green:color.New(color.FgGreen).SprintFunc(),
		Yellow: color.New(color.FgYellow).SprintFunc(),
	}
	return &logger
}


func (l *Logger) Print(categories []string, color func(...interface{}) string, text string) {
	formatString := text
	formatArgs := []any{}
	l.Printf(categories, color, formatString, formatArgs...)
}

func (l *Logger) Printf(categories []string, color func(...interface{}) string, format string, params ...any) {
	formatString := ""
	formatArgs := []any{}
	blocks := []string{}
	blocks = append(blocks, categories...)
	for _, block := range blocks {
		formatString += "[%s]"
		formatArgs = append(formatArgs, color(block))
	}
	for _, param := range params {
		formatArgs = append(formatArgs, color(param))
	}
	formatString += " " + format + "\n"

	fmt.Printf(formatString, formatArgs...)
}

func (l *Logger) Announce(categories []string, text string) {
	l.Print(append([]string{emoji.Sprintf(":fox:cloudfox v%s :fox:", l.version), l.module}, categories...), l.Cyan, text)
}

func (l *Logger) Announcef(categories []string, format string, params ...any) {
	l.Printf(append([]string{emoji.Sprintf(":fox:cloudfox v%s :fox:", l.version), l.module}, categories...), l.Cyan, format, params...)
}

func (l *Logger) Info(categories []string, text string) {
	l.Print(append([]string{l.module}, categories...), l.Cyan, text)
}

func (l *Logger) Infof(categories []string, format string, params ...any) {
	l.Printf(append([]string{l.module}, categories...), l.Cyan, format, params...)
}

func (l *Logger) Success(categories []string, text string) {
	l.Print(append([]string{l.module}, categories...), l.Green, text)
}

func (l *Logger) Successf(categories []string, format string, params ...any) {
	l.Printf(append([]string{l.module}, categories...), l.Green, format, params...)
}

func (l *Logger) Warn(categories []string, text string) {
	l.Print(append([]string{l.module}, categories...), l.Yellow, text)
}

func (l *Logger) Warnf(categories []string, format string, params ...any) {
	l.Printf(append([]string{l.module}, categories...), l.Yellow, format, params...)
}

func (l *Logger) Error(categories []string, text string) {
	l.Print(append([]string{l.module}, categories...), l.Red, text)
}

func (l *Logger) Errorf(categories []string, format string, params ...any) {
	l.Printf(append([]string{l.module}, categories...), l.Red, format, params...)
}

func (l *Logger) Fatal(categories []string, text string) {
	l.Print(append([]string{emoji.Sprintf(":fox:cloudfox v%s :fox:", l.version), l.module}, categories...), l.Red, text)
}

func (l *Logger) Fatalf(categories []string, format string, params ...any) {
	l.Printf(append([]string{emoji.Sprintf(":fox:cloudfox v%s :fox:", l.version), l.module}, categories...), l.Red, format, params...)
	panic(nil)
}
