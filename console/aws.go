package console

import (
	"fmt"
	"time"

	"github.com/BishopFox/cloudfox/utils"
	"github.com/aws/smithy-go/ptr"
	"github.com/fatih/color"
)

const clearln = "\r\x1b[2K"

var (
	cyan  = color.New(color.FgCyan).SprintFunc()
	green = color.New(color.FgGreen).SprintFunc()
)

type CommandCounter struct {
	Total     int
	Pending   int
	Complete  int
	Error     int
	Executing int
}

func SpinUntil(callingModuleName string, counter *CommandCounter, done chan bool, spinType string) {
	defer close(done)
	for {
		select {
		case <-time.After(1 * time.Second):
			fmt.Printf(clearln+"[%s] Status: %d/%d %s complete (%d errors -- For details check %s)", cyan(callingModuleName), counter.Complete, counter.Total, spinType, counter.Error, fmt.Sprintf("%s/cloudfox-error.log", ptr.ToString(utils.GetLogDirPath())))
		case <-done:
			fmt.Printf(clearln+"[%s] Status: %d/%d %s complete (%d errors -- For details check %s)\n", cyan(callingModuleName), counter.Complete, counter.Complete, spinType, counter.Error, fmt.Sprintf("%s/cloudfox-error.log", ptr.ToString(utils.GetLogDirPath())))
			done <- true
			return
		}
	}
}
