package sdk

import (
	"log"
	"os"

	"github.com/BishopFox/cloudfox/internal"
)

var sharedLogger = internal.TxtLogger()

func readTestFile(testFile string) []byte {
	file, err := os.ReadFile(testFile)
	if err != nil {
		log.Fatalf("can't read file %s", testFile)
	}
	return file
}
