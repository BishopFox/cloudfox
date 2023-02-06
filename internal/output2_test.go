package internal

import (
	"testing"
)

func TestOutput2(t *testing.T) {
	outputFileHeader := []string{"Service", "Status"}

	outputFileBody := [][]string{
		{"IAM", "Active"},
		{"EC2", "Not Active"},
		{"Lambda", "Active"},
		{"S3", "Not Active"},
	}

	lootFiles := map[fileName][]fileContents{
		"FileName1": {"line1", "line2"},
		"FileName2": {"line1", "line2", "line3", "line4"},
	}

	o := OutputClient{
		Verbosity:        2,
		CallingModule:    "testModule",
		PrefixIdentifier: "customIdentifier",
		Base: BaseClient{
			WrapTable:     true,
			Format:        "table",
			FileName:      "callingModule",
			DirectoryName: "baseOutputDirectory",
		},
		Loot: LootClient{
			DirectoryName: "lootOutputDirectory",
		},
	}

	o.WriteFullOutput(outputFileHeader, outputFileBody, lootFiles)
}
