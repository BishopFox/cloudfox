package internal

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/BishopFox/cloudfox/globals"
)

func TestOutput2(t *testing.T) {

	tables := []TableFile{
		{
			Name:   "TableFile1",
			Header: []string{"Service", "Status"},
			Body: [][]string{
				{"IAM", "Active"},
				{"EC2", "Not Active"},
				{"Lambda", "Active"},
				{"S3", "Not Active"},
			},
		},
		{
			Name:   "TableFile2",
			Header: []string{"Resource", "Condition"},
			Body: [][]string{
				{"ACR", "Good"},
				{"AKS", "Bad"},
				{"Storage Account", "Bad"},
				{"Databricks", "Good"},
			},
		},
	}

	lootFiles := []LootFile{
		{
			Name:        "loot1",
			FilePointer: nil,
			Contents:    "This is a loot file\nline1\nline2\n",
		},
		{
			Name:        "loot2",
			FilePointer: nil,
			Contents:    "This is a loot file\nline1\nline2\nline3\nline4\n",
		},
		{
			Name:        "loot3",
			FilePointer: nil,
			Contents:    "This is a loot file\nline1\nline2\nline3\n",
		},
	}

	o := OutputClient{
		Verbosity:        3,
		CallingModule:    "testModule",
		PrefixIdentifier: "DEV",
		Table: TableClient{
			Wrap:          false,
			DirectoryName: filepath.Join(globals.CLOUDFOX_BASE_DIRECTORY, globals.AZ_DIR_BASE),
		},
		Loot: LootClient{
			DirectoryName: filepath.Join(globals.CLOUDFOX_BASE_DIRECTORY, globals.AZ_DIR_BASE, "loot"),
			LootFiles:     nil,
		},
	}

	MockFileSystem(false)
	fmt.Printf("Verbose level: %d", o.Verbosity)
	o.WriteFullOutput(tables, lootFiles)
}
