package internal

import (
	"fmt"

	"github.com/spf13/afero"
)

type fileName string
type fileContents string
type statusMessage string

// Verbosity = 1 (Output and loot printed to file).
// Verbosity = 2 (Output and loot printed to file, output printed screen).
// Verbosity = 3 (Output and loot printed to file and screen).

type OutputClient struct {
	Verbosity        int
	CallingModule    string
	PrefixIdentifier string
	Base             BaseClient
	Loot             LootClient
}

func (o *OutputClient) WriteFullOutput(header []string, body [][]string, lootFiles map[fileName][]fileContents) []statusMessage {
	if o.Verbosity == 2 && o.Base.Format == "table" {
		o.Base.printTabletoScreen(header, body)

	} else if o.Verbosity == 2 && o.Base.Format == "csv" {
		o.Base.printCSVtoScreen(header, body)

	} else if o.Verbosity == 3 && o.Base.Format == "table" {
		o.Base.printTabletoScreen(header, body)
		o.Loot.printLoottoScreen(lootFiles)

	} else if o.Verbosity == 3 && o.Base.Format == "csv" {
		o.Base.printCSVtoScreen(header, body)
		o.Loot.printLoottoScreen(lootFiles)
	}

	outputFileTable := o.Base.createTableFile(o.Base.DirectoryName, o.Base.FileName)
	outputFileCSV := o.Base.createCSVFile(o.Base.DirectoryName, o.Base.FileName)
	lootFileList := o.Loot.createLootFiles(lootFiles)

	var statusMessages []statusMessage
	tableOutputFileStatus := o.Base.writeTableFile(header, body, outputFileTable)
	CSVOutputFileStatus := o.Base.writeCSVFile(header, body, outputFileCSV)
	lootFileStatuses := o.Loot.writeLootFiles(lootFiles, lootFileList)

	statusMessages = append(statusMessages, tableOutputFileStatus, CSVOutputFileStatus)
	statusMessages = append(statusMessages, lootFileStatuses...)
	return statusMessages
}

type LootClient struct {
	DirectoryName string
}

func (b *LootClient) printLoottoScreen(lootFiles map[fileName][]fileContents) {
	for fileName, fileContents := range lootFiles {
		fmt.Printf("Printing contents of loot file %s", fileName)
		for _, line := range fileContents {
			fmt.Println(line)
		}
	}
}

func (b *LootClient) createLootFiles(lootFiles map[fileName][]fileContents) []afero.File {
	for fileName, _ := range lootFiles {
		fmt.Printf("Creating file %s", fileName)
	}
	// This will return a pointer to the created file
	return nil
}

func (b *LootClient) writeLootFiles(lootFiles map[fileName][]fileContents, outputFiles []afero.File) []statusMessage {
	for fileName, fileContents := range lootFiles {
		fmt.Printf("Writing contents of loot file %s", fileName)
		for _, line := range fileContents {
			fmt.Println(line)
		}
	}
	return []statusMessage{}
}

type BaseClient struct {
	WrapTable        bool
	Format           string
	PrefixIdentifier string
	FileName         string
	DirectoryName    string
}

func (b *BaseClient) printTabletoScreen(header []string, body [][]string) {

}

func (b *BaseClient) printCSVtoScreen(header []string, body [][]string) {

}

func (b *BaseClient) createTableFile(outputDirectory, fileName string) afero.File {
	return nil
}

func (b *BaseClient) writeTableFile(header []string, body [][]string, outputFile afero.File) statusMessage {
	return statusMessage("")
}

func (b *BaseClient) createCSVFile(outputDirectory, fileName string) afero.File {
	return nil
}

func (b *BaseClient) writeCSVFile(header []string, body [][]string, outputFile afero.File) statusMessage {
	return statusMessage("")
}
