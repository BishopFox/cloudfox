package utils

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"

	"github.com/aquasecurity/table"
	"github.com/aws/smithy-go/ptr"
	"github.com/fatih/color"
	"github.com/spf13/afero"
)

// Used for file system mocking with Afero library. Set:
// fileSystem = afero.NewOsFs() if not unit testing (code will use real file system) OR
// fileSystem = afero.NewMemMapFs() for a mocked file system (when unit testing)
var fileSystem = afero.NewOsFs()

// Color functions
var cyan = color.New(color.FgCyan).SprintFunc()

// This struct is here to mantain compatibility with legacy cloudfox code
type OutputData2 struct {
	Headers       []string
	Body          [][]string
	FilePath      string
	FullFilename  string
	CallingModule string
	Verbosity     int
	Directory     string
}

// verbosity = 1 (Output and loot printed to file).
// verbosity = 2 (Output and loot printed to file, output printed screen).
// verbosity = 3 (Output and loot printed to file and screen).
// outputType = "table", "csv"
// prefixIdentifier = this string gets printed with control message calling module (e.g. aws profile, azure resource group, gcp project, etc)
func OutputSelector(verbosity int, outputType string, header []string, body [][]string, outputDirectory string, fileNameWithoutExtenstion string, callingModule string, prefixIdentifier string) {

	switch verbosity {
	case 2:
		PrintTableToScreen(header, body)
	case 3:
		PrintTableToScreen(header, body)
		// Add writeLootToScreen function here
	}
	switch outputType {
	case "table":
		outputFileTable := createOutputFile(
			ptr.String(filepath.Join(outputDirectory, "table")),
			ptr.String(fmt.Sprintf("%s.txt", fileNameWithoutExtenstion)),
			outputType,
			callingModule)
		printTableToFile(header, body, outputFileTable)
		fmt.Printf("[%s][%s] Output written to [%s]\n", cyan(callingModule), cyan(prefixIdentifier), outputFileTable.Name())
		// Add writeLootToFile function here

	case "csv":
		outputFileCSV := createOutputFile(
			ptr.String(filepath.Join(outputDirectory, "csv")),
			ptr.String(fmt.Sprintf("%s.csv", fileNameWithoutExtenstion)),
			outputType,
			callingModule)
		printCSVtoFile(header, body, outputFileCSV)
		fmt.Printf("[%s][%s] Output written to [%s]\n", cyan(callingModule), cyan(prefixIdentifier), outputFileCSV.Name())
		// Add writeLootToFile function here

	default:
		outputFileTable := createOutputFile(
			ptr.String(filepath.Join(outputDirectory, "table")),
			ptr.String(fmt.Sprintf("%s.txt", fileNameWithoutExtenstion)),
			outputType,
			callingModule)
		printTableToFile(header, body, outputFileTable)
		fmt.Printf("[%s][%s] Output written to [%s]\n", cyan(callingModule), cyan(prefixIdentifier), outputFileTable.Name())

		outputFileCSV := createOutputFile(
			ptr.String(filepath.Join(outputDirectory, "csv")),
			ptr.String(fmt.Sprintf("%s.csv", fileNameWithoutExtenstion)),
			outputType,
			callingModule)
		printCSVtoFile(header, body, outputFileCSV)
		fmt.Printf("[%s][%s] Output written to [%s]\n", cyan(callingModule), cyan(prefixIdentifier), outputFileCSV.Name())
		// Add writeLootToFile function here
	}

}

func printCSVtoFile(header []string, body [][]string, outputFile afero.File) {
	csvWriter := csv.NewWriter(outputFile)
	csvWriter.Write(header)
	for _, row := range body {
		csvWriter.Write(row)
	}
	csvWriter.Flush()
}

func printTableToFile(header []string, body [][]string, outputFile afero.File) {
	t := table.New(outputFile)
	t.SetColumnMaxWidth(1000)
	t.SetHeaders(header...)
	t.AddRows(body...)
	t.SetRowLines(false)
	t.SetDividers(table.UnicodeRoundedDividers)
	t.Render()
}

func PrintTableToScreen(header []string, body [][]string) {
	t := table.New(os.Stdout)
	// ColumnMaxWidth needs to be set as a large value so the table doesn't wrap.
	// If the table wraps it's hard to grep the output from the terminal.
	// TO-DO: add a flag to make this optional.
	t.SetColumnMaxWidth(1000)
	t.SetHeaders(header...)
	t.AddRows(body...)
	t.SetHeaderStyle(table.StyleBold)
	t.SetRowLines(false)
	t.SetLineStyle(table.StyleCyan)
	t.SetDividers(table.UnicodeRoundedDividers)
	t.Render()
}

// The Afero library enables file system mocking:
// fileSystem = afero.NewOsFs() if not unit testing (real file system) OR
// fileSystem = afero.NewMemMapFs() for a mocked file system (when unit testing)
// outputDirectory = nil (creates the file in the current directory ".")
func createOutputFile(outputDirectory *string, fileName *string, outputType string, callingModule string) afero.File {

	if outputDirectory == nil {
		outputDirectory = ptr.String(".")
	}

	if _, err := fileSystem.Stat(ptr.ToString(outputDirectory)); os.IsNotExist(err) {
		err = fileSystem.MkdirAll(ptr.ToString(outputDirectory), 0700)
		if err != nil {
			log.Fatal(err)
		}
	}
	if fileName == nil {
		log.Fatalf("Error creating output file because no file name was specified")
	}
	outputFile, err := fileSystem.OpenFile(path.Join(ptr.ToString(outputDirectory), ptr.ToString(fileName)), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		log.Fatalf("error creating output file: %s", err)
	}
	//fmt.Printf("[%s] Creating output file: %s\n", cyan(callingModule), outputFile.Name())
	return outputFile
}

func MockFileSystem(switcher bool) {
	if switcher {
		fmt.Println("Using mocked file system")
		fileSystem = afero.NewMemMapFs()
	} else {
		fmt.Println("Using OS file system. Make sure to clean up your disk!")
	}
}
