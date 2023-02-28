package internal

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"

	"github.com/aquasecurity/table"
	"github.com/aws/smithy-go/ptr"
	"github.com/spf13/afero"
	"golang.org/x/crypto/ssh/terminal"
)

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
func OutputSelector(verbosity int, outputType string, header []string, body [][]string, outputDirectory string, fileName string, callingModule string, wrapTable bool, prefixIdentifier string) {

	switch verbosity {
	case 2:
		PrintTableToScreen(header, body, wrapTable)
	case 3:
		PrintTableToScreen(header, body, wrapTable)
		// Add writeLootToScreen function here
	}
	switch outputType {
	case "table":
		fmt.Println("")
		outputFileTable := createOutputFile(
			ptr.String(filepath.Join(outputDirectory, "table")),
			ptr.String(fmt.Sprintf("%s.txt", fileName)),
			outputType,
			callingModule)
		printTableToFile(header, body, outputFileTable)
		fmt.Printf("[%s][%s] Output written to [%s]\n", cyan(callingModule), cyan(prefixIdentifier), outputFileTable.Name())
		// Add writeLootToFile function here

	case "csv":
		outputFileCSV := createOutputFile(
			ptr.String(filepath.Join(outputDirectory, "csv")),
			ptr.String(fmt.Sprintf("%s.csv", fileName)),
			outputType,
			callingModule)
		printCSVtoFile(header, body, outputFileCSV)
		fmt.Printf("[%s][%s] Output written to [%s]\n", cyan(callingModule), cyan(prefixIdentifier), outputFileCSV.Name())
		// Add writeLootToFile function here

	default:
		outputFileTable := createOutputFile(
			ptr.String(filepath.Join(outputDirectory, "table")),
			ptr.String(fmt.Sprintf("%s.txt", fileName)),
			outputType,
			callingModule)
		printTableToFile(header, body, outputFileTable)
		fmt.Printf("[%s][%s] Output written to [%s]\n", cyan(callingModule), cyan(prefixIdentifier), outputFileTable.Name())

		outputFileCSV := createOutputFile(
			ptr.String(filepath.Join(outputDirectory, "csv")),
			ptr.String(fmt.Sprintf("%s.csv", fileName)),
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
	t.SetHeaders(header...)
	t.AddRows(body...)
	t.SetRowLines(false)
	t.SetDividers(table.UnicodeRoundedDividers)
	t.SetAlignment(table.AlignLeft)
	t.Render()
}

func PrintTableToScreen(header []string, body [][]string, wrapLines bool) {
	standardColumnWidth := 1000
	t := table.New(os.Stdout)
	if wrapLines {
		terminalWidth, _, err := terminal.GetSize(int(os.Stdout.Fd()))
		if err != nil {
			fmt.Println("error getting terminal size:", err)
			return
		}
		columnCount := len(header)
		// The offset value was defined by trial and error to get the best wrapping
		trialAndErrorOffset := 1
		standardColumnWidth = terminalWidth / (columnCount + trialAndErrorOffset)
	}
	t.SetColumnMaxWidth(standardColumnWidth)
	t.SetHeaders(header...)
	t.AddRows(body...)
	t.SetHeaderStyle(table.StyleBold)
	t.SetRowLines(false)
	t.SetLineStyle(table.StyleCyan)
	t.SetDividers(table.UnicodeRoundedDividers)
	t.SetAlignment(table.AlignLeft)
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

func MockFileSystem(switcher bool) afero.Fs {
	if switcher {
		fmt.Println("Using mocked file system")
		fileSystem = afero.NewMemMapFs()
		return fileSystem
	} else {
		fmt.Println("Using OS file system. Make sure to clean up your disk!")
		fileSystem = afero.NewOsFs()
		return fileSystem
	}
}
