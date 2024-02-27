package internal

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/aquasecurity/table"
	"github.com/fatih/color"
	"github.com/spf13/afero"
)

// Used for file system mocking with Afero library. Set:
// fileSystem = afero.NewOsFs() if not unit testing (code will use real file system) OR
// fileSystem = afero.NewMemMapFs() for a mocked file system (when unit testing)
var fileSystem = afero.NewOsFs()

// Color functions
var cyan = color.New(color.FgCyan).SprintFunc()

type OutputClient struct {
	Verbosity        int
	CallingModule    string
	PrefixIdentifier string
	Table            TableClient
	Loot             LootClient
}

type TableClient struct {
	Wrap          bool
	DirectoryName string
	TableFiles    []TableFile
}

type TableFile struct {
	Name              string
	TableFilePointer  afero.File
	CSVFilePointer    afero.File
	JSONFilePointer   afero.File
	TableCols         []string
	Header            []string
	Body              [][]string
	SkipPrintToScreen bool
}

type LootClient struct {
	DirectoryName string
	LootFiles     []LootFile
}

type LootFile struct {
	Name        string
	FilePointer afero.File
	Contents    string
}

func removeColorCodes(input string) string {
	// Regular expression to match ANSI color codes
	ansiRegExp := regexp.MustCompile(`\x1b\[[0-9;]*m`)
	return ansiRegExp.ReplaceAllString(input, "")
}

func removeColorCodesFromSlice(input []string) []string {
	// Regular expression to match ANSI color codes
	ansiRegExp := regexp.MustCompile(`\x1b\[[0-9;]*m`)

	// Create a new slice to store the strings with color codes removed
	noColorSlice := make([]string, len(input))

	for i, str := range input {
		noColorSlice[i] = ansiRegExp.ReplaceAllString(str, "")
	}

	return noColorSlice
}

func removeColorCodesFromNestedSlice(input [][]string) [][]string {
	// Regular expression to match ANSI color codes
	ansiRegExp := regexp.MustCompile(`\x1b\[[0-9;]*m`)

	// Create a new slice to store the slices with color codes removed
	noColorNestedSlice := make([][]string, len(input))

	for i, strSlice := range input {
		noColorNestedSlice[i] = make([]string, len(strSlice))
		for j, str := range strSlice {
			noColorNestedSlice[i][j] = ansiRegExp.ReplaceAllString(str, "")
		}
	}

	return noColorNestedSlice
}

func (o *OutputClient) WriteFullOutput(tables []TableFile, lootFiles []LootFile) {

	switch o.Verbosity {
	case 2:
		o.Table.printTablesToScreen(tables)
	case 3:
		o.Table.printTablesToScreen(tables)
		fmt.Println()
		if lootFiles != nil {
			o.Loot.printLoottoScreen(lootFiles)
		}
	}

	o.Table.createTableFiles(tables)
	tableOutputPaths := o.Table.writeTableFiles(tables)
	o.Table.createCSVFiles()
	csvOutputPaths := o.Table.writeCSVFiles()
	o.Table.createJSONFiles()
	jsonOutputPaths := o.Table.writeJSONFiles()
	var outputPaths []string
	outputPaths = append(outputPaths, tableOutputPaths...)
	outputPaths = append(outputPaths, csvOutputPaths...)
	outputPaths = append(outputPaths, jsonOutputPaths...)

	if lootFiles != nil {
		o.Loot.createLootFiles(lootFiles)
		lootOutputPaths := o.Loot.writeLootFiles()
		outputPaths = append(outputPaths, lootOutputPaths...)
	}

	for _, path := range outputPaths {
		fmt.Printf("[%s][%s] Output written to %s\n", cyan(o.CallingModule), cyan(o.PrefixIdentifier), path)
	}
}

func (l *LootClient) printLoottoScreen(lootFiles []LootFile) {
	for _, file := range lootFiles {
		fmt.Println(file.Contents)
	}
}

func (l *LootClient) createLootFiles(lootFiles []LootFile) {
	l.LootFiles = lootFiles

	for i, file := range l.LootFiles {
		if l.DirectoryName == "" {
			l.DirectoryName = "."
		}

		lootDirectory := path.Join(l.DirectoryName, "loot")

		if _, err := fileSystem.Stat(lootDirectory); os.IsNotExist(err) {
			err = fileSystem.MkdirAll(lootDirectory, 0700)
			if err != nil {
				log.Fatal(err)
			}
		}
		if file.Name == "" {
			log.Fatalf("error creating loot file: no file name was specified")
		}

		l.LootFiles[i].Name = fmt.Sprintf("%s.txt", file.Name)

		filePointer, err := fileSystem.OpenFile(path.Join(lootDirectory, l.LootFiles[i].Name), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			log.Fatalf("error creating output file: %s", err)
		}

		l.LootFiles[i].FilePointer = filePointer
	}
}

func (l *LootClient) writeLootFiles() []string {
	var fullFilePaths []string
	for _, file := range l.LootFiles {
		contents := []byte(file.Contents)
		fullPath := path.Join(l.DirectoryName, "loot", file.Name)
		err := afero.WriteFile(fileSystem, fullPath, contents, 0644) // Use Afero's WriteFile
		if err != nil {
			log.Fatalf("error writing loot file %s: %s", file.Name, err)
		}
		fullFilePaths = append(fullFilePaths, fullPath)
	}
	return fullFilePaths
}

func (b *TableClient) printTablesToScreen(tableFiles []TableFile) {
	for _, tf := range tableFiles {
		if tf.SkipPrintToScreen {
			continue
		}
		tf.Body, tf.Header = adjustBodyForTable(tf.TableCols, tf.Header, tf.Body)
		standardColumnWidth := 1000
		t := table.New(os.Stdout)

		if !b.Wrap {
			t.SetColumnMaxWidth(standardColumnWidth)
		}

		//t.SetColumnMaxWidth(standardColumnWidth)
		t.SetHeaders(tf.Header...)
		t.AddRows(tf.Body...)
		t.SetHeaderStyle(table.StyleBold)
		t.SetRowLines(false)
		t.SetLineStyle(table.StyleCyan)
		t.SetDividers(table.UnicodeRoundedDividers)
		t.SetAlignment(table.AlignLeft)
		t.Render()
	}
}

func (b *TableClient) createTableFiles(files []TableFile) {
	b.TableFiles = files

	for i, file := range b.TableFiles {
		if b.DirectoryName == "" {
			b.DirectoryName = "."
		}

		tableDirectory := path.Join(b.DirectoryName, "table")

		if _, err := fileSystem.Stat(tableDirectory); os.IsNotExist(err) {
			err = fileSystem.MkdirAll(tableDirectory, 0700)
			if err != nil {
				log.Fatal(err)
			}
		}

		if file.Name == "" {
			log.Fatalf("error creating table file: no file name was specified")
		}

		fileNameWithExt := fmt.Sprintf("%s.txt", file.Name)

		filePointer, err := fileSystem.OpenFile(path.Join(tableDirectory, fileNameWithExt), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			log.Fatalf("error creating table file: %s", err)
		}

		b.TableFiles[i].TableFilePointer = filePointer
	}
}

func (b *TableClient) writeTableFiles(files []TableFile) []string {
	var fullFilePaths []string

	for _, file := range b.TableFiles {
		file.Body, file.Header = adjustBodyForTable(file.TableCols, file.Header, file.Body)
		standardColumnWidth := 1000
		t := table.New(file.TableFilePointer)

		if !b.Wrap {
			t.SetColumnMaxWidth(standardColumnWidth)
		}

		t.SetHeaders(file.Header...)
		file.Body = removeColorCodesFromNestedSlice(file.Body)
		t.AddRows(file.Body...)
		t.SetRowLines(false)
		t.SetDividers(table.UnicodeRoundedDividers)
		t.SetAlignment(table.AlignLeft)
		t.Render()

		fullPath := path.Join(b.DirectoryName, "table", fmt.Sprintf("%s.txt", file.Name))
		fullFilePaths = append(fullFilePaths, fullPath)
	}

	return fullFilePaths
}

func (b *TableClient) createCSVFiles() {
	for i, file := range b.TableFiles {
		if b.DirectoryName == "" {
			b.DirectoryName = "."
		}

		csvDirectory := path.Join(b.DirectoryName, "csv")

		if _, err := fileSystem.Stat(csvDirectory); os.IsNotExist(err) {
			err = fileSystem.MkdirAll(csvDirectory, 0700)
			if err != nil {
				log.Fatal(err)
			}
		}

		if file.Name == "" {
			log.Fatalf("error creating csv file: no file name was specified")
		}

		fileNameWithExt := fmt.Sprintf("%s.csv", file.Name)

		filePointer, err := fileSystem.OpenFile(path.Join(csvDirectory, fileNameWithExt), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			log.Fatalf("error creating csv file: %s", err)
		}

		b.TableFiles[i].CSVFilePointer = filePointer
	}
}

func (b *TableClient) writeCSVFiles() []string {
	var fullFilePaths []string

	for _, file := range b.TableFiles {
		csvWriter := csv.NewWriter(file.CSVFilePointer)
		csvWriter.Write(file.Header)
		for _, row := range file.Body {
			row = removeColorCodesFromSlice(row)
			//row = removeNewLinesFromSlice(row)

			csvWriter.Write(row)
		}
		csvWriter.Flush()

		fullPath := path.Join(b.DirectoryName, "csv", fmt.Sprintf("%s.csv", file.Name))
		fullFilePaths = append(fullFilePaths, fullPath)
	}

	return fullFilePaths
}

// replace newlines in row to make them csv and json safe
func removeNewLinesFromNestedSlice(input [][]string) [][]string {
	// Regular expression to match new lines
	newLineRegExp := regexp.MustCompile(`\n`)

	// Create a new slice to store the slices with new lines removed
	noNewLineNestedSlice := make([][]string, len(input))

	for i, strSlice := range input {
		noNewLineNestedSlice[i] = make([]string, len(strSlice))
		for j, str := range strSlice {
			noNewLineNestedSlice[i][j] = newLineRegExp.ReplaceAllString(str, "")
		}
	}

	return noNewLineNestedSlice
}

// replace newlines in slice of strings to make them render as newlines in csv and json when opened in excel
func removeNewLinesFromSlice(input []string) []string {
	// Regular expression to match new lines
	newLineRegExp := regexp.MustCompile(`\n`)

	// Create a new slice to store the strings with new lines removed
	noNewLineSlice := make([]string, len(input))

	for i, str := range input {
		noNewLineSlice[i] = newLineRegExp.ReplaceAllString(str, " \\n")
	}

	return noNewLineSlice
}

func (b *TableClient) createJSONFiles() {
	for i, file := range b.TableFiles {
		if b.DirectoryName == "" {
			b.DirectoryName = "."
		}

		jsonDirectory := path.Join(b.DirectoryName, "json")

		if _, err := fileSystem.Stat(jsonDirectory); os.IsNotExist(err) {
			err = fileSystem.MkdirAll(jsonDirectory, 0700)
			if err != nil {
				log.Fatal(err)
			}
		}

		if file.Name == "" {
			log.Fatalf("error creating json file: no file name was specified")
		}

		fileNameWithExt := fmt.Sprintf("%s.json", file.Name)

		filePointer, err := fileSystem.OpenFile(path.Join(jsonDirectory, fileNameWithExt), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			log.Fatalf("error creating json file: %s", err)
		}

		b.TableFiles[i].JSONFilePointer = filePointer
	}
}

// func (b *TableClient) writeJSONFiles() []string {
// 	var fullFilePaths []string

// 	for _, file := range b.TableFiles {
// 		file.Body = removeColorCodesFromNestedSlice(file.Body)
// 		jsonBytes, err := json.Marshal(file.Body)
// 		if err != nil {
// 			log.Fatalf("error marshalling json: %s", err)
// 		}

// 		_, err = file.JSONFilePointer.Write(jsonBytes)
// 		if err != nil {
// 			log.Fatalf("error writing json: %s", err)
// 		}

// 		fullPath := path.Join(b.DirectoryName, "json", fmt.Sprintf("%s.json", file.Name))
// 		fullFilePaths = append(fullFilePaths, fullPath)
// 	}

// 	return fullFilePaths
// }

func (b *TableClient) writeJSONFiles() []string {
	var fullFilePaths []string

	for _, file := range b.TableFiles {
		file.Body = removeColorCodesFromNestedSlice(file.Body)
		jsonData := make([]map[string]string, len(file.Body))
		for i, row := range file.Body {
			jsonData[i] = make(map[string]string)
			for j, column := range row {
				jsonData[i][file.Header[j]] = column
			}
		}

		jsonBytes, err := json.MarshalIndent(jsonData, "", "  ")
		if err != nil {
			fmt.Println("error marshalling json:", err)
		}

		_, err = file.JSONFilePointer.Write(jsonBytes)
		if err != nil {
			log.Fatalf("error writing json: %s", err)
		}

		fullPath := path.Join(b.DirectoryName, "json", fmt.Sprintf("%s.json", file.Name))
		fullFilePaths = append(fullFilePaths, fullPath)
	}

	return fullFilePaths
}

func adjustBodyForTable(tableHeaders []string, fullHeaders []string, fullBody [][]string) ([][]string, []string) {
	if tableHeaders == nil || len(tableHeaders) == 0 {
		return fullBody, fullHeaders
	}

	columnIndices := make([]int, 0)
	selectedHeaders := make([]string, 0)

	for _, tableHeader := range tableHeaders {
		for j, fullHeader := range fullHeaders {
			if strings.ToLower(tableHeader) == strings.ToLower(fullHeader) {
				columnIndices = append(columnIndices, j)
				selectedHeaders = append(selectedHeaders, fullHeader)
				break
			}
		}
	}

	adjustedBody := make([][]string, len(fullBody))
	for i, row := range fullBody {
		newRow := make([]string, len(columnIndices))
		for k, index := range columnIndices {
			newRow[k] = row[index]
		}
		adjustedBody[i] = newRow
	}

	return adjustedBody, selectedHeaders
}
