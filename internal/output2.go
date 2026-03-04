package internal

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

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

// global lock to prevent concurrent write races
var lootFileMu sync.Mutex

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

// TableCol represents a column definition for table output
type TableCol struct {
	Name  string
	Width int
}

// TableFiles represents table output configuration
type TableFiles struct {
	Directory   string
	TableCols   []TableCol
	ResultsFile string
	LootFile    string
}

// TODO support datastructures that enable brief or wide format
type CloudfoxOutput interface {
	TableFiles() []TableFile
	LootFiles() []LootFile
}

// HandleOutput dynamically handles the output based on the provided arguments.
// TODO support brief of wide
func HandleOutput(
	cloudProvider string,
	format string,
	outputDirectory string,
	verbosity int,
	wrap bool,
	baseCloudfoxModule string,
	principal string,
	resultsIdentifier string,
	dataToOutput CloudfoxOutput,
) error {
	// Update OutputClient fields based on arguments
	outDirectoryPath := filepath.Join(outputDirectory, "cloudfox-output", cloudProvider, fmt.Sprintf("%s-%s", principal, resultsIdentifier), baseCloudfoxModule)
	tables := dataToOutput.TableFiles()
	lootFiles := dataToOutput.LootFiles()

	outputClient := OutputClient{
		Verbosity:     verbosity,
		CallingModule: baseCloudfoxModule,
		Table: TableClient{
			Wrap:          wrap,
			DirectoryName: outDirectoryPath,
			TableFiles:    tables,
		},
		Loot: LootClient{
			DirectoryName: outDirectoryPath,
			LootFiles:     lootFiles,
		},
	}

	// Handle output based on the verbosity level
	outputClient.WriteFullOutput(tables, lootFiles)
	return nil
}

// HandleStreamingOutput writes table and loot files incrementally, then finalizes tables at the end.
// Uses the new directory structure: cloudfox-output/{CloudProvider}/{Principal}/{ScopeIdentifier}/
func HandleStreamingOutput(
	cloudProvider string,
	format string,
	outputDirectory string,
	verbosity int,
	wrap bool,
	scopeType string,
	scopeIdentifiers []string,
	scopeNames []string,
	principal string,
	dataToOutput CloudfoxOutput,
) error {
	logger := NewLogger()

	// Build scope identifier using same logic as HandleOutputSmart
	resultsIdentifier := buildResultsIdentifier(scopeType, scopeIdentifiers, scopeNames)

	// Determine base module name from first table file (for backwards compatibility)
	baseCloudfoxModule := ""
	if len(dataToOutput.TableFiles()) > 0 {
		baseCloudfoxModule = dataToOutput.TableFiles()[0].Name
	}

	// Build consistent output path using NEW structure
	outDirectoryPath := filepath.Join(
		outputDirectory,
		"cloudfox-output",
		cloudProvider,
		principal,
		resultsIdentifier,
	)

	if err := os.MkdirAll(outDirectoryPath, 0o755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// ---- STREAM ROWS TO TEMP FILES ----
	for _, t := range dataToOutput.TableFiles() {
		if verbosity > 0 {
			tmpClient := TableClient{Wrap: wrap}
			tmpClient.printTablesToScreen([]TableFile{t})
		}

		safeName := sanitizeFileName(t.Name)
		tmpTablePath := filepath.Join(outDirectoryPath, safeName+".tmp")
		if err := os.MkdirAll(filepath.Dir(tmpTablePath), 0o755); err != nil {
			return fmt.Errorf("failed to create parent directory for temp table: %w", err)
		}

		tmpTableFile, err := os.OpenFile(tmpTablePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("failed to open temporary table file: %w", err)
		}
		defer tmpTableFile.Close()

		// Append each row into the tmp file
		for _, row := range t.Body {
			cleanRow := removeColorCodesFromSlice(row)
			if _, err := tmpTableFile.WriteString(strings.Join(cleanRow, ",") + "\n"); err != nil {
				return fmt.Errorf("failed to append row to tmp table: %w", err)
			}
		}

		// Stream CSV rows
		if format == "all" || format == "csv" {
			csvPath := filepath.Join(outDirectoryPath, "csv", safeName+".csv")
			if err := os.MkdirAll(filepath.Dir(csvPath), 0o755); err != nil {
				return fmt.Errorf("failed to create csv directory: %w", err)
			}
			csvFile, err := os.OpenFile(csvPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				return fmt.Errorf("failed to open csv file: %w", err)
			}
			defer csvFile.Close()

			info, _ := csvFile.Stat()
			if info.Size() == 0 {
				_, _ = csvFile.WriteString(strings.Join(t.Header, ",") + "\n")
			}
			for _, row := range t.Body {
				cleanRow := removeColorCodesFromSlice(row)
				_, _ = csvFile.WriteString(strings.Join(cleanRow, ",") + "\n")
			}
		}

		// Stream JSONL rows
		if format == "all" || format == "json" {
			if err := AppendJSONL(outDirectoryPath, t); err != nil {
				return fmt.Errorf("failed to append JSONL: %w", err)
			}
		}
	}

	// ---- STREAM LOOT ----
	for _, l := range dataToOutput.LootFiles() {
		lootDir := filepath.Join(outDirectoryPath, "loot")
		if err := os.MkdirAll(lootDir, 0o755); err != nil {
			return fmt.Errorf("failed to create loot directory: %w", err)
		}

		lootPath := filepath.Join(lootDir, l.Name+".txt")
		lootFile, err := os.OpenFile(lootPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("failed to open loot file: %w", err)
		}
		defer lootFile.Close()

		scanner := bufio.NewScanner(strings.NewReader(l.Contents))
		for scanner.Scan() {
			if _, err := lootFile.WriteString(scanner.Text() + "\n"); err != nil {
				return fmt.Errorf("failed to append loot line: %w", err)
			}
		}
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("error reading loot lines: %w", err)
		}
	}

	// ---- FINALIZE TABLES MEMORY-SAFE ----
	if err := StreamFinalizeTables(cloudProvider, format, outputDirectory, verbosity, wrap, scopeType, scopeIdentifiers, scopeNames, principal, nil); err != nil {
		return fmt.Errorf("failed to finalize tables: %w", err)
	}

	// Log individual output files like the non-streaming output does
	for _, t := range dataToOutput.TableFiles() {
		safeName := sanitizeFileName(t.Name)
		if format == "all" || format == "table" {
			logger.InfoM(fmt.Sprintf("Output written to %s", filepath.Join(outDirectoryPath, "table", safeName+".txt")), baseCloudfoxModule)
		}
		if format == "all" || format == "csv" {
			logger.InfoM(fmt.Sprintf("Output written to %s", filepath.Join(outDirectoryPath, "csv", safeName+".csv")), baseCloudfoxModule)
		}
		if format == "all" || format == "json" {
			logger.InfoM(fmt.Sprintf("Output written to %s", filepath.Join(outDirectoryPath, "json", safeName+".jsonl")), baseCloudfoxModule)
		}
	}
	for _, l := range dataToOutput.LootFiles() {
		logger.InfoM(fmt.Sprintf("Output written to %s", filepath.Join(outDirectoryPath, "loot", l.Name+".txt")), baseCloudfoxModule)
	}

	return nil
}

// StreamFinalizeTables writes final tables line-by-line to avoid memory issues.
// It reads each .tmp file and writes it directly to a tab-delimited .txt table.
// Note: does not print a pretty table
// Uses the new directory structure: cloudfox-output/{CloudProvider}/{Principal}/{ScopeIdentifier}/
func StreamFinalizeTables(
	cloudProvider string,
	format string,
	outputDirectory string,
	verbosity int,
	wrap bool,
	scopeType string,
	scopeIdentifiers []string,
	scopeNames []string,
	principal string,
	header []string,
) error {

	// Build scope identifier using same logic as HandleOutputSmart
	resultsIdentifier := buildResultsIdentifier(scopeType, scopeIdentifiers, scopeNames)

	// Build consistent output path using NEW structure
	outDirectoryPath := filepath.Join(
		outputDirectory,
		"cloudfox-output",
		cloudProvider,
		principal,
		resultsIdentifier,
	)

	// Ensure final table directory exists
	tableDir := filepath.Join(outDirectoryPath, "table")
	if err := os.MkdirAll(tableDir, 0o755); err != nil {
		return fmt.Errorf("failed to create table directory: %w", err)
	}

	// Walk the output directory looking for .tmp files
	err := filepath.Walk(outDirectoryPath, func(tmpPath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(info.Name(), ".tmp") {
			return nil
		}

		// Derive final table file name
		baseName := strings.TrimSuffix(info.Name(), ".tmp")
		tablePath := filepath.Join(tableDir, baseName+".txt")

		// Open output .txt for writing
		outFile, err := os.OpenFile(tablePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			return fmt.Errorf("failed to open final table file %s: %w", tablePath, err)
		}
		defer outFile.Close()

		// Write header row
		if len(header) > 0 {
			_, _ = fmt.Fprintln(outFile, strings.Join(header, "\t"))
		}

		// Stream each row from .tmp file line-by-line
		tmpFile, err := os.Open(tmpPath)
		if err != nil {
			return fmt.Errorf("failed to open tmp file %s: %w", tmpPath, err)
		}
		defer tmpFile.Close()

		scanner := bufio.NewScanner(tmpFile)
		for scanner.Scan() {
			line := scanner.Text()
			cols := strings.Split(line, ",")
			// Remove any ANSI color codes
			cols = removeColorCodesFromSlice(cols)
			_, _ = fmt.Fprintln(outFile, strings.Join(cols, "\t"))
		}
		if scanErr := scanner.Err(); scanErr != nil {
			return fmt.Errorf("error scanning tmp file %s: %w", tmpPath, scanErr)
		}

		// Delete the temporary .tmp file after streaming
		_ = os.Remove(tmpPath)

		return nil
	})

	return err
}

// streamRenderTableWithHeader renders a tmp file into a table with a single header row.
func streamRenderTableWithHeader(tmpFilePath string, header []string, outFile *os.File, wrap bool) error {
	t := table.New(outFile)
	if !wrap {
		t.SetColumnMaxWidth(1000)
	}

	if len(header) > 0 {
		t.SetHeaders(header...)
	}

	t.SetRowLines(false)
	t.SetDividers(table.UnicodeRoundedDividers)
	t.SetAlignment(table.AlignLeft)
	t.SetHeaderStyle(table.StyleBold)

	// Stream rows from tmp file
	f, err := os.Open(tmpFilePath)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		row := strings.Split(line, ",")
		t.AddRow(row...)
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	t.Render()
	return nil
}

func AppendCSV(outputDir string, table TableFile) error {
	csvDir := filepath.Join(outputDir, "csv")
	if err := os.MkdirAll(csvDir, 0o755); err != nil {
		return err
	}

	filePath := filepath.Join(csvDir, table.Name+".csv")
	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	writer := csv.NewWriter(f)
	// Only write header if file is new
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Size() == 0 {
		if err := writer.Write(table.Header); err != nil {
			return err
		}
	}

	for _, row := range table.Body {
		row = removeColorCodesFromSlice(row)
		if err := writer.Write(row); err != nil {
			return err
		}
	}
	writer.Flush()
	return writer.Error()
}

func AppendLoot(outputDir string, loot LootFile) error {
	lootDir := filepath.Join(outputDir, "loot")
	if err := os.MkdirAll(lootDir, 0o755); err != nil {
		return err
	}

	filePath := filepath.Join(lootDir, loot.Name+".txt")
	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.WriteString(loot.Contents + "\n"); err != nil {
		return err
	}
	return nil
}

func AppendJSON(outputDir string, table TableFile) error {
	jsonDir := filepath.Join(outputDir, "json")
	if err := os.MkdirAll(jsonDir, 0o755); err != nil {
		return err
	}

	filePath := filepath.Join(jsonDir, table.Name+".json")
	var existing []map[string]string

	// Try to load existing JSON if file exists
	if _, err := os.Stat(filePath); err == nil {
		data, err := os.ReadFile(filePath)
		if err != nil {
			return err
		}
		if len(data) > 0 {
			if err := json.Unmarshal(data, &existing); err != nil {
				return err
			}
		}
	}

	// Append new rows
	for _, row := range table.Body {
		rowMap := make(map[string]string)
		for i, col := range row {
			rowMap[table.Header[i]] = col
		}
		existing = append(existing, rowMap)
	}

	jsonBytes, err := json.MarshalIndent(existing, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filePath, jsonBytes, 0644)
}

func AppendJSONL(outputDir string, table TableFile) error {
	jsonDir := filepath.Join(outputDir, "json")
	if err := os.MkdirAll(jsonDir, 0o755); err != nil {
		return err
	}

	filePath := filepath.Join(jsonDir, table.Name+".jsonl")
	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, row := range table.Body {
		rowMap := make(map[string]string)
		for i, col := range row {
			rowMap[table.Header[i]] = col
		}
		jsonBytes, _ := json.Marshal(rowMap)
		if _, err := f.Write(append(jsonBytes, '\n')); err != nil {
			return err
		}
	}

	return nil
}

func AppendLootFile(outputDirectory, lootFileName, entry string) error {
	// Ensure output directory exists
	lootDir := filepath.Join(outputDirectory, "loot")
	if err := os.MkdirAll(lootDir, 0755); err != nil {
		return fmt.Errorf("failed to create loot directory: %w", err)
	}

	// Loot file path
	lootPath := filepath.Join(lootDir, fmt.Sprintf("%s.txt", lootFileName))

	// Lock so concurrent workers don't clobber each other
	lootFileMu.Lock()
	defer lootFileMu.Unlock()

	// Open in append mode
	f, err := os.OpenFile(lootPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open loot file: %w", err)
	}
	defer f.Close()

	// Write entry with newline
	if _, err := f.WriteString(entry + "\n"); err != nil {
		return fmt.Errorf("failed to write to loot file: %w", err)
	}

	return nil
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
	logger := NewLogger()
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
		logger.InfoM(fmt.Sprintf("Output written to %s", path), o.CallingModule)
		// fmt.Printf("[%s][%s] Output written to %s\n", cyan(o.CallingModule), cyan(o.PrefixIdentifier), path)
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
				TxtLog.Fatal(err)
			}
		}
		if file.Name == "" {
			TxtLog.Fatalf("error creating loot file: no file name was specified")
		}

		l.LootFiles[i].Name = fmt.Sprintf("%s.txt", file.Name)

		filePointer, err := fileSystem.OpenFile(path.Join(lootDirectory, l.LootFiles[i].Name), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			TxtLog.Fatalf("error creating output file: %s", err)
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
		//err := os.WriteFile(fullPath, contents, 0644)
		if err != nil {
			TxtLog.Fatalf("error writing loot file %s: %s", file.Name, err)
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
				TxtLog.Fatal(err)
			}
		}

		if file.Name == "" {
			TxtLog.Fatalf("error creating table file: no file name was specified")
		}

		fileNameWithExt := fmt.Sprintf("%s.txt", file.Name)

		filePointer, err := fileSystem.OpenFile(path.Join(tableDirectory, fileNameWithExt), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			TxtLog.Fatalf("error creating table file: %s", err)
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
				TxtLog.Fatal(err)
			}
		}

		if file.Name == "" {
			TxtLog.Fatalf("error creating csv file: no file name was specified")
		}

		fileNameWithExt := fmt.Sprintf("%s.csv", file.Name)

		filePointer, err := fileSystem.OpenFile(path.Join(csvDirectory, fileNameWithExt), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			TxtLog.Fatalf("error creating csv file: %s", err)
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
				TxtLog.Fatal(err)
			}
		}

		if file.Name == "" {
			TxtLog.Fatalf("error creating json file: no file name was specified")
		}

		fileNameWithExt := fmt.Sprintf("%s.json", file.Name)

		filePointer, err := fileSystem.OpenFile(path.Join(jsonDirectory, fileNameWithExt), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			TxtLog.Fatalf("error creating json file: %s", err)
		}

		b.TableFiles[i].JSONFilePointer = filePointer
	}
}

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
			TxtLog.Fatalf("error writing json: %s", err)
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

func WriteJsonlFile(file *os.File, data interface{}) error {
	bytes, err := json.Marshal(data)
	if err != nil {
		return err
	}

	if _, err := file.Write(append(bytes, "\n"...)); err != nil {
		return err
	}
	return nil
}

func sanitizeFileName(name string) string {
	// replace / and \ with _
	re := regexp.MustCompile(`[\\/]+`)
	return re.ReplaceAllString(name, "_")
}

// ============================================================================
// NEW OUTPUT FUNCTIONS V2 - Multi-cloud support with intelligent routing
// ============================================================================

// HandleOutputV2 is the new generic output function that supports multi-cloud
// environments (Azure, AWS, GCP) with proper scope handling.
// This function provides a cleaner directory structure based on scope type.
//
// Directory structure:
//   - Azure (tenant mode): cloudfox-output/Azure/{UPN}/{TenantName}/module.csv
//   - Azure (subscription mode): cloudfox-output/Azure/{UPN}/{SubscriptionName}/module.csv
//   - AWS (org mode): cloudfox-output/AWS/{Principal}/{OrgID}/module.csv
//   - AWS (account mode): cloudfox-output/AWS/{Principal}/{AccountName}/module.csv
//   - GCP (org mode): cloudfox-output/GCP/{Principal}/{OrgID}/module.csv
//   - GCP (project mode): cloudfox-output/GCP/{Principal}/{ProjectName}/module.csv
func HandleOutputV2(
	cloudProvider string,
	format string,
	outputDirectory string,
	verbosity int,
	wrap bool,
	scopeType string, // "tenant", "subscription", "organization", "account", "project"
	scopeIdentifiers []string, // Tenant IDs, Subscription IDs, Account IDs, Project IDs
	scopeNames []string, // Friendly names for scopes
	principal string, // UPN or IAM user
	dataToOutput CloudfoxOutput,
) error {
	// Build the results identifier based on scope
	resultsIdentifier := buildResultsIdentifier(scopeType, scopeIdentifiers, scopeNames)

	// Build output directory path with new structure
	// Format: cloudfox-output/{CloudProvider}/{Principal}/{ResultsIdentifier}/
	outDirectoryPath := filepath.Join(
		outputDirectory,
		"cloudfox-output",
		cloudProvider,
		principal,
		resultsIdentifier,
	)

	tables := dataToOutput.TableFiles()
	lootFiles := dataToOutput.LootFiles()

	// Determine base module name from first table file (for backwards compatibility)
	baseCloudfoxModule := ""
	if len(tables) > 0 {
		baseCloudfoxModule = tables[0].Name
	}

	outputClient := OutputClient{
		Verbosity:     verbosity,
		CallingModule: baseCloudfoxModule,
		Table: TableClient{
			Wrap:          wrap,
			DirectoryName: outDirectoryPath,
			TableFiles:    tables,
		},
		Loot: LootClient{
			DirectoryName: outDirectoryPath,
			LootFiles:     lootFiles,
		},
	}

	// Handle output based on the verbosity level
	outputClient.WriteFullOutput(tables, lootFiles)
	return nil
}

// HandleOutputSmart automatically selects the best output method based on dataset size.
// This is the RECOMMENDED function for all modules to use.
//
// Decision thresholds:
//   - < 50,000 rows: Uses HandleOutputV2 (normal in-memory)
//   - >= 50,000 rows: Uses HandleStreamingOutput (memory-efficient streaming)
//   - >= 500,000 rows: Logs warning about large dataset
//   - >= 1,000,000 rows: Logs critical warning, suggests optimization flags
func HandleOutputSmart(
	cloudProvider string,
	format string,
	outputDirectory string,
	verbosity int,
	wrap bool,
	scopeType string,
	scopeIdentifiers []string,
	scopeNames []string,
	principal string,
	dataToOutput CloudfoxOutput,
) error {
	logger := NewLogger()

	// Count total rows across all table files
	totalRows := 0
	for _, tableFile := range dataToOutput.TableFiles() {
		totalRows += len(tableFile.Body)
	}

	// Log dataset size if verbose
	if verbosity >= 2 {
		logger.InfoM(fmt.Sprintf("Dataset size: %s rows", formatNumberWithCommas(totalRows)), "output")
	}

	// Decision tree based on row count
	if totalRows >= 1000000 {
		logger.InfoM(fmt.Sprintf("WARNING: Very large dataset detected (%s rows). Consider using per-scope flags for better performance.",
			formatNumberWithCommas(totalRows)), "output")
	} else if totalRows >= 500000 {
		logger.InfoM(fmt.Sprintf("WARNING: Large dataset detected (%s rows). Using streaming output.",
			formatNumberWithCommas(totalRows)), "output")
	}

	// Auto-select output method based on dataset size
	if totalRows >= 50000 {
		if verbosity >= 1 {
			logger.InfoM(fmt.Sprintf("Using streaming output for memory efficiency (%s rows)",
				formatNumberWithCommas(totalRows)), "output")
		}

		// Use streaming output for large datasets (new signature)
		return HandleStreamingOutput(
			cloudProvider,
			format,
			outputDirectory,
			verbosity,
			wrap,
			scopeType,
			scopeIdentifiers,
			scopeNames,
			principal,
			dataToOutput,
		)
	}

	// Use normal in-memory output for smaller datasets
	return HandleOutputV2(
		cloudProvider,
		format,
		outputDirectory,
		verbosity,
		wrap,
		scopeType,
		scopeIdentifiers,
		scopeNames,
		principal,
		dataToOutput,
	)
}

// buildResultsIdentifier creates a results identifier from scope information.
// It prefers friendly names over IDs for better readability.
//
// Fallback hierarchy:
//   - Azure: Tenant Name → Tenant GUID → Subscription Name → Subscription GUID
//   - AWS: Org Name → Org ID → Account Alias → Account ID
//   - GCP: Org Name → Org ID → Project Name → Project ID
//
// Directory Naming Convention:
//   - Tenant-level: [T]{TenantName} or [T]{TenantGUID}
//   - Subscription-level: [S]{SubscriptionName} or [S]{SubscriptionGUID}
//   - Organization-level: [O]-{OrgName} or [O]-{OrgID}
//   - Account-level: [A]-{AccountName} or [A]-{AccountID}
//   - Project-level: [P]-{ProjectName} or [P]-{ProjectID}
//
// Multi-scope handling:
//   - Single scope: [P]{ProjectName}
//   - Multiple scopes: [P]{FirstName}_and_{N-1}_more
func buildResultsIdentifier(scopeType string, identifiers, names []string) string {
	var rawName string

	// Prefer friendly name if available
	if len(names) > 0 && names[0] != "" {
		rawName = names[0]
	} else if len(identifiers) > 0 && identifiers[0] != "" {
		// Fallback to identifier
		rawName = identifiers[0]
	} else {
		// Ultimate fallback
		rawName = "unknown-scope"
	}

	// Handle multiple scopes - indicate how many additional scopes are included
	// This helps users understand that the folder contains data from multiple projects/accounts
	if len(identifiers) > 1 {
		rawName = fmt.Sprintf("%s_and_%d_more", rawName, len(identifiers)-1)
	}

	// Sanitize the name for Windows/Linux compatibility
	sanitizedName := sanitizeDirectoryName(rawName)

	// Add scope prefix based on scope type
	prefix := getScopePrefix(scopeType)
	if prefix != "" {
		return prefix + sanitizedName
	}

	return sanitizedName
}

// getScopePrefix returns the appropriate prefix for a given scope type
func getScopePrefix(scopeType string) string {
	switch scopeType {
	case "tenant":
		return "[T]"
	case "subscription":
		return "[S]"
	case "organization":
		return "[O]"
	case "account":
		return "[A]"
	case "project":
		return "[P]"
	default:
		return ""
	}
}

// sanitizeDirectoryName removes or replaces characters that are invalid in Windows/Linux directory names
// Invalid characters: < > : " / \ | ? *
// Also trims leading/trailing spaces and dots (Windows restriction)
func sanitizeDirectoryName(name string) string {
	// Replace invalid characters with underscore
	invalidChars := []string{"<", ">", ":", "\"", "/", "\\", "|", "?", "*"}
	sanitized := name
	for _, char := range invalidChars {
		sanitized = strings.ReplaceAll(sanitized, char, "_")
	}

	// Trim leading/trailing spaces and dots (Windows doesn't allow these)
	sanitized = strings.Trim(sanitized, " .")

	// If the name is empty after sanitization, use a default
	if sanitized == "" {
		sanitized = "unnamed"
	}

	return sanitized
}

// formatNumberWithCommas formats a number with comma separators for readability.
// Example: 1000000 -> "1,000,000"
func formatNumberWithCommas(n int) string {
	// Convert to string
	s := fmt.Sprintf("%d", n)

	// Handle negative numbers
	negative := false
	if s[0] == '-' {
		negative = true
		s = s[1:]
	}

	// Add commas every 3 digits from right
	var result []rune
	for i, digit := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			result = append(result, ',')
		}
		result = append(result, digit)
	}

	if negative {
		return "-" + string(result)
	}
	return string(result)
}

// ============================================================================
// HIERARCHICAL OUTPUT FUNCTIONS - GCP multi-project support
// ============================================================================

// HierarchicalOutputData represents output data organized by scope for hierarchical output
type HierarchicalOutputData struct {
	OrgLevelData     map[string]CloudfoxOutput // orgID -> org-level data
	FolderLevelData  map[string]CloudfoxOutput // folderID -> folder-level data
	ProjectLevelData map[string]CloudfoxOutput // projectID -> project data
}

// PathBuilder is a function type that builds output paths for hierarchical output
// This allows the caller to inject their path-building logic without importing internal/gcp
type PathBuilder func(scopeType string, scopeID string) string

// HandleHierarchicalOutput writes data to hierarchical directory structure.
// This function outputs data per-scope (organization and/or project) rather than aggregating all data.
//
// Directory structure:
//   - Org level: baseDir/gcp/principal/[O]org-name/module.csv
//   - Project under org: baseDir/gcp/principal/[O]org-name/[P]project-name/module.csv
//   - Standalone project: baseDir/gcp/principal/[P]project-name/module.csv
//
// Parameters:
//   - cloudProvider: "gcp" (or other cloud providers in future)
//   - format: Output format ("all", "csv", "json", "table")
//   - verbosity: Verbosity level for console output
//   - wrap: Whether to wrap table output
//   - pathBuilder: Function that returns the output path for a given scope
//   - outputData: Data organized by scope (org-level and project-level maps)
func HandleHierarchicalOutput(
	cloudProvider string,
	format string,
	verbosity int,
	wrap bool,
	pathBuilder PathBuilder,
	outputData HierarchicalOutputData,
) error {
	logger := NewLogger()

	// Write org-level data (if any)
	for orgID, orgData := range outputData.OrgLevelData {
		outPath := pathBuilder("organization", orgID)
		if err := writeOutputToPath(outPath, format, verbosity, wrap, orgData, logger); err != nil {
			return fmt.Errorf("failed to write org-level output for %s: %w", orgID, err)
		}
	}

	// Write folder-level data (if any)
	for folderID, folderData := range outputData.FolderLevelData {
		outPath := pathBuilder("folder", folderID)
		if err := writeOutputToPath(outPath, format, verbosity, wrap, folderData, logger); err != nil {
			return fmt.Errorf("failed to write folder-level output for %s: %w", folderID, err)
		}
	}

	// Write project-level data
	for projectID, projectData := range outputData.ProjectLevelData {
		outPath := pathBuilder("project", projectID)
		if err := writeOutputToPath(outPath, format, verbosity, wrap, projectData, logger); err != nil {
			return fmt.Errorf("failed to write project-level output for %s: %w", projectID, err)
		}
	}

	return nil
}

// writeOutputToPath writes CloudfoxOutput data to a specific path
func writeOutputToPath(outPath string, format string, verbosity int, wrap bool, data CloudfoxOutput, logger Logger) error {
	tables := data.TableFiles()
	lootFiles := data.LootFiles()

	// Determine base module name from first table file (for logging)
	baseCloudfoxModule := ""
	if len(tables) > 0 {
		baseCloudfoxModule = tables[0].Name
	}

	outputClient := OutputClient{
		Verbosity:     verbosity,
		CallingModule: baseCloudfoxModule,
		Table: TableClient{
			Wrap:          wrap,
			DirectoryName: outPath,
			TableFiles:    tables,
		},
		Loot: LootClient{
			DirectoryName: outPath,
			LootFiles:     lootFiles,
		},
	}

	// Handle output based on the verbosity level
	outputClient.WriteFullOutput(tables, lootFiles)
	return nil
}

// HandleHierarchicalOutputStreaming writes data to hierarchical directory structure using streaming.
// This is the memory-efficient version for large datasets.
//
// Parameters are the same as HandleHierarchicalOutput but uses streaming internally.
func HandleHierarchicalOutputStreaming(
	cloudProvider string,
	format string,
	verbosity int,
	wrap bool,
	pathBuilder PathBuilder,
	outputData HierarchicalOutputData,
) error {
	logger := NewLogger()

	// Stream org-level data (if any)
	for orgID, orgData := range outputData.OrgLevelData {
		outPath := pathBuilder("organization", orgID)
		if err := streamOutputToPath(outPath, format, verbosity, wrap, orgData, logger); err != nil {
			return fmt.Errorf("failed to stream org-level output for %s: %w", orgID, err)
		}
	}

	// Stream folder-level data (if any)
	for folderID, folderData := range outputData.FolderLevelData {
		outPath := pathBuilder("folder", folderID)
		if err := streamOutputToPath(outPath, format, verbosity, wrap, folderData, logger); err != nil {
			return fmt.Errorf("failed to stream folder-level output for %s: %w", folderID, err)
		}
	}

	// Stream project-level data
	for projectID, projectData := range outputData.ProjectLevelData {
		outPath := pathBuilder("project", projectID)
		if err := streamOutputToPath(outPath, format, verbosity, wrap, projectData, logger); err != nil {
			return fmt.Errorf("failed to stream project-level output for %s: %w", projectID, err)
		}
	}

	return nil
}

// streamOutputToPath streams CloudfoxOutput data to a specific path
func streamOutputToPath(outPath string, format string, verbosity int, wrap bool, data CloudfoxOutput, logger Logger) error {
	if err := os.MkdirAll(outPath, 0o755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Determine base module name from first table file (for logging)
	baseCloudfoxModule := ""
	if len(data.TableFiles()) > 0 {
		baseCloudfoxModule = data.TableFiles()[0].Name
	}

	// Stream table files
	for _, t := range data.TableFiles() {
		if verbosity > 0 {
			tmpClient := TableClient{Wrap: wrap}
			tmpClient.printTablesToScreen([]TableFile{t})
		}

		safeName := sanitizeFileName(t.Name)

		// Stream CSV rows
		if format == "all" || format == "csv" {
			csvPath := filepath.Join(outPath, "csv", safeName+".csv")
			if err := os.MkdirAll(filepath.Dir(csvPath), 0o755); err != nil {
				return fmt.Errorf("failed to create csv directory: %w", err)
			}
			csvFile, err := os.OpenFile(csvPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				return fmt.Errorf("failed to open csv file: %w", err)
			}

			info, _ := csvFile.Stat()
			if info.Size() == 0 {
				_, _ = csvFile.WriteString(strings.Join(t.Header, ",") + "\n")
			}
			for _, row := range t.Body {
				cleanRow := removeColorCodesFromSlice(row)
				_, _ = csvFile.WriteString(strings.Join(cleanRow, ",") + "\n")
			}
			csvFile.Close()

			logger.InfoM(fmt.Sprintf("Output written to %s", csvPath), baseCloudfoxModule)
		}

		// Stream JSONL rows
		if format == "all" || format == "json" {
			if err := AppendJSONL(outPath, t); err != nil {
				return fmt.Errorf("failed to append JSONL: %w", err)
			}
			logger.InfoM(fmt.Sprintf("Output written to %s", filepath.Join(outPath, "json", safeName+".jsonl")), baseCloudfoxModule)
		}

		// Stream table rows
		if format == "all" || format == "table" {
			tableDir := filepath.Join(outPath, "table")
			if err := os.MkdirAll(tableDir, 0o755); err != nil {
				return fmt.Errorf("failed to create table directory: %w", err)
			}
			tablePath := filepath.Join(tableDir, safeName+".txt")

			tableFile, err := os.OpenFile(tablePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
			if err != nil {
				return fmt.Errorf("failed to open table file: %w", err)
			}

			// Write tab-delimited data
			_, _ = fmt.Fprintln(tableFile, strings.Join(t.Header, "\t"))
			for _, row := range t.Body {
				cleanRow := removeColorCodesFromSlice(row)
				_, _ = fmt.Fprintln(tableFile, strings.Join(cleanRow, "\t"))
			}
			tableFile.Close()

			logger.InfoM(fmt.Sprintf("Output written to %s", tablePath), baseCloudfoxModule)
		}
	}

	// Stream loot files
	for _, l := range data.LootFiles() {
		lootDir := filepath.Join(outPath, "loot")
		if err := os.MkdirAll(lootDir, 0o755); err != nil {
			return fmt.Errorf("failed to create loot directory: %w", err)
		}

		lootPath := filepath.Join(lootDir, l.Name+".txt")
		lootFile, err := os.OpenFile(lootPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("failed to open loot file: %w", err)
		}

		scanner := bufio.NewScanner(strings.NewReader(l.Contents))
		for scanner.Scan() {
			if _, err := lootFile.WriteString(scanner.Text() + "\n"); err != nil {
				lootFile.Close()
				return fmt.Errorf("failed to append loot line: %w", err)
			}
		}
		lootFile.Close()

		if err := scanner.Err(); err != nil {
			return fmt.Errorf("error reading loot lines: %w", err)
		}

		logger.InfoM(fmt.Sprintf("Output written to %s", lootPath), baseCloudfoxModule)
	}

	return nil
}

// HandleHierarchicalOutputSmart automatically selects the best output method based on dataset size.
// This is the RECOMMENDED function for hierarchical output.
func HandleHierarchicalOutputSmart(
	cloudProvider string,
	format string,
	verbosity int,
	wrap bool,
	pathBuilder PathBuilder,
	outputData HierarchicalOutputData,
) error {
	logger := NewLogger()

	// Count total rows across all data
	totalRows := 0
	for _, orgData := range outputData.OrgLevelData {
		for _, tableFile := range orgData.TableFiles() {
			totalRows += len(tableFile.Body)
		}
	}
	for _, folderData := range outputData.FolderLevelData {
		for _, tableFile := range folderData.TableFiles() {
			totalRows += len(tableFile.Body)
		}
	}
	for _, projectData := range outputData.ProjectLevelData {
		for _, tableFile := range projectData.TableFiles() {
			totalRows += len(tableFile.Body)
		}
	}

	// Log dataset size if verbose
	if verbosity >= 2 {
		logger.InfoM(fmt.Sprintf("Hierarchical output - Total dataset size: %s rows", formatNumberWithCommas(totalRows)), "output")
	}

	// Decision tree based on row count
	if totalRows >= 1000000 {
		logger.InfoM(fmt.Sprintf("WARNING: Very large dataset detected (%s rows). Using streaming output.",
			formatNumberWithCommas(totalRows)), "output")
	} else if totalRows >= 500000 {
		logger.InfoM(fmt.Sprintf("Large dataset detected (%s rows). Using streaming output.",
			formatNumberWithCommas(totalRows)), "output")
	}

	// Auto-select output method based on dataset size
	if totalRows >= 50000 {
		if verbosity >= 1 {
			logger.InfoM(fmt.Sprintf("Using streaming hierarchical output for memory efficiency (%s rows)",
				formatNumberWithCommas(totalRows)), "output")
		}
		return HandleHierarchicalOutputStreaming(cloudProvider, format, verbosity, wrap, pathBuilder, outputData)
	}

	// Use normal in-memory output for smaller datasets
	return HandleHierarchicalOutput(cloudProvider, format, verbosity, wrap, pathBuilder, outputData)
}

// ============================================================================
// SINGLE-PASS TEE STREAMING - Efficient hierarchical output with row routing
// ============================================================================

// RowRouter is a function that determines which project IDs a row belongs to.
// Given a row (slice of strings), it returns the project IDs that should receive this row.
// The row is always written to org-level; this determines additional project-level routing.
type RowRouter func(row []string) []string

// ProjectLootCollector is a function that returns loot files for a specific project.
// This allows modules to provide inheritance-aware loot (e.g., org + folder + project loot).
type ProjectLootCollector func(projectID string) []LootFile

// TeeStreamingConfig holds configuration for single-pass tee streaming output
type TeeStreamingConfig struct {
	// OrgID is the organization ID for org-level output
	OrgID string

	// ProjectIDs is the list of all project IDs that may receive output
	ProjectIDs []string

	// Tables contains the table data to stream (header + body)
	Tables []TableFile

	// LootFiles contains loot files to write to org level
	LootFiles []LootFile

	// ProjectLootCollector returns loot files for a specific project (with inheritance).
	// If nil, no loot is written to project directories.
	ProjectLootCollector ProjectLootCollector

	// RowRouter determines which projects each row belongs to
	// If nil, rows are only written to org level
	RowRouter RowRouter

	// PathBuilder builds output paths for each scope
	PathBuilder PathBuilder

	// Format is the output format ("all", "csv", "json", "table")
	Format string

	// Verbosity level for console output
	Verbosity int

	// Wrap enables table wrapping
	Wrap bool
}

// teeStreamWriter manages multiple output file handles for tee streaming
type teeStreamWriter struct {
	// orgWriters holds file writers for org-level output (format -> file)
	orgCSV   *os.File
	orgJSON  *os.File
	orgTable *os.File

	// projectWriters holds file writers for each project (projectID -> format -> file)
	projectCSV   map[string]*os.File
	projectJSON  map[string]*os.File
	projectTable map[string]*os.File

	// Track which projects have had headers written
	projectHeaderWritten map[string]bool

	// Configuration
	format  string
	outPath string
}

// HandleHierarchicalOutputTee performs single-pass streaming with tee to multiple outputs.
// This is the most efficient method for large datasets that need both org-level and per-project output.
//
// Instead of streaming org data first, then streaming each project's filtered data separately,
// this function streams through the data once and writes each row to:
// 1. The org-level output (always)
// 2. Any project-level outputs determined by the RowRouter function
//
// This reduces I/O and processing time significantly for large datasets.
func HandleHierarchicalOutputTee(config TeeStreamingConfig) error {
	logger := NewLogger()

	if config.OrgID == "" {
		return fmt.Errorf("OrgID is required for tee streaming")
	}

	// Get base module name for logging
	baseCloudfoxModule := ""
	if len(config.Tables) > 0 {
		baseCloudfoxModule = config.Tables[0].Name
	}

	// Build output paths
	orgPath := config.PathBuilder("organization", config.OrgID)
	projectPaths := make(map[string]string)
	for _, projectID := range config.ProjectIDs {
		projectPaths[projectID] = config.PathBuilder("project", projectID)
	}

	// Track which projects received data (for loot file generation)
	projectsWithData := make(map[string]bool)

	// Process each table
	for _, t := range config.Tables {
		if config.Verbosity > 0 {
			tmpClient := TableClient{Wrap: config.Wrap}
			tmpClient.printTablesToScreen([]TableFile{t})
		}

		safeName := sanitizeFileName(t.Name)

		// Initialize writers
		writer := &teeStreamWriter{
			projectCSV:           make(map[string]*os.File),
			projectJSON:          make(map[string]*os.File),
			projectTable:         make(map[string]*os.File),
			projectHeaderWritten: make(map[string]bool),
			format:               config.Format,
		}

		// Open org-level files
		if err := writer.openOrgFiles(orgPath, safeName, config.Format); err != nil {
			return fmt.Errorf("failed to open org files: %w", err)
		}

		// Write org-level headers
		if err := writer.writeOrgHeader(t.Header, config.Format); err != nil {
			writer.closeAll()
			return fmt.Errorf("failed to write org header: %w", err)
		}

		// Pre-open project files if we have a router
		if config.RowRouter != nil {
			for projectID, projectPath := range projectPaths {
				if err := writer.openProjectFiles(projectID, projectPath, safeName, config.Format); err != nil {
					writer.closeAll()
					return fmt.Errorf("failed to open project files for %s: %w", projectID, err)
				}
			}
		}

		// Stream each row
		for _, row := range t.Body {
			cleanRow := removeColorCodesFromSlice(row)

			// Always write to org level
			if err := writer.writeOrgRow(cleanRow, config.Format); err != nil {
				writer.closeAll()
				return fmt.Errorf("failed to write org row: %w", err)
			}

			// Route to projects if router is configured
			if config.RowRouter != nil {
				targetProjects := config.RowRouter(row)
				for _, projectID := range targetProjects {
					// Track that this project has data
					projectsWithData[projectID] = true

					// Write header if this is the first row for this project
					if !writer.projectHeaderWritten[projectID] {
						if err := writer.writeProjectHeader(projectID, t.Header, config.Format); err != nil {
							writer.closeAll()
							return fmt.Errorf("failed to write project header for %s: %w", projectID, err)
						}
						writer.projectHeaderWritten[projectID] = true
					}

					if err := writer.writeProjectRow(projectID, cleanRow, config.Format); err != nil {
						writer.closeAll()
						return fmt.Errorf("failed to write project row for %s: %w", projectID, err)
					}
				}
			}
		}

		// Close all files
		writer.closeAll()

		// Log output paths
		if config.Format == "all" || config.Format == "csv" {
			logger.InfoM(fmt.Sprintf("Output written to %s", filepath.Join(orgPath, "csv", safeName+".csv")), baseCloudfoxModule)
		}
		if config.Format == "all" || config.Format == "json" {
			logger.InfoM(fmt.Sprintf("Output written to %s", filepath.Join(orgPath, "json", safeName+".jsonl")), baseCloudfoxModule)
		}
		if config.Format == "all" || config.Format == "table" {
			logger.InfoM(fmt.Sprintf("Output written to %s", filepath.Join(orgPath, "table", safeName+".txt")), baseCloudfoxModule)
		}

		// Log project outputs (only for projects that received data)
		for projectID := range writer.projectHeaderWritten {
			projectPath := projectPaths[projectID]
			if config.Format == "all" || config.Format == "csv" {
				logger.InfoM(fmt.Sprintf("Output written to %s", filepath.Join(projectPath, "csv", safeName+".csv")), baseCloudfoxModule)
			}
			if config.Format == "all" || config.Format == "json" {
				logger.InfoM(fmt.Sprintf("Output written to %s", filepath.Join(projectPath, "json", safeName+".jsonl")), baseCloudfoxModule)
			}
			if config.Format == "all" || config.Format == "table" {
				logger.InfoM(fmt.Sprintf("Output written to %s", filepath.Join(projectPath, "table", safeName+".txt")), baseCloudfoxModule)
			}
		}
	}

	// Write loot files to org level
	for _, l := range config.LootFiles {
		lootDir := filepath.Join(orgPath, "loot")
		if err := os.MkdirAll(lootDir, 0o755); err != nil {
			return fmt.Errorf("failed to create loot directory: %w", err)
		}

		lootPath := filepath.Join(lootDir, l.Name+".txt")
		if err := os.WriteFile(lootPath, []byte(l.Contents), 0644); err != nil {
			return fmt.Errorf("failed to write loot file: %w", err)
		}

		logger.InfoM(fmt.Sprintf("Output written to %s", lootPath), baseCloudfoxModule)
	}

	// Write per-project loot files (with inheritance) if collector is provided
	if config.ProjectLootCollector != nil {
		for projectID := range projectsWithData {
			projectPath := projectPaths[projectID]
			projectLootFiles := config.ProjectLootCollector(projectID)

			for _, l := range projectLootFiles {
				lootDir := filepath.Join(projectPath, "loot")
				if err := os.MkdirAll(lootDir, 0o755); err != nil {
					return fmt.Errorf("failed to create project loot directory: %w", err)
				}

				lootPath := filepath.Join(lootDir, l.Name+".txt")
				if err := os.WriteFile(lootPath, []byte(l.Contents), 0644); err != nil {
					return fmt.Errorf("failed to write project loot file: %w", err)
				}

				logger.InfoM(fmt.Sprintf("Output written to %s", lootPath), baseCloudfoxModule)
			}
		}
	}

	return nil
}

// openOrgFiles opens output files for org-level output
func (w *teeStreamWriter) openOrgFiles(orgPath, safeName, format string) error {
	var err error

	if format == "all" || format == "csv" {
		csvDir := filepath.Join(orgPath, "csv")
		if err = os.MkdirAll(csvDir, 0o755); err != nil {
			return err
		}
		w.orgCSV, err = os.OpenFile(filepath.Join(csvDir, safeName+".csv"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			return err
		}
	}

	if format == "all" || format == "json" {
		jsonDir := filepath.Join(orgPath, "json")
		if err = os.MkdirAll(jsonDir, 0o755); err != nil {
			return err
		}
		w.orgJSON, err = os.OpenFile(filepath.Join(jsonDir, safeName+".jsonl"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			return err
		}
	}

	if format == "all" || format == "table" {
		tableDir := filepath.Join(orgPath, "table")
		if err = os.MkdirAll(tableDir, 0o755); err != nil {
			return err
		}
		w.orgTable, err = os.OpenFile(filepath.Join(tableDir, safeName+".txt"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			return err
		}
	}

	return nil
}

// openProjectFiles opens output files for a specific project
func (w *teeStreamWriter) openProjectFiles(projectID, projectPath, safeName, format string) error {
	var err error

	if format == "all" || format == "csv" {
		csvDir := filepath.Join(projectPath, "csv")
		if err = os.MkdirAll(csvDir, 0o755); err != nil {
			return err
		}
		w.projectCSV[projectID], err = os.OpenFile(filepath.Join(csvDir, safeName+".csv"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			return err
		}
	}

	if format == "all" || format == "json" {
		jsonDir := filepath.Join(projectPath, "json")
		if err = os.MkdirAll(jsonDir, 0o755); err != nil {
			return err
		}
		w.projectJSON[projectID], err = os.OpenFile(filepath.Join(jsonDir, safeName+".jsonl"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			return err
		}
	}

	if format == "all" || format == "table" {
		tableDir := filepath.Join(projectPath, "table")
		if err = os.MkdirAll(tableDir, 0o755); err != nil {
			return err
		}
		w.projectTable[projectID], err = os.OpenFile(filepath.Join(tableDir, safeName+".txt"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			return err
		}
	}

	return nil
}

// writeOrgHeader writes header to org-level files
func (w *teeStreamWriter) writeOrgHeader(header []string, format string) error {
	if format == "all" || format == "csv" {
		if w.orgCSV != nil {
			_, err := w.orgCSV.WriteString(strings.Join(header, ",") + "\n")
			if err != nil {
				return err
			}
		}
	}

	if format == "all" || format == "table" {
		if w.orgTable != nil {
			_, err := w.orgTable.WriteString(strings.Join(header, "\t") + "\n")
			if err != nil {
				return err
			}
		}
	}

	// JSON doesn't need a header line (each row is self-contained)
	return nil
}

// writeProjectHeader writes header to project-level files
func (w *teeStreamWriter) writeProjectHeader(projectID string, header []string, format string) error {
	if format == "all" || format == "csv" {
		if f := w.projectCSV[projectID]; f != nil {
			_, err := f.WriteString(strings.Join(header, ",") + "\n")
			if err != nil {
				return err
			}
		}
	}

	if format == "all" || format == "table" {
		if f := w.projectTable[projectID]; f != nil {
			_, err := f.WriteString(strings.Join(header, "\t") + "\n")
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// writeOrgRow writes a row to org-level files
func (w *teeStreamWriter) writeOrgRow(row []string, format string) error {
	if format == "all" || format == "csv" {
		if w.orgCSV != nil {
			_, err := w.orgCSV.WriteString(strings.Join(row, ",") + "\n")
			if err != nil {
				return err
			}
		}
	}

	if format == "all" || format == "json" {
		if w.orgJSON != nil {
			jsonBytes, err := json.Marshal(row)
			if err != nil {
				return err
			}
			_, err = w.orgJSON.WriteString(string(jsonBytes) + "\n")
			if err != nil {
				return err
			}
		}
	}

	if format == "all" || format == "table" {
		if w.orgTable != nil {
			_, err := w.orgTable.WriteString(strings.Join(row, "\t") + "\n")
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// writeProjectRow writes a row to project-level files
func (w *teeStreamWriter) writeProjectRow(projectID string, row []string, format string) error {
	if format == "all" || format == "csv" {
		if f := w.projectCSV[projectID]; f != nil {
			_, err := f.WriteString(strings.Join(row, ",") + "\n")
			if err != nil {
				return err
			}
		}
	}

	if format == "all" || format == "json" {
		if f := w.projectJSON[projectID]; f != nil {
			jsonBytes, err := json.Marshal(row)
			if err != nil {
				return err
			}
			_, err = f.WriteString(string(jsonBytes) + "\n")
			if err != nil {
				return err
			}
		}
	}

	if format == "all" || format == "table" {
		if f := w.projectTable[projectID]; f != nil {
			_, err := f.WriteString(strings.Join(row, "\t") + "\n")
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// closeAll closes all open file handles
func (w *teeStreamWriter) closeAll() {
	if w.orgCSV != nil {
		w.orgCSV.Close()
	}
	if w.orgJSON != nil {
		w.orgJSON.Close()
	}
	if w.orgTable != nil {
		w.orgTable.Close()
	}

	for _, f := range w.projectCSV {
		if f != nil {
			f.Close()
		}
	}
	for _, f := range w.projectJSON {
		if f != nil {
			f.Close()
		}
	}
	for _, f := range w.projectTable {
		if f != nil {
			f.Close()
		}
	}
}
