package internal

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"path"

	"github.com/aquasecurity/table"
	"github.com/fatih/color"
	"github.com/spf13/afero"
	"golang.org/x/crypto/ssh/terminal"
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
	Name             string
	TableFilePointer afero.File
	CSVFilePointer   afero.File
	Header           []string
	Body             [][]string
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

func (o *OutputClient) WriteFullOutput(tables []TableFile, lootFiles []LootFile) {
	switch o.Verbosity {
	case 2:
		o.Table.printTablesToScreen(tables)
	case 3:
		o.Table.printTablesToScreen(tables)
		fmt.Println()
		o.Loot.printLoottoScreen(lootFiles)
	}

	o.Loot.createLootFiles(lootFiles)
	lootOutputPaths := o.Loot.writeLootFiles()
	o.Table.createTableFiles(tables)
	tableOutputPaths := o.Table.writeTableFiles(tables)
	o.Table.createCSVFiles()
	csvOutputPaths := o.Table.writeCSVFiles()

	var outputPaths []string
	outputPaths = append(outputPaths, lootOutputPaths...)
	outputPaths = append(outputPaths, tableOutputPaths...)
	outputPaths = append(outputPaths, csvOutputPaths...)

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
		if _, err := fileSystem.Stat(l.DirectoryName); os.IsNotExist(err) {
			err = fileSystem.MkdirAll(l.DirectoryName, 0700)
			if err != nil {
				log.Fatal(err)
			}
		}
		if file.Name == "" {
			log.Fatalf("error creating loot file: no file name was specified")
		}

		l.LootFiles[i].Name = fmt.Sprintf("%s.txt", file.Name)

		filePointer, err := fileSystem.OpenFile(path.Join(l.DirectoryName, l.LootFiles[i].Name), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
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
		fullPath := path.Join(l.DirectoryName, file.Name)

		err := os.WriteFile(fullPath, contents, 0644)
		if err != nil {
			log.Fatalf("error writing loot file %s: %s", file.Name, err)
		}
		fullFilePaths = append(fullFilePaths, fullPath)
	}
	return fullFilePaths
}

func (b *TableClient) printTablesToScreen(tableFiles []TableFile) {
	for _, tf := range tableFiles {
		standardColumnWidth := 1000
		t := table.New(os.Stdout)

		if b.Wrap {
			terminalWidth, _, err := terminal.GetSize(int(os.Stdout.Fd()))
			if err != nil {
				fmt.Printf("error getting terminal size: %s, please set the --wrap flag to false\n", err)
				return
			}
			columnCount := len(tf.Header)
			// The offset value was defined by trial and error to get the best wrapping
			trialAndErrorOffset := 1
			standardColumnWidth = terminalWidth / (columnCount + trialAndErrorOffset)
		}

		t.SetColumnMaxWidth(standardColumnWidth)
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
		t := table.New(file.TableFilePointer)

		t.SetHeaders(file.Header...)
		t.AddRows(file.Body...)
		t.SetRowLines(false)
		t.SetDividers(table.UnicodeRoundedDividers)
		t.SetAlignment(table.AlignLeft)
		t.Render()

		fullPath := path.Join(b.DirectoryName, file.Name)
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
			csvWriter.Write(row)
		}
		csvWriter.Flush()

		fullPath := path.Join(b.DirectoryName, file.Name)
		fullFilePaths = append(fullFilePaths, fullPath)
	}

	return fullFilePaths
}
