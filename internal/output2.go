package internal

import (
	"github.com/spf13/afero"
)

// Verbosity = 1 (Output and loot printed to file).
// Verbosity = 2 (Output and loot printed to file, output printed screen).
// Verbosity = 3 (Output and loot printed to file and screen).
// Format = "table", "csv"
// PrefixIdentifier = this string gets printed with control message calling module (e.g. aws profile, azure resource group, gcp project, etc)
type OutputClient struct {
	WrapTable        bool
	Verbosity        int
	Format           string
	PrefixIdentifier string
	CallingModule    string
	OutputFileName   string
	LootFileName     string
	DirectoryName    string
}

func (c *OutputClient) PrintOutput(header, loot []string, body [][]string) {
	if c.Verbosity == 2 && c.Format == "table" {
		c.printTabletoScreen(header, body)

	} else if c.Verbosity == 2 && c.Format == "csv" {
		c.printCSVtoScreen(header, body)

	} else if c.Verbosity == 3 && c.Format == "table" {
		c.printTabletoScreen(header, body)
		c.printLoottoScreen(loot)

	} else if c.Verbosity == 3 && c.Format == "csv" {
		c.printCSVtoScreen(header, body)
		c.printLoottoScreen(loot)
	}

	outputFileTable := c.createTableFile(c.DirectoryName, c.OutputFileName)
	outputFileCSV := c.createCSVFile(c.DirectoryName, c.OutputFileName)
	outputFileLoot := c.createLootFile(c.DirectoryName, c.LootFileName)

	c.writeTableFile(header, body, outputFileTable)
	c.writeCSVFile(header, body, outputFileCSV)
	c.writeLootFile(header, body, outputFileLoot)
}

func (c *OutputClient) printTabletoScreen(header []string, body [][]string) {

}

func (c *OutputClient) printCSVtoScreen(header []string, body [][]string) {

}

func (c *OutputClient) printLoottoScreen(loot []string) {

}

// The Afero library enables file system mocking:
// fileSystem = afero.NewOsFs() if not unit testing (real file system) OR
// fileSystem = afero.NewMemMapFs() for a mocked file system (when unit testing)
// outputDirectory = nil (creates the file in the current directory ".")

func (c *OutputClient) createTableFile(outputDirectory, fileName string) afero.File {
	return nil
}

func (c *OutputClient) createCSVFile(outputDirectory, fileName string) afero.File {
	return nil
}

func (c *OutputClient) createLootFile(outputDirectory, fileName string) afero.File {
	return nil
}

func (c *OutputClient) writeTableFile(header []string, body [][]string, outputFile afero.File) {

}

func (c *OutputClient) writeCSVFile(header []string, body [][]string, outputFile afero.File) {

}

func (c *OutputClient) writeLootFile(header []string, body [][]string, outputFile afero.File) {

}

/*
func MockFileSystem(switcher bool) {
	if switcher {
		fmt.Println("Using mocked file system")
		fileSystem = afero.NewMemMapFs()
	} else {
		fmt.Println("Using OS file system. Make sure to clean up your disk!")
	}
}
*/
