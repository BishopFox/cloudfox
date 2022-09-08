package utils

import (
	"fmt"
	"strings"
	"testing"

	"github.com/aws/smithy-go/ptr"
	"github.com/spf13/afero"
)

func TestOutputSelector(t *testing.T) {
	subTests := []struct {
		name              string
		verbosity         int
		outputType        string
		outputDirectory   string
		fileNameExtension string
		callingModule     string
	}{
		{
			name:              "Verbosity1-OutputTable",
			verbosity:         1,
			outputType:        "table",
			outputDirectory:   "cloudfox-output",
			fileNameExtension: ".txt",
			callingModule:     "calling_module_1",
		},
		{
			name:              "Verbosity2-OutputTable",
			verbosity:         2,
			outputType:        "table",
			outputDirectory:   "cloudfox-output",
			fileNameExtension: ".txt",
			callingModule:     "calling_module_2",
		},
		{
			name:              "Verbosity3-OutputTable",
			verbosity:         3,
			outputType:        "table",
			outputDirectory:   "cloudfox-output",
			fileNameExtension: ".txt",
			callingModule:     "calling_module_3",
		},
		{
			name:              "Verbosity1-OutputCSV",
			verbosity:         1,
			outputType:        "csv",
			outputDirectory:   "cloudfox-output",
			fileNameExtension: ".csv",
			callingModule:     "calling_module_4",
		},
		{
			name:              "Verbosity2-OutputCSV",
			verbosity:         2,
			outputType:        "csv",
			outputDirectory:   "cloudfox-output",
			fileNameExtension: ".csv",
			callingModule:     "calling_module_5",
		},
		{
			name:              "Verbosity3-OutputCSV",
			verbosity:         3,
			outputType:        "csv",
			outputDirectory:   "cloudfox-output",
			fileNameExtension: ".csv",
			callingModule:     "calling_module__6",
		},
	}

	fmt.Println("TEST_CASE: CreateOutputFile")
	mockFileSystem(true)

	for _, s := range subTests {
		fmt.Printf("\n[subtest]: %s\n", s.name)

		t.Run(s.name, func(t *testing.T) {
			header := []string{"Year", "Month"}
			body := [][]string{
				{"2022", "January"},
				{"2021", "February"},
				{"2020", "March"},
				{"2019", "April"},
			}
			OutputSelector(s.verbosity, s.outputType, header, body, s.outputDirectory, fmt.Sprintf("%s%s", s.callingModule, s.fileNameExtension), s.callingModule)
		})
	}
	fmt.Println()
}

func TestCreateOutputFile(t *testing.T) {
	subTests := []struct {
		name                     string
		outputDirectory          *string
		fileName                 *string
		outputType               string
		callingModule            string
		expectedAbsoluteFileName string
	}{
		{
			name:                     "EmptyDirName_TableOutput",
			outputDirectory:          nil,
			fileName:                 ptr.String("test1.txt"),
			outputType:               "table",
			expectedAbsoluteFileName: "table/test1.txt",
			callingModule:            "mocked_module",
		},
		{
			name:                     "ValidDirName_CSVOutput",
			outputDirectory:          ptr.String("cloudfox-output"),
			fileName:                 ptr.String("test2.txt"),
			outputType:               "csv",
			expectedAbsoluteFileName: "cloudfox-output/csv/test2.txt",
			callingModule:            "mocked_module",
		},
	}

	fmt.Println("TEST_CASE: CreateOutputFile")
	mockFileSystem(true)

	for _, s := range subTests {
		fmt.Printf("\n[subtest]: %s\n", s.name)

		t.Run(s.name, func(t *testing.T) {
			file := createOutputFile(s.outputDirectory, s.fileName, s.outputType, s.callingModule)
			if strings.Compare(file.Name(), s.expectedAbsoluteFileName) != 0 {
				t.Errorf("Incorrect file name. Expected %s, got %s.", file.Name(), s.expectedAbsoluteFileName)
			}
		})
	}
	fmt.Println()
}

func mockFileSystem(switcher bool) {
	if switcher {
		fmt.Println("Using mocked file system")
		fileSystem = afero.NewMemMapFs()
	} else {
		fmt.Println("Using OS file system. Make sure to clean up your disk!")
	}
}
