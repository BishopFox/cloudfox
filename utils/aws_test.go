package utils

import (
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/spf13/afero"
)

func compareSlice(a []string, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for idx, elem := range a {
		if elem != b[idx] {
			return false
		}
	}
	return true
}

// Case empty file.
// Case expected format.
func TestGetAllAWSProfiles(t *testing.T) {
	var tests = []struct {
		fileData       []byte
		expectedOutput []string
		caseName       string
	}{
		{[]byte(""), []string{}, "empty file"},
		{[]byte("[default]\naws_access_key=abc\naws_secret_access_key=123\n[123]\naws_access_key=abc\naws_secret_access_key=123"), []string{"default", "123"}, "expected format"},
	}
	credentialsFile := config.DefaultSharedCredentialsFilename()
	for _, test := range tests {
		fmt.Printf("[*] Testing %s\n", test.caseName)
		UtilsFs.Create(credentialsFile)
		afero.WriteFile(UtilsFs, credentialsFile, test.fileData, 0755)
		output := GetAllAWSProfiles()
		if !compareSlice(output, test.expectedOutput) {
			t.Errorf("Test Failed: %v inputted, %v expected, recieved: %v", test.fileData, test.expectedOutput, output)
		}
	}

}

// Case empty file.
// Case special characters \r \n \t.
// Case with extra new lines at the end.
// Case expected format.
func TestGetSelectedAWSProfiles(t *testing.T) {
	var tests = []struct {
		fileData       []byte
		expectedOutput []string
		caseName       string
	}{
		{[]byte(""), []string{}, "empty file"},
		{[]byte("abcd\r\nxyz\t\n123\r\t"), []string{"abcd", "xyz", "123"}, "special characters \\r \\n \\t"},
		{[]byte("qwerty\nxyz\n456\n\n\n"), []string{"qwerty", "xyz", "456"}, "extra new lines at the end"},
		{[]byte("nmhj\nyuioy\n098"), []string{"nmhj", "yuioy", "098"}, "expected format"},
	}
	for _, test := range tests {
		fmt.Printf("[*] Testing %s\n", test.caseName)
		UtilsFs.Create("/tmp/myfile.txt")
		afero.WriteFile(UtilsFs, "/tmp/myfile.txt", test.fileData, 0755)
		output := GetSelectedAWSProfiles("/tmp/myfile.txt")
		if !compareSlice(output, test.expectedOutput) {
			t.Errorf("Test Failed: %v inputted, %v expected, recieved: %v", test.fileData, test.expectedOutput, output)
		}
	}
}
