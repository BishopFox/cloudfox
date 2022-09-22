package utils

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/spf13/afero"
)

// Case empty file.
// Case malformed file.
// Case expected format.
func TestGetAllAWSProfiles(t *testing.T) {
	var tests = []struct {
		fileData       []byte
		expectedOutput []string
	}{
		{[]byte(""), []string{""}},
		{[]byte("[[]]\naws_access_key=abc\naws_secret_access_key=123\n123"), []string{""}},
		{[]byte("[xyz]\naws_access_key=abc\naws_secret_access_key=123\n[123]"), []string{"xyz", "123"}},
	}
	credentialsFile := config.DefaultSharedCredentialsFilename()
	for _, test := range tests {
		UtilsFs.Create(credentialsFile)
		afero.WriteFile(UtilsFs, credentialsFile, test.fileData, 0755)
		output := GetAllAWSProfiles()
		for index, element := range test.expectedOutput {
			if output[index] != element {
				t.Error("Test Failed: {} inputted, {} expected, recieved: {}", test.fileData, test.expectedOutput, output)
			}
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
	}{
		{[]byte(""), []string{""}},
		{[]byte("abcd\nxyz\n123\r\t"), []string{"abcd", "xyz", "123"}},
		{[]byte("qwerty\nxyz\n456\n\n\n"), []string{"qwerty", "xyz", "456"}},
		{[]byte("nmhj\nyuioy\n098"), []string{"nmhj", "yuioy", "098"}},
	}
	for _, test := range tests {
		UtilsFs.Create("/my/path")
		afero.WriteFile(UtilsFs, "/my/path", test.fileData, 0755)
		output := GetSelectedAWSProfiles("/my/path")
		for index, element := range test.expectedOutput {
			if element != output[index] {
				t.Error("Test Failed: {} inputted, {} expected, recieved: {}", test.fileData, test.expectedOutput, output)
			}
		}
	}
}
