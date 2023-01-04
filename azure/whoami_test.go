package azure

import (
	"fmt"
	"testing"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
)

func TestAzWhoamiCommand(t *testing.T) {
	fmt.Println()
	fmt.Println("[test case] Azure Whoami Command")

	// Mocked functions to simulate Azure calls and responses
	getTenants = mockedGetTenants
	getSubscriptions = mockedGetSubscriptions
	getResourceGroups = mockedGetResourceGroups

	// Test case parameters
	internal.MockFileSystem(true)
	subtests := []struct {
		name              string
		resourcesTestFile string
		azExtendedFilter  bool
		version           string
		wrapTableOutput   bool
	}{
		{
			name:              "./cloudfox azure whoami",
			resourcesTestFile: "./test-data/resources.json",
			azExtendedFilter:  false,
			version:           "DEV",
			wrapTableOutput:   true,
		},
		{
			name:              "./cloudfox azure whoami --extended",
			resourcesTestFile: "./test-data/resources.json",
			azExtendedFilter:  true,
			version:           "DEV",
			wrapTableOutput:   true,
		},
	}
	for _, s := range subtests {
		globals.RESOURCES_TEST_FILE = s.resourcesTestFile
		AzWhoamiCommand(s.azExtendedFilter, s.version, s.wrapTableOutput)
	}
}
