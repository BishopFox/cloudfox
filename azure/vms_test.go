package azure

import (
	"fmt"
	"log"
	"testing"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
)

func TestAzVMsCommand(t *testing.T) {
	fmt.Println()
	fmt.Println("[test case] Azure vms Command")

	// Test case parameters
	internal.MockFileSystem(true)
	subtests := []struct {
		name              string
		azTenantID        string
		azSubscriptionID  string
		azVerbosity       int
		azOutputFormat    string
		azOutputDirectory string
		version           string
		resourcesTestFile string
		vmsTestFile       string
		nicsTestFile      string
		publicIPsTestFile string
		wrapTableOutput   bool
		azMergedTable     bool
	}{
		{
			name:              "./cloudfox azure vms --tenant 11111111-1111-1111-1111-11111111",
			azTenantID:        "11111111-1111-1111-1111-11111111",
			azSubscriptionID:  "",
			azVerbosity:       2,
			azOutputDirectory: "~/.cloudfox",
			azOutputFormat:    "all",
			version:           "DEV",
			resourcesTestFile: "./test-data/resources.json",
			vmsTestFile:       "./test-data/vms.json",
			nicsTestFile:      "./test-data/nics.json",
			publicIPsTestFile: "./test-data/public-ips.json",
			wrapTableOutput:   false,
			azMergedTable:     false,
		},
		{
			name:              "./cloudfox azure vms --subscription AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAA",
			azTenantID:        "",
			azSubscriptionID:  "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAA",
			azVerbosity:       2,
			azOutputDirectory: "~/.cloudfox",
			azOutputFormat:    "all",
			version:           "DEV",
			resourcesTestFile: "./test-data/resources.json",
			vmsTestFile:       "./test-data/vms.json",
			nicsTestFile:      "./test-data/nics.json",
			publicIPsTestFile: "./test-data/public-ips.json",
			wrapTableOutput:   false,
			azMergedTable:     false,
		},
		{
			name:              "./cloudfox azure vms",
			azVerbosity:       2,
			azOutputFormat:    "all",
			azOutputDirectory: "~/.cloudfox",
			version:           "DEV",
			resourcesTestFile: "./test-data/resources.json",
			vmsTestFile:       "./test-data/vms.json",
			nicsTestFile:      "./test-data/nics.json",
			publicIPsTestFile: "./test-data/public-ips.json",
			wrapTableOutput:   false,
			azMergedTable:     false,
		},
	}

	// Mocked functions to simulate Azure calls and responses
	GetSubscriptions = mockedGetSubscriptions
	getResourceGroups = mockedGetResourceGroups
	getComputeVMsPerResourceGroup = mockedGetComputeVMsPerResourceGroup
	getNICdetails = mockedGetNICdetails
	getPublicIP = mockedGetPublicIP

	for _, s := range subtests {
		fmt.Println()
		fmt.Printf("[subtest] %s\n", s.name)
		globals.RESOURCES_TEST_FILE = s.resourcesTestFile
		globals.VMS_TEST_FILE = s.vmsTestFile
		globals.NICS_TEST_FILE = s.nicsTestFile
		globals.PUBLIC_IPS_TEST_FILE = s.publicIPsTestFile

		err := AzVMsCommand(s.azTenantID, s.azSubscriptionID, s.azOutputFormat, s.azOutputDirectory, s.version, 2, s.wrapTableOutput, s.azMergedTable)
		if err != nil {
			log.Fatalf(err.Error())
		}
	}
}
