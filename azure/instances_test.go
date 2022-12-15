package azure

import (
	"fmt"
	"log"
	"testing"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/utils"
)

func TestAzInstancesCommand(t *testing.T) {
	fmt.Println()
	fmt.Println("[test case] Azure Instances Command")

	// Test case parameters
	utils.MockFileSystem(true)
	subtests := []struct {
		Name              string
		AzTenantID        string
		AzSubscriptionID  string
		AzVerbosity       int
		AzOutputFormat    string
		resourcesTestFile string
		vmsTestFile       string
		nicsTestFile      string
		publicIPsTestFile string
	}{
		{
			Name:              "./cloudfox azure instances --tenant TENANT_ID",
			AzTenantID:        "11111111-1111-1111-1111-11111111",
			AzSubscriptionID:  "",
			AzVerbosity:       2,
			AzOutputFormat:    "table",
			resourcesTestFile: "./test-data/resources.json",
			vmsTestFile:       "./test-data/vms.json",
			nicsTestFile:      "./test-data/nics.json",
			publicIPsTestFile: "./test-data/public-ips.json",
		},
		{
			Name:              "./cloudfox azure instances --subscription SUBSCRIPTION_ID",
			AzTenantID:        "",
			AzSubscriptionID:  "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAA",
			AzVerbosity:       2,
			AzOutputFormat:    "table",
			resourcesTestFile: "./test-data/resources.json",
			vmsTestFile:       "./test-data/vms.json",
			nicsTestFile:      "./test-data/nics.json",
			publicIPsTestFile: "./test-data/public-ips.json",
		},
	}

	// Mocked functions to simulate Azure calls and responses
	getTenants = mockedGetTenants
	getSubscriptions = mockedGetSubscriptions
	getResourceGroups = mockedGetResourceGroups
	getComputeVMsPerResourceGroup = mockedGetComputeVMsPerResourceGroup
	getNICdetails = mockedGetNICdetails
	getPublicIP = mockedGetPublicIP

	for _, s := range subtests {
		fmt.Println()
		fmt.Printf("[subtest] %s\n", s.Name)
		globals.RESOURCES_TEST_FILE = s.resourcesTestFile
		globals.VMS_TEST_FILE = s.vmsTestFile
		globals.NICS_TEST_FILE = s.nicsTestFile
		globals.PUBLIC_IPS_TEST_FILE = s.publicIPsTestFile

		err := AzInstancesCommand(
			s.AzTenantID,
			s.AzSubscriptionID,
			s.AzOutputFormat,
			s.AzVerbosity)

		if err != nil {
			log.Fatalf(err.Error())
		}
	}
}
