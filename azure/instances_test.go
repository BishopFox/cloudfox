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
		AzSubscriptionID  string
		AzRGName          string
		AzVerbosity       int
		AzOutputFormat    string
		resourcesTestFile string
		vmsTestFile       string
		nicsTestFile      string
		publicIPsTestFile string
	}{
		{
			Name:              "basic acceptance with subscription filter",
			AzSubscriptionID:  "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAA",
			AzRGName:          "",
			AzVerbosity:       2,
			AzOutputFormat:    "table",
			resourcesTestFile: "./test-data/resources.json",
			vmsTestFile:       "./test-data/vms.json",
			nicsTestFile:      "./test-data/nics.json",
			publicIPsTestFile: "./test-data/public-ips.json",
		},
		{
			Name:              "basic acceptance with resource group filter",
			AzSubscriptionID:  "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAA",
			AzRGName:          "ResourceGroupA2",
			AzVerbosity:       2,
			AzOutputFormat:    "table",
			resourcesTestFile: "./test-data/resources.json",
			vmsTestFile:       "./test-data/vms.json",
			nicsTestFile:      "./test-data/nics.json",
			publicIPsTestFile: "./test-data/public-ips.json",
		},
	}

	// Mocked functions to simulate Azure calls and responses
	GetTenants = MockedGetTenants
	GetSubscriptions = MockedGetSubscriptions
	GetResourceGroups = MockedGetResourceGroups
	GetComputeVMsPerResourceGroup = MockedGetComputeVMsPerResourceGroup
	GetNICdetails = MockedGetNICdetails
	GetPublicIP = MockedGetPublicIP

	for _, s := range subtests {
		fmt.Println()
		fmt.Printf("[subtest] %s\n", s.Name)
		globals.RESOURCES_TEST_FILE = s.resourcesTestFile
		globals.VMS_TEST_FILE = s.vmsTestFile
		globals.NICS_TEST_FILE = s.nicsTestFile
		globals.PUBLIC_IPS_TEST_FILE = s.publicIPsTestFile

		err := AzInstancesCommand(
			s.AzSubscriptionID,
			s.AzRGName,
			s.AzOutputFormat,
			s.AzVerbosity)

		if err != nil {
			log.Fatalf(err.Error())
		}
	}
}
