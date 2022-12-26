package azure

import (
	"fmt"
	"log"
	"testing"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/utils"
)

func TestAzStorageCommand(t *testing.T) {
	fmt.Println()
	fmt.Println("[test case] Azure Storage Accounts")

	// Test case parameters
	subtests := []struct {
		name                    string
		AzTenantID              string
		AzSubscriptionID        string
		AzOutputFormat          string
		AzVerbosity             int
		resourcesTestFile       string
		storageAccountsTestFile string
		version                 string
	}{
		{
			name:                    "./cloudfox az storage --tenant 11111111-1111-1111-1111-11111111",
			AzTenantID:              "11111111-1111-1111-1111-11111111",
			AzSubscriptionID:        "",
			AzOutputFormat:          "all",
			AzVerbosity:             2,
			resourcesTestFile:       "./test-data/resources.json",
			storageAccountsTestFile: "./test-data/storage-accounts.json",
			version:                 "DEV",
		},
		{
			name:                    "./cloudfox az storage --subscription BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBB",
			AzTenantID:              "",
			AzSubscriptionID:        "BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBB",
			AzOutputFormat:          "all",
			AzVerbosity:             2,
			resourcesTestFile:       "./test-data/resources.json",
			storageAccountsTestFile: "./test-data/storage-accounts.json",
			version:                 "DEV",
		},
	}
	utils.MockFileSystem(true)
	// Mocked functions to simulate Azure calls and responses
	getTenants = mockedGetTenants
	getSubscriptions = mockedGetSubscriptions
	getResourceGroups = mockedGetResourceGroups
	getStorageAccounts = mockedGetStorageAccounts

	for _, s := range subtests {
		fmt.Println()
		fmt.Printf("[subtest] %s\n", s.name)
		globals.RESOURCES_TEST_FILE = s.resourcesTestFile
		globals.STORAGE_ACCOUNTS_TEST_FILE = s.storageAccountsTestFile

		err := AzStorageCommand(s.AzTenantID, s.AzSubscriptionID, s.AzOutputFormat, s.version, s.AzVerbosity)
		if err != nil {
			log.Fatal(err)
		}
	}
}
