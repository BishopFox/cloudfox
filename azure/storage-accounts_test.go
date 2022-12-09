package azure

import (
	"fmt"
	"log"
	"testing"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/utils"
)

func TestStorageAccountsCommand(t *testing.T) {
	fmt.Println()
	fmt.Println("[test case] Azure Storage Accounts")

	// Test case parameters
	subtests := []struct {
		name                    string
		AzTenantID              string
		AzSubscriptionID        string
		AzRGName                string
		AzOutputFormat          string
		AzVerbosity             int
		resourcesTestFile       string
		storageAccountsTestFile string
	}{
		{
			name:                    "./cloudfox az storage -t 11111111-1111-1111-1111-11111111",
			AzTenantID:              "11111111-1111-1111-1111-11111111",
			AzSubscriptionID:        "",
			AzRGName:                "",
			AzOutputFormat:          "all",
			AzVerbosity:             2,
			resourcesTestFile:       "./test-data/resources.json",
			storageAccountsTestFile: "./test-data/storage-accounts.json",
		},
		{
			name:                    "./cloudfox az storage -t 11111111-1111-1111-1111-11111111 -s BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBB",
			AzTenantID:              "11111111-1111-1111-1111-11111111",
			AzSubscriptionID:        "BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBB",
			AzRGName:                "",
			AzOutputFormat:          "all",
			AzVerbosity:             2,
			resourcesTestFile:       "./test-data/resources.json",
			storageAccountsTestFile: "./test-data/storage-accounts.json",
		},
		{
			name:                    "./cloudfox az storage -t 22222222-2222-2222-2222-22222222 -s CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCC -g ResourceGroupC1",
			AzTenantID:              "22222222-2222-2222-2222-22222222",
			AzSubscriptionID:        "CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCC",
			AzRGName:                "ResourceGroupC1",
			AzOutputFormat:          "all",
			AzVerbosity:             2,
			resourcesTestFile:       "./test-data/resources.json",
			storageAccountsTestFile: "./test-data/storage-accounts.json",
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

		err := AzStorageCommand(s.AzTenantID, s.AzSubscriptionID, s.AzRGName, s.AzOutputFormat, s.AzVerbosity)
		if err != nil {
			log.Fatal(err)
		}
	}
}
