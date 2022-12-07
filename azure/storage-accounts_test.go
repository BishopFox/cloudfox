package azure

import (
	"fmt"
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
		AzVerbosity             int
		AzOutputFormat          string
		resourcesTestFile       string
		storageAccountsTestFile string
	}{
		{
			name:                    "./cloudfox storage --subscription SUBSCRIPTION_ID",
			AzSubscriptionID:        "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAA",
			resourcesTestFile:       "./test-data/resources.json",
			storageAccountsTestFile: "./test-data/storage-accounts.json",
		},
	}
	utils.MockFileSystem(true)
	// Mocked functions to simulate Azure calls and responses
	getStorageAccounts = mockedGetStorageAccounts
	getTenants = mockedGetTenants
	getSubscriptions = mockedGetSubscriptions
	getResourceGroups = mockedGetResourceGroups

	for _, s := range subtests {
		fmt.Println()
		fmt.Printf("[subtest] %s\n", s.name)
		globals.RESOURCES_TEST_FILE = s.resourcesTestFile
		globals.STORAGE_ACCOUNTS_TEST_FILE = s.storageAccountsTestFile

		_, _ = getStorageAccounts(s.AzSubscriptionID)
	}
}
