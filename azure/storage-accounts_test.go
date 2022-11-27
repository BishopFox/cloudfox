package azure

import (
	"fmt"
	"testing"

	"github.com/BishopFox/cloudfox/globals"
)

func TestStorageAccountsCommand(t *testing.T) {
	fmt.Println()
	fmt.Println("[test case] Azure Storage Accounts")

	// Test case parameters
	subtests := []struct {
		name                    string
		storageAccountsTestFile string
	}{
		{
			name:                    "basic acceptance",
			storageAccountsTestFile: "./test-data/storage-accounts.json",
		},
	}
	GetStorageAccounts = MockedGetStorageAccounts
	for _, s := range subtests {
		fmt.Println()
		fmt.Printf("[subtest] %s\n", s.name)
		globals.STORAGE_ACCOUNTS_TEST_FILE = s.storageAccountsTestFile
		_, _ = MockedGetStorageAccounts("subscriptoonID_is_irrelevant_for_this_mock")
	}
}
