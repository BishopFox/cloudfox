package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/storage/mgmt/storage"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/utils"
	"github.com/aws/smithy-go/ptr"
	"github.com/fatih/color"
)

func AzStorageCommand(AzTenantID, AzSubscriptionID, AzOutputFormat string, AzVerbosity int) error {
	var err error
	var header []string
	var body [][]string
	var outputDirectory, controlMessagePrefix string

	if AzTenantID != "" && AzSubscriptionID == "" {
		// ./cloudfox azure storage --tenant TENANT_ID
		fmt.Printf("[%s] Enumerating storage accounts for tenant %s\n", color.CyanString(globals.AZ_STORAGE_MODULE_NAME), AzTenantID)
		controlMessagePrefix = fmt.Sprintf("tenant-%s", AzTenantID)
		outputDirectory = filepath.Join(globals.CLOUDFOX_BASE_DIRECTORY, globals.AZ_DIR_BASE, "tenants", AzTenantID)
		header, body, err = getStoragePerTenant(AzTenantID)

	} else if AzTenantID == "" && AzSubscriptionID != "" {
		// ./cloudfox azure storage --subscription SUBSCRIPTION_ID
		fmt.Printf("[%s] Enumerating storage account for subscription %s\n", color.CyanString(globals.AZ_STORAGE_MODULE_NAME), AzSubscriptionID)
		controlMessagePrefix = fmt.Sprintf("subscription-%s", AzSubscriptionID)
		outputDirectory = filepath.Join(globals.CLOUDFOX_BASE_DIRECTORY, globals.AZ_DIR_BASE, "subscriptions", AzSubscriptionID)
		header, body, err = getStoragePerSubscription(AzSubscriptionID)

	} else {
		// Error: please make a valid flag selection
		fmt.Println("Please enter a valid input with a valid flag. Use --help for info.")
	}
	if err != nil {
		return err
	}
	fileNameWithoutExtension := globals.AZ_STORAGE_MODULE_NAME
	utils.OutputSelector(AzVerbosity, AzOutputFormat, header, body, outputDirectory, fileNameWithoutExtension, globals.AZ_STORAGE_MODULE_NAME, controlMessagePrefix)
	return nil
}

func getStoragePerTenant(AzTenantID string) ([]string, [][]string, error) {
	var err error
	var header []string
	var body, b [][]string

	for _, s := range getSubscriptionsForTenant(AzTenantID) {
		header, b, err = getRelevantStorageAccountData(ptr.ToString(s.SubscriptionID))
		if err != nil {
			return nil, nil, err
		} else {
			body = append(body, b...)
		}
	}
	return header, body, nil
}

func getStoragePerSubscription(AzSubscriptionID string) ([]string, [][]string, error) {
	var err error
	var header []string
	var body [][]string

	for _, s := range getSubscriptions() {
		if ptr.ToString(s.SubscriptionID) == AzSubscriptionID {
			header, body, err = getRelevantStorageAccountData(ptr.ToString(s.SubscriptionID))
			if err != nil {
				return nil, nil, err
			}
		}
	}
	return header, body, nil
}

func getRelevantStorageAccountData(subscriptionID string) ([]string, [][]string, error) {
	tableHeader := []string{"Subscription ID", "Storage Account Name", "Kind", "Public Blob Allowed"}
	var tableBody [][]string
	storageAccounts, err := getStorageAccounts(subscriptionID)
	if err != nil {
		return nil, nil, err
	}
	for _, sa := range storageAccounts {
		tableBody = append(tableBody,
			[]string{
				subscriptionID,
				ptr.ToString(sa.Name),
				string(sa.Kind),
				strconv.FormatBool(ptr.ToBool(sa.AllowBlobPublicAccess)),
			},
		)
	}
	return tableHeader, tableBody, nil
}

var getStorageAccounts = getStorageAccountsOriginal

func getStorageAccountsOriginal(subscriptionID string) ([]storage.Account, error) {
	storageClient := utils.GetStorageClient(subscriptionID)
	var storageAccounts []storage.Account
	for page, err := storageClient.List(context.TODO()); page.NotDone(); page.Next() {
		if err != nil {
			return nil, fmt.Errorf("could not get storage accounts for subscription")
		}
		storageAccounts = append(storageAccounts, page.Values()...)
	}
	return storageAccounts, nil
}

func mockedGetStorageAccounts(subscriptionID string) ([]storage.Account, error) {
	testFile, err := os.ReadFile(globals.STORAGE_ACCOUNTS_TEST_FILE)
	if err != nil {
		return nil, fmt.Errorf("could not open storage accounts test file %s", globals.STORAGE_ACCOUNTS_TEST_FILE)
	}
	var storageAccountsAll, storageAccountsResults []storage.Account
	err = json.Unmarshal(testFile, &storageAccountsAll)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshall storage accounts test file %s", globals.STORAGE_ACCOUNTS_TEST_FILE)
	}
	for _, sa := range storageAccountsAll {
		saSubID := strings.Split(ptr.ToString(sa.ID), "/")[2]
		if saSubID == subscriptionID {
			storageAccountsResults = append(storageAccountsResults, sa)
		}
	}
	return storageAccountsResults, nil
}
