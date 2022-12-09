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

func AzStorageCommand(AzTenantID, AzSubscriptionID, AzRGName, AzOutputFormat string, AzVerbosity int) error {

	header := []string{"Tenant ID", "Subscription ID", "Storage Account Name", "Kind", "BlobPublicAccess"}
	var body [][]string
	var fileNameWithoutExtension, controlMessagePrefix string
	outputDirectory := filepath.Join(globals.CLOUDFOX_BASE_OUTPUT_DIRECTORY, globals.AZ_OUTPUT_DIRECTORY)

	switch AzTenantID {
	case "": // TO-DO: add an option for the interactive menu: ./cloudfox azure storage
		return fmt.Errorf(
			"[%s] please select a valid tenant ID",
			color.CyanString(globals.AZ_STORAGE_MODULE_NAME))
	default:
		switch AzSubscriptionID {
		case "": // ./cloudfox azure storage -t TENANT_ID
			subs := getSubscriptionsForTenant(AzTenantID)
			for _, s := range subs {
				b, err := getRelevantStorageAccountData(AzTenantID, ptr.ToString(s.SubscriptionID))
				if err != nil {
					// To-do: Print error message and skip
				}
				body = append(body, b...)
			}
			fileNameWithoutExtension = fmt.Sprintf("storage-tenant-%s", AzTenantID)
			controlMessagePrefix = fmt.Sprintf("ten-%s", AzTenantID)

		default:
			switch AzRGName {
			case "": // ./cloudfox azure storage -t TENANT_ID -s SUB_ID
				fileNameWithoutExtension = fmt.Sprintf("storage-sub-%s", AzSubscriptionID)
				controlMessagePrefix = fmt.Sprintf("sub-%s", AzSubscriptionID)
			default: // ./cloudfox azure storage -t TENANT_ID -s SUB_ID -g RG_NAME
				fileNameWithoutExtension = fmt.Sprintf("storage-rg-%s", AzSubscriptionID)
				controlMessagePrefix = fmt.Sprintf("rg-%s", AzSubscriptionID)
			}
		}
	}

	utils.OutputSelector(AzVerbosity, AzOutputFormat, header, body, outputDirectory, fileNameWithoutExtension, globals.AZ_STORAGE_MODULE_NAME, controlMessagePrefix)
	return nil
}

func getRelevantStorageAccountData(tenantID, subscriptionID string) ([][]string, error) {
	var tableBody [][]string
	storageAccounts, err := getStorageAccounts(subscriptionID)
	if err != nil {
		return nil, err
	}
	for _, sa := range storageAccounts {
		tableBody = append(tableBody,
			[]string{
				tenantID,
				subscriptionID,
				ptr.ToString(sa.Name),
				string(sa.Kind),
				strconv.FormatBool(ptr.ToBool(sa.AllowBlobPublicAccess)),
			},
		)
	}
	return tableBody, nil
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
