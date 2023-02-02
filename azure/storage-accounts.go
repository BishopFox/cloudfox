package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/storage/mgmt/storage"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/smithy-go/ptr"
	"github.com/fatih/color"
	"github.com/kyokomi/emoji"
)

func AzStorageCommand(AzTenantID, AzSubscriptionID, AzOutputFormat, Version string, AzVerbosity int, AzWrapTable bool) error {
	var err error
	var header []string
	var body [][]string
	var outputDirectory, controlMessagePrefix string

	if AzTenantID != "" && AzSubscriptionID == "" {
		// ./cloudfox azure storage --tenant TENANT_ID
		fmt.Printf(
			"[%s][%s] Enumerating storage accounts for tenant %s\n",
			color.CyanString(emoji.Sprintf(":fox:cloudfox %s :fox:", Version)),
			color.CyanString(globals.AZ_STORAGE_MODULE_NAME),
			AzTenantID)
		header, body, err = getStorageInfoPerTenant(AzTenantID)
		controlMessagePrefix = fmt.Sprintf("tenant-%s", AzTenantID)
		outputDirectory = filepath.Join(
			globals.CLOUDFOX_BASE_DIRECTORY,
			globals.AZ_DIR_BASE,
			"tenants",
			AzTenantID)

	} else if AzTenantID == "" && AzSubscriptionID != "" {
		// ./cloudfox azure storage --subscription SUBSCRIPTION_ID
		fmt.Printf(
			"[%s][%s] Enumerating storage accounts for subscription %s\n",
			color.CyanString(emoji.Sprintf(":fox:cloudfox %s :fox:", Version)),
			color.CyanString(globals.AZ_STORAGE_MODULE_NAME),
			AzSubscriptionID)
		AzTenantID := ptr.ToString(GetTenantIDPerSubscription(AzSubscriptionID))
		header, body, err = getStorageInfoPerSubscription(AzTenantID, AzSubscriptionID)
		controlMessagePrefix = fmt.Sprintf("subscription-%s", AzSubscriptionID)
		outputDirectory = filepath.Join(
			globals.CLOUDFOX_BASE_DIRECTORY,
			globals.AZ_DIR_BASE,
			"subscriptions",
			AzSubscriptionID)
	} else {
		// Error: please make a valid flag selection
		fmt.Println("Please enter a valid input with a valid flag. Use --help for info.")
	}
	if err != nil {
		return err
	}
	fileNameWithoutExtension := globals.AZ_STORAGE_MODULE_NAME
	if body != nil {
		internal.OutputSelector(AzVerbosity, AzOutputFormat, header, body, outputDirectory, fileNameWithoutExtension, globals.AZ_STORAGE_MODULE_NAME, AzWrapTable, controlMessagePrefix)
	}
	return nil
}

func getStorageInfoPerTenant(AzTenantID string) ([]string, [][]string, error) {
	var err error
	var header []string
	var body, b [][]string

	for _, s := range getSubscriptionsPerTenantID(AzTenantID) {
		header, b, err = getRelevantStorageAccountData(AzTenantID, ptr.ToString(s.SubscriptionID))
		if err != nil {
			return nil, nil, err
		} else {
			body = append(body, b...)
		}
	}
	return header, body, nil
}

func getStorageInfoPerSubscription(AzTenantID, AzSubscriptionID string) ([]string, [][]string, error) {
	var err error
	var header []string
	var body [][]string

	for _, s := range getSubscriptions() {
		if ptr.ToString(s.SubscriptionID) == AzSubscriptionID {
			header, body, err = getRelevantStorageAccountData(AzTenantID, ptr.ToString(s.SubscriptionID))
			if err != nil {
				return nil, nil, err
			}
		}
	}
	return header, body, nil
}

func getRelevantStorageAccountData(tenantID, subscriptionID string) ([]string, [][]string, error) {
	tableHeader := []string{"Subscription ID", "Storage Account Name", "Container Name", "Access Status"}
	var tableBody [][]string
	storageAccounts, err := getStorageAccounts(subscriptionID)
	if err != nil {
		return nil, nil, err
	}
	for _, sa := range storageAccounts {
		blobClient, err := internal.GetStorageAccountBlobClient(tenantID, ptr.ToString(sa.Name))
		if err != nil {
			return nil, nil, err
		}
		containers, err := getStorageAccountContainers(blobClient)
		if err != nil {
			return nil, nil, err
		}
		for containerName, accessType := range containers {
			tableBody = append(tableBody,
				[]string{
					subscriptionID,
					ptr.ToString(sa.Name),
					containerName,
					accessType})
		}
	}
	return tableHeader, tableBody, nil
}

var getStorageAccounts = getStorageAccountsOriginal

func getStorageAccountsOriginal(subscriptionID string) ([]storage.Account, error) {
	storageClient := internal.GetStorageClient(subscriptionID)
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

func getStorageAccountContainers(client *azblob.Client) (map[string]string, error) {
	containers := make(map[string]string)
	pager := client.NewListContainersPager(&azblob.ListContainersOptions{
		Include: azblob.ListContainersInclude{Metadata: true, Deleted: true},
	})
	for pager.More() {
		resp, err := pager.NextPage(context.TODO())
		if err != nil {
			return nil, err
		}
		for _, container := range resp.ContainerItems {
			if container.Properties.PublicAccess != nil {
				containers[ptr.ToString(container.Name)] = "public"
			} else {
				containers[ptr.ToString(container.Name)] = "private"
			}
		}
	}
	return containers, nil
}

func getPublicBlobURLsForContainer(client *azblob.Client, storageAccountName, containerName string) ([]string, error) {
	blobNames, err := getAllBlobsForContainer(client, containerName)
	if err != nil {
		return nil, err
	}
	publicBlobURLs, err := validatePublicBlobURLs(storageAccountName, containerName, blobNames)
	if err != nil {
		return nil, err
	}
	return publicBlobURLs, nil
}

func getAllBlobsForContainer(blobClient *azblob.Client, containerName string) ([]string, error) {
	var blobNames []string

	pager := blobClient.NewListBlobsFlatPager(containerName, &azblob.ListBlobsFlatOptions{
		Include: container.ListBlobsInclude{Deleted: true, Versions: true},
	})

	for pager.More() {
		resp, err := pager.NextPage(context.TODO())
		if err != nil {
			return nil, err
		}
		for _, b := range resp.Segment.BlobItems {
			blobNames = append(blobNames, ptr.ToString(b.Name))
		}
	}

	return blobNames, nil
}

func validatePublicBlobURLs(storageAccountName, containerName string, blobNames []string) ([]string, error) {
	var publicBlobURLs []string

	for _, b := range blobNames {
		blobURL := fmt.Sprintf("https://%s.blob.core.windows.net/%s/%s", storageAccountName, containerName, b)

		response, err := http.Get(blobURL)
		if err != nil {
			return nil, err
		}

		if response.StatusCode == http.StatusOK {
			publicBlobURLs = append(publicBlobURLs, blobURL)
		}
	}
	return publicBlobURLs, nil
}

func getPublicBlobURLs(client *azblob.Client, storageAccountName string, containers map[string]string) ([]string, error) {
	var publicBlobURLs []string
	for containerName, accessType := range containers {
		if accessType == "public" {
			url, err := getPublicBlobURLsForContainer(client, storageAccountName, containerName)
			if err != nil {
				return nil, err
			}
			publicBlobURLs = append(publicBlobURLs, url...)
		}
	}
	return publicBlobURLs, nil
}
