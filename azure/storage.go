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

// Color functions
var cyan = color.New(color.FgCyan).SprintFunc()

func AzStorageCommand(AzTenantID, AzSubscription, AzOutputFormat, Version string, AzVerbosity int, AzWrapTable bool) error {
	// setup logging client
	o := internal.OutputClient{
		Verbosity:     AzVerbosity,
		CallingModule: globals.AZ_STORAGE_MODULE_NAME,
		Table: internal.TableClient{
			Wrap: AzWrapTable,
		},
	}

	// set up table vars
	var header []string
	var body [][]string

	var AzSubscriptionInfo SubsriptionInfo

	var publicBlobURLs []string

	if AzTenantID != "" && AzSubscription == "" {
		// cloudfox azure storage --tenant [TENANT_ID | PRIMARY_DOMAIN]

		var err error
		tenantInfo := populateTenant(AzTenantID)

		fmt.Printf("[%s][%s] Enumerating storage accounts for tenant %s\n",
			color.CyanString(emoji.Sprintf(":fox:cloudfox %s :fox:", Version)), color.CyanString(globals.AZ_RBAC_MODULE_NAME),
			fmt.Sprintf("%s (%s)", ptr.ToString(tenantInfo.DefaultDomain), ptr.ToString(tenantInfo.ID)))

		o.PrefixIdentifier = ptr.ToString(tenantInfo.DefaultDomain)
		o.Table.DirectoryName = filepath.Join(globals.CLOUDFOX_BASE_DIRECTORY, globals.AZ_DIR_BASE, ptr.ToString(tenantInfo.DefaultDomain))

		header, body, publicBlobURLs, err = getStorageInfoPerTenant(AzTenantID)

		if err != nil {
			return err
		}
		o.Table.TableFiles = append(o.Table.TableFiles,
			internal.TableFile{
				Header: header,
				Body:   body,
				Name:   fmt.Sprintf(globals.AZ_STORAGE_MODULE_NAME)})

	} else if AzTenantID == "" && AzSubscription != "" {
		// cloudfox azure storage  --subscription [SUBSCRIPTION_ID | SUBSCRIPTION_NAME]
		var err error
		tenantID := ptr.ToString(GetTenantIDPerSubscription(AzSubscription))
		tenantInfo := populateTenant(tenantID)
		AzSubscriptionInfo = PopulateSubsriptionType(AzSubscription)
		o.PrefixIdentifier = ptr.ToString(GetSubscriptionNameFromID(AzSubscriptionInfo.Name))
		o.Table.DirectoryName = filepath.Join(globals.CLOUDFOX_BASE_DIRECTORY, globals.AZ_DIR_BASE, ptr.ToString(tenantInfo.DefaultDomain), AzSubscriptionInfo.Name)

		fmt.Printf(
			"[%s][%s] Enumerating storage accounts for subscription %s\n",
			color.CyanString(emoji.Sprintf(":fox:cloudfox %s :fox:", Version)),
			color.CyanString(globals.AZ_STORAGE_MODULE_NAME),
			fmt.Sprintf("%s (%s)", AzSubscriptionInfo.Name, AzSubscriptionInfo.ID))
		//AzTenantID := ptr.ToString(GetTenantIDPerSubscription(AzSubscription))
		header, body, publicBlobURLs, err = getStorageInfoPerSubscription(ptr.ToString(tenantInfo.ID), AzSubscriptionInfo.ID)
		if err != nil {
			return err
		}

		o.Table.TableFiles = append(o.Table.TableFiles,
			internal.TableFile{
				Header: header,
				Body:   body,
				Name:   fmt.Sprintf(globals.AZ_STORAGE_MODULE_NAME)})

	} else {
		// Error: please make a valid flag selection
		fmt.Println("Please enter a valid input with a valid flag. Use --help for info.")
	}

	if body != nil {
		//	internal.OutputSelector(AzVerbosity, AzOutputFormat, header, body, outputDirectory, fileNameWithoutExtension, globals.AZ_STORAGE_MODULE_NAME, AzWrapTable, controlMessagePrefix)
		o.WriteFullOutput(o.Table.TableFiles, nil)

	}
	if publicBlobURLs != nil {
		err := writeBlobURLslootFile(globals.AZ_STORAGE_MODULE_NAME, o.PrefixIdentifier, o.Table.DirectoryName, publicBlobURLs)
		if err != nil {
			return err
		}
	}
	return nil
}

func writeBlobURLslootFile(callingModule, controlMessagePrefix, outputDirectory string, publicBlobURLs []string) error {
	lootDirectory := filepath.Join(outputDirectory, "loot")
	lootFilePath := filepath.Join(lootDirectory, "public-blob-urls.txt")

	err := os.MkdirAll(lootDirectory, os.ModePerm)
	if err != nil {
		return err
	}

	file, err := os.Create(lootFilePath)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, url := range publicBlobURLs {
		_, err := file.WriteString(url + "\n")
		if err != nil {
			return err
		}
	}

	fmt.Printf("[%s][%s] Loot file written to [%s]\n", cyan(callingModule), cyan(controlMessagePrefix), file.Name())
	return nil
}

func getStorageInfoPerTenant(AzTenantID string) ([]string, [][]string, []string, error) {
	var err error
	var header []string
	var body, b [][]string
	var publicBlobURLs []string

	for _, s := range GetSubscriptionsPerTenantID(AzTenantID) {
		header, b, publicBlobURLs, err = getRelevantStorageAccountData(AzTenantID, ptr.ToString(s.SubscriptionID))
		if err != nil {
			return nil, nil, nil, err
		} else {
			body = append(body, b...)
		}
	}
	return header, body, publicBlobURLs, nil
}

func getStorageInfoPerSubscription(AzTenantID, AzSubscriptionID string) ([]string, [][]string, []string, error) {
	var err error
	var header []string
	var body [][]string
	var publicBlobURLs []string

	for _, s := range GetSubscriptions() {
		if ptr.ToString(s.SubscriptionID) == AzSubscriptionID {
			header, body, publicBlobURLs, err = getRelevantStorageAccountData(AzTenantID, ptr.ToString(s.SubscriptionID))
			if err != nil {
				return nil, nil, nil, err
			}
		}
	}
	return header, body, publicBlobURLs, nil
}

func getRelevantStorageAccountData(tenantID, subscriptionID string) ([]string, [][]string, []string, error) {
	tableHeader := []string{"Subscription Name", "Storage Account Name", "Container Name", "Access Status"}
	var tableBody [][]string
	var publicBlobURLs []string
	storageAccounts, err := getStorageAccounts(subscriptionID)
	if err != nil {
		return nil, nil, nil, err
	}
	for _, sa := range storageAccounts {
		blobClient, err := internal.GetStorageAccountBlobClient(tenantID, ptr.ToString(sa.Name))
		if err != nil {
			return nil, nil, nil, err
		}
		containers, err := getStorageAccountContainers(blobClient)
		if err != nil {
			// rather than return an error, we'll just add a row to the table highlighting the storage account name and that we couldn't get the containers

			tableBody = append(tableBody,
				[]string{
					subscriptionID,
					ptr.ToString(sa.Name),
					"Unknown",
					"Authorization Failure"})

			//return nil, nil, nil, nil
		}

		for containerName, accessType := range containers {
			tableBody = append(tableBody,
				[]string{
					ptr.ToString(GetSubscriptionNameFromID(subscriptionID)),
					ptr.ToString(sa.Name),
					containerName,
					accessType})
		}
		urls, err := getPublicBlobURLs(blobClient, ptr.ToString(sa.Name), containers)
		if err == nil {
			continue
			//return nil, nil, nil, err
		}
		publicBlobURLs = append(publicBlobURLs, urls...)

	}
	return tableHeader, tableBody, publicBlobURLs, nil
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

func getPublicBlobURLs(client *azblob.Client, storageAccountName string, containers map[string]string) ([]string, error) {
	var publicBlobURLs []string
	for containerName, accessType := range containers {
		if accessType == "public" {
			url, err := getPublicBlobURLsForContainer(client, storageAccountName, containerName)
			if err != nil {
				//return nil, err
				continue
			}
			publicBlobURLs = append(publicBlobURLs, url...)
		}
	}
	return publicBlobURLs, nil
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

	if blobNames == nil {
		return nil, nil
	}

	for _, b := range blobNames {
		blobURL := fmt.Sprintf("https://%s.blob.core.windows.net/%s/%s", storageAccountName, containerName, b)

		response, err := http.Head(blobURL)
		if err != nil {
			return nil, err
		}

		if response.StatusCode == http.StatusOK {
			publicBlobURLs = append(publicBlobURLs, blobURL)
		}
	}
	return publicBlobURLs, nil
}
