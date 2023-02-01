package azure

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/smithy-go/ptr"
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
		wrapTableOutput         bool
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
			wrapTableOutput:         false,
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
			wrapTableOutput:         false,
		},
		{
			name:                    "./cloudfox az storage",
			AzOutputFormat:          "all",
			AzVerbosity:             2,
			resourcesTestFile:       "./test-data/resources.json",
			storageAccountsTestFile: "./test-data/storage-accounts.json",
			version:                 "DEV",
			wrapTableOutput:         false,
		},
	}
	internal.MockFileSystem(true)
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

		err := AzStorageCommand(s.AzTenantID, s.AzSubscriptionID, s.AzOutputFormat, s.version, s.AzVerbosity, s.wrapTableOutput)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func TestEnumeratePublicBlobs(t *testing.T) {
	tenantID := ""
	storageAccountName := ""
	serviceURL := fmt.Sprintf("https://%s.blob.core.windows.net/", storageAccountName)
	containerName := ""
	var blobNames []string

	cred, err := azidentity.NewAzureCLICredential(&azidentity.AzureCLICredentialOptions{TenantID: tenantID})
	if err != nil {
		fmt.Println(err)
	}

	client, err := azblob.NewClient(serviceURL, cred, nil)
	if err != nil {
		fmt.Println(err)
	}

	pager := client.NewListBlobsFlatPager(containerName, &azblob.ListBlobsFlatOptions{
		Include: container.ListBlobsInclude{Deleted: true, Versions: true},
	})

	for pager.More() {
		resp, err := pager.NextPage(context.TODO())
		if err != nil {
			log.Fatal(err)
		}
		for _, b := range resp.Segment.BlobItems {
			blobNames = append(blobNames, ptr.ToString(b.Name))
		}
	}

	for _, b := range blobNames {
		blobURL := fmt.Sprintf("https://%s.blob.core.windows.net/%s/%s", storageAccountName, containerName, b)

		response, err := http.Get(blobURL)
		if err != nil {
			fmt.Println("Error accessing the blob:", err)
			return
		}

		if response.StatusCode == http.StatusOK {
			fmt.Printf("%s: public\n", b)
		} else {
			fmt.Printf("%s: private\n", b)
		}
	}
}
