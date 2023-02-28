package internal

import (
	"fmt"
	"log"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/authorization/mgmt/authorization"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/compute/mgmt/compute"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/network/mgmt/network"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/resources"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/subscriptions"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/storage/mgmt/storage"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/services/graphrbac/1.6/graphrbac"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/BishopFox/cloudfox/globals"
)

func getAuthorizer(endpoint string) (autorest.Authorizer, error) {
	auth, err := auth.NewAuthorizerFromCLIWithResource(endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to get client authorizer: %s", err)
	}
	return auth, nil
}

func GetTenantsClient() subscriptions.TenantsClient {
	client := subscriptions.NewTenantsClient()
	a, err := getAuthorizer(globals.AZ_RESOURCE_MANAGER_ENDPOINT)
	if err != nil {
		log.Fatalf("failed to get subscriptions client: %s", err)
	}
	client.Authorizer = a
	client.AddToUserAgent(globals.CLOUDFOX_USER_AGENT)
	return client
}

func GetSubscriptionsClient() subscriptions.Client {
	client := subscriptions.NewClient()
	a, err := getAuthorizer(globals.AZ_RESOURCE_MANAGER_ENDPOINT)
	if err != nil {
		log.Fatalf("failed to get subscriptions client: %s", err)
	}
	client.Authorizer = a
	client.AddToUserAgent(globals.CLOUDFOX_USER_AGENT)
	return client
}

func GetResourceGroupsClient(subscriptionID string) resources.GroupsClient {
	client := resources.NewGroupsClient(subscriptionID)
	a, err := getAuthorizer(globals.AZ_RESOURCE_MANAGER_ENDPOINT)
	if err != nil {
		log.Fatalf("failed to get resource groups client: %s", err)
	}
	client.Authorizer = a
	client.AddToUserAgent(globals.CLOUDFOX_USER_AGENT)
	return client
}

func GetAADUsersClient(tenantID string) graphrbac.UsersClient {
	client := graphrbac.NewUsersClient(tenantID)
	a, err := getAuthorizer(globals.AZ_GRAPH_ENDPOINT)
	if err != nil {
		log.Fatalf("failed to get azure active directory client: %s", err)
	}
	client.Authorizer = a
	client.AddToUserAgent(globals.CLOUDFOX_USER_AGENT)
	return client
}

func GetRoleAssignmentsClient(subscriptionID string) authorization.RoleAssignmentsClient {
	client := authorization.NewRoleAssignmentsClient(subscriptionID)
	a, err := getAuthorizer(globals.AZ_RESOURCE_MANAGER_ENDPOINT)
	if err != nil {
		log.Fatalf("failed to get role assignments client: %s", err)
	}
	client.Authorizer = a
	client.AddToUserAgent(globals.CLOUDFOX_USER_AGENT)
	return client
}

func GetRoleDefinitionsClient(subscriptionName string) authorization.RoleDefinitionsClient {
	client := authorization.NewRoleDefinitionsClient(subscriptionName)
	a, err := getAuthorizer(globals.AZ_RESOURCE_MANAGER_ENDPOINT)
	if err != nil {
		log.Fatalf("failed to get role definitions client: %s", err)
	}
	client.Authorizer = a
	client.AddToUserAgent(globals.CLOUDFOX_USER_AGENT)
	return client
}

func GetVirtualMachinesClient(subscriptionID string) compute.VirtualMachinesClient {
	client := compute.NewVirtualMachinesClient(subscriptionID)
	authorizer, err := getAuthorizer(globals.AZ_RESOURCE_MANAGER_ENDPOINT)
	if err != nil {
		log.Fatalf("failed to get compute client: %s", err)
	}
	client.Authorizer = authorizer
	client.AddToUserAgent(globals.CLOUDFOX_USER_AGENT)
	return client
}

func GetNICClient(subscriptionID string) network.InterfacesClient {
	client := network.NewInterfacesClient(subscriptionID)
	authorizer, err := getAuthorizer(globals.AZ_RESOURCE_MANAGER_ENDPOINT)
	if err != nil {
		log.Fatalf("failed to get nic client: %s", err)
	}
	client.Authorizer = authorizer
	client.AddToUserAgent(globals.CLOUDFOX_USER_AGENT)
	return client
}

func GetPublicIPClient(subscriptionID string) network.PublicIPAddressesClient {
	client := network.NewPublicIPAddressesClient(subscriptionID)
	authorizer, err := getAuthorizer(globals.AZ_RESOURCE_MANAGER_ENDPOINT)
	if err != nil {
		log.Fatalf("failed to get public ip client: %s", err)
	}
	client.Authorizer = authorizer
	return client
}

func GetStorageClient(subscriptionID string) storage.AccountsClient {
	client := storage.NewAccountsClient(subscriptionID)
	a, err := getAuthorizer(globals.AZ_RESOURCE_MANAGER_ENDPOINT)
	if err != nil {
		log.Fatalf("failed to get storage client: %s", err)
	}
	client.Authorizer = a
	client.AddToUserAgent(globals.CLOUDFOX_USER_AGENT)
	return client
}

func GetStorageAccountBlobClient(tenantID, storageAccountName string) (*azblob.Client, error) {
	serviceURL := fmt.Sprintf("https://%s.blob.core.windows.net/", storageAccountName)
	cred, err := azidentity.NewAzureCLICredential(&azidentity.AzureCLICredentialOptions{TenantID: tenantID})
	if err != nil {
		fmt.Println(err)
	}
	client, err := azblob.NewClient(serviceURL, cred, nil)
	if err != nil {
		return nil, err
	}
	return client, nil
}

func GetARMresourcesClient(tenantID, subscriptionID string) *armresources.Client {
	cred, err := azidentity.NewAzureCLICredential(&azidentity.AzureCLICredentialOptions{TenantID: tenantID})
	if err != nil {
		log.Fatalf("failed to get credentials from Azure CLI: %s", err)
	}
	client, err := armresources.NewClient(subscriptionID, cred, nil)
	if err != nil {
		log.Fatalf("failed to get ARM resources client: %s", err)
	}
	return client
}
