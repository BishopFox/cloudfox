package utils

import (
	"context"
	"log"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/resources"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/subscriptions"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/aws/smithy-go/ptr"
)

func AzNewGraphAuthorizer(tenantID string) autorest.Authorizer {
	a, err := auth.NewAuthorizerFromCLIWithResource("https://graph.windows.net/")
	if err != nil {
		log.Fatalf("[-] Could not create Graph API Client. %s\n", err)
	}
	return a
}

func AzNewResourceManagerAuthorizer() autorest.Authorizer {
	a, err := auth.NewAuthorizerFromCLIWithResource("https://management.azure.com/")
	if err != nil {
		log.Fatalf("[-] Could not create Azure Resource Manager (ARM) API Client. %s\n", err)
	}
	return a
}

func AzGetScopeInformation() map[string]map[string][]string {
	// Auxiliary variables
	results := make(map[string]map[string][]string)
	var subscriptionsList []string

	// Clients & Authorizers
	subscriptionsClient := subscriptions.NewClient()
	subscriptionsClient.Authorizer = AzNewResourceManagerAuthorizer()

	for page, err := subscriptionsClient.List(context.TODO()); page.NotDone(); err = page.Next() {
		if err != nil {
			log.Fatalf("[-] Could not enumerate tenants for current user. %s", err)
		}
		// Little bit of an obscure logic here but it works. It's a map of maps.
		// Format: map[TenantID]map[SubscriptionID][]ResourceGroups
		// Resource groups are mapped to subscription IDs, which in turn are mapped to tenant IDs.
		for _, sub := range page.Values() {
			tenantID := ptr.ToString(sub.TenantID)
			subscriptionsList = append(subscriptionsList, ptr.ToString(sub.SubscriptionID))

			for _, subID := range subscriptionsList {
				if _, ok := results[tenantID][subID]; !ok {
					resourceGroupList := AzGetResourceGroups(subID, subscriptionsClient.Authorizer)
					if results[tenantID] == nil {
						results[tenantID] = make(map[string][]string)
					}
					results[tenantID][subID] = resourceGroupList
				}
			}
		}
	}
	return results
}

func AzGetResourceGroups(subscriptionID string, authorizer autorest.Authorizer) []string {
	groupsClient := resources.NewGroupsClient(subscriptionID)
	groupsClient.Authorizer = authorizer
	var resourceGroups []string

	for page, err := groupsClient.List(context.TODO(), "", nil); page.NotDone(); err = page.Next() {

		if err != nil {
			log.Fatalf("[-] Could not list resource groups for subscription %s. %s", subscriptionID, err)
		}

		for _, rg := range page.Values() {
			if rg.Name != nil {
				resourceGroups = append(resourceGroups, *(rg.Name))
			}
		}
	}
	return resourceGroups
}

/* Azure Public API Edpoints:
To request a token: az account get-access-token -o json --resource URL
ManagementPortalURL: "https://manage.windowsazure.com/"
PublishSettingsURL: "https://manage.windowsazure.com/publishsettings/index"
ServiceManagementEndpoint: "https://management.core.windows.net/"
ResourceManagerEndpoint: "https://management.azure.com/"
ActiveDirectoryEndpoint: "https://login.microsoftonline.com/"
GalleryEndpoint: "https://gallery.azure.com/"
KeyVaultEndpoint: "https://vault.azure.net/"
GraphEndpoint: "https://graph.windows.net/"
ServiceBusEndpoint: "https://servicebus.windows.net/"
BatchManagementEndpoint: "https://batch.core.windows.net/"
StorageEndpointSuffix: "core.windows.net"
CosmosDBDNSSuffix: "documents.azure.com"
MariaDBDNSSuffix: "mariadb.database.azure.com"
MySQLDatabaseDNSSuffix: "mysql.database.azure.com"
PostgresqlDatabaseDNSSuffix: "postgres.database.azure.com"
SQLDatabaseDNSSuffix: "database.windows.net"
TrafficManagerDNSSuffix: "trafficmanager.net"
KeyVaultDNSSuffix: "vault.azure.net"
ServiceBusEndpointSuffix: "servicebus.windows.net"
ServiceManagementVMDNSSuffix: "cloudapp.net"
ResourceManagerVMDNSSuffix: "cloudapp.azure.com"
ContainerRegistryDNSSuffix: "azurecr.io"
TokenAudience: "https://management.azure.com/"
APIManagementHostNameSuffix: "azure-api.net"
SynapseEndpointSuffix: "dev.azuresynapse.net"
ResourceIdentifiers: github.com/Azure/go-autorest/autorest/azure.ResourceIdentifier {Graph: "https://graph.windows.net/"
KeyVault: "https://vault.azure.net"
Datalake: "https://datalake.azure.net/"
Batch: "https://batch.core.windows.net/"
OperationalInsights: "https://api.loganalytics.io"
OSSRDBMS: "https://ossrdbms-aad.database.windows.net"
Storage: "https://storage.azure.com/"
Synapse: "https://dev.azuresynapse.net"
ServiceBus: "https://servicebus.azure.net/"
SQLDatabase: "https://database.windows.net/"
CosmosDB: "https://cosmos.azure.com" */
