package azure

import (
	"fmt"
	"log"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/authorization/mgmt/authorization"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/compute/mgmt/compute"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/network/mgmt/network"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/resources"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/subscriptions"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/storage/mgmt/storage"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appplatform/armappplatform"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/datafactory/armdatafactory"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/hdinsight/armhdinsight"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/kusto/armkusto"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/servicefabric/armservicefabric"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/signalr/armsignalr"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/streamanalytics/armstreamanalytics/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/services/graphrbac/1.6/graphrbac"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
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

func GetgraphRbacClient(tenantID string) graphrbac.DomainsClient {
	client := graphrbac.NewDomainsClient(tenantID)
	a, err := getAuthorizer(globals.AZ_GRAPH_ENDPOINT)
	if err != nil {
		log.Fatalf("failed to get azure active directory client: %s", err)
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

func GetNICClient(subscriptionID string) (*network.InterfacesClient, error) {
	client := network.NewInterfacesClient(subscriptionID)
	authorizer, err := auth.NewAuthorizerFromCLI()
	if err != nil {
		return nil, fmt.Errorf("failed to get authorizer: %v", err)
	}
	client.Authorizer = authorizer
	return &client, nil
}

func GetPublicIPClient(subscriptionID string) (*network.PublicIPAddressesClient, error) {
	client := network.NewPublicIPAddressesClient(subscriptionID)
	authorizer, err := auth.NewAuthorizerFromCLI()
	if err != nil {
		return nil, fmt.Errorf("failed to get authorizer: %v", err)
	}
	client.Authorizer = authorizer
	return &client, nil
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

func GetStorageAccountBlobClient(session *SafeSession, tenantID, storageAccountName string) (*azblob.Client, error) {
	serviceURL := fmt.Sprintf("https://%s.blob.core.windows.net/", storageAccountName)

	// Get token for storage scope
	token, err := session.GetTokenForResource(globals.CommonScopes[3]) // Storage scope
	if err != nil {
		return nil, fmt.Errorf("failed to get storage token: %v", err)
	}

	cred := &StaticTokenCredential{Token: token}

	client, err := azblob.NewClient(serviceURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create blob client: %v", err)
	}
	return client, nil
}

func GetARMresourcesClient(session *SafeSession, tenantID, subscriptionID string) (*armresources.Client, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token for subscription %s: %v", subscriptionID, err)
	}

	cred := &StaticTokenCredential{Token: token}

	client, err := armresources.NewClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM resources client: %v", err)
	}
	return client, nil
}

func GetWebAppsClient(session *SafeSession, subscriptionID string) *armappservice.WebAppsClient {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil
	}

	cred := &StaticTokenCredential{Token: token}

	logger := internal.NewLogger()
	client, err := armappservice.NewWebAppsClient(subscriptionID, cred, nil)
	if err != nil && globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		logger.ErrorM(fmt.Sprintf("Failed to create WebAppsClient for subscription %s: %v", subscriptionID, err), globals.AZ_WEBAPPS_MODULE_NAME)
	}
	return client
}

func GetSubnetsClient(session *SafeSession, subscriptionID string) (*armnetwork.SubnetsClient, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token for subscription %s: %v", subscriptionID, err)
	}

	cred := &StaticTokenCredential{Token: token}

	client, err := armnetwork.NewSubnetsClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// GetVMExtensionsClient returns a VMExtensionsClient for a subscription
func GetVMExtensionsClient(session *SafeSession, subscriptionID string) (*armcompute.VirtualMachineExtensionsClient, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token for subscription %s: %v", subscriptionID, err)
	}

	cred := &StaticTokenCredential{Token: token}

	client, err := armcompute.NewVirtualMachineExtensionsClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create VMExtensions client: %v", err)
	}

	return client, nil
}

// GetNSGClient returns a SecurityGroupsClient for a subscription
func GetNSGClient(session *SafeSession, subscriptionID string) (*armnetwork.SecurityGroupsClient, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token for subscription %s: %v", subscriptionID, err)
	}

	cred := &StaticTokenCredential{Token: token}

	client, err := armnetwork.NewSecurityGroupsClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create NSG client: %v", err)
	}

	return client, nil
}

// GetFirewallClient returns an AzureFirewallsClient for a subscription
func GetFirewallClient(session *SafeSession, subscriptionID string) (*armnetwork.AzureFirewallsClient, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token for subscription %s: %v", subscriptionID, err)
	}

	cred := &StaticTokenCredential{Token: token}

	client, err := armnetwork.NewAzureFirewallsClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Firewall client: %v", err)
	}

	return client, nil
}

// GetRouteTablesClient returns a RouteTablesClient for a subscription
func GetRouteTablesClient(session *SafeSession, subscriptionID string) (*armnetwork.RouteTablesClient, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token for subscription %s: %v", subscriptionID, err)
	}

	cred := &StaticTokenCredential{Token: token}

	client, err := armnetwork.NewRouteTablesClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create RouteTables client: %v", err)
	}

	return client, nil
}

// GetVirtualNetworksClient returns a VirtualNetworksClient for a subscription
func GetVirtualNetworksClient(session *SafeSession, subscriptionID string) (*armnetwork.VirtualNetworksClient, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token for subscription %s: %v", subscriptionID, err)
	}

	cred := &StaticTokenCredential{Token: token}

	client, err := armnetwork.NewVirtualNetworksClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create VirtualNetworks client: %v", err)
	}

	return client, nil
}

// GetKustoClient returns a Kusto ClustersClient for a subscription
func GetKustoClient(session *SafeSession, subscriptionID string) (*armkusto.ClustersClient, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token for subscription %s: %v", subscriptionID, err)
	}

	cred := &StaticTokenCredential{Token: token}

	client, err := armkusto.NewClustersClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kusto Clusters client: %v", err)
	}

	return client, nil
}

// GetKustoDatabasesClient returns a Kusto DatabasesClient for a subscription
func GetKustoDatabasesClient(session *SafeSession, subscriptionID string) (*armkusto.DatabasesClient, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token for subscription %s: %v", subscriptionID, err)
	}

	cred := &StaticTokenCredential{Token: token}

	client, err := armkusto.NewDatabasesClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kusto Databases client: %v", err)
	}

	return client, nil
}

// GetDataFactoryClient returns a Data Factory FactoriesClient for a subscription
func GetDataFactoryClient(session *SafeSession, subscriptionID string) (*armdatafactory.FactoriesClient, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token for subscription %s: %v", subscriptionID, err)
	}

	cred := &StaticTokenCredential{Token: token}

	client, err := armdatafactory.NewFactoriesClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Data Factory client: %v", err)
	}

	return client, nil
}

// GetDataFactoryPipelinesClient returns a Data Factory PipelinesClient for a subscription
func GetDataFactoryPipelinesClient(session *SafeSession, subscriptionID string) (*armdatafactory.PipelinesClient, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token for subscription %s: %v", subscriptionID, err)
	}

	cred := &StaticTokenCredential{Token: token}

	client, err := armdatafactory.NewPipelinesClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Pipelines client: %v", err)
	}

	return client, nil
}

// GetDataFactoryLinkedServicesClient returns a Data Factory LinkedServicesClient for a subscription
func GetDataFactoryLinkedServicesClient(session *SafeSession, subscriptionID string) (*armdatafactory.LinkedServicesClient, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token for subscription %s: %v", subscriptionID, err)
	}

	cred := &StaticTokenCredential{Token: token}

	client, err := armdatafactory.NewLinkedServicesClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create LinkedServices client: %v", err)
	}

	return client, nil
}

// GetDataFactoryDatasetsClient returns a Data Factory DatasetsClient for a subscription
func GetDataFactoryDatasetsClient(session *SafeSession, subscriptionID string) (*armdatafactory.DatasetsClient, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token for subscription %s: %v", subscriptionID, err)
	}

	cred := &StaticTokenCredential{Token: token}

	client, err := armdatafactory.NewDatasetsClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Datasets client: %v", err)
	}

	return client, nil
}

// GetDataFactoryTriggersClient returns a Data Factory TriggersClient for a subscription
func GetDataFactoryTriggersClient(session *SafeSession, subscriptionID string) (*armdatafactory.TriggersClient, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token for subscription %s: %v", subscriptionID, err)
	}

	cred := &StaticTokenCredential{Token: token}

	client, err := armdatafactory.NewTriggersClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Triggers client: %v", err)
	}

	return client, nil
}

// GetDataFactoryIntegrationRuntimesClient returns a Data Factory IntegrationRuntimesClient for a subscription
func GetDataFactoryIntegrationRuntimesClient(session *SafeSession, subscriptionID string) (*armdatafactory.IntegrationRuntimesClient, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token for subscription %s: %v", subscriptionID, err)
	}

	cred := &StaticTokenCredential{Token: token}

	client, err := armdatafactory.NewIntegrationRuntimesClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create IntegrationRuntimes client: %v", err)
	}

	return client, nil
}

// GetStreamAnalyticsClient returns a Stream Analytics StreamingJobsClient for a subscription
func GetStreamAnalyticsClient(session *SafeSession, subscriptionID string) (*armstreamanalytics.StreamingJobsClient, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token for subscription %s: %v", subscriptionID, err)
	}

	cred := &StaticTokenCredential{Token: token}

	client, err := armstreamanalytics.NewStreamingJobsClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Stream Analytics client: %v", err)
	}

	return client, nil
}

// GetStreamAnalyticsInputsClient returns a Stream Analytics InputsClient for a subscription
func GetStreamAnalyticsInputsClient(session *SafeSession, subscriptionID string) (*armstreamanalytics.InputsClient, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token for subscription %s: %v", subscriptionID, err)
	}

	cred := &StaticTokenCredential{Token: token}

	client, err := armstreamanalytics.NewInputsClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Stream Analytics Inputs client: %v", err)
	}

	return client, nil
}

// GetStreamAnalyticsOutputsClient returns a Stream Analytics OutputsClient for a subscription
func GetStreamAnalyticsOutputsClient(session *SafeSession, subscriptionID string) (*armstreamanalytics.OutputsClient, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token for subscription %s: %v", subscriptionID, err)
	}

	cred := &StaticTokenCredential{Token: token}

	client, err := armstreamanalytics.NewOutputsClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Stream Analytics Outputs client: %v", err)
	}

	return client, nil
}

// GetHDInsightClient returns an HDInsight ClustersClient for a subscription
func GetHDInsightClient(session *SafeSession, subscriptionID string) (*armhdinsight.ClustersClient, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token for subscription %s: %v", subscriptionID, err)
	}

	cred := &StaticTokenCredential{Token: token}

	client, err := armhdinsight.NewClustersClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HDInsight client: %v", err)
	}

	return client, nil
}

// GetSpringAppsClient returns a Spring Apps ServicesClient for a subscription
func GetSpringAppsClient(session *SafeSession, subscriptionID string) (*armappplatform.ServicesClient, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token for subscription %s: %v", subscriptionID, err)
	}

	cred := &StaticTokenCredential{Token: token}

	client, err := armappplatform.NewServicesClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Spring Apps client: %v", err)
	}

	return client, nil
}

// GetSpringAppsAppsClient returns a Spring Apps AppsClient for a subscription
func GetSpringAppsAppsClient(session *SafeSession, subscriptionID string) (*armappplatform.AppsClient, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token for subscription %s: %v", subscriptionID, err)
	}

	cred := &StaticTokenCredential{Token: token}

	client, err := armappplatform.NewAppsClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Spring Apps Apps client: %v", err)
	}

	return client, nil
}

// GetSignalRClient returns a SignalR Client for a subscription
func GetSignalRClient(session *SafeSession, subscriptionID string) (*armsignalr.Client, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token for subscription %s: %v", subscriptionID, err)
	}

	cred := &StaticTokenCredential{Token: token}

	client, err := armsignalr.NewClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create SignalR client: %v", err)
	}

	return client, nil
}

// GetServiceFabricClient returns a Service Fabric Clusters Client for a subscription
func GetServiceFabricClient(session *SafeSession, subscriptionID string) (*armservicefabric.ClustersClient, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token for subscription %s: %v", subscriptionID, err)
	}

	cred := &StaticTokenCredential{Token: token}

	client, err := armservicefabric.NewClustersClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Service Fabric client: %v", err)
	}

	return client, nil
}

// GetGraphServiceClient returns a Microsoft Graph SDK client for accessing Graph API
// This is used for accessing Azure AD Identity Protection and other Graph endpoints
func GetGraphServiceClient(session *SafeSession) (*msgraphsdk.GraphServiceClient, error) {
	// Get token for Microsoft Graph scope
	token, err := session.GetTokenForResource(globals.CommonScopes[1]) // Microsoft Graph scope
	if err != nil {
		return nil, fmt.Errorf("failed to get Microsoft Graph token: %v", err)
	}

	// Create a custom authentication provider that uses our static token
	cred := NewStaticTokenCredential(token)

	// Create Graph client using the credential
	// Note: This is a simplified approach - for production use, consider implementing
	// a full Graph authentication adapter
	client, err := msgraphsdk.NewGraphServiceClientWithCredentials(cred, []string{globals.CommonScopes[1]})
	if err != nil {
		return nil, fmt.Errorf("failed to create Graph client: %v", err)
	}

	return client, nil
}
