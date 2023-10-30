package internal

import (
	"fmt"
	"log"
	"context"

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
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/kyokomi/emoji"
	"github.com/spf13/cobra"
)
// func NewAzureClient(AzVerbosity int, AzWrapTable, AzMergedTable bool, AzTenantRefs, AzSubscriptionRefs, AzRGRefs, AzResourceRefs []string, cmd *cobra.Command) *AzureClient {

type AzureClient struct {
	AzVerbosity        int
	AzWrapTable        bool
	AzMergedTable      bool

	Version            string
	AzOutputFormat     string
	AzOutputDirectory  string

	AzTenants          []*subscriptions.TenantIDDescription
	AzSubscriptions    []*subscriptions.Subscription
	AzRGs              []*resources.Group
	AzResources        []*azure.Resource
}

func (a *AzureClient) init (AzTenantRefs, AzSubscriptionRefs, AzRGRefs, AzResourceRefs []string, cmd *cobra.Command){
	availableSubscriptions := GetSubscriptions()
	availableTenants := GetTenants()
	// resource identifiers were submitted on the CLI, running modules on them only
	if len(AzResourceRefs) > 0 {
		fmt.Printf("[%s] Azure resource identifiers submitted, skipping submitted tenants and subscriptions\n", cyan(emoji.Sprintf(":fox:cloudfox v%s :fox:", cmd.Root().Version)))
		// remove any other resource scope filter
		a.AzTenants = nil
		a.AzSubscriptions = nil
		a.AzRGs = nil

		var (
			err            error
			resource       azure.Resource
		)
		// check if the submitted resource can be reached with existing credentials
		// this does not guarantees that the resource will be found since only the prefix of the resource ID
		// is checked against the available ones
		for _, azResourceRef := range AzResourceRefs {
			resource, err = azure.ParseResourceID(azResourceRef)
			if err != nil {
				fmt.Printf("[%s] Invalid resource identifier : %s\n", cyan(emoji.Sprintf(":fox:cloudfox v%s :fox:", cmd.Root().Version)), azResourceRef)
				continue
			}
			for _, subscription := range availableSubscriptions {
				if resource.SubscriptionID == *subscription.SubscriptionID {
					// add the resource to the final list of targets
					a.AzResources = append(a.AzResources, &resource)
					// also add the associated subscription since you cannot query a resource alone
					a.AzSubscriptions = append(a.AzSubscriptions, &subscription)
					goto FOUND_RESOURCE
				}
			}
			fmt.Printf("[%s] No active credentials valid for resource %s, removing from target list\n", cyan(emoji.Sprintf(":fox:cloudfox v%s :fox:", cmd.Root().Version)), azResourceRef)
			FOUND_RESOURCE:
		}
	} else if len(AzRGRefs) > 0 {
	// resource groups were submitted on the CLI, running modules on them only
		fmt.Printf("[%s] Azure subscriptions submitted, skipping submitted tenants\n", cyan(emoji.Sprintf(":fox:cloudfox v%s :fox:", cmd.Root().Version)))

		a.AzTenants = nil
		a.AzSubscriptions = nil

		for _, AzRGRef := range AzRGRefs {
			for _, subscription := range availableSubscriptions {
				for _, rg := range GetResourceGroups(*subscription.SubscriptionID) {
					if *rg.ID == AzRGRef {
						a.AzRGs = append(a.AzRGs, &rg)
						a.AzSubscriptions = append(a.AzSubscriptions, &subscription)
						goto FOUND_RG
					} else if *rg.Name == AzRGRef {
						a.AzRGs = append(a.AzRGs, &rg)
						a.AzSubscriptions = append(a.AzSubscriptions, &subscription)
						goto FOUND_RG
					}
				}
			}
			fmt.Printf("[%s] Resource Group %s not accessible with active CLI credentials, removing from targetst\n", cyan(emoji.Sprintf(":fox:cloudfox v%s :fox:", cmd.Root().Version)), AzRGRef)
			FOUND_RG:
		}
	} else if len(AzSubscriptionRefs) > 0 {
	// subscriptions were submitted on the CLI, running modules on them only
		fmt.Printf("[%s] Azure subscriptions submitted, skipping submitted tenants\n", cyan(emoji.Sprintf(":fox:cloudfox v%s :fox:", cmd.Root().Version)))
		// remove any other resource scope filter
		a.AzTenants = nil
		for _, AzSubscriptionRef := range AzSubscriptionRefs {
			for _, subscription := range availableSubscriptions {
				if *subscription.SubscriptionID == AzSubscriptionRef {
					a.AzSubscriptions = append(a.AzSubscriptions, &subscription)
					goto FOUND_SUB
				} else if *subscription.DisplayName == AzSubscriptionRef {
					a.AzSubscriptions = append(a.AzSubscriptions, &subscription)
					goto FOUND_SUB
				}
			}
			fmt.Printf("[%s] Subscription %s not accessible with active CLI credentials, removing from targetst\n", cyan(emoji.Sprintf(":fox:cloudfox v%s :fox:", cmd.Root().Version)), AzSubscriptionRef)
			FOUND_SUB:
		}
	} else if len(AzTenantRefs) > 0 {
	// tenants were submitted on the CLI, running modules on them only
		for _, AzTenantRef := range AzTenantRefs {
			for _, tenant := range availableTenants {
				if *tenant.ID == AzTenantRef {
					a.AzTenants = append(a.AzTenants, &tenant)
					goto FOUND_TENANT
				} else if *tenant.DefaultDomain == AzTenantRef {
					a.AzTenants = append(a.AzTenants, &tenant)
					goto FOUND_TENANT
				}
			}
			fmt.Printf("[%s] Tenant %s not accessible with active CLI credentials, removing from targetst\n", cyan(emoji.Sprintf(":fox:cloudfox v%s :fox:", cmd.Root().Version)), AzTenantRef)
			FOUND_TENANT:
		}
	}
}

func NewAzureClient(AzVerbosity int, AzWrapTable, AzMergedTable bool, AzTenantRefs, AzSubscriptionRefs, AzRGRefs, AzResourceRefs []string, cmd *cobra.Command, AzOutputFormat, AzOutputDirectory string) *AzureClient {
   client := new(AzureClient)
   client.Version = cmd.Root().Version
   client.AzWrapTable = AzWrapTable
   client.AzMergedTable = AzMergedTable
   client.AzVerbosity = AzVerbosity
   client.AzOutputFormat = AzOutputFormat
   client.AzOutputDirectory = AzOutputDirectory
   client.init(AzTenantRefs, AzSubscriptionRefs, AzRGRefs, AzResourceRefs, cmd)
   return client
}


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

func GetNSGClient(subscriptionID string) network.SecurityGroupsClient {
	client := network.NewSecurityGroupsClient(subscriptionID)
	authorizer, err := getAuthorizer(globals.AZ_RESOURCE_MANAGER_ENDPOINT)
	if err != nil {
		log.Fatalf("failed to get nsg client: %s", err)
	}
	client.Authorizer = authorizer
	client.AddToUserAgent(globals.CLOUDFOX_USER_AGENT)
	return client
}

func GetSubnetsClient(subscriptionID string) network.SubnetsClient {
	client := network.NewSubnetsClient(subscriptionID)
	authorizer, err := getAuthorizer(globals.AZ_RESOURCE_MANAGER_ENDPOINT)
	if err != nil {
		log.Fatalf("failed to get subnets client: %s", err)
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

func GetIPAddressesFromInterface(iface *network.Interface) []string{
	var ipAddresses []string
	for _, ipConfiguration := range *iface.InterfacePropertiesFormat.IPConfigurations {
		if ipConfiguration.InterfaceIPConfigurationPropertiesFormat.PrivateIPAddress != nil {
			ipAddresses = append(ipAddresses, *ipConfiguration.InterfaceIPConfigurationPropertiesFormat.PrivateIPAddress)
		}
		if ipConfiguration.InterfaceIPConfigurationPropertiesFormat.PublicIPAddress != nil {
			if ipConfiguration.InterfaceIPConfigurationPropertiesFormat.PublicIPAddress.PublicIPAddressPropertiesFormat != nil {
				if ipConfiguration.InterfaceIPConfigurationPropertiesFormat.PublicIPAddress.PublicIPAddressPropertiesFormat.IPAddress != nil {
					ipAddresses = append(ipAddresses, *ipConfiguration.InterfaceIPConfigurationPropertiesFormat.PublicIPAddress.PublicIPAddressPropertiesFormat.IPAddress)
				}
			}
		}
	}
	return ipAddresses
}

func GetSubscriptions() []subscriptions.Subscription {
	var results []subscriptions.Subscription
	subsClient := GetSubscriptionsClient()
	for page, err := subsClient.List(context.TODO()); page.NotDone(); err = page.Next() {
		if err != nil {
			log.Fatal("could not get subscriptions for active session")
		}
		results = append(results, page.Values()...)
	}
	return results
}

func GetTenants() []subscriptions.TenantIDDescription {
	tenantsClient := GetTenantsClient()
	var results []subscriptions.TenantIDDescription
	for page, err := tenantsClient.List(context.TODO()); page.NotDone(); err = page.Next() {
		if err != nil {
			log.Fatal("could not get tenants for active session")
		}
		results = append(results, page.Values()...)
	}
	return results
}

func GetResourceGroups(subscriptionID string) []resources.Group {
	var results []resources.Group
	rgClient := GetResourceGroupsClient(subscriptionID)

	for page, err := rgClient.List(context.TODO(), "", nil); page.NotDone(); err = page.Next() {
		if err != nil {
			log.Fatalf("error reading resource groups for subscription %s", subscriptionID)
		}
		results = append(results, page.Values()...)
	}
	return results
}
