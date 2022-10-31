package utils

import (
	"fmt"
	"log"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/compute/mgmt/compute"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/network/mgmt/network"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/resources"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/subscriptions"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/BishopFox/cloudfox/constants"
)

func getAuthorizer(endpoint string) (autorest.Authorizer, error) {
	auth, err := auth.NewAuthorizerFromCLIWithResource(endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to get authorizer: %s", err)
	}
	return auth, nil
}

func GetSubscriptionsClient() subscriptions.Client {
	client := subscriptions.NewClient()
	a, err := getAuthorizer(constants.AZ_RESOURCE_MANAGER_ENDPOINT)
	if err != nil {
		log.Fatalf("failed to get subscriptions client: %s", err)
	}
	client.Authorizer = a
	client.AddToUserAgent(constants.CLOUDFOX_USER_AGENT)
	return client
}

func GetResourceGroupsClient(subscriptionID string) resources.GroupsClient {
	client := resources.NewGroupsClient(subscriptionID)
	a, err := getAuthorizer(constants.AZ_RESOURCE_MANAGER_ENDPOINT)
	if err != nil {
		log.Fatalf("failed to get resource groups client: %s", err)
	}
	client.Authorizer = a
	client.AddToUserAgent(constants.CLOUDFOX_USER_AGENT)
	return client
}

func GetComputeClient(subscriptionID string) compute.VirtualMachinesClient {
	client := compute.NewVirtualMachinesClient(subscriptionID)
	authorizer, err := getAuthorizer(constants.AZ_RESOURCE_MANAGER_ENDPOINT)
	if err != nil {
		log.Fatalf("failed to get compute client: %s", err)
	}
	client.Authorizer = authorizer
	client.AddToUserAgent(constants.CLOUDFOX_USER_AGENT)
	return client
}

func GetNICClient(subscriptionID string) network.InterfacesClient {
	client := network.NewInterfacesClient(subscriptionID)
	authorizer, err := getAuthorizer(constants.AZ_RESOURCE_MANAGER_ENDPOINT)
	if err != nil {
		log.Fatalf("failed to get nic client: %s", err)
	}
	client.Authorizer = authorizer
	client.AddToUserAgent(constants.CLOUDFOX_USER_AGENT)
	return client
}

func GetPublicIPclient(subscriptionID string) network.PublicIPAddressesClient {
	client := network.NewPublicIPAddressesClient(subscriptionID)
	authorizer, err := getAuthorizer(constants.AZ_RESOURCE_MANAGER_ENDPOINT)
	if err != nil {
		log.Fatalf("failed to get public ip client: %s", err)
	}
	client.Authorizer = authorizer
	return client
}
