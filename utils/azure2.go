package utils

import (
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/resources"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/subscriptions"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure/auth"
)

const RESOURCE_MANAGER_ENDPOINT = "https://management.azure.com/"
const GRAPH_ENDPOINT = "https://graph.windows.net/"
const USER_AGENT = "CloudFox"

func GetSubscriptionsClient() (subscriptions.Client, error) {
	subsClient := subscriptions.NewClient()
	a, err := getAuthorizer(RESOURCE_MANAGER_ENDPOINT)
	if err != nil {
		return subsClient, err
	}
	subsClient.Authorizer = a
	subsClient.AddToUserAgent(USER_AGENT)
	return subsClient, nil
}

func GetResourceGroupsClient(subscriptionID string) (resources.GroupsClient, error) {
	groupsClient := resources.NewGroupsClient(subscriptionID)
	a, err := getAuthorizer(RESOURCE_MANAGER_ENDPOINT)
	if err != nil {
		return groupsClient, err
	}
	groupsClient.Authorizer = a
	groupsClient.AddToUserAgent(USER_AGENT)
	return groupsClient, nil
}

func getAuthorizer(endpoint string) (autorest.Authorizer, error) {
	auth, err := auth.NewAuthorizerFromCLIWithResource(endpoint)
	if err != nil {
		return nil, err
	}
	return auth, nil
}
