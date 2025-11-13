package azure

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement"
	"github.com/BishopFox/cloudfox/globals"
)

// -------------------- API Management Services --------------------

// ListAPIManagementServices returns all APIM services in a resource group
func ListAPIManagementServices(ctx context.Context, session *SafeSession, subscriptionID, rgName string) ([]*armapimanagement.ServiceResource, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token for subscription %s: %v", subscriptionID, err)
	}

	cred := &StaticTokenCredential{Token: token}
	client, err := armapimanagement.NewServiceClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create APIM service client: %v", err)
	}

	var services []*armapimanagement.ServiceResource
	pager := client.NewListByResourceGroupPager(rgName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get APIM services page for resource group %s: %v", rgName, err)
		}
		services = append(services, page.Value...)
	}

	return services, nil
}

// -------------------- APIs within a service --------------------

// ListAPIsInService returns all APIs in an APIM service
func ListAPIsInService(ctx context.Context, session *SafeSession, subscriptionID, rgName, serviceName string) ([]*armapimanagement.APIContract, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token: %v", err)
	}

	cred := &StaticTokenCredential{Token: token}
	client, err := armapimanagement.NewAPIClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create APIM API client: %v", err)
	}

	var apis []*armapimanagement.APIContract
	pager := client.NewListByServicePager(rgName, serviceName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			// If we can't list APIs, return empty list (permissions issue or service not ready)
			return apis, nil
		}
		apis = append(apis, page.Value...)
	}

	return apis, nil
}

// -------------------- Identity Providers --------------------

// GetAPIManagementIdentityProviders returns configured identity providers (AAD, etc.)
func GetAPIManagementIdentityProviders(ctx context.Context, session *SafeSession, subscriptionID, rgName, serviceName string) []string {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil
	}

	cred := &StaticTokenCredential{Token: token}
	client, err := armapimanagement.NewIdentityProviderClient(subscriptionID, cred, nil)
	if err != nil {
		return nil
	}

	var providers []string
	pager := client.NewListByServicePager(rgName, serviceName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return providers
		}
		for _, provider := range page.Value {
			if provider.Name != nil {
				providerName := string(*provider.Name)
				// Common providers: aad, aadB2C, facebook, google, microsoft, twitter
				if providerName == "aad" {
					providers = append(providers, "Azure AD (EntraID)")
				} else if providerName == "aadB2C" {
					providers = append(providers, "Azure AD B2C")
				} else {
					providers = append(providers, providerName)
				}
			}
		}
	}

	return providers
}

// -------------------- API Policies --------------------

// GetAPIPolicyXML returns the policy XML for a specific API
func GetAPIPolicyXML(ctx context.Context, session *SafeSession, subscriptionID, rgName, serviceName, apiID string) (string, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return "", err
	}

	cred := &StaticTokenCredential{Token: token}
	client, err := armapimanagement.NewAPIPolicyClient(subscriptionID, cred, nil)
	if err != nil {
		return "", err
	}

	// Get the policy
	policyID := armapimanagement.PolicyIDNamePolicy
	resp, err := client.Get(ctx, rgName, serviceName, apiID, policyID, nil)
	if err != nil {
		return "", err
	}

	if resp.Properties != nil && resp.Properties.Value != nil {
		return *resp.Properties.Value, nil
	}

	return "", nil
}

// -------------------- Safe Helpers --------------------

func GetAPIMServiceName(service *armapimanagement.ServiceResource) string {
	if service.Name != nil {
		return *service.Name
	}
	return "N/A"
}

func GetAPIMServiceLocation(service *armapimanagement.ServiceResource) string {
	if service.Location != nil {
		return *service.Location
	}
	return "N/A"
}

func GetAPIName(api *armapimanagement.APIContract) string {
	if api.Name != nil {
		return *api.Name
	}
	return "N/A"
}

func GetAPIDisplayName(api *armapimanagement.APIContract) string {
	if api.Properties != nil && api.Properties.DisplayName != nil {
		return *api.Properties.DisplayName
	}
	return GetAPIName(api)
}

func GetAPIPath(api *armapimanagement.APIContract) string {
	if api.Properties != nil && api.Properties.Path != nil {
		return *api.Properties.Path
	}
	return "N/A"
}

func GetAPIServiceURL(api *armapimanagement.APIContract) string {
	if api.Properties != nil && api.Properties.ServiceURL != nil {
		return *api.Properties.ServiceURL
	}
	return "N/A"
}
