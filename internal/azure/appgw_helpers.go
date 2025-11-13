package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
)

// -------------------- App Gateway Frontend Info --------------------
type AppGatewayFrontendInfo struct {
	PublicIP  string
	PrivateIP string
	DNSName   string
}

type RewriteRuleSet struct {
	Name                        string `json:"name"`
	RequestHeaderConfigurations []struct {
		HeaderName  string `json:"headerName"`
		HeaderValue string `json:"headerValue"`
	} `json:"requestHeaderConfigurations"`
}

// -------------------- Enumerate App Gateways per Subscription --------------------
//func GetAppGatewaysPerSubscription(subscriptionID string) []*armnetwork.ApplicationGateway {
//	cred := GetCredential()
//	logger := internal.NewLogger()
//
//	client, err := armnetwork.NewApplicationGatewaysClient(subscriptionID, cred, nil)
//	if err != nil {
//		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
//			logger.ErrorM(fmt.Sprintf("Failed to create ApplicationGateways client: %v\n", err), globals.AZ_APPGATEWAY_MODULE_NAME)
//		}
//		return nil
//	}
//
//	var appGateways []*armnetwork.ApplicationGateway
//	pager := client.NewListAllPager(nil)
//
//	ctx := context.Background()
//	for pager.More() {
//		page, err := pager.NextPage(ctx)
//		if err != nil {
//			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
//				logger.ErrorM(fmt.Sprintf("Failed to enumerate ApplicationGateways: %v\n", err), globals.AZ_APPGATEWAY_MODULE_NAME)
//			}
//			break
//		}
//		appGateways = append(appGateways, page.Value...)
//	}
//
//	return appGateways
//}

// -------------------- Enumerate App Gateways per Resource Group --------------------
func GetAppGatewaysPerResourceGroup(session *SafeSession, subscriptionID, rgName string) []*armnetwork.ApplicationGateway {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil
	}

	cred := &StaticTokenCredential{Token: token}

	logger := internal.NewLogger()

	client, err := armnetwork.NewApplicationGatewaysClient(subscriptionID, cred, nil)
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to create ApplicationGateways client: %v\n", err), globals.AZ_APPGATEWAY_MODULE_NAME)
		}
		return nil
	}

	var appGateways []*armnetwork.ApplicationGateway
	pager := client.NewListPager(rgName, nil)

	ctx := context.Background()
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Failed to enumerate ApplicationGateways in resource group %s: %v\n", rgName, err), globals.AZ_APPGATEWAY_MODULE_NAME)
			}
			break
		}
		appGateways = append(appGateways, page.Value...)
	}

	return appGateways
}

// -------------------- Get App Gateway Name --------------------
func GetAppGatewayName(agw *armnetwork.ApplicationGateway) string {
	if agw.Name != nil {
		return *agw.Name
	}
	return ""
}

// -------------------- Get App Gateway Location --------------------
func GetAppGatewayLocation(agw *armnetwork.ApplicationGateway) string {
	if agw.Location != nil {
		return *agw.Location
	}
	return ""
}

// -------------------- Get App Gateway Resource Group --------------------
func GetAppGatewayResourceGroup(agw *armnetwork.ApplicationGateway) string {
	if agw.ID == nil {
		return ""
	}
	parts := strings.Split(*agw.ID, "/")
	for i, part := range parts {
		if strings.EqualFold(part, "resourceGroups") && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

// -------------------- Get App Gateway Frontend IPs --------------------
func GetAppGatewayFrontendIPs(session *SafeSession, subscriptionID string, agw *armnetwork.ApplicationGateway) []AppGatewayFrontendInfo {
	logger := internal.NewLogger()
	var frontends []AppGatewayFrontendInfo
	if agw == nil || agw.Properties == nil || agw.Properties.FrontendIPConfigurations == nil {
		return frontends
	}

	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil
	}

	cred := &StaticTokenCredential{Token: token}

	publicIPClient, err := armnetwork.NewPublicIPAddressesClient(subscriptionID, cred, nil)
	if err != nil {
		if err != nil && globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to create PublicIPAddresses client: %v\n", err), globals.AZ_APPGATEWAY_MODULE_NAME)
		}
		return frontends
	}
	ctx := context.Background()

	var dnsName string
	for _, fe := range agw.Properties.FrontendIPConfigurations {
		var publicIP, privateIP string

		if fe.Properties != nil {
			// Private IP
			if fe.Properties.PrivateIPAddress != nil {
				privateIP = *fe.Properties.PrivateIPAddress
			}

			// Public IP (resolve resource ID → actual IP + DNS)
			if fe.Properties.PublicIPAddress != nil && fe.Properties.PublicIPAddress.ID != nil {
				pubResID := *fe.Properties.PublicIPAddress.ID
				parts := strings.Split(pubResID, "/")
				var rgName, pipName string
				for i, part := range parts {
					if strings.EqualFold(part, "resourceGroups") && i+1 < len(parts) {
						rgName = parts[i+1]
					}
					if strings.EqualFold(part, "publicIPAddresses") && i+1 < len(parts) {
						pipName = parts[i+1]
					}
				}
				if rgName != "" && pipName != "" {
					pip, err := publicIPClient.Get(ctx, rgName, pipName, nil)
					if err == nil && pip.Properties != nil {
						if pip.Properties.IPAddress != nil {
							publicIP = *pip.Properties.IPAddress
						}
						if pip.Properties.DNSSettings != nil && pip.Properties.DNSSettings.Fqdn != nil {
							dnsName = *pip.Properties.DNSSettings.Fqdn
						}
					}
				}
			}
		}

		frontends = append(frontends, AppGatewayFrontendInfo{
			PublicIP:  publicIP,
			PrivateIP: privateIP,
			DNSName:   dnsName,
		})
	}

	return frontends
}

func GetRewriteRuleSetByID(session *SafeSession, subscriptionID string, rewriteRuleSetID string) (*RewriteRuleSet, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token for subscription %s: %v", subscriptionID, err)
	}

	cred := &StaticTokenCredential{Token: token}

	if cred == nil {
		return nil, fmt.Errorf("failed to get Azure credential")
	}

	resClient, err := armresources.NewClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create resources client: %v", err)
	}

	ctx := context.Background()
	apiVersion := "2022-05-01" // Latest supported API version for rewrite rule sets
	resp, err := resClient.GetByID(ctx, rewriteRuleSetID, apiVersion, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get rewrite rule set by ID: %v", err)
	}

	if resp.Properties == nil {
		return nil, fmt.Errorf("no properties found for rewrite rule set")
	}

	propBytes, err := json.Marshal(resp.Properties)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal properties: %v", err)
	}

	var rrSet RewriteRuleSet
	if err := json.Unmarshal(propBytes, &rrSet); err != nil {
		return nil, fmt.Errorf("failed to unmarshal rewrite rule set properties: %v", err)
	}

	return &rrSet, nil
}
