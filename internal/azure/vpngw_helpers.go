package azure

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
	"github.com/BishopFox/cloudfox/globals"
)

// Struct to hold VPN GW frontend info
type VPNGatewayIPInfo struct {
	PublicIP  string
	PrivateIP string
	DNSName   string
}

// GetVPNGatewaysPerResourceGroup enumerates all VPN Gateways in a given resource group
func GetVPNGatewaysPerResourceGroup(
	ctx context.Context,
	session *SafeSession,
	subscriptionID string,
	resourceGroupName string,
) ([]*armnetwork.VirtualNetworkGateway, error) {

	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token for subscription %s: %v", subscriptionID, err)
	}

	cred := &StaticTokenCredential{Token: token}

	client, err := armnetwork.NewVirtualNetworkGatewaysClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(resourceGroupName, nil)
	var results []*armnetwork.VirtualNetworkGateway

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		results = append(results, page.Value...)
	}

	return results, nil
}

func GetVPNGatewayName(gw *armnetwork.VirtualNetworkGateway) string {
	if gw.Name != nil {
		return *gw.Name
	}
	return "N/A"
}

func GetVPNGatewayLocation(gw *armnetwork.VirtualNetworkGateway) string {
	if gw.Location != nil {
		return *gw.Location
	}
	return "N/A"
}

func GetVPNGatewayResourceGroup(gw *armnetwork.VirtualNetworkGateway) string {
	if gw.ID == nil {
		return "N/A"
	}
	parts := strings.Split(*gw.ID, "/")
	for i := 0; i < len(parts); i++ {
		if strings.EqualFold(parts[i], "resourceGroups") && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return "N/A"
}

// GetVPNGatewayIPs returns public/private IPs and DNS for each frontend
func GetVPNGatewayIPs(ctx context.Context, session *SafeSession, subscriptionID string, gw *armnetwork.VirtualNetworkGateway) []VPNGatewayIPInfo {
	var infos []VPNGatewayIPInfo
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil
	}

	cred := &StaticTokenCredential{Token: token}

	if gw.Properties == nil || gw.Properties.IPConfigurations == nil {
		return infos
	}

	publicIPClient, err := armnetwork.NewPublicIPAddressesClient(subscriptionID, cred, nil)
	if err != nil {
		return infos
	}

	for _, ipconf := range gw.Properties.IPConfigurations {
		if ipconf == nil || ipconf.Properties == nil {
			continue
		}

		info := VPNGatewayIPInfo{}

		// Private IP
		if ipconf.Properties.PrivateIPAddress != nil {
			info.PrivateIP = *ipconf.Properties.PrivateIPAddress
		}

		// Public IP (resolve via resource ID)
		if ipconf.Properties.PublicIPAddress != nil && ipconf.Properties.PublicIPAddress.ID != nil {
			pubID := *ipconf.Properties.PublicIPAddress.ID
			parts := strings.Split(pubID, "/")
			var rgName, pipName string
			for i := 0; i < len(parts); i++ {
				if strings.EqualFold(parts[i], "resourceGroups") && i+1 < len(parts) {
					rgName = parts[i+1]
				}
				if strings.EqualFold(parts[i], "publicIPAddresses") && i+1 < len(parts) {
					pipName = parts[i+1]
				}
			}

			if rgName != "" && pipName != "" {
				pip, err := publicIPClient.Get(ctx, rgName, pipName, nil)
				if err == nil && pip.Properties != nil {
					if pip.Properties.IPAddress != nil {
						info.PublicIP = *pip.Properties.IPAddress
					}
					if pip.Properties.DNSSettings != nil && pip.Properties.DNSSettings.Fqdn != nil {
						info.DNSName = *pip.Properties.DNSSettings.Fqdn
					}
				}
			}
		}

		infos = append(infos, info)
	}

	return infos
}
