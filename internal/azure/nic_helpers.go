package azure

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
	"github.com/BishopFox/cloudfox/globals"
)

// GetPublicIPsPerRG lists all Public IPs in a resource group
func GetPublicIPsPerRG(ctx context.Context, session *SafeSession, subscriptionID, rgName string) ([]*armnetwork.PublicIPAddress, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token for subscription %s: %v", subscriptionID, err)
	}

	cred := &StaticTokenCredential{Token: token}

	client, err := armnetwork.NewPublicIPAddressesClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create PublicIP client: %v", err)
	}

	var ips []*armnetwork.PublicIPAddress
	pager := client.NewListPager(rgName, nil) // <-- change here
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list public IPs in RG %s: %v", rgName, err)
		}
		ips = append(ips, page.Value...)
	}
	return ips, nil
}

// GetPublicIPsPerSubscription lists all Public IPs in a subscription
//func GetPublicIPsPerSubscription(ctx context.Context, subscriptionID string, cred azcore.TokenCredential) ([]*armnetwork.PublicIPAddress, error) {
//	client, err := armnetwork.NewPublicIPAddressesClient(subscriptionID, cred, nil)
//	if err != nil {
//		return nil, fmt.Errorf("failed to create PublicIP client: %v", err)
//	}
//
//	var ips []*armnetwork.PublicIPAddress
//	pager := client.NewListAllPager(nil) // Also valid in v1.1.0
//	for pager.More() {
//		page, err := pager.NextPage(ctx)
//		if err != nil {
//			return nil, fmt.Errorf("failed to list public IPs in subscription %s: %v", subscriptionID, err)
//		}
//		ips = append(ips, page.Value...)
//	}
//	return ips, nil
//}

// Safe getters for PublicIPAddress properties

// GetPublicIPName safely retrieves the name of a PublicIPAddress.
func GetPublicIPName(pip *armnetwork.PublicIPAddress) string {
	if pip.Name != nil {
		return *pip.Name
	}
	return "N/A"
}

// GetPublicIPLocation safely retrieves the location of a PublicIPAddress.
func GetPublicIPLocation(pip *armnetwork.PublicIPAddress) string {
	if pip.Location != nil {
		return *pip.Location
	}
	return "N/A"
}

// GetPublicIPResourceGroup safely retrieves the resource group of a PublicIPAddress.
func GetPublicIPResourceGroup(pip *armnetwork.PublicIPAddress) string {
	if pip.ID != nil {
		return GetResourceGroupFromID(*pip.ID)
	}
	return "N/A"
}

// GetPublicIPAddress safely retrieves the IP address of a PublicIPAddress.
func GetPublicIPAddress(pip *armnetwork.PublicIPAddress) string {
	if pip.Properties != nil && pip.Properties.IPAddress != nil {
		return *pip.Properties.IPAddress
	}
	return "N/A"
}

// GetPublicIPDNS safely retrieves the DNS name of a PublicIPAddress.
func GetPublicIPDNS(pip *armnetwork.PublicIPAddress) string {
	if pip.Properties != nil && pip.Properties.DNSSettings != nil && pip.Properties.DNSSettings.Fqdn != nil {
		return *pip.Properties.DNSSettings.Fqdn
	}
	return "N/A"
}

// ListNetworkInterfaces lists all NICs in a given subscription (optionally filtered by resource group)
func ListNetworkInterfaces(ctx context.Context, session *SafeSession, subscriptionID, rgName string) ([]*armnetwork.Interface, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token for subscription %s: %v", subscriptionID, err)
	}

	cred := &StaticTokenCredential{Token: token}

	client, err := armnetwork.NewInterfacesClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create NIC client: %v", err)
	}

	var nics []*armnetwork.Interface

	if rgName != "" {
		pager := client.NewListPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list NICs in RG %s: %v", rgName, err)
			}
			nics = append(nics, page.Value...)
		}
	} else {
		pager := client.NewListAllPager(nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list all NICs: %v", err)
			}
			nics = append(nics, page.Value...)
		}
	}

	return nics, nil
}

func GetPublicIPByID(ctx context.Context, session *SafeSession, publicIPID string) (string, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return "", err
	}

	cred := &StaticTokenCredential{Token: token}

	parts := strings.Split(publicIPID, "/")
	if len(parts) < 9 {
		return "", fmt.Errorf("invalid public IP resource ID: %s", publicIPID)
	}
	subscriptionID := parts[2]
	resourceGroup := parts[4]
	publicIPName := parts[8]

	client, err := armnetwork.NewPublicIPAddressesClient(subscriptionID, cred, nil)
	if err != nil {
		return "", err
	}

	resp, err := client.Get(ctx, resourceGroup, publicIPName, nil)
	if err != nil {
		return "", err
	}

	if resp.Properties != nil && resp.Properties.IPAddress != nil {
		return *resp.Properties.IPAddress, nil
	}
	return "", nil
}

// GetNameFromID extracts the last segment (resource name) from a full ARM ID
func GetNameFromID(resourceID string) string {
	parts := strings.Split(resourceID, "/")
	if len(parts) == 0 {
		return "N/A"
	}
	return parts[len(parts)-1]
}

// GetVNetAndSubnetFromID extracts the virtual network and subnet names from a subnet ID
func GetVNetAndSubnetFromID(subnetID string) (string, string) {
	vnetName := "N/A"
	subnetName := "N/A"

	parts := strings.Split(subnetID, "/")
	for i := 0; i < len(parts)-1; i++ {
		if strings.EqualFold(parts[i], "virtualNetworks") && i+1 < len(parts) {
			vnetName = parts[i+1]
		}
		if strings.EqualFold(parts[i], "subnets") && i+1 < len(parts) {
			subnetName = parts[i+1]
		}
	}
	return vnetName, subnetName
}
