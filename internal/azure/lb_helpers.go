package azure

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
	"github.com/BishopFox/cloudfox/globals"
)

type FrontendIPInfo struct {
	PublicIP  string
	PrivateIP string
	DNSName   string
}

// -------------------- Load Balancers per Subscription --------------------
//func GetLoadBalancersPerSubscription(ctx context.Context, subscriptionID string, cred azcore.TokenCredential) ([]*armnetwork.LoadBalancer, error) {
//	lbClient, err := armnetwork.NewLoadBalancersClient(subscriptionID, cred, nil)
//	if err != nil {
//		return nil, fmt.Errorf("failed to create Load Balancer client: %v", err)
//	}
//
//	var lbs []*armnetwork.LoadBalancer
//	pager := lbClient.NewListAllPager(nil)
//	for pager.More() {
//		page, err := pager.NextPage(ctx)
//		if err != nil {
//			return nil, fmt.Errorf("failed to get load balancer page: %v", err)
//		}
//		lbs = append(lbs, page.Value...)
//	}
//
//	return lbs, nil
//}

// -------------------- Load Balancers per Resource Group --------------------
func GetLoadBalancersPerResourceGroup(ctx context.Context, session *SafeSession, subscriptionID, rgName string) ([]*armnetwork.LoadBalancer, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token for subscription %s: %v", subscriptionID, err)
	}

	cred := &StaticTokenCredential{Token: token}
	lbClient, err := armnetwork.NewLoadBalancersClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Load Balancer client: %v", err)
	}

	var lbs []*armnetwork.LoadBalancer
	pager := lbClient.NewListPager(rgName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get load balancer page for resource group %s: %v", rgName, err)
		}
		lbs = append(lbs, page.Value...)
	}

	return lbs, nil
}

// -------------------- Load Balancer Frontend IPs --------------------
func GetLoadBalancerFrontendIPs(ctx context.Context, session *SafeSession, lb *armnetwork.LoadBalancer) []FrontendIPInfo {
	var frontends []FrontendIPInfo

	if lb.Properties == nil || lb.Properties.FrontendIPConfigurations == nil {
		return frontends
	}

	for _, fe := range lb.Properties.FrontendIPConfigurations {
		var publicIP, privateIP, dnsName string

		//		token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
		//		if err != nil {
		//			return nil
		//		}

		//		cred := &StaticTokenCredential{Token: token}

		if fe.Properties != nil {
			if fe.Properties.PrivateIPAddress != nil {
				privateIP = *fe.Properties.PrivateIPAddress
			}

			if fe.Properties.PublicIPAddress != nil && fe.Properties.PublicIPAddress.ID != nil {
				ip, err := GetPublicIPByID(ctx, session, *fe.Properties.PublicIPAddress.ID)
				if err == nil && ip != "" {
					publicIP = ip
				} else {
					publicIP = *fe.Properties.PublicIPAddress.ID // fallback
				}
			}

			if fe.Properties.PublicIPAddress != nil && fe.Properties.PublicIPAddress.Properties != nil &&
				fe.Properties.PublicIPAddress.Properties.DNSSettings != nil &&
				fe.Properties.PublicIPAddress.Properties.DNSSettings.DomainNameLabel != nil {
				dnsName = *fe.Properties.PublicIPAddress.Properties.DNSSettings.DomainNameLabel
			}
		}

		frontends = append(frontends, FrontendIPInfo{
			PublicIP:  publicIP,
			PrivateIP: privateIP,
			DNSName:   dnsName,
		})
	}

	return frontends
}

// -------------------- Safe Helpers --------------------
func GetLoadBalancerName(lb *armnetwork.LoadBalancer) string {
	if lb.Name != nil {
		return *lb.Name
	}
	return "N/A"
}

func GetLoadBalancerLocation(lb *armnetwork.LoadBalancer) string {
	if lb.Location != nil {
		return *lb.Location
	}
	return "N/A"
}

func GetLoadBalancerResourceGroup(lb *armnetwork.LoadBalancer) string {
	if lb.ID != nil {
		return GetResourceGroupFromID(*lb.ID)
	}
	return "N/A"
}

// ListLoadBalancers returns all load balancers in a resource group
func ListLoadBalancers(ctx context.Context, session *SafeSession, subscriptionID, rgName string) ([]*armnetwork.LoadBalancer, error) {
	return GetLoadBalancersPerResourceGroup(ctx, session, subscriptionID, rgName)
}

// GetPublicIPAddressByID resolves a public IP address from its resource ID
func GetPublicIPAddressByID(ctx context.Context, session *SafeSession, subscriptionID, publicIPID string) string {
	ip, err := GetPublicIPByID(ctx, session, publicIPID)
	if err != nil {
		return ""
	}
	return ip
}
