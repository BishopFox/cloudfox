package azure

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice"
	"github.com/BishopFox/cloudfox/globals"
)

// -------------------- AKS Clusters per Subscription --------------------
//func GetAKSClustersPerSubscription(ctx context.Context, subscriptionID string, cred azcore.TokenCredential) ([]*armcontainerservice.ManagedCluster, error) {
//	aksClient, err := armcontainerservice.NewManagedClustersClient(subscriptionID, cred, nil)
//	if err != nil {
//		return nil, fmt.Errorf("failed to create AKS client: %v", err)
//	}
//
//	var clusters []*armcontainerservice.ManagedCluster
//	pager := aksClient.NewListPager(nil)
//	for pager.More() {
//		page, err := pager.NextPage(ctx)
//		if err != nil {
//			return nil, fmt.Errorf("failed to get AKS clusters page: %v", err)
//		}
//		clusters = append(clusters, page.Value...)
//	}
//
//	return clusters, nil
//}

func GetAKSClustersPerResourceGroup(ctx context.Context, session *SafeSession, subscriptionID, rgName string) ([]*armcontainerservice.ManagedCluster, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token for subscription %s: %v", subscriptionID, err)
	}

	cred := &StaticTokenCredential{Token: token}

	aksClient, err := armcontainerservice.NewManagedClustersClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create AKS client: %v", err)
	}

	var clusters []*armcontainerservice.ManagedCluster
	pager := aksClient.NewListByResourceGroupPager(rgName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get AKS clusters page: %v", err)
		}
		clusters = append(clusters, page.Value...)
	}

	return clusters, nil
}

// -------------------- AKS Cluster Public/Private Info --------------------
func GetAKSClusterFQDNs(cluster *armcontainerservice.ManagedCluster) (publicFQDN, privateFQDN string) {
	publicFQDN = "N/A"
	privateFQDN = "N/A"

	if cluster.Properties != nil {
		if cluster.Properties.Fqdn != nil {
			publicFQDN = *cluster.Properties.Fqdn
		}
		if cluster.Properties.PrivateFQDN != nil && *cluster.Properties.PrivateFQDN != "" {
			privateFQDN = *cluster.Properties.PrivateFQDN
		}
	}

	return
}

// -------------------- AKS Cluster Roles --------------------
func GetAKSClusterRoles(ctx context.Context, session *SafeSession, cluster *armcontainerservice.ManagedCluster, subscriptionID string) (systemRoles []string, userRoles []string) {
	systemRoles = []string{}
	userRoles = []string{}

	if cluster.Identity != nil {
		// System-assigned
		if cluster.Identity.PrincipalID != nil {
			roles, err := GetRoleAssignmentsForPrincipal(ctx, session, *cluster.Identity.PrincipalID, subscriptionID)
			if err != nil {
				systemRoles = append(systemRoles, fmt.Sprintf("Error: %v", err))
			} else if len(roles) > 0 {
				systemRoles = append(systemRoles, roles...)
			}
		}

		// User-assigned
		if cluster.Identity.UserAssignedIdentities != nil {
			for _, uai := range cluster.Identity.UserAssignedIdentities {
				if uai.PrincipalID != nil {
					roles, err := GetRoleAssignmentsForPrincipal(ctx, session, *uai.PrincipalID, subscriptionID)
					if err != nil {
						userRoles = append(userRoles, fmt.Sprintf("Error: %v", err))
					} else if len(roles) > 0 {
						userRoles = append(userRoles, roles...)
					}
				}
			}
		}
	}

	if len(systemRoles) == 0 {
		systemRoles = []string{"N/A"}
	}
	if len(userRoles) == 0 {
		userRoles = []string{"N/A"}
	}

	return
}

// -------------------- Safe Helpers --------------------
func GetAKSClusterName(cluster *armcontainerservice.ManagedCluster) string {
	if cluster.Name != nil {
		return *cluster.Name
	}
	return "N/A"
}

func GetAKSClusterLocation(cluster *armcontainerservice.ManagedCluster) string {
	if cluster.Location != nil {
		return *cluster.Location
	}
	return "N/A"
}

func GetAKSKubernetesVersion(cluster *armcontainerservice.ManagedCluster) string {
	if cluster.Properties != nil && cluster.Properties.KubernetesVersion != nil {
		return *cluster.Properties.KubernetesVersion
	}
	return "N/A"
}
