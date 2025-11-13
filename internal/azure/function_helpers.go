package azure

import (
	"context"
	"fmt"
	"strings"

	web "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice"
)

func GetFunctionAppsPerResourceGroup(session *SafeSession, subscriptionID, resourceGroup string) ([]*web.Site, error) {
	client := GetWebAppsClient(session, subscriptionID)
	var apps []*web.Site
	pager := client.NewListByResourceGroupPager(resourceGroup, nil)
	for pager.More() {
		page, err := pager.NextPage(context.Background())
		if err != nil {
			return nil, fmt.Errorf("could not enumerate function apps in RG %s: %v", resourceGroup, err)
		}
		for _, app := range page.Value {
			if app.Kind != nil && strings.Contains(*app.Kind, "functionapp") {
				apps = append(apps, app)
			}
		}
	}
	return apps, nil
}

func GetFunctionAppNetworkInfo(subscriptionID, resourceGroup string, app *web.Site) (privateIPs, publicIPs []string, vnetName, subnetName string) {
	privateIPs = []string{"N/A"}
	publicIPs = []string{"N/A"}
	vnetName = "N/A"
	subnetName = "N/A"

	if app.Properties == nil {
		return
	}

	if app.Properties.VirtualNetworkSubnetID != nil {
		subnetID := *app.Properties.VirtualNetworkSubnetID
		parts := strings.Split(subnetID, "/")
		for i := 0; i < len(parts); i++ {
			if strings.EqualFold(parts[i], "virtualNetworks") && i+1 < len(parts) {
				vnetName = parts[i+1]
			}
			if strings.EqualFold(parts[i], "subnets") && i+1 < len(parts) {
				subnetName = parts[i+1]
			}
		}
		// Optionally fetch private IPs from subnet if needed
	}

	if app.Properties.OutboundIPAddresses != nil && *app.Properties.OutboundIPAddresses != "" {
		publicIPs = strings.Split(*app.Properties.OutboundIPAddresses, ",")
	} else if app.Properties.PossibleOutboundIPAddresses != nil && *app.Properties.PossibleOutboundIPAddresses != "" {
		publicIPs = strings.Split(*app.Properties.PossibleOutboundIPAddresses, ",")
	}

	return
}

// -------------------- Managed Identity Roles ----------------
func GetFunctionAppMIRoles(ctx context.Context, session *SafeSession, app *web.Site, subscriptionID string) (systemRoles string, userRoles string) {
	var sysRolesList, userRolesList []string

	if app.Identity != nil {
		// -------- System Assigned --------
		if app.Identity.Type != nil && (*app.Identity.Type == web.ManagedServiceIdentityTypeSystemAssigned || *app.Identity.Type == web.ManagedServiceIdentityTypeSystemAssignedUserAssigned || *app.Identity.Type == web.ManagedServiceIdentityTypeNone) {
			if app.Identity.PrincipalID != nil {
				roles, err := GetRoleAssignmentsForPrincipal(ctx, session, *app.Identity.PrincipalID, subscriptionID)
				if err != nil {
					sysRolesList = append(sysRolesList, fmt.Sprintf("Error: %v", err))
				} else if len(roles) > 0 {
					sysRolesList = append(sysRolesList, strings.Join(roles, ", "))
				}
			}
		}

		// -------- User Assigned --------
		if app.Identity.UserAssignedIdentities != nil {
			for _, uai := range app.Identity.UserAssignedIdentities {
				if uai.PrincipalID != nil {
					roles, err := GetRoleAssignmentsForPrincipal(ctx, session, *uai.PrincipalID, subscriptionID)
					if err != nil {
						userRolesList = append(userRolesList, fmt.Sprintf("Error: %v", err))
					} else if len(roles) > 0 {
						userRolesList = append(userRolesList, strings.Join(roles, ", "))
					}
				}
			}
		}
	}

	if len(sysRolesList) > 0 {
		systemRoles = strings.Join(sysRolesList, " | ")
	} else {
		systemRoles = "N/A"
	}

	if len(userRolesList) > 0 {
		userRoles = strings.Join(userRolesList, " | ")
	} else {
		userRoles = "N/A"
	}

	return
}
