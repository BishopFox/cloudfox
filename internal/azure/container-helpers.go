package azure

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appcontainers/armappcontainers/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerinstance/armcontainerinstance"
	"github.com/BishopFox/cloudfox/globals"
)

// -------------------- Types --------------------

// ContainerInstance represents an Azure Container Instance (ACI)
type ContainerInstance struct {
	ID                       *string
	Name                     *string
	PublicIPAddress          *string
	PrivateIPAddress         *string
	FQDN                     *string
	Ports                    *string // Comma-separated list of ports
	UserAssignedIdentities   []ManagedIdentity
	SystemAssignedIdentities []ManagedIdentity
	Image                    *string
	OsType                   *string
}

// ContainerAppJob represents an Azure Container Apps Job
type ContainerAppJob struct {
	ID                       *string
	Name                     *string
	Environment              *string // Container App Environment
	PublicIP                 *string
	PrivateIP                *string
	UserAssignedIdentities   []ManagedIdentity
	SystemAssignedIdentities []ManagedIdentity
}

// -------------------- Helpers --------------------

// ListContainerInstances returns all ACIs in the subscription + resource group
func ListContainerInstances(session *SafeSession, subscriptionID, resourceGroup string) []ContainerInstance {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil
	}

	cred := &StaticTokenCredential{Token: token}

	client, err := armcontainerinstance.NewContainerGroupsClient(subscriptionID, cred, nil)
	if err != nil {
		return nil
	}

	pager := client.NewListByResourceGroupPager(resourceGroup, nil)
	var results []ContainerInstance
	ctx := context.Background()

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			continue
		}
		for _, cg := range page.Value {
			var publicIP string
			var fqdn string
			var ports []string

			if cg.Properties != nil && cg.Properties.IPAddress != nil {
				if cg.Properties.IPAddress.IP != nil {
					publicIP = *cg.Properties.IPAddress.IP
				}

				// Extract FQDN
				if cg.Properties.IPAddress.Fqdn != nil {
					fqdn = *cg.Properties.IPAddress.Fqdn
				}

				// Extract ports
				if cg.Properties.IPAddress.Ports != nil {
					for _, port := range cg.Properties.IPAddress.Ports {
						if port.Port != nil {
							protocol := "TCP"
							if port.Protocol != nil {
								protocol = string(*port.Protocol)
							}
							ports = append(ports, fmt.Sprintf("%d/%s", *port.Port, protocol))
						}
					}
				}
			}

			privateIP := "" // no PrivateIP in current SDK

			portsStr := ""
			if len(ports) > 0 {
				portsStr = strings.Join(ports, ", ")
			}

			var userAssigned []ManagedIdentity
			if cg.Identity != nil && cg.Identity.UserAssignedIdentities != nil {
				for id, identity := range cg.Identity.UserAssignedIdentities {
					principalID := ""
					if identity != nil && identity.PrincipalID != nil {
						principalID = *identity.PrincipalID
					}
					userAssigned = append(userAssigned, ManagedIdentity{
						Name:        id,
						Type:        "UserAssigned",
						PrincipalID: principalID,
					})
				}
			}

			var systemAssigned []ManagedIdentity
			if cg.Identity != nil && cg.Identity.PrincipalID != nil {
				systemAssigned = append(systemAssigned, ManagedIdentity{
					Name:        *cg.Identity.PrincipalID,
					Type:        "SystemAssigned",
					PrincipalID: *cg.Identity.PrincipalID,
				})
			}

			results = append(results, ContainerInstance{
				ID:                       cg.ID,
				Name:                     cg.Name,
				PublicIPAddress:          &publicIP,
				PrivateIPAddress:         &privateIP,
				FQDN:                     &fqdn,
				Ports:                    &portsStr,
				UserAssignedIdentities:   userAssigned,
				SystemAssignedIdentities: systemAssigned,
			})
		}
	}

	return results
}

// ListContainerAppsJobs returns all container apps jobs in the subscription + resource group
func ListContainerAppsJobs(session *SafeSession, subscriptionID, rgName string) []ContainerAppJob {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil
	}

	cred := &StaticTokenCredential{Token: token}

	client, err := armappcontainers.NewJobsClient(subscriptionID, cred, nil)
	if err != nil {
		return nil
	}

	pager := client.NewListByResourceGroupPager(rgName, nil)
	var results []ContainerAppJob
	ctx := context.Background()

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			continue
		}
		for _, job := range page.Value {
			publicIP := ""
			privateIP := ""
			userAssigned := []ManagedIdentity{}
			systemAssigned := []ManagedIdentity{}

			if job.Identity != nil {
				// User-assigned identities
				if job.Identity.UserAssignedIdentities != nil {
					for id := range job.Identity.UserAssignedIdentities {
						roles, _ := GetRoleAssignmentsForPrincipal(ctx, session, id, subscriptionID) // fetch roles if needed
						userAssigned = append(userAssigned, ManagedIdentity{
							Name:  id,
							Roles: roles,
						})
					}
				}

				// System-assigned identity
				if job.Identity.PrincipalID != nil {
					roles, _ := GetRoleAssignmentsForPrincipal(ctx, session, *job.Identity.PrincipalID, subscriptionID)
					systemAssigned = append(systemAssigned, ManagedIdentity{
						Name:  *job.Identity.PrincipalID,
						Roles: roles,
					})
				}
			}

			env := ""
			if job.Properties != nil && job.Properties.EnvironmentID != nil {
				env = *job.Properties.EnvironmentID
			}

			results = append(results, ContainerAppJob{
				ID:                       job.ID,
				Name:                     job.Name,
				Environment:              &env,
				PublicIP:                 &publicIP,
				PrivateIP:                &privateIP,
				UserAssignedIdentities:   userAssigned,
				SystemAssignedIdentities: systemAssigned,
			})
		}
	}

	return results
}

// GetTemplatesForResource fetches deployment templates/YAML for a resource
func GetTemplatesForResource(resourceID string) string {
	// Stub: return empty string; implement fetching via Azure REST API or ARM templates if needed
	return ""
}
