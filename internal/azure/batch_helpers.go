package azure

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/batch/armbatch"
	"github.com/BishopFox/cloudfox/globals"
)

// ==================== BATCH STRUCTURES ====================

type BatchAccount struct {
	Name                string
	ID                  string
	Location            string
	ResourceGroup       string
	ProvisioningState   string
	PoolQuota           int32
	AccountEndpoint     string
	PublicNetworkAccess string
	SystemAssignedID    string
	UserAssignedIDs     string
}

type BatchPool struct {
	Name                    string
	ID                      string
	VMSize                  string
	CurrentDedicatedNodes   int32
	CurrentLowPriorityNodes int32
	TargetDedicatedNodes    int32
	TargetLowPriorityNodes  int32
	AllocationState         string
	ProvisioningState       string
}

type BatchApplication struct {
	Name         string
	ID           string
	DisplayName  string
	AllowUpdates bool
}

// ==================== BATCH HELPERS ====================

// GetBatchAccounts retrieves all Batch accounts in a subscription
func GetBatchAccounts(session *SafeSession, subscriptionID string, resourceGroups []string) ([]BatchAccount, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil, err
	}
	cred := &StaticTokenCredential{Token: token}
	ctx := context.Background()

	client, err := armbatch.NewAccountClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}

	var results []BatchAccount

	// If specific resource groups provided, enumerate those
	if len(resourceGroups) > 0 {
		for _, rgName := range resourceGroups {
			pager := client.NewListByResourceGroupPager(rgName, nil)
			for pager.More() {
				page, err := pager.NextPage(ctx)
				if err != nil {
					continue
				}
				for _, acct := range page.Value {
					results = append(results, convertBatchAccount(ctx, session, acct, rgName, subscriptionID))
				}
			}
		}
	} else {
		// Otherwise, enumerate all Batch accounts in subscription
		pager := client.NewListPager(nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return results, err
			}
			for _, acct := range page.Value {
				rgName := GetResourceGroupFromID(SafeStringPtr(acct.ID))
				results = append(results, convertBatchAccount(ctx, session, acct, rgName, subscriptionID))
			}
		}
	}

	return results, nil
}

// GetBatchPools retrieves pools for a Batch account
func GetBatchPools(session *SafeSession, subscriptionID, resourceGroup, accountName string) ([]BatchPool, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil, err
	}
	cred := &StaticTokenCredential{Token: token}
	ctx := context.Background()

	client, err := armbatch.NewPoolClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}

	var results []BatchPool

	pager := client.NewListByBatchAccountPager(resourceGroup, accountName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return results, err
		}

		for _, pool := range page.Value {
			if pool == nil {
				continue
			}

			p := BatchPool{
				Name: SafeStringPtr(pool.Name),
				ID:   SafeStringPtr(pool.ID),
			}

			if pool.Properties != nil {
				if pool.Properties.VMSize != nil {
					p.VMSize = *pool.Properties.VMSize
				}
				if pool.Properties.CurrentDedicatedNodes != nil {
					p.CurrentDedicatedNodes = *pool.Properties.CurrentDedicatedNodes
				}
				if pool.Properties.CurrentLowPriorityNodes != nil {
					p.CurrentLowPriorityNodes = *pool.Properties.CurrentLowPriorityNodes
				}
				if pool.Properties.ScaleSettings != nil && pool.Properties.ScaleSettings.FixedScale != nil {
					if pool.Properties.ScaleSettings.FixedScale.TargetDedicatedNodes != nil {
						p.TargetDedicatedNodes = *pool.Properties.ScaleSettings.FixedScale.TargetDedicatedNodes
					}
					if pool.Properties.ScaleSettings.FixedScale.TargetLowPriorityNodes != nil {
						p.TargetLowPriorityNodes = *pool.Properties.ScaleSettings.FixedScale.TargetLowPriorityNodes
					}
				}
				if pool.Properties.AllocationState != nil {
					p.AllocationState = string(*pool.Properties.AllocationState)
				}
				if pool.Properties.ProvisioningState != nil {
					p.ProvisioningState = string(*pool.Properties.ProvisioningState)
				}
			}

			results = append(results, p)
		}
	}

	return results, nil
}

// GetBatchApplications retrieves applications for a Batch account
func GetBatchApplications(session *SafeSession, subscriptionID, resourceGroup, accountName string) ([]BatchApplication, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil, err
	}
	cred := &StaticTokenCredential{Token: token}
	ctx := context.Background()

	client, err := armbatch.NewApplicationClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}

	var results []BatchApplication

	pager := client.NewListPager(resourceGroup, accountName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return results, err
		}

		for _, app := range page.Value {
			if app == nil {
				continue
			}

			a := BatchApplication{
				Name: SafeStringPtr(app.Name),
				ID:   SafeStringPtr(app.ID),
			}

			if app.Properties != nil {
				a.DisplayName = SafeStringPtr(app.Properties.DisplayName)
				if app.Properties.AllowUpdates != nil {
					a.AllowUpdates = *app.Properties.AllowUpdates
				}
			}

			results = append(results, a)
		}
	}

	return results, nil
}

// convertBatchAccount converts SDK Batch account to our struct
func convertBatchAccount(ctx context.Context, session *SafeSession, acct *armbatch.Account, resourceGroup, subscriptionID string) BatchAccount {
	result := BatchAccount{
		Name:             SafeStringPtr(acct.Name),
		ID:               SafeStringPtr(acct.ID),
		Location:         SafeStringPtr(acct.Location),
		ResourceGroup:    resourceGroup,
		SystemAssignedID: "N/A",
		UserAssignedIDs:  "N/A",
	}

	if acct.Properties != nil {
		if acct.Properties.ProvisioningState != nil {
			result.ProvisioningState = string(*acct.Properties.ProvisioningState)
		}
		if acct.Properties.PoolQuota != nil {
			result.PoolQuota = *acct.Properties.PoolQuota
		}
		result.AccountEndpoint = SafeStringPtr(acct.Properties.AccountEndpoint)
		if acct.Properties.PublicNetworkAccess != nil {
			result.PublicNetworkAccess = string(*acct.Properties.PublicNetworkAccess)
		}
	}

	// Extract managed identity information
	if acct.Identity != nil {
		// System-assigned identity
		if acct.Identity.PrincipalID != nil {
			principalID := *acct.Identity.PrincipalID
			result.SystemAssignedID = principalID
		}

		// User-assigned identities
		if acct.Identity.UserAssignedIdentities != nil {
			var userIDs []string

			for uaID := range acct.Identity.UserAssignedIdentities {
				userIDs = append(userIDs, uaID)
			}

			if len(userIDs) > 0 {
				result.UserAssignedIDs = ""
				for i, id := range userIDs {
					if i > 0 {
						result.UserAssignedIDs += ", "
					}
					result.UserAssignedIDs += id
				}
			}
		}
	}

	return result
}
