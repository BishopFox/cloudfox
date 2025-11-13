package azure

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/netapp/armnetapp"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
)

// FileSystem represents a generic filesystem (Azure Files or NetApp Files)
type FileSystem struct {
	Name        string
	Location    string
	DnsName     string
	IP          string
	MountTarget string
	AuthPolicy  string
}

// -------------------- Azure Files --------------------

// ListAzureFileShares enumerates all Azure File Shares in a resource group
func ListAzureFileShares(ctx context.Context, session *SafeSession, subscriptionID, rgName string) []FileSystem {
	var results []FileSystem
	logger := internal.NewLogger()
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil
	}

	cred := &StaticTokenCredential{Token: token}

	storageClient, err := armstorage.NewAccountsClient(subscriptionID, cred, nil)
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to create storage accounts client: %v", err), globals.AZ_FILESYSTEMS_MODULE)
		}
		return results
	}

	pager := storageClient.NewListByResourceGroupPager(rgName, nil)
	for pager.More() {
		// Timeout per page fetch
		pageCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		page, err := pager.NextPage(pageCtx)
		cancel()
		if err != nil {
			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Failed to fetch storage accounts page: %v", err), globals.AZ_FILESYSTEMS_MODULE)
			}
			break
		}
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.InfoM(fmt.Sprintf("Fetched %d storage accounts for resource group %s", len(page.Value), rgName), globals.AZ_FILESYSTEMS_MODULE)
		}
		// Reuse FileShares client
		fileClient, err := armstorage.NewFileSharesClient(subscriptionID, cred, nil)
		if err != nil {
			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Failed to create FileShares client: %v", err), globals.AZ_FILESYSTEMS_MODULE)
			}
			continue
		}

		for _, sa := range page.Value {
			accountName := SafeStringPtr(sa.Name)
			location := SafeStringPtr(sa.Location)

			fsPager := fileClient.NewListPager(rgName, accountName, nil)
			for fsPager.More() {
				fsCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
				fsPage, err := fsPager.NextPage(fsCtx)
				cancel()
				if err != nil {
					if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
						logger.ErrorM(fmt.Sprintf("Failed to fetch FileShares for account %s: %v", accountName, err), globals.AZ_FILESYSTEMS_MODULE)
					}
					break
				}
				if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
					logger.InfoM(fmt.Sprintf("Fetched %d FileShares for account %s", len(fsPage.Value), accountName), globals.AZ_FILESYSTEMS_MODULE)
				}
				for _, fs := range fsPage.Value {
					fsName := SafeStringPtr(fs.Name)
					if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
						logger.InfoM(fmt.Sprintf("Enumerating filesystem %s", fsName), globals.AZ_FILESYSTEMS_MODULE)
					}
					dnsName := fmt.Sprintf("%s.file.core.windows.net", accountName)
					results = append(results, FileSystem{
						Name:        fsName,
						Location:    location,
						DnsName:     dnsName,
						IP:          "N/A",
						MountTarget: fmt.Sprintf("//%s/%s", dnsName, fsName),
						AuthPolicy:  "Storage Account Key / SAS",
					})
				}
			}
		}
	}
	return results
}

// -------------------- Azure NetApp Files --------------------

// ListNetAppFiles enumerates all NetApp Files volumes in a resource group
func ListNetAppFiles(ctx context.Context, session *SafeSession, subscriptionID, rgName string) ([]*armnetapp.Volume, error) {
	var volumes []*armnetapp.Volume
	logger := internal.NewLogger()
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token for subscription %s: %v", subscriptionID, err)
	}

	cred := &StaticTokenCredential{Token: token}

	accountsClient, err := armnetapp.NewAccountsClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create NetApp Accounts client: %v", err)
	}
	poolsClient, err := armnetapp.NewPoolsClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create NetApp Pools client: %v", err)
	}
	volumesClient, err := armnetapp.NewVolumesClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create NetApp Volumes client: %v", err)
	}

	accPager := accountsClient.NewListBySubscriptionPager(nil)
	for accPager.More() {
		pageCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		accPage, err := accPager.NextPage(pageCtx)
		cancel()
		if err != nil {
			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Failed to fetch NetApp accounts page: %v", err), globals.AZ_FILESYSTEMS_MODULE)
			}
			break
		}
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.InfoM(fmt.Sprintf("Fetched %d NetApp accounts", len(accPage.Value)), globals.AZ_FILESYSTEMS_MODULE)
		}
		for _, acc := range accPage.Value {
			if acc.ID == nil || acc.Name == nil {
				continue
			}
			accountRG := GetResourceGroupFromID(*acc.ID)
			if rgName != "" && rgName != accountRG {
				continue
			}
			accountName := *acc.Name
			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				logger.InfoM(fmt.Sprintf("Enumerating NetApp account %s", accountName), globals.AZ_FILESYSTEMS_MODULE)
			}

			poolPager := poolsClient.NewListPager(accountRG, accountName, nil)
			for poolPager.More() {
				poolCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
				poolPage, err := poolPager.NextPage(poolCtx)
				cancel()
				if err != nil {
					if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
						logger.ErrorM(fmt.Sprintf("Failed to fetch pools for account %s: %v", accountName, err), globals.AZ_FILESYSTEMS_MODULE)
					}
					break
				}
				if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
					logger.InfoM(fmt.Sprintf("Fetched %d pools in account %s", len(poolPage.Value), accountName), globals.AZ_FILESYSTEMS_MODULE)
				}
				for _, pool := range poolPage.Value {
					if pool.ID == nil || pool.Name == nil {
						continue
					}
					poolName := *pool.Name

					volPager := volumesClient.NewListPager(accountRG, accountName, poolName, nil)
					for volPager.More() {
						volCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
						volPage, err := volPager.NextPage(volCtx)
						cancel()
						if err != nil {
							if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
								logger.ErrorM(fmt.Sprintf("Failed to fetch volumes in pool %s: %v", poolName, err), globals.AZ_FILESYSTEMS_MODULE)
							}
							break
						}
						if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
							logger.InfoM(fmt.Sprintf("Fetched %d volumes in pool %s", len(volPage.Value), poolName), globals.AZ_FILESYSTEMS_MODULE)
						}
						volumes = append(volumes, volPage.Value...)
					}
				}
			}
		}
	}

	return volumes, nil
}

// Safe getters for NetApp Volume properties

func GetNetAppVolumeRG(vol *armnetapp.Volume) string {
	if vol.ID != nil {
		return GetResourceGroupFromID(*vol.ID)
	}
	return "N/A"
}

func GetNetAppVolumeProtocol(vol *armnetapp.Volume) string {
	if vol.Properties != nil && vol.Properties.UsageThreshold != nil {
		// You can also extract protocol type from vol.Properties.ServiceLevel or ProtocolType if needed
		return string(*vol.Properties.CreationToken)
	}
	return "N/A"
}

// GetNetAppVolumeName returns a human-readable name for a NetApp volume.
func GetNetAppVolumeName(vol *armnetapp.Volume) string {
	if vol == nil {
		return "N/A"
	}
	if vol.Name != nil {
		return *vol.Name
	}
	// fallback to resource name parsed from ID
	if vol.ID != nil {
		return GetResourceGroupFromID(*vol.ID)
	}
	return "N/A"
}

// GetNetAppVolumeLocation returns the Location string.
func GetNetAppVolumeLocation(vol *armnetapp.Volume) string {
	if vol == nil {
		return "N/A"
	}
	if vol.Location != nil {
		return *vol.Location
	}
	return "N/A"
}

// GetNetAppVolumeDNS tries to return a DNS name for a mount target (best-effort).
func GetNetAppVolumeDNS(vol *armnetapp.Volume) string {
	if vol == nil || vol.Properties == nil || vol.Properties.MountTargets == nil || len(vol.Properties.MountTargets) == 0 {
		return "N/A"
	}
	mt := vol.Properties.MountTargets[0]

	// Check for SMB FQDN first
	if mt.SmbServerFqdn != nil {
		return *mt.SmbServerFqdn
	}

	// Fallback to IP if available
	if mt.IPAddress != nil {
		return *mt.IPAddress
	}

	return "N/A"
}

// GetNetAppVolumeIP returns the IP address of the first mount target (best-effort).
func GetNetAppVolumeIP(vol *armnetapp.Volume) string {
	if vol == nil || vol.Properties == nil || vol.Properties.MountTargets == nil || len(vol.Properties.MountTargets) == 0 {
		return "N/A"
	}
	mt := vol.Properties.MountTargets[0]
	if mt.IPAddress != nil {
		return *mt.IPAddress
	}
	return "N/A"
}

// GetNetAppVolumeMountTarget prefers DNS, then IP, then subnetID if available.
func GetNetAppVolumeMountTarget(vol *armnetapp.Volume) string {
	if vol == nil {
		return "N/A"
	}
	// prefer DnsName
	if mt := GetNetAppVolumeDNS(vol); mt != "N/A" {
		return mt
	}
	// then ip
	if ip := GetNetAppVolumeIP(vol); ip != "N/A" {
		return ip
	}
	// fallback to subnet ID or provisioned path (best-effort)
	if vol.Properties != nil && vol.Properties.SubnetID != nil {
		return *vol.Properties.SubnetID
	}
	return "N/A"
}

// GetNetAppVolumeAuthPolicy returns a best-effort representation of protocol types or other policy info.
func GetNetAppVolumeAuthPolicy(vol *armnetapp.Volume) string {
	if vol == nil || vol.Properties == nil {
		return "N/A"
	}
	// ProtocolTypes can be a slice; we return a human-friendly string via fmt.Sprint
	if vol.Properties.ProtocolTypes != nil {
		return fmt.Sprint(vol.Properties.ProtocolTypes)
	}
	// fallback to service level or creation token for context
	if vol.Properties.ServiceLevel != nil {
		return fmt.Sprintf("serviceLevel=%s", *vol.Properties.ServiceLevel)
	}
	if vol.Properties.CreationToken != nil {
		return fmt.Sprintf("creationToken=%s", *vol.Properties.CreationToken)
	}
	return "N/A"
}
