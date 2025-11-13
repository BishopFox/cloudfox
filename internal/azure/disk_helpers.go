package azure

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/BishopFox/cloudfox/globals"
)

// DiskInfo represents an Azure Managed Disk
type DiskInfo struct {
	SubscriptionID   string
	SubscriptionName string
	ResourceGroup    string
	Region           string
	Name             string
	DiskSizeGB       string
	OSType           string
	DiskState        string
	ManagedBy        string // Resource that uses this disk (VM, VMSS, etc.)
	EncryptionType   string
	EncryptionStatus string
}

// GetDisksForSubscription enumerates all managed disks in a subscription
func GetDisksForSubscription(ctx context.Context, session *SafeSession, subscriptionID string) ([]DiskInfo, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %v", err)
	}

	cred := &StaticTokenCredential{Token: token}

	// Get subscription name
	subName := GetSubscriptionNameFromID(ctx, session, subscriptionID)

	// Create disks client
	disksClient, err := armcompute.NewDisksClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create disks client: %w", err)
	}

	var disks []DiskInfo

	// List all disks in subscription
	pager := disksClient.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return disks, err // Return partial results
		}

		for _, disk := range page.Value {
			if disk == nil || disk.Name == nil {
				continue
			}

			info := DiskInfo{
				SubscriptionID:   subscriptionID,
				SubscriptionName: subName,
				Name:             SafeStringPtr(disk.Name),
				Region:           SafeStringPtr(disk.Location),
				ResourceGroup:    "N/A",
				DiskSizeGB:       "N/A",
				OSType:           "N/A",
				DiskState:        "N/A",
				ManagedBy:        "Unattached",
				EncryptionType:   "N/A",
				EncryptionStatus: "Unknown",
			}

			// Extract resource group from ID
			if disk.ID != nil {
				info.ResourceGroup = GetResourceGroupFromID(*disk.ID)
			}

			// Get disk properties
			if disk.Properties != nil {
				// Disk size
				if disk.Properties.DiskSizeGB != nil {
					info.DiskSizeGB = fmt.Sprintf("%d", *disk.Properties.DiskSizeGB)
				}

				// OS Type
				if disk.Properties.OSType != nil {
					info.OSType = string(*disk.Properties.OSType)
				}

				// Disk state
				if disk.Properties.DiskState != nil {
					info.DiskState = string(*disk.Properties.DiskState)
				}

				// Managed by (what resource is using this disk)
				if disk.ManagedBy != nil {
					managedByID := *disk.ManagedBy
					// Extract resource name from full resource ID
					info.ManagedBy = extractResourceNameFromID(managedByID)
				}

				// Encryption settings
				info.EncryptionType, info.EncryptionStatus = getDiskEncryptionStatus(disk)
			}

			disks = append(disks, info)
		}
	}

	return disks, nil
}

// getDiskEncryptionStatus determines the encryption status of a disk
func getDiskEncryptionStatus(disk *armcompute.Disk) (string, string) {
	if disk.Properties == nil {
		return "N/A", "Unknown"
	}

	encryptionType := "Platform Managed"
	encryptionStatus := "Encryption At Rest Only"

	// Check encryption settings
	if disk.Properties.Encryption != nil {
		if disk.Properties.Encryption.Type != nil {
			encryptionType = string(*disk.Properties.Encryption.Type)

			switch *disk.Properties.Encryption.Type {
			case armcompute.EncryptionTypeEncryptionAtRestWithPlatformKey:
				encryptionStatus = "Encryption At Rest Only"
			case armcompute.EncryptionTypeEncryptionAtRestWithCustomerKey:
				encryptionStatus = "Customer Managed Key"
			case armcompute.EncryptionTypeEncryptionAtRestWithPlatformAndCustomerKeys:
				encryptionStatus = "Platform + Customer Keys"
			}
		}

		// Check if disk encryption set is configured
		if disk.Properties.Encryption.DiskEncryptionSetID != nil {
			encryptionStatus = "Disk Encryption Set (Customer Managed)"
		}
	}

	// Check for Azure Disk Encryption (BitLocker/dm-crypt)
	if disk.Properties.EncryptionSettingsCollection != nil && disk.Properties.EncryptionSettingsCollection.Enabled != nil {
		if *disk.Properties.EncryptionSettingsCollection.Enabled {
			encryptionStatus = "Azure Disk Encryption (Full)"
			if disk.Properties.EncryptionSettingsCollection.EncryptionSettings != nil &&
				len(disk.Properties.EncryptionSettingsCollection.EncryptionSettings) > 0 {
				// Has encryption settings configured
				encryptionStatus = "Azure Disk Encryption (Active)"
			}
		}
	}

	// If no encryption settings at all, mark as not encrypted
	if disk.Properties.Encryption == nil &&
		(disk.Properties.EncryptionSettingsCollection == nil ||
			disk.Properties.EncryptionSettingsCollection.Enabled == nil ||
			!*disk.Properties.EncryptionSettingsCollection.Enabled) {
		encryptionStatus = "Not Encrypted"
	}

	return encryptionType, encryptionStatus
}

// extractResourceNameFromID extracts the resource name from a full Azure resource ID
// Example: /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Compute/virtualMachines/{name}
// Returns: {name}
func extractResourceNameFromID(resourceID string) string {
	if resourceID == "" {
		return "Unknown"
	}

	// Simple extraction - get last part after final /
	for i := len(resourceID) - 1; i >= 0; i-- {
		if resourceID[i] == '/' {
			return resourceID[i+1:]
		}
	}

	return resourceID
}
