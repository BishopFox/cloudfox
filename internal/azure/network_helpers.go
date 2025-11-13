package azure

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
	"github.com/BishopFox/cloudfox/globals"
)

// ListNetworkSecurityGroups lists all NSGs in a resource group
func ListNetworkSecurityGroups(ctx context.Context, session *SafeSession, subscriptionID, resourceGroupName string) ([]*armnetwork.SecurityGroup, error) {
	// Get NSG client
	nsgClient, err := GetNSGClient(session, subscriptionID)
	if err != nil {
		return nil, fmt.Errorf("failed to create NSG client: %v", err)
	}

	// List NSGs
	var nsgs []*armnetwork.SecurityGroup
	pager := nsgClient.NewListPager(resourceGroupName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list NSGs: %v", err)
		}
		nsgs = append(nsgs, page.Value...)
	}

	return nsgs, nil
}

// GetResourceGroupLocation returns the location/region of a resource group
func GetResourceGroupLocation(session *SafeSession, subscriptionID, resourceGroupName string) string {
	rgs := GetResourceGroupsPerSubscription(session, subscriptionID)
	for _, rg := range rgs {
		if rg.Name != nil && *rg.Name == resourceGroupName && rg.Location != nil {
			return *rg.Location
		}
	}
	return "Unknown"
}

// GetVMNetworkInterfaces returns the network interfaces attached to a VM
func GetVMNetworkInterfaces(session *SafeSession, subscriptionID, vmName, resourceGroupName string) []*armnetwork.Interface {
	// Get the VM first to find its NICs
	ctx := context.Background()

	// Get token for ARM
	token, err := session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return []*armnetwork.Interface{}
	}

	cred := &StaticTokenCredential{Token: token}

	// Create network client
	nicClient, err := armnetwork.NewInterfacesClient(subscriptionID, cred, nil)
	if err != nil {
		return []*armnetwork.Interface{}
	}

	// List all NICs in the resource group and filter by VM
	var vmNICs []*armnetwork.Interface
	pager := nicClient.NewListPager(resourceGroupName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}

		for _, nic := range page.Value {
			// Check if this NIC is attached to the specified VM
			if nic.Properties != nil && nic.Properties.VirtualMachine != nil && nic.Properties.VirtualMachine.ID != nil {
				// Extract VM name from the ID
				vmID := *nic.Properties.VirtualMachine.ID
				if len(vmID) > 0 && containsVMName(vmID, vmName) {
					vmNICs = append(vmNICs, nic)
				}
			}
		}
	}

	return vmNICs
}

// containsVMName checks if a VM ID contains the specified VM name
func containsVMName(vmID, vmName string) bool {
	// VM ID format: /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Compute/virtualMachines/{vmName}
	// Simple check: does the ID end with the VM name
	expectedSuffix := "/virtualMachines/" + vmName
	return len(vmID) >= len(expectedSuffix) && vmID[len(vmID)-len(expectedSuffix):] == expectedSuffix
}

// GetStorageContainers returns the blob containers for a storage account
func GetStorageContainers(ctx context.Context, session *SafeSession, subscriptionID, resourceGroupName, storageAccountName string) ([]string, error) {
	// Get token for ARM
	token, err := session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token: %v", err)
	}

	// Use REST API since SDK might not have all methods
	url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/storageAccounts/%s/blobServices/default/containers?api-version=2023-01-01",
		subscriptionID, resourceGroupName, storageAccountName)

	req, err := NewAuthenticatedRequest("GET", url, token, nil)
	if err != nil {
		return nil, err
	}

	resp, err := SendAuthenticatedRequest(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Value []struct {
			Name string `json:"name"`
		} `json:"value"`
	}

	if err := UnmarshalResponseBody(resp, &result); err != nil {
		return nil, err
	}

	var containers []string
	for _, c := range result.Value {
		containers = append(containers, c.Name)
	}

	return containers, nil
}

// ListVirtualNetworks lists all virtual networks in a resource group
func ListVirtualNetworks(ctx context.Context, session *SafeSession, subscriptionID, resourceGroupName string) ([]*armnetwork.VirtualNetwork, error) {
	// Get VNet client
	vnetClient, err := GetVirtualNetworksClient(session, subscriptionID)
	if err != nil {
		return nil, fmt.Errorf("failed to create VNet client: %v", err)
	}

	// List VNets
	var vnets []*armnetwork.VirtualNetwork
	pager := vnetClient.NewListPager(resourceGroupName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list VNets: %v", err)
		}
		vnets = append(vnets, page.Value...)
	}

	return vnets, nil
}

// GetSubscriptionFromResourceID extracts the subscription ID from an Azure resource ID
// Resource ID format: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/...
func GetSubscriptionFromResourceID(resourceID string) string {
	parts := strings.Split(resourceID, "/")
	// Look for "subscriptions" segment, then take the next one
	for i, part := range parts {
		if strings.EqualFold(part, "subscriptions") && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return "Unknown"
}
