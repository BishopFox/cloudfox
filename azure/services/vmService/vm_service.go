// Package vmservice provides Azure Virtual Machine service abstractions
//
// This service layer abstracts Azure Compute API calls from command modules,
// following the standardized pattern established in STANDARDIZATION.md.
package vmservice

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/BishopFox/cloudfox/globals"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/patrickmn/go-cache"
)

// serviceCache is the centralized cache for VM service calls
var serviceCache = cache.New(2*time.Hour, 10*time.Minute)

// cacheKey generates a consistent cache key from components
func cacheKey(parts ...string) string {
	result := "vmservice"
	for _, part := range parts {
		result += "-" + part
	}
	return result
}

// VMService provides methods for interacting with Azure Virtual Machines
type VMService struct {
	session *azinternal.SafeSession
}

// New creates a new VMService instance
func New(session *azinternal.SafeSession) *VMService {
	return &VMService{
		session: session,
	}
}

// NewWithSession creates a new VMService with the given session (alias for New)
func NewWithSession(session *azinternal.SafeSession) *VMService {
	return New(session)
}

// VMInfo represents an Azure VM with security-relevant fields
type VMInfo struct {
	Name               string
	ResourceGroup      string
	Location           string
	VMSize             string
	OSType             string
	OSPublisher        string
	OSOffer            string
	OSSKU              string
	ProvisioningState  string
	PowerState         string
	PrivateIPs         []string
	PublicIPs          []string
	AdminUsername      string
	SystemAssignedID   string
	UserAssignedIDs    []string
	AvailabilitySet    string
	AvailabilityZones  []string
	NetworkInterfaces  []string
}

// VMSSInfo represents an Azure VM Scale Set
type VMSSInfo struct {
	Name              string
	ResourceGroup     string
	Location          string
	Capacity          int64
	VMSize            string
	ProvisioningState string
	UpgradePolicy     string
	SystemAssignedID  string
	UserAssignedIDs   []string
}

// DiskInfo represents an Azure Managed Disk
type DiskInfo struct {
	Name              string
	ResourceGroup     string
	Location          string
	DiskSizeGB        int32
	DiskState         string
	SKU               string
	OSType            string
	Encryption        string
	NetworkAccessPolicy string
}

// getARMCredential returns ARM credential from session
func (s *VMService) getARMCredential() (*azinternal.StaticTokenCredential, error) {
	token, err := s.session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token: %w", err)
	}
	return &azinternal.StaticTokenCredential{Token: token}, nil
}

// ListVMsByResourceGroup returns all VMs in a resource group
func (s *VMService) ListVMsByResourceGroup(ctx context.Context, subID, rgName string) ([]*armcompute.VirtualMachine, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armcompute.NewVirtualMachinesClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create VM client: %w", err)
	}

	pager := client.NewListPager(rgName, nil)
	var vms []*armcompute.VirtualMachine

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return vms, fmt.Errorf("failed to list VMs: %w", err)
		}
		vms = append(vms, page.Value...)
	}

	return vms, nil
}

// ListVMs returns all VMs in a subscription
func (s *VMService) ListVMs(ctx context.Context, subID string) ([]*armcompute.VirtualMachine, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armcompute.NewVirtualMachinesClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create VM client: %w", err)
	}

	pager := client.NewListAllPager(nil)
	var vms []*armcompute.VirtualMachine

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return vms, fmt.Errorf("failed to list VMs: %w", err)
		}
		vms = append(vms, page.Value...)
	}

	return vms, nil
}

// GetVM returns a specific VM
func (s *VMService) GetVM(ctx context.Context, subID, rgName, vmName string) (*armcompute.VirtualMachine, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armcompute.NewVirtualMachinesClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create VM client: %w", err)
	}

	resp, err := client.Get(ctx, rgName, vmName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get VM: %w", err)
	}

	return &resp.VirtualMachine, nil
}

// GetVMInstanceView returns the instance view (power state, etc.) for a VM
func (s *VMService) GetVMInstanceView(ctx context.Context, subID, rgName, vmName string) (*armcompute.VirtualMachineInstanceView, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armcompute.NewVirtualMachinesClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create VM client: %w", err)
	}

	resp, err := client.InstanceView(ctx, rgName, vmName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get VM instance view: %w", err)
	}

	return &resp.VirtualMachineInstanceView, nil
}

// ListVMSS returns all VM Scale Sets in a subscription
func (s *VMService) ListVMSS(ctx context.Context, subID string) ([]*armcompute.VirtualMachineScaleSet, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armcompute.NewVirtualMachineScaleSetsClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create VMSS client: %w", err)
	}

	pager := client.NewListAllPager(nil)
	var vmss []*armcompute.VirtualMachineScaleSet

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return vmss, fmt.Errorf("failed to list VMSS: %w", err)
		}
		vmss = append(vmss, page.Value...)
	}

	return vmss, nil
}

// ListDisks returns all managed disks in a subscription
func (s *VMService) ListDisks(ctx context.Context, subID string) ([]*armcompute.Disk, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armcompute.NewDisksClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create disks client: %w", err)
	}

	pager := client.NewListPager(nil)
	var disks []*armcompute.Disk

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return disks, fmt.Errorf("failed to list disks: %w", err)
		}
		disks = append(disks, page.Value...)
	}

	return disks, nil
}

// ListDisksByResourceGroup returns all managed disks in a resource group
func (s *VMService) ListDisksByResourceGroup(ctx context.Context, subID, rgName string) ([]*armcompute.Disk, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armcompute.NewDisksClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create disks client: %w", err)
	}

	pager := client.NewListByResourceGroupPager(rgName, nil)
	var disks []*armcompute.Disk

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return disks, fmt.Errorf("failed to list disks: %w", err)
		}
		disks = append(disks, page.Value...)
	}

	return disks, nil
}

// safeString safely dereferences a string pointer
func safeString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// ============================================================================
// CACHED METHODS - Use these in command modules for better performance
// ============================================================================

// CachedListVMs returns cached VMs for a subscription
func (s *VMService) CachedListVMs(ctx context.Context, subID string) ([]*armcompute.VirtualMachine, error) {
	key := cacheKey("vms", subID)

	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armcompute.VirtualMachine), nil
	}

	result, err := s.ListVMs(ctx, subID)
	if err != nil {
		return nil, err
	}

	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListVMsByResourceGroup returns cached VMs for a resource group
func (s *VMService) CachedListVMsByResourceGroup(ctx context.Context, subID, rgName string) ([]*armcompute.VirtualMachine, error) {
	key := cacheKey("vms-by-rg", subID, rgName)

	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armcompute.VirtualMachine), nil
	}

	result, err := s.ListVMsByResourceGroup(ctx, subID, rgName)
	if err != nil {
		return nil, err
	}

	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListVMSS returns cached VM Scale Sets for a subscription
func (s *VMService) CachedListVMSS(ctx context.Context, subID string) ([]*armcompute.VirtualMachineScaleSet, error) {
	key := cacheKey("vmss", subID)

	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armcompute.VirtualMachineScaleSet), nil
	}

	result, err := s.ListVMSS(ctx, subID)
	if err != nil {
		return nil, err
	}

	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListDisks returns cached managed disks for a subscription
func (s *VMService) CachedListDisks(ctx context.Context, subID string) ([]*armcompute.Disk, error) {
	key := cacheKey("disks", subID)

	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armcompute.Disk), nil
	}

	result, err := s.ListDisks(ctx, subID)
	if err != nil {
		return nil, err
	}

	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListDisksByResourceGroup returns cached disks for a resource group
func (s *VMService) CachedListDisksByResourceGroup(ctx context.Context, subID, rgName string) ([]*armcompute.Disk, error) {
	key := cacheKey("disks-by-rg", subID, rgName)

	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armcompute.Disk), nil
	}

	result, err := s.ListDisksByResourceGroup(ctx, subID, rgName)
	if err != nil {
		return nil, err
	}

	serviceCache.Set(key, result, 0)
	return result, nil
}
