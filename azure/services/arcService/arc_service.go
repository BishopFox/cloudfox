// Package arcservice provides Azure Arc service abstractions
//
// This service layer abstracts Azure Arc API calls from command modules,
// following the standardized pattern established in STANDARDIZATION.md.
package arcservice

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/hybridcompute/armhybridcompute"
	"github.com/BishopFox/cloudfox/globals"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/patrickmn/go-cache"
)

// serviceCache is the centralized cache for Arc service calls
var serviceCache = cache.New(2*time.Hour, 10*time.Minute)

// cacheKey generates a consistent cache key from components
func cacheKey(parts ...string) string {
	result := "arcservice"
	for _, part := range parts {
		result += "-" + part
	}
	return result
}

// ArcService provides methods for interacting with Azure Arc
type ArcService struct {
	session *azinternal.SafeSession
}

// New creates a new ArcService instance
func New(session *azinternal.SafeSession) *ArcService {
	return &ArcService{
		session: session,
	}
}

// NewWithSession creates a new ArcService with the given session (alias for New)
func NewWithSession(session *azinternal.SafeSession) *ArcService {
	return New(session)
}

// MachineInfo represents an Azure Arc-enabled machine
type MachineInfo struct {
	Name              string
	ResourceGroup     string
	Location          string
	Status            string
	OSName            string
	OSVersion         string
	AgentVersion      string
	MachineFQDN       string
	PrivateIPAddress  string
	PublicIPAddress   string
	LastStatusChange  string
}

// ExtensionInfo represents an extension on an Arc machine
type ExtensionInfo struct {
	Name          string
	MachineName   string
	ResourceGroup string
	Publisher     string
	Type          string
	Version       string
	State         string
}

// getARMCredential returns ARM credential from session
func (s *ArcService) getARMCredential() (*azinternal.StaticTokenCredential, error) {
	token, err := s.session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token: %w", err)
	}
	return &azinternal.StaticTokenCredential{Token: token}, nil
}

// ListMachines returns all Arc-enabled machines in a subscription
func (s *ArcService) ListMachines(ctx context.Context, subID string) ([]*armhybridcompute.Machine, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armhybridcompute.NewMachinesClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create machines client: %w", err)
	}

	pager := client.NewListBySubscriptionPager(nil)
	var machines []*armhybridcompute.Machine

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return machines, fmt.Errorf("failed to list machines: %w", err)
		}
		machines = append(machines, page.Value...)
	}

	return machines, nil
}

// ListMachinesByResourceGroup returns all Arc machines in a resource group
func (s *ArcService) ListMachinesByResourceGroup(ctx context.Context, subID, rgName string) ([]*armhybridcompute.Machine, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armhybridcompute.NewMachinesClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create machines client: %w", err)
	}

	pager := client.NewListByResourceGroupPager(rgName, nil)
	var machines []*armhybridcompute.Machine

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return machines, fmt.Errorf("failed to list machines: %w", err)
		}
		machines = append(machines, page.Value...)
	}

	return machines, nil
}

// GetMachine returns a specific Arc machine
func (s *ArcService) GetMachine(ctx context.Context, subID, rgName, machineName string) (*armhybridcompute.Machine, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armhybridcompute.NewMachinesClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create machines client: %w", err)
	}

	resp, err := client.Get(ctx, rgName, machineName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get machine: %w", err)
	}

	return &resp.Machine, nil
}

// ListExtensions returns all extensions for an Arc machine
func (s *ArcService) ListExtensions(ctx context.Context, subID, rgName, machineName string) ([]*armhybridcompute.MachineExtension, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armhybridcompute.NewMachineExtensionsClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create extensions client: %w", err)
	}

	pager := client.NewListPager(rgName, machineName, nil)
	var extensions []*armhybridcompute.MachineExtension

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return extensions, fmt.Errorf("failed to list extensions: %w", err)
		}
		extensions = append(extensions, page.Value...)
	}

	return extensions, nil
}

// safeString safely dereferences a string pointer
func safeString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// =============================================================================
// Cached Methods
// =============================================================================

// CachedListMachines returns all Arc-enabled machines with caching
func (s *ArcService) CachedListMachines(ctx context.Context, subID string) ([]*armhybridcompute.Machine, error) {
	key := cacheKey("machines", subID)
	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armhybridcompute.Machine), nil
	}
	result, err := s.ListMachines(ctx, subID)
	if err != nil {
		return nil, err
	}
	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListExtensions returns all extensions for an Arc machine with caching
func (s *ArcService) CachedListExtensions(ctx context.Context, subID, rgName, machineName string) ([]*armhybridcompute.MachineExtension, error) {
	key := cacheKey("extensions", subID, rgName, machineName)
	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armhybridcompute.MachineExtension), nil
	}
	result, err := s.ListExtensions(ctx, subID, rgName, machineName)
	if err != nil {
		return nil, err
	}
	serviceCache.Set(key, result, 0)
	return result, nil
}
