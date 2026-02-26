// Package keyvaultservice provides Azure Key Vault service abstractions
//
// This service layer abstracts Azure Key Vault API calls from command modules,
// following the standardized pattern established in STANDARDIZATION.md.
package keyvaultservice

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/BishopFox/cloudfox/globals"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/patrickmn/go-cache"
)

// serviceCache is the centralized cache for Key Vault service calls
var serviceCache = cache.New(2*time.Hour, 10*time.Minute)

// cacheKey generates a consistent cache key from components
func cacheKey(parts ...string) string {
	result := "keyvaultservice"
	for _, part := range parts {
		result += "-" + part
	}
	return result
}

// KeyVaultService provides methods for interacting with Azure Key Vault
type KeyVaultService struct {
	session *azinternal.SafeSession
}

// New creates a new KeyVaultService instance
func New(session *azinternal.SafeSession) *KeyVaultService {
	return &KeyVaultService{
		session: session,
	}
}

// NewWithSession creates a new KeyVaultService with the given session (alias for New)
func NewWithSession(session *azinternal.SafeSession) *KeyVaultService {
	return New(session)
}

// VaultInfo represents an Azure Key Vault with security-relevant fields
type VaultInfo struct {
	Name                     string
	ResourceGroup            string
	Location                 string
	VaultURI                 string
	SKU                      string
	TenantID                 string
	EnableSoftDelete         bool
	EnablePurgeProtection    bool
	EnableRbacAuthorization  bool
	EnabledForDeployment     bool
	EnabledForDiskEncryption bool
	EnabledForTemplateDeployment bool
	NetworkDefaultAction     string
	PublicNetworkAccess      string
}

// SecretInfo represents a secret in Key Vault
type SecretInfo struct {
	VaultName   string
	Name        string
	Enabled     bool
	ContentType string
	Created     string
	Updated     string
	Expires     string
}

// KeyInfo represents a key in Key Vault
type KeyInfo struct {
	VaultName string
	Name      string
	KeyType   string
	Enabled   bool
	Created   string
	Updated   string
	Expires   string
}

// CertificateInfo represents a certificate in Key Vault
type CertificateInfo struct {
	VaultName string
	Name      string
	Enabled   bool
	Created   string
	Updated   string
	Expires   string
}

// getARMCredential returns ARM credential from session
func (s *KeyVaultService) getARMCredential() (*azinternal.StaticTokenCredential, error) {
	token, err := s.session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token: %w", err)
	}
	return &azinternal.StaticTokenCredential{Token: token}, nil
}

// getVaultCredential returns Key Vault data plane credential from session
func (s *KeyVaultService) getVaultCredential() (*azinternal.StaticTokenCredential, error) {
	token, err := s.session.GetTokenForResource("https://vault.azure.net")
	if err != nil {
		return nil, fmt.Errorf("failed to get vault token: %w", err)
	}
	return &azinternal.StaticTokenCredential{Token: token}, nil
}

// ListVaultsByResourceGroup returns all key vaults in a resource group
func (s *KeyVaultService) ListVaultsByResourceGroup(ctx context.Context, subID, rgName string) ([]*armkeyvault.Vault, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armkeyvault.NewVaultsClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create vaults client: %w", err)
	}

	pager := client.NewListByResourceGroupPager(rgName, nil)
	var vaults []*armkeyvault.Vault

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return vaults, fmt.Errorf("failed to list vaults: %w", err)
		}
		vaults = append(vaults, page.Value...)
	}

	return vaults, nil
}

// ListVaults returns all key vaults in a subscription
func (s *KeyVaultService) ListVaults(ctx context.Context, subID string) ([]*armkeyvault.Vault, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armkeyvault.NewVaultsClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create vaults client: %w", err)
	}

	pager := client.NewListBySubscriptionPager(nil)
	var vaults []*armkeyvault.Vault

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return vaults, fmt.Errorf("failed to list vaults: %w", err)
		}
		vaults = append(vaults, page.Value...)
	}

	return vaults, nil
}

// GetVault returns a specific key vault
func (s *KeyVaultService) GetVault(ctx context.Context, subID, rgName, vaultName string) (*armkeyvault.Vault, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armkeyvault.NewVaultsClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create vaults client: %w", err)
	}

	resp, err := client.Get(ctx, rgName, vaultName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get vault: %w", err)
	}

	return &resp.Vault, nil
}

// ListSecrets returns all secrets in a key vault (metadata only)
func (s *KeyVaultService) ListSecrets(ctx context.Context, vaultURI string) ([]*azsecrets.SecretProperties, error) {
	cred, err := s.getVaultCredential()
	if err != nil {
		return nil, err
	}

	client, err := azsecrets.NewClient(vaultURI, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create secrets client: %w", err)
	}

	pager := client.NewListSecretPropertiesPager(nil)
	var secrets []*azsecrets.SecretProperties

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return secrets, fmt.Errorf("failed to list secrets: %w", err)
		}
		for _, s := range page.Value {
			secrets = append(secrets, s)
		}
	}

	return secrets, nil
}

// GetSecret returns a specific secret value
func (s *KeyVaultService) GetSecret(ctx context.Context, vaultURI, secretName string) (*azsecrets.GetSecretResponse, error) {
	cred, err := s.getVaultCredential()
	if err != nil {
		return nil, err
	}

	client, err := azsecrets.NewClient(vaultURI, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create secrets client: %w", err)
	}

	resp, err := client.GetSecret(ctx, secretName, "", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret: %w", err)
	}

	return &resp, nil
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

// CachedListVaultsByResourceGroup returns cached key vaults for a resource group
func (s *KeyVaultService) CachedListVaultsByResourceGroup(ctx context.Context, subID, rgName string) ([]*armkeyvault.Vault, error) {
	key := cacheKey("vaults-by-rg", subID, rgName)

	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armkeyvault.Vault), nil
	}

	result, err := s.ListVaultsByResourceGroup(ctx, subID, rgName)
	if err != nil {
		return nil, err
	}

	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListVaults returns cached key vaults for a subscription
func (s *KeyVaultService) CachedListVaults(ctx context.Context, subID string) ([]*armkeyvault.Vault, error) {
	key := cacheKey("vaults", subID)

	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armkeyvault.Vault), nil
	}

	result, err := s.ListVaults(ctx, subID)
	if err != nil {
		return nil, err
	}

	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListSecrets returns cached secrets for a key vault
func (s *KeyVaultService) CachedListSecrets(ctx context.Context, vaultURI string) ([]*azsecrets.SecretProperties, error) {
	key := cacheKey("secrets", vaultURI)

	if cached, found := serviceCache.Get(key); found {
		return cached.([]*azsecrets.SecretProperties), nil
	}

	result, err := s.ListSecrets(ctx, vaultURI)
	if err != nil {
		return nil, err
	}

	serviceCache.Set(key, result, 0)
	return result, nil
}
