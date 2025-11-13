package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/BishopFox/cloudfox/internal/azure/sdk"
	"github.com/spf13/cobra"
)

// ------------------------------
// Cobra command
// ------------------------------
var AzKeyVaultCommand = &cobra.Command{
	Use:     "keyvaults",
	Aliases: []string{"kv"},
	Short:   "Enumerate Azure Key Vaults, Secrets, Keys, and Certificates",
	Long: `
Enumerate Azure Key Vaults for a specific tenant:
./cloudfox az kv --tenant TENANT_ID

Enumerate Azure Key Vaults for a specific subscription:
./cloudfox az kv --subscription SUBSCRIPTION_ID`,
	Run: ListKeyVaults,
}

// ------------------------------
// Module struct (AWS pattern with embedded BaseAzureModule)
// ------------------------------
type KeyVaultsModule struct {
	azinternal.BaseAzureModule // Embed common fields (15 fields)

	// Module-specific fields
	Subscriptions []string
	VaultRows     [][]string
	HsmRows       [][]string
	CertRows      [][]string
	LootMap       map[string]*internal.LootFile
	mu            sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type KeyVaultsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o KeyVaultsOutput) TableFiles() []internal.TableFile { return o.Table }
func (o KeyVaultsOutput) LootFiles() []internal.LootFile   { return o.Loot }

type CertificateInfo = azinternal.CertificateInfo
type AzureVault = azinternal.AzureVault

// ------------------------------
// Cobra command entry point (thin wrapper)
// ------------------------------
func ListKeyVaults(cmd *cobra.Command, args []string) {
	// -------------------- Use InitializeCommandContext helper --------------------
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_KEYVAULT_MODULE_NAME)
	if err != nil {
		return // error already logged by helper
	}
	defer cmdCtx.Session.StopMonitoring()

	// -------------------- Initialize module --------------------
	module := &KeyVaultsModule{
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:   cmdCtx.Subscriptions,
		VaultRows:       [][]string{},
		HsmRows:         [][]string{},
		CertRows:        [][]string{},
		LootMap: map[string]*internal.LootFile{
			"keyvault-commands":               {Name: "keyvault-commands", Contents: ""},
			"keyvault-soft-deleted-commands":  {Name: "keyvault-soft-deleted-commands", Contents: ""},
			"keyvault-access-policy-commands": {Name: "keyvault-access-policy-commands", Contents: ""},
			"managedhsm-commands":             {Name: "managedhsm-commands", Contents: ""},
		},
	}

	// -------------------- Execute module --------------------
	module.PrintKeyVaults(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method (AWS-style)
// ------------------------------
func (m *KeyVaultsModule) PrintKeyVaults(ctx context.Context, logger internal.Logger) {
	// Multi-tenant support: iterate over tenants if enabled
	if m.IsMultiTenant {
		for _, tenantCtx := range m.Tenants {
			// Save current tenant context
			savedTenantID := m.TenantID
			savedTenantName := m.TenantName
			savedTenantInfo := m.TenantInfo

			// Switch to current tenant
			m.TenantID = tenantCtx.TenantID
			m.TenantName = tenantCtx.TenantName
			m.TenantInfo = tenantCtx.TenantInfo

			// Process this tenant's subscriptions
			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_KEYVAULT_MODULE_NAME, m.processSubscription)

			// Restore tenant context
			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		// Single-tenant mode
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_KEYVAULT_MODULE_NAME, m.processSubscription)
	}

	// Generate soft-deleted recovery commands
	m.generateSoftDeletedLoot()

	// Generate access policy manipulation commands
	m.generateAccessPolicyLoot()

	// Generate and write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *KeyVaultsModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
	// Get subscription name
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)

	// Get resource groups (CACHED)
	resourceGroups := m.ResolveResourceGroups(subID)

	// Process each resource group
	for _, rgName := range resourceGroups {
		// Get Key Vaults (CACHED)
		vaults, err := sdk.CachedGetKeyVaultsPerResourceGroup(ctx, m.Session, subID, rgName)
		if err != nil {
			logger.ErrorM(fmt.Sprintf("Failed to get KeyVaults in RG %s: %v", rgName, err), globals.AZ_KEYVAULT_MODULE_NAME)
			m.CommandCounter.Error++
			continue
		}

		// Process each vault concurrently
		vaultWg := new(sync.WaitGroup)
		for _, v := range vaults {
			if m.ResourceGroupFlag != "" && v.ResourceGroup != rgName {
				continue
			}

			vaultWg.Add(1)
			go m.processVault(ctx, v, subID, subName, vaultWg, logger)
		}
		vaultWg.Wait()
	}

	// -------------------- Enumerate Managed HSMs --------------------
	token, err := m.Session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to get ARM token for subscription %s: %v", subID, err), globals.AZ_KEYVAULT_MODULE_NAME)
		}
		return
	}

	cred := &azinternal.StaticTokenCredential{Token: token}
	hsmClient, err := armkeyvault.NewManagedHsmsClient(subID, cred, nil)
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to create Managed HSM client for subscription %s: %v", subID, err), globals.AZ_KEYVAULT_MODULE_NAME)
		}
		return
	}

	// List Managed HSMs by resource group
	for _, rgName := range resourceGroups {
		hsmPager := hsmClient.NewListByResourceGroupPager(rgName, nil)
		for hsmPager.More() {
			hsmPage, err := hsmPager.NextPage(ctx)
			if err != nil {
				if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
					logger.ErrorM(fmt.Sprintf("Failed to list Managed HSMs in %s/%s: %v", subID, rgName, err), globals.AZ_KEYVAULT_MODULE_NAME)
				}
				m.CommandCounter.Error++
				continue
			}

			for _, hsm := range hsmPage.Value {
				if hsm == nil || hsm.Name == nil {
					continue
				}

				m.processManagedHsm(ctx, hsm, subID, subName, rgName, logger)
			}
		}
	}
}

// ------------------------------
// Process single vault
// ------------------------------
func (m *KeyVaultsModule) processVault(ctx context.Context, v AzureVault, subID, subName string, wg *sync.WaitGroup, logger internal.Logger) {
	defer wg.Done()

	exposure := "Unknown"
	entraIDAuth := "Unknown"
	softDeleteEnabled := "Unknown"
	systemMIRoles := "N/A"
	userMIRoles := "N/A"

	token, err := m.Session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return
	}

	cred := &azinternal.StaticTokenCredential{Token: token}
	clientFactory, err := armkeyvault.NewClientFactory(subID, cred, nil)
	if err == nil {
		vaultResp, err := clientFactory.NewVaultsClient().Get(ctx, v.ResourceGroup, v.VaultName, nil)
		if err == nil && vaultResp.Properties != nil {
			if vaultResp.Properties.EnableRbacAuthorization != nil {
				if *vaultResp.Properties.EnableRbacAuthorization {
					entraIDAuth = "Enabled"
				} else {
					entraIDAuth = "Disabled"
				}
			}
			if vaultResp.Properties.EnableSoftDelete != nil {
				if *vaultResp.Properties.EnableSoftDelete {
					softDeleteEnabled = "true"
				} else {
					softDeleteEnabled = "false"
				}
			}
			if vaultResp.Properties.PublicNetworkAccess != nil && *vaultResp.Properties.PublicNetworkAccess == string(armkeyvault.PublicNetworkAccessDisabled) {
				exposure = "PrivateOnly"
			} else if vaultResp.Properties.NetworkACLs != nil {
				n := vaultResp.Properties.NetworkACLs
				if n.DefaultAction != nil && *n.DefaultAction == armkeyvault.NetworkRuleActionAllow {
					if len(n.IPRules) == 0 {
						exposure = "PublicOpen"
					} else {
						for _, ipr := range n.IPRules {
							if ipr.Value != nil && *ipr.Value == "0.0.0.0/0" {
								exposure = "PublicOpen"
								break
							}
						}
						if exposure != "PublicOpen" {
							exposure = "PublicRestricted"
						}
					}
				} else {
					exposure = "PublicRestricted"
				}
			} else {
				exposure = "PublicOpen"
			}
			systemMIRoles, userMIRoles = GetKeyVaultMIRoles(
				ctx,
				m.Session,
				vaultResp.Properties,
				v.VaultName,
				v.ResourceGroup,
				subID,
			)
		}
	}

	// Add vault row (thread-safe)
	m.mu.Lock()
	m.VaultRows = append(m.VaultRows, []string{
		m.TenantName,
		m.TenantID,
		v.Subscription,
		subName,
		v.ResourceGroup,
		v.Region,
		v.VaultName,
		entraIDAuth,
		softDeleteEnabled,
		fmt.Sprintf("https://%s.vault.azure.net/", v.VaultName),
		exposure,
		systemMIRoles,
		userMIRoles,
	})
	m.mu.Unlock()

	// Enumerate vault contents
	vaultURI := fmt.Sprintf("https://%s.vault.azure.net/", v.VaultName)
	secrets, keys, certInfos, err := enumerateVaultContents(ctx, m.Session, vaultURI)
	if err != nil && globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("enumerateVaultContents error for %s: %v", v.VaultName, err), globals.AZ_KEYVAULT_MODULE_NAME)
	}
	certs, _ := azinternal.GetCertificatesPerKeyVault(ctx, m.Session, vaultURI)
	certInfos = append(certInfos, certs...)

	// Build loot content
	m.mu.Lock()
	defer m.mu.Unlock()

	lf := m.LootMap["keyvault-commands"]
	lf.Contents += fmt.Sprintf(
		"## Vault: %s\n"+
			"# Set subscription context\n"+
			"az account set --subscription %s\n"+
			"\n"+
			"# Show vault details\n"+
			"az keyvault show --name %s --resource-group %s\n"+
			"\n"+
			"# List secrets\n"+
			"az keyvault secret list --vault-name %s\n"+
			"\n"+
			"# List keys\n"+
			"az keyvault key list --vault-name %s\n"+
			"\n"+
			"# List certificates\n"+
			"az keyvault certificate list --vault-name %s\n"+
			"\n"+
			"## PowerShell equivalents\n"+
			"Set-AzContext -SubscriptionId %s\n"+
			"Get-AzKeyVault -VaultName %s -ResourceGroupName %s\n"+
			"Get-AzKeyVaultSecret -VaultName %s\n"+
			"Get-AzKeyVaultKey -VaultName %s\n"+
			"Get-AzKeyVaultCertificate -VaultName %s\n\n",
		v.VaultName,
		v.Subscription,
		v.VaultName, v.ResourceGroup,
		v.VaultName,
		v.VaultName,
		v.VaultName,
		v.Subscription,
		v.VaultName, v.ResourceGroup,
		v.VaultName,
		v.VaultName,
		v.VaultName,
	)

	for _, s := range secrets {
		if s != "" {
			lf.Contents += fmt.Sprintf(
				"# Show secret: %s\n"+
					"az keyvault secret show --vault-name %s --name %s\n"+
					"Get-AzKeyVaultSecret -VaultName %s -Name %s\n",
				s,
				v.VaultName, s,
				v.VaultName, s,
			)
		}
	}

	for _, k := range keys {
		if k != "" {
			lf.Contents += fmt.Sprintf(
				"# Show key: %s\n"+
					"az keyvault key show --vault-name %s --name %s\n"+
					"Get-AzKeyVaultKey -VaultName %s -Name %s\n",
				k,
				v.VaultName, k,
				v.VaultName, k,
			)
		}
	}

	for _, c := range certInfos {
		if c.Name != "" {
			lf.Contents += fmt.Sprintf(
				"# Show certificate: %s\n"+
					"az keyvault certificate show --vault-name %s --name %s\n"+
					"Get-AzKeyVaultCertificate -VaultName %s -Name %s\n",
				c.Name,
				v.VaultName, c.Name,
				v.VaultName, c.Name,
			)
			m.CertRows = append(m.CertRows, []string{
				m.TenantName,
				m.TenantID,
				v.Subscription,
				subName,
				v.VaultName,
				c.Name,
				fmt.Sprintf("%v", c.Enabled),
				c.ExpiresOn,
				c.Issuer,
				c.Subject,
				c.Thumbprint,
			})
		}
	}
}

// ------------------------------
// Process single Managed HSM
// ------------------------------
func (m *KeyVaultsModule) processManagedHsm(ctx context.Context, hsm *armkeyvault.ManagedHsm, subID, subName, rgName string, logger internal.Logger) {
	if hsm == nil || hsm.Name == nil {
		return
	}

	hsmName := *hsm.Name

	// Extract region
	region := "N/A"
	if hsm.Location != nil {
		region = *hsm.Location
	}

	// Extract HSM URI
	hsmURI := "N/A"
	if hsm.Properties != nil && hsm.Properties.HsmURI != nil {
		hsmURI = *hsm.Properties.HsmURI
	}

	// Extract provisioning state
	provisioningState := "N/A"
	if hsm.Properties != nil && hsm.Properties.ProvisioningState != nil {
		provisioningState = string(*hsm.Properties.ProvisioningState)
	}

	// Determine public vs private network access
	publicNetworkAccess := "Enabled"
	if hsm.Properties != nil && hsm.Properties.PublicNetworkAccess != nil {
		publicNetworkAccess = string(*hsm.Properties.PublicNetworkAccess)
	}

	// Determine network exposure
	exposure := "PublicOpen"
	if publicNetworkAccess == "Disabled" {
		exposure = "PrivateOnly"
	}

	// Soft delete enabled
	softDeleteEnabled := "Unknown"
	if hsm.Properties != nil && hsm.Properties.EnableSoftDelete != nil {
		if *hsm.Properties.EnableSoftDelete {
			softDeleteEnabled = "true"
		} else {
			softDeleteEnabled = "false"
		}
	}

	// Purge protection enabled
	purgeProtectionEnabled := "Unknown"
	if hsm.Properties != nil && hsm.Properties.EnablePurgeProtection != nil {
		if *hsm.Properties.EnablePurgeProtection {
			purgeProtectionEnabled = "true"
		} else {
			purgeProtectionEnabled = "false"
		}
	}

	// Security domain activation status
	securityDomainActivated := "Unknown"
	if hsm.Properties != nil && hsm.Properties.StatusMessage != nil {
		// Security domain status is typically reflected in the status message
		statusMsg := strings.ToLower(*hsm.Properties.StatusMessage)
		if strings.Contains(statusMsg, "security domain activated") || strings.Contains(statusMsg, "active") {
			securityDomainActivated = "Yes"
		} else if strings.Contains(statusMsg, "not activated") || strings.Contains(statusMsg, "pending") {
			securityDomainActivated = "No"
		}
	}

	// SKU
	sku := "N/A"
	if hsm.SKU != nil && hsm.SKU.Name != nil {
		sku = string(*hsm.SKU.Name)
	}

	// Add HSM row (thread-safe)
	m.mu.Lock()
	m.HsmRows = append(m.HsmRows, []string{
		m.TenantName,
		m.TenantID,
		subID,
		subName,
		rgName,
		region,
		hsmName,
		hsmURI,
		provisioningState,
		exposure,
		softDeleteEnabled,
		purgeProtectionEnabled,
		securityDomainActivated,
		sku,
	})
	m.mu.Unlock()

	// Generate loot commands
	m.mu.Lock()
	lf := m.LootMap["managedhsm-commands"]
	lf.Contents += fmt.Sprintf("## Managed HSM: %s\n", hsmName)
	lf.Contents += fmt.Sprintf("# Set subscription context\n")
	lf.Contents += fmt.Sprintf("az account set --subscription %s\n\n", subID)
	lf.Contents += fmt.Sprintf("# Show Managed HSM details\n")
	lf.Contents += fmt.Sprintf("az keyvault show --hsm-name %s --resource-group %s\n\n", hsmName, rgName)
	lf.Contents += fmt.Sprintf("# List keys in Managed HSM\n")
	lf.Contents += fmt.Sprintf("az keyvault key list --hsm-name %s\n\n", hsmName)
	lf.Contents += fmt.Sprintf("# Backup security domain (requires quorum of keys)\n")
	lf.Contents += fmt.Sprintf("az keyvault security-domain download --hsm-name %s --sd-file %s-security-domain.json --sd-quorum 2 --security-domain-cert-keys key1.cer key2.cer key3.cer\n\n", hsmName, hsmName)
	lf.Contents += fmt.Sprintf("# Check role assignments\n")
	lf.Contents += fmt.Sprintf("az role assignment list --scope /subscriptions/%s/resourceGroups/%s/providers/Microsoft.KeyVault/managedHSMs/%s\n\n", subID, rgName, hsmName)
	lf.Contents += fmt.Sprintf("# List Managed HSM role definitions (RBAC)\n")
	lf.Contents += fmt.Sprintf("az keyvault role definition list --hsm-name %s\n\n", hsmName)
	lf.Contents += fmt.Sprintf("# PowerShell equivalent:\n")
	lf.Contents += fmt.Sprintf("Set-AzContext -SubscriptionId %s\n", subID)
	lf.Contents += fmt.Sprintf("Get-AzKeyVaultManagedHsm -Name %s -ResourceGroupName %s\n\n", hsmName, rgName)
	lf.Contents += "---\n\n"
	m.mu.Unlock()

	m.CommandCounter.Total++
}

// ------------------------------
// Generate soft-deleted recovery loot
// ------------------------------
func (m *KeyVaultsModule) generateSoftDeletedLoot() {
	lf := m.LootMap["keyvault-soft-deleted-commands"]

	// Deduplicate vaults using a map keyed by subscription+rg+vault name
	type VaultInfo struct {
		SubscriptionID   string
		SubscriptionName string
		ResourceGroup    string
		VaultName        string
	}
	uniqueVaults := make(map[string]VaultInfo)

	for _, row := range m.VaultRows {
		if len(row) < 7 {
			continue
		}
		subID := row[2]
		subName := row[3]
		rgName := row[4]
		vaultName := row[6]

		key := subID + "/" + rgName + "/" + vaultName
		uniqueVaults[key] = VaultInfo{
			SubscriptionID:   subID,
			SubscriptionName: subName,
			ResourceGroup:    rgName,
			VaultName:        vaultName,
		}
	}

	// Generate loot for each unique vault
	for _, vault := range uniqueVaults {
		lf.Contents += fmt.Sprintf("## Vault: %s (Subscription: %s, RG: %s)\n\n",
			vault.VaultName, vault.SubscriptionName, vault.ResourceGroup)

		lf.Contents += fmt.Sprintf("# Set subscription context\n")
		lf.Contents += fmt.Sprintf("az account set --subscription %s\n\n", vault.SubscriptionID)

		// ==================== SECRETS ====================
		lf.Contents += fmt.Sprintf("# ==================== SOFT-DELETED SECRETS ====================\n\n")

		lf.Contents += fmt.Sprintf("# Step 1: List all soft-deleted secrets in the vault\n")
		lf.Contents += fmt.Sprintf("az keyvault secret list-deleted --vault-name %s\n\n", vault.VaultName)

		lf.Contents += fmt.Sprintf("# Step 2: Show details of a specific soft-deleted secret (including value if accessible)\n")
		lf.Contents += fmt.Sprintf("az keyvault secret show-deleted --vault-name %s --name <SECRET-NAME>\n\n", vault.VaultName)

		lf.Contents += fmt.Sprintf("# Step 3: Recover a soft-deleted secret (restore it to active state)\n")
		lf.Contents += fmt.Sprintf("az keyvault secret recover --vault-name %s --name <SECRET-NAME>\n\n", vault.VaultName)

		lf.Contents += fmt.Sprintf("# Step 4: Recover all soft-deleted secrets (batch recovery)\n")
		lf.Contents += fmt.Sprintf("for secret in $(az keyvault secret list-deleted --vault-name %s --query '[].name' -o tsv); do\n", vault.VaultName)
		lf.Contents += fmt.Sprintf("  echo \"Recovering secret: $secret\"\n")
		lf.Contents += fmt.Sprintf("  az keyvault secret recover --vault-name %s --name \"$secret\"\n", vault.VaultName)
		lf.Contents += fmt.Sprintf("done\n\n")

		// ==================== KEYS ====================
		lf.Contents += fmt.Sprintf("# ==================== SOFT-DELETED KEYS ====================\n\n")

		lf.Contents += fmt.Sprintf("# Step 1: List all soft-deleted keys in the vault\n")
		lf.Contents += fmt.Sprintf("az keyvault key list-deleted --vault-name %s\n\n", vault.VaultName)

		lf.Contents += fmt.Sprintf("# Step 2: Show details of a specific soft-deleted key\n")
		lf.Contents += fmt.Sprintf("az keyvault key show-deleted --vault-name %s --name <KEY-NAME>\n\n", vault.VaultName)

		lf.Contents += fmt.Sprintf("# Step 3: Recover a soft-deleted key (restore it to active state)\n")
		lf.Contents += fmt.Sprintf("az keyvault key recover --vault-name %s --name <KEY-NAME>\n\n", vault.VaultName)

		lf.Contents += fmt.Sprintf("# Step 4: Recover all soft-deleted keys (batch recovery)\n")
		lf.Contents += fmt.Sprintf("for key in $(az keyvault key list-deleted --vault-name %s --query '[].kid' -o tsv | xargs -n1 basename); do\n", vault.VaultName)
		lf.Contents += fmt.Sprintf("  echo \"Recovering key: $key\"\n")
		lf.Contents += fmt.Sprintf("  az keyvault key recover --vault-name %s --name \"$key\"\n", vault.VaultName)
		lf.Contents += fmt.Sprintf("done\n\n")

		// ==================== CERTIFICATES ====================
		lf.Contents += fmt.Sprintf("# ==================== SOFT-DELETED CERTIFICATES ====================\n\n")

		lf.Contents += fmt.Sprintf("# Step 1: List all soft-deleted certificates in the vault\n")
		lf.Contents += fmt.Sprintf("az keyvault certificate list-deleted --vault-name %s\n\n", vault.VaultName)

		lf.Contents += fmt.Sprintf("# Step 2: Show details of a specific soft-deleted certificate\n")
		lf.Contents += fmt.Sprintf("az keyvault certificate show-deleted --vault-name %s --name <CERT-NAME>\n\n", vault.VaultName)

		lf.Contents += fmt.Sprintf("# Step 3: Recover a soft-deleted certificate (restore it to active state)\n")
		lf.Contents += fmt.Sprintf("az keyvault certificate recover --vault-name %s --name <CERT-NAME>\n\n", vault.VaultName)

		lf.Contents += fmt.Sprintf("# Step 4: Recover all soft-deleted certificates (batch recovery)\n")
		lf.Contents += fmt.Sprintf("for cert in $(az keyvault certificate list-deleted --vault-name %s --query '[].id' -o tsv | xargs -n1 basename); do\n", vault.VaultName)
		lf.Contents += fmt.Sprintf("  echo \"Recovering certificate: $cert\"\n")
		lf.Contents += fmt.Sprintf("  az keyvault certificate recover --vault-name %s --name \"$cert\"\n", vault.VaultName)
		lf.Contents += fmt.Sprintf("done\n\n")

		// ==================== POWERSHELL EQUIVALENTS ====================
		lf.Contents += fmt.Sprintf("# ==================== POWERSHELL EQUIVALENTS ====================\n\n")

		lf.Contents += fmt.Sprintf("Set-AzContext -SubscriptionId %s\n\n", vault.SubscriptionID)

		lf.Contents += fmt.Sprintf("## Secrets\n")
		lf.Contents += fmt.Sprintf("Get-AzKeyVaultSecret -VaultName %s -InRemovedState\n", vault.VaultName)
		lf.Contents += fmt.Sprintf("Get-AzKeyVaultSecret -VaultName %s -Name <SECRET-NAME> -InRemovedState\n", vault.VaultName)
		lf.Contents += fmt.Sprintf("Undo-AzKeyVaultSecretRemoval -VaultName %s -Name <SECRET-NAME>\n\n", vault.VaultName)

		lf.Contents += fmt.Sprintf("## Keys\n")
		lf.Contents += fmt.Sprintf("Get-AzKeyVaultKey -VaultName %s -InRemovedState\n", vault.VaultName)
		lf.Contents += fmt.Sprintf("Get-AzKeyVaultKey -VaultName %s -Name <KEY-NAME> -InRemovedState\n", vault.VaultName)
		lf.Contents += fmt.Sprintf("Undo-AzKeyVaultKeyRemoval -VaultName %s -Name <KEY-NAME>\n\n", vault.VaultName)

		lf.Contents += fmt.Sprintf("## Certificates\n")
		lf.Contents += fmt.Sprintf("Get-AzKeyVaultCertificate -VaultName %s -InRemovedState\n", vault.VaultName)
		lf.Contents += fmt.Sprintf("Get-AzKeyVaultCertificate -VaultName %s -Name <CERT-NAME> -InRemovedState\n", vault.VaultName)
		lf.Contents += fmt.Sprintf("Undo-AzKeyVaultCertificateRemoval -VaultName %s -Name <CERT-NAME>\n\n", vault.VaultName)

		lf.Contents += fmt.Sprintf("## Batch recovery (PowerShell)\n")
		lf.Contents += fmt.Sprintf("# Recover all soft-deleted secrets\n")
		lf.Contents += fmt.Sprintf("Get-AzKeyVaultSecret -VaultName %s -InRemovedState | ForEach-Object { Undo-AzKeyVaultSecretRemoval -VaultName %s -Name $_.Name }\n\n", vault.VaultName, vault.VaultName)
		lf.Contents += fmt.Sprintf("# Recover all soft-deleted keys\n")
		lf.Contents += fmt.Sprintf("Get-AzKeyVaultKey -VaultName %s -InRemovedState | ForEach-Object { Undo-AzKeyVaultKeyRemoval -VaultName %s -Name $_.Name }\n\n", vault.VaultName, vault.VaultName)
		lf.Contents += fmt.Sprintf("# Recover all soft-deleted certificates\n")
		lf.Contents += fmt.Sprintf("Get-AzKeyVaultCertificate -VaultName %s -InRemovedState | ForEach-Object { Undo-AzKeyVaultCertificateRemoval -VaultName %s -Name $_.Name }\n\n", vault.VaultName, vault.VaultName)

		lf.Contents += fmt.Sprintf("################################################################################\n\n")
	}
}

// ------------------------------
// Generate access policy manipulation loot
// ------------------------------
func (m *KeyVaultsModule) generateAccessPolicyLoot() {
	lf := m.LootMap["keyvault-access-policy-commands"]

	// Deduplicate vaults using a map keyed by subscription+rg+vault name
	type VaultInfo struct {
		SubscriptionID   string
		SubscriptionName string
		ResourceGroup    string
		VaultName        string
	}
	uniqueVaults := make(map[string]VaultInfo)

	for _, row := range m.VaultRows {
		if len(row) < 7 {
			continue
		}
		subID := row[2]
		subName := row[3]
		rgName := row[4]
		vaultName := row[6]

		key := subID + "/" + rgName + "/" + vaultName
		uniqueVaults[key] = VaultInfo{
			SubscriptionID:   subID,
			SubscriptionName: subName,
			ResourceGroup:    rgName,
			VaultName:        vaultName,
		}
	}

	// Generate loot for each unique vault
	for _, vault := range uniqueVaults {
		lf.Contents += fmt.Sprintf("## Vault: %s (Subscription: %s, RG: %s)\n\n",
			vault.VaultName, vault.SubscriptionName, vault.ResourceGroup)

		lf.Contents += fmt.Sprintf("# Set subscription context\n")
		lf.Contents += fmt.Sprintf("az account set --subscription %s\n\n", vault.SubscriptionID)

		// ==================== ACCESS POLICIES ====================
		lf.Contents += fmt.Sprintf("# ==================== ACCESS POLICY ENUMERATION ====================\n\n")

		lf.Contents += fmt.Sprintf("# Step 1: List all current access policies for the vault\n")
		lf.Contents += fmt.Sprintf("az keyvault show --name %s --query 'properties.accessPolicies'\n\n", vault.VaultName)

		lf.Contents += fmt.Sprintf("# Step 2: Show complete vault properties including access policies and network ACLs\n")
		lf.Contents += fmt.Sprintf("az keyvault show --name %s\n\n", vault.VaultName)

		lf.Contents += fmt.Sprintf("# Step 3: Check current user's access\n")
		lf.Contents += fmt.Sprintf("CURRENT_USER_OID=$(az ad signed-in-user show --query id -o tsv)\n")
		lf.Contents += fmt.Sprintf("az keyvault show --name %s --query \"properties.accessPolicies[?objectId=='$CURRENT_USER_OID']\"\n\n", vault.VaultName)

		// ==================== ACCESS POLICY MODIFICATION ====================
		lf.Contents += fmt.Sprintf("# ==================== ACCESS POLICY MODIFICATION ====================\n\n")

		lf.Contents += fmt.Sprintf("# WARNING: Access policy modifications are logged in Azure Activity Logs.\n")
		lf.Contents += fmt.Sprintf("# Monitor for alerts: 'Microsoft.KeyVault/vaults/write' operations\n\n")

		lf.Contents += fmt.Sprintf("# Step 4: Grant a principal (user/service principal) full access to secrets\n")
		lf.Contents += fmt.Sprintf("az keyvault set-policy --name %s \\\n", vault.VaultName)
		lf.Contents += fmt.Sprintf("  --object-id <PRINCIPAL-OBJECT-ID> \\\n")
		lf.Contents += fmt.Sprintf("  --secret-permissions get list set delete recover backup restore\n\n")

		lf.Contents += fmt.Sprintf("# Step 5: Grant a principal full access to keys\n")
		lf.Contents += fmt.Sprintf("az keyvault set-policy --name %s \\\n", vault.VaultName)
		lf.Contents += fmt.Sprintf("  --object-id <PRINCIPAL-OBJECT-ID> \\\n")
		lf.Contents += fmt.Sprintf("  --key-permissions get list create update import delete recover backup restore decrypt encrypt unwrapKey wrapKey verify sign\n\n")

		lf.Contents += fmt.Sprintf("# Step 6: Grant a principal full access to certificates\n")
		lf.Contents += fmt.Sprintf("az keyvault set-policy --name %s \\\n", vault.VaultName)
		lf.Contents += fmt.Sprintf("  --object-id <PRINCIPAL-OBJECT-ID> \\\n")
		lf.Contents += fmt.Sprintf("  --certificate-permissions get list create update import delete recover backup restore managecontacts manageissuers getissuers listissuers setissuers deleteissuers\n\n")

		lf.Contents += fmt.Sprintf("# Step 7: Grant full access to all resources (secrets, keys, certificates) at once\n")
		lf.Contents += fmt.Sprintf("az keyvault set-policy --name %s \\\n", vault.VaultName)
		lf.Contents += fmt.Sprintf("  --object-id <PRINCIPAL-OBJECT-ID> \\\n")
		lf.Contents += fmt.Sprintf("  --secret-permissions get list set delete recover backup restore \\\n")
		lf.Contents += fmt.Sprintf("  --key-permissions get list create update import delete recover backup restore decrypt encrypt unwrapKey wrapKey verify sign \\\n")
		lf.Contents += fmt.Sprintf("  --certificate-permissions get list create update import delete recover backup restore managecontacts manageissuers getissuers listissuers setissuers deleteissuers\n\n")

		lf.Contents += fmt.Sprintf("# Step 8: Get your current user's object ID (for self-granting access)\n")
		lf.Contents += fmt.Sprintf("CURRENT_USER_OID=$(az ad signed-in-user show --query id -o tsv)\n")
		lf.Contents += fmt.Sprintf("echo \"Current user object ID: $CURRENT_USER_OID\"\n\n")

		lf.Contents += fmt.Sprintf("# Step 9: Grant yourself full access to the vault\n")
		lf.Contents += fmt.Sprintf("az keyvault set-policy --name %s \\\n", vault.VaultName)
		lf.Contents += fmt.Sprintf("  --object-id $CURRENT_USER_OID \\\n")
		lf.Contents += fmt.Sprintf("  --secret-permissions get list set delete recover backup restore \\\n")
		lf.Contents += fmt.Sprintf("  --key-permissions get list create update import delete recover backup restore decrypt encrypt unwrapKey wrapKey verify sign \\\n")
		lf.Contents += fmt.Sprintf("  --certificate-permissions get list create update import delete recover backup restore managecontacts manageissuers getissuers listissuers setissuers deleteissuers\n\n")

		// ==================== NETWORK ACL MODIFICATION ====================
		lf.Contents += fmt.Sprintf("# ==================== NETWORK ACL MODIFICATION ====================\n\n")

		lf.Contents += fmt.Sprintf("# WARNING: Network ACL modifications are logged in Azure Activity Logs.\n")
		lf.Contents += fmt.Sprintf("# Monitor for alerts: 'Microsoft.KeyVault/vaults/write' operations\n\n")

		lf.Contents += fmt.Sprintf("# Step 10: Show current network rules\n")
		lf.Contents += fmt.Sprintf("az keyvault show --name %s --query 'properties.networkAcls'\n\n", vault.VaultName)

		lf.Contents += fmt.Sprintf("# Step 11: Add your current IP to the vault's firewall (if vault has IP restrictions)\n")
		lf.Contents += fmt.Sprintf("CURRENT_IP=$(curl -s ifconfig.me)\n")
		lf.Contents += fmt.Sprintf("echo \"Your current IP: $CURRENT_IP\"\n")
		lf.Contents += fmt.Sprintf("az keyvault network-rule add --name %s --ip-address $CURRENT_IP\n\n", vault.VaultName)

		lf.Contents += fmt.Sprintf("# Step 12: Add a specific IP address to the allowlist\n")
		lf.Contents += fmt.Sprintf("az keyvault network-rule add --name %s --ip-address <IP-ADDRESS>\n\n", vault.VaultName)

		lf.Contents += fmt.Sprintf("# Step 13: Allow access from all networks (opens vault to public - HIGH RISK)\n")
		lf.Contents += fmt.Sprintf("az keyvault update --name %s --default-action Allow\n\n", vault.VaultName)

		lf.Contents += fmt.Sprintf("# Step 14: Bypass Azure services (allows trusted Microsoft services to access vault)\n")
		lf.Contents += fmt.Sprintf("az keyvault update --name %s --bypass AzureServices\n\n", vault.VaultName)

		lf.Contents += fmt.Sprintf("# Step 15: Disable public network access completely (private endpoint only)\n")
		lf.Contents += fmt.Sprintf("az keyvault update --name %s --public-network-access Disabled\n\n", vault.VaultName)

		lf.Contents += fmt.Sprintf("# Step 16: Enable public network access\n")
		lf.Contents += fmt.Sprintf("az keyvault update --name %s --public-network-access Enabled\n\n", vault.VaultName)

		// ==================== POWERSHELL EQUIVALENTS ====================
		lf.Contents += fmt.Sprintf("# ==================== POWERSHELL EQUIVALENTS ====================\n\n")

		lf.Contents += fmt.Sprintf("Set-AzContext -SubscriptionId %s\n\n", vault.SubscriptionID)

		lf.Contents += fmt.Sprintf("## List access policies\n")
		lf.Contents += fmt.Sprintf("$vault = Get-AzKeyVault -VaultName %s\n", vault.VaultName)
		lf.Contents += fmt.Sprintf("$vault.AccessPolicies\n\n")

		lf.Contents += fmt.Sprintf("## Grant full access to a principal\n")
		lf.Contents += fmt.Sprintf("Set-AzKeyVaultAccessPolicy -VaultName %s `\n", vault.VaultName)
		lf.Contents += fmt.Sprintf("  -ObjectId <PRINCIPAL-OBJECT-ID> `\n")
		lf.Contents += fmt.Sprintf("  -PermissionsToSecrets get,list,set,delete,recover,backup,restore `\n")
		lf.Contents += fmt.Sprintf("  -PermissionsToKeys get,list,create,update,import,delete,recover,backup,restore,decrypt,encrypt,unwrapKey,wrapKey,verify,sign `\n")
		lf.Contents += fmt.Sprintf("  -PermissionsToCertificates get,list,create,update,import,delete,recover,backup,restore,managecontacts,manageissuers,getissuers,listissuers,setissuers,deleteissuers\n\n")

		lf.Contents += fmt.Sprintf("## Get current user object ID and grant access\n")
		lf.Contents += fmt.Sprintf("$currentUser = Get-AzADUser -SignedIn\n")
		lf.Contents += fmt.Sprintf("Set-AzKeyVaultAccessPolicy -VaultName %s `\n", vault.VaultName)
		lf.Contents += fmt.Sprintf("  -ObjectId $currentUser.Id `\n")
		lf.Contents += fmt.Sprintf("  -PermissionsToSecrets get,list,set,delete,recover,backup,restore `\n")
		lf.Contents += fmt.Sprintf("  -PermissionsToKeys get,list,create,update,import,delete,recover,backup,restore,decrypt,encrypt,unwrapKey,wrapKey,verify,sign `\n")
		lf.Contents += fmt.Sprintf("  -PermissionsToCertificates get,list,create,update,import,delete,recover,backup,restore,managecontacts,manageissuers,getissuers,listissuers,setissuers,deleteissuers\n\n")

		lf.Contents += fmt.Sprintf("## Network ACL modifications\n")
		lf.Contents += fmt.Sprintf("# Add current IP to firewall\n")
		lf.Contents += fmt.Sprintf("$currentIP = (Invoke-WebRequest -Uri 'https://ifconfig.me/ip').Content.Trim()\n")
		lf.Contents += fmt.Sprintf("Add-AzKeyVaultNetworkRule -VaultName %s -IpAddressRange $currentIP\n\n", vault.VaultName)

		lf.Contents += fmt.Sprintf("# Update default network action to Allow (opens to public)\n")
		lf.Contents += fmt.Sprintf("Update-AzKeyVaultNetworkRuleSet -VaultName %s -DefaultAction Allow\n\n", vault.VaultName)

		lf.Contents += fmt.Sprintf("# Bypass Azure services\n")
		lf.Contents += fmt.Sprintf("Update-AzKeyVaultNetworkRuleSet -VaultName %s -Bypass AzureServices\n\n", vault.VaultName)

		lf.Contents += fmt.Sprintf("################################################################################\n\n")
	}
}

// ------------------------------
// Write output (AWS-style writeLoot pattern)
// ------------------------------
func (m *KeyVaultsModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.VaultRows) == 0 && len(m.HsmRows) == 0 {
		logger.InfoM("No Key Vaults or Managed HSMs found", globals.AZ_KEYVAULT_MODULE_NAME)
		return
	}

	// Build headers for vaults table
	vaultHeaders := []string{
		"Tenant Name",
		"Tenant ID",
		"Subscription ID",
		"Subscription Name",
		"Resource Group",
		"Region",
		"Vault Name",
		"EntraID Centralized Auth",
		"Soft Delete Enabled",
		"Vault URI",
		"Public?",
		"System Assigned Roles",
		"User Assigned Roles",
	}

	// Check if we should split output by tenant (takes precedence over subscription split)
	if len(m.VaultRows) > 0 && azinternal.ShouldSplitByTenant(m.IsMultiTenant, m.Tenants) {
		if err := m.FilterAndWritePerTenantAuto(
			ctx, logger, m.Tenants, m.VaultRows, vaultHeaders,
			"keyvaults", globals.AZ_KEYVAULT_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Check if we should split output by subscription (only for vaults table)
	if len(m.VaultRows) > 0 && azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		if err := m.FilterAndWritePerSubscriptionAuto(
			ctx, logger, m.Subscriptions, m.VaultRows, vaultHeaders,
			"keyvaults", globals.AZ_KEYVAULT_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Build loot array
	loot := []internal.LootFile{}
	for _, lf := range m.LootMap {
		if lf.Contents != "" {
			loot = append(loot, *lf)
		}
	}

	// Create output with vault table
	output := KeyVaultsOutput{
		Table: []internal.TableFile{},
		Loot:  loot,
	}

	// Add Key Vaults table if we have vaults
	if len(m.VaultRows) > 0 {
		output.Table = append(output.Table, internal.TableFile{
			Name:   "keyvaults",
			Header: vaultHeaders,
			Body:   m.VaultRows,
		})
	}

	// Add Managed HSMs table if we have HSMs
	if len(m.HsmRows) > 0 {
		output.Table = append(output.Table, internal.TableFile{
			Name: "keyvault-managed-hsms",
			Header: []string{
				"Tenant Name",
				"Tenant ID",
				"Subscription ID",
				"Subscription Name",
				"Resource Group",
				"Region",
				"HSM Name",
				"HSM URI",
				"Provisioning State",
				"Public?",
				"Soft Delete Enabled",
				"Purge Protection Enabled",
				"Security Domain Activated",
				"SKU",
			},
			Body: m.HsmRows,
		})
	}

	// Add certificates table if we have certificates
	if len(m.CertRows) > 0 {
		output.Table = append(output.Table, internal.TableFile{
			Name:   "keyvault-certificates",
			Header: []string{"Tenant Name", "Tenant ID", "Subscription ID", "Subscription Name", "Vault Name", "Certificate Name", "Enabled", "Expiry", "Issuer", "Subject", "Thumbprint"},
			Body:   m.CertRows,
		})
	}

	// Determine output scope (single subscription vs tenant-wide consolidation)
	scopeType, scopeIDs, scopeNames := azinternal.DetermineScopeForOutput(m.Subscriptions, m.TenantID, m.TenantName, m.TenantFlagPresent)
	scopeNames = azinternal.GetSubscriptionNamesForOutput(ctx, m.Session, scopeType, scopeIDs)

	// Write output using HandleOutputSmart (automatic streaming for large datasets)
	if err := internal.HandleOutputSmart(
		"Azure",
		m.Format,
		m.OutputDirectory,
		m.Verbosity,
		m.WrapTable,
		scopeType,
		scopeIDs,
		scopeNames,
		m.UserUPN,
		output,
	); err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_KEYVAULT_MODULE_NAME)
		m.CommandCounter.Error++
	}

	totalResources := len(m.VaultRows) + len(m.HsmRows)
	logger.SuccessM(fmt.Sprintf("Found %d Key Vault(s) and %d Managed HSM(s) (%d total) across %d subscription(s)", len(m.VaultRows), len(m.HsmRows), totalResources, len(m.Subscriptions)), globals.AZ_KEYVAULT_MODULE_NAME)
}

// enumerateVaultContents lists secrets, keys, and certificates for a given vault URI
func enumerateVaultContents(ctx context.Context, session *azinternal.SafeSession, vaultURI string) ([]string, []string, []CertificateInfo, error) {
	logger := internal.NewLogger()
	var secrets []string
	var keys []string
	var certs []CertificateInfo

	scope := globals.CommonScopes[2] // Key Vault data-plane scope
	token, err := session.GetTokenForResource(scope)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("failed to get token for scope %s: %v", scope, err), globals.AZ_KEYVAULT_MODULE_NAME)
		return nil, nil, nil, err
	}
	cred := &azinternal.StaticTokenCredential{Token: token}

	// Helper to make a short per-call timeout derived from ctx
	withShortTimeout := func(parent context.Context, d time.Duration) (context.Context, context.CancelFunc) {
		if parent == nil {
			return context.WithTimeout(context.Background(), d)
		}
		return context.WithTimeout(parent, d)
	}

	// ---------------- SECRETS ----------------
	secretClient, err := azsecrets.NewClient(vaultURI, cred, nil)
	if err == nil {
		pager := secretClient.NewListSecretPropertiesPager(nil)
		for pager.More() {
			// use a short timeout for NextPage to avoid hanging on private vaults
			pageCtx, cancel := withShortTimeout(ctx, 6*time.Second)
			page, err := pager.NextPage(pageCtx)
			cancel()
			if err != nil {
				// skip the rest of secrets for this vault if page fetch fails
				// Return a nil error so caller continues; log for diagnostics
				// Use fmt.Printf or logger depending on your style (we'll fmt.Printf to avoid import changes here)
				if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
					logger.ErrorM(fmt.Sprintf("ListSecretsPager.NextPage failed for %s: %v\n", vaultURI, err), globals.AZ_KEYVAULT_MODULE_NAME)
				}
				break
			}
			for _, s := range page.Value {
				if s.ID == nil {
					continue
				}
				// ID.Name() may panic if ID not set; guard above.
				secrets = append(secrets, s.ID.Name())
			}
		}
	} else {
		// client creation failed (likely unreachable under some conditions) — log and continue
		logger.ErrorM(fmt.Sprintf("NewClient(azsecrets) failed for %s: %v\n", vaultURI, err), globals.AZ_KEYVAULT_MODULE_NAME)
	}

	// ---------------- KEYS ----------------
	keyClient, err := azkeys.NewClient(vaultURI, cred, nil)
	if err == nil {
		pager := keyClient.NewListKeyPropertiesPager(nil)
		for pager.More() {
			pageCtx, cancel := withShortTimeout(ctx, 6*time.Second)
			page, err := pager.NextPage(pageCtx)
			cancel()
			if err != nil {
				if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
					logger.ErrorM(fmt.Sprintf("ListKeysPager.NextPage failed for %s: %v\n", vaultURI, err), globals.AZ_KEYVAULT_MODULE_NAME)
				}
				break
			}
			for _, k := range page.Value {
				if k.KID == nil {
					continue
				}
				keys = append(keys, k.KID.Name())
			}
		}
	} else {
		logger.ErrorM(fmt.Sprintf("NewClient(azkeys) failed for %s: %v\n", vaultURI, err), globals.AZ_KEYVAULT_MODULE_NAME)
	}

	// ---------------- CERTIFICATES ----------------
	certClient, err := azcertificates.NewClient(vaultURI, cred, nil)
	if err == nil {
		pager := certClient.NewListCertificatePropertiesPager(nil)
		for pager.More() {
			pageCtx, cancel := withShortTimeout(ctx, 6*time.Second)
			page, err := pager.NextPage(pageCtx)
			cancel()
			if err != nil {
				if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
					logger.ErrorM(fmt.Sprintf("ListCertificatesPager.NextPage failed for %s: %v\n", vaultURI, err), globals.AZ_KEYVAULT_MODULE_NAME)
				}
				break
			}
			for _, c := range page.Value {
				if c.ID == nil {
					continue
				}

				// for fetching certificate details we use a short timeout
				certCtx, certCancel := withShortTimeout(ctx, 5*time.Second)
				certResp, err := certClient.GetCertificate(certCtx, c.ID.Name(), c.ID.Version(), nil)
				certCancel()
				if err != nil {
					// skip this certificate if unable to get details (private vault / permission)
					if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
						logger.ErrorM(fmt.Sprintf("GetCertificate failed for %s cert %s: %v\n", vaultURI, c.ID.Name(), err), globals.AZ_KEYVAULT_MODULE_NAME)
					}
					continue
				}

				thumbprint := ""
				if certResp.X509Thumbprint != nil {
					thumbprint = fmt.Sprintf("%x", certResp.X509Thumbprint)
				}

				certs = append(certs, CertificateInfo{
					Name:       c.ID.Name(),
					Thumbprint: thumbprint,
					Enabled:    false,
					ExpiresOn:  "",
					Issuer:     "",
					Subject:    "",
				})
			}
		}
	} else {
		logger.ErrorM(fmt.Sprintf("NewClient(azcertificates) failed for %s: %v\n", vaultURI, err), globals.AZ_KEYVAULT_MODULE_NAME)
	}

	// no fatal error returned; enumeration failures show up in printed logs and result sets
	return secrets, keys, certs, nil
}

func GetKeyVaultMIRoles(ctx context.Context, session *azinternal.SafeSession, vaultProps *armkeyvault.VaultProperties, vaultName, resourceGroup, subID string) (systemMIRoles string, userMIRoles string) {
	var systemRoles, userRoles []string

	if vaultProps == nil || vaultProps.AccessPolicies == nil {
		return "N/A", "N/A"
	}

	// Enumerate roles for all principals in AccessPolicies
	for _, policy := range vaultProps.AccessPolicies {
		if policy.ObjectID == nil || *policy.ObjectID == "" {
			continue
		}

		roles, err := azinternal.GetRoleAssignmentsForPrincipal(ctx, session, *policy.ObjectID, subID)
		roleStr := "N/A"
		if err != nil {
			roleStr = fmt.Sprintf("Error: %v", err)
		} else if len(roles) > 0 {
			roleStr = strings.Join(roles, ", ")
		}

		// Tentatively classify as system/user based on TenantID presence
		if policy.TenantID != nil {
			userRoles = append(userRoles, roleStr)
		} else {
			systemRoles = append(systemRoles, roleStr)
		}
	}

	if len(systemRoles) == 0 {
		systemMIRoles = "N/A"
	} else {
		systemMIRoles = strings.Join(systemRoles, " | ")
	}

	if len(userRoles) == 0 {
		userMIRoles = "N/A"
	} else {
		userMIRoles = strings.Join(userRoles, " | ")
	}

	return systemMIRoles, userMIRoles
}
