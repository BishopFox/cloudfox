package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/spf13/cobra"
)

// ------------------------------
// Cobra command
// ------------------------------
var AzResourceGraphCommand = &cobra.Command{
	Use:     "resource-graph",
	Aliases: []string{"rg-query", "arg"},
	Short:   "Execute advanced Azure Resource Graph queries for cross-subscription analysis",
	Long: `
Execute advanced Azure Resource Graph (ARG) queries across subscriptions:
./cloudfox az resource-graph --tenant TENANT_ID

Execute Resource Graph queries for specific subscriptions:
./cloudfox az resource-graph --subscription SUBSCRIPTION_ID

Azure Resource Graph provides powerful KQL-based queries for:
- Cross-subscription resource enumeration
- Resource relationship mapping and dependencies
- Security-focused analysis (public exposure, encryption, tags)
- Compliance and governance queries
- Resource inventory with metadata

Pre-built Security Queries:
1. Internet-facing resources (public IPs, endpoints)
2. Unencrypted resources (storage, databases, disks)
3. Resources without required tags
4. Expired or soon-to-expire certificates
5. Resources in non-compliant regions
6. Orphaned resources (unattached disks, unused IPs)
7. Cross-region dependencies

RISK CLASSIFICATION:
- CRITICAL: Public exposure without encryption, expired certificates
- HIGH: Unencrypted sensitive data, missing critical tags
- MEDIUM: Regional compliance issues, missing recommended tags
- INFO: Inventory and metadata queries

Use Cases:
- Find all internet-facing resources across tenant
- Identify unencrypted databases and storage accounts
- Map resource dependencies for impact analysis
- Enforce tagging policies for cost allocation
- Detect configuration drift across environments`,
	Run: ListResourceGraph,
}

// ------------------------------
// Module struct
// ------------------------------
type ResourceGraphModule struct {
	azinternal.BaseAzureModule

	Subscriptions             []string
	InternetFacingRows        [][]string // Public IPs and endpoints
	UnencryptedRows           [][]string // Resources without encryption
	UntaggedRows              [][]string // Resources missing required tags
	CertificateExpiryRows     [][]string // Expiring certificates
	RegionalComplianceRows    [][]string // Resources in non-compliant regions
	ResourceRelationshipsRows [][]string // Resource dependencies
	ResourceInventoryRows     [][]string // Complete resource inventory
	LootMap                   map[string]*internal.LootFile
	mu                        sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type ResourceGraphOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o ResourceGraphOutput) TableFiles() []internal.TableFile { return o.Table }
func (o ResourceGraphOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point
// ------------------------------
func ListResourceGraph(cmd *cobra.Command, args []string) {
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_RESOURCE_GRAPH_MODULE_NAME)
	if err != nil {
		return
	}
	defer cmdCtx.Session.StopMonitoring()

	module := &ResourceGraphModule{
		BaseAzureModule:           azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:             cmdCtx.Subscriptions,
		InternetFacingRows:        [][]string{},
		UnencryptedRows:           [][]string{},
		UntaggedRows:              [][]string{},
		CertificateExpiryRows:     [][]string{},
		RegionalComplianceRows:    [][]string{},
		ResourceRelationshipsRows: [][]string{},
		ResourceInventoryRows:     [][]string{},
		LootMap: map[string]*internal.LootFile{
			"rg-internet-facing": {Name: "rg-internet-facing", Contents: "# Internet-Facing Resources\n\n"},
			"rg-unencrypted":     {Name: "rg-unencrypted", Contents: "# Unencrypted Resources\n\n"},
			"rg-untagged":        {Name: "rg-untagged", Contents: "# Untagged Resources\n\n"},
			"rg-expiring-certs":  {Name: "rg-expiring-certs", Contents: "# Expiring Certificates\n\n"},
			"rg-query-templates": {Name: "rg-query-templates", Contents: "# Resource Graph Query Templates\n\n"},
		},
	}

	module.PrintResourceGraph(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method
// ------------------------------
func (m *ResourceGraphModule) PrintResourceGraph(ctx context.Context, logger internal.Logger) {
	// Multi-tenant processing
	if m.IsMultiTenant {
		logger.InfoM(fmt.Sprintf("Multi-tenant mode: Processing %d tenants", len(m.Tenants)), globals.AZ_RESOURCE_GRAPH_MODULE_NAME)

		for _, tenantCtx := range m.Tenants {
			savedTenantID := m.TenantID
			savedTenantName := m.TenantName
			savedTenantInfo := m.TenantInfo

			m.TenantID = tenantCtx.TenantID
			m.TenantName = tenantCtx.TenantName
			m.TenantInfo = tenantCtx.TenantInfo

			if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
				logger.InfoM(fmt.Sprintf("Processing tenant: %s (%s)", m.TenantName, m.TenantID), globals.AZ_RESOURCE_GRAPH_MODULE_NAME)
			}

			// Resource Graph queries execute across all specified subscriptions
			m.executeResourceGraphQueries(ctx, tenantCtx.Subscriptions, logger)

			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		logger.InfoM(fmt.Sprintf("Executing Resource Graph queries across %d subscription(s)", len(m.Subscriptions)), globals.AZ_RESOURCE_GRAPH_MODULE_NAME)
		m.executeResourceGraphQueries(ctx, m.Subscriptions, logger)
	}

	// Generate query templates loot file
	m.generateQueryTemplates()

	// Generate and write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Execute Resource Graph queries
// ------------------------------
func (m *ResourceGraphModule) executeResourceGraphQueries(ctx context.Context, subscriptions []string, logger internal.Logger) {
	// 1. Internet-facing resources
	m.queryInternetFacingResources(ctx, subscriptions, logger)

	// 2. Unencrypted resources
	m.queryUnencryptedResources(ctx, subscriptions, logger)

	// 3. Untagged resources
	m.queryUntaggedResources(ctx, subscriptions, logger)

	// 4. Certificate expiry
	m.queryCertificateExpiry(ctx, subscriptions, logger)

	// 5. Regional compliance
	m.queryRegionalCompliance(ctx, subscriptions, logger)

	// 6. Resource relationships
	m.queryResourceRelationships(ctx, subscriptions, logger)

	// 7. Resource inventory (sample - limit to 100 resources)
	m.queryResourceInventory(ctx, subscriptions, logger)
}

// ------------------------------
// Query: Internet-facing resources
// ------------------------------
func (m *ResourceGraphModule) queryInternetFacingResources(ctx context.Context, subscriptions []string, logger internal.Logger) {
	query := `
Resources
| where type =~ 'Microsoft.Network/publicIPAddresses'
   or (type =~ 'Microsoft.Network/applicationGateways' and properties.frontendIPConfigurations[0].properties.publicIPAddress != '')
   or (type =~ 'Microsoft.Network/loadBalancers' and properties.frontendIPConfigurations[0].properties.publicIPAddress != '')
   or (type =~ 'Microsoft.Compute/virtualMachines' and properties.networkProfile.networkInterfaces[0].properties.ipConfigurations[0].properties.publicIPAddress != '')
| project subscriptionId, resourceGroup, name, type, location, properties.ipAddress
`

	results, err := azinternal.ExecuteResourceGraphQuery(ctx, m.Session, subscriptions, query)
	if err != nil {
		if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to query internet-facing resources: %v", err), globals.AZ_RESOURCE_GRAPH_MODULE_NAME)
		}
		return
	}

	for _, res := range results {
		// Determine risk level
		riskLevel := "HIGH" // Public exposure is generally high risk
		if res.ResourceType == "Microsoft.Network/publicIPAddresses" && res.AssociatedResource == "" {
			riskLevel = "MEDIUM" // Unattached public IP is lower risk
		}

		m.mu.Lock()
		m.InternetFacingRows = append(m.InternetFacingRows, []string{
			m.TenantName,
			m.TenantID,
			res.SubscriptionID,
			res.ResourceGroup,
			res.ResourceName,
			res.ResourceType,
			res.Location,
			res.PublicIP,
			res.AssociatedResource,
			riskLevel,
		})

		if lf, ok := m.LootMap["rg-internet-facing"]; ok {
			lf.Contents += fmt.Sprintf("## %s: %s\n", riskLevel, res.ResourceName)
			lf.Contents += fmt.Sprintf("- **Subscription**: %s\n", res.SubscriptionID)
			lf.Contents += fmt.Sprintf("- **Resource Group**: %s\n", res.ResourceGroup)
			lf.Contents += fmt.Sprintf("- **Type**: %s\n", res.ResourceType)
			lf.Contents += fmt.Sprintf("- **Public IP**: %s\n", res.PublicIP)
			lf.Contents += fmt.Sprintf("- **Associated Resource**: %s\n\n", res.AssociatedResource)
		}

		m.mu.Unlock()
	}
}

// ------------------------------
// Query: Unencrypted resources
// ------------------------------
func (m *ResourceGraphModule) queryUnencryptedResources(ctx context.Context, subscriptions []string, logger internal.Logger) {
	query := `
Resources
| where type =~ 'Microsoft.Storage/storageAccounts'
   or type =~ 'Microsoft.Sql/servers/databases'
   or type =~ 'Microsoft.Compute/disks'
| extend encrypted = case(
    type =~ 'Microsoft.Storage/storageAccounts', properties.encryption.services.blob.enabled,
    type =~ 'Microsoft.Sql/servers/databases', properties.transparentDataEncryption.status == 'Enabled',
    type =~ 'Microsoft.Compute/disks', properties.encryptionSettings.enabled,
    false
  )
| where encrypted == false
| project subscriptionId, resourceGroup, name, type, location, encrypted
`

	results, err := azinternal.ExecuteResourceGraphQuery(ctx, m.Session, subscriptions, query)
	if err != nil {
		if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to query unencrypted resources: %v", err), globals.AZ_RESOURCE_GRAPH_MODULE_NAME)
		}
		return
	}

	for _, res := range results {
		// Determine risk level based on resource type
		riskLevel := "CRITICAL"
		if res.ResourceType == "Microsoft.Compute/disks" {
			riskLevel = "HIGH" // Disks are high risk but less critical than databases
		}

		m.mu.Lock()
		m.UnencryptedRows = append(m.UnencryptedRows, []string{
			m.TenantName,
			m.TenantID,
			res.SubscriptionID,
			res.ResourceGroup,
			res.ResourceName,
			res.ResourceType,
			res.Location,
			"No Encryption",
			riskLevel,
		})

		if lf, ok := m.LootMap["rg-unencrypted"]; ok {
			lf.Contents += fmt.Sprintf("## %s: %s (%s)\n", riskLevel, res.ResourceName, res.ResourceType)
			lf.Contents += fmt.Sprintf("- **Subscription**: %s\n", res.SubscriptionID)
			lf.Contents += fmt.Sprintf("- **Resource Group**: %s\n", res.ResourceGroup)
			lf.Contents += fmt.Sprintf("- **Issue**: Encryption not enabled\n")
			lf.Contents += fmt.Sprintf("- **Recommendation**: Enable encryption immediately\n\n")
		}

		m.mu.Unlock()
	}
}

// ------------------------------
// Query: Untagged resources
// ------------------------------
func (m *ResourceGraphModule) queryUntaggedResources(ctx context.Context, subscriptions []string, logger internal.Logger) {
	query := `
Resources
| where isnull(tags) or array_length(tags) == 0
| where type !has 'microsoft.insights'
| project subscriptionId, resourceGroup, name, type, location
| limit 100
`

	results, err := azinternal.ExecuteResourceGraphQuery(ctx, m.Session, subscriptions, query)
	if err != nil {
		if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to query untagged resources: %v", err), globals.AZ_RESOURCE_GRAPH_MODULE_NAME)
		}
		return
	}

	for _, res := range results {
		m.mu.Lock()
		m.UntaggedRows = append(m.UntaggedRows, []string{
			m.TenantName,
			m.TenantID,
			res.SubscriptionID,
			res.ResourceGroup,
			res.ResourceName,
			res.ResourceType,
			res.Location,
			"No Tags",
			"MEDIUM",
		})

		if lf, ok := m.LootMap["rg-untagged"]; ok {
			lf.Contents += fmt.Sprintf("- %s/%s (%s)\n", res.ResourceGroup, res.ResourceName, res.ResourceType)
		}

		m.mu.Unlock()
	}
}

// ------------------------------
// Query: Certificate expiry
// ------------------------------
func (m *ResourceGraphModule) queryCertificateExpiry(ctx context.Context, subscriptions []string, logger internal.Logger) {
	query := `
Resources
| where type =~ 'Microsoft.Network/applicationGateways'
   or type =~ 'Microsoft.Network/frontDoors'
   or type =~ 'Microsoft.Cdn/profiles/endpoints'
| extend certExpiry = properties.sslCertificates[0].properties.expirationDate
| where isnotnull(certExpiry)
| extend daysUntilExpiry = datetime_diff('day', todatetime(certExpiry), now())
| where daysUntilExpiry < 90
| project subscriptionId, resourceGroup, name, type, location, certExpiry, daysUntilExpiry
`

	results, err := azinternal.ExecuteResourceGraphQuery(ctx, m.Session, subscriptions, query)
	if err != nil {
		if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to query certificate expiry: %v", err), globals.AZ_RESOURCE_GRAPH_MODULE_NAME)
		}
		return
	}

	for _, res := range results {
		// Determine risk level based on days until expiry
		riskLevel := "INFO"
		if res.DaysUntilExpiry < 0 {
			riskLevel = "CRITICAL"
		} else if res.DaysUntilExpiry < 30 {
			riskLevel = "HIGH"
		} else if res.DaysUntilExpiry < 60 {
			riskLevel = "MEDIUM"
		}

		m.mu.Lock()
		m.CertificateExpiryRows = append(m.CertificateExpiryRows, []string{
			m.TenantName,
			m.TenantID,
			res.SubscriptionID,
			res.ResourceGroup,
			res.ResourceName,
			res.ResourceType,
			res.Location,
			res.CertificateExpiry,
			fmt.Sprintf("%d days", res.DaysUntilExpiry),
			riskLevel,
		})

		if riskLevel == "CRITICAL" || riskLevel == "HIGH" {
			if lf, ok := m.LootMap["rg-expiring-certs"]; ok {
				lf.Contents += fmt.Sprintf("## %s: %s\n", riskLevel, res.ResourceName)
				lf.Contents += fmt.Sprintf("- **Subscription**: %s\n", res.SubscriptionID)
				lf.Contents += fmt.Sprintf("- **Resource Group**: %s\n", res.ResourceGroup)
				lf.Contents += fmt.Sprintf("- **Certificate Expiry**: %s\n", res.CertificateExpiry)
				lf.Contents += fmt.Sprintf("- **Days Until Expiry**: %d\n\n", res.DaysUntilExpiry)
			}
		}

		m.mu.Unlock()
	}
}

// ------------------------------
// Query: Regional compliance
// ------------------------------
func (m *ResourceGraphModule) queryRegionalCompliance(ctx context.Context, subscriptions []string, logger internal.Logger) {
	// Define allowed regions (example: US regions only)
	allowedRegions := []string{"eastus", "eastus2", "westus", "westus2", "centralus"}

	query := fmt.Sprintf(`
Resources
| where location !in~ ('%s')
| project subscriptionId, resourceGroup, name, type, location
| limit 100
`, strings.Join(allowedRegions, "','"))

	results, err := azinternal.ExecuteResourceGraphQuery(ctx, m.Session, subscriptions, query)
	if err != nil {
		if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to query regional compliance: %v", err), globals.AZ_RESOURCE_GRAPH_MODULE_NAME)
		}
		return
	}

	for _, res := range results {
		m.mu.Lock()
		m.RegionalComplianceRows = append(m.RegionalComplianceRows, []string{
			m.TenantName,
			m.TenantID,
			res.SubscriptionID,
			res.ResourceGroup,
			res.ResourceName,
			res.ResourceType,
			res.Location,
			"Non-Compliant Region",
			"MEDIUM",
		})
		m.mu.Unlock()
	}
}

// ------------------------------
// Query: Resource relationships
// ------------------------------
func (m *ResourceGraphModule) queryResourceRelationships(ctx context.Context, subscriptions []string, logger internal.Logger) {
	query := `
Resources
| where type =~ 'Microsoft.Compute/virtualMachines'
| extend nicId = properties.networkProfile.networkInterfaces[0].id
| join kind=leftouter (
    Resources
    | where type =~ 'Microsoft.Network/networkInterfaces'
    | extend vnetId = properties.ipConfigurations[0].properties.subnet.id
  ) on $left.nicId == $right.id
| project subscriptionId, resourceGroup, name, type, location, nicId, vnetId
| limit 50
`

	results, err := azinternal.ExecuteResourceGraphQuery(ctx, m.Session, subscriptions, query)
	if err != nil {
		if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to query resource relationships: %v", err), globals.AZ_RESOURCE_GRAPH_MODULE_NAME)
		}
		return
	}

	for _, res := range results {
		m.mu.Lock()
		m.ResourceRelationshipsRows = append(m.ResourceRelationshipsRows, []string{
			m.TenantName,
			m.TenantID,
			res.SubscriptionID,
			res.ResourceGroup,
			res.ResourceName,
			res.ResourceType,
			res.RelatedResource1,
			res.RelatedResource2,
			res.RelationshipType,
		})
		m.mu.Unlock()
	}
}

// ------------------------------
// Query: Resource inventory
// ------------------------------
func (m *ResourceGraphModule) queryResourceInventory(ctx context.Context, subscriptions []string, logger internal.Logger) {
	query := `
Resources
| project subscriptionId, resourceGroup, name, type, location, tags, properties.provisioningState
| limit 100
`

	results, err := azinternal.ExecuteResourceGraphQuery(ctx, m.Session, subscriptions, query)
	if err != nil {
		if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to query resource inventory: %v", err), globals.AZ_RESOURCE_GRAPH_MODULE_NAME)
		}
		return
	}

	for _, res := range results {
		m.mu.Lock()
		m.ResourceInventoryRows = append(m.ResourceInventoryRows, []string{
			m.TenantName,
			m.TenantID,
			res.SubscriptionID,
			res.ResourceGroup,
			res.ResourceName,
			res.ResourceType,
			res.Location,
			res.Tags,
			res.ProvisioningState,
		})
		m.mu.Unlock()
	}
}

// ------------------------------
// Generate query templates
// ------------------------------
func (m *ResourceGraphModule) generateQueryTemplates() {
	if lf, ok := m.LootMap["rg-query-templates"]; ok {
		lf.Contents += `## Pre-Built Security Query Templates

These KQL queries can be executed using Azure Resource Graph Explorer or az CLI.

### 1. All Public IPs with Associated Resources
` + "```kql" + `
Resources
| where type =~ 'Microsoft.Network/publicIPAddresses'
| extend associatedResource = properties.ipConfiguration.id
| project subscriptionId, resourceGroup, name, properties.ipAddress, associatedResource, location
` + "```\n\n"

		lf.Contents += `### 2. Unencrypted Storage Accounts
` + "```kql" + `
Resources
| where type =~ 'Microsoft.Storage/storageAccounts'
| where properties.encryption.services.blob.enabled == false
| project subscriptionId, resourceGroup, name, location, properties.encryption
` + "```\n\n"

		lf.Contents += `### 3. VMs Without Backup
` + "```kql" + `
Resources
| where type =~ 'Microsoft.Compute/virtualMachines'
| extend backupItemId = properties.storageProfile.osDisk.properties.diskState
| where isnull(backupItemId)
| project subscriptionId, resourceGroup, name, location
` + "```\n\n"

		lf.Contents += `### 4. NSG Rules Allowing RDP/SSH from Internet
` + "```kql" + `
Resources
| where type =~ 'Microsoft.Network/networkSecurityGroups'
| mv-expand rules = properties.securityRules
| where rules.properties.direction =~ 'Inbound'
  and rules.properties.access =~ 'Allow'
  and rules.properties.sourceAddressPrefix =~ '*'
  and (rules.properties.destinationPortRange =~ '22' or rules.properties.destinationPortRange =~ '3389')
| project subscriptionId, resourceGroup, name, ruleName = rules.name, location
` + "```\n\n"

		lf.Contents += `### 5. Resources by Cost (requires Cost Management export)
` + "```kql" + `
Resources
| summarize ResourceCount = count() by type, subscriptionId
| order by ResourceCount desc
` + "```\n\n"

		lf.Contents += `### 6. Cross-Subscription Resource Dependencies
` + "```kql" + `
Resources
| extend dependsOn = properties.dependsOn
| where isnotnull(dependsOn)
| mv-expand dependency = dependsOn
| project sourceSubscription = subscriptionId, sourceResource = id, dependsOn = dependency
` + "```\n\n"

		lf.Contents += `## Execute Queries with Azure CLI

` + "```bash" + `
# Execute a Resource Graph query
az graph query -q "Resources | where type =~ 'Microsoft.Compute/virtualMachines' | limit 5"

# Query across specific subscriptions
az graph query -q "Resources | summarize count() by type" --subscriptions <sub-id-1> <sub-id-2>
` + "```\n"
	}
}

// ------------------------------
// Write output
// ------------------------------
func (m *ResourceGraphModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.InternetFacingRows) == 0 && len(m.UnencryptedRows) == 0 && len(m.UntaggedRows) == 0 &&
		len(m.CertificateExpiryRows) == 0 && len(m.RegionalComplianceRows) == 0 &&
		len(m.ResourceRelationshipsRows) == 0 && len(m.ResourceInventoryRows) == 0 {
		logger.InfoM("No Resource Graph query results found", globals.AZ_RESOURCE_GRAPH_MODULE_NAME)
		return
	}

	// Build tables
	tables := []internal.TableFile{}

	// Internet-facing resources table
	if len(m.InternetFacingRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name: "internet-facing-resources",
			Header: []string{
				"Tenant Name",
				"Tenant ID",
				"Subscription ID",
				"Resource Group",
				"Resource Name",
				"Resource Type",
				"Location",
				"Public IP",
				"Associated Resource",
				"Risk",
			},
			Body: m.InternetFacingRows,
		})
	}

	// Unencrypted resources table
	if len(m.UnencryptedRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name: "unencrypted-resources",
			Header: []string{
				"Tenant Name",
				"Tenant ID",
				"Subscription ID",
				"Resource Group",
				"Resource Name",
				"Resource Type",
				"Location",
				"Encryption Status",
				"Risk",
			},
			Body: m.UnencryptedRows,
		})
	}

	// Untagged resources table
	if len(m.UntaggedRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name: "untagged-resources",
			Header: []string{
				"Tenant Name",
				"Tenant ID",
				"Subscription ID",
				"Resource Group",
				"Resource Name",
				"Resource Type",
				"Location",
				"Tag Status",
				"Risk",
			},
			Body: m.UntaggedRows,
		})
	}

	// Certificate expiry table
	if len(m.CertificateExpiryRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name: "expiring-certificates",
			Header: []string{
				"Tenant Name",
				"Tenant ID",
				"Subscription ID",
				"Resource Group",
				"Resource Name",
				"Resource Type",
				"Location",
				"Certificate Expiry",
				"Days Until Expiry",
				"Risk",
			},
			Body: m.CertificateExpiryRows,
		})
	}

	// Regional compliance table
	if len(m.RegionalComplianceRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name: "regional-compliance",
			Header: []string{
				"Tenant Name",
				"Tenant ID",
				"Subscription ID",
				"Resource Group",
				"Resource Name",
				"Resource Type",
				"Location",
				"Compliance Status",
				"Risk",
			},
			Body: m.RegionalComplianceRows,
		})
	}

	// Resource relationships table
	if len(m.ResourceRelationshipsRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name: "resource-relationships",
			Header: []string{
				"Tenant Name",
				"Tenant ID",
				"Subscription ID",
				"Resource Group",
				"Resource Name",
				"Resource Type",
				"Related Resource 1",
				"Related Resource 2",
				"Relationship Type",
			},
			Body: m.ResourceRelationshipsRows,
		})
	}

	// Resource inventory table (sample)
	if len(m.ResourceInventoryRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name: "resource-inventory-sample",
			Header: []string{
				"Tenant Name",
				"Tenant ID",
				"Subscription ID",
				"Resource Group",
				"Resource Name",
				"Resource Type",
				"Location",
				"Tags",
				"Provisioning State",
			},
			Body: m.ResourceInventoryRows,
		})
	}

	// Build loot array
	loot := []internal.LootFile{}
	for _, lf := range m.LootMap {
		if lf.Contents != "" && !strings.HasSuffix(lf.Contents, "\n\n") {
			loot = append(loot, *lf)
		}
	}

	output := ResourceGraphOutput{
		Table: tables,
		Loot:  loot,
	}

	// Determine output scope
	scopeType, scopeIDs, scopeNames := azinternal.DetermineScopeForOutput(m.Subscriptions, m.TenantID, m.TenantName, m.TenantFlagPresent)
	scopeNames = azinternal.GetSubscriptionNamesForOutput(ctx, m.Session, scopeType, scopeIDs)

	// Write output
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_RESOURCE_GRAPH_MODULE_NAME)
		m.CommandCounter.Error++
	}

	totalRows := len(m.InternetFacingRows) + len(m.UnencryptedRows) + len(m.UntaggedRows) +
		len(m.CertificateExpiryRows) + len(m.RegionalComplianceRows) +
		len(m.ResourceRelationshipsRows) + len(m.ResourceInventoryRows)
	logger.SuccessM(fmt.Sprintf("Found %d resources across %d Resource Graph queries", totalRows, len(m.Subscriptions)), globals.AZ_RESOURCE_GRAPH_MODULE_NAME)
}
