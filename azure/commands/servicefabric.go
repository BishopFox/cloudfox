package commands

import (
	"context"
	"fmt"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/servicefabric/armservicefabric"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/BishopFox/cloudfox/internal/azure/sdk"
	"github.com/spf13/cobra"
)

// ------------------------------
// Cobra command
// ------------------------------
var AzServiceFabricCommand = &cobra.Command{
	Use:     "service-fabric",
	Aliases: []string{"servicefabric", "fabric"},
	Short:   "Enumerate Azure Service Fabric clusters",
	Long: `
Enumerate Azure Service Fabric clusters for a specific tenant:
  ./cloudfox az service-fabric --tenant TENANT_ID

Enumerate Azure Service Fabric clusters for a specific subscription:
  ./cloudfox az service-fabric --subscription SUBSCRIPTION_ID`,
	Run: ListServiceFabric,
}

// ------------------------------
// Module struct
// ------------------------------
type ServiceFabricModule struct {
	azinternal.BaseAzureModule

	Subscriptions     []string
	ServiceFabricRows [][]string
	LootMap           map[string]*internal.LootFile
	mu                sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type ServiceFabricOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o ServiceFabricOutput) TableFiles() []internal.TableFile { return o.Table }
func (o ServiceFabricOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point
// ------------------------------
func ListServiceFabric(cmd *cobra.Command, args []string) {
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_SERVICEFABRIC_MODULE_NAME)
	if err != nil {
		return
	}
	defer cmdCtx.Session.StopMonitoring()

	module := &ServiceFabricModule{
		BaseAzureModule:   azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:     cmdCtx.Subscriptions,
		ServiceFabricRows: [][]string{},
		LootMap: map[string]*internal.LootFile{
			"servicefabric-commands":     {Name: "servicefabric-commands", Contents: ""},
			"servicefabric-certificates": {Name: "servicefabric-certificates", Contents: ""},
		},
	}

	module.PrintServiceFabric(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method
// ------------------------------
func (m *ServiceFabricModule) PrintServiceFabric(ctx context.Context, logger internal.Logger) {
	if m.IsMultiTenant {
		for _, tenantCtx := range m.Tenants {
			savedTenantID := m.TenantID
			savedTenantName := m.TenantName
			savedTenantInfo := m.TenantInfo

			m.TenantID = tenantCtx.TenantID
			m.TenantName = tenantCtx.TenantName
			m.TenantInfo = tenantCtx.TenantInfo

			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_SERVICEFABRIC_MODULE_NAME, m.processSubscription)

			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_SERVICEFABRIC_MODULE_NAME, m.processSubscription)
	}
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *ServiceFabricModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)

	// Get resource groups
	rgs := sdk.CachedGetResourceGroupsPerSubscription(m.Session, subID)
	if len(rgs) == 0 {
		return
	}

	// Create Service Fabric client
	sfClient, err := azinternal.GetServiceFabricClient(m.Session, subID)
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to create Service Fabric client for subscription %s: %v", subID, err), globals.AZ_SERVICEFABRIC_MODULE_NAME)
		}
		m.CommandCounter.Error++
		return
	}

	// Process each resource group
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 10)

	for _, rg := range rgs {
		if rg.Name == nil {
			continue
		}
		rgName := *rg.Name

		wg.Add(1)
		go m.processResourceGroup(ctx, subID, subName, rgName, sfClient, &wg, semaphore, logger)
	}

	wg.Wait()
}

// ------------------------------
// Process single resource group
// ------------------------------
func (m *ServiceFabricModule) processResourceGroup(ctx context.Context, subID, subName, rgName string, sfClient *armservicefabric.ClustersClient, wg *sync.WaitGroup, semaphore chan struct{}, logger internal.Logger) {
	defer wg.Done()

	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	// Get region
	region := ""
	rgs := sdk.CachedGetResourceGroupsPerSubscription(m.Session, subID)
	for _, r := range rgs {
		if r.Name != nil && *r.Name == rgName && r.Location != nil {
			region = *r.Location
			break
		}
	}

	// List Service Fabric clusters in resource group
	resp, err := sfClient.ListByResourceGroup(ctx, rgName, nil)
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to list Service Fabric clusters in %s/%s: %v", subID, rgName, err), globals.AZ_SERVICEFABRIC_MODULE_NAME)
		}
		m.CommandCounter.Error++
		return
	}

	for _, cluster := range resp.Value {
		m.processCluster(ctx, subID, subName, rgName, region, cluster, logger)
	}
}

// ------------------------------
// Process single cluster
// ------------------------------
func (m *ServiceFabricModule) processCluster(ctx context.Context, subID, subName, rgName, region string, cluster *armservicefabric.Cluster, logger internal.Logger) {
	if cluster == nil || cluster.Name == nil {
		return
	}

	clusterName := *cluster.Name

	// Extract cluster properties
	managementEndpoint := "N/A"
	clusterEndpoint := "N/A"
	clusterState := "N/A"
	provisioningState := "N/A"
	reliabilityLevel := "N/A"
	clusterCodeVersion := "N/A"
	vmImage := "N/A"
	nodeTypeCount := 0

	if cluster.Properties != nil {
		if cluster.Properties.ManagementEndpoint != nil {
			managementEndpoint = *cluster.Properties.ManagementEndpoint
		}
		if cluster.Properties.ClusterEndpoint != nil {
			clusterEndpoint = *cluster.Properties.ClusterEndpoint
		}
		if cluster.Properties.ClusterState != nil {
			clusterState = string(*cluster.Properties.ClusterState)
		}
		if cluster.Properties.ProvisioningState != nil {
			provisioningState = string(*cluster.Properties.ProvisioningState)
		}
		if cluster.Properties.ReliabilityLevel != nil {
			reliabilityLevel = string(*cluster.Properties.ReliabilityLevel)
		}
		if cluster.Properties.ClusterCodeVersion != nil {
			clusterCodeVersion = *cluster.Properties.ClusterCodeVersion
		}
		if cluster.Properties.VMImage != nil {
			vmImage = *cluster.Properties.VMImage
		}
		if cluster.Properties.NodeTypes != nil {
			nodeTypeCount = len(cluster.Properties.NodeTypes)
		}
	}

	// AAD Authentication
	aadEnabled := "false"
	aadTenantID := "N/A"
	aadClusterAppID := "N/A"
	aadClientAppID := "N/A"

	if cluster.Properties != nil && cluster.Properties.AzureActiveDirectory != nil {
		aadEnabled = "true"
		if cluster.Properties.AzureActiveDirectory.TenantID != nil {
			aadTenantID = *cluster.Properties.AzureActiveDirectory.TenantID
		}
		if cluster.Properties.AzureActiveDirectory.ClusterApplication != nil {
			aadClusterAppID = *cluster.Properties.AzureActiveDirectory.ClusterApplication
		}
		if cluster.Properties.AzureActiveDirectory.ClientApplication != nil {
			aadClientAppID = *cluster.Properties.AzureActiveDirectory.ClientApplication
		}
	}

	// EntraID Centralized Auth
	entraIDAuth := "Disabled"
	if aadEnabled == "true" {
		entraIDAuth = "Enabled"
	}

	// Certificate information
	hasCertificate := "false"
	certificateThumbprint := "N/A"
	certificateThumbprintSecondary := "N/A"

	if cluster.Properties != nil && cluster.Properties.Certificate != nil {
		hasCertificate = "true"
		if cluster.Properties.Certificate.Thumbprint != nil {
			certificateThumbprint = *cluster.Properties.Certificate.Thumbprint
		}
		if cluster.Properties.Certificate.ThumbprintSecondary != nil {
			certificateThumbprintSecondary = *cluster.Properties.Certificate.ThumbprintSecondary
		}
	}

	// Client certificates
	clientCertCount := 0
	if cluster.Properties != nil {
		if cluster.Properties.ClientCertificateCommonNames != nil {
			clientCertCount += len(cluster.Properties.ClientCertificateCommonNames)
		}
		if cluster.Properties.ClientCertificateThumbprints != nil {
			clientCertCount += len(cluster.Properties.ClientCertificateThumbprints)
		}
	}

	// Reverse proxy certificate
	hasReverseProxyCert := "false"
	if cluster.Properties != nil && cluster.Properties.ReverseProxyCertificate != nil {
		hasReverseProxyCert = "true"
	}

	// Event store service
	eventStoreEnabled := "false"
	if cluster.Properties != nil && cluster.Properties.EventStoreServiceEnabled != nil && *cluster.Properties.EventStoreServiceEnabled {
		eventStoreEnabled = "true"
	}

	// Managed identities - Classic Service Fabric clusters don't support managed identities
	// (that's a feature of Service Fabric Managed Clusters, which is a separate service)
	systemAssignedID := "N/A"
	userAssignedID := "N/A"

	// Build row
	row := []string{
		m.TenantName,
		m.TenantID,
		subID,
		subName,
		rgName,
		region,
		clusterName,
		managementEndpoint,
		clusterEndpoint,
		clusterState,
		provisioningState,
		reliabilityLevel,
		fmt.Sprintf("%d", nodeTypeCount),
		clusterCodeVersion,
		vmImage,
		aadEnabled,
		entraIDAuth,
		aadTenantID,
		aadClusterAppID,
		aadClientAppID,
		hasCertificate,
		certificateThumbprint,
		certificateThumbprintSecondary,
		fmt.Sprintf("%d", clientCertCount),
		hasReverseProxyCert,
		eventStoreEnabled,
		systemAssignedID,
		userAssignedID,
	}

	m.mu.Lock()
	m.ServiceFabricRows = append(m.ServiceFabricRows, row)
	m.mu.Unlock()
	m.CommandCounter.Total++

	// Generate loot
	m.generateLoot(subID, subName, rgName, clusterName, managementEndpoint, hasCertificate, certificateThumbprint, certificateThumbprintSecondary, clientCertCount, cluster)
}

// ------------------------------
// Generate loot
// ------------------------------
func (m *ServiceFabricModule) generateLoot(subID, subName, rgName, clusterName, managementEndpoint, hasCertificate, certThumbprint, certThumbprintSecondary string, clientCertCount int, cluster *armservicefabric.Cluster) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Generate commands loot
	lf := m.LootMap["servicefabric-commands"]
	lf.Contents += fmt.Sprintf("## Service Fabric Cluster: %s (Resource Group: %s)\n", clusterName, rgName)
	lf.Contents += fmt.Sprintf("# Set subscription context\n")
	lf.Contents += fmt.Sprintf("az account set --subscription %s\n\n", subID)
	lf.Contents += fmt.Sprintf("# Show cluster details\n")
	lf.Contents += fmt.Sprintf("az sf cluster show --name %s --resource-group %s\n\n", clusterName, rgName)
	lf.Contents += fmt.Sprintf("# List cluster nodes\n")
	lf.Contents += fmt.Sprintf("az sf cluster node list --cluster-name %s --resource-group %s\n\n", clusterName, rgName)
	lf.Contents += fmt.Sprintf("# Show cluster health\n")
	lf.Contents += fmt.Sprintf("az sf cluster show --name %s --resource-group %s --query 'clusterState'\n\n", clusterName, rgName)
	lf.Contents += fmt.Sprintf("# Management endpoint: %s\n", managementEndpoint)
	lf.Contents += fmt.Sprintf("# Connect to cluster using Service Fabric Explorer\n")
	lf.Contents += fmt.Sprintf("# URL: %s/Explorer\n\n", managementEndpoint)
	lf.Contents += fmt.Sprintf("# PowerShell equivalent:\n")
	lf.Contents += fmt.Sprintf("Set-AzContext -SubscriptionId %s\n", subID)
	lf.Contents += fmt.Sprintf("Get-AzServiceFabricCluster -Name %s -ResourceGroupName %s\n\n", clusterName, rgName)
	lf.Contents += "---\n\n"

	// Generate certificate loot if certificates exist
	if hasCertificate == "true" || clientCertCount > 0 {
		certLoot := m.LootMap["servicefabric-certificates"]
		certLoot.Contents += fmt.Sprintf("## Service Fabric Cluster: %s (Resource Group: %s)\n", clusterName, rgName)

		if hasCertificate == "true" {
			certLoot.Contents += fmt.Sprintf("# Cluster Certificate (Node-to-Node Security)\n")
			certLoot.Contents += fmt.Sprintf("Primary Thumbprint: %s\n", certThumbprint)
			if certThumbprintSecondary != "N/A" {
				certLoot.Contents += fmt.Sprintf("Secondary Thumbprint: %s\n", certThumbprintSecondary)
			}
			certLoot.Contents += "\n"
		}

		if clientCertCount > 0 {
			certLoot.Contents += fmt.Sprintf("# Client Certificates (%d total)\n", clientCertCount)

			// List client certificates by common name
			if cluster.Properties != nil && cluster.Properties.ClientCertificateCommonNames != nil {
				for _, clientCert := range cluster.Properties.ClientCertificateCommonNames {
					if clientCert.CertificateCommonName != nil {
						certLoot.Contents += fmt.Sprintf("Common Name: %s", *clientCert.CertificateCommonName)
						if clientCert.CertificateIssuerThumbprint != nil {
							certLoot.Contents += fmt.Sprintf(" (Issuer: %s)", *clientCert.CertificateIssuerThumbprint)
						}
						if clientCert.IsAdmin != nil && *clientCert.IsAdmin {
							certLoot.Contents += " [ADMIN]"
						}
						certLoot.Contents += "\n"
					}
				}
			}

			// List client certificates by thumbprint
			if cluster.Properties != nil && cluster.Properties.ClientCertificateThumbprints != nil {
				for _, clientCert := range cluster.Properties.ClientCertificateThumbprints {
					if clientCert.CertificateThumbprint != nil {
						certLoot.Contents += fmt.Sprintf("Thumbprint: %s", *clientCert.CertificateThumbprint)
						if clientCert.IsAdmin != nil && *clientCert.IsAdmin {
							certLoot.Contents += " [ADMIN]"
						}
						certLoot.Contents += "\n"
					}
				}
			}
			certLoot.Contents += "\n"
		}

		certLoot.Contents += "---\n\n"
	}
}

// ------------------------------
// Write output
// ------------------------------
func (m *ServiceFabricModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.ServiceFabricRows) == 0 {
		logger.InfoM("No Azure Service Fabric clusters found", globals.AZ_SERVICEFABRIC_MODULE_NAME)
		return
	}

	// Build headers
	headers := []string{
		"Tenant Name",
		"Tenant ID",
		"Subscription ID",
		"Subscription Name",
		"Resource Group",
		"Region",
		"Cluster Name",
		"Management Endpoint",
		"Cluster Endpoint",
		"Cluster State",
		"Provisioning State",
		"Reliability Level",
		"Node Type Count",
		"Cluster Code Version",
		"VM Image",
		"AAD Enabled",
		"EntraID Centralized Auth",
		"AAD Tenant ID",
		"AAD Cluster App ID",
		"AAD Client App ID",
		"Has Certificate",
		"Certificate Thumbprint",
		"Certificate Thumbprint Secondary",
		"Client Certificate Count",
		"Has Reverse Proxy Cert",
		"Event Store Enabled",
		"System Assigned Identity ID",
		"User Assigned Identity ID",
	}

	// Check if we should split output by tenant
	if m.IsMultiTenant {
		if err := m.FilterAndWritePerTenantAuto(
			ctx, logger, m.Tenants, m.ServiceFabricRows, headers,
			"service-fabric", globals.AZ_SERVICEFABRIC_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Check if we should split output by subscription
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		if err := m.FilterAndWritePerSubscriptionAuto(
			ctx, logger, m.Subscriptions, m.ServiceFabricRows, headers,
			"service-fabric", globals.AZ_SERVICEFABRIC_MODULE_NAME,
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

	// Create output
	output := ServiceFabricOutput{
		Table: []internal.TableFile{{
			Name:   "service-fabric",
			Header: headers,
			Body:   m.ServiceFabricRows,
		}},
		Loot: loot,
	}

	// Determine output scope
	scopeType, scopeIDs, scopeNames := azinternal.DetermineScopeForOutput(m.Subscriptions, m.TenantID, m.TenantName, m.TenantFlagPresent)
	scopeNames = azinternal.GetSubscriptionNamesForOutput(ctx, m.Session, scopeType, scopeIDs)

	// Write output using HandleOutputSmart
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
		logger.ErrorM(fmt.Sprintf("Failed to write output: %v", err), globals.AZ_SERVICEFABRIC_MODULE_NAME)
		return
	}

	// Print summary
	logger.InfoM(fmt.Sprintf("Found %d Azure Service Fabric cluster(s) across %d subscription(s)", len(m.ServiceFabricRows), len(m.Subscriptions)), globals.AZ_SERVICEFABRIC_MODULE_NAME)
}
