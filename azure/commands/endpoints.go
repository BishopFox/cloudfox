package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appplatform/armappplatform"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cdn/armcdn"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cognitiveservices/armcognitiveservices"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerinstance/armcontainerinstance"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/databricks/armdatabricks"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/datafactory/armdatafactory"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/eventhub/armeventhub"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/hdinsight/armhdinsight"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/hybridcompute/armhybridcompute"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/iothub/armiothub"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/kusto/armkusto"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/redis/armredis"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/servicebus/armservicebus"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/servicefabric/armservicefabric"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/signalr/armsignalr"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/synapse/armsynapse"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/trafficmanager/armtrafficmanager"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/spf13/cobra"
)

// ------------------------------
// Cobra command
// ------------------------------
var AzEndpointsCommand = &cobra.Command{
	Use:     "endpoints",
	Aliases: []string{"eps"},
	Short:   "Enumerate all Azure endpoints (public/private IPs and hostnames)",
	Long: `
Enumerate Azure endpoints for a specific tenant:
./cloudfox az endpoints --tenant TENANT_ID

Enumerate Azure endpoints for a specific subscription:
./cloudfox az endpoints --subscription SUBSCRIPTION_ID[,SUBSCRIPTION_ID2,...]`,
	Run: ListEndpoints,
}

// ------------------------------
// Module struct (AWS pattern)
// ------------------------------
type EndpointsModule struct {
	azinternal.BaseAzureModule // Embed common fields (15 fields)

	// Module-specific fields - SPECIAL: endpoints has 3 types of rows
	Subscriptions  []string
	PublicRows     [][]string
	PrivateRows    [][]string
	DNSRows        [][]string
	PrivateDNSRows [][]string
	LootMap        map[string]*internal.LootFile
	mu             sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type EndpointsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o EndpointsOutput) TableFiles() []internal.TableFile { return o.Table }
func (o EndpointsOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point (thin wrapper)
// ------------------------------
func ListEndpoints(cmd *cobra.Command, args []string) {
	// -------------------- Use InitializeCommandContext helper --------------------
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_ENDPOINTS_MODULE_NAME)
	if err != nil {
		return // error already logged by helper
	}
	defer cmdCtx.Session.StopMonitoring()

	// -------------------- Initialize module --------------------
	module := &EndpointsModule{
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:   cmdCtx.Subscriptions,
		PublicRows:      [][]string{},
		PrivateRows:     [][]string{},
		DNSRows:         [][]string{},
		PrivateDNSRows:  [][]string{},
		LootMap: map[string]*internal.LootFile{
			"endpoints-commands": {Name: "endpoints-commands", Contents: ""},
		},
	}

	// -------------------- Execute module --------------------
	module.PrintEndpoints(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method (AWS-style)
// ------------------------------
func (m *EndpointsModule) PrintEndpoints(ctx context.Context, logger internal.Logger) {
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
			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_ENDPOINTS_MODULE_NAME, m.processSubscription)

			// Restore tenant context
			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		// Single-tenant mode
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_ENDPOINTS_MODULE_NAME, m.processSubscription)
	}

	// Generate and write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *EndpointsModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
	// Get subscription name
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)

	// Get resource groups (CACHED)
	resourceGroups := m.ResolveResourceGroups(subID)

	// Process resource groups concurrently for better performance
	var rgWg sync.WaitGroup
	rgSemaphore := make(chan struct{}, 10) // Limit to 10 concurrent RGs

	for _, rgName := range resourceGroups {
		rgWg.Add(1)
		go m.processResourceGroup(ctx, subID, subName, rgName, &rgWg, rgSemaphore, logger)
	}

	rgWg.Wait()
}

// ------------------------------
// Process single resource group (extracted for RG-level concurrency)
// ------------------------------
func (m *EndpointsModule) processResourceGroup(ctx context.Context, subID, subName, rgName string, wg *sync.WaitGroup, semaphore chan struct{}, logger internal.Logger) {
	defer wg.Done()

	// Acquire semaphore
	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	// Get region using helper function
	region := azinternal.GetResourceGroupLocation(m.Session, subID, rgName)

	// -------------------- VMs --------------------
	vms, _ := azinternal.GetVMsPerResourceGroupObject(m.Session, subID, rgName, m.LootMap, m.TenantName, m.TenantID)

	for _, vmRow := range vms {
		// VM row structure from vm_helpers.go GetComputeRelevantData():
		// [0]=subID, [1]=subName, [2]=rgName, [3]=location, [4]=vmName,
		// [5]=vmSize, [6]=tags, [7]=privateIPs, [8]=publicIPs, [9]=hostname,
		// [10]=adminUsername, [11]=vnetName, [12]=subnetCIDR, [13]=isBastion,
		// [14]=isEntraIDAuth, [15]=diskEncryption, [16]=epStatus,
		// [17]=systemAssignedID, [18]=userAssignedID
		name := vmRow[4]
		region := vmRow[3]
		privateIPs := strings.Split(vmRow[7], "\n") // Fixed: was vmRow[5] (vmSize)
		publicIPs := strings.Split(vmRow[8], "\n")  // Fixed: was vmRow[6] (tags)
		hostname := vmRow[9]                        // Fixed: was vmRow[7] (privateIPs)
		rgName := vmRow[2]

		for _, pip := range privateIPs {
			if pip != "" && pip != "NoPublicIP" {
				m.appendRow(&m.PrivateRows, subID, subName, rgName, region, name, "VirtualMachine", hostname, pip)
			}
		}

		for _, pubip := range publicIPs {
			if pubip != "" && pubip != "NoPublicIP" {
				m.appendRow(&m.PublicRows, subID, subName, rgName, region, name, "VirtualMachine", hostname, pubip)
			}
		}
	}

	// -------------------- VM Scale Sets (VMSS) --------------------
	vmssInstances, err := azinternal.GetVMScaleSetsForSubscription(m.Session, subID, []string{rgName})
	if err == nil && len(vmssInstances) > 0 {
		for _, vmss := range vmssInstances {
			name := fmt.Sprintf("%s (VMSS Instance %s)", vmss.ScaleSetName, vmss.InstanceID)
			hostname := vmss.ComputerName
			if hostname == "" {
				hostname = "N/A"
			}

			// VMSS instances typically have private IPs
			if vmss.PrivateIP != "" && vmss.PrivateIP != "N/A" {
				m.appendRow(&m.PrivateRows, subID, subName, vmss.ResourceGroup, vmss.Region, name, "VMSS", hostname, vmss.PrivateIP)
			}

			// Note: Public IPs for VMSS instances would be retrieved via network interfaces
			// This is a basic implementation that captures private IPs
			// For public IPs, VMSS instances typically use load balancers (captured in LoadBalancer section)
		}
	}

	// -------------------- WebApps --------------------
	webApps := azinternal.GetWebAppsPerRG(ctx, subID, m.LootMap, rgName)
	for _, appRow := range webApps {
		// WebApp row structure from webapp_helpers.go GetWebAppsPerRG():
		// [0]=subID, [1]=subName, [2]=rgName, [3]=location, [4]=appName,
		// [5]=appServicePlan, [6]=runtime, [7]=tags, [8]=privIP, [9]=pubIP,
		// [10]=vnetName, [11]=subnetName, [12]=dnsName, [13]=url,
		// [14]=sysRole, [15]=userRole, [16]=credentials, [17]=httpsOnly,
		// [18]=minTlsVersion, [19]=authEnabled
		name := appRow[4]
		region := appRow[3]
		privIP := appRow[8]    // Fixed: was appRow[5] (appServicePlan)
		pubIP := appRow[9]     // Fixed: was appRow[6] (runtime)
		hostname := appRow[12] // Fixed: was appRow[9] (pubIP) - using dnsName as hostname
		rgName := appRow[2]

		if hostname == "" {
			hostname = "N/A"
		}
		if privIP == "" {
			privIP = "N/A"
		}
		if pubIP == "" {
			pubIP = "N/A"
		}

		m.appendRow(&m.PrivateRows, subID, subName, rgName, region, name, "WebApp", hostname, privIP)
		m.appendRow(&m.PublicRows, subID, subName, rgName, region, name, "WebApp", hostname, pubIP)
	}

	// -------------------- Function Apps --------------------
	functionApps, err := azinternal.GetFunctionAppsPerResourceGroup(m.Session, subID, rgName)
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Could not enumerate Function Apps for resource group %s: %v", rgName, err), globals.AZ_ENDPOINTS_MODULE_NAME)
		}
		return
	}

	for _, app := range functionApps {
		if app == nil || app.Name == nil {
			continue
		}
		name := *app.Name
		hostname := "N/A"
		if app.Properties != nil && app.Properties.DefaultHostName != nil {
			hostname = *app.Properties.DefaultHostName
		}

		privateIPs, publicIPs, _, _ := azinternal.GetFunctionAppNetworkInfo(subID, rgName, app)

		if len(privateIPs) == 0 {
			privateIPs = []string{"N/A"}
		}
		if len(publicIPs) == 0 {
			publicIPs = []string{"N/A"}
		}

		for _, privIP := range privateIPs {
			for _, pubIP := range publicIPs {
				m.appendRow(&m.PrivateRows, subID, subName, rgName, region, name, "FunctionApp", hostname, privIP)
				m.appendRow(&m.PublicRows, subID, subName, rgName, region, name, "FunctionApp", hostname, pubIP)
			}
		}
	}

	// -------------------- Load Balancers --------------------
	lbs, err := azinternal.GetLoadBalancersPerResourceGroup(ctx, m.Session, subID, rgName)
	if err != nil && globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		logger.ErrorM(fmt.Sprintf("Could not enumerate Load Balancers: %v", err), globals.AZ_ENDPOINTS_MODULE_NAME)
	} else {
		for _, lb := range lbs {
			if lb == nil || lb.Name == nil {
				continue
			}

			name := azinternal.GetLoadBalancerName(lb)
			rgName := azinternal.GetLoadBalancerResourceGroup(lb)
			region := azinternal.GetLoadBalancerLocation(lb)

			for _, fe := range azinternal.GetLoadBalancerFrontendIPs(ctx, m.Session, lb) {
				m.appendRow(&m.PrivateRows, subID, subName, rgName, region, name, "LoadBalancer", fe.DNSName, fe.PrivateIP)
				m.appendRow(&m.PublicRows, subID, subName, rgName, region, name, "LoadBalancer", fe.DNSName, fe.PublicIP)
			}
		}
	}

	// -------------------- Application Gateways --------------------
	appGws := azinternal.GetAppGatewaysPerResourceGroup(m.Session, subID, rgName)
	for _, agw := range appGws {
		if agw == nil || agw.Name == nil {
			continue
		}

		name := azinternal.GetAppGatewayName(agw)
		rgName := azinternal.GetAppGatewayResourceGroup(agw)
		region := azinternal.GetAppGatewayLocation(agw)

		for _, fe := range azinternal.GetAppGatewayFrontendIPs(m.Session, subID, agw) {
			m.appendRow(&m.PrivateRows, subID, subName, rgName, region, name, "AppGateway", fe.DNSName, fe.PrivateIP)
			m.appendRow(&m.PublicRows, subID, subName, rgName, region, name, "AppGateway", fe.DNSName, fe.PublicIP)
		}
	}

	// -------------------- VPN / Virtual Network Gateways --------------------
	vpnGateways, err := azinternal.GetVPNGatewaysPerResourceGroup(ctx, m.Session, subID, rgName)
	if err != nil && globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		logger.ErrorM(fmt.Sprintf("Could not enumerate VPN Gateways: %v", err), globals.AZ_ENDPOINTS_MODULE_NAME)
	} else {
		for _, vpn := range vpnGateways {
			if vpn == nil || vpn.Name == nil {
				continue
			}

			name := azinternal.GetVPNGatewayName(vpn)
			rgName := azinternal.GetVPNGatewayResourceGroup(vpn)
			region := azinternal.GetVPNGatewayLocation(vpn)

			for _, ip := range azinternal.GetVPNGatewayIPs(ctx, m.Session, subID, vpn) {
				dnsName := ip.DNSName
				if dnsName == "" {
					dnsName = "N/A"
				}

				m.appendRow(&m.PrivateRows, subID, subName, rgName, region, name, "VpnGateway", dnsName, ip.PrivateIP)
				m.appendRow(&m.PublicRows, subID, subName, rgName, region, name, "VpnGateway", dnsName, ip.PublicIP)
			}
		}
	}

	// -------------------- Public IP Resources --------------------
	pubIPs, err := azinternal.GetPublicIPsPerRG(ctx, m.Session, subID, rgName)
	if err != nil && globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		logger.ErrorM(fmt.Sprintf("Could not enumerate Public IPs: %v", err), globals.AZ_ENDPOINTS_MODULE_NAME)
	} else {
		for _, pip := range pubIPs {
			name := azinternal.GetPublicIPName(pip)
			dns := azinternal.GetPublicIPDNS(pip)
			ipAddr := azinternal.GetPublicIPAddress(pip)
			region := azinternal.GetPublicIPLocation(pip)

			m.appendRow(&m.PublicRows, subID, subName, rgName, region, name, "PublicIP", dns, ipAddr)
		}
	}

	// -------------------- AKS Clusters --------------------
	clusters, err := azinternal.GetAKSClustersPerResourceGroup(ctx, m.Session, subID, rgName)
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to get AKS clusters: %v", err), globals.AZ_ENDPOINTS_MODULE_NAME)
		}
		return
	}

	for _, cluster := range clusters {
		clusterName := azinternal.GetAKSClusterName(cluster)
		publicFQDN, privateFQDN := azinternal.GetAKSClusterFQDNs(cluster)
		rgName := azinternal.GetResourceGroupFromID(*cluster.ID)
		region := azinternal.GetAKSClusterLocation(cluster)

		m.appendRow(&m.PrivateRows, subID, subName, rgName, region, clusterName, "AKS Cluster", privateFQDN, "N/A")
		m.appendRow(&m.PublicRows, subID, subName, rgName, region, clusterName, "AKS Cluster", publicFQDN, "N/A")
	}

	// -------------------- Databases --------------------
	dbRows := azinternal.GetDatabasesPerResourceGroup(ctx, m.Session, subID, subName, rgName, m.LootMap, region, m.TenantName, m.TenantID)
	for _, dbRow := range dbRows {
		if len(dbRow) < 11 {
			continue // Skip malformed rows
		}
		resName := dbRow[4]                      // Database Server endpoint
		dbType := dbRow[6]                       // DB Type (SQL Database, SQL Managed Instance, MySQL, etc.)
		region := dbRow[3]                       // Region
		privIPs := strings.Split(dbRow[9], "\n") // Private IPs (index 9, not 7)
		pubIPs := strings.Split(dbRow[10], "\n") // Public IPs (index 10, not 8)
		hostname := dbRow[4]                     // Hostname/endpoint
		rgName := dbRow[2]                       // Resource Group

		for _, pip := range privIPs {
			if pip != "" && pip != "N/A" {
				m.appendRow(&m.PrivateRows, subID, subName, rgName, region, resName, dbType, hostname, pip)
			}
		}
		for _, pubip := range pubIPs {
			if pubip != "" && pubip != "N/A" {
				m.appendRow(&m.PublicRows, subID, subName, rgName, region, resName, dbType, hostname, pubip)
			}
		}
	}

	// -------------------- Redis Cache --------------------
	token, err := m.Session.GetTokenForResource(globals.CommonScopes[0])
	if err == nil {
		cred := &azinternal.StaticTokenCredential{Token: token}
		redisClient, err := armredis.NewClient(subID, cred, nil)
		if err == nil {
			pager := redisClient.NewListByResourceGroupPager(rgName, nil)
			for pager.More() {
				page, err := pager.NextPage(ctx)
				if err != nil {
					continue
				}
				for _, cache := range page.Value {
					cacheName := azinternal.SafeStringPtr(cache.Name)
					endpoint := "N/A"
					if cache.Properties != nil && cache.Properties.HostName != nil {
						endpoint = *cache.Properties.HostName
					}

					// Determine public/private
					if cache.Properties != nil && cache.Properties.PublicNetworkAccess != nil {
						if *cache.Properties.PublicNetworkAccess == armredis.PublicNetworkAccessEnabled {
							m.appendRow(&m.PublicRows, subID, subName, rgName, region, cacheName, "Redis Cache", endpoint, "N/A")
						} else {
							m.appendRow(&m.PrivateRows, subID, subName, rgName, region, cacheName, "Redis Cache", endpoint, "N/A")
						}
					} else {
						// Default to public if not specified
						m.appendRow(&m.PublicRows, subID, subName, rgName, region, cacheName, "Redis Cache", endpoint, "N/A")
					}
				}
			}
		}
	}

	// -------------------- Synapse Analytics --------------------
	if token, err := m.Session.GetTokenForResource(globals.CommonScopes[0]); err == nil {
		cred := &azinternal.StaticTokenCredential{Token: token}
		synapseClient, err := armsynapse.NewWorkspacesClient(subID, cred, nil)
		if err == nil {
			pager := synapseClient.NewListByResourceGroupPager(rgName, nil)
			for pager.More() {
				page, err := pager.NextPage(ctx)
				if err != nil {
					continue
				}
				for _, workspace := range page.Value {
					workspaceName := azinternal.SafeStringPtr(workspace.Name)

					// Extract endpoints
					workspaceEndpoint := "N/A"
					sqlEndpoint := "N/A"
					if workspace.Properties != nil && workspace.Properties.ConnectivityEndpoints != nil {
						if workspace.Properties.ConnectivityEndpoints["web"] != nil {
							workspaceEndpoint = *workspace.Properties.ConnectivityEndpoints["web"]
						}
						if workspace.Properties.ConnectivityEndpoints["sql"] != nil {
							sqlEndpoint = *workspace.Properties.ConnectivityEndpoints["sql"]
						}
					}

					// Determine public/private
					if workspace.Properties != nil && workspace.Properties.PublicNetworkAccess != nil {
						if *workspace.Properties.PublicNetworkAccess == armsynapse.WorkspacePublicNetworkAccessEnabled {
							m.appendRow(&m.PublicRows, subID, subName, rgName, region, workspaceName, "Synapse Workspace", workspaceEndpoint, "N/A")
							if sqlEndpoint != "N/A" {
								m.appendRow(&m.PublicRows, subID, subName, rgName, region, workspaceName, "Synapse SQL Endpoint", sqlEndpoint, "N/A")
							}
						} else {
							m.appendRow(&m.PrivateRows, subID, subName, rgName, region, workspaceName, "Synapse Workspace", workspaceEndpoint, "N/A")
							if sqlEndpoint != "N/A" {
								m.appendRow(&m.PrivateRows, subID, subName, rgName, region, workspaceName, "Synapse SQL Endpoint", sqlEndpoint, "N/A")
							}
						}
					} else {
						// Default to public if not specified
						m.appendRow(&m.PublicRows, subID, subName, rgName, region, workspaceName, "Synapse Workspace", workspaceEndpoint, "N/A")
						if sqlEndpoint != "N/A" {
							m.appendRow(&m.PublicRows, subID, subName, rgName, region, workspaceName, "Synapse SQL Endpoint", sqlEndpoint, "N/A")
						}
					}
				}
			}
		}
	}

	// -------------------- Azure Databricks --------------------
	if token, err := m.Session.GetTokenForResource(globals.CommonScopes[0]); err == nil {
		cred := &azinternal.StaticTokenCredential{Token: token}
		databricksClient, err := armdatabricks.NewWorkspacesClient(subID, cred, nil)
		if err == nil {
			pager := databricksClient.NewListByResourceGroupPager(rgName, nil)
			for pager.More() {
				page, err := pager.NextPage(ctx)
				if err != nil {
					continue
				}
				for _, workspace := range page.Value {
					workspaceName := azinternal.SafeStringPtr(workspace.Name)

					// Extract workspace URL
					workspaceURL := "N/A"
					if workspace.Properties != nil && workspace.Properties.WorkspaceURL != nil {
						workspaceURL = fmt.Sprintf("https://%s", *workspace.Properties.WorkspaceURL)
					}

					// Determine public/private
					if workspace.Properties != nil && workspace.Properties.PublicNetworkAccess != nil {
						if *workspace.Properties.PublicNetworkAccess == armdatabricks.PublicNetworkAccessEnabled {
							m.appendRow(&m.PublicRows, subID, subName, rgName, region, workspaceName, "Databricks Workspace", workspaceURL, "N/A")
						} else {
							m.appendRow(&m.PrivateRows, subID, subName, rgName, region, workspaceName, "Databricks Workspace", workspaceURL, "N/A")
						}
					} else {
						// Default to public if not specified
						m.appendRow(&m.PublicRows, subID, subName, rgName, region, workspaceName, "Databricks Workspace", workspaceURL, "N/A")
					}
				}
			}
		}
	}

	// -------------------- API Management (APIM) --------------------
	if token, err := m.Session.GetTokenForResource(globals.CommonScopes[0]); err == nil {
		cred := &azinternal.StaticTokenCredential{Token: token}
		apimClient, err := armapimanagement.NewServiceClient(subID, cred, nil)
		if err == nil {
			pager := apimClient.NewListByResourceGroupPager(rgName, nil)
			for pager.More() {
				page, err := pager.NextPage(ctx)
				if err != nil {
					continue
				}
				for _, service := range page.Value {
					serviceName := azinternal.SafeStringPtr(service.Name)

					// Extract endpoints
					gatewayURL := "N/A"
					managementURL := "N/A"
					portalURL := "N/A"
					scmURL := "N/A"

					if service.Properties != nil {
						if service.Properties.GatewayURL != nil {
							gatewayURL = *service.Properties.GatewayURL
						}
						if service.Properties.ManagementAPIURL != nil {
							managementURL = *service.Properties.ManagementAPIURL
						}
						if service.Properties.PortalURL != nil {
							portalURL = *service.Properties.PortalURL
						}
						if service.Properties.ScmURL != nil {
							scmURL = *service.Properties.ScmURL
						}
					}

					// Determine public/private based on virtual network type
					publicPrivate := "Public"
					if service.Properties != nil && service.Properties.VirtualNetworkType != nil {
						vnType := *service.Properties.VirtualNetworkType
						if vnType == armapimanagement.VirtualNetworkTypeInternal {
							publicPrivate = "Private"
						} else if vnType == armapimanagement.VirtualNetworkTypeExternal {
							publicPrivate = "Public (External VNet)"
						}
					}

					// Add all endpoints
					if publicPrivate == "Private" {
						if gatewayURL != "N/A" {
							m.appendRow(&m.PrivateRows, subID, subName, rgName, region, serviceName, "API Management Gateway", gatewayURL, "N/A")
						}
						if managementURL != "N/A" {
							m.appendRow(&m.PrivateRows, subID, subName, rgName, region, serviceName, "API Management API", managementURL, "N/A")
						}
						if portalURL != "N/A" {
							m.appendRow(&m.PrivateRows, subID, subName, rgName, region, serviceName, "API Management Portal", portalURL, "N/A")
						}
						if scmURL != "N/A" {
							m.appendRow(&m.PrivateRows, subID, subName, rgName, region, serviceName, "API Management SCM", scmURL, "N/A")
						}
					} else {
						if gatewayURL != "N/A" {
							m.appendRow(&m.PublicRows, subID, subName, rgName, region, serviceName, "API Management Gateway", gatewayURL, "N/A")
						}
						if managementURL != "N/A" {
							m.appendRow(&m.PublicRows, subID, subName, rgName, region, serviceName, "API Management API", managementURL, "N/A")
						}
						if portalURL != "N/A" {
							m.appendRow(&m.PublicRows, subID, subName, rgName, region, serviceName, "API Management Portal", portalURL, "N/A")
						}
						if scmURL != "N/A" {
							m.appendRow(&m.PublicRows, subID, subName, rgName, region, serviceName, "API Management SCM", scmURL, "N/A")
						}
					}
				}
			}
		}
	}

	// -------------------- Azure Front Door --------------------
	if token, err := m.Session.GetTokenForResource(globals.CommonScopes[0]); err == nil {
		cred := &azinternal.StaticTokenCredential{Token: token}
		frontDoorClient, err := armfrontdoor.NewFrontDoorsClient(subID, cred, nil)
		if err == nil {
			pager := frontDoorClient.NewListByResourceGroupPager(rgName, nil)
			for pager.More() {
				page, err := pager.NextPage(ctx)
				if err != nil {
					continue
				}
				for _, fd := range page.Value {
					fdName := azinternal.SafeStringPtr(fd.Name)

					// Extract frontend endpoints
					if fd.Properties != nil && fd.Properties.FrontendEndpoints != nil {
						for _, frontend := range fd.Properties.FrontendEndpoints {
							if frontend.Properties != nil && frontend.Properties.HostName != nil {
								hostname := *frontend.Properties.HostName

								// Front Door is always public-facing (by design)
								m.appendRow(&m.PublicRows, subID, subName, rgName, region, fdName, "Front Door Frontend", hostname, "N/A")
							}
						}
					}

					// Extract backend pools (backend origins)
					if fd.Properties != nil && fd.Properties.BackendPools != nil {
						for _, pool := range fd.Properties.BackendPools {
							if pool.Properties != nil && pool.Properties.Backends != nil {
								poolName := azinternal.SafeStringPtr(pool.Name)
								for _, backend := range pool.Properties.Backends {
									if backend.Address != nil {
										backendAddr := *backend.Address
										// Backend pools are internal/private by nature
										m.appendRow(&m.PrivateRows, subID, subName, rgName, region, fdName, fmt.Sprintf("Front Door Backend Pool: %s", poolName), backendAddr, "N/A")
									}
								}
							}
						}
					}
				}
			}
		}
	}

	// -------------------- Azure CDN --------------------
	if token, err := m.Session.GetTokenForResource(globals.CommonScopes[0]); err == nil {
		cred := &azinternal.StaticTokenCredential{Token: token}
		cdnProfileClient, err := armcdn.NewProfilesClient(subID, cred, nil)
		if err == nil {
			profilePager := cdnProfileClient.NewListByResourceGroupPager(rgName, nil)
			for profilePager.More() {
				profilePage, err := profilePager.NextPage(ctx)
				if err != nil {
					continue
				}
				for _, profile := range profilePage.Value {
					profileName := azinternal.SafeStringPtr(profile.Name)

					// Enumerate endpoints within each CDN profile
					cdnEndpointClient, err := armcdn.NewEndpointsClient(subID, cred, nil)
					if err != nil {
						continue
					}

					endpointPager := cdnEndpointClient.NewListByProfilePager(rgName, profileName, nil)
					for endpointPager.More() {
						endpointPage, err := endpointPager.NextPage(ctx)
						if err != nil {
							continue
						}
						for _, endpoint := range endpointPage.Value {
							endpointName := azinternal.SafeStringPtr(endpoint.Name)
							hostname := "N/A"

							// Extract CDN endpoint hostname
							if endpoint.Properties != nil && endpoint.Properties.HostName != nil {
								hostname = *endpoint.Properties.HostName
							}

							// CDN endpoints are always public-facing (by design)
							m.appendRow(&m.PublicRows, subID, subName, rgName, region, profileName, "CDN Endpoint", hostname, "N/A")

							// Extract origin servers (backend origins)
							if endpoint.Properties != nil && endpoint.Properties.Origins != nil {
								for _, origin := range endpoint.Properties.Origins {
									originName := "unknown"
									if origin.Name != nil {
										originName = *origin.Name
									}
									originHost := "N/A"
									if origin.Properties != nil && origin.Properties.HostName != nil {
										originHost = *origin.Properties.HostName
									}

									// Origins are internal/private backends
									m.appendRow(&m.PrivateRows, subID, subName, rgName, region, profileName, fmt.Sprintf("CDN Origin: %s/%s", endpointName, originName), originHost, "N/A")
								}
							}
						}
					}
				}
			}
		}
	}

	// -------------------- Azure Firewall --------------------
	if token, err := m.Session.GetTokenForResource(globals.CommonScopes[0]); err == nil {
		cred := &azinternal.StaticTokenCredential{Token: token}
		firewallClient, err := armnetwork.NewAzureFirewallsClient(subID, cred, nil)
		if err == nil {
			pager := firewallClient.NewListPager(rgName, nil)
			for pager.More() {
				page, err := pager.NextPage(ctx)
				if err != nil {
					continue
				}
				for _, firewall := range page.Value {
					firewallName := azinternal.SafeStringPtr(firewall.Name)

					// Extract public IP addresses - FIXED: Get actual IP addresses and FQDNs
					// Create public IP client
					pubIPClient, err := azinternal.GetPublicIPClient(subID)
					hasPublicIP := false
					if err == nil && pubIPClient != nil && firewall.Properties != nil && firewall.Properties.IPConfigurations != nil {
						for _, ipConfig := range firewall.Properties.IPConfigurations {
							if ipConfig.Properties != nil && ipConfig.Properties.PublicIPAddress != nil && ipConfig.Properties.PublicIPAddress.ID != nil {
								// Extract public IP resource name from ID
								ipID := *ipConfig.Properties.PublicIPAddress.ID
								ipParts := strings.Split(ipID, "/")
								if len(ipParts) > 0 {
									publicIPName := ipParts[len(ipParts)-1]
									// Get actual public IP details
									pubIP, err := pubIPClient.Get(ctx, rgName, publicIPName, "")
									if err == nil && pubIP.PublicIPAddressPropertiesFormat != nil {
										hasPublicIP = true
										// Extract FQDN (hostname)
										hostname := firewallName // Default to firewall name if no FQDN
										if pubIP.PublicIPAddressPropertiesFormat.DNSSettings != nil && pubIP.PublicIPAddressPropertiesFormat.DNSSettings.Fqdn != nil {
											hostname = *pubIP.PublicIPAddressPropertiesFormat.DNSSettings.Fqdn
										}
										// Extract actual IP address
										ipAddress := "N/A"
										if pubIP.PublicIPAddressPropertiesFormat.IPAddress != nil {
											ipAddress = *pubIP.PublicIPAddressPropertiesFormat.IPAddress
										}
										// Add to public rows with actual hostname and IP
										m.appendRow(&m.PublicRows, subID, subName, rgName, region, firewallName, "Azure Firewall", hostname, ipAddress)
									}
								}
							}
						}
					}

					// Firewall without public IPs (internal only)
					if !hasPublicIP {
						m.appendRow(&m.PrivateRows, subID, subName, rgName, region, firewallName, "Azure Firewall", "N/A", "N/A")
					}
				}
			}
		}
	}

	// -------------------- Traffic Manager --------------------
	if token, err := m.Session.GetTokenForResource(globals.CommonScopes[0]); err == nil {
		cred := &azinternal.StaticTokenCredential{Token: token}
		tmClient, err := armtrafficmanager.NewProfilesClient(subID, cred, nil)
		if err == nil {
			pager := tmClient.NewListByResourceGroupPager(rgName, nil)
			for pager.More() {
				page, err := pager.NextPage(ctx)
				if err != nil {
					continue
				}
				for _, profile := range page.Value {
					profileName := azinternal.SafeStringPtr(profile.Name)

					// Extract DNS name (e.g., myprofile.trafficmanager.net)
					dnsName := "N/A"
					if profile.Properties != nil && profile.Properties.DNSConfig != nil && profile.Properties.DNSConfig.Fqdn != nil {
						dnsName = *profile.Properties.DNSConfig.Fqdn
					}

					// Traffic Manager DNS name is always public-facing
					m.appendRow(&m.PublicRows, subID, subName, rgName, region, profileName, "Traffic Manager Profile", dnsName, "N/A")

					// Extract endpoints (Azure, External, or Nested)
					if profile.Properties != nil && profile.Properties.Endpoints != nil {
						for _, endpoint := range profile.Properties.Endpoints {
							endpointName := azinternal.SafeStringPtr(endpoint.Name)
							endpointType := "Unknown"
							target := "N/A"

							if endpoint.Type != nil {
								// Type format: Microsoft.Network/trafficManagerProfiles/azureEndpoints
								typeParts := strings.Split(*endpoint.Type, "/")
								if len(typeParts) > 0 {
									endpointType = typeParts[len(typeParts)-1]
								}
							}

							if endpoint.Properties != nil && endpoint.Properties.Target != nil {
								target = *endpoint.Properties.Target
							}

							// Categorize based on endpoint type
							// External endpoints are public, Azure/Nested endpoints are typically private
							if endpointType == "externalEndpoints" {
								m.appendRow(&m.PublicRows, subID, subName, rgName, region, profileName, fmt.Sprintf("Traffic Manager Endpoint: %s (%s)", endpointName, endpointType), target, "N/A")
							} else {
								m.appendRow(&m.PrivateRows, subID, subName, rgName, region, profileName, fmt.Sprintf("Traffic Manager Endpoint: %s (%s)", endpointName, endpointType), target, "N/A")
							}
						}
					}
				}
			}
		}
	}

	// -------------------- Azure Bastion --------------------
	if token, err := m.Session.GetTokenForResource(globals.CommonScopes[0]); err == nil {
		cred := &azinternal.StaticTokenCredential{Token: token}
		bastionClient, err := armnetwork.NewBastionHostsClient(subID, cred, nil)
		if err == nil {
			pager := bastionClient.NewListByResourceGroupPager(rgName, nil)
			for pager.More() {
				page, err := pager.NextPage(ctx)
				if err != nil {
					continue
				}
				for _, bastion := range page.Value {
					bastionName := azinternal.SafeStringPtr(bastion.Name)

					// Extract public IP addresses - FIXED: Get actual IP addresses and FQDNs
					// Create public IP client
					pubIPClient, err := azinternal.GetPublicIPClient(subID)
					if err == nil && pubIPClient != nil && bastion.Properties != nil && bastion.Properties.IPConfigurations != nil {
						for _, ipConfig := range bastion.Properties.IPConfigurations {
							if ipConfig.Properties != nil && ipConfig.Properties.PublicIPAddress != nil && ipConfig.Properties.PublicIPAddress.ID != nil {
								// Extract public IP resource name from ID
								ipID := *ipConfig.Properties.PublicIPAddress.ID
								ipParts := strings.Split(ipID, "/")
								if len(ipParts) > 0 {
									publicIPName := ipParts[len(ipParts)-1]
									// Get actual public IP details
									pubIP, err := pubIPClient.Get(ctx, rgName, publicIPName, "")
									if err == nil && pubIP.PublicIPAddressPropertiesFormat != nil {
										// Extract FQDN (hostname)
										hostname := "N/A"
										if pubIP.PublicIPAddressPropertiesFormat.DNSSettings != nil && pubIP.PublicIPAddressPropertiesFormat.DNSSettings.Fqdn != nil {
											hostname = *pubIP.PublicIPAddressPropertiesFormat.DNSSettings.Fqdn
										}
										// Extract actual IP address
										ipAddress := "N/A"
										if pubIP.PublicIPAddressPropertiesFormat.IPAddress != nil {
											ipAddress = *pubIP.PublicIPAddressPropertiesFormat.IPAddress
										}
										// Add to public rows with actual hostname and IP
										m.appendRow(&m.PublicRows, subID, subName, rgName, region, bastionName, "Azure Bastion", hostname, ipAddress)
									}
								}
							}
						}
					}
				}
			}
		}
	}

	// -------------------- Event Hubs --------------------
	if token, err := m.Session.GetTokenForResource(globals.CommonScopes[0]); err == nil {
		cred := &azinternal.StaticTokenCredential{Token: token}
		ehFactory, err := armeventhub.NewClientFactory(subID, cred, nil)
		if err == nil {
			nsClient := ehFactory.NewNamespacesClient()
			pager := nsClient.NewListByResourceGroupPager(rgName, nil)
			for pager.More() {
				page, err := pager.NextPage(ctx)
				if err != nil {
					continue
				}
				for _, ns := range page.Value {
					namespaceName := azinternal.SafeStringPtr(ns.Name)

					// Extract service bus endpoint (e.g., mynamespace.servicebus.windows.net)
					endpoint := "N/A"
					if ns.Properties != nil && ns.Properties.ServiceBusEndpoint != nil {
						endpoint = *ns.Properties.ServiceBusEndpoint
						// Remove https:// prefix and trailing port if present
						endpoint = strings.TrimPrefix(endpoint, "https://")
						endpoint = strings.TrimSuffix(endpoint, ":443/")
						endpoint = strings.TrimSuffix(endpoint, "/")
					}

					// Event Hub namespaces are always public-facing (messaging service)
					m.appendRow(&m.PublicRows, subID, subName, rgName, region, namespaceName, "Event Hub Namespace", endpoint, "N/A")
				}
			}
		}
	}

	// -------------------- Service Bus --------------------
	if token, err := m.Session.GetTokenForResource(globals.CommonScopes[0]); err == nil {
		cred := &azinternal.StaticTokenCredential{Token: token}
		sbClient, err := armservicebus.NewNamespacesClient(subID, cred, nil)
		if err == nil {
			pager := sbClient.NewListByResourceGroupPager(rgName, nil)
			for pager.More() {
				page, err := pager.NextPage(ctx)
				if err != nil {
					continue
				}
				for _, ns := range page.Value {
					namespaceName := azinternal.SafeStringPtr(ns.Name)

					// Extract service bus endpoint (e.g., mynamespace.servicebus.windows.net)
					endpoint := "N/A"
					if ns.Properties != nil && ns.Properties.ServiceBusEndpoint != nil {
						endpoint = *ns.Properties.ServiceBusEndpoint
						// Remove https:// prefix and trailing port if present
						endpoint = strings.TrimPrefix(endpoint, "https://")
						endpoint = strings.TrimSuffix(endpoint, ":443/")
						endpoint = strings.TrimSuffix(endpoint, "/")
					}

					// Service Bus namespaces are always public-facing (messaging service)
					m.appendRow(&m.PublicRows, subID, subName, rgName, region, namespaceName, "Service Bus Namespace", endpoint, "N/A")
				}
			}
		}
	}

	// -------------------- IoT Hub --------------------
	if token, err := m.Session.GetTokenForResource(globals.CommonScopes[0]); err == nil {
		cred := &azinternal.StaticTokenCredential{Token: token}
		iotClient, err := armiothub.NewResourceClient(subID, cred, nil)
		if err == nil {
			pager := iotClient.NewListByResourceGroupPager(rgName, nil)
			for pager.More() {
				page, err := pager.NextPage(ctx)
				if err != nil {
					continue
				}
				for _, hub := range page.Value {
					hubName := azinternal.SafeStringPtr(hub.Name)
					hostname := "N/A"
					publicPrivate := "Public"

					if hub.Properties != nil {
						if hub.Properties.HostName != nil {
							hostname = *hub.Properties.HostName
						}

						// Determine public/private
						if hub.Properties.PublicNetworkAccess != nil {
							if *hub.Properties.PublicNetworkAccess == armiothub.PublicNetworkAccessEnabled {
								publicPrivate = "Public"
							} else {
								publicPrivate = "Private"
							}
						}
					}

					// IoT Hub endpoints are categorized based on PublicNetworkAccess
					if publicPrivate == "Public" {
						m.appendRow(&m.PublicRows, subID, subName, rgName, region, hubName, "IoT Hub", hostname, "N/A")
					} else {
						m.appendRow(&m.PrivateRows, subID, subName, rgName, region, hubName, "IoT Hub", hostname, "N/A")
					}
				}
			}
		}
	}

	// -------------------- Azure Container Instances (ACI) --------------------
	if token, err := m.Session.GetTokenForResource(globals.CommonScopes[0]); err == nil {
		cred := &azinternal.StaticTokenCredential{Token: token}
		aciClient, err := armcontainerinstance.NewContainerGroupsClient(subID, cred, nil)
		if err == nil {
			pager := aciClient.NewListByResourceGroupPager(rgName, nil)
			for pager.More() {
				page, err := pager.NextPage(ctx)
				if err != nil {
					continue
				}
				for _, cg := range page.Value {
					cgName := azinternal.SafeStringPtr(cg.Name)
					endpoint := "N/A"
					ip := "N/A"
					publicPrivate := "Private"

					if cg.Properties != nil && cg.Properties.IPAddress != nil {
						// Prefer FQDN over IP
						if cg.Properties.IPAddress.Fqdn != nil && *cg.Properties.IPAddress.Fqdn != "" {
							endpoint = *cg.Properties.IPAddress.Fqdn
						} else if cg.Properties.IPAddress.IP != nil {
							ip = *cg.Properties.IPAddress.IP
							endpoint = ip
						}

						// Determine public/private based on IP address type
						if cg.Properties.IPAddress.Type != nil {
							if *cg.Properties.IPAddress.Type == armcontainerinstance.ContainerGroupIPAddressTypePublic {
								publicPrivate = "Public"
							}
						}
					}

					// Container Instances are categorized based on IP address type
					if publicPrivate == "Public" {
						m.appendRow(&m.PublicRows, subID, subName, rgName, region, cgName, "Container Instance", endpoint, ip)
					} else {
						m.appendRow(&m.PrivateRows, subID, subName, rgName, region, cgName, "Container Instance", endpoint, ip)
					}
				}
			}
		}
	}

	// -------------------- Azure Arc Servers --------------------
	if token, err := m.Session.GetTokenForResource(globals.CommonScopes[0]); err == nil {
		cred := &azinternal.StaticTokenCredential{Token: token}
		arcClient, err := armhybridcompute.NewMachinesClient(subID, cred, nil)
		if err == nil {
			pager := arcClient.NewListByResourceGroupPager(rgName, nil)
			for pager.More() {
				page, err := pager.NextPage(ctx)
				if err != nil {
					continue
				}
				for _, machine := range page.Value {
					machineName := azinternal.SafeStringPtr(machine.Name)
					hostname := "N/A"
					privateIP := "N/A"

					// Extract hostname - prioritize FQDN to differentiate from Machine Name
					if machine.Properties != nil {
						if machine.Properties.MachineFqdn != nil && *machine.Properties.MachineFqdn != "" {
							hostname = *machine.Properties.MachineFqdn
						} else if machine.Properties.DNSFqdn != nil && *machine.Properties.DNSFqdn != "" {
							hostname = *machine.Properties.DNSFqdn
						} else if machine.Properties.OSProfile != nil && machine.Properties.OSProfile.ComputerName != nil {
							hostname = *machine.Properties.OSProfile.ComputerName
						}

						// Try to extract IP address from DetectedProperties
						// Azure Arc agents report IP addresses in detected properties
						if machine.Properties.DetectedProperties != nil {
							// Common property names used by Arc agents
							for _, key := range []string{"PrivateIPAddress", "privateIPAddress", "ipAddress", "IPAddress"} {
								if val, ok := machine.Properties.DetectedProperties[key]; ok && val != nil && *val != "" {
									privateIP = *val
									break
								}
							}
						}
					}

					// Arc servers are typically on-premises or private cloud, so categorize as private
					m.appendRow(&m.PrivateRows, subID, subName, rgName, region, machineName, "Arc Server", hostname, privateIP)
				}
			}
		} else if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Could not create Arc client: %v", err), globals.AZ_ENDPOINTS_MODULE_NAME)
		}
	}

	// -------------------- Azure Data Explorer (Kusto) --------------------
	if token, err := m.Session.GetTokenForResource(globals.CommonScopes[0]); err == nil {
		cred := &azinternal.StaticTokenCredential{Token: token}
		kustoClient, err := armkusto.NewClustersClient(subID, cred, nil)
		if err == nil {
			pager := kustoClient.NewListByResourceGroupPager(rgName, nil)
			for pager.More() {
				page, err := pager.NextPage(ctx)
				if err != nil {
					continue
				}
				for _, cluster := range page.Value {
					clusterName := azinternal.SafeStringPtr(cluster.Name)
					clusterURI := "N/A"
					dataIngestionURI := "N/A"

					if cluster.Properties != nil {
						if cluster.Properties.URI != nil {
							clusterURI = *cluster.Properties.URI
						}
						if cluster.Properties.DataIngestionURI != nil {
							dataIngestionURI = *cluster.Properties.DataIngestionURI
						}
					}

					// Determine public/private based on PublicNetworkAccess
					publicPrivate := "Public"
					if cluster.Properties != nil && cluster.Properties.PublicNetworkAccess != nil {
						if *cluster.Properties.PublicNetworkAccess == armkusto.PublicNetworkAccessDisabled {
							publicPrivate = "Private"
						}
					}

					// Add cluster URI
					if clusterURI != "N/A" {
						if publicPrivate == "Public" {
							m.appendRow(&m.PublicRows, subID, subName, rgName, region, clusterName, "Kusto Cluster", clusterURI, "N/A")
						} else {
							m.appendRow(&m.PrivateRows, subID, subName, rgName, region, clusterName, "Kusto Cluster", clusterURI, "N/A")
						}
					}

					// Add data ingestion URI
					if dataIngestionURI != "N/A" {
						if publicPrivate == "Public" {
							m.appendRow(&m.PublicRows, subID, subName, rgName, region, clusterName, "Kusto Data Ingestion", dataIngestionURI, "N/A")
						} else {
							m.appendRow(&m.PrivateRows, subID, subName, rgName, region, clusterName, "Kusto Data Ingestion", dataIngestionURI, "N/A")
						}
					}
				}
			}
		}
	}

	// -------------------- Azure Data Factory --------------------
	if token, err := m.Session.GetTokenForResource(globals.CommonScopes[0]); err == nil {
		cred := &azinternal.StaticTokenCredential{Token: token}
		dfClient, err := armdatafactory.NewFactoriesClient(subID, cred, nil)
		if err == nil {
			pager := dfClient.NewListByResourceGroupPager(rgName, nil)
			for pager.More() {
				page, err := pager.NextPage(ctx)
				if err != nil {
					continue
				}
				for _, factory := range page.Value {
					factoryName := azinternal.SafeStringPtr(factory.Name)

					// Construct management endpoint: {factoryName}.{region}.datafactory.azure.net
					managementEndpoint := "N/A"
					if factoryName != "" && region != "" {
						managementEndpoint = fmt.Sprintf("%s.%s.datafactory.azure.net", factoryName, region)
					}

					// Determine public/private based on PublicNetworkAccess
					publicPrivate := "Public"
					if factory.Properties != nil && factory.Properties.PublicNetworkAccess != nil {
						if *factory.Properties.PublicNetworkAccess == armdatafactory.PublicNetworkAccessDisabled {
							publicPrivate = "Private"
						}
					}

					// Add management endpoint
					if managementEndpoint != "N/A" {
						if publicPrivate == "Public" {
							m.appendRow(&m.PublicRows, subID, subName, rgName, region, factoryName, "Data Factory", managementEndpoint, "N/A")
						} else {
							m.appendRow(&m.PrivateRows, subID, subName, rgName, region, factoryName, "Data Factory", managementEndpoint, "N/A")
						}
					}
				}
			}
		}
	}

	// -------------------- Azure HDInsight --------------------
	if token, err := m.Session.GetTokenForResource(globals.CommonScopes[0]); err == nil {
		cred := &azinternal.StaticTokenCredential{Token: token}
		hdiClient, err := armhdinsight.NewClustersClient(subID, cred, nil)
		if err == nil {
			pager := hdiClient.NewListByResourceGroupPager(rgName, nil)
			for pager.More() {
				page, err := pager.NextPage(ctx)
				if err != nil {
					continue
				}
				for _, cluster := range page.Value {
					clusterName := azinternal.SafeStringPtr(cluster.Name)

					// Extract connectivity endpoints
					if cluster.Properties != nil && cluster.Properties.ConnectivityEndpoints != nil {
						for _, endpoint := range cluster.Properties.ConnectivityEndpoints {
							if endpoint.Name == nil {
								continue
							}
							endpointName := *endpoint.Name
							location := azinternal.SafeStringPtr(endpoint.Location)
							protocol := azinternal.SafeStringPtr(endpoint.Protocol)
							port := int32(22) // Default SSH port
							if endpoint.Port != nil {
								port = *endpoint.Port
							}

							endpointStr := fmt.Sprintf("%s://%s:%d", protocol, location, port)

							// Check if it has a private IP (internal endpoint)
							isPrivate := endpoint.PrivateIPAddress != nil && *endpoint.PrivateIPAddress != ""

							// Categorize endpoint type
							endpointType := "HDInsight Endpoint"
							if strings.Contains(strings.ToLower(endpointName), "ssh") {
								endpointType = "HDInsight SSH"
							} else if strings.Contains(strings.ToLower(endpointName), "https") || strings.Contains(strings.ToLower(endpointName), "gateway") {
								endpointType = "HDInsight HTTPS"
							}

							// Add to appropriate category
							if isPrivate {
								privateIP := *endpoint.PrivateIPAddress
								m.appendRow(&m.PrivateRows, subID, subName, rgName, region, clusterName, endpointType, endpointStr, privateIP)
							} else {
								// Public endpoint (no private IP)
								m.appendRow(&m.PublicRows, subID, subName, rgName, region, clusterName, endpointType, endpointStr, "N/A")
							}
						}
					}
				}
			}
		}
	}

	// -------------------- Azure DNS (Public) --------------------
	dnsRecords, err := azinternal.ListDNSRecordsPerResourceGroup(ctx, m.Session, subID, subName, rgName)
	if err != nil && globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		logger.ErrorM(fmt.Sprintf("Failed to get DNS records: %v", err), globals.AZ_ENDPOINTS_MODULE_NAME)
	} else {
		m.mu.Lock()
		for _, r := range dnsRecords {
			m.DNSRows = append(m.DNSRows, []string{
				m.TenantName,
				m.TenantID,
				r.SubscriptionID,
				r.SubscriptionName,
				r.ResourceGroup,
				r.Region,
				r.ZoneName,
				r.RecordType,
				r.RecordName,
				r.RecordValues,
			})
		}
		m.mu.Unlock()
	}

	// -------------------- Azure Private DNS --------------------
	privateDNSZones, err := azinternal.ListPrivateDNSZonesPerResourceGroup(ctx, m.Session, subID, subName, rgName)
	if err != nil && globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		logger.ErrorM(fmt.Sprintf("Failed to get Private DNS zones: %v", err), globals.AZ_ENDPOINTS_MODULE_NAME)
	} else {
		m.mu.Lock()
		for _, z := range privateDNSZones {
			m.PrivateDNSRows = append(m.PrivateDNSRows, []string{
				m.TenantName,
				m.TenantID,
				z.SubscriptionID,
				z.SubscriptionName,
				z.ResourceGroup,
				z.Region,
				z.ZoneName,
				z.RecordCount,
				z.VNetLinks,
				z.AutoRegistration,
				z.ProvisioningState,
			})
		}
		m.mu.Unlock()
	}

	// -------------------- Cognitive Services (Azure OpenAI) --------------------
	if token, err := m.Session.GetTokenForResource(globals.CommonScopes[0]); err == nil {
		cred := &azinternal.StaticTokenCredential{Token: token}
		cogClient, err := armcognitiveservices.NewAccountsClient(subID, cred, nil)
		if err == nil {
			// List Cognitive Services accounts in resource group
			cogPager := cogClient.NewListByResourceGroupPager(rgName, nil)
			for cogPager.More() {
				cogPage, err := cogPager.NextPage(ctx)
				if err != nil {
					if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
						logger.ErrorM(fmt.Sprintf("Failed to list Cognitive Services in %s/%s: %v", subID, rgName, err), globals.AZ_ENDPOINTS_MODULE_NAME)
					}
					m.CommandCounter.Error++
					continue
				}

				for _, account := range cogPage.Value {
					if account == nil || account.Name == nil {
						continue
					}

					accountName := *account.Name

					// Extract endpoint
					endpoint := "N/A"
					if account.Properties != nil && account.Properties.Endpoint != nil {
						endpoint = *account.Properties.Endpoint
					}

					// Determine if public or private
					publicPrivate := "Public"
					if account.Properties != nil && account.Properties.PublicNetworkAccess != nil {
						if *account.Properties.PublicNetworkAccess == armcognitiveservices.PublicNetworkAccessDisabled {
							publicPrivate = "Private"
						}
					}

					// Determine service kind (OpenAI, ComputerVision, SpeechServices, etc.)
					serviceKind := "Cognitive Services"
					if account.Kind != nil {
						serviceKind = *account.Kind
						// Capitalize first letter for consistency
						if len(serviceKind) > 0 {
							serviceKind = strings.ToUpper(serviceKind[:1]) + serviceKind[1:]
						}
					}

					// Add endpoint if available
					if endpoint != "N/A" && endpoint != "" {
						if publicPrivate == "Public" {
							m.appendRow(&m.PublicRows, subID, subName, rgName, region, accountName, serviceKind, endpoint, "N/A")
						} else {
							m.appendRow(&m.PrivateRows, subID, subName, rgName, region, accountName, serviceKind, endpoint, "N/A")
						}
					}

					m.CommandCounter.Total++
				}
			}
		}
	}

	// -------------------- Azure Spring Apps --------------------
	if token, err := m.Session.GetTokenForResource(globals.CommonScopes[0]); err == nil {
		cred := &azinternal.StaticTokenCredential{Token: token}
		springClient, err := armappplatform.NewServicesClient(subID, cred, nil)
		if err == nil {
			springPager := springClient.NewListPager(rgName, nil)
			for springPager.More() {
				springPage, err := springPager.NextPage(ctx)
				if err != nil {
					if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
						logger.ErrorM(fmt.Sprintf("Failed to list Spring Apps in %s/%s: %v", subID, rgName, err), globals.AZ_ENDPOINTS_MODULE_NAME)
					}
					m.CommandCounter.Error++
					continue
				}

				for _, service := range springPage.Value {
					if service == nil || service.Name == nil {
						continue
					}

					serviceName := *service.Name
					fqdn := "N/A"
					vnetInjected := "Public"

					if service.Properties != nil {
						if service.Properties.Fqdn != nil {
							fqdn = *service.Properties.Fqdn
						}
						// Determine public/private based on VNet injection
						if service.Properties.NetworkProfile != nil && service.Properties.NetworkProfile.AppSubnetID != nil && *service.Properties.NetworkProfile.AppSubnetID != "" {
							vnetInjected = "Private"
						}
					}

					// Add Spring Apps service endpoint
					if fqdn != "N/A" && fqdn != "" {
						if vnetInjected == "Public" {
							m.appendRow(&m.PublicRows, subID, subName, rgName, region, serviceName, "Spring Apps Service", fqdn, "N/A")
						} else {
							m.appendRow(&m.PrivateRows, subID, subName, rgName, region, serviceName, "Spring Apps Service", fqdn, "N/A")
						}
					}

					m.CommandCounter.Total++
				}
			}
		}
	}

	// -------------------- Azure SignalR Service --------------------
	if token, err := m.Session.GetTokenForResource(globals.CommonScopes[0]); err == nil {
		cred := &azinternal.StaticTokenCredential{Token: token}
		signalrClient, err := armsignalr.NewClient(subID, cred, nil)
		if err == nil {
			signalrPager := signalrClient.NewListByResourceGroupPager(rgName, nil)
			for signalrPager.More() {
				signalrPage, err := signalrPager.NextPage(ctx)
				if err != nil {
					if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
						logger.ErrorM(fmt.Sprintf("Failed to list SignalR in %s/%s: %v", subID, rgName, err), globals.AZ_ENDPOINTS_MODULE_NAME)
					}
					m.CommandCounter.Error++
					continue
				}

				for _, signalr := range signalrPage.Value {
					if signalr == nil || signalr.Name == nil {
						continue
					}

					signalrName := *signalr.Name
					hostname := "N/A"
					externalIP := "N/A"
					isPublic := true

					if signalr.Properties != nil {
						if signalr.Properties.HostName != nil {
							hostname = *signalr.Properties.HostName
						}
						if signalr.Properties.ExternalIP != nil {
							externalIP = *signalr.Properties.ExternalIP
						}
						// Determine public/private based on PublicNetworkAccess
						if signalr.Properties.PublicNetworkAccess != nil && *signalr.Properties.PublicNetworkAccess == "Disabled" {
							isPublic = false
						}
					}

					// Add SignalR service endpoint
					if hostname != "N/A" && hostname != "" {
						if isPublic {
							m.appendRow(&m.PublicRows, subID, subName, rgName, region, signalrName, "SignalR Service", hostname, externalIP)
						} else {
							m.appendRow(&m.PrivateRows, subID, subName, rgName, region, signalrName, "SignalR Service", hostname, externalIP)
						}
					}

					m.CommandCounter.Total++
				}
			}
		}
	}

	// -------------------- Azure Service Fabric Clusters --------------------
	if token, err := m.Session.GetTokenForResource(globals.CommonScopes[0]); err == nil {
		cred := &azinternal.StaticTokenCredential{Token: token}
		sfClient, err := armservicefabric.NewClustersClient(subID, cred, nil)
		if err == nil {
			sfResp, err := sfClient.ListByResourceGroup(ctx, rgName, nil)
			if err != nil {
				if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
					logger.ErrorM(fmt.Sprintf("Failed to list Service Fabric clusters in %s/%s: %v", subID, rgName, err), globals.AZ_ENDPOINTS_MODULE_NAME)
				}
				m.CommandCounter.Error++
			} else {
				for _, cluster := range sfResp.Value {
					if cluster == nil || cluster.Name == nil {
						continue
					}

					clusterName := *cluster.Name
					managementEndpoint := "N/A"

					if cluster.Properties != nil && cluster.Properties.ManagementEndpoint != nil {
						managementEndpoint = *cluster.Properties.ManagementEndpoint
					}

					// Service Fabric clusters are typically public by default
					// Management endpoint format: https://{cluster-name}.{region}.cloudapp.azure.com:19080
					if managementEndpoint != "N/A" && managementEndpoint != "" {
						m.appendRow(&m.PublicRows, subID, subName, rgName, region, clusterName, "Service Fabric Cluster", managementEndpoint, "N/A")
					}

					m.CommandCounter.Total++
				}
			}
		}
	}
}

// ------------------------------
// Thread-safe row append helper
// ------------------------------
func (m *EndpointsModule) appendRow(rows *[][]string, subID, subName, rgName, region, name, resType, hostname, ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	*rows = append(*rows, []string{
		m.TenantName,
		m.TenantID,
		subID,
		subName,
		rgName,
		region,
		name,
		resType,
		hostname,
		ip,
	})
}

// ------------------------------
// Write output (AWS-style writeLoot pattern)
// ------------------------------
func (m *EndpointsModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Dedupe rows before output
	m.PublicRows = m.dedupeRows(m.PublicRows)
	m.PrivateRows = m.dedupeRows(m.PrivateRows)

	// Filter out private rows where both Hostname and Private IP are blank/N/A
	m.PrivateRows = m.filterPrivateRows(m.PrivateRows)

	if len(m.PublicRows) == 0 && len(m.PrivateRows) == 0 && len(m.DNSRows) == 0 && len(m.PrivateDNSRows) == 0 {
		logger.InfoM("No Endpoints found", globals.AZ_ENDPOINTS_MODULE_NAME)
		return
	}

	// Define headers for all tables
	publicHeader := []string{"Tenant Name", "Tenant ID", "Subscription ID", "Subscription Name", "Resource Group", "Region", "Resource Name", "Resource Type", "Hostname", "Public IP"}
	privateHeader := []string{"Tenant Name", "Tenant ID", "Subscription ID", "Subscription Name", "Resource Group", "Region", "Resource Name", "Resource Type", "Hostname", "Private IP"}
	dnsHeader := []string{"Tenant Name", "Tenant ID", "Subscription ID", "Subscription Name", "Resource Group", "Region", "Zone Name", "Record Type", "Record Name", "Record Values"}
	privateDNSHeader := []string{"Tenant Name", "Tenant ID", "Subscription ID", "Subscription Name", "Resource Group", "Region", "Zone Name", "Record Count", "VNet Links", "Auto Registration", "Provisioning State"}

	// Check if we should split output by tenant (takes precedence over subscription split)
	if azinternal.ShouldSplitByTenant(m.IsMultiTenant, m.Tenants) {
		if err := m.writePerTenant(ctx, logger, publicHeader, privateHeader, dnsHeader, privateDNSHeader); err != nil {
			return
		}
		return
	}

	// Check if we should split output by subscription
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		if err := m.writePerSubscription(ctx, logger, publicHeader, privateHeader, dnsHeader, privateDNSHeader); err != nil {
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

	// Create output with all tables (consolidated)
	output := EndpointsOutput{
		Table: []internal.TableFile{
			{Name: "endpoints-public", Header: publicHeader, Body: m.PublicRows},
			{Name: "endpoints-private", Header: privateHeader, Body: m.PrivateRows},
			{Name: "endpoints-dns", Header: dnsHeader, Body: m.DNSRows},
			{Name: "endpoints-privatedns", Header: privateDNSHeader, Body: m.PrivateDNSRows},
		},
		Loot: loot,
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_ENDPOINTS_MODULE_NAME)
		m.CommandCounter.Error++
	}

	logger.SuccessM(fmt.Sprintf("Found %d public endpoint(s), %d private endpoint(s), %d DNS record(s), %d Private DNS zone(s) across %d subscription(s)",
		len(m.PublicRows), len(m.PrivateRows), len(m.DNSRows), len(m.PrivateDNSRows), len(m.Subscriptions)), globals.AZ_ENDPOINTS_MODULE_NAME)
}

// ------------------------------
// Dedupe helper
// ------------------------------
func (m *EndpointsModule) dedupeRows(rows [][]string) [][]string {
	seen := make(map[string]bool)
	var result [][]string

	for _, row := range rows {
		key := strings.Join(row, "|")
		if !seen[key] {
			seen[key] = true
			result = append(result, row)
		}
	}
	return result
}

// ------------------------------
// Filter private rows helper - removes rows where both Hostname and Private IP are blank/N/A
// ------------------------------
func (m *EndpointsModule) filterPrivateRows(rows [][]string) [][]string {
	var result [][]string

	for _, row := range rows {
		// Row structure: [tenantName, tenantID, subID, subName, rgName, region, name, resType, hostname, ip]
		// Index 8 = Hostname, Index 9 = Private IP
		if len(row) < 10 {
			// Keep malformed rows (shouldn't happen but defensive)
			result = append(result, row)
			continue
		}

		hostname := row[8]
		privateIP := row[9]

		// Check if both hostname and private IP are blank or N/A
		hostnameEmpty := hostname == "" || hostname == "N/A"
		privateIPEmpty := privateIP == "" || privateIP == "N/A"

		// Only keep rows where at least one of hostname or private IP has a valid value
		if !hostnameEmpty || !privateIPEmpty {
			result = append(result, row)
		}
	}
	return result
}

// ------------------------------
// Write output per tenant for multi-table output
// ------------------------------
func (m *EndpointsModule) writePerTenant(ctx context.Context, logger internal.Logger, publicHeader, privateHeader, dnsHeader, privateDNSHeader []string) error {
	var lastErr error
	tenantColumnIndex := 0 // "Tenant Name" is at column 0 in all tables

	for _, tenantCtx := range m.Tenants {
		// Filter all row types for this tenant
		filteredPublic := m.filterRowsByTenant(m.PublicRows, tenantColumnIndex, tenantCtx.TenantName, tenantCtx.TenantID)
		filteredPrivate := m.filterRowsByTenant(m.PrivateRows, tenantColumnIndex, tenantCtx.TenantName, tenantCtx.TenantID)
		filteredDNS := m.filterRowsByTenant(m.DNSRows, tenantColumnIndex, tenantCtx.TenantName, tenantCtx.TenantID)
		filteredPrivateDNS := m.filterRowsByTenant(m.PrivateDNSRows, tenantColumnIndex, tenantCtx.TenantName, tenantCtx.TenantID)

		// Skip if no data for this tenant
		if len(filteredPublic) == 0 && len(filteredPrivate) == 0 && len(filteredDNS) == 0 && len(filteredPrivateDNS) == 0 {
			continue
		}

		// Build loot array
		loot := []internal.LootFile{}
		for _, lf := range m.LootMap {
			if lf.Contents != "" {
				loot = append(loot, *lf)
			}
		}

		// Create output with all tables (only include non-empty tables)
		tables := []internal.TableFile{}
		if len(filteredPublic) > 0 {
			tables = append(tables, internal.TableFile{Name: "endpoints-public", Header: publicHeader, Body: filteredPublic})
		}
		if len(filteredPrivate) > 0 {
			tables = append(tables, internal.TableFile{Name: "endpoints-private", Header: privateHeader, Body: filteredPrivate})
		}
		if len(filteredDNS) > 0 {
			tables = append(tables, internal.TableFile{Name: "endpoints-dns", Header: dnsHeader, Body: filteredDNS})
		}
		if len(filteredPrivateDNS) > 0 {
			tables = append(tables, internal.TableFile{Name: "endpoints-privatedns", Header: privateDNSHeader, Body: filteredPrivateDNS})
		}

		output := EndpointsOutput{
			Table: tables,
			Loot:  loot,
		}

		// Determine scope for this single tenant
		scopeType := "tenant"
		scopeIDs := []string{tenantCtx.TenantID}
		scopeNames := []string{tenantCtx.TenantName}

		// Write output for this tenant
		if err := internal.HandleOutputSmart("Azure", m.Format, m.OutputDirectory, m.Verbosity, m.WrapTable,
			scopeType, scopeIDs, scopeNames, m.UserUPN, output); err != nil {
			logger.ErrorM(fmt.Sprintf("Error writing output for tenant %s: %v", tenantCtx.TenantName, err), globals.AZ_ENDPOINTS_MODULE_NAME)
			m.CommandCounter.Error++
			lastErr = err
		}
	}

	return lastErr
}

// ------------------------------
// Write output per subscription for multi-table output
// ------------------------------
func (m *EndpointsModule) writePerSubscription(ctx context.Context, logger internal.Logger, publicHeader, privateHeader, dnsHeader, privateDNSHeader []string) error {
	var lastErr error
	subscriptionColumnIndex := 3 // "Subscription Name" is at column 3 in all tables (shifted by +2 for tenant columns)

	for _, subID := range m.Subscriptions {
		subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)

		// Filter all row types for this subscription
		filteredPublic := m.filterRowsBySubscription(m.PublicRows, subscriptionColumnIndex, subName, subID)
		filteredPrivate := m.filterRowsBySubscription(m.PrivateRows, subscriptionColumnIndex, subName, subID)
		filteredDNS := m.filterRowsBySubscription(m.DNSRows, subscriptionColumnIndex, subName, subID)
		filteredPrivateDNS := m.filterRowsBySubscription(m.PrivateDNSRows, subscriptionColumnIndex, subName, subID)

		// Skip if no data for this subscription
		if len(filteredPublic) == 0 && len(filteredPrivate) == 0 && len(filteredDNS) == 0 && len(filteredPrivateDNS) == 0 {
			continue
		}

		// Build loot array
		loot := []internal.LootFile{}
		for _, lf := range m.LootMap {
			if lf.Contents != "" {
				loot = append(loot, *lf)
			}
		}

		// Create output with all tables (only include non-empty tables)
		tables := []internal.TableFile{}
		if len(filteredPublic) > 0 {
			tables = append(tables, internal.TableFile{Name: "endpoints-public", Header: publicHeader, Body: filteredPublic})
		}
		if len(filteredPrivate) > 0 {
			tables = append(tables, internal.TableFile{Name: "endpoints-private", Header: privateHeader, Body: filteredPrivate})
		}
		if len(filteredDNS) > 0 {
			tables = append(tables, internal.TableFile{Name: "endpoints-dns", Header: dnsHeader, Body: filteredDNS})
		}
		if len(filteredPrivateDNS) > 0 {
			tables = append(tables, internal.TableFile{Name: "endpoints-privatedns", Header: privateDNSHeader, Body: filteredPrivateDNS})
		}

		output := EndpointsOutput{
			Table: tables,
			Loot:  loot,
		}

		// Determine scope for this single subscription
		scopeType, scopeIDs, scopeNames := azinternal.DetermineScopeForOutput([]string{subID}, m.TenantID, m.TenantName, false)
		scopeNames = azinternal.GetSubscriptionNamesForOutput(ctx, m.Session, scopeType, scopeIDs)

		// Write output for this subscription
		if err := internal.HandleOutputSmart("Azure", m.Format, m.OutputDirectory, m.Verbosity, m.WrapTable,
			scopeType, scopeIDs, scopeNames, m.UserUPN, output); err != nil {
			logger.ErrorM(fmt.Sprintf("Error writing output for subscription %s: %v", subName, err), globals.AZ_ENDPOINTS_MODULE_NAME)
			m.CommandCounter.Error++
			lastErr = err
		}
	}

	return lastErr
}

// ------------------------------
// Filter rows by tenant
// ------------------------------
func (m *EndpointsModule) filterRowsByTenant(rows [][]string, columnIndex int, tenantName, tenantID string) [][]string {
	var filtered [][]string
	for _, row := range rows {
		if len(row) > columnIndex {
			if row[columnIndex] == tenantName || row[columnIndex] == tenantID {
				filtered = append(filtered, row)
			}
		}
	}
	return filtered
}

// ------------------------------
// Filter rows by subscription
// ------------------------------
func (m *EndpointsModule) filterRowsBySubscription(rows [][]string, columnIndex int, subName, subID string) [][]string {
	var filtered [][]string
	for _, row := range rows {
		if len(row) > columnIndex {
			if row[columnIndex] == subName || row[columnIndex] == subID {
				filtered = append(filtered, row)
			}
		}
	}
	return filtered
}
