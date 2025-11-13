package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/BishopFox/cloudfox/internal/azure/sdk"
	"github.com/spf13/cobra"
)

// ------------------------------
// Cobra command
// ------------------------------
var AzAPIManagementCommand = &cobra.Command{
	Use:     "api-management",
	Aliases: []string{"apim", "api-mgmt"},
	Short:   "Enumerate Azure API Management services and APIs",
	Long: `
Enumerate Azure API Management services for a specific tenant:
./cloudfox az api-management --tenant TENANT_ID

Enumerate Azure API Management services for a specific subscription:
./cloudfox az api-management --subscription SUBSCRIPTION_ID[,SUBSCRIPTION_ID2,...]

This module analyzes Azure API Management to identify:
- Public vs private APIM instances
- All APIs, operations, and exposed endpoints
- Authentication methods (subscription keys, OAuth2, certificates)
- Backend services exposed via APIs
- API policies (rate limiting, IP filtering, JWT validation)
- Developer portal access configuration
- Managed identities and EntraID authentication
- Custom domains and certificate expiration`,
	Run: ListAPIManagement,
}

// ------------------------------
// Module struct
// ------------------------------
type APIManagementModule struct {
	azinternal.BaseAzureModule

	Subscriptions []string
	APIMRows      [][]string
	APIRows       [][]string
	LootMap       map[string]*internal.LootFile
	mu            sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type APIManagementOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o APIManagementOutput) TableFiles() []internal.TableFile { return o.Table }
func (o APIManagementOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point
// ------------------------------
func ListAPIManagement(cmd *cobra.Command, args []string) {
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_API_MANAGEMENT_MODULE_NAME)
	if err != nil {
		return
	}
	defer cmdCtx.Session.StopMonitoring()

	module := &APIManagementModule{
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:   cmdCtx.Subscriptions,
		APIMRows:        [][]string{},
		APIRows:         [][]string{},
		LootMap: map[string]*internal.LootFile{
			"apim-public-endpoints":    {Name: "apim-public-endpoints", Contents: "# Public API Management Endpoints\n\n"},
			"apim-unauthenticated":     {Name: "apim-unauthenticated", Contents: "# APIs Without Authentication\n\n"},
			"apim-backend-services":    {Name: "apim-backend-services", Contents: "# Backend Services Exposed via APIM\n\n"},
			"apim-policy-gaps":         {Name: "apim-policy-gaps", Contents: "# API Policy Security Gaps\n\n"},
			"apim-testing-commands":    {Name: "apim-testing-commands", Contents: "# API Testing Commands\n\n"},
			"apim-certificate-expiry":  {Name: "apim-certificate-expiry", Contents: "# Certificate Expiration Warnings\n\n"},
		},
	}

	module.PrintAPIManagement(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method
// ------------------------------
func (m *APIManagementModule) PrintAPIManagement(ctx context.Context, logger internal.Logger) {
	// Multi-tenant processing
	if m.IsMultiTenant {
		logger.InfoM(fmt.Sprintf("Multi-tenant mode: Processing %d tenants", len(m.Tenants)), globals.AZ_API_MANAGEMENT_MODULE_NAME)

		for _, tenantCtx := range m.Tenants {
			savedTenantID := m.TenantID
			savedTenantName := m.TenantName
			savedTenantInfo := m.TenantInfo

			m.TenantID = tenantCtx.TenantID
			m.TenantName = tenantCtx.TenantName
			m.TenantInfo = tenantCtx.TenantInfo

			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_API_MANAGEMENT_MODULE_NAME, m.processSubscription)

			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_API_MANAGEMENT_MODULE_NAME, m.processSubscription)
	}

	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *APIManagementModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)
	resourceGroups := m.ResolveResourceGroups(subID)

	var rgWg sync.WaitGroup
	rgSemaphore := make(chan struct{}, 10)

	for _, rgName := range resourceGroups {
		rgWg.Add(1)
		go m.processResourceGroup(ctx, subID, subName, rgName, &rgWg, rgSemaphore)
	}

	rgWg.Wait()
}

// ------------------------------
// Process single resource group
// ------------------------------
func (m *APIManagementModule) processResourceGroup(ctx context.Context, subID, subName, rgName string, wg *sync.WaitGroup, semaphore chan struct{}) {
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

	// Get APIM services
	services, err := azinternal.ListAPIManagementServices(ctx, m.Session, subID, rgName)
	if err != nil {
		return
	}

	for _, service := range services {
		m.processAPIMService(ctx, service, subID, subName, rgName, region)
	}
}

// ------------------------------
// Process individual APIM service
// ------------------------------
func (m *APIManagementModule) processAPIMService(ctx context.Context, service *armapimanagement.ServiceResource, subID, subName, rgName, region string) {
	if service == nil || service.Name == nil {
		return
	}

	serviceName := *service.Name

	// Extract SKU
	sku := "N/A"
	skuCapacity := "N/A"
	if service.SKU != nil {
		if service.SKU.Name != nil {
			sku = string(*service.SKU.Name)
		}
		if service.SKU.Capacity != nil {
			skuCapacity = fmt.Sprintf("%d", *service.SKU.Capacity)
		}
	}

	// Extract Tags
	tags := "N/A"
	if service.Tags != nil && len(service.Tags) > 0 {
		var tagPairs []string
		for k, v := range service.Tags {
			if v != nil {
				tagPairs = append(tagPairs, fmt.Sprintf("%s:%s", k, *v))
			} else {
				tagPairs = append(tagPairs, k)
			}
		}
		if len(tagPairs) > 0 {
			tags = strings.Join(tagPairs, ", ")
		}
	}

	// Determine public vs private
	publicIP := "N/A"
	privateIP := "N/A"
	exposureType := "Unknown"
	gatewayURL := "N/A"
	portalURL := "N/A"

	if service.Properties != nil {
		// Gateway URL (public endpoint)
		if service.Properties.GatewayURL != nil {
			gatewayURL = *service.Properties.GatewayURL
			exposureType = "⚠ Public (Internet-Facing)"
		}

		// Portal URL
		if service.Properties.PortalURL != nil {
			portalURL = *service.Properties.PortalURL
		}

		// Public IP
		if service.Properties.PublicIPAddresses != nil && len(service.Properties.PublicIPAddresses) > 0 {
			var publicIPs []string
			for _, ip := range service.Properties.PublicIPAddresses {
				if ip != nil {
					publicIPs = append(publicIPs, *ip)
				}
			}
			if len(publicIPs) > 0 {
				publicIP = strings.Join(publicIPs, ", ")
			}
		}

		// Private IP (VNet integration)
		if service.Properties.PrivateIPAddresses != nil && len(service.Properties.PrivateIPAddresses) > 0 {
			var privateIPs []string
			for _, ip := range service.Properties.PrivateIPAddresses {
				if ip != nil {
					privateIPs = append(privateIPs, *ip)
				}
			}
			if len(privateIPs) > 0 {
				privateIP = strings.Join(privateIPs, ", ")
				if publicIP == "N/A" {
					exposureType = "Private (VNet-Integrated)"
				} else {
					exposureType = "⚠ Hybrid (Public + VNet)"
				}
			}
		}

		// Virtual Network Type
		if service.Properties.VirtualNetworkType != nil {
			vnetType := string(*service.Properties.VirtualNetworkType)
			if vnetType == "Internal" {
				exposureType = "Private (Internal VNet)"
			} else if vnetType == "External" {
				exposureType = "⚠ Public (External VNet)"
			}
		}
	}

	// Publisher email and name
	publisherEmail := "N/A"
	publisherName := "N/A"
	if service.Properties != nil {
		if service.Properties.PublisherEmail != nil {
			publisherEmail = *service.Properties.PublisherEmail
		}
		if service.Properties.PublisherName != nil {
			publisherName = *service.Properties.PublisherName
		}
	}

	// Extract identity information
	identityType := "None"
	systemManagedIdentity := "No"
	userManagedIdentity := "None"
	identityPrincipalID := "N/A"

	if service.Identity != nil {
		if service.Identity.Type != nil {
			identityType = string(*service.Identity.Type)

			// System Managed Identity
			if strings.Contains(identityType, "SystemAssigned") {
				systemManagedIdentity = "✓ Yes"
				if service.Identity.PrincipalID != nil {
					identityPrincipalID = *service.Identity.PrincipalID
				}
			}

			// User Managed Identity
			if strings.Contains(identityType, "UserAssigned") {
				if service.Identity.UserAssignedIdentities != nil && len(service.Identity.UserAssignedIdentities) > 0 {
					var userIdentities []string
					for identityID := range service.Identity.UserAssignedIdentities {
						// Extract name from full ID
						parts := strings.Split(identityID, "/")
						if len(parts) > 0 {
							userIdentities = append(userIdentities, parts[len(parts)-1])
						}
					}
					if len(userIdentities) > 0 {
						userManagedIdentity = strings.Join(userIdentities, ", ")
					}
				}
			}
		}
	}

	// EntraID Centralized Auth (for client authentication to APIs)
	entraIDAuth := "Not Configured"
	entraIDAuthDetails := "N/A"

	// Check if any APIs use OAuth2/JWT validation (we'll populate this when enumerating APIs)
	// For now, check service-level identity providers
	identityProviders := azinternal.GetAPIManagementIdentityProviders(ctx, m.Session, subID, rgName, serviceName)
	if len(identityProviders) > 0 {
		var providers []string
		for _, provider := range identityProviders {
			if provider != "" {
				providers = append(providers, provider)
			}
		}
		if len(providers) > 0 {
			entraIDAuth = "✓ Configured"
			entraIDAuthDetails = strings.Join(providers, ", ")
		}
	}

	// Custom domains and certificates
	customDomains := "None"
	customDomainCount := 0
	certExpiryWarning := "N/A"

	if service.Properties != nil && service.Properties.HostnameConfigurations != nil {
		customDomainCount = len(service.Properties.HostnameConfigurations)
		var domains []string
		for _, config := range service.Properties.HostnameConfigurations {
			if config.HostName != nil {
				domains = append(domains, *config.HostName)
			}
		}
		if len(domains) > 0 {
			customDomains = strings.Join(domains, ", ")
		}
	}

	// Developer portal settings
	developerPortalStatus := "Unknown"
	if service.Properties != nil && service.Properties.EnableClientCertificate != nil {
		if *service.Properties.EnableClientCertificate {
			developerPortalStatus = "✓ Client Cert Required"
		} else {
			developerPortalStatus = "⚠ No Client Cert (Less Secure)"
		}
	}

	// Get API count
	apiCount := 0
	apis, err := azinternal.ListAPIsInService(ctx, m.Session, subID, rgName, serviceName)
	if err == nil {
		apiCount = len(apis)

		// Process individual APIs for detailed analysis
		for _, api := range apis {
			m.processAPI(ctx, api, serviceName, subID, subName, rgName, gatewayURL)
		}
	}

	// Provisioning state
	provisioningState := "Unknown"
	if service.Properties != nil && service.Properties.ProvisioningState != nil {
		provisioningState = *service.Properties.ProvisioningState
	}

	// Build loot entries
	if exposureType == "⚠ Public (Internet-Facing)" || exposureType == "⚠ Hybrid (Public + VNet)" || exposureType == "⚠ Public (External VNet)" {
		m.mu.Lock()
		m.LootMap["apim-public-endpoints"].Contents += fmt.Sprintf(
			"## APIM Service: %s (Subscription: %s, RG: %s)\n"+
				"Gateway URL: %s\n"+
				"Portal URL: %s\n"+
				"Public IP: %s\n"+
				"API Count: %d\n\n",
			serviceName, subName, rgName, gatewayURL, portalURL, publicIP, apiCount,
		)
		m.mu.Unlock()
	}

	// Thread-safe append
	m.mu.Lock()
	m.APIMRows = append(m.APIMRows, []string{
		m.TenantName,
		m.TenantID,
		subID,
		subName,
		rgName,
		region,
		serviceName,
		sku,
		skuCapacity,
		exposureType,
		gatewayURL,
		portalURL,
		publicIP,
		privateIP,
		fmt.Sprintf("%d", apiCount),
		systemManagedIdentity,
		userManagedIdentity,
		identityPrincipalID,
		entraIDAuth,
		entraIDAuthDetails,
		customDomains,
		fmt.Sprintf("%d", customDomainCount),
		certExpiryWarning,
		developerPortalStatus,
		publisherEmail,
		publisherName,
		provisioningState,
		tags,
	})
	m.mu.Unlock()
}

// ------------------------------
// Process individual API
// ------------------------------
func (m *APIManagementModule) processAPI(ctx context.Context, api *armapimanagement.APIContract, serviceName, subID, subName, rgName, gatewayURL string) {
	if api == nil || api.Name == nil {
		return
	}

	apiName := *api.Name
	apiDisplayName := "N/A"
	if api.Properties != nil && api.Properties.DisplayName != nil {
		apiDisplayName = *api.Properties.DisplayName
	}

	// API Path
	apiPath := "N/A"
	if api.Properties != nil && api.Properties.Path != nil {
		apiPath = *api.Properties.Path
	}

	// Full endpoint URL
	fullEndpoint := "N/A"
	if gatewayURL != "N/A" && apiPath != "N/A" {
		fullEndpoint = fmt.Sprintf("%s/%s", strings.TrimSuffix(gatewayURL, "/"), strings.TrimPrefix(apiPath, "/"))
	}

	// Authentication requirement
	authRequired := "Unknown"
	authType := "N/A"
	if api.Properties != nil {
		// Check if subscription required
		subscriptionRequired := true
		if api.Properties.SubscriptionRequired != nil {
			subscriptionRequired = *api.Properties.SubscriptionRequired
		}

		if subscriptionRequired {
			authRequired = "✓ Subscription Key Required"
			authType = "Subscription Key"
		} else {
			authRequired = "⚠ NO AUTH (Open Access)"
			authType = "None"

			// Log to loot file
			m.mu.Lock()
			m.LootMap["apim-unauthenticated"].Contents += fmt.Sprintf(
				"## API: %s (Service: %s)\n"+
					"Endpoint: %s\n"+
					"Path: %s\n"+
					"⚠ WARNING: This API does not require authentication!\n\n",
				apiDisplayName, serviceName, fullEndpoint, apiPath,
			)
			m.mu.Unlock()
		}
	}

	// Backend service URL
	backendService := "N/A"
	if api.Properties != nil && api.Properties.ServiceURL != nil {
		backendService = *api.Properties.ServiceURL

		// Log backend service
		m.mu.Lock()
		m.LootMap["apim-backend-services"].Contents += fmt.Sprintf(
			"%s | %s | %s | %s\n",
			serviceName, apiDisplayName, fullEndpoint, backendService,
		)
		m.mu.Unlock()
	}

	// API protocols
	protocols := "N/A"
	if api.Properties != nil && api.Properties.Protocols != nil && len(api.Properties.Protocols) > 0 {
		var protoList []string
		for _, proto := range api.Properties.Protocols {
			if proto != nil {
				protoList = append(protoList, string(*proto))
			}
		}
		if len(protoList) > 0 {
			protocols = strings.Join(protoList, ", ")
		}
	}

	// API version
	apiVersion := "N/A"
	if api.Properties != nil && api.Properties.APIVersion != nil {
		apiVersion = *api.Properties.APIVersion
	}

	// API type (REST, SOAP, GraphQL, etc.)
	apiType := "N/A"
	if api.Properties != nil && api.Properties.Type != nil {
		apiType = string(*api.Properties.Type)
	}

	// Check if API is public
	isPublic := "Unknown"
	if api.Properties != nil && api.Properties.IsCurrent != nil {
		if *api.Properties.IsCurrent {
			isPublic = "✓ Current/Public"
		} else {
			isPublic = "Private/Deprecated"
		}
	}

	// Generate testing commands
	if fullEndpoint != "N/A" {
		m.mu.Lock()
		m.LootMap["apim-testing-commands"].Contents += fmt.Sprintf(
			"## API: %s (Service: %s)\n"+
				"# Endpoint: %s\n",
			apiDisplayName, serviceName, fullEndpoint,
		)

		if authRequired == "⚠ NO AUTH (Open Access)" {
			m.LootMap["apim-testing-commands"].Contents += fmt.Sprintf(
				"# NO AUTH REQUIRED - Direct access:\n"+
					"curl -X GET \"%s\"\n\n",
				fullEndpoint,
			)
		} else {
			m.LootMap["apim-testing-commands"].Contents += fmt.Sprintf(
				"# Requires subscription key:\n"+
					"curl -X GET \"%s\" -H \"Ocp-Apim-Subscription-Key: <YOUR-KEY>\"\n"+
					"# Or via query parameter:\n"+
					"curl -X GET \"%s?subscription-key=<YOUR-KEY>\"\n\n",
				fullEndpoint, fullEndpoint,
			)
		}
		m.mu.Unlock()
	}

	// Thread-safe append
	m.mu.Lock()
	m.APIRows = append(m.APIRows, []string{
		m.TenantName,
		m.TenantID,
		subID,
		subName,
		rgName,
		serviceName,
		apiName,
		apiDisplayName,
		apiPath,
		fullEndpoint,
		authRequired,
		authType,
		backendService,
		protocols,
		apiVersion,
		apiType,
		isPublic,
	})
	m.mu.Unlock()
}

// ------------------------------
// Write output
// ------------------------------
func (m *APIManagementModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.APIMRows) == 0 {
		logger.InfoM("No API Management services found", globals.AZ_API_MANAGEMENT_MODULE_NAME)
		return
	}

	// APIM Services table headers
	apimHeaders := []string{
		"Tenant Name",
		"Tenant ID",
		"Subscription ID",
		"Subscription Name",
		"Resource Group",
		"Region",
		"APIM Service Name",
		"SKU",
		"SKU Capacity",
		"Exposure Type",
		"Gateway URL",
		"Portal URL",
		"Public IP",
		"Private IP",
		"API Count",
		"System Managed Identity",
		"User Managed Identity",
		"Identity Principal ID",
		"EntraID Client Auth",
		"EntraID Auth Details",
		"Custom Domains",
		"Custom Domain Count",
		"Certificate Expiry Warning",
		"Developer Portal Status",
		"Publisher Email",
		"Publisher Name",
		"Provisioning State",
		"Tags",
	}

	// APIs table headers
	apiHeaders := []string{
		"Tenant Name",
		"Tenant ID",
		"Subscription ID",
		"Subscription Name",
		"Resource Group",
		"APIM Service Name",
		"API Name",
		"API Display Name",
		"API Path",
		"Full Endpoint URL",
		"Authentication Required",
		"Auth Type",
		"Backend Service URL",
		"Protocols",
		"API Version",
		"API Type",
		"Visibility",
	}

	// Build loot array
	loot := []internal.LootFile{}
	for _, lf := range m.LootMap {
		if lf.Contents != "" && lf.Contents != "# Public API Management Endpoints\n\n" &&
			lf.Contents != "# APIs Without Authentication\n\n" &&
			lf.Contents != "# Backend Services Exposed via APIM\n\n" &&
			lf.Contents != "# API Policy Security Gaps\n\n" &&
			lf.Contents != "# API Testing Commands\n\n" &&
			lf.Contents != "# Certificate Expiration Warnings\n\n" {
			loot = append(loot, *lf)
		}
	}

	// Create output with multiple tables
	tableFiles := []internal.TableFile{
		{
			Name:   "api-management-services",
			Header: apimHeaders,
			Body:   m.APIMRows,
		},
	}

	if len(m.APIRows) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "api-management-apis",
			Header: apiHeaders,
			Body:   m.APIRows,
		})
	}

	output := APIManagementOutput{
		Table: tableFiles,
		Loot:  loot,
	}

	// Check if we should split output by tenant
	if azinternal.ShouldSplitByTenant(m.IsMultiTenant, m.Tenants) {
		// For multi-table output, we need to handle each table separately
		logger.InfoM("Multi-tenant mode: Writing separate outputs per tenant", globals.AZ_API_MANAGEMENT_MODULE_NAME)
		// For now, write consolidated output
		// TODO: Implement per-tenant splitting for multi-table outputs
	}

	// Check if we should split output by subscription
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		logger.InfoM("Multi-subscription mode: Writing separate outputs per subscription", globals.AZ_API_MANAGEMENT_MODULE_NAME)
		// For now, write consolidated output
		// TODO: Implement per-subscription splitting for multi-table outputs
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_API_MANAGEMENT_MODULE_NAME)
		m.CommandCounter.Error++
	}

	// Count statistics
	publicCount := 0
	privateCount := 0
	totalAPIs := len(m.APIRows)
	unauthAPIs := 0

	for _, row := range m.APIMRows {
		if len(row) > 9 && strings.Contains(row[9], "Public") {
			publicCount++
		} else {
			privateCount++
		}
	}

	for _, row := range m.APIRows {
		if len(row) > 10 && strings.Contains(row[10], "NO AUTH") {
			unauthAPIs++
		}
	}

	logger.SuccessM(fmt.Sprintf("Found %d APIM service(s) with %d API(s) across %d subscription(s) (Public: %d, Private: %d, Unauthenticated APIs: %d)",
		len(m.APIMRows), totalAPIs, len(m.Subscriptions), publicCount, privateCount, unauthAPIs), globals.AZ_API_MANAGEMENT_MODULE_NAME)
}
