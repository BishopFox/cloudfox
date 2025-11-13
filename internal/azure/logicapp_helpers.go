package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/logic/armlogic"
	"github.com/BishopFox/cloudfox/globals"
)

// LogicAppInfo represents an Azure Logic App
type LogicAppInfo struct {
	SubscriptionID   string
	ResourceGroup    string
	Region           string
	Name             string
	State            string
	TriggerType      string
	ActionCount      string
	HasParameters    string
	Definition       string
	Parameters       string
	HasSecrets       bool
	SystemAssignedID string
	UserAssignedIDs  string
}

// GetLogicAppsForResourceGroup enumerates Logic Apps in a resource group
func GetLogicAppsForResourceGroup(ctx context.Context, session *SafeSession, subscriptionID, resourceGroup string) ([]LogicAppInfo, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %v", err)
	}

	cred := &StaticTokenCredential{Token: token}

	// Create Logic Apps client
	logicClient, err := armlogic.NewWorkflowsClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create logic apps client: %w", err)
	}

	var logicApps []LogicAppInfo

	// List Logic Apps in resource group
	pager := logicClient.NewListByResourceGroupPager(resourceGroup, &armlogic.WorkflowsClientListByResourceGroupOptions{
		Top: nil,
	})

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return logicApps, err // Return partial results
		}

		for _, workflow := range page.Value {
			if workflow == nil || workflow.Name == nil {
				continue
			}

			info := LogicAppInfo{
				SubscriptionID:   subscriptionID,
				ResourceGroup:    resourceGroup,
				Name:             SafeStringPtr(workflow.Name),
				Region:           SafeStringPtr(workflow.Location),
				State:            "Unknown",
				TriggerType:      "N/A",
				ActionCount:      "0",
				HasParameters:    "No",
				HasSecrets:       false,
				SystemAssignedID: "N/A",
				UserAssignedIDs:  "N/A",
			}

			// Extract managed identity information
			if workflow.Identity != nil {
				var systemAssignedIDs []string
				var userAssignedIDs []string

				// System-assigned identity
				if workflow.Identity.PrincipalID != nil {
					principalID := *workflow.Identity.PrincipalID
					systemAssignedIDs = append(systemAssignedIDs, principalID)
				}

				// User-assigned identities
				if workflow.Identity.UserAssignedIdentities != nil {
					for uaID := range workflow.Identity.UserAssignedIdentities {
						userAssignedIDs = append(userAssignedIDs, uaID)
					}
				}

				// Format identity fields
				if len(systemAssignedIDs) > 0 {
					info.SystemAssignedID = strings.Join(systemAssignedIDs, ", ")
				}
				if len(userAssignedIDs) > 0 {
					info.UserAssignedIDs = strings.Join(userAssignedIDs, ", ")
				}
			}

			// Get workflow properties
			if workflow.Properties != nil {
				// State
				if workflow.Properties.State != nil {
					info.State = string(*workflow.Properties.State)
				}

				// Definition (workflow logic)
				if workflow.Properties.Definition != nil {
					defBytes, err := json.MarshalIndent(workflow.Properties.Definition, "", "  ")
					if err == nil {
						info.Definition = string(defBytes)

						// Parse definition to extract trigger and action info
						triggerType, actionCount := parseWorkflowDefinition(workflow.Properties.Definition)
						info.TriggerType = triggerType
						info.ActionCount = fmt.Sprintf("%d", actionCount)

						// Check for potential secrets in definition
						info.HasSecrets = checkForSecrets(string(defBytes))
					}
				}

				// Parameters
				if workflow.Properties.Parameters != nil && len(workflow.Properties.Parameters) > 0 {
					info.HasParameters = "Yes"
					paramsBytes, err := json.MarshalIndent(workflow.Properties.Parameters, "", "  ")
					if err == nil {
						info.Parameters = string(paramsBytes)

						// Check parameters for secrets
						if !info.HasSecrets {
							info.HasSecrets = checkForSecrets(string(paramsBytes))
						}
					}
				}
			}

			logicApps = append(logicApps, info)
		}
	}

	return logicApps, nil
}

// parseWorkflowDefinition extracts trigger type and action count from workflow definition
func parseWorkflowDefinition(definition interface{}) (string, int) {
	triggerType := "N/A"
	actionCount := 0

	// Try to parse definition as map
	defMap, ok := definition.(map[string]interface{})
	if !ok {
		return triggerType, actionCount
	}

	// Get triggers
	if triggers, ok := defMap["triggers"].(map[string]interface{}); ok {
		for triggerName, trigger := range triggers {
			if triggerMap, ok := trigger.(map[string]interface{}); ok {
				if tType, ok := triggerMap["type"].(string); ok {
					triggerType = tType
				} else {
					triggerType = triggerName
				}
				break // Just get the first trigger
			}
		}
	}

	// Get action count
	if actions, ok := defMap["actions"].(map[string]interface{}); ok {
		actionCount = len(actions)
	}

	return triggerType, actionCount
}

// checkForSecrets checks if content contains potential secrets
func checkForSecrets(content string) bool {
	contentLower := strings.ToLower(content)

	// Keywords that indicate potential secrets
	secretKeywords := []string{
		"password",
		"secret",
		"apikey",
		"api_key",
		"connectionstring",
		"token",
		"credentials",
		"authorization",
		"bearer",
		"clientsecret",
		"client_secret",
		"accountkey",
		"account_key",
		"sastoken",
		"accesskey",
	}

	for _, keyword := range secretKeywords {
		if strings.Contains(contentLower, keyword) {
			return true
		}
	}

	return false
}
