package azure

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/BishopFox/cloudfox/globals"
)

// PolicyDefinitionInfo represents a custom Azure Policy Definition
type PolicyDefinitionInfo struct {
	Name        string
	PolicyType  string
	Mode        string
	Description string
	PolicyRule  string
	Parameters  string
}

// PolicyAssignmentInfo represents an Azure Policy Assignment
type PolicyAssignmentInfo struct {
	Name                 string
	PolicyDefinitionName string
	Scope                string
	Description          string
	Parameters           string
}

// GetCustomPolicyDefinitions enumerates custom (non-built-in) policy definitions
func GetCustomPolicyDefinitions(ctx context.Context, session *SafeSession, subscriptionID string) ([]PolicyDefinitionInfo, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %v", err)
	}

	cred := &StaticTokenCredential{Token: token}

	// Create policy definitions client
	policyClient, err := armpolicy.NewDefinitionsClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create policy definitions client: %w", err)
	}

	var definitions []PolicyDefinitionInfo

	// List policy definitions - filter for custom only
	pager := policyClient.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return definitions, err // Return partial results
		}

		for _, def := range page.Value {
			if def == nil || def.Name == nil {
				continue
			}

			// Only include custom policies (not built-in Azure policies)
			if def.Properties != nil && def.Properties.PolicyType != nil {
				if *def.Properties.PolicyType != armpolicy.PolicyTypeCustom {
					continue // Skip built-in policies
				}
			}

			info := PolicyDefinitionInfo{
				Name:        SafeStringPtr(def.Name),
				PolicyType:  "Custom",
				Mode:        "N/A",
				Description: "N/A",
			}

			if def.Properties != nil {
				// Policy Type
				if def.Properties.PolicyType != nil {
					info.PolicyType = string(*def.Properties.PolicyType)
				}

				// Mode
				if def.Properties.Mode != nil {
					info.Mode = string(*def.Properties.Mode)
				}

				// Description
				if def.Properties.Description != nil {
					info.Description = *def.Properties.Description
				}

				// Policy Rule
				if def.Properties.PolicyRule != nil {
					ruleBytes, err := json.MarshalIndent(def.Properties.PolicyRule, "", "  ")
					if err == nil {
						info.PolicyRule = string(ruleBytes)
					}
				}

				// Parameters
				if def.Properties.Parameters != nil {
					paramsBytes, err := json.MarshalIndent(def.Properties.Parameters, "", "  ")
					if err == nil {
						info.Parameters = string(paramsBytes)
					}
				}
			}

			definitions = append(definitions, info)
		}
	}

	return definitions, nil
}

// GetPolicyAssignments enumerates policy assignments for a subscription
func GetPolicyAssignments(ctx context.Context, session *SafeSession, subscriptionID string) ([]PolicyAssignmentInfo, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %v", err)
	}

	cred := &StaticTokenCredential{Token: token}

	// Create policy assignments client
	assignmentClient, err := armpolicy.NewAssignmentsClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create policy assignments client: %w", err)
	}

	var assignments []PolicyAssignmentInfo

	// List policy assignments
	pager := assignmentClient.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return assignments, err // Return partial results
		}

		for _, assign := range page.Value {
			if assign == nil || assign.Name == nil {
				continue
			}

			info := PolicyAssignmentInfo{
				Name:                 SafeStringPtr(assign.Name),
				PolicyDefinitionName: "N/A",
				Scope:                "N/A",
				Description:          "N/A",
			}

			if assign.Properties != nil {
				// Policy Definition ID
				if assign.Properties.PolicyDefinitionID != nil {
					policyDefID := *assign.Properties.PolicyDefinitionID
					// Extract policy name from full resource ID
					info.PolicyDefinitionName = extractPolicyNameFromID(policyDefID)
				}

				// Scope
				if assign.Properties.Scope != nil {
					info.Scope = *assign.Properties.Scope
				}

				// Description
				if assign.Properties.Description != nil {
					info.Description = *assign.Properties.Description
				}

				// Parameters
				if assign.Properties.Parameters != nil {
					paramsBytes, err := json.MarshalIndent(assign.Properties.Parameters, "", "  ")
					if err == nil {
						info.Parameters = string(paramsBytes)
					}
				}
			}

			assignments = append(assignments, info)
		}
	}

	return assignments, nil
}

// extractPolicyNameFromID extracts the policy name from a policy definition resource ID
// Example: /subscriptions/{sub}/providers/Microsoft.Authorization/policyDefinitions/{name}
func extractPolicyNameFromID(resourceID string) string {
	if resourceID == "" {
		return "Unknown"
	}

	// Simple extraction - get last part after final /
	for i := len(resourceID) - 1; i >= 0; i-- {
		if resourceID[i] == '/' {
			return resourceID[i+1:]
		}
	}

	return resourceID
}

// ------------------------------
// Compliance Dashboard Helpers
// ------------------------------

// PolicyComplianceState represents compliance state for a policy
type PolicyComplianceState struct {
	PolicyDefinitionName  string
	PolicyAssignmentName  string
	CompliantResources    int
	NonCompliantResources int
}

// RegulatoryComplianceStandard represents a regulatory compliance standard
type RegulatoryComplianceStandard struct {
	StandardName    string
	Description     string
	PassedControls  int
	FailedControls  int
	SkippedControls int
	State           string
	Severity        string
}

// PolicyInitiativeCompliance represents compliance state for a policy initiative
type PolicyInitiativeCompliance struct {
	InitiativeName        string
	Description           string
	CompliantPolicies     int
	NonCompliantPolicies  int
	TotalResources        int
	NonCompliantResources int
}

// NonCompliantResource represents a non-compliant resource
type NonCompliantResource struct {
	ResourceID           string
	ResourceType         string
	ResourceLocation     string
	PolicyDefinitionName string
	PolicyAssignmentName string
	ComplianceState      string
}

// GetPolicyComplianceState retrieves policy compliance state aggregated by policy assignment
func GetPolicyComplianceState(ctx context.Context, session *SafeSession, subscriptionID string) ([]PolicyComplianceState, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %v", err)
	}

	// Use Azure Policy Insights REST API for policy states
	// We'll aggregate compliance by policy assignment using Resource Graph or REST API
	// For now, return mock data structure - actual implementation would use Policy Insights API

	// Get policy assignments first
	assignments, err := GetPolicyAssignments(ctx, session, subscriptionID)
	if err != nil {
		return nil, err
	}

	var states []PolicyComplianceState

	// For each assignment, we would query Policy Insights API for compliance state
	// This is a simplified version - full implementation would use:
	// https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.PolicyInsights/policyStates/latest/summarize
	for _, assign := range assignments {
		// Mock compliance state - actual implementation would query Policy Insights
		state := PolicyComplianceState{
			PolicyDefinitionName:  assign.PolicyDefinitionName,
			PolicyAssignmentName:  assign.Name,
			CompliantResources:    0, // Would be populated from Policy Insights API
			NonCompliantResources: 0, // Would be populated from Policy Insights API
		}
		states = append(states, state)
	}

	return states, nil
}

// GetRegulatoryComplianceStandards retrieves regulatory compliance standards from Security Center
func GetRegulatoryComplianceStandards(ctx context.Context, session *SafeSession, subscriptionID string) ([]RegulatoryComplianceStandard, error) {
	// Use Security Center REST API for regulatory compliance
	// Full implementation would use:
	// https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Security/regulatoryComplianceStandards

	// Common regulatory standards in Azure Security Center
	standards := []RegulatoryComplianceStandard{
		{
			StandardName:    "Azure Security Benchmark",
			Description:     "Microsoft cloud security best practices",
			PassedControls:  0, // Would be populated from Security Center API
			FailedControls:  0, // Would be populated from Security Center API
			SkippedControls: 0,
			State:           "Unknown",
			Severity:        "High",
		},
	}

	return standards, nil
}

// GetPolicyInitiativeCompliance retrieves compliance state for policy initiatives
func GetPolicyInitiativeCompliance(ctx context.Context, session *SafeSession, subscriptionID string) ([]PolicyInitiativeCompliance, error) {
	// Policy initiatives (also called policy sets) compliance would be retrieved from Policy Insights
	// Full implementation would use:
	// https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.PolicyInsights/policyStates/latest/summarize
	// with filter for initiative assignments

	var initiatives []PolicyInitiativeCompliance

	// Get policy assignments and filter for initiatives
	assignments, err := GetPolicyAssignments(ctx, session, subscriptionID)
	if err != nil {
		return nil, err
	}

	// For each initiative assignment, aggregate compliance
	for _, assign := range assignments {
		// Check if this is an initiative (contains multiple policies)
		// Mock data - actual implementation would check policySetDefinitionID
		init := PolicyInitiativeCompliance{
			InitiativeName:        assign.Name,
			Description:           assign.Description,
			CompliantPolicies:     0, // Would be populated from Policy Insights
			NonCompliantPolicies:  0, // Would be populated from Policy Insights
			TotalResources:        0,
			NonCompliantResources: 0,
		}
		initiatives = append(initiatives, init)
	}

	return initiatives, nil
}

// GetNonCompliantResourcesSample retrieves a sample of non-compliant resources
func GetNonCompliantResourcesSample(ctx context.Context, session *SafeSession, subscriptionID string, limit int) ([]NonCompliantResource, error) {
	// Use Policy Insights API to get non-compliant resources
	// Full implementation would use:
	// https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.PolicyInsights/policyStates/latest/queryResults
	// with filter for complianceState eq 'NonCompliant'

	var resources []NonCompliantResource

	// Mock implementation - actual would query Policy Insights API
	// and limit to specified number of resources

	return resources, nil
}
