package azure

import (
	"context"
	"fmt"
	"time"

	"github.com/BishopFox/cloudfox/globals"
)

// ------------------------------
// Cost Security Types
// ------------------------------

// CostAnomaly represents a detected cost anomaly
type CostAnomaly struct {
	DetectionDate    string
	ResourceType     string
	ImpactPercentage float64
	ActualCost       float64
	ExpectedCost     float64
	AnomalyType      string
	PotentialCause   string
	StartDate        string
	EndDate          string
}

// BudgetConfiguration represents budget settings for a subscription
type BudgetConfiguration struct {
	BudgetName   string
	Amount       float64
	CurrentSpend float64
	HasAlerts    bool
	AlertStatus  string
}

// ExpensiveResource represents a high-cost resource with security assessment
type ExpensiveResource struct {
	ResourceName   string
	ResourceType   string
	ResourceID     string
	Location       string
	MonthlyCost    float64
	SecurityRisk   string
	SecurityIssues string
}

// OrphanedResource represents an unused resource costing money
type OrphanedResource struct {
	ResourceName string
	ResourceType string
	ResourceID   string
	Location     string
	OrphanReason string
	MonthlyCost  float64
	DaysOrphaned float64
}

// CostByResourceType represents cost aggregation by resource type
type CostByResourceType struct {
	ResourceType   string
	ResourceCount  int
	MonthlyCost    float64
	PercentOfTotal float64
	TopConsumers   string
}

// ------------------------------
// Cost Anomaly Detection
// ------------------------------

// GetCostAnomalies detects cost anomalies using Azure Cost Management API
func GetCostAnomalies(ctx context.Context, session *SafeSession, subscriptionID string) ([]CostAnomaly, error) {
	// Use Azure Cost Management REST API for anomaly detection
	// Full implementation would use:
	// https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.CostManagement/costAnomalies

	_, err := session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %v", err)
	}

	var anomalies []CostAnomaly

	// Mock anomaly data - actual implementation would query Cost Management API
	// This would detect:
	// - Sudden cost spikes (crypto mining)
	// - Unusual resource creation patterns
	// - Geographic anomalies (resources in unexpected regions)

	// For demonstration, return empty list
	// Actual implementation would parse Cost Management Anomaly API response

	return anomalies, nil
}

// ------------------------------
// Budget Configuration
// ------------------------------

// GetBudgetConfiguration retrieves budget settings for a subscription
func GetBudgetConfiguration(ctx context.Context, session *SafeSession, subscriptionID string) ([]BudgetConfiguration, error) {
	// Use Azure Cost Management REST API for budget configuration
	// Full implementation would use:
	// https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.CostManagement/budgets

	_, err := session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %v", err)
	}

	var budgets []BudgetConfiguration

	// Mock implementation - actual would query budgets API
	// Check:
	// - Budget amount vs actual spend
	// - Alert configuration (email notifications)
	// - Budget threshold percentages (50%, 80%, 100%)

	return budgets, nil
}

// ------------------------------
// Expensive Resources
// ------------------------------

// GetExpensiveResources retrieves top expensive resources with security assessment
func GetExpensiveResources(ctx context.Context, session *SafeSession, subscriptionID string, limit int) ([]ExpensiveResource, error) {
	// Use Azure Cost Management API to get resource costs
	// Then correlate with security assessments from Security Center
	// Full implementation would use:
	// - Microsoft.CostManagement/query for resource costs
	// - Microsoft.Security/assessments for security risk

	_, err := session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %v", err)
	}

	var resources []ExpensiveResource

	// Mock implementation - actual would:
	// 1. Query cost by resource for last 30 days
	// 2. Sort by cost descending
	// 3. Limit to top N resources
	// 4. For each resource, check security assessments:
	//    - NSG rules (public access)
	//    - Encryption status
	//    - Managed identity usage
	//    - Security Center recommendations

	return resources, nil
}

// ------------------------------
// Orphaned Resources
// ------------------------------

// GetOrphanedResources finds unused resources costing money
func GetOrphanedResources(ctx context.Context, session *SafeSession, subscriptionID string) ([]OrphanedResource, error) {
	// Identify orphaned resources:
	// - Unattached managed disks (not attached to any VM)
	// - Unused public IPs (not associated with resources)
	// - Idle VMs (low CPU utilization for 30+ days)
	// - Empty storage accounts (no blobs/files)
	// - Unused network interfaces (not attached to VM)

	_, err := session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %v", err)
	}

	var orphaned []OrphanedResource

	// Mock implementation - actual would enumerate:
	// 1. Disks: Check disk.ManagedBy == nil
	// 2. Public IPs: Check ipConfiguration == nil
	// 3. VMs: Query metrics API for CPU utilization < 5% for 30 days
	// 4. Storage: Check blob/file container count
	// 5. NICs: Check virtualMachine == nil

	// For each orphaned resource:
	// - Calculate days since last used/attached
	// - Estimate monthly cost from Cost Management API
	// - Calculate total waste (days * daily cost)

	return orphaned, nil
}

// ------------------------------
// Cost by Resource Type
// ------------------------------

// GetCostByResourceType aggregates costs by resource type
func GetCostByResourceType(ctx context.Context, session *SafeSession, subscriptionID string) ([]CostByResourceType, error) {
	// Use Azure Cost Management API to aggregate costs by resource type
	// Full implementation would use:
	// https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.CostManagement/query
	// with groupBy: ResourceType

	_, err := session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %v", err)
	}

	var costByType []CostByResourceType

	// Mock implementation - actual would:
	// 1. Query costs grouped by resourceType
	// 2. Calculate percentage of total subscription cost
	// 3. Identify top 3 consumers per resource type
	// 4. Sort by cost descending

	// Common expensive resource types:
	// - Microsoft.Compute/virtualMachines
	// - Microsoft.Storage/storageAccounts
	// - Microsoft.Network/applicationGateways
	// - Microsoft.Sql/servers/databases
	// - Microsoft.ContainerService/managedClusters

	return costByType, nil
}

// ------------------------------
// Cost Optimization Helpers
// ------------------------------

// CalculateOrphanedResourceWaste calculates annual waste from orphaned resources
func CalculateOrphanedResourceWaste(resources []OrphanedResource) float64 {
	totalWaste := 0.0
	for _, res := range resources {
		totalWaste += res.MonthlyCost * 12
	}
	return totalWaste
}

// GetAnomalyDetectionDate returns formatted detection date
func GetAnomalyDetectionDate() string {
	return time.Now().Format("2006-01-02")
}

// CalculateCostImpact calculates percentage impact of cost anomaly
func CalculateCostImpact(actual, expected float64) float64 {
	if expected == 0 {
		return 0
	}
	return ((actual - expected) / expected) * 100
}

// ClassifySecurityRisk classifies resource security risk based on findings
func ClassifySecurityRisk(publicAccess bool, encryptionEnabled bool, managedIdentity bool) string {
	// HIGH: Public access without encryption
	// MEDIUM: Public access with encryption, or no managed identity
	// LOW: Private access with encryption and managed identity

	if publicAccess && !encryptionEnabled {
		return "HIGH"
	} else if publicAccess || !managedIdentity {
		return "MEDIUM"
	}
	return "LOW"
}
