// Package shared provides common utilities for GCP CloudFox modules.
//
// This package contains helper functions and types that are used across multiple
// GCP command modules to reduce code duplication and ensure consistency.
//
// # Package Organization
//
// The shared package is organized into several files by functionality:
//
//   - principals.go: IAM principal type detection and parsing utilities
//   - formatting.go: Table formatting helpers (bool to string, truncation, etc.)
//   - risk.go: Risk assessment constants, types, and utilities
//   - loot.go: Loot file management and command formatting helpers
//   - aggregate.go: Generic aggregation utilities for per-project data
//
// # Principal Utilities
//
// The principals.go file provides functions for working with GCP IAM principals:
//
//	// Get the type of a principal
//	principalType := shared.GetPrincipalType("user:admin@example.com") // "User"
//
//	// Check if a principal is public
//	if shared.IsPublicPrincipal("allUsers") {
//	    // Handle public access
//	}
//
//	// Extract email from principal string
//	email := shared.ExtractPrincipalEmail("serviceAccount:sa@project.iam.gserviceaccount.com")
//
// # Formatting Utilities
//
// The formatting.go file provides helpers for table and output formatting:
//
//	// Convert bool to display string
//	shared.BoolToYesNo(true)     // "Yes"
//	shared.BoolToEnabled(false)  // "Disabled"
//
//	// Format lists for display
//	shared.FormatList([]string{"a", "b", "c", "d", "e"}, 3) // "a, b, c (+2 more)"
//
//	// Extract resource names from paths
//	shared.ExtractResourceName("projects/my-project/locations/us-central1/functions/my-func")
//	// Returns: "my-func"
//
// # Risk Assessment
//
// The risk.go file provides standardized risk assessment utilities:
//
//	// Use standard risk level constants
//	if riskLevel == shared.RiskCritical {
//	    // Handle critical risk
//	}
//
//	// Track risk counts
//	counts := &shared.RiskCounts{}
//	counts.Add(shared.RiskHigh)
//	counts.Add(shared.RiskMedium)
//	fmt.Println(counts.Summary()) // "1 HIGH, 1 MEDIUM"
//
//	// Assess specific risks
//	level := shared.AssessRoleRisk("roles/owner") // "CRITICAL"
//
// # Loot File Management
//
// The loot.go file provides helpers for creating and managing loot files:
//
//	// Create a loot file manager
//	lootMgr := shared.NewLootFileManager()
//
//	// Initialize and add content
//	lootMgr.CreateLootFile(projectID, "buckets-commands",
//	    shared.LootHeaderCommands("buckets", "Storage bucket access commands"))
//	lootMgr.AddToLoot(projectID, "buckets-commands",
//	    shared.FormatGcloudCommand("List bucket", "gsutil ls gs://my-bucket/"))
//
//	// Get formatted command strings
//	cmd := shared.GcloudAccessSecretVersion("my-project", "my-secret", "latest")
//
// # Aggregation Utilities
//
// The aggregate.go file provides generic functions for combining per-project data:
//
//	// Aggregate from per-project maps
//	allBuckets := shared.AggregateFromProjects(projectBucketsMap)
//
//	// Filter and transform
//	publicBuckets := shared.FilterItems(allBuckets, func(b Bucket) bool {
//	    return b.IsPublic
//	})
//
//	// Group by field
//	bucketsByRegion := shared.GroupBy(allBuckets, func(b Bucket) string {
//	    return b.Region
//	})
//
// # Usage in Modules
//
// Import the shared package in GCP command modules:
//
//	import (
//	    "github.com/BishopFox/cloudfox/gcp/shared"
//	)
//
//	func (m *MyModule) processResource(resource Resource) {
//	    principalType := shared.GetPrincipalType(resource.Principal)
//	    riskLevel := shared.AssessRoleRisk(resource.Role)
//
//	    if shared.IsPublicPrincipal(resource.Principal) {
//	        m.addToLoot(shared.FormatExploitEntry(
//	            "Public Access",
//	            "Resource is publicly accessible",
//	            shared.GsutilList(resource.BucketName),
//	        ))
//	    }
//	}
package shared
