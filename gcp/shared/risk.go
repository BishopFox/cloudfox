package shared

import (
	"fmt"
	"strings"
)

// RiskLevel constants for standardized risk assessment across modules
const (
	RiskCritical = "CRITICAL" // Immediate exploitation possible, highest priority
	RiskHigh     = "HIGH"     // Significant security issue, high priority
	RiskMedium   = "MEDIUM"   // Notable risk, moderate priority
	RiskLow      = "LOW"      // Minor issue or informational
	RiskInfo     = "INFO"     // Informational, no direct risk
	RiskNone     = "NONE"     // No risk identified
)

// RiskScore represents a risk assessment with reasons
type RiskScore struct {
	Level   string   // RiskCritical, RiskHigh, RiskMedium, RiskLow
	Score   int      // Numeric score for comparison (0-100)
	Reasons []string // Explanations for the risk level
}

// NewRiskScore creates a new RiskScore with default low risk
func NewRiskScore() *RiskScore {
	return &RiskScore{
		Level:   RiskLow,
		Score:   0,
		Reasons: []string{},
	}
}

// AddReason adds a reason and recalculates the risk level
func (r *RiskScore) AddReason(reason string, points int) {
	r.Reasons = append(r.Reasons, reason)
	r.Score += points
	r.updateLevel()
}

// SetCritical sets the risk to critical level with a reason
func (r *RiskScore) SetCritical(reason string) {
	r.Level = RiskCritical
	r.Score = 100
	r.Reasons = append(r.Reasons, reason)
}

// updateLevel updates the risk level based on score
func (r *RiskScore) updateLevel() {
	switch {
	case r.Score >= 80:
		r.Level = RiskCritical
	case r.Score >= 50:
		r.Level = RiskHigh
	case r.Score >= 25:
		r.Level = RiskMedium
	default:
		r.Level = RiskLow
	}
}

// ReasonsString returns all reasons as a single string
func (r *RiskScore) ReasonsString() string {
	if len(r.Reasons) == 0 {
		return "-"
	}
	return strings.Join(r.Reasons, "; ")
}

// IsHighRisk returns true if risk level is HIGH or CRITICAL
func (r *RiskScore) IsHighRisk() bool {
	return r.Level == RiskCritical || r.Level == RiskHigh
}

// RiskLevelOrder returns the numeric order of a risk level (for sorting)
// Higher number = higher risk
func RiskLevelOrder(level string) int {
	switch level {
	case RiskCritical:
		return 4
	case RiskHigh:
		return 3
	case RiskMedium:
		return 2
	case RiskLow:
		return 1
	case RiskInfo, RiskNone:
		return 0
	default:
		return -1
	}
}

// CompareRiskLevels compares two risk levels.
// Returns: -1 if a < b, 0 if a == b, 1 if a > b
func CompareRiskLevels(a, b string) int {
	orderA := RiskLevelOrder(a)
	orderB := RiskLevelOrder(b)
	if orderA < orderB {
		return -1
	}
	if orderA > orderB {
		return 1
	}
	return 0
}

// MaxRiskLevel returns the higher of two risk levels
func MaxRiskLevel(a, b string) string {
	if CompareRiskLevels(a, b) >= 0 {
		return a
	}
	return b
}

// RiskLevelFromScore converts a numeric score to a risk level
func RiskLevelFromScore(score int) string {
	switch {
	case score >= 80:
		return RiskCritical
	case score >= 50:
		return RiskHigh
	case score >= 25:
		return RiskMedium
	case score > 0:
		return RiskLow
	default:
		return RiskNone
	}
}

// RiskCounts tracks counts of findings by risk level
type RiskCounts struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Info     int
	Total    int
}

// Add increments the appropriate counter based on risk level
func (rc *RiskCounts) Add(level string) {
	rc.Total++
	switch level {
	case RiskCritical:
		rc.Critical++
	case RiskHigh:
		rc.High++
	case RiskMedium:
		rc.Medium++
	case RiskLow:
		rc.Low++
	case RiskInfo, RiskNone:
		rc.Info++
	}
}

// Summary returns a formatted summary string
func (rc *RiskCounts) Summary() string {
	parts := []string{}
	if rc.Critical > 0 {
		parts = append(parts, fmt.Sprintf("%d CRITICAL", rc.Critical))
	}
	if rc.High > 0 {
		parts = append(parts, fmt.Sprintf("%d HIGH", rc.High))
	}
	if rc.Medium > 0 {
		parts = append(parts, fmt.Sprintf("%d MEDIUM", rc.Medium))
	}
	if rc.Low > 0 {
		parts = append(parts, fmt.Sprintf("%d LOW", rc.Low))
	}
	if len(parts) == 0 {
		return "No risks found"
	}
	return strings.Join(parts, ", ")
}

// HasHighRisk returns true if there are any CRITICAL or HIGH findings
func (rc *RiskCounts) HasHighRisk() bool {
	return rc.Critical > 0 || rc.High > 0
}

// Common risk assessment functions for GCP resources

// AssessPublicAccessRisk returns risk level for public access configuration
func AssessPublicAccessRisk(isPublic bool, hasAllUsers bool, hasAllAuthenticatedUsers bool) string {
	if hasAllUsers {
		return RiskCritical // Publicly accessible to everyone
	}
	if hasAllAuthenticatedUsers {
		return RiskHigh // Accessible to any Google account
	}
	if isPublic {
		return RiskMedium // Some form of public access
	}
	return RiskNone
}

// AssessEncryptionRisk returns risk level for encryption configuration
func AssessEncryptionRisk(encryptionEnabled bool, usesCMEK bool) string {
	if !encryptionEnabled {
		return RiskHigh // No encryption
	}
	if !usesCMEK {
		return RiskLow // Google-managed keys (default)
	}
	return RiskNone // Customer-managed keys
}

// AssessLoggingRisk returns risk level for logging configuration
func AssessLoggingRisk(loggingEnabled bool) string {
	if !loggingEnabled {
		return RiskMedium // No audit trail
	}
	return RiskNone
}

// DangerousPermissionCategories defines categories of dangerous permissions
var DangerousPermissionCategories = map[string]string{
	// Privilege Escalation
	"iam.serviceAccountKeys.create":           "privesc",
	"iam.serviceAccounts.actAs":               "privesc",
	"iam.serviceAccounts.getAccessToken":      "privesc",
	"iam.serviceAccounts.implicitDelegation":  "privesc",
	"iam.serviceAccounts.signBlob":            "privesc",
	"iam.serviceAccounts.signJwt":             "privesc",
	"deploymentmanager.deployments.create":    "privesc",
	"cloudfunctions.functions.create":         "privesc",
	"cloudfunctions.functions.update":         "privesc",
	"run.services.create":                     "privesc",
	"composer.environments.create":            "privesc",
	"dataproc.clusters.create":                "privesc",
	"cloudbuild.builds.create":                "privesc",
	"resourcemanager.projects.setIamPolicy":   "privesc",
	"resourcemanager.folders.setIamPolicy":    "privesc",
	"resourcemanager.organizations.setIamPolicy": "privesc",

	// Lateral Movement
	"compute.instances.setMetadata":     "lateral",
	"compute.projects.setCommonInstanceMetadata": "lateral",
	"compute.instances.setServiceAccount": "lateral",
	"container.clusters.getCredentials": "lateral",

	// Data Exfiltration
	"storage.objects.get":         "exfil",
	"storage.objects.list":        "exfil",
	"bigquery.tables.getData":     "exfil",
	"bigquery.jobs.create":        "exfil",
	"secretmanager.versions.access": "exfil",
	"cloudkms.cryptoKeyVersions.useToDecrypt": "exfil",
}

// IsDangerousPermission checks if a permission is considered dangerous
func IsDangerousPermission(permission string) bool {
	_, exists := DangerousPermissionCategories[permission]
	return exists
}

// GetPermissionCategory returns the risk category for a permission
func GetPermissionCategory(permission string) string {
	if cat, exists := DangerousPermissionCategories[permission]; exists {
		return cat
	}
	return ""
}

// AssessPermissionRisk returns the risk level for a specific permission
func AssessPermissionRisk(permission string) string {
	category := GetPermissionCategory(permission)
	switch category {
	case "privesc":
		return RiskCritical
	case "lateral":
		return RiskHigh
	case "exfil":
		return RiskHigh
	default:
		return RiskLow
	}
}

// HighPrivilegeRoles lists roles that grant significant permissions
var HighPrivilegeRoles = map[string]string{
	"roles/owner":                      RiskCritical,
	"roles/editor":                     RiskCritical,
	"roles/iam.securityAdmin":          RiskCritical,
	"roles/iam.serviceAccountAdmin":    RiskCritical,
	"roles/iam.serviceAccountKeyAdmin": RiskCritical,
	"roles/iam.serviceAccountTokenCreator": RiskCritical,
	"roles/iam.serviceAccountUser":     RiskHigh,
	"roles/iam.workloadIdentityUser":   RiskHigh,
	"roles/storage.admin":              RiskHigh,
	"roles/bigquery.admin":             RiskHigh,
	"roles/secretmanager.admin":        RiskHigh,
	"roles/cloudkms.admin":             RiskHigh,
	"roles/compute.admin":              RiskHigh,
	"roles/container.admin":            RiskHigh,
	"roles/cloudfunctions.admin":       RiskHigh,
	"roles/run.admin":                  RiskHigh,
	"roles/cloudsql.admin":             RiskHigh,
	"roles/dataproc.admin":             RiskHigh,
	"roles/composer.admin":             RiskHigh,
}

// AssessRoleRisk returns the risk level for a given role
func AssessRoleRisk(role string) string {
	if level, exists := HighPrivilegeRoles[role]; exists {
		return level
	}
	// Check for admin patterns
	if strings.HasSuffix(role, ".admin") || strings.Contains(role, "Admin") {
		return RiskMedium
	}
	return RiskLow
}
