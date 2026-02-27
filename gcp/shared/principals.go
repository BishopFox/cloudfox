// Package shared provides common utilities for GCP CloudFox modules.
// This package contains helper functions for IAM principals, formatting,
// risk assessment, and other cross-cutting concerns.
package shared

import "strings"

// PrincipalType constants for IAM member types
const (
	PrincipalTypePublic             = "PUBLIC"
	PrincipalTypeAllAuthenticated   = "ALL_AUTHENTICATED"
	PrincipalTypeUser               = "User"
	PrincipalTypeServiceAccount     = "ServiceAccount"
	PrincipalTypeGroup              = "Group"
	PrincipalTypeDomain             = "Domain"
	PrincipalTypeProjectOwner       = "ProjectOwner"
	PrincipalTypeProjectEditor      = "ProjectEditor"
	PrincipalTypeProjectViewer      = "ProjectViewer"
	PrincipalTypeDeleted            = "Deleted"
	PrincipalTypeUnknown            = "Unknown"
)

// Lowercase principal type constants (for consistency with some existing code)
const (
	PrincipalTypeLowerUser           = "user"
	PrincipalTypeLowerServiceAccount = "serviceAccount"
	PrincipalTypeLowerGroup          = "group"
	PrincipalTypeLowerUnknown        = "unknown"
)

// GetPrincipalType extracts the type of an IAM principal from its full member string.
// This handles the standard GCP IAM member format (e.g., "user:email@example.com").
// Returns a capitalized type suitable for table display.
//
// Examples:
//   - "allUsers" -> "PUBLIC"
//   - "allAuthenticatedUsers" -> "ALL_AUTHENTICATED"
//   - "user:admin@example.com" -> "User"
//   - "serviceAccount:sa@project.iam.gserviceaccount.com" -> "ServiceAccount"
//   - "group:devs@example.com" -> "Group"
//   - "domain:example.com" -> "Domain"
func GetPrincipalType(member string) string {
	switch {
	case member == "allUsers":
		return PrincipalTypePublic
	case member == "allAuthenticatedUsers":
		return PrincipalTypeAllAuthenticated
	case strings.HasPrefix(member, "user:"):
		return PrincipalTypeUser
	case strings.HasPrefix(member, "serviceAccount:"):
		return PrincipalTypeServiceAccount
	case strings.HasPrefix(member, "group:"):
		return PrincipalTypeGroup
	case strings.HasPrefix(member, "domain:"):
		return PrincipalTypeDomain
	case strings.HasPrefix(member, "projectOwner:"):
		return PrincipalTypeProjectOwner
	case strings.HasPrefix(member, "projectEditor:"):
		return PrincipalTypeProjectEditor
	case strings.HasPrefix(member, "projectViewer:"):
		return PrincipalTypeProjectViewer
	case strings.HasPrefix(member, "deleted:"):
		return PrincipalTypeDeleted
	default:
		return PrincipalTypeUnknown
	}
}

// GetPrincipalTypeLower returns the principal type in lowercase format.
// This is useful when consistent lowercase output is needed.
//
// Examples:
//   - "user:admin@example.com" -> "user"
//   - "serviceAccount:sa@project.iam.gserviceaccount.com" -> "serviceAccount"
//   - "group:devs@example.com" -> "group"
func GetPrincipalTypeLower(principal string) string {
	if strings.HasPrefix(principal, "user:") {
		return PrincipalTypeLowerUser
	} else if strings.HasPrefix(principal, "serviceAccount:") {
		return PrincipalTypeLowerServiceAccount
	} else if strings.HasPrefix(principal, "group:") {
		return PrincipalTypeLowerGroup
	}
	return PrincipalTypeLowerUnknown
}

// ExtractPrincipalEmail extracts the email/identifier from an IAM member string.
// Returns the part after the ":" prefix, or the original string if no prefix found.
//
// Examples:
//   - "user:admin@example.com" -> "admin@example.com"
//   - "serviceAccount:sa@project.iam.gserviceaccount.com" -> "sa@project.iam.gserviceaccount.com"
//   - "allUsers" -> "allUsers"
func ExtractPrincipalEmail(member string) string {
	if idx := strings.Index(member, ":"); idx != -1 {
		return member[idx+1:]
	}
	return member
}

// IsPublicPrincipal checks if a principal represents public access.
// Returns true for "allUsers" or "allAuthenticatedUsers".
func IsPublicPrincipal(member string) bool {
	return member == "allUsers" || member == "allAuthenticatedUsers"
}

// IsServiceAccount checks if a principal is a service account.
func IsServiceAccount(member string) bool {
	return strings.HasPrefix(member, "serviceAccount:")
}

// IsUser checks if a principal is a user.
func IsUser(member string) bool {
	return strings.HasPrefix(member, "user:")
}

// IsGroup checks if a principal is a group.
func IsGroup(member string) bool {
	return strings.HasPrefix(member, "group:")
}

// IsDeleted checks if a principal has been deleted.
func IsDeleted(member string) bool {
	return strings.HasPrefix(member, "deleted:")
}

// ExtractServiceAccountProject extracts the project ID from a service account email.
// Service account format: name@project-id.iam.gserviceaccount.com
// Returns empty string if not a valid service account format.
func ExtractServiceAccountProject(saEmail string) string {
	// Handle prefixed format
	email := ExtractPrincipalEmail(saEmail)

	// Check for .iam.gserviceaccount.com suffix
	suffix := ".iam.gserviceaccount.com"
	if !strings.HasSuffix(email, suffix) {
		return ""
	}

	// Extract project from name@project-id.iam.gserviceaccount.com
	atIdx := strings.Index(email, "@")
	if atIdx == -1 {
		return ""
	}

	projectPart := email[atIdx+1 : len(email)-len(suffix)]
	return projectPart
}

// IsDefaultServiceAccount checks if a service account is a default compute or app engine SA.
// Default SAs follow patterns like:
//   - PROJECT_NUMBER-compute@developer.gserviceaccount.com
//   - PROJECT_ID@appspot.gserviceaccount.com
func IsDefaultServiceAccount(saEmail string) bool {
	email := ExtractPrincipalEmail(saEmail)
	return strings.HasSuffix(email, "@developer.gserviceaccount.com") ||
		strings.HasSuffix(email, "@appspot.gserviceaccount.com")
}

// IsGoogleManagedServiceAccount checks if a service account is managed by Google.
// These typically have formats like:
//   - service-PROJECT_NUMBER@*.iam.gserviceaccount.com
//   - PROJECT_NUMBER@cloudservices.gserviceaccount.com
func IsGoogleManagedServiceAccount(saEmail string) bool {
	email := ExtractPrincipalEmail(saEmail)
	return strings.HasPrefix(email, "service-") ||
		strings.Contains(email, "@cloudservices.gserviceaccount.com") ||
		strings.Contains(email, "@cloud-ml.google.com.iam.gserviceaccount.com") ||
		strings.Contains(email, "@gcp-sa-")
}
