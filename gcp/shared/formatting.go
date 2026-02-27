package shared

import (
	"fmt"
	"strings"
)

// BoolToYesNo converts a boolean to "Yes" or "No" string.
// Useful for table display where boolean values should be human-readable.
func BoolToYesNo(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

// BoolToEnabled converts a boolean to "Enabled" or "Disabled" string.
func BoolToEnabled(b bool) string {
	if b {
		return "Enabled"
	}
	return "Disabled"
}

// BoolToCheck converts a boolean to a checkmark or empty string.
// Useful for table columns showing presence/absence of a feature.
func BoolToCheck(b bool) string {
	if b {
		return "✓"
	}
	return ""
}

// BoolToStatus converts a boolean to "Active" or "Inactive" string.
func BoolToStatus(b bool) string {
	if b {
		return "Active"
	}
	return "Inactive"
}

// TruncateString truncates a string to maxLen characters, adding "..." if truncated.
func TruncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// TruncateMiddle truncates a string in the middle, keeping the start and end.
// Useful for long resource names where both prefix and suffix are informative.
func TruncateMiddle(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 5 {
		return s[:maxLen]
	}
	keepLen := (maxLen - 3) / 2
	return s[:keepLen] + "..." + s[len(s)-keepLen:]
}

// FormatList formats a slice of strings for table display.
// If the list is longer than maxItems, it truncates and adds a count.
//
// Examples:
//   - ["a", "b"] -> "a, b"
//   - ["a", "b", "c", "d", "e"] with maxItems=3 -> "a, b, c (+2 more)"
func FormatList(items []string, maxItems int) string {
	if len(items) == 0 {
		return "-"
	}
	if maxItems <= 0 || len(items) <= maxItems {
		return strings.Join(items, ", ")
	}
	shown := strings.Join(items[:maxItems], ", ")
	return fmt.Sprintf("%s (+%d more)", shown, len(items)-maxItems)
}

// FormatCount formats a count with appropriate singular/plural suffix.
//
// Examples:
//   - FormatCount(0, "item", "items") -> "0 items"
//   - FormatCount(1, "item", "items") -> "1 item"
//   - FormatCount(5, "item", "items") -> "5 items"
func FormatCount(count int, singular, plural string) string {
	if count == 1 {
		return fmt.Sprintf("%d %s", count, singular)
	}
	return fmt.Sprintf("%d %s", count, plural)
}

// FormatBytes formats a byte count as a human-readable string.
func FormatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// DefaultString returns the value if non-empty, otherwise returns the default.
func DefaultString(value, defaultValue string) string {
	if value == "" {
		return defaultValue
	}
	return value
}

// DefaultInt returns the value if non-zero, otherwise returns the default.
func DefaultInt(value, defaultValue int) int {
	if value == 0 {
		return defaultValue
	}
	return value
}

// JoinNonEmpty joins non-empty strings with the given separator.
// Empty strings are filtered out before joining.
func JoinNonEmpty(sep string, items ...string) string {
	var nonEmpty []string
	for _, item := range items {
		if item != "" {
			nonEmpty = append(nonEmpty, item)
		}
	}
	return strings.Join(nonEmpty, sep)
}

// ExtractResourceName extracts the last component from a resource path.
// GCP resource names often have format: projects/PROJECT/locations/LOCATION/resources/NAME
//
// Examples:
//   - "projects/my-project/locations/us-central1/functions/my-func" -> "my-func"
//   - "my-resource" -> "my-resource"
func ExtractResourceName(fullPath string) string {
	parts := strings.Split(fullPath, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return fullPath
}

// ExtractProjectFromResourceName extracts the project ID from a full resource name.
// GCP resources typically have format: projects/PROJECT_ID/...
//
// Returns empty string if project cannot be extracted.
func ExtractProjectFromResourceName(resourceName string) string {
	parts := strings.Split(resourceName, "/")
	for i, part := range parts {
		if part == "projects" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

// ExtractLocationFromResourceName extracts the location from a full resource name.
// GCP resources often have format: projects/PROJECT/locations/LOCATION/...
//
// Returns empty string if location cannot be extracted.
func ExtractLocationFromResourceName(resourceName string) string {
	parts := strings.Split(resourceName, "/")
	for i, part := range parts {
		if (part == "locations" || part == "regions" || part == "zones") && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

// SanitizeForTable removes or replaces characters that may break table formatting.
func SanitizeForTable(s string) string {
	// Replace newlines and tabs with spaces
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	// Collapse multiple spaces
	for strings.Contains(s, "  ") {
		s = strings.ReplaceAll(s, "  ", " ")
	}
	return strings.TrimSpace(s)
}

// FormatPermissionList formats a list of permissions for display.
// Optionally highlights dangerous permissions.
func FormatPermissionList(permissions []string, maxShow int) string {
	if len(permissions) == 0 {
		return "-"
	}
	return FormatList(permissions, maxShow)
}

// FormatRoleShort shortens a role name for table display.
// Removes the "roles/" prefix if present.
//
// Examples:
//   - "roles/owner" -> "owner"
//   - "roles/storage.admin" -> "storage.admin"
//   - "projects/my-project/roles/customRole" -> "customRole"
func FormatRoleShort(role string) string {
	if strings.HasPrefix(role, "roles/") {
		return strings.TrimPrefix(role, "roles/")
	}
	// Handle custom roles: projects/PROJECT/roles/ROLE or organizations/ORG/roles/ROLE
	parts := strings.Split(role, "/roles/")
	if len(parts) == 2 {
		return parts[1]
	}
	return role
}
