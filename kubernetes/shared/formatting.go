package shared

import (
	"fmt"
	"strings"
	"time"
)

// Boolean formatting - standardized Yes/No display
func FormatBool(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

// FormatBoolPtr formats a *bool with default for nil
func FormatBoolPtr(b *bool, defaultVal string) string {
	if b == nil {
		return defaultVal
	}
	return FormatBool(*b)
}

// NonEmpty returns the string or a default if empty
func NonEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// NonEmptyDefault returns the string or specified default if empty
func NonEmptyDefault(s, defaultVal string) string {
	if s == "" {
		return defaultVal
	}
	return s
}

// FormatList returns comma-separated list or default if empty
func FormatList(items []string) string {
	if len(items) == 0 {
		return "-"
	}
	return strings.Join(items, ", ")
}

// FormatListTruncated returns truncated list with count of remaining items
func FormatListTruncated(items []string, maxItems int) string {
	if len(items) == 0 {
		return "-"
	}
	if len(items) <= maxItems {
		return strings.Join(items, ", ")
	}
	shown := strings.Join(items[:maxItems], ", ")
	return fmt.Sprintf("%s (+%d more)", shown, len(items)-maxItems)
}

// FormatListMax is an alias for FormatListTruncated with default max of 3
func FormatListMax(items []string) string {
	return FormatListTruncated(items, 3)
}

// FormatCount returns formatted count string
func FormatCount(count int, singular, plural string) string {
	if count == 1 {
		return fmt.Sprintf("%d %s", count, singular)
	}
	return fmt.Sprintf("%d %s", count, plural)
}

// FormatAge returns human-readable age string
func FormatAge(t time.Time) string {
	if t.IsZero() {
		return "-"
	}

	duration := time.Since(t)

	days := int(duration.Hours() / 24)
	hours := int(duration.Hours()) % 24
	minutes := int(duration.Minutes()) % 60

	switch {
	case days > 365:
		years := days / 365
		return fmt.Sprintf("%dy", years)
	case days > 30:
		months := days / 30
		return fmt.Sprintf("%dmo", months)
	case days > 0:
		return fmt.Sprintf("%dd", days)
	case hours > 0:
		return fmt.Sprintf("%dh", hours)
	case minutes > 0:
		return fmt.Sprintf("%dm", minutes)
	default:
		return "<1m"
	}
}

// FormatAgeDuration returns human-readable duration string
func FormatAgeDuration(d time.Duration) string {
	if d == 0 {
		return "-"
	}

	days := int(d.Hours() / 24)
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60

	switch {
	case days > 365:
		years := days / 365
		return fmt.Sprintf("%dy", years)
	case days > 30:
		months := days / 30
		return fmt.Sprintf("%dmo", months)
	case days > 0:
		return fmt.Sprintf("%dd", days)
	case hours > 0:
		return fmt.Sprintf("%dh", hours)
	case minutes > 0:
		return fmt.Sprintf("%dm", minutes)
	default:
		return "<1m"
	}
}

// FormatInt returns string representation of int
func FormatInt(i int) string {
	return fmt.Sprintf("%d", i)
}

// FormatInt64 returns string representation of int64
func FormatInt64(i int64) string {
	return fmt.Sprintf("%d", i)
}

// FormatPercentage returns formatted percentage
func FormatPercentage(value, total int) string {
	if total == 0 {
		return "0%"
	}
	return fmt.Sprintf("%.0f%%", float64(value)/float64(total)*100)
}

// FormatBytes returns human-readable byte size
func FormatBytes(bytes int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
		TB = GB * 1024
	)

	switch {
	case bytes >= TB:
		return fmt.Sprintf("%.1fTi", float64(bytes)/TB)
	case bytes >= GB:
		return fmt.Sprintf("%.1fGi", float64(bytes)/GB)
	case bytes >= MB:
		return fmt.Sprintf("%.1fMi", float64(bytes)/MB)
	case bytes >= KB:
		return fmt.Sprintf("%.1fKi", float64(bytes)/KB)
	default:
		return fmt.Sprintf("%dB", bytes)
	}
}

// TruncateString truncates string to max length with ellipsis
func TruncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// UniqueStrings returns unique strings from slice
func UniqueStrings(items []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(items))
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}

// Contains checks if slice contains string
func Contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// ContainsAny checks if slice contains any of the items
func ContainsAny(slice []string, items ...string) bool {
	for _, item := range items {
		if Contains(slice, item) {
			return true
		}
	}
	return false
}

// FilterNonEmpty returns only non-empty strings
func FilterNonEmpty(items []string) []string {
	result := make([]string, 0, len(items))
	for _, item := range items {
		if item != "" {
			result = append(result, item)
		}
	}
	return result
}

// JoinNonEmpty joins non-empty strings with separator
func JoinNonEmpty(items []string, sep string) string {
	return strings.Join(FilterNonEmpty(items), sep)
}
