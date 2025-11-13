package kubernetes

import (
	"regexp"
	"strings"
)

// --- Regex matchers for role formats ---

// AWS IAM role ARN
var awsRoleRegex = regexp.MustCompile(`^arn:aws:iam::\d{12}:role\/[A-Za-z0-9+=,.@\-_/]+$`)

// GCP Service Account email
var gcpSARegex = regexp.MustCompile(`^[a-zA-Z0-9\-]+@[a-z0-9\-]+\.iam\.gserviceaccount\.com$`)

// Azure Managed Identity clientID or resourceID
var azureMIRegex = regexp.MustCompile(`^[0-9a-fA-F\-]{36}$`)

// --- Helpers ---

func IsAWSRoleArn(s string) bool {
	return awsRoleRegex.MatchString(strings.TrimSpace(s))
}

func IsGCPServiceAccount(s string) bool {
	return gcpSARegex.MatchString(strings.TrimSpace(s))
}

func IsAzureManagedIdentity(s string) bool {
	return azureMIRegex.MatchString(strings.TrimSpace(s))
}

// Classify string into provider/role
func ClassifyCloudRole(s string) (provider, role string, ok bool) {
	if IsAWSRoleArn(s) {
		return "AWS", s, true
	}
	if IsGCPServiceAccount(s) {
		return "GCP", s, true
	}
	if IsAzureManagedIdentity(s) {
		return "Azure", s, true
	}
	return "", "", false
}

// SafeGet fetches a map key safely
func SafeGet(m map[string]string, key string) string {
	if m == nil {
		return ""
	}
	return m[key]
}
