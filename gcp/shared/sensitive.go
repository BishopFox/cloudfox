package shared

import (
	"regexp"
	"strings"
)

// SensitivePattern defines a pattern for matching file/object names or resource names.
type SensitivePattern struct {
	Pattern     string
	Category    string
	RiskLevel   string
	Description string
}

// ContentPattern defines a regex-based pattern for matching inside text content.
type ContentPattern struct {
	Regex       *regexp.Regexp
	Category    string
	RiskLevel   string
	Description string
}

// SensitiveMatch represents a file/resource name match result.
type SensitiveMatch struct {
	Pattern     string
	Category    string
	RiskLevel   string
	Description string
	MatchedText string
}

// ContentMatch represents a content regex match result.
type ContentMatch struct {
	Pattern     string
	Category    string
	RiskLevel   string
	Description string
	MatchedText string
	Snippet     string // surrounding context
}

// GetFilePatterns returns patterns for detecting sensitive files in bucket/object names.
// These are the same patterns previously defined in bucketEnumService.
func GetFilePatterns() []SensitivePattern {
	return []SensitivePattern{
		// Credentials - CRITICAL
		{Pattern: ".json", Category: "Credential", RiskLevel: "CRITICAL", Description: "Service account key file"},
		{Pattern: "credentials.json", Category: "Credential", RiskLevel: "CRITICAL", Description: "GCP credentials file"},
		{Pattern: "service-account", Category: "Credential", RiskLevel: "CRITICAL", Description: "Service account key"},
		{Pattern: "keyfile", Category: "Credential", RiskLevel: "CRITICAL", Description: "Key file"},
		{Pattern: ".pem", Category: "Credential", RiskLevel: "CRITICAL", Description: "PEM private key"},
		{Pattern: ".key", Category: "Credential", RiskLevel: "CRITICAL", Description: "Private key file"},
		{Pattern: ".p12", Category: "Credential", RiskLevel: "CRITICAL", Description: "PKCS12 key file"},
		{Pattern: ".pfx", Category: "Credential", RiskLevel: "CRITICAL", Description: "PFX certificate file"},
		{Pattern: "id_rsa", Category: "Credential", RiskLevel: "CRITICAL", Description: "SSH private key"},
		{Pattern: "id_ed25519", Category: "Credential", RiskLevel: "CRITICAL", Description: "SSH private key (ed25519)"},
		{Pattern: "id_ecdsa", Category: "Credential", RiskLevel: "CRITICAL", Description: "SSH private key (ECDSA)"},

		// Secrets - CRITICAL/HIGH
		{Pattern: ".env", Category: "Secret", RiskLevel: "CRITICAL", Description: "Environment variables (may contain secrets)"},
		{Pattern: "secrets", Category: "Secret", RiskLevel: "HIGH", Description: "Secrets file or directory"},
		{Pattern: "password", Category: "Secret", RiskLevel: "HIGH", Description: "Password file"},
		{Pattern: "api_key", Category: "Secret", RiskLevel: "HIGH", Description: "API key file"},
		{Pattern: "apikey", Category: "Secret", RiskLevel: "HIGH", Description: "API key file"},
		{Pattern: "token", Category: "Secret", RiskLevel: "HIGH", Description: "Token file"},
		{Pattern: "auth", Category: "Secret", RiskLevel: "HIGH", Description: "Authentication file"},
		{Pattern: ".htpasswd", Category: "Secret", RiskLevel: "HIGH", Description: "HTTP password file"},
		{Pattern: ".netrc", Category: "Secret", RiskLevel: "HIGH", Description: "FTP/other credentials"},

		// Config files - HIGH/MEDIUM
		{Pattern: "config", Category: "Config", RiskLevel: "MEDIUM", Description: "Configuration file"},
		{Pattern: ".yaml", Category: "Config", RiskLevel: "MEDIUM", Description: "YAML config (may contain secrets)"},
		{Pattern: ".yml", Category: "Config", RiskLevel: "MEDIUM", Description: "YAML config (may contain secrets)"},
		{Pattern: "application.properties", Category: "Config", RiskLevel: "HIGH", Description: "Java app config"},
		{Pattern: "web.config", Category: "Config", RiskLevel: "HIGH", Description: ".NET config"},
		{Pattern: "appsettings.json", Category: "Config", RiskLevel: "HIGH", Description: ".NET app settings"},
		{Pattern: "settings.py", Category: "Config", RiskLevel: "HIGH", Description: "Django settings"},
		{Pattern: "database.yml", Category: "Config", RiskLevel: "HIGH", Description: "Rails database config"},
		{Pattern: "wp-config.php", Category: "Config", RiskLevel: "HIGH", Description: "WordPress config"},
		{Pattern: ".npmrc", Category: "Config", RiskLevel: "HIGH", Description: "NPM config (may contain tokens)"},
		{Pattern: ".dockercfg", Category: "Config", RiskLevel: "HIGH", Description: "Docker registry credentials"},
		{Pattern: "docker-compose", Category: "Config", RiskLevel: "MEDIUM", Description: "Docker compose config"},
		{Pattern: "terraform.tfstate", Category: "Config", RiskLevel: "CRITICAL", Description: "Terraform state (contains secrets)"},
		{Pattern: ".tfstate", Category: "Config", RiskLevel: "CRITICAL", Description: "Terraform state file"},
		{Pattern: "terraform.tfvars", Category: "Config", RiskLevel: "HIGH", Description: "Terraform variables"},
		{Pattern: "kubeconfig", Category: "Config", RiskLevel: "CRITICAL", Description: "Kubernetes config"},
		{Pattern: ".kube/config", Category: "Config", RiskLevel: "CRITICAL", Description: "Kubernetes config"},

		// Backups - HIGH
		{Pattern: ".sql", Category: "Backup", RiskLevel: "HIGH", Description: "SQL database dump"},
		{Pattern: ".dump", Category: "Backup", RiskLevel: "HIGH", Description: "Database dump"},
		{Pattern: ".bak", Category: "Backup", RiskLevel: "MEDIUM", Description: "Backup file"},
		{Pattern: "backup", Category: "Backup", RiskLevel: "MEDIUM", Description: "Backup file/directory"},
		{Pattern: ".tar.gz", Category: "Backup", RiskLevel: "MEDIUM", Description: "Compressed archive"},
		{Pattern: ".zip", Category: "Backup", RiskLevel: "MEDIUM", Description: "ZIP archive"},

		// Source code - MEDIUM
		{Pattern: ".git", Category: "Source", RiskLevel: "MEDIUM", Description: "Git repository data"},
		{Pattern: "source", Category: "Source", RiskLevel: "LOW", Description: "Source code"},

		// Logs - LOW (but may contain sensitive data)
		{Pattern: ".log", Category: "Log", RiskLevel: "LOW", Description: "Log file (may contain sensitive data)"},
		{Pattern: "access.log", Category: "Log", RiskLevel: "MEDIUM", Description: "Access log"},
		{Pattern: "error.log", Category: "Log", RiskLevel: "MEDIUM", Description: "Error log"},

		// Cloud-specific
		{Pattern: "cloudfunctions", Category: "Cloud", RiskLevel: "MEDIUM", Description: "Cloud Functions source"},
		{Pattern: "gcf-sources", Category: "Cloud", RiskLevel: "MEDIUM", Description: "Cloud Functions source bucket"},
		{Pattern: "cloud-build", Category: "Cloud", RiskLevel: "MEDIUM", Description: "Cloud Build artifacts"},
		{Pattern: "artifacts", Category: "Cloud", RiskLevel: "LOW", Description: "Build artifacts"},
	}
}

// contentPatterns is the compiled list, initialized once.
var contentPatterns []ContentPattern

func init() {
	contentPatterns = compileContentPatterns()
}

func compileContentPatterns() []ContentPattern {
	defs := []struct {
		pattern     string
		category    string
		riskLevel   string
		description string
	}{
		// Credentials - CRITICAL
		{`"type"\s*:\s*"service_account"`, "Credential", "CRITICAL", "GCP service account key JSON"},
		{`-----BEGIN\s*(RSA|EC|DSA|OPENSSH)?\s*PRIVATE KEY-----`, "Credential", "CRITICAL", "Private key"},
		{`AKIA[0-9A-Z]{16}`, "Credential", "CRITICAL", "AWS access key"},
		{`AIza[0-9A-Za-z_\-]{35}`, "Credential", "CRITICAL", "GCP API key"},

		// Secrets - HIGH
		{`(?i)(password|passwd|pwd)\s*[:=]\s*\S+`, "Secret", "HIGH", "Password assignment"},
		{`(?i)bearer\s+[a-zA-Z0-9_\-\.]+`, "Secret", "HIGH", "Bearer token"},
		{`(?i)(jdbc|mongodb|mysql|postgres|redis)://[^\s]+`, "Secret", "HIGH", "Connection string"},

		// Tokens - HIGH
		{`eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*`, "Token", "HIGH", "JWT token"},
		{`ya29\.[0-9A-Za-z_-]+`, "Token", "HIGH", "GCP OAuth token"},
		{`gh[ps]_[A-Za-z0-9_]{36,}`, "Token", "HIGH", "GitHub token"},

		// PII - MEDIUM
		{`\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b`, "PII", "MEDIUM", "Credit card number"},
		{`\b\d{3}-\d{2}-\d{4}\b`, "PII", "MEDIUM", "SSN pattern"},
	}

	patterns := make([]ContentPattern, 0, len(defs))
	for _, d := range defs {
		compiled := regexp.MustCompile(d.pattern)
		patterns = append(patterns, ContentPattern{
			Regex:       compiled,
			Category:    d.category,
			RiskLevel:   d.riskLevel,
			Description: d.description,
		})
	}
	return patterns
}

// GetContentPatterns returns regex-based patterns for matching inside text content
// (log entries, query results, etc.).
func GetContentPatterns() []ContentPattern {
	return contentPatterns
}

// GetNamePatterns returns patterns for detecting sensitive resource names
// (table names, column names, dataset names).
func GetNamePatterns() []SensitivePattern {
	return []SensitivePattern{
		// Credentials/keys
		{Pattern: "password", Category: "Credential", RiskLevel: "HIGH", Description: "Password-related resource"},
		{Pattern: "passwd", Category: "Credential", RiskLevel: "HIGH", Description: "Password-related resource"},
		{Pattern: "secret", Category: "Credential", RiskLevel: "HIGH", Description: "Secret-related resource"},
		{Pattern: "credential", Category: "Credential", RiskLevel: "HIGH", Description: "Credential-related resource"},
		{Pattern: "token", Category: "Credential", RiskLevel: "HIGH", Description: "Token-related resource"},
		{Pattern: "auth", Category: "Credential", RiskLevel: "MEDIUM", Description: "Authentication-related resource"},
		{Pattern: "private_key", Category: "Credential", RiskLevel: "CRITICAL", Description: "Private key resource"},
		{Pattern: "api_key", Category: "Credential", RiskLevel: "HIGH", Description: "API key resource"},
		{Pattern: "access_key", Category: "Credential", RiskLevel: "HIGH", Description: "Access key resource"},
		{Pattern: "encryption_key", Category: "Credential", RiskLevel: "HIGH", Description: "Encryption key resource"},

		// PII
		{Pattern: "ssn", Category: "PII", RiskLevel: "HIGH", Description: "SSN-related resource"},
		{Pattern: "social_security", Category: "PII", RiskLevel: "HIGH", Description: "Social security resource"},
		{Pattern: "credit_card", Category: "PII", RiskLevel: "HIGH", Description: "Credit card resource"},
		{Pattern: "cc_number", Category: "PII", RiskLevel: "HIGH", Description: "Credit card number resource"},
		{Pattern: "cvv", Category: "PII", RiskLevel: "HIGH", Description: "CVV resource"},

		// Compliance
		{Pattern: "pii", Category: "Compliance", RiskLevel: "HIGH", Description: "PII-labeled resource"},
		{Pattern: "phi", Category: "Compliance", RiskLevel: "HIGH", Description: "PHI-labeled resource"},
		{Pattern: "hipaa", Category: "Compliance", RiskLevel: "HIGH", Description: "HIPAA-labeled resource"},
		{Pattern: "gdpr", Category: "Compliance", RiskLevel: "HIGH", Description: "GDPR-labeled resource"},
		{Pattern: "sensitive", Category: "Compliance", RiskLevel: "MEDIUM", Description: "Sensitive-labeled resource"},

		// Financial
		{Pattern: "payment", Category: "Financial", RiskLevel: "HIGH", Description: "Payment-related resource"},
		{Pattern: "billing", Category: "Financial", RiskLevel: "MEDIUM", Description: "Billing-related resource"},
		{Pattern: "financial", Category: "Financial", RiskLevel: "HIGH", Description: "Financial resource"},
		{Pattern: "salary", Category: "Financial", RiskLevel: "HIGH", Description: "Salary-related resource"},
		{Pattern: "bank", Category: "Financial", RiskLevel: "HIGH", Description: "Banking-related resource"},

		// General sensitive data
		{Pattern: "user_data", Category: "Data", RiskLevel: "MEDIUM", Description: "User data resource"},
		{Pattern: "customer_data", Category: "Data", RiskLevel: "MEDIUM", Description: "Customer data resource"},
		{Pattern: "personal", Category: "Data", RiskLevel: "MEDIUM", Description: "Personal data resource"},
		{Pattern: "confidential", Category: "Data", RiskLevel: "HIGH", Description: "Confidential resource"},
	}
}

// MatchFileName checks an object/file name against file patterns.
// Returns the first match, or nil if no match.
func MatchFileName(objectName string, patterns []SensitivePattern) *SensitiveMatch {
	name := strings.ToLower(objectName)
	ext := strings.ToLower(fileExt(objectName))
	baseName := strings.ToLower(fileBase(objectName))

	for _, pattern := range patterns {
		matched := false
		patternLower := strings.ToLower(pattern.Pattern)

		// Check extension match
		if strings.HasPrefix(patternLower, ".") && ext == patternLower {
			matched = true
		}
		// Check name contains pattern
		if strings.Contains(name, patternLower) {
			matched = true
		}
		// Check base name match
		if strings.Contains(baseName, patternLower) {
			matched = true
		}

		if matched {
			if IsFilePathFalsePositive(objectName, pattern) {
				continue
			}
			return &SensitiveMatch{
				Pattern:     pattern.Pattern,
				Category:    pattern.Category,
				RiskLevel:   pattern.RiskLevel,
				Description: pattern.Description,
				MatchedText: objectName,
			}
		}
	}
	return nil
}

// MatchContent checks text content against content patterns.
// Returns all matches found.
func MatchContent(text string, patterns []ContentPattern) []ContentMatch {
	var matches []ContentMatch
	for _, pattern := range patterns {
		locs := pattern.Regex.FindAllStringIndex(text, -1)
		for _, loc := range locs {
			matchedText := text[loc[0]:loc[1]]
			snippet := extractSnippet(text, loc[0], loc[1], 50)
			matches = append(matches, ContentMatch{
				Pattern:     pattern.Regex.String(),
				Category:    pattern.Category,
				RiskLevel:   pattern.RiskLevel,
				Description: pattern.Description,
				MatchedText: matchedText,
				Snippet:     snippet,
			})
		}
	}
	return matches
}

// MatchResourceName checks a resource name (table, column, dataset) against name patterns.
// Uses case-insensitive substring matching. Returns the first match, or nil.
func MatchResourceName(name string, patterns []SensitivePattern) *SensitiveMatch {
	nameLower := strings.ToLower(name)
	for _, pattern := range patterns {
		patternLower := strings.ToLower(pattern.Pattern)
		if strings.Contains(nameLower, patternLower) {
			return &SensitiveMatch{
				Pattern:     pattern.Pattern,
				Category:    pattern.Category,
				RiskLevel:   pattern.RiskLevel,
				Description: pattern.Description,
				MatchedText: name,
			}
		}
	}
	return nil
}

// IsFilePathFalsePositive checks if a file path match is a common false positive.
func IsFilePathFalsePositive(path string, pattern SensitivePattern) bool {
	nameLower := strings.ToLower(path)

	// Filter out common false positive paths
	falsePositivePaths := []string{
		"node_modules/",
		"vendor/",
		".git/objects/",
		"__pycache__/",
		"dist/",
		"build/",
	}

	for _, fp := range falsePositivePaths {
		if strings.Contains(nameLower, fp) {
			return true
		}
	}

	// JSON files that are likely not credentials
	if pattern.Pattern == ".json" {
		if !strings.Contains(nameLower, "service") &&
			!strings.Contains(nameLower, "account") &&
			!strings.Contains(nameLower, "credential") &&
			!strings.Contains(nameLower, "key") &&
			!strings.Contains(nameLower, "secret") &&
			!strings.Contains(nameLower, "auth") {
			return true
		}
	}

	return false
}

// extractSnippet returns surrounding context around a match.
func extractSnippet(text string, start, end, contextLen int) string {
	snippetStart := start - contextLen
	if snippetStart < 0 {
		snippetStart = 0
	}
	snippetEnd := end + contextLen
	if snippetEnd > len(text) {
		snippetEnd = len(text)
	}
	snippet := text[snippetStart:snippetEnd]
	// Replace newlines with spaces for cleaner output
	snippet = strings.ReplaceAll(snippet, "\n", " ")
	snippet = strings.ReplaceAll(snippet, "\r", "")
	return snippet
}

// fileExt returns the file extension (e.g., ".json").
func fileExt(name string) string {
	for i := len(name) - 1; i >= 0; i-- {
		if name[i] == '.' {
			return name[i:]
		}
		if name[i] == '/' {
			return ""
		}
	}
	return ""
}

// fileBase returns the last component of a path.
func fileBase(name string) string {
	for i := len(name) - 1; i >= 0; i-- {
		if name[i] == '/' {
			return name[i+1:]
		}
	}
	return name
}
