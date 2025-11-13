package azure

import (
	"fmt"
	"regexp"
	"strings"
)

// ------------------------------
// Secret Pattern Definitions
// ------------------------------

// SecretPattern represents a regex pattern for detecting secrets
type SecretPattern struct {
	Name               string            // Human-readable name
	Description        string            // What this pattern detects
	Regex              *regexp.Regexp    // Compiled regex
	Severity           string            // CRITICAL, HIGH, MEDIUM, LOW
	FalsePositiveCheck func(string) bool // Optional: additional validation
}

// SecretMatch represents a detected secret
type SecretMatch struct {
	Pattern        string // Pattern name that matched
	Description    string // Pattern description
	Match          string // The actual matched secret
	Context        string // Surrounding text (3 lines before/after)
	LineNumber     int    // Line number where secret was found
	SourceName     string // File/resource name where secret was found
	SourceType     string // Type: pipeline, runbook, repo, linkedservice, etc.
	Severity       string // CRITICAL, HIGH, MEDIUM, LOW
	Recommendation string // Remediation advice
}

// ------------------------------
// Global Secret Patterns
// ------------------------------

var SecretPatterns = []SecretPattern{
	// ==================== AWS CREDENTIALS ====================
	{
		Name:        "AWS Access Key",
		Description: "AWS Access Key ID (AKIA...)",
		Regex:       regexp.MustCompile(`(AKIA[0-9A-Z]{16})`),
		Severity:    "CRITICAL",
	},
	{
		Name:        "AWS Secret Access Key",
		Description: "AWS Secret Access Key (40 characters)",
		Regex:       regexp.MustCompile(`(?i)(aws_secret_access_key|aws_secret|secret_access_key)[\s]*[=:][\s]*[\"']?([A-Za-z0-9/+=]{40})[\"']?`),
		Severity:    "CRITICAL",
	},
	{
		Name:        "AWS Session Token",
		Description: "AWS Session Token",
		Regex:       regexp.MustCompile(`(?i)(aws_session_token|session_token)[\s]*[=:][\s]*[\"']?([A-Za-z0-9/+=]{100,})[\"']?`),
		Severity:    "HIGH",
	},

	// ==================== AZURE CREDENTIALS ====================
	{
		Name:        "Azure Storage Account Key",
		Description: "Azure Storage Account Key (88 characters base64)",
		Regex:       regexp.MustCompile(`(?i)(AccountKey|account_key)[\s]*=[\s]*[\"']?([A-Za-z0-9+/]{86}==)[\"']?`),
		Severity:    "CRITICAL",
	},
	{
		Name:        "Azure Connection String",
		Description: "Azure Storage/Service Bus Connection String",
		Regex:       regexp.MustCompile(`(?i)(DefaultEndpointsProtocol=https;.*AccountKey=|Endpoint=sb://.*SharedAccessKey=)`),
		Severity:    "CRITICAL",
	},
	{
		Name:        "Azure Service Principal Secret",
		Description: "Azure Service Principal Client Secret",
		Regex:       regexp.MustCompile(`(?i)(client_secret|clientSecret|azure_client_secret)[\s]*[=:][\s]*[\"']?([A-Za-z0-9_\-~\.]{34,})[\"']?`),
		Severity:    "CRITICAL",
	},
	{
		Name:        "Azure SAS Token",
		Description: "Azure Shared Access Signature Token",
		Regex:       regexp.MustCompile(`(?i)(sig=|SharedAccessSignature)[\s]*[=:]?[\s]*[\"']?([A-Za-z0-9%]{40,})[\"']?`),
		Severity:    "HIGH",
	},
	{
		Name:        "Azure Subscription Key",
		Description: "Azure API Management / Cognitive Services Subscription Key",
		Regex:       regexp.MustCompile(`(?i)(Ocp-Apim-Subscription-Key|subscription-key|subscriptionKey)[\s]*[=:][\s]*[\"']?([A-Fa-f0-9]{32})[\"']?`),
		Severity:    "HIGH",
	},

	// ==================== DATABASE CREDENTIALS ====================
	{
		Name:        "SQL Connection String",
		Description: "SQL Server Connection String with password",
		Regex:       regexp.MustCompile(`(?i)(Server|Data Source)=.*?(Password|Pwd)[\s]*=[\s]*[\"']?([^;\"']{8,})[\"']?`),
		Severity:    "CRITICAL",
	},
	{
		Name:        "PostgreSQL Connection String",
		Description: "PostgreSQL Connection String",
		Regex:       regexp.MustCompile(`(?i)postgres(ql)?://[^:]+:([^@]{8,})@`),
		Severity:    "CRITICAL",
	},
	{
		Name:        "MySQL Connection String",
		Description: "MySQL Connection String",
		Regex:       regexp.MustCompile(`(?i)mysql://[^:]+:([^@]{8,})@`),
		Severity:    "CRITICAL",
	},
	{
		Name:        "MongoDB Connection String",
		Description: "MongoDB Connection String",
		Regex:       regexp.MustCompile(`(?i)mongodb(\+srv)?://[^:]+:([^@]{8,})@`),
		Severity:    "CRITICAL",
	},
	{
		Name:        "Redis Connection String",
		Description: "Redis Connection String with password",
		Regex:       regexp.MustCompile(`(?i)redis://:[^@]{8,}@`),
		Severity:    "HIGH",
	},

	// ==================== API KEYS & TOKENS ====================
	{
		Name:        "GitHub Token",
		Description: "GitHub Personal Access Token or OAuth Token",
		Regex:       regexp.MustCompile(`(ghp_[A-Za-z0-9_]{36}|gho_[A-Za-z0-9_]{36}|ghu_[A-Za-z0-9_]{36}|ghs_[A-Za-z0-9_]{36}|ghr_[A-Za-z0-9_]{36})`),
		Severity:    "CRITICAL",
	},
	{
		Name:        "GitLab Token",
		Description: "GitLab Personal Access Token",
		Regex:       regexp.MustCompile(`(glpat-[A-Za-z0-9_\-]{20,})`),
		Severity:    "CRITICAL",
	},
	{
		Name:        "Slack Token",
		Description: "Slack API Token",
		Regex:       regexp.MustCompile(`(xox[pboa]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,})`),
		Severity:    "HIGH",
	},
	{
		Name:        "Stripe API Key",
		Description: "Stripe API Secret Key",
		Regex:       regexp.MustCompile(`(sk_live_[A-Za-z0-9]{24,}|rk_live_[A-Za-z0-9]{24,})`),
		Severity:    "CRITICAL",
	},
	{
		Name:        "Twilio API Key",
		Description: "Twilio API Key",
		Regex:       regexp.MustCompile(`(SK[A-Za-z0-9]{32})`),
		Severity:    "HIGH",
	},
	{
		Name:        "SendGrid API Key",
		Description: "SendGrid API Key",
		Regex:       regexp.MustCompile(`(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})`),
		Severity:    "HIGH",
	},
	{
		Name:        "Google API Key",
		Description: "Google Cloud API Key",
		Regex:       regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`),
		Severity:    "HIGH",
	},
	{
		Name:        "Google OAuth Token",
		Description: "Google OAuth Access Token",
		Regex:       regexp.MustCompile(`ya29\.[0-9A-Za-z_\-]{68,}`),
		Severity:    "CRITICAL",
	},

	// ==================== PRIVATE KEYS ====================
	{
		Name:        "RSA Private Key",
		Description: "RSA Private Key (PEM format)",
		Regex:       regexp.MustCompile(`-----BEGIN (RSA |OPENSSH )?PRIVATE KEY-----`),
		Severity:    "CRITICAL",
	},
	{
		Name:        "SSH Private Key",
		Description: "SSH Private Key",
		Regex:       regexp.MustCompile(`-----BEGIN (DSA|EC|OPENSSH) PRIVATE KEY-----`),
		Severity:    "CRITICAL",
	},
	{
		Name:        "PGP Private Key",
		Description: "PGP Private Key Block",
		Regex:       regexp.MustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK-----`),
		Severity:    "CRITICAL",
	},

	// ==================== JWT TOKENS ====================
	{
		Name:        "JWT Token",
		Description: "JSON Web Token",
		Regex:       regexp.MustCompile(`eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+`),
		Severity:    "HIGH",
	},

	// ==================== GENERIC PASSWORDS ====================
	{
		Name:        "Generic Password (Variable Assignment)",
		Description: "Password in variable assignment (password=...)",
		Regex:       regexp.MustCompile(`(?i)(password|passwd|pwd|pass|secret)[\s]*[=:][\s]*[\"']([^\"'\s]{8,})[\"']`),
		Severity:    "MEDIUM",
		FalsePositiveCheck: func(match string) bool {
			// Filter out common placeholders
			lower := strings.ToLower(match)
			placeholders := []string{
				"password", "your_password", "yourpassword", "changeme", "change_me",
				"placeholder", "example", "sample", "test", "dummy", "default",
				"xxxxxxxx", "********", "$(password)", "${password}", "$password",
			}
			for _, placeholder := range placeholders {
				if strings.Contains(lower, placeholder) {
					return false // It's a placeholder, filter it out
				}
			}
			return true // Likely a real password
		},
	},
	{
		Name:        "Generic API Key",
		Description: "Generic API Key in variable assignment",
		Regex:       regexp.MustCompile(`(?i)(api_key|apikey|api-key)[\s]*[=:][\s]*[\"']([A-Za-z0-9_\-]{20,})[\"']`),
		Severity:    "HIGH",
		FalsePositiveCheck: func(match string) bool {
			lower := strings.ToLower(match)
			return !strings.Contains(lower, "your_api_key") && !strings.Contains(lower, "api_key_here")
		},
	},
	{
		Name:        "Generic Secret",
		Description: "Generic secret in variable assignment",
		Regex:       regexp.MustCompile(`(?i)(secret|token|auth)[\s]*[=:][\s]*[\"']([A-Za-z0-9_\-]{16,})[\"']`),
		Severity:    "MEDIUM",
		FalsePositiveCheck: func(match string) bool {
			lower := strings.ToLower(match)
			return !strings.Contains(lower, "your_secret") && !strings.Contains(lower, "secret_here")
		},
	},

	// ==================== AZURE DEVOPS ====================
	{
		Name:        "Azure DevOps PAT",
		Description: "Azure DevOps Personal Access Token",
		Regex:       regexp.MustCompile(`(?i)(AZDO_PAT|azdo_pat|devops_pat)[\s]*[=:][\s]*[\"']?([A-Za-z0-9]{52})[\"']?`),
		Severity:    "CRITICAL",
	},

	// ==================== MISCELLANEOUS ====================
	{
		Name:        "Webhook URL with Token",
		Description: "Webhook URL containing authentication token",
		Regex:       regexp.MustCompile(`https?://[^\s]+/[A-Za-z0-9_\-]{20,}`),
		Severity:    "MEDIUM",
	},
	{
		Name:        "Base64 Encoded String (Potential Secret)",
		Description: "Long base64 encoded string (may contain secrets)",
		Regex:       regexp.MustCompile(`(?i)(token|secret|key|password|auth)[\s]*[=:][\s]*[\"']?([A-Za-z0-9+/]{64,}={0,2})[\"']?`),
		Severity:    "LOW",
	},
}

// ------------------------------
// Scanner Functions
// ------------------------------

// ScanForSecrets scans content for secrets and returns matches
func ScanForSecrets(content, sourceName, sourceType string) []SecretMatch {
	matches := []SecretMatch{}

	// Split content into lines for line number tracking
	lines := strings.Split(content, "\n")

	// Scan each pattern
	for _, pattern := range SecretPatterns {
		// Find all matches in content
		allMatches := pattern.Regex.FindAllStringSubmatchIndex(content, -1)

		for _, matchIdx := range allMatches {
			if len(matchIdx) < 2 {
				continue
			}

			// Extract the full match
			matchStart := matchIdx[0]
			matchEnd := matchIdx[1]
			matchedText := content[matchStart:matchEnd]

			// Apply false positive check if defined
			if pattern.FalsePositiveCheck != nil && !pattern.FalsePositiveCheck(matchedText) {
				continue
			}

			// Find line number
			lineNum := findLineNumber(content, matchStart)

			// Extract context (3 lines before and after)
			context := extractContext(lines, lineNum, 3)

			// Generate recommendation
			recommendation := generateRecommendation(pattern.Name, sourceType)

			// Create match
			match := SecretMatch{
				Pattern:        pattern.Name,
				Description:    pattern.Description,
				Match:          matchedText,
				Context:        context,
				LineNumber:     lineNum,
				SourceName:     sourceName,
				SourceType:     sourceType,
				Severity:       pattern.Severity,
				Recommendation: recommendation,
			}

			matches = append(matches, match)
		}
	}

	return matches
}

// ScanFileContent is a convenience wrapper for scanning file content
func ScanFileContent(fileContent, fileName, fileType string) []SecretMatch {
	return ScanForSecrets(fileContent, fileName, fileType)
}

// ScanYAMLContent scans YAML content (pipelines, repos)
func ScanYAMLContent(yamlContent, resourceName string) []SecretMatch {
	return ScanForSecrets(yamlContent, resourceName, "YAML")
}

// ScanJSONContent scans JSON content (Data Factory, ARM templates)
func ScanJSONContent(jsonContent, resourceName string) []SecretMatch {
	return ScanForSecrets(jsonContent, resourceName, "JSON")
}

// ScanScriptContent scans script content (runbooks, inline scripts)
func ScanScriptContent(scriptContent, resourceName, scriptType string) []SecretMatch {
	return ScanForSecrets(scriptContent, resourceName, scriptType)
}

// ------------------------------
// Helper Functions
// ------------------------------

// findLineNumber finds the line number for a given character position
func findLineNumber(content string, charPos int) int {
	lineNum := 1
	for i := 0; i < charPos && i < len(content); i++ {
		if content[i] == '\n' {
			lineNum++
		}
	}
	return lineNum
}

// extractContext extracts surrounding lines for context
func extractContext(lines []string, lineNum, contextLines int) string {
	start := lineNum - contextLines - 1
	if start < 0 {
		start = 0
	}
	end := lineNum + contextLines
	if end > len(lines) {
		end = len(lines)
	}

	contextBuilder := strings.Builder{}
	for i := start; i < end; i++ {
		prefix := "  "
		if i == lineNum-1 {
			prefix = "→ " // Mark the actual line with secret
		}
		contextBuilder.WriteString(fmt.Sprintf("%s%s\n", prefix, lines[i]))
	}

	return contextBuilder.String()
}

// generateRecommendation generates remediation advice based on pattern and source type
func generateRecommendation(patternName, sourceType string) string {
	recommendations := map[string]string{
		"AWS Access Key":                         "Use Azure Key Vault or Azure DevOps variable groups with secure variables. Never commit AWS credentials to code.",
		"AWS Secret Access Key":                  "Rotate this key immediately. Use Azure Managed Identities or Azure Key Vault references instead.",
		"Azure Storage Account Key":              "Use Managed Identity or SAS tokens with limited scope. Store keys in Azure Key Vault.",
		"Azure Connection String":                "Use Managed Identity authentication. Store connection strings in Azure Key Vault and reference via Key Vault secrets.",
		"Azure Service Principal Secret":         "Rotate this secret immediately. Use certificate-based authentication or workload identity federation.",
		"SQL Connection String":                  "Use Managed Identity for Azure SQL. Store connection strings in Key Vault. Never use SQL authentication in production.",
		"GitHub Token":                           "Revoke this token immediately in GitHub settings. Use Azure DevOps service connections with GitHub App authentication.",
		"RSA Private Key":                        "Remove this key immediately. Use Azure Key Vault for certificate storage. Rotate all systems using this key.",
		"SSH Private Key":                        "Remove this key immediately. Use Azure Bastion or Azure Key Vault for SSH key management.",
		"Generic Password (Variable Assignment)": "Use Azure Key Vault secrets or Azure DevOps secure variables. Enable secret scanning in repository.",
		"Azure DevOps PAT":                       "Revoke this PAT immediately. Use service principals with limited scope or Azure DevOps service connections.",
	}

	if rec, ok := recommendations[patternName]; ok {
		return rec
	}

	// Default recommendation based on source type
	switch sourceType {
	case "pipeline", "YAML":
		return "Use Azure DevOps variable groups with secret variables. Reference Azure Key Vault secrets in pipeline."
	case "runbook", "PowerShell", "Bash":
		return "Use Azure Automation variables (encrypted). Reference Key Vault secrets via Get-AzKeyVaultSecret cmdlet."
	case "linkedservice", "JSON":
		return "Use Managed Identity authentication. Reference Azure Key Vault secrets via linked service."
	default:
		return "Remove hardcoded secret. Use Azure Key Vault and reference secrets via managed identity or service principal."
	}
}

// ------------------------------
// Formatting Functions
// ------------------------------

// FormatSecretMatchesForLoot formats secret matches for loot file output
func FormatSecretMatchesForLoot(matches []SecretMatch) string {
	if len(matches) == 0 {
		return "# No secrets detected\n"
	}

	output := strings.Builder{}
	output.WriteString(strings.Repeat("=", 80) + "\n")
	output.WriteString(fmt.Sprintf("SECRETS DETECTED: %d\n", len(matches)))
	output.WriteString(strings.Repeat("=", 80) + "\n\n")

	// Group by severity
	severityOrder := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"}
	for _, severity := range severityOrder {
		severityMatches := []SecretMatch{}
		for _, m := range matches {
			if m.Severity == severity {
				severityMatches = append(severityMatches, m)
			}
		}

		if len(severityMatches) == 0 {
			continue
		}

		output.WriteString(fmt.Sprintf("\n%s SEVERITY: %d matches\n", severity, len(severityMatches)))
		output.WriteString(strings.Repeat("-", 80) + "\n\n")

		for i, match := range severityMatches {
			output.WriteString(fmt.Sprintf("[%d] %s\n", i+1, match.Pattern))
			output.WriteString(fmt.Sprintf("    Description: %s\n", match.Description))
			output.WriteString(fmt.Sprintf("    Source: %s (%s)\n", match.SourceName, match.SourceType))
			output.WriteString(fmt.Sprintf("    Line: %d\n", match.LineNumber))
			output.WriteString(fmt.Sprintf("    Matched: %s\n", truncateMatch(match.Match, 100)))
			output.WriteString(fmt.Sprintf("    Recommendation: %s\n", match.Recommendation))
			output.WriteString("\n    Context:\n")
			output.WriteString(indentContext(match.Context, 4))
			output.WriteString("\n")
		}
	}

	output.WriteString(strings.Repeat("=", 80) + "\n")
	output.WriteString("END OF SECRET SCAN RESULTS\n")
	output.WriteString(strings.Repeat("=", 80) + "\n")

	return output.String()
}

// truncateMatch truncates long matches for readability
func truncateMatch(match string, maxLen int) string {
	if len(match) <= maxLen {
		return match
	}
	return match[:maxLen] + "... [truncated]"
}

// indentContext indents context lines
func indentContext(context string, spaces int) string {
	indent := strings.Repeat(" ", spaces)
	lines := strings.Split(context, "\n")
	indented := []string{}
	for _, line := range lines {
		if line != "" {
			indented = append(indented, indent+line)
		}
	}
	return strings.Join(indented, "\n") + "\n"
}

// GetSecretStatistics returns statistics about detected secrets
func GetSecretStatistics(matches []SecretMatch) map[string]int {
	stats := map[string]int{
		"total":    len(matches),
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
	}

	for _, match := range matches {
		switch match.Severity {
		case "CRITICAL":
			stats["critical"]++
		case "HIGH":
			stats["high"]++
		case "MEDIUM":
			stats["medium"]++
		case "LOW":
			stats["low"]++
		}
	}

	return stats
}
