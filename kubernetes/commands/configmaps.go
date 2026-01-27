package commands

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/BishopFox/cloudfox/kubernetes/sdk"
	"github.com/BishopFox/cloudfox/kubernetes/shared"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
)

var ConfigMapsCmd = &cobra.Command{
	Use:     "configmaps",
	Aliases: []string{"cm"},
	Short:   "List all cluster ConfigMaps",
	Long: `
List all cluster ConfigMaps and detailed information:
  cloudfox kubernetes configmaps`,
	Run: ListConfigMaps,
}

type ConfigMapsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t ConfigMapsOutput) TableFiles() []internal.TableFile {
	return t.Table
}

func (t ConfigMapsOutput) LootFiles() []internal.LootFile {
	return t.Loot
}

type ConfigMapFinding struct {
	Namespace            string
	Name                 string
	RiskLevel            string
	RiskScore            int
	SensitiveKeys        []string
	DangerousPatterns    []string
	SecurityIssues       []string
	AWSCredentials       []string
	GCPCredentials       []string
	GitHubTokens         []string
	PrivateKeys          []string
	Base64Secrets        []string
	ConnectionStrings    []string
	DockerCredentials    []string
	KubeconfigFound      bool
	MountedByPods        []string
	UsageCount           int
	DataSize             int
	DataKeys             []string
	CreationTimestamp    string
	IsImmutable          bool
	Annotations          map[string]string
}

type CredentialFinding struct {
	Type        string // "AWS", "GCP", "GitHub", "PrivateKey", etc.
	Key         string // ConfigMap key where found
	Value       string // Actual credential (truncated for display)
	FullValue   string // Full credential value
	Description string // What this credential is
}

func ListConfigMaps(cmd *cobra.Command, args []string) {
	ctx, cancel := shared.ContextWithCancel()
	defer cancel()
	logger := internal.NewLogger()

	// Extract global flags
	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating configmaps for %s", globals.ClusterName), globals.K8S_CONFIGMAPS_MODULE_NAME)

	clientset := config.GetClientOrExit()

	// Get all pods using cache for mounting analysis
	allPods, err := sdk.GetPods(ctx, clientset)
	if err != nil {
		shared.LogListError(&logger, "pods", "", err, globals.K8S_CONFIGMAPS_MODULE_NAME, false)
		allPods = []corev1.Pod{}
	}

	// Get all ConfigMaps using cache
	allConfigMaps, err := sdk.GetConfigMaps(ctx, clientset)
	if err != nil {
		shared.LogListError(&logger, "configmaps", "", err, globals.K8S_CONFIGMAPS_MODULE_NAME, true)
		return
	}

	// Table 1: ConfigMaps Summary
	summaryHeaders := []string{
		"Namespace", "Name", "Keys Count", "Data Size", "Pods Mounted", "Immutable", "Has Sensitive Data", "Created",
	}

	// Table 2: ConfigMap-Keys Detail (one row per configmap/key/pod combination)
	keysHeaders := []string{
		"Namespace", "ConfigMap", "Key Name", "Value Size", "Detected Pattern", "Mounted By Pod",
	}

	var summaryRows [][]string
	var keysRows [][]string
	var findings []ConfigMapFinding

	// Risk counters
	riskCounts := shared.NewRiskCounts()

	for _, cm := range allConfigMaps {
		// Perform comprehensive security analysis
		finding := analyzeConfigMapSecurity(&cm)

		// Find pods mounting this ConfigMap using pre-fetched pods
		finding.MountedByPods = findPodsMountingConfigMapCached(allPods, cm.Namespace, cm.Name)
			finding.UsageCount = len(finding.MountedByPods)

			// Generate security issues and recommendations
			finding.SecurityIssues = generateConfigMapSecurityIssues(finding)

			// Calculate risk score and level
			finding.RiskScore = calculateConfigMapRiskScore(finding)
			finding.RiskLevel = calculateConfigMapRiskLevel(finding)

			// Update risk counters
			riskCounts.Add(finding.RiskLevel)

			findings = append(findings, finding)

			// Build summary table row
			immutableStr := "No"
			if finding.IsImmutable {
				immutableStr = "Yes"
			}

			hasSensitiveData := "No"
			if len(finding.DangerousPatterns) > 0 || len(finding.SensitiveKeys) > 0 {
				hasSensitiveData = "Yes"
			}

			summaryRow := []string{
				finding.Namespace,
				finding.Name,
				fmt.Sprintf("%d", len(finding.DataKeys)),
				fmt.Sprintf("%d bytes", finding.DataSize),
				fmt.Sprintf("%d", finding.UsageCount),
				immutableStr,
				hasSensitiveData,
				finding.CreationTimestamp,
			}
			summaryRows = append(summaryRows, summaryRow)

			// Build keys table rows - one row per (configmap, key, pod) combination
			// Create a map of key -> detected pattern for quick lookup
			keyPatterns := buildKeyPatternMap(&cm, finding)

			// If no pods mount this configmap, still show the keys with empty pod column
			if len(finding.MountedByPods) == 0 {
				for _, keyName := range finding.DataKeys {
					valueSize := len(cm.Data[keyName])
					detectedPattern := keyPatterns[keyName]
					if detectedPattern == "" {
						detectedPattern = "-"
					}

					keysRow := []string{
						finding.Namespace,
						finding.Name,
						keyName,
						fmt.Sprintf("%d bytes", valueSize),
						detectedPattern,
						"-",
					}
					keysRows = append(keysRows, keysRow)
				}
			} else {
				// One row per (key, pod) combination
				for _, keyName := range finding.DataKeys {
					valueSize := len(cm.Data[keyName])
					detectedPattern := keyPatterns[keyName]
					if detectedPattern == "" {
						detectedPattern = "-"
					}

					for _, podName := range finding.MountedByPods {
						keysRow := []string{
							finding.Namespace,
							finding.Name,
							keyName,
							fmt.Sprintf("%d bytes", valueSize),
							detectedPattern,
							podName,
						}
						keysRows = append(keysRows, keysRow)
					}
				}
			}
	}

	// Log risk summary
	logger.InfoM(fmt.Sprintf("Risk Distribution: CRITICAL=%d | HIGH=%d | MEDIUM=%d | LOW=%d",
		riskCounts.Critical, riskCounts.High, riskCounts.Medium, riskCounts.Low),
		globals.K8S_CONFIGMAPS_MODULE_NAME)

	summaryTable := internal.TableFile{
		Name:   "ConfigMaps",
		Header: summaryHeaders,
		Body:   summaryRows,
	}

	keysTable := internal.TableFile{
		Name:   "ConfigMap-Keys",
		Header: keysHeaders,
		Body:   keysRows,
	}

	// Generate loot files
	lootFiles := generateConfigMapLoot(findings, outputDirectory)

	err = internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"ConfigMaps",
		globals.ClusterName,
		"results",
		ConfigMapsOutput{
			Table: []internal.TableFile{summaryTable, keysTable},
			Loot:  lootFiles,
		},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_CONFIGMAPS_MODULE_NAME)
		return
	}

	if len(summaryRows) > 0 {
		logger.InfoM(fmt.Sprintf("%d configmaps found, %d key entries", len(summaryRows), len(keysRows)), globals.K8S_CONFIGMAPS_MODULE_NAME)
	} else {
		logger.InfoM("No configmaps found, skipping output file creation", globals.K8S_CONFIGMAPS_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_CONFIGMAPS_MODULE_NAME), globals.K8S_CONFIGMAPS_MODULE_NAME)
}

// detectAWSCredentials checks for AWS access keys and secret keys
func detectAWSCredentials(data map[string]string) []string {
	var findings []string

	// AWS Access Key ID pattern: AKIA[0-9A-Z]{16}
	accessKeyPattern := regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	// AWS Secret Access Key pattern: 40 characters base64-like
	secretKeyPattern := regexp.MustCompile(`[A-Za-z0-9/+=]{40}`)

	for key, value := range data {
		if accessKeyPattern.MatchString(value) {
			findings = append(findings, fmt.Sprintf("AWS Access Key in '%s'", key))
		}
		// Check if key name suggests AWS secret
		lowerKey := strings.ToLower(key)
		if (strings.Contains(lowerKey, "aws") && strings.Contains(lowerKey, "secret")) ||
			strings.Contains(lowerKey, "aws_secret_access_key") {
			if secretKeyPattern.MatchString(value) {
				findings = append(findings, fmt.Sprintf("AWS Secret Key in '%s'", key))
			}
		}
	}

	return findings
}

// detectGCPCredentials checks for GCP service account JSON keys
func detectGCPCredentials(data map[string]string) []string {
	var findings []string

	for key, value := range data {
		// Check if value is JSON with GCP service account structure
		var jsonData map[string]interface{}
		if err := json.Unmarshal([]byte(value), &jsonData); err == nil {
			if _, hasPrivateKeyID := jsonData["private_key_id"]; hasPrivateKeyID {
				if _, hasPrivateKey := jsonData["private_key"]; hasPrivateKey {
					if _, hasClientEmail := jsonData["client_email"]; hasClientEmail {
						findings = append(findings, fmt.Sprintf("GCP Service Account Key in '%s'", key))
					}
				}
			}
		}
	}

	return findings
}

// detectGitHubTokens checks for GitHub personal access tokens
func detectGitHubTokens(data map[string]string) []string {
	var findings []string

	// GitHub token patterns
	patterns := []struct {
		regex *regexp.Regexp
		desc  string
	}{
		{regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`), "GitHub Personal Access Token"},
		{regexp.MustCompile(`gho_[a-zA-Z0-9]{36}`), "GitHub OAuth Token"},
		{regexp.MustCompile(`ghs_[a-zA-Z0-9]{36}`), "GitHub Server Token"},
		{regexp.MustCompile(`github_pat_[a-zA-Z0-9_]{82}`), "GitHub Fine-grained PAT"},
		{regexp.MustCompile(`ghr_[a-zA-Z0-9]{36}`), "GitHub Refresh Token"},
	}

	for key, value := range data {
		for _, pattern := range patterns {
			if pattern.regex.MatchString(value) {
				findings = append(findings, fmt.Sprintf("%s in '%s'", pattern.desc, key))
			}
		}
	}

	return findings
}

// detectPrivateKeys checks for PEM-encoded private keys
func detectPrivateKeys(data map[string]string) []string {
	var findings []string

	privateKeyPatterns := []string{
		"-----BEGIN RSA PRIVATE KEY-----",
		"-----BEGIN EC PRIVATE KEY-----",
		"-----BEGIN PRIVATE KEY-----",
		"-----BEGIN OPENSSH PRIVATE KEY-----",
		"-----BEGIN DSA PRIVATE KEY-----",
		"-----BEGIN ENCRYPTED PRIVATE KEY-----",
	}

	for key, value := range data {
		for _, pattern := range privateKeyPatterns {
			if strings.Contains(value, pattern) {
				findings = append(findings, fmt.Sprintf("Private Key in '%s'", key))
				break
			}
		}
	}

	return findings
}

// detectConnectionStrings checks for database and service URLs with credentials
func detectConnectionStrings(data map[string]string) []string {
	var findings []string

	// Connection string patterns
	patterns := []struct {
		regex *regexp.Regexp
		desc  string
	}{
		{regexp.MustCompile(`postgres://[^:]+:[^@]+@`), "PostgreSQL"},
		{regexp.MustCompile(`mysql://[^:]+:[^@]+@`), "MySQL"},
		{regexp.MustCompile(`mongodb://[^:]+:[^@]+@`), "MongoDB"},
		{regexp.MustCompile(`redis://[^:]+:[^@]+@`), "Redis"},
		{regexp.MustCompile(`amqp://[^:]+:[^@]+@`), "AMQP/RabbitMQ"},
		{regexp.MustCompile(`Server=[^;]+;.*Password=[^;]+`), "SQL Server"},
	}

	for key, value := range data {
		for _, pattern := range patterns {
			if pattern.regex.MatchString(value) {
				findings = append(findings, fmt.Sprintf("%s Connection String in '%s'", pattern.desc, key))
			}
		}
	}

	return findings
}

// detectBase64Secrets attempts to decode base64 values and analyze content
func detectBase64Secrets(data map[string]string) []string {
	var findings []string

	base64Pattern := regexp.MustCompile(`^[A-Za-z0-9+/]{20,}={0,2}$`)

	for key, value := range data {
		// Skip if already contains PEM markers (already detected)
		if strings.Contains(value, "-----BEGIN") {
			continue
		}

		// Check if value looks like base64
		if base64Pattern.MatchString(value) && len(value) > 20 {
			decoded, err := base64.StdEncoding.DecodeString(value)
			if err == nil {
				decodedStr := string(decoded)
				// Check if decoded content contains sensitive patterns
				lowerDecoded := strings.ToLower(decodedStr)
				if strings.Contains(lowerDecoded, "password") ||
					strings.Contains(lowerDecoded, "secret") ||
					strings.Contains(lowerDecoded, "token") ||
					strings.Contains(lowerDecoded, "api") ||
					strings.Contains(decodedStr, "-----BEGIN") {
					findings = append(findings, fmt.Sprintf("Base64-encoded Secret in '%s'", key))
				}
			}
		}
	}

	return findings
}

// detectDockerCredentials checks for Docker registry credentials
func detectDockerCredentials(data map[string]string) []string {
	var findings []string

	for key, value := range data {
		// Check for .dockerconfigjson format
		if strings.Contains(key, "docker") && strings.Contains(key, "config") {
			var dockerConfig map[string]interface{}
			if err := json.Unmarshal([]byte(value), &dockerConfig); err == nil {
				if auths, ok := dockerConfig["auths"].(map[string]interface{}); ok && len(auths) > 0 {
					findings = append(findings, fmt.Sprintf("Docker Registry Credentials in '%s'", key))
				}
			}
		}

		// Check for plain auth fields
		lowerKey := strings.ToLower(key)
		if strings.Contains(lowerKey, "docker") && (strings.Contains(lowerKey, "auth") || strings.Contains(lowerKey, "password")) {
			findings = append(findings, fmt.Sprintf("Docker Credentials in '%s'", key))
		}
	}

	return findings
}

// detectKubeconfig checks if data contains kubeconfig content
func detectKubeconfig(data map[string]string) bool {
	for _, value := range data {
		if strings.Contains(value, "apiVersion:") &&
			strings.Contains(value, "kind: Config") &&
			(strings.Contains(value, "clusters:") || strings.Contains(value, "users:")) {
			return true
		}
	}
	return false
}

// detectSensitiveKeywords checks for sensitive keywords in keys and values
func detectSensitiveKeywords(data map[string]string) []string {
	suspects := []string{"password", "passwd", "secret", "key", "token", "credentials", "api_key", "apikey"}
	var hits []string

	for k, v := range data {
		lk := strings.ToLower(k)
		lv := strings.ToLower(v)
		for _, s := range suspects {
			if strings.Contains(lk, s) || strings.Contains(lv, s) {
				hits = append(hits, k)
				break
			}
		}
	}

	return hits
}

// analyzeConfigMapSecurity performs comprehensive security analysis
func analyzeConfigMapSecurity(cm *corev1.ConfigMap) ConfigMapFinding {
	finding := ConfigMapFinding{
		Namespace:         cm.Namespace,
		Name:              cm.Name,
		CreationTimestamp: cm.CreationTimestamp.String(),
		DataKeys:          []string{},
		Annotations:       cm.Annotations,
	}

	// Check immutability
	if cm.Immutable != nil && *cm.Immutable {
		finding.IsImmutable = true
	}

	// Collect data keys
	for key := range cm.Data {
		finding.DataKeys = append(finding.DataKeys, key)
	}
	sort.Strings(finding.DataKeys)

	// Calculate data size
	for _, value := range cm.Data {
		finding.DataSize += len(value)
	}

	// Detect various credential types
	finding.AWSCredentials = detectAWSCredentials(cm.Data)
	finding.GCPCredentials = detectGCPCredentials(cm.Data)
	finding.GitHubTokens = detectGitHubTokens(cm.Data)
	finding.PrivateKeys = detectPrivateKeys(cm.Data)
	finding.ConnectionStrings = detectConnectionStrings(cm.Data)
	finding.Base64Secrets = detectBase64Secrets(cm.Data)
	finding.DockerCredentials = detectDockerCredentials(cm.Data)
	finding.KubeconfigFound = detectKubeconfig(cm.Data)
	finding.SensitiveKeys = detectSensitiveKeywords(cm.Data)

	// Aggregate dangerous patterns
	finding.DangerousPatterns = append(finding.DangerousPatterns, finding.AWSCredentials...)
	finding.DangerousPatterns = append(finding.DangerousPatterns, finding.GCPCredentials...)
	finding.DangerousPatterns = append(finding.DangerousPatterns, finding.GitHubTokens...)
	finding.DangerousPatterns = append(finding.DangerousPatterns, finding.PrivateKeys...)
	finding.DangerousPatterns = append(finding.DangerousPatterns, finding.ConnectionStrings...)
	finding.DangerousPatterns = append(finding.DangerousPatterns, finding.Base64Secrets...)
	finding.DangerousPatterns = append(finding.DangerousPatterns, finding.DockerCredentials...)
	if finding.KubeconfigFound {
		finding.DangerousPatterns = append(finding.DangerousPatterns, "Kubeconfig found")
	}

	return finding
}

// buildKeyPatternMap creates a map of key names to their detected sensitive patterns
func buildKeyPatternMap(cm *corev1.ConfigMap, finding ConfigMapFinding) map[string]string {
	keyPatterns := make(map[string]string)

	// Parse the pattern strings to extract key names and build the map
	// Pattern format is like "AWS Access Key in 'keyname'" or "Private Key in 'keyname'"
	parsePatterns := func(patterns []string, patternType string) {
		for _, pattern := range patterns {
			// Extract key name from pattern like "Something in 'keyname'"
			if idx := strings.Index(pattern, " in '"); idx != -1 {
				keyStart := idx + 5
				keyEnd := strings.LastIndex(pattern, "'")
				if keyEnd > keyStart {
					keyName := pattern[keyStart:keyEnd]
					if existing, ok := keyPatterns[keyName]; ok {
						keyPatterns[keyName] = existing + ", " + patternType
					} else {
						keyPatterns[keyName] = patternType
					}
				}
			}
		}
	}

	parsePatterns(finding.AWSCredentials, "AWS Credential")
	parsePatterns(finding.GCPCredentials, "GCP Credential")
	parsePatterns(finding.GitHubTokens, "GitHub Token")
	parsePatterns(finding.PrivateKeys, "Private Key")
	parsePatterns(finding.ConnectionStrings, "Connection String")
	parsePatterns(finding.Base64Secrets, "Base64 Secret")
	parsePatterns(finding.DockerCredentials, "Docker Credential")

	// Check for kubeconfig in all keys
	if finding.KubeconfigFound {
		for key, value := range cm.Data {
			if strings.Contains(value, "apiVersion:") &&
				strings.Contains(value, "kind: Config") {
				if existing, ok := keyPatterns[key]; ok {
					keyPatterns[key] = existing + ", Kubeconfig"
				} else {
					keyPatterns[key] = "Kubeconfig"
				}
			}
		}
	}

	// Add sensitive keywords detection
	for _, keyName := range finding.SensitiveKeys {
		if _, ok := keyPatterns[keyName]; !ok {
			keyPatterns[keyName] = "Sensitive Keyword"
		}
	}

	return keyPatterns
}

// findPodsMountingConfigMapCached finds all pods that mount a specific ConfigMap using pre-fetched pods
func findPodsMountingConfigMapCached(allPods []corev1.Pod, namespace, configMapName string) []string {
	var mountingPods []string

	for _, pod := range allPods {
		// Only check pods in the same namespace
		if pod.Namespace != namespace {
			continue
		}
		for _, volume := range pod.Spec.Volumes {
			if volume.ConfigMap != nil && volume.ConfigMap.Name == configMapName {
				mountingPods = append(mountingPods, pod.Name)
				break
			}
		}
	}

	return mountingPods
}

// calculateConfigMapRiskLevel determines the risk level
func calculateConfigMapRiskLevel(finding ConfigMapFinding) string {
	// CRITICAL: Contains actual credentials or private keys
	if len(finding.AWSCredentials) > 0 ||
		len(finding.GCPCredentials) > 0 ||
		len(finding.GitHubTokens) > 0 ||
		len(finding.PrivateKeys) > 0 ||
		len(finding.ConnectionStrings) > 0 ||
		len(finding.DockerCredentials) > 0 ||
		finding.KubeconfigFound {
		return shared.RiskCritical
	}

	// HIGH: Contains base64 secrets or mounted by many pods
	if len(finding.Base64Secrets) > 0 || finding.UsageCount >= 5 {
		return shared.RiskHigh
	}

	// MEDIUM: Contains sensitive keywords or mounted by some pods
	if len(finding.SensitiveKeys) > 0 || finding.UsageCount >= 2 {
		return shared.RiskMedium
	}

	// LOW: Standard configuration
	return shared.RiskLow
}

// calculateConfigMapRiskScore calculates a numeric risk score (0-100)
func calculateConfigMapRiskScore(finding ConfigMapFinding) int {
	score := 0

	// Credentials (40 points max)
	if len(finding.AWSCredentials) > 0 {
		score += 20
	}
	if len(finding.GCPCredentials) > 0 {
		score += 20
	}
	if len(finding.GitHubTokens) > 0 {
		score += 15
	}
	if len(finding.PrivateKeys) > 0 {
		score += 25
	}
	if len(finding.DockerCredentials) > 0 {
		score += 15
	}
	if len(finding.ConnectionStrings) > 0 {
		score += 20
	}
	if finding.KubeconfigFound {
		score += 30
	}

	// Base64 secrets (15 points)
	if len(finding.Base64Secrets) > 0 {
		score += 15
	}

	// Sensitive keywords (10 points)
	if len(finding.SensitiveKeys) > 0 {
		score += 10
	}

	// Usage/exposure (15 points max)
	if finding.UsageCount >= 10 {
		score += 15
	} else if finding.UsageCount >= 5 {
		score += 10
	} else if finding.UsageCount >= 2 {
		score += 5
	}

	// Not immutable with sensitive data (10 points)
	if !finding.IsImmutable && (len(finding.DangerousPatterns) > 0 || len(finding.SensitiveKeys) > 0) {
		score += 10
	}

	// Large data size with sensitive content (5 points)
	if finding.DataSize > 100000 && len(finding.SensitiveKeys) > 0 {
		score += 5
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}

// generateConfigMapSecurityIssues creates a list of specific security issues and recommendations
func generateConfigMapSecurityIssues(finding ConfigMapFinding) []string {
	var issues []string

	// Credential-specific issues
	if len(finding.AWSCredentials) > 0 {
		issues = append(issues, "CRITICAL: AWS credentials stored in ConfigMap - migrate to AWS Secrets Manager or Kubernetes Secrets with encryption")
	}
	if len(finding.GCPCredentials) > 0 {
		issues = append(issues, "CRITICAL: GCP service account keys in ConfigMap - use Workload Identity instead")
	}
	if len(finding.GitHubTokens) > 0 {
		issues = append(issues, "CRITICAL: GitHub tokens in ConfigMap - revoke and use GitHub Actions secrets or sealed secrets")
	}
	if len(finding.PrivateKeys) > 0 {
		issues = append(issues, "CRITICAL: Private keys in ConfigMap - migrate to cert-manager or sealed secrets")
	}
	if len(finding.ConnectionStrings) > 0 {
		issues = append(issues, "CRITICAL: Database connection strings with credentials - use Secrets or external secret managers")
	}
	if len(finding.DockerCredentials) > 0 {
		issues = append(issues, "CRITICAL: Docker registry credentials - use imagePullSecrets instead")
	}
	if finding.KubeconfigFound {
		issues = append(issues, "CRITICAL: Kubeconfig in ConfigMap - immediate security risk, remove and use RBAC")
	}

	// Base64 secrets
	if len(finding.Base64Secrets) > 0 {
		issues = append(issues, "HIGH: Base64-encoded secrets detected - base64 is encoding not encryption, migrate to Secrets")
	}

	// Immutability
	if !finding.IsImmutable && len(finding.DangerousPatterns) > 0 {
		issues = append(issues, "MEDIUM: ConfigMap with sensitive data is mutable - set immutable: true to prevent tampering")
	}

	// High exposure
	if finding.UsageCount >= 10 {
		issues = append(issues, fmt.Sprintf("MEDIUM: ConfigMap mounted by %d pods - high exposure, audit access", finding.UsageCount))
	} else if finding.UsageCount >= 5 {
		issues = append(issues, fmt.Sprintf("LOW: ConfigMap mounted by %d pods - moderate exposure", finding.UsageCount))
	}

	// Sensitive keywords without specific pattern match
	if len(finding.SensitiveKeys) > 0 && len(finding.DangerousPatterns) == 0 {
		issues = append(issues, "MEDIUM: Contains sensitive keywords - verify no actual secrets present")
	}

	// No issues found
	if len(issues) == 0 && len(finding.DataKeys) > 0 {
		issues = append(issues, "LOW: Standard configuration data - no obvious security issues")
	}

	return issues
}

// generateConfigMapLoot creates a single consolidated commands loot file
func generateConfigMapLoot(findings []ConfigMapFinding, outputDirectory string) []internal.LootFile {
	loot := shared.NewLootBuilder()

	// Filter findings by risk level
	criticalFindings := []ConfigMapFinding{}
	highFindings := []ConfigMapFinding{}

	for _, f := range findings {
		switch f.RiskLevel {
		case shared.RiskCritical:
			criticalFindings = append(criticalFindings, f)
		case shared.RiskHigh:
			highFindings = append(highFindings, f)
		}
	}

	// Single consolidated commands file
	cmds := loot.Section("ConfigMap-Commands")
	cmds.Add("═══════════════════════════════════════════════════════════════")
	cmds.Add("         CONFIGMAP ENUMERATION AND EXPLOITATION COMMANDS")
	cmds.Add("═══════════════════════════════════════════════════════════════")
	cmds.Add("")

	// Section 1: Enumeration
	cmds.Add("##############################################")
	cmds.Add("## 1. ENUMERATION")
	cmds.Add("##############################################")
	cmds.Add("")
	cmds.Add("# Check permissions")
	cmds.Add("kubectl auth can-i get configmaps --all-namespaces")
	cmds.Add("kubectl auth can-i list configmaps --all-namespaces")
	cmds.Add("kubectl auth can-i update configmaps --all-namespaces")
	cmds.Add("")
	cmds.Add("# List all ConfigMaps")
	cmds.Add("kubectl get configmaps -A")
	cmds.Add("kubectl get configmaps -A -o wide")
	cmds.Add("")
	cmds.Add("# Get ConfigMap details")
	cmds.Add("kubectl get configmap <name> -n <namespace> -o yaml")
	cmds.Add("kubectl describe configmap <name> -n <namespace>")
	cmds.Add("")
	cmds.Add("# Extract all ConfigMap data as JSON")
	cmds.Add("kubectl get configmaps -A -o json | jq -r '.items[] | \"\\(.metadata.namespace)/\\(.metadata.name): \\(.data | keys)\"'")
	cmds.Add("")
	cmds.Add("# Find ConfigMaps with specific keys")
	cmds.Add("kubectl get configmaps -A -o json | jq -r '.items[] | select(.data | keys | any(test(\"password|secret|key|token\"; \"i\"))) | \"\\(.metadata.namespace)/\\(.metadata.name)\"'")
	cmds.Add("")

	// Section 2: Sensitive ConfigMap Extraction
	cmds.Add("##############################################")
	cmds.Add("## 2. EXTRACTION - Sensitive ConfigMaps")
	cmds.Add("##############################################")
	cmds.Add("")

	if len(criticalFindings) > 0 || len(highFindings) > 0 {
		cmds.Add("# Bulk extraction script")
		cmds.Add("mkdir -p configmap-dump && cd configmap-dump")
		cmds.Add("")

		for _, f := range criticalFindings {
			cmds.Addf("# [CRITICAL] %s/%s - %s", f.Namespace, f.Name, strings.Join(f.DangerousPatterns, ", "))
			cmds.Addf("kubectl get configmap -n %s %s -o yaml > %s-%s.yaml", f.Namespace, f.Name, f.Namespace, f.Name)
			cmds.Add("")
		}
		for _, f := range highFindings {
			cmds.Addf("# [HIGH] %s/%s", f.Namespace, f.Name)
			cmds.Addf("kubectl get configmap -n %s %s -o yaml > %s-%s.yaml", f.Namespace, f.Name, f.Namespace, f.Name)
			cmds.Add("")
		}
	} else {
		cmds.Add("# No CRITICAL or HIGH risk ConfigMaps found")
		cmds.Add("# Use generic extraction:")
		cmds.Add("kubectl get configmap <name> -n <namespace> -o yaml > configmap.yaml")
		cmds.Add("")
	}

	// Section 3: Decode Base64 secrets
	hasBase64 := false
	for _, f := range highFindings {
		if len(f.Base64Secrets) > 0 {
			hasBase64 = true
			break
		}
	}
	if hasBase64 {
		cmds.Add("##############################################")
		cmds.Add("## 3. DECODE BASE64 SECRETS")
		cmds.Add("##############################################")
		cmds.Add("")
		for _, f := range highFindings {
			if len(f.Base64Secrets) > 0 {
				cmds.Addf("# %s/%s", f.Namespace, f.Name)
				for _, key := range f.DataKeys {
					cmds.Addf("kubectl get configmap -n %s %s -o jsonpath='{.data.%s}' | base64 -d",
						f.Namespace, f.Name, key)
				}
				cmds.Add("")
			}
		}
	}

	// Section 4: Credential-specific exploitation
	cmds.Add("##############################################")
	cmds.Add("## 4. CREDENTIAL EXPLOITATION")
	cmds.Add("##############################################")
	cmds.Add("")

	hasAWS := false
	hasGCP := false
	hasGitHub := false
	hasDB := false
	hasPrivateKey := false
	hasKubeconfig := false

	for _, f := range criticalFindings {
		if len(f.AWSCredentials) > 0 {
			hasAWS = true
		}
		if len(f.GCPCredentials) > 0 {
			hasGCP = true
		}
		if len(f.GitHubTokens) > 0 {
			hasGitHub = true
		}
		if len(f.ConnectionStrings) > 0 {
			hasDB = true
		}
		if len(f.PrivateKeys) > 0 {
			hasPrivateKey = true
		}
		if f.KubeconfigFound {
			hasKubeconfig = true
		}
	}

	if hasAWS {
		cmds.Add("### AWS Credentials ###")
		for _, f := range criticalFindings {
			if len(f.AWSCredentials) > 0 {
				cmds.Addf("# Extract from %s/%s", f.Namespace, f.Name)
				cmds.Addf("AWS_ACCESS_KEY_ID=$(kubectl get configmap -n %s %s -o jsonpath='{.data.AWS_ACCESS_KEY_ID}')", f.Namespace, f.Name)
				cmds.Addf("AWS_SECRET_ACCESS_KEY=$(kubectl get configmap -n %s %s -o jsonpath='{.data.AWS_SECRET_ACCESS_KEY}')", f.Namespace, f.Name)
				cmds.Add("export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY")
				cmds.Add("aws sts get-caller-identity")
				cmds.Add("aws s3 ls")
				cmds.Add("")
			}
		}
	}

	if hasGCP {
		cmds.Add("### GCP Service Account Keys ###")
		for _, f := range criticalFindings {
			if len(f.GCPCredentials) > 0 {
				cmds.Addf("# Extract from %s/%s", f.Namespace, f.Name)
				cmds.Addf("kubectl get configmap -n %s %s -o jsonpath='{.data.GOOGLE_APPLICATION_CREDENTIALS}' > gcp-key.json", f.Namespace, f.Name)
				cmds.Add("gcloud auth activate-service-account --key-file=gcp-key.json")
				cmds.Add("gcloud projects list")
				cmds.Add("")
			}
		}
	}

	if hasGitHub {
		cmds.Add("### GitHub Tokens ###")
		for _, f := range criticalFindings {
			if len(f.GitHubTokens) > 0 {
				cmds.Addf("# Extract from %s/%s", f.Namespace, f.Name)
				cmds.Addf("GH_TOKEN=$(kubectl get configmap -n %s %s -o jsonpath='{.data.GITHUB_TOKEN}')", f.Namespace, f.Name)
				cmds.Add("curl -H \"Authorization: token $GH_TOKEN\" https://api.github.com/user")
				cmds.Add("")
			}
		}
	}

	if hasDB {
		cmds.Add("### Database Connection Strings ###")
		for _, f := range criticalFindings {
			if len(f.ConnectionStrings) > 0 {
				cmds.Addf("# Extract from %s/%s", f.Namespace, f.Name)
				cmds.Addf("DB_URL=$(kubectl get configmap -n %s %s -o jsonpath='{.data.DATABASE_URL}')", f.Namespace, f.Name)
				cmds.Add("psql \"$DB_URL\"  # or mysql, mongo, etc.")
				cmds.Add("")
			}
		}
	}

	if hasPrivateKey {
		cmds.Add("### Private Keys ###")
		for _, f := range criticalFindings {
			if len(f.PrivateKeys) > 0 {
				cmds.Addf("# Extract from %s/%s", f.Namespace, f.Name)
				for _, key := range f.DataKeys {
					cmds.Addf("kubectl get configmap -n %s %s -o jsonpath='{.data.%s}' > extracted-key.pem", f.Namespace, f.Name, key)
				}
				cmds.Add("chmod 600 extracted-key.pem")
				cmds.Add("ssh -i extracted-key.pem user@host")
				cmds.Add("")
			}
		}
	}

	if hasKubeconfig {
		cmds.Add("### Kubeconfig Files ###")
		for _, f := range criticalFindings {
			if f.KubeconfigFound {
				cmds.Addf("# Extract from %s/%s", f.Namespace, f.Name)
				for _, key := range f.DataKeys {
					cmds.Addf("kubectl get configmap -n %s %s -o jsonpath='{.data.%s}' > extracted-kubeconfig", f.Namespace, f.Name, key)
				}
				cmds.Add("export KUBECONFIG=./extracted-kubeconfig")
				cmds.Add("kubectl get pods -A")
				cmds.Add("")
			}
		}
	}

	if !hasAWS && !hasGCP && !hasGitHub && !hasDB && !hasPrivateKey && !hasKubeconfig {
		cmds.Add("# No specific credentials found in ConfigMaps")
		cmds.Add("# Review ConfigMaps manually for sensitive data")
		cmds.Add("")
	}

	// Section 5: Pod injection technique
	cmds.Add("##############################################")
	cmds.Add("## 5. POD INJECTION - Mount ConfigMaps")
	cmds.Add("##############################################")
	cmds.Add("")
	cmds.Add("# If you can create pods, mount sensitive ConfigMaps:")
	cmds.Add("cat <<EOF | kubectl apply -f -")
	cmds.Add("apiVersion: v1")
	cmds.Add("kind: Pod")
	cmds.Add("metadata:")
	cmds.Add("  name: configmap-reader")
	cmds.Add("  namespace: <TARGET_NAMESPACE>")
	cmds.Add("spec:")
	cmds.Add("  containers:")
	cmds.Add("  - name: reader")
	cmds.Add("    image: alpine")
	cmds.Add("    command: [\"sleep\", \"3600\"]")
	cmds.Add("    volumeMounts:")
	cmds.Add("    - name: config")
	cmds.Add("      mountPath: /config")
	cmds.Add("  volumes:")
	cmds.Add("  - name: config")
	cmds.Add("    configMap:")
	cmds.Add("      name: <TARGET_CONFIGMAP>")
	cmds.Add("EOF")
	cmds.Add("")
	cmds.Add("# Extract data from pod")
	cmds.Add("kubectl exec -it configmap-reader -n <TARGET_NAMESPACE> -- cat /config/*")
	cmds.Add("")

	// Section 6: Modify ConfigMaps
	cmds.Add("##############################################")
	cmds.Add("## 6. MODIFICATION - Inject Malicious Config")
	cmds.Add("##############################################")
	cmds.Add("")
	cmds.Add("# Check if you can update ConfigMaps")
	cmds.Add("kubectl auth can-i update configmaps -n <namespace>")
	cmds.Add("")
	cmds.Add("# Edit ConfigMap directly")
	cmds.Add("kubectl edit configmap <name> -n <namespace>")
	cmds.Add("")
	cmds.Add("# Patch specific key")
	cmds.Add("kubectl patch configmap <name> -n <namespace> --type=merge -p '{\"data\":{\"key\":\"malicious-value\"}}'")
	cmds.Add("")

	// Section 7: Find pods mounting ConfigMaps
	cmds.Add("##############################################")
	cmds.Add("## 7. FIND PODS MOUNTING CONFIGMAPS")
	cmds.Add("##############################################")
	cmds.Add("")
	cmds.Add("# Find all pods mounting a specific ConfigMap")
	cmds.Add("kubectl get pods -A -o json | jq -r '.items[] | select(.spec.volumes[]?.configMap.name == \"<CONFIGMAP_NAME>\") | \"\\(.metadata.namespace)/\\(.metadata.name)\"'")
	cmds.Add("")
	cmds.Add("# Find pods using ConfigMaps as environment variables")
	cmds.Add("kubectl get pods -A -o json | jq -r '.items[] | select(.spec.containers[].envFrom[]?.configMapRef != null) | \"\\(.metadata.namespace)/\\(.metadata.name)\"'")
	cmds.Add("")

	return loot.Build()
}
