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
	SensitiveKeys        []string
	DangerousPatterns    []string
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
	CredentialFindings   []CredentialFinding
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
		"Namespace", "ConfigMap", "Key Name", "Mounted By Pod", "Value Size", "Detected Pattern", "Detected Value",
	}

	var summaryRows [][]string
	var keysRows [][]string
	var findings []ConfigMapFinding

	for _, cm := range allConfigMaps {
		// Perform comprehensive security analysis
		finding := analyzeConfigMapSecurity(&cm)

		// Find pods mounting this ConfigMap using pre-fetched pods
		finding.MountedByPods = findPodsMountingConfigMapCached(allPods, cm.Namespace, cm.Name)
			finding.UsageCount = len(finding.MountedByPods)

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
			keyPatterns := buildKeyPatternMap(&cm, finding)

			// Build key -> detected value map from credential findings
			keyValues := make(map[string]string)
			for _, cf := range finding.CredentialFindings {
				if _, exists := keyValues[cf.Key]; !exists {
					keyValues[cf.Key] = cf.Value
				}
			}

			if len(finding.MountedByPods) == 0 {
				for _, keyName := range finding.DataKeys {
					valueSize := len(cm.Data[keyName])
					detectedPattern := keyPatterns[keyName]
					if detectedPattern == "" {
						detectedPattern = "-"
					}
					detectedValue := keyValues[keyName]
					if detectedValue == "" {
						if detectedPattern == "Sensitive Keyword" {
							detectedValue = "Check Config"
						} else {
							detectedValue = "-"
						}
					}

					keysRows = append(keysRows, []string{
						finding.Namespace, finding.Name, keyName, "-",
						fmt.Sprintf("%d bytes", valueSize),
						detectedPattern, detectedValue,
					})
				}
			} else {
				for _, keyName := range finding.DataKeys {
					valueSize := len(cm.Data[keyName])
					detectedPattern := keyPatterns[keyName]
					if detectedPattern == "" {
						detectedPattern = "-"
					}
					detectedValue := keyValues[keyName]
					if detectedValue == "" {
						if detectedPattern == "Sensitive Keyword" {
							detectedValue = "Check Config"
						} else {
							detectedValue = "-"
						}
					}

					for _, podName := range finding.MountedByPods {
						keysRows = append(keysRows, []string{
							finding.Namespace, finding.Name, keyName, podName,
							fmt.Sprintf("%d bytes", valueSize),
							detectedPattern, detectedValue,
						})
					}
				}
			}
	}

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
	lootFiles := generateConfigMapLoot(findings, allConfigMaps, outputDirectory)

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
func detectAWSCredentials(data map[string]string) ([]string, []CredentialFinding) {
	var findings []string
	var creds []CredentialFinding

	// AWS Access Key ID pattern: AKIA[0-9A-Z]{16}
	accessKeyPattern := regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	// AWS Secret Access Key pattern: 40 characters base64-like
	secretKeyPattern := regexp.MustCompile(`[A-Za-z0-9/+=]{40}`)

	for key, value := range data {
		if match := accessKeyPattern.FindString(value); match != "" {
			findings = append(findings, fmt.Sprintf("AWS Access Key in '%s'", key))
			creds = append(creds, CredentialFinding{Type: "AWS", Key: key, Value: match, FullValue: match, Description: "AWS Access Key ID"})
		}
		lowerKey := strings.ToLower(key)
		if (strings.Contains(lowerKey, "aws") && strings.Contains(lowerKey, "secret")) ||
			strings.Contains(lowerKey, "aws_secret_access_key") {
			if match := secretKeyPattern.FindString(value); match != "" {
				findings = append(findings, fmt.Sprintf("AWS Secret Key in '%s'", key))
				creds = append(creds, CredentialFinding{Type: "AWS", Key: key, Value: match, FullValue: match, Description: "AWS Secret Access Key"})
			}
		}
	}

	return findings, creds
}

// detectGCPCredentials checks for GCP service account JSON keys
func detectGCPCredentials(data map[string]string) ([]string, []CredentialFinding) {
	var findings []string
	var creds []CredentialFinding

	for key, value := range data {
		var jsonData map[string]interface{}
		if err := json.Unmarshal([]byte(value), &jsonData); err == nil {
			if _, hasPrivateKeyID := jsonData["private_key_id"]; hasPrivateKeyID {
				if _, hasPrivateKey := jsonData["private_key"]; hasPrivateKey {
					if clientEmail, hasClientEmail := jsonData["client_email"]; hasClientEmail {
						findings = append(findings, fmt.Sprintf("GCP Service Account Key in '%s'", key))
						email, _ := clientEmail.(string)
						creds = append(creds, CredentialFinding{Type: "GCP", Key: key, Value: email, FullValue: value, Description: "GCP Service Account Key"})
					}
				}
			}
		}
	}

	return findings, creds
}

// detectGitHubTokens checks for GitHub personal access tokens
func detectGitHubTokens(data map[string]string) ([]string, []CredentialFinding) {
	var findings []string
	var creds []CredentialFinding

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
			if match := pattern.regex.FindString(value); match != "" {
				findings = append(findings, fmt.Sprintf("%s in '%s'", pattern.desc, key))
				creds = append(creds, CredentialFinding{Type: "GitHub", Key: key, Value: match, FullValue: match, Description: pattern.desc})
			}
		}
	}

	return findings, creds
}

// detectPrivateKeys checks for PEM-encoded private keys
func detectPrivateKeys(data map[string]string) ([]string, []CredentialFinding) {
	var findings []string
	var creds []CredentialFinding

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
				creds = append(creds, CredentialFinding{Type: "PrivateKey", Key: key, Value: pattern, FullValue: value, Description: pattern})
				break
			}
		}
	}

	return findings, creds
}

// detectConnectionStrings checks for database and service URLs with credentials
func detectConnectionStrings(data map[string]string) ([]string, []CredentialFinding) {
	var findings []string
	var creds []CredentialFinding

	patterns := []struct {
		regex *regexp.Regexp
		desc  string
	}{
		{regexp.MustCompile(`postgres://[^:]+:[^@]+@[^\s]+`), "PostgreSQL"},
		{regexp.MustCompile(`mysql://[^:]+:[^@]+@[^\s]+`), "MySQL"},
		{regexp.MustCompile(`mongodb://[^:]+:[^@]+@[^\s]+`), "MongoDB"},
		{regexp.MustCompile(`redis://[^:]+:[^@]+@[^\s]+`), "Redis"},
		{regexp.MustCompile(`amqp://[^:]+:[^@]+@[^\s]+`), "AMQP/RabbitMQ"},
		{regexp.MustCompile(`Server=[^;]+;.*Password=[^;]+`), "SQL Server"},
	}

	for key, value := range data {
		for _, pattern := range patterns {
			if match := pattern.regex.FindString(value); match != "" {
				findings = append(findings, fmt.Sprintf("%s Connection String in '%s'", pattern.desc, key))
				creds = append(creds, CredentialFinding{Type: "ConnString", Key: key, Value: match, FullValue: match, Description: pattern.desc + " Connection String"})
			}
		}
	}

	return findings, creds
}

// detectBase64Secrets attempts to decode base64 values and analyze content
func detectBase64Secrets(data map[string]string) ([]string, []CredentialFinding) {
	var findings []string
	var creds []CredentialFinding

	base64Pattern := regexp.MustCompile(`^[A-Za-z0-9+/]{20,}={0,2}$`)

	for key, value := range data {
		if strings.Contains(value, "-----BEGIN") {
			continue
		}

		if base64Pattern.MatchString(value) && len(value) > 20 {
			decoded, err := base64.StdEncoding.DecodeString(value)
			if err == nil {
				decodedStr := string(decoded)
				lowerDecoded := strings.ToLower(decodedStr)
				if strings.Contains(lowerDecoded, "password") ||
					strings.Contains(lowerDecoded, "secret") ||
					strings.Contains(lowerDecoded, "token") ||
					strings.Contains(lowerDecoded, "api") ||
					strings.Contains(decodedStr, "-----BEGIN") {
					findings = append(findings, fmt.Sprintf("Base64-encoded Secret in '%s'", key))
					creds = append(creds, CredentialFinding{Type: "Base64", Key: key, Value: decodedStr, FullValue: decodedStr, Description: "Base64-encoded Secret"})
				}
			}
		}
	}

	return findings, creds
}

// detectDockerCredentials checks for Docker registry credentials
func detectDockerCredentials(data map[string]string) ([]string, []CredentialFinding) {
	var findings []string
	var creds []CredentialFinding

	for key, value := range data {
		if strings.Contains(key, "docker") && strings.Contains(key, "config") {
			var dockerConfig map[string]interface{}
			if err := json.Unmarshal([]byte(value), &dockerConfig); err == nil {
				if auths, ok := dockerConfig["auths"].(map[string]interface{}); ok && len(auths) > 0 {
					var registries []string
					for reg := range auths {
						registries = append(registries, reg)
					}
					findings = append(findings, fmt.Sprintf("Docker Registry Credentials in '%s'", key))
					creds = append(creds, CredentialFinding{Type: "Docker", Key: key, Value: strings.Join(registries, ","), FullValue: value, Description: "Docker Registry Credentials"})
				}
			}
		}

		lowerKey := strings.ToLower(key)
		if strings.Contains(lowerKey, "docker") && (strings.Contains(lowerKey, "auth") || strings.Contains(lowerKey, "password")) {
			findings = append(findings, fmt.Sprintf("Docker Credentials in '%s'", key))
			creds = append(creds, CredentialFinding{Type: "Docker", Key: key, Value: value, FullValue: value, Description: "Docker Credentials"})
		}
	}

	return findings, creds
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

// detectSensitiveKeywords checks for sensitive keywords in key names only (not values).
// alreadyDetected contains keys already flagged by specific detectors to avoid duplicates.
func detectSensitiveKeywords(data map[string]string, alreadyDetected map[string]bool) ([]string, []CredentialFinding) {
	suspects := []string{"password", "passwd", "secret_key", "secret-key", "secretkey", "token", "credentials", "api_key", "api-key", "apikey", "private_key", "private-key", "access_key", "access-key"}
	var hits []string
	var creds []CredentialFinding

	for k, v := range data {
		if alreadyDetected[k] {
			continue
		}
		lk := strings.ToLower(k)
		for _, s := range suspects {
			if strings.Contains(lk, s) {
				hits = append(hits, k)
				creds = append(creds, CredentialFinding{Type: "SensitiveKeyword", Key: k, Value: v, FullValue: v, Description: fmt.Sprintf("keyword: %s", s)})
				break
			}
		}
	}

	return hits, creds
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
	var credFindings []CredentialFinding
	var creds []CredentialFinding
	finding.AWSCredentials, creds = detectAWSCredentials(cm.Data)
	credFindings = append(credFindings, creds...)
	finding.GCPCredentials, creds = detectGCPCredentials(cm.Data)
	credFindings = append(credFindings, creds...)
	finding.GitHubTokens, creds = detectGitHubTokens(cm.Data)
	credFindings = append(credFindings, creds...)
	finding.PrivateKeys, creds = detectPrivateKeys(cm.Data)
	credFindings = append(credFindings, creds...)
	finding.ConnectionStrings, creds = detectConnectionStrings(cm.Data)
	credFindings = append(credFindings, creds...)
	finding.Base64Secrets, creds = detectBase64Secrets(cm.Data)
	credFindings = append(credFindings, creds...)
	finding.DockerCredentials, creds = detectDockerCredentials(cm.Data)
	credFindings = append(credFindings, creds...)
	finding.KubeconfigFound = detectKubeconfig(cm.Data)
	if finding.KubeconfigFound {
		for key, value := range cm.Data {
			if strings.Contains(value, "apiVersion:") && strings.Contains(value, "kind: Config") {
				credFindings = append(credFindings, CredentialFinding{Type: "Kubeconfig", Key: key, Value: value, FullValue: value, Description: "Kubeconfig"})
			}
		}
	}
	// Sensitive keywords don't produce credential findings (no detected value shown)
	alreadyDetected := make(map[string]bool)
	for _, cf := range credFindings {
		alreadyDetected[cf.Key] = true
	}
	finding.SensitiveKeys, _ = detectSensitiveKeywords(cm.Data, alreadyDetected)
	finding.CredentialFindings = credFindings

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

// hasSensitiveData returns true if the configmap contains credentials or sensitive patterns
func hasSensitiveData(finding ConfigMapFinding) bool {
	return len(finding.AWSCredentials) > 0 ||
		len(finding.GCPCredentials) > 0 ||
		len(finding.GitHubTokens) > 0 ||
		len(finding.PrivateKeys) > 0 ||
		len(finding.ConnectionStrings) > 0 ||
		len(finding.DockerCredentials) > 0 ||
		len(finding.Base64Secrets) > 0 ||
		finding.KubeconfigFound
}

// generateConfigMapLoot creates a single consolidated commands loot file
func generateConfigMapLoot(findings []ConfigMapFinding, allConfigMaps []corev1.ConfigMap, outputDirectory string) []internal.LootFile {
	loot := shared.NewLootBuilder()

	// Filter findings by sensitivity
	var sensitiveFindings []ConfigMapFinding

	for _, f := range findings {
		if hasSensitiveData(f) {
			sensitiveFindings = append(sensitiveFindings, f)
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

	if len(sensitiveFindings) > 0 {
		cmds.Add("# Bulk extraction script")
		cmds.Add("mkdir -p configmap-dump && cd configmap-dump")
		cmds.Add("")

		for _, f := range sensitiveFindings {
			cmds.Addf("# %s/%s - %s", f.Namespace, f.Name, strings.Join(f.DangerousPatterns, ", "))
			cmds.Addf("kubectl get configmap -n %s %s -o yaml > %s-%s.yaml", f.Namespace, f.Name, f.Namespace, f.Name)
			cmds.Add("")
		}
	} else {
		cmds.Add("# No ConfigMaps with detected credentials found")
		cmds.Add("# Use generic extraction:")
		cmds.Add("kubectl get configmap <name> -n <namespace> -o yaml > configmap.yaml")
		cmds.Add("")
	}

	// Section 3: Decode Base64 secrets
	hasBase64 := false
	for _, f := range sensitiveFindings {
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
		for _, f := range sensitiveFindings {
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

	for _, f := range sensitiveFindings {
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
		for _, f := range sensitiveFindings {
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
		for _, f := range sensitiveFindings {
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
		for _, f := range sensitiveFindings {
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
		for _, f := range sensitiveFindings {
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
		for _, f := range sensitiveFindings {
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
		for _, f := range sensitiveFindings {
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

	// Full configmap data dump
	dump := loot.Section("ConfigMap-Data")
	dump.Add("═══════════════════════════════════════════════════════════════")
	dump.Add("         CONFIGMAP FULL DATA DUMP")
	dump.Add("═══════════════════════════════════════════════════════════════")
	dump.Add("")

	for _, cm := range allConfigMaps {
		if len(cm.Data) == 0 && len(cm.BinaryData) == 0 {
			continue
		}

		dump.Add(fmt.Sprintf("##############################################"))
		dump.Add(fmt.Sprintf("## %s/%s", cm.Namespace, cm.Name))
		dump.Add(fmt.Sprintf("## Keys: %d | Created: %s", len(cm.Data)+len(cm.BinaryData), cm.CreationTimestamp.Format("2006-01-02 15:04:05")))
		if cm.Immutable != nil && *cm.Immutable {
			dump.Add("## Immutable: Yes")
		}
		dump.Add(fmt.Sprintf("##############################################"))
		dump.Add("")

		for key, value := range cm.Data {
			dump.Add(fmt.Sprintf("--- [%s] ---", key))
			dump.Add(value)
			dump.Add("")
		}

		for key, value := range cm.BinaryData {
			encoded := base64.StdEncoding.EncodeToString(value)
			dump.Add(fmt.Sprintf("--- [%s] (binary, base64-encoded) ---", key))
			dump.Add(encoded)
			dump.Add("")
		}
	}

	return loot.Build()
}
