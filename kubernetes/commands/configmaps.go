package commands

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
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
}

type CredentialFinding struct {
	Type        string // "AWS", "GCP", "GitHub", "PrivateKey", etc.
	Key         string // ConfigMap key where found
	Value       string // Actual credential (truncated for display)
	FullValue   string // Full credential value
	Description string // What this credential is
}

func ListConfigMaps(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	logger := internal.NewLogger()

	// Extract global flags
	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating configmaps for %s", globals.ClusterName), globals.K8S_CONFIGMAPS_MODULE_NAME)

	clientset := config.GetClientOrExit()

	namespaces, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing namespaces: %v", err), globals.K8S_CONFIGMAPS_MODULE_NAME)
		return
	}

	headers := []string{
		"Namespace", "Name", "Risk Level", "Dangerous Patterns", "Data Keys", "Mounted By Pods", "Data Size", "Creation Timestamp",
	}

	var outputRows [][]string
	var findings []ConfigMapFinding

	// Risk counters
	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0

	for _, ns := range namespaces.Items {
		cms, err := clientset.CoreV1().ConfigMaps(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error listing configmaps in namespace %s: %v\n", ns.Name, err)
			continue
		}

		for _, cm := range cms.Items {
			// Perform comprehensive security analysis
			finding := analyzeConfigMapSecurity(&cm)

			// Find pods mounting this ConfigMap
			finding.MountedByPods = findPodsMountingConfigMap(ctx, clientset, cm.Namespace, cm.Name)
			finding.UsageCount = len(finding.MountedByPods)

			// Calculate risk level
			finding.RiskLevel = calculateConfigMapRiskLevel(finding)

			// Update risk counters
			switch finding.RiskLevel {
			case "CRITICAL":
				criticalCount++
			case "HIGH":
				highCount++
			case "MEDIUM":
				mediumCount++
			case "LOW":
				lowCount++
			}

			findings = append(findings, finding)

			// Build table row
			dangerousPatternsStr := fmt.Sprintf("%d found", len(finding.DangerousPatterns))
			if len(finding.DangerousPatterns) == 0 {
				dangerousPatternsStr = "None"
			}

			dataKeysStr := strings.Join(finding.DataKeys, ", ")
			if len(dataKeysStr) > 50 {
				dataKeysStr = dataKeysStr[:47] + "..."
			}
			if len(finding.DataKeys) == 0 {
				dataKeysStr = "<NONE>"
			}

			mountedByStr := fmt.Sprintf("%d pods", finding.UsageCount)
			if finding.UsageCount == 0 {
				mountedByStr = "Not mounted"
			}

			dataSizeStr := fmt.Sprintf("%d bytes", finding.DataSize)

			row := []string{
				finding.Namespace,
				finding.Name,
				finding.RiskLevel,
				dangerousPatternsStr,
				dataKeysStr,
				mountedByStr,
				dataSizeStr,
				finding.CreationTimestamp,
			}
			outputRows = append(outputRows, row)
		}
	}

	// Log risk summary
	logger.InfoM(fmt.Sprintf("Risk Distribution: CRITICAL=%d | HIGH=%d | MEDIUM=%d | LOW=%d",
		criticalCount, highCount, mediumCount, lowCount),
		globals.K8S_CONFIGMAPS_MODULE_NAME)

	table := internal.TableFile{
		Name:   "ConfigMaps",
		Header: headers,
		Body:   outputRows,
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
			Table: []internal.TableFile{table},
			Loot:  lootFiles,
		},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_CONFIGMAPS_MODULE_NAME)
		return
	}

	if len(outputRows) > 0 {
		logger.InfoM(fmt.Sprintf("%d configmaps found", len(outputRows)), globals.K8S_CONFIGMAPS_MODULE_NAME)
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

// findPodsMountingConfigMap finds all pods that mount a specific ConfigMap
func findPodsMountingConfigMap(ctx context.Context, clientset *kubernetes.Clientset, namespace, configMapName string) []string {
	var mountingPods []string

	pods, err := clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return mountingPods
	}

	for _, pod := range pods.Items {
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
		return "CRITICAL"
	}

	// HIGH: Contains base64 secrets or mounted by many pods
	if len(finding.Base64Secrets) > 0 || finding.UsageCount >= 5 {
		return "HIGH"
	}

	// MEDIUM: Contains sensitive keywords or mounted by some pods
	if len(finding.SensitiveKeys) > 0 || finding.UsageCount >= 2 {
		return "MEDIUM"
	}

	// LOW: Standard configuration
	return "LOW"
}

// generateConfigMapLoot creates loot files with exploitation techniques
func generateConfigMapLoot(findings []ConfigMapFinding, outputDirectory string) []internal.LootFile {
	var lootFiles []internal.LootFile

	// Filter findings by risk level
	criticalFindings := []ConfigMapFinding{}
	highFindings := []ConfigMapFinding{}
	mediumFindings := []ConfigMapFinding{}

	for _, f := range findings {
		switch f.RiskLevel {
		case "CRITICAL":
			criticalFindings = append(criticalFindings, f)
		case "HIGH":
			highFindings = append(highFindings, f)
		case "MEDIUM":
			mediumFindings = append(mediumFindings, f)
		}
	}

	// Loot 1: Basic enumeration (all ConfigMaps)
	enumLoot := "# ConfigMap Enumeration\n\n"
	enumLoot += fmt.Sprintf("## Summary\n")
	enumLoot += fmt.Sprintf("- Total ConfigMaps: %d\n", len(findings))
	enumLoot += fmt.Sprintf("- CRITICAL Risk: %d\n", len(criticalFindings))
	enumLoot += fmt.Sprintf("- HIGH Risk: %d\n", len(highFindings))
	enumLoot += fmt.Sprintf("- MEDIUM Risk: %d\n", len(mediumFindings))
	enumLoot += fmt.Sprintf("\n## Enumeration Commands\n\n")
	enumLoot += "### List all ConfigMaps\n"
	enumLoot += "kubectl get configmaps -A\n\n"
	enumLoot += "### Get specific ConfigMap\n"
	enumLoot += "kubectl get configmap <name> -n <namespace> -o yaml\n\n"
	enumLoot += "### Extract all ConfigMap data\n"
	enumLoot += "kubectl get configmaps -A -o json | jq -r '.items[] | \"\\(.metadata.namespace)/\\(.metadata.name): \\(.data)\"'\n\n"

	for _, f := range findings {
		if f.RiskLevel != "LOW" {
			enumLoot += fmt.Sprintf("### %s/%s (%s)\n", f.Namespace, f.Name, f.RiskLevel)
			enumLoot += fmt.Sprintf("kubectl get configmap -n %s %s -o yaml\n", f.Namespace, f.Name)
			enumLoot += fmt.Sprintf("kubectl get configmap -n %s %s -o json | jq '.data'\n\n", f.Namespace, f.Name)
		}
	}

	lootFiles = append(lootFiles, internal.LootFile{
		Name:     "ConfigMap-Enum",
		Contents: enumLoot,
	})

	// Loot 2: Sensitive Data (CRITICAL and HIGH findings)
	if len(criticalFindings) > 0 || len(highFindings) > 0 {
		sensitiveLoot := "# ConfigMap Sensitive Data\n\n"
		sensitiveLoot += "## CRITICAL Findings\n\n"

		for _, f := range criticalFindings {
			sensitiveLoot += fmt.Sprintf("### %s/%s\n", f.Namespace, f.Name)
			sensitiveLoot += fmt.Sprintf("**Risk Level:** CRITICAL\n\n")

			if len(f.DangerousPatterns) > 0 {
				sensitiveLoot += "**Detected Secrets:**\n"
				for _, pattern := range f.DangerousPatterns {
					sensitiveLoot += fmt.Sprintf("- %s\n", pattern)
				}
				sensitiveLoot += "\n"
			}

			sensitiveLoot += "**Extraction Commands:**\n"
			sensitiveLoot += fmt.Sprintf("```bash\n")
			sensitiveLoot += fmt.Sprintf("# Extract all data\n")
			sensitiveLoot += fmt.Sprintf("kubectl get configmap -n %s %s -o json | jq '.data'\n\n", f.Namespace, f.Name)

			for _, key := range f.DataKeys {
				sensitiveLoot += fmt.Sprintf("# Extract specific key: %s\n", key)
				sensitiveLoot += fmt.Sprintf("kubectl get configmap -n %s %s -o jsonpath='{.data.%s}'\n", f.Namespace, f.Name, key)
			}
			sensitiveLoot += "```\n\n"
		}

		sensitiveLoot += "## HIGH Findings\n\n"
		for _, f := range highFindings {
			sensitiveLoot += fmt.Sprintf("### %s/%s\n", f.Namespace, f.Name)
			if len(f.Base64Secrets) > 0 {
				sensitiveLoot += "**Base64-encoded secrets detected**\n"
				sensitiveLoot += fmt.Sprintf("```bash\n")
				for _, key := range f.DataKeys {
					sensitiveLoot += fmt.Sprintf("# Decode %s\n", key)
					sensitiveLoot += fmt.Sprintf("kubectl get configmap -n %s %s -o jsonpath='{.data.%s}' | base64 -d\n", f.Namespace, f.Name, key)
				}
				sensitiveLoot += "```\n\n"
			}
		}

		lootFiles = append(lootFiles, internal.LootFile{
			Name:     "ConfigMap-Sensitive-Data",
			Contents: sensitiveLoot,
		})
	}

	// Loot 3: Exploitation techniques
	exploitLoot := "# ConfigMap Exploitation\n\n"
	exploitLoot += "## Overview\n"
	exploitLoot += "ConfigMaps containing sensitive data can be exploited in multiple ways.\n\n"

	exploitLoot += "## Technique 1: Direct Access (if you have read permissions)\n"
	exploitLoot += "```bash\n"
	exploitLoot += "# List all ConfigMaps you can access\n"
	exploitLoot += "kubectl auth can-i get configmaps --all-namespaces\n"
	exploitLoot += "kubectl get configmaps -A\n\n"
	exploitLoot += "# Extract sensitive ConfigMaps\n"
	for _, f := range criticalFindings {
		exploitLoot += fmt.Sprintf("kubectl get configmap -n %s %s -o json | jq '.data'\n", f.Namespace, f.Name)
	}
	exploitLoot += "```\n\n"

	exploitLoot += "## Technique 2: Pod Injection to Mount ConfigMaps\n"
	exploitLoot += "If you can create pods, mount sensitive ConfigMaps:\n"
	exploitLoot += "```yaml\n"
	exploitLoot += "apiVersion: v1\n"
	exploitLoot += "kind: Pod\n"
	exploitLoot += "metadata:\n"
	exploitLoot += "  name: configmap-reader\n"
	exploitLoot += "  namespace: TARGET_NAMESPACE\n"
	exploitLoot += "spec:\n"
	exploitLoot += "  containers:\n"
	exploitLoot += "  - name: reader\n"
	exploitLoot += "    image: alpine\n"
	exploitLoot += "    command: [\"sleep\", \"3600\"]\n"
	exploitLoot += "    volumeMounts:\n"
	exploitLoot += "    - name: config\n"
	exploitLoot += "      mountPath: /config\n"
	exploitLoot += "  volumes:\n"
	exploitLoot += "  - name: config\n"
	exploitLoot += "    configMap:\n"
	exploitLoot += "      name: TARGET_CONFIGMAP\n"
	exploitLoot += "```\n\n"
	exploitLoot += "Then extract:\n"
	exploitLoot += "```bash\n"
	exploitLoot += "kubectl exec -it configmap-reader -n TARGET_NAMESPACE -- cat /config/*\n"
	exploitLoot += "```\n\n"

	exploitLoot += "## Technique 3: Modify ConfigMaps (if you have write permissions)\n"
	exploitLoot += "```bash\n"
	exploitLoot += "# Check if you can update ConfigMaps\n"
	exploitLoot += "kubectl auth can-i update configmaps --all-namespaces\n\n"
	exploitLoot += "# Inject malicious configuration\n"
	exploitLoot += "kubectl edit configmap -n TARGET_NAMESPACE TARGET_CONFIGMAP\n"
	exploitLoot += "```\n\n"

	exploitLoot += "## Technique 4: Using Found Credentials\n\n"

	if len(criticalFindings) > 0 {
		exploitLoot += "### AWS Credentials\n"
		for _, f := range criticalFindings {
			if len(f.AWSCredentials) > 0 {
				exploitLoot += fmt.Sprintf("```bash\n")
				exploitLoot += fmt.Sprintf("# Extract AWS credentials from %s/%s\n", f.Namespace, f.Name)
				exploitLoot += fmt.Sprintf("AWS_ACCESS_KEY_ID=$(kubectl get configmap -n %s %s -o jsonpath='{.data.AWS_ACCESS_KEY_ID}')\n", f.Namespace, f.Name)
				exploitLoot += fmt.Sprintf("AWS_SECRET_ACCESS_KEY=$(kubectl get configmap -n %s %s -o jsonpath='{.data.AWS_SECRET_ACCESS_KEY}')\n\n", f.Namespace, f.Name)
				exploitLoot += "# Use credentials\n"
				exploitLoot += "export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY\n"
				exploitLoot += "aws sts get-caller-identity\n"
				exploitLoot += "aws s3 ls\n"
				exploitLoot += "```\n\n"
			}
		}

		exploitLoot += "### GitHub Tokens\n"
		for _, f := range criticalFindings {
			if len(f.GitHubTokens) > 0 {
				exploitLoot += fmt.Sprintf("```bash\n")
				exploitLoot += fmt.Sprintf("# Extract GitHub token from %s/%s\n", f.Namespace, f.Name)
				exploitLoot += fmt.Sprintf("GH_TOKEN=$(kubectl get configmap -n %s %s -o jsonpath='{.data.GITHUB_TOKEN}')\n\n", f.Namespace, f.Name)
				exploitLoot += "# Use token\n"
				exploitLoot += "curl -H \"Authorization: token $GH_TOKEN\" https://api.github.com/user\n"
				exploitLoot += "```\n\n"
			}
		}

		exploitLoot += "### Database Connection Strings\n"
		for _, f := range criticalFindings {
			if len(f.ConnectionStrings) > 0 {
				exploitLoot += fmt.Sprintf("```bash\n")
				exploitLoot += fmt.Sprintf("# Extract connection string from %s/%s\n", f.Namespace, f.Name)
				exploitLoot += fmt.Sprintf("DB_URL=$(kubectl get configmap -n %s %s -o jsonpath='{.data.DATABASE_URL}')\n\n", f.Namespace, f.Name)
				exploitLoot += "# Connect to database\n"
				exploitLoot += "psql \"$DB_URL\"\n"
				exploitLoot += "```\n\n"
			}
		}
	}

	lootFiles = append(lootFiles, internal.LootFile{
		Name:     "ConfigMap-Exploitation",
		Contents: exploitLoot,
	})

	// Loot 4: Pod Mounting Analysis
	mountingLoot := "# ConfigMap Pod Mounting Analysis\n\n"
	mountingLoot += "## Overview\n"
	mountingLoot += "Understanding which pods mount ConfigMaps helps identify access patterns and potential targets.\n\n"

	mountingLoot += "## Sensitive ConfigMaps Mounted by Pods\n\n"
	for _, f := range findings {
		if f.UsageCount > 0 && f.RiskLevel != "LOW" {
			mountingLoot += fmt.Sprintf("### %s/%s (%s)\n", f.Namespace, f.Name, f.RiskLevel)
			mountingLoot += fmt.Sprintf("**Mounted by %d pod(s):**\n", f.UsageCount)
			for _, pod := range f.MountedByPods {
				mountingLoot += fmt.Sprintf("- %s\n", pod)
			}
			mountingLoot += "\n**Access Commands:**\n"
			mountingLoot += "```bash\n"
			for _, pod := range f.MountedByPods {
				mountingLoot += fmt.Sprintf("# Access ConfigMap from pod %s\n", pod)
				mountingLoot += fmt.Sprintf("kubectl exec -it %s -n %s -- env\n", pod, f.Namespace)
				mountingLoot += fmt.Sprintf("kubectl exec -it %s -n %s -- find / -name '*config*' 2>/dev/null\n", pod, f.Namespace)
			}
			mountingLoot += "```\n\n"
		}
	}

	mountingLoot += "## Find All Pods Mounting ConfigMaps\n"
	mountingLoot += "```bash\n"
	mountingLoot += "# List all pods with their mounted ConfigMaps\n"
	mountingLoot += "kubectl get pods -A -o json | jq -r '.items[] | \"\\(.metadata.namespace)/\\(.metadata.name): \" + ([.spec.volumes[]? | select(.configMap != null) | .configMap.name] | join(\", \"))'\n"
	mountingLoot += "```\n\n"

	lootFiles = append(lootFiles, internal.LootFile{
		Name:     "ConfigMap-Mounted-By",
		Contents: mountingLoot,
	})

	// Loot 5: Extraction commands for all sensitive ConfigMaps
	extractionLoot := "# ConfigMap Extraction Commands\n\n"
	extractionLoot += "## Quick Extraction Scripts\n\n"

	extractionLoot += "### Extract All CRITICAL ConfigMaps\n"
	extractionLoot += "```bash\n"
	for _, f := range criticalFindings {
		extractionLoot += fmt.Sprintf("# %s/%s\n", f.Namespace, f.Name)
		extractionLoot += fmt.Sprintf("kubectl get configmap -n %s %s -o json > %s-%s.json\n", f.Namespace, f.Name, f.Namespace, f.Name)
	}
	extractionLoot += "```\n\n"

	extractionLoot += "### Extract and Decode Base64 Secrets\n"
	extractionLoot += "```bash\n"
	for _, f := range highFindings {
		if len(f.Base64Secrets) > 0 {
			extractionLoot += fmt.Sprintf("# %s/%s\n", f.Namespace, f.Name)
			for _, key := range f.DataKeys {
				extractionLoot += fmt.Sprintf("kubectl get configmap -n %s %s -o jsonpath='{.data.%s}' | base64 -d > %s-%s-%s.txt\n",
					f.Namespace, f.Name, key, f.Namespace, f.Name, key)
			}
		}
	}
	extractionLoot += "```\n\n"

	extractionLoot += "### Bulk Extraction Script\n"
	extractionLoot += "```bash\n"
	extractionLoot += "#!/bin/bash\n"
	extractionLoot += "# Extract all sensitive ConfigMaps\n\n"
	extractionLoot += "mkdir -p configmap-dump\n"
	extractionLoot += "cd configmap-dump\n\n"
	for _, f := range append(criticalFindings, highFindings...) {
		extractionLoot += fmt.Sprintf("echo \"Extracting %s/%s\"\n", f.Namespace, f.Name)
		extractionLoot += fmt.Sprintf("kubectl get configmap -n %s %s -o yaml > %s-%s.yaml\n", f.Namespace, f.Name, f.Namespace, f.Name)
	}
	extractionLoot += "```\n"

	lootFiles = append(lootFiles, internal.LootFile{
		Name:     "ConfigMap-Extraction",
		Contents: extractionLoot,
	})

	return lootFiles
}
