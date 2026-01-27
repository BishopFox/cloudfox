package attackpathservice

import (
	"context"
	"fmt"
	"strings"

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
		{Verb: "get", Resource: "nodes/proxy", APIGroup: "", Category: "Node Access", RiskLevel: shared.RiskHigh, Description: "Access kubelet API via proxy"},

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

// analyzeRulesForAttackPaths analyzes RBAC rules for attack paths
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

	// Get permission maps based on path type
	privescMap := buildPrivescPermissionMap()
	lateralMap := buildLateralPermissionMap()
	exfilMap := buildDataExfilPermissionMap()

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
					permKey := buildPermissionKey(verb, resource, apiGroup)

					// Check against appropriate permission maps based on pathType
					if pathType == "privesc" || pathType == "all" {
						if perm, ok := privescMap[permKey]; ok {
							path := AttackPath{
								Principal:      principal,
								PrincipalType:  principalType,
								Method:         perm.Category,
								TargetResource: resource,
								Permissions:    []string{fmt.Sprintf("%s %s", verb, resource)},
								Category:       perm.Category,
								RiskLevel:      perm.RiskLevel,
								Description:    perm.Description,
								ExploitCommand: generateExploitCommand("privesc", verb, resource, scopeID, principal),
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
						// Check wildcards
						if verb == "*" || resource == "*" {
							path := AttackPath{
								Principal:      principal,
								PrincipalType:  principalType,
								Method:         "Wildcard Access",
								TargetResource: resource,
								Permissions:    []string{fmt.Sprintf("%s %s", verb, resource)},
								Category:       "Wildcard",
								RiskLevel:      shared.RiskCritical,
								Description:    "Wildcard verb or resource grants excessive permissions",
								ExploitCommand: generateExploitCommand("privesc", verb, resource, scopeID, principal),
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

					if pathType == "lateral" || pathType == "all" {
						if perm, ok := lateralMap[permKey]; ok {
							path := AttackPath{
								Principal:      principal,
								PrincipalType:  principalType,
								Method:         perm.Category,
								TargetResource: resource,
								Permissions:    []string{fmt.Sprintf("%s %s", verb, resource)},
								Category:       perm.Category,
								RiskLevel:      perm.RiskLevel,
								Description:    perm.Description,
								ExploitCommand: generateExploitCommand("lateral", verb, resource, scopeID, principal),
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

					if pathType == "exfil" || pathType == "all" {
						if perm, ok := exfilMap[permKey]; ok {
							path := AttackPath{
								Principal:      principal,
								PrincipalType:  principalType,
								Method:         perm.Category,
								TargetResource: resource,
								Permissions:    []string{fmt.Sprintf("%s %s", verb, resource)},
								Category:       perm.Category,
								RiskLevel:      perm.RiskLevel,
								Description:    perm.Description,
								ExploitCommand: generateExploitCommand("exfil", verb, resource, scopeID, principal),
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

func buildPermissionKey(verb, resource, apiGroup string) string {
	if apiGroup == "" {
		return fmt.Sprintf("%s:%s:", verb, resource)
	}
	return fmt.Sprintf("%s:%s:%s", verb, resource, apiGroup)
}

func buildPrivescPermissionMap() map[string]PrivescPermission {
	m := make(map[string]PrivescPermission)
	for _, p := range GetPrivescPermissions() {
		key := buildPermissionKey(p.Verb, p.Resource, p.APIGroup)
		m[key] = p
	}
	return m
}

func buildLateralPermissionMap() map[string]LateralMovementPermission {
	m := make(map[string]LateralMovementPermission)
	for _, p := range GetLateralMovementPermissions() {
		key := buildPermissionKey(p.Verb, p.Resource, p.APIGroup)
		m[key] = p
	}
	return m
}

func buildDataExfilPermissionMap() map[string]DataExfilPermission {
	m := make(map[string]DataExfilPermission)
	for _, p := range GetDataExfilPermissions() {
		key := buildPermissionKey(p.Verb, p.Resource, p.APIGroup)
		m[key] = p
	}
	return m
}

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

	switch pathType {
	case "privesc":
		switch {
		case resource == "pods" && verb == "create":
			return fmt.Sprintf("kubectl %srun privesc --image=alpine --restart=Never --overrides='{\"spec\":{\"serviceAccountName\":\"%s\",\"containers\":[{\"name\":\"privesc\",\"image\":\"alpine\",\"command\":[\"sh\",\"-c\",\"sleep 3600\"],\"securityContext\":{\"privileged\":true}}]}}' -- sleep 3600", namespaceFlag, principal)
		case resource == "pods/exec":
			return fmt.Sprintf("kubectl %sexec -it <pod-name> -- /bin/sh", namespaceFlag)
		case resource == "clusterrolebindings" && verb == "create":
			return fmt.Sprintf("kubectl create clusterrolebinding escalate-binding --clusterrole=cluster-admin --user=%s", principal)
		case resource == "rolebindings" && verb == "create":
			return fmt.Sprintf("kubectl %screate rolebinding escalate-binding --clusterrole=admin --user=%s", namespaceFlag, principal)
		case strings.Contains(resource, "impersonate"):
			return fmt.Sprintf("kubectl %sget secrets --as=system:admin", namespaceFlag)
		case resource == "serviceaccounts/token":
			return fmt.Sprintf("kubectl %screate token <service-account-name>", namespaceFlag)
		default:
			return fmt.Sprintf("kubectl %s%s %s", namespaceFlag, verb, resource)
		}

	case "lateral":
		switch {
		case resource == "pods/exec":
			return fmt.Sprintf("kubectl %sexec -it <target-pod> -- /bin/sh", namespaceFlag)
		case resource == "pods/portforward":
			return fmt.Sprintf("kubectl %sport-forward <pod-name> 8080:80", namespaceFlag)
		case resource == "secrets":
			return fmt.Sprintf("kubectl %sget secrets -o yaml", namespaceFlag)
		case resource == "services":
			return fmt.Sprintf("kubectl %sget services -o wide", namespaceFlag)
		default:
			return fmt.Sprintf("kubectl %s%s %s", namespaceFlag, verb, resource)
		}

	case "exfil":
		switch {
		case resource == "secrets":
			return fmt.Sprintf("kubectl %sget secrets -o json | jq '.items[].data | map_values(@base64d)'", namespaceFlag)
		case resource == "configmaps":
			return fmt.Sprintf("kubectl %sget configmaps -o yaml", namespaceFlag)
		case resource == "pods/log":
			return fmt.Sprintf("kubectl %slogs <pod-name> --all-containers", namespaceFlag)
		case resource == "pods/exec":
			return fmt.Sprintf("kubectl %sexec <pod-name> -- cat /etc/passwd", namespaceFlag)
		default:
			return fmt.Sprintf("kubectl %s%s %s", namespaceFlag, verb, resource)
		}
	}

	return fmt.Sprintf("kubectl %s%s %s", namespaceFlag, verb, resource)
}
