package commands

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	k8sinternal "github.com/BishopFox/cloudfox/internal/kubernetes"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/spf13/cobra"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var ServiceAccountsCmd = &cobra.Command{
	Use:     "serviceaccounts",
	Aliases: []string{"sa"},
	Short:   "Enumerate service accounts with comprehensive security analysis",
	Long: `
Enumerate all service accounts in the cluster with enterprise-grade security analysis including:
  - Numeric risk scoring (0-100) with escalation path weights
  - Blast radius calculation (pods × risk score × workload multipliers)
  - Specific privilege escalation path detection (10+ attack vectors)
  - Token lifecycle analysis (projected vs legacy, rotation needs)
  - Workload type analysis (DaemonSet/CronJob/Deployment detection)
  - Default ServiceAccount security analysis
  - Cross-namespace access detection and scope analysis
  - Node-level permission analysis (container escape risks)
  - External exposure detection (SA tokens accessible from outside)
  - RBAC sprawl and policy bypass capability detection

  cloudfox kubernetes serviceaccounts`,
	Run: ListServiceAccounts,
}

type ServiceAccountOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (s ServiceAccountOutput) TableFiles() []internal.TableFile {
	return s.Table
}

func (s ServiceAccountOutput) LootFiles() []internal.LootFile {
	return s.Loot
}

type SAFinding struct {
	// Basic Info
	Namespace string
	Name      string
	Age       time.Duration
	AgeDays   int

	// Token Analysis
	Secrets             []string
	HasToken            bool
	AutoMountToken      string
	TokenType           string // "projected", "legacy-secret", "none"
	TokenAge            int    // days since secret created
	TokenRotationNeeded bool   // >90 days old
	LegacyTokenCount    int    // number of legacy token secrets
	ImagePullSecrets    []string

	// RBAC Bindings
	Roles             []string
	ClusterRoles      []string
	TotalRoleBindings int
	RBACSprawl        bool // >5 role bindings

	// Permission Analysis
	DangerousPermissions []string
	PermissionSummary    string
	AllPermissions       []string

	// Access Scope
	ClusterWideAccess    bool
	CrossNamespaceAccess bool
	AccessibleNamespaces []string
	PermissionScope      string // "cluster-wide", "cross-namespace", "namespace-only"

	// Escalation Capabilities
	CanCreatePods       bool
	CanExecPods         bool
	CanReadSecrets      bool
	CanModifyRBAC       bool
	CanImpersonate      bool
	CanAccessNodes      bool
	CanProxyNodes       bool
	CanModifyAdmission  bool
	CanBypassPolicies   bool
	EscalationPaths     []string
	EscalationPathCount int

	// Node-Level Permissions
	NodeAccess      bool
	NodePermissions []string

	// Workload Usage
	ActivelyUsed       bool
	PodsUsingSA        []string
	TotalPods          int
	WorkloadTypes      map[string]int // "Deployment": 2, "DaemonSet": 1
	WorkloadSummary    string         // "2 Deployments, 1 DaemonSet"
	DeploymentCount    int
	DaemonSetCount     int
	StatefulSetCount   int
	CronJobCount       int
	JobCount           int
	StandalonePodCount int

	// Pod Security Context Analysis
	PrivilegedPods       int
	HostNetworkPods      int
	HostPIDPods          int
	HostIPCPods          int
	PodsWithHostPath     int
	PodsWithCapabilities map[string]int // "SYS_ADMIN": 2, "NET_RAW": 1

	// External Exposure
	ExternallyExposed bool
	ExposureMethod    string // "LoadBalancer", "NodePort", "Ingress"
	ExposedPods       []string

	// Default SA Analysis
	IsDefaultSA     bool
	DefaultSARisk   string
	DefaultSAIssues []string

	// Risk Analysis
	RiskLevel      string
	RiskScore      int
	BlastRadius    int
	ImpactSummary  string
	SecurityIssues []string
}

type EscalationPath struct {
	Vector      string
	Description string
	Severity    string
	Steps       []string
	Mitigation  string
}

type WorkloadAnalysis struct {
	Types            map[string]int
	DeploymentCount  int
	DaemonSetCount   int
	StatefulSetCount int
	CronJobCount     int
	JobCount         int
	StandalonePods   int
	PrivilegedPods   int
	HostNetworkPods  int
	HostPIDPods      int
	HostIPCPods      int
	HostPathMounts   int
	Capabilities     map[string]int
}

type NodeAccessInfo struct {
	CanAccess   bool
	CanProxy    bool
	Permissions []string
}

type ExposureInfo struct {
	IsExposed bool
	Method    string
	Pods      []string
}

func ListServiceAccounts(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating service accounts for %s", globals.ClusterName), globals.K8S_SERVICEACCOUNTS_MODULE_NAME)

	clientset := config.GetClientOrExit()

	namespaces, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing namespaces: %v", err), globals.K8S_SERVICEACCOUNTS_MODULE_NAME)
		return
	}

	headers := []string{
		"Risk",
		"Score",
		"Blast Radius",
		"Namespace",
		"Service Account",
		"Active Pods",
		"Workload Types",
		"Priv Pods",
		"Token Type",
		"Escalation Paths",
		"Node Access",
		"Cross-NS",
		"Permissions",
		"Roles",
		"ClusterRoles",
		"Auto-Mount",
		"Issues",
	}

	var outputRows [][]string
	var findings []SAFinding

	// Risk level counters
	riskCounts := map[string]int{
		"CRITICAL": 0,
		"HIGH":     0,
		"MEDIUM":   0,
		"LOW":      0,
	}

	var lootEnum []string
	var lootTokens []string
	var lootImpersonate []string
	var lootExploit []string
	var lootPermissions []string
	var lootDefaultSA []string
	var lootCrossNS []string
	var lootNodeAccess []string
	var lootEscalationPaths []string
	var lootBlastRadius []string
	var lootTokenLifecycle []string
	var lootUnused []string
	var lootWorkloadMapping []string
	var lootRemediation []string

	lootEnum = append(lootEnum, `#####################################
##### ServiceAccount Enumeration
#####################################
#
# Complete service account inventory with security analysis
#
`)

	lootTokens = append(lootTokens, `#####################################
##### ServiceAccount Token Extraction
#####################################
#
# Extract and decode service account tokens
# IMPORTANT: Tokens provide authentication to the cluster
#
`)

	lootImpersonate = append(lootImpersonate, `#####################################
##### ServiceAccount Impersonation
#####################################
#
# Use service account tokens for authentication
# MANUAL EXECUTION REQUIRED
#
`)

	lootExploit = append(lootExploit, `#####################################
##### ServiceAccount Privilege Escalation
#####################################
#
# MANUAL EXECUTION REQUIRED
# Create pods to use privileged service accounts
# or abuse existing pods with high-privilege SAs
#
`)

	lootPermissions = append(lootPermissions, `#####################################
##### RBAC Permission Analysis
#####################################
#
# Detailed permission analysis for high-risk service accounts
# Focus on dangerous permissions that enable privilege escalation
#
`)

	lootDefaultSA = append(lootDefaultSA, `#####################################
##### Default ServiceAccount Security Issues
#####################################
#
# Default SAs should have minimal/no permissions
# Pods should use dedicated SAs, not default
#
`)

	lootCrossNS = append(lootCrossNS, `#####################################
##### Cross-Namespace Access
#####################################
#
# ServiceAccounts with cross-namespace or cluster-wide access
# High-risk: can pivot between namespaces
#
`)

	lootNodeAccess = append(lootNodeAccess, `#####################################
##### Node-Level Access
#####################################
#
# ServiceAccounts with node-level permissions
# CRITICAL: Can escape containers and access nodes
#
`)

	lootEscalationPaths = append(lootEscalationPaths, `#####################################
##### Privilege Escalation Paths
#####################################
#
# Specific attack vectors for each high-risk ServiceAccount
# Ordered by severity and exploitability
#
`)

	lootBlastRadius = append(lootBlastRadius, `#####################################
##### Blast Radius Analysis
#####################################
#
# Impact analysis: pods × risk score × workload multipliers
# Focus on highest blast radius for maximum cluster impact
#
`)

	lootTokenLifecycle = append(lootTokenLifecycle, `#####################################
##### Token Lifecycle and Rotation
#####################################
#
# Token age, type, and rotation recommendations
# Legacy tokens should be migrated to projected tokens
#
`)

	lootUnused = append(lootUnused, `#####################################
##### Unused ServiceAccounts
#####################################
#
# ServiceAccounts with 0 active pods
# Cleanup candidates to reduce attack surface
#
`)

	lootWorkloadMapping = append(lootWorkloadMapping, `#####################################
##### Workload to ServiceAccount Mapping
#####################################
#
# Which workloads use which ServiceAccounts
# Useful for impact analysis and least privilege design
#
`)

	lootRemediation = append(lootRemediation, `#####################################
##### Security Hardening Recommendations
#####################################
#
# Remediation steps for identified security issues
# Implement these to improve cluster security posture
#
`)

	if globals.KubeContext != "" {
		lootEnum = append(lootEnum, fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext))
	}

	// Build maps for RBAC bindings
	saRoleBindings := make(map[string]map[string][]string)        // ns -> sa -> []roles
	saClusterRoleBindings := make(map[string]map[string][]string) // ns -> sa -> []clusterroles
	saPods := make(map[string]map[string][]corev1.Pod)            // ns -> sa -> []pods
	saSecrets := make(map[string]map[string][]corev1.Secret)      // ns -> sa -> []secrets

	// Get all roles and clusterroles for permission analysis
	allRoles := make(map[string]map[string]*rbacv1.Role)    // ns -> role name -> Role
	allClusterRoles := make(map[string]*rbacv1.ClusterRole) // role name -> ClusterRole

	// Get all services for external exposure detection
	allServices := make(map[string][]corev1.Service) // ns -> []services

	// Get all ClusterRoles
	clusterRoles, err := clientset.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing cluster roles: %v", err), globals.K8S_SERVICEACCOUNTS_MODULE_NAME)
	} else {
		for _, cr := range clusterRoles.Items {
			allClusterRoles[cr.Name] = &cr
		}
	}

	// Get all ClusterRoleBindings
	clusterRoleBindings, err := clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing cluster role bindings: %v", err), globals.K8S_SERVICEACCOUNTS_MODULE_NAME)
	} else {
		for _, crb := range clusterRoleBindings.Items {
			for _, subj := range crb.Subjects {
				if subj.Kind == "ServiceAccount" {
					ns := subj.Namespace
					sa := subj.Name
					if saClusterRoleBindings[ns] == nil {
						saClusterRoleBindings[ns] = make(map[string][]string)
					}
					saClusterRoleBindings[ns][sa] = append(saClusterRoleBindings[ns][sa], crb.RoleRef.Name)
				}
			}
		}
	}

	// Process each namespace
	for _, ns := range namespaces.Items {
		// Get all roles in namespace
		roles, err := clientset.RbacV1().Roles(ns.Name).List(ctx, metav1.ListOptions{})
		if err == nil {
			allRoles[ns.Name] = make(map[string]*rbacv1.Role)
			for _, role := range roles.Items {
				allRoles[ns.Name][role.Name] = &role
			}
		}

		// Get all pods in namespace to map SA usage
		pods, err := clientset.CoreV1().Pods(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			logger.ErrorM(fmt.Sprintf("Error listing pods in namespace %s: %v", ns.Name, err), globals.K8S_SERVICEACCOUNTS_MODULE_NAME)
		} else {
			for _, pod := range pods.Items {
				// Only count running/pending pods for "active usage"
				if pod.Status.Phase == corev1.PodRunning || pod.Status.Phase == corev1.PodPending {
					saName := pod.Spec.ServiceAccountName
					if saName == "" {
						saName = "default"
					}
					if saPods[ns.Name] == nil {
						saPods[ns.Name] = make(map[string][]corev1.Pod)
					}
					saPods[ns.Name][saName] = append(saPods[ns.Name][saName], pod)
				}
			}
		}

		// Get RoleBindings in namespace
		roleBindings, err := clientset.RbacV1().RoleBindings(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			logger.ErrorM(fmt.Sprintf("Error listing role bindings in namespace %s: %v", ns.Name, err), globals.K8S_SERVICEACCOUNTS_MODULE_NAME)
		} else {
			for _, rb := range roleBindings.Items {
				for _, subj := range rb.Subjects {
					if subj.Kind == "ServiceAccount" {
						sa := subj.Name
						if saRoleBindings[ns.Name] == nil {
							saRoleBindings[ns.Name] = make(map[string][]string)
						}
						saRoleBindings[ns.Name][sa] = append(saRoleBindings[ns.Name][sa], rb.RoleRef.Name)
					}
				}
			}
		}

		// Get all secrets for token lifecycle analysis
		secrets, err := clientset.CoreV1().Secrets(ns.Name).List(ctx, metav1.ListOptions{})
		if err == nil {
			for _, secret := range secrets.Items {
				// Only track SA token secrets
				if secret.Type == corev1.SecretTypeServiceAccountToken {
					if saName, ok := secret.Annotations["kubernetes.io/service-account.name"]; ok {
						if saSecrets[ns.Name] == nil {
							saSecrets[ns.Name] = make(map[string][]corev1.Secret)
						}
						saSecrets[ns.Name][saName] = append(saSecrets[ns.Name][saName], secret)
					}
				}
			}
		}

		// Get services for external exposure detection
		services, err := clientset.CoreV1().Services(ns.Name).List(ctx, metav1.ListOptions{})
		if err == nil {
			allServices[ns.Name] = services.Items
		}

		// Get ServiceAccounts
		serviceAccounts, err := clientset.CoreV1().ServiceAccounts(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			logger.ErrorM(fmt.Sprintf("Error listing service accounts in namespace %s: %v", ns.Name, err), globals.K8S_SERVICEACCOUNTS_MODULE_NAME)
			continue
		}

		for _, sa := range serviceAccounts.Items {
			finding := SAFinding{
				Namespace:            ns.Name,
				Name:                 sa.Name,
				WorkloadTypes:        make(map[string]int),
				PodsWithCapabilities: make(map[string]int),
			}

			// Calculate age
			finding.Age = time.Since(sa.CreationTimestamp.Time)
			finding.AgeDays = int(finding.Age.Hours() / 24)

			// Get secrets
			var secretNames []string
			for _, secret := range sa.Secrets {
				secretNames = append(secretNames, secret.Name)
			}
			finding.Secrets = secretNames

			// Token lifecycle analysis
			tokenSecrets := saSecrets[ns.Name][sa.Name]
			finding.LegacyTokenCount = len(tokenSecrets)
			finding.HasToken = len(secretNames) > 0 || len(tokenSecrets) > 0

			if len(tokenSecrets) > 0 {
				finding.TokenType = "legacy-secret"
				// Calculate token age from oldest secret
				oldestAge := 0
				for _, secret := range tokenSecrets {
					age := int(time.Since(secret.CreationTimestamp.Time).Hours() / 24)
					if age > oldestAge {
						oldestAge = age
					}
				}
				finding.TokenAge = oldestAge
				finding.TokenRotationNeeded = oldestAge > 90
			} else if len(secretNames) == 0 {
				// No legacy secrets - likely using projected tokens (K8s 1.21+)
				finding.TokenType = "projected"
			} else {
				finding.TokenType = "none"
			}

			// Auto-mount token setting
			autoMount := "true (default)"
			if sa.AutomountServiceAccountToken != nil {
				if *sa.AutomountServiceAccountToken {
					autoMount = "true"
				} else {
					autoMount = "false"
				}
			}
			finding.AutoMountToken = autoMount

			// Get roles bound to this SA
			roles := saRoleBindings[ns.Name][sa.Name]
			clusterRoles := saClusterRoleBindings[ns.Name][sa.Name]
			finding.Roles = roles
			finding.ClusterRoles = clusterRoles
			finding.TotalRoleBindings = len(roles) + len(clusterRoles)
			finding.RBACSprawl = finding.TotalRoleBindings > 5

			// Get pods using this SA
			podsUsingSA := saPods[ns.Name][sa.Name]
			finding.TotalPods = len(podsUsingSA)
			finding.ActivelyUsed = len(podsUsingSA) > 0

			// Analyze workload types and pod security context
			if len(podsUsingSA) > 0 {
				workloadAnalysis := analyzeWorkloadTypes(ctx, clientset, ns.Name, podsUsingSA)
				finding.WorkloadTypes = workloadAnalysis.Types
				finding.DeploymentCount = workloadAnalysis.DeploymentCount
				finding.DaemonSetCount = workloadAnalysis.DaemonSetCount
				finding.StatefulSetCount = workloadAnalysis.StatefulSetCount
				finding.CronJobCount = workloadAnalysis.CronJobCount
				finding.JobCount = workloadAnalysis.JobCount
				finding.StandalonePodCount = workloadAnalysis.StandalonePods
				finding.PrivilegedPods = workloadAnalysis.PrivilegedPods
				finding.HostNetworkPods = workloadAnalysis.HostNetworkPods
				finding.HostPIDPods = workloadAnalysis.HostPIDPods
				finding.HostIPCPods = workloadAnalysis.HostIPCPods
				finding.PodsWithHostPath = workloadAnalysis.HostPathMounts
				finding.PodsWithCapabilities = workloadAnalysis.Capabilities

				finding.WorkloadSummary = generateWorkloadSummary(workloadAnalysis)

				// Store pod names for reference
				for _, pod := range podsUsingSA {
					finding.PodsUsingSA = append(finding.PodsUsingSA, pod.Name)
				}
			}

			// Get image pull secrets
			var imagePullSecrets []string
			for _, ips := range sa.ImagePullSecrets {
				imagePullSecrets = append(imagePullSecrets, ips.Name)
			}
			finding.ImagePullSecrets = imagePullSecrets

			// Analyze permissions
			permAnalysis := analyzePermissionsEnhanced(ns.Name, roles, clusterRoles, allRoles, allClusterRoles)
			finding.DangerousPermissions = permAnalysis.DangerousPerms
			finding.PermissionSummary = permAnalysis.Summary
			finding.AllPermissions = permAnalysis.AllPerms

			// Capability flags
			finding.CanCreatePods = permAnalysis.CanCreatePods
			finding.CanExecPods = permAnalysis.CanExecPods
			finding.CanReadSecrets = permAnalysis.CanReadSecrets
			finding.CanModifyRBAC = permAnalysis.CanModifyRBAC
			finding.CanImpersonate = permAnalysis.CanImpersonate
			finding.CanModifyAdmission = permAnalysis.CanModifyAdmission
			finding.CanBypassPolicies = permAnalysis.CanBypassPolicies

			// Node access analysis
			nodeAccess := analyzeNodePermissions(roles, clusterRoles, allRoles, allClusterRoles, ns.Name)
			finding.NodeAccess = nodeAccess.CanAccess
			finding.CanAccessNodes = nodeAccess.CanAccess
			finding.CanProxyNodes = nodeAccess.CanProxy
			finding.NodePermissions = nodeAccess.Permissions

			// Cross-namespace access analysis
			crossNSInfo := analyzeCrossNamespaceAccess(roles, clusterRoles, allRoles, allClusterRoles, ns.Name)
			finding.ClusterWideAccess = crossNSInfo.ClusterWide
			finding.CrossNamespaceAccess = crossNSInfo.CrossNamespace
			finding.AccessibleNamespaces = crossNSInfo.AccessibleNamespaces
			finding.PermissionScope = crossNSInfo.Scope

			// Default SA analysis
			if sa.Name == "default" {
				finding.IsDefaultSA = true
				defaultIssues := analyzeDefaultSA(&finding)
				finding.DefaultSAIssues = defaultIssues
				if len(defaultIssues) > 0 {
					finding.DefaultSARisk = "CRITICAL: default SA has security issues"
					finding.SecurityIssues = append(finding.SecurityIssues, defaultIssues...)
				}
			}

			// Detect escalation paths
			escalationPaths := detectEscalationPaths(&finding, permAnalysis)
			finding.EscalationPaths = escalationPaths
			finding.EscalationPathCount = len(escalationPaths)

			// External exposure detection
			if len(podsUsingSA) > 0 {
				exposureInfo := detectExternalExposure(podsUsingSA, allServices[ns.Name])
				finding.ExternallyExposed = exposureInfo.IsExposed
				finding.ExposureMethod = exposureInfo.Method
				finding.ExposedPods = exposureInfo.Pods
				if exposureInfo.IsExposed {
					finding.SecurityIssues = append(finding.SecurityIssues,
						fmt.Sprintf("SA tokens exposed via %s", exposureInfo.Method))
				}
			}

			// Token lifecycle issues
			if finding.TokenRotationNeeded {
				finding.SecurityIssues = append(finding.SecurityIssues,
					fmt.Sprintf("Token >90 days old (needs rotation)"))
			}
			if finding.TokenType == "legacy-secret" {
				finding.SecurityIssues = append(finding.SecurityIssues,
					"Using legacy token secret (migrate to projected)")
			}

			// RBAC sprawl
			if finding.RBACSprawl {
				finding.SecurityIssues = append(finding.SecurityIssues,
					fmt.Sprintf("%d role bindings (excessive, review needed)", finding.TotalRoleBindings))
			}

			// Calculate risk score and blast radius
			riskLevel, riskScore := calculateSARiskScore(&finding)
			finding.RiskLevel = riskLevel
			finding.RiskScore = riskScore
			finding.BlastRadius = calculateBlastRadius(&finding)
			finding.ImpactSummary = generateImpactSummary(&finding)

			riskCounts[finding.RiskLevel]++
			findings = append(findings, finding)

			// Format output row
			activePodStr := fmt.Sprintf("%d", finding.TotalPods)
			if finding.TotalPods == 0 {
				activePodStr = "0 (unused)"
			}

			nodeAccessStr := "No"
			if finding.CanProxyNodes {
				nodeAccessStr = "PROXY"
			} else if finding.NodeAccess {
				nodeAccessStr = "Yes"
			}

			crossNSStr := "No"
			if finding.ClusterWideAccess {
				crossNSStr = "Cluster"
			} else if finding.CrossNamespaceAccess {
				crossNSStr = fmt.Sprintf("%d NS", len(finding.AccessibleNamespaces))
			}

			outputRows = append(outputRows, []string{
				finding.RiskLevel,
				fmt.Sprintf("%d", finding.RiskScore),
				fmt.Sprintf("%d", finding.BlastRadius),
				ns.Name,
				sa.Name,
				activePodStr,
				finding.WorkloadSummary,
				fmt.Sprintf("%d", finding.PrivilegedPods),
				finding.TokenType,
				fmt.Sprintf("%d", finding.EscalationPathCount),
				nodeAccessStr,
				crossNSStr,
				finding.PermissionSummary,
				strings.Join(k8sinternal.Unique(roles), ", "),
				strings.Join(k8sinternal.Unique(clusterRoles), ", "),
				autoMount,
				fmt.Sprintf("%d", len(finding.SecurityIssues)),
			})

			// Generate loot content
			generateLootContent(&finding, &lootEnum, &lootTokens, &lootImpersonate, &lootExploit,
				&lootPermissions, &lootDefaultSA, &lootCrossNS, &lootNodeAccess,
				&lootEscalationPaths, &lootBlastRadius, &lootTokenLifecycle,
				&lootUnused, &lootWorkloadMapping, &lootRemediation)
		}
	}

	// Sort findings by blast radius (descending)
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].BlastRadius > findings[j].BlastRadius
	})

	// Add summaries
	if riskCounts["CRITICAL"] > 0 || riskCounts["HIGH"] > 0 {
		summary := fmt.Sprintf(`
# SUMMARY: Risk Distribution
# CRITICAL: %d service accounts
# HIGH: %d service accounts
# MEDIUM: %d service accounts
# LOW: %d service accounts
#
# Focus on CRITICAL and HIGH risk service accounts for maximum impact.
# Prioritize by blast radius for efficient exploitation.
`, riskCounts["CRITICAL"], riskCounts["HIGH"], riskCounts["MEDIUM"], riskCounts["LOW"])

		lootPermissions = append([]string{summary}, lootPermissions...)
		lootExploit = append([]string{summary}, lootExploit...)
		lootEscalationPaths = append([]string{summary}, lootEscalationPaths...)
		lootBlastRadius = append([]string{summary}, lootBlastRadius...)
	}

	table := internal.TableFile{
		Name:   "ServiceAccounts",
		Header: headers,
		Body:   outputRows,
	}

	lootFiles := []internal.LootFile{
		{
			Name:     "ServiceAccounts-Enum",
			Contents: strings.Join(lootEnum, "\n"),
		},
		{
			Name:     "ServiceAccounts-Token-Extraction",
			Contents: strings.Join(lootTokens, "\n"),
		},
		{
			Name:     "ServiceAccounts-Impersonation",
			Contents: strings.Join(lootImpersonate, "\n"),
		},
		{
			Name:     "ServiceAccounts-Privilege-Escalation",
			Contents: strings.Join(lootExploit, "\n"),
		},
		{
			Name:     "ServiceAccounts-RBAC-Analysis",
			Contents: strings.Join(lootPermissions, "\n"),
		},
		{
			Name:     "ServiceAccounts-Default-SA-Security",
			Contents: strings.Join(lootDefaultSA, "\n"),
		},
		{
			Name:     "ServiceAccounts-Cross-Namespace-Access",
			Contents: strings.Join(lootCrossNS, "\n"),
		},
		{
			Name:     "ServiceAccounts-Node-Access",
			Contents: strings.Join(lootNodeAccess, "\n"),
		},
		{
			Name:     "ServiceAccounts-Escalation-Paths",
			Contents: strings.Join(lootEscalationPaths, "\n"),
		},
		{
			Name:     "ServiceAccounts-Blast-Radius",
			Contents: strings.Join(lootBlastRadius, "\n"),
		},
		{
			Name:     "ServiceAccounts-Token-Lifecycle",
			Contents: strings.Join(lootTokenLifecycle, "\n"),
		},
		{
			Name:     "ServiceAccounts-Unused",
			Contents: strings.Join(lootUnused, "\n"),
		},
		{
			Name:     "ServiceAccounts-Workload-Mapping",
			Contents: strings.Join(lootWorkloadMapping, "\n"),
		},
		{
			Name:     "ServiceAccounts-Remediation",
			Contents: strings.Join(lootRemediation, "\n"),
		},
	}

	err = internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"ServiceAccounts",
		globals.ClusterName,
		"results",
		ServiceAccountOutput{
			Table: []internal.TableFile{table},
			Loot:  lootFiles,
		},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_SERVICEACCOUNTS_MODULE_NAME)
		return
	}

	if len(outputRows) > 0 {
		logger.InfoM(fmt.Sprintf("%d service accounts found across %d namespaces | Risk: CRITICAL=%d, HIGH=%d, MEDIUM=%d, LOW=%d",
			len(outputRows), len(namespaces.Items),
			riskCounts["CRITICAL"], riskCounts["HIGH"], riskCounts["MEDIUM"], riskCounts["LOW"]),
			globals.K8S_SERVICEACCOUNTS_MODULE_NAME)
	} else {
		logger.InfoM("No service accounts found, skipping output file creation", globals.K8S_SERVICEACCOUNTS_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_SERVICEACCOUNTS_MODULE_NAME), globals.K8S_SERVICEACCOUNTS_MODULE_NAME)
}

// ====================
// Helper Functions
// ====================

type PermissionAnalysis struct {
	DangerousPerms     []string
	Summary            string
	AllPerms           []string
	CanCreatePods      bool
	CanExecPods        bool
	CanReadSecrets     bool
	CanModifyRBAC      bool
	CanImpersonate     bool
	CanModifyAdmission bool
	CanBypassPolicies  bool
}

func analyzePermissionsEnhanced(namespace string, roles, clusterRoles []string,
	allRoles map[string]map[string]*rbacv1.Role, allClusterRoles map[string]*rbacv1.ClusterRole) PermissionAnalysis {

	var result PermissionAnalysis
	var allPerms []string

	// Dangerous permission patterns to detect
	dangerousPatterns := map[string]bool{
		"create pods":                            true,
		"create *":                               true,
		"* pods":                                 true,
		"* *":                                    true,
		"get secrets":                            true,
		"list secrets":                           true,
		"exec pods":                              true,
		"create deployments":                     true,
		"create daemonsets":                      true,
		"create roles":                           true,
		"create rolebindings":                    true,
		"create clusterroles":                    true,
		"create clusterrolebindings":             true,
		"escalate":                               true,
		"impersonate":                            true,
		"bind":                                   true,
		"proxy nodes":                            true,
		"get nodes":                              true,
		"create validatingwebhookconfigurations": true,
		"create mutatingwebhookconfigurations":   true,
		"create podsecuritypolicies":             true,
	}

	// Analyze cluster roles
	for _, crName := range clusterRoles {
		// Check for well-known dangerous roles
		if crName == "cluster-admin" {
			result.DangerousPerms = append(result.DangerousPerms, "cluster-admin (full cluster access)")
			allPerms = append(allPerms, "cluster-admin")
			// Cluster-admin has all capabilities
			result.CanCreatePods = true
			result.CanExecPods = true
			result.CanReadSecrets = true
			result.CanModifyRBAC = true
			result.CanImpersonate = true
			result.CanModifyAdmission = true
			continue
		}
		if strings.Contains(strings.ToLower(crName), "admin") {
			result.DangerousPerms = append(result.DangerousPerms, fmt.Sprintf("%s (admin access)", crName))
		}

		// Analyze actual permissions
		if cr, ok := allClusterRoles[crName]; ok {
			for _, rule := range cr.Rules {
				perms := formatRulePermissions(rule)
				allPerms = append(allPerms, perms...)

				// Check capabilities
				checkCapabilities(rule, &result)

				for _, perm := range perms {
					if dangerousPatterns[perm] {
						if !contains(result.DangerousPerms, perm) {
							result.DangerousPerms = append(result.DangerousPerms, perm)
						}
					}
				}
			}
		}
	}

	// Analyze namespace roles
	for _, roleName := range roles {
		if strings.Contains(strings.ToLower(roleName), "admin") || strings.Contains(strings.ToLower(roleName), "edit") {
			result.DangerousPerms = append(result.DangerousPerms, fmt.Sprintf("%s (elevated access)", roleName))
		}

		if nsRoles, ok := allRoles[namespace]; ok {
			if role, ok := nsRoles[roleName]; ok {
				for _, rule := range role.Rules {
					perms := formatRulePermissions(rule)
					allPerms = append(allPerms, perms...)

					// Check capabilities
					checkCapabilities(rule, &result)

					for _, perm := range perms {
						if dangerousPatterns[perm] {
							if !contains(result.DangerousPerms, perm) {
								result.DangerousPerms = append(result.DangerousPerms, perm)
							}
						}
					}
				}
			}
		}
	}

	// Create summary
	result.Summary = "<none>"
	if len(result.DangerousPerms) > 0 {
		// Limit to first 3 dangerous perms for summary
		if len(result.DangerousPerms) > 3 {
			result.Summary = strings.Join(result.DangerousPerms[:3], ", ") + fmt.Sprintf(" (+%d more)", len(result.DangerousPerms)-3)
		} else {
			result.Summary = strings.Join(result.DangerousPerms, ", ")
		}
	} else if len(allPerms) > 0 {
		// Show limited permissions if no dangerous ones
		if len(allPerms) > 3 {
			result.Summary = strings.Join(allPerms[:3], ", ") + "..."
		} else {
			result.Summary = strings.Join(allPerms, ", ")
		}
	}

	result.AllPerms = allPerms
	return result
}

func checkCapabilities(rule rbacv1.PolicyRule, result *PermissionAnalysis) {
	for _, verb := range rule.Verbs {
		for _, resource := range rule.Resources {
			perm := fmt.Sprintf("%s %s", verb, resource)

			if perm == "create pods" || perm == "* pods" || perm == "* *" || perm == "create *" {
				result.CanCreatePods = true
			}
			if perm == "create pods/exec" || strings.Contains(perm, "exec") {
				result.CanExecPods = true
			}
			if strings.Contains(perm, "secrets") && (verb == "get" || verb == "list" || verb == "*") {
				result.CanReadSecrets = true
			}
			if (strings.Contains(resource, "rolebindings") || strings.Contains(resource, "clusterrolebindings") ||
				strings.Contains(resource, "roles") || strings.Contains(resource, "clusterroles")) &&
				(verb == "create" || verb == "update" || verb == "patch" || verb == "*") {
				result.CanModifyRBAC = true
			}
			if verb == "impersonate" || strings.Contains(perm, "impersonate") {
				result.CanImpersonate = true
			}
			if strings.Contains(resource, "webhook") || strings.Contains(resource, "podsecuritypolicies") {
				if verb == "create" || verb == "update" || verb == "*" {
					result.CanModifyAdmission = true
					result.CanBypassPolicies = true
				}
			}
		}
	}
}

func formatRulePermissions(rule rbacv1.PolicyRule) []string {
	var perms []string

	for _, verb := range rule.Verbs {
		for _, resource := range rule.Resources {
			perm := fmt.Sprintf("%s %s", verb, resource)
			perms = append(perms, perm)
		}
	}

	return perms
}

func analyzeWorkloadTypes(ctx context.Context, clientset *k8sinternal.Clientset, namespace string, pods []corev1.Pod) WorkloadAnalysis {
	analysis := WorkloadAnalysis{
		Types:        make(map[string]int),
		Capabilities: make(map[string]int),
	}

	for _, pod := range pods {
		// Detect controller type from OwnerReferences
		if len(pod.OwnerReferences) > 0 {
			owner := pod.OwnerReferences[0]
			ownerKind := owner.Kind

			// Handle ReplicaSet -> Deployment mapping
			if ownerKind == "ReplicaSet" {
				// Try to find parent Deployment
				rs, err := clientset.AppsV1().ReplicaSets(namespace).Get(ctx, owner.Name, metav1.GetOptions{})
				if err == nil && len(rs.OwnerReferences) > 0 && rs.OwnerReferences[0].Kind == "Deployment" {
					ownerKind = "Deployment"
					analysis.DeploymentCount++
				}
			} else if ownerKind == "Deployment" {
				analysis.DeploymentCount++
			} else if ownerKind == "DaemonSet" {
				analysis.DaemonSetCount++
			} else if ownerKind == "StatefulSet" {
				analysis.StatefulSetCount++
			} else if ownerKind == "Job" {
				analysis.JobCount++
				// Check if Job is owned by CronJob
				job, err := clientset.BatchV1().Jobs(namespace).Get(ctx, owner.Name, metav1.GetOptions{})
				if err == nil && len(job.OwnerReferences) > 0 && job.OwnerReferences[0].Kind == "CronJob" {
					ownerKind = "CronJob"
					analysis.CronJobCount++
				}
			} else if ownerKind == "CronJob" {
				analysis.CronJobCount++
			}

			analysis.Types[ownerKind]++
		} else {
			// Standalone pod
			analysis.StandalonePods++
			analysis.Types["Pod"]++
		}

		// Analyze pod security context
		for _, container := range pod.Spec.Containers {
			if container.SecurityContext != nil {
				if container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
					analysis.PrivilegedPods++
					break
				}

				// Track capabilities
				if container.SecurityContext.Capabilities != nil {
					for _, cap := range container.SecurityContext.Capabilities.Add {
						analysis.Capabilities[string(cap)]++
					}
				}
			}
		}

		if pod.Spec.HostNetwork {
			analysis.HostNetworkPods++
		}
		if pod.Spec.HostPID {
			analysis.HostPIDPods++
		}
		if pod.Spec.HostIPC {
			analysis.HostIPCPods++
		}

		// Check for hostPath mounts
		for _, vol := range pod.Spec.Volumes {
			if vol.HostPath != nil {
				analysis.HostPathMounts++
				break
			}
		}
	}

	return analysis
}

func generateWorkloadSummary(analysis WorkloadAnalysis) string {
	if len(analysis.Types) == 0 {
		return "none"
	}

	var parts []string
	if analysis.DeploymentCount > 0 {
		parts = append(parts, fmt.Sprintf("%d Deploy", analysis.DeploymentCount))
	}
	if analysis.DaemonSetCount > 0 {
		parts = append(parts, fmt.Sprintf("%d DS", analysis.DaemonSetCount))
	}
	if analysis.StatefulSetCount > 0 {
		parts = append(parts, fmt.Sprintf("%d STS", analysis.StatefulSetCount))
	}
	if analysis.CronJobCount > 0 {
		parts = append(parts, fmt.Sprintf("%d Cron", analysis.CronJobCount))
	}
	if analysis.JobCount > 0 {
		parts = append(parts, fmt.Sprintf("%d Job", analysis.JobCount))
	}
	if analysis.StandalonePods > 0 {
		parts = append(parts, fmt.Sprintf("%d Pod", analysis.StandalonePods))
	}

	if len(parts) == 0 {
		return "unknown"
	}
	return strings.Join(parts, ", ")
}

type CrossNamespaceInfo struct {
	ClusterWide          bool
	CrossNamespace       bool
	AccessibleNamespaces []string
	Scope                string
}

func analyzeCrossNamespaceAccess(roles, clusterRoles []string,
	allRoles map[string]map[string]*rbacv1.Role,
	allClusterRoles map[string]*rbacv1.ClusterRole,
	currentNamespace string) CrossNamespaceInfo {

	info := CrossNamespaceInfo{
		AccessibleNamespaces: []string{currentNamespace},
	}

	// ClusterRoles can grant cluster-wide access
	for _, crName := range clusterRoles {
		if cr, ok := allClusterRoles[crName]; ok {
			for _, rule := range cr.Rules {
				// Check for cluster-scoped resources or wildcards
				for _, resource := range rule.Resources {
					if resource == "*" || resource == "namespaces" || resource == "nodes" ||
						resource == "clusterroles" || resource == "clusterrolebindings" ||
						resource == "persistentvolumes" || resource == "storageclasses" {
						info.ClusterWide = true
						info.Scope = "cluster-wide"
						return info
					}
				}

				// Wildcard verbs or resources indicate cluster-wide access
				for _, verb := range rule.Verbs {
					if verb == "*" {
						info.ClusterWide = true
						info.Scope = "cluster-wide"
						return info
					}
				}
			}
		}
	}

	// If has ClusterRole but not cluster-wide, it's cross-namespace
	if len(clusterRoles) > 0 && !info.ClusterWide {
		info.CrossNamespace = true
		info.Scope = "cross-namespace"
		// In reality, we'd need to parse all RoleBindings in all namespaces
		// to know exactly which namespaces are accessible
		// For now, we'll indicate it has potential cross-namespace access
		return info
	}

	// Only namespace-scoped Roles
	info.Scope = "namespace-only"
	return info
}

func analyzeNodePermissions(roles, clusterRoles []string,
	allRoles map[string]map[string]*rbacv1.Role,
	allClusterRoles map[string]*rbacv1.ClusterRole,
	namespace string) NodeAccessInfo {

	info := NodeAccessInfo{}

	// Check ClusterRoles for node permissions
	for _, crName := range clusterRoles {
		if cr, ok := allClusterRoles[crName]; ok {
			for _, rule := range cr.Rules {
				for _, resource := range rule.Resources {
					if resource == "nodes" || resource == "*" || resource == "nodes/proxy" {
						for _, verb := range rule.Verbs {
							perm := fmt.Sprintf("%s %s", verb, resource)
							info.Permissions = append(info.Permissions, perm)

							if verb == "proxy" || resource == "nodes/proxy" {
								info.CanProxy = true
								info.CanAccess = true
							}
							if verb == "get" || verb == "list" || verb == "*" {
								info.CanAccess = true
							}
						}
					}
				}
			}
		}
	}

	return info
}

func analyzeDefaultSA(finding *SAFinding) []string {
	var issues []string

	// Default SA should have minimal/no permissions
	if len(finding.Roles) > 0 || len(finding.ClusterRoles) > 0 {
		issues = append(issues, "Default SA has role bindings (should have none)")
	}

	// Default SA should NOT auto-mount tokens
	if finding.AutoMountToken != "false" {
		issues = append(issues, "Default SA auto-mounts tokens (should be false)")
	}

	// Pods should use dedicated SAs, not default
	if finding.TotalPods > 0 {
		issues = append(issues, fmt.Sprintf("%d pods using default SA (should use dedicated SAs)", finding.TotalPods))
	}

	// Default SA with dangerous permissions is CRITICAL
	if len(finding.DangerousPermissions) > 0 {
		issues = append(issues, fmt.Sprintf("Default SA has dangerous permissions: %s",
			strings.Join(finding.DangerousPermissions, ", ")))
	}

	return issues
}

func detectEscalationPaths(finding *SAFinding, permAnalysis PermissionAnalysis) []string {
	var paths []string

	// Path 1: Pod creation → container escape → node compromise
	if finding.CanCreatePods {
		paths = append(paths, "pod-creation-escape: Create privileged pods to escape to node")
	}

	// Path 2: Secret read → credential theft → lateral movement
	if finding.CanReadSecrets {
		paths = append(paths, "secret-theft: Read secrets including cloud credentials and SA tokens")
	}

	// Path 3: Node proxy → cluster takeover
	if finding.CanProxyNodes {
		paths = append(paths, "node-proxy-takeover: Proxy to nodes and access kubelet API")
	}

	// Path 4: RBAC modification → privilege escalation
	if finding.CanModifyRBAC {
		paths = append(paths, "rbac-escalation: Grant self cluster-admin via role bindings")
	}

	// Path 5: Impersonation → identity theft
	if finding.CanImpersonate {
		paths = append(paths, "impersonation: Impersonate users/groups/serviceaccounts")
	}

	// Path 6: Admission controller bypass
	if finding.CanModifyAdmission {
		paths = append(paths, "admission-bypass: Modify admission controllers to bypass security policies")
	}

	// Path 7: Pod exec → lateral movement
	if finding.CanExecPods {
		paths = append(paths, "pod-exec-pivot: Exec into pods to access other workloads")
	}

	// Path 8: Existing privileged pods → immediate escape
	if finding.PrivilegedPods > 0 && finding.ActivelyUsed {
		paths = append(paths, fmt.Sprintf("privileged-pod-escape: %d existing privileged pods provide immediate node access", finding.PrivilegedPods))
	}

	// Path 9: DaemonSet → all nodes
	if finding.DaemonSetCount > 0 {
		paths = append(paths, fmt.Sprintf("daemonset-spread: %d DaemonSets run on ALL cluster nodes", finding.DaemonSetCount))
	}

	// Path 10: External exposure → remote exploitation
	if finding.ExternallyExposed {
		paths = append(paths, fmt.Sprintf("external-exposure: SA tokens accessible via %s", finding.ExposureMethod))
	}

	return paths
}

func calculateSARiskScore(finding *SAFinding) (string, int) {
	score := 0

	// Cluster-admin = instant CRITICAL
	for _, cr := range finding.ClusterRoles {
		if cr == "cluster-admin" {
			return "CRITICAL", 100
		}
	}

	// Escalation path scoring
	if finding.CanCreatePods {
		score += 80 // Can escape to node
		if finding.ActivelyUsed {
			score += 10 // Active exploitation ready
		}
	}

	if finding.CanReadSecrets {
		score += 70 // Credential theft
	}

	if finding.CanProxyNodes {
		score += 90 // Direct node access
	}

	if finding.CanModifyRBAC {
		score += 85 // Self-escalation to cluster-admin
	}

	if finding.CanExecPods {
		score += 60 // Lateral movement
	}

	if finding.CanImpersonate {
		score += 75 // Identity theft
	}

	if finding.CanModifyAdmission {
		score += 70 // Policy bypass
	}

	// Scope multipliers
	if finding.ClusterWideAccess {
		score += 40
	} else if finding.CrossNamespaceAccess {
		score += 20
	}

	// Active usage increases risk
	if finding.ActivelyUsed {
		score += 15

		// Privileged pods = immediate escape
		if finding.PrivilegedPods > 0 {
			score += 30
		}

		// DaemonSets = all nodes compromised
		if finding.DaemonSetCount > 0 {
			score += 25
		}

		// HostNetwork/HostPID = node access
		if finding.HostNetworkPods > 0 || finding.HostPIDPods > 0 {
			score += 20
		}
	}

	// Default SA with permissions = CRITICAL misconfiguration
	if finding.IsDefaultSA && (len(finding.Roles) > 0 || len(finding.ClusterRoles) > 0) {
		score += 50
	}

	// External exposure
	if finding.ExternallyExposed {
		score += 40
	}

	// Token lifecycle
	if finding.TokenRotationNeeded {
		score += 10
	}

	// RBAC sprawl (indicates over-permissioning)
	if finding.RBACSprawl {
		score += 15
	}

	// Node access
	if finding.CanAccessNodes {
		score += 20
	}

	// Determine risk level
	if score >= 85 {
		return "CRITICAL", min(score, 100)
	} else if score >= 60 {
		return "HIGH", score
	} else if score >= 30 {
		return "MEDIUM", score
	}
	return "LOW", score
}

func calculateBlastRadius(finding *SAFinding) int {
	// Base: number of pods × risk score
	radius := finding.TotalPods * finding.RiskScore

	// Multipliers for special workload types
	if finding.DaemonSetCount > 0 {
		// DaemonSets run on ALL nodes - massive blast radius
		radius = radius * 3
	}

	if finding.PrivilegedPods > 0 {
		// Privileged pods = direct node access
		radius = radius * 2
	}

	if finding.CrossNamespaceAccess || finding.ClusterWideAccess {
		// Cross-namespace/cluster-wide = larger attack surface
		radius = int(float64(radius) * 1.5)
	}

	if finding.ExternallyExposed {
		// External exposure = remote exploitation
		radius = int(float64(radius) * 1.3)
	}

	return radius
}

func generateImpactSummary(finding *SAFinding) string {
	if finding.BlastRadius > 500 {
		return fmt.Sprintf("CRITICAL: %d blast radius (pods×risk×multipliers)",
			finding.BlastRadius)
	}

	if finding.DaemonSetCount > 0 {
		return fmt.Sprintf("Runs on ALL NODES via %d DaemonSets", finding.DaemonSetCount)
	}

	if finding.PrivilegedPods > 0 {
		return fmt.Sprintf("%d privileged pods can escape to nodes", finding.PrivilegedPods)
	}

	if finding.ClusterWideAccess {
		return "Cluster-wide access across all namespaces"
	}

	if finding.CrossNamespaceAccess {
		return fmt.Sprintf("Can access %d namespaces", len(finding.AccessibleNamespaces))
	}

	if finding.TotalPods > 0 {
		return fmt.Sprintf("%d pods using this SA", finding.TotalPods)
	}

	return "Unused (0 active pods)"
}

func detectExternalExposure(pods []corev1.Pod, services []corev1.Service) ExposureInfo {
	info := ExposureInfo{}

	for _, pod := range pods {
		for _, svc := range services {
			// Check if service selector matches pod labels
			if labelsMatch(svc.Spec.Selector, pod.Labels) {
				if svc.Spec.Type == corev1.ServiceTypeLoadBalancer || svc.Spec.Type == corev1.ServiceTypeNodePort {
					info.IsExposed = true
					info.Method = string(svc.Spec.Type)
					info.Pods = append(info.Pods, pod.Name)
				}
			}
		}
	}

	return info
}

func labelsMatch(selector, labels map[string]string) bool {
	if len(selector) == 0 {
		return false
	}
	for key, value := range selector {
		if labels[key] != value {
			return false
		}
	}
	return true
}

func generateLootContent(finding *SAFinding,
	lootEnum, lootTokens, lootImpersonate, lootExploit,
	lootPermissions, lootDefaultSA, lootCrossNS, lootNodeAccess,
	lootEscalationPaths, lootBlastRadius, lootTokenLifecycle,
	lootUnused, lootWorkloadMapping, lootRemediation *[]string) {

	ns := finding.Namespace
	sa := finding.Name

	// Enumeration
	*lootEnum = append(*lootEnum, fmt.Sprintf("\n# [%s] ServiceAccount: %s/%s", finding.RiskLevel, ns, sa))
	*lootEnum = append(*lootEnum, fmt.Sprintf("# Risk Score: %d | Blast Radius: %d | %s", finding.RiskScore, finding.BlastRadius, finding.ImpactSummary))
	*lootEnum = append(*lootEnum, fmt.Sprintf("kubectl get serviceaccount %s -n %s -o yaml", sa, ns))
	*lootEnum = append(*lootEnum, fmt.Sprintf("kubectl describe serviceaccount %s -n %s", sa, ns))

	// Show RBAC permissions
	if len(finding.Roles) > 0 {
		*lootEnum = append(*lootEnum, fmt.Sprintf("# Roles: %s", strings.Join(finding.Roles, ", ")))
		for _, role := range finding.Roles {
			*lootEnum = append(*lootEnum, fmt.Sprintf("kubectl get role %s -n %s -o yaml", role, ns))
		}
	}
	if len(finding.ClusterRoles) > 0 {
		*lootEnum = append(*lootEnum, fmt.Sprintf("# ClusterRoles: %s", strings.Join(finding.ClusterRoles, ", ")))
		for _, cr := range finding.ClusterRoles {
			*lootEnum = append(*lootEnum, fmt.Sprintf("kubectl get clusterrole %s -o yaml", cr))
		}
	}
	*lootEnum = append(*lootEnum, "")

	// Token extraction
	if finding.HasToken {
		*lootTokens = append(*lootTokens, fmt.Sprintf("\n# [%s] ServiceAccount: %s/%s", finding.RiskLevel, ns, sa))
		*lootTokens = append(*lootTokens, fmt.Sprintf("# Token Type: %s | Age: %d days", finding.TokenType, finding.TokenAge))

		if len(finding.Secrets) > 0 {
			for _, secretName := range finding.Secrets {
				*lootTokens = append(*lootTokens, fmt.Sprintf("# Secret: %s", secretName))
				*lootTokens = append(*lootTokens, fmt.Sprintf("kubectl get secret %s -n %s -o jsonpath='{.data.token}' | base64 -d", secretName, ns))
			}
		} else {
			*lootTokens = append(*lootTokens, fmt.Sprintf("# Create projected token:"))
			*lootTokens = append(*lootTokens, fmt.Sprintf("kubectl create token %s -n %s --duration=24h", sa, ns))
		}
		*lootTokens = append(*lootTokens, "")
	}

	// Impersonation
	*lootImpersonate = append(*lootImpersonate, fmt.Sprintf("\n# [%s] ServiceAccount: %s/%s", finding.RiskLevel, ns, sa))
	if len(finding.DangerousPermissions) > 0 {
		*lootImpersonate = append(*lootImpersonate, fmt.Sprintf("# Dangerous Permissions: %s", strings.Join(finding.DangerousPermissions[:min(3, len(finding.DangerousPermissions))], ", ")))
	}
	*lootImpersonate = append(*lootImpersonate, fmt.Sprintf("# Extract token:"))
	if len(finding.Secrets) > 0 {
		*lootImpersonate = append(*lootImpersonate, fmt.Sprintf("export SA_TOKEN=$(kubectl get secret %s -n %s -o jsonpath='{.data.token}' | base64 -d)", finding.Secrets[0], ns))
	} else {
		*lootImpersonate = append(*lootImpersonate, fmt.Sprintf("export SA_TOKEN=$(kubectl create token %s -n %s --duration=24h)", sa, ns))
	}
	*lootImpersonate = append(*lootImpersonate, fmt.Sprintf("# Use token:"))
	*lootImpersonate = append(*lootImpersonate, fmt.Sprintf("kubectl --token=$SA_TOKEN auth can-i --list"))
	*lootImpersonate = append(*lootImpersonate, "")

	// Privilege escalation for CRITICAL/HIGH
	if finding.RiskLevel == "CRITICAL" || finding.RiskLevel == "HIGH" {
		*lootExploit = append(*lootExploit, fmt.Sprintf("\n### [%s] ServiceAccount: %s/%s", finding.RiskLevel, ns, sa))
		*lootExploit = append(*lootExploit, fmt.Sprintf("# Risk Score: %d | Blast Radius: %d", finding.RiskScore, finding.BlastRadius))
		*lootExploit = append(*lootExploit, fmt.Sprintf("# Permissions: %s", finding.PermissionSummary))

		if len(finding.PodsUsingSA) > 0 {
			*lootExploit = append(*lootExploit, fmt.Sprintf("# OPTION 1: Exploit existing %d pods", len(finding.PodsUsingSA)))
			for i, pod := range finding.PodsUsingSA {
				if i < 5 { // Limit to first 5 pods
					*lootExploit = append(*lootExploit, fmt.Sprintf("kubectl exec -it %s -n %s -- sh", pod, ns))
				}
			}
			*lootExploit = append(*lootExploit, "# Inside pod: SA_TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)")
		}

		*lootExploit = append(*lootExploit, fmt.Sprintf("# OPTION 2: Create new pod:"))
		*lootExploit = append(*lootExploit, fmt.Sprintf("kubectl run exploit-%s --image=alpine -n %s --serviceaccount=%s -- sleep 3600", sa, ns, sa))
		*lootExploit = append(*lootExploit, "")

		// Permissions analysis
		*lootPermissions = append(*lootPermissions, fmt.Sprintf("\n### [%s] %s/%s", finding.RiskLevel, ns, sa))
		*lootPermissions = append(*lootPermissions, fmt.Sprintf("# Risk Score: %d | Blast Radius: %d", finding.RiskScore, finding.BlastRadius))
		*lootPermissions = append(*lootPermissions, fmt.Sprintf("# Permissions: %s", finding.PermissionSummary))
		if len(finding.DangerousPermissions) > 0 {
			*lootPermissions = append(*lootPermissions, "# Dangerous Permissions:")
			for _, perm := range finding.DangerousPermissions {
				*lootPermissions = append(*lootPermissions, fmt.Sprintf("#   - %s", perm))
			}
		}
		*lootPermissions = append(*lootPermissions, "")

		// Escalation paths
		if len(finding.EscalationPaths) > 0 {
			*lootEscalationPaths = append(*lootEscalationPaths, fmt.Sprintf("\n### [%s] %s/%s - %d Escalation Paths", finding.RiskLevel, ns, sa, len(finding.EscalationPaths)))
			*lootEscalationPaths = append(*lootEscalationPaths, fmt.Sprintf("# Risk Score: %d | Blast Radius: %d", finding.RiskScore, finding.BlastRadius))
			for _, path := range finding.EscalationPaths {
				*lootEscalationPaths = append(*lootEscalationPaths, fmt.Sprintf("# - %s", path))
			}
			*lootEscalationPaths = append(*lootEscalationPaths, "")
		}

		// Blast radius
		if finding.BlastRadius > 100 {
			*lootBlastRadius = append(*lootBlastRadius, fmt.Sprintf("\n### Blast Radius: %d - %s/%s", finding.BlastRadius, ns, sa))
			*lootBlastRadius = append(*lootBlastRadius, fmt.Sprintf("# Risk Score: %d × Pods: %d × Multipliers = %d", finding.RiskScore, finding.TotalPods, finding.BlastRadius))
			*lootBlastRadius = append(*lootBlastRadius, fmt.Sprintf("# Workloads: %s", finding.WorkloadSummary))
			*lootBlastRadius = append(*lootBlastRadius, fmt.Sprintf("# Impact: %s", finding.ImpactSummary))
			*lootBlastRadius = append(*lootBlastRadius, "")
		}
	}

	// Default SA issues
	if finding.IsDefaultSA && len(finding.DefaultSAIssues) > 0 {
		*lootDefaultSA = append(*lootDefaultSA, fmt.Sprintf("\n### CRITICAL: default SA in %s has security issues", ns))
		for _, issue := range finding.DefaultSAIssues {
			*lootDefaultSA = append(*lootDefaultSA, fmt.Sprintf("# - %s", issue))
		}
		*lootDefaultSA = append(*lootDefaultSA, fmt.Sprintf("# Remediation:"))
		*lootDefaultSA = append(*lootDefaultSA, fmt.Sprintf("kubectl patch serviceaccount default -n %s -p '{\"automountServiceAccountToken\":false}'", ns))
		*lootDefaultSA = append(*lootDefaultSA, "")
	}

	// Cross-namespace access
	if finding.CrossNamespaceAccess || finding.ClusterWideAccess {
		*lootCrossNS = append(*lootCrossNS, fmt.Sprintf("\n### [%s] %s/%s - %s Access", finding.RiskLevel, ns, sa, finding.PermissionScope))
		*lootCrossNS = append(*lootCrossNS, fmt.Sprintf("# Risk Score: %d | Blast Radius: %d", finding.RiskScore, finding.BlastRadius))
		if finding.ClusterWideAccess {
			*lootCrossNS = append(*lootCrossNS, "# Can access ALL namespaces and cluster resources")
		} else {
			*lootCrossNS = append(*lootCrossNS, fmt.Sprintf("# Can access %d namespaces", len(finding.AccessibleNamespaces)))
		}
		*lootCrossNS = append(*lootCrossNS, "")
	}

	// Node access
	if finding.NodeAccess {
		*lootNodeAccess = append(*lootNodeAccess, fmt.Sprintf("\n### [%s] %s/%s - Node-Level Access", finding.RiskLevel, ns, sa))
		*lootNodeAccess = append(*lootNodeAccess, fmt.Sprintf("# Risk Score: %d | Blast Radius: %d", finding.RiskScore, finding.BlastRadius))
		if finding.CanProxyNodes {
			*lootNodeAccess = append(*lootNodeAccess, "# CRITICAL: Can proxy to nodes (full kubelet access)")
		}
		*lootNodeAccess = append(*lootNodeAccess, fmt.Sprintf("# Node Permissions: %s", strings.Join(finding.NodePermissions, ", ")))
		*lootNodeAccess = append(*lootNodeAccess, "")
	}

	// Token lifecycle
	if finding.TokenRotationNeeded || finding.TokenType == "legacy-secret" {
		*lootTokenLifecycle = append(*lootTokenLifecycle, fmt.Sprintf("\n### %s/%s - Token Lifecycle Issue", ns, sa))
		*lootTokenLifecycle = append(*lootTokenLifecycle, fmt.Sprintf("# Token Type: %s | Age: %d days", finding.TokenType, finding.TokenAge))
		if finding.TokenRotationNeeded {
			*lootTokenLifecycle = append(*lootTokenLifecycle, "# URGENT: Token >90 days old, needs rotation")
		}
		if finding.TokenType == "legacy-secret" {
			*lootTokenLifecycle = append(*lootTokenLifecycle, "# Migrate to projected tokens (K8s 1.21+)")
		}
		*lootTokenLifecycle = append(*lootTokenLifecycle, "")
	}

	// Unused SAs
	if !finding.ActivelyUsed {
		*lootUnused = append(*lootUnused, fmt.Sprintf("\n### %s/%s - Unused (0 pods)", ns, sa))
		*lootUnused = append(*lootUnused, fmt.Sprintf("# Age: %d days | Has Permissions: %v", finding.AgeDays, len(finding.Roles)+len(finding.ClusterRoles) > 0))
		if len(finding.Roles) > 0 || len(finding.ClusterRoles) > 0 {
			*lootUnused = append(*lootUnused, "# RISK: Unused but has permissions (cleanup candidate)")
		}
		*lootUnused = append(*lootUnused, fmt.Sprintf("# Consider deletion: kubectl delete serviceaccount %s -n %s", sa, ns))
		*lootUnused = append(*lootUnused, "")
	}

	// Workload mapping
	if finding.ActivelyUsed {
		*lootWorkloadMapping = append(*lootWorkloadMapping, fmt.Sprintf("\n### %s/%s - %d Pods", ns, sa, finding.TotalPods))
		*lootWorkloadMapping = append(*lootWorkloadMapping, fmt.Sprintf("# Workloads: %s", finding.WorkloadSummary))
		if finding.PrivilegedPods > 0 {
			*lootWorkloadMapping = append(*lootWorkloadMapping, fmt.Sprintf("# CRITICAL: %d privileged pods", finding.PrivilegedPods))
		}
		*lootWorkloadMapping = append(*lootWorkloadMapping, "")
	}

	// Remediation
	if len(finding.SecurityIssues) > 0 {
		*lootRemediation = append(*lootRemediation, fmt.Sprintf("\n### %s/%s - %d Security Issues", ns, sa, len(finding.SecurityIssues)))
		for _, issue := range finding.SecurityIssues {
			*lootRemediation = append(*lootRemediation, fmt.Sprintf("# - %s", issue))
		}
		*lootRemediation = append(*lootRemediation, "# Remediation steps:")
		if finding.IsDefaultSA {
			*lootRemediation = append(*lootRemediation, fmt.Sprintf("kubectl patch serviceaccount default -n %s -p '{\"automountServiceAccountToken\":false}'", ns))
		}
		if finding.TokenRotationNeeded {
			*lootRemediation = append(*lootRemediation, fmt.Sprintf("# Rotate token by deleting secrets: kubectl delete secret <token-secret> -n %s", ns))
		}
		*lootRemediation = append(*lootRemediation, "")
	}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
