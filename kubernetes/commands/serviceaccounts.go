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
	"github.com/BishopFox/cloudfox/kubernetes/shared"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
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

	// SA Hunter - Node and Pod targeting info
	NodesUsingSA     []string               // Unique nodes where this SA is active
	PodNodeMap       map[string]string      // pod name -> node name
	NodePodCount     map[string]int         // node name -> number of pods using this SA
	TargetSummary    string                 // Summary for quick targeting

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

	// Effective Admin Analysis
	EffectiveAdmin      string // "Yes - Cluster", "Yes - Namespace", "No"
	IsClusterAdmin      bool
	IsNamespaceAdmin    bool

	// Risk Analysis
	RiskLevel      string
	RiskScore      int
	BlastRadius    int
	ImpactSummary  string
	SecurityIssues []string

	// Cloud Workload Identity
	HasCloudIdentity       bool
	CloudIdentitySummary   string
	AWSRoleARN             string   // AWS EKS Pod Identity role ARN
	AWSPodIdentityAssoc    string   // AWS PodIdentityAssociation name
	GCPServiceAccountEmail string   // GCP Workload Identity GSA email
	AzureClientID          string   // Azure Workload Identity client ID
	AzureTenantID          string   // Azure Workload Identity tenant ID
	CloudProviders         []string // Which cloud providers have identity mapped
}

type ServiceAccountEscalationPath struct {
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
	ctx, cancel := shared.ContextWithTimeout()
	defer cancel()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating service accounts for %s", globals.ClusterName), globals.K8S_SERVICEACCOUNTS_MODULE_NAME)

	clientset := config.GetClientOrExit()

	// Create dynamic client for cloud workload identity CRD detection
	var dynamicClient dynamic.Interface
	restConfig, err := config.GetRESTConfig()
	if err == nil && restConfig != nil {
		dynamicClient, err = dynamic.NewForConfig(restConfig)
		if err != nil {
			// Dynamic client creation failed - cloud identity detection will be limited to annotations
			dynamicClient = nil
		}
	}

	namespaces := shared.GetTargetNamespaces(ctx, clientset, &logger, globals.K8S_SERVICEACCOUNTS_MODULE_NAME)

	headers := []string{
		"Blast Radius",
		"Effective Admin",
		"Namespace",
		"Service Account",
		"Target Pods",
		"Target Nodes",
		"Workload Types",
		"Priv Pods",
		"Token Type",
		"Escalation Paths",
		"Node Access",
		"Cross-NS",
		"Cloud Identity",
		"Permissions",
		"Roles",
		"ClusterRoles",
		"Auto-Mount",
		"Issues",
	}

	var outputRows [][]string
	var findings []SAFinding

	// Risk level counters
	riskCounts := shared.NewRiskCounts()

	loot := shared.NewLootBuilder()

	loot.Section("ServiceAccounts-Enum").SetHeader(`#####################################
##### ServiceAccount Enumeration
#####################################
#
# Complete service account inventory with security analysis
#`)

	loot.Section("ServiceAccounts-Token-Extraction").SetHeader(`#####################################
##### ServiceAccount Token Extraction
#####################################
#
# Extract and decode service account tokens
# IMPORTANT: Tokens provide authentication to the cluster
#`)

	loot.Section("ServiceAccounts-Impersonation").SetHeader(`#####################################
##### ServiceAccount Impersonation
#####################################
#
# Use service account tokens for authentication
# MANUAL EXECUTION REQUIRED
#`)

	loot.Section("ServiceAccounts-Privilege-Escalation").SetHeader(`#####################################
##### ServiceAccount Privilege Escalation
#####################################
#
# MANUAL EXECUTION REQUIRED
# Create pods to use privileged service accounts
# or abuse existing pods with high-privilege SAs
#`)

	loot.Section("ServiceAccounts-RBAC-Analysis").SetHeader(`#####################################
##### RBAC Permission Analysis
#####################################
#
# Detailed permission analysis for high-risk service accounts
# Focus on dangerous permissions that enable privilege escalation
#`)

	loot.Section("ServiceAccounts-Default-SA-Security").SetHeader(`#####################################
##### Default ServiceAccount Security Issues
#####################################
#
# Default SAs should have minimal/no permissions
# Pods should use dedicated SAs, not default
#`)

	loot.Section("ServiceAccounts-Cross-Namespace-Access").SetHeader(`#####################################
##### Cross-Namespace Access
#####################################
#
# ServiceAccounts with cross-namespace or cluster-wide access
# High-risk: can pivot between namespaces
#`)

	loot.Section("ServiceAccounts-Node-Access").SetHeader(`#####################################
##### Node-Level Access
#####################################
#
# ServiceAccounts with node-level permissions
# CRITICAL: Can escape containers and access nodes
#`)

	loot.Section("ServiceAccounts-Escalation-Paths").SetHeader(`#####################################
##### Privilege Escalation Paths
#####################################
#
# Specific attack vectors for each high-risk ServiceAccount
# Ordered by severity and exploitability
#`)

	loot.Section("ServiceAccounts-Blast-Radius").SetHeader(`#####################################
##### Blast Radius Analysis
#####################################
#
# Impact analysis: pods × risk score × workload multipliers
# Focus on highest blast radius for maximum cluster impact
#`)

	loot.Section("ServiceAccounts-Token-Lifecycle").SetHeader(`#####################################
##### Token Lifecycle and Rotation
#####################################
#
# Token age, type, and rotation recommendations
# Legacy tokens should be migrated to projected tokens
#`)

	loot.Section("ServiceAccounts-Unused").SetHeader(`#####################################
##### Unused ServiceAccounts
#####################################
#
# ServiceAccounts with 0 active pods
# Cleanup candidates to reduce attack surface
#`)

	loot.Section("ServiceAccounts-Workload-Mapping").SetHeader(`#####################################
##### Workload to ServiceAccount Mapping
#####################################
#
# Which workloads use which ServiceAccounts
# Useful for impact analysis and least privilege design
#`)

	loot.Section("ServiceAccounts-Remediation").SetHeader(`#####################################
##### Security Hardening Recommendations
#####################################
#
# Remediation steps for identified security issues
# Implement these to improve cluster security posture
#`)

	loot.Section("ServiceAccounts-SA-Hunter").SetHeader(`#####################################
##### SA Hunter - Targeting Information
#####################################
#
# Quick reference for targeting specific service accounts
# Shows which pods and nodes have active SA tokens
# Use this to plan your attack vector and pivot targets
#
# ATTACK STRATEGY:
# 1. Identify high-value SAs (CRITICAL/HIGH risk)
# 2. Find pods using those SAs
# 3. Target the specific nodes those pods run on
# 4. Exec into pods or exploit node to get SA token
#`)

	loot.Section("ServiceAccounts-Cloud-Identity").SetHeader(`#####################################
##### Cloud Workload Identity Mappings
#####################################
#
# Service accounts with cloud provider identity mappings
# These SAs can access cloud resources (AWS, GCP, Azure)
# CRITICAL: Review cloud IAM roles for least privilege
#`)

	if globals.KubeContext != "" {
		loot.Section("ServiceAccounts-Enum").Addf("kubectl config use-context %s\n", globals.KubeContext)
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
		shared.LogListError(&logger, "cluster roles", "", err, globals.K8S_SERVICEACCOUNTS_MODULE_NAME, false)
	} else {
		for _, cr := range clusterRoles.Items {
			allClusterRoles[cr.Name] = &cr
		}
	}

	// Get all ClusterRoleBindings
	clusterRoleBindings, err := clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		shared.LogListError(&logger, "cluster role bindings", "", err, globals.K8S_SERVICEACCOUNTS_MODULE_NAME, false)
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
	for _, ns := range namespaces {
		// Get all roles in namespace
		roles, err := clientset.RbacV1().Roles(ns).List(ctx, metav1.ListOptions{})
		if err == nil {
			allRoles[ns] = make(map[string]*rbacv1.Role)
			for _, role := range roles.Items {
				allRoles[ns][role.Name] = &role
			}
		}

		// Get all pods in namespace to map SA usage
		pods, err := clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			shared.LogListError(&logger, "pods", ns, err, globals.K8S_SERVICEACCOUNTS_MODULE_NAME, false)
		} else {
			for _, pod := range pods.Items {
				// Only count running/pending pods for "active usage"
				if pod.Status.Phase == corev1.PodRunning || pod.Status.Phase == corev1.PodPending {
					saName := pod.Spec.ServiceAccountName
					if saName == "" {
						saName = "default"
					}
					if saPods[ns] == nil {
						saPods[ns] = make(map[string][]corev1.Pod)
					}
					saPods[ns][saName] = append(saPods[ns][saName], pod)
				}
			}
		}

		// Get RoleBindings in namespace
		roleBindings, err := clientset.RbacV1().RoleBindings(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			shared.LogListError(&logger, "role bindings", ns, err, globals.K8S_SERVICEACCOUNTS_MODULE_NAME, false)
		} else {
			for _, rb := range roleBindings.Items {
				for _, subj := range rb.Subjects {
					if subj.Kind == "ServiceAccount" {
						sa := subj.Name
						if saRoleBindings[ns] == nil {
							saRoleBindings[ns] = make(map[string][]string)
						}
						saRoleBindings[ns][sa] = append(saRoleBindings[ns][sa], rb.RoleRef.Name)
					}
				}
			}
		}

		// Get all secrets for token lifecycle analysis
		secrets, err := clientset.CoreV1().Secrets(ns).List(ctx, metav1.ListOptions{})
		if err == nil {
			for _, secret := range secrets.Items {
				// Only track SA token secrets
				if secret.Type == corev1.SecretTypeServiceAccountToken {
					if saName, ok := secret.Annotations["kubernetes.io/service-account.name"]; ok {
						if saSecrets[ns] == nil {
							saSecrets[ns] = make(map[string][]corev1.Secret)
						}
						saSecrets[ns][saName] = append(saSecrets[ns][saName], secret)
					}
				}
			}
		}

		// Get services for external exposure detection
		services, err := clientset.CoreV1().Services(ns).List(ctx, metav1.ListOptions{})
		if err == nil {
			allServices[ns] = services.Items
		}

		// Get ServiceAccounts
		serviceAccounts, err := clientset.CoreV1().ServiceAccounts(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			shared.LogListError(&logger, "service accounts", ns, err, globals.K8S_SERVICEACCOUNTS_MODULE_NAME, false)
			continue
		}

		for _, sa := range serviceAccounts.Items {
			finding := SAFinding{
				Namespace:            ns,
				Name:                 sa.Name,
				WorkloadTypes:        make(map[string]int),
				PodsWithCapabilities: make(map[string]int),
				PodNodeMap:           make(map[string]string),
				NodePodCount:         make(map[string]int),
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
			tokenSecrets := saSecrets[ns][sa.Name]
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
			autoMount := "Yes (default)"
			if sa.AutomountServiceAccountToken != nil {
				if *sa.AutomountServiceAccountToken {
					autoMount = "Yes"
				} else {
					autoMount = "No"
				}
			}
			finding.AutoMountToken = autoMount

			// Get roles bound to this SA
			roles := saRoleBindings[ns][sa.Name]
			clusterRoles := saClusterRoleBindings[ns][sa.Name]
			finding.Roles = roles
			finding.ClusterRoles = clusterRoles
			finding.TotalRoleBindings = len(roles) + len(clusterRoles)
			finding.RBACSprawl = finding.TotalRoleBindings > 5

			// Get pods using this SA
			podsUsingSA := saPods[ns][sa.Name]
			finding.TotalPods = len(podsUsingSA)
			finding.ActivelyUsed = len(podsUsingSA) > 0

			// Analyze workload types and pod security context
			if len(podsUsingSA) > 0 {
				workloadAnalysis := analyzeWorkloadTypes(ctx, clientset, ns, podsUsingSA)
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

				// Store pod names and node info for SA Hunter targeting
				nodeSet := make(map[string]bool)
				for _, pod := range podsUsingSA {
					finding.PodsUsingSA = append(finding.PodsUsingSA, pod.Name)

					// Track node information
					nodeName := pod.Spec.NodeName
					if nodeName != "" {
						finding.PodNodeMap[pod.Name] = nodeName
						finding.NodePodCount[nodeName]++
						nodeSet[nodeName] = true
					}
				}

				// Build unique nodes list
				for node := range nodeSet {
					finding.NodesUsingSA = append(finding.NodesUsingSA, node)
				}

				// Generate target summary for quick reference
				finding.TargetSummary = generateTargetSummary(&finding)
			}

			// Get image pull secrets
			var imagePullSecrets []string
			for _, ips := range sa.ImagePullSecrets {
				imagePullSecrets = append(imagePullSecrets, ips.Name)
			}
			finding.ImagePullSecrets = imagePullSecrets

			// Analyze permissions
			permAnalysis := analyzePermissionsEnhanced(ns, roles, clusterRoles, allRoles, allClusterRoles)
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
			nodeAccess := analyzeNodePermissions(roles, clusterRoles, allRoles, allClusterRoles, ns)
			finding.NodeAccess = nodeAccess.CanAccess
			finding.CanAccessNodes = nodeAccess.CanAccess
			finding.CanProxyNodes = nodeAccess.CanProxy
			finding.NodePermissions = nodeAccess.Permissions

			// Cross-namespace access analysis
			crossNSInfo := analyzeCrossNamespaceAccess(roles, clusterRoles, allRoles, allClusterRoles, ns)
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
				exposureInfo := detectExternalExposure(podsUsingSA, allServices[ns])
				finding.ExternallyExposed = exposureInfo.IsExposed
				finding.ExposureMethod = exposureInfo.Method
				finding.ExposedPods = exposureInfo.Pods
				if exposureInfo.IsExposed {
					finding.SecurityIssues = append(finding.SecurityIssues,
						fmt.Sprintf("SA tokens exposed via %s", exposureInfo.Method))
				}
			}

			// Cloud workload identity analysis
			cloudIdentity := analyzeCloudWorkloadIdentity(ctx, dynamicClient, &sa)
			finding.HasCloudIdentity = cloudIdentity.HasCloudIdentity
			finding.CloudIdentitySummary = cloudIdentity.Summary
			finding.AWSRoleARN = cloudIdentity.AWSRoleARN
			finding.AWSPodIdentityAssoc = cloudIdentity.AWSAssocName
			finding.GCPServiceAccountEmail = cloudIdentity.GCPEmail
			finding.AzureClientID = cloudIdentity.AzureClientID
			finding.AzureTenantID = cloudIdentity.AzureTenantID
			finding.CloudProviders = cloudIdentity.Providers

			// Cloud identity increases risk if SA has dangerous permissions
			if cloudIdentity.HasCloudIdentity && len(finding.DangerousPermissions) > 0 {
				finding.SecurityIssues = append(finding.SecurityIssues,
					fmt.Sprintf("Cloud identity (%s) + K8s permissions = cross-boundary escalation", strings.Join(cloudIdentity.Providers, ",")))
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

			// Determine effective admin status
			finding.EffectiveAdmin, finding.IsClusterAdmin, finding.IsNamespaceAdmin = determineEffectiveAdmin(&finding)

			// Calculate risk score and blast radius
			riskLevel, riskScore := calculateSARiskScore(&finding)
			finding.RiskLevel = riskLevel
			finding.RiskScore = riskScore
			finding.BlastRadius = calculateBlastRadius(&finding)
			finding.ImpactSummary = serviceAccountGenerateImpactSummary(&finding)

			riskCounts.Add(finding.RiskLevel)
			findings = append(findings, finding)

			// Format output row
			// Target pods - show all pod names
			targetPodsStr := "-"
			if finding.TotalPods > 0 {
				targetPodsStr = strings.Join(finding.PodsUsingSA, ", ")
			}

			// Target nodes - show all node names
			targetNodesStr := "-"
			if len(finding.NodesUsingSA) > 0 {
				targetNodesStr = strings.Join(finding.NodesUsingSA, ", ")
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

			// Cloud identity string
			cloudIdentityStr := "-"
			if finding.HasCloudIdentity {
				cloudIdentityStr = finding.CloudIdentitySummary
			}

			outputRows = append(outputRows, []string{
				fmt.Sprintf("%d", finding.BlastRadius),
				finding.EffectiveAdmin,
				ns,
				sa.Name,
				targetPodsStr,
				targetNodesStr,
				finding.WorkloadSummary,
				fmt.Sprintf("%d", finding.PrivilegedPods),
				finding.TokenType,
				fmt.Sprintf("%d", finding.EscalationPathCount),
				nodeAccessStr,
				crossNSStr,
				cloudIdentityStr,
				finding.PermissionSummary,
				strings.Join(k8sinternal.Unique(roles), ", "),
				strings.Join(k8sinternal.Unique(clusterRoles), ", "),
				autoMount,
				fmt.Sprintf("%d", len(finding.SecurityIssues)),
			})

			// Generate loot content
			serviceAccountGenerateLootContent(&finding, loot)
		}
	}

	// Sort findings by blast radius (descending)
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].BlastRadius > findings[j].BlastRadius
	})

	// Add summaries
	if riskCounts.Critical > 0 || riskCounts.High > 0 {
		summary := fmt.Sprintf(`
# SUMMARY: Risk Distribution
# CRITICAL: %d service accounts
# HIGH: %d service accounts
# MEDIUM: %d service accounts
# LOW: %d service accounts
#
# Focus on CRITICAL and HIGH risk service accounts for maximum impact.
# Prioritize by blast radius for efficient exploitation.
`, riskCounts.Critical, riskCounts.High, riskCounts.Medium, riskCounts.Low)

		loot.Section("ServiceAccounts-RBAC-Analysis").SetSummary(summary)
		loot.Section("ServiceAccounts-Privilege-Escalation").SetSummary(summary)
		loot.Section("ServiceAccounts-Escalation-Paths").SetSummary(summary)
		loot.Section("ServiceAccounts-Blast-Radius").SetSummary(summary)
	}

	table := internal.TableFile{
		Name:   "ServiceAccounts",
		Header: headers,
		Body:   outputRows,
	}

	lootFiles := loot.Build()

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
			len(outputRows), len(namespaces),
			riskCounts.Critical, riskCounts.High, riskCounts.Medium, riskCounts.Low),
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
						if !serviceAccountsContains(result.DangerousPerms, perm) {
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
							if !serviceAccountsContains(result.DangerousPerms, perm) {
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

func analyzeWorkloadTypes(ctx context.Context, clientset *kubernetes.Clientset, namespace string, pods []corev1.Pod) WorkloadAnalysis {
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

// generateTargetSummary creates a targeting summary for SA Hunter feature
func generateTargetSummary(finding *SAFinding) string {
	if finding.TotalPods == 0 {
		return "No active pods"
	}

	parts := []string{fmt.Sprintf("%d pods", finding.TotalPods)}

	if len(finding.NodesUsingSA) > 0 {
		parts = append(parts, fmt.Sprintf("%d nodes", len(finding.NodesUsingSA)))
	}

	if finding.PrivilegedPods > 0 {
		parts = append(parts, fmt.Sprintf("%d privileged", finding.PrivilegedPods))
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
	if finding.AutoMountToken != "No" {
		issues = append(issues, "Default SA auto-mounts tokens (should be No)")
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

	// Path 11: Cloud identity → cross-boundary access
	if finding.HasCloudIdentity {
		paths = append(paths, fmt.Sprintf("cloud-identity: Access cloud resources via %s workload identity", strings.Join(finding.CloudProviders, "/")))
	}

	return paths
}

func calculateSARiskScore(finding *SAFinding) (string, int) {
	score := 0

	// Cluster-admin = instant CRITICAL
	for _, cr := range finding.ClusterRoles {
		if cr == "cluster-admin" {
			return shared.RiskCritical, 100
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

	// Cloud workload identity (cross-boundary access)
	if finding.HasCloudIdentity {
		score += 25 // Cross-boundary access to cloud resources
		// Extra risk if combined with dangerous K8s permissions
		if len(finding.DangerousPermissions) > 0 {
			score += 15 // Combined K8s + cloud access is severe
		}
	}

	// Determine risk level
	if score >= 85 {
		return shared.RiskCritical, min(score, 100)
	} else if score >= 60 {
		return shared.RiskHigh, score
	} else if score >= 30 {
		return shared.RiskMedium, score
	}
	return shared.RiskLow, score
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

// determineEffectiveAdmin analyzes permissions and returns the effective admin status
// Returns: "Cluster Admin", "<namespace1>, <namespace2>", or "No"
func determineEffectiveAdmin(finding *SAFinding) (string, bool, bool) {
	// Check for cluster-admin level access
	for _, cr := range finding.ClusterRoles {
		if cr == "cluster-admin" {
			return "Cluster Admin", true, false
		}
	}

	// Cluster-level admin indicators:
	// - Can modify RBAC at cluster level (create clusterroles/clusterrolebindings)
	// - Has wildcard permissions at cluster scope (* * on cluster resources)
	// - Can impersonate at cluster level
	// - Has cluster-wide access + can modify RBAC
	if finding.ClusterWideAccess {
		// Check for cluster-admin-equivalent permissions
		if finding.CanModifyRBAC {
			return "Cluster Admin", true, false
		}
		// Can impersonate users/groups cluster-wide
		if finding.CanImpersonate {
			return "Cluster Admin", true, false
		}
		// Can modify admission controllers (bypass all security)
		if finding.CanModifyAdmission {
			return "Cluster Admin", true, false
		}
		// Can proxy to nodes (full kubelet access = cluster admin)
		if finding.CanProxyNodes {
			return "Cluster Admin", true, false
		}
	}

	// Namespace-level admin indicators:
	// - Can create pods + read secrets + exec into pods (full namespace control)
	// - Can modify RBAC within namespace
	// - Has "admin" or "edit" role in the namespace
	isNamespaceAdmin := false
	namespaceAdminCapabilities := 0

	if finding.CanCreatePods {
		namespaceAdminCapabilities++
	}
	if finding.CanReadSecrets {
		namespaceAdminCapabilities++
	}
	if finding.CanExecPods {
		namespaceAdminCapabilities++
	}
	if finding.CanModifyRBAC {
		namespaceAdminCapabilities++
	}

	// If SA has 3+ of these capabilities, it's effectively a namespace admin
	if namespaceAdminCapabilities >= 3 {
		isNamespaceAdmin = true
	}

	// Check for admin/edit role names (common patterns)
	if !isNamespaceAdmin {
		for _, role := range finding.Roles {
			roleLower := strings.ToLower(role)
			if roleLower == "admin" || roleLower == "edit" ||
				strings.HasSuffix(roleLower, "-admin") ||
				strings.Contains(roleLower, "namespace-admin") {
				isNamespaceAdmin = true
				break
			}
		}
	}

	if !isNamespaceAdmin {
		for _, cr := range finding.ClusterRoles {
			crLower := strings.ToLower(cr)
			if crLower == "admin" || crLower == "edit" {
				isNamespaceAdmin = true
				break
			}
		}
	}

	if isNamespaceAdmin {
		// Build the namespace list
		var adminNamespaces []string

		// Always include the SA's own namespace if it's a namespace admin
		adminNamespaces = append(adminNamespaces, finding.Namespace)

		// If cross-namespace access, include those namespaces too
		if finding.CrossNamespaceAccess && len(finding.AccessibleNamespaces) > 0 {
			for _, ns := range finding.AccessibleNamespaces {
				if ns != finding.Namespace {
					adminNamespaces = append(adminNamespaces, ns)
				}
			}
		}

		// Format output - list all namespaces
		return strings.Join(adminNamespaces, ", "), false, true
	}

	return "No", false, false
}

func serviceAccountGenerateImpactSummary(finding *SAFinding) string {
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

func serviceAccountGenerateLootContent(finding *SAFinding, loot *shared.LootBuilder) {
	ns := finding.Namespace
	sa := finding.Name

	// Enumeration
	loot.Section("ServiceAccounts-Enum").Addf("\n# [%s] ServiceAccount: %s/%s", finding.RiskLevel, ns, sa)
	loot.Section("ServiceAccounts-Enum").Addf("# Risk Score: %d | Blast Radius: %d | %s", finding.RiskScore, finding.BlastRadius, finding.ImpactSummary)
	loot.Section("ServiceAccounts-Enum").Addf("kubectl get serviceaccount %s -n %s -o yaml", sa, ns)
	loot.Section("ServiceAccounts-Enum").Addf("kubectl describe serviceaccount %s -n %s", sa, ns)

	// Show RBAC permissions
	if len(finding.Roles) > 0 {
		loot.Section("ServiceAccounts-Enum").Addf("# Roles: %s", strings.Join(finding.Roles, ", "))
		for _, role := range finding.Roles {
			loot.Section("ServiceAccounts-Enum").Addf("kubectl get role %s -n %s -o yaml", role, ns)
		}
	}
	if len(finding.ClusterRoles) > 0 {
		loot.Section("ServiceAccounts-Enum").Addf("# ClusterRoles: %s", strings.Join(finding.ClusterRoles, ", "))
		for _, cr := range finding.ClusterRoles {
			loot.Section("ServiceAccounts-Enum").Addf("kubectl get clusterrole %s -o yaml", cr)
		}
	}
	loot.Section("ServiceAccounts-Enum").Add("")

	// SA Hunter - Targeting Information (for CRITICAL/HIGH or actively used SAs)
	if finding.ActivelyUsed && (finding.RiskLevel == shared.RiskCritical || finding.RiskLevel == shared.RiskHigh || len(finding.DangerousPermissions) > 0) {
		loot.Section("ServiceAccounts-SA-Hunter").Addf("\n### [%s] TARGET: %s/%s", finding.RiskLevel, ns, sa)
		loot.Section("ServiceAccounts-SA-Hunter").Addf("# Risk Score: %d | Blast Radius: %d | %s", finding.RiskScore, finding.BlastRadius, finding.TargetSummary)
		if len(finding.DangerousPermissions) > 0 {
			loot.Section("ServiceAccounts-SA-Hunter").Addf("# Dangerous Permissions: %s", strings.Join(finding.DangerousPermissions, ", "))
		}
		loot.Section("ServiceAccounts-SA-Hunter").Add("#")
		loot.Section("ServiceAccounts-SA-Hunter").Add("# === POD → NODE MAPPING ===")

		// Show each pod and its node
		for pod, node := range finding.PodNodeMap {
			loot.Section("ServiceAccounts-SA-Hunter").Addf("# Pod: %s → Node: %s", pod, node)
		}

		loot.Section("ServiceAccounts-SA-Hunter").Add("#")
		loot.Section("ServiceAccounts-SA-Hunter").Add("# === ATTACK COMMANDS ===")

		// Exec commands for targeting - show ALL pods
		for _, pod := range finding.PodsUsingSA {
			node := finding.PodNodeMap[pod]
			if node != "" {
				loot.Section("ServiceAccounts-SA-Hunter").Addf("# Target pod on node %s:", node)
			}
			loot.Section("ServiceAccounts-SA-Hunter").Addf("kubectl exec -it %s -n %s -- sh", pod, ns)
		}

		// Show node breakdown
		if len(finding.NodePodCount) > 0 {
			loot.Section("ServiceAccounts-SA-Hunter").Add("#")
			loot.Section("ServiceAccounts-SA-Hunter").Add("# === NODE BREAKDOWN ===")
			for node, count := range finding.NodePodCount {
				loot.Section("ServiceAccounts-SA-Hunter").Addf("# Node %s: %d pods with this SA", node, count)
			}
		}

		// If privileged pods exist, highlight them
		if finding.PrivilegedPods > 0 {
			loot.Section("ServiceAccounts-SA-Hunter").Add("#")
			loot.Section("ServiceAccounts-SA-Hunter").Addf("# !!! %d PRIVILEGED PODS - HIGH VALUE TARGETS !!!", finding.PrivilegedPods)
			loot.Section("ServiceAccounts-SA-Hunter").Add("# Privileged pods can escape to the node!")
		}

		// Quick token extraction for this SA
		loot.Section("ServiceAccounts-SA-Hunter").Add("#")
		loot.Section("ServiceAccounts-SA-Hunter").Add("# === EXTRACT SA TOKEN FROM POD ===")
		if len(finding.PodsUsingSA) > 0 {
			loot.Section("ServiceAccounts-SA-Hunter").Addf("kubectl exec %s -n %s -- cat /var/run/secrets/kubernetes.io/serviceaccount/token", finding.PodsUsingSA[0], ns)
		}
		loot.Section("ServiceAccounts-SA-Hunter").Add("")
	}

	// Token extraction
	if finding.HasToken {
		loot.Section("ServiceAccounts-Token-Extraction").Addf("\n# [%s] ServiceAccount: %s/%s", finding.RiskLevel, ns, sa)
		loot.Section("ServiceAccounts-Token-Extraction").Addf("# Token Type: %s | Age: %d days", finding.TokenType, finding.TokenAge)

		if len(finding.Secrets) > 0 {
			for _, secretName := range finding.Secrets {
				loot.Section("ServiceAccounts-Token-Extraction").Addf("# Secret: %s", secretName)
				loot.Section("ServiceAccounts-Token-Extraction").Addf("kubectl get secret %s -n %s -o jsonpath='{.data.token}' | base64 -d", secretName, ns)
			}
		} else {
			loot.Section("ServiceAccounts-Token-Extraction").Add("# Create projected token:")
			loot.Section("ServiceAccounts-Token-Extraction").Addf("kubectl create token %s -n %s --duration=24h", sa, ns)
		}
		loot.Section("ServiceAccounts-Token-Extraction").Add("")
	}

	// Impersonation
	loot.Section("ServiceAccounts-Impersonation").Addf("\n# [%s] ServiceAccount: %s/%s", finding.RiskLevel, ns, sa)
	if len(finding.DangerousPermissions) > 0 {
		loot.Section("ServiceAccounts-Impersonation").Addf("# Dangerous Permissions: %s", strings.Join(finding.DangerousPermissions[:min(3, len(finding.DangerousPermissions))], ", "))
	}
	loot.Section("ServiceAccounts-Impersonation").Add("# Extract token:")
	if len(finding.Secrets) > 0 {
		loot.Section("ServiceAccounts-Impersonation").Addf("export SA_TOKEN=$(kubectl get secret %s -n %s -o jsonpath='{.data.token}' | base64 -d)", finding.Secrets[0], ns)
	} else {
		loot.Section("ServiceAccounts-Impersonation").Addf("export SA_TOKEN=$(kubectl create token %s -n %s --duration=24h)", sa, ns)
	}
	loot.Section("ServiceAccounts-Impersonation").Add("# Use token:")
	loot.Section("ServiceAccounts-Impersonation").Add("kubectl --token=$SA_TOKEN auth can-i --list")
	loot.Section("ServiceAccounts-Impersonation").Add("")

	// Privilege escalation for CRITICAL/HIGH
	if finding.RiskLevel == shared.RiskCritical || finding.RiskLevel == shared.RiskHigh {
		loot.Section("ServiceAccounts-Privilege-Escalation").Addf("\n### [%s] ServiceAccount: %s/%s", finding.RiskLevel, ns, sa)
		loot.Section("ServiceAccounts-Privilege-Escalation").Addf("# Risk Score: %d | Blast Radius: %d", finding.RiskScore, finding.BlastRadius)
		loot.Section("ServiceAccounts-Privilege-Escalation").Addf("# Permissions: %s", finding.PermissionSummary)

		if len(finding.PodsUsingSA) > 0 {
			loot.Section("ServiceAccounts-Privilege-Escalation").Addf("# OPTION 1: Exploit existing %d pods", len(finding.PodsUsingSA))
			for _, pod := range finding.PodsUsingSA {
				node := finding.PodNodeMap[pod]
				if node != "" {
					loot.Section("ServiceAccounts-Privilege-Escalation").Addf("# Pod on node: %s", node)
				}
				loot.Section("ServiceAccounts-Privilege-Escalation").Addf("kubectl exec -it %s -n %s -- sh", pod, ns)
			}
			loot.Section("ServiceAccounts-Privilege-Escalation").Add("# Inside pod: SA_TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)")
		}

		loot.Section("ServiceAccounts-Privilege-Escalation").Add("# OPTION 2: Create new pod:")
		loot.Section("ServiceAccounts-Privilege-Escalation").Addf("kubectl run exploit-%s --image=alpine -n %s --serviceaccount=%s -- sleep 3600", sa, ns, sa)
		loot.Section("ServiceAccounts-Privilege-Escalation").Add("")

		// Permissions analysis
		loot.Section("ServiceAccounts-RBAC-Analysis").Addf("\n### [%s] %s/%s", finding.RiskLevel, ns, sa)
		loot.Section("ServiceAccounts-RBAC-Analysis").Addf("# Risk Score: %d | Blast Radius: %d", finding.RiskScore, finding.BlastRadius)
		loot.Section("ServiceAccounts-RBAC-Analysis").Addf("# Permissions: %s", finding.PermissionSummary)
		if len(finding.DangerousPermissions) > 0 {
			loot.Section("ServiceAccounts-RBAC-Analysis").Add("# Dangerous Permissions:")
			for _, perm := range finding.DangerousPermissions {
				loot.Section("ServiceAccounts-RBAC-Analysis").Addf("#   - %s", perm)
			}
		}
		loot.Section("ServiceAccounts-RBAC-Analysis").Add("")

		// Escalation paths
		if len(finding.EscalationPaths) > 0 {
			loot.Section("ServiceAccounts-Escalation-Paths").Addf("\n### [%s] %s/%s - %d Escalation Paths", finding.RiskLevel, ns, sa, len(finding.EscalationPaths))
			loot.Section("ServiceAccounts-Escalation-Paths").Addf("# Risk Score: %d | Blast Radius: %d", finding.RiskScore, finding.BlastRadius)
			for _, path := range finding.EscalationPaths {
				loot.Section("ServiceAccounts-Escalation-Paths").Addf("# - %s", path)
			}
			loot.Section("ServiceAccounts-Escalation-Paths").Add("")
		}

		// Blast radius
		if finding.BlastRadius > 100 {
			loot.Section("ServiceAccounts-Blast-Radius").Addf("\n### Blast Radius: %d - %s/%s", finding.BlastRadius, ns, sa)
			loot.Section("ServiceAccounts-Blast-Radius").Addf("# Risk Score: %d × Pods: %d × Multipliers = %d", finding.RiskScore, finding.TotalPods, finding.BlastRadius)
			loot.Section("ServiceAccounts-Blast-Radius").Addf("# Workloads: %s", finding.WorkloadSummary)
			loot.Section("ServiceAccounts-Blast-Radius").Addf("# Impact: %s", finding.ImpactSummary)
			loot.Section("ServiceAccounts-Blast-Radius").Add("")
		}
	}

	// Default SA issues
	if finding.IsDefaultSA && len(finding.DefaultSAIssues) > 0 {
		loot.Section("ServiceAccounts-Default-SA-Security").Addf("\n### CRITICAL: default SA in %s has security issues", ns)
		for _, issue := range finding.DefaultSAIssues {
			loot.Section("ServiceAccounts-Default-SA-Security").Addf("# - %s", issue)
		}
		loot.Section("ServiceAccounts-Default-SA-Security").Add("# Remediation:")
		loot.Section("ServiceAccounts-Default-SA-Security").Addf("kubectl patch serviceaccount default -n %s -p '{\"automountServiceAccountToken\":false}'", ns)
		loot.Section("ServiceAccounts-Default-SA-Security").Add("")
	}

	// Cross-namespace access
	if finding.CrossNamespaceAccess || finding.ClusterWideAccess {
		loot.Section("ServiceAccounts-Cross-Namespace-Access").Addf("\n### [%s] %s/%s - %s Access", finding.RiskLevel, ns, sa, finding.PermissionScope)
		loot.Section("ServiceAccounts-Cross-Namespace-Access").Addf("# Risk Score: %d | Blast Radius: %d", finding.RiskScore, finding.BlastRadius)
		if finding.ClusterWideAccess {
			loot.Section("ServiceAccounts-Cross-Namespace-Access").Add("# Can access ALL namespaces and cluster resources")
		} else {
			loot.Section("ServiceAccounts-Cross-Namespace-Access").Addf("# Can access %d namespaces", len(finding.AccessibleNamespaces))
		}
		loot.Section("ServiceAccounts-Cross-Namespace-Access").Add("")
	}

	// Node access
	if finding.NodeAccess {
		loot.Section("ServiceAccounts-Node-Access").Addf("\n### [%s] %s/%s - Node-Level Access", finding.RiskLevel, ns, sa)
		loot.Section("ServiceAccounts-Node-Access").Addf("# Risk Score: %d | Blast Radius: %d", finding.RiskScore, finding.BlastRadius)
		if finding.CanProxyNodes {
			loot.Section("ServiceAccounts-Node-Access").Add("# CRITICAL: Can proxy to nodes (full kubelet access)")
		}
		loot.Section("ServiceAccounts-Node-Access").Addf("# Node Permissions: %s", strings.Join(finding.NodePermissions, ", "))
		loot.Section("ServiceAccounts-Node-Access").Add("")
	}

	// Token lifecycle
	if finding.TokenRotationNeeded || finding.TokenType == "legacy-secret" {
		loot.Section("ServiceAccounts-Token-Lifecycle").Addf("\n### %s/%s - Token Lifecycle Issue", ns, sa)
		loot.Section("ServiceAccounts-Token-Lifecycle").Addf("# Token Type: %s | Age: %d days", finding.TokenType, finding.TokenAge)
		if finding.TokenRotationNeeded {
			loot.Section("ServiceAccounts-Token-Lifecycle").Add("# URGENT: Token >90 days old, needs rotation")
		}
		if finding.TokenType == "legacy-secret" {
			loot.Section("ServiceAccounts-Token-Lifecycle").Add("# Migrate to projected tokens (K8s 1.21+)")
		}
		loot.Section("ServiceAccounts-Token-Lifecycle").Add("")
	}

	// Unused SAs
	if !finding.ActivelyUsed {
		loot.Section("ServiceAccounts-Unused").Addf("\n### %s/%s - Unused (0 pods)", ns, sa)
		loot.Section("ServiceAccounts-Unused").Addf("# Age: %d days | Has Permissions: %v", finding.AgeDays, len(finding.Roles)+len(finding.ClusterRoles) > 0)
		if len(finding.Roles) > 0 || len(finding.ClusterRoles) > 0 {
			loot.Section("ServiceAccounts-Unused").Add("# RISK: Unused but has permissions (cleanup candidate)")
		}
		loot.Section("ServiceAccounts-Unused").Addf("# Consider deletion: kubectl delete serviceaccount %s -n %s", sa, ns)
		loot.Section("ServiceAccounts-Unused").Add("")
	}

	// Workload mapping
	if finding.ActivelyUsed {
		loot.Section("ServiceAccounts-Workload-Mapping").Addf("\n### %s/%s - %d Pods", ns, sa, finding.TotalPods)
		loot.Section("ServiceAccounts-Workload-Mapping").Addf("# Workloads: %s", finding.WorkloadSummary)
		if finding.PrivilegedPods > 0 {
			loot.Section("ServiceAccounts-Workload-Mapping").Addf("# CRITICAL: %d privileged pods", finding.PrivilegedPods)
		}
		loot.Section("ServiceAccounts-Workload-Mapping").Add("")
	}

	// Remediation
	if len(finding.SecurityIssues) > 0 {
		loot.Section("ServiceAccounts-Remediation").Addf("\n### %s/%s - %d Security Issues", ns, sa, len(finding.SecurityIssues))
		for _, issue := range finding.SecurityIssues {
			loot.Section("ServiceAccounts-Remediation").Addf("# - %s", issue)
		}
		loot.Section("ServiceAccounts-Remediation").Add("# Remediation steps:")
		if finding.IsDefaultSA {
			loot.Section("ServiceAccounts-Remediation").Addf("kubectl patch serviceaccount default -n %s -p '{\"automountServiceAccountToken\":false}'", ns)
		}
		if finding.TokenRotationNeeded {
			loot.Section("ServiceAccounts-Remediation").Addf("# Rotate token by deleting secrets: kubectl delete secret <token-secret> -n %s", ns)
		}
		loot.Section("ServiceAccounts-Remediation").Add("")
	}

	// Cloud workload identity
	if finding.HasCloudIdentity {
		loot.Section("ServiceAccounts-Cloud-Identity").Addf("\n### [%s] %s/%s - Cloud Identity Mapping", finding.RiskLevel, ns, sa)
		loot.Section("ServiceAccounts-Cloud-Identity").Addf("# Risk Score: %d | Blast Radius: %d", finding.RiskScore, finding.BlastRadius)
		loot.Section("ServiceAccounts-Cloud-Identity").Addf("# Cloud Providers: %s", strings.Join(finding.CloudProviders, ", "))

		if finding.AWSRoleARN != "" {
			loot.Section("ServiceAccounts-Cloud-Identity").Addf("# AWS IAM Role: %s", finding.AWSRoleARN)
			if finding.AWSPodIdentityAssoc != "" {
				loot.Section("ServiceAccounts-Cloud-Identity").Addf("# AWS Pod Identity Association: %s", finding.AWSPodIdentityAssoc)
			}
			loot.Section("ServiceAccounts-Cloud-Identity").Add("# Check AWS IAM role policies:")
			loot.Section("ServiceAccounts-Cloud-Identity").Addf("aws iam get-role --role-name %s", extractRoleName(finding.AWSRoleARN))
			loot.Section("ServiceAccounts-Cloud-Identity").Addf("aws iam list-attached-role-policies --role-name %s", extractRoleName(finding.AWSRoleARN))
			loot.Section("ServiceAccounts-Cloud-Identity").Addf("aws iam list-role-policies --role-name %s", extractRoleName(finding.AWSRoleARN))
		}

		if finding.GCPServiceAccountEmail != "" {
			loot.Section("ServiceAccounts-Cloud-Identity").Addf("# GCP Service Account: %s", finding.GCPServiceAccountEmail)
			loot.Section("ServiceAccounts-Cloud-Identity").Add("# Check GCP IAM bindings:")
			loot.Section("ServiceAccounts-Cloud-Identity").Addf("gcloud iam service-accounts get-iam-policy %s", finding.GCPServiceAccountEmail)
			loot.Section("ServiceAccounts-Cloud-Identity").Add("# List roles for GSA (requires project):")
			loot.Section("ServiceAccounts-Cloud-Identity").Add("gcloud projects get-iam-policy $PROJECT_ID --flatten='bindings[].members' --filter='bindings.members:serviceAccount:' --format='table(bindings.role)'")
		}

		if finding.AzureClientID != "" {
			loot.Section("ServiceAccounts-Cloud-Identity").Addf("# Azure Client ID: %s", finding.AzureClientID)
			if finding.AzureTenantID != "" {
				loot.Section("ServiceAccounts-Cloud-Identity").Addf("# Azure Tenant ID: %s", finding.AzureTenantID)
			}
			loot.Section("ServiceAccounts-Cloud-Identity").Add("# Check Azure role assignments:")
			loot.Section("ServiceAccounts-Cloud-Identity").Addf("az ad sp show --id %s", finding.AzureClientID)
			loot.Section("ServiceAccounts-Cloud-Identity").Addf("az role assignment list --assignee %s", finding.AzureClientID)
		}

		// Highlight cross-boundary risk
		if len(finding.DangerousPermissions) > 0 {
			loot.Section("ServiceAccounts-Cloud-Identity").Add("#")
			loot.Section("ServiceAccounts-Cloud-Identity").Add("# WARNING: This SA has both cloud identity AND dangerous K8s permissions!")
			loot.Section("ServiceAccounts-Cloud-Identity").Addf("# K8s Permissions: %s", strings.Join(finding.DangerousPermissions[:min(3, len(finding.DangerousPermissions))], ", "))
			loot.Section("ServiceAccounts-Cloud-Identity").Add("# RISK: Compromising this SA gives access to BOTH K8s cluster AND cloud resources")
		}

		loot.Section("ServiceAccounts-Cloud-Identity").Add("")
	}
}

func serviceAccountsContains(slice []string, item string) bool {
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

// ====================
// Cloud Workload Identity Functions
// ====================

// CloudIdentityInfo holds cloud identity information for a service account
type CloudIdentityInfo struct {
	HasCloudIdentity bool
	Summary          string
	Providers        []string
	AWSRoleARN       string
	AWSAssocName     string
	GCPEmail         string
	AzureClientID    string
	AzureTenantID    string
}

// analyzeCloudWorkloadIdentity analyzes cloud workload identity for a service account
func analyzeCloudWorkloadIdentity(ctx context.Context, dynamicClient dynamic.Interface, sa *corev1.ServiceAccount) CloudIdentityInfo {
	info := CloudIdentityInfo{}

	// Check GCP Workload Identity (annotation-based)
	if gcpSA, ok := sa.Annotations["iam.gke.io/gcp-service-account"]; ok && gcpSA != "" {
		info.HasCloudIdentity = true
		info.GCPEmail = gcpSA
		info.Providers = append(info.Providers, "GCP")
	}

	// Check Azure Workload Identity (annotation-based for newer versions)
	if azureClientID, ok := sa.Annotations["azure.workload.identity/client-id"]; ok && azureClientID != "" {
		info.HasCloudIdentity = true
		info.AzureClientID = azureClientID
		info.Providers = append(info.Providers, "Azure")
		// Tenant ID is often in a separate annotation
		if tenantID, ok := sa.Annotations["azure.workload.identity/tenant-id"]; ok {
			info.AzureTenantID = tenantID
		}
	}

	// Check AWS EKS Pod Identity annotation (newer)
	if roleARN, ok := sa.Annotations["eks.amazonaws.com/role-arn"]; ok && roleARN != "" {
		info.HasCloudIdentity = true
		info.AWSRoleARN = roleARN
		if !saContainsProvider(info.Providers, "AWS") {
			info.Providers = append(info.Providers, "AWS")
		}
	}

	// Check AWS EKS Pod Identity Associations via CRD
	if dynamicClient != nil {
		awsInfo := checkAWSPodIdentityAssociation(ctx, dynamicClient, sa.Namespace, sa.Name)
		if awsInfo.RoleARN != "" {
			info.HasCloudIdentity = true
			info.AWSRoleARN = awsInfo.RoleARN
			info.AWSAssocName = awsInfo.Name
			if !saContainsProvider(info.Providers, "AWS") {
				info.Providers = append(info.Providers, "AWS")
			}
		}

		// Check Azure legacy AAD Pod Identity bindings
		if !saContainsProvider(info.Providers, "Azure") {
			azureInfo := checkAzureIdentityBinding(ctx, dynamicClient, sa.Namespace, sa.Name)
			if azureInfo.ClientID != "" {
				info.HasCloudIdentity = true
				info.AzureClientID = azureInfo.ClientID
				info.AzureTenantID = azureInfo.TenantID
				info.Providers = append(info.Providers, "Azure")
			}
		}
	}

	// Build summary
	if info.HasCloudIdentity {
		var parts []string
		if info.AWSRoleARN != "" {
			// Extract role name from ARN for summary
			parts = append(parts, fmt.Sprintf("AWS:%s", extractRoleName(info.AWSRoleARN)))
		}
		if info.GCPEmail != "" {
			// Extract SA name from email for summary
			parts = append(parts, fmt.Sprintf("GCP:%s", extractGSAName(info.GCPEmail)))
		}
		if info.AzureClientID != "" {
			parts = append(parts, fmt.Sprintf("Azure:%s", truncateString(info.AzureClientID, 12)))
		}
		info.Summary = strings.Join(parts, ", ")
	}

	return info
}

// AWSPodIdentityResult holds AWS Pod Identity Association info
type AWSPodIdentityResult struct {
	Name    string
	RoleARN string
}

// checkAWSPodIdentityAssociation checks for AWS EKS Pod Identity Associations
func checkAWSPodIdentityAssociation(ctx context.Context, dynamicClient dynamic.Interface, namespace, saName string) AWSPodIdentityResult {
	result := AWSPodIdentityResult{}

	gvr := schema.GroupVersionResource{
		Group:    "eks.amazonaws.com",
		Version:  "v1alpha1",
		Resource: "podidentityassociations",
	}

	// Try cluster-scoped first
	list, err := dynamicClient.Resource(gvr).List(ctx, metav1.ListOptions{})
	if err != nil {
		// Try namespace-scoped
		list, err = dynamicClient.Resource(gvr).Namespace(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return result
		}
	}

	for _, item := range list.Items {
		spec, ok := item.Object["spec"].(map[string]interface{})
		if !ok {
			continue
		}

		// Check if this association is for our service account
		assocNamespace, _ := spec["namespace"].(string)
		assocSA, _ := spec["serviceAccount"].(string)
		roleARN, _ := spec["roleArn"].(string)

		// Match by namespace and SA name
		if (assocNamespace == namespace || assocNamespace == "") && assocSA == saName {
			result.Name = item.GetName()
			result.RoleARN = roleARN
			return result
		}
	}

	return result
}

// AzureIdentityResult holds Azure identity binding info
type AzureIdentityResult struct {
	ClientID string
	TenantID string
}

// checkAzureIdentityBinding checks for Azure AAD Pod Identity bindings (legacy)
func checkAzureIdentityBinding(ctx context.Context, dynamicClient dynamic.Interface, namespace, saName string) AzureIdentityResult {
	result := AzureIdentityResult{}

	// Check AzureIdentityBinding CRD
	bindingGVR := schema.GroupVersionResource{
		Group:    "aadpodidentity.k8s.io",
		Version:  "v1",
		Resource: "azureidentitybindings",
	}

	bindings, err := dynamicClient.Resource(bindingGVR).Namespace(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return result
	}

	for _, binding := range bindings.Items {
		spec, ok := binding.Object["spec"].(map[string]interface{})
		if !ok {
			continue
		}

		// Check selector - Azure identity bindings use pod labels, not SA names directly
		// But we can check if there's an associated AzureIdentity and extract its info
		azureIdentityName, _ := spec["azureIdentity"].(string)
		if azureIdentityName == "" {
			continue
		}

		// Look up the associated AzureIdentity
		identityGVR := schema.GroupVersionResource{
			Group:    "aadpodidentity.k8s.io",
			Version:  "v1",
			Resource: "azureidentities",
		}

		identity, err := dynamicClient.Resource(identityGVR).Namespace(namespace).Get(ctx, azureIdentityName, metav1.GetOptions{})
		if err != nil {
			continue
		}

		identitySpec, ok := identity.Object["spec"].(map[string]interface{})
		if !ok {
			continue
		}

		clientID, _ := identitySpec["clientID"].(string)
		tenantID, _ := identitySpec["tenantID"].(string)

		// For now, return the first identity found in the namespace
		// A more sophisticated approach would match based on pod labels
		if clientID != "" {
			result.ClientID = clientID
			result.TenantID = tenantID
			return result
		}
	}

	return result
}

// Helper functions

func saContainsProvider(providers []string, provider string) bool {
	for _, p := range providers {
		if p == provider {
			return true
		}
	}
	return false
}

func extractRoleName(roleARN string) string {
	// ARN format: arn:aws:iam::123456789012:role/MyRoleName
	parts := strings.Split(roleARN, "/")
	if len(parts) > 1 {
		return parts[len(parts)-1]
	}
	// Fallback: return last 20 chars
	if len(roleARN) > 20 {
		return "..." + roleARN[len(roleARN)-17:]
	}
	return roleARN
}

func extractGSAName(email string) string {
	// Format: sa-name@project.iam.gserviceaccount.com
	parts := strings.Split(email, "@")
	if len(parts) > 0 {
		return parts[0]
	}
	return email
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
