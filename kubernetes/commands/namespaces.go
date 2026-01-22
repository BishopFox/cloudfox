package commands

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	k8sinternal "github.com/BishopFox/cloudfox/internal/kubernetes"
	"github.com/BishopFox/cloudfox/kubernetes/shared"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

var NamespacesCmd = &cobra.Command{
	Use:     "namespaces",
	Aliases: []string{"ns"},
	Short:   "Enumerate namespaces with comprehensive security analysis",
	Long: `
Enumerate all namespaces in the cluster with comprehensive security analysis including:
  - Risk-based scoring (CRITICAL/HIGH/MEDIUM/LOW)
  - Resource governance (ResourceQuota, LimitRange)
  - Network isolation (NetworkPolicy enforcement)
  - Pod Security Standards (PSS) enforcement
  - Workload distribution and resource counts
  - RBAC permissions analysis
  - Default namespace detection
  - Environment classification

  cloudfox kubernetes namespaces`,
	Run: ListNamespaces,
}

type NamespacesOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t NamespacesOutput) TableFiles() []internal.TableFile {
	return t.Table
}

func (t NamespacesOutput) LootFiles() []internal.LootFile {
	return t.Loot
}

// NamespaceFinding contains comprehensive namespace security analysis
type NamespaceFinding struct {
	// Basic info
	Name              string
	Phase             string
	CreationTimestamp string
	Age               string
	AgeInDays         int

	// Security analysis
	RiskLevel      string // CRITICAL/HIGH/MEDIUM/LOW
	SecurityIssues []string

	// Classification
	Environment  string // production, staging, dev
	IsProduction bool
	IsDefault    bool
	IsSensitive  bool
	IsEmpty      bool

	// Resource governance
	HasResourceQuota bool
	ResourceQuotas   []string
	HasLimitRange    bool
	LimitRanges      []string
	DoSRisk          bool

	// Network isolation
	HasNetworkPolicies bool
	NetworkPolicyCount int
	NetworkPolicies    []string
	DefaultDenyPolicy  bool
	IsolationLevel     string // "Isolated", "Partial", "None"

	// Pod Security Standards
	PSSEnforce        string // "restricted", "baseline", "privileged", "none"
	PSSAudit          string
	PSSWarn           string
	HasPSSEnforcement bool

	// Workload distribution
	PodCount         int
	DeploymentCount  int
	StatefulSetCount int
	DaemonSetCount   int
	JobCount         int
	CronJobCount     int
	SecretCount      int
	ConfigMapCount   int
	ServiceCount     int
	IngressCount     int
	TotalWorkloads   int

	// RBAC
	RoleBindingCount        int
	ClusterRoleBindingCount int
	ServiceAccountCount     int
	AdminBindings           []string
	DangerousPermissions    []string
	ExcessiveAccess         bool

	// Metadata
	Labels      map[string]string
	Annotations map[string]string
	Finalizers  []string
}

func ListNamespaces(cmd *cobra.Command, args []string) {
	ctx, cancel := shared.ContextWithTimeout()
	defer cancel()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating namespaces for %s", globals.ClusterName), globals.K8S_NAMESPACES_MODULE_NAME)

	clientset := config.GetClientOrExit()

	allNamespaces, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		shared.LogListError(&logger, "namespaces", "", err, globals.K8S_NAMESPACES_MODULE_NAME, true)
		return
	}

	// Filter namespaces based on target namespace flags
	var namespaces []corev1.Namespace
	for _, ns := range allNamespaces.Items {
		if shared.ShouldIncludeNamespace(ns.Name) {
			namespaces = append(namespaces, ns)
		}
	}

	headers := []string{
		"Namespace",
		"Environment",
		"Age",
		"Is Default",
		"Workloads",
		"Pods",
		"Services",
		"Ingresses",
		"Secrets",
		"ConfigMaps",
		"PSS Enforce",
		"Net Policies",
		"Isolation",
		"Resource Quota",
		"Limit Range",
		"RBAC Bindings",
		"Dangerous Perms",
		"Admin Bindings",
	}

	var outputRows [][]string
	var findings []NamespaceFinding

	// Risk level counters
	riskCounts := shared.NewRiskCounts()

	// Loot file builder
	loot := shared.NewLootBuilder()

	loot.Section("Namespace-Commands").SetHeader(`# ===========================================
# Namespace Enumeration & Configuration Commands
# ===========================================`)

	if globals.KubeContext != "" {
		loot.Section("Namespace-Commands").AddBlank().Addf("kubectl config use-context %s", globals.KubeContext)
	}

	loot.Section("Namespace-Commands").AddBlank().
		Add("# List all namespaces:").
		Add("kubectl get namespaces").
		Add("kubectl get namespaces -o wide").
		AddBlank().
		Add("# Describe namespace:").
		Add("kubectl describe namespace <name>").
		AddBlank().
		Add("# Get namespace YAML:").
		Add("kubectl get namespace <name> -o yaml")

	for _, ns := range namespaces {
		finding := analyzeNamespace(ctx, clientset, &ns)
		findings = append(findings, finding)
		riskCounts.Add(finding.RiskLevel)

		// Build table row with expanded data

		// Is Default
		isDefaultStr := ""
		if finding.IsDefault {
			isDefaultStr = "Default"
		}

		// Net Policies - show policy names
		netPoliciesStr := "None"
		if len(finding.NetworkPolicies) > 0 {
			netPoliciesStr = strings.Join(finding.NetworkPolicies, ", ")
		}

		// Resource Quota - show quota names
		resourceQuotaStr := "None"
		if len(finding.ResourceQuotas) > 0 {
			resourceQuotaStr = strings.Join(finding.ResourceQuotas, ", ")
		}

		// Limit Range - show range names
		limitRangeStr := "None"
		if len(finding.LimitRanges) > 0 {
			limitRangeStr = strings.Join(finding.LimitRanges, ", ")
		}

		// RBAC Bindings - clearer format
		rbacBindingsStr := fmt.Sprintf("%d RB", finding.RoleBindingCount)
		if finding.ClusterRoleBindingCount > 0 {
			rbacBindingsStr = fmt.Sprintf("%d RB, %d CRB", finding.RoleBindingCount, finding.ClusterRoleBindingCount)
		}

		// Dangerous Perms - show RoleBinding names (cross-reference with rolebindings/permissions)
		dangerousPermsStr := "None"
		if len(finding.DangerousPermissions) > 0 {
			dangerousPermsStr = strings.Join(finding.DangerousPermissions, ", ")
		}

		// Admin Bindings - show RB/CRB names (cross-reference with rolebindings/permissions)
		adminBindingsStr := "None"
		if len(finding.AdminBindings) > 0 {
			adminBindingsStr = strings.Join(finding.AdminBindings, ", ")
		}

		outputRows = append(outputRows, []string{
			finding.Name,
			k8sinternal.NonEmpty(finding.Environment),
			finding.Age,
			isDefaultStr,
			fmt.Sprintf("%d", finding.TotalWorkloads),
			fmt.Sprintf("%d", finding.PodCount),
			fmt.Sprintf("%d", finding.ServiceCount),
			fmt.Sprintf("%d", finding.IngressCount),
			fmt.Sprintf("%d", finding.SecretCount),
			fmt.Sprintf("%d", finding.ConfigMapCount),
			k8sinternal.NonEmpty(finding.PSSEnforce),
			netPoliciesStr,
			finding.IsolationLevel,
			resourceQuotaStr,
			limitRangeStr,
			rbacBindingsStr,
			dangerousPermsStr,
			adminBindingsStr,
		})

	}

	// Add templates and remediation commands
	buildNamespaceCommandsLoot(loot, findings)

	table := internal.TableFile{
		Name:   "Namespaces",
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
		"Namespaces",
		globals.ClusterName,
		"results",
		NamespacesOutput{
			Table: []internal.TableFile{table},
			Loot:  lootFiles,
		},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_NAMESPACES_MODULE_NAME)
		return
	}

	if len(outputRows) > 0 {
		logger.InfoM(fmt.Sprintf("%d namespaces found | Risk: CRITICAL=%d, HIGH=%d, MEDIUM=%d, LOW=%d",
			len(outputRows),
			riskCounts.Critical, riskCounts.High, riskCounts.Medium, riskCounts.Low),
			globals.K8S_NAMESPACES_MODULE_NAME)
	} else {
		logger.InfoM("No namespaces found, skipping output file creation", globals.K8S_NAMESPACES_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_NAMESPACES_MODULE_NAME), globals.K8S_NAMESPACES_MODULE_NAME)
}

// ====================
// Main Analysis Function
// ====================

func analyzeNamespace(ctx context.Context, clientset *kubernetes.Clientset, ns *corev1.Namespace) NamespaceFinding {
	finding := NamespaceFinding{
		Name:              ns.Name,
		Phase:             string(ns.Status.Phase),
		CreationTimestamp: ns.CreationTimestamp.String(),
		Labels:            ns.Labels,
		Annotations:       ns.Annotations,
		Finalizers:        ns.Finalizers,
	}

	// Calculate age
	finding.Age, finding.AgeInDays = calculateAge(ns.CreationTimestamp.Time)

	// Classification
	finding.Environment = detectEnvironment(ns.Labels)
	finding.IsProduction = finding.Environment == "production"
	finding.IsDefault = ns.Name == "default"
	finding.IsSensitive = detectSensitiveNamespace(ns.Labels)

	// Resource governance
	finding.HasResourceQuota, finding.ResourceQuotas = analyzeResourceQuotas(ctx, clientset, ns.Name)
	finding.HasLimitRange, finding.LimitRanges = analyzeLimitRanges(ctx, clientset, ns.Name)

	// Network isolation
	finding.HasNetworkPolicies, finding.NetworkPolicyCount, finding.NetworkPolicies, finding.DefaultDenyPolicy = analyzeNetworkPolicies(ctx, clientset, ns.Name)
	finding.IsolationLevel = calculateIsolationLevel(finding.HasNetworkPolicies, finding.DefaultDenyPolicy)

	// Pod Security Standards
	finding.PSSEnforce, finding.PSSAudit, finding.PSSWarn, finding.HasPSSEnforcement = analyzePSSEnforcement(ns)

	// Workload distribution
	finding.PodCount, finding.DeploymentCount, finding.StatefulSetCount, finding.DaemonSetCount,
		finding.JobCount, finding.CronJobCount, finding.SecretCount, finding.ConfigMapCount,
		finding.ServiceCount, finding.IngressCount, finding.TotalWorkloads = analyzeWorkloadDistribution(ctx, clientset, ns.Name)

	finding.IsEmpty = finding.TotalWorkloads == 0

	// RBAC analysis
	finding.RoleBindingCount, finding.ClusterRoleBindingCount, finding.ServiceAccountCount,
		finding.AdminBindings, finding.DangerousPermissions, finding.ExcessiveAccess = analyzeRBAC(ctx, clientset, ns.Name)

	// DoS risk
	finding.DoSRisk = !finding.HasResourceQuota && finding.TotalWorkloads > 10

	// Security issues
	finding.SecurityIssues = analyzeNamespaceSecurity(finding)

	// Calculate risk level
	finding.RiskLevel = calculateNamespaceRiskLevel(finding)

	return finding
}

// ====================
// Helper Functions
// ====================

func calculateAge(creationTime time.Time) (string, int) {
	age := time.Since(creationTime)
	days := int(age.Hours() / 24)

	if days < 1 {
		hours := int(age.Hours())
		return fmt.Sprintf("%dh", hours), 0
	} else if days < 30 {
		return fmt.Sprintf("%dd", days), days
	} else if days < 365 {
		months := days / 30
		return fmt.Sprintf("%dmo", months), days
	}
	years := days / 365
	return fmt.Sprintf("%dy", years), days
}

func detectEnvironment(labels map[string]string) string {
	// Check common environment labels
	envLabels := []string{"environment", "env", "stage", "tier"}
	for _, label := range envLabels {
		if val, ok := labels[label]; ok {
			lowerVal := strings.ToLower(val)
			if strings.Contains(lowerVal, "prod") {
				return "production"
			} else if strings.Contains(lowerVal, "stag") {
				return "staging"
			} else if strings.Contains(lowerVal, "dev") {
				return "development"
			} else if strings.Contains(lowerVal, "test") {
				return "test"
			}
			return val
		}
	}
	return ""
}

func detectSensitiveNamespace(labels map[string]string) bool {
	sensitiveIndicators := []string{"sensitive", "confidential", "pci", "hipaa", "gdpr"}
	for k, v := range labels {
		lowerKey := strings.ToLower(k)
		lowerVal := strings.ToLower(v)
		for _, indicator := range sensitiveIndicators {
			if strings.Contains(lowerKey, indicator) || strings.Contains(lowerVal, indicator) {
				return true
			}
		}
	}
	return false
}

func analyzeResourceQuotas(ctx context.Context, clientset *kubernetes.Clientset, namespace string) (bool, []string) {
	quotas, err := clientset.CoreV1().ResourceQuotas(namespace).List(ctx, metav1.ListOptions{})
	if err != nil || len(quotas.Items) == 0 {
		return false, []string{}
	}

	var quotaNames []string
	for _, quota := range quotas.Items {
		quotaNames = append(quotaNames, quota.Name)
	}
	return true, quotaNames
}

func analyzeLimitRanges(ctx context.Context, clientset *kubernetes.Clientset, namespace string) (bool, []string) {
	limits, err := clientset.CoreV1().LimitRanges(namespace).List(ctx, metav1.ListOptions{})
	if err != nil || len(limits.Items) == 0 {
		return false, []string{}
	}

	var limitNames []string
	for _, limit := range limits.Items {
		limitNames = append(limitNames, limit.Name)
	}
	return true, limitNames
}

func analyzeNetworkPolicies(ctx context.Context, clientset *kubernetes.Clientset, namespace string) (bool, int, []string, bool) {
	policies, err := clientset.NetworkingV1().NetworkPolicies(namespace).List(ctx, metav1.ListOptions{})
	if err != nil || len(policies.Items) == 0 {
		return false, 0, []string{}, false
	}

	var policyNames []string
	hasDefaultDeny := false

	for _, policy := range policies.Items {
		policyNames = append(policyNames, policy.Name)

		// Check for default deny policy
		if isNamespaceDefaultDenyPolicy(&policy) {
			hasDefaultDeny = true
		}
	}

	return true, len(policies.Items), policyNames, hasDefaultDeny
}

func isNamespaceDefaultDenyPolicy(policy *networkingv1.NetworkPolicy) bool {
	// Default deny ingress: empty podSelector + empty ingress rules
	if len(policy.Spec.PodSelector.MatchLabels) == 0 &&
		len(policy.Spec.PodSelector.MatchExpressions) == 0 &&
		len(policy.Spec.Ingress) == 0 {
		return true
	}

	// Default deny egress: empty podSelector + empty egress rules
	if len(policy.Spec.PodSelector.MatchLabels) == 0 &&
		len(policy.Spec.PodSelector.MatchExpressions) == 0 &&
		len(policy.Spec.Egress) == 0 {
		return true
	}

	return false
}

func calculateIsolationLevel(hasNetworkPolicies bool, defaultDenyPolicy bool) string {
	if hasNetworkPolicies && defaultDenyPolicy {
		return "Isolated"
	} else if hasNetworkPolicies {
		return "Partial"
	}
	return "None"
}

func analyzePSSEnforcement(ns *corev1.Namespace) (string, string, string, bool) {
	enforce := "none"
	audit := "none"
	warn := "none"

	if ns.Labels != nil {
		if val, ok := ns.Labels["pod-security.kubernetes.io/enforce"]; ok {
			enforce = val
		}
		if val, ok := ns.Labels["pod-security.kubernetes.io/audit"]; ok {
			audit = val
		}
		if val, ok := ns.Labels["pod-security.kubernetes.io/warn"]; ok {
			warn = val
		}
	}

	hasEnforcement := enforce != "none"
	return enforce, audit, warn, hasEnforcement
}

func analyzeWorkloadDistribution(ctx context.Context, clientset *kubernetes.Clientset, namespace string) (
	int, int, int, int, int, int, int, int, int, int, int) {

	podCount := 0
	deploymentCount := 0
	statefulSetCount := 0
	daemonSetCount := 0
	jobCount := 0
	cronJobCount := 0
	secretCount := 0
	configMapCount := 0
	serviceCount := 0
	ingressCount := 0

	// Count pods
	pods, err := clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err == nil {
		podCount = len(pods.Items)
	}

	// Count deployments
	deployments, err := clientset.AppsV1().Deployments(namespace).List(ctx, metav1.ListOptions{})
	if err == nil {
		deploymentCount = len(deployments.Items)
	}

	// Count statefulsets
	statefulSets, err := clientset.AppsV1().StatefulSets(namespace).List(ctx, metav1.ListOptions{})
	if err == nil {
		statefulSetCount = len(statefulSets.Items)
	}

	// Count daemonsets
	daemonSets, err := clientset.AppsV1().DaemonSets(namespace).List(ctx, metav1.ListOptions{})
	if err == nil {
		daemonSetCount = len(daemonSets.Items)
	}

	// Count jobs
	jobs, err := clientset.BatchV1().Jobs(namespace).List(ctx, metav1.ListOptions{})
	if err == nil {
		jobCount = len(jobs.Items)
	}

	// Count cronjobs
	cronJobs, err := clientset.BatchV1().CronJobs(namespace).List(ctx, metav1.ListOptions{})
	if err == nil {
		cronJobCount = len(cronJobs.Items)
	}

	// Count secrets
	secrets, err := clientset.CoreV1().Secrets(namespace).List(ctx, metav1.ListOptions{})
	if err == nil {
		secretCount = len(secrets.Items)
	}

	// Count configmaps
	configMaps, err := clientset.CoreV1().ConfigMaps(namespace).List(ctx, metav1.ListOptions{})
	if err == nil {
		configMapCount = len(configMaps.Items)
	}

	// Count services
	services, err := clientset.CoreV1().Services(namespace).List(ctx, metav1.ListOptions{})
	if err == nil {
		serviceCount = len(services.Items)
	}

	// Count ingresses
	ingresses, err := clientset.NetworkingV1().Ingresses(namespace).List(ctx, metav1.ListOptions{})
	if err == nil {
		ingressCount = len(ingresses.Items)
	}

	totalWorkloads := deploymentCount + statefulSetCount + daemonSetCount + jobCount + cronJobCount

	return podCount, deploymentCount, statefulSetCount, daemonSetCount, jobCount, cronJobCount,
		secretCount, configMapCount, serviceCount, ingressCount, totalWorkloads
}

func analyzeRBAC(ctx context.Context, clientset *kubernetes.Clientset, namespace string) (
	int, int, int, []string, []string, bool) {

	roleBindingCount := 0
	clusterRoleBindingCount := 0
	serviceAccountCount := 0
	var adminBindings []string
	var dangerousBindings []string // RoleBinding/ClusterRoleBinding names with dangerous permissions
	excessiveAccess := false

	// Get Roles in namespace for permission analysis
	roles, _ := clientset.RbacV1().Roles(namespace).List(ctx, metav1.ListOptions{})
	roleMap := make(map[string]*rbacv1.Role)
	if roles != nil {
		for i := range roles.Items {
			roleMap[roles.Items[i].Name] = &roles.Items[i]
		}
	}

	// Get ClusterRoles for permission analysis
	clusterRoles, _ := clientset.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	clusterRoleMap := make(map[string]*rbacv1.ClusterRole)
	if clusterRoles != nil {
		for i := range clusterRoles.Items {
			clusterRoleMap[clusterRoles.Items[i].Name] = &clusterRoles.Items[i]
		}
	}

	// Count RoleBindings and check for dangerous permissions
	roleBindings, err := clientset.RbacV1().RoleBindings(namespace).List(ctx, metav1.ListOptions{})
	if err == nil {
		roleBindingCount = len(roleBindings.Items)

		for _, rb := range roleBindings.Items {
			// Check for admin/cluster-admin roles
			if rb.RoleRef.Name == "admin" || rb.RoleRef.Name == "cluster-admin" {
				adminBindings = append(adminBindings, rb.Name)
				excessiveAccess = true
			}

			// Check if the referenced role has dangerous permissions
			if rb.RoleRef.Kind == "Role" {
				if role, exists := roleMap[rb.RoleRef.Name]; exists {
					if hasDangerousPermissions(role.Rules) {
						dangerousBindings = append(dangerousBindings, rb.Name)
					}
				}
			} else if rb.RoleRef.Kind == "ClusterRole" {
				// RoleBinding can reference a ClusterRole
				if clusterRole, exists := clusterRoleMap[rb.RoleRef.Name]; exists {
					if hasDangerousPermissions(clusterRole.Rules) {
						dangerousBindings = append(dangerousBindings, rb.Name)
					}
				}
			}
		}
	}

	// Check ClusterRoleBindings targeting this namespace's ServiceAccounts
	clusterRoleBindings, err := clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, crb := range clusterRoleBindings.Items {
			for _, subject := range crb.Subjects {
				if subject.Namespace == namespace && subject.Kind == "ServiceAccount" {
					clusterRoleBindingCount++

					// Check for admin/cluster-admin roles
					if crb.RoleRef.Name == "cluster-admin" || crb.RoleRef.Name == "admin" {
						adminBindings = append(adminBindings, crb.Name)
						excessiveAccess = true
					}

					// Check if the referenced ClusterRole has dangerous permissions
					if clusterRole, exists := clusterRoleMap[crb.RoleRef.Name]; exists {
						if hasDangerousPermissions(clusterRole.Rules) {
							dangerousBindings = append(dangerousBindings, crb.Name)
						}
					}
					break
				}
			}
		}
	}

	// Count ServiceAccounts
	serviceAccounts, err := clientset.CoreV1().ServiceAccounts(namespace).List(ctx, metav1.ListOptions{})
	if err == nil {
		serviceAccountCount = len(serviceAccounts.Items)
	}

	return roleBindingCount, clusterRoleBindingCount, serviceAccountCount, adminBindings, dangerousBindings, excessiveAccess
}

func hasDangerousPermissions(rules []rbacv1.PolicyRule) bool {
	dangerousVerbs := []string{"*", "create", "update", "patch", "delete"}
	dangerousResources := []string{"*", "secrets", "pods/exec", "pods/portforward"}

	for _, rule := range rules {
		for _, resource := range rule.Resources {
			for _, verb := range rule.Verbs {
				// Wildcard on both
				if resource == "*" && verb == "*" {
					return true
				}
				// Dangerous resource with dangerous verb
				for _, dangerousRes := range dangerousResources {
					if resource == dangerousRes {
						for _, dangerousVerb := range dangerousVerbs {
							if verb == dangerousVerb {
								return true
							}
						}
					}
				}
			}
		}
	}

	return false
}

func analyzeNamespaceSecurity(finding NamespaceFinding) []string {
	var issues []string

	// CRITICAL issues
	if finding.IsDefault && finding.TotalWorkloads > 0 {
		issues = append(issues, "CRITICAL: Workloads running in default namespace")
	}
	if finding.IsProduction && !finding.HasNetworkPolicies {
		issues = append(issues, "Production namespace without network isolation")
	}
	if finding.ExcessiveAccess && finding.IsProduction {
		issues = append(issues, "Excessive RBAC permissions in production")
	}

	// HIGH issues
	if !finding.HasResourceQuota && finding.TotalWorkloads > 10 {
		issues = append(issues, "No ResourceQuota with many workloads (DoS risk)")
	}
	if !finding.HasNetworkPolicies && finding.TotalWorkloads > 0 {
		issues = append(issues, "No NetworkPolicies (lateral movement risk)")
	}
	if len(finding.AdminBindings) > 0 {
		issues = append(issues, fmt.Sprintf("Admin role bindings: %d", len(finding.AdminBindings)))
	}
	if finding.PSSEnforce == "privileged" && finding.IsProduction {
		issues = append(issues, "Permissive PSS (privileged) in production")
	}

	// MEDIUM issues
	if !finding.HasLimitRange && finding.TotalWorkloads > 0 {
		issues = append(issues, "No LimitRange (resource abuse risk)")
	}
	if !finding.HasPSSEnforcement {
		issues = append(issues, "No Pod Security Standards enforcement")
	}
	if finding.SecretCount > 20 {
		issues = append(issues, fmt.Sprintf("High secret count: %d", finding.SecretCount))
	}
	if !finding.HasNetworkPolicies && finding.IsSensitive {
		issues = append(issues, "Sensitive namespace without network isolation")
	}
	if !finding.DefaultDenyPolicy && finding.HasNetworkPolicies {
		issues = append(issues, "No default-deny network policy")
	}

	// LOW issues
	if finding.Environment == "" && finding.TotalWorkloads > 0 {
		issues = append(issues, "No environment classification label")
	}
	if len(finding.DangerousPermissions) > 0 {
		issues = append(issues, fmt.Sprintf("Dangerous RBAC permissions: %d", len(finding.DangerousPermissions)))
	}
	if finding.IsEmpty && finding.AgeInDays > 30 {
		issues = append(issues, "Appears abandoned (empty + old)")
	}

	return issues
}

func calculateNamespaceRiskLevel(finding NamespaceFinding) string {
	riskScore := 0

	// CRITICAL FACTORS (50+ points)
	if finding.IsDefault && finding.TotalWorkloads > 0 {
		riskScore += 100 // Workloads in default namespace
	}
	if finding.IsProduction && !finding.HasNetworkPolicies {
		riskScore += 70 // Production without network isolation
	}
	if finding.ExcessiveAccess && finding.IsProduction {
		riskScore += 60 // Admin access in production
	}
	if !finding.HasResourceQuota && finding.TotalWorkloads > 10 {
		riskScore += 50 // DoS risk with many workloads
	}

	// HIGH FACTORS (25-40 points)
	if len(finding.AdminBindings) > 0 {
		riskScore += 40 // cluster-admin/admin bindings
	}
	if !finding.HasNetworkPolicies && finding.TotalWorkloads > 0 {
		riskScore += 30 // No network isolation
	}
	if !finding.HasResourceQuota {
		riskScore += 25 // Missing resource quota
	}
	if finding.PSSEnforce == "privileged" && finding.IsProduction {
		riskScore += 25 // Permissive PSS in production
	}

	// MEDIUM FACTORS (10-20 points)
	if !finding.HasLimitRange && finding.TotalWorkloads > 0 {
		riskScore += 15 // Missing limit ranges
	}
	if !finding.HasPSSEnforcement {
		riskScore += 15 // No PSS enforcement
	}
	if finding.SecretCount > 20 {
		riskScore += 10 // High secret count
	}
	if !finding.HasNetworkPolicies && finding.IsSensitive {
		riskScore += 10 // Sensitive namespace not isolated
	}

	// LOW FACTORS (1-5 points)
	if finding.Environment == "" && finding.TotalWorkloads > 0 {
		riskScore += 5 // No environment label
	}
	if len(finding.DangerousPermissions) > 0 {
		riskScore += 3
	}

	// Determine risk level
	if riskScore >= 50 {
		return shared.RiskCritical
	} else if riskScore >= 25 {
		return shared.RiskHigh
	} else if riskScore >= 10 {
		return shared.RiskMedium
	}
	return shared.RiskLow
}

// ====================
// Loot File Builder
// ====================

func buildNamespaceCommandsLoot(loot *shared.LootBuilder, findings []NamespaceFinding) {
	section := loot.Section("Namespace-Commands")

	// ResourceQuota Template
	section.AddBlank().
		Add("# -------------------------------------------").
		Add("# ResourceQuota Template").
		Add("# -------------------------------------------").
		Add("# Apply to namespaces missing resource quotas:").
		AddBlank().
		Add("kubectl apply -f - <<EOF").
		Add("apiVersion: v1").
		Add("kind: ResourceQuota").
		Add("metadata:").
		Add("  name: compute-quota").
		Add("  namespace: <namespace-name>").
		Add("spec:").
		Add("  hard:").
		Add("    requests.cpu: \"10\"").
		Add("    requests.memory: 20Gi").
		Add("    limits.cpu: \"20\"").
		Add("    limits.memory: 40Gi").
		Add("    pods: \"50\"").
		Add("EOF")

	// LimitRange Template
	section.AddBlank().
		Add("# -------------------------------------------").
		Add("# LimitRange Template").
		Add("# -------------------------------------------").
		Add("# Apply to namespaces missing limit ranges:").
		AddBlank().
		Add("kubectl apply -f - <<EOF").
		Add("apiVersion: v1").
		Add("kind: LimitRange").
		Add("metadata:").
		Add("  name: default-limits").
		Add("  namespace: <namespace-name>").
		Add("spec:").
		Add("  limits:").
		Add("  - default:").
		Add("      cpu: \"500m\"").
		Add("      memory: \"512Mi\"").
		Add("    defaultRequest:").
		Add("      cpu: \"100m\"").
		Add("      memory: \"128Mi\"").
		Add("    type: Container").
		Add("EOF")

	// NetworkPolicy Default-Deny Template
	section.AddBlank().
		Add("# -------------------------------------------").
		Add("# NetworkPolicy Default-Deny Template").
		Add("# -------------------------------------------").
		Add("# Apply to namespaces missing network policies:").
		AddBlank().
		Add("kubectl apply -f - <<EOF").
		Add("apiVersion: networking.k8s.io/v1").
		Add("kind: NetworkPolicy").
		Add("metadata:").
		Add("  name: default-deny-ingress").
		Add("  namespace: <namespace-name>").
		Add("spec:").
		Add("  podSelector: {}").
		Add("  policyTypes:").
		Add("  - Ingress").
		Add("EOF")

	// PSS Labeling Commands
	section.AddBlank().
		Add("# -------------------------------------------").
		Add("# Pod Security Standards (PSS) Labeling").
		Add("# -------------------------------------------").
		AddBlank().
		Add("# For production namespaces (restricted):").
		Add("kubectl label namespace <namespace> \\").
		Add("  pod-security.kubernetes.io/enforce=restricted \\").
		Add("  pod-security.kubernetes.io/audit=restricted \\").
		Add("  pod-security.kubernetes.io/warn=restricted").
		AddBlank().
		Add("# For non-production namespaces (baseline):").
		Add("kubectl label namespace <namespace> \\").
		Add("  pod-security.kubernetes.io/enforce=baseline \\").
		Add("  pod-security.kubernetes.io/audit=baseline \\").
		Add("  pod-security.kubernetes.io/warn=baseline")

	// Namespace-specific remediation for default namespace
	for _, f := range findings {
		if f.IsDefault && f.TotalWorkloads > 0 {
			section.AddBlank().
				Add("# -------------------------------------------").
				Add("# Default Namespace Migration").
				Add("# -------------------------------------------").
				Addf("# WARNING: %d workloads running in default namespace", f.TotalWorkloads).
				AddBlank().
				Add("# 1. Create dedicated namespace:").
				Add("kubectl create namespace <app-name>").
				AddBlank().
				Add("# 2. Move deployments:").
				Add("kubectl get deployment -n default -o yaml | sed 's/namespace: default/namespace: <app-name>/' | kubectl apply -f -").
				AddBlank().
				Add("# 3. Move services:").
				Add("kubectl get service -n default -o yaml | sed 's/namespace: default/namespace: <app-name>/' | kubectl apply -f -").
				AddBlank().
				Add("# 4. Delete from default after verification:").
				Add("kubectl delete deployment <name> -n default")
			break
		}
	}
}
