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

	// Cloud
	CloudProvider string
}

func ListNamespaces(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating namespaces for %s", globals.ClusterName), globals.K8S_NAMESPACES_MODULE_NAME)

	clientset := config.GetClientOrExit()

	namespaces, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing namespaces: %v", err), globals.K8S_NAMESPACES_MODULE_NAME)
		return
	}

	headers := []string{
		"Risk",
		"Namespace",
		"Environment",
		"Age",
		"Security Issues",
		"Workloads",
		"Pods",
		"Secrets",
		"PSS Enforce",
		"Net Policies",
		"Resource Quota",
		"Limit Range",
		"RBAC Bindings",
		"Dangerous Perms",
		"Isolation",
		"Is Default",
		"Is Production",
		"Cloud Provider",
	}

	var outputRows [][]string
	var findings []NamespaceFinding

	// Risk level counters
	riskCounts := map[string]int{
		"CRITICAL": 0,
		"HIGH":     0,
		"MEDIUM":   0,
		"LOW":      0,
	}

	// Loot file builders
	var lootEnum []string
	var lootRiskDashboard []string
	var lootDefaultUsage []string
	var lootResourceGov []string
	var lootNetworkIsolation []string
	var lootPSSEnforcement []string
	var lootRBACAnalysis []string
	var lootWorkloadDist []string

	lootEnum = append(lootEnum, `#####################################
##### Namespace Enumeration
#####################################
#
# Basic namespace enumeration commands
#
`)

	if globals.KubeContext != "" {
		lootEnum = append(lootEnum, fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext))
	}

	for _, ns := range namespaces.Items {
		finding := analyzeNamespace(ctx, clientset, &ns)
		findings = append(findings, finding)
		riskCounts[finding.RiskLevel]++

		// Build table row
		securityIssuesStr := "<none>"
		if len(finding.SecurityIssues) > 0 {
			if len(finding.SecurityIssues) > 2 {
				securityIssuesStr = strings.Join(finding.SecurityIssues[:2], "; ") + fmt.Sprintf(" (+%d more)", len(finding.SecurityIssues)-2)
			} else {
				securityIssuesStr = strings.Join(finding.SecurityIssues, "; ")
			}
		}

		netPoliciesStr := "0"
		if finding.NetworkPolicyCount > 0 {
			netPoliciesStr = fmt.Sprintf("%d", finding.NetworkPolicyCount)
		}

		resourceQuotaStr := "Missing"
		if finding.HasResourceQuota {
			resourceQuotaStr = fmt.Sprintf("Set (%d)", len(finding.ResourceQuotas))
		}

		limitRangeStr := "Missing"
		if finding.HasLimitRange {
			limitRangeStr = fmt.Sprintf("Set (%d)", len(finding.LimitRanges))
		}

		rbacBindingsStr := fmt.Sprintf("%d", finding.RoleBindingCount)
		if finding.ClusterRoleBindingCount > 0 {
			rbacBindingsStr = fmt.Sprintf("%d+%dCRB", finding.RoleBindingCount, finding.ClusterRoleBindingCount)
		}

		dangerousPermsStr := "No"
		if len(finding.DangerousPermissions) > 0 {
			dangerousPermsStr = fmt.Sprintf("Yes (%d)", len(finding.DangerousPermissions))
		}

		isDefaultStr := "No"
		if finding.IsDefault {
			isDefaultStr = "Yes"
		}

		isProdStr := "No"
		if finding.IsProduction {
			isProdStr = "Yes"
		}

		outputRows = append(outputRows, []string{
			finding.RiskLevel,
			finding.Name,
			k8sinternal.NonEmpty(finding.Environment),
			finding.Age,
			securityIssuesStr,
			fmt.Sprintf("%d", finding.TotalWorkloads),
			fmt.Sprintf("%d", finding.PodCount),
			fmt.Sprintf("%d", finding.SecretCount),
			k8sinternal.NonEmpty(finding.PSSEnforce),
			netPoliciesStr,
			resourceQuotaStr,
			limitRangeStr,
			rbacBindingsStr,
			dangerousPermsStr,
			finding.IsolationLevel,
			isDefaultStr,
			isProdStr,
			k8sinternal.NonEmpty(finding.CloudProvider),
		})

		// Generate enumeration commands
		lootEnum = append(lootEnum, fmt.Sprintf("\n# [%s] %s (Environment: %s)", finding.RiskLevel, finding.Name, finding.Environment))
		lootEnum = append(lootEnum, fmt.Sprintf("kubectl get namespace %s -o yaml", finding.Name))
		lootEnum = append(lootEnum, fmt.Sprintf("kubectl describe namespace %s", finding.Name))
		lootEnum = append(lootEnum, "")
	}

	// Build Risk Dashboard loot file
	lootRiskDashboard = buildRiskDashboard(findings, riskCounts)

	// Build Default Usage loot file
	lootDefaultUsage = buildDefaultUsageLoot(findings)

	// Build Resource Governance loot file
	lootResourceGov = buildResourceGovernanceLoot(findings)

	// Build Network Isolation loot file
	lootNetworkIsolation = buildNetworkIsolationLoot(findings)

	// Build PSS Enforcement loot file
	lootPSSEnforcement = buildPSSEnforcementLoot(findings)

	// Build RBAC Analysis loot file
	lootRBACAnalysis = buildRBACAnalysisLoot(findings)

	// Build Workload Distribution loot file
	lootWorkloadDist = buildWorkloadDistributionLoot(findings)

	table := internal.TableFile{
		Name:   "Namespaces",
		Header: headers,
		Body:   outputRows,
	}

	lootFiles := []internal.LootFile{
		{Name: "Namespace-Risk-Dashboard", Contents: strings.Join(lootRiskDashboard, "\n")},
		{Name: "Namespace-Enum", Contents: strings.Join(lootEnum, "\n")},
		{Name: "Namespace-Default-Usage", Contents: strings.Join(lootDefaultUsage, "\n")},
		{Name: "Namespace-Resource-Governance", Contents: strings.Join(lootResourceGov, "\n")},
		{Name: "Namespace-Network-Isolation", Contents: strings.Join(lootNetworkIsolation, "\n")},
		{Name: "Namespace-PSS-Enforcement", Contents: strings.Join(lootPSSEnforcement, "\n")},
		{Name: "Namespace-RBAC-Analysis", Contents: strings.Join(lootRBACAnalysis, "\n")},
		{Name: "Namespace-Workload-Distribution", Contents: strings.Join(lootWorkloadDist, "\n")},
	}

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
			riskCounts["CRITICAL"], riskCounts["HIGH"], riskCounts["MEDIUM"], riskCounts["LOW"]),
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

	// Cloud provider detection
	finding.CloudProvider = k8sinternal.DetectCloudProvider(ns.Labels, ns.Annotations)

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
		if isDefaultDenyPolicy(&policy) {
			hasDefaultDeny = true
		}
	}

	return true, len(policies.Items), policyNames, hasDefaultDeny
}

func isDefaultDenyPolicy(policy *networkingv1.NetworkPolicy) bool {
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
	var dangerousPermissions []string
	excessiveAccess := false

	// Count RoleBindings
	roleBindings, err := clientset.RbacV1().RoleBindings(namespace).List(ctx, metav1.ListOptions{})
	if err == nil {
		roleBindingCount = len(roleBindings.Items)

		for _, rb := range roleBindings.Items {
			// Check for admin/cluster-admin roles
			if rb.RoleRef.Name == "admin" || rb.RoleRef.Name == "cluster-admin" {
				adminBindings = append(adminBindings, fmt.Sprintf("%s->%s", rb.Name, rb.RoleRef.Name))
				excessiveAccess = true
			}
		}
	}

	// Count ClusterRoleBindings targeting this namespace's ServiceAccounts
	clusterRoleBindings, err := clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, crb := range clusterRoleBindings.Items {
			for _, subject := range crb.Subjects {
				if subject.Namespace == namespace && subject.Kind == "ServiceAccount" {
					clusterRoleBindingCount++
					if crb.RoleRef.Name == "cluster-admin" {
						adminBindings = append(adminBindings, fmt.Sprintf("%s->%s", crb.Name, crb.RoleRef.Name))
						excessiveAccess = true
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

	// Analyze roles for dangerous permissions
	roles, err := clientset.RbacV1().Roles(namespace).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, role := range roles.Items {
			dangerous := analyzeDangerousRolePermissions(&role)
			dangerousPermissions = append(dangerousPermissions, dangerous...)
		}
	}

	return roleBindingCount, clusterRoleBindingCount, serviceAccountCount, adminBindings, dangerousPermissions, excessiveAccess
}

func analyzeDangerousRolePermissions(role *rbacv1.Role) []string {
	var dangerous []string
	dangerousVerbs := []string{"*", "create", "update", "patch", "delete"}
	dangerousResources := []string{"*", "secrets", "pods/exec", "pods/portforward"}

	for _, rule := range role.Rules {
		// Check for wildcard permissions
		for _, resource := range rule.Resources {
			for _, verb := range rule.Verbs {
				if resource == "*" && verb == "*" {
					dangerous = append(dangerous, fmt.Sprintf("%s: wildcard (*/*)", role.Name))
					break
				}
			}
		}

		// Check for dangerous resource access
		for _, resource := range rule.Resources {
			for _, dangerousRes := range dangerousResources {
				if resource == dangerousRes {
					for _, verb := range rule.Verbs {
						for _, dangerousVerb := range dangerousVerbs {
							if verb == dangerousVerb {
								dangerous = append(dangerous, fmt.Sprintf("%s: %s on %s", role.Name, verb, resource))
								break
							}
						}
					}
				}
			}
		}
	}

	return dangerous
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
		return "CRITICAL"
	} else if riskScore >= 25 {
		return "HIGH"
	} else if riskScore >= 10 {
		return "MEDIUM"
	}
	return "LOW"
}

// ====================
// Loot File Builders
// ====================

func buildRiskDashboard(findings []NamespaceFinding, riskCounts map[string]int) []string {
	var lines []string
	lines = append(lines, `#####################################
##### Namespace Risk Statistics Dashboard
#####################################
#
# Summary of namespace security posture
#
`)

	totalNamespaces := len(findings)
	lines = append(lines, "\n## Overall Statistics")
	lines = append(lines, fmt.Sprintf("Total Namespaces: %d", totalNamespaces))
	lines = append(lines, fmt.Sprintf("CRITICAL Risk: %d", riskCounts["CRITICAL"]))
	lines = append(lines, fmt.Sprintf("HIGH Risk:     %d", riskCounts["HIGH"]))
	lines = append(lines, fmt.Sprintf("MEDIUM Risk:   %d", riskCounts["MEDIUM"]))
	lines = append(lines, fmt.Sprintf("LOW Risk:      %d", riskCounts["LOW"]))

	// Count various security metrics
	defaultNSWithWorkloads := 0
	productionCount := 0
	noNetPolicies := 0
	noResourceQuotas := 0
	noLimitRanges := 0
	noPSSEnforcement := 0
	excessiveAccess := 0
	emptyNamespaces := 0

	for _, f := range findings {
		if f.IsDefault && f.TotalWorkloads > 0 {
			defaultNSWithWorkloads++
		}
		if f.IsProduction {
			productionCount++
		}
		if !f.HasNetworkPolicies && f.TotalWorkloads > 0 {
			noNetPolicies++
		}
		if !f.HasResourceQuota {
			noResourceQuotas++
		}
		if !f.HasLimitRange {
			noLimitRanges++
		}
		if !f.HasPSSEnforcement {
			noPSSEnforcement++
		}
		if f.ExcessiveAccess {
			excessiveAccess++
		}
		if f.IsEmpty {
			emptyNamespaces++
		}
	}

	lines = append(lines, "\n## Security Posture")
	lines = append(lines, fmt.Sprintf("Production Namespaces: %d", productionCount))
	lines = append(lines, fmt.Sprintf("Default NS with Workloads: %d", defaultNSWithWorkloads))
	lines = append(lines, fmt.Sprintf("No Network Policies: %d", noNetPolicies))
	lines = append(lines, fmt.Sprintf("No Resource Quotas: %d", noResourceQuotas))
	lines = append(lines, fmt.Sprintf("No Limit Ranges: %d", noLimitRanges))
	lines = append(lines, fmt.Sprintf("No PSS Enforcement: %d", noPSSEnforcement))
	lines = append(lines, fmt.Sprintf("Excessive RBAC Access: %d", excessiveAccess))
	lines = append(lines, fmt.Sprintf("Empty/Abandoned: %d", emptyNamespaces))

	lines = append(lines, "\n## Recommendations")
	if riskCounts["CRITICAL"] > 0 {
		lines = append(lines, fmt.Sprintf("⚠️  URGENT: %d CRITICAL namespaces require immediate remediation", riskCounts["CRITICAL"]))
	}
	if defaultNSWithWorkloads > 0 {
		lines = append(lines, "⚠️  WARNING: Workloads running in default namespace (migrate immediately)")
	}
	if noNetPolicies > 0 {
		lines = append(lines, fmt.Sprintf("⚠️  WARNING: %d namespaces lack network isolation", noNetPolicies))
	}
	if noResourceQuotas > productionCount {
		lines = append(lines, fmt.Sprintf("⚠️  WARNING: %d namespaces missing ResourceQuotas (DoS risk)", noResourceQuotas))
	}

	return lines
}

func buildDefaultUsageLoot(findings []NamespaceFinding) []string {
	var lines []string
	lines = append(lines, `#####################################
##### Default Namespace Usage Analysis
#####################################
#
# Workloads in default namespace (anti-pattern)
#
`)

	hasDefaultUsage := false
	for _, f := range findings {
		if f.IsDefault && f.TotalWorkloads > 0 {
			hasDefaultUsage = true
			lines = append(lines, fmt.Sprintf("\n## Default Namespace: %d total workloads", f.TotalWorkloads))
			lines = append(lines, fmt.Sprintf("Deployments: %d", f.DeploymentCount))
			lines = append(lines, fmt.Sprintf("StatefulSets: %d", f.StatefulSetCount))
			lines = append(lines, fmt.Sprintf("DaemonSets: %d", f.DaemonSetCount))
			lines = append(lines, fmt.Sprintf("Jobs: %d", f.JobCount))
			lines = append(lines, fmt.Sprintf("CronJobs: %d", f.CronJobCount))
			lines = append(lines, fmt.Sprintf("Pods: %d", f.PodCount))

			lines = append(lines, "\n### Migration Recommendation")
			lines = append(lines, "# 1. Create dedicated namespaces per application/team:")
			lines = append(lines, "kubectl create namespace app-name")
			lines = append(lines, "")
			lines = append(lines, "# 2. Update deployments to use new namespace:")
			lines = append(lines, "kubectl get deployment -n default -o yaml | sed 's/namespace: default/namespace: app-name/' | kubectl apply -f -")
			lines = append(lines, "")
			lines = append(lines, "# 3. Move services:")
			lines = append(lines, "kubectl get service -n default -o yaml | sed 's/namespace: default/namespace: app-name/' | kubectl apply -f -")
			lines = append(lines, "")
			lines = append(lines, "# 4. Delete from default after verification:")
			lines = append(lines, "kubectl delete deployment <name> -n default")
		}
	}

	if !hasDefaultUsage {
		lines = append(lines, "\n✓ No workloads in default namespace (good practice)")
	}

	return lines
}

func buildResourceGovernanceLoot(findings []NamespaceFinding) []string {
	var lines []string
	lines = append(lines, `#####################################
##### Resource Governance Analysis
#####################################
#
# ResourceQuota and LimitRange status
#
`)

	lines = append(lines, "\n## Namespaces Missing ResourceQuotas")
	missingQuotas := 0
	for _, f := range findings {
		if !f.HasResourceQuota && f.TotalWorkloads > 0 {
			missingQuotas++
			lines = append(lines, fmt.Sprintf("- [%s] %s (Workloads: %d)", f.RiskLevel, f.Name, f.TotalWorkloads))
		}
	}
	if missingQuotas == 0 {
		lines = append(lines, "✓ All active namespaces have ResourceQuotas")
	}

	lines = append(lines, "\n## Namespaces Missing LimitRanges")
	missingLimits := 0
	for _, f := range findings {
		if !f.HasLimitRange && f.TotalWorkloads > 0 {
			missingLimits++
			lines = append(lines, fmt.Sprintf("- [%s] %s (Workloads: %d)", f.RiskLevel, f.Name, f.TotalWorkloads))
		}
	}
	if missingLimits == 0 {
		lines = append(lines, "✓ All active namespaces have LimitRanges")
	}

	lines = append(lines, "\n## Sample ResourceQuota Configuration")
	lines = append(lines, "# Apply this to each namespace:")
	lines = append(lines, "kubectl apply -f - <<EOF")
	lines = append(lines, "apiVersion: v1")
	lines = append(lines, "kind: ResourceQuota")
	lines = append(lines, "metadata:")
	lines = append(lines, "  name: compute-quota")
	lines = append(lines, "  namespace: <namespace-name>")
	lines = append(lines, "spec:")
	lines = append(lines, "  hard:")
	lines = append(lines, "    requests.cpu: \"10\"")
	lines = append(lines, "    requests.memory: 20Gi")
	lines = append(lines, "    limits.cpu: \"20\"")
	lines = append(lines, "    limits.memory: 40Gi")
	lines = append(lines, "    pods: \"50\"")
	lines = append(lines, "EOF")

	return lines
}

func buildNetworkIsolationLoot(findings []NamespaceFinding) []string {
	var lines []string
	lines = append(lines, `#####################################
##### Network Isolation Analysis
#####################################
#
# NetworkPolicy enforcement status
#
`)

	lines = append(lines, "\n## Namespaces Without Network Policies")
	noIsolation := 0
	for _, f := range findings {
		if !f.HasNetworkPolicies && f.TotalWorkloads > 0 {
			noIsolation++
			lines = append(lines, fmt.Sprintf("- [%s] %s (Environment: %s, Workloads: %d)", f.RiskLevel, f.Name, f.Environment, f.TotalWorkloads))
		}
	}
	if noIsolation == 0 {
		lines = append(lines, "✓ All active namespaces have NetworkPolicies")
	}

	lines = append(lines, "\n## Namespaces Without Default-Deny Policy")
	noDefaultDeny := 0
	for _, f := range findings {
		if f.HasNetworkPolicies && !f.DefaultDenyPolicy && f.TotalWorkloads > 0 {
			noDefaultDeny++
			lines = append(lines, fmt.Sprintf("- [%s] %s", f.RiskLevel, f.Name))
		}
	}
	if noDefaultDeny == 0 {
		lines = append(lines, "✓ All isolated namespaces have default-deny policies")
	}

	lines = append(lines, "\n## Default-Deny NetworkPolicy Template")
	lines = append(lines, "# Apply to each namespace for default-deny ingress:")
	lines = append(lines, "kubectl apply -f - <<EOF")
	lines = append(lines, "apiVersion: networking.k8s.io/v1")
	lines = append(lines, "kind: NetworkPolicy")
	lines = append(lines, "metadata:")
	lines = append(lines, "  name: default-deny-ingress")
	lines = append(lines, "  namespace: <namespace-name>")
	lines = append(lines, "spec:")
	lines = append(lines, "  podSelector: {}")
	lines = append(lines, "  policyTypes:")
	lines = append(lines, "  - Ingress")
	lines = append(lines, "EOF")

	return lines
}

func buildPSSEnforcementLoot(findings []NamespaceFinding) []string {
	var lines []string
	lines = append(lines, `#####################################
##### Pod Security Standards Enforcement
#####################################
#
# PSS label analysis per namespace
#
`)

	lines = append(lines, "\n## PSS Enforcement Status")
	for _, f := range findings {
		if f.TotalWorkloads > 0 {
			lines = append(lines, fmt.Sprintf("\n### [%s] %s", f.RiskLevel, f.Name))
			lines = append(lines, fmt.Sprintf("Enforce: %s", f.PSSEnforce))
			lines = append(lines, fmt.Sprintf("Audit:   %s", f.PSSAudit))
			lines = append(lines, fmt.Sprintf("Warn:    %s", f.PSSWarn))

			if !f.HasPSSEnforcement {
				lines = append(lines, "⚠️  No PSS enforcement configured")
			} else if f.PSSEnforce == "privileged" && f.IsProduction {
				lines = append(lines, "⚠️  Production namespace with permissive PSS (should be 'restricted')")
			}
		}
	}

	lines = append(lines, "\n## Recommended PSS Configuration")
	lines = append(lines, "# For production namespaces (restrictive):")
	lines = append(lines, "kubectl label namespace <namespace> \\")
	lines = append(lines, "  pod-security.kubernetes.io/enforce=restricted \\")
	lines = append(lines, "  pod-security.kubernetes.io/audit=restricted \\")
	lines = append(lines, "  pod-security.kubernetes.io/warn=restricted")
	lines = append(lines, "")
	lines = append(lines, "# For non-production (baseline):")
	lines = append(lines, "kubectl label namespace <namespace> \\")
	lines = append(lines, "  pod-security.kubernetes.io/enforce=baseline \\")
	lines = append(lines, "  pod-security.kubernetes.io/audit=baseline \\")
	lines = append(lines, "  pod-security.kubernetes.io/warn=baseline")

	return lines
}

func buildRBACAnalysisLoot(findings []NamespaceFinding) []string {
	var lines []string
	lines = append(lines, `#####################################
##### RBAC Permissions Analysis
#####################################
#
# RoleBinding and dangerous permissions
#
`)

	lines = append(lines, "\n## Namespaces with Admin Bindings")
	hasAdmin := false
	for _, f := range findings {
		if len(f.AdminBindings) > 0 {
			hasAdmin = true
			lines = append(lines, fmt.Sprintf("\n### [%s] %s", f.RiskLevel, f.Name))
			lines = append(lines, fmt.Sprintf("Admin Bindings: %d", len(f.AdminBindings)))
			for _, binding := range f.AdminBindings {
				lines = append(lines, fmt.Sprintf("  - %s", binding))
			}
		}
	}
	if !hasAdmin {
		lines = append(lines, "✓ No cluster-admin or admin role bindings found")
	}

	lines = append(lines, "\n## Dangerous Permissions Detected")
	hasDangerous := false
	for _, f := range findings {
		if len(f.DangerousPermissions) > 0 {
			hasDangerous = true
			lines = append(lines, fmt.Sprintf("\n### [%s] %s", f.RiskLevel, f.Name))
			for _, perm := range f.DangerousPermissions {
				lines = append(lines, fmt.Sprintf("  - %s", perm))
			}
		}
	}
	if !hasDangerous {
		lines = append(lines, "✓ No dangerous permissions detected")
	}

	lines = append(lines, "\n## RBAC Best Practices")
	lines = append(lines, "1. Use least privilege principle")
	lines = append(lines, "2. Avoid cluster-admin role bindings")
	lines = append(lines, "3. Prefer Role/RoleBinding over ClusterRole/ClusterRoleBinding")
	lines = append(lines, "4. Review permissions regularly")
	lines = append(lines, "5. Use specific verbs instead of wildcards")

	return lines
}

func buildWorkloadDistributionLoot(findings []NamespaceFinding) []string {
	var lines []string
	lines = append(lines, `#####################################
##### Workload Distribution Analysis
#####################################
#
# Resource counts per namespace
#
`)

	// Sort findings by total workloads
	sortedFindings := make([]NamespaceFinding, len(findings))
	copy(sortedFindings, findings)
	sort.Slice(sortedFindings, func(i, j int) bool {
		return sortedFindings[i].TotalWorkloads > sortedFindings[j].TotalWorkloads
	})

	lines = append(lines, "\n## Workload Distribution")
	lines = append(lines, fmt.Sprintf("%-30s %10s %8s %8s %8s", "Namespace", "Workloads", "Pods", "Secrets", "Services"))
	lines = append(lines, strings.Repeat("-", 70))

	for _, f := range sortedFindings {
		if f.TotalWorkloads > 0 {
			lines = append(lines, fmt.Sprintf("%-30s %10d %8d %8d %8d",
				f.Name, f.TotalWorkloads, f.PodCount, f.SecretCount, f.ServiceCount))
		}
	}

	lines = append(lines, "\n## Empty/Abandoned Namespaces")
	emptyCount := 0
	for _, f := range findings {
		if f.IsEmpty {
			emptyCount++
			lines = append(lines, fmt.Sprintf("- %s (Age: %s)", f.Name, f.Age))
		}
	}
	if emptyCount == 0 {
		lines = append(lines, "✓ No empty namespaces found")
	}

	lines = append(lines, "\n## Overpopulated Namespaces (>50 workloads)")
	overpopulated := false
	for _, f := range sortedFindings {
		if f.TotalWorkloads > 50 {
			overpopulated = true
			lines = append(lines, fmt.Sprintf("- [%s] %s (%d workloads) - Consider splitting", f.RiskLevel, f.Name, f.TotalWorkloads))
		}
	}
	if !overpopulated {
		lines = append(lines, "✓ No overpopulated namespaces")
	}

	return lines
}
