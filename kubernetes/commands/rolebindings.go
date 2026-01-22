package commands

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	k8sinternal "github.com/BishopFox/cloudfox/internal/kubernetes"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/BishopFox/cloudfox/kubernetes/shared"
	"github.com/spf13/cobra"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

var RoleBindingsCmd = &cobra.Command{
	Use:     "rolebindings",
	Aliases: []string{"rb", "bindings"},
	Short:   "Enumerate RoleBindings and ClusterRoleBindings",
	Long: `Enumerate all RoleBindings and ClusterRoleBindings in the cluster.

This module provides a binding-centric view of RBAC configuration, showing:
- What roles are bound to which subjects
- The scope of each binding (namespace vs cluster)
- Dangerous permissions granted through bindings
- Bindings to admin/cluster-admin roles

This complements the permissions module which shows individual verb/resource pairs.

Usage:
  cloudfox kubernetes rolebindings`,
	Run: runRoleBindingsCommand,
}

type RoleBindingsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o RoleBindingsOutput) TableFiles() []internal.TableFile { return o.Table }
func (o RoleBindingsOutput) LootFiles() []internal.LootFile   { return o.Loot }

// RoleBindingFinding represents a single role binding
type RoleBindingFinding struct {
	// Basic info
	Name      string
	Namespace string
	Type      string // "RoleBinding" or "ClusterRoleBinding"
	Age       string
	AgeInDays int

	// Role reference
	RoleRefKind string // "Role" or "ClusterRole"
	RoleRefName string

	// Subjects
	Subjects     []SubjectInfo
	SubjectCount int

	// Analysis
	IsAdminBinding       bool
	IsClusterAdminBinding bool
	DangerousPermissions []string
	BindsToDefaultSA     bool
	BindsToAllSAs        bool
	OrphanedBinding      bool // Role doesn't exist
}

// SubjectInfo represents a subject in a binding
type SubjectInfo struct {
	Kind      string // User, Group, ServiceAccount
	Name      string
	Namespace string // Only for ServiceAccount
}

func runRoleBindingsCommand(cmd *cobra.Command, args []string) {
	ctx, cancel := shared.ContextWithTimeout()
	defer cancel()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating role bindings for %s", globals.ClusterName), globals.K8S_ROLEBINDINGS_MODULE_NAME)

	clientset := config.GetClientOrExit()

	// Get all ClusterRoleBindings
	clusterRoleBindings, err := clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		shared.LogListError(&logger, "cluster role bindings", "", err, globals.K8S_ROLEBINDINGS_MODULE_NAME, true)
		return
	}

	// Get all ClusterRoles for reference
	clusterRoles, err := clientset.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		shared.LogListError(&logger, "cluster roles", "", err, globals.K8S_ROLEBINDINGS_MODULE_NAME, false)
	}
	clusterRoleMap := make(map[string]*rbacv1.ClusterRole)
	if clusterRoles != nil {
		for i := range clusterRoles.Items {
			clusterRoleMap[clusterRoles.Items[i].Name] = &clusterRoles.Items[i]
		}
	}

	// Get target namespaces
	namespaces := shared.GetTargetNamespaces(ctx, clientset, &logger, globals.K8S_ROLEBINDINGS_MODULE_NAME)

	var findings []RoleBindingFinding

	// Process ClusterRoleBindings
	for _, crb := range clusterRoleBindings.Items {
		finding := analyzeClusterRoleBinding(ctx, clientset, &crb, clusterRoleMap)
		findings = append(findings, finding)
	}

	// Process RoleBindings per namespace
	for _, ns := range namespaces {
		roleBindings, err := clientset.RbacV1().RoleBindings(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			shared.LogListError(&logger, "role bindings", ns, err, globals.K8S_ROLEBINDINGS_MODULE_NAME, false)
			continue
		}

		roles, err := clientset.RbacV1().Roles(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			shared.LogListError(&logger, "roles", ns, err, globals.K8S_ROLEBINDINGS_MODULE_NAME, false)
		}
		roleMap := make(map[string]*rbacv1.Role)
		if roles != nil {
			for i := range roles.Items {
				roleMap[roles.Items[i].Name] = &roles.Items[i]
			}
		}

		for _, rb := range roleBindings.Items {
			finding := analyzeRoleBinding(ctx, clientset, &rb, roleMap, clusterRoleMap)
			findings = append(findings, finding)
		}
	}

	if len(findings) == 0 {
		logger.InfoM("No role bindings found", globals.K8S_ROLEBINDINGS_MODULE_NAME)
		return
	}

	// Build output
	tables := buildRoleBindingsTables(findings)
	loot := buildRoleBindingsLoot(findings)

	output := RoleBindingsOutput{
		Table: tables,
		Loot:  loot,
	}

	err = internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"RoleBindings",
		globals.ClusterName,
		"results",
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.K8S_ROLEBINDINGS_MODULE_NAME)
		return
	}

	// Summary
	crbCount := 0
	rbCount := 0
	adminCount := 0
	dangerousCount := 0
	for _, f := range findings {
		if f.Type == "ClusterRoleBinding" {
			crbCount++
		} else {
			rbCount++
		}
		if f.IsAdminBinding || f.IsClusterAdminBinding {
			adminCount++
		}
		if len(f.DangerousPermissions) > 0 {
			dangerousCount++
		}
	}

	logger.InfoM(fmt.Sprintf("Found %d bindings: %d ClusterRoleBindings, %d RoleBindings",
		len(findings), crbCount, rbCount), globals.K8S_ROLEBINDINGS_MODULE_NAME)
	if adminCount > 0 || dangerousCount > 0 {
		logger.InfoM(fmt.Sprintf("Security: %d admin bindings, %d with dangerous permissions",
			adminCount, dangerousCount), globals.K8S_ROLEBINDINGS_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_ROLEBINDINGS_MODULE_NAME), globals.K8S_ROLEBINDINGS_MODULE_NAME)
}

func analyzeClusterRoleBinding(ctx context.Context, clientset *kubernetes.Clientset, crb *rbacv1.ClusterRoleBinding, clusterRoleMap map[string]*rbacv1.ClusterRole) RoleBindingFinding {
	finding := RoleBindingFinding{
		Name:        crb.Name,
		Namespace:   "cluster-wide",
		Type:        "ClusterRoleBinding",
		RoleRefKind: crb.RoleRef.Kind,
		RoleRefName: crb.RoleRef.Name,
	}

	// Calculate age
	finding.Age, finding.AgeInDays = calculateBindingAge(crb.CreationTimestamp.Time)

	// Parse subjects
	finding.Subjects = parseSubjects(crb.Subjects)
	finding.SubjectCount = len(crb.Subjects)

	// Check for special subject patterns
	for _, subj := range crb.Subjects {
		if subj.Kind == "ServiceAccount" && subj.Name == "default" {
			finding.BindsToDefaultSA = true
		}
		if subj.Kind == "Group" && (subj.Name == "system:serviceaccounts" || subj.Name == "system:authenticated") {
			finding.BindsToAllSAs = true
		}
	}

	// Check for admin bindings
	if crb.RoleRef.Name == "cluster-admin" {
		finding.IsClusterAdminBinding = true
		finding.IsAdminBinding = true
	} else if crb.RoleRef.Name == "admin" {
		finding.IsAdminBinding = true
	}

	// Check for orphaned binding
	if crb.RoleRef.Kind == "ClusterRole" {
		if _, exists := clusterRoleMap[crb.RoleRef.Name]; !exists {
			// Check if it's a system role that might not be in our map
			if !strings.HasPrefix(crb.RoleRef.Name, "system:") {
				finding.OrphanedBinding = true
			}
		}
	}

	// Analyze dangerous permissions
	if clusterRole, exists := clusterRoleMap[crb.RoleRef.Name]; exists {
		finding.DangerousPermissions = analyzeRoleDangerousPermissions(clusterRole.Rules)
	}

	return finding
}

func analyzeRoleBinding(ctx context.Context, clientset *kubernetes.Clientset, rb *rbacv1.RoleBinding, roleMap map[string]*rbacv1.Role, clusterRoleMap map[string]*rbacv1.ClusterRole) RoleBindingFinding {
	finding := RoleBindingFinding{
		Name:        rb.Name,
		Namespace:   rb.Namespace,
		Type:        "RoleBinding",
		RoleRefKind: rb.RoleRef.Kind,
		RoleRefName: rb.RoleRef.Name,
	}

	// Calculate age
	finding.Age, finding.AgeInDays = calculateBindingAge(rb.CreationTimestamp.Time)

	// Parse subjects
	finding.Subjects = parseSubjects(rb.Subjects)
	finding.SubjectCount = len(rb.Subjects)

	// Check for special subject patterns
	for _, subj := range rb.Subjects {
		if subj.Kind == "ServiceAccount" && subj.Name == "default" {
			finding.BindsToDefaultSA = true
		}
		if subj.Kind == "Group" && (subj.Name == "system:serviceaccounts" || subj.Name == "system:authenticated") {
			finding.BindsToAllSAs = true
		}
	}

	// Check for admin bindings
	if rb.RoleRef.Name == "cluster-admin" {
		finding.IsClusterAdminBinding = true
		finding.IsAdminBinding = true
	} else if rb.RoleRef.Name == "admin" {
		finding.IsAdminBinding = true
	}

	// Check for orphaned binding and analyze permissions
	if rb.RoleRef.Kind == "ClusterRole" {
		if clusterRole, exists := clusterRoleMap[rb.RoleRef.Name]; exists {
			finding.DangerousPermissions = analyzeRoleDangerousPermissions(clusterRole.Rules)
		} else if !strings.HasPrefix(rb.RoleRef.Name, "system:") {
			finding.OrphanedBinding = true
		}
	} else {
		// Role reference
		if role, exists := roleMap[rb.RoleRef.Name]; exists {
			finding.DangerousPermissions = analyzeRoleDangerousPermissions(role.Rules)
		} else {
			finding.OrphanedBinding = true
		}
	}

	return finding
}

func parseSubjects(subjects []rbacv1.Subject) []SubjectInfo {
	var result []SubjectInfo
	for _, subj := range subjects {
		result = append(result, SubjectInfo{
			Kind:      subj.Kind,
			Name:      subj.Name,
			Namespace: subj.Namespace,
		})
	}
	return result
}

func calculateBindingAge(creationTime time.Time) (string, int) {
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

func analyzeRoleDangerousPermissions(rules []rbacv1.PolicyRule) []string {
	var dangerous []string
	seen := make(map[string]bool)

	for _, rule := range rules {
		for _, resource := range rule.Resources {
			for _, verb := range rule.Verbs {
				var perm string

				// Check for critical permissions
				if resource == "*" && verb == "*" {
					perm = "wildcard (*/*)"
				} else if resource == "*" {
					perm = fmt.Sprintf("%s on all resources", verb)
				} else if verb == "*" {
					perm = fmt.Sprintf("all verbs on %s", resource)
				} else if resource == "secrets" && (verb == "get" || verb == "list" || verb == "*") {
					perm = fmt.Sprintf("%s secrets", verb)
				} else if resource == "pods/exec" && (verb == "create" || verb == "*") {
					perm = "exec into pods"
				} else if resource == "pods" && verb == "create" {
					perm = "create pods"
				} else if (resource == "rolebindings" || resource == "clusterrolebindings") && verb == "create" {
					perm = fmt.Sprintf("create %s", resource)
				} else if verb == "impersonate" {
					perm = fmt.Sprintf("impersonate %s", resource)
				} else if verb == "escalate" || verb == "bind" {
					perm = fmt.Sprintf("%s verb", verb)
				}

				if perm != "" && !seen[perm] {
					seen[perm] = true
					dangerous = append(dangerous, perm)
				}
			}
		}
	}

	return dangerous
}

func buildRoleBindingsTables(findings []RoleBindingFinding) []internal.TableFile {
	headers := []string{
		"Type",
		"Name",
		"Namespace",
		"Role Kind",
		"Role Name",
		"Subjects",
		"Subject Types",
		"Dangerous Permissions",
		"Flags",
		"Age",
	}

	var body [][]string

	for _, f := range findings {
		// Build subjects string
		var subjectNames []string
		var subjectTypes []string
		subjectTypeSet := make(map[string]bool)
		for _, s := range f.Subjects {
			if s.Kind == "ServiceAccount" && s.Namespace != "" {
				subjectNames = append(subjectNames, fmt.Sprintf("%s/%s", s.Namespace, s.Name))
			} else {
				subjectNames = append(subjectNames, s.Name)
			}
			if !subjectTypeSet[s.Kind] {
				subjectTypeSet[s.Kind] = true
				subjectTypes = append(subjectTypes, s.Kind)
			}
		}

		subjectsStr := strings.Join(subjectNames, ", ")
		subjectTypesStr := strings.Join(subjectTypes, ", ")

		// Dangerous permissions
		dangerousStr := "None"
		if len(f.DangerousPermissions) > 0 {
			dangerousStr = strings.Join(f.DangerousPermissions, ", ")
		}

		// Build flags
		var flags []string
		if f.IsClusterAdminBinding {
			flags = append(flags, "ClusterAdmin")
		} else if f.IsAdminBinding {
			flags = append(flags, "Admin")
		}
		if f.BindsToDefaultSA {
			flags = append(flags, "DefaultSA")
		}
		if f.BindsToAllSAs {
			flags = append(flags, "AllSAs")
		}
		if f.OrphanedBinding {
			flags = append(flags, "Orphaned")
		}

		flagsStr := ""
		if len(flags) > 0 {
			flagsStr = strings.Join(flags, ", ")
		}

		body = append(body, []string{
			f.Type,
			f.Name,
			f.Namespace,
			f.RoleRefKind,
			f.RoleRefName,
			subjectsStr,
			subjectTypesStr,
			dangerousStr,
			k8sinternal.NonEmpty(flagsStr),
			f.Age,
		})
	}

	return []internal.TableFile{
		{
			Name:   "RoleBindings",
			Header: headers,
			Body:   body,
		},
	}
}

func buildRoleBindingsLoot(findings []RoleBindingFinding) []internal.LootFile {
	loot := shared.NewLootBuilder()

	section := loot.Section("RoleBindings-Commands")
	section.SetHeader(`# ===========================================
# Role Bindings Enumeration Commands
# ===========================================`)

	if globals.KubeContext != "" {
		section.AddBlank().Addf("kubectl config use-context %s", globals.KubeContext)
	}

	// Basic enumeration commands
	section.AddBlank().
		Add("# List all ClusterRoleBindings:").
		Add("kubectl get clusterrolebindings").
		AddBlank().
		Add("# List all RoleBindings in all namespaces:").
		Add("kubectl get rolebindings -A").
		AddBlank().
		Add("# Get detailed info on a binding:").
		Add("kubectl describe clusterrolebinding <name>").
		Add("kubectl describe rolebinding <name> -n <namespace>")

	// Admin bindings section
	var adminBindings []RoleBindingFinding
	for _, f := range findings {
		if f.IsClusterAdminBinding || f.IsAdminBinding {
			adminBindings = append(adminBindings, f)
		}
	}

	if len(adminBindings) > 0 {
		section.AddBlank().
			Add("# -------------------------------------------").
			Add("# Admin/Cluster-Admin Bindings").
			Add("# -------------------------------------------")

		for _, f := range adminBindings {
			section.AddBlank()
			if f.Type == "ClusterRoleBinding" {
				section.Addf("# %s (ClusterRoleBinding) -> %s", f.Name, f.RoleRefName)
				section.Addf("kubectl describe clusterrolebinding %s", f.Name)
			} else {
				section.Addf("# %s (RoleBinding in %s) -> %s", f.Name, f.Namespace, f.RoleRefName)
				section.Addf("kubectl describe rolebinding %s -n %s", f.Name, f.Namespace)
			}
			for _, s := range f.Subjects {
				if s.Kind == "ServiceAccount" {
					section.Addf("# Subject: ServiceAccount %s/%s", s.Namespace, s.Name)
				} else {
					section.Addf("# Subject: %s %s", s.Kind, s.Name)
				}
			}
		}
	}

	// Dangerous permissions section
	var dangerousBindings []RoleBindingFinding
	for _, f := range findings {
		if len(f.DangerousPermissions) > 0 && !f.IsClusterAdminBinding {
			dangerousBindings = append(dangerousBindings, f)
		}
	}

	if len(dangerousBindings) > 0 {
		section.AddBlank().
			Add("# -------------------------------------------").
			Add("# Bindings with Dangerous Permissions").
			Add("# -------------------------------------------")

		for _, f := range dangerousBindings {
			section.AddBlank().
				Addf("# %s (%s)", f.Name, f.Type)
			section.Addf("# Permissions: %s", strings.Join(f.DangerousPermissions, ", "))
			if f.Type == "ClusterRoleBinding" {
				section.Addf("kubectl describe clusterrolebinding %s", f.Name)
				section.Addf("kubectl describe clusterrole %s", f.RoleRefName)
			} else {
				section.Addf("kubectl describe rolebinding %s -n %s", f.Name, f.Namespace)
				if f.RoleRefKind == "ClusterRole" {
					section.Addf("kubectl describe clusterrole %s", f.RoleRefName)
				} else {
					section.Addf("kubectl describe role %s -n %s", f.RoleRefName, f.Namespace)
				}
			}
		}
	}

	// Default SA bindings section
	var defaultSABindings []RoleBindingFinding
	for _, f := range findings {
		if f.BindsToDefaultSA {
			defaultSABindings = append(defaultSABindings, f)
		}
	}

	if len(defaultSABindings) > 0 {
		section.AddBlank().
			Add("# -------------------------------------------").
			Add("# Bindings to Default ServiceAccount").
			Add("# -------------------------------------------").
			Add("# WARNING: Binding permissions to default SA affects all pods that don't specify a SA")

		for _, f := range defaultSABindings {
			section.AddBlank().
				Addf("# %s -> %s", f.Name, f.RoleRefName)
		}
	}

	// All SAs bindings section
	var allSABindings []RoleBindingFinding
	for _, f := range findings {
		if f.BindsToAllSAs {
			allSABindings = append(allSABindings, f)
		}
	}

	if len(allSABindings) > 0 {
		section.AddBlank().
			Add("# -------------------------------------------").
			Add("# Bindings to All ServiceAccounts/Users").
			Add("# -------------------------------------------").
			Add("# WARNING: These bindings grant permissions to all SAs or authenticated users")

		for _, f := range allSABindings {
			section.AddBlank().
				Addf("# %s -> %s", f.Name, f.RoleRefName)
			for _, s := range f.Subjects {
				if s.Kind == "Group" {
					section.Addf("# Group: %s", s.Name)
				}
			}
		}
	}

	// Orphaned bindings section
	var orphanedBindings []RoleBindingFinding
	for _, f := range findings {
		if f.OrphanedBinding {
			orphanedBindings = append(orphanedBindings, f)
		}
	}

	if len(orphanedBindings) > 0 {
		section.AddBlank().
			Add("# -------------------------------------------").
			Add("# Orphaned Bindings (Role Not Found)").
			Add("# -------------------------------------------").
			Add("# These bindings reference roles that don't exist")

		for _, f := range orphanedBindings {
			section.AddBlank().
				Addf("# %s -> %s (missing)", f.Name, f.RoleRefName)
			if f.Type == "ClusterRoleBinding" {
				section.Addf("kubectl delete clusterrolebinding %s", f.Name)
			} else {
				section.Addf("kubectl delete rolebinding %s -n %s", f.Name, f.Namespace)
			}
		}
	}

	return loot.Build()
}
