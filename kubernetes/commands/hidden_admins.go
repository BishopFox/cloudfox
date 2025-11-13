package commands

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	k8sinternal "github.com/BishopFox/cloudfox/internal/kubernetes"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/spf13/cobra"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var HiddenAdminsCmd = &cobra.Command{
	Use:   "hidden-admins",
	Short: "Enumerate roles, users, groups, and service accounts with dangerous or escalatory permissions",
	Long: `
Identify hidden or dangerous administrators in a Kubernetes cluster. This includes:
  - Membership in system:masters group
  - Cluster-admin permissions
  - Ability to create/update Roles, ClusterRoles, RoleBindings, or ClusterRoleBindings
  - Ability to create/update Secrets or ConfigMaps
  - Impersonation rights
  - RBAC aggregation roles
  - Entities who can escalate privileges

Outputs detailed findings and attack paths:
  cloudfox kubernetes hidden-admins`,
	Run: ListHiddenAdmins,
}

type HiddenAdminFinding struct {
	Namespace      string
	Entity         string
	EntityType     string
	Scope          string
	DangerousPerms string
	Source         string
}

type HiddenAdminsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (h HiddenAdminsOutput) TableFiles() []internal.TableFile {
	return h.Table
}

func (h HiddenAdminsOutput) LootFiles() []internal.LootFile {
	return h.Loot
}

func (h HiddenAdminFinding) ToTableRow() []string {
	return []string{
		h.Namespace,
		h.Entity,
		h.EntityType,
		h.Scope,
		h.DangerousPerms,
		h.Source,
	}
}

func (h HiddenAdminFinding) Loot() string {
	return fmt.Sprintf(
		"[Hidden Admin Detection]\nNamespace: %s\nEntity: %s (%s)\nScope: %s\nSource: %s\nDangerous Permissions: %s\n",
		h.Namespace,
		h.Entity,
		h.EntityType,
		h.Scope,
		h.Source,
		h.DangerousPerms,
	)
}

func ListHiddenAdmins(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	clientset := config.GetClientOrExit()
	if clientset == nil {
		logger.ErrorM("Error getting Kubernetes client:", globals.K8S_HIDDEN_ADMINS_MODULE_NAME)
		os.Exit(1)
	}

	headers := []string{"Namespace", "Entity", "Type", "Scope", "Dangerous Permissions", "Source"}
	var tableRows [][]string
	var lootLines []string

	// ClusterRoles
	clusterRoles, err := clientset.RbacV1().ClusterRoles().List(ctx, v1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error fetching ClusterRoles: %v", err), globals.K8S_HIDDEN_ADMINS_MODULE_NAME)
		return
	}
	for _, role := range clusterRoles.Items {
		var findings []string

		if role.Name == "cluster-admin" {
			findings = append(findings, "cluster-admin role")
		}
		if strings.Contains(role.Name, "system:masters") {
			findings = append(findings, "member of system:masters group")
		}
		if role.AggregationRule != nil && role.AggregationRule.ClusterRoleSelectors != nil && len(role.AggregationRule.ClusterRoleSelectors) > 0 {
			findings = append(findings, "RBAC Aggregation role")
		}
		if role.Rules != nil {
			for _, rule := range role.Rules {
				if k8sinternal.IsDangerousRule(rule) {
					findings = append(findings, fmt.Sprintf("rule: %s", k8sinternal.RuleToString(rule)))
				}
			}
		}
		if len(findings) > 0 {
			row := HiddenAdminFinding{
				Namespace:      "<cluster>",
				Entity:         role.Name,
				EntityType:     "ClusterRole",
				Scope:          "cluster",
				DangerousPerms: strings.Join(findings, "; "),
				Source:         "ClusterRole definition",
			}
			tableRows = append(tableRows, row.ToTableRow())
			lootLines = append(lootLines, row.Loot())
		}
	}

	// ClusterRoleBindings
	crbs, err := clientset.RbacV1().ClusterRoleBindings().List(ctx, v1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error fetching ClusterRoleBindings: %v", err), globals.K8S_HIDDEN_ADMINS_MODULE_NAME)
		return
	}
	for _, binding := range crbs.Items {
		if binding.Subjects != nil {
			for _, subject := range binding.Subjects {
				ns := subject.Namespace
				if ns == "" {
					ns = "<cluster>"
				}
				role := binding.RoleRef.Name
				if role == "cluster-admin" || role == "system:masters" {
					row := HiddenAdminFinding{
						Namespace:      ns,
						Entity:         subject.Name,
						EntityType:     subject.Kind,
						Scope:          "cluster",
						DangerousPerms: fmt.Sprintf("bound to %s", role),
						Source:         fmt.Sprintf("ClusterRoleBinding %s", binding.Name),
					}
					tableRows = append(tableRows, row.ToTableRow())
					lootLines = append(lootLines, row.Loot())
				}
			}
		}
	}

	// Roles & RoleBindings
	namespaces, err := clientset.CoreV1().Namespaces().List(ctx, v1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error fetching Namespaces: %v", err), globals.K8S_HIDDEN_ADMINS_MODULE_NAME)
		return
	}
	for _, ns := range namespaces.Items {
		roles, err := clientset.RbacV1().Roles(ns.Name).List(ctx, v1.ListOptions{})
		if err != nil {
			logger.ErrorM(fmt.Sprintf("Error fetching Roles in namespace %s: %v", ns.Name, err), globals.K8S_HIDDEN_ADMINS_MODULE_NAME)
			continue
		}
		for _, role := range roles.Items {
			var findings []string
			if role.Rules != nil {
				for _, rule := range role.Rules {
					if k8sinternal.IsDangerousRule(rule) {
						findings = append(findings, fmt.Sprintf("rule: %s", k8sinternal.RuleToString(rule)))
					}
				}
			}
			if len(findings) > 0 {
				row := HiddenAdminFinding{
					Namespace:      ns.Name,
					Entity:         role.Name,
					EntityType:     "Role",
					Scope:          "namespace",
					DangerousPerms: strings.Join(findings, "; "),
					Source:         fmt.Sprintf("Role definition (%s)", role.Name),
				}
				tableRows = append(tableRows, row.ToTableRow())
				lootLines = append(lootLines, row.Loot())
			}
		}

		rbs, err := clientset.RbacV1().RoleBindings(ns.Name).List(ctx, v1.ListOptions{})
		if err != nil {
			logger.ErrorM(fmt.Sprintf("Error fetching RoleBindings in namespace %s: %v", ns.Name, err), globals.K8S_HIDDEN_ADMINS_MODULE_NAME)
			continue
		}
		for _, binding := range rbs.Items {
			if binding.Subjects != nil {
				for _, subject := range binding.Subjects {
					row := HiddenAdminFinding{
						Namespace:      ns.Name,
						Entity:         subject.Name,
						EntityType:     subject.Kind,
						Scope:          "namespace",
						DangerousPerms: fmt.Sprintf("bound to %s", binding.RoleRef.Name),
						Source:         fmt.Sprintf("RoleBinding %s", binding.Name),
					}
					tableRows = append(tableRows, row.ToTableRow())
					lootLines = append(lootLines, row.Loot())
				}
			}
		}
	}

	var lootEnum []string
	lootEnum = append(lootEnum, `#####################################
##### Enumerate Dangerous Permissions
#####################################

`)
	if globals.KubeContext != "" {
		lootEnum = append(lootEnum, fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext))
	}

	lootEnum = append(lootEnum, `
# Check for system:masters membership
kubectl get clusterrolebindings -o json | jq '.items[] | select(.subjects[]?.name == "system:masters")'
kubectl get clusterrolebindings -o json | jq -r '.items[] | select(.subjects[]?.name=="system:masters")'

# Find impersonation rules
kubectl get clusterroles -o json | jq '.items[] | select(.rules[]? | .verbs[]? | ascii_downcase == "impersonate")'
kubectl get clusterroles -o json | jq -r '.items[] | select(.rules[]?.verbs[]?=="impersonate") | .metadata.name, .rules[]? | select(.verbs[]?=="impersonate")'

# Find Role/ClusterRole creation permissions
kubectl get clusterroles -o json | jq '.items[] | select(.rules[]? | (.verbs[]? | ascii_downcase == "create") and (.resources[]? | ascii_downcase | contains("role") ))'

# Find ConfigMap and Secret modification permissions
kubectl get clusterroles -o json | jq '.items[] | select(.rules[]? | (.verbs[]? | ascii_downcase == "create" or ascii_downcase == "update") and (.resources[]? | ascii_downcase | contains("secret") or contains("configmap") ))'

# Check who can bind cluster-admin
kubectl get clusterroles -o json | jq '.items[] | select(.metadata.name == "cluster-admin")'

# Find cluster-admin bindings (Any subject (User, Group, ServiceAccount) bound to the cluster-admin role.)
kubectl get clusterrolebindings -o json | jq -r '.items[] | select(.roleRef.name=="cluster-admin") | .metadata.name, .subjects[]? | "\(.kind):\(.name) (ns=\(.namespace // "cluster-scope"))"'

# Roles that can escalate privileges via RBAC editing 
# Looks for: Ability to create, update, or patch roles, clusterroles, rolebindings, or clusterrolebindings.
kubectl get clusterroles -o json | jq -r '.items[] | select(.rules[]? | (.resources[]? | test("roles|clusterroles|rolebindings|clusterrolebindings"))) | .metadata.name, .rules[]'

# Create/modify secrets
# Looks for: Ability to read or modify secrets, which can be used for credential theft.
kubectl get clusterroles -o json | jq -r '.items[] | select(.rules[]? | (.resources[]?=="secrets") and (.verbs[]? | test("create|update|patch|get"))) | .metadata.name'

# Create/modify configmaps
# Looks for: Ability to change configmaps, which can lead to code injection or malicious configuration.
kubectl get clusterroles -o json | jq -r '.items[] | select(.rules[]? | (.resources[]?=="configmaps") and (.verbs[]? | test("create|update|patch"))) | .metadata.name'


# Namespace-Scoped Permissions

# Namespace-level cluster-admin equivalents
# Looks for: Namespace admin access (can usually escalate to cluster-wide access in many cases).
kubectl get rolebindings --all-namespaces -o json | jq -r '.items[] | select(.roleRef.name=="admin" or .roleRef.name=="cluster-admin") | "\(.metadata.namespace): \(.roleRef.name) -> \(.subjects[]?.kind):\(.subjects[]?.name)"'

# Namespace-scoped RBAC modification
# Looks for: Roles that can modify RBAC inside a namespace.
kubectl get roles --all-namespaces -o json | jq -r '.items[] | select(.rules[]? | (.resources[]? | test("roles|rolebindings")) and (.verbs[]? | test("create|update|patch"))) | "\(.metadata.namespace): \(.metadata.name)"'

# Namespace impersonation
# Looks for: Roles that allow impersonation inside a namespace.
kubectl get roles --all-namespaces -o json | jq -r '.items[] | select(.rules[]? | (.verbs[]?=="impersonate")) | "\(.metadata.namespace): \(.metadata.name)"'

# Create Pods with elevated privileges
# Looks for: Roles that allow creating pods, which could be used to run privileged containers.
kubectl get roles --all-namespaces -o json | jq -r '.items[] | select(.rules[]? | (.resources[]?=="pods") and (.verbs[]? | test("create"))) | "\(.metadata.namespace): \(.metadata.name)"'

`)
	// Output section
	table := internal.TableFile{
		Name:   "Hidden-Admins",
		Header: headers,
		Body:   tableRows,
	}

	lootAdmins := internal.LootFile{
		Name:     "Hidden-Admin-Attack-Paths",
		Contents: strings.Join(k8sinternal.UniqueStrings(lootLines), "\n-----\n"),
	}

	loot := internal.LootFile{
		Name:     "Dangerous-Permissions-Enum",
		Contents: strings.Join(lootEnum, "\n"),
	}

	err = internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"Hidden-Admins",
		globals.ClusterName,
		"results",
		HiddenAdminsOutput{
			Table: []internal.TableFile{table},
			Loot:  []internal.LootFile{lootAdmins, loot},
		},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_HIDDEN_ADMINS_MODULE_NAME)
	}
}
