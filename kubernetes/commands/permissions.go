package commands

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

var PermissionsCmd = &cobra.Command{
	Use:     "permissions",
	Aliases: []string{"perms"},
	Short:   "List all cluster entities and their respective permissions",
	Long: `
List all cluster entities and their respective permissions:
  cloudfox kubernetes permissions`,
	Run: RunEnumPermissions,
}

type PermissionsOutput struct {
	ResourceType string
	Namespace    string
	SubjectKind  string
	SubjectName  string
	Role         string
	ClusterRole  string
	Verb         string
	Resource     string
	APIGroup     string
	Scope        string
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

func (p PermissionsOutput) Headers() []string {
	return []string{"Resource Type", "Namespace", "Subject Kind", "Subject Name", "Role", "Cluster Role", "Verb", "Resource", "API Group", "Scope"}
}

func (p PermissionsOutput) Row() []string {
	return []string{p.ResourceType, p.Namespace, p.SubjectKind, p.SubjectName, p.Role, p.ClusterRole, p.Verb, p.Resource, p.APIGroup, p.Scope}
}

func (p PermissionsOutput) LootFiles() map[string]string {
	return nil
}

type PermissionsResults struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (p PermissionsResults) TableFiles() []internal.TableFile {
	return p.Table
}

func (p PermissionsResults) LootFiles() []internal.LootFile {
	return p.Loot
}

func RunEnumPermissions(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	logger := internal.NewLogger()
	parentCmd := cmd.Parent()

	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	clientset := config.GetClientOrExit()
	if clientset == nil {
		logger.ErrorM("Error getting Kubernetes client:", globals.K8S_PERMISSIONS_MODULE_NAME)
		os.Exit(1)
	}

	// List namespaces
	namespaces, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing namespaces: %v", err), globals.K8S_PERMISSIONS_MODULE_NAME)
		return
	}

	// Get cluster roles and their permissions
	clusterRolePerms := make(map[string][][]string)
	clusterRoles, err := clientset.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing cluster roles: %v", err), globals.K8S_PERMISSIONS_MODULE_NAME)
		return
	}
	for _, cr := range clusterRoles.Items {
		clusterRolePerms[cr.Name] = explodeRules(cr.Rules)
	}

	// Get cluster role bindings
	clusterRoleBindings, err := clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing cluster role bindings: %v", err), globals.K8S_PERMISSIONS_MODULE_NAME)
		return
	}

	var output []PermissionsOutput
	seen := make(map[string]struct{})

	// Process ClusterRoleBindings
	for _, crb := range clusterRoleBindings.Items {
		if len(crb.Subjects) == 0 {
			continue
		}
		perms := clusterRolePerms[crb.RoleRef.Name]
		for _, subj := range crb.Subjects {
			subjNamespace := subj.Namespace
			if subjNamespace == "" {
				subjNamespace = "<cluster>" // special handling for cluster-scoped subjects
			}
			for _, perm := range perms {
				key := buildKey("cluster", subj.Kind, subjNamespace, subj.Name, "", crb.RoleRef.Name, perm[0], perm[1], perm[2])
				if _, exists := seen[key]; !exists {
					seen[key] = struct{}{}
					output = append(output, PermissionsOutput{
						ResourceType: "ClusterRoleBinding",
						Namespace:    subjNamespace,
						SubjectKind:  subj.Kind,
						SubjectName:  subj.Name,
						ClusterRole:  crb.RoleRef.Name,
						Verb:         perm[0],
						Resource:     perm[1],
						APIGroup:     perm[2],
						Scope:        "cluster",
					})
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
		rolePerms := make(map[string][][]string)
		for _, role := range roles.Items {
			rolePerms[role.Name] = explodeRules(role.Rules)
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
			perms := rolePerms[rb.RoleRef.Name]
			for _, subj := range rb.Subjects {
				subjNamespace := subj.Namespace
				if subjNamespace == "" {
					subjNamespace = "<NONE>" // regular namespaces
				}
				for _, perm := range perms {
					key := buildKey("namespace", subj.Kind, subjNamespace, subj.Name, rb.RoleRef.Name, "", perm[0], perm[1], perm[2])
					if _, exists := seen[key]; !exists {
						seen[key] = struct{}{}
						output = append(output, PermissionsOutput{
							ResourceType: "RoleBinding",
							Namespace:    ns.Name,
							SubjectKind:  subj.Kind,
							SubjectName:  subj.Name,
							Role:         rb.RoleRef.Name,
							Verb:         perm[0],
							Resource:     perm[1],
							APIGroup:     perm[2],
							Scope:        "namespace",
						})
					}
				}
			}
		}
	}

	// Sort output for consistent display
	sort.Slice(output, func(i, j int) bool {
		a, b := output[i], output[j]
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		if a.SubjectKind != b.SubjectKind {
			return a.SubjectKind < b.SubjectKind
		}
		if a.SubjectName != b.SubjectName {
			return a.SubjectName < b.SubjectName
		}
		if a.Verb != b.Verb {
			return a.Verb < b.Verb
		}
		return a.Resource < b.Resource
	})

	// Safely get headers in case output is empty
	var headers []string
	if len(output) > 0 {
		headers = output[0].Headers()
	} else {
		headers = PermissionsOutput{}.Headers()
	}

	var rows [][]string
	for _, row := range output {
		rows = append(rows, row.Row())
	}

	// ------------------------------
	// Build Impersonation Loot
	// ------------------------------
	var lootImpersonate []string
	lootImpersonate = append(lootImpersonate, `#####################################
##### Impersonation Pentest Commands
#####################################
`)
	if globals.KubeContext != "" {
		lootImpersonate = append(lootImpersonate, fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext))
	}

	// Map of entity -> allowed actions
	impersonateMap := make(map[string][]PermissionsOutput)
	for _, p := range output {
		if strings.ToLower(p.Verb) == "impersonate" {
			key := fmt.Sprintf("%s/%s", p.SubjectKind, p.SubjectName)
			impersonateMap[key] = append(impersonateMap[key], p)
		}
	}

	// Now build pentest commands for each impersonated entity
	for entity := range impersonateMap {
		lootImpersonate = append(lootImpersonate, fmt.Sprintf("# Subject: %s can be impersonated", entity))

		for _, perm := range output {
			// Only generate commands if the impersonated entity has this permission
			target := fmt.Sprintf("%s/%s", perm.SubjectKind, perm.SubjectName)
			if target != entity {
				continue
			}

			ns := perm.Namespace
			switch strings.ToLower(perm.Resource) {
			case "secrets":
				if strings.ToLower(perm.Verb) == "get" {
					lootImpersonate = append(lootImpersonate,
						fmt.Sprintf("kubectl get secrets -n %s --as=%s", ns, entity),
					)
				}
			case "pods":
				if strings.ToLower(perm.Verb) == "create" {
					lootImpersonate = append(lootImpersonate,
						fmt.Sprintf("kubectl run test-pod --image=busybox -n %s --as=%s --restart=Never -- sleep 3600", ns, entity),
					)
				}
				if strings.ToLower(perm.Verb) == "exec" {
					lootImpersonate = append(lootImpersonate,
						fmt.Sprintf("kubectl exec -it <pod-name> -n %s --as=%s -- /bin/sh", ns, entity),
					)
				}
			}
		}
	}

	var lootPodYAMLs []string
	lootPodYAMLs = append(lootPodYAMLs, `#####################################
##### Example Pod YAMLs for ServiceAccounts
#####################################
`)

	// Track unique service accounts to avoid duplicates
	seenSA := make(map[string]struct{})

	for _, perm := range output {
		if strings.ToLower(perm.SubjectKind) == "serviceaccount" {
			sa := perm.SubjectName
			ns := perm.Namespace
			key := fmt.Sprintf("%s/%s", ns, sa)
			if _, exists := seenSA[key]; exists {
				continue
			}
			seenSA[key] = struct{}{}

			podName := fmt.Sprintf("example-%s", strings.ToLower(strings.ReplaceAll(sa, "/", "-")))
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
					ServiceAccountName: sa,
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
				lootPodYAMLs = append(lootPodYAMLs,
					fmt.Sprintf("# --- POD YAML for ServiceAccount: %s, Namespace: %s ---\n%s", sa, ns, string(yamlData)),
					"# Apply with: kubectl create -f <filename>.yaml",
				)
			} else {
				logger.ErrorM(fmt.Sprintf("Error marshaling YAML for ServiceAccount %s in namespace %s: %v", sa, ns, err), globals.K8S_PERMISSIONS_MODULE_NAME)
			}
		}
	}

	lootPodYAMLFile := internal.LootFile{
		Name:     "Permissions-ExamplePodYAML",
		Contents: strings.Join(lootPodYAMLs, "\n"),
	}

	lootImpersonateFile := internal.LootFile{
		Name:     "Permissions-Impersonate",
		Contents: strings.Join(lootImpersonate, "\n"),
	}

	table := internal.TableFile{
		Name:   "Permissions",
		Header: headers,
		Body:   rows,
	}

	// Build loot file with kubectl + jq commands for deeper inspection.
	// Use a set to avoid duplicates.
	// Build loot file with kubectl + jq commands grouped by related roles and bindings
	lootSet := []string{}

	lootSet = append(lootSet, `#####################################
##### Enumerate RBAC Information
#####################################

# Identity provider integration checks
# (Requires specific plugins or cloud CLI tools)
# Example for AWS EKS:
aws eks list-identity-provider-configs --cluster-name <cluster>
# Example for GCP GKE:
gcloud container clusters describe <cluster> --format="value(identityConfig)"
# Example for Azure AKS:
az aks show --name <cluster> --resource-group <rg> --query "oidcIssuerProfile"

# ------------------------------------------------------------------------

`)
	if globals.KubeContext != "" {
		lootSet = append(lootSet, fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext))
	}

	// Group clusterroles with their bindings
	for _, cr := range clusterRoles.Items {
		lootSet = append(lootSet,
			fmt.Sprintf("# ClusterRole: %s", cr.Name),
			fmt.Sprintf("kubectl get clusterrole %s -o json | jq '{name: .metadata.name, aggregationRule: .aggregationRule, rules: .rules}'", cr.Name),
		)
		for _, crb := range clusterRoleBindings.Items {
			if crb.RoleRef.Name == cr.Name {
				lootSet = append(lootSet,
					fmt.Sprintf("kubectl get clusterrolebinding %s -o json | jq '{name: .metadata.name, roleRef: .roleRef, subjects: .subjects}'", crb.Name),
				)
			}
		}
		lootSet = append(lootSet, "")
	}

	// Group roles with their bindings in each namespace
	for _, ns := range namespaces.Items {
		roles, _ := clientset.RbacV1().Roles(ns.Name).List(ctx, metav1.ListOptions{})
		rbs, _ := clientset.RbacV1().RoleBindings(ns.Name).List(ctx, metav1.ListOptions{})

		for _, role := range roles.Items {
			lootSet = append(lootSet,
				fmt.Sprintf("# Role: %s (Namespace: %s)", role.Name, ns.Name),
				fmt.Sprintf("kubectl get role %s -n %s -o json | jq '{name: .metadata.name, rules: .rules}'", role.Name, ns.Name),
			)
			for _, rb := range rbs.Items {
				if rb.RoleRef.Name == role.Name {
					lootSet = append(lootSet,
						fmt.Sprintf("kubectl get rolebinding %s -n %s -o json | jq '{name: .metadata.name, roleRef: .roleRef, subjects: .subjects}'", rb.Name, ns.Name),
					)
				}
			}
			lootSet = append(lootSet, "")
		}
	}

	loot := internal.LootFile{
		Name:     "Permissions-Enum",
		Contents: strings.Join(lootSet, "\n"),
	}

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
			Table: []internal.TableFile{table},
			Loot:  []internal.LootFile{loot, lootImpersonateFile, lootPodYAMLFile},
		},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_PERMISSIONS_MODULE_NAME)
	}

}

// explodeRules breaks down PolicyRules into verb/resource/apiGroup tuples
func explodeRules(rules []v1.PolicyRule) [][]string {
	var perms [][]string
	for _, rule := range rules {
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
					perms = append(perms, []string{verb, res, group})
				}
			}
		}
	}
	return perms
}

// buildKey creates a unique key string for deduplication of permissions output
func buildKey(scope, subjectKind, subjectNamespace, subjectName, role, clusterRole, verb, resource, apiGroup string) string {
	return fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s|%s", scope, subjectKind, subjectNamespace, subjectName, role, clusterRole, verb, resource, apiGroup)
}
