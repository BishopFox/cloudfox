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
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var ServiceAccountsCmd = &cobra.Command{
	Use:     "serviceaccounts",
	Aliases: []string{"sa"},
	Short:   "Enumerate service accounts with RBAC permissions and token information",
	Long: `
Enumerate all service accounts in the cluster including:
  - Associated secrets and tokens
  - RBAC role bindings (Roles and ClusterRoles)
  - Pods using each service account
  - Auto-mount token settings
  - Token extraction and impersonation techniques

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
		"Namespace",
		"Service Account",
		"Secrets",
		"Auto-Mount Token",
		"Roles",
		"ClusterRoles",
		"Pods Using SA",
		"Image Pull Secrets",
	}

	var outputRows [][]string
	var lootEnum []string
	var lootTokens []string
	var lootImpersonate []string
	var lootExploit []string

	lootEnum = append(lootEnum, `#####################################
##### ServiceAccount Enumeration
#####################################
#
# List and describe all service accounts
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
#
`)

	if globals.KubeContext != "" {
		lootEnum = append(lootEnum, fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext))
	}

	// Build maps for RBAC bindings
	saRoleBindings := make(map[string]map[string][]string)      // ns -> sa -> []roles
	saClusterRoleBindings := make(map[string]map[string][]string) // ns -> sa -> []clusterroles
	saPods := make(map[string]map[string][]string)              // ns -> sa -> []pods

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
		// Get all pods in namespace to map SA usage
		pods, err := clientset.CoreV1().Pods(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			logger.ErrorM(fmt.Sprintf("Error listing pods in namespace %s: %v", ns.Name, err), globals.K8S_SERVICEACCOUNTS_MODULE_NAME)
		} else {
			for _, pod := range pods.Items {
				saName := pod.Spec.ServiceAccountName
				if saName == "" {
					saName = "default"
				}
				if saPods[ns.Name] == nil {
					saPods[ns.Name] = make(map[string][]string)
				}
				saPods[ns.Name][saName] = append(saPods[ns.Name][saName], pod.Name)
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

		// Get ServiceAccounts
		serviceAccounts, err := clientset.CoreV1().ServiceAccounts(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			logger.ErrorM(fmt.Sprintf("Error listing service accounts in namespace %s: %v", ns.Name, err), globals.K8S_SERVICEACCOUNTS_MODULE_NAME)
			continue
		}

		for _, sa := range serviceAccounts.Items {
			// Get secrets
			var secretNames []string
			for _, secret := range sa.Secrets {
				secretNames = append(secretNames, secret.Name)
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

			// Get roles bound to this SA
			roles := saRoleBindings[ns.Name][sa.Name]
			clusterRoles := saClusterRoleBindings[ns.Name][sa.Name]

			// Get pods using this SA
			podsUsingSA := saPods[ns.Name][sa.Name]

			// Get image pull secrets
			var imagePullSecrets []string
			for _, ips := range sa.ImagePullSecrets {
				imagePullSecrets = append(imagePullSecrets, ips.Name)
			}

			outputRows = append(outputRows, []string{
				ns.Name,
				sa.Name,
				strings.Join(k8sinternal.Unique(secretNames), ", "),
				autoMount,
				strings.Join(k8sinternal.Unique(roles), ", "),
				strings.Join(k8sinternal.Unique(clusterRoles), ", "),
				fmt.Sprintf("%d pods", len(podsUsingSA)),
				strings.Join(k8sinternal.Unique(imagePullSecrets), ", "),
			})

			// Generate enumeration commands
			lootEnum = append(lootEnum, fmt.Sprintf("\n# ServiceAccount: %s/%s", ns.Name, sa.Name))
			lootEnum = append(lootEnum, fmt.Sprintf("kubectl get serviceaccount %s -n %s -o yaml", sa.Name, ns.Name))
			lootEnum = append(lootEnum, fmt.Sprintf("kubectl describe serviceaccount %s -n %s", sa.Name, ns.Name))

			// Show RBAC permissions
			if len(roles) > 0 {
				lootEnum = append(lootEnum, fmt.Sprintf("# Roles: %s", strings.Join(roles, ", ")))
				for _, role := range roles {
					lootEnum = append(lootEnum, fmt.Sprintf("kubectl get role %s -n %s -o yaml", role, ns.Name))
				}
			}
			if len(clusterRoles) > 0 {
				lootEnum = append(lootEnum, fmt.Sprintf("# ClusterRoles: %s", strings.Join(clusterRoles, ", ")))
				for _, cr := range clusterRoles {
					lootEnum = append(lootEnum, fmt.Sprintf("kubectl get clusterrole %s -o yaml", cr))
				}
			}
			lootEnum = append(lootEnum, "")

			// Token extraction
			if len(secretNames) > 0 {
				lootTokens = append(lootTokens, fmt.Sprintf("\n# ServiceAccount: %s/%s", ns.Name, sa.Name))
				for _, secretName := range secretNames {
					lootTokens = append(lootTokens, fmt.Sprintf("# Secret: %s", secretName))
					lootTokens = append(lootTokens, fmt.Sprintf("kubectl get secret %s -n %s -o jsonpath='{.data.token}' | base64 -d", secretName, ns.Name))
					lootTokens = append(lootTokens, fmt.Sprintf("# Decode token (paste output above):"))
					lootTokens = append(lootTokens, fmt.Sprintf("# echo '<token>' | cut -d. -f2 | base64 -d 2>/dev/null | jq ."))
				}
				lootTokens = append(lootTokens, "")
			}

			// Impersonation commands
			lootImpersonate = append(lootImpersonate, fmt.Sprintf("\n# ServiceAccount: %s/%s", ns.Name, sa.Name))
			lootImpersonate = append(lootImpersonate, fmt.Sprintf("# Extract token and set as environment variable:"))
			if len(secretNames) > 0 {
				lootImpersonate = append(lootImpersonate, fmt.Sprintf("export SA_TOKEN=$(kubectl get secret %s -n %s -o jsonpath='{.data.token}' | base64 -d)", secretNames[0], ns.Name))
			} else {
				lootImpersonate = append(lootImpersonate, fmt.Sprintf("# No token secret found - may need to create one manually"))
				lootImpersonate = append(lootImpersonate, fmt.Sprintf("# kubectl create token %s -n %s --duration=24h", sa.Name, ns.Name))
			}
			lootImpersonate = append(lootImpersonate, fmt.Sprintf("# Use token with kubectl:"))
			lootImpersonate = append(lootImpersonate, fmt.Sprintf("kubectl --token=$SA_TOKEN auth can-i --list"))
			lootImpersonate = append(lootImpersonate, fmt.Sprintf("kubectl --token=$SA_TOKEN get pods -n %s", ns.Name))
			lootImpersonate = append(lootImpersonate, "")

			// Privilege escalation - create pods using high-privilege SAs
			if len(clusterRoles) > 0 || len(roles) > 0 {
				hasHighPrivs := false
				dangerousRoles := []string{"admin", "cluster-admin", "edit"}
				for _, cr := range clusterRoles {
					for _, dr := range dangerousRoles {
						if strings.Contains(strings.ToLower(cr), dr) {
							hasHighPrivs = true
							break
						}
					}
				}

				if hasHighPrivs {
					lootExploit = append(lootExploit, fmt.Sprintf("\n# HIGH PRIVILEGE ServiceAccount: %s/%s", ns.Name, sa.Name))
					lootExploit = append(lootExploit, fmt.Sprintf("# Roles: %s", strings.Join(append(roles, clusterRoles...), ", ")))
					lootExploit = append(lootExploit, fmt.Sprintf("# Create a pod using this ServiceAccount:"))
					lootExploit = append(lootExploit, fmt.Sprintf(`cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: privesc-pod-%s
  namespace: %s
spec:
  serviceAccountName: %s
  containers:
  - name: shell
    image: alpine:latest
    command: ["/bin/sh"]
    args: ["-c", "sleep 3600"]
EOF`, sa.Name, ns.Name, sa.Name))
					lootExploit = append(lootExploit, fmt.Sprintf("# Then exec into the pod:"))
					lootExploit = append(lootExploit, fmt.Sprintf("kubectl exec -it privesc-pod-%s -n %s -- /bin/sh", sa.Name, ns.Name))
					lootExploit = append(lootExploit, fmt.Sprintf("# Inside pod, token is at: /var/run/secrets/kubernetes.io/serviceaccount/token"))
					lootExploit = append(lootExploit, "")
				}
			}
		}
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
		logger.InfoM(fmt.Sprintf("%d service accounts found across %d namespaces", len(outputRows), len(namespaces.Items)), globals.K8S_SERVICEACCOUNTS_MODULE_NAME)
	} else {
		logger.InfoM("No service accounts found, skipping output file creation", globals.K8S_SERVICEACCOUNTS_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_SERVICEACCOUNTS_MODULE_NAME), globals.K8S_SERVICEACCOUNTS_MODULE_NAME)
}
