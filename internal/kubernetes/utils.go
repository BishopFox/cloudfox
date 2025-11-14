package kubernetes

import (
	"encoding/json"
	"fmt"
	"strings"

	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// FindMountPath locates the mount path for a given volume name in the provided containers.
func FindMountPath(volumeName string, containers []v1.Container) string {
	for _, c := range containers {
		for _, m := range c.VolumeMounts {
			if m.Name == volumeName {
				return m.MountPath
			}
		}
	}
	return "<NONE>"
}

// NonEmpty normalizes empty, dash, or whitespace-only strings to "<NONE>".
func NonEmpty(value string) string {
	if strings.TrimSpace(value) == "" || value == "-" {
		return "<NONE>"
	}
	return value
}

// SafeInt32Ptr safely dereferences an *int32, returning "<NONE>" if nil
func SafeInt32Ptr(p *int32) string {
	if p == nil {
		return "<NONE>"
	}
	return fmt.Sprintf("%d", *p)
}

// SafeBoolPtr safely dereferences a *bool, returning "<NONE>" if nil
func SafeBoolPtr(p *bool) string {
	if p == nil {
		return "<NONE>"
	}
	return fmt.Sprintf("%v", *p)
}

// SafeStringPtr safely dereferences a *string, returning "<NONE>" if nil
func SafeStringPtr(p *string) string {
	if p == nil {
		return "<NONE>"
	}
	return *p
}

func SafeBool(val bool) string {
	return fmt.Sprintf("%v", val)
}

func SafeInt32(val *int32) string {
	if val == nil {
		return "nil"
	}
	return fmt.Sprintf("%d", *val)
}

// MapToStringList converts a map[string]string to a []string of "key=value"
func MapToStringList(m map[string]string) []string {
	result := []string{}
	for k, v := range m {
		result = append(result, fmt.Sprintf("%s=%s", k, v))
	}
	return result
}

// SelectorMatch returns the label selector match labels as key=value strings
func SelectorMatch(sel *metav1.LabelSelector) []string {
	if sel == nil {
		return []string{}
	}
	return MapToStringList(sel.MatchLabels)
}

// Unique removes duplicate strings from a slice
func Unique(input []string) []string {
	seen := make(map[string]struct{})
	result := []string{}
	for _, val := range input {
		if _, ok := seen[val]; !ok {
			seen[val] = struct{}{}
			result = append(result, val)
		}
	}
	return result
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func IsDangerousRule(rule rbacv1.PolicyRule) bool {
	// Check for wildcard permissions - CRITICAL
	for _, verb := range rule.Verbs {
		if verb == "*" {
			return true
		}
	}
	for _, res := range rule.Resources {
		if res == "*" {
			return true
		}
	}

	// Define dangerous permission categories
	rbacModification := []string{"roles", "rolebindings", "clusterroles", "clusterrolebindings"}
	secretAccess := []string{"secrets", "configmaps"}
	impersonation := []string{"users", "groups", "serviceaccounts"}
	podExecution := []string{"pods/exec", "pods/attach", "pods/portforward"}
	privilegedWorkloads := []string{"pods", "daemonsets", "deployments", "statefulsets", "replicasets", "jobs", "cronjobs"}
	admissionControl := []string{"validatingwebhookconfigurations", "mutatingwebhookconfigurations"}
	certApproval := []string{"certificatesigningrequests", "certificatesigningrequests/approval"}
	nodeAccess := []string{"nodes", "nodes/proxy"}
	volumeAccess := []string{"persistentvolumes", "persistentvolumeclaims"}

	modifyVerbs := []string{"create", "update", "patch", "delete"}
	readVerbs := []string{"get", "list"}

	for _, verb := range rule.Verbs {
		for _, res := range rule.Resources {
			// RBAC modification - HIGH
			if contains(modifyVerbs, verb) && contains(rbacModification, res) {
				return true
			}

			// Secret/ConfigMap modification - HIGH
			if contains(modifyVerbs, verb) && contains(secretAccess, res) {
				return true
			}

			// Impersonation - HIGH
			if verb == "impersonate" && contains(impersonation, res) {
				return true
			}

			// Pod execution - HIGH (can extract secrets, execute commands)
			if (verb == "create" || verb == "get") && contains(podExecution, res) {
				return true
			}

			// Privileged workload creation - MEDIUM to HIGH
			if contains(modifyVerbs, verb) && contains(privilegedWorkloads, res) {
				return true
			}

			// Admission webhook control - CRITICAL (can intercept/modify all requests)
			if contains(modifyVerbs, verb) && contains(admissionControl, res) {
				return true
			}

			// Certificate approval - HIGH (can create admin certs)
			if (verb == "create" || verb == "update" || verb == "approve") && contains(certApproval, res) {
				return true
			}

			// Node modification - HIGH (can taint, drain, modify kubelet)
			if contains(modifyVerbs, verb) && contains(nodeAccess, res) {
				return true
			}

			// Volume access - MEDIUM (can read sensitive data)
			if contains(modifyVerbs, verb) && contains(volumeAccess, res) {
				return true
			}

			// Secret read access - MEDIUM
			if contains(readVerbs, verb) && res == "secrets" {
				return true
			}
		}
	}
	return false
}

func RuleToString(rule rbacv1.PolicyRule) string {
	return fmt.Sprintf("verbs=%v resources=%v apiGroups=%v", rule.Verbs, rule.Resources, rule.APIGroups)
}

// GetRuleRiskLevel returns the risk level of a policy rule
// Returns: "CRITICAL", "HIGH", "MEDIUM", "LOW", or "" if not dangerous
func GetRuleRiskLevel(rule rbacv1.PolicyRule) string {
	// Check for wildcard permissions - CRITICAL
	for _, verb := range rule.Verbs {
		if verb == "*" {
			return "CRITICAL"
		}
	}
	for _, res := range rule.Resources {
		if res == "*" {
			return "CRITICAL"
		}
	}

	// Define dangerous permission categories
	rbacModification := []string{"roles", "rolebindings", "clusterroles", "clusterrolebindings"}
	secretAccess := []string{"secrets", "configmaps"}
	impersonation := []string{"users", "groups", "serviceaccounts"}
	podExecution := []string{"pods/exec", "pods/attach", "pods/portforward"}
	privilegedWorkloads := []string{"pods", "daemonsets", "deployments", "statefulsets", "replicasets", "jobs", "cronjobs"}
	admissionControl := []string{"validatingwebhookconfigurations", "mutatingwebhookconfigurations"}
	certApproval := []string{"certificatesigningrequests", "certificatesigningrequests/approval"}
	nodeAccess := []string{"nodes", "nodes/proxy"}
	volumeAccess := []string{"persistentvolumes", "persistentvolumeclaims"}

	modifyVerbs := []string{"create", "update", "patch", "delete"}
	readVerbs := []string{"get", "list"}

	highestRisk := ""

	for _, verb := range rule.Verbs {
		for _, res := range rule.Resources {
			// Admission webhook control - CRITICAL
			if contains(modifyVerbs, verb) && contains(admissionControl, res) {
				return "CRITICAL" // Return immediately for CRITICAL
			}

			// RBAC modification - HIGH
			if contains(modifyVerbs, verb) && contains(rbacModification, res) {
				if highestRisk == "" || highestRisk == "MEDIUM" || highestRisk == "LOW" {
					highestRisk = "HIGH"
				}
			}

			// Secret/ConfigMap modification - HIGH
			if contains(modifyVerbs, verb) && contains(secretAccess, res) {
				if highestRisk == "" || highestRisk == "MEDIUM" || highestRisk == "LOW" {
					highestRisk = "HIGH"
				}
			}

			// Impersonation - HIGH
			if verb == "impersonate" && contains(impersonation, res) {
				if highestRisk == "" || highestRisk == "MEDIUM" || highestRisk == "LOW" {
					highestRisk = "HIGH"
				}
			}

			// Pod execution - HIGH
			if (verb == "create" || verb == "get") && contains(podExecution, res) {
				if highestRisk == "" || highestRisk == "MEDIUM" || highestRisk == "LOW" {
					highestRisk = "HIGH"
				}
			}

			// Certificate approval - HIGH
			if (verb == "create" || verb == "update" || verb == "approve") && contains(certApproval, res) {
				if highestRisk == "" || highestRisk == "MEDIUM" || highestRisk == "LOW" {
					highestRisk = "HIGH"
				}
			}

			// Node modification - HIGH
			if contains(modifyVerbs, verb) && contains(nodeAccess, res) {
				if highestRisk == "" || highestRisk == "MEDIUM" || highestRisk == "LOW" {
					highestRisk = "HIGH"
				}
			}

			// Privileged workload creation - MEDIUM
			if contains(modifyVerbs, verb) && contains(privilegedWorkloads, res) {
				if highestRisk == "" || highestRisk == "LOW" {
					highestRisk = "MEDIUM"
				}
			}

			// Volume access - MEDIUM
			if contains(modifyVerbs, verb) && contains(volumeAccess, res) {
				if highestRisk == "" || highestRisk == "LOW" {
					highestRisk = "MEDIUM"
				}
			}

			// Secret read access - MEDIUM
			if contains(readVerbs, verb) && res == "secrets" {
				if highestRisk == "" || highestRisk == "LOW" {
					highestRisk = "MEDIUM"
				}
			}
		}
	}

	return highestRisk
}

// GetRuleRiskDescription returns a human-readable description of why a rule is dangerous
func GetRuleRiskDescription(rule rbacv1.PolicyRule) string {
	var descriptions []string

	// Check for wildcard permissions
	for _, verb := range rule.Verbs {
		if verb == "*" {
			descriptions = append(descriptions, "wildcard verbs (*)")
		}
	}
	for _, res := range rule.Resources {
		if res == "*" {
			descriptions = append(descriptions, "wildcard resources (*)")
		}
	}

	rbacModification := []string{"roles", "rolebindings", "clusterroles", "clusterrolebindings"}
	secretAccess := []string{"secrets", "configmaps"}
	impersonation := []string{"users", "groups", "serviceaccounts"}
	podExecution := []string{"pods/exec", "pods/attach", "pods/portforward"}
	privilegedWorkloads := []string{"pods", "daemonsets", "deployments", "statefulsets", "replicasets", "jobs", "cronjobs"}
	admissionControl := []string{"validatingwebhookconfigurations", "mutatingwebhookconfigurations"}
	certApproval := []string{"certificatesigningrequests", "certificatesigningrequests/approval"}
	nodeAccess := []string{"nodes", "nodes/proxy"}
	volumeAccess := []string{"persistentvolumes", "persistentvolumeclaims"}

	modifyVerbs := []string{"create", "update", "patch", "delete"}
	readVerbs := []string{"get", "list"}

	for _, verb := range rule.Verbs {
		for _, res := range rule.Resources {
			if contains(modifyVerbs, verb) && contains(rbacModification, res) {
				descriptions = append(descriptions, fmt.Sprintf("can %s %s (RBAC escalation)", verb, res))
			}
			if contains(modifyVerbs, verb) && contains(secretAccess, res) {
				descriptions = append(descriptions, fmt.Sprintf("can %s %s (credential access)", verb, res))
			}
			if verb == "impersonate" && contains(impersonation, res) {
				descriptions = append(descriptions, fmt.Sprintf("can impersonate %s", res))
			}
			if (verb == "create" || verb == "get") && contains(podExecution, res) {
				descriptions = append(descriptions, fmt.Sprintf("can execute into pods via %s", res))
			}
			if contains(modifyVerbs, verb) && contains(privilegedWorkloads, res) {
				descriptions = append(descriptions, fmt.Sprintf("can %s %s (workload manipulation)", verb, res))
			}
			if contains(modifyVerbs, verb) && contains(admissionControl, res) {
				descriptions = append(descriptions, fmt.Sprintf("can %s %s (cluster-wide interception)", verb, res))
			}
			if (verb == "create" || verb == "update" || verb == "approve") && contains(certApproval, res) {
				descriptions = append(descriptions, fmt.Sprintf("can %s certificates (auth bypass)", verb))
			}
			if contains(modifyVerbs, verb) && contains(nodeAccess, res) {
				descriptions = append(descriptions, fmt.Sprintf("can %s %s (node compromise)", verb, res))
			}
			if contains(modifyVerbs, verb) && contains(volumeAccess, res) {
				descriptions = append(descriptions, fmt.Sprintf("can %s %s (data access)", verb, res))
			}
			if contains(readVerbs, verb) && res == "secrets" {
				descriptions = append(descriptions, fmt.Sprintf("can read secrets"))
			}
		}
	}

	if len(descriptions) == 0 {
		return RuleToString(rule)
	}
	return strings.Join(descriptions, "; ")
}

func UniqueStrings(input []string) []string {
	seen := map[string]bool{}
	var result []string
	for _, item := range input {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}

// PrettyPrintAffinity converts Affinity object to a compact JSON string
func PrettyPrintAffinity(affinity *v1.Affinity) string {
	if affinity == nil {
		return "<NONE>"
	}
	b, err := json.MarshalIndent(affinity, "", "  ")
	if err != nil {
		return "<ERROR>"
	}
	return string(b)
}

// Webhook Security Analysis Functions

// IsWebhookExternalURL checks if a webhook URL is external (not in-cluster)
func IsWebhookExternalURL(url string) bool {
	if url == "" || url == "<none>" || url == "<N/A>" || url == "<external URL>" {
		return false
	}
	// External URLs start with http:// or https://
	return strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://")
}

// IsSensitiveResource checks if a resource is security-sensitive
func IsSensitiveResource(resource string) bool {
	sensitiveResources := []string{
		"secrets",
		"configmaps",
		"pods",
		"serviceaccounts",
		"roles",
		"rolebindings",
		"clusterroles",
		"clusterrolebindings",
		"certificatesigningrequests",
		"nodes",
		"persistentvolumes",
		"persistentvolumeclaims",
	}
	return contains(sensitiveResources, resource)
}

// HasWildcardOperations checks if operations list contains wildcards
func HasWildcardOperations(operations []string) bool {
	for _, op := range operations {
		if op == "*" {
			return true
		}
	}
	return false
}

// HasWildcardResources checks if resources list contains wildcards
func HasWildcardResources(resources []string) bool {
	for _, res := range resources {
		if res == "*" {
			return true
		}
	}
	return false
}

// GetWebhookRiskLevel calculates risk level for a webhook configuration
// Factors: external URL, missing CABundle, wildcards, sensitive resources, failure policy, timeout
func GetWebhookRiskLevel(
	isExternal bool,
	hasCABundle bool,
	hasWildcardOps bool,
	hasWildcardRes bool,
	interceptsSensitive bool,
	failurePolicy string,
	timeoutSeconds int32,
) string {
	// CRITICAL: External URL without CABundle or with Fail policy (can DOS cluster)
	if isExternal && !hasCABundle {
		return "CRITICAL"
	}
	if isExternal && failurePolicy == "Fail" {
		return "CRITICAL"
	}

	// CRITICAL: Wildcard operations or resources (intercepts everything)
	if hasWildcardOps || hasWildcardRes {
		return "CRITICAL"
	}

	// HIGH: External URL (exfiltration risk)
	if isExternal {
		return "HIGH"
	}

	// HIGH: Intercepts sensitive resources with Fail policy
	if interceptsSensitive && failurePolicy == "Fail" {
		return "HIGH"
	}

	// HIGH: Missing CABundle (MITM vulnerable)
	if !hasCABundle && failurePolicy == "Fail" {
		return "HIGH"
	}

	// MEDIUM: Intercepts sensitive resources
	if interceptsSensitive {
		return "MEDIUM"
	}

	// MEDIUM: Long timeout (>20s) with Fail policy (DOS risk)
	if timeoutSeconds > 20 && failurePolicy == "Fail" {
		return "MEDIUM"
	}

	// LOW: Basic webhook with no major risks
	return "LOW"
}

// GetWebhookRiskDescription returns human-readable risk description
func GetWebhookRiskDescription(
	isExternal bool,
	hasCABundle bool,
	hasWildcardOps bool,
	hasWildcardRes bool,
	interceptsSensitive bool,
	failurePolicy string,
	timeoutSeconds int32,
	sensitiveResources []string,
) string {
	var risks []string

	if isExternal {
		risks = append(risks, "EXTERNAL URL (data exfiltration risk)")
	}
	if !hasCABundle {
		risks = append(risks, "MISSING CABundle (MITM vulnerable)")
	}
	if hasWildcardOps {
		risks = append(risks, "WILDCARD operations (*)")
	}
	if hasWildcardRes {
		risks = append(risks, "WILDCARD resources (*)")
	}
	if interceptsSensitive && len(sensitiveResources) > 0 {
		risks = append(risks, fmt.Sprintf("intercepts sensitive resources: %s", strings.Join(sensitiveResources, ", ")))
	}
	if failurePolicy == "Fail" {
		risks = append(risks, "FailurePolicy=Fail (blocks on webhook failure)")
	}
	if timeoutSeconds > 20 {
		risks = append(risks, fmt.Sprintf("long timeout (%ds, DOS risk)", timeoutSeconds))
	}

	if len(risks) == 0 {
		return "no major security risks detected"
	}
	return strings.Join(risks, "; ")
}

// Secret Security Analysis Functions

// GetSecretRiskLevel calculates risk level for a secret
// Factors: type, sensitive patterns, active exposure, RBAC access
func GetSecretRiskLevel(
	secretType string,
	hasSensitivePattern bool,
	mountedInPods int,
	readableByNonDefaultSAs int,
	hasCloudCreds bool,
	hasPrivateKeys bool,
	hasServiceAccountToken bool,
	saHasDangerousPerms bool,
) string {
	// CRITICAL: Cloud credentials or private keys mounted in pods or widely accessible
	if hasCloudCreds && (mountedInPods > 0 || readableByNonDefaultSAs > 5) {
		return "CRITICAL"
	}
	if hasPrivateKeys && mountedInPods > 0 {
		return "CRITICAL"
	}
	if hasServiceAccountToken && saHasDangerousPerms {
		return "CRITICAL"
	}

	// HIGH: Sensitive secrets actively exposed or widely readable
	if hasSensitivePattern && mountedInPods > 0 {
		return "HIGH"
	}
	if hasCloudCreds || hasPrivateKeys {
		return "HIGH"
	}
	if readableByNonDefaultSAs > 10 {
		return "HIGH"
	}

	// MEDIUM: Sensitive secrets not actively exposed
	if hasSensitivePattern {
		return "MEDIUM"
	}
	if mountedInPods > 0 {
		return "MEDIUM"
	}
	if readableByNonDefaultSAs > 3 {
		return "MEDIUM"
	}

	// LOW: Basic secrets with limited exposure
	return "LOW"
}

// DetectSensitiveSecretPattern checks if secret contains sensitive data patterns
func DetectSensitiveSecretPattern(secretType, secretName string, dataKeys []string) (bool, []string) {
	var patterns []string

	// Type-based detection
	if secretType == "kubernetes.io/dockerconfigjson" {
		patterns = append(patterns, "Docker registry credentials")
	}
	if secretType == "kubernetes.io/tls" {
		patterns = append(patterns, "TLS certificate/private key")
	}
	if secretType == "kubernetes.io/ssh-auth" {
		patterns = append(patterns, "SSH authentication key")
	}
	if secretType == "kubernetes.io/basic-auth" {
		patterns = append(patterns, "Basic authentication credentials")
	}

	// Key-based detection
	for _, key := range dataKeys {
		keyLower := strings.ToLower(key)

		// Cloud provider credentials
		if keyLower == "aws_access_key_id" || keyLower == "aws_secret_access_key" || strings.Contains(keyLower, "aws") {
			patterns = append(patterns, "AWS credentials")
		}
		if keyLower == "credentials.json" || keyLower == "key.json" || strings.Contains(keyLower, "gcp") || strings.Contains(keyLower, "google") {
			patterns = append(patterns, "GCP credentials")
		}
		if strings.Contains(keyLower, "azure") || keyLower == "client_secret" || keyLower == "tenant_id" {
			patterns = append(patterns, "Azure credentials")
		}

		// Authentication credentials
		if strings.Contains(keyLower, "password") || strings.Contains(keyLower, "passwd") {
			patterns = append(patterns, "password")
		}
		if strings.Contains(keyLower, "token") || strings.Contains(keyLower, "api_key") || strings.Contains(keyLower, "apikey") {
			patterns = append(patterns, "API token/key")
		}

		// Private keys
		if strings.Contains(keyLower, "private_key") || strings.Contains(keyLower, "id_rsa") || strings.Contains(keyLower, "id_ed25519") || keyLower == "tls.key" {
			patterns = append(patterns, "private key")
		}

		// Database credentials
		if strings.Contains(keyLower, "database") || strings.Contains(keyLower, "db_") || strings.Contains(keyLower, "connection_string") || keyLower == "username" {
			patterns = append(patterns, "database credentials")
		}
	}

	// Name-based detection
	nameLower := strings.ToLower(secretName)
	if strings.Contains(nameLower, "admin") {
		patterns = append(patterns, "admin credentials")
	}
	if strings.Contains(nameLower, "root") {
		patterns = append(patterns, "root credentials")
	}

	return len(patterns) > 0, UniqueStrings(patterns)
}

// HasCloudCredentials checks if secret contains cloud provider credentials
func HasCloudCredentials(dataKeys []string) bool {
	for _, key := range dataKeys {
		keyLower := strings.ToLower(key)
		if strings.Contains(keyLower, "aws") || strings.Contains(keyLower, "gcp") || strings.Contains(keyLower, "google") || strings.Contains(keyLower, "azure") || keyLower == "credentials.json" || keyLower == "key.json" {
			return true
		}
	}
	return false
}

// HasPrivateKeys checks if secret contains private keys
func HasPrivateKeys(secretType string, dataKeys []string) bool {
	if secretType == "kubernetes.io/tls" || secretType == "kubernetes.io/ssh-auth" {
		return true
	}
	for _, key := range dataKeys {
		keyLower := strings.ToLower(key)
		if strings.Contains(keyLower, "private_key") || strings.Contains(keyLower, "id_rsa") || strings.Contains(keyLower, "id_ed25519") || keyLower == "tls.key" {
			return true
		}
	}
	return false
}
