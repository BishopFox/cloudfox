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

// Pod Security Analysis Functions

// GetPodRiskLevel calculates risk level for a pod based on security context
func GetPodRiskLevel(
	privileged bool,
	hostPID bool,
	hostIPC bool,
	hostNetwork bool,
	hostPathCount int,
	writableHostPaths int,
	runAsRoot bool,
	hasDangerousCaps bool,
	allowPrivilegeEscalation bool,
) string {
	// CRITICAL: Privileged + host namespaces + writable host paths = node compromise
	if privileged && (hostPID || hostNetwork || hostIPC) {
		return "CRITICAL"
	}
	if writableHostPaths > 0 && (hostPID || hostNetwork) {
		return "CRITICAL"
	}
	if privileged && writableHostPaths > 0 {
		return "CRITICAL"
	}

	// HIGH: Container escape vectors
	if privileged {
		return "HIGH"
	}
	if hostPID || hostIPC || hostNetwork {
		return "HIGH"
	}
	if writableHostPaths > 0 {
		return "HIGH"
	}
	if hasDangerousCaps {
		return "HIGH"
	}

	// MEDIUM: Potential escape vectors
	if hostPathCount > 0 {
		return "MEDIUM"
	}
	if runAsRoot && allowPrivilegeEscalation {
		return "MEDIUM"
	}

	// LOW: Basic pod with no major risks
	return "LOW"
}

// IsDangerousCapability checks if a capability is dangerous
func IsDangerousCapability(cap string) bool {
	dangerousCaps := []string{
		"SYS_ADMIN",       // Mount, pivot_root, unshare, etc
		"SYS_PTRACE",      // Debug processes, inject code
		"SYS_MODULE",      // Load kernel modules
		"DAC_READ_SEARCH", // Bypass file read permission checks
		"DAC_OVERRIDE",    // Bypass file permission checks
		"SYS_RAWIO",       // Raw I/O operations
		"SYS_CHROOT",      // chroot() escape
		"SYS_BOOT",        // Reboot system
		"NET_ADMIN",       // Network manipulation
		"NET_RAW",         // Raw sockets, packet sniffing
		"SYS_TIME",        // Manipulate system clock
		"SYS_RESOURCE",    // Override resource limits
	}
	return contains(dangerousCaps, cap)
}

// AnalyzeHostPath checks if a host path is sensitive
func AnalyzeHostPath(path string, readOnly bool) (bool, string) {
	sensitivePaths := map[string]string{
		"/":                               "Full host filesystem access",
		"/host":                           "Full host filesystem (mounted at /host)",
		"/var/run/docker.sock":            "Docker socket (container escape)",
		"/var/run/cri-dockerd.sock":       "Docker socket (container escape)",
		"/run/containerd/containerd.sock": "Containerd socket (container escape)",
		"/var/run/crio/crio.sock":         "CRI-O socket (container escape)",
		"/etc":                            "Host configuration files",
		"/etc/kubernetes":                 "Kubernetes configuration",
		"/etc/kubernetes/manifests":       "Static pod manifests",
		"/etc/kubernetes/pki":             "Kubernetes certificates",
		"/var/lib/kubelet":                "Kubelet data directory",
		"/var/lib/kubelet/pki":            "Kubelet certificates",
		"/var/lib/docker":                 "Docker data directory",
		"/var/lib/containerd":             "Containerd data directory",
		"/proc":                           "Host process information",
		"/sys":                            "Host system information",
		"/dev":                            "Host devices",
		"/root":                           "Host root user home",
		"/home":                           "Host user home directories",
	}

	for sensitivePath, description := range sensitivePaths {
		if strings.HasPrefix(path, sensitivePath) || path == sensitivePath {
			return true, description
		}
	}

	return false, ""
}

// GetDeploymentRiskLevel calculates risk level for a deployment's pod template
// This is similar to GetPodRiskLevel but includes deployment-specific factors
func GetDeploymentRiskLevel(
	privileged bool,
	hostPID bool,
	hostIPC bool,
	hostNetwork bool,
	hostPathCount int,
	writableHostPaths int,
	runAsRoot bool,
	hasDangerousCaps bool,
	allowPrivilegeEscalation bool,
	hasImageWithLatestTag bool,
	hasResourceLimits bool,
) string {
	// Use existing pod risk calculation as base
	baseRisk := GetPodRiskLevel(
		privileged,
		hostPID,
		hostIPC,
		hostNetwork,
		hostPathCount,
		writableHostPaths,
		runAsRoot,
		hasDangerousCaps,
		allowPrivilegeEscalation,
	)

	// Additional deployment-specific risk factors
	// HIGH risk + latest tag + no resource limits = CRITICAL (supply chain + DoS risk)
	if baseRisk == "HIGH" && hasImageWithLatestTag && !hasResourceLimits {
		return "CRITICAL"
	}

	// HIGH risk + latest tag (supply chain risk)
	if baseRisk == "HIGH" && hasImageWithLatestTag {
		return "CRITICAL"
	}

	return baseRisk
}

// Service Security Analysis Functions for Endpoints

// ServiceClassification represents a classified service type
type ServiceClassification struct {
	Type        string // Database, Admin, API, ControlPlane, MessageQueue, etc.
	Description string
	IsSensitive bool
}

// ClassifyServiceByPort identifies service type based on port number
func ClassifyServiceByPort(port int32) ServiceClassification {
	serviceMap := map[int32]ServiceClassification{
		// Kubernetes Control Plane
		2379:  {Type: "ControlPlane", Description: "etcd", IsSensitive: true},
		2380:  {Type: "ControlPlane", Description: "etcd peer", IsSensitive: true},
		6443:  {Type: "ControlPlane", Description: "Kubernetes API Server", IsSensitive: true},
		10250: {Type: "ControlPlane", Description: "Kubelet API", IsSensitive: true},
		10255: {Type: "ControlPlane", Description: "Kubelet read-only", IsSensitive: true},
		10256: {Type: "ControlPlane", Description: "kube-proxy health", IsSensitive: false},

		// Databases
		3306:  {Type: "Database", Description: "MySQL/MariaDB", IsSensitive: true},
		5432:  {Type: "Database", Description: "PostgreSQL", IsSensitive: true},
		27017: {Type: "Database", Description: "MongoDB", IsSensitive: true},
		27018: {Type: "Database", Description: "MongoDB shard", IsSensitive: true},
		6379:  {Type: "Database", Description: "Redis", IsSensitive: true},
		9200:  {Type: "Database", Description: "Elasticsearch", IsSensitive: true},
		9300:  {Type: "Database", Description: "Elasticsearch cluster", IsSensitive: true},
		7000:  {Type: "Database", Description: "Cassandra", IsSensitive: true},
		7001:  {Type: "Database", Description: "Cassandra SSL", IsSensitive: true},
		8086:  {Type: "Database", Description: "InfluxDB", IsSensitive: true},
		5984:  {Type: "Database", Description: "CouchDB", IsSensitive: true},
		7474:  {Type: "Database", Description: "Neo4j", IsSensitive: true},
		8529:  {Type: "Database", Description: "ArangoDB", IsSensitive: true},

		// Admin Panels & Monitoring
		8443:  {Type: "Admin", Description: "Kubernetes Dashboard", IsSensitive: true},
		3000:  {Type: "Admin", Description: "Grafana", IsSensitive: true},
		9090:  {Type: "Admin", Description: "Prometheus", IsSensitive: true},
		9093:  {Type: "Admin", Description: "Alertmanager", IsSensitive: true},
		5601:  {Type: "Admin", Description: "Kibana", IsSensitive: true},
		8080:  {Type: "Admin", Description: "Jenkins/Generic Admin", IsSensitive: true},
		8081:  {Type: "Admin", Description: "Generic Admin Panel", IsSensitive: true},
		9000:  {Type: "Admin", Description: "Portainer/SonarQube", IsSensitive: true},
		3001:  {Type: "Admin", Description: "Grafana alternate", IsSensitive: true},
		16686: {Type: "Admin", Description: "Jaeger UI", IsSensitive: false},

		// Message Queues
		5672:  {Type: "MessageQueue", Description: "RabbitMQ AMQP", IsSensitive: true},
		15672: {Type: "MessageQueue", Description: "RabbitMQ Management", IsSensitive: true},
		9092:  {Type: "MessageQueue", Description: "Kafka", IsSensitive: true},
		4222:  {Type: "MessageQueue", Description: "NATS", IsSensitive: true},
		6650:  {Type: "MessageQueue", Description: "Pulsar", IsSensitive: true},
		8161:  {Type: "MessageQueue", Description: "ActiveMQ", IsSensitive: true},

		// Remote Access
		22:   {Type: "RemoteAccess", Description: "SSH", IsSensitive: true},
		3389: {Type: "RemoteAccess", Description: "RDP", IsSensitive: true},
		5900: {Type: "RemoteAccess", Description: "VNC", IsSensitive: true},
		23:   {Type: "RemoteAccess", Description: "Telnet", IsSensitive: true},

		// Web/API
		80:   {Type: "Web", Description: "HTTP", IsSensitive: false},
		443:  {Type: "Web", Description: "HTTPS", IsSensitive: false},
		8000: {Type: "API", Description: "Generic API", IsSensitive: false},
		8888: {Type: "API", Description: "Generic API", IsSensitive: false},

		// CI/CD
		50000: {Type: "CICD", Description: "Jenkins agent", IsSensitive: true},
	}

	if classification, exists := serviceMap[port]; exists {
		return classification
	}

	// Default classification based on port range
	if port < 1024 {
		return ServiceClassification{Type: "System", Description: "System service", IsSensitive: true}
	}
	return ServiceClassification{Type: "Application", Description: "Application service", IsSensitive: false}
}

// GetServiceRiskLevel calculates risk level for a service endpoint
func GetServiceRiskLevel(serviceType string, port int32, isExternal bool, isReady bool, hasAuth bool) string {
	// CRITICAL: External + Unauthenticated + Control Plane
	if isExternal && !hasAuth && serviceType == "ControlPlane" {
		return "CRITICAL"
	}

	// CRITICAL: External + Unauthenticated + Database
	if isExternal && !hasAuth && serviceType == "Database" {
		return "CRITICAL"
	}

	// CRITICAL: Kubernetes control plane exposed internally without auth
	if serviceType == "ControlPlane" && !hasAuth {
		return "CRITICAL"
	}

	// CRITICAL: External admin panels without auth
	if isExternal && !hasAuth && serviceType == "Admin" {
		return "CRITICAL"
	}

	// HIGH: Database without auth (internal)
	if serviceType == "Database" && !hasAuth {
		return "HIGH"
	}

	// HIGH: External remote access
	if isExternal && serviceType == "RemoteAccess" {
		return "HIGH"
	}

	// HIGH: Admin panels without auth (internal)
	if serviceType == "Admin" && !hasAuth {
		return "HIGH"
	}

	// HIGH: External message queues
	if isExternal && serviceType == "MessageQueue" {
		return "HIGH"
	}

	// MEDIUM: Sensitive services with auth
	if (serviceType == "Database" || serviceType == "Admin" || serviceType == "ControlPlane") && hasAuth {
		return "MEDIUM"
	}

	// MEDIUM: External APIs
	if isExternal && serviceType == "API" {
		return "MEDIUM"
	}

	// LOW: Everything else
	return "LOW"
}

// IsUnauthenticatedService checks if a service typically lacks authentication
func IsUnauthenticatedService(port int32, serviceName string) bool {
	// Common services that often don't require authentication in K8s
	unauthenticatedPorts := map[int32]bool{
		6379:  true, // Redis (often no auth in internal deployments)
		27017: true, // MongoDB (default config)
		9200:  true, // Elasticsearch (often open)
		5601:  true, // Kibana (often open)
		9090:  true, // Prometheus (usually open)
		10255: true, // Kubelet read-only (unauthenticated)
		9093:  true, // Alertmanager (often open)
		16686: true, // Jaeger (often open)
	}

	// Check by port
	if unauthenticatedPorts[port] {
		return true
	}

	// Check by service name patterns
	lowerName := strings.ToLower(serviceName)
	if strings.Contains(lowerName, "redis") ||
		strings.Contains(lowerName, "elasticsearch") ||
		strings.Contains(lowerName, "kibana") ||
		strings.Contains(lowerName, "prometheus") ||
		strings.Contains(lowerName, "grafana") {
		return true
	}

	return false
}

// GetServiceExploitationTechniques returns exploit commands for service type
func GetServiceExploitationTechniques(serviceType string, serviceName string, ip string, port int32) []string {
	var techniques []string

	switch serviceType {
	case "ControlPlane":
		if port == 2379 || port == 2380 {
			techniques = append(techniques, fmt.Sprintf("# etcd - Kubernetes secrets database"))
			techniques = append(techniques, fmt.Sprintf("ETCDCTL_API=3 etcdctl --endpoints=https://%s:%d get / --prefix --keys-only", ip, port))
			techniques = append(techniques, fmt.Sprintf("ETCDCTL_API=3 etcdctl --endpoints=https://%s:%d get /registry/secrets --prefix", ip, port))
			techniques = append(techniques, fmt.Sprintf("# Dump all configmaps:"))
			techniques = append(techniques, fmt.Sprintf("ETCDCTL_API=3 etcdctl --endpoints=https://%s:%d get /registry/configmaps --prefix", ip, port))
		} else if port == 10250 {
			techniques = append(techniques, fmt.Sprintf("# Kubelet API - Execute commands in pods"))
			techniques = append(techniques, fmt.Sprintf("curl -k https://%s:%d/pods", ip, port))
			techniques = append(techniques, fmt.Sprintf("curl -k -XPOST https://%s:%d/run/<namespace>/<pod>/<container> -d 'cmd=id'", ip, port))
		} else if port == 10255 {
			techniques = append(techniques, fmt.Sprintf("# Kubelet read-only - No auth required"))
			techniques = append(techniques, fmt.Sprintf("curl http://%s:%d/pods", ip, port))
			techniques = append(techniques, fmt.Sprintf("curl http://%s:%d/spec/", ip, port))
		} else if port == 6443 {
			techniques = append(techniques, fmt.Sprintf("# Kubernetes API Server"))
			techniques = append(techniques, fmt.Sprintf("curl -k https://%s:%d/version", ip, port))
			techniques = append(techniques, fmt.Sprintf("curl -k https://%s:%d/api/v1/namespaces", ip, port))
		}

	case "Database":
		if port == 3306 {
			techniques = append(techniques, fmt.Sprintf("# MySQL/MariaDB"))
			techniques = append(techniques, fmt.Sprintf("mysql -h %s -P %d -u root -p", ip, port))
			techniques = append(techniques, fmt.Sprintf("mysql -h %s -P %d -e 'SHOW DATABASES;'", ip, port))
			techniques = append(techniques, fmt.Sprintf("# Try default creds: root/root, root/<empty>, admin/admin"))
		} else if port == 5432 {
			techniques = append(techniques, fmt.Sprintf("# PostgreSQL"))
			techniques = append(techniques, fmt.Sprintf("psql -h %s -p %d -U postgres", ip, port))
			techniques = append(techniques, fmt.Sprintf("PGPASSWORD=postgres psql -h %s -p %d -U postgres -c '\\l'", ip, port))
		} else if port == 27017 || port == 27018 {
			techniques = append(techniques, fmt.Sprintf("# MongoDB"))
			techniques = append(techniques, fmt.Sprintf("mongo --host %s --port %d", ip, port))
			techniques = append(techniques, fmt.Sprintf("mongosh 'mongodb://%s:%d'", ip, port))
			techniques = append(techniques, fmt.Sprintf("# List databases: show dbs"))
		} else if port == 6379 {
			techniques = append(techniques, fmt.Sprintf("# Redis - Often no authentication"))
			techniques = append(techniques, fmt.Sprintf("redis-cli -h %s -p %d INFO", ip, port))
			techniques = append(techniques, fmt.Sprintf("redis-cli -h %s -p %d KEYS '*'", ip, port))
			techniques = append(techniques, fmt.Sprintf("redis-cli -h %s -p %d CONFIG GET *", ip, port))
			techniques = append(techniques, fmt.Sprintf("# Dump sensitive data:"))
			techniques = append(techniques, fmt.Sprintf("redis-cli -h %s -p %d --scan --pattern 'session:*'", ip, port))
		} else if port == 9200 || port == 9300 {
			techniques = append(techniques, fmt.Sprintf("# Elasticsearch"))
			techniques = append(techniques, fmt.Sprintf("curl http://%s:%d/", ip, port))
			techniques = append(techniques, fmt.Sprintf("curl http://%s:%d/_cat/indices?v", ip, port))
			techniques = append(techniques, fmt.Sprintf("curl http://%s:%d/_search?pretty", ip, port))
			techniques = append(techniques, fmt.Sprintf("curl http://%s:%d/_cluster/health?pretty", ip, port))
		}

	case "Admin":
		if port == 3000 || port == 3001 {
			techniques = append(techniques, fmt.Sprintf("# Grafana - Try default admin:admin"))
			techniques = append(techniques, fmt.Sprintf("curl http://%s:%d/login", ip, port))
			techniques = append(techniques, fmt.Sprintf("curl -u admin:admin http://%s:%d/api/datasources", ip, port))
		} else if port == 9090 {
			techniques = append(techniques, fmt.Sprintf("# Prometheus - Usually open"))
			techniques = append(techniques, fmt.Sprintf("curl http://%s:%d/api/v1/targets", ip, port))
			techniques = append(techniques, fmt.Sprintf("curl http://%s:%d/api/v1/query?query=up", ip, port))
			techniques = append(techniques, fmt.Sprintf("# Find secrets in metrics:"))
			techniques = append(techniques, fmt.Sprintf("curl http://%s:%d/api/v1/label/__name__/values | grep -i secret", ip, port))
		} else if port == 5601 {
			techniques = append(techniques, fmt.Sprintf("# Kibana"))
			techniques = append(techniques, fmt.Sprintf("curl http://%s:%d/api/status", ip, port))
			techniques = append(techniques, fmt.Sprintf("curl http://%s:%d/", ip, port))
		} else if port == 8443 {
			techniques = append(techniques, fmt.Sprintf("# Kubernetes Dashboard"))
			techniques = append(techniques, fmt.Sprintf("curl -k https://%s:%d/", ip, port))
		}

	case "MessageQueue":
		if port == 5672 {
			techniques = append(techniques, fmt.Sprintf("# RabbitMQ AMQP"))
			techniques = append(techniques, fmt.Sprintf("# Connect with guest:guest (default)"))
		} else if port == 15672 {
			techniques = append(techniques, fmt.Sprintf("# RabbitMQ Management - Try guest:guest"))
			techniques = append(techniques, fmt.Sprintf("curl -u guest:guest http://%s:%d/api/overview", ip, port))
			techniques = append(techniques, fmt.Sprintf("curl -u guest:guest http://%s:%d/api/queues", ip, port))
		} else if port == 9092 {
			techniques = append(techniques, fmt.Sprintf("# Kafka"))
			techniques = append(techniques, fmt.Sprintf("kafka-topics.sh --bootstrap-server %s:%d --list", ip, port))
		}

	case "RemoteAccess":
		if port == 22 {
			techniques = append(techniques, fmt.Sprintf("# SSH"))
			techniques = append(techniques, fmt.Sprintf("ssh root@%s -p %d", ip, port))
			techniques = append(techniques, fmt.Sprintf("nmap -p %d -sV %s", port, ip))
		}
	}

	// Generic techniques for any service
	if len(techniques) == 0 {
		techniques = append(techniques, fmt.Sprintf("# Generic reconnaissance"))
		techniques = append(techniques, fmt.Sprintf("nc -zv %s %d", ip, port))
		techniques = append(techniques, fmt.Sprintf("nmap -sV -p %d %s", port, ip))
	}

	return techniques
}

// GetDatabaseConnectionString generates connection string for database type
func GetDatabaseConnectionString(dbType string, ip string, port int32, username string, database string) string {
	switch dbType {
	case "MySQL", "MariaDB":
		return fmt.Sprintf("mysql -h %s -P %d -u %s -p %s", ip, port, username, database)
	case "PostgreSQL":
		return fmt.Sprintf("psql -h %s -p %d -U %s -d %s", ip, port, username, database)
	case "MongoDB":
		return fmt.Sprintf("mongosh 'mongodb://%s:%s@%s:%d/%s'", username, "<password>", ip, port, database)
	case "Redis":
		return fmt.Sprintf("redis-cli -h %s -p %d", ip, port)
	case "Elasticsearch":
		return fmt.Sprintf("curl http://%s:%d", ip, port)
	default:
		return fmt.Sprintf("# Connect to %s at %s:%d", dbType, ip, port)
	}
}

// IsSensitiveService checks if a service type is sensitive
func IsSensitiveService(serviceType string) bool {
	sensitiveTypes := []string{
		"ControlPlane",
		"Database",
		"Admin",
		"RemoteAccess",
		"MessageQueue",
		"CICD",
	}
	return contains(sensitiveTypes, serviceType)
}
