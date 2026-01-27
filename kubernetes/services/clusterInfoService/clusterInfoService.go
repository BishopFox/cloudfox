package clusterInfoService

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/kubernetes/sdk"
	"github.com/BishopFox/cloudfox/kubernetes/services/models"
	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// ClusterInfoService provides methods to get cluster and identity information
type ClusterInfoService struct {
	clientset *kubernetes.Clientset
}

// New creates a new ClusterInfoService using the shared clientset
func New() (*ClusterInfoService, error) {
	clientset, err := sdk.GetClientset()
	if err != nil {
		return nil, fmt.Errorf("failed to get clientset: %w", err)
	}
	return &ClusterInfoService{clientset: clientset}, nil
}

// NewWithClientset creates a ClusterInfoService with a specific clientset
func NewWithClientset(clientset *kubernetes.Clientset) *ClusterInfoService {
	return &ClusterInfoService{clientset: clientset}
}

// GetClusterInfo returns comprehensive information about the cluster
func (s *ClusterInfoService) GetClusterInfo(ctx context.Context) (*models.ClusterInfo, error) {
	// Try cache first
	cacheKey := sdk.CacheKey("cluster-info")
	if cached, found := sdk.Get(cacheKey); found {
		if info, ok := cached.(*models.ClusterInfo); ok {
			return info, nil
		}
	}

	info := &models.ClusterInfo{}

	// Use cluster name from globals (set by CLI using internal/kubernetes/clustername.go)
	info.Name = globals.ClusterName

	// Get API server URL
	if s.clientset.RESTClient() != nil {
		apiURL := s.clientset.RESTClient().Get().URL()
		if apiURL != nil {
			info.APIServerURL = fmt.Sprintf("%s://%s", apiURL.Scheme, apiURL.Host)
		}
	}

	// Get version info
	if version, err := s.clientset.Discovery().ServerVersion(); err == nil {
		info.Version = &models.VersionInfo{
			Major:      version.Major,
			Minor:      version.Minor,
			GitVersion: version.GitVersion,
			Platform:   version.Platform,
		}
	}

	// Detect cloud provider and metadata from nodes
	s.detectCloudMetadata(ctx, info)

	// Cache the result
	sdk.Set(cacheKey, info)

	return info, nil
}

// GetIdentity returns the current authenticated identity
func (s *ClusterInfoService) GetIdentity(ctx context.Context) (*models.Identity, error) {
	// Try cache first
	cacheKey := sdk.CacheKey("identity")
	if cached, found := sdk.Get(cacheKey); found {
		if identity, ok := cached.(*models.Identity); ok {
			return identity, nil
		}
	}

	identity := &models.Identity{
		Source: models.IdentitySourceUnknown,
	}

	// Method 1: Try kubeconfig extraction
	if user := s.extractUserFromKubeconfig(); user != "" {
		identity.KubeconfigUser = user
	}

	// Method 2: Try modern SelfSubjectReview API (K8s 1.27+)
	if username, groups, err := s.trySelfSubjectReview(ctx); err == nil {
		identity.Username = username
		identity.Groups = groups
		identity.Source = models.IdentitySourceSelfSubjectReview
	} else {
		// Fallback: Try forbidden error parsing
		if username, groups := s.tryForbiddenErrorParsing(ctx); username != "" {
			identity.Username = username
			identity.Groups = groups
			identity.Source = models.IdentitySourceForbiddenError
		}
	}

	// Method 3: Try ServiceAccount token decoding (in-cluster)
	if ns, name, err := s.decodeServiceAccountToken(); err == nil {
		identity.ServiceAccountNamespace = ns
		identity.ServiceAccountName = name
		if identity.Source == models.IdentitySourceUnknown {
			identity.Source = models.IdentitySourceServiceAccountToken
			identity.Username = fmt.Sprintf("system:serviceaccount:%s:%s", ns, name)
		}
	}

	// Method 4: Extract RBAC binding info from SelfSubjectAccessReview
	s.extractRBACInfo(ctx, identity)

	// If still no username, use kubeconfig user
	if identity.Username == "" && identity.KubeconfigUser != "" {
		identity.Username = identity.KubeconfigUser
		identity.Source = models.IdentitySourceKubeconfig
	}

	// Cache the result
	sdk.Set(cacheKey, identity)

	return identity, nil
}

// GetPermissions enumerates permissions across namespaces
func (s *ClusterInfoService) GetPermissions(ctx context.Context, namespaces []string) (*models.PermissionSummary, error) {
	summary := &models.PermissionSummary{
		NamespacePermissions: make(map[string][]string),
		DangerousPerms:       []DangerousPermission{},
	}

	for _, ns := range namespaces {
		perms, dangerous := s.enumerateNamespacePermissions(ctx, ns)
		if len(perms) > 0 {
			summary.NamespacePermissions[ns] = perms
			summary.TotalPermissions += len(perms)
		}
		summary.DangerousPerms = append(summary.DangerousPerms, dangerous...)
	}

	summary.TotalNamespaces = len(summary.NamespacePermissions)
	summary.DangerousPermissions = len(summary.DangerousPerms)

	// Calculate risk level
	summary.RiskLevel = s.calculateRiskLevel(summary)

	return summary, nil
}

// GetWhoami returns comprehensive whoami information
func (s *ClusterInfoService) GetWhoami(ctx context.Context) (*models.WhoamiResult, error) {
	result := &models.WhoamiResult{}

	// Get cluster info
	clusterInfo, err := s.GetClusterInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get cluster info: %w", err)
	}
	result.Cluster = *clusterInfo

	// Get identity
	identity, err := s.GetIdentity(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get identity: %w", err)
	}
	result.Identity = *identity

	// Get namespaces for permission enumeration
	namespaces := s.getNamespaces(ctx)

	// Get permissions
	permissions, err := s.GetPermissions(ctx, namespaces)
	if err != nil {
		return nil, fmt.Errorf("failed to get permissions: %w", err)
	}

	// Enrich with source information from RBAC
	permissionsWithSource := s.enumeratePermissionsWithSource(ctx, identity)
	permissions.PermissionsWithSource = permissionsWithSource

	result.Permissions = *permissions

	// Adjust risk level based on RBAC
	if identity.IsClusterAdmin() && result.Permissions.RiskLevel != "CRITICAL" {
		result.Permissions.RiskLevel = "CRITICAL"
	}

	return result, nil
}

// enumeratePermissionsWithSource finds all permissions for the identity with their RBAC sources
func (s *ClusterInfoService) enumeratePermissionsWithSource(ctx context.Context, identity *models.Identity) []models.PermissionWithSource {
	var perms []models.PermissionWithSource

	// Build set of principals that match this identity
	principals := s.buildPrincipalSet(identity)

	// Get ClusterRoles for reference (cached)
	clusterRolesList, err := sdk.GetClusterRoles(ctx, s.clientset)
	if err != nil {
		return perms
	}
	crMap := make(map[string]*rbacv1.ClusterRole)
	for i := range clusterRolesList {
		crMap[clusterRolesList[i].Name] = &clusterRolesList[i]
	}

	// Check ClusterRoleBindings (cached)
	crbsList, err := sdk.GetClusterRoleBindings(ctx, s.clientset)
	if err == nil {
		for _, crb := range crbsList {
			// Find which subjects match the identity
			matchedSubjects := s.findMatchingSubjects(crb.Subjects, principals)
			if len(matchedSubjects) == 0 {
				continue
			}

			cr, ok := crMap[crb.RoleRef.Name]
			if !ok {
				continue
			}

			// Extract permissions from this ClusterRole for each matching subject
			for _, subject := range matchedSubjects {
				for _, rule := range cr.Rules {
					rulePerms := s.extractPermissionsFromRule(rule, "cluster-wide", cr.Name, "ClusterRole", crb.Name, "ClusterRoleBinding", subject)
					perms = append(perms, rulePerms...)
				}
			}
		}
	}

	// Get all Roles (cached) and build map by namespace
	allRolesList, err := sdk.GetRoles(ctx, s.clientset)
	if err != nil {
		allRolesList = []rbacv1.Role{}
	}
	// Build namespace -> role name -> role map
	rolesByNS := make(map[string]map[string]*rbacv1.Role)
	for i := range allRolesList {
		role := &allRolesList[i]
		if rolesByNS[role.Namespace] == nil {
			rolesByNS[role.Namespace] = make(map[string]*rbacv1.Role)
		}
		rolesByNS[role.Namespace][role.Name] = role
	}

	// Get all RoleBindings (cached)
	allRBsList, err := sdk.GetRoleBindings(ctx, s.clientset)
	if err != nil {
		allRBsList = []rbacv1.RoleBinding{}
	}

	// Check RoleBindings in each namespace
	namespaces := s.getNamespaces(ctx)
	nsSet := make(map[string]struct{})
	for _, ns := range namespaces {
		nsSet[ns] = struct{}{}
	}

	for _, rb := range allRBsList {
		// Only process RoleBindings in target namespaces
		if _, ok := nsSet[rb.Namespace]; !ok {
			continue
		}

		// Find which subjects match the identity
		matchedSubjects := s.findMatchingSubjects(rb.Subjects, principals)
		if len(matchedSubjects) == 0 {
			continue
		}

		var rules []rbacv1.PolicyRule
		var roleName, roleKind string

		if rb.RoleRef.Kind == "Role" {
			if roleMap, ok := rolesByNS[rb.Namespace]; ok {
				if role, ok := roleMap[rb.RoleRef.Name]; ok {
					rules = role.Rules
					roleName = role.Name
					roleKind = "Role"
				}
			}
		} else if rb.RoleRef.Kind == "ClusterRole" {
			if cr, ok := crMap[rb.RoleRef.Name]; ok {
				rules = cr.Rules
				roleName = cr.Name
				roleKind = "ClusterRole"
			}
		}

		for _, subject := range matchedSubjects {
			for _, rule := range rules {
				rulePerms := s.extractPermissionsFromRule(rule, rb.Namespace, roleName, roleKind, rb.Name, "RoleBinding", subject)
				perms = append(perms, rulePerms...)
			}
		}
	}

	return perms
}

// buildPrincipalSet builds a set of all principals that match the identity
func (s *ClusterInfoService) buildPrincipalSet(identity *models.Identity) map[string]bool {
	principals := make(map[string]bool)

	// Add username
	if identity.Username != "" {
		principals[identity.Username] = true
	}

	// Add groups
	for _, group := range identity.Groups {
		principals[group] = true
	}

	// Add service account format
	if identity.IsServiceAccount() {
		saName := fmt.Sprintf("system:serviceaccount:%s:%s", identity.ServiceAccountNamespace, identity.ServiceAccountName)
		principals[saName] = true
		principals[identity.ServiceAccountName] = true
	}

	return principals
}

// bindingAppliesToIdentity checks if any subject in the binding matches the identity
func (s *ClusterInfoService) bindingAppliesToIdentity(subjects []rbacv1.Subject, principals map[string]bool) bool {
	for _, subject := range subjects {
		switch subject.Kind {
		case "User":
			if principals[subject.Name] {
				return true
			}
		case "Group":
			if principals[subject.Name] {
				return true
			}
		case "ServiceAccount":
			saName := fmt.Sprintf("system:serviceaccount:%s:%s", subject.Namespace, subject.Name)
			if principals[saName] || principals[subject.Name] {
				return true
			}
		}
	}
	return false
}

// findMatchingSubjects returns all subjects that match the identity's principals
func (s *ClusterInfoService) findMatchingSubjects(subjects []rbacv1.Subject, principals map[string]bool) []rbacv1.Subject {
	var matched []rbacv1.Subject
	for _, subject := range subjects {
		switch subject.Kind {
		case "User":
			if principals[subject.Name] {
				matched = append(matched, subject)
			}
		case "Group":
			if principals[subject.Name] {
				matched = append(matched, subject)
			}
		case "ServiceAccount":
			saName := fmt.Sprintf("system:serviceaccount:%s:%s", subject.Namespace, subject.Name)
			if principals[saName] || principals[subject.Name] {
				matched = append(matched, subject)
			}
		}
	}
	return matched
}

// extractPermissionsFromRule extracts individual permissions from a PolicyRule with subject info
func (s *ClusterInfoService) extractPermissionsFromRule(rule rbacv1.PolicyRule, namespace, roleName, roleKind, bindingName, bindingKind string, subject rbacv1.Subject) []models.PermissionWithSource {
	var perms []models.PermissionWithSource

	apiGroups := rule.APIGroups
	if len(apiGroups) == 0 {
		apiGroups = []string{""}
	}

	for _, verb := range rule.Verbs {
		for _, resource := range rule.Resources {
			for _, apiGroup := range apiGroups {
				perms = append(perms, models.PermissionWithSource{
					Namespace:   namespace,
					Verb:        verb,
					Resource:    resource,
					APIGroup:    apiGroup,
					RoleName:    roleName,
					RoleKind:    roleKind,
					BindingName: bindingName,
					BindingKind: bindingKind,
					SubjectName: subject.Name,
					SubjectKind: subject.Kind,
					SubjectNS:   subject.Namespace,
				})
			}
		}
	}

	return perms
}

// ============================================================================
// Private helper methods
// ============================================================================

func (s *ClusterInfoService) detectCloudMetadata(ctx context.Context, info *models.ClusterInfo) {
	nodes, err := s.clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{Limit: 1})
	if err != nil {
		return
	}

	info.NodeCount = len(nodes.Items)

	for _, node := range nodes.Items {
		providerID := node.Spec.ProviderID
		labels := node.GetLabels()

		// Detect cloud provider
		switch {
		case strings.HasPrefix(providerID, "aws://"):
			info.CloudProvider = "AWS"
		case strings.HasPrefix(providerID, "gce://"):
			info.CloudProvider = "GCP"
		case strings.HasPrefix(providerID, "azure://"):
			info.CloudProvider = "Azure"
		}

		// Extract region/zone
		if zone, ok := labels["topology.kubernetes.io/zone"]; ok {
			info.Zone = zone
		} else if zone, ok := labels["failure-domain.beta.kubernetes.io/zone"]; ok {
			info.Zone = zone
		}

		if region, ok := labels["topology.kubernetes.io/region"]; ok {
			info.Region = region
		} else if region, ok := labels["failure-domain.beta.kubernetes.io/region"]; ok {
			info.Region = region
		}

		break // Only need first node
	}
}

func (s *ClusterInfoService) extractUserFromKubeconfig() string {
	if globals.KubeConfigPath == "" {
		return ""
	}

	kubeconfig, err := clientcmd.LoadFromFile(globals.KubeConfigPath)
	if err != nil {
		return ""
	}

	contextName := globals.KubeContext
	if contextName == "" {
		contextName = kubeconfig.CurrentContext
	}
	if contextName == "" {
		return ""
	}

	ctx, ok := kubeconfig.Contexts[contextName]
	if !ok {
		return ""
	}

	return ctx.AuthInfo
}

func (s *ClusterInfoService) trySelfSubjectReview(ctx context.Context) (string, []string, error) {
	ssr := &authenticationv1.SelfSubjectReview{}
	result, err := s.clientset.AuthenticationV1().SelfSubjectReviews().Create(ctx, ssr, metav1.CreateOptions{})
	if err != nil {
		return "", nil, err
	}

	return result.Status.UserInfo.Username, result.Status.UserInfo.Groups, nil
}

func (s *ClusterInfoService) tryForbiddenErrorParsing(ctx context.Context) (string, []string) {
	// Try to access cluster-admin resources to get a forbidden error
	_, err := s.clientset.RbacV1().ClusterRoles().Get(ctx, "cluster-admin", metav1.GetOptions{})
	if err != nil {
		username := parseUsernameFromError(err)
		groups := parseGroupsFromError(err)
		return username, groups
	}

	// Try secrets if first attempt succeeded (user might be admin)
	_, err = s.clientset.CoreV1().Secrets("kube-system").List(ctx, metav1.ListOptions{Limit: 1})
	if err != nil {
		username := parseUsernameFromError(err)
		groups := parseGroupsFromError(err)
		return username, groups
	}

	return "", nil
}

func (s *ClusterInfoService) decodeServiceAccountToken() (string, string, error) {
	tokenPath := "/var/run/secrets/kubernetes.io/serviceaccount/token"
	tokenBytes, err := os.ReadFile(tokenPath)
	if err != nil {
		return "", "", err
	}

	parts := strings.Split(string(tokenBytes), ".")
	if len(parts) != 3 {
		return "", "", fmt.Errorf("invalid JWT format")
	}

	payload := parts[1]
	if l := len(payload) % 4; l > 0 {
		payload += strings.Repeat("=", 4-l)
	}

	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return "", "", err
	}

	var claims struct {
		KubernetesIo struct {
			Namespace      string `json:"namespace"`
			ServiceAccount struct {
				Name string `json:"name"`
			} `json:"serviceaccount"`
		} `json:"kubernetes.io"`
	}

	if err := json.Unmarshal(decoded, &claims); err != nil {
		return "", "", err
	}

	return claims.KubernetesIo.Namespace, claims.KubernetesIo.ServiceAccount.Name, nil
}

func (s *ClusterInfoService) extractRBACInfo(ctx context.Context, identity *models.Identity) {
	ssar := &authorizationv1.SelfSubjectAccessReview{
		Spec: authorizationv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Verb:     "get",
				Resource: "pods",
			},
		},
	}

	result, err := s.clientset.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, ssar, metav1.CreateOptions{})
	if err != nil {
		return
	}

	reason := result.Status.Reason

	reClusterRoleBinding := regexp.MustCompile(`ClusterRoleBinding "([^"]+)"`)
	reClusterRole := regexp.MustCompile(`ClusterRole "([^"]+)"`)
	reUser := regexp.MustCompile(`[Uu]ser "([^"]+)"`)

	if match := reClusterRoleBinding.FindStringSubmatch(reason); len(match) > 1 {
		identity.ClusterRoleBinding = match[1]
	}
	if match := reClusterRole.FindStringSubmatch(reason); len(match) > 1 {
		identity.ClusterRole = match[1]
	}
	if identity.Username == "" {
		if match := reUser.FindStringSubmatch(reason); len(match) > 1 {
			identity.Username = match[1]
		}
	}
}

func (s *ClusterInfoService) getNamespaces(ctx context.Context) []string {
	nsList, err := sdk.GetNamespaces(ctx, s.clientset)
	if err != nil {
		// Fallback to common namespaces
		return []string{"default", "kube-system", "kube-public", "kube-node-lease"}
	}

	namespaces := make([]string, 0, len(nsList))
	for _, ns := range nsList {
		namespaces = append(namespaces, ns.Name)
	}
	return namespaces
}

func (s *ClusterInfoService) enumerateNamespacePermissions(ctx context.Context, namespace string) ([]string, []DangerousPermission) {
	ssrr := &authorizationv1.SelfSubjectRulesReview{
		Spec: authorizationv1.SelfSubjectRulesReviewSpec{
			Namespace: namespace,
		},
	}

	result, err := s.clientset.AuthorizationV1().SelfSubjectRulesReviews().Create(ctx, ssrr, metav1.CreateOptions{})
	if err != nil {
		return nil, nil
	}

	var perms []string
	var dangerous []DangerousPermission

	for _, rule := range result.Status.ResourceRules {
		for _, verb := range rule.Verbs {
			for _, resource := range rule.Resources {
				perm := fmt.Sprintf("%s %s", verb, resource)
				perms = append(perms, perm)

				if reason := isDangerousPermission(verb, resource, rule.APIGroups); reason != "" {
					dangerous = append(dangerous, DangerousPermission{
						Namespace: namespace,
						Verb:      verb,
						Resource:  resource,
						APIGroup:  strings.Join(rule.APIGroups, ","),
						Reason:    reason,
					})
				}
			}
		}
	}

	return perms, dangerous
}

func (s *ClusterInfoService) calculateRiskLevel(summary *models.PermissionSummary) string {
	// CRITICAL: 5+ dangerous permissions
	if summary.DangerousPermissions >= 5 {
		return "CRITICAL"
	}

	// Check for specific critical permissions
	for _, perm := range summary.DangerousPerms {
		if perm.Verb == "*" && perm.Resource == "*" {
			return "CRITICAL"
		}
		if strings.Contains(perm.Reason, "impersonate") ||
			strings.Contains(perm.Reason, "escalate") {
			return "HIGH"
		}
	}

	// HIGH: 3+ dangerous permissions
	if summary.DangerousPermissions >= 3 {
		return "HIGH"
	}

	// MEDIUM: 1-2 dangerous permissions
	if summary.DangerousPermissions > 0 {
		return "MEDIUM"
	}

	return "LOW"
}

// ============================================================================
// Helper functions
// ============================================================================

// DangerousPermission is an alias for the model type
type DangerousPermission = models.DangerousPermission

func parseUsernameFromError(err error) string {
	if err == nil {
		return ""
	}
	re := regexp.MustCompile(`[Uu]ser\s+"([^"]+)"`)
	match := re.FindStringSubmatch(err.Error())
	if len(match) > 1 {
		return match[1]
	}
	return ""
}

func parseGroupsFromError(err error) []string {
	if err == nil {
		return nil
	}
	re := regexp.MustCompile(`groups:\s*\[([^\]]+)\]`)
	match := re.FindStringSubmatch(err.Error())
	if len(match) > 1 {
		return strings.Fields(match[1])
	}
	return nil
}

func isDangerousPermission(verb, resource string, apiGroups []string) string {
	dangerousPatterns := map[string]string{
		"*:*":                          "Full wildcard access - can perform any action",
		"create:pods":                  "Can create pods for container escape or privilege escalation",
		"patch:pods":                   "Can modify pods for container escape or privilege escalation",
		"create:pods/exec":             "Can execute commands in any pod",
		"create:pods/attach":           "Can attach to any pod",
		"get:secrets":                  "Can read secrets containing credentials",
		"list:secrets":                 "Can list and read secrets containing credentials",
		"create:deployments":           "Can deploy workloads with privileged access",
		"create:daemonsets":            "Can deploy daemonsets running on all nodes",
		"impersonate:users":            "Can impersonate other users",
		"impersonate:groups":           "Can impersonate groups including system:masters",
		"impersonate:serviceaccounts":  "Can impersonate service accounts",
		"escalate:roles":               "Can grant permissions not held",
		"escalate:clusterroles":        "Can grant cluster-wide permissions not held",
		"bind:roles":                   "Can bind any role",
		"bind:clusterroles":            "Can bind any cluster role",
		"create:rolebindings":          "Can grant permissions via role bindings",
		"create:clusterrolebindings":   "Can grant cluster-wide permissions",
		"create:serviceaccounts/token": "Can create tokens for any service account",
	}

	key := fmt.Sprintf("%s:%s", verb, resource)
	if reason, ok := dangerousPatterns[key]; ok {
		return reason
	}

	// Check wildcards
	if verb == "*" || resource == "*" {
		return "Wildcard permission may grant excessive access"
	}

	return ""
}
