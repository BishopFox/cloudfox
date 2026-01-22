package models

// ClusterInfo contains information about the Kubernetes cluster
type ClusterInfo struct {
	Name          string        `json:"name"`
	APIServerURL  string        `json:"apiServerUrl"`
	Version       *VersionInfo  `json:"version,omitempty"`
	CloudProvider string        `json:"cloudProvider,omitempty"` // AWS, GCP, Azure, or empty
	Region        string        `json:"region,omitempty"`
	Zone          string        `json:"zone,omitempty"`
	NodeCount     int           `json:"nodeCount,omitempty"`
}

// VersionInfo contains Kubernetes version information
type VersionInfo struct {
	Major        string `json:"major"`
	Minor        string `json:"minor"`
	GitVersion   string `json:"gitVersion"`
	Platform     string `json:"platform"`
}

// Identity represents the current authenticated identity
type Identity struct {
	// Primary identity fields
	Username string   `json:"username"`
	Groups   []string `json:"groups,omitempty"`

	// Source of identity detection
	Source IdentitySource `json:"source"`

	// ServiceAccount info (if applicable)
	ServiceAccountNamespace string `json:"serviceAccountNamespace,omitempty"`
	ServiceAccountName      string `json:"serviceAccountName,omitempty"`

	// RBAC bindings
	ClusterRoleBinding string `json:"clusterRoleBinding,omitempty"`
	ClusterRole        string `json:"clusterRole,omitempty"`

	// Cloud identity (if running in cloud)
	CloudProvider string `json:"cloudProvider,omitempty"`
	CloudRole     string `json:"cloudRole,omitempty"` // AWS IAM Role ARN, GCP SA email, Azure MI

	// Additional context
	KubeconfigUser string `json:"kubeconfigUser,omitempty"` // User name from kubeconfig
}

// IdentitySource indicates how the identity was detected
type IdentitySource string

const (
	IdentitySourceSelfSubjectReview   IdentitySource = "SelfSubjectReview"
	IdentitySourceKubeconfig          IdentitySource = "Kubeconfig"
	IdentitySourceServiceAccountToken IdentitySource = "ServiceAccountToken"
	IdentitySourceForbiddenError      IdentitySource = "ForbiddenError"
	IdentitySourceUnknown             IdentitySource = "Unknown"
)

// IsServiceAccount returns true if the identity is a service account
func (i *Identity) IsServiceAccount() bool {
	return i.ServiceAccountNamespace != "" && i.ServiceAccountName != ""
}

// FullServiceAccountName returns the full service account name (namespace/name)
func (i *Identity) FullServiceAccountName() string {
	if i.IsServiceAccount() {
		return i.ServiceAccountNamespace + "/" + i.ServiceAccountName
	}
	return ""
}

// IsClusterAdmin returns true if the identity has cluster-admin privileges
func (i *Identity) IsClusterAdmin() bool {
	if i.ClusterRole == "cluster-admin" {
		return true
	}
	for _, group := range i.Groups {
		if group == "system:masters" {
			return true
		}
	}
	return false
}

// HasGroup returns true if the identity belongs to the specified group
func (i *Identity) HasGroup(group string) bool {
	for _, g := range i.Groups {
		if g == group {
			return true
		}
	}
	return false
}

// PermissionWithSource represents a permission with its RBAC source
type PermissionWithSource struct {
	Namespace     string `json:"namespace"`
	Verb          string `json:"verb"`
	Resource      string `json:"resource"`
	APIGroup      string `json:"apiGroup,omitempty"`
	RoleName      string `json:"roleName"`
	RoleKind      string `json:"roleKind"`    // Role or ClusterRole
	BindingName   string `json:"bindingName"`
	BindingKind   string `json:"bindingKind"` // RoleBinding or ClusterRoleBinding
	SubjectName   string `json:"subjectName"` // The user, group, or SA name
	SubjectKind   string `json:"subjectKind"` // User, Group, or ServiceAccount
	SubjectNS     string `json:"subjectNs,omitempty"` // Namespace for ServiceAccount
}

// PermissionSummary contains a summary of permissions for an identity
type PermissionSummary struct {
	// Total counts
	TotalNamespaces      int `json:"totalNamespaces"`
	TotalPermissions     int `json:"totalPermissions"`
	DangerousPermissions int `json:"dangerousPermissions"`

	// Per-namespace permissions (simple format for backward compat)
	NamespacePermissions map[string][]string `json:"namespacePermissions,omitempty"`

	// Permissions with full source information
	PermissionsWithSource []PermissionWithSource `json:"permissionsWithSource,omitempty"`

	// List of dangerous permissions with context
	DangerousPerms []DangerousPermission `json:"dangerousPerms,omitempty"`

	// Risk assessment
	RiskLevel string `json:"riskLevel"` // CRITICAL, HIGH, MEDIUM, LOW
}

// DangerousPermission represents a security-sensitive permission
type DangerousPermission struct {
	Namespace string `json:"namespace"`
	Verb      string `json:"verb"`
	Resource  string `json:"resource"`
	APIGroup  string `json:"apiGroup,omitempty"`
	Reason    string `json:"reason"` // Why it's dangerous
}

// WhoamiResult combines cluster info, identity, and permissions
type WhoamiResult struct {
	Cluster     ClusterInfo       `json:"cluster"`
	Identity    Identity          `json:"identity"`
	Permissions PermissionSummary `json:"permissions"`
}
