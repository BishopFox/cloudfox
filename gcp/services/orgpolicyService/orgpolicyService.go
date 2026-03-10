package orgpolicyservice

import (
	"context"
	"fmt"
	"strings"

	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/internal/gcp/sdk"
	"google.golang.org/api/orgpolicy/v2"
)

type OrgPolicyService struct {
	session *gcpinternal.SafeSession
}

func New() *OrgPolicyService {
	return &OrgPolicyService{session: gcpinternal.GetDefaultSession()}
}

func NewWithSession(session *gcpinternal.SafeSession) *OrgPolicyService {
	return &OrgPolicyService{session: session}
}

// getService returns an Org Policy service client using cached session if available
func (s *OrgPolicyService) getService(ctx context.Context) (*orgpolicy.Service, error) {
	if s.session != nil {
		return sdk.CachedGetOrgPolicyService(ctx, s.session)
	}
	return orgpolicy.NewService(ctx)
}

// OrgPolicyInfo represents an organization policy
type OrgPolicyInfo struct {
	Name          string   `json:"name"`
	Constraint    string   `json:"constraint"`
	ProjectID     string   `json:"projectId"`
	ScopeType     string   `json:"scopeType"` // "organization", "folder", or "project"
	ScopeID       string   `json:"scopeId"`   // org/folder/project ID
	ScopeName     string   `json:"scopeName"` // display name
	Enforced      bool     `json:"enforced"`
	AllowAll      bool     `json:"allowAll"`
	DenyAll       bool     `json:"denyAll"`
	AllowedValues []string `json:"allowedValues"`
	DeniedValues  []string `json:"deniedValues"`
	InheritParent bool     `json:"inheritFromParent"`
	Description   string   `json:"description"`
}

// SecurityRelevantConstraints maps constraint names to their security implications
var SecurityRelevantConstraints = map[string]struct {
	Description    string
	RiskWhenWeak   string
	DefaultSecure  bool
}{
	// Domain restriction
	"constraints/iam.allowedPolicyMemberDomains": {
		Description:   "Restricts IAM members to specific domains",
		RiskWhenWeak:  "Allows external users/accounts to be granted IAM permissions",
		DefaultSecure: false,
	},
	// Service account key creation
	"constraints/iam.disableServiceAccountKeyCreation": {
		Description:   "Prevents service account key creation",
		RiskWhenWeak:  "Allows persistent SA key creation for long-term access",
		DefaultSecure: false,
	},
	"constraints/iam.disableServiceAccountKeyUpload": {
		Description:   "Prevents uploading service account keys",
		RiskWhenWeak:  "Allows external keys to be uploaded for SA access",
		DefaultSecure: false,
	},
	// Workload identity
	"constraints/iam.workloadIdentityPoolProviders": {
		Description:   "Restricts workload identity pool providers",
		RiskWhenWeak:  "Allows external identity providers to assume GCP identities",
		DefaultSecure: false,
	},
	"constraints/iam.workloadIdentityPoolAwsAccounts": {
		Description:   "Restricts AWS accounts for workload identity",
		RiskWhenWeak:  "Allows any AWS account to assume GCP identity",
		DefaultSecure: false,
	},
	// Compute restrictions
	"constraints/compute.requireShieldedVm": {
		Description:   "Requires Shielded VMs",
		RiskWhenWeak:  "Allows VMs without Shielded VM protections",
		DefaultSecure: false,
	},
	"constraints/compute.requireOsLogin": {
		Description:   "Requires OS Login for SSH access",
		RiskWhenWeak:  "Allows metadata-based SSH keys instead of centralized access",
		DefaultSecure: false,
	},
	"constraints/compute.vmExternalIpAccess": {
		Description:   "Restricts which VMs can have external IPs",
		RiskWhenWeak:  "Allows any VM to have an external IP",
		DefaultSecure: false,
	},
	"constraints/compute.disableSerialPortAccess": {
		Description:   "Disables serial port access to VMs",
		RiskWhenWeak:  "Allows serial console access to VMs",
		DefaultSecure: false,
	},
	"constraints/compute.disableNestedVirtualization": {
		Description:   "Disables nested virtualization",
		RiskWhenWeak:  "Allows nested VMs for potential sandbox escape",
		DefaultSecure: false,
	},
	// Storage restrictions
	"constraints/storage.uniformBucketLevelAccess": {
		Description:   "Requires uniform bucket-level access",
		RiskWhenWeak:  "Allows ACL-based access which is harder to audit",
		DefaultSecure: false,
	},
	"constraints/storage.publicAccessPrevention": {
		Description:   "Prevents public access to storage buckets",
		RiskWhenWeak:  "Allows public bucket/object access",
		DefaultSecure: false,
	},
	// SQL restrictions
	"constraints/sql.restrictPublicIp": {
		Description:   "Restricts public IPs on Cloud SQL",
		RiskWhenWeak:  "Allows Cloud SQL instances with public IPs",
		DefaultSecure: false,
	},
	"constraints/sql.restrictAuthorizedNetworks": {
		Description:   "Restricts authorized networks for Cloud SQL",
		RiskWhenWeak:  "Allows broad network access to Cloud SQL",
		DefaultSecure: false,
	},
	// GKE restrictions
	"constraints/container.restrictPublicEndpoint": {
		Description:   "Restricts GKE public endpoints",
		RiskWhenWeak:  "Allows GKE clusters with public API endpoints",
		DefaultSecure: false,
	},
	// Resource location
	"constraints/gcp.resourceLocations": {
		Description:   "Restricts resource locations/regions",
		RiskWhenWeak:  "Allows resources in any region (compliance risk)",
		DefaultSecure: false,
	},
	// Service usage
	"constraints/serviceuser.services": {
		Description:   "Restricts which services can be enabled",
		RiskWhenWeak:  "Allows any GCP service to be enabled",
		DefaultSecure: false,
	},
	// VPC
	"constraints/compute.restrictSharedVpcSubnetworks": {
		Description:   "Restricts Shared VPC subnetworks",
		RiskWhenWeak:  "Allows access to any Shared VPC subnetwork",
		DefaultSecure: false,
	},
	"constraints/compute.restrictVpnPeerIPs": {
		Description:   "Restricts VPN peer IPs",
		RiskWhenWeak:  "Allows VPN tunnels to any peer",
		DefaultSecure: false,
	},
}

// ListProjectPolicies lists all org policies for a project
func (s *OrgPolicyService) ListProjectPolicies(projectID string) ([]OrgPolicyInfo, error) {
	ctx := context.Background()

	service, err := s.getService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "orgpolicy.googleapis.com")
	}

	var policies []OrgPolicyInfo
	parent := fmt.Sprintf("projects/%s", projectID)

	err = service.Projects.Policies.List(parent).Pages(ctx, func(resp *orgpolicy.GoogleCloudOrgpolicyV2ListPoliciesResponse) error {
		for _, policy := range resp.Policies {
			info := s.parsePolicyInfo(policy, "project", projectID, "")
			policies = append(policies, info)
		}
		return nil
	})
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "orgpolicy.googleapis.com")
	}

	return policies, nil
}

// ListOrganizationPolicies lists all org policies for an organization
func (s *OrgPolicyService) ListOrganizationPolicies(orgID, orgDisplayName string) ([]OrgPolicyInfo, error) {
	ctx := context.Background()

	service, err := s.getService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "orgpolicy.googleapis.com")
	}

	var policies []OrgPolicyInfo
	parent := fmt.Sprintf("organizations/%s", orgID)

	err = service.Organizations.Policies.List(parent).Pages(ctx, func(resp *orgpolicy.GoogleCloudOrgpolicyV2ListPoliciesResponse) error {
		for _, policy := range resp.Policies {
			info := s.parsePolicyInfo(policy, "organization", orgID, orgDisplayName)
			policies = append(policies, info)
		}
		return nil
	})
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "orgpolicy.googleapis.com")
	}

	return policies, nil
}

// ListFolderPolicies lists all org policies for a folder
func (s *OrgPolicyService) ListFolderPolicies(folderID, folderDisplayName string) ([]OrgPolicyInfo, error) {
	ctx := context.Background()

	service, err := s.getService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "orgpolicy.googleapis.com")
	}

	var policies []OrgPolicyInfo
	parent := fmt.Sprintf("folders/%s", folderID)

	err = service.Folders.Policies.List(parent).Pages(ctx, func(resp *orgpolicy.GoogleCloudOrgpolicyV2ListPoliciesResponse) error {
		for _, policy := range resp.Policies {
			info := s.parsePolicyInfo(policy, "folder", folderID, folderDisplayName)
			policies = append(policies, info)
		}
		return nil
	})
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "orgpolicy.googleapis.com")
	}

	return policies, nil
}

// GetEffectivePolicy gets the effective (inherited + local) policy for a specific constraint at a given scope.
// scopeType must be "project", "folder", or "organization".
// constraint should be the short name (e.g., "compute.requireOsLogin").
func (s *OrgPolicyService) GetEffectivePolicy(scopeType, scopeID, constraint string) (*OrgPolicyInfo, error) {
	ctx := context.Background()

	service, err := s.getService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "orgpolicy.googleapis.com")
	}

	// Strip "constraints/" prefix if present
	constraint = strings.TrimPrefix(constraint, "constraints/")

	var policy *orgpolicy.GoogleCloudOrgpolicyV2Policy

	switch scopeType {
	case "project":
		name := fmt.Sprintf("projects/%s/policies/%s", scopeID, constraint)
		policy, err = service.Projects.Policies.GetEffectivePolicy(name).Context(ctx).Do()
	case "folder":
		name := fmt.Sprintf("folders/%s/policies/%s", scopeID, constraint)
		policy, err = service.Folders.Policies.GetEffectivePolicy(name).Context(ctx).Do()
	case "organization":
		name := fmt.Sprintf("organizations/%s/policies/%s", scopeID, constraint)
		policy, err = service.Organizations.Policies.GetEffectivePolicy(name).Context(ctx).Do()
	default:
		return nil, fmt.Errorf("unsupported scope type: %s", scopeType)
	}

	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "orgpolicy.googleapis.com")
	}

	info := s.parsePolicyInfo(policy, scopeType, scopeID, "")
	return &info, nil
}

func (s *OrgPolicyService) parsePolicyInfo(policy *orgpolicy.GoogleCloudOrgpolicyV2Policy, scopeType, scopeID, scopeName string) OrgPolicyInfo {
	info := OrgPolicyInfo{
		Name:      policy.Name,
		ScopeType: scopeType,
		ScopeID:   scopeID,
		ScopeName: scopeName,
	}

	// Set ProjectID for backward compatibility when scope is project
	if scopeType == "project" {
		info.ProjectID = scopeID
	}

	// Extract constraint name from policy name
	parts := strings.Split(policy.Name, "/policies/")
	if len(parts) > 1 {
		info.Constraint = "constraints/" + parts[1]
	}

	// Get description from SecurityRelevantConstraints if available
	if secInfo, ok := SecurityRelevantConstraints[info.Constraint]; ok {
		info.Description = secInfo.Description
	}

	// Parse the spec
	if policy.Spec != nil {
		info.InheritParent = policy.Spec.InheritFromParent

		for _, rule := range policy.Spec.Rules {
			if rule == nil {
				continue
			}

			// In v2 API, these are booleans
			info.Enforced = rule.Enforce
			info.AllowAll = rule.AllowAll
			info.DenyAll = rule.DenyAll

			if rule.Values != nil {
				info.AllowedValues = append(info.AllowedValues, rule.Values.AllowedValues...)
				info.DeniedValues = append(info.DeniedValues, rule.Values.DeniedValues...)
			}
		}
	}

	return info
}

