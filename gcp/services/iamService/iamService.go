package iamservice

import (
	"context"
	"fmt"
	"strings"

	iampb "cloud.google.com/go/iam/apiv1/iampb"
	resourcemanager "cloud.google.com/go/resourcemanager/apiv3"
	resourcemanagerpb "cloud.google.com/go/resourcemanager/apiv3/resourcemanagerpb"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
)

type IAMService struct {
	// DataStoreService datastoreservice.DataStoreService
}

func New() *IAMService {
	return &IAMService{}
}

// AncestryResource represents a single resource in the project's ancestry.
type AncestryResource struct {
	Type string `json:"type"`
	Id   string `json:"id"`
}

// PolicyBindings represents IAM policy bindings.
type PolicyBinding struct {
	Role         string   `json:"role"`
	Members      []string `json:"members"`
	ResourceID   string   `json:"resourceID"`
	ResourceType string
	PolicyName   string `json:"policyBindings"`
	Condition    string
}

type PrincipalWithRoles struct {
	Name           string
	Type           string
	PolicyBindings []PolicyBinding
	ResourceID     string
	ResourceType   string
}

var logger internal.Logger

func projectAncestry(projectID string) ([]AncestryResource, error) {
	ctx := context.Background()
	projectsClient, err := resourcemanager.NewProjectsClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create projects client: %v", err)
	}
	defer projectsClient.Close()

	foldersClient, err := resourcemanager.NewFoldersClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create folders client: %v", err)
	}
	defer foldersClient.Close()

	resourceID := "projects/" + projectID
	var ancestry []AncestryResource

	for {
		if strings.HasPrefix(resourceID, "organizations/") {
			ancestry = append(ancestry, AncestryResource{Type: "organization", Id: strings.TrimPrefix(resourceID, "organizations/")})
			break
		} else if strings.HasPrefix(resourceID, "folders/") {
			resp, err := foldersClient.GetFolder(ctx, &resourcemanagerpb.GetFolderRequest{Name: resourceID})
			if err != nil {
				logger.ErrorM(fmt.Sprintf("failed to access folder %s, %v", resourceID, err), globals.GCP_IAM_MODULE_NAME)
				break // Stop processing further if a folder is inaccessible
			}
			ancestry = append(ancestry, AncestryResource{Type: "folder", Id: strings.TrimPrefix(resp.Name, "folders/")})
			resourceID = resp.Parent
		} else if strings.HasPrefix(resourceID, "projects/") {
			resp, err := projectsClient.GetProject(ctx, &resourcemanagerpb.GetProjectRequest{Name: resourceID})
			if err != nil {
				logger.ErrorM(fmt.Sprintf("failed to access project %s, %v", resourceID, err), globals.GCP_IAM_MODULE_NAME)
				return nil, fmt.Errorf("failed to get project: %v", err)
			}
			ancestry = append(ancestry, AncestryResource{Type: "project", Id: strings.TrimPrefix(resp.Name, "projects/")})
			resourceID = resp.Parent
		} else {
			return nil, fmt.Errorf("unknown resource type for: %s", resourceID)
		}
	}

	// Reverse the slice as we've built it from child to ancestor
	for i, j := 0, len(ancestry)-1; i < j; i, j = i+1, j-1 {
		ancestry[i], ancestry[j] = ancestry[j], ancestry[i]
	}

	return ancestry, nil
}

// Policies fetches IAM policy for a given resource and all policies in resource ancestry
func (s *IAMService) Policies(resourceID string, resourceType string) ([]PolicyBinding, error) {
	ctx := context.Background()
	client, err := resourcemanager.NewProjectsClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("resourcemanager.NewProjectsClient: %v", err)
	}
	defer client.Close()

	var resourceName string
	switch resourceType {
	case "project":
		resourceName = "projects/" + resourceID
	case "folder":
		resourceName = "folders/" + resourceID
	case "organization":
		resourceName = "organizations/" + resourceID
	default:
		return nil, fmt.Errorf("unsupported resource type: %s", resourceType)
	}

	req := &iampb.GetIamPolicyRequest{
		Resource: resourceName,
	}

	// Fetch the IAM policy for the resource
	policy, err := client.GetIamPolicy(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("client.GetIamPolicy: %v", err)
	}

	// Assemble the policy bindings
	var policyBindings []PolicyBinding
	for _, binding := range policy.Bindings {
		policyBinding := PolicyBinding{
			Role:         binding.Role,
			Members:      binding.Members,
			ResourceID:   resourceID,
			ResourceType: resourceType,
			Condition:    binding.Condition.String(),
			PolicyName:   resourceName + "_policyBindings",
		}
		policyBindings = append(policyBindings, policyBinding)
	}

	return policyBindings, nil
}

func determinePrincipalType(member string) string {
	if strings.HasPrefix(member, "user:") {
		return "User"
	} else if strings.HasPrefix(member, "serviceAccount:") {
		return "ServiceAccount"
	} else if strings.HasPrefix(member, "group:") {
		return "Group"
	} else {
		return "Unknown"
	}
}

func (s *IAMService) PrincipalsWithRoles(resourceID string, resourceType string) ([]PrincipalWithRoles, error) {
	policyBindings, err := s.Policies(resourceID, resourceType)
	if err != nil {
		return nil, err
	}

	principalMap := make(map[string]*PrincipalWithRoles)
	for _, pb := range policyBindings {
		for _, member := range pb.Members {
			principalType := determinePrincipalType(member) // Implement this function based on member prefix
			if principal, ok := principalMap[member]; ok {
				principal.PolicyBindings = append(principal.PolicyBindings, pb)
			} else {
				principalMap[member] = &PrincipalWithRoles{
					Name:           member,
					Type:           principalType,
					PolicyBindings: []PolicyBinding{pb},
					ResourceID:     resourceID,
					ResourceType:   resourceType,
				}
			}
		}
	}

	var principals []PrincipalWithRoles
	for _, principal := range principalMap {
		principals = append(principals, *principal)
	}

	return principals, nil
}
