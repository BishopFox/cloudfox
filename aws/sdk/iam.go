package sdk

import (
	"context"
	"crypto/md5"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamTypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/patrickmn/go-cache"
)

type AWSIAMClientInterface interface {
	ListUsers(ctx context.Context, params *iam.ListUsersInput, optFns ...func(*iam.Options)) (*iam.ListUsersOutput, error)
	ListAccessKeys(ctx context.Context, params *iam.ListAccessKeysInput, optFns ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error)
	ListRoles(ctx context.Context, params *iam.ListRolesInput, optFns ...func(*iam.Options)) (*iam.ListRolesOutput, error)
	GetAccountAuthorizationDetails(ctx context.Context, params *iam.GetAccountAuthorizationDetailsInput, optFns ...func(*iam.Options)) (*iam.GetAccountAuthorizationDetailsOutput, error)
	SimulatePrincipalPolicy(ctx context.Context, params *iam.SimulatePrincipalPolicyInput, optFns ...func(*iam.Options)) (*iam.SimulatePrincipalPolicyOutput, error)
	ListInstanceProfiles(ctx context.Context, params *iam.ListInstanceProfilesInput, optFns ...func(*iam.Options)) (*iam.ListInstanceProfilesOutput, error)
	ListGroups(ctx context.Context, params *iam.ListGroupsInput, optFns ...func(*iam.Options)) (*iam.ListGroupsOutput, error)
}

func init() {
	gob.Register([]iamTypes.User{})
	gob.Register([]iamTypes.AccessKeyMetadata{})
	gob.Register([]iamTypes.Role{})
	gob.Register([]iamTypes.PolicyDetail{})
	gob.Register([]iamTypes.InstanceProfile{})
	gob.Register([]iamTypes.EvaluationResult{})
	gob.Register(customGAADOutput{})
}

func CachedIamListUsers(IAMClient AWSIAMClientInterface, accountID string) ([]iamTypes.User, error) {
	var PaginationControl *string
	var users []iamTypes.User
	cacheKey := fmt.Sprintf("%s-iam-ListUsers", accountID)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.([]iamTypes.User), nil
	}

	for {
		ListUsers, err := IAMClient.ListUsers(
			context.TODO(),
			&iam.ListUsersInput{
				Marker: PaginationControl,
			},
		)
		if err != nil {
			sharedLogger.Error(err.Error())
			break
		}

		users = append(users, ListUsers.Users...)

		// Pagination control.
		if ListUsers.Marker != nil {
			PaginationControl = ListUsers.Marker
		} else {
			PaginationControl = nil
			break
		}
	}

	internal.Cache.Set(cacheKey, users, cache.DefaultExpiration)
	return users, nil

}

func CachedIamListRoles(IAMClient AWSIAMClientInterface, accountID string) ([]iamTypes.Role, error) {
	var PaginationControl *string
	var roles []iamTypes.Role
	cacheKey := fmt.Sprintf("%s-iam-ListRoles", accountID)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.([]iamTypes.Role), nil
	}

	for {
		ListRoles, err := IAMClient.ListRoles(
			context.TODO(),
			&iam.ListRolesInput{
				Marker: PaginationControl,
			},
		)
		if err != nil {
			sharedLogger.Error(err.Error())
			break
		}

		roles = append(roles, ListRoles.Roles...)

		// Pagination control.
		if ListRoles.Marker != nil {
			PaginationControl = ListRoles.Marker
		} else {
			PaginationControl = nil
			break
		}
	}

	internal.Cache.Set(cacheKey, roles, cache.DefaultExpiration)
	return roles, nil

}

func CachedIamListAccessKeys(IAMClient AWSIAMClientInterface, accountID string, userName string) ([]iamTypes.AccessKeyMetadata, error) {
	var PaginationControl *string
	var accessKeys []iamTypes.AccessKeyMetadata
	cacheKey := fmt.Sprintf("%s-iam-ListAccessKeys-%s", accountID, userName)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.([]iamTypes.AccessKeyMetadata), nil
	}

	for {
		ListAccessKeys, err := IAMClient.ListAccessKeys(
			context.TODO(),
			&iam.ListAccessKeysInput{
				UserName: &userName,
				Marker:   PaginationControl,
			},
		)
		if err != nil {
			return accessKeys, err
		}

		accessKeys = append(accessKeys, ListAccessKeys.AccessKeyMetadata...)

		// Pagination control.
		if ListAccessKeys.Marker != nil {
			PaginationControl = ListAccessKeys.Marker
		} else {
			PaginationControl = nil
			break
		}
	}

	internal.Cache.Set(cacheKey, accessKeys, cache.DefaultExpiration)
	return accessKeys, nil

}

type customGAADOutput struct {
	GroupDetailList []iamTypes.GroupDetail
	UserDetailList  []iamTypes.UserDetail
	RoleDetailList  []iamTypes.RoleDetail
	Policies        []iamTypes.ManagedPolicyDetail
}

func CachedIAMGetAccountAuthorizationDetails(IAMClient AWSIAMClientInterface, accountID string) (customGAADOutput, error) {
	var PaginationControl *string
	var GroupDetailList []iamTypes.GroupDetail
	var UserDetailList []iamTypes.UserDetail
	var RoleDetailList []iamTypes.RoleDetail
	var Policies []iamTypes.ManagedPolicyDetail
	var AllAccountAuthorizationDetails = customGAADOutput{
		GroupDetailList: GroupDetailList,
		UserDetailList:  UserDetailList,
		RoleDetailList:  RoleDetailList,
		Policies:        Policies,
	}

	cacheKey := fmt.Sprintf("%s-iam-GetAccountAuthorizationDetails", accountID)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.(customGAADOutput), nil
	}

	for {
		GetAccountAuthorizationDetails, err := IAMClient.GetAccountAuthorizationDetails(
			context.TODO(),
			&iam.GetAccountAuthorizationDetailsInput{
				Marker: PaginationControl,
			},
		)
		if err != nil {
			return AllAccountAuthorizationDetails, err
		}

		AllAccountAuthorizationDetails.GroupDetailList = append(AllAccountAuthorizationDetails.GroupDetailList, GetAccountAuthorizationDetails.GroupDetailList...)
		AllAccountAuthorizationDetails.UserDetailList = append(AllAccountAuthorizationDetails.UserDetailList, GetAccountAuthorizationDetails.UserDetailList...)
		AllAccountAuthorizationDetails.RoleDetailList = append(AllAccountAuthorizationDetails.RoleDetailList, GetAccountAuthorizationDetails.RoleDetailList...)
		AllAccountAuthorizationDetails.Policies = append(AllAccountAuthorizationDetails.Policies, GetAccountAuthorizationDetails.Policies...)

		if GetAccountAuthorizationDetails.Marker != nil {
			PaginationControl = GetAccountAuthorizationDetails.Marker
		} else {
			PaginationControl = nil
			break
		}
	}

	internal.Cache.Set(cacheKey, AllAccountAuthorizationDetails, cache.DefaultExpiration)
	return AllAccountAuthorizationDetails, nil

}

func CachedIamSimulatePrincipalPolicy(IAMClient AWSIAMClientInterface, accountID string, principal *string, actionNames []string, resourceArns []string) ([]iamTypes.EvaluationResult, error) {
	var PaginationControl2 *string
	var EvaluationResults []iamTypes.EvaluationResult
	md5hashedActionNames := md5.Sum([]byte(strings.Join(actionNames, "")))
	md5hashedResourceArns := md5.Sum([]byte(strings.Join(resourceArns, "")))
	// proccess arn and get the name of the resource
	arn, err := arn.Parse(*principal)
	if err != nil {
		return EvaluationResults, err
	}
	name := arn.Resource
	// if name has muliplte / then get the last one
	if strings.Contains(arn.Resource, "/") {
		name = arn.Resource[strings.LastIndex(arn.Resource, "/")+1:]
	}

	truncatedHashLength := 8
	cacheKey := fmt.Sprintf("%s-iamSimulator-%s-%s-%s", accountID, name, hex.EncodeToString(md5hashedActionNames[:truncatedHashLength]), hex.EncodeToString(md5hashedResourceArns[:truncatedHashLength]))
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.([]iamTypes.EvaluationResult), nil
	}

	for {
		SimulatePrincipalPolicy, err := IAMClient.SimulatePrincipalPolicy(
			context.TODO(),
			&iam.SimulatePrincipalPolicyInput{
				Marker:          PaginationControl2,
				ActionNames:     actionNames,
				PolicySourceArn: principal,
				ResourceArns:    resourceArns,
			},
		)
		if err != nil {
			return EvaluationResults, err
		}

		EvaluationResults = append(EvaluationResults, SimulatePrincipalPolicy.EvaluationResults...)

		if SimulatePrincipalPolicy.Marker != nil {
			PaginationControl2 = SimulatePrincipalPolicy.Marker
		} else {
			PaginationControl2 = nil
			break
		}

	}
	internal.Cache.Set(cacheKey, EvaluationResults, cache.DefaultExpiration)
	return EvaluationResults, nil
}

func CachedIamListGroups(IAMClient AWSIAMClientInterface, accountID string) ([]iamTypes.Group, error) {
	var PaginationControl *string
	var Groups []iamTypes.Group
	cacheKey := fmt.Sprintf("%s-iam-ListGroups", accountID)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.([]iamTypes.Group), nil
	}

	for {
		ListGroups, err := IAMClient.ListGroups(
			context.TODO(),
			&iam.ListGroupsInput{
				Marker: PaginationControl,
			},
		)
		if err != nil {
			return Groups, err
		}

		Groups = append(Groups, ListGroups.Groups...)

		// Pagination control.
		if ListGroups.Marker != nil {
			PaginationControl = ListGroups.Marker
		} else {
			PaginationControl = nil
			break
		}
	}

	internal.Cache.Set(cacheKey, Groups, cache.DefaultExpiration)
	return Groups, nil

}
