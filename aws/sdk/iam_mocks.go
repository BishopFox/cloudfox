package sdk

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamTypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

type MockedIAMClient struct {
}

func (m *MockedIAMClient) ListUsers(ctx context.Context, input *iam.ListUsersInput, options ...func(*iam.Options)) (*iam.ListUsersOutput, error) {
	return &iam.ListUsersOutput{
		Users: []iamTypes.User{
			{
				Arn:        aws.String("arn:aws:iam::123456789012:user/user1"),
				CreateDate: aws.Time(time.Now()),
				Path:       aws.String("/"),
				UserId:     aws.String("123456789012"),
				UserName:   aws.String("user1"),
			},
			{
				Arn:        aws.String("arn:aws:iam::123456789012:user/user2"),
				CreateDate: aws.Time(time.Now()),
				Path:       aws.String("/"),
				UserId:     aws.String("123456789012"),
				UserName:   aws.String("user2"),
			},
		},
	}, nil
}

func (m *MockedIAMClient) ListAccessKeys(ctx context.Context, input *iam.ListAccessKeysInput, options ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
	return &iam.ListAccessKeysOutput{
		AccessKeyMetadata: []iamTypes.AccessKeyMetadata{
			{
				AccessKeyId: aws.String("accesskey1"),
				CreateDate:  aws.Time(time.Now()),
				Status:      iamTypes.StatusTypeActive,
				UserName:    aws.String("user1"),
			},
			{
				AccessKeyId: aws.String("accesskey2"),
				CreateDate:  aws.Time(time.Now()),
				Status:      iamTypes.StatusTypeActive,
				UserName:    aws.String("user2"),
			},
		},
	}, nil

}

func (m *MockedIAMClient) ListGroups(ctx context.Context, input *iam.ListGroupsInput, options ...func(*iam.Options)) (*iam.ListGroupsOutput, error) {
	return &iam.ListGroupsOutput{
		Groups: []iamTypes.Group{
			{
				Arn:        aws.String("arn:aws:iam::123456789012:group/group1"),
				CreateDate: aws.Time(time.Now()),
				GroupId:    aws.String("123456789012"),
				GroupName:  aws.String("group1"),
				Path:       aws.String("/"),
			},
			{
				Arn:        aws.String("arn:aws:iam::123456789012:group/group2"),
				CreateDate: aws.Time(time.Now()),
				GroupId:    aws.String("123456789012"),
				GroupName:  aws.String("group2"),
				Path:       aws.String("/"),
			},
		},
	}, nil

}

func (m *MockedIAMClient) ListRoles(ctx context.Context, input *iam.ListRolesInput, options ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	return &iam.ListRolesOutput{
		Roles: []iamTypes.Role{
			{
				Arn:                      aws.String("arn:aws:iam::123456789012:role/role1"),
				AssumeRolePolicyDocument: aws.String("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"ec2.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}"),
				CreateDate:               aws.Time(time.Now()),
				RoleId:                   aws.String("123456789012"),
				RoleName:                 aws.String("role1"),
				Path:                     aws.String("/"),
			},
			{
				Arn:                      aws.String("arn:aws:iam::123456789012:role/role2"),
				AssumeRolePolicyDocument: aws.String("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"ec2.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}"),
				CreateDate:               aws.Time(time.Now()),
				RoleId:                   aws.String("123456789012"),
				RoleName:                 aws.String("role2"),
				Path:                     aws.String("/"),
			},
			{
				Arn:                      aws.String("arn:aws:iam::123456789012:role/role3"),
				AssumeRolePolicyDocument: aws.String("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::123456789012:root\"},\"Action\":\"sts:AssumeRole\"}]}"),
				CreateDate:               aws.Time(time.Now()),
				RoleId:                   aws.String("123456789012"),
				RoleName:                 aws.String("role3"),
				Path:                     aws.String("/"),
			},
		},
	}, nil

}

func (m *MockedIAMClient) GetAccountAuthorizationDetails(ctx context.Context, params *iam.GetAccountAuthorizationDetailsInput, optFns ...func(*iam.Options)) (*iam.GetAccountAuthorizationDetailsOutput, error) {
	return &iam.GetAccountAuthorizationDetailsOutput{
		GroupDetailList: []iamTypes.GroupDetail{
			{
				Arn:        aws.String("arn:aws:iam::123456789012:group/group1"),
				CreateDate: aws.Time(time.Now()),
				GroupId:    aws.String("123456789012"),
				GroupName:  aws.String("group1"),
				Path:       aws.String("/"),
			},
			{
				Arn:        aws.String("arn:aws:iam::123456789012:group/group2"),
				CreateDate: aws.Time(time.Now()),
				GroupId:    aws.String("123456789012"),
				GroupName:  aws.String("group2"),
				Path:       aws.String("/"),
			},
		},
		RoleDetailList: []iamTypes.RoleDetail{
			{
				Arn:                      aws.String("arn:aws:iam::123456789012:role/role1"),
				AssumeRolePolicyDocument: aws.String("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"ec2.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}"),
				CreateDate:               aws.Time(time.Now()),
				RoleId:                   aws.String("123456789012"),
				RoleName:                 aws.String("role1"),
				Path:                     aws.String("/"),
			},
			{
				Arn:                      aws.String("arn:aws:iam::123456789012:role/role2"),
				AssumeRolePolicyDocument: aws.String("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"ec2.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}"),
				CreateDate:               aws.Time(time.Now()),
				RoleId:                   aws.String("123456789012"),
				RoleName:                 aws.String("role2"),
				Path:                     aws.String("/"),
			},
			{
				Arn:                      aws.String("arn:aws:iam::123456789012:role/role3"),
				AssumeRolePolicyDocument: aws.String("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::123456789012:root\"},\"Action\":\"sts:AssumeRole\"}]}"),
				CreateDate:               aws.Time(time.Now()),
				RoleId:                   aws.String("123456789012"),

				RoleName: aws.String("role3"),
				Path:     aws.String("/"),
			},
		},
		UserDetailList: []iamTypes.UserDetail{
			{
				Arn:        aws.String("arn:aws:iam::123456789012:user/user1"),
				CreateDate: aws.Time(time.Now()),

				UserId:   aws.String("123456789012"),
				UserName: aws.String("user1"),
				Path:     aws.String("/"),
			},
			{
				Arn:        aws.String("arn:aws:iam::123456789012:user/user2"),
				CreateDate: aws.Time(time.Now()),

				UserId:   aws.String("123456789012"),
				UserName: aws.String("user2"),
				Path:     aws.String("/"),
			},
		},
	}, nil
}

func (m *MockedIAMClient) SimulatePrincipalPolicy(ctx context.Context, params *iam.SimulatePrincipalPolicyInput, optFns ...func(*iam.Options)) (*iam.SimulatePrincipalPolicyOutput, error) {
	return &iam.SimulatePrincipalPolicyOutput{
		EvaluationResults: []iamTypes.EvaluationResult{
			{
				EvalActionName:   aws.String("sts:AssumeRole"),
				EvalDecision:     iamTypes.PolicyEvaluationDecisionTypeAllowed,
				EvalResourceName: aws.String("arn:aws:iam::123456789012:role/role1"),
				MatchedStatements: []iamTypes.Statement{
					{
						SourcePolicyId:   aws.String("PolicyForRole1"),
						SourcePolicyType: iamTypes.PolicySourceTypeUser,
						StartPosition: &iamTypes.Position{
							Column: 0,
							Line:   0,
						},
					},
				},
			},
		},
	}, nil

}

func (m *MockedIAMClient) ListInstanceProfiles(ctx context.Context, params *iam.ListInstanceProfilesInput, optFns ...func(*iam.Options)) (*iam.ListInstanceProfilesOutput, error) {
	return &iam.ListInstanceProfilesOutput{
		InstanceProfiles: []iamTypes.InstanceProfile{
			{
				Arn:                 aws.String("arn:aws:iam::123456789012:instance-profile/instance-profile1"),
				CreateDate:          aws.Time(time.Now()),
				InstanceProfileId:   aws.String("123456789012"),
				InstanceProfileName: aws.String("instance-profile1"),
				Path:                aws.String("/"),
				Roles: []iamTypes.Role{
					{
						Arn:                      aws.String("arn:aws:iam::123456789012:role/role1"),
						AssumeRolePolicyDocument: aws.String("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"ec2.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}"),
						CreateDate:               aws.Time(time.Now()),
						RoleId:                   aws.String("123456789012"),
						RoleName:                 aws.String("role1"),
						Path:                     aws.String("/"),
					},
				},
			},
		},
	}, nil

}
