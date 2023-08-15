package sdk

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codedeploy"
	codedeployTypes "github.com/aws/aws-sdk-go-v2/service/codedeploy/types"
)

type MockedCodedeployClient struct {
}

func (m *MockedCodedeployClient) ListApplications(ctx context.Context, input *codedeploy.ListApplicationsInput, options ...func(*codedeploy.Options)) (*codedeploy.ListApplicationsOutput, error) {
	return &codedeploy.ListApplicationsOutput{
		Applications: []string{
			"app1",
			"app2",
		},
	}, nil
}

func (m *MockedCodedeployClient) ListDeployments(ctx context.Context, input *codedeploy.ListDeploymentsInput, options ...func(*codedeploy.Options)) (*codedeploy.ListDeploymentsOutput, error) {
	return &codedeploy.ListDeploymentsOutput{
		Deployments: []string{
			"deployment1",
			"deployment2",
		},
	}, nil
}

func (m *MockedCodedeployClient) ListDeploymentConfigs(ctx context.Context, input *codedeploy.ListDeploymentConfigsInput, options ...func(*codedeploy.Options)) (*codedeploy.ListDeploymentConfigsOutput, error) {
	return &codedeploy.ListDeploymentConfigsOutput{
		DeploymentConfigsList: []string{
			"deploymentConfig1",
			"deploymentConfig2",
		},
	}, nil
}

func (m *MockedCodedeployClient) GetApplication(ctx context.Context, input *codedeploy.GetApplicationInput, options ...func(*codedeploy.Options)) (*codedeploy.GetApplicationOutput, error) {
	return &codedeploy.GetApplicationOutput{
		Application: &codedeployTypes.ApplicationInfo{
			ApplicationName:   aws.String("application1"),
			ApplicationId:     aws.String("application1"),
			CreateTime:        aws.Time(time.Now()),
			GitHubAccountName: aws.String("github"),
			LinkedToGitHub:    true,
		},
	}, nil
}

func (m *MockedCodedeployClient) GetDeployment(ctx context.Context, input *codedeploy.GetDeploymentInput, options ...func(*codedeploy.Options)) (*codedeploy.GetDeploymentOutput, error) {
	return &codedeploy.GetDeploymentOutput{
		DeploymentInfo: &codedeployTypes.DeploymentInfo{
			ApplicationName: aws.String("application1"),
			CreateTime:      aws.Time(time.Now()),
			DeploymentId:    aws.String("deployment1"),
			DeploymentOverview: &codedeployTypes.DeploymentOverview{
				Failed:     0,
				InProgress: 0,
				Pending:    0,
				Ready:      0,
				Skipped:    0,
				Succeeded:  0,
			},
			DeploymentConfigName: aws.String("deploymentConfig1"),
			Status:               codedeployTypes.DeploymentStatusSucceeded,
		},
	}, nil
}

func (m *MockedCodedeployClient) GetDeploymentConfig(ctx context.Context, input *codedeploy.GetDeploymentConfigInput, options ...func(*codedeploy.Options)) (*codedeploy.GetDeploymentConfigOutput, error) {
	return &codedeploy.GetDeploymentConfigOutput{
		DeploymentConfigInfo: &codedeployTypes.DeploymentConfigInfo{
			DeploymentConfigName: aws.String("deploymentConfig1"),
			ComputePlatform:      codedeployTypes.ComputePlatformServer,
			MinimumHealthyHosts: &codedeployTypes.MinimumHealthyHosts{
				Type:  codedeployTypes.MinimumHealthyHostsTypeFleetPercent,
				Value: 100,
			},
		},
	}, nil
}
