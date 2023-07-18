package sdk

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/grafana"
	grafanaTypes "github.com/aws/aws-sdk-go-v2/service/grafana/types"
)

type MockedGrafanaClient struct {
}

func (m *MockedGrafanaClient) ListWorkspaces(ctx context.Context, input *grafana.ListWorkspacesInput, options ...func(*grafana.Options)) (*grafana.ListWorkspacesOutput, error) {
	return &grafana.ListWorkspacesOutput{
		Workspaces: []grafanaTypes.WorkspaceSummary{
			{
				Authentication: &grafanaTypes.AuthenticationSummary{
					Providers: []grafanaTypes.AuthenticationProviderTypes{
						grafanaTypes.AuthenticationProviderTypesAwsSso,
					},
				},
				Created: aws.Time(time.Now()),
				Id:      aws.String("workspace1"),
				Name:    aws.String("workspace1"),
				Status:  grafanaTypes.WorkspaceStatusActive,
			},
			{
				Authentication: &grafanaTypes.AuthenticationSummary{
					Providers: []grafanaTypes.AuthenticationProviderTypes{
						grafanaTypes.AuthenticationProviderTypesAwsSso,
					},
				},
				Created: aws.Time(time.Now()),
				Id:      aws.String("workspace2"),
				Name:    aws.String("workspace2"),
				Status:  grafanaTypes.WorkspaceStatusActive,
			},
		},
	}, nil
}
