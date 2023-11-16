package sdk

import (
	"context"
	"encoding/gob"
	"fmt"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/service/grafana"
	grafanaTypes "github.com/aws/aws-sdk-go-v2/service/grafana/types"
	"github.com/patrickmn/go-cache"
)

type GrafanaClientInterface interface {
	ListWorkspaces(context.Context, *grafana.ListWorkspacesInput, ...func(*grafana.Options)) (*grafana.ListWorkspacesOutput, error)
}

func init() {
	gob.Register([]grafanaTypes.WorkspaceSummary{})
}

func CachedGrafanaListWorkspaces(client GrafanaClientInterface, accountID string, region string) ([]grafanaTypes.WorkspaceSummary, error) {
	var PaginationControl *string
	var workspaces []grafanaTypes.WorkspaceSummary
	cacheKey := fmt.Sprintf("%s-grafana-ListWorkspaces-%s", accountID, region)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.([]grafanaTypes.WorkspaceSummary), nil
	}

	for {

		ListWorkspaces, err := client.ListWorkspaces(
			context.TODO(),
			&grafana.ListWorkspacesInput{
				NextToken: PaginationControl,
			},
			func(o *grafana.Options) {
				o.Region = region
			},
		)
		if err != nil {
			return workspaces, err

		}

		workspaces = append(workspaces, ListWorkspaces.Workspaces...)

		//pagination
		if ListWorkspaces.NextToken == nil {
			break
		}
		PaginationControl = ListWorkspaces.NextToken
	}

	internal.Cache.Set(cacheKey, workspaces, cache.DefaultExpiration)
	return workspaces, nil
}
