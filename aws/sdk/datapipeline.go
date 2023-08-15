package sdk

import (
	"context"
	"encoding/gob"
	"fmt"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/service/datapipeline"
	dataPipelineTypes "github.com/aws/aws-sdk-go-v2/service/datapipeline/types"
	"github.com/patrickmn/go-cache"
)

type AWSDataPipelineClientInterface interface {
	ListPipelines(ctx context.Context, input *datapipeline.ListPipelinesInput, opts ...func(*datapipeline.Options)) (*datapipeline.ListPipelinesOutput, error)
}

func init() {
	gob.Register([]dataPipelineTypes.PipelineIdName{})
}

func CachedDataPipelineListPipelines(client AWSDataPipelineClientInterface, accountID string, region string) ([]dataPipelineTypes.PipelineIdName, error) {
	var PaginationControl *string
	var pipelines []dataPipelineTypes.PipelineIdName
	cacheKey := fmt.Sprintf("%s-datapipeline-ListPipelines-%s", accountID, region)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.([]dataPipelineTypes.PipelineIdName), nil
	}
	for {
		ListPipelines, err := client.ListPipelines(
			context.TODO(),
			&datapipeline.ListPipelinesInput{
				Marker: PaginationControl,
			},
			func(o *datapipeline.Options) {
				o.Region = region
			},
		)

		if err != nil {
			return pipelines, err
		}

		pipelines = append(pipelines, ListPipelines.PipelineIdList...)

		//pagination
		if ListPipelines.Marker == nil {
			break
		}
		PaginationControl = ListPipelines.Marker
	}

	internal.Cache.Set(cacheKey, pipelines, cache.DefaultExpiration)
	return pipelines, nil
}
