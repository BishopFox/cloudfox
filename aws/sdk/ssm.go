package sdk

import (
	"context"
	"encoding/gob"
	"fmt"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/patrickmn/go-cache"
)

type AWSSSMClientInterface interface {
	DescribeParameters(ctx context.Context, params *ssm.DescribeParametersInput, optFns ...func(*ssm.Options)) (*ssm.DescribeParametersOutput, error)
}

func init() {
	gob.Register([]types.ParameterMetadata{})
}

// create a CachedSSMDescribeParameters function that uses go-cache line the other Cached* functions. It should accept a ssm client, account id, and region. Make sure it handles the region option and pagination if needed
func CachedSSMDescribeParameters(SSMClient AWSSSMClientInterface, accountID string, region string) ([]types.ParameterMetadata, error) {
	var PaginationControl *string
	var parameters []types.ParameterMetadata
	cacheKey := fmt.Sprintf("%s-ssm-DescribeParameters-%s", accountID, region)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.Debug("Using cached SSM parameters data")
		return cached.([]types.ParameterMetadata), nil
	}

	for {
		DescribeParameters, err := SSMClient.DescribeParameters(
			context.TODO(),
			&ssm.DescribeParametersInput{
				NextToken: PaginationControl,
			},
			func(o *ssm.Options) {
				o.Region = region
			},
		)
		if err != nil {
			sharedLogger.Error(err.Error())
			break
		}

		parameters = append(parameters, DescribeParameters.Parameters...)

		// Pagination control.
		if DescribeParameters.NextToken != nil {
			PaginationControl = DescribeParameters.NextToken
		} else {
			PaginationControl = nil
			break
		}
	}

	internal.Cache.Set(cacheKey, parameters, cache.DefaultExpiration)
	return parameters, nil
}
