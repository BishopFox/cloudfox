package sdk

import (
	"context"
	"encoding/gob"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	glueTypes "github.com/aws/aws-sdk-go-v2/service/glue/types"
	"github.com/patrickmn/go-cache"
)

type AWSGlueClientInterface interface {
	ListDevEndpoints(ctx context.Context, params *glue.ListDevEndpointsInput, optFns ...func(*glue.Options)) (*glue.ListDevEndpointsOutput, error)
	ListJobs(ctx context.Context, params *glue.ListJobsInput, optFns ...func(*glue.Options)) (*glue.ListJobsOutput, error)
}

func init() {
	gob.Register([]string{})
	gob.Register(glueTypes.DevEndpoint{})
	gob.Register(glueTypes.Job{})
}

func CachedGlueListDevEndpoints(GlueClient AWSGlueClientInterface, accountID string, region string) ([]string, error) {
	var PaginationControl *string
	var devEndpoints []string
	cacheKey := "glue-ListDevEndpoints-" + accountID + "-" + region
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.Debug("Using cached Glue dev endpoints data")
		return cached.([]string), nil
	}

	for {
		ListDevEndpoints, err := GlueClient.ListDevEndpoints(
			context.TODO(),
			&glue.ListDevEndpointsInput{
				NextToken: PaginationControl,
			},
			func(o *glue.Options) {
				o.Region = region
			},
		)
		if err != nil {
			sharedLogger.Error(err.Error())
			break
		}

		devEndpoints = append(devEndpoints, ListDevEndpoints.DevEndpointNames...)

		// Pagination control.
		if aws.ToString(ListDevEndpoints.NextToken) != "" {
			PaginationControl = ListDevEndpoints.NextToken
		} else {
			PaginationControl = nil
			break
		}
	}

	internal.Cache.Set(cacheKey, devEndpoints, cache.DefaultExpiration)

	return devEndpoints, nil
}

func CachedGlueListJobs(GlueClient AWSGlueClientInterface, accountID string, region string) ([]string, error) {
	var PaginationControl *string
	var jobs []string
	cacheKey := "glue-ListJobs-" + accountID + "-" + region
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.Debug("Using cached Glue jobs data")
		return cached.([]string), nil
	}

	for {
		ListJobs, err := GlueClient.ListJobs(
			context.TODO(),
			&glue.ListJobsInput{
				NextToken: PaginationControl,
			},
			func(o *glue.Options) {
				o.Region = region
			},
		)
		if err != nil {
			sharedLogger.Error(err.Error())
			break
		}

		jobs = append(jobs, ListJobs.JobNames...)

		// Pagination control.
		if ListJobs.NextToken != nil {
			PaginationControl = ListJobs.NextToken
		} else {
			PaginationControl = nil
			break
		}
	}

	internal.Cache.Set(cacheKey, jobs, cache.DefaultExpiration)

	return jobs, nil
}
