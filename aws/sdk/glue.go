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
	GetTables(ctx context.Context, params *glue.GetTablesInput, optFns ...func(*glue.Options)) (*glue.GetTablesOutput, error)
	GetDatabases(ctx context.Context, params *glue.GetDatabasesInput, optFns ...func(*glue.Options)) (*glue.GetDatabasesOutput, error)
}

func init() {
	gob.Register([]string{})
	gob.Register(glueTypes.DevEndpoint{})
	gob.Register(glueTypes.Job{})
	gob.Register([]glueTypes.Table{})
	gob.Register([]glueTypes.Database{})
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

func CachedGlueGetTables(GlueClient AWSGlueClientInterface, accountID string, region string, dbName string) ([]glueTypes.Table, error) {
	var PaginationControl *string
	var tables []glueTypes.Table
	cacheKey := "glue-GetTables-" + accountID + "-" + region
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.Debug("Using cached Glue tables data")
		return cached.([]glueTypes.Table), nil
	}

	for {
		GetTables, err := GlueClient.GetTables(
			context.TODO(),
			&glue.GetTablesInput{
				DatabaseName: &dbName,
				NextToken:    PaginationControl,
			},
			func(o *glue.Options) {
				o.Region = region
			},
		)
		if err != nil {
			sharedLogger.Error(err.Error())
			break
		}

		tables = append(tables, GetTables.TableList...)

		// Pagination control.
		if GetTables.NextToken != nil {
			PaginationControl = GetTables.NextToken
		} else {
			PaginationControl = nil
			break
		}
	}

	internal.Cache.Set(cacheKey, tables, cache.DefaultExpiration)

	return tables, nil
}

func CachedGlueGetDatabases(GlueClient AWSGlueClientInterface, accountID string, region string) ([]glueTypes.Database, error) {
	var PaginationControl *string
	var databases []glueTypes.Database
	cacheKey := "glue-GetDatabases-" + accountID + "-" + region
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.Debug("Using cached Glue databases data")
		return cached.([]glueTypes.Database), nil
	}

	for {
		GetDatabases, err := GlueClient.GetDatabases(
			context.TODO(),
			&glue.GetDatabasesInput{
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

		databases = append(databases, GetDatabases.DatabaseList...)

		// Pagination control.
		if GetDatabases.NextToken != nil {
			PaginationControl = GetDatabases.NextToken
		} else {
			PaginationControl = nil
			break
		}
	}

	internal.Cache.Set(cacheKey, databases, cache.DefaultExpiration)

	return databases, nil
}
