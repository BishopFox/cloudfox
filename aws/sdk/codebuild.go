package sdk

import (
	"context"
	"encoding/gob"
	"fmt"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	codeBuildTypes "github.com/aws/aws-sdk-go-v2/service/codebuild/types"
	"github.com/patrickmn/go-cache"
)

type CodeBuildClientInterface interface {
	ListProjects(ctx context.Context, params *codebuild.ListProjectsInput, optFns ...func(*codebuild.Options)) (*codebuild.ListProjectsOutput, error)
	BatchGetProjects(ctx context.Context, params *codebuild.BatchGetProjectsInput, optFns ...func(*codebuild.Options)) (*codebuild.BatchGetProjectsOutput, error)
	GetResourcePolicy(ctx context.Context, params *codebuild.GetResourcePolicyInput, optFns ...func(*codebuild.Options)) (*codebuild.GetResourcePolicyOutput, error)
}

func init() {
	gob.Register(codeBuildTypes.Project{})
	gob.Register([]codeBuildTypes.Project{})

}

// create a CachedCodeBuildListProjects function that accepts a codebuild client, account id, and region. Make sure it handles the region option and pagination
func CachedCodeBuildListProjects(CodeBuildClient CodeBuildClientInterface, accountID string, region string) ([]string, error) {
	var PaginationControl *string
	var projects []string
	cacheKey := fmt.Sprintf("%s-codebuild-ListProjects", accountID)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.([]string), nil
	}

	for {
		ListProjects, err := CodeBuildClient.ListProjects(
			context.TODO(),
			&codebuild.ListProjectsInput{
				NextToken: PaginationControl,
			},
			func(o *codebuild.Options) {
				o.Region = region
			},
		)
		if err != nil {
			sharedLogger.Error(err.Error())
			break
		}

		projects = append(projects, ListProjects.Projects...)

		// Pagination control.
		if ListProjects.NextToken != nil {
			PaginationControl = ListProjects.NextToken
		} else {
			PaginationControl = nil
			break
		}
	}

	internal.Cache.Set(cacheKey, projects, cache.DefaultExpiration)
	return projects, nil

}

// create a CachedCodeBuildBatchGetProjects function that accepts a codebuild client, account id, region, and a single projectId. Make sure it handles the region option and pagination
func CachedCodeBuildBatchGetProjects(CodeBuildClient CodeBuildClientInterface, accountID string, region string, projectID string) (codeBuildTypes.Project, error) {
	project := codeBuildTypes.Project{}
	cacheKey := fmt.Sprintf("%s-codebuild-BatchGetProjects-%s-%s", accountID, region, projectID)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.(codeBuildTypes.Project), nil
	}

	BatchGetProjects, err := CodeBuildClient.BatchGetProjects(
		context.TODO(),
		&codebuild.BatchGetProjectsInput{
			Names: []string{projectID},
		},
		func(o *codebuild.Options) {
			o.Region = region
		},
	)
	if err != nil {
		sharedLogger.Error(err.Error())
		return project, err
	}

	internal.Cache.Set(cacheKey, BatchGetProjects.Projects, cache.DefaultExpiration)
	return BatchGetProjects.Projects[0], nil
}

// create a CachedCodeBuildGetResourcePolicy function that accepts a codebuild client, account id, region, and a single projectId. Make sure it handles the region option and pagination
func CachedCodeBuildGetResourcePolicy(CodeBuildClient CodeBuildClientInterface, accountID string, region string, projectID string) (string, error) {
	cacheKey := fmt.Sprintf("%s-codebuild-GetResourcePolicy-%s-%s", accountID, region, projectID)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.(string), nil
	}

	GetResourcePolicy, err := CodeBuildClient.GetResourcePolicy(
		context.TODO(),
		&codebuild.GetResourcePolicyInput{
			ResourceArn: aws.String("arn:aws:codebuild:" + region + ":" + accountID + ":project/" + projectID),
		},
		func(o *codebuild.Options) {
			o.Region = region
		},
	)
	if err != nil {
		sharedLogger.Error(err.Error())
		return "", err
	}

	internal.Cache.Set(cacheKey, GetResourcePolicy, cache.DefaultExpiration)
	return aws.ToString(GetResourcePolicy.Policy), nil
}
