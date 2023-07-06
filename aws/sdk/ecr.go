package sdk

import (
	"context"
	"encoding/gob"
	"fmt"
	"strings"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrTypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/patrickmn/go-cache"
)

type AWSECRClientInterface interface {
	DescribeRepositories(ctx context.Context, params *ecr.DescribeRepositoriesInput, optFns ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error)
	DescribeImages(ctx context.Context, params *ecr.DescribeImagesInput, optFns ...func(*ecr.Options)) (*ecr.DescribeImagesOutput, error)
	GetRepositoryPolicy(ctx context.Context, params *ecr.GetRepositoryPolicyInput, optFns ...func(*ecr.Options)) (*ecr.GetRepositoryPolicyOutput, error)
}

func init() {
	gob.Register([]ecrTypes.Repository{})
	gob.Register([]ecrTypes.ImageDetail{})

}

// create a CachedECRDescribeRepositories function that uses go-cache line the other Cached* functions. It should accept a ecr client, account id, and region. Make sure it handles the region option and pagination if needed
func CachedECRDescribeRepositories(ECRClient AWSECRClientInterface, accountID string, region string) ([]ecrTypes.Repository, error) {
	var PaginationControl *string
	var repositories []ecrTypes.Repository
	cacheKey := fmt.Sprintf("%s-ecr-DescribeRepositories-%s", accountID, region)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.Debug("Using cached ECR repositories data")
		return cached.([]ecrTypes.Repository), nil
	}

	for {
		DescribeRepositories, err := ECRClient.DescribeRepositories(
			context.TODO(),
			&ecr.DescribeRepositoriesInput{
				NextToken: PaginationControl,
			},
			func(o *ecr.Options) {
				o.Region = region
			},
		)
		if err != nil {
			sharedLogger.Error(err.Error())
			break
		}

		repositories = append(repositories, DescribeRepositories.Repositories...)

		// Pagination control.
		if DescribeRepositories.NextToken != nil {
			PaginationControl = DescribeRepositories.NextToken
		} else {
			PaginationControl = nil
			break
		}
	}
	internal.Cache.Set(cacheKey, repositories, cache.DefaultExpiration)
	return repositories, nil
}

// create a CachedECRDescribeImages function that uses go-cache line the other Cached* functions. It should accept a ecr client, account id, and region. Make sure it handles the region option and pagination if needed
func CachedECRDescribeImages(ECRClient AWSECRClientInterface, accountID string, region string, repositoryName string) ([]ecrTypes.ImageDetail, error) {
	var PaginationControl *string
	var images []ecrTypes.ImageDetail
	cacheKey := fmt.Sprintf("%s-efs-DescribImages-%s-%s", accountID, region, strings.ReplaceAll(repositoryName, "/", "-"))
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.Debug("Using cached Images data")
		return cached.([]ecrTypes.ImageDetail), nil
	}

	for {
		DescribeImages, err := ECRClient.DescribeImages(
			context.TODO(),
			&ecr.DescribeImagesInput{
				NextToken:      PaginationControl,
				RepositoryName: &repositoryName,
			},
			func(o *ecr.Options) {
				o.Region = region
			},
		)
		if err != nil {
			sharedLogger.Error(err.Error())
			break
		}

		images = append(images, DescribeImages.ImageDetails...)

		// Pagination control.
		if DescribeImages.NextToken != nil {
			PaginationControl = DescribeImages.NextToken
		} else {
			PaginationControl = nil
			break
		}
	}
	internal.Cache.Set(cacheKey, images, cache.DefaultExpiration)
	return images, nil
}

// create a CachedECRGetRepositoryPolicy function that uses go-cache line the other Cached* functions. It should accept a ecr client, account id, and region. Make sure it handles the region option and pagination if needed
func CachedECRGetRepositoryPolicy(ECRClient AWSECRClientInterface, accountID string, region string, repositoryName string) (string, error) {
	// in repositoryName, replace "/" with "-"
	cacheKey := fmt.Sprintf("%s-ecr-GetRepositoryPolicy-%s-%s", accountID, region, strings.ReplaceAll(repositoryName, "/", "-"))
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.Debug("Using cached ECR repository policy data")
		return cached.(string), nil
	}

	GetRepositoryPolicy, err := ECRClient.GetRepositoryPolicy(
		context.TODO(),
		&ecr.GetRepositoryPolicyInput{
			RepositoryName: &repositoryName,
		},
		func(o *ecr.Options) {
			o.Region = region
		},
	)
	if err != nil {
		sharedLogger.Error(err.Error())
		return "", err
	}
	PolicyText := aws.ToString(GetRepositoryPolicy.PolicyText)

	internal.Cache.Set(cacheKey, PolicyText, cache.DefaultExpiration)
	return PolicyText, nil
}
