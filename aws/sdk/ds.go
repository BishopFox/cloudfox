package sdk

import (
	"context"
	"encoding/gob"
	"fmt"

	"github.com/patrickmn/go-cache"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/service/directoryservice"
	dsTypes "github.com/aws/aws-sdk-go-v2/service/directoryservice/types"
)

type AWSDSClientInterface interface {
	DescribeDirectories(context.Context, *directoryservice.DescribeDirectoriesInput, ...func(*directoryservice.Options)) (*directoryservice.DescribeDirectoriesOutput, error)
	DescribeTrusts(context.Context, *directoryservice.DescribeTrustsInput, ...func(*directoryservice.Options)) (*directoryservice.DescribeTrustsOutput, error)
}

func init() {
	gob.Register([]dsTypes.DirectoryDescription{})
	gob.Register([]dsTypes.Trust{})

}

func CachedDSDescribeDirectories(client AWSDSClientInterface, accountID string, region string) ([]dsTypes.DirectoryDescription, error) {
	var PaginationControl *string
	var directories []dsTypes.DirectoryDescription
	cacheKey := fmt.Sprintf("%s-ds-DescribeDirectories-%s", accountID, region)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.([]dsTypes.DirectoryDescription), nil
	}
	for {
		DescribeDirectories, err := client.DescribeDirectories(
			context.TODO(),
			&directoryservice.DescribeDirectoriesInput{
				NextToken: PaginationControl,
			},
			func(o *directoryservice.Options) {
				o.Region = region
			},
		)

		if err != nil {
			return directories, err
		}

		directories = append(directories, DescribeDirectories.DirectoryDescriptions...)

		//pagination
		if DescribeDirectories.NextToken == nil {
			break
		}
		PaginationControl = DescribeDirectories.NextToken
	}

	internal.Cache.Set(cacheKey, directories, cache.DefaultExpiration)
	return directories, nil
}

func CachedDSDescribeTrusts(client AWSDSClientInterface, accountID string, region string, directoryId string) ([]dsTypes.Trust, error) {
	var PaginationControl *string
	var trusts []dsTypes.Trust
	cacheKey := fmt.Sprintf("%s-ds-DescribeTrusts-%s-%s", accountID, region, directoryId)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.([]dsTypes.Trust), nil
	}
	for {
		DescribeDirectoryTrusts, err := client.DescribeTrusts(
			context.TODO(),
			&directoryservice.DescribeTrustsInput{
				DirectoryId: &directoryId,
				NextToken: PaginationControl,
			},
			func(o *directoryservice.Options) {
				o.Region = region
			},
		)
		if err != nil {
			return trusts, err
		}

		trusts = append(trusts, DescribeDirectoryTrusts.Trusts...)

		//pagination
		if DescribeDirectoryTrusts.NextToken == nil {
			break
		}
		PaginationControl = DescribeDirectoryTrusts.NextToken
	}
	internal.Cache.Set(cacheKey, trusts, cache.DefaultExpiration)

	return trusts, nil
}
