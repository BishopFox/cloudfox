package sdk

import (
	"context"
	"encoding/gob"
	"fmt"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3Types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/patrickmn/go-cache"
)

type AWSS3ClientInterface interface {
	ListBuckets(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
	GetBucketPolicy(ctx context.Context, params *s3.GetBucketPolicyInput, optFns ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error)
	GetBucketLocation(ctx context.Context, params *s3.GetBucketLocationInput, optFns ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error)
	GetPublicAccessBlock(ctx context.Context, params *s3.GetPublicAccessBlockInput, optFns ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error)
}

func RegisterS3Types() {
	gob.Register([]s3Types.Bucket{})
	gob.Register(s3Types.Bucket{})
	gob.Register(&s3Types.PublicAccessBlockConfiguration{})
}

func CachedListBuckets(S3Client AWSS3ClientInterface, accountID string) ([]s3Types.Bucket, error) {
	var buckets []s3Types.Bucket
	cacheKey := fmt.Sprintf("%s-s3-ListBuckets", accountID)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.Debug("Using cached data for ListBuckets data")
		return cached.([]s3Types.Bucket), nil

	}
	ListBuckets, err := S3Client.ListBuckets(
		context.TODO(),
		&s3.ListBucketsInput{},
	)
	if err != nil {
		return buckets, err
	}

	buckets = append(buckets, ListBuckets.Buckets...)
	internal.Cache.Set(cacheKey, buckets, cache.DefaultExpiration)
	return buckets, nil

}

func CachedGetBucketLocation(S3Client AWSS3ClientInterface, accountID string, bucketName string) (string, error) {
	cacheKey := fmt.Sprintf("%s-s3-GetBucketLocation-%s", accountID, bucketName)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.Debug("Using cached data for GetBucketLocation data")
		return cached.(string), nil
	}
	GetBucketRegion, err := S3Client.GetBucketLocation(
		context.TODO(),
		&s3.GetBucketLocationInput{
			Bucket: &bucketName,
		},
	)
	if err != nil {
		return "", err
	}
	location := string(GetBucketRegion.LocationConstraint)
	if location == "" {
		location = "us-east-1"
	}
	internal.Cache.Set(cacheKey, location, cache.DefaultExpiration)
	return location, err
}

func CachedGetBucketPolicy(S3Client AWSS3ClientInterface, accountID string, r string, bucketName string) (string, error) {
	cacheKey := fmt.Sprintf("%s-s3-GetBucketPolicy-%s-%s", accountID, r, bucketName)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.Debug("Using cached data for GetBucketPolicy data")
		return cached.(string), nil
	}

	BucketPolicyObject, err := S3Client.GetBucketPolicy(
		context.TODO(),
		&s3.GetBucketPolicyInput{
			Bucket: &bucketName,
		},
		func(o *s3.Options) {
			o.Region = r
		},
	)
	if err != nil {
		return "", err
	}

	internal.Cache.Set(cacheKey, aws.ToString(BucketPolicyObject.Policy), cache.DefaultExpiration)
	return *BucketPolicyObject.Policy, nil

}

func CachedGetPublicAccessBlock(S3Client AWSS3ClientInterface, accountID string, r string, bucketName string) (*s3Types.PublicAccessBlockConfiguration, error) {
	cacheKey := fmt.Sprintf("%s-s3-GetPublicAccessBlock-%s-%s", accountID, r, bucketName)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.Debug("Using cached data for GetPublicAccessBlock data")
		return cached.(*s3Types.PublicAccessBlockConfiguration), nil
	}

	PublicAccessBlock, err := S3Client.GetPublicAccessBlock(
		context.TODO(),
		&s3.GetPublicAccessBlockInput{
			Bucket: &bucketName,
		},
		func(o *s3.Options) {
			o.Region = r
		},
	)
	if err != nil {
		return nil, err
	}

	internal.Cache.Set(cacheKey, PublicAccessBlock.PublicAccessBlockConfiguration, cache.DefaultExpiration)
	return PublicAccessBlock.PublicAccessBlockConfiguration, err
}
