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
	"github.com/sirupsen/logrus"
)

type AWSS3ClientInterface interface {
	ListBuckets(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
	GetBucketPolicy(ctx context.Context, params *s3.GetBucketPolicyInput, optFns ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error)
	GetBucketLocation(ctx context.Context, params *s3.GetBucketLocationInput, optFns ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error)
	GetPublicAccessBlock(ctx context.Context, params *s3.GetPublicAccessBlockInput, optFns ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error)
}

func init() {
	gob.Register([]s3Types.Bucket{})
	gob.Register(s3Types.Bucket{})
	gob.Register(&s3Types.PublicAccessBlockConfiguration{})
}

func CachedListBuckets(S3Client AWSS3ClientInterface, accountID string) ([]s3Types.Bucket, error) {
	var buckets []s3Types.Bucket
	cacheKey := fmt.Sprintf("%s-s3-ListBuckets", accountID)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.WithFields(logrus.Fields{
			"api":     "s3:ListBuckets",
			"account": accountID,
			"cache":   "hit",
		}).Info("AWS API call")
		return cached.([]s3Types.Bucket), nil

	}
	sharedLogger.WithFields(logrus.Fields{
		"api":     "s3:ListBuckets",
		"account": accountID,
		"cache":   "miss",
	}).Info("AWS API call")
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
		sharedLogger.WithFields(logrus.Fields{
			"api":     "s3:GetBucketLocation",
			"account": accountID,
			"bucket":  bucketName,
			"cache":   "hit",
		}).Info("AWS API call")
		return cached.(string), nil
	}
	sharedLogger.WithFields(logrus.Fields{
		"api":     "s3:GetBucketLocation",
		"account": accountID,
		"bucket":  bucketName,
		"cache":   "miss",
	}).Info("AWS API call")
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
		sharedLogger.WithFields(logrus.Fields{
			"api":     "s3:GetBucketPolicy",
			"account": accountID,
			"region":  r,
			"bucket":  bucketName,
			"cache":   "hit",
		}).Info("AWS API call")
		return cached.(string), nil
	}
	sharedLogger.WithFields(logrus.Fields{
		"api":     "s3:GetBucketPolicy",
		"account": accountID,
		"region":  r,
		"bucket":  bucketName,
		"cache":   "miss",
	}).Info("AWS API call")

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
		internal.Cache.Set(cacheKey, "", cache.DefaultExpiration)
		return "", err
	}

	internal.Cache.Set(cacheKey, aws.ToString(BucketPolicyObject.Policy), cache.DefaultExpiration)
	return *BucketPolicyObject.Policy, nil

}

func CachedGetPublicAccessBlock(S3Client AWSS3ClientInterface, accountID string, r string, bucketName string) (*s3Types.PublicAccessBlockConfiguration, error) {
	cacheKey := fmt.Sprintf("%s-s3-GetPublicAccessBlock-%s-%s", accountID, r, bucketName)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.WithFields(logrus.Fields{
			"api":     "s3:GetPublicAccessBlock",
			"account": accountID,
			"region":  r,
			"bucket":  bucketName,
			"cache":   "hit",
		}).Info("AWS API call")
		return cached.(*s3Types.PublicAccessBlockConfiguration), nil
	}
	sharedLogger.WithFields(logrus.Fields{
		"api":     "s3:GetPublicAccessBlock",
		"account": accountID,
		"region":  r,
		"bucket":  bucketName,
		"cache":   "miss",
	}).Info("AWS API call")

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
