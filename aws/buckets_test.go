package aws

import (
	"context"
	"log"
	"testing"
	"time"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type MockedS3ListBuckets struct {
	AWSRegions []string
}

func (m *MockedS3ListBuckets) ListBuckets(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	buckets := make([]types.Bucket, 1)
	mockBucket := types.Bucket{
		CreationDate: aws.Time(time.Now()),
		Name:         aws.String("mockBucket123"),
	}
	buckets[0] = mockBucket
	output := &s3.ListBucketsOutput{
		Buckets: buckets,
	}
	return output, nil

}

func TestListBuckets(t *testing.T) {
	subtests := []struct {
		name            string
		outputDirectory string
		verbosity       int
		testModule      BucketsModule
		expectedResult  []Bucket
	}{
		{
			name:            "test1",
			outputDirectory: ".",
			verbosity:       2,
			testModule: BucketsModule{
				S3ClientListBucketsInterface: &MockedS3ListBuckets{},
				Caller:                       sts.GetCallerIdentityOutput{Arn: aws.String("test")},
				OutputFormat:                 "table",
				AWSProfile:                   "test",
				Goroutines:                   30,
				AWSRegions:                   AWSRegions,
			},
			expectedResult: []Bucket{{
				Name: "mockBucket123",
			}},
		},
	}

	internal.MockFileSystem(true)
	for _, subtest := range subtests {
		t.Run(subtest.name, func(t *testing.T) {
			subtest.testModule.PrintBuckets(subtest.testModule.OutputFormat, subtest.outputDirectory, subtest.verbosity)
			for index, expectedBucket := range subtest.expectedResult {
				if expectedBucket.Name != subtest.testModule.Buckets[index].Name {
					log.Fatal("Bucket name does not match expected name")
				}

			}
		})
	}
}
