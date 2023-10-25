package aws

import (
	"context"
	"log"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/spf13/afero"
)

type MockedS3Client struct {
}

func (m *MockedS3Client) ListBuckets(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
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

func (m *MockedS3Client) GetBucketPolicy(ctx context.Context, params *s3.GetBucketPolicyInput, optFns ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error) {
	bucketPolicy := `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Sid": "AddPerm",
				"Effect": "Allow",
				"Principal": "*",
				"Action": "s3:GetObject",
				"Resource": "arn:aws:s3:::examplebucket/*"
			}
		]
	}`
	output := &s3.GetBucketPolicyOutput{
		Policy: aws.String(bucketPolicy),
	}
	return output, nil
}

func (m *MockedS3Client) GetBucketLocation(ctx context.Context, params *s3.GetBucketLocationInput, optFns ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error) {
	locationConstraint := types.BucketLocationConstraint("us-east-2")
	output := &s3.GetBucketLocationOutput{
		LocationConstraint: locationConstraint,
	}
	return output, nil
}

func (m *MockedS3Client) GetPublicAccessBlock(ctx context.Context, params *s3.GetPublicAccessBlockInput, optFns ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
	output := &s3.GetPublicAccessBlockOutput{
		PublicAccessBlockConfiguration: &types.PublicAccessBlockConfiguration{
			BlockPublicAcls:       true,
			BlockPublicPolicy:     true,
			IgnorePublicAcls:      false,
			RestrictPublicBuckets: true,
		},
	}
	return output, nil
}

func TestListBuckets(t *testing.T) {

	m := BucketsModule{

		S3Client: &MockedS3Client{},
		Caller: sts.GetCallerIdentityOutput{
			Arn:     aws.String("arn:aws:iam::123456789012:user/cloudfox_unit_tests"),
			Account: aws.String("123456789012"),
		},
		AWSRegions:          []string{"us-east-1", "us-west-1", "us-west-2"},
		AWSProfile:          "unittesting",
		AWSOutputType:       "",
		CheckBucketPolicies: true,
		Goroutines:          3,
	}

	subtests := []struct {
		name            string
		outputDirectory string
		verbosity       int
		testModule      BucketsModule
		expectedResult  []BucketRow
	}{
		{
			name:            "test1",
			outputDirectory: ".",
			verbosity:       2,
			testModule:      m,
			expectedResult: []BucketRow{{
				Name: "mockBucket123",
			}},
		},
	}

	fs := internal.MockFileSystem(true)
	defer internal.MockFileSystem(false)
	tmpDir := "."

	for _, subtest := range subtests {
		t.Run(subtest.name, func(t *testing.T) {
			subtest.testModule.PrintBuckets(subtest.outputDirectory, subtest.verbosity)
			for index, expectedBucket := range subtest.expectedResult {
				resultsFilePath := filepath.Join(tmpDir, "cloudfox-output/aws/unittesting-123456789012/table/buckets.txt")
				resultsFile, err := afero.ReadFile(fs, resultsFilePath)
				if err != nil {
					t.Fatalf("Cannot read output file at %s: %s", resultsFilePath, err)
				}

				expectedResults := strings.TrimLeft(`
╭───────────────┬───────────┬─────────┬───────────────────────────╮
│     Name      │  Region   │ Public? │  Resource Policy Summary  │
├───────────────┼───────────┼─────────┼───────────────────────────┤
│ mockBucket123 │ us-east-2 │ YES     │ Everyone can s3:GetObject │
╰───────────────┴───────────┴─────────┴───────────────────────────╯
`, "\n")
				if string(resultsFile) != expectedResults {
					t.Fatalf("Unexpected results:\n%s\n", resultsFile)
				}

				if expectedBucket.Name != subtest.testModule.Buckets[index].Name {
					log.Fatal("Bucket name does not match expected name")
				}

			}
		})
	}
}
