package aws

import (
	"context"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/spf13/afero"
)

func TestSQSQueues(t *testing.T) {
	c := &mockedSQSClient{
		Queues: map[string]map[string]string{
			"https://sqs.us-east-1.amazonaws.com/123456789012/policy-queue": {
				string(types.QueueAttributeNamePolicy):   `{"Version": "2012-10-17","Id": "anyID","Statement": [{"Sid":"unconditionally_public","Effect": "Allow","Principal": {"AWS": "*"},"Action": "sqs:*","Resource": "arn:aws:sqs:*:123456789012:some-queue"}]}`,
				string(types.QueueAttributeNameQueueArn): `arn:aws:sqs:us-east-1:123456789012:policy-queue`,
			},
			"https://sqs.us-west-1.amazonaws.com/123456789012/no-policy-queue": {
				string(types.QueueAttributeNameQueueArn): `arn:aws:sqs:us-east-1:123456789012:no-policy-queue`,
			},
			"https://sqs.us-east-1.amazonaws.com/123456789012/condition-queue": {
				string(types.QueueAttributeNamePolicy):   `{"Version":"2012-10-17","Id":"SQS-Account-Policy","Statement":[{"Sid":"Allows3Access","Effect":"Allow","Principal":{"Service":"s3.amazonaws.com"},"Action":"SQS:SendMessage","Resource":"arn:aws:sqs:us-west-2:123456789012:terraform-example-queue"},{"Sid":"AllowRoleAccess","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"SQS:*","Resource":"arn:aws:sqs:us-west-2:123456789012:terraform-example-queue"},{"Sid":"AllowFullAccess","Effect":"Allow","Principal":"*","Action":["SQS:SendMessage","SQS:ReceiveMessage"],"Resource":"arn:aws:sqs:us-west-2:123456789012:terraform-example-queue"}]}`,
				string(types.QueueAttributeNameQueueArn): `arn:aws:sqs:us-east-1:123456789012:condition-queue`,
			},
		},
	}

	m := SQSModule{
		SQSClient:  c,
		AWSProfile: "unittesting",
		AWSRegions: []string{"us-east-1", "us-west-1", "us-west-2"},
		Caller: sts.GetCallerIdentityOutput{
			Arn:     aws.String("arn:aws:iam::123456789012:user/cloudfox_unit_tests"),
			Account: aws.String("123456789012"),
		},
		Goroutines: 3,
	}

	fs := internal.MockFileSystem(true)
	defer internal.MockFileSystem(false)
	tmpDir := "."

	// execute the module with verbosity set to 2
	m.PrintSQS("table", tmpDir, 2)

	resultsFilePath := filepath.Join(tmpDir, "cloudfox-output/aws/unittesting/table/sqs.txt")
	resultsFile, err := afero.ReadFile(fs, resultsFilePath)
	if err != nil {
		t.Fatalf("Cannot read output file at %s: %s", resultsFilePath, err)
	}
	expectedResults := strings.TrimLeft(`
╭────────────────────────────────────────────────────┬─────────┬─────────────────────────────────────────────────────────────────────────╮
│                        Arn                         │ Public? │                         Resource Policy Summary                         │
├────────────────────────────────────────────────────┼─────────┼─────────────────────────────────────────────────────────────────────────┤
│ arn:aws:sqs:us-east-1:123456789012:condition-queue │ YES     │ Statement 0 says: s3.amazonaws.com can SQS:SendMessage                  │
│                                                    │         │                                                                         │
│                                                    │         │ Statement 1 says: arn:aws:iam::123456789012:root can SQS:*              │
│                                                    │         │                                                                         │
│                                                    │         │ Statement 2 says: Everyone can SQS:SendMessage & can SQS:ReceiveMessage │
│                                                    │         │                                                                         │
│ arn:aws:sqs:us-east-1:123456789012:policy-queue    │ YES     │ * can sqs:*                                                             │
│                                                    │         │                                                                         │
│ arn:aws:sqs:us-east-1:123456789012:no-policy-queue │ No      │                                                                         │
╰────────────────────────────────────────────────────┴─────────┴─────────────────────────────────────────────────────────────────────────╯
`, "\n")
	if string(resultsFile) != expectedResults {
		t.Fatalf("Unexpected results:\n%s\n", resultsFile)
	}
}

/// ########## Mocks ##########

// mockedSQSClient can return data about a hardcoded set of queues
type mockedSQSClient struct {
	Queues map[string]map[string]string // map of queue URL to attributes (which are maps of string names to string values)
}

func (c *mockedSQSClient) ListQueues(ctx context.Context, params *sqs.ListQueuesInput, optFns ...func(*sqs.Options)) (*sqs.ListQueuesOutput, error) {
	out := sqs.ListQueuesOutput{}

	region := getRequestedRegion(optFns...)

	for url := range c.Queues {
		if getRegionFromQueueURL(url) != region {
			continue
		}

		out.QueueUrls = append(out.QueueUrls, url)
	}

	return &out, nil
}

func (c *mockedSQSClient) GetQueueAttributes(ctx context.Context, params *sqs.GetQueueAttributesInput, optFns ...func(*sqs.Options)) (*sqs.GetQueueAttributesOutput, error) {
	out := sqs.GetQueueAttributesOutput{}

	if params.QueueUrl == nil {
		return &out, nil
	}

	region := getRequestedRegion(optFns...)

	out.Attributes = make(map[string]string)

	for url, attributes := range c.Queues {
		if url != *params.QueueUrl {
			continue
		}

		if getRegionFromQueueURL(url) != region {
			continue
		}

		for k, v := range attributes {
			out.Attributes[k] = v
		}
	}

	return &out, nil
}

// Example: https://sqs.us-east-1.amazonaws.com/123456789012/some-name
var reGetRegionFromQueueURL = regexp.MustCompile(`https://sqs.([a-z0-9-]+).amazonaws.com`)

func getRegionFromQueueURL(url string) string {
	match := reGetRegionFromQueueURL.FindStringSubmatch(url)
	if len(match) != 2 {
		return ""
	}

	return match[1]
}

func getRequestedRegion(optFns ...func(*sqs.Options)) string {
	opts := &sqs.Options{}
	for _, optFn := range optFns {
		optFn(opts)
	}

	return opts.Region
}
