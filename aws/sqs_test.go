package aws

import (
	"context"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/BishopFox/cloudfox/utils"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/spf13/afero"
)

func TestSQSQueues(t *testing.T) {
	c := &mockedSQSClient{
		Queues: map[string]map[string]string{
			"https://sqs.us-east-1.amazonaws.com/123456789012/some-name": {
				string(types.QueueAttributeNamePolicy): `{"Version": "2012-10-17","Id": "anyID","Statement": [{"Sid":"unconditionally_public","Effect": "Allow","Principal": {"AWS": "*"},"Action": "sqs:*","Resource": "arn:aws:sqs:*:123456789012:some-queue"}]}`,
			},
			"https://sqs.us-west-1.amazonaws.com/123456789012/another-name": {},
		},
	}

	m := SQSModule{
		SQSClient:  c,
		AWSProfile: "default",
		AWSRegions: []string{"us-east-1", "us-west-1", "us-west-2"},
		Caller:     sts.GetCallerIdentityOutput{Arn: aws.String("arn:aws:iam::123456789012:user/cloudfox_unit_tests")},
		Goroutines: 3,
	}

	fs := utils.MockFileSystem(true)
	defer utils.MockFileSystem(false)
	tmpDir := "."

	// execute the module with 3 goroutines
	m.PrintSQS("table", tmpDir, 3)

	resultsFilePath := filepath.Join(tmpDir, "cloudfox-output/aws/default/table/sqs.txt")
	resultsFile, err := afero.ReadFile(fs, resultsFilePath)
	if err != nil {
		t.Fatalf("Cannot read output file at %s: %s", resultsFilePath, err)
	}
	expectedResults := strings.TrimLeft(`
╭───────────────────────────────────────────────────────────────┬────────┬──────────────╮
│                              URL                              │ Public │ Cond. Public │
├───────────────────────────────────────────────────────────────┼────────┼──────────────┤
│ https://sqs.us-east-1.amazonaws.com/123456789012/some-name    │ public │              │
│ https://sqs.us-west-1.amazonaws.com/123456789012/another-name │        │              │
╰───────────────────────────────────────────────────────────────┴────────┴──────────────╯
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
