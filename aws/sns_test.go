package aws

import (
	"context"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sns/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/spf13/afero"
)

func TestSNSQueues(t *testing.T) {
	c := &mockedSNSClient{
		Topics: map[string]map[string]string{
			"arn:aws:sns:us-east-1:123456789012:MyFirstTopic": {
				"Policy": `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"SNS:Publish","Resource":"arn:aws:sns:us-east-1:123456789012:MyFirstTopic","Condition":{"StringEquals":{"aws:sourceVpce":"vpce-1a2b3c4d"}}}]}`,
			},
			"arn:aws:sns:us-west-2:123456789012:MySecondTopic": {},
		},
	}

	m := SNSModule{
		SNSClient:  c,
		AWSProfile: "default",
		AWSRegions: []string{"us-east-1", "us-west-1", "us-west-2"},
		Caller:     sts.GetCallerIdentityOutput{Arn: aws.String("arn:aws:iam::123456789012:user/cloudfox_unit_tests")},
		Goroutines: 3,
	}

	fs := internal.MockFileSystem(true)
	defer internal.MockFileSystem(false)
	tmpDir := "."

	// execute the module with 3 goroutines
	m.PrintSNS("table", tmpDir, 3)

	resultsFilePath := filepath.Join(tmpDir, "cloudfox-output/aws/default/table/sns.txt")
	resultsFile, err := afero.ReadFile(fs, resultsFilePath)
	if err != nil {
		t.Fatalf("Cannot read output file at %s: %s", resultsFilePath, err)
	}
	expectedResults := strings.TrimLeft(`
╭──────────────────────────────────────────────────┬────────┬──────────────╮
│                       ARN                        │ Public │ Cond. Public │
├──────────────────────────────────────────────────┼────────┼──────────────┤
│ arn:aws:sns:us-east-1:123456789012:MyFirstTopic  │        │ public-wc    │
│ arn:aws:sns:us-west-2:123456789012:MySecondTopic │        │              │
╰──────────────────────────────────────────────────┴────────┴──────────────╯
`, "\n")
	if string(resultsFile) != expectedResults {
		t.Fatalf("Unexpected results:\n%s\n", resultsFile)
	}
}

/// ########## Mocks ##########

// mockedSNSClient can return data about a hardcoded set of topics
type mockedSNSClient struct {
	Topics map[string]map[string]string // map of topic ARNs to attributes (which are maps of string names to string values)
}

func (c *mockedSNSClient) ListTopics(ctx context.Context, params *sns.ListTopicsInput, optFns ...func(*sns.Options)) (*sns.ListTopicsOutput, error) {
	out := sns.ListTopicsOutput{}

	region := c.getRequestedRegion(optFns...)

	for arn := range c.Topics {
		if getRegionFromTopicARN(arn) != region {
			continue
		}

		out.Topics = append(out.Topics, types.Topic{
			TopicArn: aws.String(arn),
		})
	}

	return &out, nil
}

func (c *mockedSNSClient) GetTopicAttributes(ctx context.Context, params *sns.GetTopicAttributesInput, optFns ...func(*sns.Options)) (*sns.GetTopicAttributesOutput, error) {
	out := sns.GetTopicAttributesOutput{}

	if params.TopicArn == nil {
		return &out, nil
	}

	region := c.getRequestedRegion(optFns...)

	out.Attributes = make(map[string]string)

	for arn, attributes := range c.Topics {
		if arn != *params.TopicArn {
			continue
		}

		if getRegionFromTopicARN(arn) != region {
			continue
		}

		for k, v := range attributes {
			out.Attributes[k] = v
		}
	}

	return &out, nil
}

// Example: arn:aws:sns:us-east-2:123456789012:MyTopic
var reGetRegionFromTopicARN = regexp.MustCompile(`arn:aws:sns:([a-z0-9-]+):[0-9]+:`)

func getRegionFromTopicARN(url string) string {
	match := reGetRegionFromTopicARN.FindStringSubmatch(url)
	if len(match) != 2 {
		return ""
	}

	return match[1]
}

func (c *mockedSNSClient) getRequestedRegion(optFns ...func(*sns.Options)) string {
	opts := &sns.Options{}
	for _, optFn := range optFns {
		optFn(opts)
	}

	return opts.Region
}
