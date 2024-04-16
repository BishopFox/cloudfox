package policy

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
)

// ensure we don't loose information after parsing and remarshaling
// we marshal only for testing, the output will not necessarily be a valid IAM policy
func TestParsePolicy(t *testing.T) {
	tests := []struct {
		filename string
		want     string
	}{
		{
			filename: "amazon-ec2-full-access.json",
			want:     `{"Version":"2012-10-17","Id":"","Statement":[{"Effect":"Allow","Principal":{},"Action":["ec2:*"],"Resource":["*"]},{"Effect":"Allow","Principal":{},"Action":["elasticloadbalancing:*"],"Resource":["*"]},{"Effect":"Allow","Principal":{},"Action":["cloudwatch:*"],"Resource":["*"]},{"Effect":"Allow","Principal":{},"Action":["autoscaling:*"],"Resource":["*"]},{"Effect":"Allow","Principal":{},"Action":["iam:CreateServiceLinkedRole"],"Resource":["*"],"Condition":{"StringEquals":{"iam:AWSServiceName":["autoscaling.amazonaws.com","ec2scheduled.amazonaws.com","elasticloadbalancing.amazonaws.com","spot.amazonaws.com","spotfleet.amazonaws.com","transitgateway.amazonaws.com"]}}}]}`,
		},
		{
			filename: "sns-conditionally-public.json",
			want:     `{"Version":"","Id":"","Statement":[{"Effect":"Allow","Principal":"*","Action":["SNS:Publish"],"Resource":["arn:aws:sns:us-east-1:123456789012:MyFirstTopic"],"Condition":{"StringEquals":{"aws:sourceVpce":["vpce-1a2b3c4d"]}}}]}`,
		},
		{
			filename: "sns-shared-via-condition.json",
			want:     `{"Version":"","Id":"","Statement":[{"Effect":"Allow","Principal":{"AWS":["*"]},"Action":["SNS:Publish"],"Resource":["arn:aws:sns:us-east-2:444455556666:MyTopic"],"Condition":{"ArnLike":{"aws:SourceArn":["arn:aws:cloudwatch:us-east-2:111122223333:alarm:*"]}}}]}`,
		},
		{
			filename: "sns-shared-with-org.json",
			want:     `{"Version":"","Id":"","Statement":[{"Effect":"Allow","Principal":{"AWS":["*"]},"Action":["SNS:Publish"],"Resource":["arn:aws:sns:us-east-2:444455556666:MyTopic"],"Condition":{"StringEquals":{"aws:PrincipalOrgID":["o-yj4fwt1bwm"]}}}]}`,
		},
		{
			filename: "sqs-conditionally-public.json",
			want:     `{"Version":"2012-10-17","Id":"anyID","Statement":[{"Sid":"conditionally_public","Effect":"Allow","Principal":"*","Action":["sqs:*"],"Resource":["arn:aws:sqs:*:111122223333:queue1"],"Condition":{"IpAddress":{"aws:SourceIp":["192.0.2.0/24"]}}}]}`,
		},
		{
			filename: "sqs-public.json",
			want:     `{"Version":"2012-10-17","Id":"anyID","Statement":[{"Sid":"unconditionally_public","Effect":"Allow","Principal":{"AWS":["*"]},"Action":["sqs:*"],"Resource":["arn:aws:sqs:*:111122223333:queue1"]}]}`,
		},
		{
			filename: "sqs-shared-with-condition.json",
			want:     `{"Version":"2012-10-17","Id":"anyID","Statement":[{"Sid":"conditionally_shared","Effect":"Allow","Principal":{"AWS":["123456789012"]},"Action":["sqs:*"],"Resource":["arn:aws:sqs:*:111122223333:queue1"],"Condition":{"IpAddress":{"aws:SourceIp":["192.0.2.0/24"]}}}]}`,
		},
		{
			filename: "sqs-shared.json",
			want:     `{"Version":"2012-10-17","Id":"anyID","Statement":[{"Sid":"unconditionally_shared","Effect":"Allow","Principal":{"AWS":["111122223333","arn:aws:iam::123456789012:root"]},"Action":["sqs:*"],"Resource":["arn:aws:sqs:*:111122223333:queue1"]}]}`,
		},
	}

	for _, tt := range tests {
		policy, err := getTestFixure(tt.filename)
		if err != nil {
			t.Errorf("Error getting test fixture %s: %s", tt.filename, err)
			continue
		}

		actual, err := json.Marshal(policy)
		if err != nil {
			t.Errorf("Error parsing test fixture %s: %s", tt.filename, err)
			continue
		}

		if tt.want != string(actual) {
			t.Errorf("Policy %s parsed in unexpected way:\n%s\n---\n%s\n---", tt.filename, actual, tt.want)
			continue
		}
	}
}

func TestIsConditionallyPublic(t *testing.T) {
	tests := []struct {
		filename string
		want     bool
	}{
		{filename: "amazon-ec2-full-access.json", want: false},
		{filename: "sns-conditionally-public.json", want: true},
		{filename: "sns-shared-via-condition.json", want: false},
		{filename: "sns-shared-with-org.json", want: false},
		{filename: "sqs-conditionally-public.json", want: true},
		{filename: "sqs-public.json", want: false},
		{filename: "sqs-shared-with-condition.json", want: false},
		{filename: "sqs-shared.json", want: false},
	}

	for _, tt := range tests {
		policy, err := getTestFixure(tt.filename)
		if err != nil {
			t.Errorf("Error getting test fixture %s: %s", tt.filename, err)
			continue
		}

		actual := policy.IsConditionallyPublic()

		if tt.want != actual {
			t.Errorf("IsConditionallyPublic(%s) is %v but should be %v", tt.filename, actual, tt.want)
			continue
		}
	}
}

func TestIsPublic(t *testing.T) {
	tests := []struct {
		filename string
		want     bool
	}{
		{filename: "amazon-ec2-full-access.json", want: false},
		{filename: "sns-conditionally-public.json", want: false},
		{filename: "sns-shared-via-condition.json", want: false},
		{filename: "sns-shared-with-org.json", want: false},
		{filename: "sqs-conditionally-public.json", want: false},
		{filename: "sqs-public.json", want: true},
		{filename: "sqs-shared-with-condition.json", want: false},
		{filename: "sqs-shared.json", want: false},
	}

	for _, tt := range tests {
		policy, err := getTestFixure(tt.filename)
		if err != nil {
			t.Errorf("Error getting test fixture %s: %s", tt.filename, err)
			continue
		}

		actual := policy.IsPublic()

		if tt.want != actual {
			t.Errorf("IsPublic(%s) is %v but should be %v", tt.filename, actual, tt.want)
			continue
		}
	}
}

func getTestFixure(filename string) (*Policy, error) {
	f, err := os.Open("testdata/" + filename)
	if err != nil {
		return nil, fmt.Errorf("opening file: %s", err)
	}
	defer f.Close()

	data, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("reading file: %s", err)
	}

	policy, err := ParseJSONPolicy(data)
	if err != nil {
		return nil, fmt.Errorf("parsing JSON: %s", err)
	}

	return &policy, nil
}
func TestDoesPolicyHaveMatchingStatement(t *testing.T) {
	p := &Policy{
		Statement: []PolicyStatement{
			{
				Effect:   "Allow",
				Action:   []string{"ec2:*"},
				Resource: []string{"*"},
			},
			{
				Effect:   "Allow",
				Action:   []string{"s3:GetObject"},
				Resource: []string{"arn:aws:s3:::bucket/*"},
			},
			{
				Effect:   "Deny",
				Action:   []string{"s3:*"},
				Resource: []string{"arn:aws:s3:::bucket2/*"},
			},
		},
	}

	tests := []struct {
		effect          string
		actionToCheck   string
		resourceToCheck string
		want            bool
	}{
		{
			effect:          "Allow",
			actionToCheck:   "ec2:DescribeInstances",
			resourceToCheck: "arn:aws:ec2:us-west-2:123456789012:instance/*",
			want:            true,
		},
		{
			effect:          "Allow",
			actionToCheck:   "s3:GetObject",
			resourceToCheck: "arn:aws:s3:::bucket/file.txt",
			want:            true,
		},
		{
			effect:          "Allow",
			actionToCheck:   "s3:PutObject",
			resourceToCheck: "arn:aws:s3:::bucket/file.txt",
			want:            false,
		},
		{
			effect:          "Deny",
			actionToCheck:   "s3:GetObject",
			resourceToCheck: "arn:aws:s3:::bucket2/file.txt",
			want:            true,
		},
		{
			effect:          "Deny",
			actionToCheck:   "s3:PutObject",
			resourceToCheck: "arn:aws:s3:::bucket2/file.txt",
			want:            true,
		},
		{
			effect:          "Deny",
			actionToCheck:   "s3:GetObject",
			resourceToCheck: "arn:aws:s3:::bucket/file.txt",
			want:            false,
		},
	}

	for _, tt := range tests {
		actual := p.DoesPolicyHaveMatchingStatement(tt.effect, tt.actionToCheck, tt.resourceToCheck)
		if tt.want != actual {
			t.Errorf("DoesPolicyHaveMatchingStatement(%s, %s, %s) is %v but should be %v", tt.effect, tt.actionToCheck, tt.resourceToCheck, actual, tt.want)
		}
	}
}
