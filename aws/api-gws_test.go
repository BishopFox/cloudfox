package aws

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BishopFox/cloudfox/aws/sdk"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/spf13/afero"
)

func TestApiGw(t *testing.T) {

	m := ApiGwModule{
		AWSProfile: "unittesting",
		AWSRegions: []string{"us-east-1"},
		Caller: sts.GetCallerIdentityOutput{
			Arn:     aws.String("arn:aws:iam::123456789012:user/Alice"),
			Account: aws.String("123456789012"),
		},
		Goroutines:         3,
		WrapTable:          false,
		APIGatewayClient:   &sdk.MockedAWSAPIGatewayClient{},
		APIGatewayv2Client: &sdk.MockedAWSAPIGatewayv2Client{},
	}

	fs := internal.MockFileSystem(true)
	defer internal.MockFileSystem(false)
	tmpDir := "~/.cloudfox/"

	m.PrintApiGws(tmpDir, 2)

	resultsFilePath := filepath.Join(tmpDir, "cloudfox-output/aws/unittesting-123456789012/table/api-gw.txt")
	resultsFile, err := afero.ReadFile(fs, resultsFilePath)
	if err != nil {
		t.Fatalf("Cannot read output file at %s: %s", resultsFilePath, err)
	}
	//print the results file to the screen
	fmt.Println(string(resultsFile))

	// I want a test that runs the main function and checks the output to see if the following items are in the output: "https://qwerty.execute-api.us-east-1.amazonaws.com/stage1/path1", "https://asdfsdfasdf.execute-api.us-east-1.amazonaws.com/stage1/route2"

	expectedResults := []string{
		"https://qwerty.execute-api.us-east-1.amazonaws.com/stage1/path1",
		"https://asdfsdfasdf.execute-api.us-east-1.amazonaws.com/stage1/route2",
		"https://asdfsdfasdf.execute-api.us-east-1.amazonaws.com/stage2/route1",
		"23oieuwefo3rfs",
	}

	for _, expected := range expectedResults {
		if !strings.Contains(string(resultsFile), expected) {
			t.Errorf("Expected %s to be in the results file", expected)
		}
	}
}
