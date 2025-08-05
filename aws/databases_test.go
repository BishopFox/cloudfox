package aws

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/BishopFox/cloudfox/aws/sdk"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go/ptr"
	"github.com/spf13/afero"
)

func TestDatabasesCommand(t *testing.T) {

	m := DatabasesModule{
		AWSProfile: "unittesting",
		AWSRegions: []string{"us-east-1"},
		Caller: sts.GetCallerIdentityOutput{
			Arn:     aws.String("arn:aws:iam::123456789012:user/Alice"),
			Account: aws.String("123456789012"),
		},
		Goroutines:     3,
		WrapTable:      false,
		RDSClient:      &sdk.MockedRDSClient{},
		DynamoDBClient: &sdk.MockedAWSDynamoDBClient{},
		RedshiftClient: &sdk.MockedRedshiftClient{},
	}

	fs := internal.MockFileSystem(true)
	defer internal.MockFileSystem(false)
	tmpDir := ptr.ToString(internal.GetLogDirPath())

	m.PrintDatabases(tmpDir, 2)
	//resultsFile, err := afero.ReadFile(fs, "table/databases.txt")
	resultsFilePath := filepath.Join(tmpDir, "cloudfox-output/aws/unittesting-123456789012/table/databases.txt")
	resultsFile, err := afero.ReadFile(fs, resultsFilePath)
	if err != nil {
		t.Fatalf("Cannot read output file at %s: %s", resultsFile, err)
	}

	expectedResults := []string{
		"db1.cluster-123456789012.us-west-2.rds.amazonaws.com", // make sure it includes the Aurora clusters
		"db2.cluster-123456789012.us-west-2.rds.amazonaws.com", // make sure it includes the Aurora clusters
		"db3.cluster-123456789012.us-west-2.neptune.amazonaws.com", // make sure it includes the Neptune instances
		"db4.cluster-123456789012.us-west-2.docdb.amazonaws.com", // make sure it includes the DocumentDB instances
		"db1-instances-1.blah.us-west-2.rds.amazonaws.com", // make sure it includes the RDS instances
	}

	for _, expected := range expectedResults {
		if !strings.Contains(string(resultsFile), expected) {
			t.Errorf("Expected %s to be in the results file", expected)
		}
	}

}
