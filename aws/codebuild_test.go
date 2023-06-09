package aws

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	"github.com/aws/aws-sdk-go-v2/service/codebuild/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/spf13/afero"
)

type mockedCodeBuildClient struct {
}

func (m *mockedCodeBuildClient) ListProjects(ctx context.Context, params *codebuild.ListProjectsInput, optFns ...func(*codebuild.Options)) (*codebuild.ListProjectsOutput, error) {
	out := codebuild.ListProjectsOutput{
		Projects: []string{"test1", "test2"},
	}

	return &out, nil
}

func (m *mockedCodeBuildClient) BatchGetProjects(ctx context.Context, params *codebuild.BatchGetProjectsInput, optFns ...func(*codebuild.Options)) (*codebuild.BatchGetProjectsOutput, error) {
	project1out := codebuild.BatchGetProjectsOutput{
		Projects: []types.Project{
			{
				Name: aws.String("test1"),
				Environment: &types.ProjectEnvironment{
					Image: aws.String("aws/codebuild/standard:4.0"),
				},
				ServiceRole: aws.String("arn:aws:iam::123456789012:role/test1"),
				Source: &types.ProjectSource{
					Type:     "CODECOMMIT",
					Location: aws.String("https://git-codecommit.us-east-1.amazonaws.com/v1/repos/test1"),
				},
				Artifacts: &types.ProjectArtifacts{
					Type:     "S3",
					Location: aws.String("s3://test1"),
				},
				TimeoutInMinutes: aws.Int32(60),
			},
		},
	}

	project2out := codebuild.BatchGetProjectsOutput{
		Projects: []types.Project{
			{
				Name: aws.String("test2"),
				Environment: &types.ProjectEnvironment{
					Image: aws.String("aws/codebuild/standard:4.0"),
				},
				ServiceRole: aws.String("arn:aws:iam::123456789012:role/test2"),
				Source: &types.ProjectSource{
					Type:     "GITHUB",
					Location: aws.String("https://test.github.com/test2"),
				},
				Artifacts: &types.ProjectArtifacts{
					Type:     "S3",
					Location: aws.String("s3://test2"),
				},
				TimeoutInMinutes: aws.Int32(60),
			},
		},
	}

	if params.Names[0] == "test1" {
		return &project1out, nil
	} else if params.Names[0] == "test2" {
		return &project2out, nil
	} else {
		return nil, nil
	}
}

func (m *mockedCodeBuildClient) GetResourcePolicy(ctx context.Context, params *codebuild.GetResourcePolicyInput, optFns ...func(*codebuild.Options)) (*codebuild.GetResourcePolicyOutput, error) {
	out := codebuild.GetResourcePolicyOutput{
		Policy: aws.String(`{
			"Version": "2012-10-17",
			"Statement": [
				{
					"Effect": "Allow",
					"Principal": {
						"AWS": "*"
					},
					"Action": [
					"codebuild:StartBuild",
					"codebuild:BatchGetBuilds",
					"codebuild:StopBuild",
					"codebuild:ListProjects",
					"codebuild:BatchGetProjects"
					],
					"Resource": "*"
				}
			]
		}`),
	}

	return &out, nil
}

func TestCodeBuildProjects(t *testing.T) {

	m := CodeBuildModule{
		CodeBuildClient: &mockedCodeBuildClient{},
		AWSProfile:      "unittesting",
		AWSRegions:      []string{"us-west-1"},
		Caller: sts.GetCallerIdentityOutput{
			Arn:     aws.String("arn:aws:iam::123456789012:user/Alice"),
			Account: aws.String("123456789012"),
		},
		Goroutines:     3,
		WrapTable:      true,
		SkipAdminCheck: true,
	}

	fs := internal.MockFileSystem(true)
	defer internal.MockFileSystem(false)
	tmpDir := "."

	// execute the module with verbosity set to 2
	m.PrintCodeBuildProjects("table", tmpDir, 2)

	resultsFilePath := filepath.Join(tmpDir, "cloudfox-output/aws/123456789012-unittesting/table/codebuild.txt")
	resultsFile, err := afero.ReadFile(fs, resultsFilePath)
	if err != nil {
		t.Fatalf("Cannot read output file at %s: %s", resultsFilePath, err)
	}

	expectedResults := strings.TrimLeft(`
╭───────────┬───────┬──────────────────────────────────────┬──────────────╮
│  Region   │ Name  │                 Role                 │ IsAdminRole? │
├───────────┼───────┼──────────────────────────────────────┼──────────────┤
│ us-west-1 │ test1 │ arn:aws:iam::123456789012:role/test1 │ Skipped      │
│ us-west-1 │ test2 │ arn:aws:iam::123456789012:role/test2 │ Skipped      │
╰───────────┴───────┴──────────────────────────────────────┴──────────────╯
`, "\n")
	fmt.Println(expectedResults)
	fmt.Println("results file")
	fmt.Println(string(resultsFile))

	if string(resultsFile) != expectedResults {
		t.Fatalf("Unexpected results:\n%s\n", resultsFile)
	}
}
