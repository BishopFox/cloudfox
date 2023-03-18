package aws

// import (
// 	"context"

// 	"github.com/aws/aws-sdk-go-v2/service/codebuild"
// )

// type mockedCodeBuildClient struct {

// }

// m := CodeBuildModule{
// 	CodeBuildClient: &mockedCodeBuildClient{},
// 	AWSProfile: 	"unittesting",
// 	AWSRegions:      []string{"us-east-1"},
// 	Caller: 		sts.GetCallerIdentityOutput{
// 		Arn: aws.String("arn:aws:iam::123456789012:user/Alice"),
// 		Account: aws.String("123456789012"),

// 	},
// 	Goroutines: 3,
// 	WrapTable:  true,

// }

// func (m *MockedCodeBuildClient) ListProjects(ctx context.Context, params *codebuild.ListProjectsInput, optFns ...func(*codebuild.Options)) (*codebuild.ListProjectsOutput, error) {
// 	out := codebuild.ListProjectsOutput{}

// 	region := m.getRequestedRegion(optFns...)

// 	for arn := range m.Projects {
// 		if getRegionFromProjectARN(arn) != region {
// 			continue
// 		}

// 		out.Projects = append(out.Projects, arn)
// 	}

// 	return &out, nil
// }

// func (m *MockedCodeBuildClient) BatchGetProjects(ctx context.Context, params *codebuild.BatchGetProjectsInput, optFns ...func(*codebuild.Options)) (*codebuild.BatchGetProjectsOutput, error) {
// 	out := codebuild.BatchGetProjectsOutput{}

// 	for _, arn := range params.ProjectNames {
// 		project, ok := m.Projects[arn]
// 		if !ok {
// 			continue
// 		}

// 		out.Projects = append(out.Projects, project)
// 	}

// 	return &out, nil
// }
