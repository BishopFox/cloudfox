package aws

import (
	"context"
	"log"
	"testing"

	"github.com/BishopFox/cloudfox/utils"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/eks/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type MockedEKSClientListClusters struct {
	AWSRegions []string
}

type MockedEKSClientDescribeCluster struct {
	AWSRegions []string
}

type MockedEKSClientListNodegroups struct {
	AWSRegions []string
}

type MockedEKSClientDescribeNodegroup struct {
	AWSRegions []string
}

type MockedIAMSimulatePrincipalPolicy struct {
	AWSRegions []string
}

func (m *MockedEKSClientListClusters) ListClusters(ctx context.Context, params *eks.ListClustersInput, optFns ...func(*eks.Options)) (*eks.ListClustersOutput, error) {
	testClusters := []string{}
	testClusters = append(testClusters, "test1")

	testListClustersOutput := &eks.ListClustersOutput{
		Clusters: testClusters,
	}

	return testListClustersOutput, nil
}

func (m *MockedEKSClientDescribeCluster) DescribeCluster(context.Context, *eks.DescribeClusterInput, ...func(*eks.Options)) (*eks.DescribeClusterOutput, error) {
	testCluster := types.Cluster{}
	testIdentity := types.Identity{}
	testOidc := types.OIDC{}
	testCluster.Identity = &testIdentity
	testCluster.Identity.Oidc = &testOidc
	testCluster.Identity.Oidc.Issuer = aws.String("abc123")
	testCluster.Endpoint = aws.String("http://endpoint.com")
	testRVPC := types.VpcConfigResponse{}
	testCluster.ResourcesVpcConfig = &testRVPC
	testCluster.ResourcesVpcConfig.EndpointPublicAccess = true

	testDescribeClusterOutput := &eks.DescribeClusterOutput{
		Cluster: &testCluster,
	}

	return testDescribeClusterOutput, nil
}

func (m *MockedEKSClientListNodegroups) ListNodegroups(ctx context.Context, params *eks.ListNodegroupsInput, optFns ...func(*eks.Options)) (*eks.ListNodegroupsOutput, error) {
	testNodegroups := []string{}
	testNodegroups = append(testNodegroups, "test1")

	testListNodegroupsOutput := &eks.ListNodegroupsOutput{
		Nodegroups: testNodegroups,
	}

	return testListNodegroupsOutput, nil
}

func (m *MockedEKSClientDescribeNodegroup) DescribeNodegroup(context.Context, *eks.DescribeNodegroupInput, ...func(*eks.Options)) (*eks.DescribeNodegroupOutput, error) {
	testNodegroup := types.Nodegroup{}
	testNodegroup.NodeRole = aws.String("roleABC")
	testDescribeNodegroupOutput := &eks.DescribeNodegroupOutput{
		Nodegroup: &testNodegroup,
	}

	return testDescribeNodegroupOutput, nil
}

func TestEks(t *testing.T) {
	subtests := []struct {
		name            string
		outputDirectory string
		verbosity       int
		testModule      EKSModule
		expectedResult  []Cluster
	}{
		{
			name:            "test1",
			outputDirectory: ".",
			verbosity:       2,
			testModule: EKSModule{
				EKSClientListClustersInterface:      &MockedEKSClientListClusters{},
				EKSClientDescribeClusterInterface:   &MockedEKSClientDescribeCluster{},
				EKSClientListNodeGroupsInterface:    &MockedEKSClientListNodegroups{},
				EKSClientDescribeNodeGroupInterface: &MockedEKSClientDescribeNodegroup{},
				//IAMSimulatePrincipalPolicyClient:    iam.SimulatePrincipalPolicyAPIClient,
				Caller:         sts.GetCallerIdentityOutput{Arn: aws.String("test")},
				OutputFormat:   "table",
				AWSProfile:     "test",
				Goroutines:     30,
				AWSRegions:     AWSRegions,
				SkipAdminCheck: true,
			},
			expectedResult: []Cluster{Cluster{
				Name:     "test1",
				Endpoint: "http://endpoint.com",
				OIDC:     "abc123",
				Public:   "Yes",
			}},
		},
	}
	utils.MockFileSystem(true)
	for _, subtest := range subtests {
		t.Run(subtest.name, func(t *testing.T) {
			subtest.testModule.EKS(subtest.testModule.OutputFormat, subtest.outputDirectory, subtest.verbosity)
			for index, expectedCluster := range subtest.expectedResult {
				if expectedCluster.Name != subtest.testModule.Clusters[index].Name {
					log.Fatal("Cluster name does not match expected name")
				}

			}
		})
	}
}
