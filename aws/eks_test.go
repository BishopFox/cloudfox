package aws

import (
	"context"
	"log"
	"testing"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/eks/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type MockedEKSClientInterface struct {
}

func (m *MockedEKSClientInterface) ListClusters(ctx context.Context, params *eks.ListClustersInput, optFns ...func(*eks.Options)) (*eks.ListClustersOutput, error) {
	testClusters := []string{}
	testClusters = append(testClusters, "test1")

	testListClustersOutput := &eks.ListClustersOutput{
		Clusters: testClusters,
	}

	return testListClustersOutput, nil
}

func (m *MockedEKSClientInterface) DescribeCluster(context.Context, *eks.DescribeClusterInput, ...func(*eks.Options)) (*eks.DescribeClusterOutput, error) {
	testIdentity := types.Identity{
		Oidc: &types.OIDC{
			Issuer: aws.String("abc123"),
		},
	}
	testRVPC := types.VpcConfigResponse{
		EndpointPublicAccess: true,
	}

	testCluster := types.Cluster{
		Identity:           &testIdentity,
		Endpoint:           aws.String("http://endpoint.com"),
		ResourcesVpcConfig: &testRVPC,
	}

	testDescribeClusterOutput := &eks.DescribeClusterOutput{
		Cluster: &testCluster,
	}

	return testDescribeClusterOutput, nil
}

func (m *MockedEKSClientInterface) ListNodegroups(ctx context.Context, params *eks.ListNodegroupsInput, optFns ...func(*eks.Options)) (*eks.ListNodegroupsOutput, error) {
	testNodegroups := []string{}
	testNodegroups = append(testNodegroups, "test1")

	testListNodegroupsOutput := &eks.ListNodegroupsOutput{
		Nodegroups: testNodegroups,
	}

	return testListNodegroupsOutput, nil
}

func (m *MockedEKSClientInterface) DescribeNodegroup(context.Context, *eks.DescribeNodegroupInput, ...func(*eks.Options)) (*eks.DescribeNodegroupOutput, error) {
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
				EKSClient: &MockedEKSClientInterface{},
				//IAMSimulatePrincipalPolicyClient:    iam.SimulatePrincipalPolicyAPIClient,
				Caller:         sts.GetCallerIdentityOutput{Arn: aws.String("test")},
				AWSProfile:     "test",
				Goroutines:     30,
				AWSRegions:     AWSRegions,
				SkipAdminCheck: true,
			},
			expectedResult: []Cluster{{
				Name:      "test1",
				Endpoint:  "http://endpoint.com",
				NodeGroup: "test1",
				OIDC:      "abc123",
				Public:    "true",
			}},
		},
	}
	internal.MockFileSystem(true)
	for _, subtest := range subtests {
		t.Run(subtest.name, func(t *testing.T) {
			subtest.testModule.EKS(subtest.outputDirectory, subtest.verbosity)
			for index, expectedCluster := range subtest.expectedResult {
				if expectedCluster.Name != subtest.testModule.Clusters[index].Name {
					log.Fatal("Cluster name does not match expected value")
				}
				if expectedCluster.Endpoint != subtest.testModule.Clusters[index].Endpoint {
					log.Fatal("Cluster endpoint does not match expected value")
				}
				if expectedCluster.OIDC != subtest.testModule.Clusters[index].OIDC {
					log.Fatal("Cluster OIDC does not match expected value")
				}
				if expectedCluster.Public != subtest.testModule.Clusters[index].Public {
					log.Fatal("Cluster public does not match expected value")
				}
				if expectedCluster.NodeGroup != subtest.testModule.Clusters[index].NodeGroup {
					log.Fatal("Cluster NodeGroup does not match expected value")
				}

			}
		})
	}
}
