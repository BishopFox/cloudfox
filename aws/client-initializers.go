package aws

import (
	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func initIAMSimClient(iamSimPPClient iam.SimulatePrincipalPolicyAPIClient, caller sts.GetCallerIdentityOutput, AWSProfile string, Goroutines int) IamSimulatorModule {

	iamSimMod := IamSimulatorModule{
		IAMSimulatePrincipalPolicyClient: iamSimPPClient,
		Caller:                           caller,
		AWSProfile:                       AWSProfile,
		Goroutines:                       Goroutines,
	}

	return iamSimMod

}

func InitCloudFoxSNSClient(caller sts.GetCallerIdentityOutput, AWSProfile string, cfVersion string) CloudFoxSNSClient {
	var AWSConfig = internal.AWSConfigFileLoader(AWSProfile, cfVersion)
	cloudFoxSNSClient := CloudFoxSNSClient{
		SNSClient:  sns.NewFromConfig(AWSConfig),
		Caller:     caller,
		AWSProfile: AWSProfile,
		AWSRegions: internal.GetEnabledRegions(AWSProfile, cfVersion),
	}
	return cloudFoxSNSClient

}

func initCloudFoxS3Client(caller sts.GetCallerIdentityOutput, AWSProfile string, cfVersion string) CloudFoxS3Client {
	var AWSConfig = internal.AWSConfigFileLoader(AWSProfile, cfVersion)
	cloudFoxS3Client := CloudFoxS3Client{
		S3Client:   s3.NewFromConfig(AWSConfig),
		Caller:     caller,
		AWSProfile: AWSProfile,
		AWSRegions: internal.GetEnabledRegions(AWSProfile, cfVersion),
	}
	return cloudFoxS3Client

}

func InitSQSClient(caller sts.GetCallerIdentityOutput, AWSProfile string, cfVersion string, Goroutines int) SQSModule {
	var AWSConfig = internal.AWSConfigFileLoader(AWSProfile, cfVersion)
	sqsClient := SQSModule{
		SQSClient: sqs.NewFromConfig(AWSConfig),

		Caller:     caller,
		AWSRegions: internal.GetEnabledRegions(AWSProfile, cfVersion),
		AWSProfile: AWSProfile,
		Goroutines: Goroutines,
	}

	return sqsClient

}

func InitLambdaClient(caller sts.GetCallerIdentityOutput, AWSProfile string, cfVersion string) LambdasModule {
	var AWSConfig = internal.AWSConfigFileLoader(AWSProfile, cfVersion)
	lambdaClient := LambdasModule{
		LambdaClient: lambda.NewFromConfig(AWSConfig),
		Caller:       caller,
		AWSProfile:   AWSProfile,
		AWSRegions:   internal.GetEnabledRegions(AWSProfile, cfVersion),
	}
	return lambdaClient
}

func InitCodeBuildClient(caller sts.GetCallerIdentityOutput, AWSProfile string, cfVersion string, Goroutines int) CodeBuildModule {
	var AWSConfig = internal.AWSConfigFileLoader(AWSProfile, cfVersion)
	codeBuildClient := CodeBuildModule{
		CodeBuildClient: codebuild.NewFromConfig(AWSConfig),
		Caller:          caller,
		AWSProfile:      AWSProfile,
		AWSRegions:      internal.GetEnabledRegions(AWSProfile, cfVersion),
	}
	return codeBuildClient
}

func InitECRClient(caller sts.GetCallerIdentityOutput, AWSProfile string, cfVersion string, Goroutines int) ECRModule {
	var AWSConfig = internal.AWSConfigFileLoader(AWSProfile, cfVersion)
	ecrClient := ECRModule{
		ECRClient:  ecr.NewFromConfig(AWSConfig),
		Caller:     caller,
		AWSProfile: AWSProfile,
		AWSRegions: internal.GetEnabledRegions(AWSProfile, cfVersion),
	}
	return ecrClient
}
