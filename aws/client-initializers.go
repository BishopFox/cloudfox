package aws

import (
	"github.com/BishopFox/cloudfox/aws/sdk"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	"github.com/aws/aws-sdk-go-v2/service/fsx"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func initIAMSimClient(iamSimPPClient sdk.AWSIAMClientInterface, caller sts.GetCallerIdentityOutput, AWSProfile string, Goroutines int) IamSimulatorModule {

	iamSimMod := IamSimulatorModule{
		IAMClient:          iamSimPPClient,
		Caller:             caller,
		AWSProfileProvided: AWSProfile,
		Goroutines:         Goroutines,
	}

	return iamSimMod

}

func InitCloudFoxSNSClient(caller sts.GetCallerIdentityOutput, AWSProfile string, cfVersion string, Goroutines int, AWSWrapTable bool, AWSMFAToken string) SNSModule {
	var AWSConfig = internal.AWSConfigFileLoader(AWSProfile, cfVersion, AWSMFAToken)
	cloudFoxSNSClient := SNSModule{
		SNSClient:  sns.NewFromConfig(AWSConfig),
		Caller:     caller,
		AWSProfile: AWSProfile,
		AWSRegions: internal.GetEnabledRegions(AWSProfile, cfVersion, AWSMFAToken),
		Goroutines: Goroutines,
		WrapTable:  AWSWrapTable,
	}
	return cloudFoxSNSClient

}

func initCloudFoxS3Client(caller sts.GetCallerIdentityOutput, AWSProfile string, cfVersion string, AWSMFAToken string) BucketsModule {
	var AWSConfig = internal.AWSConfigFileLoader(AWSProfile, cfVersion, AWSMFAToken)
	cloudFoxS3Client := BucketsModule{
		S3Client:   s3.NewFromConfig(AWSConfig),
		Caller:     caller,
		AWSProfile: AWSProfile,
		AWSRegions: internal.GetEnabledRegions(AWSProfile, cfVersion, AWSMFAToken),
	}
	return cloudFoxS3Client

}

func InitSQSClient(caller sts.GetCallerIdentityOutput, AWSProfile string, cfVersion string, Goroutines int, AWSMFAToken string) SQSModule {
	var AWSConfig = internal.AWSConfigFileLoader(AWSProfile, cfVersion, AWSMFAToken)
	sqsClient := SQSModule{
		SQSClient: sqs.NewFromConfig(AWSConfig),

		Caller:     caller,
		AWSRegions: internal.GetEnabledRegions(AWSProfile, cfVersion, AWSMFAToken),
		AWSProfile: AWSProfile,
		Goroutines: Goroutines,
	}

	return sqsClient

}

func InitLambdaClient(caller sts.GetCallerIdentityOutput, AWSProfile string, cfVersion string, Goroutines int, AWSMFAToken string) LambdasModule {
	var AWSConfig = internal.AWSConfigFileLoader(AWSProfile, cfVersion, AWSMFAToken)
	lambdaClient := LambdasModule{
		LambdaClient: lambda.NewFromConfig(AWSConfig),
		Caller:       caller,
		AWSProfile:   AWSProfile,
		AWSRegions:   internal.GetEnabledRegions(AWSProfile, cfVersion, AWSMFAToken),
	}
	return lambdaClient
}

func InitCodeBuildClient(caller sts.GetCallerIdentityOutput, AWSProfile string, cfVersion string, Goroutines int, AWSMFAToken string) CodeBuildModule {
	var AWSConfig = internal.AWSConfigFileLoader(AWSProfile, cfVersion, AWSMFAToken)
	codeBuildClient := CodeBuildModule{
		CodeBuildClient: codebuild.NewFromConfig(AWSConfig),
		Caller:          caller,
		AWSProfile:      AWSProfile,
		AWSRegions:      internal.GetEnabledRegions(AWSProfile, cfVersion, AWSMFAToken),
	}
	return codeBuildClient
}

func InitECRClient(caller sts.GetCallerIdentityOutput, AWSProfile string, cfVersion string, Goroutines int, AWSMFAToken string) ECRModule {
	var AWSConfig = internal.AWSConfigFileLoader(AWSProfile, cfVersion, AWSMFAToken)
	ecrClient := ECRModule{
		ECRClient:  ecr.NewFromConfig(AWSConfig),
		Caller:     caller,
		AWSProfile: AWSProfile,
		AWSRegions: internal.GetEnabledRegions(AWSProfile, cfVersion, AWSMFAToken),
	}
	return ecrClient
}

func InitFileSystemsClient(caller sts.GetCallerIdentityOutput, AWSProfile string, cfVersion string, Goroutines int, AWSMFAToken string) FilesystemsModule {
	var AWSConfig = internal.AWSConfigFileLoader(AWSProfile, cfVersion, AWSMFAToken)
	fileSystemsClient := FilesystemsModule{
		EFSClient:  efs.NewFromConfig(AWSConfig),
		FSxClient:  fsx.NewFromConfig(AWSConfig),
		Caller:     caller,
		AWSProfile: AWSProfile,
		AWSRegions: internal.GetEnabledRegions(AWSProfile, cfVersion, AWSMFAToken),
	}
	return fileSystemsClient
}

func InitOrgClient(caller sts.GetCallerIdentityOutput, AWSProfile string, cfVersion string, Goroutines int, AWSMFAToken string) OrgModule {
	var AWSConfig = internal.AWSConfigFileLoader(AWSProfile, cfVersion, AWSMFAToken)
	orgClient := OrgModule{
		OrganizationsClient: organizations.NewFromConfig(AWSConfig),
		Caller:              caller,
		AWSProfile:          AWSProfile,
		AWSRegions:          internal.GetEnabledRegions(AWSProfile, cfVersion, AWSMFAToken),
	}
	return orgClient
}

func InitSecretsManagerClient(caller sts.GetCallerIdentityOutput, AWSProfile string, cfVersion string, Goroutines int, AWSMFAToken string) *secretsmanager.Client {
	var AWSConfig = internal.AWSConfigFileLoader(AWSProfile, cfVersion, AWSMFAToken)
	return secretsmanager.NewFromConfig(AWSConfig)
}

func InitGlueClient(caller sts.GetCallerIdentityOutput, AWSProfile string, cfVersion string, Goroutines int, AWSMFAToken string) *glue.Client {
	var AWSConfig = internal.AWSConfigFileLoader(AWSProfile, cfVersion, AWSMFAToken)
	return glue.NewFromConfig(AWSConfig)
}
