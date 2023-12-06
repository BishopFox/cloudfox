package aws

import (
	"github.com/BishopFox/cloudfox/aws/sdk"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	"github.com/aws/aws-sdk-go-v2/service/fsx"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func InitIamCommandClient(iamSimPPClient sdk.AWSIAMClientInterface, caller sts.GetCallerIdentityOutput, AWSProfile string, Goroutines int) IamSimulatorModule {

	iamSimMod := IamSimulatorModule{
		IAMClient:  iamSimPPClient,
		Caller:     caller,
		AWSProfile: AWSProfile,
		Goroutines: Goroutines,
	}

	return iamSimMod

}

func InitSNSCommandClient(caller sts.GetCallerIdentityOutput, AWSProfile string, cfVersion string, Goroutines int, AWSWrapTable bool) SNSModule {
	var AWSConfig = internal.AWSConfigFileLoader(AWSProfile, cfVersion)
	cloudFoxSNSClient := SNSModule{
		SNSClient:  sns.NewFromConfig(AWSConfig),
		Caller:     caller,
		AWSProfile: AWSProfile,
		AWSRegions: internal.GetEnabledRegions(AWSProfile, cfVersion),
		Goroutines: Goroutines,
		WrapTable:  AWSWrapTable,
	}
	return cloudFoxSNSClient

}

func InitS3CommandClient(caller sts.GetCallerIdentityOutput, AWSProfile string, cfVersion string) BucketsModule {
	var AWSConfig = internal.AWSConfigFileLoader(AWSProfile, cfVersion)
	cloudFoxS3Client := BucketsModule{
		S3Client:   s3.NewFromConfig(AWSConfig),
		Caller:     caller,
		AWSProfile: AWSProfile,
		AWSRegions: internal.GetEnabledRegions(AWSProfile, cfVersion),
	}
	return cloudFoxS3Client

}

func InitSQSCommandClient(caller sts.GetCallerIdentityOutput, AWSProfile string, cfVersion string, Goroutines int) SQSModule {
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

func InitLambdaCommandClient(caller sts.GetCallerIdentityOutput, AWSProfile string, cfVersion string, Goroutines int) LambdasModule {
	var AWSConfig = internal.AWSConfigFileLoader(AWSProfile, cfVersion)
	lambdaClient := LambdasModule{
		LambdaClient: lambda.NewFromConfig(AWSConfig),
		Caller:       caller,
		AWSProfile:   AWSProfile,
		AWSRegions:   internal.GetEnabledRegions(AWSProfile, cfVersion),
	}
	return lambdaClient
}

func InitCodeBuildCommandClient(caller sts.GetCallerIdentityOutput, AWSProfile string, cfVersion string, Goroutines int) CodeBuildModule {
	var AWSConfig = internal.AWSConfigFileLoader(AWSProfile, cfVersion)
	codeBuildClient := CodeBuildModule{
		CodeBuildClient: codebuild.NewFromConfig(AWSConfig),
		Caller:          caller,
		AWSProfile:      AWSProfile,
		AWSRegions:      internal.GetEnabledRegions(AWSProfile, cfVersion),
	}
	return codeBuildClient
}

func InitECRCommandClient(caller sts.GetCallerIdentityOutput, AWSProfile string, cfVersion string, Goroutines int) ECRModule {
	var AWSConfig = internal.AWSConfigFileLoader(AWSProfile, cfVersion)
	ecrClient := ECRModule{
		ECRClient:  ecr.NewFromConfig(AWSConfig),
		Caller:     caller,
		AWSProfile: AWSProfile,
		AWSRegions: internal.GetEnabledRegions(AWSProfile, cfVersion),
	}
	return ecrClient
}

func InitFileSystemsCommandClient(caller sts.GetCallerIdentityOutput, AWSProfile string, cfVersion string, Goroutines int) FilesystemsModule {
	var AWSConfig = internal.AWSConfigFileLoader(AWSProfile, cfVersion)
	fileSystemsClient := FilesystemsModule{
		EFSClient:  efs.NewFromConfig(AWSConfig),
		FSxClient:  fsx.NewFromConfig(AWSConfig),
		Caller:     caller,
		AWSProfile: AWSProfile,
		AWSRegions: internal.GetEnabledRegions(AWSProfile, cfVersion),
	}
	return fileSystemsClient
}

func InitOrgCommandClient(caller sts.GetCallerIdentityOutput, AWSProfile string, cfVersion string, Goroutines int) OrgModule {
	var AWSConfig = internal.AWSConfigFileLoader(AWSProfile, cfVersion)
	orgClient := OrgModule{
		OrganizationsClient: organizations.NewFromConfig(AWSConfig),
		Caller:              caller,
		AWSProfile:          AWSProfile,
		AWSRegions:          internal.GetEnabledRegions(AWSProfile, cfVersion),
	}
	return orgClient
}

func InitPermissionsClient(caller sts.GetCallerIdentityOutput, AWSProfile string, cfVersion string, Goroutines int) IamPermissionsModule {
	var AWSConfig = internal.AWSConfigFileLoader(AWSProfile, cfVersion)
	permissionsClient := IamPermissionsModule{
		IAMClient:  iam.NewFromConfig(AWSConfig),
		Caller:     caller,
		AWSProfile: AWSProfile,
		AWSRegions: internal.GetEnabledRegions(AWSProfile, cfVersion),
	}
	return permissionsClient
}

func InitSecretsManagerClient(caller sts.GetCallerIdentityOutput, AWSProfile string, cfVersion string, Goroutines int) *secretsmanager.Client {
	var AWSConfig = internal.AWSConfigFileLoader(AWSProfile, cfVersion)
	return secretsmanager.NewFromConfig(AWSConfig)
}

func InitGlueClient(caller sts.GetCallerIdentityOutput, AWSProfile string, cfVersion string, Goroutines int) *glue.Client {
	var AWSConfig = internal.AWSConfigFileLoader(AWSProfile, cfVersion)
	return glue.NewFromConfig(AWSConfig)
}

func InitOrgClient(AWSConfig aws.Config) *organizations.Client {
	return organizations.NewFromConfig(AWSConfig)
}

func InitIAMClient(AWSConfig aws.Config) *iam.Client {
	return iam.NewFromConfig(AWSConfig)
}
