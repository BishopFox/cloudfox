module github.com/BishopFox/cloudfox

go 1.20

require (
	github.com/Azure/azure-sdk-for-go v68.0.0+incompatible
	github.com/Azure/azure-sdk-for-go/sdk/azidentity v1.4.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources v1.2.0
	github.com/Azure/azure-sdk-for-go/sdk/storage/azblob v1.2.1
	github.com/Azure/go-autorest/autorest v0.11.29
	github.com/Azure/go-autorest/autorest/azure/auth v0.5.12
	github.com/aquasecurity/table v1.8.0
	github.com/aws/aws-sdk-go-v2 v1.24.1
	github.com/aws/aws-sdk-go-v2/config v1.26.2
	github.com/aws/aws-sdk-go-v2/service/apigateway v1.21.6
	github.com/aws/aws-sdk-go-v2/service/apigatewayv2 v1.18.6
	github.com/aws/aws-sdk-go-v2/service/apprunner v1.25.5
	github.com/aws/aws-sdk-go-v2/service/cloud9 v1.22.5
	github.com/aws/aws-sdk-go-v2/service/cloudformation v1.42.5
	github.com/aws/aws-sdk-go-v2/service/cloudfront v1.32.5
	github.com/aws/aws-sdk-go-v2/service/cloudtrail v1.35.6
	github.com/aws/aws-sdk-go-v2/service/codebuild v1.26.5
	github.com/aws/aws-sdk-go-v2/service/dynamodb v1.26.7
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.142.0
	github.com/aws/aws-sdk-go-v2/service/ecr v1.24.6
	github.com/aws/aws-sdk-go-v2/service/ecs v1.35.6
	github.com/aws/aws-sdk-go-v2/service/efs v1.26.5
	github.com/aws/aws-sdk-go-v2/service/eks v1.37.0
	github.com/aws/aws-sdk-go-v2/service/elasticache v1.34.6
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing v1.21.6
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2 v1.26.6
	github.com/aws/aws-sdk-go-v2/service/fsx v1.40.0
	github.com/aws/aws-sdk-go-v2/service/glue v1.73.0
	github.com/aws/aws-sdk-go-v2/service/grafana v1.18.5
	github.com/aws/aws-sdk-go-v2/service/iam v1.28.5
	github.com/aws/aws-sdk-go-v2/service/lambda v1.49.6
	github.com/aws/aws-sdk-go-v2/service/lightsail v1.32.5
	github.com/aws/aws-sdk-go-v2/service/mq v1.20.6
	github.com/aws/aws-sdk-go-v2/service/opensearch v1.27.1
	github.com/aws/aws-sdk-go-v2/service/organizations v1.23.5
	github.com/aws/aws-sdk-go-v2/service/ram v1.23.7
	github.com/aws/aws-sdk-go-v2/service/rds v1.66.0
	github.com/aws/aws-sdk-go-v2/service/redshift v1.39.7
	github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi v1.19.6
	github.com/aws/aws-sdk-go-v2/service/route53 v1.36.0
	github.com/aws/aws-sdk-go-v2/service/s3 v1.47.7
	github.com/aws/aws-sdk-go-v2/service/sagemaker v1.122.0
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.26.0
	github.com/aws/aws-sdk-go-v2/service/sns v1.26.6
	github.com/aws/aws-sdk-go-v2/service/sqs v1.29.6
	github.com/aws/aws-sdk-go-v2/service/ssm v1.44.6
	github.com/aws/aws-sdk-go-v2/service/sts v1.26.6
	github.com/aws/smithy-go v1.19.0
	github.com/bishopfox/awsservicemap v1.0.3
	github.com/dominikbraun/graph v0.23.0
	github.com/fatih/color v1.16.0
	github.com/jedib0t/go-pretty v4.3.0+incompatible
	github.com/kyokomi/emoji v2.2.4+incompatible
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/sirupsen/logrus v1.9.3
	github.com/spf13/afero v1.11.0
	github.com/spf13/cobra v1.8.0
	golang.org/x/crypto v0.17.0
)

require (
	github.com/aws/aws-sdk-go-v2/service/neptune v1.28.2 // indirect
	github.com/golang-jwt/jwt/v5 v5.2.0 // indirect
)

require (
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.9.1 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.5.1 // indirect
	github.com/Azure/go-autorest v14.2.0+incompatible // indirect
	github.com/Azure/go-autorest/autorest/adal v0.9.23 // indirect
	github.com/Azure/go-autorest/autorest/azure/cli v0.4.6 // indirect
	github.com/Azure/go-autorest/autorest/date v0.3.0 // indirect
	github.com/Azure/go-autorest/autorest/to v0.4.0 // indirect
	github.com/Azure/go-autorest/autorest/validation v0.3.1 // indirect
	github.com/Azure/go-autorest/logger v0.2.1 // indirect
	github.com/Azure/go-autorest/tracing v0.6.0 // indirect
	github.com/AzureAD/microsoft-authentication-library-for-go v1.2.0 // indirect
	github.com/asaskevich/govalidator v0.0.0-20230301143203-a9d515a09cc2 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.5.4 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.16.13
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.14.10 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.2.10 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.5.10 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.7.2 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.2.9 // indirect
	github.com/aws/aws-sdk-go-v2/service/athena v1.37.3
	github.com/aws/aws-sdk-go-v2/service/codeartifact v1.23.5
	github.com/aws/aws-sdk-go-v2/service/codecommit v1.20.0
	github.com/aws/aws-sdk-go-v2/service/codedeploy v1.22.2
	github.com/aws/aws-sdk-go-v2/service/datapipeline v1.19.5
	github.com/aws/aws-sdk-go-v2/service/docdb v1.29.5
	github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk v1.20.5
	github.com/aws/aws-sdk-go-v2/service/emr v1.35.6
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.10.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.2.9 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/endpoint-discovery v1.8.10 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.10.10 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.16.9 // indirect
	github.com/aws/aws-sdk-go-v2/service/kinesis v1.24.6
	github.com/aws/aws-sdk-go-v2/service/sfn v1.24.6
	github.com/aws/aws-sdk-go-v2/service/sso v1.18.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.21.5 // indirect
	github.com/dimchansky/utfbom v1.1.1 // indirect
	github.com/go-openapi/errors v0.21.0 // indirect
	github.com/go-openapi/strfmt v0.21.10 // indirect
	github.com/golang-jwt/jwt/v4 v4.5.0 // indirect
	github.com/google/uuid v1.5.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-runewidth v0.0.15 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/oklog/ulid v1.3.1 // indirect
	github.com/pkg/browser v0.0.0-20210911075715-681adbf594b8 // indirect
	github.com/rivo/uniseg v0.4.4 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	go.mongodb.org/mongo-driver v1.13.1 // indirect
	golang.org/x/net v0.19.0 // indirect
	golang.org/x/sys v0.15.0 // indirect
	golang.org/x/term v0.15.0 // indirect
	golang.org/x/text v0.14.0 // indirect
)
