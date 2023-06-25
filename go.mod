module github.com/BishopFox/cloudfox

go 1.20

require (
	cloud.google.com/go/resourcemanager v1.7.0
	cloud.google.com/go/storage v1.28.1
	github.com/Azure/azure-sdk-for-go v68.0.0+incompatible
	github.com/Azure/azure-sdk-for-go/sdk/azidentity v1.3.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources v1.1.1
	github.com/Azure/azure-sdk-for-go/sdk/storage/azblob v1.0.0
	github.com/Azure/go-autorest/autorest v0.11.29
	github.com/Azure/go-autorest/autorest/azure/auth v0.5.12
	github.com/aquasecurity/table v1.8.0
	github.com/aws/aws-sdk-go-v2 v1.18.0
	github.com/aws/aws-sdk-go-v2/config v1.18.25
	github.com/aws/aws-sdk-go-v2/service/apigateway v1.16.11
	github.com/aws/aws-sdk-go-v2/service/apigatewayv2 v1.13.11
	github.com/aws/aws-sdk-go-v2/service/apprunner v1.17.9
	github.com/aws/aws-sdk-go-v2/service/cloudformation v1.29.0
	github.com/aws/aws-sdk-go-v2/service/cloudfront v1.26.6
	github.com/aws/aws-sdk-go-v2/service/cloudtrail v1.26.0
	github.com/aws/aws-sdk-go-v2/service/codebuild v1.20.13
	github.com/aws/aws-sdk-go-v2/service/dynamodb v1.19.7
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.99.0
	github.com/aws/aws-sdk-go-v2/service/ecr v1.18.11
	github.com/aws/aws-sdk-go-v2/service/ecs v1.27.1
	github.com/aws/aws-sdk-go-v2/service/efs v1.20.1
	github.com/aws/aws-sdk-go-v2/service/eks v1.27.12
	github.com/aws/aws-sdk-go-v2/service/elasticache v1.27.0
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing v1.15.10
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2 v1.19.11
	github.com/aws/aws-sdk-go-v2/service/fsx v1.28.13
	github.com/aws/aws-sdk-go-v2/service/glue v1.50.0
	github.com/aws/aws-sdk-go-v2/service/grafana v1.13.1
	github.com/aws/aws-sdk-go-v2/service/iam v1.20.0
	github.com/aws/aws-sdk-go-v2/service/lambda v1.35.0
	github.com/aws/aws-sdk-go-v2/service/lightsail v1.26.6
	github.com/aws/aws-sdk-go-v2/service/mq v1.14.11
	github.com/aws/aws-sdk-go-v2/service/opensearch v1.17.0
	github.com/aws/aws-sdk-go-v2/service/organizations v1.19.6
	github.com/aws/aws-sdk-go-v2/service/ram v1.18.2
	github.com/aws/aws-sdk-go-v2/service/rds v1.45.0
	github.com/aws/aws-sdk-go-v2/service/redshift v1.27.11
	github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi v1.14.12
	github.com/aws/aws-sdk-go-v2/service/route53 v1.28.1
	github.com/aws/aws-sdk-go-v2/service/s3 v1.33.1
	github.com/aws/aws-sdk-go-v2/service/sagemaker v1.83.0
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.19.8
	github.com/aws/aws-sdk-go-v2/service/sns v1.20.11
	github.com/aws/aws-sdk-go-v2/service/sqs v1.23.0
	github.com/aws/aws-sdk-go-v2/service/ssm v1.36.4
	github.com/aws/aws-sdk-go-v2/service/sts v1.19.0
	github.com/aws/smithy-go v1.13.5
	github.com/bishopfox/awsservicemap v1.0.2
	github.com/dominikbraun/graph v0.22.2
	github.com/fatih/color v1.15.0
	github.com/jedib0t/go-pretty v4.3.0+incompatible
	github.com/kyokomi/emoji v2.2.4+incompatible
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/shivamMg/ppds v0.0.1
	github.com/sirupsen/logrus v1.9.3
	github.com/spf13/afero v1.9.5
	github.com/spf13/cobra v1.7.0
	golang.org/x/crypto v0.9.0
	golang.org/x/oauth2 v0.8.0
	google.golang.org/api v0.127.0
	gopkg.in/ini.v1 v1.67.0
	modernc.org/sqlite v1.23.1
)

require (
	cloud.google.com/go v0.110.0 // indirect
	cloud.google.com/go/compute v1.19.3 // indirect
	cloud.google.com/go/compute/metadata v0.2.3 // indirect
	cloud.google.com/go/iam v0.13.0 // indirect
	cloud.google.com/go/longrunning v0.4.1 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/google/s2a-go v0.1.4 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.2.4 // indirect
	github.com/googleapis/gax-go/v2 v2.10.0 // indirect
	github.com/kballard/go-shellquote v0.0.0-20180428030007-95032a82bc51 // indirect
	github.com/mattn/go-sqlite3 v1.14.17 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	go.opencensus.io v0.24.0 // indirect
	golang.org/x/mod v0.8.0 // indirect
	golang.org/x/tools v0.6.0 // indirect
	golang.org/x/xerrors v0.0.0-20220907171357-04be3eba64a2 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto v0.0.0-20230530153820-e85fd2cbaebc // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20230530153820-e85fd2cbaebc // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20230530153820-e85fd2cbaebc // indirect
	google.golang.org/grpc v1.55.0 // indirect
	google.golang.org/protobuf v1.30.0 // indirect
	lukechampine.com/uint128 v1.2.0 // indirect
	modernc.org/cc/v3 v3.40.0 // indirect
	modernc.org/ccgo/v3 v3.16.13 // indirect
	modernc.org/libc v1.22.5 // indirect
	modernc.org/mathutil v1.5.0 // indirect
	modernc.org/memory v1.5.0 // indirect
	modernc.org/opt v0.1.3 // indirect
	modernc.org/strutil v1.1.3 // indirect
	modernc.org/token v1.0.1 // indirect
)

require (
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.6.1 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.3.0 // indirect
	github.com/Azure/go-autorest v14.2.0+incompatible // indirect
	github.com/Azure/go-autorest/autorest/adal v0.9.23 // indirect
	github.com/Azure/go-autorest/autorest/azure/cli v0.4.6 // indirect
	github.com/Azure/go-autorest/autorest/date v0.3.0 // indirect
	github.com/Azure/go-autorest/autorest/to v0.4.0 // indirect
	github.com/Azure/go-autorest/autorest/validation v0.3.1 // indirect
	github.com/Azure/go-autorest/logger v0.2.1 // indirect
	github.com/Azure/go-autorest/tracing v0.6.0 // indirect
	github.com/AzureAD/microsoft-authentication-library-for-go v1.0.0 // indirect
	github.com/asaskevich/govalidator v0.0.0-20230301143203-a9d515a09cc2 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.4.10 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.13.24 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.13.3 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.1.33 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.4.27 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.3.34 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.0.25 // indirect
	github.com/aws/aws-sdk-go-v2/service/docdb v1.21.3
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.9.11 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.1.28 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/endpoint-discovery v1.7.27 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.9.27 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.14.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/sfn v1.17.11
	github.com/aws/aws-sdk-go-v2/service/sso v1.12.10 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.14.10 // indirect
	github.com/dimchansky/utfbom v1.1.1 // indirect
	github.com/go-openapi/errors v0.20.3 // indirect
	github.com/go-openapi/strfmt v0.21.7 // indirect
	github.com/golang-jwt/jwt/v4 v4.5.0 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.19 // indirect
	github.com/mattn/go-runewidth v0.0.14 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/oklog/ulid v1.3.1 // indirect
	github.com/pkg/browser v0.0.0-20210911075715-681adbf594b8 // indirect
	github.com/rivo/uniseg v0.4.4 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	go.mongodb.org/mongo-driver v1.11.7 // indirect
	golang.org/x/net v0.10.0 // indirect
	golang.org/x/sys v0.8.0 // indirect
	golang.org/x/term v0.8.0 // indirect
	golang.org/x/text v0.9.0 // indirect
)
