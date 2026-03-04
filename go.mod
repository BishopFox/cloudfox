module github.com/BishopFox/cloudfox

go 1.24.2

require (
	cloud.google.com/go/artifactregistry v1.18.0
	cloud.google.com/go/bigquery v1.72.0
	cloud.google.com/go/iam v1.5.3
	cloud.google.com/go/resourcemanager v1.10.7
	cloud.google.com/go/secretmanager v1.16.0
	cloud.google.com/go/storage v1.58.0
	github.com/Azure/azure-sdk-for-go v68.0.0+incompatible
	github.com/Azure/azure-sdk-for-go/sdk/azidentity v1.13.1
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources v1.2.0
	github.com/Azure/azure-sdk-for-go/sdk/storage/azblob v1.6.3
	github.com/Azure/go-autorest/autorest v0.11.30
	github.com/Azure/go-autorest/autorest/azure/auth v0.5.13
	github.com/aquasecurity/table v1.11.0
	github.com/aws/aws-sdk-go-v2 v1.41.0
	github.com/aws/aws-sdk-go-v2/config v1.32.5
	github.com/aws/aws-sdk-go-v2/credentials v1.19.5
	github.com/aws/aws-sdk-go-v2/service/apigateway v1.38.3
	github.com/aws/aws-sdk-go-v2/service/apigatewayv2 v1.33.4
	github.com/aws/aws-sdk-go-v2/service/apprunner v1.39.9
	github.com/aws/aws-sdk-go-v2/service/athena v1.56.4
	github.com/aws/aws-sdk-go-v2/service/cloud9 v1.33.15
	github.com/aws/aws-sdk-go-v2/service/cloudformation v1.71.4
	github.com/aws/aws-sdk-go-v2/service/cloudfront v1.58.3
	github.com/aws/aws-sdk-go-v2/service/cloudtrail v1.55.4
	github.com/aws/aws-sdk-go-v2/service/codeartifact v1.38.16
	github.com/aws/aws-sdk-go-v2/service/codebuild v1.68.8
	github.com/aws/aws-sdk-go-v2/service/codecommit v1.33.7
	github.com/aws/aws-sdk-go-v2/service/codedeploy v1.35.8
	github.com/aws/aws-sdk-go-v2/service/datapipeline v1.30.15
	github.com/aws/aws-sdk-go-v2/service/directoryservice v1.38.11
	github.com/aws/aws-sdk-go-v2/service/docdb v1.48.8
	github.com/aws/aws-sdk-go-v2/service/dynamodb v1.53.5
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.276.1
	github.com/aws/aws-sdk-go-v2/service/ecr v1.54.4
	github.com/aws/aws-sdk-go-v2/service/ecs v1.69.5
	github.com/aws/aws-sdk-go-v2/service/efs v1.41.9
	github.com/aws/aws-sdk-go-v2/service/eks v1.76.3
	github.com/aws/aws-sdk-go-v2/service/elasticache v1.51.8
	github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk v1.33.18
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing v1.33.18
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2 v1.54.5
	github.com/aws/aws-sdk-go-v2/service/emr v1.57.4
	github.com/aws/aws-sdk-go-v2/service/fsx v1.65.1
	github.com/aws/aws-sdk-go-v2/service/glue v1.135.3
	github.com/aws/aws-sdk-go-v2/service/grafana v1.32.9
	github.com/aws/aws-sdk-go-v2/service/iam v1.53.1
	github.com/aws/aws-sdk-go-v2/service/kinesis v1.42.9
	github.com/aws/aws-sdk-go-v2/service/lambda v1.87.0
	github.com/aws/aws-sdk-go-v2/service/lightsail v1.50.10
	github.com/aws/aws-sdk-go-v2/service/mq v1.34.14
	github.com/aws/aws-sdk-go-v2/service/opensearch v1.56.0
	github.com/aws/aws-sdk-go-v2/service/organizations v1.50.0
	github.com/aws/aws-sdk-go-v2/service/ram v1.34.18
	github.com/aws/aws-sdk-go-v2/service/rds v1.113.1
	github.com/aws/aws-sdk-go-v2/service/redshift v1.61.4
	github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi v1.31.5
	github.com/aws/aws-sdk-go-v2/service/route53 v1.62.0
	github.com/aws/aws-sdk-go-v2/service/s3 v1.93.2
	github.com/aws/aws-sdk-go-v2/service/sagemaker v1.228.2
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.41.0
	github.com/aws/aws-sdk-go-v2/service/sfn v1.40.5
	github.com/aws/aws-sdk-go-v2/service/sns v1.39.10
	github.com/aws/aws-sdk-go-v2/service/sqs v1.42.20
	github.com/aws/aws-sdk-go-v2/service/ssm v1.67.7
	github.com/aws/aws-sdk-go-v2/service/sts v1.41.5
	github.com/aws/smithy-go v1.24.0
	github.com/bishopfox/awsservicemap v1.1.0
	github.com/bishopfox/knownawsaccountslookup v0.0.0-20231228165844-c37ef8df33cb
	github.com/dominikbraun/graph v0.23.0
	github.com/fatih/color v1.18.0
	github.com/goccy/go-json v0.10.5
	github.com/googleapis/gax-go/v2 v2.15.0
	github.com/jedib0t/go-pretty v4.3.0+incompatible
	github.com/kyokomi/emoji v2.2.4+incompatible
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/sirupsen/logrus v1.9.3
	github.com/spf13/afero v1.15.0
	github.com/spf13/cobra v1.10.2
	golang.org/x/crypto v0.46.0
	golang.org/x/exp v0.0.0-20251209150349-8475f28825e9
)

require (
	cel.dev/expr v0.25.1 // indirect
	cloud.google.com/go/accesscontextmanager v1.9.7 // indirect
	cloud.google.com/go/auth v0.17.0 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.2.8 // indirect
	cloud.google.com/go/orgpolicy v1.15.1 // indirect
	cloud.google.com/go/osconfig v1.15.1 // indirect
	cloud.google.com/go/pubsub/v2 v2.0.0 // indirect
	github.com/GoogleCloudPlatform/opentelemetry-operations-go/detectors/gcp v1.30.0 // indirect
	github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/metric v0.54.0 // indirect
	github.com/GoogleCloudPlatform/opentelemetry-operations-go/internal/resourcemapping v0.54.0 // indirect
	github.com/apache/arrow/go/v15 v15.0.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.0.4 // indirect
	github.com/aymanbagabas/go-osc52/v2 v2.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/charmbracelet/colorprofile v0.4.1 // indirect
	github.com/charmbracelet/x/ansi v0.11.3 // indirect
	github.com/charmbracelet/x/cellbuf v0.0.14 // indirect
	github.com/charmbracelet/x/term v0.2.2 // indirect
	github.com/clipperhouse/displaywidth v0.6.1 // indirect
	github.com/clipperhouse/stringish v0.1.1 // indirect
	github.com/clipperhouse/uax29/v2 v2.3.0 // indirect
	github.com/cncf/xds/go v0.0.0-20251210132809-ee656c7534f5 // indirect
	github.com/envoyproxy/go-control-plane/envoy v1.36.0 // indirect
	github.com/envoyproxy/protoc-gen-validate v1.3.0 // indirect
	github.com/erikgeiser/coninput v0.0.0-20211004153227-1c3628e74d0f // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/go-jose/go-jose/v4 v4.1.3 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-viper/mapstructure/v2 v2.4.0 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.0 // indirect
	github.com/lucasb-eyer/go-colorful v1.3.0 // indirect
	github.com/mattn/go-localereader v0.0.1 // indirect
	github.com/muesli/ansi v0.0.0-20230316100256-276c6243b2f6 // indirect
	github.com/muesli/cancelreader v0.2.2 // indirect
	github.com/muesli/termenv v0.16.0 // indirect
	github.com/planetscale/vtprotobuf v0.6.1-0.20240319094008-0393e58bdf10 // indirect
	github.com/spiffe/go-spiffe/v2 v2.6.0 // indirect
	github.com/xo/terminfo v0.0.0-20220910002029-abceb7e1c41e // indirect
	go.opencensus.io v0.24.0 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/detectors/gcp v1.39.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.64.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.64.0 // indirect
	go.opentelemetry.io/otel v1.39.0 // indirect
	go.opentelemetry.io/otel/metric v1.39.0 // indirect
	go.opentelemetry.io/otel/sdk v1.39.0 // indirect
	go.opentelemetry.io/otel/sdk/metric v1.39.0 // indirect
	go.opentelemetry.io/otel/trace v1.39.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/telemetry v0.0.0-20251208220230-2638a1023523 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
)

require (
	cloud.google.com/go/asset v1.22.0
	cloud.google.com/go/kms v1.23.2
	cloud.google.com/go/monitoring v1.24.3
	cloud.google.com/go/pubsub v1.50.1
	cloud.google.com/go/securitycenter v1.38.1
	github.com/aws/aws-sdk-go-v2/service/kms v1.49.4
	golang.org/x/oauth2 v0.34.0
	google.golang.org/api v0.257.0
	google.golang.org/genproto v0.0.0-20251202230838-ff82c1b0f217
	google.golang.org/protobuf v1.36.11
)

require (
	cloud.google.com/go v0.123.0 // indirect
	cloud.google.com/go/compute/metadata v0.9.0 // indirect
	cloud.google.com/go/longrunning v0.7.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.20.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.11.2 // indirect
	github.com/Azure/go-autorest v14.2.0+incompatible // indirect
	github.com/Azure/go-autorest/autorest/adal v0.9.24 // indirect
	github.com/Azure/go-autorest/autorest/azure/cli v0.4.7 // indirect
	github.com/Azure/go-autorest/autorest/date v0.3.1 // indirect
	github.com/Azure/go-autorest/autorest/to v0.4.1 // indirect
	github.com/Azure/go-autorest/autorest/validation v0.3.2 // indirect
	github.com/Azure/go-autorest/logger v0.2.2 // indirect
	github.com/Azure/go-autorest/tracing v0.6.1 // indirect
	github.com/AzureAD/microsoft-authentication-library-for-go v1.6.0 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.4 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.16 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.16 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.16 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.4 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.16 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.9.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/endpoint-discovery v1.11.16 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.16 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.19.16 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.30.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.35.12 // indirect
	github.com/charmbracelet/bubbles v0.21.0
	github.com/charmbracelet/bubbletea v1.3.10
	github.com/charmbracelet/lipgloss v1.1.0
	github.com/dimchansky/utfbom v1.1.1 // indirect
	github.com/go-openapi/errors v0.22.5 // indirect
	github.com/go-openapi/strfmt v0.25.0 // indirect
	github.com/golang-jwt/jwt/v4 v4.5.2 // indirect
	github.com/google/flatbuffers v25.9.23+incompatible // indirect
	github.com/google/s2a-go v0.1.9 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.7 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/klauspost/compress v1.18.2 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-runewidth v0.0.19 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/neo4j/neo4j-go-driver/v5 v5.28.4
	github.com/oklog/ulid v1.3.1 // indirect
	github.com/pierrec/lz4/v4 v4.1.22 // indirect
	github.com/pkg/browser v0.0.0-20240102092130-5ac0b6a4141c // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/zeebo/xxh3 v1.0.2 // indirect
	go.mongodb.org/mongo-driver v1.17.6 // indirect
	golang.org/x/mod v0.31.0 // indirect
	golang.org/x/net v0.48.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
	golang.org/x/term v0.38.0 // indirect
	golang.org/x/text v0.32.0 // indirect
	golang.org/x/time v0.14.0 // indirect
	golang.org/x/tools v0.40.0 // indirect
	golang.org/x/xerrors v0.0.0-20240903120638-7835f813f4da // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20251202230838-ff82c1b0f217 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251202230838-ff82c1b0f217 // indirect
	google.golang.org/grpc v1.77.0
)
