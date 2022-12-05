package cli

import (
	"fmt"
	"log"
	"os"

	"github.com/BishopFox/cloudfox/aws"
	"github.com/BishopFox/cloudfox/utils"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	"github.com/aws/aws-sdk-go-v2/service/apprunner"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/fsx"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	"github.com/aws/aws-sdk-go-v2/service/grafana"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lightsail"
	"github.com/aws/aws-sdk-go-v2/service/mq"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	"github.com/aws/aws-sdk-go-v2/service/ram"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
	"github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/fatih/color"
	"github.com/kyokomi/emoji"
	"github.com/spf13/cobra"
)

var (
	cyan  = color.New(color.FgCyan).SprintFunc()
	green = color.New(color.FgGreen).SprintFunc()

	AWSProfile         string
	AWSProfilesList    string
	AWSAllProfiles     bool
	AWSProfiles        []string
	AWSConfirm         bool
	AWSOutputFormat    string
	AWSOutputDirectory string
	Goroutines         int
	Verbosity          int
	AWSCommands        = &cobra.Command{
		Use:   "aws",
		Short: "See \"Available Commands\" for AWS Modules",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}

	AccessKeysFilter  string
	AccessKeysCommand = &cobra.Command{
		Use:     "access-keys",
		Aliases: []string{"accesskeys", "keys"},
		Short:   "Enumerate active access keys for all users",
		Long: "\nUse case examples:\n" +
			"Map active access keys:\n" +
			os.Args[0] + " aws access-keys --profile test_account" +
			os.Args[0] + " aws access-keys --filter access_key_id --profile readonly_profile",
		PreRun: awsPreRun,
		Run:    runAccessKeysCommand,
	}

	BucketsCommand = &cobra.Command{
		Use:     "buckets",
		Aliases: []string{"bucket"},
		Short:   "Enumerate all of the buckets. Get loot file with s3 commands to list/download bucket contents",
		Long: "\nUse case examples:\n" +
			"List all buckets create a file with pre-populated aws s3 commands:\n" +
			os.Args[0] + " aws buckets --profile test_account",
		PreRun: awsPreRun,
		Run:    runBucketsCommand,
	}

	CloudformationCommand = &cobra.Command{
		Use:     "cloudformation",
		Aliases: []string{"cf", "cfstacks", "stacks"},
		Short:   "Enumerate Cloudformation stacks. Get a loot file with stack details. Look for secrets.",
		Long: "\nUse case examples:\n" +
			os.Args[0] + " aws ecr --profile readonly_profile",
		PreRun: awsPreRun,
		Run:    runCloudformationCommand,
	}

	ECRCommand = &cobra.Command{
		Use:     "ecr",
		Aliases: []string{"repos", "repo", "repositories"},
		Short:   "Enumerate the most recently pushed image URI from all repositories. Get a loot file with commands to pull images",
		Long: "\nUse case examples:\n" +
			os.Args[0] + " aws ecr --profile readonly_profile",
		PreRun: awsPreRun,
		Run:    runECRCommand,
	}

	EndpointsCommand = &cobra.Command{
		Use:     "endpoints",
		Aliases: []string{"endpoint"},
		Short:   "Enumerates endpoints from various services. Get a loot file with http endpoints to scan.",
		Long: "\nUse case examples:\n" +
			os.Args[0] + " aws endpoints --profile readonly_profile",
		PreRun: awsPreRun,
		Run:    runEndpointsCommand,
	}

	EnvsCommand = &cobra.Command{
		Use:     "env-vars",
		Aliases: []string{"envs", "envvars", "env"},
		Short:   "Enumerate the environment variables from mutliple services that have them",
		Long: "\nUse case examples:\n" +
			os.Args[0] + " aws env-vars --profile readonly_profile",
		PreRun: awsPreRun,
		Run:    runEnvsCommand,
	}

	FilesystemsCommand = &cobra.Command{
		Use:     "filesystems",
		Aliases: []string{"filesystem"},
		Short:   "Enumerate the EFS and FSx filesystems. Get a loot file with mount commands",
		Long: "\nUse case examples:\n" +
			os.Args[0] + " aws filesystems --profile readonly_profile",
		PreRun: awsPreRun,
		Run:    runFilesystemsCommand,
	}

	SimulatorResource   string
	SimulatorAction     string
	SimulatorPrincipal  string
	IamSimulatorCommand = &cobra.Command{
		Use:     "iam-simulator",
		Aliases: []string{"iamsimulator", "simulator"},
		Short:   "Wrapper around the AWS IAM Simulate Principal Policy command",
		Long: "\nUse case examples:\n" +
			os.Args[0] + " aws iam-simulator --profile readonly_profile",
		PreRun: awsPreRun,
		Run:    runIamSimulatorCommand,
	}

	// This filter could be an instance ID or a TXT file with instance IDs separated by a new line.
	InstancesFilter                   string
	InstanceMapUserDataAttributesOnly bool
	InstancesCommand                  = &cobra.Command{
		Use:     "instances",
		Aliases: []string{"instance"},
		Short:   "Enumerate all instances along with assigned IPs, profiles, and user-data",
		Long: "\nUse case examples:\n" +
			os.Args[0] + " aws instances --profile readonly_profile",
		PreRun: awsPreRun,
		Run:    runInstancesCommand,
	}

	ECSTasksCommand = &cobra.Command{
		Use:     "ecs-tasks",
		Aliases: []string{"ecs"},
		Short:   "Enumerate all ECS tasks along with assigned IPs and profiles",
		Long: "\nUse case examples:\n" +
			os.Args[0] + " aws ecs-tasks --profile readonly_profile",
		PreRun: awsPreRun,
		Run:    runECSTasksCommand,
	}

	ElasticNetworkInterfacesCommand = &cobra.Command{
		Use:     "elastic-network-interfaces",
		Aliases: []string{"eni"},
		Short:   "Enumerate all elastic network interafces along with their private and public IPs and the VPC",
		Long: "\nUse case examples:\n" +
			os.Args[0] + " aws elastic-network-interfaces --profile readonly_profile",
		PreRun: awsPreRun,
		Run:    runENICommand,
	}

	InventoryCommand = &cobra.Command{
		Use:   "inventory",
		Short: "Gain a rough understanding of size of the account and preferred regions",
		Long: "\nUse case examples:\n" +
			os.Args[0] + " aws inventory --profile readonly_profile",
		PreRun: awsPreRun,
		Run:    runInventoryCommand,
	}

	LambdasCommand = &cobra.Command{
		Use:     "lambda",
		Aliases: []string{"lambdas", "functions"},
		Short:   "Enumerate lambdas.",
		Long: "\nUse case examples:\n" +
			os.Args[0] + " aws lambda --profile readonly_profile",
		PreRun: awsPreRun,
		Run:    runLambdasCommand,
	}

	OutboundAssumedRolesDays    int
	OutboundAssumedRolesCommand = &cobra.Command{
		Use:     "outbound-assumed-roles",
		Aliases: []string{"assumedroles", "assumeroles", "outboundassumedroles"},
		Short:   "Find the roles that have been assumed by principals in this account",
		Long: "\nUse case examples:\n" +
			os.Args[0] + " aws outbound-assumed-roles --profile readonly_profile",
		PreRun: awsPreRun,
		Run:    runOutboundAssumedRolesCommand,
	}

	PermissionsPrincipal string
	PermissionsCommand   = &cobra.Command{
		Use:     "permissions",
		Aliases: []string{"perms", "permission"},
		Short:   "Enumerate IAM permissions per principal",
		Long: "\nUse case examples:\n" +
			os.Args[0] + " aws permissions --profile profile\n" +
			os.Args[0] + " aws permissions --profile profile --principal arn:aws:iam::111111111111:role/test123",
		PreRun: awsPreRun,
		Run:    runPermissionsCommand,
	}

	PrincipalsCommand = &cobra.Command{
		Use:     "principals",
		Aliases: []string{"principal"},
		Short:   "Enumerate IAM users and Roles so you have the data at your fingertips",
		Long: "\nUse case examples:\n" +
			os.Args[0] + " aws principals --profile readonly_profile",
		PreRun: awsPreRun,
		Run:    runPrincipalsCommand,
	}

	RAMCommand = &cobra.Command{
		Use:   "ram",
		Short: "Enumerate cross-account shared resources",
		Long: "\nUse case examples:\n" +
			os.Args[0] + " aws ram --profile readonly_profile",
		PreRun: awsPreRun,
		Run:    runRAMCommand,
	}

	// The filter is set to "all" when the flag "--filter" is not used
	RoleTrustFilter  string
	RoleTrustCommand = &cobra.Command{
		Use:     "role-trusts",
		Aliases: []string{"roletrusts", "role-trust"},
		Short:   "Enumerate all role trusts",
		Long: "\nUse case examples:\n" +
			"Map all role trusts for caller's account:\n" +
			os.Args[0] + " aws role-trusts\n",
		PreRun: awsPreRun,
		Run:    runRoleTrustCommand,
	}

	Route53Command = &cobra.Command{
		Use:     "route53",
		Aliases: []string{"dns", "route", "routes"},
		Short:   "Enumerate all records from all zones managed by route53. Get a loot file with A records you can scan",
		Long: "\nUse case examples:\n" +
			os.Args[0] + " aws route53 --profile readonly_profile",
		PreRun: awsPreRun,
		Run:    runRoute53Command,
	}

	SecretsCommand = &cobra.Command{
		Use:     "secrets",
		Aliases: []string{"secret"},
		Short:   "Enumerate secrets from secrets manager and SSM",
		Long: "\nUse case examples:\n" +
			os.Args[0] + " aws secrets --profile readonly_profile",
		PreRun: awsPreRun,
		Run:    runSecretsCommand,
	}

	TagsCommand = &cobra.Command{
		Use:     "tags",
		Aliases: []string{"tag"},
		Short:   "Enumerate resources with tags.",
		Long: "\nUse case examples:\n" +
			os.Args[0] + " aws tags --profile readonly_profile",
		PreRun: awsPreRun,
		Run:    runTagsCommand,
	}

	AllChecksCommand = &cobra.Command{

		Use:     "all-checks",
		Aliases: []string{"allchecks", "all"},
		Short:   "Run all of the other checks (excluding outbound-assumed-roles)",
		Long: "\nUse case examples:\n" +
			os.Args[0] + " aws all-checks --profile readonly_profile", //TODO add examples? os.Args[0] + " aws all-checks --profiles profiles.txt, os.Args[0] + " aws all-checks --all-profiles""
		PreRun: awsPreRun,
		Run:    runAllChecksCommand,
	}
)

func init() {
	cobra.OnInitialize(initAWSProfiles)
	// Principal Trusts Module Flags
	RoleTrustCommand.Flags().StringVarP(&RoleTrustFilter, "filter", "t", "all", "[AccountNumber | PrincipalARN | PrincipalName | ServiceName]")

	// Map Access Keys Module Flags
	AccessKeysCommand.Flags().StringVarP(&AccessKeysFilter, "filter", "t", "none", "Access key ID to search for")

	// IAM Simulator Module Flags
	//IamSimulatorCommand.Flags().StringVarP(&IamSimulatorFilter, "filter", "f", "none", "Access key ID to search for")

	// Instances Map Module Flags
	InstancesCommand.Flags().StringVarP(&InstancesFilter, "filter", "t", "all", "[InstanceID | InstanceIDsFile]")
	InstancesCommand.Flags().BoolVarP(&InstanceMapUserDataAttributesOnly, "userdata", "u", false, "Use this flag to retrieve only the userData attribute from EC2 instances.")

	//  outbound-assumed-roles module flags
	OutboundAssumedRolesCommand.Flags().IntVarP(&OutboundAssumedRolesDays, "days", "d", 7, "How many days of CloudTrail events should we go back and look at.")

	//  iam-simulator module flags
	IamSimulatorCommand.Flags().StringVar(&SimulatorPrincipal, "principal", "", "Principal Arn")
	IamSimulatorCommand.Flags().StringVar(&SimulatorAction, "action", "", "Action")
	IamSimulatorCommand.Flags().StringVar(&SimulatorResource, "resource", "*", "Resource")

	//  iam-simulator module flags
	PermissionsCommand.Flags().StringVar(&PermissionsPrincipal, "principal", "", "Principal Arn")

	// Global flags for the AWS modules
	AWSCommands.PersistentFlags().StringVarP(&AWSProfile, "profile", "p", "", "AWS CLI Profile Name")
	AWSCommands.PersistentFlags().StringVarP(&AWSProfilesList, "profiles-list", "l", "", "File containing a AWS CLI profile names separated by newlines")
	AWSCommands.PersistentFlags().BoolVarP(&AWSAllProfiles, "all-profiles", "a", false, "Use all AWS CLI profiles in AWS credentials file")
	AWSCommands.PersistentFlags().BoolVarP(&AWSConfirm, "yes", "y", false, "Non-interactive mode (like apt/yum)")
	AWSCommands.PersistentFlags().StringVarP(&AWSOutputFormat, "output", "o", "all", "[\"table\" | \"csv\" | \"all\" ]")
	AWSCommands.PersistentFlags().IntVarP(&Verbosity, "verbosity", "v", 1, "1 = Print control messages only\n2 = Print control messages, module output\n3 = Print control messages, module output, and loot file output\n")
	AWSCommands.PersistentFlags().StringVar(&AWSOutputDirectory, "outdir", ".", "Output Directory ")
	AWSCommands.PersistentFlags().IntVarP(&Goroutines, "max-goroutines", "g", 30, "Maximum number of concurrent goroutines")

	AWSCommands.AddCommand(
		AllChecksCommand,
		RoleTrustCommand,
		AccessKeysCommand,
		InstancesCommand,
		ECSTasksCommand,
		ElasticNetworkInterfacesCommand,
		InventoryCommand,
		EndpointsCommand,
		SecretsCommand,
		Route53Command,
		ECRCommand,
		OutboundAssumedRolesCommand,
		EnvsCommand,
		PrincipalsCommand,
		IamSimulatorCommand,
		FilesystemsCommand,
		BucketsCommand,
		PermissionsCommand,
		CloudformationCommand,
		RAMCommand,
		TagsCommand,
		LambdasCommand,
	)

}

func initAWSProfiles() {
	// Ensure only one profile setting is chosen
	if AWSProfile != "" && AWSProfilesList != "" || AWSProfile != "" && AWSAllProfiles || AWSProfilesList != "" && AWSAllProfiles {
		log.Fatalf("[-] Error specifying AWS profiles. Choose only one of -p/--profile, -a/--all-profiles, -l/--profiles-list")
	} else if AWSProfile != "" {
		AWSProfiles = append(AWSProfiles, AWSProfile)
	} else if AWSProfilesList != "" {
		// Written like so to enable testing while still being readable
		AWSProfiles = utils.GetSelectedAWSProfiles(AWSProfilesList)
	} else if AWSAllProfiles {
		AWSProfiles = utils.GetAllAWSProfiles(AWSConfirm)
	} else {
		AWSProfiles = append(AWSProfiles, "")
	}
}

func awsPreRun(cmd *cobra.Command, args []string) {
	for _, profile := range AWSProfiles {
		caller, err := utils.AWSWhoami(profile, cmd.Root().Version)
		if err != nil {
			continue
		}
		fmt.Printf("[%s] AWS Caller Identity: %s\n", cyan(emoji.Sprintf(":fox:cloudfox v%s :fox:", cmd.Root().Version)), *caller.Arn)
	}
}

func runAccessKeysCommand(cmd *cobra.Command, args []string) {
	for _, profile := range AWSProfiles {
		caller, err := utils.AWSWhoami(profile, cmd.Root().Version)
		if err != nil {
			continue
		}
		m := aws.AccessKeysModule{
			IAMClient:  iam.NewFromConfig(utils.AWSConfigFileLoader(profile, cmd.Root().Version)),
			Caller:     *caller,
			AWSProfile: profile,
			Goroutines: Goroutines,
		}
		m.PrintAccessKeys(AccessKeysFilter, AWSOutputFormat, AWSOutputDirectory, Verbosity)
	}
}

func runBucketsCommand(cmd *cobra.Command, args []string) {
	for _, profile := range AWSProfiles {
		caller, err := utils.AWSWhoami(profile, cmd.Root().Version)
		if err != nil {
			continue
		}
		m := aws.BucketsModule{
			//S3Client: s3.NewFromConfig(utils.AWSConfigFileLoader(profile, cmd.Root().Version)),
			S3ClientListBucketsInterface: s3.NewFromConfig(utils.AWSConfigFileLoader(profile, cmd.Root().Version)),
			Caller:                       *caller,
			AWSProfile:                   profile,
			Goroutines:                   Goroutines,
		}
		m.PrintBuckets(AWSOutputFormat, AWSOutputDirectory, Verbosity)
	}

}

func runCloudformationCommand(cmd *cobra.Command, args []string) {
	for _, profile := range AWSProfiles {
		var AWSConfig = utils.AWSConfigFileLoader(profile, cmd.Root().Version)
		caller, err := utils.AWSWhoami(profile, cmd.Root().Version)
		if err != nil {
			continue
		}
		m := aws.CloudformationModule{
			CloudFormationClient: cloudformation.NewFromConfig(AWSConfig),
			Caller:               *caller,
			AWSRegions:           utils.GetEnabledRegions(AWSProfile, cmd.Root().Version),
			AWSProfile:           profile,
			Goroutines:           Goroutines,
		}
		m.PrintCloudformationStacks(AWSOutputFormat, AWSOutputDirectory, Verbosity)
	}
}

func runECRCommand(cmd *cobra.Command, args []string) {
	for _, profile := range AWSProfiles {
		var AWSConfig = utils.AWSConfigFileLoader(profile, cmd.Root().Version)
		caller, err := utils.AWSWhoami(profile, cmd.Root().Version)
		if err != nil {
			continue
		}
		m := aws.ECRModule{
			//ECRClient:                       ecr.NewFromConfig(AWSConfig),
			ECRClientDescribeReposInterface:  ecr.NewFromConfig(AWSConfig),
			ECRClientDescribeImagesInterface: ecr.NewFromConfig(AWSConfig),

			Caller:     *caller,
			AWSRegions: utils.GetEnabledRegions(AWSProfile, cmd.Root().Version),
			AWSProfile: profile,
			Goroutines: Goroutines,
		}
		m.PrintECR(AWSOutputFormat, AWSOutputDirectory, Verbosity)
	}
}

func runEndpointsCommand(cmd *cobra.Command, args []string) {
	for _, profile := range AWSProfiles {
		var AWSConfig = utils.AWSConfigFileLoader(profile, cmd.Root().Version)
		caller, err := utils.AWSWhoami(profile, cmd.Root().Version)
		if err != nil {
			continue
		}
		m := aws.EndpointsModule{
			APIGatewayClient:   apigateway.NewFromConfig(AWSConfig),
			APIGatewayv2Client: apigatewayv2.NewFromConfig(AWSConfig),
			AppRunnerClient:    apprunner.NewFromConfig(AWSConfig),
			CloudfrontClient:   cloudfront.NewFromConfig(AWSConfig),
			EKSClient:          eks.NewFromConfig(AWSConfig),
			ELBClient:          elasticloadbalancing.NewFromConfig(AWSConfig),
			ELBv2Client:        elasticloadbalancingv2.NewFromConfig(AWSConfig),
			GrafanaClient:      grafana.NewFromConfig(AWSConfig),
			LambdaClient:       lambda.NewFromConfig(AWSConfig),
			LightsailClient:    lightsail.NewFromConfig(AWSConfig),
			MQClient:           mq.NewFromConfig(AWSConfig),
			OpenSearchClient:   opensearch.NewFromConfig(AWSConfig),
			RDSClient:          rds.NewFromConfig(AWSConfig),
			RedshiftClient:     redshift.NewFromConfig(AWSConfig),
			S3Client:           s3.NewFromConfig(AWSConfig),

			Caller:     *caller,
			AWSRegions: utils.GetEnabledRegions(AWSProfile, cmd.Root().Version),
			AWSProfile: profile,
			Goroutines: Goroutines,
		}
		m.PrintEndpoints(AWSOutputFormat, AWSOutputDirectory, Verbosity)
	}
}

func runEnvsCommand(cmd *cobra.Command, args []string) {
	for _, profile := range AWSProfiles {
		var AWSConfig = utils.AWSConfigFileLoader(profile, cmd.Root().Version)
		caller, err := utils.AWSWhoami(profile, cmd.Root().Version)
		if err != nil {
			continue
		}
		m := aws.EnvsModule{

			Caller:          *caller,
			AWSRegions:      utils.GetEnabledRegions(AWSProfile, cmd.Root().Version),
			AWSProfile:      profile,
			Goroutines:      Goroutines,
			ECSClient:       ecs.NewFromConfig(AWSConfig),
			AppRunnerClient: apprunner.NewFromConfig(AWSConfig),
			LambdaClient:    lambda.NewFromConfig(AWSConfig),
			LightsailClient: lightsail.NewFromConfig(AWSConfig),
			SagemakerClient: sagemaker.NewFromConfig(AWSConfig),
		}
		m.PrintEnvs(AWSOutputFormat, AWSOutputDirectory, Verbosity)
	}
}

func runFilesystemsCommand(cmd *cobra.Command, args []string) {
	for _, profile := range AWSProfiles {
		var AWSConfig = utils.AWSConfigFileLoader(profile, cmd.Root().Version)
		caller, err := utils.AWSWhoami(profile, cmd.Root().Version)
		if err != nil {
			continue
		}
		filesystems := aws.FilesystemsModule{
			EFSClient: efs.NewFromConfig(AWSConfig),
			FSxClient: fsx.NewFromConfig(AWSConfig),

			Caller:     *caller,
			AWSProfile: profile,
			Goroutines: Goroutines,
			AWSRegions: utils.GetEnabledRegions(AWSProfile, cmd.Root().Version),
		}
		filesystems.PrintFilesystems(AWSOutputFormat, AWSOutputDirectory, Verbosity)
	}
}

func runIamSimulatorCommand(cmd *cobra.Command, args []string) {
	for _, profile := range AWSProfiles {
		var AWSConfig = utils.AWSConfigFileLoader(profile, cmd.Root().Version)
		caller, err := utils.AWSWhoami(profile, cmd.Root().Version)
		if err != nil {
			continue
		}
		m := aws.IamSimulatorModule{
			IAMClient:  iam.NewFromConfig(AWSConfig),
			Caller:     *caller,
			AWSProfile: profile,
			Goroutines: Goroutines,
		}
		m.PrintIamSimulator(SimulatorPrincipal, SimulatorAction, SimulatorResource, AWSOutputFormat, AWSOutputDirectory, Verbosity)
	}
}

func runInstancesCommand(cmd *cobra.Command, args []string) {
	for _, profile := range AWSProfiles {
		caller, err := utils.AWSWhoami(profile, cmd.Root().Version)
		if err != nil {
			continue
		}
		m := aws.InstancesModule{
			EC2Client: ec2.NewFromConfig(utils.AWSConfigFileLoader(profile, cmd.Root().Version)),
			IAMClient: iam.NewFromConfig(utils.AWSConfigFileLoader(profile, cmd.Root().Version)),

			Caller:     *caller,
			AWSRegions: utils.GetEnabledRegions(AWSProfile, cmd.Root().Version),

			UserDataAttributesOnly: InstanceMapUserDataAttributesOnly,
			AWSProfile:             profile,
		}
		m.Instances(InstancesFilter, AWSOutputFormat, AWSOutputDirectory, Verbosity)
	}
}

func runInventoryCommand(cmd *cobra.Command, args []string) {
	for _, profile := range AWSProfiles {
		var AWSConfig = utils.AWSConfigFileLoader(profile, cmd.Root().Version)
		caller, err := utils.AWSWhoami(profile, cmd.Root().Version)
		if err != nil {
			continue
		}
		m := aws.Inventory2Module{
			APIGatewayClient:     apigateway.NewFromConfig(AWSConfig),
			APIGatewayv2Client:   apigatewayv2.NewFromConfig(AWSConfig),
			AppRunnerClient:      apprunner.NewFromConfig(AWSConfig),
			CloudFormationClient: cloudformation.NewFromConfig(AWSConfig),
			CloudfrontClient:     cloudfront.NewFromConfig(AWSConfig),
			DynamoDBClient:       dynamodb.NewFromConfig(AWSConfig),
			EC2Client:            ec2.NewFromConfig(AWSConfig),
			ECSClient:            ecs.NewFromConfig(AWSConfig),
			EKSClient:            eks.NewFromConfig(AWSConfig),
			ELBClient:            elasticloadbalancing.NewFromConfig(AWSConfig),
			ELBv2Client:          elasticloadbalancingv2.NewFromConfig(AWSConfig),
			GlueClient:           glue.NewFromConfig(AWSConfig),
			GrafanaClient:        grafana.NewFromConfig(AWSConfig),
			IAMClient:            iam.NewFromConfig(AWSConfig),
			LambdaClient:         lambda.NewFromConfig(AWSConfig),
			LightsailClient:      lightsail.NewFromConfig(AWSConfig),
			MQClient:             mq.NewFromConfig(AWSConfig),
			OpenSearchClient:     opensearch.NewFromConfig(AWSConfig),
			RDSClient:            rds.NewFromConfig(AWSConfig),
			RedshiftClient:       redshift.NewFromConfig(AWSConfig),
			S3Client:             s3.NewFromConfig(AWSConfig),
			SecretsManagerClient: secretsmanager.NewFromConfig(AWSConfig),
			SNSClient:            sns.NewFromConfig(AWSConfig),
			SQSClient:            sqs.NewFromConfig(AWSConfig),
			SSMClient:            ssm.NewFromConfig(AWSConfig),

			Caller:     *caller,
			AWSRegions: utils.GetEnabledRegions(AWSProfile, cmd.Root().Version),
			AWSProfile: profile,
			Goroutines: Goroutines,
		}
		m.PrintInventoryPerRegion(AWSOutputFormat, AWSOutputDirectory, Verbosity)
	}
}

func runLambdasCommand(cmd *cobra.Command, args []string) {
	for _, profile := range AWSProfiles {
		var AWSConfig = utils.AWSConfigFileLoader(profile, cmd.Root().Version)
		caller, err := utils.AWSWhoami(profile, cmd.Root().Version)
		if err != nil {
			continue
		}
		m := aws.LambdasModule{
			LambdaClient: lambda.NewFromConfig(AWSConfig),
			IAMClient:    iam.NewFromConfig(AWSConfig),
			Caller:       *caller,
			AWSRegions:   utils.GetEnabledRegions(AWSProfile, cmd.Root().Version),
			AWSProfile:   profile,
			Goroutines:   Goroutines,
		}
		m.PrintLambdas(AWSOutputFormat, AWSOutputDirectory, Verbosity)
	}
}

func runOutboundAssumedRolesCommand(cmd *cobra.Command, args []string) {
	for _, profile := range AWSProfiles {
		var AWSConfig = utils.AWSConfigFileLoader(profile, cmd.Root().Version)
		caller, err := utils.AWSWhoami(profile, cmd.Root().Version)
		if err != nil {
			continue
		}
		m := aws.OutboundAssumedRolesModule{
			CloudTrailClient: cloudtrail.NewFromConfig(AWSConfig),

			Caller:     *caller,
			AWSRegions: utils.GetEnabledRegions(AWSProfile, cmd.Root().Version),
			AWSProfile: profile,
			Goroutines: Goroutines,
		}
		m.PrintOutboundRoleTrusts(OutboundAssumedRolesDays, AWSOutputFormat, AWSOutputDirectory, Verbosity)
	}
}

func runPermissionsCommand(cmd *cobra.Command, args []string) {
	for _, profile := range AWSProfiles {
		var AWSConfig = utils.AWSConfigFileLoader(profile, cmd.Root().Version)
		caller, err := utils.AWSWhoami(profile, cmd.Root().Version)
		if err != nil {
			continue
		}
		m := aws.IamPermissionsModule{
			IAMClient:  iam.NewFromConfig(AWSConfig),
			Caller:     *caller,
			AWSProfile: profile,
			Goroutines: Goroutines,
		}
		m.PrintIamPermissions(AWSOutputFormat, AWSOutputDirectory, Verbosity, PermissionsPrincipal)
	}
}

func runPrincipalsCommand(cmd *cobra.Command, args []string) {
	for _, profile := range AWSProfiles {
		var AWSConfig = utils.AWSConfigFileLoader(profile, cmd.Root().Version)
		caller, err := utils.AWSWhoami(profile, cmd.Root().Version)
		if err != nil {
			continue
		}
		m := aws.IamPrincipalsModule{
			IAMClient:  iam.NewFromConfig(AWSConfig),
			Caller:     *caller,
			AWSProfile: profile,
			Goroutines: Goroutines,
		}
		m.PrintIamPrincipals(AWSOutputFormat, AWSOutputDirectory, Verbosity)
	}
}

func runRAMCommand(cmd *cobra.Command, args []string) {
	for _, profile := range AWSProfiles {
		var AWSConfig = utils.AWSConfigFileLoader(profile, cmd.Root().Version)
		caller, err := utils.AWSWhoami(profile, cmd.Root().Version)
		if err != nil {
			continue
		}
		ram := aws.RAMModule{
			RAMClient:  ram.NewFromConfig(AWSConfig),
			Caller:     *caller,
			AWSProfile: profile,
			Goroutines: Goroutines,
			AWSRegions: utils.GetEnabledRegions(AWSProfile, cmd.Root().Version),
		}
		ram.PrintRAM(AWSOutputFormat, AWSOutputDirectory, Verbosity)

	}
}

func runRoleTrustCommand(cmd *cobra.Command, args []string) {
	for _, profile := range AWSProfiles {
		caller, err := utils.AWSWhoami(profile, cmd.Root().Version)
		if err != nil {
			continue
		}
		m := aws.RoleTrustsModule{
			IAMClientListRoles: iam.NewFromConfig(utils.AWSConfigFileLoader(profile, cmd.Root().Version)),
			IAMClient:          iam.NewFromConfig(utils.AWSConfigFileLoader(profile, cmd.Root().Version)),
			Caller:             *caller,
			AWSProfile:         profile,
			Goroutines:         Goroutines,
		}
		m.PrintRoleTrusts(AWSOutputFormat, AWSOutputDirectory, Verbosity)
	}
}

func runRoute53Command(cmd *cobra.Command, args []string) {
	for _, profile := range AWSProfiles {
		var AWSConfig = utils.AWSConfigFileLoader(profile, cmd.Root().Version)
		caller, err := utils.AWSWhoami(profile, cmd.Root().Version)
		if err != nil {
			continue
		}
		m := aws.Route53Module{
			Route53Client: route53.NewFromConfig(AWSConfig),

			Caller:     *caller,
			AWSRegions: utils.GetEnabledRegions(AWSProfile, cmd.Root().Version),
			AWSProfile: profile,
			Goroutines: Goroutines,
		}
		m.PrintRoute53(AWSOutputFormat, AWSOutputDirectory, Verbosity)
	}
}

func runSecretsCommand(cmd *cobra.Command, args []string) {
	for _, profile := range AWSProfiles {
		var AWSConfig = utils.AWSConfigFileLoader(profile, cmd.Root().Version)
		caller, err := utils.AWSWhoami(profile, cmd.Root().Version)
		if err != nil {
			continue
		}
		m := aws.SecretsModule{
			SecretsManagerClient: secretsmanager.NewFromConfig(AWSConfig),
			SSMClient:            ssm.NewFromConfig(AWSConfig),

			Caller:     *caller,
			AWSRegions: utils.GetEnabledRegions(AWSProfile, cmd.Root().Version),
			AWSProfile: profile,
			Goroutines: Goroutines,
		}
		m.PrintSecrets(AWSOutputFormat, AWSOutputDirectory, Verbosity)
	}
}

func runTagsCommand(cmd *cobra.Command, args []string) {
	for _, profile := range AWSProfiles {
		var AWSConfig = utils.AWSConfigFileLoader(profile, cmd.Root().Version)
		caller, err := utils.AWSWhoami(profile, cmd.Root().Version)
		if err != nil {
			continue
		}
		m := aws.TagsModule{
			ResourceGroupsTaggingApiClient: resourcegroupstaggingapi.NewFromConfig(AWSConfig),
			Caller:                         *caller,
			AWSRegions:                     utils.GetEnabledRegions(AWSProfile, cmd.Root().Version),
			AWSProfile:                     profile,
			Goroutines:                     Goroutines,
		}
		m.PrintTags(AWSOutputFormat, AWSOutputDirectory, Verbosity)
	}
}

func runECSTasksCommand(cmd *cobra.Command, args []string) {
	for _, profile := range AWSProfiles {
		caller, err := utils.AWSWhoami(profile, cmd.Root().Version)
		if err != nil {
			continue
		}
		m := aws.ECSTasksModule{
			DescribeTasksClient:             ecs.NewFromConfig(utils.AWSConfigFileLoader(profile, cmd.Root().Version)),
			DescribeTaskDefinitionClient:    ecs.NewFromConfig(utils.AWSConfigFileLoader(profile, cmd.Root().Version)),
			ListTasksClient:                 ecs.NewFromConfig(utils.AWSConfigFileLoader(profile, cmd.Root().Version)),
			ListClustersClient:              ecs.NewFromConfig(utils.AWSConfigFileLoader(profile, cmd.Root().Version)),
			DescribeNetworkInterfacesClient: ec2.NewFromConfig(utils.AWSConfigFileLoader(profile, cmd.Root().Version)),
			IAMClient:                       iam.NewFromConfig(utils.AWSConfigFileLoader(profile, cmd.Root().Version)),

			Caller:     *caller,
			AWSRegions: utils.GetEnabledRegions(AWSProfile, cmd.Root().Version),
			AWSProfile: profile,
			Goroutines: Goroutines,
		}
		m.ECSTasks(AWSOutputFormat, AWSOutputDirectory, Verbosity)
	}
}

func runENICommand(cmd *cobra.Command, args []string) {
	for _, profile := range AWSProfiles {
		caller, err := utils.AWSWhoami(profile, cmd.Root().Version)
		if err != nil {
			continue
		}
		m := aws.ElasticNetworkInterfacesModule{
			//EC2Client:                       ec2.NewFromConfig(utils.AWSConfigFileLoader(profile, cmd.Root().Version)),
			DescribeNetworkInterfacesClient: ec2.NewFromConfig(utils.AWSConfigFileLoader(profile, cmd.Root().Version)),

			Caller:     *caller,
			AWSRegions: utils.GetEnabledRegions(AWSProfile, cmd.Root().Version),

			AWSProfile: profile,
		}
		m.ElasticNetworkInterfaces(AWSOutputFormat, AWSOutputDirectory, Verbosity)
	}
}

func runAllChecksCommand(cmd *cobra.Command, args []string) {
	for _, profile := range AWSProfiles {
		var AWSConfig = utils.AWSConfigFileLoader(profile, cmd.Root().Version)
		Caller, err := utils.AWSWhoami(profile, cmd.Root().Version)
		if err != nil {
			continue
		}

		apiGatewayClient := apigateway.NewFromConfig(AWSConfig)
		apiGatewayv2Client := apigatewayv2.NewFromConfig(AWSConfig)
		appRunnerClient := apprunner.NewFromConfig(AWSConfig)
		cloudFormationClient := cloudformation.NewFromConfig(AWSConfig)
		cloudfrontClient := cloudfront.NewFromConfig(AWSConfig)
		dynamodbClient := dynamodb.NewFromConfig(AWSConfig)
		ec2Client := ec2.NewFromConfig(AWSConfig)
		ecrClient := ecr.NewFromConfig(AWSConfig)
		ecsClient := ecs.NewFromConfig(AWSConfig)
		efsClient := efs.NewFromConfig(AWSConfig)
		eksClient := eks.NewFromConfig(AWSConfig)
		elbClient := elasticloadbalancing.NewFromConfig(AWSConfig)
		elbv2Client := elasticloadbalancingv2.NewFromConfig(AWSConfig)
		fsxClient := fsx.NewFromConfig(AWSConfig)
		glueClient := glue.NewFromConfig(AWSConfig)
		grafanaClient := grafana.NewFromConfig(AWSConfig)
		iamClient := iam.NewFromConfig(AWSConfig)
		lambdaClient := lambda.NewFromConfig(AWSConfig)
		lightsailClient := lightsail.NewFromConfig(AWSConfig)
		mqClient := mq.NewFromConfig(AWSConfig)
		openSearchClient := opensearch.NewFromConfig(AWSConfig)
		ramClient := ram.NewFromConfig(AWSConfig)
		rdsClient := rds.NewFromConfig(AWSConfig)
		redshiftClient := redshift.NewFromConfig(AWSConfig)
		resourceClient := resourcegroupstaggingapi.NewFromConfig(AWSConfig)
		route53Client := route53.NewFromConfig(AWSConfig)
		s3Client := s3.NewFromConfig(AWSConfig)
		sagemakerClient := sagemaker.NewFromConfig(AWSConfig)
		secretsManagerClient := secretsmanager.NewFromConfig(AWSConfig)
		snsClient := sns.NewFromConfig(AWSConfig)
		sqsClient := sqs.NewFromConfig(AWSConfig)
		ssmClient := ssm.NewFromConfig(AWSConfig)

		fmt.Printf("[%s] %s\n", cyan(emoji.Sprintf(":fox:cloudfox :fox:")), green("Getting a lay of the land, aka \"What regions is this account using?\""))
		inventory2 := aws.Inventory2Module{
			APIGatewayClient:     apiGatewayClient,
			APIGatewayv2Client:   apiGatewayv2Client,
			AppRunnerClient:      appRunnerClient,
			CloudFormationClient: cloudFormationClient,
			CloudfrontClient:     cloudfrontClient,
			DynamoDBClient:       dynamodbClient,
			EC2Client:            ec2Client,
			ECSClient:            ecsClient,
			EKSClient:            eksClient,
			ELBClient:            elbClient,
			ELBv2Client:          elbv2Client,
			GlueClient:           glueClient,
			GrafanaClient:        grafanaClient,
			IAMClient:            iamClient,
			LambdaClient:         lambdaClient,
			LightsailClient:      lightsailClient,
			MQClient:             mqClient,
			OpenSearchClient:     openSearchClient,
			RDSClient:            rdsClient,
			RedshiftClient:       redshiftClient,
			S3Client:             s3Client,
			SecretsManagerClient: secretsManagerClient,
			SNSClient:            snsClient,
			SQSClient:            sqsClient,
			SSMClient:            ssmClient,

			Caller:     *Caller,
			AWSRegions: utils.GetEnabledRegions(AWSProfile, cmd.Root().Version),
			AWSProfile: profile,
			Goroutines: Goroutines,
		}
		inventory2.PrintInventoryPerRegion(AWSOutputFormat, AWSOutputDirectory, Verbosity)

		tagsMod := aws.TagsModule{
			ResourceGroupsTaggingApiClient: resourceClient,
			Caller:                         *Caller,
			AWSRegions:                     utils.GetEnabledRegions(AWSProfile, cmd.Root().Version),
			AWSProfile:                     profile,
			Goroutines:                     Goroutines,
		}
		tagsMod.PrintTags(AWSOutputFormat, AWSOutputDirectory, Verbosity)

		// Service and endpoint enum section
		fmt.Printf("[%s] %s\n", cyan(emoji.Sprintf(":fox:cloudfox :fox:")), green("Gathering the info you'll want for your application & service enumeration needs."))
		instances := aws.InstancesModule{
			EC2Client:  ec2Client,
			IAMClient:  iamClient,
			Caller:     *Caller,
			AWSRegions: utils.GetEnabledRegions(AWSProfile, cmd.Root().Version),

			UserDataAttributesOnly: false,
			AWSProfile:             profile,
		}
		instances.Instances(InstancesFilter, AWSOutputFormat, AWSOutputDirectory, Verbosity)
		route53 := aws.Route53Module{
			Route53Client: route53Client,

			Caller:     *Caller,
			AWSRegions: utils.GetEnabledRegions(AWSProfile, cmd.Root().Version),
			AWSProfile: profile,
			Goroutines: Goroutines,
		}

		lambdasMod := aws.LambdasModule{
			LambdaClient: lambdaClient,
			IAMClient:    iamClient,
			Caller:       *Caller,
			AWSRegions:   utils.GetEnabledRegions(AWSProfile, cmd.Root().Version),
			AWSProfile:   profile,
			Goroutines:   Goroutines,
		}
		lambdasMod.PrintLambdas(AWSOutputFormat, AWSOutputDirectory, Verbosity)

		route53.PrintRoute53(AWSOutputFormat, AWSOutputDirectory, Verbosity)

		filesystems := aws.FilesystemsModule{
			EFSClient:  efsClient,
			FSxClient:  fsxClient,
			Caller:     *Caller,
			AWSProfile: profile,
			AWSRegions: utils.GetEnabledRegions(AWSProfile, cmd.Root().Version),
			Goroutines: Goroutines,
		}
		filesystems.PrintFilesystems(AWSOutputFormat, AWSOutputDirectory, Verbosity)

		endpoints := aws.EndpointsModule{

			EKSClient:          eksClient,
			S3Client:           s3Client,
			LambdaClient:       lambdaClient,
			RDSClient:          rdsClient,
			APIGatewayv2Client: apiGatewayv2Client,
			APIGatewayClient:   apiGatewayClient,
			ELBClient:          elbClient,
			ELBv2Client:        elbv2Client,
			MQClient:           mqClient,
			OpenSearchClient:   openSearchClient,
			GrafanaClient:      grafanaClient,
			RedshiftClient:     redshiftClient,
			CloudfrontClient:   cloudfrontClient,
			AppRunnerClient:    appRunnerClient,
			LightsailClient:    lightsailClient,

			Caller:     *Caller,
			AWSRegions: utils.GetEnabledRegions(AWSProfile, cmd.Root().Version),
			AWSProfile: profile,
			Goroutines: Goroutines,
		}

		endpoints.PrintEndpoints(AWSOutputFormat, AWSOutputDirectory, Verbosity)

		ecstasks := aws.ECSTasksModule{
			DescribeTasksClient:             ecsClient,
			ListTasksClient:                 ecsClient,
			ListClustersClient:              ecsClient,
			DescribeNetworkInterfacesClient: ec2Client,
			Caller:                          *Caller,
			AWSRegions:                      utils.GetEnabledRegions(AWSProfile, cmd.Root().Version),
			AWSProfile:                      profile,
		}
		ecstasks.ECSTasks(AWSOutputFormat, AWSOutputDirectory, Verbosity)

		elasticnetworkinterfaces := aws.ElasticNetworkInterfacesModule{
			DescribeNetworkInterfacesClient: ec2Client,
			Caller:                          *Caller,
			AWSRegions:                      utils.GetEnabledRegions(AWSProfile, cmd.Root().Version),
			AWSProfile:                      profile,
		}
		elasticnetworkinterfaces.ElasticNetworkInterfaces(AWSOutputFormat, AWSOutputDirectory, Verbosity)

		// Secrets section
		fmt.Printf("[%s] %s\n", cyan(emoji.Sprintf(":fox:cloudfox :fox:")), green("Looking for secrets hidden between the seat cushions."))

		ec2UserData := aws.InstancesModule{
			EC2Client:  ec2Client,
			IAMClient:  iamClient,
			Caller:     *Caller,
			AWSRegions: utils.GetEnabledRegions(AWSProfile, cmd.Root().Version),

			UserDataAttributesOnly: true,
			AWSProfile:             profile,
			Goroutines:             Goroutines,
		}
		ec2UserData.Instances(InstancesFilter, AWSOutputFormat, AWSOutputDirectory, Verbosity)
		envsMod := aws.EnvsModule{

			Caller:          *Caller,
			AWSRegions:      utils.GetEnabledRegions(AWSProfile, cmd.Root().Version),
			AWSProfile:      profile,
			ECSClient:       ecsClient,
			AppRunnerClient: appRunnerClient,
			LambdaClient:    lambdaClient,
			LightsailClient: lightsailClient,
			SagemakerClient: sagemakerClient,
			Goroutines:      Goroutines,
		}
		envsMod.PrintEnvs(AWSOutputFormat, AWSOutputDirectory, Verbosity)

		cfMod := aws.CloudformationModule{
			CloudFormationClient: cloudFormationClient,
			Caller:               *Caller,
			AWSRegions:           utils.GetEnabledRegions(AWSProfile, cmd.Root().Version),
			AWSProfile:           profile,
			Goroutines:           Goroutines,
		}
		cfMod.PrintCloudformationStacks(AWSOutputFormat, AWSOutputDirectory, Verbosity)

		// CPT Enum
		//fmt.Printf("[%s] %s\n", cyan(emoji.Sprintf(":fox:cloudfox :fox:")), green("Gathering some other info that is often useful."))
		fmt.Printf("[%s] %s\n", cyan(emoji.Sprintf(":fox:cloudfox :fox:")), green("Arming you with the data you'll need for privesc quests."))

		buckets := aws.BucketsModule{
			S3ClientListBucketsInterface: s3Client,
			Caller:                       *Caller,
			AWSProfile:                   profile,
			Goroutines:                   Goroutines,
		}
		buckets.PrintBuckets(AWSOutputFormat, AWSOutputDirectory, Verbosity)

		ecr := aws.ECRModule{
			//ECRClient:  ecrClient,
			ECRClientDescribeReposInterface:  ecrClient,
			ECRClientDescribeImagesInterface: ecrClient,
			Caller:                           *Caller,
			AWSRegions:                       utils.GetEnabledRegions(AWSProfile, cmd.Root().Version),
			AWSProfile:                       profile,
			Goroutines:                       Goroutines,
		}
		ecr.PrintECR(AWSOutputFormat, AWSOutputDirectory, Verbosity)

		secrets := aws.SecretsModule{
			SecretsManagerClient: secretsManagerClient,
			SSMClient:            ssmClient,

			Caller:     *Caller,
			AWSRegions: utils.GetEnabledRegions(AWSProfile, cmd.Root().Version),
			AWSProfile: profile,
			Goroutines: Goroutines,
		}
		secrets.PrintSecrets(AWSOutputFormat, AWSOutputDirectory, Verbosity)

		ram := aws.RAMModule{
			RAMClient:  ramClient,
			Caller:     *Caller,
			AWSProfile: profile,
			Goroutines: Goroutines,
			AWSRegions: utils.GetEnabledRegions(AWSProfile, cmd.Root().Version),
		}
		ram.PrintRAM(AWSOutputFormat, AWSOutputDirectory, Verbosity)

		// IAM privesc section
		fmt.Printf("[%s] %s\n", cyan(emoji.Sprintf(":fox:cloudfox :fox:")), green("IAM is complicated. Complicated usually means misconfigurations. You'll want to pay attention here."))
		principals := aws.IamPrincipalsModule{
			IAMClient:  iamClient,
			Caller:     *Caller,
			AWSProfile: profile,
			Goroutines: Goroutines,
		}
		principals.PrintIamPrincipals(AWSOutputFormat, AWSOutputDirectory, Verbosity)
		permissions := aws.IamPermissionsModule{
			IAMClient:  iamClient,
			Caller:     *Caller,
			AWSProfile: profile,
			Goroutines: Goroutines,
		}
		permissions.PrintIamPermissions(AWSOutputFormat, AWSOutputDirectory, Verbosity, PermissionsPrincipal)
		accessKeys := aws.AccessKeysModule{
			IAMClient:  iam.NewFromConfig(AWSConfig),
			Caller:     *Caller,
			AWSProfile: profile,
			Goroutines: Goroutines,
		}
		accessKeys.PrintAccessKeys(AccessKeysFilter, AWSOutputFormat, AWSOutputDirectory, Verbosity)
		roleTrusts := aws.RoleTrustsModule{
			IAMClientListRoles: iamClient,
			IAMClient:          iamClient,
			Caller:             *Caller,
			AWSProfile:         profile,
			Goroutines:         Goroutines,
		}
		roleTrusts.PrintRoleTrusts(AWSOutputFormat, AWSOutputDirectory, Verbosity)
		iamSimulator := aws.IamSimulatorModule{
			IAMClient:  iamClient,
			Caller:     *Caller,
			AWSProfile: profile,
			Goroutines: Goroutines,
		}
		iamSimulator.PrintIamSimulator(SimulatorPrincipal, SimulatorAction, SimulatorResource, AWSOutputFormat, AWSOutputDirectory, Verbosity)

		fmt.Printf("[%s] %s\n", cyan(emoji.Sprintf(":fox:cloudfox :fox:")), green("That's it! Check your output files for situational awareness and check your loot files for next steps."))
		fmt.Printf("[%s] %s\n\n", cyan(emoji.Sprintf(":fox:cloudfox :fox:")), green("FYI, we skipped the outbound-assumed-roles module in all-checks (really long run time). Make sure to try it out manually."))
	}
}
