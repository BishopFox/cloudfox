package aws

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"

	"github.com/BishopFox/cloudfox/aws/sdk"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	"github.com/aws/aws-sdk-go-v2/service/apprunner"
	"github.com/aws/aws-sdk-go-v2/service/athena"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/grafana"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lightsail"
	"github.com/aws/aws-sdk-go-v2/service/mq"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/bishopfox/awsservicemap"
	"github.com/sirupsen/logrus"
)

type Inventory2Module struct {
	// General configuration data
	APIGatewayClient       *apigateway.Client
	APIGatewayv2Client     *apigatewayv2.Client
	AppRunnerClient        *apprunner.Client
	AthenaClient           *athena.Client
	CloudFormationClient   *cloudformation.Client
	CloudfrontClient       *cloudfront.Client
	CodeArtifactClient     sdk.AWSCodeArtifactClientInterface
	CodeBuildClient        sdk.CodeBuildClientInterface
	CodeCommitClient       sdk.AWSCodeCommitClientInterface
	CodeDeployClient       sdk.AWSCodeDeployClientInterface
	DataPipelineClient     sdk.AWSDataPipelineClientInterface
	DynamoDBClient         *dynamodb.Client
	EC2Client              *ec2.Client
	ECRClient              sdk.AWSECRClientInterface
	ECSClient              *ecs.Client
	EKSClient              sdk.EKSClientInterface
	ELBClient              *elasticloadbalancing.Client
	ELBv2Client            *elasticloadbalancingv2.Client
	ElasticacheClient      sdk.AWSElastiCacheClientInterface
	ElasticBeanstalkClient sdk.AWSElasticBeanstalkClientInterface
	EMRClient              sdk.AWSEMRClientInterface
	GrafanaClient          *grafana.Client
	GlueClient             sdk.AWSGlueClientInterface
	KinesisClient          sdk.AWSKinesisClientInterface
	IAMClient              *iam.Client
	LambdaClient           *lambda.Client
	LightsailClient        *lightsail.Client
	MQClient               *mq.Client
	OpenSearchClient       *opensearch.Client
	RDSClient              *rds.Client
	RedshiftClient         sdk.AWSRedShiftClientInterface
	Route53Client          sdk.AWSRoute53ClientInterface
	S3Client               *s3.Client
	SQSClient              *sqs.Client
	SSMClient              *ssm.Client
	SNSClient              *sns.Client
	SecretsManagerClient   *secretsmanager.Client
	StepFunctionClient     sdk.StepFunctionsClientInterface

	Caller       sts.GetCallerIdentityOutput
	AWSRegions   []string
	OutputFormat string
	Goroutines   int
	AWSProfile   string
	WrapTable    bool

	// Main module data
	RegionResourceCount  int
	CommandCounter       internal.CommandCounter
	GlobalResourceCounts []GlobalResourceCount2
	serviceMap           map[string]map[string]int
	services             []string
	totalRegionCounts    map[string]int
	mu                   sync.Mutex
	resources            []string

	// Used to store output data for pretty printing
	output       internal.OutputData2
	globalOutput internal.OutputData2

	modLog *logrus.Entry
}

type GlobalResourceCount2 struct {
	resourceType string
	count        int
}

func (m *Inventory2Module) PrintInventoryPerRegion(outputFormat string, outputDirectory string, verbosity int) {

	// These stuct values are used by the output module
	m.output.Verbosity = verbosity
	m.output.Directory = outputDirectory
	m.output.CallingModule = "inventory"
	m.modLog = internal.TxtLog.WithFields(logrus.Fields{
		"module": "inventory",
	},
	)

	m.services = []string{
		"total",
		"APIGateway RestAPIs",
		"APIGatewayv2 APIs",
		"Athena Databases",
		//"Athena Data Catalogs",
		"AppRunner Services",
		"CloudFormation Stacks",
		"Cloudfront Distributions",
		"CodeArtifact Repositories",
		"CodeArtifact Domains",
		"CodeBuild Projects",
		"CodeCommit Repositories",
		"CodeDeploy Applications",
		"CodeDeploy Deployments",
		"DataPipeline Pipelines",
		"DynamoDB Tables",
		"EC2 Instances",
		"EC2 AMIs",
		"EC2 Volumes",
		"EC2 Snapshots",
		"ECS Clusters",
		"ECS Tasks",
		"ECS Services",
		"ECR Repositories",
		"EKS Clusters",
		"EKS Cluster NodeGroups",
		"Elasticache Clusters",
		"ElasticBeanstalk Applications",
		"ELB Load Balancers",
		"ELBv2 Load Balancers",
		"EMR Clusters",
		"EMR Instances",
		"Glue Databases",
		"Glue Dev Endpoints",
		"Glue Jobs",
		"Glue Tables",
		"Grafana Workspaces",
		"IAM Access Keys",
		"IAM Roles",
		"IAM Users",
		"IAM Groups",
		"Kinesis Data Streams",
		"Lambda Functions",
		"Lightsail Instances/Containers",
		"MQ Brokers",
		"OpenSearch DomainNames",
		"Redshift Clusters",
		"RDS DB Instances",
		"Route53 Zones",
		"Route53 Records",
		"S3 Buckets",
		"SecretsManager Secrets",
		"SNS Topics",
		"SQS Queues",
		"SSM Parameters",
		"StepFunctions State Machines",
	}

	m.serviceMap = map[string]map[string]int{}
	m.totalRegionCounts = map[string]int{}

	if m.AWSProfile == "" {
		m.AWSProfile = internal.BuildAWSPath(m.Caller)
	}

	//initialize servicemap and total
	for _, service := range m.services {
		m.serviceMap[service] = map[string]int{}

		for _, region := range m.AWSRegions {
			m.serviceMap[service][region] = 0
			m.totalRegionCounts[region] = 0
		}
		m.serviceMap[service]["Global"] = 0
	}

	fmt.Printf("[%s][%s] Enumerating selected services in all regions for account %s.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), aws.ToString(m.Caller.Account))
	fmt.Printf("[%s][%s] Supported Services: ApiGateway, ApiGatewayv2, AppRunner, CloudFormation, Cloudfront, CodeBuild, DynamoDB,  \n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	fmt.Printf("[%s][%s] \t\t\tEC2, ECS, ECR, EKS, ELB, ELBv2, Glue, Grafana, IAM, Lambda, Lightsail, MQ, \n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	fmt.Printf("[%s][%s] \t\t\tOpenSearch, RedShift, RDS, Route53, S3, SecretsManager, SNS, SQS, SSM, Step Functions\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))

	wg := new(sync.WaitGroup)
	semaphore := make(chan struct{}, m.Goroutines)

	// Create a channel to signal the spinner aka task status goroutine to finish
	spinnerDone := make(chan bool)
	//fire up the the task status spinner/updated
	go internal.SpinUntil(m.output.CallingModule, &m.CommandCounter, spinnerDone, "tasks")

	//create a channel to receive the objects
	dataReceiver := make(chan GlobalResourceCount2)

	// Create a channel to signal to stop
	receiverDone := make(chan bool)

	go m.Receiver(dataReceiver, receiverDone)

	for _, region := range m.AWSRegions {

		m.CommandCounter.Total++
		wg.Add(1)
		m.CommandCounter.Pending++
		go m.executeChecks(region, wg, semaphore, dataReceiver)

	}

	// Time for the non-concurrent global checks
	m.getBuckets(verbosity, dataReceiver)
	m.getIAMUsers(verbosity, dataReceiver)
	m.getIAMRoles(verbosity, dataReceiver)
	m.getIAMGroups(verbosity, dataReceiver)
	m.getIAMAccessKeys(verbosity, dataReceiver)
	m.getCloudfrontDistros(verbosity, dataReceiver)
	m.getRoute53Zones(verbosity, dataReceiver)
	m.getRoute53Records(verbosity, dataReceiver)

	wg.Wait()

	// Send a message to the spinner goroutine to close the channel and stop
	spinnerDone <- true
	<-spinnerDone

	// This creates the header row (columns) dynamically - a region oly gets printed if it has at least one resource.
	m.output.Headers = append(m.output.Headers, "Resource Type")

	type kv struct {
		Key   string
		Value int
	}

	var ss []kv
	for k, v := range m.totalRegionCounts {
		ss = append(ss, kv{k, v})
	}

	sort.Slice(ss, func(i, j int) bool {
		return ss[i].Value > ss[j].Value
	})

	// move the Global column to the front
	for i, v := range ss {
		if v.Key == "Global" {
			ss[0], ss[i] = ss[i], ss[0]
		}
	}

	//add the regions to the header row
	for _, region := range ss {

		if region.Value != 0 {
			m.output.Headers = append(m.output.Headers, region.Key)

		}
	}
	//move total up here.
	var totalRow []string
	var temprow []string
	temprow = append(temprow, "Total")
	for _, region := range ss {
		if region.Value != 0 {
			if m.serviceMap["total"][region.Key] > 0 {
				temprow = append(temprow, strconv.Itoa(m.serviceMap["total"][region.Key]))
			} else {
				temprow = append(temprow, "-")
			}
		}
	}
	for _, val := range temprow {
		totalRow = append(totalRow, val)
	}
	m.output.Body = append(m.output.Body, totalRow)

	// This is where we create the per service row with variable number of columns as well, using the same logic we used for the header
	for _, service := range m.services {
		if service != "total" {
			var outputRow []string
			var temprow []string

			temprow = append(temprow, service)
			for _, region := range ss {
				if region.Value != 0 {
					if m.serviceMap[service][region.Key] > 0 {
						temprow = append(temprow, strconv.Itoa(m.serviceMap[service][region.Key]))
					} else {
						temprow = append(temprow, "-")
					}
				}

			}

			// check to see if all regions have no resources for the service. Skip the first column, which is hte resource type.
			// If any value is other than "-" set rowEmpty to false.
			var rowEmtpy bool = true
			for _, val := range temprow[1:] {

				if val != "-" {
					rowEmtpy = false
				}
			}
			// If rowEmpty is still true at the end of the row, we dont add the row to the output, otherwise we do.
			if !rowEmtpy {
				// Convert the slice of strings to a slice of interfaces???  not sure, but this was needed. I couldnt just pass temp row to the output.Body
				for _, val := range temprow {
					outputRow = append(outputRow, val)

				}
				// Finally write the row to the table if the service has at least one resource
				m.output.Body = append(m.output.Body, outputRow)
			}

		}
	}

	m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", fmt.Sprintf("%s-%s", m.AWSProfile, aws.ToString(m.Caller.Account)))

	// if verbosity > 1 {
	// 	fmt.Printf("\nAnalyzed Global Resources\n\n")
	// }
	if len(m.output.Body) > 0 {

		//m.output.OutputSelector(outputFormat)
		//utils.OutputSelector(verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.CallingModule, m.output.CallingModule)
		//internal.OutputSelector(verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.CallingModule, m.output.CallingModule, m.WrapTable, m.AWSProfile)

		o := internal.OutputClient{
			Verbosity:     verbosity,
			CallingModule: m.output.CallingModule,
			Table: internal.TableClient{
				Wrap: m.WrapTable,
			},
		}
		o.Table.TableFiles = append(o.Table.TableFiles, internal.TableFile{
			Header: m.output.Headers,
			Body:   m.output.Body,
			Name:   m.output.CallingModule,
		})

		o.PrefixIdentifier = m.AWSProfile
		o.Table.DirectoryName = filepath.Join(outputDirectory, "cloudfox-output", "aws", fmt.Sprintf("%s-%s", m.AWSProfile, aws.ToString(m.Caller.Account)))
		// var header []string
		// var body [][]string
		// header, body = m.PrintGlobalResources(outputFormat, outputDirectory, verbosity, dataReceiver)
		// o.Table.TableFiles = append(o.Table.TableFiles, internal.TableFile{
		// 	Header: header,
		// 	Body:   body,
		// 	Name:   "inventory-global",
		// })
		o.WriteFullOutput(o.Table.TableFiles, nil)
		m.writeLoot(o.Table.DirectoryName, verbosity)

		m.PrintTotalResources(outputFormat)
		//m.writeLoot(m.output.FilePath, verbosity)
	} else {
		fmt.Printf("[%s][%s] No resources identified, skipping the creation of an output file.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	}
	fmt.Printf("[%s][%s] For context and next steps: https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#%s\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), m.output.CallingModule)
	receiverDone <- true
	<-receiverDone
}

func (m *Inventory2Module) writeLoot(outputDirectory string, verbosity int) {
	path := filepath.Join(outputDirectory, "loot")
	err := os.MkdirAll(path, os.ModePerm)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
	}
	lootFile := filepath.Join(path, "inventory.txt")
	var out string

	for _, resource := range m.resources {
		out += fmt.Sprintf("%s\n", resource)
	}

	err = os.WriteFile(lootFile, []byte(out), 0644)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
	}

	if verbosity > 2 {
		fmt.Println()
		fmt.Printf("[%s][%s] %s \n", cyan(m.output.CallingModule), cyan(m.AWSProfile), green("All identified resources"))
		fmt.Print(out)
		fmt.Printf("[%s][%s] %s \n\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), green("End of loot file."))
	}

	fmt.Printf("[%s][%s] Loot written to [%s]\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), lootFile)

}

func (m *Inventory2Module) Receiver(receiver chan GlobalResourceCount2, receiverDone chan bool) {

	defer close(receiverDone)
	for {
		select {
		case data := <-receiver:
			m.GlobalResourceCounts = append(m.GlobalResourceCounts, data)
		case <-receiverDone:
			receiverDone <- true
			return
		}
	}
}

func (m *Inventory2Module) executeChecks(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan GlobalResourceCount2) {
	defer wg.Done()

	servicemap := &awsservicemap.AwsServiceMap{
		JsonFileSource: "DOWNLOAD_FROM_AWS",
	}

	// AppRunner is not supported in the aws service region catalog so we have to run it in all regions
	m.CommandCounter.Total++
	wg.Add(1)
	go m.getAppRunnerServicesPerRegion(r, wg, semaphore)

	res, err := servicemap.IsServiceInRegion("apigateway", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		go m.getAPIGatewayvAPIsPerRegion(r, wg, semaphore)

		m.CommandCounter.Total++
		wg.Add(1)
		go m.getAPIGatewayv2APIsPerRegion(r, wg, semaphore)
	}

	res, err = servicemap.IsServiceInRegion("athena", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		go m.getAthenaDatabasesPerRegion(r, wg, semaphore)
		// wg.Add(1)
		// go m.getAthenaDataCatalogsPerRegion(r, wg, semaphore)
	}

	res, err = servicemap.IsServiceInRegion("cloudformation", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		go m.getCloudFormationStacksPerRegion(r, wg, semaphore)
	}

	res, err = servicemap.IsServiceInRegion("codeartifact", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		go m.getCodeArtifactDomainsPerRegion(r, wg, semaphore)
	}

	res, err = servicemap.IsServiceInRegion("codebuild", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		go m.getCodeBuildProjectsPerRegion(r, wg, semaphore)
	}

	res, err = servicemap.IsServiceInRegion("codecommit", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		go m.getCodeCommitRepositoriesPerRegion(r, wg, semaphore)
	}

	res, err = servicemap.IsServiceInRegion("codedeploy", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		go m.getCodeDeployApplicationsPerRegion(r, wg, semaphore)
		wg.Add(1)
		go m.getCodeDeployDeploymentsPerRegion(r, wg, semaphore)

	}

	res, err = servicemap.IsServiceInRegion("datapipeline", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		go m.getDataPipelinePipelinesPerRegion(r, wg, semaphore)
	}

	res, err = servicemap.IsServiceInRegion("dynamodb", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		go m.getDynamoDBTablesPerRegion(r, wg, semaphore)
	}

	res, err = servicemap.IsServiceInRegion("ec2", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		go m.getEc2InstancesPerRegion(r, wg, semaphore)
		wg.Add(1)
		go m.getEc2ImagesPerRegion(r, wg, semaphore)
		wg.Add(1)
		go m.getEc2SnapshotsPerRegion(r, wg, semaphore)
		wg.Add(1)
		go m.getEc2VolumesPerRegion(r, wg, semaphore)
	}

	res, err = servicemap.IsServiceInRegion("ecs", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		go m.getEcsTasksPerRegion(r, wg, semaphore)
		wg.Add(1)
		go m.getEcsClustersPerRegion(r, wg, semaphore)
		wg.Add(1)
		go m.getEcsServicesPerRegion(r, wg, semaphore)

	}

	res, err = servicemap.IsServiceInRegion("ecr", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		go m.getEcrRepositoriesPerRegion(r, wg, semaphore)
	}

	res, err = servicemap.IsServiceInRegion("eks", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		go m.getEksClustersPerRegion(r, wg, semaphore)
		wg.Add(1)
		go m.getEKSNodeGroupsPerRegion(r, wg, semaphore)
	}

	res, err = servicemap.IsServiceInRegion("elb", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		go m.getELBv2ListenersPerRegion(r, wg, semaphore)

		m.CommandCounter.Total++
		wg.Add(1)
		go m.getELBListenersPerRegion(r, wg, semaphore)
	}

	res, err = servicemap.IsServiceInRegion("elasticache", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		go m.getElasticacheClustersPerRegion(r, wg, semaphore)
	}

	res, err = servicemap.IsServiceInRegion("elasticbeanstalk", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		go m.getElasticBeanstalkApplicationsPerRegion(r, wg, semaphore)
	}

	res, err = servicemap.IsServiceInRegion("elasticbeanstalk", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		go m.getEMRClustersPerRegion(r, wg, semaphore)
		wg.Add(1)
		go m.GetEMRInstancesPerRegion(r, wg, semaphore)
	}

	res, err = servicemap.IsServiceInRegion("es", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		m.getOpenSearchPerRegion(r, wg, semaphore)
	}

	res, err = servicemap.IsServiceInRegion("grafana", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		go m.getGrafanaWorkspacesPerRegion(r, wg, semaphore)
	}

	res, err = servicemap.IsServiceInRegion("glue", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		go m.getGlueDevEndpointsPerRegion(r, wg, semaphore)
		wg.Add(1)
		go m.getGlueJobsPerRegion(r, wg, semaphore)
		wg.Add(1)
		go m.getGlueTablesPerRegion(r, wg, semaphore)
		wg.Add(1)
		go m.getGlueDatabasesPerRegion(r, wg, semaphore)

	}

	res, err = servicemap.IsServiceInRegion("kinesis", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		go m.getKinesisDatastreamsPerRegion(r, wg, semaphore)
	}

	res, err = servicemap.IsServiceInRegion("lambda", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++

		wg.Add(1)
		go m.getLambdaFunctionsPerRegion(r, wg, semaphore)
	}

	res, err = servicemap.IsServiceInRegion("lightsail", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		go m.getLightsailInstancesAndContainersPerRegion(r, wg, semaphore)
	}

	res, err = servicemap.IsServiceInRegion("mq", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		m.getMqBrokersPerRegion(r, wg, semaphore)
	}

	res, err = servicemap.IsServiceInRegion("rds", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		go m.getRdsClustersPerRegion(r, wg, semaphore)
	}

	res, err = servicemap.IsServiceInRegion("redshift", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		go m.getRedshiftClustersPerRegion(r, wg, semaphore)
	}

	res, err = servicemap.IsServiceInRegion("secretsmanager", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		go m.getSecretsManagerSecretsPerRegion(r, wg, semaphore)
	}

	res, err = servicemap.IsServiceInRegion("sns", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		go m.getSNSTopicsPerRegion(r, wg, semaphore)
	}

	res, err = servicemap.IsServiceInRegion("sqs", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		go m.getSQSQueuesPerRegion(r, wg, semaphore)
	}

	res, err = servicemap.IsServiceInRegion("ssm", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		go m.getSSMParametersPerRegion(r, wg, semaphore)
	}

	res, err = servicemap.IsServiceInRegion("stepfunctions", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		m.getStepFunctionsPerRegion(r, wg, semaphore)
	}

}

func (m *Inventory2Module) PrintTotalResources(outputFormat string) {
	var totalResources int
	for _, r := range m.AWSRegions {
		if m.totalRegionCounts[r] != 0 {
			totalResources = totalResources + m.totalRegionCounts[r]
		}
	}

	for i := range m.GlobalResourceCounts {
		totalResources = totalResources + m.GlobalResourceCounts[i].count
	}
	fmt.Printf("[%s][%s] %d resources found in the services we looked at. This is NOT the total number of resources in the account.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), totalResources)
}

func (m *Inventory2Module) getLambdaFunctionsPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer func() {
		wg.Done()
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	var totalCountThisServiceThisRegion = 0
	var service = "Lambda Functions"
	var resourceNames []string

	ListFunctions, err := sdk.CachedLambdaListFunctions(m.LambdaClient, aws.ToString(m.Caller.Account), r)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	// Add this page of resources to the total count
	totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(ListFunctions)

	// Add this page of resources to the module's resource list
	for _, f := range ListFunctions {
		resourceNames = append(resourceNames, aws.ToString(f.FunctionArn))
	}

	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.serviceMap[service][r] = totalCountThisServiceThisRegion
	m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
	m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion
	m.mu.Unlock()

}

func (m *Inventory2Module) getAthenaDatabasesPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer func() {
		wg.Done()
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()

	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++

	var totalCountThisServiceThisRegion = 0
	var service = "Athena Databases"
	var resourceNames []string

	ListDataCatalogs, err := sdk.CachedAthenaListDataCatalogs(m.AthenaClient, aws.ToString(m.Caller.Account), r)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	for _, dc := range ListDataCatalogs {

		ListDatabases, err := sdk.CachedAthenaListDatabases(m.AthenaClient, aws.ToString(m.Caller.Account), r, aws.ToString(dc.CatalogName))
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			return
		}

		// Add this page of resources to the total count
		totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(ListDatabases)

		for _, d := range ListDatabases {
			arn := "arn:aws:athena:" + r + ":" + aws.ToString(m.Caller.Account) + ":database/" + d
			resourceNames = append(resourceNames, arn)
		}
	}

	m.mu.Lock()

	m.resources = append(m.resources, resourceNames...)
	m.serviceMap[service][r] = totalCountThisServiceThisRegion
	m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
	m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion
	m.mu.Unlock()

}

// func (m *Inventory2Module) getAthenaDataCatalogsPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}) {
// 	defer func() {
// 		wg.Done()
// 		m.CommandCounter.Executing--
// 		m.CommandCounter.Complete++
// 	}()
// 	semaphore <- struct{}{}
// 	defer func() {
// 		<-semaphore
// 	}()

// 	// m.CommandCounter.Total++
// 	m.CommandCounter.Pending--
// 	m.CommandCounter.Executing++

// 	var totalCountThisServiceThisRegion = 0
// 	var service = "Athena Data Catalogs"
// 	var resourceNames []string

// 	ListDataCatalogs, err := sdk.CachedAthenaListDataCatalogs(m.AthenaClient, aws.ToString(m.Caller.Account), r)
// 	if err != nil {
// 		m.modLog.Error(err.Error())
// 		m.CommandCounter.Error++
// 		return
// 	}

// 	// Add this page of resources to the total count
// 	totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(ListDataCatalogs)

// 	// Add this page of resources to the module's resource list
// 	for _, d := range ListDataCatalogs {
// 		arn := "arn:aws:athena:" + r + ":" + aws.ToString(m.Caller.Account) + ":datacatalog/" + aws.ToString(d.CatalogName)
// 		resourceNames = append(resourceNames, arn)

// 	}

// 	m.mu.Lock()

// 	m.resources = append(m.resources, resourceNames...)
// 	m.serviceMap[service][r] = totalCountThisServiceThisRegion
// 	m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
// 	m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion
// 	m.mu.Unlock()
// }

func (m *Inventory2Module) getEc2InstancesPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer func() {
		wg.Done()
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	// "PaginationMarker" is a control variable used for output continuity, as AWS return the output in pages.
	var totalCountThisServiceThisRegion = 0
	var service = "EC2 Instances"
	var resourceNames []string

	// used CachedDescribeInstancesInput to avoid the need to call DescribeInstancesInput
	DescribeInstances, err := sdk.CachedEC2DescribeInstances(m.EC2Client, aws.ToString(m.Caller.Account), r)

	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	// Add this page of resources to the total count
	totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(DescribeInstances)

	// Add this page of resources to the module's resource list

	for _, instance := range DescribeInstances {
		arn := "arn:aws:ec2:" + r + ":" + aws.ToString(m.Caller.Account) + ":instance/" + aws.ToString(instance.InstanceId)
		resourceNames = append(resourceNames, arn)
	}

	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.serviceMap[service][r] = totalCountThisServiceThisRegion
	m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
	m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion
	m.mu.Unlock()
}

func (m *Inventory2Module) getEc2ImagesPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer func() {
		wg.Done()
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	// "PaginationMarker" is a control variable used for output continuity, as AWS return the output in pages.
	var totalCountThisServiceThisRegion = 0
	var service = "EC2 AMIs"
	var resourceNames []string

	// used CachedDescribeImagesInput to avoid the need to call DescribeImagesInput
	DescribeImages, err := sdk.CachedEC2DescribeImages(m.EC2Client, aws.ToString(m.Caller.Account), r)

	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	// Add this page of resources to the total count
	totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(DescribeImages)

	// Add this page of resources to the module's resource list
	for _, image := range DescribeImages {
		arn := "arn:aws:ec2:" + r + ":" + aws.ToString(m.Caller.Account) + ":image/" + aws.ToString(image.ImageId)
		resourceNames = append(resourceNames, arn)
	}

	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.serviceMap[service][r] = totalCountThisServiceThisRegion
	m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
	m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion
	m.mu.Unlock()
}

func (m *Inventory2Module) getEc2SnapshotsPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer func() {
		wg.Done()
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	// "PaginationMarker" is a control variable used for output continuity, as AWS return the output in pages.
	var totalCountThisServiceThisRegion = 0
	var service = "EC2 Snapshots"
	var resourceNames []string

	// used CachedDescribeSnapshotsInput to avoid the need to call DescribeSnapshotsInput
	DescribeSnapshots, err := sdk.CachedEC2DescribeSnapshots(m.EC2Client, aws.ToString(m.Caller.Account), r)

	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	// Add this page of resources to the total count
	totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(DescribeSnapshots)

	// Add this page of resources to the module's resource list
	for _, snapshot := range DescribeSnapshots {
		arn := "arn:aws:ec2:" + r + ":" + aws.ToString(m.Caller.Account) + ":snapshot/" + aws.ToString(snapshot.SnapshotId)
		resourceNames = append(resourceNames, arn)
	}

	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.serviceMap[service][r] = totalCountThisServiceThisRegion
	m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
	m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion
	m.mu.Unlock()
}

func (m *Inventory2Module) getEc2VolumesPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer func() {
		wg.Done()
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	// "PaginationMarker" is a control variable used for output continuity, as AWS return the output in pages.
	var totalCountThisServiceThisRegion = 0
	var service = "EC2 Volumes"
	var resourceNames []string

	// used CachedDescribeVolumesInput to avoid the need to call DescribeVolumesInput
	DescribeVolumes, err := sdk.CachedEC2DescribeVolumes(m.EC2Client, aws.ToString(m.Caller.Account), r)

	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	// Add this page of resources to the total count
	totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(DescribeVolumes)

	// Add this page of resources to the module's resource list
	for _, volume := range DescribeVolumes {
		arn := "arn:aws:ec2:" + r + ":" + aws.ToString(m.Caller.Account) + ":volume/" + aws.ToString(volume.VolumeId)
		resourceNames = append(resourceNames, arn)
	}

	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.serviceMap[service][r] = totalCountThisServiceThisRegion
	m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
	m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion
	m.mu.Unlock()
}

func (m *Inventory2Module) getEksClustersPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer func() {
		wg.Done()
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	// "PaginationMarker" is a control variable used for output continuity, as AWS return the output in pages.
	var totalCountThisServiceThisRegion = 0
	var service = "EKS Clusters"
	var resourceNames []string

	ListClusters, err := sdk.CachedEKSListClusters(m.EKSClient, aws.ToString(m.Caller.Account), r)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	// Add this page of resources to the total count
	totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(ListClusters)

	// Add this page of resources to the module's resource list
	for _, cluster := range ListClusters {
		arn := "arn:aws:eks:" + r + ":" + aws.ToString(m.Caller.Account) + ":cluster/" + cluster
		resourceNames = append(resourceNames, arn)
	}

	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.serviceMap[service][r] = totalCountThisServiceThisRegion
	m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
	m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion
	m.mu.Unlock()

}

func (m *Inventory2Module) getEKSNodeGroupsPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer func() {
		wg.Done()
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	// "PaginationMarker" is a control variable used for output continuity, as AWS return the output in pages.
	var totalCountThisServiceThisRegion = 0
	var service = "EKS Cluster NodeGroups"
	var resourceNames []string

	ListClusters, err := sdk.CachedEKSListClusters(m.EKSClient, aws.ToString(m.Caller.Account), r)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	for _, cluster := range ListClusters {
		NodeGroups, err := sdk.CachedEKSListNodeGroups(m.EKSClient, aws.ToString(m.Caller.Account), r, cluster)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			return
		}
		// Add this page of resources to the total count
		totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(NodeGroups)

		// Add this page of resources to the module's resource list
		for _, nodegroup := range NodeGroups {
			arn := "arn:aws:eks:" + r + ":" + aws.ToString(m.Caller.Account) + ":nodegroup/" + cluster + "/" + nodegroup
			resourceNames = append(resourceNames, arn)
		}

		m.mu.Lock()
		m.resources = append(m.resources, resourceNames...)
		m.serviceMap[service][r] = totalCountThisServiceThisRegion
		m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
		m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion
		m.mu.Unlock()
	}

}

func (m *Inventory2Module) getCloudFormationStacksPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer func() {
		wg.Done()
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	// "PaginationMarker" is a control variable used for output continuity, as AWS return the output in pages.
	var totalCountThisServiceThisRegion = 0
	var service = "CloudFormation Stacks"
	var resourceNames []string

	ListStacks, err := sdk.CachedCloudFormationListStacks(m.CloudFormationClient, aws.ToString(m.Caller.Account), r)

	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	// Add this page of resources to the total count
	// Currently this counts both active and deleted stacks as they technically still exist. Might
	// change this to only count active ones in the future.
	totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(ListStacks)

	// Add this page of resources to the module's resource list
	for _, stack := range ListStacks {
		resourceNames = append(resourceNames, aws.ToString(stack.StackId))
	}

	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.serviceMap[service][r] = totalCountThisServiceThisRegion
	m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
	m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion
	m.mu.Unlock()

}

func (m *Inventory2Module) getElasticacheClustersPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer func() {
		wg.Done()
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	// "PaginationMarker" is a control variable used for output continuity, as AWS return the output in pages.
	var totalCountThisServiceThisRegion = 0
	var service = "Elasticache Clusters"
	var resourceNames []string

	ListClusters, err := sdk.CachedElastiCacheDescribeCacheClusters(m.ElasticacheClient, aws.ToString(m.Caller.Account), r)

	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	// Add this page of resources to the total count
	totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(ListClusters)

	// Add this page of resources to the module's resource list
	for _, cluster := range ListClusters {
		resourceNames = append(resourceNames, aws.ToString(cluster.ARN))
	}

	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.serviceMap[service][r] = totalCountThisServiceThisRegion
	m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
	m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion
	m.mu.Unlock()

}

func (m *Inventory2Module) getElasticBeanstalkApplicationsPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer func() {
		wg.Done()
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	// "PaginationMarker" is a control variable used for output continuity, as AWS return the output in pages.
	var totalCountThisServiceThisRegion = 0
	var service = "ElasticBeanstalk Applications"
	var resourceNames []string

	ListApplications, err := sdk.CachedElasticBeanstalkDescribeApplications(m.ElasticBeanstalkClient, aws.ToString(m.Caller.Account), r)

	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	// Add this page of resources to the total count
	totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(ListApplications)

	// Add this page of resources to the module's resource list
	for _, application := range ListApplications {
		arn := aws.ToString(application.ApplicationArn)
		resourceNames = append(resourceNames, arn)
	}

	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.serviceMap[service][r] = totalCountThisServiceThisRegion
	m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
	m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion
	m.mu.Unlock()

}

func (m *Inventory2Module) getEMRClustersPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer func() {
		wg.Done()
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	// "PaginationMarker" is a control variable used for output continuity, as AWS return the output in pages.
	var totalCountThisServiceThisRegion = 0
	var service = "EMR Clusters"
	var resourceNames []string

	ListClusters, err := sdk.CachedEMRListClusters(m.EMRClient, aws.ToString(m.Caller.Account), r)

	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	// Add this page of resources to the total count
	totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(ListClusters)

	// Add this page of resources to the module's resource list
	for _, cluster := range ListClusters {
		resourceNames = append(resourceNames, aws.ToString(cluster.ClusterArn))
	}

	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.serviceMap[service][r] = totalCountThisServiceThisRegion
	m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
	m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion
	m.mu.Unlock()

}

func (m *Inventory2Module) GetEMRInstancesPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer func() {
		wg.Done()
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++

	var totalCountThisServiceThisRegion = 0
	var service = "EMR Instances"
	var resourceNames []string

	ListClusters, err := sdk.CachedEMRListClusters(m.EMRClient, aws.ToString(m.Caller.Account), r)

	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	for _, cluster := range ListClusters {

		ListInstances, err := sdk.CachedEMRListInstances(m.EMRClient, aws.ToString(m.Caller.Account), r, aws.ToString(cluster.Id))

		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			return
		}

		// Add this page of resources to the total count
		totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(ListInstances)

		// Add this page of resources to the module's resource list
		for _, instance := range ListInstances {
			arn := "arn:aws:elasticmapreduce:" + r + ":" + aws.ToString(m.Caller.Account) + ":instance/" + aws.ToString(instance.Id)
			resourceNames = append(resourceNames, arn)
		}
	}

	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.serviceMap[service][r] = totalCountThisServiceThisRegion
	m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
	m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion
	m.mu.Unlock()
}

func (m *Inventory2Module) getSecretsManagerSecretsPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer func() {
		wg.Done()
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	// "PaginationMarker" is a control variable used for output continuity, as AWS return the output in pages.
	var totalCountThisServiceThisRegion = 0
	var service = "SecretsManager Secrets"
	var resourceNames []string

	ListSecrets, err := sdk.CachedSecretsManagerListSecrets(m.SecretsManagerClient, aws.ToString(m.Caller.Account), r)

	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	// Add this page of results to the total count
	totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(ListSecrets)

	// Add this page of resources to the module's resource list
	for _, secret := range ListSecrets {
		resourceNames = append(resourceNames, aws.ToString(secret.ARN))
	}

	// No more pages, update the module's service map
	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.serviceMap[service][r] = totalCountThisServiceThisRegion
	m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
	m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion
	m.mu.Unlock()

}

func (m *Inventory2Module) getRdsClustersPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer func() {
		wg.Done()
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	// "PaginationMarker" is a control variable used for output continuity, as AWS return the output in pages.
	var totalCountThisServiceThisRegion = 0
	var service = "RDS DB Instances"
	var resourceNames []string

	DescribeDBInstances, err := sdk.CachedRDSDescribeDBInstances(m.RDSClient, aws.ToString(m.Caller.Account), r)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	// Add this page of resources to the total count
	totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(DescribeDBInstances)

	// Add this page of resources to the module's resource list
	for _, instance := range DescribeDBInstances {
		resourceNames = append(resourceNames, aws.ToString(instance.DBInstanceArn))
	}

	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.serviceMap[service][r] = totalCountThisServiceThisRegion
	m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
	m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion
	m.mu.Unlock()
}

func (m *Inventory2Module) getAPIGatewayvAPIsPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer func() {
		wg.Done()
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	// "PaginationMarker" is a control variable used for output continuity, as AWS return the output in pages.
	var totalCountThisServiceThisRegion = 0
	var service = "APIGateway RestAPIs"
	var resourceNames []string

	GetRestApis, err := sdk.CachedApiGatewayGetRestAPIs(m.APIGatewayClient, aws.ToString(m.Caller.Account), r)

	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	// Add this page of resources to the total count
	totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(GetRestApis)

	// Add this page of resources to the module's resource list
	for _, restAPI := range GetRestApis {
		arn := aws.ToString(restAPI.Id)
		resourceNames = append(resourceNames, arn)
	}

	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.serviceMap[service][r] = totalCountThisServiceThisRegion
	m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
	m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion
	m.mu.Unlock()
}

func (m *Inventory2Module) getAPIGatewayv2APIsPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer func() {
		wg.Done()
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	// "PaginationMarker" is a control variable used for output continuity, as AWS return the output in pages.
	var totalCountThisServiceThisRegion = 0
	var service = "APIGatewayv2 APIs"
	var resourceNames []string

	GetApis, err := sdk.CachedAPIGatewayv2GetAPIs(m.APIGatewayv2Client, aws.ToString(m.Caller.Account), r)

	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	// Add this page of resources to the total count
	totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(GetApis)

	// Add this page of resources to the module's resource list
	for _, api := range GetApis {
		arn := aws.ToString(api.ApiId)
		resourceNames = append(resourceNames, arn)
	}

	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.serviceMap[service][r] = totalCountThisServiceThisRegion
	m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
	m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion
	m.mu.Unlock()
}

func (m *Inventory2Module) getELBv2ListenersPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer func() {
		wg.Done()
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	var totalCountThisServiceThisRegion = 0
	var service = "ELBv2 Load Balancers"
	var resourceNames []string

	DescribeLoadBalancers, err := sdk.CachedELBv2DescribeLoadBalancers(m.ELBv2Client, aws.ToString(m.Caller.Account), r)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	// Add this page of resources to the total count
	totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(DescribeLoadBalancers)

	// Add this page of resources to the module's resource list
	for _, loadBalancer := range DescribeLoadBalancers {
		arn := aws.ToString(loadBalancer.LoadBalancerArn)
		resourceNames = append(resourceNames, arn)
	}

	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.serviceMap[service][r] = totalCountThisServiceThisRegion
	m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
	m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion
	m.mu.Unlock()
}

func (m *Inventory2Module) getELBListenersPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer func() {
		wg.Done()
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	// "PaginationMarker" is a control variable used for output continuity, as AWS return the output in pages.
	var totalCountThisServiceThisRegion = 0
	var service = "ELB Load Balancers"
	var resourceNames []string

	DescribeLoadBalancers, err := sdk.CachedELBDescribeLoadBalancers(m.ELBClient, aws.ToString(m.Caller.Account), r)

	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	// Add this page of resources to the total count
	totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(DescribeLoadBalancers)

	// Add this page of resources to the module's resource list
	for _, loadBalancer := range DescribeLoadBalancers {
		arn := "arn:aws:elasticloadbalancing:" + r + ":" + aws.ToString(m.Caller.Account) + ":loadbalancer/" + aws.ToString(loadBalancer.LoadBalancerName)
		resourceNames = append(resourceNames, arn)
	}

	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.serviceMap[service][r] = totalCountThisServiceThisRegion
	m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
	m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion
	m.mu.Unlock()
}

func (m *Inventory2Module) getMqBrokersPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer func() {
		wg.Done()
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()

	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	var totalCountThisServiceThisRegion = 0
	var service = "MQ Brokers"
	var resourceNames []string

	ListBrokers, err := sdk.CachedMQListBrokers(m.MQClient, aws.ToString(m.Caller.Account), r)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	// Add this page of resources to the total count
	totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(ListBrokers)

	// Add this page of resources to the module's resource list
	for _, broker := range ListBrokers {
		resourceNames = append(resourceNames, aws.ToString(broker.BrokerArn))
	}

	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.serviceMap[service][r] = totalCountThisServiceThisRegion
	m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
	m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion
	m.mu.Unlock()
}

func (m *Inventory2Module) getOpenSearchPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer func() {
		wg.Done()
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	// "PaginationMarker" is a control variable used for output continuity, as AWS return the output in pages.
	var totalCountThisServiceThisRegion = 0
	var service = "OpenSearch DomainNames"
	var resourceNames []string

	ListDomainNames, err := sdk.CachedOpenSearchListDomainNames(m.OpenSearchClient, aws.ToString(m.Caller.Account), r)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	// Add this page of resources to the total count
	totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(ListDomainNames)

	// Add this page of resources to the module's resource list
	for _, domain := range ListDomainNames {
		arn := "arn:aws:opensearch:" + r + ":" + aws.ToString(m.Caller.Account) + ":domain/" + aws.ToString(domain.DomainName)
		resourceNames = append(resourceNames, arn)
	}

	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.serviceMap[service][r] = totalCountThisServiceThisRegion
	m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
	m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion
	m.mu.Unlock()

}

func (m *Inventory2Module) getGrafanaWorkspacesPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer func() {
		wg.Done()
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	// "PaginationMarker" is a control variable used for output continuity, as AWS return the output in pages.
	var totalCountThisServiceThisRegion = 0
	var service = "Grafana Workspaces"
	var resourceNames []string

	ListWorkspaces, err := sdk.CachedGrafanaListWorkspaces(m.GrafanaClient, aws.ToString(m.Caller.Account), r)
	// This for loop exits at the end depending on whether the output hits its last page (see pagination control block at the end of the loop).

	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	// Add this page of resources to the total count
	totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(ListWorkspaces)

	// Add this page of resources to the module's resource list
	for _, workspace := range ListWorkspaces {
		arn := "arn:aws:grafana:" + r + ":" + aws.ToString(m.Caller.Account) + ":workspace/" + aws.ToString(workspace.Id)
		resourceNames = append(resourceNames, arn)
	}

	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.serviceMap[service][r] = totalCountThisServiceThisRegion
	m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
	m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion
	m.mu.Unlock()
}

func (m *Inventory2Module) getAppRunnerServicesPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer func() {
		wg.Done()
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++

	var totalCountThisServiceThisRegion = 0
	var service = "AppRunner Services"
	var resourceNames []string

	ServiceSummaryList, err := sdk.CachedAppRunnerListServices(m.AppRunnerClient, aws.ToString(m.Caller.Account), r)

	if err != nil {
		//modLog.Error(err.Error())
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	// Add this page of resources to the total count
	totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(ServiceSummaryList)

	// Add this page of resources to the module's resource list
	for _, service := range ServiceSummaryList {
		resourceNames = append(resourceNames, aws.ToString(service.ServiceArn))
	}

	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.serviceMap[service][r] = totalCountThisServiceThisRegion
	m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
	m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion
	m.mu.Unlock()
}

func (m *Inventory2Module) getLightsailInstancesAndContainersPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer func() {
		wg.Done()
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	// "PaginationMarker" is a control variable used for output continuity, as AWS return the output in pages.
	var totalCountThisServiceThisRegion = 0
	var service = "Lightsail Instances/Containers"
	var resourceNames []string

	ContainerServices, err := sdk.CachedLightsailGetContainerServices(m.LightsailClient, aws.ToString(m.Caller.Account), r)

	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	} else {
		// Add this page of resources to the total count
		totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(ContainerServices)

		// Add this page of resources to the module's resource list
		for _, containerService := range ContainerServices {
			resourceNames = append(resourceNames, aws.ToString(containerService.Arn))
		}
	}

	Instances, err := sdk.CachedLightsailGetInstances(m.LightsailClient, aws.ToString(m.Caller.Account), r)

	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	// Add this page of resources to the total count
	totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(Instances)

	// Add this page of resources to the module's resource list
	for _, instance := range Instances {
		resourceNames = append(resourceNames, aws.ToString(instance.Arn))
	}

	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.serviceMap[service][r] = totalCountThisServiceThisRegion
	m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
	m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion
	m.mu.Unlock()

}

func (m *Inventory2Module) getSSMParametersPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer func() {
		wg.Done()
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	var totalCountThisServiceThisRegion = 0
	var service = "SSM Parameters"
	var resourceNames []string

	Parameters, err := sdk.CachedSSMDescribeParameters(m.SSMClient, aws.ToString(m.Caller.Account), r)

	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	// Add this page of resources to the total count
	totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(Parameters)

	// Add this page of resources to the module's resource list
	for _, parameter := range Parameters {
		arn := "arn:aws:ssm:" + r + ":" + aws.ToString(m.Caller.Account) + ":parameter/" + aws.ToString(parameter.Name)
		resourceNames = append(resourceNames, arn)
	}

	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.serviceMap[service][r] = totalCountThisServiceThisRegion
	m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
	m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion
	m.mu.Unlock()

}

func (m *Inventory2Module) getEcsTasksPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer func() {
		wg.Done()
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++

	var totalCountThisServiceThisRegion = 0
	var service = "ECS Tasks"
	var resourceNames []string

	Clusters, err := sdk.CachedECSListClusters(m.ECSClient, aws.ToString(m.Caller.Account), r)

	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}
	for _, cluster := range Clusters {

		Tasks, err := sdk.CachedECSListTasks(m.ECSClient, aws.ToString(m.Caller.Account), r, cluster)

		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			return
		}
		// Add this page of resources to the total count
		totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(Tasks)

		// Add this page of resources to the module's resource list
		for _, task := range Tasks {
			resourceNames = append(resourceNames, task)
		}

	}

	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.serviceMap[service][r] = totalCountThisServiceThisRegion
	m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
	m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion
	m.mu.Unlock()

}

func (m *Inventory2Module) getEcsServicesPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer func() {
		wg.Done()
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++

	var totalCountThisServiceThisRegion = 0
	var service = "ECS Services"
	var resourceNames []string

	Clusters, err := sdk.CachedECSListClusters(m.ECSClient, aws.ToString(m.Caller.Account), r)

	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}
	for _, cluster := range Clusters {

		Services, err := sdk.CachedECSListServices(m.ECSClient, aws.ToString(m.Caller.Account), r, cluster)

		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			return
		}
		// Add this page of resources to the total count
		totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(Services)

		// Add this page of resources to the module's resource list
		for _, service := range Services {
			arn := "arn:aws:ecs:" + r + ":" + aws.ToString(m.Caller.Account) + ":service/" + service
			resourceNames = append(resourceNames, arn)
		}

	}

	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.serviceMap[service][r] = totalCountThisServiceThisRegion
	m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
	m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion
	m.mu.Unlock()

}

func (m *Inventory2Module) getEcsClustersPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer func() {
		wg.Done()
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++

	var totalCountThisServiceThisRegion = 0
	var service = "ECS Clusters"
	var resourceNames []string

	Clusters, err := sdk.CachedECSListClusters(m.ECSClient, aws.ToString(m.Caller.Account), r)

	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	// Add this page of resources to the total count
	totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(Clusters)

	// Add this page of resources to the module's resource list
	for _, cluster := range Clusters {
		resourceNames = append(resourceNames, cluster)
	}

	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.serviceMap[service][r] = totalCountThisServiceThisRegion
	m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
	m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion
	m.mu.Unlock()

}

func (m *Inventory2Module) getEcrRepositoriesPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}) {
	// Don't use this method as a template for future ones. There is a one off in the way the NextToken is handled.
	defer func() {
		wg.Done()
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++

	var totalCountThisServiceThisRegion = 0
	var service = "ECR Repositories"
	var resourceNames []string

	Repositories, err := sdk.CachedECRDescribeRepositories(m.ECRClient, aws.ToString(m.Caller.Account), r)

	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	// Add this page of resources to the total count
	totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(Repositories)

	// Add this page of resources to the module's resource list
	for _, repo := range Repositories {
		resourceNames = append(resourceNames, aws.ToString(repo.RepositoryArn))
	}

	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.serviceMap[service][r] = totalCountThisServiceThisRegion
	m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
	m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion
	m.mu.Unlock()

}

func (m *Inventory2Module) getGlueDevEndpointsPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}) {
	// Don't use this method as a template for future ones. There is a one off in the way the NextToken is handled.
	defer func() {
		wg.Done()
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	var totalCountThisServiceThisRegion = 0
	var service = "Glue Dev Endpoints"
	var resourceNames []string

	DevEndpointNames, err := sdk.CachedGlueListDevEndpoints(m.GlueClient, aws.ToString(m.Caller.Account), r)

	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	// Add this page of resources to the total count
	totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(DevEndpointNames)

	// Add this page of resources to the module's resource list
	for _, devEndpoint := range DevEndpointNames {
		arn := "arn:aws:glue:" + r + ":" + aws.ToString(m.Caller.Account) + ":devEndpoint/" + devEndpoint
		resourceNames = append(resourceNames, arn)
	}

	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.serviceMap[service][r] = totalCountThisServiceThisRegion
	m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
	m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion
	m.mu.Unlock()

}

func (m *Inventory2Module) getGlueJobsPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer func() {
		wg.Done()
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++

	var totalCountThisServiceThisRegion = 0
	var service = "Glue Jobs"
	var resourceNames []string

	JobNames, err := sdk.CachedGlueListJobs(m.GlueClient, aws.ToString(m.Caller.Account), r)

	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	// Add this page of resources to the total count
	totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(JobNames)

	// Add this page of resources to the module's resource list
	for _, job := range JobNames {
		arn := "arn:aws:glue:" + r + ":" + aws.ToString(m.Caller.Account) + ":job/" + job
		resourceNames = append(resourceNames, arn)
	}

	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.serviceMap[service][r] = totalCountThisServiceThisRegion
	m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
	m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion
	m.mu.Unlock()

}

func (m *Inventory2Module) getGlueDatabasesPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer func() {
		wg.Done()
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++

	var totalCountThisServiceThisRegion = 0
	var service = "Glue Databases"
	var resourceNames []string

	Databases, err := sdk.CachedGlueGetDatabases(m.GlueClient, aws.ToString(m.Caller.Account), r)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	for _, database := range Databases {
		arn := "arn:aws:glue:" + r + ":" + aws.ToString(m.Caller.Account) + ":database/" + aws.ToString(database.Name)
		resourceNames = append(resourceNames, arn)
	}

	// Add this page of resources to the total count
	totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(Databases)

	// Add this page of resources to the module's resource list
	for _, database := range Databases {
		resourceNames = append(resourceNames, aws.ToString(database.Name))
	}

	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.serviceMap[service][r] = totalCountThisServiceThisRegion
	m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
	m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion
	m.mu.Unlock()

}

func (m *Inventory2Module) getGlueTablesPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer func() {
		wg.Done()
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++

	var totalCountThisServiceThisRegion = 0
	var service = "Glue Jobs"
	var resourceNames []string

	Databases, err := sdk.CachedGlueGetDatabases(m.GlueClient, aws.ToString(m.Caller.Account), r)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	for _, database := range Databases {
		TableNames, err := sdk.CachedGlueGetTables(m.GlueClient, aws.ToString(m.Caller.Account), r, aws.ToString(database.Name))
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			return

		}

		// Add this page of resources to the total count

		totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(TableNames)

		// Add this page of resources to the module's resource list
		for _, table := range TableNames {
			arn := "arn:aws:glue:" + r + ":" + aws.ToString(m.Caller.Account) + ":table/" + aws.ToString(database.Name) + "/" + aws.ToString(table.Name)
			resourceNames = append(resourceNames, arn)
		}
	}

	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.serviceMap[service][r] = totalCountThisServiceThisRegion
	m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
	m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion
	m.mu.Unlock()
}

func (m *Inventory2Module) getKinesisDatastreamsPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer func() {
		wg.Done()
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++

	var totalCountThisServiceThisRegion = 0
	var service = "Kinesis Data Streams"
	var resourceNames []string

	Datastreams, err := sdk.CachedKinesisListStreams(m.KinesisClient, aws.ToString(m.Caller.Account), r)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	// Add this page of resources to the total count
	totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(Datastreams)

	// Add this page of resources to the module's resource list
	for _, stream := range Datastreams {
		arn := "arn:aws:kinesis:" + r + ":" + aws.ToString(m.Caller.Account) + ":stream/" + stream
		resourceNames = append(resourceNames, arn)
	}

	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.serviceMap[service][r] = totalCountThisServiceThisRegion
	m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
	m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion
	m.mu.Unlock()

}

func (m *Inventory2Module) getSNSTopicsPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer func() {
		wg.Done()
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	// "PaginationMarker" is a control variable used for output continuity, as AWS return the output in pages.
	var totalCountThisServiceThisRegion = 0
	var service = "SNS Topics"
	var resourceNames []string

	Topics, err := sdk.CachedSNSListTopics(m.SNSClient, aws.ToString(m.Caller.Account), r)

	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	// Add this page of resources to the total count
	totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(Topics)

	// Add this page of resources to the module's resource list

	resourceNames = append(resourceNames, Topics...)

	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.serviceMap[service][r] = totalCountThisServiceThisRegion
	m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
	m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion
	m.mu.Unlock()
}

func (m *Inventory2Module) getSQSQueuesPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer func() {
		wg.Done()
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	var totalCountThisServiceThisRegion = 0
	var service = "SQS Queues"
	var resourceNames []string

	QueueUrls, err := sdk.CachedSQSListQueues(m.SQSClient, aws.ToString(m.Caller.Account), r)

	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	// Add this page of resources to the total count
	totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(QueueUrls)

	// Add this page of resources to the module's resource list
	for _, queue := range QueueUrls {
		arn := "arn:aws:sqs:" + r + ":" + aws.ToString(m.Caller.Account) + ":" + queue
		resourceNames = append(resourceNames, arn)
	}
	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.serviceMap[service][r] = totalCountThisServiceThisRegion
	m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
	m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion
	m.mu.Unlock()

}

func (m *Inventory2Module) getDynamoDBTablesPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer func() {
		wg.Done()
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	var totalCountThisServiceThisRegion = 0
	var service = "DynamoDB Tables"
	var resourceNames []string

	TableNames, err := sdk.CachedDynamoDBListTables(m.DynamoDBClient, aws.ToString(m.Caller.Account), r)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	// Add this page of resources to the total count
	totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(TableNames)

	// Add this page of resources to the module's resource list
	for _, table := range TableNames {
		arn := "arn:aws:dynamodb:" + r + ":" + aws.ToString(m.Caller.Account) + ":table/" + table
		resourceNames = append(resourceNames, arn)
	}

	// No more pages, update the module's service map
	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.serviceMap[service][r] = totalCountThisServiceThisRegion
	m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
	m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion

	m.mu.Unlock()
}

func (m *Inventory2Module) getRedshiftClustersPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer func() {
		wg.Done()
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	var totalCountThisServiceThisRegion = 0
	var service = "Redshift Clusters"
	var resourceNames []string

	Clusters, err := sdk.CachedRedShiftDescribeClusters(m.RedshiftClient, aws.ToString(m.Caller.Account), r)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	// Add this page of resources to the total count
	totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(Clusters)

	// Add this page of resources to the module's resource list
	for _, cluster := range Clusters {
		//arn := "arn:aws:redshift:" + r + ":" + aws.ToString(m.Caller.Account) + ":cluster:" + cluster

		resourceNames = append(resourceNames, aws.ToString(cluster.ClusterNamespaceArn))
	}

	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.serviceMap[service][r] = totalCountThisServiceThisRegion
	m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
	m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion

	m.mu.Unlock()
}

func (m *Inventory2Module) getCodeArtifactDomainsPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer func() {
		wg.Done()
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	var totalCountThisServiceThisRegion = 0
	var service = "CodeArtifact Domains"
	var resourceNames []string

	Domains, err := sdk.CachedCodeArtifactListDomains(m.CodeArtifactClient, aws.ToString(m.Caller.Account), r)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	// Add this page of resources to the total count
	totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(Domains)

	// Add this page of resources to the module's resource list
	for _, domain := range Domains {
		arn := aws.ToString(domain.Arn)
		resourceNames = append(resourceNames, arn)
	}

	// No more pages, update the module's service map
	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.serviceMap[service][r] = totalCountThisServiceThisRegion
	m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
	m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion

	m.mu.Unlock()
}

func (m *Inventory2Module) getCodeBuildProjectsPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer func() {
		wg.Done()
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	var totalCountThisServiceThisRegion = 0
	var service = "CodeBuild Projects"
	var resourceNames []string

	projects, err := sdk.CachedCodeBuildListProjects(m.CodeBuildClient, aws.ToString(m.Caller.Account), r)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	// Add this page of resources to the total count
	totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(projects)

	// Add this page of resources to the module's resource list
	for _, project := range projects {
		arn := "arn:aws:codebuild:" + r + ":" + aws.ToString(m.Caller.Account) + ":project/" + project
		resourceNames = append(resourceNames, arn)
	}

	// No more pages, update the module's service map
	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.serviceMap[service][r] = totalCountThisServiceThisRegion
	m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
	m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion

	m.mu.Unlock()
}

func (m *Inventory2Module) getCodeCommitRepositoriesPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer func() {
		wg.Done()
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	var totalCountThisServiceThisRegion = 0
	var service = "CodeCommit Repositories"
	var resourceNames []string

	repos, err := sdk.CachedCodeCommitListRepositories(m.CodeCommitClient, aws.ToString(m.Caller.Account), r)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	// Add this page of resources to the total count
	totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(repos)

	// Add this page of resources to the module's resource list
	for _, repo := range repos {
		arn := "arn:aws:codecommit:" + r + ":" + aws.ToString(m.Caller.Account) + ":" + aws.ToString(repo.RepositoryName)
		resourceNames = append(resourceNames, arn)
	}

	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.serviceMap[service][r] = totalCountThisServiceThisRegion
	m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
	m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion
	m.mu.Unlock()
}

func (m *Inventory2Module) getCodeDeployApplicationsPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer func() {
		wg.Done()
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	var totalCountThisServiceThisRegion = 0
	var service = "CodeDeploy Applications"
	var resourceNames []string

	apps, err := sdk.CachedCodeDeployListApplications(m.CodeDeployClient, aws.ToString(m.Caller.Account), r)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return

	}

	// Add this page of resources to the total count
	totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(apps)

	// Add this page of resources to the module's resource list
	for _, app := range apps {
		arn := "arn:aws:codedeploy:" + r + ":" + aws.ToString(m.Caller.Account) + ":application:" + app
		resourceNames = append(resourceNames, arn)
	}

	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.serviceMap[service][r] = totalCountThisServiceThisRegion
	m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
	m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion
	m.mu.Unlock()
}

func (m *Inventory2Module) getCodeDeployDeploymentsPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer func() {
		wg.Done()
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	var totalCountThisServiceThisRegion = 0
	var service = "CodeDeploy Deployments"
	var resourceNames []string

	deployments, err := sdk.CachedCodeDeployListDeployments(m.CodeDeployClient, aws.ToString(m.Caller.Account), r)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return

	}

	// Add this page of resources to the total count
	totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(deployments)

	// Add this page of resources to the module's resource list
	for _, d := range deployments {
		arn := "arn:aws:codedeploy:" + r + ":" + aws.ToString(m.Caller.Account) + ":application:" + d
		resourceNames = append(resourceNames, arn)
	}

	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.serviceMap[service][r] = totalCountThisServiceThisRegion
	m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
	m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion
	m.mu.Unlock()
}

func (m *Inventory2Module) getDataPipelinePipelinesPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer func() {
		wg.Done()
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	var totalCountThisServiceThisRegion = 0
	var service = "DataPipeline Pipelines"
	var resourceNames []string

	pipelines, err := sdk.CachedDataPipelineListPipelines(m.DataPipelineClient, aws.ToString(m.Caller.Account), r)

	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return

	}

	// Add this page of resources to the total count
	totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(pipelines)

	// Add this page of resources to the module's resource list
	for _, p := range pipelines {
		arn := "arn:aws:datapipeline:" + r + ":" + aws.ToString(m.Caller.Account) + ":pipeline:" + aws.ToString(p.Id)
		resourceNames = append(resourceNames, arn)
	}

	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.serviceMap[service][r] = totalCountThisServiceThisRegion
	m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
	m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion
	m.mu.Unlock()
}

func (m *Inventory2Module) getStepFunctionsPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer func() {
		wg.Done()
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	var totalCountThisServiceThisRegion = 0
	var service = "StepFunctions State Machines"
	var resourceNames []string

	ListStateMachines, err := sdk.CachedStepFunctionsListStateMachines(m.StepFunctionClient, aws.ToString(m.Caller.Account), r)

	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	// Add this page of resources to the total count
	totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(ListStateMachines)

	// Add this page of resources to the module's resource list
	for _, stateMachine := range ListStateMachines {
		arn := "arn:aws:states:" + r + ":" + aws.ToString(m.Caller.Account) + ":stateMachine:" + aws.ToString(stateMachine.Name)
		resourceNames = append(resourceNames, arn)
	}

	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.serviceMap[service][r] = totalCountThisServiceThisRegion
	m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
	m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion
	m.mu.Unlock()
}

// Global Resources

func (m *Inventory2Module) getBuckets(verbosity int, dataReceiver chan GlobalResourceCount2) {
	// "PaginationMarker" is a control variable used for output continuity, as AWS return the output in pages.
	var total int
	resourceType := "S3 Buckets"
	service := "S3 Buckets"
	var r string = "Global"
	var totalCountThisServiceThisRegion = 0
	var resourceNames []string

	Buckets, err := sdk.CachedListBuckets(m.S3Client, aws.ToString(m.Caller.Account))

	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	total = len(Buckets)

	// Add this page of resources to the module's resource list
	for _, bucket := range Buckets {
		arn := "arn:aws:s3:::" + aws.ToString(bucket.Name)
		m.resources = append(m.resources, arn)
	}

	// Add this page of resources to the total count
	totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(Buckets)

	dataReceiver <- GlobalResourceCount2{
		resourceType: resourceType,
		count:        total,
	}

	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.serviceMap[service][r] = totalCountThisServiceThisRegion
	m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
	m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion
	m.mu.Unlock()
	// if verbosity > 1 {
	// 	fmt.Printf("S3 Buckets: %d\n", total_buckets)
	// }
}

func (m *Inventory2Module) getCloudfrontDistros(verbosity int, dataReceiver chan GlobalResourceCount2) {
	var total int
	var r string = "Global"
	service := "Cloudfront Distributions"
	resourceType := "Cloudfront Distributions"
	var totalCountThisServiceThisRegion = 0
	var resourceNames []string

	Items, err := sdk.CachedCloudFrontListDistributions(m.CloudfrontClient, aws.ToString(m.Caller.Account))
	// This for loop exits at the end depending on whether the output hits its last page (see pagination control block at the end of the loop).

	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	// Add this page of resources to the total count
	total = total + len(Items)

	// Add this page of resources to the module's resource list
	for _, distro := range Items {
		resourceNames = append(resourceNames, aws.ToString(distro.ARN))
	}

	// Add this page of resources to the total count
	totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(Items)

	dataReceiver <- GlobalResourceCount2{
		resourceType: resourceType,
		count:        total,
	}
	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.serviceMap[service][r] = totalCountThisServiceThisRegion
	m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
	m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion
	m.mu.Unlock()
}

func (m *Inventory2Module) getIAMUsers(verbosity int, dataReceiver chan GlobalResourceCount2) {

	var total int
	var r string = "Global"
	service := "IAM Users"
	var totalCountThisServiceThisRegion = 0
	resourceType := "IAM Users"
	var resourceNames []string

	Users, err := sdk.CachedIamListUsers(m.IAMClient, aws.ToString(m.Caller.Account))

	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}
	total = total + len(Users)

	// Add this page of resources to the module's resource list
	for _, user := range Users {
		resourceNames = append(resourceNames, aws.ToString(user.Arn))
	}

	// Add this page of resources to the total count
	totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(Users)

	dataReceiver <- GlobalResourceCount2{
		resourceType: resourceType,
		count:        total,
	}
	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.serviceMap[service][r] = totalCountThisServiceThisRegion
	m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
	m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion

	m.mu.Unlock()
}
func (m *Inventory2Module) getIAMRoles(verbosity int, dataReceiver chan GlobalResourceCount2) {
	var total int
	var r string = "Global"
	service := "IAM Roles"
	var totalCountThisServiceThisRegion = 0
	resourceType := "IAM Roles"
	var resourceNames []string

	Roles, err := sdk.CachedIamListRoles(m.IAMClient, aws.ToString(m.Caller.Account))

	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}
	total = total + len(Roles)

	// Add this page of resources to the module's resource list
	for _, role := range Roles {
		resourceNames = append(resourceNames, aws.ToString(role.Arn))
	}

	// Add this page of resources to the total count
	totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(Roles)

	dataReceiver <- GlobalResourceCount2{
		resourceType: resourceType,
		count:        total,
	}

	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.serviceMap[service][r] = totalCountThisServiceThisRegion
	m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
	m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion
	m.mu.Unlock()

}

func (m *Inventory2Module) getIAMGroups(verbosity int, dataReceiver chan GlobalResourceCount2) {
	var total int
	var r string = "Global"
	service := "IAM Groups"
	var totalCountThisServiceThisRegion = 0
	resourceType := "IAM Groups"
	var resourceNames []string

	Groups, err := sdk.CachedIamListGroups(m.IAMClient, aws.ToString(m.Caller.Account))

	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}
	total = total + len(Groups)

	// Add this page of resources to the module's resource list
	for _, group := range Groups {
		resourceNames = append(resourceNames, aws.ToString(group.Arn))
	}

	// Add this page of resources to the total count
	totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(Groups)

	dataReceiver <- GlobalResourceCount2{
		resourceType: resourceType,
		count:        total,
	}

	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.serviceMap[service][r] = totalCountThisServiceThisRegion
	m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
	m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion

	m.mu.Unlock()
}

func (m *Inventory2Module) getIAMAccessKeys(verbosity int, dataReceiver chan GlobalResourceCount2) {
	var total int
	var r string = "Global"
	service := "IAM Access Keys"
	var totalCountThisServiceThisRegion = 0
	resourceType := "IAM Access Keys"
	var resourceNames []string

	Users, err := sdk.CachedIamListUsers(m.IAMClient, aws.ToString(m.Caller.Account))

	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	for _, user := range Users {

		AccessKeys, err := sdk.CachedIamListAccessKeys(m.IAMClient, aws.ToString(m.Caller.Account), aws.ToString(user.UserName))

		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			return
		}
		total = total + len(AccessKeys)

		// Add this page of resources to the module's resource list
		for _, key := range AccessKeys {
			resourceNames = append(resourceNames, aws.ToString(key.UserName))
		}

		// Add this page of resources to the total count
		totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(AccessKeys)

		dataReceiver <- GlobalResourceCount2{
			resourceType: resourceType,
			count:        total,
		}
	}

	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.serviceMap[service][r] = totalCountThisServiceThisRegion
	m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
	m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion

	m.mu.Unlock()
}

func (m *Inventory2Module) getRoute53Zones(verbosity int, dataReceiver chan GlobalResourceCount2) {
	var total int
	var r string = "Global"
	service := "Route53 Zones"
	var totalCountThisServiceThisRegion = 0
	resourceType := "Route53 Zones"
	var resourceNames []string

	Zones, err := sdk.CachedRoute53ListHostedZones(m.Route53Client, aws.ToString(m.Caller.Account))

	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}
	total = total + len(Zones)

	// Add this page of resources to the module's resource list
	for _, zone := range Zones {
		resourceNames = append(resourceNames, aws.ToString(zone.Id))
	}

	// Add this page of resources to the total count
	totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(Zones)

	dataReceiver <- GlobalResourceCount2{
		resourceType: resourceType,
		count:        total,
	}

	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.serviceMap[service][r] = totalCountThisServiceThisRegion
	m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
	m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion
	m.mu.Unlock()
}

func (m *Inventory2Module) getRoute53Records(verbosity int, dataReceiver chan GlobalResourceCount2) {
	var total int
	var r string = "Global"
	service := "Route53 Records"
	var totalCountThisServiceThisRegion = 0
	resourceType := "Route53 Records"
	var resourceNames []string

	Zones, err := sdk.CachedRoute53ListHostedZones(m.Route53Client, aws.ToString(m.Caller.Account))

	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	for _, zone := range Zones {
		Records, err := sdk.CachedRoute53ListResourceRecordSets(m.Route53Client, aws.ToString(m.Caller.Account), aws.ToString(zone.Id))

		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			return
		}
		total = total + len(Records)

		// Add this page of resources to the module's resource list
		for _, record := range Records {
			resourceNames = append(resourceNames, aws.ToString(record.Name))
		}

		// Add this page of resources to the total count
		totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(Records)
	}

	dataReceiver <- GlobalResourceCount2{
		resourceType: resourceType,
		count:        total,
	}

	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.serviceMap[service][r] = totalCountThisServiceThisRegion
	m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
	m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion

	m.mu.Unlock()
}
