package aws

import (
	"context"
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
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	"github.com/aws/aws-sdk-go-v2/service/grafana"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lightsail"
	"github.com/aws/aws-sdk-go-v2/service/mq"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
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
	LambdaClient         *lambda.Client
	EC2Client            *ec2.Client
	ECSClient            *ecs.Client
	EKSClient            sdk.EKSClientInterface
	S3Client             *s3.Client
	CloudFormationClient *cloudformation.Client
	SecretsManagerClient *secretsmanager.Client
	SSMClient            *ssm.Client
	RDSClient            *rds.Client
	APIGatewayv2Client   *apigatewayv2.Client
	ELBv2Client          *elasticloadbalancingv2.Client
	ELBClient            *elasticloadbalancing.Client
	IAMClient            *iam.Client
	MQClient             *mq.Client
	OpenSearchClient     *opensearch.Client
	GrafanaClient        *grafana.Client
	APIGatewayClient     *apigateway.Client
	RedshiftClient       *redshift.Client
	CloudfrontClient     *cloudfront.Client
	AppRunnerClient      *apprunner.Client
	LightsailClient      *lightsail.Client
	GlueClient           *glue.Client
	SNSClient            *sns.Client
	SQSClient            *sqs.Client
	DynamoDBClient       *dynamodb.Client
	CodeBuildClient      sdk.CodeBuildClientInterface
	StepFunctionClient   sdk.StepFunctionsClientInterface

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
	// def change this to build dynamically in the future.
	m.services = []string{"total", "APIGateway RestAPIs", "APIGatewayv2 APIs", "AppRunner Services", "CloudFormation Stacks", "Cloudfront Distributions", "CodeBuild Projects", "DynamoDB Tables", "EC2 Instances", "ECS Tasks", "EKS Clusters", "ELB Load Balancers", "ELBv2 Load Balancers", "Glue Dev Endpoints", "Glue Jobs", "Grafana Workspaces", "Lambda Functions", "Lightsail Instances/Containers", "MQ Brokers", "OpenSearch DomainNames", "RDS DB Instances", "SecretsManager Secrets", "SNS Topics", "SQS Queues", "SSM Parameters", "StepFunctions State Machines"}
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
	}

	fmt.Printf("[%s][%s] Enumerating selected services in all regions for account %s.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), aws.ToString(m.Caller.Account))
	fmt.Printf("[%s][%s] Supported Services: ApiGateway, ApiGatewayv2, AppRunner, CloudFormation, Cloudfront, CodeBuild, DynamoDB,  \n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	fmt.Printf("[%s][%s] \t\t\tEC2, ECS, EKS, ELB, ELBv2, Glue, Grafana, IAM, Lambda, Lightsail, MQ, \n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	fmt.Printf("[%s][%s] \t\t\tOpenSearch, RDS, S3, SecretsManager, SNS, SQS, SSM, Step Functions\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))

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

	// for _, r := range []string{"us-east-1", "us-east-2", "ap-northeast-1", "eu-west-1", "us-west-2"} {
	// 	m.CommandCounter.Total++
	// wg.Add(1)
	// 	go m.getAppRunnerServicesPerRegion(r, wg, semaphore)
	// }

	wg.Wait()
	//time.Sleep(time.Second * 2)

	// Send a message to the spinner goroutine to close the channel and stop
	spinnerDone <- true
	<-spinnerDone

	//duration := time.Since(start)
	//fmt.Printf("\n\n[*] Total execution time %s\n", duration)

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

	// var sortedBody []kv
	// for k, v := range m.serviceMap {
	// 	sortedBody = append(sortedBody, kv{k, v})
	// }

	// sort.Slice(sortedBody, func(i, j int) bool {
	// 	return sortedBody[i].Key > ss[j].Key
	// })

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
			// Convert the slice of strings to a slice of interfaces???  not sure, but this was needed. I couldnt just pass temp row to the output.Body
			for _, val := range temprow {
				outputRow = append(outputRow, val)

			}

			// Finally write the row to the table
			m.output.Body = append(m.output.Body, outputRow)

		}
	}

	m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", fmt.Sprintf("%s-%s", aws.ToString(m.Caller.Account), m.AWSProfile))

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
		o.Table.DirectoryName = filepath.Join(outputDirectory, "cloudfox-output", "aws", fmt.Sprintf("%s-%s", aws.ToString(m.Caller.Account), m.AWSProfile))
		var header []string
		var body [][]string
		header, body = m.PrintGlobalResources(outputFormat, outputDirectory, verbosity, dataReceiver)
		o.Table.TableFiles = append(o.Table.TableFiles, internal.TableFile{
			Header: header,
			Body:   body,
			Name:   "inventory-global",
		})
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

func (m *Inventory2Module) PrintGlobalResources(outputFormat string, outputDirectory string, verbosity int, dataReceiver chan GlobalResourceCount2) ([]string, [][]string) {
	m.globalOutput.Verbosity = verbosity
	m.globalOutput.CallingModule = "inventory"
	m.globalOutput.FullFilename = "inventory-global"

	m.getBuckets(verbosity, dataReceiver)
	m.getIAMUsers(verbosity, dataReceiver)
	m.getIAMRoles(verbosity, dataReceiver)
	m.getCloudfrontDistros(verbosity, dataReceiver)

	//m.globalOutput.CallingModule = fmt.Sprintf("%s-global", m.globalOutput.CallingModule)
	m.globalOutput.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", m.AWSProfile)

	m.globalOutput.Headers = []string{
		"Resource Type",
		"Total",
	}

	for i, GlobalResourceCount := range m.GlobalResourceCounts {
		if m.GlobalResourceCounts[i].count != 0 {
			m.globalOutput.Body = append(
				m.globalOutput.Body,
				[]string{
					GlobalResourceCount.resourceType,
					strconv.Itoa(GlobalResourceCount.count),
				},
			)
		}
	}
	//m.globalOutput.FilePath = filepath.Join(path, m.globalOutput.CallingModule)
	//m.globalOutput.OutputSelector(outputFormat)
	//internal.OutputSelector(verbosity, outputFormat, m.globalOutput.Headers, m.globalOutput.Body, m.globalOutput.FilePath, m.globalOutput.FullFilename, m.globalOutput.CallingModule, false, m.AWSProfile)
	return m.globalOutput.Headers, m.globalOutput.Body

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

	res, err := servicemap.IsServiceInRegion("lambda", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		go m.getLambdaFunctionsPerRegion(r, wg, semaphore)
	}

	res, err = servicemap.IsServiceInRegion("ec2", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		go m.getEc2InstancesPerRegion(r, wg, semaphore)
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

	res, err = servicemap.IsServiceInRegion("secretsmanager", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		go m.getSecretsManagerSecretsPerRegion(r, wg, semaphore)
	}

	res, err = servicemap.IsServiceInRegion("eks", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		go m.getEksClustersPerRegion(r, wg, semaphore)
	}

	res, err = servicemap.IsServiceInRegion("ecs", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		go m.getEcsTasksPerRegion(r, wg, semaphore)
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

	res, err = servicemap.IsServiceInRegion("apigateway", r)
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

	res, err = servicemap.IsServiceInRegion("mq", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		m.getMqBrokersPerRegion(r, wg, semaphore)
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

	// AppRunner is not supported in the aws service region catalog so we have to run it in all regions
	m.CommandCounter.Total++
	wg.Add(1)
	go m.getAppRunnerServicesPerRegion(r, wg, semaphore)

	res, err = servicemap.IsServiceInRegion("lightsail", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		go m.getLightsailInstancesAndContainersPerRegion(r, wg, semaphore)
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

	res, err = servicemap.IsServiceInRegion("glue", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		go m.getGlueDevEndpointsPerRegion(r, wg, semaphore)
	}

	res, err = servicemap.IsServiceInRegion("ssm", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		go m.getGlueJobsPerRegion(r, wg, semaphore)
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
	res, err = servicemap.IsServiceInRegion("dynamodb", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		go m.getDynamoDBTablesPerRegion(r, wg, semaphore)
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
	// "PaginationMarker" is a control variable used for output continuity, as AWS return the output in pages.
	var PaginationControl *string
	var totalCountThisServiceThisRegion = 0
	var service = "SSM Parameters"
	var resourceNames []string

	for {
		DescribeParameters, err := m.SSMClient.DescribeParameters(
			context.TODO(),
			&(ssm.DescribeParametersInput{
				NextToken: PaginationControl,
			}),
			func(o *ssm.Options) {
				o.Region = r
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		// Add this page of resources to the total count
		totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(DescribeParameters.Parameters)

		// Add this page of resources to the module's resource list
		for _, parameter := range DescribeParameters.Parameters {
			arn := "arn:aws:ssm:" + r + ":" + aws.ToString(m.Caller.Account) + ":parameter/" + aws.ToString(parameter.Name)
			resourceNames = append(resourceNames, arn)
		}

		// Pagination control. After the last page of output, the for loop exits.
		if DescribeParameters.NextToken != nil {
			PaginationControl = DescribeParameters.NextToken
		} else {
			PaginationControl = nil
			m.mu.Lock()
			m.resources = append(m.resources, resourceNames...)
			m.serviceMap[service][r] = totalCountThisServiceThisRegion
			m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
			m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion
			m.mu.Unlock()
			break
		}

	}
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
	// "PaginationMarker" is a control variable used for output continuity, as AWS return the output in pages.
	var PaginationControl *string
	var PaginationControl2 *string
	var totalCountThisServiceThisRegion = 0
	var service = "ECS Tasks"
	var resourceNames []string

	for {
		ListClusters, err := m.ECSClient.ListClusters(
			context.TODO(),
			&(ecs.ListClustersInput{
				NextToken: PaginationControl,
			}),
			func(o *ecs.Options) {
				o.Region = r
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}
		for _, cluster := range ListClusters.ClusterArns {
			ListTasks, err := m.ECSClient.ListTasks(
				context.TODO(),
				&(ecs.ListTasksInput{
					Cluster:   &cluster,
					NextToken: PaginationControl2,
				}),
				func(o *ecs.Options) {
					o.Region = r
				},
			)
			if err != nil {
				m.modLog.Error(err.Error())
				m.CommandCounter.Error++
				break
			}
			// Add this page of resources to the total count
			totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(ListTasks.TaskArns)

			// Add this page of resources to the module's resource list
			for _, task := range ListTasks.TaskArns {
				resourceNames = append(resourceNames, task)
			}

			if ListTasks.NextToken != nil {
				PaginationControl2 = ListTasks.NextToken
			} else {
				PaginationControl2 = nil
				break
			}
		}

		// The "NextToken" value is nil when there's no more data to return.
		if ListClusters.NextToken != nil {
			PaginationControl = ListClusters.NextToken
		} else {
			PaginationControl = nil
			// No more pages, update the module's service map
			m.mu.Lock()
			m.resources = append(m.resources, resourceNames...)
			m.serviceMap[service][r] = totalCountThisServiceThisRegion
			m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
			m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion
			m.mu.Unlock()
			break
		}
	}
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
	var PaginationControl *string
	var resourceNames []string

	for {
		ListDevEndpoints, err := m.GlueClient.ListDevEndpoints(
			context.TODO(),
			&(glue.ListDevEndpointsInput{
				NextToken: PaginationControl,
			}),
			func(o *glue.Options) {
				o.Region = r
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		// Add this page of resources to the total count
		totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(ListDevEndpoints.DevEndpointNames)

		// Add this page of resources to the module's resource list
		for _, devEndpoint := range ListDevEndpoints.DevEndpointNames {
			arn := "arn:aws:glue:" + r + ":" + aws.ToString(m.Caller.Account) + ":devEndpoint/" + devEndpoint
			resourceNames = append(resourceNames, arn)
		}

		// This next line is non-standard. For some reason this next token is an empty string instead of nil, so
		// as a result we had to change the comparison.
		if aws.ToString(ListDevEndpoints.NextToken) != "" {
			PaginationControl = ListDevEndpoints.NextToken
		} else {
			PaginationControl = nil
			m.mu.Lock()
			m.resources = append(m.resources, resourceNames...)
			m.serviceMap[service][r] = totalCountThisServiceThisRegion
			m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
			m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion
			m.mu.Unlock()
			break
		}
	}
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
	// "PaginationMarker" is a control variable used for output continuity, as AWS return the output in pages.
	var PaginationControl *string
	var totalCountThisServiceThisRegion = 0
	var service = "Glue Jobs"
	var resourceNames []string

	for {
		m.modLog.Info(fmt.Sprintf("Getting jobs %v\n", PaginationControl))
		ListJobs, err := m.GlueClient.ListJobs(
			context.TODO(),
			&(glue.ListJobsInput{
				NextToken: PaginationControl,
			}),
			func(o *glue.Options) {
				o.Region = r
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		// Add this page of resources to the total count
		totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(ListJobs.JobNames)

		// Add this page of resources to the module's resource list
		for _, job := range ListJobs.JobNames {
			arn := "arn:aws:glue:" + r + ":" + aws.ToString(m.Caller.Account) + ":job/" + job
			resourceNames = append(resourceNames, arn)
		}

		// The "NextToken" value is nil when there's no more data to return.
		if ListJobs.NextToken != nil {
			PaginationControl = ListJobs.NextToken
		} else {
			PaginationControl = nil
			// No more pages, update the module's service map
			m.mu.Lock()
			m.resources = append(m.resources, resourceNames...)
			m.serviceMap[service][r] = totalCountThisServiceThisRegion
			m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
			m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion
			m.mu.Unlock()
			break
		}
	}
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
	var PaginationControl *string
	var totalCountThisServiceThisRegion = 0
	var service = "SNS Topics"
	var resourceNames []string

	for {
		ListTopics, err := m.SNSClient.ListTopics(
			context.TODO(),
			&(sns.ListTopicsInput{
				NextToken: PaginationControl,
			}),
			func(o *sns.Options) {
				o.Region = r
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		// Add this page of resources to the total count
		totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(ListTopics.Topics)

		// Add this page of resources to the module's resource list
		for _, topic := range ListTopics.Topics {
			resourceNames = append(resourceNames, aws.ToString(topic.TopicArn))
		}

		// The "NextToken" value is nil when there's no more data to return.
		if ListTopics.NextToken != nil {
			PaginationControl = ListTopics.NextToken
		} else {
			PaginationControl = nil
			// No more pages, update the module's service map
			m.mu.Lock()
			m.resources = append(m.resources, resourceNames...)
			m.serviceMap[service][r] = totalCountThisServiceThisRegion
			m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
			m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion
			m.mu.Unlock()
			break
		}
	}
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
	// "PaginationMarker" is a control variable used for output continuity, as AWS return the output in pages.
	var PaginationControl *string
	var totalCountThisServiceThisRegion = 0
	var service = "SQS Queues"
	var resourceNames []string

	for {
		ListQueues, err := m.SQSClient.ListQueues(
			context.TODO(),
			&(sqs.ListQueuesInput{
				NextToken: PaginationControl,
			}),
			func(o *sqs.Options) {
				o.Region = r
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		// Add this page of resources to the total count
		totalCountThisServiceThisRegion = totalCountThisServiceThisRegion + len(ListQueues.QueueUrls)

		// Add this page of resources to the module's resource list
		for _, queue := range ListQueues.QueueUrls {
			arn := "arn:aws:sqs:" + r + ":" + aws.ToString(m.Caller.Account) + ":" + queue
			resourceNames = append(resourceNames, arn)
		}

		// The "NextToken" value is nil when there's no more data to return.
		if ListQueues.NextToken != nil {
			PaginationControl = ListQueues.NextToken
		} else {
			PaginationControl = nil
			// No more pages, update the module's service map
			m.mu.Lock()
			m.resources = append(m.resources, resourceNames...)
			m.serviceMap[service][r] = totalCountThisServiceThisRegion
			m.totalRegionCounts[r] = m.totalRegionCounts[r] + totalCountThisServiceThisRegion
			m.serviceMap["total"][r] = m.serviceMap["total"][r] + totalCountThisServiceThisRegion
			m.mu.Unlock()
			break
		}
	}
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

	projects, err := m.getcodeBuildProjects(r)
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
	var resourceNames []string

	ListBuckets, err := m.S3Client.ListBuckets(
		context.TODO(),
		&s3.ListBucketsInput{},
	)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	total = len(ListBuckets.Buckets)

	// Add this page of resources to the module's resource list
	for _, bucket := range ListBuckets.Buckets {
		arn := "arn:aws:s3:::" + aws.ToString(bucket.Name)
		m.resources = append(m.resources, arn)
	}

	dataReceiver <- GlobalResourceCount2{
		resourceType: resourceType,
		count:        total,
	}

	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.mu.Unlock()
	// if verbosity > 1 {
	// 	fmt.Printf("S3 Buckets: %d\n", total_buckets)
	// }
}

func (m *Inventory2Module) getCloudfrontDistros(verbosity int, dataReceiver chan GlobalResourceCount2) {
	// "PaginationMarker" is a control variable used for output continuity, as AWS return the output in pages.
	var PaginationControl *string
	var total int
	resourceType := "Cloudfront Distributions"
	var resourceNames []string

	// This for loop exits at the end depending on whether the output hits its last page (see pagination control block at the end of the loop).
	for {
		ListDistributions, err := m.CloudfrontClient.ListDistributions(
			context.TODO(),
			&cloudfront.ListDistributionsInput{
				Marker: PaginationControl,
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}
		if ListDistributions.DistributionList.Quantity == nil {
			break
		}

		// Add this page of resources to the total count
		total = total + len(ListDistributions.DistributionList.Items)

		// Add this page of resources to the module's resource list
		for _, distro := range ListDistributions.DistributionList.Items {
			resourceNames = append(resourceNames, aws.ToString(distro.ARN))
		}

		// Pagination control. After the last page of output, the for loop exits.
		if ListDistributions.DistributionList.NextMarker != nil {
			PaginationControl = ListDistributions.DistributionList.NextMarker
		} else {
			PaginationControl = nil
			dataReceiver <- GlobalResourceCount2{
				resourceType: resourceType,
				count:        total,
			}
			break
		}

	}
	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.mu.Unlock()
}

func (m *Inventory2Module) getIAMUsers(verbosity int, dataReceiver chan GlobalResourceCount2) {
	// "PaginationMarker" is a control variable used for output continuity, as AWS return the output in pages.
	var PaginationControl *string
	var total int
	resourceType := "IAM Users"
	var resourceNames []string

	for {
		ListUsers, err := m.IAMClient.ListUsers(
			context.TODO(),
			&iam.ListUsersInput{
				Marker: PaginationControl,
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}
		total = total + len(ListUsers.Users)

		// Add this page of resources to the module's resource list
		for _, user := range ListUsers.Users {
			resourceNames = append(resourceNames, aws.ToString(user.Arn))
		}

		// Pagination control. After the last page of output, the for loop exits.
		if ListUsers.Marker != nil {
			PaginationControl = ListUsers.Marker
		} else {
			PaginationControl = nil
			dataReceiver <- GlobalResourceCount2{
				resourceType: resourceType,
				count:        total,
			}
			break
		}
	}
	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.mu.Unlock()

}

func (m *Inventory2Module) getIAMRoles(verbosity int, dataReceiver chan GlobalResourceCount2) {
	// "PaginationMarker" is a control variable used for output continuity, as AWS return the output in pages.
	var PaginationControl *string
	var total int
	var resourceType = "IAM Roles"
	var resourceNames []string

	for {
		ListRoles, err := m.IAMClient.ListRoles(
			context.TODO(),
			&iam.ListRolesInput{
				Marker: PaginationControl,
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}
		total = total + len(ListRoles.Roles)

		// Add this page of resources to the module's resource list
		for _, role := range ListRoles.Roles {
			resourceNames = append(resourceNames, aws.ToString(role.Arn))
		}

		// Pagination control. After the last page of output, the for loop exits.
		if ListRoles.Marker != nil {
			PaginationControl = ListRoles.Marker
		} else {
			PaginationControl = nil
			dataReceiver <- GlobalResourceCount2{
				resourceType: resourceType,
				count:        total,
			}
			break
		}
	}
	m.mu.Lock()
	m.resources = append(m.resources, resourceNames...)
	m.mu.Unlock()

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

func (m *Inventory2Module) getcodeBuildProjects(r string) ([]string, error) {
	CodeBuildProjects, err := m.CodeBuildClient.ListProjects(
		context.TODO(),
		&codebuild.ListProjectsInput{},
		func(options *codebuild.Options) {
			options.Region = r
		},
	)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return nil, err
	}
	return CodeBuildProjects.Projects, nil
}
