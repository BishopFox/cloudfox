package aws

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/BishopFox/cloudfox/console"
	"github.com/BishopFox/cloudfox/utils"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	"github.com/aws/aws-sdk-go-v2/service/apprunner"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/grafana"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lightsail"
	"github.com/aws/aws-sdk-go-v2/service/mq"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	"github.com/bishopfox/awsservicemap/pkg/awsservicemap"
	"github.com/sirupsen/logrus"
)

type EndpointsModule struct {
	// General configuration data
	LambdaClient       *lambda.Client
	EKSClient          *eks.Client
	MQClient           *mq.Client
	OpenSearchClient   *opensearch.Client
	GrafanaClient      *grafana.Client
	ELBv2Client        *elasticloadbalancingv2.Client
	ELBClient          *elasticloadbalancing.Client
	APIGatewayClient   *apigateway.Client
	APIGatewayv2Client *apigatewayv2.Client
	RDSClient          *rds.Client
	RedshiftClient     *redshift.Client
	S3Client           *s3.Client
	CloudfrontClient   *cloudfront.Client
	AppRunnerClient    *apprunner.Client
	LightsailClient    *lightsail.Client

	Caller       sts.GetCallerIdentityOutput
	AWSRegions   []string
	OutputFormat string
	Goroutines   int
	AWSProfile   string

	// Main module data
	Endpoints      []Endpoint
	CommandCounter console.CommandCounter
	Errors         []string
	// Used to store output data for pretty printing
	output utils.OutputData2
	modLog *logrus.Entry
}

type Endpoint struct {
	AWSService string
	Region     string
	Name       string
	Endpoint   string
	Port       int32
	Protocol   string
	Public     string
}

var oe *smithy.OperationError

func (m *EndpointsModule) PrintEndpoints(outputFormat string, outputDirectory string, verbosity int) {
	// These stuct values are used by the output module
	m.output.Verbosity = verbosity
	m.output.Directory = outputDirectory
	m.output.CallingModule = "endpoints"
	m.modLog = utils.TxtLog.WithFields(logrus.Fields{
		"module": m.output.CallingModule,
	})
	if m.AWSProfile == "" {
		m.AWSProfile = utils.BuildAWSPath(m.Caller)
	}

	fmt.Printf("[%s][%s] Enumerating endpoints for account %s.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), aws.ToString(m.Caller.Account))
	fmt.Printf("[%s][%s] Supported Services: App Runner, APIGateway, ApiGatewayV2, Cloudfront, EKS, ELB, ELBv2, Grafana, \n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	fmt.Printf("[%s][%s] \t\t\tLambda, MQ, OpenSearch, Redshift, RDS\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))

	wg := new(sync.WaitGroup)
	semaphore := make(chan struct{}, m.Goroutines)
	// Create a channel to signal the spinner aka task status goroutine to finish
	spinnerDone := make(chan bool)
	//fire up the the task status spinner/updated
	go console.SpinUntil(m.output.CallingModule, &m.CommandCounter, spinnerDone, "tasks")

	//create a channel to receive the objects
	dataReceiver := make(chan Endpoint)

	go m.Receiver(dataReceiver)

	//execute global checks -- removing from now. not sure i want s3 data in here
	// wg.Add(1)
	// go m.getS3EndpointsPerRegion(wg)
	wg.Add(1)
	go m.getCloudfrontEndpoints(wg, semaphore, dataReceiver)

	//execute regional checks

	for _, region := range m.AWSRegions {
		wg.Add(1)
		go m.executeChecks(region, wg, semaphore, dataReceiver)
	}

	// for _, r := range utils.GetRegionsForService(m.AWSProfile, "apprunner") {
	// 	fmt.Println()
	// 	fmt.Println(r)
	// 	m.getAppRunnerEndpointsPerRegion(r, wg)
	// }

	wg.Wait()
	// Send a message to the spinner goroutine to close the channel and stop
	spinnerDone <- true
	<-spinnerDone
	close(dataReceiver)

	sort.Slice(m.Endpoints, func(i, j int) bool {
		return m.Endpoints[i].AWSService < m.Endpoints[j].AWSService
	})

	m.output.Headers = []string{
		"Service",
		"Region",
		"Name",
		"Endpoint",
		"Port",
		"Protocol",
		"Public",
	}

	// Table rows
	for i := range m.Endpoints {
		m.output.Body = append(
			m.output.Body,
			[]string{
				m.Endpoints[i].AWSService,
				m.Endpoints[i].Region,
				m.Endpoints[i].Name,
				m.Endpoints[i].Endpoint,
				strconv.Itoa(int(m.Endpoints[i].Port)),
				m.Endpoints[i].Protocol,
				m.Endpoints[i].Public,
			},
		)

	}
	if len(m.output.Body) > 0 {
		m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", m.AWSProfile)
		//m.output.OutputSelector(outputFormat)
		utils.OutputSelector(verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.CallingModule, m.output.CallingModule, m.AWSProfile)
		m.writeLoot(m.output.FilePath, verbosity)
		fmt.Printf("[%s][%s] %s endpoints found.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), strconv.Itoa(len(m.output.Body)))
	} else {
		fmt.Printf("[%s][%s] No endpoints found, skipping the creation of an output file.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	}

	// This works great to print errors out after the module but i'm not really sure i want that.
	// sort.Slice(m.Errors, func(i, j int) bool {
	// 	return m.Errors[i] < m.Errors[j]
	// })
	// for _, e := range m.Errors {
	// 	fmt.Printf("[%s][%s] %s\n", cyan(m.output.CallingModule),  cyan(m.AWSProfile), e)
	// }

}

func (m *EndpointsModule) Receiver(receiver chan Endpoint) {
	for data := range receiver {
		m.Endpoints = append(m.Endpoints, data)

	}
}

func (m *EndpointsModule) executeChecks(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Endpoint) {
	defer wg.Done()
	// check the concurrency semaphore
	// semaphore <- struct{}{}
	// defer func() {
	// 	<-semaphore
	// }()

	servicemap := awsservicemap.NewServiceMap()
	res, err := servicemap.IsServiceInRegion("lambda", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		go m.getLambdaFunctionsPerRegion(r, wg, semaphore, dataReceiver)
	}
	res, err = servicemap.IsServiceInRegion("eks", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		go m.getEksClustersPerRegion(r, wg, semaphore, dataReceiver)
	}
	res, err = servicemap.IsServiceInRegion("mq", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		go m.getMqBrokersPerRegion(r, wg, semaphore, dataReceiver)
	}
	res, err = servicemap.IsServiceInRegion("es", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		m.getOpenSearchPerRegion(r, wg, semaphore, dataReceiver)
	}
	res, err = servicemap.IsServiceInRegion("grafana", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		m.getGrafanaEndPointsPerRegion(r, wg, semaphore, dataReceiver)
	}
	res, err = servicemap.IsServiceInRegion("elb", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		go m.getELBv2ListenersPerRegion(r, wg, semaphore, dataReceiver)

		m.CommandCounter.Total++
		wg.Add(1)
		go m.getELBListenersPerRegion(r, wg, semaphore, dataReceiver)
	}
	res, err = servicemap.IsServiceInRegion("apigateway", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		go m.getAPIGatewayAPIsPerRegion(r, wg, semaphore, dataReceiver)

		m.CommandCounter.Total++
		wg.Add(1)
		go m.getAPIGatewayv2APIsPerRegion(r, wg, semaphore, dataReceiver)
	}
	res, err = servicemap.IsServiceInRegion("rds", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		go m.getRdsClustersPerRegion(r, wg, semaphore, dataReceiver)
	}
	res, err = servicemap.IsServiceInRegion("redshift", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		m.getRedshiftEndPointsPerRegion(r, wg, semaphore, dataReceiver)
	}

	//apprunner is not supported by the aws json so we have to call it in every region
	m.CommandCounter.Total++
	wg.Add(1)
	go m.getAppRunnerEndpointsPerRegion(r, wg, semaphore, dataReceiver)

	res, err = servicemap.IsServiceInRegion("lightsail", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		go m.getLightsailContainerEndpointsPerRegion(r, wg, semaphore, dataReceiver)
	}
}

func (m *EndpointsModule) writeLoot(outputDirectory string, verbosity int) {
	path := filepath.Join(outputDirectory, "loot")
	err := os.MkdirAll(path, os.ModePerm)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		panic(err.Error())
	}
	f := filepath.Join(path, "endpoints-UrlsOnly.txt")

	var out string

	for _, endpoint := range m.Endpoints {
		out = out + fmt.Sprintln(endpoint.Endpoint)
	}

	err = os.WriteFile(f, []byte(out), 0644)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		panic(err.Error())
	}

	if verbosity > 2 {
		fmt.Println()
		fmt.Printf("[%s][%s] %s \n", cyan(m.output.CallingModule), cyan(m.AWSProfile), green("Feed this endpoints into nmap and something like gowitness/aquatone for screenshots."))
		fmt.Print(out)
		fmt.Printf("[%s][%s] %s \n\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), green("End of loot file."))
	}

	fmt.Printf("[%s][%s] Loot written to [%s]\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), f)

}

func (m *EndpointsModule) getLambdaFunctionsPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Endpoint) {
	defer func() {
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
		wg.Done()

	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	// "PaginationMarker" is a control variable used for output continuity, as AWS return the output in pages.
	var PaginationMarker *string
	var public string

	// This for loop exits at the end dependeding on whether the output hits its last page (see pagination control block at the end of the loop).
	for {
		ListFunctions, err := m.LambdaClient.ListFunctions(
			context.TODO(),
			&lambda.ListFunctionsInput{
				Marker: PaginationMarker,
			},
			func(o *lambda.Options) {
				o.Region = r
			},
		)
		if err != nil {
			if errors.As(err, &oe) {
				m.Errors = append(m.Errors, (fmt.Sprintf(" Error: Region: %s, Service: %s, Operation: %s", r, oe.Service(), oe.Operation())))
			}
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		for _, function := range ListFunctions.Functions {
			name := function.FunctionName
			FunctionDetails, err := m.LambdaClient.GetFunctionUrlConfig(
				context.TODO(),
				&(lambda.GetFunctionUrlConfigInput{
					FunctionName: name,
				}),
				func(o *lambda.Options) {
					o.Region = r
				},
			)
			if err != nil {
				if errors.As(err, &oe) {
					m.Errors = append(m.Errors, (fmt.Sprintf(" Error: Region: %s, Service: %s, Operation: %s", r, oe.Service(), oe.Operation())))
				}
				m.modLog.Error(err.Error())
				m.CommandCounter.Error++
				break
			}
			endpoint := aws.ToString(FunctionDetails.FunctionUrl)

			if FunctionDetails.AuthType == "NONE" {
				public = "True"
			} else {
				public = "False"
			}

			dataReceiver <- Endpoint{
				AWSService: "Lambda",
				Region:     r,
				Name:       aws.ToString(name),
				Endpoint:   endpoint,
				Port:       443,
				Protocol:   "https",
				Public:     public,
			}
			//fmt.Println(endpoint, name, roleArn)
		}

		// Pagination control. After the last page of output, the for loop exits.
		if ListFunctions.NextMarker != nil {
			PaginationMarker = ListFunctions.NextMarker
		} else {
			PaginationMarker = nil
			break
		}
	}

}

func (m *EndpointsModule) getEksClustersPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Endpoint) {
	defer func() {
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
		wg.Done()

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

	for {
		ListClusters, err := m.EKSClient.ListClusters(
			context.TODO(),
			&(eks.ListClustersInput{
				NextToken: PaginationControl,
			}),
			func(o *eks.Options) {
				o.Region = r
			},
		)
		if err != nil {
			if errors.As(err, &oe) {
				m.Errors = append(m.Errors, (fmt.Sprintf(" Error: Region: %s, Service: %s, Operation: %s", r, oe.Service(), oe.Operation())))
			}
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		for _, cluster := range ListClusters.Clusters {
			ClusterDetails, err := m.EKSClient.DescribeCluster(
				context.TODO(),
				&(eks.DescribeClusterInput{
					Name: &cluster,
				}),
				func(o *eks.Options) {
					o.Region = r
				},
			)
			if err != nil {
				if errors.As(err, &oe) {
					m.Errors = append(m.Errors, (fmt.Sprintf(" Error: Region: %s, Service: %s, Operation: %s", r, oe.Service(), oe.Operation())))
				}
				m.modLog.Error(err.Error())
				m.CommandCounter.Error++
				break
			}
			var endpoint string
			var name string
			var public string
			vpcConfig := ClusterDetails.Cluster.ResourcesVpcConfig.EndpointPublicAccess
			if vpcConfig {
				//
				if ClusterDetails.Cluster.ResourcesVpcConfig.PublicAccessCidrs[0] == "0.0.0.0/0" {
					public = "True"
				} else {
					public = "False"
				}
			}

			endpoint = aws.ToString(ClusterDetails.Cluster.Endpoint)
			name = aws.ToString(ClusterDetails.Cluster.Name)
			dataReceiver <- Endpoint{
				AWSService: "Eks",
				Region:     r,
				Name:       name,
				Endpoint:   endpoint,
				Port:       443,
				Protocol:   "https",
				Public:     public,
			}

		}

		// The "NextToken" value is nil when there's no more data to return.
		if ListClusters.NextToken != nil {
			PaginationControl = ListClusters.NextToken
		} else {
			PaginationControl = nil
			break
		}
	}
}

func (m *EndpointsModule) getMqBrokersPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Endpoint) {
	defer func() {
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
		wg.Done()

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

	// This for loop exits at the end depending on whether the output hits its last page (see pagination control block at the end of the loop).
	for {
		ListBrokers, err := m.MQClient.ListBrokers(
			context.TODO(),
			&mq.ListBrokersInput{
				NextToken: PaginationControl,
			},
			func(o *mq.Options) {
				o.Region = r
			},
		)
		if err != nil {
			if errors.As(err, &oe) {
				m.Errors = append(m.Errors, (fmt.Sprintf(" Error: Region: %s, Service: %s, Operation: %s", r, oe.Service(), oe.Operation())))
			}
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		var public string
		for _, broker := range ListBrokers.BrokerSummaries {
			name := aws.ToString(broker.BrokerName)
			id := broker.BrokerId

			BrokerDetails, err := m.MQClient.DescribeBroker(
				context.TODO(),
				&(mq.DescribeBrokerInput{
					BrokerId: id,
				}),
				func(o *mq.Options) {
					o.Region = r
				},
			)
			if err != nil {
				if errors.As(err, &oe) {
					m.Errors = append(m.Errors, (fmt.Sprintf(" Error: Region: %s, Service: %s, Operation: %s", r, oe.Service(), oe.Operation())))
				}
				m.modLog.Error(err.Error())
				m.CommandCounter.Error++
				break
			}
			if BrokerDetails.PubliclyAccessible {
				public = "True"
			} else {
				public = "False"
			}

			endpoint := aws.ToString(BrokerDetails.BrokerInstances[0].ConsoleURL)

			dataReceiver <- Endpoint{
				AWSService: "Amazon MQ",
				Region:     r,
				Name:       name,
				Endpoint:   endpoint,
				Port:       443,
				Protocol:   "https",
				Public:     public,
			}

		}

		// Pagination control. After the last page of output, the for loop exits.
		if ListBrokers.NextToken != nil {
			PaginationControl = ListBrokers.NextToken
		} else {
			PaginationControl = nil
			break
		}
	}

}

func (m *EndpointsModule) getOpenSearchPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Endpoint) {
	defer func() {
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
		wg.Done()

	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	// "PaginationMarker" is a control variable used for output continuity, as AWS return the output in pages.
	//var PaginationControl *string

	// This for loop exits at the end dependeding on whether the output hits its last page (see pagination control block at the end of the loop).

	ListDomainNames, err := m.OpenSearchClient.ListDomainNames(
		context.TODO(),
		&opensearch.ListDomainNamesInput{},
		func(o *opensearch.Options) {
			o.Region = r
		},
	)
	if err != nil {
		if errors.As(err, &oe) {
			m.Errors = append(m.Errors, (fmt.Sprintf(" Error: Region: %s, Service: %s, Operation: %s", r, oe.Service(), oe.Operation())))
		}
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	for _, domainName := range ListDomainNames.DomainNames {
		name := aws.ToString(domainName.DomainName)

		DomainNameDetails, err := m.OpenSearchClient.DescribeDomain(
			context.TODO(),
			&(opensearch.DescribeDomainInput{
				DomainName: &name,
			}),
			func(o *opensearch.Options) {
				o.Region = r
			},
		)
		if err != nil {
			if errors.As(err, &oe) {
				m.Errors = append(m.Errors, (fmt.Sprintf(" Error: Region: %s, Service: %s, Operation: %s", r, oe.Service(), oe.Operation())))
			}
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			return
		}

		raw_endpoint := DomainNameDetails.DomainStatus.Endpoint
		var endpoint string
		var kibana_endpoint string

		// This exits thie function if an opensearch domain exists but there is no endpoint
		if raw_endpoint == nil {
			return
		} else {

			endpoint = fmt.Sprintf("https://%s", aws.ToString(raw_endpoint))
			kibana_endpoint = fmt.Sprintf("https://%s/_plugin/kibana/", aws.ToString(raw_endpoint))
		}

		//fmt.Println(endpoint)

		public := "Unknown"
		dataReceiver <- Endpoint{
			AWSService: "OpenSearch",
			Region:     r,
			Name:       name,
			Endpoint:   endpoint,
			Port:       443,
			Protocol:   "https",
			Public:     public,
		}
		dataReceiver <- Endpoint{
			AWSService: "OpenSearch",
			Region:     r,
			Name:       name,
			Endpoint:   kibana_endpoint,
			Port:       443,
			Protocol:   "https",
			Public:     public,
		}

	}

}

func (m *EndpointsModule) getGrafanaEndPointsPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Endpoint) {
	defer func() {
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
		wg.Done()

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

	// This for loop exits at the end dependeding on whether the output hits its last page (see pagination control block at the end of the loop).
	for {
		ListWorkspaces, err := m.GrafanaClient.ListWorkspaces(
			context.TODO(),
			&grafana.ListWorkspacesInput{
				NextToken: PaginationControl,
			},
			func(o *grafana.Options) {
				o.Region = r
			},
		)
		if err != nil {
			if errors.As(err, &oe) {
				m.Errors = append(m.Errors, (fmt.Sprintf(" Error: Region: %s, Service: %s, Operation: %s", r, oe.Service(), oe.Operation())))
			}
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		var public string
		for _, workspace := range ListWorkspaces.Workspaces {
			name := aws.ToString(workspace.Name)
			//id := workspace.Id
			endpoint := aws.ToString(workspace.Endpoint)
			awsService := "Grafana"

			public = "Unknown"
			protocol := "https"
			var port int32 = 443

			dataReceiver <- Endpoint{
				AWSService: awsService,
				Region:     r,
				Name:       name,
				Endpoint:   endpoint,
				Port:       port,
				Protocol:   protocol,
				Public:     public,
			}

		}

		// Pagination control. After the last page of output, the for loop exits.
		if ListWorkspaces.NextToken != nil {
			PaginationControl = ListWorkspaces.NextToken
		} else {
			PaginationControl = nil
			break
		}
	}

}

func (m *EndpointsModule) getELBv2ListenersPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Endpoint) {
	defer func() {
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
		wg.Done()

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
	awsService := "ELBv2"

	// This for loop exits at the end dependeding on whether the output hits its last page (see pagination control block at the end of the loop).
	for {
		DescribeLoadBalancers, err := m.ELBv2Client.DescribeLoadBalancers(
			context.TODO(),
			&elasticloadbalancingv2.DescribeLoadBalancersInput{
				Marker: PaginationControl,
			},
			func(o *elasticloadbalancingv2.Options) {
				o.Region = r
			},
		)
		if err != nil {
			if errors.As(err, &oe) {
				m.Errors = append(m.Errors, (fmt.Sprintf(" Error: Region: %s, Service: %s, Operation: %s", r, oe.Service(), oe.Operation())))
			}
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		var public string
		for _, lb := range DescribeLoadBalancers.LoadBalancers {

			name := aws.ToString(lb.LoadBalancerName)
			arn := aws.ToString(lb.LoadBalancerArn)
			scheme := lb.Scheme

			ListenerDetails, err := m.ELBv2Client.DescribeListeners(
				context.TODO(),
				&(elasticloadbalancingv2.DescribeListenersInput{
					LoadBalancerArn: &arn,
				}),
				func(o *elasticloadbalancingv2.Options) {
					o.Region = r
				},
			)
			if err != nil {
				if errors.As(err, &oe) {
					m.Errors = append(m.Errors, (fmt.Sprintf(" Error: Region: %s, Service: %s, Operation: %s", r, oe.Service(), oe.Operation())))
				}
				m.modLog.Error(err.Error())
				m.CommandCounter.Error++
				break
			}
			if scheme == "internet-facing" {
				public = "True"
			} else {
				public = "False"
			}

			for _, listener := range ListenerDetails.Listeners {
				endpoint := aws.ToString(lb.DNSName)
				port := aws.ToInt32(listener.Port)
				protocol := string(listener.Protocol)
				if protocol == "HTTPS" {
					endpoint = fmt.Sprintf("https://%s:%s", endpoint, strconv.Itoa(int(port)))
				} else if protocol == "HTTP" {
					endpoint = fmt.Sprintf("http://%s:%s", endpoint, strconv.Itoa(int(port)))
				}

				dataReceiver <- Endpoint{
					AWSService: awsService,
					Region:     r,
					Name:       name,
					Endpoint:   endpoint,
					Port:       port,
					Protocol:   protocol,
					Public:     public,
				}
			}

		}

		// Pagination control. After the last page of output, the for loop exits.
		if DescribeLoadBalancers.NextMarker != nil {
			PaginationControl = DescribeLoadBalancers.NextMarker
		} else {
			PaginationControl = nil
			break
		}
	}

}

func (m *EndpointsModule) getELBListenersPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Endpoint) {
	defer func() {
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
		wg.Done()

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
	awsService := "ELB"

	// This for loop exits at the end dependeding on whether the output hits its last page (see pagination control block at the end of the loop).
	for {
		DescribeLoadBalancers, err := m.ELBClient.DescribeLoadBalancers(
			context.TODO(),
			&elasticloadbalancing.DescribeLoadBalancersInput{
				Marker: PaginationControl,
			},
			func(o *elasticloadbalancing.Options) {
				o.Region = r
			},
		)
		if err != nil {
			if errors.As(err, &oe) {
				m.Errors = append(m.Errors, (fmt.Sprintf(" Error: Region: %s, Service: %s, Operation: %s", r, oe.Service(), oe.Operation())))
			}
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		var public string
		for _, lb := range DescribeLoadBalancers.LoadBalancerDescriptions {

			name := aws.ToString(lb.LoadBalancerName)
			scheme := aws.ToString(lb.Scheme)

			if scheme == "internet-facing" {
				public = "True"
			} else {
				public = "False"
			}

			for _, listener := range lb.ListenerDescriptions {
				endpoint := aws.ToString(lb.DNSName)
				port := listener.Listener.LoadBalancerPort
				protocol := aws.ToString(listener.Listener.Protocol)
				if protocol == "HTTPS" {
					endpoint = fmt.Sprintf("https://%s:%s", endpoint, strconv.Itoa(int(port)))
				} else if protocol == "HTTP" {
					endpoint = fmt.Sprintf("http://%s:%s", endpoint, strconv.Itoa(int(port)))
				}

				dataReceiver <- Endpoint{
					AWSService: awsService,
					Region:     r,
					Name:       name,
					Endpoint:   endpoint,
					Port:       port,
					Protocol:   protocol,
					Public:     public,
				}
			}

		}

		// Pagination control. After the last page of output, the for loop exits.
		if DescribeLoadBalancers.NextMarker != nil {
			PaginationControl = DescribeLoadBalancers.NextMarker
		} else {
			PaginationControl = nil
			break
		}
	}

}

func (m *EndpointsModule) getAPIGatewayAPIsPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Endpoint) {
	defer func() {
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
		wg.Done()

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
	awsService := "APIGateway"

	// This for loop exits at the end dependeding on whether the output hits its last page (see pagination control block at the end of the loop).
	for {
		GetRestApis, err := m.APIGatewayClient.GetRestApis(
			context.TODO(),
			&apigateway.GetRestApisInput{
				Position: PaginationControl,
			},
			func(o *apigateway.Options) {
				o.Region = r
			},
		)
		if err != nil {
			if errors.As(err, &oe) {
				m.Errors = append(m.Errors, (fmt.Sprintf(" Error: Region: %s, Service: %s, Operation: %s", r, oe.Service(), oe.Operation())))
			}
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		var public string
		for _, api := range GetRestApis.Items {

			name := aws.ToString(api.Name)
			id := aws.ToString(api.Id)
			raw_endpoint := fmt.Sprintf("https://%s.execute-api.%s.amazonaws.com", id, r)
			var port int32 = 443
			protocol := "https"

			endpointType := *api.EndpointConfiguration
			//fmt.Println(endpointType)
			if endpointType.Types[0] == "PRIVATE" {
				public = "False"
			} else {
				public = "True"
			}

			for {
				GetResources, err := m.APIGatewayClient.GetResources(
					context.TODO(),
					&apigateway.GetResourcesInput{
						RestApiId: &id,
						Position:  PaginationControl2,
					},
					func(o *apigateway.Options) {
						o.Region = r
					},
				)

				if err != nil {
					if errors.As(err, &oe) {
						m.Errors = append(m.Errors, (fmt.Sprintf(" Error: Region: %s, Service: %s, Operation: %s", r, oe.Service(), oe.Operation())))
					}
					m.modLog.Error(err.Error())
					m.CommandCounter.Error++
					break
				}

				for _, resource := range GetResources.Items {

					path := resource.Path
					//pathPart := resource.PathPart
					//fmt.Printf(*path, *pathPart)
					//var path string

					// if len(strings.Fields(*routeKey)) == 2 {
					// 	path = strings.Fields(*routeKey)[1]
					// }
					endpoint := fmt.Sprintf("%s%s", raw_endpoint, aws.ToString(path))

					dataReceiver <- Endpoint{
						AWSService: awsService,
						Region:     r,
						Name:       name,
						Endpoint:   endpoint,
						Port:       port,
						Protocol:   protocol,
						Public:     public,
					}

				}
				if GetResources.Position != nil {
					PaginationControl2 = GetResources.Position
				} else {
					PaginationControl2 = nil
					break
				}

			}
		}
		// Pagination control. After the last page of output, the for loop exits.
		if GetRestApis.Position != nil {
			PaginationControl = GetRestApis.Position
		} else {
			PaginationControl = nil
			break
		}

	}
}

func (m *EndpointsModule) getAPIGatewayv2APIsPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Endpoint) {
	defer func() {
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
		wg.Done()

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
	awsService := "APIGatewayv2"

	// This for loop exits at the end dependeding on whether the output hits its last page (see pagination control block at the end of the loop).
	for {
		GetApis, err := m.APIGatewayv2Client.GetApis(
			context.TODO(),
			&apigatewayv2.GetApisInput{
				NextToken: PaginationControl,
			},
			func(o *apigatewayv2.Options) {
				o.Region = r
			},
		)
		if err != nil {
			if errors.As(err, &oe) {
				m.Errors = append(m.Errors, (fmt.Sprintf(" Error: Region: %s, Service: %s, Operation: %s", r, oe.Service(), oe.Operation())))
			}
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		var public string
		for _, api := range GetApis.Items {

			name := aws.ToString(api.Name)
			raw_endpoint := aws.ToString(api.ApiEndpoint)
			id := aws.ToString(api.ApiId)
			var port int32 = 443
			protocol := "https"

			for {
				GetRoutes, err := m.APIGatewayv2Client.GetRoutes(
					context.TODO(),
					&apigatewayv2.GetRoutesInput{
						ApiId:     &id,
						NextToken: PaginationControl2,
					},
					func(o *apigatewayv2.Options) {
						o.Region = r
					},
				)

				if err != nil {
					if errors.As(err, &oe) {
						m.Errors = append(m.Errors, (fmt.Sprintf(" Error: Region: %s, Service: %s, Operation: %s", r, oe.Service(), oe.Operation())))
					}
					m.modLog.Error(err.Error())
					m.CommandCounter.Error++
					break
				}

				for _, route := range GetRoutes.Items {
					routeKey := route.RouteKey
					var path string
					if len(strings.Fields(*routeKey)) == 2 {
						path = strings.Fields(*routeKey)[1]
					}
					endpoint := fmt.Sprintf("%s%s", raw_endpoint, path)
					public = "True"

					dataReceiver <- Endpoint{
						AWSService: awsService,
						Region:     r,
						Name:       name,
						Endpoint:   endpoint,
						Port:       port,
						Protocol:   protocol,
						Public:     public,
					}

				}
				if GetRoutes.NextToken != nil {
					PaginationControl2 = GetRoutes.NextToken
				} else {
					PaginationControl2 = nil
					break
				}

			}
		}
		// Pagination control. After the last page of output, the for loop exits.
		if GetApis.NextToken != nil {
			PaginationControl = GetApis.NextToken
		} else {
			PaginationControl = nil
			break
		}

	}
}

func (m *EndpointsModule) getRdsClustersPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Endpoint) {
	defer func() {
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
		wg.Done()

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

	for {
		DescribeDBInstances, err := m.RDSClient.DescribeDBInstances(
			context.TODO(),
			&(rds.DescribeDBInstancesInput{
				Marker: PaginationControl,
			}),
			func(o *rds.Options) {
				o.Region = r
			},
		)
		if err != nil {
			if errors.As(err, &oe) {
				m.Errors = append(m.Errors, (fmt.Sprintf(" Error: Region: %s, Service: %s, Operation: %s", r, oe.Service(), oe.Operation())))
			}
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		var public string
		for _, instance := range DescribeDBInstances.DBInstances {
			if instance.Endpoint != nil {
				name := aws.ToString(instance.DBInstanceIdentifier)
				port := instance.Endpoint.Port
				endpoint := aws.ToString(instance.Endpoint.Address)
				awsService := fmt.Sprintf("RDS")

				if instance.PubliclyAccessible {
					public = "True"
				} else {
					public = "False"
				}

				dataReceiver <- Endpoint{
					AWSService: awsService,
					Region:     r,
					Name:       name,
					Endpoint:   endpoint,
					Port:       port,
					Protocol:   aws.ToString(instance.Engine),
					Public:     public,
				}
			}

		}
		// The "NextToken" value is nil when there's no more data to return.
		if DescribeDBInstances.Marker != nil {
			PaginationControl = DescribeDBInstances.Marker
		} else {
			PaginationControl = nil
			break
		}
	}
}

func (m *EndpointsModule) getRedshiftEndPointsPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Endpoint) {
	defer func() {
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
		wg.Done()

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
	awsService := "Redshift"
	protocol := "https"

	// This for loop exits at the end dependeding on whether the output hits its last page (see pagination control block at the end of the loop).
	for {
		DescribeClusters, err := m.RedshiftClient.DescribeClusters(
			context.TODO(),
			&redshift.DescribeClustersInput{
				Marker: PaginationControl,
			},
			func(o *redshift.Options) {
				o.Region = r
			},
		)
		if err != nil {
			if errors.As(err, &oe) {
				m.Errors = append(m.Errors, (fmt.Sprintf(" Error: Region: %s, Service: %s, Operation: %s", r, oe.Service(), oe.Operation())))
			}
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		var public string
		for _, cluster := range DescribeClusters.Clusters {
			name := aws.ToString(cluster.DBName)
			//id := workspace.Id
			endpoint := aws.ToString(cluster.Endpoint.Address)

			if cluster.PubliclyAccessible {
				public = "True"
			} else {
				public = "False"
			}

			port := cluster.Endpoint.Port

			dataReceiver <- Endpoint{
				AWSService: awsService,
				Region:     r,
				Name:       name,
				Endpoint:   endpoint,
				Port:       port,
				Protocol:   protocol,
				Public:     public,
			}

		}

		// Pagination control. After the last page of output, the for loop exits.
		if DescribeClusters.Marker != nil {
			PaginationControl = DescribeClusters.Marker
		} else {
			PaginationControl = nil
			break
		}
	}

}

func (m *EndpointsModule) getS3EndpointsPerRegion(wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Endpoint) {
	defer func() {
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
		wg.Done()

	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++

	// This for loop exits at the end dependeding on whether the output hits its last page (see pagination control block at the end of the loop).
	ListBuckets, _ := m.S3Client.ListBuckets(
		context.TODO(),
		&s3.ListBucketsInput{},
	)

	var public string
	for _, bucket := range ListBuckets.Buckets {
		name := aws.ToString(bucket.Name)
		endpoint := fmt.Sprintf("https://%s.s3.amazonaws.com", name)
		awsService := "S3"

		var port int32 = 443
		protocol := "https"
		var r string = "Global"
		public = "False"

		GetBucketPolicyStatus, err := m.S3Client.GetBucketPolicyStatus(
			context.TODO(),
			&s3.GetBucketPolicyStatusInput{
				Bucket: &name,
			},
		)

		if err == nil {
			isPublic := GetBucketPolicyStatus.PolicyStatus.IsPublic
			if isPublic {
				public = "True"
			}
		}

		// GetBucketWebsite, err := m.S3Client.GetBucketWebsite(
		// 	context.TODO(),
		// 	&s3.GetBucketWebsiteInput{
		// 		Bucket: &name,
		// 	},
		// )

		// if err != nil {
		// 	index := *GetBucketWebsite.IndexDocument.Suffix
		// 	if index != "" {
		// 		public = "True"
		// 	}

		// }

		dataReceiver <- Endpoint{
			AWSService: awsService,
			Region:     r,
			Name:       name,
			Endpoint:   endpoint,
			Port:       port,
			Protocol:   protocol,
			Public:     public,
		}

	}
}

func (m *EndpointsModule) getCloudfrontEndpoints(wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Endpoint) {
	defer func() {
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
		wg.Done()

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
	var awsService string = "Cloudfront"
	var protocol string = "https"
	var r string = "Global"
	var public string = "True"

	// This for loop exits at the end dependeding on whether the output hits its last page (see pagination control block at the end of the loop).
	for {
		ListDistributions, err := m.CloudfrontClient.ListDistributions(
			context.TODO(),
			&cloudfront.ListDistributionsInput{
				Marker: PaginationControl,
			},
		)
		if err != nil {
			if errors.As(err, &oe) {
				m.Errors = append(m.Errors, (fmt.Sprintf(" Error: Region: %s, Service: %s, Operation: %s", r, oe.Service(), oe.Operation())))
			}
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}
		if ListDistributions.DistributionList.Quantity == nil {
			break
		}
		// var public string
		// var hostnames []string
		// var aliases []string
		// var origins []string

		for _, item := range ListDistributions.DistributionList.Items {
			name := aws.ToString(item.DomainName)
			public = "True"
			var port int32 = 443
			endpoint := fmt.Sprintf("https://%s", aws.ToString(item.DomainName))
			dataReceiver <- Endpoint{
				AWSService: awsService,
				Region:     r,
				Name:       name,
				Endpoint:   endpoint,
				Port:       port,
				Protocol:   protocol,
				Public:     public,
			}
			//fmt.Println(*item.DomainName)
			for _, alias := range item.Aliases.Items {
				//aliases = append(aliases, alias)

				endpoint := fmt.Sprintf("https://%s", alias)
				awsServiceAlias := fmt.Sprintf("%s [alias]", awsService)
				dataReceiver <- Endpoint{
					AWSService: awsServiceAlias,
					Region:     r,
					Name:       name,
					Endpoint:   endpoint,
					Port:       port,
					Protocol:   protocol,
					Public:     public,
				}
			}

			for _, origin := range item.Origins.Items {
				//origins = append(origins, *origin.DomainName)
				//fmt.Println(origin.DomainName)
				public = "Unknown"
				var port int32 = 443
				endpoint := fmt.Sprintf("https://%s/%s", aws.ToString(origin.DomainName), aws.ToString(origin.OriginPath))
				awsServiceOrigin := fmt.Sprintf("%s [origin]", awsService)
				dataReceiver <- Endpoint{
					AWSService: awsServiceOrigin,
					Region:     r,
					Name:       name,
					Endpoint:   endpoint,
					Port:       port,
					Protocol:   protocol,
					Public:     public,
				}
			}

		}

		// port := cluster.Endpoint.Port

		// Pagination control. After the last page of output, the for loop exits.
		if ListDistributions.DistributionList.NextMarker != nil {
			PaginationControl = ListDistributions.DistributionList.NextMarker
		} else {
			PaginationControl = nil
			break
		}
	}
}

func (m *EndpointsModule) getAppRunnerEndpointsPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Endpoint) {
	defer func() {
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
		wg.Done()

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

	var public string = "True"

	for {
		ListServices, err := m.AppRunnerClient.ListServices(
			context.TODO(),
			&(apprunner.ListServicesInput{
				NextToken: PaginationControl,
			}),
			func(o *apprunner.Options) {
				o.Region = r
			},
		)
		if err != nil {
			if errors.As(err, &oe) {
				m.Errors = append(m.Errors, (fmt.Sprintf(" Error: Region: %s, Service: %s, Operation: %s", r, oe.Service(), oe.Operation())))
			}
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}
		if len(ListServices.ServiceSummaryList) > 0 {

			for _, service := range ListServices.ServiceSummaryList {
				name := aws.ToString(service.ServiceName)
				arn := aws.ToString(service.ServiceArn)
				var port int32 = 443
				var protocol string = "https"
				endpoint := fmt.Sprintf("https://%s", aws.ToString(service.ServiceUrl))
				awsService := "App Runner"

				DescribeService, err := m.AppRunnerClient.DescribeService(
					context.TODO(),
					&apprunner.DescribeServiceInput{
						ServiceArn: &arn,
					},
					func(o *apprunner.Options) {
						o.Region = r
					},
				)
				if err != nil {
					if errors.As(err, &oe) {
						m.Errors = append(m.Errors, (fmt.Sprintf(" Error: Region: %s, Service: %s, Operation: %s", r, oe.Service(), oe.Operation())))
					}
					m.modLog.Error(err.Error())
					m.CommandCounter.Error++
					break
				}

				if DescribeService.Service.NetworkConfiguration.EgressConfiguration.EgressType == "DEFAULT" {
					public = "True"
				} else {
					public = "False"
				}

				dataReceiver <- Endpoint{
					AWSService: awsService,
					Region:     r,
					Name:       name,
					Endpoint:   endpoint,
					Port:       port,
					Protocol:   protocol,
					Public:     public,
				}
			}
		}

		// The "NextToken" value is nil when there's no more data to return.
		if ListServices.NextToken != nil {
			PaginationControl = ListServices.NextToken
		} else {
			PaginationControl = nil
			break
		}
	}
}

func (m *EndpointsModule) getLightsailContainerEndpointsPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Endpoint) {
	defer func() {
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
		wg.Done()

	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	var public string = "True"
	var protocol string = "https"
	var port int32 = 443

	GetContainerServices, err := m.LightsailClient.GetContainerServices(
		context.TODO(),
		&(lightsail.GetContainerServicesInput{}),
		func(o *lightsail.Options) {
			o.Region = r
		},
	)
	if err == nil {

		if len(GetContainerServices.ContainerServices) > 0 {

			for _, containerService := range GetContainerServices.ContainerServices {
				name := aws.ToString(containerService.ContainerServiceName)
				//arn := *containerService.Arn
				endpoint := aws.ToString(containerService.Url)
				//endpoint := fmt.Sprintf("https//%s", *service.ServiceUrl)
				awsService := "Lightsail [Container]"

				dataReceiver <- Endpoint{
					AWSService: awsService,
					Region:     r,
					Name:       name,
					Endpoint:   endpoint,
					Port:       port,
					Protocol:   protocol,
					Public:     public,
				}
			}
		}
	}
}
