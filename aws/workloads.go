package aws

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/BishopFox/cloudfox/aws/sdk"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamTypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/bishopfox/awsservicemap"
	"github.com/sirupsen/logrus"
)

type WorkloadsModule struct {
	// General configuration data
	Caller         sts.GetCallerIdentityOutput
	AWSRegions     []string
	AWSProfile     string
	AWSOutputType  string
	AWSTableCols   string
	Goroutines     int
	WrapTable      bool
	SkipAdminCheck bool

	// Service Clients
	EC2Client       sdk.AWSEC2ClientInterface
	ECSClient       sdk.AWSECSClientInterface
	LambdaClient    sdk.LambdaClientInterface
	AppRunnerClient sdk.AppRunnerClientInterface
	IAMClient       sdk.AWSIAMClientInterface
	//LightsailClient sdk.MockedLightsailClient
	//SagemakerClient *sagemaker.Client

	pmapperMod          PmapperModule
	pmapperError        error
	PmapperDataBasePath string

	iamSimClient              IamSimulatorModule
	InstanceProfileToRolesMap map[string][]iamTypes.Role

	// Main module data
	Workloads      []Workload
	CommandCounter internal.CommandCounter
	modLog         *logrus.Entry

	// Used to store output data for pretty printing
	output internal.OutputData2
}

type Workload struct {
	AWSService string
	Region     string
	Type       string
	Name       string
	Arn        string
	Role       string
	Admin      string
	CanPrivEsc string
	Public     string
}

func (m *WorkloadsModule) PrintWorkloads(outputDirectory string, verbosity int) {
	// These struct values are used by the output module
	m.output.Verbosity = verbosity
	m.output.Directory = outputDirectory
	m.output.CallingModule = "workloads"
	localAdminMap := make(map[string]bool)
	m.modLog = internal.TxtLog.WithFields(logrus.Fields{
		"module": m.output.CallingModule,
	})
	if m.AWSProfile == "" {
		m.AWSProfile = internal.BuildAWSPath(m.Caller)
	}

	fmt.Printf("[%s][%s] Enumerating compute workloads in all regions for account %s.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), aws.ToString(m.Caller.Account))
	fmt.Printf("[%s][%s] Supported Services: App Runner, EC2, ECS, Lambda \n", cyan(m.output.CallingModule), cyan(m.AWSProfile))

	m.pmapperMod, m.pmapperError = InitPmapperGraph(m.Caller, m.AWSProfile, m.Goroutines, m.PmapperDataBasePath)
	m.iamSimClient = InitIamCommandClient(m.IAMClient, m.Caller, m.AWSProfile, m.Goroutines)

	wg := new(sync.WaitGroup)
	semaphore := make(chan struct{}, m.Goroutines)

	// Create a channel to signal the spinner aka task status goroutine to finish
	spinnerDone := make(chan bool)
	//fire up the the task status spinner/updated
	go internal.SpinUntil(m.output.CallingModule, &m.CommandCounter, spinnerDone, "tasks")

	//create a channel to receive the objects
	dataReceiver := make(chan Workload)

	// Create a channel to signal to stop
	receiverDone := make(chan bool)

	// Create a channel to signal to stop
	go m.Receiver(dataReceiver, receiverDone)

	// Get roles from instance profiles to use for EC2 instance to role lookups
	m.getRolesFromInstanceProfiles()

	for _, region := range m.AWSRegions {
		wg.Add(1)
		m.CommandCounter.Pending++
		go m.executeChecks(region, wg, semaphore, dataReceiver)

	}

	wg.Wait()

	// Perform role analysis
	if m.pmapperError == nil {
		for i := range m.Workloads {
			m.Workloads[i].Admin, m.Workloads[i].CanPrivEsc = GetPmapperResults(m.SkipAdminCheck, m.pmapperMod, &m.Workloads[i].Role)
		}
	} else {
		for i := range m.Workloads {
			m.Workloads[i].Admin, m.Workloads[i].CanPrivEsc = GetIamSimResult(m.SkipAdminCheck, &m.Workloads[i].Role, m.iamSimClient, localAdminMap)
		}
	}

	// Send a message to the spinner goroutine to close the channel and stop
	spinnerDone <- true
	<-spinnerDone
	receiverDone <- true
	<-receiverDone

	// Table headers
	m.output.Headers = []string{
		"Account",
		"Service",
		"Region",
		"Name",
		"Arn",
		"Role",
		"IsAdminRole?",
		"CanPrivEscToAdmin?",
	}

	// If the user specified table columns, use those.
	// If the user specified -o wide, use the wide default cols for this module.
	// Otherwise, use the hardcoded default cols for this module.
	var tableCols []string
	// If the user specified table columns, use those.
	if m.AWSTableCols != "" {
		// If the user specified wide as the output format, use these columns.
		// remove any spaces between any commas and the first letter after the commas
		m.AWSTableCols = strings.ReplaceAll(m.AWSTableCols, ", ", ",")
		m.AWSTableCols = strings.ReplaceAll(m.AWSTableCols, ",  ", ",")
		tableCols = strings.Split(m.AWSTableCols, ",")
	} else if m.AWSOutputType == "wide" {
		tableCols = []string{
			"Account",
			"Service",
			"Region",
			"Arn",
			"Role",
			"IsAdminRole?",
			"CanPrivEscToAdmin?",
		}
		// Otherwise, use the default columns.
	} else {
		tableCols = []string{
			"Service",
			"Region",
			"Name",
			"Role",
			"IsAdminRole?",
			"CanPrivEscToAdmin?",
		}
	}
	// Remove the pmapper row if there is no pmapper data
	if m.pmapperError != nil {
		sharedLogger.Errorf("%s - %s - No pmapper data found for this account. Skipping the pmapper column in the output table.", m.output.CallingModule, m.AWSProfile)
		tableCols = removeStringFromSlice(tableCols, "CanPrivEscToAdmin?")
	}

	sort.Slice(m.Workloads, func(i, j int) bool {
		return m.Workloads[i].AWSService < m.Workloads[j].AWSService
	})

	// Table rows
	for i := range m.Workloads {
		// If the role is an admin or can privesc to admin, make it magenta
		if m.Workloads[i].Admin == "YES" || m.Workloads[i].CanPrivEsc == "YES" {
			m.Workloads[i].AWSService = magenta(m.Workloads[i].AWSService)
			m.Workloads[i].Region = magenta(m.Workloads[i].Region)
			m.Workloads[i].Name = magenta(m.Workloads[i].Name)
			m.Workloads[i].Role = magenta(m.Workloads[i].Role)
			m.Workloads[i].Admin = magenta(m.Workloads[i].Admin)
			m.Workloads[i].CanPrivEsc = magenta(m.Workloads[i].CanPrivEsc)
		}

		m.output.Body = append(
			m.output.Body,
			[]string{
				aws.ToString(m.Caller.Account),
				m.Workloads[i].AWSService,
				m.Workloads[i].Region,
				m.Workloads[i].Name,
				m.Workloads[i].Arn,
				m.Workloads[i].Role,
				m.Workloads[i].Admin,
				m.Workloads[i].CanPrivEsc,
			},
		)

	}
	if len(m.output.Body) > 0 {

		m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", fmt.Sprintf("%s-%s", m.AWSProfile, aws.ToString(m.Caller.Account)))

		o := internal.OutputClient{
			Verbosity:     verbosity,
			CallingModule: m.output.CallingModule,
			Table: internal.TableClient{
				Wrap: m.WrapTable,
			},
		}

		o.PrefixIdentifier = m.AWSProfile
		o.Table.DirectoryName = filepath.Join(outputDirectory, "cloudfox-output", "aws", fmt.Sprintf("%s-%s", m.AWSProfile, aws.ToString(m.Caller.Account)))

		o.Table.TableFiles = append(o.Table.TableFiles, internal.TableFile{
			Header:    m.output.Headers,
			Body:      m.output.Body,
			TableCols: tableCols,
			Name:      m.output.CallingModule,
		})

		// Create another table file that contains only the admin roles or the ones that can privesc to admin. Call another function to do this.

		body := m.adminOnlyResults(m.output.Headers, m.output.Body)
		o.Table.TableFiles = append(o.Table.TableFiles, internal.TableFile{
			Header:            m.output.Headers,
			Body:              body,
			TableCols:         tableCols,
			Name:              fmt.Sprintf("%s-admin", m.output.CallingModule),
			SkipPrintToScreen: true,
		})

		o.WriteFullOutput(o.Table.TableFiles, nil)
		fmt.Printf("[%s][%s] %s compute workloads found.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), strconv.Itoa(len(m.output.Body)))

	} else {
		fmt.Printf("[%s][%s] No compute workloads found, skipping the creation of an output file.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	}
	fmt.Printf("[%s][%s] For context and next steps: https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#%s\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), m.output.CallingModule)
}

func (m *WorkloadsModule) Receiver(receiver chan Workload, receiverDone chan bool) {
	defer close(receiverDone)
	for {
		select {
		case data := <-receiver:
			m.Workloads = append(m.Workloads, data)
		case <-receiverDone:
			receiverDone <- true
			return
		}
	}
}

func (m *WorkloadsModule) executeChecks(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Workload) {
	defer wg.Done()
	servicemap := &awsservicemap.AwsServiceMap{
		JsonFileSource: "DOWNLOAD_FROM_AWS",
	}

	res, _ := servicemap.IsServiceInRegion("ec2", r)
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		go m.getEC2WorkloadsPerRegion(r, wg, semaphore, dataReceiver)
	}

	res, _ = servicemap.IsServiceInRegion("ecs", r)
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		go m.getECSWorkloadsPerRegion(r, wg, semaphore, dataReceiver)
	}

	res, err := servicemap.IsServiceInRegion("lambda", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		go m.getLambdaWorkloadsPerRegion(r, wg, semaphore, dataReceiver)
	}

	// AppRunner is not supported in the aws service region catalog so we have to run it in all regions
	m.CommandCounter.Total++
	wg.Add(1)
	go m.getAppRunnerWorkloadsPerRegion(r, wg, semaphore, dataReceiver)

}

func (m *WorkloadsModule) getEC2WorkloadsPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Workload) {
	defer func() {
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
		wg.Done()

	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()

	// Get EC2 instances
	ec2Instances, err := sdk.CachedEC2DescribeInstances(m.EC2Client, aws.ToString(m.Caller.Account), r)
	if err != nil {
		m.modLog.Error(err)
	}
	for _, instance := range ec2Instances {
		var profileArn, profileName, name string

		// The name is in a tag so we have to do this to grab the value from the right tag
		for _, tag := range instance.Tags {
			if *tag.Key == "Name" {
				name = *tag.Value
			}
		}
		if name == "" {
			name = aws.ToString(instance.InstanceId)
		}

		if instance.IamInstanceProfile != nil {
			profileArn = aws.ToString(instance.IamInstanceProfile.Arn)

			// Extracting instance profile name from ARN
			profileName = strings.Split(profileArn, "/")[len(strings.Split(profileArn, "/"))-1]

			// Describe the IAM instance profile
			profileOutput, err := sdk.CachedIamGetInstanceProfile(m.IAMClient, aws.ToString(m.Caller.Account), profileName)
			if err != nil {
				log.Printf("failed to get instance profile for %s, %v", profileArn, err)
				continue
			}

			for _, role := range profileOutput.Roles {
				dataReceiver <- Workload{
					AWSService: "EC2",
					Region:     r,
					Type:       "instance",
					Name:       name,
					Arn:        fmt.Sprintf("arn:aws:ec2:%s:%s:instance/%s", r, aws.ToString(m.Caller.Account), aws.ToString(instance.InstanceId)),
					Role:       aws.ToString(role.Arn),
				}
			}
		}
	}
}

func (m *WorkloadsModule) getECSWorkloadsPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Workload) {
	defer func() {
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
		wg.Done()

	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()

	// Get ECS clusters
	ecsClusters, err := sdk.CachedECSListClusters(m.ECSClient, aws.ToString(m.Caller.Account), r)
	if err != nil {
		m.modLog.Error(err)
	}
	for _, cluster := range ecsClusters {

		// Get ECS tasks
		taskARNs, err := sdk.CachedECSListTasks(m.ECSClient, aws.ToString(m.Caller.Account), r, cluster)
		if err != nil {
			m.modLog.Error(err)
		}

		Tasks, err := sdk.CachedECSDescribeTasks(m.ECSClient, aws.ToString(m.Caller.Account), r, cluster, taskARNs)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			return
		}

		for _, task := range Tasks {
			var role string
			// Get ECS task definition
			ecsTaskDefinition, err := sdk.CachedECSDescribeTaskDefinition(m.ECSClient, aws.ToString(m.Caller.Account), r, aws.ToString(task.TaskDefinitionArn))
			if err != nil {
				m.modLog.Error(err)
			}
			if ecsTaskDefinition.TaskRoleArn != nil {
				role = aws.ToString(ecsTaskDefinition.TaskRoleArn)
			}

			dataReceiver <- Workload{
				AWSService: "ECS",
				Region:     r,
				Type:       "task",
				Name:       getNameFromARN(aws.ToString(task.TaskDefinitionArn)),
				Arn:        aws.ToString(task.TaskArn),
				Role:       role,
			}
		}
	}
}

func (m *WorkloadsModule) getLambdaWorkloadsPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Workload) {
	defer func() {
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
		wg.Done()

	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()

	// Get Lambda functions
	lambdaFunctions, err := sdk.CachedLambdaListFunctions(m.LambdaClient, aws.ToString(m.Caller.Account), r)
	if err != nil {
		m.modLog.Error(err)
	}
	for _, function := range lambdaFunctions {
		//var role string
		// if function.Role != nil {
		// 	role = aws.ToString(function.Role)
		// }
		dataReceiver <- Workload{
			AWSService: "Lambda",
			Region:     r,
			Type:       "function",
			Name:       aws.ToString(function.FunctionName),
			Arn:        aws.ToString(function.FunctionArn),
			Role:       aws.ToString(function.Role),
		}
	}
}

func (m *WorkloadsModule) getAppRunnerWorkloadsPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Workload) {
	defer func() {
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
		wg.Done()

	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()

	// Get App Runner services
	appRunnerServices, err := sdk.CachedAppRunnerListServices(m.AppRunnerClient, aws.ToString(m.Caller.Account), r)
	if err != nil {
		m.modLog.Error(err)
	}
	for _, service := range appRunnerServices {
		var role string
		if service.ServiceArn != nil {
			role = aws.ToString(service.ServiceArn)
		}
		dataReceiver <- Workload{
			AWSService: "App Runner",
			Region:     r,
			Type:       "service",
			Name:       aws.ToString(service.ServiceName),
			Arn:        aws.ToString(service.ServiceArn),
			Role:       role,
		}
	}
}

func (m *WorkloadsModule) adminOnlyResults(headers []string, body [][]string) [][]string {
	var adminOnlyBody [][]string
	var adminOnlyHeaders []string
	var adminOnlyTableCols []string
	var adminColIndex int
	var canPrivEscColIndex int

	// First find which col is the admin col and which is the can privesc col and simply note which index they are in. Then we can use those indexes to see if the value in the body is "YES".
	// For any row where isAdmin or CanPrivEsc is "YES", we will append that row to the adminOnlyBody.

	// Find the index of the admin col
	for i, header := range headers {
		if header == "IsAdminRole?" {
			adminOnlyHeaders = append(adminOnlyHeaders, header)
			adminOnlyTableCols = append(adminOnlyTableCols, header)
			adminColIndex = i
		}
	}

	// Find the index of the can privesc col
	for i, header := range headers {
		if header == "CanPrivEscToAdmin?" {
			adminOnlyHeaders = append(adminOnlyHeaders, header)
			adminOnlyTableCols = append(adminOnlyTableCols, header)
			canPrivEscColIndex = i
		}
	}

	// Now that we have the indexes of the admin and can privesc cols, we can iterate through the body and append the rows where isAdmin or CanPrivEsc is "YES" to the adminOnlyBody
	for _, row := range body {
		if row[adminColIndex] == "YES" || row[canPrivEscColIndex] == "YES" {
			adminOnlyBody = append(adminOnlyBody, row)
		}
	}

	return adminOnlyBody
}

func (m *WorkloadsModule) getRolesFromInstanceProfiles() {

	// The "PaginationControl" value is nil when there's no more data to return.
	var PaginationMarker *string
	PaginationControl := true
	m.InstanceProfileToRolesMap = map[string][]iamTypes.Role{}

	for PaginationControl {
		ListInstanceProfiles, err := m.IAMClient.ListInstanceProfiles(
			context.TODO(),
			&(iam.ListInstanceProfilesInput{
				Marker: PaginationMarker,
			}),
		)

		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}
		for _, instanceProfile := range ListInstanceProfiles.InstanceProfiles {
			m.InstanceProfileToRolesMap[aws.ToString(instanceProfile.InstanceProfileId)] = instanceProfile.Roles
		}
		if aws.ToString(ListInstanceProfiles.Marker) != "" {
			PaginationMarker = ListInstanceProfiles.Marker
		} else {
			PaginationMarker = nil
			break
		}
	}

}
