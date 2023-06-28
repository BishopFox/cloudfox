package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/BishopFox/cloudfox/aws/sdk"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/bishopfox/awsservicemap"
	"github.com/sirupsen/logrus"
)

type DescribeTasksDefinitionAPIClient interface {
	DescribeTaskDefinition(context.Context, *ecs.DescribeTaskDefinitionInput, ...func(*ecs.Options)) (*ecs.DescribeTaskDefinitionOutput, error)
}
type ECSTasksModule struct {
	DescribeTaskDefinitionClient    DescribeTasksDefinitionAPIClient
	DescribeTasksClient             ecs.DescribeTasksAPIClient
	ListTasksClient                 ecs.ListTasksAPIClient
	ListClustersClient              ecs.ListClustersAPIClient
	DescribeNetworkInterfacesClient ec2.DescribeNetworkInterfacesAPIClient
	IAMClient                       sdk.AWSIAMClientInterface

	Caller         sts.GetCallerIdentityOutput
	AWSRegions     []string
	OutputFormat   string
	AWSProfile     string
	Goroutines     int
	SkipAdminCheck bool
	WrapTable      bool
	pmapperMod     PmapperModule
	pmapperError   error
	iamSimClient   IamSimulatorModule

	MappedECSTasks []MappedECSTask
	CommandCounter internal.CommandCounter

	output internal.OutputData2
	modLog *logrus.Entry
}

type MappedECSTask struct {
	Cluster               string
	TaskDefinitionName    string
	TaskDefinitionContent string
	LaunchType            string
	ID                    string
	ExternalIP            string
	PrivateIP             string
	Role                  string
	Admin                 string
	CanPrivEsc            string
}

func (m *ECSTasksModule) ECSTasks(outputFormat string, outputDirectory string, verbosity int) {
	m.output.Verbosity = verbosity
	m.output.Directory = outputDirectory
	m.output.CallingModule = "ecs-tasks"
	localAdminMap := make(map[string]bool)
	m.modLog = internal.TxtLog.WithFields(logrus.Fields{
		"module": m.output.CallingModule,
	})
	if m.AWSProfile == "" {
		m.AWSProfile = internal.BuildAWSPath(m.Caller)
	}

	fmt.Printf("[%s][%s] Enumerating ECS tasks in all regions for account %s\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), aws.ToString(m.Caller.Account))
	// Initialized the tools we'll need to check if any workload roles are admin or can privesc to admin
	//fmt.Printf("[%s][%s] Attempting to build a PrivEsc graph in memory using local pmapper data if it exists on the filesystem.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	m.pmapperMod, m.pmapperError = initPmapperGraph(m.Caller, m.AWSProfile, m.Goroutines)
	m.iamSimClient = initIAMSimClient(m.IAMClient, m.Caller, m.AWSProfile, m.Goroutines)

	// if m.pmapperError != nil {
	// 	fmt.Printf("[%s][%s] No pmapper data found for this account. Using cloudfox's iam-simulator for role analysis.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	// } else {
	// 	fmt.Printf("[%s][%s] Found pmapper data for this account. Using it for role analysis.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	// }
	fmt.Printf("[%s][%s] For context and next steps: https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#%s\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), m.output.CallingModule)

	wg := new(sync.WaitGroup)

	spinnerDone := make(chan bool)
	go internal.SpinUntil(m.output.CallingModule, &m.CommandCounter, spinnerDone, "tasks")

	dataReceiver := make(chan MappedECSTask)

	// Create a channel to signal to stop
	receiverDone := make(chan bool)

	go m.Receiver(dataReceiver, receiverDone)

	for _, region := range m.AWSRegions {
		wg.Add(1)
		m.CommandCounter.Pending++
		go m.executeChecks(region, wg, dataReceiver)

	}

	wg.Wait()
	//time.Sleep(time.Second * 2)

	// Perform role analysis
	if m.pmapperError == nil {
		for i := range m.MappedECSTasks {
			m.MappedECSTasks[i].Admin, m.MappedECSTasks[i].CanPrivEsc = GetPmapperResults(m.SkipAdminCheck, m.pmapperMod, &m.MappedECSTasks[i].Role)
		}
	} else {
		for i := range m.MappedECSTasks {
			m.MappedECSTasks[i].Admin, m.MappedECSTasks[i].CanPrivEsc = GetIamSimResult(m.SkipAdminCheck, &m.MappedECSTasks[i].Role, m.iamSimClient, localAdminMap)
		}
	}

	spinnerDone <- true
	<-spinnerDone
	receiverDone <- true
	<-receiverDone

	m.printECSTaskData(outputFormat, outputDirectory, dataReceiver, verbosity)

}

func (m *ECSTasksModule) Receiver(receiver chan MappedECSTask, receiverDone chan bool) {
	defer close(receiverDone)
	for {
		select {
		case data := <-receiver:
			m.MappedECSTasks = append(m.MappedECSTasks, data)
		case <-receiverDone:
			receiverDone <- true
			return
		}
	}
}

func (m *ECSTasksModule) printECSTaskData(outputFormat string, outputDirectory string, dataReceiver chan MappedECSTask, verbosity int) {
	if m.pmapperError == nil {
		m.output.Headers = []string{
			"Cluster",
			"TaskDefinition",
			"LaunchType",
			"ID",
			"External IP",
			"Internal IP",
			"RoleArn",
			"IsAdminRole?",
			"CanPrivEscToAdmin?",
		}
	} else {
		m.output.Headers = []string{
			"Cluster",
			"TaskDefinition",
			"LaunchType",
			"ID",
			"External IP",
			"Internal IP",
			"RoleArn",
			"IsAdminRole?",
			//"CanPrivEscToAdmin?",
		}
	}

	if m.pmapperError == nil {
		for _, ecsTask := range m.MappedECSTasks {
			m.output.Body = append(
				m.output.Body,
				[]string{
					ecsTask.Cluster,
					ecsTask.TaskDefinitionName,
					ecsTask.LaunchType,
					ecsTask.ID,
					ecsTask.ExternalIP,
					ecsTask.PrivateIP,
					ecsTask.Role,
					ecsTask.Admin,
					ecsTask.CanPrivEsc,
				},
			)
		}
	} else {
		for _, ecsTask := range m.MappedECSTasks {
			m.output.Body = append(
				m.output.Body,
				[]string{
					ecsTask.Cluster,
					ecsTask.TaskDefinitionName,
					ecsTask.LaunchType,
					ecsTask.ID,
					ecsTask.ExternalIP,
					ecsTask.PrivateIP,
					ecsTask.Role,
					ecsTask.Admin,
					//ecsTask.CanPrivEsc,
				},
			)
		}
	}

	if len(m.output.Body) > 0 {
		m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", fmt.Sprintf("%s-%s", m.AWSProfile, aws.ToString(m.Caller.Account)))
		//utils.OutputSelector(m.output.Verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.CallingModule, m.output.CallingModule)
		//internal.OutputSelector(m.output.Verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.CallingModule, m.output.CallingModule, m.WrapTable, m.AWSProfile)
		//m.writeLoot(m.output.FilePath)
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
		o.WriteFullOutput(o.Table.TableFiles, nil)
		m.writeLoot(o.Table.DirectoryName)
		fmt.Printf("[%s][%s] %s ECS tasks found.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), strconv.Itoa(len(m.output.Body)))

	} else {
		fmt.Printf("[%s][%s] No ECS tasks found, skipping the creation of an output file.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	}
}

func (m *ECSTasksModule) writeLoot(outputDirectory string) {
	path := filepath.Join(outputDirectory, "loot")
	err := os.MkdirAll(path, os.ModePerm)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
	}
	privateIPsFilename := filepath.Join(path, "ecs-tasks-PrivateIPs.txt")
	publicIPsFilename := filepath.Join(path, "ecs-tasks-PublicIPs.txt")

	var publicIPs string
	var privateIPs string

	for _, task := range m.MappedECSTasks {
		if task.ExternalIP != "NoExternalIP" {
			publicIPs = publicIPs + fmt.Sprintln(task.ExternalIP)
		}
		if task.PrivateIP != "" {
			privateIPs = privateIPs + fmt.Sprintln(task.PrivateIP)
		}

	}
	err = os.WriteFile(privateIPsFilename, []byte(privateIPs), 0644)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
	}
	err = os.WriteFile(publicIPsFilename, []byte(publicIPs), 0644)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
	}

	for _, task := range m.MappedECSTasks {
		if task.TaskDefinitionContent != "" {
			path := filepath.Join(path, "task-definitions")
			err := os.MkdirAll(path, os.ModePerm)
			if err != nil {
				m.modLog.Error(err.Error())
				m.CommandCounter.Error++
			}
			taskDefinitionFilename := filepath.Join(path, task.TaskDefinitionName+".json")

			err = os.WriteFile(taskDefinitionFilename, []byte(task.TaskDefinitionContent), 0644)
			if err != nil {
				m.modLog.Error(err.Error())
				m.CommandCounter.Error++
			}
		}
	}

	fmt.Printf("[%s][%s] Loot written to [%s]\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), privateIPsFilename)
	fmt.Printf("[%s][%s] Loot written to [%s]\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), publicIPsFilename)

}

func (m *ECSTasksModule) executeChecks(r string, wg *sync.WaitGroup, dataReceiver chan MappedECSTask) {
	defer wg.Done()

	servicemap := &awsservicemap.AwsServiceMap{
		JsonFileSource: "DOWNLOAD_FROM_AWS",
	}
	res, err := servicemap.IsServiceInRegion("ecs", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {

		m.CommandCounter.Total++
		m.CommandCounter.Pending--
		m.CommandCounter.Executing++
		m.getListClusters(r, dataReceiver)
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}
}

func (m *ECSTasksModule) getListClusters(region string, dataReceiver chan MappedECSTask) {

	var PaginationControl *string
	for {
		ListClusters, err := m.ListClustersClient.ListClusters(
			context.TODO(),
			&(ecs.ListClustersInput{
				NextToken: PaginationControl,
			}),
			func(o *ecs.Options) {
				o.Region = region
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		for _, clusterARN := range ListClusters.ClusterArns {
			m.getListTasks(clusterARN, region, dataReceiver)
		}

		if ListClusters.NextToken != nil {
			PaginationControl = ListClusters.NextToken
		} else {
			PaginationControl = nil
			break
		}

	}
}

func (m *ECSTasksModule) getListTasks(clusterARN string, region string, dataReceiver chan MappedECSTask) {
	var PaginationControl *string
	for {

		ListTasks, err := m.ListTasksClient.ListTasks(
			context.TODO(),
			&(ecs.ListTasksInput{
				Cluster:   aws.String(clusterARN),
				NextToken: PaginationControl,
			}),
			func(o *ecs.Options) {
				o.Region = region
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		batchSize := 100 // maximum value: https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_DescribeTasks.html#API_DescribeTasks_RequestSyntax
		for i := 0; i < len(ListTasks.TaskArns); i += batchSize {
			j := i + batchSize
			if j > len(ListTasks.TaskArns) {
				j = len(ListTasks.TaskArns)
			}

			m.loadTasksData(clusterARN, ListTasks.TaskArns[i:j], region, dataReceiver)
		}

		if ListTasks.NextToken != nil {
			PaginationControl = ListTasks.NextToken
		} else {
			PaginationControl = nil
			break
		}

	}
}

func (m *ECSTasksModule) loadTasksData(clusterARN string, taskARNs []string, region string, dataReceiver chan MappedECSTask) {

	if len(taskARNs) == 0 {
		return
	}

	DescribeTasks, err := m.DescribeTasksClient.DescribeTasks(
		context.TODO(),
		&(ecs.DescribeTasksInput{
			Cluster: aws.String(clusterARN),
			Tasks:   taskARNs,
		}),
		func(o *ecs.Options) {
			o.Region = region
		},
	)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	eniIDs := []string{}
	for _, task := range DescribeTasks.Tasks {
		eniID := getElasticNetworkInterfaceIDOfECSTask(task)
		if eniID != "" {
			eniIDs = append(eniIDs, eniID)
		}
	}
	publicIPs, err := m.loadPublicIPs(eniIDs, region)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	for _, task := range DescribeTasks.Tasks {
		taskDefinition, err := m.describeTaskDefinition(aws.ToString(task.TaskDefinitionArn), region)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			return
		}
		mappedTask := MappedECSTask{
			Cluster:               getNameFromARN(clusterARN),
			TaskDefinitionName:    getNameFromARN(aws.ToString(task.TaskDefinitionArn)),
			TaskDefinitionContent: getTaskDefinitionContent(taskDefinition),
			LaunchType:            string(task.LaunchType),
			ID:                    getIDFromECSTask(aws.ToString(task.TaskArn)),
			PrivateIP:             getPrivateIPv4AddressFromECSTask(task),
			Role:                  getTaskRole(taskDefinition),
		}

		eniID := getElasticNetworkInterfaceIDOfECSTask(task)
		if eniID != "" {
			mappedTask.ExternalIP = publicIPs[eniID]
		}

		dataReceiver <- mappedTask
	}
}

func getTaskRole(taskDefinition types.TaskDefinition) string {
	return aws.ToString(taskDefinition.TaskRoleArn)
}

func getTaskDefinitionContent(taskDefinition types.TaskDefinition) string {
	// return taskDefinition as a json string

	taskDefinitionContent, err := json.Marshal(taskDefinition)
	if err != nil {
		return ""
	}
	return string(taskDefinitionContent)
}

func (m *ECSTasksModule) describeTaskDefinition(taskDefinitionArn string, region string) (types.TaskDefinition, error) {
	DescribeTaskDefinition, err := m.DescribeTaskDefinitionClient.DescribeTaskDefinition(
		context.TODO(),
		&ecs.DescribeTaskDefinitionInput{
			TaskDefinition: &taskDefinitionArn,
		},
		func(o *ecs.Options) {
			o.Region = region
		},
	)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return types.TaskDefinition{}, err
	}
	return *DescribeTaskDefinition.TaskDefinition, nil
}

/* UNUSED CODE BLOCK - PLEASE REVIEW AND DELETE IF NOT NEEDED
func (m *ECSTasksModule) loadAllPublicIPs(eniIDs []string, region string) (map[string]string, error) {
	eniPublicIPs := make(map[string]string)

	batchSize := 1000 // seems to be maximum value: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeNetworkInterfaces.html
	for i := 0; i < len(eniIDs); i += batchSize {
		j := i + batchSize
		if j > len(eniIDs) {
			j = len(eniIDs)
		}

		publicIPs, err := m.loadPublicIPs(eniIDs[i:j], region)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			return nil, fmt.Errorf("getting elastic network interfaces: %s", err)
		}

		for eniID, publicIP := range publicIPs {
			eniPublicIPs[eniID] = publicIP
		}
	}

	return eniPublicIPs, nil
}
*/

func (m *ECSTasksModule) loadPublicIPs(eniIDs []string, region string) (map[string]string, error) {
	eniPublicIPs := make(map[string]string)

	if len(eniIDs) == 0 {
		return eniPublicIPs, nil
	}
	DescribeNetworkInterfaces, err := m.DescribeNetworkInterfacesClient.DescribeNetworkInterfaces(
		context.TODO(),
		&(ec2.DescribeNetworkInterfacesInput{
			NetworkInterfaceIds: eniIDs,
		}),
		func(o *ec2.Options) {
			o.Region = region
		},
	)
	if err != nil {
		return nil, fmt.Errorf("getting elastic network interfaces: %s", err)
	}

	for _, eni := range DescribeNetworkInterfaces.NetworkInterfaces {
		eniPublicIPs[aws.ToString(eni.NetworkInterfaceId)] = getPublicIPOfElasticNetworkInterface(eni)
	}

	return eniPublicIPs, nil
}

func getNameFromARN(arn string) string {
	tokens := strings.SplitN(arn, "/", 2)
	if len(tokens) != 2 {
		return arn
	}

	return tokens[1]
}

func getIDFromECSTask(arn string) string {
	tokens := strings.SplitN(arn, "/", 3)
	if len(tokens) != 3 {
		return arn
	}

	return tokens[2]
}

func getPrivateIPv4AddressFromECSTask(task types.Task) string {
	ips := []string{}

	for _, attachment := range task.Attachments {
		if aws.ToString(attachment.Type) != "ElasticNetworkInterface" || aws.ToString(attachment.Status) != "ATTACHED" {
			continue
		}

		for _, kvp := range attachment.Details {
			if aws.ToString(kvp.Name) == "privateIPv4Address" {
				ips = append(ips, aws.ToString(kvp.Value))
			}
		}
	}

	return strings.Join(ips, "|")
}

func getElasticNetworkInterfaceIDOfECSTask(task types.Task) string {
	for _, attachment := range task.Attachments {
		if aws.ToString(attachment.Type) != "ElasticNetworkInterface" || aws.ToString(attachment.Status) != "ATTACHED" {
			continue
		}

		for _, kvp := range attachment.Details {
			if aws.ToString(kvp.Name) == "networkInterfaceId" {
				return aws.ToString(kvp.Value)
			}
		}
	}

	return ""
}
