package aws

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/BishopFox/cloudfox/console"
	"github.com/BishopFox/cloudfox/utils"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/sirupsen/logrus"
)

type ECSTasksModule struct {
	//ECSClient           *ecs.Client
	DescribeTasksClient ecs.DescribeTasksAPIClient
	ListTasksClient     ecs.ListTasksAPIClient
	ListClustersClient  ecs.ListClustersAPIClient
	//EC2Client                       *ec2.Client
	DescribeNetworkInterfacesClient ec2.DescribeNetworkInterfacesAPIClient

	Caller       sts.GetCallerIdentityOutput
	AWSRegions   []string
	OutputFormat string
	AWSProfile   string

	MappedECSTasks []MappedECSTask
	CommandCounter console.CommandCounter

	output utils.OutputData2
	modLog *logrus.Entry
}

type MappedECSTask struct {
	Cluster        string
	TaskDefinition string
	LaunchType     string
	ID             string
	ExternalIP     string
	PrivateIP      string
}

func (m *ECSTasksModule) ECSTasks(outputFormat string, outputDirectory string, verbosity int) {
	m.output.Verbosity = verbosity
	m.output.Directory = outputDirectory
	m.output.CallingModule = "ecs-tasks"
	m.modLog = utils.TxtLog.WithFields(logrus.Fields{
		"module": m.output.CallingModule,
	})
	if m.AWSProfile == "" {
		m.AWSProfile = utils.BuildAWSPath(m.Caller)
	}

	fmt.Printf("[%s][%s] Enumerating ECS tasks in all regions for account %s\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), aws.ToString(m.Caller.Account))

	wg := new(sync.WaitGroup)

	spinnerDone := make(chan bool)
	go console.SpinUntil(m.output.CallingModule, &m.CommandCounter, spinnerDone, "tasks")

	dataReceiver := make(chan MappedECSTask)

	receiverDone := make(chan bool)
	go m.Receiver(dataReceiver, receiverDone)
	for _, region := range m.AWSRegions {
		wg.Add(1)
		m.CommandCounter.Pending++
		go m.executeChecks(region, wg, dataReceiver)

	}

	wg.Wait()
	spinnerDone <- true
	<-spinnerDone
	receiverDone <- true
	<-receiverDone

	m.printECSTaskData(outputFormat, outputDirectory, dataReceiver)

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

func (m *ECSTasksModule) printECSTaskData(outputFormat string, outputDirectory string, dataReceiver chan MappedECSTask) {
	m.output.Headers = []string{
		"Cluster",
		"TaskDefinition",
		"LaunchType",
		"ID",
		"External IP",
		"Internal IP",
	}

	for _, ecsTask := range m.MappedECSTasks {
		m.output.Body = append(
			m.output.Body,
			[]string{
				ecsTask.Cluster,
				ecsTask.TaskDefinition,
				ecsTask.LaunchType,
				ecsTask.ID,
				ecsTask.ExternalIP,
				ecsTask.PrivateIP,
			},
		)
	}
	if len(m.output.Body) > 0 {
		m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", m.AWSProfile)
		utils.OutputSelector(m.output.Verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.CallingModule, m.output.CallingModule)

		m.writeLoot(m.output.FilePath)
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

	fmt.Printf("[%s][%s] Loot written to [%s]\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), privateIPsFilename)
	fmt.Printf("[%s][%s] Loot written to [%s]\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), publicIPsFilename)

}

func (m *ECSTasksModule) executeChecks(r string, wg *sync.WaitGroup, dataReceiver chan MappedECSTask) {
	defer wg.Done()
	m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	m.getListClusters(r, dataReceiver)
	m.CommandCounter.Executing--
	m.CommandCounter.Complete++
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
		mappedTask := MappedECSTask{
			Cluster:        getNameFromARN(clusterARN),
			TaskDefinition: getNameFromARN(aws.ToString(task.TaskDefinitionArn)),
			LaunchType:     string(task.LaunchType),
			ID:             getIDFromECSTask(aws.ToString(task.TaskArn)),
			PrivateIP:      getPrivateIPv4AddressFromECSTask(task),
		}

		eniID := getElasticNetworkInterfaceIDOfECSTask(task)
		if eniID != "" {
			mappedTask.ExternalIP = publicIPs[eniID]
		}

		dataReceiver <- mappedTask
	}
}

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
