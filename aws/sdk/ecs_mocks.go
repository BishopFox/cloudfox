package sdk

import (
	"context"
	"encoding/json"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecsTypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
)

const DESCRIBE_TASKS_TEST_FILE = "./test-data/describe-tasks.json"

type MockedECSClient struct {
	describeTasks DescribeTasks
}

type ListTasks struct {
	TaskArns []string `json:"taskArns"`
}

type DescribeTasks struct {
	Tasks []struct {
		Attachments []struct {
			ID      string `json:"id"`
			Type    string `json:"type"`
			Status  string `json:"status"`
			Details []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"details"`
		} `json:"attachments"`
		Attributes []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"attributes"`
		AvailabilityZone string `json:"availabilityZone"`
		ClusterArn       string `json:"clusterArn"`
		Connectivity     string `json:"connectivity"`
		ConnectivityAt   string `json:"connectivityAt"`
		Containers       []struct {
			ContainerArn      string        `json:"containerArn"`
			TaskArn           string        `json:"taskArn"`
			Name              string        `json:"name"`
			Image             string        `json:"image"`
			RuntimeID         string        `json:"runtimeId"`
			LastStatus        string        `json:"lastStatus"`
			NetworkBindings   []interface{} `json:"networkBindings"`
			NetworkInterfaces []struct {
				AttachmentID       string `json:"attachmentId"`
				PrivateIpv4Address string `json:"privateIpv4Address"`
			} `json:"networkInterfaces"`
			HealthStatus string `json:"healthStatus"`
			CPU          string `json:"cpu"`
			Memory       string `json:"memory"`
		} `json:"containers"`
		CPU                  string `json:"cpu"`
		CreatedAt            string `json:"createdAt"`
		DesiredStatus        string `json:"desiredStatus"`
		EnableExecuteCommand bool   `json:"enableExecuteCommand"`
		Group                string `json:"group"`
		HealthStatus         string `json:"healthStatus"`
		LastStatus           string `json:"lastStatus"`
		LaunchType           string `json:"launchType"`
		Memory               string `json:"memory"`
		Overrides            struct {
			ContainerOverrides []struct {
				Name string `json:"name"`
			} `json:"containerOverrides"`
			InferenceAcceleratorOverrides []interface{} `json:"inferenceAcceleratorOverrides"`
		} `json:"overrides"`
		PlatformVersion   string        `json:"platformVersion"`
		PlatformFamily    string        `json:"platformFamily"`
		PullStartedAt     string        `json:"pullStartedAt"`
		PullStoppedAt     string        `json:"pullStoppedAt"`
		StartedAt         string        `json:"startedAt"`
		StartedBy         string        `json:"startedBy"`
		Tags              []interface{} `json:"tags"`
		TaskArn           string        `json:"taskArn"`
		TaskDefinitionArn string        `json:"taskDefinitionArn"`
		Version           int           `json:"version"`
		EphemeralStorage  struct {
			SizeInGiB int `json:"sizeInGiB"`
		} `json:"ephemeralStorage"`
	} `json:"tasks"`
	Failures []interface{} `json:"failures"`
}

func (c *MockedECSClient) ListClusters(context.Context, *ecs.ListClustersInput, ...func(*ecs.Options)) (*ecs.ListClustersOutput, error) {
	return &ecs.ListClustersOutput{ClusterArns: []string{
		"arn:aws:ecs:us-east-1:123456789012:cluster/MyCluster",
		"arn:aws:ecs:us-east-1:123456789012:cluster/MyCluster2",
		"arn:aws:ecs:us-east-1:123456789012:cluster/MyCluster3",
	}}, nil
}

func (c *MockedECSClient) ListTasks(ctx context.Context, input *ecs.ListTasksInput, f ...func(*ecs.Options)) (*ecs.ListTasksOutput, error) {
	return &ecs.ListTasksOutput{TaskArns: []string{
		"arn:aws:ecs:us-east-1:123456789012:task/MyCluster/74de0355a10a4f979ac495c14EXAMPLE",
		"arn:aws:ecs:us-east-1:123456789012:task/MyCluster/d789e94343414c25b9f6bd59eEXAMPLE",
	}}, nil
}

func (c *MockedECSClient) ListServices(ctx context.Context, input *ecs.ListServicesInput, f ...func(*ecs.Options)) (*ecs.ListServicesOutput, error) {
	return &ecs.ListServicesOutput{ServiceArns: []string{
		"arn:aws:ecs:us-east-1:123456789012:service/MyService",
		"arn:aws:ecs:us-east-1:123456789012:service/MyService2",
		"arn:aws:ecs:us-east-1:123456789012:service/MyService3",
	}}, nil
}

func (c *MockedECSClient) DescribeTasks(ctx context.Context, input *ecs.DescribeTasksInput, f ...func(*ecs.Options)) (*ecs.DescribeTasksOutput, error) {
	err := json.Unmarshal(readTestFile(DESCRIBE_TASKS_TEST_FILE), &c.describeTasks)
	if err != nil {
		log.Fatalf("can't unmarshall file %s", DESCRIBE_TASKS_TEST_FILE)
	}
	var tasks []ecsTypes.Task
	for _, mockedTask := range c.describeTasks.Tasks {
		if mockedTask.ClusterArn == aws.ToString(input.Cluster) {
			for _, inputTask := range input.Tasks {
				if mockedTask.TaskArn == inputTask {
					var attachments []ecsTypes.Attachment
					for _, a := range mockedTask.Attachments {
						var deets []ecsTypes.KeyValuePair
						for _, detail := range a.Details {
							deets = append(deets, ecsTypes.KeyValuePair{
								Name:  aws.String(detail.Name),
								Value: aws.String(detail.Value)})
						}
						attachments = append(attachments, ecsTypes.Attachment{
							Type:    aws.String(a.Type),
							Details: deets,
							Id:      aws.String(a.ID),
							Status:  aws.String(a.Status),
						})
					}

					var containers []ecsTypes.Container

					for _, container := range mockedTask.Containers {
						containers = append(containers, ecsTypes.Container{
							ContainerArn: aws.String(container.ContainerArn),
							Cpu:          aws.String(container.CPU),
							HealthStatus: ecsTypes.HealthStatus(container.HealthStatus),
							Image:        aws.String(container.Image),
							LastStatus:   aws.String(container.LastStatus),
							Memory:       aws.String(container.Memory),
							Name:         aws.String(container.Name),
							RuntimeId:    aws.String(container.RuntimeID),
							TaskArn:      aws.String(container.TaskArn),
						})
					}

					tasks = append(tasks, ecsTypes.Task{
						ClusterArn:        aws.String(mockedTask.ClusterArn),
						TaskDefinitionArn: aws.String(mockedTask.TaskDefinitionArn),
						LaunchType:        ecsTypes.LaunchType(*aws.String(mockedTask.LaunchType)),
						TaskArn:           aws.String(mockedTask.TaskArn),
						Attachments:       attachments,
						Containers:        containers,
					})
				}
			}
		}
	}
	return &ecs.DescribeTasksOutput{Tasks: tasks}, nil
}

func (c *MockedECSClient) DescribeTaskDefinition(ctx context.Context, input *ecs.DescribeTaskDefinitionInput, f ...func(o *ecs.Options)) (*ecs.DescribeTaskDefinitionOutput, error) {
	testTaskDefinition := ecsTypes.TaskDefinition{}
	testTaskDefinition.TaskRoleArn = aws.String("test123")
	return &ecs.DescribeTaskDefinitionOutput{TaskDefinition: &testTaskDefinition}, nil
}
