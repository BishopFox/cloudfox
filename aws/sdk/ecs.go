package sdk

import (
	"context"
	"encoding/gob"
	"fmt"
	"strings"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecsTypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/patrickmn/go-cache"
)

type AWSECSClientInterface interface {
	ListClusters(ctx context.Context, params *ecs.ListClustersInput, optFns ...func(*ecs.Options)) (*ecs.ListClustersOutput, error)
	ListTasks(ctx context.Context, params *ecs.ListTasksInput, optFns ...func(*ecs.Options)) (*ecs.ListTasksOutput, error)
	ListServices(ctx context.Context, params *ecs.ListServicesInput, optFns ...func(*ecs.Options)) (*ecs.ListServicesOutput, error)
	DescribeTasks(ctx context.Context, params *ecs.DescribeTasksInput, optFns ...func(*ecs.Options)) (*ecs.DescribeTasksOutput, error)
	DescribeTaskDefinition(ctx context.Context, params *ecs.DescribeTaskDefinitionInput, optFns ...func(*ecs.Options)) (*ecs.DescribeTaskDefinitionOutput, error)
}

func init() {
	gob.Register([]string{})
	gob.Register(ecsTypes.Task{})
	gob.Register([]ecsTypes.Task{})
	gob.Register(ecsTypes.TaskDefinition{})

}

func CachedECSListClusters(ECSClient AWSECSClientInterface, accountID string, region string) ([]string, error) {
	var PaginationControl *string
	var clusters []string
	cacheKey := fmt.Sprintf("%s-ecs-ListClusters-%s", accountID, region)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.Debug("Using cached ECS clusters data")
		return cached.([]string), nil
	}

	for {
		ListClusters, err := ECSClient.ListClusters(
			context.TODO(),
			&ecs.ListClustersInput{
				NextToken: PaginationControl,
			},
			func(o *ecs.Options) {
				o.Region = region
			},
		)
		if err != nil {
			sharedLogger.Error(err.Error())
			break
		}

		clusters = append(clusters, ListClusters.ClusterArns...)

		// Pagination control.
		if ListClusters.NextToken != nil {
			PaginationControl = ListClusters.NextToken
		} else {
			PaginationControl = nil
			break
		}
	}

	internal.Cache.Set(cacheKey, clusters, cache.DefaultExpiration)
	return clusters, nil
}

func CachedECSListTasks(ECSClient AWSECSClientInterface, accountID string, region string, cluster string) ([]string, error) {
	var PaginationControl *string
	var tasks []string
	//grab cluster name from AWS ARN
	clusterName := cluster[strings.LastIndex(cluster, "/")+1:]

	cacheKey := fmt.Sprintf("%s-ecs-ListTasks-%s-%s", accountID, region, clusterName)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.Debug("Using cached ECS tasks data")
		return cached.([]string), nil
	}

	for {
		ListTasks, err := ECSClient.ListTasks(
			context.TODO(),
			&ecs.ListTasksInput{
				Cluster:   &cluster,
				NextToken: PaginationControl,
			},
			func(o *ecs.Options) {
				o.Region = region
			},
		)
		if err != nil {
			sharedLogger.Error(err.Error())
			break
		}

		tasks = append(tasks, ListTasks.TaskArns...)

		// Pagination control.
		if ListTasks.NextToken != nil {
			PaginationControl = ListTasks.NextToken
		} else {
			PaginationControl = nil
			break
		}
	}

	internal.Cache.Set(cacheKey, tasks, cache.DefaultExpiration)
	return tasks, nil
}

func CachedECSDescribeTasks(ECSClient AWSECSClientInterface, accountID string, region string, cluster string, tasks []string) ([]ecsTypes.Task, error) {
	var taskDetails []ecsTypes.Task
	//replace semi-colons with underscores in task definition name
	clusterFileSystemSafe := strings.ReplaceAll(cluster, ":", "_")
	clusterFileSystemSafe = strings.ReplaceAll(clusterFileSystemSafe, "/", "_")
	cacheKey := fmt.Sprintf("%s-ecs-DescribeTasks-%s-%s", accountID, region, clusterFileSystemSafe)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.Debug("Using cached ECS task details data")
		return cached.([]ecsTypes.Task), nil
	}

	DescribeTasks, err := ECSClient.DescribeTasks(
		context.TODO(),
		&ecs.DescribeTasksInput{
			Cluster: &cluster,
			Tasks:   tasks,
		},
		func(o *ecs.Options) {
			o.Region = region
		},
	)
	if err != nil {
		sharedLogger.Error(err.Error())
		return []ecsTypes.Task{}, err
	}

	taskDetails = append(taskDetails, DescribeTasks.Tasks...)

	internal.Cache.Set(cacheKey, taskDetails, cache.DefaultExpiration)
	return taskDetails, nil
}

func CachedECSDescribeTaskDefinition(ECSClient AWSECSClientInterface, accountID string, region string, taskDefinition string) (ecsTypes.TaskDefinition, error) {
	var taskDefinitionDetails ecsTypes.TaskDefinition
	//replace semi-colons with underscores in task definition name
	taskDefinitionFileSystemSafe := strings.ReplaceAll(taskDefinition, ":", "_")
	taskDefinitionFileSystemSafe = strings.ReplaceAll(taskDefinitionFileSystemSafe, "/", "_")
	cacheKey := fmt.Sprintf("%s-ecs-DescribeTaskDefinition-%s-%s", accountID, region, taskDefinitionFileSystemSafe)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.Debug("Using cached ECS task definition details data")
		return cached.(ecsTypes.TaskDefinition), nil
	}

	DescribeTaskDefinition, err := ECSClient.DescribeTaskDefinition(
		context.TODO(),
		&ecs.DescribeTaskDefinitionInput{
			TaskDefinition: &taskDefinition,
		},
		func(o *ecs.Options) {
			o.Region = region
		},
	)
	if err != nil {
		sharedLogger.Error(err.Error())
		return ecsTypes.TaskDefinition{}, err
	}

	taskDefinitionDetails = *DescribeTaskDefinition.TaskDefinition

	internal.Cache.Set(cacheKey, taskDefinitionDetails, cache.DefaultExpiration)
	return taskDefinitionDetails, nil
}

func CachedECSListServices(ECSClient AWSECSClientInterface, accountID string, region string, cluster string) ([]string, error) {
	var PaginationControl *string
	var services []string
	//grab cluster name from AWS ARN
	clusterName := cluster[strings.LastIndex(cluster, "/")+1:]

	cacheKey := fmt.Sprintf("%s-ecs-ListServices-%s-%s", accountID, region, clusterName)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.Debug("Using cached ECS services data")
		return cached.([]string), nil
	}

	for {
		ListServices, err := ECSClient.ListServices(
			context.TODO(),
			&ecs.ListServicesInput{
				Cluster:   &cluster,
				NextToken: PaginationControl,
			},
			func(o *ecs.Options) {
				o.Region = region
			},
		)
		if err != nil {
			sharedLogger.Error(err.Error())
			break
		}

		services = append(services, ListServices.ServiceArns...)

		// Pagination control.
		if ListServices.NextToken != nil {
			PaginationControl = ListServices.NextToken
		} else {
			PaginationControl = nil
			break
		}
	}

	internal.Cache.Set(cacheKey, services, cache.DefaultExpiration)
	return services, nil
}
