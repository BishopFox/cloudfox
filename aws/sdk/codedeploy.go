package sdk

import (
	"context"
	"encoding/gob"
	"fmt"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/service/codedeploy"
	codeDeployTypes "github.com/aws/aws-sdk-go-v2/service/codedeploy/types"
	"github.com/patrickmn/go-cache"
	"github.com/sirupsen/logrus"
)

type AWSCodeDeployClientInterface interface {
	ListApplications(context.Context, *codedeploy.ListApplicationsInput, ...func(*codedeploy.Options)) (*codedeploy.ListApplicationsOutput, error)
	GetApplication(context.Context, *codedeploy.GetApplicationInput, ...func(*codedeploy.Options)) (*codedeploy.GetApplicationOutput, error)
	ListDeployments(context.Context, *codedeploy.ListDeploymentsInput, ...func(*codedeploy.Options)) (*codedeploy.ListDeploymentsOutput, error)
	GetDeployment(context.Context, *codedeploy.GetDeploymentInput, ...func(*codedeploy.Options)) (*codedeploy.GetDeploymentOutput, error)
	ListDeploymentConfigs(context.Context, *codedeploy.ListDeploymentConfigsInput, ...func(*codedeploy.Options)) (*codedeploy.ListDeploymentConfigsOutput, error)
	GetDeploymentConfig(context.Context, *codedeploy.GetDeploymentConfigInput, ...func(*codedeploy.Options)) (*codedeploy.GetDeploymentConfigOutput, error)
}

func init() {
	gob.Register([]string{})
	gob.Register([]codeDeployTypes.ApplicationInfo{})
	gob.Register([]codeDeployTypes.DeploymentConfigInfo{})
	gob.Register([]codeDeployTypes.DeploymentInfo{})

}

func CachedCodeDeployListApplications(client AWSCodeDeployClientInterface, accountID string, region string) ([]string, error) {
	var PaginationControl *string
	var applications []string
	cacheKey := fmt.Sprintf("%s-codedeploy-ListApplications-%s", accountID, region)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.WithFields(logrus.Fields{
			"api":     "codedeploy:ListApplications",
			"account": accountID,
			"region":  region,
			"cache":   "hit",
		}).Info("AWS API call")
		return cached.([]string), nil
	}
	sharedLogger.WithFields(logrus.Fields{
		"api":     "codedeploy:ListApplications",
		"account": accountID,
		"region":  region,
		"cache":   "miss",
	}).Info("AWS API call")
	for {
		ListApplications, err := client.ListApplications(
			context.TODO(),
			&codedeploy.ListApplicationsInput{
				NextToken: PaginationControl,
			},
			func(o *codedeploy.Options) {
				o.Region = region
			},
		)

		if err != nil {
			return applications, err
		}

		applications = append(applications, ListApplications.Applications...)

		//pagination
		if ListApplications.NextToken == nil {
			break
		}
		PaginationControl = ListApplications.NextToken
	}

	internal.Cache.Set(cacheKey, applications, cache.DefaultExpiration)
	return applications, nil
}

func CachedCodeDeployListDeploymentConfigs(client AWSCodeDeployClientInterface, accountID string, region string) ([]string, error) {
	var PaginationControl *string
	var deploymentConfigs []string
	cacheKey := fmt.Sprintf("%s-codedeploy-ListDeploymentConfigs-%s", accountID, region)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.WithFields(logrus.Fields{
			"api":     "codedeploy:ListDeploymentConfigs",
			"account": accountID,
			"region":  region,
			"cache":   "hit",
		}).Info("AWS API call")
		return cached.([]string), nil
	}
	sharedLogger.WithFields(logrus.Fields{
		"api":     "codedeploy:ListDeploymentConfigs",
		"account": accountID,
		"region":  region,
		"cache":   "miss",
	}).Info("AWS API call")
	for {
		ListDeploymentConfigs, err := client.ListDeploymentConfigs(
			context.TODO(),
			&codedeploy.ListDeploymentConfigsInput{
				NextToken: PaginationControl,
			},
			func(o *codedeploy.Options) {
				o.Region = region
			},
		)

		if err != nil {
			return deploymentConfigs, err
		}

		deploymentConfigs = append(deploymentConfigs, ListDeploymentConfigs.DeploymentConfigsList...)

		//pagination
		if ListDeploymentConfigs.NextToken == nil {
			break
		}
		PaginationControl = ListDeploymentConfigs.NextToken
	}

	internal.Cache.Set(cacheKey, deploymentConfigs, cache.DefaultExpiration)
	return deploymentConfigs, nil
}

func CachedCodeDeployListDeployments(client AWSCodeDeployClientInterface, accountID string, region string) ([]string, error) {
	var PaginationControl *string
	var deployments []string
	cacheKey := fmt.Sprintf("%s-codedeploy-ListDeployments-%s", accountID, region)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.WithFields(logrus.Fields{
			"api":     "codedeploy:ListDeployments",
			"account": accountID,
			"region":  region,
			"cache":   "hit",
		}).Info("AWS API call")
		return cached.([]string), nil
	}
	sharedLogger.WithFields(logrus.Fields{
		"api":     "codedeploy:ListDeployments",
		"account": accountID,
		"region":  region,
		"cache":   "miss",
	}).Info("AWS API call")
	for {
		ListDeployments, err := client.ListDeployments(
			context.TODO(),
			&codedeploy.ListDeploymentsInput{
				NextToken: PaginationControl,
			},
			func(o *codedeploy.Options) {
				o.Region = region
			},
		)

		if err != nil {
			return deployments, err
		}

		deployments = append(deployments, ListDeployments.Deployments...)

		//pagination
		if ListDeployments.NextToken == nil {
			break
		}
		PaginationControl = ListDeployments.NextToken
	}

	internal.Cache.Set(cacheKey, deployments, cache.DefaultExpiration)
	return deployments, nil
}

func CachedCodeDeployGetApplication(client AWSCodeDeployClientInterface, accountID string, region string, applicationName string) (codeDeployTypes.ApplicationInfo, error) {
	cacheKey := fmt.Sprintf("%s-codedeploy-GetApplication-%s-%s", accountID, region, applicationName)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.WithFields(logrus.Fields{
			"api":         "codedeploy:GetApplication",
			"account":     accountID,
			"region":      region,
			"application": applicationName,
			"cache":       "hit",
		}).Info("AWS API call")
		return cached.(codeDeployTypes.ApplicationInfo), nil
	}
	sharedLogger.WithFields(logrus.Fields{
		"api":         "codedeploy:GetApplication",
		"account":     accountID,
		"region":      region,
		"application": applicationName,
		"cache":       "miss",
	}).Info("AWS API call")
	GetApplication, err := client.GetApplication(
		context.TODO(),
		&codedeploy.GetApplicationInput{
			ApplicationName: &applicationName,
		},
		func(o *codedeploy.Options) {
			o.Region = region
		},
	)

	if err != nil {
		return *GetApplication.Application, err
	}

	internal.Cache.Set(cacheKey, *GetApplication.Application, cache.DefaultExpiration)

	return *GetApplication.Application, nil
}

func CachedCodeDeployGetDeploymentConfig(client AWSCodeDeployClientInterface, accountID string, region string, deploymentConfigName string) (codeDeployTypes.DeploymentConfigInfo, error) {
	cacheKey := fmt.Sprintf("%s-codedeploy-GetDeploymentConfig-%s-%s", accountID, region, deploymentConfigName)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.WithFields(logrus.Fields{
			"api":            "codedeploy:GetDeploymentConfig",
			"account":        accountID,
			"region":         region,
			"deploymentConfig": deploymentConfigName,
			"cache":          "hit",
		}).Info("AWS API call")
		return cached.(codeDeployTypes.DeploymentConfigInfo), nil
	}
	sharedLogger.WithFields(logrus.Fields{
		"api":            "codedeploy:GetDeploymentConfig",
		"account":        accountID,
		"region":         region,
		"deploymentConfig": deploymentConfigName,
		"cache":          "miss",
	}).Info("AWS API call")
	GetDeploymentConfig, err := client.GetDeploymentConfig(
		context.TODO(),
		&codedeploy.GetDeploymentConfigInput{
			DeploymentConfigName: &deploymentConfigName,
		},
		func(o *codedeploy.Options) {
			o.Region = region
		},
	)

	if err != nil {
		return *GetDeploymentConfig.DeploymentConfigInfo, err
	}

	internal.Cache.Set(cacheKey, *GetDeploymentConfig.DeploymentConfigInfo, cache.DefaultExpiration)

	return *GetDeploymentConfig.DeploymentConfigInfo, nil
}

func CachedCodeDeployGetDeployment(client AWSCodeDeployClientInterface, accountID string, region string, deploymentID string) (codeDeployTypes.DeploymentInfo, error) {
	cacheKey := fmt.Sprintf("%s-codedeploy-GetDeployment-%s-%s", accountID, region, deploymentID)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.WithFields(logrus.Fields{
			"api":        "codedeploy:GetDeployment",
			"account":    accountID,
			"region":     region,
			"deployment": deploymentID,
			"cache":      "hit",
		}).Info("AWS API call")
		return cached.(codeDeployTypes.DeploymentInfo), nil
	}
	sharedLogger.WithFields(logrus.Fields{
		"api":        "codedeploy:GetDeployment",
		"account":    accountID,
		"region":     region,
		"deployment": deploymentID,
		"cache":      "miss",
	}).Info("AWS API call")
	GetDeployment, err := client.GetDeployment(
		context.TODO(),
		&codedeploy.GetDeploymentInput{
			DeploymentId: &deploymentID,
		},
		func(o *codedeploy.Options) {
			o.Region = region
		},
	)

	if err != nil {
		return *GetDeployment.DeploymentInfo, err
	}

	internal.Cache.Set(cacheKey, *GetDeployment.DeploymentInfo, cache.DefaultExpiration)

	return *GetDeployment.DeploymentInfo, nil
}
