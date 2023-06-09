package sdk

import (
	"context"
	"encoding/gob"
	"fmt"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cloudFormationTypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/patrickmn/go-cache"
)

type CloudFormationClientInterface interface {
	GetTemplate(context.Context, *cloudformation.GetTemplateInput, ...func(*cloudformation.Options)) (*cloudformation.GetTemplateOutput, error)
	DescribeStacks(context.Context, *cloudformation.DescribeStacksInput, ...func(*cloudformation.Options)) (*cloudformation.DescribeStacksOutput, error)
	ListStacks(context.Context, *cloudformation.ListStacksInput, ...func(*cloudformation.Options)) (*cloudformation.ListStacksOutput, error)
}

func RegisterCloudFormationTypes() {
	gob.Register([]cloudFormationTypes.Stack{})
	gob.Register([]cloudFormationTypes.StackSummary{})
}

func CachedCloudFormationDescribeStacks(client CloudFormationClientInterface, accountID string, region string) ([]cloudFormationTypes.Stack, error) {
	var PaginationControl *string
	var stacks []cloudFormationTypes.Stack
	cacheKey := fmt.Sprintf("%s-cloudformation-DescribeStacks-%s", accountID, region)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.([]cloudFormationTypes.Stack), nil
	}
	for {
		DescribeStacks, err := client.DescribeStacks(
			context.TODO(),
			&cloudformation.DescribeStacksInput{
				NextToken: PaginationControl,
			},
			func(o *cloudformation.Options) {
				o.Region = region
			},
		)

		if err != nil {
			return stacks, err
		}

		stacks = append(stacks, DescribeStacks.Stacks...)
		//pagination
		if DescribeStacks.NextToken == nil {
			break
		}
		PaginationControl = DescribeStacks.NextToken
	}

	internal.Cache.Set(cacheKey, stacks, cache.DefaultExpiration)
	return stacks, nil
}

func CachedCloudFormationGetTemplate(client CloudFormationClientInterface, accountID string, region string, stackName string) (string, error) {
	var stackTemplateBody string
	cacheKey := fmt.Sprintf("%s-cloudformation-GetTemplate-%s-%s", accountID, region, stackName)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.(string), nil
	}

	GetTemplate, err := client.GetTemplate(
		context.TODO(),
		&cloudformation.GetTemplateInput{
			StackName: &stackName,
		}, func(o *cloudformation.Options) {
			o.Region = region
		},
	)

	if err != nil {
		return stackTemplateBody, err
	}
	stackTemplateBody = aws.ToString(GetTemplate.TemplateBody)
	internal.Cache.Set(cacheKey, *GetTemplate.TemplateBody, cache.DefaultExpiration)
	return stackTemplateBody, nil
}

func CachedCloudFormationListStacks(client CloudFormationClientInterface, accountID string, region string) ([]cloudFormationTypes.StackSummary, error) {
	var PaginationControl *string
	var stacks []cloudFormationTypes.StackSummary
	cacheKey := fmt.Sprintf("%s-cloudformation-ListStacks-%s", accountID, region)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.([]cloudFormationTypes.StackSummary), nil
	}
	for {
		ListStacks, err := client.ListStacks(
			context.TODO(),
			&cloudformation.ListStacksInput{
				NextToken: PaginationControl,
			},
			func(o *cloudformation.Options) {
				o.Region = region
			},
		)

		if err != nil {
			return stacks, err
		}

		stacks = append(stacks, ListStacks.StackSummaries...)
		//pagination
		if ListStacks.NextToken == nil {
			break
		}
		PaginationControl = ListStacks.NextToken
	}

	internal.Cache.Set(cacheKey, stacks, cache.DefaultExpiration)
	return stacks, nil
}
