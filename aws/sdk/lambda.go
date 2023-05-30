package sdk

import (
	"context"
	"encoding/gob"
	"fmt"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdaTypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/patrickmn/go-cache"
)

type LambdaClientInterface interface {
	ListFunctions(context.Context, *lambda.ListFunctionsInput, ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error)
	GetFunction(context.Context, *lambda.GetFunctionInput, ...func(*lambda.Options)) (*lambda.GetFunctionOutput, error)
	GetFunctionUrlConfig(context.Context, *lambda.GetFunctionUrlConfigInput, ...func(*lambda.Options)) (*lambda.GetFunctionUrlConfigOutput, error)
}

func RegisterLambdaTypes() {
	gob.Register([]lambdaTypes.FunctionConfiguration{})
	gob.Register(lambda.GetFunctionUrlConfigOutput{})
}

// create a  CachedLambdaListFunctions function that accepts a lambda client, account id, region. Make sure it uses go-cache and handles the region option and pagination
func CachedLambdaListFunctions(client LambdaClientInterface, accountID string, region string) ([]lambdaTypes.FunctionConfiguration, error) {
	var PaginationControl *string
	var functions []lambdaTypes.FunctionConfiguration
	cacheKey := fmt.Sprintf("%s-lambda-ListFunctions-%s", accountID, region)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.([]lambdaTypes.FunctionConfiguration), nil
	}

	for {
		ListFunctions, err := client.ListFunctions(
			context.TODO(),
			&lambda.ListFunctionsInput{
				Marker: PaginationControl,
			},
			func(o *lambda.Options) {
				o.Region = region
			},
		)

		if err != nil {
			return functions, err
		}

		functions = append(functions, ListFunctions.Functions...)

		//pagination
		if ListFunctions.NextMarker == nil {
			break
		}
		PaginationControl = ListFunctions.NextMarker
	}
	internal.Cache.Set(cacheKey, functions, cache.DefaultExpiration)

	return functions, nil
}

// create a  CachedLambdaGetFunctionUrlConfig function that accepts a lambda client, account id, region, and function name. Make sure it uses go-cache and handles the region option
func CachedLambdaGetFunctionUrlConfig(client LambdaClientInterface, accountID string, region string, functionName string) (lambda.GetFunctionUrlConfigOutput, error) {
	var functionUrlConfigOutput lambda.GetFunctionUrlConfigOutput
	cacheKey := fmt.Sprintf("%s-lambda-GetFunctionUrlConfig-%s-%s", accountID, region, functionName)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.(lambda.GetFunctionUrlConfigOutput), nil
	}

	GetFunctionUrlConfig, err := client.GetFunctionUrlConfig(
		context.TODO(),
		&lambda.GetFunctionUrlConfigInput{
			FunctionName: &functionName,
		},
		func(o *lambda.Options) {
			o.Region = region
		},
	)

	if err != nil {
		return functionUrlConfigOutput, err
	}

	functionUrlConfigOutput = *GetFunctionUrlConfig

	internal.Cache.Set(cacheKey, functionUrlConfigOutput, cache.DefaultExpiration)

	return functionUrlConfigOutput, nil
}
