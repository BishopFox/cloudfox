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

func init() {
	gob.Register([]lambdaTypes.FunctionConfiguration{})
	gob.Register(customGetFuntionURLOutput{})
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

type customGetFuntionURLOutput struct {
	// The type of authentication that your function URL uses. Set to AWS_IAM if you
	// want to restrict access to authenticated users only. Set to NONE if you want to
	// bypass IAM authentication to create a public endpoint. For more information, see
	// Security and auth model for Lambda function URLs (https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html)
	// .
	//
	// This member is required.
	AuthType lambdaTypes.FunctionUrlAuthType

	// When the function URL was created, in ISO-8601 format (https://www.w3.org/TR/NOTE-datetime)
	// (YYYY-MM-DDThh:mm:ss.sTZD).
	//
	// This member is required.
	CreationTime *string

	// The Amazon Resource Name (ARN) of your function.
	//
	// This member is required.
	FunctionArn *string

	// The HTTP URL endpoint for your function.
	//
	// This member is required.
	FunctionUrl *string

	// When the function URL configuration was last updated, in ISO-8601 format (https://www.w3.org/TR/NOTE-datetime)
	// (YYYY-MM-DDThh:mm:ss.sTZD).
	//
	// This member is required.
	LastModifiedTime *string

	// The cross-origin resource sharing (CORS) (https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
	// settings for your function URL.
	Cors *lambdaTypes.Cors

	// Use one of the following options:
	//   - BUFFERED – This is the default option. Lambda invokes your function using
	//   the Invoke API operation. Invocation results are available when the payload is
	//   complete. The maximum payload size is 6 MB.
	//   - RESPONSE_STREAM – Your function streams payload results as they become
	//   available. Lambda invokes your function using the InvokeWithResponseStream API
	//   operation. The maximum response payload size is 20 MB, however, you can
	//   request a quota increase (https://docs.aws.amazon.com/servicequotas/latest/userguide/request-quota-increase.html)
	//   .
	InvokeMode lambdaTypes.InvokeMode
}

// create a  CachedLambdaGetFunctionUrlConfig function that accepts a lambda client, account id, region, and function name. Make sure it uses go-cache and handles the region option
func CachedLambdaGetFunctionUrlConfig(client LambdaClientInterface, accountID string, region string, functionName string) (customGetFuntionURLOutput, error) {
	var functionUrlConfigOutput customGetFuntionURLOutput
	cacheKey := fmt.Sprintf("%s-lambda-GetFunctionUrlConfig-%s-%s", accountID, region, functionName)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.(customGetFuntionURLOutput), nil
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

	functionUrlConfigOutput = customGetFuntionURLOutput{
		AuthType:         GetFunctionUrlConfig.AuthType,
		CreationTime:     GetFunctionUrlConfig.CreationTime,
		FunctionArn:      GetFunctionUrlConfig.FunctionArn,
		FunctionUrl:      GetFunctionUrlConfig.FunctionUrl,
		LastModifiedTime: GetFunctionUrlConfig.LastModifiedTime,
		Cors:             GetFunctionUrlConfig.Cors,
		InvokeMode:       GetFunctionUrlConfig.InvokeMode,
	}

	internal.Cache.Set(cacheKey, functionUrlConfigOutput, cache.DefaultExpiration)

	return functionUrlConfigOutput, nil
}
