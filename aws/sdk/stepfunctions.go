package sdk

import (
	"context"
	"encoding/gob"
	"fmt"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	sfnTypes "github.com/aws/aws-sdk-go-v2/service/sfn/types"
	"github.com/patrickmn/go-cache"
)

type StepFunctionsClientInterface interface {
	ListStateMachines(context.Context, *sfn.ListStateMachinesInput, ...func(*sfn.Options)) (*sfn.ListStateMachinesOutput, error)
}

func init() {
	gob.Register([]sfnTypes.StateMachineListItem{})
}

func CachedStepFunctionsListStateMachines(client StepFunctionsClientInterface, accountID string, region string) ([]sfnTypes.StateMachineListItem, error) {
	var PaginationControl *string
	var stateMachines []sfnTypes.StateMachineListItem
	cacheKey := fmt.Sprintf("%s-stepfunctions-ListStateMachines-%s", accountID, region)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		return cached.([]sfnTypes.StateMachineListItem), nil
	}
	for {
		ListStateMachines, err := client.ListStateMachines(
			context.TODO(),
			&sfn.ListStateMachinesInput{
				NextToken: PaginationControl,
			},
			func(o *sfn.Options) {
				o.Region = region
			},
		)

		if err != nil {
			return stateMachines, err
		}

		stateMachines = append(stateMachines, ListStateMachines.StateMachines...)

		//pagination
		if ListStateMachines.NextToken == nil {
			break
		}
		PaginationControl = ListStateMachines.NextToken
	}

	internal.Cache.Set(cacheKey, stateMachines, cache.DefaultExpiration)
	return stateMachines, nil
}
