package sdk

import (
	"context"
	"encoding/gob"
	"fmt"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/service/bedrockagent"
	bedrockagentTypes "github.com/aws/aws-sdk-go-v2/service/bedrockagent/types"
	"github.com/patrickmn/go-cache"
	"github.com/sirupsen/logrus"
)

type BedrockAgentClientInterface interface {
	ListAgents(context.Context, *bedrockagent.ListAgentsInput, ...func(*bedrockagent.Options)) (*bedrockagent.ListAgentsOutput, error)
	GetAgent(context.Context, *bedrockagent.GetAgentInput, ...func(*bedrockagent.Options)) (*bedrockagent.GetAgentOutput, error)
	ListAgentAliases(context.Context, *bedrockagent.ListAgentAliasesInput, ...func(*bedrockagent.Options)) (*bedrockagent.ListAgentAliasesOutput, error)
	ListAgentActionGroups(context.Context, *bedrockagent.ListAgentActionGroupsInput, ...func(*bedrockagent.Options)) (*bedrockagent.ListAgentActionGroupsOutput, error)
	GetAgentActionGroup(context.Context, *bedrockagent.GetAgentActionGroupInput, ...func(*bedrockagent.Options)) (*bedrockagent.GetAgentActionGroupOutput, error)
	ListAgentCollaborators(context.Context, *bedrockagent.ListAgentCollaboratorsInput, ...func(*bedrockagent.Options)) (*bedrockagent.ListAgentCollaboratorsOutput, error)
	GetAgentCollaborator(context.Context, *bedrockagent.GetAgentCollaboratorInput, ...func(*bedrockagent.Options)) (*bedrockagent.GetAgentCollaboratorOutput, error)
}

func init() {
	gob.Register([]bedrockagentTypes.AgentSummary{})
	gob.Register([]bedrockagentTypes.AgentAliasSummary{})
	gob.Register([]bedrockagentTypes.ActionGroupSummary{})
	gob.Register([]bedrockagentTypes.AgentCollaboratorSummary{})
	gob.Register(bedrockagentTypes.Agent{})
	gob.Register(&bedrockagentTypes.AgentActionGroup{})
	gob.Register(&bedrockagentTypes.ActionGroupExecutorMemberLambda{})
	gob.Register(&bedrockagentTypes.ActionGroupExecutorMemberCustomControl{})
	gob.Register(&bedrockagentTypes.APISchemaMemberPayload{})
	gob.Register(&bedrockagentTypes.APISchemaMemberS3{})
	gob.Register(&bedrockagentTypes.FunctionSchemaMemberFunctions{})
}

func CachedBedrockAgentListAgents(client BedrockAgentClientInterface, accountID string, region string) ([]bedrockagentTypes.AgentSummary, error) {
	var PaginationControl *string
	var agents []bedrockagentTypes.AgentSummary
	cacheKey := fmt.Sprintf("%s-bedrockagent-ListAgents-%s", accountID, region)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.WithFields(logrus.Fields{
			"api":     "bedrockagent:ListAgents",
			"account": accountID,
			"region":  region,
			"cache":   "hit",
		}).Info("AWS API call")
		return cached.([]bedrockagentTypes.AgentSummary), nil
	}
	sharedLogger.WithFields(logrus.Fields{
		"api":     "bedrockagent:ListAgents",
		"account": accountID,
		"region":  region,
		"cache":   "miss",
	}).Info("AWS API call")

	for {
		ListAgents, err := client.ListAgents(
			context.TODO(),
			&bedrockagent.ListAgentsInput{
				NextToken: PaginationControl,
			},
			func(o *bedrockagent.Options) {
				o.Region = region
			},
		)
		if err != nil {
			return agents, err
		}

		agents = append(agents, ListAgents.AgentSummaries...)

		if ListAgents.NextToken == nil {
			break
		}
		PaginationControl = ListAgents.NextToken
	}
	internal.Cache.Set(cacheKey, agents, cache.DefaultExpiration)

	return agents, nil
}

func CachedBedrockAgentListAgentAliases(client BedrockAgentClientInterface, accountID string, region string, agentID string) ([]bedrockagentTypes.AgentAliasSummary, error) {
	var PaginationControl *string
	var aliases []bedrockagentTypes.AgentAliasSummary
	cacheKey := fmt.Sprintf("%s-bedrockagent-ListAgentAliases-%s-%s", accountID, region, agentID)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.WithFields(logrus.Fields{
			"api":     "bedrockagent:ListAgentAliases",
			"account": accountID,
			"region":  region,
			"agent":   agentID,
			"cache":   "hit",
		}).Info("AWS API call")
		return cached.([]bedrockagentTypes.AgentAliasSummary), nil
	}
	sharedLogger.WithFields(logrus.Fields{
		"api":     "bedrockagent:ListAgentAliases",
		"account": accountID,
		"region":  region,
		"agent":   agentID,
		"cache":   "miss",
	}).Info("AWS API call")

	for {
		ListAliases, err := client.ListAgentAliases(
			context.TODO(),
			&bedrockagent.ListAgentAliasesInput{
				AgentId:   &agentID,
				NextToken: PaginationControl,
			},
			func(o *bedrockagent.Options) {
				o.Region = region
			},
		)
		if err != nil {
			return aliases, err
		}

		aliases = append(aliases, ListAliases.AgentAliasSummaries...)

		if ListAliases.NextToken == nil {
			break
		}
		PaginationControl = ListAliases.NextToken
	}
	internal.Cache.Set(cacheKey, aliases, cache.DefaultExpiration)

	return aliases, nil
}

func CachedBedrockAgentListAgentActionGroups(client BedrockAgentClientInterface, accountID string, region string, agentID string, agentVersion string) ([]bedrockagentTypes.ActionGroupSummary, error) {
	var PaginationControl *string
	var actionGroups []bedrockagentTypes.ActionGroupSummary
	cacheKey := fmt.Sprintf("%s-bedrockagent-ListAgentActionGroups-%s-%s", accountID, region, agentID)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.WithFields(logrus.Fields{
			"api":     "bedrockagent:ListAgentActionGroups",
			"account": accountID,
			"region":  region,
			"agent":   agentID,
			"cache":   "hit",
		}).Info("AWS API call")
		return cached.([]bedrockagentTypes.ActionGroupSummary), nil
	}
	sharedLogger.WithFields(logrus.Fields{
		"api":     "bedrockagent:ListAgentActionGroups",
		"account": accountID,
		"region":  region,
		"agent":   agentID,
		"cache":   "miss",
	}).Info("AWS API call")

	for {
		ListActionGroups, err := client.ListAgentActionGroups(
			context.TODO(),
			&bedrockagent.ListAgentActionGroupsInput{
				AgentId:      &agentID,
				AgentVersion: &agentVersion,
				NextToken:    PaginationControl,
			},
			func(o *bedrockagent.Options) {
				o.Region = region
			},
		)
		if err != nil {
			return actionGroups, err
		}

		actionGroups = append(actionGroups, ListActionGroups.ActionGroupSummaries...)

		if ListActionGroups.NextToken == nil {
			break
		}
		PaginationControl = ListActionGroups.NextToken
	}
	internal.Cache.Set(cacheKey, actionGroups, cache.DefaultExpiration)

	return actionGroups, nil
}

func CachedBedrockAgentListAgentCollaborators(client BedrockAgentClientInterface, accountID string, region string, agentID string, agentVersion string) ([]bedrockagentTypes.AgentCollaboratorSummary, error) {
	var PaginationControl *string
	var collaborators []bedrockagentTypes.AgentCollaboratorSummary
	cacheKey := fmt.Sprintf("%s-bedrockagent-ListAgentCollaborators-%s-%s", accountID, region, agentID)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.WithFields(logrus.Fields{
			"api":     "bedrockagent:ListAgentCollaborators",
			"account": accountID,
			"region":  region,
			"agent":   agentID,
			"cache":   "hit",
		}).Info("AWS API call")
		return cached.([]bedrockagentTypes.AgentCollaboratorSummary), nil
	}
	sharedLogger.WithFields(logrus.Fields{
		"api":     "bedrockagent:ListAgentCollaborators",
		"account": accountID,
		"region":  region,
		"agent":   agentID,
		"cache":   "miss",
	}).Info("AWS API call")

	for {
		ListCollaborators, err := client.ListAgentCollaborators(
			context.TODO(),
			&bedrockagent.ListAgentCollaboratorsInput{
				AgentId:      &agentID,
				AgentVersion: &agentVersion,
				NextToken:    PaginationControl,
			},
			func(o *bedrockagent.Options) {
				o.Region = region
			},
		)
		if err != nil {
			return collaborators, err
		}

		collaborators = append(collaborators, ListCollaborators.AgentCollaboratorSummaries...)

		if ListCollaborators.NextToken == nil {
			break
		}
		PaginationControl = ListCollaborators.NextToken
	}
	internal.Cache.Set(cacheKey, collaborators, cache.DefaultExpiration)

	return collaborators, nil
}

func CachedBedrockAgentGetAgent(client BedrockAgentClientInterface, accountID string, region string, agentID string) (bedrockagentTypes.Agent, error) {
	var agent bedrockagentTypes.Agent
	cacheKey := fmt.Sprintf("%s-bedrockagent-GetAgent-%s-%s", accountID, region, agentID)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.WithFields(logrus.Fields{
			"api":     "bedrockagent:GetAgent",
			"account": accountID,
			"region":  region,
			"agent":   agentID,
			"cache":   "hit",
		}).Info("AWS API call")
		return cached.(bedrockagentTypes.Agent), nil
	}
	sharedLogger.WithFields(logrus.Fields{
		"api":     "bedrockagent:GetAgent",
		"account": accountID,
		"region":  region,
		"agent":   agentID,
		"cache":   "miss",
	}).Info("AWS API call")

	resp, err := client.GetAgent(
		context.TODO(),
		&bedrockagent.GetAgentInput{
			AgentId: &agentID,
		},
		func(o *bedrockagent.Options) {
			o.Region = region
		},
	)
	if err != nil {
		return agent, err
	}
	agent = *resp.Agent
	internal.Cache.Set(cacheKey, agent, cache.DefaultExpiration)

	return agent, nil
}

func CachedBedrockAgentGetAgentActionGroup(client BedrockAgentClientInterface, accountID string, region string, agentID string, agentVersion string, actionGroupID string) (*bedrockagentTypes.AgentActionGroup, error) {
	cacheKey := fmt.Sprintf("%s-bedrockagent-GetAgentActionGroup-%s-%s-%s", accountID, region, agentID, actionGroupID)
	cached, found := internal.Cache.Get(cacheKey)
	if found {
		sharedLogger.WithFields(logrus.Fields{
			"api":         "bedrockagent:GetAgentActionGroup",
			"account":     accountID,
			"region":      region,
			"agent":       agentID,
			"actionGroup": actionGroupID,
			"cache":       "hit",
		}).Info("AWS API call")
		return cached.(*bedrockagentTypes.AgentActionGroup), nil
	}
	sharedLogger.WithFields(logrus.Fields{
		"api":         "bedrockagent:GetAgentActionGroup",
		"account":     accountID,
		"region":      region,
		"agent":       agentID,
		"actionGroup": actionGroupID,
		"cache":       "miss",
	}).Info("AWS API call")

	resp, err := client.GetAgentActionGroup(
		context.TODO(),
		&bedrockagent.GetAgentActionGroupInput{
			AgentId:       &agentID,
			AgentVersion:  &agentVersion,
			ActionGroupId: &actionGroupID,
		},
		func(o *bedrockagent.Options) {
			o.Region = region
		},
	)
	if err != nil {
		return nil, err
	}
	internal.Cache.Set(cacheKey, resp.AgentActionGroup, cache.DefaultExpiration)

	return resp.AgentActionGroup, nil
}
