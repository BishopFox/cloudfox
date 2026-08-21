package aws

import (
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
	bedrockagentTypes "github.com/aws/aws-sdk-go-v2/service/bedrockagent/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/bishopfox/awsservicemap"
	"github.com/sirupsen/logrus"
)

type BedrockAgentsModule struct {
	BedrockAgentClient sdk.BedrockAgentClientInterface

	Caller        sts.GetCallerIdentityOutput
	AWSRegions    []string
	AWSProfile    string
	Goroutines    int
	WrapTable     bool
	AWSOutputType string
	AWSTableCols  string
	ServiceMap    *awsservicemap.AwsServiceMap

	Agents         []BedrockAgent
	CommandCounter internal.CommandCounter
	output         internal.OutputData2
	modLog         *logrus.Entry
}

type BedrockAgent struct {
	Region             string
	Name               string
	AgentId            string
	AgentArn           string
	Status             string
	FoundationModel    string
	RoleArn            string
	Instruction        string
	ActionGroups       int
	Collaborators      int
	Aliases            int
	MemoryEnabled      string
	GuardrailId        string
	IdleSessionTTL     int32
	LatestVersion      string
	ActionGroupDetails []BedrockActionGroupDetail
}

type BedrockActionGroupDetail struct {
	Name        string
	Id          string
	Description string
	ExecutorType string
	ExecutorArn  string
	ApiSchema    string
	Functions    []BedrockActionGroupFunction
}

type BedrockActionGroupFunction struct {
	Name        string
	Description string
	Parameters  map[string]string
}

func (m *BedrockAgentsModule) PrintBedrockAgents(outputDirectory string, verbosity int) {
	m.output.Verbosity = verbosity
	m.output.Directory = outputDirectory
	m.output.CallingModule = "bedrock-agents"
	m.modLog = internal.TxtLog.WithFields(logrus.Fields{
		"module": m.output.CallingModule,
	})
	if m.AWSProfile == "" {
		m.AWSProfile = internal.BuildAWSPath(m.Caller)
	}

	fmt.Printf("[%s][%s] Enumerating Bedrock agents for account %s.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), aws.ToString(m.Caller.Account))

	wg := new(sync.WaitGroup)
	semaphore := make(chan struct{}, m.Goroutines)

	spinnerDone := make(chan bool)
	go internal.SpinUntil(m.output.CallingModule, &m.CommandCounter, spinnerDone, "regions")

	dataReceiver := make(chan BedrockAgent)
	receiverDone := make(chan bool)
	go m.Receiver(dataReceiver, receiverDone)

	for _, region := range m.AWSRegions {
		wg.Add(1)
		m.CommandCounter.IncrPending()
		go m.executeChecks(region, wg, semaphore, dataReceiver)
	}
	wg.Wait()

	spinnerDone <- true
	<-spinnerDone
	receiverDone <- true
	<-receiverDone

	m.output.Headers = []string{
		"Account",
		"Region",
		"Name",
		"AgentId",
		"Status",
		"FoundationModel",
		"RoleArn",
		"ActionGroups",
		"Collaborators",
		"AgentArn",
		"IdleSessionTTL",
		"Aliases",
		"MemoryEnabled",
		"GuardrailId",
	}

	var tableCols []string
	if m.AWSTableCols != "" {
		m.AWSTableCols = strings.ReplaceAll(m.AWSTableCols, ", ", ",")
		m.AWSTableCols = strings.ReplaceAll(m.AWSTableCols, ",  ", ",")
		tableCols = strings.Split(m.AWSTableCols, ",")
	} else if m.AWSOutputType == "wide" {
		tableCols = []string{
			"Account",
			"Region",
			"Name",
			"Status",
			"FoundationModel",
			"RoleArn",
			"ActionGroups",
			"Collaborators",
			"AgentArn",
			"IdleSessionTTL",
			"Aliases",
			"MemoryEnabled",
			"GuardrailId",
		}
	} else {
		tableCols = []string{
			"Account",
			"Region",
			"Name",
			"Status",
			"FoundationModel",
			"RoleArn",
			"ActionGroups",
			"Collaborators",
		}
	}

	for _, agent := range m.Agents {
		m.output.Body = append(
			m.output.Body,
			[]string{
				aws.ToString(m.Caller.Account),
				agent.Region,
				agent.Name,
				agent.AgentId,
				agent.Status,
				agent.FoundationModel,
				agent.RoleArn,
				strconv.Itoa(agent.ActionGroups),
				strconv.Itoa(agent.Collaborators),
				agent.AgentArn,
				strconv.Itoa(int(agent.IdleSessionTTL)),
				strconv.Itoa(agent.Aliases),
				agent.MemoryEnabled,
				agent.GuardrailId,
			},
		)
	}

	if len(m.output.Body) > 0 {
		m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", fmt.Sprintf("%s-%s", m.AWSProfile, aws.ToString(m.Caller.Account)))
		o := internal.OutputClient{
			Verbosity:     verbosity,
			CallingModule: m.output.CallingModule,
			Table: internal.TableClient{
				Wrap: m.WrapTable,
			},
		}
		o.Table.TableFiles = append(o.Table.TableFiles, internal.TableFile{
			Header:    m.output.Headers,
			Body:      m.output.Body,
			TableCols: tableCols,
			Name:      m.output.CallingModule,
		})
		o.PrefixIdentifier = m.AWSProfile
		o.Table.DirectoryName = filepath.Join(outputDirectory, "cloudfox-output", "aws", fmt.Sprintf("%s-%s", m.AWSProfile, aws.ToString(m.Caller.Account)))
		o.WriteFullOutput(o.Table.TableFiles, nil)
		m.writeLoot(o.Table.DirectoryName, verbosity)
		fmt.Printf("[%s][%s] %s Bedrock agents found.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), strconv.Itoa(len(m.output.Body)))
	} else {
		fmt.Printf("[%s][%s] No Bedrock agents found, skipping the creation of an output file.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	}
	fmt.Printf("[%s][%s] For context and next steps: https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#%s\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), m.output.CallingModule)
}

func (m *BedrockAgentsModule) executeChecks(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan BedrockAgent) {
	defer wg.Done()

	servicemap := m.ServiceMap
	if servicemap == nil {
		servicemap = &awsservicemap.AwsServiceMap{
			JsonFileSource: "DOWNLOAD_FROM_AWS",
		}
	}
	res, err := servicemap.IsServiceInRegion("bedrock", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.IncrTotal()
		wg.Add(1)
		m.getBedrockAgentsPerRegion(r, wg, semaphore, dataReceiver)
	}
}

func (m *BedrockAgentsModule) Receiver(receiver chan BedrockAgent, receiverDone chan bool) {
	defer close(receiverDone)
	for {
		select {
		case data := <-receiver:
			m.Agents = append(m.Agents, data)
		case <-receiverDone:
			receiverDone <- true
			return
		}
	}
}

func (m *BedrockAgentsModule) getBedrockAgentsPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan BedrockAgent) {
	defer func() {
		m.CommandCounter.DecrExecuting()
		m.CommandCounter.IncrComplete()
		wg.Done()
	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()

	agents, err := sdk.CachedBedrockAgentListAgents(m.BedrockAgentClient, aws.ToString(m.Caller.Account), r)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.IncrError()
		return
	}

	for _, agentSummary := range agents {
		agentID := aws.ToString(agentSummary.AgentId)
		agentVersion := aws.ToString(agentSummary.LatestAgentVersion)
		if agentVersion == "" {
			agentVersion = "DRAFT"
		}

		agent, err := sdk.CachedBedrockAgentGetAgent(m.BedrockAgentClient, aws.ToString(m.Caller.Account), r, agentID)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.IncrError()
			continue
		}

		aliases, _ := sdk.CachedBedrockAgentListAgentAliases(m.BedrockAgentClient, aws.ToString(m.Caller.Account), r, agentID)
		actionGroupSummaries, _ := sdk.CachedBedrockAgentListAgentActionGroups(m.BedrockAgentClient, aws.ToString(m.Caller.Account), r, agentID, agentVersion)
		collaborators, _ := sdk.CachedBedrockAgentListAgentCollaborators(m.BedrockAgentClient, aws.ToString(m.Caller.Account), r, agentID, agentVersion)

		var actionGroupDetails []BedrockActionGroupDetail
		for _, agSummary := range actionGroupSummaries {
			agDetail := m.getActionGroupDetail(r, agentID, agentVersion, agSummary)
			actionGroupDetails = append(actionGroupDetails, agDetail)
		}

		memoryEnabled := "No"
		if agent.MemoryConfiguration != nil && len(agent.MemoryConfiguration.EnabledMemoryTypes) > 0 {
			memoryEnabled = "Yes"
		}

		guardrailId := ""
		if agent.GuardrailConfiguration != nil {
			guardrailId = aws.ToString(agent.GuardrailConfiguration.GuardrailIdentifier)
		}

		var idleSessionTTL int32
		if agent.IdleSessionTTLInSeconds != nil {
			idleSessionTTL = *agent.IdleSessionTTLInSeconds
		}

		dataReceiver <- BedrockAgent{
			Region:             r,
			Name:               aws.ToString(agent.AgentName),
			AgentId:            agentID,
			AgentArn:           aws.ToString(agent.AgentArn),
			Status:             string(agent.AgentStatus),
			FoundationModel:    aws.ToString(agent.FoundationModel),
			RoleArn:            aws.ToString(agent.AgentResourceRoleArn),
			Instruction:        aws.ToString(agent.Instruction),
			ActionGroups:       len(actionGroupSummaries),
			Collaborators:      len(collaborators),
			Aliases:            len(aliases),
			MemoryEnabled:      memoryEnabled,
			GuardrailId:        guardrailId,
			IdleSessionTTL:     idleSessionTTL,
			LatestVersion:      agentVersion,
			ActionGroupDetails: actionGroupDetails,
		}
	}
}

func (m *BedrockAgentsModule) getActionGroupDetail(region string, agentID string, agentVersion string, summary bedrockagentTypes.ActionGroupSummary) BedrockActionGroupDetail {
	agID := aws.ToString(summary.ActionGroupId)
	detail := BedrockActionGroupDetail{
		Name: aws.ToString(summary.ActionGroupName),
		Id:   agID,
	}

	ag, err := sdk.CachedBedrockAgentGetAgentActionGroup(m.BedrockAgentClient, aws.ToString(m.Caller.Account), region, agentID, agentVersion, agID)
	if err != nil {
		m.modLog.Error(err.Error())
		return detail
	}
	detail.Description = aws.ToString(ag.Description)

	switch v := ag.ActionGroupExecutor.(type) {
	case *bedrockagentTypes.ActionGroupExecutorMemberLambda:
		detail.ExecutorType = "Lambda"
		detail.ExecutorArn = v.Value
	case *bedrockagentTypes.ActionGroupExecutorMemberCustomControl:
		detail.ExecutorType = "ReturnControl"
	}

	switch v := ag.ApiSchema.(type) {
	case *bedrockagentTypes.APISchemaMemberPayload:
		detail.ApiSchema = v.Value
	case *bedrockagentTypes.APISchemaMemberS3:
		detail.ApiSchema = fmt.Sprintf("s3://%s/%s", aws.ToString(v.Value.S3BucketName), aws.ToString(v.Value.S3ObjectKey))
	}

	switch v := ag.FunctionSchema.(type) {
	case *bedrockagentTypes.FunctionSchemaMemberFunctions:
		for _, fn := range v.Value {
			f := BedrockActionGroupFunction{
				Name:        aws.ToString(fn.Name),
				Description: aws.ToString(fn.Description),
				Parameters:  make(map[string]string),
			}
			for paramName, paramDetail := range fn.Parameters {
				required := ""
				if paramDetail.Required != nil && *paramDetail.Required {
					required = ",required"
				}
				f.Parameters[paramName] = fmt.Sprintf("%s%s", paramDetail.Type, required)
			}
			detail.Functions = append(detail.Functions, f)
		}
	}

	return detail
}

func (m *BedrockAgentsModule) writeLoot(outputDirectory string, verbosity int) {
	path := filepath.Join(outputDirectory, "loot")
	err := os.MkdirAll(path, os.ModePerm)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.IncrError()
	}

	m.writeLootCommands(path, verbosity)
	m.writeLootDetails(path, verbosity)
}

func (m *BedrockAgentsModule) writeLootCommands(lootDir string, verbosity int) {
	commandsFile := filepath.Join(lootDir, "bedrock-agents-commands.txt")

	var out string
	out += fmt.Sprintln("#############################################")
	out += fmt.Sprintln("# The profile you will use to perform these commands is most likely not the profile you used to run CloudFox")
	out += fmt.Sprintln("# Set the $profile environment variable to the profile you are going to use.")
	out += fmt.Sprintln("# E.g., export profile=dev-prod.")
	out += fmt.Sprintln("#############################################")
	out += fmt.Sprintln("")

	for _, agent := range m.Agents {
		out += fmt.Sprintln("=============================================")
		out += fmt.Sprintf("# Agent: %s (%s) in %s\n\n", agent.Name, agent.AgentId, agent.Region)

		out += "# Get full agent configuration including instruction/system prompt\n"
		out += fmt.Sprintf("aws --profile $profile --region %s bedrock-agent get-agent --agent-id %s\n\n", agent.Region, agent.AgentId)

		out += "# List agent aliases (production routing)\n"
		out += fmt.Sprintf("aws --profile $profile --region %s bedrock-agent list-agent-aliases --agent-id %s\n\n", agent.Region, agent.AgentId)

		out += "# List action groups (tool integrations)\n"
		out += fmt.Sprintf("aws --profile $profile --region %s bedrock-agent list-agent-action-groups --agent-id %s --agent-version %s\n\n", agent.Region, agent.AgentId, agent.LatestVersion)

		for _, ag := range agent.ActionGroupDetails {
			out += fmt.Sprintf("# Get action group detail: %s\n", ag.Name)
			out += fmt.Sprintf("aws --profile $profile --region %s bedrock-agent get-agent-action-group --agent-id %s --agent-version %s --action-group-id %s\n\n", agent.Region, agent.AgentId, agent.LatestVersion, ag.Id)
		}

		if agent.Collaborators > 0 {
			out += "# List collaborators (supervisor/worker topology)\n"
			out += fmt.Sprintf("aws --profile $profile --region %s bedrock-agent list-agent-collaborators --agent-id %s --agent-version %s\n\n", agent.Region, agent.AgentId, agent.LatestVersion)
		}
	}

	err := os.WriteFile(commandsFile, []byte(out), 0644)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.IncrError()
	}

	if verbosity > 2 {
		fmt.Println()
		fmt.Printf("[%s][%s] %s \n\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), green("Beginning of commands loot file."))
		fmt.Print(out)
		fmt.Printf("[%s][%s] %s \n\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), green("End of commands loot file."))
	}
	fmt.Printf("[%s][%s] Loot written to [%s]\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), commandsFile)
}

func (m *BedrockAgentsModule) writeLootDetails(lootDir string, verbosity int) {
	detailsFile := filepath.Join(lootDir, "bedrock-agents-details.txt")

	var out string
	for _, agent := range m.Agents {
		out += fmt.Sprintln("=============================================")
		out += fmt.Sprintf("# Agent: %s\n", agent.Name)
		out += fmt.Sprintf("# ID: %s | Region: %s\n", agent.AgentId, agent.Region)
		out += fmt.Sprintf("# ARN: %s\n", agent.AgentArn)
		out += fmt.Sprintf("# Status: %s\n", agent.Status)
		out += fmt.Sprintf("# Foundation Model: %s\n", agent.FoundationModel)
		out += fmt.Sprintf("# Execution Role: %s\n", agent.RoleArn)
		out += fmt.Sprintf("# Memory Enabled: %s\n", agent.MemoryEnabled)
		out += fmt.Sprintf("# Guardrail: %s\n", agent.GuardrailId)
		out += fmt.Sprintf("# Idle Session TTL: %ds\n", agent.IdleSessionTTL)
		out += fmt.Sprintf("# Action Groups: %d | Collaborators: %d | Aliases: %d\n", agent.ActionGroups, agent.Collaborators, agent.Aliases)
		out += fmt.Sprintln("")
		out += fmt.Sprintln("## Instruction / System Prompt:")
		if agent.Instruction != "" {
			out += fmt.Sprintln(agent.Instruction)
		} else {
			out += fmt.Sprintln("(none)")
		}
		out += fmt.Sprintln("")

		if len(agent.ActionGroupDetails) > 0 {
			out += fmt.Sprintln("## Action Groups:")
			for _, ag := range agent.ActionGroupDetails {
				out += fmt.Sprintf("  [%s] %s\n", ag.Id, ag.Name)
				if ag.Description != "" {
					out += fmt.Sprintf("    Description: %s\n", ag.Description)
				}
				if ag.ExecutorType != "" {
					out += fmt.Sprintf("    Executor: %s", ag.ExecutorType)
					if ag.ExecutorArn != "" {
						out += fmt.Sprintf(" -> %s", ag.ExecutorArn)
					}
					out += "\n"
				}
				if ag.ApiSchema != "" {
					out += fmt.Sprintf("    API Schema:\n%s\n", indentBlock(ag.ApiSchema, "      "))
				}
				for _, fn := range ag.Functions {
					out += fmt.Sprintf("    Function: %s\n", fn.Name)
					if fn.Description != "" {
						out += fmt.Sprintf("      Description: %s\n", fn.Description)
					}
					if len(fn.Parameters) > 0 {
						params, _ := json.Marshal(fn.Parameters)
						out += fmt.Sprintf("      Parameters: %s\n", string(params))
					}
				}
				out += fmt.Sprintln("")
			}
		}
	}

	err := os.WriteFile(detailsFile, []byte(out), 0644)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.IncrError()
	}

	fmt.Printf("[%s][%s] Loot written to [%s]\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), detailsFile)
}

func indentBlock(text string, prefix string) string {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		if line != "" {
			lines[i] = prefix + line
		}
	}
	return strings.Join(lines, "\n")
}

