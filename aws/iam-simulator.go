package aws

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/BishopFox/cloudfox/console"
	"github.com/BishopFox/cloudfox/utils"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/sirupsen/logrus"
)

type IamSimulatorModule struct {
	// General configuration data
	IAMClient *iam.Client

	Caller       sts.GetCallerIdentityOutput
	AWSRegions   []string
	OutputFormat string
	Goroutines   int
	AWSProfile   string

	// Main module data
	SimulatorResults []SimulatorResult
	CommandCounter   console.CommandCounter
	// Used to store output data for pretty printing
	output utils.OutputData2
	modLog *logrus.Entry
}

type SimulatorResult struct {
	AWSService string
	Query      string
	Principal  string
	Decision   string
}

var (
	defaultActionNames = []string{
		"sts:AssumeRole",
		"iam:PassRole",
		"secretsmanager:GetSecretValue",
		"ssm:GetParameter",
		"s3:ListBucket",
		"s3:GetObject",
		"ssm:sSendCommand",
		"ssm:StartSession",
		"ecr:BatchGetImage",
		"ecr:GetAuthorizationToken",
		"eks:UpdateClusterConfig",
		"lambda:ListFunctions",
		"ecs:DescribeTaskDefinition",
		"apprunner:DescribeService",
		"ec2:DescribeInstanceAttributeInput",
	}
	adminActionNames = []string{
		"iam:PutUserPolicy",
		"iam:AttachUserPolicy",
		"iam:PutRolePolicy",
		"iam:AttachRolePolicy",
		"secretsmanager:GetSecretValue",
		"ssm:GetDocument",
	}
)

func (m *IamSimulatorModule) PrintIamSimulator(principal string, action string, resource string, outputFormat string, outputDirectory string, verbosity int) {
	// These stuct values are used by the output module
	m.output.Verbosity = verbosity
	m.output.Directory = outputDirectory
	m.output.CallingModule = "iam-simulator"
	m.modLog = utils.TxtLogger.WithFields(logrus.Fields{
		"module": m.output.CallingModule,
	})
	m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", m.AWSProfile)
	var actionList []string
	var pmapperCommands []string
	var pmapperOutFileName string

	if m.AWSProfile == "" {
		m.AWSProfile = utils.BuildAWSPath(m.Caller)
	}
	wg := new(sync.WaitGroup)
	// Create a channel to signal the spinner aka task status goroutine to finish
	spinnerDone := make(chan bool)
	//fire up the the task status spinner/updated
	go console.SpinUntil(m.output.CallingModule, &m.CommandCounter, spinnerDone, "tasks")

	//create a channel to receive the objects
	dataReceiver := make(chan SimulatorResult)

	// Create a channel to signal to stop
	receiverDone := make(chan bool)
	go m.Receiver(dataReceiver, receiverDone)

	// This double if/else section is here to handle the cases where --principal or --action (or both) are specified.
	if principal != "" {
		if action != "" {
			// The user specified a specific --principal and a specific --action
			fmt.Printf("[%s] Checking to see if %s can do %s.\n", cyan(m.output.CallingModule), principal, action)
			m.output.FullFilename = filepath.Join(fmt.Sprintf("%s-custom-%s", m.output.CallingModule, strconv.FormatInt((time.Now().Unix()), 10)))
			actionList = append(actionList, action)
			m.getPolicySimulatorResult((&principal), actionList, resource, dataReceiver)

		} else {
			// The user specified a specific --principal, but --action was empty
			fmt.Printf("[%s] Checking to see if %s can do any actions of interest.\n", cyan(m.output.CallingModule), principal)
			m.output.FullFilename = filepath.Join(fmt.Sprintf("%s-custom-%s", m.output.CallingModule, strconv.FormatInt((time.Now().Unix()), 10)))
			m.getPolicySimulatorResult((&principal), defaultActionNames, resource, dataReceiver)
		}
	} else {
		if action != "" {
			// The did not specify a specific --principal, but they did specify an --action
			fmt.Printf("[%s] Checking to see if any principal can do %s.\n", cyan(m.output.CallingModule), action)
			m.output.FullFilename = filepath.Join(fmt.Sprintf("%s-custom-%s", m.output.CallingModule, strconv.FormatInt((time.Now().Unix()), 10)))
			actionList = append(actionList, action)
			wg.Add(1)
			m.getIAMUsers(wg, actionList, resource, dataReceiver)
			wg.Add(1)
			m.getIAMRoles(wg, actionList, resource, dataReceiver)
			pmapperOutFileName = filepath.Join(m.output.FullFilename, "loot", fmt.Sprintf("pmapper-output-%s.txt", action))
			pmapperCommands = append(pmapperCommands, fmt.Sprintf("pmapper --profile %s query \"who can do %s with %s\" | tee %s\n", m.AWSProfile, action, resource, pmapperOutFileName))
		} else {
			// Both --principal and --action are empty. Run in default mode!
			fmt.Printf("[%s] Running multiple iam-simulator queries for account %s. (This command can be pretty slow, FYI)\n", cyan(m.output.CallingModule), aws.ToString(m.Caller.Account))
			m.output.FullFilename = m.output.CallingModule
			m.executeChecks(wg, resource, dataReceiver)
			for _, action := range defaultActionNames {
				pmapperOutFileName = filepath.Join(m.output.FullFilename, "loot", fmt.Sprintf("pmapper-output-%s.txt", action))
				pmapperCommands = append(pmapperCommands, fmt.Sprintf("pmapper --profile %s query \"who can do %s with %s\" | tee %s\n", m.AWSProfile, action, resource, pmapperOutFileName))
			}

		}
	}

	wg.Wait()
	// Send a message to the spinner goroutine to close the channel and stop
	spinnerDone <- true
	<-spinnerDone
	// Send a message to the data receiver goroutine to close the channel and stop
	receiverDone <- true
	<-receiverDone

	//duration := time.Since(start)
	//fmt.Printf("\n\n[*] Total execution time %s\n", duration)

	// Regardless of what options were selected, for now at least, we will always print the data using the output module (table/csv mode)
	m.output.Headers = []string{
		"Service",
		"Principal",
		"Query",
	}

	sort.Slice(m.SimulatorResults, func(i, j int) bool {
		return m.SimulatorResults[i].Query < m.SimulatorResults[j].Query
	})

	//Table rows
	for i := range m.SimulatorResults {
		m.output.Body = append(
			m.output.Body,
			[]string{
				m.SimulatorResults[i].AWSService,
				m.SimulatorResults[i].Principal,
				m.SimulatorResults[i].Query,
			},
		)

	}
	if len(m.output.Body) > 0 {
		m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", m.AWSProfile)
		utils.OutputSelector(verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.FullFilename, m.output.CallingModule)
		fmt.Printf("[%s] We suggest running the pmapper commands in the loot file to get the same information but taking privesc paths into account.\n", cyan(m.output.CallingModule))
		// fmt.Printf("[%s]\t\tpmapper --profile %s graph create\n", cyan(m.output.CallingModule), m.AWSProfile)
		// for _, line := range pmapperCommands {
		// 	fmt.Printf("[%s]\t\t%s", cyan(m.output.CallingModule), line)
		// }
		m.writeLoot(m.output.FilePath, verbosity, pmapperCommands)

	} else if principal != "" || action != "" {
		fmt.Printf("[%s] No allowed permissions identified, skipping the creation of an output file.\n", cyan(m.output.CallingModule))
	}

}

func (m *IamSimulatorModule) writeLoot(outputDirectory string, verbosity int, pmapperCommands []string) {
	path := filepath.Join(outputDirectory, "loot")
	err := os.MkdirAll(path, os.ModePerm)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
	}

	outFile := filepath.Join(path, "iam-simulator-pmapper-commands.txt")
	var out string
	out = out + fmt.Sprintf("pmapper --profile %s graph create\n", m.AWSProfile)
	for _, line := range pmapperCommands {
		out = out + line
	}
	err = os.WriteFile(outFile, []byte(out), 0644)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
	}

	if verbosity > 2 {
		fmt.Println()
		fmt.Printf("[%s] %s \n", cyan(m.output.CallingModule), green("We suggest running these pmapper commands in the loot file to get the same information but taking privesc paths into account."))
		fmt.Print(out)
		fmt.Printf("[%s] %s \n\n", cyan(m.output.CallingModule), green("End of loot file."))
	}

	fmt.Printf("[%s] Loot written to [%s]\n", cyan(m.output.CallingModule), outFile)

}

func (m *IamSimulatorModule) Receiver(receiver chan SimulatorResult, receiverDone chan bool) {
	defer close(receiverDone)
	for {
		select {
		case data := <-receiver:
			m.SimulatorResults = append(m.SimulatorResults, data)
		case <-receiverDone:
			receiverDone <- true
			return
		}
	}
}

func (m *IamSimulatorModule) executeChecks(wg *sync.WaitGroup, resource string, dataReceiver chan SimulatorResult) {
	wg.Add(1)
	m.getIAMUsers(wg, defaultActionNames, resource, dataReceiver)
	wg.Add(1)
	m.getIAMRoles(wg, defaultActionNames, resource, dataReceiver)
}

func (m *IamSimulatorModule) getIAMUsers(wg *sync.WaitGroup, actions []string, resource string, dataReceiver chan SimulatorResult) {
	defer func() {
		wg.Done()
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}()
	m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	// "PaginationMarker" is a control variable used for output continuity, as AWS return the output in pages.
	var PaginationControl *string
	var adminCheckResult bool

	for {
		ListUsers, err := m.IAMClient.ListUsers(
			context.TODO(),
			&iam.ListUsersInput{
				Marker: PaginationControl,
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		for _, user := range ListUsers.Users {
			//name := user.UserName
			principal := user.Arn
			adminCheckResult = m.policySimulatorAdminCheck(principal, adminActionNames, resource, dataReceiver)
			if !adminCheckResult {
				m.getPolicySimulatorResult(principal, actions, resource, dataReceiver)
			}

		}

		// Pagination control. After the last page of output, the for loop exits.
		if ListUsers.Marker != nil {
			PaginationControl = ListUsers.Marker
		} else {
			PaginationControl = nil
			break
		}
	}

}

func (m *IamSimulatorModule) getIAMRoles(wg *sync.WaitGroup, actions []string, resource string, dataReceiver chan SimulatorResult) {
	defer func() {
		wg.Done()
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}()
	m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	// "PaginationMarker" is a control variable used for output continuity, as AWS return the output in pages.
	var PaginationControl *string
	var adminCheckResult bool

	for {
		ListRoles, err := m.IAMClient.ListRoles(
			context.TODO(),
			&iam.ListRolesInput{
				Marker: PaginationControl,
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		for _, role := range ListRoles.Roles {
			//name := user.UserName
			principal := role.Arn
			adminCheckResult = m.policySimulatorAdminCheck(principal, adminActionNames, resource, dataReceiver)
			if !adminCheckResult {
				m.getPolicySimulatorResult(principal, actions, resource, dataReceiver)
			}

		}

		// Pagination control. After the last page of output, the for loop exits.
		if ListRoles.Marker != nil {
			PaginationControl = ListRoles.Marker
		} else {
			PaginationControl = nil
			break
		}
	}
}

func (m *IamSimulatorModule) getPolicySimulatorResult(principal *string, actionNames []string, resource string, dataReceiver chan SimulatorResult) {
	var PaginationControl2 *string

	//var policySourceArn = "*"
	//var arn *string
	var resourceArns []string
	resourceArns = append(resourceArns, resource)
	//var resourceArns = []string{"*"}

	for {
		SimulatePrincipalPolicy, err := m.IAMClient.SimulatePrincipalPolicy(
			context.TODO(),
			&iam.SimulatePrincipalPolicyInput{
				Marker:          PaginationControl2,
				ActionNames:     actionNames,
				PolicySourceArn: principal,
				ResourceArns:    resourceArns,
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			m.modLog.Error(fmt.Sprintf("Failed to query actions for %s\n\n", aws.ToString(principal)))

			break
		}

		for _, result := range SimulatePrincipalPolicy.EvaluationResults {
			evalName := result.EvalActionName
			query := fmt.Sprintf("can %s on %s", *evalName, resource)
			decision := result.EvalDecision
			if decision == "allowed" {
				dataReceiver <- SimulatorResult{
					AWSService: "IAM",
					Principal:  aws.ToString(principal),
					Query:      query,
					Decision:   string(decision),
				}
			}
		}

		// Pagination control. After the last page of output, the for loop exits.
		if SimulatePrincipalPolicy.Marker != nil {
			PaginationControl2 = SimulatePrincipalPolicy.Marker
		} else {
			PaginationControl2 = nil
			break
		}

	}
}

func (m *IamSimulatorModule) policySimulatorAdminCheck(principal *string, actionNames []string, resource string, dataReceiver chan SimulatorResult) bool {
	var PaginationControl2 *string
	var resourceArns []string
	resourceArns = append(resourceArns, resource)

	for {
		SimulatePrincipalPolicy, err := m.IAMClient.SimulatePrincipalPolicy(
			context.TODO(),
			&iam.SimulatePrincipalPolicyInput{
				Marker:          PaginationControl2,
				ActionNames:     actionNames,
				PolicySourceArn: principal,
				ResourceArns:    resourceArns,
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			m.modLog.Error(fmt.Sprintf("Failed admin check on %s\n\n", aws.ToString(principal)))
			return false
		}

		for _, result := range SimulatePrincipalPolicy.EvaluationResults {
			// If the adminCheck argument was sent to this function don't update the results table, rather just return if it's an admin or not.
			decision := result.EvalDecision

			//fmt.Printf("%s is %s\n\n", *principal, string(decision))
			if string(decision) != "allowed" {
				// If any of the permission in our short list are denied we can break out and call it a non-admin
				return false
			}

		}

		// Pagination control. After the last page of output, the for loop exits.
		if SimulatePrincipalPolicy.Marker != nil {
			PaginationControl2 = SimulatePrincipalPolicy.Marker
		} else {
			PaginationControl2 = nil
			break
		}
	}

	query := fmt.Sprintf("Appears to be an administrator")
	dataReceiver <- SimulatorResult{
		AWSService: "IAM",
		Principal:  aws.ToString(principal),
		Query:      query,
		Decision:   "",
	}

	return true
}
