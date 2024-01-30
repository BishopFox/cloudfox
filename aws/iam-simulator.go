package aws

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/BishopFox/cloudfox/aws/sdk"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/sirupsen/logrus"
)

type IamSimulatorModule struct {
	// General configuration data
	IAMClient     sdk.AWSIAMClientInterface
	Caller        sts.GetCallerIdentityOutput
	AWSRegions    []string
	AWSOutputType string
	AWSTableCols  string

	Goroutines         int
	AWSProfileProvided string
	AWSProfileStub     string
	WrapTable          bool

	// Main module data
	SimulatorResults []SimulatorResult
	CommandCounter   internal.CommandCounter
	// Used to store output data for pretty printing
	output internal.OutputData2
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
		"ssm:SendCommand",
		"ssm:StartSession",
		"ecr:BatchGetImage",
		"ecr:GetAuthorizationToken",
		"eks:UpdateClusterConfig",
		"lambda:ListFunctions",
		"ec2:DescribeInstanceAttributeInput",
		"sns:Subscribe",
		"sqs:SendMessage",
	}
	TxtLogger = internal.TxtLogger()
)

func (m *IamSimulatorModule) PrintIamSimulator(principal string, action string, resource string, outputDirectory string, verbosity int) {

	// These struct values are used by the output module
	m.output.Verbosity = verbosity
	m.output.Directory = outputDirectory
	m.output.CallingModule = "iam-simulator"
	m.modLog = internal.TxtLog.WithFields(logrus.Fields{
		"module": m.output.CallingModule,
	})
	m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", fmt.Sprintf("%s-%s", m.AWSProfileStub, aws.ToString(m.Caller.Account)))
	var filename string
	var actionList []string
	var pmapperCommands []string
	var pmapperOutFileName string
	var inputArn string

	if m.AWSProfileProvided == "" {
		m.AWSProfileStub = internal.BuildAWSPath(m.Caller)
	} else {
		m.AWSProfileStub = m.AWSProfileProvided
	}

	wg := new(sync.WaitGroup)
	// Create a channel to signal the spinner aka task status goroutine to finish
	spinnerDone := make(chan bool)
	//fire up the the task status spinner/updated
	go internal.SpinUntil(m.output.CallingModule, &m.CommandCounter, spinnerDone, "tasks")

	//create a channel to receive the objects
	dataReceiver := make(chan SimulatorResult)

	// Create a channel to signal to stop
	receiverDone := make(chan bool)

	go m.Receiver(dataReceiver, receiverDone)

	// This double if/else section is here to handle the cases where --principal or --action (or both) are specified.
	if principal != "" {
		if action != "" {
			// The user specified a specific --principal and a specific --action
			fmt.Printf("[%s][%s] Checking to see if %s can do %s.\n", cyan(m.output.CallingModule), cyan(m.AWSProfileStub), principal, action)
			filename = filepath.Join(fmt.Sprintf("%s-custom-%s", m.output.CallingModule, strconv.FormatInt((time.Now().Unix()), 10)))
			actionList = append(actionList, action)
			// if user supplied a principal name without the arn, try to create the arn as a user and as a role and run both
			if !strings.Contains(principal, "arn:") {
				// try as a role
				inputArn = fmt.Sprintf("arn:aws:iam::%s:role/%s", aws.ToString(m.Caller.Account), principal)
				m.getPolicySimulatorResult((&inputArn), actionList, resource, dataReceiver)
				// try as a user
				inputArn = fmt.Sprintf("arn:aws:iam::%s:user/%s", aws.ToString(m.Caller.Account), principal)
				m.getPolicySimulatorResult((&inputArn), actionList, resource, dataReceiver)
			} else {
				// the arn was supplied so just run it
				m.getPolicySimulatorResult((&principal), actionList, resource, dataReceiver)
			}

		} else {
			// The user specified a specific --principal, but --action was empty
			fmt.Printf("[%s][%s] Checking to see if %s can do any actions of interest.\n", cyan(m.output.CallingModule), cyan(m.AWSProfileStub), principal)
			filename = filepath.Join(fmt.Sprintf("%s-custom-%s", m.output.CallingModule, strconv.FormatInt((time.Now().Unix()), 10)))

			// if user supplied a principal name without the arn, try to create the arn as a user and as a role and run both
			if !strings.Contains(principal, "arn:") {
				// try as a role
				inputArn = fmt.Sprintf("arn:aws:iam::%s:role/%s", aws.ToString(m.Caller.Account), principal)
				m.getPolicySimulatorResult((&inputArn), defaultActionNames, resource, dataReceiver)
				// try as a user
				inputArn = fmt.Sprintf("arn:aws:iam::%s:user/%s", aws.ToString(m.Caller.Account), principal)
				m.getPolicySimulatorResult((&inputArn), defaultActionNames, resource, dataReceiver)
			} else {
				// the arn was supplied so just run it
				m.getPolicySimulatorResult((&principal), defaultActionNames, resource, dataReceiver)
			}

		}
	} else {
		if action != "" {
			// The did not specify a specific --principal, but they did specify an --action
			fmt.Printf("[%s][%s] Checking to see if any principal can do %s.\n", cyan(m.output.CallingModule), cyan(m.AWSProfileStub), action)
			filename = filepath.Join(fmt.Sprintf("%s-custom-%s", m.output.CallingModule, strconv.FormatInt((time.Now().Unix()), 10)))
			actionList = append(actionList, action)
			wg.Add(1)
			m.getIAMUsers(wg, actionList, resource, dataReceiver)
			wg.Add(1)
			m.getIAMRoles(wg, actionList, resource, dataReceiver)
			pmapperOutFileName = filepath.Join(filename, "loot", fmt.Sprintf("pmapper-output-%s.txt", action))
			if m.AWSProfileProvided != "" {
				pmapperCommands = append(pmapperCommands, fmt.Sprintf("pmapper --profile %s query \"who can do %s with %s\" | tee %s\n", m.AWSProfileProvided, action, resource, pmapperOutFileName))
			} else {
				pmapperCommands = append(pmapperCommands, fmt.Sprintf("pmapper query \"who can do %s with %s\" | tee %s\n", action, resource, pmapperOutFileName))
			}
		} else {
			// Both --principal and --action are empty. Run in default mode!
			fmt.Printf("[%s][%s] Running multiple iam-simulator queries for account %s. (This command can be pretty slow, FYI)\n", cyan(m.output.CallingModule), cyan(m.AWSProfileStub), aws.ToString(m.Caller.Account))
			filename = m.output.CallingModule
			m.executeChecks(wg, resource, dataReceiver)
			for _, action := range defaultActionNames {
				pmapperOutFileName = filepath.Join(filename, "loot", fmt.Sprintf("pmapper-output-%s.txt", action))
				if m.AWSProfileProvided != "" {
					pmapperCommands = append(pmapperCommands, fmt.Sprintf("pmapper --profile %s query \"who can do %s with %s\" | tee %s\n", m.AWSProfileProvided, action, resource, pmapperOutFileName))
				} else {
					pmapperCommands = append(pmapperCommands, fmt.Sprintf("pmapper query \"who can do %s with %s\" | tee %s\n", action, resource, pmapperOutFileName))
				}
			}

		}
	}

	wg.Wait()
	//time.Sleep(time.Second * 2)

	// Send a message to the spinner goroutine to close the channel and stop
	spinnerDone <- true
	<-spinnerDone
	receiverDone <- true
	<-receiverDone

	//duration := time.Since(start)
	//fmt.Printf("\n\n[*] Total execution time %s\n", duration)

	// Regardless of what options were selected, for now at least, we will always print the data using the output module (table/csv mode)
	m.output.Headers = []string{
		"Account",
		"Principal",
		"Query",
	}

	// If the user specified table columns, use those.
	// If the user specified -o wide, use the wide default cols for this module.
	// Otherwise, use the hardcoded default cols for this module.
	var tableCols []string
	// If the user specified table columns, use those.
	if m.AWSTableCols != "" {
		// If the user specified wide as the output format, use these columns.
		// remove any spaces between any commas and the first letter after the commas
		m.AWSTableCols = strings.ReplaceAll(m.AWSTableCols, ", ", ",")
		m.AWSTableCols = strings.ReplaceAll(m.AWSTableCols, ",  ", ",")
		tableCols = strings.Split(m.AWSTableCols, ",")
		// If the user specified wide as the output format, use these columns.
	} else if m.AWSOutputType == "wide" {
		tableCols = []string{
			"Account",
			"Principal",
			"Query",
		}
	} else {
		tableCols = []string{
			"Principal",
			"Query",
		}
	}

	sort.Slice(m.SimulatorResults, func(i, j int) bool {
		return m.SimulatorResults[i].Query < m.SimulatorResults[j].Query
	})

	//Table rows
	for i := range m.SimulatorResults {
		m.output.Body = append(
			m.output.Body,
			[]string{
				aws.ToString(m.Caller.Account),
				m.SimulatorResults[i].Principal,
				m.SimulatorResults[i].Query,
			},
		)

	}
	if len(m.output.Body) > 0 {
		m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", fmt.Sprintf("%s-%s", m.AWSProfileStub, aws.ToString(m.Caller.Account)))

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
			Name:      filename,
		})
		o.PrefixIdentifier = m.AWSProfileStub
		o.Table.DirectoryName = filepath.Join(outputDirectory, "cloudfox-output", "aws", fmt.Sprintf("%s-%s", m.AWSProfileStub, aws.ToString(m.Caller.Account)))
		o.WriteFullOutput(o.Table.TableFiles, nil)
		fmt.Printf("[%s][%s] We suggest running the pmapper commands in the loot file to get the same information but taking privesc paths into account.\n", cyan(m.output.CallingModule), cyan(m.AWSProfileStub))
		// fmt.Printf("[%s]\t\tpmapper --profile %s graph create\n", cyan(m.output.CallingModule),  cyan(m.AWSProfile), m.AWSProfile)
		// for _, line := range pmapperCommands {
		// 	fmt.Printf("[%s]\t\t%s", cyan(m.output.CallingModule),  cyan(m.AWSProfile), line)
		// }
		m.writeLoot(o.Table.DirectoryName, verbosity, pmapperCommands)

	} else if principal != "" || action != "" {
		fmt.Printf("[%s][%s] No allowed permissions identified, skipping the creation of an output file.\n", cyan(m.output.CallingModule), cyan(m.AWSProfileStub))
	}
	fmt.Printf("[%s][%s] For context and next steps: https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#%s\n", cyan(m.output.CallingModule), cyan(m.AWSProfileStub), m.output.CallingModule)
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
	if m.AWSProfileProvided != "" {
		out = out + fmt.Sprintf("pmapper --profile %s graph create\n", m.AWSProfileProvided)
	} else {
		out = out + fmt.Sprintf("pmapper graph create\n")
	}
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
		fmt.Printf("[%s][%s] %s \n", cyan(m.output.CallingModule), cyan(m.AWSProfileStub), green("We suggest running these pmapper commands in the loot file to get the same information but taking privesc paths into account."))
		fmt.Print(out)
		fmt.Printf("[%s][%s] %s \n\n", cyan(m.output.CallingModule), cyan(m.AWSProfileStub), green("End of loot file."))
	}

	fmt.Printf("[%s][%s] Loot written to [%s]\n", cyan(m.output.CallingModule), cyan(m.AWSProfileStub), outFile)

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

	ListUsers, err := sdk.CachedIamListUsers(m.IAMClient, aws.ToString(m.Caller.Account))

	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	for _, user := range ListUsers {
		//name := user.UserName
		principal := user.Arn
		adminCheckResult := m.isPrincipalAnAdmin(principal)
		if adminCheckResult {
			query := "Appears to be an administrator"
			dataReceiver <- SimulatorResult{
				AWSService: "IAM",
				Principal:  aws.ToString(principal),
				Query:      query,
				Decision:   "",
			}
		} else {
			m.getPolicySimulatorResult(principal, actions, resource, dataReceiver)
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

	ListRoles, err := sdk.CachedIamListRoles(m.IAMClient, aws.ToString(m.Caller.Account))

	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return

	}

	for _, role := range ListRoles {
		//name := user.UserName
		principal := role.Arn
		adminCheckResult := m.isPrincipalAnAdmin(principal)
		if adminCheckResult {
			query := "Appears to be an administrator"
			dataReceiver <- SimulatorResult{
				AWSService: "IAM",
				Principal:  aws.ToString(principal),
				Query:      query,
				Decision:   "",
			}
		} else {
			m.getPolicySimulatorResult(principal, actions, resource, dataReceiver)
		}

	}

}

func (m *IamSimulatorModule) getPolicySimulatorResult(principal *string, actionNames []string, resource string, dataReceiver chan SimulatorResult) {
	//var policySourceArn = "*"
	//var arn *string
	var resourceArns []string
	resourceArns = append(resourceArns, resource)
	//var resourceArns = []string{"*"}

	EvaluationResults, err := sdk.CachedIamSimulatePrincipalPolicy(m.IAMClient, aws.ToString(m.Caller.Account), principal, actionNames, resourceArns)

	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		m.modLog.Error(fmt.Sprintf("Failed to query actions for %s\n\n", aws.ToString(principal)))
		return
	}

	for _, result := range EvaluationResults {
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

}

func (m *IamSimulatorModule) isPrincipalAnAdmin(principal *string) bool {
	var PaginationControl2 *string
	var resourceArns []string
	resourceArns = append(resourceArns, "*")
	var adminActionNames = []string{
		"iam:PutUserPolicy",
		"iam:AttachUserPolicy",
		"iam:PutRolePolicy",
		"iam:AttachRolePolicy",
		"secretsmanager:GetSecretValue",
		"ssm:GetDocument",
	}
	for {
		SimulatePrincipalPolicy, err := m.IAMClient.SimulatePrincipalPolicy(
			context.TODO(),
			&iam.SimulatePrincipalPolicyInput{
				Marker:          PaginationControl2,
				ActionNames:     adminActionNames,
				PolicySourceArn: principal,
				ResourceArns:    resourceArns,
			},
		)
		if err != nil {
			//m.modLog.Error(err.Error())
			TxtLogger.Println(err.Error())
			m.CommandCounter.Error++
			//m.modLog.Error(fmt.Sprintf("Failed admin check on %s\n\n", aws.ToString(principal)))
			TxtLogger.Printf("Failed admin check on %s\n\n", aws.ToString(principal))
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
	return true
}
