package aws

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"

	"github.com/BishopFox/cloudfox/console"
	"github.com/BishopFox/cloudfox/utils"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/bishopfox/awsservicemap"
	"github.com/sirupsen/logrus"
)

type LambdasModule struct {
	// General configuration data
	LambdaClient                     *lambda.Client
	IAMSimulatePrincipalPolicyClient iam.SimulatePrincipalPolicyAPIClient

	Caller         sts.GetCallerIdentityOutput
	AWSRegions     []string
	OutputFormat   string
	Goroutines     int
	AWSProfile     string
	SkipAdminCheck bool
	pmapperMod     PmapperModule
	pmapperError   error

	// Main module data
	Lambdas        []Lambda
	CommandCounter console.CommandCounter
	// Used to store output data for pretty printing
	output utils.OutputData2
	modLog *logrus.Entry
}

type Lambda struct {
	AWSService string
	Region     string
	Type       string
	Name       string
	Role       string
	Admin      string
	Public     string
}

func (m *LambdasModule) PrintLambdas(outputFormat string, outputDirectory string, verbosity int) {
	// These stuct values are used by the output module
	m.output.Verbosity = verbosity
	m.output.Directory = outputDirectory
	m.output.CallingModule = "lambdas"
	m.modLog = utils.TxtLog.WithFields(logrus.Fields{
		"module": m.output.CallingModule,
	})
	if m.AWSProfile == "" {
		m.AWSProfile = utils.BuildAWSPath(m.Caller)
	}

	fmt.Printf("[%s][%s] Enumerating lambdas for account %s.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), aws.ToString(m.Caller.Account))
	m.pmapperMod, m.pmapperError = m.initPmapperGraph()
	if m.pmapperError != nil {
		fmt.Printf("[%s][%s] No pmapper data found for this account. Using cloudfox's iam-simulator for role analysis\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	} else {
		fmt.Printf("[%s][%s] Found pmapper data for this account. Using it for role analysis\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))

	}
	wg := new(sync.WaitGroup)
	semaphore := make(chan struct{}, m.Goroutines)

	// Create a channel to signal the spinner aka task status goroutine to finish
	spinnerDone := make(chan bool)
	//fire up the the task status spinner/updated
	go console.SpinUntil(m.output.CallingModule, &m.CommandCounter, spinnerDone, "regions")

	//create a channel to receive the objects
	dataReceiver := make(chan Lambda)

	go m.Receiver(dataReceiver)

	for _, region := range m.AWSRegions {
		wg.Add(1)
		m.CommandCounter.Pending++
		go m.executeChecks(region, wg, semaphore, dataReceiver)

	}

	wg.Wait()
	// Send a message to the spinner goroutine to close the channel and stop
	spinnerDone <- true
	<-spinnerDone
	close(dataReceiver)

	// add - if struct is not empty do this. otherwise, dont write anything.
	m.output.Headers = []string{
		"Service",
		"Region",
		//"Type",
		"Resource Arn",
		"Role",
		//"isAdminRole?",
		"CanPrivEscToAdmin?",
	}

	sort.Slice(m.Lambdas, func(i, j int) bool {
		return m.Lambdas[i].AWSService < m.Lambdas[j].AWSService
	})

	// Table rows
	for i := range m.Lambdas {

		m.output.Body = append(
			m.output.Body,
			[]string{
				m.Lambdas[i].AWSService,
				m.Lambdas[i].Region,
				//m.Lambdas[i].Type,
				m.Lambdas[i].Name,
				m.Lambdas[i].Role,
				m.Lambdas[i].Admin,
				//m.Lambdas[i].Public,
			},
		)

	}
	if len(m.output.Body) > 0 {
		m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", m.AWSProfile)
		utils.OutputSelector(verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.CallingModule, m.output.CallingModule)
		m.writeLoot(m.output.FilePath, verbosity)
		fmt.Printf("[%s][%s] %s lambdas found.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), strconv.Itoa(len(m.output.Body)))
	} else {
		fmt.Printf("[%s][%s] No lambdas found, skipping the creation of an output file.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	}

}

func (m *LambdasModule) executeChecks(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Lambda) {
	defer wg.Done()

	servicemap := &awsservicemap.AwsServiceMap{
		JsonFileSource: "EMBEDDED_IN_PACKAGE",
	}
	res, err := servicemap.IsServiceInRegion("lambda", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		m.getLambdasPerRegion(r, wg, semaphore, dataReceiver)
	}
}

func (m *LambdasModule) Receiver(receiver chan Lambda) {
	for data := range receiver {
		m.Lambdas = append(m.Lambdas, data)

	}
}

func (m *LambdasModule) writeLoot(outputDirectory string, verbosity int) {
	path := filepath.Join(outputDirectory, "loot")
	err := os.MkdirAll(path, os.ModePerm)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
	}
	pullFile := filepath.Join(path, "lambda-get-function-commands.txt")

	var out string
	out = out + fmt.Sprintln("#############################################")
	out = out + fmt.Sprintln("# The profile you will use to perform these commands is most likely not the profile you used to run CloudFox")
	out = out + fmt.Sprintln("# Set the $profile environment variable to the profile you are going to use to inspect the buckets.")
	out = out + fmt.Sprintln("# E.g., export profile=dev-prod.")
	out = out + fmt.Sprintln("#############################################")
	out = out + fmt.Sprintln("")

	for _, function := range m.Lambdas {
		out = out + fmt.Sprintf("=============================================\n")
		out = out + fmt.Sprintf("# Lambda Name: %s\n\n", function.Name)
		out = out + "# Get function metadata including download location\n"
		out = out + fmt.Sprintf("aws --profile $profile --region %s lambda get-function --function-name %s\n", function.Region, function.Name)
		out = out + "# Download function code to to disk (requires jq and curl) \n"
		out = out + fmt.Sprintf("mkdir -p ./lambdas/%s\n", function.Name)
		out = out + fmt.Sprintf("url=`aws --profile $profile lambda get-function --region %s --function-name %s | jq .Code.Location | sed s/\"//g` && curl \"$url\" -o ./lambdas/%s.zip\n", function.Region, function.Name, function.Name)
	}
	err = os.WriteFile(pullFile, []byte(out), 0644)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
	}

	if verbosity > 2 {
		fmt.Println()
		fmt.Printf("[%s][%s] %s \n\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), green("Beginning of loot file."))

		fmt.Print(out)
		fmt.Printf("[%s][%s] %s \n\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), green("End of loot file."))
	}

	fmt.Printf("[%s][%s] Loot written to [%s]\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), pullFile)

}

func (m *LambdasModule) getLambdasPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Lambda) {
	defer func() {
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
		wg.Done()

	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// "PaginationMarker" is a control variable used for output continuity, as AWS return the output in pages.
	var PaginationControl *string
	var adminRole string = ""
	localAdminMap := make(map[string]bool)

	for {
		ListFunctions, err := m.LambdaClient.ListFunctions(
			context.TODO(),
			&lambda.ListFunctionsInput{
				Marker: PaginationControl,
			},
			func(o *lambda.Options) {
				o.Region = r
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}
		//var parsedArn types.Arn
		for _, function := range ListFunctions.Functions {
			//arn := aws.ToString(function.FunctionArn)
			name := aws.ToString(function.FunctionName)
			role := aws.ToString(function.Role)
			if function.Role != nil {
				// If we've seen the function before, skip the isRoleAdmin function and just pull the value from the localAdminMap
				if val, ok := localAdminMap[role]; ok {
					if val {
						// we've seen it before and it's an admin
						adminRole = "YES"
					} else {
						// we've seen it before and it's NOT an admin
						adminRole = "No"
					}
				} else {
					if !m.SkipAdminCheck {
						//isRoleAdmin := m.isRoleAdmin(function.Role)
						isRoleAdmin := m.hasPathToAdmin(m.pmapperMod, function.Role)
						if isRoleAdmin {
							adminRole = "YES"
							localAdminMap[role] = true
						} else {
							adminRole = "No"
							localAdminMap[role] = false
						}
					} else {
						adminRole = "Skipped"
					}
				}
			}

			dataReceiver <- Lambda{
				AWSService: "Lambda",
				Name:       name,
				Region:     r,
				Type:       "",
				Role:       role,
				Admin:      adminRole,
				Public:     "",
			}

		}

		if aws.ToString(ListFunctions.NextMarker) != "" {
			PaginationControl = ListFunctions.NextMarker
		} else {
			PaginationControl = nil
			break
		}
	}
}

func (m *LambdasModule) isRoleAdmin(principal *string) bool {
	iamSimMod := IamSimulatorModule{
		IAMSimulatePrincipalPolicyClient: m.IAMSimulatePrincipalPolicyClient,
		Caller:                           m.Caller,
		AWSProfile:                       m.AWSProfile,
		Goroutines:                       m.Goroutines,
	}

	adminCheckResult := iamSimMod.isPrincipalAnAdmin(principal)

	if adminCheckResult {
		return true
	} else {
		return false
	}

}

func (m *LambdasModule) hasPathToAdmin(pmapperMod PmapperModule, principal *string) bool {
	privescCheckResult := pmapperMod.DoesPrincipalHavePathToAdmin(aws.ToString(principal))

	if privescCheckResult {
		return true
	} else {
		return false
	}

}

func (m *LambdasModule) initPmapperGraph() (PmapperModule, error) {
	pmapperMod := PmapperModule{
		Caller:     m.Caller,
		AWSProfile: m.AWSProfile,
		Goroutines: m.Goroutines,
	}
	err := pmapperMod.initPmapperGraph()
	if err != nil {
		return pmapperMod, err
	}
	return pmapperMod, nil

}
