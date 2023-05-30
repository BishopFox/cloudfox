package aws

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"

	"github.com/BishopFox/cloudfox/aws/sdk"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/BishopFox/cloudfox/internal/aws/policy"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/bishopfox/awsservicemap"
	"github.com/sirupsen/logrus"
)

type LambdasModule struct {
	// General configuration data
	LambdaClient *lambda.Client
	IAMClient    sdk.AWSIAMClientInterface

	Caller         sts.GetCallerIdentityOutput
	AWSRegions     []string
	OutputFormat   string
	Goroutines     int
	AWSProfile     string
	SkipAdminCheck bool
	WrapTable      bool
	pmapperMod     PmapperModule
	pmapperError   error
	iamSimClient   IamSimulatorModule

	// Main module data
	Lambdas        []Lambda
	CommandCounter internal.CommandCounter
	// Used to store output data for pretty printing
	output internal.OutputData2
	modLog *logrus.Entry
}

type Lambda struct {
	AWSService string
	Region     string
	Type       string
	Name       string
	Role       string
	Admin      string
	CanPrivEsc string
	Public     string
}

func (m *LambdasModule) PrintLambdas(outputFormat string, outputDirectory string, verbosity int) {

	// These stuct values are used by the output module
	m.output.Verbosity = verbosity
	m.output.Directory = outputDirectory
	m.output.CallingModule = "lambda"
	localAdminMap := make(map[string]bool)
	m.modLog = internal.TxtLog.WithFields(logrus.Fields{
		"module": m.output.CallingModule,
	})
	if m.AWSProfile == "" {
		m.AWSProfile = internal.BuildAWSPath(m.Caller)
	}

	fmt.Printf("[%s][%s] Enumerating lambdas for account %s.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), aws.ToString(m.Caller.Account))
	//fmt.Printf("[%s][%s] Attempting to build a PrivEsc graph in memory using local pmapper data if it exists on the filesystem.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	m.pmapperMod, m.pmapperError = initPmapperGraph(m.Caller, m.AWSProfile, m.Goroutines)
	m.iamSimClient = initIAMSimClient(m.IAMClient, m.Caller, m.AWSProfile, m.Goroutines)

	// if m.pmapperError != nil {
	// 	fmt.Printf("[%s][%s] No pmapper data found for this account. Using cloudfox's iam-simulator for role analysis.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	// } else {
	// 	fmt.Printf("[%s][%s] Found pmapper data for this account. Using it for role analysis.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	// }

	wg := new(sync.WaitGroup)
	semaphore := make(chan struct{}, m.Goroutines)

	// Create a channel to signal the spinner aka task status goroutine to finish
	spinnerDone := make(chan bool)
	//fire up the the task status spinner/updated
	go internal.SpinUntil(m.output.CallingModule, &m.CommandCounter, spinnerDone, "regions")

	//create a channel to receive the objects
	dataReceiver := make(chan Lambda)

	// Create a channel to signal to stop
	receiverDone := make(chan bool)

	go m.Receiver(dataReceiver, receiverDone)

	for _, region := range m.AWSRegions {
		wg.Add(1)
		m.CommandCounter.Pending++
		go m.executeChecks(region, wg, semaphore, dataReceiver)

	}
	wg.Wait()
	//time.Sleep(time.Second * 2)

	// Perform role analysis
	if m.pmapperError == nil {
		for i := range m.Lambdas {
			m.Lambdas[i].Admin, m.Lambdas[i].CanPrivEsc = GetPmapperResults(m.SkipAdminCheck, m.pmapperMod, &m.Lambdas[i].Role)
		}
	} else {
		for i := range m.Lambdas {
			m.Lambdas[i].Admin, m.Lambdas[i].CanPrivEsc = GetIamSimResult(m.SkipAdminCheck, &m.Lambdas[i].Role, m.iamSimClient, localAdminMap)
		}
	}

	// Send a message to the spinner goroutine to close the channel and stop
	spinnerDone <- true
	<-spinnerDone
	receiverDone <- true
	<-receiverDone

	// add - if struct is not empty do this. otherwise, dont write anything.
	if m.pmapperError == nil {
		m.output.Headers = []string{
			"Service",
			"Region",
			//"Type",
			"Resource",
			"Role",
			"IsAdminRole?",
			"CanPrivEscToAdmin?",
		}
	} else {
		m.output.Headers = []string{
			"Service",
			"Region",
			"Resource Arn",
			"Role",
			"IsAdminRole?",
		}
	}

	sort.Slice(m.Lambdas, func(i, j int) bool {
		return m.Lambdas[i].AWSService < m.Lambdas[j].AWSService
	})

	// Table rows
	for i := range m.Lambdas {

		if m.pmapperError == nil {
			m.output.Body = append(
				m.output.Body,
				[]string{
					m.Lambdas[i].AWSService,
					m.Lambdas[i].Region,
					//m.Lambdas[i].Type,
					m.Lambdas[i].Name,
					m.Lambdas[i].Role,
					m.Lambdas[i].Admin,
					m.Lambdas[i].CanPrivEsc,
					//m.Lambdas[i].Public,
				},
			)
		} else {
			m.output.Body = append(
				m.output.Body,
				[]string{
					m.Lambdas[i].AWSService,
					m.Lambdas[i].Region,
					//m.Lambdas[i].Type,
					m.Lambdas[i].Name,
					m.Lambdas[i].Role,
					m.Lambdas[i].Admin,
					//m.Lambdas[i].CanPrivEsc,
					//m.Lambdas[i].Public,
				},
			)
		}

	}
	if len(m.output.Body) > 0 {
		m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", fmt.Sprintf("%s-%s", aws.ToString(m.Caller.Account), m.AWSProfile))
		//utils.OutputSelector(verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.CallingModule, m.output.CallingModule)
		//internal.OutputSelector(verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.CallingModule, m.output.CallingModule, m.WrapTable, m.AWSProfile)
		o := internal.OutputClient{
			Verbosity:     verbosity,
			CallingModule: m.output.CallingModule,
			Table: internal.TableClient{
				Wrap: m.WrapTable,
			},
		}
		o.Table.TableFiles = append(o.Table.TableFiles, internal.TableFile{
			Header: m.output.Headers,
			Body:   m.output.Body,
			Name:   m.output.CallingModule,
		})
		o.PrefixIdentifier = m.AWSProfile
		o.Table.DirectoryName = filepath.Join(outputDirectory, "cloudfox-output", "aws", fmt.Sprintf("%s-%s", aws.ToString(m.Caller.Account), m.AWSProfile))
		o.WriteFullOutput(o.Table.TableFiles, nil)
		m.writeLoot(o.Table.DirectoryName, verbosity)
		fmt.Printf("[%s][%s] %s lambdas found.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), strconv.Itoa(len(m.output.Body)))
	} else {
		fmt.Printf("[%s][%s] No lambdas found, skipping the creation of an output file.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	}
	fmt.Printf("[%s][%s] For context and next steps: https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#%s\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), m.output.CallingModule)
}

func (m *LambdasModule) executeChecks(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Lambda) {
	defer wg.Done()

	servicemap := &awsservicemap.AwsServiceMap{
		JsonFileSource: "DOWNLOAD_FROM_AWS",
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

func (m *LambdasModule) Receiver(receiver chan Lambda, receiverDone chan bool) {
	defer close(receiverDone)
	for {
		select {
		case data := <-receiver:
			m.Lambdas = append(m.Lambdas, data)
		case <-receiverDone:
			receiverDone <- true
			return
		}
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
		out = out + fmt.Sprintln("=============================================")
		out = out + fmt.Sprintf("# Lambda Name: %s\n\n", function.Name)
		out = out + "# Get function metadata including download location\n"
		out = out + fmt.Sprintf("aws --profile $profile --region %s lambda get-function --function-name %s\n", function.Region, function.Name)
		out = out + "# Download function code to to disk (requires jq and curl) \n"
		out = out + fmt.Sprintf("mkdir -p ./lambdas/%s\n", function.Name)
		out = out + fmt.Sprintf("url=`aws --profile $profile lambda get-function --region %s --function-name %s | jq .Code.Location | sed s/\\\"//g` && curl \"$url\" -o ./lambdas/%s.zip\n", function.Region, function.Name, function.Name)
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

	functions, err := m.listFunctions(r)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
	}

	for _, function := range functions {
		//arn := aws.ToString(function.FunctionArn)
		name := aws.ToString(function.FunctionName)
		role := aws.ToString(function.Role)

		dataReceiver <- Lambda{
			AWSService: "Lambda",
			Name:       name,
			Region:     r,
			Type:       "",
			Role:       role,
			Admin:      "",
			CanPrivEsc: "",
			Public:     "",
		}

	}

}

func (m *LambdasModule) listFunctions(r string) ([]types.FunctionConfiguration, error) {
	// "PaginationMarker" is a control variable used for output continuity, as AWS return the output in pages.
	var PaginationControl *string
	var functions []types.FunctionConfiguration

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
			sharedLogger.Error(err.Error())
			m.CommandCounter.Error++
			return functions, err
		}
		functions = append(functions, ListFunctions.Functions...)

		if aws.ToString(ListFunctions.NextMarker) != "" {
			PaginationControl = ListFunctions.NextMarker
		} else {
			PaginationControl = nil
			break
		}
	}
	return functions, nil
}

func (m *LambdasModule) getResourcePolicy(r string, functionName string) (policy.Policy, error) {
	var projectPolicy policy.Policy
	var policyJSON string
	Policy, err := m.LambdaClient.GetPolicy(
		context.TODO(),
		&lambda.GetPolicyInput{
			FunctionName: &functionName,
		},
		func(options *lambda.Options) {
			options.Region = r
		},
	)
	if err != nil {
		sharedLogger.Error(err.Error())
		m.CommandCounter.Error++
		return projectPolicy, err
	}

	policyJSON = aws.ToString(Policy.Policy)
	projectPolicy, err = policy.ParseJSONPolicy([]byte(policyJSON))
	if err != nil {
		return projectPolicy, fmt.Errorf("parsing policy (%s) as JSON: %s", functionName, err)
	}
	return projectPolicy, nil
}
