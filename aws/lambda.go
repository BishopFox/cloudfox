package aws

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"sync"

	"github.com/BishopFox/cloudfox/console"
	"github.com/BishopFox/cloudfox/utils"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/sirupsen/logrus"
)

type LambdasModule struct {
	// General configuration data
	LambdaClient *lambda.Client

	Caller       sts.GetCallerIdentityOutput
	AWSRegions   []string
	OutputFormat string
	Goroutines   int
	AWSProfile   string

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
	Public     string
}

func (m *LambdasModule) PrintLambdas(outputFormat string, outputDirectory string, verbosity int) {
	// These stuct values are used by the output module
	m.output.Verbosity = verbosity
	m.output.Directory = outputDirectory
	m.output.CallingModule = "lambdas"
	m.modLog = utils.TxtLogger.WithFields(logrus.Fields{
		"module": m.output.CallingModule,
	})
	if m.AWSProfile == "" {
		m.AWSProfile = utils.BuildAWSPath(m.Caller)
	}

	fmt.Printf("[%s] Enumerating lambdas for account %s.\n", cyan(m.output.CallingModule), aws.ToString(m.Caller.Account))

	wg := new(sync.WaitGroup)
	semaphore := make(chan struct{}, m.Goroutines)

	// Create a channel to signal the spinner aka task status goroutine to finish
	spinnerDone := make(chan bool)
	//fire up the the task status spinner/updated
	go console.SpinUntil(m.output.CallingModule, &m.CommandCounter, spinnerDone, "regions")

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
	// Send a message to the spinner goroutine to close the channel and stop
	spinnerDone <- true
	<-spinnerDone
	// Send a message to the data receiver goroutine to close the channel and stop
	receiverDone <- true
	<-receiverDone

	// add - if struct is not empty do this. otherwise, dont write anything.
	m.output.Headers = []string{
		"Service",
		"Region",
		//"Type",
		"Resource Arn",
		"Role",
		"Public",
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
				m.Lambdas[i].Public,
			},
		)

	}
	if len(m.output.Body) > 0 {
		m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", m.AWSProfile)
		utils.OutputSelector(verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.CallingModule, m.output.CallingModule)
		//m.writeLoot(m.output.FilePath, verbosity)
		fmt.Printf("[%s] %s lambdas found.\n", cyan(m.output.CallingModule), strconv.Itoa(len(m.output.Body)))
	} else {
		fmt.Printf("[%s] No lambdas found, skipping the creation of an output file.\n", cyan(m.output.CallingModule))
	}

}

func (m *LambdasModule) executeChecks(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Lambda) {
	defer wg.Done()

	m.CommandCounter.Total++
	wg.Add(1)
	m.getLambdasPerRegion(r, wg, semaphore, dataReceiver)
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

// func (m *LambdasModule) writeLoot(outputDirectory string, verbosity int) {
// 	path := filepath.Join(outputDirectory, "loot")
// 	err := os.MkdirAll(path, os.ModePerm)
// 	if err != nil {
// 		m.modLog.Error(err.Error())
// 		m.CommandCounter.Error++
// 	}
// 	pullFile := filepath.Join(path, "cloudformation-data.txt")

// 	var out string
// 	out = out + fmt.Sprintln("#############################################")
// 	out = out + fmt.Sprintln("# Look for secrets. Use something like trufflehog")
// 	out = out + fmt.Sprintln("#############################################")
// 	out = out + fmt.Sprintln("")

// 	for _, stack := range m.CFStacks {
// 		out = out + fmt.Sprintf("=============================================\n")
// 		out = out + fmt.Sprintf("Stack Name: %s\n\n", stack.Name)
// 		out = out + fmt.Sprintf("Stack Outputs:\n\n")
// 		for _, output := range stack.Outputs {
// 			outputDescription := aws.ToString(output.Description)
// 			outputExport := aws.ToString(output.ExportName)
// 			outputKey := aws.ToString(output.OutputKey)
// 			outputValue := aws.ToString(output.OutputValue)
// 			out = out + fmt.Sprintf("Stack Output Description: %s\n", outputDescription)
// 			out = out + fmt.Sprintf("Stack Output Name: %s\n", outputExport)
// 			out = out + fmt.Sprintf("Stack Output Key: %s\n", outputKey)
// 			out = out + fmt.Sprintf("Stack Output Value: %s\n\n", outputValue)
// 		}
// 		out = out + fmt.Sprintf("Stack Parameters:\n\n")
// 		for _, param := range stack.Parameters {
// 			paramKey := aws.ToString(param.ParameterKey)
// 			paramValue := aws.ToString(param.ParameterValue)
// 			out = out + fmt.Sprintf("Stack Parameter Key: %s\n", paramKey)
// 			out = out + fmt.Sprintf("Stack Parameter Value: %s\n\n", paramValue)
// 		}
// 		//out = out + fmt.Sprintf("Stack Parameters:\n %s\n", stack.Parameters)
// 		out = out + fmt.Sprintf("Stack Template:\n %s\n", stack.Template)
// 		out = out + fmt.Sprintf("=============================================\n")

// 	}
// 	err = os.WriteFile(pullFile, []byte(out), 0644)
// 	if err != nil {
// 		m.modLog.Error(err.Error())
// 		m.CommandCounter.Error++
// 	}

// 	if verbosity > 2 {
// 		fmt.Println()
// 		fmt.Printf("[%s] %s \n", cyan(m.output.CallingModule), green("Look for secrets. Use something like trufflehog"))
// 		fmt.Print(out)
// 		fmt.Printf("[%s] %s \n", cyan(m.output.CallingModule), green("Look for secrets. Use something like trufflehog"))
// 		fmt.Printf("[%s] %s \n\n", cyan(m.output.CallingModule), green("End of loot file."))
// 	}

// 	fmt.Printf("[%s] Loot written to [%s]\n", cyan(m.output.CallingModule), pullFile)

// }

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

			dataReceiver <- Lambda{
				AWSService: "Lambda",
				Name:       name,
				Region:     r,
				Type:       "",
				Role:       role,
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
