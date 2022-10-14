package aws

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/BishopFox/cloudfox/console"
	"github.com/BishopFox/cloudfox/utils"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/sirupsen/logrus"
)

type CloudformationModule struct {
	// General configuration data
	CloudFormationClient *cloudformation.Client

	Caller       sts.GetCallerIdentityOutput
	AWSRegions   []string
	OutputFormat string
	Goroutines   int
	AWSProfile   string

	// Main module data
	CFStacks       []CFStack
	CommandCounter console.CommandCounter
	// Used to store output data for pretty printing
	output utils.OutputData2
	modLog *logrus.Entry
}

type CFStack struct {
	AWSService string
	Region     string
	Name       string
	Role       string
	Outputs    []types.Output
	Parameters []types.Parameter
	Template   string
}

func (m *CloudformationModule) PrintCloudformationStacks(outputFormat string, outputDirectory string, verbosity int) {
	// These stuct values are used by the output module
	m.output.Verbosity = verbosity
	m.output.Directory = outputDirectory
	m.output.CallingModule = "cloudformation"
	m.modLog = utils.TxtLog.WithFields(logrus.Fields{
		"module": m.output.CallingModule,
	})
	if m.AWSProfile == "" {
		m.AWSProfile = utils.BuildAWSPath(m.Caller)
	}

	fmt.Printf("[%s][%s] Enumerating cloudformation stacks for account %s.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), aws.ToString(m.Caller.Account))

	wg := new(sync.WaitGroup)
	semaphore := make(chan struct{}, m.Goroutines)

	// Create a channel to signal the spinner aka task status goroutine to finish
	spinnerDone := make(chan bool)
	//fire up the the task status spinner/updated
	go console.SpinUntil(m.output.CallingModule, &m.CommandCounter, spinnerDone, "regions")

	//create a channel to receive the objects
	dataReceiver := make(chan CFStack)

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
		"Name",
		"Role",
		// "Parameters",
		// "Outputs",
	}

	// Table rows
	for i := range m.CFStacks {
		// var isParameters string
		// var isOutputs string
		// if m.CFStacks[i].Parameters != nil {
		// 	isParameters = "Y"
		// } else {
		// 	isParameters = "N"
		// }
		// if m.CFStacks[i].Outputs != nil {
		// 	isOutputs = "Y"
		// } else {
		// 	isOutputs = "N"
		// }

		m.output.Body = append(
			m.output.Body,
			[]string{
				m.CFStacks[i].AWSService,
				m.CFStacks[i].Region,
				m.CFStacks[i].Name,
				m.CFStacks[i].Role,
				// isParameters,
				// isOutputs,
			},
		)

	}
	if len(m.output.Body) > 0 {
		m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", m.AWSProfile)
		//m.output.OutputSelector(outputFormat)
		utils.OutputSelector(verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.CallingModule, m.output.CallingModule)
		m.writeLoot(m.output.FilePath, verbosity)
		fmt.Printf("[%s][%s] %s cloudformation stacks found.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), strconv.Itoa(len(m.output.Body)))
	} else {
		fmt.Printf("[%s][%s] No cloudformation stacks found, skipping the creation of an output file.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	}

}

func (m *CloudformationModule) executeChecks(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan CFStack) {
	defer wg.Done()

	m.CommandCounter.Total++
	wg.Add(1)
	m.getCFStacksPerRegion(r, wg, semaphore, dataReceiver)
}

func (m *CloudformationModule) Receiver(receiver chan CFStack, receiverDone chan bool) {
	defer close(receiverDone)
	for {
		select {
		case data := <-receiver:
			m.CFStacks = append(m.CFStacks, data)
		case <-receiverDone:
			receiverDone <- true
			return
		}
	}
}

func (m *CloudformationModule) writeLoot(outputDirectory string, verbosity int) {
	path := filepath.Join(outputDirectory, "loot")
	err := os.MkdirAll(path, os.ModePerm)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
	}
	pullFile := filepath.Join(path, "cloudformation-data.txt")

	var out string
	out = out + fmt.Sprintln("#############################################")
	out = out + fmt.Sprintln("# Look for secrets. Use something like trufflehog")
	out = out + fmt.Sprintln("#############################################")
	out = out + fmt.Sprintln("")

	for _, stack := range m.CFStacks {
		out = out + fmt.Sprintf("=============================================\n")
		out = out + fmt.Sprintf("Stack Name: %s\n\n", stack.Name)
		out = out + fmt.Sprintf("Stack Outputs:\n\n")
		for _, output := range stack.Outputs {
			outputDescription := aws.ToString(output.Description)
			outputExport := aws.ToString(output.ExportName)
			outputKey := aws.ToString(output.OutputKey)
			outputValue := aws.ToString(output.OutputValue)
			out = out + fmt.Sprintf("Stack Output Description: %s\n", outputDescription)
			out = out + fmt.Sprintf("Stack Output Name: %s\n", outputExport)
			out = out + fmt.Sprintf("Stack Output Key: %s\n", outputKey)
			out = out + fmt.Sprintf("Stack Output Value: %s\n\n", outputValue)
		}
		out = out + fmt.Sprintf("Stack Parameters:\n\n")
		for _, param := range stack.Parameters {
			paramKey := aws.ToString(param.ParameterKey)
			paramValue := aws.ToString(param.ParameterValue)
			out = out + fmt.Sprintf("Stack Parameter Key: %s\n", paramKey)
			out = out + fmt.Sprintf("Stack Parameter Value: %s\n\n", paramValue)
		}
		//out = out + fmt.Sprintf("Stack Parameters:\n %s\n", stack.Parameters)
		out = out + fmt.Sprintf("Stack Template:\n %s\n", stack.Template)
		out = out + fmt.Sprintf("=============================================\n")

	}
	err = os.WriteFile(pullFile, []byte(out), 0644)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
	}

	if verbosity > 2 {
		fmt.Println()
		fmt.Printf("[%s][%s] %s \n", cyan(m.output.CallingModule), cyan(m.AWSProfile), green("Look for secrets. Use something like trufflehog"))
		fmt.Print(out)
		fmt.Printf("[%s][%s] %s \n", cyan(m.output.CallingModule), cyan(m.AWSProfile), green("Look for secrets. Use something like trufflehog"))
		fmt.Printf("[%s][%s] %s \n\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), green("End of loot file."))
	}

	fmt.Printf("[%s][%s] Loot written to [%s]\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), pullFile)

}

func (m *CloudformationModule) getCFStacksPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan CFStack) {
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
		DescribeStacks, err := m.CloudFormationClient.DescribeStacks(
			context.TODO(),
			&cloudformation.DescribeStacksInput{
				NextToken: PaginationControl,
			},
			func(o *cloudformation.Options) {
				o.Region = r
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}
		//var stackOutputs []types.Output
		for _, stack := range DescribeStacks.Stacks {
			stackName := aws.ToString(stack.StackName)
			stackRole := aws.ToString(stack.RoleARN)
			stackOutputs := stack.Outputs
			stackParameters := stack.Parameters

			for {
				GetTemplate, err := m.CloudFormationClient.GetTemplate(
					context.TODO(),
					&cloudformation.GetTemplateInput{
						StackName: &stackName,
					},
					func(o *cloudformation.Options) {
						o.Region = r
					},
				)
				if err != nil {
					m.modLog.Error(err.Error())
					m.CommandCounter.Error++
					break
				}

				stackTemplateBody := aws.ToString(GetTemplate.TemplateBody)

				dataReceiver <- CFStack{
					AWSService: "cloudformation",
					Name:       stackName,
					Region:     r,
					Role:       stackRole,
					Outputs:    stackOutputs,
					Parameters: stackParameters,
					Template:   stackTemplateBody,
				}

				// }
				break
			}

		}

		// The "NextToken" value is nil when there's no more data to return.
		if DescribeStacks.NextToken != nil {
			PaginationControl = DescribeStacks.NextToken
		} else {
			PaginationControl = nil
			break
		}
	}
}
