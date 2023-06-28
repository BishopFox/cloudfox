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
	"unicode/utf8"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/BishopFox/cloudfox/internal/aws/policy"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/bishopfox/awsservicemap"
	"github.com/sirupsen/logrus"
)

type SQSModule struct {
	// General configuration data
	SQSClient AWSSQSClient

	StorePolicies bool

	Caller       sts.GetCallerIdentityOutput
	AWSRegions   []string
	OutputFormat string
	Goroutines   int
	AWSProfile   string
	WrapTable    bool

	// Main module data
	Queues         []Queue
	CommandCounter internal.CommandCounter
	// Used to store output data for pretty printing
	output internal.OutputData2
	modLog *logrus.Entry
}

type AWSSQSClient interface {
	ListQueues(ctx context.Context, params *sqs.ListQueuesInput, optFns ...func(*sqs.Options)) (*sqs.ListQueuesOutput, error)
	GetQueueAttributes(ctx context.Context, params *sqs.GetQueueAttributesInput, optFns ...func(*sqs.Options)) (*sqs.GetQueueAttributesOutput, error)
}

type Queue struct {
	URL                   string
	Name                  string
	Arn                   string
	Region                string
	Policy                policy.Policy
	PolicyJSON            string
	Access                string
	IsPublic              string
	IsConditionallyPublic string
	Statement             string
	Actions               string
	ConditionText         string
	ResourcePolicySummary string
}

func (m *SQSModule) PrintSQS(outputFormat string, outputDirectory string, verbosity int) {
	// These stuct values are used by the output module
	m.output.Verbosity = verbosity
	m.output.Directory = outputDirectory
	m.output.CallingModule = "sqs"
	m.modLog = internal.TxtLog.WithFields(logrus.Fields{
		"module": m.output.CallingModule,
	})
	if m.AWSProfile == "" {
		m.AWSProfile = internal.BuildAWSPath(m.Caller)
	}
	m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", fmt.Sprintf("%s-%s", m.AWSProfile, aws.ToString(m.Caller.Account)))

	fmt.Printf("[%s][%s] Enumerating SQS queues for account %s.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), aws.ToString(m.Caller.Account))

	wg := new(sync.WaitGroup)
	semaphore := make(chan struct{}, m.Goroutines)

	// Create a channel to signal the spinner aka task status goroutine to finish
	spinnerDone := make(chan bool)
	//fire up the the task status spinner/updated
	go internal.SpinUntil(m.output.CallingModule, &m.CommandCounter, spinnerDone, "regions")

	//create a channel to receive the objects
	dataReceiver := make(chan Queue)

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
		"Arn",
		"Public?",
		"Resource Policy Summary",
	}

	sort.SliceStable(m.Queues, func(i, j int) bool {
		return m.Queues[i].URL < m.Queues[j].URL
	})

	// Table rows
	for i := range m.Queues {
		m.output.Body = append(
			m.output.Body,
			[]string{
				m.Queues[i].Arn,
				m.Queues[i].IsPublic,
				m.Queues[i].ResourcePolicySummary,
			},
		)

	}
	if len(m.output.Body) > 0 {
		//m.output.OutputSelector(outputFormat)
		//internal.OutputSelector(verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.CallingModule, m.output.CallingModule, m.WrapTable, m.AWSProfile)
		//m.writeLoot(m.output.FilePath, verbosity, m.AWSProfile)
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
		o.Table.DirectoryName = filepath.Join(outputDirectory, "cloudfox-output", "aws", fmt.Sprintf("%s-%s", m.AWSProfile, aws.ToString(m.Caller.Account)))
		o.WriteFullOutput(o.Table.TableFiles, nil)
		m.writeLoot(o.Table.DirectoryName, verbosity, m.AWSProfile)
		fmt.Printf("[%s][%s] %s queues found.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), strconv.Itoa(len(m.output.Body)))
		fmt.Printf("[%s][%s] Access policies stored to: %s\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), m.getLootDir())
	} else {
		fmt.Printf("[%s][%s] No queues found, skipping the creation of an output file.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	}
	fmt.Printf("[%s][%s] For context and next steps: https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#%s\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), m.output.CallingModule)

}

func (m *SQSModule) executeChecks(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Queue) {
	defer wg.Done()
	servicemap := &awsservicemap.AwsServiceMap{
		JsonFileSource: "DOWNLOAD_FROM_AWS",
	}
	res, err := servicemap.IsServiceInRegion("sqs", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		m.getSQSRecordsPerRegion(r, wg, semaphore, dataReceiver)
	}
}
func (m *SQSModule) Receiver(receiver chan Queue, receiverDone chan bool) {
	defer close(receiverDone)
	for {
		select {
		case data := <-receiver:
			m.Queues = append(m.Queues, data)
		case <-receiverDone:
			receiverDone <- true
			return
		}
	}
}

func (m *SQSModule) writeLoot(outputDirectory string, verbosity int, profile string) {
	path := filepath.Join(outputDirectory, "loot")
	err := os.MkdirAll(path, os.ModePerm)
	if err != nil {
		m.modLog.Error(err.Error())
	}
	lootCommandsFile := filepath.Join(path, "sqs-commands.txt")

	var out string
	out = out + fmt.Sprintln("#############################################")
	out = out + fmt.Sprintln("# The profile you will use to perform these commands is most likely not the profile you used to run CloudFox")
	out = out + fmt.Sprintln("# Set the $profile environment variable to the profile you are going to use to inspect the buckets.")
	out = out + fmt.Sprintln("# E.g., export profile=dev-prod.")
	out = out + fmt.Sprintln("#############################################")
	out = out + fmt.Sprintln("")

	for _, queue := range m.Queues {

		out = out + fmt.Sprintln("# "+strings.Repeat("-", utf8.RuneCountInString(queue.Name)+7))
		out = out + fmt.Sprintf("# Queue: %s\n", queue.Name)
		out = out + fmt.Sprintln("# "+strings.Repeat("-", utf8.RuneCountInString(queue.Name)+7))
		out = out + fmt.Sprintln("# Receive a message from the queue ")
		out = out + fmt.Sprintln("")
		out = out + fmt.Sprintln("# WARNING: The following command can cause adverse effects in the environment. In production environments, use this command with caution")
		out = out + fmt.Sprintln("# WARNING: and in coordination with application owners. Receiving a message does not delete it from the queue, but this action")
		out = out + fmt.Sprintln("# WARNING: can potentially cause latency or it could DoS applications that consume the queue messages")
		out = out + fmt.Sprintln("")
		out = out + fmt.Sprintf("aws --profile $profile --region %s sqs receive-message --queue-url  %s --attribute-names All --message-attribute-names All --max-number-of-messages 5 --visibility-timeout 0\n\n", queue.Region, queue.URL)
		out = out + fmt.Sprintln("# Send a message to the queue without attributes file")
		out = out + fmt.Sprintln("")
		out = out + fmt.Sprintln("# WARNING: The following command can cause adverse effects in the environment. Like fuzzing a web application, if you inject")
		out = out + fmt.Sprintln("# WARNING: malicious data you might find a vulnerability, but you also might break something. Unless you really know how the")
		out = out + fmt.Sprintln("# WARNING: messages are consumed, you should leave fuzzing to non-production environments.")
		out = out + fmt.Sprintf("aws --profile $profile --region %s sqs send-message --queue-url %s --message-body \"[INSERT MESSAGE BODY]\"\n\n", queue.Region, queue.URL)
		out = out + fmt.Sprintln("")
		out = out + fmt.Sprintln("# Send message to the queue with attributes file (You'll have to create and populate the file)")
		out = out + fmt.Sprintln("")
		out = out + fmt.Sprintln("# WARNING: The following command can cause adverse effects in the environment. Like fuzzing a web application, if you inject")
		out = out + fmt.Sprintln("# WARNING: malicious data you might find a vulnerability, but you also might break something. Unless you really know how the")
		out = out + fmt.Sprintln("# WARNING: messages are consumed, you should leave fuzzing to non-production environments.")
		out = out + fmt.Sprintf("aws --profile $profile --region %s sqs send-message --queue-url %s --message-body \"[INSERT MESSAGE BODY] --message-attributes file://./file.json\"\n\n", queue.Region, queue.URL)

	}

	err = os.WriteFile(lootCommandsFile, []byte(out), 0644)
	if err != nil {
		m.modLog.Error(err.Error())
	}

	if verbosity > 2 {
		fmt.Println()
		fmt.Printf("[%s][%s] %s \n", cyan(m.output.CallingModule), cyan(m.AWSProfile), green("Use the commands below to send/receive sqs messages if you have right permissions."))
		fmt.Print(out)
		fmt.Printf("[%s][%s] %s \n", cyan(m.output.CallingModule), cyan(m.AWSProfile), green("End of loot file."))
	}

	fmt.Printf("[%s][%s] Loot written to [%s]\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), lootCommandsFile)

}

func (m *SQSModule) getSQSRecordsPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Queue) {
	defer func() {
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
		wg.Done()

	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()

	ListQueues, err := m.listQueues(r)

	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	for _, url := range ListQueues {
		queue, err := m.getQueueWithAttributes(url, r)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		// easier to just set the default state to be no and only flip it to yes if we have a case that matches
		queue.IsPublic = "No"

		if !queue.Policy.IsEmpty() {
			m.analyseQueuePolicy(queue, dataReceiver)
		} else {
			// If the queue policy "resource policy" is empty, the only principals that have permisisons
			// are those that are granted access by IAM policies
			//queue.Access = "Private. Access allowed by IAM policies"
			queue.Access = "Only intra-account access (via IAM) allowed"
			dataReceiver <- *queue

		}

	}

}

func (m *SQSModule) listQueues(region string) ([]string, error) {
	var PaginationControl *string
	var queues []string

	for {
		ListQueues, err := m.SQSClient.ListQueues(
			context.TODO(),
			&sqs.ListQueuesInput{
				MaxResults: aws.Int32(1000),
				NextToken:  PaginationControl,
			},
			func(o *sqs.Options) {
				o.Region = region
			},
		)
		if err != nil {
			return nil, fmt.Errorf("ListQueues() failed: %s", err)
		}

		for _, url := range ListQueues.QueueUrls {
			queues = append(queues, url)
		}

		// The "NextToken" value is nil when there's no more data to return.
		if ListQueues.NextToken != nil {
			PaginationControl = ListQueues.NextToken
		} else {
			PaginationControl = nil
			break
		}
	}

	return queues, nil
}

func (m *SQSModule) getQueueWithAttributes(queueURL string, region string) (*Queue, error) {
	queue := &Queue{
		URL: queueURL,
	}

	GetQueueAttributes, err := m.SQSClient.GetQueueAttributes(
		context.TODO(),
		&sqs.GetQueueAttributesInput{
			QueueUrl: aws.String(queueURL),
			AttributeNames: []types.QueueAttributeName{
				types.QueueAttributeNamePolicy,
				types.QueueAttributeNameQueueArn,
			},
		},
		func(o *sqs.Options) {
			o.Region = region
		},
	)
	if err != nil {
		return nil, fmt.Errorf("GetQueueAttributes(%s) failed: %s", queueURL, err)
	}

	if queueArn, ok := GetQueueAttributes.Attributes[string(types.QueueAttributeNameQueueArn)]; ok {
		parsedArn, err := arn.Parse(queueArn)
		if err != nil {
			queue.Name = queueArn
		}
		queue.Arn = queueArn
		queue.Name = parsedArn.Resource
		queue.Region = parsedArn.Region
	}

	if policyJSON, ok := GetQueueAttributes.Attributes[string(types.QueueAttributeNamePolicy)]; ok {
		policy, err := policy.ParseJSONPolicy([]byte(policyJSON))
		if err != nil {
			return nil, fmt.Errorf("parsing queue access policy (%s) as JSON: %s", queueURL, err)
		}

		queue.PolicyJSON = policyJSON
		queue.Policy = policy
	}

	return queue, nil
}

func (m *SQSModule) analyseQueuePolicy(queue *Queue, dataReceiver chan Queue) {
	m.storeAccessPolicy(queue)

	if queue.Policy.IsPublic() && !queue.Policy.IsConditionallyPublic() {
		queue.IsPublic = "YES"
	}

	for i, statement := range queue.Policy.Statement {
		var prefix string = ""
		if len(queue.Policy.Statement) > 1 {
			prefix = fmt.Sprintf("Statement %d says: ", i)
			queue.ResourcePolicySummary = queue.ResourcePolicySummary + prefix + statement.GetStatementSummaryInEnglish(*m.Caller.Account)
		} else {
			queue.ResourcePolicySummary = statement.GetStatementSummaryInEnglish(*m.Caller.Account)
		}
		queue.ResourcePolicySummary = strings.TrimSuffix(queue.ResourcePolicySummary, "\n")

	}
	dataReceiver <- *queue
}

func (m *SQSModule) storeAccessPolicy(queue *Queue) {
	f := filepath.Join(m.getLootDir(), fmt.Sprintf("%s.json", m.getQueueName(queue.URL)))

	if err := m.storeFile(f, queue.PolicyJSON); err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
	}
}

func (m *SQSModule) getLootDir() string {
	return filepath.Join(m.output.FilePath, "loot", "sqs-policies")
}

func (m *SQSModule) getQueueName(url string) string {
	tokens := strings.SplitN(url, "/", 5)
	if len(tokens) != 5 {
		return ""
	}
	return tokens[4]
}

func (m *SQSModule) storeFile(filename string, policy string) error {
	err := os.MkdirAll(filepath.Dir(filename), 0750)
	if err != nil && !os.IsExist(err) {
		return fmt.Errorf("creating parent dirs: %s", err)
	}

	return os.WriteFile(filename, []byte(policy), 0644)

}
