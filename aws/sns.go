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

	"github.com/BishopFox/cloudfox/internal"
	"github.com/BishopFox/cloudfox/internal/aws/policy"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/bishopfox/awsservicemap"
	"github.com/sirupsen/logrus"
)

type SNSModule struct {
	// General configuration data
	SNSClient AWSSNSClient

	StorePolicies bool

	Caller       sts.GetCallerIdentityOutput
	AWSRegions   []string
	OutputFormat string
	Goroutines   int
	AWSProfile   string
	WrapTable    bool

	// Main module data
	Topics         []SNSTopic
	CommandCounter internal.CommandCounter
	// Used to store output data for pretty printing
	output internal.OutputData2
	modLog *logrus.Entry
}

type AWSSNSClient interface {
	ListTopics(ctx context.Context, params *sns.ListTopicsInput, optFns ...func(*sns.Options)) (*sns.ListTopicsOutput, error)
	GetTopicAttributes(ctx context.Context, params *sns.GetTopicAttributesInput, optFns ...func(*sns.Options)) (*sns.GetTopicAttributesOutput, error)
}

type SNSTopic struct {
	ARN string

	Policy                policy.Policy
	PolicyJSON            string
	IsPublic              string
	IsConditionallyPublic string
}

func (m *SNSModule) PrintSNS(outputFormat string, outputDirectory string, verbosity int) {
	// These stuct values are used by the output module
	m.output.Verbosity = verbosity
	m.output.Directory = outputDirectory
	m.output.CallingModule = "sns"
	m.modLog = internal.TxtLog.WithFields(logrus.Fields{
		"module": m.output.CallingModule,
	})
	m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", m.AWSProfile)
	if m.AWSProfile == "" {
		m.AWSProfile = internal.BuildAWSPath(m.Caller)
	}

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
		"Public",
		"Cond. Public",
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
				m.Topics[i].IsConditionallyPublic,
			},
		)

	}
	if len(m.output.Body) > 0 {
		//m.output.OutputSelector(outputFormat)
		internal.OutputSelector(verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.CallingModule, m.output.CallingModule, m.WrapTable, m.AWSProfile)
		fmt.Printf("[%s][%s] %s topics found.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), strconv.Itoa(len(m.output.Body)))
		if m.StorePolicies {
			fmt.Printf("[%s][%s] Access policies stored to: %s\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), m.getLootDir())
		}
	} else {
		fmt.Printf("[%s][%s] No topics found, skipping the creation of an output file.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	}

}

func (m *SNSModule) executeChecks(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan SNSTopic) {
	defer wg.Done()

	servicemap := &awsservicemap.AwsServiceMap{
		JsonFileSource: "EMBEDDED_IN_PACKAGE",
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
	// "PaginationMarker" is a control variable used for output continuity, as AWS return the output in pages.
	var PaginationControl *string

	for {
		ListTopics, err := m.SNSClient.ListTopics(
			context.TODO(),
			&sns.ListTopicsInput{
				NextToken: PaginationControl,
			},
			func(o *sns.Options) {
				o.Region = r
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		for _, t := range ListTopics.Topics {
			topic, err := m.getTopicWithAttributes(aws.ToString(t.TopicArn), r)
			if err != nil {
				m.modLog.Error(err.Error())
				m.CommandCounter.Error++
				break
			}

			if !topic.Policy.IsEmpty() {
				m.analyseTopicPolicy(topic)
			}

			dataReceiver <- *topic

		}

		// The "NextToken" value is nil when there's no more data to return.
		if ListTopics.NextToken != nil {
			PaginationControl = ListTopics.NextToken
		} else {
			PaginationControl = nil
			break
		}
	}
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

func (m *SNSModule) analyseTopicPolicy(topic *SNSTopic) {
	if topic.Policy.IsPublic() {
		topic.IsPublic = "public"

		if m.StorePolicies {
			m.storeAccessPolicy("public", topic)
		}

	}
	if topic.Policy.IsConditionallyPublic() {
		topic.IsConditionallyPublic = "public-wc"

		if m.StorePolicies {
			m.storeAccessPolicy("public-wc", topic)
		}
	}
}

func (m *SNSModule) storeAccessPolicy(dir string, topic *SNSTopic) {
	f := filepath.Join(m.getLootDir(), dir, fmt.Sprintf("%s.json", m.getTopicName(topic.ARN)))

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
