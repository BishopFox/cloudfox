package aws

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/BishopFox/cloudfox/internal/aws/policy"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/bishopfox/awsservicemap"
	"github.com/sirupsen/logrus"
)

type ResourceTrustsModule struct {
	// General configuration data
	Caller          sts.GetCallerIdentityOutput
	AWSRegions      []string
	Goroutines      int
	WrapTable       bool
	AWSProfile      string
	CloudFoxVersion string

	Resources2     []Resource2
	CommandCounter internal.CommandCounter

	output internal.OutputData2
	modLog *logrus.Entry
}

type Resource2 struct {
	AccountID             string
	Name                  string
	ARN                   string
	Region                string
	Policy                policy.Policy
	PolicyJSON            string
	ResourcePolicySummary string
}

func (m *ResourceTrustsModule) PrintResources(outputFormat string, outputDirectory string, verbosity int) {
	// These stuct values are used by the output module
	m.output.Verbosity = verbosity
	m.output.Directory = outputDirectory
	m.output.CallingModule = "resource-trusts"
	m.modLog = internal.TxtLog.WithFields(logrus.Fields{
		"module": m.output.CallingModule,
	})
	m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", m.AWSProfile)
	if m.AWSProfile == "" {
		m.AWSProfile = internal.BuildAWSPath(m.Caller)
	}

	fmt.Printf("[%s][%s] Enumerating Resources with resource policies for account %s.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), aws.ToString(m.Caller.Account))
	fmt.Printf("[%s][%s] Supported Services: CodeBuild, ECR, S3, SNS, SQS\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	wg := new(sync.WaitGroup)
	semaphore := make(chan struct{}, m.Goroutines)

	// Create a channel to signal the spinner aka task status goroutine to finish
	spinnerDone := make(chan bool)
	//fire up the the task status spinner/updated
	go internal.SpinUntil(m.output.CallingModule, &m.CommandCounter, spinnerDone, "tasks")

	//create a channel to receive the objects
	dataReceiver := make(chan Resource2)

	// Create a channel to signal to stop
	receiverDone := make(chan bool)
	go m.Receiver(dataReceiver, receiverDone)

	for _, region := range m.AWSRegions {
		wg.Add(1)
		m.CommandCounter.Pending++
		go m.executeChecks(region, wg, semaphore, dataReceiver)

	}
	wg.Add(1)
	go m.getS3Buckets(wg, semaphore, dataReceiver)

	wg.Wait()
	// Send a message to the spinner goroutine to close the channel and stop
	spinnerDone <- true
	<-spinnerDone
	// Send a message to the data receiver goroutine to close the channel and stop
	receiverDone <- true
	<-receiverDone

	// add - if struct is not empty do this. otherwise, dont write anything.
	m.output.Headers = []string{
		"Account ID",
		"ARN",
		"Resource Policy Summary",
	}

	// Table rows
	for i := range m.Resources2 {
		m.output.Body = append(
			m.output.Body,
			[]string{
				m.Resources2[i].AccountID,
				m.Resources2[i].ARN,
				m.Resources2[i].ResourcePolicySummary,
			},
		)

	}
	if len(m.output.Body) > 0 {
		internal.OutputSelector(verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.CallingModule, m.output.CallingModule, m.WrapTable, m.AWSProfile)
		//m.writeLoot(m.output.FilePath, verbosity, m.AWSProfile)
		fmt.Printf("[%s][%s] %s resource policies found.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), strconv.Itoa(len(m.output.Body)))
		//fmt.Printf("[%s][%s] Resource policies stored to: %s\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), m.getLootDir())
	} else {
		fmt.Printf("[%s][%s] No resource policies found, skipping the creation of an output file.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	}
	fmt.Printf("[%s][%s] For context and next steps: https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#%s\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), m.output.CallingModule)

}

func (m *ResourceTrustsModule) executeChecks(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Resource2) {
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

	res, err = servicemap.IsServiceInRegion("sqs", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		m.getSQSQueuesPerRegion(r, wg, semaphore, dataReceiver)
	}

	res, err = servicemap.IsServiceInRegion("ecr", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		m.getECRRecordsPerRegion(r, wg, semaphore, dataReceiver)
	}

	res, err = servicemap.IsServiceInRegion("codebuild", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		m.getCodeBuildResourcePoliciesPerRegion(r, wg, semaphore, dataReceiver)
	}

}

func (m *ResourceTrustsModule) Receiver(receiver chan Resource2, receiverDone chan bool) {
	defer close(receiverDone)
	for {
		select {
		case data := <-receiver:
			m.Resources2 = append(m.Resources2, data)
		case <-receiverDone:
			receiverDone <- true
			return
		}
	}
}

func (m *ResourceTrustsModule) getSNSTopicsPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Resource2) {
	defer wg.Done()
	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	cloudFoxSNSClient := InitCloudFoxSNSClient(m.Caller, m.AWSProfile, m.CloudFoxVersion)

	ListTopics, err := cloudFoxSNSClient.listTopics(r)
	if err != nil {
		m.modLog.Error(err.Error())
		return
	}

	for _, t := range ListTopics {
		topic, err := cloudFoxSNSClient.getTopicWithAttributes(aws.ToString(t.TopicArn), r)
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
		if !topic.Policy.IsEmpty() {
			for _, statement := range topic.Policy.Statement {
				statementInEnglish := statement.GetStatementSummaryInEnglish(*m.Caller.Account)
				// check if statementInEnglish contains an AWS ARN other than caller.Arn
				if (strings.Contains(statementInEnglish, "arn:aws") && !strings.Contains(statementInEnglish, aws.ToString(m.Caller.Account))) ||
					((strings.Contains(statementInEnglish, "AWS:SourceOwner") || strings.Contains(statementInEnglish, "AWS:SourceAccount")) && !strings.Contains(statementInEnglish, aws.ToString(m.Caller.Account))) {
					statementInEnglish := strings.TrimSuffix(statementInEnglish, "\n")
					dataReceiver <- Resource2{
						AccountID:             aws.ToString(m.Caller.Account),
						ARN:                   aws.ToString(t.TopicArn),
						ResourcePolicySummary: statementInEnglish,
					}
				}

			}

		}

	}
}

func (m *ResourceTrustsModule) getS3Buckets(wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Resource2) {
	defer wg.Done()
	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	cloudFoxS3Client := initCloudFoxS3Client(m.Caller, m.AWSProfile, m.CloudFoxVersion)

	ListBuckets, err := cloudFoxS3Client.listBuckets()
	if err != nil {
		m.modLog.Error(err.Error())
		return
	}

	for _, b := range ListBuckets {
		bucket := &Bucket{
			Arn: fmt.Sprintf("arn:aws:s3:::%s", aws.ToString(b.Name)),
		}
		name := aws.ToString(b.Name)

		policyJSON, err := cloudFoxS3Client.getBucketPolicy(aws.ToString(b.Name))
		if err != nil {
			m.modLog.Error(err.Error())
		} else {
			bucket.PolicyJSON = policyJSON
		}

		policy, err := policy.ParseJSONPolicy([]byte(policyJSON))
		if err != nil {
			m.modLog.Error(fmt.Sprintf("parsing bucket access policy (%s) as JSON: %s", name, err))
		} else {
			bucket.Policy = policy
		}
		// easier to just set the default state to be no and only flip it to yes if we have a case that matches
		bucket.IsPublic = "No"
		if !bucket.Policy.IsEmpty() {
			for _, statement := range bucket.Policy.Statement {
				statementInEnglish := statement.GetStatementSummaryInEnglish(*m.Caller.Account)
				// check if statementInEnglish contains an AWS ARN other than caller.Arn
				if (strings.Contains(statementInEnglish, "arn:aws") && !strings.Contains(statementInEnglish, aws.ToString(m.Caller.Account))) ||
					((strings.Contains(statementInEnglish, "AWS:SourceOwner") || strings.Contains(statementInEnglish, "AWS:SourceAccount")) && !strings.Contains(statementInEnglish, aws.ToString(m.Caller.Account))) {
					statementInEnglish := strings.TrimSuffix(statementInEnglish, "\n")
					dataReceiver <- Resource2{
						AccountID:             aws.ToString(m.Caller.Account),
						ARN:                   bucket.Arn,
						ResourcePolicySummary: statementInEnglish,
					}
				}
			}

		}

	}
}

func (m *ResourceTrustsModule) getSQSQueuesPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Resource2) {
	defer wg.Done()
	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	cloudFoxSQSClient := InitSQSClient(m.Caller, m.AWSProfile, m.CloudFoxVersion, m.Goroutines)

	ListQueues, err := cloudFoxSQSClient.listQueues(r)
	if err != nil {
		m.modLog.Error(err.Error())
		return
	}

	for _, q := range ListQueues {
		queue, err := cloudFoxSQSClient.getQueueWithAttributes(q, r)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		if !queue.Policy.IsEmpty() {
			for _, statement := range queue.Policy.Statement {
				statementInEnglish := statement.GetStatementSummaryInEnglish(*m.Caller.Account)
				// check if statementInEnglish contains an AWS ARN other than caller.Arn
				if (strings.Contains(statementInEnglish, "arn:aws") && !strings.Contains(statementInEnglish, aws.ToString(m.Caller.Account))) ||
					((strings.Contains(statementInEnglish, "AWS:SourceOwner") || strings.Contains(statementInEnglish, "AWS:SourceAccount")) && !strings.Contains(statementInEnglish, aws.ToString(m.Caller.Account))) {
					statementInEnglish := strings.TrimSuffix(statementInEnglish, "\n")
					dataReceiver <- Resource2{
						AccountID:             aws.ToString(m.Caller.Account),
						ARN:                   aws.ToString(&queue.Arn),
						ResourcePolicySummary: statementInEnglish,
					}
				}
			}

		}

	}
}

func (m *ResourceTrustsModule) getECRRecordsPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Resource2) {
	defer wg.Done()
	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	cloudFoxECRClient := InitECRClient(m.Caller, m.AWSProfile, m.CloudFoxVersion, m.Goroutines)

	DescribeRepositories, err := cloudFoxECRClient.describeRepositories(r)
	if err != nil {
		m.modLog.Error(err.Error())
		return
	}

	for _, repo := range DescribeRepositories {
		repoPolicy, err := cloudFoxECRClient.getECRRepositoryPolicy(r, aws.ToString(repo.RepositoryName))
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		if !repoPolicy.IsEmpty() {
			for _, statement := range repoPolicy.Statement {
				statementInEnglish := statement.GetStatementSummaryInEnglish(*m.Caller.Account)
				// check if statementInEnglish contains an AWS ARN other than caller.Arn
				if (strings.Contains(statementInEnglish, "arn:aws") && !strings.Contains(statementInEnglish, aws.ToString(m.Caller.Account))) ||
					((strings.Contains(statementInEnglish, "AWS:SourceOwner") || strings.Contains(statementInEnglish, "AWS:SourceAccount")) && !strings.Contains(statementInEnglish, aws.ToString(m.Caller.Account))) {
					statementInEnglish := strings.TrimSuffix(statementInEnglish, "\n")
					dataReceiver <- Resource2{
						AccountID:             aws.ToString(m.Caller.Account),
						ARN:                   aws.ToString(repo.RepositoryArn),
						ResourcePolicySummary: statementInEnglish,
					}
				}
			}

		}

	}
}

func (m *ResourceTrustsModule) getCodeBuildResourcePoliciesPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Resource2) {
	defer wg.Done()
	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	cloudFoxCodeBuildClient := InitCodeBuildClient(m.Caller, m.AWSProfile, m.CloudFoxVersion, m.Goroutines)

	ListProjects, err := cloudFoxCodeBuildClient.getcodeBuildProjects(r)
	if err != nil {
		m.modLog.Error(err.Error())
		return
	}

	for _, p := range ListProjects {
		project, err := cloudFoxCodeBuildClient.getProjectDetails(p, r)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		policy, err := cloudFoxCodeBuildClient.getResourcePolicy(r, p)
		if err != nil {
			m.modLog.Error(err.Error())
			return
		}

		if !policy.IsEmpty() {
			for _, statement := range policy.Statement {
				statementInEnglish := statement.GetStatementSummaryInEnglish(*m.Caller.Account)
				// check if statementInEnglish contains an AWS ARN other than caller.Arn
				if (strings.Contains(statementInEnglish, "arn:aws") && !strings.Contains(statementInEnglish, aws.ToString(m.Caller.Account))) ||
					((strings.Contains(statementInEnglish, "AWS:SourceOwner") || strings.Contains(statementInEnglish, "AWS:SourceAccount")) && !strings.Contains(statementInEnglish, aws.ToString(m.Caller.Account))) {
					statementInEnglish := strings.TrimSuffix(statementInEnglish, "\n")
					dataReceiver <- Resource2{
						AccountID:             aws.ToString(m.Caller.Account),
						ARN:                   aws.ToString(project.Arn),
						ResourcePolicySummary: statementInEnglish,
					}
				}
			}

		}

	}
}
