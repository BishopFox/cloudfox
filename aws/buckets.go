package aws

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/BishopFox/cloudfox/internal/aws/policy"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/sirupsen/logrus"
)

type S3ListBucketsAPI interface {
	ListBuckets(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
}

type S3GetBucketPolicyAPI interface {
	GetBucketPolicy(ctx context.Context, params *s3.GetBucketPolicyInput, optFns ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error)
}

type S3GetBucketLocationAPI interface {
	GetBucketLocation(ctx context.Context, params *s3.GetBucketLocationInput, optFns ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error)
}

type S3GetPublicAccessBlockAPI interface {
	GetPublicAccessBlock(ctx context.Context, params *s3.GetPublicAccessBlockInput, optFns ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error)
}

type BucketsModule struct {
	// General configuration data
	S3Client *s3.Client

	// This interface is used for unit testing
	S3ClientListBucketsInterface          S3ListBucketsAPI
	S3ClientGetBucketPolicyInterface      S3GetBucketPolicyAPI
	S3ClientGetBucketLocationInterface    S3GetBucketLocationAPI
	S3ClientGetPublicAccessBlockInterface S3GetPublicAccessBlockAPI

	Caller       sts.GetCallerIdentityOutput
	AWSRegions   []string
	OutputFormat string
	Goroutines   int
	AWSProfile   string
	WrapTable    bool

	// Main module data
	Buckets        []Bucket
	CommandCounter internal.CommandCounter
	// Used to store output data for pretty printing
	output internal.OutputData2
	modLog *logrus.Entry
}

type Bucket struct {
	Arn                   string
	AWSService            string
	Region                string
	Name                  string
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

func (m *BucketsModule) PrintBuckets(outputFormat string, outputDirectory string, verbosity int) {
	// These stuct values are used by the output module
	m.output.Verbosity = verbosity
	m.output.Directory = outputDirectory
	m.output.CallingModule = "buckets"
	m.modLog = internal.TxtLog.WithFields(logrus.Fields{
		"module": m.output.CallingModule,
	})
	m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", m.AWSProfile)

	if m.AWSProfile == "" {
		m.AWSProfile = internal.BuildAWSPath(m.Caller)
	}

	fmt.Printf("[%s][%s] Enumerating buckets for account %s.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), aws.ToString(m.Caller.Account))

	wg := new(sync.WaitGroup)
	semaphore := make(chan struct{}, m.Goroutines)

	// Create a channel to signal the spinner aka task status goroutine to finish
	spinnerDone := make(chan bool)
	//fire up the the task status spinner/updated
	go internal.SpinUntil(m.output.CallingModule, &m.CommandCounter, spinnerDone, "tasks")

	//create a channel to receive the objects
	dataReceiver := make(chan Bucket)

	// Create a channel to signal to stop
	receiverDone := make(chan bool)

	go m.Receiver(dataReceiver, receiverDone)

	wg.Add(1)
	m.CommandCounter.Pending++
	go m.executeChecks(wg, semaphore, dataReceiver)

	wg.Wait()
	//time.Sleep(time.Second * 2)

	// Send a message to the spinner goroutine to close the channel and stop
	spinnerDone <- true
	<-spinnerDone
	receiverDone <- true
	<-receiverDone

	// add - if struct is not empty do this. otherwise, dont write anything.
	m.output.Headers = []string{
		//"Service",
		"Public?",
		//"Arn",
		"Name",
		"Region",
		//"Stmt",
		//"Who?",
		//"Cond. Public",
		//"Can do what?",
		//"Conditions?",
		"Resource Policy Summary",
	}

	// Table rows
	for i := range m.Buckets {
		m.output.Body = append(
			m.output.Body,
			[]string{
				//m.Buckets[i].AWSService,
				m.Buckets[i].IsPublic,
				m.Buckets[i].Name,
				m.Buckets[i].Region,
				//m.Buckets[i].Arn,
				//m.Buckets[i].Statement,
				//m.Buckets[i].Access,
				//m.Buckets[i].IsConditionallyPublic,
				//m.Buckets[i].Actions,
				//m.Buckets[i].ConditionText,
				m.Buckets[i].ResourcePolicySummary,
			},
		)

	}
	if len(m.output.Body) > 0 {
		internal.OutputSelector(verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.CallingModule, m.output.CallingModule, m.WrapTable, m.AWSProfile)
		m.writeLoot(m.output.FilePath, verbosity, m.AWSProfile)
		fmt.Printf("[%s][%s] %s buckets found.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), strconv.Itoa(len(m.output.Body)))
		fmt.Printf("[%s][%s] Bucket policies written to: %s\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), m.getLootDir())

	} else {
		fmt.Printf("[%s][%s] No buckets found, skipping the creation of an output file.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	}
	fmt.Printf("[%s][%s] For context and next steps: https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#%s\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), m.output.CallingModule)
}

func (m *BucketsModule) Receiver(receiver chan Bucket, receiverDone chan bool) {
	defer close(receiverDone)
	for {
		select {
		case data := <-receiver:
			m.Buckets = append(m.Buckets, data)
		case <-receiverDone:
			receiverDone <- true
			return
		}
	}
}

func (m *BucketsModule) executeChecks(wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Bucket) {
	defer wg.Done()

	m.CommandCounter.Total++
	wg.Add(1)
	m.createBucketsRows(m.output.Verbosity, wg, semaphore, dataReceiver)
	m.CommandCounter.Executing--
	m.CommandCounter.Complete++
}

func (m *BucketsModule) writeLoot(outputDirectory string, verbosity int, profile string) {
	path := filepath.Join(outputDirectory, "loot")
	err := os.MkdirAll(path, os.ModePerm)
	if err != nil {
		m.modLog.Error(err.Error())
	}
	pullFile := filepath.Join(path, "bucket-commands.txt")

	var out string
	out = out + fmt.Sprintln("#############################################")
	out = out + fmt.Sprintln("# The profile you will use to perform these commands is most likely not the profile you used to run CloudFox")
	out = out + fmt.Sprintln("# Set the $profile environment variable to the profile you are going to use to inspect the buckets.")
	out = out + fmt.Sprintln("# E.g., export profile=dev-prod.")
	out = out + fmt.Sprintln("#############################################")
	out = out + fmt.Sprintln("")

	for _, bucket := range m.Buckets {

		out = out + fmt.Sprintln("# "+strings.Repeat("-", utf8.RuneCountInString(bucket.Name)+8))
		out = out + fmt.Sprintf("# Bucket: %s\n", bucket.Name)
		out = out + fmt.Sprintln("# Recursively list all file names")
		out = out + fmt.Sprintf("aws --profile $profile s3 ls --human-readable --summarize --recursive --page-size 1000 s3://%s/\n", bucket.Name)
		out = out + fmt.Sprintln("# Download entire bucket (do this with caution as some buckets are HUGE)")
		out = out + fmt.Sprintf("mkdir -p ./s3-buckets/%s\n", bucket.Name)
		out = out + fmt.Sprintf("aws --profile $profile s3 cp s3://%s/ ./s3-buckets/%s --recursive\n\n", bucket.Name, bucket.Name)

	}

	err = os.WriteFile(pullFile, []byte(out), 0644)
	if err != nil {
		m.modLog.Error(err.Error())
	}

	if verbosity > 2 {
		fmt.Println()
		fmt.Printf("[%s][%s] %s \n", cyan(m.output.CallingModule), cyan(m.AWSProfile), green("Use the commands below to manually inspect certain buckets of interest."))
		fmt.Print(out)
		fmt.Printf("[%s][%s] %s \n", cyan(m.output.CallingModule), cyan(m.AWSProfile), green("End of loot file."))
	}

	fmt.Printf("[%s][%s] Loot written to [%s]\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), pullFile)

}

func (m *BucketsModule) createBucketsRows(verbosity int, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Bucket) {
	defer func() {
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
		wg.Done()

	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	var region string = "Global"
	var name string
	ListBuckets, err := m.listBuckets()
	if err != nil {
		m.modLog.Error(err.Error())
		return
	}

	for _, b := range ListBuckets {
		bucket := &Bucket{
			Name:       aws.ToString(b.Name),
			AWSService: "S3",
		}
		region, err = m.getBucketRegion(aws.ToString(b.Name))
		if err != nil {
			m.modLog.Error(err.Error())
		}
		bucket.Region = region

		policyJSON, err := m.getBucketPolicy(aws.ToString(b.Name))
		if err != nil {
			m.modLog.Error(err.Error())
		} else {
			bucket.PolicyJSON = policyJSON
		}

		policy, err := policy.ParseJSONPolicy([]byte(policyJSON))
		if err != nil {
			m.modLog.Error("parsing bucket access policy (%s) as JSON: %s", name, err)
		} else {
			bucket.Policy = policy
		}

		bucket.IsPublic = "No"
		if !bucket.Policy.IsEmpty() {
			m.analyseBucketPolicy(bucket, dataReceiver)
		} else {
			bucket.Access = "No resource policy"
			dataReceiver <- *bucket
		}

		// Send Bucket object through the channel to the receiver

	}

}

func (m *BucketsModule) listBuckets() ([]types.Bucket, error) {

	var buckets []types.Bucket
	ListBuckets, err := m.S3ClientListBucketsInterface.ListBuckets(
		context.TODO(),
		&s3.ListBucketsInput{},
	)
	if err != nil {
		m.modLog.Error(err.Error())
		return buckets, err
	}

	buckets = append(buckets, ListBuckets.Buckets...)
	return buckets, nil

}

func (m *BucketsModule) getBucketRegion(bucketName string) (string, error) {
	GetBucketRegion, err := m.S3ClientGetBucketLocationInterface.GetBucketLocation(
		context.TODO(),
		&s3.GetBucketLocationInput{
			Bucket: &bucketName,
		},
	)
	if err != nil {
		m.modLog.Error(err.Error())
		return "", err
	}
	location := string(GetBucketRegion.LocationConstraint)
	if location == "" {
		location = "us-east-1"
	}
	return location, err
}

func (m *BucketsModule) getBucketPolicy(bucketName string) (string, error) {

	r, err := m.getBucketRegion(bucketName)
	if err != nil {
		m.modLog.Error(err.Error())
		return "", err
	}
	BucketPolicyObject, err := m.S3ClientGetBucketPolicyInterface.GetBucketPolicy(
		context.TODO(),
		&s3.GetBucketPolicyInput{
			Bucket: &bucketName,
		},
		func(o *s3.Options) {
			o.Region = r
		},
	)
	if err != nil {
		m.modLog.Error(err.Error())
		return "", err
	}

	return *BucketPolicyObject.Policy, nil

}

func (m *BucketsModule) getPublicAccessBlock(bucketName string) (*types.PublicAccessBlockConfiguration, error) {
	r, err := m.getBucketRegion(bucketName)
	PublicAccessBlock, err := m.S3ClientGetPublicAccessBlockInterface.GetPublicAccessBlock(
		context.TODO(),
		&s3.GetPublicAccessBlockInput{
			Bucket: &bucketName,
		},
		func(o *s3.Options) {
			o.Region = r
		},
	)
	if err != nil {
		m.modLog.Error(err.Error())
		return nil, err
	}
	return PublicAccessBlock.PublicAccessBlockConfiguration, err
}

func (m *BucketsModule) isPublicAccessBlocked(bucketName string) bool {
	publicAccessBlock, err := m.getPublicAccessBlock(bucketName)
	if err != nil {
		return false
	}
	return publicAccessBlock.IgnorePublicAcls

}

func (m *BucketsModule) analyseBucketPolicy(bucket *Bucket, dataReceiver chan Bucket) {
	m.storeAccessPolicy(bucket)

	if bucket.Policy.IsPublic() && !bucket.Policy.IsConditionallyPublic() && !m.isPublicAccessBlocked(bucket.Name) {
		bucket.IsPublic = "YES"
	}

	for i, statement := range bucket.Policy.Statement {
		var prefix string = ""
		if len(bucket.Policy.Statement) > 1 {
			prefix = fmt.Sprintf("Statement %d says: ", i)
			bucket.ResourcePolicySummary = bucket.ResourcePolicySummary + prefix + statement.GetStatementSummaryInEnglish(*m.Caller.Account)
		} else {
			bucket.ResourcePolicySummary = statement.GetStatementSummaryInEnglish(*m.Caller.Account)
		}

	}
	dataReceiver <- *bucket

}

func (m *BucketsModule) storeAccessPolicy(bucket *Bucket) {
	f := filepath.Join(m.getLootDir(), fmt.Sprintf("%s.json", bucket.Name))

	if err := m.storeFile(f, bucket.PolicyJSON); err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
	}
}

func (m *BucketsModule) getLootDir() string {
	return filepath.Join(m.output.FilePath, "loot", "bucket-policies")
}

func (m *BucketsModule) storeFile(filename string, policy string) error {
	err := os.MkdirAll(filepath.Dir(filename), 0750)
	if err != nil && !os.IsExist(err) {
		return fmt.Errorf("creating parent dirs: %s", err)
	}

	return os.WriteFile(filename, []byte(policy), 0644)

}
