package aws

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/BishopFox/cloudfox/aws/sdk"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/BishopFox/cloudfox/internal/aws/policy"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/sirupsen/logrus"
)

type BucketsModule struct {
	// General configuration data
	//BucketsS3Client CloudFoxS3Client
	CheckBucketPolicies bool
	S3Client            sdk.AWSS3ClientInterface
	AWSRegions          []string
	AWSProfile          string
	Caller              sts.GetCallerIdentityOutput
	AWSTableCols        string
	AWSOutputType       string

	Goroutines int
	WrapTable  bool

	// Main module data
	Buckets        []BucketRow
	CommandCounter internal.CommandCounter
	// Used to store output data for pretty printing
	output internal.OutputData2
	modLog *logrus.Entry
}

type BucketRow struct {
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

func (m *BucketsModule) PrintBuckets(outputDirectory string, verbosity int) {
	// These struct values are used by the output module
	m.output.Verbosity = verbosity
	m.output.Directory = outputDirectory
	m.output.CallingModule = "buckets"
	m.modLog = internal.TxtLog.WithFields(logrus.Fields{
		"module": m.output.CallingModule,
	})

	if m.AWSProfile == "" {
		m.AWSProfile = internal.BuildAWSPath(m.Caller)
	}
	m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", fmt.Sprintf("%s-%s", m.AWSProfile, aws.ToString(m.Caller.Account)))

	fmt.Printf("[%s][%s] Enumerating buckets for account %s.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), aws.ToString(m.Caller.Account))

	wg := new(sync.WaitGroup)
	semaphore := make(chan struct{}, m.Goroutines)

	// Create a channel to signal the spinner aka task status goroutine to finish
	spinnerDone := make(chan bool)
	//fire up the the task status spinner/updated
	go internal.SpinUntil(m.output.CallingModule, &m.CommandCounter, spinnerDone, "tasks")

	//create a channel to receive the objects
	dataReceiver := make(chan BucketRow)

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
		"Name",
		"Region",
		"Public?",
		"Resource Policy Summary",
	}

	// Table rows
	for i := range m.Buckets {
		m.output.Body = append(
			m.output.Body,
			[]string{
				m.Buckets[i].Name,
				m.Buckets[i].Region,
				m.Buckets[i].IsPublic,
				m.Buckets[i].ResourcePolicySummary,
			},
		)
	}

	if len(m.output.Body) > 0 {
		o := internal.OutputClient{
			Verbosity:     verbosity,
			CallingModule: m.output.CallingModule,
			Table: internal.TableClient{
				Wrap: m.WrapTable,
			},
		}

		// If the user specified table columns, use those.
		// If the user specified -o wide, use the wide default cols for this module.
		// Otherwise, use the hardcoded default cols for this module.
		var tableCols []string
		// If the user specified table columns, use those.
		if m.AWSTableCols != "" {
			// remove any spaces between any commans and the first letter after the commas
			m.AWSTableCols = strings.ReplaceAll(m.AWSTableCols, ", ", ",")
			m.AWSTableCols = strings.ReplaceAll(m.AWSTableCols, ",  ", ",")
			tableCols = strings.Split(m.AWSTableCols, ",")
			// If the user specified wide as the output format, use these columns.
		} else if m.AWSOutputType == "wide" {
			tableCols = []string{"Name", "Region", "Public?", "Resource Policy Summary"}
			// Otherwise, use the default columns for this module (brief)
		} else {
			tableCols = []string{"Name", "Region", "Public?", "Resource Policy Summary"}
		}

		// Remove the Public? and Resource Policy Summary columns if the user did not specify CheckBucketPolicies
		if !m.CheckBucketPolicies {
			tableCols = removeStringFromSlice(tableCols, "Public?")
			tableCols = removeStringFromSlice(tableCols, "Resource Policy Summary")
		}

		o.Table.TableFiles = append(o.Table.TableFiles, internal.TableFile{
			Header:    m.output.Headers,
			TableCols: tableCols,
			Body:      m.output.Body,
			Name:      m.output.CallingModule,
		})
		o.PrefixIdentifier = m.AWSProfile
		o.Table.DirectoryName = filepath.Join(outputDirectory, "cloudfox-output", "aws", fmt.Sprintf("%s-%s", m.AWSProfile, aws.ToString(m.Caller.Account)))
		o.WriteFullOutput(o.Table.TableFiles, nil)
		m.writeLoot(o.Table.DirectoryName, verbosity, m.AWSProfile)

		fmt.Printf("[%s][%s] %s buckets found.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), strconv.Itoa(len(m.output.Body)))
		fmt.Printf("[%s][%s] Bucket policies written to: %s\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), m.getLootDir())

	} else {
		fmt.Printf("[%s][%s] No buckets found, skipping the creation of an output file.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	}
	fmt.Printf("[%s][%s] For context and next steps: https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#%s\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), m.output.CallingModule)
}

func (m *BucketsModule) Receiver(receiver chan BucketRow, receiverDone chan bool) {
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

func (m *BucketsModule) executeChecks(wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan BucketRow) {
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

func (m *BucketsModule) createBucketsRows(verbosity int, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan BucketRow) {
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

	ListBuckets, err := sdk.CachedListBuckets(m.S3Client, aws.ToString(m.Caller.Account))

	if err != nil {
		m.modLog.Error(err.Error())
		return
	}

	for _, b := range ListBuckets {
		bucket := &BucketRow{
			Name:       aws.ToString(b.Name),
			AWSService: "S3",
		}
		region, err = sdk.CachedGetBucketLocation(m.S3Client, aws.ToString(m.Caller.Account), aws.ToString(b.Name))
		if err != nil {
			m.modLog.Error(err.Error())
			region = "Unknown"

		}
		bucket.Region = region

		if m.CheckBucketPolicies {

			policyJSON, err := sdk.CachedGetBucketPolicy(m.S3Client, aws.ToString(m.Caller.Account), region, aws.ToString(b.Name))
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

			bucket.IsPublic = "No"
			if !bucket.Policy.IsEmpty() {
				m.analyseBucketPolicy(bucket, dataReceiver)
			} else {
				bucket.Access = "No resource policy"
				dataReceiver <- *bucket
			}
		} else {

			// Send Bucket object through the channel to the receiver
			bucket.Access = "Skipped"
			bucket.IsPublic = "Skipped"
			dataReceiver <- *bucket
		}
	}
}

func (m *BucketsModule) isPublicAccessBlocked(bucketName string, r string) bool {
	publicAccessBlock, err := sdk.CachedGetPublicAccessBlock(m.S3Client, aws.ToString(m.Caller.Account), r, bucketName)
	if err != nil {
		return false
	}
	return publicAccessBlock.IgnorePublicAcls

}

func (m *BucketsModule) analyseBucketPolicy(bucket *BucketRow, dataReceiver chan BucketRow) {
	m.storeAccessPolicy(bucket)

	if bucket.Policy.IsPublic() && !bucket.Policy.IsConditionallyPublic() && !m.isPublicAccessBlocked(bucket.Name, bucket.Region) {
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
		//bucket.ResourcePolicySummary = strings.TrimSuffix(bucket.ResourcePolicySummary, "\n")

	}
	dataReceiver <- *bucket

}

func (m *BucketsModule) storeAccessPolicy(bucket *BucketRow) {
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
