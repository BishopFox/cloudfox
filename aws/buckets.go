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

	"github.com/BishopFox/cloudfox/console"
	"github.com/BishopFox/cloudfox/utils"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/sirupsen/logrus"
)

type S3ListBucketsAPI interface {
	ListBuckets(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
}
type BucketsModule struct {
	// General configuration data
	S3Client *s3.Client

	// This interface is used for unit testing
	S3ClientListBucketsInterface S3ListBucketsAPI

	Caller       sts.GetCallerIdentityOutput
	AWSRegions   []string
	OutputFormat string
	Goroutines   int
	AWSProfile   string
	WrapTable    bool

	// Main module data
	Buckets        []Bucket
	CommandCounter console.CommandCounter
	// Used to store output data for pretty printing
	output utils.OutputData2
	modLog *logrus.Entry
}

type Bucket struct {
	AWSService string
	Region     string
	Name       string
}

func (m *BucketsModule) PrintBuckets(outputFormat string, outputDirectory string, verbosity int) {
	// These stuct values are used by the output module
	m.output.Verbosity = verbosity
	m.output.Directory = outputDirectory
	m.output.CallingModule = "buckets"
	m.modLog = utils.TxtLog.WithFields(logrus.Fields{
		"module": m.output.CallingModule,
	})

	if m.AWSProfile == "" {
		m.AWSProfile = utils.BuildAWSPath(m.Caller)
	}

	fmt.Printf("[%s][%s] Enumerating buckets for account %s.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), aws.ToString(m.Caller.Account))

	wg := new(sync.WaitGroup)
	semaphore := make(chan struct{}, m.Goroutines)

	// Create a channel to signal the spinner aka task status goroutine to finish
	spinnerDone := make(chan bool)
	//fire up the the task status spinner/updated
	go console.SpinUntil(m.output.CallingModule, &m.CommandCounter, spinnerDone, "tasks")

	//create a channel to receive the objects
	dataReceiver := make(chan Bucket)

	go m.Receiver(dataReceiver)

	wg.Add(1)
	m.CommandCounter.Pending++
	go m.executeChecks(wg, semaphore, dataReceiver)

	wg.Wait()
	// Send a message to the spinner goroutine to close the channel and stop
	spinnerDone <- true
	<-spinnerDone
	close(dataReceiver)

	// add - if struct is not empty do this. otherwise, dont write anything.
	m.output.Headers = []string{"Service", "Region", "Name"}

	// Table rows
	for i := range m.Buckets {
		m.output.Body = append(
			m.output.Body,
			[]string{
				m.Buckets[i].AWSService,
				m.Buckets[i].Region,
				m.Buckets[i].Name,
			},
		)

	}
	if len(m.output.Body) > 0 {
		m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", m.AWSProfile)
		////m.output.OutputSelector(outputFormat)
		//utils.OutputSelector(verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.CallingModule, m.output.CallingModule)
		utils.OutputSelector(verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.CallingModule, m.output.CallingModule, m.WrapTable)
		m.writeLoot(m.output.FilePath, verbosity, m.AWSProfile)
		fmt.Printf("[%s][%s] %s buckets found.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), strconv.Itoa(len(m.output.Body)))

	} else {
		fmt.Printf("[%s][%s] No buckets found, skipping the creation of an output file.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	}

}

func (m *BucketsModule) Receiver(receiver chan Bucket) {
	for data := range receiver {
		m.Buckets = append(m.Buckets, data)

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
	var r string = "Global"
	var name string
	ListBuckets, err := m.listBuckets()
	if err != nil {
		m.modLog.Error(err.Error())
		return
	}

	for _, bucket := range ListBuckets {
		name = aws.ToString(bucket.Name)
		// Send Bucket object through the channel to the receiver
		dataReceiver <- Bucket{
			AWSService: "S3",
			Name:       name,
			Region:     r,
		}
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
