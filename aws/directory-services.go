package aws

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/BishopFox/cloudfox/aws/sdk"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	dsTypes "github.com/aws/aws-sdk-go-v2/service/directoryservice/types"
	"github.com/bishopfox/awsservicemap"
	"github.com/sirupsen/logrus"
)

type DirectoryModule struct {
	// General configuration data
	DSClient           sdk.AWSDSClientInterface
	Caller             sts.GetCallerIdentityOutput
	AWSRegions         []string
	AWSProfile         string
	Goroutines         int
	WrapTable          bool
	AWSOutputType      string
	AWSTableCols       string
	AWSMFAToken        string
	AWSConfig          aws.Config
	AWSProfileProvided string
	AWSProfileStub     string
	CloudFoxVersion    string
	
	Directories        []Directory
	CommandCounter     internal.CommandCounter
	output             internal.OutputData2
	modLog             *logrus.Entry
}

type Directory struct {
	DirectoryId      string
	DNS              string
	NetBios          string
	AccessURL        string
	Alias            string
	OsVersion        string
	Region           string
	TrustInfo        string
}

func (m *DirectoryModule) PrintDirectories(outputDirectory string, verbosity int) {
	// These struct values are used by the output module
	m.output.Verbosity = verbosity
	m.output.Directory = outputDirectory
	m.output.CallingModule = "directory-services"
	m.modLog = internal.TxtLog.WithFields(logrus.Fields{
		"module": m.output.CallingModule,
	})

	if m.AWSProfileProvided == "" {
		m.AWSProfileStub = internal.BuildAWSPath(m.Caller)
	} else {
		m.AWSProfileStub = m.AWSProfileProvided
	}
	m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", fmt.Sprintf("%s-%s", m.AWSProfileProvided, aws.ToString(m.Caller.Account)))

	fmt.Printf("[%s][%s] Enumerating Cloud Directories with resource policies for account %s.\n", cyan(m.output.CallingModule), cyan(m.AWSProfileStub), aws.ToString(m.Caller.Account))
	wg := new(sync.WaitGroup)
	semaphore := make(chan struct{}, m.Goroutines)

	// Create a channel to signal the spinner aka task status goroutine to finish
	spinnerDone := make(chan bool)
	//fire up the the task status spinner/updated
	go internal.SpinUntil(m.output.CallingModule, &m.CommandCounter, spinnerDone, "tasks")

	//create a channel to receive the objects
	dataReceiver := make(chan Directory)

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
		"Account",
		"Name",
		"Alias",
		"Domain",
		"NetBIOS name",
		"Access URL",
		"Version",
		"Trusts",
	}

	// If the user specified table columns, use those.
	// If the user specified -o wide, use the wide default cols for this module.
	// Otherwise, use the hardcoded default cols for this module.
	var tableCols []string
	// If the user specified table columns, use those.
	if m.AWSTableCols != "" {
		// If the user specified wide as the output format, use these columns.
		// remove any spaces between any commas and the first letter after the commas
		m.AWSTableCols = strings.ReplaceAll(m.AWSTableCols, ", ", ",")
		m.AWSTableCols = strings.ReplaceAll(m.AWSTableCols, ",  ", ",")
		tableCols = strings.Split(m.AWSTableCols, ",")
	} else if m.AWSOutputType == "wide" {
		tableCols = []string{
			"Account",
			"Name",
			"Alias",
			"Domain",
			"NetBIOS name",
			"Access URL",
			"Version",
			"Trusts",
		}
	} else {
		tableCols = []string{
			"Account",
			"Name",
			"Domain",
			"NetBIOS name",
			"Access URL",
			"Version",
			"Trusts",
		}
	}


	// Table rows
	for i := range m.Directories {
		m.output.Body = append(
			m.output.Body,
			[]string{
				aws.ToString(m.Caller.Account),
				m.Directories[i].DirectoryId,
				m.Directories[i].Alias,
				m.Directories[i].DNS,
				m.Directories[i].NetBios,
				m.Directories[i].AccessURL,
				m.Directories[i].OsVersion,
				m.Directories[i].TrustInfo,
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
		o.Table.TableFiles = append(o.Table.TableFiles, internal.TableFile{
			Header:    m.output.Headers,
			Body:      m.output.Body,
			TableCols: tableCols,
			Name:      m.output.CallingModule,
		})
		o.PrefixIdentifier = m.AWSProfileStub
		o.Table.DirectoryName = filepath.Join(outputDirectory, "cloudfox-output", "aws", fmt.Sprintf("%s-%s", m.AWSProfileStub, aws.ToString(m.Caller.Account)))
		o.WriteFullOutput(o.Table.TableFiles, nil)
		//m.writeLoot(o.Table.DirectoryName, verbosity)
		fmt.Printf("[%s][%s] %s directories found.\n", cyan(m.output.CallingModule), cyan(m.AWSProfileStub), strconv.Itoa(len(m.output.Body)))
		//fmt.Printf("[%s][%s] Resource policies stored to: %s\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), m.getLootDir())
	} else {
		fmt.Printf("[%s][%s] No directories found, skipping the creation of an output file.\n", cyan(m.output.CallingModule), cyan(m.AWSProfileStub))
	}
	fmt.Printf("[%s][%s] For context and next steps: https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#%s\n", cyan(m.output.CallingModule), cyan(m.AWSProfileStub), m.output.CallingModule)

}

func (m *DirectoryModule) executeChecks(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Directory) {
	defer wg.Done()

	servicemap := &awsservicemap.AwsServiceMap{
		JsonFileSource: "DOWNLOAD_FROM_AWS",
	}
	res, err := servicemap.IsServiceInRegion("clouddirectory", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		m.getDirectoriesPerRegion(r, wg, semaphore, dataReceiver)
	}
}

func (m *DirectoryModule) Receiver(receiver chan Directory, receiverDone chan bool) {
	defer close(receiverDone)
	for {
		select {
		case data := <-receiver:
			m.Directories = append(m.Directories, data)
		case <-receiverDone:
			receiverDone <- true
			return
		}
	}
}
func (m *DirectoryModule) getDirectoriesPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Directory) {
	defer func() {
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
		wg.Done()

	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()

	// Get directories
	directories, err := sdk.CachedDSDescribeDirectories(m.DSClient, aws.ToString(m.Caller.Account), r)
	if err != nil {
		m.modLog.Error(err)
	}
	for _, directory := range directories {
		trusts, err := sdk.CachedDSDescribeTrusts(m.DSClient, aws.ToString(m.Caller.Account), r, *directory.DirectoryId)
		if err != nil {
			m.modLog.Error(err)
		}
		dataReceiver <- Directory{
			DirectoryId: *directory.DirectoryId,
			DNS:         *directory.Name,
			NetBios:     *directory.ShortName,
			Region:      r,
			AccessURL:   *directory.AccessUrl,
			Alias:       *directory.Alias,
			OsVersion:   fmt.Sprintf("%s", directory.OsVersion),
			TrustInfo:   m.formatTrusts(trusts),
		}
	}
}

func (m *DirectoryModule) formatTrusts(t []dsTypes.Trust) string {
	var output string = ""
	for idx, trust := range t {
		if idx != 0 {
			output = output + "\n"
		}
		if trust.TrustDirection == "One-Way: Outgoing" {
			output = output + "→"
		} else if trust.TrustDirection == "One-Way: Ingoing" {
			output = output + "←"
		} else {
			output = output + "↔"
		}
		output = fmt.Sprintf("%s %s", output, *trust.RemoteDomainName)
		// check trust type (external or forest)
		if trust.TrustType == "External" {
			output = fmt.Sprintf("%s (%s)", output, "Domain")
		} else {
			output = fmt.Sprintf("%s (%s)", output, "Forest")
		}
	}
	return output
}
