package aws

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/BishopFox/cloudfox/console"
	"github.com/BishopFox/cloudfox/utils"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ram"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/sirupsen/logrus"
)

type RAMModule struct {
	// General configuration data
	RAMClient *ram.Client

	Caller       sts.GetCallerIdentityOutput
	AWSRegions   []string
	OutputFormat string
	Goroutines   int
	AWSProfile   string

	// Main module data
	Resources      []Resource
	CommandCounter console.CommandCounter
	// Used to store output data for pretty printing
	output utils.OutputData2
	modLog *logrus.Entry
}

type Resource struct {
	AWSService string
	Region     string
	Name       string
	Owner      string
}

func (m *RAMModule) PrintRAM(outputFormat string, outputDirectory string, verbosity int) {
	// These stuct values are used by the output module
	m.output.Verbosity = verbosity
	m.output.Directory = outputDirectory
	m.output.CallingModule = "ram"
	m.modLog = utils.TxtLogger.WithFields(logrus.Fields{
		"module": m.output.CallingModule,
	})
	if m.AWSProfile == "" {
		m.AWSProfile = fmt.Sprintf("%s-%s", aws.ToString(m.Caller.Account), aws.ToString(m.Caller.UserId))
	}

	fmt.Printf("[%s] Enumerating shared resources for account %s.\n", cyan(m.output.CallingModule), aws.ToString(m.Caller.Account))

	wg := new(sync.WaitGroup)

	// Create a channel to signal the spinner aka task status goroutine to finish
	spinnerDone := make(chan bool)
	//fire up the the task status spinner/updated
	go console.SpinUntil(m.output.CallingModule, &m.CommandCounter, spinnerDone, "regions")

	//create a channel to receive the objects
	dataReceiver := make(chan Resource)

	// Create a channel to signal to stop
	receiverDone := make(chan bool)
	go m.Receiver(dataReceiver, receiverDone)

	for _, region := range m.AWSRegions {
		wg.Add(1)
		m.CommandCounter.Pending++
		go m.executeChecks(region, wg, dataReceiver)

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
		"Owner",
	}

	// Table rows
	for i := range m.Resources {
		m.output.Body = append(
			m.output.Body,
			[]string{
				m.Resources[i].AWSService,
				m.Resources[i].Region,
				m.Resources[i].Name,
				m.Resources[i].Owner,
			},
		)

	}
	if len(m.output.Body) > 0 {
		m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", m.AWSProfile)
		//m.output.OutputSelector(outputFormat)
		utils.OutputSelector(verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.CallingModule, m.output.CallingModule)
		fmt.Printf("[%s] %s resources found.\n", cyan(m.output.CallingModule), strconv.Itoa(len(m.output.Body)))
	} else {
		fmt.Printf("[%s] No resources found, skipping the creation of an output file.\n", cyan(m.output.CallingModule))
	}

}

func (m *RAMModule) executeChecks(r string, wg *sync.WaitGroup, dataReceiver chan Resource) {
	defer wg.Done()
	m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	m.getRAMResourcesPerRegion(r, dataReceiver)
	m.CommandCounter.Executing--
	m.CommandCounter.Complete++
}

func (m *RAMModule) Receiver(receiver chan Resource, receiverDone chan bool) {
	defer close(receiverDone)
	for {
		select {
		case data := <-receiver:
			m.Resources = append(m.Resources, data)
		case <-receiverDone:
			receiverDone <- true
			return
		}
	}
}

func (m *RAMModule) getRAMResourcesPerRegion(r string, dataReceiver chan Resource) {
	// "PaginationMarker" is a control variable used for output continuity, as AWS return the output in pages.
	var PaginationControl *string

	for {
		GetResourceShares, err := m.RAMClient.GetResourceShares(
			context.TODO(),
			&ram.GetResourceSharesInput{
				NextToken: PaginationControl,
			},
			func(o *ram.Options) {
				o.Region = r
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		for _, resource := range GetResourceShares.ResourceShares {
			name := aws.ToString(resource.Name)
			ownerID := aws.ToString(resource.OwningAccountId)

			dataReceiver <- Resource{
				AWSService: "RAM",
				Name:       name,
				Region:     r,
				Owner:      ownerID,
			}

			// }
			break
		}

		// The "NextToken" value is nil when there's no more data to return.
		if GetResourceShares.NextToken != nil {
			PaginationControl = GetResourceShares.NextToken
		} else {
			PaginationControl = nil
			break
		}
	}
}
