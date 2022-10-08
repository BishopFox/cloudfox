package aws

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"sync"

	"github.com/BishopFox/cloudfox/console"
	"github.com/BishopFox/cloudfox/utils"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/sirupsen/logrus"
)

type TagsModule struct {
	// General configuration data
	ResourceGroupsTaggingApiClient *resourcegroupstaggingapi.Client

	Caller       sts.GetCallerIdentityOutput
	AWSRegions   []string
	OutputFormat string
	Goroutines   int
	AWSProfile   string

	// Main module data
	Tags           []Tag
	CommandCounter console.CommandCounter
	// Used to store output data for pretty printing
	output utils.OutputData2
	modLog *logrus.Entry
}

type Tag struct {
	AWSService string
	Region     string
	Type       string
	Name       string
	Key        string
	Value      string
}

func (m *TagsModule) PrintTags(outputFormat string, outputDirectory string, verbosity int) {
	// These stuct values are used by the output module
	m.output.Verbosity = verbosity
	m.output.Directory = outputDirectory
	m.output.CallingModule = "tags"
	m.modLog = utils.TxtLogger.WithFields(logrus.Fields{
		"module": m.output.CallingModule,
	})
	if m.AWSProfile == "" {
		m.AWSProfile = utils.BuildAWSPath(m.Caller)
	}

	fmt.Printf("[%s] Enumerating tags for account %s.\n", cyan(m.output.CallingModule), aws.ToString(m.Caller.Account))

	wg := new(sync.WaitGroup)
	semaphore := make(chan struct{}, m.Goroutines)

	// Create a channel to signal the spinner aka task status goroutine to finish
	spinnerDone := make(chan bool)
	//fire up the the task status spinner/updated
	go console.SpinUntil(m.output.CallingModule, &m.CommandCounter, spinnerDone, "regions")

	//create a channel to receive the objects
	dataReceiver := make(chan Tag)

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
		//"Type",
		"Resource Arn",
		"Key",
		"Value",
	}

	sort.Slice(m.Tags, func(i, j int) bool {
		return m.Tags[i].AWSService < m.Tags[j].AWSService
	})

	// Table rows
	for i := range m.Tags {

		m.output.Body = append(
			m.output.Body,
			[]string{
				m.Tags[i].AWSService,
				m.Tags[i].Region,
				//m.Tags[i].Type,
				m.Tags[i].Name,
				m.Tags[i].Key,
				m.Tags[i].Value,
			},
		)

	}
	if len(m.output.Body) > 0 {
		m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", m.AWSProfile)
		utils.OutputSelector(verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.CallingModule, m.output.CallingModule)
		//m.writeLoot(m.output.FilePath, verbosity)
		fmt.Printf("[%s] %s tags found.\n", cyan(m.output.CallingModule), strconv.Itoa(len(m.output.Body)))
		count := m.countUniqueResourcesWithTags()
		fmt.Printf("[%s] %d unique resources with tags found.\n", cyan(m.output.CallingModule), count)
	} else {
		fmt.Printf("[%s] No tags found, skipping the creation of an output file.\n", cyan(m.output.CallingModule))
	}

}

func (m *TagsModule) countUniqueResourcesWithTags() int {
	var uniqueResources []string
	for i := range m.Tags {
		if !utils.Contains(m.Tags[i].Name, uniqueResources) {
			uniqueResources = append(uniqueResources, m.Tags[i].Name)
		}
	}
	return len(uniqueResources)
}

func (m *TagsModule) executeChecks(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Tag) {
	defer wg.Done()

	m.CommandCounter.Total++
	wg.Add(1)
	m.getTagsPerRegion(r, wg, semaphore, dataReceiver)
}

func (m *TagsModule) Receiver(receiver chan Tag, receiverDone chan bool) {
	defer close(receiverDone)
	for {
		select {
		case data := <-receiver:
			m.Tags = append(m.Tags, data)
		case <-receiverDone:
			receiverDone <- true
			return
		}
	}
}

func (m *TagsModule) getTagsPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Tag) {
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
		GetResources, err := m.ResourceGroupsTaggingApiClient.GetResources(
			context.TODO(),
			&resourcegroupstaggingapi.GetResourcesInput{
				PaginationToken: PaginationControl,
			},
			func(o *resourcegroupstaggingapi.Options) {
				o.Region = r
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}
		//var parsedArn types.Arn
		for _, resource := range GetResources.ResourceTagMappingList {
			resourceArn := aws.ToString(resource.ResourceARN)
			parsedArn, err := arn.Parse(resourceArn)
			if err != nil {
				break
			}

			for _, tag := range resource.Tags {
				key := aws.ToString(tag.Key)
				value := aws.ToString(tag.Value)

				dataReceiver <- Tag{
					AWSService: parsedArn.Service,
					Name:       parsedArn.Resource,
					Region:     r,
					Type:       "",
					Key:        key,
					Value:      value,
				}

			}

		}

		if aws.ToString(GetResources.PaginationToken) != "" {
			PaginationControl = GetResources.PaginationToken
		} else {
			PaginationControl = nil
			break
		}
	}
}
