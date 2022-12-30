package aws

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
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
	WrapTable    bool

	// Main module data
	Tags               []Tag
	CommandCounter     console.CommandCounter
	ResourceTypeCounts map[string]int

	// Used to store output data for pretty printing
	output utils.OutputData2
	modLog *logrus.Entry
}

type Tag struct {
	AWSService string
	Region     string
	Arn        string
	Name       string
	Type       string
	Key        string
	Value      string
}

func (m *TagsModule) PrintTags(outputFormat string, outputDirectory string, verbosity int) {
	// These stuct values are used by the output module
	m.output.Verbosity = verbosity
	m.output.Directory = outputDirectory
	m.output.CallingModule = "tags"
	m.modLog = utils.TxtLog.WithFields(logrus.Fields{
		"module": m.output.CallingModule,
	})
	if m.AWSProfile == "" {
		m.AWSProfile = utils.BuildAWSPath(m.Caller)
	}

	fmt.Printf("[%s][%s] Enumerating tags for account %s.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), aws.ToString(m.Caller.Account))

	wg := new(sync.WaitGroup)
	semaphore := make(chan struct{}, m.Goroutines)

	// Create a channel to signal the spinner aka task status goroutine to finish
	spinnerDone := make(chan bool)
	//fire up the the task status spinner/updated
	go console.SpinUntil(m.output.CallingModule, &m.CommandCounter, spinnerDone, "regions")

	//create a channel to receive the objects
	dataReceiver := make(chan Tag)

	go m.Receiver(dataReceiver)

	for _, region := range m.AWSRegions {
		wg.Add(1)
		m.CommandCounter.Pending++
		go m.executeChecks(region, wg, semaphore, dataReceiver)

	}

	wg.Wait()
	// Send a message to the spinner goroutine to close the channel and stop
	spinnerDone <- true
	<-spinnerDone
	close(dataReceiver)

	// add - if struct is not empty do this. otherwise, dont write anything.
	m.output.Headers = []string{
		"Service",
		"Region",
		"Type",
		//"Name",
		//"Resource Arn",
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
				m.Tags[i].Type,
				//m.Tags[i].Arn,
				//m.Tags[i].Name,
				m.Tags[i].Key,
				m.Tags[i].Value,
			},
		)

	}
	if len(m.output.Body) > 0 {
		m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", m.AWSProfile)
		//utils.OutputSelector(verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.CallingModule, m.output.CallingModule)
		utils.OutputSelector(verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.CallingModule, m.output.CallingModule, m.WrapTable)
		//m.writeLoot(m.output.FilePath, verbosity)
		fmt.Printf("[%s][%s] %s tags found.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), strconv.Itoa(len(m.output.Body)))
		count := m.countUniqueResourcesWithTags()
		fmt.Printf("[%s][%s] %d unique resources with tags found.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), count)
	} else {
		fmt.Printf("[%s][%s] No tags found, skipping the creation of an output file.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	}

}

func (m *TagsModule) countUniqueResourcesWithTags() int {
	var uniqueResources []string
	for i := range m.Tags {
		if !utils.Contains(m.Tags[i].Name, uniqueResources) {
			uniqueResources = append(uniqueResources, m.Tags[i].Name)
		}
	}
	//
	return len(uniqueResources)
}

// TODO: Make summary table

// func (m *TagsModule) createTagsSummary() {
// 	var serviceMap map[string]map[string]int
// 	// var services []string
// 	// var totalRegionCounts map[string]int

// 	var uniqueResources []string
// 	var uniqueServiceTypes []string

// 	for i := range m.Tags {
// 		if !utils.Contains(m.Tags[i].Name, uniqueResources) {
// 			uniqueResources = append(uniqueResources, m.serviceMap[m.Tags[i].Name][m.])
// 		}

// 		if !utils.Contains(fmt.Sprintf("%s %s", m.Tags[i].AWSService, m.Tags[i].Type), uniqueServiceTypes) {
// 			uniqueServiceTypes = append(uniqueServiceTypes, fmt.Sprintf("%s %s", m.Tags[i].AWSService, m.Tags[i].Type))
// 		}

// 	}

// 	for j, resource := range uniqueResources {
// 		for k, ServiceType := range uniqueServiceTypes {
// 			if fmt.Sprintf("%s %s", resource[j].AWSService, m.Tags[i].Type). == ServiceType[k]
// 		}
// 	}
// }

func (m *TagsModule) executeChecks(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Tag) {
	defer wg.Done()

	m.CommandCounter.Total++
	wg.Add(1)
	m.getTagsPerRegion(r, wg, semaphore, dataReceiver)
}

func (m *TagsModule) Receiver(receiver chan Tag) {
	for data := range receiver {
		m.Tags = append(m.Tags, data)

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
			var resourceType string
			resourceArn := aws.ToString(resource.ResourceARN)
			parsedArn, err := arn.Parse(resourceArn)
			if parsedArn.Service != "s3" {
				resourceType = strings.Split(parsedArn.Resource, ":")[0]
				resourceType = strings.Split(resourceType, "/")[0]
			} else {
				resourceType = "bucket"
			}
			//resourceName := strings.Split(parsedArn.Resource, ":")[]
			if err != nil {
				break
			}

			for _, tag := range resource.Tags {
				key := aws.ToString(tag.Key)
				value := aws.ToString(tag.Value)

				dataReceiver <- Tag{
					AWSService: parsedArn.Service,
					Arn:        resourceArn,
					Name:       parsedArn.Resource,
					Region:     r,
					Type:       resourceType,
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
