package aws

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi"
	"github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/sirupsen/logrus"
)

type TagsGetResourcesAPI interface {
	GetResources(ctx context.Context, params *resourcegroupstaggingapi.GetResourcesInput, optFns ...func(*resourcegroupstaggingapi.Options)) (*resourcegroupstaggingapi.GetResourcesOutput, error)
}

type TagsModule struct {
	// General configuration data
	ResourceGroupsTaggingApiInterface TagsGetResourcesAPI

	Caller        sts.GetCallerIdentityOutput
	AWSRegions    []string
	AWSOutputType string
	AWSTableCols  string

	Goroutines            int
	AWSProfile            string
	WrapTable             bool
	MaxResourcesPerRegion int

	// Main module data
	Tags               []Tag
	CommandCounter     internal.CommandCounter
	ResourceTypeCounts map[string]int

	// Used to store output data for pretty printing
	output internal.OutputData2
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

func (m *TagsModule) PrintTags(outputDirectory string, verbosity int) {
	// These struct values are used by the output module
	m.output.Verbosity = verbosity
	m.output.Directory = outputDirectory
	m.output.CallingModule = "tags"
	m.modLog = internal.TxtLog.WithFields(logrus.Fields{
		"module": m.output.CallingModule,
	})
	if m.AWSProfile == "" {
		m.AWSProfile = internal.BuildAWSPath(m.Caller)
	}

	fmt.Printf("[%s][%s] Enumerating tags for account %s.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), aws.ToString(m.Caller.Account))

	wg := new(sync.WaitGroup)
	semaphore := make(chan struct{}, m.Goroutines)

	// Create a channel to signal the spinner aka task status goroutine to finish
	spinnerDone := make(chan bool)
	//fire up the the task status spinner/updated
	go internal.SpinUntil(m.output.CallingModule, &m.CommandCounter, spinnerDone, "regions")

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
	//time.Sleep(time.Second * 2)

	// Send a message to the spinner goroutine to close the channel and stop
	spinnerDone <- true
	<-spinnerDone
	receiverDone <- true
	<-receiverDone

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
			"Service",
			"Region",
			"Type",
			//"Name",
			//"Resource Arn",
			"Key",
			"Value",
		}
		// Otherwise, use the default columns.
	} else {
		tableCols = []string{
			"Service",
			"Region",
			"Type",
			//"Name",
			//"Resource Arn",
			"Key",
			"Value",
		}
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
		m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", fmt.Sprintf("%s-%s", m.AWSProfile, aws.ToString(m.Caller.Account)))

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
		o.PrefixIdentifier = m.AWSProfile
		o.Table.DirectoryName = filepath.Join(outputDirectory, "cloudfox-output", "aws", fmt.Sprintf("%s-%s", m.AWSProfile, aws.ToString(m.Caller.Account)))
		o.WriteFullOutput(o.Table.TableFiles, nil)
		//m.writeLoot(o.Table.DirectoryName, verbosity, m.AWSProfile)
		fmt.Printf("[%s][%s] %s tags found.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), strconv.Itoa(len(m.output.Body)))
		count := m.countUniqueResourcesWithTags()
		fmt.Printf("[%s][%s] %d unique resources with tags found.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), count)
		if m.MaxResourcesPerRegion != 0 {
			fmt.Printf("[%s][%s] NOTE: Only looked at %d resources per region. To enum all tags for all resources,\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), m.MaxResourcesPerRegion)
			fmt.Printf("[%s][%s] NOTE: run the tags command without the -m/--max-resources-per-region flag set.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
		}
	} else {
		fmt.Printf("[%s][%s] No tags found, skipping the creation of an output file.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	}
	fmt.Printf("[%s][%s] For context and next steps: https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#%s\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), m.output.CallingModule)
}

func (m *TagsModule) countUniqueResourcesWithTags() int {
	var uniqueResources []string
	for i := range m.Tags {
		if !internal.Contains(m.Tags[i].Name, uniqueResources) {
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

	resources, err := m.getResources(r)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
	}
	//var parsedArn types.Arn
	for _, resource := range resources {
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

}

func (m *TagsModule) getResources(r string) ([]types.ResourceTagMapping, error) {
	var PaginationControl *string
	var resources []types.ResourceTagMapping

	// a for loop that accepts user input. If no user input, it will continue to paginate until there are no more pages. If there is user input, it will paginate until the user input is reached.

	for {
		if len(resources) < m.MaxResourcesPerRegion || m.MaxResourcesPerRegion == 0 {
			GetResources, err := m.ResourceGroupsTaggingApiInterface.GetResources(
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
				return resources, err
			}

			resources = append(resources, GetResources.ResourceTagMappingList...)

			if aws.ToString(GetResources.PaginationToken) != "" {
				PaginationControl = GetResources.PaginationToken
			} else {
				PaginationControl = nil
				break
			}

		} else {
			return resources, nil
		}

	}
	return resources, nil
}
