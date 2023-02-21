package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cloudtrailTypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/bishopfox/awsservicemap"
	"github.com/sirupsen/logrus"
)

type OutboundAssumedRolesModule struct {
	// General configuration data
	CloudTrailClient *cloudtrail.Client

	Caller       sts.GetCallerIdentityOutput
	AWSRegions   []string
	OutputFormat string
	Goroutines   int
	AWSProfile   string
	WrapTable    bool

	// Main module data
	OutboundAssumeRoleEntries []OutboundAssumeRoleEntry
	Days                      int
	CommandCounter            internal.CommandCounter
	// Used to store output data for pretty printing
	output internal.OutputData2

	modLog *logrus.Entry
}

type OutboundAssumeRoleEntry struct {
	AWSService           string
	Region               string
	Type                 string
	SourceAccount        string
	SourcePrincipal      string
	DestinationAccount   string
	DestinationPrincipal string
	LogTimestamp         string
}

type CloudTrailEvent struct {
	EventVersion string `json:"eventVersion"`
	UserIdentity struct {
		Type           string `json:"type"`
		PrincipalID    string `json:"principalId"`
		Arn            string `json:"arn"`
		AccountID      string `json:"accountId"`
		AccessKeyID    string `json:"accessKeyId"`
		SessionContext struct {
			SessionIssuer struct {
				Type        string `json:"type"`
				PrincipalID string `json:"principalId"`
				Arn         string `json:"arn"`
				AccountID   string `json:"accountId"`
				UserName    string `json:"userName"`
			} `json:"sessionIssuer"`
			WebIDFederationData struct {
			} `json:"webIdFederationData"`
			Attributes struct {
				CreationDate     time.Time `json:"creationDate"`
				MfaAuthenticated string    `json:"mfaAuthenticated"`
			} `json:"attributes"`
		} `json:"sessionContext"`
	} `json:"userIdentity"`
	EventTime         time.Time `json:"eventTime"`
	EventSource       string    `json:"eventSource"`
	EventName         string    `json:"eventName"`
	AwsRegion         string    `json:"awsRegion"`
	SourceIPAddress   string    `json:"sourceIPAddress"`
	UserAgent         string    `json:"userAgent"`
	RequestParameters struct {
		RoleArn         string `json:"roleArn"`
		RoleSessionName string `json:"roleSessionName"`
	} `json:"requestParameters"`
	ResponseElements struct {
		Credentials struct {
			AccessKeyID  string `json:"accessKeyId"`
			SessionToken string `json:"sessionToken"`
			Expiration   string `json:"expiration"`
		} `json:"credentials"`
		AssumedRoleUser struct {
			AssumedRoleID string `json:"assumedRoleId"`
			Arn           string `json:"arn"`
		} `json:"assumedRoleUser"`
	} `json:"responseElements"`
	RequestID string `json:"requestID"`
	EventID   string `json:"eventID"`
	ReadOnly  bool   `json:"readOnly"`
	Resources []struct {
		AccountID string `json:"accountId"`
		Type      string `json:"type"`
		Arn       string `json:"ARN"`
	} `json:"resources"`
	EventType          string `json:"eventType"`
	ManagementEvent    bool   `json:"managementEvent"`
	RecipientAccountID string `json:"recipientAccountId"`
	EventCategory      string `json:"eventCategory"`
	TLSDetails         struct {
		TLSVersion               string `json:"tlsVersion"`
		CipherSuite              string `json:"cipherSuite"`
		ClientProvidedHostHeader string `json:"clientProvidedHostHeader"`
	} `json:"tlsDetails"`
}

func (m *OutboundAssumedRolesModule) PrintOutboundRoleTrusts(days int, outputFormat string, outputDirectory string, verbosity int) {
	// These stuct values are used by the output module
	m.output.Verbosity = verbosity
	m.output.Directory = outputDirectory
	m.output.CallingModule = "outbound-assumed-roles"
	m.modLog = internal.TxtLog.WithFields(logrus.Fields{
		"module": m.output.CallingModule,
	})
	if m.AWSProfile == "" {
		m.AWSProfile = internal.BuildAWSPath(m.Caller)
	}
	m.Days = days

	fmt.Printf("[%s][%s] Enumerating outbound assumed role entries in cloudtrail for account %s.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), aws.ToString(m.Caller.Account))
	fmt.Printf("[%s][%s] Going back through %d days of cloudtrail events. (This command can be pretty slow, FYI)\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), days)

	wg := new(sync.WaitGroup)
	semaphore := make(chan struct{}, m.Goroutines)

	// Create a channel to signal the spinner aka task status goroutine to finish
	spinnerDone := make(chan bool)
	//fire up the the task status spinner/updated
	go internal.SpinUntil(m.output.CallingModule, &m.CommandCounter, spinnerDone, "regions")

	//create a channel to receive the objects
	dataReceiver := make(chan OutboundAssumeRoleEntry)

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
	receiverDone <- true
	<-receiverDone

	m.output.Headers = []string{
		"Service",
		"Region",
		"Type",
		//"Source Account",
		"Source Principal",
		//"Destination Account",
		"Destination Principal",
		"Log Entry Timestamp",
	}

	// Table rows
	for i := range m.OutboundAssumeRoleEntries {
		m.output.Body = append(
			m.output.Body,
			[]string{
				m.OutboundAssumeRoleEntries[i].AWSService,
				m.OutboundAssumeRoleEntries[i].Region,
				m.OutboundAssumeRoleEntries[i].Type,
				//m.OutboundAssumeRoleEntries[i].SourceAccount,
				m.OutboundAssumeRoleEntries[i].SourcePrincipal,
				//m.OutboundAssumeRoleEntries[i].DestinationAccount,
				m.OutboundAssumeRoleEntries[i].DestinationPrincipal,
				m.OutboundAssumeRoleEntries[i].LogTimestamp,
			},
		)

	}
	if len(m.output.Body) > 0 {

		m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", m.AWSProfile)
		//m.output.OutputSelector(outputFormat)
		//utils.OutputSelector(verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.CallingModule, m.output.CallingModule)
		internal.OutputSelector(verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.CallingModule, m.output.CallingModule, m.WrapTable, m.AWSProfile)
		fmt.Printf("[%s][%s] %s log entries found.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), strconv.Itoa(len(m.output.Body)))

		//m.writeLoot()
	} else {
		fmt.Printf("[%s][%s] No matching log entries found, skipping the creation of an output file.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	}
	fmt.Printf("[%s][%s] For context and next steps: https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#%s\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), m.output.CallingModule)
}

func (m *OutboundAssumedRolesModule) Receiver(receiver chan OutboundAssumeRoleEntry, receiverDone chan bool) {
	defer close(receiverDone)
	for {
		select {
		case data := <-receiver:
			m.OutboundAssumeRoleEntries = append(m.OutboundAssumeRoleEntries, data)
		case <-receiverDone:
			receiverDone <- true
			return
		}
	}
}

func (m *OutboundAssumedRolesModule) executeChecks(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan OutboundAssumeRoleEntry) {
	defer wg.Done()
	servicemap := &awsservicemap.AwsServiceMap{
		JsonFileSource: "DOWNLOAD_FROM_AWS",
	}
	res, err := servicemap.IsServiceInRegion("cloudtrail", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		wg.Add(1)
		m.CommandCounter.Total++
		m.getAssumeRoleLogEntriesPerRegion(r, wg, semaphore, dataReceiver)
	}

}

func (m *OutboundAssumedRolesModule) getAssumeRoleLogEntriesPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan OutboundAssumeRoleEntry) {
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
	//var LookupAttributes []types.LookupAttributes
	//var LookupAttribute types.LookupAttribute
	var pages int

	days := 0 - m.Days
	endTime := aws.Time(time.Now())
	startTime := endTime.AddDate(0, 0, days)
	for {
		LookupEvents, err := m.CloudTrailClient.LookupEvents(
			context.TODO(),
			&cloudtrail.LookupEventsInput{
				EndTime:   endTime,
				StartTime: &startTime,
				LookupAttributes: []cloudtrailTypes.LookupAttribute{
					{
						AttributeKey:   cloudtrailTypes.LookupAttributeKeyEventName,
						AttributeValue: aws.String("AssumeRole"),
					},
				},
				NextToken: PaginationControl,
			},

			func(o *cloudtrail.Options) {
				o.Region = r
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		for _, event := range LookupEvents.Events {
			//eventData := *event.CloudTrailEvent
			//fmt.Println(eventData)
			var sourceAccount, sourcePrincipal, destinationAccount, destinationPrincipal, userType string
			cloudtrailEvent := CloudTrailEvent{}
			json.Unmarshal([]byte(*event.CloudTrailEvent), &cloudtrailEvent)

			if cloudtrailEvent.UserIdentity.Type == "AssumedRole" || cloudtrailEvent.UserIdentity.Type == "IAMUser" {
				if cloudtrailEvent.UserIdentity.Type == "AssumedRole" {
					sourcePrincipal = cloudtrailEvent.UserIdentity.SessionContext.SessionIssuer.Arn
				} else {
					sourcePrincipal = cloudtrailEvent.UserIdentity.Arn
				}
				userType = cloudtrailEvent.UserIdentity.Type
				sourceAccount = ""
				destinationAccount = ""
				destinationPrincipal = cloudtrailEvent.RequestParameters.RoleArn
				logTimestamp := cloudtrailEvent.EventTime.Format("2006-01-02 15:04:05")
				//fmt.Printf("%s,%s,%s,%s\n", sourceAccount, sourcePrincipal, destinationAccount, destinationPrincipal)

				dataReceiver <- OutboundAssumeRoleEntry{
					AWSService:           "CloudTrail",
					Region:               r,
					Type:                 userType,
					SourceAccount:        sourceAccount,
					SourcePrincipal:      sourcePrincipal,
					DestinationAccount:   destinationAccount,
					DestinationPrincipal: destinationPrincipal,
					LogTimestamp:         logTimestamp,
				}
			}

		}

		// The "NextToken" value is nil when there's no more data to return.
		if LookupEvents.NextToken != nil {
			PaginationControl = LookupEvents.NextToken
			pages++
		} else {
			PaginationControl = nil
			break
		}
	}

}
