package aws

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/bishopfox/awsservicemap"
	"github.com/sirupsen/logrus"
)

type ElasticNetworkInterfacesModule struct {
	//EC2Client                       *ec2.Client
	DescribeNetworkInterfacesClient ec2.DescribeNetworkInterfacesAPIClient

	Caller       sts.GetCallerIdentityOutput
	AWSRegions   []string
	OutputFormat string
	AWSProfile   string
	WrapTable    bool

	MappedENIs     []MappedENI
	CommandCounter internal.CommandCounter

	output internal.OutputData2
	modLog *logrus.Entry
}

type MappedENI struct {
	ID               string
	Type             string
	ExternalIP       string
	PrivateIP        string
	VPCID            string
	AttachedInstance string
	Description      string
}

func (m *ElasticNetworkInterfacesModule) ElasticNetworkInterfaces(outputFormat string, outputDirectory string, verbosity int) {
	m.output.Verbosity = verbosity
	m.output.Directory = outputDirectory
	m.output.CallingModule = "elastic-network-interfaces"
	m.modLog = internal.TxtLog.WithFields(logrus.Fields{
		"module": m.output.CallingModule,
	})
	if m.AWSProfile == "" {
		m.AWSProfile = internal.BuildAWSPath(m.Caller)
	}

	fmt.Printf("[%s][%s] Enumerating elastic network interfaces in all regions for account %s\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), aws.ToString(m.Caller.Account))

	wg := new(sync.WaitGroup)

	spinnerDone := make(chan bool)
	go internal.SpinUntil(m.output.CallingModule, &m.CommandCounter, spinnerDone, "tasks")

	dataReceiver := make(chan MappedENI)

	// Create a channel to signal to stop
	receiverDone := make(chan bool)

	go m.Receiver(dataReceiver, receiverDone)

	for _, region := range m.AWSRegions {
		wg.Add(1)
		m.CommandCounter.Pending++
		go m.executeChecks(region, wg, dataReceiver)

	}

	wg.Wait()
	//time.Sleep(time.Second * 2)

	spinnerDone <- true
	<-spinnerDone
	receiverDone <- true
	<-receiverDone

	m.printENIsData(outputFormat, outputDirectory, dataReceiver)

}

func (m *ElasticNetworkInterfacesModule) Receiver(receiver chan MappedENI, receiverDone chan bool) {
	defer close(receiverDone)
	for {
		select {
		case data := <-receiver:
			m.MappedENIs = append(m.MappedENIs, data)
		case <-receiverDone:
			receiverDone <- true
			return
		}
	}
}

func (m *ElasticNetworkInterfacesModule) printENIsData(outputFormat string, outputDirectory string, dataReceiver chan MappedENI) {
	m.output.Headers = []string{
		"ID",
		"Type",
		"External IP",
		"Internal IP",
		"VPC ID",
		"Attached Instance",
		"Description",
	}
	for _, eni := range m.MappedENIs {
		m.output.Body = append(
			m.output.Body,
			[]string{
				eni.ID,
				eni.Type,
				eni.ExternalIP,
				eni.PrivateIP,
				eni.VPCID,
				eni.AttachedInstance,
				eni.Description,
			},
		)
	}
	if len(m.output.Body) > 0 {
		m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", m.AWSProfile)
		//utils.OutputSelector(m.output.Verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.CallingModule, m.output.CallingModule)
		internal.OutputSelector(m.output.Verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.CallingModule, m.output.CallingModule, m.WrapTable, m.AWSProfile)

		m.writeLoot(m.output.FilePath)
		fmt.Printf("[%s][%s] %s elastic network interfaces found.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), strconv.Itoa(len(m.output.Body)))

	} else {
		fmt.Printf("[%s][%s] No elastic network interfaces found, skipping the creation of an output file.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	}
	fmt.Printf("[%s][%s] For context and next steps: https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#%s\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), m.output.CallingModule)
}

func (m *ElasticNetworkInterfacesModule) writeLoot(outputDirectory string) {
	path := filepath.Join(outputDirectory, "loot")
	err := os.MkdirAll(path, os.ModePerm)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
	}
	privateIPsFilename := filepath.Join(path, "elastic-network-interfaces-PrivateIPs.txt")
	publicIPsFilename := filepath.Join(path, "elastic-network-interfaces-PublicIPs.txt")

	var publicIPs string
	var privateIPs string

	for _, eni := range m.MappedENIs {
		if eni.ExternalIP != "NoExternalIP" {
			publicIPs = publicIPs + fmt.Sprintln(eni.ExternalIP)
		}
		if eni.PrivateIP != "" {
			privateIPs = privateIPs + fmt.Sprintln(eni.PrivateIP)
		}

	}
	err = os.WriteFile(privateIPsFilename, []byte(privateIPs), 0644)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
	}
	err = os.WriteFile(publicIPsFilename, []byte(publicIPs), 0644)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
	}

	fmt.Printf("[%s][%s] Loot written to [%s]\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), privateIPsFilename)
	fmt.Printf("[%s][%s] Loot written to [%s]\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), publicIPsFilename)

}

func (m *ElasticNetworkInterfacesModule) executeChecks(r string, wg *sync.WaitGroup, dataReceiver chan MappedENI) {
	defer wg.Done()
	servicemap := &awsservicemap.AwsServiceMap{
		JsonFileSource: "EMBEDDED_IN_PACKAGE",
	}
	res, err := servicemap.IsServiceInRegion("ec2", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		m.CommandCounter.Pending--
		m.CommandCounter.Executing++
		m.getDescribeNetworkInterfaces(r, dataReceiver)
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}
}

func (m *ElasticNetworkInterfacesModule) getDescribeNetworkInterfaces(region string, dataReceiver chan MappedENI) {
	var PaginationControl *string
	for {
		DescribeNetworkInterfaces, err := m.DescribeNetworkInterfacesClient.DescribeNetworkInterfaces(
			context.TODO(),
			&(ec2.DescribeNetworkInterfacesInput{
				NextToken: PaginationControl,
			}),
			func(o *ec2.Options) {
				o.Region = region
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		for _, eni := range DescribeNetworkInterfaces.NetworkInterfaces {
			status := string(eni.Status)
			if status == "available" {
				continue // unused ENI
			}

			mappedENI := MappedENI{
				ID:               aws.ToString(eni.NetworkInterfaceId),
				Type:             string(eni.InterfaceType),
				ExternalIP:       getPublicIPOfElasticNetworkInterface(eni),
				PrivateIP:        aws.ToString(eni.PrivateIpAddress),
				VPCID:            aws.ToString(eni.VpcId),
				AttachedInstance: getAttachmentInstanceOfElasticNetworkInterface(eni),
				Description:      aws.ToString(eni.Description),
			}

			dataReceiver <- mappedENI
		}

		if DescribeNetworkInterfaces.NextToken != nil {
			PaginationControl = DescribeNetworkInterfaces.NextToken
		} else {
			PaginationControl = nil
			break
		}

	}
}

func getPublicIPOfElasticNetworkInterface(elasticNetworkInterface types.NetworkInterface) string {
	if elasticNetworkInterface.Association != nil {
		return aws.ToString(elasticNetworkInterface.Association.PublicIp)
	}

	return "NoExternalIP"
}

func getAttachmentInstanceOfElasticNetworkInterface(elasticNetworkInterface types.NetworkInterface) string {
	if elasticNetworkInterface.Attachment == nil {
		return ""
	}

	return aws.ToString(elasticNetworkInterface.Attachment.InstanceId)
}
