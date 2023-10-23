package aws

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/BishopFox/cloudfox/aws/sdk"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/sirupsen/logrus"
)

type Route53Module struct {
	// General configuration data
	Route53Client sdk.AWSRoute53ClientInterface

	Caller        sts.GetCallerIdentityOutput
	AWSRegions    []string
	AWSOutputType string
	AWSTableCols  string

	Goroutines     int
	AWSProfile     string
	WrapTable      bool
	CommandCounter internal.CommandCounter

	// Main module data
	Records []Record
	// Used to store output data for pretty printing
	output internal.OutputData2

	modLog *logrus.Entry
}

type Record struct {
	AWSService  string
	Name        string
	Type        string
	Value       string
	PrivateZone string
}

func (m *Route53Module) PrintRoute53(outputDirectory string, verbosity int) {

	// These struct values are used by the output module
	m.output.Verbosity = verbosity
	m.output.Directory = outputDirectory
	m.output.CallingModule = "route53"
	m.modLog = internal.TxtLog.WithFields(logrus.Fields{
		"module": m.output.CallingModule,
	})
	if m.AWSProfile == "" {
		m.AWSProfile = internal.BuildAWSPath(m.Caller)
	}

	fmt.Printf("[%s][%s] Enumerating Route53 for account %s.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), aws.ToString(m.Caller.Account))

	m.getRoute53Records()

	m.output.Headers = []string{
		"Service",
		"Name",
		"Type",
		"Value",
		"PrivateZone",
	}

	// Table rows
	for i := range m.Records {
		m.output.Body = append(
			m.output.Body,
			[]string{
				m.Records[i].AWSService,
				m.Records[i].Name,
				m.Records[i].Type,
				m.Records[i].Value,
				m.Records[i].PrivateZone,
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
			Header: m.output.Headers,
			Body:   m.output.Body,
			Name:   m.output.CallingModule,
		})
		o.PrefixIdentifier = m.AWSProfile
		o.Table.DirectoryName = filepath.Join(outputDirectory, "cloudfox-output", "aws", fmt.Sprintf("%s-%s", m.AWSProfile, aws.ToString(m.Caller.Account)))
		o.WriteFullOutput(o.Table.TableFiles, nil)
		m.writeLoot(o.Table.DirectoryName, verbosity)
		fmt.Printf("[%s][%s] %s DNS records found.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), strconv.Itoa(len(m.output.Body)))

	} else {
		fmt.Printf("[%s][%s] No DNS records found, skipping the creation of an output file.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	}
	fmt.Printf("[%s][%s] For context and next steps: https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#%s\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), m.output.CallingModule)
}

func (m *Route53Module) writeLoot(outputDirectory string, verbosity int) {
	path := filepath.Join(outputDirectory, "loot")
	err := os.MkdirAll(path, os.ModePerm)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		panic(err.Error())
	}
	route53ARecordsPublicZonesFileName := filepath.Join(path, "route53-A-records-public-Zones.txt")
	route53ARecordsPrivateZonesFileName := filepath.Join(path, "route53-A-records-private-Zones.txt")

	var route53APrivateRecords string
	var route53APublicRecords string

	for _, record := range m.Records {
		if record.Type == "A" || record.Type == "AAAA" || record.Type == "CNAME" {
			if record.PrivateZone == "True" {
				route53APrivateRecords = route53APrivateRecords + fmt.Sprintln(record.Name)
			} else {
				route53APublicRecords = route53APublicRecords + fmt.Sprintln(record.Name)
			}

		}
	}
	err = os.WriteFile(route53ARecordsPublicZonesFileName, []byte(route53APublicRecords), 0644)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		panic(err.Error())
	}

	if verbosity > 2 {
		if len(route53APublicRecords) > 0 {
			fmt.Println()
			fmt.Printf("[%s][%s] %s \n", cyan(m.output.CallingModule), cyan(m.AWSProfile), green("Feed these public zone A records into nmap and something like gowitness or aquatone."))
			fmt.Print(route53APublicRecords)
			fmt.Printf("[%s][%s] %s \n", cyan(m.output.CallingModule), cyan(m.AWSProfile), green("End of loot file."))
		}
	}

	fmt.Printf("[%s][%s] Loot written to [%s]\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), route53ARecordsPublicZonesFileName)

	err = os.WriteFile(route53ARecordsPrivateZonesFileName, []byte(route53APrivateRecords), 0644)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		panic(err.Error())
	}

	if verbosity > 2 {
		if len(route53APrivateRecords) > 0 {
			fmt.Println()
			fmt.Printf("[%s][%s] %s \n", cyan(m.output.CallingModule), cyan(m.AWSProfile), green("Feed these private zone A records into nmap and something like gowitness or aquatone."))
			fmt.Print(route53APrivateRecords)
			fmt.Printf("[%s][%s] %s \n", cyan(m.output.CallingModule), cyan(m.AWSProfile), green("End of loot file."))
		}
	}

	fmt.Printf("[%s][%s] Loot written to [%s]\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), route53ARecordsPrivateZonesFileName)

}

func (m *Route53Module) getRoute53Records() {
	// "PaginationMarker" is a control variable used for output continuity, as AWS return the output in pages.
	var recordName string
	var recordType string

	HostedZones, err := sdk.CachedRoute53ListHostedZones(m.Route53Client, aws.ToString(m.Caller.Account))

	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	var privateZone string
	for _, zone := range HostedZones {
		if zone.Config.PrivateZone {
			privateZone = "True"
		} else {
			privateZone = "False"
		}

		Records, err := sdk.CachedRoute53ListResourceRecordSets(m.Route53Client, aws.ToString(m.Caller.Account), aws.ToString(zone.Id))

		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}
		for _, record := range Records {
			recordName = aws.ToString(record.Name)
			recordType = string(record.Type)

			for _, resourceRecord := range record.ResourceRecords {
				recordValue := resourceRecord.Value
				m.Records = append(
					m.Records,
					Record{
						AWSService:  "Route53",
						Name:        recordName,
						Type:        recordType,
						Value:       aws.ToString(recordValue),
						PrivateZone: privateZone,
					})

			}
		}

	}

}
