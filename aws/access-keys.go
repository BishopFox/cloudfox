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

type AccessKeysModule struct {
	// General configuration data
	IAMClient      sdk.AWSIAMClientInterface
	Caller         sts.GetCallerIdentityOutput
	AWSProfile     string
	OutputFormat   string
	Goroutines     int
	WrapTable      bool
	CommandCounter internal.CommandCounter

	// Main module data
	AnalyzedUsers []UserKeys

	// Used to store output data for pretty printing
	output internal.OutputData2
	modLog *logrus.Entry
}

type UserKeys struct {
	Username string
	Key      string
}

func (m *AccessKeysModule) PrintAccessKeys(filter string, outputFormat string, outputDirectory string, verbosity int) {
	// These struct values are used by the output module
	m.output.Verbosity = verbosity
	m.output.Directory = outputDirectory
	m.output.CallingModule = "access-keys"
	m.modLog = internal.TxtLog.WithFields(logrus.Fields{
		"module": m.output.CallingModule,
	},
	)

	if m.AWSProfile == "" {
		m.AWSProfile = internal.BuildAWSPath(m.Caller)
	}

	fmt.Printf("[%s][%s] Mapping user access keys for account: %s.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), aws.ToString(m.Caller.Account))
	m.getAccessKeysForAllUsers()

	// Variables used to draw table output
	m.output.Headers = []string{
		"User Name",
		"Access Key ID",
	}

	// Table rows
	for _, key := range m.AnalyzedUsers {
		if filter == "none" || key.Key == filter {
			m.output.Body = append(
				m.output.Body,
				[]string{
					key.Username,
					key.Key,
				},
			)
		}
	}
	// Only create output files if there is output
	if len(m.output.Body) > 0 {

		// Pretty prints output
		fmt.Printf("[%s][%s] Only active access keys are shown.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
		//fmt.Printf("[%s][%s] Preparing output.\n\n")

		m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", fmt.Sprintf("%s-%s", m.AWSProfile, aws.ToString(m.Caller.Account)))
		//m.output.OutputSelector(outputFormat)
		//utils.OutputSelector(verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.CallingModule, m.output.CallingModule)
		//internal.OutputSelector(verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.CallingModule, m.output.CallingModule, m.WrapTable, m.AWSProfile)
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
		//m.writeLoot(m.output.FilePath, verbosity)
		fmt.Printf("[%s][%s] %s access keys found.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), strconv.Itoa(len(m.output.Body)))
	} else {
		fmt.Printf("[%s][%s] No  access keys found, skipping the creation of an output file.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	}
	fmt.Printf("[%s][%s] For context and next steps: https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#%s\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), m.output.CallingModule)
}

func (m *AccessKeysModule) writeLoot(outputDirectory string, verbosity int) {
	path := filepath.Join(outputDirectory, "loot")
	err := os.MkdirAll(path, os.ModePerm)
	if err != nil {
		m.modLog.Error(err.Error())
	}
	f := filepath.Join(path, "access-keys.txt")

	var out string

	for _, key := range m.AnalyzedUsers {
		out = out + fmt.Sprintln(key.Key)
	}

	err = os.WriteFile(f, []byte(out), 0644)
	if err != nil {
		m.modLog.Error(err.Error())
	}
	fmt.Printf("[%s][%s] Loot written to [%s]\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), f)

}

func (m *AccessKeysModule) getAccessKeysForAllUsers() {

	ListUsers, err := sdk.CachedIamListUsers(m.IAMClient, aws.ToString(m.Caller.Account))
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
	}

	// added this to break out if there no users
	if len(ListUsers) != 0 {
		for _, user := range ListUsers {

			results, err := sdk.CachedIamListAccessKeys(m.IAMClient, aws.ToString(m.Caller.Account), aws.ToString(user.UserName))
			if err != nil {
				m.modLog.Error(err.Error())
				m.CommandCounter.Error++
				break
			}

			// This for loop extracts relevant information for each access key and adds to output array
			for _, key := range results {

				if key.Status == "Active" {
					m.AnalyzedUsers = append(m.AnalyzedUsers, UserKeys{Username: *user.UserName, Key: *key.AccessKeyId})
				}
			}
		}
	}
}
