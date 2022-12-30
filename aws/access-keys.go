package aws

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/BishopFox/cloudfox/console"
	"github.com/BishopFox/cloudfox/utils"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/sirupsen/logrus"
)

type AccessKeysModule struct {
	// General configuration data
	IAMClient      *iam.Client
	Caller         sts.GetCallerIdentityOutput
	AWSProfile     string
	OutputFormat   string
	Goroutines     int
	WrapTable      bool
	CommandCounter console.CommandCounter

	// Main module data
	AnalyzedUsers []UserKeys

	// Used to store output data for pretty printing
	output utils.OutputData2
	modLog *logrus.Entry
}

type UserKeys struct {
	Username string
	Key      string
}

func (m *AccessKeysModule) PrintAccessKeys(filter string, outputFormat string, outputDirectory string, verbosity int) {
	// These stuct values are used by the output module
	m.output.Verbosity = verbosity
	m.output.Directory = outputDirectory
	m.output.CallingModule = "access-keys"
	m.modLog = utils.TxtLog.WithFields(logrus.Fields{
		"module": m.output.CallingModule,
	},
	)

	if m.AWSProfile == "" {
		m.AWSProfile = utils.BuildAWSPath(m.Caller)
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

		m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", m.AWSProfile)
		//m.output.OutputSelector(outputFormat)
		//utils.OutputSelector(verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.CallingModule, m.output.CallingModule)
		utils.OutputSelector(verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.CallingModule, m.output.CallingModule, m.WrapTable)

		m.writeLoot(m.output.FilePath, verbosity)
		fmt.Printf("[%s][%s] %s access keys found.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), strconv.Itoa(len(m.output.Body)))
	} else {
		fmt.Printf("[%s][%s] No  access keys found, skipping the creation of an output file.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))

	}
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

	// The "PaginationControl" value remains true until all data is received (default is 100 results per page).
	// "" is a control variable used for output continuity, as AWS return the output in pages.
	var PaginationMarker *string
	PaginationControl := true

	for PaginationControl {

		IAMQuery, err := m.IAMClient.ListUsers(context.TODO(), &iam.ListUsersInput{Marker: PaginationMarker})
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		// added this to break out if there no users
		if len(IAMQuery.Users) == 0 {
			break
		}

		// This for loop iterates through all users.
		for PaginationControl {
			PaginationMarker = nil
			for _, user := range IAMQuery.Users {

				results, err := m.IAMClient.ListAccessKeys(context.TODO(), &iam.ListAccessKeysInput{UserName: user.UserName, Marker: PaginationMarker})
				if err != nil {
					m.modLog.Error(err.Error())
					m.CommandCounter.Error++
					break
				}

				// This for loop extracts relevant information for each access key and adds to output array
				for _, key := range results.AccessKeyMetadata {

					if key.Status == "Active" {
						m.AnalyzedUsers = append(m.AnalyzedUsers, UserKeys{Username: *user.UserName, Key: *key.AccessKeyId})
					}
				}
				PaginationControl = results.IsTruncated
				PaginationMarker = results.Marker
			}
		}

		PaginationControl = IAMQuery.IsTruncated
		PaginationMarker = IAMQuery.Marker
	}
}
