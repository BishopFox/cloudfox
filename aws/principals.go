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
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/sirupsen/logrus"
)

type IamPrincipalsModule struct {
	// General configuration data
	IAMClient *iam.Client

	Caller       sts.GetCallerIdentityOutput
	AWSRegions   []string
	OutputFormat string
	Goroutines   int
	AWSProfile   string

	// Main module data
	Users          []User
	Roles          []Role
	Groups         []Group
	CommandCounter console.CommandCounter
	// Used to store output data for pretty printing
	output utils.OutputData2
	modLog *logrus.Entry
}

type User struct {
	AWSService       string
	Type             string
	Arn              string
	Name             string
	AttachedPolicies []string
	InlinePolicies   []string
}

type Group struct {
	AWSService       string
	Type             string
	Arn              string
	Name             string
	AttachedPolicies []string
	InlinePolicies   []string
	AttachedUsers    []string
}

type Role struct {
	AWSService       string
	Type             string
	Arn              string
	Name             string
	AttachedPolicies []string
	InlinePolicies   []string
}

func (m *IamPrincipalsModule) PrintIamPrincipals(outputFormat string, outputDirectory string, verbosity int) {
	// These stuct values are used by the output module
	m.output.Verbosity = verbosity
	m.output.Directory = outputDirectory
	m.output.CallingModule = "principals"
	m.modLog = utils.TxtLog.WithFields(logrus.Fields{
		"module": m.output.CallingModule,
	})
	if m.AWSProfile == "" {
		m.AWSProfile = utils.BuildAWSPath(m.Caller)
	}

	fmt.Printf("[%s][%s] Enumerating IAM Users and Roles for account %s.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), aws.ToString(m.Caller.Account))

	// wg := new(sync.WaitGroup)

	// done := make(chan bool)
	// go console.SpinUntil(m.output.CallingModule, &m.CommandCounter, done)
	// wg.Add(1)
	// m.CommandCounter.Pending++
	//m.executeChecks(wg)
	// wg.Wait()
	// done <- true
	// <-done

	m.getIAMUsers()
	m.getIAMRoles()

	//fmt.Printf("\nAnalyzed Resources by Region\n\n")

	m.output.Headers = []string{
		"Service",
		"Type",
		"Name",
		"Arn",

		// "AttachedPolicies",
		// "InlinePolicies",
	}

	//Table rows
	for i := range m.Users {
		m.output.Body = append(
			m.output.Body,
			[]string{
				m.Users[i].AWSService,
				m.Users[i].Type,
				m.Users[i].Name,
				m.Users[i].Arn,

				// m.Users[i].AttachedPolicies,
				// m.Users[i].InlinePolicies,
			},
		)

	}

	for i := range m.Roles {
		m.output.Body = append(
			m.output.Body,
			[]string{
				m.Roles[i].AWSService,
				m.Roles[i].Type,
				m.Roles[i].Name,
				m.Roles[i].Arn,

				// m.Roles[i].AttachedPolicies,
				// m.Roles[i].InlinePolicies,
			},
		)

	}
	if len(m.output.Body) > 0 {
		m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", m.AWSProfile)
		//m.output.OutputSelector(outputFormat)
		utils.OutputSelector(verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.CallingModule, m.output.CallingModule, m.AWSProfile)
		fmt.Printf("[%s][%s] %s IAM principals found.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), strconv.Itoa(len(m.output.Body)))

	} else {
		fmt.Printf("[%s][%s] No IAM principals found, skipping the creation of an output file.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	}

}

func (m *IamPrincipalsModule) executeChecks(wg *sync.WaitGroup) {
	defer wg.Done()
	m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	m.getIAMUsers()
	m.getIAMRoles()
	m.CommandCounter.Executing--
	m.CommandCounter.Complete++
}

func (m *IamPrincipalsModule) getIAMUsers() {
	// "PaginationMarker" is a control variable used for output continuity, as AWS return the output in pages.
	var PaginationControl *string
	var AWSService = "IAM"

	var IAMtype = "User"
	var attachedPolicies []string
	var inlinePolicies []string

	for {
		ListUsers, err := m.IAMClient.ListUsers(
			context.TODO(),
			&iam.ListUsersInput{
				Marker: PaginationControl,
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		for _, user := range ListUsers.Users {
			arn := user.Arn
			name := user.UserName

			m.Users = append(
				m.Users,
				User{
					AWSService:       AWSService,
					Arn:              aws.ToString(arn),
					Name:             aws.ToString(name),
					Type:             IAMtype,
					AttachedPolicies: attachedPolicies,
					InlinePolicies:   inlinePolicies,
				})
		}

		// Pagination control. After the last page of output, the for loop exits.
		if ListUsers.Marker != nil {
			PaginationControl = ListUsers.Marker
		} else {
			PaginationControl = nil
			break
		}
	}

}

func (m *IamPrincipalsModule) getIAMRoles() {
	// "PaginationMarker" is a control variable used for output continuity, as AWS return the output in pages.
	var PaginationControl *string
	//var totalRoles int
	var AWSService = "IAM"
	var IAMtype = "Role"
	var attachedPolicies []string
	var inlinePolicies []string

	for {
		ListRoles, err := m.IAMClient.ListRoles(
			context.TODO(),
			&iam.ListRolesInput{
				Marker: PaginationControl,
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}
		for _, role := range ListRoles.Roles {
			arn := role.Arn
			name := role.RoleName

			m.Roles = append(
				m.Roles,
				Role{
					AWSService:       AWSService,
					Arn:              aws.ToString(arn),
					Name:             aws.ToString(name),
					Type:             IAMtype,
					AttachedPolicies: attachedPolicies,
					InlinePolicies:   inlinePolicies,
				})
		}

		// Pagination control. After the last page of output, the for loop exits.
		if ListRoles.Marker != nil {
			PaginationControl = ListRoles.Marker
		} else {
			PaginationControl = nil
			//fmt.Printf("IAM Roles: %d\n\n", totalRoles)
			break
		}
	}

}
