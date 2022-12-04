package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/BishopFox/cloudfox/console"
	"github.com/BishopFox/cloudfox/utils"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/sirupsen/logrus"
)

type RoleTrustsModule struct {
	// General configuration data
	IAMClientListRoles iam.ListRolesAPIClient
	IAMClient          *iam.Client

	Caller         sts.GetCallerIdentityOutput
	AWSProfile     string
	Goroutines     int
	CommandCounter console.CommandCounter

	// Main module data
	AnalyzedRoles []AnalyzedRole

	// Used to store output data for pretty printing
	output utils.OutputData2

	modLog *logrus.Entry
}

func (m *RoleTrustsModule) PrintRoleTrusts(outputFormat string, outputDirectory string, verbosity int) {
	m.output.Verbosity = verbosity
	m.output.Directory = outputDirectory
	m.output.CallingModule = "role-trusts"
	m.modLog = utils.TxtLog.WithFields(logrus.Fields{
		"module": m.output.CallingModule,
	})
	if m.AWSProfile == "" {
		m.AWSProfile = utils.BuildAWSPath(m.Caller)
	}
	fmt.Printf("[%s][%s] Enumerating role trusts for account %s.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), aws.ToString(m.Caller.Account))

	m.getAllRoleTrusts()
	m.printPrincipalTrusts(outputFormat, outputDirectory)
	m.printServiceTrusts(outputFormat, outputDirectory)
}

func (m *RoleTrustsModule) printPrincipalTrusts(outputFormat string, outputDirectory string) {
	m.output.FullFilename = ""
	m.output.Body = nil
	m.output.CallingModule = "role-trusts"
	m.output.FullFilename = "role-trusts-principals"
	m.output.Headers = []string{
		"Role",
		"Trusted Principal",
		"ExternalID",
		"isAdmin",
	}

	for _, role := range m.AnalyzedRoles {
		if len(role.trustsDoc.Statement[0].Principal.AWS) > 0 {
			for _, principal := range role.trustsDoc.Statement[0].Principal.AWS {
				column1 := aws.ToString(role.roleARN)
				column2 := principal
				column3 := role.trustsDoc.Statement[0].Condition.StringEquals.StsExternalID
				column4 := role.isAdmin
				m.output.Body = append(m.output.Body, []string{column1, column2, column3, column4})
			}
		}
	}
	m.sortTrustsTablePerTrustedPrincipal()
	if len(m.output.Body) > 0 {
		m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", m.AWSProfile)
		////m.output.OutputSelector(outputFormat)
		utils.OutputSelector(m.output.Verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.FullFilename, m.output.CallingModule)
		fmt.Printf("[%s][%s] %s role trusts found.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), strconv.Itoa(len(m.output.Body)))

	} else {
		fmt.Printf("[%s][%s] No role trusts found, skipping the creation of an output file.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	}
}

func (m *RoleTrustsModule) printServiceTrusts(outputFormat string, outputDirectory string) {
	m.output.FullFilename = ""
	m.output.Body = nil
	m.output.CallingModule = "role-trusts"
	m.output.FullFilename = "role-trusts-services"
	m.output.Headers = []string{
		"Role",
		"Trusted Service",
		"ExternalID",
		"isAdmin",
	}

	for _, role := range m.AnalyzedRoles {
		if len(role.trustsDoc.Statement[0].Principal.Service) > 0 {
			for _, service := range role.trustsDoc.Statement[0].Principal.Service {
				column1 := aws.ToString(role.roleARN)
				column2 := service
				column3 := role.trustsDoc.Statement[0].Condition.StringEquals.StsExternalID
				column4 := role.isAdmin
				m.output.Body = append(m.output.Body, []string{column1, column2, column3, column4})
			}
		}
	}

	m.sortTrustsTablePerTrustedPrincipal()
	if len(m.output.Body) > 0 {
		m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", m.AWSProfile)
		//m.output.OutputSelector(outputFormat)
		utils.OutputSelector(m.output.Verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.FullFilename, m.output.CallingModule)
		fmt.Printf("[%s][%s] %s role trusts found.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), strconv.Itoa(len(m.output.Body)))

	} else {
		fmt.Printf("[%s][%s] No role trusts found, skipping the creation of an output file.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	}
}

func (m *RoleTrustsModule) sortTrustsTablePerTrustedPrincipal() {
	sort.Slice(
		m.output.Body,
		func(i int, j int) bool {
			return m.output.Body[i][1] < m.output.Body[j][1]
		},
	)
}

func (m *RoleTrustsModule) getAllRoleTrusts() {
	// "PaginationMarker" is a control variable used for output continuity, as AWS return the output in pages.
	var PaginationMarker *string

	var adminRole string = ""

	// This for loop exits at the end dependeding on whether the output hits its last page (see pagination control block at the end of the loop).
	for {
		results, err := m.IAMClientListRoles.ListRoles(
			context.TODO(),
			&iam.ListRolesInput{
				Marker: PaginationMarker,
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		for _, role := range results.Roles {
			trustsdoc, err := parseRoleTrustPolicyDocument(role)
			if err != nil {
				m.modLog.Error(err.Error())
				m.CommandCounter.Error++
				break
			}
			if role.Arn != nil {
				isRoleAdmin := m.isRoleAdmin(role.Arn)
				if isRoleAdmin {
					adminRole = "YES"
				} else {
					adminRole = "No"

				}
				m.AnalyzedRoles = append(m.AnalyzedRoles, AnalyzedRole{roleARN: role.Arn, trustsDoc: trustsdoc, isAdmin: adminRole})
			}

		}

		// Pagination control. After the last page of output, the for loop exits.
		if results.IsTruncated {
			PaginationMarker = results.Marker
		} else {
			PaginationMarker = nil
			break
		}
	}
}

type AnalyzedRole struct {
	roleARN   *string
	trustsDoc trustPolicyDocument
	trustType string
	isAdmin   string
}

type trustPolicyDocument struct {
	Version   string `json:"Version"`
	Statement []struct {
		Sid       string `json:"Sid"`
		Effect    string `json:"Effect"`
		Principal struct {
			AWS     ListOfPrincipals `json:"AWS"`
			Service ListOfPrincipals `json:"Service"`
		} `json:"Principal"`
		Action    string `json:"Action"`
		Condition struct {
			StringEquals struct {
				StsExternalID string `json:"sts:ExternalId"`
			} `json:"StringEquals"`
		} `json:"Condition"`
	} `json:"Statement"`
}

func parseRoleTrustPolicyDocument(role types.Role) (trustPolicyDocument, error) {
	document, _ := url.QueryUnescape(aws.ToString(role.AssumeRolePolicyDocument))
	var parsedDocumentToJSON trustPolicyDocument
	_ = json.Unmarshal([]byte(document), &parsedDocumentToJSON)
	return parsedDocumentToJSON, nil
}

// A custom unmarshaller is necessary because the list of principals can be an array of strings or a string.
// https://stackoverflow.com/questions/65854778/parsing-arn-from-iam-policy-using-regex
type ListOfPrincipals []string

func (r *ListOfPrincipals) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*r = append(*r, s)
		return nil
	}
	var ss []string
	if err := json.Unmarshal(b, &ss); err == nil {
		*r = ss
		return nil
	}
	return errors.New("cannot unmarshal neither to a string nor a slice of strings")
}

func (m *RoleTrustsModule) isRoleAdmin(principal *string) bool {
	iamSimMod := IamSimulatorModule{
		IAMClient:  m.IAMClient,
		Caller:     m.Caller,
		AWSProfile: m.AWSProfile,
		Goroutines: m.Goroutines,
	}

	adminCheckResult := iamSimMod.isPrincipalAnAdmin(principal)

	if adminCheckResult {
		return true
	} else {
		return false
	}

}
