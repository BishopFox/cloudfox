package aws

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/BishopFox/cloudfox/aws/sdk"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/sirupsen/logrus"
)

type RoleTrustsModule struct {
	// General configuration data
	IAMClient                        sdk.AWSIAMClientInterface
	IAMSimulatePrincipalPolicyClient iam.SimulatePrincipalPolicyAPIClient

	Caller         sts.GetCallerIdentityOutput
	AWSProfile     string
	Goroutines     int
	CommandCounter internal.CommandCounter
	SkipAdminCheck bool
	WrapTable      bool
	pmapperMod     PmapperModule
	pmapperError   error
	iamSimClient   IamSimulatorModule

	// Main module data
	AnalyzedRoles []AnalyzedRole

	// Used to store output data for pretty printing
	output internal.OutputData2

	modLog *logrus.Entry
}

type AnalyzedRole struct {
	roleARN   *string
	trustsDoc trustPolicyDocument
	// trustType  string // UNUSED FIELD, PLEASE REVIEW
	Admin      string
	CanPrivEsc string
}

type trustPolicyDocument struct {
	Version   string                    `json:"Version"`
	Statement []RoleTrustStatementEntry `json:"Statement"`
}

type RoleTrustStatementEntry struct {
	Sid       string `json:"Sid"`
	Effect    string `json:"Effect"`
	Principal struct {
		AWS       ListOfPrincipals `json:"AWS"`
		Service   ListOfPrincipals `json:"Service"`
		Federated ListOfPrincipals `json:"Federated"`
	} `json:"Principal"`
	Action    string `json:"Action"`
	Condition struct {
		StringEquals struct {
			StsExternalID string `json:"sts:ExternalId"`
			SAMLAud       string `json:"SAML:aud"`
			OidcEksSub    string `json:"OidcEksSub"`
			OidcEksAud    string `json:"OidcEksAud"`
			CognitoAud    string `json:"cognito-identity.amazonaws.com:aud"`
		} `json:"StringEquals"`
		StringLike struct {
			TokenActionsGithubusercontentComSub ListOfPrincipals `json:"token.actions.githubusercontent.com:sub"`
			TokenActionsGithubusercontentComAud string           `json:"token.actions.githubusercontent.com:aud"`
			OidcEksSub                          string           `json:"OidcEksSub"`
			OidcEksAud                          string           `json:"OidcEksAud"`
		} `json:"StringLike"`
		ForAnyValueStringLike struct {
			CognitoAMR string `json:"cognito-identity.amazonaws.com:amr"`
		} `json:"ForAnyValue:StringLike"`
	} `json:"Condition"`
}

func (m *RoleTrustsModule) PrintRoleTrusts(outputFormat string, outputDirectory string, verbosity int) {
	m.output.Verbosity = verbosity
	m.output.Directory = outputDirectory
	m.output.CallingModule = "role-trusts"
	m.modLog = internal.TxtLog.WithFields(logrus.Fields{
		"module": m.output.CallingModule,
	})
	if m.AWSProfile == "" {
		m.AWSProfile = internal.BuildAWSPath(m.Caller)
	}
	localAdminMap := make(map[string]bool)
	fmt.Printf("[%s][%s] Enumerating role trusts for account %s.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), aws.ToString(m.Caller.Account))
	//fmt.Printf("[%s][%s] Looking for pmapper data for this account and building a PrivEsc graph in golang if it exists.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	m.pmapperMod, m.pmapperError = initPmapperGraph(m.Caller, m.AWSProfile, m.Goroutines)
	m.iamSimClient = initIAMSimClient(m.IAMClient, m.Caller, m.AWSProfile, m.Goroutines)
	// if m.pmapperError != nil {
	// 	fmt.Printf("[%s][%s] No pmapper data found for this account. Using cloudfox's iam-simulator for role analysis\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	// } else {
	// 	fmt.Printf("[%s][%s] Found pmapper data for this account. Using it for role analysis\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	// }
	m.getAllRoleTrusts()

	if m.pmapperError == nil {
		for i := range m.AnalyzedRoles {
			m.AnalyzedRoles[i].Admin, m.AnalyzedRoles[i].CanPrivEsc = GetPmapperResults(m.SkipAdminCheck, m.pmapperMod, m.AnalyzedRoles[i].roleARN)
		}
	} else {
		for i := range m.AnalyzedRoles {
			m.AnalyzedRoles[i].Admin, m.AnalyzedRoles[i].CanPrivEsc = GetIamSimResult(m.SkipAdminCheck, m.AnalyzedRoles[i].roleARN, m.iamSimClient, localAdminMap)

		}
	}
	o := internal.OutputClient{
		Verbosity:     verbosity,
		CallingModule: m.output.CallingModule,
		Table: internal.TableClient{
			Wrap: m.WrapTable,
		},
	}

	o.PrefixIdentifier = m.AWSProfile
	o.Table.DirectoryName = filepath.Join(outputDirectory, "cloudfox-output", "aws", fmt.Sprintf("%s-%s", aws.ToString(m.Caller.Account), m.AWSProfile))

	principalsHeader, principalsBody := m.printPrincipalTrusts(outputFormat, outputDirectory)
	o.Table.TableFiles = append(o.Table.TableFiles, internal.TableFile{
		Header: principalsHeader,
		Body:   principalsBody,
		Name:   "role-trusts-principals",
	})

	servicesHeader, servicesBody := m.printServiceTrusts(outputFormat, outputDirectory)
	o.Table.TableFiles = append(o.Table.TableFiles, internal.TableFile{
		Header: servicesHeader,
		Body:   servicesBody,
		Name:   "role-trusts-services",
	})

	federatedHeader, federatedBody := m.printFederatedTrusts(outputFormat, outputDirectory)
	o.Table.TableFiles = append(o.Table.TableFiles, internal.TableFile{
		Header: federatedHeader,
		Body:   federatedBody,
		Name:   "role-trusts-federated",
	})

	o.WriteFullOutput(o.Table.TableFiles, nil)
	if len(principalsBody) > 0 {
		fmt.Printf("[%s][%s] %s principal role trusts found.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), strconv.Itoa(len(principalsBody)))
	} else {
		fmt.Printf("[%s][%s] No role trusts found, skipping the creation of an output file.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	}
	if len(servicesBody) > 0 {
		fmt.Printf("[%s][%s] %s principal role trusts found.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), strconv.Itoa(len(servicesBody)))
	} else {
		fmt.Printf("[%s][%s] No role trusts found, skipping the creation of an output file.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	}
	if len(federatedBody) > 0 {
		fmt.Printf("[%s][%s] %s principal role trusts found.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), strconv.Itoa(len(federatedBody)))
	} else {
		fmt.Printf("[%s][%s] No role trusts found, skipping the creation of an output file.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	}

}

func (m *RoleTrustsModule) printPrincipalTrusts(outputFormat string, outputDirectory string) ([]string, [][]string) {
	var header []string
	var body [][]string
	m.output.FullFilename = ""
	m.output.Body = nil
	m.output.CallingModule = "role-trusts"
	m.output.FullFilename = "role-trusts-principals"
	var column1 string
	if m.pmapperError == nil {
		header = []string{
			"Role",
			"Trusted Principal",
			"ExternalID",
			"IsAdmin?",
			"CanPrivEscToAdmin?",
		}
	} else {
		header = []string{
			"Role",
			"Trusted Principal",
			"ExternalID",
			"IsAdmin?",
			//"CanPrivEscToAdmin?",
		}

	}

	for _, role := range m.AnalyzedRoles {
		for _, statement := range role.trustsDoc.Statement {
			for _, principal := range statement.Principal.AWS {
				if outputFormat == "wide" {
					column1 = aws.ToString(role.roleARN)
				} else {
					column1 = GetResourceNameFromArn(aws.ToString(role.roleARN))
				}
				column2 := principal
				column3 := statement.Condition.StringEquals.StsExternalID
				column4 := role.Admin
				column5 := role.CanPrivEsc
				if m.pmapperError == nil {
					body = append(body, []string{column1, column2, column3, column4, column5})
				} else {
					body = append(body, []string{column1, column2, column3, column4})
				}

			}
		}
	}
	m.sortTrustsTablePerTrustedPrincipal()
	return header, body
	// if len(m.output.Body) > 0 {
	// 		m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", fmt.Sprintf("%s-%s", aws.ToString(m.Caller.Account),m.AWSProfile))
	// 	////m.output.OutputSelector(outputFormat)
	// 	//utils.OutputSelector(m.output.Verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.FullFilename, m.output.CallingModule)
	// 	//internal.OutputSelector(m.output.Verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.FullFilename, m.output.CallingModule, m.WrapTable, m.AWSProfile)
	// 	fmt.Printf("[%s][%s] %s role trusts found.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), strconv.Itoa(len(m.output.Body)))

	// } else {
	// 	fmt.Printf("[%s][%s] No role trusts found, skipping the creation of an output file.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	// }
	// fmt.Printf("[%s][%s] For context and next steps: https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#%s\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), m.output.CallingModule)
}

func (m *RoleTrustsModule) printServiceTrusts(outputFormat string, outputDirectory string) ([]string, [][]string) {
	var header []string
	var body [][]string
	m.output.FullFilename = ""
	m.output.Body = nil
	m.output.CallingModule = "role-trusts"
	m.output.FullFilename = "role-trusts-services"
	var column1 string
	if m.pmapperError == nil {
		header = []string{
			"Role",
			"Trusted Service",
			"ExternalID",
			"IsAdmin?",
			"CanPrivEscToAdmin?",
		}
	} else {
		header = []string{
			"Role",
			"Trusted Service",
			"ExternalID",
			"IsAdmin?",
			//"CanPrivEscToAdmin?",
		}
	}

	for _, role := range m.AnalyzedRoles {
		for _, statement := range role.trustsDoc.Statement {
			for _, service := range statement.Principal.Service {
				if outputFormat == "wide" {
					column1 = aws.ToString(role.roleARN)
				} else {
					column1 = GetResourceNameFromArn(aws.ToString(role.roleARN))
				}
				column2 := service
				column3 := statement.Condition.StringEquals.StsExternalID
				column4 := role.Admin
				column5 := role.CanPrivEsc
				if m.pmapperError == nil {
					body = append(body, []string{column1, column2, column3, column4, column5})
				} else {
					body = append(body, []string{column1, column2, column3, column4})
				}
			}
		}
	}

	m.sortTrustsTablePerTrustedPrincipal()
	return header, body

	// if len(m.output.Body) > 0 {
	// 		m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", fmt.Sprintf("%s-%s", aws.ToString(m.Caller.Account),m.AWSProfile))
	// 	//m.output.OutputSelector(outputFormat)
	// 	//utils.OutputSelector(m.output.Verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.FullFilename, m.output.CallingModule)
	// 	internal.OutputSelector(m.output.Verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.FullFilename, m.output.CallingModule, m.WrapTable, m.AWSProfile)
	// 	fmt.Printf("[%s][%s] %s role trusts found.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), strconv.Itoa(len(m.output.Body)))

	// } else {
	// 	fmt.Printf("[%s][%s] No role trusts found, skipping the creation of an output file.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	// }
}

func (m *RoleTrustsModule) printFederatedTrusts(outputFormat string, outputDirectory string) ([]string, [][]string) {
	var header []string
	var body [][]string
	m.output.FullFilename = ""
	m.output.Body = nil
	m.output.CallingModule = "role-trusts"
	m.output.FullFilename = "role-trusts-federated"
	var column1, column3, column2 string
	if m.pmapperError == nil {

		header = []string{
			"Role",
			"Trusted Provider",
			"Trusted Subject",
			"IsAdmin?",
			"CanPrivEscToAdmin?",
		}
	} else {
		header = []string{
			"Role",
			"Trusted Provider",
			"Trusted Subject",
			"IsAdmin?",
			//"CanPrivEscToAdmin?",
		}
	}

	for _, role := range m.AnalyzedRoles {
		if outputFormat == "wide" {
			column1 = aws.ToString(role.roleARN)
		} else {
			column1 = GetResourceNameFromArn(aws.ToString(role.roleARN))
		}
		for _, statement := range role.trustsDoc.Statement {
			if len(statement.Principal.Federated) > 0 {
				column2, column3 = parseFederatedTrustPolicy(statement)
				column4 := role.Admin
				column5 := role.CanPrivEsc
				if m.pmapperError == nil {
					body = append(body, []string{column1, column2, column3, column4, column5})
				} else {
					body = append(body, []string{column1, column2, column3, column4})
				}
			}
		}
	}

	m.sortTrustsTablePerTrustedPrincipal()
	return header, body

	// if len(m.output.Body) > 0 {
	// 		m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", fmt.Sprintf("%s-%s", aws.ToString(m.Caller.Account),m.AWSProfile))
	// 	//m.output.OutputSelector(outputFormat)
	// 	//utils.OutputSelector(m.output.Verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.FullFilename, m.output.CallingModule)
	// 	internal.OutputSelector(m.output.Verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.FullFilename, m.output.CallingModule, m.WrapTable, m.AWSProfile)
	// 	fmt.Printf("[%s][%s] %s role trusts found.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), strconv.Itoa(len(m.output.Body)))

	// } else {
	// 	fmt.Printf("[%s][%s] No role trusts found, skipping the creation of an output file.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	// }
}

func parseFederatedTrustPolicy(statement RoleTrustStatementEntry) (string, string) {
	var column2, column3 string
	if statement.Condition.StringLike.TokenActionsGithubusercontentComAud != "" || len(statement.Condition.StringLike.TokenActionsGithubusercontentComSub) > 0 {
		column2 = "GitHub Actions" //  (" + statement.Principal.Federated[0] + ")"
		trustedRepos := strings.Join(statement.Condition.StringLike.TokenActionsGithubusercontentComSub, "\n")
		if trustedRepos == "" {
			column3 = "ALL REPOS!!!"
		} else {
			column3 = trustedRepos
		}
	} else if statement.Condition.StringEquals.SAMLAud == "https://signin.aws.amazon.com/saml" {
		if strings.Contains(statement.Principal.Federated[0], "AWSSSO") {
			column2 = "AWS SSO" // (" + statement.Principal.Federated[0] + ")"
		} else if strings.Contains(statement.Principal.Federated[0], "Okta") {
			column2 = "Okta" //  (" + statement.Principal.Federated[0] + ")"
		}
		column3 = "Not applicable"
	} else if statement.Condition.StringEquals.OidcEksAud != "" || statement.Condition.StringEquals.OidcEksSub != "" || statement.Condition.StringLike.OidcEksAud != "" || statement.Condition.StringLike.OidcEksSub != "" {
		column2 = "EKS" // (" + statement.Principal.Federated[0] + ")"
		if statement.Condition.StringEquals.OidcEksSub != "" {
			column3 = statement.Condition.StringEquals.OidcEksSub
		} else if statement.Condition.StringLike.OidcEksSub != "" {
			column3 = statement.Condition.StringLike.OidcEksSub
		} else {
			column3 = "ALL SERVICE ACCOUNTS!"
		}
	} else if statement.Principal.Federated[0] == "cognito-identity.amazonaws.com" {
		column2 = "Cognito" // (" + statement.Principal.Federated[0] + ")"
		if statement.Condition.ForAnyValueStringLike.CognitoAMR != "" {
			column3 = statement.Condition.ForAnyValueStringLike.CognitoAMR
		}
	} else {
		if column2 == "" && strings.Contains(statement.Principal.Federated[0], "oidc.eks") {
			column2 = "EKS" // (" + statement.Principal.Federated[0] + ")"
			column3 = "ALL SERVICE ACCOUNTS!"
		} else if column2 == "" && strings.Contains(statement.Principal.Federated[0], "AWSSSO") {
			column2 = "AWS SSO" // (" + statement.Principal.Federated[0] + ")"
		}

	}
	return column2, column3
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
	ListRoles, err := sdk.CachedIamListRoles(m.IAMClient, aws.ToString(m.Caller.Account))
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
	}

	for _, role := range ListRoles {
		trustsdoc, err := parseRoleTrustPolicyDocument(role)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		if role.Arn != nil {
			m.AnalyzedRoles = append(m.AnalyzedRoles, AnalyzedRole{
				roleARN:    role.Arn,
				trustsDoc:  trustsdoc,
				Admin:      "",
				CanPrivEsc: "",
			})
		}

	}

}

func parseRoleTrustPolicyDocument(role types.Role) (trustPolicyDocument, error) {
	document, _ := url.QueryUnescape(aws.ToString(role.AssumeRolePolicyDocument))

	// These next six lines are a hack, needed because the EKS OIDC json field name is dynamic
	// and therefore can't be used to unmarshall in a predictable way. The hack involves replacing
	// the random pattern with a predictable one so that we can add the predictable one in the struct
	// used to unmarshall.
	pattern := `(\w+)\:`
	pattern2 := `".[a-zA-Z0-9\-\.]+/id/`
	var reEKSSub = regexp.MustCompile(pattern2 + pattern + "sub")
	var reEKSAud = regexp.MustCompile(pattern2 + pattern + "aud")
	document = reEKSSub.ReplaceAllString(document, "\"OidcEksSub")
	document = reEKSAud.ReplaceAllString(document, "\"OidcEksAud")

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
