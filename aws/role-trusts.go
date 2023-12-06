package aws

import (
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/BishopFox/cloudfox/aws/sdk"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/BishopFox/cloudfox/internal/aws/policy"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
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
	AWSOutputType  string
	AWSTableCols   string

	pmapperMod   PmapperModule
	pmapperError error
	iamSimClient IamSimulatorModule

	// Main module data
	AnalyzedRoles  []AnalyzedRole
	RoleTrustTable []RoleTrustRow

	// Used to store output data for pretty printing
	output internal.OutputData2

	modLog *logrus.Entry
}

type RoleTrustRow struct {
	RoleARN                  string
	RoleName                 string
	TrustedPrincipal         string
	TrustedService           string
	TrustedFederatedProvider string
	TrustedFederatedSubject  string
	ExternalID               string
	IsAdmin                  string
	CanPrivEsc               string
}

type AnalyzedRole struct {
	roleARN   *string
	trustsDoc policy.TrustPolicyDocument
	// trustType  string // UNUSED FIELD, PLEASE REVIEW
	Admin      string
	CanPrivEsc string
}

func (m *RoleTrustsModule) PrintRoleTrusts(outputDirectory string, verbosity int) {
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
	m.iamSimClient = InitIamCommandClient(m.IAMClient, m.Caller, m.AWSProfile, m.Goroutines)
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
	o.Table.DirectoryName = filepath.Join(outputDirectory, "cloudfox-output", "aws", fmt.Sprintf("%s-%s", m.AWSProfile, aws.ToString(m.Caller.Account)))

	principalsHeader, principalsBody, principalTableCols := m.printPrincipalTrusts(outputDirectory)
	o.Table.TableFiles = append(o.Table.TableFiles, internal.TableFile{
		Header:    principalsHeader,
		Body:      principalsBody,
		TableCols: principalTableCols,
		Name:      "role-trusts-principals",
	})

	servicesHeader, servicesBody, serviceTableCols := m.printServiceTrusts(outputDirectory)
	o.Table.TableFiles = append(o.Table.TableFiles, internal.TableFile{
		Header:    servicesHeader,
		Body:      servicesBody,
		TableCols: serviceTableCols,
		Name:      "role-trusts-services",
	})

	federatedHeader, federatedBody, federatedTableCols := m.printFederatedTrusts(outputDirectory)
	o.Table.TableFiles = append(o.Table.TableFiles, internal.TableFile{
		Header:    federatedHeader,
		Body:      federatedBody,
		TableCols: federatedTableCols,
		Name:      "role-trusts-federated",
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

func (m *RoleTrustsModule) printPrincipalTrusts(outputDirectory string) ([]string, [][]string, []string) {
	var header []string
	var body [][]string
	m.output.FullFilename = ""
	m.output.Body = nil
	m.output.CallingModule = "role-trusts"
	m.output.FullFilename = "role-trusts-principals"
	header = []string{
		"Account",
		"Role Arn",
		"Role Name",
		"Trusted Principal",
		"ExternalID",
		"IsAdmin?",
		"CanPrivEscToAdmin?",
	}

	// If the user specified table columns, use those.
	// If the user specified -o wide, use the wide default cols for this module.
	// Otherwise, use the hardcoded default cols for this module.
	var tableCols []string
	// If the user specified table columns, use those.
	if m.AWSTableCols != "" {
		tableCols = strings.Split(m.AWSTableCols, ",")
		// If the user specified wide as the output format, use these columns.
	} else if m.AWSOutputType == "wide" {
		tableCols = []string{"Account", "Role Arn", "Trusted Principal", "ExternalID", "IsAdmin?", "CanPrivEscToAdmin?"}
		// Otherwise, use the default columns for this module (brief)
	} else {
		tableCols = []string{"Role Name", "Trusted Principal", "ExternalID", "IsAdmin?", "CanPrivEscToAdmin?"}
	}
	// Remove the pmapper row if there is no pmapper data
	if m.pmapperError != nil {
		sharedLogger.Errorf("%s - %s - No pmapper data found for this account. Skipping the pmapper column in the output table.", m.output.CallingModule, m.AWSProfile)
		tableCols = removeStringFromSlice(tableCols, "CanPrivEscToAdmin?")
	}

	for _, role := range m.AnalyzedRoles {
		for _, statement := range role.trustsDoc.Statement {
			for _, principal := range statement.Principal.AWS {

				RoleTrustRow := RoleTrustRow{
					RoleARN:          aws.ToString(role.roleARN),
					RoleName:         GetResourceNameFromArn(aws.ToString(role.roleARN)),
					TrustedPrincipal: principal,
					ExternalID:       statement.Condition.StringEquals.StsExternalID,
					IsAdmin:          role.Admin,
					CanPrivEsc:       role.CanPrivEsc,
				}
				body = append(body, []string{
					aws.ToString(m.Caller.Account),
					RoleTrustRow.RoleARN,
					RoleTrustRow.RoleName,
					RoleTrustRow.TrustedPrincipal,
					RoleTrustRow.ExternalID,
					RoleTrustRow.IsAdmin,
					RoleTrustRow.CanPrivEsc})
			}
		}
	}

	m.sortTrustsTablePerTrustedPrincipal()
	return header, body, tableCols

}

func (m *RoleTrustsModule) printServiceTrusts(outputDirectory string) ([]string, [][]string, []string) {
	var header []string
	var body [][]string
	m.output.FullFilename = ""
	m.output.Body = nil
	m.output.CallingModule = "role-trusts"
	m.output.FullFilename = "role-trusts-services"
	header = []string{
		"Account",
		"Role Arn",
		"Role Name",
		"Trusted Service",
		"IsAdmin?",
		"CanPrivEscToAdmin?",
	}

	// If the user specified table columns, use those.
	// If the user specified -o wide, use the wide default cols for this module.
	// Otherwise, use the hardcoded default cols for this module.
	var tableCols []string
	// If the user specified table columns, use those.
	if m.AWSTableCols != "" {
		tableCols = strings.Split(m.AWSTableCols, ",")
		// If the user specified wide as the output format, use these columns.
	} else if m.AWSOutputType == "wide" {
		tableCols = []string{"Account", "Role Arn", "Trusted Service", "IsAdmin?", "CanPrivEscToAdmin?"}
		// Otherwise, use the default columns for this module (brief)
	} else {
		tableCols = []string{"Role Name", "Trusted Service", "IsAdmin?", "CanPrivEscToAdmin?"}
	}
	// Remove the pmapper row if there is no pmapper data
	if m.pmapperError != nil {
		sharedLogger.Errorf("%s - %s - No pmapper data found for this account. Skipping the pmapper column in the output table.", m.output.CallingModule, m.AWSProfile)
		tableCols = removeStringFromSlice(tableCols, "CanPrivEscToAdmin?")
	}

	for _, role := range m.AnalyzedRoles {
		for _, statement := range role.trustsDoc.Statement {
			for _, service := range statement.Principal.Service {
				RoleTrustRow := RoleTrustRow{
					RoleARN:        aws.ToString(role.roleARN),
					RoleName:       GetResourceNameFromArn(aws.ToString(role.roleARN)),
					TrustedService: service,
					IsAdmin:        role.Admin,
					CanPrivEsc:     role.CanPrivEsc,
				}
				body = append(body, []string{
					aws.ToString(m.Caller.Account),
					RoleTrustRow.RoleARN,
					RoleTrustRow.RoleName,
					RoleTrustRow.TrustedService,
					RoleTrustRow.IsAdmin,
					RoleTrustRow.CanPrivEsc})

			}
		}
	}

	// sort the rows based on column 2 (service)
	sort.SliceStable(body, func(i, j int) bool {
		return body[i][1] < body[j][1]
	})

	return header, body, tableCols

}

func (m *RoleTrustsModule) printFederatedTrusts(outputDirectory string) ([]string, [][]string, []string) {
	var header []string
	var body [][]string
	m.output.FullFilename = ""
	m.output.Body = nil
	m.output.CallingModule = "role-trusts"
	m.output.FullFilename = "role-trusts-federated"
	header = []string{
		"Account",
		"Role Arn",
		"Role Name",
		"Trusted Provider",
		"Trusted Subject",
		"IsAdmin?",
		"CanPrivEscToAdmin?",
	}

	// If the user specified table columns, use those.
	// If the user specified -o wide, use the wide default cols for this module.
	// Otherwise, use the hardcoded default cols for this module.
	var tableCols []string
	// If the user specified table columns, use those.
	if m.AWSTableCols != "" {
		tableCols = strings.Split(m.AWSTableCols, ",")
		// If the user specified wide as the output format, use these columns.
	} else if m.AWSOutputType == "wide" {
		tableCols = []string{"Account", "Role Arn", "Trusted Provider", "Trusted Subject", "IsAdmin?", "CanPrivEscToAdmin?"}
		// Otherwise, use the default columns for this module (brief)
	} else {
		tableCols = []string{"Role Name", "Trusted Provider", "Trusted Subject", "IsAdmin?", "CanPrivEscToAdmin?"}
	}
	// Remove the pmapper row if there is no pmapper data
	if m.pmapperError != nil {
		sharedLogger.Errorf("%s - %s - No pmapper data found for this account. Skipping the pmapper column in the output table.", m.output.CallingModule, m.AWSProfile)
		tableCols = removeStringFromSlice(tableCols, "CanPrivEscToAdmin?")
	}
	for _, role := range m.AnalyzedRoles {
		for _, statement := range role.trustsDoc.Statement {
			if len(statement.Principal.Federated) > 0 {
				provider, subject := parseFederatedTrustPolicy(statement)
				RoleTrustRow := RoleTrustRow{
					RoleARN:                  aws.ToString(role.roleARN),
					RoleName:                 GetResourceNameFromArn(aws.ToString(role.roleARN)),
					TrustedFederatedProvider: provider,
					TrustedFederatedSubject:  subject,
					IsAdmin:                  role.Admin,
					CanPrivEsc:               role.CanPrivEsc,
				}
				body = append(body, []string{
					aws.ToString(m.Caller.Account),
					RoleTrustRow.RoleARN,
					RoleTrustRow.RoleName,
					RoleTrustRow.TrustedFederatedProvider,
					RoleTrustRow.TrustedFederatedSubject,
					RoleTrustRow.IsAdmin,
					RoleTrustRow.CanPrivEsc})
			}

		}
	}

	m.sortTrustsTablePerTrustedPrincipal()
	return header, body, tableCols

}

func parseFederatedTrustPolicy(statement policy.RoleTrustStatementEntry) (string, string) {
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
		trustsdoc, err := policy.ParseRoleTrustPolicyDocument(role)
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
