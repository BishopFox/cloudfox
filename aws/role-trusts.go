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
	"github.com/bishopfox/knownawsaccountslookup"
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

	pmapperMod          PmapperModule
	pmapperError        error
	PmapperDataBasePath string

	iamSimClient IamSimulatorModule

	// Main module data
	AnalyzedRoles  []AnalyzedRole
	RoleTrustTable []RoleTrustRow

	vendors *knownawsaccountslookup.Vendors

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
	m.vendors = knownawsaccountslookup.NewVendorMap()
	m.vendors.PopulateKnownAWSAccounts()

	fmt.Printf("[%s][%s] Enumerating role trusts for account %s.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), aws.ToString(m.Caller.Account))
	//fmt.Printf("[%s][%s] Looking for pmapper data for this account and building a PrivEsc graph in golang if it exists.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	m.pmapperMod, m.pmapperError = InitPmapperGraph(m.Caller, m.AWSProfile, m.Goroutines, m.PmapperDataBasePath)
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
	rootPrincipalsHeader, rootPrincipalsBody, rootPrincipalTableCols := m.printPrincipalTrustsRootOnly(outputDirectory)
	o.Table.TableFiles = append(o.Table.TableFiles, internal.TableFile{
		Header:            rootPrincipalsHeader,
		Body:              rootPrincipalsBody,
		TableCols:         rootPrincipalTableCols,
		Name:              "role-trusts-principals-root-trusts-without-external-id",
		SkipPrintToScreen: true,
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
		fmt.Printf("[%s][%s] %s service role trusts found.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), strconv.Itoa(len(servicesBody)))
	} else {
		fmt.Printf("[%s][%s] No role trusts found, skipping the creation of an output file.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	}
	if len(federatedBody) > 0 {
		fmt.Printf("[%s][%s] %s federated role trusts found.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), strconv.Itoa(len(federatedBody)))
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
				//check to see if the accountID is known
				if strings.Contains(principal, "arn:aws:iam::") || strings.Contains(principal, "root") {
					accountID := strings.Split(principal, ":")[4]
					vendorName := m.vendors.GetVendorNameFromAccountID(accountID)
					if vendorName != "" {
						principal = fmt.Sprintf("%s (%s)", principal, vendorName)
					}
				}

				RoleTrustRow := RoleTrustRow{
					RoleARN:          aws.ToString(role.roleARN),
					RoleName:         GetResourceNameFromArn(aws.ToString(role.roleARN)),
					TrustedPrincipal: principal,
					// if there is more than one externalID concat them using newlines
					ExternalID: strings.Join(statement.Condition.StringEquals.StsExternalID, "\n"),
					IsAdmin:    role.Admin,
					CanPrivEsc: role.CanPrivEsc,
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

// printPrincipalTrusts but only those that have a trusted principal that contains :root and also does not have an external ID
func (m *RoleTrustsModule) printPrincipalTrustsRootOnly(outputDirectory string) ([]string, [][]string, []string) {
	var header []string
	var body [][]string
	m.output.FullFilename = ""
	m.output.Body = nil
	m.output.CallingModule = "role-trusts"
	m.output.FullFilename = "role-trusts-principals-root-trusts-without-external-id"
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
				if strings.Contains(principal, ":root") && statement.Condition.StringEquals.StsExternalID == nil {
					accountID := strings.Split(principal, ":")[4]
					vendorName := m.vendors.GetVendorNameFromAccountID(accountID)
					if vendorName != "" {
						principal = fmt.Sprintf("%s (%s)", principal, vendorName)
					}

					RoleTrustRow := RoleTrustRow{
						RoleARN:          aws.ToString(role.roleARN),
						RoleName:         GetResourceNameFromArn(aws.ToString(role.roleARN)),
						TrustedPrincipal: principal,
						ExternalID:       strings.Join(statement.Condition.StringEquals.StsExternalID, "\n"),
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
		return body[i][3] < body[j][3]
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
				provider, subjects := parseFederatedTrustPolicy(statement)
				for _, subject := range subjects {
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
	}

	m.sortTrustsTablePerTrustedPrincipal()
	return header, body, tableCols

}

func parseFederatedTrustPolicy(statement policy.RoleTrustStatementEntry) (string, []string) {
	var provider string
	var subjects []string
	if len(statement.Principal.Federated) > 1 {
		sharedLogger.Warnf("Multiple federated providers found in the trust policy. This is not currently supported. Please review the trust policy for specifics.")
		provider = "Multiple Federated Providers"
		subjects = append(subjects, "Review policy for specifics\nand submit issue to cloudfox repo.")
	}

	switch {
	// lets use the Federated field to determine the provider, then based on the provider we can grab the list of subjects
	case strings.Contains(statement.Principal.Federated[0], "token.actions.githubusercontent.com"):
		provider = "GitHub"
		if len(statement.Condition.StringLike.TokenActionsGithubusercontentComSub) > 0 {
			subjects = append(subjects, statement.Condition.StringLike.TokenActionsGithubusercontentComSub...)
		} else if len(statement.Condition.StringEquals.TokenActionsGithubusercontentComSub) > 0 {
			subjects = append(subjects, statement.Condition.StringEquals.TokenActionsGithubusercontentComSub...)
		} else {
			subjects = append(subjects, "ALL REPOS!!!")
		}
	case strings.Contains(statement.Principal.Federated[0], "oidc.eks"):
		// extract accountId from statement.Principal.Federated[0]
		accountId := strings.Split(statement.Principal.Federated[0], ":")[4]
		provider = fmt.Sprintf("EKS-%s", accountId)
		//provider = "EKS"
		//provider = statement.Principal.Federated[0]
		if len(statement.Condition.StringLike.OidcEksSub) > 0 {
			subjects = append(subjects, statement.Condition.StringLike.OidcEksSub...)
		} else if len(statement.Condition.StringEquals.OidcEksSub) > 0 {
			subjects = append(subjects, statement.Condition.StringEquals.OidcEksSub...)
		} else {
			subjects = append(subjects, "ALL SERVICE ACCOUNTS!!!")
		}
		// terraform case
	case strings.Contains(statement.Principal.Federated[0], "app.terraform.io"):
		provider = "Terraform Cloud"
		if len(statement.Condition.StringLike.TerraformSub) > 0 {
			subjects = append(subjects, statement.Condition.StringLike.TerraformSub...)
		} else if len(statement.Condition.StringEquals.TerraformSub) > 0 {
			subjects = append(subjects, statement.Condition.StringEquals.TerraformSub...)
		} else {
			subjects = append(subjects, "ALL WORKSPACES")
		}
		// Azure AD case
	case strings.Contains(statement.Principal.Federated[0], "http://sts.windows.net"):
		provider = "Azure AD"
		if len(statement.Condition.StringLike.AzureADIss) > 0 {
			subjects = append(subjects, statement.Condition.StringLike.AzureADIss...)
		} else if len(statement.Condition.StringEquals.AzureADIss) > 0 {
			subjects = append(subjects, statement.Condition.StringEquals.AzureADIss...)
		} else {
			subjects = append(subjects, "ALL ISSUERS")
		}

	///AWS SSO case
	case strings.Contains(statement.Principal.Federated[0], "AWSSSO"):
		//provider = "AWS SSO"
		accountId := strings.Split(statement.Principal.Federated[0], ":")[4]
		provider = fmt.Sprintf("AWSSSO-%s", accountId)
		subjects = append(subjects, "Not applicable")

	// okta case
	case strings.Contains(statement.Principal.Federated[0], "Okta"):
		provider = "Okta"
		subjects = append(subjects, "Not applicable")

	// cognito case
	case statement.Principal.Federated[0] == "cognito-identity.amazonaws.com":
		provider = "Cognito"
		if statement.Condition.ForAnyValueStringLike.CognitoAMR != "" {
			subjects = append(subjects, statement.Condition.ForAnyValueStringLike.CognitoAMR)
		} else {
			subjects = append(subjects, "ALL IDENTITIES")
		}
		// google workspace case
	case strings.Contains(statement.Principal.Federated[0], "workspace.google.com"):
		provider = "Google Workspace"
		if len(statement.Condition.StringLike.GoogleWorkspaceSub) > 0 {
			subjects = append(subjects, statement.Condition.StringLike.GoogleWorkspaceSub...)
		} else if len(statement.Condition.StringEquals.GoogleWorkspaceSub) > 0 {
			subjects = append(subjects, statement.Condition.StringEquals.GoogleWorkspaceSub...)
		} else {
			subjects = append(subjects, "ALL USERS")
		}
		// GCP case
	case strings.Contains(statement.Principal.Federated[0], "accounts.google.com"):
		provider = "GCP"
		if len(statement.Condition.StringLike.GCPSub) > 0 {
			subjects = append(subjects, statement.Condition.StringLike.GCPSub...)
		} else if len(statement.Condition.StringEquals.GCPSub) > 0 {
			subjects = append(subjects, statement.Condition.StringEquals.GCPSub...)
		} else {
			subjects = append(subjects, "ALL USERS")
		}
	// auth0 case
	//not ready yet
	// case strings.Contains(statement.Principal.Federated[0], "auth0.com"):
	// 	provider = "Auth0"
	// 	if len(statement.Condition.ForAnyValueStringLike.Auth0Amr) > 0 {
	// 		subjects = append(subjects, statement.Condition.ForAnyValueStringLike.Auth0Amr...)
	// 	} else {
	// 		subjects = append(subjects, "ALL GROUPS")
	// 	}
	// circleci case
	case strings.Contains(statement.Principal.Federated[0], "oidc.circleci.com"):
		provider = "CircleCI"
		if len(statement.Condition.StringLike.CircleCIAud) > 0 {
			subjects = append(subjects, statement.Condition.StringLike.CircleCIAud...)
		} else if len(statement.Condition.StringEquals.CircleCIAud) > 0 {
			subjects = append(subjects, statement.Condition.StringEquals.CircleCIAud...)
		} else {
			subjects = append(subjects, "ALL PROJECTS")
		}
	case strings.Contains(statement.Principal.Federated[0], "saml-provider"):
		// the provider name is the last part of the ARN
		provider = strings.Split(statement.Principal.Federated[0], ":saml-provider/")[1]
		subjects = append(subjects, "Not applicable")

	default:
		provider = "Unknown Federated Provider"
		subjects = append(subjects, "Review policy for specifics\nand submit issue to cloudfox repo.")

	}
	return provider, subjects
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
