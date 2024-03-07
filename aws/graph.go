package aws

import (
	"context"
	"fmt"
	"os"
	"strings"

	ingestor "github.com/BishopFox/cloudfox/aws/graph/ingester"
	"github.com/BishopFox/cloudfox/aws/graph/ingester/schema/models"
	"github.com/BishopFox/cloudfox/aws/sdk"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/BishopFox/cloudfox/internal/aws/policy"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/bishopfox/knownawsaccountslookup"
	"github.com/sirupsen/logrus"
)

type GraphCommand struct {

	// General configuration data
	Caller             sts.GetCallerIdentityOutput
	AWSRegions         []string
	Goroutines         int
	AWSProfile         string
	WrapTable          bool
	AWSOutputType      string
	AWSTableCols       string
	Verbosity          int
	AWSOutputDirectory string
	AWSConfig          aws.Config
	Version            string
	SkipAdminCheck     bool

	pmapperMod   PmapperModule
	pmapperError error

	vendors *knownawsaccountslookup.Vendors

	// Main module data
	// Used to store output data for pretty printing
	output internal.OutputData2

	modLog *logrus.Entry
}

func (m *GraphCommand) RunGraphCommand() {

	// These struct values are used by the output module
	m.output.Verbosity = m.Verbosity
	m.output.Directory = m.AWSOutputDirectory
	m.output.CallingModule = "graph"
	m.modLog = internal.TxtLog.WithFields(logrus.Fields{
		"module": m.output.CallingModule,
	})
	if m.AWSProfile == "" {
		m.AWSProfile = internal.BuildAWSPath(m.Caller)
	}

	m.vendors = knownawsaccountslookup.NewVendorMap()
	m.vendors.PopulateKnownAWSAccounts()

	m.modLog.Info("Collecting data for graph ingestor...")

	m.pmapperMod, m.pmapperError = InitPmapperGraph(m.Caller, m.AWSProfile, m.Goroutines)

	////////////////
	// Accounts
	////////////////

	accounts := m.collectAccountDataForGraph()
	// write data to jsonl file for ingestor to read
	fileName := fmt.Sprintf("%s/graph/%s/%s.jsonl", m.output.Directory, aws.ToString(m.Caller.Account), "accounts")
	// create file and directory if it doesnt exist
	if err := os.MkdirAll(fmt.Sprintf("%s/graph/%s", m.output.Directory, aws.ToString(m.Caller.Account)), 0755); err != nil {
		m.modLog.Error(err)
		return
	}

	outputFile, err := os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		m.modLog.Error(err)
		return
	}
	defer outputFile.Close()

	for _, account := range accounts {
		if err := internal.WriteJsonlFile(outputFile, account); err != nil {
			m.modLog.Error(err)
			return
		}
	}

	////////////////
	// Users
	////////////////

	// users := m.collectUserDataForGraph()
	// // write data to jsonl file for ingestor to read
	// fileName = fmt.Sprintf("%s/graph/%s/%s.jsonl", m.output.Directory, aws.ToString(m.Caller.Account), "users")
	// // create file and directory if it doesnt exist
	// if err := os.MkdirAll(fmt.Sprintf("%s/graph/%s", m.output.Directory, aws.ToString(m.Caller.Account)), 0755); err != nil {
	// 	m.modLog.Error(err)
	// 	return
	// }

	// outputFile, err = os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	// if err != nil {
	// 	m.modLog.Error(err)
	// 	return
	// }
	// defer outputFile.Close()

	// for _, user := range users {
	// 	if err := internal.WriteJsonlFile(outputFile, user); err != nil {
	// 		m.modLog.Error(err)
	// 		return
	// 	}
	// }

	////////////////
	// Roles
	////////////////

	roles := m.collectRoleDataForGraph()
	// write data to jsonl file for ingestor to read
	fileName = fmt.Sprintf("%s/graph/%s/%s.jsonl", m.output.Directory, aws.ToString(m.Caller.Account), "roles")
	// create file and directory if it doesnt exist
	if err := os.MkdirAll(fmt.Sprintf("%s/graph/%s", m.output.Directory, aws.ToString(m.Caller.Account)), 0755); err != nil {
		m.modLog.Error(err)
		return
	}

	outputFile, err = os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		m.modLog.Error(err)
		return
	}
	defer outputFile.Close()

	for _, role := range roles {
		if err := internal.WriteJsonlFile(outputFile, role); err != nil {
			m.modLog.Error(err)
			return
		}
	}

	ingestor, err := ingestor.NewCloudFoxIngestor()
	if err != nil {
		return
	}

	// Pmapper hack

	goCtx := context.Background()
	sharedLogger.Infof("Verifying connectivity to Neo4J at %s", ingestor.Uri)
	if err := ingestor.Driver.VerifyConnectivity(goCtx); err != nil {
		sharedLogger.Error(err)
	}
	defer ingestor.Driver.Close(goCtx)
	m.pmapperMod.GenerateCypherStatements(goCtx, ingestor.Driver)

	// back to regular stuff

	ingestor.Run(fmt.Sprintf("%s/graph/%s", m.output.Directory, aws.ToString(m.Caller.Account)))

}

func (m *GraphCommand) collectAccountDataForGraph() []models.Account {
	//OrganizationsCommandClient := InitOrgClient(m.AWSConfig)
	var accounts []models.Account
	OrganizationsCommandClient := InitOrgClient(m.AWSConfig)
	DescribeOrgOutput, err := sdk.CachedOrganizationsDescribeOrganization(OrganizationsCommandClient, aws.ToString(m.Caller.Account))
	if err != nil {
		m.modLog.Fatal(err)
	}
	if DescribeOrgOutput.MasterAccountId == nil {
		m.modLog.Error("Organization is not configured")
	}
	// If the account is not the org mgmt account, it can only see some info about itself and some info about the org mgmt account.
	// populate both of them here.
	if aws.ToString(DescribeOrgOutput.MasterAccountId) != aws.ToString(m.Caller.Account) {

		//create new object of type models.Account for this account
		thisAccount := models.Account{
			Id:  aws.ToString(m.Caller.Account),
			Arn: fmt.Sprintf("arn:aws:iam::%s:root", aws.ToString(m.Caller.Account)),
			//Name:             aws.ToString(m.Caller.Account),
			IsOrgMgmt:        false,
			IsChildAccount:   true,
			OrgMgmtAccountID: aws.ToString(DescribeOrgOutput.MasterAccountId),
			OrganizationID:   aws.ToString(DescribeOrgOutput.Id),
		}
		accounts = append(accounts, thisAccount)

		//create new object of type models.Account for the mgmt account
		mgmtAccount := models.Account{
			Id:    aws.ToString(DescribeOrgOutput.MasterAccountId),
			Arn:   aws.ToString(DescribeOrgOutput.MasterAccountArn),
			Email: aws.ToString(DescribeOrgOutput.MasterAccountEmail),
			//Status:           string(account.Status),
			//JoinedMethod:     string(account.JoinedMethod),
			//JoinedTimestamp:  account.JoinedTimestamp.String(),
			IsOrgMgmt:        true,
			IsChildAccount:   false,
			OrgMgmtAccountID: aws.ToString(DescribeOrgOutput.MasterAccountId),
			OrganizationID:   aws.ToString(DescribeOrgOutput.Id),
		}
		accounts = append(accounts, mgmtAccount)
		return accounts

	} else {
		// In this case we are the org mgmt account, so we can see all the accounts in the org.
		ListAccounts, err := sdk.CachedOrganizationsListAccounts(OrganizationsCommandClient, aws.ToString(DescribeOrgOutput.MasterAccountId))
		if err != nil {
			m.modLog.Fatal(err)
		}
		for _, account := range ListAccounts {
			var isMgmtAccount bool
			var isChildAccount bool
			m.modLog.Info("Account: ", aws.ToString(account.Name))
			if aws.ToString(DescribeOrgOutput.MasterAccountId) == aws.ToString(account.Id) {
				// this is the org mgmt account
				isMgmtAccount = true
				isChildAccount = false
			} else if DescribeOrgOutput.MasterAccountId == nil {
				// this is a standalone account
				isChildAccount = false
				isMgmtAccount = false
			} else {
				// this is a child account
				isChildAccount = true
				isMgmtAccount = false
			}

			//create new object of type models.Account
			account := models.Account{
				Id:               aws.ToString(account.Id),
				Arn:              aws.ToString(account.Arn),
				Name:             aws.ToString(account.Name),
				Email:            aws.ToString(account.Email),
				Status:           string(account.Status),
				JoinedMethod:     string(account.JoinedMethod),
				JoinedTimestamp:  account.JoinedTimestamp.String(),
				IsOrgMgmt:        isMgmtAccount,
				IsChildAccount:   isChildAccount,
				OrgMgmtAccountID: aws.ToString(DescribeOrgOutput.MasterAccountId),
				OrganizationID:   aws.ToString(DescribeOrgOutput.Id),
			}
			accounts = append(accounts, account)
		}
		return accounts
	}
}

func (m *GraphCommand) collectRoleDataForGraph() []models.Role {
	var isAdmin, canPrivEscToAdmin string

	// iamClient := InitIAMClient(m.AWSConfig)
	// iamSimClient := InitIamCommandClient(iamClient, m.Caller, m.AWSProfile, m.Goroutines)
	// localAdminMap := make(map[string]bool)

	var roles []models.Role
	IAMCommandClient := InitIAMClient(m.AWSConfig)
	ListRolesOutput, err := sdk.CachedIamListRoles(IAMCommandClient, aws.ToString(m.Caller.Account))
	if err != nil {
		m.modLog.Error(err)
	}

	for _, role := range ListRolesOutput {
		accountId := strings.Split(aws.ToString(role.Arn), ":")[4]
		trustsdoc, err := policy.ParseRoleTrustPolicyDocument(role)
		if err != nil {
			m.modLog.Error(err.Error())
			break
		}

		// if m.pmapperError == nil {
		// 	isAdmin, canPrivEscToAdmin = GetPmapperResults(m.SkipAdminCheck, m.pmapperMod, role.Arn)
		// } else {
		// 	isAdmin, canPrivEscToAdmin = GetIamSimResult(m.SkipAdminCheck, role.Arn, iamSimClient, localAdminMap)
		// }

		// for _, row := range m.PermissionRowsFromAllProfiles {
		// 	if row.Arn == aws.ToString(role.Arn) {

		// 		// look for cases where there is a permission that allows sts:assumeRole or *
		// 		// lowercase the action and compare it against the list of checks below
		// 		if strings.EqualFold(row.Action, "sts:AssumeRole") ||
		// 			strings.EqualFold(row.Action, "*") ||
		// 			strings.EqualFold(row.Action, "sts:Assume*") ||
		// 			strings.EqualFold(row.Action, "sts:*") {

		// 			if row.Effect == "Allow" {
		// 				//PrivEscPermissions = append(PrivEscPermissions, "sts:AssumeRole")
		// 				if row.Resource == "*" {
		// 					PrivEscPermissions = append(PrivEscPermissions, "sts:AssumeRole")
		// 				} else if strings.EqualFold(row.Resource, aws.ToString(role.Arn)) {
		// 					PrivEscPermissions = append(PrivEscPermissions, "sts:AssumeRole")
		// 				}
		// 			}
		// 		}
		// 		if row.Effect == "Deny" {
		// 			// Remove the string sts:AssumeRole from the PrivEscPermissions slice
		// 			for i, v := range PrivEscPermissions {
		// 				if v == "sts:AssumeRole" {
		// 					PrivEscPermissions = append(PrivEscPermissions[:i], PrivEscPermissions[i+1:]...)
		// 				}
		// 			}
		// 		}
		// 	}
		// }

		var TrustedPrincipals []models.TrustedPrincipal
		var TrustedServices []models.TrustedService
		var TrustedFederatedProviders []models.TrustedFederatedProvider
		//var TrustedFederatedSubjects string
		var trustedProvider string
		var trustedSubjects string
		var vendorName string

		for _, statement := range trustsdoc.Statement {
			for _, principal := range statement.Principal.AWS {
				if strings.Contains(principal, ":root") {
					//check to see if the accountID is known
					accountID := strings.Split(principal, ":")[4]
					vendorName = m.vendors.GetVendorNameFromAccountID(accountID)
				}

				TrustedPrincipals = append(TrustedPrincipals, models.TrustedPrincipal{
					TrustedPrincipal: principal,
					ExternalID:       statement.Condition.StringEquals.StsExternalID,
					VendorName:       vendorName,
					//IsAdmin:           false,
					//CanPrivEscToAdmin: false,
				})

			}
			for _, service := range statement.Principal.Service {
				TrustedServices = append(TrustedServices, models.TrustedService{
					TrustedService: service,
					AccountID:      accountId,
					//IsAdmin:           false,
					//CanPrivEscToAdmin: false,
				})

			}
			for _, federated := range statement.Principal.Federated {
				if statement.Condition.StringLike.TokenActionsGithubusercontentComAud != "" || len(statement.Condition.StringLike.TokenActionsGithubusercontentComSub) > 0 {
					trustedProvider = "GitHub"
					trustedSubjects := strings.Join(statement.Condition.StringLike.TokenActionsGithubusercontentComSub, ",")
					if trustedSubjects == "" {
						trustedSubjects = "ALL REPOS!!!"
					} else {
						trustedSubjects = "Repos: " + trustedSubjects
					}

				} else if statement.Condition.StringEquals.SAMLAud == "https://signin.aws.amazon.com/saml" {
					if strings.Contains(statement.Principal.Federated[0], "AWSSSO") {
						trustedProvider = "AWS SSO" // (" + statement.Principal.Federated[0] + ")"
					} else if strings.Contains(statement.Principal.Federated[0], "Okta") {
						trustedProvider = "Okta" //  (" + statement.Principal.Federated[0] + ")"
					}
					trustedSubjects = "Not applicable"
				} else if statement.Condition.StringEquals.OidcEksAud != "" || statement.Condition.StringEquals.OidcEksSub != nil || statement.Condition.StringLike.OidcEksAud != "" || statement.Condition.StringLike.OidcEksSub != nil {
					trustedProvider = "EKS" // (" + statement.Principal.Federated[0] + ")"
					// if statement.Condition.StringEquals.OidcEksSub != "" {
					// 	trustedSubjects = statement.Condition.StringEquals.OidcEksSub
					// } else if statement.Condition.StringLike.OidcEksSub != "" {
					// 	trustedSubjects = statement.Condition.StringLike.OidcEksSub
					// } else {
					// 	trustedSubjects = "ALL SERVICE ACCOUNTS!"
					// }
					trustedSubjects = "ALL SERVICE ACCOUNTS!"
				} else if statement.Principal.Federated[0] == "cognito-identity.amazonaws.com" {
					trustedProvider = "Cognito" // (" + statement.Principal.Federated[0] + ")"
					if statement.Condition.ForAnyValueStringLike.CognitoAMR != "" {
						trustedSubjects = statement.Condition.ForAnyValueStringLike.CognitoAMR
					}
				} else {
					if trustedProvider == "" && strings.Contains(statement.Principal.Federated[0], "oidc.eks") {
						trustedProvider = "EKS" // (" + statement.Principal.Federated[0] + ")"
						trustedSubjects = "ALL SERVICE ACCOUNTS!"
					} else if trustedProvider == "" && strings.Contains(statement.Principal.Federated[0], "AWSSSO") {
						trustedProvider = "AWS SSO" // (" + statement.Principal.Federated[0] + ")"
					}
					trustedSubjects = "Not applicable"
				}

				TrustedFederatedProviders = append(TrustedFederatedProviders, models.TrustedFederatedProvider{
					TrustedFederatedProvider: federated,
					ProviderShortName:        trustedProvider,
					TrustedSubjects:          trustedSubjects,
					//IsAdmin:                  false,
					//CanPrivEscToAdmin:        false,
				})
			}
		}

		//create new object of type models.Role
		role := models.Role{
			Id:                        aws.ToString(role.Arn),
			AccountID:                 accountId,
			ARN:                       aws.ToString(role.Arn),
			Name:                      aws.ToString(role.RoleName),
			TrustsDoc:                 trustsdoc,
			TrustedPrincipals:         TrustedPrincipals,
			TrustedServices:           TrustedServices,
			TrustedFederatedProviders: TrustedFederatedProviders,
			CanPrivEscToAdmin:         canPrivEscToAdmin,
			IsAdmin:                   isAdmin,
		}
		roles = append(roles, role)
	}
	return roles
}
