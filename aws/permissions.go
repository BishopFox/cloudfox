package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strconv"
	"time"

	"github.com/BishopFox/cloudfox/console"
	"github.com/BishopFox/cloudfox/utils"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/sirupsen/logrus"
)

type IamPermissionsModule struct {
	// General configuration data
	IAMClient *iam.Client

	Caller       sts.GetCallerIdentityOutput
	AWSRegions   []string
	OutputFormat string
	Goroutines   int
	AWSProfile   string
	WrapTable    bool

	// Main module data

	Policies       []GAADPolicy
	Users          []GAADUser
	Roles          []GAADRole
	Groups         []GAADGroup
	Rows           []PermissionsRow
	CommandCounter console.CommandCounter
	// Used to store output data for pretty printing
	output utils.OutputData2
	modLog *logrus.Entry
}

type GAADPolicy struct {
	Name              string
	Arn               string
	PolicyVersionList []types.PolicyVersion
}

type GAADUser struct {
	Name             string
	Arn              string
	AttachedPolicies []types.AttachedPolicy
	InlinePolicies   []types.PolicyDetail
	GroupList        []string
}

type GAADRole struct {
	Arn              string
	Name             string
	AttachedPolicies []types.AttachedPolicy
	InlinePolicies   []types.PolicyDetail
}

type GAADGroup struct {
	Arn              string
	Name             string
	AttachedPolicies []types.AttachedPolicy
	InlinePolicies   []types.PolicyDetail
}

type PermissionsRow struct {
	AWSService string
	Type       string
	Name       string
	Arn        string
	PolicyType string
	PolicyName string
	Effect     string
	Action     string
	Resource   string
}

func (m *IamPermissionsModule) PrintIamPermissions(outputFormat string, outputDirectory string, verbosity int, principal string) {
	// These stuct values are used by the output module
	m.output.Verbosity = verbosity
	m.output.Directory = outputDirectory
	m.output.CallingModule = "permissions"
	m.output.FullFilename = m.output.CallingModule
	m.modLog = utils.TxtLog.WithFields(logrus.Fields{
		"module": m.output.CallingModule,
	})
	if m.AWSProfile == "" {
		m.AWSProfile = utils.BuildAWSPath(m.Caller)
	}
	m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", m.AWSProfile)
	fmt.Printf("[%s][%s] Enumerating IAM permissions for account %s.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), aws.ToString(m.Caller.Account))

	if principal != "" {
		m.output.FullFilename = filepath.Join(fmt.Sprintf("%s-custom-%s", m.output.CallingModule, strconv.FormatInt((time.Now().Unix()), 10)))
	}

	m.getGAAD(principal)
	m.parsePermissions()

	m.output.Headers = []string{
		"Service",
		"Principal Type",
		"Name",
		//"Arn",
		"Policy Type",
		"Policy Name",
		"Effect",
		"Action",
		"Resource",
	}

	//Table rows
	for i := range m.Rows {
		m.output.Body = append(
			m.output.Body,
			[]string{
				m.Rows[i].AWSService,
				m.Rows[i].Type,
				m.Rows[i].Name,
				//m.Rows[i].Arn,
				m.Rows[i].PolicyType,
				m.Rows[i].PolicyName,
				m.Rows[i].Effect,
				m.Rows[i].Action,
				m.Rows[i].Resource,
			},
		)

	}

	if len(m.output.Body) > 0 {
		m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", m.AWSProfile)
		//m.output.OutputSelector3(outputFormat)
		//utils.OutputSelector(verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.FullFilename, m.output.CallingModule)
		utils.OutputSelector(verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.FullFilename, m.output.CallingModule, m.WrapTable)
		fmt.Printf("[%s][%s] %s unique permissions identified.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), strconv.Itoa(len(m.output.Body)))

	} else {
		fmt.Printf("[%s][%s] No IAM permissions found. skipping the creation of an output file.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	}

}

func (m *IamPermissionsModule) getGAAD(principal string) {
	// "PaginationMarker" is a control variable used for output continuity, as AWS return the output in pages.
	var PaginationControl *string
	//var totalRoles int

	// var attachedPolicies []types.AttachedPolicy
	// var inlinePolicies []types.PolicyDetail

	for {
		GAAD, err := m.IAMClient.GetAccountAuthorizationDetails(
			context.TODO(),
			&iam.GetAccountAuthorizationDetailsInput{
				Marker: PaginationControl,
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		for _, policy := range GAAD.Policies {
			//var IAMtype = "Role"
			arn := aws.ToString(policy.Arn)
			name := aws.ToString(policy.PolicyName)

			m.Policies = append(m.Policies, GAADPolicy{
				Arn:               arn,
				Name:              name,
				PolicyVersionList: policy.PolicyVersionList,
			})

		}

		for _, role := range GAAD.RoleDetailList {
			arn := aws.ToString(role.Arn)
			name := aws.ToString(role.RoleName)
			if principal == "" {
				m.Roles = append(m.Roles, GAADRole{
					Arn:              arn,
					Name:             name,
					AttachedPolicies: role.AttachedManagedPolicies,
					InlinePolicies:   role.RolePolicyList,
				})
			} else {
				if arn == principal {
					m.Roles = append(m.Roles, GAADRole{
						Arn:              arn,
						Name:             name,
						AttachedPolicies: role.AttachedManagedPolicies,
						InlinePolicies:   role.RolePolicyList,
					})
				}

			}
		}

		// i think the error here is pagination!!

		for _, user := range GAAD.UserDetailList {
			//var IAMtype = "User"
			arn := aws.ToString(user.Arn)
			name := aws.ToString(user.UserName)
			groupList := user.GroupList
			if principal == "" {
				m.Users = append(m.Users, GAADUser{
					Arn:              arn,
					Name:             name,
					AttachedPolicies: user.AttachedManagedPolicies,
					InlinePolicies:   user.UserPolicyList,
					GroupList:        groupList,
				})
			} else {
				if arn == principal {
					m.Users = append(m.Users, GAADUser{
						Arn:              arn,
						Name:             name,
						AttachedPolicies: user.AttachedManagedPolicies,
						InlinePolicies:   user.UserPolicyList,
						GroupList:        groupList,
					})
				}
			}
		}

		for _, group := range GAAD.GroupDetailList {
			arn := aws.ToString(group.Arn)
			name := aws.ToString(group.GroupName)
			if principal == "" {
				m.Groups = append(m.Groups, GAADGroup{
					Arn:              arn,
					Name:             name,
					AttachedPolicies: group.AttachedManagedPolicies,
					InlinePolicies:   group.GroupPolicyList,
				})
			} else {
				if arn == principal {
					m.Groups = append(m.Groups, GAADGroup{
						Arn:              arn,
						Name:             name,
						AttachedPolicies: group.AttachedManagedPolicies,
						InlinePolicies:   group.GroupPolicyList,
					})
				}
			}
		}

		// Pagination control. After the last page of output, the for loop exits.
		if GAAD.Marker != nil {
			PaginationControl = GAAD.Marker
		} else {
			PaginationControl = nil
			break
		}
	}
}

func (m *IamPermissionsModule) parsePermissions() {

	for i := range m.Roles {

		for _, attachedPolicy := range m.Roles[i].AttachedPolicies {
			m.getPermissionsFromAttachedPolicy(m.Roles[i].Arn, attachedPolicy, "Role", m.Roles[i].Name)
		}

		for _, inlinePolicy := range m.Roles[i].InlinePolicies {
			m.getPermissionsFromInlinePolicy(m.Roles[i].Arn, inlinePolicy, "Role", m.Roles[i].Name)
		}
	}

	for i := range m.Users {
		for _, attachedPolicy := range m.Users[i].AttachedPolicies {
			m.getPermissionsFromAttachedPolicy(m.Users[i].Arn, attachedPolicy, "User", m.Users[i].Name)
		}

		for _, inlinePolicy := range m.Users[i].InlinePolicies {
			m.getPermissionsFromInlinePolicy(m.Users[i].Arn, inlinePolicy, "User", m.Users[i].Name)
		}

		for j, group := range m.Users[i].GroupList {
			for _, gaadGroup := range m.Groups {
				if gaadGroup.Name == group {
					for _, attachedPolicy := range m.Groups[j].AttachedPolicies {
						m.getPermissionsFromAttachedPolicy(m.Users[i].Arn, attachedPolicy, "User", m.Users[i].Name)
					}
					for _, inlinePolicy := range m.Groups[j].InlinePolicies {
						m.getPermissionsFromInlinePolicy(m.Users[i].Arn, inlinePolicy, "User", m.Users[i].Name)
					}
				}
			}

		}
	}

}

func (m *IamPermissionsModule) getPermissionsFromAttachedPolicy(arn string, attachedPolicy types.AttachedPolicy, IAMtype string, name string) {
	//var policies []types.ManagedPolicyDetail
	var s StatementEntry
	var AWSService = "IAM"

	for _, p := range m.Policies {
		if p.Name == aws.ToString(attachedPolicy.PolicyName) {
			for _, d := range p.PolicyVersionList {
				if d.IsDefaultVersion {
					parsedPolicyDocument, _ := parsePolicyDocument(d.Document)
					for _, s = range parsedPolicyDocument.Statement {
						//version := parsedPolicyDocument.Version
						effect := s.Effect
						for _, action := range s.Action {
							for _, resource := range s.Resource {
								m.Rows = append(
									m.Rows,
									PermissionsRow{
										AWSService: AWSService,
										Arn:        arn,
										Name:       name,
										Type:       IAMtype,
										PolicyType: "Managed",
										PolicyName: p.Name,
										Effect:     effect,
										Action:     action,
										Resource:   resource,
									})
							}
						}
					}
				}
			}
		}
	}
}

func (m *IamPermissionsModule) getPermissionsFromInlinePolicy(arn string, inlinePolicy types.PolicyDetail, IAMtype string, name string) {
	//var policies []types.ManagedPolicyDetail
	var s StatementEntry
	var AWSService = "IAM"

	parsedPolicyDocument, _ := parsePolicyDocument(inlinePolicy.PolicyDocument)
	for _, s = range parsedPolicyDocument.Statement {
		//version := parsedPolicyDocument.Version
		effect := s.Effect
		for _, action := range s.Action {
			for _, resource := range s.Resource {
				m.Rows = append(
					m.Rows,
					PermissionsRow{
						AWSService: AWSService,
						Arn:        arn,
						Name:       name,
						Type:       IAMtype,
						PolicyType: "Inline",
						PolicyName: aws.ToString(inlinePolicy.PolicyName),
						Effect:     effect,
						Action:     action,
						Resource:   resource,
					})
			}
		}
	}
}

type policyDocument struct {
	Version   string           `json:"Version"`
	Statement []StatementEntry `json:"Statement"`
}

type StatementEntry struct {
	Effect    string      `json:"Effect"`
	Action    ListOfItems `json:"Action"`
	Resource  ListOfItems `json:"Resource"`
	Condition ListOfItems `json:"Condition"`
}

func parsePolicyDocument(doc *string) (policyDocument, error) {
	document, _ := url.QueryUnescape(aws.ToString(doc))
	var parsedDocumentToJSON policyDocument
	_ = json.Unmarshal([]byte(document), &parsedDocumentToJSON)
	return parsedDocumentToJSON, nil
}

// A custom unmarshaller is necessary because the list of principals can be an array of strings or a string.
// https://stackoverflow.com/questions/65854778/parsing-arn-from-iam-policy-using-regex
type ListOfItems []string

func (r *ListOfItems) UnmarshalJSON(b []byte) error {
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
