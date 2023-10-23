package aws

import (
	"fmt"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/BishopFox/cloudfox/aws/sdk"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/BishopFox/cloudfox/internal/aws/policy"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/sirupsen/logrus"
)

type IamPermissionsModule struct {
	// General configuration data
	IAMClient sdk.AWSIAMClientInterface

	Caller        sts.GetCallerIdentityOutput
	AWSRegions    []string
	AWSOutputType string
	AWSTableCols  string

	Goroutines int
	AWSProfile string
	WrapTable  bool

	// Main module data

	Policies       []GAADPolicy
	Users          []GAADUser
	Roles          []GAADRole
	Groups         []GAADGroup
	Rows           []PermissionsRow
	CommandCounter internal.CommandCounter
	// Used to store output data for pretty printing
	output internal.OutputData2
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
	PolicyArn  string
	Effect     string
	Action     string
	Resource   string
	Condition  string
}

func (m *IamPermissionsModule) PrintIamPermissions(outputDirectory string, verbosity int, principal string) {
	// These struct values are used by the output module
	m.output.Verbosity = verbosity
	m.output.Directory = outputDirectory
	m.output.CallingModule = "permissions"
	m.output.FullFilename = m.output.CallingModule
	m.modLog = internal.TxtLog.WithFields(logrus.Fields{
		"module": m.output.CallingModule,
	})
	if m.AWSProfile == "" {
		m.AWSProfile = internal.BuildAWSPath(m.Caller)
	}
	m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", fmt.Sprintf("%s-%s", m.AWSProfile, aws.ToString(m.Caller.Account)))
	fmt.Printf("[%s][%s] Enumerating IAM permissions for account %s.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), aws.ToString(m.Caller.Account))

	if principal != "" {
		m.output.FullFilename = filepath.Join(fmt.Sprintf("%s-custom-%s", m.output.CallingModule, strconv.FormatInt((time.Now().Unix()), 10)))
	}

	m.getGAAD()
	m.parsePermissions(principal)

	m.output.Headers = []string{
		//"Service",
		"Type",
		"Name",
		"Arn",
		"Policy",
		"Policy Name",
		"Policy Arn",
		"Effect",
		"Action",
		"Resource",
		"Condition",
	}

	//Table rows
	for i := range m.Rows {
		m.output.Body = append(
			m.output.Body,
			[]string{
				//m.Rows[i].AWSService,
				m.Rows[i].Type,
				m.Rows[i].Name,
				m.Rows[i].Arn,
				m.Rows[i].PolicyType,
				m.Rows[i].PolicyName,
				m.Rows[i].PolicyArn,
				m.Rows[i].Effect,
				m.Rows[i].Action,
				m.Rows[i].Resource,
				m.Rows[i].Condition,
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

		// If the user specified table columns, use those.
		// If the user specified -o wide, use the wide default cols for this module.
		// Otherwise, use the hardcoded default cols for this module.
		var tableCols []string
		// If the user specified table columns, use those.
		if m.AWSTableCols != "" {
			tableCols = strings.Split(m.AWSTableCols, ",")
			// If the user specified wide as the output format, use these columns.
		} else if m.AWSOutputType == "wide" {
			tableCols = []string{"Type",
				//"Name",
				"Arn",
				"Policy",
				"Policy Name",
				"Policy Arn",
				"Effect",
				"Action",
				"Resource",
				"Condition"}
			// Otherwise, use the default columns for this module (brief)
		} else {
			tableCols = []string{"Type",
				"Name",
				//"Arn",
				"Policy",
				"Policy Name",
				"Effect",
				"Action",
				"Resource",
				"Condition",
			}
		}

		o.Table.TableFiles = append(o.Table.TableFiles, internal.TableFile{
			Header:    m.output.Headers,
			TableCols: tableCols,
			Body:      m.output.Body,
			Name:      m.output.CallingModule,
		})
		o.PrefixIdentifier = m.AWSProfile
		o.Table.DirectoryName = filepath.Join(outputDirectory, "cloudfox-output", "aws", fmt.Sprintf("%s-%s", m.AWSProfile, aws.ToString(m.Caller.Account)))
		o.WriteFullOutput(o.Table.TableFiles, nil)
		//m.writeLoot(o.Table.DirectoryName, verbosity)
		fmt.Printf("[%s][%s] %s unique permissions identified.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), strconv.Itoa(len(m.output.Body)))

	} else {
		fmt.Printf("[%s][%s] No IAM permissions found. skipping the creation of an output file.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	}
	fmt.Printf("[%s][%s] For context and next steps: https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#%s\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), m.output.CallingModule)
}

func (m *IamPermissionsModule) getGAAD() {
	GAAD, err := sdk.CachedIAMGetAccountAuthorizationDetails(m.IAMClient, aws.ToString(m.Caller.Account))
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	// // if user supplied a principal name without the arn, try to create the arn
	// if !strings.Contains(principal, "arn:") {
	// 	principal = fmt.Sprintf("arn:aws:iam::%s:user/%s", aws.ToString(m.Caller.Account), principal)
	// }

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
		m.Roles = append(m.Roles, GAADRole{
			Arn:              arn,
			Name:             name,
			AttachedPolicies: role.AttachedManagedPolicies,
			InlinePolicies:   role.RolePolicyList,
		})

	}

	for _, user := range GAAD.UserDetailList {
		//var IAMtype = "User"
		arn := aws.ToString(user.Arn)
		name := aws.ToString(user.UserName)
		groupList := user.GroupList
		m.Users = append(m.Users, GAADUser{
			Arn:              arn,
			Name:             name,
			AttachedPolicies: user.AttachedManagedPolicies,
			InlinePolicies:   user.UserPolicyList,
			GroupList:        groupList,
		})
	}

	for _, group := range GAAD.GroupDetailList {
		arn := aws.ToString(group.Arn)
		name := aws.ToString(group.GroupName)

		m.Groups = append(m.Groups, GAADGroup{
			Arn:              arn,
			Name:             name,
			AttachedPolicies: group.AttachedManagedPolicies,
			InlinePolicies:   group.GroupPolicyList,
		})

	}

}

// create a function that will take a principal name and try to see if it is a role, user, or group and return the arn of the principal
func (m *IamPermissionsModule) getPrincipalArn(principal string) string {
	var arn string
	for _, role := range m.Roles {
		if role.Name == principal {
			arn = role.Arn
		}
	}

	for _, user := range m.Users {
		if user.Name == principal {
			arn = user.Arn
		}
	}

	for _, group := range m.Groups {
		if group.Name == principal {
			arn = group.Arn
		}
	}

	return arn
}

func (m *IamPermissionsModule) parsePermissions(principal string) {
	var inputArn string
	for i := range m.Roles {
		if principal == "" {
			for _, attachedPolicy := range m.Roles[i].AttachedPolicies {
				m.getPermissionsFromAttachedPolicy(m.Roles[i].Arn, attachedPolicy, "Role", m.Roles[i].Name)
			}

			for _, inlinePolicy := range m.Roles[i].InlinePolicies {
				m.getPermissionsFromInlinePolicy(m.Roles[i].Arn, inlinePolicy, "Role", m.Roles[i].Name)
			}
		} else {
			// if user supplied a principal name without the arn, try to create the arn
			if !strings.Contains(principal, "arn:") {
				inputArn = fmt.Sprintf("arn:aws:iam::%s:role/%s", aws.ToString(m.Caller.Account), principal)
			} else {
				inputArn = principal
			}

			if strings.ToLower(m.Roles[i].Arn) == strings.ToLower(inputArn) {
				for _, attachedPolicy := range m.Roles[i].AttachedPolicies {
					m.getPermissionsFromAttachedPolicy(m.Roles[i].Arn, attachedPolicy, "Role", m.Roles[i].Name)
				}

				for _, inlinePolicy := range m.Roles[i].InlinePolicies {
					m.getPermissionsFromInlinePolicy(m.Roles[i].Arn, inlinePolicy, "Role", m.Roles[i].Name)
				}
			}
		}

	}

	for i := range m.Users {
		if principal == "" {
			for _, attachedPolicy := range m.Users[i].AttachedPolicies {
				m.getPermissionsFromAttachedPolicy(m.Users[i].Arn, attachedPolicy, "User", m.Users[i].Name)
			}

			for _, inlinePolicy := range m.Users[i].InlinePolicies {
				m.getPermissionsFromInlinePolicy(m.Users[i].Arn, inlinePolicy, "User", m.Users[i].Name)
			}
		} else {
			// if user supplied a principal name without the arn, try to create the arn
			if !strings.Contains(principal, "arn:") {
				inputArn = fmt.Sprintf("arn:aws:iam::%s:user/%s", aws.ToString(m.Caller.Account), principal)
			} else {
				inputArn = principal
			}
			if strings.ToLower(m.Users[i].Arn) == strings.ToLower(inputArn) {
				for _, attachedPolicy := range m.Users[i].AttachedPolicies {
					m.getPermissionsFromAttachedPolicy(m.Users[i].Arn, attachedPolicy, "User", m.Users[i].Name)
				}

				for _, inlinePolicy := range m.Users[i].InlinePolicies {
					m.getPermissionsFromInlinePolicy(m.Users[i].Arn, inlinePolicy, "User", m.Users[i].Name)
				}
			}
		}

		// for each group in the user's group list, get the attached and inline policy names, and then get the permissions from those policies
		for g := range m.Users[i].GroupList {
			if principal == "" {
				for _, group := range m.Groups {
					if group.Name == m.Users[i].GroupList[g] {
						for _, attachedPolicy := range group.AttachedPolicies {
							m.getPermissionsFromAttachedPolicy(m.Users[i].Arn, attachedPolicy, "User", m.Users[i].Name)
						}
						for _, inlinePolicy := range group.InlinePolicies {
							m.getPermissionsFromInlinePolicy(m.Users[i].Arn, inlinePolicy, "User", m.Users[i].Name)
						}
					}
				}
			} else {
				// if user supplied a principal name without the arn, try to create the arn
				if !strings.Contains(principal, "arn:") {
					inputArn = fmt.Sprintf("arn:aws:iam::%s:user/%s", aws.ToString(m.Caller.Account), principal)
				} else {
					inputArn = principal
				}
				if strings.ToLower(m.Users[i].Arn) == strings.ToLower(inputArn) {
					for _, group := range m.Groups {
						if group.Name == m.Users[i].GroupList[g] {
							for _, attachedPolicy := range group.AttachedPolicies {
								m.getPermissionsFromAttachedPolicy(m.Users[i].Arn, attachedPolicy, "User", m.Users[i].Name)
							}
							for _, inlinePolicy := range group.InlinePolicies {
								m.getPermissionsFromInlinePolicy(m.Users[i].Arn, inlinePolicy, "User", m.Users[i].Name)
							}
						}
					}
				}
			}

		}

		// for group := range m.Users[i].GroupList {
		// 	for _, gaadGroup := range m.Groups {
		// 		if gaadGroup.Name == group {
		// 			for _, attachedPolicy := range m.Groups[j].AttachedPolicies {
		// 				m.getPermissionsFromAttachedPolicy(m.Users[i].Arn, attachedPolicy, "User", m.Users[i].Name)
		// 			}
		// 			for _, inlinePolicy := range m.Groups[j].InlinePolicies {
		// 				m.getPermissionsFromInlinePolicy(m.Users[i].Arn, inlinePolicy, "User", m.Users[i].Name)
		// 			}
		// 		}
		// 	}

		// }
	}

}

func (m *IamPermissionsModule) getPermissionsFromAttachedPolicy(arn string, attachedPolicy types.AttachedPolicy, IAMtype string, name string) {
	//var policies []types.ManagedPolicyDetail
	var s policy.PolicyStatement
	var AWSService = "IAM"
	var hasConditions string

	for _, p := range m.Policies {
		if p.Name == aws.ToString(attachedPolicy.PolicyName) {
			for _, d := range p.PolicyVersionList {
				if d.IsDefaultVersion {
					//parsedPolicyDocument, _ := parsePolicyDocument(d.Document)
					document, _ := url.QueryUnescape(aws.ToString(d.Document))
					parsedPolicyDocument, _ := policy.ParseJSONPolicy([]byte(document))
					for _, s = range parsedPolicyDocument.Statement {
						//version := parsedPolicyDocument.Version
						effect := s.Effect
						if s.Action != nil {
							for _, action := range s.Action {
								for _, resource := range s.Resource {
									if s.Condition != nil {
										hasConditions = "Yes"
									} else {
										hasConditions = "No"
									}
									m.Rows = append(
										m.Rows,
										PermissionsRow{
											AWSService: AWSService,
											Arn:        arn,
											Name:       name,
											Type:       IAMtype,
											PolicyType: "Managed",
											PolicyName: p.Name,
											PolicyArn:  p.Arn,
											Effect:     effect,
											Action:     action,
											Resource:   resource,
											Condition:  hasConditions,
										})
								}
							}
						}

						if s.NotAction != nil {
							for _, action := range s.NotAction {
								for _, resource := range s.Resource {
									if s.Condition != nil {
										hasConditions = "Yes"
									} else {
										hasConditions = "No"
									}
									m.Rows = append(
										m.Rows,
										PermissionsRow{
											AWSService: AWSService,
											Arn:        arn,
											Name:       name,
											Type:       IAMtype,
											PolicyType: "Managed",
											PolicyName: p.Name,
											PolicyArn:  p.Arn,
											Effect:     effect,
											Action:     "[NotAction] " + action,
											Resource:   resource,
											Condition:  hasConditions,
										})
								}
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
	var s policy.PolicyStatement
	var AWSService = "IAM"
	var hasConditions string

	//parsedPolicyDocument, _ := parsePolicyDocument(inlinePolicy.PolicyDocument)
	document, _ := url.QueryUnescape(aws.ToString(inlinePolicy.PolicyDocument))
	parsedPolicyDocument, _ := policy.ParseJSONPolicy([]byte(document))

	for _, s = range parsedPolicyDocument.Statement {
		effect := s.Effect
		if s.Action != nil {
			for _, action := range s.Action {
				for _, resource := range s.Resource {
					if s.Condition != nil {
						hasConditions = "Yes"
					} else {
						hasConditions = "No"
					}
					m.Rows = append(
						m.Rows,
						PermissionsRow{
							AWSService: AWSService,
							Arn:        arn,
							Name:       name,
							Type:       IAMtype,
							PolicyType: "Inline",
							PolicyName: aws.ToString(inlinePolicy.PolicyName),
							PolicyArn:  aws.ToString(inlinePolicy.PolicyName),
							Effect:     effect,
							Action:     action,
							Resource:   resource,
							Condition:  hasConditions,
						})
				}
			}
		}
		if s.NotAction != nil {
			for _, action := range s.NotAction {
				for _, resource := range s.Resource {
					if s.Condition != nil {
						hasConditions = "Yes"
					} else {
						hasConditions = "No"
					}
					m.Rows = append(
						m.Rows,
						PermissionsRow{
							AWSService: AWSService,
							Arn:        arn,
							Name:       name,
							Type:       IAMtype,
							PolicyType: "Inline",
							PolicyName: aws.ToString(inlinePolicy.PolicyName),
							PolicyArn:  aws.ToString(inlinePolicy.PolicyName),
							Effect:     effect,
							Action:     "[NotAction] " + action,
							Resource:   resource,
							Condition:  hasConditions,
						})
				}
			}
		}

	}
}
