package aws

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/BishopFox/cloudfox/internal/aws/policy"
	"github.com/BishopFox/cloudfox/internal/common"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/bishopfox/knownawsaccountslookup"
	"github.com/dominikbraun/graph"
	"github.com/sirupsen/logrus"
)

type CaperCommand struct {

	// General configuration data
	Caller              sts.GetCallerIdentityOutput
	AWSRegions          []string
	Goroutines          int
	AWSProfile          string
	WrapTable           bool
	AWSOutputType       string
	AWSTableCols        string
	Verbosity           int
	AWSOutputDirectory  string
	AWSConfig           aws.Config
	Version             string
	SkipAdminCheck      bool
	GlobalGraph         graph.Graph[string, string]
	PmapperDataBasePath string

	output internal.OutputData2
	modLog *logrus.Entry
}

func (m *CaperCommand) RunCaperCommand() {

	// These struct values are used by the output module
	m.output.Verbosity = m.Verbosity
	m.output.Directory = m.AWSOutputDirectory
	m.output.CallingModule = "caper"
	m.modLog = internal.TxtLog.WithFields(logrus.Fields{
		"module": m.output.CallingModule,
	})
	if m.AWSProfile == "" {
		m.AWSProfile = internal.BuildAWSPath(m.Caller)
	}
	m.output.FilePath = filepath.Join(m.AWSOutputDirectory, "cloudfox-output", "aws", fmt.Sprintf("%s-%s", m.AWSProfile, aws.ToString(m.Caller.Account)))

	o := internal.OutputClient{
		Verbosity:     m.Verbosity,
		CallingModule: m.output.CallingModule,
		Table: internal.TableClient{
			Wrap: m.WrapTable,
		},
	}

	o.PrefixIdentifier = m.AWSProfile
	o.Table.DirectoryName = filepath.Join(m.AWSOutputDirectory, "cloudfox-output", "aws", fmt.Sprintf("%s-%s", m.AWSProfile, aws.ToString(m.Caller.Account)))

	// Table #1: Inbound Privilege Escalation Paths
	fmt.Println("Printing inbound privesc paths for account: ", aws.ToString(m.Caller.Account))
	header, body, _ := m.generateInboundPrivEscTableData()
	o.Table.TableFiles = append(o.Table.TableFiles, internal.TableFile{
		Header: header,
		Body:   body,
		//TableCols:         tableCols,
		Name:              "inbound-privesc-paths",
		SkipPrintToScreen: false,
	})

	// // Table #2: Outbound Privilege Escalation Paths
	// header, body, tableCols := m.generateOutBoundPrivEscTable()
	// o.Table.TableFiles = append(o.Table.TableFiles, internal.TableFile{
	// 	Header:            header,
	// 	Body:              body,
	// 	TableCols:         tableCols,
	// 	Name:              "outbound-privesc-paths",
	// 	SkipPrintToScreen: false,
	// })

	o.WriteFullOutput(o.Table.TableFiles, nil)

}

func (m *CaperCommand) generateInboundPrivEscTableData() ([]string, [][]string, []string) {
	var body [][]string
	var tableCols []string
	var header []string
	header = []string{
		"Account",
		"Source",
		"Target",
		"isTargetAdmin",
		"Summary",
	}

	// If the user specified table columns, use those.
	// If the user specified -o wide, use the wide default cols for this module.
	// Otherwise, use the hardcoded default cols for this module.

	// If the user specified table columns, use those.
	if m.AWSTableCols != "" {
		tableCols = strings.Split(m.AWSTableCols, ",")
		// If the user specified wide as the output format, use these columns.
	} else if m.AWSOutputType == "wide" {
		tableCols = []string{
			"Account",
			"Source",
			"Target",
			"isTargetAdmin",
			"Summary",
		}
		// Otherwise, use these columns.
	} else {
		tableCols = []string{
			"Source",
			"Target",
			"isTargetAdmin",
			"Summary",
		}
	}

	//var reason string
	var paths string
	var privescPathsBody [][]string
	//var vertices map[string]map[string]graph.Edge[string]
	//vertices, err := graph.TopologicalSort(m.GlobalGraph)
	//vertices, err := m.GlobalGraph.AdjacencyMap()

	// if err != nil {
	// 	m.modLog.Error(err)
	// 	fmt.Println("Error sorting graph: ", err)
	// }
	//edges, _ := m.GlobalGraph.Edges()
	//var reason string
	adjacencyMap, _ := m.GlobalGraph.AdjacencyMap()
	for destination := range adjacencyMap {
		d, destinationVertexWithProperties, _ := m.GlobalGraph.VertexWithProperties(destination)
		//for the destination vertex, we only want to deal with the ones that are in this account
		if destinationVertexWithProperties.Attributes["AccountID"] == aws.ToString(m.Caller.Account) {
			// now let's look at every other vertex and see if it has a path to this destination
			for source := range adjacencyMap {
				s, sourceVertexWithProperties, _ := m.GlobalGraph.VertexWithProperties(source)
				//for the source vertex, we only want to deal with the ones that are NOT in this account
				if sourceVertexWithProperties.Attributes["AccountID"] != aws.ToString(m.Caller.Account) {
					// now let's see if there is a path from this source to our destination
					path, _ := graph.ShortestPath(m.GlobalGraph, s, d)
					// if we have a path, then lets document this source as having a path to our destination
					if path != nil {
						if s != d {
							paths = ""
							// if we got here theres a path. Lets print the reason and the short reason for each edge in the path to the screen
							// and then lets print the full path to the screen
							for i := 0; i < len(path)-1; i++ {
								thisEdge, _ := m.GlobalGraph.Edge(path[i], path[i+1])

								for _, value := range thisEdge.Properties.Attributes {
									value = strings.ReplaceAll(value, ",", " and")
									paths += fmt.Sprintf("%s %s %s\n", thisEdge.Source, value, thisEdge.Target)
								}
							}

							//trim the last newline from csvPaths
							paths = strings.TrimSuffix(paths, "\n")
							if destinationVertexWithProperties.Attributes["IsAdminString"] == "Yes" {
								privescPathsBody = append(privescPathsBody, []string{
									aws.ToString(m.Caller.Account),
									s,
									magenta(d),
									magenta(destinationVertexWithProperties.Attributes["IsAdminString"]),
									paths})
							} else {
								privescPathsBody = append(privescPathsBody, []string{
									aws.ToString(m.Caller.Account),
									s,
									d,
									destinationVertexWithProperties.Attributes["IsAdminString"],
									paths})
							}

						}
					}
				}
			}
		}

	}

	// if destinationVertexWithProperties.Attributes["IsAdminString"] == "Yes" {
	// 	fmt.Println("Admin: ", d)
	// }
	// if destinationVertexWithProperties.Attributes["CanPrivEscToAdminString"] == "Yes" {
	// 	fmt.Println("Has Path to admin: ", d)
	// }

	body = append(body, privescPathsBody...)
	return header, body, tableCols

}

func ConvertIAMRoleToNode(role types.Role, vendors *knownawsaccountslookup.Vendors) Node {
	//var isAdmin, canPrivEscToAdmin string

	accountId := strings.Split(aws.ToString(role.Arn), ":")[4]
	trustsdoc, err := policy.ParseRoleTrustPolicyDocument(role)
	if err != nil {
		internal.TxtLog.Error(err.Error())
		return Node{}
	}

	var TrustedPrincipals []TrustedPrincipal
	var TrustedServices []TrustedService
	var TrustedFederatedProviders []TrustedFederatedProvider
	//var TrustedFederatedSubjects string
	var trustedProvider string
	var trustedSubjects []string
	var vendorName string

	for _, statement := range trustsdoc.Statement {
		for _, principal := range statement.Principal.AWS {
			if strings.Contains(principal, ":root") {
				//check to see if the accountID is known
				accountID := strings.Split(principal, ":")[4]
				vendorName = vendors.GetVendorNameFromAccountID(accountID)
			}

			TrustedPrincipals = append(TrustedPrincipals, TrustedPrincipal{
				TrustedPrincipal: principal,
				ExternalID:       statement.Condition.StringEquals.StsExternalID,
				VendorName:       vendorName,
				//IsAdmin:           false,
				//CanPrivEscToAdmin: false,
			})

		}
		for _, service := range statement.Principal.Service {
			TrustedServices = append(TrustedServices, TrustedService{
				TrustedService: service,
				AccountID:      accountId,
				//IsAdmin:           false,
				//CanPrivEscToAdmin: false,
			})

		}
		for _, federated := range statement.Principal.Federated {
			if statement.Condition.StringLike.TokenActionsGithubusercontentComAud != "" || len(statement.Condition.StringLike.TokenActionsGithubusercontentComSub) > 0 {
				trustedProvider = "GitHub"
				//trustedSubjects = strings.Join(statement.Condition.StringLike.TokenActionsGithubusercontentComSub, ",")
				trustedSubjects = statement.Condition.StringLike.TokenActionsGithubusercontentComSub
				if strings.Join(statement.Condition.StringLike.TokenActionsGithubusercontentComSub, ",") == "" {
					trustedSubjects = append(trustedSubjects, "ALL REPOS")
				}
				// 	} else {
				// 	trustedSubjects = "Repos: " + trustedSubjects
				// }

			} else if statement.Condition.StringEquals.SAMLAud == "https://signin.aws.amazon.com/saml" {
				if strings.Contains(statement.Principal.Federated[0], "AWSSSO") {
					trustedProvider = "AWS SSO" // (" + statement.Principal.Federated[0] + ")"
				} else if strings.Contains(statement.Principal.Federated[0], "Okta") {
					trustedProvider = "Okta" //  (" + statement.Principal.Federated[0] + ")"
				}
				trustedSubjects = append(trustedSubjects, "Not applicable")
			} else if statement.Condition.StringEquals.OidcEksAud != "" || statement.Condition.StringEquals.OidcEksSub != "" || statement.Condition.StringLike.OidcEksAud != "" || statement.Condition.StringLike.OidcEksSub != "" {
				trustedProvider = "EKS" // (" + statement.Principal.Federated[0] + ")"
				if statement.Condition.StringEquals.OidcEksSub != "" {
					trustedSubjects = append(trustedSubjects, statement.Condition.StringEquals.OidcEksSub)
				} else if statement.Condition.StringLike.OidcEksSub != "" {
					trustedSubjects = append(trustedSubjects, statement.Condition.StringLike.OidcEksSub)
				} else {
					trustedSubjects = append(trustedSubjects, "ALL SERVICE ACCOUNTS!")
				}
			} else if statement.Principal.Federated[0] == "cognito-identity.amazonaws.com" {
				trustedProvider = "Cognito" // (" + statement.Principal.Federated[0] + ")"
				if statement.Condition.ForAnyValueStringLike.CognitoAMR != "" {
					trustedSubjects = append(trustedSubjects, statement.Condition.ForAnyValueStringLike.CognitoAMR)
				}
			} else {
				if trustedProvider == "" && strings.Contains(statement.Principal.Federated[0], "oidc.eks") {
					trustedProvider = "EKS" // (" + statement.Principal.Federated[0] + ")"
					trustedSubjects = append(trustedSubjects, "ALL SERVICE ACCOUNTS!")
				} else if trustedProvider == "" && strings.Contains(statement.Principal.Federated[0], "AWSSSO") {
					trustedProvider = "AWS SSO" // (" + statement.Principal.Federated[0] + ")"
				}
				trustedSubjects = append(trustedSubjects, "Not applicable")
			}

			TrustedFederatedProviders = append(TrustedFederatedProviders, TrustedFederatedProvider{
				TrustedFederatedProvider: federated,
				ProviderShortName:        trustedProvider,
				TrustedSubjects:          trustedSubjects,
				//IsAdmin:                  false,
				//CanPrivEscToAdmin:        false,
			})
		}
	}

	node := Node{
		Arn:                       aws.ToString(role.Arn),
		Type:                      "Role",
		AccountID:                 accountId,
		Name:                      aws.ToString(role.RoleName),
		TrustsDoc:                 trustsdoc,
		TrustedPrincipals:         TrustedPrincipals,
		TrustedServices:           TrustedServices,
		TrustedFederatedProviders: TrustedFederatedProviders,
	}

	return node
}

func ConvertIAMUserToNode(user types.User) Node {
	accountId := strings.Split(aws.ToString(user.Arn), ":")[4]

	//create new object of type models.User
	// cfUser := models.User{
	// 	Id:                aws.ToString(user.UserId),
	// 	ARN:               aws.ToString(user.Arn),
	// 	Name:              aws.ToString(user.UserName),
	// 	IsAdmin:           false,
	// 	CanPrivEscToAdmin: false,
	// }

	node := Node{
		Arn:       aws.ToString(user.Arn),
		Type:      "User",
		AccountID: accountId,
		Name:      aws.ToString(user.UserName),
	}

	return node
}

func FindVerticesInRoleTrust(a Node, vendors *knownawsaccountslookup.Vendors) []Node {

	var newNodes []Node

	// get thisAccount id from role arn
	// var thisAccount string
	// if len(a.Arn) >= 25 {
	// 	thisAccount = a.Arn[13:25]
	// } else {
	// 	fmt.Sprintf("Could not get account number from this role arn%s", a.Arn)
	// }

	for _, TrustedPrincipal := range a.TrustedPrincipals {
		//get account id from the trusted principal arn
		var trustedPrincipalAccount string
		if len(TrustedPrincipal.TrustedPrincipal) >= 25 {
			trustedPrincipalAccount = TrustedPrincipal.TrustedPrincipal[13:25]
		} else {
			fmt.Sprintf("Could not get account number from this TrustedPrincipal%s", TrustedPrincipal.TrustedPrincipal)
		}

		// If the role trusts a principal in this account or another account using the :root notation, then we need to iterate over all of the rows in AllPermissionsRows to find the principals that have sts:AssumeRole permissions on this role
		// if the role we are looking at trusts root in it's own account

		// if strings.Contains(TrustedPrincipal.TrustedPrincipal, fmt.Sprintf("%s:root", thisAccount)) {

		// 	newNodes = append(newNodes, Node{
		// 		Arn:       a.Arn,
		// 		Type:      "Account",
		// 		AccountID: a.AccountID,
		// 		Name:      a.Name,
		// 	})

		// } else

		if strings.Contains(TrustedPrincipal.TrustedPrincipal, ":root") && TrustedPrincipal.VendorName != "" {
			newNodes = append(newNodes, Node{
				Arn: fmt.Sprintf("%s [%s]", TrustedPrincipal.TrustedPrincipal, TrustedPrincipal.VendorName),
				//Arn:        TrustedPrincipal.VendorName,
				Type:       "Account",
				AccountID:  trustedPrincipalAccount,
				Name:       TrustedPrincipal.VendorName,
				VendorName: TrustedPrincipal.VendorName,
			})

			// } else if strings.Contains(TrustedPrincipal.TrustedPrincipal, fmt.Sprintf("%s:root", trustedPrincipalAccount)) {
			// 	newNodes = append(newNodes, Node{
			// 		Arn:       TrustedPrincipal.TrustedPrincipal,
			// 		Type:      "Account",
			// 		AccountID: trustedPrincipalAccount,
			// 	})

		} else if strings.Contains(TrustedPrincipal.TrustedPrincipal, fmt.Sprintf(":user")) {
			newNodes = append(newNodes, Node{
				Arn:       TrustedPrincipal.TrustedPrincipal,
				Type:      "User",
				AccountID: trustedPrincipalAccount,
			})

		} else if strings.Contains(TrustedPrincipal.TrustedPrincipal, fmt.Sprintf(":role")) {
			newNodes = append(newNodes, Node{
				Arn:       TrustedPrincipal.TrustedPrincipal,
				Type:      "Role",
				AccountID: trustedPrincipalAccount,
			})

		} else if strings.Contains(TrustedPrincipal.TrustedPrincipal, fmt.Sprintf(":group")) {
			newNodes = append(newNodes, Node{
				Arn:       TrustedPrincipal.TrustedPrincipal,
				Type:      "Group",
				AccountID: trustedPrincipalAccount,
			})

		} else if strings.Contains(TrustedPrincipal.TrustedPrincipal, fmt.Sprintf(":assumed-role")) {
			newNodes = append(newNodes, Node{
				Arn:       TrustedPrincipal.TrustedPrincipal,
				Type:      "AssumedRole",
				AccountID: trustedPrincipalAccount,
			})
		}
	}
	// pmapper takes care of this part so commenting out for now - but leaving as a placeholder
	// for _, TrustedService := range a.TrustedServices {
	// 	// make relationship from trusted service to this role of type can assume
	// 	// make relationship from this role to trusted service of type can be assumed by
	// }

	for _, TrustedFederatedProvider := range a.TrustedFederatedProviders {
		// make relationship from trusted federated provider to this role of type can assume

		var providerAndSubject string
		for _, trustedSubject := range TrustedFederatedProvider.TrustedSubjects {
			if trustedSubject == "Not applicable" {
				providerAndSubject = TrustedFederatedProvider.ProviderShortName
			} else {
				providerAndSubject = TrustedFederatedProvider.ProviderShortName + ":" + trustedSubject
			}
			newNodes = append(newNodes, Node{
				Arn:       providerAndSubject,
				Name:      TrustedFederatedProvider.ProviderShortName,
				Type:      "FederatedIdentity",
				AccountID: a.AccountID,
			})
		}

	}

	return newNodes
}

func MergeNodes(nodes []Node) []Node {
	nodeMap := make(map[string]Node)

	for _, node := range nodes {
		existingNode, exists := nodeMap[node.Arn]
		if exists {
			// fmt.Println("Found a duplicate node: %s, merging", node.Arn)
			// fmt.Println("Existing node: %v", existingNode)
			// fmt.Println("New node: %v", node)

			mergedNode := mergeNodeData(existingNode, node)
			nodeMap[node.Arn] = mergedNode
			//fmt.Println("Merged node: %v", mergedNode)
		} else {
			nodeMap[node.Arn] = node
		}
	}

	var mergedNodes []Node
	for _, node := range nodeMap {
		mergedNodes = append(mergedNodes, node)
	}

	return mergedNodes
}

func mergeNodeData(existingNode Node, newNode Node) Node {
	if existingNode.Arn == "" {
		existingNode.Arn = newNode.Arn
	} else {
		existingNode.Arn = existingNode.Arn
	}
	if existingNode.Name == "" {
		existingNode.Name = newNode.Name
	} else {
		existingNode.Name = existingNode.Name
	}
	if existingNode.Type == "" {
		existingNode.Type = newNode.Type
	} else {
		existingNode.Type = existingNode.Type
	}
	if existingNode.AccountID == "" {
		existingNode.AccountID = newNode.AccountID
	} else {
		existingNode.AccountID = existingNode.AccountID
	}
	if existingNode.CanPrivEscToAdminString == "" {
		existingNode.CanPrivEscToAdminString = newNode.CanPrivEscToAdminString
	} else {
		existingNode.CanPrivEscToAdminString = existingNode.CanPrivEscToAdminString
	}
	if existingNode.IsAdminString == "" {
		existingNode.IsAdminString = newNode.IsAdminString
	} else {
		existingNode.IsAdminString = existingNode.IsAdminString
	}
	if existingNode.VendorName == "" {
		existingNode.VendorName = newNode.VendorName
	} else {
		existingNode.VendorName = existingNode.VendorName
	}
	if existingNode.AccessKeys == 0 {
		existingNode.AccessKeys = newNode.AccessKeys
	} else {
		existingNode.AccessKeys = existingNode.AccessKeys
	}
	if existingNode.ActivePassword == false {
		existingNode.ActivePassword = newNode.ActivePassword
	} else {
		existingNode.ActivePassword = existingNode.ActivePassword
	}
	if existingNode.HasMfa == false {
		existingNode.HasMfa = newNode.HasMfa
	} else {
		existingNode.HasMfa = existingNode.HasMfa
	}
	if existingNode.PathToAdmin == false {
		existingNode.PathToAdmin = newNode.PathToAdmin
	} else {
		existingNode.PathToAdmin = existingNode.PathToAdmin
	}
	if existingNode.AttachedPolicies == nil {
		existingNode.AttachedPolicies = newNode.AttachedPolicies
	} else {
		existingNode.AttachedPolicies = existingNode.AttachedPolicies
	}
	if existingNode.TrustedFederatedProviders == nil {
		existingNode.TrustedFederatedProviders = newNode.TrustedFederatedProviders
	} else {
		existingNode.TrustedFederatedProviders = existingNode.TrustedFederatedProviders
	}
	if existingNode.TrustedPrincipals == nil {
		existingNode.TrustedPrincipals = newNode.TrustedPrincipals
	} else {
		existingNode.TrustedPrincipals = existingNode.TrustedPrincipals
	}
	if existingNode.TrustedServices == nil {
		existingNode.TrustedServices = newNode.TrustedServices
	} else {
		existingNode.TrustedServices = existingNode.TrustedServices
	}
	// if existingNode.TrustsDoc.Statement == nil {
	// 	existingNode.TrustsDoc = newNode.TrustsDoc
	// } else {
	// }
	return existingNode
}

func (a *Node) MakeRoleEdges(GlobalGraph graph.Graph[string, string]) {

	// get thisAccount id from role arn
	var thisAccount string
	if len(a.Arn) >= 25 {
		thisAccount = a.Arn[13:25]
	} else {
		fmt.Sprintf("Could not get account number from this role arn%s", a.Arn)
	}

	for _, TrustedPrincipal := range a.TrustedPrincipals {
		//get account id from the trusted principal arn
		var trustedPrincipalAccount string
		if len(TrustedPrincipal.TrustedPrincipal) >= 25 {
			trustedPrincipalAccount = TrustedPrincipal.TrustedPrincipal[13:25]
		} else {
			fmt.Sprintf("Could not get account number from this TrustedPrincipal%s", TrustedPrincipal.TrustedPrincipal)
		}
		var PermissionsRowAccount string

		// if the role trusts a principal in this same account explicitly, then the principal can assume the role
		if thisAccount == trustedPrincipalAccount {
			// make a CAN_ASSUME relationship between the trusted principal and this role

			err := GlobalGraph.AddEdge(
				TrustedPrincipal.TrustedPrincipal,
				a.Arn,
				//graph.EdgeAttribute("AssumeRole", "Same account explicit trust"),
				graph.EdgeAttribute("AssumeRole", "can assume (because of an explicit same account trust) "),
			)
			if err != nil {
				//fmt.Println(err)
				//fmt.Println(TrustedPrincipal.TrustedPrincipal + a.Arn + "Same account explicit trust")
				if err == graph.ErrEdgeAlreadyExists {
					// update the ege by copying the existing graph.Edge with attributes and add the new attributes
					//fmt.Println("Edge already exists")

					// get the existing edge
					existingEdge, _ := GlobalGraph.Edge(TrustedPrincipal.TrustedPrincipal, a.Arn)
					// get the map of attributes
					existingProperties := existingEdge.Properties
					// add the new attributes to attributes map within the properties struct
					// Check if the Attributes map is initialized, if not, initialize it
					if existingProperties.Attributes == nil {
						existingProperties.Attributes = make(map[string]string)
					}

					// Add or update the attribute
					existingProperties.Attributes["AssumeRole"] = "can assume (because of an explicit same account trust) "
					err = GlobalGraph.UpdateEdge(
						TrustedPrincipal.TrustedPrincipal,
						a.Arn,
						graph.EdgeAttributes(existingProperties.Attributes),
					)
					if err != nil {
						fmt.Println(err)
					}
				}

			}
		}

		// If the role trusts a principal in this account or another account using the :root notation, then we need to iterate over all of the rows in AllPermissionsRows to find the principals that have sts:AssumeRole permissions on this role
		// if the role we are looking at trusts root in it's own account

		if strings.Contains(TrustedPrincipal.TrustedPrincipal, fmt.Sprintf("%s:root", thisAccount)) {

			// iterate over all rows in AllPermissionsRows
			for _, PermissionsRow := range common.PermissionRowsFromAllProfiles {
				// but we only care about the rows that have arns that are in this account

				if len(PermissionsRow.Arn) >= 25 {
					PermissionsRowAccount = PermissionsRow.Arn[13:25]
				} else {
					fmt.Sprintf("Could not get account number from this PermissionsRow%s", PermissionsRow.Arn)
				}

				if PermissionsRowAccount == thisAccount {
					if policy.MatchesAfterExpansion(PermissionsRow.Action, "sts:AssumeRole") {
						// // lets only look for rows that have sts:AssumeRole permissions
						// if strings.EqualFold(PermissionsRow.Action, "sts:AssumeRole") ||
						// 	strings.EqualFold(PermissionsRow.Action, "*") ||
						// 	strings.EqualFold(PermissionsRow.Action, "sts:Assume*") ||
						// 	strings.EqualFold(PermissionsRow.Action, "sts:*") {
						// lets only focus on rows that have an effect of Allow
						if strings.EqualFold(PermissionsRow.Effect, "Allow") {
							// if the resource is * or the resource is this role arn, then this principal can assume this role
							if PermissionsRow.Resource == "*" || strings.Contains(PermissionsRow.Resource, a.Arn) {
								// make a CAN_ASSUME relationship between the trusted principal and this role
								//evaluate if the principal is a user or a role and set a variable accordingly
								//var principalType schema.NodeLabel
								if strings.EqualFold(PermissionsRow.Type, "User") || strings.EqualFold(PermissionsRow.Type, "Role") {
									err := GlobalGraph.AddEdge(
										PermissionsRow.Arn,
										a.Arn,
										//graph.EdgeAttribute("AssumeRole", "Same account root trust and trusted principal has permission to assume role"),
										graph.EdgeAttribute("AssumeRole", "can assume (because of a same account root trust and trusted principal has permission to assume role) "),
									)
									if err != nil {
										// fmt.Println(err)
										// fmt.Println(PermissionsRow.Arn + a.Arn + "Same account root trust and trusted principal has permission to assume role")
										if err == graph.ErrEdgeAlreadyExists {
											// update the ege by copying the existing graph.Edge with attributes and add the new attributes

											// get the existing edge
											existingEdge, _ := GlobalGraph.Edge(PermissionsRow.Arn, a.Arn)
											// get the map of attributes
											existingProperties := existingEdge.Properties
											// add the new attributes to attributes map within the properties struct
											// Check if the Attributes map is initialized, if not, initialize it
											if existingProperties.Attributes == nil {
												existingProperties.Attributes = make(map[string]string)
											}

											// Add or update the attribute
											existingProperties.Attributes["AssumeRole"] = "can assume (because of a same account root trust and trusted principal has permission to assume role) "
											err = GlobalGraph.UpdateEdge(
												PermissionsRow.Arn,
												a.Arn,
												graph.EdgeAttributes(existingProperties.Attributes),
											)
											if err != nil {
												fmt.Println(err)
											}
										}

									}
								}
							}
						}
					}
				}
			}
		} else if strings.Contains(TrustedPrincipal.TrustedPrincipal, ":root") && TrustedPrincipal.VendorName != "" {

			// If the role trusts :root in another account and the trusted principal is a vendor, we will make a relationship between our role and a vendor node instead of a principal node

			err := GlobalGraph.AddEdge(
				//TrustedPrincipal.TrustedPrincipal,
				//TrustedPrincipal.VendorName,
				fmt.Sprintf("%s [%s]", TrustedPrincipal.TrustedPrincipal, TrustedPrincipal.VendorName),
				a.Arn,
				//graph.EdgeAttribute("VendorAssumeRole", "Cross account root trust and trusted principal is a vendor"),
				graph.EdgeAttribute("VendorAssumeRole", "can assume (because of a cross account root trust and trusted principal is a vendor) "),
			)
			if err != nil {
				// fmt.Println(err)
				// fmt.Println(TrustedPrincipal.VendorName + a.Arn + "Cross account root trust and trusted principal is a vendor")
				if err == graph.ErrEdgeAlreadyExists {
					// update the ege by copying the existing graph.Edge with attributes and add the new attributes

					// get the existing edge
					existingEdge, _ := GlobalGraph.Edge(TrustedPrincipal.VendorName, a.Arn)
					// get the map of attributes
					existingProperties := existingEdge.Properties
					// add the new attributes to attributes map within the properties struct
					// Check if the Attributes map is initialized, if not, initialize it
					if existingProperties.Attributes == nil {
						existingProperties.Attributes = make(map[string]string)
					}

					// Add or update the attribute
					existingProperties.Attributes["VendorAssumeRole"] = "can assume (because of a cross account root trust and trusted principal is a vendor) "
					err := GlobalGraph.UpdateEdge(
						//fmt.Sprintf("%s-%s", a.Arn, TrustedPrincipal.VendorName),
						TrustedPrincipal.TrustedPrincipal,
						a.Arn,
						graph.EdgeAttributes(existingProperties.Attributes),
					)
					if err != nil {
						fmt.Println(err)
					}
				}

			}
		} else if strings.Contains(TrustedPrincipal.TrustedPrincipal, fmt.Sprintf("%s:root", trustedPrincipalAccount)) {

			// iterate over all rows in AllPermissionsRows
			for _, PermissionsRow := range common.PermissionRowsFromAllProfiles {
				// but we only care about the rows that have arns that are in this other account
				if len(PermissionsRow.Arn) >= 25 {
					PermissionsRowAccount = PermissionsRow.Arn[13:25]
				} else {
					fmt.Sprintf("Could not get account number from this PermissionsRow%s", PermissionsRow.Arn)
				}
				if PermissionsRowAccount == trustedPrincipalAccount {
					// lets only look for rows that have sts:AssumeRole permissions
					if policy.MatchesAfterExpansion(PermissionsRow.Action, "sts:AssumeRole") {
						// if strings.EqualFold(PermissionsRow.Action, "sts:AssumeRole") ||
						// 	strings.EqualFold(PermissionsRow.Action, "*") ||
						// 	strings.EqualFold(PermissionsRow.Action, "sts:Assume*") ||
						// 	strings.EqualFold(PermissionsRow.Action, "sts:*") {
						// lets only focus on rows that have an effect of Allow
						if strings.EqualFold(PermissionsRow.Effect, "Allow") {
							// if the resource is * or the resource is this role arn, then this principal can assume this role
							if PermissionsRow.Resource == "*" || strings.Contains(PermissionsRow.Resource, a.Arn) {
								// make a CAN_ASSUME relationship between the trusted principal and this role

								if strings.EqualFold(PermissionsRow.Type, "User") {
									err := GlobalGraph.AddEdge(
										PermissionsRow.Arn,
										a.Arn,
										//graph.EdgeAttribute("CrossAccountAssumeRole", "Cross account root trust and trusted principal has permission to assume role"),
										graph.EdgeAttribute("CrossAccountAssumeRole", "can assume (because of a cross account root trust and trusted principal has permission to assume role) "),
									)
									if err != nil {
										//fmt.Println(err)
										//fmt.Println(PermissionsRow.Arn + a.Arn + "Cross account root trust and trusted principal has permission to assume role")
										if err == graph.ErrEdgeAlreadyExists {
											// update the ege by copying the existing graph.Edge with attributes and add the new attributes

											// get the existing edge
											existingEdge, _ := GlobalGraph.Edge(PermissionsRow.Arn, a.Arn)
											// get the map of attributes
											existingProperties := existingEdge.Properties
											// add the new attributes to attributes map within the properties struct
											// Check if the Attributes map is initialized, if not, initialize it
											if existingProperties.Attributes == nil {
												existingProperties.Attributes = make(map[string]string)
											}

											// Add or update the attribute
											existingProperties.Attributes["CrossAccountAssumeRole"] = "can assume (because of a cross account root trust and trusted principal has permission to assume role) "
											err = GlobalGraph.UpdateEdge(
												PermissionsRow.Arn,
												a.Arn,
												graph.EdgeAttributes(existingProperties.Attributes),
											)
											if err != nil {
												fmt.Println(err)
											}
										}
									}

								} else if strings.EqualFold(PermissionsRow.Type, "Role") {
									err := GlobalGraph.AddEdge(
										PermissionsRow.Arn,
										a.Arn,
										//graph.EdgeAttribute("CrossAccountAssumeRole", "Cross account root trust and trusted principal has permission to assume role"),
										graph.EdgeAttribute("CrossAccountAssumeRole", "can assume (because of a cross account root trust and trusted principal has permission to assume role) "),
									)
									if err != nil {
										//fmt.Println(err)
										//fmt.Println(PermissionsRow.Arn + a.Arn + "Cross account root trust and trusted principal has permission to assume role")
										if err == graph.ErrEdgeAlreadyExists {
											// update the ege by copying the existing graph.Edge with attributes and add the new attributes

											// get the existing edge
											existingEdge, _ := GlobalGraph.Edge(PermissionsRow.Arn, a.Arn)
											// get the map of attributes
											existingProperties := existingEdge.Properties
											// add the new attributes to attributes map within the properties struct
											// Check if the Attributes map is initialized, if not, initialize it
											if existingProperties.Attributes == nil {
												existingProperties.Attributes = make(map[string]string)
											}

											// Add or update the attribute
											existingProperties.Attributes["CrossAccountAssumeRole"] = "can assume (because of a cross account root trust and trusted principal has permission to assume role) "
											err = GlobalGraph.UpdateEdge(
												PermissionsRow.Arn,
												a.Arn,
												graph.EdgeAttributes(existingProperties.Attributes),
											)
											if err != nil {
												fmt.Println(err)
											}
										}
									}
								}
							}
						}
					}

				}
			}

		}
	}
	// pmapper takes care of this part so commenting out for now - but leaving as a placeholder

	// for _, TrustedService := range a.TrustedServices {
	// 	// make relationship from trusted service to this role of type can assume
	// 	// make relationship from this role to trusted service of type can be assumed by
	// }

	for _, TrustedFederatedProvider := range a.TrustedFederatedProviders {
		// make relationship from trusted federated provider to this role of type can assume

		var providerAndSubject string
		for _, trustedSubject := range TrustedFederatedProvider.TrustedSubjects {
			if trustedSubject == "Not applicable" {
				providerAndSubject = TrustedFederatedProvider.ProviderShortName
			} else {
				providerAndSubject = TrustedFederatedProvider.ProviderShortName + ":" + trustedSubject
			}

			err := GlobalGraph.AddEdge(
				providerAndSubject,
				a.Arn,
				//graph.EdgeAttribute("FederatedAssumeRole", "Trusted federated provider"),
				graph.EdgeAttribute("FederatedAssumeRole", "can assume (because of a trusted federated provider) "),
			)
			if err != nil {
				//fmt.Println(err)
				//fmt.Println(TrustedFederatedProvider.TrustedFederatedProvider + a.Arn + "Trusted federated provider")
				if err == graph.ErrEdgeAlreadyExists {
					// update the ege by copying the existing graph.Edge with attributes and add the new attributes

					// get the existing edge
					existingEdge, _ := GlobalGraph.Edge(TrustedFederatedProvider.TrustedFederatedProvider, a.Arn)
					// get the map of attributes
					existingProperties := existingEdge.Properties
					// add the new attributes to attributes map within the properties struct
					// Check if the Attributes map is initialized, if not, initialize it
					if existingProperties.Attributes == nil {
						existingProperties.Attributes = make(map[string]string)
					}

					// Add or update the attribute
					existingProperties.Attributes["FederatedAssumeRole"] = "can assume (because of a trusted federated provider) "
					err = GlobalGraph.UpdateEdge(
						providerAndSubject,
						a.Arn,
						graph.EdgeAttributes(existingProperties.Attributes),
					)
					if err != nil {
						fmt.Println(err)
					}
				}
			}

		}
	}

}
