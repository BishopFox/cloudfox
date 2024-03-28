package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/BishopFox/cloudfox/internal/aws/policy"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/dominikbraun/graph"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/sirupsen/logrus"
)

type PmapperModule struct {
	// General configuration data
	Caller        sts.GetCallerIdentityOutput
	AWSRegions    []string
	AWSOutputType string
	AWSTableCols  string

	Goroutines int
	AWSProfile string
	WrapTable  bool

	// Main module data
	PmapperDataBasePath string
	pmapperGraph        graph.Graph[string, string]
	Nodes               []Node
	Edges               []Edge
	CommandCounter      internal.CommandCounter
	// Used to store output data for pretty printing
	output internal.OutputData2
	modLog *logrus.Entry
}

type PmapperOutputRow struct {
	Start string
	End   string
	Paths []string
}

type Edge struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Reason      string `json:"reason"`
	ShortReason string `json:"short_reason"`
}

type Node struct {
	Arn                       string `json:"arn"`
	Type                      string
	AccountID                 string
	Name                      string
	IDValue                   string             `json:"id_value"`
	AttachedPolicies          []AttachedPolicies `json:"attached_policies"`
	GroupMemberships          []interface{}      `json:"group_memberships"`
	TrustPolicy               interface{}        `json:"trust_policy"`
	TrustsDoc                 policy.TrustPolicyDocument
	TrustedPrincipals         []TrustedPrincipal
	TrustedServices           []TrustedService
	TrustedFederatedProviders []TrustedFederatedProvider
	InstanceProfile           interface{} `json:"instance_profile"`
	ActivePassword            bool        `json:"active_password"`
	AccessKeys                int         `json:"access_keys"`
	IsAdmin                   bool        `json:"is_admin"`
	PathToAdmin               bool
	PermissionsBoundary       interface{} `json:"permissions_boundary"`
	HasMfa                    bool        `json:"has_mfa"`
	Tags                      Tags        `json:"tags"`
	CanPrivEscToAdminString   string
	IsAdminString             string
	VendorName                string
}

type TrustedPrincipal struct {
	TrustedPrincipal               string
	ExternalID                     string
	VendorName                     string
	AccountIsInAnalyzedAccountList bool
	//IsAdmin           bool
	//CanPrivEscToAdmin bool
}

type TrustedService struct {
	TrustedService string
	AccountID      string
	//IsAdmin           bool
	//CanPrivEscToAdmin bool
}

type TrustedFederatedProvider struct {
	TrustedFederatedProvider string
	ProviderAccountId        string
	ProviderShortName        string
	TrustedSubjects          []string
	//IsAdmin                  bool
	//CanPrivEscToAdmin        bool
}

type AttachedPolicies struct {
	Arn  string `json:"arn"`
	Name string `json:"name"`
}
type Tags struct {
}

func (m *PmapperModule) initPmapperGraph() error {
	// Parse mapper nodes and edges and populate the m.Nodes and m.Edges slices in the method struct
	err := m.readPmapperData(m.Caller.Account)
	if err != nil {
		return err
	}

	m.pmapperGraph = m.createAndPopulateGraph()

	for i := range m.Nodes {
		if m.doesNodeHavePathToAdmin(m.Nodes[i]) {
			m.Nodes[i].PathToAdmin = true
			m.Nodes[i].CanPrivEscToAdminString = "Yes"
			//fmt.Println(m.Nodes[i].Arn, m.Nodes[i].IsAdmin, m.Nodes[i].PathToAdmin)
		} else {
			m.Nodes[i].PathToAdmin = false
			m.Nodes[i].CanPrivEscToAdminString = "No"
		}
		if m.Nodes[i].IsAdmin {
			m.Nodes[i].IsAdminString = "Yes"
		} else {
			m.Nodes[i].IsAdminString = "No"
		}
	}

	return nil
}

func (m *PmapperModule) createAndPopulateGraph() graph.Graph[string, string] {

	pmapperGraph := graph.New(graph.StringHash, graph.Directed())

	// having issues with caching the graph. will have to swing back and try again later

	// gob.Register(pmapperGraph)
	// cacheKey := fmt.Sprintf("%s-pmapperGraph", aws.ToString(m.Caller.Account))
	// cached, found := internal.Cache.Get(cacheKey)
	// if found {
	// 	return cached.(graph.Graph[string, string])
	// }

	for _, node := range m.Nodes {
		_ = pmapperGraph.AddVertex(node.Arn)

	}

	for _, edge := range m.Edges {
		err := pmapperGraph.AddEdge(
			edge.Source,
			edge.Destination,
			graph.EdgeAttribute(edge.ShortReason, edge.Reason),
		)
		if err != nil {
			if err == graph.ErrEdgeAlreadyExists {
				// update the ege by copying the existing graph.Edge with attributes and add the new attributes
				//fmt.Println("Edge already exists, but adding a new one!")

				// get the existing edge
				existingEdge, _ := pmapperGraph.Edge(edge.Source, edge.Destination)
				// get the map of attributes
				existingProperties := existingEdge.Properties
				// add the new attributes to attributes map within the properties struct
				// Check if the Attributes map is initialized, if not, initialize it
				if existingProperties.Attributes == nil {
					existingProperties.Attributes = make(map[string]string)
				}

				// Add or update the attribute
				existingProperties.Attributes[edge.ShortReason] = edge.Reason
				//Update the edge
				pmapperGraph.UpdateEdge(
					edge.Source,
					edge.Destination,
					graph.EdgeAttributes(existingProperties.Attributes),
				)

			}
			//fmt.Println(edge.Reason)
		}

	}

	//internal.Cache.Set(cacheKey, pmapperGraph, cache.DefaultExpiration)
	return pmapperGraph

}

func (m *PmapperModule) DoesPrincipalHavePathToAdmin(principal string) bool {
	for i := range m.Nodes {
		if m.Nodes[i].Arn == principal {
			if m.Nodes[i].PathToAdmin {
				m.Nodes[i].CanPrivEscToAdminString = "Yes"
				return true
			} else {
				m.Nodes[i].CanPrivEscToAdminString = "No"
				return false
			}
		}

	}
	return false
}

func (m *PmapperModule) DoesPrincipalHaveAdmin(principal string) bool {
	for i := range m.Nodes {
		if m.Nodes[i].Arn == principal {
			if m.Nodes[i].IsAdmin {
				m.Nodes[i].IsAdminString = "Yes"
				return true
			} else {
				m.Nodes[i].IsAdminString = "No"
				return false
			}
		}

	}
	return false
}

func (m *PmapperModule) PrintPmapperData(outputDirectory string, verbosity int) {
	// These struct values are used by the output module
	m.output.Verbosity = verbosity
	m.output.Directory = outputDirectory
	m.output.CallingModule = "pmapper"
	m.output.FullFilename = m.output.CallingModule
	m.modLog = internal.TxtLog.WithFields(logrus.Fields{
		"module": m.output.CallingModule,
	})
	if m.AWSProfile == "" {
		m.AWSProfile = internal.BuildAWSPath(m.Caller)
	}
	m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", fmt.Sprintf("%s-%s", m.AWSProfile, aws.ToString(m.Caller.Account)))
	fmt.Printf("[%s][%s] Looking for pmapper data for this account and building a PrivEsc graph in golang if it exists.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	pmapperError := m.initPmapperGraph()
	if pmapperError != nil {
		fmt.Printf("[%s][%s] No pmapper data found for this account. \n\t\t\t1. Generate pmapper data by running `pmapper --profile %s graph create`\n\t\t\t2. After that completes, cloudfox will attempt to enrich this command and others with pmapper privesc data\n\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), m.AWSProfile)
		fmt.Printf("[%s][%s] For more info and troubleshooting steps: https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#%s\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), m.output.CallingModule)
		m.modLog.Error(pmapperError)
		return

	} else {
		fmt.Printf("[%s][%s] Parsing pmapper data for account %s.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), aws.ToString(m.Caller.Account))

	}

	m.output.Headers = []string{
		"Account",
		"Principal Arn",
		"IsAdmin?",
		"CanPrivEscToAdmin?",
	}

	// If the user specified table columns, use those.
	// If the user specified -o wide, use the wide default cols for this module.
	// Otherwise, use the hardcoded default cols for this module.
	var tableCols []string
	// If the user specified table columns, use those.
	if m.AWSTableCols != "" {
		// If the user specified wide as the output format, use these columns.
		// remove any spaces between any commas and the first letter after the commas
		m.AWSTableCols = strings.ReplaceAll(m.AWSTableCols, ", ", ",")
		m.AWSTableCols = strings.ReplaceAll(m.AWSTableCols, ",  ", ",")
		tableCols = strings.Split(m.AWSTableCols, ",")
	} else if m.AWSOutputType == "wide" {
		tableCols = []string{
			"Account",
			"Principal Arn",
			"IsAdmin?",
			"CanPrivEscToAdmin?",
		}
		// Otherwise, use the default columns.
	} else {
		tableCols = []string{
			"Principal Arn",
			"IsAdmin?",
			"CanPrivEscToAdmin?",
		}
	}

	//Table rows
	var isAdmin, pathToAdmin string
	for i := range m.Nodes {
		if m.Nodes[i].PathToAdmin || m.Nodes[i].IsAdmin {
			if m.Nodes[i].IsAdmin {
				isAdmin = "YES"
			} else {
				isAdmin = "No"
			}
			if m.Nodes[i].PathToAdmin {
				pathToAdmin = "YES"
			} else {
				pathToAdmin = "No"
			}

			m.output.Body = append(
				m.output.Body,
				[]string{
					aws.ToString(m.Caller.Account),
					m.Nodes[i].Arn,
					isAdmin,
					pathToAdmin,
				},
			)
		}
	}

	if len(m.output.Body) > 0 {
		m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", fmt.Sprintf("%s-%s", m.AWSProfile, aws.ToString(m.Caller.Account)))
		o := internal.OutputClient{
			Verbosity:     verbosity,
			CallingModule: m.output.CallingModule,
			Table: internal.TableClient{
				Wrap: m.WrapTable,
			},
			Loot: internal.LootClient{
				DirectoryName: m.output.FilePath,
			},
		}
		o.Table.TableFiles = append(o.Table.TableFiles, internal.TableFile{
			Header:    m.output.Headers,
			Body:      m.output.Body,
			TableCols: tableCols,
			Name:      m.output.CallingModule,
		})
		o.PrefixIdentifier = m.AWSProfile
		o.Table.DirectoryName = filepath.Join(outputDirectory, "cloudfox-output", "aws", fmt.Sprintf("%s-%s", m.AWSProfile, aws.ToString(m.Caller.Account)))

		header, body := m.createPmapperTableData(outputDirectory)
		o.Table.TableFiles = append(o.Table.TableFiles, internal.TableFile{
			Header: header,
			Body:   body,
			Name:   "pmapper-privesc-paths-enhanced",
		})

		loot := m.writeLoot(o.Table.DirectoryName, verbosity)
		o.Loot.LootFiles = append(o.Loot.LootFiles, internal.LootFile{
			Name:     m.output.CallingModule,
			Contents: loot,
		})
		o.WriteFullOutput(o.Table.TableFiles, o.Loot.LootFiles)
		//m.writeLoot(o.Table.DirectoryName, verbosity)

		fmt.Printf("[%s][%s] %s principals who are admin or have a path to admin identified.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), strconv.Itoa(len(m.output.Body)))

	} else {
		fmt.Printf("[%s][%s] No principals who are admin or have a path to admin identified. skipping the creation of an output file.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	}
	fmt.Printf("[%s][%s] For context and next steps: https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#%s\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), m.output.CallingModule)
}

func (m *PmapperModule) doesNodeHavePathToAdmin(startNode Node) bool {
	if startNode.IsAdmin {
		return true
	} else {
		for _, destNode := range m.Nodes {
			if destNode.IsAdmin {
				path, _ := graph.ShortestPath(m.pmapperGraph, startNode.Arn, destNode.Arn)
				for _, p := range path {
					if p != "" {
						if startNode.Arn != destNode.Arn {
							return true
						}

					}
				}
			}
		}
	}
	return false
}

func (m *PmapperModule) createPmapperTableData(outputDirectory string) ([]string, [][]string) {
	var header []string
	var body [][]string

	header = []string{
		"Start",
		"End",
		"Path(s)",
	}

	var paths string
	var admins, privescPathsBody [][]string

	for _, startNode := range m.Nodes {
		if startNode.IsAdmin {
			admins = append(admins, []string{startNode.Arn, "", "ADMIN"})

		} else {
			for _, destNode := range m.Nodes {
				if destNode.IsAdmin {
					path, _ := graph.ShortestPath(m.pmapperGraph, startNode.Arn, destNode.Arn)
					// if we have a path,

					if len(path) > 0 {
						if startNode.Arn != destNode.Arn {
							paths = ""
							// if we got here theres a path. Lets print the reason and the short reason for each edge in the path to the screen
							for i := 0; i < len(path)-1; i++ {
								for _, edge := range m.Edges {
									if edge.Source == path[i] && edge.Destination == path[i+1] {

										//Some pmapper reasons have commas in them so lets get rid of them in the csvOutputdata
										edge.Reason = strings.ReplaceAll(edge.Reason, ",", " and")
										paths += fmt.Sprintf("%s %s %s\n", path[i], edge.Reason, path[i+1])
									}

								}
							}
							//trim the last newline from csvPaths
							paths = strings.TrimSuffix(paths, "\n")
							privescPathsBody = append(privescPathsBody, []string{startNode.Arn, destNode.Arn, paths})

						}

					}
				}
			}
		}
	}

	// create body by first adding the admins and then the privesc paths
	body = append(body, admins...)
	body = append(body, privescPathsBody...)
	return header, body

}

func (m *PmapperModule) writeLoot(outputDirectory string, verbosity int) string {
	path := filepath.Join(outputDirectory, "loot")
	err := os.MkdirAll(path, os.ModePerm)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		panic(err.Error())
	}
	f := filepath.Join(path, "pmapper-privesc-paths-enhanced.txt")

	var admins, out string

	for _, startNode := range m.Nodes {
		if startNode.IsAdmin {
			admins += fmt.Sprintf("ADMIN FOUND: %s\n", startNode.Arn)
		} else {
			for _, destNode := range m.Nodes {
				if destNode.IsAdmin {
					path, _ := graph.ShortestPath(m.pmapperGraph, startNode.Arn, destNode.Arn)
					// if we have a path,

					if len(path) > 0 {
						if startNode.Arn != destNode.Arn {
							// if we got here there is a path
							out += fmt.Sprintf("PATH TO ADMIN FOUND\n   Start: %s\n     End: %s\n Path(s):\n", startNode.Arn, destNode.Arn)
							//fmt.Println(path)
							// if we got here theres a path. Lets print the reason and the short reason for each edge in the path to the screen
							for i := 0; i < len(path)-1; i++ {
								for _, edge := range m.Edges {
									if edge.Source == path[i] && edge.Destination == path[i+1] {
										// print it like this: [start node] [reason] [end node]
										out += fmt.Sprintf("     %s %s %s\n", path[i], edge.Reason, path[i+1])
									}
									// shortest path only finds the shortest path. We want to find all paths. So we need to find all paths that have the same start and end nodes from the path, but going back to the main edges slice
									//for _, edge := range GlobalPmapperEdges {
									// 	if edge.Source == path[i] && edge.Destination == path[i+1] {
									// 		// print it like this: [start node] [reason] [end node]
									// 		out += fmt.Sprintf("   %s %s %s\n", path[i], edge.Reason, path[i+1])
									// 	}
									// }
								}
							}
							out += fmt.Sprintf("\n")

						}

					}
				}
			}
		}
	}
	out = admins + "\n\n" + out

	if verbosity > 2 {
		fmt.Println()
		fmt.Println("[%s][%s] %s \n", cyan(m.output.CallingModule), cyan(m.AWSProfile), green("Beginning of loot file"))
		fmt.Print(out)
		fmt.Printf("[%s][%s] %s \n\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), green("End of loot file"))
	}
	fmt.Printf("[%s][%s] Loot written to [%s]\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), f)
	return out

}

func (m *PmapperModule) readPmapperData(accountID *string) error {

	e, n := generatePmapperDataBasePaths(accountID)

	nodesFile, err := os.Open(n)
	if err != nil {
		return err
	}
	defer nodesFile.Close()
	nodesByteValue, _ := ioutil.ReadAll(nodesFile)
	json.Unmarshal([]byte(nodesByteValue), &m.Nodes)

	edgesFile, err := os.Open(e)
	if err != nil {
		return err
	}
	defer edgesFile.Close()
	edgesByteValue, _ := ioutil.ReadAll(edgesFile)
	json.Unmarshal([]byte(edgesByteValue), &m.Edges)

	return nil

}

func (m *PmapperModule) GenerateCypherStatements(goCtx context.Context, driver neo4j.DriverWithContext) error {
	// Insert nodes
	for i, node := range m.Nodes {
		query, params := m.generateNodeCreateStatement(node, i)
		if err := m.executeCypherQuery(goCtx, driver, query, params); err != nil {
			return err
		}
	}

	// Insert edges
	for i, edge := range m.Edges {
		query, params := m.generateEdgeCreateStatement(edge, i)
		if err := m.executeCypherQuery(goCtx, driver, query, params); err != nil {
			return err
		}
	}

	return nil
}

func (m *PmapperModule) generateNodeCreateStatement(node Node, i int) (string, map[string]interface{}) {
	var ptype, label, query string
	var params map[string]any

	if strings.Contains(node.Arn, "role") {
		label = GetResourceNameFromArn(node.Arn)
		ptype = "Role"
		params = map[string]any{
			"Id":          node.Arn,
			"ARN":         node.Arn,
			"Name":        GetResourceNameFromArn(node.Arn),
			"IdValue":     node.IDValue,
			"IsAdminP":    node.IsAdmin,
			"PathToAdmin": node.PathToAdmin,
		}

	} else if strings.Contains(node.Arn, "user") {
		label = GetResourceNameFromArn(node.Arn)
		ptype = "User"
		//node.TrustPolicy = ""
		params = map[string]any{
			"Id":          node.Arn,
			"ARN":         node.Arn,
			"Name":        GetResourceNameFromArn(node.Arn),
			"IdValue":     node.IDValue,
			"IsAdminP":    node.IsAdmin,
			"PathToAdmin": node.PathToAdmin,
		}

	} else if strings.Contains(node.Arn, "group") {
		label = GetResourceNameFromArn(node.Arn)
		ptype = "Group"
	}
	label = strings.ReplaceAll(label, "-", "_")
	label = strings.ReplaceAll(label, ".", "_")

	query = `MERGE (%s:%s {Id: $Id, ARN: $ARN, Name: $Name, IdValue: $IdValue, IsAdminP: $IsAdminP, PathToAdmin: $PathToAdmin})`

	//sanitizedArn := sanitizeArnForNeo4jLabel(node.Arn)
	//id := fmt.Sprintf("%s_%s", sanitizedArn, ptype)

	fmt.Println(fmt.Sprintf(query, label, ptype), params)
	return fmt.Sprintf(query, label, ptype), params
}

func (m *PmapperModule) generateEdgeCreateStatement(edge Edge, i int) (string, map[string]interface{}) {
	// Sanitize ARNs for matching nodes
	//srcArnSanitized := sanitizeArnForNeo4jLabel(edge.Source)
	//destArnSanitized := sanitizeArnForNeo4jLabel(edge.Destination)

	query := `MATCH (a {ARN: $srcArn}), (b {ARN: $destArn}) CREATE (a)-[:CAN_ACCESS {reason: $reason, shortReason: $shortReason}]->(b)`
	params := map[string]any{
		"srcArn":      edge.Source,
		"destArn":     edge.Destination,
		"reason":      edge.Reason,
		"shortReason": edge.ShortReason,
	}
	fmt.Println(query, params)
	return query, params
}

func (m *PmapperModule) executeCypherQuery(ctx context.Context, driver neo4j.DriverWithContext, query string, params map[string]interface{}) error {
	_, err := neo4j.ExecuteQuery(ctx, driver, query, params, neo4j.EagerResultTransformer, neo4j.ExecuteQueryWithDatabase("neo4j"))
	if err != nil {
		sharedLogger.Errorf("Error executing query: %s -- %v", err, params)
		return err
	}
	return nil
}

func sanitizeArnForNeo4jLabel(arn string) string {
	// Replace non-allowed characters with underscores or other allowed characters
	sanitized := strings.ReplaceAll(arn, ":", "_")
	sanitized = strings.ReplaceAll(sanitized, "-", "_")
	// Add more replacements if needed
	return sanitized
}

// func GetRelationshipsForRole(roleArn string) []schema.Relationship {
// 	var relationships []schema.Relationship
// 	if strings.Contains(node.Arn, "role") {
// 		ptype = "Role"
// 	} else if strings.Contains(node.Arn, "user") {
// 		ptype = "User"
// 		node.TrustPolicy = ""
// 	} else if strings.Contains(node.Arn, "group") {
// 		ptype = "Group"
// 	}
// 	for _, edge := range m.Edges {
// 		if edge.Source == roleArn {
// 			relationships = append(relationships, schema.Relationship{
// 				Source:         roleArn,
// 				SourceProperty: "arn",
// 				Target:         edge.Destination,
// 				TargetProperty: "arn",
// 				Type:           "CAN_ACCESS",
// 			})
// 		}
// 	}
