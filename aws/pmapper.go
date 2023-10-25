package aws

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/dominikbraun/graph"
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
	pmapperGraph   graph.Graph[string, string]
	Nodes          []Node
	Edges          []Edge
	CommandCounter internal.CommandCounter
	// Used to store output data for pretty printing
	output internal.OutputData2
	modLog *logrus.Entry
}

type Edge struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Reason      string `json:"reason"`
	ShortReason string `json:"short_reason"`
}

type Node struct {
	Arn                 string             `json:"arn"`
	IDValue             string             `json:"id_value"`
	AttachedPolicies    []AttachedPolicies `json:"attached_policies"`
	GroupMemberships    []interface{}      `json:"group_memberships"`
	TrustPolicy         interface{}        `json:"trust_policy"`
	InstanceProfile     interface{}        `json:"instance_profile"`
	ActivePassword      bool               `json:"active_password"`
	AccessKeys          int                `json:"access_keys"`
	IsAdmin             bool               `json:"is_admin"`
	PermissionsBoundary interface{}        `json:"permissions_boundary"`
	HasMfa              bool               `json:"has_mfa"`
	Tags                Tags               `json:"tags"`
	PathToAdmin         bool
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
			//fmt.Println(m.Nodes[i].Arn, m.Nodes[i].IsAdmin, m.Nodes[i].PathToAdmin)
		} else {
			m.Nodes[i].PathToAdmin = false
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
		_ = pmapperGraph.AddEdge(edge.Source, edge.Destination)
	}

	//internal.Cache.Set(cacheKey, pmapperGraph, cache.DefaultExpiration)
	return pmapperGraph

}

func (m *PmapperModule) DoesPrincipalHavePathToAdmin(principal string) bool {
	for i := range m.Nodes {
		if m.Nodes[i].Arn == principal {
			if m.Nodes[i].PathToAdmin {
				return true
			}
		}

	}
	return false
}

func (m *PmapperModule) DoesPrincipalHaveAdmin(principal string) bool {
	for i := range m.Nodes {
		if m.Nodes[i].Arn == principal {
			if m.Nodes[i].IsAdmin {
				return true
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
		// remove any spaces between any commans and the first letter after the commas
		m.AWSTableCols = strings.ReplaceAll(m.AWSTableCols, ", ", ",")
		m.AWSTableCols = strings.ReplaceAll(m.AWSTableCols, ",  ", ",")
		tableCols = strings.Split(m.AWSTableCols, ",")
	} else if m.AWSOutputType == "wide" {
		tableCols = []string{
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
		}
		o.Table.TableFiles = append(o.Table.TableFiles, internal.TableFile{
			Header:    m.output.Headers,
			Body:      m.output.Body,
			TableCols: tableCols,
			Name:      m.output.CallingModule,
		})
		o.PrefixIdentifier = m.AWSProfile
		o.Table.DirectoryName = filepath.Join(outputDirectory, "cloudfox-output", "aws", fmt.Sprintf("%s-%s", m.AWSProfile, aws.ToString(m.Caller.Account)))
		o.WriteFullOutput(o.Table.TableFiles, nil)
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
							// if we got here there is a path
							//fmt.Printf("%s has a path %s who is an admin.\n", startNode.Arn, destNode.Arn)
							//fmt.Println(path)
							return true
						}

					}
				}
			}
		}
	}
	return false
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
