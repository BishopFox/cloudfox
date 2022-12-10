package aws

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"

	"github.com/BishopFox/cloudfox/console"
	"github.com/BishopFox/cloudfox/utils"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/dominikbraun/graph"
	"github.com/sirupsen/logrus"
)

type PmapperModule struct {
	// General configuration data
	Caller       sts.GetCallerIdentityOutput
	AWSRegions   []string
	OutputFormat string
	Goroutines   int
	AWSProfile   string

	// Main module data
	Nodes          []Node
	Edges          []Edge
	CommandCounter console.CommandCounter
	// Used to store output data for pretty printing
	output utils.OutputData2
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
}

type AttachedPolicies struct {
	Arn  string `json:"arn"`
	Name string `json:"name"`
}
type Tags struct {
}

func (m *PmapperModule) PrintPmapperData(outputFormat string, outputDirectory string, verbosity int) {
	// These stuct values are used by the output module
	m.output.Verbosity = verbosity
	m.output.Directory = outputDirectory
	m.output.CallingModule = "pmapper"
	m.output.FullFilename = m.output.CallingModule
	m.modLog = utils.TxtLog.WithFields(logrus.Fields{
		"module": m.output.CallingModule,
	})
	if m.AWSProfile == "" {
		m.AWSProfile = utils.BuildAWSPath(m.Caller)
	}
	m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", m.AWSProfile)
	fmt.Printf("[%s][%s] Parsing pmapper data for account %s.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), aws.ToString(m.Caller.Account))

	nodes, edges := parsePmapperData()

	// nodeHash := func(n Node) string {
	// 	return n.Arn
	// }

	g := graph.New(graph.StringHash, graph.Directed())

	for _, node := range nodes {
		_ = g.AddVertex(node.Arn)

	}

	for _, edge := range edges {
		_ = g.AddEdge(edge.Source, edge.Destination)
	}

	for _, destNode := range nodes {
		if destNode.IsAdmin == true {
			fmt.Printf("%s is an administrative principal\n", destNode.Arn)
			for _, startNode := range nodes {

				path, _ := graph.ShortestPath(g, startNode.Arn, destNode.Arn)
				for _, p := range path {
					if p != "" {
						if startNode.Arn != destNode.Arn {
							fmt.Printf("%s has a path %s who is an admin.\n", startNode.Arn, destNode.Arn)
						}
					}
				}
			}

		}
	}

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
	// for i := range m.Rows {
	// 	m.output.Body = append(
	// 		m.output.Body,
	// 		[]string{
	// 			m.Rows[i].AWSService,
	// 			m.Rows[i].Type,
	// 			m.Rows[i].Name,
	// 			//m.Rows[i].Arn,
	// 			m.Rows[i].PolicyType,
	// 			m.Rows[i].PolicyName,
	// 			m.Rows[i].Effect,
	// 			m.Rows[i].Action,
	// 			m.Rows[i].Resource,
	// 		},
	// 	)

	// }

	if len(m.output.Body) > 0 {
		m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", m.AWSProfile)
		//m.output.OutputSelector3(outputFormat)
		utils.OutputSelector(verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.FullFilename, m.output.CallingModule)

		fmt.Printf("[%s][%s] %s unique permissions identified.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), strconv.Itoa(len(m.output.Body)))

	} else {
		fmt.Printf("[%s][%s] No IAM permissions found. skipping the creation of an output file.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	}

}

// func ParsePmapperData(nodesFileName string, edgesFileName string) (Nodes, Edges) {
func parsePmapperData() ([]Node, []Edge) {

	nodesFile, err := os.Open("/Users/sethart/Library/Application Support/com.nccgroup.principalmapper/874389354274/graph/nodes.json")
	if err != nil {
		panic(fmt.Sprintf("Failed to open nodes file %v", err))
	}
	defer nodesFile.Close()
	nodesByteValue, _ := ioutil.ReadAll(nodesFile)

	var parsedNodeData []Node
	json.Unmarshal([]byte(nodesByteValue), &parsedNodeData)

	edgesFile, err := os.Open("/Users/sethart/Library/Application Support/com.nccgroup.principalmapper/874389354274/graph/edges.json")
	if err != nil {
		panic(fmt.Sprintf("Failed to open nodes file %v", err))
	}
	defer edgesFile.Close()
	edgesByteValue, _ := ioutil.ReadAll(edgesFile)

	var parsedEdgeData []Edge
	json.Unmarshal([]byte(edgesByteValue), &parsedEdgeData)

	return parsedNodeData, parsedEdgeData

}
