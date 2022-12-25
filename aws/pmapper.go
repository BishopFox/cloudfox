package aws

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"runtime"
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
	pmapperGraph   graph.Graph[string, string]
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
	PathToAdmin         bool
}

type AttachedPolicies struct {
	Arn  string `json:"arn"`
	Name string `json:"name"`
}
type Tags struct {
}

var pmapperTxtLogger = utils.TxtLogger()

func (m *PmapperModule) initPmapperGraph() error {
	// Parse mapper nodes and edges and populate the m.Nodes and m.Edges slices in the method struct
	err := m.readPmapperData(m.Caller.Account)
	if err != nil {
		return err
	}

	m.pmapperGraph = graph.New(graph.StringHash, graph.Directed())

	for _, node := range m.Nodes {
		_ = m.pmapperGraph.AddVertex(node.Arn)

	}

	for _, edge := range m.Edges {
		_ = m.pmapperGraph.AddEdge(edge.Source, edge.Destination)
	}

	// //populate mod level map of nodes
	// for _, node := range m.Nodes {
	// 	m.Nodes[node.Arn] = node
	// }

	for i, _ := range m.Nodes {
		if m.doesNodeHavePathToAdmin(m.Nodes[i]) {
			m.Nodes[i].PathToAdmin = true
			//fmt.Println(m.Nodes[i].Arn, m.Nodes[i].IsAdmin, m.Nodes[i].PathToAdmin)
		} else {
			m.Nodes[i].PathToAdmin = false
		}

	}
	return nil
}

func (m *PmapperModule) DoesPrincipalHavePathToAdmin(principal string) bool {
	for i, _ := range m.Nodes {
		if m.Nodes[i].Arn == principal {
			if m.doesNodeHavePathToAdmin(m.Nodes[i]) {
				return true
			}
		}

	}
	return false
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

	err := m.initPmapperGraph()
	if err != nil {
		m.modLog.Error(err)
	}

	m.output.Headers = []string{
		"Principal Arn",
		"isAdmin?",
		"HasPathToAdmin?",
	}

	//Table rows
	for i := range m.Nodes {
		if m.Nodes[i].PathToAdmin || m.Nodes[i].IsAdmin {
			m.output.Body = append(
				m.output.Body,
				[]string{
					m.Nodes[i].Arn,
					strconv.FormatBool(m.Nodes[i].IsAdmin),
					strconv.FormatBool(m.Nodes[i].PathToAdmin),
				},
			)
		}
	}

	if len(m.output.Body) > 0 {
		m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", m.AWSProfile)
		utils.OutputSelector(verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.FullFilename, m.output.CallingModule, cyan(m.output.CallingModule))
		fmt.Printf("[%s][%s] %s principals who are admin or have a path to admin identified.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), strconv.Itoa(len(m.output.Body)))

	} else {
		fmt.Printf("[%s][%s] No principals who are admin or have a path to admin identified. skipping the creation of an output file.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	}

}

func (m *PmapperModule) doesNodeHavePathToAdmin(startNode Node) bool {
	if startNode.IsAdmin == true {
		return true
	} else {
		for _, destNode := range m.Nodes {
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

func generatePmapperDataBasePaths(accountId *string) (string, string) {
	var edgesPath, nodesPath string

	if runtime.GOOS == "darwin" {
		dir, err := os.UserHomeDir()
		if err != nil {
			log.Fatal("Could not get homedir")
		}
		edgesPath = fmt.Sprintf(dir + "/Library/Application Support/com.nccgroup.principalmapper/" + aws.ToString(accountId) + "/graph/edges.json")
		nodesPath = fmt.Sprintf(dir + "/Library/Application Support/com.nccgroup.principalmapper/" + aws.ToString(accountId) + "/graph/nodes.json")

	} else if runtime.GOOS == "linux" || runtime.GOOS == "freebsd" || runtime.GOOS == "openbsd" {
		xdg, ok := os.LookupEnv("XDG_DATA_HOME")
		if !ok {
			edgesPath = fmt.Sprintf(xdg + aws.ToString(accountId) + "/graph/edges.json")
			nodesPath = fmt.Sprintf(xdg + aws.ToString(accountId) + "/graph/nodes.json")
		} else {
			edgesPath = fmt.Sprintf("~/.local/share/principalmapper/" + aws.ToString(accountId) + "/graph/edges.json")
			nodesPath = fmt.Sprintf("~/.local/share/principalmapper/" + aws.ToString(accountId) + "/graph/nodes.json")
		}

	} else if runtime.GOOS == "windows" {
		dir, err := os.UserConfigDir()
		if err != nil {
			log.Fatal("Could not get userconfigdir")
		}
		edgesPath = fmt.Sprintf(dir + "\\principalmapper" + aws.ToString(accountId) + "\\graph\\edges.json")
		nodesPath = fmt.Sprintf(dir + "\\principalmapper" + aws.ToString(accountId) + "\\graph\\nodes.json")

	}

	return edgesPath, nodesPath
}
