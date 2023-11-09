package ingestor

import (
	"archive/zip"
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/BishopFox/cloudfox/aws/graph/ingester/schema"
	"github.com/BishopFox/cloudfox/aws/graph/ingester/schema/models"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	log "github.com/sirupsen/logrus"
)

const (
	// Neo4j
	MergeNodeQueryTemplate = `CALL apoc.merge.node([$labels[0]], {id: $id}, $properties, $properties) YIELD node as obj
	CALL apoc.create.setLabels(obj, $labels) YIELD node as labeledObj
	RETURN labeledObj`

	MergeRelationQueryTemplate = `UNWIND $batch as row
	CALL apoc.merge.node([row.sourceLabel], apoc.map.fromValues([row.sourceProperty, row.sourceNodeId])) YIELD node as from
	CALL apoc.merge.node([row.targetLabel], apoc.map.fromValues([row.targetProperty, row.targetNodeId])) YIELD node as to
	CALL apoc.merge.relationship(from, row.relationshipType, {}, row.properties, to) YIELD rel
	RETURN rel`

	// Using sprintf to insert the label name since the driver doesn't support parameters for labels here
	// %[1]s is a nice way to say "insert the first parameter here"
	CreateConstraintQueryTemplate = "CREATE CONSTRAINT IF NOT EXISTS FOR (n: %s) REQUIRE n.id IS UNIQUE"
	CreateIndexQueryTemplate      = "CREATE INDEX %[1]s_id IF NOT EXISTS FOR (n: %[1]s) ON (n.id)"

	PostProcessMergeQueryTemplate = `MATCH (n)
	WITH n.id AS id, COLLECT(n) AS nodesToMerge
	WHERE size(nodesToMerge) > 1
	CALL apoc.refactor.mergeNodes(nodesToMerge, {properties: 'combine', mergeRels:true})
	YIELD node
	RETURN count(*);`
)

type Neo4jConfig struct {
	Uri      string
	Username string
	Password string
}

type CloudFoxIngestor struct {
	Neo4jConfig
	ResultsFile string
	Driver      neo4j.DriverWithContext
	TmpDir      string
}

func NewCloudFoxIngestor(resultsFile string, username string, password string, server string) (*CloudFoxIngestor, error) {
	config := Neo4jConfig{
		Uri:      server,
		Username: username,
		Password: password,
	}
	driver, err := neo4j.NewDriverWithContext(config.Uri, neo4j.BasicAuth(config.Username, config.Password, ""))
	if err != nil {
		return nil, err
	}
	return &CloudFoxIngestor{
		Neo4jConfig: config,
		ResultsFile: resultsFile,
		Driver:      driver,
	}, nil
}

func unzipToTemp(zipFilePath string) (string, error) {
	// Create a temporary directory to extract the zip file to
	tempDir, err := os.MkdirTemp("", "cirro")
	if err != nil {
		return "", err
	}

	// Open the zip file and extract to a temporary directory
	zipfile, err := zip.OpenReader(zipFilePath)
	if err != nil {
		return "", err
	}
	defer zipfile.Close()

	for _, file := range zipfile.File {
		path := filepath.Join(tempDir, file.Name)
		log.Debugf("Extracting file: %s", path)

		fileData, err := file.Open()
		if err != nil {
			return "", err
		}
		defer fileData.Close()

		newFile, err := os.Create(path)
		if err != nil {
			return "", err
		}
		defer newFile.Close()

		if _, err := io.Copy(newFile, fileData); err != nil {
			return "", err
		}
	}
	return tempDir, nil
}

// func (i *CloudFoxIngestor) ProcessFile(path string, info os.FileInfo) error {
// 	log.Infof("Processing file: %s", info.Name())

// 	switch info.Name() {
// 	case "users.jsonl":
// 		return i.ProcessFileObjects(path, schema.GraphUser, schema.GraphObject)
// 	case "groups.jsonl":
// 		return i.ProcessFileObjects(path, schema.GraphGroup, schema.GraphObject)
// 	case "servicePrincipals.jsonl":
// 		return i.ProcessFileObjects(path, schema.GraphServicePrincipal, schema.GraphObject)
// 	case "applications.jsonl":
// 		return i.ProcessFileObjects(path, schema.GraphApplication, schema.GraphObject)
// 	case "devices.jsonl":
// 		return i.ProcessFileObjects(path, schema.GraphDevice, schema.GraphObject)
// 	case "directoryRoles.jsonl":
// 		return i.ProcessFileObjects(path, schema.GraphRole, schema.GraphObject)
// 	case "subscriptions.jsonl":
// 		return i.ProcessFileObjects(path, schema.Subscription, schema.ArmResource)
// 	case "tenants.jsonl":
// 		return i.ProcessFileObjects(path, schema.Tenant, schema.ArmResource)
// 	case "rbac.jsonl":
// 		return i.ProcessFileObjects(path, schema.AzureRbac, "")
// 	default:
// 		return nil
// 	}
// }

// function that takes objects, object type and then makes relationships

// func (i *CloudFoxIngestor) ProcessObjectsFromSlice(objects []interface{}, objectType schema.NodeLabel, generalType schema.NodeLabel) error {
// func (i *CloudFoxIngestor) ProcessObjectsFromSlice(accounts []models.Account, objectType schema.NodeLabel, generalType schema.NodeLabel) error {
// 	var object = models.NodeLabelToNodeMap[objectType]

// 	//Iterate over the lines and create the nodes
// 	for _, account := range accounts {
// 		relationships := object.MakeRelationships()
// 		if err := i.InsertDBObjects(account, relationships, []schema.NodeLabel{generalType, objectType}); err != nil {
// 			log.Error(err)
// 			continue
// 		}

// 	}
// 	return nil
// }

func (i *CloudFoxIngestor) ProcessFileObjects(path string, objectType schema.NodeLabel, generalType schema.NodeLabel) error {

	var object = models.NodeLabelToNodeMap[objectType]

	// Open the file
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	// Read the file line by line
	scanner := bufio.NewScanner(file)

	//Iterate over the lines and create the nodes
	for scanner.Scan() {
		line := strings.TrimSuffix(scanner.Text(), "\n")

		// Skip empty lines
		if len(line) > 0 {
			if err := json.Unmarshal([]byte(line), &object); err != nil {
				log.Errorf("%s : %s", err, line)
				continue
			}
		}
		relationships := object.MakeRelationships()
		if err := i.InsertDBObjects(object, relationships, []schema.NodeLabel{generalType, objectType}); err != nil {
			log.Error(err)
			continue
		}

	}
	return nil
}

func (i *CloudFoxIngestor) InsertDBObjects(object schema.Node, relationships []schema.Relationship, labels []schema.NodeLabel) error {
	goCtx := context.Background()
	var err error

	// Insert the node
	if object != nil {
		nodeMap := schema.AsNeo4j(&object)
		nodeQueryParams := map[string]interface{}{
			"id":         nodeMap["id"],
			"labels":     labels,
			"properties": nodeMap,
		}
		_, err := neo4j.ExecuteQuery(goCtx, i.Driver, MergeNodeQueryTemplate, nodeQueryParams, neo4j.EagerResultTransformer, neo4j.ExecuteQueryWithDatabase("neo4j"))
		if err != nil {
			log.Errorf("Error inserting node: %s -- %v", err, nodeQueryParams)
			return err
		}
	}

	// Insert the relationships
	if len(relationships) > 0 {
		var relationshipInterface []map[string]interface{}

		// Check the default SourceProperty and TargetProperty values
		for _, relationship := range relationships {
			var currentRelationship map[string]interface{}

			if relationship.SourceProperty == "" {
				relationship.SourceProperty = "id"
			}
			if relationship.TargetProperty == "" {
				relationship.TargetProperty = "id"
			}
			relationshipBytes, err := json.Marshal(relationship)
			if err != nil {
				return err
			}
			if err := json.Unmarshal(relationshipBytes, &currentRelationship); err != nil {
				return err
			}
			relationshipInterface = append(relationshipInterface, currentRelationship)
		}

		_, err = neo4j.ExecuteQuery(goCtx, i.Driver, MergeRelationQueryTemplate, map[string]interface{}{"batch": relationshipInterface}, neo4j.EagerResultTransformer, neo4j.ExecuteQueryWithDatabase("neo4j"))
		if err != nil {
			log.Errorf("Error inserting relationships: %s -- %v", err, relationshipInterface)
			return err
		}
	}

	return nil
}

func (i *CloudFoxIngestor) Run() error {
	goCtx := context.Background()
	log.Infof("Verifying connectivity to Neo4J at %s", i.Uri)
	if err := i.Driver.VerifyConnectivity(goCtx); err != nil {
		return err
	}
	defer i.Driver.Close(goCtx)

	// Get the label to model map

	// Create constraints and indexes
	// log.Info("Creating constraints and indexes for labels")
	// for label := range models.NodeLabelToNodeMap {
	// 	for _, query := range []string{CreateConstraintQueryTemplate, CreateIndexQueryTemplate} {
	// 		_, err := neo4j.ExecuteQuery(goCtx, i.Driver, fmt.Sprintf(query, label), nil, neo4j.EagerResultTransformer, neo4j.ExecuteQueryWithDatabase("neo4j"))
	// 		if err != nil {
	// 			log.Error(err)
	// 			continue
	// 		}
	// 	}
	// }

	// Unzip the results file to a temporary directory
	tempDir, err := unzipToTemp(i.ResultsFile)
	if err != nil {
		return err
	}
	defer os.RemoveAll(tempDir)
	log.Debugf("Using temp dir: %s", tempDir)

	// Open the temporary directory and iterate over the files
	fileWg := new(sync.WaitGroup)
	filepath.Walk(tempDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if tempDir == path {
			return nil
		}

		fileWg.Add(1)
		go func(path string) {
			defer fileWg.Done()
			//i.ProcessFile(path, info)
			log.Infof("Finished processing file: %s", info.Name())
		}(path)
		return nil
	})
	fileWg.Wait()
	log.Info("Finished processing files")

	// Run the post processing merge query
	log.Info("Running post processing merge query")
	_, err = neo4j.ExecuteQuery(goCtx, i.Driver, PostProcessMergeQueryTemplate, nil, neo4j.EagerResultTransformer, neo4j.ExecuteQueryWithDatabase("neo4j"))
	if err != nil {
		log.Error(err)
		return err
	}
	return nil
}
