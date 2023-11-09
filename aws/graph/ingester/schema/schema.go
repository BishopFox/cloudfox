package schema

import (
	"github.com/goccy/go-json"
	"golang.org/x/exp/slices"
)

type RelationshipType string
type NodeLabel string

type Node interface {
	MakeRelationships() []Relationship
}

type Relationship struct {
	SourceNodeID     string                 `json:"sourceNodeId"`
	TargetNodeID     string                 `json:"targetNodeId"`
	SourceLabel      NodeLabel              `json:"sourceLabel"`
	TargetLabel      NodeLabel              `json:"targetLabel"`
	RelationshipType RelationshipType       `json:"relationshipType"`
	Properties       map[string]interface{} `json:"properties"`
	SourceProperty   string                 `json:"sourceProperty"`
	TargetProperty   string                 `json:"targetProperty"`
}

const (
	// Relationships

	AssociatedTo  RelationshipType = "AssociatedTo"
	AttachedTo    RelationshipType = "AttachedTo"
	Authenticates RelationshipType = "Authenticates"
	ConnectedTo   RelationshipType = "ConnectedTo"
	Contains      RelationshipType = "Contains"
	Exposes       RelationshipType = "Exposes"
	HasAccess     RelationshipType = "HasAccess"
	HasConfig     RelationshipType = "HasConfig"
	HasDisk       RelationshipType = "HasDisk"
	HasInstance   RelationshipType = "HasInstance"
	HasRbac       RelationshipType = "HasRbac"
	HasRole       RelationshipType = "HasRole"
	Manages       RelationshipType = "Manages"
	MemberOf      RelationshipType = "MemberOf"
	Owns          RelationshipType = "Owns"
	Represents    RelationshipType = "Represents"
	Trusts        RelationshipType = "Trusts"
)

const (
	// Node labels
	Resource          NodeLabel = "Resource"
	Account           NodeLabel = "Account"
	Organization      NodeLabel = "Org"
	Service           NodeLabel = "Service"
	Role              NodeLabel = "Role"
	Group             NodeLabel = "Group"
	User              NodeLabel = "User"
	FederatedIdentity NodeLabel = "FederatedIdentity"
)

func AsNeo4j(object *Node) map[string]interface{} {

	// We don't want to include these fields in the map
	fieldsToExclude := []string{"members", "owners", "appRoles", "registeredUsers"}
	objectMap, err := json.Marshal(object)
	if err != nil {
		return nil
	}

	var objectMapInterface map[string]interface{}
	json.Unmarshal(objectMap, &objectMapInterface)
	for _, field := range fieldsToExclude {
		delete(objectMapInterface, field)
	}

	// We need to convert flatten maps to an array
	// We'll want to keep order of the keys for things like extensionAttributes
	for key, value := range objectMapInterface {
		_, isMap := value.(map[string]interface{})
		if isMap {
			var valueArray []string
			var keys []string

			for k := range value.(map[string]interface{}) {
				keys = append(keys, k)
			}
			slices.Sort(keys)

			for _, k := range keys {
				valueString := value.(map[string]interface{})[k].(string)
				if valueString != "" {
					valueArray = append(valueArray, k, valueString)
				}
			}
			objectMapInterface[key] = valueArray
		}
	}
	return objectMapInterface
}
