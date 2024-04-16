package schema

import (
	"fmt"
	"reflect"

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

	AssociatedTo          RelationshipType = "AssociatedTo"
	AttachedTo            RelationshipType = "AttachedTo"
	Authenticates         RelationshipType = "Authenticates"
	ConnectedTo           RelationshipType = "ConnectedTo"
	Contains              RelationshipType = "Contains"
	Exposes               RelationshipType = "Exposes"
	HasAccess             RelationshipType = "HasAccess"
	HasConfig             RelationshipType = "HasConfig"
	HasDisk               RelationshipType = "HasDisk"
	HasInstance           RelationshipType = "HasInstance"
	HasRbac               RelationshipType = "HasRbac"
	HasRole               RelationshipType = "HasRole"
	Manages               RelationshipType = "Manages"
	MemberOf              RelationshipType = "MemberOf"
	Owns                  RelationshipType = "Owns"
	Represents            RelationshipType = "Represents"
	Trusts                RelationshipType = "Trusts"
	IsTrustedBy           RelationshipType = "IsTrustedBy"
	CanAssume             RelationshipType = "CanAssume"
	CanAssumeCrossAccount RelationshipType = "CanAssumeCrossAccount"
	CanBeAssumedBy        RelationshipType = "CanBeAssumedBy"
	CanBeAssumedByTest    RelationshipType = "CanBeAssumedByTest"
	CanAssumeTest         RelationshipType = "CanAssumeTest"
	CanAccess             RelationshipType = "CAN_ACCESS"
)

const (
	// Node labels
	Resource          NodeLabel = "Resource"
	Account           NodeLabel = "Account"
	Organization      NodeLabel = "Org"
	Service           NodeLabel = "Service"
	Principal         NodeLabel = "Principal"
	Vendor            NodeLabel = "Vendor"
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

func ConvertCustomTypesToNeo4j(node interface{}) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	val := reflect.ValueOf(node)

	// Handling pointers to structs or interfaces
	for val.Kind() == reflect.Ptr || val.Kind() == reflect.Interface {
		val = val.Elem()
	}

	// Check if the value is valid and if it's a struct
	if !val.IsValid() || val.Kind() != reflect.Struct {
		return nil, fmt.Errorf("invalid input: not a struct or a pointer to a struct")
	}

	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		fieldType := val.Type().Field(i) // Get the StructField

		// Check if the field is a struct or slice of structs and not one of the basic types
		if (fieldType.Type.Kind() == reflect.Struct ||
			(fieldType.Type.Kind() == reflect.Slice && fieldType.Type.Elem().Kind() == reflect.Struct)) &&
			fieldType.Type != reflect.TypeOf([]string{}) &&
			fieldType.Type != reflect.TypeOf([]int{}) &&
			fieldType.Type != reflect.TypeOf([]bool{}) {
			// Convert complex field to JSON string
			jsonStr, err := json.Marshal(field.Interface())
			if err != nil {
				return nil, err
			}
			result[fieldType.Name] = string(jsonStr)
		} else {
			// Directly use the field for primitive types
			result[fieldType.Name] = field.Interface()
		}
	}
	return result, nil
}
