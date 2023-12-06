package models

import (
	"github.com/BishopFox/cloudfox/aws/graph/ingester/schema"
)

var NodeLabelToNodeMap = map[schema.NodeLabel]schema.Node{
	schema.Organization: &Organization{},
	schema.Account:      &Account{},
	schema.Role:         &Role{},
}
