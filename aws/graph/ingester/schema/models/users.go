package models

import (
	"fmt"

	"github.com/BishopFox/cloudfox/aws/graph/ingester/schema"
)

type User struct {
	Id                string
	ARN               string
	Name              string
	IsAdmin           string
	CanPrivEscToAdmin string
	IdValue           string
	IsAdminP          bool
	PathToAdmin       bool
}

func (a *User) MakeRelationships() []schema.Relationship {
	// make a relationship between each role and the account it belongs to
	relationships := []schema.Relationship{}

	// get thisAccount id from user arn
	var thisAccount string
	if len(a.ARN) >= 25 {
		thisAccount = a.ARN[13:25]
	} else {
		fmt.Sprintf("Could not get account number from this user arn%s", a.ARN)
	}

	relationships = append(relationships, schema.Relationship{
		SourceNodeID:     a.Id,
		TargetNodeID:     thisAccount,
		SourceLabel:      schema.User,
		TargetLabel:      schema.Account,
		RelationshipType: schema.MemberOf,
		Properties:       map[string]interface{}{},
	})
	return relationships
}
