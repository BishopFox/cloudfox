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

func (a *User) GenerateAttributes() map[string]string {
	return map[string]string{
		"Id":                a.Id,
		"ARN":               a.ARN,
		"Name":              a.Name,
		"IsAdmin":           a.IsAdmin,
		"CanPrivEscToAdmin": a.CanPrivEscToAdmin,
		"IdValue":           a.IdValue,
	}
}

func (a *User) MergeAttributes(other map[string]string) {
	if other["Id"] != "" {
		a.Id = other["Id"]
	}
	if other["ARN"] != "" {
		a.ARN = other["ARN"]
	}
	if other["Name"] != "" {
		a.Name = other["Name"]
	}
	if other["IsAdmin"] != "" {
		a.IsAdmin = other["IsAdmin"]
	}
	if other["CanPrivEscToAdmin"] != "" {
		a.CanPrivEscToAdmin = other["CanPrivEscToAdmin"]
	}
	if other["IdValue"] != "" {
		a.IdValue = other["IdValue"]
	}
}
