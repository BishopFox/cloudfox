package models

import (
	"github.com/BishopFox/cloudfox/aws/graph/ingester/schema"
)

type Organization struct {
	Id                 string
	OrgId              string
	Arn                string
	MasterAccountArn   string
	MasterAccountId    string
	MasterAccountEmail string
	ChildAccounts      []Account
	MgmtAccount        Account
}

func (o *Organization) MakeRelationships() []schema.Relationship {
	return []schema.Relationship{}
}
