package models

import "github.com/BishopFox/cloudfox/aws/graph/ingester/schema"

type Account struct {
	Id               string
	Arn              string
	Email            string
	Name             string
	Status           string
	JoinedMethod     string
	JoinedTimestamp  string
	IsOrgMgmt        bool
	IsChildAccount   bool
	OrgMgmtAccountID string
	OrganizationID   string
}

func (a *Account) MakeRelationships() []schema.Relationship {
	var relationships []schema.Relationship

	// make relationship from children accounts to parent org
	if a.IsChildAccount {
		// make relationship from child to org mgmt account
		relationships = append(relationships, schema.Relationship{
			SourceNodeID:     a.OrganizationID,
			TargetNodeID:     a.Id,
			SourceLabel:      schema.Organization,
			TargetLabel:      schema.Account,
			RelationshipType: schema.Manages,
		})
		// make relationship from parent org mgmt account to child account
		relationships = append(relationships, schema.Relationship{
			SourceNodeID:     a.Id,
			TargetNodeID:     a.OrganizationID,
			SourceLabel:      schema.Account,
			TargetLabel:      schema.Organization,
			RelationshipType: schema.MemberOf,
		})

	}

	return relationships
}
