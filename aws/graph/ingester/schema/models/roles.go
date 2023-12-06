package models

import (
	"fmt"
	"strings"

	"github.com/BishopFox/cloudfox/aws/graph/ingester/schema"
	"github.com/BishopFox/cloudfox/internal/aws/policy"
	"github.com/BishopFox/cloudfox/internal/common"
)

type User struct {
	Id                string
	UserArn           string
	UserName          string
	IsAdmin           string
	CanPrivEscToAdmin string
}

type Role struct {
	Id                        string
	AccountID                 string
	RoleARN                   string
	RoleName                  string
	TrustsDoc                 policy.TrustPolicyDocument
	TrustedPrincipals         []TrustedPrincipal
	TrustedServices           []TrustedService
	TrustedFederatedProviders []TrustedFederatedProvider
	CanPrivEscToAdmin         string
	IsAdmin                   string
}

type TrustedPrincipal struct {
	TrustedPrincipal string
	ExternalID       string
	//IsAdmin           bool
	//CanPrivEscToAdmin bool
}

type TrustedService struct {
	TrustedService string
	//IsAdmin           bool
	//CanPrivEscToAdmin bool
}

type TrustedFederatedProvider struct {
	TrustedFederatedProvider string
	ProviderShortName        string
	TrustedSubjects          string
	//IsAdmin                  bool
	//CanPrivEscToAdmin        bool
}

func (a *Role) MakeRelationships() []schema.Relationship {
	var relationships []schema.Relationship
	//instance := singleton.GetInstance()

	// get thisAccount id from role arn
	var thisAccount string
	if len(a.RoleARN) >= 25 {
		thisAccount = a.RoleARN[13:25]
	} else {
		fmt.Sprintf("Could not get account number from this role arn%s", a.RoleARN)
	}

	// make a relationship between each role and the account it belongs to
	relationships = append(relationships, schema.Relationship{
		SourceNodeID:     a.Id,
		TargetNodeID:     thisAccount,
		SourceLabel:      schema.Role,
		TargetLabel:      schema.Account,
		RelationshipType: schema.MemberOf,
	})

	for _, TrustedPrincipal := range a.TrustedPrincipals {
		//get account id from the trusted principal arn
		var trustedPrincipalAccount string
		if len(TrustedPrincipal.TrustedPrincipal) >= 25 {
			trustedPrincipalAccount = TrustedPrincipal.TrustedPrincipal[13:25]
		} else {
			fmt.Sprintf("Could not get account number from this TrustedPrincipal%s", TrustedPrincipal.TrustedPrincipal)
		}
		var PermissionsRowAccount string
		// make a TRUSTED_BY relationship between the role and the trusted principal. This does not mean the principal can assume this role, we need more logic to determine that (see below)
		// relationships = append(relationships, schema.Relationship{
		// 	SourceNodeID:     TrustedPrincipal.TrustedPrincipal,
		// 	TargetNodeID:     a.Id,
		// 	SourceLabel:      schema.Principal,
		// 	TargetLabel:      schema.Role,
		// 	RelationshipType: schema.IsTrustedBy,
		// })
		// // make a TRUSTS relationship between the trusted principal and this role. This does not mean the principal can assume this role, we need more logic to determine that (see below)
		// relationships = append(relationships, schema.Relationship{
		// 	SourceNodeID:     a.Id,
		// 	TargetNodeID:     TrustedPrincipal.TrustedPrincipal,
		// 	SourceLabel:      schema.Role,
		// 	TargetLabel:      schema.Principal,
		// 	RelationshipType: schema.Trusts,
		// })
		// // make a MEMBER_OF relationship between the role and the account
		// relationships = append(relationships, schema.Relationship{
		// 	SourceNodeID:     TrustedPrincipal.TrustedPrincipal,
		// 	TargetNodeID:     trustedPrincipalAccount,
		// 	SourceLabel:      schema.Principal,
		// 	TargetLabel:      schema.Account,
		// 	RelationshipType: schema.MemberOf,
		// })

		// if the role trusts a principal in this same account explicitly, then the principal can assume the role
		if thisAccount == trustedPrincipalAccount {
			// make a CAN_ASSUME relationship between the trusted principal and this role
			relationships = append(relationships, schema.Relationship{
				SourceNodeID:     TrustedPrincipal.TrustedPrincipal,
				TargetNodeID:     a.Id,
				SourceLabel:      schema.Principal,
				TargetLabel:      schema.Role,
				RelationshipType: schema.CanAssume,
			})
			// make a CAN_BE_ASSUMED_BY relationship between this role and the trusted principal
			// relationships = append(relationships, schema.Relationship{
			// 	SourceNodeID:     a.Id,
			// 	TargetNodeID:     TrustedPrincipal.TrustedPrincipal,
			// 	SourceLabel:      schema.Role,
			// 	TargetLabel:      schema.Principal,
			// 	RelationshipType: schema.CanBeAssumedBy,
			// })
		}

		// If the role trusts a principal in this account or another account using the :root notation, then we need to iterate over all of the rows in AllPermissionsRows to find the principals that have sts:AssumeRole permissions on this role
		// if the role we are looking at trusts root in it's own account

		if strings.Contains(TrustedPrincipal.TrustedPrincipal, fmt.Sprintf("%s:root", thisAccount)) {
			// iterate over all rows in AllPermissionsRows
			for _, PermissionsRow := range common.PermissionRowsFromAllProfiles {
				// but we only care about the rows that have arns that are in this account

				if len(PermissionsRow.Arn) >= 25 {
					PermissionsRowAccount = PermissionsRow.Arn[13:25]
				} else {
					fmt.Sprintf("Could not get account number from this PermissionsRow%s", PermissionsRow.Arn)
				}

				if PermissionsRowAccount == thisAccount {
					// lets only look for rows that have sts:AssumeRole permissions
					if strings.EqualFold(PermissionsRow.Action, "sts:AssumeRole") ||
						strings.EqualFold(PermissionsRow.Action, "*") ||
						strings.EqualFold(PermissionsRow.Action, "sts:Assume*") ||
						strings.EqualFold(PermissionsRow.Action, "sts:*") {
						// lets only focus on rows that have an effect of Allow
						if strings.EqualFold(PermissionsRow.Effect, "Allow") {
							// if the resource is * or the resource is this role arn, then this principal can assume this role
							if PermissionsRow.Resource == "*" || strings.Contains(PermissionsRow.Resource, a.RoleARN) {
								// make a CAN_ASSUME relationship between the trusted principal and this role
								//evalutate if the princiapl is a user or a role and set a variable accordingly
								//var principalType schema.NodeLabel
								if strings.EqualFold(PermissionsRow.Type, "User") {
									relationships = append(relationships, schema.Relationship{
										SourceNodeID:     PermissionsRow.Arn,
										TargetNodeID:     a.Id,
										SourceLabel:      schema.User,
										TargetLabel:      schema.Role,
										RelationshipType: schema.CanAssume,
									})
								} else if strings.EqualFold(PermissionsRow.Type, "Role") {
									relationships = append(relationships, schema.Relationship{
										SourceNodeID:     PermissionsRow.Arn,
										TargetNodeID:     a.Id,
										SourceLabel:      schema.Role,
										TargetLabel:      schema.Role,
										RelationshipType: schema.CanAssume,
									})
								}

								// relationships = append(relationships, schema.Relationship{
								// 	SourceNodeID:     PermissionsRow.Arn,
								// 	TargetNodeID:     a.Id,
								// 	SourceLabel:      principalType,
								// 	TargetLabel:      schema.Role,
								// 	RelationshipType: schema.CanAssumeTest,
								// })
								// make a CAN_BE_ASSUMED_BY relationship between this role and the trusted principal
								// relationships = append(relationships, schema.Relationship{
								// 	SourceNodeID:     a.Id,
								// 	TargetNodeID:     PermissionsRow.Arn,
								// 	SourceLabel:      schema.Role,
								// 	TargetLabel:      schema.Principal,
								// 	RelationshipType: schema.CanBeAssumedByTest,
								// })

							}
						}
					}

				}
			}
		} else if strings.Contains(TrustedPrincipal.TrustedPrincipal, fmt.Sprintf("%s:root", trustedPrincipalAccount)) {
			// iterate over all rows in AllPermissionsRows
			for _, PermissionsRow := range common.PermissionRowsFromAllProfiles {
				// but we only care about the rows that have arns that are in this other account
				if len(PermissionsRow.Arn) >= 25 {
					PermissionsRowAccount = PermissionsRow.Arn[13:25]
				} else {
					fmt.Sprintf("Could not get account number from this PermissionsRow%s", PermissionsRow.Arn)
				}
				if PermissionsRowAccount == trustedPrincipalAccount {
					// lets only look for rows that have sts:AssumeRole permissions
					if strings.EqualFold(PermissionsRow.Action, "sts:AssumeRole") ||
						strings.EqualFold(PermissionsRow.Action, "*") ||
						strings.EqualFold(PermissionsRow.Action, "sts:Assume*") ||
						strings.EqualFold(PermissionsRow.Action, "sts:*") {
						// lets only focus on rows that have an effect of Allow
						if strings.EqualFold(PermissionsRow.Effect, "Allow") {
							// if the resource is * or the resource is this role arn, then this principal can assume this role
							if PermissionsRow.Resource == "*" || strings.Contains(PermissionsRow.Resource, a.RoleARN) {
								// make a CAN_ASSUME relationship between the trusted principal and this role

								if strings.EqualFold(PermissionsRow.Type, "User") {
									relationships = append(relationships, schema.Relationship{
										SourceNodeID:     PermissionsRow.Arn,
										TargetNodeID:     a.Id,
										SourceLabel:      schema.User,
										TargetLabel:      schema.Role,
										RelationshipType: schema.CanAssumeCrossAccount,
									})
								} else if strings.EqualFold(PermissionsRow.Type, "Role") {
									relationships = append(relationships, schema.Relationship{
										SourceNodeID:     PermissionsRow.Arn,
										TargetNodeID:     a.Id,
										SourceLabel:      schema.Role,
										TargetLabel:      schema.Role,
										RelationshipType: schema.CanAssumeCrossAccount,
									})
								}
								// // make a CAN_BE_ASSUMED_BY relationship between this role and the trusted principal
								// relationships = append(relationships, schema.Relationship{
								// 	SourceNodeID:     a.Id,
								// 	TargetNodeID:     PermissionsRow.Arn,
								// 	SourceLabel:      schema.Role,
								// 	TargetLabel:      schema.Principal,
								// 	RelationshipType: schema.CanBeAssumedByTest,
								// })

							}
						}
					}

				}
			}
		}

	}

	for _, TrustedService := range a.TrustedServices {
		// make relationship from trusted service to this role of type can assume
		relationships = append(relationships, schema.Relationship{
			SourceNodeID:     TrustedService.TrustedService,
			TargetNodeID:     a.Id,
			SourceLabel:      schema.Service,
			TargetLabel:      schema.Role,
			RelationshipType: schema.IsTrustedBy,
		})
		// make relationship from this role to trusted service of type can be assumed by
		relationships = append(relationships, schema.Relationship{
			SourceNodeID:     a.Id,
			TargetNodeID:     TrustedService.TrustedService,
			SourceLabel:      schema.Role,
			TargetLabel:      schema.Service,
			RelationshipType: schema.Trusts,
		})
	}

	for _, TrustedFederatedProvider := range a.TrustedFederatedProviders {
		// make relationship from trusted federated provider to this role of type can assume
		relationships = append(relationships, schema.Relationship{
			SourceNodeID:     TrustedFederatedProvider.TrustedFederatedProvider,
			TargetNodeID:     a.Id,
			SourceLabel:      schema.FederatedIdentity,
			TargetLabel:      schema.Role,
			RelationshipType: schema.CanAssume,
		})
		// make relationship from this role to trusted federated provider of type can be assumed by
		relationships = append(relationships, schema.Relationship{
			SourceNodeID:     a.Id,
			TargetNodeID:     TrustedFederatedProvider.TrustedFederatedProvider,
			SourceLabel:      schema.Role,
			TargetLabel:      schema.FederatedIdentity,
			RelationshipType: schema.CanBeAssumedBy,
		})
		// make relationship from trusted federated provider to this role of type can assume
		relationships = append(relationships, schema.Relationship{
			SourceNodeID:     TrustedFederatedProvider.TrustedFederatedProvider,
			TargetNodeID:     a.Id,
			SourceLabel:      schema.FederatedIdentity,
			TargetLabel:      schema.Role,
			RelationshipType: schema.IsTrustedBy,
		})
		// make relationship from this role to trusted federated provider of type can be assumed by
		relationships = append(relationships, schema.Relationship{
			SourceNodeID:     a.Id,
			TargetNodeID:     TrustedFederatedProvider.TrustedFederatedProvider,
			SourceLabel:      schema.Role,
			TargetLabel:      schema.FederatedIdentity,
			RelationshipType: schema.Trusts,
		})
	}

	return relationships
}
