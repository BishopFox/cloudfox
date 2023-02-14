package policy

import (
	"fmt"
	"strings"
)

type PolicyStatement struct {
	Sid       string                   `json:"Sid,omitempty"`
	Effect    string                   `json:"Effect"`
	Principal PolicyStatementPrincipal `json:"Principal,omitempty"`
	Action    ListOrString             `json:"Action"`
	Resource  ListOrString             `json:"Resource,omitempty"`
	Condition PolicyStatementCondition `json:"Condition,omitempty"`
}

func (ps *PolicyStatement) IsEmpty() bool {
	return ps.Sid == "" &&
		ps.Effect == "" &&
		ps.Principal.IsEmpty() &&
		len(ps.Action) < 1 &&
		len(ps.Resource) < 1 &&
		ps.Condition.IsEmpty()
}

func (ps *PolicyStatement) IsAllow() bool {
	return strings.TrimSpace(strings.ToLower(ps.Effect)) == "allow"
}

func (ps *PolicyStatement) GetAllActionsAsString() string {
	actions := ""
	for _, action := range ps.Action {
		if ps.Effect == "Allow" {
			actions = fmt.Sprintf("%s%s\n", actions, action)
		} else if ps.Effect == "Deny" {
			actions = fmt.Sprintf("%snot %s\n", actions, action)
		}
	}
	return actions
}

func (ps *PolicyStatement) GetAllPrincipalsAsString() string {
	principals := ""
	for _, principal := range ps.Principal.O.GetListOfPrincipals() {
		principals = fmt.Sprintf("%s%s\n", principals, principal)
	}
	if principals == "" && ps.Principal.S == "*" {
		principals = "Everyone"

	}
	return principals
}

func (ps *PolicyStatement) GetConditionsInEnglish() string {
	conditionTextAll := ""
	for condition, kv := range ps.Condition {
		if condition == "StringEquals" || condition == "ArnEquals" {
			condition = "="
		} else if condition == "StringLike" || condition == "ArnLike" {
			condition = "is like"
		}
		for k, v := range kv {
			for _, arn := range v {
				var conditionText string
				if k == "AWS:SourceOwner" || k == "AWS:SourceAccount" {
					conditionText = "Default resource policy: Not exploitable"
				} else {
					conditionText = fmt.Sprintf("Only when %s %s %s", k, condition, arn)
				}

				conditionTextAll = fmt.Sprintf("%s%s\n", conditionTextAll, conditionText)

			}
		}

	}
	return conditionTextAll
}
