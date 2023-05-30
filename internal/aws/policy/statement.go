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
	NotAction ListOrString             `json:"NotAction,omitempty"`
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
	if len(ps.Action) < 3 {
		for _, action := range ps.Action {
			if ps.Effect == "Allow" {
				actions = fmt.Sprintf("%scan %s & ", actions, action)
			} else if ps.Effect == "Deny" {
				actions = fmt.Sprintf("%sis denied %s & ", actions, action)
			}
		}
	} else {
		if ps.Effect == "Allow" {
			actions = fmt.Sprintf("can perform %d actions", len(ps.Action))
		} else if ps.Effect == "Deny" {
			actions = fmt.Sprintf("is denied %d actions", len(ps.Action))

		}
	}
	actions = strings.TrimSuffix(actions, " & ")
	actions = actions + "\n"

	return actions
}

func (ps *PolicyStatement) GetAllPrincipalsAsString() string {
	principals := ""
	for _, principal := range ps.Principal.O.GetListOfPrincipals() {
		principals = fmt.Sprintf("%s%s & ", principals, principal)
	}
	if principals == "" && ps.Principal.S == "*" {
		principals = "Everyone"

	}
	return strings.TrimSuffix(principals, " & ")
}

func (ps *PolicyStatement) GetConditionsInEnglish(caller string) string {
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
				if (k == "AWS:SourceOwner" || k == "AWS:SourceAccount") && contains(v, caller) {
					conditionText = "Default resource policy: Not exploitable"
				} else {
					conditionText = fmt.Sprintf("->   Only when %s %s %s", k, condition, arn)
				}

				conditionTextAll = fmt.Sprintf("%s%s\n", conditionTextAll, conditionText)

			}
		}

	}
	return conditionTextAll
}

func (ps *PolicyStatement) GetStatementSummaryInEnglish(caller string) string {

	var statementSummary string
	actions := ps.GetAllActionsAsString()
	principals := ps.GetAllPrincipalsAsString()
	conditions := ps.GetConditionsInEnglish(caller)

	if conditions == "Default resource policy: Not exploitable\n" {
		statementSummary = "Default resource policy: Not exploitable\n" + "\n"
	} else if conditions != "\n" && conditions != "" {
		statementSummary = fmt.Sprintf("%s %s %s", strings.TrimSuffix(principals, "\n"), actions, conditions) + "\n"

	} else {
		statementSummary = fmt.Sprintf("%s %s\n", strings.TrimSuffix(principals, "\n"), actions)

	}
	return statementSummary
}
