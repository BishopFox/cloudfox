package policy

import (
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
