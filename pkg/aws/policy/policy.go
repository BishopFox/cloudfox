package policy

import (
	"encoding/json"
	"fmt"
)

type Policy struct {
	Version   string            `json:"Version"`
	Id        string            `json:"Id"`
	Statement []PolicyStatement `json:"Statement"`
}

func ParseJSONPolicy(data []byte) (Policy, error) {
	var p Policy
	if err := json.Unmarshal(data, &p); err != nil {
		return p, fmt.Errorf("unmarshal JSON: %s", err)
	}

	return p, nil
}

// IsNull returns true iff the Policy is empty
// you cannot do a comparison like this: `p == Policy{}' since we use custom types in the struct`
func (p *Policy) IsEmpty() bool {
	out := true

	out = out && p.Version == ""
	out = out && p.Id == ""

	for _, s := range p.Statement {
		out = out && s.IsEmpty()
	}

	return out
}

// true iff there is at least one statement with principal * and no conditions
func (p *Policy) IsPublic() bool {
	for _, s := range p.Statement {
		if s.IsAllow() && s.Principal.IsPublic() && s.Condition.IsEmpty() {
			return true
		}
	}

	return false
}

// true iff there is at least one statement with principal * with conditions that do not scope access down to AWS accounts or organizations
func (p *Policy) IsConditionallyPublic() bool {
	for _, s := range p.Statement {
		if s.IsAllow() && s.Principal.IsPublic() && !s.Condition.IsScopedOnAccountOrOrganization() && !s.Condition.IsEmpty() {
			return true
		}
	}

	return false
}

func unique(slice []string) []string {
	m := make(map[string]struct{})
	for _, v := range slice {
		m[v] = struct{}{}
	}

	out := make([]string, 0, len(m))
	for v := range m {
		out = append(out, v)
	}
	return out
}

func contains(list []string, elem string) bool {
	for _, e := range list {
		if e == elem {
			return true
		}
	}

	return false
}
