package policy

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
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

// source: https://github.com/nccgroup/PMapper/blob/master/principalmapper/querying/local_policy_simulation.py
func composePattern(stringToTransform string) *regexp.Regexp {
	// Escape special characters and replace wildcards
	escaped := strings.ReplaceAll(stringToTransform, ".", "\\.")
	escaped = strings.ReplaceAll(escaped, "*", ".*")
	escaped = strings.ReplaceAll(escaped, "?", ".")
	escaped = strings.ReplaceAll(escaped, "$", "\\$")
	escaped = strings.ReplaceAll(escaped, "^", "\\^")

	// Compile the regular expression, ignoring case
	pattern, err := regexp.Compile("(?i)^" + escaped + "$")
	if err != nil {
		panic("regexp compile error: " + err.Error())
	}
	return pattern
}

// source: https://github.com/nccgroup/PMapper/blob/master/principalmapper/querying/local_policy_simulation.py
// MatchesAfterExpansion checks the stringToCheck against stringToCheckAgainst.
func MatchesAfterExpansion(stringFromPolicyToCheck, stringToCheckAgainst string) bool {
	// Transform the stringToCheckAgainst into a regex pattern
	pattern := composePattern(stringToCheckAgainst)

	// Check if the pattern matches stringToCheck
	return pattern.MatchString(stringFromPolicyToCheck)
}




func (p *Policy) DoesPolicyHaveMatchingStatement(effect string, actionToCheck string, resourceToCheck string) bool {

	for _, statement := range p.Statement {
		if statement.Effect == effect {
			matchesAction, matchesResource := false, false
			for _, action := range statement.Action {
				if MatchesAfterExpansion(actionToCheck, action) {
					matchesAction = true
					if resourceToCheck != "" {
						for _, resource := range statement.Resource {
							if MatchesAfterExpansion(resourceToCheck, resource) {
								matchesResource = true
							}
						}
						for _, notResource := range statement.NotResource {
							if MatchesAfterExpansion(resourceToCheck, notResource) {
								matchesResource = false
							}
						}
					}
				}
			}
			for _, notAction := range statement.NotAction {
				matchesAction = true
				if notAction == "*" {
					matchesAction = false
				}
				if notAction == actionToCheck {
					matchesAction = false
				}

				if MatchesAfterExpansion(actionToCheck, notAction) {
					matchesAction = false
				}
				if resourceToCheck != "" {
					for _, resource := range statement.Resource {
						if MatchesAfterExpansion(resourceToCheck, resource) {
							matchesResource = true
						}
					}
					for _, notResource := range statement.NotResource {
						if MatchesAfterExpansion(resourceToCheck, notResource) {
							matchesResource = false
						}
					}
				}

			}
			if matchesAction && matchesResource {
				return true
			}
		}

	}

	return false
}
