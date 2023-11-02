package policy

import (
	"encoding/json"
	"errors"
	"strings"
)

type PolicyStatementPrincipal struct {
	S string
	O PolicyStatementPrincipalObject
}

func (psp *PolicyStatementPrincipal) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		psp.S = s
		return nil
	}

	var obj PolicyStatementPrincipalObject
	if err := json.Unmarshal(b, &obj); err == nil {
		psp.O = obj
		return nil
	}

	return errors.New("principal is not a string or complex object")
}

func (psp *PolicyStatementPrincipal) MarshalJSON() ([]byte, error) {
	if psp.S != "" {
		return json.Marshal(psp.S)
	}

	return json.Marshal(psp.O)
}

func (psp *PolicyStatementPrincipal) IsEmpty() bool {
	return psp.S == "" && psp.O.IsEmpty()
}

func (psp *PolicyStatementPrincipal) IsPublic() bool {
	return psp.S == "*" || psp.O.IsPublic()
}

type PolicyStatementPrincipalObject struct {
	AWS           ListOrString `json:"AWS,omitempty"`
	CanonicalUser ListOrString `json:"CanonicalUser,omitempty"`
	Federated     ListOrString `json:"Federated,omitempty"`
	Service       ListOrString `json:"Service,omitempty"`
}

func (pspo *PolicyStatementPrincipalObject) IsEmpty() bool {
	return len(pspo.AWS) == 0 &&
		len(pspo.CanonicalUser) == 0 &&
		len(pspo.Federated) == 0 &&
		len(pspo.Service) == 0
}

func (pspo *PolicyStatementPrincipalObject) IsPublic() bool {
	for _, s := range pspo.AWS {
		if s == "*" {
			return true
		}
	}

	return false
}

func (pspo *PolicyStatementPrincipalObject) GetListOfPrincipals() []string {
	var allPrincipals []string
	allPrincipals = append(allPrincipals, pspo.AWS...)
	allPrincipals = append(allPrincipals, pspo.CanonicalUser...)
	allPrincipals = append(allPrincipals, pspo.Federated...)
	allPrincipals = append(allPrincipals, pspo.Service...)
	return allPrincipals
}

type ListOrString []string

func (ls *ListOrString) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*ls = append(*ls, s)
		return nil
	}

	var ss []string
	if err := json.Unmarshal(b, &ss); err == nil {
		*ls = ss
		return nil
	}

	return errors.New("not a string or list of strings")
}

// create a method on *PolicyStatementPrincipalObject that will determine if trusted principal is from the same account as the resource or a different account
func (pspo *PolicyStatementPrincipalObject) IsTrustedPrincipalSameAccount(accountID string) bool {
	for _, principal := range pspo.CanonicalUser {
		if strings.Contains(principal, ":") {
			principalAccount := strings.Split(principal, ":")[4]
			if principalAccount == accountID {
				return true
			}
		}
	}
	return false
}
