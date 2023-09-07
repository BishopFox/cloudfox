package policy

import (
	"regexp"
	"strings"
)

// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html
// Conditions have the following general structure:
//   "Condition" : { "{condition-operator}" : { "{condition-key}" : "{condition-value}" }}
type PolicyStatementCondition map[string]map[string]ListOrString

func (psc *PolicyStatementCondition) IsEmpty() bool {
	if psc == nil {
		return true
	}

	return len(*psc) == 0
}

// IsScopedOnAccountOrOrganization returns true if the policy condition ensures access only for specific
// AWS accounts or organizations. If may return false even if access is restricted in such a way.
// Such policies should be reported to the user and analyzed case by case to judge if conditions are sufficiently restrictive.
func (psc *PolicyStatementCondition) IsScopedOnAccountOrOrganization() bool {
	for condition, kv := range *psc {
		for k, v := range kv {
			if strings.ToLower(condition) == "stringequals" && contains([]string{
				"aws:sourceowner",      // https://docs.aws.amazon.com/sns/latest/dg/sns-access-policy-use-cases.html#source-account-versus-source-owner
				"aws:sourceaccount",    // https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html#condition-keys-sourceaccount
				"aws:principalaccount", // https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html#condition-keys-principalaccount
				"aws:principalorgid",   // https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html#condition-keys-principalorgid
				"sns:endpoint",         // https://docs.aws.amazon.com/sns/latest/dg/sns-using-identity-based-policies.html#sns-policy-keys
			}, strings.ToLower(k)) {
				return len(v) > 0
			}

			if strings.ToLower(condition) == "stringlike" && contains([]string{
				"sns:endpoint", // https://docs.aws.amazon.com/sns/latest/dg/sns-using-identity-based-policies.html#sns-policy-keys
			}, strings.ToLower(k)) {
				return isAccountIDInWildcardPattern(v)
			}

			// handling for aws:SourceArn
			// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html#condition-keys-sourcearn
			if contains([]string{
				"arnequals",
				"stringequals",
			}, strings.ToLower(condition)) && strings.ToLower(k) == "aws:sourcearn" {
				return len(v) > 0 // this means there is an exact AWS resource
			}

			if contains([]string{
				"arnlike",
				"stringlike",
			}, strings.ToLower(condition)) && strings.ToLower(k) == "aws:sourcearn" {
				return isAccountIDInWildcardPattern(v)
			}
		}
	}

	return false
}

// isAccountIDInWildcardPattern returns true iff at least one entry in v
// contains an ARN pattern with a full account ID.
func isAccountIDInWildcardPattern(v []string) bool {
	for _, e := range v {
		s := getAccountIDInARN(e)
		if s != "" {
			return true
		}
	}

	return false
}

// Format: arn:aws:<service>:<optional-region>:<account-id>:<rest-of-the-arn>
var reAccountIDInARN = regexp.MustCompile(`arn:aws:[a-zA-Z0-9]+:[a-zA-Z0-9-]*:([0-9]+):`)

func getAccountIDInARN(arn string) string {
	match := reAccountIDInARN.FindStringSubmatch(arn)
	if len(match) != 2 {
		return ""
	}

	return match[1]
}
