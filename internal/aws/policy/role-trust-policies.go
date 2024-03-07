package policy

import (
	"encoding/json"
	"errors"
	"net/url"
	"regexp"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

type TrustPolicyDocument struct {
	Version   string                    `json:"Version"`
	Statement []RoleTrustStatementEntry `json:"Statement"`
}

type RoleTrustStatementEntry struct {
	Sid       string `json:"Sid"`
	Effect    string `json:"Effect"`
	Principal struct {
		AWS       ListOfPrincipals `json:"AWS"`
		Service   ListOfPrincipals `json:"Service"`
		Federated ListOfPrincipals `json:"Federated"`
	} `json:"Principal"`
	Action    string `json:"Action"`
	Condition struct {
		StringEquals struct {
			StsExternalID string           `json:"sts:ExternalId"`
			SAMLAud       string           `json:"SAML:aud"`
			OidcEksSub    ListOfPrincipals `json:"OidcEksSub"`
			OidcEksAud    string           `json:"OidcEksAud"`
			CognitoAud    string           `json:"cognito-identity.amazonaws.com:aud"`
		} `json:"StringEquals"`
		StringLike struct {
			TokenActionsGithubusercontentComSub ListOfPrincipals `json:"token.actions.githubusercontent.com:sub"`
			TokenActionsGithubusercontentComAud string           `json:"token.actions.githubusercontent.com:aud"`
			OidcEksSub                          ListOfPrincipals `json:"OidcEksSub"`
			OidcEksAud                          string           `json:"OidcEksAud"`
		} `json:"StringLike"`
		ForAnyValueStringLike struct {
			CognitoAMR string `json:"cognito-identity.amazonaws.com:amr"`
		} `json:"ForAnyValue:StringLike"`
	} `json:"Condition"`
}

// A custom unmarshaller is necessary because the list of principals can be an array of strings or a string.
// https://stackoverflow.com/questions/65854778/parsing-arn-from-iam-policy-using-regex
type ListOfPrincipals []string

func (r *ListOfPrincipals) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*r = append(*r, s)
		return nil
	}
	var ss []string
	if err := json.Unmarshal(b, &ss); err == nil {
		*r = ss
		return nil
	}
	return errors.New("cannot unmarshal neither to a string nor a slice of strings")
}

func ParseRoleTrustPolicyDocument(role types.Role) (TrustPolicyDocument, error) {
	document, _ := url.QueryUnescape(aws.ToString(role.AssumeRolePolicyDocument))

	// These next six lines are a hack, needed because the EKS OIDC json field name is dynamic
	// and therefore can't be used to unmarshall in a predictable way. The hack involves replacing
	// the random pattern with a predictable one so that we can add the predictable one in the struct
	// used to unmarshall.
	pattern := `(\w+)\:`
	pattern2 := `".[a-zA-Z0-9\-\.]+/id/`
	var reEKSSub = regexp.MustCompile(pattern2 + pattern + "sub")
	var reEKSAud = regexp.MustCompile(pattern2 + pattern + "aud")
	document = reEKSSub.ReplaceAllString(document, "\"OidcEksSub")
	document = reEKSAud.ReplaceAllString(document, "\"OidcEksAud")

	var parsedDocumentToJSON TrustPolicyDocument
	_ = json.Unmarshal([]byte(document), &parsedDocumentToJSON)
	return parsedDocumentToJSON, nil
}
