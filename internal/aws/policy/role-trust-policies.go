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
			StsExternalID                       ListOfPrincipals `json:"sts:ExternalId"`
			SAMLAud                             string           `json:"SAML:aud"`
			TokenActionsGithubusercontentComSub ListOfPrincipals `json:"token.actions.githubusercontent.com:sub"`
			TokenActionsGithubusercontentComAud string           `json:"token.actions.githubusercontent.com:aud"`
			OidcEksSub                          ListOfPrincipals `json:"OidcEksSub"`
			OidcEksAud                          string           `json:"OidcEksAud"`
			CognitoAud                          string           `json:"cognito-identity.amazonaws.com:aud"`
			TerraformAud                        string           `json:"app.terraform.io:aud"` // Terraform Cloud specific
			TerraformSub                        ListOfPrincipals `json:"app.terraform.io:sub"` // Terraform Cloud specific
			GCPAud                              string           `json:"accounts.google.com:aud"`
			GCPSub                              ListOfPrincipals `json:"accounts.google.com:sub"`
			AzureADIss                          ListOfPrincipals `json:"http://sts.windows.net/tenant-id/iss"` // Azure AD specific
			AzureADSub                          ListOfPrincipals `json:"sub"`                                  // Common among OIDC providers
			PingClientId                        string           `json:"pingidentity.com:client_id"`
			GoogleWorkspaceAud                  string           `json:"workspace.google.com:aud"`
			GoogleWorkspaceSub                  ListOfPrincipals `json:"workspace.google.com:sub"`
			CircleCIAud                         ListOfPrincipals `json:"CircleCIAud"`
			CircleCISub                         ListOfPrincipals `json:"CircleCISub"`
			// Add other provider-specific claims here
		} `json:"StringEquals"`
		StringLike struct {
			TokenActionsGithubusercontentComSub ListOfPrincipals `json:"token.actions.githubusercontent.com:sub"`
			TokenActionsGithubusercontentComAud string           `json:"token.actions.githubusercontent.com:aud"`
			OidcEksSub                          ListOfPrincipals `json:"OidcEksSub"`
			OidcEksAud                          string           `json:"OidcEksAud"`
			TerraformAud                        string           `json:"app.terraform.io:aud"` // Terraform Cloud specific
			TerraformSub                        ListOfPrincipals `json:"app.terraform.io:sub"` // Terraform Cloud specific
			GCPAud                              string           `json:"accounts.google.com:aud"`
			GCPSub                              ListOfPrincipals `json:"accounts.google.com:sub"`
			AzureADIss                          ListOfPrincipals `json:"http://sts.windows.net/tenant-id/iss"` // Azure AD specific
			AzureADSub                          ListOfPrincipals `json:"sub"`                                  // Common among OIDC providers
			PingClientId                        string           `json:"pingidentity.com:client_id"`
			GoogleWorkspaceAud                  string           `json:"workspace.google.com:aud"`
			GoogleWorkspaceSub                  ListOfPrincipals `json:"workspace.google.com:sub"`
			CircleCIAud                         ListOfPrincipals `json:"CircleCIAud"`
			CircleCISub                         ListOfPrincipals `json:"CircleCISub"`
			// Add patterns for provider-specific claims that support wildcards or partial matches
		} `json:"StringLike"`
		ForAnyValueStringLike struct {
			CognitoAMR string `json:"cognito-identity.amazonaws.com:amr"`
			//Auth0Amr   ListOfPrincipals `json:"Auth0Amr"`
			// This section can be extended with any-value-like conditions for other providers if they support such conditions
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
	//auth0Pattern := `"auth0.com\:`
	circleCIPattern := `"oidc.circleci.com/org/[a-zA-Z0-9\-]+:`
	var reEKSSub = regexp.MustCompile(pattern2 + pattern + "sub")
	var reEKSAud = regexp.MustCompile(pattern2 + pattern + "aud")
	//var reAuth0Sub = regexp.MustCompile(auth0Pattern + "amr")
	var reCircleCIAud = regexp.MustCompile(circleCIPattern + "aud")
	var reCircleCISSub = regexp.MustCompile(circleCIPattern + "sub")

	document = reEKSSub.ReplaceAllString(document, "\"OidcEksSub")
	document = reEKSAud.ReplaceAllString(document, "\"OidcEksAud")
	//document = reAuth0Sub.ReplaceAllString(document, "\"Auth0Amr")
	document = reCircleCIAud.ReplaceAllString(document, "\"CircleCIAud")
	document = reCircleCISSub.ReplaceAllString(document, "\"CircleCISub")

	var parsedDocumentToJSON TrustPolicyDocument
	_ = json.Unmarshal([]byte(document), &parsedDocumentToJSON)
	return parsedDocumentToJSON, nil
}
