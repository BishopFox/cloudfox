package models

type Role struct {
	RoleARN                  string
	RoleName                 string
	TrustDocument            string
	TrustedPrincipal         string
	TrustedService           string
	TrustedFederatedProvider string
	TrustedFederatedSubject  string
}
