package azure

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/BishopFox/cloudfox/globals"
)

// Internal representation of a vault
type AzureVault struct {
	Tenant        string
	Subscription  string
	VaultName     string
	ResourceGroup string
	Region        string
	Tags          map[string]string
}

type CertificateInfo struct {
	Name       string
	Enabled    bool
	ExpiresOn  string
	Issuer     string
	Subject    string
	Thumbprint string
}

// Returns a slice of AzureVault structs for a subscription
//func GetKeyVaultsPerSubscription(ctx context.Context, cred azcore.TokenCredential, subID string) ([]AzureVault, error) {
//	clientFactory, err := armkeyvault.NewClientFactory(subID, cred, nil)
//	if err != nil {
//		return nil, err
//	}
//
//	vaultsPager := clientFactory.NewVaultsClient().NewListBySubscriptionPager(nil)
//	var vaults []AzureVault
//
//	for vaultsPager.More() {
//		page, err := vaultsPager.NextPage(ctx)
//		if err != nil {
//			return vaults, err
//		}
//
//		for _, v := range page.Value {
//			if v == nil || v.Properties == nil || v.Properties.VaultURI == nil {
//				continue
//			}
//
//			resourceGroup := SafeString(GetResourceGroupNameFromID(*v.ID))
//			if resourceGroup == "" {
//				resourceGroup = "Unknown"
//			}
//
//			vaults = append(vaults, AzureVault{
//				Subscription:  subID,
//				VaultName:     *v.Name,
//				ResourceGroup: resourceGroup,
//				Region:        SafeString(*v.Location),
//				Tags:          convertTags(v.Tags),
//			})
//		}
//	}
//
//	return vaults, nil
//}

func GetKeyVaultsPerResourceGroup(ctx context.Context, session *SafeSession, subID, rgName string) ([]AzureVault, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token for subscription %s: %v", subID, err)
	}

	cred := &StaticTokenCredential{Token: token}

	// Pass the wrapped token to ARM Key Vault client
	clientFactory, err := armkeyvault.NewClientFactory(subID, cred, nil)
	if err != nil {
		return nil, err
	}

	vaultsPager := clientFactory.NewVaultsClient().NewListByResourceGroupPager(rgName, nil)
	var vaults []AzureVault

	for vaultsPager.More() {
		page, err := vaultsPager.NextPage(ctx)
		if err != nil {
			return vaults, err
		}

		for _, v := range page.Value {
			if v == nil || v.Properties == nil || v.Properties.VaultURI == nil {
				continue
			}

			resourceGroup := rgName
			if resourceGroup == "" {
				resourceGroup = "Unknown"
			}

			vaults = append(vaults, AzureVault{
				Subscription:  subID,
				VaultName:     SafeString(*v.Name),
				ResourceGroup: resourceGroup,
				Region:        SafeString(*v.Location),
				Tags:          convertTags(v.Tags),
			})
		}
	}

	return vaults, nil
}

// pager := client.NewListCertificatePropertiesPager(nil)
func GetCertificatesPerKeyVault(ctx context.Context, session *SafeSession, vaultURI string) ([]CertificateInfo, error) {
	// Use Key Vault data-plane scope
	token, err := session.GetTokenForResource(globals.CommonScopes[2] + ".default")
	if err != nil {
		return nil, fmt.Errorf("failed to get Key Vault token: %v", err)
	}

	cred := &StaticTokenCredential{Token: token}

	certClient, err := azcertificates.NewClient(vaultURI, cred, nil)
	if err != nil {
		return nil, err
	}

	var certs []CertificateInfo

	pager := certClient.NewListCertificatePropertiesPager(nil)

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return certs, err
		}

		for _, certProp := range page.Value {
			if certProp.ID == nil {
				continue
			}

			// Extract certificate name from ID
			idParts := strings.Split(string(*certProp.ID), "/")
			if len(idParts) < 5 {
				continue
			}
			certName := idParts[4]

			// Get the latest version of the certificate
			certResp, err := certClient.GetCertificate(ctx, certName, "", nil)
			if err != nil {
				continue
			}

			thumbprint := ""
			if certResp.X509Thumbprint != nil {
				thumbprint = fmt.Sprintf("%x", certResp.X509Thumbprint)
			}

			// Access fields through Properties.Attributes
			enabled := false
			if certResp.Attributes != nil && certResp.Attributes.Enabled != nil {
				enabled = *certResp.Attributes.Enabled
			}

			expiresOn := ""
			if certResp.Attributes != nil && certResp.Attributes.Expires != nil {
				expiresOn = certResp.Attributes.Expires.Format(time.RFC3339)
			}

			// Access issuer through Policy.IssuerParameters
			issuer := ""
			if certResp.Policy != nil && certResp.Policy.IssuerParameters != nil && certResp.Policy.IssuerParameters.Name != nil {
				issuer = *certResp.Policy.IssuerParameters.Name
			}

			// Access subject through Policy.X509CertificateProperties
			subject := ""
			if certResp.Policy != nil && certResp.Policy.X509CertificateProperties != nil && certResp.Policy.X509CertificateProperties.Subject != nil {
				subject = *certResp.Policy.X509CertificateProperties.Subject
			}

			certs = append(certs, CertificateInfo{
				Name:       certName,
				Enabled:    enabled,
				ExpiresOn:  expiresOn,
				Issuer:     issuer,
				Subject:    subject,
				Thumbprint: thumbprint,
			})
		}
	}

	return certs, nil
}

func convertTags(tags map[string]*string) map[string]string {
	res := make(map[string]string)
	for k, v := range tags {
		if v != nil {
			res[k] = *v
		} else {
			res[k] = ""
		}
	}
	return res
}
