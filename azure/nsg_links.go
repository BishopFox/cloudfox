package azure

import (
	"context"
	"strings"
	"fmt"
	"path/filepath"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/smithy-go/ptr"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/network/mgmt/network"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/subscriptions"
	"github.com/Azure/go-autorest/autorest/azure"
)

func (m *AzNSGModule) AzNSGLinksCommand() error {

	m.getNSGData = m.getNSGLinksData

	if len(m.AzClient.AzTenants) > 0 {
		for _, AzTenant := range m.AzClient.AzTenants {
			m.Log.Infof([]string{"links"}, "Enumerating Network Security Group links for tenant %s (%s)", ptr.ToString(AzTenant.DefaultDomain), ptr.ToString(AzTenant.TenantID))
			for _, AzTenant := range m.AzClient.AzTenants {
				for _, AzSubscription := range GetSubscriptionsPerTenantID(ptr.ToString(AzTenant.TenantID)) {
					m.runNSGLinksCommandForSingleSubcription(*AzTenant.DefaultDomain, &AzSubscription)
				}
			}
		}
	} else {
		for tenantSlug, AzSubscriptions := range m.AzClient.AzSubscriptionsAlt {
			for _, AzSubscription := range AzSubscriptions {
				m.runNSGLinksCommandForSingleSubcription(tenantSlug, AzSubscription)
			}
		}
	}
	return nil
}

func (m *AzNSGModule) runNSGLinksCommandForSingleSubcription(tenantSlug string, AzSubscription *subscriptions.Subscription) error {
	var err error

	m.Log.Infof([]string{"links"}, "Enumerating Network Security Groups links for subscription %s (%s)", *AzSubscription.DisplayName, *AzSubscription.SubscriptionID)
	err = m.getNSGInfoPerSubscription(tenantSlug, AzSubscription)
	if err != nil {
		return err
	}

	return nil
}


func (m *AzNSGModule) getNSGLinksData(tenantSlug string, AzSubscription *subscriptions.Subscription) error {
	tableHeader := []string{"Network Security Group", "Link Type", "Linked Name", "Link Target"}
	var tableBody [][]string
	networkSecurityGroups, err := m.getNSG(*AzSubscription.SubscriptionID)
	nsgClient := internal.GetNSGClient(*AzSubscription.SubscriptionID)
	//subnetsClient := internal.GetSubnetsClient(subscriptionID)
	if err != nil {
		return err
	}
	for _, networkSecurityGroup := range *networkSecurityGroups {
		tableBody = nil
		// setup logging client
		o := internal.OutputClient{
			Verbosity:     m.AzClient.AzVerbosity,
			CallingModule: globals.AZ_NSG_LINKS_MODULE_NAME,
			Table: internal.TableClient{
				Wrap: m.AzClient.AzWrapTable,
			},
		}

		var resource azure.Resource
		resource, err = azure.ParseResourceID(*networkSecurityGroup.ID)
		if err != nil {
			continue
		}
		networkSecurityGroup, err = nsgClient.Get(context.TODO(), resource.ResourceGroup, resource.ResourceName, "Subnets,NetworkInterfaces")
		if err != nil {
			m.Log.Warnf([]string{"links"}, "Failed to enumerate links for NSG %s", *networkSecurityGroup.Name)
			continue
		} else {
			m.Log.Infof([]string{"links"}, "Enumerating rules for NSG %s", *networkSecurityGroup.Name)
		}
		if networkSecurityGroup.Subnets != nil {
			for _, subnet := range *networkSecurityGroup.Subnets {
				var addressPrefixes []string
				if subnet.AddressPrefixes != nil {
					for _, prefix := range *subnet.AddressPrefixes {
						addressPrefixes = append(addressPrefixes, prefix)
					}
				}
				if subnet.AddressPrefix != nil {
					addressPrefixes = append(addressPrefixes, *subnet.AddressPrefix)
				}
				tableBody = append(tableBody,
					[]string{
						*networkSecurityGroup.Name,
						"Subnet",
						ptr.ToString(subnet.Name),
						strings.Join(addressPrefixes[:], "\n"),
					},
				)
			}
		}
		if networkSecurityGroup.NetworkInterfaces != nil {
			for _, networkInterface := range *networkSecurityGroup.NetworkInterfaces {
				tableBody = append(tableBody,
					[]string{
						*networkSecurityGroup.Name,
						"NIC",
						ptr.ToString(networkInterface.Name),
						strings.Join(internal.GetIPAddressesFromInterface(&networkInterface)[:], "\n"),
					},
				)
			}
		}

		// set up table vars
		o.PrefixIdentifier = fmt.Sprintf("%s", *AzSubscription.DisplayName)
		o.Table.DirectoryName = filepath.Join(m.AzClient.AzOutputDirectory, globals.CLOUDFOX_BASE_DIRECTORY, globals.AZ_DIR_BASE, tenantSlug, *AzSubscription.DisplayName)
		o.Table.TableFiles = append(o.Table.TableFiles,
			internal.TableFile{
				Header: tableHeader,
				Body:   tableBody,
				Name:   fmt.Sprintf("%s-%s", globals.AZ_NSG_LINKS_MODULE_NAME, *networkSecurityGroup.Name)})

		if tableBody != nil {
			o.WriteFullOutput(o.Table.TableFiles, nil)
		}
	}
	return nil
}


func stringAndArrayToString(value *string, values *[]string, separator string) string {
	var final string
	if value != nil {
		final = *value
	} else {
		final = ""
	}
	if len(*values) > 0 {
		if len(final) > 0 {
			final = fmt.Sprintf("%s%s%s", final, separator, strings.Join((*values)[:], separator))
		} else {
			final = strings.Join((*values)[:], separator)
		}
	}
	return final
}


func getSourceFromSecurityGroupRule(rule *network.SecurityRule) string {
	var final string
	final = stringAndArrayToString(rule.SecurityRulePropertiesFormat.SourceAddressPrefix, rule.SecurityRulePropertiesFormat.SourceAddressPrefixes, "\n")
	if rule.SecurityRulePropertiesFormat.SourceApplicationSecurityGroups != nil {
		for _, app := range *rule.SecurityRulePropertiesFormat.SourceApplicationSecurityGroups {
			resource, _ := azure.ParseResourceID(ptr.ToString(app.ID))
			final = fmt.Sprintf("%s\n%s", final, resource.ResourceName)
		}
	}
	return final
}

func getDestinationFromSecurityGroupRule(rule *network.SecurityRule) string {
	var final string
	final = stringAndArrayToString(rule.SecurityRulePropertiesFormat.DestinationAddressPrefix, rule.SecurityRulePropertiesFormat.DestinationAddressPrefixes, "\n")
	if rule.SecurityRulePropertiesFormat.DestinationApplicationSecurityGroups != nil {
		for _, app := range *rule.SecurityRulePropertiesFormat.DestinationApplicationSecurityGroups {
			resource, _ := azure.ParseResourceID(ptr.ToString(app.ID))
			final = fmt.Sprintf("%s\n%s", final, resource.ResourceName)
		}
	}
	return final
}
