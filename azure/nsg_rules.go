package azure

import (
	"fmt"
	"path/filepath"
	"context"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/smithy-go/ptr"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/subscriptions"
)


func (m *AzNSGModule) AzNSGRulesCommand() error {

	m.getNSGData = m.getNSGRulesData

	if len(m.AzClient.AzTenants) > 0 {
		for _, AzTenant := range m.AzClient.AzTenants {
			m.log.Infof([]string{"rules"}, "Enumerating Network Security Group rules for tenant %s (%s)", ptr.ToString(AzTenant.DefaultDomain), ptr.ToString(AzTenant.TenantID))
			for _, AzTenant := range m.AzClient.AzTenants {
				// cloudfox azure nsg-rules --tenant [TENANT_ID | PRIMARY_DOMAIN]
				for _, AzSubscription := range GetSubscriptionsPerTenantID(ptr.ToString(AzTenant.TenantID)) {
					m.runNSGRulesCommandForSingleSubcription(*AzTenant.DefaultDomain, &AzSubscription)
				}
			}
		}
	} else {
		for tenantSlug, AzSubscriptions := range m.AzClient.AzSubscriptionsAlt {
			for _, AzSubscription := range AzSubscriptions {
				m.runNSGRulesCommandForSingleSubcription(tenantSlug, AzSubscription)
			}
		}
	}

	return nil
}

func (m *AzNSGModule) runNSGRulesCommandForSingleSubcription(tenantSlug string, AzSubscription *subscriptions.Subscription) error {
	var err error

	m.log.Infof([]string{"rules"}, "Enumerating Network Security Groups rules for subscription %s (%s)", *AzSubscription.DisplayName, *AzSubscription.SubscriptionID)
	err = m.getNSGInfoPerSubscription(tenantSlug, AzSubscription)
	if err != nil {
		return err
	}

	return nil

}

func (m *AzNSGModule) getNSGRulesData(tenantSlug string, AzSubscription *subscriptions.Subscription) error {
	tableHeader := []string{"Name", "Rule Type", "Protocol", "Source", "Destination", "Destination port", "Action", "Description"}
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
		networkSecurityGroup, err = nsgClient.Get(context.TODO(), resource.ResourceGroup, resource.ResourceName, "")
		if err != nil {
			m.log.Warnf([]string{"rules"}, "Failed to enumerate rules for NSG %s", *networkSecurityGroup.Name)
			continue
		} else {
			m.log.Infof([]string{"rules"}, "Enumerating rules for NSG %s", *networkSecurityGroup.Name)
		}
		for _, securityRule := range *networkSecurityGroup.SecurityRules {
			tableBody = append(tableBody,
				[]string{
					*securityRule.Name,
					fmt.Sprintf("%v", securityRule.SecurityRulePropertiesFormat.Direction),
					fmt.Sprintf("%v", securityRule.SecurityRulePropertiesFormat.Protocol),
					getSourceFromSecurityGroupRule(&securityRule),
					getDestinationFromSecurityGroupRule(&securityRule),
					stringAndArrayToString(securityRule.SecurityRulePropertiesFormat.DestinationPortRange,
						securityRule.SecurityRulePropertiesFormat.DestinationPortRanges),
					m.colorRule(fmt.Sprintf("%v", securityRule.SecurityRulePropertiesFormat.Access)),
					ptr.ToString(securityRule.Description),
				},
			)
		}

		// set up table vars
		o.PrefixIdentifier = fmt.Sprintf("%s", *AzSubscription.DisplayName)
		o.Table.DirectoryName = filepath.Join(m.AzClient.AzOutputDirectory, globals.CLOUDFOX_BASE_DIRECTORY, globals.AZ_DIR_BASE, tenantSlug, *AzSubscription.DisplayName)
		o.Table.TableFiles = append(o.Table.TableFiles,
			internal.TableFile{
				Header: tableHeader,
				Body:   tableBody,
				Name:   fmt.Sprintf("%s-%s", globals.AZ_NSG_RULES_MODULE_NAME, *networkSecurityGroup.Name)})

		if tableBody != nil {
			o.WriteFullOutput(o.Table.TableFiles, nil)
		}
	}
	return nil
}

func (m *AzNSGModule) colorRule(action string) string {
	if action == "Allow" {
		return m.log.Green(action)
	} else if action == "Deny" {
		return m.log.Red(action)
	} else {
		return action
	}
}
