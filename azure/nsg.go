package azure

import (
	"fmt"
	"context"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/network/mgmt/network"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/subscriptions"
)

type AzNSGModule struct {
	AzClient            *internal.AzureClient
	getNSGData          func(string, *subscriptions.Subscription) error
}


func (m *AzNSGModule) AzNSGCommand(data string) error {

	if data == "links" {
		m.AzNSGLinksCommand()
	} else if data == "rules" {
		m.AzNSGRulesCommand()
	} else {
		return fmt.Errorf("Invalid data selection for NSG")
	}

	return nil
}

func (m *AzNSGModule) getNSGInfoPerSubscription(tenantSlug string, AzSubscription *subscriptions.Subscription) error {
	var err error

	err = m.getNSGData(tenantSlug, AzSubscription)
	if err != nil {
		return err
	}
	return nil
}

func (m *AzNSGModule) getNSG(subscriptionID string) (*[]network.SecurityGroup, error) {
	nsgClient := internal.GetNSGClient(subscriptionID)
	var networkSecurityGroups []network.SecurityGroup
	for page, err := nsgClient.ListAll(context.TODO()); page.NotDone(); page.Next() {
		if err != nil {
			return nil, fmt.Errorf("could not get network security groups for subscription")
		}
		networkSecurityGroups = append(networkSecurityGroups, page.Values()...)
	}
	return &networkSecurityGroups, nil
}
