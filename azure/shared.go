package azure

import "github.com/aws/smithy-go/ptr"

// function that takes a subscription ID and returns the DisplayName of the subscription
func GetSubscriptionName(subscriptionID string) *string {
	subs := GetSubscriptions()
	for _, s := range subs {
		if ptr.ToString(s.SubscriptionID) == subscriptionID {
			return s.DisplayName
		}
	}
	return nil
}

type AzSubsriptionType struct {
	SubscriptionID string
	DisplayName    string
}

// function that determins if AzSubsriptionType is a subscritpion ID or a subscription display name and returns the AzSubsriptionType struct with both populated
func PopulateSubsriptionType(subscription string) AzSubsriptionType {
	subs := GetSubscriptions()
	for _, s := range subs {
		if ptr.ToString(s.SubscriptionID) == subscription {
			return AzSubsriptionType{SubscriptionID: subscription, DisplayName: ptr.ToString(s.DisplayName)}
		}
		if ptr.ToString(s.DisplayName) == subscription {
			return AzSubsriptionType{SubscriptionID: ptr.ToString(s.SubscriptionID), DisplayName: subscription}
		}
	}
	return AzSubsriptionType{}
}
