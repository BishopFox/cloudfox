package azure

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/subscriptions"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/smithy-go/ptr"
)

type TenantInfo struct {
	ID            *string
	DefaultDomain *string
	Subscriptions []SubsriptionInfo
}

type SubsriptionInfo struct {
	Subscription subscriptions.Subscription
	ID           string
	Name         string
}

// function that takes a subscription ID and returns the DisplayName of the subscription
func GetSubscriptionNameFromID(subscriptionID string) *string {
	subs := GetSubscriptions()
	for _, s := range subs {
		if ptr.ToString(s.SubscriptionID) == subscriptionID {
			return s.DisplayName
		}
	}
	return nil
}

func GetSubscriptionIDFromName(subscriptionName string) *string {
	subs := GetSubscriptions()
	for _, s := range subs {
		if ptr.ToString(s.DisplayName) == subscriptionName {
			return s.SubscriptionID
		}
	}
	return nil
}

// function that takes the AzSubscription string and first checks to see if it is a valid subscription ID, and if not, checks to see if it is a valid subscription display name. It then returns the subscription ID
func GetSubscriptionID(subscription string) *string {
	subs := GetSubscriptions()
	for _, s := range subs {
		if ptr.ToString(s.SubscriptionID) == subscription {
			return s.SubscriptionID
		}
		if ptr.ToString(s.DisplayName) == subscription {
			return s.SubscriptionID
		}
	}
	return nil
}

func GetSubscriptionsPerTenantID(tenantID string) []subscriptions.Subscription {
	subs := GetSubscriptions()
	var results []subscriptions.Subscription
	for _, s := range subs {
		if ptr.ToString(s.TenantID) == tenantID {
			results = append(results, s)
		}
	}
	return results
}

func GetTenantIDPerSubscription(subscriptionID string) *string {
	subs := GetSubscriptions()
	for _, s := range subs {
		if ptr.ToString(s.SubscriptionID) == subscriptionID {
			return s.TenantID
		}
		if ptr.ToString(s.DisplayName) == subscriptionID {
			return s.TenantID
		}
	}
	return nil
}

// function that determines if AzSubsriptionType is a subscription ID or a subscription display name and returns the AzSubsriptionType struct with both populated
func PopulateSubsriptionType(subscription string) SubsriptionInfo {
	subs := GetSubscriptions()
	for _, s := range subs {
		if ptr.ToString(s.SubscriptionID) == subscription {
			return SubsriptionInfo{ID: subscription, Name: ptr.ToString(s.DisplayName)}
		}
		if ptr.ToString(s.DisplayName) == subscription {
			return SubsriptionInfo{ID: ptr.ToString(s.SubscriptionID), Name: subscription}
		}
	}
	return SubsriptionInfo{}
}

func GetDefaultDomainFromTenantID(tenantID string) (string, error) {
	// Get the client using the function
	client := internal.GetgraphRbacClient(tenantID)

	// List domains
	domainList, err := client.List(context.Background(), "")
	if err != nil {
		return "", err
	}

	for _, domain := range *domainList.Value {
		if *domain.IsDefault {
			primaryDomain := *domain.Name
			return primaryDomain, nil
		}
	}

	return "", fmt.Errorf("No default domain found")
}

func populateTenant(tenantID string) TenantInfo {

	for _, t := range getTenants() {
		if ptr.ToString(t.TenantID) == tenantID || ptr.ToString(t.DefaultDomain) == tenantID {
			var subscriptions []SubsriptionInfo
			for _, s := range GetSubscriptionsPerTenantID(ptr.ToString(t.ID)) {
				subscriptions = append(subscriptions, SubsriptionInfo{Subscription: s, ID: ptr.ToString(s.SubscriptionID), Name: ptr.ToString(s.DisplayName)})
			}
			return TenantInfo{ID: t.TenantID, DefaultDomain: t.DefaultDomain, Subscriptions: subscriptions}
		}
	}
	return TenantInfo{}
}
