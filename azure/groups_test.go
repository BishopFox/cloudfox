package azure

import (
	"fmt"
	"log"
	"testing"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/resources"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/subscriptions"
	"github.com/aws/smithy-go/ptr"
)

func TestScopeSelection(t *testing.T) {
	fmt.Println()
	fmt.Println("[test case] Scope Selection Interactive Menu")

	GetResourceGroupsPerSub = func(subscriptionID string) ([]resources.Group, error) {
		switch subscriptionID {
		case "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAA":
			return []resources.Group{
				{Name: ptr.String("A1")},
				{Name: ptr.String("A2")},
			}, nil
		case "BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBB":
			return []resources.Group{
				{Name: ptr.String("B3")},
				{Name: ptr.String("B4")},
			}, nil
		case "CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCC":
			return []resources.Group{
				{Name: ptr.String("C5")},
				{Name: ptr.String("C6")},
			}, nil
		default:
			return []resources.Group{}, fmt.Errorf("no resource groups found for subscription: %s", subscriptionID)
		}
	}
	GetSubscriptions = func() ([]subscriptions.Subscription, error) {
		return []subscriptions.Subscription{
			{SubscriptionID: ptr.String("AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAA")},
			{SubscriptionID: ptr.String("BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBB")},
			{SubscriptionID: ptr.String("CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCC")},
		}, nil
	}

	mockedUserSelection := ptr.String("1,2,6")
	expectedScope := []scopeElement{
		{Rg: resources.Group{Name: ptr.String("A1")}},
		{Rg: resources.Group{Name: ptr.String("A2")}},
		{Rg: resources.Group{Name: ptr.String("C6")}},
	}

	for i, scopeElement := range ScopeSelection(mockedUserSelection) {
		if ptr.ToString(scopeElement.Rg.Name) != ptr.ToString(expectedScope[i].Rg.Name) {
			log.Fatalf(
				"expected %s, got %s",
				ptr.ToString(expectedScope[i].Rg.Name),
				ptr.ToString(scopeElement.Rg.Name))
		}
		fmt.Printf(
			"mocked user input %d matches expected RG %s\n",
			scopeElement.menuIndex,
			ptr.ToString(expectedScope[i].Rg.Name))
	}
}

func TestGetSubscriptionForResourceGroup(t *testing.T) {
	fmt.Println()
	fmt.Println("[test case] GetSubscriptionForResourceGroup Function")

	GetResourceGroupsPerSub = func(subscriptionID string) ([]resources.Group, error) {
		switch subscriptionID {
		case "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAA":
			return []resources.Group{
				{Name: ptr.String("A1")},
				{Name: ptr.String("A2")},
			}, nil
		case "BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBB":
			return []resources.Group{
				{Name: ptr.String("B3")},
				{Name: ptr.String("B4")},
			}, nil
		case "CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCC":
			return []resources.Group{
				{Name: ptr.String("C5")},
				{Name: ptr.String("C6")},
			}, nil
		default:
			return []resources.Group{}, fmt.Errorf("no resource groups found for subscription: %s", subscriptionID)
		}
	}
	GetSubscriptions = func() ([]subscriptions.Subscription, error) {
		return []subscriptions.Subscription{
			{SubscriptionID: ptr.String("AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAA")},
			{SubscriptionID: ptr.String("BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBB")},
			{SubscriptionID: ptr.String("CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCC")},
		}, nil
	}

	subTests := map[string]string{
		"A1": "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAA",
		"B4": "BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBB",
		"C6": "CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCC",
	}

	for inputRG, expectedSub := range subTests {
		sub, err := GetSubscriptionForResourceGroup(inputRG)
		if err != nil {
			log.Fatalf("can't find subscription for resource group %s", inputRG)
		}
		if ptr.ToString(sub.SubscriptionID) != expectedSub {
			log.Fatalf("expected %s, got %s", expectedSub, ptr.ToString(sub.SubscriptionID))
		}
		fmt.Printf("subscription %s found for RG %s\n", expectedSub, inputRG)
	}

}

// Requires Az CLI Authentication to pass
func TestMapResourceGroups(t *testing.T) {
	t.Skip()
	fmt.Println()
	subs, err := GetSubscriptions()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("[test case] mapResourceGroups")
	fmt.Println("Subscription, ResourceGroup")
	for _, sub := range subs {
		rgsMapped, err := GetResourceGroupsPerSub(ptr.ToString(sub.SubscriptionID))
		if err != nil {
			log.Fatal(err)
		}
		for _, rg := range rgsMapped {
			fmt.Printf("%s, %s", ptr.ToString(sub.SubscriptionID), ptr.ToString(rg.Name))
		}
	}
	fmt.Println()
}
