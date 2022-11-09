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

	// Mocked functions to simulate Azure responses
	GetResourceGroupsPerSub = func(subscriptionID string) []resources.Group {
		switch subscriptionID {
		case "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAA":
			return []resources.Group{
				{Name: ptr.String("A1")},
				{Name: ptr.String("A2")},
			}
		case "BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBB":
			return []resources.Group{
				{Name: ptr.String("B3")},
				{Name: ptr.String("B4")},
			}
		case "CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCC":
			return []resources.Group{
				{Name: ptr.String("C5")},
				{Name: ptr.String("C6")},
			}
		default:
			return []resources.Group{}
		}
	}
	GetSubscriptions = func() []subscriptions.Subscription {
		return []subscriptions.Subscription{
			{SubscriptionID: ptr.String("AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAA")},
			{SubscriptionID: ptr.String("BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBB")},
			{SubscriptionID: ptr.String("CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCC")},
		}
	}

	// Test case parameters
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

	// Mocked functions to simulate Azure responses
	GetResourceGroupsPerSub = func(subscriptionID string) []resources.Group {
		switch subscriptionID {
		case "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAA":
			return []resources.Group{
				{Name: ptr.String("A1")},
				{Name: ptr.String("A2")},
			}
		case "BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBB":
			return []resources.Group{
				{Name: ptr.String("B3")},
				{Name: ptr.String("B4")},
			}
		case "CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCC":
			return []resources.Group{
				{Name: ptr.String("C5")},
				{Name: ptr.String("C6")},
			}
		default:
			return []resources.Group{}
		}
	}
	GetSubscriptions = func() []subscriptions.Subscription {
		return []subscriptions.Subscription{
			{SubscriptionID: ptr.String("AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAA")},
			{SubscriptionID: ptr.String("BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBB")},
			{SubscriptionID: ptr.String("CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCC")},
		}
	}

	// Test case parameters
	subTests := map[string]string{
		"A1": "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAA",
		"B4": "BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBB",
		"C6": "CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCC",
	}
	for inputRG, expectedSub := range subTests {
		sub := GetSubscriptionForResourceGroup(inputRG)
		if ptr.ToString(sub.SubscriptionID) != expectedSub {
			log.Fatalf("expected %s, got %s", expectedSub, ptr.ToString(sub.SubscriptionID))
		}
		fmt.Printf("subscription %s found for RG %s\n", expectedSub, inputRG)
	}

}

// Requires Az CLI Authentication to pass
func TestMapResourceGroups(t *testing.T) {
	t.Skip()
	fmt.Println("[test case] mapResourceGroups")
	fmt.Println("Subscription, ResourceGroup")
	subs := GetSubscriptions()
	for _, sub := range subs {
		rgsMapped := GetResourceGroupsPerSub(ptr.ToString(sub.SubscriptionID))
		for _, rg := range rgsMapped {
			fmt.Printf("%s, %s", ptr.ToString(sub.SubscriptionID), ptr.ToString(rg.Name))
		}
	}
	fmt.Println()
}
