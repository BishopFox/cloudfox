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
	subtests := []struct {
		name                string
		mockedUserSelection *string
		expectedScope       []scopeElement
		// These mocked functions below are wrapping Azure API calls
		getResourceGroupsPerSub func(subscription string) ([]resources.Group, error)
		getSubscriptions        func() ([]subscriptions.Subscription, error)
	}{
		{
			name:                "subtest 1",
			mockedUserSelection: ptr.String("1,2,6"),
			expectedScope: []scopeElement{
				{Rg: resources.Group{Name: ptr.String("A1")}},
				{Rg: resources.Group{Name: ptr.String("A2")}},
				{Rg: resources.Group{Name: ptr.String("C6")}},
			},
			getResourceGroupsPerSub: func(subscription string) ([]resources.Group, error) {
				switch subscription {
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
					return []resources.Group{}, fmt.Errorf("no resource groups found for subscription: %s", subscription)
				}
			},
			getSubscriptions: func() ([]subscriptions.Subscription, error) {
				return []subscriptions.Subscription{
					{SubscriptionID: ptr.String("AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAA")},
					{SubscriptionID: ptr.String("BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBB")},
					{SubscriptionID: ptr.String("CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCC")},
				}, nil
			},
		},
	}
	fmt.Println()
	fmt.Println("[test case] Scope Selection Interactive Menu")
	for _, subtest := range subtests {
		t.Run(subtest.name, func(t *testing.T) {
			getResourceGroupsPerSubM = subtest.getResourceGroupsPerSub
			getSubscriptionsM = subtest.getSubscriptions
			for i, scopeElement := range ScopeSelection(subtest.mockedUserSelection) {
				if ptr.ToString(scopeElement.Rg.Name) != ptr.ToString(subtest.expectedScope[i].Rg.Name) {
					log.Fatalf(
						"[%s] Selection mismatch: got %s, expected: %s",
						subtest.name,
						ptr.ToString(scopeElement.Rg.Name),
						ptr.ToString(subtest.expectedScope[i].Rg.Name))
				}
				fmt.Printf(
					"[%s] mocked input %d matches expected RG %s\n",
					subtest.name,
					scopeElement.menuIndex,
					ptr.ToString(subtest.expectedScope[i].Rg.Name))
			}
		})
	}
	fmt.Println()
}

// Requires Az CLI Authentication to pass
func TestMapResourceGroups(t *testing.T) {
	t.Skip()
	fmt.Println()
	subs, err := getSubscriptionsM()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("[test case] mapResourceGroups")
	fmt.Println("Subscription, ResourceGroup")
	for _, sub := range subs {
		rgsMapped, err := getResourceGroupsPerSubM(ptr.ToString(sub.ID))
		if err != nil {
			log.Fatal(err)
		}
		for _, rg := range rgsMapped {
			fmt.Printf("%s, %s", ptr.ToString(sub.ID), ptr.ToString(rg.Name))
		}
	}
	fmt.Println()
}
