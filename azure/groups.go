package azure

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/resources"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/subscriptions"
	"github.com/BishopFox/cloudfox/constants"
	"github.com/BishopFox/cloudfox/utils"
	"github.com/aws/smithy-go/ptr"
	"github.com/fatih/color"
)

// userInput = nil will prompt interactive menu for RG selection.
// The userInput argument is used to toggle the interactive menu (useful for unit tests).
func ScopeSelection(userInput *string) []scopeElement {
	fmt.Printf("[%s] Fetching available resource groups from Az CLI sessions...\n", color.CyanString(constants.AZ_INTERACTIVE_MENU_MODULE_NAME))
	var results []scopeElement

	availableScope := getAvailableScope()
	printAvailableScope(availableScope)

	if userInput == nil {
		var input string
		fmt.Printf("[%s] Please select resource groups numbers to analyze. Separate selection by commas (e.g. '1,2,3').\n", color.CyanString(constants.AZ_INTERACTIVE_MENU_MODULE_NAME))
		fmt.Printf("[%s]> ", color.CyanString(constants.AZ_INTERACTIVE_MENU_MODULE_NAME))
		fmt.Scanln(&input)
		userInput = ptr.String(input)
	}

	for _, scopeItem := range availableScope {
		for _, userSelection := range strings.Split(ptr.ToString(userInput), ",") {
			userInputInt, err := strconv.Atoi(userSelection)
			if err != nil {
				log.Fatalln("Error: Invalid resource group selection.")
			}
			if userInputInt == scopeItem.menuIndex {
				results = append(
					results,
					scopeElement{
						menuIndex:          scopeItem.menuIndex,
						includeInExecution: true,
						Sub:                scopeItem.Sub,
						Rg:                 scopeItem.Rg})
			}
		}
	}

	return results
}

func printAvailableScope(availableScope []scopeElement) {
	var tableBody [][]string

	for _, scopeItem := range availableScope {
		tableBody = append(
			tableBody,
			[]string{
				strconv.Itoa(scopeItem.menuIndex),
				ptr.ToString(scopeItem.Sub.SubscriptionID),
				ptr.ToString(scopeItem.Rg.Name)})
	}
	sort.Slice(
		tableBody,
		func(i int, j int) bool {
			return tableBody[i][1] < tableBody[j][1]
		},
	)
	utils.PrintTableToScreen([]string{"Number", "Subscription", "Resource Group Name"}, tableBody)
}

type scopeElement struct {
	// Use for user selection in interactive mode.
	menuIndex int
	// True will cause CloudFox to enumerate the resource group.
	includeInExecution bool
	Sub                subscriptions.Subscription
	Rg                 resources.Group
}

func getAvailableScope() []scopeElement {
	var index int
	var results []scopeElement
	subs := GetSubscriptions()
	for _, sub := range subs {
		rgs := GetResourceGroupsPerSub(ptr.ToString(sub.SubscriptionID))

		for _, rg := range rgs {
			index++
			results = append(results, scopeElement{menuIndex: index, Sub: sub, Rg: rg})
		}
	}
	return results
}

var GetResourceGroupsPerSub = getResourceGroupsPerSub

func getResourceGroupsPerSub(subscriptionID string) []resources.Group {
	var results []resources.Group
	rgClient := utils.GetResourceGroupsClient(subscriptionID)

	for page, err := rgClient.List(context.TODO(), "", nil); page.NotDone(); err = page.Next() {
		if err != nil {
			log.Fatalf("error reading resource groups for subscription %s", subscriptionID)
		}
		results = append(results, page.Values()...)
	}
	return results
}

var GetSubscriptions = getSubscriptions

func getSubscriptions() []subscriptions.Subscription {
	var results []subscriptions.Subscription
	subsClient := utils.GetSubscriptionsClient()
	for page, err := subsClient.List(context.TODO()); page.NotDone(); err = page.Next() {
		if err != nil {
			log.Fatal("could not get subscriptions for active session")
		}
		results = append(results, page.Values()...)
	}
	return results
}

func GetSubscriptionForResourceGroup(resourceGroupName string) subscriptions.Subscription {
	subs := GetSubscriptions()
	for _, sub := range subs {
		rgs := GetResourceGroupsPerSub(ptr.ToString(sub.SubscriptionID))
		for _, rg := range rgs {
			if ptr.ToString(rg.Name) == resourceGroupName {
				return sub
			}
		}
	}
	return subscriptions.Subscription{}
}
