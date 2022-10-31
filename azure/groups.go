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
	"github.com/BishopFox/cloudfox/utils"
	"github.com/aws/smithy-go/ptr"
)

// userInput = nil will prompt interactive menu for RG selection.
// The userInput argument is used to toggle the interactive menu (useful for unit tests).
func ScopeSelection(userInput *string) []scopeElement {
	fmt.Println("Fetching available resource groups from Az CLI sessions...")
	var results []scopeElement

	availableScope := getAvailableScope()
	printAvailableScope(availableScope)

	if userInput == nil {
		var input string
		fmt.Println("Please select resource groups numbers to analyze. Separate selection by commas (e.g. '1,2,3').")
		fmt.Printf("Selection: ")
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
	subs, err := getSubscriptionsM()

	if err != nil {
		log.Fatalf("error getting available scope from Azure CLI: %s", err)
	}
	for _, sub := range subs {
		rgs, err := getResourceGroupsPerSubM(ptr.ToString(sub.SubscriptionID))
		if err != nil {
			log.Fatalf("error getting available scope from Azure CLI: %s", err)
		}

		for _, rg := range rgs {
			index++
			results = append(results, scopeElement{menuIndex: index, Sub: sub, Rg: rg})
		}
	}
	return results
}

var getResourceGroupsPerSubM = getResourceGroupsPerSub

func getResourceGroupsPerSub(subscription string) ([]resources.Group, error) {
	var results []resources.Group
	rgClient := utils.GetResourceGroupsClient(subscription)

	for page, err := rgClient.List(context.TODO(), "", nil); page.NotDone(); err = page.Next() {
		if err != nil {
			return results, err
		}
		results = append(results, page.Values()...)
	}
	return results, nil
}

var getSubscriptionsM = getSubscriptions

func getSubscriptions() ([]subscriptions.Subscription, error) {
	var results []subscriptions.Subscription
	subsClient := utils.GetSubscriptionsClient()
	for page, err := subsClient.List(context.TODO()); page.NotDone(); err = page.Next() {
		if err != nil {
			return results, err
		}
		results = append(results, page.Values()...)
	}
	return results, nil
}
