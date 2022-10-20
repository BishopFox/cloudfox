package azure

import (
	"context"
	"log"
	"strconv"
	"strings"

	"github.com/BishopFox/cloudfox/utils"
	"github.com/aws/smithy-go/ptr"
)

func ScopeSelection(userInput string) []string {
	availableScope := getAvailableScopeM()
	printAvailableScope(availableScope)

	var userSelectedScope []string
	for _, input := range strings.Split(userInput, ",") {
		inputInt, err := strconv.Atoi(input)
		if err != nil {
			log.Fatalf("error during scope selection: %s", err)
		}
		userSelectedScope = append(userSelectedScope, availableScope[int(inputInt)])
	}
	return userSelectedScope
}

func printAvailableScope(availableScope map[int]string) {
	var tableBody [][]string
	for rgID, rgName := range availableScope {
		tableBody = append(tableBody, []string{strconv.Itoa(rgID), rgName})
		/*
			TO-DO:
			Figure out how to sort the table body by the first element.
			Here's some example code that might help:

			func (m *RoleTrustsModule) sortTrustsTablePerTrustedPrincipal() {
				sort.Slice(
					m.output.Body,
					func(i int, j int) bool {
						return m.output.Body[i][1] < m.output.Body[j][1]
					},
				)
			}
		*/
	}
	utils.PrintTableToScreen([]string{"Number", "Resource Group Name"}, tableBody)
}

var getAvailableScopeM = getAvailableScope

func getAvailableScope() map[int]string {
	var index int
	menu := make(map[int]string)
	subs, err := ListSubscriptions()
	if err != nil {
		log.Fatalf("error getting available scope from Azure CLI: %s", err)
	}
	for _, sub := range subs {
		rgs, err := ListResourceGroups(sub)
		if err != nil {
			log.Fatalf("error getting available scope from Azure CLI: %s", err)
		}
		for _, rg := range rgs {
			index++
			menu[index] = rg
		}
	}
	return menu
}

var ListSubscriptions = listSubscriptions

func listSubscriptions() ([]string, error) {
	var subs []string
	subsClient := utils.GetSubscriptionsClient()
	for page, err := subsClient.List(context.TODO()); page.NotDone(); err = page.Next() {
		if err != nil {
			return subs, err
		}
		for _, sub := range page.Values() {
			subs = append(subs, ptr.ToString(sub.SubscriptionID))
		}
	}
	return subs, nil
}

var ListResourceGroups = listResourceGroups

func listResourceGroups(subscription string) ([]string, error) {
	var resourceGroups []string
	rgClient := utils.GetResourceGroupsClient(subscription)
	for page, err := rgClient.List(context.TODO(), "", nil); page.NotDone(); err = page.Next() {
		if err != nil {
			return resourceGroups, err
		}
		for _, rg := range page.Values() {
			if rg.Name != nil {
				resourceGroups = append(resourceGroups, ptr.ToString(rg.Name))
			}
		}
	}
	return resourceGroups, nil
}
