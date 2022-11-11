package azure

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"testing"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/resources"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/subscriptions"
	"github.com/BishopFox/cloudfox/constants"
	"github.com/aws/smithy-go/ptr"
	"github.com/fatih/color"
)

func TestScopeSelectionFull(t *testing.T) {
	fmt.Println("[test case] scope selection interactive menu")

	// Mocked Azure calls
	GetTenants = MockedGetTenants
	GetSubscriptions = MockedGetSubscriptions
	GetResourceGroups = MockedGetResourceGroups

	// Test case parameters
	subtests := []struct {
		name            string
		mockedUserInput *string
		expectedScope   []scopeElement
	}{
		{
			name:            "multiple selections",
			mockedUserInput: ptr.String("1,2,3"),
		},
	}

	for _, subtest := range subtests {
		fmt.Println()
		fmt.Printf("[subtest] %s\n", subtest.name)

		selectedScope := ScopeSelection(subtest.mockedUserInput, "full")
		fmt.Printf("[%s]> %s\n", color.CyanString("mocked_input"), ptr.ToString(subtest.mockedUserInput))
		fmt.Printf("[%s] ", color.CyanString("selection"))
		for _, s := range selectedScope {
			fmt.Printf("%s ", ptr.ToString(s.ResourceGroup.Name))
		}
		fmt.Println()
		fmt.Println()
	}
}

func TestGetSubscriptionForResourceGroup(t *testing.T) {
	fmt.Println()
	fmt.Println("[test case] GetSubscriptionForResourceGroup Function")

	// Mocked Azure calls
	GetTenants = MockedGetTenants
	GetSubscriptions = MockedGetSubscriptions
	GetResourceGroups = MockedGetResourceGroups

	// Test case parameters
	subTests := map[string]string{
		"Resource Group A1": "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAA",
		"Resource Group B2": "BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBB",
		"Resource Group C1": "CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCC",
	}

	for inputRG, expectedSub := range subTests {
		sub := GetSubscriptionForResourceGroup(inputRG)
		if ptr.ToString(sub.SubscriptionID) != expectedSub {
			log.Fatalf("expected %s, got %s", expectedSub, ptr.ToString(sub.SubscriptionID))
		}
		fmt.Printf("expected %s got %s\n", expectedSub, ptr.ToString(sub.SubscriptionID))
	}
}

func MockedGetResourceGroups(subscriptionID string) []resources.Group {
	var results []resources.Group
	for _, tenant := range loadTestFile(constants.RESOURCES_TEST_FILE).Tenants {
		for _, sub := range tenant.Subscriptions {
			if ptr.ToString(sub.SubscriptionId) == subscriptionID {
				for _, rg := range sub.ResourceGroups {
					results = append(results, resources.Group{
						ID:   rg.ID,
						Name: rg.Name,
					})
				}
			}
		}
	}
	return results
}

func MockedGetSubscriptions() []subscriptions.Subscription {
	var results []subscriptions.Subscription
	for _, tenant := range loadTestFile(constants.RESOURCES_TEST_FILE).Tenants {
		for _, sub := range tenant.Subscriptions {
			results = append(results, subscriptions.Subscription{
				TenantID:       tenant.TenantID,
				SubscriptionID: sub.SubscriptionId,
				DisplayName:    sub.DisplayName,
			})
		}
	}
	return results
}

func MockedGetTenants() []subscriptions.TenantIDDescription {
	var results []subscriptions.TenantIDDescription
	for _, tenant := range loadTestFile(constants.RESOURCES_TEST_FILE).Tenants {
		results = append(results, subscriptions.TenantIDDescription{
			TenantID:      tenant.TenantID,
			DisplayName:   tenant.DisplayName,
			DefaultDomain: tenant.DefaultDomain,
		})
	}
	return results
}

func loadTestFile(fileName string) ResourcesTestFile {
	file, err := os.ReadFile(fileName)
	if err != nil {
		log.Fatalf("could not read file %s", constants.RESOURCES_TEST_FILE)
	}
	var testFile ResourcesTestFile
	err = json.Unmarshal(file, &testFile)
	if err != nil {
		log.Fatalf("could not unmarshall file %s", constants.RESOURCES_TEST_FILE)
	}
	return testFile
}

type ResourcesTestFile struct {
	Tenants []struct {
		DisplayName   *string `json:"displayName"`
		TenantID      *string `json:"tenantId"`
		DefaultDomain *string `json:"defaultDomain,omitempty"`
		Subscriptions []struct {
			DisplayName    *string `json:"displayName"`
			SubscriptionId *string `json:"subscriptionId"`
			ResourceGroups []struct {
				Name *string `json:"Name"`
				ID   *string `json:"id"`
			} `json:"ResourceGroups"`
		} `json:"Subscriptions"`
	} `json:"Tenants"`
}
