package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/resources"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/subscriptions"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/smithy-go/ptr"
	"github.com/fatih/color"
	"github.com/kyokomi/emoji"
)

func AzWhoamiCommand(version string, AzWrapTable bool) error {
	fmt.Printf("[%s][%s] Enumerating Azure CLI sessions...\n", color.CyanString(emoji.Sprintf(":fox:cloudfox %s :fox:", version)), color.CyanString(globals.AZ_WHOAMI_MODULE_NAME))
	var header []string
	var body [][]string
	header, body = getWhoamiRelevantDataPerRG()
	internal.PrintTableToScreen(header, body, AzWrapTable)
	return nil
}

func getWhoamiRelevantDataPerRG() ([]string, [][]string) {
	tableHead := []string{"Tenant ID", "Subscription ID", "Subscription Name", "RG Name", "Region", "Domain"}
	var tableBody [][]string

	for _, t := range getTenants() {
		for _, s := range getSubscriptions() {
			if ptr.ToString(t.TenantID) == ptr.ToString(s.TenantID) {
				for _, rg := range getResourceGroups(ptr.ToString(s.SubscriptionID)) {
					tableBody = append(
						tableBody,
						[]string{
							ptr.ToString(s.TenantID),
							ptr.ToString(s.SubscriptionID),
							ptr.ToString(s.DisplayName),
							ptr.ToString(rg.Name),
							ptr.ToString(rg.Location),
							ptr.ToString(t.DefaultDomain)})
				}
			}
		}
	}

	return tableHead, tableBody
}

func GetTenantIDPerSubscription(subscriptionID string) *string {
	subs := getSubscriptions()
	for _, s := range subs {
		if ptr.ToString(s.SubscriptionID) == subscriptionID {
			return s.TenantID
		}
	}
	return nil
}

func GetSubscriptionsPerTenantID(tenantID string) []subscriptions.Subscription {
	subs := getSubscriptions()
	var results []subscriptions.Subscription
	for _, s := range subs {
		if ptr.ToString(s.TenantID) == tenantID {
			results = append(results, s)
		}
	}
	return results
}

var getTenants = getTenantsOriginal

func getTenantsOriginal() []subscriptions.TenantIDDescription {
	tenantsClient := internal.GetTenantsClient()
	var results []subscriptions.TenantIDDescription
	for page, err := tenantsClient.List(context.TODO()); page.NotDone(); err = page.Next() {
		if err != nil {
			log.Fatal("could not get tenants for active session")
		}
		results = append(results, page.Values()...)
	}
	return results
}

func mockedGetTenants() []subscriptions.TenantIDDescription {
	var results []subscriptions.TenantIDDescription
	for _, tenant := range loadTestFile(globals.RESOURCES_TEST_FILE).Tenants {
		results = append(results, subscriptions.TenantIDDescription{
			TenantID:      tenant.TenantID,
			DisplayName:   tenant.DisplayName,
			DefaultDomain: tenant.DefaultDomain,
		})
	}
	return results
}

var getSubscriptions = getSubscriptionsOriginal

func getSubscriptionsOriginal() []subscriptions.Subscription {
	var results []subscriptions.Subscription
	subsClient := internal.GetSubscriptionsClient()
	for page, err := subsClient.List(context.TODO()); page.NotDone(); err = page.Next() {
		if err != nil {
			log.Fatal("could not get subscriptions for active session")
		}
		results = append(results, page.Values()...)
	}
	return results
}

func mockedGetSubscriptions() []subscriptions.Subscription {
	var results []subscriptions.Subscription
	tenants := loadTestFile(globals.RESOURCES_TEST_FILE).Tenants
	for _, tenant := range tenants {
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

var getResourceGroups = getResourceGroupsOriginal

func getResourceGroupsOriginal(subscriptionID string) []resources.Group {
	var results []resources.Group
	rgClient := internal.GetResourceGroupsClient(subscriptionID)

	for page, err := rgClient.List(context.TODO(), "", nil); page.NotDone(); err = page.Next() {
		if err != nil {
			log.Fatalf("error reading resource groups for subscription %s", subscriptionID)
		}
		results = append(results, page.Values()...)
	}
	return results
}

func mockedGetResourceGroups(subscriptionID string) []resources.Group {
	var results []resources.Group
	for _, tenant := range loadTestFile(globals.RESOURCES_TEST_FILE).Tenants {
		for _, sub := range tenant.Subscriptions {
			if ptr.ToString(sub.SubscriptionId) == subscriptionID {
				for _, rg := range sub.ResourceGroups {
					results = append(results, resources.Group{
						ID:       rg.ID,
						Name:     rg.Name,
						Location: rg.Location,
					})
				}
			}
		}
	}
	return results
}

func loadTestFile(fileName string) ResourcesTestFile {
	file, err := os.ReadFile(fileName)
	if err != nil {
		log.Fatalf("could not read file %s", globals.RESOURCES_TEST_FILE)
	}
	var testFile ResourcesTestFile
	err = json.Unmarshal(file, &testFile)
	if err != nil {
		log.Fatalf("could not unmarshall file %s", globals.RESOURCES_TEST_FILE)
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
				Name     *string `json:"Name"`
				ID       *string `json:"id"`
				Location *string `json:"location"`
			} `json:"ResourceGroups"`
		} `json:"Subscriptions"`
	} `json:"Tenants"`
}
