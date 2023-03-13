package azure

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/smithy-go/ptr"
	"github.com/fatih/color"
	"github.com/kyokomi/emoji"
)

func AzInventoryCommand(AzTenantID, AzSubscriptionID, Version string, AzVerbosity int, AzWrapTable bool) error {
	o := internal.OutputClient{
		Verbosity:     AzVerbosity,
		CallingModule: globals.AZ_INVENTORY_MODULE_NAME,
		Table: internal.TableClient{
			Wrap: AzWrapTable,
		},
	}

	if AzTenantID != "" && AzSubscriptionID == "" {
		// To-Do: implement per tentant
		fmt.Println("Inventory per tenant not yet implemented. Please use the --subscription flag instead.")

	} else if AzTenantID == "" && AzSubscriptionID != "" {

		// ./cloudfox azure storage --subscription SUBSCRIPTION_ID
		fmt.Printf(
			"[%s][%s] Gathering inventory for subscription %s\n",
			color.CyanString(emoji.Sprintf(":fox:cloudfox %s :fox:", Version)),
			color.CyanString(o.CallingModule),
			AzSubscriptionID)

		AzTenantID := ptr.ToString(GetTenantIDPerSubscription(AzSubscriptionID))

		header, body, err := prepareInventoryTable(AzTenantID, AzSubscriptionID)
		if err != nil {
			return err
		}

		o.Table.TableFiles = append(o.Table.TableFiles,
			internal.TableFile{
				Header: header,
				Body:   body,
				Name:   globals.AZ_INVENTORY_MODULE_NAME})
		o.PrefixIdentifier = fmt.Sprintf("subscription-%s", AzSubscriptionID)
		o.Table.DirectoryName = filepath.Join(
			globals.CLOUDFOX_BASE_DIRECTORY,
			globals.AZ_DIR_BASE,
			"subscriptions",
			AzSubscriptionID)

	} else {
		// Error: please make a valid flag selection
		fmt.Println("Please enter a valid input with a valid flag. Use --help for info.")
	}
	o.WriteFullOutput(o.Table.TableFiles, nil)
	return nil
}

func prepareInventoryTable(tenantID, subscriptionID string) ([]string, [][]string, error) {
	resources, err := getResources(tenantID, subscriptionID)
	if err != nil {
		return nil, nil, err
	}

	inventory := make(map[string]map[string]int)
	resourceTypes := make(map[string]bool)
	resourceLocations := make(map[string]bool)

	for _, resource := range resources {
		resourceType := ptr.ToString(resource.Type)
		resourceLocation := ptr.ToString(resource.Location)

		_, ok := inventory[resourceType]
		if !ok {
			inventory[resourceType] = make(map[string]int)
		}
		inventory[resourceType][resourceLocation]++
		resourceTypes[resourceType] = true
		resourceLocations[resourceLocation] = true
	}

	header := []string{"Resource Type"}
	var body [][]string
	for location := range resourceLocations {
		header = append(header, location)
	}

	for t := range resourceTypes {
		row := []string{t}
		for location := range resourceLocations {
			count, ok := inventory[t][location]
			if ok {
				row = append(row, fmt.Sprintf("%d", count))
			} else {
				row = append(row, "-")
			}
		}
		body = append(body, row)
	}

	sort.Slice(body, func(i, j int) bool {
		return body[i][0] < body[j][0]
	})

	return header, body, nil
}

func getResources(tenantID, subscriptionID string) ([]*armresources.GenericResourceExpanded, error) {
	client := internal.GetARMresourcesClient(tenantID, subscriptionID)

	var resources []*armresources.GenericResourceExpanded

	pager := client.NewListPager(nil)
	for pager.More() {
		nextResult, err := pager.NextPage(context.TODO())
		if err != nil {
			return nil, err
		}
		resources = append(resources, nextResult.Value...)
	}

	return resources, nil
}
