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

func AzInventoryCommand(AzClient *internal.AzureClient, AzOutputDirectory, Version string, AzVerbosity int, AzWrapTable bool, AzMergedTable bool) error {
	o := internal.OutputClient{
		Verbosity:     AzVerbosity,
		CallingModule: globals.AZ_INVENTORY_MODULE_NAME,
		Table: internal.TableClient{
			Wrap: AzWrapTable,
		},
	}

	if len(AzClient.AzTenants) > 0 {
		// cloudfox azure inventory --tenant [TENANT_ID | PRIMARY_DOMAIN]
		for _, AzTenant := range AzClient.AzTenants {
			tenantInfo := populateTenant(*AzTenant.ID)

			if AzMergedTable {
				// set up table vars
				var header []string
				var body [][]string

				o := internal.OutputClient{
					Verbosity:     AzVerbosity,
					CallingModule: globals.AZ_INVENTORY_MODULE_NAME,
					Table: internal.TableClient{
						Wrap: AzWrapTable,
					},
				}

				fmt.Printf(
					"[%s][%s] Gathering inventory for tenant %s\n",
					color.CyanString(emoji.Sprintf(":fox:cloudfox %s :fox:", Version)), color.CyanString(o.CallingModule),
					fmt.Sprintf("%s (%s)", ptr.ToString(tenantInfo.DefaultDomain), ptr.ToString(tenantInfo.ID)))

				o.PrefixIdentifier = ptr.ToString(tenantInfo.DefaultDomain)
				o.Table.DirectoryName = filepath.Join(AzOutputDirectory, globals.CLOUDFOX_BASE_DIRECTORY, globals.AZ_DIR_BASE, ptr.ToString(tenantInfo.DefaultDomain), "1-tenant-level")

				//populate the table data
				header, body, err := getInventoryInfoPerTenant(ptr.ToString(tenantInfo.ID))
				if err != nil {
					return err
				}
				o.Table.TableFiles = append(o.Table.TableFiles,
					internal.TableFile{
						Header: header,
						Body:   body,
						Name:   fmt.Sprintf(o.CallingModule)})

				if body != nil {
					o.WriteFullOutput(o.Table.TableFiles, nil)
				}
			} else {
				for _, s := range GetSubscriptionsPerTenantID(ptr.ToString(tenantInfo.ID)) {
					runInventoryCommandForSingleSubscription(ptr.ToString(s.SubscriptionID), AzOutputDirectory, AzVerbosity, AzWrapTable, Version)
				}
			}
		} 
	} else {
		// ./cloudfox azure inventory --subscription [SUBSCRIPTION_ID | SUBSCRIPTION_NAME]
		for _, AzSubscription := range AzClient.AzSubscriptions {
			runInventoryCommandForSingleSubscription(*AzSubscription.SubscriptionID, AzOutputDirectory, AzVerbosity, AzWrapTable, Version)
		}

	}
	o.WriteFullOutput(o.Table.TableFiles, nil)
	return nil
}

func runInventoryCommandForSingleSubscription(AzSubscription string, AzOutputDirectory string, AzVerbosity int, AzWrapTable bool, Version string) error {
	// set up table vars
	var header []string
	var body [][]string
	var err error
	o := internal.OutputClient{
		Verbosity:     AzVerbosity,
		CallingModule: globals.AZ_INVENTORY_MODULE_NAME,
		Table: internal.TableClient{
			Wrap: AzWrapTable,
		},
	}
	var AzSubscriptionInfo SubsriptionInfo
	tenantID := ptr.ToString(GetTenantIDPerSubscription(AzSubscription))
	tenantInfo := populateTenant(tenantID)
	AzSubscriptionInfo = PopulateSubsriptionType(AzSubscription)
	o.PrefixIdentifier = AzSubscriptionInfo.Name
	o.Table.DirectoryName = filepath.Join(AzOutputDirectory, globals.CLOUDFOX_BASE_DIRECTORY, globals.AZ_DIR_BASE, ptr.ToString(tenantInfo.DefaultDomain), AzSubscriptionInfo.Name)

	fmt.Printf(
		"[%s][%s] Gathering inventory for subscription %s\n",
		color.CyanString(emoji.Sprintf(":fox:cloudfox %s :fox:", Version)), color.CyanString(o.CallingModule),
		fmt.Sprintf("%s (%s)", AzSubscriptionInfo.Name, AzSubscriptionInfo.ID))

	// populate the table data
	header, body, err = getInventoryInfoPerSubscription(ptr.ToString(tenantInfo.ID), AzSubscriptionInfo.ID)
	if err != nil {
		return err
	}

	o.Table.TableFiles = append(o.Table.TableFiles,
		internal.TableFile{
			Header: header,
			Body:   body,
			Name:   fmt.Sprintf(globals.AZ_INVENTORY_MODULE_NAME)})

	if body != nil {
		o.WriteFullOutput(o.Table.TableFiles, nil)
		fmt.Println()
	}

	return nil
}

func getInventoryInfoPerSubscription(tenantID, subscriptionID string) ([]string, [][]string, error) {
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

func getInventoryInfoPerTenant(tenantID string) ([]string, [][]string, error) {

	inventory := make(map[string]map[string]int)
	resourceTypes := make(map[string]bool)
	resourceLocations := make(map[string]bool)

	for _, s := range GetSubscriptionsPerTenantID(tenantID) {
		resources, err := getResources(tenantID, ptr.ToString(s.SubscriptionID))
		if err != nil {
			return nil, nil, err
		}

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
