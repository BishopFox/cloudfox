package azure

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/aws/smithy-go/ptr"
	"github.com/fatih/color"
	"github.com/kyokomi/emoji"
)

type AzInventoryModule struct {
	AzClient            *internal.AzureClient
}


func (m *AzInventoryModule) AzInventoryCommand() error {
	o := internal.OutputClient{
		Verbosity:     m.AzClient.AzVerbosity,
		CallingModule: globals.AZ_INVENTORY_MODULE_NAME,
		Table: internal.TableClient{
			Wrap: m.AzClient.AzWrapTable,
		},
	}

	if len(m.AzClient.AzTenants) > 0 {
		// cloudfox azure inventory --tenant [TENANT_ID | PRIMARY_DOMAIN]
		for _, AzTenant := range m.AzClient.AzTenants {

			if m.AzClient.AzMergedTable {
				// set up table vars
				var header []string
				var body [][]string

				o := internal.OutputClient{
					Verbosity:     m.AzClient.AzVerbosity,
					CallingModule: globals.AZ_INVENTORY_MODULE_NAME,
					Table: internal.TableClient{
						Wrap: m.AzClient.AzWrapTable,
					},
				}

				fmt.Printf(
					"[%s][%s] Gathering inventory for tenant %s\n",
					color.CyanString(emoji.Sprintf(":fox:cloudfox %s :fox:", m.AzClient.Version)), color.CyanString(o.CallingModule),
					fmt.Sprintf("%s (%s)", ptr.ToString(AzTenant.DefaultDomain), ptr.ToString(AzTenant.TenantID)))

				o.PrefixIdentifier = ptr.ToString(AzTenant.DefaultDomain)
				o.Table.DirectoryName = filepath.Join(m.AzClient.AzOutputDirectory, globals.CLOUDFOX_BASE_DIRECTORY, globals.AZ_DIR_BASE, ptr.ToString(AzTenant.DefaultDomain), "1-tenant-level")

				//populate the table data
				header, body, err := m.getInventoryInfoPerTenant(ptr.ToString(AzTenant.TenantID))
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
				for _, s := range GetSubscriptionsPerTenantID(ptr.ToString(AzTenant.TenantID)) {
					m.runInventoryCommandForSingleSubscription(ptr.ToString(s.SubscriptionID))
				}
			}
		} 
	} else {
		// ./cloudfox azure inventory --subscription [SUBSCRIPTION_ID | SUBSCRIPTION_NAME]
		for _, AzSubscription := range m.AzClient.AzSubscriptions {
			m.runInventoryCommandForSingleSubscription(*AzSubscription.SubscriptionID)
		}

	}
	o.WriteFullOutput(o.Table.TableFiles, nil)
	return nil
}

func (m *AzInventoryModule) runInventoryCommandForSingleSubscription(AzSubscription string) error {
	// set up table vars
	var header []string
	var body [][]string
	var err error
	o := internal.OutputClient{
		Verbosity:     m.AzClient.AzVerbosity,
		CallingModule: globals.AZ_INVENTORY_MODULE_NAME,
		Table: internal.TableClient{
			Wrap: m.AzClient.AzWrapTable,
		},
	}
	var AzSubscriptionInfo SubsriptionInfo
	tenantID := ptr.ToString(GetTenantIDPerSubscription(AzSubscription))
	tenantInfo := populateTenant(tenantID)
	AzSubscriptionInfo = PopulateSubsriptionType(AzSubscription)
	o.PrefixIdentifier = AzSubscriptionInfo.Name
	o.Table.DirectoryName = filepath.Join(m.AzClient.AzOutputDirectory, globals.CLOUDFOX_BASE_DIRECTORY, globals.AZ_DIR_BASE, ptr.ToString(tenantInfo.DefaultDomain), AzSubscriptionInfo.Name)

	fmt.Printf(
		"[%s][%s] Gathering inventory for subscription %s\n",
		color.CyanString(emoji.Sprintf(":fox:cloudfox %s :fox:", m.AzClient.Version)), color.CyanString(o.CallingModule),
		fmt.Sprintf("%s (%s)", AzSubscriptionInfo.Name, AzSubscriptionInfo.ID))

	// populate the table data
	header, body, err = m.getInventoryInfoPerSubscription(ptr.ToString(tenantInfo.ID), AzSubscriptionInfo.ID)
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

func (m *AzInventoryModule) getInventoryInfoPerSubscription(tenantID, subscriptionID string) ([]string, [][]string, error) {
	resources, err := m.getResources(tenantID, subscriptionID)
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
		if len(m.AzClient.AzRGs) > 0 {
			for _, AzRG := range m.AzClient.AzRGs {
				metaResource, _ := azure.ParseResourceID(*resource.ID)
				if metaResource.ResourceGroup == *AzRG.Name {
					goto ADD_RESOURCE
				}
			}
			goto SKIP_RESOURCE
		}
		ADD_RESOURCE:
		if !ok {
			inventory[resourceType] = make(map[string]int)
		}
		inventory[resourceType][resourceLocation]++
		resourceTypes[resourceType] = true
		resourceLocations[resourceLocation] = true
		SKIP_RESOURCE:
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

func (m *AzInventoryModule) getInventoryInfoPerTenant(tenantID string) ([]string, [][]string, error) {

	inventory := make(map[string]map[string]int)
	resourceTypes := make(map[string]bool)
	resourceLocations := make(map[string]bool)

	for _, s := range GetSubscriptionsPerTenantID(tenantID) {
		resources, err := m.getResources(tenantID, ptr.ToString(s.SubscriptionID))
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

func (m *AzInventoryModule) getResources(tenantID, subscriptionID string) ([]*armresources.GenericResourceExpanded, error) {
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
