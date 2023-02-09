package azure

import (
	"context"
	"fmt"
	"sort"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/smithy-go/ptr"
)

func TestAzInventoryCommand(t *testing.T) {
	// Using the new version implementation
	// https://github.com/Azure/azure-sdk-for-go/blob/main/documentation/MIGRATION_GUIDE.md

	tenantID := ""
	subscriptionID := ""

	cred, err := azidentity.NewAzureCLICredential(&azidentity.AzureCLICredentialOptions{TenantID: tenantID})
	if err != nil {
		return
	}

	client, err := armresources.NewClient(subscriptionID, cred, nil)
	if err != nil {
		return
	}

	var resources []*armresources.GenericResourceExpanded

	pager := client.NewListPager(nil)
	for pager.More() {
		nextResult, err := pager.NextPage(context.TODO())
		if err != nil {
			return
		}
		resources = append(resources, nextResult.Value...)
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

	internal.MockFileSystem(true)
	internal.OutputSelector(2, "table", header, body, ".", "test.txt", "inventory", true, "sub-11111111-1111-11111-1111-1111111111111111")
}
