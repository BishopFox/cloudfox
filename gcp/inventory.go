package gcp

import (
	"fmt"
	"github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/globals"
)

type InventoryModule struct {
	Client gcp.GCPClient
	// Filtering data
	Organizations []string
	Folders []string
	Projects []string
}

func (m *InventoryModule) PrintInventory(outputFormat string, outputDirectory string, verbosity int) error {
	GCPLogger.InfoM(fmt.Sprintf("Enumerating GCP resources with account %s...", m.Client.Name), globals.GCP_INVENTORY_MODULE_NAME)
	for _, project := range m.Projects {
		searchAllResponse, err := m.Client.ResourcesService.SearchAll(fmt.Sprintf("projects/%s", project)).Do()
		if (err != nil) {
			GCPLogger.ErrorM(fmt.Sprintf("Could not list resource within scope: %v", err), globals.GCP_INVENTORY_MODULE_NAME)
			continue
		}
		for _, resource := range searchAllResponse.Results {
			fmt.Printf("%s - %s\n", resource.DisplayName, resource.AssetType)
		}
	}
	return nil
}
