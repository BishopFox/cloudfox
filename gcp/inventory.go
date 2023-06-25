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
	GCPLogger.InfoM(fmt.Sprintf("Enumerating GCP resources with account %s...\n", m.Client.Name), globals.GCP_INVENTORY_MODULE_NAME)
	return nil
}
