package gcp

import (
	"fmt"
	"github.com/fatih/color"
	"github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/kyokomi/emoji"
	"github.com/BishopFox/cloudfox/globals"
)

type InventoryModule struct {
	// Filtering data
	Organizations []string
	Folders []string
	Projects []string
}

func (m *InventoryModule) PrintInventory(version string, outputFormat string, outputDirectory string, verbosity int) error {
	fmt.Printf("[%s][%s] Enumerating GCP resources...\n", color.CyanString(emoji.Sprintf(":fox:cloudfox %s :fox:", version)), color.CyanString(globals.GCP_WHOAMI_MODULE_NAME))
	var client gcp.GCPClient = *gcp.NewGCPClient()
	blah, _ := client.ResourcesService.SearchAll("project/gcp-goat-d1456434c69b3e84").Do()
	fmt.Print(blah)
	return nil
}
