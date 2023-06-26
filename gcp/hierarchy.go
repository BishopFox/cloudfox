package gcp

import (
	"fmt"
	"github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/globals"

	// tree stuff
	"github.com/shivamMg/ppds/tree"
)

type HierarchyModule struct {
	Client gcp.GCPClient
	
	// Filtering data
	Organizations []string
	Folders []string
	Projects []string
}


func (m *HierarchyModule) DisplayHierarchy(format string) error {
	GCPLogger.InfoM(fmt.Sprintf("Fetching GCP resources and hierarchy with account %s...", m.Client.Name), globals.GCP_HIERARCHY_MODULE_NAME)
	var roots = m.Client.GetResourcesRoots(m.Organizations, m.Folders, m.Projects)

	for _, root := range roots {
		if (format == "horizontal") {
			tree.PrintHr(root)
		} else if (format == "vertical") {
			tree.Print(root)
		} else {
			GCPLogger.ErrorM(fmt.Sprintf("Unknown tree format '%s'", format), globals.GCP_HIERARCHY_MODULE_NAME)
		}

	}
	return nil
}

