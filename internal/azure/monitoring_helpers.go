package azure

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/operationalinsights/armoperationalinsights"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
)

// GetLogAnalyticsWorkspacesPerSubscription returns a slice of workspace IDs for a given subscription
func GetLogAnalyticsWorkspacesPerSubscription(session *SafeSession, subscriptionID string) []string {
	logger := internal.NewLogger()
	ctx := context.Background()

	// Get ARM token
	token, err := session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to get ARM token for subscription %s: %v", subscriptionID, err), globals.AZ_UTILS_MODULE_NAME)
		}
		return nil
	}

	// Create credential from token
	cred := NewStaticTokenCredential(token)

	// Create Operational Insights client
	client, err := armoperationalinsights.NewWorkspacesClient(subscriptionID, cred, nil)
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to create Log Analytics client for subscription %s: %v", subscriptionID, err), globals.AZ_UTILS_MODULE_NAME)
		}
		return nil
	}

	// List all Log Analytics workspaces and collect their IDs
	var workspaceIDs []string
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Error listing Log Analytics workspaces for subscription %s: %v", subscriptionID, err), globals.AZ_UTILS_MODULE_NAME)
			}
			return workspaceIDs
		}

		for _, workspace := range page.Value {
			if workspace != nil && workspace.ID != nil {
				workspaceIDs = append(workspaceIDs, *workspace.ID)
			}
		}
	}

	return workspaceIDs
}
