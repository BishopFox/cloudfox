package azure

import (
	"fmt"
	"testing"

	"github.com/BishopFox/cloudfox/utils"
)

func TestAzRunInstancesCommand(t *testing.T) {
	fmt.Println()
	fmt.Println("[test case] Azure Run Instances Command")

	// Mocked functions to simulate Azure responses
	GetTenants = MockedGetTenants
	GetSubscriptions = MockedGetSubscriptions
	GetResourceGroups = MockedGetResourceGroups
	// Need to adjust these three mocked functions, they are not filtering right
	GetComputeVMsPerResourceGroup = MockedGetComputeVMsPerResourceGroup
	GetNICdetails = MockedGetNICdetails
	GetPublicIP = MockedGetPublicIP

	// Test case parameters
	utils.MockFileSystem(true)

	subtests := []struct {
		Name           string
		AzSubFilter    string
		AzRGFilter     string
		AzVerbosity    int
		AzOutputFormat string
	}{
		{
			Name:           "./cloudfox az instances --subscription SUB_NAME",
			AzSubFilter:    "SubscriptionA",
			AzRGFilter:     "interactive",
			AzVerbosity:    2,
			AzOutputFormat: "table",
		},
		{
			Name:           "./cloudfox az instances --resource-group RG_NAME",
			AzSubFilter:    "interactive",
			AzRGFilter:     "ResourceGroupC1",
			AzVerbosity:    2,
			AzOutputFormat: "table",
		},
	}

	for _, s := range subtests {
		fmt.Printf("[subtest] %s\n", s.Name)
		AzRunInstancesCommand(s.AzSubFilter, s.AzRGFilter, s.AzOutputFormat, s.AzVerbosity)
		fmt.Println()
	}
}
