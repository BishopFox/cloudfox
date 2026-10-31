package azure

import (
	"fmt"
	"testing"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/smithy-go/ptr"
)

func TestAzTokenCacheCommand(t *testing.T) {
	fmt.Println()
	fmt.Println("[test case] Azure Token Cache Command")

	// Mocked functions to simulate Azure calls and responses
	getTenants = mockedGetTenants
	GetSubscriptions = mockedGetSubscriptions
	getResourceGroups = mockedGetResourceGroups
	t.Cleanup(func() {
		getTenants = getTenantsOriginal
		GetSubscriptions = getSubscriptionsOriginal
		getResourceGroups = getResourceGroupsOriginal
	})

	// Test case parameters
	internal.MockFileSystem(true)
	subtests := []struct {
		name              string
		resourcesTestFile string
		azExtendedFilter  bool
		version           string
		wrapTableOutput   bool
		azOutputDirectory string
	}{
		{
			name:              "./cloudfox azure tokencache",
			resourcesTestFile: "./test-data/resources.json",
			azExtendedFilter:  false,
			version:           "DEV",
			wrapTableOutput:   false,
			azOutputDirectory: "~/.cloudfox",
		},
		{
			name:              "./cloudfox azure tokencache --list-rgs",
			resourcesTestFile: "./test-data/resources.json",
			azExtendedFilter:  true,
			version:           "DEV",
			wrapTableOutput:   true,
			azOutputDirectory: "~/.cloudfox",
		},
	}
	for _, s := range subtests {
		globals.RESOURCES_TEST_FILE = s.resourcesTestFile
		fmt.Println()
		fmt.Printf("[subtest] %s\n", s.name)
		if err := AzTokenCacheCommand(s.azOutputDirectory, s.version, s.wrapTableOutput, 1, s.azExtendedFilter); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAzWhoamiCommand(t *testing.T) {
	originalEntra, originalRBAC := getWhoamiEntraRoles, getWhoamiAzureRBAC
	getWhoamiEntraRoles = func() ([]string, [][]string, []error) {
		return []string{"Tenant ID", "Membership"}, [][]string{{"tenant", "Global Reader"}}, nil
	}
	getWhoamiAzureRBAC = func() ([]string, [][]string, []error) {
		return []string{"Tenant ID", "Azure RBAC Role"}, [][]string{{"tenant", "Reader"}}, nil
	}
	t.Cleanup(func() {
		getWhoamiEntraRoles = originalEntra
		getWhoamiAzureRBAC = originalRBAC
	})
	if err := AzWhoamiCommand("~/.cloudfox", "DEV", false, 1); err != nil {
		t.Fatal(err)
	}
}

func TestTest(t *testing.T) {
	fmt.Println(ptr.ToString(GetTenantIDPerSubscription("4cedc5dd-e3ad-468d-bf66-32e31bdb9148")))
}
