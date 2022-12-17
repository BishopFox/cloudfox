package azure

import (
	"fmt"
	"testing"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/aws/smithy-go/ptr"
	"github.com/fatih/color"
)

func TestAzWhoamiCommand(t *testing.T) {
	fmt.Println()
	fmt.Println("[test case] Azure Whoami Command")

	// Mocked functions to simulate Azure calls and responses
	getTenants = mockedGetTenants
	getSubscriptions = mockedGetSubscriptions
	getResourceGroups = mockedGetResourceGroups

	// Test case parameters
	subtests := []struct {
		name              string
		resourcesTestFile string
		mockedUserInput   *string
		expectedScope     []scopeElement
	}{
		{
			name:              "./cloudfox azure whoami",
			resourcesTestFile: "./test-data/resources.json",
		},
	}

	for _, s := range subtests {
		globals.RESOURCES_TEST_FILE = s.resourcesTestFile
		AzWhoamiCommand()
	}
}

func TestScopeSelectionFull(t *testing.T) {
	t.Skip()
	fmt.Println()
	fmt.Println("[test case] scope selection interactive menu")

	// Mocked functions to simulate Azure calls and responses
	getTenants = mockedGetTenants
	getSubscriptions = mockedGetSubscriptions
	getResourceGroups = mockedGetResourceGroups

	// Test case parameters
	subtests := []struct {
		name              string
		resourcesTestFile string
		mockedUserInput   *string
		expectedScope     []scopeElement
	}{
		{
			name:              "basic acceptance",
			mockedUserInput:   ptr.String("1,2,3"),
			resourcesTestFile: "./test-data/resources.json",
		},
	}

	for _, s := range subtests {
		globals.RESOURCES_TEST_FILE = s.resourcesTestFile
		selectedScope := scopeSelection(s.mockedUserInput, "full")
		fmt.Printf("[%s]> %s\n", color.CyanString("mocked_input"), ptr.ToString(s.mockedUserInput))
		fmt.Printf("[%s] ", color.CyanString("selection"))
		for _, s := range selectedScope {
			fmt.Printf("%s ", ptr.ToString(s.ResourceGroup.Name))
		}
		fmt.Println()
		fmt.Println()
	}
}
