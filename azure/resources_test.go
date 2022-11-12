package azure

import (
	"fmt"
	"testing"

	"github.com/aws/smithy-go/ptr"
	"github.com/fatih/color"
)

func TestScopeSelectionFull(t *testing.T) {
	fmt.Println()
	fmt.Println("[test case] scope selection interactive menu")

	// Mocked Azure calls
	GetTenants = MockedGetTenants
	GetSubscriptions = MockedGetSubscriptions
	GetResourceGroups = MockedGetResourceGroups

	// Test case parameters
	subtests := []struct {
		name            string
		mockedUserInput *string
		expectedScope   []scopeElement
	}{
		{
			name:            "multiple selections",
			mockedUserInput: ptr.String("1,2,3"),
		},
	}

	for _, subtest := range subtests {
		selectedScope := ScopeSelection(subtest.mockedUserInput, "full")
		fmt.Printf("[%s]> %s\n", color.CyanString("mocked_input"), ptr.ToString(subtest.mockedUserInput))
		fmt.Printf("[%s] ", color.CyanString("selection"))
		for _, s := range selectedScope {
			fmt.Printf("%s ", ptr.ToString(s.ResourceGroup.Name))
		}
		fmt.Println()
		fmt.Println()
	}
}
