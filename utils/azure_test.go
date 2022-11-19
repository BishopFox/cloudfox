package utils

import (
	"fmt"
	"log"
	"testing"

	"github.com/BishopFox/cloudfox/globals"
)

// Requires Az CLI Authentication to passs
func TestGetAuthorizer(t *testing.T) {
	t.Skip()
	subtests := []struct {
		name     string
		endpoint string
	}{
		{
			name:     "Resource Manager Authorizer",
			endpoint: globals.AZ_RESOURCE_MANAGER_ENDPOINT,
		},
		{
			name:     "Graph API Authorizer",
			endpoint: globals.AZ_GRAPH_ENDPOINT,
		},
	}
	for _, subtest := range subtests {
		t.Run(subtest.name, func(t *testing.T) {
			log.Printf("Test case: %s", subtest.name)
			authorizer, err := getAuthorizer(subtest.endpoint)
			if err != nil {
				log.Print(err)
			} else {
				log.Print(authorizer)
			}
			fmt.Println()
		})
	}
}
