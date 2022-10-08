package utils

import (
	"fmt"
	"log"
	"testing"
)

func TestGetAuthorizer(t *testing.T) {
	subtests := []struct {
		name     string
		endpoint string
	}{
		{
			name:     "Resource Manager Authorizer",
			endpoint: RESOURCE_MANAGER_ENDPOINT,
		},
		{
			name:     "Graph API Authorizer",
			endpoint: GRAPH_ENDPOINT,
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
