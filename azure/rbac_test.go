package azure

import (
	"testing"
)

func TestRBACCommand(t *testing.T) {
	GetAzureADUsers = MockedGetAzureADUsers
	GetRoleDefinitions = MockedGetRoleDefinitions
	GetRoleAssignments = MockedGetRoleAssignments

}

type InstancesClient struct {
}
