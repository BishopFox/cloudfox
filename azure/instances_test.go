package azure

import (
	"fmt"
	"log"
	"testing"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/compute/mgmt/compute"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/network/mgmt/network"
	"github.com/aws/smithy-go/ptr"
)

func TestGetComputeRelevantData(t *testing.T) {
	getComputeVMsPerResourceGroupM = func(subscriptionID, resourceGroup string) []compute.VirtualMachine {
		return []compute.VirtualMachine{
			{
				Name:                     nil,
				ID:                       nil,
				Location:                 nil,
				VirtualMachineProperties: nil,
				Identity:                 nil,
			},
			{
				Name:     ptr.String("TestVM1_AAAAAAAAAAAAAAAAAAAA"),
				ID:       ptr.String("id-1234"),
				Location: ptr.String("us-east1"),
				VirtualMachineProperties: &compute.VirtualMachineProperties{
					OsProfile: &compute.OSProfile{
						ComputerName:  ptr.String("HOME1"),
						AdminUsername: ptr.String("admin"),
						AdminPassword: ptr.String(""),
						// Equivalent of User Data in AWS
						// CustomData:    ptr.String(""),
					},
					NetworkProfile: &compute.NetworkProfile{
						NetworkInterfaces: nil,
					},
				},
				Identity: &compute.VirtualMachineIdentity{
					PrincipalID: ptr.String("11111111-1111-1111-1111-111111111112"),
					TenantID:    ptr.String("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaaa"),
				},
			},
			{
				Name:     ptr.String("TestVM2"),
				ID:       ptr.String("id-5678"),
				Location: ptr.String("us-west-1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
				VirtualMachineProperties: &compute.VirtualMachineProperties{
					OsProfile: &compute.OSProfile{
						ComputerName:  ptr.String("LAB1"),
						AdminUsername: ptr.String("admin"),
						AdminPassword: ptr.String(""),
					},
					NetworkProfile: &compute.NetworkProfile{
						NetworkInterfaces: &[]compute.NetworkInterfaceReference{
							{ID: nil},
							{ID: nil},
						},
					},
				},
				Identity: &compute.VirtualMachineIdentity{
					PrincipalID: ptr.String("11111111-1111-1111-1111-111111111113"),
					TenantID:    ptr.String("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
				},
			},
			{
				Name:     ptr.String("TestVM3"),
				ID:       ptr.String("id-9101112"),
				Location: ptr.String("us-west-2"),
				VirtualMachineProperties: &compute.VirtualMachineProperties{
					OsProfile: &compute.OSProfile{
						ComputerName:  ptr.String("DATACENTER1"),
						AdminUsername: ptr.String("admin_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
						AdminPassword: ptr.String(""),
					},
					NetworkProfile: &compute.NetworkProfile{
						NetworkInterfaces: &[]compute.NetworkInterfaceReference{
							{ID: ptr.String("/subscriptions/4cedc5dd-e3ad-468d-bf66-32e31bdb9148/resourceGroups/1-1d656534-playground-sandbox/providers/Microsoft.Network/networkInterfaces/test1391_z1")},
							{ID: nil},
						},
					},
				},
				Identity: &compute.VirtualMachineIdentity{
					PrincipalID: ptr.String("11111111-1111-1111-1111-111111111113"),
					TenantID:    ptr.String("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
				},
			},
		}
	}
	GetNICdetailsM = func(subscriptionID string, resourceGroup string, nic compute.NetworkInterfaceReference) (network.Interface, error) {
		return network.Interface{
			InterfacePropertiesFormat: &network.InterfacePropertiesFormat{
				IPConfigurations: &[]network.InterfaceIPConfiguration{
					{
						InterfaceIPConfigurationPropertiesFormat: &network.InterfaceIPConfigurationPropertiesFormat{
							PrivateIPAddress: ptr.String("192.168.0.1"),
							PublicIPAddress:  &network.PublicIPAddress{ID: nil},
						},
					},
					{
						InterfaceIPConfigurationPropertiesFormat: &network.InterfaceIPConfigurationPropertiesFormat{
							PrivateIPAddress: ptr.String("192.168.0.1"),
							PublicIPAddress:  nil,
						},
					},
					{
						InterfaceIPConfigurationPropertiesFormat: &network.InterfaceIPConfigurationPropertiesFormat{
							PrivateIPAddress: ptr.String("192.168.0.1"),
							PublicIPAddress:  &network.PublicIPAddress{ID: ptr.String("172.10.10.50")},
						},
					},
					{
						InterfaceIPConfigurationPropertiesFormat: nil,
					},
					{
						InterfaceIPConfigurationPropertiesFormat: &network.InterfaceIPConfigurationPropertiesFormat{
							PrivateIPAddress: nil,
							PublicIPAddress:  nil,
						},
					},
				},
			},
		}, nil
	}
}

func TestGetIPs(t *testing.T) {
	subtests := []struct {
		name string
		vm   compute.VirtualMachine
	}{
		{
			name: "Sub test 1",
			vm: compute.VirtualMachine{
				Name:                     nil,
				ID:                       nil,
				Location:                 nil,
				VirtualMachineProperties: nil,
				Identity:                 nil,
			},
		},
		{
			name: "Sub test 2",
			vm: compute.VirtualMachine{
				Name:     ptr.String("TestVM1_AAAAAAAAAAAAAAAAAAAA"),
				ID:       ptr.String("id-1234"),
				Location: ptr.String("us-east1"),
				VirtualMachineProperties: &compute.VirtualMachineProperties{
					OsProfile: &compute.OSProfile{
						ComputerName:  ptr.String("HOME1"),
						AdminUsername: ptr.String("admin"),
						AdminPassword: ptr.String(""),
						// Equivalent of User Data in AWS
						// CustomData:    ptr.String(""),
					},
					NetworkProfile: &compute.NetworkProfile{
						NetworkInterfaces: nil,
					},
				},
				Identity: &compute.VirtualMachineIdentity{
					PrincipalID: ptr.String("11111111-1111-1111-1111-111111111112"),
					TenantID:    ptr.String("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaaa"),
				},
			},
		},
		{
			name: "Sub test 3",
			vm: compute.VirtualMachine{
				Name:     ptr.String("TestVM2"),
				ID:       ptr.String("id-5678"),
				Location: ptr.String("us-west-1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
				VirtualMachineProperties: &compute.VirtualMachineProperties{
					OsProfile: &compute.OSProfile{
						ComputerName:  ptr.String("LAB1"),
						AdminUsername: ptr.String("admin"),
						AdminPassword: ptr.String(""),
					},
					NetworkProfile: &compute.NetworkProfile{
						NetworkInterfaces: &[]compute.NetworkInterfaceReference{
							{ID: nil},
							{ID: nil},
						},
					},
				},
				Identity: &compute.VirtualMachineIdentity{
					PrincipalID: ptr.String("11111111-1111-1111-1111-111111111113"),
					TenantID:    ptr.String("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
				},
			},
		},
		{
			name: "Sub test 4",
			vm: compute.VirtualMachine{
				Name:     ptr.String("TestVM3"),
				ID:       ptr.String("id-9101112"),
				Location: ptr.String("us-west-2"),
				VirtualMachineProperties: &compute.VirtualMachineProperties{
					OsProfile: &compute.OSProfile{
						ComputerName:  ptr.String("DATACENTER1"),
						AdminUsername: ptr.String("admin_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
						AdminPassword: ptr.String(""),
					},
					NetworkProfile: &compute.NetworkProfile{
						NetworkInterfaces: &[]compute.NetworkInterfaceReference{
							{ID: ptr.String("/subscriptions/4cedc5dd-e3ad-468d-bf66-32e31bdb9148/resourceGroups/1-1d656534-playground-sandbox/providers/Microsoft.Network/networkInterfaces/test1391_z1")},
							{ID: nil},
						},
					},
				},
				Identity: &compute.VirtualMachineIdentity{
					PrincipalID: ptr.String("11111111-1111-1111-1111-111111111113"),
					TenantID:    ptr.String("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
				},
			},
		},
	}
	for _, subtest := range subtests {
		t.Run(subtest.name, func(t *testing.T) {
			log.Println(subtest.name)
			internalIPs, externalIPs := getIPs("SUB", "RG", subtest.vm)
			fmt.Println(internalIPs, externalIPs)
		})
	}
}
