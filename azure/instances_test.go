package azure

import (
	"fmt"
	"log"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/compute/mgmt/compute"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/network/mgmt/network"
	"github.com/BishopFox/cloudfox/utils"
	"github.com/aws/smithy-go/ptr"
)

func TestGetComputeRelevantData(t *testing.T) {
	var subtests = []struct {
		name                          string
		expectedBody                  [][]string
		getComputeVMsPerResourceGroup func(subscriptionID string, resourceGroup string) []compute.VirtualMachine
		getIPs                        func(subscriptionID string, resourceGroup string, vm compute.VirtualMachine) ([]string, []string)
	}{
		{
			name: "subtest 1",
			expectedBody: [][]string{
				{"TestVM1", "vm_id_1", "us-west-2", "admin", "192.168.0.1", "72.88.100.1"},
				{"TestVM2", "vm_id_2", "us-west-2", "admin", "192.168.0.2", "72.88.100.2"},
				{"TestVM3", "vm_id_3", "us-west-2", "admin", "192.168.0.3", "72.88.100.3"},
			},
			getComputeVMsPerResourceGroup: func(subscriptionID, resourceGroup string) []compute.VirtualMachine {
				return []compute.VirtualMachine{
					{
						Name:     ptr.String("TestVM1"),
						ID:       ptr.String("vm_id_1"),
						Location: ptr.String("us-west-2"),
						VirtualMachineProperties: &compute.VirtualMachineProperties{
							OsProfile: &compute.OSProfile{
								AdminUsername: ptr.String("admin"),
							},
						},
					},
					{
						Name:     ptr.String("TestVM2"),
						ID:       ptr.String("vm_id_2"),
						Location: ptr.String("us-west-2"),
						VirtualMachineProperties: &compute.VirtualMachineProperties{
							OsProfile: &compute.OSProfile{
								AdminUsername: ptr.String("admin"),
							},
						},
					},
					{
						Name:     ptr.String("TestVM3"),
						ID:       ptr.String("vm_id_3"),
						Location: ptr.String("us-west-2"),
						VirtualMachineProperties: &compute.VirtualMachineProperties{
							OsProfile: &compute.OSProfile{
								AdminUsername: ptr.String("admin"),
							},
						},
					},
				}
			},
			getIPs: func(subscriptionID, resourceGroup string, vm compute.VirtualMachine) ([]string, []string) {
				switch ptr.ToString(vm.Name) {
				case "TestVM1":
					return []string{"192.168.0.1"}, []string{"72.88.100.1"}
				case "TestVM2":
					return []string{"192.168.0.2"}, []string{"72.88.100.2"}
				case "TestVM3":
					return []string{"192.168.0.3"}, []string{"72.88.100.3"}
				default:
					return nil, nil
				}
			},
		},
	}
	fmt.Println()
	fmt.Println("[test case] GetComputeRelevantData")
	for _, subtest := range subtests {
		getComputeVMsPerResourceGroupM = subtest.getComputeVMsPerResourceGroup
		getIPsM = subtest.getIPs

		header, body := GetComputeRelevantData("subID", "rg1")
		for rowIndex, row := range body {
			for columIndex := range row {
				if body[rowIndex][columIndex] != subtest.expectedBody[rowIndex][columIndex] {
					log.Fatalf("[%s] Public IP mismatch: got %s, expected: %s", subtest.name, body[rowIndex][columIndex], subtest.expectedBody[rowIndex][columIndex])
				}
			}
		}

		utils.MockFileSystem(true)
		utils.OutputSelector(2, "table", header, body, ".", "test.txt", "instances")
	}
	fmt.Println()
}

func TestGetIPs(t *testing.T) {
	var subtests = []struct {
		name               string
		expectedPublicIPs  []string
		expectedPrivateIPs []string
		vm                 compute.VirtualMachine
		getNICdetails      func(subscriptionID, resourceGroup string, nicReference compute.NetworkInterfaceReference) (network.Interface, error)
		getPublicIP        func(subscriptionID, resourceGroup string, ip network.InterfaceIPConfiguration) (string, error)
	}{
		{
			name:               "subtest 1",
			expectedPrivateIPs: []string{"192.168.0.1"},
			expectedPublicIPs:  []string{"72.88.100.1"},
			vm: compute.VirtualMachine{
				Name: ptr.String("TestVM1"),
				VirtualMachineProperties: &compute.VirtualMachineProperties{
					NetworkProfile: &compute.NetworkProfile{
						NetworkInterfaces: &[]compute.NetworkInterfaceReference{
							{
								ID: ptr.String("/subscriptions/subid/resourceGroups/rg1//providers/Microsoft.Network/networkInterfaces/NetworkInterface1"),
							},
						},
					},
				},
			},
			getNICdetails: func(subscriptionID, resourceGroup string, nicReference compute.NetworkInterfaceReference) (network.Interface, error) {
				return network.Interface{
					ID: ptr.String("/subscriptions/subid/resourceGroups/rg1//providers/Microsoft.Network/networkInterfaces/NetworkInterface1"),
					InterfacePropertiesFormat: &network.InterfacePropertiesFormat{
						IPConfigurations: &[]network.InterfaceIPConfiguration{
							{
								InterfaceIPConfigurationPropertiesFormat: &network.InterfaceIPConfigurationPropertiesFormat{
									PrivateIPAddress: ptr.String("192.168.0.1"),
									PublicIPAddress: &network.PublicIPAddress{
										ID: ptr.String("/subscriptions/subid/resourceGroups/rg1/providers/Microsoft.Network/publicIPAddresses/PublicIpAddress1A"),
									},
								},
							},
						},
					},
				}, nil
			},
			getPublicIP: func(subscriptionID, resourceGroup string, ip network.InterfaceIPConfiguration) (string, error) {
				return "72.88.100.1", nil
			},
		},
	}
	fmt.Println()
	fmt.Println("[test case] getIPs")
	for _, subtest := range subtests {
		t.Run(subtest.name, func(t *testing.T) {
			getNICdetailsM = subtest.getNICdetails
			getPublicIPM = subtest.getPublicIP
			privateIPs, publicIPs := getIPs("subID", "rg1", subtest.vm)
			for i := range privateIPs {
				if privateIPs[i] != subtest.expectedPrivateIPs[i] {
					log.Fatalf("[%s] Private IP mismatch: got %s, expected: %s", subtest.name, privateIPs[i], subtest.expectedPrivateIPs[i])
				}
			}
			for i := range publicIPs {
				if publicIPs[i] != subtest.expectedPublicIPs[i] {
					log.Fatalf("[%s] Public IP mismatch: got %s, expected: %s", subtest.name, publicIPs[i], subtest.expectedPublicIPs[i])
				}
			}
			log.Printf("[%s] Public IPs match: %s", subtest.name, strings.Join(subtest.expectedPublicIPs, ", "))
			log.Printf("[%s] Private IPs match: %s", subtest.name, strings.Join(subtest.expectedPrivateIPs, ", "))
			fmt.Println()
		})
	}
}
