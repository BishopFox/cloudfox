package azure

import (
	"fmt"
	"log"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/compute/mgmt/compute"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/network/mgmt/network"
	"github.com/BishopFox/cloudfox/constants"
	"github.com/BishopFox/cloudfox/utils"
	"github.com/aws/smithy-go/ptr"
)

func TestInstancesCommand(t *testing.T) {
	var subtests = []struct {
		name          string
		subscription  string
		resourceGroup string
		expectedBody  [][]string
		// These mocked functions below are wrapping Azure API calls
		getComputeVMsPerResourceGroup func(subscriptionID string, resourceGroup string) []compute.VirtualMachine
		getNICdetails                 func(subscriptionID, resourceGroup string, nicReference compute.NetworkInterfaceReference) (network.Interface, error)
		getPublicIP                   func(subscriptionID, resourceGroup string, ip network.InterfaceIPConfiguration) (*string, error)
	}{
		{
			name:          "subtest 1",
			subscription:  "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAA",
			resourceGroup: "ResourceGroup_A1",
			expectedBody: [][]string{
				{"TestVM1", "vm_id_1", "us-east-1", "admin", "192.168.0.1,192.168.0.2", "72.88.100.1,72.88.100.2"},
				{"TestVM2", "vm_id_2", "us-west-2", "admin", "192.168.0.3,192.168.0.4", "72.88.100.3,72.88.100.4"},
			},
			getComputeVMsPerResourceGroup: func(subscriptionID, resourceGroup string) []compute.VirtualMachine {
				return []compute.VirtualMachine{
					{
						Name:     ptr.String("TestVM1"),
						ID:       ptr.String("vm_id_1"),
						Location: ptr.String("us-east-1"),
						VirtualMachineProperties: &compute.VirtualMachineProperties{
							OsProfile: &compute.OSProfile{
								AdminUsername: ptr.String("admin"),
							},
							NetworkProfile: &compute.NetworkProfile{
								NetworkInterfaces: &[]compute.NetworkInterfaceReference{
									{
										ID: ptr.String("/subscriptions/subid/resourceGroups/rg1/providers/Microsoft.Network/networkInterfaces/NetworkInterface1"),
									},
								},
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
							NetworkProfile: &compute.NetworkProfile{
								NetworkInterfaces: &[]compute.NetworkInterfaceReference{
									{
										ID: ptr.String("/subscriptions/subid/resourceGroups/rg1/providers/Microsoft.Network/networkInterfaces/NetworkInterface2"),
									},
									{
										ID: ptr.String("/subscriptions/subid/resourceGroups/rg1/providers/Microsoft.Network/networkInterfaces/NetworkInterface3"),
									},
								},
							},
						},
					},
				}
			},
			getNICdetails: func(subscriptionID, resourceGroup string, nicReference compute.NetworkInterfaceReference) (network.Interface, error) {
				NICName := strings.Split(ptr.ToString(nicReference.ID), "/")[len(strings.Split(ptr.ToString(nicReference.ID), "/"))-1]
				switch NICName {
				case "NetworkInterface1":
					return network.Interface{
						ID: ptr.String("/subscriptions/subid/resourceGroups/rg1/providers/Microsoft.Network/networkInterfaces/NetworkInterface1"),
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
								{
									InterfaceIPConfigurationPropertiesFormat: &network.InterfaceIPConfigurationPropertiesFormat{
										PrivateIPAddress: ptr.String("192.168.0.2"),
										PublicIPAddress: &network.PublicIPAddress{
											ID: ptr.String("/subscriptions/subid/resourceGroups/rg1/providers/Microsoft.Network/publicIPAddresses/PublicIpAddress1B"),
										},
									},
								},
							},
						},
					}, nil
				case "NetworkInterface2":
					return network.Interface{
						ID: ptr.String("/subscriptions/subid/resourceGroups/rg1/providers/Microsoft.Network/networkInterfaces/NetworkInterface2"),
						InterfacePropertiesFormat: &network.InterfacePropertiesFormat{
							IPConfigurations: &[]network.InterfaceIPConfiguration{
								{
									InterfaceIPConfigurationPropertiesFormat: &network.InterfaceIPConfigurationPropertiesFormat{
										PrivateIPAddress: ptr.String("192.168.0.3"),
										PublicIPAddress: &network.PublicIPAddress{
											ID: ptr.String("/subscriptions/subid/resourceGroups/rg1/providers/Microsoft.Network/publicIPAddresses/PublicIpAddress2A"),
										},
									},
								},
							},
						},
					}, nil
				case "NetworkInterface3":
					return network.Interface{
						ID: ptr.String("/subscriptions/subid/resourceGroups/rg1/providers/Microsoft.Network/networkInterfaces/NetworkInterface3"),
						InterfacePropertiesFormat: &network.InterfacePropertiesFormat{
							IPConfigurations: &[]network.InterfaceIPConfiguration{
								{
									InterfaceIPConfigurationPropertiesFormat: &network.InterfaceIPConfigurationPropertiesFormat{
										PrivateIPAddress: ptr.String("192.168.0.4"),
										PublicIPAddress: &network.PublicIPAddress{
											ID: ptr.String("/subscriptions/subid/resourceGroups/rg1/providers/Microsoft.Network/publicIPAddresses/PublicIpAddress3A"),
										},
									},
								},
							},
						},
					}, nil
				default:
					return network.Interface{}, fmt.Errorf("nic not found: %s", ptr.ToString(nicReference.ID))
				}
			},
			getPublicIP: func(subscriptionID, resourceGroup string, ip network.InterfaceIPConfiguration) (*string, error) {
				publicIPID := ptr.ToString(ip.InterfaceIPConfigurationPropertiesFormat.PublicIPAddress.ID)
				publicIPName := strings.Split(publicIPID, "/")[len(strings.Split(publicIPID, "/"))-1]

				switch publicIPName {
				case "PublicIpAddress1A":
					return ptr.String("72.88.100.1"), nil
				case "PublicIpAddress1B":
					return ptr.String("72.88.100.2"), nil
				case "PublicIpAddress2A":
					return ptr.String("72.88.100.3"), nil
				case "PublicIpAddress3A":
					return ptr.String("72.88.100.4"), nil
				default:
					return nil, fmt.Errorf("public IP not found %s", publicIPName)
				}
			},
		},
	}
	fmt.Println()
	fmt.Println("[test case] Azure Instances Command")
	utils.MockFileSystem(true)
	for _, s := range subtests {
		getComputeVMsPerResourceGroupM = s.getComputeVMsPerResourceGroup
		getNICdetailsM = s.getNICdetails
		getPublicIPM = s.getPublicIP
		header, body := GetComputeRelevantData(s.subscription, s.resourceGroup)
		for rownIndex, row := range body {
			for columnIndex, element := range row {
				if element != s.expectedBody[rownIndex][columnIndex] {
					log.Fatalf("[%s] got %s, expected %s", s.name, element, s.expectedBody[rownIndex][columnIndex])
				}
			}
		}
		utils.OutputSelector(3, "table", header, body, constants.AZ_OUTPUT_DIRECTORY, fmt.Sprintf("instances_%s", s.resourceGroup), constants.AZ_INTANCES_MODULE_NAME, s.resourceGroup)
	}
	fmt.Println()
}
