package azure

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/compute/mgmt/compute"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/network/mgmt/network"
	"github.com/BishopFox/cloudfox/utils"
	"github.com/aws/smithy-go/ptr"
)

func GetComputeRelevantData(subscriptionID string, resourceGroupName string) ([]string, [][]string) {
	header := []string{"Name", "Location", "Admin Username", "Private IP", "Public IP"}
	var body [][]string

	// Format received from Azure: subscriptionID = "/subscriptions/0f39574d-d756-48cf-b622-0e27a6943bd2"
	subID := strings.Split(subscriptionID, "/")[len(strings.Split(subscriptionID, "/"))-1]

	for _, vm := range GetComputeVMsPerResourceGroup(subID, resourceGroupName) {
		var adminUsername string
		if vm.VirtualMachineProperties != nil && vm.OsProfile != nil {
			adminUsername = ptr.ToString(vm.OsProfile.AdminUsername)
		}
		privateIPs, publicIPs := getIPs(subID, resourceGroupName, vm)

		body = append(
			body,
			[]string{
				ptr.ToString(vm.Name),
				ptr.ToString(vm.Location),
				adminUsername,
				strings.Join(privateIPs, ","),
				strings.Join(publicIPs, ","),
			},
		)
	}
	return header, body
}

var GetComputeVMsPerResourceGroup = getComputeVMsPerResourceGroup

func getComputeVMsPerResourceGroup(subscriptionID string, resourceGroup string) []compute.VirtualMachine {
	computeClient := utils.GetComputeClient(subscriptionID)
	var vms []compute.VirtualMachine

	for page, err := computeClient.List(context.TODO(), resourceGroup); page.NotDone(); page.Next() {
		if err != nil {
			log.Fatalf("could not enumerate resource group %s. %s", resourceGroup, err)
		} else {

			vms = append(vms, page.Values()...)
		}
	}

	return vms
}

func getIPs(subscriptionID string, resourceGroup string, vm compute.VirtualMachine) ([]string, []string) {
	var privateIPs, publicIPs []string

	if vm.VirtualMachineProperties.NetworkProfile.NetworkInterfaces != nil {
		for _, nicReference := range *vm.VirtualMachineProperties.NetworkProfile.NetworkInterfaces {
			nic, err := GetNICdetails(subscriptionID, resourceGroup, nicReference)
			if err != nil {
				return []string{"nicNotFound"}, []string{"nicNotFound"}
			}
			if nic.InterfacePropertiesFormat.IPConfigurations != nil {
				for _, ip := range *nic.InterfacePropertiesFormat.IPConfigurations {
					privateIPs = append(
						privateIPs,
						ptr.ToString(
							ip.InterfaceIPConfigurationPropertiesFormat.PrivateIPAddress))

					publicIP, err := GetPublicIPM(subscriptionID, resourceGroup, ip)
					if err != nil {
						publicIPs = append(publicIPs, err.Error())
					} else {
						publicIPs = append(publicIPs, ptr.ToString(publicIP))
					}
				}
			}
		}
	}
	return privateIPs, publicIPs
}

var GetNICdetails = getNICdetails

func getNICdetails(subscriptionID string, resourceGroup string, nicReference compute.NetworkInterfaceReference) (network.Interface, error) {
	client := utils.GetNICClient(subscriptionID)
	NICName := strings.Split(ptr.ToString(nicReference.ID), "/")[len(strings.Split(ptr.ToString(nicReference.ID), "/"))-1]

	nic, err := client.Get(context.TODO(), resourceGroup, NICName, "")
	if err != nil {
		return network.Interface{}, err
	}

	return nic, nil
}

var GetPublicIPM = getPublicIP

func getPublicIP(subscriptionID string, resourceGroup string, ip network.InterfaceIPConfiguration) (*string, error) {
	client := utils.GetPublicIPclient(subscriptionID)
	publicIPID := ptr.ToString(ip.InterfaceIPConfigurationPropertiesFormat.PublicIPAddress.ID)
	publicIPName := strings.Split(publicIPID, "/")[len(strings.Split(publicIPID, "/"))-1]
	publicIPExpanded, err := client.Get(context.TODO(), resourceGroup, publicIPName, "")
	if err != nil {
		return nil, fmt.Errorf("IPNotFound:%s", publicIPName)
	}
	return publicIPExpanded.PublicIPAddressPropertiesFormat.IPAddress, nil
}
