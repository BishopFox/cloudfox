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

func GetComputeRelevantData(subscriptionID string, resourceGroup string) ([]string, [][]string) {
	header := []string{"Name", "ID", "Location", "Admin Username", "Private IP", "Public IP"}
	var body [][]string

	for _, vm := range getComputeVMsPerResourceGroupM(subscriptionID, resourceGroup) {
		var adminUsername string
		if vm.VirtualMachineProperties != nil && vm.OsProfile != nil {
			adminUsername = ptr.ToString(vm.OsProfile.AdminUsername)
		}
		privateIPs, publicIPs := getIPsM(subscriptionID, resourceGroup, vm)

		body = append(
			body,
			[]string{
				ptr.ToString(vm.Name),
				ptr.ToString(vm.ID),
				ptr.ToString(vm.Location),
				adminUsername,
				strings.Join(privateIPs, "\n"),
				strings.Join(publicIPs, "\n"),
			},
		)
	}
	return header, body
}

var getComputeVMsPerResourceGroupM = getComputeVMsPerResourceGroup

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

var getIPsM = getIPs

func getIPs(subscriptionID string, resourceGroup string, vm compute.VirtualMachine) ([]string, []string) {
	var privateIPs, publicIPs []string

	if vm.VirtualMachineProperties.NetworkProfile.NetworkInterfaces != nil {
		for _, nicReference := range *vm.VirtualMachineProperties.NetworkProfile.NetworkInterfaces {
			nic, err := getNICdetailsM(subscriptionID, resourceGroup, nicReference)
			if err != nil {
				return []string{"nicNotFound"}, []string{"nicNotFound"}
			}
			if nic.InterfacePropertiesFormat.IPConfigurations != nil {
				for _, ip := range *nic.InterfacePropertiesFormat.IPConfigurations {
					privateIPs = append(privateIPs, ptr.ToString(ip.InterfaceIPConfigurationPropertiesFormat.PrivateIPAddress))

					publicIP, err := getPublicIPM(subscriptionID, resourceGroup, ip)
					if err != nil {
						// error handling placeholder
					} else {
						publicIPs = append(publicIPs, publicIP)
					}
				}
			}
		}
	}
	return privateIPs, publicIPs
}

var getNICdetailsM = getNICdetails

func getNICdetails(subscriptionID string, resourceGroup string, nicReference compute.NetworkInterfaceReference) (network.Interface, error) {
	client := utils.GetNICClient(subscriptionID)
	NICName := strings.Split(ptr.ToString(nicReference.ID), "/")[len(strings.Split(ptr.ToString(nicReference.ID), "/"))-1]

	nic, err := client.Get(context.TODO(), resourceGroup, NICName, "")
	if err != nil {
		return network.Interface{}, err
	}

	return nic, nil
}

var getPublicIPM = getPublicIP

func getPublicIP(subscriptionID string, resourceGroup string, ip network.InterfaceIPConfiguration) (string, error) {
	client := utils.GetPublicIPclient(subscriptionID)
	publicIPID := ptr.ToString(ip.InterfaceIPConfigurationPropertiesFormat.PublicIPAddress.ID)
	publicIPName := strings.Split(publicIPID, "/")[len(strings.Split(publicIPID, "/"))-1]
	fmt.Println(publicIPName)
	publicIPExpanded, err := client.Get(context.TODO(), resourceGroup, publicIPName, "")
	if err != nil {
		return "", nil
	}
	return ptr.ToString(publicIPExpanded.PublicIPAddressPropertiesFormat.IPAddress), nil
}
