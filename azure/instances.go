package azure

import (
	"context"
	"log"
	"strings"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/compute/mgmt/compute"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/network/mgmt/network"
	"github.com/BishopFox/cloudfox/utils"
	"github.com/aws/smithy-go/ptr"
)

/*
func() (table.Row, []table.Row)
header := table.Row{"Name", "Location", "Admin User Name"}
var body []table.Row

body = append(
			body,
			table.Row{
				ptr.ToString(vm.Name),
				ptr.ToString(vm.Location),
				ptr.ToString(vm.VirtualMachineProperties.OsProfile.AdminUsername),
			},
		)
return header, body
*/

type ComputeRelevantData struct {
	Name          string
	Id            string
	Location      string
	AdminUsername string
	PrivateIPs    string
	PublicIPs     string
}

func GetComputeRelevantData(subscriptionID string, resourceGroup string) []ComputeRelevantData {
	var results []ComputeRelevantData

	for _, vm := range getComputeVMsPerResourceGroupM(subscriptionID, resourceGroup) {
		var adminUsername string
		if vm.VirtualMachineProperties != nil && vm.OsProfile != nil {
			adminUsername = ptr.ToString(vm.OsProfile.AdminUsername)
		}
		privateIPs, publicIPs := getIPs(subscriptionID, resourceGroup, vm)
		results = append(results, ComputeRelevantData{
			Name:          ptr.ToString(vm.Name),
			Id:            ptr.ToString(vm.ID),
			Location:      ptr.ToString(vm.Location),
			AdminUsername: adminUsername,
			PrivateIPs:    strings.Join(privateIPs, "\n"),
			PublicIPs:     strings.Join(publicIPs, "\n"),
		})
	}
	return results
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

var GetNICdetailsM = getNICdetails

func getIPs(subscriptionID string, resourceGroup string, vm compute.VirtualMachine) ([]string, []string) {
	// Cross reference NIC with IP addresses here

	return []string{"1.1.1.1", "2.2.2.2"}, []string{"3.3.3.3", "4.4.4.4"}
}

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

func getPublicIP(subscriptionID string, resourceGroup string, ipConfig *[]network.InterfaceIPConfiguration) []string {
	client := utils.GetPublicIPclient(subscriptionID)
	var results []string
	if ipConfig == nil {
		return results
	}

	for _, ip := range *ipConfig {
		publicIPID := ptr.ToString(ip.InterfaceIPConfigurationPropertiesFormat.PublicIPAddress.ID)
		publicIPName := strings.Split(publicIPID, "/")[len(strings.Split(publicIPID, "/"))-1]
		publicIPProperties, err := client.Get(context.TODO(), resourceGroup, publicIPName, "")
		if err == nil {
			results = append(results, ptr.ToString(publicIPProperties.PublicIPAddressPropertiesFormat.IPAddress))
		}
	}
	return results
}
