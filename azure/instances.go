package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/compute/mgmt/compute"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/network/mgmt/network"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/resources"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/subscriptions"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/utils"
	"github.com/aws/smithy-go/ptr"
	"github.com/fatih/color"
)

func AzRunInstancesCommand(AzSubFilter, AzRGFilter, AzOutputFormat string, AzVerbosity int) {
	tableHead := []string{"Subscription", "Resource Group", "Name", "Location", "Admin Username", "Private IP", "Public IP"}
	var tableBody [][]string
	var outputFile, outputMessagePrefix string

	// Enumerate VMs based on interactive menu selection
	if AzRGFilter == "interactive" && AzSubFilter == "interactive" {
		for _, scopeItem := range ScopeSelection(nil, "full") {
			_, tableBodyTemp := GetComputeRelevantData(scopeItem.Sub, scopeItem.ResourceGroup)
			tableBody = append(tableBody, tableBodyTemp[0])
		}
		outputFile = fmt.Sprintf("%s_interactiveMenuSelection", globals.AZ_INTANCES_MODULE_NAME)
		outputMessagePrefix = "multiple_selections"
	}
	// Enumerate VMs for a single subscription with the --subscription flag
	if AzRGFilter == "interactive" && AzSubFilter != "interactive" {
		fmt.Printf("[%s] Enumerating VMs for subscription: %s\n", color.CyanString(globals.AZ_INTANCES_MODULE_NAME), AzSubFilter)
		for _, sub := range GetSubscriptions() {
			if ptr.ToString(sub.DisplayName) == AzSubFilter {
				for _, rg := range GetResourceGroups(ptr.ToString(sub.SubscriptionID)) {
					_, tableBodyTemp := GetComputeRelevantData(sub, rg)
					tableBody = append(tableBody, tableBodyTemp[0])
				}
			}
		}
		outputFile = fmt.Sprintf("%s_sub_%s", globals.AZ_INTANCES_MODULE_NAME, AzSubFilter)
		outputMessagePrefix = fmt.Sprintf("sub:%s", AzSubFilter)
	}
	// Enumerate VMs for a single resource group with the --resource-group flag
	if AzRGFilter != "interactive" && AzSubFilter == "interactive" {
		fmt.Printf("[%s] Enumerating VMs for resource group: %s\n", color.CyanString(globals.AZ_INTANCES_MODULE_NAME), AzRGFilter)
		sub := GetSubscriptionForResourceGroup(AzRGFilter)
		_, tableBody = GetComputeRelevantData(sub, resources.Group{Name: ptr.String(AzRGFilter)})
		outputFile = fmt.Sprintf("%s_sub_%s", globals.AZ_INTANCES_MODULE_NAME, AzRGFilter)
		outputMessagePrefix = fmt.Sprintf("rg:%s", AzRGFilter)
	}

	// Prints output to screen and file
	utils.OutputSelector(AzVerbosity, AzOutputFormat, tableHead, tableBody, globals.CLOUDFOX_BASE_OUTPUT_DIRECTORY, outputFile, globals.AZ_INTANCES_MODULE_NAME, outputMessagePrefix)
}

func GetComputeRelevantData(sub subscriptions.Subscription, rg resources.Group) ([]string, [][]string) {
	header := []string{"Subscription", "Resource Group", "Name", "Location", "Admin Username", "Private IP", "Public IP"}
	var body [][]string

	for _, vm := range GetComputeVMsPerResourceGroup(ptr.ToString(sub.SubscriptionID), ptr.ToString(rg.Name)) {
		var adminUsername string
		if vm.VirtualMachineProperties != nil && vm.OsProfile != nil {
			adminUsername = ptr.ToString(vm.OsProfile.AdminUsername)
		}
		privateIPs, publicIPs := getIPs(ptr.ToString(sub.SubscriptionID), ptr.ToString(rg.Name), vm)

		body = append(
			body,
			[]string{
				ptr.ToString(sub.DisplayName),
				ptr.ToString(rg.Name),
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
	computeClient := utils.GetVirtualMachinesClient(subscriptionID)
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

					publicIP, err := GetPublicIP(subscriptionID, resourceGroup, ip)
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

var GetPublicIP = getPublicIP

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

/************* MOCKED FUNCTIONS BELOW (USE IT FOR UNIT TESTING) *************/

func MockedGetComputeVMsPerResourceGroup(subscriptionID, resourceGroup string) []compute.VirtualMachine {
	testFile, err := os.ReadFile(globals.VMS_TEST_FILE)
	if err != nil {
		log.Fatalf("could not read file %s", globals.VMS_TEST_FILE)
	}

	var vms []compute.VirtualMachine
	err = json.Unmarshal(testFile, &vms)
	if err != nil {
		log.Fatalf("could not unmarshall file %s", globals.VMS_TEST_FILE)
	}

	var results []compute.VirtualMachine
	for _, vm := range vms {
		vmSub := strings.Split(ptr.ToString(vm.ID), "/")[2]
		vmRG := strings.Split(ptr.ToString(vm.ID), "/")[4]
		if vmSub == subscriptionID && vmRG == resourceGroup {
			results = append(results, vm)
		}
	}
	return results
}

func MockedGetNICdetails(subscriptionID, resourceGroup string, nicReference compute.NetworkInterfaceReference) (network.Interface, error) {
	testFile, err := os.ReadFile(globals.NICS_TEST_FILE)
	if err != nil {
		log.Fatalf("could not read file %s", globals.NICS_TEST_FILE)
	}
	var nics []network.Interface
	err = json.Unmarshal(testFile, &nics)
	if err != nil {
		log.Fatalf("could not unmarshall file %s", globals.VMS_TEST_FILE)
	}
	nicName := strings.Split(ptr.ToString(nicReference.ID), "/")[len(strings.Split(ptr.ToString(nicReference.ID), "/"))-1]
	switch nicName {
	case "NetworkInterface1":
		return nics[0], nil
	case "NetworkInterface2":
		return nics[1], nil
	case "NetworkInterface3":
		return nics[2], nil
	case "NetworkInterface4":
		return nics[3], nil
	default:
		return network.Interface{}, fmt.Errorf("nic not found: %s", ptr.ToString(nicReference.ID))
	}
}

func MockedGetPublicIP(subscriptionID, resourceGroup string, ip network.InterfaceIPConfiguration) (*string, error) {
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
		return ptr.String("72.88.100.3"), nil
	case "PublicIpAddress4A":
		return ptr.String("72.88.100.4"), nil
	case "PublicIpAddress5A":
		return ptr.String("72.88.100.5"), nil
	default:
		return nil, fmt.Errorf("public IP not found %s", publicIPName)
	}
}
