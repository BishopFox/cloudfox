package azure

import (
	"context"
	"log"
	"strings"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/compute/mgmt/compute"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/network/mgmt/network"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/aws/smithy-go/ptr"
	"github.com/jedib0t/go-pretty/table"
)

// verbosity = 1 (control messages only).
// verbosity = 2 (control messages and module output).
// verbosity = 3 (control messages, module output and loot file output).
func GetInstancesDataPerResourceGroup(subscriptionID string, resourceGroup string) (table.Row, []table.Row) {
	header := table.Row{"Name", "Location", "Admin User Name"}
	var body []table.Row

	log.Println("[*] Querying Azure for compute instances data...")
	for _, vm := range GetComputeVMsPerResourceGroup(subscriptionID, resourceGroup) {
		var adminUserName string
		if vm.VirtualMachineProperties != nil && vm.OsProfile != nil {
			adminUserName = ptr.ToString(vm.VirtualMachineProperties.OsProfile.AdminUsername)
		}

		body = append(
			body,
			table.Row{
				ptr.ToString(vm.Name),
				ptr.ToString(vm.Location),
				adminUserName,
			},
		)
	}
	log.Println("[+] ...done!")
	return header, body
}

func createComputeClient(subscriptionID string) compute.VirtualMachinesClient {
	log.Printf("[*] Creating Compute client for subscription %s.", subscriptionID)
	client := compute.NewVirtualMachinesClient(subscriptionID)
	authorizer, err := auth.NewAuthorizerFromCLIWithResource("https://management.azure.com/")
	if err != nil {
		log.Fatalf("[-] Failed to obtain Authorizer to create the Compute client for subscription %s. Error: %s", subscriptionID, err)
	}
	client.Authorizer = authorizer
	return client
}

var GetComputeVMsPerResourceGroup = getComputeVMsPerResourceGroup

// Use the GetComputeVMsPerResourceGroup variable to mock this function when unit testing.
func getComputeVMsPerResourceGroup(subscriptionID string, resourceGroup string) []compute.VirtualMachine {
	log.Printf("[*] Enumerating resource group%s", resourceGroup)
	computeClient := createComputeClient(subscriptionID)
	var vms []compute.VirtualMachine

	for page, err := computeClient.List(context.TODO(), resourceGroup); page.NotDone(); page.Next() {
		if err != nil {
			log.Fatalf("[-] Could not enumerate resource group %s. %s", resourceGroup, err)
		} else {
			vms = append(vms, page.Values()...)
		}
	}
	return vms
}

func createNICClient(subscriptionID string) network.InterfacesClient {
	log.Printf("[*] Creating NIC client for subscription %s.", subscriptionID)
	client := network.NewInterfacesClient(subscriptionID)
	authorizer, err := auth.NewAuthorizerFromCLIWithResource("https://management.azure.com/")
	if err != nil {
		log.Fatalf("[-] Failed to obtain Authorizer to create the Network Interfaces client for subscription %s. Error: %s", subscriptionID, err)
	}
	client.Authorizer = authorizer
	return client
}

var GetNICdetails = getNICdetails

// Use the GetNICdetails variable to mock this function when unit testing.
func getNICdetails(subscriptionID string, resourceGroup string, nic compute.NetworkInterfaceReference) (network.Interface, error) {
	client := createNICClient(subscriptionID)
	NICName := strings.Split(ptr.ToString(nic.ID), "/")[len(strings.Split(ptr.ToString(nic.ID), "/"))-1]

	NICExpanded, err := client.Get(context.TODO(), resourceGroup, NICName, "")
	if err != nil {
		return network.Interface{}, err
	}

	return NICExpanded, nil
}

func createPublicIPClient(subscriptionID string) network.PublicIPAddressesClient {
	log.Printf("[*] Creating NIC client for subscription %s.", subscriptionID)
	client := network.NewPublicIPAddressesClient(subscriptionID)
	authorizer, err := auth.NewAuthorizerFromCLIWithResource("https://management.azure.com/")
	if err != nil {
		log.Fatalf("[-] Failed to obtain Authorizer to create the Public IPs client for subscription %s. Error: %s", subscriptionID, err)
	}
	client.Authorizer = authorizer
	return client
}

var GetPublicIP = getPublicIP

// Use the GetPublicIP variable to mock this function when unit testing.
func getPublicIP(subscriptionID string, resourceGroup string, ip network.InterfaceIPConfiguration) (string, error) {
	client := createPublicIPClient(subscriptionID)
	publicIPID := ptr.ToString(ip.InterfaceIPConfigurationPropertiesFormat.PublicIPAddress.ID)
	publicIPName := strings.Split(publicIPID, "/")[len(strings.Split(publicIPID, "/"))-1]

	publicIPProperties, err := client.Get(context.TODO(), resourceGroup, publicIPName, "")
	if err != nil {
		return "", err
	}

	return ptr.ToString(publicIPProperties.PublicIPAddressPropertiesFormat.IPAddress), nil
}
