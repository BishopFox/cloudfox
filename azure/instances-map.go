package azure

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/compute/mgmt/compute"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/network/mgmt/network"
	"github.com/BishopFox/cloudfox/constants"
	"github.com/BishopFox/cloudfox/utils"
	"github.com/aws/smithy-go/ptr"
)

type InstancesMapModule struct {
	// Tenants, Subs and RGs: map[TenantID]map[SubscriptionID][]ResourceGroups
	Scope map[string]map[string][]string

	// This module queries 3 different resource types (Compute, NIC and PublicIP), thus 3 different clients.
	computeClient  compute.VirtualMachinesClient
	nicClient      network.InterfacesClient
	publicIPClient network.PublicIPAddressesClient
	// Module's Results
	results []vmRelevantInformation
}

type vmRelevantInformation struct {
	subscriptionID  string
	resourceGroup   string
	name            string
	adminUsername   string
	operatingSystem string
	internalIPs     []string
	externalIPs     []string
}

func (m *InstancesMapModule) InstancesMap(verbosity int, outputFormat string, outputDirectory string, resourceGroupFilter string) {
	for tenantID, subscriptionsMap := range m.Scope {
		fmt.Printf("[*] Started tenant: %s\n", tenantID)
		for subscriptionID := range subscriptionsMap {
			m.getVMsDataPerSubscription(tenantID, subscriptionID, resourceGroupFilter)
			fmt.Printf("[*] Enumerating subscription %s... done!\n", subscriptionID)
		}
		fmt.Printf("[*] Finished tenant: %s\n\n", tenantID)
	}

	fmt.Printf("\n[*] Preparing output...\n\n")
	// Prepare table headers
	header := []string{
		"RESOURCE_GROUP",
		"NAME",
		"OS",
		"ADMIN_USERNAME",
		"INTERNAL_IPS",
		"EXTERNAL_IPS",
	}

	// Prepare table body
	var body [][]string
	for _, result := range m.results {
		body = append(
			body,
			[]string{
				result.resourceGroup,
				result.name,
				result.operatingSystem,
				result.adminUsername,
				strings.Join(result.internalIPs, ", "),
				strings.Join(result.externalIPs, ", "),
				//Use the format below if you don't like the array format on output
				//strings.Join(result.internalIPs, ", "),
				//strings.Join(result.externalIPs, ", "),
			},
		)
	}
	// Pretty prints output
	//m.output.OutputSelector(outputFormat)
	utils.OutputSelector(
		verbosity,
		outputFormat,
		header,
		body,
		outputDirectory,
		"instances",
		"RG_PLACEHOLDER",
		constants.AZ_INTANCES_MODULE_NAME,
	)
}

func (m *InstancesMapModule) setNecessaryClients(subscriptionID string) {
	a := utils.AzNewResourceManagerAuthorizer()

	m.computeClient = compute.NewVirtualMachinesClient(subscriptionID)
	m.computeClient.Authorizer = a

	m.nicClient = network.NewInterfacesClient(subscriptionID)
	m.nicClient.Authorizer = a

	m.publicIPClient = network.NewPublicIPAddressesClient(subscriptionID)
	m.publicIPClient.Authorizer = a
}

func (m *InstancesMapModule) getVMsDataPerSubscription(tenantID string, subscriptionID string, resourceGroupFilter string) {
	m.setNecessaryClients(subscriptionID)
	for _, rg := range m.Scope[tenantID][subscriptionID] {
		if resourceGroupFilter == "all" || resourceGroupFilter == rg {
			m.getVMsDataPerResourceGroup(subscriptionID, rg)
		}
	}
}

type ListAPIClientInterface interface {
	List(ctx context.Context, resourceGroupName string) (result compute.VirtualMachineListResultPage, err error)
}

func (m *InstancesMapModule) getVMsDataPerResourceGroup(subscriptionID string, resourceGroup string) {
	var vmData vmRelevantInformation
	for page, err := m.computeClient.List(context.TODO(), resourceGroup); page.NotDone(); page.Next() {
		if err != nil {
			fmt.Printf("[-] Could not enumerate resource group %s. Skipping it. %s\n", resourceGroup, err)
		} else {
			for _, vm := range page.Values() {
				vmData.subscriptionID = subscriptionID
				vmData.resourceGroup = resourceGroup
				vmData.name = ptr.ToString(vm.Name)
				vmData.adminUsername = ptr.ToString(vm.VirtualMachineProperties.OsProfile.AdminUsername)
				vmData.operatingSystem = ptr.ToString(vm.VirtualMachineProperties.StorageProfile.ImageReference.Offer) + " " + ptr.ToString(vm.VirtualMachineProperties.StorageProfile.ImageReference.Sku)

				if vm.VirtualMachineProperties.NetworkProfile.NetworkInterfaces != nil {
					for _, nic := range *vm.VirtualMachineProperties.NetworkProfile.NetworkInterfaces {
						internalIP, externalIP := m.getNICInternalAndExternalIPs(nic, resourceGroup)
						vmData.internalIPs = append(vmData.internalIPs, internalIP)
						if externalIP != "" {
							vmData.externalIPs = append(vmData.externalIPs, externalIP)
						}
					}
				} else {
					vmData.internalIPs = append(vmData.internalIPs, "Error: NICnotFound")
					vmData.externalIPs = append(vmData.externalIPs, "Error: NICnotFound")
				}

				m.results = append(m.results, vmData)
				vmData.internalIPs = nil
				vmData.externalIPs = nil
			}
		}
	}
}

func (m *InstancesMapModule) getNICInternalAndExternalIPs(nic compute.NetworkInterfaceReference, resourceGroup string) (internalIP string, externalIP string) {
	var internal, external string

	NICName := strings.Split(ptr.ToString(nic.ID), "/")[len(strings.Split(ptr.ToString(nic.ID), "/"))-1]
	NICExpanded, err := m.nicClient.Get(context.TODO(), resourceGroup, NICName, "")
	if err != nil {
		return "Error: NICnotFound", "Error: NICnotFound"
	}

	if NICExpanded.InterfacePropertiesFormat.IPConfigurations != nil {

		for _, ip := range *NICExpanded.InterfacePropertiesFormat.IPConfigurations {
			internal = ptr.ToString(ip.InterfaceIPConfigurationPropertiesFormat.PrivateIPAddress)

			if ip.InterfaceIPConfigurationPropertiesFormat.PublicIPAddress != nil {
				publicIPID := ptr.ToString(ip.InterfaceIPConfigurationPropertiesFormat.PublicIPAddress.ID)
				publicIPName := strings.Split(publicIPID, "/")[len(strings.Split(publicIPID, "/"))-1]
				publicIPExpanded, err := m.publicIPClient.Get(context.TODO(), resourceGroup, publicIPName, "")
				if err == nil {
					external = ptr.ToString(publicIPExpanded.PublicIPAddressPropertiesFormat.IPAddress)
				}
			} else {
				external = ""
			}
		}
	}
	return internal, external
}
