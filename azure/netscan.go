package azure
// https://learn.microsoft.com/en-us/azure/virtual-network/network-security-group-how-it-works
// https://learn.microsoft.com/en-us/azure/virtual-network/application-security-groups
// https://learn.microsoft.com/en-us/azure/network-watcher/diagnose-vm-network-traffic-filtering-problem?toc=%2Fazure%2Fvirtual-network%2Ftoc.json
import (
	"github.com/BishopFox/cloudfox/internal"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/network/mgmt/network"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/compute/mgmt/compute"
	"github.com/Azure/go-autorest/autorest/azure"
	"strings"
	"github.com/aws/smithy-go/ptr"
	"context"
	"path/filepath"
	"fmt"
	"net"
	"os"
)

type AzNetScanModule struct {
	AzClient            *internal.AzureClient
	Log                 *internal.Logger
}


func (m *AzNetScanModule) AzNetScanCommand(sourceIP string) error {
	
	o := internal.OutputClient{
		Verbosity:    m.AzClient.AzVerbosity,
		CallingModule: "netscan",
		Table: internal.TableClient{
			Wrap: m.AzClient.AzWrapTable,
		},
	}

	if len(m.AzClient.AzResources) == 0 && sourceIP == "" {
		return fmt.Errorf("No resource ID or source IP address supplied")
	}
	if sourceIP != "" {
		m.Log.Warnf(nil, "Searching resources attached to IP %s, this might take a while", sourceIP)
	} else {
		for _, AzResource := range m.AzClient.AzResources {
			if AzResource.ResourceType == "virtualMachines" {
				m.Log.Infof(nil, "Starting network analysis for Virtual Machine %s", AzResource.ResourceName)
				m.processVM(AzResource.SubscriptionID, AzResource.ResourceGroup, AzResource.ResourceName)
			} else {
				m.Log.Errorf(nil, "Resource type %s / %s not implemented", AzResource.Provider, AzResource.ResourceType)
				continue
			}
		}
	}

	o.WriteFullOutput(o.Table.TableFiles, nil)
	return nil
}


func (m *AzNetScanModule) processVM(subscriptionID string, resourceGroupName string, VMName string) {
	computeClient := internal.GetVirtualMachinesClient(subscriptionID)
	vm, err := computeClient.Get(context.TODO(), resourceGroupName, VMName, "")
	targetSubnets := []string{}
	targetSubnetsAlt := make(map[string][]string)
	vmSubscriptionIDs := make(map[string]bool)
	vmSubscriptionIDs[subscriptionID] = true
	if err != nil {
		m.Log.Errorf([]string{VMName}, "Could not fetch virtual machine details")
		return
	} else {
		if vm.VirtualMachineProperties.NetworkProfile.NetworkInterfaces != nil {
			for _, nicReference := range *vm.VirtualMachineProperties.NetworkProfile.NetworkInterfaces {
				nic, err := getNICdetails(subscriptionID, resourceGroupName, nicReference, "networkSecurityGroup")
				if err != nil {
					m.Log.Warnf([]string{VMName}, "Could not get details of network interface %s", *nicReference.ID)
					continue
				}
				if nic.InterfacePropertiesFormat.IPConfigurations == nil {
					m.Log.Warn([]string{VMName, *nic.Name}, "Interface has no IP address configured")
					continue
				}
				if nic.InterfacePropertiesFormat.NetworkSecurityGroup != nil {
					m.Log.Infof([]string{VMName, *nic.Name}, "Linked to NSG %s", *nic.InterfacePropertiesFormat.NetworkSecurityGroup.Name)
				}
				//var subnet *network.Subnet
				for _, ip := range *nic.InterfacePropertiesFormat.IPConfigurations {
					if ip.InterfaceIPConfigurationPropertiesFormat.PrivateIPAddress == nil {
						m.Log.Warn([]string{VMName, *nic.Name}, "Empty IP configuration")
						continue
					}
					ipConfig := ip.InterfaceIPConfigurationPropertiesFormat
					m.Log.Infof([]string{VMName, *nic.Name}, "Interface assigned with address %s", *ipConfig.PrivateIPAddress)
					subnet := *ipConfig.Subnet
					subnetRGName := strings.Split(*subnet.ID, "/")[4]
					VNETName := strings.Split(*subnet.ID, "/")[8]
					subnetName := strings.Split(*subnet.ID, "/")[10]
					subnet, err := getSubnetDetails(subscriptionID, subnetRGName, VNETName, subnetName, "networkSecurityGroup")
					if err != nil {
						m.Log.Warnf([]string{VMName, *nic.Name, *ipConfig.PrivateIPAddress}, "Unable to get subnet %s details", subnetName)
						continue
					}
					if subnet.SubnetPropertiesFormat.NetworkSecurityGroup != nil {
						m.Log.Infof([]string{VMName, *nic.Name, *ipConfig.PrivateIPAddress}, "Linked to NSG %s through subnet %s", *subnet.SubnetPropertiesFormat.NetworkSecurityGroup.Name, *subnet.Name)
					}
					m.Log.Infof([]string{VMName, *nic.Name, *ipConfig.PrivateIPAddress}, "Subnet %s, in Virtual Network %s", subnetName, VNETName)
					vnet, err := getVNET(subscriptionID, subnetRGName, VNETName, "")
					if err != nil {
						m.Log.Warnf([]string{VMName, *nic.Name, *ipConfig.PrivateIPAddress, *subnet.Name}, "Unable to get Virtual Network %s details", VNETName)
						continue
					}
					m.Log.Infof([]string{VMName, *nic.Name, *ipConfig.PrivateIPAddress}, "Virtual Network %s has %s subnets as potential targets", VNETName, len(*vnet.VirtualNetworkPropertiesFormat.Subnets))
					for _, subnet := range *vnet.VirtualNetworkPropertiesFormat.Subnets {
						m.Log.Infof([]string{VMName, *nic.Name, *ipConfig.PrivateIPAddress}, "Potential target : %s", *subnet.SubnetPropertiesFormat.AddressPrefix)
						targetSubnets = append(targetSubnets, *subnet.SubnetPropertiesFormat.AddressPrefix)
						targetSubnetsAlt[*subnet.SubnetPropertiesFormat.AddressPrefix] = []string{}
					}
					for _, peering := range *vnet.VirtualNetworkPropertiesFormat.VirtualNetworkPeerings {
						remoteVnetID := *peering.VirtualNetworkPeeringPropertiesFormat.RemoteVirtualNetwork.ID
						remoteVnetResource, _ := azure.ParseResourceID(remoteVnetID)
						vmSubscriptionIDs[remoteVnetResource.SubscriptionID] = true
						if !*peering.VirtualNetworkPeeringPropertiesFormat.AllowForwardedTraffic {
							m.Log.Warnf([]string{VMName, *nic.Name, *ipConfig.PrivateIPAddress, *subnet.Name}, "Peering to Virtual Network %s is disabled", remoteVnetResource.ResourceName)
						} else {
							m.Log.Successf([]string{VMName, *nic.Name, *ipConfig.PrivateIPAddress, *subnet.Name}, "Peering to Virtual Network %s is active : %s",
								remoteVnetResource.ResourceName, stringAndArrayToString(nil, peering.VirtualNetworkPeeringPropertiesFormat.RemoteAddressSpace.AddressPrefixes, " "))
							for _, addressPrefix := range *peering.VirtualNetworkPeeringPropertiesFormat.RemoteAddressSpace.AddressPrefixes {
								targetSubnets = append(targetSubnets, addressPrefix)
								targetSubnetsAlt[addressPrefix] = []string{}
							}
						}
					}

				}
			}
		m.Log.Info([]string{VMName}, "Narrowing down potential target subnets with running compute instances...")
		var vms []compute.VirtualMachine
		for subscriptionID, _ := range vmSubscriptionIDs {
			subscriptionVMs, err := getComputeVMsPerSubscription(subscriptionID)
			if err != nil {
				m.Log.Warnf([]string{VMName}, "Unable to enumerate VMs in subscription %s", subscriptionID)
				continue
			}
			vms = append(vms, subscriptionVMs...)
		}
		for i, vm := range vms {
			fmt.Printf("Processing machine %d%%\r", 100*i/len(vms))
			vmResource, _ := azure.ParseResourceID(*vm.ID)
			vmDetails, err := getComputeVmInstanceView(subscriptionID, vmResource.ResourceGroup, ptr.ToString(vm.Name))
			if err != nil {
				m.Log.Warnf([]string{VMName}, "Unable to fetch VM %s details", ptr.ToString(vm.Name))
				continue
			}
			if vmDetails.VirtualMachineProperties != nil && vmDetails.VirtualMachineProperties.InstanceView != nil {
				for _, status := range *vmDetails.VirtualMachineProperties.InstanceView.Statuses {
					if *status.Code == "PowerState/running" {
						privateIPs, _ := getIPs(subscriptionID, vmResource.ResourceGroup, vm)
						for targetSubnet, _ := range targetSubnetsAlt {
							_, ipnet, _ := net.ParseCIDR(targetSubnet)
							for _, privateIP := range privateIPs {
								ip := net.ParseIP(privateIP)
								if ipnet.Contains(ip) {
									targetSubnetsAlt[targetSubnet] = append(targetSubnetsAlt[targetSubnet], privateIP)
								}
							}
						}
						break
					}
				}
			}
		}
		for targetSubnet, targets := range targetSubnetsAlt {
			m.Log.Infof([]string{VMName}, "%s subnet has %s addresses", targetSubnet, len(targets))
		}
		m.writeScanFile(VMName, targetSubnetsAlt)
		} else {
			m.Log.Errorf(nil, "Virtual Machine %s has no network interface", VMName)
			return
		}
	}
}

func (m *AzNetScanModule) filterVM(vm compute.VirtualMachine) {

}
func getComputeVMsPerSubscription(subscriptionID string) ([]compute.VirtualMachine, error) {
	computeClient := internal.GetVirtualMachinesClient(subscriptionID)
	var vms []compute.VirtualMachine

	for _, rg := range GetResourceGroups(subscriptionID) {
		for page, err := computeClient.List(context.TODO(), ptr.ToString(rg.Name), ""); page.NotDone(); page.Next() {
			if err != nil {
				return nil, fmt.Errorf("could not enumerate resource group %s. %s", rg, err)
			} else {

				vms = append(vms, page.Values()...)
			}
		}
	}
	return vms, nil
}

func (m *AzNetScanModule) writeScanFile(vm string, targetSubnetsAlt map[string][]string) error {
	lootDirectory := filepath.Join(m.AzClient.AzOutputDirectory, "loot")
	lootFilePath := filepath.Join(lootDirectory, fmt.Sprintf("scan-from-%s.txt", vm))
	err := os.MkdirAll(lootDirectory, os.ModePerm)
	if err != nil {
		return err
	}

	file, err := os.Create(lootFilePath)
	if err != nil {
		return err
	}
	defer file.Close()

	for targetSubnet, targets := range targetSubnetsAlt {
		cleanSubnet := strings.Replace(targetSubnet, "/", "_", -1)
		_, err := file.WriteString(fmt.Sprintf("nmap -p- --max-retries 1 -T4 -Pn -sV -sC -oA %s -iL %s.lst\n", cleanSubnet, cleanSubnet))
		if err != nil {
			return err
		}
		targetsFile, err := os.Create(filepath.Join(lootDirectory, fmt.Sprintf("%s.lst", cleanSubnet)))
		if err != nil {
			return err
		}
		defer targetsFile.Close()
		for _, target := range targets {
			targetsFile.WriteString(fmt.Sprintf("%s\n", target))
		}
	}
	m.Log.Successf(nil, "Scan file written to %s", lootFilePath)
	return nil
}

func getSubnetDetails(subscriptionID, resourceGroup, VNETName, subnetName, expand string) (network.Subnet, error) {
	client := internal.GetSubnetsClient(subscriptionID)
	subnet, err := client.Get(context.TODO(), resourceGroup, VNETName, subnetName, expand)
	if err != nil {
		return network.Subnet{}, err
	}
	return subnet, nil
}

func getVNET(subscriptionID, resourceGroup, VNETName, expand string) (network.VirtualNetwork, error) {
	client := internal.GetVNETsClient(subscriptionID)
	subnet, err := client.Get(context.TODO(), resourceGroup, VNETName, expand)
	if err != nil {
		return network.VirtualNetwork{}, err
	}
	return subnet, nil
}
