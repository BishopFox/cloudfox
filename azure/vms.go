package azure

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/compute/mgmt/compute"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/network/mgmt/network"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/resources"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/subscriptions"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/smithy-go/ptr"
)

type AzVMsModule struct {
	AzClient            *internal.AzureClient
	Log                 *internal.Logger
}


func (m *AzVMsModule) AzVMsCommand() error {

	o := internal.OutputClient{
		Verbosity:    m.AzClient.AzVerbosity,
		CallingModule: globals.AZ_VMS_MODULE_NAME,
		Table: internal.TableClient{
			Wrap: m.AzClient.AzWrapTable,
		},
	}

	if len(m.AzClient.AzTenants) > 0 {
		// cloudfox azure inventory --tenant [TENANT_ID | PRIMARY_DOMAIN]
		for _, AzTenant := range m.AzClient.AzTenants {

			if m.AzClient.AzMergedTable {
				// set up table vars
				var header []string
				var body [][]string
				var userData string

				o := internal.OutputClient{
					Verbosity:     m.AzClient.AzVerbosity,
					CallingModule: globals.AZ_INVENTORY_MODULE_NAME,
					Table: internal.TableClient{
						Wrap: m.AzClient.AzWrapTable,
					},
				}

				m.Log.Infof(nil, "Enumerating VMs for tenant %s (%s)", ptr.ToString(AzTenant.DefaultDomain), ptr.ToString(AzTenant.TenantID))

				o.PrefixIdentifier = ptr.ToString(AzTenant.DefaultDomain)
				o.Table.DirectoryName = filepath.Join(m.AzClient.AzOutputDirectory, globals.CLOUDFOX_BASE_DIRECTORY, globals.AZ_DIR_BASE, ptr.ToString(AzTenant.DefaultDomain), "1-tenant-level")

				//populate the table data
				header, body, userData = m.getVMsPerTenantID(ptr.ToString(AzTenant.TenantID))

				o.Table.TableFiles = append(o.Table.TableFiles,
					internal.TableFile{
						Header: header,
						Body:   body,
						Name:   fmt.Sprintf(globals.AZ_VMS_MODULE_NAME)})

				if body != nil {
					if userData != "" {
						o.Loot.DirectoryName = filepath.Join(m.AzClient.AzOutputDirectory, globals.CLOUDFOX_BASE_DIRECTORY, globals.AZ_DIR_BASE, ptr.ToString(AzTenant.DefaultDomain), "loot")
						o.Loot.LootFiles = append(o.Loot.LootFiles,
							internal.LootFile{
								Contents: userData,
								Name:     "virtualmachines-user-data"})
						o.WriteFullOutput(o.Table.TableFiles, o.Loot.LootFiles)
						fmt.Println()
					} else {
						o.WriteFullOutput(o.Table.TableFiles, nil)
						fmt.Println()
					}
				}
			} else {
				for _, AzSubscription := range GetSubscriptionsPerTenantID(ptr.ToString(AzTenant.TenantID)) {
					m.runVMsCommandForSingleSubscription(*AzTenant.DefaultDomain, &AzSubscription)
				}
			}
		} 
	} else {
		// ./cloudfox azure inventory --subscription [SUBSCRIPTION_ID | SUBSCRIPTION_NAME]
		for tenantSlug, AzSubscriptions := range m.AzClient.AzSubscriptionsAlt {
			for _, AzSubscription := range AzSubscriptions {
				m.runVMsCommandForSingleSubscription(tenantSlug, AzSubscription)
			}
		}
	}
	o.WriteFullOutput(o.Table.TableFiles, nil)
	return nil
}

func (m *AzVMsModule) runVMsCommandForSingleSubscription(tenantSlug string, AzSubscription *subscriptions.Subscription) error {
	// set up table vars
	var header []string
	var body [][]string
	var userData string

	o := internal.OutputClient{
		Verbosity:     m.AzClient.AzVerbosity,
		CallingModule: globals.AZ_VMS_MODULE_NAME,
		Table: internal.TableClient{
			Wrap: m.AzClient.AzWrapTable,
		},
	}
	o.PrefixIdentifier = *AzSubscription.DisplayName
	o.Table.DirectoryName = filepath.Join(m.AzClient.AzOutputDirectory, globals.CLOUDFOX_BASE_DIRECTORY, globals.AZ_DIR_BASE, tenantSlug, *AzSubscription.DisplayName)

	m.Log.Infof(nil, "Enumerating VMs in subscription %s (%s)", *AzSubscription.DisplayName, *AzSubscription.SubscriptionID)

	// populate the table data
	header, body, userData = m.getVMsPerSubscriptionID(tenantSlug, AzSubscription)

	o.Table.TableFiles = append(o.Table.TableFiles,
		internal.TableFile{
			Header: header,
			Body:   body,
			Name:   fmt.Sprintf(globals.AZ_VMS_MODULE_NAME)})

	if body != nil {
		if userData != "" {
			o.Loot.DirectoryName = filepath.Join(m.AzClient.AzOutputDirectory, globals.CLOUDFOX_BASE_DIRECTORY, globals.AZ_DIR_BASE, tenantSlug, *AzSubscription.DisplayName, "loot")
			o.Loot.LootFiles = append(o.Loot.LootFiles,
				internal.LootFile{
					Contents: userData,
					Name:     "virtualmachines-user-data"})
			o.WriteFullOutput(o.Table.TableFiles, o.Loot.LootFiles)
			fmt.Println()
		} else {

			o.WriteFullOutput(o.Table.TableFiles, nil)
			fmt.Println()
		}

	}

	return nil
}

func (m *AzVMsModule) getVMsPerTenantID(AzTenantID string) ([]string, [][]string, string) {
	var resultsHeader []string
	var resultsBody, b [][]string
	var userDataCombined, userData string
	var err error

	for _, s := range GetSubscriptionsPerTenantID(AzTenantID) {
		for _, rg := range GetResourceGroups(ptr.ToString(s.SubscriptionID)) {
			resultsHeader, b, userData, err = m.getComputeRelevantData(s, rg)
			if err != nil {
				m.Log.Warnf(nil, "Could not enumerate VMs for resource group %s in subscription %s", ptr.ToString(rg.Name), ptr.ToString(s.SubscriptionID))
			} else {
				resultsBody = append(resultsBody, b...)
				userDataCombined += userData
			}
		}
	}
	return resultsHeader, resultsBody, userDataCombined
}

func (m *AzVMsModule) getVMsPerSubscriptionID(tenantSlug string, AzSubscription *subscriptions.Subscription) ([]string, [][]string, string) {
	var resultsHeader []string
	var resultsBody, b [][]string
	var userDataCombined, userData string
	var err error

	for _, rg := range GetResourceGroups(ptr.ToString(AzSubscription.SubscriptionID)) {
		resultsHeader, b, userData, err = m.getComputeRelevantData(*AzSubscription, rg)
		if err != nil {
			m.Log.Warnf(nil, "Could not enumerate VMs for resource group %s in subscription %s", ptr.ToString(rg.Name), ptr.ToString(AzSubscription.SubscriptionID))
		} else {
			resultsBody = append(resultsBody, b...)
			userDataCombined += userData
		}
	}
	return resultsHeader, resultsBody, userDataCombined
}

func (m *AzVMsModule) getComputeRelevantData(sub subscriptions.Subscription, rg resources.Group) ([]string, [][]string, string, error) {
	header := []string{"Subscription Name", "VM Name", "VM Location", "Private IPs", "Public IPs", "Admin Username", "Resource Group Name"}
	var body [][]string
	var userDataString string

	// User has requested specific resource groups, filtering
	if len(m.AzClient.AzRGs) > 0 {
		for _, AzRG := range m.AzClient.AzRGs {
			if *rg.Name == *AzRG.Name {
				goto ADD_RESOURCE
			}
		}
		return header, body, userDataString, nil
	}
	ADD_RESOURCE:

	subscriptionID := ptr.ToString(sub.SubscriptionID)
	subscriptionName := ptr.ToString(sub.DisplayName)
	resourceGroupName := ptr.ToString(rg.Name)

	vms, err := m.getComputeVMsPerResourceGroup(subscriptionID, resourceGroupName)
	if err != nil {
		return nil, nil, "", fmt.Errorf("error fetching vms for resource group %s: %s", resourceGroupName, err)
	}

	for _, vm := range vms {
		var adminUsername string
		if vm.VirtualMachineProperties != nil && vm.OsProfile != nil {
			adminUsername = ptr.ToString(vm.OsProfile.AdminUsername)
		}
		privateIPs, publicIPs := getIPs(ptr.ToString(sub.SubscriptionID), ptr.ToString(rg.Name), vm)
		// get userdata
		vmDetails, err := getComputeVmInfo(subscriptionID, resourceGroupName, ptr.ToString(vm.Name))
		if err != nil {
			fmt.Println("error fetching vm details for vm: ", ptr.ToString(vm.Name))
		}

		if vmDetails.VirtualMachineProperties != nil && vmDetails.VirtualMachineProperties.UserData != nil {
			userData, err := base64.StdEncoding.DecodeString(ptr.ToString(vmDetails.VirtualMachineProperties.UserData))
			if err != nil {
				fmt.Println("error decoding userdata for vm: ", ptr.ToString(vm.Name))
			}
			//append userdata from this vm to the string with headers and newlines for VM name, location, and resource group name
			userDataString += fmt.Sprintf(
				"===============================================================\n"+
					"VM Name: %s\n"+
					"Subscription Name: %s\n"+
					"VM Location: %s\n"+
					"Resource Group Name: %s\n\n"+
					"UserData:\n%s\n\n",
				ptr.ToString(vm.Name),
				ptr.ToString(sub.DisplayName),
				ptr.ToString(vmDetails.Location),
				ptr.ToString(rg.Name),
				string(userData),
			)

		}

		body = append(
			body,
			[]string{
				subscriptionName,
				ptr.ToString(vm.Name),
				ptr.ToString(vm.Location),
				strings.Join(privateIPs, "\n"),
				strings.Join(publicIPs, "\n"),
				adminUsername,
				ptr.ToString(rg.Name),
			},
		)
	}
	return header, body, userDataString, nil
}


func (m *AzVMsModule) getComputeVMsPerResourceGroup(subscriptionID string, resourceGroup string) ([]compute.VirtualMachine, error) {
	return m.getComputeVMsPerResourceGroupOriginal(subscriptionID, resourceGroup)
}

func (m *AzVMsModule) getComputeVMsPerResourceGroupOriginal(subscriptionID string, resourceGroup string) ([]compute.VirtualMachine, error) {
	computeClient := internal.GetVirtualMachinesClient(subscriptionID)
	var vms []compute.VirtualMachine

	for page, err := computeClient.List(context.TODO(), resourceGroup, ""); page.NotDone(); page.Next() {
		if err != nil {
			return nil, fmt.Errorf("could not enumerate resource group %s. %s", resourceGroup, err)
		} else {

			vms = append(vms, page.Values()...)
		}
	}

	return vms, nil
}

// get vms with user-data view
func getComputeVmInfo(subscriptionID string, resourceGroup string, vmName string) (compute.VirtualMachine, error) {
	computeClient := internal.GetVirtualMachinesClient(subscriptionID)
	vm, err := computeClient.Get(context.Background(), resourceGroup, vmName, compute.InstanceViewTypesUserData)
	if err != nil {
		return compute.VirtualMachine{}, fmt.Errorf("could not get vm %s. %s", vmName, err)
	}
	return vm, nil
}
func getComputeVmInstanceView(subscriptionID string, resourceGroup string, vmName string) (compute.VirtualMachine, error) {
	computeClient := internal.GetVirtualMachinesClient(subscriptionID)
	vm, err := computeClient.Get(context.Background(), resourceGroup, vmName, compute.InstanceViewTypesInstanceView)
	if err != nil {
		return compute.VirtualMachine{}, fmt.Errorf("could not get vm %s. %s", vmName, err)
	}
	return vm, nil
}

func (m *AzVMsModule) mockedGetComputeVMsPerResourceGroup(subscriptionID, resourceGroup string) ([]compute.VirtualMachine, error) {
	testFile, err := os.ReadFile(globals.VMS_TEST_FILE)
	if err != nil {
		return nil, fmt.Errorf("could not read file %s", globals.VMS_TEST_FILE)
	}

	var vms []compute.VirtualMachine
	err = json.Unmarshal(testFile, &vms)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshall file %s", globals.VMS_TEST_FILE)
	}

	var results []compute.VirtualMachine
	for _, vm := range vms {
		vmSub := strings.Split(ptr.ToString(vm.ID), "/")[2]
		vmRG := strings.Split(ptr.ToString(vm.ID), "/")[4]
		if vmSub == subscriptionID && vmRG == resourceGroup {
			results = append(results, vm)
		}
	}
	return results, nil
}

func getIPs(subscriptionID string, resourceGroup string, vm compute.VirtualMachine) ([]string, []string) {
	var privateIPs, publicIPs []string

	if vm.VirtualMachineProperties.NetworkProfile.NetworkInterfaces != nil {
		for _, nicReference := range *vm.VirtualMachineProperties.NetworkProfile.NetworkInterfaces {
			nic, err := getNICdetails(subscriptionID, resourceGroup, nicReference, "")
			if err != nil {
				return []string{err.Error()}, []string{err.Error()}
			}
			if nic.InterfacePropertiesFormat.IPConfigurations != nil {
				for _, ip := range *nic.InterfacePropertiesFormat.IPConfigurations {
					privateIPs = append(
						privateIPs,
						ptr.ToString(
							ip.InterfaceIPConfigurationPropertiesFormat.PrivateIPAddress))

					publicIP, err := getPublicIP(subscriptionID, resourceGroup, ip)
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

func getNICdetails(subscriptionID string, resourceGroup string, nicReference compute.NetworkInterfaceReference, expand string) (network.Interface, error) {
	return getNICdetailsOriginal(subscriptionID, resourceGroup, nicReference, expand)
}

func getNICdetailsOriginal(subscriptionID string, resourceGroup string, nicReference compute.NetworkInterfaceReference, expand string) (network.Interface, error) {
	client := internal.GetNICClient(subscriptionID)
	NICName := strings.Split(ptr.ToString(nicReference.ID), "/")[len(strings.Split(ptr.ToString(nicReference.ID), "/"))-1]

	nic, err := client.Get(context.TODO(), resourceGroup, NICName, expand)
	if err != nil {
		return network.Interface{}, fmt.Errorf("NICnotFound_%s", NICName)
	}

	return nic, nil
}

func (m *AzVMsModule) mockedGetNICdetails(subscriptionID, resourceGroup string, nicReference compute.NetworkInterfaceReference) (network.Interface, error) {
	testFile, err := os.ReadFile(globals.NICS_TEST_FILE)
	if err != nil {
		return network.Interface{}, fmt.Errorf("NICnotFound_%s", globals.NICS_TEST_FILE)
	}

	var nics []network.Interface
	err = json.Unmarshal(testFile, &nics)
	if err != nil {
		return network.Interface{}, fmt.Errorf("NICnotFound_%s", globals.NICS_TEST_FILE)
	}

	for _, nic := range nics {
		if ptr.ToString(nic.ID) == ptr.ToString(nicReference.ID) {
			return nic, nil
		}
	}
	return network.Interface{}, fmt.Errorf("NICnotFound_%s", ptr.ToString(nicReference.ID))
}

func getPublicIP(subscriptionID string, resourceGroup string, ip network.InterfaceIPConfiguration) (*string, error) {
	return getPublicIPOriginal(subscriptionID, resourceGroup, ip)
}

func getPublicIPOriginal(subscriptionID string, resourceGroup string, ip network.InterfaceIPConfiguration) (*string, error) {
	client := internal.GetPublicIPClient(subscriptionID)
	if ip.InterfaceIPConfigurationPropertiesFormat.PublicIPAddress == nil {
		return nil, fmt.Errorf("NoPublicIP")
	}
	publicIPID := ptr.ToString(ip.InterfaceIPConfigurationPropertiesFormat.PublicIPAddress.ID)
	publicIPName := strings.Split(publicIPID, "/")[len(strings.Split(publicIPID, "/"))-1]
	publicIPExpanded, err := client.Get(context.TODO(), resourceGroup, publicIPName, "")
	if err != nil {
		return nil, fmt.Errorf("NoPublicIP")
	}
	return publicIPExpanded.PublicIPAddressPropertiesFormat.IPAddress, nil
}

func (m *AzVMsModule) mockedGetPublicIP(subscriptionID, resourceGroup string, ip network.InterfaceIPConfiguration) (*string, error) {
	f, err := os.ReadFile(globals.PUBLIC_IPS_TEST_FILE)
	if err != nil {
		return nil, fmt.Errorf("IPNotFound_%s", globals.PUBLIC_IPS_TEST_FILE)
	}

	var ips []network.PublicIPAddress
	err = json.Unmarshal(f, &ips)
	if err != nil {
		return nil, fmt.Errorf("IPNotFound_%s", globals.PUBLIC_IPS_TEST_FILE)
	}

	publicIPID := ptr.ToString(ip.InterfaceIPConfigurationPropertiesFormat.PublicIPAddress.ID)
	publicIPName := strings.Split(publicIPID, "/")[len(strings.Split(publicIPID, "/"))-1]

	// replace this switch for a for loop
	for _, ip := range ips {
		if ptr.ToString(ip.ID) == publicIPID {
			return ip.PublicIPAddressPropertiesFormat.IPAddress, nil
		}
	}
	return nil, fmt.Errorf("IPNotFound_%s", publicIPName)
}
