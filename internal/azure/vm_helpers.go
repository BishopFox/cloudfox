package azure

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/compute/mgmt/compute"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/network/mgmt/network"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
)

// GetBastionClient returns a BastionHostsClient for the subscription
func GetBastionHostsPerSubscription(session *SafeSession, subscriptionID string) ([]*armnetwork.BastionHost, error) {
	//cred, _ := azidentity.NewDefaultAzureCredential(nil)
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token for subscription %s: %v", subscriptionID, err)
	}

	cred := &StaticTokenCredential{Token: token}

	client, _ := armnetwork.NewBastionHostsClient(subscriptionID, cred, nil)

	var results []*armnetwork.BastionHost
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(context.Background())
		if err != nil {
			return nil, fmt.Errorf("failed to list bastion hosts: %v", err)
		}
		results = append(results, page.Value...)
	}

	return results, nil
}

//func GetVMsPerSubscriptionID(subscriptionID string, lootMap map[string]*internal.LootFile, endpointProtection bool) ([][]string, string) {
//	var resultsBody [][]string
//	var userDataCombined string
//	logger := internal.NewLogger()
//
//	for _, s := range GetSubscriptions() { // returns []*armsubscriptions.Subscription
//		if s.SubscriptionID != nil && *s.SubscriptionID == subscriptionID {
//			resourceGroups := GetResourceGroupsPerSubscription(subscriptionID)
//			for _, rg := range resourceGroups {
//				_, b, userData, err := GetComputeRelevantData(s, rg, lootMap, endpointProtection)
//				if err != nil && globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
//					logger.ErrorM(fmt.Sprintf("Could not enumerate VMs for resource group %s in subscription %s\n", *rg.Name, *s.SubscriptionID), globals.AZ_VMS_MODULE_NAME)
//				} else {
//					resultsBody = append(resultsBody, b...)
//					userDataCombined += userData
//				}
//			}
//		}
//	}
//	return resultsBody, userDataCombined
//}

func GetVMsPerResourceGroupObject(session *SafeSession, subscriptionID string, rgName string, lootMap map[string]*internal.LootFile, tenantName string, tenantID string) ([][]string, string) {
	var resultsBody [][]string
	var userDataCombined string
	logger := internal.NewLogger()

	for _, s := range GetSubscriptions(session) { // returns []*armsubscriptions.Subscription
		if s.SubscriptionID != nil && *s.SubscriptionID == subscriptionID {
			var region string
			if rg := GetResourceGroupIDFromName(session, subscriptionID, rgName); rg != nil {
				// Retrieve ResourceGroup object to get Location
				rgs := GetResourceGroupsPerSubscription(session, subscriptionID)
				for _, r := range rgs {
					if r.Name != nil && *r.Name == rgName && r.Location != nil {
						region = *r.Location
						break
					}
				}
			}

			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				logger.InfoM(fmt.Sprintf("Enumerating VMs for resource group %s in subscription %s (region: %s)", rgName, subscriptionID, region), globals.AZ_VMS_MODULE_NAME)
			}

			_, b, userData, err := GetComputeRelevantData(session, s, rgName, lootMap, tenantName, tenantID)
			if err != nil && globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Could not enumerate VMs for resource group %s in subscription %s: %v", rgName, subscriptionID, err), globals.AZ_VMS_MODULE_NAME)
			} else {
				resultsBody = append(resultsBody, b...)
				userDataCombined += userData
			}
		}
	}
	return resultsBody, userDataCombined
}

func GetComputeRelevantData(
	session *SafeSession,
	sub *armsubscriptions.Subscription,
	rgName string,
	lootMap map[string]*internal.LootFile,
	tenantName string,
	tenantID string,
) ([]string, [][]string, string, error) {
	var body [][]string
	var userDataString string
	var vmCommandInfoList []VMCommandInfo

	// ---------------- Safe subscription + RG values ----------------
	subID, subName := "N/A", "N/A"
	if sub != nil {
		if sub.SubscriptionID != nil {
			subID = *sub.SubscriptionID
		}
		if sub.DisplayName != nil {
			subName = *sub.DisplayName
		}
	}

	// ---------------- VM fetch ----------------
	if subID == "N/A" || rgName == "N/A" {
		return nil, nil, "", fmt.Errorf("invalid subscription or resource group")
	}

	vms, err := GetComputeVMsPerResourceGroup(subID, rgName)
	if err != nil {
		return nil, nil, "", fmt.Errorf("error fetching vms for resource group %s: %s", rgName, err)
	}

	for _, vm := range vms {
		// Safe defaults
		vmName, location, adminUsername, vmID := "N/A", "N/A", "N/A", "N/A"
		privateIPs, publicIPs := []string{}, []string{}
		vnetName, subnetCIDR, subnetID := "N/A", "N/A", "N/A"
		isBastion, systemAssignedID, userAssignedID, epStatus, hostname := "False", "N/A", "N/A", "N/A", "N/A"

		// ---------------- Top-level safe fields ----------------
		if vm.Name != nil {
			vmName = *vm.Name
		}
		if vm.Location != nil {
			location = *vm.Location
		}
		if vm.ID != nil {
			vmID = *vm.ID
		}

		// ---------------- VM Size (SKU) ----------------
		vmSize := "N/A"
		if vm.VirtualMachineProperties != nil &&
			vm.VirtualMachineProperties.HardwareProfile != nil &&
			vm.VirtualMachineProperties.HardwareProfile.VMSize != "" {
			vmSize = string(vm.VirtualMachineProperties.HardwareProfile.VMSize)
		}

		// ---------------- Tags ----------------
		tags := "N/A"
		if vm.Tags != nil && len(vm.Tags) > 0 {
			var tagPairs []string
			for k, v := range vm.Tags {
				if v != nil {
					tagPairs = append(tagPairs, fmt.Sprintf("%s:%s", k, *v))
				} else {
					tagPairs = append(tagPairs, k)
				}
			}
			if len(tagPairs) > 0 {
				tags = strings.Join(tagPairs, ", ")
			}
		}

		// ---------------- OS profile (admin username) ----------------
		if vm.VirtualMachineProperties != nil &&
			vm.VirtualMachineProperties.OsProfile != nil &&
			vm.VirtualMachineProperties.OsProfile.AdminUsername != nil {
			adminUsername = *vm.VirtualMachineProperties.OsProfile.AdminUsername
		}

		// ---------------- IP addresses ----------------
		if vm.VirtualMachineProperties != nil &&
			vm.VirtualMachineProperties.NetworkProfile != nil &&
			vm.VirtualMachineProperties.NetworkProfile.NetworkInterfaces != nil {
			privateIPs, publicIPs = GetIPs(subID, rgName, vm)
		}

		// ---------------- UserData ----------------
		if vmName != "N/A" {
			if vmDetails, derr := GetComputeVmInfo(subID, rgName, vmName); derr == nil {
				if vmDetails.VirtualMachineProperties != nil &&
					vmDetails.VirtualMachineProperties.UserData != nil {
					if ud, decErr := base64.StdEncoding.DecodeString(*vmDetails.VirtualMachineProperties.UserData); decErr == nil {
						userDataString += fmt.Sprintf(
							"===============================================================\n"+
								"VM Name: %s\n"+
								"Subscription Name: %s\n"+
								"VM Location: %s\n"+
								"Resource Group Name: %s\n\n"+
								"UserData:\n%s\n\n",
							vmName, subName, location, rgName, string(ud),
						)
					}
				}
			}
		}

		// ---------------- VNet/Subnet ----------------
		if vm.VirtualMachineProperties != nil &&
			vm.VirtualMachineProperties.NetworkProfile != nil &&
			vm.VirtualMachineProperties.NetworkProfile.NetworkInterfaces != nil &&
			len(*vm.VirtualMachineProperties.NetworkProfile.NetworkInterfaces) > 0 {
			vnetName, subnetCIDR, subnetID = GetVNetAndSubnet(
				session,
				subID,
				rgName,
				vm.VirtualMachineProperties.NetworkProfile.NetworkInterfaces,
			)
		}

		// ---------------- Bastion check ----------------
		if vmName != "N/A" {
			if b, _ := IsBastionHost(session, subID, rgName, vmName); b {
				isBastion = "True"
			}
		}

		// ---------------- Identity IDs ----------------
		if vm.Identity != nil {
			// System assigned identity ID
			if vm.Identity.PrincipalID != nil {
				systemAssignedID = *vm.Identity.PrincipalID
			}

			// User assigned identity IDs
			if vm.Identity.UserAssignedIdentities != nil {
				var userAssignedIDsList []string
				for _, v := range vm.Identity.UserAssignedIdentities {
					if v.PrincipalID != nil {
						userAssignedIDsList = append(userAssignedIDsList, *v.PrincipalID)
					}
				}
				if len(userAssignedIDsList) > 0 {
					userAssignedID = strings.Join(userAssignedIDsList, "\n")
				}
			}
		}

		// ---------------- EntraID Centralized Auth ----------------
		isEntraIDAuth := "Disabled"

		// If the VM has a system identity, then it's possible EntraID-based login is enabled.
		// We can't read extensions from the vm object directly (the SDK's VM properties type
		// doesn't expose Extensions), so list VM extensions via the VMExtensions client.
		if vm.Identity != nil && vmName != "N/A" {
			client, cerr := GetVMExtensionsClient(session, subID)
			if cerr == nil && client != nil {
				ctx := context.Background()
				if resp, err := client.List(ctx, rgName, vmName, nil); err == nil {
					for _, ext := range resp.Value {
						// Check name, type, and publisher for known AAD/Azure AD login extension identifiers
						if ext.Name != nil && (strings.Contains(*ext.Name, "AADSSHLoginForLinux") || strings.Contains(*ext.Name, "AADLoginForWindows")) {
							isEntraIDAuth = "Enabled"
							break
						}
						if ext.Properties != nil {
							if ext.Properties.Type != nil && (strings.Contains(*ext.Properties.Type, "AADSSHLoginForLinux") || strings.Contains(*ext.Properties.Type, "AADLoginForWindows")) {
								isEntraIDAuth = "Enabled"
								break
							}
							if ext.Properties.Publisher != nil {
								pub := strings.ToLower(*ext.Properties.Publisher)
								if strings.Contains(pub, "azure") && (strings.Contains(pub, "active") || strings.Contains(pub, "ad") || strings.Contains(pub, "azureactive")) {
									// best-effort publisher match; treat as EntraID-enabled if type/name also hints
									// (kept conservative: only set Enabled if type/name matched above; optional)
								}
							}
						}
					}
				}
			}
		}

		// ---------------- Endpoint protection ----------------
		if vmName != "N/A" {
			if enabled, cerr := CheckEndpointProtection(session, subID, rgName, vmName); cerr == nil {
				if enabled {
					epStatus = "Enabled"
				} else {
					epStatus = "Disabled"
				}
			}
		}

		// ---------------- Hostname ----------------
		if vm.VirtualMachineProperties != nil {
			if hn := GetVMHostName(subID, rgName, vm); hn != "" {
				hostname = hn
			}
		}

		// ---------------- Disk Encryption ----------------
		diskEncryption := "N/A"
		if vm.VirtualMachineProperties != nil && vm.VirtualMachineProperties.StorageProfile != nil {
			// Check if disk encryption is enabled via Azure Disk Encryption (ADE)
			if vm.VirtualMachineProperties.StorageProfile.OsDisk != nil {
				osDisk := vm.VirtualMachineProperties.StorageProfile.OsDisk

				// Check if encryption settings exist
				if osDisk.EncryptionSettings != nil && osDisk.EncryptionSettings.Enabled != nil {
					if *osDisk.EncryptionSettings.Enabled {
						diskEncryption = "Enabled (ADE)"
					} else {
						diskEncryption = "Disabled"
					}
				} else {
					// If no encryption settings, check if using managed disk with encryption at host
					if osDisk.ManagedDisk != nil {
						// Default for managed disks is encryption at rest with platform-managed keys
						diskEncryption = "Platform-Managed"
					} else {
						diskEncryption = "Disabled"
					}
				}
			}
		}

		// ---------------- Table row ----------------
		row := []string{
			tenantName, // NEW: for multi-tenant support
			tenantID,   // NEW: for multi-tenant support
			subID,
			subName,
			rgName,
			location,
			vmName,
			vmSize,
			tags,
			strings.Join(privateIPs, "\n"),
			strings.Join(publicIPs, "\n"),
			hostname,
			adminUsername,
			vnetName,
			subnetCIDR,
			isBastion,
			isEntraIDAuth,
			diskEncryption,
			epStatus,
			systemAssignedID,
			userAssignedID,
		}
		body = append(body, row)

		// ---------------- Loot generation (all gated by safe checks) ----------------
		cliVMName := ""
		if vmName != "N/A" {
			cliVMName = vmName
		}
		cliVMID := ""
		if vmID != "N/A" {
			cliVMID = vmID
		}

		// Collect VM command info for detailed template generation
		if cliVMName != "" && rgName != "N/A" {
			// Determine OS type
			osType := "Linux" // default
			if vm.VirtualMachineProperties != nil &&
				vm.VirtualMachineProperties.StorageProfile != nil &&
				vm.VirtualMachineProperties.StorageProfile.OsDisk != nil &&
				vm.VirtualMachineProperties.StorageProfile.OsDisk.OsType == compute.OperatingSystemTypesWindows {
				osType = "Windows"
			}

			// Check if VM has managed identity
			hasIdentity := false
			identityType := "None"
			if vm.Identity != nil {
				hasIdentity = true
				identityType = string(vm.Identity.Type)
			}

			vmInfo := VMCommandInfo{
				VMName:         cliVMName,
				ResourceGroup:  rgName,
				SubscriptionID: subID,
				Location:       location,
				OSType:         osType,
				VMResourceID:   cliVMID,
				PrivateIPs:     privateIPs,
				PublicIPs:      publicIPs,
				HasIdentity:    hasIdentity,
				IdentityType:   identityType,
			}
			vmCommandInfoList = append(vmCommandInfoList, vmInfo)

			// Generate individual VM command template
			if lootMap != nil {
				if lf, ok := lootMap["vms-run-command"]; ok {
					template := GenerateVMRunCommandTemplate(vmInfo)
					lf.Contents += template + "\n"
				}
			}
		}

		// Bastion loot (only if subnetID and VMID exist)
		if lootMap != nil && !strings.EqualFold(isBastion, "True") && subnetID != "N/A" && cliVMID != "" {
			if bastionName := GetClosestBastionForVM(session, subID, rgName, subnetID); bastionName != "" {
				if lf, ok := lootMap["vms-bastion"]; ok {
					lf.Contents += fmt.Sprintf(
						"## Az CLI: SSH to VM via Bastion\naz --subscription %s network bastion ssh --name %s --resource-group %s --target-resource-id %s\n",
						subID, bastionName, rgName, cliVMID,
					)
				}
			}
		}
	}

	// Generate bulk VM command template if we found multiple VMs
	if lootMap != nil && len(vmCommandInfoList) > 0 {
		if lf, ok := lootMap["vms-bulk-command"]; ok {
			bulkTemplate := GenerateBulkVMCommandTemplate(vmCommandInfoList, subID)
			lf.Contents += bulkTemplate
		}
	}

	return nil, body, userDataString, nil
}

// ---------------- Azure SDK Helpers ----------------

func GetComputeVMsPerResourceGroup(subscriptionID, resourceGroup string) ([]compute.VirtualMachine, error) {
	client := GetVirtualMachinesClient(subscriptionID)
	var vms []compute.VirtualMachine
	for page, err := client.List(context.TODO(), resourceGroup, ""); page.NotDone(); page.Next() {
		if err != nil {
			return nil, fmt.Errorf("could not enumerate resource group %s: %s", resourceGroup, err)
		}
		vms = append(vms, page.Values()...)
	}
	return vms, nil
}

func GetComputeVmInfo(subscriptionID, resourceGroup, vmName string) (compute.VirtualMachine, error) {
	client := GetVirtualMachinesClient(subscriptionID)
	vm, err := client.Get(context.Background(), resourceGroup, vmName, compute.InstanceViewTypesUserData)
	if err != nil {
		return compute.VirtualMachine{}, fmt.Errorf("could not get vm %s: %s", vmName, err)
	}
	return vm, nil
}

func GetNICdetails(subscriptionID, resourceGroup string, nicRef compute.NetworkInterfaceReference) (network.Interface, error) {
	if nicRef.ID == nil || *nicRef.ID == "" {
		return network.Interface{}, fmt.Errorf("nic reference ID is nil or empty")
	}
	parts := strings.Split(*nicRef.ID, "/")
	if len(parts) == 0 {
		return network.Interface{}, fmt.Errorf("invalid NIC ID format")
	}
	nicName := parts[len(parts)-1]

	client, err := GetNICClient(subscriptionID)
	if err != nil {
		return network.Interface{}, err
	}
	if client == nil {
		return network.Interface{}, fmt.Errorf("failed to create NIC client")
	}

	nic, err := client.Get(context.TODO(), resourceGroup, nicName, "")
	if err != nil {
		return network.Interface{}, fmt.Errorf("nic not found %s: %v", nicName, err)
	}
	return nic, nil
}

func GetPublicIP(subscriptionID, resourceGroup string, ip network.InterfaceIPConfiguration) (*string, error) {
	if ip.InterfaceIPConfigurationPropertiesFormat == nil ||
		ip.InterfaceIPConfigurationPropertiesFormat.PublicIPAddress == nil ||
		ip.InterfaceIPConfigurationPropertiesFormat.PublicIPAddress.ID == nil {
		return nil, fmt.Errorf("no Public IP reference on NIC config")
	}

	publicIPID := *ip.InterfaceIPConfigurationPropertiesFormat.PublicIPAddress.ID
	parts := strings.Split(publicIPID, "/")
	if len(parts) == 0 {
		return nil, fmt.Errorf("invalid Public IP resource ID")
	}
	publicIPName := parts[len(parts)-1]

	client, err := GetPublicIPClient(subscriptionID)
	if err != nil {
		return nil, err
	}

	pubIP, err := client.Get(context.TODO(), resourceGroup, publicIPName, "")
	if err != nil {
		return nil, fmt.Errorf("NoPublicIP")
	}
	return pubIP.PublicIPAddressPropertiesFormat.IPAddress, nil
}

func GetIPs(subscriptionID, resourceGroup string, vm compute.VirtualMachine) ([]string, []string) {
	var privateIPs, publicIPs []string

	if vm.VirtualMachineProperties == nil ||
		vm.VirtualMachineProperties.NetworkProfile == nil ||
		vm.VirtualMachineProperties.NetworkProfile.NetworkInterfaces == nil {
		return privateIPs, publicIPs
	}

	for _, nicRef := range *vm.VirtualMachineProperties.NetworkProfile.NetworkInterfaces {
		nic, err := GetNICdetails(subscriptionID, resourceGroup, nicRef)
		if err != nil {
			privateIPs = append(privateIPs, "UNKNOWN")
			continue
		}
		if nic.InterfacePropertiesFormat == nil || nic.InterfacePropertiesFormat.IPConfigurations == nil {
			continue
		}

		for _, ip := range *nic.InterfacePropertiesFormat.IPConfigurations {
			if ip.InterfaceIPConfigurationPropertiesFormat == nil {
				continue
			}
			if ip.InterfaceIPConfigurationPropertiesFormat.PrivateIPAddress != nil {
				privateIPs = append(privateIPs, *ip.InterfaceIPConfigurationPropertiesFormat.PrivateIPAddress)
			}
			if ip.InterfaceIPConfigurationPropertiesFormat.PublicIPAddress != nil {
				if pubIP, err := GetPublicIP(subscriptionID, resourceGroup, ip); err == nil && pubIP != nil {
					publicIPs = append(publicIPs, *pubIP)
				}
			}
		}
	}
	return privateIPs, publicIPs
}

func IsBastionHost(session *SafeSession, subscriptionID, resourceGroup, vmName string) (bool, error) {
	logger := internal.NewLogger()
	bastions, err := GetBastionHostsPerSubscription(session, subscriptionID)
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error getting Bastion hosts: %v\n", err), globals.AZ_STORAGE_MODULE_NAME)
		}
		bastions = []*armnetwork.BastionHost{}
	}

	for _, b := range bastions {
		bRG := GetResourceGroupFromID(*b.ID)
		if *b.Name == vmName && bRG == resourceGroup {
			return true, nil
		}
	}
	return false, nil
}

func GetVNetAndSubnet(session *SafeSession, subscriptionID, resourceGroup string, nicRefs *[]compute.NetworkInterfaceReference) (string, string, string) {
	if nicRefs == nil || len(*nicRefs) == 0 {
		return "N/A", "N/A", "N/A"
	}

	nic, err := GetNICdetails(subscriptionID, resourceGroup, (*nicRefs)[0])
	if err != nil || nic.InterfacePropertiesFormat == nil || nic.InterfacePropertiesFormat.IPConfigurations == nil {
		return "N/A", "N/A", "N/A"
	}
	if len(*nic.InterfacePropertiesFormat.IPConfigurations) == 0 {
		return "N/A", "N/A", "N/A"
	}

	ipConf := (*nic.InterfacePropertiesFormat.IPConfigurations)[0]
	if ipConf.InterfaceIPConfigurationPropertiesFormat == nil ||
		ipConf.InterfaceIPConfigurationPropertiesFormat.Subnet == nil ||
		ipConf.InterfaceIPConfigurationPropertiesFormat.Subnet.ID == nil {
		return "N/A", "N/A", "N/A"
	}

	subnetID := *ipConf.InterfaceIPConfigurationPropertiesFormat.Subnet.ID
	parts := strings.Split(subnetID, "/")
	vnetName, subnetName := "N/A", "N/A"
	for i := 0; i < len(parts); i++ {
		if strings.EqualFold(parts[i], "virtualNetworks") && i+1 < len(parts) {
			vnetName = parts[i+1]
		}
		if strings.EqualFold(parts[i], "subnets") && i+1 < len(parts) {
			subnetName = parts[i+1]
		}
	}

	// Get subnet CIDR
	subnetCIDR := subnetName
	if vnetName != "N/A" && subnetName != "N/A" {
		if subnetClient, err := GetSubnetsClient(session, subscriptionID); err == nil && subnetClient != nil {
			if resp, err := subnetClient.Get(context.TODO(), resourceGroup, vnetName, subnetName, nil); err == nil &&
				resp.Subnet.Properties != nil && resp.Subnet.Properties.AddressPrefix != nil {
				subnetCIDR = fmt.Sprintf("%s (%s)", subnetName, *resp.Subnet.Properties.AddressPrefix)
			}
		}
	}

	return vnetName, subnetCIDR, subnetID
}

// GetClosestBastionForVM returns the name of the closest bastion host for a given VM
// based on same VNet (preferred) or same resource group (fallback). Returns empty string if none found.
func GetClosestBastionForVM(session *SafeSession, subscriptionID, resourceGroup, vmSubnetID string) string {
	logger := internal.NewLogger()

	bastions, err := GetBastionHostsPerSubscription(session, subscriptionID)
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error getting Bastion hosts for subscription %s: %v\n", subscriptionID, err), globals.AZ_VMS_MODULE_NAME)
		}
		return ""
	}

	// First pass: look for bastion in same subnet
	for _, b := range bastions {
		if b.Properties != nil && b.Properties.IPConfigurations != nil {
			for _, ipconf := range b.Properties.IPConfigurations {
				if ipconf.Properties != nil && ipconf.Properties.Subnet != nil && ipconf.Properties.Subnet.ID != nil {
					if *ipconf.Properties.Subnet.ID == vmSubnetID {
						if b.Name != nil {
							return *b.Name
						}
					}
				}
			}
		}
	}

	// Second pass: look for bastion in same resource group
	for _, b := range bastions {
		if b.ID != nil {
			// Resource ID format: /subscriptions/{sub}/resourceGroups/{rg}/providers/...
			parts := strings.Split(*b.ID, "/")
			for i := range parts {
				if strings.EqualFold(parts[i], "resourceGroups") && i+1 < len(parts) {
					if parts[i+1] == resourceGroup {
						if b.Name != nil {
							return *b.Name
						}
					}
				}
			}
		}
	}

	// No match found
	return ""
}

func CheckEndpointProtection(session *SafeSession, subscriptionID, resourceGroup, vmName string) (bool, error) {
	client, err := GetVMExtensionsClient(session, subscriptionID)
	if err != nil {
		return false, err
	}

	ctx := context.Background()
	resp, err := client.List(ctx, resourceGroup, vmName, nil)
	if err != nil {
		return false, fmt.Errorf("failed to list VM extensions: %v", err)
	}

	for _, ext := range resp.Value {
		if ext.Properties != nil && ext.Properties.Publisher != nil && ext.Properties.Type != nil {
			pub := strings.ToLower(*ext.Properties.Publisher)
			typ := strings.ToLower(*ext.Properties.Type)

			if strings.Contains(pub, "microsoft.azure.security") &&
				(strings.Contains(typ, "antimalware") || strings.Contains(typ, "defender")) {
				return true, nil
			}

			if strings.Contains(pub, "microsoft.security") {
				return true, nil
			}
		}
	}

	return false, nil
}

func GetVMHostName(subscriptionID, resourceGroup string, vm compute.VirtualMachine) string {
	if vm.VirtualMachineProperties == nil || vm.VirtualMachineProperties.NetworkProfile == nil ||
		vm.VirtualMachineProperties.NetworkProfile.NetworkInterfaces == nil || len(*vm.VirtualMachineProperties.NetworkProfile.NetworkInterfaces) == 0 {
		return "N/A"
	}

	// Use the first NIC
	nicRef := (*vm.VirtualMachineProperties.NetworkProfile.NetworkInterfaces)[0]
	nic, err := GetNICdetails(subscriptionID, resourceGroup, nicRef)
	if err != nil {
		return "N/A"
	}

	if nic.InterfacePropertiesFormat.IPConfigurations != nil {
		for _, ipConf := range *nic.InterfacePropertiesFormat.IPConfigurations {
			if ipConf.InterfaceIPConfigurationPropertiesFormat.PublicIPAddress != nil {
				pubIPID := *ipConf.InterfaceIPConfigurationPropertiesFormat.PublicIPAddress.ID
				pubIPName := strings.Split(pubIPID, "/")[len(strings.Split(pubIPID, "/"))-1]
				client, _ := GetPublicIPClient(subscriptionID)
				pubIP, err := client.Get(context.TODO(), resourceGroup, pubIPName, "")
				if err == nil && pubIP.PublicIPAddressPropertiesFormat != nil && pubIP.PublicIPAddressPropertiesFormat.DNSSettings != nil &&
					pubIP.PublicIPAddressPropertiesFormat.DNSSettings.Fqdn != nil {
					return *pubIP.PublicIPAddressPropertiesFormat.DNSSettings.Fqdn
				}
			}
		}
	}

	return "N/A"
}

// ==================== VM COMMAND EXECUTION TEMPLATE GENERATION ====================

// VMCommandInfo contains information needed to generate command execution templates
type VMCommandInfo struct {
	VMName         string
	ResourceGroup  string
	SubscriptionID string
	Location       string
	OSType         string // "Windows" or "Linux"
	VMResourceID   string
	PrivateIPs     []string
	PublicIPs      []string
	HasIdentity    bool
	IdentityType   string
}

// GenerateVMRunCommandTemplate creates comprehensive command execution templates for a VM
func GenerateVMRunCommandTemplate(vm VMCommandInfo) string {
	var template string

	template += fmt.Sprintf("# ============================================================================\n")
	template += fmt.Sprintf("# VM Command Execution Template\n")
	template += fmt.Sprintf("# VM: %s\n", vm.VMName)
	template += fmt.Sprintf("# Resource Group: %s\n", vm.ResourceGroup)
	template += fmt.Sprintf("# Subscription: %s\n", vm.SubscriptionID)
	template += fmt.Sprintf("# OS Type: %s\n", vm.OSType)
	template += fmt.Sprintf("# Location: %s\n", vm.Location)
	if len(vm.PrivateIPs) > 0 {
		template += fmt.Sprintf("# Private IPs: %s\n", strings.Join(vm.PrivateIPs, ", "))
	}
	if len(vm.PublicIPs) > 0 {
		template += fmt.Sprintf("# Public IPs: %s\n", strings.Join(vm.PublicIPs, ", "))
	}
	if vm.HasIdentity {
		template += fmt.Sprintf("# Managed Identity: %s\n", vm.IdentityType)
	}
	template += fmt.Sprintf("# ============================================================================\n\n")

	// Determine command ID based on OS
	commandID := "RunShellScript"
	scriptExtension := "sh"
	exampleCommand := "whoami && hostname"

	if vm.OSType == "Windows" {
		commandID = "RunPowerShellScript"
		scriptExtension = "ps1"
		exampleCommand = "whoami; hostname; Get-ComputerInfo"
	}

	template += fmt.Sprintf("## Method 1: Azure CLI - Inline Command\n\n")
	template += fmt.Sprintf("```bash\n")
	template += fmt.Sprintf("# Execute a simple command\n")
	template += fmt.Sprintf("az vm run-command invoke \\\n")
	template += fmt.Sprintf("  --subscription %s \\\n", vm.SubscriptionID)
	template += fmt.Sprintf("  --resource-group %s \\\n", vm.ResourceGroup)
	template += fmt.Sprintf("  --name %s \\\n", vm.VMName)
	template += fmt.Sprintf("  --command-id %s \\\n", commandID)
	template += fmt.Sprintf("  --scripts \"%s\"\n", exampleCommand)
	template += fmt.Sprintf("```\n\n")

	template += fmt.Sprintf("## Method 2: Azure CLI - Script File\n\n")
	template += fmt.Sprintf("```bash\n")
	template += fmt.Sprintf("# Execute a script file\n")
	template += fmt.Sprintf("az vm run-command invoke \\\n")
	template += fmt.Sprintf("  --subscription %s \\\n", vm.SubscriptionID)
	template += fmt.Sprintf("  --resource-group %s \\\n", vm.ResourceGroup)
	template += fmt.Sprintf("  --name %s \\\n", vm.VMName)
	template += fmt.Sprintf("  --command-id %s \\\n", commandID)
	template += fmt.Sprintf("  --script-path ./my-script.%s\n", scriptExtension)
	template += fmt.Sprintf("```\n\n")

	template += fmt.Sprintf("## Method 3: Azure PowerShell - Invoke-AzVMRunCommand\n\n")
	template += fmt.Sprintf("```powershell\n")
	template += fmt.Sprintf("# Execute inline script\n")
	template += fmt.Sprintf("$result = Invoke-AzVMRunCommand `\n")
	template += fmt.Sprintf("  -ResourceGroupName %s `\n", vm.ResourceGroup)
	template += fmt.Sprintf("  -VMName %s `\n", vm.VMName)
	template += fmt.Sprintf("  -CommandId '%s' `\n", commandID)
	template += fmt.Sprintf("  -ScriptString '%s'\n\n", exampleCommand)
	template += fmt.Sprintf("# Display output\n")
	template += fmt.Sprintf("$result.Value[0].Message\n\n")
	template += fmt.Sprintf("# Execute script from file\n")
	template += fmt.Sprintf("$result = Invoke-AzVMRunCommand `\n")
	template += fmt.Sprintf("  -ResourceGroupName %s `\n", vm.ResourceGroup)
	template += fmt.Sprintf("  -VMName %s `\n", vm.VMName)
	template += fmt.Sprintf("  -CommandId '%s' `\n", commandID)
	template += fmt.Sprintf("  -ScriptPath ./my-script.%s\n\n", scriptExtension)
	template += fmt.Sprintf("$result.Value[0].Message\n")
	template += fmt.Sprintf("```\n\n")

	template += fmt.Sprintf("## Method 4: REST API Direct\n\n")
	template += fmt.Sprintf("```powershell\n")
	template += fmt.Sprintf("# Get access token\n")
	template += fmt.Sprintf("$token = (Get-AzAccessToken -ResourceUrl \"https://management.azure.com/\").Token\n\n")
	template += fmt.Sprintf("# Prepare request body\n")

	if vm.OSType == "Windows" {
		template += fmt.Sprintf("$body = @{\n")
		template += fmt.Sprintf("  commandId = \"RunPowerShellScript\"\n")
		template += fmt.Sprintf("  script = @(\"%s\")\n", exampleCommand)
		template += fmt.Sprintf("  parameters = @()\n")
		template += fmt.Sprintf("} | ConvertTo-Json\n\n")
	} else {
		template += fmt.Sprintf("$body = @{\n")
		template += fmt.Sprintf("  commandId = \"RunShellScript\"\n")
		template += fmt.Sprintf("  script = @(\"%s\")\n", exampleCommand)
		template += fmt.Sprintf("  parameters = @()\n")
		template += fmt.Sprintf("} | ConvertTo-Json\n\n")
	}

	template += fmt.Sprintf("# Execute command via REST API\n")
	template += fmt.Sprintf("$uri = \"https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Compute/virtualMachines/%s/runCommand?api-version=2023-03-01\"\n\n",
		vm.SubscriptionID, vm.ResourceGroup, vm.VMName)
	template += fmt.Sprintf("$response = Invoke-RestMethod -Uri $uri `\n")
	template += fmt.Sprintf("  -Method POST `\n")
	template += fmt.Sprintf("  -Headers @{Authorization=\"Bearer $token\"} `\n")
	template += fmt.Sprintf("  -ContentType \"application/json\" `\n")
	template += fmt.Sprintf("  -Body $body\n\n")
	template += fmt.Sprintf("# Poll for completion\n")
	template += fmt.Sprintf("$location = $response.Headers.Location\n")
	template += fmt.Sprintf("do {\n")
	template += fmt.Sprintf("  Start-Sleep -Seconds 5\n")
	template += fmt.Sprintf("  $status = Invoke-RestMethod -Uri $location -Headers @{Authorization=\"Bearer $token\"}\n")
	template += fmt.Sprintf("} while ($status.value -eq $null)\n\n")
	template += fmt.Sprintf("# Display output\n")
	template += fmt.Sprintf("$status.value.message\n")
	template += fmt.Sprintf("```\n\n")

	// Add OS-specific examples
	if vm.OSType == "Windows" {
		template += generateWindowsSpecificExamples(vm)
	} else {
		template += generateLinuxSpecificExamples(vm)
	}

	template += fmt.Sprintf("## Required Permissions\n\n")
	template += fmt.Sprintf("To execute commands on this VM, you need one of the following:\n")
	template += fmt.Sprintf("- **Virtual Machine Contributor** role on the VM\n")
	template += fmt.Sprintf("- **Contributor** role on the resource group or subscription\n")
	template += fmt.Sprintf("- **Owner** role on the resource group or subscription\n")
	template += fmt.Sprintf("- Custom role with `Microsoft.Compute/virtualMachines/runCommand/action` permission\n\n")

	template += fmt.Sprintf("## Notes\n\n")
	template += fmt.Sprintf("- Commands execute with SYSTEM privileges on Windows or root on Linux\n")
	template += fmt.Sprintf("- Output is limited to approximately 4KB\n")
	template += fmt.Sprintf("- Long-running commands may timeout (default: 90 seconds)\n")
	template += fmt.Sprintf("- The VM agent must be running for RunCommand to work\n")
	template += fmt.Sprintf("- All command execution is logged in Azure Activity Log\n\n")

	return template
}

// generateWindowsSpecificExamples generates Windows-specific command examples
func generateWindowsSpecificExamples(vm VMCommandInfo) string {
	var examples string

	examples += fmt.Sprintf("## Windows-Specific Examples\n\n")

	examples += fmt.Sprintf("### Example 1: System Information\n\n")
	examples += fmt.Sprintf("```powershell\n")
	examples += fmt.Sprintf("$script = @'\n")
	examples += fmt.Sprintf("# Get computer info\n")
	examples += fmt.Sprintf("Get-ComputerInfo | Select-Object WindowsVersion, OsHardwareAbstractionLayer\n")
	examples += fmt.Sprintf("# Get local users\n")
	examples += fmt.Sprintf("Get-LocalUser | Select-Object Name, Enabled, LastLogon\n")
	examples += fmt.Sprintf("# Get local administrators\n")
	examples += fmt.Sprintf("Get-LocalGroupMember -Group \"Administrators\"\n")
	examples += fmt.Sprintf("'@\n\n")
	examples += fmt.Sprintf("Invoke-AzVMRunCommand -ResourceGroupName %s -VMName %s -CommandId 'RunPowerShellScript' -ScriptString $script\n",
		vm.ResourceGroup, vm.VMName)
	examples += fmt.Sprintf("```\n\n")

	examples += fmt.Sprintf("### Example 2: Credential Harvesting\n\n")
	examples += fmt.Sprintf("```powershell\n")
	examples += fmt.Sprintf("$script = @'\n")
	examples += fmt.Sprintf("# Search for saved credentials\n")
	examples += fmt.Sprintf("cmdkey /list\n")
	examples += fmt.Sprintf("# Search for interesting files\n")
	examples += fmt.Sprintf("Get-ChildItem -Path C:\\ -Recurse -Include *.config,*.xml,*.ini,*.txt,*.rdg -ErrorAction SilentlyContinue | Select-String -Pattern \"password\" -SimpleMatch\n")
	examples += fmt.Sprintf("'@\n\n")
	examples += fmt.Sprintf("Invoke-AzVMRunCommand -ResourceGroupName %s -VMName %s -CommandId 'RunPowerShellScript' -ScriptString $script\n",
		vm.ResourceGroup, vm.VMName)
	examples += fmt.Sprintf("```\n\n")

	examples += fmt.Sprintf("### Example 3: Network Enumeration\n\n")
	examples += fmt.Sprintf("```powershell\n")
	examples += fmt.Sprintf("$script = @'\n")
	examples += fmt.Sprintf("# Get network configuration\n")
	examples += fmt.Sprintf("Get-NetIPAddress | Where-Object {$_.AddressFamily -eq \"IPv4\"} | Select-Object IPAddress, InterfaceAlias\n")
	examples += fmt.Sprintf("# Get network routes\n")
	examples += fmt.Sprintf("Get-NetRoute | Where-Object {$_.DestinationPrefix -ne \"ff00::/8\"} | Select-Object DestinationPrefix, NextHop\n")
	examples += fmt.Sprintf("# Get listening ports\n")
	examples += fmt.Sprintf("Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess\n")
	examples += fmt.Sprintf("'@\n\n")
	examples += fmt.Sprintf("Invoke-AzVMRunCommand -ResourceGroupName %s -VMName %s -CommandId 'RunPowerShellScript' -ScriptString $script\n",
		vm.ResourceGroup, vm.VMName)
	examples += fmt.Sprintf("```\n\n")

	if vm.HasIdentity {
		examples += fmt.Sprintf("### Example 4: Extract Managed Identity Token\n\n")
		examples += fmt.Sprintf("```powershell\n")
		examples += fmt.Sprintf("$script = @'\n")
		examples += fmt.Sprintf("# Get token for Azure Resource Manager\n")
		examples += fmt.Sprintf("$response = Invoke-WebRequest -Uri 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' -Method GET -Headers @{Metadata=\"true\"} -UseBasicParsing\n")
		examples += fmt.Sprintf("$token = ($response.Content | ConvertFrom-Json).access_token\n")
		examples += fmt.Sprintf("Write-Output \"Token: $token\"\n")
		examples += fmt.Sprintf("'@\n\n")
		examples += fmt.Sprintf("Invoke-AzVMRunCommand -ResourceGroupName %s -VMName %s -CommandId 'RunPowerShellScript' -ScriptString $script\n",
			vm.ResourceGroup, vm.VMName)
		examples += fmt.Sprintf("```\n\n")
	}

	return examples
}

// generateLinuxSpecificExamples generates Linux-specific command examples
func generateLinuxSpecificExamples(vm VMCommandInfo) string {
	var examples string

	examples += fmt.Sprintf("## Linux-Specific Examples\n\n")

	examples += fmt.Sprintf("### Example 1: System Information\n\n")
	examples += fmt.Sprintf("```bash\n")
	examples += fmt.Sprintf("az vm run-command invoke \\\n")
	examples += fmt.Sprintf("  --resource-group %s \\\n", vm.ResourceGroup)
	examples += fmt.Sprintf("  --name %s \\\n", vm.VMName)
	examples += fmt.Sprintf("  --command-id RunShellScript \\\n")
	examples += fmt.Sprintf("  --scripts \"uname -a && cat /etc/os-release && who && last | head -20\"\n")
	examples += fmt.Sprintf("```\n\n")

	examples += fmt.Sprintf("### Example 2: Search for Credentials\n\n")
	examples += fmt.Sprintf("```bash\n")
	examples += fmt.Sprintf("az vm run-command invoke \\\n")
	examples += fmt.Sprintf("  --resource-group %s \\\n", vm.ResourceGroup)
	examples += fmt.Sprintf("  --name %s \\\n", vm.VMName)
	examples += fmt.Sprintf("  --command-id RunShellScript \\\n")
	examples += fmt.Sprintf("  --scripts \"find /home /root /var /opt -type f -name '*.pem' -o -name '*.key' -o -name '.ssh/*' -o -name '*.config' 2>/dev/null | head -50\"\n")
	examples += fmt.Sprintf("```\n\n")

	examples += fmt.Sprintf("### Example 3: Network Enumeration\n\n")
	examples += fmt.Sprintf("```bash\n")
	examples += fmt.Sprintf("az vm run-command invoke \\\n")
	examples += fmt.Sprintf("  --resource-group %s \\\n", vm.ResourceGroup)
	examples += fmt.Sprintf("  --name %s \\\n", vm.VMName)
	examples += fmt.Sprintf("  --command-id RunShellScript \\\n")
	examples += fmt.Sprintf("  --scripts \"ip addr show && ip route show && ss -tlnp\"\n")
	examples += fmt.Sprintf("```\n\n")

	examples += fmt.Sprintf("### Example 4: Sudo and Privilege Check\n\n")
	examples += fmt.Sprintf("```bash\n")
	examples += fmt.Sprintf("az vm run-command invoke \\\n")
	examples += fmt.Sprintf("  --resource-group %s \\\n", vm.ResourceGroup)
	examples += fmt.Sprintf("  --name %s \\\n", vm.VMName)
	examples += fmt.Sprintf("  --command-id RunShellScript \\\n")
	examples += fmt.Sprintf("  --scripts \"id && sudo -l\"\n")
	examples += fmt.Sprintf("```\n\n")

	if vm.HasIdentity {
		examples += fmt.Sprintf("### Example 5: Extract Managed Identity Token\n\n")
		examples += fmt.Sprintf("```bash\n")
		examples += fmt.Sprintf("az vm run-command invoke \\\n")
		examples += fmt.Sprintf("  --resource-group %s \\\n", vm.ResourceGroup)
		examples += fmt.Sprintf("  --name %s \\\n", vm.VMName)
		examples += fmt.Sprintf("  --command-id RunShellScript \\\n")
		examples += fmt.Sprintf("  --scripts \"curl 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' -H Metadata:true\"\n")
		examples += fmt.Sprintf("```\n\n")
	}

	return examples
}

// GenerateBulkVMCommandTemplate creates a template for running commands on multiple VMs
func GenerateBulkVMCommandTemplate(vms []VMCommandInfo, subscriptionID string) string {
	if len(vms) == 0 {
		return ""
	}

	var template string

	template += fmt.Sprintf("# ============================================================================\n")
	template += fmt.Sprintf("# BULK VM COMMAND EXECUTION TEMPLATE\n")
	template += fmt.Sprintf("# Subscription: %s\n", subscriptionID)
	template += fmt.Sprintf("# Total VMs: %d\n", len(vms))
	template += fmt.Sprintf("# ============================================================================\n\n")

	template += fmt.Sprintf("## WARNING\n")
	template += fmt.Sprintf("# Executing commands on multiple VMs simultaneously can:\n")
	template += fmt.Sprintf("# - Generate significant Azure Activity Log entries\n")
	template += fmt.Sprintf("# - Trigger security alerts if monitoring is enabled\n")
	template += fmt.Sprintf("# - Impact VM performance\n")
	template += fmt.Sprintf("# - Be detected by EDR/antivirus solutions\n\n")

	template += fmt.Sprintf("## Method 1: PowerShell - Iterate All VMs\n\n")
	template += fmt.Sprintf("```powershell\n")
	template += fmt.Sprintf("# Define VMs to target\n")
	template += fmt.Sprintf("$vms = @(\n")
	for i, vm := range vms {
		template += fmt.Sprintf("    @{Name='%s'; ResourceGroup='%s'; OSType='%s'}",
			vm.VMName, vm.ResourceGroup, vm.OSType)
		if i < len(vms)-1 {
			template += fmt.Sprintf(",\n")
		} else {
			template += fmt.Sprintf("\n")
		}
	}
	template += fmt.Sprintf(")\n\n")
	template += fmt.Sprintf("# Set subscription context\n")
	template += fmt.Sprintf("Set-AzContext -Subscription '%s'\n\n", subscriptionID)
	template += fmt.Sprintf("# Iterate and execute commands\n")
	template += fmt.Sprintf("foreach ($vm in $vms) {\n")
	template += fmt.Sprintf("    Write-Host \"Executing on: $($vm.Name)\"\n")
	template += fmt.Sprintf("    \n")
	template += fmt.Sprintf("    # Determine command ID based on OS type\n")
	template += fmt.Sprintf("    $commandId = if ($vm.OSType -eq 'Windows') { 'RunPowerShellScript' } else { 'RunShellScript' }\n")
	template += fmt.Sprintf("    \n")
	template += fmt.Sprintf("    # Set your command here\n")
	template += fmt.Sprintf("    $command = if ($vm.OSType -eq 'Windows') { 'whoami; hostname' } else { 'whoami && hostname' }\n")
	template += fmt.Sprintf("    \n")
	template += fmt.Sprintf("    try {\n")
	template += fmt.Sprintf("        $result = Invoke-AzVMRunCommand `\n")
	template += fmt.Sprintf("            -ResourceGroupName $vm.ResourceGroup `\n")
	template += fmt.Sprintf("            -VMName $vm.Name `\n")
	template += fmt.Sprintf("            -CommandId $commandId `\n")
	template += fmt.Sprintf("            -ScriptString $command `\n")
	template += fmt.Sprintf("            -ErrorAction Stop\n")
	template += fmt.Sprintf("        \n")
	template += fmt.Sprintf("        Write-Host \"Output from $($vm.Name):\"\n")
	template += fmt.Sprintf("        Write-Host $result.Value[0].Message\n")
	template += fmt.Sprintf("        Write-Host \"`n\" + ('-' * 80) + \"`n\"\n")
	template += fmt.Sprintf("    }\n")
	template += fmt.Sprintf("    catch {\n")
	template += fmt.Sprintf("        Write-Host \"Error on $($vm.Name): $_\"\n")
	template += fmt.Sprintf("    }\n")
	template += fmt.Sprintf("}\n")
	template += fmt.Sprintf("```\n\n")

	template += fmt.Sprintf("## Method 2: Azure CLI - Bash Loop\n\n")
	template += fmt.Sprintf("```bash\n")
	template += fmt.Sprintf("#!/bin/bash\n\n")
	template += fmt.Sprintf("# Set subscription\n")
	template += fmt.Sprintf("az account set --subscription %s\n\n", subscriptionID)
	template += fmt.Sprintf("# Define command to execute\n")
	template += fmt.Sprintf("COMMAND=\"whoami && hostname\"\n\n")

	// Group VMs by OS type
	windowsVMs := []VMCommandInfo{}
	linuxVMs := []VMCommandInfo{}
	for _, vm := range vms {
		if vm.OSType == "Windows" {
			windowsVMs = append(windowsVMs, vm)
		} else {
			linuxVMs = append(linuxVMs, vm)
		}
	}

	if len(windowsVMs) > 0 {
		template += fmt.Sprintf("# Execute on Windows VMs\n")
		for _, vm := range windowsVMs {
			template += fmt.Sprintf("echo \"Executing on: %s\"\n", vm.VMName)
			template += fmt.Sprintf("az vm run-command invoke \\\n")
			template += fmt.Sprintf("  --resource-group %s \\\n", vm.ResourceGroup)
			template += fmt.Sprintf("  --name %s \\\n", vm.VMName)
			template += fmt.Sprintf("  --command-id RunPowerShellScript \\\n")
			template += fmt.Sprintf("  --scripts \"$COMMAND\"\n\n")
		}
	}

	if len(linuxVMs) > 0 {
		template += fmt.Sprintf("# Execute on Linux VMs\n")
		for _, vm := range linuxVMs {
			template += fmt.Sprintf("echo \"Executing on: %s\"\n", vm.VMName)
			template += fmt.Sprintf("az vm run-command invoke \\\n")
			template += fmt.Sprintf("  --resource-group %s \\\n", vm.ResourceGroup)
			template += fmt.Sprintf("  --name %s \\\n", vm.VMName)
			template += fmt.Sprintf("  --command-id RunShellScript \\\n")
			template += fmt.Sprintf("  --scripts \"$COMMAND\"\n\n")
		}
	}
	template += fmt.Sprintf("```\n\n")

	template += fmt.Sprintf("## Method 3: Parallel Execution with PowerShell Jobs\n\n")
	template += fmt.Sprintf("```powershell\n")
	template += fmt.Sprintf("# Define VMs (same as Method 1)\n")
	template += fmt.Sprintf("$vms = @(\n")
	for i, vm := range vms {
		template += fmt.Sprintf("    @{Name='%s'; ResourceGroup='%s'; OSType='%s'}",
			vm.VMName, vm.ResourceGroup, vm.OSType)
		if i < len(vms)-1 {
			template += fmt.Sprintf(",\n")
		} else {
			template += fmt.Sprintf("\n")
		}
	}
	template += fmt.Sprintf(")\n\n")
	template += fmt.Sprintf("# Set subscription context\n")
	template += fmt.Sprintf("Set-AzContext -Subscription '%s'\n\n", subscriptionID)
	template += fmt.Sprintf("# Execute in parallel using jobs\n")
	template += fmt.Sprintf("$jobs = @()\n")
	template += fmt.Sprintf("foreach ($vm in $vms) {\n")
	template += fmt.Sprintf("    $jobs += Start-Job -ScriptBlock {\n")
	template += fmt.Sprintf("        param($VMName, $ResourceGroup, $OSType, $SubscriptionId)\n")
	template += fmt.Sprintf("        \n")
	template += fmt.Sprintf("        Import-Module Az.Compute\n")
	template += fmt.Sprintf("        Set-AzContext -Subscription $SubscriptionId | Out-Null\n")
	template += fmt.Sprintf("        \n")
	template += fmt.Sprintf("        $commandId = if ($OSType -eq 'Windows') { 'RunPowerShellScript' } else { 'RunShellScript' }\n")
	template += fmt.Sprintf("        $command = if ($OSType -eq 'Windows') { 'whoami; hostname' } else { 'whoami && hostname' }\n")
	template += fmt.Sprintf("        \n")
	template += fmt.Sprintf("        $result = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroup -VMName $VMName -CommandId $commandId -ScriptString $command\n")
	template += fmt.Sprintf("        \n")
	template += fmt.Sprintf("        [PSCustomObject]@{\n")
	template += fmt.Sprintf("            VMName = $VMName\n")
	template += fmt.Sprintf("            Output = $result.Value[0].Message\n")
	template += fmt.Sprintf("        }\n")
	template += fmt.Sprintf("    } -ArgumentList $vm.Name, $vm.ResourceGroup, $vm.OSType, '%s'\n", subscriptionID)
	template += fmt.Sprintf("}\n\n")
	template += fmt.Sprintf("# Wait for all jobs to complete\n")
	template += fmt.Sprintf("$jobs | Wait-Job | Receive-Job | Format-Table -AutoSize\n\n")
	template += fmt.Sprintf("# Clean up jobs\n")
	template += fmt.Sprintf("$jobs | Remove-Job\n")
	template += fmt.Sprintf("```\n\n")

	return template
}

// VMExtensionInfo contains information about a VM extension for local extraction
type VMExtensionInfo struct {
	VMName               string
	ResourceGroup        string
	SubscriptionID       string
	ExtensionName        string
	Publisher            string
	ExtensionType        string
	TypeHandlerVersion   string
	ProvisioningState    string
	PublicSettings       string
	ProtectedSettings    string // Will be encrypted/redacted
	HasProtectedSettings bool
}

// GetVMExtensionsForSubscription enumerates all VM extensions across all VMs in a subscription
func GetVMExtensionsForSubscription(session *SafeSession, subscriptionID string, resourceGroups []string, lootMap map[string]*internal.LootFile) {
	if lootMap == nil {
		return
	}

	extensionLoot, ok := lootMap["vms-extension-settings"]
	if !ok {
		return
	}

	var extensionInfoList []VMExtensionInfo

	// Iterate through each resource group
	for _, rgName := range resourceGroups {
		// Get VMs in this resource group
		vms, err := GetComputeVMsPerResourceGroup(subscriptionID, rgName)
		if err != nil {
			continue
		}

		// For each VM, enumerate extensions
		for _, vm := range vms {
			if vm.Name == nil {
				continue
			}
			vmName := *vm.Name

			// Get extensions client
			client, err := GetVMExtensionsClient(session, subscriptionID)
			if err != nil {
				continue
			}

			// List extensions for this VM
			ctx := context.Background()
			resp, err := client.List(ctx, rgName, vmName, nil)
			if err != nil {
				continue
			}

			// Process each extension
			for _, ext := range resp.Value {
				if ext.Name == nil {
					continue
				}

				extInfo := VMExtensionInfo{
					VMName:         vmName,
					ResourceGroup:  rgName,
					SubscriptionID: subscriptionID,
					ExtensionName:  *ext.Name,
				}

				// Extract extension properties
				if ext.Properties != nil {
					if ext.Properties.Publisher != nil {
						extInfo.Publisher = *ext.Properties.Publisher
					}
					if ext.Properties.Type != nil {
						extInfo.ExtensionType = *ext.Properties.Type
					}
					if ext.Properties.TypeHandlerVersion != nil {
						extInfo.TypeHandlerVersion = *ext.Properties.TypeHandlerVersion
					}
					if ext.Properties.ProvisioningState != nil {
						extInfo.ProvisioningState = *ext.Properties.ProvisioningState
					}

					// Public settings (can be read)
					if ext.Properties.Settings != nil {
						if settingsJSON, err := json.MarshalIndent(ext.Properties.Settings, "", "  "); err == nil {
							extInfo.PublicSettings = string(settingsJSON)
						}
					}

					// Protected settings (encrypted - just note presence)
					if ext.Properties.ProtectedSettings != nil {
						extInfo.HasProtectedSettings = true
						extInfo.ProtectedSettings = "[ENCRYPTED - Use local script to decrypt]"
					}
				}

				extensionInfoList = append(extensionInfoList, extInfo)
			}
		}
	}

	// Generate output if we found extensions
	if len(extensionInfoList) > 0 {
		extensionLoot.Contents += GenerateVMExtensionSettingsOutput(extensionInfoList, subscriptionID)
	}
}

// GenerateVMExtensionSettingsOutput creates a comprehensive loot file with extension details and extraction script
func GenerateVMExtensionSettingsOutput(extensions []VMExtensionInfo, subscriptionID string) string {
	var output string

	output += fmt.Sprintf("# Azure VM Extension Settings - Subscription: %s\n\n", subscriptionID)
	output += fmt.Sprintf("**IMPORTANT**: VM extension settings enumerated via Azure API show public settings but protected settings are encrypted.\n")
	output += fmt.Sprintf("To decrypt protected settings, you must run the extraction script **locally on the VM** with appropriate privileges.\n\n")
	output += fmt.Sprintf("---\n\n")

	// Section 1: Extensions found via API
	output += fmt.Sprintf("## Extensions Enumerated via Azure API\n\n")
	output += fmt.Sprintf("Found %d VM extension(s) across subscription:\n\n", len(extensions))

	for i, ext := range extensions {
		output += fmt.Sprintf("### Extension %d: %s\n\n", i+1, ext.ExtensionName)
		output += fmt.Sprintf("- **VM Name**: %s\n", ext.VMName)
		output += fmt.Sprintf("- **Resource Group**: %s\n", ext.ResourceGroup)
		output += fmt.Sprintf("- **Publisher**: %s\n", ext.Publisher)
		output += fmt.Sprintf("- **Type**: %s\n", ext.ExtensionType)
		output += fmt.Sprintf("- **Version**: %s\n", ext.TypeHandlerVersion)
		output += fmt.Sprintf("- **Provisioning State**: %s\n", ext.ProvisioningState)
		output += fmt.Sprintf("- **Has Protected Settings**: %v\n\n", ext.HasProtectedSettings)

		if ext.PublicSettings != "" {
			output += fmt.Sprintf("**Public Settings**:\n```json\n%s\n```\n\n", ext.PublicSettings)
		}

		if ext.HasProtectedSettings {
			output += fmt.Sprintf("**Protected Settings**: %s\n\n", ext.ProtectedSettings)
		}

		output += fmt.Sprintf("---\n\n")
	}

	// Section 2: Local extraction script
	output += GenerateLocalExtensionExtractionScript()

	return output
}

// GenerateLocalExtensionExtractionScript creates the PowerShell script for local execution
func GenerateLocalExtensionExtractionScript() string {
	var script string

	script += fmt.Sprintf("## Local Extension Settings Extraction Script\n\n")
	script += fmt.Sprintf("**Purpose**: Run this script **locally on a Windows VM** to extract and decrypt extension settings.\n\n")
	script += fmt.Sprintf("**Requirements**:\n")
	script += fmt.Sprintf("- Must be executed on the target Windows VM\n")
	script += fmt.Sprintf("- Requires administrative privileges to access certificate private keys\n")
	script += fmt.Sprintf("- Settings files are located at: `C:\\Packages\\Plugins\\*\\*\\RuntimeSettings\\*.settings`\n\n")

	script += fmt.Sprintf("**What it does**:\n")
	script += fmt.Sprintf("1. Reads extension settings from local filesystem\n")
	script += fmt.Sprintf("2. Finds certificates with matching thumbprints\n")
	script += fmt.Sprintf("3. Decrypts protected settings using certificate private keys\n")
	script += fmt.Sprintf("4. Outputs all extension settings including decrypted values\n\n")

	script += fmt.Sprintf("**Common sensitive data in extensions**:\n")
	script += fmt.Sprintf("- CustomScriptExtension: Script URLs, file URIs, storage account keys\n")
	script += fmt.Sprintf("- VMAccessAgent: Administrator passwords\n")
	script += fmt.Sprintf("- DSC (Desired State Configuration): Configuration credentials\n")
	script += fmt.Sprintf("- Azure Disk Encryption: Encryption keys and secrets\n\n")

	script += fmt.Sprintf("### PowerShell Script\n\n")
	script += fmt.Sprintf("```powershell\n")
	script += fmt.Sprintf("Function Get-AzureVMExtensionSettings\n")
	script += fmt.Sprintf("{\n")
	script += fmt.Sprintf("    <#\n")
	script += fmt.Sprintf("    .SYNOPSIS\n")
	script += fmt.Sprintf("        Extracts Azure VM Extension Settings from local filesystem\n")
	script += fmt.Sprintf("    .DESCRIPTION\n")
	script += fmt.Sprintf("        Reads all available extension settings, decrypts protected values (if the required certificate can be found) and returns all the settings.\n")
	script += fmt.Sprintf("    .EXAMPLE\n")
	script += fmt.Sprintf("        PS C:\\> Get-AzureVMExtensionSettings\n")
	script += fmt.Sprintf("    #>\n\n")

	script += fmt.Sprintf("    # Load required assembly for decryption\n")
	script += fmt.Sprintf("    [System.Reflection.Assembly]::LoadWithPartialName(\"System.Security\") | Out-Null\n\n")

	script += fmt.Sprintf("    # Get all runtime settings files\n")
	script += fmt.Sprintf("    $settingsFiles = Get-ChildItem -Path C:\\Packages\\Plugins\\*\\*\\RuntimeSettings -Include *.settings -Recurse -ErrorAction SilentlyContinue\n")
	script += fmt.Sprintf("    \n")
	script += fmt.Sprintf("    Write-Host \"[*] Found $($settingsFiles.Count) extension settings files\"\n")
	script += fmt.Sprintf("    \n")
	script += fmt.Sprintf("    foreach($settingsFile in $settingsFiles) {\n")
	script += fmt.Sprintf("        try {\n")
	script += fmt.Sprintf("            # Convert file contents to JSON\n")
	script += fmt.Sprintf("            $settingsJson = Get-Content $settingsFile | Out-String | ConvertFrom-Json\n")
	script += fmt.Sprintf("            $extensionName = $settingsFile.FullName | Split-Path -Parent | Split-Path -Parent | Split-Path -Parent | Split-Path -Leaf\n")
	script += fmt.Sprintf("            \n")
	script += fmt.Sprintf("            JsonParser $settingsFile.FullName $extensionName $settingsJson\n")
	script += fmt.Sprintf("        } catch {\n")
	script += fmt.Sprintf("            Write-Warning \"[!] Error processing $($settingsFile.FullName): $($_.Exception.Message)\"\n")
	script += fmt.Sprintf("        }\n")
	script += fmt.Sprintf("    }\n\n")

	script += fmt.Sprintf("    # Check for ZIP archives with extension configs\n")
	script += fmt.Sprintf("    if(Test-Path C:\\WindowsAzure\\CollectGuestLogsTemp\\*.zip) {\n")
	script += fmt.Sprintf("        Write-Host \"[*] Found ZIP archives with extension configs\"\n")
	script += fmt.Sprintf("        \n")
	script += fmt.Sprintf("        Add-Type -assembly \"system.io.compression.filesystem\"\n")
	script += fmt.Sprintf("        $psZipFile = Get-Item -Path C:\\WindowsAzure\\CollectGuestLogsTemp\\*.zip -ErrorAction SilentlyContinue\n")
	script += fmt.Sprintf("        \n")
	script += fmt.Sprintf("        if ($psZipFile) {\n")
	script += fmt.Sprintf("            try {\n")
	script += fmt.Sprintf("                $zip = [io.compression.zipfile]::OpenRead($psZipFile.FullName)\n")
	script += fmt.Sprintf("                $file = $zip.Entries | where-object { $_.Name -Like \"WireServerRoleExtensionsConfig*.xml\"}\n")
	script += fmt.Sprintf("                \n")
	script += fmt.Sprintf("                if ($file) {\n")
	script += fmt.Sprintf("                    $stream = $file.Open()\n")
	script += fmt.Sprintf("                    $reader = New-Object IO.StreamReader($stream)\n")
	script += fmt.Sprintf("                    $text = $reader.ReadToEnd()\n")
	script += fmt.Sprintf("                    $reader.Close()\n")
	script += fmt.Sprintf("                    $stream.Close()\n")
	script += fmt.Sprintf("                    \n")
	script += fmt.Sprintf("                    [xml]$extensionsConfig = $text\n")
	script += fmt.Sprintf("                    \n")
	script += fmt.Sprintf("                    foreach($extension in $extensionsConfig.Extensions.PluginSettings.Plugin) {\n")
	script += fmt.Sprintf("                        $extensionJson = $extension.RuntimeSettings.'#text' | ConvertFrom-Json\n")
	script += fmt.Sprintf("                        JsonParser ($psZipFile.FullName+'\\'+$file.FullName.Replace(\"/\",\"\\\")) $extension.name $extensionJson\n")
	script += fmt.Sprintf("                    }\n")
	script += fmt.Sprintf("                }\n")
	script += fmt.Sprintf("                \n")
	script += fmt.Sprintf("                $zip.Dispose()\n")
	script += fmt.Sprintf("            } catch {\n")
	script += fmt.Sprintf("                Write-Warning \"[!] Error processing ZIP archive: $($_.Exception.Message)\"\n")
	script += fmt.Sprintf("            }\n")
	script += fmt.Sprintf("        }\n")
	script += fmt.Sprintf("    }\n")
	script += fmt.Sprintf("}\n\n")

	script += fmt.Sprintf("# Helper function to parse the runTimeSettings JSON\n")
	script += fmt.Sprintf("function JsonParser($fileName, $extensionName, $json) {\n")
	script += fmt.Sprintf("    foreach($setting in $json.runtimeSettings) {\n")
	script += fmt.Sprintf("        $outputObj = \"\" | Select-Object -Property FileName,ExtensionName,ProtectedSettingsCertThumbprint,ProtectedSettings,ProtectedSettingsDecrypted,PublicSettings\n")
	script += fmt.Sprintf("        $outputObj.FileName = $fileName\n")
	script += fmt.Sprintf("        $outputObj.ExtensionName = $extensionName\n")
	script += fmt.Sprintf("        $outputObj.ProtectedSettingsCertThumbprint = $setting.handlerSettings.protectedSettingsCertThumbprint\n")
	script += fmt.Sprintf("        $outputObj.ProtectedSettings = $setting.handlerSettings.protectedSettings\n")
	script += fmt.Sprintf("        $outputObj.PublicSettings = $setting.handlerSettings.publicSettings | ConvertTo-Json -Compress\n\n")

	script += fmt.Sprintf("        # Extract the certificate thumbprint\n")
	script += fmt.Sprintf("        $thumbprint = $setting.handlerSettings.protectedSettingsCertThumbprint\n\n")

	script += fmt.Sprintf("        # Only decrypt if a thumbprint is specified\n")
	script += fmt.Sprintf("        if($thumbprint) {\n")
	script += fmt.Sprintf("            Write-Host \"[*] Found protected settings with thumbprint: $thumbprint\"\n")
	script += fmt.Sprintf("            \n")
	script += fmt.Sprintf("            # Search for certificate with matching thumbprint\n")
	script += fmt.Sprintf("            $cert = Get-ChildItem -Path 'Cert:\\' -Recurse -ErrorAction SilentlyContinue | where {$_.Thumbprint -eq $thumbprint}\n\n")

	script += fmt.Sprintf("            if($cert) {\n")
	script += fmt.Sprintf("                Write-Host \"[+] Found certificate for decryption\"\n")
	script += fmt.Sprintf("                \n")
	script += fmt.Sprintf("                if($cert.HasPrivateKey) {\n")
	script += fmt.Sprintf("                    Write-Host \"[+] Certificate has private key - attempting decryption\"\n")
	script += fmt.Sprintf("                    \n")
	script += fmt.Sprintf("                    try {\n")
	script += fmt.Sprintf("                        # Decode and decrypt protected settings\n")
	script += fmt.Sprintf("                        $bytes = [System.Convert]::FromBase64String($outputObj.ProtectedSettings)\n")
	script += fmt.Sprintf("                        $envelope = New-Object Security.Cryptography.Pkcs.EnvelopedCms\n")
	script += fmt.Sprintf("                        $envelope.Decode($bytes)\n")
	script += fmt.Sprintf("                        $col = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection $cert\n")
	script += fmt.Sprintf("                        $envelope.Decrypt($col)\n")
	script += fmt.Sprintf("                        $decryptedContent = [text.encoding]::UTF8.getstring($envelope.ContentInfo.Content)\n")
	script += fmt.Sprintf("                        \n")
	script += fmt.Sprintf("                        $outputObj.ProtectedSettingsDecrypted = $decryptedContent | ConvertFrom-Json | ConvertTo-Json -Compress\n")
	script += fmt.Sprintf("                        \n")
	script += fmt.Sprintf("                        Write-Host \"[+] Successfully decrypted protected settings\" -ForegroundColor Green\n")
	script += fmt.Sprintf("                    } catch {\n")
	script += fmt.Sprintf("                        Write-Warning \"[!] Failed to decrypt: $($_.Exception.Message)\"\n")
	script += fmt.Sprintf("                    }\n")
	script += fmt.Sprintf("                } else {\n")
	script += fmt.Sprintf("                    Write-Warning \"[!] Certificate found but no private key available\"\n")
	script += fmt.Sprintf("                }\n")
	script += fmt.Sprintf("            } else {\n")
	script += fmt.Sprintf("                Write-Warning \"[!] Certificate not found for thumbprint: $thumbprint\"\n")
	script += fmt.Sprintf("            }\n")
	script += fmt.Sprintf("        }\n\n")

	script += fmt.Sprintf("        # Output the extension info\n")
	script += fmt.Sprintf("        Write-Output $outputObj\n")
	script += fmt.Sprintf("    }\n")
	script += fmt.Sprintf("}\n\n")

	script += fmt.Sprintf("# Execute the function\n")
	script += fmt.Sprintf("Get-AzureVMExtensionSettings\n")
	script += fmt.Sprintf("```\n\n")

	script += fmt.Sprintf("### Usage Instructions\n\n")
	script += fmt.Sprintf("1. **Copy the script** to the target Windows VM\n")
	script += fmt.Sprintf("2. **Open PowerShell as Administrator**\n")
	script += fmt.Sprintf("3. **Run the script**: `Get-AzureVMExtensionSettings`\n")
	script += fmt.Sprintf("4. **Review the output** for sensitive information in decrypted protected settings\n\n")

	script += fmt.Sprintf("### What to Look For\n\n")
	script += fmt.Sprintf("- **CustomScriptExtension**: URLs to scripts, storage account keys, connection strings\n")
	script += fmt.Sprintf("- **VMAccessAgent**: Administrator or user passwords set via portal\n")
	script += fmt.Sprintf("- **DSC Extensions**: Credentials used in configuration\n")
	script += fmt.Sprintf("- **Disk Encryption**: Key vault URLs and secrets\n")
	script += fmt.Sprintf("- **Domain Join**: Service account credentials\n\n")

	return script
}

// BastionShareableLink contains information about a bastion shareable link
type BastionShareableLink struct {
	BastionName    string
	ResourceGroup  string
	SubscriptionID string
	VMResourceID   string
	ShareableLink  string
	VMName         string
}

// GetBastionShareableLinks enumerates shareable links for all Bastion hosts in a subscription
func GetBastionShareableLinks(session *SafeSession, subscriptionID string, lootMap map[string]*internal.LootFile) {
	if lootMap == nil {
		return
	}

	bastionLoot, ok := lootMap["vms-bastion"]
	if !ok {
		return
	}

	// Get all bastion hosts in subscription
	bastions, err := GetBastionHostsPerSubscription(session, subscriptionID)
	if err != nil || len(bastions) == 0 {
		return
	}

	// Get access token for REST API calls
	token, err := session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return
	}

	var shareableLinks []BastionShareableLink

	// For each bastion, attempt to get shareable links
	for _, bastion := range bastions {
		if bastion.Name == nil || bastion.ID == nil {
			continue
		}

		bastionName := *bastion.Name
		resourceGroup := GetResourceGroupFromID(*bastion.ID)

		// API endpoint to get shareable links
		// POST https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Network/bastionHosts/{name}/GetShareableLinks?api-version=2022-05-01
		url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/bastionHosts/%s/GetShareableLinks?api-version=2022-05-01",
			subscriptionID, resourceGroup, bastionName)

		// Configure retry for ARM API
		config := DefaultRateLimitConfig()
		config.MaxRetries = 5
		config.InitialDelay = 2 * time.Second
		config.MaxDelay = 2 * time.Minute

		// Make REST API call with retry logic
		body, err := HTTPRequestWithRetry(context.Background(), "POST", url, token, nil, config)
		if err != nil {
			// If error, it might mean no shareable links exist or we don't have permissions
			continue
		}

		// Parse JSON response
		var respMap map[string]interface{}
		if err := json.Unmarshal(body, &respMap); err != nil {
			continue
		}

		// Parse response - looking for "value" array with "bsl" (bastion shareable link) field
		if respMap != nil {
			if value, ok := respMap["value"].([]interface{}); ok {
				for _, item := range value {
					if itemMap, ok := item.(map[string]interface{}); ok {
						link := BastionShareableLink{
							BastionName:    bastionName,
							ResourceGroup:  resourceGroup,
							SubscriptionID: subscriptionID,
						}

						// Extract shareable link URL
						if bsl, ok := itemMap["bsl"].(string); ok {
							link.ShareableLink = bsl
						}

						// Extract VM resource ID
						if vm, ok := itemMap["vm"].(map[string]interface{}); ok {
							if id, ok := vm["id"].(string); ok {
								link.VMResourceID = id
								// Extract VM name from resource ID
								parts := strings.Split(id, "/")
								if len(parts) > 0 {
									link.VMName = parts[len(parts)-1]
								}
							}
						}

						if link.ShareableLink != "" {
							shareableLinks = append(shareableLinks, link)
						}
					}
				}
			}
		}
	}

	// Generate output if we found shareable links
	if len(shareableLinks) > 0 {
		bastionLoot.Contents += fmt.Sprintf("\n\n## Bastion Shareable Links\n\n")
		bastionLoot.Contents += fmt.Sprintf("**SECURITY NOTE**: Shareable links provide unauthenticated access to VMs via Bastion!\n")
		bastionLoot.Contents += fmt.Sprintf("Anyone with the link can access the VM without Azure AD authentication.\n\n")
		bastionLoot.Contents += fmt.Sprintf("Found %d active shareable link(s):\n\n", len(shareableLinks))

		for i, link := range shareableLinks {
			bastionLoot.Contents += fmt.Sprintf("### Shareable Link %d\n\n", i+1)
			bastionLoot.Contents += fmt.Sprintf("- **Bastion Name**: %s\n", link.BastionName)
			bastionLoot.Contents += fmt.Sprintf("- **Resource Group**: %s\n", link.ResourceGroup)
			bastionLoot.Contents += fmt.Sprintf("- **VM Name**: %s\n", link.VMName)
			bastionLoot.Contents += fmt.Sprintf("- **VM Resource ID**: %s\n", link.VMResourceID)
			bastionLoot.Contents += fmt.Sprintf("- **Shareable Link**: %s\n\n", link.ShareableLink)
			bastionLoot.Contents += fmt.Sprintf("**Access the VM**: Simply open the shareable link in a browser (no Azure authentication required)\n\n")
			bastionLoot.Contents += fmt.Sprintf("---\n\n")
		}

		bastionLoot.Contents += fmt.Sprintf("## Remediation\n\n")
		bastionLoot.Contents += fmt.Sprintf("To delete shareable links:\n\n")
		bastionLoot.Contents += fmt.Sprintf("```bash\n")
		bastionLoot.Contents += fmt.Sprintf("# Delete shareable link for a specific VM\n")
		bastionLoot.Contents += fmt.Sprintf("az network bastion delete-shareable-link \\\n")
		bastionLoot.Contents += fmt.Sprintf("  --name <BASTION_NAME> \\\n")
		bastionLoot.Contents += fmt.Sprintf("  --resource-group <RESOURCE_GROUP> \\\n")
		bastionLoot.Contents += fmt.Sprintf("  --vms <VM_RESOURCE_ID>\n")
		bastionLoot.Contents += fmt.Sprintf("```\n\n")
	}
}

// VMSSInfo represents a VM Scale Set instance
type VMSSInfo struct {
	SubscriptionID    string
	SubscriptionName  string
	ResourceGroup     string
	Region            string
	ScaleSetName      string
	InstanceID        string
	InstanceName      string
	ComputerName      string
	PrivateIP         string
	AdminUsername     string
	ProvisioningState string
	OSType            string
}

// GetVMScaleSetsForSubscription enumerates all VM Scale Sets and their instances
func GetVMScaleSetsForSubscription(session *SafeSession, subscriptionID string, resourceGroups []string) ([]VMSSInfo, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %v", err)
	}

	ctx := context.Background()

	// Get subscription name
	subName := GetSubscriptionNameFromID(ctx, session, subscriptionID)

	var vmssInstances []VMSSInfo

	// Enumerate each resource group
	for _, rgName := range resourceGroups {
		if rgName == "" {
			continue
		}

		// Get region for resource group (best effort)
		region := "N/A"
		rgs := GetResourceGroupsPerSubscription(session, subscriptionID)
		for _, rg := range rgs {
			if SafeStringPtr(rg.Name) == rgName {
				region = SafeStringPtr(rg.Location)
				break
			}
		}

		// List Scale Sets in this RG using REST API with retry logic
		// We use REST API because the SDK methods for VMSS require additional packages
		url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Compute/virtualMachineScaleSets?api-version=2023-03-01",
			subscriptionID, rgName)

		// Configure retry for ARM API
		config := DefaultRateLimitConfig()
		config.MaxRetries = 5
		config.InitialDelay = 2 * time.Second
		config.MaxDelay = 2 * time.Minute

		body, err := HTTPRequestWithRetry(context.Background(), "GET", url, token, nil, config)
		if err != nil {
			continue
		}

		// Parse VMSS list
		var vmssListResp struct {
			Value []struct {
				Name       string `json:"name"`
				Location   string `json:"location"`
				Properties struct {
					VirtualMachineProfile struct {
						OSProfile struct {
							ComputerNamePrefix string `json:"computerNamePrefix"`
							AdminUsername      string `json:"adminUsername"`
						} `json:"osProfile"`
						StorageProfile struct {
							OSDisk struct {
								OSType string `json:"osType"`
							} `json:"osDisk"`
						} `json:"storageProfile"`
					} `json:"virtualMachineProfile"`
					ProvisioningState string `json:"provisioningState"`
				} `json:"properties"`
			} `json:"value"`
		}

		if err := json.Unmarshal(body, &vmssListResp); err != nil {
			continue
		}

		// For each Scale Set, enumerate instances
		for _, vmss := range vmssListResp.Value {
			scaleSetName := vmss.Name
			vmssRegion := vmss.Location
			if vmssRegion == "" {
				vmssRegion = region
			}

			// List VMSS instances with retry logic
			instancesURL := fmt.Sprintf("https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Compute/virtualMachineScaleSets/%s/virtualMachines?api-version=2023-03-01",
				subscriptionID, rgName, scaleSetName)

			// Configure retry for ARM API
			config := DefaultRateLimitConfig()
			config.MaxRetries = 5
			config.InitialDelay = 2 * time.Second
			config.MaxDelay = 2 * time.Minute

			instBody, err := HTTPRequestWithRetry(context.Background(), "GET", instancesURL, token, nil, config)
			if err != nil {
				continue
			}

			// Parse instance list
			var instanceListResp struct {
				Value []struct {
					InstanceID string `json:"instanceId"`
					Name       string `json:"name"`
					Properties struct {
						OSProfile struct {
							ComputerName  string `json:"computerName"`
							AdminUsername string `json:"adminUsername"`
						} `json:"osProfile"`
						ProvisioningState string `json:"provisioningState"`
						NetworkProfile    struct {
							NetworkInterfaces []struct {
								ID string `json:"id"`
							} `json:"networkInterfaces"`
						} `json:"networkProfile"`
					} `json:"properties"`
				} `json:"value"`
			}

			if err := json.Unmarshal(instBody, &instanceListResp); err != nil {
				continue
			}

			// Process each instance
			for _, inst := range instanceListResp.Value {
				privateIP := "N/A"

				// Try to get private IP from network interface
				if len(inst.Properties.NetworkProfile.NetworkInterfaces) > 0 {
					nicID := inst.Properties.NetworkProfile.NetworkInterfaces[0].ID
					if nicID != "" {
						// Get NIC details with retry logic
						nicURL := fmt.Sprintf("https://management.azure.com%s?api-version=2023-05-01", nicID)

						// Configure retry for ARM API
						nicConfig := DefaultRateLimitConfig()
						nicConfig.MaxRetries = 5
						nicConfig.InitialDelay = 2 * time.Second
						nicConfig.MaxDelay = 2 * time.Minute

						nicBody, err := HTTPRequestWithRetry(context.Background(), "GET", nicURL, token, nil, nicConfig)
						if err == nil {
							var nicData struct {
								Properties struct {
									IPConfigurations []struct {
										Properties struct {
											PrivateIPAddress string `json:"privateIPAddress"`
										} `json:"properties"`
									} `json:"ipConfigurations"`
								} `json:"properties"`
							}
							if json.Unmarshal(nicBody, &nicData) == nil {
								if len(nicData.Properties.IPConfigurations) > 0 {
									privateIP = nicData.Properties.IPConfigurations[0].Properties.PrivateIPAddress
								}
							}
						}
					}
				}

				osType := vmss.Properties.VirtualMachineProfile.StorageProfile.OSDisk.OSType
				if osType == "" {
					osType = "N/A"
				}

				vmssInstances = append(vmssInstances, VMSSInfo{
					SubscriptionID:    subscriptionID,
					SubscriptionName:  subName,
					ResourceGroup:     rgName,
					Region:            vmssRegion,
					ScaleSetName:      scaleSetName,
					InstanceID:        inst.InstanceID,
					InstanceName:      inst.Name,
					ComputerName:      inst.Properties.OSProfile.ComputerName,
					PrivateIP:         privateIP,
					AdminUsername:     inst.Properties.OSProfile.AdminUsername,
					ProvisioningState: inst.Properties.ProvisioningState,
					OSType:            osType,
				})
			}
		}
	}

	return vmssInstances, nil
}
