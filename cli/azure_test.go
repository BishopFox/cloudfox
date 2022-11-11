package cli

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/compute/mgmt/compute"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/network/mgmt/network"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/resources"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/subscriptions"
	"github.com/BishopFox/cloudfox/azure"
	"github.com/BishopFox/cloudfox/constants"
	"github.com/BishopFox/cloudfox/utils"
	"github.com/aws/smithy-go/ptr"
)

func TestAzRunInstancesCommand(t *testing.T) {
	fmt.Println()
	fmt.Println("[test case] Azure Run Instances Command")

	// Mocked functions to simulate Azure responses
	azure.GetSubscriptions = GetSubscriptions
	azure.GetResourceGroups = GetResourceGroups
	azure.GetComputeVMsPerResourceGroup = GetComputeVMsPerResourceGroup
	azure.GetNICdetails = GetNICdetails
	azure.GetPublicIPM = GetPublicIPM

	// Test case parameters
	utils.MockFileSystem(true)

	subtests := []struct {
		Name           string
		AzSubFilter    string
		AzRGFilter     string
		AzVerbosity    int
		AzOutputFormat string
	}{
		{
			Name:           "./cloudfox az instances --subscription SUB_ID",
			AzSubFilter:    "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAA",
			AzRGFilter:     "interactive",
			AzVerbosity:    2,
			AzOutputFormat: "table",
		},
		{
			Name:           "./cloudfox az instances --resource-group RG_NAME",
			AzSubFilter:    "interactive",
			AzRGFilter:     "B3",
			AzVerbosity:    2,
			AzOutputFormat: "table",
		},
	}

	for _, s := range subtests {
		fmt.Printf("\n[subtest] %s\n", s.Name)
		AzRunInstancesCommand(s.AzSubFilter, s.AzRGFilter, s.AzOutputFormat, s.AzVerbosity)
	}
}

// The mocked functions below are used to simulate Azure responses
var GetSubscriptions = func() []subscriptions.Subscription {
	return []subscriptions.Subscription{
		{SubscriptionID: ptr.String("AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAA")},
		{SubscriptionID: ptr.String("BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBB")},
	}
}

var GetResourceGroups = func(subscriptionID string) []resources.Group {
	switch subscriptionID {
	case "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAA":
		return []resources.Group{
			{Name: ptr.String("A1")},
			{Name: ptr.String("A2")},
		}
	case "BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBB":
		return []resources.Group{
			{Name: ptr.String("B3")},
			{Name: ptr.String("B4")},
		}
	default:
		return []resources.Group{}
	}
}

var GetComputeVMsPerResourceGroup = func(subscriptionID, resourceGroup string) []compute.VirtualMachine {
	testFile, err := os.ReadFile(constants.VMS_TEST_FILE)
	if err != nil {
		log.Fatalf("could not read file %s", constants.VMS_TEST_FILE)
	}
	var vms []compute.VirtualMachine
	err = json.Unmarshal(testFile, &vms)
	if err != nil {
		log.Fatalf("could not unmarshall file %s", constants.VMS_TEST_FILE)
	}

	if subscriptionID == "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAA" || resourceGroup == "A1" {
		return vms[:1]
	}
	if subscriptionID == "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAA" || resourceGroup == "A2" {
		return vms[1:2]
	}
	if subscriptionID == "BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBB" || resourceGroup == "B3" {
		return vms[2:]
	}
	return []compute.VirtualMachine{}
}

var GetNICdetails = func(subscriptionID, resourceGroup string, nicReference compute.NetworkInterfaceReference) (network.Interface, error) {
	testFile, err := os.ReadFile(constants.NICS_TEST_FILE)
	if err != nil {
		log.Fatalf("could not read file %s", constants.NICS_TEST_FILE)
	}
	var nics []network.Interface
	err = json.Unmarshal(testFile, &nics)
	if err != nil {
		log.Fatalf("could not unmarshall file %s", constants.VMS_TEST_FILE)
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
	case "NetworkInterface5":
		return nics[4], nil
	default:
		return network.Interface{}, fmt.Errorf("nic not found: %s", ptr.ToString(nicReference.ID))
	}
}

var GetPublicIPM = func(subscriptionID, resourceGroup string, ip network.InterfaceIPConfiguration) (*string, error) {
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
