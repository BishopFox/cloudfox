package azure

import (
	"context"
	"strings"
	"fmt"
	"path/filepath"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/smithy-go/ptr"
	"github.com/fatih/color"
	"github.com/kyokomi/emoji"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/network/mgmt/network"
	"github.com/Azure/go-autorest/autorest/azure"
)


type NSGLinksModule struct {
	NSGClient *network.SecurityGroupsClient

}

func AzNSGLinksCommand(AzTenantID string, AzSubscription string, AzResourceIDs []string, AzOutputFormat, AzOutputDirectory, Version string, AzVerbosity int, AzWrapTable bool, AzMergedTable bool) error {


	if AzTenantID != "" && AzSubscription == "" {
		// cloudfox azure nsg-links --tenant [TENANT_ID | PRIMARY_DOMAIN]
		tenantInfo := populateTenant(AzTenantID)

		if AzMergedTable {

			// set up table vars
			var header []string
			var body [][]string
			// setup logging client
			o := internal.OutputClient{
				Verbosity:     AzVerbosity,
				CallingModule: globals.AZ_NSG_LINKS_MODULE_NAME,
				Table: internal.TableClient{
					Wrap: AzWrapTable,
				},
			}

			var err error

			fmt.Printf("[%s][%s] Enumerating Network Security Group links for tenant %s\n",
				color.CyanString(emoji.Sprintf(":fox:cloudfox %s :fox:", Version)), color.CyanString(globals.AZ_NSG_LINKS_MODULE_NAME),
				fmt.Sprintf("%s (%s)", ptr.ToString(tenantInfo.DefaultDomain), ptr.ToString(tenantInfo.ID)))

			o.PrefixIdentifier = ptr.ToString(tenantInfo.DefaultDomain)
			o.Table.DirectoryName = filepath.Join(AzOutputDirectory, globals.CLOUDFOX_BASE_DIRECTORY, globals.AZ_DIR_BASE, ptr.ToString(tenantInfo.DefaultDomain), "1-tenant-level")

			header, body, err = getNSGInfoPerTenant(ptr.ToString(tenantInfo.ID))

			if err != nil {
				return err
			}
			o.Table.TableFiles = append(o.Table.TableFiles,
				internal.TableFile{
					Header: header,
					Body:   body,
					Name:   fmt.Sprintf(globals.AZ_NSG_LINKS_MODULE_NAME)})

			if body != nil {
				o.WriteFullOutput(o.Table.TableFiles, nil)
			}
		} else {

			for _, s := range GetSubscriptionsPerTenantID(ptr.ToString(tenantInfo.ID)) {
				runNSGCommandForSingleSubcription(ptr.ToString(s.SubscriptionID), AzOutputDirectory, AzVerbosity, AzWrapTable, Version)
			}
		}

	} else if AzTenantID == "" && AzSubscription != "" {
		//cloudfox azure nsg-links  --subscription [SUBSCRIPTION_ID | SUBSCRIPTION_NAME]
		runNSGCommandForSingleSubcription(AzSubscription, AzOutputDirectory, AzVerbosity, AzWrapTable, Version)

	} else {
		// Error: please make a valid flag selection
		fmt.Println("Please enter a valid input with a valid flag. Use --help for info.")
	}

	return nil
}

func runNSGCommandForSingleSubcription(AzSubscription string, AzOutputDirectory string, AzVerbosity int, AzWrapTable bool, Version string) error {
	var err error
	// setup logging client
	o := internal.OutputClient{
		Verbosity:     AzVerbosity,
		CallingModule: globals.AZ_NSG_LINKS_MODULE_NAME,
		Table: internal.TableClient{
			Wrap: AzWrapTable,
		},
	}

	// set up table vars
	var header []string
	var body [][]string

	tenantID := ptr.ToString(GetTenantIDPerSubscription(AzSubscription))
	tenantInfo := populateTenant(tenantID)
	AzSubscriptionInfo := PopulateSubsriptionType(AzSubscription)
	o.PrefixIdentifier = AzSubscriptionInfo.Name
	o.Table.DirectoryName = filepath.Join(AzOutputDirectory, globals.CLOUDFOX_BASE_DIRECTORY, globals.AZ_DIR_BASE, ptr.ToString(tenantInfo.DefaultDomain), AzSubscriptionInfo.Name)

	fmt.Printf(
		"[%s][%s] Enumerating Network Security Groups links for subscription %s\n",
		color.CyanString(emoji.Sprintf(":fox:cloudfox %s :fox:", Version)),
		color.CyanString(globals.AZ_NSG_LINKS_MODULE_NAME),
		fmt.Sprintf("%s (%s)", AzSubscriptionInfo.Name, AzSubscriptionInfo.ID))
	//AzTenantID := ptr.ToString(GetTenantIDPerSubscription(AzSubscription))
	header, body, err = getNSGInfoPerSubscription(ptr.ToString(tenantInfo.ID), AzSubscriptionInfo.ID)
	if err != nil {
		return err
	}

	o.Table.TableFiles = append(o.Table.TableFiles,
		internal.TableFile{
			Header: header,
			Body:   body,
			Name:   fmt.Sprintf(globals.AZ_NSG_LINKS_MODULE_NAME)})
	if body != nil {
		o.WriteFullOutput(o.Table.TableFiles, nil)

	}
	return nil

}


func getNSGInfoPerTenant(AzTenantID string) ([]string, [][]string, error) {
	var err error
	var header []string
	var body, b [][]string

	for _, s := range GetSubscriptionsPerTenantID(AzTenantID) {
		header, b, err = getNSGData(ptr.ToString(s.SubscriptionID))
		if err != nil {
			return nil, nil, err
		} else {
			body = append(body, b...)
		}
	}
	return header, body, nil
}

func getNSGInfoPerSubscription(AzTenantID, AzSubscriptionID string) ([]string, [][]string, error) {
	var err error
	var header []string
	var body [][]string

	for _, s := range GetSubscriptions() {
		if ptr.ToString(s.SubscriptionID) == AzSubscriptionID {
			header, body, err = getNSGData(ptr.ToString(s.SubscriptionID))
			if err != nil {
				return nil, nil, err
			}
		}
	}
	return header, body, nil
}
func value(ptr *string) string {
	if ptr != nil {
		return *ptr
	} else {
		return "AAAAA"
	}
}

func getNSGData(subscriptionID string) ([]string, [][]string, error) {
	tableHeader := []string{"Subscription Name", "Network Security Group", "Link Type", "Linked Name", "Link Target"}
	var tableBody [][]string
	networkSecurityGroups, err := getNSG(subscriptionID)
	nsgClient := internal.GetNSGClient(subscriptionID)
	//subnetsClient := internal.GetSubnetsClient(subscriptionID)
	if err != nil {
		return tableHeader, tableBody, err
	}
	for _, networkSecurityGroup := range *networkSecurityGroups {
		var resource azure.Resource
		resource, err = azure.ParseResourceID(*networkSecurityGroup.ID)
		if err != nil {
			continue
		}
		networkSecurityGroup, _ = nsgClient.Get(context.TODO(), resource.ResourceGroup, resource.ResourceName, "Subnets,NetworkInterfaces")
		fmt.Println(*networkSecurityGroup.ID)
		if networkSecurityGroup.Subnets != nil {
			for _, subnet := range *networkSecurityGroup.Subnets {
				var addressPrefixes []string
				if subnet.AddressPrefixes != nil {
					for _, prefix := range *subnet.AddressPrefixes {
						addressPrefixes = append(addressPrefixes, prefix)
					}
				}
				if subnet.AddressPrefix != nil {
					addressPrefixes = append(addressPrefixes, *subnet.AddressPrefix)
				}
				tableBody = append(tableBody,
					[]string{
						subscriptionID,
						*networkSecurityGroup.Name,
						"Subnet",
						value(subnet.Name),
						strings.Join(addressPrefixes[:], "\n"),
					},
				)
			}
		}
		if networkSecurityGroup.NetworkInterfaces != nil {
			for _, networkInterface := range *networkSecurityGroup.NetworkInterfaces {
				tableBody = append(tableBody,
					[]string{
						subscriptionID,
						*networkSecurityGroup.Name,
						"NIC",
						value(networkInterface.Name),
						strings.Join(internal.GetIPAddressesFromInterface(&networkInterface)[:], "\n"),
					},
				)
			}
		}
	}
	return tableHeader, tableBody, nil
}


func getNSG(subscriptionID string) (*[]network.SecurityGroup, error) {
	nsgClient := internal.GetNSGClient(subscriptionID)
	var networkSecurityGroups []network.SecurityGroup
	for page, err := nsgClient.ListAll(context.TODO()); page.NotDone(); page.Next() {
		if err != nil {
			return nil, fmt.Errorf("could not get network security groups for subscription")
		}
		networkSecurityGroups = append(networkSecurityGroups, page.Values()...)
	}
	return &networkSecurityGroups, nil
}
