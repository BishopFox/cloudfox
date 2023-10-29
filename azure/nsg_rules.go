package azure

import (
	"fmt"
	"path/filepath"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/smithy-go/ptr"
	"github.com/fatih/color"
	"github.com/kyokomi/emoji"
)


func AzNSGRulesCommand(AzTenantID string, AzSubscription string, AzResourceIDs []string, AzOutputFormat, AzOutputDirectory, Version string, AzVerbosity int, AzWrapTable bool, AzMergedTable bool) error {


	if AzTenantID != "" && AzSubscription == "" {
		// cloudfox azure nsg-rules --tenant [TENANT_ID | PRIMARY_DOMAIN]
		tenantInfo := populateTenant(AzTenantID)

		if AzMergedTable {

			// set up table vars
			var header []string
			var body [][]string
			// setup logging client
			o := internal.OutputClient{
				Verbosity:     AzVerbosity,
				CallingModule: globals.AZ_NSG_RULES_MODULE_NAME,
				Table: internal.TableClient{
					Wrap: AzWrapTable,
				},
			}

			var err error

			fmt.Printf("[%s][%s] Enumerating Network Security Group rules for tenant %s\n",
				color.CyanString(emoji.Sprintf(":fox:cloudfox %s :fox:", Version)), color.CyanString(globals.AZ_NSG_RULES_MODULE_NAME),
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
					Name:   fmt.Sprintf(globals.AZ_NSG_RULES_MODULE_NAME)})

			if body != nil {
				o.WriteFullOutput(o.Table.TableFiles, nil)
			}
		} else {

			for _, s := range GetSubscriptionsPerTenantID(ptr.ToString(tenantInfo.ID)) {
				//runNSGCommandForSingleSubcription(ptr.ToString(s.SubscriptionID), AzOutputDirectory, AzVerbosity, AzWrapTable, Version)
				fmt.Println(s)
			}
		}

	} else if AzTenantID == "" && AzSubscription != "" {
		//cloudfox azure nsg-rules  --subscription [SUBSCRIPTION_ID | SUBSCRIPTION_NAME]
		runNSGCommandForSingleSubcription(AzSubscription, AzOutputDirectory, AzVerbosity, AzWrapTable, Version)

	} else {
		// Error: please make a valid flag selection
		fmt.Println("Please enter a valid input with a valid flag. Use --help for info.")
	}

	return nil
}
