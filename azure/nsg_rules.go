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


func AzNSGRulesCommand(AzClient *internal.AzureClient, AzOutputFormat, AzOutputDirectory, Version string, AzVerbosity int, AzWrapTable bool, AzMergedTable bool) error {


	if len(AzClient.AzTenants) > 0 {
		for _, AzTenant := range AzClient.AzTenants {
			// cloudfox azure nsg-rules --tenant [TENANT_ID | PRIMARY_DOMAIN]

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
					fmt.Sprintf("%s (%s)", ptr.ToString(AzTenant.DefaultDomain), ptr.ToString(AzTenant.TenantID)))

				o.PrefixIdentifier = ptr.ToString(AzTenant.DefaultDomain)
				o.Table.DirectoryName = filepath.Join(AzOutputDirectory, globals.CLOUDFOX_BASE_DIRECTORY, globals.AZ_DIR_BASE, ptr.ToString(AzTenant.DefaultDomain), "1-tenant-level")

				header, body, err = getNSGInfoPerTenant(ptr.ToString(AzTenant.TenantID))

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

				for _, s := range GetSubscriptionsPerTenantID(ptr.ToString(AzTenant.TenantID)) {
					//runNSGCommandForSingleSubcription(ptr.ToString(s.SubscriptionID), AzOutputDirectory, AzVerbosity, AzWrapTable, Version)
					fmt.Println(s)
				}
			}
		}
	} else {
		for _, AzSubscription := range AzClient.AzSubscriptions {
			runNSGCommandForSingleSubcription(*AzSubscription.SubscriptionID, AzOutputDirectory, AzVerbosity, AzWrapTable, Version)
		}
	}

	return nil
}
