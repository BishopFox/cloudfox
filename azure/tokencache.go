package azure

import (
	"fmt"
	"path/filepath"
	"strconv"
	"time"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/smithy-go/ptr"
)

func AzTokenCacheCommand(outputDirectory, version string, wrap bool, verbosity int, listResourceGroups bool) error {
	azureLogger.InfoM("Enumerating Azure CLI sessions...", globals.AZ_TOKENCACHE_MODULE_NAME)
	header, body := getTokenCacheRelevantDataSubsOnly()
	fileName := globals.AZ_TOKENCACHE_MODULE_NAME + "-subscriptions"
	if listResourceGroups {
		header, body = getTokenCacheRelevantDataPerRG()
		fileName = globals.AZ_TOKENCACHE_MODULE_NAME + "-resource-groups"
	}

	o := internal.OutputClient{
		Verbosity:        verbosity,
		CallingModule:    globals.AZ_TOKENCACHE_MODULE_NAME,
		PrefixIdentifier: "N/A",
		Table: internal.TableClient{
			Wrap:          wrap,
			DirectoryName: filepath.Join(outputDirectory, globals.CLOUDFOX_BASE_DIRECTORY, globals.AZ_DIR_BASE, "tokencache-data"),
		},
	}
	o.Table.TableFiles = append(o.Table.TableFiles, internal.TableFile{
		Header: header,
		Body:   body,
		Name:   fmt.Sprintf("%s-%s", fileName, strconv.FormatInt(time.Now().Unix(), 10)),
	})
	o.WriteFullOutput(o.Table.TableFiles, nil)
	return nil
}

func getTokenCacheRelevantDataPerRG() ([]string, [][]string) {
	header := []string{"Tenant ID", "Tenant Primary Domain", "Subscription ID", "Subscription Name", "RG Name", "Region"}
	var body [][]string
	for _, tenant := range getTenants() {
		for _, subscription := range GetSubscriptions() {
			if ptr.ToString(tenant.TenantID) != ptr.ToString(subscription.TenantID) {
				continue
			}
			for _, resourceGroup := range getResourceGroups(ptr.ToString(subscription.SubscriptionID)) {
				body = append(body, []string{ptr.ToString(subscription.TenantID), ptr.ToString(tenant.DefaultDomain), ptr.ToString(subscription.SubscriptionID), ptr.ToString(subscription.DisplayName), ptr.ToString(resourceGroup.Name), ptr.ToString(resourceGroup.Location)})
			}
		}
	}
	return header, body
}

func getTokenCacheRelevantDataSubsOnly() ([]string, [][]string) {
	header := []string{"Tenant ID", "Tenant Primary Domain", "Subscription ID", "Subscription Name"}
	var body [][]string
	for _, tenant := range getTenants() {
		for _, subscription := range GetSubscriptions() {
			if ptr.ToString(tenant.TenantID) == ptr.ToString(subscription.TenantID) {
				body = append(body, []string{ptr.ToString(subscription.TenantID), ptr.ToString(tenant.DefaultDomain), ptr.ToString(subscription.SubscriptionID), ptr.ToString(subscription.DisplayName)})
			}
		}
	}
	return header, body
}
