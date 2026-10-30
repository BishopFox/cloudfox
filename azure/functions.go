package azure

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/subscriptions"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/web/mgmt/web"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/smithy-go/ptr"
	"github.com/fatih/color"
	"github.com/kyokomi/emoji"
)

var (
	getFunctionApps          = getFunctionAppsOriginal
	getFunctionConfiguration = getFunctionConfigurationOriginal
)

type functionConfiguration struct {
	AppSettings       map[string]*string
	ConnectionStrings map[string]*web.ConnStringValueTypePair
}

func AzFuncCommand(tenantID, subscription, outputDirectory, version string, verbosity int, wrap, merged bool) error {
	if tenantID != "" && subscription == "" && merged {
		tenant := populateTenant(tenantID)
		if ptr.ToString(tenant.ID) == "" {
			return fmt.Errorf("could not find Azure tenant %q", tenantID)
		}
		subs := GetSubscriptionsPerTenantID(ptr.ToString(tenant.ID))
		var rows [][]string
		var loot strings.Builder
		for _, sub := range subs {
			subRows, subLoot, warnings, err := getFunctionData(sub)
			if err != nil {
				return err
			}
			rows = append(rows, subRows...)
			loot.WriteString(subLoot)
			for _, warning := range warnings {
				fmt.Printf("[%s] %s\n", color.CyanString(globals.AZ_FUNC_MODULE_NAME), warning)
			}
		}
		if len(subs) > 0 {
			writeScopedAzureOutput(outputDirectory, subs[0], globals.AZ_FUNC_MODULE_NAME, []string{"Function Name", "Subscription Name", "Subscription ID", "URL"}, rows, "function-app-configuration", loot.String(), verbosity, wrap, true)
		}
		return nil
	}
	return runAzureScopedModule(tenantID, subscription, merged, func(sub subscriptions.Subscription) error {
		fmt.Printf("[%s][%s] Enumerating Function Apps for subscription %s (%s)\n", color.CyanString(emoji.Sprintf(":fox:cloudfox %s :fox:", version)), color.CyanString(globals.AZ_FUNC_MODULE_NAME), ptr.ToString(sub.DisplayName), ptr.ToString(sub.SubscriptionID))
		rows, loot, errs, err := getFunctionData(sub)
		if err != nil {
			return err
		}
		for _, warning := range errs {
			fmt.Printf("[%s] %s\n", color.CyanString(globals.AZ_FUNC_MODULE_NAME), warning)
		}
		writeScopedAzureOutput(outputDirectory, sub, globals.AZ_FUNC_MODULE_NAME, []string{"Function Name", "Subscription Name", "Subscription ID", "URL"}, rows, "function-app-configuration", loot, verbosity, wrap, false)
		return nil
	})
}

func getFunctionData(subscription subscriptions.Subscription) ([][]string, string, []error, error) {
	subscriptionID := ptr.ToString(subscription.SubscriptionID)
	apps, err := getFunctionApps(subscriptionID)
	if err != nil {
		return nil, "", nil, fmt.Errorf("could not enumerate Function Apps for subscription %s: %w", subscriptionID, err)
	}
	var rows [][]string
	var loot strings.Builder
	var warnings []error
	for _, app := range apps {
		if !strings.Contains(strings.ToLower(ptr.ToString(app.Kind)), "functionapp") {
			continue
		}
		name := ptr.ToString(app.Name)
		host := ""
		if app.SiteProperties != nil {
			host = ptr.ToString(app.DefaultHostName)
		}
		appURL := host
		if host != "" {
			appURL = "https://" + host
		}
		rows = append(rows, []string{name, ptr.ToString(subscription.DisplayName), subscriptionID, appURL})
		rg := resourceGroupFromID(ptr.ToString(app.ID))
		config, err := getFunctionConfiguration(subscriptionID, rg, name)
		if err != nil {
			warnings = append(warnings, fmt.Errorf("could not read configuration for Function App %s: %w", name, err))
			continue
		}
		loot.WriteString(formatFunctionLoot(name, appURL, config))
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i][0] < rows[j][0] })
	return rows, loot.String(), warnings, nil
}

func formatFunctionLoot(name, appURL string, config functionConfiguration) string {
	if len(config.AppSettings) == 0 && len(config.ConnectionStrings) == 0 {
		return ""
	}
	var loot strings.Builder
	fmt.Fprintf(&loot, "===============================================================\nFunction App: %s\nURL: %s\n\n", name, appURL)
	loot.WriteString("App Settings:\n")
	settings := sortedKeys(config.AppSettings)
	for _, key := range settings {
		fmt.Fprintf(&loot, "%s=%s\n", key, ptr.ToString(config.AppSettings[key]))
	}
	loot.WriteString("\nConnection Strings:\n")
	connections := make([]string, 0, len(config.ConnectionStrings))
	for key := range config.ConnectionStrings {
		connections = append(connections, key)
	}
	sort.Strings(connections)
	for _, key := range connections {
		value := config.ConnectionStrings[key]
		if value != nil {
			fmt.Fprintf(&loot, "%s=%s (type=%s)\n", key, ptr.ToString(value.Value), value.Type)
		}
	}
	loot.WriteString("\n")
	return loot.String()
}

func sortedKeys(values map[string]*string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func getFunctionAppsOriginal(subscriptionID string) ([]web.Site, error) {
	client := internal.GetWebAppsClient(subscriptionID)
	page, err := client.List(context.TODO())
	if err != nil {
		return nil, err
	}
	var apps []web.Site
	for page.NotDone() {
		apps = append(apps, page.Values()...)
		if err := page.NextWithContext(context.TODO()); err != nil {
			return nil, err
		}
	}
	return apps, nil
}

func getFunctionConfigurationOriginal(subscriptionID, resourceGroup, name string) (functionConfiguration, error) {
	client := internal.GetWebAppsClient(subscriptionID)
	settings, err := client.ListApplicationSettings(context.TODO(), resourceGroup, name)
	if err != nil {
		return functionConfiguration{}, err
	}
	connections, err := client.ListConnectionStrings(context.TODO(), resourceGroup, name)
	if err != nil {
		return functionConfiguration{}, err
	}
	return functionConfiguration{AppSettings: settings.Properties, ConnectionStrings: connections.Properties}, nil
}

func resourceGroupFromID(id string) string {
	parts := strings.Split(strings.Trim(id, "/"), "/")
	for i := 0; i+1 < len(parts); i++ {
		if strings.EqualFold(parts[i], "resourceGroups") {
			return parts[i+1]
		}
	}
	return ""
}

func runAzureScopedModule(tenantID, subscription string, merged bool, run func(subscriptions.Subscription) error) error {
	if tenantID != "" && subscription == "" {
		tenant := populateTenant(tenantID)
		if ptr.ToString(tenant.ID) == "" {
			return fmt.Errorf("could not find Azure tenant %q", tenantID)
		}
		for _, sub := range GetSubscriptionsPerTenantID(ptr.ToString(tenant.ID)) {
			if err := run(sub); err != nil {
				return err
			}
		}
		return nil
	}
	if tenantID == "" && subscription != "" {
		id := ptr.ToString(GetSubscriptionID(subscription))
		if id == "" {
			return fmt.Errorf("could not find Azure subscription %q", subscription)
		}
		for _, sub := range GetSubscriptions() {
			if ptr.ToString(sub.SubscriptionID) == id {
				return run(sub)
			}
		}
	}
	return fmt.Errorf("please specify either --tenant or --subscription")
}

func writeScopedAzureOutput(outputDirectory string, sub subscriptions.Subscription, module string, header []string, rows [][]string, lootName, loot string, verbosity int, wrap, merged bool) {
	tenant := populateTenant(ptr.ToString(sub.TenantID))
	suffix := ptr.ToString(sub.DisplayName)
	prefix := ptr.ToString(sub.DisplayName)
	if merged {
		suffix = "1-tenant-level"
		prefix = ptr.ToString(tenant.DefaultDomain)
	}
	o := internal.OutputClient{Verbosity: verbosity, CallingModule: module, PrefixIdentifier: prefix, Table: internal.TableClient{Wrap: wrap, DirectoryName: filepath.Join(outputDirectory, globals.CLOUDFOX_BASE_DIRECTORY, globals.AZ_DIR_BASE, ptr.ToString(tenant.DefaultDomain), suffix)}}
	o.Table.TableFiles = append(o.Table.TableFiles, internal.TableFile{Header: header, Body: rows, Name: module})
	if loot != "" {
		o.Loot.DirectoryName = filepath.Join(o.Table.DirectoryName, "loot")
		o.Loot.LootFiles = append(o.Loot.LootFiles, internal.LootFile{Name: lootName, Contents: loot})
		o.WriteFullOutput(o.Table.TableFiles, o.Loot.LootFiles)
	} else {
		o.WriteFullOutput(o.Table.TableFiles, nil)
	}
	fmt.Println()
}
