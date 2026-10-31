package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/subscriptions"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/web/mgmt/web"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/smithy-go/ptr"
)

var (
	getFunctionApps          = getFunctionAppsOriginal
	getFunctionConfiguration = getFunctionConfigurationOriginal
	getFunctions             = getFunctionsOriginal
)

type functionConfiguration struct {
	AppSettings       map[string]*string
	ConnectionStrings map[string]*web.ConnStringValueTypePair
	AuthSettings      web.SiteAuthSettingsV2
}

type functionLoot struct {
	Configuration string
	TestData      string
}

func AzFuncCommand(tenantID, subscription, outputDirectory, version string, verbosity int, wrap, merged bool) error {
	if tenantID != "" && subscription == "" {
		tenant := populateTenant(tenantID)
		if ptr.ToString(tenant.ID) == "" {
			return fmt.Errorf("could not find Azure tenant %q", tenantID)
		}
		azureLogger.InfoM(fmt.Sprintf("Enumerating Function Apps for tenant %s (%s)", ptr.ToString(tenant.DefaultDomain), ptr.ToString(tenant.ID)), globals.AZ_FUNC_MODULE_NAME)
		subs := GetSubscriptionsPerTenantID(ptr.ToString(tenant.ID))
		if !merged {
			for _, sub := range subs {
				if err := runFuncForSubscription(sub, outputDirectory, verbosity, wrap); err != nil {
					return err
				}
			}
			return nil
		}
		var rows [][]string
		var loot functionLoot
		for _, sub := range subs {
			subRows, subLoot, warnings, err := getFunctionData(sub)
			if err != nil {
				return err
			}
			rows = append(rows, subRows...)
			loot.Configuration += subLoot.Configuration
			loot.TestData += subLoot.TestData
			for _, warning := range warnings {
				azureLogger.WarnM(warning.Error(), globals.AZ_FUNC_MODULE_NAME)
			}
		}
		if len(subs) > 0 {
			writeFunctionOutput(outputDirectory, ptr.ToString(tenant.DefaultDomain), "1-tenant-level", ptr.ToString(tenant.DefaultDomain), rows, loot, verbosity, wrap)
		}
		return nil
	}
	if tenantID == "" && subscription != "" {
		id := ptr.ToString(GetSubscriptionID(subscription))
		for _, sub := range GetSubscriptions() {
			if ptr.ToString(sub.SubscriptionID) == id {
				return runFuncForSubscription(sub, outputDirectory, verbosity, wrap)
			}
		}
		return fmt.Errorf("could not find Azure subscription %q", subscription)
	}
	return fmt.Errorf("please specify either --tenant or --subscription")
}

func runFuncForSubscription(sub subscriptions.Subscription, outputDirectory string, verbosity int, wrap bool) error {
	azureLogger.InfoM(fmt.Sprintf("Enumerating Function Apps for subscription %s (%s)", ptr.ToString(sub.DisplayName), ptr.ToString(sub.SubscriptionID)), globals.AZ_FUNC_MODULE_NAME)
	rows, loot, warnings, err := getFunctionData(sub)
	if err != nil {
		return err
	}
	for _, warning := range warnings {
		azureLogger.WarnM(warning.Error(), globals.AZ_FUNC_MODULE_NAME)
	}
	tenant := populateTenant(ptr.ToString(sub.TenantID))
	writeFunctionOutput(outputDirectory, ptr.ToString(tenant.DefaultDomain), ptr.ToString(sub.DisplayName), ptr.ToString(sub.DisplayName), rows, loot, verbosity, wrap)
	return nil
}

func getFunctionData(subscription subscriptions.Subscription) ([][]string, functionLoot, []error, error) {
	subscriptionID := ptr.ToString(subscription.SubscriptionID)
	apps, err := getFunctionApps(subscriptionID)
	if err != nil {
		return nil, functionLoot{}, nil, fmt.Errorf("could not enumerate Function Apps for subscription %s: %w", subscriptionID, err)
	}
	var rows [][]string
	var loot functionLoot
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
		rg := resourceGroupFromID(ptr.ToString(app.ID))
		config, err := getFunctionConfiguration(subscriptionID, rg, name)
		if err != nil {
			warnings = append(warnings, fmt.Errorf("could not read configuration for Function App %s: %w", name, err))
		}
		providers := functionAuthProviders(config.AuthSettings)
		functions, err := getFunctions(subscriptionID, rg, name)
		if err != nil {
			warnings = append(warnings, fmt.Errorf("could not enumerate functions for Function App %s: %w", name, err))
			rows = append(rows, functionAppFallbackRow(name, subscription, appURL, providers))
		} else if len(functions) == 0 {
			rows = append(rows, functionAppFallbackRow(name, subscription, appURL, providers))
		} else {
			for _, function := range functions {
				functionName := lastResourceIDSegment(ptr.ToString(function.Name))
				trigger := "Unknown"
				state := "Unknown"
				if function.FunctionEnvelopeProperties != nil {
					trigger = functionTrigger(function.Config, ptr.ToString(function.InvokeURLTemplate))
					state = "Enabled"
					if ptr.ToBool(function.IsDisabled) {
						state = "Disabled"
					}
					loot.TestData += formatFunctionTestDataLoot(subscriptionID, rg, name, functionName, ptr.ToString(function.TestData))
				}
				authMethods := append(functionAuthLevels(function.Config), providers...)
				if len(authMethods) == 0 {
					authMethods = []string{"Unknown"}
				}
				rows = append(rows, []string{name, functionName, trigger, strings.Join(uniqueStrings(authMethods), ", "), state, ptr.ToString(subscription.DisplayName), subscriptionID})
			}
		}
		loot.Configuration += formatFunctionLoot(name, appURL, config)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i][0] == rows[j][0] {
			return rows[i][1] < rows[j][1]
		}
		return rows[i][0] < rows[j][0]
	})
	return rows, loot, warnings, nil
}

func functionAppFallbackRow(name string, subscription subscriptions.Subscription, appURL string, providers []string) []string {
	authentication := strings.Join(providers, ", ")
	if authentication == "" {
		authentication = "Unknown"
	}
	trigger := "Unknown"
	if appURL != "" {
		trigger = "App URL: " + appURL
	}
	return []string{name, "", trigger, authentication, "Unknown", ptr.ToString(subscription.DisplayName), ptr.ToString(subscription.SubscriptionID)}
}

func functionTableHeader() []string {
	return []string{"Function App", "Function Name", "Trigger", "Authentication", "State", "Subscription Name", "Subscription ID"}
}

func functionVisibleColumns() []string {
	return []string{"Function App", "Function Name", "Trigger", "Authentication", "State", "Subscription Name"}
}

func formatFunctionLoot(name, appURL string, config functionConfiguration) string {
	if len(config.AppSettings) == 0 && len(config.ConnectionStrings) == 0 {
		return ""
	}
	var loot strings.Builder
	fmt.Fprintf(&loot, "===============================================================\nFunction App: %s\nURL: %s\n\n", name, appURL)
	fmt.Fprintf(&loot, "App Service Authentication: %s\n\n", strings.Join(functionAuthProviders(config.AuthSettings), ", "))
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

func functionAuthProviders(settings web.SiteAuthSettingsV2) []string {
	if settings.SiteAuthSettingsV2Properties == nil || settings.Platform == nil || !ptr.ToBool(settings.Platform.Enabled) {
		return nil
	}
	providers := settings.IdentityProviders
	if providers == nil {
		return []string{"App Service Authentication enabled"}
	}
	var methods []string
	if providers.AzureActiveDirectory != nil && ptr.ToBool(providers.AzureActiveDirectory.Enabled) {
		methods = append(methods, "Entra ID")
	}
	if providers.Facebook != nil && ptr.ToBool(providers.Facebook.Enabled) {
		methods = append(methods, "Facebook")
	}
	if providers.GitHub != nil && ptr.ToBool(providers.GitHub.Enabled) {
		methods = append(methods, "GitHub")
	}
	if providers.Google != nil && ptr.ToBool(providers.Google.Enabled) {
		methods = append(methods, "Google")
	}
	if providers.LegacyMicrosoftAccount != nil && ptr.ToBool(providers.LegacyMicrosoftAccount.Enabled) {
		methods = append(methods, "Microsoft Account")
	}
	if providers.Twitter != nil && ptr.ToBool(providers.Twitter.Enabled) {
		methods = append(methods, "Twitter")
	}
	if providers.Apple != nil && ptr.ToBool(providers.Apple.Enabled) {
		methods = append(methods, "Apple")
	}
	if providers.AzureStaticWebApps != nil && ptr.ToBool(providers.AzureStaticWebApps.Enabled) {
		methods = append(methods, "Azure Static Web Apps")
	}
	for name, provider := range providers.CustomOpenIDConnectProviders {
		if provider != nil && ptr.ToBool(provider.Enabled) {
			methods = append(methods, "OpenID Connect: "+name)
		}
	}
	sort.Strings(methods)
	return methods
}

func functionAuthLevels(config any) []string {
	encoded, err := json.Marshal(config)
	if err != nil {
		return nil
	}
	var value any
	if json.Unmarshal(encoded, &value) != nil {
		return nil
	}
	var levels []string
	var visit func(any)
	visit = func(current any) {
		switch typed := current.(type) {
		case map[string]any:
			for key, child := range typed {
				if strings.EqualFold(key, "authLevel") {
					if level, ok := child.(string); ok {
						levels = append(levels, formatFunctionAuthLevel(level))
					}
				} else {
					visit(child)
				}
			}
		case []any:
			for _, child := range typed {
				visit(child)
			}
		}
	}
	visit(value)
	return uniqueStrings(levels)
}

func functionTrigger(config any, invokeURL string) string {
	encoded, err := json.Marshal(config)
	if err != nil {
		return "Unknown"
	}
	var value any
	if json.Unmarshal(encoded, &value) != nil {
		return "Unknown"
	}
	result := ""
	var visit func(any)
	visit = func(current any) {
		if result != "" {
			return
		}
		switch typed := current.(type) {
		case map[string]any:
			bindingType := mapStringValue(typed, "type")
			if strings.HasSuffix(strings.ToLower(bindingType), "trigger") {
				label := functionTriggerLabel(bindingType)
				detail := functionTriggerDetail(bindingType, typed, invokeURL)
				result = label
				if detail != "" {
					result += ": " + detail
				}
				return
			}
			for _, child := range typed {
				visit(child)
			}
		case []any:
			for _, child := range typed {
				visit(child)
			}
		}
	}
	visit(value)
	if result == "" {
		return "Unknown"
	}
	return result
}

func functionTriggerLabel(bindingType string) string {
	switch strings.ToLower(bindingType) {
	case "httptrigger":
		return "HTTP"
	case "timertrigger":
		return "Time Trigger"
	case "blobtrigger":
		return "Blob Trigger"
	case "queuetrigger":
		return "Queue Trigger"
	case "servicebustrigger":
		return "Service Bus Trigger"
	case "eventhubtrigger":
		return "Event Hub Trigger"
	case "eventgridtrigger":
		return "Event Grid Trigger"
	case "cosmosdbtrigger":
		return "Cosmos DB Trigger"
	case "kafkatrigger":
		return "Kafka Trigger"
	default:
		name := strings.TrimSuffix(bindingType, "Trigger")
		return name + " Trigger"
	}
}

func functionTriggerDetail(bindingType string, binding map[string]any, invokeURL string) string {
	switch strings.ToLower(bindingType) {
	case "httptrigger":
		return invokeURL
	case "timertrigger":
		return mapStringValue(binding, "schedule")
	case "blobtrigger":
		return mapStringValue(binding, "path")
	case "queuetrigger":
		return mapStringValue(binding, "queueName")
	case "servicebustrigger":
		return firstNonEmpty(mapStringValue(binding, "queueName"), mapStringValue(binding, "topicName"))
	case "eventhubtrigger":
		return mapStringValue(binding, "eventHubName")
	case "cosmosdbtrigger":
		database := mapStringValue(binding, "databaseName")
		container := firstNonEmpty(mapStringValue(binding, "containerName"), mapStringValue(binding, "collectionName"))
		return strings.Trim(strings.Join([]string{database, container}, "/"), "/")
	case "kafkatrigger":
		return firstNonEmpty(mapStringValue(binding, "topic"), mapStringValue(binding, "brokerList"))
	default:
		return ""
	}
}

func mapStringValue(values map[string]any, name string) string {
	for key, value := range values {
		if strings.EqualFold(key, name) {
			if text, ok := value.(string); ok {
				return text
			}
		}
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func formatFunctionTestDataLoot(subscriptionID, resourceGroup, appName, functionName, testData string) string {
	if testData == "" {
		return ""
	}
	return fmt.Sprintf("az functionapp function show --name %q --resource-group %q --function-name %q --subscription %q --query testData --output tsv\n%s\n\n", appName, resourceGroup, functionName, subscriptionID, testData)
}

func formatFunctionAuthLevel(level string) string {
	switch strings.ToLower(level) {
	case "anonymous":
		return "Anonymous"
	case "function":
		return "Function key"
	case "admin":
		return "Admin/master key"
	default:
		return level
	}
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	var result []string
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
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
	var config functionConfiguration
	settings, err := client.ListApplicationSettings(context.TODO(), resourceGroup, name)
	if err != nil {
		return config, err
	}
	config.AppSettings = settings.Properties
	connections, err := client.ListConnectionStrings(context.TODO(), resourceGroup, name)
	if err != nil {
		return config, err
	}
	config.ConnectionStrings = connections.Properties
	authSettings, err := client.GetAuthSettingsV2WithoutSecrets(context.TODO(), resourceGroup, name)
	if err != nil {
		return config, err
	}
	config.AuthSettings = authSettings
	return config, nil
}

func getFunctionsOriginal(subscriptionID, resourceGroup, appName string) ([]web.FunctionEnvelope, error) {
	client := internal.GetWebAppsClient(subscriptionID)
	page, err := client.ListFunctions(context.TODO(), resourceGroup, appName)
	if err != nil {
		return nil, err
	}
	var functions []web.FunctionEnvelope
	for page.NotDone() {
		functions = append(functions, page.Values()...)
		if err := page.NextWithContext(context.TODO()); err != nil {
			return nil, err
		}
	}
	return functions, nil
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

func writeFunctionOutput(outputDirectory, tenantDomain, directorySuffix, prefix string, rows [][]string, loot functionLoot, verbosity int, wrap bool) {
	o := internal.OutputClient{
		Verbosity:        verbosity,
		CallingModule:    globals.AZ_FUNC_MODULE_NAME,
		PrefixIdentifier: prefix,
		Table: internal.TableClient{
			Wrap:          wrap,
			DirectoryName: filepath.Join(outputDirectory, globals.CLOUDFOX_BASE_DIRECTORY, globals.AZ_DIR_BASE, tenantDomain, directorySuffix),
		},
	}
	o.Table.TableFiles = append(o.Table.TableFiles, internal.TableFile{Header: functionTableHeader(), Body: rows, Name: globals.AZ_FUNC_MODULE_NAME, TableCols: functionVisibleColumns()})
	o.Loot.DirectoryName = filepath.Join(o.Table.DirectoryName, "loot")
	if loot.Configuration != "" {
		o.Loot.LootFiles = append(o.Loot.LootFiles, internal.LootFile{Name: "function-app-configuration", Contents: loot.Configuration})
	}
	if loot.TestData != "" {
		o.Loot.LootFiles = append(o.Loot.LootFiles, internal.LootFile{Name: "function-test-data", Contents: loot.TestData})
	}
	if len(o.Loot.LootFiles) > 0 {
		o.WriteFullOutput(o.Table.TableFiles, o.Loot.LootFiles)
	} else {
		o.WriteFullOutput(o.Table.TableFiles, nil)
	}
	fmt.Println()
}
