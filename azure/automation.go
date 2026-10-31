package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/automation/mgmt/automation"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/subscriptions"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/smithy-go/ptr"
)

var (
	getAutomationAccounts = getAutomationAccountsOriginal
	getAutomationAssets   = getAutomationAssetsOriginal
)

type automationAssets struct {
	Runbooks       []automation.Runbook    `json:"runbooks"`
	RunbookSources map[string]string       `json:"-"`
	Credentials    []automation.Credential `json:"credentials"`
	Webhooks       []automation.Webhook    `json:"webhooks"`
}

type automationLoot struct {
	Runbooks    string
	Credentials string
	Webhooks    string
}

func AzAutomationCommand(tenantID, subscription, outputDirectory, version string, verbosity int, wrap, merged bool) error {
	if tenantID != "" && subscription == "" {
		tenant := populateTenant(tenantID)
		if ptr.ToString(tenant.ID) == "" {
			return fmt.Errorf("could not find Azure tenant %q", tenantID)
		}
		azureLogger.InfoM(fmt.Sprintf("Enumerating Automation Accounts for tenant %s (%s)", ptr.ToString(tenant.DefaultDomain), ptr.ToString(tenant.ID)), globals.AZ_AUTOMATION_MODULE_NAME)
		subs := GetSubscriptionsPerTenantID(ptr.ToString(tenant.ID))
		if !merged {
			for _, sub := range subs {
				if err := runAutomationForSubscription(sub, outputDirectory, verbosity, wrap); err != nil {
					return err
				}
			}
			return nil
		}
		var rows [][]string
		var loot automationLoot
		for _, sub := range subs {
			subRows, subLoot, warnings, err := getAutomationData(sub)
			if err != nil {
				return err
			}
			rows = append(rows, subRows...)
			loot.Runbooks += subLoot.Runbooks
			loot.Credentials += subLoot.Credentials
			loot.Webhooks += subLoot.Webhooks
			for _, warning := range warnings {
				azureLogger.WarnM(warning.Error(), globals.AZ_AUTOMATION_MODULE_NAME)
			}
		}
		if len(subs) > 0 {
			writeAutomationOutput(outputDirectory, ptr.ToString(tenant.DefaultDomain), "1-tenant-level", ptr.ToString(tenant.DefaultDomain), rows, loot, verbosity, wrap)
		}
		return nil
	}
	if tenantID == "" && subscription != "" {
		id := ptr.ToString(GetSubscriptionID(subscription))
		for _, sub := range GetSubscriptions() {
			if ptr.ToString(sub.SubscriptionID) == id {
				return runAutomationForSubscription(sub, outputDirectory, verbosity, wrap)
			}
		}
		return fmt.Errorf("could not find Azure subscription %q", subscription)
	}
	return fmt.Errorf("please specify either --tenant or --subscription")
}

func runAutomationForSubscription(sub subscriptions.Subscription, outputDirectory string, verbosity int, wrap bool) error {
	azureLogger.InfoM(fmt.Sprintf("Enumerating Automation Accounts for subscription %s (%s)", ptr.ToString(sub.DisplayName), ptr.ToString(sub.SubscriptionID)), globals.AZ_AUTOMATION_MODULE_NAME)
	rows, loot, warnings, err := getAutomationData(sub)
	if err != nil {
		return err
	}
	for _, warning := range warnings {
		azureLogger.WarnM(warning.Error(), globals.AZ_AUTOMATION_MODULE_NAME)
	}
	tenant := populateTenant(ptr.ToString(sub.TenantID))
	writeAutomationOutput(outputDirectory, ptr.ToString(tenant.DefaultDomain), ptr.ToString(sub.DisplayName), ptr.ToString(sub.DisplayName), rows, loot, verbosity, wrap)
	return nil
}

func getAutomationData(subscription subscriptions.Subscription) ([][]string, automationLoot, []error, error) {
	subscriptionID := ptr.ToString(subscription.SubscriptionID)
	accounts, err := getAutomationAccounts(subscriptionID)
	if err != nil {
		return nil, automationLoot{}, nil, fmt.Errorf("could not enumerate Automation Accounts for subscription %s: %w", subscriptionID, err)
	}
	var rows [][]string
	var loot automationLoot
	var warnings []error
	for _, account := range accounts {
		name := ptr.ToString(account.Name)
		rg := resourceGroupFromID(ptr.ToString(account.ID))
		assets, err := getAutomationAssets(subscriptionID, rg, name)
		if err != nil {
			warnings = append(warnings, fmt.Errorf("could not enumerate assets for Automation Account %s: %w", name, err))
			continue
		}
		rows = append(rows, []string{name, ptr.ToString(subscription.DisplayName), subscriptionID, rg, fmt.Sprintf("%d", len(assets.Runbooks)), fmt.Sprintf("%d", len(assets.Credentials)), fmt.Sprintf("%d", len(assets.Webhooks))})
		if len(assets.Runbooks)+len(assets.Credentials)+len(assets.Webhooks) > 0 {
			accountLoot := formatAutomationLoot(subscriptionID, name, rg, assets)
			loot.Runbooks += accountLoot.Runbooks
			loot.Credentials += accountLoot.Credentials
			loot.Webhooks += accountLoot.Webhooks
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i][0] < rows[j][0] })
	return rows, loot, warnings, nil
}

func formatAutomationLoot(subscriptionID, accountName, resourceGroup string, assets automationAssets) automationLoot {
	var loot automationLoot
	var runbooks, credentials, webhooks strings.Builder
	for _, runbook := range assets.Runbooks {
		name := ptr.ToString(runbook.Name)
		fmt.Fprintf(&runbooks, "===============================================================\nAutomation Account: %s\nResource Group: %s\nRunbook: %s\n\n%s\n\n", accountName, resourceGroup, name, assets.RunbookSources[name])
	}
	for _, credential := range assets.Credentials {
		name := ptr.ToString(credential.Name)
		value, _ := json.MarshalIndent(map[string]any{"name": name, "properties": credential.CredentialProperties}, "", "  ")
		fmt.Fprintf(&credentials, "az automation credential show --automation-account-name %q --resource-group %q --name %q --subscription %q\n%s\n\n", accountName, resourceGroup, name, subscriptionID, value)
	}
	for _, webhook := range assets.Webhooks {
		name := ptr.ToString(webhook.Name)
		value, _ := json.MarshalIndent(map[string]any{"name": name, "properties": webhook.WebhookProperties}, "", "  ")
		fmt.Fprintf(&webhooks, "az automation webhook show --automation-account-name %q --resource-group %q --name %q --subscription %q\n%s\n\n", accountName, resourceGroup, name, subscriptionID, value)
	}
	loot.Runbooks = runbooks.String()
	loot.Credentials = credentials.String()
	loot.Webhooks = webhooks.String()
	return loot
}

func writeAutomationOutput(outputDirectory, tenantDomain, directorySuffix, prefix string, rows [][]string, loot automationLoot, verbosity int, wrap bool) {
	o := internal.OutputClient{
		Verbosity:        verbosity,
		CallingModule:    globals.AZ_AUTOMATION_MODULE_NAME,
		PrefixIdentifier: prefix,
		Table: internal.TableClient{
			Wrap:          wrap,
			DirectoryName: filepath.Join(outputDirectory, globals.CLOUDFOX_BASE_DIRECTORY, globals.AZ_DIR_BASE, tenantDomain, directorySuffix),
		},
	}
	o.Table.TableFiles = append(o.Table.TableFiles, internal.TableFile{
		Header: []string{"Automation Account", "Subscription Name", "Subscription ID", "Resource Group", "Runbooks", "Credentials", "Webhooks"},
		Body:   rows,
		Name:   globals.AZ_AUTOMATION_MODULE_NAME,
	})
	o.Loot.DirectoryName = filepath.Join(o.Table.DirectoryName, "loot")
	if loot.Runbooks != "" {
		o.Loot.LootFiles = append(o.Loot.LootFiles, internal.LootFile{Name: "automation-runbooks", Contents: loot.Runbooks})
	}
	if loot.Credentials != "" {
		o.Loot.LootFiles = append(o.Loot.LootFiles, internal.LootFile{Name: "automation-credentials", Contents: loot.Credentials})
	}
	if loot.Webhooks != "" {
		o.Loot.LootFiles = append(o.Loot.LootFiles, internal.LootFile{Name: "automation-webhooks", Contents: loot.Webhooks})
	}
	if len(o.Loot.LootFiles) > 0 {
		o.WriteFullOutput(o.Table.TableFiles, o.Loot.LootFiles)
	} else {
		o.WriteFullOutput(o.Table.TableFiles, nil)
	}
	fmt.Println()
}

func getAutomationAccountsOriginal(subscriptionID string) ([]automation.Account, error) {
	accountsClient, _, _, _ := internal.GetAutomationClients(subscriptionID)
	page, err := accountsClient.List(context.TODO())
	if err != nil {
		return nil, err
	}
	var accounts []automation.Account
	for page.NotDone() {
		accounts = append(accounts, page.Values()...)
		if err := page.NextWithContext(context.TODO()); err != nil {
			return nil, err
		}
	}
	return accounts, nil
}

func getAutomationAssetsOriginal(subscriptionID, resourceGroup, accountName string) (automationAssets, error) {
	_, runbooksClient, credentialsClient, webhooksClient := internal.GetAutomationClients(subscriptionID)
	var assets automationAssets
	runbooks, err := runbooksClient.ListByAutomationAccount(context.TODO(), resourceGroup, accountName)
	if err != nil {
		return assets, err
	}
	for runbooks.NotDone() {
		assets.Runbooks = append(assets.Runbooks, runbooks.Values()...)
		if err := runbooks.NextWithContext(context.TODO()); err != nil {
			return assets, err
		}
	}
	assets.RunbookSources = make(map[string]string, len(assets.Runbooks))
	for _, runbook := range assets.Runbooks {
		name := ptr.ToString(runbook.Name)
		content, contentErr := runbooksClient.GetContent(context.TODO(), resourceGroup, accountName, name)
		if contentErr != nil {
			assets.RunbookSources[name] = fmt.Sprintf("[source unavailable: %s]", contentErr)
			continue
		}
		assets.RunbookSources[name] = ptr.ToString(content.Value)
	}
	credentials, err := credentialsClient.ListByAutomationAccount(context.TODO(), resourceGroup, accountName)
	if err != nil {
		return assets, err
	}
	for credentials.NotDone() {
		assets.Credentials = append(assets.Credentials, credentials.Values()...)
		if err := credentials.NextWithContext(context.TODO()); err != nil {
			return assets, err
		}
	}
	webhooks, err := webhooksClient.ListByAutomationAccount(context.TODO(), resourceGroup, accountName, "")
	if err != nil {
		return assets, err
	}
	for webhooks.NotDone() {
		assets.Webhooks = append(assets.Webhooks, webhooks.Values()...)
		if err := webhooks.NextWithContext(context.TODO()); err != nil {
			return assets, err
		}
	}
	return assets, nil
}
