package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/automation/mgmt/automation"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/subscriptions"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/smithy-go/ptr"
	"github.com/fatih/color"
	"github.com/kyokomi/emoji"
)

var (
	getAutomationAccounts = getAutomationAccountsOriginal
	getAutomationAssets   = getAutomationAssetsOriginal
)

type automationAssets struct {
	Runbooks    []automation.Runbook    `json:"runbooks"`
	Credentials []automation.Credential `json:"credentials"`
	Webhooks    []automation.Webhook    `json:"webhooks"`
}

func AzAutomationCommand(tenantID, subscription, outputDirectory, version string, verbosity int, wrap, merged bool) error {
	if tenantID != "" && subscription == "" && merged {
		tenant := populateTenant(tenantID)
		if ptr.ToString(tenant.ID) == "" {
			return fmt.Errorf("could not find Azure tenant %q", tenantID)
		}
		subs := GetSubscriptionsPerTenantID(ptr.ToString(tenant.ID))
		var rows [][]string
		var loot strings.Builder
		for _, sub := range subs {
			subRows, subLoot, warnings, err := getAutomationData(sub)
			if err != nil {
				return err
			}
			rows = append(rows, subRows...)
			loot.WriteString(subLoot)
			for _, warning := range warnings {
				fmt.Printf("[%s] %s\n", color.CyanString(globals.AZ_AUTOMATION_MODULE_NAME), warning)
			}
		}
		if len(subs) > 0 {
			writeScopedAzureOutput(outputDirectory, subs[0], globals.AZ_AUTOMATION_MODULE_NAME, []string{"Automation Account", "Subscription Name", "Subscription ID", "Resource Group", "Runbooks", "Credentials", "Webhooks"}, rows, "automation-assets", loot.String(), verbosity, wrap, true)
		}
		return nil
	}
	return runAzureScopedModule(tenantID, subscription, merged, func(sub subscriptions.Subscription) error {
		fmt.Printf("[%s][%s] Enumerating Automation Accounts for subscription %s (%s)\n", color.CyanString(emoji.Sprintf(":fox:cloudfox %s :fox:", version)), color.CyanString(globals.AZ_AUTOMATION_MODULE_NAME), ptr.ToString(sub.DisplayName), ptr.ToString(sub.SubscriptionID))
		rows, loot, warnings, err := getAutomationData(sub)
		if err != nil {
			return err
		}
		for _, warning := range warnings {
			fmt.Printf("[%s] %s\n", color.CyanString(globals.AZ_AUTOMATION_MODULE_NAME), warning)
		}
		writeScopedAzureOutput(outputDirectory, sub, globals.AZ_AUTOMATION_MODULE_NAME, []string{"Automation Account", "Subscription Name", "Subscription ID", "Resource Group", "Runbooks", "Credentials", "Webhooks"}, rows, "automation-assets", loot, verbosity, wrap, false)
		return nil
	})
}

func getAutomationData(subscription subscriptions.Subscription) ([][]string, string, []error, error) {
	subscriptionID := ptr.ToString(subscription.SubscriptionID)
	accounts, err := getAutomationAccounts(subscriptionID)
	if err != nil {
		return nil, "", nil, fmt.Errorf("could not enumerate Automation Accounts for subscription %s: %w", subscriptionID, err)
	}
	var rows [][]string
	var loot strings.Builder
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
			encoded, marshalErr := json.MarshalIndent(automationAssetsForLoot(assets), "", "  ")
			if marshalErr == nil {
				fmt.Fprintf(&loot, "===============================================================\nAutomation Account: %s\nResource Group: %s\n%s\n\n", name, rg, encoded)
			}
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i][0] < rows[j][0] })
	return rows, loot.String(), warnings, nil
}

func automationAssetsForLoot(assets automationAssets) map[string]any {
	runbooks := make([]map[string]any, 0, len(assets.Runbooks))
	for _, runbook := range assets.Runbooks {
		runbooks = append(runbooks, map[string]any{"name": ptr.ToString(runbook.Name), "properties": runbook.RunbookProperties})
	}
	credentials := make([]map[string]any, 0, len(assets.Credentials))
	for _, credential := range assets.Credentials {
		credentials = append(credentials, map[string]any{"name": ptr.ToString(credential.Name), "properties": credential.CredentialProperties})
	}
	webhooks := make([]map[string]any, 0, len(assets.Webhooks))
	for _, webhook := range assets.Webhooks {
		webhooks = append(webhooks, map[string]any{"name": ptr.ToString(webhook.Name), "properties": webhook.WebhookProperties})
	}
	return map[string]any{"runbooks": runbooks, "credentials": credentials, "webhooks": webhooks}
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
