package azure

import (
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/automation/mgmt/automation"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/subscriptions"
	"github.com/aws/smithy-go/ptr"
)

func TestGetAutomationDataCountsAndLoot(t *testing.T) {
	originalAccounts, originalAssets := getAutomationAccounts, getAutomationAssets
	t.Cleanup(func() { getAutomationAccounts, getAutomationAssets = originalAccounts, originalAssets })
	getAutomationAccounts = func(string) ([]automation.Account, error) {
		return []automation.Account{{Name: ptr.String("operations"), ID: ptr.String("/subscriptions/sub/resourceGroups/ops/providers/Microsoft.Automation/automationAccounts/operations")}}, nil
	}
	getAutomationAssets = func(_, resourceGroup, account string) (automationAssets, error) {
		if resourceGroup != "ops" || account != "operations" {
			t.Fatalf("unexpected automation target %s/%s", resourceGroup, account)
		}
		return automationAssets{Runbooks: []automation.Runbook{{Name: ptr.String("daily")}, {Name: ptr.String("weekly")}}, RunbookSources: map[string]string{"daily": "Write-Output 'daily'", "weekly": "print('weekly')"}, Credentials: []automation.Credential{{Name: ptr.String("service-account")}}, Webhooks: []automation.Webhook{{Name: ptr.String("deploy")}}}, nil
	}
	sub := subscriptions.Subscription{SubscriptionID: ptr.String("sub"), DisplayName: ptr.String("Production")}
	rows, loot, warnings, err := getAutomationData(sub)
	if err != nil || len(warnings) != 0 {
		t.Fatalf("unexpected errors: err=%v warnings=%v", err, warnings)
	}
	if len(rows) != 1 || rows[0][4] != "2" || rows[0][5] != "1" || rows[0][6] != "1" {
		t.Fatalf("unexpected automation rows: %+v", rows)
	}
	if !strings.Contains(loot.Runbooks, "Runbook: daily") || !strings.Contains(loot.Runbooks, "Write-Output 'daily'") {
		t.Errorf("runbook loot is incomplete: %s", loot.Runbooks)
	}
	for _, value := range []string{"az automation credential show", "service-account", `"name": "service-account"`} {
		if !strings.Contains(loot.Credentials, value) {
			t.Errorf("credential loot missing %q: %s", value, loot.Credentials)
		}
	}
	for _, value := range []string{"az automation webhook show", "deploy", `"name": "deploy"`} {
		if !strings.Contains(loot.Webhooks, value) {
			t.Errorf("webhook loot missing %q: %s", value, loot.Webhooks)
		}
	}
}
