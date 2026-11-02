package azure

import (
	"errors"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/subscriptions"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/web/mgmt/web"
	"github.com/aws/smithy-go/ptr"
)

func TestGetFunctionDataAndConfigurationLoot(t *testing.T) {
	originalApps, originalConfig, originalFunctions := getFunctionApps, getFunctionConfiguration, getFunctions
	t.Cleanup(func() {
		getFunctionApps, getFunctionConfiguration, getFunctions = originalApps, originalConfig, originalFunctions
	})
	getFunctionApps = func(string) ([]web.Site, error) {
		return []web.Site{
			{Name: ptr.String("process-orders"), Kind: ptr.String("functionapp,linux"), ID: ptr.String("/subscriptions/sub/resourceGroups/apps/providers/Microsoft.Web/sites/process-orders"), SiteProperties: &web.SiteProperties{DefaultHostName: ptr.String("process-orders.azurewebsites.net")}},
			{Name: ptr.String("ordinary-web-app"), Kind: ptr.String("app")},
		}, nil
	}
	getFunctionConfiguration = func(_, resourceGroup, name string) (functionConfiguration, error) {
		if resourceGroup != "apps" || name != "process-orders" {
			t.Fatalf("unexpected configuration target %s/%s", resourceGroup, name)
		}
		return functionConfiguration{AppSettings: map[string]*string{"API_KEY": ptr.String("secret")}, ConnectionStrings: map[string]*web.ConnStringValueTypePair{"Database": {Value: ptr.String("Server=db")}}, AuthSettings: web.SiteAuthSettingsV2{SiteAuthSettingsV2Properties: &web.SiteAuthSettingsV2Properties{Platform: &web.AuthPlatform{Enabled: ptr.Bool(true)}, IdentityProviders: &web.IdentityProviders{AzureActiveDirectory: &web.AzureActiveDirectory{Enabled: ptr.Bool(true)}}}}}, nil
	}
	getFunctions = func(_, _, _ string) ([]web.FunctionEnvelope, error) {
		return []web.FunctionEnvelope{{Name: ptr.String("process-orders/HttpTrigger"), FunctionEnvelopeProperties: &web.FunctionEnvelopeProperties{InvokeURLTemplate: ptr.String("https://process-orders.azurewebsites.net/api/orders"), Config: map[string]any{"bindings": []any{map[string]any{"type": "httpTrigger", "authLevel": "function"}}}, IsDisabled: ptr.Bool(false), TestData: ptr.String(`{"orderId":42}`)}}}, nil
	}
	sub := subscriptions.Subscription{SubscriptionID: ptr.String("sub"), DisplayName: ptr.String("Production")}
	rows, loot, warnings, err := getFunctionData(sub)
	if err != nil || len(warnings) != 0 {
		t.Fatalf("unexpected errors: err=%v warnings=%v", err, warnings)
	}
	if len(rows) != 1 || rows[0][0] != "process-orders" || rows[0][1] != "HttpTrigger" || rows[0][2] != "HTTP: https://process-orders.azurewebsites.net/api/orders" || !strings.Contains(rows[0][3], "Function key") || !strings.Contains(rows[0][3], "Entra ID") || rows[0][4] != "Enabled" || rows[0][5] != "Production" || rows[0][6] != "sub" {
		t.Fatalf("unexpected function rows: %+v", rows)
	}
	for _, value := range []string{"API_KEY=secret", "Database=Server=db", "Entra ID"} {
		if !strings.Contains(loot.Configuration, value) {
			t.Errorf("loot missing %q: %s", value, loot.Configuration)
		}
	}
	for _, value := range []string{"az functionapp function show", `--function-name "HttpTrigger"`, `{"orderId":42}`} {
		if !strings.Contains(loot.TestData, value) {
			t.Errorf("test-data loot missing %q: %s", value, loot.TestData)
		}
	}
}

func TestGetFunctionDataFallsBackWhenEnrichmentFails(t *testing.T) {
	originalApps, originalConfig, originalFunctions := getFunctionApps, getFunctionConfiguration, getFunctions
	t.Cleanup(func() {
		getFunctionApps, getFunctionConfiguration, getFunctions = originalApps, originalConfig, originalFunctions
	})
	getFunctionApps = func(string) ([]web.Site, error) {
		return []web.Site{{Name: ptr.String("visible-app"), Kind: ptr.String("functionapp"), ID: ptr.String("/subscriptions/sub/resourceGroups/apps/providers/Microsoft.Web/sites/visible-app"), SiteProperties: &web.SiteProperties{DefaultHostName: ptr.String("visible.azurewebsites.net")}}}, nil
	}
	getFunctionConfiguration = func(_, _, _ string) (functionConfiguration, error) {
		return functionConfiguration{}, errors.New("forbidden")
	}
	getFunctions = func(_, _, _ string) ([]web.FunctionEnvelope, error) { return nil, nil }

	rows, _, warnings, err := getFunctionData(subscriptions.Subscription{SubscriptionID: ptr.String("sub"), DisplayName: ptr.String("Production")})
	if err != nil || len(rows) != 1 || rows[0][0] != "visible-app" || rows[0][2] != "App URL: https://visible.azurewebsites.net" || rows[0][4] != "Unknown" || len(warnings) != 1 {
		t.Fatalf("expected visible fallback row and warning, got rows=%+v warnings=%v err=%v", rows, warnings, err)
	}
}

func TestGetFunctionDataUsesCronScheduleAsTrigger(t *testing.T) {
	originalApps, originalConfig, originalFunctions := getFunctionApps, getFunctionConfiguration, getFunctions
	t.Cleanup(func() {
		getFunctionApps, getFunctionConfiguration, getFunctions = originalApps, originalConfig, originalFunctions
	})
	getFunctionApps = func(string) ([]web.Site, error) {
		return []web.Site{{Name: ptr.String("scheduled-app"), Kind: ptr.String("functionapp"), ID: ptr.String("/subscriptions/sub/resourceGroups/apps/providers/Microsoft.Web/sites/scheduled-app")}}, nil
	}
	getFunctionConfiguration = func(_, _, _ string) (functionConfiguration, error) { return functionConfiguration{}, nil }
	getFunctions = func(_, _, _ string) ([]web.FunctionEnvelope, error) {
		return []web.FunctionEnvelope{{
			Name: ptr.String("scheduled-app/Cleanup"),
			FunctionEnvelopeProperties: &web.FunctionEnvelopeProperties{
				Config:     map[string]any{"bindings": []any{map[string]any{"type": "timerTrigger", "schedule": "0 */5 * * * *"}}},
				IsDisabled: ptr.Bool(true),
			},
		}}, nil
	}
	rows, _, _, err := getFunctionData(subscriptions.Subscription{SubscriptionID: ptr.String("sub"), DisplayName: ptr.String("Production")})
	if err != nil || len(rows) != 1 || rows[0][2] != "Time Trigger: 0 */5 * * * *" || rows[0][4] != "Disabled" {
		t.Fatalf("expected CRON schedule trigger, got rows=%+v err=%v", rows, err)
	}
}
