package azure

import (
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/subscriptions"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/web/mgmt/web"
	"github.com/aws/smithy-go/ptr"
)

func TestGetFunctionDataAndConfigurationLoot(t *testing.T) {
	originalApps, originalConfig := getFunctionApps, getFunctionConfiguration
	t.Cleanup(func() { getFunctionApps, getFunctionConfiguration = originalApps, originalConfig })
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
		return functionConfiguration{AppSettings: map[string]*string{"API_KEY": ptr.String("secret")}, ConnectionStrings: map[string]*web.ConnStringValueTypePair{"Database": {Value: ptr.String("Server=db")}}}, nil
	}
	sub := subscriptions.Subscription{SubscriptionID: ptr.String("sub"), DisplayName: ptr.String("Production")}
	rows, loot, warnings, err := getFunctionData(sub)
	if err != nil || len(warnings) != 0 {
		t.Fatalf("unexpected errors: err=%v warnings=%v", err, warnings)
	}
	if len(rows) != 1 || rows[0][3] != "https://process-orders.azurewebsites.net" {
		t.Fatalf("unexpected function rows: %+v", rows)
	}
	for _, value := range []string{"API_KEY=secret", "Database=Server=db"} {
		if !strings.Contains(loot, value) {
			t.Errorf("loot missing %q: %s", value, loot)
		}
	}
}
