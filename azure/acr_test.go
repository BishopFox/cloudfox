package azure

import (
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/subscriptions"
	containerregistry "github.com/Azure/azure-sdk-for-go/services/preview/containerregistry/mgmt/2022-02-01-preview/containerregistry"
	"github.com/aws/smithy-go/ptr"
)

func TestGetACRRelevantData(t *testing.T) {
	registries := []containerregistry.Registry{
		{
			Name: ptr.String("packnet"),
			RegistryProperties: &containerregistry.RegistryProperties{
				LoginServer:          ptr.String("packnet.azurecr.io"),
				AnonymousPullEnabled: ptr.Bool(true),
			},
		},
	}
	subscription := subscriptions.Subscription{
		SubscriptionID: ptr.String("8bb4e6f5-be51-4eab-bd68-ecf6fd08338f"),
		DisplayName:    ptr.String("Production"),
	}

	body, loot, err := getACRRelevantData(subscription, registries)
	if err != nil {
		t.Fatalf("getACRRelevantData returned an error: %v", err)
	}
	if len(body) != 1 || body[0][0] != "packnet" || body[0][3] != "packnet.azurecr.io" || body[0][4] != "true" {
		t.Fatalf("unexpected ACR table body: %+v", body)
	}
	for _, expected := range []string{
		"az acr login -n packnet --subscription 8bb4e6f5-be51-4eab-bd68-ecf6fd08338f --expose-token",
		"docker login packnet.azurecr.io --username " + acrDockerTokenUsername + " --password-stdin",
	} {
		if !strings.Contains(loot, expected) {
			t.Errorf("loot does not contain %q:\n%s", expected, loot)
		}
	}
}
