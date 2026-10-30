package azure

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/subscriptions"
	containerregistry "github.com/Azure/azure-sdk-for-go/services/preview/containerregistry/mgmt/2022-02-01-preview/containerregistry"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/smithy-go/ptr"
)

const acrDockerTokenUsername = "00000000-0000-0000-0000-000000000000"

var getContainerRegistries = getContainerRegistriesOriginal

func AzACRCommand(AzTenantID, AzSubscription, AzOutputDirectory, Version string, AzVerbosity int, AzWrapTable bool, AzMergedTable bool) error {
	if AzTenantID != "" && AzSubscription == "" {
		tenantInfo := populateTenant(AzTenantID)
		if ptr.ToString(tenantInfo.ID) == "" {
			return fmt.Errorf("could not find Azure tenant %q", AzTenantID)
		}
		if !AzMergedTable {
			for _, subscription := range GetSubscriptionsPerTenantID(ptr.ToString(tenantInfo.ID)) {
				if err := runACRCommandForSingleSubscription(ptr.ToString(subscription.SubscriptionID), AzOutputDirectory, AzVerbosity, AzWrapTable, Version); err != nil {
					return err
				}
			}
			return nil
		}

		azureLogger.InfoM(fmt.Sprintf("Enumerating container registries for tenant %s (%s)", ptr.ToString(tenantInfo.DefaultDomain), ptr.ToString(tenantInfo.ID)), globals.AZ_ACR_MODULE_NAME)

		var body [][]string
		var loot strings.Builder
		for _, subscription := range GetSubscriptionsPerTenantID(ptr.ToString(tenantInfo.ID)) {
			rows, commands, err := getACRData(subscription)
			if err != nil {
				return err
			}
			body = append(body, rows...)
			loot.WriteString(commands)
		}
		writeACROutput(AzOutputDirectory, ptr.ToString(tenantInfo.DefaultDomain), "1-tenant-level", ptr.ToString(tenantInfo.DefaultDomain), body, loot.String(), AzVerbosity, AzWrapTable)
		return nil
	}

	if AzTenantID == "" && AzSubscription != "" {
		return runACRCommandForSingleSubscription(AzSubscription, AzOutputDirectory, AzVerbosity, AzWrapTable, Version)
	}

	return fmt.Errorf("please specify either --tenant or --subscription")
}

func runACRCommandForSingleSubscription(AzSubscription, AzOutputDirectory string, AzVerbosity int, AzWrapTable bool, Version string) error {
	subscriptionInfo := PopulateSubsriptionType(AzSubscription)
	if subscriptionInfo.ID == "" {
		return fmt.Errorf("could not find Azure subscription %q", AzSubscription)
	}
	tenantID := ptr.ToString(GetTenantIDPerSubscription(subscriptionInfo.ID))
	tenantInfo := populateTenant(tenantID)

	azureLogger.InfoM(fmt.Sprintf("Enumerating container registries for subscription %s (%s)", subscriptionInfo.Name, subscriptionInfo.ID), globals.AZ_ACR_MODULE_NAME)

	var selectedSubscription subscriptions.Subscription
	for _, subscription := range GetSubscriptions() {
		if ptr.ToString(subscription.SubscriptionID) == subscriptionInfo.ID {
			selectedSubscription = subscription
			break
		}
	}
	rows, loot, err := getACRData(selectedSubscription)
	if err != nil {
		return err
	}
	writeACROutput(AzOutputDirectory, ptr.ToString(tenantInfo.DefaultDomain), subscriptionInfo.Name, subscriptionInfo.Name, rows, loot, AzVerbosity, AzWrapTable)
	return nil
}

func getACRData(subscription subscriptions.Subscription) ([][]string, string, error) {
	subscriptionID := ptr.ToString(subscription.SubscriptionID)
	registries, err := getContainerRegistries(subscriptionID)
	if err != nil {
		return nil, "", fmt.Errorf("could not enumerate container registries for subscription %s: %w", subscriptionID, err)
	}
	return getACRRelevantData(subscription, registries)
}

func getACRRelevantData(subscription subscriptions.Subscription, registries []containerregistry.Registry) ([][]string, string, error) {
	var body [][]string
	var loot strings.Builder
	subscriptionID := ptr.ToString(subscription.SubscriptionID)
	subscriptionName := ptr.ToString(subscription.DisplayName)

	for _, registry := range registries {
		name := ptr.ToString(registry.Name)
		loginServer := ""
		anonymousPulls := false
		if registry.RegistryProperties != nil {
			loginServer = ptr.ToString(registry.LoginServer)
			anonymousPulls = ptr.ToBool(registry.AnonymousPullEnabled)
		}
		body = append(body, []string{name, subscriptionName, subscriptionID, loginServer, fmt.Sprintf("%t", anonymousPulls)})
		loot.WriteString(acrLootCommands(name, subscriptionID, loginServer))
	}

	sort.Slice(body, func(i, j int) bool {
		if body[i][1] == body[j][1] {
			return body[i][0] < body[j][0]
		}
		return body[i][1] < body[j][1]
	})
	return body, loot.String(), nil
}

func acrLootCommands(registryName, subscriptionID, loginServer string) string {
	if registryName == "" || subscriptionID == "" || loginServer == "" {
		return ""
	}
	return fmt.Sprintf("# %s (%s)\nACR_TOKEN=$(az acr login -n %s --subscription %s --expose-token --output tsv --query accessToken)\nprintf '%%s' \"$ACR_TOKEN\" | docker login %s --username %s --password-stdin\n\n",
		registryName, loginServer, registryName, subscriptionID, loginServer, acrDockerTokenUsername)
}

func writeACROutput(outputDirectory, tenantDomain, directorySuffix, prefix string, body [][]string, loot string, verbosity int, wrap bool) {
	o := internal.OutputClient{
		Verbosity:        verbosity,
		CallingModule:    globals.AZ_ACR_MODULE_NAME,
		PrefixIdentifier: prefix,
		Table: internal.TableClient{
			Wrap:          wrap,
			DirectoryName: filepath.Join(outputDirectory, globals.CLOUDFOX_BASE_DIRECTORY, globals.AZ_DIR_BASE, tenantDomain, directorySuffix),
		},
	}
	o.Table.TableFiles = append(o.Table.TableFiles, internal.TableFile{
		Header: []string{"Registry Name", "Subscription Name", "Subscription ID", "Login Server", "Anonymous Pulls"},
		Body:   body,
		Name:   globals.AZ_ACR_MODULE_NAME,
	})
	if loot != "" {
		o.Loot.DirectoryName = filepath.Join(outputDirectory, globals.CLOUDFOX_BASE_DIRECTORY, globals.AZ_DIR_BASE, tenantDomain, directorySuffix, "loot")
		o.Loot.LootFiles = append(o.Loot.LootFiles, internal.LootFile{Contents: loot, Name: "acr-login-commands"})
		o.WriteFullOutput(o.Table.TableFiles, o.Loot.LootFiles)
	} else {
		o.WriteFullOutput(o.Table.TableFiles, nil)
	}
	fmt.Println()
}

func getContainerRegistriesOriginal(subscriptionID string) ([]containerregistry.Registry, error) {
	client := internal.GetContainerRegistriesClient(subscriptionID)
	page, err := client.List(context.TODO())
	if err != nil {
		return nil, err
	}
	var registries []containerregistry.Registry
	for page.NotDone() {
		registries = append(registries, page.Values()...)
		if err := page.NextWithContext(context.TODO()); err != nil {
			return nil, err
		}
	}
	return registries, nil
}
