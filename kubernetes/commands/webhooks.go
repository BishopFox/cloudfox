package commands

import (
	"context"
	"fmt"
	"strings"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/spf13/cobra"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

var WebhooksCmd = &cobra.Command{
	Use:     "webhooks",
	Aliases: []string{"wh"},
	Short:   "List all Mutating, Validating, and CRD conversion webhooks",
	Long: `
List all cluster webhook configurations (Mutating, Validating, CRD conversion):
  cloudfox kubernetes webhooks`,

	Run: ListWebhooks,
}

type WebhooksOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t WebhooksOutput) TableFiles() []internal.TableFile {
	return t.Table
}

func (t WebhooksOutput) LootFiles() []internal.LootFile {
	return t.Loot
}

func ListWebhooks(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	logger := internal.NewLogger()

	// Extract global flags
	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating webhooks for %s", globals.ClusterName), globals.K8S_WEBHOOKS_MODULE_NAME)

	headers := []string{
		"Type", "Name", "Namespace", "Service", "Path", "CABundle (set?)", "Rules",
	}

	var outputRows [][]string
	var lootEnum []string

	lootEnum = append(lootEnum, `#####################################
##### Enumerate Webhook Information
#####################################`)
	if globals.KubeContext != "" {
		lootEnum = append(lootEnum, fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext))
	}

	// Create dynamic client once
	restCfg, err := config.GetRESTConfig()
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error getting REST config: %v", err), globals.K8S_WEBHOOKS_MODULE_NAME)
		return
	}
	dynClient, err := dynamic.NewForConfig(restCfg)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error creating dynamic client: %v", err), globals.K8S_WEBHOOKS_MODULE_NAME)
		return
	}

	// Helper to process webhook configurations dynamically
	processWebhooks := func(gvr schema.GroupVersionResource, whType string) {
		list, err := dynClient.Resource(gvr).List(ctx, metav1.ListOptions{})
		if err != nil {
			logger.ErrorM(fmt.Sprintf("Error listing %s: %v", whType, err), globals.K8S_WEBHOOKS_MODULE_NAME)
			return
		}

		for _, item := range list.Items {
			webhooks, found, _ := unstructured.NestedSlice(item.Object, "webhooks")
			if !found {
				continue
			}

			cfgName, _, _ := unstructured.NestedString(item.Object, "metadata", "name")

			for _, whObj := range webhooks {
				whMap := whObj.(map[string]interface{})

				ns := "<N/A>"
				svc := "<external URL>"
				pathStr := "<none>"
				caBundle := "false"

				// Extract clientConfig
				if clientMap, ok := whMap["clientConfig"].(map[string]interface{}); ok {
					if svcMap, ok := clientMap["service"].(map[string]interface{}); ok {
						if n, ok := svcMap["namespace"].(string); ok {
							ns = n
						}
						if s, ok := svcMap["name"].(string); ok {
							svc = s
						}
						if p, ok := svcMap["path"].(string); ok && p != "" {
							pathStr = p
						}
					}
					if u, ok := clientMap["url"].(string); ok && u != "" {
						pathStr = u
					}
					if cb, ok := clientMap["caBundle"].(string); ok && cb != "" {
						caBundle = "true"
					}
				}

				// Extract rules
				rulesSlice, found, _ := unstructured.NestedSlice(whMap, "rules")
				rulesStr := "<none>"
				if found && len(rulesSlice) > 0 {
					var ruleParts []string
					for _, r := range rulesSlice {
						ruleMap := r.(map[string]interface{})
						ops, _, _ := unstructured.NestedStringSlice(ruleMap, "operations")
						resources, _, _ := unstructured.NestedStringSlice(ruleMap, "resources")
						ruleParts = append(ruleParts, fmt.Sprintf("%v %v", ops, resources))
					}
					rulesStr = strings.Join(ruleParts, "; ")
				}

				outputRows = append(outputRows, []string{
					whType, cfgName, ns, svc, pathStr, caBundle, rulesStr,
				})

				lootEnum = append(lootEnum,
					fmt.Sprintf("kubectl get %s %s -o json | jq '.webhooks[] | {name: .name, clientConfig: .clientConfig, rules: .rules}'", strings.ToLower(whType), cfgName),
				)
			}
		}
	}

	// Mutating webhooks
	mutGVR := schema.GroupVersionResource{
		Group:    "admissionregistration.k8s.io",
		Version:  "v1",
		Resource: "mutatingwebhookconfigurations",
	}
	processWebhooks(mutGVR, "Mutating")

	// Validating webhooks
	validGVR := schema.GroupVersionResource{
		Group:    "admissionregistration.k8s.io",
		Version:  "v1",
		Resource: "validatingwebhookconfigurations",
	}
	processWebhooks(validGVR, "Validating")

	// CRD conversion webhooks
	crdGVR := schema.GroupVersionResource{
		Group:    "apiextensions.k8s.io",
		Version:  "v1",
		Resource: "customresourcedefinitions",
	}

	crdList, err := dynClient.Resource(crdGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing CRDs dynamically: %v", err), globals.K8S_WEBHOOKS_MODULE_NAME)
	} else {
		for _, crd := range crdList.Items {
			conversion, found, _ := unstructured.NestedMap(crd.Object, "spec", "conversion")
			if !found {
				continue
			}

			webhookCC, hasWebhook, _ := unstructured.NestedMap(conversion, "webhook", "clientConfig")
			if !hasWebhook {
				continue
			}

			ns := "<N/A>"
			svc := "<external URL>"
			urlStr := "<none>"
			caBundle := "false"

			if svcMap, ok := webhookCC["service"].(map[string]interface{}); ok {
				if n, ok := svcMap["namespace"].(string); ok {
					ns = n
				}
				if s, ok := svcMap["name"].(string); ok {
					svc = s
				}
				if p, ok := svcMap["path"].(string); ok && p != "" {
					urlStr = p
				}
			}
			if u, ok := webhookCC["url"].(string); ok && u != "" {
				urlStr = u
			}
			if cb, ok := webhookCC["caBundle"].(string); ok && cb != "" {
				caBundle = "true"
			}

			outputRows = append(outputRows, []string{
				"CRD Conversion", crd.GetName(), ns, svc, urlStr, caBundle, "<CRD conversion>",
			})

			lootEnum = append(lootEnum,
				fmt.Sprintf("kubectl get crd %s -o json | jq '.spec.conversion'", crd.GetName()),
			)
		}
	}

	// Prepare output
	table := internal.TableFile{
		Name:   "Webhooks",
		Header: headers,
		Body:   outputRows,
	}
	loot := internal.LootFile{
		Name:     "Webhook-Enum",
		Contents: strings.Join(lootEnum, "\n"),
	}

	err = internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"Webhooks",
		globals.ClusterName,
		"results",
		WebhooksOutput{
			Table: []internal.TableFile{table},
			Loot:  []internal.LootFile{loot},
		},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_WEBHOOKS_MODULE_NAME)
		return
	}

	if len(outputRows) > 0 {
		logger.InfoM(fmt.Sprintf("%d webhooks found", len(outputRows)), globals.K8S_WEBHOOKS_MODULE_NAME)
	} else {
		logger.InfoM("No webhooks found, skipping output file creation", globals.K8S_WEBHOOKS_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_WEBHOOKS_MODULE_NAME), globals.K8S_WEBHOOKS_MODULE_NAME)
}

// helper to stringify rules
func webhookRulesToString(rules []admissionv1.RuleWithOperations) string {
	if len(rules) == 0 {
		return "<none>"
	}
	var sb []string
	for _, r := range rules {
		sb = append(sb, fmt.Sprintf("%v %v", r.Operations, r.Resources))
	}
	return strings.Join(sb, "; ")
}
