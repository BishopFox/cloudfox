package commands

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	k8sinternal "github.com/BishopFox/cloudfox/internal/kubernetes"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var PodSecurityCmd = &cobra.Command{
	Use:     "pod-security",
	Aliases: []string{"psa"},
	Short:   "List all cluster Pod Security Policies or Admission settings",
	Long: `
List all cluster Pod Security Policies or Admission settings:
  cloudfox kubernetes pod-security`,
	Run: ListPodSecurity,
}

type PodSecurityOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t PodSecurityOutput) TableFiles() []internal.TableFile { return t.Table }
func (t PodSecurityOutput) LootFiles() []internal.LootFile   { return t.Loot }

func ListPodSecurity(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	logger := internal.NewLogger()

	// Extract global flags
	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	clientset := config.GetClientOrExit()
	if clientset == nil {
		logger.ErrorM("Error getting Kubernetes client:", globals.K8S_POD_SECURITY_MODULE_NAME)
		os.Exit(1)
	}

	dynClient := config.GetDynamicClientOrExit()

	// --- Detect PSP ---
	clusterHasPSP := "false"
	pspGVR := schema.GroupVersionResource{Group: "policy", Version: "v1beta1", Resource: "podsecuritypolicies"}
	pspList, err := dynClient.Resource(pspGVR).List(ctx, metav1.ListOptions{})
	if err == nil && len(pspList.Items) > 0 {
		clusterHasPSP = "true"
	}

	// --- List Namespaces ---
	nsGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "namespaces"}
	nsList, err := dynClient.Resource(nsGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing namespaces: %v", err), globals.K8S_POD_SECURITY_MODULE_NAME)
		return
	}

	// --- List Webhooks ---
	webhookGVRs := []schema.GroupVersionResource{
		{Group: "admissionregistration.k8s.io", Version: "v1", Resource: "mutatingwebhookconfigurations"},
		{Group: "admissionregistration.k8s.io", Version: "v1", Resource: "validatingwebhookconfigurations"},
	}

	mutatingMap := map[string][]string{}
	validatingMap := map[string][]string{}

	for _, gvr := range webhookGVRs {
		webhookList, err := dynClient.Resource(gvr).List(ctx, metav1.ListOptions{})
		if err != nil {
			logger.ErrorM(fmt.Sprintf("Error listing %s: %v", gvr.Resource, err), globals.K8S_POD_SECURITY_MODULE_NAME)
			continue
		}
		for _, wh := range webhookList.Items {
			webhooks, found := wh.Object["webhooks"].([]interface{})
			if !found || len(webhooks) == 0 {
				continue
			}
			for _, w := range webhooks {
				wMap := w.(map[string]interface{})
				rules, ok := wMap["rules"].([]interface{})
				if !ok {
					continue
				}
				if len(rules) == 0 {
					continue
				}
				// Check if targets Pods
				targetsPods := false
				for _, r := range rules {
					rMap := r.(map[string]interface{})
					resources, _ := rMap["resources"].([]interface{})
					for _, res := range resources {
						if resStr, ok := res.(string); ok && resStr == "pods" {
							targetsPods = true
						}
					}
				}
				if !targetsPods {
					continue
				}

				nsSelector, ok := wMap["namespaceSelector"].(map[string]interface{})
				if !ok {
					nsSelector = nil
				}
				if nsSelector == nil {
					if gvr.Resource == "mutatingwebhookconfigurations" {
						mutatingMap["<cluster-wide>"] = append(mutatingMap["<cluster-wide>"], wh.GetName())
					} else {
						validatingMap["<cluster-wide>"] = append(validatingMap["<cluster-wide>"], wh.GetName())
					}
				} else {
					for _, ns := range nsList.Items {
						nsName := ns.GetName()
						if gvr.Resource == "mutatingwebhookconfigurations" {
							mutatingMap[nsName] = append(mutatingMap[nsName], wh.GetName())
						} else {
							validatingMap[nsName] = append(validatingMap[nsName], wh.GetName())
						}
					}
				}
			}
		}
	}

	// --- Dynamic Policy Detection (Namespace-aware) ---
	dynamicPolicies := map[string][]string{}
	crdGVR := schema.GroupVersionResource{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}
	crdList, err := dynClient.Resource(crdGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing CRDs: %v", err), globals.K8S_POD_SECURITY_MODULE_NAME)
	} else {
		for _, crd := range crdList.Items {
			crdName := crd.GetName()
			switch {
			case strings.Contains(crdName, "gatekeeper"):
				// Gatekeeper constraints
				// Try to map to namespaces from spec.match.kinds
				if spec, found, _ := unstructured.NestedMap(crd.Object, "spec"); found {
					namespaces, _, _ := unstructured.NestedStringSlice(spec, "namespaces")
					if len(namespaces) == 0 {
						dynamicPolicies["<cluster-wide>"] = append(dynamicPolicies["<cluster-wide>"], "Gatekeeper/OPA:"+crdName)
					} else {
						for _, ns := range namespaces {
							dynamicPolicies[ns] = append(dynamicPolicies[ns], "Gatekeeper/OPA:"+crdName)
						}
					}
				} else {
					dynamicPolicies["<cluster-wide>"] = append(dynamicPolicies["<cluster-wide>"], "Gatekeeper/OPA:"+crdName)
				}
			case strings.Contains(crdName, "kyverno"):
				// Kyverno policies
				if spec, found, _ := unstructured.NestedMap(crd.Object, "spec"); found {
					nsSelector, _, _ := unstructured.NestedStringSlice(spec, "namespaceSelector.matchNames")
					if len(nsSelector) == 0 {
						dynamicPolicies["<cluster-wide>"] = append(dynamicPolicies["<cluster-wide>"], "Kyverno:"+crdName)
					} else {
						for _, ns := range nsSelector {
							dynamicPolicies[ns] = append(dynamicPolicies[ns], "Kyverno:"+crdName)
						}
					}
				} else {
					dynamicPolicies["<cluster-wide>"] = append(dynamicPolicies["<cluster-wide>"], "Kyverno:"+crdName)
				}
			}
		}
	}

	// --- Prepare Table & Loot ---
	headers := []string{
		"Namespace", "PodSecurity Label", "PodSecurity Annotation", "ClusterHasPSP",
		"Mutating Webhook", "Validating Webhook", "Dynamic Policy", "ConflictFlag",
	}

	var outputRows [][]string
	var lootEnum []string
	lootEnum = append(lootEnum,
		"#####################################",
		"##### Enumerate Pod Security Information",
		"#####################################",
	)
	if globals.KubeContext != "" {
		lootEnum = append(lootEnum, fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext))
	}

	namespaces, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error enumerating namespaces: %v", err), globals.K8S_POD_SECURITY_MODULE_NAME)
		return
	}

	for _, ns := range namespaces.Items {
		label := k8sinternal.NonEmpty(ns.Labels["pod-security.kubernetes.io/enforce"])
		annotation := k8sinternal.NonEmpty(ns.Annotations["pod-security.kubernetes.io/enforce"])
		nsName := ns.GetName()

		conflictFlag := "false"
		if label != "" && annotation != "" && label != annotation {
			conflictFlag = "true"
		}
		if clusterHasPSP == "true" && (label != "" || annotation != "") {
			conflictFlag = "true"
		}
		if len(mutatingMap[nsName]) > 0 || len(validatingMap[nsName]) > 0 {
			conflictFlag = "true"
		}
		if len(dynamicPolicies[nsName]) > 0 || len(dynamicPolicies["<cluster-wide>"]) > 0 {
			conflictFlag = "true"
		}

		row := []string{
			nsName, label, annotation, clusterHasPSP,
			strings.Join(mutatingMap[nsName], "; "),
			strings.Join(validatingMap[nsName], "; "),
			strings.Join(dynamicPolicies[nsName], "; "),
			conflictFlag,
		}
		outputRows = append(outputRows, row)

		lootEnum = append(lootEnum,
			fmt.Sprintf("# Namespace: %s", nsName),
			fmt.Sprintf(`kubectl get ns %s --show-labels | grep 'pod-security.kubernetes.io'`, nsName),
			fmt.Sprintf(`kubectl get ns %s -o json | jq -r '.metadata.annotations."pod-security.kubernetes.io/enforce"'`, nsName),
		)
	}

	// --- Loot generation for dynamic policies per namespace ---
	for ns, policies := range dynamicPolicies {
		for _, pol := range policies {
			parts := strings.SplitN(pol, ":", 2)
			if len(parts) != 2 {
				continue
			}
			tool, crdName := parts[0], parts[1]
			nsStr := ns
			if ns == "<cluster-wide>" {
				nsStr = "CLUSTER-WIDE"
			}
			switch tool {
			case "Gatekeeper/OPA":
				lootEnum = append(lootEnum,
					fmt.Sprintf("# Gatekeeper/OPA constraint: %s (%s)", crdName, nsStr),
					fmt.Sprintf("kubectl get %s -o yaml", crdName),
				)
			case "Kyverno":
				lootEnum = append(lootEnum,
					fmt.Sprintf("# Kyverno policy: %s (%s)", crdName, nsStr),
					fmt.Sprintf("kubectl get %s -o yaml", crdName),
				)
			}
		}
	}

	// Cluster-wide row
	clusterRow := []string{
		"CLUSTER-WIDE", "<N/A>", "<N/A>", clusterHasPSP,
		strings.Join(mutatingMap["<cluster-wide>"], "; "),
		strings.Join(validatingMap["<cluster-wide>"], "; "),
		strings.Join(dynamicPolicies["<cluster-wide>"], "; "),
		"<N/A>",
	}
	outputRows = append(outputRows, clusterRow)

	// Loot for webhooks and PSP
	for _, whName := range mutatingMap["<cluster-wide>"] {
		lootEnum = append(lootEnum,
			fmt.Sprintf("kubectl get mutatingwebhookconfiguration %s -o json | jq '.webhooks[] | select(.rules[].resources[]==\"pods\")'", whName))
	}
	for _, whName := range validatingMap["<cluster-wide>"] {
		lootEnum = append(lootEnum,
			fmt.Sprintf("kubectl get validatingwebhookconfiguration %s -o json | jq '.webhooks[] | select(.rules[].resources[]==\"pods\")'", whName))
	}
	if clusterHasPSP == "true" {
		lootEnum = append(lootEnum,
			"kubectl get psp -o wide",
			"kubectl get psp -o yaml",
		)
	}

	// Sort rows by namespace
	sort.Slice(outputRows, func(i, j int) bool {
		return outputRows[i][0] < outputRows[j][0]
	})

	table := internal.TableFile{
		Name:   "Pod-Security",
		Header: headers,
		Body:   outputRows,
	}
	loot := internal.LootFile{
		Name:     "Pod-Security-Enum",
		Contents: strings.Join(lootEnum, "\n"),
	}

	err = internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"Pod-Security",
		globals.ClusterName,
		"results",
		PodSecurityOutput{
			Table: []internal.TableFile{table},
			Loot:  []internal.LootFile{loot},
		},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_POD_SECURITY_MODULE_NAME)
	}
}

func safeGet(m map[string]string, key string) string {
	if m == nil {
		return ""
	}
	return m[key]
}
