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
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/clientcmd"
)

var NetworkPoliciesCmd = &cobra.Command{
	Use:     "network-policy",
	Aliases: []string{"net-pol"},
	Short:   "List all cluster Network Policies",
	Long: `
List all cluster Network Policies:
  cloudfox kubernetes network-policy`,
	Run: ListNetworkPolicies,
}

type NetworkPoliciesOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t NetworkPoliciesOutput) TableFiles() []internal.TableFile {
	return t.Table
}

func (t NetworkPoliciesOutput) LootFiles() []internal.LootFile {
	return t.Loot
}

func buildDynamicClient() dynamic.Interface {
	restConfig, err := clientcmd.RESTConfigFromKubeConfig(globals.RawKubeconfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to load kubeconfig for dynamic client: %v\n", err)
		os.Exit(1)
	}

	dynClient, err := dynamic.NewForConfig(restConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to create dynamic client: %v\n", err)
		os.Exit(1)
	}
	return dynClient
}

func ListNetworkPolicies(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	clientset := config.GetClientOrExit()
	if clientset == nil {
		logger.ErrorM("Error getting Kubernetes client:", globals.K8S_NETWORK_POLICY_MODULE_NAME)
		os.Exit(1)
	}
	dyn := buildDynamicClient()

	namespaces, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing namespaces: %v", err), globals.K8S_NETWORK_POLICY_MODULE_NAME)
		return
	}

	headers := []string{"Namespace", "Name", "Type", "Pod Selector", "Policy Types", "Ingress Rules", "Egress Rules"}
	var outputRows [][]string

	namespaceMap := make(map[string][]string)

	// --- Standard Kubernetes NetworkPolicies ---
	for _, ns := range namespaces.Items {
		nps, err := clientset.NetworkingV1().NetworkPolicies(ns.Name).List(ctx, metav1.ListOptions{})
		if err == nil {
			for _, np := range nps.Items {
				row := []string{
					np.Namespace,
					np.Name,
					"NetworkPolicy",
					k8sinternal.NonEmpty(formatLabelSelector(&np.Spec.PodSelector)),
					k8sinternal.NonEmpty(formatPolicyTypes(np.Spec.PolicyTypes)),
					k8sinternal.NonEmpty(formatIngressRules(np.Spec.Ingress)),
					k8sinternal.NonEmpty(formatEgressRules(np.Spec.Egress)),
				}
				outputRows = append(outputRows, row)
				namespaceMap[np.Namespace] = append(namespaceMap[np.Namespace],
					fmt.Sprintf("kubectl get networkpolicy %q -n %q -o yaml", np.Name, np.Namespace))
			}
		}
	}

	// --- CNI CRDs ---
	crds := []struct {
		GVR       schema.GroupVersionResource
		Kind      string
		Namespace bool
	}{
		{
			GVR:  schema.GroupVersionResource{Group: "networking.projectcalico.org", Version: "v3", Resource: "networkpolicies"},
			Kind: "CalicoNetworkPolicy", Namespace: true,
		},
		{
			GVR:  schema.GroupVersionResource{Group: "cilium.io", Version: "v2", Resource: "ciliumnetworkpolicies"},
			Kind: "CiliumNetworkPolicy", Namespace: true,
		},
		{
			GVR:  schema.GroupVersionResource{Group: "cilium.io", Version: "v2", Resource: "ciliumclusterwidenetworkpolicies"},
			Kind: "CiliumClusterwideNetworkPolicy", Namespace: false,
		},
		{
			GVR:  schema.GroupVersionResource{Group: "crd.antrea.io", Version: "v1beta1", Resource: "networkpolicies"},
			Kind: "AntreaNetworkPolicy", Namespace: true,
		},
		{
			GVR:  schema.GroupVersionResource{Group: "crd.antrea.io", Version: "v1beta1", Resource: "clusternetworkpolicies"},
			Kind: "AntreaClusterNetworkPolicy", Namespace: false,
		},
	}

	for _, crd := range crds {
		if crd.Namespace {
			for _, ns := range namespaces.Items {
				res, err := dyn.Resource(crd.GVR).Namespace(ns.Name).List(ctx, metav1.ListOptions{})
				if err != nil {
					continue
				}
				for _, item := range res.Items {
					var s, t, in, eg string
					switch crd.Kind {
					case "CalicoNetworkPolicy":
						s, t, in, eg = parseCalicoPolicy(item.Object)
					case "CiliumNetworkPolicy", "CiliumClusterwideNetworkPolicy":
						s, t, in, eg = parseCiliumPolicy(item.Object)
					case "AntreaNetworkPolicy", "AntreaClusterNetworkPolicy":
						s, t, in, eg = parseAntreaPolicy(item.Object)
					default:
						s, t, in, eg = "<UNKNOWN>", "<UNKNOWN>", "<UNKNOWN>", "<UNKNOWN>"
					}
					row := []string{ns.Name, item.GetName(), crd.Kind, s, t, in, eg}
					outputRows = append(outputRows, row)
					namespaceMap[ns.Name] = append(namespaceMap[ns.Name],
						fmt.Sprintf("kubectl get %s %q -n %q -o yaml", strings.ToLower(crd.Kind), item.GetName(), ns.Name))
				}
			}
		} else {
			res, err := dyn.Resource(crd.GVR).List(ctx, metav1.ListOptions{})
			if err != nil {
				continue
			}
			for _, item := range res.Items {
				var s, t, in, eg string
				switch crd.Kind {
				case "CiliumClusterwideNetworkPolicy":
					s, t, in, eg = parseCiliumPolicy(item.Object)
				case "AntreaClusterNetworkPolicy":
					s, t, in, eg = parseAntreaPolicy(item.Object)
				default:
					s, t, in, eg = "<UNKNOWN>", "<UNKNOWN>", "<UNKNOWN>", "<UNKNOWN>"
				}
				row := []string{"<CLUSTER>", item.GetName(), crd.Kind, s, t, in, eg}
				outputRows = append(outputRows, row)
				namespaceMap["CLUSTER"] = append(namespaceMap["CLUSTER"],
					fmt.Sprintf("kubectl get %s %q -o yaml", strings.ToLower(crd.Kind), item.GetName()))
			}
		}
	}

	lootEnum := []string{
		"#####################################",
		"##### Enumerate Network Policy Information",
		"#####################################",
		"",
	}
	if globals.KubeContext != "" {
		lootEnum = append(lootEnum, fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext))
	}

	namespacesList := make([]string, 0, len(namespaceMap))
	for ns := range namespaceMap {
		namespacesList = append(namespacesList, ns)
	}
	sort.Strings(namespacesList)

	for i, ns := range namespacesList {
		lootEnum = append(lootEnum, fmt.Sprintf("\n# Namespace: %s\n", ns))
		lootEnum = append(lootEnum, namespaceMap[ns]...)
		if i < len(namespacesList)-1 {
			lootEnum = append(lootEnum, "")
		}
	}

	table := internal.TableFile{
		Name:   "Network-Policies",
		Header: headers,
		Body:   outputRows,
	}

	loot := internal.LootFile{
		Name:     "Network-Policy-Enum",
		Contents: strings.Join(lootEnum, "\n"),
	}

	err = internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"Network-Policies",
		globals.ClusterName,
		"results",
		NetworkPoliciesOutput{
			Table: []internal.TableFile{table},
			Loot:  []internal.LootFile{loot},
		},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_NETWORK_POLICY_MODULE_NAME)
	}
}

// ====================
// Helper Functions
// ====================

func formatLabelSelector(selector *metav1.LabelSelector) string {
	if selector == nil || len(selector.MatchLabels) == 0 {
		return "<NONE>"
	}
	var pairs []string
	for k, v := range selector.MatchLabels {
		pairs = append(pairs, fmt.Sprintf("%s=%s", k, v))
	}
	return strings.Join(pairs, ",")
}

func formatPolicyTypes(policyTypes []netv1.PolicyType) string {
	if len(policyTypes) == 0 {
		return "<NONE>"
	}
	var result []string
	for _, pt := range policyTypes {
		result = append(result, string(pt))
	}
	return strings.Join(result, ",")
}

func formatIngressRules(rules []netv1.NetworkPolicyIngressRule) string {
	if len(rules) == 0 {
		return "<NONE>"
	}
	var details []string
	for i, rule := range rules {
		var fromParts []string
		for _, from := range rule.From {
			if from.PodSelector != nil {
				fromParts = append(fromParts, fmt.Sprintf("PodSelector{%s}", formatLabelSelector(from.PodSelector)))
			}
			if from.NamespaceSelector != nil {
				fromParts = append(fromParts, fmt.Sprintf("NSSelector{%s}", formatLabelSelector(from.NamespaceSelector)))
			}
			if from.IPBlock != nil {
				fromParts = append(fromParts, fmt.Sprintf("IPBlock{CIDR:%s, Except:%v}", from.IPBlock.CIDR, from.IPBlock.Except))
			}
		}

		var ports []string
		for _, p := range rule.Ports {
			protocol := "<ANY>"
			if p.Protocol != nil {
				protocol = string(*p.Protocol)
			}
			port := "<ANY>"
			if p.Port != nil {
				port = p.Port.String()
			}
			ports = append(ports, fmt.Sprintf("%s/%s", protocol, port))
		}

		line := fmt.Sprintf("Rule %d: From=[%s], Ports=[%s]", i+1, strings.Join(fromParts, "; "), strings.Join(ports, "; "))
		details = append(details, line)
	}
	return strings.Join(details, "\n")
}

func formatEgressRules(rules []netv1.NetworkPolicyEgressRule) string {
	if len(rules) == 0 {
		return "<NONE>"
	}
	var details []string
	for i, rule := range rules {
		var toParts []string
		for _, to := range rule.To {
			if to.PodSelector != nil {
				toParts = append(toParts, fmt.Sprintf("PodSelector{%s}", formatLabelSelector(to.PodSelector)))
			}
			if to.NamespaceSelector != nil {
				toParts = append(toParts, fmt.Sprintf("NSSelector{%s}", formatLabelSelector(to.NamespaceSelector)))
			}
			if to.IPBlock != nil {
				toParts = append(toParts, fmt.Sprintf("IPBlock{CIDR:%s, Except:%v}", to.IPBlock.CIDR, to.IPBlock.Except))
			}
		}

		var ports []string
		for _, p := range rule.Ports {
			protocol := "<ANY>"
			if p.Protocol != nil {
				protocol = string(*p.Protocol)
			}
			port := "<ANY>"
			if p.Port != nil {
				port = p.Port.String()
			}
			ports = append(ports, fmt.Sprintf("%s/%s", protocol, port))
		}

		line := fmt.Sprintf("Rule %d: To=[%s], Ports=[%s]", i+1, strings.Join(toParts, "; "), strings.Join(ports, "; "))
		details = append(details, line)
	}
	return strings.Join(details, "\n")
}

func parseCalicoPolicy(item map[string]interface{}) (selector, policyTypes, ingress, egress string) {
	spec := item["spec"].(map[string]interface{})
	selector = "<NONE>"
	if s, ok := spec["selector"].(string); ok && s != "" {
		selector = s
	}

	types := []string{}
	if _, ok := spec["ingress"]; ok {
		types = append(types, "Ingress")
	}
	if _, ok := spec["egress"]; ok {
		types = append(types, "Egress")
	}
	if len(types) == 0 {
		types = []string{"<NONE>"}
	}
	policyTypes = strings.Join(types, ",")

	ingress = formatGenericRules(spec["ingress"])
	egress = formatGenericRules(spec["egress"])
	return
}

func parseCiliumPolicy(item map[string]interface{}) (selector, policyTypes, ingress, egress string) {
	spec := item["spec"].(map[string]interface{})
	selector = "<NONE>"
	if sel, ok := spec["endpointSelector"].(map[string]interface{}); ok {
		if ml, ok := sel["matchLabels"].(map[string]interface{}); ok {
			var parts []string
			for k, v := range ml {
				parts = append(parts, fmt.Sprintf("%s=%s", k, v))
			}
			selector = strings.Join(parts, ",")
		}
	}

	types := []string{}
	if _, ok := spec["ingress"]; ok {
		types = append(types, "Ingress")
	}
	if _, ok := spec["egress"]; ok {
		types = append(types, "Egress")
	}
	if len(types) == 0 {
		types = []string{"<NONE>"}
	}
	policyTypes = strings.Join(types, ",")

	ingress = formatGenericRules(spec["ingress"])
	egress = formatGenericRules(spec["egress"])
	return
}

func parseAntreaPolicy(item map[string]interface{}) (selector, policyTypes, ingress, egress string) {
	spec := item["spec"].(map[string]interface{})
	selector = "<NONE>"
	if appliedTo, ok := spec["appliedTo"].([]interface{}); ok {
		var sels []string
		for _, at := range appliedTo {
			if atMap, ok := at.(map[string]interface{}); ok {
				if ps, ok := atMap["podSelector"].(map[string]interface{}); ok {
					var parts []string
					if ml, ok := ps["matchLabels"].(map[string]interface{}); ok {
						for k, v := range ml {
							parts = append(parts, fmt.Sprintf("%s=%s", k, v))
						}
					}
					sels = append(sels, strings.Join(parts, ","))
				}
			}
		}
		if len(sels) > 0 {
			selector = strings.Join(sels, ";")
		}
	}

	types := []string{}
	if _, ok := spec["ingress"]; ok {
		types = append(types, "Ingress")
	}
	if _, ok := spec["egress"]; ok {
		types = append(types, "Egress")
	}
	if len(types) == 0 {
		types = []string{"<NONE>"}
	}
	policyTypes = strings.Join(types, ",")

	ingress = formatGenericRules(spec["ingress"])
	egress = formatGenericRules(spec["egress"])
	return
}

func formatGenericRules(obj interface{}) string {
	if obj == nil {
		return "<NONE>"
	}
	rules, ok := obj.([]interface{})
	if !ok || len(rules) == 0 {
		return "<NONE>"
	}

	var details []string
	for i, r := range rules {
		rule, _ := r.(map[string]interface{})
		var parts []string

		if from, ok := rule["from"].([]interface{}); ok {
			for _, f := range from {
				if fMap, ok := f.(map[string]interface{}); ok {
					if ps, ok := fMap["podSelector"]; ok {
						parts = append(parts, fmt.Sprintf("PodSelector%v", ps))
					}
					if ns, ok := fMap["namespaceSelector"]; ok {
						parts = append(parts, fmt.Sprintf("NSSelector%v", ns))
					}
					if ipb, ok := fMap["ipBlock"]; ok {
						parts = append(parts, fmt.Sprintf("IPBlock%v", ipb))
					}
				}
			}
		}

		if ports, ok := rule["ports"].([]interface{}); ok {
			var portParts []string
			for _, p := range ports {
				if pm, ok := p.(map[string]interface{}); ok {
					proto := "<ANY>"
					if pr, ok := pm["protocol"].(string); ok {
						proto = pr
					}
					port := "<ANY>"
					if po, ok := pm["port"]; ok {
						port = fmt.Sprintf("%v", po)
					}
					portParts = append(portParts, fmt.Sprintf("%s/%s", proto, port))
				}
			}
			parts = append(parts, fmt.Sprintf("Ports=[%s]", strings.Join(portParts, ";")))
		}

		line := fmt.Sprintf("Rule %d: %s", i+1, strings.Join(parts, ", "))
		details = append(details, line)
	}
	return strings.Join(details, "\n")
}
