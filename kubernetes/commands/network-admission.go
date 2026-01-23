package commands

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/BishopFox/cloudfox/kubernetes/sdk"
	"github.com/BishopFox/cloudfox/kubernetes/shared"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

var NetworkAdmissionCmd = &cobra.Command{
	Use:     "network-admission",
	Aliases: []string{"net-adm", "network-policy", "net-pol"},
	Short:   "Analyze network admission controllers, policies, and security enforcement",
	Long: `
Analyze all cluster network admission configurations including:
  - Kubernetes NetworkPolicies with comprehensive security analysis
  - CNI-specific policies (Calico, Cilium, Antrea)
  - Service mesh policies (Istio AuthorizationPolicy, Linkerd)
  - Coverage gap identification (namespaces/pods without policies)
  - Policy weakness detection (overly permissive rules)
  - Lateral movement opportunity analysis
  - Data exfiltration risk assessment
  - Metadata API access detection
  - Default-deny policy recommendations
  - Risk-based scoring for prioritized security review

  cloudfox kubernetes network-admission`,
	Run: ListNetworkAdmission,
}

// NetworkPoliciesCmd is an alias for backwards compatibility
var NetworkPoliciesCmd = NetworkAdmissionCmd

type NetworkAdmissionOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t NetworkAdmissionOutput) TableFiles() []internal.TableFile { return t.Table }
func (t NetworkAdmissionOutput) LootFiles() []internal.LootFile   { return t.Loot }

// NetworkAdmissionFinding represents comprehensive network policy analysis for a namespace
type NetworkAdmissionFinding struct {
	// Basic Info
	Namespace string
	Age       string

	// Security Analysis
	RiskLevel      string
	SecurityIssues []string

	// Policy Coverage
	HasNetworkPolicy bool
	PolicyCount      int
	CoveredPods      int
	TotalPods        int
	UncoveredPods    int

	// Default Deny Status
	HasDefaultDenyIngress bool
	HasDefaultDenyEgress  bool
	DefaultDenyPolicies   []string

	// Traffic Analysis (what's allowed without policy engine blocking)
	AllowsInternetIngress  bool
	AllowsInternetEgress   bool
	AllowsCrossNSIngress   bool
	AllowsCrossNSEgress    bool
	AllowsMetadataAPI      bool
	AllowsDNSEgress        bool
	AllowsAllPodsIngress   bool
	AllowsAllPodsEgress    bool
	AllowsKubeAPIEgress    bool
	IngressDangerousPorts  []int32
	EgressDangerousPorts   []int32

	// Policy Engine Counts
	K8sNetworkPolicyCount int
	CalicoCount           int
	CiliumCount           int
	AntreaCount           int
	IstioCount            int
	LinkerdCount          int
	AWSSecurityGroupCount int
	OpenShiftEgressCount  int
	ConsulConnectCount    int
	KumaMeshCount         int
	SMICount              int
	GlooMeshCount         int
	NSXTCount             int
	GCPBackendCount       int
	AzureNetworkCount     int

	// Policy Engine Blocking (prevents false positives)
	PolicyEngineBlocks NetworkPolicyEngineBlocking

	// Detailed policies for this namespace
	K8sNetworkPolicies    []K8sNetworkPolicyInfo
	CalicoPolicies        []CalicoNetworkPolicyInfo
	CiliumPolicies        []CiliumNetworkPolicyInfo
	AntreaPolicies        []AntreaNetworkPolicyInfo
	IstioPolicies         []IstioAuthorizationPolicyInfo
	LinkerdPolicies       []LinkerdPolicyInfo
	AWSSecurityGroupPols  []AWSSecurityGroupPolicyInfo
	OpenShiftEgressPols   []OpenShiftEgressFirewallInfo
	ConsulConnectPols     []ConsulConnectIntentionInfo
	KumaMeshPols          []KumaMeshPolicyInfo
	SMIPolicies           []SMITrafficPolicyInfo
	GlooMeshPols          []GlooMeshPolicyInfo
	NSXTPolicies          []NSXTSecurityPolicyInfo
	GCPBackendPols        []GCPBackendPolicyInfo
	AzureNetworkPols      []AzureNetworkPolicyInfo

	// Recommendations
	Recommendations []string
}

// NetworkPolicyEngineBlocking tracks which traffic patterns are blocked by policy engines
type NetworkPolicyEngineBlocking struct {
	InternetIngressBlocked   bool
	InternetIngressBlockedBy []string
	InternetEgressBlocked    bool
	InternetEgressBlockedBy  []string
	CrossNSIngressBlocked    bool
	CrossNSIngressBlockedBy  []string
	CrossNSEgressBlocked     bool
	CrossNSEgressBlockedBy   []string
	MetadataAPIBlocked       bool
	MetadataAPIBlockedBy     []string
	DNSEgressRestricted      bool
	DNSEgressRestrictedBy    []string
	AllPodsIngressBlocked    bool // Default deny ingress
	AllPodsIngressBlockedBy  []string
	AllPodsEgressBlocked     bool // Default deny egress
	AllPodsEgressBlockedBy   []string
	KubeAPIEgressBlocked     bool
	KubeAPIEgressBlockedBy   []string
}

// K8sNetworkPolicyInfo represents a Kubernetes NetworkPolicy
type K8sNetworkPolicyInfo struct {
	Name                  string
	Namespace             string
	PodSelector           string
	PolicyTypes           []string
	IngressRuleCount      int
	EgressRuleCount       int
	AllowsInternetIngress bool
	AllowsInternetEgress  bool
	AllowsCrossNS         bool
	AllowsMetadataAPI     bool
	IsDefaultDeny         bool
	DefaultDenyIngress    bool
	DefaultDenyEgress     bool
	CoveredPods           int
	RiskLevel             string
	Weaknesses            []string
	ImageVerified         bool // True if CNI/policy controller image was verified
}

// CalicoNetworkPolicyInfo represents a Calico NetworkPolicy or GlobalNetworkPolicy
type CalicoNetworkPolicyInfo struct {
	Name                  string
	Namespace             string // empty for GlobalNetworkPolicy
	IsGlobal              bool
	Selector              string
	Order                 float64
	Types                 []string // ingress, egress
	IngressRuleCount      int
	EgressRuleCount       int
	AllowsInternetIngress bool
	AllowsInternetEgress  bool
	AllowsCrossNS         bool
	AllowsMetadataAPI     bool
	IsDefaultDeny         bool
	Action                string // Allow, Deny, Log, Pass
	RiskLevel             string
	ImageVerified         bool // True if Calico controller image was verified
}

// CiliumNetworkPolicyInfo represents a Cilium NetworkPolicy
type CiliumNetworkPolicyInfo struct {
	Name                  string
	Namespace             string // empty for CiliumClusterwideNetworkPolicy
	IsClusterwide         bool
	EndpointSelector      string
	IngressRuleCount      int
	EgressRuleCount       int
	AllowsInternetIngress bool
	AllowsInternetEgress  bool
	AllowsCrossNS         bool
	AllowsMetadataAPI     bool
	HasL7Rules            bool // HTTP, DNS, Kafka, etc.
	L7Protocols           []string
	IsDefaultDeny         bool
	RiskLevel             string
	ImageVerified         bool // True if Cilium agent image was verified
}

// AntreaNetworkPolicyInfo represents an Antrea NetworkPolicy
type AntreaNetworkPolicyInfo struct {
	Name                  string
	Namespace             string // empty for ClusterNetworkPolicy
	IsCluster             bool
	AppliedTo             string
	Priority              float64
	Tier                  string
	IngressRuleCount      int
	EgressRuleCount       int
	AllowsInternetIngress bool
	AllowsInternetEgress  bool
	AllowsCrossNS         bool
	AllowsMetadataAPI     bool
	IsDefaultDeny         bool
	Action                string // Allow, Drop, Reject, Pass
	RiskLevel             string
	ImageVerified         bool // True if Antrea agent image was verified
}

// IstioAuthorizationPolicyInfo represents an Istio AuthorizationPolicy
type IstioAuthorizationPolicyInfo struct {
	Name                  string
	Namespace             string
	Action                string // ALLOW, DENY, CUSTOM, AUDIT
	Selector              string
	Rules                 int
	AllowsInternetIngress bool
	AllowsCrossNS         bool
	HasMTLS               bool
	RiskLevel             string
	ImageVerified         bool // True if Istio proxy/control plane image was verified
}

// LinkerdPolicyInfo represents Linkerd Server/ServerAuthorization
type LinkerdPolicyInfo struct {
	Name          string
	Namespace     string
	Kind          string // Server, ServerAuthorization, AuthorizationPolicy
	Selector      string
	RiskLevel     string
	ImageVerified bool // True if Linkerd proxy/control plane image was verified
}

// AWSSecurityGroupPolicyInfo represents AWS VPC CNI SecurityGroupPolicy
type AWSSecurityGroupPolicyInfo struct {
	Name                 string
	Namespace            string
	PodSelector          string
	SecurityGroupIDs     []string
	AllowsInternetEgress bool // SG rules analysis
	AllowsAllTraffic     bool
	RiskLevel            string
	ImageVerified        bool // True if AWS VPC CNI image was verified
}

// OpenShiftEgressFirewallInfo represents OpenShift EgressFirewall/EgressNetworkPolicy
type OpenShiftEgressFirewallInfo struct {
	Name              string
	Namespace         string
	Kind              string // EgressFirewall, EgressNetworkPolicy
	RuleCount         int
	AllowsInternet    bool
	DeniesMetadataAPI bool
	DeniesAllEgress   bool
	RiskLevel         string
	ImageVerified     bool // True if OpenShift network operator image was verified
}

// ConsulConnectIntentionInfo represents HashiCorp Consul Connect ServiceIntentions
type ConsulConnectIntentionInfo struct {
	Name               string
	Namespace          string
	Destination        string
	Action             string // allow, deny
	SourceCount        int
	AllowsAllSources   bool
	DeniesAllSources   bool
	HasMTLS            bool
	RiskLevel          string
	ImageVerified      bool // True if Consul Connect image was verified
}

// KumaMeshPolicyInfo represents Kuma/Kong Mesh traffic policies
type KumaMeshPolicyInfo struct {
	Name                string
	Namespace           string
	Kind                string // MeshTrafficPermission, MeshAccessLog, TrafficPermission
	TargetRef           string
	Action              string // Allow, Deny, AllowWithShadowDeny
	RuleCount           int
	AllowsAllTraffic    bool
	DeniesAllTraffic    bool
	RiskLevel           string
	ImageVerified       bool // True if Kuma control plane image was verified
}

// SMITrafficPolicyInfo represents Service Mesh Interface policies (OSM, Traefik Mesh)
type SMITrafficPolicyInfo struct {
	Name               string
	Namespace          string
	Kind               string // TrafficTarget, TrafficPolicy, HTTPRouteGroup
	MeshProvider       string // OSM, TraefikMesh
	DestinationService string
	SourceServices     []string
	AllowsAllSources   bool
	RiskLevel          string
	ImageVerified      bool // True if SMI mesh provider image was verified
}

// GlooMeshPolicyInfo represents Solo.io Gloo Mesh policies
type GlooMeshPolicyInfo struct {
	Name             string
	Namespace        string
	Kind             string // AccessPolicy, TrafficPolicy
	ApplyToRefs      string
	Action           string // ALLOW, DENY
	RuleCount        int
	AllowsAllTraffic bool
	RiskLevel        string
	ImageVerified    bool // True if Gloo Mesh management plane image was verified
}

// NSXTSecurityPolicyInfo represents VMware NSX-T security policies
type NSXTSecurityPolicyInfo struct {
	Name             string
	Namespace        string
	AppliedTo        string
	Priority         int
	RuleCount        int
	DefaultAction    string // allow, drop, reject
	AllowsAllTraffic bool
	RiskLevel        string
	ImageVerified    bool // True if NSX-T NCP image was verified
}

// GCPBackendPolicyInfo represents GKE Cloud Armor and backend security policies
type GCPBackendPolicyInfo struct {
	Name                      string
	Namespace                 string
	Kind                      string // GCPBackendPolicy, GCPGatewayPolicy
	TargetRef                 string
	CloudArmorPolicy          string // Cloud Armor security policy name
	HasCloudArmor             bool
	HasIAP                    bool // Identity-Aware Proxy enabled
	ConnectionDrainingTimeout int
	RiskLevel                 string
	ImageVerified             bool // True if GKE gateway controller image was verified
}

// AzureNetworkPolicyInfo represents Azure-specific network configurations
type AzureNetworkPolicyInfo struct {
	Name               string
	Namespace          string
	Kind               string // AzureIngressProhibitedTarget, AzureManagedIdentity
	TargetService      string
	ProhibitedTargets  []string
	HasManagedIdentity bool
	RiskLevel          string
	ImageVerified      bool // True if Azure CNI/network policy image was verified
}

// NetworkEngineVerification tracks which network policy engines are verified by image
type NetworkEngineVerification struct {
	Calico       bool
	Cilium       bool
	Antrea       bool
	Istio        bool
	Linkerd      bool
	AWSVPCCNI    bool
	OpenShift    bool
	Consul       bool
	Kuma         bool
	SMI          bool
	GlooMesh     bool
	NSXT         bool
	GCPGateway   bool
	AzureCNI     bool
	K8sNetPolicy bool // Native K8s NetworkPolicy (always true as it's built-in)
}

// networkEngineToSDKMapping maps local engine names to SDK engine IDs
var networkEngineToSDKMapping = map[string]string{
	"calico":     "calico",
	"cilium":     "cilium",
	"antrea":     "antrea",
	"istio":      "istio",
	"linkerd":    "linkerd",
	"awsvpccni":  "aws-vpc-cni",
	"openshift":  "openshift-project",
	"consul":     "consul",
	"kuma":       "kuma",
	"smi":        "osm",
	"gloomesh":   "gloo-mesh",
	"nsxt":       "ovn",
	"gcpgateway": "gke-netpol",
	"azurecni":   "azure-cni",
}

// verifyNetworkEngines checks for network policy engine installations by verifying container images
func verifyNetworkEngines(ctx context.Context, clientset kubernetes.Interface) NetworkEngineVerification {
	verification := NetworkEngineVerification{
		K8sNetPolicy: true, // Native K8s NetworkPolicy is always available
	}

	// Check all namespaces commonly used by network policy engines
	checkNamespaces := []string{
		"kube-system",
		"calico-system",
		"tigera-operator",
		"cilium",
		"kube-cilium",
		"antrea-system",
		"istio-system",
		"linkerd",
		"linkerd-viz",
		"consul",
		"consul-system",
		"kuma-system",
		"osm-system",
		"traefik-mesh",
		"gloo-system",
		"gloo-mesh",
		"vmware-system-nsx",
		"nsx-system",
		"gke-system",
		"azure-system",
	}

	for _, ns := range checkNamespaces {
		// Check deployments
		deps, err := clientset.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
		if err == nil {
			for _, dep := range deps.Items {
				for _, container := range dep.Spec.Template.Spec.Containers {
					checkAndSetVerification(&verification, container.Image)
				}
			}
		}

		// Check daemonsets (CNI plugins often run as daemonsets)
		dss, err := clientset.AppsV1().DaemonSets(ns).List(ctx, metav1.ListOptions{})
		if err == nil {
			for _, ds := range dss.Items {
				for _, container := range ds.Spec.Template.Spec.Containers {
					checkAndSetVerification(&verification, container.Image)
				}
			}
		}
	}

	return verification
}

// checkAndSetVerification checks if an image matches any known engine patterns
// Now uses the shared admission SDK for centralized engine detection
func checkAndSetVerification(v *NetworkEngineVerification, image string) {
	for localEngine, sdkEngine := range networkEngineToSDKMapping {
		if VerifyControllerImage(image, sdkEngine) {
			switch localEngine {
			case "calico":
				v.Calico = true
			case "cilium":
				v.Cilium = true
			case "antrea":
				v.Antrea = true
			case "istio":
				v.Istio = true
			case "linkerd":
				v.Linkerd = true
			case "awsvpccni":
				v.AWSVPCCNI = true
			case "openshift":
				v.OpenShift = true
			case "consul":
				v.Consul = true
			case "kuma":
				v.Kuma = true
			case "smi":
				v.SMI = true
			case "gloomesh":
				v.GlooMesh = true
			case "nsxt":
				v.NSXT = true
			case "gcpgateway":
				v.GCPGateway = true
			case "azurecni":
				v.AzureCNI = true
			}
			return // Found a match for this image
		}
	}
}

func ListNetworkAdmission(cmd *cobra.Command, args []string) {
	ctx, cancel := shared.ContextWithCancel()
	defer cancel()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Analyzing network admission policies for %s", globals.ClusterName), globals.K8S_NETWORK_ADMISSION_MODULE_NAME)

	clientset := config.GetClientOrExit()
	dynClient := config.GetDynamicClientOrExit()

	// Verify which network policy engines are installed by checking container images
	logger.InfoM("Verifying network policy engine installations...", globals.K8S_NETWORK_ADMISSION_MODULE_NAME)
	engineVerification := verifyNetworkEngines(ctx, clientset)

	// Suppress stderr to hide noisy auth plugin errors
	restoreStderr := sdk.SuppressStderr()

	// Get namespaces
	namespaces := shared.GetTargetNamespaces(ctx, clientset, &logger, globals.K8S_NETWORK_ADMISSION_MODULE_NAME)

	// Fetch all pods for coverage analysis
	logger.InfoM("Fetching pods...", globals.K8S_NETWORK_ADMISSION_MODULE_NAME)
	allPods := make(map[string][]corev1.Pod)
	allPodsList, err := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		shared.LogListError(&logger, "pods", "", err, globals.K8S_NETWORK_ADMISSION_MODULE_NAME, false)
	} else {
		for _, pod := range allPodsList.Items {
			allPods[pod.Namespace] = append(allPods[pod.Namespace], pod)
		}
		logger.InfoM(fmt.Sprintf("Found %d pods across all namespaces", len(allPodsList.Items)), globals.K8S_NETWORK_ADMISSION_MODULE_NAME)
	}

	// Analyze all policy engines cluster-wide first
	logger.InfoM("Analyzing Kubernetes NetworkPolicies...", globals.K8S_NETWORK_ADMISSION_MODULE_NAME)
	allK8sNetPolicies := analyzeK8sNetworkPolicies(ctx, clientset, allPods)

	logger.InfoM("Analyzing Calico policies...", globals.K8S_NETWORK_ADMISSION_MODULE_NAME)
	allCalicoPolicies, calicoGlobalPolicies := analyzeCalicoNetworkPolicies(ctx, dynClient)

	logger.InfoM("Analyzing Cilium policies...", globals.K8S_NETWORK_ADMISSION_MODULE_NAME)
	allCiliumPolicies, ciliumClusterwidePolicies := analyzeCiliumNetworkPolicies(ctx, dynClient)

	logger.InfoM("Analyzing Antrea policies...", globals.K8S_NETWORK_ADMISSION_MODULE_NAME)
	allAntreaPolicies, antreaClusterPolicies := analyzeAntreaNetworkPolicies(ctx, dynClient)

	logger.InfoM("Analyzing Istio AuthorizationPolicies...", globals.K8S_NETWORK_ADMISSION_MODULE_NAME)
	allIstioPolicies := analyzeIstioAuthorizationPolicies(ctx, dynClient)

	logger.InfoM("Analyzing Linkerd policies...", globals.K8S_NETWORK_ADMISSION_MODULE_NAME)
	allLinkerdPolicies := analyzeLinkerdPolicies(ctx, dynClient)

	logger.InfoM("Analyzing AWS SecurityGroupPolicies...", globals.K8S_NETWORK_ADMISSION_MODULE_NAME)
	allAWSSecurityGroupPolicies := analyzeAWSSecurityGroupPolicies(ctx, dynClient)

	logger.InfoM("Analyzing OpenShift EgressFirewall policies...", globals.K8S_NETWORK_ADMISSION_MODULE_NAME)
	allOpenShiftEgressPolicies := analyzeOpenShiftEgressFirewalls(ctx, dynClient)

	logger.InfoM("Analyzing Consul Connect intentions...", globals.K8S_NETWORK_ADMISSION_MODULE_NAME)
	allConsulConnectPolicies := analyzeConsulConnectIntentions(ctx, dynClient)

	logger.InfoM("Analyzing Kuma/Kong Mesh policies...", globals.K8S_NETWORK_ADMISSION_MODULE_NAME)
	allKumaMeshPolicies := analyzeKumaMeshPolicies(ctx, dynClient)

	logger.InfoM("Analyzing SMI policies (OSM/Traefik Mesh)...", globals.K8S_NETWORK_ADMISSION_MODULE_NAME)
	allSMIPolicies := analyzeSMIPolicies(ctx, dynClient)

	logger.InfoM("Analyzing Gloo Mesh policies...", globals.K8S_NETWORK_ADMISSION_MODULE_NAME)
	allGlooMeshPolicies := analyzeGlooMeshPolicies(ctx, dynClient)

	logger.InfoM("Analyzing NSX-T policies...", globals.K8S_NETWORK_ADMISSION_MODULE_NAME)
	allNSXTPolicies := analyzeNSXTPolicies(ctx, dynClient)

	logger.InfoM("Analyzing GCP/GKE backend policies...", globals.K8S_NETWORK_ADMISSION_MODULE_NAME)
	allGCPBackendPolicies := analyzeGCPBackendPolicies(ctx, dynClient)

	logger.InfoM("Analyzing Azure/AKS network policies...", globals.K8S_NETWORK_ADMISSION_MODULE_NAME)
	allAzureNetworkPolicies := analyzeAzureNetworkPolicies(ctx, dynClient)

	// Restore stderr
	restoreStderr()

	// Apply image verification status to all policies
	applyK8sNetPolicyVerification(allK8sNetPolicies, engineVerification.K8sNetPolicy)
	applyCalicoPolicyVerification(allCalicoPolicies, calicoGlobalPolicies, engineVerification.Calico)
	applyCiliumPolicyVerification(allCiliumPolicies, ciliumClusterwidePolicies, engineVerification.Cilium)
	applyAntreaPolicyVerification(allAntreaPolicies, antreaClusterPolicies, engineVerification.Antrea)
	applyIstioPolicyVerification(allIstioPolicies, engineVerification.Istio)
	applyLinkerdPolicyVerification(allLinkerdPolicies, engineVerification.Linkerd)
	applyAWSSecurityGroupPolicyVerification(allAWSSecurityGroupPolicies, engineVerification.AWSVPCCNI)
	applyOpenShiftEgressPolicyVerification(allOpenShiftEgressPolicies, engineVerification.OpenShift)
	applyConsulConnectPolicyVerification(allConsulConnectPolicies, engineVerification.Consul)
	applyKumaMeshPolicyVerification(allKumaMeshPolicies, engineVerification.Kuma)
	applySMIPolicyVerification(allSMIPolicies, engineVerification.SMI)
	applyGlooMeshPolicyVerification(allGlooMeshPolicies, engineVerification.GlooMesh)
	applyNSXTPolicyVerification(allNSXTPolicies, engineVerification.NSXT)
	applyGCPBackendPolicyVerification(allGCPBackendPolicies, engineVerification.GCPGateway)
	applyAzureNetworkPolicyVerification(allAzureNetworkPolicies, engineVerification.AzureCNI)

	// Process each namespace
	var findings []NetworkAdmissionFinding

	for _, ns := range namespaces {
		nsObj, err := clientset.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{})
		if err != nil {
			shared.LogGetError(&logger, "namespace", ns, err, globals.K8S_NETWORK_ADMISSION_MODULE_NAME, false)
			continue
		}

		finding := NetworkAdmissionFinding{
			Namespace: ns,
		}

		// Calculate age
		age := time.Since(nsObj.CreationTimestamp.Time)
		finding.Age = networkAdmissionFormatDuration(age)

		// Pod coverage
		nsPods := allPods[ns]
		finding.TotalPods = len(nsPods)

		// Get policies for this namespace
		finding.K8sNetworkPolicies = filterK8sPoliciesForNamespace(allK8sNetPolicies, ns)
		finding.CalicoPolicies = filterCalicoPoliciesForNamespace(allCalicoPolicies, calicoGlobalPolicies, ns)
		finding.CiliumPolicies = filterCiliumPoliciesForNamespace(allCiliumPolicies, ciliumClusterwidePolicies, ns)
		finding.AntreaPolicies = filterAntreaPoliciesForNamespace(allAntreaPolicies, antreaClusterPolicies, ns)
		finding.IstioPolicies = filterIstioPoliciesForNamespace(allIstioPolicies, ns)
		finding.LinkerdPolicies = filterLinkerdPoliciesForNamespace(allLinkerdPolicies, ns)
		finding.AWSSecurityGroupPols = filterAWSSecurityGroupPoliciesForNamespace(allAWSSecurityGroupPolicies, ns)
		finding.OpenShiftEgressPols = filterOpenShiftEgressPoliciesForNamespace(allOpenShiftEgressPolicies, ns)
		finding.ConsulConnectPols = filterConsulConnectPoliciesForNamespace(allConsulConnectPolicies, ns)
		finding.KumaMeshPols = filterKumaMeshPoliciesForNamespace(allKumaMeshPolicies, ns)
		finding.SMIPolicies = filterSMIPoliciesForNamespace(allSMIPolicies, ns)
		finding.GlooMeshPols = filterGlooMeshPoliciesForNamespace(allGlooMeshPolicies, ns)
		finding.NSXTPolicies = filterNSXTPoliciesForNamespace(allNSXTPolicies, ns)
		finding.GCPBackendPols = filterGCPBackendPoliciesForNamespace(allGCPBackendPolicies, ns)
		finding.AzureNetworkPols = filterAzureNetworkPoliciesForNamespace(allAzureNetworkPolicies, ns)

		// Counts
		finding.K8sNetworkPolicyCount = len(finding.K8sNetworkPolicies)
		finding.CalicoCount = len(finding.CalicoPolicies)
		finding.CiliumCount = len(finding.CiliumPolicies)
		finding.AntreaCount = len(finding.AntreaPolicies)
		finding.IstioCount = len(finding.IstioPolicies)
		finding.LinkerdCount = len(finding.LinkerdPolicies)
		finding.AWSSecurityGroupCount = len(finding.AWSSecurityGroupPols)
		finding.OpenShiftEgressCount = len(finding.OpenShiftEgressPols)
		finding.ConsulConnectCount = len(finding.ConsulConnectPols)
		finding.KumaMeshCount = len(finding.KumaMeshPols)
		finding.SMICount = len(finding.SMIPolicies)
		finding.GlooMeshCount = len(finding.GlooMeshPols)
		finding.NSXTCount = len(finding.NSXTPolicies)
		finding.GCPBackendCount = len(finding.GCPBackendPols)
		finding.AzureNetworkCount = len(finding.AzureNetworkPols)

		finding.PolicyCount = finding.K8sNetworkPolicyCount + finding.CalicoCount +
			finding.CiliumCount + finding.AntreaCount + finding.IstioCount + finding.LinkerdCount +
			finding.AWSSecurityGroupCount + finding.OpenShiftEgressCount + finding.ConsulConnectCount +
			finding.KumaMeshCount + finding.SMICount + finding.GlooMeshCount + finding.NSXTCount +
			finding.GCPBackendCount + finding.AzureNetworkCount
		finding.HasNetworkPolicy = finding.PolicyCount > 0

		// Calculate covered pods
		finding.CoveredPods = calculateNetworkPolicyCoverage(nsPods, finding.K8sNetworkPolicies)
		finding.UncoveredPods = finding.TotalPods - finding.CoveredPods

		// Analyze default deny status
		for _, p := range finding.K8sNetworkPolicies {
			if p.DefaultDenyIngress {
				finding.HasDefaultDenyIngress = true
				finding.DefaultDenyPolicies = append(finding.DefaultDenyPolicies, "K8s:"+p.Name)
			}
			if p.DefaultDenyEgress {
				finding.HasDefaultDenyEgress = true
				finding.DefaultDenyPolicies = append(finding.DefaultDenyPolicies, "K8s:"+p.Name)
			}
		}
		for _, p := range finding.CalicoPolicies {
			if p.IsDefaultDeny {
				if contains(p.Types, "ingress") || contains(p.Types, "Ingress") {
					finding.HasDefaultDenyIngress = true
				}
				if contains(p.Types, "egress") || contains(p.Types, "Egress") {
					finding.HasDefaultDenyEgress = true
				}
				prefix := "Calico:"
				if p.IsGlobal {
					prefix = "CalicoGlobal:"
				}
				finding.DefaultDenyPolicies = append(finding.DefaultDenyPolicies, prefix+p.Name)
			}
		}
		for _, p := range finding.CiliumPolicies {
			if p.IsDefaultDeny {
				prefix := "Cilium:"
				if p.IsClusterwide {
					prefix = "CiliumCW:"
				}
				finding.DefaultDenyPolicies = append(finding.DefaultDenyPolicies, prefix+p.Name)
				finding.HasDefaultDenyIngress = true
				finding.HasDefaultDenyEgress = true
			}
		}
		for _, p := range finding.AntreaPolicies {
			if p.IsDefaultDeny {
				prefix := "Antrea:"
				if p.IsCluster {
					prefix = "AntreaCNP:"
				}
				finding.DefaultDenyPolicies = append(finding.DefaultDenyPolicies, prefix+p.Name)
				finding.HasDefaultDenyIngress = true
				finding.HasDefaultDenyEgress = true
			}
		}

		// Detect policy engine blocking
		finding.PolicyEngineBlocks = detectNetworkPolicyEngineBlocking(
			finding.K8sNetworkPolicies,
			finding.CalicoPolicies,
			finding.CiliumPolicies,
			finding.AntreaPolicies,
			finding.IstioPolicies,
			finding.AWSSecurityGroupPols,
			finding.OpenShiftEgressPols,
			finding.ConsulConnectPols,
			finding.KumaMeshPols,
			finding.SMIPolicies,
			finding.GlooMeshPols,
			finding.NSXTPolicies,
			finding.GCPBackendPols,
			finding.AzureNetworkPols,
		)

		// Determine what's allowed (if not blocked by any policy)
		finding.AllowsInternetIngress = !finding.PolicyEngineBlocks.InternetIngressBlocked && !finding.HasDefaultDenyIngress
		finding.AllowsInternetEgress = !finding.PolicyEngineBlocks.InternetEgressBlocked && !finding.HasDefaultDenyEgress
		finding.AllowsCrossNSIngress = !finding.PolicyEngineBlocks.CrossNSIngressBlocked && !finding.HasDefaultDenyIngress
		finding.AllowsCrossNSEgress = !finding.PolicyEngineBlocks.CrossNSEgressBlocked && !finding.HasDefaultDenyEgress
		finding.AllowsMetadataAPI = !finding.PolicyEngineBlocks.MetadataAPIBlocked && !finding.HasDefaultDenyEgress
		finding.AllowsDNSEgress = !finding.PolicyEngineBlocks.DNSEgressRestricted
		finding.AllowsAllPodsIngress = !finding.HasDefaultDenyIngress
		finding.AllowsAllPodsEgress = !finding.HasDefaultDenyEgress
		finding.AllowsKubeAPIEgress = !finding.PolicyEngineBlocks.KubeAPIEgressBlocked && !finding.HasDefaultDenyEgress

		// If no policies at all, everything is allowed
		if !finding.HasNetworkPolicy {
			finding.AllowsInternetIngress = true
			finding.AllowsInternetEgress = true
			finding.AllowsCrossNSIngress = true
			finding.AllowsCrossNSEgress = true
			finding.AllowsMetadataAPI = true
			finding.AllowsDNSEgress = true
			finding.AllowsAllPodsIngress = true
			finding.AllowsAllPodsEgress = true
			finding.AllowsKubeAPIEgress = true
		}

		// Risk scoring
		finding.RiskLevel = calculateNetworkAdmissionRiskLevel(finding)

		// Recommendations
		finding.Recommendations = generateNetworkAdmissionRecommendations(finding)

		findings = append(findings, finding)
	}

	// Generate output tables

	// Main namespace summary table
	headers := []string{
		"Namespace",
		"Policies",
		"Pods Covered",
		"Default Deny",
		"Internet In",
		"Internet Out",
		"Metadata API",
		"Cross-NS",
		"Kube API",
		"Policy Engines",
		"Age",
	}

	// K8s NetworkPolicy detail table
	k8sNetPolHeaders := []string{
		"Namespace",
		"Name",
		"Pod Selector",
		"Ingress Rules",
		"Egress Rules",
		"Default Deny",
		"Internet In",
		"Internet Out",
		"Cross-NS",
		"Metadata",
		"Covered Pods",
	}

	// Calico policy detail table
	calicoHeaders := []string{
		"Namespace",
		"Name",
		"Scope",
		"Selector",
		"Order",
		"Ingress Rules",
		"Egress Rules",
		"Default Deny",
		"Internet In",
		"Internet Out",
	}

	// Cilium policy detail table
	ciliumHeaders := []string{
		"Namespace",
		"Name",
		"Scope",
		"Endpoint Selector",
		"Ingress Rules",
		"Egress Rules",
		"L7 Rules",
		"Default Deny",
		"Internet In",
		"Internet Out",
	}

	// Antrea policy detail table
	antreaHeaders := []string{
		"Namespace",
		"Name",
		"Scope",
		"Tier",
		"Priority",
		"Applied To",
		"Ingress Rules",
		"Egress Rules",
		"Action",
	}

	// Istio policy detail table
	istioHeaders := []string{
		"Namespace",
		"Name",
		"Action",
		"Selector",
		"Rules",
		"mTLS",
	}

	// Linkerd policy detail table
	linkerdHeaders := []string{
		"Namespace",
		"Name",
		"Kind",
		"Selector",
	}

	// AWS SecurityGroupPolicy detail table
	awsSGHeaders := []string{
		"Namespace",
		"Name",
		"Pod Selector",
		"Security Groups",
		"Allows All",
	}

	// OpenShift EgressFirewall detail table
	openshiftEgressHeaders := []string{
		"Namespace",
		"Name",
		"Kind",
		"Rules",
		"Allows Internet",
		"Denies Metadata",
	}

	// Consul Connect detail table
	consulHeaders := []string{
		"Namespace",
		"Name",
		"Destination",
		"Action",
		"Sources",
		"Allows All",
	}

	// Kuma Mesh detail table
	kumaHeaders := []string{
		"Namespace",
		"Name",
		"Kind",
		"Target",
		"Action",
		"Rules",
	}

	// SMI detail table
	smiHeaders := []string{
		"Namespace",
		"Name",
		"Kind",
		"Provider",
		"Destination",
		"Allows All",
	}

	// Gloo Mesh detail table
	glooHeaders := []string{
		"Namespace",
		"Name",
		"Kind",
		"Apply To",
		"Action",
		"Rules",
	}

	// NSX-T detail table
	nsxtHeaders := []string{
		"Namespace",
		"Name",
		"Applied To",
		"Priority",
		"Rules",
		"Default Action",
	}

	// GCP Backend Policy detail table
	gcpHeaders := []string{
		"Namespace",
		"Name",
		"Kind",
		"Target",
		"Cloud Armor",
		"IAP Enabled",
	}

	// Azure Network Policy detail table
	azureHeaders := []string{
		"Namespace",
		"Name",
		"Kind",
		"Target",
		"Managed Identity",
	}

	var outputRows [][]string
	var k8sNetPolRows [][]string
	var calicoRows [][]string
	var ciliumRows [][]string
	var antreaRows [][]string
	var istioRows [][]string
	var linkerdRows [][]string
	var awsSGRows [][]string
	var openshiftEgressRows [][]string
	var consulRows [][]string
	var kumaRows [][]string
	var smiRows [][]string
	var glooRows [][]string
	var nsxtRows [][]string
	var gcpRows [][]string
	var azureRows [][]string

	loot := shared.NewLootBuilder()

	// Initialize loot sections
	loot.Section("Network-Admission-Enum").SetHeader(`#####################################
##### Network Admission Enumeration
#####################################
#
# Network policies control pod-to-pod and pod-to-external traffic
# Multiple policy engines can be active simultaneously
#
# Policy Engines Detected:
# - Kubernetes NetworkPolicy (native)
# - Calico NetworkPolicy/GlobalNetworkPolicy
# - Cilium CiliumNetworkPolicy/CiliumClusterwideNetworkPolicy
# - Antrea NetworkPolicy/ClusterNetworkPolicy
# - Istio AuthorizationPolicy
# - Linkerd Server/ServerAuthorization
# - AWS VPC CNI SecurityGroupPolicy
# - OpenShift EgressFirewall/EgressNetworkPolicy
# - HashiCorp Consul Connect ServiceIntentions
# - Kuma/Kong MeshTrafficPermission
# - SMI TrafficTarget (OSM, Traefik Mesh)
# - Gloo Mesh AccessPolicy/TrafficPolicy
# - VMware NSX-T SecurityPolicy
# - GCP/GKE GCPBackendPolicy (Cloud Armor)
# - Azure/AKS network configurations
#`)

	loot.Section("Network-Admission-Default-Deny").SetHeader(`#####################################
##### Default-Deny Recommendations
#####################################
#
# SECURITY BEST PRACTICE: Implement default-deny policies
# Namespaces without default-deny allow unrestricted traffic
#`)

	loot.Section("Network-Admission-Lateral-Movement").SetHeader(`#####################################
##### Lateral Movement Analysis
#####################################
#
# Namespaces where lateral movement is possible due to:
# - Missing network policies
# - Permissive cross-namespace access
# - No default-deny policies
#`)

	loot.Section("Network-Admission-Data-Exfil").SetHeader(`#####################################
##### Data Exfiltration Risks
#####################################
#
# Egress policies that allow potential data exfiltration:
# - Internet egress allowed
# - Metadata API access (169.254.169.254)
# - Unrestricted DNS egress
#`)

	loot.Section("Network-Admission-Policy-Enumeration").SetHeader(`#####################################
##### Network Policy Enumeration Commands
#####################################
#
# Commands to enumerate all network policies across the cluster
# Run these commands to get a complete view of network controls
#`)

	if globals.KubeContext != "" {
		loot.Section("Network-Admission-Enum").Addf("kubectl config use-context %s\n", globals.KubeContext)
	}

	for _, finding := range findings {
		// Build policy engines string
		var policyEngines []string
		if finding.K8sNetworkPolicyCount > 0 {
			policyEngines = append(policyEngines, fmt.Sprintf("K8s (%d)", finding.K8sNetworkPolicyCount))
		}
		if finding.CalicoCount > 0 {
			policyEngines = append(policyEngines, fmt.Sprintf("Calico (%d)", finding.CalicoCount))
		}
		if finding.CiliumCount > 0 {
			policyEngines = append(policyEngines, fmt.Sprintf("Cilium (%d)", finding.CiliumCount))
		}
		if finding.AntreaCount > 0 {
			policyEngines = append(policyEngines, fmt.Sprintf("Antrea (%d)", finding.AntreaCount))
		}
		if finding.IstioCount > 0 {
			policyEngines = append(policyEngines, fmt.Sprintf("Istio (%d)", finding.IstioCount))
		}
		if finding.LinkerdCount > 0 {
			policyEngines = append(policyEngines, fmt.Sprintf("Linkerd (%d)", finding.LinkerdCount))
		}
		if finding.AWSSecurityGroupCount > 0 {
			policyEngines = append(policyEngines, fmt.Sprintf("AWS-SG (%d)", finding.AWSSecurityGroupCount))
		}
		if finding.OpenShiftEgressCount > 0 {
			policyEngines = append(policyEngines, fmt.Sprintf("OCP-Egress (%d)", finding.OpenShiftEgressCount))
		}
		if finding.ConsulConnectCount > 0 {
			policyEngines = append(policyEngines, fmt.Sprintf("Consul (%d)", finding.ConsulConnectCount))
		}
		if finding.KumaMeshCount > 0 {
			policyEngines = append(policyEngines, fmt.Sprintf("Kuma (%d)", finding.KumaMeshCount))
		}
		if finding.SMICount > 0 {
			policyEngines = append(policyEngines, fmt.Sprintf("SMI (%d)", finding.SMICount))
		}
		if finding.GlooMeshCount > 0 {
			policyEngines = append(policyEngines, fmt.Sprintf("Gloo (%d)", finding.GlooMeshCount))
		}
		if finding.NSXTCount > 0 {
			policyEngines = append(policyEngines, fmt.Sprintf("NSX-T (%d)", finding.NSXTCount))
		}
		if finding.GCPBackendCount > 0 {
			policyEngines = append(policyEngines, fmt.Sprintf("GCP (%d)", finding.GCPBackendCount))
		}
		if finding.AzureNetworkCount > 0 {
			policyEngines = append(policyEngines, fmt.Sprintf("Azure (%d)", finding.AzureNetworkCount))
		}
		policyEnginesStr := "<NONE>"
		if len(policyEngines) > 0 {
			policyEnginesStr = strings.Join(policyEngines, ", ")
		}

		// Default deny column
		defaultDenyStr := "No"
		if finding.HasDefaultDenyIngress && finding.HasDefaultDenyEgress {
			defaultDenyStr = "Yes (In+Out)"
		} else if finding.HasDefaultDenyIngress {
			defaultDenyStr = "Ingress Only"
		} else if finding.HasDefaultDenyEgress {
			defaultDenyStr = "Egress Only"
		}

		// Internet In column
		internetInStr := "Yes"
		if finding.PolicyEngineBlocks.InternetIngressBlocked {
			internetInStr = "Blocked by " + strings.Join(finding.PolicyEngineBlocks.InternetIngressBlockedBy, ", ")
		} else if finding.HasDefaultDenyIngress {
			internetInStr = "Blocked (default-deny)"
		}

		// Internet Out column
		internetOutStr := "Yes"
		if finding.PolicyEngineBlocks.InternetEgressBlocked {
			internetOutStr = "Blocked by " + strings.Join(finding.PolicyEngineBlocks.InternetEgressBlockedBy, ", ")
		} else if finding.HasDefaultDenyEgress {
			internetOutStr = "Blocked (default-deny)"
		}

		// Metadata API column
		metadataStr := "Yes"
		if finding.PolicyEngineBlocks.MetadataAPIBlocked {
			metadataStr = "Blocked by " + strings.Join(finding.PolicyEngineBlocks.MetadataAPIBlockedBy, ", ")
		} else if finding.HasDefaultDenyEgress {
			metadataStr = "Blocked (default-deny)"
		}

		// Cross-NS column
		crossNSStr := "Yes"
		if finding.PolicyEngineBlocks.CrossNSIngressBlocked && finding.PolicyEngineBlocks.CrossNSEgressBlocked {
			crossNSStr = "Blocked (In+Out)"
		} else if finding.PolicyEngineBlocks.CrossNSIngressBlocked {
			crossNSStr = "Blocked (In)"
		} else if finding.PolicyEngineBlocks.CrossNSEgressBlocked {
			crossNSStr = "Blocked (Out)"
		} else if finding.HasDefaultDenyIngress && finding.HasDefaultDenyEgress {
			crossNSStr = "Blocked (default-deny)"
		}

		// Kube API column
		kubeAPIStr := "Yes"
		if finding.PolicyEngineBlocks.KubeAPIEgressBlocked {
			kubeAPIStr = "Blocked by " + strings.Join(finding.PolicyEngineBlocks.KubeAPIEgressBlockedBy, ", ")
		} else if finding.HasDefaultDenyEgress {
			kubeAPIStr = "Blocked (default-deny)"
		}

		// Pods covered
		podsCoveredStr := fmt.Sprintf("%d/%d", finding.CoveredPods, finding.TotalPods)
		if finding.TotalPods == 0 {
			podsCoveredStr = "0/0"
		} else if !finding.HasNetworkPolicy {
			podsCoveredStr = fmt.Sprintf("0/%d (no policy)", finding.TotalPods)
		}

		outputRows = append(outputRows, []string{
			finding.Namespace,
			fmt.Sprintf("%d", finding.PolicyCount),
			podsCoveredStr,
			defaultDenyStr,
			internetInStr,
			internetOutStr,
			metadataStr,
			crossNSStr,
			kubeAPIStr,
			policyEnginesStr,
			finding.Age,
		})

		// Generate loot
		generateNetworkAdmissionLoot(&finding, loot)
	}

	// Generate detail rows for each policy type
	for _, policies := range allK8sNetPolicies {
		for _, p := range policies {
			defaultDenyStr := "No"
			if p.DefaultDenyIngress && p.DefaultDenyEgress {
				defaultDenyStr = "Yes (In+Out)"
			} else if p.DefaultDenyIngress {
				defaultDenyStr = "Ingress"
			} else if p.DefaultDenyEgress {
				defaultDenyStr = "Egress"
			}

			k8sNetPolRows = append(k8sNetPolRows, []string{
				p.Namespace,
				p.Name,
				p.PodSelector,
				fmt.Sprintf("%d", p.IngressRuleCount),
				fmt.Sprintf("%d", p.EgressRuleCount),
				defaultDenyStr,
				shared.FormatBool(p.AllowsInternetIngress),
				shared.FormatBool(p.AllowsInternetEgress),
				shared.FormatBool(p.AllowsCrossNS),
				shared.FormatBool(p.AllowsMetadataAPI),
				fmt.Sprintf("%d", p.CoveredPods),
			})
		}
	}

	// Calico rows
	for _, policies := range allCalicoPolicies {
		for _, p := range policies {
			scope := "Namespace"
			ns := p.Namespace
			if p.IsGlobal {
				scope = "Global"
				ns = "<CLUSTER>"
			}
			calicoRows = append(calicoRows, []string{
				ns,
				p.Name,
				scope,
				p.Selector,
				fmt.Sprintf("%.0f", p.Order),
				fmt.Sprintf("%d", p.IngressRuleCount),
				fmt.Sprintf("%d", p.EgressRuleCount),
				shared.FormatBool(p.IsDefaultDeny),
				shared.FormatBool(p.AllowsInternetIngress),
				shared.FormatBool(p.AllowsInternetEgress),
			})
		}
	}
	for _, p := range calicoGlobalPolicies {
		calicoRows = append(calicoRows, []string{
			"<CLUSTER>",
			p.Name,
			"Global",
			p.Selector,
			fmt.Sprintf("%.0f", p.Order),
			fmt.Sprintf("%d", p.IngressRuleCount),
			fmt.Sprintf("%d", p.EgressRuleCount),
			shared.FormatBool(p.IsDefaultDeny),
			shared.FormatBool(p.AllowsInternetIngress),
			shared.FormatBool(p.AllowsInternetEgress),
		})
	}

	// Cilium rows
	for _, policies := range allCiliumPolicies {
		for _, p := range policies {
			scope := "Namespace"
			ns := p.Namespace
			if p.IsClusterwide {
				scope = "Clusterwide"
				ns = "<CLUSTER>"
			}
			l7Str := "-"
			if p.HasL7Rules {
				l7Str = strings.Join(p.L7Protocols, ",")
			}
			ciliumRows = append(ciliumRows, []string{
				ns,
				p.Name,
				scope,
				p.EndpointSelector,
				fmt.Sprintf("%d", p.IngressRuleCount),
				fmt.Sprintf("%d", p.EgressRuleCount),
				l7Str,
				shared.FormatBool(p.IsDefaultDeny),
				shared.FormatBool(p.AllowsInternetIngress),
				shared.FormatBool(p.AllowsInternetEgress),
			})
		}
	}
	for _, p := range ciliumClusterwidePolicies {
		l7Str := "-"
		if p.HasL7Rules {
			l7Str = strings.Join(p.L7Protocols, ",")
		}
		ciliumRows = append(ciliumRows, []string{
			"<CLUSTER>",
			p.Name,
			"Clusterwide",
			p.EndpointSelector,
			fmt.Sprintf("%d", p.IngressRuleCount),
			fmt.Sprintf("%d", p.EgressRuleCount),
			l7Str,
			shared.FormatBool(p.IsDefaultDeny),
			shared.FormatBool(p.AllowsInternetIngress),
			shared.FormatBool(p.AllowsInternetEgress),
		})
	}

	// Antrea rows
	for _, policies := range allAntreaPolicies {
		for _, p := range policies {
			scope := "Namespace"
			ns := p.Namespace
			if p.IsCluster {
				scope = "Cluster"
				ns = "<CLUSTER>"
			}
			antreaRows = append(antreaRows, []string{
				ns,
				p.Name,
				scope,
				p.Tier,
				fmt.Sprintf("%.0f", p.Priority),
				p.AppliedTo,
				fmt.Sprintf("%d", p.IngressRuleCount),
				fmt.Sprintf("%d", p.EgressRuleCount),
				p.Action,
			})
		}
	}
	for _, p := range antreaClusterPolicies {
		antreaRows = append(antreaRows, []string{
			"<CLUSTER>",
			p.Name,
			"Cluster",
			p.Tier,
			fmt.Sprintf("%.0f", p.Priority),
			p.AppliedTo,
			fmt.Sprintf("%d", p.IngressRuleCount),
			fmt.Sprintf("%d", p.EgressRuleCount),
			p.Action,
		})
	}

	// Istio rows
	for _, policies := range allIstioPolicies {
		for _, p := range policies {
			istioRows = append(istioRows, []string{
				p.Namespace,
				p.Name,
				p.Action,
				p.Selector,
				fmt.Sprintf("%d", p.Rules),
				shared.FormatBool(p.HasMTLS),
			})
		}
	}

	// Linkerd rows
	for _, policies := range allLinkerdPolicies {
		for _, p := range policies {
			linkerdRows = append(linkerdRows, []string{
				p.Namespace,
				p.Name,
				p.Kind,
				p.Selector,
			})
		}
	}

	// AWS SecurityGroupPolicy rows
	for _, policies := range allAWSSecurityGroupPolicies {
		for _, p := range policies {
			awsSGRows = append(awsSGRows, []string{
				p.Namespace,
				p.Name,
				p.PodSelector,
				strings.Join(p.SecurityGroupIDs, ", "),
				shared.FormatBool(p.AllowsAllTraffic),
			})
		}
	}

	// OpenShift EgressFirewall rows
	for _, policies := range allOpenShiftEgressPolicies {
		for _, p := range policies {
			openshiftEgressRows = append(openshiftEgressRows, []string{
				p.Namespace,
				p.Name,
				p.Kind,
				fmt.Sprintf("%d", p.RuleCount),
				shared.FormatBool(p.AllowsInternet),
				shared.FormatBool(p.DeniesMetadataAPI),
			})
		}
	}

	// Consul Connect rows
	for _, policies := range allConsulConnectPolicies {
		for _, p := range policies {
			consulRows = append(consulRows, []string{
				p.Namespace,
				p.Name,
				p.Destination,
				p.Action,
				fmt.Sprintf("%d", p.SourceCount),
				shared.FormatBool(p.AllowsAllSources),
			})
		}
	}

	// Kuma Mesh rows
	for _, policies := range allKumaMeshPolicies {
		for _, p := range policies {
			kumaRows = append(kumaRows, []string{
				p.Namespace,
				p.Name,
				p.Kind,
				p.TargetRef,
				p.Action,
				fmt.Sprintf("%d", p.RuleCount),
			})
		}
	}

	// SMI rows
	for _, policies := range allSMIPolicies {
		for _, p := range policies {
			smiRows = append(smiRows, []string{
				p.Namespace,
				p.Name,
				p.Kind,
				p.MeshProvider,
				p.DestinationService,
				shared.FormatBool(p.AllowsAllSources),
			})
		}
	}

	// Gloo Mesh rows
	for _, policies := range allGlooMeshPolicies {
		for _, p := range policies {
			glooRows = append(glooRows, []string{
				p.Namespace,
				p.Name,
				p.Kind,
				p.ApplyToRefs,
				p.Action,
				fmt.Sprintf("%d", p.RuleCount),
			})
		}
	}

	// NSX-T rows
	for _, policies := range allNSXTPolicies {
		for _, p := range policies {
			nsxtRows = append(nsxtRows, []string{
				p.Namespace,
				p.Name,
				p.AppliedTo,
				fmt.Sprintf("%d", p.Priority),
				fmt.Sprintf("%d", p.RuleCount),
				p.DefaultAction,
			})
		}
	}

	// GCP Backend Policy rows
	for _, policies := range allGCPBackendPolicies {
		for _, p := range policies {
			gcpRows = append(gcpRows, []string{
				p.Namespace,
				p.Name,
				p.Kind,
				p.TargetRef,
				p.CloudArmorPolicy,
				shared.FormatBool(p.HasIAP),
			})
		}
	}

	// Azure Network Policy rows
	for _, policies := range allAzureNetworkPolicies {
		for _, p := range policies {
			azureRows = append(azureRows, []string{
				p.Namespace,
				p.Name,
				p.Kind,
				p.TargetService,
				shared.FormatBool(p.HasManagedIdentity),
			})
		}
	}

	// Sort by namespace
	sort.SliceStable(outputRows, func(i, j int) bool {
		return outputRows[i][0] < outputRows[j][0]
	})

	// Build tables
	tables := []internal.TableFile{
		{
			Name:   "Network-Admission-Namespaces",
			Header: headers,
			Body:   outputRows,
		},
	}

	if len(k8sNetPolRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Network-Admission-K8s-Policies",
			Header: k8sNetPolHeaders,
			Body:   k8sNetPolRows,
		})
	}

	if len(calicoRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Network-Admission-Calico",
			Header: calicoHeaders,
			Body:   calicoRows,
		})
	}

	if len(ciliumRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Network-Admission-Cilium",
			Header: ciliumHeaders,
			Body:   ciliumRows,
		})
	}

	if len(antreaRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Network-Admission-Antrea",
			Header: antreaHeaders,
			Body:   antreaRows,
		})
	}

	if len(istioRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Network-Admission-Istio",
			Header: istioHeaders,
			Body:   istioRows,
		})
	}

	if len(linkerdRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Network-Admission-Linkerd",
			Header: linkerdHeaders,
			Body:   linkerdRows,
		})
	}

	if len(awsSGRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Network-Admission-AWS-SecurityGroup",
			Header: awsSGHeaders,
			Body:   awsSGRows,
		})
	}

	if len(openshiftEgressRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Network-Admission-OpenShift-Egress",
			Header: openshiftEgressHeaders,
			Body:   openshiftEgressRows,
		})
	}

	if len(consulRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Network-Admission-Consul-Connect",
			Header: consulHeaders,
			Body:   consulRows,
		})
	}

	if len(kumaRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Network-Admission-Kuma-Mesh",
			Header: kumaHeaders,
			Body:   kumaRows,
		})
	}

	if len(smiRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Network-Admission-SMI",
			Header: smiHeaders,
			Body:   smiRows,
		})
	}

	if len(glooRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Network-Admission-Gloo-Mesh",
			Header: glooHeaders,
			Body:   glooRows,
		})
	}

	if len(nsxtRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Network-Admission-NSX-T",
			Header: nsxtHeaders,
			Body:   nsxtRows,
		})
	}

	if len(gcpRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Network-Admission-GCP",
			Header: gcpHeaders,
			Body:   gcpRows,
		})
	}

	if len(azureRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Network-Admission-Azure",
			Header: azureHeaders,
			Body:   azureRows,
		})
	}

	// Generate comprehensive policy enumeration commands
	generateNetworkPolicyEnumerationLoot(findings, loot)

	lootFiles := loot.Build()

	err = internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"Network-Admission",
		globals.ClusterName,
		"results",
		NetworkAdmissionOutput{
			Table: tables,
			Loot:  lootFiles,
		},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_NETWORK_ADMISSION_MODULE_NAME)
		return
	}

	// Summary stats
	noPolicyCount := 0
	noDefaultDenyCount := 0
	for _, f := range findings {
		if !f.HasNetworkPolicy {
			noPolicyCount++
		}
		if !f.HasDefaultDenyIngress && !f.HasDefaultDenyEgress {
			noDefaultDenyCount++
		}
	}

	logger.InfoM(fmt.Sprintf("%d namespaces analyzed (%d without policies, %d without default-deny)",
		len(findings), noPolicyCount, noDefaultDenyCount), globals.K8S_NETWORK_ADMISSION_MODULE_NAME)

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_NETWORK_ADMISSION_MODULE_NAME), globals.K8S_NETWORK_ADMISSION_MODULE_NAME)
}

// ============================================================================
// Policy Analysis Functions
// ============================================================================

func analyzeK8sNetworkPolicies(ctx context.Context, clientset *kubernetes.Clientset, allPods map[string][]corev1.Pod) map[string][]K8sNetworkPolicyInfo {
	result := make(map[string][]K8sNetworkPolicyInfo)

	policies, err := clientset.NetworkingV1().NetworkPolicies("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return result
	}

	for _, np := range policies.Items {
		info := K8sNetworkPolicyInfo{
			Name:             np.Name,
			Namespace:        np.Namespace,
			PodSelector:      formatK8sLabelSelector(&np.Spec.PodSelector),
			IngressRuleCount: len(np.Spec.Ingress),
			EgressRuleCount:  len(np.Spec.Egress),
		}

		for _, pt := range np.Spec.PolicyTypes {
			info.PolicyTypes = append(info.PolicyTypes, string(pt))
		}

		// Check for default deny
		if isEmptyK8sSelector(&np.Spec.PodSelector) {
			for _, pt := range np.Spec.PolicyTypes {
				if pt == netv1.PolicyTypeIngress && len(np.Spec.Ingress) == 0 {
					info.DefaultDenyIngress = true
					info.IsDefaultDeny = true
				}
				if pt == netv1.PolicyTypeEgress && len(np.Spec.Egress) == 0 {
					info.DefaultDenyEgress = true
					info.IsDefaultDeny = true
				}
			}
		}

		// Analyze ingress rules
		for _, rule := range np.Spec.Ingress {
			if len(rule.From) == 0 {
				info.AllowsInternetIngress = true // Empty from = allow all
			}
			for _, from := range rule.From {
				if from.IPBlock != nil && (from.IPBlock.CIDR == "0.0.0.0/0" || from.IPBlock.CIDR == "::/0") {
					info.AllowsInternetIngress = true
				}
				if from.NamespaceSelector != nil && len(from.NamespaceSelector.MatchLabels) == 0 {
					info.AllowsCrossNS = true
				}
			}
		}

		// Analyze egress rules
		for _, rule := range np.Spec.Egress {
			if len(rule.To) == 0 {
				info.AllowsInternetEgress = true // Empty to = allow all
			}
			for _, to := range rule.To {
				if to.IPBlock != nil && (to.IPBlock.CIDR == "0.0.0.0/0" || to.IPBlock.CIDR == "::/0") {
					info.AllowsInternetEgress = true
				}
				if to.IPBlock != nil && strings.HasPrefix(to.IPBlock.CIDR, "169.254.") {
					info.AllowsMetadataAPI = true
				}
				if to.NamespaceSelector != nil && len(to.NamespaceSelector.MatchLabels) == 0 {
					info.AllowsCrossNS = true
				}
			}
		}

		// Calculate covered pods
		if pods, ok := allPods[np.Namespace]; ok {
			info.CoveredPods = countMatchingPods(pods, &np.Spec.PodSelector)
		}

		// Risk level
		info.RiskLevel = calculateK8sNetworkPolicyRisk(info)

		result[np.Namespace] = append(result[np.Namespace], info)
	}

	return result
}

func analyzeCalicoNetworkPolicies(ctx context.Context, dynClient dynamic.Interface) (map[string][]CalicoNetworkPolicyInfo, []CalicoNetworkPolicyInfo) {
	nsPolicies := make(map[string][]CalicoNetworkPolicyInfo)
	var globalPolicies []CalicoNetworkPolicyInfo

	// Namespace-scoped NetworkPolicy
	gvr := schema.GroupVersionResource{Group: "projectcalico.org", Version: "v3", Resource: "networkpolicies"}
	list, err := dynClient.Resource(gvr).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range list.Items {
			info := parseCalicoPolicy(item.Object, false)
			nsPolicies[info.Namespace] = append(nsPolicies[info.Namespace], info)
		}
	}

	// Also try crd.projectcalico.org
	gvr2 := schema.GroupVersionResource{Group: "crd.projectcalico.org", Version: "v1", Resource: "networkpolicies"}
	list2, err := dynClient.Resource(gvr2).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range list2.Items {
			info := parseCalicoPolicy(item.Object, false)
			nsPolicies[info.Namespace] = append(nsPolicies[info.Namespace], info)
		}
	}

	// GlobalNetworkPolicy
	gvrGlobal := schema.GroupVersionResource{Group: "projectcalico.org", Version: "v3", Resource: "globalnetworkpolicies"}
	globalList, err := dynClient.Resource(gvrGlobal).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range globalList.Items {
			info := parseCalicoPolicy(item.Object, true)
			globalPolicies = append(globalPolicies, info)
		}
	}

	// Also try crd.projectcalico.org
	gvrGlobal2 := schema.GroupVersionResource{Group: "crd.projectcalico.org", Version: "v1", Resource: "globalnetworkpolicies"}
	globalList2, err := dynClient.Resource(gvrGlobal2).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range globalList2.Items {
			info := parseCalicoPolicy(item.Object, true)
			globalPolicies = append(globalPolicies, info)
		}
	}

	return nsPolicies, globalPolicies
}

func parseCalicoPolicy(obj map[string]interface{}, isGlobal bool) CalicoNetworkPolicyInfo {
	info := CalicoNetworkPolicyInfo{
		IsGlobal: isGlobal,
	}

	if metadata, ok := obj["metadata"].(map[string]interface{}); ok {
		info.Name, _ = metadata["name"].(string)
		info.Namespace, _ = metadata["namespace"].(string)
	}

	if spec, ok := obj["spec"].(map[string]interface{}); ok {
		info.Selector, _ = spec["selector"].(string)
		if order, ok := spec["order"].(float64); ok {
			info.Order = order
		}

		if ingress, ok := spec["ingress"].([]interface{}); ok {
			info.IngressRuleCount = len(ingress)
			info.Types = append(info.Types, "Ingress")
			info.AllowsInternetIngress = checkCalicoInternetAccess(ingress)
		}

		if egress, ok := spec["egress"].([]interface{}); ok {
			info.EgressRuleCount = len(egress)
			info.Types = append(info.Types, "Egress")
			info.AllowsInternetEgress = checkCalicoInternetAccess(egress)
			info.AllowsMetadataAPI = checkCalicoMetadataAccess(egress)
		}

		// Check for default deny (empty selector with no rules or deny action)
		if info.Selector == "all()" || info.Selector == "" {
			if info.IngressRuleCount == 0 || info.EgressRuleCount == 0 {
				info.IsDefaultDeny = true
			}
		}
	}

	return info
}

func checkCalicoInternetAccess(rules []interface{}) bool {
	for _, r := range rules {
		if rule, ok := r.(map[string]interface{}); ok {
			if nets, ok := rule["source"].(map[string]interface{})["nets"].([]interface{}); ok {
				for _, net := range nets {
					if netStr, ok := net.(string); ok {
						if netStr == "0.0.0.0/0" || netStr == "::/0" {
							return true
						}
					}
				}
			}
			if nets, ok := rule["destination"].(map[string]interface{})["nets"].([]interface{}); ok {
				for _, net := range nets {
					if netStr, ok := net.(string); ok {
						if netStr == "0.0.0.0/0" || netStr == "::/0" {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

func checkCalicoMetadataAccess(rules []interface{}) bool {
	for _, r := range rules {
		if rule, ok := r.(map[string]interface{}); ok {
			if dest, ok := rule["destination"].(map[string]interface{}); ok {
				if nets, ok := dest["nets"].([]interface{}); ok {
					for _, net := range nets {
						if netStr, ok := net.(string); ok {
							if strings.HasPrefix(netStr, "169.254.") {
								return true
							}
						}
					}
				}
			}
		}
	}
	return false
}

func analyzeCiliumNetworkPolicies(ctx context.Context, dynClient dynamic.Interface) (map[string][]CiliumNetworkPolicyInfo, []CiliumNetworkPolicyInfo) {
	nsPolicies := make(map[string][]CiliumNetworkPolicyInfo)
	var clusterwidePolicies []CiliumNetworkPolicyInfo

	// CiliumNetworkPolicy
	gvr := schema.GroupVersionResource{Group: "cilium.io", Version: "v2", Resource: "ciliumnetworkpolicies"}
	list, err := dynClient.Resource(gvr).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range list.Items {
			info := parseCiliumPolicy(item.Object, false)
			nsPolicies[info.Namespace] = append(nsPolicies[info.Namespace], info)
		}
	}

	// CiliumClusterwideNetworkPolicy
	gvrCW := schema.GroupVersionResource{Group: "cilium.io", Version: "v2", Resource: "ciliumclusterwidenetworkpolicies"}
	cwList, err := dynClient.Resource(gvrCW).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range cwList.Items {
			info := parseCiliumPolicy(item.Object, true)
			clusterwidePolicies = append(clusterwidePolicies, info)
		}
	}

	return nsPolicies, clusterwidePolicies
}

func parseCiliumPolicy(obj map[string]interface{}, isClusterwide bool) CiliumNetworkPolicyInfo {
	info := CiliumNetworkPolicyInfo{
		IsClusterwide: isClusterwide,
	}

	if metadata, ok := obj["metadata"].(map[string]interface{}); ok {
		info.Name, _ = metadata["name"].(string)
		info.Namespace, _ = metadata["namespace"].(string)
	}

	if spec, ok := obj["spec"].(map[string]interface{}); ok {
		// Endpoint selector
		if endpointSelector, ok := spec["endpointSelector"].(map[string]interface{}); ok {
			if matchLabels, ok := endpointSelector["matchLabels"].(map[string]interface{}); ok {
				var parts []string
				for k, v := range matchLabels {
					parts = append(parts, fmt.Sprintf("%s=%v", k, v))
				}
				info.EndpointSelector = strings.Join(parts, ",")
			}
		}
		if info.EndpointSelector == "" {
			info.EndpointSelector = "<all>"
		}

		// Ingress rules
		if ingress, ok := spec["ingress"].([]interface{}); ok {
			info.IngressRuleCount = len(ingress)
			for _, r := range ingress {
				if rule, ok := r.(map[string]interface{}); ok {
					// Check for L7 rules
					if toPorts, ok := rule["toPorts"].([]interface{}); ok {
						for _, tp := range toPorts {
							if toPort, ok := tp.(map[string]interface{}); ok {
								if rules, ok := toPort["rules"].(map[string]interface{}); ok {
									if _, hasHTTP := rules["http"]; hasHTTP {
										info.HasL7Rules = true
										info.L7Protocols = appendUnique(info.L7Protocols, "HTTP")
									}
									if _, hasDNS := rules["dns"]; hasDNS {
										info.HasL7Rules = true
										info.L7Protocols = appendUnique(info.L7Protocols, "DNS")
									}
									if _, hasKafka := rules["kafka"]; hasKafka {
										info.HasL7Rules = true
										info.L7Protocols = appendUnique(info.L7Protocols, "Kafka")
									}
								}
							}
						}
					}
					// Check for CIDR
					if fromCIDR, ok := rule["fromCIDR"].([]interface{}); ok {
						for _, cidr := range fromCIDR {
							if cidrStr, ok := cidr.(string); ok {
								if cidrStr == "0.0.0.0/0" || cidrStr == "::/0" {
									info.AllowsInternetIngress = true
								}
							}
						}
					}
				}
			}
		}

		// Egress rules
		if egress, ok := spec["egress"].([]interface{}); ok {
			info.EgressRuleCount = len(egress)
			for _, r := range egress {
				if rule, ok := r.(map[string]interface{}); ok {
					// Check for L7 rules
					if toPorts, ok := rule["toPorts"].([]interface{}); ok {
						for _, tp := range toPorts {
							if toPort, ok := tp.(map[string]interface{}); ok {
								if rules, ok := toPort["rules"].(map[string]interface{}); ok {
									if _, hasHTTP := rules["http"]; hasHTTP {
										info.HasL7Rules = true
										info.L7Protocols = appendUnique(info.L7Protocols, "HTTP")
									}
									if _, hasDNS := rules["dns"]; hasDNS {
										info.HasL7Rules = true
										info.L7Protocols = appendUnique(info.L7Protocols, "DNS")
									}
								}
							}
						}
					}
					// Check for CIDR
					if toCIDR, ok := rule["toCIDR"].([]interface{}); ok {
						for _, cidr := range toCIDR {
							if cidrStr, ok := cidr.(string); ok {
								if cidrStr == "0.0.0.0/0" || cidrStr == "::/0" {
									info.AllowsInternetEgress = true
								}
								if strings.HasPrefix(cidrStr, "169.254.") {
									info.AllowsMetadataAPI = true
								}
							}
						}
					}
				}
			}
		}

		// Check for default deny (empty endpoint selector with no rules)
		if info.EndpointSelector == "<all>" && info.IngressRuleCount == 0 && info.EgressRuleCount == 0 {
			info.IsDefaultDeny = true
		}
	}

	return info
}

func analyzeAntreaNetworkPolicies(ctx context.Context, dynClient dynamic.Interface) (map[string][]AntreaNetworkPolicyInfo, []AntreaNetworkPolicyInfo) {
	nsPolicies := make(map[string][]AntreaNetworkPolicyInfo)
	var clusterPolicies []AntreaNetworkPolicyInfo

	// Antrea NetworkPolicy
	gvr := schema.GroupVersionResource{Group: "crd.antrea.io", Version: "v1beta1", Resource: "networkpolicies"}
	list, err := dynClient.Resource(gvr).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range list.Items {
			info := parseAntreaPolicy(item.Object, false)
			nsPolicies[info.Namespace] = append(nsPolicies[info.Namespace], info)
		}
	}

	// Also try v1alpha1
	gvr2 := schema.GroupVersionResource{Group: "crd.antrea.io", Version: "v1alpha1", Resource: "networkpolicies"}
	list2, err := dynClient.Resource(gvr2).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range list2.Items {
			info := parseAntreaPolicy(item.Object, false)
			nsPolicies[info.Namespace] = append(nsPolicies[info.Namespace], info)
		}
	}

	// Antrea ClusterNetworkPolicy
	gvrCluster := schema.GroupVersionResource{Group: "crd.antrea.io", Version: "v1beta1", Resource: "clusternetworkpolicies"}
	clusterList, err := dynClient.Resource(gvrCluster).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range clusterList.Items {
			info := parseAntreaPolicy(item.Object, true)
			clusterPolicies = append(clusterPolicies, info)
		}
	}

	return nsPolicies, clusterPolicies
}

func parseAntreaPolicy(obj map[string]interface{}, isCluster bool) AntreaNetworkPolicyInfo {
	info := AntreaNetworkPolicyInfo{
		IsCluster: isCluster,
		Action:    "Allow",
	}

	if metadata, ok := obj["metadata"].(map[string]interface{}); ok {
		info.Name, _ = metadata["name"].(string)
		info.Namespace, _ = metadata["namespace"].(string)
	}

	if spec, ok := obj["spec"].(map[string]interface{}); ok {
		if priority, ok := spec["priority"].(float64); ok {
			info.Priority = priority
		}
		if tier, ok := spec["tier"].(string); ok {
			info.Tier = tier
		}

		// AppliedTo
		if appliedTo, ok := spec["appliedTo"].([]interface{}); ok {
			var parts []string
			for _, at := range appliedTo {
				if atMap, ok := at.(map[string]interface{}); ok {
					if podSelector, ok := atMap["podSelector"].(map[string]interface{}); ok {
						if matchLabels, ok := podSelector["matchLabels"].(map[string]interface{}); ok {
							for k, v := range matchLabels {
								parts = append(parts, fmt.Sprintf("%s=%v", k, v))
							}
						}
					}
				}
			}
			if len(parts) > 0 {
				info.AppliedTo = strings.Join(parts, ",")
			} else {
				info.AppliedTo = "<all>"
			}
		}

		// Ingress
		if ingress, ok := spec["ingress"].([]interface{}); ok {
			info.IngressRuleCount = len(ingress)
			for _, r := range ingress {
				if rule, ok := r.(map[string]interface{}); ok {
					if action, ok := rule["action"].(string); ok {
						info.Action = action
					}
				}
			}
		}

		// Egress
		if egress, ok := spec["egress"].([]interface{}); ok {
			info.EgressRuleCount = len(egress)
			for _, r := range egress {
				if rule, ok := r.(map[string]interface{}); ok {
					if action, ok := rule["action"].(string); ok {
						info.Action = action
					}
				}
			}
		}

		// Default deny check
		if info.AppliedTo == "<all>" && info.Action == "Drop" {
			info.IsDefaultDeny = true
		}
	}

	return info
}

func analyzeIstioAuthorizationPolicies(ctx context.Context, dynClient dynamic.Interface) map[string][]IstioAuthorizationPolicyInfo {
	result := make(map[string][]IstioAuthorizationPolicyInfo)

	gvr := schema.GroupVersionResource{Group: "security.istio.io", Version: "v1", Resource: "authorizationpolicies"}
	list, err := dynClient.Resource(gvr).List(ctx, metav1.ListOptions{})
	if err != nil {
		// Try v1beta1
		gvr = schema.GroupVersionResource{Group: "security.istio.io", Version: "v1beta1", Resource: "authorizationpolicies"}
		list, err = dynClient.Resource(gvr).List(ctx, metav1.ListOptions{})
		if err != nil {
			return result
		}
	}

	for _, item := range list.Items {
		info := IstioAuthorizationPolicyInfo{}

		if metadata, ok := item.Object["metadata"].(map[string]interface{}); ok {
			info.Name, _ = metadata["name"].(string)
			info.Namespace, _ = metadata["namespace"].(string)
		}

		if spec, ok := item.Object["spec"].(map[string]interface{}); ok {
			info.Action, _ = spec["action"].(string)
			if info.Action == "" {
				info.Action = "ALLOW"
			}

			if selector, ok := spec["selector"].(map[string]interface{}); ok {
				if matchLabels, ok := selector["matchLabels"].(map[string]interface{}); ok {
					var parts []string
					for k, v := range matchLabels {
						parts = append(parts, fmt.Sprintf("%s=%v", k, v))
					}
					info.Selector = strings.Join(parts, ",")
				}
			}
			if info.Selector == "" {
				info.Selector = "<all>"
			}

			if rules, ok := spec["rules"].([]interface{}); ok {
				info.Rules = len(rules)
			}
		}

		result[info.Namespace] = append(result[info.Namespace], info)
	}

	return result
}

func analyzeLinkerdPolicies(ctx context.Context, dynClient dynamic.Interface) map[string][]LinkerdPolicyInfo {
	result := make(map[string][]LinkerdPolicyInfo)

	// Server
	gvr := schema.GroupVersionResource{Group: "policy.linkerd.io", Version: "v1beta1", Resource: "servers"}
	list, err := dynClient.Resource(gvr).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range list.Items {
			info := LinkerdPolicyInfo{Kind: "Server"}
			if metadata, ok := item.Object["metadata"].(map[string]interface{}); ok {
				info.Name, _ = metadata["name"].(string)
				info.Namespace, _ = metadata["namespace"].(string)
			}
			result[info.Namespace] = append(result[info.Namespace], info)
		}
	}

	// ServerAuthorization
	gvr2 := schema.GroupVersionResource{Group: "policy.linkerd.io", Version: "v1beta1", Resource: "serverauthorizations"}
	list2, err := dynClient.Resource(gvr2).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range list2.Items {
			info := LinkerdPolicyInfo{Kind: "ServerAuthorization"}
			if metadata, ok := item.Object["metadata"].(map[string]interface{}); ok {
				info.Name, _ = metadata["name"].(string)
				info.Namespace, _ = metadata["namespace"].(string)
			}
			result[info.Namespace] = append(result[info.Namespace], info)
		}
	}

	// AuthorizationPolicy (newer)
	gvr3 := schema.GroupVersionResource{Group: "policy.linkerd.io", Version: "v1alpha1", Resource: "authorizationpolicies"}
	list3, err := dynClient.Resource(gvr3).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range list3.Items {
			info := LinkerdPolicyInfo{Kind: "AuthorizationPolicy"}
			if metadata, ok := item.Object["metadata"].(map[string]interface{}); ok {
				info.Name, _ = metadata["name"].(string)
				info.Namespace, _ = metadata["namespace"].(string)
			}
			result[info.Namespace] = append(result[info.Namespace], info)
		}
	}

	return result
}

func analyzeAWSSecurityGroupPolicies(ctx context.Context, dynClient dynamic.Interface) map[string][]AWSSecurityGroupPolicyInfo {
	result := make(map[string][]AWSSecurityGroupPolicyInfo)

	// AWS VPC CNI SecurityGroupPolicy
	gvr := schema.GroupVersionResource{Group: "vpcresources.k8s.aws", Version: "v1beta1", Resource: "securitygrouppolicies"}
	list, err := dynClient.Resource(gvr).List(ctx, metav1.ListOptions{})
	if err != nil {
		return result
	}

	for _, item := range list.Items {
		info := AWSSecurityGroupPolicyInfo{}

		if metadata, ok := item.Object["metadata"].(map[string]interface{}); ok {
			info.Name, _ = metadata["name"].(string)
			info.Namespace, _ = metadata["namespace"].(string)
		}

		if spec, ok := item.Object["spec"].(map[string]interface{}); ok {
			// Pod selector
			if podSelector, ok := spec["podSelector"].(map[string]interface{}); ok {
				if matchLabels, ok := podSelector["matchLabels"].(map[string]interface{}); ok {
					var parts []string
					for k, v := range matchLabels {
						parts = append(parts, fmt.Sprintf("%s=%v", k, v))
					}
					info.PodSelector = strings.Join(parts, ",")
				}
			}
			if info.PodSelector == "" {
				info.PodSelector = "<all>"
			}

			// Security groups
			if securityGroups, ok := spec["securityGroups"].(map[string]interface{}); ok {
				if groupIds, ok := securityGroups["groupIds"].([]interface{}); ok {
					for _, id := range groupIds {
						if idStr, ok := id.(string); ok {
							info.SecurityGroupIDs = append(info.SecurityGroupIDs, idStr)
						}
					}
				}
			}
		}

		result[info.Namespace] = append(result[info.Namespace], info)
	}

	return result
}

func analyzeOpenShiftEgressFirewalls(ctx context.Context, dynClient dynamic.Interface) map[string][]OpenShiftEgressFirewallInfo {
	result := make(map[string][]OpenShiftEgressFirewallInfo)

	// OpenShift EgressFirewall (newer)
	gvr := schema.GroupVersionResource{Group: "k8s.ovn.org", Version: "v1", Resource: "egressfirewalls"}
	list, err := dynClient.Resource(gvr).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range list.Items {
			info := parseOpenShiftEgressFirewall(item.Object, "EgressFirewall")
			result[info.Namespace] = append(result[info.Namespace], info)
		}
	}

	// Try OpenShift network.openshift.io group
	gvr2 := schema.GroupVersionResource{Group: "network.openshift.io", Version: "v1", Resource: "egressnetworkpolicies"}
	list2, err := dynClient.Resource(gvr2).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range list2.Items {
			info := parseOpenShiftEgressFirewall(item.Object, "EgressNetworkPolicy")
			result[info.Namespace] = append(result[info.Namespace], info)
		}
	}

	return result
}

func parseOpenShiftEgressFirewall(obj map[string]interface{}, kind string) OpenShiftEgressFirewallInfo {
	info := OpenShiftEgressFirewallInfo{
		Kind: kind,
	}

	if metadata, ok := obj["metadata"].(map[string]interface{}); ok {
		info.Name, _ = metadata["name"].(string)
		info.Namespace, _ = metadata["namespace"].(string)
	}

	if spec, ok := obj["spec"].(map[string]interface{}); ok {
		if egress, ok := spec["egress"].([]interface{}); ok {
			info.RuleCount = len(egress)
			for _, e := range egress {
				if rule, ok := e.(map[string]interface{}); ok {
					ruleType, _ := rule["type"].(string)
					if to, ok := rule["to"].(map[string]interface{}); ok {
						if cidr, ok := to["cidrSelector"].(string); ok {
							if cidr == "0.0.0.0/0" && ruleType == "Allow" {
								info.AllowsInternet = true
							}
							if strings.HasPrefix(cidr, "169.254.") && ruleType == "Deny" {
								info.DeniesMetadataAPI = true
							}
						}
					}
					if ruleType == "Deny" && info.RuleCount == 1 {
						info.DeniesAllEgress = true
					}
				}
			}
		}
	}

	return info
}

func analyzeConsulConnectIntentions(ctx context.Context, dynClient dynamic.Interface) map[string][]ConsulConnectIntentionInfo {
	result := make(map[string][]ConsulConnectIntentionInfo)

	// ServiceIntentions (newer CRD)
	gvr := schema.GroupVersionResource{Group: "consul.hashicorp.com", Version: "v1alpha1", Resource: "serviceintentions"}
	list, err := dynClient.Resource(gvr).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range list.Items {
			info := parseConsulServiceIntention(item.Object)
			result[info.Namespace] = append(result[info.Namespace], info)
		}
	}

	// IngressGateway
	gvr2 := schema.GroupVersionResource{Group: "consul.hashicorp.com", Version: "v1alpha1", Resource: "ingressgateways"}
	list2, err := dynClient.Resource(gvr2).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range list2.Items {
			info := ConsulConnectIntentionInfo{}
			if metadata, ok := item.Object["metadata"].(map[string]interface{}); ok {
				info.Name, _ = metadata["name"].(string)
				info.Namespace, _ = metadata["namespace"].(string)
			}
			info.Destination = "IngressGateway"
			info.Action = "allow"
			info.AllowsAllSources = true // Ingress gateways typically allow external traffic
			result[info.Namespace] = append(result[info.Namespace], info)
		}
	}

	return result
}

func parseConsulServiceIntention(obj map[string]interface{}) ConsulConnectIntentionInfo {
	info := ConsulConnectIntentionInfo{}

	if metadata, ok := obj["metadata"].(map[string]interface{}); ok {
		info.Name, _ = metadata["name"].(string)
		info.Namespace, _ = metadata["namespace"].(string)
	}

	if spec, ok := obj["spec"].(map[string]interface{}); ok {
		info.Destination, _ = spec["destination"].(map[string]interface{})["name"].(string)

		if sources, ok := spec["sources"].([]interface{}); ok {
			info.SourceCount = len(sources)
			for _, s := range sources {
				if source, ok := s.(map[string]interface{}); ok {
					action, _ := source["action"].(string)
					info.Action = action
					name, _ := source["name"].(string)
					if name == "*" {
						if action == "allow" {
							info.AllowsAllSources = true
						} else if action == "deny" {
							info.DeniesAllSources = true
						}
					}
				}
			}
		}
	}

	return info
}

func analyzeKumaMeshPolicies(ctx context.Context, dynClient dynamic.Interface) map[string][]KumaMeshPolicyInfo {
	result := make(map[string][]KumaMeshPolicyInfo)

	// MeshTrafficPermission (Kuma 2.x)
	gvr := schema.GroupVersionResource{Group: "kuma.io", Version: "v1alpha1", Resource: "meshtrafficpermissions"}
	list, err := dynClient.Resource(gvr).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range list.Items {
			info := parseKumaMeshPolicy(item.Object, "MeshTrafficPermission")
			result[info.Namespace] = append(result[info.Namespace], info)
		}
	}

	// TrafficPermission (legacy Kuma 1.x)
	gvr2 := schema.GroupVersionResource{Group: "kuma.io", Version: "v1alpha1", Resource: "trafficpermissions"}
	list2, err := dynClient.Resource(gvr2).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range list2.Items {
			info := parseKumaMeshPolicy(item.Object, "TrafficPermission")
			result[info.Namespace] = append(result[info.Namespace], info)
		}
	}

	// MeshAccessLog
	gvr3 := schema.GroupVersionResource{Group: "kuma.io", Version: "v1alpha1", Resource: "meshaccesslogs"}
	list3, err := dynClient.Resource(gvr3).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range list3.Items {
			info := parseKumaMeshPolicy(item.Object, "MeshAccessLog")
			result[info.Namespace] = append(result[info.Namespace], info)
		}
	}

	return result
}

func parseKumaMeshPolicy(obj map[string]interface{}, kind string) KumaMeshPolicyInfo {
	info := KumaMeshPolicyInfo{
		Kind: kind,
	}

	if metadata, ok := obj["metadata"].(map[string]interface{}); ok {
		info.Name, _ = metadata["name"].(string)
		info.Namespace, _ = metadata["namespace"].(string)
	}

	if spec, ok := obj["spec"].(map[string]interface{}); ok {
		// TargetRef
		if targetRef, ok := spec["targetRef"].(map[string]interface{}); ok {
			kind, _ := targetRef["kind"].(string)
			name, _ := targetRef["name"].(string)
			if name == "" {
				name = "*"
			}
			info.TargetRef = fmt.Sprintf("%s/%s", kind, name)
		}

		// From rules
		if from, ok := spec["from"].([]interface{}); ok {
			info.RuleCount = len(from)
			for _, f := range from {
				if rule, ok := f.(map[string]interface{}); ok {
					if defaultRule, ok := rule["default"].(map[string]interface{}); ok {
						info.Action, _ = defaultRule["action"].(string)
					}
					// Check for allow all
					if targetRef, ok := rule["targetRef"].(map[string]interface{}); ok {
						kind, _ := targetRef["kind"].(string)
						if kind == "Mesh" {
							if info.Action == "Allow" {
								info.AllowsAllTraffic = true
							} else if info.Action == "Deny" {
								info.DeniesAllTraffic = true
							}
						}
					}
				}
			}
		}
	}

	return info
}

func analyzeSMIPolicies(ctx context.Context, dynClient dynamic.Interface) map[string][]SMITrafficPolicyInfo {
	result := make(map[string][]SMITrafficPolicyInfo)

	// TrafficTarget (SMI spec)
	gvr := schema.GroupVersionResource{Group: "access.smi-spec.io", Version: "v1alpha3", Resource: "traffictargets"}
	list, err := dynClient.Resource(gvr).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range list.Items {
			info := parseSMITrafficTarget(item.Object)
			result[info.Namespace] = append(result[info.Namespace], info)
		}
	}

	// Try v1alpha2
	gvr2 := schema.GroupVersionResource{Group: "access.smi-spec.io", Version: "v1alpha2", Resource: "traffictargets"}
	list2, err := dynClient.Resource(gvr2).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range list2.Items {
			info := parseSMITrafficTarget(item.Object)
			result[info.Namespace] = append(result[info.Namespace], info)
		}
	}

	// TrafficSplit (SMI spec)
	gvr3 := schema.GroupVersionResource{Group: "split.smi-spec.io", Version: "v1alpha4", Resource: "trafficsplits"}
	list3, err := dynClient.Resource(gvr3).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range list3.Items {
			info := SMITrafficPolicyInfo{Kind: "TrafficSplit"}
			if metadata, ok := item.Object["metadata"].(map[string]interface{}); ok {
				info.Name, _ = metadata["name"].(string)
				info.Namespace, _ = metadata["namespace"].(string)
			}
			if spec, ok := item.Object["spec"].(map[string]interface{}); ok {
				info.DestinationService, _ = spec["service"].(string)
			}
			info.MeshProvider = "SMI"
			result[info.Namespace] = append(result[info.Namespace], info)
		}
	}

	// HTTPRouteGroup (SMI spec)
	gvr4 := schema.GroupVersionResource{Group: "specs.smi-spec.io", Version: "v1alpha4", Resource: "httproutegroups"}
	list4, err := dynClient.Resource(gvr4).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range list4.Items {
			info := SMITrafficPolicyInfo{Kind: "HTTPRouteGroup"}
			if metadata, ok := item.Object["metadata"].(map[string]interface{}); ok {
				info.Name, _ = metadata["name"].(string)
				info.Namespace, _ = metadata["namespace"].(string)
			}
			info.MeshProvider = "SMI"
			result[info.Namespace] = append(result[info.Namespace], info)
		}
	}

	return result
}

func parseSMITrafficTarget(obj map[string]interface{}) SMITrafficPolicyInfo {
	info := SMITrafficPolicyInfo{
		Kind:         "TrafficTarget",
		MeshProvider: "SMI",
	}

	if metadata, ok := obj["metadata"].(map[string]interface{}); ok {
		info.Name, _ = metadata["name"].(string)
		info.Namespace, _ = metadata["namespace"].(string)
	}

	if spec, ok := obj["spec"].(map[string]interface{}); ok {
		// Destination
		if destination, ok := spec["destination"].(map[string]interface{}); ok {
			kind, _ := destination["kind"].(string)
			name, _ := destination["name"].(string)
			info.DestinationService = fmt.Sprintf("%s/%s", kind, name)
		}

		// Sources
		if sources, ok := spec["sources"].([]interface{}); ok {
			for _, s := range sources {
				if source, ok := s.(map[string]interface{}); ok {
					kind, _ := source["kind"].(string)
					name, _ := source["name"].(string)
					info.SourceServices = append(info.SourceServices, fmt.Sprintf("%s/%s", kind, name))
					if name == "*" {
						info.AllowsAllSources = true
					}
				}
			}
		}
	}

	return info
}

func analyzeGlooMeshPolicies(ctx context.Context, dynClient dynamic.Interface) map[string][]GlooMeshPolicyInfo {
	result := make(map[string][]GlooMeshPolicyInfo)

	// AccessPolicy
	gvr := schema.GroupVersionResource{Group: "security.policy.gloo.solo.io", Version: "v2", Resource: "accesspolicies"}
	list, err := dynClient.Resource(gvr).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range list.Items {
			info := parseGlooMeshPolicy(item.Object, "AccessPolicy")
			result[info.Namespace] = append(result[info.Namespace], info)
		}
	}

	// TrafficPolicy
	gvr2 := schema.GroupVersionResource{Group: "trafficcontrol.policy.gloo.solo.io", Version: "v2", Resource: "trafficpolicies"}
	list2, err := dynClient.Resource(gvr2).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range list2.Items {
			info := parseGlooMeshPolicy(item.Object, "TrafficPolicy")
			result[info.Namespace] = append(result[info.Namespace], info)
		}
	}

	// RateLimitPolicy
	gvr3 := schema.GroupVersionResource{Group: "trafficcontrol.policy.gloo.solo.io", Version: "v2", Resource: "ratelimitpolicies"}
	list3, err := dynClient.Resource(gvr3).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range list3.Items {
			info := parseGlooMeshPolicy(item.Object, "RateLimitPolicy")
			result[info.Namespace] = append(result[info.Namespace], info)
		}
	}

	return result
}

func parseGlooMeshPolicy(obj map[string]interface{}, kind string) GlooMeshPolicyInfo {
	info := GlooMeshPolicyInfo{
		Kind: kind,
	}

	if metadata, ok := obj["metadata"].(map[string]interface{}); ok {
		info.Name, _ = metadata["name"].(string)
		info.Namespace, _ = metadata["namespace"].(string)
	}

	if spec, ok := obj["spec"].(map[string]interface{}); ok {
		// ApplyToRefs
		if applyToRefs, ok := spec["applyToRoutes"].([]interface{}); ok {
			var refs []string
			for _, ref := range applyToRefs {
				if r, ok := ref.(map[string]interface{}); ok {
					if route, ok := r["route"].(map[string]interface{}); ok {
						name, _ := route["name"].(string)
						refs = append(refs, name)
					}
				}
			}
			info.ApplyToRefs = strings.Join(refs, ",")
		}
		if info.ApplyToRefs == "" {
			if applyToDestinations, ok := spec["applyToDestinations"].([]interface{}); ok {
				var refs []string
				for _, dest := range applyToDestinations {
					if d, ok := dest.(map[string]interface{}); ok {
						if selector, ok := d["selector"].(map[string]interface{}); ok {
							name, _ := selector["name"].(string)
							refs = append(refs, name)
						}
					}
				}
				info.ApplyToRefs = strings.Join(refs, ",")
			}
		}
		if info.ApplyToRefs == "" {
			info.ApplyToRefs = "<all>"
		}

		// Config (for AccessPolicy)
		if config, ok := spec["config"].(map[string]interface{}); ok {
			if authn, ok := config["authn"].(map[string]interface{}); ok {
				if authzList, ok := authn["authzList"].([]interface{}); ok {
					info.RuleCount = len(authzList)
				}
			}
			if allowedClients, ok := config["allowedClients"].([]interface{}); ok {
				info.RuleCount = len(allowedClients)
				for _, c := range allowedClients {
					if client, ok := c.(map[string]interface{}); ok {
						if _, hasServiceAccountRef := client["serviceAccountRef"]; !hasServiceAccountRef {
							info.AllowsAllTraffic = true
						}
					}
				}
			}
		}

		// Action
		info.Action = "ALLOW"
		if denyAction, ok := spec["denyAction"].(bool); ok && denyAction {
			info.Action = "DENY"
		}
	}

	return info
}

func analyzeNSXTPolicies(ctx context.Context, dynClient dynamic.Interface) map[string][]NSXTSecurityPolicyInfo {
	result := make(map[string][]NSXTSecurityPolicyInfo)

	// NSX-T SecurityPolicy
	gvr := schema.GroupVersionResource{Group: "nsx.vmware.com", Version: "v1alpha1", Resource: "securitypolicies"}
	list, err := dynClient.Resource(gvr).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range list.Items {
			info := parseNSXTPolicy(item.Object)
			result[info.Namespace] = append(result[info.Namespace], info)
		}
	}

	// Also try crd.nsx.vmware.com
	gvr2 := schema.GroupVersionResource{Group: "crd.nsx.vmware.com", Version: "v1alpha1", Resource: "securitypolicies"}
	list2, err := dynClient.Resource(gvr2).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range list2.Items {
			info := parseNSXTPolicy(item.Object)
			result[info.Namespace] = append(result[info.Namespace], info)
		}
	}

	return result
}

func parseNSXTPolicy(obj map[string]interface{}) NSXTSecurityPolicyInfo {
	info := NSXTSecurityPolicyInfo{
		DefaultAction: "allow",
	}

	if metadata, ok := obj["metadata"].(map[string]interface{}); ok {
		info.Name, _ = metadata["name"].(string)
		info.Namespace, _ = metadata["namespace"].(string)
	}

	if spec, ok := obj["spec"].(map[string]interface{}); ok {
		// AppliedTo
		if appliedTo, ok := spec["appliedTo"].([]interface{}); ok {
			var targets []string
			for _, at := range appliedTo {
				if atMap, ok := at.(map[string]interface{}); ok {
					if podSelector, ok := atMap["podSelector"].(map[string]interface{}); ok {
						if matchLabels, ok := podSelector["matchLabels"].(map[string]interface{}); ok {
							for k, v := range matchLabels {
								targets = append(targets, fmt.Sprintf("%s=%v", k, v))
							}
						}
					}
				}
			}
			if len(targets) > 0 {
				info.AppliedTo = strings.Join(targets, ",")
			} else {
				info.AppliedTo = "<all>"
			}
		}

		// Priority
		if priority, ok := spec["priority"].(float64); ok {
			info.Priority = int(priority)
		}

		// Rules
		if rules, ok := spec["rules"].([]interface{}); ok {
			info.RuleCount = len(rules)
			for _, r := range rules {
				if rule, ok := r.(map[string]interface{}); ok {
					if action, ok := rule["action"].(string); ok {
						if action == "drop" || action == "reject" {
							info.DefaultAction = action
						}
					}
				}
			}
		}
	}

	return info
}

func analyzeGCPBackendPolicies(ctx context.Context, dynClient dynamic.Interface) map[string][]GCPBackendPolicyInfo {
	result := make(map[string][]GCPBackendPolicyInfo)

	// GCPBackendPolicy (GKE Gateway API)
	gvr := schema.GroupVersionResource{Group: "networking.gke.io", Version: "v1", Resource: "gcpbackendpolicies"}
	list, err := dynClient.Resource(gvr).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range list.Items {
			info := parseGCPBackendPolicy(item.Object, "GCPBackendPolicy")
			result[info.Namespace] = append(result[info.Namespace], info)
		}
	}

	// Try v1beta1
	gvr2 := schema.GroupVersionResource{Group: "networking.gke.io", Version: "v1beta1", Resource: "gcpbackendpolicies"}
	list2, err := dynClient.Resource(gvr2).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range list2.Items {
			info := parseGCPBackendPolicy(item.Object, "GCPBackendPolicy")
			result[info.Namespace] = append(result[info.Namespace], info)
		}
	}

	// GCPGatewayPolicy
	gvr3 := schema.GroupVersionResource{Group: "networking.gke.io", Version: "v1", Resource: "gcpgatewaypolicies"}
	list3, err := dynClient.Resource(gvr3).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range list3.Items {
			info := parseGCPBackendPolicy(item.Object, "GCPGatewayPolicy")
			result[info.Namespace] = append(result[info.Namespace], info)
		}
	}

	// HealthCheckPolicy (can affect traffic)
	gvr4 := schema.GroupVersionResource{Group: "networking.gke.io", Version: "v1", Resource: "healthcheckpolicies"}
	list4, err := dynClient.Resource(gvr4).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range list4.Items {
			info := GCPBackendPolicyInfo{Kind: "HealthCheckPolicy"}
			if metadata, ok := item.Object["metadata"].(map[string]interface{}); ok {
				info.Name, _ = metadata["name"].(string)
				info.Namespace, _ = metadata["namespace"].(string)
			}
			result[info.Namespace] = append(result[info.Namespace], info)
		}
	}

	return result
}

func parseGCPBackendPolicy(obj map[string]interface{}, kind string) GCPBackendPolicyInfo {
	info := GCPBackendPolicyInfo{
		Kind: kind,
	}

	if metadata, ok := obj["metadata"].(map[string]interface{}); ok {
		info.Name, _ = metadata["name"].(string)
		info.Namespace, _ = metadata["namespace"].(string)
	}

	if spec, ok := obj["spec"].(map[string]interface{}); ok {
		// TargetRef
		if targetRef, ok := spec["targetRef"].(map[string]interface{}); ok {
			kind, _ := targetRef["kind"].(string)
			name, _ := targetRef["name"].(string)
			info.TargetRef = fmt.Sprintf("%s/%s", kind, name)
		}

		// Default section (contains securityPolicy for Cloud Armor)
		if defaultConfig, ok := spec["default"].(map[string]interface{}); ok {
			if securityPolicy, ok := defaultConfig["securityPolicy"].(string); ok {
				info.CloudArmorPolicy = securityPolicy
				info.HasCloudArmor = true
			}
			// IAP config
			if iap, ok := defaultConfig["iap"].(map[string]interface{}); ok {
				if enabled, ok := iap["enabled"].(bool); ok && enabled {
					info.HasIAP = true
				}
			}
		}

		// SecurityPolicy directly in spec (older format)
		if securityPolicy, ok := spec["securityPolicy"].(string); ok {
			info.CloudArmorPolicy = securityPolicy
			info.HasCloudArmor = true
		}
	}

	return info
}

func analyzeAzureNetworkPolicies(ctx context.Context, dynClient dynamic.Interface) map[string][]AzureNetworkPolicyInfo {
	result := make(map[string][]AzureNetworkPolicyInfo)

	// AzureIngressProhibitedTarget (AGIC)
	gvr := schema.GroupVersionResource{Group: "appgw.ingress.k8s.io", Version: "v1", Resource: "azureingressprohibitedtargets"}
	list, err := dynClient.Resource(gvr).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range list.Items {
			info := parseAzureIngressProhibitedTarget(item.Object)
			result[info.Namespace] = append(result[info.Namespace], info)
		}
	}

	// AzureIdentity (AAD Pod Identity - legacy)
	gvr2 := schema.GroupVersionResource{Group: "aadpodidentity.k8s.io", Version: "v1", Resource: "azureidentities"}
	list2, err := dynClient.Resource(gvr2).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range list2.Items {
			info := AzureNetworkPolicyInfo{Kind: "AzureIdentity", HasManagedIdentity: true}
			if metadata, ok := item.Object["metadata"].(map[string]interface{}); ok {
				info.Name, _ = metadata["name"].(string)
				info.Namespace, _ = metadata["namespace"].(string)
			}
			result[info.Namespace] = append(result[info.Namespace], info)
		}
	}

	// AzureIdentityBinding (AAD Pod Identity - legacy)
	gvr3 := schema.GroupVersionResource{Group: "aadpodidentity.k8s.io", Version: "v1", Resource: "azureidentitybindings"}
	list3, err := dynClient.Resource(gvr3).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range list3.Items {
			info := AzureNetworkPolicyInfo{Kind: "AzureIdentityBinding", HasManagedIdentity: true}
			if metadata, ok := item.Object["metadata"].(map[string]interface{}); ok {
				info.Name, _ = metadata["name"].(string)
				info.Namespace, _ = metadata["namespace"].(string)
			}
			if spec, ok := item.Object["spec"].(map[string]interface{}); ok {
				info.TargetService, _ = spec["selector"].(string)
			}
			result[info.Namespace] = append(result[info.Namespace], info)
		}
	}

	return result
}

func parseAzureIngressProhibitedTarget(obj map[string]interface{}) AzureNetworkPolicyInfo {
	info := AzureNetworkPolicyInfo{
		Kind: "AzureIngressProhibitedTarget",
	}

	if metadata, ok := obj["metadata"].(map[string]interface{}); ok {
		info.Name, _ = metadata["name"].(string)
		info.Namespace, _ = metadata["namespace"].(string)
	}

	if spec, ok := obj["spec"].(map[string]interface{}); ok {
		// Hostname
		if hostname, ok := spec["hostname"].(string); ok {
			info.TargetService = hostname
		}
		// Paths
		if paths, ok := spec["paths"].([]interface{}); ok {
			for _, p := range paths {
				if pathStr, ok := p.(string); ok {
					info.ProhibitedTargets = append(info.ProhibitedTargets, pathStr)
				}
			}
		}
	}

	return info
}

// ============================================================================
// Policy Engine Blocking Detection
// ============================================================================

func detectNetworkPolicyEngineBlocking(
	k8sPolicies []K8sNetworkPolicyInfo,
	calicoPolicies []CalicoNetworkPolicyInfo,
	ciliumPolicies []CiliumNetworkPolicyInfo,
	antreaPolicies []AntreaNetworkPolicyInfo,
	istioPolicies []IstioAuthorizationPolicyInfo,
	awsSGPolicies []AWSSecurityGroupPolicyInfo,
	openshiftEgressPolicies []OpenShiftEgressFirewallInfo,
	consulPolicies []ConsulConnectIntentionInfo,
	kumaPolicies []KumaMeshPolicyInfo,
	smiPolicies []SMITrafficPolicyInfo,
	glooPolicies []GlooMeshPolicyInfo,
	nsxtPolicies []NSXTSecurityPolicyInfo,
	gcpPolicies []GCPBackendPolicyInfo,
	azurePolicies []AzureNetworkPolicyInfo,
) NetworkPolicyEngineBlocking {
	blocking := NetworkPolicyEngineBlocking{}

	// Check K8s NetworkPolicies
	for _, p := range k8sPolicies {
		if p.DefaultDenyIngress {
			blocking.AllPodsIngressBlocked = true
			blocking.AllPodsIngressBlockedBy = append(blocking.AllPodsIngressBlockedBy, "K8s:"+p.Name)
			blocking.InternetIngressBlocked = true
			blocking.InternetIngressBlockedBy = append(blocking.InternetIngressBlockedBy, "K8s:"+p.Name)
			blocking.CrossNSIngressBlocked = true
			blocking.CrossNSIngressBlockedBy = append(blocking.CrossNSIngressBlockedBy, "K8s:"+p.Name)
		}
		if p.DefaultDenyEgress {
			blocking.AllPodsEgressBlocked = true
			blocking.AllPodsEgressBlockedBy = append(blocking.AllPodsEgressBlockedBy, "K8s:"+p.Name)
			blocking.InternetEgressBlocked = true
			blocking.InternetEgressBlockedBy = append(blocking.InternetEgressBlockedBy, "K8s:"+p.Name)
			blocking.MetadataAPIBlocked = true
			blocking.MetadataAPIBlockedBy = append(blocking.MetadataAPIBlockedBy, "K8s:"+p.Name)
			blocking.CrossNSEgressBlocked = true
			blocking.CrossNSEgressBlockedBy = append(blocking.CrossNSEgressBlockedBy, "K8s:"+p.Name)
			blocking.KubeAPIEgressBlocked = true
			blocking.KubeAPIEgressBlockedBy = append(blocking.KubeAPIEgressBlockedBy, "K8s:"+p.Name)
		}
	}

	// Check Calico policies
	for _, p := range calicoPolicies {
		prefix := "Calico:"
		if p.IsGlobal {
			prefix = "CalicoGlobal:"
		}
		if p.IsDefaultDeny {
			if contains(p.Types, "Ingress") || contains(p.Types, "ingress") {
				blocking.AllPodsIngressBlocked = true
				blocking.AllPodsIngressBlockedBy = append(blocking.AllPodsIngressBlockedBy, prefix+p.Name)
				blocking.InternetIngressBlocked = true
				blocking.InternetIngressBlockedBy = append(blocking.InternetIngressBlockedBy, prefix+p.Name)
			}
			if contains(p.Types, "Egress") || contains(p.Types, "egress") {
				blocking.AllPodsEgressBlocked = true
				blocking.AllPodsEgressBlockedBy = append(blocking.AllPodsEgressBlockedBy, prefix+p.Name)
				blocking.InternetEgressBlocked = true
				blocking.InternetEgressBlockedBy = append(blocking.InternetEgressBlockedBy, prefix+p.Name)
				blocking.MetadataAPIBlocked = true
				blocking.MetadataAPIBlockedBy = append(blocking.MetadataAPIBlockedBy, prefix+p.Name)
			}
		}
	}

	// Check Cilium policies
	for _, p := range ciliumPolicies {
		prefix := "Cilium:"
		if p.IsClusterwide {
			prefix = "CiliumCW:"
		}
		if p.IsDefaultDeny {
			blocking.AllPodsIngressBlocked = true
			blocking.AllPodsIngressBlockedBy = append(blocking.AllPodsIngressBlockedBy, prefix+p.Name)
			blocking.AllPodsEgressBlocked = true
			blocking.AllPodsEgressBlockedBy = append(blocking.AllPodsEgressBlockedBy, prefix+p.Name)
			blocking.InternetIngressBlocked = true
			blocking.InternetIngressBlockedBy = append(blocking.InternetIngressBlockedBy, prefix+p.Name)
			blocking.InternetEgressBlocked = true
			blocking.InternetEgressBlockedBy = append(blocking.InternetEgressBlockedBy, prefix+p.Name)
		}
		// Check if Cilium DNS L7 rules restrict DNS
		if p.HasL7Rules && contains(p.L7Protocols, "DNS") {
			blocking.DNSEgressRestricted = true
			blocking.DNSEgressRestrictedBy = append(blocking.DNSEgressRestrictedBy, prefix+p.Name)
		}
	}

	// Check Antrea policies
	// Only count as default deny if the policy applies to all pods AND has Drop action
	// Individual Drop rules don't mean all traffic is blocked
	for _, p := range antreaPolicies {
		prefix := "Antrea:"
		if p.IsCluster {
			prefix = "AntreaCNP:"
		}
		// IsDefaultDeny is only true when AppliedTo == "<all>" && Action == "Drop"
		if p.IsDefaultDeny {
			blocking.AllPodsIngressBlocked = true
			blocking.AllPodsIngressBlockedBy = append(blocking.AllPodsIngressBlockedBy, prefix+p.Name)
			blocking.AllPodsEgressBlocked = true
			blocking.AllPodsEgressBlockedBy = append(blocking.AllPodsEgressBlockedBy, prefix+p.Name)
		}
	}

	// Check Istio policies
	for _, p := range istioPolicies {
		if p.Action == "DENY" {
			blocking.AllPodsIngressBlocked = true
			blocking.AllPodsIngressBlockedBy = append(blocking.AllPodsIngressBlockedBy, "Istio:"+p.Name)
		}
	}

	// Check AWS SecurityGroupPolicies
	// Note: AWS SGs work differently - they're allow-list based
	// We detect them but can't determine blocking without AWS API access
	for _, p := range awsSGPolicies {
		if !p.AllowsAllTraffic && len(p.SecurityGroupIDs) > 0 {
			// SGs are applied - traffic is restricted to SG rules
			blocking.InternetIngressBlocked = true
			blocking.InternetIngressBlockedBy = append(blocking.InternetIngressBlockedBy, "AWS-SG:"+p.Name)
		}
	}

	// Check OpenShift EgressFirewall policies
	for _, p := range openshiftEgressPolicies {
		if p.DeniesAllEgress {
			blocking.AllPodsEgressBlocked = true
			blocking.AllPodsEgressBlockedBy = append(blocking.AllPodsEgressBlockedBy, "OCP-Egress:"+p.Name)
			blocking.InternetEgressBlocked = true
			blocking.InternetEgressBlockedBy = append(blocking.InternetEgressBlockedBy, "OCP-Egress:"+p.Name)
			blocking.MetadataAPIBlocked = true
			blocking.MetadataAPIBlockedBy = append(blocking.MetadataAPIBlockedBy, "OCP-Egress:"+p.Name)
		} else if p.DeniesMetadataAPI {
			blocking.MetadataAPIBlocked = true
			blocking.MetadataAPIBlockedBy = append(blocking.MetadataAPIBlockedBy, "OCP-Egress:"+p.Name)
		}
		if !p.AllowsInternet && p.RuleCount > 0 {
			blocking.InternetEgressBlocked = true
			blocking.InternetEgressBlockedBy = append(blocking.InternetEgressBlockedBy, "OCP-Egress:"+p.Name)
		}
	}

	// Check Consul Connect intentions
	for _, p := range consulPolicies {
		if p.DeniesAllSources {
			blocking.AllPodsIngressBlocked = true
			blocking.AllPodsIngressBlockedBy = append(blocking.AllPodsIngressBlockedBy, "Consul:"+p.Name)
			blocking.CrossNSIngressBlocked = true
			blocking.CrossNSIngressBlockedBy = append(blocking.CrossNSIngressBlockedBy, "Consul:"+p.Name)
		}
	}

	// Check Kuma Mesh policies
	for _, p := range kumaPolicies {
		if p.DeniesAllTraffic {
			blocking.AllPodsIngressBlocked = true
			blocking.AllPodsIngressBlockedBy = append(blocking.AllPodsIngressBlockedBy, "Kuma:"+p.Name)
			blocking.CrossNSIngressBlocked = true
			blocking.CrossNSIngressBlockedBy = append(blocking.CrossNSIngressBlockedBy, "Kuma:"+p.Name)
		}
	}

	// Check SMI policies
	// SMI TrafficTarget defines what's allowed - presence indicates restriction
	for _, p := range smiPolicies {
		if p.Kind == "TrafficTarget" && !p.AllowsAllSources {
			// TrafficTarget restricts to specific sources
			blocking.CrossNSIngressBlocked = true
			blocking.CrossNSIngressBlockedBy = append(blocking.CrossNSIngressBlockedBy, "SMI:"+p.Name)
		}
	}

	// Check Gloo Mesh policies
	for _, p := range glooPolicies {
		if p.Action == "DENY" {
			blocking.AllPodsIngressBlocked = true
			blocking.AllPodsIngressBlockedBy = append(blocking.AllPodsIngressBlockedBy, "Gloo:"+p.Name)
		}
		if p.Kind == "AccessPolicy" && !p.AllowsAllTraffic {
			blocking.CrossNSIngressBlocked = true
			blocking.CrossNSIngressBlockedBy = append(blocking.CrossNSIngressBlockedBy, "Gloo:"+p.Name)
		}
	}

	// Check NSX-T policies
	for _, p := range nsxtPolicies {
		if p.DefaultAction == "drop" || p.DefaultAction == "reject" {
			blocking.AllPodsIngressBlocked = true
			blocking.AllPodsIngressBlockedBy = append(blocking.AllPodsIngressBlockedBy, "NSX-T:"+p.Name)
			blocking.AllPodsEgressBlocked = true
			blocking.AllPodsEgressBlockedBy = append(blocking.AllPodsEgressBlockedBy, "NSX-T:"+p.Name)
		}
	}

	// Check GCP Backend policies
	// Cloud Armor provides WAF/DDoS protection - indicates ingress protection
	for _, p := range gcpPolicies {
		if p.HasCloudArmor {
			// Cloud Armor restricts internet ingress based on security policy rules
			blocking.InternetIngressBlocked = true
			blocking.InternetIngressBlockedBy = append(blocking.InternetIngressBlockedBy, "GCP-CloudArmor:"+p.Name)
		}
		if p.HasIAP {
			// IAP requires authentication for ingress
			blocking.InternetIngressBlocked = true
			blocking.InternetIngressBlockedBy = append(blocking.InternetIngressBlockedBy, "GCP-IAP:"+p.Name)
		}
	}

	// Check Azure policies
	// Azure policies are informational - they don't directly block at the K8s level
	// but indicate managed identity configurations that affect network access
	for _, p := range azurePolicies {
		if p.Kind == "AzureIngressProhibitedTarget" {
			// AGIC prohibits certain ingress targets
			blocking.InternetIngressBlocked = true
			blocking.InternetIngressBlockedBy = append(blocking.InternetIngressBlockedBy, "Azure-AGIC:"+p.Name)
		}
	}

	return blocking
}

// ============================================================================
// Filter Functions
// ============================================================================

func filterK8sPoliciesForNamespace(allPolicies map[string][]K8sNetworkPolicyInfo, ns string) []K8sNetworkPolicyInfo {
	return allPolicies[ns]
}

func filterCalicoPoliciesForNamespace(nsPolicies map[string][]CalicoNetworkPolicyInfo, globalPolicies []CalicoNetworkPolicyInfo, ns string) []CalicoNetworkPolicyInfo {
	result := nsPolicies[ns]
	// Global policies apply to all namespaces
	result = append(result, globalPolicies...)
	return result
}

func filterCiliumPoliciesForNamespace(nsPolicies map[string][]CiliumNetworkPolicyInfo, clusterwidePolicies []CiliumNetworkPolicyInfo, ns string) []CiliumNetworkPolicyInfo {
	result := nsPolicies[ns]
	result = append(result, clusterwidePolicies...)
	return result
}

func filterAntreaPoliciesForNamespace(nsPolicies map[string][]AntreaNetworkPolicyInfo, clusterPolicies []AntreaNetworkPolicyInfo, ns string) []AntreaNetworkPolicyInfo {
	result := nsPolicies[ns]
	result = append(result, clusterPolicies...)
	return result
}

func filterIstioPoliciesForNamespace(allPolicies map[string][]IstioAuthorizationPolicyInfo, ns string) []IstioAuthorizationPolicyInfo {
	return allPolicies[ns]
}

func filterLinkerdPoliciesForNamespace(allPolicies map[string][]LinkerdPolicyInfo, ns string) []LinkerdPolicyInfo {
	return allPolicies[ns]
}

func filterAWSSecurityGroupPoliciesForNamespace(allPolicies map[string][]AWSSecurityGroupPolicyInfo, ns string) []AWSSecurityGroupPolicyInfo {
	return allPolicies[ns]
}

func filterOpenShiftEgressPoliciesForNamespace(allPolicies map[string][]OpenShiftEgressFirewallInfo, ns string) []OpenShiftEgressFirewallInfo {
	return allPolicies[ns]
}

func filterConsulConnectPoliciesForNamespace(allPolicies map[string][]ConsulConnectIntentionInfo, ns string) []ConsulConnectIntentionInfo {
	return allPolicies[ns]
}

func filterKumaMeshPoliciesForNamespace(allPolicies map[string][]KumaMeshPolicyInfo, ns string) []KumaMeshPolicyInfo {
	return allPolicies[ns]
}

func filterSMIPoliciesForNamespace(allPolicies map[string][]SMITrafficPolicyInfo, ns string) []SMITrafficPolicyInfo {
	return allPolicies[ns]
}

func filterGlooMeshPoliciesForNamespace(allPolicies map[string][]GlooMeshPolicyInfo, ns string) []GlooMeshPolicyInfo {
	return allPolicies[ns]
}

func filterNSXTPoliciesForNamespace(allPolicies map[string][]NSXTSecurityPolicyInfo, ns string) []NSXTSecurityPolicyInfo {
	return allPolicies[ns]
}

func filterGCPBackendPoliciesForNamespace(allPolicies map[string][]GCPBackendPolicyInfo, ns string) []GCPBackendPolicyInfo {
	return allPolicies[ns]
}

func filterAzureNetworkPoliciesForNamespace(allPolicies map[string][]AzureNetworkPolicyInfo, ns string) []AzureNetworkPolicyInfo {
	return allPolicies[ns]
}

// ============================================================================
// Helper Functions
// ============================================================================

func calculateNetworkPolicyCoverage(pods []corev1.Pod, policies []K8sNetworkPolicyInfo) int {
	if len(policies) == 0 {
		return 0
	}

	covered := make(map[string]bool)
	for _, policy := range policies {
		for _, pod := range pods {
			if isPodCoveredByPolicy(pod, policy) {
				covered[pod.Name] = true
			}
		}
	}
	return len(covered)
}

func isPodCoveredByPolicy(pod corev1.Pod, policy K8sNetworkPolicyInfo) bool {
	if policy.PodSelector == "<all>" || policy.PodSelector == "" {
		return true
	}
	// Simple label matching
	for _, part := range strings.Split(policy.PodSelector, ",") {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 {
			if pod.Labels[kv[0]] == kv[1] {
				return true
			}
		}
	}
	return false
}

func countMatchingPods(pods []corev1.Pod, selector *metav1.LabelSelector) int {
	if isEmptyK8sSelector(selector) {
		return len(pods)
	}

	sel := labels.Set(selector.MatchLabels).AsSelector()
	count := 0
	for _, pod := range pods {
		if sel.Matches(labels.Set(pod.Labels)) {
			count++
		}
	}
	return count
}

func formatK8sLabelSelector(selector *metav1.LabelSelector) string {
	if selector == nil || (len(selector.MatchLabels) == 0 && len(selector.MatchExpressions) == 0) {
		return "<all>"
	}
	var parts []string
	for k, v := range selector.MatchLabels {
		parts = append(parts, fmt.Sprintf("%s=%s", k, v))
	}
	if len(parts) == 0 {
		return "<all>"
	}
	return strings.Join(parts, ",")
}

func isEmptyK8sSelector(selector *metav1.LabelSelector) bool {
	return selector == nil || (len(selector.MatchLabels) == 0 && len(selector.MatchExpressions) == 0)
}

func calculateK8sNetworkPolicyRisk(info K8sNetworkPolicyInfo) string {
	if info.AllowsInternetIngress && info.AllowsInternetEgress {
		return shared.RiskCritical
	}
	if info.AllowsInternetIngress || info.AllowsInternetEgress {
		return shared.RiskHigh
	}
	if info.AllowsMetadataAPI {
		return shared.RiskHigh
	}
	if info.AllowsCrossNS {
		return shared.RiskMedium
	}
	return shared.RiskLow
}

func calculateNetworkAdmissionRiskLevel(finding NetworkAdmissionFinding) string {
	if !finding.HasNetworkPolicy {
		return shared.RiskCritical
	}
	if finding.AllowsInternetIngress && finding.AllowsInternetEgress {
		return shared.RiskCritical
	}
	if finding.AllowsMetadataAPI {
		return shared.RiskHigh
	}
	if finding.AllowsInternetIngress || finding.AllowsInternetEgress {
		return shared.RiskHigh
	}
	if !finding.HasDefaultDenyIngress && !finding.HasDefaultDenyEgress {
		return shared.RiskMedium
	}
	return shared.RiskLow
}

func generateNetworkAdmissionRecommendations(finding NetworkAdmissionFinding) []string {
	var recs []string

	if !finding.HasNetworkPolicy {
		recs = append(recs, "CRITICAL: No network policies - implement default-deny")
	}
	if !finding.HasDefaultDenyIngress {
		recs = append(recs, "Implement default-deny ingress policy")
	}
	if !finding.HasDefaultDenyEgress {
		recs = append(recs, "Implement default-deny egress policy")
	}
	if finding.AllowsMetadataAPI {
		recs = append(recs, "Block metadata API access (169.254.169.254)")
	}
	if finding.AllowsInternetEgress {
		recs = append(recs, "Restrict internet egress to prevent data exfiltration")
	}

	return recs
}

func networkAdmissionFormatDuration(d time.Duration) string {
	days := int(d.Hours() / 24)
	if days > 365 {
		return fmt.Sprintf("%dy", days/365)
	}
	if days > 30 {
		return fmt.Sprintf("%dmo", days/30)
	}
	if days > 0 {
		return fmt.Sprintf("%dd", days)
	}
	hours := int(d.Hours())
	if hours > 0 {
		return fmt.Sprintf("%dh", hours)
	}
	return fmt.Sprintf("%dm", int(d.Minutes()))
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func appendUnique(slice []string, item string) []string {
	for _, s := range slice {
		if s == item {
			return slice
		}
	}
	return append(slice, item)
}

// ============================================================================
// Loot Generation
// ============================================================================

func generateNetworkAdmissionLoot(finding *NetworkAdmissionFinding, loot *shared.LootBuilder) {
	// No policies - critical finding
	if !finding.HasNetworkPolicy {
		loot.Section("Network-Admission-Lateral-Movement").
			Addf("\n# [CRITICAL] Namespace: %s", finding.Namespace).
			Add("# NO network policies - all traffic allowed").
			Addf("# %d pods are completely unprotected", finding.TotalPods).
			Addf("kubectl get pods -n %s", finding.Namespace).
			AddBlank()

		loot.Section("Network-Admission-Default-Deny").
			Addf("\n# ─────────────────────────────────────────────────────────────").
			Addf("# Namespace: %s (NO POLICIES)", finding.Namespace).
			Addf("# ─────────────────────────────────────────────────────────────").
			Add("# Recommended default-deny policy:").
			Add(generateK8sDefaultDenyTemplate(finding.Namespace)).
			AddBlank()

		return
	}

	// Has policies but no default deny
	if !finding.HasDefaultDenyIngress || !finding.HasDefaultDenyEgress {
		loot.Section("Network-Admission-Default-Deny").
			Addf("\n# ─────────────────────────────────────────────────────────────").
			Addf("# Namespace: %s", finding.Namespace)
		if !finding.HasDefaultDenyIngress {
			loot.Section("Network-Admission-Default-Deny").Add("# Missing: default-deny INGRESS")
		}
		if !finding.HasDefaultDenyEgress {
			loot.Section("Network-Admission-Default-Deny").Add("# Missing: default-deny EGRESS")
		}
		loot.Section("Network-Admission-Default-Deny").
			Add("# Recommended policy:").
			Add(generateK8sDefaultDenyTemplate(finding.Namespace)).
			AddBlank()
	}

	// Data exfiltration risks
	if finding.AllowsInternetEgress || finding.AllowsMetadataAPI {
		loot.Section("Network-Admission-Data-Exfil").
			Addf("\n# [HIGH] Namespace: %s", finding.Namespace)
		if finding.AllowsInternetEgress {
			loot.Section("Network-Admission-Data-Exfil").Add("# [!] Internet egress allowed - data exfiltration possible")
		}
		if finding.AllowsMetadataAPI {
			loot.Section("Network-Admission-Data-Exfil").Add("# [!] Metadata API access allowed - credential theft risk")
		}
		loot.Section("Network-Admission-Data-Exfil").
			Addf("kubectl get networkpolicies -n %s", finding.Namespace).
			AddBlank()
	}

	// Enum section
	loot.Section("Network-Admission-Enum").
		Addf("\n# Namespace: %s (%d policies)", finding.Namespace, finding.PolicyCount)

	if finding.K8sNetworkPolicyCount > 0 {
		loot.Section("Network-Admission-Enum").Addf("kubectl get networkpolicies -n %s", finding.Namespace)
	}
	if finding.CalicoCount > 0 {
		loot.Section("Network-Admission-Enum").Addf("kubectl get networkpolicies.projectcalico.org -n %s", finding.Namespace)
	}
	if finding.CiliumCount > 0 {
		loot.Section("Network-Admission-Enum").Addf("kubectl get ciliumnetworkpolicies -n %s", finding.Namespace)
	}
	if finding.AntreaCount > 0 {
		loot.Section("Network-Admission-Enum").Addf("kubectl get networkpolicies.crd.antrea.io -n %s", finding.Namespace)
	}
	if finding.IstioCount > 0 {
		loot.Section("Network-Admission-Enum").Addf("kubectl get authorizationpolicies.security.istio.io -n %s", finding.Namespace)
	}
	if finding.AWSSecurityGroupCount > 0 {
		loot.Section("Network-Admission-Enum").Addf("kubectl get securitygrouppolicies.vpcresources.k8s.aws -n %s", finding.Namespace)
	}
	if finding.OpenShiftEgressCount > 0 {
		loot.Section("Network-Admission-Enum").Addf("kubectl get egressfirewalls.k8s.ovn.org -n %s", finding.Namespace)
		loot.Section("Network-Admission-Enum").Addf("kubectl get egressnetworkpolicies.network.openshift.io -n %s", finding.Namespace)
	}
	if finding.ConsulConnectCount > 0 {
		loot.Section("Network-Admission-Enum").Addf("kubectl get serviceintentions.consul.hashicorp.com -n %s", finding.Namespace)
	}
	if finding.KumaMeshCount > 0 {
		loot.Section("Network-Admission-Enum").Addf("kubectl get meshtrafficpermissions.kuma.io -n %s", finding.Namespace)
	}
	if finding.SMICount > 0 {
		loot.Section("Network-Admission-Enum").Addf("kubectl get traffictargets.access.smi-spec.io -n %s", finding.Namespace)
	}
	if finding.GlooMeshCount > 0 {
		loot.Section("Network-Admission-Enum").Addf("kubectl get accesspolicies.security.policy.gloo.solo.io -n %s", finding.Namespace)
	}
	if finding.NSXTCount > 0 {
		loot.Section("Network-Admission-Enum").Addf("kubectl get securitypolicies.nsx.vmware.com -n %s", finding.Namespace)
	}
	if finding.GCPBackendCount > 0 {
		loot.Section("Network-Admission-Enum").Addf("kubectl get gcpbackendpolicies.networking.gke.io -n %s", finding.Namespace)
	}
	if finding.AzureNetworkCount > 0 {
		loot.Section("Network-Admission-Enum").Addf("kubectl get azureingressprohibitedtargets.appgw.ingress.k8s.io -n %s", finding.Namespace)
		loot.Section("Network-Admission-Enum").Addf("kubectl get azureidentitybindings.aadpodidentity.k8s.io -n %s", finding.Namespace)
	}

	loot.Section("Network-Admission-Enum").AddBlank()
}

func generateK8sDefaultDenyTemplate(namespace string) string {
	return fmt.Sprintf(`apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: %s
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress`, namespace)
}

// Image verification helper functions

func applyK8sNetPolicyVerification(policies map[string][]K8sNetworkPolicyInfo, verified bool) {
	for ns := range policies {
		for i := range policies[ns] {
			policies[ns][i].ImageVerified = verified
		}
	}
}

func applyCalicoPolicyVerification(nsPolicies map[string][]CalicoNetworkPolicyInfo, globalPolicies []CalicoNetworkPolicyInfo, verified bool) {
	for ns := range nsPolicies {
		for i := range nsPolicies[ns] {
			nsPolicies[ns][i].ImageVerified = verified
		}
	}
	for i := range globalPolicies {
		globalPolicies[i].ImageVerified = verified
	}
}

func applyCiliumPolicyVerification(nsPolicies map[string][]CiliumNetworkPolicyInfo, clusterwidePolicies []CiliumNetworkPolicyInfo, verified bool) {
	for ns := range nsPolicies {
		for i := range nsPolicies[ns] {
			nsPolicies[ns][i].ImageVerified = verified
		}
	}
	for i := range clusterwidePolicies {
		clusterwidePolicies[i].ImageVerified = verified
	}
}

func applyAntreaPolicyVerification(nsPolicies map[string][]AntreaNetworkPolicyInfo, clusterPolicies []AntreaNetworkPolicyInfo, verified bool) {
	for ns := range nsPolicies {
		for i := range nsPolicies[ns] {
			nsPolicies[ns][i].ImageVerified = verified
		}
	}
	for i := range clusterPolicies {
		clusterPolicies[i].ImageVerified = verified
	}
}

func applyIstioPolicyVerification(policies map[string][]IstioAuthorizationPolicyInfo, verified bool) {
	for ns := range policies {
		for i := range policies[ns] {
			policies[ns][i].ImageVerified = verified
		}
	}
}

func applyLinkerdPolicyVerification(policies map[string][]LinkerdPolicyInfo, verified bool) {
	for ns := range policies {
		for i := range policies[ns] {
			policies[ns][i].ImageVerified = verified
		}
	}
}

func applyAWSSecurityGroupPolicyVerification(policies map[string][]AWSSecurityGroupPolicyInfo, verified bool) {
	for ns := range policies {
		for i := range policies[ns] {
			policies[ns][i].ImageVerified = verified
		}
	}
}

func applyOpenShiftEgressPolicyVerification(policies map[string][]OpenShiftEgressFirewallInfo, verified bool) {
	for ns := range policies {
		for i := range policies[ns] {
			policies[ns][i].ImageVerified = verified
		}
	}
}

func applyConsulConnectPolicyVerification(policies map[string][]ConsulConnectIntentionInfo, verified bool) {
	for ns := range policies {
		for i := range policies[ns] {
			policies[ns][i].ImageVerified = verified
		}
	}
}

func applyKumaMeshPolicyVerification(policies map[string][]KumaMeshPolicyInfo, verified bool) {
	for ns := range policies {
		for i := range policies[ns] {
			policies[ns][i].ImageVerified = verified
		}
	}
}

func applySMIPolicyVerification(policies map[string][]SMITrafficPolicyInfo, verified bool) {
	for ns := range policies {
		for i := range policies[ns] {
			policies[ns][i].ImageVerified = verified
		}
	}
}

func applyGlooMeshPolicyVerification(policies map[string][]GlooMeshPolicyInfo, verified bool) {
	for ns := range policies {
		for i := range policies[ns] {
			policies[ns][i].ImageVerified = verified
		}
	}
}

func applyNSXTPolicyVerification(policies map[string][]NSXTSecurityPolicyInfo, verified bool) {
	for ns := range policies {
		for i := range policies[ns] {
			policies[ns][i].ImageVerified = verified
		}
	}
}

func applyGCPBackendPolicyVerification(policies map[string][]GCPBackendPolicyInfo, verified bool) {
	for ns := range policies {
		for i := range policies[ns] {
			policies[ns][i].ImageVerified = verified
		}
	}
}

func applyAzureNetworkPolicyVerification(policies map[string][]AzureNetworkPolicyInfo, verified bool) {
	for ns := range policies {
		for i := range policies[ns] {
			policies[ns][i].ImageVerified = verified
		}
	}
}

// generateNetworkPolicyEnumerationLoot creates comprehensive enumeration commands for all detected policy engines
func generateNetworkPolicyEnumerationLoot(findings []NetworkAdmissionFinding, loot *shared.LootBuilder) {
	// Track which engines are detected across all namespaces
	hasK8sNetworkPolicy := false
	hasCalico := false
	hasCilium := false
	hasAntrea := false
	hasIstio := false
	hasLinkerd := false
	hasAWSSecurityGroup := false
	hasOpenShiftEgress := false
	hasConsulConnect := false
	hasKumaMesh := false
	hasSMI := false
	hasGlooMesh := false
	hasNSXT := false
	hasGCPBackend := false
	hasAzureNetwork := false

	// Scan all findings to determine which engines are active
	for _, finding := range findings {
		if finding.K8sNetworkPolicyCount > 0 {
			hasK8sNetworkPolicy = true
		}
		if finding.CalicoCount > 0 {
			hasCalico = true
		}
		if finding.CiliumCount > 0 {
			hasCilium = true
		}
		if finding.AntreaCount > 0 {
			hasAntrea = true
		}
		if finding.IstioCount > 0 {
			hasIstio = true
		}
		if finding.LinkerdCount > 0 {
			hasLinkerd = true
		}
		if finding.AWSSecurityGroupCount > 0 {
			hasAWSSecurityGroup = true
		}
		if finding.OpenShiftEgressCount > 0 {
			hasOpenShiftEgress = true
		}
		if finding.ConsulConnectCount > 0 {
			hasConsulConnect = true
		}
		if finding.KumaMeshCount > 0 {
			hasKumaMesh = true
		}
		if finding.SMICount > 0 {
			hasSMI = true
		}
		if finding.GlooMeshCount > 0 {
			hasGlooMesh = true
		}
		if finding.NSXTCount > 0 {
			hasNSXT = true
		}
		if finding.GCPBackendCount > 0 {
			hasGCPBackend = true
		}
		if finding.AzureNetworkCount > 0 {
			hasAzureNetwork = true
		}
	}

	// Add context command
	if globals.KubeContext != "" {
		loot.Section("Network-Admission-Policy-Enumeration").Addf("kubectl config use-context %s\n", globals.KubeContext)
	}

	// Kubernetes Native NetworkPolicy (always include as it's the base)
	loot.Section("Network-Admission-Policy-Enumeration").Add("# ═══════════════════════════════════════════════════════════")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# KUBERNETES NATIVE NETWORK POLICIES")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# ═══════════════════════════════════════════════════════════")
	if hasK8sNetworkPolicy {
		loot.Section("Network-Admission-Policy-Enumeration").Add("# [DETECTED] Kubernetes NetworkPolicy resources found")
	} else {
		loot.Section("Network-Admission-Policy-Enumeration").Add("# [NOT DETECTED] No Kubernetes NetworkPolicy resources found")
	}
	loot.Section("Network-Admission-Policy-Enumeration").Add("")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# List all NetworkPolicies across all namespaces:")
	loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get networkpolicies -A")
	loot.Section("Network-Admission-Policy-Enumeration").Add("")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# Get detailed YAML for all NetworkPolicies:")
	loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get networkpolicies -A -o yaml")
	loot.Section("Network-Admission-Policy-Enumeration").Add("")

	// Calico
	loot.Section("Network-Admission-Policy-Enumeration").Add("# ═══════════════════════════════════════════════════════════")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# CALICO NETWORK POLICIES")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# ═══════════════════════════════════════════════════════════")
	if hasCalico {
		loot.Section("Network-Admission-Policy-Enumeration").Add("# [DETECTED] Calico policies found")
	} else {
		loot.Section("Network-Admission-Policy-Enumeration").Add("# [NOT DETECTED] No Calico policies found (commands may error)")
	}
	loot.Section("Network-Admission-Policy-Enumeration").Add("")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# List Calico NetworkPolicies (namespace-scoped):")
	loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get networkpolicies.crd.projectcalico.org -A")
	loot.Section("Network-Admission-Policy-Enumeration").Add("")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# List Calico GlobalNetworkPolicies (cluster-scoped):")
	loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get globalnetworkpolicies.crd.projectcalico.org")
	loot.Section("Network-Admission-Policy-Enumeration").Add("")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# Get detailed YAML:")
	loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get networkpolicies.crd.projectcalico.org -A -o yaml")
	loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get globalnetworkpolicies.crd.projectcalico.org -o yaml")
	loot.Section("Network-Admission-Policy-Enumeration").Add("")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# List Calico GlobalNetworkSets (IP allowlists):")
	loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get globalnetworksets.crd.projectcalico.org -o yaml")
	loot.Section("Network-Admission-Policy-Enumeration").Add("")

	// Cilium
	loot.Section("Network-Admission-Policy-Enumeration").Add("# ═══════════════════════════════════════════════════════════")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# CILIUM NETWORK POLICIES")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# ═══════════════════════════════════════════════════════════")
	if hasCilium {
		loot.Section("Network-Admission-Policy-Enumeration").Add("# [DETECTED] Cilium policies found")
	} else {
		loot.Section("Network-Admission-Policy-Enumeration").Add("# [NOT DETECTED] No Cilium policies found (commands may error)")
	}
	loot.Section("Network-Admission-Policy-Enumeration").Add("")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# List CiliumNetworkPolicies (namespace-scoped):")
	loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get ciliumnetworkpolicies -A")
	loot.Section("Network-Admission-Policy-Enumeration").Add("")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# List CiliumClusterwideNetworkPolicies (cluster-scoped):")
	loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get ciliumclusterwidenetworkpolicies")
	loot.Section("Network-Admission-Policy-Enumeration").Add("")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# Get detailed YAML:")
	loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get ciliumnetworkpolicies -A -o yaml")
	loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get ciliumclusterwidenetworkpolicies -o yaml")
	loot.Section("Network-Admission-Policy-Enumeration").Add("")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# List Cilium Endpoints (shows policy enforcement status):")
	loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get ciliumendpoints -A")
	loot.Section("Network-Admission-Policy-Enumeration").Add("")

	// Antrea
	loot.Section("Network-Admission-Policy-Enumeration").Add("# ═══════════════════════════════════════════════════════════")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# ANTREA NETWORK POLICIES")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# ═══════════════════════════════════════════════════════════")
	if hasAntrea {
		loot.Section("Network-Admission-Policy-Enumeration").Add("# [DETECTED] Antrea policies found")
	} else {
		loot.Section("Network-Admission-Policy-Enumeration").Add("# [NOT DETECTED] No Antrea policies found (commands may error)")
	}
	loot.Section("Network-Admission-Policy-Enumeration").Add("")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# List Antrea NetworkPolicies (namespace-scoped):")
	loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get networkpolicies.crd.antrea.io -A")
	loot.Section("Network-Admission-Policy-Enumeration").Add("")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# List Antrea ClusterNetworkPolicies (cluster-scoped):")
	loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get clusternetworkpolicies.crd.antrea.io")
	loot.Section("Network-Admission-Policy-Enumeration").Add("")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# Get detailed YAML:")
	loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get networkpolicies.crd.antrea.io -A -o yaml")
	loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get clusternetworkpolicies.crd.antrea.io -o yaml")
	loot.Section("Network-Admission-Policy-Enumeration").Add("")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# List Antrea Tiers (policy priority):")
	loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get tiers.crd.antrea.io")
	loot.Section("Network-Admission-Policy-Enumeration").Add("")

	// Istio
	loot.Section("Network-Admission-Policy-Enumeration").Add("# ═══════════════════════════════════════════════════════════")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# ISTIO AUTHORIZATION POLICIES")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# ═══════════════════════════════════════════════════════════")
	if hasIstio {
		loot.Section("Network-Admission-Policy-Enumeration").Add("# [DETECTED] Istio AuthorizationPolicies found")
	} else {
		loot.Section("Network-Admission-Policy-Enumeration").Add("# [NOT DETECTED] No Istio policies found (commands may error)")
	}
	loot.Section("Network-Admission-Policy-Enumeration").Add("")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# List Istio AuthorizationPolicies:")
	loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get authorizationpolicies.security.istio.io -A")
	loot.Section("Network-Admission-Policy-Enumeration").Add("")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# List Istio PeerAuthentication (mTLS):")
	loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get peerauthentications.security.istio.io -A")
	loot.Section("Network-Admission-Policy-Enumeration").Add("")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# Get detailed YAML:")
	loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get authorizationpolicies.security.istio.io -A -o yaml")
	loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get peerauthentications.security.istio.io -A -o yaml")
	loot.Section("Network-Admission-Policy-Enumeration").Add("")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# List Istio Sidecars (traffic scoping):")
	loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get sidecars.networking.istio.io -A -o yaml")
	loot.Section("Network-Admission-Policy-Enumeration").Add("")

	// Linkerd
	loot.Section("Network-Admission-Policy-Enumeration").Add("# ═══════════════════════════════════════════════════════════")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# LINKERD POLICIES")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# ═══════════════════════════════════════════════════════════")
	if hasLinkerd {
		loot.Section("Network-Admission-Policy-Enumeration").Add("# [DETECTED] Linkerd policies found")
	} else {
		loot.Section("Network-Admission-Policy-Enumeration").Add("# [NOT DETECTED] No Linkerd policies found (commands may error)")
	}
	loot.Section("Network-Admission-Policy-Enumeration").Add("")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# List Linkerd Server resources:")
	loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get servers.policy.linkerd.io -A")
	loot.Section("Network-Admission-Policy-Enumeration").Add("")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# List Linkerd ServerAuthorizations:")
	loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get serverauthorizations.policy.linkerd.io -A")
	loot.Section("Network-Admission-Policy-Enumeration").Add("")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# List Linkerd AuthorizationPolicies:")
	loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get authorizationpolicies.policy.linkerd.io -A")
	loot.Section("Network-Admission-Policy-Enumeration").Add("")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# Get detailed YAML:")
	loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get servers.policy.linkerd.io -A -o yaml")
	loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get serverauthorizations.policy.linkerd.io -A -o yaml")
	loot.Section("Network-Admission-Policy-Enumeration").Add("")

	// AWS Security Groups
	loot.Section("Network-Admission-Policy-Enumeration").Add("# ═══════════════════════════════════════════════════════════")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# AWS VPC CNI SECURITY GROUP POLICIES")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# ═══════════════════════════════════════════════════════════")
	if hasAWSSecurityGroup {
		loot.Section("Network-Admission-Policy-Enumeration").Add("# [DETECTED] AWS SecurityGroupPolicies found")
	} else {
		loot.Section("Network-Admission-Policy-Enumeration").Add("# [NOT DETECTED] No AWS SecurityGroupPolicies found (commands may error)")
	}
	loot.Section("Network-Admission-Policy-Enumeration").Add("")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# List AWS SecurityGroupPolicies:")
	loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get securitygrouppolicies.vpcresources.k8s.aws -A")
	loot.Section("Network-Admission-Policy-Enumeration").Add("")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# Get detailed YAML:")
	loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get securitygrouppolicies.vpcresources.k8s.aws -A -o yaml")
	loot.Section("Network-Admission-Policy-Enumeration").Add("")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# Check AWS CLI for security group details (requires AWS credentials):")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# aws ec2 describe-security-groups --group-ids <sg-id>")
	loot.Section("Network-Admission-Policy-Enumeration").Add("")

	// OpenShift Egress
	loot.Section("Network-Admission-Policy-Enumeration").Add("# ═══════════════════════════════════════════════════════════")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# OPENSHIFT EGRESS POLICIES")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# ═══════════════════════════════════════════════════════════")
	if hasOpenShiftEgress {
		loot.Section("Network-Admission-Policy-Enumeration").Add("# [DETECTED] OpenShift EgressFirewalls found")
	} else {
		loot.Section("Network-Admission-Policy-Enumeration").Add("# [NOT DETECTED] No OpenShift egress policies found (commands may error)")
	}
	loot.Section("Network-Admission-Policy-Enumeration").Add("")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# List OVN-Kubernetes EgressFirewalls:")
	loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get egressfirewalls.k8s.ovn.org -A")
	loot.Section("Network-Admission-Policy-Enumeration").Add("")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# List legacy EgressNetworkPolicies:")
	loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get egressnetworkpolicies.network.openshift.io -A")
	loot.Section("Network-Admission-Policy-Enumeration").Add("")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# Get detailed YAML:")
	loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get egressfirewalls.k8s.ovn.org -A -o yaml")
	loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get egressnetworkpolicies.network.openshift.io -A -o yaml")
	loot.Section("Network-Admission-Policy-Enumeration").Add("")

	// Consul Connect
	loot.Section("Network-Admission-Policy-Enumeration").Add("# ═══════════════════════════════════════════════════════════")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# HASHICORP CONSUL CONNECT INTENTIONS")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# ═══════════════════════════════════════════════════════════")
	if hasConsulConnect {
		loot.Section("Network-Admission-Policy-Enumeration").Add("# [DETECTED] Consul ServiceIntentions found")
	} else {
		loot.Section("Network-Admission-Policy-Enumeration").Add("# [NOT DETECTED] No Consul intentions found (commands may error)")
	}
	loot.Section("Network-Admission-Policy-Enumeration").Add("")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# List Consul ServiceIntentions:")
	loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get serviceintentions.consul.hashicorp.com -A")
	loot.Section("Network-Admission-Policy-Enumeration").Add("")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# List Consul IngressGateways:")
	loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get ingressgateways.consul.hashicorp.com -A")
	loot.Section("Network-Admission-Policy-Enumeration").Add("")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# Get detailed YAML:")
	loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get serviceintentions.consul.hashicorp.com -A -o yaml")
	loot.Section("Network-Admission-Policy-Enumeration").Add("")

	// Kuma Mesh
	loot.Section("Network-Admission-Policy-Enumeration").Add("# ═══════════════════════════════════════════════════════════")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# KUMA/KONG MESH POLICIES")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# ═══════════════════════════════════════════════════════════")
	if hasKumaMesh {
		loot.Section("Network-Admission-Policy-Enumeration").Add("# [DETECTED] Kuma MeshTrafficPermissions found")
	} else {
		loot.Section("Network-Admission-Policy-Enumeration").Add("# [NOT DETECTED] No Kuma policies found (commands may error)")
	}
	loot.Section("Network-Admission-Policy-Enumeration").Add("")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# List Kuma MeshTrafficPermissions:")
	loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get meshtrafficpermissions.kuma.io -A")
	loot.Section("Network-Admission-Policy-Enumeration").Add("")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# List Kuma TrafficPermissions (legacy):")
	loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get trafficpermissions.kuma.io -A")
	loot.Section("Network-Admission-Policy-Enumeration").Add("")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# Get detailed YAML:")
	loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get meshtrafficpermissions.kuma.io -A -o yaml")
	loot.Section("Network-Admission-Policy-Enumeration").Add("")

	// SMI (Service Mesh Interface)
	loot.Section("Network-Admission-Policy-Enumeration").Add("# ═══════════════════════════════════════════════════════════")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# SMI (SERVICE MESH INTERFACE) POLICIES")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# ═══════════════════════════════════════════════════════════")
	if hasSMI {
		loot.Section("Network-Admission-Policy-Enumeration").Add("# [DETECTED] SMI TrafficTargets found")
	} else {
		loot.Section("Network-Admission-Policy-Enumeration").Add("# [NOT DETECTED] No SMI policies found (commands may error)")
	}
	loot.Section("Network-Admission-Policy-Enumeration").Add("")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# List SMI TrafficTargets (access control):")
	loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get traffictargets.access.smi-spec.io -A")
	loot.Section("Network-Admission-Policy-Enumeration").Add("")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# List SMI TrafficSplits (traffic routing):")
	loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get trafficsplits.split.smi-spec.io -A")
	loot.Section("Network-Admission-Policy-Enumeration").Add("")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# Get detailed YAML:")
	loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get traffictargets.access.smi-spec.io -A -o yaml")
	loot.Section("Network-Admission-Policy-Enumeration").Add("")

	// Gloo Mesh
	loot.Section("Network-Admission-Policy-Enumeration").Add("# ═══════════════════════════════════════════════════════════")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# GLOO MESH POLICIES")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# ═══════════════════════════════════════════════════════════")
	if hasGlooMesh {
		loot.Section("Network-Admission-Policy-Enumeration").Add("# [DETECTED] Gloo Mesh AccessPolicies found")
	} else {
		loot.Section("Network-Admission-Policy-Enumeration").Add("# [NOT DETECTED] No Gloo Mesh policies found (commands may error)")
	}
	loot.Section("Network-Admission-Policy-Enumeration").Add("")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# List Gloo Mesh AccessPolicies:")
	loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get accesspolicies.security.policy.gloo.solo.io -A")
	loot.Section("Network-Admission-Policy-Enumeration").Add("")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# List Gloo Mesh TrafficPolicies:")
	loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get trafficpolicies.networking.mesh.gloo.solo.io -A")
	loot.Section("Network-Admission-Policy-Enumeration").Add("")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# Get detailed YAML:")
	loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get accesspolicies.security.policy.gloo.solo.io -A -o yaml")
	loot.Section("Network-Admission-Policy-Enumeration").Add("")

	// VMware NSX-T
	loot.Section("Network-Admission-Policy-Enumeration").Add("# ═══════════════════════════════════════════════════════════")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# VMWARE NSX-T SECURITY POLICIES")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# ═══════════════════════════════════════════════════════════")
	if hasNSXT {
		loot.Section("Network-Admission-Policy-Enumeration").Add("# [DETECTED] NSX-T SecurityPolicies found")
	} else {
		loot.Section("Network-Admission-Policy-Enumeration").Add("# [NOT DETECTED] No NSX-T policies found (commands may error)")
	}
	loot.Section("Network-Admission-Policy-Enumeration").Add("")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# List NSX-T SecurityPolicies:")
	loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get securitypolicies.nsx.vmware.com -A")
	loot.Section("Network-Admission-Policy-Enumeration").Add("")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# Get detailed YAML:")
	loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get securitypolicies.nsx.vmware.com -A -o yaml")
	loot.Section("Network-Admission-Policy-Enumeration").Add("")

	// GCP Backend Policies (Cloud Armor)
	loot.Section("Network-Admission-Policy-Enumeration").Add("# ═══════════════════════════════════════════════════════════")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# GCP/GKE BACKEND POLICIES (CLOUD ARMOR)")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# ═══════════════════════════════════════════════════════════")
	if hasGCPBackend {
		loot.Section("Network-Admission-Policy-Enumeration").Add("# [DETECTED] GCP BackendPolicies found")
	} else {
		loot.Section("Network-Admission-Policy-Enumeration").Add("# [NOT DETECTED] No GCP BackendPolicies found (commands may error)")
	}
	loot.Section("Network-Admission-Policy-Enumeration").Add("")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# List GCP BackendPolicies:")
	loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get gcpbackendpolicies.networking.gke.io -A")
	loot.Section("Network-Admission-Policy-Enumeration").Add("")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# Get detailed YAML:")
	loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get gcpbackendpolicies.networking.gke.io -A -o yaml")
	loot.Section("Network-Admission-Policy-Enumeration").Add("")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# Check Cloud Armor policies via gcloud (requires GCP credentials):")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# gcloud compute security-policies list")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# gcloud compute security-policies describe <policy-name>")
	loot.Section("Network-Admission-Policy-Enumeration").Add("")

	// Azure Network Policies
	loot.Section("Network-Admission-Policy-Enumeration").Add("# ═══════════════════════════════════════════════════════════")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# AZURE/AKS NETWORK CONFIGURATIONS")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# ═══════════════════════════════════════════════════════════")
	if hasAzureNetwork {
		loot.Section("Network-Admission-Policy-Enumeration").Add("# [DETECTED] Azure network configurations found")
	} else {
		loot.Section("Network-Admission-Policy-Enumeration").Add("# [NOT DETECTED] No Azure configurations found (commands may error)")
	}
	loot.Section("Network-Admission-Policy-Enumeration").Add("")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# List Azure Ingress Prohibited Targets:")
	loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get azureingressprohibitedtargets.appgw.ingress.k8s.io -A")
	loot.Section("Network-Admission-Policy-Enumeration").Add("")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# List Azure Identity Bindings:")
	loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get azureidentitybindings.aadpodidentity.k8s.io -A")
	loot.Section("Network-Admission-Policy-Enumeration").Add("")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# Get detailed YAML:")
	loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get azureingressprohibitedtargets.appgw.ingress.k8s.io -A -o yaml")
	loot.Section("Network-Admission-Policy-Enumeration").Add("")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# Check Azure NSG via az CLI (requires Azure credentials):")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# az network nsg list")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# az network nsg rule list --nsg-name <nsg-name> -g <resource-group>")
	loot.Section("Network-Admission-Policy-Enumeration").Add("")

	// Quick reference summary
	loot.Section("Network-Admission-Policy-Enumeration").Add("# ═══════════════════════════════════════════════════════════")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# QUICK ENUMERATION (ALL DETECTED ENGINES)")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# ═══════════════════════════════════════════════════════════")
	loot.Section("Network-Admission-Policy-Enumeration").Add("# Run these commands to quickly enumerate all detected policies:")
	loot.Section("Network-Admission-Policy-Enumeration").Add("")

	if hasK8sNetworkPolicy {
		loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get networkpolicies -A -o wide")
	}
	if hasCalico {
		loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get networkpolicies.crd.projectcalico.org -A -o wide")
		loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get globalnetworkpolicies.crd.projectcalico.org -o wide")
	}
	if hasCilium {
		loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get ciliumnetworkpolicies -A -o wide")
		loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get ciliumclusterwidenetworkpolicies -o wide")
	}
	if hasAntrea {
		loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get networkpolicies.crd.antrea.io -A -o wide")
		loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get clusternetworkpolicies.crd.antrea.io -o wide")
	}
	if hasIstio {
		loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get authorizationpolicies.security.istio.io -A -o wide")
	}
	if hasLinkerd {
		loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get servers.policy.linkerd.io -A -o wide")
		loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get serverauthorizations.policy.linkerd.io -A -o wide")
	}
	if hasAWSSecurityGroup {
		loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get securitygrouppolicies.vpcresources.k8s.aws -A -o wide")
	}
	if hasOpenShiftEgress {
		loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get egressfirewalls.k8s.ovn.org -A -o wide")
	}
	if hasConsulConnect {
		loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get serviceintentions.consul.hashicorp.com -A -o wide")
	}
	if hasKumaMesh {
		loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get meshtrafficpermissions.kuma.io -A -o wide")
	}
	if hasSMI {
		loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get traffictargets.access.smi-spec.io -A -o wide")
	}
	if hasGlooMesh {
		loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get accesspolicies.security.policy.gloo.solo.io -A -o wide")
	}
	if hasNSXT {
		loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get securitypolicies.nsx.vmware.com -A -o wide")
	}
	if hasGCPBackend {
		loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get gcpbackendpolicies.networking.gke.io -A -o wide")
	}
	if hasAzureNetwork {
		loot.Section("Network-Admission-Policy-Enumeration").Add("kubectl get azureingressprohibitedtargets.appgw.ingress.k8s.io -A -o wide")
	}

	loot.Section("Network-Admission-Policy-Enumeration").Add("")
}
