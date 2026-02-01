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
	"github.com/BishopFox/cloudfox/kubernetes/shared/admission"
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

Kubernetes Network Policies:
  - Native NetworkPolicies with comprehensive security analysis
  - Coverage gap identification (namespaces/pods without policies)
  - Policy weakness detection (overly permissive rules)
  - Default-deny policy recommendations

CNI-Specific Policies:
  - Calico NetworkPolicy and GlobalNetworkPolicy
  - Cilium NetworkPolicy and CiliumClusterwideNetworkPolicy
  - Antrea NetworkPolicy and ClusterNetworkPolicy

Service Mesh Policies:
  - Istio AuthorizationPolicy
  - Linkerd Server and ServerAuthorization

Security Analysis:
  - Lateral movement opportunity analysis
  - Data exfiltration risk assessment
  - Metadata API access detection (169.254.169.254)

Cloud-Specific Network Policies (in-cluster detection):
  Detects cloud-specific network policies from in-cluster CRDs.
  No --cloud-provider flag required - reads CRDs directly.

  AWS EKS:
    - VPC CNI SecurityGroupPolicy (pod-level security groups)
    - AWS security group attachments to pods

  GCP GKE:
    - GCPBackendPolicy (Cloud Armor, IAP integration)
    - GCPGatewayPolicy (Gateway API security)
    - HealthCheckPolicy

  Azure AKS:
    - AzureIngressProhibitedTarget (AGIC configuration)
    - AzureIdentity/AzureIdentityBinding (AAD Pod Identity)
    - Azure CNI network policy integration

Examples:
  cloudfox kubernetes network-admission
  cloudfox kubernetes network-admission --detailed`,
	Run: ListNetworkAdmission,
}

// init() removed - detailed flag is now a global persistent flag in cli/kubernetes.go

// NetworkPoliciesCmd is an alias for backwards compatibility
var NetworkPoliciesCmd = NetworkAdmissionCmd

type NetworkAdmissionOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t NetworkAdmissionOutput) TableFiles() []internal.TableFile { return t.Table }
func (t NetworkAdmissionOutput) LootFiles() []internal.LootFile   { return t.Loot }

type NetworkEnumeratedPolicy struct {
	Namespace string
	Tool      string
	Name      string
	Scope     string
	Type      string
	Details   string
}

// NetworkAdmissionFinding represents comprehensive network policy analysis for a namespace
type NetworkAdmissionFinding struct {
	// Basic Info
	Namespace string
	Age       string

	// Security Analysis
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
	ImageVerified         bool // True if Istio proxy/control plane image was verified
}

// LinkerdPolicyInfo represents Linkerd Server/ServerAuthorization
type LinkerdPolicyInfo struct {
	Name          string
	Namespace     string
	Kind          string // Server, ServerAuthorization, AuthorizationPolicy
	Selector      string
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
		if admission.VerifyControllerImage(image, sdkEngine) {
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
	detailed := globals.K8sDetailed

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

	// Analyze policy engine network constraints (Gatekeeper, Kyverno, Kubewarden)
	logger.InfoM("Analyzing Gatekeeper network constraints...", globals.K8S_NETWORK_ADMISSION_MODULE_NAME)
	allGatekeeperNetworkConstraints := analyzeGatekeeperNetworkConstraints(ctx, dynClient)
	if len(allGatekeeperNetworkConstraints) > 0 {
		logger.InfoM(fmt.Sprintf("Found %d Gatekeeper network constraints", len(allGatekeeperNetworkConstraints)), globals.K8S_NETWORK_ADMISSION_MODULE_NAME)
	}

	logger.InfoM("Analyzing Kyverno network policies...", globals.K8S_NETWORK_ADMISSION_MODULE_NAME)
	allKyvernoNetworkPolicies := analyzeKyvernoNetworkPolicies(ctx, dynClient)
	if len(allKyvernoNetworkPolicies) > 0 {
		logger.InfoM(fmt.Sprintf("Found %d Kyverno network policies", len(allKyvernoNetworkPolicies)), globals.K8S_NETWORK_ADMISSION_MODULE_NAME)
	}

	logger.InfoM("Analyzing Kubewarden network policies...", globals.K8S_NETWORK_ADMISSION_MODULE_NAME)
	allKubewardenNetworkPolicies := analyzeKubewardenNetworkPolicies(ctx, dynClient)
	if len(allKubewardenNetworkPolicies) > 0 {
		logger.InfoM(fmt.Sprintf("Found %d Kubewarden network policies", len(allKubewardenNetworkPolicies)), globals.K8S_NETWORK_ADMISSION_MODULE_NAME)
	}

	// Analyze CNAPP platform network policies
	logger.InfoM("Analyzing Aqua network policies...", globals.K8S_NETWORK_ADMISSION_MODULE_NAME)
	allAquaNetworkPolicies := analyzeAquaNetworkPolicies(ctx, dynClient)
	if len(allAquaNetworkPolicies) > 0 {
		logger.InfoM(fmt.Sprintf("Found %d Aqua network policies", len(allAquaNetworkPolicies)), globals.K8S_NETWORK_ADMISSION_MODULE_NAME)
	}

	logger.InfoM("Analyzing Prisma network policies...", globals.K8S_NETWORK_ADMISSION_MODULE_NAME)
	allPrismaNetworkPolicies := analyzePrismaNetworkPolicies(ctx, dynClient)
	if len(allPrismaNetworkPolicies) > 0 {
		logger.InfoM(fmt.Sprintf("Found %d Prisma network policies", len(allPrismaNetworkPolicies)), globals.K8S_NETWORK_ADMISSION_MODULE_NAME)
	}

	logger.InfoM("Analyzing Sysdig network policies...", globals.K8S_NETWORK_ADMISSION_MODULE_NAME)
	allSysdigNetworkPolicies := analyzeSysdigNetworkPolicies(ctx, dynClient)
	if len(allSysdigNetworkPolicies) > 0 {
		logger.InfoM(fmt.Sprintf("Found %d Sysdig network policies", len(allSysdigNetworkPolicies)), globals.K8S_NETWORK_ADMISSION_MODULE_NAME)
	}

	logger.InfoM("Analyzing StackRox network policies...", globals.K8S_NETWORK_ADMISSION_MODULE_NAME)
	allStackRoxNetworkPolicies := analyzeStackRoxNetworkPolicies(ctx, dynClient)
	if len(allStackRoxNetworkPolicies) > 0 {
		logger.InfoM(fmt.Sprintf("Found %d StackRox network policies", len(allStackRoxNetworkPolicies)), globals.K8S_NETWORK_ADMISSION_MODULE_NAME)
	}

	logger.InfoM("Analyzing NeuVector network policies...", globals.K8S_NETWORK_ADMISSION_MODULE_NAME)
	allNeuVectorNetworkPolicies := analyzeNeuVectorNetworkPolicies(ctx, dynClient)
	if len(allNeuVectorNetworkPolicies) > 0 {
		logger.InfoM(fmt.Sprintf("Found %d NeuVector network policies", len(allNeuVectorNetworkPolicies)), globals.K8S_NETWORK_ADMISSION_MODULE_NAME)
	}

	// Analyze multitenancy platform network policies
	logger.InfoM("Analyzing Capsule network policies...", globals.K8S_NETWORK_ADMISSION_MODULE_NAME)
	allCapsuleNetworkPolicies := analyzeCapsuleNetworkPolicies(ctx, dynClient)
	if len(allCapsuleNetworkPolicies) > 0 {
		logger.InfoM(fmt.Sprintf("Found %d Capsule network policies", len(allCapsuleNetworkPolicies)), globals.K8S_NETWORK_ADMISSION_MODULE_NAME)
	}

	logger.InfoM("Analyzing Rancher network policies...", globals.K8S_NETWORK_ADMISSION_MODULE_NAME)
	allRancherNetworkPolicies := analyzeRancherNetworkPolicies(ctx, dynClient)
	if len(allRancherNetworkPolicies) > 0 {
		logger.InfoM(fmt.Sprintf("Found %d Rancher network policies", len(allRancherNetworkPolicies)), globals.K8S_NETWORK_ADMISSION_MODULE_NAME)
	}

	// Analyze Polaris network checks
	logger.InfoM("Analyzing Polaris network checks...", globals.K8S_NETWORK_ADMISSION_MODULE_NAME)
	allPolarisNetworkChecks := analyzePolarisNetworkChecks(ctx, dynClient)
	if len(allPolarisNetworkChecks) > 0 {
		logger.InfoM(fmt.Sprintf("Found %d Polaris network checks", len(allPolarisNetworkChecks)), globals.K8S_NETWORK_ADMISSION_MODULE_NAME)
	}

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
	// Uniform header for all detailed policy tables
	// Schema: Namespace | Name | Scope | Target | Type | Configuration | Details | Issues
	uniformPolicyHeader := []string{
		"Namespace",
		"Name",
		"Scope",
		"Target",
		"Type",
		"Configuration",
		"Details",
		"Issues",
	}

	// Use uniform headers for all policy types
	k8sNetPolHeaders := uniformPolicyHeader
	calicoHeaders := uniformPolicyHeader
	ciliumHeaders := uniformPolicyHeader
	antreaHeaders := uniformPolicyHeader
	istioHeaders := uniformPolicyHeader
	linkerdHeaders := uniformPolicyHeader
	awsSGHeaders := uniformPolicyHeader
	openshiftEgressHeaders := uniformPolicyHeader
	consulHeaders := uniformPolicyHeader
	kumaHeaders := uniformPolicyHeader
	smiHeaders := uniformPolicyHeader
	glooHeaders := uniformPolicyHeader
	nsxtHeaders := uniformPolicyHeader
	gcpHeaders := uniformPolicyHeader
	azureHeaders := uniformPolicyHeader
	gatekeeperNetworkHeaders := uniformPolicyHeader
	kyvernoNetworkHeaders := uniformPolicyHeader
	kubewardenNetworkHeaders := uniformPolicyHeader
	cnappNetworkHeaders := uniformPolicyHeader
	capsuleNetworkHeaders := uniformPolicyHeader
	rancherNetworkHeaders := uniformPolicyHeader
	polarisNetworkHeaders := uniformPolicyHeader

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
	var gatekeeperNetworkRows [][]string
	var kyvernoNetworkRows [][]string
	var kubewardenNetworkRows [][]string
	var cnappNetworkRows [][]string
	var capsuleNetworkRows [][]string
	var rancherNetworkRows [][]string
	var polarisNetworkRows [][]string

	loot := shared.NewLootBuilder()

	// Initialize single loot section
	loot.Section("Network-Admission-Commands").SetHeader(`#####################################
##### Network Admission Enumeration
#####################################
#
# Network policies control pod-to-pod and pod-to-external traffic
# Multiple policy engines can be active simultaneously
#`)

	if globals.KubeContext != "" {
		loot.Section("Network-Admission-Commands").Addf("kubectl config use-context %s\n", globals.KubeContext)
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
		internetInStr := "Unrestricted"
		if finding.PolicyEngineBlocks.InternetIngressBlocked {
			internetInStr = "Blocked (" + strings.Join(finding.PolicyEngineBlocks.InternetIngressBlockedBy, ", ") + ")"
		} else if finding.HasDefaultDenyIngress {
			internetInStr = "Blocked (default-deny)"
		}

		// Internet Out column
		internetOutStr := "Unrestricted"
		if finding.PolicyEngineBlocks.InternetEgressBlocked {
			internetOutStr = "Blocked (" + strings.Join(finding.PolicyEngineBlocks.InternetEgressBlockedBy, ", ") + ")"
		} else if finding.HasDefaultDenyEgress {
			internetOutStr = "Blocked (default-deny)"
		}

		// Metadata API column
		metadataStr := "Unrestricted"
		if finding.PolicyEngineBlocks.MetadataAPIBlocked {
			metadataStr = "Blocked (" + strings.Join(finding.PolicyEngineBlocks.MetadataAPIBlockedBy, ", ") + ")"
		} else if finding.HasDefaultDenyEgress {
			metadataStr = "Blocked (default-deny)"
		}

		// Cross-NS column
		crossNSStr := "Unrestricted"
		if finding.PolicyEngineBlocks.CrossNSIngressBlocked && finding.PolicyEngineBlocks.CrossNSEgressBlocked {
			crossNSStr = "Blocked (In+Out)"
		} else if finding.PolicyEngineBlocks.CrossNSIngressBlocked {
			crossNSStr = "Partial (In blocked)"
		} else if finding.PolicyEngineBlocks.CrossNSEgressBlocked {
			crossNSStr = "Partial (Out blocked)"
		} else if finding.HasDefaultDenyIngress && finding.HasDefaultDenyEgress {
			crossNSStr = "Blocked (default-deny)"
		} else if finding.HasDefaultDenyIngress {
			crossNSStr = "Partial (In blocked)"
		} else if finding.HasDefaultDenyEgress {
			crossNSStr = "Partial (Out blocked)"
		}

		// Kube API column
		kubeAPIStr := "Unrestricted"
		if finding.PolicyEngineBlocks.KubeAPIEgressBlocked {
			kubeAPIStr = "Blocked (" + strings.Join(finding.PolicyEngineBlocks.KubeAPIEgressBlockedBy, ", ") + ")"
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
	// Uniform schema: Namespace | Name | Scope | Target | Type | Configuration | Details | Issues
	for _, policies := range allK8sNetPolicies {
		for _, p := range policies {
			// Type: direction type
			policyType := strings.Join(p.PolicyTypes, "/")
			if policyType == "" {
				policyType = "Ingress"
			}

			// Configuration: rules summary
			var config []string
			if p.DefaultDenyIngress {
				config = append(config, "Default deny ingress")
			}
			if p.DefaultDenyEgress {
				config = append(config, "Default deny egress")
			}
			if p.AllowsInternetIngress {
				config = append(config, "Allows internet in")
			}
			if p.AllowsInternetEgress {
				config = append(config, "Allows internet out")
			}
			if p.AllowsCrossNS {
				config = append(config, "Allows cross-NS")
			}
			if p.AllowsMetadataAPI {
				config = append(config, "Allows metadata API")
			}
			configStr := strings.Join(config, "; ")
			if configStr == "" {
				configStr = "-"
			}

			// Details
			details := fmt.Sprintf("Pods covered: %d", p.CoveredPods)

			// Detect issues
			var npIssues []string
			if !p.DefaultDenyIngress && !p.DefaultDenyEgress {
				npIssues = append(npIssues, "No default deny")
			}
			if p.AllowsInternetIngress {
				npIssues = append(npIssues, "Allows internet ingress")
			}
			if p.AllowsInternetEgress {
				npIssues = append(npIssues, "Allows internet egress")
			}
			if p.AllowsMetadataAPI {
				npIssues = append(npIssues, "Allows metadata API")
			}
			if p.CoveredPods == 0 {
				npIssues = append(npIssues, "No pods covered")
			}
			npIssuesStr := "<NONE>"
			if len(npIssues) > 0 {
				npIssuesStr = strings.Join(npIssues, "; ")
			}

			k8sNetPolRows = append(k8sNetPolRows, []string{
				p.Namespace,
				p.Name,
				"Namespace",
				p.PodSelector,
				policyType,
				configStr,
				details,
				npIssuesStr,
			})
		}
	}

	// Calico rows - Uniform schema: Namespace | Name | Scope | Target | Type | Configuration | Details | Issues
	for _, policies := range allCalicoPolicies {
		for _, p := range policies {
			scope := "Namespace"
			ns := p.Namespace
			if p.IsGlobal {
				scope = "Global"
				ns = "<CLUSTER>"
			}

			// Type: policy type/direction
			policyType := strings.Join(p.Types, "/")
			if policyType == "" {
				policyType = "Both"
			}

			// Configuration: rules summary
			var config []string
			if p.IsDefaultDeny {
				config = append(config, "Default deny")
			}
			if p.AllowsInternetIngress {
				config = append(config, "Allows internet in")
			}
			if p.AllowsInternetEgress {
				config = append(config, "Allows internet out")
			}
			configStr := strings.Join(config, "; ")
			if configStr == "" {
				configStr = fmt.Sprintf("Action: %s", p.Action)
			}

			// Details
			details := fmt.Sprintf("Order: %.0f", p.Order)

			// Detect issues
			var calicoIssues []string
			if !p.IsDefaultDeny {
				calicoIssues = append(calicoIssues, "No default deny")
			}
			if p.AllowsInternetIngress {
				calicoIssues = append(calicoIssues, "Allows internet ingress")
			}
			if p.AllowsInternetEgress {
				calicoIssues = append(calicoIssues, "Allows internet egress")
			}
			calicoIssuesStr := "<NONE>"
			if len(calicoIssues) > 0 {
				calicoIssuesStr = strings.Join(calicoIssues, "; ")
			}

			calicoRows = append(calicoRows, []string{
				ns,
				p.Name,
				scope,
				p.Selector,
				policyType,
				configStr,
				details,
				calicoIssuesStr,
			})
		}
	}
	for _, p := range calicoGlobalPolicies {
		// Type: policy type/direction
		policyType := strings.Join(p.Types, "/")
		if policyType == "" {
			policyType = "Both"
		}

		// Configuration: rules summary
		var config []string
		if p.IsDefaultDeny {
			config = append(config, "Default deny")
		}
		if p.AllowsInternetIngress {
			config = append(config, "Allows internet in")
		}
		if p.AllowsInternetEgress {
			config = append(config, "Allows internet out")
		}
		configStr := strings.Join(config, "; ")
		if configStr == "" {
			configStr = fmt.Sprintf("Action: %s", p.Action)
		}

		// Details
		details := fmt.Sprintf("Order: %.0f", p.Order)

		// Detect issues for global policies
		var calicoGlobalIssues []string
		if !p.IsDefaultDeny {
			calicoGlobalIssues = append(calicoGlobalIssues, "No default deny")
		}
		if p.AllowsInternetIngress {
			calicoGlobalIssues = append(calicoGlobalIssues, "Allows internet ingress")
		}
		if p.AllowsInternetEgress {
			calicoGlobalIssues = append(calicoGlobalIssues, "Allows internet egress")
		}
		calicoGlobalIssuesStr := "<NONE>"
		if len(calicoGlobalIssues) > 0 {
			calicoGlobalIssuesStr = strings.Join(calicoGlobalIssues, "; ")
		}

		calicoRows = append(calicoRows, []string{
			"<CLUSTER>",
			p.Name,
			"Global",
			p.Selector,
			policyType,
			configStr,
			details,
			calicoGlobalIssuesStr,
		})
	}

	// Cilium rows - Uniform schema: Namespace | Name | Scope | Target | Type | Configuration | Details | Issues
	for _, policies := range allCiliumPolicies {
		for _, p := range policies {
			scope := "Namespace"
			ns := p.Namespace
			if p.IsClusterwide {
				scope = "Clusterwide"
				ns = "<CLUSTER>"
			}

			// Type: direction type
			policyType := "Both"
			if p.IngressRuleCount > 0 && p.EgressRuleCount == 0 {
				policyType = "Ingress"
			} else if p.EgressRuleCount > 0 && p.IngressRuleCount == 0 {
				policyType = "Egress"
			}

			// Configuration: rules summary
			var config []string
			if p.IsDefaultDeny {
				config = append(config, "Default deny")
			}
			if p.AllowsInternetIngress {
				config = append(config, "Allows internet in")
			}
			if p.AllowsInternetEgress {
				config = append(config, "Allows internet out")
			}
			configStr := strings.Join(config, "; ")
			if configStr == "" {
				configStr = "-"
			}

			// Details (L7 info)
			details := "-"
			if p.HasL7Rules {
				details = fmt.Sprintf("L7: %s", strings.Join(p.L7Protocols, ", "))
			}

			// Detect issues
			var ciliumIssues []string
			if !p.IsDefaultDeny {
				ciliumIssues = append(ciliumIssues, "No default deny")
			}
			if p.AllowsInternetIngress {
				ciliumIssues = append(ciliumIssues, "Allows internet ingress")
			}
			if p.AllowsInternetEgress {
				ciliumIssues = append(ciliumIssues, "Allows internet egress")
			}
			ciliumIssuesStr := "<NONE>"
			if len(ciliumIssues) > 0 {
				ciliumIssuesStr = strings.Join(ciliumIssues, "; ")
			}

			ciliumRows = append(ciliumRows, []string{
				ns,
				p.Name,
				scope,
				p.EndpointSelector,
				policyType,
				configStr,
				details,
				ciliumIssuesStr,
			})
		}
	}
	for _, p := range ciliumClusterwidePolicies {
		// Type: direction type
		policyType := "Both"
		if p.IngressRuleCount > 0 && p.EgressRuleCount == 0 {
			policyType = "Ingress"
		} else if p.EgressRuleCount > 0 && p.IngressRuleCount == 0 {
			policyType = "Egress"
		}

		// Configuration: rules summary
		var config []string
		if p.IsDefaultDeny {
			config = append(config, "Default deny")
		}
		if p.AllowsInternetIngress {
			config = append(config, "Allows internet in")
		}
		if p.AllowsInternetEgress {
			config = append(config, "Allows internet out")
		}
		configStr := strings.Join(config, "; ")
		if configStr == "" {
			configStr = "-"
		}

		// Details (L7 info)
		details := "-"
		if p.HasL7Rules {
			details = fmt.Sprintf("L7: %s", strings.Join(p.L7Protocols, ", "))
		}

		// Detect issues for clusterwide policies
		var ciliumCWIssues []string
		if !p.IsDefaultDeny {
			ciliumCWIssues = append(ciliumCWIssues, "No default deny")
		}
		if p.AllowsInternetIngress {
			ciliumCWIssues = append(ciliumCWIssues, "Allows internet ingress")
		}
		if p.AllowsInternetEgress {
			ciliumCWIssues = append(ciliumCWIssues, "Allows internet egress")
		}
		ciliumCWIssuesStr := "<NONE>"
		if len(ciliumCWIssues) > 0 {
			ciliumCWIssuesStr = strings.Join(ciliumCWIssues, "; ")
		}

		ciliumRows = append(ciliumRows, []string{
			"<CLUSTER>",
			p.Name,
			"Clusterwide",
			p.EndpointSelector,
			policyType,
			configStr,
			details,
			ciliumCWIssuesStr,
		})
	}

	// Antrea rows - Uniform schema: Namespace | Name | Scope | Target | Type | Configuration | Details | Issues
	for _, policies := range allAntreaPolicies {
		for _, p := range policies {
			scope := "Namespace"
			ns := p.Namespace
			if p.IsCluster {
				scope = "Cluster"
				ns = "<CLUSTER>"
			}

			// Type: direction type
			policyType := "Both"
			if p.IngressRuleCount > 0 && p.EgressRuleCount == 0 {
				policyType = "Ingress"
			} else if p.EgressRuleCount > 0 && p.IngressRuleCount == 0 {
				policyType = "Egress"
			}

			// Configuration: rules summary
			configStr := fmt.Sprintf("Action: %s", p.Action)

			// Details
			details := fmt.Sprintf("Tier: %s, Priority: %.0f", p.Tier, p.Priority)

			// Detect issues
			var antreaIssues []string
			if p.Action == "Allow" {
				antreaIssues = append(antreaIssues, "Allow action (permissive)")
			}
			if p.IngressRuleCount == 0 && p.EgressRuleCount == 0 {
				antreaIssues = append(antreaIssues, "No rules defined")
			}
			antreaIssuesStr := "<NONE>"
			if len(antreaIssues) > 0 {
				antreaIssuesStr = strings.Join(antreaIssues, "; ")
			}

			antreaRows = append(antreaRows, []string{
				ns,
				p.Name,
				scope,
				p.AppliedTo,
				policyType,
				configStr,
				details,
				antreaIssuesStr,
			})
		}
	}
	for _, p := range antreaClusterPolicies {
		// Type: direction type
		policyType := "Both"
		if p.IngressRuleCount > 0 && p.EgressRuleCount == 0 {
			policyType = "Ingress"
		} else if p.EgressRuleCount > 0 && p.IngressRuleCount == 0 {
			policyType = "Egress"
		}

		// Configuration: rules summary
		configStr := fmt.Sprintf("Action: %s", p.Action)

		// Details
		details := fmt.Sprintf("Tier: %s, Priority: %.0f", p.Tier, p.Priority)

		// Detect issues for cluster policies
		var antreaCPIssues []string
		if p.Action == "Allow" {
			antreaCPIssues = append(antreaCPIssues, "Allow action (permissive)")
		}
		if p.IngressRuleCount == 0 && p.EgressRuleCount == 0 {
			antreaCPIssues = append(antreaCPIssues, "No rules defined")
		}
		antreaCPIssuesStr := "<NONE>"
		if len(antreaCPIssues) > 0 {
			antreaCPIssuesStr = strings.Join(antreaCPIssues, "; ")
		}

		antreaRows = append(antreaRows, []string{
			"<CLUSTER>",
			p.Name,
			"Cluster",
			p.AppliedTo,
			policyType,
			configStr,
			details,
			antreaCPIssuesStr,
		})
	}

	// Istio rows - Uniform schema: Namespace | Name | Scope | Target | Type | Configuration | Details | Issues
	for _, policies := range allIstioPolicies {
		for _, p := range policies {
			// Type: authorization policy type
			policyType := "AuthorizationPolicy"

			// Configuration: rules summary
			configStr := fmt.Sprintf("Action: %s", p.Action)

			// Details
			var detailParts []string
			if p.HasMTLS {
				detailParts = append(detailParts, "mTLS: enabled")
			} else {
				detailParts = append(detailParts, "mTLS: disabled")
			}
			details := strings.Join(detailParts, ", ")

			// Detect issues
			var istioIssues []string
			if p.Action == "ALLOW" {
				istioIssues = append(istioIssues, "Allow action")
			}
			if !p.HasMTLS {
				istioIssues = append(istioIssues, "No mTLS")
			}
			if p.Rules == 0 {
				istioIssues = append(istioIssues, "No rules defined")
			}
			istioIssuesStr := "<NONE>"
			if len(istioIssues) > 0 {
				istioIssuesStr = strings.Join(istioIssues, "; ")
			}

			istioRows = append(istioRows, []string{
				p.Namespace,
				p.Name,
				"Namespace",
				p.Selector,
				policyType,
				configStr,
				details,
				istioIssuesStr,
			})
		}
	}

	// Linkerd rows - Uniform schema: Namespace | Name | Scope | Target | Type | Configuration | Details | Issues
	for _, policies := range allLinkerdPolicies {
		for _, p := range policies {
			// Detect issues
			var linkerdIssues []string
			if p.Selector == "" || p.Selector == "*" {
				linkerdIssues = append(linkerdIssues, "Broad selector")
			}
			linkerdIssuesStr := "<NONE>"
			if len(linkerdIssues) > 0 {
				linkerdIssuesStr = strings.Join(linkerdIssues, "; ")
			}

			linkerdRows = append(linkerdRows, []string{
				p.Namespace,
				p.Name,
				"Namespace",
				p.Selector,
				p.Kind,
				"-",
				fmt.Sprintf("Kind: %s", p.Kind),
				linkerdIssuesStr,
			})
		}
	}

	// AWS SecurityGroupPolicy rows - Uniform schema: Namespace | Name | Scope | Target | Type | Configuration | Details | Issues
	for _, policies := range allAWSSecurityGroupPolicies {
		for _, p := range policies {
			// Type: security group policy
			policyType := "SecurityGroupPolicy"

			// Configuration: traffic rules
			configStr := "-"
			if p.AllowsAllTraffic {
				configStr = "Allows all traffic"
			}

			// Details - security group IDs
			details := strings.Join(p.SecurityGroupIDs, ", ")
			if details == "" {
				details = "No security groups"
			}

			// Detect issues
			var awsSGIssues []string
			if p.AllowsAllTraffic {
				awsSGIssues = append(awsSGIssues, "Allows all traffic")
			}
			if len(p.SecurityGroupIDs) == 0 {
				awsSGIssues = append(awsSGIssues, "No security groups")
			}
			awsSGIssuesStr := "<NONE>"
			if len(awsSGIssues) > 0 {
				awsSGIssuesStr = strings.Join(awsSGIssues, "; ")
			}

			awsSGRows = append(awsSGRows, []string{
				p.Namespace,
				p.Name,
				"Namespace",
				p.PodSelector,
				policyType,
				configStr,
				details,
				awsSGIssuesStr,
			})
		}
	}

	// OpenShift EgressFirewall rows - Uniform schema: Namespace | Name | Scope | Target | Type | Configuration | Details | Issues
	for _, policies := range allOpenShiftEgressPolicies {
		for _, p := range policies {
			// Type: egress firewall type
			policyType := "Egress"

			// Configuration: rules summary
			var config []string
			if p.AllowsInternet {
				config = append(config, "Allows internet")
			}
			if p.DeniesMetadataAPI {
				config = append(config, "Denies metadata API")
			}
			configStr := strings.Join(config, "; ")
			if configStr == "" {
				configStr = "-"
			}

			// Details
			details := fmt.Sprintf("Kind: %s", p.Kind)

			// Detect issues
			var ocpIssues []string
			if p.AllowsInternet {
				ocpIssues = append(ocpIssues, "Allows internet egress")
			}
			if !p.DeniesMetadataAPI {
				ocpIssues = append(ocpIssues, "Metadata API not denied")
			}
			if p.RuleCount == 0 {
				ocpIssues = append(ocpIssues, "No rules defined")
			}
			ocpIssuesStr := "<NONE>"
			if len(ocpIssues) > 0 {
				ocpIssuesStr = strings.Join(ocpIssues, "; ")
			}

			openshiftEgressRows = append(openshiftEgressRows, []string{
				p.Namespace,
				p.Name,
				"Namespace",
				"All pods",
				policyType,
				configStr,
				details,
				ocpIssuesStr,
			})
		}
	}

	// Consul Connect rows - Uniform schema: Namespace | Name | Scope | Target | Type | Configuration | Details | Issues
	for _, policies := range allConsulConnectPolicies {
		for _, p := range policies {
			// Type: service intentions
			policyType := "ServiceIntentions"

			// Configuration: rules summary
			configStr := fmt.Sprintf("Action: %s", p.Action)
			if p.AllowsAllSources {
				configStr += "; Allows all sources"
			}

			// Details
			details := fmt.Sprintf("Destination: %s", p.Destination)

			// Detect issues
			var consulIssues []string
			if p.AllowsAllSources {
				consulIssues = append(consulIssues, "Allows all sources")
			}
			if p.Action == "allow" && p.SourceCount == 0 {
				consulIssues = append(consulIssues, "No source restrictions")
			}
			consulIssuesStr := "<NONE>"
			if len(consulIssues) > 0 {
				consulIssuesStr = strings.Join(consulIssues, "; ")
			}

			consulRows = append(consulRows, []string{
				p.Namespace,
				p.Name,
				"Namespace",
				p.Destination,
				policyType,
				configStr,
				details,
				consulIssuesStr,
			})
		}
	}

	// Kuma Mesh rows - Uniform schema: Namespace | Name | Scope | Target | Type | Configuration | Details | Issues
	for _, policies := range allKumaMeshPolicies {
		for _, p := range policies {
			// Type: mesh policy kind
			policyType := p.Kind

			// Configuration: rules summary
			configStr := fmt.Sprintf("Action: %s", p.Action)

			// Details
			details := fmt.Sprintf("Kind: %s", p.Kind)

			// Detect issues
			var kumaIssues []string
			if p.Action == "Allow" || p.Action == "allow" {
				kumaIssues = append(kumaIssues, "Allow action")
			}
			if p.RuleCount == 0 {
				kumaIssues = append(kumaIssues, "No rules defined")
			}
			kumaIssuesStr := "<NONE>"
			if len(kumaIssues) > 0 {
				kumaIssuesStr = strings.Join(kumaIssues, "; ")
			}

			kumaRows = append(kumaRows, []string{
				p.Namespace,
				p.Name,
				"Namespace",
				p.TargetRef,
				policyType,
				configStr,
				details,
				kumaIssuesStr,
			})
		}
	}

	// SMI rows - Uniform schema: Namespace | Name | Scope | Target | Type | Configuration | Details | Issues
	for _, policies := range allSMIPolicies {
		for _, p := range policies {
			// Type: SMI policy kind
			policyType := p.Kind

			// Configuration: rules summary
			configStr := "-"
			if p.AllowsAllSources {
				configStr = "Allows all sources"
			}

			// Details
			details := fmt.Sprintf("Kind: %s, Provider: %s", p.Kind, p.MeshProvider)

			// Detect issues
			var smiIssues []string
			if p.AllowsAllSources {
				smiIssues = append(smiIssues, "Allows all sources")
			}
			smiIssuesStr := "<NONE>"
			if len(smiIssues) > 0 {
				smiIssuesStr = strings.Join(smiIssues, "; ")
			}

			smiRows = append(smiRows, []string{
				p.Namespace,
				p.Name,
				"Namespace",
				p.DestinationService,
				policyType,
				configStr,
				details,
				smiIssuesStr,
			})
		}
	}

	// Gloo Mesh rows - Uniform schema: Namespace | Name | Scope | Target | Type | Configuration | Details | Issues
	for _, policies := range allGlooMeshPolicies {
		for _, p := range policies {
			// Type: gloo mesh policy kind
			policyType := p.Kind

			// Configuration: rules summary
			configStr := fmt.Sprintf("Action: %s", p.Action)

			// Details
			details := fmt.Sprintf("Kind: %s", p.Kind)

			// Detect issues
			var glooIssues []string
			if p.Action == "ALLOW" || p.Action == "allow" {
				glooIssues = append(glooIssues, "Allow action")
			}
			if p.RuleCount == 0 {
				glooIssues = append(glooIssues, "No rules defined")
			}
			glooIssuesStr := "<NONE>"
			if len(glooIssues) > 0 {
				glooIssuesStr = strings.Join(glooIssues, "; ")
			}

			glooRows = append(glooRows, []string{
				p.Namespace,
				p.Name,
				"Namespace",
				p.ApplyToRefs,
				policyType,
				configStr,
				details,
				glooIssuesStr,
			})
		}
	}

	// NSX-T rows - Uniform schema: Namespace | Name | Scope | Target | Type | Configuration | Details | Issues
	for _, policies := range allNSXTPolicies {
		for _, p := range policies {
			// Type: security policy
			policyType := "SecurityPolicy"

			// Configuration: rules summary
			configStr := fmt.Sprintf("Default: %s", p.DefaultAction)

			// Details
			details := fmt.Sprintf("Priority: %d", p.Priority)

			// Detect issues
			var nsxtIssues []string
			if p.DefaultAction == "ALLOW" || p.DefaultAction == "allow" {
				nsxtIssues = append(nsxtIssues, "Default allow action")
			}
			if p.RuleCount == 0 {
				nsxtIssues = append(nsxtIssues, "No rules defined")
			}
			nsxtIssuesStr := "<NONE>"
			if len(nsxtIssues) > 0 {
				nsxtIssuesStr = strings.Join(nsxtIssues, "; ")
			}

			nsxtRows = append(nsxtRows, []string{
				p.Namespace,
				p.Name,
				"Namespace",
				p.AppliedTo,
				policyType,
				configStr,
				details,
				nsxtIssuesStr,
			})
		}
	}

	// GCP Backend Policy rows - Uniform schema: Namespace | Name | Scope | Target | Type | Configuration | Details | Issues
	for _, policies := range allGCPBackendPolicies {
		for _, p := range policies {
			// Type: backend policy kind
			policyType := p.Kind

			// Configuration: rules summary
			var config []string
			if p.CloudArmorPolicy != "" {
				config = append(config, fmt.Sprintf("Cloud Armor: %s", p.CloudArmorPolicy))
			}
			if p.HasIAP {
				config = append(config, "IAP: enabled")
			}
			configStr := strings.Join(config, "; ")
			if configStr == "" {
				configStr = "-"
			}

			// Details
			details := fmt.Sprintf("Kind: %s", p.Kind)

			// Detect issues
			var gcpIssues []string
			if p.CloudArmorPolicy == "" {
				gcpIssues = append(gcpIssues, "No Cloud Armor policy")
			}
			if !p.HasIAP {
				gcpIssues = append(gcpIssues, "No IAP configured")
			}
			gcpIssuesStr := "<NONE>"
			if len(gcpIssues) > 0 {
				gcpIssuesStr = strings.Join(gcpIssues, "; ")
			}

			gcpRows = append(gcpRows, []string{
				p.Namespace,
				p.Name,
				"Namespace",
				p.TargetRef,
				policyType,
				configStr,
				details,
				gcpIssuesStr,
			})
		}
	}

	// Azure Network Policy rows - Uniform schema: Namespace | Name | Scope | Target | Type | Configuration | Details | Issues
	for _, policies := range allAzureNetworkPolicies {
		for _, p := range policies {
			// Type: azure policy kind
			policyType := p.Kind

			// Configuration: rules summary
			configStr := "-"
			if p.HasManagedIdentity {
				configStr = "Managed Identity: enabled"
			}

			// Details
			details := fmt.Sprintf("Kind: %s", p.Kind)

			// Detect issues
			var azureIssues []string
			if !p.HasManagedIdentity {
				azureIssues = append(azureIssues, "No managed identity")
			}
			azureIssuesStr := "<NONE>"
			if len(azureIssues) > 0 {
				azureIssuesStr = strings.Join(azureIssues, "; ")
			}

			azureRows = append(azureRows, []string{
				p.Namespace,
				p.Name,
				"Namespace",
				p.TargetService,
				policyType,
				configStr,
				details,
				azureIssuesStr,
			})
		}
	}

	// Gatekeeper Network Constraint rows - Uniform schema: Namespace | Name | Scope | Target | Type | Configuration | Details | Issues
	for _, c := range allGatekeeperNetworkConstraints {
		// Type: constraint kind
		policyType := c.Kind

		// Target namespaces
		target := "-"
		if len(c.MatchNamespaces) > 0 {
			if len(c.MatchNamespaces) > 3 {
				target = strings.Join(c.MatchNamespaces[:3], ", ") + "..."
			} else {
				target = strings.Join(c.MatchNamespaces, ", ")
			}
		}

		// Configuration: rules summary
		configStr := "-"
		if len(c.NetworkRules) > 0 {
			if len(c.NetworkRules) > 2 {
				configStr = strings.Join(c.NetworkRules[:2], "; ") + "..."
			} else {
				configStr = strings.Join(c.NetworkRules, "; ")
			}
		}

		// Details
		var detailParts []string
		detailParts = append(detailParts, fmt.Sprintf("Kind: %s", c.Kind))
		detailParts = append(detailParts, fmt.Sprintf("Enforcement: %s", c.EnforcementAction))
		if c.ViolationCount > 0 {
			detailParts = append(detailParts, fmt.Sprintf("Violations: %d", c.ViolationCount))
		}
		details := strings.Join(detailParts, ", ")

		// Detect issues
		var gkNetIssues []string
		if c.EnforcementAction == "dryrun" || c.EnforcementAction == "warn" {
			gkNetIssues = append(gkNetIssues, "Not enforcing ("+c.EnforcementAction+")")
		}
		if c.ViolationCount > 0 {
			gkNetIssues = append(gkNetIssues, fmt.Sprintf("%d violations", c.ViolationCount))
		}
		if len(c.ExcludeNamespaces) > 0 {
			gkNetIssues = append(gkNetIssues, "Has exclusions")
		}
		if len(c.NetworkRules) == 0 {
			gkNetIssues = append(gkNetIssues, "No network rules")
		}
		gkNetIssuesStr := "<NONE>"
		if len(gkNetIssues) > 0 {
			gkNetIssuesStr = strings.Join(gkNetIssues, "; ")
		}

		gatekeeperNetworkRows = append(gatekeeperNetworkRows, []string{
			"<CLUSTER>",
			c.Name,
			"Cluster",
			target,
			policyType,
			configStr,
			details,
			gkNetIssuesStr,
		})
	}

	// Kyverno Network Policy rows - Uniform schema: Namespace | Name | Scope | Target | Type | Configuration | Details | Issues
	for _, p := range allKyvernoNetworkPolicies {
		scope := "Namespace"
		ns := p.Namespace
		if p.IsClusterPolicy {
			scope = "Cluster"
			ns = "<CLUSTER>"
		}

		// Type: kyverno policy type
		policyType := "NetworkPolicy"
		if p.IsClusterPolicy {
			policyType = "ClusterPolicy"
		}

		// Configuration: rules summary
		configStr := "-"
		if len(p.NetworkRules) > 0 {
			if len(p.NetworkRules) > 2 {
				configStr = strings.Join(p.NetworkRules[:2], "; ") + "..."
			} else {
				configStr = strings.Join(p.NetworkRules, "; ")
			}
		}

		// Details
		var detailParts []string
		detailParts = append(detailParts, fmt.Sprintf("Action: %s", p.ValidationAction))
		if p.Background {
			detailParts = append(detailParts, "Background: enabled")
		}
		details := strings.Join(detailParts, ", ")

		// Detect issues
		var kyNetIssues []string
		if p.ValidationAction == "Audit" || p.ValidationAction == "audit" {
			kyNetIssues = append(kyNetIssues, "Audit mode (not enforcing)")
		}
		if !p.Background {
			kyNetIssues = append(kyNetIssues, "Background processing disabled")
		}
		if p.RuleCount == 0 {
			kyNetIssues = append(kyNetIssues, "No rules defined")
		}
		if len(p.NetworkRules) == 0 {
			kyNetIssues = append(kyNetIssues, "No network rules")
		}
		kyNetIssuesStr := "<NONE>"
		if len(kyNetIssues) > 0 {
			kyNetIssuesStr = strings.Join(kyNetIssues, "; ")
		}

		kyvernoNetworkRows = append(kyvernoNetworkRows, []string{
			ns,
			p.Name,
			scope,
			"All matching",
			policyType,
			configStr,
			details,
			kyNetIssuesStr,
		})
	}

	// Kubewarden Network Policy rows - Uniform schema: Namespace | Name | Scope | Target | Type | Configuration | Details | Issues
	for _, p := range allKubewardenNetworkPolicies {
		ns := p.Namespace
		if ns == "" {
			ns = "<CLUSTER>"
		}

		// Type: admission policy
		policyType := "AdmissionPolicy"

		// Configuration: rules summary
		configStr := "-"
		if len(p.NetworkRules) > 0 {
			if len(p.NetworkRules) > 2 {
				configStr = strings.Join(p.NetworkRules[:2], "; ") + "..."
			} else {
				configStr = strings.Join(p.NetworkRules, "; ")
			}
		}

		// Details
		module := p.Module
		if len(module) > 40 {
			module = module[:40] + "..."
		}
		details := fmt.Sprintf("Mode: %s, Server: %s, Module: %s", p.Mode, p.PolicyServer, module)

		// Detect issues
		var kwNetIssues []string
		if p.Mode == "monitor" {
			kwNetIssues = append(kwNetIssues, "Monitor mode (not enforcing)")
		}
		if p.Module == "" {
			kwNetIssues = append(kwNetIssues, "No module specified")
		}
		if len(p.NetworkRules) == 0 {
			kwNetIssues = append(kwNetIssues, "No network rules")
		}
		kwNetIssuesStr := "<NONE>"
		if len(kwNetIssues) > 0 {
			kwNetIssuesStr = strings.Join(kwNetIssues, "; ")
		}

		kubewardenNetworkRows = append(kubewardenNetworkRows, []string{
			ns,
			p.Name,
			"Namespace",
			"All matching",
			policyType,
			configStr,
			details,
			kwNetIssuesStr,
		})
	}

	// Build CNAPP Network Policy rows (Aqua, Prisma, Sysdig, StackRox, NeuVector)
	// Uniform schema: Namespace | Name | Scope | Target | Type | Configuration | Details | Issues
	allCNAPPPolicies := append(allAquaNetworkPolicies, allPrismaNetworkPolicies...)
	allCNAPPPolicies = append(allCNAPPPolicies, allSysdigNetworkPolicies...)
	allCNAPPPolicies = append(allCNAPPPolicies, allStackRoxNetworkPolicies...)
	allCNAPPPolicies = append(allCNAPPPolicies, allNeuVectorNetworkPolicies...)

	for _, p := range allCNAPPPolicies {
		scope := p.Scope
		if scope == "" {
			scope = "Namespace"
		}
		ns := p.Namespace
		if scope == "cluster-wide" || scope == "*" {
			ns = "<CLUSTER>"
			scope = "Cluster"
		}

		// Type: direction type
		policyType := "Both"
		if p.IngressRules > 0 && p.EgressRules == 0 {
			policyType = "Ingress"
		} else if p.EgressRules > 0 && p.IngressRules == 0 {
			policyType = "Egress"
		}

		// Configuration: rules summary
		var config []string
		if p.HasDefaultDeny {
			config = append(config, "Default deny")
		}
		configStr := strings.Join(config, "; ")
		if configStr == "" {
			configStr = "-"
		}

		// Details
		mode := p.Mode
		if mode == "" {
			mode = "enforce"
		}
		details := fmt.Sprintf("Platform: %s, Mode: %s", p.Platform, mode)

		// Detect issues
		var cnappIssues []string
		if !p.HasDefaultDeny {
			cnappIssues = append(cnappIssues, "No default deny")
		}
		if p.IngressRules == 0 && p.EgressRules == 0 {
			cnappIssues = append(cnappIssues, "No rules defined")
		}
		if mode == "audit" || mode == "monitor" || mode == "learn" {
			cnappIssues = append(cnappIssues, "Not enforcing")
		}
		issuesStr := "<NONE>"
		if len(cnappIssues) > 0 {
			issuesStr = strings.Join(cnappIssues, "; ")
		}

		cnappNetworkRows = append(cnappNetworkRows, []string{
			ns,
			p.Name,
			scope,
			"All matching",
			policyType,
			configStr,
			details,
			issuesStr,
		})
	}

	// Build Capsule Network Policy rows - Uniform schema: Namespace | Name | Scope | Target | Type | Configuration | Details | Issues
	for _, p := range allCapsuleNetworkPolicies {
		// Type: tenant policy
		policyType := "TenantPolicy"

		// Configuration: rules summary
		var config []string
		if p.HasNetworkIsolation {
			config = append(config, "Network isolation enabled")
		}
		if len(p.NetworkPolicies) > 0 {
			config = append(config, fmt.Sprintf("Policies: %s", strings.Join(p.NetworkPolicies, ", ")))
		}
		configStr := strings.Join(config, "; ")
		if configStr == "" {
			configStr = "-"
		}

		// Details
		var detailParts []string
		if len(p.AllowedExternalIPs) > 0 {
			detailParts = append(detailParts, fmt.Sprintf("External IPs: %s", strings.Join(p.AllowedExternalIPs, ", ")))
		}
		if len(p.IngressClasses) > 0 {
			detailParts = append(detailParts, fmt.Sprintf("Ingress: %s", strings.Join(p.IngressClasses, ", ")))
		}
		details := strings.Join(detailParts, ", ")
		if details == "" {
			details = "-"
		}

		// Detect issues
		var capsuleNetIssues []string
		if !p.HasNetworkIsolation {
			capsuleNetIssues = append(capsuleNetIssues, "No network isolation")
		}
		if len(p.NetworkPolicies) == 0 {
			capsuleNetIssues = append(capsuleNetIssues, "No network policies")
		}
		for _, ip := range p.AllowedExternalIPs {
			if ip == "*" || ip == "0.0.0.0/0" || ip == "::/0" {
				capsuleNetIssues = append(capsuleNetIssues, "Allows all external IPs")
				break
			}
		}
		issuesStr := "<NONE>"
		if len(capsuleNetIssues) > 0 {
			issuesStr = strings.Join(capsuleNetIssues, "; ")
		}

		capsuleNetworkRows = append(capsuleNetworkRows, []string{
			p.Namespace,
			p.TenantName,
			"Tenant",
			"All tenant pods",
			policyType,
			configStr,
			details,
			issuesStr,
		})
	}

	// Build Rancher Network Policy rows - Uniform schema: Namespace | Name | Scope | Target | Type | Configuration | Details | Issues
	for _, p := range allRancherNetworkPolicies {
		// Type: project policy
		policyType := "ProjectPolicy"

		// Configuration: rules summary
		var config []string
		if p.HasIsolation {
			config = append(config, "Network isolation enabled")
		}
		if p.NetworkPolicy != "" {
			config = append(config, fmt.Sprintf("Policy: %s", p.NetworkPolicy))
		}
		configStr := strings.Join(config, "; ")
		if configStr == "" {
			configStr = "-"
		}

		// Details
		details := fmt.Sprintf("Project: %s (%s)", p.ProjectName, p.ProjectID)
		if p.PSPTemplate != "" {
			details += fmt.Sprintf(", PSP: %s", p.PSPTemplate)
		}

		// Detect issues
		var rancherNetIssues []string
		if !p.HasIsolation {
			rancherNetIssues = append(rancherNetIssues, "No network isolation")
		}
		if p.NetworkPolicy == "" {
			rancherNetIssues = append(rancherNetIssues, "No network policy")
		}
		if p.PSPTemplate == "" {
			rancherNetIssues = append(rancherNetIssues, "No PSP template")
		}
		issuesStr := "<NONE>"
		if len(rancherNetIssues) > 0 {
			issuesStr = strings.Join(rancherNetIssues, "; ")
		}

		rancherNetworkRows = append(rancherNetworkRows, []string{
			p.Namespace,
			p.ProjectName,
			"Project",
			"All project pods",
			policyType,
			configStr,
			details,
			issuesStr,
		})
	}

	// Build Polaris Network Check rows - Uniform schema: Namespace | Name | Scope | Target | Type | Configuration | Details | Issues
	for _, p := range allPolarisNetworkChecks {
		// Type: polaris check
		policyType := "PolarisCheck"

		// Configuration: rules summary
		configStr := "-"
		if p.HasNetworkPolicy {
			configStr = "Network policy present"
		} else {
			configStr = "No network policy"
		}

		// Details
		details := fmt.Sprintf("Check: %s, Severity: %s, Category: %s", p.CheckName, p.Severity, p.Category)

		// Detect issues
		var polarisNetIssues []string
		if !p.HasNetworkPolicy {
			polarisNetIssues = append(polarisNetIssues, "No network policy")
		}
		if p.Severity == "danger" || p.Severity == "critical" || p.Severity == "high" {
			polarisNetIssues = append(polarisNetIssues, "High severity finding")
		}
		issuesStr := "<NONE>"
		if len(polarisNetIssues) > 0 {
			issuesStr = strings.Join(polarisNetIssues, "; ")
		}

		polarisNetworkRows = append(polarisNetworkRows, []string{
			p.Namespace,
			p.CheckID,
			"Namespace",
			"All pods",
			policyType,
			configStr,
			details,
			issuesStr,
		})
	}

	// Create unified policies table (merging all policy types)
	// Uniform schema: Namespace | Tool | Name | Scope | Type | Configuration | Details | Issues
	var unifiedPolicyRows [][]string
	unifiedPolicyHeaders := []string{"Namespace", "Tool", "Name", "Scope", "Type", "Configuration", "Details", "Issues"}

	// K8s NetworkPolicies
	for _, policies := range allK8sNetPolicies {
		for _, p := range policies {
			policyType := strings.Join(p.PolicyTypes, ",")
			if policyType == "" {
				policyType = "Ingress"
			}
			var config []string
			if p.DefaultDenyIngress || p.DefaultDenyEgress {
				config = append(config, "Default-Deny")
			}
			configStr := strings.Join(config, "; ")
			if configStr == "" {
				configStr = "-"
			}
			details := fmt.Sprintf("Ingress rules: %d, Egress rules: %d", p.IngressRuleCount, p.EgressRuleCount)
			var issues []string
			if !p.DefaultDenyIngress && !p.DefaultDenyEgress {
				issues = append(issues, "No default deny")
			}
			if p.AllowsInternetIngress {
				issues = append(issues, "Allows internet ingress")
			}
			issuesStr := "<NONE>"
			if len(issues) > 0 {
				issuesStr = strings.Join(issues, "; ")
			}
			unifiedPolicyRows = append(unifiedPolicyRows, []string{
				p.Namespace,
				"K8s NetworkPolicy",
				p.Name,
				"Namespace",
				policyType,
				configStr,
				details,
				issuesStr,
			})
		}
	}

	// Calico policies
	for _, policies := range allCalicoPolicies {
		for _, p := range policies {
			scope := "Namespace"
			ns := p.Namespace
			if p.IsGlobal {
				scope = "Global"
				ns = "<CLUSTER>"
			}
			policyType := strings.Join(p.Types, ",")
			if policyType == "" {
				policyType = "Both"
			}
			configStr := fmt.Sprintf("Action: %s", p.Action)
			details := fmt.Sprintf("Ingress rules: %d, Egress rules: %d", p.IngressRuleCount, p.EgressRuleCount)
			var issues []string
			if !p.IsDefaultDeny {
				issues = append(issues, "No default deny")
			}
			issuesStr := "<NONE>"
			if len(issues) > 0 {
				issuesStr = strings.Join(issues, "; ")
			}
			unifiedPolicyRows = append(unifiedPolicyRows, []string{
				ns,
				"Calico",
				p.Name,
				scope,
				policyType,
				configStr,
				details,
				issuesStr,
			})
		}
	}
	for _, p := range calicoGlobalPolicies {
		policyType := strings.Join(p.Types, ",")
		if policyType == "" {
			policyType = "Both"
		}
		configStr := fmt.Sprintf("Action: %s", p.Action)
		details := fmt.Sprintf("Ingress rules: %d, Egress rules: %d", p.IngressRuleCount, p.EgressRuleCount)
		issuesStr := "<NONE>"
		if !p.IsDefaultDeny {
			issuesStr = "No default deny"
		}
		unifiedPolicyRows = append(unifiedPolicyRows, []string{
			"<CLUSTER>",
			"Calico",
			p.Name,
			"Global",
			policyType,
			configStr,
			details,
			issuesStr,
		})
	}

	// Cilium policies
	for _, policies := range allCiliumPolicies {
		for _, p := range policies {
			scope := "Namespace"
			ns := p.Namespace
			if p.IsClusterwide {
				scope = "Clusterwide"
				ns = "<CLUSTER>"
			}
			policyType := "NetworkPolicy"
			configStr := "-"
			if p.IsDefaultDeny {
				configStr = "Default deny"
			}
			details := fmt.Sprintf("Ingress rules: %d, Egress rules: %d", p.IngressRuleCount, p.EgressRuleCount)
			if p.HasL7Rules {
				details += fmt.Sprintf(", L7: %s", strings.Join(p.L7Protocols, ", "))
			}
			issuesStr := "<NONE>"
			if !p.IsDefaultDeny {
				issuesStr = "No default deny"
			}
			unifiedPolicyRows = append(unifiedPolicyRows, []string{
				ns,
				"Cilium",
				p.Name,
				scope,
				policyType,
				configStr,
				details,
				issuesStr,
			})
		}
	}
	for _, p := range ciliumClusterwidePolicies {
		configStr := "-"
		if p.IsDefaultDeny {
			configStr = "Default deny"
		}
		details := fmt.Sprintf("Ingress rules: %d, Egress rules: %d", p.IngressRuleCount, p.EgressRuleCount)
		if p.HasL7Rules {
			details += fmt.Sprintf(", L7: %s", strings.Join(p.L7Protocols, ", "))
		}
		issuesStr := "<NONE>"
		if !p.IsDefaultDeny {
			issuesStr = "No default deny"
		}
		unifiedPolicyRows = append(unifiedPolicyRows, []string{
			"<CLUSTER>",
			"Cilium",
			p.Name,
			"Clusterwide",
			"NetworkPolicy",
			configStr,
			details,
			issuesStr,
		})
	}

	// Antrea policies
	for _, policies := range allAntreaPolicies {
		for _, p := range policies {
			scope := "Namespace"
			ns := p.Namespace
			if p.IsCluster {
				scope = "Cluster"
				ns = "<CLUSTER>"
			}
			configStr := fmt.Sprintf("Action: %s, Tier: %s", p.Action, p.Tier)
			details := fmt.Sprintf("Ingress rules: %d, Egress rules: %d", p.IngressRuleCount, p.EgressRuleCount)
			issuesStr := "<NONE>"
			if p.Action == "Allow" {
				issuesStr = "Allow action (permissive)"
			}
			unifiedPolicyRows = append(unifiedPolicyRows, []string{
				ns,
				"Antrea",
				p.Name,
				scope,
				"NetworkPolicy",
				configStr,
				details,
				issuesStr,
			})
		}
	}
	for _, p := range antreaClusterPolicies {
		configStr := fmt.Sprintf("Action: %s, Tier: %s", p.Action, p.Tier)
		details := fmt.Sprintf("Ingress rules: %d, Egress rules: %d", p.IngressRuleCount, p.EgressRuleCount)
		issuesStr := "<NONE>"
		if p.Action == "Allow" {
			issuesStr = "Allow action (permissive)"
		}
		unifiedPolicyRows = append(unifiedPolicyRows, []string{
			"<CLUSTER>",
			"Antrea",
			p.Name,
			"Cluster",
			"NetworkPolicy",
			configStr,
			details,
			issuesStr,
		})
	}

	// Istio policies
	for _, policies := range allIstioPolicies {
		for _, p := range policies {
			configStr := fmt.Sprintf("Action: %s", p.Action)
			if p.HasMTLS {
				configStr += ", mTLS: enabled"
			}
			details := fmt.Sprintf("Rules: %d", p.Rules)
			var issues []string
			if p.Action == "ALLOW" {
				issues = append(issues, "Allow action")
			}
			if !p.HasMTLS {
				issues = append(issues, "No mTLS")
			}
			issuesStr := "<NONE>"
			if len(issues) > 0 {
				issuesStr = strings.Join(issues, "; ")
			}
			unifiedPolicyRows = append(unifiedPolicyRows, []string{
				p.Namespace,
				"Istio",
				p.Name,
				"Namespace",
				"AuthorizationPolicy",
				configStr,
				details,
				issuesStr,
			})
		}
	}

	// Linkerd policies
	for _, policies := range allLinkerdPolicies {
		for _, p := range policies {
			issuesStr := "<NONE>"
			if p.Selector == "" || p.Selector == "*" {
				issuesStr = "Broad selector"
			}
			unifiedPolicyRows = append(unifiedPolicyRows, []string{
				p.Namespace,
				"Linkerd",
				p.Name,
				"Namespace",
				p.Kind,
				"-",
				fmt.Sprintf("Kind: %s", p.Kind),
				issuesStr,
			})
		}
	}

	// AWS SecurityGroupPolicy
	for _, policies := range allAWSSecurityGroupPolicies {
		for _, p := range policies {
			configStr := "-"
			if p.AllowsAllTraffic {
				configStr = "Allows all traffic"
			}
			details := fmt.Sprintf("Security Groups: %s", strings.Join(p.SecurityGroupIDs, ", "))
			issuesStr := "<NONE>"
			if p.AllowsAllTraffic {
				issuesStr = "Allows all traffic"
			}
			unifiedPolicyRows = append(unifiedPolicyRows, []string{
				p.Namespace,
				"AWS VPC CNI",
				p.Name,
				"Namespace",
				"SecurityGroupPolicy",
				configStr,
				details,
				issuesStr,
			})
		}
	}

	// OpenShift EgressFirewall
	for _, policies := range allOpenShiftEgressPolicies {
		for _, p := range policies {
			configStr := "-"
			if p.AllowsInternet {
				configStr = "Allows internet"
			}
			details := fmt.Sprintf("Rules: %d", p.RuleCount)
			issuesStr := "<NONE>"
			if p.AllowsInternet {
				issuesStr = "Allows internet egress"
			}
			unifiedPolicyRows = append(unifiedPolicyRows, []string{
				p.Namespace,
				"OpenShift",
				p.Name,
				"Namespace",
				p.Kind,
				configStr,
				details,
				issuesStr,
			})
		}
	}

	// Consul Connect
	for _, policies := range allConsulConnectPolicies {
		for _, p := range policies {
			configStr := fmt.Sprintf("Action: %s", p.Action)
			details := fmt.Sprintf("Sources: %d", p.SourceCount)
			issuesStr := "<NONE>"
			if p.AllowsAllSources {
				issuesStr = "Allows all sources"
			}
			unifiedPolicyRows = append(unifiedPolicyRows, []string{
				p.Namespace,
				"Consul Connect",
				p.Name,
				"Namespace",
				"ServiceIntentions",
				configStr,
				details,
				issuesStr,
			})
		}
	}

	// Kuma Mesh
	for _, policies := range allKumaMeshPolicies {
		for _, p := range policies {
			configStr := fmt.Sprintf("Action: %s", p.Action)
			details := fmt.Sprintf("Rules: %d", p.RuleCount)
			issuesStr := "<NONE>"
			if p.Action == "Allow" || p.Action == "allow" {
				issuesStr = "Allow action"
			}
			unifiedPolicyRows = append(unifiedPolicyRows, []string{
				p.Namespace,
				"Kuma/Kong Mesh",
				p.Name,
				"Namespace",
				p.Kind,
				configStr,
				details,
				issuesStr,
			})
		}
	}

	// SMI policies
	for _, policies := range allSMIPolicies {
		for _, p := range policies {
			configStr := "-"
			if p.AllowsAllSources {
				configStr = "Allows all sources"
			}
			details := fmt.Sprintf("Provider: %s", p.MeshProvider)
			issuesStr := "<NONE>"
			if p.AllowsAllSources {
				issuesStr = "Allows all sources"
			}
			unifiedPolicyRows = append(unifiedPolicyRows, []string{
				p.Namespace,
				"SMI",
				p.Name,
				"Namespace",
				p.Kind,
				configStr,
				details,
				issuesStr,
			})
		}
	}

	// Gloo Mesh
	for _, policies := range allGlooMeshPolicies {
		for _, p := range policies {
			configStr := fmt.Sprintf("Action: %s", p.Action)
			details := fmt.Sprintf("Rules: %d", p.RuleCount)
			issuesStr := "<NONE>"
			if p.Action == "ALLOW" || p.Action == "allow" {
				issuesStr = "Allow action"
			}
			unifiedPolicyRows = append(unifiedPolicyRows, []string{
				p.Namespace,
				"Gloo Mesh",
				p.Name,
				"Namespace",
				p.Kind,
				configStr,
				details,
				issuesStr,
			})
		}
	}

	// NSX-T
	for _, policies := range allNSXTPolicies {
		for _, p := range policies {
			configStr := fmt.Sprintf("Default: %s", p.DefaultAction)
			details := fmt.Sprintf("Rules: %d, Priority: %d", p.RuleCount, p.Priority)
			issuesStr := "<NONE>"
			if p.DefaultAction == "ALLOW" || p.DefaultAction == "allow" {
				issuesStr = "Default allow action"
			}
			unifiedPolicyRows = append(unifiedPolicyRows, []string{
				p.Namespace,
				"VMware NSX-T",
				p.Name,
				"Namespace",
				"SecurityPolicy",
				configStr,
				details,
				issuesStr,
			})
		}
	}

	// GCP Backend Policy
	for _, policies := range allGCPBackendPolicies {
		for _, p := range policies {
			var config []string
			if p.CloudArmorPolicy != "" {
				config = append(config, fmt.Sprintf("Cloud Armor: %s", p.CloudArmorPolicy))
			}
			if p.HasIAP {
				config = append(config, "IAP: enabled")
			}
			configStr := strings.Join(config, ", ")
			if configStr == "" {
				configStr = "-"
			}
			details := fmt.Sprintf("Kind: %s", p.Kind)
			var issues []string
			if p.CloudArmorPolicy == "" {
				issues = append(issues, "No Cloud Armor")
			}
			issuesStr := "<NONE>"
			if len(issues) > 0 {
				issuesStr = strings.Join(issues, "; ")
			}
			unifiedPolicyRows = append(unifiedPolicyRows, []string{
				p.Namespace,
				"GCP/GKE",
				p.Name,
				"Namespace",
				p.Kind,
				configStr,
				details,
				issuesStr,
			})
		}
	}

	// Azure Network Policy
	for _, policies := range allAzureNetworkPolicies {
		for _, p := range policies {
			configStr := "-"
			if p.HasManagedIdentity {
				configStr = "Managed Identity: enabled"
			}
			details := fmt.Sprintf("Kind: %s", p.Kind)
			issuesStr := "<NONE>"
			if !p.HasManagedIdentity {
				issuesStr = "No managed identity"
			}
			unifiedPolicyRows = append(unifiedPolicyRows, []string{
				p.Namespace,
				"Azure/AKS",
				p.Name,
				"Namespace",
				p.Kind,
				configStr,
				details,
				issuesStr,
			})
		}
	}

	// Gatekeeper Network Constraints
	for _, c := range allGatekeeperNetworkConstraints {
		configStr := fmt.Sprintf("Enforcement: %s", c.EnforcementAction)
		details := "-"
		if len(c.MatchNamespaces) > 0 {
			details = fmt.Sprintf("Match: %d namespaces", len(c.MatchNamespaces))
		}
		var issues []string
		if c.EnforcementAction == "dryrun" || c.EnforcementAction == "warn" {
			issues = append(issues, "Not enforcing")
		}
		if c.ViolationCount > 0 {
			issues = append(issues, fmt.Sprintf("%d violations", c.ViolationCount))
		}
		issuesStr := "<NONE>"
		if len(issues) > 0 {
			issuesStr = strings.Join(issues, "; ")
		}
		unifiedPolicyRows = append(unifiedPolicyRows, []string{
			"<CLUSTER>",
			"Gatekeeper",
			c.Name,
			"Cluster",
			c.Kind,
			configStr,
			details,
			issuesStr,
		})
	}

	// Kyverno Network Policies
	for _, p := range allKyvernoNetworkPolicies {
		scope := "Namespace"
		ns := p.Namespace
		if p.IsClusterPolicy {
			scope = "Cluster"
			ns = "<CLUSTER>"
		}
		configStr := fmt.Sprintf("Action: %s", p.ValidationAction)
		if p.Background {
			configStr += ", Background: enabled"
		}
		details := fmt.Sprintf("Rules: %d", p.RuleCount)
		issuesStr := "<NONE>"
		if p.ValidationAction == "Audit" || p.ValidationAction == "audit" {
			issuesStr = "Audit mode (not enforcing)"
		}
		unifiedPolicyRows = append(unifiedPolicyRows, []string{
			ns,
			"Kyverno",
			p.Name,
			scope,
			"NetworkPolicy",
			configStr,
			details,
			issuesStr,
		})
	}

	// Kubewarden Network Policies
	for _, p := range allKubewardenNetworkPolicies {
		ns := p.Namespace
		if ns == "" {
			ns = "<CLUSTER>"
		}
		configStr := fmt.Sprintf("Mode: %s", p.Mode)
		// Shorten long module names
		module := p.Module
		if len(module) > 30 {
			module = module[:30] + "..."
		}
		details := "-"
		if module != "" {
			details = fmt.Sprintf("Module: %s", module)
		}
		issuesStr := "<NONE>"
		if p.Mode == "monitor" {
			issuesStr = "Monitor mode (not enforcing)"
		}
		unifiedPolicyRows = append(unifiedPolicyRows, []string{
			ns,
			"Kubewarden",
			p.Name,
			"Namespace",
			"AdmissionPolicy",
			configStr,
			details,
			issuesStr,
		})
	}

	// Sort unified policies by namespace, then tool
	sort.SliceStable(unifiedPolicyRows, func(i, j int) bool {
		if unifiedPolicyRows[i][0] != unifiedPolicyRows[j][0] {
			return unifiedPolicyRows[i][0] < unifiedPolicyRows[j][0]
		}
		return unifiedPolicyRows[i][1] < unifiedPolicyRows[j][1]
	})

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

	// Add unified policies table (always shown)
	if len(unifiedPolicyRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Network-Admission-Policy-Overview",
			Header: unifiedPolicyHeaders,
			Body:   unifiedPolicyRows,
		})
	}

	// Detail tables only shown with --detailed flag
	if detailed {
		if len(k8sNetPolRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Network-Admission-K8s-Policies",
				Header: k8sNetPolHeaders,
				Body:   k8sNetPolRows,
			})
		}

		if len(calicoRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Network-Admission-Calico-Policies",
				Header: calicoHeaders,
				Body:   calicoRows,
			})
		}

		if len(ciliumRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Network-Admission-Cilium-Policies",
				Header: ciliumHeaders,
				Body:   ciliumRows,
			})
		}

		if len(antreaRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Network-Admission-Antrea-Policies",
				Header: antreaHeaders,
				Body:   antreaRows,
			})
		}

		if len(istioRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Network-Admission-Istio-Policies",
				Header: istioHeaders,
				Body:   istioRows,
			})
		}

		if len(linkerdRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Network-Admission-Linkerd-Policies",
				Header: linkerdHeaders,
				Body:   linkerdRows,
			})
		}

		if len(awsSGRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Network-Admission-AWS-SecurityGroup-Policies",
				Header: awsSGHeaders,
				Body:   awsSGRows,
			})
		}

		if len(openshiftEgressRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Network-Admission-OpenShift-Egress-Policies",
				Header: openshiftEgressHeaders,
				Body:   openshiftEgressRows,
			})
		}

		if len(consulRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Network-Admission-Consul-Connect-Policies",
				Header: consulHeaders,
				Body:   consulRows,
			})
		}

		if len(kumaRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Network-Admission-Kuma-Mesh-Policies",
				Header: kumaHeaders,
				Body:   kumaRows,
			})
		}

		if len(smiRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Network-Admission-SMI-Policies",
				Header: smiHeaders,
				Body:   smiRows,
			})
		}

		if len(glooRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Network-Admission-Gloo-Mesh-Policies",
				Header: glooHeaders,
				Body:   glooRows,
			})
		}

		if len(nsxtRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Network-Admission-NSX-T-Policies",
				Header: nsxtHeaders,
				Body:   nsxtRows,
			})
		}

		if len(gcpRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Network-Admission-GCP-Policies",
				Header: gcpHeaders,
				Body:   gcpRows,
			})
		}

		if len(azureRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Network-Admission-Azure-Policies",
				Header: azureHeaders,
				Body:   azureRows,
			})
		}

		// Policy engine detailed tables
		if len(gatekeeperNetworkRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Network-Admission-Gatekeeper-Policies",
				Header: gatekeeperNetworkHeaders,
				Body:   gatekeeperNetworkRows,
			})
		}

		if len(kyvernoNetworkRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Network-Admission-Kyverno-Policies",
				Header: kyvernoNetworkHeaders,
				Body:   kyvernoNetworkRows,
			})
		}

		if len(kubewardenNetworkRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Network-Admission-Kubewarden-Policies",
				Header: kubewardenNetworkHeaders,
				Body:   kubewardenNetworkRows,
			})
		}

		// CNAPP Network Policies (Aqua, Prisma, Sysdig, StackRox, NeuVector)
		if len(cnappNetworkRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Network-Admission-CNAPP-Policies",
				Header: cnappNetworkHeaders,
				Body:   cnappNetworkRows,
			})
		}

		// Capsule Network Policies
		if len(capsuleNetworkRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Network-Admission-Capsule-Policies",
				Header: capsuleNetworkHeaders,
				Body:   capsuleNetworkRows,
			})
		}

		// Rancher Network Policies
		if len(rancherNetworkRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Network-Admission-Rancher-Policies",
				Header: rancherNetworkHeaders,
				Body:   rancherNetworkRows,
			})
		}

		// Polaris Network Checks
		if len(polarisNetworkRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Network-Admission-Polaris-Policies",
				Header: polarisNetworkHeaders,
				Body:   polarisNetworkRows,
			})
		}
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
		loot.Section("Network-Admission-Commands").
			Addf("\n# [CRITICAL] Namespace: %s - NO network policies", finding.Namespace).
			Addf("kubectl get pods -n %s", finding.Namespace).
			AddBlank()
		return
	}

	// Enum section
	loot.Section("Network-Admission-Commands").
		Addf("\n# Namespace: %s (%d policies)", finding.Namespace, finding.PolicyCount)

	if finding.K8sNetworkPolicyCount > 0 {
		loot.Section("Network-Admission-Commands").Addf("kubectl get networkpolicies -n %s", finding.Namespace)
	}
	if finding.CalicoCount > 0 {
		loot.Section("Network-Admission-Commands").Addf("kubectl get networkpolicies.projectcalico.org -n %s", finding.Namespace)
	}
	if finding.CiliumCount > 0 {
		loot.Section("Network-Admission-Commands").Addf("kubectl get ciliumnetworkpolicies -n %s", finding.Namespace)
	}
	if finding.AntreaCount > 0 {
		loot.Section("Network-Admission-Commands").Addf("kubectl get networkpolicies.crd.antrea.io -n %s", finding.Namespace)
	}
	if finding.IstioCount > 0 {
		loot.Section("Network-Admission-Commands").Addf("kubectl get authorizationpolicies.security.istio.io -n %s", finding.Namespace)
	}
	if finding.AWSSecurityGroupCount > 0 {
		loot.Section("Network-Admission-Commands").Addf("kubectl get securitygrouppolicies.vpcresources.k8s.aws -n %s", finding.Namespace)
	}
	if finding.OpenShiftEgressCount > 0 {
		loot.Section("Network-Admission-Commands").Addf("kubectl get egressfirewalls.k8s.ovn.org -n %s", finding.Namespace)
		loot.Section("Network-Admission-Commands").Addf("kubectl get egressnetworkpolicies.network.openshift.io -n %s", finding.Namespace)
	}
	if finding.ConsulConnectCount > 0 {
		loot.Section("Network-Admission-Commands").Addf("kubectl get serviceintentions.consul.hashicorp.com -n %s", finding.Namespace)
	}
	if finding.KumaMeshCount > 0 {
		loot.Section("Network-Admission-Commands").Addf("kubectl get meshtrafficpermissions.kuma.io -n %s", finding.Namespace)
	}
	if finding.SMICount > 0 {
		loot.Section("Network-Admission-Commands").Addf("kubectl get traffictargets.access.smi-spec.io -n %s", finding.Namespace)
	}
	if finding.GlooMeshCount > 0 {
		loot.Section("Network-Admission-Commands").Addf("kubectl get accesspolicies.security.policy.gloo.solo.io -n %s", finding.Namespace)
	}
	if finding.NSXTCount > 0 {
		loot.Section("Network-Admission-Commands").Addf("kubectl get securitypolicies.nsx.vmware.com -n %s", finding.Namespace)
	}
	if finding.GCPBackendCount > 0 {
		loot.Section("Network-Admission-Commands").Addf("kubectl get gcpbackendpolicies.networking.gke.io -n %s", finding.Namespace)
	}
	if finding.AzureNetworkCount > 0 {
		loot.Section("Network-Admission-Commands").Addf("kubectl get azureingressprohibitedtargets.appgw.ingress.k8s.io -n %s", finding.Namespace)
		loot.Section("Network-Admission-Commands").Addf("kubectl get azureidentitybindings.aadpodidentity.k8s.io -n %s", finding.Namespace)
	}

	loot.Section("Network-Admission-Commands").AddBlank()
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

// generateNetworkPolicyEnumerationLoot creates enumeration commands only for detected policy engines
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

	// Only add commands for detected policy engines
	loot.Section("Network-Admission-Commands").Add("\n# Cluster-wide policy enumeration (detected tools only)")

	if hasK8sNetworkPolicy {
		loot.Section("Network-Admission-Commands").Add("\n# K8s NetworkPolicy")
		loot.Section("Network-Admission-Commands").Add("kubectl get networkpolicies -A -o wide")
	}
	if hasCalico {
		loot.Section("Network-Admission-Commands").Add("\n# Calico")
		loot.Section("Network-Admission-Commands").Add("kubectl get networkpolicies.crd.projectcalico.org -A -o wide")
		loot.Section("Network-Admission-Commands").Add("kubectl get globalnetworkpolicies.crd.projectcalico.org -o wide")
	}
	if hasCilium {
		loot.Section("Network-Admission-Commands").Add("\n# Cilium")
		loot.Section("Network-Admission-Commands").Add("kubectl get ciliumnetworkpolicies -A -o wide")
		loot.Section("Network-Admission-Commands").Add("kubectl get ciliumclusterwidenetworkpolicies -o wide")
	}
	if hasAntrea {
		loot.Section("Network-Admission-Commands").Add("\n# Antrea")
		loot.Section("Network-Admission-Commands").Add("kubectl get networkpolicies.crd.antrea.io -A -o wide")
		loot.Section("Network-Admission-Commands").Add("kubectl get clusternetworkpolicies.crd.antrea.io -o wide")
	}
	if hasIstio {
		loot.Section("Network-Admission-Commands").Add("\n# Istio")
		loot.Section("Network-Admission-Commands").Add("kubectl get authorizationpolicies.security.istio.io -A -o wide")
	}
	if hasLinkerd {
		loot.Section("Network-Admission-Commands").Add("\n# Linkerd")
		loot.Section("Network-Admission-Commands").Add("kubectl get servers.policy.linkerd.io -A -o wide")
		loot.Section("Network-Admission-Commands").Add("kubectl get serverauthorizations.policy.linkerd.io -A -o wide")
	}
	if hasAWSSecurityGroup {
		loot.Section("Network-Admission-Commands").Add("\n# AWS SecurityGroupPolicy")
		loot.Section("Network-Admission-Commands").Add("kubectl get securitygrouppolicies.vpcresources.k8s.aws -A -o wide")
	}
	if hasOpenShiftEgress {
		loot.Section("Network-Admission-Commands").Add("\n# OpenShift EgressFirewall")
		loot.Section("Network-Admission-Commands").Add("kubectl get egressfirewalls.k8s.ovn.org -A -o wide")
	}
	if hasConsulConnect {
		loot.Section("Network-Admission-Commands").Add("\n# Consul Connect")
		loot.Section("Network-Admission-Commands").Add("kubectl get serviceintentions.consul.hashicorp.com -A -o wide")
	}
	if hasKumaMesh {
		loot.Section("Network-Admission-Commands").Add("\n# Kuma/Kong Mesh")
		loot.Section("Network-Admission-Commands").Add("kubectl get meshtrafficpermissions.kuma.io -A -o wide")
	}
	if hasSMI {
		loot.Section("Network-Admission-Commands").Add("\n# SMI")
		loot.Section("Network-Admission-Commands").Add("kubectl get traffictargets.access.smi-spec.io -A -o wide")
	}
	if hasGlooMesh {
		loot.Section("Network-Admission-Commands").Add("\n# Gloo Mesh")
		loot.Section("Network-Admission-Commands").Add("kubectl get accesspolicies.security.policy.gloo.solo.io -A -o wide")
	}
	if hasNSXT {
		loot.Section("Network-Admission-Commands").Add("\n# VMware NSX-T")
		loot.Section("Network-Admission-Commands").Add("kubectl get securitypolicies.nsx.vmware.com -A -o wide")
	}
	if hasGCPBackend {
		loot.Section("Network-Admission-Commands").Add("\n# GCP/GKE")
		loot.Section("Network-Admission-Commands").Add("kubectl get gcpbackendpolicies.networking.gke.io -A -o wide")
	}
	if hasAzureNetwork {
		loot.Section("Network-Admission-Commands").Add("\n# Azure/AKS")
		loot.Section("Network-Admission-Commands").Add("kubectl get azureingressprohibitedtargets.appgw.ingress.k8s.io -A -o wide")
	}
}

// ============================================================================
// Policy Engine Network Policy Analysis (Gatekeeper, Kyverno, Kubewarden)
// ============================================================================

// GatekeeperNetworkConstraintInfo represents a Gatekeeper constraint related to network policies
type GatekeeperNetworkConstraintInfo struct {
	Name               string
	Kind               string // The constraint template kind (e.g., K8sAllowedNetworks)
	EnforcementAction  string // deny, dryrun, warn
	MatchNamespaces    []string
	ExcludeNamespaces  []string
	NetworkRules       []string // Extracted network-related rules
	ViolationCount     int
	IsNetworkRelated   bool
}

// KyvernoNetworkPolicyInfo represents a Kyverno policy related to network resources
type KyvernoNetworkPolicyInfo struct {
	Name                string
	Namespace           string
	IsClusterPolicy     bool
	ValidationAction    string // enforce, audit
	Background          bool
	RuleCount           int
	NetworkRules        []string // Rules that target NetworkPolicy resources
	IsNetworkRelated    bool
	TargetsNetworkPolicy bool
}

// KubewardenNetworkPolicyInfo represents a Kubewarden policy for network resources
type KubewardenNetworkPolicyInfo struct {
	Name              string
	Namespace         string
	PolicyServer      string
	Mode              string // protect, monitor
	Module            string // The WASM module
	IsNetworkRelated  bool
	NetworkRules      []string
}

// analyzeGatekeeperNetworkConstraints finds Gatekeeper constraints that enforce network policies
func analyzeGatekeeperNetworkConstraints(ctx context.Context, dynClient dynamic.Interface) []GatekeeperNetworkConstraintInfo {
	var constraints []GatekeeperNetworkConstraintInfo

	// Network-related constraint template patterns
	networkPatterns := []string{
		"network", "egress", "ingress", "cidr", "port", "protocol",
		"allowednetwork", "denynetwork", "networkpolicy",
	}

	// List all constraint templates first
	templateGVR := schema.GroupVersionResource{
		Group:    "templates.gatekeeper.sh",
		Version:  "v1",
		Resource: "constrainttemplates",
	}

	templates, err := dynClient.Resource(templateGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return constraints
	}

	// For each template, check if it's network-related and get constraints
	for _, tmpl := range templates.Items {
		templateName := tmpl.GetName()
		isNetworkRelated := false

		// Check if template name suggests network policy
		for _, pattern := range networkPatterns {
			if strings.Contains(strings.ToLower(templateName), pattern) {
				isNetworkRelated = true
				break
			}
		}

		// Check CRD targets
		if spec, ok := tmpl.Object["spec"].(map[string]interface{}); ok {
			if crd, ok := spec["crd"].(map[string]interface{}); ok {
				if specNested, ok := crd["spec"].(map[string]interface{}); ok {
					if names, ok := specNested["names"].(map[string]interface{}); ok {
						if kind, ok := names["kind"].(string); ok {
							for _, pattern := range networkPatterns {
								if strings.Contains(strings.ToLower(kind), pattern) {
									isNetworkRelated = true
									break
								}
							}
						}
					}
				}
			}
			// Check targets for NetworkPolicy resources
			if targets, ok := spec["targets"].([]interface{}); ok {
				for _, target := range targets {
					if targetMap, ok := target.(map[string]interface{}); ok {
						if rego, ok := targetMap["rego"].(string); ok {
							if strings.Contains(rego, "NetworkPolicy") ||
								strings.Contains(rego, "network") ||
								strings.Contains(rego, "egress") ||
								strings.Contains(rego, "ingress") {
								isNetworkRelated = true
							}
						}
					}
				}
			}
		}

		if !isNetworkRelated {
			continue
		}

		// Now get constraints of this type
		constraintGVR := schema.GroupVersionResource{
			Group:    "constraints.gatekeeper.sh",
			Version:  "v1beta1",
			Resource: strings.ToLower(templateName),
		}

		constraintList, err := dynClient.Resource(constraintGVR).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, c := range constraintList.Items {
			info := GatekeeperNetworkConstraintInfo{
				Name:             c.GetName(),
				Kind:             templateName,
				IsNetworkRelated: true,
			}

			if spec, ok := c.Object["spec"].(map[string]interface{}); ok {
				if action, ok := spec["enforcementAction"].(string); ok {
					info.EnforcementAction = action
				} else {
					info.EnforcementAction = "deny" // default
				}

				if match, ok := spec["match"].(map[string]interface{}); ok {
					if namespaces, ok := match["namespaces"].([]interface{}); ok {
						for _, ns := range namespaces {
							if nsStr, ok := ns.(string); ok {
								info.MatchNamespaces = append(info.MatchNamespaces, nsStr)
							}
						}
					}
					if excluded, ok := match["excludedNamespaces"].([]interface{}); ok {
						for _, ns := range excluded {
							if nsStr, ok := ns.(string); ok {
								info.ExcludeNamespaces = append(info.ExcludeNamespaces, nsStr)
							}
						}
					}
				}

				// Extract parameters as network rules
				if params, ok := spec["parameters"].(map[string]interface{}); ok {
					info.NetworkRules = append(info.NetworkRules, fmt.Sprintf("%v", params))
				}
			}

			// Get violation count from status
			if status, ok := c.Object["status"].(map[string]interface{}); ok {
				if violations, ok := status["totalViolations"].(int64); ok {
					info.ViolationCount = int(violations)
				} else if violations, ok := status["totalViolations"].(float64); ok {
					info.ViolationCount = int(violations)
				}
			}

			constraints = append(constraints, info)
		}
	}

	return constraints
}

// analyzeKyvernoNetworkPolicies finds Kyverno policies that target NetworkPolicy resources
func analyzeKyvernoNetworkPolicies(ctx context.Context, dynClient dynamic.Interface) []KyvernoNetworkPolicyInfo {
	var policies []KyvernoNetworkPolicyInfo

	// ClusterPolicy
	cpGVR := schema.GroupVersionResource{
		Group:    "kyverno.io",
		Version:  "v1",
		Resource: "clusterpolicies",
	}

	cpList, err := dynClient.Resource(cpGVR).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, cp := range cpList.Items {
			info := analyzeKyvernoPolicy(cp.Object, cp.GetName(), "", true)
			if info.IsNetworkRelated {
				policies = append(policies, info)
			}
		}
	}

	// Namespaced Policy
	pGVR := schema.GroupVersionResource{
		Group:    "kyverno.io",
		Version:  "v1",
		Resource: "policies",
	}

	pList, err := dynClient.Resource(pGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, p := range pList.Items {
			info := analyzeKyvernoPolicy(p.Object, p.GetName(), p.GetNamespace(), false)
			if info.IsNetworkRelated {
				policies = append(policies, info)
			}
		}
	}

	return policies
}

func analyzeKyvernoPolicy(obj map[string]interface{}, name, namespace string, isCluster bool) KyvernoNetworkPolicyInfo {
	info := KyvernoNetworkPolicyInfo{
		Name:            name,
		Namespace:       namespace,
		IsClusterPolicy: isCluster,
	}

	if spec, ok := obj["spec"].(map[string]interface{}); ok {
		if vfa, ok := spec["validationFailureAction"].(string); ok {
			info.ValidationAction = vfa
		}
		if bg, ok := spec["background"].(bool); ok {
			info.Background = bg
		}

		if rules, ok := spec["rules"].([]interface{}); ok {
			info.RuleCount = len(rules)
			for _, r := range rules {
				if rMap, ok := r.(map[string]interface{}); ok {
					ruleName, _ := rMap["name"].(string)

					// Check if rule matches NetworkPolicy resources
					if match, ok := rMap["match"].(map[string]interface{}); ok {
						if any, ok := match["any"].([]interface{}); ok {
							for _, a := range any {
								if aMap, ok := a.(map[string]interface{}); ok {
									if resources, ok := aMap["resources"].(map[string]interface{}); ok {
										if kinds, ok := resources["kinds"].([]interface{}); ok {
											for _, k := range kinds {
												if kStr, ok := k.(string); ok {
													if strings.Contains(kStr, "NetworkPolicy") {
														info.IsNetworkRelated = true
														info.TargetsNetworkPolicy = true
														info.NetworkRules = append(info.NetworkRules, ruleName)
													}
												}
											}
										}
									}
								}
							}
						}
						if all, ok := match["all"].([]interface{}); ok {
							for _, a := range all {
								if aMap, ok := a.(map[string]interface{}); ok {
									if resources, ok := aMap["resources"].(map[string]interface{}); ok {
										if kinds, ok := resources["kinds"].([]interface{}); ok {
											for _, k := range kinds {
												if kStr, ok := k.(string); ok {
													if strings.Contains(kStr, "NetworkPolicy") {
														info.IsNetworkRelated = true
														info.TargetsNetworkPolicy = true
														info.NetworkRules = append(info.NetworkRules, ruleName)
													}
												}
											}
										}
									}
								}
							}
						}
						// Also check resources directly (older format)
						if resources, ok := match["resources"].(map[string]interface{}); ok {
							if kinds, ok := resources["kinds"].([]interface{}); ok {
								for _, k := range kinds {
									if kStr, ok := k.(string); ok {
										if strings.Contains(kStr, "NetworkPolicy") {
											info.IsNetworkRelated = true
											info.TargetsNetworkPolicy = true
											info.NetworkRules = append(info.NetworkRules, ruleName)
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	return info
}

// analyzeKubewardenNetworkPolicies finds Kubewarden policies related to network resources
func analyzeKubewardenNetworkPolicies(ctx context.Context, dynClient dynamic.Interface) []KubewardenNetworkPolicyInfo {
	var policies []KubewardenNetworkPolicyInfo

	// Network-related module patterns
	networkModules := []string{
		"network", "egress", "ingress", "port", "protocol",
	}

	// ClusterAdmissionPolicy
	capGVR := schema.GroupVersionResource{
		Group:    "policies.kubewarden.io",
		Version:  "v1",
		Resource: "clusteradmissionpolicies",
	}

	capList, err := dynClient.Resource(capGVR).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, cap := range capList.Items {
			info := parseKubewardenPolicy(cap.Object, cap.GetName(), "", networkModules)
			if info.IsNetworkRelated {
				policies = append(policies, info)
			}
		}
	}

	// AdmissionPolicy (namespaced)
	apGVR := schema.GroupVersionResource{
		Group:    "policies.kubewarden.io",
		Version:  "v1",
		Resource: "admissionpolicies",
	}

	apList, err := dynClient.Resource(apGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, ap := range apList.Items {
			info := parseKubewardenPolicy(ap.Object, ap.GetName(), ap.GetNamespace(), networkModules)
			if info.IsNetworkRelated {
				policies = append(policies, info)
			}
		}
	}

	return policies
}

func parseKubewardenPolicy(obj map[string]interface{}, name, namespace string, networkModules []string) KubewardenNetworkPolicyInfo {
	info := KubewardenNetworkPolicyInfo{
		Name:      name,
		Namespace: namespace,
	}

	if spec, ok := obj["spec"].(map[string]interface{}); ok {
		if module, ok := spec["module"].(string); ok {
			info.Module = module
			// Check if module is network-related
			for _, pattern := range networkModules {
				if strings.Contains(strings.ToLower(module), pattern) {
					info.IsNetworkRelated = true
					break
				}
			}
		}

		if mode, ok := spec["mode"].(string); ok {
			info.Mode = mode
		}

		if policyServer, ok := spec["policyServer"].(string); ok {
			info.PolicyServer = policyServer
		}

		// Check rules for NetworkPolicy targets
		if rules, ok := spec["rules"].([]interface{}); ok {
			for _, r := range rules {
				if rMap, ok := r.(map[string]interface{}); ok {
					if resources, ok := rMap["resources"].([]interface{}); ok {
						for _, res := range resources {
							if resStr, ok := res.(string); ok {
								if strings.Contains(resStr, "networkpolicies") {
									info.IsNetworkRelated = true
									info.NetworkRules = append(info.NetworkRules, resStr)
								}
							}
						}
					}
				}
			}
		}
	}

	return info
}

// ============================================================================
// CNAPP Platform Network Policy Analysis
// ============================================================================

// CNAPPNetworkPolicyInfo represents network policies from CNAPP platforms
type CNAPPNetworkPolicyInfo struct {
	Platform        string // aqua, prisma, sysdig, stackrox, neuvector
	Name            string
	Namespace       string
	Scope           string // cluster, namespace, workload
	Mode            string // enforce, alert, monitor
	NetworkRules    []string
	IngressRules    int
	EgressRules     int
	HasDefaultDeny  bool
}

// analyzeAquaNetworkPolicies analyzes Aqua network micro-segmentation policies
func analyzeAquaNetworkPolicies(ctx context.Context, dynClient dynamic.Interface) []CNAPPNetworkPolicyInfo {
	var policies []CNAPPNetworkPolicyInfo

	// Aqua uses RuntimePolicy CRD for network controls
	gvr := schema.GroupVersionResource{
		Group:    "aquasecurity.github.io",
		Version:  "v1alpha1",
		Resource: "runtimepolicies",
	}

	list, err := dynClient.Resource(gvr).List(ctx, metav1.ListOptions{})
	if err != nil {
		return policies
	}

	for _, item := range list.Items {
		info := CNAPPNetworkPolicyInfo{
			Platform:  "aqua",
			Name:      item.GetName(),
			Namespace: item.GetNamespace(),
		}

		if spec, ok := item.Object["spec"].(map[string]interface{}); ok {
			if networkPolicy, ok := spec["network"].(map[string]interface{}); ok {
				info.Scope = "workload"
				if enabled, ok := networkPolicy["enabled"].(bool); ok && enabled {
					if blockInbound, ok := networkPolicy["block_inbound"].(bool); ok && blockInbound {
						info.HasDefaultDeny = true
						info.IngressRules++
					}
					if blockOutbound, ok := networkPolicy["block_outbound"].(bool); ok && blockOutbound {
						info.EgressRules++
					}
				}
			}
			if enforcement, ok := spec["enforcement_mode"].(string); ok {
				info.Mode = enforcement
			}
		}

		if info.IngressRules > 0 || info.EgressRules > 0 {
			policies = append(policies, info)
		}
	}

	return policies
}

// analyzePrismaNetworkPolicies analyzes Prisma Cloud/Twistlock network policies
func analyzePrismaNetworkPolicies(ctx context.Context, dynClient dynamic.Interface) []CNAPPNetworkPolicyInfo {
	var policies []CNAPPNetworkPolicyInfo

	// Prisma Cloud uses different CRD versions
	gvrs := []schema.GroupVersionResource{
		{Group: "twistlock.com", Version: "v1", Resource: "policies"},
		{Group: "prismacloud.io", Version: "v1", Resource: "policies"},
	}

	for _, gvr := range gvrs {
		list, err := dynClient.Resource(gvr).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, item := range list.Items {
			info := CNAPPNetworkPolicyInfo{
				Platform:  "prisma",
				Name:      item.GetName(),
				Namespace: item.GetNamespace(),
			}

			if spec, ok := item.Object["spec"].(map[string]interface{}); ok {
				if pType, ok := spec["type"].(string); ok {
					if strings.Contains(strings.ToLower(pType), "network") ||
						strings.Contains(strings.ToLower(pType), "firewall") {
						info.Scope = "workload"
						if rules, ok := spec["rules"].([]interface{}); ok {
							for _, r := range rules {
								if rMap, ok := r.(map[string]interface{}); ok {
									if direction, ok := rMap["direction"].(string); ok {
										if strings.ToLower(direction) == "inbound" {
											info.IngressRules++
										} else {
											info.EgressRules++
										}
									}
								}
							}
						}
						policies = append(policies, info)
					}
				}
			}
		}
	}

	return policies
}

// analyzeSysdigNetworkPolicies analyzes Sysdig network policies
func analyzeSysdigNetworkPolicies(ctx context.Context, dynClient dynamic.Interface) []CNAPPNetworkPolicyInfo {
	var policies []CNAPPNetworkPolicyInfo

	gvr := schema.GroupVersionResource{
		Group:    "sysdig.com",
		Version:  "v1",
		Resource: "policies",
	}

	list, err := dynClient.Resource(gvr).List(ctx, metav1.ListOptions{})
	if err != nil {
		return policies
	}

	for _, item := range list.Items {
		info := CNAPPNetworkPolicyInfo{
			Platform:  "sysdig",
			Name:      item.GetName(),
			Namespace: item.GetNamespace(),
		}

		if spec, ok := item.Object["spec"].(map[string]interface{}); ok {
			if pType, ok := spec["type"].(string); ok {
				if strings.Contains(strings.ToLower(pType), "network") {
					info.Scope = "workload"
					policies = append(policies, info)
				}
			}
		}
	}

	return policies
}

// analyzeStackRoxNetworkPolicies analyzes StackRox/RHACS network policies
func analyzeStackRoxNetworkPolicies(ctx context.Context, dynClient dynamic.Interface) []CNAPPNetworkPolicyInfo {
	var policies []CNAPPNetworkPolicyInfo

	gvr := schema.GroupVersionResource{
		Group:    "platform.stackrox.io",
		Version:  "v1alpha1",
		Resource: "networkpolicies",
	}

	list, err := dynClient.Resource(gvr).List(ctx, metav1.ListOptions{})
	if err != nil {
		return policies
	}

	for _, item := range list.Items {
		info := CNAPPNetworkPolicyInfo{
			Platform:  "stackrox",
			Name:      item.GetName(),
			Namespace: item.GetNamespace(),
			Scope:     "cluster",
		}

		if spec, ok := item.Object["spec"].(map[string]interface{}); ok {
			if deployment, ok := spec["deployment"].(map[string]interface{}); ok {
				info.Scope = "workload"
				if name, ok := deployment["name"].(string); ok {
					info.NetworkRules = append(info.NetworkRules, "deployment:"+name)
				}
			}
		}

		policies = append(policies, info)
	}

	return policies
}

// analyzeNeuVectorNetworkPolicies analyzes NeuVector network policies
func analyzeNeuVectorNetworkPolicies(ctx context.Context, dynClient dynamic.Interface) []CNAPPNetworkPolicyInfo {
	var policies []CNAPPNetworkPolicyInfo

	// NeuVector uses CRD for network rules
	gvr := schema.GroupVersionResource{
		Group:    "neuvector.com",
		Version:  "v1",
		Resource: "nvrules",
	}

	list, err := dynClient.Resource(gvr).List(ctx, metav1.ListOptions{})
	if err != nil {
		// Try nvsecurityrules
		gvr.Resource = "nvsecurityrules"
		list, err = dynClient.Resource(gvr).List(ctx, metav1.ListOptions{})
		if err != nil {
			return policies
		}
	}

	for _, item := range list.Items {
		info := CNAPPNetworkPolicyInfo{
			Platform:  "neuvector",
			Name:      item.GetName(),
			Namespace: item.GetNamespace(),
			Scope:     "workload",
		}

		if spec, ok := item.Object["spec"].(map[string]interface{}); ok {
			if networkRules, ok := spec["network"].(map[string]interface{}); ok {
				if ingress, ok := networkRules["ingress"].([]interface{}); ok {
					info.IngressRules = len(ingress)
				}
				if egress, ok := networkRules["egress"].([]interface{}); ok {
					info.EgressRules = len(egress)
				}
			}
			if mode, ok := spec["mode"].(string); ok {
				info.Mode = mode
			}
		}

		if info.IngressRules > 0 || info.EgressRules > 0 {
			policies = append(policies, info)
		}
	}

	return policies
}

// ============================================================================
// Multitenancy Platform Network Policy Analysis (Capsule, Rancher)
// ============================================================================

// CapsuleNetworkPolicyInfo represents Capsule tenant network restrictions
type CapsuleNetworkPolicyInfo struct {
	TenantName           string
	Namespace            string
	NetworkPolicies      []string
	AllowedExternalIPs   []string
	ForbiddenLabels      []string
	IngressClasses       []string
	StorageClasses       []string
	LimitRanges          []string
	HasNetworkIsolation  bool
}

// RancherNetworkPolicyInfo represents Rancher project network policies
type RancherNetworkPolicyInfo struct {
	ProjectName       string
	Namespace         string
	ProjectID         string
	NetworkPolicy     string
	PSPTemplate       string
	HasIsolation      bool
}

// analyzeCapsuleNetworkPolicies analyzes Capsule tenant network isolation
func analyzeCapsuleNetworkPolicies(ctx context.Context, dynClient dynamic.Interface) []CapsuleNetworkPolicyInfo {
	var policies []CapsuleNetworkPolicyInfo

	gvr := schema.GroupVersionResource{
		Group:    "capsule.clastix.io",
		Version:  "v1beta2",
		Resource: "tenants",
	}

	list, err := dynClient.Resource(gvr).List(ctx, metav1.ListOptions{})
	if err != nil {
		// Try v1beta1
		gvr.Version = "v1beta1"
		list, err = dynClient.Resource(gvr).List(ctx, metav1.ListOptions{})
		if err != nil {
			return policies
		}
	}

	for _, item := range list.Items {
		info := CapsuleNetworkPolicyInfo{
			TenantName: item.GetName(),
		}

		if spec, ok := item.Object["spec"].(map[string]interface{}); ok {
			// Check network policies
			if netPol, ok := spec["networkPolicies"].(map[string]interface{}); ok {
				info.HasNetworkIsolation = true
				if items, ok := netPol["items"].([]interface{}); ok {
					for _, np := range items {
						if npMap, ok := np.(map[string]interface{}); ok {
							if name, ok := npMap["name"].(string); ok {
								info.NetworkPolicies = append(info.NetworkPolicies, name)
							}
						}
					}
				}
			}

			// Check external IPs restriction
			if externalIPs, ok := spec["externalServiceIPs"].(map[string]interface{}); ok {
				if allowed, ok := externalIPs["allowed"].([]interface{}); ok {
					for _, ip := range allowed {
						if ipStr, ok := ip.(string); ok {
							info.AllowedExternalIPs = append(info.AllowedExternalIPs, ipStr)
						}
					}
				}
			}

			// Check ingress classes restriction
			if ingress, ok := spec["ingressOptions"].(map[string]interface{}); ok {
				if classes, ok := ingress["allowedClasses"].(map[string]interface{}); ok {
					if items, ok := classes["allowed"].([]interface{}); ok {
						for _, c := range items {
							if cStr, ok := c.(string); ok {
								info.IngressClasses = append(info.IngressClasses, cStr)
							}
						}
					}
				}
			}
		}

		// Get namespaces owned by tenant
		if status, ok := item.Object["status"].(map[string]interface{}); ok {
			if namespaces, ok := status["namespaces"].([]interface{}); ok {
				for _, ns := range namespaces {
					if nsStr, ok := ns.(string); ok {
						infoCopy := info
						infoCopy.Namespace = nsStr
						policies = append(policies, infoCopy)
					}
				}
			}
		}

		// If no namespaces in status, still add the policy
		if len(policies) == 0 || policies[len(policies)-1].TenantName != info.TenantName {
			policies = append(policies, info)
		}
	}

	return policies
}

// analyzeRancherNetworkPolicies analyzes Rancher project network isolation
func analyzeRancherNetworkPolicies(ctx context.Context, dynClient dynamic.Interface) []RancherNetworkPolicyInfo {
	var policies []RancherNetworkPolicyInfo

	// Projects
	projectGVR := schema.GroupVersionResource{
		Group:    "management.cattle.io",
		Version:  "v3",
		Resource: "projects",
	}

	projectList, err := dynClient.Resource(projectGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return policies
	}

	for _, item := range projectList.Items {
		info := RancherNetworkPolicyInfo{
			ProjectName: item.GetName(),
		}

		if spec, ok := item.Object["spec"].(map[string]interface{}); ok {
			if projectID, ok := spec["projectId"].(string); ok {
				info.ProjectID = projectID
			}

			// Check container default resource limit
			if containerDefault, ok := spec["containerDefaultResourceLimit"].(map[string]interface{}); ok {
				if _, ok := containerDefault["limitsCpu"]; ok {
					info.HasIsolation = true
				}
			}

			// Check namespace default resource quota
			if nsDefault, ok := spec["namespaceDefaultResourceQuota"].(map[string]interface{}); ok {
				if limit, ok := nsDefault["limit"].(map[string]interface{}); ok {
					if _, ok := limit["pods"]; ok {
						info.HasIsolation = true
					}
				}
			}
		}

		// Get annotations for network policy
		annotations := item.GetAnnotations()
		if np, ok := annotations["field.cattle.io/projectDefaultNetworkPolicy"]; ok {
			info.NetworkPolicy = np
			info.HasIsolation = true
		}

		policies = append(policies, info)
	}

	// Also check ProjectNetworkPolicy CRD
	pnpGVR := schema.GroupVersionResource{
		Group:    "management.cattle.io",
		Version:  "v3",
		Resource: "projectnetworkpolicies",
	}

	pnpList, err := dynClient.Resource(pnpGVR).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range pnpList.Items {
			info := RancherNetworkPolicyInfo{
				ProjectName:  item.GetName(),
				Namespace:    item.GetNamespace(),
				HasIsolation: true,
			}

			if spec, ok := item.Object["spec"].(map[string]interface{}); ok {
				if projectID, ok := spec["projectId"].(string); ok {
					info.ProjectID = projectID
				}
			}

			policies = append(policies, info)
		}
	}

	return policies
}

// ============================================================================
// Polaris Network Policy Analysis
// ============================================================================

// PolarisNetworkCheckInfo represents Polaris checks related to network policies
type PolarisNetworkCheckInfo struct {
	Namespace              string
	CheckID                string
	CheckName              string
	Severity               string
	Category               string
	HasNetworkPolicy       bool
	MissingNetworkPolicy   bool
}

// analyzePolarisNetworkChecks analyzes Polaris reports for network policy findings
func analyzePolarisNetworkChecks(ctx context.Context, dynClient dynamic.Interface) []PolarisNetworkCheckInfo {
	var checks []PolarisNetworkCheckInfo

	// Polaris stores results in ConfigAuditReport CRD (from its operator mode)
	// or as annotations on resources

	// Check for Polaris ConfigAuditReport (if using with trivy-operator compatibility)
	gvr := schema.GroupVersionResource{
		Group:    "aquasecurity.github.io",
		Version:  "v1alpha1",
		Resource: "configauditreports",
	}

	list, err := dynClient.Resource(gvr).List(ctx, metav1.ListOptions{})
	if err != nil {
		return checks
	}

	for _, item := range list.Items {
		namespace := item.GetNamespace()

		if report, ok := item.Object["report"].(map[string]interface{}); ok {
			if checksList, ok := report["checks"].([]interface{}); ok {
				for _, c := range checksList {
					if cMap, ok := c.(map[string]interface{}); ok {
						checkID, _ := cMap["checkID"].(string)
						// Filter for network-related checks
						if strings.Contains(strings.ToLower(checkID), "network") {
							info := PolarisNetworkCheckInfo{
								Namespace: namespace,
								CheckID:   checkID,
							}
							if title, ok := cMap["title"].(string); ok {
								info.CheckName = title
							}
							if severity, ok := cMap["severity"].(string); ok {
								info.Severity = severity
							}
							if category, ok := cMap["category"].(string); ok {
								info.Category = category
							}
							if success, ok := cMap["success"].(bool); ok {
								info.HasNetworkPolicy = success
								info.MissingNetworkPolicy = !success
							}
							checks = append(checks, info)
						}
					}
				}
			}
		}
	}

	return checks
}

// ============================================================================
// Conftest Network Policy Analysis
// ============================================================================

// ConftestNetworkPolicyInfo represents Conftest policy results for network resources
type ConftestNetworkPolicyInfo struct {
	Namespace    string
	PolicyName   string
	PolicyPath   string
	ResourceKind string
	Failures     int
	Warnings     int
	Successes    int
}
