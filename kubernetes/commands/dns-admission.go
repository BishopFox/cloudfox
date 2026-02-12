package commands

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/BishopFox/cloudfox/kubernetes/shared"
	"github.com/BishopFox/cloudfox/kubernetes/shared/admission"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	// Cloud SDK imports for DNS policy enumeration
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dnsresolver/armdnsresolver"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/privatedns/armprivatedns"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/route53resolver"
	"google.golang.org/api/dns/v1"
	"google.golang.org/api/option"
)

const K8S_DNS_ADMISSION_MODULE_NAME = "dns-admission"

var DNSAdmissionCmd = &cobra.Command{
	Use:     "dns-admission",
	Aliases: []string{"dns-security", "coredns"},
	Short:   "Analyze DNS security configurations and policies",
	Long: `
Analyze all DNS security configurations including:

In-Cluster Analysis:
  - CoreDNS configuration and security plugins
  - NodeLocalDNS and external-dns detection
  - Pod DNS policies (Default, ClusterFirst, ClusterFirstWithHostNet, None)
  - Cilium and Calico DNS policies
  - Kyverno and Gatekeeper DNS constraints
  - EKS Admin Network Policies (FQDN egress)
  - Kubernetes NetworkPolicy DNS rules (port 53)
  - Istio ServiceEntry DNS routing
  - ExternalName services and headless services
  - DNS exfiltration risks

Cloud Provider DNS Policies (requires --cloud-provider flag):
  Use --cloud-provider to enable cloud API enumeration for DNS security policies.

  AWS (--cloud-provider aws):
    - Route 53 DNS Firewall rule groups and domain lists
    - VPC DNS Firewall associations
    - Uses AWS credentials from --aws-profile or default credential chain

  GCP (--cloud-provider gcp):
    - Cloud DNS Response Policies and rules
    - Uses GCP credentials with --gcp-project or discovers accessible projects

  Azure (--cloud-provider azure):
    - DNS Private Resolver configurations
    - DNS Forwarding Rulesets
    - Private DNS Zones
    - Uses Azure credentials with --azure-subscription or discovers subscriptions

Examples:
  # Basic cluster analysis
  cloudfox kubernetes dns-admission

  # With AWS DNS Firewall enumeration
  cloudfox kubernetes dns-admission --cloud-provider aws --aws-profile myprofile

  # With GCP Response Policies enumeration
  cloudfox kubernetes dns-admission --cloud-provider gcp --gcp-project my-project

  # With Azure DNS Private Resolver enumeration
  cloudfox kubernetes dns-admission --cloud-provider azure --azure-subscription sub-id

  # Multiple cloud providers
  cloudfox kubernetes dns-admission --cloud-provider aws,gcp,azure`,
	Run: ListDNSAdmission,
}

// init() removed - detailed flag is now a global persistent flag in cli/kubernetes.go

type DNSAdmissionOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t DNSAdmissionOutput) TableFiles() []internal.TableFile { return t.Table }
func (t DNSAdmissionOutput) LootFiles() []internal.LootFile   { return t.Loot }

// DNSEnumeratedPolicy represents a unified DNS policy entry
type DNSEnumeratedPolicy struct {
	Namespace string
	Tool      string
	Name      string
	Scope     string
	Type      string
	Details   string
}

// DNSAdmissionFinding represents DNS security for a namespace
type DNSAdmissionFinding struct {
	Namespace string

	// DNS Configuration
	DNSPolicy     string // Default, ClusterFirst, ClusterFirstWithHostNet, None
	CustomDNS     bool
	DNSConfig     string

	// DNS Policies by tool
	CiliumPolicies      int
	CalicoPolicies      int
	KyvernoPolicies     int
	GatekeeperPolicies  int
	EKSAdminPolicies    int // AWS EKS AdminNetworkPolicy/ClusterNetworkPolicy
	K8sNetPolDNS        int // Native K8s NetworkPolicy with DNS rules
	IstioServiceEntries int // Istio ServiceEntry for DNS

	// Pod Analysis
	TotalPods          int
	PodsWithDefaultDNS int
	PodsWithCustomDNS  int
	PodsWithNoDNS      int

	SecurityIssues []string
}

// CoreDNSInfo represents CoreDNS deployment status
type CoreDNSInfo struct {
	Name            string
	Namespace       string
	Status          string
	PodsRunning     int
	TotalPods       int
	Version         string
	Plugins         []string
	SecurityPlugins []string
	CacheEnabled    bool
	LoggingEnabled  bool
	HealthEnabled   bool
	DNSSECEnabled   bool // True if DNSSEC validation/signing is enabled
	DoTEnabled      bool // True if DNS over TLS forwarding is configured
	DoHEnabled      bool // True if DNS over HTTPS forwarding is configured
	ACLEnabled      bool // True if access control lists are configured
	ImageVerified   bool // True if CoreDNS image was verified
}

// CoreDNSConfigInfo represents CoreDNS Corefile configuration
type CoreDNSConfigInfo struct {
	Zone             string
	Plugins          []string
	Upstreams        []string
	Caching          bool
	CacheTTL         int
	NegativeCacheTTL int
	ForwardTo        []string
	StubDomains      map[string][]string
	DNSSECEnabled    bool // True if dnssec plugin is enabled for this zone
	DoTForwarding    bool // True if forwarding uses tls:// protocol
	DoHForwarding    bool // True if forwarding uses https:// protocol
}

// NodeLocalDNSInfo represents NodeLocalDNS deployment status
type NodeLocalDNSInfo struct {
	Name          string
	Namespace     string
	Status        string
	PodsRunning   int
	TotalPods     int
	LocalIP       string
	ImageVerified bool // True if NodeLocalDNS image was verified
}

// ExternalDNSInfo represents external-dns deployment status
type ExternalDNSInfo struct {
	Name          string
	Namespace     string
	Status        string
	PodsRunning   int
	TotalPods     int
	Provider      string
	Sources       []string
	Policy        string // upsert-only, sync
	Registry      string
	ImageVerified bool // True if external-dns image was verified
}

// CiliumDNSPolicyInfo represents a Cilium DNS policy
type CiliumDNSPolicyInfo struct {
	Name          string
	Namespace     string
	IsCluster     bool
	DNSRules      int
	MatchFQDNs    []string
	MatchPatterns []string
	Action        string
}

// CalicoDNSPolicyInfo represents a Calico DNS policy
type CalicoDNSPolicyInfo struct {
	Name      string
	Namespace string
	IsGlobal  bool
	DNSRules  int
	Domains   []string
	Action    string
}

// PodDNSInfo represents DNS configuration for pods
type PodDNSInfo struct {
	Name         string
	Namespace    string
	DNSPolicy    string
	HasCustomDNS bool
	Nameservers  []string
	Searches     []string
}

// IstioDNSInfo represents Istio DNS proxy configuration
type IstioDNSInfo struct {
	Name                string
	Namespace           string
	Status              string
	PodsRunning         int
	TotalPods           int
	DNSCaptureEnabled   bool
	AutoAllocateEnabled bool
	ImageVerified       bool // True if Istio image was verified
}

// CloudDNSInfo represents cloud provider DNS configuration
type CloudDNSInfo struct {
	Provider      string // AWS, GCP, Azure
	Name          string
	Namespace     string
	Status        string
	Type          string // Route53, CloudDNS, AzureDNS
	PodsRunning   int
	TotalPods     int
	ImageVerified bool // True if cloud DNS controller image was verified
}

// ExternalNameServiceInfo represents a service with ExternalName type (DNS CNAME to external)
type ExternalNameServiceInfo struct {
	Name         string
	Namespace    string
	ExternalName string   // The external DNS name this service points to
	Notes        []string // Factual observations about the service
}

// HeadlessServiceInfo represents a headless service (clusterIP: None) that exposes pod IPs via DNS
type HeadlessServiceInfo struct {
	Name      string
	Namespace string
	Selector  map[string]string
	PodCount  int
	Ports     []string
	Notes     []string // Factual observations about the headless service
}

// DNSExfiltrationRisk represents a pod/namespace with DNS exfiltration risk
type DNSExfiltrationRisk struct {
	Namespace       string
	PodName         string
	DNSPolicy       string   // DNS policy configured on pod
	Notes           []string // Factual observations about DNS configuration
	ExternalDNS     []string // External nameservers configured
	HasEgressPolicy bool
}

// CoreDNSSecurityAnalysis represents deep security analysis of CoreDNS configuration
type CoreDNSSecurityAnalysis struct {
	// Security plugins status
	ACLEnabled          bool
	ACLRules            []string
	RRLEnabled          bool // Response Rate Limiting
	RRLConfig           string
	DNSTapEnabled       bool
	DNSTapEndpoint      string
	FirewallEnabled     bool
	FirewallRules       []string
	// Security concerns
	SecurityIssues      []string
	Recommendations     []string
}

// KyvernoDNSPolicyInfo represents a Kyverno policy related to DNS
type KyvernoDNSPolicyInfo struct {
	Name       string
	Namespace  string
	IsCluster  bool
	Type       string // validate, mutate, generate
	Target     string // Pod, Service, etc.
	DNSRule    string // What DNS aspect it controls
	Action     string // enforce, audit
}

// GatekeeperDNSConstraintInfo represents a Gatekeeper constraint related to DNS
type GatekeeperDNSConstraintInfo struct {
	Name           string
	Kind           string // The constraint kind
	TemplateName   string
	EnforcementAction string
	Target         string
	DNSRule        string
}

// ConsulDNSInfo represents Consul Connect DNS configuration
type ConsulDNSInfo struct {
	Name          string
	Namespace     string
	Status        string
	PodsRunning   int
	TotalPods     int
	DNSDomain     string
	ImageVerified bool
}

// EKSAdminNetworkPolicyInfo represents AWS EKS Admin Network Policy (ClusterNetworkPolicy/AdminNetworkPolicy)
type EKSAdminNetworkPolicyInfo struct {
	Name       string
	Kind       string // AdminNetworkPolicy or ClusterNetworkPolicy
	Priority   int
	Subject    string // What the policy applies to
	DNSRules   []string
	IsCluster  bool
}

// K8sNetworkPolicyDNSInfo represents native Kubernetes NetworkPolicy with DNS port rules
type K8sNetworkPolicyDNSInfo struct {
	Name            string
	Namespace       string
	HasDNSEgress    bool     // Has egress rule for port 53
	DNSEgressAction string   // Allow or Deny (based on policy structure)
	PodSelector     string
	Notes           []string
}

// IstioServiceEntryInfo represents Istio ServiceEntry for DNS routing
type IstioServiceEntryInfo struct {
	Name       string
	Namespace  string
	Hosts      []string
	Location   string // MESH_INTERNAL or MESH_EXTERNAL
	Resolution string // STATIC, DNS, NONE
	Ports      []string
	IsCluster  bool // If exported to all namespaces
}

// AWSRoute53DNSFirewallInfo represents AWS Route 53 DNS Firewall configuration
// Note: Full enumeration requires AWS API access with --aws-profile flag
type AWSRoute53DNSFirewallInfo struct {
	Name                string
	Namespace           string
	VPCAssociation      bool   // If associated with cluster VPC
	RuleGroupCount      int    // Number of rule groups
	DomainListCount     int    // Number of domain lists
	Notes               []string
	RequiresCloudAccess bool // Indicates cloud API needed for full details
}

// GCPResponsePolicyInfo represents GCP Cloud DNS Response Policy
// Note: Full enumeration requires GCP API access with --gcp-project flag
type GCPResponsePolicyInfo struct {
	Name                string
	Namespace           string
	ClusterScope        bool // If bound to GKE cluster
	RuleCount           int
	Notes               []string
	RequiresCloudAccess bool
}

// AzureDNSPrivateResolverInfo represents Azure DNS Private Resolver
// Note: Full enumeration requires Azure API access with --azure-subscription flag
type AzureDNSPrivateResolverInfo struct {
	Name                string
	Namespace           string
	LinkedVNET          bool
	InboundEndpoints    int
	OutboundEndpoints   int
	ForwardingRuleSets  int
	Notes               []string
	RequiresCloudAccess bool
}

// DNSCloudClients holds cloud provider clients for DNS policy enumeration
type DNSCloudClients struct {
	// AWS Route 53 Resolver
	AWSRoute53ResolverClient *route53resolver.Client
	AWSRegion                string

	// GCP Cloud DNS
	GCPDNSService *dns.Service
	GCPProjects   []string

	// Azure DNS
	AzureCredential    *azidentity.DefaultAzureCredential
	AzureSubscriptions []string
}

// containsDNSProvider checks if a provider is in the list
func containsDNSProvider(providers []string, provider string) bool {
	for _, p := range providers {
		if p == provider {
			return true
		}
	}
	return false
}

// initDNSCloudClients attempts to initialize cloud provider clients for DNS policy enumeration
// All errors are suppressed since cloud correlation is optional
// Only initializes clients for providers specified in globals.K8sCloudProviders
func initDNSCloudClients(logger internal.Logger) *DNSCloudClients {
	// If no cloud providers specified, skip cloud correlation entirely
	if len(globals.K8sCloudProviders) == 0 {
		logger.InfoM("DNS cloud correlation disabled (use --cloud-provider to enable)", K8S_DNS_ADMISSION_MODULE_NAME)
		return nil
	}

	clients := &DNSCloudClients{}
	cloudEnabled := false

	// Try AWS Route 53 Resolver - only if "aws" is in the provider list
	if containsDNSProvider(globals.K8sCloudProviders, "aws") {
		var awsCfg aws.Config
		var err error
		if globals.K8sAWSProfile != "" {
			awsCfg, err = awsconfig.LoadDefaultConfig(context.Background(),
				awsconfig.WithSharedConfigProfile(globals.K8sAWSProfile))
		} else {
			// Load default config with EC2 IMDS region detection for instance roles
			awsCfg, err = awsconfig.LoadDefaultConfig(context.Background(),
				awsconfig.WithEC2IMDSRegion())
		}
		if err == nil {
			clients.AWSRoute53ResolverClient = route53resolver.NewFromConfig(awsCfg)
			clients.AWSRegion = awsCfg.Region
			if awsCfg.Region != "" {
				logger.InfoM(fmt.Sprintf("AWS DNS correlation enabled (region: %s)", awsCfg.Region), K8S_DNS_ADMISSION_MODULE_NAME)
				cloudEnabled = true
			} else {
				// Try to get region from EC2 IMDS as a fallback
				imdsClient := imds.NewFromConfig(awsCfg)
				regionResp, regionErr := imdsClient.GetRegion(context.Background(), &imds.GetRegionInput{})
				if regionErr == nil && regionResp.Region != "" {
					clients.AWSRegion = regionResp.Region
					// Rebuild config with explicit region
					awsCfg, err = awsconfig.LoadDefaultConfig(context.Background(),
						awsconfig.WithRegion(regionResp.Region))
					if err == nil {
						clients.AWSRoute53ResolverClient = route53resolver.NewFromConfig(awsCfg)
						logger.InfoM(fmt.Sprintf("AWS DNS correlation enabled (EC2 instance credentials, region: %s)", regionResp.Region), K8S_DNS_ADMISSION_MODULE_NAME)
						cloudEnabled = true
					}
				}
			}
		} else {
			logger.InfoM(fmt.Sprintf("AWS DNS correlation failed: %v", err), K8S_DNS_ADMISSION_MODULE_NAME)
		}
	}

	// Try GCP Cloud DNS - only if "gcp" is in the provider list
	if containsDNSProvider(globals.K8sCloudProviders, "gcp") {
		gcpSvc, err := dns.NewService(context.Background(), option.WithScopes(dns.CloudPlatformReadOnlyScope))
		if err == nil {
			clients.GCPDNSService = gcpSvc

			// Use projects from flag if provided
			if len(globals.K8sGCPProjects) > 0 {
				clients.GCPProjects = globals.K8sGCPProjects
				logger.InfoM(fmt.Sprintf("GCP DNS correlation enabled (%d projects)", len(globals.K8sGCPProjects)), K8S_DNS_ADMISSION_MODULE_NAME)
				cloudEnabled = true
			} else {
				logger.InfoM("GCP DNS correlation enabled (no projects specified, will try to discover)", K8S_DNS_ADMISSION_MODULE_NAME)
				cloudEnabled = true
			}
		} else {
			logger.InfoM(fmt.Sprintf("GCP DNS correlation failed: %v", err), K8S_DNS_ADMISSION_MODULE_NAME)
		}
	}

	// Try Azure DNS - only if "azure" is in the provider list
	if containsDNSProvider(globals.K8sCloudProviders, "azure") {
		azCred, err := azidentity.NewDefaultAzureCredential(nil)
		if err == nil {
			clients.AzureCredential = azCred

			// Use subscriptions from flag if provided
			if len(globals.K8sAzureSubscriptions) > 0 {
				clients.AzureSubscriptions = globals.K8sAzureSubscriptions
				logger.InfoM(fmt.Sprintf("Azure DNS correlation enabled (%d subscriptions)", len(globals.K8sAzureSubscriptions)), K8S_DNS_ADMISSION_MODULE_NAME)
				cloudEnabled = true
			} else {
				logger.InfoM("Azure DNS correlation enabled (no subscriptions specified, will try to discover)", K8S_DNS_ADMISSION_MODULE_NAME)
				cloudEnabled = true
			}
		} else {
			logger.InfoM(fmt.Sprintf("Azure DNS correlation failed: %v", err), K8S_DNS_ADMISSION_MODULE_NAME)
		}
	}

	if !cloudEnabled {
		return nil
	}

	return clients
}

func ListDNSAdmission(cmd *cobra.Command, args []string) {
	ctx, cancel := shared.ContextWithCancel()
	defer cancel()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDir, _ := parentCmd.PersistentFlags().GetString("outdir")
	detailed := globals.K8sDetailed

	logger.InfoM(fmt.Sprintf("Analyzing DNS security for %s", globals.ClusterName), K8S_DNS_ADMISSION_MODULE_NAME)

	clientset := config.GetClientOrExit()
	dynClient := config.GetDynamicClientOrExit()

	// Analyze CoreDNS
	logger.InfoM("Analyzing CoreDNS...", K8S_DNS_ADMISSION_MODULE_NAME)
	coredns, corednsConfig := analyzeCoreDNS(ctx, clientset)

	// Analyze NodeLocalDNS
	logger.InfoM("Analyzing NodeLocalDNS...", K8S_DNS_ADMISSION_MODULE_NAME)
	nodeLocalDNS := analyzeNodeLocalDNS(ctx, clientset)

	// Analyze external-dns
	logger.InfoM("Analyzing external-dns...", K8S_DNS_ADMISSION_MODULE_NAME)
	externalDNS := analyzeExternalDNS(ctx, clientset)

	// Analyze Cilium DNS policies
	logger.InfoM("Analyzing Cilium DNS policies...", K8S_DNS_ADMISSION_MODULE_NAME)
	ciliumDNS := analyzeCiliumDNSPolicies(ctx, dynClient)

	// Analyze Calico DNS policies
	logger.InfoM("Analyzing Calico DNS policies...", K8S_DNS_ADMISSION_MODULE_NAME)
	calicoDNS := analyzeCalicoDNSPolicies(ctx, dynClient)

	// Analyze pod DNS configurations
	logger.InfoM("Analyzing pod DNS configurations...", K8S_DNS_ADMISSION_MODULE_NAME)
	podDNS := analyzePodDNS(ctx, clientset)

	// Analyze Istio DNS proxy
	logger.InfoM("Analyzing Istio DNS proxy...", K8S_DNS_ADMISSION_MODULE_NAME)
	istioDNS := analyzeIstioDNS(ctx, clientset)

	// Analyze cloud provider DNS
	logger.InfoM("Analyzing cloud provider DNS...", K8S_DNS_ADMISSION_MODULE_NAME)
	cloudDNS := analyzeCloudDNS(ctx, clientset)

	// Analyze ExternalName services
	logger.InfoM("Analyzing ExternalName services...", K8S_DNS_ADMISSION_MODULE_NAME)
	externalNameSvcs := analyzeExternalNameServices(ctx, clientset)

	// Analyze Headless services
	logger.InfoM("Analyzing Headless services...", K8S_DNS_ADMISSION_MODULE_NAME)
	headlessSvcs := analyzeHeadlessServices(ctx, clientset)

	// Analyze DNS exfiltration risks
	logger.InfoM("Analyzing DNS exfiltration risks...", K8S_DNS_ADMISSION_MODULE_NAME)
	exfilRisks := analyzeDNSExfiltrationRisks(ctx, clientset, podDNS, ciliumDNS, calicoDNS)

	// Analyze Kyverno DNS policies
	logger.InfoM("Analyzing Kyverno DNS policies...", K8S_DNS_ADMISSION_MODULE_NAME)
	kyvernoDNS := analyzeKyvernoDNSPolicies(ctx, dynClient)

	// Analyze Gatekeeper DNS constraints
	logger.InfoM("Analyzing Gatekeeper DNS constraints...", K8S_DNS_ADMISSION_MODULE_NAME)
	gatekeeperDNS := analyzeGatekeeperDNSConstraints(ctx, dynClient)

	// Analyze Consul DNS
	logger.InfoM("Analyzing Consul DNS...", K8S_DNS_ADMISSION_MODULE_NAME)
	consulDNS := analyzeConsulDNS(ctx, clientset)

	// Analyze EKS Admin Network Policies
	logger.InfoM("Analyzing EKS Admin Network Policies...", K8S_DNS_ADMISSION_MODULE_NAME)
	eksAdminPolicies := analyzeEKSAdminNetworkPolicies(ctx, dynClient)

	// Analyze native Kubernetes NetworkPolicy DNS rules
	logger.InfoM("Analyzing Kubernetes NetworkPolicy DNS rules...", K8S_DNS_ADMISSION_MODULE_NAME)
	k8sNetPolDNS := analyzeK8sNetworkPolicyDNS(ctx, clientset)

	// Analyze Istio ServiceEntry for DNS
	logger.InfoM("Analyzing Istio ServiceEntry DNS...", K8S_DNS_ADMISSION_MODULE_NAME)
	istioServiceEntries := analyzeIstioServiceEntries(ctx, dynClient)

	// Analyze Antrea FQDN policies
	logger.InfoM("Analyzing Antrea FQDN policies...", K8S_DNS_ADMISSION_MODULE_NAME)
	antreaFQDNPolicies := analyzeAntreaFQDNPolicies(ctx, dynClient)
	if len(antreaFQDNPolicies) > 0 {
		logger.InfoM(fmt.Sprintf("Found %d Antrea FQDN policies", len(antreaFQDNPolicies)), K8S_DNS_ADMISSION_MODULE_NAME)
	}

	// Analyze Consul DNS forwarding
	logger.InfoM("Analyzing Consul DNS forwarding...", K8S_DNS_ADMISSION_MODULE_NAME)
	consulDNSForwarding := analyzeConsulDNSForwarding(ctx, dynClient, clientset)
	if len(consulDNSForwarding) > 0 {
		logger.InfoM(fmt.Sprintf("Found %d Consul DNS forwarding configurations", len(consulDNSForwarding)), K8S_DNS_ADMISSION_MODULE_NAME)
	}

	// Analyze Kubewarden DNS policies
	logger.InfoM("Analyzing Kubewarden DNS policies...", K8S_DNS_ADMISSION_MODULE_NAME)
	kubewardenDNSPolicies := analyzeKubewardenDNSPolicies(ctx, dynClient)
	if len(kubewardenDNSPolicies) > 0 {
		logger.InfoM(fmt.Sprintf("Found %d Kubewarden DNS policies", len(kubewardenDNSPolicies)), K8S_DNS_ADMISSION_MODULE_NAME)
	}

	// Initialize cloud clients for DNS policy enumeration (if cloud providers specified)
	dnsCloudClients := initDNSCloudClients(logger)

	// Analyze cloud provider DNS policies (in-cluster detection + cloud API if available)
	logger.InfoM("Analyzing cloud provider DNS policies...", K8S_DNS_ADMISSION_MODULE_NAME)
	awsDNSFirewall := analyzeAWSRoute53DNSFirewall(ctx, clientset, cloudDNS, dnsCloudClients, logger)
	gcpResponsePolicies := analyzeGCPResponsePolicies(ctx, clientset, cloudDNS, dnsCloudClients, logger)
	azureDNSResolver := analyzeAzureDNSPrivateResolver(ctx, clientset, cloudDNS, dnsCloudClients, logger)

	// Log detected cloud provider DNS configurations
	if awsDNSFirewall.Name != "" {
		logger.InfoM(fmt.Sprintf("Detected AWS DNS: %s (%d rule groups, %d domain lists)", awsDNSFirewall.Name, awsDNSFirewall.RuleGroupCount, awsDNSFirewall.DomainListCount), K8S_DNS_ADMISSION_MODULE_NAME)
	}
	if gcpResponsePolicies.Name != "" {
		logger.InfoM(fmt.Sprintf("Detected GCP DNS: %s (%d rules)", gcpResponsePolicies.Name, gcpResponsePolicies.RuleCount), K8S_DNS_ADMISSION_MODULE_NAME)
	}
	if azureDNSResolver.Name != "" {
		logger.InfoM(fmt.Sprintf("Detected Azure DNS: %s (%d inbound, %d outbound, %d rulesets)", azureDNSResolver.Name, azureDNSResolver.InboundEndpoints, azureDNSResolver.OutboundEndpoints, azureDNSResolver.ForwardingRuleSets), K8S_DNS_ADMISSION_MODULE_NAME)
	}

	// Build findings per namespace
	findings := buildDNSAdmissionFindings(coredns, ciliumDNS, calicoDNS, kyvernoDNS, gatekeeperDNS, eksAdminPolicies, k8sNetPolDNS, istioServiceEntries, podDNS)

	// Generate tables
	summaryHeader := []string{
		"Namespace",
		"Pods Total",
		"Default DNS",
		"Custom DNS",
		"No DNS",
		"Cilium",
		"Calico",
		"Kyverno",
		"Gatekeeper",
		"EKS",
		"NetPol",
		"Istio",
		"Issues",
	}

	// Unified policies table header
	policiesHeader := []string{
		"Namespace",
		"Tool",
		"Name",
		"Scope",
		"Type",
		"Details",
	}

	corednsHeader := []string{
		"Namespace",
		"Status",
		"Pods Running",
		"Version",
		"Caching",
		"Logging",
		"Health",
		"Issues",
	}

	corednsConfigHeader := []string{
		"Zone",
		"Plugins",
		"Upstreams",
		"Forward To",
		"Cache TTL",
		"Issues",
	}

	nodeLocalDNSHeader := []string{
		"Namespace",
		"Status",
		"Pods Running",
		"Local IP",
		"Issues",
	}

	externalDNSHeader := []string{
		"Namespace",
		"Status",
		"Provider",
		"Sources",
		"Policy",
		"Issues",
	}

	// Uniform header for detailed policy tables (consistent across all admission modules)
	uniformPolicyHeader := []string{
		"Namespace",
		"Name",
		"Scope",
		"Target",
		"Type",
		"Rules",
		"Details",
		"Issues",
	}

	// Use uniform headers for detailed policy tables
	ciliumDNSHeader := uniformPolicyHeader
	calicoDNSHeader := uniformPolicyHeader
	kyvernoHeader := uniformPolicyHeader
	gatekeeperHeader := uniformPolicyHeader
	k8sNetPolDNSHeader := uniformPolicyHeader
	consulDNSForwardingHeader := uniformPolicyHeader
	kubewardenDNSHeader := uniformPolicyHeader
	awsDNSFirewallHeader := uniformPolicyHeader
	gcpResponsePolicyHeader := uniformPolicyHeader
	azureDNSResolverHeader := uniformPolicyHeader
	istioServiceEntryHeader := uniformPolicyHeader
	podDNSHeader := uniformPolicyHeader
	externalNameHeader := uniformPolicyHeader
	headlessHeader := uniformPolicyHeader
	exfilRiskHeader := uniformPolicyHeader

	// Deployment status tables keep their specific headers
	istioDNSHeader := []string{
		"Namespace",
		"Status",
		"Pods Running",
		"DNS Capture",
		"Auto Allocate",
		"Issues",
	}

	cloudDNSHeader := []string{
		"Namespace",
		"Provider",
		"Name",
		"Status",
		"Type",
		"Pods Running",
		"Issues",
	}

	consulHeader := []string{
		"Namespace",
		"Name",
		"Status",
		"Pods Running",
		"DNS Domain",
		"Issues",
	}

	var summaryRows [][]string
	var policiesRows [][]string
	var corednsRows [][]string
	var corednsConfigRows [][]string
	var nodeLocalDNSRows [][]string
	var externalDNSRows [][]string
	var ciliumDNSRows [][]string
	var calicoDNSRows [][]string
	var podDNSRows [][]string
	var istioDNSRows [][]string
	var cloudDNSRows [][]string
	var externalNameRows [][]string
	var headlessRows [][]string
	var exfilRiskRows [][]string
	var kyvernoRows [][]string
	var gatekeeperRows [][]string
	var consulRows [][]string
	var k8sNetPolDNSRows [][]string
	var consulDNSForwardingRows [][]string
	var kubewardenDNSRows [][]string
	var awsDNSFirewallRows [][]string
	var gcpResponsePolicyRows [][]string
	var azureDNSResolverRows [][]string
	var istioServiceEntryRows [][]string

	loot := shared.NewLootBuilder()

	// Build summary rows
	for _, finding := range findings {
		issues := "-"
		if len(finding.SecurityIssues) > 0 {
			if len(finding.SecurityIssues) > 2 {
				issues = strings.Join(finding.SecurityIssues[:2], "; ") + fmt.Sprintf(" (+%d)", len(finding.SecurityIssues)-2)
			} else {
				issues = strings.Join(finding.SecurityIssues, "; ")
			}
		}

		summaryRows = append(summaryRows, []string{
			finding.Namespace,
			fmt.Sprintf("%d", finding.TotalPods),
			fmt.Sprintf("%d", finding.PodsWithDefaultDNS),
			fmt.Sprintf("%d", finding.PodsWithCustomDNS),
			fmt.Sprintf("%d", finding.PodsWithNoDNS),
			fmt.Sprintf("%d", finding.CiliumPolicies),
			fmt.Sprintf("%d", finding.CalicoPolicies),
			fmt.Sprintf("%d", finding.KyvernoPolicies),
			fmt.Sprintf("%d", finding.GatekeeperPolicies),
			fmt.Sprintf("%d", finding.EKSAdminPolicies),
			fmt.Sprintf("%d", finding.K8sNetPolDNS),
			fmt.Sprintf("%d", finding.IstioServiceEntries),
			issues,
		})
	}

	// Build CoreDNS rows
	if coredns.Name != "" {
		caching := "No"
		if coredns.CacheEnabled {
			caching = "Yes"
		}
		logging := "No"
		if coredns.LoggingEnabled {
			logging = "Yes"
		}
		health := "No"
		if coredns.HealthEnabled {
			health = "Yes"
		}

		// Detect issues
		var corednsIssues []string
		if !coredns.CacheEnabled {
			corednsIssues = append(corednsIssues, "Caching disabled")
		}
		if !coredns.LoggingEnabled {
			corednsIssues = append(corednsIssues, "Logging disabled")
		}
		if !coredns.HealthEnabled {
			corednsIssues = append(corednsIssues, "Health checks disabled")
		}
		if coredns.Status != "Running" && coredns.Status != "Healthy" {
			corednsIssues = append(corednsIssues, "Not running")
		}
		if coredns.PodsRunning < coredns.TotalPods {
			corednsIssues = append(corednsIssues, "Some pods not running")
		}
		corednsIssuesStr := "<NONE>"
		if len(corednsIssues) > 0 {
			corednsIssuesStr = strings.Join(corednsIssues, "; ")
		}

		corednsRows = append(corednsRows, []string{
			coredns.Namespace,
			coredns.Status,
			fmt.Sprintf("%d/%d", coredns.PodsRunning, coredns.TotalPods),
			coredns.Version,
			caching,
			logging,
			health,
			corednsIssuesStr,
		})

		// Add to unified policies table
		policiesRows = append(policiesRows, []string{
			coredns.Namespace,
			"CoreDNS",
			coredns.Name,
			"Cluster",
			"DNS Server",
			fmt.Sprintf("Status: %s, Pods: %d/%d, Version: %s", coredns.Status, coredns.PodsRunning, coredns.TotalPods, coredns.Version),
		})
	}

	// Build CoreDNS config rows
	for _, cfg := range corednsConfig {
		plugins := "-"
		if len(cfg.Plugins) > 0 {
			if len(cfg.Plugins) > 5 {
				plugins = strings.Join(cfg.Plugins[:5], ", ") + "..."
			} else {
				plugins = strings.Join(cfg.Plugins, ", ")
			}
		}

		upstreams := "-"
		if len(cfg.Upstreams) > 0 {
			upstreams = strings.Join(cfg.Upstreams, ", ")
		}

		forwardTo := "-"
		if len(cfg.ForwardTo) > 0 {
			forwardTo = strings.Join(cfg.ForwardTo, ", ")
		}

		cacheTTL := "-"
		if cfg.Caching {
			cacheTTL = fmt.Sprintf("%ds", cfg.CacheTTL)
		}

		// Detect issues
		var cfgIssues []string
		if !cfg.Caching {
			cfgIssues = append(cfgIssues, "No caching configured")
		}
		if len(cfg.ForwardTo) == 0 && len(cfg.Upstreams) == 0 {
			cfgIssues = append(cfgIssues, "No upstreams configured")
		}
		cfgIssuesStr := "<NONE>"
		if len(cfgIssues) > 0 {
			cfgIssuesStr = strings.Join(cfgIssues, "; ")
		}

		corednsConfigRows = append(corednsConfigRows, []string{
			cfg.Zone,
			plugins,
			upstreams,
			forwardTo,
			cacheTTL,
			cfgIssuesStr,
		})

		// Add to unified policies table
		details := fmt.Sprintf("Plugins: %s", plugins)
		if forwardTo != "-" {
			details += fmt.Sprintf(", Forward: %s", forwardTo)
		}
		if cacheTTL != "-" {
			details += fmt.Sprintf(", Cache TTL: %s", cacheTTL)
		}

		policiesRows = append(policiesRows, []string{
			coredns.Namespace,
			"CoreDNS Config",
			cfg.Zone,
			"Cluster",
			"Zone Config",
			details,
		})
	}

	// Build NodeLocalDNS rows
	if nodeLocalDNS.Name != "" {
		// Detect issues
		var nodeLocalIssues []string
		if nodeLocalDNS.Status != "Running" && nodeLocalDNS.Status != "Healthy" {
			nodeLocalIssues = append(nodeLocalIssues, "Not running")
		}
		if nodeLocalDNS.PodsRunning < nodeLocalDNS.TotalPods {
			nodeLocalIssues = append(nodeLocalIssues, "Some pods not running")
		}
		if nodeLocalDNS.LocalIP == "" {
			nodeLocalIssues = append(nodeLocalIssues, "No local IP configured")
		}
		nodeLocalIssuesStr := "<NONE>"
		if len(nodeLocalIssues) > 0 {
			nodeLocalIssuesStr = strings.Join(nodeLocalIssues, "; ")
		}

		nodeLocalDNSRows = append(nodeLocalDNSRows, []string{
			nodeLocalDNS.Namespace,
			nodeLocalDNS.Status,
			fmt.Sprintf("%d/%d", nodeLocalDNS.PodsRunning, nodeLocalDNS.TotalPods),
			nodeLocalDNS.LocalIP,
			nodeLocalIssuesStr,
		})

		// Add to unified policies table
		policiesRows = append(policiesRows, []string{
			nodeLocalDNS.Namespace,
			"NodeLocalDNS",
			nodeLocalDNS.Name,
			"Node",
			"DNS Cache",
			fmt.Sprintf("Status: %s, Pods: %d/%d, Local IP: %s", nodeLocalDNS.Status, nodeLocalDNS.PodsRunning, nodeLocalDNS.TotalPods, nodeLocalDNS.LocalIP),
		})
	}

	// Build external-dns rows
	if externalDNS.Name != "" {
		sources := "-"
		if len(externalDNS.Sources) > 0 {
			sources = strings.Join(externalDNS.Sources, ", ")
		}

		// Detect issues
		var extDNSIssues []string
		if externalDNS.Status != "Running" && externalDNS.Status != "Healthy" {
			extDNSIssues = append(extDNSIssues, "Not running")
		}
		if externalDNS.Policy == "sync" {
			extDNSIssues = append(extDNSIssues, "Sync policy (deletes records)")
		}
		if len(externalDNS.Sources) == 0 {
			extDNSIssues = append(extDNSIssues, "No sources configured")
		}
		extDNSIssuesStr := "<NONE>"
		if len(extDNSIssues) > 0 {
			extDNSIssuesStr = strings.Join(extDNSIssues, "; ")
		}

		externalDNSRows = append(externalDNSRows, []string{
			externalDNS.Namespace,
			externalDNS.Status,
			externalDNS.Provider,
			sources,
			externalDNS.Policy,
			extDNSIssuesStr,
		})

		// Add to unified policies table
		policiesRows = append(policiesRows, []string{
			externalDNS.Namespace,
			"external-dns",
			externalDNS.Name,
			"Cluster",
			"External DNS",
			fmt.Sprintf("Provider: %s, Policy: %s, Sources: %s", externalDNS.Provider, externalDNS.Policy, sources),
		})
	}

	// Build Cilium DNS policy rows
	for _, cdns := range ciliumDNS {
		scope := "Namespace"
		ns := cdns.Namespace
		if cdns.IsCluster {
			scope = "Cluster"
			ns = "<CLUSTER>"
		}

		// Target - FQDNs or patterns being matched
		target := "-"
		if len(cdns.MatchFQDNs) > 0 {
			if len(cdns.MatchFQDNs) > 2 {
				target = strings.Join(cdns.MatchFQDNs[:2], ", ") + "..."
			} else {
				target = strings.Join(cdns.MatchFQDNs, ", ")
			}
		} else if len(cdns.MatchPatterns) > 0 {
			if len(cdns.MatchPatterns) > 2 {
				target = strings.Join(cdns.MatchPatterns[:2], ", ") + "..."
			} else {
				target = strings.Join(cdns.MatchPatterns, ", ")
			}
		}

		// Rules description
		var rulesParts []string
		if len(cdns.MatchFQDNs) > 0 {
			rulesParts = append(rulesParts, fmt.Sprintf("FQDNs (%d)", len(cdns.MatchFQDNs)))
		}
		if len(cdns.MatchPatterns) > 0 {
			rulesParts = append(rulesParts, fmt.Sprintf("Patterns (%d)", len(cdns.MatchPatterns)))
		}
		rules := "None"
		if len(rulesParts) > 0 {
			rules = strings.Join(rulesParts, ", ")
		}

		// Details
		details := fmt.Sprintf("Action: %s, DNS Rules: %d", cdns.Action, cdns.DNSRules)

		// Detect issues
		var ciliumIssues []string
		if cdns.DNSRules == 0 {
			ciliumIssues = append(ciliumIssues, "No DNS rules defined")
		}
		if cdns.Action == "allow" || cdns.Action == "Allow" {
			ciliumIssues = append(ciliumIssues, "Allows DNS traffic")
		}
		if len(cdns.MatchPatterns) > 0 {
			for _, p := range cdns.MatchPatterns {
				if p == "*" || p == ".*" {
					ciliumIssues = append(ciliumIssues, "Wildcard pattern")
					break
				}
			}
		}
		ciliumIssuesStr := "<NONE>"
		if len(ciliumIssues) > 0 {
			ciliumIssuesStr = strings.Join(ciliumIssues, "; ")
		}

		ciliumDNSRows = append(ciliumDNSRows, []string{
			ns,
			cdns.Name,
			scope,
			target,
			"Cilium DNS Policy",
			rules,
			details,
			ciliumIssuesStr,
		})

		// Add to unified policies table
		policyDetails := fmt.Sprintf("DNS Rules: %d, Action: %s", cdns.DNSRules, cdns.Action)
		if target != "-" {
			policyDetails += fmt.Sprintf(", Target: %s", target)
		}

		policiesRows = append(policiesRows, []string{
			ns,
			"Cilium DNS Policy",
			cdns.Name,
			scope,
			"Network Policy",
			policyDetails,
		})
	}

	// Build Calico DNS policy rows (uniform schema: Namespace, Name, Scope, Target, Type, Rules, Details, Issues)
	for _, cal := range calicoDNS {
		scope := "Namespace"
		ns := cal.Namespace
		if cal.IsGlobal {
			scope = "Global"
			ns = "<GLOBAL>"
		}

		// Target - domains being matched
		target := "-"
		if len(cal.Domains) > 0 {
			if len(cal.Domains) > 2 {
				target = strings.Join(cal.Domains[:2], ", ") + "..."
			} else {
				target = strings.Join(cal.Domains, ", ")
			}
		}

		// Rules description
		rules := fmt.Sprintf("Domains (%d)", len(cal.Domains))
		if len(cal.Domains) == 0 {
			rules = "None"
		}

		// Details
		details := fmt.Sprintf("Action: %s, DNS Rules: %d", cal.Action, cal.DNSRules)

		// Detect issues
		var calicoIssues []string
		if cal.DNSRules == 0 {
			calicoIssues = append(calicoIssues, "No DNS rules defined")
		}
		if cal.Action == "Allow" || cal.Action == "allow" {
			calicoIssues = append(calicoIssues, "Allows DNS traffic")
		}
		if len(cal.Domains) > 0 {
			for _, d := range cal.Domains {
				if d == "*" || d == ".*" {
					calicoIssues = append(calicoIssues, "Wildcard domain")
					break
				}
			}
		}
		calicoIssuesStr := "<NONE>"
		if len(calicoIssues) > 0 {
			calicoIssuesStr = strings.Join(calicoIssues, "; ")
		}

		calicoDNSRows = append(calicoDNSRows, []string{
			ns,
			cal.Name,
			scope,
			target,
			"Calico DNS Policy",
			rules,
			details,
			calicoIssuesStr,
		})

		// Add to unified policies table
		policyDetails := fmt.Sprintf("DNS Rules: %d, Action: %s", cal.DNSRules, cal.Action)
		if target != "-" {
			policyDetails += fmt.Sprintf(", Domains: %s", target)
		}

		policiesRows = append(policiesRows, []string{
			ns,
			"Calico DNS Policy",
			cal.Name,
			scope,
			"Network Policy",
			policyDetails,
		})
	}

	// Build pod DNS rows (uniform schema: Namespace, Name, Scope, Target, Type, Rules, Details, Issues)
	for _, p := range podDNS {
		if p.DNSPolicy == "None" || p.HasCustomDNS {
			// Target - nameservers
			target := "-"
			if len(p.Nameservers) > 0 {
				target = strings.Join(p.Nameservers, ", ")
			}

			// Rules - DNS policy setting
			rules := fmt.Sprintf("Policy: %s", p.DNSPolicy)
			if p.HasCustomDNS {
				rules += ", Custom: Yes"
			}

			// Details - searches and additional info
			var detailParts []string
			if len(p.Searches) > 0 {
				if len(p.Searches) > 2 {
					detailParts = append(detailParts, fmt.Sprintf("Searches: %s...", strings.Join(p.Searches[:2], ", ")))
				} else {
					detailParts = append(detailParts, fmt.Sprintf("Searches: %s", strings.Join(p.Searches, ", ")))
				}
			}
			details := strings.Join(detailParts, ", ")
			if details == "" {
				details = "-"
			}

			// Detect issues
			var podDNSIssues []string
			if p.DNSPolicy == "None" {
				podDNSIssues = append(podDNSIssues, "DNS policy None (external DNS)")
			}
			if p.HasCustomDNS {
				podDNSIssues = append(podDNSIssues, "Custom DNS configured")
			}
			for _, ns := range p.Nameservers {
				if !strings.HasPrefix(ns, "10.") && !strings.HasPrefix(ns, "172.") && !strings.HasPrefix(ns, "192.168.") {
					podDNSIssues = append(podDNSIssues, "External nameserver")
					break
				}
			}
			podDNSIssuesStr := "<NONE>"
			if len(podDNSIssues) > 0 {
				podDNSIssuesStr = strings.Join(podDNSIssues, "; ")
			}

			podDNSRows = append(podDNSRows, []string{
				p.Namespace,
				p.Name,
				"Pod",
				target,
				"Pod DNS Config",
				rules,
				details,
				podDNSIssuesStr,
			})

			// Add to unified policies table
			policyDetails := fmt.Sprintf("DNS Policy: %s", p.DNSPolicy)
			if p.HasCustomDNS {
				policyDetails += ", Custom: Yes"
			}
			if target != "-" {
				policyDetails += fmt.Sprintf(", Nameservers: %s", target)
			}

			policiesRows = append(policiesRows, []string{
				p.Namespace,
				"Pod DNS Config",
				p.Name,
				"Pod",
				"DNS Override",
				policyDetails,
			})
		}
	}

	// Build Istio DNS rows
	if istioDNS.Name != "" {
		dnsCapture := "No"
		if istioDNS.DNSCaptureEnabled {
			dnsCapture = "Yes"
		}
		autoAllocate := "No"
		if istioDNS.AutoAllocateEnabled {
			autoAllocate = "Yes"
		}

		// Detect issues
		var istioDNSIssues []string
		if istioDNS.Status != "Running" && istioDNS.Status != "Healthy" {
			istioDNSIssues = append(istioDNSIssues, "Not running")
		}
		if istioDNS.PodsRunning < istioDNS.TotalPods {
			istioDNSIssues = append(istioDNSIssues, "Some pods not running")
		}
		if !istioDNS.DNSCaptureEnabled {
			istioDNSIssues = append(istioDNSIssues, "DNS capture disabled")
		}
		istioDNSIssuesStr := "<NONE>"
		if len(istioDNSIssues) > 0 {
			istioDNSIssuesStr = strings.Join(istioDNSIssues, "; ")
		}

		istioDNSRows = append(istioDNSRows, []string{
			istioDNS.Namespace,
			istioDNS.Status,
			fmt.Sprintf("%d/%d", istioDNS.PodsRunning, istioDNS.TotalPods),
			dnsCapture,
			autoAllocate,
			istioDNSIssuesStr,
		})

		// Add to unified policies table
		policiesRows = append(policiesRows, []string{
			istioDNS.Namespace,
			"Istio DNS",
			istioDNS.Name,
			"Service Mesh",
			"DNS Proxy",
			fmt.Sprintf("Status: %s, DNS Capture: %s, Auto Allocate: %s", istioDNS.Status, dnsCapture, autoAllocate),
		})
	}

	// Build cloud DNS rows
	for _, cloud := range cloudDNS {
		// Detect issues
		var cloudIssues []string
		if cloud.Status != "Running" && cloud.Status != "Healthy" {
			cloudIssues = append(cloudIssues, "Not running")
		}
		if cloud.PodsRunning < cloud.TotalPods {
			cloudIssues = append(cloudIssues, "Some pods not running")
		}
		cloudIssuesStr := "<NONE>"
		if len(cloudIssues) > 0 {
			cloudIssuesStr = strings.Join(cloudIssues, "; ")
		}

		cloudDNSRows = append(cloudDNSRows, []string{
			cloud.Namespace,
			cloud.Provider,
			cloud.Name,
			cloud.Status,
			cloud.Type,
			fmt.Sprintf("%d/%d", cloud.PodsRunning, cloud.TotalPods),
			cloudIssuesStr,
		})

		// Add to unified policies table
		policiesRows = append(policiesRows, []string{
			cloud.Namespace,
			"Cloud DNS",
			cloud.Name,
			"Cloud",
			cloud.Type,
			fmt.Sprintf("Provider: %s, Status: %s, Pods: %d/%d", cloud.Provider, cloud.Status, cloud.PodsRunning, cloud.TotalPods),
		})
	}

	// Build ExternalName service rows (uniform schema: Namespace, Name, Scope, Target, Type, Rules, Details, Issues)
	for _, svc := range externalNameSvcs {
		notes := "-"
		if len(svc.Notes) > 0 {
			notes = strings.Join(svc.Notes, "; ")
		}

		// Detect issues
		var extNameIssues []string
		if strings.Contains(svc.ExternalName, "internal") {
			extNameIssues = append(extNameIssues, "Points to internal service")
		}
		if !strings.Contains(svc.ExternalName, ".") {
			extNameIssues = append(extNameIssues, "Not a valid FQDN")
		}
		extNameIssuesStr := "<NONE>"
		if len(extNameIssues) > 0 {
			extNameIssuesStr = strings.Join(extNameIssues, "; ")
		}

		externalNameRows = append(externalNameRows, []string{
			svc.Namespace,
			svc.Name,
			"Namespace",
			svc.ExternalName,
			"ExternalName Service",
			"DNS CNAME",
			notes,
			extNameIssuesStr,
		})

		// Add to unified policies table
		policiesRows = append(policiesRows, []string{
			svc.Namespace,
			"ExternalName Service",
			svc.Name,
			"Service",
			notes,
			fmt.Sprintf("Points to: %s", svc.ExternalName),
		})
	}

	// Build Headless service rows (uniform schema: Namespace, Name, Scope, Target, Type, Rules, Details, Issues)
	for _, svc := range headlessSvcs {
		ports := "-"
		if len(svc.Ports) > 0 {
			ports = strings.Join(svc.Ports, ", ")
		}
		notes := "-"
		if len(svc.Notes) > 0 {
			notes = strings.Join(svc.Notes, "; ")
		}

		// Detect issues
		var headlessIssues []string
		if svc.PodCount == 0 {
			headlessIssues = append(headlessIssues, "No backing pods")
		}
		if len(svc.Ports) == 0 {
			headlessIssues = append(headlessIssues, "No ports defined")
		}
		headlessIssuesStr := "<NONE>"
		if len(headlessIssues) > 0 {
			headlessIssuesStr = strings.Join(headlessIssues, "; ")
		}

		// Target - pods backing the service
		target := fmt.Sprintf("%d pods", svc.PodCount)

		// Rules - ports configuration
		rules := fmt.Sprintf("Ports: %s", ports)

		headlessRows = append(headlessRows, []string{
			svc.Namespace,
			svc.Name,
			"Namespace",
			target,
			"Headless Service",
			rules,
			notes,
			headlessIssuesStr,
		})
	}

	// Build DNS configuration rows (uniform schema: Namespace, Name, Scope, Target, Type, Rules, Details, Issues)
	for _, info := range exfilRisks {
		// Skip pods with no notable findings
		if len(info.Notes) == 0 {
			continue
		}
		hasPolicy := "No"
		if info.HasEgressPolicy {
			hasPolicy = "Yes"
		}
		externalDNS := "-"
		if len(info.ExternalDNS) > 0 {
			externalDNS = strings.Join(info.ExternalDNS, ", ")
		}
		dnsPolicy := info.DNSPolicy
		if dnsPolicy == "" {
			dnsPolicy = "ClusterFirst"
		}
		// Filter notes to remove redundant info now shown in columns
		var filteredNotes []string
		for _, note := range info.Notes {
			if !strings.Contains(note, "DNSPolicy=") && !strings.Contains(note, "External nameservers:") {
				filteredNotes = append(filteredNotes, note)
			}
		}
		notesStr := "-"
		if len(filteredNotes) > 0 {
			notesStr = strings.Join(filteredNotes, "; ")
		}

		// Detect issues
		var exfilIssues []string
		if !info.HasEgressPolicy {
			exfilIssues = append(exfilIssues, "No egress policy")
		}
		if dnsPolicy == "None" {
			exfilIssues = append(exfilIssues, "DNS policy None")
		}
		if len(info.ExternalDNS) > 0 {
			exfilIssues = append(exfilIssues, "External DNS configured")
		}
		exfilIssuesStr := "<NONE>"
		if len(exfilIssues) > 0 {
			exfilIssuesStr = strings.Join(exfilIssues, "; ")
		}

		// Target - external DNS servers if any
		target := "Cluster DNS"
		if externalDNS != "-" {
			target = externalDNS
		}

		// Rules - DNS policy and egress policy status
		rules := fmt.Sprintf("DNS: %s, Egress Policy: %s", dnsPolicy, hasPolicy)

		exfilRiskRows = append(exfilRiskRows, []string{
			info.Namespace,
			info.PodName,
			"Pod",
			target,
			"DNS Exfil Risk",
			rules,
			notesStr,
			exfilIssuesStr,
		})
	}

	// Build Kyverno DNS policy rows (uniform schema: Namespace, Name, Scope, Target, Type, Rules, Details, Issues)
	for _, policy := range kyvernoDNS {
		scope := "Namespace"
		ns := policy.Namespace
		if policy.IsCluster {
			scope = "Cluster"
			ns = "<CLUSTER>"
		}

		// Detect issues
		var kyvernoIssues []string
		if policy.Action == "audit" || policy.Action == "Audit" {
			kyvernoIssues = append(kyvernoIssues, "Audit mode only")
		}
		if policy.DNSRule == "" {
			kyvernoIssues = append(kyvernoIssues, "No DNS rule defined")
		}
		kyvernoIssuesStr := "<NONE>"
		if len(kyvernoIssues) > 0 {
			kyvernoIssuesStr = strings.Join(kyvernoIssues, "; ")
		}

		// Rules description
		rules := policy.DNSRule
		if rules == "" {
			rules = "None"
		}

		// Details
		details := fmt.Sprintf("Action: %s, Type: %s", policy.Action, policy.Type)

		kyvernoRows = append(kyvernoRows, []string{
			ns,
			policy.Name,
			scope,
			policy.Target,
			"Kyverno DNS Policy",
			rules,
			details,
			kyvernoIssuesStr,
		})

		// Add to unified policies table
		policiesRows = append(policiesRows, []string{
			ns,
			"Kyverno DNS Policy",
			policy.Name,
			scope,
			policy.Type,
			fmt.Sprintf("Target: %s, Rule: %s", policy.Target, policy.DNSRule),
		})
	}

	// Build Gatekeeper DNS constraint rows (uniform schema: Namespace, Name, Scope, Target, Type, Rules, Details, Issues)
	for _, constraint := range gatekeeperDNS {
		// Detect issues
		var gkIssues []string
		if constraint.EnforcementAction == "dryrun" || constraint.EnforcementAction == "warn" {
			gkIssues = append(gkIssues, "Not enforcing")
		}
		if constraint.DNSRule == "" {
			gkIssues = append(gkIssues, "No DNS rule defined")
		}
		gkIssuesStr := "<NONE>"
		if len(gkIssues) > 0 {
			gkIssuesStr = strings.Join(gkIssues, "; ")
		}

		// Rules description
		rules := constraint.DNSRule
		if rules == "" {
			rules = "None"
		}

		// Details
		details := fmt.Sprintf("Template: %s, Enforcement: %s", constraint.TemplateName, constraint.EnforcementAction)

		gatekeeperRows = append(gatekeeperRows, []string{
			"<CLUSTER>",
			constraint.Name,
			"Cluster",
			constraint.Target,
			"Gatekeeper DNS Constraint",
			rules,
			details,
			gkIssuesStr,
		})

		// Add to unified policies table
		policiesRows = append(policiesRows, []string{
			"<CLUSTER>",
			"Gatekeeper DNS Constraint",
			constraint.Name,
			"Cluster",
			constraint.EnforcementAction,
			fmt.Sprintf("Template: %s, Target: %s", constraint.TemplateName, constraint.Target),
		})
	}

	// Build Consul DNS rows
	if consulDNS.Name != "" {
		// Detect issues
		var consulIssues []string
		if consulDNS.Status != "Running" && consulDNS.Status != "Healthy" {
			consulIssues = append(consulIssues, "Not running")
		}
		if consulDNS.PodsRunning < consulDNS.TotalPods {
			consulIssues = append(consulIssues, "Some pods not running")
		}
		if consulDNS.DNSDomain == "" {
			consulIssues = append(consulIssues, "No DNS domain configured")
		}
		consulIssuesStr := "<NONE>"
		if len(consulIssues) > 0 {
			consulIssuesStr = strings.Join(consulIssues, "; ")
		}

		consulRows = append(consulRows, []string{
			consulDNS.Namespace,
			consulDNS.Name,
			consulDNS.Status,
			fmt.Sprintf("%d/%d", consulDNS.PodsRunning, consulDNS.TotalPods),
			consulDNS.DNSDomain,
			consulIssuesStr,
		})

		// Add to unified policies table
		policiesRows = append(policiesRows, []string{
			consulDNS.Namespace,
			"Consul DNS",
			consulDNS.Name,
			"Service Mesh",
			"Service Discovery",
			fmt.Sprintf("Status: %s, Domain: %s", consulDNS.Status, consulDNS.DNSDomain),
		})
	}

	// Build K8s NetworkPolicy DNS rows (uniform schema: Namespace, Name, Scope, Target, Type, Rules, Details, Issues)
	for _, p := range k8sNetPolDNS {
		notes := "-"
		if len(p.Notes) > 0 {
			notes = strings.Join(p.Notes, "; ")
		}

		// Detect issues
		var k8sNetPolIssues []string
		if !p.HasDNSEgress {
			k8sNetPolIssues = append(k8sNetPolIssues, "No DNS egress rules")
		}
		if p.DNSEgressAction == "allow" || p.DNSEgressAction == "" {
			k8sNetPolIssues = append(k8sNetPolIssues, "DNS egress allowed")
		}
		if p.PodSelector == "" || p.PodSelector == "*" {
			k8sNetPolIssues = append(k8sNetPolIssues, "Broad pod selector")
		}
		issuesStr := "<NONE>"
		if len(k8sNetPolIssues) > 0 {
			issuesStr = strings.Join(k8sNetPolIssues, "; ")
		}

		// Target - pod selector
		target := p.PodSelector
		if target == "" {
			target = "All pods"
		}

		// Rules - DNS egress configuration
		hasDNS := "No"
		if p.HasDNSEgress {
			hasDNS = "Yes"
		}
		rules := fmt.Sprintf("DNS Egress: %s, Action: %s", hasDNS, p.DNSEgressAction)

		k8sNetPolDNSRows = append(k8sNetPolDNSRows, []string{
			p.Namespace,
			p.Name,
			"Namespace",
			target,
			"K8s NetworkPolicy DNS",
			rules,
			notes,
			issuesStr,
		})
	}

	// Build Consul DNS Forwarding rows (uniform schema: Namespace, Name, Scope, Target, Type, Rules, Details, Issues)
	for _, c := range consulDNSForwarding {
		recursors := "-"
		if len(c.Recursors) > 0 {
			recursors = strings.Join(c.Recursors, ", ")
		}
		forwardingRules := "-"
		if len(c.ForwardingRules) > 0 {
			forwardingRules = strings.Join(c.ForwardingRules, ", ")
		}

		// Detect issues
		var consulDNSIssues []string
		if !c.EnableDNSProxy {
			consulDNSIssues = append(consulDNSIssues, "DNS proxy disabled")
		}
		if len(c.Recursors) == 0 {
			consulDNSIssues = append(consulDNSIssues, "No recursors configured")
		}
		if len(c.ForwardingRules) == 0 {
			consulDNSIssues = append(consulDNSIssues, "No forwarding rules")
		}
		issuesStr := "<NONE>"
		if len(consulDNSIssues) > 0 {
			issuesStr = strings.Join(consulDNSIssues, "; ")
		}

		// Target - DNS domain
		target := c.DNSDomain
		if target == "" {
			target = "Default"
		}

		// Rules - forwarding configuration
		rules := fmt.Sprintf("Recursors: %s", recursors)

		// Details
		proxyEnabled := "No"
		if c.EnableDNSProxy {
			proxyEnabled = "Yes"
		}
		details := fmt.Sprintf("DNS Proxy: %s, Forwarding: %s", proxyEnabled, forwardingRules)

		consulDNSForwardingRows = append(consulDNSForwardingRows, []string{
			c.Namespace,
			c.Name,
			"Namespace",
			target,
			"Consul DNS Forwarding",
			rules,
			details,
			issuesStr,
		})
	}

	// Build Kubewarden DNS Policy rows (uniform schema: Namespace, Name, Scope, Target, Type, Rules, Details, Issues)
	for _, p := range kubewardenDNSPolicies {
		// Detect issues
		var kubewardenDNSIssues []string
		if p.Mode == "monitor" || p.Mode == "audit" {
			kubewardenDNSIssues = append(kubewardenDNSIssues, "Not enforcing")
		}
		if len(p.DNSRules) == 0 {
			kubewardenDNSIssues = append(kubewardenDNSIssues, "No DNS rules defined")
		}
		issuesStr := "<NONE>"
		if len(kubewardenDNSIssues) > 0 {
			issuesStr = strings.Join(kubewardenDNSIssues, "; ")
		}

		// Target - affected resources
		target := "All pods"

		// Rules description
		rules := fmt.Sprintf("DNS Rules (%d)", len(p.DNSRules))
		if len(p.DNSRules) == 0 {
			rules = "None"
		}

		// Details
		details := fmt.Sprintf("Mode: %s, Server: %s, Module: %s", p.Mode, p.PolicyServer, p.Module)

		kubewardenDNSRows = append(kubewardenDNSRows, []string{
			p.Namespace,
			p.Name,
			"Namespace",
			target,
			"Kubewarden DNS Policy",
			rules,
			details,
			issuesStr,
		})
	}

	// Build AWS DNS Firewall rows (uniform schema: Namespace, Name, Scope, Target, Type, Rules, Details, Issues)
	if awsDNSFirewall.Name != "" {
		notes := "-"
		if len(awsDNSFirewall.Notes) > 0 {
			notes = strings.Join(awsDNSFirewall.Notes, "; ")
		}

		// Detect issues
		var awsDNSIssues []string
		if !awsDNSFirewall.VPCAssociation {
			awsDNSIssues = append(awsDNSIssues, "VPC not associated")
		}
		if awsDNSFirewall.RuleGroupCount == 0 {
			awsDNSIssues = append(awsDNSIssues, "No rule groups")
		}
		if awsDNSFirewall.DomainListCount == 0 {
			awsDNSIssues = append(awsDNSIssues, "No domain lists")
		}
		issuesStr := "<NONE>"
		if len(awsDNSIssues) > 0 {
			issuesStr = strings.Join(awsDNSIssues, "; ")
		}

		// Target - VPC
		target := "VPC"
		if !awsDNSFirewall.VPCAssociation {
			target = "VPC (not associated)"
		}

		// Rules description
		rules := fmt.Sprintf("Rule Groups: %d, Domain Lists: %d", awsDNSFirewall.RuleGroupCount, awsDNSFirewall.DomainListCount)

		// Details
		vpcAssoc := "No"
		if awsDNSFirewall.VPCAssociation {
			vpcAssoc = "Yes"
		}
		details := fmt.Sprintf("VPC Associated: %s, %s", vpcAssoc, notes)

		awsDNSFirewallRows = append(awsDNSFirewallRows, []string{
			awsDNSFirewall.Namespace,
			awsDNSFirewall.Name,
			"Cloud",
			target,
			"AWS DNS Firewall",
			rules,
			details,
			issuesStr,
		})
	}

	// Build GCP Response Policy rows (uniform schema: Namespace, Name, Scope, Target, Type, Rules, Details, Issues)
	if gcpResponsePolicies.Name != "" {
		notes := "-"
		if len(gcpResponsePolicies.Notes) > 0 {
			notes = strings.Join(gcpResponsePolicies.Notes, "; ")
		}

		// Detect issues
		var gcpRespIssues []string
		if !gcpResponsePolicies.ClusterScope {
			gcpRespIssues = append(gcpRespIssues, "Limited scope")
		}
		if gcpResponsePolicies.RuleCount == 0 {
			gcpRespIssues = append(gcpRespIssues, "No rules defined")
		}
		issuesStr := "<NONE>"
		if len(gcpRespIssues) > 0 {
			issuesStr = strings.Join(gcpRespIssues, "; ")
		}

		// Scope
		scope := "Limited"
		if gcpResponsePolicies.ClusterScope {
			scope = "Cluster"
		}

		// Target
		target := "DNS queries"

		// Rules description
		rules := fmt.Sprintf("Response Rules: %d", gcpResponsePolicies.RuleCount)

		// Details
		details := notes

		gcpResponsePolicyRows = append(gcpResponsePolicyRows, []string{
			gcpResponsePolicies.Namespace,
			gcpResponsePolicies.Name,
			scope,
			target,
			"GCP Response Policy",
			rules,
			details,
			issuesStr,
		})
	}

	// Build Azure DNS Private Resolver rows (uniform schema: Namespace, Name, Scope, Target, Type, Rules, Details, Issues)
	if azureDNSResolver.Name != "" {
		notes := "-"
		if len(azureDNSResolver.Notes) > 0 {
			notes = strings.Join(azureDNSResolver.Notes, "; ")
		}

		// Detect issues
		var azureDNSIssues []string
		if !azureDNSResolver.LinkedVNET {
			azureDNSIssues = append(azureDNSIssues, "VNET not linked")
		}
		if azureDNSResolver.InboundEndpoints == 0 {
			azureDNSIssues = append(azureDNSIssues, "No inbound endpoints")
		}
		if azureDNSResolver.ForwardingRuleSets == 0 {
			azureDNSIssues = append(azureDNSIssues, "No forwarding rules")
		}
		issuesStr := "<NONE>"
		if len(azureDNSIssues) > 0 {
			issuesStr = strings.Join(azureDNSIssues, "; ")
		}

		// Target - VNET
		target := "VNET"
		if !azureDNSResolver.LinkedVNET {
			target = "VNET (not linked)"
		}

		// Rules description
		rules := fmt.Sprintf("Inbound: %d, Outbound: %d, Forwarding: %d", azureDNSResolver.InboundEndpoints, azureDNSResolver.OutboundEndpoints, azureDNSResolver.ForwardingRuleSets)

		// Details
		vnetLinked := "No"
		if azureDNSResolver.LinkedVNET {
			vnetLinked = "Yes"
		}
		details := fmt.Sprintf("VNET Linked: %s, %s", vnetLinked, notes)

		azureDNSResolverRows = append(azureDNSResolverRows, []string{
			azureDNSResolver.Namespace,
			azureDNSResolver.Name,
			"Cloud",
			target,
			"Azure DNS Resolver",
			rules,
			details,
			issuesStr,
		})
	}

	// Build Istio ServiceEntry rows (uniform schema: Namespace, Name, Scope, Target, Type, Rules, Details, Issues)
	for _, s := range istioServiceEntries {
		// Target - hosts
		target := "-"
		if len(s.Hosts) > 0 {
			if len(s.Hosts) > 2 {
				target = strings.Join(s.Hosts[:2], ", ") + "..."
			} else {
				target = strings.Join(s.Hosts, ", ")
			}
		}

		ports := "-"
		if len(s.Ports) > 0 {
			if len(s.Ports) > 3 {
				ports = strings.Join(s.Ports[:3], ", ") + "..."
			} else {
				ports = strings.Join(s.Ports, ", ")
			}
		}

		// Detect issues
		var istioSEIssues []string
		if s.Location == "MESH_EXTERNAL" {
			istioSEIssues = append(istioSEIssues, "External mesh access")
		}
		for _, h := range s.Hosts {
			if h == "*" || strings.HasPrefix(h, "*.") {
				istioSEIssues = append(istioSEIssues, "Wildcard host")
				break
			}
		}
		if s.IsCluster {
			istioSEIssues = append(istioSEIssues, "Cluster-wide scope")
		}
		issuesStr := "<NONE>"
		if len(istioSEIssues) > 0 {
			issuesStr = strings.Join(istioSEIssues, "; ")
		}

		// Scope
		scope := "Namespace"
		ns := s.Namespace
		if s.IsCluster {
			scope = "Cluster"
			ns = "<CLUSTER>"
		}

		// Rules - location and resolution
		rules := fmt.Sprintf("Location: %s, Resolution: %s", s.Location, s.Resolution)

		// Details - ports
		details := fmt.Sprintf("Ports: %s", ports)

		istioServiceEntryRows = append(istioServiceEntryRows, []string{
			ns,
			s.Name,
			scope,
			target,
			"Istio ServiceEntry",
			rules,
			details,
			issuesStr,
		})
	}

	// Generate loot
	generateDNSAdmissionLoot(loot, coredns, nodeLocalDNS, externalDNS, ciliumDNS, calicoDNS, externalNameSvcs, exfilRisks)

	// Build output tables
	var tables []internal.TableFile

	tables = append(tables, internal.TableFile{
		Name:   "DNS-Admission-Summary",
		Header: summaryHeader,
		Body:   summaryRows,
	})

	// Always add unified policies table
	if len(policiesRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "DNS-Admission-Policy-Overview",
			Header: policiesHeader,
			Body:   policiesRows,
		})
	}

	// Always show security-critical tables
	if len(externalNameRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "DNS-Admission-ExternalName-Services",
			Header: externalNameHeader,
			Body:   externalNameRows,
		})
	}

	if len(exfilRiskRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "DNS-Admission-Exfiltration-Risks",
			Header: exfilRiskHeader,
			Body:   exfilRiskRows,
		})
	}

	// Detailed tables only if --detailed flag is set
	if detailed {
		if len(corednsRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "DNS-Admission-CoreDNS-Policies",
				Header: corednsHeader,
				Body:   corednsRows,
			})
		}

		if len(corednsConfigRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "DNS-Admission-CoreDNS-Config-Policies",
				Header: corednsConfigHeader,
				Body:   corednsConfigRows,
			})
		}

		if len(nodeLocalDNSRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "DNS-Admission-NodeLocalDNS-Policies",
				Header: nodeLocalDNSHeader,
				Body:   nodeLocalDNSRows,
			})
		}

		if len(externalDNSRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "DNS-Admission-ExternalDNS-Policies",
				Header: externalDNSHeader,
				Body:   externalDNSRows,
			})
		}

		if len(ciliumDNSRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "DNS-Admission-Cilium-DNS-Policies",
				Header: ciliumDNSHeader,
				Body:   ciliumDNSRows,
			})
		}

		if len(calicoDNSRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "DNS-Admission-Calico-DNS-Policies",
				Header: calicoDNSHeader,
				Body:   calicoDNSRows,
			})
		}

		if len(podDNSRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "DNS-Admission-Pod-DNS-Config-Policies",
				Header: podDNSHeader,
				Body:   podDNSRows,
			})
		}

		if len(istioDNSRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "DNS-Admission-Istio-DNS-Policies",
				Header: istioDNSHeader,
				Body:   istioDNSRows,
			})
		}

		if len(cloudDNSRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "DNS-Admission-Cloud-DNS-Policies",
				Header: cloudDNSHeader,
				Body:   cloudDNSRows,
			})
		}

		if len(headlessRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "DNS-Admission-Headless-Services-Policies",
				Header: headlessHeader,
				Body:   headlessRows,
			})
		}

		if len(kyvernoRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "DNS-Admission-Kyverno-Policies",
				Header: kyvernoHeader,
				Body:   kyvernoRows,
			})
		}

		if len(gatekeeperRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "DNS-Admission-Gatekeeper-Constraints-Policies",
				Header: gatekeeperHeader,
				Body:   gatekeeperRows,
			})
		}

		if len(consulRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "DNS-Admission-Consul-Policies",
				Header: consulHeader,
				Body:   consulRows,
			})
		}

		if len(k8sNetPolDNSRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "DNS-Admission-K8s-NetworkPolicy-Policies",
				Header: k8sNetPolDNSHeader,
				Body:   k8sNetPolDNSRows,
			})
		}

		if len(consulDNSForwardingRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "DNS-Admission-Consul-Forwarding-Policies",
				Header: consulDNSForwardingHeader,
				Body:   consulDNSForwardingRows,
			})
		}

		if len(kubewardenDNSRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "DNS-Admission-Kubewarden-Policies",
				Header: kubewardenDNSHeader,
				Body:   kubewardenDNSRows,
			})
		}

		if len(awsDNSFirewallRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "DNS-Admission-AWS-Firewall-Policies",
				Header: awsDNSFirewallHeader,
				Body:   awsDNSFirewallRows,
			})
		}

		if len(gcpResponsePolicyRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "DNS-Admission-GCP-ResponsePolicy-Policies",
				Header: gcpResponsePolicyHeader,
				Body:   gcpResponsePolicyRows,
			})
		}

		if len(azureDNSResolverRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "DNS-Admission-Azure-PrivateResolver-Policies",
				Header: azureDNSResolverHeader,
				Body:   azureDNSResolverRows,
			})
		}

		if len(istioServiceEntryRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "DNS-Admission-Istio-ServiceEntry-Policies",
				Header: istioServiceEntryHeader,
				Body:   istioServiceEntryRows,
			})
		}
	}

	output := DNSAdmissionOutput{
		Table: tables,
		Loot:  loot.Build(),
	}

	err := internal.HandleOutput(
		"Kubernetes",
		"table",
		outputDir,
		verbosity,
		wrap,
		"DNS-Admission",
		globals.ClusterName,
		"results",
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), K8S_DNS_ADMISSION_MODULE_NAME)
		return
	}
}

// ============================================================================
// CoreDNS Analysis
// ============================================================================

func analyzeCoreDNS(ctx context.Context, clientset kubernetes.Interface) (CoreDNSInfo, []CoreDNSConfigInfo) {
	info := CoreDNSInfo{}
	var configs []CoreDNSConfigInfo

	// Check for CoreDNS deployment
	namespaces := []string{"kube-system", "coredns"}
	for _, ns := range namespaces {
		deployments, err := clientset.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, dep := range deployments.Items {
			if strings.Contains(strings.ToLower(dep.Name), "coredns") {
				info.Name = "CoreDNS"
				info.Namespace = ns
				info.Status = "active"

				// Get version from image and verify using SDK
				for _, container := range dep.Spec.Template.Spec.Containers {
					if admission.VerifyControllerImage(container.Image, "coredns") {
						info.ImageVerified = true
						parts := strings.Split(container.Image, ":")
						if len(parts) > 1 {
							info.Version = parts[1]
						}
					}
				}

				if dep.Status.ReadyReplicas < dep.Status.Replicas {
					info.Status = "degraded"
				}
				info.TotalPods = int(dep.Status.Replicas)
				info.PodsRunning = int(dep.Status.ReadyReplicas)
				break
			}
		}
		if info.Name != "" {
			break
		}
	}

	if info.Name == "" {
		return info, configs
	}

	// Get CoreDNS ConfigMap
	cm, err := clientset.CoreV1().ConfigMaps(info.Namespace).Get(ctx, "coredns", metav1.GetOptions{})
	if err != nil {
		// Try alternative name
		cm, err = clientset.CoreV1().ConfigMaps(info.Namespace).Get(ctx, "coredns-custom", metav1.GetOptions{})
	}

	if err == nil {
		if corefile, ok := cm.Data["Corefile"]; ok {
			configs = parseCorefile(corefile)

			// Extract plugins for info
			for _, cfg := range configs {
				info.Plugins = append(info.Plugins, cfg.Plugins...)
				for _, plugin := range cfg.Plugins {
					switch plugin {
					case "cache":
						info.CacheEnabled = true
					case "log":
						info.LoggingEnabled = true
					case "health":
						info.HealthEnabled = true
					case "dnssec":
						info.DNSSECEnabled = true
					case "acl":
						info.ACLEnabled = true
					}
					// Track security-relevant plugins
					if plugin == "cache" || plugin == "log" || plugin == "health" || plugin == "ready" || plugin == "errors" ||
						plugin == "dnssec" || plugin == "acl" || plugin == "dnstap" {
						info.SecurityPlugins = append(info.SecurityPlugins, plugin)
					}
				}
				// Check for DoT/DoH forwarding at config level
				if cfg.DoTForwarding {
					info.DoTEnabled = true
				}
				if cfg.DoHForwarding {
					info.DoHEnabled = true
				}
			}
		}
	}

	return info, configs
}

func parseCorefile(corefile string) []CoreDNSConfigInfo {
	var configs []CoreDNSConfigInfo

	// Simple Corefile parser
	lines := strings.Split(corefile, "\n")
	var currentConfig *CoreDNSConfigInfo
	braceCount := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Check for zone declaration (e.g., ".:53 {")
		if strings.Contains(line, "{") && braceCount == 0 {
			zone := strings.Split(line, " ")[0]
			zone = strings.TrimSuffix(zone, "{")
			zone = strings.TrimSpace(zone)
			currentConfig = &CoreDNSConfigInfo{
				Zone:       zone,
				StubDomains: make(map[string][]string),
			}
			braceCount++
			continue
		}

		if strings.Contains(line, "{") {
			braceCount++
		}
		if strings.Contains(line, "}") {
			braceCount--
			if braceCount == 0 && currentConfig != nil {
				configs = append(configs, *currentConfig)
				currentConfig = nil
			}
			continue
		}

		if currentConfig == nil {
			continue
		}

		// Parse plugin directives
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}

		plugin := parts[0]
		currentConfig.Plugins = append(currentConfig.Plugins, plugin)

		switch plugin {
		case "forward":
			if len(parts) > 1 {
				for _, upstream := range parts[1:] {
					if strings.Contains(upstream, ".") || strings.Contains(upstream, "/") {
						currentConfig.ForwardTo = append(currentConfig.ForwardTo, upstream)
						// Check for DNS over TLS (tls://)
						if strings.HasPrefix(upstream, "tls://") {
							currentConfig.DoTForwarding = true
						}
						// Check for DNS over HTTPS (https://)
						if strings.HasPrefix(upstream, "https://") {
							currentConfig.DoHForwarding = true
						}
					}
				}
			}
		case "cache":
			currentConfig.Caching = true
			if len(parts) > 1 {
				fmt.Sscanf(parts[1], "%d", &currentConfig.CacheTTL)
			} else {
				currentConfig.CacheTTL = 30 // Default
			}
		case "upstream":
			if len(parts) > 1 {
				currentConfig.Upstreams = append(currentConfig.Upstreams, parts[1:]...)
			}
		case "dnssec":
			currentConfig.DNSSECEnabled = true
		}
	}

	return configs
}

// ============================================================================
// NodeLocalDNS Analysis
// ============================================================================

func analyzeNodeLocalDNS(ctx context.Context, clientset kubernetes.Interface) NodeLocalDNSInfo {
	info := NodeLocalDNSInfo{}

	// Check for NodeLocalDNS DaemonSet
	daemonSets, err := clientset.AppsV1().DaemonSets("kube-system").List(ctx, metav1.ListOptions{})
	if err != nil {
		return info
	}

	for _, ds := range daemonSets.Items {
		// First check name
		nameMatch := strings.Contains(strings.ToLower(ds.Name), "node-local-dns") ||
			strings.Contains(strings.ToLower(ds.Name), "nodelocaldns")

		if !nameMatch {
			continue
		}

		// Verify by image using SDK to reduce false positives
		imageVerified := false
		for _, container := range ds.Spec.Template.Spec.Containers {
			if admission.VerifyControllerImage(container.Image, "nodelocaldns") {
				imageVerified = true
				break
			}
		}

		if !imageVerified {
			continue
		}

		info.Name = "NodeLocalDNS"
		info.Namespace = "kube-system"
		info.Status = "active"
		info.TotalPods = int(ds.Status.DesiredNumberScheduled)
		info.PodsRunning = int(ds.Status.NumberReady)
		info.ImageVerified = true

		// Get local IP from containers
		for _, container := range ds.Spec.Template.Spec.Containers {
			for _, arg := range container.Args {
				if strings.Contains(arg, "localip") {
					parts := strings.Split(arg, "=")
					if len(parts) > 1 {
						info.LocalIP = parts[1]
					}
				}
			}
		}

		if info.PodsRunning < info.TotalPods {
			info.Status = "degraded"
		}

		break
	}

	return info
}

// ============================================================================
// External DNS Analysis
// ============================================================================

func analyzeExternalDNS(ctx context.Context, clientset kubernetes.Interface) ExternalDNSInfo {
	info := ExternalDNSInfo{}

	// Check for external-dns deployment
	namespaces := []string{"external-dns", "kube-system", "default"}
	for _, ns := range namespaces {
		deployments, err := clientset.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, dep := range deployments.Items {
			if !strings.Contains(strings.ToLower(dep.Name), "external-dns") {
				continue
			}

			// Verify by image using SDK to reduce false positives
			imageVerified := false
			for _, container := range dep.Spec.Template.Spec.Containers {
				if admission.VerifyControllerImage(container.Image, "external-dns") {
					imageVerified = true
					break
				}
			}

			if !imageVerified {
				continue
			}

			info.Name = "external-dns"
			info.Namespace = ns
			info.Status = "active"
			info.ImageVerified = true

			if dep.Status.ReadyReplicas < dep.Status.Replicas {
				info.Status = "degraded"
			}
			info.TotalPods = int(dep.Status.Replicas)
			info.PodsRunning = int(dep.Status.ReadyReplicas)

			// Parse configuration from args
			for _, container := range dep.Spec.Template.Spec.Containers {
				for _, arg := range container.Args {
					if strings.HasPrefix(arg, "--provider=") {
						info.Provider = strings.TrimPrefix(arg, "--provider=")
					}
					if strings.HasPrefix(arg, "--source=") {
						info.Sources = append(info.Sources, strings.TrimPrefix(arg, "--source="))
					}
					if strings.HasPrefix(arg, "--policy=") {
						info.Policy = strings.TrimPrefix(arg, "--policy=")
					}
					if strings.HasPrefix(arg, "--registry=") {
						info.Registry = strings.TrimPrefix(arg, "--registry=")
					}
				}
			}

			break
		}
		if info.Name != "" {
			break
		}
	}

	return info
}

// ============================================================================
// Cilium DNS Policies Analysis
// ============================================================================

func analyzeCiliumDNSPolicies(ctx context.Context, dynClient dynamic.Interface) []CiliumDNSPolicyInfo {
	var policies []CiliumDNSPolicyInfo

	// CiliumNetworkPolicy
	cnpGVR := schema.GroupVersionResource{
		Group:    "cilium.io",
		Version:  "v2",
		Resource: "ciliumnetworkpolicies",
	}

	cnpList, err := dynClient.Resource(cnpGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range cnpList.Items {
			policy := parseCiliumDNSPolicy(item.Object, false)
			if policy.DNSRules > 0 {
				policies = append(policies, policy)
			}
		}
	}

	// CiliumClusterwideNetworkPolicy
	ccnpGVR := schema.GroupVersionResource{
		Group:    "cilium.io",
		Version:  "v2",
		Resource: "ciliumclusterwidenetworkpolicies",
	}

	ccnpList, err := dynClient.Resource(ccnpGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range ccnpList.Items {
			policy := parseCiliumDNSPolicy(item.Object, true)
			if policy.DNSRules > 0 {
				policies = append(policies, policy)
			}
		}
	}

	return policies
}

func parseCiliumDNSPolicy(obj map[string]interface{}, isCluster bool) CiliumDNSPolicyInfo {
	policy := CiliumDNSPolicyInfo{
		IsCluster: isCluster,
	}

	if metadata, ok := obj["metadata"].(map[string]interface{}); ok {
		policy.Name, _ = metadata["name"].(string)
		if !isCluster {
			policy.Namespace, _ = metadata["namespace"].(string)
		}
	}

	if spec, ok := obj["spec"].(map[string]interface{}); ok {
		// Check egress rules for DNS
		if egress, ok := spec["egress"].([]interface{}); ok {
			for _, e := range egress {
				if eMap, ok := e.(map[string]interface{}); ok {
					// Check for toFQDNs
					if toFQDNs, ok := eMap["toFQDNs"].([]interface{}); ok {
						for _, fqdn := range toFQDNs {
							if fqdnMap, ok := fqdn.(map[string]interface{}); ok {
								policy.DNSRules++
								if matchName, ok := fqdnMap["matchName"].(string); ok {
									policy.MatchFQDNs = append(policy.MatchFQDNs, matchName)
								}
								if matchPattern, ok := fqdnMap["matchPattern"].(string); ok {
									policy.MatchPatterns = append(policy.MatchPatterns, matchPattern)
								}
							}
						}
					}

					// Check for toPorts with dns rules
					if toPorts, ok := eMap["toPorts"].([]interface{}); ok {
						for _, tp := range toPorts {
							if tpMap, ok := tp.(map[string]interface{}); ok {
								if rules, ok := tpMap["rules"].(map[string]interface{}); ok {
									if dns, ok := rules["dns"].([]interface{}); ok {
										policy.DNSRules += len(dns)
									}
								}
							}
						}
					}
				}
			}
		}
	}

	if policy.DNSRules > 0 {
		policy.Action = "Allow"
	}

	return policy
}

// ============================================================================
// Calico DNS Policies Analysis
// ============================================================================

func analyzeCalicoDNSPolicies(ctx context.Context, dynClient dynamic.Interface) []CalicoDNSPolicyInfo {
	var policies []CalicoDNSPolicyInfo

	// NetworkPolicy (Calico-specific with DNS)
	npGVR := schema.GroupVersionResource{
		Group:    "crd.projectcalico.org",
		Version:  "v1",
		Resource: "networkpolicies",
	}

	npList, err := dynClient.Resource(npGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range npList.Items {
			policy := parseCalicoDNSPolicy(item.Object, false)
			if policy.DNSRules > 0 {
				policies = append(policies, policy)
			}
		}
	}

	// GlobalNetworkPolicy
	gnpGVR := schema.GroupVersionResource{
		Group:    "crd.projectcalico.org",
		Version:  "v1",
		Resource: "globalnetworkpolicies",
	}

	gnpList, err := dynClient.Resource(gnpGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range gnpList.Items {
			policy := parseCalicoDNSPolicy(item.Object, true)
			if policy.DNSRules > 0 {
				policies = append(policies, policy)
			}
		}
	}

	return policies
}

func parseCalicoDNSPolicy(obj map[string]interface{}, isGlobal bool) CalicoDNSPolicyInfo {
	policy := CalicoDNSPolicyInfo{
		IsGlobal: isGlobal,
	}

	if metadata, ok := obj["metadata"].(map[string]interface{}); ok {
		policy.Name, _ = metadata["name"].(string)
		if !isGlobal {
			policy.Namespace, _ = metadata["namespace"].(string)
		}
	}

	if spec, ok := obj["spec"].(map[string]interface{}); ok {
		// Check egress rules
		if egress, ok := spec["egress"].([]interface{}); ok {
			for _, e := range egress {
				if eMap, ok := e.(map[string]interface{}); ok {
					// Check for destination domains
					if destination, ok := eMap["destination"].(map[string]interface{}); ok {
						if domains, ok := destination["domains"].([]interface{}); ok {
							policy.DNSRules += len(domains)
							for _, d := range domains {
								if dStr, ok := d.(string); ok {
									policy.Domains = append(policy.Domains, dStr)
								}
							}
						}
					}

					// Get action
					if action, ok := eMap["action"].(string); ok {
						policy.Action = action
					}
				}
			}
		}
	}

	if policy.Action == "" {
		policy.Action = "Allow"
	}

	return policy
}

// ============================================================================
// Pod DNS Analysis
// ============================================================================

func analyzePodDNS(ctx context.Context, clientset kubernetes.Interface) []PodDNSInfo {
	var podDNS []PodDNSInfo

	for _, ns := range globals.K8sNamespaces {
		pods, err := clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, pod := range pods.Items {
			info := PodDNSInfo{
				Name:      pod.Name,
				Namespace: pod.Namespace,
				DNSPolicy: string(pod.Spec.DNSPolicy),
			}

			if info.DNSPolicy == "" {
				info.DNSPolicy = "ClusterFirst"
			}

			// Check for custom DNS config
			if pod.Spec.DNSConfig != nil {
				info.HasCustomDNS = true
				info.Nameservers = pod.Spec.DNSConfig.Nameservers
				info.Searches = pod.Spec.DNSConfig.Searches
			}

			podDNS = append(podDNS, info)
		}
	}

	return podDNS
}

// ============================================================================
// Build Findings
// ============================================================================

func buildDNSAdmissionFindings(
	coredns CoreDNSInfo,
	ciliumDNS []CiliumDNSPolicyInfo,
	calicoDNS []CalicoDNSPolicyInfo,
	kyvernoDNS []KyvernoDNSPolicyInfo,
	gatekeeperDNS []GatekeeperDNSConstraintInfo,
	eksAdminPolicies []EKSAdminNetworkPolicyInfo,
	k8sNetPolDNS []K8sNetworkPolicyDNSInfo,
	istioServiceEntries []IstioServiceEntryInfo,
	podDNS []PodDNSInfo) []DNSAdmissionFinding {

	// Initialize findings per namespace
	namespaceData := make(map[string]*DNSAdmissionFinding)
	for _, ns := range globals.K8sNamespaces {
		namespaceData[ns] = &DNSAdmissionFinding{
			Namespace: ns,
		}
	}

	// Count Cilium DNS policies per namespace
	for _, p := range ciliumDNS {
		if !p.IsCluster {
			if finding, ok := namespaceData[p.Namespace]; ok {
				finding.CiliumPolicies++
			}
		} else {
			// Cluster-wide policies apply to all
			for _, finding := range namespaceData {
				finding.CiliumPolicies++
			}
		}
	}

	// Count Calico DNS policies per namespace
	for _, p := range calicoDNS {
		if !p.IsGlobal {
			if finding, ok := namespaceData[p.Namespace]; ok {
				finding.CalicoPolicies++
			}
		} else {
			// Global policies apply to all
			for _, finding := range namespaceData {
				finding.CalicoPolicies++
			}
		}
	}

	// Count Kyverno DNS policies per namespace
	for _, p := range kyvernoDNS {
		if !p.IsCluster {
			if finding, ok := namespaceData[p.Namespace]; ok {
				finding.KyvernoPolicies++
			}
		} else {
			// Cluster-wide policies apply to all
			for _, finding := range namespaceData {
				finding.KyvernoPolicies++
			}
		}
	}

	// Count Gatekeeper DNS constraints per namespace
	for range gatekeeperDNS {
		// Gatekeeper constraints are typically cluster-wide
		for _, finding := range namespaceData {
			finding.GatekeeperPolicies++
		}
	}

	// Count EKS Admin Network Policies per namespace
	for _, p := range eksAdminPolicies {
		if !p.IsCluster {
			if finding, ok := namespaceData[p.Subject]; ok {
				finding.EKSAdminPolicies++
			}
		} else {
			// Cluster-wide policies apply to all
			for _, finding := range namespaceData {
				finding.EKSAdminPolicies++
			}
		}
	}

	// Count K8s NetworkPolicy DNS rules per namespace
	for _, p := range k8sNetPolDNS {
		if finding, ok := namespaceData[p.Namespace]; ok {
			finding.K8sNetPolDNS++
		}
	}

	// Count Istio ServiceEntry per namespace
	for _, se := range istioServiceEntries {
		if !se.IsCluster {
			if finding, ok := namespaceData[se.Namespace]; ok {
				finding.IstioServiceEntries++
			}
		} else {
			// Exported to all namespaces
			for _, finding := range namespaceData {
				finding.IstioServiceEntries++
			}
		}
	}

	// Analyze pod DNS configurations
	for _, p := range podDNS {
		if finding, ok := namespaceData[p.Namespace]; ok {
			finding.TotalPods++
			switch p.DNSPolicy {
			case "Default":
				finding.PodsWithDefaultDNS++
			case "None":
				finding.PodsWithNoDNS++
			default:
				if p.HasCustomDNS {
					finding.PodsWithCustomDNS++
				} else {
					finding.PodsWithDefaultDNS++
				}
			}
		}
	}

	// Build findings list
	var findings []DNSAdmissionFinding
	for _, finding := range namespaceData {
		// Identify security issues
		if finding.PodsWithNoDNS > 0 {
			finding.SecurityIssues = append(finding.SecurityIssues, fmt.Sprintf("%d pods with DNS=None", finding.PodsWithNoDNS))
		}

		if finding.PodsWithCustomDNS > 0 {
			finding.SecurityIssues = append(finding.SecurityIssues, fmt.Sprintf("%d pods with custom DNS", finding.PodsWithCustomDNS))
		}

		hasDNSPolicy := finding.CiliumPolicies > 0 || finding.CalicoPolicies > 0 || finding.KyvernoPolicies > 0 || finding.GatekeeperPolicies > 0 || finding.EKSAdminPolicies > 0 || finding.K8sNetPolDNS > 0
		if !hasDNSPolicy && finding.TotalPods > 0 {
			finding.SecurityIssues = append(finding.SecurityIssues, "No DNS egress policy")
		}

		findings = append(findings, *finding)
	}

	// Sort by namespace
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Namespace < findings[j].Namespace
	})

	return findings
}

// ============================================================================
// Loot Generation
// ============================================================================

func generateDNSAdmissionLoot(loot *shared.LootBuilder,
	coredns CoreDNSInfo,
	nodeLocalDNS NodeLocalDNSInfo,
	externalDNS ExternalDNSInfo,
	ciliumDNS []CiliumDNSPolicyInfo,
	calicoDNS []CalicoDNSPolicyInfo,
	externalNameSvcs []ExternalNameServiceInfo,
	exfilRisks []DNSExfiltrationRisk) {

	// Unified dns-admission section
	loot.Section("dns-admission").Add("# DNS Admission Analysis")
	loot.Section("dns-admission").Add("#")

	// Detected tools
	detectedTools := []string{}

	if coredns.Name != "" {
		plugins := "none"
		if len(coredns.SecurityPlugins) > 0 {
			plugins = strings.Join(coredns.SecurityPlugins, ", ")
		}
		loot.Section("dns-admission").Add(fmt.Sprintf("# CoreDNS: %s (version: %s, security plugins: %s)", coredns.Status, coredns.Version, plugins))
		detectedTools = append(detectedTools, "coredns")
	}

	if nodeLocalDNS.Name != "" {
		loot.Section("dns-admission").Add(fmt.Sprintf("# NodeLocalDNS: %s (local IP: %s)", nodeLocalDNS.Status, nodeLocalDNS.LocalIP))
		detectedTools = append(detectedTools, "nodelocaldns")
	}

	if externalDNS.Name != "" {
		loot.Section("dns-admission").Add(fmt.Sprintf("# external-dns: %s (provider: %s, policy: %s)", externalDNS.Status, externalDNS.Provider, externalDNS.Policy))
		detectedTools = append(detectedTools, "external-dns")
	}

	if len(ciliumDNS) > 0 {
		loot.Section("dns-admission").Add(fmt.Sprintf("# Cilium DNS policies: %d", len(ciliumDNS)))
		detectedTools = append(detectedTools, "cilium")
	}

	if len(calicoDNS) > 0 {
		loot.Section("dns-admission").Add(fmt.Sprintf("# Calico DNS policies: %d", len(calicoDNS)))
		detectedTools = append(detectedTools, "calico")
	}

	loot.Section("dns-admission").Add("#")

	// Security findings section
	hasSecurityFindings := len(externalNameSvcs) > 0 || len(exfilRisks) > 0

	if hasSecurityFindings {
		loot.Section("dns-admission").Add("# === SECURITY FINDINGS ===")
		loot.Section("dns-admission").Add("#")
	}

	// ExternalName services - potential network policy bypass
	if len(externalNameSvcs) > 0 {
		loot.Section("dns-admission").Add("# ExternalName Services (potential network policy bypass):")
		for _, svc := range externalNameSvcs {
			lines := shared.FormatSuspiciousEntry(svc.Namespace, svc.Name, append([]string{fmt.Sprintf("Points to: %s", svc.ExternalName)}, svc.Notes...))
			for _, line := range lines {
				loot.Section("dns-admission").Add(line)
			}
		}
		loot.Section("dns-admission").Add("#")
		loot.Section("dns-admission").Add("# Investigate ExternalName services:")
		for _, svc := range externalNameSvcs {
			loot.Section("dns-admission").Add(fmt.Sprintf("kubectl get svc %s -n %s -o yaml", svc.Name, svc.Namespace))
		}
		loot.Section("dns-admission").Add("#")
	}

	// Pods with notable DNS configuration
	if len(exfilRisks) > 0 {
		loot.Section("dns-admission").Add("# Pods with Notable DNS Configuration:")
		for _, info := range exfilRisks {
			lines := shared.FormatSuspiciousEntry(info.Namespace, info.PodName, info.Notes)
			for _, line := range lines {
				loot.Section("dns-admission").Add(line)
			}
		}
		loot.Section("dns-admission").Add("#")
		loot.Section("dns-admission").Add("# Investigate pods with custom DNS configuration:")
		for _, info := range exfilRisks {
			loot.Section("dns-admission").Add(fmt.Sprintf("kubectl get pod %s -n %s -o yaml | grep -A10 dnsConfig", info.PodName, info.Namespace))
		}
		loot.Section("dns-admission").Add("#")
	}

	// Commands only for detected tools
	if len(detectedTools) > 0 {
		loot.Section("dns-admission").Add("# === ENUMERATION COMMANDS ===")
		loot.Section("dns-admission").Add("#")

		for _, tool := range detectedTools {
			switch tool {
			case "coredns":
				loot.Section("dns-admission").Add("# Check CoreDNS config:")
				loot.Section("dns-admission").Add("kubectl get configmap coredns -n kube-system -o yaml")
				loot.Section("dns-admission").Add("#")
				loot.Section("dns-admission").Add("# Check CoreDNS logs:")
				loot.Section("dns-admission").Add("kubectl logs -l k8s-app=kube-dns -n kube-system")
				loot.Section("dns-admission").Add("#")
			case "nodelocaldns":
				loot.Section("dns-admission").Add("# Check NodeLocalDNS logs:")
				loot.Section("dns-admission").Add("kubectl logs -l k8s-app=node-local-dns -n kube-system")
				loot.Section("dns-admission").Add("#")
			case "external-dns":
				loot.Section("dns-admission").Add("# Check external-dns logs:")
				loot.Section("dns-admission").Add("kubectl logs -l app=external-dns -n kube-system")
				loot.Section("dns-admission").Add("#")
			case "cilium":
				loot.Section("dns-admission").Add("# List Cilium DNS policies:")
				loot.Section("dns-admission").Add("kubectl get ciliumnetworkpolicies -A")
				loot.Section("dns-admission").Add("#")
			case "calico":
				loot.Section("dns-admission").Add("# List Calico DNS policies:")
				loot.Section("dns-admission").Add("kubectl get networkpolicies.crd.projectcalico.org -A")
				loot.Section("dns-admission").Add("#")
			}
		}
	}

	// General DNS investigation commands
	loot.Section("dns-admission").Add("# === GENERAL DNS INVESTIGATION ===")
	loot.Section("dns-admission").Add("#")
	loot.Section("dns-admission").Add("# List all ExternalName services:")
	loot.Section("dns-admission").Add("kubectl get svc -A -o json | jq '.items[] | select(.spec.type==\"ExternalName\") | {namespace:.metadata.namespace, name:.metadata.name, externalName:.spec.externalName}'")
	loot.Section("dns-admission").Add("#")
	loot.Section("dns-admission").Add("# Find pods with custom DNS config:")
	loot.Section("dns-admission").Add("kubectl get pods -A -o json | jq '.items[] | select(.spec.dnsConfig != null) | {namespace:.metadata.namespace, name:.metadata.name, dnsConfig:.spec.dnsConfig}'")
	loot.Section("dns-admission").Add("#")
	loot.Section("dns-admission").Add("# Find pods with DNSPolicy=None:")
	loot.Section("dns-admission").Add("kubectl get pods -A -o json | jq '.items[] | select(.spec.dnsPolicy==\"None\") | {namespace:.metadata.namespace, name:.metadata.name}'")
	loot.Section("dns-admission").Add("#")
	loot.Section("dns-admission").Add("# Test DNS resolution from a pod:")
	loot.Section("dns-admission").Add("kubectl run dns-test --rm -it --restart=Never --image=busybox -- nslookup kubernetes.default")
	loot.Section("dns-admission").Add("#")
	loot.Section("dns-admission").Add("# === CLOUD PROVIDER DNS POLICIES ===")
	loot.Section("dns-admission").Add("#")
	loot.Section("dns-admission").Add("# AWS Route 53 DNS Firewall (requires AWS CLI):")
	loot.Section("dns-admission").Add("# aws route53resolver list-firewall-rule-groups")
	loot.Section("dns-admission").Add("# aws route53resolver list-firewall-rules --firewall-rule-group-id <group-id>")
	loot.Section("dns-admission").Add("# aws route53resolver list-firewall-domain-lists")
	loot.Section("dns-admission").Add("# aws route53resolver list-resolver-endpoints")
	loot.Section("dns-admission").Add("#")
	loot.Section("dns-admission").Add("# GCP Cloud DNS Response Policies (requires gcloud CLI):")
	loot.Section("dns-admission").Add("# gcloud dns response-policies list")
	loot.Section("dns-admission").Add("# gcloud dns response-policies rules list --response-policy=<policy-name>")
	loot.Section("dns-admission").Add("# gcloud dns managed-zones list")
	loot.Section("dns-admission").Add("#")
	loot.Section("dns-admission").Add("# Azure DNS Private Resolver (requires az CLI):")
	loot.Section("dns-admission").Add("# az dns-resolver list --resource-group <rg>")
	loot.Section("dns-admission").Add("# az dns-resolver forwarding-ruleset list --resource-group <rg>")
	loot.Section("dns-admission").Add("# az dns-resolver forwarding-rule list --dns-forwarding-ruleset-name <ruleset> --resource-group <rg>")
	loot.Section("dns-admission").Add("# az network private-dns zone list")
}

// ============================================================================
// Istio DNS Proxy Analysis
// ============================================================================

func analyzeIstioDNS(ctx context.Context, clientset kubernetes.Interface) IstioDNSInfo {
	info := IstioDNSInfo{}

	// Image patterns for verification
	imagePatterns := []string{"istio/proxyv2", "istio/pilot", "istiod"}

	// Check for Istiod deployment
	namespaces := []string{"istio-system", "istio"}
	for _, ns := range namespaces {
		deployments, err := clientset.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, dep := range deployments.Items {
			if !strings.Contains(strings.ToLower(dep.Name), "istiod") {
				continue
			}

			// Verify by image
			imageVerified := false
			for _, container := range dep.Spec.Template.Spec.Containers {
				for _, pattern := range imagePatterns {
					if strings.Contains(strings.ToLower(container.Image), pattern) {
						imageVerified = true
						break
					}
				}
				if imageVerified {
					break
				}
			}

			if !imageVerified {
				continue
			}

			info.Name = "Istio DNS Proxy"
			info.Namespace = ns
			info.Status = "active"
			info.TotalPods = int(dep.Status.Replicas)
			info.PodsRunning = int(dep.Status.ReadyReplicas)
			info.ImageVerified = true

			if info.PodsRunning < info.TotalPods {
				info.Status = "degraded"
			}

			// Check for DNS proxy configuration in mesh config
			meshCM, err := clientset.CoreV1().ConfigMaps(ns).Get(ctx, "istio", metav1.GetOptions{})
			if err == nil {
				if meshConfig, ok := meshCM.Data["mesh"]; ok {
					if strings.Contains(meshConfig, "proxyMetadata") && strings.Contains(meshConfig, "ISTIO_META_DNS_CAPTURE") {
						info.DNSCaptureEnabled = true
					}
					if strings.Contains(meshConfig, "ISTIO_META_DNS_AUTO_ALLOCATE") {
						info.AutoAllocateEnabled = true
					}
				}
			}

			break
		}
		if info.Name != "" {
			break
		}
	}

	return info
}

// ============================================================================
// Cloud Provider DNS Analysis
// ============================================================================

func analyzeCloudDNS(ctx context.Context, clientset kubernetes.Interface) []CloudDNSInfo {
	var cloudDNS []CloudDNSInfo

	// AWS Route53 external-dns or AWS cloud-map controller
	awsNamespaces := []string{"kube-system", "aws-controllers", "external-dns"}
	awsImagePatterns := []string{"amazon/cloud-map-controller", "route53", "aws-load-balancer"}

	for _, ns := range awsNamespaces {
		deployments, err := clientset.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, dep := range deployments.Items {
			for _, container := range dep.Spec.Template.Spec.Containers {
				for _, pattern := range awsImagePatterns {
					if strings.Contains(strings.ToLower(container.Image), pattern) {
						info := CloudDNSInfo{
							Provider:      "AWS",
							Name:          dep.Name,
							Namespace:     ns,
							Status:        "active",
							Type:          "Route53/CloudMap",
							TotalPods:     int(dep.Status.Replicas),
							PodsRunning:   int(dep.Status.ReadyReplicas),
							ImageVerified: true,
						}

						if info.PodsRunning < info.TotalPods {
							info.Status = "degraded"
						}

						cloudDNS = append(cloudDNS, info)
						break
					}
				}
			}
		}
	}

	// GCP Cloud DNS
	gcpNamespaces := []string{"kube-system", "gke-system", "external-dns"}
	gcpImagePatterns := []string{"gcr.io/k8s-dns", "gke.gcr.io", "cloud-dns"}

	for _, ns := range gcpNamespaces {
		deployments, err := clientset.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, dep := range deployments.Items {
			for _, container := range dep.Spec.Template.Spec.Containers {
				for _, pattern := range gcpImagePatterns {
					if strings.Contains(strings.ToLower(container.Image), pattern) {
						info := CloudDNSInfo{
							Provider:      "GCP",
							Name:          dep.Name,
							Namespace:     ns,
							Status:        "active",
							Type:          "Cloud DNS",
							TotalPods:     int(dep.Status.Replicas),
							PodsRunning:   int(dep.Status.ReadyReplicas),
							ImageVerified: true,
						}

						if info.PodsRunning < info.TotalPods {
							info.Status = "degraded"
						}

						cloudDNS = append(cloudDNS, info)
						break
					}
				}
			}
		}
	}

	// Azure DNS
	azureNamespaces := []string{"kube-system", "azure-dns", "external-dns"}
	azureImagePatterns := []string{"mcr.microsoft.com", "azure-dns", "azure/external-dns"}

	for _, ns := range azureNamespaces {
		deployments, err := clientset.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, dep := range deployments.Items {
			for _, container := range dep.Spec.Template.Spec.Containers {
				for _, pattern := range azureImagePatterns {
					if strings.Contains(strings.ToLower(container.Image), pattern) {
						info := CloudDNSInfo{
							Provider:      "Azure",
							Name:          dep.Name,
							Namespace:     ns,
							Status:        "active",
							Type:          "Azure DNS",
							TotalPods:     int(dep.Status.Replicas),
							PodsRunning:   int(dep.Status.ReadyReplicas),
							ImageVerified: true,
						}

						if info.PodsRunning < info.TotalPods {
							info.Status = "degraded"
						}

						cloudDNS = append(cloudDNS, info)
						break
					}
				}
			}
		}
	}

	return cloudDNS
}

// ============================================================================
// ExternalName Service Analysis
// ============================================================================

func analyzeExternalNameServices(ctx context.Context, clientset kubernetes.Interface) []ExternalNameServiceInfo {
	var services []ExternalNameServiceInfo

	for _, ns := range globals.K8sNamespaces {
		svcList, err := clientset.CoreV1().Services(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, svc := range svcList.Items {
			if svc.Spec.Type != "ExternalName" {
				continue
			}

			info := ExternalNameServiceInfo{
				Name:         svc.Name,
				Namespace:    svc.Namespace,
				ExternalName: svc.Spec.ExternalName,
			}

			// Collect factual observations about the external name
			extName := strings.ToLower(svc.Spec.ExternalName)

			// Check for metadata services
			if strings.Contains(extName, "metadata") ||
				strings.Contains(extName, "169.254.169.254") ||
				strings.Contains(extName, "metadata.google.internal") {
				info.Notes = append(info.Notes, "Points to cloud metadata service")
			}

			// Check for cloud provider internal services
			if strings.Contains(extName, ".internal") ||
				strings.Contains(extName, ".amazonaws.com") ||
				strings.Contains(extName, ".azure.com") ||
				strings.Contains(extName, ".googleapis.com") {
				info.Notes = append(info.Notes, "Points to cloud provider internal service")
			}

			// Check for external domains
			if !strings.Contains(extName, ".svc.cluster.local") &&
				!strings.Contains(extName, ".cluster.local") {
				info.Notes = append(info.Notes, "External domain - bypasses network policies")
			}

			// Check for specific TLDs
			specificTLDs := []string{".onion", ".bit", ".i2p", ".xyz", ".top", ".tk", ".ml", ".ga", ".cf"}
			for _, tld := range specificTLDs {
				if strings.HasSuffix(extName, tld) {
					info.Notes = append(info.Notes, fmt.Sprintf("TLD: %s", tld))
				}
			}

			services = append(services, info)
		}
	}

	return services
}

// ============================================================================
// Headless Service Analysis
// ============================================================================

func analyzeHeadlessServices(ctx context.Context, clientset kubernetes.Interface) []HeadlessServiceInfo {
	var services []HeadlessServiceInfo

	for _, ns := range globals.K8sNamespaces {
		svcList, err := clientset.CoreV1().Services(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, svc := range svcList.Items {
			// Headless service has ClusterIP = None
			if svc.Spec.ClusterIP != "None" {
				continue
			}

			info := HeadlessServiceInfo{
				Name:      svc.Name,
				Namespace: svc.Namespace,
				Selector:  svc.Spec.Selector,
			}

			// Get port information
			for _, port := range svc.Spec.Ports {
				info.Ports = append(info.Ports, fmt.Sprintf("%d/%s", port.Port, port.Protocol))
			}

			// Count matching pods
			if len(svc.Spec.Selector) > 0 {
				labelSelector := metav1.LabelSelector{MatchLabels: svc.Spec.Selector}
				selector, _ := metav1.LabelSelectorAsSelector(&labelSelector)
				pods, err := clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
					LabelSelector: selector.String(),
				})
				if err == nil {
					info.PodCount = len(pods.Items)
				}
			}

			// Note if exposing many pods
			if info.PodCount > 10 {
				info.Notes = append(info.Notes, fmt.Sprintf("Exposes %d pod IPs via DNS", info.PodCount))
			}

			// Note sensitive ports
			sensitivePorts := map[int32]string{
				22: "SSH", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
				27017: "MongoDB", 9200: "Elasticsearch", 8500: "Consul",
			}
			for _, port := range svc.Spec.Ports {
				if name, ok := sensitivePorts[port.Port]; ok {
					info.Notes = append(info.Notes, fmt.Sprintf("Exposes %s port (%d)", name, port.Port))
				}
			}

			services = append(services, info)
		}
	}

	return services
}

// ============================================================================
// DNS Exfiltration Risk Analysis
// ============================================================================

func analyzeDNSExfiltrationRisks(ctx context.Context, clientset kubernetes.Interface, podDNS []PodDNSInfo, ciliumDNS []CiliumDNSPolicyInfo, calicoDNS []CalicoDNSPolicyInfo) []DNSExfiltrationRisk {
	var risks []DNSExfiltrationRisk

	// Build a map of namespaces with DNS egress policies
	nsWithPolicy := make(map[string]bool)
	for _, p := range ciliumDNS {
		if p.IsCluster {
			// Cluster-wide policy covers all
			for _, ns := range globals.K8sNamespaces {
				nsWithPolicy[ns] = true
			}
		} else {
			nsWithPolicy[p.Namespace] = true
		}
	}
	for _, p := range calicoDNS {
		if p.IsGlobal {
			for _, ns := range globals.K8sNamespaces {
				nsWithPolicy[ns] = true
			}
		} else {
			nsWithPolicy[p.Namespace] = true
		}
	}

	// Analyze each pod
	for _, pod := range podDNS {
		info := DNSExfiltrationRisk{
			Namespace:       pod.Namespace,
			PodName:         pod.Name,
			DNSPolicy:       pod.DNSPolicy,
			HasEgressPolicy: nsWithPolicy[pod.Namespace],
		}

		// Check for external nameservers
		for _, ns := range pod.Nameservers {
			// Check if nameserver is external (not cluster DNS)
			if !strings.HasPrefix(ns, "10.") && !strings.HasPrefix(ns, "172.") && !strings.HasPrefix(ns, "192.168.") {
				info.ExternalDNS = append(info.ExternalDNS, ns)
			}
		}

		// Collect factual observations
		if pod.DNSPolicy == "None" {
			info.Notes = append(info.Notes, "DNSPolicy=None (no cluster DNS)")
		}

		if len(info.ExternalDNS) > 0 {
			info.Notes = append(info.Notes, fmt.Sprintf("External nameservers: %s", strings.Join(info.ExternalDNS, ", ")))
		}

		if !info.HasEgressPolicy {
			info.Notes = append(info.Notes, "No DNS egress policy")
		}

		if pod.HasCustomDNS {
			info.Notes = append(info.Notes, "Custom DNS configuration")
		}

		// Only include pods with notable DNS configuration
		if len(info.Notes) > 0 {
			risks = append(risks, info)
		}
	}

	// Sort alphabetically by namespace then pod name
	sort.Slice(risks, func(i, j int) bool {
		if risks[i].Namespace != risks[j].Namespace {
			return risks[i].Namespace < risks[j].Namespace
		}
		return risks[i].PodName < risks[j].PodName
	})

	return risks
}

// ============================================================================
// CoreDNS Security Deep Analysis
// ============================================================================

func analyzeCoreDNSSecurity(corednsConfig []CoreDNSConfigInfo, corefile string) CoreDNSSecurityAnalysis {
	analysis := CoreDNSSecurityAnalysis{}

	// Check for security plugins in configuration
	for _, cfg := range corednsConfig {
		for _, plugin := range cfg.Plugins {
			switch plugin {
			case "acl":
				analysis.ACLEnabled = true
			case "rrl":
				analysis.RRLEnabled = true
			case "dnstap":
				analysis.DNSTapEnabled = true
			case "firewall":
				analysis.FirewallEnabled = true
			}
		}
	}

	// Parse corefile for detailed security config
	if corefile != "" {
		lines := strings.Split(corefile, "\n")
		inACL := false
		inFirewall := false

		for _, line := range lines {
			line = strings.TrimSpace(line)

			// ACL rules
			if strings.HasPrefix(line, "acl") {
				inACL = true
				continue
			}
			if inACL {
				if strings.Contains(line, "}") {
					inACL = false
				} else if strings.Contains(line, "allow") || strings.Contains(line, "deny") || strings.Contains(line, "block") {
					analysis.ACLRules = append(analysis.ACLRules, line)
				}
			}

			// Firewall rules
			if strings.HasPrefix(line, "firewall") {
				inFirewall = true
				continue
			}
			if inFirewall {
				if strings.Contains(line, "}") {
					inFirewall = false
				} else if line != "" && !strings.HasPrefix(line, "#") {
					analysis.FirewallRules = append(analysis.FirewallRules, line)
				}
			}

			// RRL config
			if strings.HasPrefix(line, "rrl") {
				analysis.RRLConfig = line
			}

			// DNSTap endpoint
			if strings.HasPrefix(line, "dnstap") {
				parts := strings.Fields(line)
				if len(parts) > 1 {
					analysis.DNSTapEndpoint = parts[1]
				}
			}
		}
	}

	// Security issues and recommendations
	if !analysis.ACLEnabled {
		analysis.SecurityIssues = append(analysis.SecurityIssues, "No ACL plugin - DNS queries not restricted by source")
		analysis.Recommendations = append(analysis.Recommendations, "Enable 'acl' plugin to restrict DNS query sources")
	}

	if !analysis.RRLEnabled {
		analysis.SecurityIssues = append(analysis.SecurityIssues, "No RRL plugin - vulnerable to DNS amplification attacks")
		analysis.Recommendations = append(analysis.Recommendations, "Enable 'rrl' plugin for response rate limiting")
	}

	if !analysis.DNSTapEnabled {
		analysis.SecurityIssues = append(analysis.SecurityIssues, "No DNSTap - limited DNS query visibility")
		analysis.Recommendations = append(analysis.Recommendations, "Enable 'dnstap' plugin for DNS query logging")
	}

	return analysis
}

// ============================================================================
// Kyverno DNS Policy Analysis
// ============================================================================

func analyzeKyvernoDNSPolicies(ctx context.Context, dynClient dynamic.Interface) []KyvernoDNSPolicyInfo {
	var policies []KyvernoDNSPolicyInfo

	// ClusterPolicy
	cpGVR := schema.GroupVersionResource{
		Group:    "kyverno.io",
		Version:  "v1",
		Resource: "clusterpolicies",
	}

	cpList, err := dynClient.Resource(cpGVR).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range cpList.Items {
			policy := parseKyvernoDNSPolicy(item.Object, true)
			if policy.DNSRule != "" {
				policies = append(policies, policy)
			}
		}
	}

	// Policy (namespaced)
	pGVR := schema.GroupVersionResource{
		Group:    "kyverno.io",
		Version:  "v1",
		Resource: "policies",
	}

	pList, err := dynClient.Resource(pGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range pList.Items {
			policy := parseKyvernoDNSPolicy(item.Object, false)
			if policy.DNSRule != "" {
				policies = append(policies, policy)
			}
		}
	}

	return policies
}

func parseKyvernoDNSPolicy(obj map[string]interface{}, isCluster bool) KyvernoDNSPolicyInfo {
	policy := KyvernoDNSPolicyInfo{
		IsCluster: isCluster,
	}

	if metadata, ok := obj["metadata"].(map[string]interface{}); ok {
		policy.Name, _ = metadata["name"].(string)
		if !isCluster {
			policy.Namespace, _ = metadata["namespace"].(string)
		}
	}

	if spec, ok := obj["spec"].(map[string]interface{}); ok {
		// Check validation action
		if validationFailureAction, ok := spec["validationFailureAction"].(string); ok {
			policy.Action = validationFailureAction
		}

		// Check rules for DNS-related patterns
		if rules, ok := spec["rules"].([]interface{}); ok {
			for _, rule := range rules {
				if ruleMap, ok := rule.(map[string]interface{}); ok {
					ruleName, _ := ruleMap["name"].(string)

					// Check if rule matches pods/services
					if match, ok := ruleMap["match"].(map[string]interface{}); ok {
						if resources, ok := match["resources"].(map[string]interface{}); ok {
							if kinds, ok := resources["kinds"].([]interface{}); ok {
								for _, k := range kinds {
									if kStr, ok := k.(string); ok {
										if kStr == "Pod" || kStr == "Service" {
											policy.Target = kStr
										}
									}
								}
							}
						}
					}

					// Check for DNS-related validation
					if validate, ok := ruleMap["validate"].(map[string]interface{}); ok {
						validateStr := fmt.Sprintf("%v", validate)
						if strings.Contains(strings.ToLower(validateStr), "dnsconfig") ||
							strings.Contains(strings.ToLower(validateStr), "dnspolicy") ||
							strings.Contains(strings.ToLower(validateStr), "nameserver") ||
							strings.Contains(strings.ToLower(validateStr), "externalname") {
							policy.Type = "validate"
							policy.DNSRule = ruleName
						}
					}

					// Check for DNS-related mutation
					if mutate, ok := ruleMap["mutate"].(map[string]interface{}); ok {
						mutateStr := fmt.Sprintf("%v", mutate)
						if strings.Contains(strings.ToLower(mutateStr), "dnsconfig") ||
							strings.Contains(strings.ToLower(mutateStr), "dnspolicy") {
							policy.Type = "mutate"
							policy.DNSRule = ruleName
						}
					}
				}
			}
		}
	}

	return policy
}

// ============================================================================
// Gatekeeper DNS Constraint Analysis
// ============================================================================

func analyzeGatekeeperDNSConstraints(ctx context.Context, dynClient dynamic.Interface) []GatekeeperDNSConstraintInfo {
	var constraints []GatekeeperDNSConstraintInfo

	// First, list all ConstraintTemplates to find DNS-related ones
	ctGVR := schema.GroupVersionResource{
		Group:    "templates.gatekeeper.sh",
		Version:  "v1",
		Resource: "constrainttemplates",
	}

	ctList, err := dynClient.Resource(ctGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return constraints
	}

	// Find DNS-related templates
	dnsTemplates := []string{}
	for _, item := range ctList.Items {
		name, _, _ := getUnstructuredField(item.Object, "metadata", "name")
		nameStr, _ := name.(string)

		// Check if template is DNS-related
		specStr := fmt.Sprintf("%v", item.Object)
		if strings.Contains(strings.ToLower(nameStr), "dns") ||
			strings.Contains(strings.ToLower(specStr), "dnspolicy") ||
			strings.Contains(strings.ToLower(specStr), "dnsconfig") ||
			strings.Contains(strings.ToLower(specStr), "externalname") {
			dnsTemplates = append(dnsTemplates, strings.ToLower(nameStr))
		}
	}

	// For each DNS template, find constraints
	for _, templateName := range dnsTemplates {
		constraintGVR := schema.GroupVersionResource{
			Group:    "constraints.gatekeeper.sh",
			Version:  "v1beta1",
			Resource: templateName,
		}

		constraintList, err := dynClient.Resource(constraintGVR).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, item := range constraintList.Items {
			info := GatekeeperDNSConstraintInfo{
				TemplateName: templateName,
				Kind:         templateName,
			}

			if metadata, ok := item.Object["metadata"].(map[string]interface{}); ok {
				info.Name, _ = metadata["name"].(string)
			}

			if spec, ok := item.Object["spec"].(map[string]interface{}); ok {
				if enforcement, ok := spec["enforcementAction"].(string); ok {
					info.EnforcementAction = enforcement
				} else {
					info.EnforcementAction = "deny" // default
				}

				if match, ok := spec["match"].(map[string]interface{}); ok {
					if kinds, ok := match["kinds"].([]interface{}); ok {
						var targets []string
						for _, k := range kinds {
							if kMap, ok := k.(map[string]interface{}); ok {
								if apiKinds, ok := kMap["kinds"].([]interface{}); ok {
									for _, ak := range apiKinds {
										if akStr, ok := ak.(string); ok {
											targets = append(targets, akStr)
										}
									}
								}
							}
						}
						info.Target = strings.Join(targets, ", ")
					}
				}
			}

			info.DNSRule = fmt.Sprintf("Enforces %s constraint", templateName)
			constraints = append(constraints, info)
		}
	}

	return constraints
}

// Helper function to get nested field from unstructured object
func getUnstructuredField(obj map[string]interface{}, fields ...string) (interface{}, bool, error) {
	current := obj
	for i, field := range fields {
		if i == len(fields)-1 {
			val, ok := current[field]
			return val, ok, nil
		}
		next, ok := current[field].(map[string]interface{})
		if !ok {
			return nil, false, nil
		}
		current = next
	}
	return nil, false, nil
}

// ============================================================================
// Consul DNS Analysis
// ============================================================================

func analyzeConsulDNS(ctx context.Context, clientset kubernetes.Interface) ConsulDNSInfo {
	info := ConsulDNSInfo{}

	// Check for Consul deployment
	namespaces := []string{"consul", "hashicorp", "default", "kube-system"}
	for _, ns := range namespaces {
		deployments, err := clientset.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, dep := range deployments.Items {
			if !strings.Contains(strings.ToLower(dep.Name), "consul") {
				continue
			}

			// Verify by image
			imageVerified := false
			for _, container := range dep.Spec.Template.Spec.Containers {
				if strings.Contains(strings.ToLower(container.Image), "consul") ||
					strings.Contains(strings.ToLower(container.Image), "hashicorp/consul") {
					imageVerified = true
					break
				}
			}

			if !imageVerified {
				continue
			}

			info.Name = dep.Name
			info.Namespace = ns
			info.Status = "active"
			info.TotalPods = int(dep.Status.Replicas)
			info.PodsRunning = int(dep.Status.ReadyReplicas)
			info.ImageVerified = true
			info.DNSDomain = "consul" // default

			if info.PodsRunning < info.TotalPods {
				info.Status = "degraded"
			}

			// Try to get DNS domain from ConfigMap or args
			for _, container := range dep.Spec.Template.Spec.Containers {
				for _, arg := range container.Args {
					if strings.Contains(arg, "-domain=") {
						info.DNSDomain = strings.TrimPrefix(arg, "-domain=")
					}
				}
			}

			return info
		}
	}

	return info
}

// ============================================================================
// EKS Admin Network Policy Analysis
// ============================================================================

func analyzeEKSAdminNetworkPolicies(ctx context.Context, dynClient dynamic.Interface) []EKSAdminNetworkPolicyInfo {
	var policies []EKSAdminNetworkPolicyInfo

	// AdminNetworkPolicy (policy.networking.k8s.io/v1alpha1)
	gvr := schema.GroupVersionResource{
		Group:    "policy.networking.k8s.io",
		Version:  "v1alpha1",
		Resource: "adminnetworkpolicies",
	}

	list, err := dynClient.Resource(gvr).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range list.Items {
			policy := parseEKSAdminNetworkPolicy(item.Object, "AdminNetworkPolicy", true)
			if len(policy.DNSRules) > 0 {
				policies = append(policies, policy)
			}
		}
	}

	// ClusterNetworkPolicy (policy.networking.k8s.io/v1alpha1) - EKS specific
	gvr2 := schema.GroupVersionResource{
		Group:    "policy.networking.k8s.io",
		Version:  "v1alpha1",
		Resource: "clusternetworkpolicies",
	}

	list2, err := dynClient.Resource(gvr2).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range list2.Items {
			policy := parseEKSAdminNetworkPolicy(item.Object, "ClusterNetworkPolicy", true)
			if len(policy.DNSRules) > 0 {
				policies = append(policies, policy)
			}
		}
	}

	// BaselineAdminNetworkPolicy
	gvr3 := schema.GroupVersionResource{
		Group:    "policy.networking.k8s.io",
		Version:  "v1alpha1",
		Resource: "baselineadminnetworkpolicies",
	}

	list3, err := dynClient.Resource(gvr3).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range list3.Items {
			policy := parseEKSAdminNetworkPolicy(item.Object, "BaselineAdminNetworkPolicy", true)
			if len(policy.DNSRules) > 0 {
				policies = append(policies, policy)
			}
		}
	}

	return policies
}

func parseEKSAdminNetworkPolicy(obj map[string]interface{}, kind string, isCluster bool) EKSAdminNetworkPolicyInfo {
	policy := EKSAdminNetworkPolicyInfo{
		Kind:      kind,
		IsCluster: isCluster,
	}

	if metadata, ok := obj["metadata"].(map[string]interface{}); ok {
		if name, ok := metadata["name"].(string); ok {
			policy.Name = name
		}
	}

	if spec, ok := obj["spec"].(map[string]interface{}); ok {
		// Get priority
		if priority, ok := spec["priority"].(float64); ok {
			policy.Priority = int(priority)
		}

		// Get subject
		if subject, ok := spec["subject"].(map[string]interface{}); ok {
			if namespaces, ok := subject["namespaces"].(map[string]interface{}); ok {
				if matchLabels, ok := namespaces["matchLabels"].(map[string]interface{}); ok {
					var labels []string
					for k, v := range matchLabels {
						labels = append(labels, fmt.Sprintf("%s=%v", k, v))
					}
					policy.Subject = strings.Join(labels, ",")
				}
			}
		}

		// Check egress rules for DNS
		if egress, ok := spec["egress"].([]interface{}); ok {
			for _, rule := range egress {
				if ruleMap, ok := rule.(map[string]interface{}); ok {
					// Check for DNS-based rules (FQDN)
					if to, ok := ruleMap["to"].([]interface{}); ok {
						for _, peer := range to {
							if peerMap, ok := peer.(map[string]interface{}); ok {
								// Check for networks with DNS names
								if networks, ok := peerMap["networks"].([]interface{}); ok {
									for _, network := range networks {
										if netStr, ok := network.(string); ok {
											if strings.Contains(netStr, ".") && !strings.Contains(netStr, "/") {
												policy.DNSRules = append(policy.DNSRules, netStr)
											}
										}
									}
								}
								// Check for FQDN field (EKS specific)
								if fqdn, ok := peerMap["fqdn"].(string); ok {
									policy.DNSRules = append(policy.DNSRules, fqdn)
								}
								if fqdns, ok := peerMap["fqdns"].([]interface{}); ok {
									for _, f := range fqdns {
										if fStr, ok := f.(string); ok {
											policy.DNSRules = append(policy.DNSRules, fStr)
										}
									}
								}
							}
						}
					}

					// Check for ports containing DNS (53)
					if ports, ok := ruleMap["ports"].([]interface{}); ok {
						for _, port := range ports {
							if portMap, ok := port.(map[string]interface{}); ok {
								if portNum, ok := portMap["port"].(float64); ok {
									if int(portNum) == 53 {
										action := "Allow"
										if a, ok := ruleMap["action"].(string); ok {
											action = a
										}
										policy.DNSRules = append(policy.DNSRules, fmt.Sprintf("Port 53 %s", action))
									}
								}
							}
						}
					}
				}
			}
		}
	}

	return policy
}

// ============================================================================
// Native Kubernetes NetworkPolicy DNS Analysis
// ============================================================================

func analyzeK8sNetworkPolicyDNS(ctx context.Context, clientset kubernetes.Interface) []K8sNetworkPolicyDNSInfo {
	var policies []K8sNetworkPolicyDNSInfo

	for _, ns := range globals.K8sNamespaces {
		netpols, err := clientset.NetworkingV1().NetworkPolicies(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, np := range netpols.Items {
			info := K8sNetworkPolicyDNSInfo{
				Name:      np.Name,
				Namespace: np.Namespace,
			}

			// Get pod selector
			if len(np.Spec.PodSelector.MatchLabels) > 0 {
				var labels []string
				for k, v := range np.Spec.PodSelector.MatchLabels {
					labels = append(labels, fmt.Sprintf("%s=%s", k, v))
				}
				info.PodSelector = strings.Join(labels, ",")
			} else {
				info.PodSelector = "<all pods>"
			}

			// Check if there are egress rules
			hasEgressRules := false
			for _, policyType := range np.Spec.PolicyTypes {
				if policyType == "Egress" {
					hasEgressRules = true
					break
				}
			}

			if !hasEgressRules {
				continue // Skip policies without egress rules
			}

			// Check egress rules for DNS port (53)
			for _, egress := range np.Spec.Egress {
				for _, port := range egress.Ports {
					if port.Port != nil {
						portNum := port.Port.IntValue()
						if portNum == 53 {
							info.HasDNSEgress = true
							info.DNSEgressAction = "Allow"

							// Check what it's allowed to
							if len(egress.To) == 0 {
								info.Notes = append(info.Notes, "DNS allowed to any destination")
							} else {
								for _, to := range egress.To {
									if to.NamespaceSelector != nil {
										info.Notes = append(info.Notes, "DNS allowed to specific namespaces")
									}
									if to.PodSelector != nil {
										info.Notes = append(info.Notes, "DNS allowed to specific pods")
									}
									if to.IPBlock != nil {
										info.Notes = append(info.Notes, fmt.Sprintf("DNS allowed to CIDR: %s", to.IPBlock.CIDR))
									}
								}
							}
						}
					}
				}
			}

			// If egress is defined but DNS port not explicitly allowed, DNS is blocked
			if hasEgressRules && !info.HasDNSEgress && len(np.Spec.Egress) > 0 {
				// Check if there's a catch-all rule that would allow DNS
				for _, egress := range np.Spec.Egress {
					if len(egress.Ports) == 0 && len(egress.To) == 0 {
						// Empty egress rule allows all
						info.HasDNSEgress = true
						info.DNSEgressAction = "Allow (implicit)"
						info.Notes = append(info.Notes, "All egress allowed")
						break
					}
				}
			}

			// Only include if there's DNS-related configuration
			if info.HasDNSEgress || hasEgressRules {
				if !info.HasDNSEgress && hasEgressRules {
					info.DNSEgressAction = "Blocked (not in allow list)"
					info.Notes = append(info.Notes, "DNS port 53 not in egress allow list")
				}
				policies = append(policies, info)
			}
		}
	}

	return policies
}

// ============================================================================
// Istio ServiceEntry DNS Analysis
// ============================================================================

func analyzeIstioServiceEntries(ctx context.Context, dynClient dynamic.Interface) []IstioServiceEntryInfo {
	var entries []IstioServiceEntryInfo

	// ServiceEntry (networking.istio.io/v1beta1 or v1alpha3)
	versions := []string{"v1beta1", "v1alpha3", "v1"}

	for _, version := range versions {
		gvr := schema.GroupVersionResource{
			Group:    "networking.istio.io",
			Version:  version,
			Resource: "serviceentries",
		}

		list, err := dynClient.Resource(gvr).Namespace("").List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, item := range list.Items {
			entry := parseIstioServiceEntry(item.Object)
			// Only include entries that have DNS resolution
			if entry.Resolution == "DNS" || entry.Resolution == "DNS_ROUND_ROBIN" || len(entry.Hosts) > 0 {
				entries = append(entries, entry)
			}
		}

		if len(entries) > 0 {
			break // Found entries in this version, don't check others
		}
	}

	return entries
}

func parseIstioServiceEntry(obj map[string]interface{}) IstioServiceEntryInfo {
	entry := IstioServiceEntryInfo{}

	if metadata, ok := obj["metadata"].(map[string]interface{}); ok {
		if name, ok := metadata["name"].(string); ok {
			entry.Name = name
		}
		if namespace, ok := metadata["namespace"].(string); ok {
			entry.Namespace = namespace
		}
	}

	if spec, ok := obj["spec"].(map[string]interface{}); ok {
		// Get hosts
		if hosts, ok := spec["hosts"].([]interface{}); ok {
			for _, h := range hosts {
				if hStr, ok := h.(string); ok {
					entry.Hosts = append(entry.Hosts, hStr)
				}
			}
		}

		// Get location
		if location, ok := spec["location"].(string); ok {
			entry.Location = location
		}

		// Get resolution
		if resolution, ok := spec["resolution"].(string); ok {
			entry.Resolution = resolution
		}

		// Get ports
		if ports, ok := spec["ports"].([]interface{}); ok {
			for _, p := range ports {
				if pMap, ok := p.(map[string]interface{}); ok {
					var portStr string
					if number, ok := pMap["number"].(float64); ok {
						portStr = fmt.Sprintf("%d", int(number))
					}
					if protocol, ok := pMap["protocol"].(string); ok {
						portStr = fmt.Sprintf("%s/%s", portStr, protocol)
					}
					if portStr != "" {
						entry.Ports = append(entry.Ports, portStr)
					}
				}
			}
		}

		// Check exportTo for cluster-wide scope
		if exportTo, ok := spec["exportTo"].([]interface{}); ok {
			for _, e := range exportTo {
				if eStr, ok := e.(string); ok {
					if eStr == "*" {
						entry.IsCluster = true
						break
					}
				}
			}
		} else {
			// Default is exported to all namespaces
			entry.IsCluster = true
		}
	}

	return entry
}

// ============================================================================
// Cloud Provider DNS Policy Analysis
// ============================================================================

// analyzeAWSRoute53DNSFirewall detects AWS Route 53 DNS Firewall configuration
// Uses AWS API if cloud clients are available, otherwise falls back to in-cluster detection
func analyzeAWSRoute53DNSFirewall(ctx context.Context, clientset kubernetes.Interface, cloudDNS []CloudDNSInfo, dnsClients *DNSCloudClients, logger internal.Logger) AWSRoute53DNSFirewallInfo {
	info := AWSRoute53DNSFirewallInfo{
		RequiresCloudAccess: true,
	}

	// Check if we detected AWS DNS components
	for _, dns := range cloudDNS {
		if dns.Provider == "AWS" {
			info.VPCAssociation = true
			info.Notes = append(info.Notes, fmt.Sprintf("AWS DNS component detected: %s", dns.Name))
		}
	}

	// Check for AWS VPC CNI which indicates EKS
	namespaces := []string{"kube-system", "aws-system"}
	for _, ns := range namespaces {
		deployments, err := clientset.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, dep := range deployments.Items {
			// Check for aws-vpc-cni or AWS components
			if strings.Contains(strings.ToLower(dep.Name), "aws-node") ||
				strings.Contains(strings.ToLower(dep.Name), "vpc-cni") {
				info.Name = "AWS Route 53 DNS Firewall"
				info.Namespace = ns
				info.Notes = append(info.Notes, "EKS cluster detected - DNS Firewall may be configured at VPC level")
			}
		}
	}

	// Check for Route53 Resolver endpoints (indicated by service endpoints)
	configmaps, err := clientset.CoreV1().ConfigMaps("kube-system").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, cm := range configmaps.Items {
			if strings.Contains(strings.ToLower(cm.Name), "coredns") {
				// Check for forward to Route53 Resolver
				if data, ok := cm.Data["Corefile"]; ok {
					if strings.Contains(data, "forward") && (strings.Contains(data, "169.254") || strings.Contains(data, "AmazonProvidedDNS")) {
						info.Notes = append(info.Notes, "CoreDNS forwards to AWS VPC DNS - DNS Firewall rules apply")
					}
				}
			}
		}
	}

	// If AWS cloud client is available, enumerate DNS Firewall via API
	if dnsClients != nil && dnsClients.AWSRoute53ResolverClient != nil {
		info.RequiresCloudAccess = false

		// List Firewall Rule Groups
		ruleGroupsOutput, err := dnsClients.AWSRoute53ResolverClient.ListFirewallRuleGroups(ctx, &route53resolver.ListFirewallRuleGroupsInput{})
		if err == nil {
			info.RuleGroupCount = len(ruleGroupsOutput.FirewallRuleGroups)
			for _, rg := range ruleGroupsOutput.FirewallRuleGroups {
				if rg.Name != nil {
					info.Notes = append(info.Notes, fmt.Sprintf("Firewall Rule Group: %s (ShareStatus: %s)", *rg.Name, rg.ShareStatus))
				}
			}
		} else {
			logger.InfoM(fmt.Sprintf("Failed to list AWS DNS Firewall rule groups: %v", err), K8S_DNS_ADMISSION_MODULE_NAME)
		}

		// List Firewall Domain Lists
		domainListsOutput, err := dnsClients.AWSRoute53ResolverClient.ListFirewallDomainLists(ctx, &route53resolver.ListFirewallDomainListsInput{})
		if err == nil {
			info.DomainListCount = len(domainListsOutput.FirewallDomainLists)
			for _, dl := range domainListsOutput.FirewallDomainLists {
				if dl.Name != nil {
					owner := "user"
					if dl.ManagedOwnerName != nil {
						owner = *dl.ManagedOwnerName
					}
					info.Notes = append(info.Notes, fmt.Sprintf("Domain List: %s (Owner: %s)", *dl.Name, owner))
				}
			}
		} else {
			logger.InfoM(fmt.Sprintf("Failed to list AWS DNS Firewall domain lists: %v", err), K8S_DNS_ADMISSION_MODULE_NAME)
		}

		// List Firewall Rule Group Associations (VPC associations)
		assocOutput, err := dnsClients.AWSRoute53ResolverClient.ListFirewallRuleGroupAssociations(ctx, &route53resolver.ListFirewallRuleGroupAssociationsInput{})
		if err == nil && len(assocOutput.FirewallRuleGroupAssociations) > 0 {
			info.VPCAssociation = true
			for _, assoc := range assocOutput.FirewallRuleGroupAssociations {
				if assoc.Name != nil && assoc.VpcId != nil {
					info.Notes = append(info.Notes, fmt.Sprintf("VPC Association: %s -> %s", *assoc.Name, *assoc.VpcId))
				}
			}
		}

		if info.RuleGroupCount > 0 || info.DomainListCount > 0 {
			info.Name = "AWS Route 53 DNS Firewall"
		}
	}

	return info
}

// analyzeGCPResponsePolicies detects GCP Cloud DNS Response Policies
// Uses GCP API if cloud clients are available, otherwise falls back to in-cluster detection
func analyzeGCPResponsePolicies(ctx context.Context, clientset kubernetes.Interface, cloudDNS []CloudDNSInfo, dnsClients *DNSCloudClients, logger internal.Logger) GCPResponsePolicyInfo {
	info := GCPResponsePolicyInfo{
		RequiresCloudAccess: true,
	}

	// Check if we detected GCP DNS components
	for _, dns := range cloudDNS {
		if dns.Provider == "GCP" {
			info.ClusterScope = true
			info.Notes = append(info.Notes, fmt.Sprintf("GCP DNS component detected: %s", dns.Name))
		}
	}

	// Check for GKE-specific components
	namespaces := []string{"kube-system", "gke-system", "gke-managed-system"}
	for _, ns := range namespaces {
		deployments, err := clientset.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, dep := range deployments.Items {
			// Check for GKE DNS components
			if strings.Contains(strings.ToLower(dep.Name), "kube-dns") ||
				strings.Contains(strings.ToLower(dep.Name), "gke-dns") {
				info.Name = "GCP Cloud DNS Response Policies"
				info.Namespace = ns
				info.Notes = append(info.Notes, "GKE cluster detected - Response Policies may be bound to cluster")
			}
		}
	}

	// Check node labels for GKE
	nodes, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err == nil && len(nodes.Items) > 0 {
		for k := range nodes.Items[0].Labels {
			if strings.Contains(k, "cloud.google.com") || strings.Contains(k, "gke") {
				if info.Name == "" {
					info.Name = "GCP Cloud DNS Response Policies"
				}
				info.Notes = append(info.Notes, "GKE node detected - Cloud DNS Response Policies may apply")
				break
			}
		}
	}

	// If GCP cloud client is available, enumerate Response Policies via API
	if dnsClients != nil && dnsClients.GCPDNSService != nil && len(dnsClients.GCPProjects) > 0 {
		info.RequiresCloudAccess = false

		for _, project := range dnsClients.GCPProjects {
			// List Response Policies
			policiesCall := dnsClients.GCPDNSService.ResponsePolicies.List(project)
			policies, err := policiesCall.Do()
			if err == nil && policies.ResponsePolicies != nil {
				for _, rp := range policies.ResponsePolicies {
					info.Name = "GCP Cloud DNS Response Policies"
					info.Notes = append(info.Notes, fmt.Sprintf("Response Policy: %s (Project: %s)", rp.ResponsePolicyName, project))

					// List rules for each response policy
					rulesCall := dnsClients.GCPDNSService.ResponsePolicyRules.List(project, rp.ResponsePolicyName)
					rules, err := rulesCall.Do()
					if err == nil && rules.ResponsePolicyRules != nil {
						info.RuleCount += len(rules.ResponsePolicyRules)
						for _, rule := range rules.ResponsePolicyRules {
							if rule.DnsName != "" {
								info.Notes = append(info.Notes, fmt.Sprintf("  Rule: %s -> %s", rule.RuleName, rule.DnsName))
							}
						}
					}
				}
			} else if err != nil {
				logger.InfoM(fmt.Sprintf("Failed to list GCP DNS Response Policies for project %s: %v", project, err), K8S_DNS_ADMISSION_MODULE_NAME)
			}
		}
	}

	return info
}

// analyzeAzureDNSPrivateResolver detects Azure DNS Private Resolver
// Uses Azure API if cloud clients are available, otherwise falls back to in-cluster detection
func analyzeAzureDNSPrivateResolver(ctx context.Context, clientset kubernetes.Interface, cloudDNS []CloudDNSInfo, dnsClients *DNSCloudClients, logger internal.Logger) AzureDNSPrivateResolverInfo {
	info := AzureDNSPrivateResolverInfo{
		RequiresCloudAccess: true,
	}

	// Check if we detected Azure DNS components
	for _, dnsInfo := range cloudDNS {
		if dnsInfo.Provider == "Azure" {
			info.LinkedVNET = true
			info.Notes = append(info.Notes, fmt.Sprintf("Azure DNS component detected: %s", dnsInfo.Name))
		}
	}

	// Check for AKS-specific components
	namespaces := []string{"kube-system", "azure-system", "aks-system"}
	for _, ns := range namespaces {
		deployments, err := clientset.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, dep := range deployments.Items {
			// Check for Azure CNI or AKS components
			if strings.Contains(strings.ToLower(dep.Name), "azure-cni") ||
				strings.Contains(strings.ToLower(dep.Name), "aks") {
				info.Name = "Azure DNS Private Resolver"
				info.Namespace = ns
				info.Notes = append(info.Notes, "AKS cluster detected - Private Resolver may be linked to VNET")
			}
		}
	}

	// Check node labels for AKS
	nodes, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err == nil && len(nodes.Items) > 0 {
		for k := range nodes.Items[0].Labels {
			if strings.Contains(k, "kubernetes.azure.com") || strings.Contains(k, "node.kubernetes.io/instance-type") {
				// Check if it's Azure
				if strings.Contains(nodes.Items[0].Spec.ProviderID, "azure") {
					if info.Name == "" {
						info.Name = "Azure DNS Private Resolver"
					}
					info.Notes = append(info.Notes, "AKS node detected - Azure DNS Private Resolver may apply")
					break
				}
			}
		}
	}

	// If Azure cloud client is available, enumerate DNS Resolver and Private DNS via API
	if dnsClients != nil && dnsClients.AzureCredential != nil && len(dnsClients.AzureSubscriptions) > 0 {
		info.RequiresCloudAccess = false

		for _, subscriptionID := range dnsClients.AzureSubscriptions {
			// Create DNS Resolver client
			resolverClient, err := armdnsresolver.NewDNSResolversClient(subscriptionID, dnsClients.AzureCredential, nil)
			if err != nil {
				logger.InfoM(fmt.Sprintf("Failed to create Azure DNS Resolver client: %v", err), K8S_DNS_ADMISSION_MODULE_NAME)
				continue
			}

			// List DNS Resolvers in the subscription
			pager := resolverClient.NewListPager(nil)
			for pager.More() {
				page, err := pager.NextPage(ctx)
				if err != nil {
					logger.InfoM(fmt.Sprintf("Failed to list Azure DNS Resolvers: %v", err), K8S_DNS_ADMISSION_MODULE_NAME)
					break
				}

				for _, resolver := range page.Value {
					if resolver.Name != nil {
						info.Name = "Azure DNS Private Resolver"
						state := "Unknown"
						if resolver.Properties != nil && resolver.Properties.ProvisioningState != nil {
							state = string(*resolver.Properties.ProvisioningState)
						}
						info.Notes = append(info.Notes, fmt.Sprintf("DNS Resolver: %s (State: %s)", *resolver.Name, state))
					}
				}
			}

			// Create Forwarding Rulesets client
			forwardingClient, err := armdnsresolver.NewDNSForwardingRulesetsClient(subscriptionID, dnsClients.AzureCredential, nil)
			if err == nil {
				// List Forwarding Rulesets
				rulesetPager := forwardingClient.NewListPager(nil)
				for rulesetPager.More() {
					page, err := rulesetPager.NextPage(ctx)
					if err != nil {
						break
					}
					info.ForwardingRuleSets += len(page.Value)
					for _, ruleset := range page.Value {
						if ruleset.Name != nil {
							info.Notes = append(info.Notes, fmt.Sprintf("Forwarding Ruleset: %s", *ruleset.Name))
						}
					}
				}
			}

			// Create Private DNS Zones client to check for private zones
			privateDNSClient, err := armprivatedns.NewPrivateZonesClient(subscriptionID, dnsClients.AzureCredential, nil)
			if err == nil {
				// List Private DNS Zones
				zonePager := privateDNSClient.NewListPager(nil)
				for zonePager.More() {
					page, err := zonePager.NextPage(ctx)
					if err != nil {
						break
					}
					for _, zone := range page.Value {
						if zone.Name != nil {
							info.Notes = append(info.Notes, fmt.Sprintf("Private DNS Zone: %s", *zone.Name))
						}
					}
				}
			}

			// Create Inbound Endpoints client
			inboundClient, err := armdnsresolver.NewInboundEndpointsClient(subscriptionID, dnsClients.AzureCredential, nil)
			if err == nil {
				// We need resolver name and resource group to list inbound endpoints
				// For now, just note that we have the capability
				_ = inboundClient
			}

			// Create Outbound Endpoints client
			outboundClient, err := armdnsresolver.NewOutboundEndpointsClient(subscriptionID, dnsClients.AzureCredential, nil)
			if err == nil {
				_ = outboundClient
			}
		}

		if info.Name != "" || info.ForwardingRuleSets > 0 {
			info.Name = "Azure DNS Private Resolver"
		}
	}

	return info
}

// ============================================================================
// Antrea FQDN Policy Analysis
// ============================================================================

// AntreaFQDNPolicyInfo represents Antrea policies with FQDN rules
type AntreaFQDNPolicyInfo struct {
	Name           string
	Namespace      string
	IsCluster      bool
	FQDNRules      []string // FQDN patterns in egress rules
	Action         string   // Allow, Drop
	Priority       int
	AppliedTo      string
}

// analyzeAntreaFQDNPolicies finds Antrea policies with FQDN-based egress rules
func analyzeAntreaFQDNPolicies(ctx context.Context, dynClient dynamic.Interface) []AntreaFQDNPolicyInfo {
	var policies []AntreaFQDNPolicyInfo

	// ClusterNetworkPolicy
	cnpGVR := schema.GroupVersionResource{
		Group:    "crd.antrea.io",
		Version:  "v1beta1",
		Resource: "clusternetworkpolicies",
	}

	cnpList, err := dynClient.Resource(cnpGVR).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, cnp := range cnpList.Items {
			info := parseAntreaFQDNPolicy(cnp.Object, cnp.GetName(), "", true)
			if len(info.FQDNRules) > 0 {
				policies = append(policies, info)
			}
		}
	}

	// NetworkPolicy (namespaced)
	npGVR := schema.GroupVersionResource{
		Group:    "crd.antrea.io",
		Version:  "v1beta1",
		Resource: "networkpolicies",
	}

	npList, err := dynClient.Resource(npGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, np := range npList.Items {
			info := parseAntreaFQDNPolicy(np.Object, np.GetName(), np.GetNamespace(), false)
			if len(info.FQDNRules) > 0 {
				policies = append(policies, info)
			}
		}
	}

	return policies
}

func parseAntreaFQDNPolicy(obj map[string]interface{}, name, namespace string, isCluster bool) AntreaFQDNPolicyInfo {
	info := AntreaFQDNPolicyInfo{
		Name:      name,
		Namespace: namespace,
		IsCluster: isCluster,
	}

	if spec, ok := obj["spec"].(map[string]interface{}); ok {
		// Get priority
		if priority, ok := spec["priority"].(float64); ok {
			info.Priority = int(priority)
		}

		// Get appliedTo
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

		// Check egress rules for FQDN
		if egress, ok := spec["egress"].([]interface{}); ok {
			for _, e := range egress {
				if eMap, ok := e.(map[string]interface{}); ok {
					// Get action
					if action, ok := eMap["action"].(string); ok {
						info.Action = action
					}

					// Check for FQDN in to field
					if to, ok := eMap["to"].([]interface{}); ok {
						for _, t := range to {
							if tMap, ok := t.(map[string]interface{}); ok {
								if fqdn, ok := tMap["fqdn"].(string); ok {
									info.FQDNRules = append(info.FQDNRules, fqdn)
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
// Consul DNS Policy Analysis
// ============================================================================

// ConsulDNSForwardingInfo represents Consul DNS forwarding configuration
type ConsulDNSForwardingInfo struct {
	Name            string
	Namespace       string
	DNSDomain       string // e.g., "consul"
	Recursors       []string
	ForwardingRules []string
	EnableDNSProxy  bool
}

// analyzeConsulDNSForwarding analyzes Consul DNS forwarding configuration
func analyzeConsulDNSForwarding(ctx context.Context, dynClient dynamic.Interface, clientset kubernetes.Interface) []ConsulDNSForwardingInfo {
	var configs []ConsulDNSForwardingInfo

	// Check ProxyDefaults CRD for DNS settings
	pdGVR := schema.GroupVersionResource{
		Group:    "consul.hashicorp.com",
		Version:  "v1alpha1",
		Resource: "proxydefaults",
	}

	pdList, err := dynClient.Resource(pdGVR).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, pd := range pdList.Items {
			info := ConsulDNSForwardingInfo{
				Name:      pd.GetName(),
				Namespace: pd.GetNamespace(),
			}

			if spec, ok := pd.Object["spec"].(map[string]interface{}); ok {
				if transparentProxy, ok := spec["transparentProxy"].(map[string]interface{}); ok {
					if outboundListenerPort, ok := transparentProxy["outboundListenerPort"].(float64); ok && outboundListenerPort > 0 {
						info.EnableDNSProxy = true
					}
				}
				if meshGateway, ok := spec["meshGateway"].(map[string]interface{}); ok {
					if mode, ok := meshGateway["mode"].(string); ok {
						info.ForwardingRules = append(info.ForwardingRules, "meshGateway:"+mode)
					}
				}
			}

			if info.EnableDNSProxy || len(info.ForwardingRules) > 0 {
				configs = append(configs, info)
			}
		}
	}

	// Check Consul server ConfigMap for DNS configuration
	configMaps, err := clientset.CoreV1().ConfigMaps("").List(ctx, metav1.ListOptions{
		LabelSelector: "app=consul,component=server",
	})
	if err == nil {
		for _, cm := range configMaps.Items {
			if config, ok := cm.Data["server.json"]; ok {
				info := ConsulDNSForwardingInfo{
					Name:      cm.Name,
					Namespace: cm.Namespace,
				}

				// Parse recursors from config
				if strings.Contains(config, "recursors") {
					info.Recursors = append(info.Recursors, "configured")
				}

				// Check for DNS domain
				if strings.Contains(config, "domain") {
					info.DNSDomain = "consul" // default
				}

				configs = append(configs, info)
			}
		}
	}

	return configs
}

// ============================================================================
// Kubewarden DNS Policy Analysis
// ============================================================================

// KubewardenDNSPolicyInfo represents Kubewarden policies related to DNS
type KubewardenDNSPolicyInfo struct {
	Name         string
	Namespace    string
	PolicyServer string
	Mode         string // protect, monitor
	Module       string
	DNSRules     []string
}

// analyzeKubewardenDNSPolicies finds Kubewarden policies related to DNS resources
func analyzeKubewardenDNSPolicies(ctx context.Context, dynClient dynamic.Interface) []KubewardenDNSPolicyInfo {
	var policies []KubewardenDNSPolicyInfo

	// DNS-related module patterns
	dnsModules := []string{
		"dns", "coredns", "external-dns", "service",
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
			info := parseKubewardenDNSPolicy(cap.Object, cap.GetName(), "", dnsModules)
			if len(info.DNSRules) > 0 || info.Module != "" {
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
			info := parseKubewardenDNSPolicy(ap.Object, ap.GetName(), ap.GetNamespace(), dnsModules)
			if len(info.DNSRules) > 0 || info.Module != "" {
				policies = append(policies, info)
			}
		}
	}

	return policies
}

func parseKubewardenDNSPolicy(obj map[string]interface{}, name, namespace string, dnsModules []string) KubewardenDNSPolicyInfo {
	info := KubewardenDNSPolicyInfo{
		Name:      name,
		Namespace: namespace,
	}

	isDNSRelated := false

	if spec, ok := obj["spec"].(map[string]interface{}); ok {
		if module, ok := spec["module"].(string); ok {
			info.Module = module
			for _, pattern := range dnsModules {
				if strings.Contains(strings.ToLower(module), pattern) {
					isDNSRelated = true
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

		// Check rules for DNS-related resources
		if rules, ok := spec["rules"].([]interface{}); ok {
			for _, r := range rules {
				if rMap, ok := r.(map[string]interface{}); ok {
					if resources, ok := rMap["resources"].([]interface{}); ok {
						for _, res := range resources {
							if resStr, ok := res.(string); ok {
								// Check for services (which include ExternalName)
								if strings.Contains(resStr, "services") {
									isDNSRelated = true
									info.DNSRules = append(info.DNSRules, resStr)
								}
								// Check for ConfigMaps (CoreDNS config)
								if strings.Contains(resStr, "configmaps") {
									info.DNSRules = append(info.DNSRules, resStr)
								}
							}
						}
					}
				}
			}
		}
	}

	if !isDNSRelated {
		info.Module = "" // Clear module if not DNS related
	}

	return info
}
