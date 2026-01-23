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
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

const K8S_DNS_ADMISSION_MODULE_NAME = "dns-admission"

var DNSAdmissionCmd = &cobra.Command{
	Use:     "dns-admission",
	Aliases: []string{"dns-security", "coredns"},
	Short:   "Analyze DNS security configurations and policies",
	Long: `
Analyze all DNS security configurations including:
  - CoreDNS configuration analysis
  - CoreDNS security plugins (log, errors, cache, health)
  - NodeLocalDNS detection
  - external-dns configuration
  - Pod DNS policies (Default, ClusterFirst, None)
  - Cilium DNS policies
  - Calico DNS policies
  - DNS exfiltration risks

  cloudfox kubernetes dns-admission`,
	Run: ListDNSAdmission,
}

type DNSAdmissionOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t DNSAdmissionOutput) TableFiles() []internal.TableFile { return t.Table }
func (t DNSAdmissionOutput) LootFiles() []internal.LootFile   { return t.Loot }

// DNSAdmissionFinding represents DNS security for a namespace
type DNSAdmissionFinding struct {
	Namespace string

	// DNS Configuration
	DNSPolicy     string // Default, ClusterFirst, ClusterFirstWithHostNet, None
	CustomDNS     bool
	DNSConfig     string

	// DNS Policies
	HasCiliumDNSPolicy bool
	HasCalicoDNSPolicy bool
	CiliumPolicies     int
	CalicoPolicies     int

	// Pod Analysis
	TotalPods          int
	PodsWithDefaultDNS int
	PodsWithCustomDNS  int
	PodsWithNoDNS      int

	// Risk Analysis
	RiskLevel      string
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
	DNSSECEnabled   bool   // True if DNSSEC validation/signing is enabled
	DoTEnabled      bool   // True if DNS over TLS forwarding is configured
	DoHEnabled      bool   // True if DNS over HTTPS forwarding is configured
	ACLEnabled      bool   // True if access control lists are configured
	BypassRisk      string
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
	DNSSECEnabled    bool   // True if dnssec plugin is enabled for this zone
	DoTForwarding    bool   // True if forwarding uses tls:// protocol
	DoHForwarding    bool   // True if forwarding uses https:// protocol
	BypassRisk       string
}

// NodeLocalDNSInfo represents NodeLocalDNS deployment status
type NodeLocalDNSInfo struct {
	Name          string
	Namespace     string
	Status        string
	PodsRunning   int
	TotalPods     int
	LocalIP       string
	BypassRisk    string
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
	BypassRisk    string
	ImageVerified bool // True if external-dns image was verified
}

// CiliumDNSPolicyInfo represents a Cilium DNS policy
type CiliumDNSPolicyInfo struct {
	Name        string
	Namespace   string
	IsCluster   bool
	DNSRules    int
	MatchFQDNs  []string
	MatchPatterns []string
	Action      string
	BypassRisk  string
}

// CalicoDNSPolicyInfo represents a Calico DNS policy
type CalicoDNSPolicyInfo struct {
	Name        string
	Namespace   string
	IsGlobal    bool
	DNSRules    int
	Domains     []string
	Action      string
	BypassRisk  string
}

// PodDNSInfo represents DNS configuration for pods
type PodDNSInfo struct {
	Name        string
	Namespace   string
	DNSPolicy   string
	HasCustomDNS bool
	Nameservers []string
	Searches    []string
	BypassRisk  string
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
	BypassRisk          string
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
	BypassRisk    string
	ImageVerified bool // True if cloud DNS controller image was verified
}

func ListDNSAdmission(cmd *cobra.Command, args []string) {
	ctx, cancel := shared.ContextWithCancel()
	defer cancel()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDir, _ := parentCmd.PersistentFlags().GetString("outdir")

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

	// Build findings per namespace
	findings := buildDNSAdmissionFindings(coredns, ciliumDNS, calicoDNS, podDNS)

	// Generate tables
	summaryHeader := []string{
		"Namespace",
		"Pods Total",
		"Default DNS",
		"Custom DNS",
		"No DNS",
		"Cilium Policies",
		"Calico Policies",
		"Risk Level",
		"Issues",
	}

	corednsHeader := []string{
		"Namespace",
		"Status",
		"Pods Running",
		"Version",
		"Caching",
		"Logging",
		"Health",
		"Bypass Risk",
	}

	corednsConfigHeader := []string{
		"Zone",
		"Plugins",
		"Upstreams",
		"Forward To",
		"Cache TTL",
		"Bypass Risk",
	}

	nodeLocalDNSHeader := []string{
		"Namespace",
		"Status",
		"Pods Running",
		"Local IP",
		"Bypass Risk",
	}

	externalDNSHeader := []string{
		"Namespace",
		"Status",
		"Provider",
		"Sources",
		"Policy",
		"Bypass Risk",
	}

	ciliumDNSHeader := []string{
		"Name",
		"Namespace",
		"Scope",
		"DNS Rules",
		"Match FQDNs",
		"Match Patterns",
		"Action",
		"Bypass Risk",
	}

	calicoDNSHeader := []string{
		"Name",
		"Namespace",
		"Scope",
		"DNS Rules",
		"Domains",
		"Action",
		"Bypass Risk",
	}

	podDNSHeader := []string{
		"Name",
		"Namespace",
		"DNS Policy",
		"Custom DNS",
		"Nameservers",
		"Searches",
		"Bypass Risk",
	}

	istioDNSHeader := []string{
		"Namespace",
		"Status",
		"Pods Running",
		"DNS Capture",
		"Auto Allocate",
		"Bypass Risk",
	}

	cloudDNSHeader := []string{
		"Provider",
		"Name",
		"Namespace",
		"Status",
		"Type",
		"Pods Running",
		"Bypass Risk",
	}

	var summaryRows [][]string
	var corednsRows [][]string
	var corednsConfigRows [][]string
	var nodeLocalDNSRows [][]string
	var externalDNSRows [][]string
	var ciliumDNSRows [][]string
	var calicoDNSRows [][]string
	var podDNSRows [][]string
	var istioDNSRows [][]string
	var cloudDNSRows [][]string

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
			finding.RiskLevel,
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

		corednsRows = append(corednsRows, []string{
			coredns.Namespace,
			coredns.Status,
			fmt.Sprintf("%d/%d", coredns.PodsRunning, coredns.TotalPods),
			coredns.Version,
			caching,
			logging,
			health,
			coredns.BypassRisk,
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

		corednsConfigRows = append(corednsConfigRows, []string{
			cfg.Zone,
			plugins,
			upstreams,
			forwardTo,
			cacheTTL,
			cfg.BypassRisk,
		})
	}

	// Build NodeLocalDNS rows
	if nodeLocalDNS.Name != "" {
		nodeLocalDNSRows = append(nodeLocalDNSRows, []string{
			nodeLocalDNS.Namespace,
			nodeLocalDNS.Status,
			fmt.Sprintf("%d/%d", nodeLocalDNS.PodsRunning, nodeLocalDNS.TotalPods),
			nodeLocalDNS.LocalIP,
			nodeLocalDNS.BypassRisk,
		})
	}

	// Build external-dns rows
	if externalDNS.Name != "" {
		sources := "-"
		if len(externalDNS.Sources) > 0 {
			sources = strings.Join(externalDNS.Sources, ", ")
		}

		externalDNSRows = append(externalDNSRows, []string{
			externalDNS.Namespace,
			externalDNS.Status,
			externalDNS.Provider,
			sources,
			externalDNS.Policy,
			externalDNS.BypassRisk,
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

		fqdns := "-"
		if len(cdns.MatchFQDNs) > 0 {
			if len(cdns.MatchFQDNs) > 2 {
				fqdns = strings.Join(cdns.MatchFQDNs[:2], ", ") + "..."
			} else {
				fqdns = strings.Join(cdns.MatchFQDNs, ", ")
			}
		}

		patterns := "-"
		if len(cdns.MatchPatterns) > 0 {
			if len(cdns.MatchPatterns) > 2 {
				patterns = strings.Join(cdns.MatchPatterns[:2], ", ") + "..."
			} else {
				patterns = strings.Join(cdns.MatchPatterns, ", ")
			}
		}

		ciliumDNSRows = append(ciliumDNSRows, []string{
			cdns.Name,
			ns,
			scope,
			fmt.Sprintf("%d", cdns.DNSRules),
			fqdns,
			patterns,
			cdns.Action,
			cdns.BypassRisk,
		})
	}

	// Build Calico DNS policy rows
	for _, cal := range calicoDNS {
		scope := "Namespace"
		ns := cal.Namespace
		if cal.IsGlobal {
			scope = "Global"
			ns = "<GLOBAL>"
		}

		domains := "-"
		if len(cal.Domains) > 0 {
			if len(cal.Domains) > 2 {
				domains = strings.Join(cal.Domains[:2], ", ") + "..."
			} else {
				domains = strings.Join(cal.Domains, ", ")
			}
		}

		calicoDNSRows = append(calicoDNSRows, []string{
			cal.Name,
			ns,
			scope,
			fmt.Sprintf("%d", cal.DNSRules),
			domains,
			cal.Action,
			cal.BypassRisk,
		})
	}

	// Build pod DNS rows (only show interesting ones)
	for _, p := range podDNS {
		if p.DNSPolicy == "None" || p.HasCustomDNS || p.BypassRisk != "" {
			customDNS := "No"
			if p.HasCustomDNS {
				customDNS = "Yes"
			}

			nameservers := "-"
			if len(p.Nameservers) > 0 {
				nameservers = strings.Join(p.Nameservers, ", ")
			}

			searches := "-"
			if len(p.Searches) > 0 {
				if len(p.Searches) > 2 {
					searches = strings.Join(p.Searches[:2], ", ") + "..."
				} else {
					searches = strings.Join(p.Searches, ", ")
				}
			}

			podDNSRows = append(podDNSRows, []string{
				p.Name,
				p.Namespace,
				p.DNSPolicy,
				customDNS,
				nameservers,
				searches,
				p.BypassRisk,
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
		bypassRisk := "-"
		if istioDNS.BypassRisk != "" {
			bypassRisk = istioDNS.BypassRisk
		}

		istioDNSRows = append(istioDNSRows, []string{
			istioDNS.Namespace,
			istioDNS.Status,
			fmt.Sprintf("%d/%d", istioDNS.PodsRunning, istioDNS.TotalPods),
			dnsCapture,
			autoAllocate,
			bypassRisk,
		})
	}

	// Build cloud DNS rows
	for _, cloud := range cloudDNS {
		bypassRisk := "-"
		if cloud.BypassRisk != "" {
			bypassRisk = cloud.BypassRisk
		}

		cloudDNSRows = append(cloudDNSRows, []string{
			cloud.Provider,
			cloud.Name,
			cloud.Namespace,
			cloud.Status,
			cloud.Type,
			fmt.Sprintf("%d/%d", cloud.PodsRunning, cloud.TotalPods),
			bypassRisk,
		})
	}

	// Generate loot
	generateDNSAdmissionLoot(loot, findings, coredns, corednsConfig, nodeLocalDNS, externalDNS, ciliumDNS, calicoDNS, podDNS)

	// Build output tables
	var tables []internal.TableFile

	tables = append(tables, internal.TableFile{
		Name:   "DNS-Admission-Summary",
		Header: summaryHeader,
		Body:   summaryRows,
	})

	if len(corednsRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "DNS-Admission-CoreDNS",
			Header: corednsHeader,
			Body:   corednsRows,
		})
	}

	if len(corednsConfigRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "DNS-Admission-CoreDNS-Config",
			Header: corednsConfigHeader,
			Body:   corednsConfigRows,
		})
	}

	if len(nodeLocalDNSRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "DNS-Admission-NodeLocalDNS",
			Header: nodeLocalDNSHeader,
			Body:   nodeLocalDNSRows,
		})
	}

	if len(externalDNSRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "DNS-Admission-ExternalDNS",
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
			Name:   "DNS-Admission-Pod-DNS-Config",
			Header: podDNSHeader,
			Body:   podDNSRows,
		})
	}

	if len(istioDNSRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "DNS-Admission-Istio-DNS",
			Header: istioDNSHeader,
			Body:   istioDNSRows,
		})
	}

	if len(cloudDNSRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "DNS-Admission-Cloud-DNS",
			Header: cloudDNSHeader,
			Body:   cloudDNSRows,
		})
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
					if VerifyControllerImage(container.Image, "coredns") {
						info.ImageVerified = true
						parts := strings.Split(container.Image, ":")
						if len(parts) > 1 {
							info.Version = parts[1]
						}
					}
				}

				if dep.Status.ReadyReplicas < dep.Status.Replicas {
					info.Status = "degraded"
					info.BypassRisk = fmt.Sprintf("Only %d/%d CoreDNS pods running", dep.Status.ReadyReplicas, dep.Status.Replicas)
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

	// Assess risk
	if !info.LoggingEnabled {
		if info.BypassRisk != "" {
			info.BypassRisk += "; "
		}
		info.BypassRisk += "DNS logging disabled"
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

	// Assess risks
	for i := range configs {
		// Check for external DNS forwarding
		for _, fwd := range configs[i].ForwardTo {
			if fwd == "8.8.8.8" || fwd == "8.8.4.4" || fwd == "1.1.1.1" || strings.Contains(fwd, "dns.google") {
				configs[i].BypassRisk = "Forwards to public DNS"
			}
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
			if VerifyControllerImage(container.Image, "nodelocaldns") {
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
			info.BypassRisk = fmt.Sprintf("Only %d/%d NodeLocalDNS pods running", info.PodsRunning, info.TotalPods)
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
				if VerifyControllerImage(container.Image, "external-dns") {
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
				info.BypassRisk = fmt.Sprintf("Only %d/%d external-dns pods running", dep.Status.ReadyReplicas, dep.Status.Replicas)
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

			// Assess risk
			if info.Policy == "sync" {
				info.BypassRisk = "Sync policy may delete DNS records"
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

			// Assess risk
			if info.DNSPolicy == string(corev1.DNSNone) {
				info.BypassRisk = "DNS policy is None - may bypass cluster DNS"
			} else if info.DNSPolicy == string(corev1.DNSDefault) {
				info.BypassRisk = "Uses node DNS directly"
			}

			if info.HasCustomDNS {
				for _, ns := range info.Nameservers {
					// Check for external DNS servers
					if !strings.HasPrefix(ns, "10.") && !strings.HasPrefix(ns, "172.") && !strings.HasPrefix(ns, "192.168.") {
						if info.BypassRisk != "" {
							info.BypassRisk += "; "
						}
						info.BypassRisk += "External DNS servers configured"
						break
					}
				}
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
				finding.HasCiliumDNSPolicy = true
				finding.CiliumPolicies++
			}
		} else {
			// Cluster-wide policies apply to all
			for _, finding := range namespaceData {
				finding.HasCiliumDNSPolicy = true
				finding.CiliumPolicies++
			}
		}
	}

	// Count Calico DNS policies per namespace
	for _, p := range calicoDNS {
		if !p.IsGlobal {
			if finding, ok := namespaceData[p.Namespace]; ok {
				finding.HasCalicoDNSPolicy = true
				finding.CalicoPolicies++
			}
		} else {
			// Global policies apply to all
			for _, finding := range namespaceData {
				finding.HasCalicoDNSPolicy = true
				finding.CalicoPolicies++
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
		// Calculate risk
		riskScore := 0

		if finding.PodsWithNoDNS > 0 {
			riskScore += 3
			finding.SecurityIssues = append(finding.SecurityIssues, fmt.Sprintf("%d pods with DNS=None", finding.PodsWithNoDNS))
		}

		if finding.PodsWithCustomDNS > 0 {
			riskScore += 1
			finding.SecurityIssues = append(finding.SecurityIssues, fmt.Sprintf("%d pods with custom DNS", finding.PodsWithCustomDNS))
		}

		if !finding.HasCiliumDNSPolicy && !finding.HasCalicoDNSPolicy && finding.TotalPods > 0 {
			riskScore += 1
			finding.SecurityIssues = append(finding.SecurityIssues, "No DNS egress policy")
		}

		if riskScore >= 3 {
			finding.RiskLevel = "HIGH"
		} else if riskScore >= 1 {
			finding.RiskLevel = "MEDIUM"
		} else {
			finding.RiskLevel = "LOW"
		}

		findings = append(findings, *finding)
	}

	// Sort by risk level then namespace
	sort.Slice(findings, func(i, j int) bool {
		riskOrder := map[string]int{"HIGH": 0, "MEDIUM": 1, "LOW": 2}
		if riskOrder[findings[i].RiskLevel] != riskOrder[findings[j].RiskLevel] {
			return riskOrder[findings[i].RiskLevel] < riskOrder[findings[j].RiskLevel]
		}
		return findings[i].Namespace < findings[j].Namespace
	})

	return findings
}

// ============================================================================
// Loot Generation
// ============================================================================

func generateDNSAdmissionLoot(loot *shared.LootBuilder,
	findings []DNSAdmissionFinding,
	coredns CoreDNSInfo, corednsConfig []CoreDNSConfigInfo,
	nodeLocalDNS NodeLocalDNSInfo,
	externalDNS ExternalDNSInfo,
	ciliumDNS []CiliumDNSPolicyInfo,
	calicoDNS []CalicoDNSPolicyInfo,
	podDNS []PodDNSInfo) {

	// Summary
	loot.Section("Summary").Add("# DNS Security Summary")
	loot.Section("Summary").Add("#")

	if coredns.Name != "" {
		plugins := "none"
		if len(coredns.SecurityPlugins) > 0 {
			plugins = strings.Join(coredns.SecurityPlugins, ", ")
		}
		loot.Section("Summary").Add(fmt.Sprintf("# CoreDNS: %s (version: %s, security plugins: %s)", coredns.Status, coredns.Version, plugins))
	} else {
		loot.Section("Summary").Add("# CoreDNS: NOT FOUND")
	}

	if nodeLocalDNS.Name != "" {
		loot.Section("Summary").Add(fmt.Sprintf("# NodeLocalDNS: %s (local IP: %s)", nodeLocalDNS.Status, nodeLocalDNS.LocalIP))
	}

	if externalDNS.Name != "" {
		loot.Section("Summary").Add(fmt.Sprintf("# external-dns: %s (provider: %s, policy: %s)", externalDNS.Status, externalDNS.Provider, externalDNS.Policy))
	}

	loot.Section("Summary").Add(fmt.Sprintf("# Cilium DNS policies: %d", len(ciliumDNS)))
	loot.Section("Summary").Add(fmt.Sprintf("# Calico DNS policies: %d", len(calicoDNS)))
	loot.Section("Summary").Add("#")

	// DNS Exfiltration Risks
	loot.Section("ExfiltrationRisks").Add("# DNS Exfiltration Risk Analysis")
	loot.Section("ExfiltrationRisks").Add("#")

	noDNSPods := 0
	customDNSPods := 0
	for _, p := range podDNS {
		if p.DNSPolicy == "None" {
			noDNSPods++
		}
		if p.HasCustomDNS {
			customDNSPods++
		}
	}

	if noDNSPods > 0 {
		loot.Section("ExfiltrationRisks").Add(fmt.Sprintf("# HIGH: %d pods with DNS policy=None (can use arbitrary DNS)", noDNSPods))
	}
	if customDNSPods > 0 {
		loot.Section("ExfiltrationRisks").Add(fmt.Sprintf("# MEDIUM: %d pods with custom DNS configuration", customDNSPods))
	}
	if len(ciliumDNS) == 0 && len(calicoDNS) == 0 {
		loot.Section("ExfiltrationRisks").Add("# MEDIUM: No DNS egress policies detected - all DNS queries allowed")
	}

	loot.Section("ExfiltrationRisks").Add("#")

	// Pods with DNS bypass
	if noDNSPods > 0 || customDNSPods > 0 {
		loot.Section("DNSBypassPods").Add("# Pods with DNS Configuration Bypass")
		loot.Section("DNSBypassPods").Add("#")
		for _, p := range podDNS {
			if p.BypassRisk != "" {
				loot.Section("DNSBypassPods").Add(fmt.Sprintf("# %s/%s: %s", p.Namespace, p.Name, p.BypassRisk))
			}
		}
		loot.Section("DNSBypassPods").Add("#")
	}

	// Bypass vectors
	loot.Section("BypassVectors").Add("# DNS Security Bypass Vectors")
	loot.Section("BypassVectors").Add("#")

	if coredns.BypassRisk != "" {
		loot.Section("BypassVectors").Add(fmt.Sprintf("# CoreDNS: %s", coredns.BypassRisk))
	}

	for _, cfg := range corednsConfig {
		if cfg.BypassRisk != "" {
			loot.Section("BypassVectors").Add(fmt.Sprintf("# CoreDNS zone %s: %s", cfg.Zone, cfg.BypassRisk))
		}
	}

	if externalDNS.BypassRisk != "" {
		loot.Section("BypassVectors").Add(fmt.Sprintf("# external-dns: %s", externalDNS.BypassRisk))
	}

	loot.Section("BypassVectors").Add("#")

	// Recommendations
	loot.Section("Recommendations").Add("# Recommendations")
	loot.Section("Recommendations").Add("#")

	if !coredns.LoggingEnabled {
		loot.Section("Recommendations").Add("# 1. Enable CoreDNS logging for visibility into DNS queries")
	}

	if len(ciliumDNS) == 0 && len(calicoDNS) == 0 {
		loot.Section("Recommendations").Add("# 2. Implement DNS egress policies to control DNS resolution")
		loot.Section("Recommendations").Add("#    Example Cilium DNS policy:")
		loot.Section("Recommendations").Add("#    toFQDNs:")
		loot.Section("Recommendations").Add("#    - matchPattern: \"*.example.com\"")
	}

	if noDNSPods > 0 {
		loot.Section("Recommendations").Add(fmt.Sprintf("# 3. Review %d pods with DNS policy=None for necessity", noDNSPods))
	}

	// Commands
	loot.Section("Commands").Add("# Useful Commands")
	loot.Section("Commands").Add("#")
	loot.Section("Commands").Add("# Check CoreDNS config:")
	loot.Section("Commands").Add("kubectl get configmap coredns -n kube-system -o yaml")
	loot.Section("Commands").Add("#")
	loot.Section("Commands").Add("# Check CoreDNS logs:")
	loot.Section("Commands").Add("kubectl logs -l k8s-app=kube-dns -n kube-system")
	loot.Section("Commands").Add("#")
	loot.Section("Commands").Add("# Check pods with custom DNS:")
	loot.Section("Commands").Add("kubectl get pods -A -o jsonpath='{range .items[?(@.spec.dnsPolicy==\"None\")]}{.metadata.namespace}/{.metadata.name}{\"\\n\"}{end}'")
	loot.Section("Commands").Add("#")
	loot.Section("Commands").Add("# List Cilium DNS policies:")
	loot.Section("Commands").Add("kubectl get ciliumnetworkpolicies -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{\"\\n\"}{end}' | xargs -I {} kubectl get cnp {} -o yaml | grep -A5 toFQDNs")
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
				info.BypassRisk = fmt.Sprintf("Only %d/%d Istiod pods running", info.PodsRunning, info.TotalPods)
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
							info.BypassRisk = fmt.Sprintf("Only %d/%d pods running", info.PodsRunning, info.TotalPods)
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
							info.BypassRisk = fmt.Sprintf("Only %d/%d pods running", info.PodsRunning, info.TotalPods)
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
							info.BypassRisk = fmt.Sprintf("Only %d/%d pods running", info.PodsRunning, info.TotalPods)
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
