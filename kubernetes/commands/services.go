package commands

import (
	"fmt"
	"net"
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
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var ServicesCmd = &cobra.Command{
	Use:     "services",
	Aliases: []string{"svc"},
	Short:   "Enumerate services with comprehensive security analysis",
	Long: `
Enumerate all services in the cluster with enterprise-grade security analysis including:
  - External exposure analysis (LoadBalancer, NodePort, Ingress correlation)
  - Attack surface calculation (exposed ports × backend pods)
  - Backend pod security analysis (privileged, host access)
  - Dangerous port detection (administrative, database, unencrypted protocols)
  - TLS/encryption status analysis
  - Network policy protection detection
  - Service type risk scoring (ExternalName = DNS hijack risk)
  - NodePort range and collision detection
  - Headless service DNS enumeration risks
  - Service account access analysis
  - Cost and security optimization recommendations

  cloudfox kubernetes services`,
	Run: ListServices,
}

// Package-level maps for port categorization (performance optimization)
var dangerousPortMap = map[int32]DangerousPort{
	// Administrative
	22:    {22, "SSH", "TCP", "SSH administrative access", "admin"},
	23:    {23, "Telnet", "TCP", "Telnet unencrypted admin", "admin"},
	3389:  {3389, "RDP", "TCP", "Remote Desktop", "admin"},
	5900:  {5900, "VNC", "TCP", "VNC remote desktop", "admin"},
	5984:  {5984, "CouchDB", "TCP", "CouchDB admin", "admin"},
	8080:  {8080, "HTTP-Alt", "TCP", "HTTP alternative (often admin)", "admin"},
	9090:  {9090, "Prometheus", "TCP", "Prometheus metrics", "admin"},
	10250: {10250, "Kubelet", "TCP", "Kubelet API (node compromise)", "admin"},

	// Databases (unencrypted)
	1433:  {1433, "MSSQL", "TCP", "Microsoft SQL Server", "database"},
	3306:  {3306, "MySQL", "TCP", "MySQL unencrypted", "database"},
	5432:  {5432, "PostgreSQL", "TCP", "PostgreSQL", "database"},
	6379:  {6379, "Redis", "TCP", "Redis no auth default", "database"},
	7000:  {7000, "Cassandra", "TCP", "Cassandra", "database"},
	8529:  {8529, "ArangoDB", "TCP", "ArangoDB", "database"},
	9042:  {9042, "Cassandra", "TCP", "Cassandra CQL", "database"},
	9200:  {9200, "Elasticsearch", "TCP", "Elasticsearch", "database"},
	27017: {27017, "MongoDB", "TCP", "MongoDB", "database"},
	28015: {28015, "RethinkDB", "TCP", "RethinkDB", "database"},

	// Unencrypted Protocols
	21:   {21, "FTP", "TCP", "FTP unencrypted", "unencrypted"},
	80:   {80, "HTTP", "TCP", "HTTP unencrypted", "unencrypted"},
	8000: {8000, "HTTP-Alt", "TCP", "HTTP alternative", "unencrypted"},
	8888: {8888, "HTTP-Alt", "TCP", "HTTP alternative", "unencrypted"},

	// Development/Debug
	2375: {2375, "Docker", "TCP", "Docker API unencrypted", "development"},
	4444: {4444, "Metasploit", "TCP", "Metasploit default", "development"},
	5000: {5000, "Flask", "TCP", "Flask dev server", "development"},
	8081: {8081, "Debug", "TCP", "Common debug port", "development"},
}

var tlsPortMap = map[int32]bool{
	443:   true, // HTTPS
	8443:  true, // HTTPS alternative
	6443:  true, // Kubernetes API
	9443:  true, // Alternative HTTPS
	10250: false, // Kubelet (can be TLS but often not verified)
}

type ServicesOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t ServicesOutput) TableFiles() []internal.TableFile {
	return t.Table
}

func (t ServicesOutput) LootFiles() []internal.LootFile {
	return t.Loot
}

type ServiceFinding struct {
	// Basic Info
	Namespace string
	Name      string
	Type      string // ClusterIP, NodePort, LoadBalancer, ExternalName
	Age       time.Duration
	AgeDays   int

	// IP and DNS
	ClusterIPs      []string
	ExternalIPs     []string
	LoadBalancerIPs []string
	ExternalName    string // for ExternalName type
	IsHeadless      bool
	DNSName         string

	// Exposure Analysis
	ExternallyExposed bool
	ExposureType      string   // "LoadBalancer", "NodePort", "Ingress", "ExternalIPs"
	ExposureMethods   []string // can have multiple
	PublicIP          bool
	IngressCount      int
	IngressNames      []string

	// Port Analysis
	TotalPorts       int
	TCPPorts         []int32
	UDPPorts         []int32
	NodePorts        []int32
	DangerousPorts   []string // "3306 (MySQL unencrypted)", "6379 (Redis no auth)"
	AdminPorts       []string // "22 (SSH)", "3389 (RDP)", "9090 (Prometheus)"
	UnencryptedPorts []string // HTTP, FTP, Telnet, etc.
	EncryptedPorts   []string // HTTPS, 8443, etc.
	HasTLS           bool

	// Backend Analysis
	EndpointCount         int
	BackendPods           []string
	BackendPodCount       int
	PrivilegedBackends    int
	HostNetworkBackends   int
	HostPIDBackends       int
	BackendSecurityIssues []string

	// Network Security
	NetworkPolicyProtected bool
	NetworkPolicyNames     []string
	AllowedSources         []string // CIDR ranges from NetworkPolicies
	UnrestrictedAccess     bool     // no NetworkPolicy = unrestricted

	// Service Account Access
	AccessibleBySAs []string
	PublicAccess    bool // accessible by default SA or unauthenticated

	// Security Issues
	RiskLevel      string
	RiskScore      int
	AttackSurface  int // ports × endpoints × exposure multipliers
	SecurityIssues []string
	ImpactSummary  string

	// Cost and Optimization
	LoadBalancerCost bool // LoadBalancer = cloud provider cost
	NodePortOverlap  bool // NodePort collision detection

	// Annotations
	Annotations      map[string]string
	SuspiciousAnnots []string // cloud provider specific, custom domains
	SessionAffinity  string
}

type DangerousPort struct {
	Port        int32
	Name        string
	Protocol    string
	Description string
	Category    string // "database", "admin", "unencrypted", "development"
}

type IngressInfo struct {
	Name      string
	Namespace string
	Hosts     []string
	TLS       bool
	Rules     int
}

type NetworkPolicyInfo struct {
	Name            string
	ProtectsService bool
	AllowedCIDRs    []string
	AllowedPods     []string
}

func ListServices(cmd *cobra.Command, args []string) {
	ctx, cancel := shared.ContextWithCancel()
	defer cancel()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating services for %s", globals.ClusterName), globals.K8S_SERVICES_MODULE_NAME)

	clientset := config.GetClientOrExit()

	// Get all Services from cache
	services, err := sdk.GetServices(ctx, clientset)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error retrieving services: %v", err), globals.K8S_SERVICES_MODULE_NAME)
		return
	}

	// Get all Ingresses for correlation using cache
	allIngresses, err := sdk.GetIngresses(ctx, clientset)
	if err != nil {
		shared.LogListError(&logger, "ingresses", "", err, globals.K8S_SERVICES_MODULE_NAME, false)
		allIngresses = []networkingv1.Ingress{}
	}

	// Get all NetworkPolicies using cache
	allNetworkPolicies, err := sdk.GetNetworkPolicies(ctx, clientset)
	if err != nil {
		shared.LogListError(&logger, "network policies", "", err, globals.K8S_SERVICES_MODULE_NAME, false)
		allNetworkPolicies = []networkingv1.NetworkPolicy{}
	}

	// Get all Pods for backend analysis using cache
	allPods, err := sdk.GetPods(ctx, clientset)
	if err != nil {
		shared.LogListError(&logger, "pods", "", err, globals.K8S_SERVICES_MODULE_NAME, false)
		allPods = []corev1.Pod{}
	}

	headers := []string{
		"Attack Surface",
		"Namespace",
		"Service",
		"Type",
		"Exposure",
		"Backends",
		"Priv Pods",
		"Dangerous Ports",
		"TLS",
		"NetPol",
		"Ingress",
		"External IPs",
		"Issues",
	}

	var outputRows [][]string
	var findings []ServiceFinding

	// Risk counters using shared type
	riskCounts := shared.NewRiskCounts()

	// Loot builder using shared pattern
	loot := shared.NewLootBuilder()

	loot.Section("Services-Enum").SetHeader(`#####################################
##### Service Enumeration
#####################################
#
# Complete service inventory with security analysis
#`)

	loot.Section("Services-TCP").SetHeader(`#####################################
##### TCP Service Port-Forward Commands
#####################################
#
# Port-forward to access internal services
#`)

	loot.Section("Services-UDP").SetHeader(`#####################################
##### UDP Service Access Commands
#####################################
#
# UDP services require special handling
#`)

	loot.Section("Services-ExternalExposure").SetHeader(`#####################################
##### Externally Exposed Services
#####################################
#
# Services accessible from outside the cluster
#`)

	loot.Section("Services-DangerousPorts").SetHeader(`#####################################
##### Dangerous Port Exposure
#####################################
#
# Administrative, database, or unencrypted protocols
#`)

	loot.Section("Services-LoadBalancers").SetHeader(`#####################################
##### LoadBalancer Services
#####################################
#
# LoadBalancer services incur cloud provider costs
#`)

	loot.Section("Services-NodePorts").SetHeader(`#####################################
##### NodePort Services
#####################################
#
# NodePort services expose on ALL cluster nodes
#`)

	loot.Section("Services-Unprotected").SetHeader(`#####################################
##### Services Without Network Policies
#####################################
#
# Services lacking NetworkPolicy protection
#`)

	loot.Section("Services-Ingress").SetHeader(`#####################################
##### Ingress-Exposed Services
#####################################
#
# Services exposed via Ingress resources
#`)

	loot.Section("Services-AttackSurface").SetHeader(`#####################################
##### Attack Surface Analysis
#####################################
#
# Services ranked by attack surface
#`)

	loot.Section("Services-Remediation").SetHeader(`#####################################
##### Security Remediation Recommendations
#####################################
#
# Step-by-step fixes for identified issues
#`)

	if globals.KubeContext != "" {
		loot.Section("Services-Enum").Addf("kubectl config use-context %s", globals.KubeContext)
		loot.Section("Services-TCP").Addf("kubectl config use-context %s", globals.KubeContext)
		loot.Section("Services-UDP").Addf("kubectl config use-context %s", globals.KubeContext)
	}

	for _, svc := range services {
		finding := ServiceFinding{
			Namespace:   svc.Namespace,
			Name:        svc.Name,
			Type:        string(svc.Spec.Type),
			Annotations: svc.Annotations,
		}

		// Calculate age
		finding.Age = time.Since(svc.CreationTimestamp.Time)
		finding.AgeDays = int(finding.Age.Hours() / 24)

		// IP Analysis
		finding.ClusterIPs = svc.Spec.ClusterIPs
		finding.ExternalIPs = svc.Spec.ExternalIPs
		finding.IsHeadless = svc.Spec.ClusterIP == "None"
		finding.DNSName = fmt.Sprintf("%s.%s.svc.cluster.local", svc.Name, svc.Namespace)

		if svc.Spec.Type == corev1.ServiceTypeExternalName {
			finding.ExternalName = svc.Spec.ExternalName
			finding.SecurityIssues = append(finding.SecurityIssues,
				fmt.Sprintf("ExternalName service pointing to %s (DNS hijack risk)", svc.Spec.ExternalName))
		}

		// LoadBalancer IPs
		for _, lb := range svc.Status.LoadBalancer.Ingress {
			if lb.IP != "" {
				finding.LoadBalancerIPs = append(finding.LoadBalancerIPs, lb.IP)
				finding.PublicIP = isPublicIP(lb.IP)
			}
			if lb.Hostname != "" {
				finding.LoadBalancerIPs = append(finding.LoadBalancerIPs, lb.Hostname)
			}
		}

		// Port Analysis
		finding.TotalPorts = len(svc.Spec.Ports)
		for _, p := range svc.Spec.Ports {
			switch p.Protocol {
			case corev1.ProtocolTCP:
				finding.TCPPorts = append(finding.TCPPorts, p.Port)
			case corev1.ProtocolUDP:
				finding.UDPPorts = append(finding.UDPPorts, p.Port)
			}

			if p.NodePort != 0 {
				finding.NodePorts = append(finding.NodePorts, p.NodePort)
			}

			// Check for dangerous ports
			if dangerousPort := getDangerousPort(p.Port); dangerousPort != nil {
				finding.DangerousPorts = append(finding.DangerousPorts,
					fmt.Sprintf("%d (%s)", p.Port, dangerousPort.Description))

				if dangerousPort.Category == "admin" {
					finding.AdminPorts = append(finding.AdminPorts,
						fmt.Sprintf("%d (%s)", p.Port, dangerousPort.Name))
				} else if dangerousPort.Category == "unencrypted" {
					finding.UnencryptedPorts = append(finding.UnencryptedPorts,
						fmt.Sprintf("%d (%s)", p.Port, dangerousPort.Name))
				}
			}

			// Check for TLS/encrypted ports
			if isTLSPort(p.Port) {
				finding.HasTLS = true
				finding.EncryptedPorts = append(finding.EncryptedPorts,
					fmt.Sprintf("%d", p.Port))
			}
		}

		// Exposure Analysis
		if svc.Spec.Type == corev1.ServiceTypeLoadBalancer {
			finding.ExternallyExposed = true
			finding.ExposureMethods = append(finding.ExposureMethods, "LoadBalancer")
			finding.ExposureType = "LoadBalancer"
			finding.LoadBalancerCost = true
		}

		if svc.Spec.Type == corev1.ServiceTypeNodePort || len(finding.NodePorts) > 0 {
			finding.ExternallyExposed = true
			finding.ExposureMethods = append(finding.ExposureMethods, "NodePort")
			if finding.ExposureType == "" {
				finding.ExposureType = "NodePort"
			}
		}

		if len(svc.Spec.ExternalIPs) > 0 {
			finding.ExternallyExposed = true
			finding.ExposureMethods = append(finding.ExposureMethods, "ExternalIPs")
			if finding.ExposureType == "" {
				finding.ExposureType = "ExternalIPs"
			}
		}

		// Ingress correlation
		ingressList := findIngressesForService(allIngresses, svc.Namespace, svc.Name)
		finding.IngressCount = len(ingressList)
		for _, ing := range ingressList {
			finding.IngressNames = append(finding.IngressNames, ing.Name)
			if !finding.ExternallyExposed {
				finding.ExternallyExposed = true
				finding.ExposureMethods = append(finding.ExposureMethods, "Ingress")
				if finding.ExposureType == "" {
					finding.ExposureType = "Ingress"
				}
			}
		}

		// Endpoints and backend pod analysis
		ep, err := clientset.CoreV1().Endpoints(svc.Namespace).Get(ctx, svc.Name, metav1.GetOptions{})
		if err == nil {
			for _, subset := range ep.Subsets {
				finding.EndpointCount += len(subset.Addresses)
			}
		} else {
			logger.ErrorM(fmt.Sprintf("Warning: Could not get endpoints for service %s/%s: %v", svc.Namespace, svc.Name, err), globals.K8S_SERVICES_MODULE_NAME)
		}

		// Backend pod security analysis
		backendPods := findBackendPods(allPods, svc.Namespace, svc.Spec.Selector)
		finding.BackendPodCount = len(backendPods)
		for _, pod := range backendPods {
			finding.BackendPods = append(finding.BackendPods, pod.Name)

			// Check for privileged containers (both init and regular containers)
			podHasPrivileged := false

			// Check init containers
			for _, container := range pod.Spec.InitContainers {
				if container.SecurityContext != nil &&
					container.SecurityContext.Privileged != nil &&
					*container.SecurityContext.Privileged {
					podHasPrivileged = true
					break
				}
			}

			// Check regular containers if not already found in init containers
			if !podHasPrivileged {
				for _, container := range pod.Spec.Containers {
					if container.SecurityContext != nil &&
						container.SecurityContext.Privileged != nil &&
						*container.SecurityContext.Privileged {
						podHasPrivileged = true
						break
					}
				}
			}

			if podHasPrivileged {
				finding.PrivilegedBackends++
			}

			if pod.Spec.HostNetwork {
				finding.HostNetworkBackends++
			}
			if pod.Spec.HostPID {
				finding.HostPIDBackends++
			}
		}

		if finding.PrivilegedBackends > 0 {
			finding.BackendSecurityIssues = append(finding.BackendSecurityIssues,
				fmt.Sprintf("%d privileged backend pods", finding.PrivilegedBackends))
		}
		if finding.HostNetworkBackends > 0 {
			finding.BackendSecurityIssues = append(finding.BackendSecurityIssues,
				fmt.Sprintf("%d hostNetwork backend pods", finding.HostNetworkBackends))
		}

		// Network Policy analysis
		if len(svc.Spec.Selector) > 0 {
			netpolInfo := servicesAnalyzeNetworkPolicies(allNetworkPolicies, svc.Namespace, svc.Spec.Selector)
			finding.NetworkPolicyProtected = len(netpolInfo) > 0
			for _, np := range netpolInfo {
				finding.NetworkPolicyNames = append(finding.NetworkPolicyNames, np.Name)
				finding.AllowedSources = append(finding.AllowedSources, np.AllowedCIDRs...)
			}
			finding.UnrestrictedAccess = !finding.NetworkPolicyProtected
		}

		// Session affinity
		finding.SessionAffinity = string(svc.Spec.SessionAffinity)

		// Suspicious annotations
		finding.SuspiciousAnnots = detectSuspiciousAnnotations(svc.Annotations)

		// Calculate risk score and attack surface
		riskLevel, riskScore := calculateServiceRiskScore(&finding)
		finding.RiskLevel = riskLevel
		finding.RiskScore = riskScore
		finding.AttackSurface = calculateAttackSurface(&finding)
		finding.ImpactSummary = generateServiceImpactSummary(&finding)

		// Add to security issues
		if finding.ExternallyExposed && len(finding.DangerousPorts) > 0 {
			finding.SecurityIssues = append(finding.SecurityIssues,
				fmt.Sprintf("Externally exposed dangerous ports: %s", strings.Join(finding.DangerousPorts, ", ")))
		}
		if finding.ExternallyExposed && !finding.NetworkPolicyProtected {
			finding.SecurityIssues = append(finding.SecurityIssues,
				"Externally exposed without NetworkPolicy protection")
		}
		if finding.LoadBalancerCost {
			finding.SecurityIssues = append(finding.SecurityIssues,
				"LoadBalancer incurs cloud provider costs")
		}
		if finding.UnrestrictedAccess && finding.ExternallyExposed {
			finding.SecurityIssues = append(finding.SecurityIssues,
				"CRITICAL: Externally exposed with unrestricted internal access")
		}

		riskCounts.Add(finding.RiskLevel)
		findings = append(findings, finding)

		// Generate output row
		exposureStr := "Internal"
		if finding.ExternallyExposed {
			exposureStr = strings.Join(finding.ExposureMethods, ",")
		}

		netpolStr := "No"
		if finding.NetworkPolicyProtected {
			netpolStr = fmt.Sprintf("%d", len(finding.NetworkPolicyNames))
		}

		tlsStr := "No"
		if finding.HasTLS {
			tlsStr = "Yes"
		}

		ingressStr := "No"
		if finding.IngressCount > 0 {
			ingressStr = fmt.Sprintf("%d", finding.IngressCount)
		}

		externalIPStr := ""
		if len(finding.ExternalIPs) > 0 {
			externalIPStr = strings.Join(finding.ExternalIPs, ",")
		} else if len(finding.LoadBalancerIPs) > 0 {
			externalIPStr = strings.Join(finding.LoadBalancerIPs, ",")
		}

		outputRows = append(outputRows, []string{
			fmt.Sprintf("%d", finding.AttackSurface),
			svc.Namespace,
			svc.Name,
			finding.Type,
			exposureStr,
			fmt.Sprintf("%d", finding.BackendPodCount),
			fmt.Sprintf("%d", finding.PrivilegedBackends),
			fmt.Sprintf("%d", len(finding.DangerousPorts)),
			tlsStr,
			netpolStr,
			ingressStr,
			externalIPStr,
			fmt.Sprintf("%d", len(finding.SecurityIssues)),
		})

		// Generate loot content using builder
		generateServiceLootContent(&finding, loot)
	}

	// Sort findings by attack surface (descending)
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].AttackSurface > findings[j].AttackSurface
	})

	// Add risk summary to key sections
	if riskCounts.Critical > 0 || riskCounts.High > 0 {
		summary := shared.RiskSummaryLoot(riskCounts)
		loot.Section("Services-ExternalExposure").SetSummary(summary)
		loot.Section("Services-AttackSurface").SetSummary(summary)
	}

	table := internal.TableFile{
		Name:   "Services",
		Header: headers,
		Body:   outputRows,
	}

	// Build loot files from builder
	lootFiles := loot.Build()

	err = internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"Services",
		globals.ClusterName,
		"results",
		ServicesOutput{
			Table: []internal.TableFile{table},
			Loot:  lootFiles,
		},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_SERVICES_MODULE_NAME)
		return
	}

	if len(outputRows) > 0 {
		logger.InfoM(fmt.Sprintf("%d services found | Risk: CRITICAL=%d, HIGH=%d, MEDIUM=%d, LOW=%d",
			len(outputRows),
			riskCounts.Critical, riskCounts.High, riskCounts.Medium, riskCounts.Low),
			globals.K8S_SERVICES_MODULE_NAME)
	} else {
		logger.InfoM("No services found, skipping output file creation", globals.K8S_SERVICES_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_SERVICES_MODULE_NAME), globals.K8S_SERVICES_MODULE_NAME)
}

// ====================
// Helper Functions
// ====================

func getDangerousPort(port int32) *DangerousPort {
	if dp, exists := dangerousPortMap[port]; exists {
		return &dp
	}
	return nil
}

func isTLSPort(port int32) bool {
	return tlsPortMap[port]
}

func isPublicIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false // Invalid IP, treat as non-public
	}

	// Check private IP ranges
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",     // Loopback
		"169.254.0.0/16",  // Link-local
		"::1/128",         // IPv6 loopback
		"fc00::/7",        // IPv6 private
		"fe80::/10",       // IPv6 link-local
	}

	for _, cidr := range privateRanges {
		_, network, _ := net.ParseCIDR(cidr)
		if network != nil && network.Contains(ip) {
			return false
		}
	}
	return true
}

func findIngressesForService(ingresses []networkingv1.Ingress, namespace, serviceName string) []IngressInfo {
	ingressMap := make(map[string]*IngressInfo) // Deduplicate by ingress name

	for _, ing := range ingresses {
		if ing.Namespace != namespace {
			continue
		}

		hasTLS := len(ing.Spec.TLS) > 0
		var matchingHosts []string

		for _, rule := range ing.Spec.Rules {
			if rule.HTTP != nil {
				for _, path := range rule.HTTP.Paths {
					if path.Backend.Service != nil && path.Backend.Service.Name == serviceName {
						if rule.Host != "" && !servicesContains(matchingHosts, rule.Host) {
							matchingHosts = append(matchingHosts, rule.Host)
						}
					}
				}
			}
		}

		if len(matchingHosts) > 0 {
			ingressMap[ing.Name] = &IngressInfo{
				Name:      ing.Name,
				Namespace: ing.Namespace,
				Hosts:     matchingHosts,
				TLS:       hasTLS,
				Rules:     len(ing.Spec.Rules),
			}
		}
	}

	result := make([]IngressInfo, 0, len(ingressMap))
	for _, info := range ingressMap {
		result = append(result, *info)
	}
	return result
}

func findBackendPods(pods []corev1.Pod, namespace string, selector map[string]string) []corev1.Pod {
	var result []corev1.Pod

	if len(selector) == 0 {
		return result
	}

	for _, pod := range pods {
		if pod.Namespace != namespace {
			continue
		}

		if pod.Status.Phase != corev1.PodRunning && pod.Status.Phase != corev1.PodPending {
			continue
		}

		// Check if pod labels match service selector
		matches := true
		for key, value := range selector {
			if pod.Labels[key] != value {
				matches = false
				break
			}
		}

		if matches {
			result = append(result, pod)
		}
	}

	return result
}

func servicesAnalyzeNetworkPolicies(policies []networkingv1.NetworkPolicy, namespace string, selector map[string]string) []NetworkPolicyInfo {
	var result []NetworkPolicyInfo

	if len(selector) == 0 {
		return result
	}

	for _, np := range policies {
		if np.Namespace != namespace {
			continue
		}

		// Empty PodSelector matches all pods in namespace
		if len(np.Spec.PodSelector.MatchLabels) == 0 && len(np.Spec.PodSelector.MatchExpressions) == 0 {
			info := NetworkPolicyInfo{
				Name:            np.Name,
				ProtectsService: true,
			}
			extractAllowedCIDRs(&info, &np)
			result = append(result, info)
			continue
		}

		// Check if all NetworkPolicy selector labels match the service selector
		// The NetworkPolicy applies if all its selector labels exist in the service selector with matching values
		matches := true
		for key, value := range np.Spec.PodSelector.MatchLabels {
			if selector[key] != value {
				matches = false
				break
			}
		}

		if matches {
			info := NetworkPolicyInfo{
				Name:            np.Name,
				ProtectsService: true,
			}
			extractAllowedCIDRs(&info, &np)
			result = append(result, info)
		}
	}

	return result
}

func extractAllowedCIDRs(info *NetworkPolicyInfo, np *networkingv1.NetworkPolicy) {
	// Extract allowed CIDRs from ingress rules
	for _, ingress := range np.Spec.Ingress {
		for _, from := range ingress.From {
			if from.IPBlock != nil {
				info.AllowedCIDRs = append(info.AllowedCIDRs, from.IPBlock.CIDR)
			}
		}
	}

	// Also extract from egress rules
	for _, egress := range np.Spec.Egress {
		for _, to := range egress.To {
			if to.IPBlock != nil {
				info.AllowedCIDRs = append(info.AllowedCIDRs, to.IPBlock.CIDR)
			}
		}
	}
}

func detectSuspiciousAnnotations(annotations map[string]string) []string {
	var suspicious []string

	suspiciousPatterns := []string{
		"external-dns",
		"cert-manager",
		"loadbalancer",
		"ingress",
		"proxy",
	}

	for key, value := range annotations {
		keyLower := strings.ToLower(key)
		valueLower := strings.ToLower(value)

		for _, pattern := range suspiciousPatterns {
			if strings.Contains(keyLower, pattern) || strings.Contains(valueLower, pattern) {
				suspicious = append(suspicious, fmt.Sprintf("%s=%s", key, value))
				break
			}
		}
	}

	return suspicious
}

func calculateServiceRiskScore(finding *ServiceFinding) (string, int) {
	score := 0

	// ExternalName = DNS hijack risk
	if finding.Type == "ExternalName" {
		return "CRITICAL", 95
	}

	// External exposure
	if finding.ExternallyExposed {
		score += 40

		if finding.PublicIP {
			score += 20 // Public IP = internet accessible
		}

		// Exposure method scoring
		if servicesContains(finding.ExposureMethods, "LoadBalancer") {
			score += 30
		}
		if servicesContains(finding.ExposureMethods, "NodePort") {
			score += 25 // NodePort on ALL nodes
		}
		if servicesContains(finding.ExposureMethods, "ExternalIPs") {
			score += 20
		}
	}

	// Dangerous ports
	if len(finding.DangerousPorts) > 0 {
		score += len(finding.DangerousPorts) * 15

		if finding.ExternallyExposed {
			score += 20 // Extra penalty for external dangerous ports
		}
	}

	// Admin ports externally exposed = CRITICAL
	if len(finding.AdminPorts) > 0 && finding.ExternallyExposed {
		score += 30
	}

	// Unencrypted protocols
	if len(finding.UnencryptedPorts) > 0 {
		score += len(finding.UnencryptedPorts) * 10
	}

	// Backend security issues
	if finding.PrivilegedBackends > 0 {
		score += 25
		if finding.ExternallyExposed {
			score += 15 // Externally accessible privileged containers
		}
	}

	if finding.HostNetworkBackends > 0 || finding.HostPIDBackends > 0 {
		score += 20
	}

	// Network policy protection
	if finding.ExternallyExposed && !finding.NetworkPolicyProtected {
		score += 30 // Exposed without network restrictions
	}

	// Unrestricted access
	if finding.UnrestrictedAccess && finding.ExternallyExposed {
		score += 25
	}

	// TLS/encryption
	if finding.ExternallyExposed && !finding.HasTLS && len(finding.TCPPorts) > 0 {
		score += 15 // External without TLS
	}

	// Multiple exposure methods
	if len(finding.ExposureMethods) > 1 {
		score += 10
	}

	// Determine risk level
	if score >= 85 {
		return "CRITICAL", servicesMin(score, 100)
	} else if score >= 60 {
		return "HIGH", score
	} else if score >= 30 {
		return "MEDIUM", score
	}
	return "LOW", score
}

func calculateAttackSurface(finding *ServiceFinding) int {
	// Base: number of ports × number of backend pods
	surface := finding.TotalPorts * finding.BackendPodCount

	// Cap at max int to prevent overflow
	const maxAttackSurface = 1000000

	// Multipliers with overflow protection
	if finding.ExternallyExposed {
		surface = servicesSafeMul(surface, 3, maxAttackSurface)
	}

	if len(finding.DangerousPorts) > 0 {
		surface = servicesSafeMul(surface, 2, maxAttackSurface)
	}

	if finding.PrivilegedBackends > 0 {
		surface = int(float64(surface) * 1.5)
		if surface > maxAttackSurface {
			surface = maxAttackSurface
		}
	}

	if !finding.NetworkPolicyProtected && finding.ExternallyExposed {
		surface = int(float64(surface) * 1.3)
		if surface > maxAttackSurface {
			surface = maxAttackSurface
		}
	}

	return surface
}

func servicesSafeMul(a, b, max int) int {
	// Check for overflow before multiplication
	if a == 0 || b == 0 {
		return 0
	}
	if a > max/b {
		return max
	}
	result := a * b
	if result > max {
		return max
	}
	return result
}

func generateServiceImpactSummary(finding *ServiceFinding) string {
	if finding.Type == "ExternalName" {
		return fmt.Sprintf("DNS hijack risk: points to %s", finding.ExternalName)
	}

	if finding.AttackSurface > 500 {
		return fmt.Sprintf("CRITICAL: %d attack surface (%d ports × %d backends × multipliers)",
			finding.AttackSurface, finding.TotalPorts, finding.BackendPodCount)
	}

	if finding.ExternallyExposed && len(finding.DangerousPorts) > 0 {
		return fmt.Sprintf("Exposes %d dangerous ports externally", len(finding.DangerousPorts))
	}

	if finding.ExternallyExposed {
		return fmt.Sprintf("Externally exposed via %s", strings.Join(finding.ExposureMethods, ","))
	}

	if finding.IsHeadless {
		return "Headless service (DNS-based load balancing)"
	}

	return fmt.Sprintf("%d backend pods", finding.BackendPodCount)
}

func generateServiceLootContent(finding *ServiceFinding, loot *shared.LootBuilder) {
	ns := finding.Namespace
	name := finding.Name

	// Enumeration
	loot.Section("Services-Enum").
		Addf("\n# [%s] Service: %s/%s", finding.RiskLevel, ns, name).
		Addf("# Type: %s | Attack Surface: %d | Backends: %d", finding.Type, finding.AttackSurface, finding.BackendPodCount).
		Addf("kubectl get svc %s -n %s -o yaml", name, ns).
		Addf("kubectl describe svc %s -n %s", name, ns)

	// TCP port-forward
	tcp := loot.Section("Services-TCP")
	for _, port := range finding.TCPPorts {
		tcp.Addf("\n# [%s] %s/%s - Port %d", finding.RiskLevel, ns, name, port).
			Addf("kubectl -n %s port-forward svc/%s %d:%d", ns, name, port, port)
	}

	// UDP access
	udp := loot.Section("Services-UDP")
	for _, port := range finding.UDPPorts {
		udp.Addf("\n# [%s] %s/%s - UDP Port %d", finding.RiskLevel, ns, name, port).
			Add("# UDP requires pod with socat or nc").
			Add("kubectl run udp-test --image=alpine --rm -it -- sh")
	}

	// External exposure
	if finding.ExternallyExposed {
		ext := loot.Section("Services-ExternalExposure")
		ext.Addf("\n### [%s] %s/%s", finding.RiskLevel, ns, name).
			Addf("# Type: %s | Exposure: %s", finding.Type, strings.Join(finding.ExposureMethods, ",")).
			Addf("# Attack Surface: %d | Backends: %d", finding.AttackSurface, finding.BackendPodCount)
		if len(finding.LoadBalancerIPs) > 0 {
			ext.Addf("# LoadBalancer IPs: %s", strings.Join(finding.LoadBalancerIPs, ", "))
		}
		if len(finding.ExternalIPs) > 0 {
			ext.Addf("# External IPs: %s", strings.Join(finding.ExternalIPs, ", "))
		}
		if len(finding.NodePorts) > 0 {
			ext.Addf("# NodePorts: %v (accessible on ALL nodes)", finding.NodePorts)
		}
	}

	// Dangerous ports
	if len(finding.DangerousPorts) > 0 {
		dp := loot.Section("Services-DangerousPorts")
		dp.Addf("\n### [%s] %s/%s - %d Dangerous Ports", finding.RiskLevel, ns, name, len(finding.DangerousPorts)).
			Addf("# Exposed: %v | Protected: %v", finding.ExternallyExposed, finding.NetworkPolicyProtected)
		for _, port := range finding.DangerousPorts {
			dp.Addf("# - %s", port)
		}
		dp.Addf("kubectl -n %s port-forward svc/%s <port>:<port>", ns, name)
	}

	// LoadBalancers
	if finding.LoadBalancerCost {
		loot.Section("Services-LoadBalancers").
			Addf("\n### %s/%s - LoadBalancer Service", ns, name).
			Addf("# IPs: %s", strings.Join(finding.LoadBalancerIPs, ", ")).
			Add("# Cost: Cloud provider charges apply").
			Add("# Alternative: Use Ingress controller instead")
	}

	// NodePorts
	if len(finding.NodePorts) > 0 {
		loot.Section("Services-NodePorts").
			Addf("\n### [%s] %s/%s - NodePort Service", finding.RiskLevel, ns, name).
			Addf("# NodePorts: %v", finding.NodePorts).
			Add("# Risk: Accessible on ALL cluster nodes").
			Addf("# Access: <any-node-ip>:%d", finding.NodePorts[0])
	}

	// Unprotected
	if finding.UnrestrictedAccess && finding.ExternallyExposed {
		loot.Section("Services-Unprotected").
			Addf("\n### [%s] %s/%s - No NetworkPolicy", finding.RiskLevel, ns, name).
			Add("# Risk: Unrestricted pod-to-pod access").
			Addf("# Backends: %d pods without network restrictions", finding.BackendPodCount).
			Add("# Remediation: Create NetworkPolicy to restrict ingress")
	}

	// Ingress
	if finding.IngressCount > 0 {
		ing := loot.Section("Services-Ingress")
		ing.Addf("\n### %s/%s - %d Ingress Resources", ns, name, finding.IngressCount).
			Addf("# Ingresses: %s", strings.Join(finding.IngressNames, ", ")).
			Addf("# TLS: %v", finding.HasTLS)
		for _, ingName := range finding.IngressNames {
			ing.Addf("kubectl get ingress %s -n %s -o yaml", ingName, ns)
		}
	}

	// Attack surface
	if finding.AttackSurface > 100 {
		loot.Section("Services-AttackSurface").
			Addf("\n### Attack Surface: %d - %s/%s", finding.AttackSurface, ns, name).
			Addf("# Calculation: %d ports × %d backends × multipliers = %d", finding.TotalPorts, finding.BackendPodCount, finding.AttackSurface).
			Addf("# External: %v | Dangerous Ports: %d | Privileged: %d", finding.ExternallyExposed, len(finding.DangerousPorts), finding.PrivilegedBackends).
			Addf("# Impact: %s", finding.ImpactSummary)
	}

	// Remediation
	if len(finding.SecurityIssues) > 0 {
		rem := loot.Section("Services-Remediation")
		rem.Addf("\n### %s/%s - %d Security Issues", ns, name, len(finding.SecurityIssues))
		for _, issue := range finding.SecurityIssues {
			rem.Addf("# - %s", issue)
		}
		rem.Add("# Remediation steps:")
		if finding.ExternallyExposed && !finding.NetworkPolicyProtected {
			rem.Addf("# 1. Create NetworkPolicy for %s/%s", ns, name)
		}
		if !finding.HasTLS && finding.ExternallyExposed {
			rem.Add("# 2. Enable TLS/HTTPS encryption")
		}
		if len(finding.DangerousPorts) > 0 {
			rem.Add("# 3. Review dangerous port exposure")
		}
		if finding.LoadBalancerCost {
			rem.Add("# 4. Consider migrating to Ingress")
		}
	}
}

func servicesContains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func servicesMin(a, b int) int {
	if a < b {
		return a
	}
	return b
}
