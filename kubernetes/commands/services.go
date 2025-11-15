package commands

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	k8sinternal "github.com/BishopFox/cloudfox/internal/kubernetes"
	"github.com/BishopFox/cloudfox/kubernetes/config"
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
	ctx := context.Background()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating services for %s", globals.ClusterName), globals.K8S_SERVICES_MODULE_NAME)

	clientset := config.GetClientOrExit()

	svcClient := clientset.CoreV1().Services("")
	endpointsClient := clientset.CoreV1().Endpoints("")
	podClient := clientset.CoreV1().Pods("")

	services, err := svcClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error retrieving services: %v", err), globals.K8S_SERVICES_MODULE_NAME)
		return
	}

	// Get all Ingresses for correlation
	allIngresses, err := clientset.NetworkingV1().Ingresses("").List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Warning: Could not list ingresses: %v", err), globals.K8S_SERVICES_MODULE_NAME)
		allIngresses = &networkingv1.IngressList{}
	}

	// Get all NetworkPolicies
	allNetworkPolicies, err := clientset.NetworkingV1().NetworkPolicies("").List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Warning: Could not list network policies: %v", err), globals.K8S_SERVICES_MODULE_NAME)
		allNetworkPolicies = &networkingv1.NetworkPolicyList{}
	}

	// Get all Pods for backend analysis
	allPods, err := podClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Warning: Could not list pods: %v", err), globals.K8S_SERVICES_MODULE_NAME)
		allPods = &corev1.PodList{}
	}

	headers := []string{
		"Risk",
		"Score",
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

	// Risk counters
	riskCounts := map[string]int{
		"CRITICAL": 0,
		"HIGH":     0,
		"MEDIUM":   0,
		"LOW":      0,
	}

	var lootEnum []string
	var lootTCP []string
	var lootUDP []string
	var lootExternalExposure []string
	var lootDangerousPorts []string
	var lootLoadBalancers []string
	var lootNodePorts []string
	var lootUnprotected []string
	var lootIngress []string
	var lootAttackSurface []string
	var lootRemediation []string

	lootEnum = append(lootEnum, `#####################################
##### Service Enumeration
#####################################
#
# Complete service inventory with security analysis
#
`)

	lootTCP = append(lootTCP, `#####################################
##### TCP Service Port-Forward Commands
#####################################
#
# Port-forward to access internal services
#
`)

	lootUDP = append(lootUDP, `#####################################
##### UDP Service Access Commands
#####################################
#
# UDP services require special handling
#
`)

	lootExternalExposure = append(lootExternalExposure, `#####################################
##### Externally Exposed Services
#####################################
#
# Services accessible from outside the cluster
# CRITICAL: Review and minimize external exposure
#
`)

	lootDangerousPorts = append(lootDangerousPorts, `#####################################
##### Dangerous Port Exposure
#####################################
#
# Services exposing administrative, database, or unencrypted protocols
# HIGH RISK: These ports should not be publicly accessible
#
`)

	lootLoadBalancers = append(lootLoadBalancers, `#####################################
##### LoadBalancer Services
#####################################
#
# LoadBalancer services incur cloud provider costs
# Review for necessity and security
#
`)

	lootNodePorts = append(lootNodePorts, `#####################################
##### NodePort Services
#####################################
#
# NodePort services expose on ALL cluster nodes
# Risk: Bypass ingress controls, direct node access
#
`)

	lootUnprotected = append(lootUnprotected, `#####################################
##### Services Without Network Policies
#####################################
#
# Services lacking NetworkPolicy protection
# RISK: Unrestricted pod-to-pod access
#
`)

	lootIngress = append(lootIngress, `#####################################
##### Ingress-Exposed Services
#####################################
#
# Services exposed via Ingress resources
# Review TLS, authentication, and host configurations
#
`)

	lootAttackSurface = append(lootAttackSurface, `#####################################
##### Attack Surface Analysis
#####################################
#
# Services ranked by attack surface (ports × backends × exposure)
# Prioritize highest attack surface for security review
#
`)

	lootRemediation = append(lootRemediation, `#####################################
##### Security Remediation Recommendations
#####################################
#
# Step-by-step fixes for identified security issues
#
`)

	if globals.KubeContext != "" {
		lootEnum = append(lootEnum, fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext))
		lootTCP = append(lootTCP, fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext))
		lootUDP = append(lootUDP, fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext))
	}

	for _, svc := range services.Items {
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
		ep, err := endpointsClient.Get(ctx, svc.Name, metav1.GetOptions{Namespace: svc.Namespace})
		if err == nil {
			for _, subset := range ep.Subsets {
				finding.EndpointCount += len(subset.Addresses)
			}
		}

		// Backend pod security analysis
		backendPods := findBackendPods(allPods.Items, svc.Namespace, svc.Spec.Selector)
		finding.BackendPodCount = len(backendPods)
		for _, pod := range backendPods {
			finding.BackendPods = append(finding.BackendPods, pod.Name)

			// Check for privileged containers
			for _, container := range pod.Spec.Containers {
				if container.SecurityContext != nil &&
					container.SecurityContext.Privileged != nil &&
					*container.SecurityContext.Privileged {
					finding.PrivilegedBackends++
					break
				}
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
			netpolInfo := analyzeNetworkPolicies(allNetworkPolicies.Items, svc.Namespace, svc.Spec.Selector)
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

		riskCounts[finding.RiskLevel]++
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
			finding.RiskLevel,
			fmt.Sprintf("%d", finding.RiskScore),
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

		// Generate loot content
		generateServiceLootContent(&finding, &lootEnum, &lootTCP, &lootUDP,
			&lootExternalExposure, &lootDangerousPorts, &lootLoadBalancers,
			&lootNodePorts, &lootUnprotected, &lootIngress,
			&lootAttackSurface, &lootRemediation)
	}

	// Sort findings by attack surface (descending)
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].AttackSurface > findings[j].AttackSurface
	})

	// Add summaries
	if riskCounts["CRITICAL"] > 0 || riskCounts["HIGH"] > 0 {
		summary := fmt.Sprintf(`
# SUMMARY: Risk Distribution
# CRITICAL: %d services
# HIGH: %d services
# MEDIUM: %d services
# LOW: %d services
#
# Focus on externally exposed services with dangerous ports.
# Prioritize by attack surface for efficient security review.
`, riskCounts["CRITICAL"], riskCounts["HIGH"], riskCounts["MEDIUM"], riskCounts["LOW"])

		lootExternalExposure = append([]string{summary}, lootExternalExposure...)
		lootAttackSurface = append([]string{summary}, lootAttackSurface...)
	}

	table := internal.TableFile{
		Name:   "Services",
		Header: headers,
		Body:   outputRows,
	}

	lootFiles := []internal.LootFile{
		{
			Name:     "Services-Enum",
			Contents: strings.Join(lootEnum, "\n"),
		},
		{
			Name:     "Services-PortForward-TCP",
			Contents: strings.Join(lootTCP, "\n"),
		},
		{
			Name:     "Services-PortForward-UDP",
			Contents: strings.Join(lootUDP, "\n"),
		},
		{
			Name:     "Services-External-Exposure",
			Contents: strings.Join(lootExternalExposure, "\n"),
		},
		{
			Name:     "Services-Dangerous-Ports",
			Contents: strings.Join(lootDangerousPorts, "\n"),
		},
		{
			Name:     "Services-LoadBalancers",
			Contents: strings.Join(lootLoadBalancers, "\n"),
		},
		{
			Name:     "Services-NodePorts",
			Contents: strings.Join(lootNodePorts, "\n"),
		},
		{
			Name:     "Services-Unprotected",
			Contents: strings.Join(lootUnprotected, "\n"),
		},
		{
			Name:     "Services-Ingress",
			Contents: strings.Join(lootIngress, "\n"),
		},
		{
			Name:     "Services-Attack-Surface",
			Contents: strings.Join(lootAttackSurface, "\n"),
		},
		{
			Name:     "Services-Remediation",
			Contents: strings.Join(lootRemediation, "\n"),
		},
	}

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
			riskCounts["CRITICAL"], riskCounts["HIGH"], riskCounts["MEDIUM"], riskCounts["LOW"]),
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
	dangerousPorts := map[int32]DangerousPort{
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

	if dp, exists := dangerousPorts[port]; exists {
		return &dp
	}
	return nil
}

func isTLSPort(port int32) bool {
	tlsPorts := map[int32]bool{
		443:   true,  // HTTPS
		8443:  true,  // HTTPS alternative
		6443:  true,  // Kubernetes API
		9443:  true,  // Alternative HTTPS
		10250: false, // Kubelet (can be TLS but often not verified)
	}

	return tlsPorts[port]
}

func isPublicIP(ip string) bool {
	// Simple check - could be enhanced with actual IP parsing
	// This is a simplified version
	if strings.HasPrefix(ip, "10.") ||
		strings.HasPrefix(ip, "192.168.") ||
		strings.HasPrefix(ip, "172.16.") ||
		strings.HasPrefix(ip, "172.17.") ||
		strings.HasPrefix(ip, "172.18.") ||
		strings.HasPrefix(ip, "172.19.") ||
		strings.HasPrefix(ip, "172.20.") ||
		strings.HasPrefix(ip, "172.21.") ||
		strings.HasPrefix(ip, "172.22.") ||
		strings.HasPrefix(ip, "172.23.") ||
		strings.HasPrefix(ip, "172.24.") ||
		strings.HasPrefix(ip, "172.25.") ||
		strings.HasPrefix(ip, "172.26.") ||
		strings.HasPrefix(ip, "172.27.") ||
		strings.HasPrefix(ip, "172.28.") ||
		strings.HasPrefix(ip, "172.29.") ||
		strings.HasPrefix(ip, "172.30.") ||
		strings.HasPrefix(ip, "172.31.") ||
		strings.HasPrefix(ip, "127.") {
		return false
	}
	return true
}

func findIngressesForService(ingresses *networkingv1.IngressList, namespace, serviceName string) []IngressInfo {
	var result []IngressInfo

	for _, ing := range ingresses.Items {
		if ing.Namespace != namespace {
			continue
		}

		hasTLS := len(ing.Spec.TLS) > 0
		var hosts []string

		for _, rule := range ing.Spec.Rules {
			if rule.HTTP != nil {
				for _, path := range rule.HTTP.Paths {
					if path.Backend.Service != nil && path.Backend.Service.Name == serviceName {
						hosts = append(hosts, rule.Host)
						result = append(result, IngressInfo{
							Name:      ing.Name,
							Namespace: ing.Namespace,
							Hosts:     []string{rule.Host},
							TLS:       hasTLS,
							Rules:     len(ing.Spec.Rules),
						})
					}
				}
			}
		}
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

func analyzeNetworkPolicies(policies []networkingv1.NetworkPolicy, namespace string, selector map[string]string) []NetworkPolicyInfo {
	var result []NetworkPolicyInfo

	if len(selector) == 0 {
		return result
	}

	for _, np := range policies {
		if np.Namespace != namespace {
			continue
		}

		// Check if NetworkPolicy applies to this service's pods
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

			// Extract allowed CIDRs
			for _, ingress := range np.Spec.Ingress {
				for _, from := range ingress.From {
					if from.IPBlock != nil {
						info.AllowedCIDRs = append(info.AllowedCIDRs, from.IPBlock.CIDR)
					}
				}
			}

			result = append(result, info)
		}
	}

	return result
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
		if contains(finding.ExposureMethods, "LoadBalancer") {
			score += 30
		}
		if contains(finding.ExposureMethods, "NodePort") {
			score += 25 // NodePort on ALL nodes
		}
		if contains(finding.ExposureMethods, "ExternalIPs") {
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
		return "CRITICAL", min(score, 100)
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

	// Multipliers
	if finding.ExternallyExposed {
		surface = surface * 3
	}

	if len(finding.DangerousPorts) > 0 {
		surface = surface * 2
	}

	if finding.PrivilegedBackends > 0 {
		surface = int(float64(surface) * 1.5)
	}

	if !finding.NetworkPolicyProtected && finding.ExternallyExposed {
		surface = int(float64(surface) * 1.3)
	}

	return surface
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

func generateServiceLootContent(finding *ServiceFinding,
	lootEnum, lootTCP, lootUDP, lootExternalExposure, lootDangerousPorts,
	lootLoadBalancers, lootNodePorts, lootUnprotected, lootIngress,
	lootAttackSurface, lootRemediation *[]string) {

	ns := finding.Namespace
	name := finding.Name

	// Enumeration
	*lootEnum = append(*lootEnum, fmt.Sprintf("\n# [%s] Service: %s/%s", finding.RiskLevel, ns, name))
	*lootEnum = append(*lootEnum, fmt.Sprintf("# Type: %s | Attack Surface: %d | Backends: %d",
		finding.Type, finding.AttackSurface, finding.BackendPodCount))
	*lootEnum = append(*lootEnum, fmt.Sprintf("kubectl get svc %s -n %s -o yaml", name, ns))
	*lootEnum = append(*lootEnum, fmt.Sprintf("kubectl describe svc %s -n %s", name, ns))
	*lootEnum = append(*lootEnum, "")

	// TCP port-forward
	for _, port := range finding.TCPPorts {
		*lootTCP = append(*lootTCP, fmt.Sprintf("\n# [%s] %s/%s - Port %d",
			finding.RiskLevel, ns, name, port))
		*lootTCP = append(*lootTCP, fmt.Sprintf("kubectl -n %s port-forward svc/%s %d:%d",
			ns, name, port, port))
	}

	// UDP access
	for _, port := range finding.UDPPorts {
		*lootUDP = append(*lootUDP, fmt.Sprintf("\n# [%s] %s/%s - UDP Port %d",
			finding.RiskLevel, ns, name, port))
		*lootUDP = append(*lootUDP, fmt.Sprintf("# UDP requires pod with socat or nc"))
		*lootUDP = append(*lootUDP, fmt.Sprintf("kubectl run udp-test --image=alpine --rm -it -- sh"))
	}

	// External exposure
	if finding.ExternallyExposed {
		*lootExternalExposure = append(*lootExternalExposure, fmt.Sprintf("\n### [%s] %s/%s",
			finding.RiskLevel, ns, name))
		*lootExternalExposure = append(*lootExternalExposure, fmt.Sprintf("# Type: %s | Exposure: %s",
			finding.Type, strings.Join(finding.ExposureMethods, ",")))
		*lootExternalExposure = append(*lootExternalExposure, fmt.Sprintf("# Attack Surface: %d | Backends: %d",
			finding.AttackSurface, finding.BackendPodCount))

		if len(finding.LoadBalancerIPs) > 0 {
			*lootExternalExposure = append(*lootExternalExposure, fmt.Sprintf("# LoadBalancer IPs: %s",
				strings.Join(finding.LoadBalancerIPs, ", ")))
		}
		if len(finding.ExternalIPs) > 0 {
			*lootExternalExposure = append(*lootExternalExposure, fmt.Sprintf("# External IPs: %s",
				strings.Join(finding.ExternalIPs, ", ")))
		}
		if len(finding.NodePorts) > 0 {
			*lootExternalExposure = append(*lootExternalExposure, fmt.Sprintf("# NodePorts: %v (accessible on ALL nodes)",
				finding.NodePorts))
		}
		*lootExternalExposure = append(*lootExternalExposure, "")
	}

	// Dangerous ports
	if len(finding.DangerousPorts) > 0 {
		*lootDangerousPorts = append(*lootDangerousPorts, fmt.Sprintf("\n### [%s] %s/%s - %d Dangerous Ports",
			finding.RiskLevel, ns, name, len(finding.DangerousPorts)))
		*lootDangerousPorts = append(*lootDangerousPorts, fmt.Sprintf("# Exposed: %v | Protected: %v",
			finding.ExternallyExposed, finding.NetworkPolicyProtected))
		for _, port := range finding.DangerousPorts {
			*lootDangerousPorts = append(*lootDangerousPorts, fmt.Sprintf("# - %s", port))
		}
		*lootDangerousPorts = append(*lootDangerousPorts, fmt.Sprintf("kubectl -n %s port-forward svc/%s <port>:<port>", ns, name))
		*lootDangerousPorts = append(*lootDangerousPorts, "")
	}

	// LoadBalancers
	if finding.LoadBalancerCost {
		*lootLoadBalancers = append(*lootLoadBalancers, fmt.Sprintf("\n### %s/%s - LoadBalancer Service",
			ns, name))
		*lootLoadBalancers = append(*lootLoadBalancers, fmt.Sprintf("# IPs: %s",
			strings.Join(finding.LoadBalancerIPs, ", ")))
		*lootLoadBalancers = append(*lootLoadBalancers, fmt.Sprintf("# Cost: Cloud provider charges apply"))
		*lootLoadBalancers = append(*lootLoadBalancers, fmt.Sprintf("# Alternative: Use Ingress controller instead"))
		*lootLoadBalancers = append(*lootLoadBalancers, "")
	}

	// NodePorts
	if len(finding.NodePorts) > 0 {
		*lootNodePorts = append(*lootNodePorts, fmt.Sprintf("\n### [%s] %s/%s - NodePort Service",
			finding.RiskLevel, ns, name))
		*lootNodePorts = append(*lootNodePorts, fmt.Sprintf("# NodePorts: %v", finding.NodePorts))
		*lootNodePorts = append(*lootNodePorts, fmt.Sprintf("# Risk: Accessible on ALL cluster nodes"))
		*lootNodePorts = append(*lootNodePorts, fmt.Sprintf("# Access: <any-node-ip>:%d", finding.NodePorts[0]))
		*lootNodePorts = append(*lootNodePorts, "")
	}

	// Unprotected
	if finding.UnrestrictedAccess && finding.ExternallyExposed {
		*lootUnprotected = append(*lootUnprotected, fmt.Sprintf("\n### [%s] %s/%s - No NetworkPolicy",
			finding.RiskLevel, ns, name))
		*lootUnprotected = append(*lootUnprotected, fmt.Sprintf("# Risk: Unrestricted pod-to-pod access"))
		*lootUnprotected = append(*lootUnprotected, fmt.Sprintf("# Backends: %d pods without network restrictions",
			finding.BackendPodCount))
		*lootUnprotected = append(*lootUnprotected, "# Remediation: Create NetworkPolicy to restrict ingress")
		*lootUnprotected = append(*lootUnprotected, "")
	}

	// Ingress
	if finding.IngressCount > 0 {
		*lootIngress = append(*lootIngress, fmt.Sprintf("\n### %s/%s - %d Ingress Resources",
			ns, name, finding.IngressCount))
		*lootIngress = append(*lootIngress, fmt.Sprintf("# Ingresses: %s",
			strings.Join(finding.IngressNames, ", ")))
		*lootIngress = append(*lootIngress, fmt.Sprintf("# TLS: %v", finding.HasTLS))
		for _, ingName := range finding.IngressNames {
			*lootIngress = append(*lootIngress, fmt.Sprintf("kubectl get ingress %s -n %s -o yaml", ingName, ns))
		}
		*lootIngress = append(*lootIngress, "")
	}

	// Attack surface
	if finding.AttackSurface > 100 {
		*lootAttackSurface = append(*lootAttackSurface, fmt.Sprintf("\n### Attack Surface: %d - %s/%s",
			finding.AttackSurface, ns, name))
		*lootAttackSurface = append(*lootAttackSurface, fmt.Sprintf("# Calculation: %d ports × %d backends × multipliers = %d",
			finding.TotalPorts, finding.BackendPodCount, finding.AttackSurface))
		*lootAttackSurface = append(*lootAttackSurface, fmt.Sprintf("# External: %v | Dangerous Ports: %d | Privileged: %d",
			finding.ExternallyExposed, len(finding.DangerousPorts), finding.PrivilegedBackends))
		*lootAttackSurface = append(*lootAttackSurface, fmt.Sprintf("# Impact: %s", finding.ImpactSummary))
		*lootAttackSurface = append(*lootAttackSurface, "")
	}

	// Remediation
	if len(finding.SecurityIssues) > 0 {
		*lootRemediation = append(*lootRemediation, fmt.Sprintf("\n### %s/%s - %d Security Issues",
			ns, name, len(finding.SecurityIssues)))
		for _, issue := range finding.SecurityIssues {
			*lootRemediation = append(*lootRemediation, fmt.Sprintf("# - %s", issue))
		}
		*lootRemediation = append(*lootRemediation, "# Remediation steps:")

		if finding.ExternallyExposed && !finding.NetworkPolicyProtected {
			*lootRemediation = append(*lootRemediation, fmt.Sprintf("# 1. Create NetworkPolicy for %s/%s", ns, name))
		}
		if !finding.HasTLS && finding.ExternallyExposed {
			*lootRemediation = append(*lootRemediation, "# 2. Enable TLS/HTTPS encryption")
		}
		if len(finding.DangerousPorts) > 0 {
			*lootRemediation = append(*lootRemediation, "# 3. Review dangerous port exposure, restrict or disable")
		}
		if finding.LoadBalancerCost {
			*lootRemediation = append(*lootRemediation, "# 4. Consider migrating to Ingress to reduce costs")
		}
		*lootRemediation = append(*lootRemediation, "")
	}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func parseInt32(s string) int32 {
	i, _ := strconv.ParseInt(s, 10, 32)
	return int32(i)
}
