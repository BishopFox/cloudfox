package commands

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	k8sinternal "github.com/BishopFox/cloudfox/internal/kubernetes"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
)

var NetworkExposureCmd = &cobra.Command{
	Use:     "network-exposure",
	Aliases: []string{"net-ports"},
	Short:   "Enumerate cluster exposed network ports with comprehensive security analysis",
	Long: `
Enumerate cluster exposed network hosts and ports with risk-based security analysis:
  cloudfox kubernetes network-exposure

This command analyzes:
- LoadBalancer services (internet-facing exposure)
- NodePort services (exposed on all nodes)
- ExternalIP services
- HostPort pods (bypass NetworkPolicy)
- Ingress resources
- Backend workload security
- Dangerous port detection (SSH, RDP, databases, Kubelet API, etc.)
- Attack path visualization`,
	Run: NetworkExposure,
}

// NetworkExposureFinding represents a comprehensive network exposure with security analysis
type NetworkExposureFinding struct {
	// Basic info
	Namespace    string
	ResourceType string
	ResourceName string
	ExposureType string // "LoadBalancer", "NodePort", "ExternalIP", "Ingress", "HostNetwork", "HostPort"

	// Network details
	IPAddress  string
	Hostname   string
	Port       int32
	TargetPort string
	NodePort   int32
	Protocol   string

	// Security analysis
	RiskLevel        string // CRITICAL/HIGH/MEDIUM/LOW
	SecurityIssues   []string
	IsDangerousPort  bool
	PortCategory     string // "SSH", "RDP", "Database", "Admin", "Web", "Kubernetes", "Custom"
	PortDescription  string
	IsInternetFacing bool
	CloudProvider    string // "AWS", "Azure", "GCP", "Unknown"

	// Service details (if applicable)
	ServiceType           string // LoadBalancer, NodePort, ClusterIP, ExternalName
	Selector              string
	SessionAffinity       string
	ExternalTrafficPolicy string
	ExternalName          string // For ExternalName services

	// Backend workload security
	BackendPods           int
	BackendDeployment     string
	BackendPrivileged     bool
	BackendHostNetwork    bool
	BackendServiceAccount string
	BackendSecurityLevel  string // "Secure", "Vulnerable", "Unknown"
	BackendSecurityIssues []string

	// Network policy
	HasNetworkPolicy bool
	NetworkPolicies  []string
	IsIsolated       bool

	// Attack surface
	AttackVector       string // "Internet -> Service -> Pod -> Host"
	ExposedWorkloads   []string
	CredentialExposure bool
	DataExposureRisk   string // "Database", "Admin Panel", "Metrics", "Secrets", "None"

	// Annotations
	DangerousAnnotations []string
	AnnotationIssues     []string
}

// PortInfo describes security characteristics of a port
type PortInfo struct {
	Category    string
	Risk        string
	Description string
}

// BackendSecurityInfo contains security analysis of backend workloads
type BackendSecurityInfo struct {
	ServiceName      string
	Namespace        string
	SecurityLevel    string // "Secure", "Vulnerable", "Unknown"
	PodCount         int
	Deployment       string
	ServiceAccount   string
	HasNetworkPolicy bool
	Privileged       bool
	HostNetwork      bool
	SecurityIssues   []string
	Workloads        []string
}

// Dangerous port database
var networkExposureDangerousPorts = map[int32]PortInfo{
	// Remote access (CRITICAL)
	22:   {Category: "SSH", Risk: "CRITICAL", Description: "SSH remote access"},
	23:   {Category: "Telnet", Risk: "CRITICAL", Description: "Unencrypted remote access (Telnet)"},
	3389: {Category: "RDP", Risk: "CRITICAL", Description: "Windows Remote Desktop (RDP)"},
	5900: {Category: "VNC", Risk: "CRITICAL", Description: "VNC remote desktop"},
	5901: {Category: "VNC", Risk: "CRITICAL", Description: "VNC remote desktop (alt)"},

	// Kubernetes components (CRITICAL)
	6443:  {Category: "Kubernetes", Risk: "CRITICAL", Description: "Kubernetes API server"},
	10250: {Category: "Kubernetes", Risk: "CRITICAL", Description: "Kubelet API (unauthenticated RCE risk)"},
	10255: {Category: "Kubernetes", Risk: "HIGH", Description: "Kubelet read-only port"},
	2379:  {Category: "Kubernetes", Risk: "CRITICAL", Description: "etcd client API (cluster secrets)"},
	2380:  {Category: "Kubernetes", Risk: "CRITICAL", Description: "etcd peer API"},

	// Databases (HIGH)
	3306:  {Category: "Database", Risk: "HIGH", Description: "MySQL/MariaDB database"},
	5432:  {Category: "Database", Risk: "HIGH", Description: "PostgreSQL database"},
	1433:  {Category: "Database", Risk: "HIGH", Description: "Microsoft SQL Server"},
	1521:  {Category: "Database", Risk: "HIGH", Description: "Oracle database"},
	27017: {Category: "Database", Risk: "HIGH", Description: "MongoDB database"},
	27018: {Category: "Database", Risk: "HIGH", Description: "MongoDB shard server"},
	6379:  {Category: "Database", Risk: "HIGH", Description: "Redis key-value store"},
	9200:  {Category: "Database", Risk: "HIGH", Description: "Elasticsearch"},
	9300:  {Category: "Database", Risk: "HIGH", Description: "Elasticsearch cluster"},
	5984:  {Category: "Database", Risk: "HIGH", Description: "CouchDB"},
	8086:  {Category: "Database", Risk: "HIGH", Description: "InfluxDB"},
	7000:  {Category: "Database", Risk: "HIGH", Description: "Cassandra"},
	7001:  {Category: "Database", Risk: "HIGH", Description: "Cassandra SSL"},

	// Admin/Management (HIGH)
	8080: {Category: "Admin", Risk: "HIGH", Description: "Common admin panel/management"},
	8443: {Category: "Admin", Risk: "HIGH", Description: "Admin panel (HTTPS)"},
	9090: {Category: "Admin", Risk: "MEDIUM", Description: "Prometheus metrics"},
	9093: {Category: "Admin", Risk: "MEDIUM", Description: "Prometheus Alertmanager"},
	3000: {Category: "Admin", Risk: "MEDIUM", Description: "Grafana dashboards"},
	9000: {Category: "Admin", Risk: "MEDIUM", Description: "SonarQube/Portainer"},
	8081: {Category: "Admin", Risk: "MEDIUM", Description: "Common admin panel (alt)"},
	8888: {Category: "Admin", Risk: "MEDIUM", Description: "Jupyter/admin panel"},
	5000: {Category: "Admin", Risk: "MEDIUM", Description: "Docker Registry/Flask"},
	5001: {Category: "Admin", Risk: "MEDIUM", Description: "Docker Registry (alt)"},

	// Message queues (MEDIUM)
	5672:  {Category: "MessageQueue", Risk: "MEDIUM", Description: "RabbitMQ"},
	15672: {Category: "MessageQueue", Risk: "MEDIUM", Description: "RabbitMQ Management"},
	9092:  {Category: "MessageQueue", Risk: "MEDIUM", Description: "Kafka"},
	4222:  {Category: "MessageQueue", Risk: "MEDIUM", Description: "NATS"},

	// Web services
	80:   {Category: "Web", Risk: "MEDIUM", Description: "HTTP web service"},
	443:  {Category: "Web", Risk: "LOW", Description: "HTTPS web service"},
	8000: {Category: "Web", Risk: "MEDIUM", Description: "HTTP web service (alt)"},
}

// Dangerous service annotations by cloud provider
var dangerousServiceAnnotations = []struct {
	key         string
	risk        string
	description string
}{
	// AWS
	{"service.beta.kubernetes.io/aws-load-balancer-internal", "MEDIUM", "If 'false' or missing, creates internet-facing LB"},
	{"service.beta.kubernetes.io/aws-load-balancer-scheme", "MEDIUM", "internet-facing vs internal"},
	{"service.beta.kubernetes.io/aws-load-balancer-ssl-cert", "INFO", "SSL certificate ARN"},
	{"service.beta.kubernetes.io/aws-load-balancer-backend-protocol", "MEDIUM", "Backend protocol (http/https/tcp/ssl)"},

	// Azure
	{"service.beta.kubernetes.io/azure-load-balancer-internal", "MEDIUM", "If missing, creates public LB"},
	{"service.beta.kubernetes.io/azure-pip-name", "INFO", "Public IP name"},
	{"service.beta.kubernetes.io/azure-dns-label-name", "INFO", "DNS label for public IP"},

	// GCP
	{"cloud.google.com/load-balancer-type", "HIGH", "Internal vs External LB"},
	{"cloud.google.com/neg", "INFO", "Network Endpoint Group"},
	{"networking.gke.io/load-balancer-type", "HIGH", "Internal vs External"},
}

type NetworkExposureOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (n NetworkExposureOutput) TableFiles() []internal.TableFile {
	return n.Table
}

func (n NetworkExposureOutput) LootFiles() []internal.LootFile {
	return n.Loot
}

// analyzePort determines if a port is dangerous and returns its characteristics
func analyzePort(port int32) (bool, string, string, string) {
	if info, found := networkExposureDangerousPorts[port]; found {
		return true, info.Category, info.Risk, info.Description
	}
	return false, "Custom", "LOW", "Custom service"
}

// detectInternetFacing determines if a service is internet-facing
func detectInternetFacing(svc *corev1.Service) (bool, string) {
	// LoadBalancer services are typically internet-facing unless explicitly internal
	if svc.Spec.Type == corev1.ServiceTypeLoadBalancer {
		// Check for internal annotations
		internalAnnotations := map[string][]string{
			"AWS": {
				"service.beta.kubernetes.io/aws-load-balancer-internal",
				"service.beta.kubernetes.io/aws-load-balancer-scheme",
			},
			"Azure": {
				"service.beta.kubernetes.io/azure-load-balancer-internal",
			},
			"GCP": {
				"cloud.google.com/load-balancer-type",
				"networking.gke.io/load-balancer-type",
			},
		}

		for provider, annotations := range internalAnnotations {
			for _, anno := range annotations {
				if val, ok := svc.Annotations[anno]; ok {
					if val == "true" || val == "Internal" || strings.Contains(val, "internal") {
						return false, provider
					}
					// For AWS scheme annotation
					if anno == "service.beta.kubernetes.io/aws-load-balancer-scheme" && val == "internal" {
						return false, "AWS"
					}
				}
			}
		}

		// If no internal annotation found, likely internet-facing
		provider := detectCloudProvider(svc)
		return true, provider
	}

	// ExternalIPs can be internet-facing
	if len(svc.Spec.ExternalIPs) > 0 {
		return true, "ExternalIP"
	}

	// NodePort with public nodes can be internet-facing
	if svc.Spec.Type == corev1.ServiceTypeNodePort {
		return true, "NodePort"
	}

	return false, "Internal"
}

// detectCloudProvider identifies the cloud provider from service annotations
func detectCloudProvider(svc *corev1.Service) string {
	// AWS
	awsAnnotations := []string{
		"service.beta.kubernetes.io/aws-load-balancer-type",
		"service.beta.kubernetes.io/aws-load-balancer-internal",
		"service.beta.kubernetes.io/aws-load-balancer-scheme",
	}
	for _, anno := range awsAnnotations {
		if _, ok := svc.Annotations[anno]; ok {
			return "AWS"
		}
	}

	// Azure
	azureAnnotations := []string{
		"service.beta.kubernetes.io/azure-load-balancer-internal",
		"service.beta.kubernetes.io/azure-pip-name",
		"service.beta.kubernetes.io/azure-dns-label-name",
	}
	for _, anno := range azureAnnotations {
		if _, ok := svc.Annotations[anno]; ok {
			return "Azure"
		}
	}

	// GCP
	gcpAnnotations := []string{
		"cloud.google.com/load-balancer-type",
		"cloud.google.com/neg",
		"networking.gke.io/load-balancer-type",
	}
	for _, anno := range gcpAnnotations {
		if _, ok := svc.Annotations[anno]; ok {
			return "GCP"
		}
	}

	return "Unknown"
}

// analyzeBackendSecurity analyzes security posture of backend workloads
func analyzeNetworkExposureBackendSecurity(ctx context.Context, clientset *kubernetes.Clientset, svc *corev1.Service) BackendSecurityInfo {
	backendInfo := BackendSecurityInfo{
		ServiceName:   svc.Name,
		Namespace:     svc.Namespace,
		SecurityLevel: "Unknown",
	}

	// Check if service has selector
	if len(svc.Spec.Selector) == 0 {
		backendInfo.SecurityIssues = append(backendInfo.SecurityIssues, "No selector - cannot determine backend pods")
		return backendInfo
	}

	// Get pods matching service selector
	labelSelector := labels.Set(svc.Spec.Selector).String()
	pods, err := clientset.CoreV1().Pods(svc.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labelSelector,
	})

	if err != nil || len(pods.Items) == 0 {
		if err != nil {
			backendInfo.SecurityIssues = append(backendInfo.SecurityIssues, fmt.Sprintf("Error listing pods: %v", err))
		} else {
			backendInfo.SecurityIssues = append(backendInfo.SecurityIssues, "No pods match service selector")
		}
		return backendInfo
	}

	backendInfo.PodCount = len(pods.Items)
	vulnerableCount := 0

	// Analyze each pod
	for _, pod := range pods.Items {
		// Collect workload information
		if ownerRef := getOwnerReference(&pod); ownerRef != "" {
			if !networkExposureContains(backendInfo.Workloads, ownerRef) {
				backendInfo.Workloads = append(backendInfo.Workloads, ownerRef)
				if backendInfo.Deployment == "" {
					backendInfo.Deployment = ownerRef
				}
			}
		}

		// Get ServiceAccount
		if backendInfo.ServiceAccount == "" && pod.Spec.ServiceAccountName != "" {
			backendInfo.ServiceAccount = pod.Spec.ServiceAccountName
		}

		// Check for privileged containers
		allContainers := append(pod.Spec.Containers, pod.Spec.InitContainers...)
		for _, c := range allContainers {
			if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
				backendInfo.Privileged = true
				vulnerableCount++
				backendInfo.SecurityIssues = append(backendInfo.SecurityIssues,
					fmt.Sprintf("Pod %s runs privileged container '%s'", pod.Name, c.Name))
			}

			// Check for dangerous capabilities
			if c.SecurityContext != nil && c.SecurityContext.Capabilities != nil {
				for _, cap := range c.SecurityContext.Capabilities.Add {
					if isDangerousCapability(string(cap)) {
						backendInfo.SecurityIssues = append(backendInfo.SecurityIssues,
							fmt.Sprintf("Pod %s has dangerous capability: %s", pod.Name, cap))
						vulnerableCount++
					}
				}
			}
		}

		// Check hostNetwork
		if pod.Spec.HostNetwork {
			backendInfo.HostNetwork = true
			vulnerableCount++
			backendInfo.SecurityIssues = append(backendInfo.SecurityIssues,
				fmt.Sprintf("Pod %s uses hostNetwork", pod.Name))
		}
	}

	// Check NetworkPolicy
	policies, err := clientset.NetworkingV1().NetworkPolicies(svc.Namespace).List(ctx, metav1.ListOptions{})
	if err == nil && len(policies.Items) > 0 {
		backendInfo.HasNetworkPolicy = true
	}

	// Determine security level
	if vulnerableCount > 0 {
		backendInfo.SecurityLevel = "Vulnerable"
	} else if backendInfo.HasNetworkPolicy && backendInfo.ServiceAccount != "default" {
		backendInfo.SecurityLevel = "Secure"
	} else {
		backendInfo.SecurityLevel = "Moderate"
	}

	return backendInfo
}

// getOwnerReference returns a string representation of the pod's owner
func getOwnerReference(pod *corev1.Pod) string {
	if len(pod.OwnerReferences) > 0 {
		owner := pod.OwnerReferences[0]
		return fmt.Sprintf("%s/%s", owner.Kind, owner.Name)
	}
	return ""
}

// isDangerousCapability checks if a capability is dangerous
func isDangerousCapability(cap string) bool {
	dangerousCaps := []string{"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH", "DAC_OVERRIDE"}
	for _, dangerous := range dangerousCaps {
		if cap == dangerous {
			return true
		}
	}
	return false
}

// contains checks if a string slice contains a value
func networkExposureContains(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}

// analyzeServiceAnnotations checks for dangerous or interesting service annotations
func analyzeServiceAnnotations(svc *corev1.Service) ([]string, []string) {
	var issues []string
	var dangerous []string

	for _, anno := range dangerousServiceAnnotations {
		if val, ok := svc.Annotations[anno.key]; ok {
			msg := fmt.Sprintf("[%s] %s = %s: %s", anno.risk, anno.key, val, anno.description)
			issues = append(issues, msg)

			if anno.risk == "HIGH" || anno.risk == "CRITICAL" {
				dangerous = append(dangerous, anno.key)
			}
		}
	}

	// Check for missing internal annotations on LoadBalancer (default = public!)
	if svc.Spec.Type == corev1.ServiceTypeLoadBalancer {
		hasInternalFlag := false
		internalAnnotations := []string{
			"service.beta.kubernetes.io/aws-load-balancer-internal",
			"service.beta.kubernetes.io/azure-load-balancer-internal",
			"cloud.google.com/load-balancer-type",
			"networking.gke.io/load-balancer-type",
		}
		for _, key := range internalAnnotations {
			if _, ok := svc.Annotations[key]; ok {
				hasInternalFlag = true
				break
			}
		}

		if !hasInternalFlag {
			issues = append(issues, "WARNING: LoadBalancer without internal flag may be internet-facing by default")
			dangerous = append(dangerous, "missing-internal-flag")
		}
	}

	return issues, dangerous
}

// analyzeExternalName checks ExternalName services for suspicious destinations
func analyzeExternalName(svc *corev1.Service) []string {
	var issues []string

	if svc.Spec.Type != corev1.ServiceTypeExternalName {
		return issues
	}

	externalName := svc.Spec.ExternalName
	if externalName == "" {
		issues = append(issues, "ExternalName service with empty externalName")
		return issues
	}

	// Check for internal service exfiltration
	if strings.Contains(externalName, ".internal") || strings.Contains(externalName, ".local") {
		issues = append(issues, "ExternalName points to internal domain (possible lateral movement)")
	}

	// Check for suspicious external services
	suspiciousDomains := []string{
		"ngrok.io", "burpcollaborator", "requestbin",
		"webhook.site", "pipedream.net", "beeceptor.com",
		"hookbin.com", "postb.in",
	}
	for _, domain := range suspiciousDomains {
		if strings.Contains(strings.ToLower(externalName), domain) {
			issues = append(issues, fmt.Sprintf("SUSPICIOUS: ExternalName points to %s (potential data exfiltration)", domain))
		}
	}

	// Check for cloud storage (data exfiltration risk)
	cloudStorageDomains := []string{
		"s3.amazonaws.com", "s3-", "blob.core.windows.net",
		"storage.googleapis.com", "storage.cloud.google.com",
	}
	for _, domain := range cloudStorageDomains {
		if strings.Contains(strings.ToLower(externalName), domain) {
			issues = append(issues, "ExternalName points to cloud storage (data exfiltration risk)")
			break
		}
	}

	return issues
}

// buildAttackPath creates an attack path visualization
func buildAttackPath(finding NetworkExposureFinding) string {
	path := []string{}

	// Entry point
	if finding.IsInternetFacing {
		path = append(path, "Internet")
	} else {
		path = append(path, "Internal Network")
	}

	// Exposure mechanism
	switch finding.ExposureType {
	case "LoadBalancer":
		if finding.CloudProvider != "Unknown" {
			path = append(path, fmt.Sprintf("LoadBalancer (%s)", finding.CloudProvider))
		} else {
			path = append(path, "LoadBalancer")
		}
	case "NodePort":
		path = append(path, fmt.Sprintf("NodePort :%d", finding.NodePort))
	case "HostPort":
		path = append(path, fmt.Sprintf("HostPort :%d", finding.Port))
	case "ExternalIP":
		path = append(path, "ExternalIP")
	case "Ingress":
		path = append(path, "Ingress")
	}

	// Service
	if finding.ResourceType == "Service" {
		path = append(path, fmt.Sprintf("Service:%d", finding.Port))
	}

	// Backend
	if finding.BackendDeployment != "" {
		path = append(path, finding.BackendDeployment)
	} else if finding.BackendPods > 0 {
		path = append(path, fmt.Sprintf("%d Pods", finding.BackendPods))
	}

	// Escalation risks
	if finding.BackendPrivileged {
		path = append(path, "Privileged Container")
	}
	if finding.BackendHostNetwork {
		path = append(path, "Host Network")
		path = append(path, "Node Compromise")
	}

	return strings.Join(path, " → ")
}

// calculateNetworkExposureRisk determines risk level based on multiple factors
func calculateNetworkExposureRisk(finding NetworkExposureFinding) string {
	riskScore := 0

	// CRITICAL FACTORS (50+ points)
	if finding.IsDangerousPort && finding.IsInternetFacing && finding.BackendPrivileged {
		riskScore += 100 // Privileged workload exposed via dangerous port to internet
	}
	if finding.PortCategory == "Kubernetes" && finding.IsInternetFacing {
		riskScore += 90 // Exposed Kubelet/API/etcd = cluster compromise
	}
	if finding.ExposureType == "HostPort" && finding.BackendHostNetwork {
		riskScore += 80 // HostPort + hostNetwork = node compromise
	}
	if strings.Contains(finding.PortDescription, "etcd") && finding.IsInternetFacing {
		riskScore += 100 // etcd exposure = cluster secrets compromise
	}
	if finding.Port == 10250 && finding.IsInternetFacing {
		riskScore += 95 // Kubelet API = unauthenticated RCE
	}
	if finding.PortCategory == "SSH" || finding.PortCategory == "RDP" {
		if finding.IsInternetFacing {
			riskScore += 50 // Remote access to internet
		} else {
			riskScore += 20
		}
	}

	// HIGH FACTORS (25-40 points)
	if finding.IsDangerousPort && finding.IsInternetFacing {
		riskScore += 40 // Dangerous port exposed to internet
	}
	if finding.ExposureType == "NodePort" && finding.IsDangerousPort {
		riskScore += 35 // NodePort with dangerous service
	}
	if finding.BackendPrivileged && finding.IsInternetFacing {
		riskScore += 30 // Privileged backend exposed
	}
	if finding.PortCategory == "Database" && finding.IsInternetFacing {
		riskScore += 35 // Exposed database
	}
	if finding.ExposureType == "HostPort" {
		riskScore += 30 // HostPort bypasses NetworkPolicy
	}
	if len(finding.DangerousAnnotations) > 0 && finding.IsInternetFacing {
		riskScore += 25
	}

	// MEDIUM FACTORS (10-20 points)
	if !finding.HasNetworkPolicy && finding.IsInternetFacing {
		riskScore += 15 // No network isolation
	}
	if finding.ExposureType == "LoadBalancer" && finding.Protocol == "HTTP" {
		riskScore += 15 // Unencrypted LoadBalancer
	}
	if finding.BackendHostNetwork {
		riskScore += 12 // hostNetwork backend
	}
	if finding.PortCategory == "Admin" && finding.IsInternetFacing {
		riskScore += 18 // Admin panel exposed
	}
	if finding.BackendSecurityLevel == "Vulnerable" {
		riskScore += 10
	}

	// LOW FACTORS (1-5 points)
	if finding.IsInternetFacing {
		riskScore += 5
	}
	if finding.ExposureType == "NodePort" {
		riskScore += 3
	}
	if finding.PortCategory == "Database" || finding.PortCategory == "Admin" {
		riskScore += 2
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

// determineDataExposureRisk identifies what kind of sensitive data might be exposed
func determineDataExposureRisk(finding NetworkExposureFinding) string {
	switch finding.PortCategory {
	case "Database":
		return "Database"
	case "Admin":
		return "Admin Panel"
	case "Kubernetes":
		if strings.Contains(finding.PortDescription, "etcd") {
			return "Cluster Secrets"
		}
		return "Cluster Control"
	case "SSH", "RDP", "Telnet", "VNC":
		return "System Access"
	}

	// Check for metrics/monitoring
	if finding.Port == 9090 || finding.Port == 9093 || finding.Port == 3000 {
		return "Metrics/Monitoring"
	}

	return "None"
}

func appendNmapCommands(commands *[]string, target string, ports []corev1.ServicePort) {
	var tcpPorts, udpPorts []int32
	for _, port := range ports {
		switch port.Protocol {
		case corev1.ProtocolTCP:
			tcpPorts = append(tcpPorts, port.Port)
		case corev1.ProtocolUDP:
			udpPorts = append(udpPorts, port.Port)
		}
	}
	var nmapParts []string
	if len(tcpPorts) > 0 {
		sort.Slice(tcpPorts, func(i, j int) bool { return tcpPorts[i] < tcpPorts[j] })
		portStr := strings.Trim(strings.Join(strings.Fields(fmt.Sprint(tcpPorts)), ","), "[]")
		nmapParts = append(nmapParts, fmt.Sprintf("nmap -PN -sV -p %s %s", portStr, target))
	}
	if len(udpPorts) > 0 {
		sort.Slice(udpPorts, func(i, j int) bool { return udpPorts[i] < udpPorts[j] })
		portStr := strings.Trim(strings.Join(strings.Fields(fmt.Sprint(udpPorts)), ","), "[]")
		nmapParts = append(nmapParts, fmt.Sprintf("nmap -PN -sU -p %s %s", portStr, target))
	}
	if len(nmapParts) == 0 {
		nmapParts = append(nmapParts, fmt.Sprintf("nmap -PN -sV %s", target))
	}
	*commands = append(*commands, strings.Join(nmapParts, "\n"))
}

func NetworkExposure(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	logger := internal.NewLogger()
	parentCmd := cmd.Parent()

	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating network exposures with security analysis for %s", globals.ClusterName), globals.K8S_NETWORK_PORTS_MODULE_NAME)

	clientset := config.GetClientOrExit()

	var findings []NetworkExposureFinding
	var lootNmapCommands []string

	// ---- Services Analysis
	services, err := clientset.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing Services: %v", err), globals.K8S_NETWORK_PORTS_MODULE_NAME)
	} else {
		for _, svc := range services.Items {
			// Skip headless services
			if svc.Spec.ClusterIP == "None" {
				continue
			}

			// Determine internet-facing status
			isInternetFacing, cloudProvider := detectInternetFacing(&svc)

			// Analyze backend security
			backendSecurity := analyzeNetworkExposureBackendSecurity(ctx, clientset, &svc)

			// Analyze annotations
			annotationIssues, dangerousAnnotations := analyzeServiceAnnotations(&svc)

			// Analyze ExternalName services
			externalNameIssues := analyzeExternalName(&svc)

			// Get NetworkPolicies
			policies, _ := clientset.NetworkingV1().NetworkPolicies(svc.Namespace).List(ctx, metav1.ListOptions{})
			var policyNames []string
			for _, p := range policies.Items {
				policyNames = append(policyNames, p.Name)
			}

			// Process each port
			for _, port := range svc.Spec.Ports {
				// Determine targets
				targets := []string{}
				exposureType := "ClusterIP"

				if svc.Spec.Type == corev1.ServiceTypeExternalName {
					if svc.Spec.ExternalName != "" {
						targets = append(targets, svc.Spec.ExternalName)
						exposureType = "ExternalName"
					}
				} else {
					// LoadBalancer ingress
					if len(svc.Status.LoadBalancer.Ingress) > 0 {
						exposureType = "LoadBalancer"
						for _, ing := range svc.Status.LoadBalancer.Ingress {
							if ing.IP != "" {
								targets = append(targets, ing.IP)
							} else if ing.Hostname != "" {
								targets = append(targets, ing.Hostname)
							}
						}
					}

					// ExternalIPs
					if len(svc.Spec.ExternalIPs) > 0 {
						exposureType = "ExternalIP"
						targets = append(targets, svc.Spec.ExternalIPs...)
					}

					// NodePort
					if svc.Spec.Type == corev1.ServiceTypeNodePort && port.NodePort != 0 {
						exposureType = "NodePort"
						// Use ClusterIP as representative target
						if svc.Spec.ClusterIP != "" && svc.Spec.ClusterIP != "None" {
							targets = append(targets, svc.Spec.ClusterIP)
						}
					}

					// If no external targets, use ClusterIP for internal services
					if len(targets) == 0 && svc.Spec.ClusterIP != "" && svc.Spec.ClusterIP != "None" {
						targets = append(targets, svc.Spec.ClusterIP)
					}
				}

				// Create finding for each target
				for _, target := range targets {
					finding := NetworkExposureFinding{
						Namespace:    svc.Namespace,
						ResourceType: "Service",
						ResourceName: svc.Name,
						ExposureType: exposureType,
						Port:         port.Port,
						TargetPort:   port.TargetPort.String(),
						NodePort:     port.NodePort,
						Protocol:     string(port.Protocol),
						ServiceType:  string(svc.Spec.Type),

						// Network details
						IsInternetFacing: isInternetFacing,
						CloudProvider:    cloudProvider,

						// Backend security
						BackendPods:           backendSecurity.PodCount,
						BackendDeployment:     backendSecurity.Deployment,
						BackendPrivileged:     backendSecurity.Privileged,
						BackendHostNetwork:    backendSecurity.HostNetwork,
						BackendServiceAccount: backendSecurity.ServiceAccount,
						BackendSecurityLevel:  backendSecurity.SecurityLevel,
						BackendSecurityIssues: backendSecurity.SecurityIssues,
						ExposedWorkloads:      backendSecurity.Workloads,

						// Network policy
						HasNetworkPolicy: len(policies.Items) > 0,
						NetworkPolicies:  policyNames,

						// Annotations
						AnnotationIssues:     annotationIssues,
						DangerousAnnotations: dangerousAnnotations,
					}

					// Determine IP vs Hostname
					if strings.Contains(target, ".") && !strings.Contains(target, ":") {
						// Simple heuristic: if it has dots but no colons, check if it's an IP
						if strings.Count(target, ".") == 3 {
							finding.IPAddress = target
						} else {
							finding.Hostname = target
						}
					} else {
						finding.Hostname = target
					}

					// Selector
					if len(svc.Spec.Selector) > 0 {
						finding.Selector = labels.FormatLabels(svc.Spec.Selector)
					}

					// Session affinity
					finding.SessionAffinity = string(svc.Spec.SessionAffinity)
					if svc.Spec.ExternalTrafficPolicy != "" {
						finding.ExternalTrafficPolicy = string(svc.Spec.ExternalTrafficPolicy)
					}

					// ExternalName
					if svc.Spec.Type == corev1.ServiceTypeExternalName {
						finding.ExternalName = svc.Spec.ExternalName
						finding.SecurityIssues = append(finding.SecurityIssues, externalNameIssues...)
					}

					// Port analysis
					isDangerous, category, _, description := analyzePort(port.Port)
					finding.IsDangerousPort = isDangerous
					finding.PortCategory = category
					finding.PortDescription = description

					// Data exposure risk
					finding.DataExposureRisk = determineDataExposureRisk(finding)

					// Build attack path
					finding.AttackVector = buildAttackPath(finding)

					// Add security issues
					if finding.BackendPrivileged {
						finding.SecurityIssues = append(finding.SecurityIssues, "Backend pods run privileged containers")
					}
					if finding.BackendHostNetwork {
						finding.SecurityIssues = append(finding.SecurityIssues, "Backend pods use hostNetwork")
					}
					if !finding.HasNetworkPolicy && finding.IsInternetFacing {
						finding.SecurityIssues = append(finding.SecurityIssues, "No NetworkPolicy enforcement")
					}
					if finding.IsDangerousPort && finding.IsInternetFacing {
						finding.SecurityIssues = append(finding.SecurityIssues,
							fmt.Sprintf("Dangerous port %d (%s) exposed to internet", finding.Port, finding.PortCategory))
					}

					// Calculate risk
					finding.RiskLevel = calculateNetworkExposureRisk(finding)

					findings = append(findings, finding)

					// Add nmap command
					appendNmapCommands(&lootNmapCommands, target, []corev1.ServicePort{port})
				}
			}
		}
	}

	// ---- HostPort Detection (Pods)
	pods, err := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing Pods for HostPort detection: %v", err), globals.K8S_NETWORK_PORTS_MODULE_NAME)
	} else {
		for _, pod := range pods.Items {
			for _, container := range append(pod.Spec.Containers, pod.Spec.InitContainers...) {
				for _, port := range container.Ports {
					if port.HostPort != 0 {
						finding := NetworkExposureFinding{
							Namespace:          pod.Namespace,
							ResourceType:       "Pod",
							ResourceName:       pod.Name,
							ExposureType:       "HostPort",
							Port:               port.HostPort,
							TargetPort:         fmt.Sprintf("%d", port.ContainerPort),
							Protocol:           string(port.Protocol),
							IsInternetFacing:   pod.Spec.HostNetwork, // HostPort + HostNetwork = very exposed
							BackendHostNetwork: pod.Spec.HostNetwork,
							SecurityIssues: []string{
								fmt.Sprintf("Container '%s' uses HostPort %d", container.Name, port.HostPort),
								"HostPort bypasses NetworkPolicy",
								"HostPort exposes service on node IP",
							},
						}

						// Check if pod is privileged
						if container.SecurityContext != nil && container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
							finding.BackendPrivileged = true
							finding.SecurityIssues = append(finding.SecurityIssues, "Container is privileged")
						}

						// Port analysis
						isDangerous, category, _, description := analyzePort(port.HostPort)
						finding.IsDangerousPort = isDangerous
						finding.PortCategory = category
						finding.PortDescription = description
						finding.DataExposureRisk = determineDataExposureRisk(finding)

						// Attack path
						finding.AttackVector = buildAttackPath(finding)

						// Risk calculation
						finding.RiskLevel = calculateNetworkExposureRisk(finding)

						findings = append(findings, finding)
					}
				}
			}
		}
	}

	// ---- Ingresses (simplified - detailed analysis in ingress.go)
	ingresses, err := clientset.NetworkingV1().Ingresses("").List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing Ingresses: %v", err), globals.K8S_NETWORK_PORTS_MODULE_NAME)
	} else {
		for _, ing := range ingresses.Items {
			for _, rule := range ing.Spec.Rules {
				if rule.Host != "" && rule.HTTP != nil && len(rule.HTTP.Paths) > 0 {
					// Determine if TLS is enabled
					hasTLS := false
					for _, tls := range ing.Spec.TLS {
						for _, host := range tls.Hosts {
							if host == rule.Host {
								hasTLS = true
								break
							}
						}
					}

					port := int32(80)
					protocol := "HTTP"
					if hasTLS {
						port = 443
						protocol = "HTTPS"
					}

					finding := NetworkExposureFinding{
						Namespace:        ing.Namespace,
						ResourceType:     "Ingress",
						ResourceName:     ing.Name,
						ExposureType:     "Ingress",
						Hostname:         rule.Host,
						Port:             port,
						Protocol:         protocol,
						IsInternetFacing: true, // Ingresses are typically internet-facing
						PortCategory:     "Web",
						PortDescription:  fmt.Sprintf("%s web service", protocol),
						DataExposureRisk: "Web Application",
					}

					// Security issues
					if !hasTLS {
						finding.SecurityIssues = append(finding.SecurityIssues, "No TLS configured (unencrypted HTTP)")
					}

					// Attack path
					finding.AttackVector = buildAttackPath(finding)

					// Risk
					finding.RiskLevel = calculateNetworkExposureRisk(finding)

					findings = append(findings, finding)

					// Nmap
					if rule.Host != "" {
						appendNmapCommands(&lootNmapCommands, rule.Host, nil)
					}
				}
			}
		}
	}

	// ---- Build Table
	headers := []string{
		"Risk Level",
		"Namespace",
		"Resource Type",
		"Resource Name",
		"Exposure Type",
		"IP Address",
		"Hostname",
		"Port",
		"Port Category",
		"Protocol",
		"Internet-Facing",
		"Backend Security",
		"Has NetworkPolicy",
		"Backend Pods",
		"Cloud Provider",
		"Security Issues",
	}

	var rows [][]string
	for _, f := range findings {
		ipAddr := k8sinternal.NonEmpty(f.IPAddress)
		hostname := k8sinternal.NonEmpty(f.Hostname)
		internetFacing := "No"
		if f.IsInternetFacing {
			internetFacing = "Yes"
		}
		hasNetPol := "No"
		if f.HasNetworkPolicy {
			hasNetPol = "Yes"
		}
		securityIssuesCount := fmt.Sprintf("%d issues", len(f.SecurityIssues))
		if len(f.SecurityIssues) == 0 {
			securityIssuesCount = "None"
		}

		rows = append(rows, []string{
			f.RiskLevel,
			k8sinternal.NonEmpty(f.Namespace),
			k8sinternal.NonEmpty(f.ResourceType),
			k8sinternal.NonEmpty(f.ResourceName),
			k8sinternal.NonEmpty(f.ExposureType),
			ipAddr,
			hostname,
			fmt.Sprintf("%d", f.Port),
			k8sinternal.NonEmpty(f.PortCategory),
			k8sinternal.NonEmpty(f.Protocol),
			internetFacing,
			k8sinternal.NonEmpty(f.BackendSecurityLevel),
			hasNetPol,
			fmt.Sprintf("%d", f.BackendPods),
			k8sinternal.NonEmpty(f.CloudProvider),
			securityIssuesCount,
		})
	}

	// ---- Build Loot Files

	// 1. Risk Dashboard
	riskDashboard := buildNetworkExposureRiskDashboard(findings)

	// 2. Internet-Facing Exposures
	internetFacingLoot := buildInternetFacingLoot(findings)

	// 3. Dangerous Ports
	dangerousPortsLoot := buildDangerousPortsLoot(findings)

	// 4. NodePort Exposures
	nodePortLoot := buildNodePortLoot(findings)

	// 5. HostPort Exposures
	hostPortLoot := buildHostPortLoot(findings)

	// 6. Privileged Backend
	privilegedBackendLoot := buildPrivilegedBackendLoot(findings)

	// 7. Attack Paths
	attackPathsLoot := buildAttackPathsLoot(findings)

	// 8. NMAP Commands (deduplicated)
	lootSet := map[string]struct{}{}
	var lootNmapCommandsUniq []string
	lootNmapCommandsUniq = append(lootNmapCommandsUniq, `#####################################
##### NMAP Network Exposure Commands
#####################################

# Use these nmap commands to scan exposed network endpoints

`)
	for _, c := range lootNmapCommands {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if _, ok := lootSet[c]; ok {
			continue
		}
		lootSet[c] = struct{}{}
		lootNmapCommandsUniq = append(lootNmapCommandsUniq, c)
	}
	nmapLoot := strings.Join(lootNmapCommandsUniq, "\n")

	table := internal.TableFile{
		Name:   "Network-Exposure",
		Header: headers,
		Body:   rows,
	}

	lootFiles := []internal.LootFile{
		{Name: "Network-Exposure-Risk-Dashboard", Contents: riskDashboard},
		{Name: "Network-Exposure-Internet-Facing", Contents: internetFacingLoot},
		{Name: "Network-Exposure-Dangerous-Ports", Contents: dangerousPortsLoot},
		{Name: "Network-Exposure-NodePort", Contents: nodePortLoot},
		{Name: "Network-Exposure-HostPort", Contents: hostPortLoot},
		{Name: "Network-Exposure-Privileged-Backend", Contents: privilegedBackendLoot},
		{Name: "Network-Exposure-Attack-Paths", Contents: attackPathsLoot},
		{Name: "NMAP-Network", Contents: nmapLoot},
	}

	err = internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"Network-Exposure",
		globals.ClusterName,
		"results",
		NetworkExposureOutput{
			Table: []internal.TableFile{table},
			Loot:  lootFiles,
		},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_NETWORK_PORTS_MODULE_NAME)
		return
	}

	// Summary stats
	criticalCount := 0
	highCount := 0
	internetFacingCount := 0
	for _, f := range findings {
		if f.RiskLevel == "CRITICAL" {
			criticalCount++
		} else if f.RiskLevel == "HIGH" {
			highCount++
		}
		if f.IsInternetFacing {
			internetFacingCount++
		}
	}

	if len(rows) > 0 {
		logger.InfoM(fmt.Sprintf("%d network exposures found (%d CRITICAL, %d HIGH, %d internet-facing)",
			len(rows), criticalCount, highCount, internetFacingCount), globals.K8S_NETWORK_PORTS_MODULE_NAME)
	} else {
		logger.InfoM("No network exposures found, skipping output file creation", globals.K8S_NETWORK_PORTS_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_NETWORK_PORTS_MODULE_NAME), globals.K8S_NETWORK_PORTS_MODULE_NAME)
}

// buildNetworkExposureRiskDashboard creates a risk-sorted exposure summary
func buildNetworkExposureRiskDashboard(findings []NetworkExposureFinding) string {
	var sb strings.Builder
	sb.WriteString(`#####################################
##### Network Exposure Risk Dashboard
#####################################

This file contains all network exposures sorted by risk level.
Focus on CRITICAL and HIGH risk exposures first.

`)

	// Sort by risk: CRITICAL > HIGH > MEDIUM > LOW
	riskOrder := map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
	sort.Slice(findings, func(i, j int) bool {
		return riskOrder[findings[i].RiskLevel] < riskOrder[findings[j].RiskLevel]
	})

	currentRisk := ""
	for _, f := range findings {
		if f.RiskLevel != currentRisk {
			currentRisk = f.RiskLevel
			sb.WriteString(fmt.Sprintf("\n========== %s RISK ==========\n\n", currentRisk))
		}

		sb.WriteString(fmt.Sprintf("[%s] %s/%s\n", f.RiskLevel, f.Namespace, f.ResourceName))
		sb.WriteString(fmt.Sprintf("  Type: %s (%s)\n", f.ResourceType, f.ExposureType))
		if f.IPAddress != "" {
			sb.WriteString(fmt.Sprintf("  IP: %s\n", f.IPAddress))
		}
		if f.Hostname != "" {
			sb.WriteString(fmt.Sprintf("  Hostname: %s\n", f.Hostname))
		}
		sb.WriteString(fmt.Sprintf("  Port: %d (%s - %s)\n", f.Port, f.PortCategory, f.PortDescription))
		sb.WriteString(fmt.Sprintf("  Internet-Facing: %v\n", f.IsInternetFacing))
		if f.BackendDeployment != "" {
			sb.WriteString(fmt.Sprintf("  Backend: %s (%d pods, %s)\n", f.BackendDeployment, f.BackendPods, f.BackendSecurityLevel))
		}
		sb.WriteString(fmt.Sprintf("  Attack Path: %s\n", f.AttackVector))
		if len(f.SecurityIssues) > 0 {
			sb.WriteString("  Security Issues:\n")
			for _, issue := range f.SecurityIssues {
				sb.WriteString(fmt.Sprintf("    - %s\n", issue))
			}
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

// buildInternetFacingLoot creates loot file for internet-facing exposures
func buildInternetFacingLoot(findings []NetworkExposureFinding) string {
	var sb strings.Builder
	sb.WriteString(`#####################################
##### Internet-Facing Network Exposures
#####################################

These services are exposed to the internet and represent your external attack surface.

`)

	count := 0
	for _, f := range findings {
		if !f.IsInternetFacing {
			continue
		}
		count++

		sb.WriteString(fmt.Sprintf("[%s] %s/%s\n", f.RiskLevel, f.Namespace, f.ResourceName))
		sb.WriteString(fmt.Sprintf("  Exposure: %s", f.ExposureType))
		if f.CloudProvider != "Unknown" {
			sb.WriteString(fmt.Sprintf(" (%s)", f.CloudProvider))
		}
		sb.WriteString("\n")
		if f.Hostname != "" {
			sb.WriteString(fmt.Sprintf("  Target: %s:%d\n", f.Hostname, f.Port))
		} else if f.IPAddress != "" {
			sb.WriteString(fmt.Sprintf("  Target: %s:%d\n", f.IPAddress, f.Port))
		}
		sb.WriteString(fmt.Sprintf("  Service: %s (%s)\n", f.PortCategory, f.PortDescription))
		if f.DataExposureRisk != "None" {
			sb.WriteString(fmt.Sprintf("  Data Risk: %s\n", f.DataExposureRisk))
		}
		sb.WriteString("\n")
	}

	if count == 0 {
		sb.WriteString("No internet-facing exposures found.\n")
	}

	return sb.String()
}

// buildDangerousPortsLoot creates loot file for dangerous port exposures
func buildDangerousPortsLoot(findings []NetworkExposureFinding) string {
	var sb strings.Builder
	sb.WriteString(`#####################################
##### Dangerous Port Exposures
#####################################

These exposures involve dangerous ports (SSH, RDP, databases, Kubernetes APIs, etc.)

`)

	count := 0
	for _, f := range findings {
		if !f.IsDangerousPort {
			continue
		}
		count++

		sb.WriteString(fmt.Sprintf("[%s] Port %d - %s\n", f.RiskLevel, f.Port, f.PortDescription))
		sb.WriteString(fmt.Sprintf("  Resource: %s/%s (%s)\n", f.Namespace, f.ResourceName, f.ResourceType))
		sb.WriteString(fmt.Sprintf("  Category: %s\n", f.PortCategory))
		sb.WriteString(fmt.Sprintf("  Internet-Facing: %v\n", f.IsInternetFacing))
		if f.IPAddress != "" || f.Hostname != "" {
			target := f.IPAddress
			if target == "" {
				target = f.Hostname
			}
			sb.WriteString(fmt.Sprintf("  Target: %s:%d\n", target, f.Port))
		}
		if f.BackendSecurityLevel == "Vulnerable" {
			sb.WriteString(fmt.Sprintf("  WARNING: Backend is vulnerable (privileged=%v, hostNetwork=%v)\n",
				f.BackendPrivileged, f.BackendHostNetwork))
		}
		sb.WriteString("\n")
	}

	if count == 0 {
		sb.WriteString("No dangerous port exposures found.\n")
	}

	return sb.String()
}

// buildNodePortLoot creates loot file for NodePort services
func buildNodePortLoot(findings []NetworkExposureFinding) string {
	var sb strings.Builder
	sb.WriteString(`#####################################
##### NodePort Exposures
#####################################

NodePort services are exposed on ALL cluster nodes.
If nodes have external IPs, these services are internet-accessible.

`)

	count := 0
	for _, f := range findings {
		if f.ExposureType != "NodePort" {
			continue
		}
		count++

		sb.WriteString(fmt.Sprintf("[%s] %s/%s\n", f.RiskLevel, f.Namespace, f.ResourceName))
		sb.WriteString(fmt.Sprintf("  NodePort: %d (Service Port: %d)\n", f.NodePort, f.Port))
		sb.WriteString(fmt.Sprintf("  Port Category: %s - %s\n", f.PortCategory, f.PortDescription))
		sb.WriteString(fmt.Sprintf("  Exposed on: ALL cluster nodes\n"))
		if f.BackendDeployment != "" {
			sb.WriteString(fmt.Sprintf("  Backend: %s (%d pods)\n", f.BackendDeployment, f.BackendPods))
		}
		sb.WriteString("\n")
	}

	if count == 0 {
		sb.WriteString("No NodePort services found.\n")
	}

	return sb.String()
}

// buildHostPortLoot creates loot file for HostPort pods
func buildHostPortLoot(findings []NetworkExposureFinding) string {
	var sb strings.Builder
	sb.WriteString(`#####################################
##### HostPort Exposures
#####################################

Pods using HostPort bypass NetworkPolicy and expose directly on the node IP.
This is a high-risk configuration.

`)

	count := 0
	for _, f := range findings {
		if f.ExposureType != "HostPort" {
			continue
		}
		count++

		sb.WriteString(fmt.Sprintf("[%s] %s/%s\n", f.RiskLevel, f.Namespace, f.ResourceName))
		sb.WriteString(fmt.Sprintf("  HostPort: %d (Container Port: %s)\n", f.Port, f.TargetPort))
		sb.WriteString(fmt.Sprintf("  Protocol: %s\n", f.Protocol))
		sb.WriteString(fmt.Sprintf("  Port Category: %s - %s\n", f.PortCategory, f.PortDescription))
		sb.WriteString("  WARNING: HostPort bypasses NetworkPolicy!\n")
		if f.BackendPrivileged {
			sb.WriteString("  CRITICAL: Container is privileged!\n")
		}
		if f.BackendHostNetwork {
			sb.WriteString("  CRITICAL: Pod uses hostNetwork!\n")
		}
		sb.WriteString("\n")
	}

	if count == 0 {
		sb.WriteString("No HostPort pods found.\n")
	}

	return sb.String()
}

// buildPrivilegedBackendLoot creates loot file for exposures with privileged backends
func buildPrivilegedBackendLoot(findings []NetworkExposureFinding) string {
	var sb strings.Builder
	sb.WriteString(`#####################################
##### Exposures with Privileged Backends
#####################################

These network exposures have backend pods running with dangerous privileges.
Compromise of these services can lead to container escape and node compromise.

`)

	count := 0
	for _, f := range findings {
		if !f.BackendPrivileged && !f.BackendHostNetwork {
			continue
		}
		count++

		sb.WriteString(fmt.Sprintf("[%s] %s/%s\n", f.RiskLevel, f.Namespace, f.ResourceName))
		sb.WriteString(fmt.Sprintf("  Port: %d (%s)\n", f.Port, f.PortCategory))
		sb.WriteString(fmt.Sprintf("  Internet-Facing: %v\n", f.IsInternetFacing))
		sb.WriteString(fmt.Sprintf("  Backend: %s (%d pods)\n", f.BackendDeployment, f.BackendPods))
		if f.BackendPrivileged {
			sb.WriteString("  CRITICAL: Privileged containers\n")
		}
		if f.BackendHostNetwork {
			sb.WriteString("  CRITICAL: Host network access\n")
		}
		sb.WriteString(fmt.Sprintf("  Attack Path: %s\n", f.AttackVector))
		if len(f.BackendSecurityIssues) > 0 {
			sb.WriteString("  Backend Security Issues:\n")
			for _, issue := range f.BackendSecurityIssues {
				sb.WriteString(fmt.Sprintf("    - %s\n", issue))
			}
		}
		sb.WriteString("\n")
	}

	if count == 0 {
		sb.WriteString("No privileged backend exposures found.\n")
	}

	return sb.String()
}

// buildAttackPathsLoot creates loot file with attack path visualizations
func buildAttackPathsLoot(findings []NetworkExposureFinding) string {
	var sb strings.Builder
	sb.WriteString(`#####################################
##### Network Exposure Attack Paths
#####################################

Complete attack paths from entry point to potential compromise.
Focus on paths that lead to "Node Compromise" or expose "Cluster Secrets".

`)

	// Sort by risk for attack path analysis
	riskOrder := map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
	sortedFindings := make([]NetworkExposureFinding, len(findings))
	copy(sortedFindings, findings)
	sort.Slice(sortedFindings, func(i, j int) bool {
		return riskOrder[sortedFindings[i].RiskLevel] < riskOrder[sortedFindings[j].RiskLevel]
	})

	for _, f := range sortedFindings {
		if f.RiskLevel == "LOW" {
			continue // Skip low risk for attack paths
		}

		sb.WriteString(fmt.Sprintf("\n[%s] %s/%s (Port %d)\n", f.RiskLevel, f.Namespace, f.ResourceName, f.Port))
		sb.WriteString(fmt.Sprintf("Attack Path: %s\n", f.AttackVector))

		if f.DataExposureRisk != "None" {
			sb.WriteString(fmt.Sprintf("Data at Risk: %s\n", f.DataExposureRisk))
		}

		if len(f.SecurityIssues) > 0 {
			sb.WriteString("Exploitable Issues:\n")
			for _, issue := range f.SecurityIssues {
				sb.WriteString(fmt.Sprintf("  - %s\n", issue))
			}
		}
	}

	return sb.String()
}
