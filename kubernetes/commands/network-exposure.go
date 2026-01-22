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
	"github.com/BishopFox/cloudfox/kubernetes/sdk"
	"github.com/BishopFox/cloudfox/kubernetes/shared"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"

	// Cloud SDK imports for optional correlation
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/subscription/armsubscription"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/option"
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

	// Cloud network correlation (optional)
	CloudNetwork *CloudNetworkInfo
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

// CloudNetworkInfo contains network information from cloud providers
type CloudNetworkInfo struct {
	Provider  string // AWS, GCP, Azure
	VPCID     string // VPC ID (AWS/GCP) or VNet ID (Azure)
	Subnets   []string
	PublicIPs []string
	Region    string
	LBType    string // NLB, ALB, Classic, Internal, etc.
	LBName    string // Cloud load balancer name
	LBArn     string // Load balancer ARN (AWS)
}

// CloudClients holds optional cloud provider clients for correlation
type CloudClients struct {
	// AWS
	AWSELBv2Client *elasticloadbalancingv2.Client
	AWSRegion      string

	// GCP
	GCPCompute  *compute.Service
	GCPProjects []string // List of projects to check

	// Azure
	AzureCredential    azcore.TokenCredential
	AzureSubscriptions []string // List of subscriptions to check
}

// Dangerous port database
var networkExposureDangerousPorts = map[int32]PortInfo{
	// Remote access (CRITICAL)
	22:   {Category: "SSH", Risk: shared.RiskCritical, Description: "SSH remote access"},
	23:   {Category: "Telnet", Risk: shared.RiskCritical, Description: "Unencrypted remote access (Telnet)"},
	3389: {Category: "RDP", Risk: shared.RiskCritical, Description: "Windows Remote Desktop (RDP)"},
	5900: {Category: "VNC", Risk: shared.RiskCritical, Description: "VNC remote desktop"},
	5901: {Category: "VNC", Risk: shared.RiskCritical, Description: "VNC remote desktop (alt)"},

	// Kubernetes components (CRITICAL)
	6443:  {Category: "Kubernetes", Risk: shared.RiskCritical, Description: "Kubernetes API server"},
	10250: {Category: "Kubernetes", Risk: shared.RiskCritical, Description: "Kubelet API (unauthenticated RCE risk)"},
	10255: {Category: "Kubernetes", Risk: shared.RiskHigh, Description: "Kubelet read-only port"},
	2379:  {Category: "Kubernetes", Risk: shared.RiskCritical, Description: "etcd client API (cluster secrets)"},
	2380:  {Category: "Kubernetes", Risk: shared.RiskCritical, Description: "etcd peer API"},

	// Databases (HIGH)
	3306:  {Category: "Database", Risk: shared.RiskHigh, Description: "MySQL/MariaDB database"},
	5432:  {Category: "Database", Risk: shared.RiskHigh, Description: "PostgreSQL database"},
	1433:  {Category: "Database", Risk: shared.RiskHigh, Description: "Microsoft SQL Server"},
	1521:  {Category: "Database", Risk: shared.RiskHigh, Description: "Oracle database"},
	27017: {Category: "Database", Risk: shared.RiskHigh, Description: "MongoDB database"},
	27018: {Category: "Database", Risk: shared.RiskHigh, Description: "MongoDB shard server"},
	6379:  {Category: "Database", Risk: shared.RiskHigh, Description: "Redis key-value store"},
	9200:  {Category: "Database", Risk: shared.RiskHigh, Description: "Elasticsearch"},
	9300:  {Category: "Database", Risk: shared.RiskHigh, Description: "Elasticsearch cluster"},
	5984:  {Category: "Database", Risk: shared.RiskHigh, Description: "CouchDB"},
	8086:  {Category: "Database", Risk: shared.RiskHigh, Description: "InfluxDB"},
	7000:  {Category: "Database", Risk: shared.RiskHigh, Description: "Cassandra"},
	7001:  {Category: "Database", Risk: shared.RiskHigh, Description: "Cassandra SSL"},

	// Admin/Management (HIGH)
	8080: {Category: "Admin", Risk: shared.RiskHigh, Description: "Common admin panel/management"},
	8443: {Category: "Admin", Risk: shared.RiskHigh, Description: "Admin panel (HTTPS)"},
	9090: {Category: "Admin", Risk: shared.RiskMedium, Description: "Prometheus metrics"},
	9093: {Category: "Admin", Risk: shared.RiskMedium, Description: "Prometheus Alertmanager"},
	3000: {Category: "Admin", Risk: shared.RiskMedium, Description: "Grafana dashboards"},
	9000: {Category: "Admin", Risk: shared.RiskMedium, Description: "SonarQube/Portainer"},
	8081: {Category: "Admin", Risk: shared.RiskMedium, Description: "Common admin panel (alt)"},
	8888: {Category: "Admin", Risk: shared.RiskMedium, Description: "Jupyter/admin panel"},
	5000: {Category: "Admin", Risk: shared.RiskMedium, Description: "Docker Registry/Flask"},
	5001: {Category: "Admin", Risk: shared.RiskMedium, Description: "Docker Registry (alt)"},

	// Message queues (MEDIUM)
	5672:  {Category: "MessageQueue", Risk: shared.RiskMedium, Description: "RabbitMQ"},
	15672: {Category: "MessageQueue", Risk: shared.RiskMedium, Description: "RabbitMQ Management"},
	9092:  {Category: "MessageQueue", Risk: shared.RiskMedium, Description: "Kafka"},
	4222:  {Category: "MessageQueue", Risk: shared.RiskMedium, Description: "NATS"},

	// Web services
	80:   {Category: "Web", Risk: shared.RiskMedium, Description: "HTTP web service"},
	443:  {Category: "Web", Risk: shared.RiskLow, Description: "HTTPS web service"},
	8000: {Category: "Web", Risk: shared.RiskMedium, Description: "HTTP web service (alt)"},
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
	return false, "Custom", shared.RiskLow, "Custom service"
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
		// For ExternalName services, show the external target
		if svc.Spec.Type == corev1.ServiceTypeExternalName && svc.Spec.ExternalName != "" {
			backendInfo.Workloads = append(backendInfo.Workloads, fmt.Sprintf("External/%s", svc.Spec.ExternalName))
		} else {
			// Check Endpoints for services without selectors (manually created endpoints)
			endpoints, err := clientset.CoreV1().Endpoints(svc.Namespace).Get(ctx, svc.Name, metav1.GetOptions{})
			if err == nil && len(endpoints.Subsets) > 0 {
				for _, subset := range endpoints.Subsets {
					for _, addr := range subset.Addresses {
						if addr.TargetRef != nil && addr.TargetRef.Kind == "Pod" {
							// Look up the pod to get its owner
							pod, err := clientset.CoreV1().Pods(svc.Namespace).Get(ctx, addr.TargetRef.Name, metav1.GetOptions{})
							if err == nil {
								backendInfo.PodCount++
								if backendInfo.ServiceAccount == "" {
									backendInfo.ServiceAccount = pod.Spec.ServiceAccountName
								}
								ownerRef := getOwnerReference(pod)
								if ownerRef != "" {
									if !networkExposureContains(backendInfo.Workloads, ownerRef) {
										backendInfo.Workloads = append(backendInfo.Workloads, ownerRef)
									}
								} else {
									podRef := fmt.Sprintf("Pod/%s", pod.Name)
									if !networkExposureContains(backendInfo.Workloads, podRef) {
										backendInfo.Workloads = append(backendInfo.Workloads, podRef)
									}
								}
							}
						} else if addr.IP != "" {
							// External IP endpoint
							ipRef := fmt.Sprintf("IP/%s", addr.IP)
							if !networkExposureContains(backendInfo.Workloads, ipRef) {
								backendInfo.Workloads = append(backendInfo.Workloads, ipRef)
							}
						}
					}
				}
			}
			if len(backendInfo.Workloads) == 0 {
				backendInfo.SecurityIssues = append(backendInfo.SecurityIssues, "No selector or endpoints - cannot determine backend")
			}
		}
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
		ownerRef := getOwnerReference(&pod)
		if ownerRef != "" {
			if !networkExposureContains(backendInfo.Workloads, ownerRef) {
				backendInfo.Workloads = append(backendInfo.Workloads, ownerRef)
				if backendInfo.Deployment == "" {
					backendInfo.Deployment = ownerRef
				}
			}
		} else {
			// Standalone pod (no owner) - use pod name
			podRef := fmt.Sprintf("Pod/%s", pod.Name)
			if !networkExposureContains(backendInfo.Workloads, podRef) {
				backendInfo.Workloads = append(backendInfo.Workloads, podRef)
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

// extractPrivilegedContainers extracts container names from security issues
func extractPrivilegedContainers(issues []string) string {
	var containers []string
	for _, issue := range issues {
		// Look for "Pod X runs privileged container 'Y'"
		if strings.Contains(issue, "privileged container") {
			// Extract container name between quotes
			start := strings.Index(issue, "'")
			end := strings.LastIndex(issue, "'")
			if start != -1 && end != -1 && end > start {
				containers = append(containers, issue[start+1:end])
			}
		}
	}
	if len(containers) > 0 {
		return strings.Join(containers, ", ")
	}
	return ""
}

// analyzeServiceAnnotations checks for dangerous or interesting service annotations
func analyzeServiceAnnotations(svc *corev1.Service) ([]string, []string) {
	var issues []string
	var dangerous []string

	for _, anno := range dangerousServiceAnnotations {
		if val, ok := svc.Annotations[anno.key]; ok {
			msg := fmt.Sprintf("[%s] %s = %s: %s", anno.risk, anno.key, val, anno.description)
			issues = append(issues, msg)

			if anno.risk == shared.RiskHigh || anno.risk == shared.RiskCritical {
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
		return shared.RiskCritical
	} else if riskScore >= 25 {
		return shared.RiskHigh
	} else if riskScore >= 10 {
		return shared.RiskMedium
	}
	return shared.RiskLow
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

// containsProvider checks if a provider is in the list
func containsProvider(providers []string, provider string) bool {
	for _, p := range providers {
		if p == provider {
			return true
		}
	}
	return false
}

// initCloudClients attempts to initialize cloud provider clients for correlation
// All errors are suppressed since cloud correlation is optional
// Uses flags from globals if set, otherwise falls back to default credential chains
// Will enumerate all accessible projects/subscriptions if not specified
// Only initializes clients for providers specified in globals.K8sCloudProviders
func initCloudClients(logger *internal.Logger) *CloudClients {
	// If no cloud providers specified, skip cloud correlation entirely
	if len(globals.K8sCloudProviders) == 0 {
		logger.InfoM("Cloud correlation disabled (use --cloud-provider to enable)", globals.K8S_NETWORK_PORTS_MODULE_NAME)
		return nil
	}

	clients := &CloudClients{}
	cloudEnabled := false

	// Try AWS - only if "aws" is in the provider list
	if containsProvider(globals.K8sCloudProviders, "aws") {
		var awsCfg aws.Config
		var err error
		if globals.K8sAWSProfile != "" {
			awsCfg, err = awsconfig.LoadDefaultConfig(context.Background(),
				awsconfig.WithSharedConfigProfile(globals.K8sAWSProfile))
			if err == nil {
				clients.AWSELBv2Client = elasticloadbalancingv2.NewFromConfig(awsCfg)
				clients.AWSRegion = awsCfg.Region
				logger.InfoM(fmt.Sprintf("AWS cloud correlation enabled (profile: %s, region: %s)", globals.K8sAWSProfile, awsCfg.Region), globals.K8S_NETWORK_PORTS_MODULE_NAME)
				cloudEnabled = true
			} else {
				logger.InfoM(fmt.Sprintf("AWS cloud correlation failed (profile: %s): %v", globals.K8sAWSProfile, err), globals.K8S_NETWORK_PORTS_MODULE_NAME)
			}
		} else {
			awsCfg, err = awsconfig.LoadDefaultConfig(context.Background())
			if err == nil {
				clients.AWSELBv2Client = elasticloadbalancingv2.NewFromConfig(awsCfg)
				clients.AWSRegion = awsCfg.Region
				// Only log if we have a region configured (indicates valid credentials)
				if awsCfg.Region != "" {
					logger.InfoM(fmt.Sprintf("AWS cloud correlation enabled (default credentials, region: %s)", awsCfg.Region), globals.K8S_NETWORK_PORTS_MODULE_NAME)
					cloudEnabled = true
				} else {
					logger.InfoM("AWS cloud correlation failed (no region configured)", globals.K8S_NETWORK_PORTS_MODULE_NAME)
				}
			} else {
				logger.InfoM(fmt.Sprintf("AWS cloud correlation failed: %v", err), globals.K8S_NETWORK_PORTS_MODULE_NAME)
			}
		}
	}

	// Try GCP - only if "gcp" is in the provider list
	if containsProvider(globals.K8sCloudProviders, "gcp") {
		gcpSvc, err := compute.NewService(context.Background(), option.WithScopes(compute.ComputeReadonlyScope))
		if err == nil {
			clients.GCPCompute = gcpSvc

			// Use projects from flag if provided (supports CSV)
			if len(globals.K8sGCPProjects) > 0 {
				clients.GCPProjects = globals.K8sGCPProjects
				logger.InfoM(fmt.Sprintf("GCP cloud correlation enabled (%d projects: %s)", len(globals.K8sGCPProjects), strings.Join(globals.K8sGCPProjects, ", ")), globals.K8S_NETWORK_PORTS_MODULE_NAME)
				cloudEnabled = true
			} else {
				// Try environment variables
				gcpProject := getGCPProject()
				if gcpProject != "" {
					clients.GCPProjects = []string{gcpProject}
					logger.InfoM(fmt.Sprintf("GCP cloud correlation enabled (project from env: %s)", gcpProject), globals.K8S_NETWORK_PORTS_MODULE_NAME)
					cloudEnabled = true
				} else {
					// Try to list all accessible projects
					projects := listGCPProjects()
					if len(projects) > 0 {
						clients.GCPProjects = projects
						logger.InfoM(fmt.Sprintf("GCP cloud correlation enabled (discovered %d projects)", len(projects)), globals.K8S_NETWORK_PORTS_MODULE_NAME)
						cloudEnabled = true
					} else {
						logger.InfoM("GCP cloud correlation failed (no projects found)", globals.K8S_NETWORK_PORTS_MODULE_NAME)
					}
				}
			}
		} else {
			logger.InfoM(fmt.Sprintf("GCP cloud correlation failed: %v", err), globals.K8S_NETWORK_PORTS_MODULE_NAME)
		}
	}

	// Try Azure - only if "azure" is in the provider list
	if containsProvider(globals.K8sCloudProviders, "azure") {
		azCred, err := azidentity.NewDefaultAzureCredential(nil)
		if err == nil {
			clients.AzureCredential = azCred

			// Use subscriptions from flag if provided (supports CSV)
			if len(globals.K8sAzureSubscriptions) > 0 {
				clients.AzureSubscriptions = globals.K8sAzureSubscriptions
				logger.InfoM(fmt.Sprintf("Azure cloud correlation enabled (%d subscriptions: %s)", len(globals.K8sAzureSubscriptions), strings.Join(globals.K8sAzureSubscriptions, ", ")), globals.K8S_NETWORK_PORTS_MODULE_NAME)
				cloudEnabled = true
			} else {
				// Try environment variable
				azSub := getAzureSubscriptionFromEnv()
				if azSub != "" {
					clients.AzureSubscriptions = []string{azSub}
					logger.InfoM(fmt.Sprintf("Azure cloud correlation enabled (subscription from env: %s)", azSub), globals.K8S_NETWORK_PORTS_MODULE_NAME)
					cloudEnabled = true
				} else {
					// Try to list all accessible subscriptions
					subs := listAzureSubscriptions(azCred)
					if len(subs) > 0 {
						clients.AzureSubscriptions = subs
						logger.InfoM(fmt.Sprintf("Azure cloud correlation enabled (discovered %d subscriptions)", len(subs)), globals.K8S_NETWORK_PORTS_MODULE_NAME)
						cloudEnabled = true
					} else {
						logger.InfoM("Azure cloud correlation failed (no subscriptions found)", globals.K8S_NETWORK_PORTS_MODULE_NAME)
					}
				}
			}
		} else {
			logger.InfoM(fmt.Sprintf("Azure cloud correlation failed: %v", err), globals.K8S_NETWORK_PORTS_MODULE_NAME)
		}
	}

	if !cloudEnabled {
		logger.InfoM("Cloud correlation failed for all specified providers", globals.K8S_NETWORK_PORTS_MODULE_NAME)
		return nil
	}

	return clients
}

// getGCPProject tries to get the GCP project from environment variables
func getGCPProject() string {
	envVars := []string{"GOOGLE_CLOUD_PROJECT", "GCLOUD_PROJECT", "CLOUDSDK_CORE_PROJECT", "GCP_PROJECT"}
	for _, v := range envVars {
		if val := os.Getenv(v); val != "" {
			return val
		}
	}
	return ""
}

// listGCPProjects lists all GCP projects accessible to the current credentials
func listGCPProjects() []string {
	var projects []string

	crmSvc, err := cloudresourcemanager.NewService(context.Background(), option.WithScopes(cloudresourcemanager.CloudPlatformReadOnlyScope))
	if err != nil {
		return projects
	}

	// List projects (with a reasonable limit)
	resp, err := crmSvc.Projects.List().PageSize(100).Do()
	if err != nil {
		return projects
	}

	for _, proj := range resp.Projects {
		if proj.LifecycleState == "ACTIVE" {
			projects = append(projects, proj.ProjectId)
		}
	}

	return projects
}

// getAzureSubscriptionFromEnv tries to get the Azure subscription ID from environment
func getAzureSubscriptionFromEnv() string {
	envVars := []string{"AZURE_SUBSCRIPTION_ID", "ARM_SUBSCRIPTION_ID"}
	for _, v := range envVars {
		if val := os.Getenv(v); val != "" {
			return val
		}
	}
	return ""
}

// listAzureSubscriptions lists all Azure subscriptions accessible to the current credentials
func listAzureSubscriptions(cred azcore.TokenCredential) []string {
	var subscriptions []string

	client, err := armsubscription.NewSubscriptionsClient(cred, nil)
	if err != nil {
		return subscriptions
	}

	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(context.Background())
		if err != nil {
			break
		}
		for _, sub := range page.Value {
			if sub.SubscriptionID != nil && sub.State != nil && *sub.State == armsubscription.SubscriptionStateEnabled {
				subscriptions = append(subscriptions, *sub.SubscriptionID)
			}
		}
	}

	return subscriptions
}

// lookupAWSLoadBalancer looks up AWS ELB/NLB details by hostname
// Returns nil on any error (suppressed)
func lookupAWSLoadBalancer(ctx context.Context, clients *CloudClients, hostname string) *CloudNetworkInfo {
	if clients == nil || clients.AWSELBv2Client == nil || hostname == "" {
		return nil
	}

	// AWS ELB hostnames follow pattern: name-hash.region.elb.amazonaws.com
	if !strings.Contains(hostname, ".elb.amazonaws.com") && !strings.Contains(hostname, ".elb.") {
		return nil
	}

	// Try to describe load balancers and find matching one
	result, err := clients.AWSELBv2Client.DescribeLoadBalancers(ctx, &elasticloadbalancingv2.DescribeLoadBalancersInput{})
	if err != nil {
		return nil // Suppress error
	}

	for _, lb := range result.LoadBalancers {
		if lb.DNSName != nil && *lb.DNSName == hostname {
			info := &CloudNetworkInfo{
				Provider: "AWS",
				LBName:   safeString(lb.LoadBalancerName),
				LBArn:    safeString(lb.LoadBalancerArn),
				LBType:   string(lb.Type),
			}

			if lb.VpcId != nil {
				info.VPCID = *lb.VpcId
			}

			// Extract subnets and IPs from availability zones
			for _, az := range lb.AvailabilityZones {
				if az.SubnetId != nil {
					info.Subnets = append(info.Subnets, *az.SubnetId)
				}
				for _, lba := range az.LoadBalancerAddresses {
					if lba.IpAddress != nil {
						info.PublicIPs = append(info.PublicIPs, *lba.IpAddress)
					}
				}
			}

			// Extract region from ARN if available
			if lb.LoadBalancerArn != nil {
				parts := strings.Split(*lb.LoadBalancerArn, ":")
				if len(parts) >= 4 {
					info.Region = parts[3]
				}
			}

			return info
		}
	}

	return nil
}

// lookupGCPForwardingRule looks up GCP forwarding rule details by IP across all configured projects
// Returns nil on any error (suppressed)
func lookupGCPForwardingRule(ctx context.Context, clients *CloudClients, ipAddress string, logger *internal.Logger) *CloudNetworkInfo {
	if clients == nil || clients.GCPCompute == nil || ipAddress == "" || len(clients.GCPProjects) == 0 {
		return nil
	}

	// Try each project
	for _, project := range clients.GCPProjects {
		// List all global forwarding rules
		globalRules, err := clients.GCPCompute.GlobalForwardingRules.List(project).Context(ctx).Do()
		if err != nil {
			if logger != nil {
				logger.InfoM(fmt.Sprintf("GCP: failed to list global forwarding rules in %s: %v", project, err), globals.K8S_NETWORK_PORTS_MODULE_NAME)
			}
		} else if globalRules != nil {
			if logger != nil && len(globalRules.Items) > 0 {
				var ips []string
				for _, r := range globalRules.Items {
					ips = append(ips, fmt.Sprintf("%s=%s", r.Name, r.IPAddress))
				}
				logger.InfoM(fmt.Sprintf("GCP: found %d global forwarding rules in %s: %s", len(globalRules.Items), project, strings.Join(ips, ", ")), globals.K8S_NETWORK_PORTS_MODULE_NAME)
			}
			for _, rule := range globalRules.Items {
				if rule.IPAddress == ipAddress {
					info := &CloudNetworkInfo{
						Provider: "GCP",
						LBName:   rule.Name,
						LBType:   rule.LoadBalancingScheme,
						Region:   "global",
					}
					info.PublicIPs = append(info.PublicIPs, rule.IPAddress)

					// Extract network from target if available
					if rule.Network != "" {
						parts := strings.Split(rule.Network, "/")
						if len(parts) > 0 {
							info.VPCID = parts[len(parts)-1]
						}
					}
					return info
				}
			}
		}

		// Also check regional forwarding rules by aggregating across regions
		aggregatedList, err := clients.GCPCompute.ForwardingRules.AggregatedList(project).Context(ctx).Do()
		if err != nil {
			if logger != nil {
				logger.InfoM(fmt.Sprintf("GCP: failed to list regional forwarding rules in %s: %v", project, err), globals.K8S_NETWORK_PORTS_MODULE_NAME)
			}
		} else if aggregatedList != nil {
			// Count and log regional forwarding rules
			if logger != nil {
				var regionalIPs []string
				for _, scopedList := range aggregatedList.Items {
					if scopedList.ForwardingRules == nil {
						continue
					}
					for _, r := range scopedList.ForwardingRules {
						regionalIPs = append(regionalIPs, fmt.Sprintf("%s=%s", r.Name, r.IPAddress))
					}
				}
				if len(regionalIPs) > 0 {
					logger.InfoM(fmt.Sprintf("GCP: found %d regional forwarding rules in %s: %s", len(regionalIPs), project, strings.Join(regionalIPs, ", ")), globals.K8S_NETWORK_PORTS_MODULE_NAME)
				}
			}

			for region, scopedList := range aggregatedList.Items {
				if scopedList.ForwardingRules == nil {
					continue
				}
				for _, rule := range scopedList.ForwardingRules {
					if rule.IPAddress == ipAddress {
						info := &CloudNetworkInfo{
							Provider: "GCP",
							LBName:   rule.Name,
							LBType:   rule.LoadBalancingScheme,
						}
						// Extract region name from the key (format: regions/us-central1)
						if strings.HasPrefix(region, "regions/") {
							info.Region = strings.TrimPrefix(region, "regions/")
						} else {
							info.Region = region
						}
						info.PublicIPs = append(info.PublicIPs, rule.IPAddress)

						if rule.Network != "" {
							parts := strings.Split(rule.Network, "/")
							if len(parts) > 0 {
								info.VPCID = parts[len(parts)-1]
							}
						}
						return info
					}
				}
			}
		}
	}

	return nil
}

// lookupGCPNEG looks up GCP Network Endpoint Groups that might be associated with a K8s service
// NEG names follow pattern: k8s1-{cluster-uid}-{namespace}-{service}-{port}-{hash}
// Returns nil on any error (suppressed)
func lookupGCPNEG(ctx context.Context, clients *CloudClients, namespace, serviceName string, logger *internal.Logger) *CloudNetworkInfo {
	if clients == nil || clients.GCPCompute == nil || len(clients.GCPProjects) == 0 {
		return nil
	}

	// Build search pattern - NEG names contain namespace and service name
	searchPattern := fmt.Sprintf("%s-%s", namespace, serviceName)

	for _, project := range clients.GCPProjects {
		// List NEGs across all zones (aggregated)
		aggregatedList, err := clients.GCPCompute.NetworkEndpointGroups.AggregatedList(project).Context(ctx).Do()
		if err != nil {
			if logger != nil {
				logger.InfoM(fmt.Sprintf("GCP: failed to list NEGs in %s: %v", project, err), globals.K8S_NETWORK_PORTS_MODULE_NAME)
			}
			continue
		}

		if aggregatedList == nil {
			continue
		}

		var matchingNEGs []string
		for zone, scopedList := range aggregatedList.Items {
			if scopedList.NetworkEndpointGroups == nil {
				continue
			}
			for _, neg := range scopedList.NetworkEndpointGroups {
				// Check if NEG name contains our service pattern
				if strings.Contains(neg.Name, searchPattern) {
					matchingNEGs = append(matchingNEGs, neg.Name)

					info := &CloudNetworkInfo{
						Provider: "GCP",
						LBName:   fmt.Sprintf("NEG:%s", neg.Name),
						LBType:   neg.NetworkEndpointType,
					}

					// Extract zone/region
					if strings.HasPrefix(zone, "zones/") {
						info.Region = strings.TrimPrefix(zone, "zones/")
					} else {
						info.Region = zone
					}

					// Extract network
					if neg.Network != "" {
						parts := strings.Split(neg.Network, "/")
						if len(parts) > 0 {
							info.VPCID = parts[len(parts)-1]
						}
					}

					// Extract subnetwork
					if neg.Subnetwork != "" {
						parts := strings.Split(neg.Subnetwork, "/")
						if len(parts) > 0 {
							info.Subnets = append(info.Subnets, parts[len(parts)-1])
						}
					}

					if logger != nil {
						logger.InfoM(fmt.Sprintf("GCP: found NEG %s matching %s/%s", neg.Name, namespace, serviceName), globals.K8S_NETWORK_PORTS_MODULE_NAME)
					}

					return info
				}
			}
		}

		// Log all NEGs found for debugging
		if logger != nil && len(matchingNEGs) == 0 {
			var allNEGs []string
			for _, scopedList := range aggregatedList.Items {
				if scopedList.NetworkEndpointGroups == nil {
					continue
				}
				for _, neg := range scopedList.NetworkEndpointGroups {
					allNEGs = append(allNEGs, neg.Name)
				}
			}
			if len(allNEGs) > 0 {
				logger.InfoM(fmt.Sprintf("GCP: %d NEGs in %s (none matched %s): %s", len(allNEGs), project, searchPattern, strings.Join(allNEGs, ", ")), globals.K8S_NETWORK_PORTS_MODULE_NAME)
			}
		}
	}

	return nil
}

// lookupGCPBackendService looks up GCP Backend Services that might be associated with a K8s service
// Backend service names often contain the namespace and service name
func lookupGCPBackendService(ctx context.Context, clients *CloudClients, namespace, serviceName string, logger *internal.Logger) *CloudNetworkInfo {
	if clients == nil || clients.GCPCompute == nil || len(clients.GCPProjects) == 0 {
		return nil
	}

	searchPattern := fmt.Sprintf("%s-%s", namespace, serviceName)

	for _, project := range clients.GCPProjects {
		// Check global backend services (for HTTP(S) LBs)
		globalBackends, err := clients.GCPCompute.BackendServices.List(project).Context(ctx).Do()
		if err == nil && globalBackends != nil {
			for _, backend := range globalBackends.Items {
				if strings.Contains(backend.Name, searchPattern) || strings.Contains(backend.Name, serviceName) {
					info := &CloudNetworkInfo{
						Provider: "GCP",
						LBName:   fmt.Sprintf("Backend:%s", backend.Name),
						LBType:   backend.LoadBalancingScheme,
						Region:   "global",
					}

					if logger != nil {
						logger.InfoM(fmt.Sprintf("GCP: found backend service %s matching %s/%s", backend.Name, namespace, serviceName), globals.K8S_NETWORK_PORTS_MODULE_NAME)
					}

					return info
				}
			}
		}

		// Note: Regional backend services don't have an aggregated list API
		// They would need to be queried per-region, which is expensive
		// The global backend services check above should cover most cases
	}

	return nil
}

// lookupGCPAddress looks up GCP Address (static IP) by name pattern
// Address names might contain cluster/service info
func lookupGCPAddress(ctx context.Context, clients *CloudClients, ipAddress string, logger *internal.Logger) *CloudNetworkInfo {
	if clients == nil || clients.GCPCompute == nil || len(clients.GCPProjects) == 0 || ipAddress == "" {
		return nil
	}

	for _, project := range clients.GCPProjects {
		// Check global addresses
		globalAddresses, err := clients.GCPCompute.GlobalAddresses.List(project).Context(ctx).Do()
		if err == nil && globalAddresses != nil {
			for _, addr := range globalAddresses.Items {
				if addr.Address == ipAddress {
					info := &CloudNetworkInfo{
						Provider:  "GCP",
						LBName:    fmt.Sprintf("Address:%s", addr.Name),
						LBType:    addr.AddressType,
						Region:    "global",
						PublicIPs: []string{addr.Address},
					}

					if logger != nil {
						logger.InfoM(fmt.Sprintf("GCP: found global address %s with IP %s", addr.Name, ipAddress), globals.K8S_NETWORK_PORTS_MODULE_NAME)
					}

					return info
				}
			}
		}

		// Check regional addresses
		regionalAddresses, err := clients.GCPCompute.Addresses.AggregatedList(project).Context(ctx).Do()
		if err == nil && regionalAddresses != nil {
			for region, scopedList := range regionalAddresses.Items {
				if scopedList.Addresses == nil {
					continue
				}
				for _, addr := range scopedList.Addresses {
					if addr.Address == ipAddress {
						info := &CloudNetworkInfo{
							Provider:  "GCP",
							LBName:    fmt.Sprintf("Address:%s", addr.Name),
							LBType:    addr.AddressType,
							PublicIPs: []string{addr.Address},
						}
						if strings.HasPrefix(region, "regions/") {
							info.Region = strings.TrimPrefix(region, "regions/")
						} else {
							info.Region = region
						}

						// Get network info
						if addr.Network != "" {
							parts := strings.Split(addr.Network, "/")
							if len(parts) > 0 {
								info.VPCID = parts[len(parts)-1]
							}
						}
						if addr.Subnetwork != "" {
							parts := strings.Split(addr.Subnetwork, "/")
							if len(parts) > 0 {
								info.Subnets = append(info.Subnets, parts[len(parts)-1])
							}
						}

						if logger != nil {
							logger.InfoM(fmt.Sprintf("GCP: found regional address %s with IP %s", addr.Name, ipAddress), globals.K8S_NETWORK_PORTS_MODULE_NAME)
						}

						return info
					}
				}
			}
		}
	}

	return nil
}

// lookupAzureLoadBalancer looks up Azure Load Balancer details by IP across all configured subscriptions
// Returns nil on any error (suppressed)
func lookupAzureLoadBalancer(ctx context.Context, clients *CloudClients, ipAddress string) *CloudNetworkInfo {
	if clients == nil || clients.AzureCredential == nil || ipAddress == "" || len(clients.AzureSubscriptions) == 0 {
		return nil
	}

	// Try each subscription
	for _, subscription := range clients.AzureSubscriptions {
		// Create clients for this subscription
		publicIPClient, err := armnetwork.NewPublicIPAddressesClient(subscription, clients.AzureCredential, nil)
		if err != nil {
			continue
		}

		lbClient, err := armnetwork.NewLoadBalancersClient(subscription, clients.AzureCredential, nil)
		if err != nil {
			continue
		}

		// First, find the public IP that matches our IP address
		publicIPPager := publicIPClient.NewListAllPager(nil)
		var matchingPublicIP *armnetwork.PublicIPAddress

		for publicIPPager.More() {
			page, err := publicIPPager.NextPage(ctx)
			if err != nil {
				break // Try next subscription
			}
			for _, pip := range page.Value {
				if pip.Properties != nil && pip.Properties.IPAddress != nil && *pip.Properties.IPAddress == ipAddress {
					matchingPublicIP = pip
					break
				}
			}
			if matchingPublicIP != nil {
				break
			}
		}

		if matchingPublicIP == nil {
			continue // Try next subscription
		}

		// Now list all load balancers and find one that references this public IP
		lbPager := lbClient.NewListAllPager(nil)
		for lbPager.More() {
			page, err := lbPager.NextPage(ctx)
			if err != nil {
				break // Try next subscription
			}

			for _, lb := range page.Value {
				if lb.Properties == nil || lb.Properties.FrontendIPConfigurations == nil {
					continue
				}

				for _, feIP := range lb.Properties.FrontendIPConfigurations {
					if feIP.Properties != nil && feIP.Properties.PublicIPAddress != nil && feIP.Properties.PublicIPAddress.ID != nil {
						if matchingPublicIP.ID != nil && *feIP.Properties.PublicIPAddress.ID == *matchingPublicIP.ID {
							// Found matching load balancer
							info := &CloudNetworkInfo{
								Provider:  "Azure",
								LBName:    safeString(lb.Name),
								PublicIPs: []string{ipAddress},
							}

							// Extract location as region
							if lb.Location != nil {
								info.Region = *lb.Location
							}

							// Get SKU as LB type
							if lb.SKU != nil && lb.SKU.Name != nil {
								info.LBType = string(*lb.SKU.Name)
							}

							// Extract VNet/Subnet from frontend IP configuration
							if feIP.Properties.Subnet != nil && feIP.Properties.Subnet.ID != nil {
								// Subnet ID format: /subscriptions/.../resourceGroups/.../providers/Microsoft.Network/virtualNetworks/{vnet}/subnets/{subnet}
								subnetID := *feIP.Properties.Subnet.ID
								parts := strings.Split(subnetID, "/")
								for i, part := range parts {
									if part == "virtualNetworks" && i+1 < len(parts) {
										info.VPCID = parts[i+1] // VNet name
									}
									if part == "subnets" && i+1 < len(parts) {
										info.Subnets = append(info.Subnets, parts[i+1])
									}
								}
							}

							return info
						}
					}
				}
			}
		}
	}

	return nil
}

// correlateCloudNetwork attempts to correlate K8s network exposure with cloud network
func correlateCloudNetwork(ctx context.Context, clients *CloudClients, finding *NetworkExposureFinding, logger *internal.Logger) {
	if clients == nil {
		return
	}

	// Correlate LoadBalancer services and Ingress resources
	if finding.ExposureType != "LoadBalancer" && finding.ExposureType != "Ingress" {
		return
	}

	logger.InfoM(fmt.Sprintf("Cloud correlation: looking up %s/%s (IP: %s, Hostname: %s, Provider hint: %s)",
		finding.Namespace, finding.ResourceName, finding.IPAddress, finding.Hostname, finding.CloudProvider), globals.K8S_NETWORK_PORTS_MODULE_NAME)

	// Try AWS lookup (matches by hostname)
	if finding.CloudProvider == "AWS" || finding.CloudProvider == "Unknown" {
		hostname := finding.Hostname
		if hostname == "" && finding.IPAddress != "" {
			hostname = finding.IPAddress
		}
		if info := lookupAWSLoadBalancer(ctx, clients, hostname); info != nil {
			finding.CloudNetwork = info
			if finding.CloudProvider == "Unknown" {
				finding.CloudProvider = "AWS"
			}
			return
		}
	}

	// Try GCP lookups (multiple methods)
	if finding.CloudProvider == "GCP" || finding.CloudProvider == "Unknown" {
		// Method 1: Forwarding Rule by IP
		if info := lookupGCPForwardingRule(ctx, clients, finding.IPAddress, logger); info != nil {
			finding.CloudNetwork = info
			if finding.CloudProvider == "Unknown" {
				finding.CloudProvider = "GCP"
			}
			return
		}

		// Method 2: Address by IP (static external IPs)
		if info := lookupGCPAddress(ctx, clients, finding.IPAddress, logger); info != nil {
			finding.CloudNetwork = info
			if finding.CloudProvider == "Unknown" {
				finding.CloudProvider = "GCP"
			}
			return
		}

		// Method 3: NEG by namespace/service name pattern
		if info := lookupGCPNEG(ctx, clients, finding.Namespace, finding.ResourceName, logger); info != nil {
			finding.CloudNetwork = info
			if finding.CloudProvider == "Unknown" {
				finding.CloudProvider = "GCP"
			}
			return
		}

		// Method 4: Backend Service by namespace/service name pattern
		if info := lookupGCPBackendService(ctx, clients, finding.Namespace, finding.ResourceName, logger); info != nil {
			finding.CloudNetwork = info
			if finding.CloudProvider == "Unknown" {
				finding.CloudProvider = "GCP"
			}
			return
		}
	}

	// Try Azure lookup (matches by IP)
	if finding.CloudProvider == "Azure" || finding.CloudProvider == "Unknown" {
		if info := lookupAzureLoadBalancer(ctx, clients, finding.IPAddress); info != nil {
			finding.CloudNetwork = info
			if finding.CloudProvider == "Unknown" {
				finding.CloudProvider = "Azure"
			}
			return
		}
	}
}

// safeString safely dereferences a string pointer
func safeString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// formatCloudNetwork formats cloud network info for display (IPs shown in separate column)
func formatCloudNetwork(info *CloudNetworkInfo) string {
	if info == nil {
		return ""
	}

	parts := []string{}

	// VPC/Network
	if info.VPCID != "" {
		parts = append(parts, fmt.Sprintf("VPC:%s", info.VPCID))
	}

	// Region
	if info.Region != "" {
		parts = append(parts, fmt.Sprintf("Region:%s", info.Region))
	}

	// LB Type
	if info.LBType != "" {
		parts = append(parts, info.LBType)
	}

	// LB Name
	if info.LBName != "" {
		parts = append(parts, fmt.Sprintf("LB:%s", info.LBName))
	}

	// Subnets (show first 2)
	if len(info.Subnets) > 0 {
		subnets := info.Subnets
		if len(subnets) > 2 {
			subnets = subnets[:2]
			parts = append(parts, fmt.Sprintf("Subnets:%s...", strings.Join(subnets, ",")))
		} else {
			parts = append(parts, fmt.Sprintf("Subnets:%s", strings.Join(subnets, ",")))
		}
	}

	if len(parts) == 0 {
		return ""
	}

	return strings.Join(parts, " | ")
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
	ctx, cancel := shared.ContextWithTimeout()
	defer cancel()
	logger := internal.NewLogger()
	parentCmd := cmd.Parent()

	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating network exposures with security analysis for %s", globals.ClusterName), globals.K8S_NETWORK_PORTS_MODULE_NAME)

	clientset := config.GetClientOrExit()

	// Initialize cloud clients for optional correlation (errors suppressed)
	cloudClients := initCloudClients(&logger)

	var findings []NetworkExposureFinding
	var lootNmapCommands []string

	// Suppress stderr to hide noisy auth plugin errors (gke-gcloud-auth-plugin, aws-iam-authenticator, etc.)
	restoreStderr := sdk.SuppressStderr()

	// ---- Services Analysis
	services, err := clientset.CoreV1().Services(shared.GetNamespaceOrAll()).List(ctx, metav1.ListOptions{})
	if err != nil {
		shared.LogListError(&logger, "services", shared.GetNamespaceOrAll(), err, globals.K8S_NETWORK_PORTS_MODULE_NAME, false)
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

					// Correlate with cloud network (optional, errors suppressed)
					correlateCloudNetwork(ctx, cloudClients, &finding, &logger)

					findings = append(findings, finding)

					// Add nmap command
					appendNmapCommands(&lootNmapCommands, target, []corev1.ServicePort{port})
				}
			}
		}
	}

	// ---- HostPort Detection (Pods)
	pods, err := clientset.CoreV1().Pods(shared.GetNamespaceOrAll()).List(ctx, metav1.ListOptions{})
	if err != nil {
		shared.LogListError(&logger, "pods", shared.GetNamespaceOrAll(), err, globals.K8S_NETWORK_PORTS_MODULE_NAME, false)
	} else {
		for _, pod := range pods.Items {
			for _, container := range append(pod.Spec.Containers, pod.Spec.InitContainers...) {
				for _, port := range container.Ports {
					if port.HostPort != 0 {
						// Get workload owner or use pod name
						var workloads []string
						if ownerRef := getOwnerReference(&pod); ownerRef != "" {
							workloads = append(workloads, ownerRef)
						} else {
							workloads = append(workloads, fmt.Sprintf("Pod/%s", pod.Name))
						}

						finding := NetworkExposureFinding{
							Namespace:            pod.Namespace,
							ResourceType:         "Pod",
							ResourceName:         pod.Name,
							ExposureType:         "HostPort",
							Port:                 port.HostPort,
							TargetPort:           fmt.Sprintf("%d", port.ContainerPort),
							Protocol:             string(port.Protocol),
							IsInternetFacing:     pod.Spec.HostNetwork, // HostPort + HostNetwork = very exposed
							BackendHostNetwork:   pod.Spec.HostNetwork,
							BackendServiceAccount: pod.Spec.ServiceAccountName,
							BackendPods:          1,
							ExposedWorkloads:     workloads,
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
							finding.BackendSecurityIssues = append(finding.BackendSecurityIssues,
								fmt.Sprintf("Pod %s runs privileged container '%s'", pod.Name, container.Name))
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
	ingresses, err := clientset.NetworkingV1().Ingresses(shared.GetNamespaceOrAll()).List(ctx, metav1.ListOptions{})
	if err != nil {
		shared.LogListError(&logger, "ingresses", shared.GetNamespaceOrAll(), err, globals.K8S_NETWORK_PORTS_MODULE_NAME, false)
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

					// Trace backend services to find workloads
					var backendWorkloads []string
					var backendSA string
					var backendPodCount int
					for _, path := range rule.HTTP.Paths {
						if path.Backend.Service != nil {
							svcName := path.Backend.Service.Name
							// Look up the service and trace to pods
							svc, err := clientset.CoreV1().Services(ing.Namespace).Get(ctx, svcName, metav1.GetOptions{})
							if err == nil && len(svc.Spec.Selector) > 0 {
								labelSelector := labels.Set(svc.Spec.Selector).String()
								pods, err := clientset.CoreV1().Pods(ing.Namespace).List(ctx, metav1.ListOptions{
									LabelSelector: labelSelector,
								})
								if err == nil {
									backendPodCount += len(pods.Items)
									for _, pod := range pods.Items {
										if backendSA == "" {
											backendSA = pod.Spec.ServiceAccountName
										}
										ownerRef := getOwnerReference(&pod)
										if ownerRef != "" {
											if !networkExposureContains(backendWorkloads, ownerRef) {
												backendWorkloads = append(backendWorkloads, ownerRef)
											}
										} else {
											podRef := fmt.Sprintf("Pod/%s", pod.Name)
											if !networkExposureContains(backendWorkloads, podRef) {
												backendWorkloads = append(backendWorkloads, podRef)
											}
										}
									}
								}
							}
							// If no pods found, at least show the service
							if len(backendWorkloads) == 0 {
								backendWorkloads = append(backendWorkloads, fmt.Sprintf("Service/%s", svcName))
							}
						}
					}

					finding := NetworkExposureFinding{
						Namespace:             ing.Namespace,
						ResourceType:          "Ingress",
						ResourceName:          ing.Name,
						ExposureType:          "Ingress",
						Hostname:              rule.Host,
						Port:                  port,
						Protocol:              protocol,
						IsInternetFacing:      true, // Ingresses are typically internet-facing
						PortCategory:          "Web",
						PortDescription:       fmt.Sprintf("%s web service", protocol),
						DataExposureRisk:      "Web Application",
						ExposedWorkloads:      backendWorkloads,
						BackendServiceAccount: backendSA,
						BackendPods:           backendPodCount,
					}

					// Security issues
					if !hasTLS {
						finding.SecurityIssues = append(finding.SecurityIssues, "No TLS configured (unencrypted HTTP)")
					}

					// Attack path
					finding.AttackVector = buildAttackPath(finding)

					// Risk
					finding.RiskLevel = calculateNetworkExposureRisk(finding)

					// Correlate with cloud network for Ingress
					correlateCloudNetwork(ctx, cloudClients, &finding, &logger)

					findings = append(findings, finding)

					// Nmap
					if rule.Host != "" {
						appendNmapCommands(&lootNmapCommands, rule.Host, nil)
					}
				}
			}

			// Check for default backend (ingress without host rules or as fallback)
			if ing.Spec.DefaultBackend != nil && ing.Spec.DefaultBackend.Service != nil {
				svcName := ing.Spec.DefaultBackend.Service.Name

				// Trace backend to workloads
				var backendWorkloads []string
				var backendSA string
				var backendPodCount int

				svc, err := clientset.CoreV1().Services(ing.Namespace).Get(ctx, svcName, metav1.GetOptions{})
				if err == nil && len(svc.Spec.Selector) > 0 {
					labelSelector := labels.Set(svc.Spec.Selector).String()
					pods, err := clientset.CoreV1().Pods(ing.Namespace).List(ctx, metav1.ListOptions{
						LabelSelector: labelSelector,
					})
					if err == nil {
						backendPodCount = len(pods.Items)
						for _, pod := range pods.Items {
							if backendSA == "" {
								backendSA = pod.Spec.ServiceAccountName
							}
							ownerRef := getOwnerReference(&pod)
							if ownerRef != "" {
								if !networkExposureContains(backendWorkloads, ownerRef) {
									backendWorkloads = append(backendWorkloads, ownerRef)
								}
							} else {
								podRef := fmt.Sprintf("Pod/%s", pod.Name)
								if !networkExposureContains(backendWorkloads, podRef) {
									backendWorkloads = append(backendWorkloads, podRef)
								}
							}
						}
					}
				}
				if len(backendWorkloads) == 0 {
					backendWorkloads = append(backendWorkloads, fmt.Sprintf("Service/%s", svcName))
				}

				// Determine TLS from any TLS config
				hasTLS := len(ing.Spec.TLS) > 0
				port := int32(80)
				protocol := "HTTP"
				if hasTLS {
					port = 443
					protocol = "HTTPS"
				}

				finding := NetworkExposureFinding{
					Namespace:             ing.Namespace,
					ResourceType:          "Ingress",
					ResourceName:          ing.Name,
					ExposureType:          "Ingress",
					Hostname:              "(default)",
					Port:                  port,
					Protocol:              protocol,
					IsInternetFacing:      true,
					PortCategory:          "Web",
					PortDescription:       fmt.Sprintf("%s default backend", protocol),
					DataExposureRisk:      "Web Application",
					ExposedWorkloads:      backendWorkloads,
					BackendServiceAccount: backendSA,
					BackendPods:           backendPodCount,
				}

				if !hasTLS {
					finding.SecurityIssues = append(finding.SecurityIssues, "No TLS configured")
				}

				finding.AttackVector = buildAttackPath(finding)
				finding.RiskLevel = calculateNetworkExposureRisk(finding)

				// Correlate with cloud network for Ingress default backend
				correlateCloudNetwork(ctx, cloudClients, &finding, &logger)

				findings = append(findings, finding)
			}
		}
	}

	// Restore stderr now that K8s API calls are done
	restoreStderr()

	// ---- Build Table
	// Column order: Identity -> Exposure -> Target -> Security -> Backend -> Cloud
	headers := []string{
		"Namespace",
		"Name",
		"Type",
		"Exposure",
		"Internet",
		"IP Address",
		"Hostname",
		"Port",
		"Protocol",
		"TLS",
		"Net Policy",
		"Backend SA",
		"Backend Workloads",
		"Privileged",
		"Host Network",
		"Cloud IPs",
		"Cloud Network",
	}

	var rows [][]string
	for _, f := range findings {
		ipAddr := k8sinternal.NonEmpty(f.IPAddress)
		hostname := k8sinternal.NonEmpty(f.Hostname)

		// Internet-Facing
		internetFacing := ""
		if f.IsInternetFacing {
			internetFacing = "Yes"
		}

		// TLS
		tlsStr := ""
		if f.ResourceType == "Ingress" || f.ExposureType == "Ingress" {
			if f.Protocol == "HTTPS" {
				tlsStr = "Enabled"
			} else {
				tlsStr = "Disabled"
			}
		}

		// Net Policy - show policy names or None
		netPolicyStr := "None"
		if f.HasNetworkPolicy && len(f.NetworkPolicies) > 0 {
			netPolicyStr = strings.Join(f.NetworkPolicies, ", ")
		} else if f.HasNetworkPolicy {
			netPolicyStr = "Yes"
		}

		// Backend SA with cloud provider prefix (K for Kubernetes/unknown)
		backendSA := ""
		if f.BackendServiceAccount != "" {
			prefix := "(K) "
			switch f.CloudProvider {
			case "AWS":
				prefix = "(AWS) "
			case "Azure":
				prefix = "(AZ) "
			case "GCP":
				prefix = "(GCP) "
			}
			backendSA = prefix + f.BackendServiceAccount
		}

		// Backend Workloads - show workload names
		backendWorkloadsStr := ""
		if len(f.ExposedWorkloads) > 0 {
			backendWorkloadsStr = strings.Join(f.ExposedWorkloads, ", ")
		} else if f.BackendPods > 0 {
			backendWorkloadsStr = fmt.Sprintf("%d pods", f.BackendPods)
		}

		// Privileged - show container names or empty
		privilegedStr := ""
		if f.BackendPrivileged {
			// Extract container names from security issues
			privilegedStr = extractPrivilegedContainers(f.BackendSecurityIssues)
			if privilegedStr == "" {
				privilegedStr = "Yes"
			}
		}

		// Host Network
		hostNetworkStr := ""
		if f.BackendHostNetwork {
			hostNetworkStr = "Yes"
		}

		// Cloud IPs - show public IPs from cloud correlation
		cloudIPsStr := ""
		if f.CloudNetwork != nil && len(f.CloudNetwork.PublicIPs) > 0 {
			cloudIPsStr = strings.Join(f.CloudNetwork.PublicIPs, ", ")
		}

		// Cloud Network
		cloudNetworkStr := formatCloudNetwork(f.CloudNetwork)

		rows = append(rows, []string{
			k8sinternal.NonEmpty(f.Namespace),
			k8sinternal.NonEmpty(f.ResourceName),
			k8sinternal.NonEmpty(f.ResourceType),
			k8sinternal.NonEmpty(f.ExposureType),
			internetFacing,
			ipAddr,
			hostname,
			fmt.Sprintf("%d", f.Port),
			k8sinternal.NonEmpty(f.Protocol),
			tlsStr,
			netPolicyStr,
			backendSA,
			backendWorkloadsStr,
			privilegedStr,
			hostNetworkStr,
			cloudIPsStr,
			cloudNetworkStr,
		})
	}

	// ---- Build Loot Files (consolidated)
	loot := shared.NewLootBuilder()
	buildNetworkExposureCommandsLoot(loot, findings, lootNmapCommands)

	table := internal.TableFile{
		Name:   "Network-Exposure",
		Header: headers,
		Body:   rows,
	}

	lootFiles := loot.Build()

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
	riskCounts := shared.NewRiskCounts()
	internetFacingCount := 0
	for _, f := range findings {
		riskCounts.Add(f.RiskLevel)
		if f.IsInternetFacing {
			internetFacingCount++
		}
	}

	if len(rows) > 0 {
		logger.InfoM(fmt.Sprintf("%d network exposures found (%d CRITICAL, %d HIGH, %d internet-facing)",
			len(rows), riskCounts.Critical, riskCounts.High, internetFacingCount), globals.K8S_NETWORK_PORTS_MODULE_NAME)
	} else {
		logger.InfoM("No network exposures found, skipping output file creation", globals.K8S_NETWORK_PORTS_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_NETWORK_PORTS_MODULE_NAME), globals.K8S_NETWORK_PORTS_MODULE_NAME)
}

// buildNetworkExposureCommandsLoot creates a consolidated loot file
func buildNetworkExposureCommandsLoot(loot *shared.LootBuilder, findings []NetworkExposureFinding, nmapCommands []string) {
	section := loot.Section("NetworkExposure-Commands")
	section.SetHeader(`# ===========================================
# Network Exposure Enumeration Commands
# ===========================================`)

	if globals.KubeContext != "" {
		section.AddBlank().Addf("kubectl config use-context %s", globals.KubeContext)
	}

	// Basic enumeration commands
	section.AddBlank().
		Add("# List all services with external exposure:").
		Add("kubectl get svc -A -o wide | grep -E 'LoadBalancer|NodePort'").
		AddBlank().
		Add("# List LoadBalancer services:").
		Add("kubectl get svc -A --field-selector spec.type=LoadBalancer").
		AddBlank().
		Add("# List NodePort services:").
		Add("kubectl get svc -A --field-selector spec.type=NodePort").
		AddBlank().
		Add("# Find pods using HostPort:").
		Add("kubectl get pods -A -o json | jq -r '.items[] | select(.spec.containers[].ports[]?.hostPort != null) | \"\\(.metadata.namespace)/\\(.metadata.name)\"'").
		AddBlank().
		Add("# List ingresses:").
		Add("kubectl get ingress -A")

	// Internet-facing exposures
	var internetFacing []NetworkExposureFinding
	for _, f := range findings {
		if f.IsInternetFacing {
			internetFacing = append(internetFacing, f)
		}
	}

	if len(internetFacing) > 0 {
		section.AddBlank().
			Add("# -------------------------------------------").
			Add("# Internet-Facing Exposures").
			Add("# -------------------------------------------")

		for _, f := range internetFacing {
			section.AddBlank()
			target := f.Hostname
			if target == "" {
				target = f.IPAddress
			}
			section.Addf("# %s/%s - %s:%d (%s)", f.Namespace, f.ResourceName, target, f.Port, f.ExposureType)
			if f.ResourceType == "Service" {
				section.Addf("kubectl describe svc %s -n %s", f.ResourceName, f.Namespace)
			} else if f.ResourceType == "Ingress" {
				section.Addf("kubectl describe ingress %s -n %s", f.ResourceName, f.Namespace)
			}
		}
	}

	// Dangerous ports
	var dangerousPorts []NetworkExposureFinding
	for _, f := range findings {
		if f.IsDangerousPort {
			dangerousPorts = append(dangerousPorts, f)
		}
	}

	if len(dangerousPorts) > 0 {
		section.AddBlank().
			Add("# -------------------------------------------").
			Add("# Dangerous Port Exposures").
			Add("# -------------------------------------------")

		for _, f := range dangerousPorts {
			section.AddBlank().
				Addf("# %s/%s - Port %d (%s)", f.Namespace, f.ResourceName, f.Port, f.PortDescription)
		}
	}

	// HostPort exposures
	var hostPorts []NetworkExposureFinding
	for _, f := range findings {
		if f.ExposureType == "HostPort" {
			hostPorts = append(hostPorts, f)
		}
	}

	if len(hostPorts) > 0 {
		section.AddBlank().
			Add("# -------------------------------------------").
			Add("# HostPort Exposures (bypass NetworkPolicy)").
			Add("# -------------------------------------------")

		for _, f := range hostPorts {
			section.AddBlank().
				Addf("# %s/%s - HostPort %d", f.Namespace, f.ResourceName, f.Port).
				Addf("kubectl describe pod %s -n %s", f.ResourceName, f.Namespace)
		}
	}

	// Privileged backends
	var privilegedBackends []NetworkExposureFinding
	for _, f := range findings {
		if f.BackendPrivileged || f.BackendHostNetwork {
			privilegedBackends = append(privilegedBackends, f)
		}
	}

	if len(privilegedBackends) > 0 {
		section.AddBlank().
			Add("# -------------------------------------------").
			Add("# Exposures with Privileged Backends").
			Add("# -------------------------------------------")

		for _, f := range privilegedBackends {
			section.AddBlank().
				Addf("# %s/%s - Port %d", f.Namespace, f.ResourceName, f.Port)
			if f.BackendPrivileged {
				section.Add("# WARNING: Privileged containers")
			}
			if f.BackendHostNetwork {
				section.Add("# WARNING: Host network access")
			}
			section.Addf("# Attack Path: %s", f.AttackVector)
		}
	}

	// NMAP commands
	if len(nmapCommands) > 0 {
		section.AddBlank().
			Add("# -------------------------------------------").
			Add("# NMAP Scanning Commands").
			Add("# -------------------------------------------")

		seen := make(map[string]bool)
		for _, cmd := range nmapCommands {
			cmd = strings.TrimSpace(cmd)
			if cmd == "" || seen[cmd] {
				continue
			}
			seen[cmd] = true
			section.AddBlank().Add(cmd)
		}
	}
}
