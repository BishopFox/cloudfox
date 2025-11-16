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
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

var EndpointsCmd = &cobra.Command{
	Use:     "endpoints",
	Aliases: []string{"ep"},
	Short:   "List all cluster Endpoints with security analysis",
	Long: `
List all cluster Endpoints with comprehensive security analysis including:
- Service discovery and classification (databases, admin panels, control plane)
- Risk-based scoring for prioritized targeting
- Direct network access commands for lateral movement
- Service-specific exploitation techniques
- Unauthenticated service detection
  cloudfox kubernetes endpoints`,
	Run: ListEndpoints,
}

type EndpointsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t EndpointsOutput) TableFiles() []internal.TableFile {
	return t.Table
}

func (t EndpointsOutput) LootFiles() []internal.LootFile {
	return t.Loot
}

type EndpointFinding struct {
	Namespace       string
	ServiceName     string
	EndpointIP      string
	Port            int32
	Protocol        string
	Readiness       string
	ServiceType     string
	ServiceDesc     string
	RiskLevel       string
	IsExternal      bool
	HasAuth         bool
	PodName         string
	ServiceAccount  string
	TargetRef       string
	Hostname        string
}

func ListEndpoints(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating endpoints for %s", globals.ClusterName), globals.K8S_ENDPOINTS_MODULE_NAME)

	clientset := config.GetClientOrExit()

	endpoints, err := clientset.CoreV1().Endpoints("").List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing endpoints: %v", err), globals.K8S_ENDPOINTS_MODULE_NAME)
		return
	}

	// Also fetch EndpointSlices for more complete data
	_, err = clientset.DiscoveryV1().EndpointSlices("").List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing endpoint slices: %v", err), globals.K8S_ENDPOINTS_MODULE_NAME)
		// Continue without EndpointSlices
	}

	headers := []string{
		"Risk", "Service Type", "Service Description", "Namespace", "Service Name",
		"Readiness", "IP", "Port", "Protocol", "Exposure", "Authentication",
		"Pod Name", "Service Account", "Hostname", "Target Ref",
	}

	var outputRows [][]string
	var findings []EndpointFinding

	// Risk level counters
	riskCounts := map[string]int{
		"CRITICAL": 0,
		"HIGH":     0,
		"MEDIUM":   0,
		"LOW":      0,
	}

	// Loot collections
	var lootEnum []string
	var lootDirectAccess []string
	var lootDatabases []string
	var lootControlPlane []string
	var lootUnauthenticated []string
	var lootExploitation []string
	var lootPortForwardTCP []string
	var lootPortForwardUDP []string

	// Initialize loot files with headers
	lootEnum = append(lootEnum, `#####################################
##### Enumerate Endpoint Information
#####################################

`)
	lootDirectAccess = append(lootDirectAccess, `#####################################
##### Direct Network Access
#####################################
#
# Use these commands from within a compromised pod
# for direct IP:port access without kubectl
#
`)
	lootDatabases = append(lootDatabases, `#####################################
##### Database Endpoints
#####################################
#
# Database connection strings and enumeration
#
`)
	lootControlPlane = append(lootControlPlane, `#####################################
##### Kubernetes Control Plane Endpoints
#####################################
#
# CRITICAL: Direct access to K8s control plane
# These can lead to full cluster compromise
#
`)
	lootUnauthenticated = append(lootUnauthenticated, `#####################################
##### Unauthenticated Services
#####################################
#
# Services that typically don't require authentication
# Priority targets for lateral movement
#
`)
	lootExploitation = append(lootExploitation, `#####################################
##### Service-Specific Exploitation
#####################################
#
# Protocol-specific exploitation techniques
#
`)
	lootPortForwardTCP = append(lootPortForwardTCP, `#####################################
##### TCP Port-Forward Commands
#####################################

`)
	lootPortForwardUDP = append(lootPortForwardUDP, `#####################################
##### UDP Port-Forward Commands
#####################################

`)

	if globals.KubeContext != "" {
		contextCmd := fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext)
		lootEnum = append(lootEnum, contextCmd)
		lootPortForwardTCP = append(lootPortForwardTCP, contextCmd)
		lootPortForwardUDP = append(lootPortForwardUDP, contextCmd)
	}

	// Namespace organization
	namespaceToEndpoints := map[string][]string{}

	// Process traditional Endpoints
	for _, endpoint := range endpoints.Items {
		if len(endpoint.Subsets) == 0 {
			continue
		}

		namespace := endpoint.Namespace
		serviceName := endpoint.Name

		// Try to get the associated Service for more context
		svc, _ := clientset.CoreV1().Services(namespace).Get(ctx, serviceName, metav1.GetOptions{})
		isExternal := false
		if svc != nil {
			if svc.Spec.Type == "LoadBalancer" || svc.Spec.Type == "NodePort" || len(svc.Spec.ExternalIPs) > 0 {
				isExternal = true
			}
		}

		// Add enumeration command
		cmd := fmt.Sprintf(
			`kubectl -n %s get endpoints %s -o json | jq '{
	Namespace: .metadata.namespace,
	Name: .metadata.name,
	Subsets: [.subsets[] | {
		Addresses: [.addresses[]? | {IP:.ip, Hostname:.hostname, TargetRef:.targetRef}],
		NotReadyAddresses: [.notReadyAddresses[]? | {IP:.ip, Hostname:.hostname, TargetRef:.targetRef}],
		Ports: [.ports[] | {Port:.port, Protocol:.protocol}]
	}]}'`,
			namespace, serviceName)
		namespaceToEndpoints[namespace] = append(namespaceToEndpoints[namespace], cmd)

		// Process each subset
		for _, subset := range endpoint.Subsets {
			// Process ready addresses
			for _, addr := range subset.Addresses {
				processEndpointAddress(ctx, clientset, &findings, &outputRows, &riskCounts,
					namespace, serviceName, addr, subset.Ports, "Ready", isExternal,
					&lootDirectAccess, &lootDatabases, &lootControlPlane,
					&lootUnauthenticated, &lootExploitation,
					&lootPortForwardTCP, &lootPortForwardUDP)
			}

			// Process not-ready addresses
			for _, addr := range subset.NotReadyAddresses {
				processEndpointAddress(ctx, clientset, &findings, &outputRows, &riskCounts,
					namespace, serviceName, addr, subset.Ports, "NotReady", isExternal,
					&lootDirectAccess, &lootDatabases, &lootControlPlane,
					&lootUnauthenticated, &lootExploitation,
					&lootPortForwardTCP, &lootPortForwardUDP)
			}
		}
	}

	// Build enumeration loot file
	namespaces := make([]string, 0, len(namespaceToEndpoints))
	for ns := range namespaceToEndpoints {
		namespaces = append(namespaces, ns)
	}
	sort.Strings(namespaces)
	for _, ns := range namespaces {
		lootEnum = append(lootEnum, fmt.Sprintf("\n# Namespace: %s\n", ns))
		lootEnum = append(lootEnum, namespaceToEndpoints[ns]...)
	}

	// Add summaries to loot files
	if riskCounts["CRITICAL"] > 0 || riskCounts["HIGH"] > 0 {
		summary := fmt.Sprintf(`
# SUMMARY: Risk Distribution
# CRITICAL: %d endpoints
# HIGH: %d endpoints
# MEDIUM: %d endpoints
# LOW: %d endpoints
#
# Focus on CRITICAL and HIGH risk endpoints for maximum impact
`, riskCounts["CRITICAL"], riskCounts["HIGH"], riskCounts["MEDIUM"], riskCounts["LOW"])

		lootDirectAccess = append([]string{summary}, lootDirectAccess...)
		lootDatabases = append([]string{summary}, lootDatabases...)
		lootControlPlane = append([]string{summary}, lootControlPlane...)
		lootUnauthenticated = append([]string{summary}, lootUnauthenticated...)
		lootExploitation = append([]string{summary}, lootExploitation...)
	}

	// Define table and loot files
	table := internal.TableFile{
		Name:   "Endpoints",
		Header: headers,
		Body:   outputRows,
	}

	lootFiles := []internal.LootFile{
		{Name: "Endpoint-Enum", Contents: strings.Join(lootEnum, "\n")},
		{Name: "Endpoint-Direct-Access", Contents: strings.Join(lootDirectAccess, "\n")},
		{Name: "Endpoint-Databases", Contents: strings.Join(lootDatabases, "\n")},
		{Name: "Endpoint-Control-Plane", Contents: strings.Join(lootControlPlane, "\n")},
		{Name: "Endpoint-Unauthenticated", Contents: strings.Join(lootUnauthenticated, "\n")},
		{Name: "Endpoint-Exploitation", Contents: strings.Join(lootExploitation, "\n")},
		{Name: "Endpoint-PortForward-TCP", Contents: strings.Join(lootPortForwardTCP, "\n")},
		{Name: "Endpoint-PortForward-UDP", Contents: strings.Join(lootPortForwardUDP, "\n")},
	}

	// Output everything
	err = internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"Endpoints",
		globals.ClusterName,
		"results",
		EndpointsOutput{
			Table: []internal.TableFile{table},
			Loot:  lootFiles,
		},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_ENDPOINTS_MODULE_NAME)
		return
	}

	if len(outputRows) > 0 {
		logger.InfoM(fmt.Sprintf("%d endpoints found | Risk: CRITICAL=%d, HIGH=%d, MEDIUM=%d, LOW=%d",
			len(outputRows),
			riskCounts["CRITICAL"], riskCounts["HIGH"], riskCounts["MEDIUM"], riskCounts["LOW"]),
			globals.K8S_ENDPOINTS_MODULE_NAME)
	} else {
		logger.InfoM("No endpoints found, skipping output file creation", globals.K8S_ENDPOINTS_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_ENDPOINTS_MODULE_NAME), globals.K8S_ENDPOINTS_MODULE_NAME)
}

func processEndpointAddress(
	ctx context.Context,
	clientset *kubernetes.Clientset,
	findings *[]EndpointFinding,
	outputRows *[][]string,
	riskCounts *map[string]int,
	namespace string,
	serviceName string,
	addr v1.EndpointAddress,
	ports []v1.EndpointPort,
	readiness string,
	isExternal bool,
	lootDirectAccess *[]string,
	lootDatabases *[]string,
	lootControlPlane *[]string,
	lootUnauthenticated *[]string,
	lootExploitation *[]string,
	lootPortForwardTCP *[]string,
	lootPortForwardUDP *[]string,
) {
	ip := addr.IP
	hostname := addr.Hostname
	targetRef := formatTargetRef(addr.TargetRef)

	// Get pod details if target is a pod
	podName := ""
	serviceAccount := ""
	if addr.TargetRef != nil && addr.TargetRef.Kind == "Pod" {
		podName = addr.TargetRef.Name
		pod, err := clientset.CoreV1().Pods(addr.TargetRef.Namespace).Get(ctx, addr.TargetRef.Name, metav1.GetOptions{})
		if err == nil {
			serviceAccount = pod.Spec.ServiceAccountName
		}
	}

	// Process each port
	for _, port := range ports {
		portNum := port.Port
		protocol := string(port.Protocol)

		// Classify service
		classification := k8sinternal.ClassifyServiceByPort(portNum)

		// Check if unauthenticated
		hasAuth := !k8sinternal.IsUnauthenticatedService(portNum, serviceName)

		// Calculate risk
		riskLevel := k8sinternal.GetServiceRiskLevel(
			classification.Type,
			portNum,
			isExternal,
			readiness == "Ready",
			hasAuth,
		)

		(*riskCounts)[riskLevel]++

		// Create finding
		finding := EndpointFinding{
			Namespace:      namespace,
			ServiceName:    serviceName,
			EndpointIP:     ip,
			Port:           portNum,
			Protocol:       protocol,
			Readiness:      readiness,
			ServiceType:    classification.Type,
			ServiceDesc:    classification.Description,
			RiskLevel:      riskLevel,
			IsExternal:     isExternal,
			HasAuth:        hasAuth,
			PodName:        podName,
			ServiceAccount: serviceAccount,
			TargetRef:      targetRef,
			Hostname:       hostname,
		}
		*findings = append(*findings, finding)

		// Build table row
		exposure := "Internal"
		if isExternal {
			exposure = "External"
		}

		authStatus := "Required"
		if !hasAuth {
			authStatus = "None"
		}

		row := []string{
			riskLevel,
			classification.Type,
			classification.Description,
			namespace,
			serviceName,
			readiness,
			k8sinternal.NonEmpty(ip),
			fmt.Sprintf("%d", portNum),
			protocol,
			exposure,
			authStatus,
			k8sinternal.NonEmpty(podName),
			k8sinternal.NonEmpty(serviceAccount),
			k8sinternal.NonEmpty(hostname),
			targetRef,
		}
		*outputRows = append(*outputRows, row)

		// Generate loot based on service type and risk
		endpointID := fmt.Sprintf("%s/%s:%s:%d", namespace, serviceName, ip, portNum)

		// Direct Access Loot
		*lootDirectAccess = append(*lootDirectAccess, fmt.Sprintf("\n### [%s] %s - %s", riskLevel, endpointID, classification.Description))
		if protocol == "TCP" {
			*lootDirectAccess = append(*lootDirectAccess, fmt.Sprintf("nc -zv %s %d", ip, portNum))
			*lootDirectAccess = append(*lootDirectAccess, fmt.Sprintf("nmap -sV -p %d %s", portNum, ip))
			if portNum == 80 || portNum == 8080 || portNum == 8000 || portNum == 8888 {
				*lootDirectAccess = append(*lootDirectAccess, fmt.Sprintf("curl -v http://%s:%d/", ip, portNum))
			} else if portNum == 443 || portNum == 8443 {
				*lootDirectAccess = append(*lootDirectAccess, fmt.Sprintf("curl -kv https://%s:%d/", ip, portNum))
			}
		} else if protocol == "UDP" {
			*lootDirectAccess = append(*lootDirectAccess, fmt.Sprintf("nc -zuv %s %d", ip, portNum))
		}
		*lootDirectAccess = append(*lootDirectAccess, "")

		// Database Loot
		if classification.Type == "Database" {
			*lootDatabases = append(*lootDatabases, fmt.Sprintf("\n### [%s] %s - %s", riskLevel, endpointID, classification.Description))
			connStr := k8sinternal.GetDatabaseConnectionString(classification.Description, ip, portNum, "root", "database")
			*lootDatabases = append(*lootDatabases, connStr)
			techniques := k8sinternal.GetServiceExploitationTechniques(classification.Type, serviceName, ip, portNum)
			*lootDatabases = append(*lootDatabases, techniques...)
			*lootDatabases = append(*lootDatabases, "")
		}

		// Control Plane Loot
		if classification.Type == "ControlPlane" {
			*lootControlPlane = append(*lootControlPlane, fmt.Sprintf("\n### [%s] %s - %s", riskLevel, endpointID, classification.Description))
			techniques := k8sinternal.GetServiceExploitationTechniques(classification.Type, serviceName, ip, portNum)
			*lootControlPlane = append(*lootControlPlane, techniques...)
			*lootControlPlane = append(*lootControlPlane, "")
		}

		// Unauthenticated Services Loot
		if !hasAuth {
			*lootUnauthenticated = append(*lootUnauthenticated, fmt.Sprintf("\n### [%s] %s - %s (NO AUTH)", riskLevel, endpointID, classification.Description))
			*lootUnauthenticated = append(*lootUnauthenticated, "# This service typically does not require authentication")
			techniques := k8sinternal.GetServiceExploitationTechniques(classification.Type, serviceName, ip, portNum)
			*lootUnauthenticated = append(*lootUnauthenticated, techniques...)
			*lootUnauthenticated = append(*lootUnauthenticated, "")
		}

		// Exploitation Loot (for all HIGH/CRITICAL services)
		if riskLevel == "CRITICAL" || riskLevel == "HIGH" {
			*lootExploitation = append(*lootExploitation, fmt.Sprintf("\n### [%s] %s - %s", riskLevel, endpointID, classification.Description))
			if isExternal {
				*lootExploitation = append(*lootExploitation, "# WARNING: This endpoint is EXTERNALLY ACCESSIBLE")
			}
			if !hasAuth {
				*lootExploitation = append(*lootExploitation, "# This service typically has NO AUTHENTICATION")
			}
			techniques := k8sinternal.GetServiceExploitationTechniques(classification.Type, serviceName, ip, portNum)
			*lootExploitation = append(*lootExploitation, techniques...)
			*lootExploitation = append(*lootExploitation, "")
		}

		// Port-Forward Loot
		if protocol == "TCP" {
			*lootPortForwardTCP = append(*lootPortForwardTCP,
				fmt.Sprintf("# [%s] %s - %s", riskLevel, endpointID, classification.Description))
			*lootPortForwardTCP = append(*lootPortForwardTCP,
				fmt.Sprintf("kubectl -n %s port-forward svc/%s %d:%d\n", namespace, serviceName, portNum, portNum))
		} else if protocol == "UDP" {
			*lootPortForwardUDP = append(*lootPortForwardUDP,
				fmt.Sprintf("# [%s] %s - %s", riskLevel, endpointID, classification.Description))
			*lootPortForwardUDP = append(*lootPortForwardUDP,
				fmt.Sprintf("kubectl run udp-forwarder --image=alpine --restart=Never --rm -it -- sh -c \"apk add socat && socat UDP4-LISTEN:%d,fork UDP4:%s:%d\"\n",
					portNum, ip, portNum))
		}
	}
}

func formatTargetRef(ref *v1.ObjectReference) string {
	if ref == nil {
		return "<NONE>"
	}
	return fmt.Sprintf("%s/%s", ref.Kind, ref.Name)
}
