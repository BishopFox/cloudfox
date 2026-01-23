package commands

import (
	"context"
	"fmt"
	"net"
	"sort"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	k8sinternal "github.com/BishopFox/cloudfox/internal/kubernetes"
	"github.com/BishopFox/cloudfox/kubernetes/shared"
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
	ctx, cancel := shared.ContextWithCancel()
	defer cancel()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating endpoints for %s", globals.ClusterName), globals.K8S_ENDPOINTS_MODULE_NAME)

	clientset := config.GetClientOrExit()

	// Using v1 Endpoints API for broader compatibility (deprecated in k8s 1.33+, use EndpointSlices for newer clusters)
	endpoints, err := clientset.CoreV1().Endpoints(shared.GetNamespaceOrAll()).List(ctx, metav1.ListOptions{})
	if err != nil {
		shared.LogListError(&logger, "endpoints", shared.GetNamespaceOrAll(), err, globals.K8S_ENDPOINTS_MODULE_NAME, true)
		return
	}

	headers := []string{
		"Namespace", "Service Name", "Hostname", "IP", "Port", "Protocol",
		"Service Type", "Exposure", "Auth", "Readiness",
		"Pod Name", "Service Account", "Description",
	}

	var outputRows [][]string
	var findings []EndpointFinding

	// Risk level counters
	riskCounts := shared.NewRiskCounts()

	// Loot collections
	loot := shared.NewLootBuilder()

	// Initialize two loot files
	// 1. Network commands (nmap, curl, nc) - for use from within a pod
	netCmds := loot.Section("Endpoint-Network-Commands")
	netCmds.Add("═══════════════════════════════════════════════════════════════")
	netCmds.Add("         ENDPOINT NETWORK COMMANDS (nmap, curl, nc)")
	netCmds.Add("═══════════════════════════════════════════════════════════════")
	netCmds.Add("")
	netCmds.Add("# Run these commands from within a compromised pod")
	netCmds.Add("# Install tools: apk add nmap curl netcat-openbsd")
	netCmds.Add("")

	// 2. Port-forward commands - kubectl commands from outside
	pfCmds := loot.Section("Endpoint-PortForward")
	pfCmds.Add("═══════════════════════════════════════════════════════════════")
	pfCmds.Add("         ENDPOINT PORT-FORWARD COMMANDS (kubectl)")
	pfCmds.Add("═══════════════════════════════════════════════════════════════")
	pfCmds.Add("")

	if globals.KubeContext != "" {
		pfCmds.Addf("kubectl config use-context %s", globals.KubeContext)
		pfCmds.Add("")
	}

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

		// Process each subset
		for _, subset := range endpoint.Subsets {
			// Process ready addresses
			for _, addr := range subset.Addresses {
				processEndpointAddress(ctx, clientset, &findings, &outputRows, riskCounts,
					namespace, serviceName, addr, subset.Ports, "Ready", isExternal, loot)
			}

			// Process not-ready addresses
			for _, addr := range subset.NotReadyAddresses {
				processEndpointAddress(ctx, clientset, &findings, &outputRows, riskCounts,
					namespace, serviceName, addr, subset.Ports, "NotReady", isExternal, loot)
			}
		}
	}

	// Generate loot content from findings
	generateEndpointLootSections(loot, findings)

	// Define table and loot files
	table := internal.TableFile{
		Name:   "Endpoints",
		Header: headers,
		Body:   outputRows,
	}

	lootFiles := loot.Build()

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
			riskCounts.Critical, riskCounts.High, riskCounts.Medium, riskCounts.Low),
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
	riskCounts *shared.RiskCounts,
	namespace string,
	serviceName string,
	addr v1.EndpointAddress,
	ports []v1.EndpointPort,
	readiness string,
	isExternal bool,
	loot *shared.LootBuilder,
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

		riskCounts.Add(riskLevel)

		// Determine if endpoint is external (service type OR IP is public)
		ipIsExternal := ip != "" && !isPrivateIP(ip)
		endpointIsExternal := isExternal || ipIsExternal

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
			IsExternal:     endpointIsExternal,
			HasAuth:        hasAuth,
			PodName:        podName,
			ServiceAccount: serviceAccount,
			TargetRef:      targetRef,
			Hostname:       hostname,
		}
		*findings = append(*findings, finding)

		// Build table row
		// Determine exposure label for display
		exposure := "Internal"
		if endpointIsExternal {
			if ipIsExternal && !isExternal {
				exposure = "External (IP)" // IP itself is external, even if service isn't LoadBalancer/NodePort
			} else {
				exposure = "External"
			}
		}

		authStatus := "Yes"
		if !hasAuth {
			authStatus = "No"
		}

		// Truncate description if too long
		desc := classification.Description
		if len(desc) > 30 {
			desc = desc[:27] + "..."
		}

		row := []string{
			namespace,
			serviceName,
			k8sinternal.NonEmpty(hostname),
			k8sinternal.NonEmpty(ip),
			fmt.Sprintf("%d", portNum),
			protocol,
			classification.Type,
			exposure,
			authStatus,
			readiness,
			k8sinternal.NonEmpty(podName),
			k8sinternal.NonEmpty(serviceAccount),
			desc,
		}
		*outputRows = append(*outputRows, row)

		// Store endpoint info for later loot generation
		// The actual loot content is generated after all endpoints are processed
	}
}

func formatTargetRef(ref *v1.ObjectReference) string {
	if ref == nil {
		return "<NONE>"
	}
	return fmt.Sprintf("%s/%s", ref.Kind, ref.Name)
}

// isPrivateIP checks if an IP address is in a private/internal range
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// Private and internal IP ranges
	privateRanges := []string{
		"10.0.0.0/8",      // RFC1918 Class A
		"172.16.0.0/12",   // RFC1918 Class B
		"192.168.0.0/16",  // RFC1918 Class C
		"127.0.0.0/8",     // Loopback
		"169.254.0.0/16",  // Link-local
		"100.64.0.0/10",   // Carrier-grade NAT (RFC6598)
		"fc00::/7",        // IPv6 unique local
		"fe80::/10",       // IPv6 link-local
		"::1/128",         // IPv6 loopback
	}

	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// generateEndpointLootSections creates two loot files: network commands and port-forward commands
func generateEndpointLootSections(loot *shared.LootBuilder, findings []EndpointFinding) {
	netCmds := loot.Section("Endpoint-Network-Commands")
	pfCmds := loot.Section("Endpoint-PortForward")

	// Collect unique IPs for nmap
	ipSet := make(map[string]bool)
	for _, f := range findings {
		if f.EndpointIP != "" {
			ipSet[f.EndpointIP] = true
		}
	}
	ips := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		ips = append(ips, ip)
	}
	sort.Strings(ips)

	// ============================================
	// Network Commands (nmap, curl, nc)
	// ============================================

	// Nmap section
	netCmds.Add("##############################################")
	netCmds.Add("## NMAP SCANS")
	netCmds.Add("##############################################")
	netCmds.Add("")

	if len(ips) > 0 {
		netCmds.Add("# Quick service scan of all endpoint IPs")
		for _, ip := range ips {
			netCmds.Addf("nmap -sV -T4 %s", ip)
		}
		netCmds.Add("")

		netCmds.Add("# Full port scan (slower)")
		for _, ip := range ips {
			netCmds.Addf("nmap -sV -p- %s", ip)
		}
		netCmds.Add("")
	}

	// Curl/nc section organized by service type
	netCmds.Add("##############################################")
	netCmds.Add("## CURL / NETCAT COMMANDS")
	netCmds.Add("##############################################")
	netCmds.Add("")

	for _, f := range findings {
		endpointID := fmt.Sprintf("%s/%s:%d", f.Namespace, f.ServiceName, f.Port)

		// Generate appropriate commands based on port/protocol
		if f.Protocol == "TCP" {
			// HTTP ports
			if f.Port == 80 || f.Port == 8080 || f.Port == 8000 || f.Port == 8888 || f.Port == 3000 {
				netCmds.Addf("# %s (%s)", endpointID, f.ServiceDesc)
				netCmds.Addf("curl -sv http://%s:%d/", f.EndpointIP, f.Port)
				netCmds.Add("")
			} else if f.Port == 443 || f.Port == 8443 || f.Port == 6443 {
				// HTTPS ports
				netCmds.Addf("# %s (%s)", endpointID, f.ServiceDesc)
				netCmds.Addf("curl -skv https://%s:%d/", f.EndpointIP, f.Port)
				netCmds.Add("")
			} else if f.ServiceType == "Database" {
				// Database ports - nc check
				netCmds.Addf("# %s (%s)", endpointID, f.ServiceDesc)
				netCmds.Addf("nc -zv %s %d", f.EndpointIP, f.Port)
				connStr := k8sinternal.GetDatabaseConnectionString(f.ServiceDesc, f.EndpointIP, f.Port, "<user>", "<database>")
				if connStr != "" {
					netCmds.Add(connStr)
				}
				netCmds.Add("")
			} else {
				// Other TCP ports - nc check
				netCmds.Addf("# %s (%s)", endpointID, f.ServiceDesc)
				netCmds.Addf("nc -zv %s %d", f.EndpointIP, f.Port)
				netCmds.Add("")
			}
		} else if f.Protocol == "UDP" {
			netCmds.Addf("# %s (%s) [UDP]", endpointID, f.ServiceDesc)
			netCmds.Addf("nc -zuv %s %d", f.EndpointIP, f.Port)
			netCmds.Add("")
		}
	}

	// ============================================
	// Port-Forward Commands (kubectl)
	// ============================================

	// Track unique service/port combinations to avoid duplicates
	seen := make(map[string]bool)

	pfCmds.Add("##############################################")
	pfCmds.Add("## TCP PORT-FORWARDS")
	pfCmds.Add("##############################################")
	pfCmds.Add("")

	for _, f := range findings {
		if f.Protocol != "TCP" {
			continue
		}
		key := fmt.Sprintf("%s/%s:%d", f.Namespace, f.ServiceName, f.Port)
		if seen[key] {
			continue
		}
		seen[key] = true

		pfCmds.Addf("# %s (%s)", key, f.ServiceDesc)
		pfCmds.Addf("kubectl -n %s port-forward svc/%s %d:%d", f.Namespace, f.ServiceName, f.Port, f.Port)
		pfCmds.Add("")
	}

	// UDP section
	hasUDP := false
	for _, f := range findings {
		if f.Protocol == "UDP" {
			hasUDP = true
			break
		}
	}

	if hasUDP {
		pfCmds.Add("##############################################")
		pfCmds.Add("## UDP PORT-FORWARDS (via socat pod)")
		pfCmds.Add("##############################################")
		pfCmds.Add("")
		pfCmds.Add("# kubectl port-forward doesn't support UDP")
		pfCmds.Add("# Use a socat pod as a relay instead")
		pfCmds.Add("")

		seen = make(map[string]bool)
		for _, f := range findings {
			if f.Protocol != "UDP" {
				continue
			}
			key := fmt.Sprintf("%s/%s:%d", f.Namespace, f.ServiceName, f.Port)
			if seen[key] {
				continue
			}
			seen[key] = true

			pfCmds.Addf("# %s (%s)", key, f.ServiceDesc)
			pfCmds.Addf("kubectl run udp-relay-%d --image=alpine --restart=Never -n %s -- sh -c 'apk add --no-cache socat && socat UDP4-LISTEN:%d,fork UDP4:%s:%d'",
				f.Port, f.Namespace, f.Port, f.EndpointIP, f.Port)
			pfCmds.Add("")
		}
	}
}
