package kubernetes

import (
	"context"
	"math/rand"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/BishopFox/cloudfox/globals"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// randomSuffix generates a random 6-character alphanumeric string
func randomSuffix() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, 6)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

// GetClusterName retrieves the cluster name using multiple detection methods
func GetClusterName(clientset *kubernetes.Clientset) string {
	ctx := context.Background()

	// Attempt 1: Check node labels for cluster name (most authoritative)
	if name := getClusterNameFromNodes(ctx, clientset); name != "" {
		return name
	}

	// Attempt 2: Parse kubeconfig context name (very reliable)
	if name := getClusterNameFromKubeconfig(); name != "" {
		return name
	}

	// Attempt 3: Extract from API server URL (cloud provider specific)
	if name := getClusterNameFromAPIServer(clientset); name != "" {
		return name
	}

	// Attempt 4: Force an error and parse the cluster info from it
	if name := getClusterNameFromError(ctx, clientset); name != "" {
		return name
	}

	return "unknown-cluster-" + randomSuffix()
}

// getClusterNameFromNodes checks node labels for cluster name
func getClusterNameFromNodes(ctx context.Context, clientset *kubernetes.Clientset) string {
	nodes, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{Limit: 1})
	if err != nil {
		return ""
	}

	for _, node := range nodes.Items {
		labels := node.GetLabels()

		// Check known cloud provider labels first
		knownKeys := []string{
			"eks.amazonaws.com/cluster-name",        // AWS EKS
			"kubernetes.azure.com/cluster",          // Azure AKS
			"cloud.google.com/gke-nodepool",         // GKE (nodepool contains cluster info)
			"cluster.x-k8s.io/cluster-name",         // Cluster API
			"alpha.eksctl.io/cluster-name",          // eksctl
			"kops.k8s.io/instancegroup",             // kops
		}
		for _, key := range knownKeys {
			if val, ok := labels[key]; ok && val != "" {
				// For GKE nodepool, try to extract cluster name from node name
				if key == "cloud.google.com/gke-nodepool" {
					if gkeName := extractGKEClusterFromNodeName(node.Name); gkeName != "" {
						return gkeName
					}
				}
				return val
			}
		}

		// Check provider ID for cloud-specific parsing
		if providerID := node.Spec.ProviderID; providerID != "" {
			if name := extractClusterFromProviderID(providerID); name != "" {
				return name
			}
		}

		// Fallback: any label containing "cluster"
		for k, v := range labels {
			if strings.Contains(strings.ToLower(k), "cluster") && v != "" && !strings.Contains(v, "/") {
				return v
			}
		}
	}

	return ""
}

// getClusterNameFromKubeconfig extracts cluster name from kubeconfig context
func getClusterNameFromKubeconfig() string {
	if globals.KubeConfigPath == "" {
		return ""
	}

	kubeconfig, err := clientcmd.LoadFromFile(globals.KubeConfigPath)
	if err != nil {
		return ""
	}

	// Determine which context to use
	contextName := globals.KubeContext
	if contextName == "" {
		contextName = kubeconfig.CurrentContext
	}
	if contextName == "" {
		return ""
	}

	ctx, ok := kubeconfig.Contexts[contextName]
	if !ok {
		return ""
	}

	// Get cluster name from context
	clusterName := ctx.Cluster
	if clusterName == "" {
		return ""
	}

	// For EKS: context often looks like "arn:aws:eks:us-east-1:123456789012:cluster/my-cluster"
	if strings.HasPrefix(clusterName, "arn:aws:eks:") {
		if name := extractEKSClusterName(clusterName); name != "" {
			return name
		}
	}

	// For AKS: context often looks like "my-aks-cluster" directly or "my-resource-group_my-aks-cluster"
	if strings.Contains(clusterName, "_") {
		parts := strings.Split(clusterName, "_")
		if len(parts) >= 2 {
			return parts[len(parts)-1] // Return last part (cluster name)
		}
	}

	// For GKE: context often looks like "gke_project-id_zone_cluster-name"
	if strings.HasPrefix(clusterName, "gke_") {
		if name := extractGKEClusterName(clusterName); name != "" {
			return name
		}
	}

	// For generic kubeconfigs, return the cluster name as-is if it's reasonable
	if !strings.Contains(clusterName, ":") && len(clusterName) < 100 {
		return clusterName
	}

	return ""
}

// getClusterNameFromAPIServer extracts cluster name from API server URL
func getClusterNameFromAPIServer(clientset *kubernetes.Clientset) string {
	if clientset.RESTClient() == nil {
		return ""
	}

	apiURL := clientset.RESTClient().Get().URL()
	if apiURL == nil {
		return ""
	}

	host := apiURL.Host

	// EKS: https://<hash>.gr7.us-east-1.eks.amazonaws.com
	if strings.Contains(host, ".eks.amazonaws.com") {
		// Can't get cluster name from URL, but we know it's EKS
		return ""
	}

	// AKS: https://<cluster>-<resource-group>-<random>.<region>.azmk8s.io:443
	if strings.Contains(host, ".azmk8s.io") {
		return extractAKSClusterFromURL(host)
	}

	// GKE: https://<ip> or https://<hash>.gke.goog
	if strings.Contains(host, ".gke.goog") {
		return "" // Can't extract name from GKE URL
	}

	// Generic: try to extract from hostname
	if name := extractClusterFromHostname(host); name != "" {
		return name
	}

	return ""
}

// getClusterNameFromError forces an error and parses cluster info from it
func getClusterNameFromError(ctx context.Context, clientset *kubernetes.Clientset) string {
	// Try to access a non-existent resource to get an error with cluster info
	_, err := clientset.CoreV1().Namespaces().Get(ctx, "cloudfox-nonexistent-namespace-probe", metav1.GetOptions{})
	if err != nil {
		errStr := err.Error()

		// Some clusters include cluster name in error messages
		// Example: "namespaces \"cloudfox-nonexistent\" not found" with cluster context

		// Check for server URL in error
		if strings.Contains(errStr, "server") {
			re := regexp.MustCompile(`server[:\s]+["']?([^"'\s]+)["']?`)
			if match := re.FindStringSubmatch(errStr); len(match) > 1 {
				if parsed, parseErr := url.Parse(match[1]); parseErr == nil {
					if name := extractClusterFromHostname(parsed.Host); name != "" {
						return name
					}
				}
			}
		}
	}

	return ""
}

// extractEKSClusterName extracts cluster name from EKS ARN
// Format: arn:aws:eks:region:account:cluster/cluster-name
func extractEKSClusterName(arn string) string {
	re := regexp.MustCompile(`arn:aws:eks:[^:]+:[^:]+:cluster/(.+)$`)
	if match := re.FindStringSubmatch(arn); len(match) > 1 {
		return match[1]
	}
	return ""
}

// extractGKEClusterName extracts cluster name from GKE context
// Format: gke_project-id_zone_cluster-name
func extractGKEClusterName(context string) string {
	parts := strings.Split(context, "_")
	if len(parts) >= 4 && parts[0] == "gke" {
		return parts[len(parts)-1]
	}
	return ""
}

// extractGKEClusterFromNodeName extracts cluster name from GKE node name
// Format: gke-cluster-name-nodepool-name-random
func extractGKEClusterFromNodeName(nodeName string) string {
	if !strings.HasPrefix(nodeName, "gke-") {
		return ""
	}
	parts := strings.Split(nodeName, "-")
	if len(parts) < 3 {
		return ""
	}
	// Find where nodepool name starts (usually has "pool" or "default-pool")
	for i := 1; i < len(parts)-1; i++ {
		if parts[i] == "pool" || parts[i] == "default" {
			return strings.Join(parts[1:i], "-")
		}
	}
	// Fallback: take parts[1] as cluster name
	return parts[1]
}

// extractAKSClusterFromURL extracts cluster name from AKS API server URL
// Format: cluster-resourcegroup-random.region.azmk8s.io
func extractAKSClusterFromURL(host string) string {
	// Remove port if present
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}

	parts := strings.Split(host, ".")
	if len(parts) < 3 {
		return ""
	}

	// First part is: cluster-resourcegroup-random
	nameParts := strings.Split(parts[0], "-")
	if len(nameParts) >= 2 {
		// Return first part as cluster name (rough heuristic)
		return nameParts[0]
	}

	return ""
}

// extractClusterFromProviderID extracts cluster hints from provider ID
func extractClusterFromProviderID(providerID string) string {
	// AWS: aws:///us-east-1a/i-xxxxx
	// GCE: gce://project/zone/instance-name
	// Azure: azure:///subscriptions/xxx/resourceGroups/xxx/providers/Microsoft.Compute/virtualMachineScaleSets/xxx/virtualMachines/xxx

	// For Azure, try to extract resource group (often named after cluster)
	if strings.HasPrefix(providerID, "azure://") {
		re := regexp.MustCompile(`resourceGroups/([^/]+)`)
		if match := re.FindStringSubmatch(providerID); len(match) > 1 {
			// Resource group often contains cluster name
			rg := match[1]
			// AKS resource groups are often: MC_<resource-group>_<cluster-name>_<region>
			if strings.HasPrefix(rg, "MC_") {
				parts := strings.Split(rg, "_")
				if len(parts) >= 3 {
					return parts[2] // cluster name
				}
			}
			return rg
		}
	}

	return ""
}

// extractClusterFromHostname attempts to extract cluster name from generic hostname
func extractClusterFromHostname(host string) string {
	// Remove port if present
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}

	// Skip IP addresses
	if isIPAddress(host) {
		return ""
	}

	// For hostnames like "kubernetes.default.svc.cluster.local" or similar
	if strings.Contains(host, "kubernetes") || strings.Contains(host, "cluster.local") {
		return ""
	}

	// For simple hostnames, return the first segment
	parts := strings.Split(host, ".")
	if len(parts) > 0 && len(parts[0]) > 0 && len(parts[0]) < 64 {
		return parts[0]
	}

	return ""
}

// isIPAddress checks if a string is an IP address
func isIPAddress(s string) bool {
	// Simple check for IPv4
	parts := strings.Split(s, ".")
	if len(parts) == 4 {
		for _, part := range parts {
			if len(part) > 3 {
				return false
			}
			for _, c := range part {
				if c < '0' || c > '9' {
					return false
				}
			}
		}
		return true
	}

	// Check for IPv6 (contains colons)
	if strings.Contains(s, ":") && !strings.Contains(s, ".") {
		return true
	}

	return false
}
