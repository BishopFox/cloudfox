package kubernetes

import (
	"context"
	"math/rand"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
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

// GetClusterName retrieves the cluster name using an authenticated clientset
func GetClusterName(clientset *kubernetes.Clientset) string {
	ctx := context.Background()

	// Attempt 1: check node labels for cluster name
	nodes, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, node := range nodes.Items {
			labels := node.GetLabels()
			knownKeys := []string{
				"eks.amazonaws.com/cluster-name",
				"cluster.x-k8s.io/cluster-name",
				"kubernetes.azure.com/cluster",
				"googleapis.com/cluster-name",
			}
			for _, key := range knownKeys {
				if val, ok := labels[key]; ok && val != "" {
					return val
				}
			}
			// fallback: anything containing "cluster"
			for k, v := range labels {
				if strings.Contains(strings.ToLower(k), "cluster") && v != "" {
					return v
				}
			}
		}
	}

	// Attempt 2: fallback to kubeconfig/current context
	if clientset.RESTClient() != nil {
		return "unknown-cluster-" + randomSuffix()
	}

	return "unknown-cluster-" + randomSuffix()
}
