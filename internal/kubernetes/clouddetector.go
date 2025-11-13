package kubernetes

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// CloudRoleDetectionResult holds a unified detection
type CloudRoleDetectionResult struct {
	Provider string
	Role     string
	Source   string // e.g., "pod env", "pod annotation", "serviceaccount annotation", "configmap", "secret"
}

// DetectCloudRole inspects PodSpec + annotations + ServiceAccount for cloud roles.
func DetectCloudRole(ctx context.Context, clientset *kubernetes.Clientset, namespace, serviceAccountName string, podSpec *corev1.PodSpec, annotations map[string]string) []CloudRoleDetectionResult {
	results := []CloudRoleDetectionResult{}

	// --- 1. Pod annotations ---
	for k, v := range annotations {
		if provider, role, ok := ClassifyCloudRole(v); ok {
			results = append(results, CloudRoleDetectionResult{
				Provider: provider,
				Role:     role,
				Source:   fmt.Sprintf("pod annotation %s", k),
			})
		}
	}

	// --- 2. ServiceAccount annotations ---
	if podSpec.ServiceAccountName != "" {
		sa, err := clientset.CoreV1().ServiceAccounts(namespace).Get(ctx, podSpec.ServiceAccountName, metav1.GetOptions{})
		if err == nil {
			for k, v := range sa.Annotations {
				if provider, role, ok := ClassifyCloudRole(v); ok {
					results = append(results, CloudRoleDetectionResult{
						Provider: provider,
						Role:     role,
						Source:   fmt.Sprintf("serviceaccount %s annotation %s", podSpec.ServiceAccountName, k),
					})
				}
			}
		}
	}

	// --- 3. Environment variables (direct values) ---
	for _, c := range podSpec.Containers {
		for _, e := range c.Env {
			if e.Value != "" {
				if provider, role, ok := ClassifyCloudRole(e.Value); ok {
					results = append(results, CloudRoleDetectionResult{
						Provider: provider,
						Role:     role,
						Source:   fmt.Sprintf("pod env %s", e.Name),
					})
				}
			}
		}
	}

	// --- 4. Env sourced from ConfigMaps/Secrets ---
	for _, c := range podSpec.Containers {
		for _, e := range c.Env {
			if e.ValueFrom != nil && e.ValueFrom.ConfigMapKeyRef != nil {
				cmName := e.ValueFrom.ConfigMapKeyRef.Name
				key := e.ValueFrom.ConfigMapKeyRef.Key
				cm, err := clientset.CoreV1().ConfigMaps(namespace).Get(ctx, cmName, metav1.GetOptions{})
				if err == nil {
					if val := SafeGet(cm.Data, key); val != "" {
						if provider, role, ok := ClassifyCloudRole(val); ok {
							results = append(results, CloudRoleDetectionResult{
								Provider: provider,
								Role:     role,
								Source:   fmt.Sprintf("configmap %s/%s key %s", namespace, cmName, key),
							})
						}
					}
				}
			}
			if e.ValueFrom != nil && e.ValueFrom.SecretKeyRef != nil {
				secName := e.ValueFrom.SecretKeyRef.Name
				key := e.ValueFrom.SecretKeyRef.Key
				sec, err := clientset.CoreV1().Secrets(namespace).Get(ctx, secName, metav1.GetOptions{})
				if err == nil {
					if val := SafeGetString(sec.Data, key); val != "" {
						if provider, role, ok := ClassifyCloudRole(val); ok {
							results = append(results, CloudRoleDetectionResult{
								Provider: provider,
								Role:     role,
								Source:   fmt.Sprintf("secret %s/%s key %s", namespace, secName, key),
							})
						}
					}
				}
			}
		}
	}

	// --- Deduplicate ---
	return DeduplicateDetections(results)
}

// Deduplicate results by Provider+Role
func DeduplicateDetections(in []CloudRoleDetectionResult) []CloudRoleDetectionResult {
	seen := map[string]bool{}
	out := []CloudRoleDetectionResult{}
	for _, r := range in {
		key := r.Provider + "|" + r.Role
		if !seen[key] {
			seen[key] = true
			out = append(out, r)
		}
	}
	return out
}

// SafeGetString fetches from Secret.Data safely
func SafeGetString(m map[string][]byte, key string) string {
	if m == nil {
		return ""
	}
	val, ok := m[key]
	if !ok {
		return ""
	}
	return strings.TrimSpace(string(val))
}

// DetectCloudProviderFromNode detects the cloud provider from Node.Spec.ProviderID
func DetectCloudProviderFromNode(providerID string) string {
	if providerID == "" {
		return ""
	}
	switch {
	case strings.HasPrefix(providerID, "aws://"):
		return "AWS"
	case strings.HasPrefix(providerID, "gce://"):
		return "GCP"
	case strings.HasPrefix(providerID, "azure://"):
		return "Azure"
	default:
		return "Unknown"
	}
}

// DetectCloudRoleFromNodeLabels returns a role (string) based on node labels (optional)
func DetectCloudRoleFromNodeLabels(labels map[string]string) string {
	if labels == nil {
		return ""
	}
	// Example: AWS node IAM role label
	if role, ok := labels["iam.amazonaws.com/role"]; ok {
		return role
	}
	// Add other label-based detection if needed
	return ""
}
