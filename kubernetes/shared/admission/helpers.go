package admission

import (
	"context"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Global engine registry singleton for all admission modules
var globalRegistry = NewEngineRegistry()

// GetRegistry returns the global admission engine registry
func GetRegistry() *EngineRegistry {
	return globalRegistry
}

// VerifyControllerImage checks if an image matches a known controller
func VerifyControllerImage(image string, engineID string) bool {
	verifier := NewImageVerifier(globalRegistry)
	result := verifier.VerifyImageForEngine(image, engineID)
	return result.Matched
}

// VerifyControllerImageAny checks if an image matches any known controller in a category
func VerifyControllerImageAny(image string, category EngineCategory) (string, bool) {
	verifier := NewImageVerifier(globalRegistry)
	result := verifier.VerifyImage(image)
	if result.Matched && result.Category == category {
		return result.EngineID, true
	}
	return "", false
}

// GetEngineByID returns an engine by its ID
func GetEngineByID(engineID string) *Engine {
	return globalRegistry.GetEngine(engineID)
}

// GetEnginesByCategory returns all engines in a category
func GetEnginesByCategory(category EngineCategory) []*Engine {
	return globalRegistry.GetEnginesByCategory(category)
}

// VerifyPodsRunning checks if controller pods are running and verifies images
func VerifyPodsRunning(ctx context.Context, clientset kubernetes.Interface, namespaces []string, labelSelector string, engineID string) (podsRunning bool, runningNamespace string, imageVerified bool, runningCount int, totalCount int) {
	for _, ns := range namespaces {
		opts := metav1.ListOptions{}
		if labelSelector != "" {
			opts.LabelSelector = labelSelector
		}
		pods, err := clientset.CoreV1().Pods(ns).List(ctx, opts)
		if err != nil || len(pods.Items) == 0 {
			continue
		}

		totalCount = len(pods.Items)
		for _, pod := range pods.Items {
			if pod.Status.Phase == "Running" {
				runningCount++
				for _, container := range pod.Spec.Containers {
					if VerifyControllerImage(container.Image, engineID) {
						imageVerified = true
					}
				}
			}
		}

		if runningCount > 0 {
			return true, ns, imageVerified, runningCount, totalCount
		}
	}
	return false, "", false, 0, 0
}

// DetectControllerByDeployment detects a controller by deployment name pattern
func DetectControllerByDeployment(ctx context.Context, clientset kubernetes.Interface, engineID string) (*DetectionResult, error) {
	detector := NewControllerDetector(globalRegistry)
	return detector.DetectControllerByEngine(ctx, clientset, engineID)
}

// DetectControllersByCategory detects all controllers in a category
func DetectControllersByCategory(ctx context.Context, clientset kubernetes.Interface, category EngineCategory) ([]DetectionResult, error) {
	detector := NewControllerDetector(globalRegistry)
	return detector.DetectControllers(ctx, clientset, category)
}

// AnalyzeWebhooksByCategory analyzes webhooks for a category
func AnalyzeWebhooksByCategory(ctx context.Context, clientset kubernetes.Interface, category EngineCategory) ([]WebhookInfo, error) {
	analyzer := NewWebhookAnalyzer(globalRegistry)
	return analyzer.AnalyzeWebhooks(ctx, clientset, category)
}

// AnalyzeWebhooksByEngine analyzes webhooks for a specific engine
func AnalyzeWebhooksByEngine(ctx context.Context, clientset kubernetes.Interface, engineID string) ([]WebhookInfo, error) {
	analyzer := NewWebhookAnalyzer(globalRegistry)
	return analyzer.AnalyzeWebhookByEngine(ctx, clientset, engineID)
}

// MatchesEngineWebhook checks if a webhook name matches an engine's patterns
func MatchesEngineWebhook(webhookName string, engineID string) bool {
	engine := globalRegistry.GetEngine(engineID)
	if engine == nil {
		return false
	}
	return engine.MatchWebhookName(webhookName)
}

// MatchesEngineDeployment checks if a deployment name matches an engine's patterns
func MatchesEngineDeployment(deploymentName string, engineID string) bool {
	engine := globalRegistry.GetEngine(engineID)
	if engine == nil {
		return false
	}
	return engine.MatchDeploymentName(deploymentName)
}

// IsExpectedNamespace checks if a namespace is expected for an engine
func IsExpectedNamespace(namespace string, engineID string) bool {
	engine := globalRegistry.GetEngine(engineID)
	if engine == nil {
		return false
	}
	return engine.IsExpectedNamespace(namespace)
}

// GetExpectedNamespaces returns expected namespaces for an engine
func GetExpectedNamespaces(engineID string) []string {
	engine := globalRegistry.GetEngine(engineID)
	if engine == nil {
		return nil
	}
	return engine.ExpectedNamespaces
}

// GetEngineLabelSelectors returns label selectors for an engine
func GetEngineLabelSelectors(engineID string) []string {
	engine := globalRegistry.GetEngine(engineID)
	if engine == nil {
		return nil
	}
	return engine.LabelSelectors
}

// GetEngineCRDGroups returns CRD groups for an engine
func GetEngineCRDGroups(engineID string) []string {
	engine := globalRegistry.GetEngine(engineID)
	if engine == nil {
		return nil
	}
	return engine.CRDGroups
}

// VerifyImageFromTrustedRegistry checks if image is from a trusted registry for the engine
func VerifyImageFromTrustedRegistry(image string, engineID string) bool {
	engine := globalRegistry.GetEngine(engineID)
	if engine == nil {
		return false
	}
	imageLower := strings.ToLower(image)
	for _, registry := range engine.TrustedRegistries {
		if strings.HasPrefix(imageLower, strings.ToLower(registry)) {
			return true
		}
	}
	return false
}
