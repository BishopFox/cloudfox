package commands

import (
	"context"
	"strings"

	"github.com/BishopFox/cloudfox/kubernetes/shared/admission"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Global engine registry for all admission modules
var admissionRegistry = admission.NewEngineRegistry()

// GetAdmissionRegistry returns the global admission engine registry
func GetAdmissionRegistry() *admission.EngineRegistry {
	return admissionRegistry
}

// VerifyControllerImage checks if an image matches a known controller using the SDK
func VerifyControllerImage(image string, engineID string) bool {
	verifier := admission.NewImageVerifier(admissionRegistry)
	result := verifier.VerifyImageForEngine(image, engineID)
	return result.Matched
}

// VerifyControllerImageAny checks if an image matches any known controller in a category
func VerifyControllerImageAny(image string, category admission.EngineCategory) (string, bool) {
	verifier := admission.NewImageVerifier(admissionRegistry)
	result := verifier.VerifyImage(image)
	if result.Matched && result.Category == category {
		return result.EngineID, true
	}
	return "", false
}

// GetEngineByID returns an engine by its ID
func GetEngineByID(engineID string) *admission.Engine {
	return admissionRegistry.GetEngine(engineID)
}

// GetEnginesByCategory returns all engines in a category
func GetEnginesByCategory(category admission.EngineCategory) []*admission.Engine {
	return admissionRegistry.GetEnginesByCategory(category)
}

// VerifyPodsRunningWithSDK checks if controller pods are running and verifies images using SDK
func VerifyPodsRunningWithSDK(ctx context.Context, clientset kubernetes.Interface, namespaces []string, labelSelector string, engineID string) (podsRunning bool, runningNamespace string, imageVerified bool, runningCount int, totalCount int) {
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
				// Check images using SDK
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

// DetectControllerByDeployment detects a controller by deployment name pattern using SDK
func DetectControllerByDeployment(ctx context.Context, clientset kubernetes.Interface, engineID string) (*admission.DetectionResult, error) {
	detector := admission.NewControllerDetector(admissionRegistry)
	return detector.DetectControllerByEngine(ctx, clientset, engineID)
}

// DetectControllersByCategory detects all controllers in a category using SDK
func DetectControllersByCategory(ctx context.Context, clientset kubernetes.Interface, category admission.EngineCategory) ([]admission.DetectionResult, error) {
	detector := admission.NewControllerDetector(admissionRegistry)
	return detector.DetectControllers(ctx, clientset, category)
}

// AnalyzeWebhooksByCategory analyzes webhooks for a category using SDK
func AnalyzeWebhooksByCategory(ctx context.Context, clientset kubernetes.Interface, category admission.EngineCategory) ([]admission.WebhookInfo, error) {
	analyzer := admission.NewWebhookAnalyzer(admissionRegistry)
	return analyzer.AnalyzeWebhooks(ctx, clientset, category)
}

// AnalyzeWebhooksByEngine analyzes webhooks for a specific engine using SDK
func AnalyzeWebhooksByEngine(ctx context.Context, clientset kubernetes.Interface, engineID string) ([]admission.WebhookInfo, error) {
	analyzer := admission.NewWebhookAnalyzer(admissionRegistry)
	return analyzer.AnalyzeWebhookByEngine(ctx, clientset, engineID)
}

// MatchesEngineWebhook checks if a webhook name matches an engine's patterns
func MatchesEngineWebhook(webhookName string, engineID string) bool {
	engine := admissionRegistry.GetEngine(engineID)
	if engine == nil {
		return false
	}
	return engine.MatchWebhookName(webhookName)
}

// MatchesEngineDeployment checks if a deployment name matches an engine's patterns
func MatchesEngineDeployment(deploymentName string, engineID string) bool {
	engine := admissionRegistry.GetEngine(engineID)
	if engine == nil {
		return false
	}
	return engine.MatchDeploymentName(deploymentName)
}

// IsExpectedNamespace checks if a namespace is expected for an engine
func IsExpectedNamespace(namespace string, engineID string) bool {
	engine := admissionRegistry.GetEngine(engineID)
	if engine == nil {
		return false
	}
	return engine.IsExpectedNamespace(namespace)
}

// GetExpectedNamespaces returns expected namespaces for an engine
func GetExpectedNamespaces(engineID string) []string {
	engine := admissionRegistry.GetEngine(engineID)
	if engine == nil {
		return nil
	}
	return engine.ExpectedNamespaces
}

// GetEngineLabelSelectors returns label selectors for an engine
func GetEngineLabelSelectors(engineID string) []string {
	engine := admissionRegistry.GetEngine(engineID)
	if engine == nil {
		return nil
	}
	return engine.LabelSelectors
}

// GetEngineCRDGroups returns CRD groups for an engine
func GetEngineCRDGroups(engineID string) []string {
	engine := admissionRegistry.GetEngine(engineID)
	if engine == nil {
		return nil
	}
	return engine.CRDGroups
}

// VerifyImageFromTrustedRegistry checks if image is from a trusted registry for the engine
func VerifyImageFromTrustedRegistry(image string, engineID string) bool {
	engine := admissionRegistry.GetEngine(engineID)
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

// Engine category constants re-exported for convenience
const (
	CategoryImage        = admission.CategoryImage
	CategoryPod          = admission.CategoryPod
	CategoryNetwork      = admission.CategoryNetwork
	CategorySecret       = admission.CategorySecret
	CategoryDNS          = admission.CategoryDNS
	CategoryRuntime      = admission.CategoryRuntime
	CategoryMultitenancy = admission.CategoryMultitenancy
	CategoryCert         = admission.CategoryCert
	CategoryMesh         = admission.CategoryMesh
	CategoryAudit        = admission.CategoryAudit
)
