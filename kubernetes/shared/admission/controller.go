package admission

import (
	"context"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// ControllerDetector provides centralized detection of admission controllers
type ControllerDetector struct {
	registry *EngineRegistry
	verifier *ImageVerifier
}

// NewControllerDetector creates a new ControllerDetector
func NewControllerDetector(registry *EngineRegistry) *ControllerDetector {
	return &ControllerDetector{
		registry: registry,
		verifier: NewImageVerifier(registry),
	}
}

// DetectionResult contains details about a detected controller
type DetectionResult struct {
	EngineID      string
	EngineName    string
	Category      EngineCategory
	Namespace     string
	ResourceName  string
	ResourceKind  string // Deployment, DaemonSet, StatefulSet
	Replicas      int32
	ReadyReplicas int32
	Images        []string
	ImageVerified bool
	Confidence    string // "high", "medium", "low"
	Labels        map[string]string
}

// DetectControllers finds all admission controllers in the cluster
func (d *ControllerDetector) DetectControllers(ctx context.Context, clientset kubernetes.Interface, category EngineCategory) ([]DetectionResult, error) {
	var results []DetectionResult

	engines := d.registry.GetEnginesByCategory(category)

	// Check all expected namespaces for this category
	namespacesToCheck := make(map[string]bool)
	for _, engine := range engines {
		for _, ns := range engine.ExpectedNamespaces {
			namespacesToCheck[ns] = true
		}
	}

	// Always check kube-system
	namespacesToCheck["kube-system"] = true

	for ns := range namespacesToCheck {
		// Check Deployments
		deployments, err := clientset.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
		if err == nil {
			for _, dep := range deployments.Items {
				if result := d.checkDeployment(dep, engines); result != nil {
					results = append(results, *result)
				}
			}
		}

		// Check DaemonSets
		daemonSets, err := clientset.AppsV1().DaemonSets(ns).List(ctx, metav1.ListOptions{})
		if err == nil {
			for _, ds := range daemonSets.Items {
				if result := d.checkDaemonSet(ds, engines); result != nil {
					results = append(results, *result)
				}
			}
		}

		// Check StatefulSets
		statefulSets, err := clientset.AppsV1().StatefulSets(ns).List(ctx, metav1.ListOptions{})
		if err == nil {
			for _, ss := range statefulSets.Items {
				if result := d.checkStatefulSet(ss, engines); result != nil {
					results = append(results, *result)
				}
			}
		}
	}

	return results, nil
}

// DetectControllerByEngine finds a specific engine's controller
func (d *ControllerDetector) DetectControllerByEngine(ctx context.Context, clientset kubernetes.Interface, engineID string) (*DetectionResult, error) {
	engine := d.registry.GetEngine(engineID)
	if engine == nil {
		return nil, nil
	}

	engines := []*Engine{engine}

	for _, ns := range engine.ExpectedNamespaces {
		// Check Deployments
		deployments, err := clientset.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
		if err == nil {
			for _, dep := range deployments.Items {
				if result := d.checkDeployment(dep, engines); result != nil {
					return result, nil
				}
			}
		}

		// Check DaemonSets
		daemonSets, err := clientset.AppsV1().DaemonSets(ns).List(ctx, metav1.ListOptions{})
		if err == nil {
			for _, ds := range daemonSets.Items {
				if result := d.checkDaemonSet(ds, engines); result != nil {
					return result, nil
				}
			}
		}

		// Check StatefulSets
		statefulSets, err := clientset.AppsV1().StatefulSets(ns).List(ctx, metav1.ListOptions{})
		if err == nil {
			for _, ss := range statefulSets.Items {
				if result := d.checkStatefulSet(ss, engines); result != nil {
					return result, nil
				}
			}
		}
	}

	return nil, nil
}

func (d *ControllerDetector) checkDeployment(dep appsv1.Deployment, engines []*Engine) *DetectionResult {
	images := extractContainerImages(dep.Spec.Template.Spec.Containers)

	for _, engine := range engines {
		// First check deployment name patterns
		if !d.matchesDeploymentName(dep.Name, engine) {
			continue
		}

		// Then verify images
		imageVerified := false
		for _, img := range images {
			result := d.verifier.VerifyImageForEngine(img, engine.ID)
			if result.Matched {
				imageVerified = true
				break
			}
		}

		// If engine requires image verification and we didn't find it, skip
		if engine.RequireImageVerification && !imageVerified {
			continue
		}

		confidence := "medium"
		if imageVerified {
			confidence = "high"
		}

		return &DetectionResult{
			EngineID:      engine.ID,
			EngineName:    engine.Name,
			Category:      engine.Category,
			Namespace:     dep.Namespace,
			ResourceName:  dep.Name,
			ResourceKind:  "Deployment",
			Replicas:      *dep.Spec.Replicas,
			ReadyReplicas: dep.Status.ReadyReplicas,
			Images:        images,
			ImageVerified: imageVerified,
			Confidence:    confidence,
			Labels:        dep.Labels,
		}
	}

	return nil
}

func (d *ControllerDetector) checkDaemonSet(ds appsv1.DaemonSet, engines []*Engine) *DetectionResult {
	images := extractContainerImages(ds.Spec.Template.Spec.Containers)

	for _, engine := range engines {
		// First check deployment name patterns
		if !d.matchesDeploymentName(ds.Name, engine) {
			continue
		}

		// Then verify images
		imageVerified := false
		for _, img := range images {
			result := d.verifier.VerifyImageForEngine(img, engine.ID)
			if result.Matched {
				imageVerified = true
				break
			}
		}

		// If engine requires image verification and we didn't find it, skip
		if engine.RequireImageVerification && !imageVerified {
			continue
		}

		confidence := "medium"
		if imageVerified {
			confidence = "high"
		}

		return &DetectionResult{
			EngineID:      engine.ID,
			EngineName:    engine.Name,
			Category:      engine.Category,
			Namespace:     ds.Namespace,
			ResourceName:  ds.Name,
			ResourceKind:  "DaemonSet",
			Replicas:      ds.Status.DesiredNumberScheduled,
			ReadyReplicas: ds.Status.NumberReady,
			Images:        images,
			ImageVerified: imageVerified,
			Confidence:    confidence,
			Labels:        ds.Labels,
		}
	}

	return nil
}

func (d *ControllerDetector) checkStatefulSet(ss appsv1.StatefulSet, engines []*Engine) *DetectionResult {
	images := extractContainerImages(ss.Spec.Template.Spec.Containers)

	for _, engine := range engines {
		// First check deployment name patterns
		if !d.matchesDeploymentName(ss.Name, engine) {
			continue
		}

		// Then verify images
		imageVerified := false
		for _, img := range images {
			result := d.verifier.VerifyImageForEngine(img, engine.ID)
			if result.Matched {
				imageVerified = true
				break
			}
		}

		// If engine requires image verification and we didn't find it, skip
		if engine.RequireImageVerification && !imageVerified {
			continue
		}

		confidence := "medium"
		if imageVerified {
			confidence = "high"
		}

		return &DetectionResult{
			EngineID:      engine.ID,
			EngineName:    engine.Name,
			Category:      engine.Category,
			Namespace:     ss.Namespace,
			ResourceName:  ss.Name,
			ResourceKind:  "StatefulSet",
			Replicas:      *ss.Spec.Replicas,
			ReadyReplicas: ss.Status.ReadyReplicas,
			Images:        images,
			ImageVerified: imageVerified,
			Confidence:    confidence,
			Labels:        ss.Labels,
		}
	}

	return nil
}

func (d *ControllerDetector) matchesDeploymentName(name string, engine *Engine) bool {
	nameLower := strings.ToLower(name)
	for _, pattern := range engine.DeploymentPatterns {
		patternLower := strings.ToLower(pattern)
		// Exact match or prefix match with hyphen boundary
		if nameLower == patternLower ||
			strings.HasPrefix(nameLower, patternLower+"-") ||
			strings.HasSuffix(nameLower, "-"+patternLower) {
			return true
		}
	}
	return false
}

func extractContainerImages(containers []corev1.Container) []string {
	var images []string
	for _, c := range containers {
		images = append(images, c.Image)
	}
	return images
}
