// Package admission provides a shared SDK for admission controller detection across all admission modules.
// This centralizes engine detection, image verification, and risk assessment to reduce code duplication
// and ensure consistent, accurate detection with minimal false positives.
package admission

import (
	"regexp"
	"strings"
)

// EngineCategory represents the category of an admission engine
type EngineCategory string

const (
	CategoryImage        EngineCategory = "image"
	CategoryPod          EngineCategory = "pod"
	CategoryNetwork      EngineCategory = "network"
	CategorySecret       EngineCategory = "secret"
	CategoryDNS          EngineCategory = "dns"
	CategoryRuntime      EngineCategory = "runtime"
	CategoryMultitenancy EngineCategory = "multitenancy"
	CategoryCert         EngineCategory = "cert"
	CategoryMesh         EngineCategory = "mesh"
	CategoryAudit        EngineCategory = "audit"
)

// Engine represents a registered admission controller/engine
type Engine struct {
	// Unique identifier for the engine
	ID string

	// Human-readable name
	Name string

	// Category this engine belongs to
	Category EngineCategory

	// Trusted registries for this engine's images
	TrustedRegistries []string

	// Image patterns (exact match after registry prefix)
	// e.g., "falcosecurity/falco" matches "docker.io/falcosecurity/falco:latest"
	ImagePatterns []string

	// Compiled regex patterns for image matching (built from ImagePatterns)
	imageRegexes []*regexp.Regexp

	// Deployment/DaemonSet/StatefulSet name patterns (exact or prefix match)
	DeploymentPatterns []string

	// Namespace patterns where this engine is typically deployed
	ExpectedNamespaces []string

	// Webhook name patterns for detection
	WebhookPatterns []string

	// CRD groups this engine uses (for CRD-based detection)
	CRDGroups []string

	// Label selectors for pod detection
	LabelSelectors []string

	// Whether this engine requires image verification to be considered "active"
	RequireImageVerification bool
}

// EngineRegistry holds all registered engines across all categories
type EngineRegistry struct {
	engines map[string]*Engine
}

// NewEngineRegistry creates a new registry with all known engines
func NewEngineRegistry() *EngineRegistry {
	r := &EngineRegistry{
		engines: make(map[string]*Engine),
	}
	r.registerAllEngines()
	return r
}

// GetEngine returns an engine by ID
func (r *EngineRegistry) GetEngine(id string) *Engine {
	return r.engines[id]
}

// GetEnginesByCategory returns all engines in a category
func (r *EngineRegistry) GetEnginesByCategory(category EngineCategory) []*Engine {
	var result []*Engine
	for _, e := range r.engines {
		if e.Category == category {
			result = append(result, e)
		}
	}
	return result
}

// MatchImage checks if an image matches any engine and returns the engine ID
func (r *EngineRegistry) MatchImage(image string) (engineID string, verified bool) {
	imageLower := strings.ToLower(image)

	for id, engine := range r.engines {
		if engine.matchImage(imageLower) {
			return id, true
		}
	}
	return "", false
}

// MatchImageForEngine checks if an image matches a specific engine
func (r *EngineRegistry) MatchImageForEngine(image string, engineID string) bool {
	engine := r.engines[engineID]
	if engine == nil {
		return false
	}
	return engine.matchImage(strings.ToLower(image))
}

// matchImage checks if an image matches this engine's patterns
func (e *Engine) matchImage(imageLower string) bool {
	// Build regexes if not already built
	if len(e.imageRegexes) == 0 && len(e.ImagePatterns) > 0 {
		e.buildImageRegexes()
	}

	// First check trusted registry + pattern combination
	for _, registry := range e.TrustedRegistries {
		registryLower := strings.ToLower(registry)
		if strings.HasPrefix(imageLower, registryLower) {
			// Image is from trusted registry, now check pattern
			for _, regex := range e.imageRegexes {
				if regex.MatchString(imageLower) {
					return true
				}
			}
		}
	}

	// If no trusted registries defined, fall back to pattern-only matching
	// but mark as less confident (caller should check this)
	if len(e.TrustedRegistries) == 0 {
		for _, regex := range e.imageRegexes {
			if regex.MatchString(imageLower) {
				return true
			}
		}
	}

	return false
}

// buildImageRegexes compiles image patterns into regexes with proper boundaries
func (e *Engine) buildImageRegexes() {
	for _, pattern := range e.ImagePatterns {
		// Build regex with word boundaries to avoid substring false positives
		// Pattern "falco" should match "falcosecurity/falco:v1" but not "myfalconry:v1"
		escaped := regexp.QuoteMeta(strings.ToLower(pattern))
		// Match pattern at path boundaries (after / or at start) and before : or end
		regexStr := `(^|/)` + escaped + `(:|$|/)`
		if regex, err := regexp.Compile(regexStr); err == nil {
			e.imageRegexes = append(e.imageRegexes, regex)
		}
	}
}

// MatchDeploymentName checks if a deployment name matches this engine
func (e *Engine) MatchDeploymentName(name string) bool {
	nameLower := strings.ToLower(name)
	for _, pattern := range e.DeploymentPatterns {
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

// MatchWebhookName checks if a webhook name matches this engine
func (e *Engine) MatchWebhookName(name string) bool {
	nameLower := strings.ToLower(name)
	for _, pattern := range e.WebhookPatterns {
		patternLower := strings.ToLower(pattern)
		if nameLower == patternLower || strings.Contains(nameLower, patternLower) {
			return true
		}
	}
	return false
}

// IsExpectedNamespace checks if a namespace is expected for this engine
func (e *Engine) IsExpectedNamespace(namespace string) bool {
	if len(e.ExpectedNamespaces) == 0 {
		return true // No restriction
	}
	nsLower := strings.ToLower(namespace)
	for _, expected := range e.ExpectedNamespaces {
		if strings.ToLower(expected) == nsLower {
			return true
		}
	}
	return false
}

// registerAllEngines registers all known engines across all categories
func (r *EngineRegistry) registerAllEngines() {
	// Image admission engines
	r.registerImageEngines()
	// Pod admission engines
	r.registerPodEngines()
	// Network admission engines
	r.registerNetworkEngines()
	// Secret admission engines
	r.registerSecretEngines()
	// DNS admission engines
	r.registerDNSEngines()
	// Runtime admission engines
	r.registerRuntimeEngines()
	// Multitenancy engines
	r.registerMultitenancyEngines()
	// Certificate engines
	r.registerCertEngines()
	// Service mesh engines
	r.registerMeshEngines()
	// Audit engines
	r.registerAuditEngines()
}

func (r *EngineRegistry) register(e *Engine) {
	r.engines[e.ID] = e
}
