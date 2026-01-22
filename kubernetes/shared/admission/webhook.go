package admission

import (
	"context"
	"strings"

	admissionregv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// WebhookAnalyzer provides centralized webhook detection and analysis
type WebhookAnalyzer struct {
	registry *EngineRegistry
}

// NewWebhookAnalyzer creates a new WebhookAnalyzer
func NewWebhookAnalyzer(registry *EngineRegistry) *WebhookAnalyzer {
	return &WebhookAnalyzer{
		registry: registry,
	}
}

// WebhookInfo contains detailed information about a webhook
type WebhookInfo struct {
	Name           string
	Type           string // "validating" or "mutating"
	EngineID       string
	EngineName     string
	Category       EngineCategory
	ServiceName    string
	ServiceNS      string
	FailurePolicy  string
	MatchPolicy    string
	TimeoutSeconds int32
	Rules          []WebhookRule
	BypassRisk     string
	RiskLevel      string
}

// WebhookRule represents a single rule from a webhook
type WebhookRule struct {
	Operations  []string
	APIGroups   []string
	APIVersions []string
	Resources   []string
	Scope       string
}

// AnalyzeWebhooks finds and analyzes all webhooks in the cluster
func (w *WebhookAnalyzer) AnalyzeWebhooks(ctx context.Context, clientset kubernetes.Interface, category EngineCategory) ([]WebhookInfo, error) {
	var results []WebhookInfo

	engines := w.registry.GetEnginesByCategory(category)

	// Get validating webhooks
	validating, err := clientset.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, vwc := range validating.Items {
			if info := w.analyzeValidatingWebhook(vwc, engines); info != nil {
				results = append(results, *info)
			}
		}
	}

	// Get mutating webhooks
	mutating, err := clientset.AdmissionregistrationV1().MutatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, mwc := range mutating.Items {
			if info := w.analyzeMutatingWebhook(mwc, engines); info != nil {
				results = append(results, *info)
			}
		}
	}

	return results, nil
}

// AnalyzeWebhookByEngine finds webhooks for a specific engine
func (w *WebhookAnalyzer) AnalyzeWebhookByEngine(ctx context.Context, clientset kubernetes.Interface, engineID string) ([]WebhookInfo, error) {
	engine := w.registry.GetEngine(engineID)
	if engine == nil {
		return nil, nil
	}

	var results []WebhookInfo
	engines := []*Engine{engine}

	// Get validating webhooks
	validating, err := clientset.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, vwc := range validating.Items {
			if info := w.analyzeValidatingWebhook(vwc, engines); info != nil {
				results = append(results, *info)
			}
		}
	}

	// Get mutating webhooks
	mutating, err := clientset.AdmissionregistrationV1().MutatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, mwc := range mutating.Items {
			if info := w.analyzeMutatingWebhook(mwc, engines); info != nil {
				results = append(results, *info)
			}
		}
	}

	return results, nil
}

func (w *WebhookAnalyzer) analyzeValidatingWebhook(vwc admissionregv1.ValidatingWebhookConfiguration, engines []*Engine) *WebhookInfo {
	for _, engine := range engines {
		if w.matchesWebhook(vwc.Name, engine) {
			info := &WebhookInfo{
				Name:       vwc.Name,
				Type:       "validating",
				EngineID:   engine.ID,
				EngineName: engine.Name,
				Category:   engine.Category,
			}

			// Extract info from first webhook config
			if len(vwc.Webhooks) > 0 {
				wh := vwc.Webhooks[0]
				if wh.ClientConfig.Service != nil {
					info.ServiceName = wh.ClientConfig.Service.Name
					info.ServiceNS = wh.ClientConfig.Service.Namespace
				}
				if wh.FailurePolicy != nil {
					info.FailurePolicy = string(*wh.FailurePolicy)
				}
				if wh.MatchPolicy != nil {
					info.MatchPolicy = string(*wh.MatchPolicy)
				}
				if wh.TimeoutSeconds != nil {
					info.TimeoutSeconds = *wh.TimeoutSeconds
				}

				// Extract rules
				for _, rule := range wh.Rules {
					info.Rules = append(info.Rules, WebhookRule{
						Operations:  convertOperations(rule.Operations),
						APIGroups:   rule.APIGroups,
						APIVersions: rule.APIVersions,
						Resources:   rule.Resources,
						Scope:       scopeToString(rule.Scope),
					})
				}
			}

			// Analyze risk
			w.analyzeWebhookRisk(info)

			return info
		}
	}
	return nil
}

func (w *WebhookAnalyzer) analyzeMutatingWebhook(mwc admissionregv1.MutatingWebhookConfiguration, engines []*Engine) *WebhookInfo {
	for _, engine := range engines {
		if w.matchesWebhook(mwc.Name, engine) {
			info := &WebhookInfo{
				Name:       mwc.Name,
				Type:       "mutating",
				EngineID:   engine.ID,
				EngineName: engine.Name,
				Category:   engine.Category,
			}

			// Extract info from first webhook config
			if len(mwc.Webhooks) > 0 {
				wh := mwc.Webhooks[0]
				if wh.ClientConfig.Service != nil {
					info.ServiceName = wh.ClientConfig.Service.Name
					info.ServiceNS = wh.ClientConfig.Service.Namespace
				}
				if wh.FailurePolicy != nil {
					info.FailurePolicy = string(*wh.FailurePolicy)
				}
				if wh.MatchPolicy != nil {
					info.MatchPolicy = string(*wh.MatchPolicy)
				}
				if wh.TimeoutSeconds != nil {
					info.TimeoutSeconds = *wh.TimeoutSeconds
				}

				// Extract rules
				for _, rule := range wh.Rules {
					info.Rules = append(info.Rules, WebhookRule{
						Operations:  convertOperations(rule.Operations),
						APIGroups:   rule.APIGroups,
						APIVersions: rule.APIVersions,
						Resources:   rule.Resources,
						Scope:       scopeToString(rule.Scope),
					})
				}
			}

			// Analyze risk
			w.analyzeWebhookRisk(info)

			return info
		}
	}
	return nil
}

func (w *WebhookAnalyzer) matchesWebhook(name string, engine *Engine) bool {
	nameLower := strings.ToLower(name)
	for _, pattern := range engine.WebhookPatterns {
		patternLower := strings.ToLower(pattern)
		if nameLower == patternLower || strings.Contains(nameLower, patternLower) {
			return true
		}
	}
	return false
}

func (w *WebhookAnalyzer) analyzeWebhookRisk(info *WebhookInfo) {
	var risks []string

	// Check failure policy
	if info.FailurePolicy == "Ignore" {
		risks = append(risks, "Failure policy is Ignore - webhook can be bypassed on timeout")
		info.RiskLevel = "MEDIUM"
	}

	// Check timeout
	if info.TimeoutSeconds > 0 && info.TimeoutSeconds < 5 {
		risks = append(risks, "Low timeout may cause bypasses under load")
	}

	// Check for wildcard rules
	for _, rule := range info.Rules {
		for _, res := range rule.Resources {
			if res == "*" {
				risks = append(risks, "Wildcard resource matching may have performance impact")
			}
		}
		for _, grp := range rule.APIGroups {
			if grp == "*" {
				risks = append(risks, "Wildcard API group matching")
			}
		}
	}

	// Check service namespace
	if info.ServiceNS != "" && info.ServiceNS != "kube-system" {
		risks = append(risks, "Webhook service not in kube-system namespace")
	}

	if len(risks) > 0 {
		info.BypassRisk = strings.Join(risks, "; ")
	}

	if info.RiskLevel == "" {
		if len(risks) > 0 {
			info.RiskLevel = "LOW"
		} else {
			info.RiskLevel = "NONE"
		}
	}
}

func convertOperations(ops []admissionregv1.OperationType) []string {
	var result []string
	for _, op := range ops {
		result = append(result, string(op))
	}
	return result
}

func scopeToString(scope *admissionregv1.ScopeType) string {
	if scope == nil {
		return "*"
	}
	return string(*scope)
}

// FindBypassVectors identifies potential webhook bypass vectors
func (w *WebhookAnalyzer) FindBypassVectors(webhooks []WebhookInfo) []BypassVector {
	var vectors []BypassVector

	// Check for missing enforcement
	webhookByEngine := make(map[string]bool)
	for _, wh := range webhooks {
		webhookByEngine[wh.EngineID] = true
	}

	// Check for ignore failure policies
	for _, wh := range webhooks {
		if wh.FailurePolicy == "Ignore" {
			vectors = append(vectors, BypassVector{
				Type:        "FailurePolicyIgnore",
				Description: "Webhook " + wh.Name + " uses Ignore failure policy",
				Severity:    "MEDIUM",
				Engine:      wh.EngineName,
			})
		}
	}

	// Check for low timeouts
	for _, wh := range webhooks {
		if wh.TimeoutSeconds > 0 && wh.TimeoutSeconds < 5 {
			vectors = append(vectors, BypassVector{
				Type:        "LowTimeout",
				Description: "Webhook " + wh.Name + " has low timeout (" + string(rune(wh.TimeoutSeconds)) + "s)",
				Severity:    "LOW",
				Engine:      wh.EngineName,
			})
		}
	}

	return vectors
}

// BypassVector represents a potential way to bypass admission control
type BypassVector struct {
	Type        string
	Description string
	Severity    string
	Engine      string
}
