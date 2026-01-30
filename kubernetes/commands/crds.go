package commands

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/BishopFox/cloudfox/kubernetes/sdk"
	"github.com/BishopFox/cloudfox/kubernetes/shared"
	"github.com/spf13/cobra"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

var CRDsCmd = &cobra.Command{
	Use:     "crds",
	Aliases: []string{"crd", "customresources"},
	Short:   "Analyze Custom Resource Definitions for security risks",
	Long: `
Analyze Custom Resource Definitions with comprehensive security analysis including:
  - CRD inventory with resource counts
  - Interesting/security-relevant CRDs (certs, secrets, policy, RBAC)
  - RBAC analysis: who can CRUD each CRD's resources
  - Webhook analysis: validating/mutating webhooks covering CRDs
  - Missing validation schemas (injection risk)
  - Conversion webhooks (admission bypass potential)
  - Cluster-scoped CRDs (broad access implications)

  cloudfox kubernetes crds`,
	Run: ListCRDs,
}

// init() removed - detailed flag is now a global persistent flag in cli/kubernetes.go

type CRDsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t CRDsOutput) TableFiles() []internal.TableFile {
	return t.Table
}

func (t CRDsOutput) LootFiles() []internal.LootFile {
	return t.Loot
}

type CRDAnalysis struct {
	Name                 string
	Group                string
	Kind                 string
	Plural               string
	Scope                string
	Versions             []string
	StoredVersions       []string
	LatestVersion        string
	HasValidation        bool
	HasConversionWebhook bool
	ConversionStrategy   string
	HasStatus            bool
	HasScale             bool
	Namespaced           bool
	Categories           []string
	ShortNames           []string
	DeprecatedVersions   []string
	ResourceCount        int
}

type CRDResourceInfo struct {
	CRDName      string
	Group        string
	Kind         string
	Resource     string
	Namespace    string
	ResourceName string
	Labels       string
	CreatedAt    string
}

type CRDRBACEntry struct {
	CRDGroup    string
	Resource    string
	SubjectKind string
	SubjectName string
	Namespace   string
	Verbs       string
	Scope       string
	RoleName    string
}

type CRDWebhookEntry struct {
	CRDGroup      string
	WebhookName   string
	Type          string
	FailurePolicy string
	Operations    string
	Service       string
}

type InterestingCRD struct {
	Name      string
	Group     string
	Kind      string
	Category  string
	Why       string
	Resources int
}

// interestingGroupPatterns maps category to group substrings
var interestingGroupPatterns = map[string][]string{
	"Secrets/Certs": {"cert-manager", "secrets-store", "sealed-secrets", "vault", "external-secrets", "certmanager", "spiffe"},
	"Policy":        {"policy", "kyverno", "gatekeeper", "opa", "constraints", "kubearmor", "falco", "neuvector", "stackrox", "crowdstrike", "security-profiles-operator", "sysdig", "aquasec", "prismacloud"},
	"RBAC/Auth":     {"rbac", "auth", "identity", "oidc", "dex", "keycloak"},
	"Workload":      {"argoproj", "tekton", "flux", "keda", "knative", "crossplane"},
	"Network":       {"networking.istio", "cilium", "calico", "linkerd", "gateway.networking"},
	"Storage":       {"snapshot.storage", "rook", "longhorn", "velero"},
}

func ListCRDs(cmd *cobra.Command, args []string) {
	ctx, cancel := shared.ContextWithCancel()
	defer cancel()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")
	detailed := globals.K8sDetailed

	logger.InfoM(fmt.Sprintf("Analyzing CRDs for %s", globals.ClusterName), globals.K8S_CRDS_MODULE_NAME)

	// Standard clientset for RBAC and webhooks
	clientset := config.GetClientOrExit()

	// Dynamic client for resource counting
	dynClient := config.GetDynamicClientOrExit()

	// Fetch CRDs (via SDK cache)
	crdItems, err := sdk.GetCRDs(ctx)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error fetching CRDs: %v", err), globals.K8S_CRDS_MODULE_NAME)
		return
	}

	// Build set of CRD groups for RBAC/webhook matching
	crdGroups := make(map[string]bool)

	var crdAnalyses []CRDAnalysis
	for _, crd := range crdItems {
		analysis := analyzeCRD(&crd)
		crdGroups[analysis.Group] = true
		crdAnalyses = append(crdAnalyses, analysis)
	}

	// Enumerate CRD resources
	logger.InfoM("Enumerating CRD resources...", globals.K8S_CRDS_MODULE_NAME)
	resourceInfos := enumerateCRDResources(ctx, dynClient, crdAnalyses)

	// Build resource count map
	resourceCountMap := make(map[string]int)
	for _, ri := range resourceInfos {
		resourceCountMap[ri.CRDName]++
	}
	for i := range crdAnalyses {
		crdAnalyses[i].ResourceCount = resourceCountMap[crdAnalyses[i].Name]
	}

	// Identify interesting CRDs
	interestingCRDs := identifyInterestingCRDs(crdAnalyses)

	// RBAC analysis
	logger.InfoM("Analyzing RBAC for CRD groups...", globals.K8S_CRDS_MODULE_NAME)
	rbacEntries := analyzeCRDRBAC(ctx, clientset, crdGroups)

	// Webhook analysis
	logger.InfoM("Analyzing webhooks for CRD groups...", globals.K8S_CRDS_MODULE_NAME)
	webhookEntries := analyzeCRDWebhooks(ctx, clientset, crdGroups)

	// Build loot — only CRD-Commands (RBAC and Interesting are covered by tables)
	loot := shared.NewLootBuilder()
	loot.Section("CRD-Commands").Add(generateCRDCommands(crdAnalyses))
	lootFiles := loot.Build()

	// Build tables
	var tables []internal.TableFile

	// Always show: main CRDs table and Interesting CRDs
	tables = append(tables, generateCRDTable(crdAnalyses))
	if len(interestingCRDs) > 0 {
		tables = append(tables, generateInterestingCRDTable(interestingCRDs))
	}

	// Detailed: RBAC, webhooks, per-namespace resources
	if detailed {
		if len(rbacEntries) > 0 {
			tables = append(tables, generateCRDRBACTable(rbacEntries))
		}
		if len(webhookEntries) > 0 {
			tables = append(tables, generateCRDWebhookTable(webhookEntries))
		}
		if len(resourceInfos) > 0 {
			tables = append(tables, generateCRDResourceTable(resourceInfos))
		}
	}

	err = internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"CRDs",
		globals.ClusterName,
		"results",
		CRDsOutput{
			Table: tables,
			Loot:  lootFiles,
		},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_CRDS_MODULE_NAME)
		return
	}

	// Summary logging
	if len(crdItems) > 0 {
		noValidationCount := 0
		clusterScopedCount := 0
		webhooksCount := 0

		for _, analysis := range crdAnalyses {
			if !analysis.HasValidation {
				noValidationCount++
			}
			if !analysis.Namespaced {
				clusterScopedCount++
			}
			if analysis.HasConversionWebhook {
				webhooksCount++
			}
		}

		logger.InfoM(fmt.Sprintf("%d CRDs analyzed | Interesting: %d | No Validation: %d | Cluster-Scoped: %d | Conversion Webhooks: %d | RBAC Entries: %d | Admission Webhooks: %d",
			len(crdItems), len(interestingCRDs), noValidationCount, clusterScopedCount, webhooksCount, len(rbacEntries), len(webhookEntries)),
			globals.K8S_CRDS_MODULE_NAME)
	} else {
		logger.InfoM("No CRDs found", globals.K8S_CRDS_MODULE_NAME)
	}
}

func analyzeCRD(crd *apiextensionsv1.CustomResourceDefinition) CRDAnalysis {
	analysis := CRDAnalysis{
		Name:       crd.Name,
		Group:      crd.Spec.Group,
		Kind:       crd.Spec.Names.Kind,
		Plural:     crd.Spec.Names.Plural,
		Scope:      string(crd.Spec.Scope),
		Categories: crd.Spec.Names.Categories,
		ShortNames: crd.Spec.Names.ShortNames,
		Namespaced: crd.Spec.Scope == apiextensionsv1.NamespaceScoped,
	}

	for _, ver := range crd.Spec.Versions {
		analysis.Versions = append(analysis.Versions, ver.Name)
		if ver.Served && ver.Storage {
			analysis.LatestVersion = ver.Name
		}
		if ver.Schema != nil && ver.Schema.OpenAPIV3Schema != nil {
			analysis.HasValidation = true
		}
		if ver.Deprecated {
			analysis.DeprecatedVersions = append(analysis.DeprecatedVersions, ver.Name)
		}
		if ver.Subresources != nil {
			if ver.Subresources.Status != nil {
				analysis.HasStatus = true
			}
			if ver.Subresources.Scale != nil {
				analysis.HasScale = true
			}
		}
	}

	analysis.StoredVersions = crd.Status.StoredVersions

	if crd.Spec.Conversion != nil {
		analysis.ConversionStrategy = string(crd.Spec.Conversion.Strategy)
		if crd.Spec.Conversion.Strategy == apiextensionsv1.WebhookConverter {
			analysis.HasConversionWebhook = true
		}
	}

	return analysis
}

// enumerateCRDResources fetches actual instances of each CRD
func enumerateCRDResources(ctx context.Context, dynClient dynamic.Interface, analyses []CRDAnalysis) []CRDResourceInfo {
	var results []CRDResourceInfo

	for _, crd := range analyses {
		if crd.LatestVersion == "" || crd.Plural == "" {
			continue
		}

		gvr := schema.GroupVersionResource{
			Group:    crd.Group,
			Version:  crd.LatestVersion,
			Resource: crd.Plural,
		}

		list, err := dynClient.Resource(gvr).Namespace("").List(ctx, metav1.ListOptions{})
		if err != nil || len(list.Items) == 0 {
			continue
		}

		for _, item := range list.Items {
			ns := item.GetNamespace()
			if ns == "" {
				ns = "(cluster-scoped)"
			}

			// Format labels
			labels := item.GetLabels()
			var labelParts []string
			for k, v := range labels {
				labelParts = append(labelParts, fmt.Sprintf("%s=%s", k, v))
			}
			labelsStr := "-"
			if len(labelParts) > 0 {
				sort.Strings(labelParts)
				labelsStr = strings.Join(labelParts, ", ")
			}

			createdAt := "-"
			if t := item.GetCreationTimestamp(); !t.IsZero() {
				createdAt = t.Format("2006-01-02 15:04")
			}

			results = append(results, CRDResourceInfo{
				CRDName:      crd.Name,
				Group:        crd.Group,
				Kind:         crd.Kind,
				Resource:     crd.Plural,
				Namespace:    ns,
				ResourceName: item.GetName(),
				Labels:       labelsStr,
				CreatedAt:    createdAt,
			})
		}
	}

	return results
}

// identifyInterestingCRDs categorizes security-relevant CRDs
func identifyInterestingCRDs(analyses []CRDAnalysis) []InterestingCRD {
	var results []InterestingCRD

	for _, crd := range analyses {
		groupLower := strings.ToLower(crd.Group)
		for category, patterns := range interestingGroupPatterns {
			for _, pattern := range patterns {
				if strings.Contains(groupLower, pattern) {
					why := fmt.Sprintf("Group matches: %s", pattern)
					if !crd.HasValidation {
						why += ", no validation"
					}
					if !crd.Namespaced {
						why += ", cluster-scoped"
					}
					results = append(results, InterestingCRD{
						Name:      crd.Name,
						Group:     crd.Group,
						Kind:      crd.Kind,
						Category:  category,
						Why:       why,
						Resources: crd.ResourceCount,
					})
					break // one category per CRD
				}
			}
		}
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].Category != results[j].Category {
			return results[i].Category < results[j].Category
		}
		return results[i].Name < results[j].Name
	})

	return results
}

// analyzeCRDRBAC finds RBAC entries that grant access to CRD API groups
func analyzeCRDRBAC(ctx context.Context, clientset *kubernetes.Clientset, crdGroups map[string]bool) []CRDRBACEntry {
	var results []CRDRBACEntry

	clusterRoles, err := sdk.GetClusterRoles(ctx, clientset)
	if err != nil {
		return results
	}
	clusterRoleBindings, err := sdk.GetClusterRoleBindings(ctx, clientset)
	if err != nil {
		return results
	}
	roles, err := sdk.GetRoles(ctx, clientset)
	if err != nil {
		return results
	}
	roleBindings, err := sdk.GetRoleBindings(ctx, clientset)
	if err != nil {
		return results
	}

	// Build role lookup maps
	crMap := make(map[string]*rbacv1.ClusterRole)
	for i := range clusterRoles {
		crMap[clusterRoles[i].Name] = &clusterRoles[i]
	}
	rMap := make(map[string]*rbacv1.Role)
	for i := range roles {
		key := roles[i].Namespace + "/" + roles[i].Name
		rMap[key] = &roles[i]
	}

	// Check ClusterRoleBindings
	for _, crb := range clusterRoleBindings {
		cr, ok := crMap[crb.RoleRef.Name]
		if !ok {
			continue
		}
		entries := extractCRDRBACFromRules(cr.Rules, crdGroups, crb.Subjects, crb.RoleRef.Name, "Cluster", "")
		results = append(results, entries...)
	}

	// Check RoleBindings
	for _, rb := range roleBindings {
		var rules []rbacv1.PolicyRule
		if rb.RoleRef.Kind == "ClusterRole" {
			if cr, ok := crMap[rb.RoleRef.Name]; ok {
				rules = cr.Rules
			}
		} else {
			key := rb.Namespace + "/" + rb.RoleRef.Name
			if r, ok := rMap[key]; ok {
				rules = r.Rules
			}
		}
		if len(rules) == 0 {
			continue
		}
		entries := extractCRDRBACFromRules(rules, crdGroups, rb.Subjects, rb.RoleRef.Name, "Namespace", rb.Namespace)
		results = append(results, entries...)
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].CRDGroup != results[j].CRDGroup {
			return results[i].CRDGroup < results[j].CRDGroup
		}
		return results[i].SubjectName < results[j].SubjectName
	})

	return results
}

func extractCRDRBACFromRules(rules []rbacv1.PolicyRule, crdGroups map[string]bool, subjects []rbacv1.Subject, roleName, scope, namespace string) []CRDRBACEntry {
	var results []CRDRBACEntry

	for _, rule := range rules {
		for _, apiGroup := range rule.APIGroups {
			if !crdGroups[apiGroup] && apiGroup != "*" {
				continue
			}
			// This rule covers a CRD group (or wildcard)
			matchedGroup := apiGroup
			if apiGroup == "*" {
				matchedGroup = "(all groups)"
			}
			resources := strings.Join(rule.Resources, ",")
			if len(rule.Resources) == 0 {
				resources = "*"
			}
			verbs := strings.Join(rule.Verbs, ",")

			for _, subj := range subjects {
				results = append(results, CRDRBACEntry{
					CRDGroup:    matchedGroup,
					Resource:    resources,
					SubjectKind: subj.Kind,
					SubjectName: subj.Name,
					Namespace:   namespace,
					Verbs:       verbs,
					Scope:       scope,
					RoleName:    roleName,
				})
			}
		}
	}

	return results
}

// analyzeCRDWebhooks finds webhooks that cover CRD API groups
func analyzeCRDWebhooks(ctx context.Context, clientset *kubernetes.Clientset, crdGroups map[string]bool) []CRDWebhookEntry {
	var results []CRDWebhookEntry

	validating, err := clientset.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, vwc := range validating.Items {
			for _, wh := range vwc.Webhooks {
				fp := "Unknown"
				if wh.FailurePolicy != nil {
					fp = string(*wh.FailurePolicy)
				}
				svc := webhookClientConfigStr(wh.ClientConfig)
				for _, rule := range wh.Rules {
					entries := extractWebhookCRDEntries(rule.APIGroups, rule.Operations, crdGroups, vwc.Name, "Validating", fp, svc)
					results = append(results, entries...)
				}
			}
		}
	}

	mutating, err := clientset.AdmissionregistrationV1().MutatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, mwc := range mutating.Items {
			for _, wh := range mwc.Webhooks {
				fp := "Unknown"
				if wh.FailurePolicy != nil {
					fp = string(*wh.FailurePolicy)
				}
				svc := webhookClientConfigStr(wh.ClientConfig)
				for _, rule := range wh.Rules {
					entries := extractWebhookCRDEntries(rule.APIGroups, rule.Operations, crdGroups, mwc.Name, "Mutating", fp, svc)
					results = append(results, entries...)
				}
			}
		}
	}

	return results
}

func extractWebhookCRDEntries(apiGroups []string, operations []admissionregv1.OperationType, crdGroups map[string]bool, webhookName, whType, failurePolicy, service string) []CRDWebhookEntry {
	var results []CRDWebhookEntry

	for _, apiGroup := range apiGroups {
		if !crdGroups[apiGroup] && apiGroup != "*" {
			continue
		}
		matchedGroup := apiGroup
		if apiGroup == "*" {
			matchedGroup = "(all groups)"
		}
		ops := make([]string, len(operations))
		for i, op := range operations {
			ops[i] = string(op)
		}
		results = append(results, CRDWebhookEntry{
			CRDGroup:      matchedGroup,
			WebhookName:   webhookName,
			Type:          whType,
			FailurePolicy: failurePolicy,
			Operations:    strings.Join(ops, ","),
			Service:       service,
		})
	}

	return results
}

func webhookClientConfigStr(cc admissionregv1.WebhookClientConfig) string {
	if cc.Service != nil {
		return fmt.Sprintf("%s/%s", cc.Service.Namespace, cc.Service.Name)
	}
	if cc.URL != nil {
		return *cc.URL
	}
	return "-"
}

// Table generators

func generateCRDTable(analyses []CRDAnalysis) internal.TableFile {
	header := []string{"Name", "Group", "Kind", "Scope", "Versions", "Validation", "Conv. Webhook", "Resources"}

	sort.Slice(analyses, func(i, j int) bool {
		return analyses[i].Name < analyses[j].Name
	})

	var rows [][]string
	for _, crd := range analyses {
		versionsStr := strings.Join(crd.Versions, ",")
		if len(versionsStr) > 20 {
			versionsStr = versionsStr[:17] + "..."
		}

		rows = append(rows, []string{
			truncateStr(crd.Name, 50),
			crd.Group,
			crd.Kind,
			crd.Scope,
			versionsStr,
			shared.FormatBool(crd.HasValidation),
			shared.FormatBool(crd.HasConversionWebhook),
			fmt.Sprintf("%d", crd.ResourceCount),
		})
	}

	return internal.TableFile{
		Name:   "CRDs",
		Header: header,
		Body:   rows,
	}
}

func generateInterestingCRDTable(crds []InterestingCRD) internal.TableFile {
	header := []string{"Name", "Group", "Kind", "Category", "Why", "Resources"}
	var rows [][]string

	for _, crd := range crds {
		rows = append(rows, []string{
			truncateStr(crd.Name, 50),
			crd.Group,
			crd.Kind,
			crd.Category,
			crd.Why,
			fmt.Sprintf("%d", crd.Resources),
		})
	}

	return internal.TableFile{
		Name:   "Interesting-CRDs",
		Header: header,
		Body:   rows,
	}
}

func generateCRDRBACTable(entries []CRDRBACEntry) internal.TableFile {
	header := []string{"Namespace", "CRD Group", "Resource", "Verbs", "Subject", "Subject Name", "Role", "Scope"}
	var rows [][]string

	for _, e := range entries {
		ns := e.Namespace
		if ns == "" {
			ns = "(cluster)"
		}
		rows = append(rows, []string{
			ns,
			e.CRDGroup,
			e.Resource,
			e.Verbs,
			e.SubjectKind,
			e.SubjectName,
			e.RoleName,
			e.Scope,
		})
	}

	return internal.TableFile{
		Name:   "CRD-RBAC",
		Header: header,
		Body:   rows,
	}
}

func generateCRDWebhookTable(entries []CRDWebhookEntry) internal.TableFile {
	header := []string{"CRD Group", "Webhook Name", "Type", "Service", "Operations", "Failure Policy"}
	var rows [][]string

	for _, e := range entries {
		rows = append(rows, []string{
			e.CRDGroup,
			e.WebhookName,
			e.Type,
			e.Service,
			e.Operations,
			e.FailurePolicy,
		})
	}

	return internal.TableFile{
		Name:   "CRD-Webhooks",
		Header: header,
		Body:   rows,
	}
}

func generateCRDResourceTable(infos []CRDResourceInfo) internal.TableFile {
	header := []string{"Namespace", "Kind", "Name", "Created", "Labels"}
	var rows [][]string

	sort.Slice(infos, func(i, j int) bool {
		if infos[i].Namespace != infos[j].Namespace {
			return infos[i].Namespace < infos[j].Namespace
		}
		if infos[i].Kind != infos[j].Kind {
			return infos[i].Kind < infos[j].Kind
		}
		return infos[i].ResourceName < infos[j].ResourceName
	})

	for _, ri := range infos {
		rows = append(rows, []string{
			ri.Namespace,
			ri.Kind,
			ri.ResourceName,
			ri.CreatedAt,
			ri.Labels,
		})
	}

	return internal.TableFile{
		Name:   "CRD-Resources",
		Header: header,
		Body:   rows,
	}
}

// Loot generators

// generateCRDCommands creates enumeration and exploitation commands for CRDs
func generateCRDCommands(analyses []CRDAnalysis) string {
	var lines []string

	lines = append(lines, "═══════════════════════════════════════════════════════════════")
	lines = append(lines, "         CRD ENUMERATION AND EXPLOITATION COMMANDS")
	lines = append(lines, "═══════════════════════════════════════════════════════════════")
	lines = append(lines, "")

	// Basic enumeration
	lines = append(lines, "##############################################")
	lines = append(lines, "## 1. ENUMERATION - List All CRDs")
	lines = append(lines, "##############################################")
	lines = append(lines, "")
	lines = append(lines, "kubectl get crds")
	lines = append(lines, "kubectl get crds -o wide")
	lines = append(lines, "kubectl get crd <crd-name> -o yaml")
	lines = append(lines, "kubectl describe crd <crd-name>")
	lines = append(lines, "")

	// Find vulnerable CRDs
	lines = append(lines, "##############################################")
	lines = append(lines, "## 2. IDENTIFY VULNERABLE CRDs")
	lines = append(lines, "##############################################")
	lines = append(lines, "")
	lines = append(lines, "# CRDs without validation schema")
	lines = append(lines, "kubectl get crds -o json | jq -r '.items[] | select(.spec.versions[].schema == null or .spec.versions[].schema.openAPIV3Schema == null) | .metadata.name'")
	lines = append(lines, "")
	lines = append(lines, "# Cluster-scoped CRDs")
	lines = append(lines, "kubectl get crds -o json | jq -r '.items[] | select(.spec.scope == \"Cluster\") | .metadata.name'")
	lines = append(lines, "")
	lines = append(lines, "# CRDs with conversion webhooks")
	lines = append(lines, "kubectl get crds -o json | jq -r '.items[] | select(.spec.conversion.strategy == \"Webhook\") | {name: .metadata.name, webhook: .spec.conversion.webhook}'")
	lines = append(lines, "")

	// Enumerate custom resources
	lines = append(lines, "##############################################")
	lines = append(lines, "## 3. ENUMERATE CUSTOM RESOURCES")
	lines = append(lines, "##############################################")
	lines = append(lines, "")
	if len(analyses) > 0 {
		for _, crd := range analyses {
			plural := crd.Plural
			if plural == "" {
				plural = strings.ToLower(crd.Kind) + "s"
			}
			if len(crd.ShortNames) > 0 {
				lines = append(lines, fmt.Sprintf("kubectl get %s -A  # %s (shortname: %s)", plural, crd.Name, strings.Join(crd.ShortNames, ",")))
			} else {
				lines = append(lines, fmt.Sprintf("kubectl get %s -A  # %s", plural, crd.Name))
			}
		}
		lines = append(lines, "")
	}

	// RBAC analysis commands
	lines = append(lines, "##############################################")
	lines = append(lines, "## 4. RBAC ANALYSIS FOR CRDs")
	lines = append(lines, "##############################################")
	lines = append(lines, "")
	lines = append(lines, "kubectl auth can-i list customresourcedefinitions")
	lines = append(lines, "kubectl auth can-i create customresourcedefinitions")
	lines = append(lines, "kubectl auth can-i delete customresourcedefinitions")
	lines = append(lines, "")
	lines = append(lines, "# Find roles granting CRD access")
	lines = append(lines, "kubectl get clusterroles -o json | jq -r '.items[] | select(.rules[]?.resources[]? | contains(\"customresourcedefinitions\")) | .metadata.name'")
	lines = append(lines, "")

	// No-validation exploitation
	noValidationCRDs := []CRDAnalysis{}
	for _, crd := range analyses {
		if !crd.HasValidation {
			noValidationCRDs = append(noValidationCRDs, crd)
		}
	}

	if len(noValidationCRDs) > 0 {
		lines = append(lines, "##############################################")
		lines = append(lines, "## 5. NO-VALIDATION CRDs (INJECTION TARGETS)")
		lines = append(lines, "##############################################")
		lines = append(lines, "")
		for _, crd := range noValidationCRDs {
			lines = append(lines, fmt.Sprintf("# %s (Group: %s) - no validation", crd.Name, crd.Group))
			plural := crd.Plural
			if plural == "" {
				plural = strings.ToLower(crd.Kind) + "s"
			}
			lines = append(lines, fmt.Sprintf("kubectl get %s -A -o yaml", plural))
		}
		lines = append(lines, "")
	}

	// Webhook bypass
	lines = append(lines, "##############################################")
	lines = append(lines, "## 6. WEBHOOK BYPASS")
	lines = append(lines, "##############################################")
	lines = append(lines, "")
	lines = append(lines, "# Check conversion webhook config")
	lines = append(lines, "kubectl get crd <crd-name> -o jsonpath='{.spec.conversion}'")
	lines = append(lines, "")
	lines = append(lines, "# Find webhook service")
	lines = append(lines, "kubectl get crd <crd-name> -o json | jq '.spec.conversion.webhook.clientConfig'")
	lines = append(lines, "")

	// Privilege escalation
	lines = append(lines, "##############################################")
	lines = append(lines, "## 7. PRIVILEGE ESCALATION VIA CRDs")
	lines = append(lines, "##############################################")
	lines = append(lines, "")
	lines = append(lines, "kubectl auth can-i create customresourcedefinitions")
	lines = append(lines, "")
	lines = append(lines, "# If you can create CRDs, create one without validation:")
	lines = append(lines, "cat <<EOF | kubectl apply -f -")
	lines = append(lines, "apiVersion: apiextensions.k8s.io/v1")
	lines = append(lines, "kind: CustomResourceDefinition")
	lines = append(lines, "metadata:")
	lines = append(lines, "  name: exploits.attacker.example.com")
	lines = append(lines, "spec:")
	lines = append(lines, "  group: attacker.example.com")
	lines = append(lines, "  names:")
	lines = append(lines, "    kind: Exploit")
	lines = append(lines, "    plural: exploits")
	lines = append(lines, "  scope: Namespaced")
	lines = append(lines, "  versions:")
	lines = append(lines, "  - name: v1")
	lines = append(lines, "    served: true")
	lines = append(lines, "    storage: true")
	lines = append(lines, "    schema:")
	lines = append(lines, "      openAPIV3Schema:")
	lines = append(lines, "        type: object")
	lines = append(lines, "        x-kubernetes-preserve-unknown-fields: true")
	lines = append(lines, "EOF")
	lines = append(lines, "")

	return strings.Join(lines, "\n")
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
