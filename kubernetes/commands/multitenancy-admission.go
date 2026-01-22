package commands

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/BishopFox/cloudfox/kubernetes/shared"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

const K8S_MULTITENANCY_ADMISSION_MODULE_NAME = "multitenancy-admission"

var MultitenancyAdmissionCmd = &cobra.Command{
	Use:     "multitenancy-admission",
	Aliases: []string{"tenant-isolation", "multitenancy"},
	Short:   "Analyze multi-tenancy and namespace isolation configurations",
	Long: `
Analyze all multi-tenancy configurations including:
  - Hierarchical Namespace Controller (HNC)
  - Capsule (Tenant CRDs)
  - vCluster detection
  - Loft (VirtualCluster, Space CRDs)
  - Kiosk (Account, Space CRDs)
  - Namespace isolation analysis
  - Cross-tenant resource detection
  - Resource quota enforcement

  cloudfox kubernetes multitenancy-admission`,
	Run: ListMultitenancyAdmission,
}

type MultitenancyAdmissionOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t MultitenancyAdmissionOutput) TableFiles() []internal.TableFile { return t.Table }
func (t MultitenancyAdmissionOutput) LootFiles() []internal.LootFile   { return t.Loot }

// MultitenancyAdmissionFinding represents multi-tenancy status for a namespace
type MultitenancyAdmissionFinding struct {
	Namespace string

	// Tenant assignment
	TenantName     string
	TenantProvider string // HNC, Capsule, Loft, Kiosk, vCluster

	// Isolation status
	IsIsolated         bool
	HasNetworkPolicy   bool
	HasResourceQuota   bool
	HasLimitRange      bool
	HasPodSecurityStd  bool

	// Hierarchy
	ParentNamespace    string
	ChildNamespaces    []string
	HierarchyDepth     int

	// Risk Analysis
	RiskLevel      string
	SecurityIssues []string
}

// HNCInfo represents Hierarchical Namespace Controller status
type HNCInfo struct {
	Name          string
	Namespace     string
	Status        string
	PodsRunning   int
	TotalPods     int
	Hierarchies   int
	ImageVerified bool
	BypassRisk    string
}

// HNCHierarchyInfo represents an HNC hierarchy
type HNCHierarchyInfo struct {
	Namespace       string
	Parent          string
	Children        []string
	DepthFromRoot   int
	PropagatedRoles int
	BypassRisk      string
}

// CapsuleInfo represents Capsule controller status
type CapsuleInfo struct {
	Name          string
	Namespace     string
	Status        string
	PodsRunning   int
	TotalPods     int
	Tenants       int
	ImageVerified bool
	BypassRisk    string
}

// CapsuleTenantInfo represents a Capsule Tenant
type CapsuleTenantInfo struct {
	Name              string
	Namespaces        []string
	NamespaceQuota    int
	Owners            []string
	NodeSelector      map[string]string
	IngressClasses    []string
	StorageClasses    []string
	LimitRanges       bool
	ResourceQuotas    bool
	NetworkPolicies   bool
	BypassRisk        string
}

// VClusterInfo represents a vCluster instance
type VClusterInfo struct {
	Name            string
	Namespace       string
	Status          string
	PodsRunning     int
	TotalPods       int
	SyncerRunning   bool
	K8sVersion      string
	HostClusterRole string
	ImageVerified   bool
	BypassRisk      string
}

// LoftInfo represents Loft controller status
type LoftInfo struct {
	Name             string
	Namespace        string
	Status           string
	PodsRunning      int
	TotalPods        int
	VirtualClusters  int
	Spaces           int
	Teams            int
	ImageVerified    bool
	BypassRisk       string
}

// LoftSpaceInfo represents a Loft Space
type LoftSpaceInfo struct {
	Name            string
	Namespace       string
	Team            string
	User            string
	SleepAfter      string
	DeleteAfter     string
	BypassRisk      string
}

// KioskInfo represents Kiosk controller status
type KioskInfo struct {
	Name          string
	Namespace     string
	Status        string
	PodsRunning   int
	TotalPods     int
	Accounts      int
	Spaces        int
	ImageVerified bool
	BypassRisk    string
}

// KioskAccountInfo represents a Kiosk Account
type KioskAccountInfo struct {
	Name            string
	Subjects        []string
	SpaceLimit      int
	SpacesUsed      int
	DefaultCluster  string
	BypassRisk      string
}

// OPAGatekeeperTenantInfo represents OPA/Gatekeeper tenant policy configuration
type OPAGatekeeperTenantInfo struct {
	Name                    string
	Namespace               string
	Status                  string
	PodsRunning             int
	TotalPods               int
	ImageVerified           bool
	ConstraintTemplates     int
	Constraints             int
	TenantIsolationPolicies int
	BypassRisk              string
}

// NamespaceIsolationInfo represents isolation status for a namespace
type NamespaceIsolationInfo struct {
	Namespace          string
	TenantLabel        string
	TenantValue        string
	HasNetworkPolicy   bool
	DefaultDenyIngress bool
	DefaultDenyEgress  bool
	HasResourceQuota   bool
	HasLimitRange      bool
	PodSecurityStd     string // privileged, baseline, restricted
	BypassRisk         string
}

// CrossTenantResourceInfo represents resources that may cross tenant boundaries
type CrossTenantResourceInfo struct {
	Type           string // ClusterRole, ClusterRoleBinding, PV, Service
	Name           string
	Scope          string // Cluster, Namespaces
	AffectedTenants []string
	RiskLevel      string
	Description    string
	BypassRisk     string
}

func ListMultitenancyAdmission(cmd *cobra.Command, args []string) {
	ctx, cancel := shared.ContextWithTimeout()
	defer cancel()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDir, _ := parentCmd.PersistentFlags().GetString("outdir")

	logger.InfoM(fmt.Sprintf("Analyzing multi-tenancy for %s", globals.ClusterName), K8S_MULTITENANCY_ADMISSION_MODULE_NAME)

	clientset := config.GetClientOrExit()
	dynClient := config.GetDynamicClientOrExit()

	// Analyze HNC
	logger.InfoM("Analyzing HNC...", K8S_MULTITENANCY_ADMISSION_MODULE_NAME)
	hnc, hncHierarchies := analyzeHNC(ctx, clientset, dynClient)

	// Analyze Capsule
	logger.InfoM("Analyzing Capsule...", K8S_MULTITENANCY_ADMISSION_MODULE_NAME)
	capsule, capsuleTenants := analyzeCapsule(ctx, clientset, dynClient)

	// Analyze vClusters
	logger.InfoM("Analyzing vClusters...", K8S_MULTITENANCY_ADMISSION_MODULE_NAME)
	vclusters := analyzeVClusters(ctx, clientset, dynClient)

	// Analyze Loft
	logger.InfoM("Analyzing Loft...", K8S_MULTITENANCY_ADMISSION_MODULE_NAME)
	loft, loftSpaces := analyzeLoft(ctx, clientset, dynClient)

	// Analyze Kiosk
	logger.InfoM("Analyzing Kiosk...", K8S_MULTITENANCY_ADMISSION_MODULE_NAME)
	kiosk, kioskAccounts := analyzeKiosk(ctx, clientset, dynClient)

	// Analyze OPA/Gatekeeper tenant policies
	logger.InfoM("Analyzing OPA/Gatekeeper tenant policies...", K8S_MULTITENANCY_ADMISSION_MODULE_NAME)
	opaGatekeeper := analyzeOPAGatekeeperTenant(ctx, clientset, dynClient)

	// Analyze namespace isolation
	logger.InfoM("Analyzing namespace isolation...", K8S_MULTITENANCY_ADMISSION_MODULE_NAME)
	nsIsolation := analyzeNamespaceIsolation(ctx, clientset, dynClient)

	// Analyze cross-tenant resources
	logger.InfoM("Analyzing cross-tenant resources...", K8S_MULTITENANCY_ADMISSION_MODULE_NAME)
	crossTenantResources := analyzeCrossTenantResources(ctx, clientset, dynClient, capsuleTenants, hncHierarchies)

	// Build findings per namespace
	findings := buildMultitenancyFindings(hnc, hncHierarchies, capsule, capsuleTenants, vclusters, loft, loftSpaces, kiosk, kioskAccounts, nsIsolation)

	// Generate tables
	summaryHeader := []string{
		"Namespace",
		"Tenant",
		"Provider",
		"Isolated",
		"Network Policy",
		"Resource Quota",
		"Limit Range",
		"Pod Security",
		"Risk Level",
		"Issues",
	}

	hncHeader := []string{
		"Namespace",
		"Status",
		"Pods Running",
		"Hierarchies",
		"Bypass Risk",
	}

	hncHierarchyHeader := []string{
		"Namespace",
		"Parent",
		"Children",
		"Depth",
		"Propagated Roles",
		"Bypass Risk",
	}

	capsuleHeader := []string{
		"Namespace",
		"Status",
		"Pods Running",
		"Tenants",
		"Bypass Risk",
	}

	capsuleTenantHeader := []string{
		"Tenant",
		"Namespaces",
		"Namespace Quota",
		"Owners",
		"Limit Ranges",
		"Resource Quotas",
		"Network Policies",
		"Bypass Risk",
	}

	vclusterHeader := []string{
		"Name",
		"Namespace",
		"Status",
		"Syncer Running",
		"K8s Version",
		"Host Role",
		"Bypass Risk",
	}

	isolationHeader := []string{
		"Namespace",
		"Tenant Label",
		"Network Policy",
		"Default Deny Ingress",
		"Default Deny Egress",
		"Resource Quota",
		"Limit Range",
		"Pod Security Std",
		"Bypass Risk",
	}

	crossTenantHeader := []string{
		"Type",
		"Name",
		"Scope",
		"Affected Tenants",
		"Risk Level",
		"Description",
		"Bypass Risk",
	}

	opaGatekeeperHeader := []string{
		"Namespace",
		"Status",
		"Pods Running",
		"Image Verified",
		"Constraint Templates",
		"Constraints",
		"Tenant Policies",
		"Bypass Risk",
	}

	var summaryRows [][]string
	var hncRows [][]string
	var hncHierarchyRows [][]string
	var capsuleRows [][]string
	var capsuleTenantRows [][]string
	var vclusterRows [][]string
	var isolationRows [][]string
	var crossTenantRows [][]string
	var opaGatekeeperRows [][]string

	loot := shared.NewLootBuilder()

	// Build summary rows
	for _, finding := range findings {
		isolated := "No"
		if finding.IsIsolated {
			isolated = "Yes"
		}
		netpol := "No"
		if finding.HasNetworkPolicy {
			netpol = "Yes"
		}
		quota := "No"
		if finding.HasResourceQuota {
			quota = "Yes"
		}
		limitRange := "No"
		if finding.HasLimitRange {
			limitRange = "Yes"
		}
		podSec := "-"
		if finding.HasPodSecurityStd {
			podSec = "Yes"
		}

		tenant := finding.TenantName
		if tenant == "" {
			tenant = "-"
		}
		provider := finding.TenantProvider
		if provider == "" {
			provider = "-"
		}

		issues := "-"
		if len(finding.SecurityIssues) > 0 {
			if len(finding.SecurityIssues) > 2 {
				issues = strings.Join(finding.SecurityIssues[:2], "; ") + fmt.Sprintf(" (+%d)", len(finding.SecurityIssues)-2)
			} else {
				issues = strings.Join(finding.SecurityIssues, "; ")
			}
		}

		summaryRows = append(summaryRows, []string{
			finding.Namespace,
			tenant,
			provider,
			isolated,
			netpol,
			quota,
			limitRange,
			podSec,
			finding.RiskLevel,
			issues,
		})
	}

	// Build HNC rows
	if hnc.Name != "" {
		hncRows = append(hncRows, []string{
			hnc.Namespace,
			hnc.Status,
			fmt.Sprintf("%d/%d", hnc.PodsRunning, hnc.TotalPods),
			fmt.Sprintf("%d", hnc.Hierarchies),
			hnc.BypassRisk,
		})
	}

	// Build HNC hierarchy rows
	for _, h := range hncHierarchies {
		children := "-"
		if len(h.Children) > 0 {
			if len(h.Children) > 3 {
				children = strings.Join(h.Children[:3], ", ") + "..."
			} else {
				children = strings.Join(h.Children, ", ")
			}
		}

		parent := h.Parent
		if parent == "" {
			parent = "-"
		}

		hncHierarchyRows = append(hncHierarchyRows, []string{
			h.Namespace,
			parent,
			children,
			fmt.Sprintf("%d", h.DepthFromRoot),
			fmt.Sprintf("%d", h.PropagatedRoles),
			h.BypassRisk,
		})
	}

	// Build Capsule rows
	if capsule.Name != "" {
		capsuleRows = append(capsuleRows, []string{
			capsule.Namespace,
			capsule.Status,
			fmt.Sprintf("%d/%d", capsule.PodsRunning, capsule.TotalPods),
			fmt.Sprintf("%d", capsule.Tenants),
			capsule.BypassRisk,
		})
	}

	// Build Capsule tenant rows
	for _, t := range capsuleTenants {
		namespaces := "-"
		if len(t.Namespaces) > 0 {
			if len(t.Namespaces) > 3 {
				namespaces = strings.Join(t.Namespaces[:3], ", ") + "..."
			} else {
				namespaces = strings.Join(t.Namespaces, ", ")
			}
		}

		owners := "-"
		if len(t.Owners) > 0 {
			owners = strings.Join(t.Owners, ", ")
		}

		limitRanges := "No"
		if t.LimitRanges {
			limitRanges = "Yes"
		}
		resourceQuotas := "No"
		if t.ResourceQuotas {
			resourceQuotas = "Yes"
		}
		networkPolicies := "No"
		if t.NetworkPolicies {
			networkPolicies = "Yes"
		}

		capsuleTenantRows = append(capsuleTenantRows, []string{
			t.Name,
			namespaces,
			fmt.Sprintf("%d", t.NamespaceQuota),
			owners,
			limitRanges,
			resourceQuotas,
			networkPolicies,
			t.BypassRisk,
		})
	}

	// Build vCluster rows
	for _, v := range vclusters {
		syncer := "No"
		if v.SyncerRunning {
			syncer = "Yes"
		}

		vclusterRows = append(vclusterRows, []string{
			v.Name,
			v.Namespace,
			v.Status,
			syncer,
			v.K8sVersion,
			v.HostClusterRole,
			v.BypassRisk,
		})
	}

	// Build isolation rows
	for _, iso := range nsIsolation {
		netpol := "No"
		if iso.HasNetworkPolicy {
			netpol = "Yes"
		}
		denyIngress := "No"
		if iso.DefaultDenyIngress {
			denyIngress = "Yes"
		}
		denyEgress := "No"
		if iso.DefaultDenyEgress {
			denyEgress = "Yes"
		}
		quota := "No"
		if iso.HasResourceQuota {
			quota = "Yes"
		}
		limitRange := "No"
		if iso.HasLimitRange {
			limitRange = "Yes"
		}

		tenantLabel := "-"
		if iso.TenantLabel != "" && iso.TenantValue != "" {
			tenantLabel = fmt.Sprintf("%s=%s", iso.TenantLabel, iso.TenantValue)
		}

		podSecStd := iso.PodSecurityStd
		if podSecStd == "" {
			podSecStd = "-"
		}

		isolationRows = append(isolationRows, []string{
			iso.Namespace,
			tenantLabel,
			netpol,
			denyIngress,
			denyEgress,
			quota,
			limitRange,
			podSecStd,
			iso.BypassRisk,
		})
	}

	// Build cross-tenant resource rows
	for _, ctr := range crossTenantResources {
		affectedTenants := "-"
		if len(ctr.AffectedTenants) > 0 {
			if len(ctr.AffectedTenants) > 3 {
				affectedTenants = strings.Join(ctr.AffectedTenants[:3], ", ") + "..."
			} else {
				affectedTenants = strings.Join(ctr.AffectedTenants, ", ")
			}
		}

		bypassRisk := "-"
		if ctr.BypassRisk != "" {
			bypassRisk = ctr.BypassRisk
		}

		crossTenantRows = append(crossTenantRows, []string{
			ctr.Type,
			ctr.Name,
			ctr.Scope,
			affectedTenants,
			ctr.RiskLevel,
			ctr.Description,
			bypassRisk,
		})
	}

	// Build OPA/Gatekeeper rows
	if opaGatekeeper.Name != "" {
		imageVerified := "No"
		if opaGatekeeper.ImageVerified {
			imageVerified = "Yes"
		}
		bypassRisk := "-"
		if opaGatekeeper.BypassRisk != "" {
			bypassRisk = opaGatekeeper.BypassRisk
		}
		opaGatekeeperRows = append(opaGatekeeperRows, []string{
			opaGatekeeper.Namespace,
			opaGatekeeper.Status,
			fmt.Sprintf("%d/%d", opaGatekeeper.PodsRunning, opaGatekeeper.TotalPods),
			imageVerified,
			fmt.Sprintf("%d", opaGatekeeper.ConstraintTemplates),
			fmt.Sprintf("%d", opaGatekeeper.Constraints),
			fmt.Sprintf("%d", opaGatekeeper.TenantIsolationPolicies),
			bypassRisk,
		})
	}

	// Generate loot
	generateMultitenancyLoot(loot, findings, hnc, hncHierarchies, capsule, capsuleTenants, vclusters, loft, loftSpaces, kiosk, kioskAccounts, nsIsolation, opaGatekeeper)

	// Build output tables
	var tables []internal.TableFile

	tables = append(tables, internal.TableFile{
		Name:   "Multitenancy-Admission-Summary",
		Header: summaryHeader,
		Body:   summaryRows,
	})

	if len(hncRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Multitenancy-Admission-HNC",
			Header: hncHeader,
			Body:   hncRows,
		})
	}

	if len(hncHierarchyRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Multitenancy-Admission-HNC-Hierarchies",
			Header: hncHierarchyHeader,
			Body:   hncHierarchyRows,
		})
	}

	if len(capsuleRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Multitenancy-Admission-Capsule",
			Header: capsuleHeader,
			Body:   capsuleRows,
		})
	}

	if len(capsuleTenantRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Multitenancy-Admission-Capsule-Tenants",
			Header: capsuleTenantHeader,
			Body:   capsuleTenantRows,
		})
	}

	if len(vclusterRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Multitenancy-Admission-vClusters",
			Header: vclusterHeader,
			Body:   vclusterRows,
		})
	}

	if len(isolationRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Multitenancy-Admission-Namespace-Isolation",
			Header: isolationHeader,
			Body:   isolationRows,
		})
	}

	if len(crossTenantRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Multitenancy-Admission-Cross-Tenant-Resources",
			Header: crossTenantHeader,
			Body:   crossTenantRows,
		})
	}

	if len(opaGatekeeperRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Multitenancy-Admission-OPA-Gatekeeper",
			Header: opaGatekeeperHeader,
			Body:   opaGatekeeperRows,
		})
	}

	output := MultitenancyAdmissionOutput{
		Table: tables,
		Loot:  loot.Build(),
	}

	err := internal.HandleOutput(
		"Kubernetes",
		"table",
		outputDir,
		verbosity,
		wrap,
		"Multitenancy-Admission",
		globals.ClusterName,
		"results",
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), K8S_MULTITENANCY_ADMISSION_MODULE_NAME)
		return
	}
}

// ============================================================================
// HNC Analysis
// ============================================================================

func analyzeHNC(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) (HNCInfo, []HNCHierarchyInfo) {
	info := HNCInfo{}
	var hierarchies []HNCHierarchyInfo

	// Image patterns for verification to reduce false positives
	imagePatterns := []string{
		"hierarchical-namespaces",
		"hnc-controller",
		"hnc-manager",
		"k8s.gcr.io/hnc",
		"gcr.io/k8s-staging-multitenancy",
		"registry.k8s.io/hnc",
	}

	// Check for HNC deployment
	namespaces := []string{"hnc-system", "kube-system"}
	for _, ns := range namespaces {
		deployments, err := clientset.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, dep := range deployments.Items {
			if strings.Contains(strings.ToLower(dep.Name), "hnc-controller") ||
				strings.Contains(strings.ToLower(dep.Name), "hierarchical-namespaces") {
				info.Name = "HNC"
				info.Namespace = ns
				info.Status = "active"

				// Verify by image to reduce false positives
				for _, container := range dep.Spec.Template.Spec.Containers {
					for _, pattern := range imagePatterns {
						if strings.Contains(strings.ToLower(container.Image), pattern) {
							info.ImageVerified = true
							break
						}
					}
					if info.ImageVerified {
						break
					}
				}

				if dep.Status.ReadyReplicas < dep.Status.Replicas {
					info.Status = "degraded"
					info.BypassRisk = fmt.Sprintf("Only %d/%d HNC pods running", dep.Status.ReadyReplicas, dep.Status.Replicas)
				}

				if !info.ImageVerified {
					info.Status = "unverified"
					if info.BypassRisk != "" {
						info.BypassRisk += "; "
					}
					info.BypassRisk += "Detection based on name only - verify manually"
				}

				info.TotalPods = int(dep.Status.Replicas)
				info.PodsRunning = int(dep.Status.ReadyReplicas)
				break
			}
		}
		if info.Name != "" {
			break
		}
	}

	if info.Name == "" {
		return info, hierarchies
	}

	// Get HierarchyConfiguration CRDs
	hncConfigGVR := schema.GroupVersionResource{
		Group:    "hnc.x-k8s.io",
		Version:  "v1alpha2",
		Resource: "hierarchyconfigurations",
	}

	configList, err := dynClient.Resource(hncConfigGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range configList.Items {
			h := parseHNCHierarchy(item.Object)
			hierarchies = append(hierarchies, h)
			info.Hierarchies++
		}
	}

	// Build parent-child relationships
	parentMap := make(map[string]string)
	for _, h := range hierarchies {
		if h.Parent != "" {
			parentMap[h.Namespace] = h.Parent
		}
	}

	// Calculate depth and children
	for i := range hierarchies {
		// Calculate depth
		depth := 0
		current := hierarchies[i].Namespace
		visited := make(map[string]bool)
		for {
			parent, hasParent := parentMap[current]
			if !hasParent || visited[current] {
				break
			}
			visited[current] = true
			depth++
			current = parent
		}
		hierarchies[i].DepthFromRoot = depth

		// Find children
		for _, h := range hierarchies {
			if h.Parent == hierarchies[i].Namespace {
				hierarchies[i].Children = append(hierarchies[i].Children, h.Namespace)
			}
		}
	}

	return info, hierarchies
}

func parseHNCHierarchy(obj map[string]interface{}) HNCHierarchyInfo {
	h := HNCHierarchyInfo{}

	if metadata, ok := obj["metadata"].(map[string]interface{}); ok {
		h.Namespace, _ = metadata["namespace"].(string)
	}

	if spec, ok := obj["spec"].(map[string]interface{}); ok {
		if parent, ok := spec["parent"].(string); ok {
			h.Parent = parent
		}
	}

	if status, ok := obj["status"].(map[string]interface{}); ok {
		if children, ok := status["children"].([]interface{}); ok {
			for _, child := range children {
				if childStr, ok := child.(string); ok {
					h.Children = append(h.Children, childStr)
				}
			}
		}
	}

	return h
}

// ============================================================================
// Capsule Analysis
// ============================================================================

func analyzeCapsule(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) (CapsuleInfo, []CapsuleTenantInfo) {
	info := CapsuleInfo{}
	var tenants []CapsuleTenantInfo

	// Image patterns for verification to reduce false positives
	imagePatterns := []string{
		"capsule",
		"clastix/capsule",
		"ghcr.io/projectcapsule/capsule",
		"quay.io/clastix/capsule",
	}

	// Check for Capsule deployment
	namespaces := []string{"capsule-system", "kube-system"}
	for _, ns := range namespaces {
		deployments, err := clientset.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, dep := range deployments.Items {
			if strings.Contains(strings.ToLower(dep.Name), "capsule") {
				info.Name = "Capsule"
				info.Namespace = ns
				info.Status = "active"

				// Verify by image to reduce false positives
				for _, container := range dep.Spec.Template.Spec.Containers {
					for _, pattern := range imagePatterns {
						if strings.Contains(strings.ToLower(container.Image), pattern) {
							info.ImageVerified = true
							break
						}
					}
					if info.ImageVerified {
						break
					}
				}

				if dep.Status.ReadyReplicas < dep.Status.Replicas {
					info.Status = "degraded"
					info.BypassRisk = fmt.Sprintf("Only %d/%d Capsule pods running", dep.Status.ReadyReplicas, dep.Status.Replicas)
				}

				if !info.ImageVerified {
					info.Status = "unverified"
					if info.BypassRisk != "" {
						info.BypassRisk += "; "
					}
					info.BypassRisk += "Detection based on name only - verify manually"
				}

				info.TotalPods = int(dep.Status.Replicas)
				info.PodsRunning = int(dep.Status.ReadyReplicas)
				break
			}
		}
		if info.Name != "" {
			break
		}
	}

	if info.Name == "" {
		return info, tenants
	}

	// Get Tenant CRDs
	tenantGVR := schema.GroupVersionResource{
		Group:    "capsule.clastix.io",
		Version:  "v1beta2",
		Resource: "tenants",
	}

	tenantList, err := dynClient.Resource(tenantGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err != nil {
		// Try v1beta1
		tenantGVR.Version = "v1beta1"
		tenantList, err = dynClient.Resource(tenantGVR).Namespace("").List(ctx, metav1.ListOptions{})
	}

	if err == nil {
		for _, item := range tenantList.Items {
			t := parseCapsuleTenant(item.Object)
			tenants = append(tenants, t)
			info.Tenants++
		}
	}

	return info, tenants
}

func parseCapsuleTenant(obj map[string]interface{}) CapsuleTenantInfo {
	t := CapsuleTenantInfo{}

	if metadata, ok := obj["metadata"].(map[string]interface{}); ok {
		t.Name, _ = metadata["name"].(string)
	}

	if spec, ok := obj["spec"].(map[string]interface{}); ok {
		// Parse owners
		if owners, ok := spec["owners"].([]interface{}); ok {
			for _, owner := range owners {
				if ownerMap, ok := owner.(map[string]interface{}); ok {
					if name, ok := ownerMap["name"].(string); ok {
						kind, _ := ownerMap["kind"].(string)
						t.Owners = append(t.Owners, fmt.Sprintf("%s/%s", kind, name))
					}
				}
			}
		}

		// Parse namespace quota
		if nsQuota, ok := spec["namespaceOptions"].(map[string]interface{}); ok {
			if quota, ok := nsQuota["quota"].(float64); ok {
				t.NamespaceQuota = int(quota)
			}
		}

		// Check for limit ranges
		if limitRanges, ok := spec["limitRanges"].(map[string]interface{}); ok {
			if items, ok := limitRanges["items"].([]interface{}); ok && len(items) > 0 {
				t.LimitRanges = true
			}
		}

		// Check for resource quotas
		if resourceQuotas, ok := spec["resourceQuotas"].(map[string]interface{}); ok {
			if items, ok := resourceQuotas["items"].([]interface{}); ok && len(items) > 0 {
				t.ResourceQuotas = true
			}
		}

		// Check for network policies
		if networkPolicies, ok := spec["networkPolicies"].(map[string]interface{}); ok {
			if items, ok := networkPolicies["items"].([]interface{}); ok && len(items) > 0 {
				t.NetworkPolicies = true
			}
		}

		// Parse allowed ingress classes
		if ingressClasses, ok := spec["ingressOptions"].(map[string]interface{}); ok {
			if allowed, ok := ingressClasses["allowedClasses"].(map[string]interface{}); ok {
				if items, ok := allowed["allowed"].([]interface{}); ok {
					for _, item := range items {
						if str, ok := item.(string); ok {
							t.IngressClasses = append(t.IngressClasses, str)
						}
					}
				}
			}
		}

		// Parse allowed storage classes
		if storageClasses, ok := spec["storageClasses"].(map[string]interface{}); ok {
			if allowed, ok := storageClasses["allowed"].([]interface{}); ok {
				for _, item := range allowed {
					if str, ok := item.(string); ok {
						t.StorageClasses = append(t.StorageClasses, str)
					}
				}
			}
		}
	}

	if status, ok := obj["status"].(map[string]interface{}); ok {
		if namespaces, ok := status["namespaces"].([]interface{}); ok {
			for _, ns := range namespaces {
				if nsStr, ok := ns.(string); ok {
					t.Namespaces = append(t.Namespaces, nsStr)
				}
			}
		}
	}

	// Assess risk
	if !t.NetworkPolicies {
		t.BypassRisk = "No network policies enforced"
	}
	if !t.ResourceQuotas {
		if t.BypassRisk != "" {
			t.BypassRisk += "; "
		}
		t.BypassRisk += "No resource quotas"
	}

	return t
}

// ============================================================================
// vCluster Analysis
// ============================================================================

func analyzeVClusters(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) []VClusterInfo {
	var vclusters []VClusterInfo

	// Image patterns for verification to reduce false positives
	imagePatterns := []string{
		"vcluster",
		"loft-sh/vcluster",
		"ghcr.io/loft-sh/vcluster",
		"loftsh/vcluster",
	}

	// Check for vCluster via label selector
	statefulSets, err := clientset.AppsV1().StatefulSets("").List(ctx, metav1.ListOptions{
		LabelSelector: "app=vcluster",
	})
	if err == nil {
		for _, sts := range statefulSets.Items {
			v := VClusterInfo{
				Name:      strings.TrimSuffix(sts.Name, "-vcluster"),
				Namespace: sts.Namespace,
				Status:    "active",
			}

			if sts.Status.ReadyReplicas < *sts.Spec.Replicas {
				v.Status = "degraded"
				v.BypassRisk = fmt.Sprintf("Only %d/%d replicas ready", sts.Status.ReadyReplicas, *sts.Spec.Replicas)
			}
			v.TotalPods = int(*sts.Spec.Replicas)
			v.PodsRunning = int(sts.Status.ReadyReplicas)

			// Check for syncer and verify image
			for _, container := range sts.Spec.Template.Spec.Containers {
				// Verify by image to reduce false positives
				for _, pattern := range imagePatterns {
					if strings.Contains(strings.ToLower(container.Image), pattern) {
						v.ImageVerified = true
						break
					}
				}

				if strings.Contains(container.Image, "syncer") || container.Name == "syncer" {
					v.SyncerRunning = true
				}
				// Try to get K8s version from image
				if strings.Contains(container.Image, "k8s.io") || strings.Contains(container.Image, "k3s") {
					parts := strings.Split(container.Image, ":")
					if len(parts) > 1 {
						v.K8sVersion = parts[1]
					}
				}
			}

			if !v.ImageVerified {
				v.Status = "unverified"
				if v.BypassRisk != "" {
					v.BypassRisk += "; "
				}
				v.BypassRisk += "Detection based on labels only - verify manually"
			}

			vclusters = append(vclusters, v)
		}
	}

	// Also check for VirtualCluster CRD (Loft/vCluster Pro)
	vcGVR := schema.GroupVersionResource{
		Group:    "management.loft.sh",
		Version:  "v1",
		Resource: "virtualclusters",
	}

	vcList, err := dynClient.Resource(vcGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range vcList.Items {
			v := parseVirtualCluster(item.Object)
			// Avoid duplicates
			found := false
			for _, existing := range vclusters {
				if existing.Name == v.Name && existing.Namespace == v.Namespace {
					found = true
					break
				}
			}
			if !found {
				vclusters = append(vclusters, v)
			}
		}
	}

	return vclusters
}

func parseVirtualCluster(obj map[string]interface{}) VClusterInfo {
	v := VClusterInfo{
		Status: "active",
	}

	if metadata, ok := obj["metadata"].(map[string]interface{}); ok {
		v.Name, _ = metadata["name"].(string)
		v.Namespace, _ = metadata["namespace"].(string)
	}

	if spec, ok := obj["spec"].(map[string]interface{}); ok {
		if helmRelease, ok := spec["helmRelease"].(map[string]interface{}); ok {
			if values, ok := helmRelease["values"].(string); ok {
				if strings.Contains(values, "k3s") {
					v.K8sVersion = "k3s"
				}
			}
		}
	}

	if status, ok := obj["status"].(map[string]interface{}); ok {
		if phase, ok := status["phase"].(string); ok {
			if phase != "Running" {
				v.Status = strings.ToLower(phase)
			}
		}
	}

	return v
}

// ============================================================================
// Loft Analysis
// ============================================================================

func analyzeLoft(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) (LoftInfo, []LoftSpaceInfo) {
	info := LoftInfo{}
	var spaces []LoftSpaceInfo

	// Image patterns for verification to reduce false positives
	imagePatterns := []string{
		"loft",
		"loft-sh/loft",
		"ghcr.io/loft-sh/loft",
		"loftsh/loft",
	}

	// Check for Loft deployment
	namespaces := []string{"loft", "loft-system"}
	for _, ns := range namespaces {
		deployments, err := clientset.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, dep := range deployments.Items {
			if strings.Contains(strings.ToLower(dep.Name), "loft") {
				info.Name = "Loft"
				info.Namespace = ns
				info.Status = "active"

				// Verify by image to reduce false positives
				for _, container := range dep.Spec.Template.Spec.Containers {
					for _, pattern := range imagePatterns {
						if strings.Contains(strings.ToLower(container.Image), pattern) {
							info.ImageVerified = true
							break
						}
					}
					if info.ImageVerified {
						break
					}
				}

				if dep.Status.ReadyReplicas < dep.Status.Replicas {
					info.Status = "degraded"
					info.BypassRisk = fmt.Sprintf("Only %d/%d Loft pods running", dep.Status.ReadyReplicas, dep.Status.Replicas)
				}

				if !info.ImageVerified {
					info.Status = "unverified"
					if info.BypassRisk != "" {
						info.BypassRisk += "; "
					}
					info.BypassRisk += "Detection based on name only - verify manually"
				}

				info.TotalPods = int(dep.Status.Replicas)
				info.PodsRunning = int(dep.Status.ReadyReplicas)
				break
			}
		}
		if info.Name != "" {
			break
		}
	}

	if info.Name == "" {
		return info, spaces
	}

	// Get Space CRDs
	spaceGVR := schema.GroupVersionResource{
		Group:    "management.loft.sh",
		Version:  "v1",
		Resource: "spaces",
	}

	spaceList, err := dynClient.Resource(spaceGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range spaceList.Items {
			s := parseLoftSpace(item.Object)
			spaces = append(spaces, s)
			info.Spaces++
		}
	}

	// Get VirtualCluster count
	vcGVR := schema.GroupVersionResource{
		Group:    "management.loft.sh",
		Version:  "v1",
		Resource: "virtualclusters",
	}

	vcList, err := dynClient.Resource(vcGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		info.VirtualClusters = len(vcList.Items)
	}

	// Get Team count
	teamGVR := schema.GroupVersionResource{
		Group:    "management.loft.sh",
		Version:  "v1",
		Resource: "teams",
	}

	teamList, err := dynClient.Resource(teamGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		info.Teams = len(teamList.Items)
	}

	return info, spaces
}

func parseLoftSpace(obj map[string]interface{}) LoftSpaceInfo {
	s := LoftSpaceInfo{}

	if metadata, ok := obj["metadata"].(map[string]interface{}); ok {
		s.Name, _ = metadata["name"].(string)
	}

	if spec, ok := obj["spec"].(map[string]interface{}); ok {
		if team, ok := spec["team"].(string); ok {
			s.Team = team
		}
		if user, ok := spec["user"].(string); ok {
			s.User = user
		}
		if sleepAfter, ok := spec["sleepAfter"].(string); ok {
			s.SleepAfter = sleepAfter
		}
		if deleteAfter, ok := spec["deleteAfter"].(string); ok {
			s.DeleteAfter = deleteAfter
		}
	}

	if status, ok := obj["status"].(map[string]interface{}); ok {
		if namespace, ok := status["namespace"].(string); ok {
			s.Namespace = namespace
		}
	}

	return s
}

// ============================================================================
// Kiosk Analysis
// ============================================================================

func analyzeKiosk(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) (KioskInfo, []KioskAccountInfo) {
	info := KioskInfo{}
	var accounts []KioskAccountInfo

	// Image patterns for verification to reduce false positives
	imagePatterns := []string{
		"kiosk",
		"loft-sh/kiosk",
		"ghcr.io/loft-sh/kiosk",
		"loftsh/kiosk",
	}

	// Check for Kiosk deployment
	namespaces := []string{"kiosk", "kube-system"}
	for _, ns := range namespaces {
		deployments, err := clientset.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, dep := range deployments.Items {
			if strings.Contains(strings.ToLower(dep.Name), "kiosk") {
				info.Name = "Kiosk"
				info.Namespace = ns
				info.Status = "active"

				// Verify by image to reduce false positives
				for _, container := range dep.Spec.Template.Spec.Containers {
					for _, pattern := range imagePatterns {
						if strings.Contains(strings.ToLower(container.Image), pattern) {
							info.ImageVerified = true
							break
						}
					}
					if info.ImageVerified {
						break
					}
				}

				if dep.Status.ReadyReplicas < dep.Status.Replicas {
					info.Status = "degraded"
					info.BypassRisk = fmt.Sprintf("Only %d/%d Kiosk pods running", dep.Status.ReadyReplicas, dep.Status.Replicas)
				}

				if !info.ImageVerified {
					info.Status = "unverified"
					if info.BypassRisk != "" {
						info.BypassRisk += "; "
					}
					info.BypassRisk += "Detection based on name only - verify manually"
				}

				info.TotalPods = int(dep.Status.Replicas)
				info.PodsRunning = int(dep.Status.ReadyReplicas)
				break
			}
		}
		if info.Name != "" {
			break
		}
	}

	if info.Name == "" {
		return info, accounts
	}

	// Get Account CRDs
	accountGVR := schema.GroupVersionResource{
		Group:    "tenancy.kiosk.sh",
		Version:  "v1alpha1",
		Resource: "accounts",
	}

	accountList, err := dynClient.Resource(accountGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range accountList.Items {
			a := parseKioskAccount(item.Object)
			accounts = append(accounts, a)
			info.Accounts++
		}
	}

	// Get Space count
	spaceGVR := schema.GroupVersionResource{
		Group:    "tenancy.kiosk.sh",
		Version:  "v1alpha1",
		Resource: "spaces",
	}

	spaceList, err := dynClient.Resource(spaceGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		info.Spaces = len(spaceList.Items)
	}

	return info, accounts
}

func parseKioskAccount(obj map[string]interface{}) KioskAccountInfo {
	a := KioskAccountInfo{}

	if metadata, ok := obj["metadata"].(map[string]interface{}); ok {
		a.Name, _ = metadata["name"].(string)
	}

	if spec, ok := obj["spec"].(map[string]interface{}); ok {
		// Parse subjects
		if subjects, ok := spec["subjects"].([]interface{}); ok {
			for _, subj := range subjects {
				if subjMap, ok := subj.(map[string]interface{}); ok {
					kind, _ := subjMap["kind"].(string)
					name, _ := subjMap["name"].(string)
					a.Subjects = append(a.Subjects, fmt.Sprintf("%s/%s", kind, name))
				}
			}
		}

		// Parse space limit
		if space, ok := spec["space"].(map[string]interface{}); ok {
			if limit, ok := space["limit"].(float64); ok {
				a.SpaceLimit = int(limit)
			}
		}
	}

	if status, ok := obj["status"].(map[string]interface{}); ok {
		if namespaces, ok := status["namespaces"].([]interface{}); ok {
			a.SpacesUsed = len(namespaces)
		}
	}

	if a.SpaceLimit == 0 {
		a.BypassRisk = "No space limit configured"
	}

	return a
}

// ============================================================================
// OPA/Gatekeeper Tenant Policy Analysis
// ============================================================================

func analyzeOPAGatekeeperTenant(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) OPAGatekeeperTenantInfo {
	info := OPAGatekeeperTenantInfo{}

	// Image patterns for verification to reduce false positives
	imagePatterns := []string{
		"gatekeeper",
		"openpolicyagent/gatekeeper",
		"gatekeeper.azurecr.io",
		"opa-gatekeeper",
	}

	// Check for Gatekeeper deployment
	namespaces := []string{"gatekeeper-system", "opa-system", "kube-system"}
	for _, ns := range namespaces {
		deployments, err := clientset.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, dep := range deployments.Items {
			if strings.Contains(strings.ToLower(dep.Name), "gatekeeper") ||
				strings.Contains(strings.ToLower(dep.Name), "controller-manager") {
				info.Name = "OPA Gatekeeper"
				info.Namespace = ns
				info.Status = "active"

				// Verify by image to reduce false positives
				for _, container := range dep.Spec.Template.Spec.Containers {
					for _, pattern := range imagePatterns {
						if strings.Contains(strings.ToLower(container.Image), pattern) {
							info.ImageVerified = true
							break
						}
					}
					if info.ImageVerified {
						break
					}
				}

				if dep.Status.ReadyReplicas < dep.Status.Replicas {
					info.Status = "degraded"
					info.BypassRisk = fmt.Sprintf("Only %d/%d Gatekeeper pods running", dep.Status.ReadyReplicas, dep.Status.Replicas)
				}

				if !info.ImageVerified {
					info.Status = "unverified"
					if info.BypassRisk != "" {
						info.BypassRisk += "; "
					}
					info.BypassRisk += "Detection based on name only - verify manually"
				}

				info.TotalPods = int(dep.Status.Replicas)
				info.PodsRunning = int(dep.Status.ReadyReplicas)
				break
			}
		}
		if info.Name != "" {
			break
		}
	}

	if info.Name == "" {
		return info
	}

	// Count ConstraintTemplates
	constraintTemplateGVR := schema.GroupVersionResource{
		Group:    "templates.gatekeeper.sh",
		Version:  "v1",
		Resource: "constrainttemplates",
	}

	ctList, err := dynClient.Resource(constraintTemplateGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		info.ConstraintTemplates = len(ctList.Items)
	} else {
		// Try v1beta1
		constraintTemplateGVR.Version = "v1beta1"
		ctList, err = dynClient.Resource(constraintTemplateGVR).Namespace("").List(ctx, metav1.ListOptions{})
		if err == nil {
			info.ConstraintTemplates = len(ctList.Items)
		}
	}

	// Count Constraints and check for tenant isolation policies
	tenantPolicyKeywords := []string{"tenant", "namespace", "isolation", "label", "team", "project"}

	// Get all constraint kinds by listing constraint templates
	if ctList != nil {
		for _, ct := range ctList.Items {
			kind := ""
			if spec, ok := ct.Object["spec"].(map[string]interface{}); ok {
				if crd, ok := spec["crd"].(map[string]interface{}); ok {
					if names, ok := crd["spec"].(map[string]interface{}); ok {
						if namesSpec, ok := names["names"].(map[string]interface{}); ok {
							kind, _ = namesSpec["kind"].(string)
						}
					}
				}
			}

			if kind != "" {
				// Try to list constraints of this kind
				constraintGVR := schema.GroupVersionResource{
					Group:    "constraints.gatekeeper.sh",
					Version:  "v1beta1",
					Resource: strings.ToLower(kind),
				}

				constraintList, err := dynClient.Resource(constraintGVR).Namespace("").List(ctx, metav1.ListOptions{})
				if err == nil {
					info.Constraints += len(constraintList.Items)

					// Check for tenant isolation policies
					for _, constraint := range constraintList.Items {
						name := constraint.GetName()
						nameLower := strings.ToLower(name)
						for _, keyword := range tenantPolicyKeywords {
							if strings.Contains(nameLower, keyword) {
								info.TenantIsolationPolicies++
								break
							}
						}
					}
				}
			}
		}
	}

	// Assess bypass risk
	if info.TenantIsolationPolicies == 0 {
		if info.BypassRisk != "" {
			info.BypassRisk += "; "
		}
		info.BypassRisk += "No tenant isolation policies detected"
	}

	return info
}

// ============================================================================
// Namespace Isolation Analysis
// ============================================================================

func analyzeNamespaceIsolation(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) []NamespaceIsolationInfo {
	var isolation []NamespaceIsolationInfo

	for _, ns := range globals.K8sNamespaces {
		iso := NamespaceIsolationInfo{
			Namespace: ns,
		}

		// Get namespace
		namespace, err := clientset.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{})
		if err != nil {
			continue
		}

		// Check for tenant labels
		tenantLabels := []string{
			"capsule.clastix.io/tenant",
			"tenant",
			"team",
			"project",
			"hnc.x-k8s.io/included-namespace",
		}
		for _, label := range tenantLabels {
			if value, ok := namespace.Labels[label]; ok {
				iso.TenantLabel = label
				iso.TenantValue = value
				break
			}
		}

		// Check for Pod Security Standards
		if enforce, ok := namespace.Labels["pod-security.kubernetes.io/enforce"]; ok {
			iso.PodSecurityStd = enforce
		}

		// Check for network policies
		netpols, err := clientset.NetworkingV1().NetworkPolicies(ns).List(ctx, metav1.ListOptions{})
		if err == nil && len(netpols.Items) > 0 {
			iso.HasNetworkPolicy = true

			// Check for default deny
			for _, np := range netpols.Items {
				// Default deny ingress: empty podSelector, ingress with no rules
				if len(np.Spec.PodSelector.MatchLabels) == 0 && len(np.Spec.PodSelector.MatchExpressions) == 0 {
					for _, policyType := range np.Spec.PolicyTypes {
						if policyType == "Ingress" && len(np.Spec.Ingress) == 0 {
							iso.DefaultDenyIngress = true
						}
						if policyType == "Egress" && len(np.Spec.Egress) == 0 {
							iso.DefaultDenyEgress = true
						}
					}
				}
			}
		}

		// Check for resource quotas
		quotas, err := clientset.CoreV1().ResourceQuotas(ns).List(ctx, metav1.ListOptions{})
		if err == nil && len(quotas.Items) > 0 {
			iso.HasResourceQuota = true
		}

		// Check for limit ranges
		limitRanges, err := clientset.CoreV1().LimitRanges(ns).List(ctx, metav1.ListOptions{})
		if err == nil && len(limitRanges.Items) > 0 {
			iso.HasLimitRange = true
		}

		// Assess risk
		var risks []string
		if !iso.HasNetworkPolicy {
			risks = append(risks, "No network policy")
		} else if !iso.DefaultDenyIngress {
			risks = append(risks, "No default deny ingress")
		}
		if !iso.HasResourceQuota {
			risks = append(risks, "No resource quota")
		}
		if iso.PodSecurityStd == "" || iso.PodSecurityStd == "privileged" {
			risks = append(risks, "No pod security enforcement")
		}

		if len(risks) > 0 {
			iso.BypassRisk = strings.Join(risks, "; ")
		}

		isolation = append(isolation, iso)
	}

	return isolation
}

// ============================================================================
// Build Findings
// ============================================================================

func buildMultitenancyFindings(
	hnc HNCInfo, hncHierarchies []HNCHierarchyInfo,
	capsule CapsuleInfo, capsuleTenants []CapsuleTenantInfo,
	vclusters []VClusterInfo,
	loft LoftInfo, loftSpaces []LoftSpaceInfo,
	kiosk KioskInfo, kioskAccounts []KioskAccountInfo,
	nsIsolation []NamespaceIsolationInfo) []MultitenancyAdmissionFinding {

	var findings []MultitenancyAdmissionFinding

	// Build namespace -> tenant mapping
	nsTenant := make(map[string]string)
	nsProvider := make(map[string]string)

	// From Capsule tenants
	for _, t := range capsuleTenants {
		for _, ns := range t.Namespaces {
			nsTenant[ns] = t.Name
			nsProvider[ns] = "Capsule"
		}
	}

	// From HNC hierarchies
	for _, h := range hncHierarchies {
		if _, ok := nsTenant[h.Namespace]; !ok {
			if h.Parent != "" {
				nsTenant[h.Namespace] = h.Parent
				nsProvider[h.Namespace] = "HNC"
			}
		}
	}

	// From vClusters
	for _, v := range vclusters {
		if _, ok := nsTenant[v.Namespace]; !ok {
			nsTenant[v.Namespace] = v.Name
			nsProvider[v.Namespace] = "vCluster"
		}
	}

	// From Loft spaces
	for _, s := range loftSpaces {
		if _, ok := nsTenant[s.Namespace]; !ok {
			if s.Team != "" {
				nsTenant[s.Namespace] = s.Team
			} else if s.User != "" {
				nsTenant[s.Namespace] = s.User
			}
			nsProvider[s.Namespace] = "Loft"
		}
	}

	// Build findings from isolation data
	for _, iso := range nsIsolation {
		finding := MultitenancyAdmissionFinding{
			Namespace:         iso.Namespace,
			TenantName:        nsTenant[iso.Namespace],
			TenantProvider:    nsProvider[iso.Namespace],
			HasNetworkPolicy:  iso.HasNetworkPolicy,
			HasResourceQuota:  iso.HasResourceQuota,
			HasLimitRange:     iso.HasLimitRange,
			HasPodSecurityStd: iso.PodSecurityStd != "" && iso.PodSecurityStd != "privileged",
		}

		// Determine if isolated
		finding.IsIsolated = finding.HasNetworkPolicy && iso.DefaultDenyIngress

		// Get HNC hierarchy info
		for _, h := range hncHierarchies {
			if h.Namespace == iso.Namespace {
				finding.ParentNamespace = h.Parent
				finding.ChildNamespaces = h.Children
				finding.HierarchyDepth = h.DepthFromRoot
				break
			}
		}

		// Calculate risk
		riskScore := 0
		if !finding.HasNetworkPolicy {
			riskScore += 3
			finding.SecurityIssues = append(finding.SecurityIssues, "No network policy")
		} else if !iso.DefaultDenyIngress {
			riskScore += 2
			finding.SecurityIssues = append(finding.SecurityIssues, "No default deny")
		}

		if !finding.HasResourceQuota {
			riskScore += 1
			finding.SecurityIssues = append(finding.SecurityIssues, "No resource quota")
		}

		if !finding.HasPodSecurityStd {
			riskScore += 2
			finding.SecurityIssues = append(finding.SecurityIssues, "No pod security")
		}

		if finding.TenantProvider == "" {
			riskScore += 1
			finding.SecurityIssues = append(finding.SecurityIssues, "No tenant assignment")
		}

		if riskScore >= 5 {
			finding.RiskLevel = "HIGH"
		} else if riskScore >= 3 {
			finding.RiskLevel = "MEDIUM"
		} else {
			finding.RiskLevel = "LOW"
		}

		findings = append(findings, finding)
	}

	// Sort by risk level then namespace
	sort.Slice(findings, func(i, j int) bool {
		riskOrder := map[string]int{"HIGH": 0, "MEDIUM": 1, "LOW": 2}
		if riskOrder[findings[i].RiskLevel] != riskOrder[findings[j].RiskLevel] {
			return riskOrder[findings[i].RiskLevel] < riskOrder[findings[j].RiskLevel]
		}
		return findings[i].Namespace < findings[j].Namespace
	})

	return findings
}

// ============================================================================
// Loot Generation
// ============================================================================

func generateMultitenancyLoot(loot *shared.LootBuilder,
	findings []MultitenancyAdmissionFinding,
	hnc HNCInfo, hncHierarchies []HNCHierarchyInfo,
	capsule CapsuleInfo, capsuleTenants []CapsuleTenantInfo,
	vclusters []VClusterInfo,
	loft LoftInfo, loftSpaces []LoftSpaceInfo,
	kiosk KioskInfo, kioskAccounts []KioskAccountInfo,
	nsIsolation []NamespaceIsolationInfo,
	opaGatekeeper OPAGatekeeperTenantInfo) {

	// Summary
	loot.Section("Summary").Add("# Multi-Tenancy Summary")
	loot.Section("Summary").Add("#")

	providerCount := 0
	if hnc.Name != "" {
		providerCount++
		loot.Section("Summary").Add(fmt.Sprintf("# HNC: %s (%d hierarchies)", hnc.Status, hnc.Hierarchies))
	}
	if capsule.Name != "" {
		providerCount++
		loot.Section("Summary").Add(fmt.Sprintf("# Capsule: %s (%d tenants)", capsule.Status, capsule.Tenants))
	}
	if len(vclusters) > 0 {
		providerCount++
		loot.Section("Summary").Add(fmt.Sprintf("# vClusters: %d instances", len(vclusters)))
	}
	if loft.Name != "" {
		providerCount++
		loot.Section("Summary").Add(fmt.Sprintf("# Loft: %s (%d spaces, %d vClusters, %d teams)", loft.Status, loft.Spaces, loft.VirtualClusters, loft.Teams))
	}
	if kiosk.Name != "" {
		providerCount++
		loot.Section("Summary").Add(fmt.Sprintf("# Kiosk: %s (%d accounts, %d spaces)", kiosk.Status, kiosk.Accounts, kiosk.Spaces))
	}
	if opaGatekeeper.Name != "" {
		providerCount++
		status := opaGatekeeper.Status
		if opaGatekeeper.ImageVerified {
			status += " (verified)"
		}
		loot.Section("Summary").Add(fmt.Sprintf("# OPA Gatekeeper: %s (%d templates, %d constraints, %d tenant policies)", status, opaGatekeeper.ConstraintTemplates, opaGatekeeper.Constraints, opaGatekeeper.TenantIsolationPolicies))
	}

	if providerCount == 0 {
		loot.Section("Summary").Add("#")
		loot.Section("Summary").Add("# WARNING: No multi-tenancy solution detected!")
		loot.Section("Summary").Add("# Namespace isolation is limited to basic Kubernetes primitives")
	}

	loot.Section("Summary").Add("#")

	// Isolation analysis
	loot.Section("Isolation").Add("# Namespace Isolation Analysis")
	loot.Section("Isolation").Add("#")

	isolated := 0
	noNetpol := 0
	noQuota := 0
	noPodSec := 0

	for _, iso := range nsIsolation {
		if iso.HasNetworkPolicy && iso.DefaultDenyIngress {
			isolated++
		}
		if !iso.HasNetworkPolicy {
			noNetpol++
		}
		if !iso.HasResourceQuota {
			noQuota++
		}
		if iso.PodSecurityStd == "" || iso.PodSecurityStd == "privileged" {
			noPodSec++
		}
	}

	loot.Section("Isolation").Add(fmt.Sprintf("# Namespaces with proper isolation: %d/%d", isolated, len(nsIsolation)))
	loot.Section("Isolation").Add(fmt.Sprintf("# Namespaces without network policy: %d", noNetpol))
	loot.Section("Isolation").Add(fmt.Sprintf("# Namespaces without resource quota: %d", noQuota))
	loot.Section("Isolation").Add(fmt.Sprintf("# Namespaces without pod security: %d", noPodSec))
	loot.Section("Isolation").Add("#")

	// Bypass vectors
	loot.Section("BypassVectors").Add("# Tenant Isolation Bypass Vectors")
	loot.Section("BypassVectors").Add("#")

	for _, iso := range nsIsolation {
		if iso.BypassRisk != "" {
			loot.Section("BypassVectors").Add(fmt.Sprintf("# %s: %s", iso.Namespace, iso.BypassRisk))
		}
	}

	for _, t := range capsuleTenants {
		if t.BypassRisk != "" {
			loot.Section("BypassVectors").Add(fmt.Sprintf("# Capsule tenant %s: %s", t.Name, t.BypassRisk))
		}
	}

	loot.Section("BypassVectors").Add("#")

	// Recommendations
	loot.Section("Recommendations").Add("# Recommendations")
	loot.Section("Recommendations").Add("#")

	if providerCount == 0 {
		loot.Section("Recommendations").Add("# 1. Deploy a multi-tenancy solution:")
		loot.Section("Recommendations").Add("#    Capsule: kubectl apply -f https://raw.githubusercontent.com/projectcapsule/capsule/main/config/install.yaml")
		loot.Section("Recommendations").Add("#    HNC: kubectl apply -f https://github.com/kubernetes-sigs/hierarchical-namespaces/releases/latest/download/default.yaml")
	}

	if noNetpol > 0 {
		loot.Section("Recommendations").Add(fmt.Sprintf("# 2. Add network policies to %d namespaces", noNetpol))
	}

	if noQuota > 0 {
		loot.Section("Recommendations").Add(fmt.Sprintf("# 3. Add resource quotas to %d namespaces", noQuota))
	}

	if noPodSec > 0 {
		loot.Section("Recommendations").Add(fmt.Sprintf("# 4. Enable Pod Security Standards for %d namespaces", noPodSec))
	}

	// Commands
	loot.Section("Commands").Add("# Useful Commands")
	loot.Section("Commands").Add("#")
	loot.Section("Commands").Add("# List Capsule tenants:")
	loot.Section("Commands").Add("kubectl get tenants")
	loot.Section("Commands").Add("#")
	loot.Section("Commands").Add("# List HNC hierarchies:")
	loot.Section("Commands").Add("kubectl hns tree --all-namespaces")
	loot.Section("Commands").Add("#")
	loot.Section("Commands").Add("# List vClusters:")
	loot.Section("Commands").Add("vcluster list")
	loot.Section("Commands").Add("#")
	loot.Section("Commands").Add("# Check namespace isolation:")
	loot.Section("Commands").Add("kubectl get networkpolicies -A")
	loot.Section("Commands").Add("kubectl get resourcequotas -A")
}

// ============================================================================
// Cross-Tenant Resource Detection
// ============================================================================

func analyzeCrossTenantResources(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface, capsuleTenants []CapsuleTenantInfo, hncHierarchies []HNCHierarchyInfo) []CrossTenantResourceInfo {
	var resources []CrossTenantResourceInfo

	// Build tenant namespace mapping
	tenantNamespaces := make(map[string]string) // namespace -> tenant name
	for _, tenant := range capsuleTenants {
		for _, ns := range tenant.Namespaces {
			tenantNamespaces[ns] = tenant.Name
		}
	}
	for _, hier := range hncHierarchies {
		if hier.Parent == "" {
			// Root namespace - use as tenant
			tenantNamespaces[hier.Namespace] = hier.Namespace
		}
	}

	// 1. Detect ClusterRoleBindings that grant wide permissions
	crbs, err := clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, crb := range crbs.Items {
			// Skip system bindings
			if strings.HasPrefix(crb.Name, "system:") || strings.HasPrefix(crb.Name, "kubeadm:") {
				continue
			}

			// Check if binding references subjects from multiple namespaces
			subjectNamespaces := make(map[string]bool)
			for _, subject := range crb.Subjects {
				if subject.Namespace != "" {
					subjectNamespaces[subject.Namespace] = true
				}
			}

			// Check if subjects span multiple tenants
			tenantsAffected := make(map[string]bool)
			for ns := range subjectNamespaces {
				if tenant, ok := tenantNamespaces[ns]; ok {
					tenantsAffected[tenant] = true
				}
			}

			if len(tenantsAffected) > 1 {
				tenantList := make([]string, 0, len(tenantsAffected))
				for t := range tenantsAffected {
					tenantList = append(tenantList, t)
				}

				resources = append(resources, CrossTenantResourceInfo{
					Type:            "ClusterRoleBinding",
					Name:            crb.Name,
					Scope:           "Cluster",
					AffectedTenants: tenantList,
					RiskLevel:       "HIGH",
					Description:     fmt.Sprintf("Grants %s role to subjects in %d tenants", crb.RoleRef.Name, len(tenantsAffected)),
					BypassRisk:      "May allow cross-tenant privilege escalation",
				})
			}

			// Check for bindings that grant cluster-admin or high privilege roles
			highPrivRoles := []string{"cluster-admin", "admin", "edit"}
			for _, role := range highPrivRoles {
				if crb.RoleRef.Name == role {
					resources = append(resources, CrossTenantResourceInfo{
						Type:            "ClusterRoleBinding",
						Name:            crb.Name,
						Scope:           "Cluster",
						AffectedTenants: []string{"all"},
						RiskLevel:       "CRITICAL",
						Description:     fmt.Sprintf("Grants '%s' cluster-wide", role),
						BypassRisk:      "Full cluster access bypasses tenant isolation",
					})
					break
				}
			}
		}
	}

	// 2. Detect PersistentVolumes that might be shared
	pvs, err := clientset.CoreV1().PersistentVolumes().List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, pv := range pvs.Items {
			// Check access modes - ReadWriteMany can be shared
			for _, accessMode := range pv.Spec.AccessModes {
				if accessMode == "ReadWriteMany" || accessMode == "ReadOnlyMany" {
					claimNs := ""
					if pv.Spec.ClaimRef != nil {
						claimNs = pv.Spec.ClaimRef.Namespace
					}

					resources = append(resources, CrossTenantResourceInfo{
						Type:            "PersistentVolume",
						Name:            pv.Name,
						Scope:           "Cluster",
						AffectedTenants: []string{claimNs},
						RiskLevel:       "MEDIUM",
						Description:     fmt.Sprintf("PV with %s mode can be shared", accessMode),
						BypassRisk:      "Data may be accessible across namespaces",
					})
					break
				}
			}

			// Check for hostPath volumes - security risk
			if pv.Spec.HostPath != nil {
				resources = append(resources, CrossTenantResourceInfo{
					Type:            "PersistentVolume",
					Name:            pv.Name,
					Scope:           "Cluster",
					AffectedTenants: []string{"all"},
					RiskLevel:       "CRITICAL",
					Description:     fmt.Sprintf("HostPath PV: %s", pv.Spec.HostPath.Path),
					BypassRisk:      "Host filesystem access bypasses all isolation",
				})
			}
		}
	}

	// 3. Detect cluster-scoped custom resources that may affect tenants
	// Check for GlobalNetworkPolicies (Calico)
	globalNetpolGVR := schema.GroupVersionResource{
		Group:    "crd.projectcalico.org",
		Version:  "v1",
		Resource: "globalnetworkpolicies",
	}

	gnpList, err := dynClient.Resource(globalNetpolGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil && len(gnpList.Items) > 0 {
		for _, gnp := range gnpList.Items {
			resources = append(resources, CrossTenantResourceInfo{
				Type:            "GlobalNetworkPolicy",
				Name:            gnp.GetName(),
				Scope:           "Cluster",
				AffectedTenants: []string{"all"},
				RiskLevel:       "MEDIUM",
				Description:     "Cluster-wide network policy affects all tenants",
				BypassRisk:      "May override tenant network policies",
			})
		}
	}

	// 4. Check for services with externalName that could leak
	for _, ns := range globals.K8sNamespaces {
		services, err := clientset.CoreV1().Services(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, svc := range services.Items {
			if svc.Spec.Type == "ExternalName" && svc.Spec.ExternalName != "" {
				// Check if pointing to another namespace's service
				if strings.Contains(svc.Spec.ExternalName, ".svc.cluster.local") {
					resources = append(resources, CrossTenantResourceInfo{
						Type:            "Service",
						Name:            fmt.Sprintf("%s/%s", ns, svc.Name),
						Scope:           fmt.Sprintf("-> %s", svc.Spec.ExternalName),
						AffectedTenants: []string{ns},
						RiskLevel:       "MEDIUM",
						Description:     "ExternalName service points to another namespace",
						BypassRisk:      "May bypass network policies",
					})
				}
			}
		}
	}

	// 5. Check for ClusterRoles with excessive permissions
	clusterRoles, err := clientset.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, cr := range clusterRoles.Items {
			// Skip system roles
			if strings.HasPrefix(cr.Name, "system:") || strings.HasPrefix(cr.Name, "kubeadm:") {
				continue
			}

			// Check for wildcard permissions
			for _, rule := range cr.Rules {
				hasWildcard := false
				for _, verb := range rule.Verbs {
					if verb == "*" {
						hasWildcard = true
						break
					}
				}
				for _, resource := range rule.Resources {
					if resource == "*" {
						hasWildcard = true
						break
					}
				}
				for _, group := range rule.APIGroups {
					if group == "*" {
						hasWildcard = true
						break
					}
				}

				if hasWildcard {
					resources = append(resources, CrossTenantResourceInfo{
						Type:            "ClusterRole",
						Name:            cr.Name,
						Scope:           "Cluster",
						AffectedTenants: []string{"all"},
						RiskLevel:       "HIGH",
						Description:     "ClusterRole with wildcard permissions",
						BypassRisk:      "Wide permissions may bypass tenant boundaries",
					})
					break
				}
			}
		}
	}

	return resources
}
