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

Kubernetes Multi-Tenancy:
  - Hierarchical Namespace Controller (HNC)
  - Capsule (Tenant CRDs)
  - vCluster detection
  - Loft (VirtualCluster, Space CRDs)
  - Kiosk (Account, Space CRDs)
  - Rancher project/cluster management

Isolation Analysis:
  - Namespace isolation analysis
  - Cross-tenant resource detection
  - Resource quota enforcement
  - Network policy coverage

Cloud-Specific Multi-Tenancy (in-cluster detection):
  Detects cloud resource controllers for multi-tenant management.
  No --cloud-provider flag required - reads cluster resources directly.

  AWS:
    - AWS Controllers for Kubernetes (ACK)
    - EKS namespace-based team isolation

  GCP:
    - GCP Config Connector resource quotas
    - GKE Config Sync for tenant configuration

  Azure:
    - Azure Service Operator resource policies
    - AKS namespace isolation

  Multi-Cloud:
    - Crossplane multi-cloud resource management
    - Karmada multi-cluster management
    - Admiralty multi-cluster scheduling

Examples:
  cloudfox kubernetes multitenancy-admission
  cloudfox kubernetes multitenancy-admission --detailed`,
	Run: ListMultitenancyAdmission,
}

// init() removed - detailed flag is now a global persistent flag in cli/kubernetes.go

type MultitenancyAdmissionOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t MultitenancyAdmissionOutput) TableFiles() []internal.TableFile { return t.Table }
func (t MultitenancyAdmissionOutput) LootFiles() []internal.LootFile   { return t.Loot }

type MultitenancyEnumeratedPolicy struct {
	Namespace string
	Tool      string
	Name      string
	Scope     string
	Type      string
	Details   string
}

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
}

// HNCHierarchyInfo represents an HNC hierarchy
type HNCHierarchyInfo struct {
	Namespace       string
	Parent          string
	Children        []string
	DepthFromRoot   int
	PropagatedRoles int
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
}

// LoftSpaceInfo represents a Loft Space
type LoftSpaceInfo struct {
	Name            string
	Namespace       string
	Team            string
	User            string
	SleepAfter      string
	DeleteAfter     string
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
}

// KioskAccountInfo represents a Kiosk Account
type KioskAccountInfo struct {
	Name            string
	Subjects        []string
	SpaceLimit      int
	SpacesUsed      int
	DefaultCluster  string
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
}

// ConstraintTemplateInfo represents an individual OPA Gatekeeper ConstraintTemplate
type ConstraintTemplateInfo struct {
	Name        string
	Kind        string // The constraint kind this template creates
	Description string
	Rego        string // First line or summary of the Rego policy
	Targets     string // target (e.g., "admission.k8s.gatekeeper.sh")
}

// ConstraintInfo represents an individual OPA Gatekeeper Constraint
type ConstraintInfo struct {
	Name               string
	Kind               string // The constraint kind (from ConstraintTemplate)
	EnforcementAction  string // deny, dryrun, warn
	Match              string // Summary of match criteria
	Parameters         string // Summary of parameters
	Violations         int
	TotalViolations    int
	IsTenantIsolation  bool
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
}

// CrossTenantResourceInfo represents resources that may cross tenant boundaries
type CrossTenantResourceInfo struct {
	Type           string // ClusterRole, ClusterRoleBinding, PV, Service
	Name           string
	Scope          string // Cluster, Namespaces
	AffectedTenants []string
	Description    string
}

func ListMultitenancyAdmission(cmd *cobra.Command, args []string) {
	ctx, cancel := shared.ContextWithCancel()
	defer cancel()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDir, _ := parentCmd.PersistentFlags().GetString("outdir")
	detailed := globals.K8sDetailed

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
	opaGatekeeper, opaTemplates, opaConstraints := analyzeOPAGatekeeperTenant(ctx, clientset, dynClient)

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
		"Issues",
	}

	// Uniform header for all detailed policy tables
	uniformPolicyHeader := []string{
		"Namespace",
		"Name",
		"Scope",
		"Target",
		"Type",
		"Configuration",
		"Details",
		"Issues",
	}

	// All detailed tables use uniform schema
	hncHeader := uniformPolicyHeader
	hncHierarchyHeader := uniformPolicyHeader
	capsuleHeader := uniformPolicyHeader
	capsuleTenantHeader := uniformPolicyHeader
	vclusterHeader := uniformPolicyHeader
	isolationHeader := uniformPolicyHeader
	crossTenantHeader := uniformPolicyHeader
	opaGatekeeperHeader := uniformPolicyHeader
	opaTemplatesHeader := uniformPolicyHeader
	opaConstraintsHeader := uniformPolicyHeader
	loftSpaceHeader := uniformPolicyHeader
	kioskAccountHeader := uniformPolicyHeader

	policiesHeader := []string{
		"Namespace",
		"Tool",
		"Name",
		"Scope",
		"Type",
		"Details",
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
	var opaTemplatesRows [][]string
	var opaConstraintsRows [][]string
	var loftSpaceRows [][]string
	var kioskAccountRows [][]string
	var policiesRows [][]string

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
			issues = strings.Join(finding.SecurityIssues, "; ")
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
			issues,
		})
	}

	// Build HNC rows
	if hnc.Name != "" {
		// Detect issues
		var hncIssues []string
		if !hnc.ImageVerified {
			hncIssues = append(hncIssues, "Image not verified")
		}
		if hnc.Status == "degraded" {
			hncIssues = append(hncIssues, "Controller degraded")
		}
		if hnc.PodsRunning < hnc.TotalPods {
			hncIssues = append(hncIssues, "Not all pods running")
		}
		if hnc.Hierarchies == 0 {
			hncIssues = append(hncIssues, "No hierarchies configured")
		}
		hncIssuesStr := "<NONE>"
		if len(hncIssues) > 0 {
			hncIssuesStr = strings.Join(hncIssues, "; ")
		}

		// Uniform schema: Namespace, Name, Scope, Target, Type, Configuration, Details, Issues
		hncScope := "Cluster"
		hncTarget := "Namespaces"
		hncType := "HNC Controller"
		hncConfig := fmt.Sprintf("Hierarchies: %d", hnc.Hierarchies)
		hncDetails := fmt.Sprintf("Status: %s, Pods: %d/%d", hnc.Status, hnc.PodsRunning, hnc.TotalPods)

		hncRows = append(hncRows, []string{
			hnc.Namespace,
			hnc.Name,
			hncScope,
			hncTarget,
			hncType,
			hncConfig,
			hncDetails,
			hncIssuesStr,
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

		// Detect issues
		var hierIssues []string
		if h.DepthFromRoot > 3 {
			hierIssues = append(hierIssues, "Deep hierarchy (>3 levels)")
		}
		if h.PropagatedRoles == 0 && h.Parent != "" {
			hierIssues = append(hierIssues, "No propagated roles")
		}
		if h.Parent == "" && len(h.Children) == 0 {
			hierIssues = append(hierIssues, "Orphan namespace")
		}
		hierIssuesStr := "<NONE>"
		if len(hierIssues) > 0 {
			hierIssuesStr = strings.Join(hierIssues, "; ")
		}

		// Uniform schema: Namespace, Name, Scope, Target, Type, Configuration, Details, Issues
		hierName := h.Namespace
		hierScope := "Namespace"
		hierTarget := children
		if hierTarget == "-" {
			hierTarget = "No children"
		}
		hierType := "HNC Hierarchy"
		hierConfig := fmt.Sprintf("Parent: %s, Depth: %d", parent, h.DepthFromRoot)
		hierDetails := fmt.Sprintf("Propagated Roles: %d", h.PropagatedRoles)

		hncHierarchyRows = append(hncHierarchyRows, []string{
			h.Namespace,
			hierName,
			hierScope,
			hierTarget,
			hierType,
			hierConfig,
			hierDetails,
			hierIssuesStr,
		})
	}

	// Build Capsule rows
	if capsule.Name != "" {
		// Detect issues
		var capsuleIssues []string
		if !capsule.ImageVerified {
			capsuleIssues = append(capsuleIssues, "Image not verified")
		}
		if capsule.Status == "degraded" {
			capsuleIssues = append(capsuleIssues, "Controller degraded")
		}
		if capsule.PodsRunning < capsule.TotalPods {
			capsuleIssues = append(capsuleIssues, "Not all pods running")
		}
		if capsule.Tenants == 0 {
			capsuleIssues = append(capsuleIssues, "No tenants configured")
		}
		capsuleIssuesStr := "<NONE>"
		if len(capsuleIssues) > 0 {
			capsuleIssuesStr = strings.Join(capsuleIssues, "; ")
		}

		// Uniform schema: Namespace, Name, Scope, Target, Type, Configuration, Details, Issues
		capsuleScope := "Cluster"
		capsuleTarget := "Tenants"
		capsuleType := "Capsule Controller"
		capsuleConfig := fmt.Sprintf("Tenants: %d", capsule.Tenants)
		capsuleDetails := fmt.Sprintf("Status: %s, Pods: %d/%d", capsule.Status, capsule.PodsRunning, capsule.TotalPods)

		capsuleRows = append(capsuleRows, []string{
			capsule.Namespace,
			capsule.Name,
			capsuleScope,
			capsuleTarget,
			capsuleType,
			capsuleConfig,
			capsuleDetails,
			capsuleIssuesStr,
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

		// Use first namespace or "-" for namespace column
		namespace := "-"
		if len(t.Namespaces) > 0 {
			namespace = t.Namespaces[0]
		}

		// Detect issues
		var tenantIssues []string
		if len(t.Owners) == 0 {
			tenantIssues = append(tenantIssues, "No owners defined")
		}
		if !t.LimitRanges {
			tenantIssues = append(tenantIssues, "No limit ranges")
		}
		if !t.ResourceQuotas {
			tenantIssues = append(tenantIssues, "No resource quotas")
		}
		if !t.NetworkPolicies {
			tenantIssues = append(tenantIssues, "No network policies")
		}
		if len(t.Namespaces) == 0 {
			tenantIssues = append(tenantIssues, "No namespaces assigned")
		}
		if t.NamespaceQuota == 0 {
			tenantIssues = append(tenantIssues, "Unlimited namespace quota")
		}
		tenantIssuesStr := "<NONE>"
		if len(tenantIssues) > 0 {
			tenantIssuesStr = strings.Join(tenantIssues, "; ")
		}

		// Uniform schema: Namespace, Name, Scope, Target, Type, Configuration, Details, Issues
		tenantScope := "Tenant"
		tenantTarget := namespaces
		tenantType := "Capsule Tenant"
		tenantConfig := fmt.Sprintf("Quota: %d, LimitRanges: %s, ResourceQuotas: %s", t.NamespaceQuota, limitRanges, resourceQuotas)
		tenantDetails := fmt.Sprintf("Owners: %s, NetworkPolicies: %s", owners, networkPolicies)

		capsuleTenantRows = append(capsuleTenantRows, []string{
			namespace,
			t.Name,
			tenantScope,
			tenantTarget,
			tenantType,
			tenantConfig,
			tenantDetails,
			tenantIssuesStr,
		})
	}

	// Build vCluster rows
	for _, v := range vclusters {
		syncer := "No"
		if v.SyncerRunning {
			syncer = "Yes"
		}

		// Detect issues
		var vclusterIssues []string
		if !v.ImageVerified {
			vclusterIssues = append(vclusterIssues, "Image not verified")
		}
		if v.Status == "degraded" || v.Status == "unverified" {
			vclusterIssues = append(vclusterIssues, "vCluster not healthy")
		}
		if !v.SyncerRunning {
			vclusterIssues = append(vclusterIssues, "Syncer not running")
		}
		if v.HostClusterRole == "cluster-admin" {
			vclusterIssues = append(vclusterIssues, "Excessive host role")
		}
		vclusterIssuesStr := "<NONE>"
		if len(vclusterIssues) > 0 {
			vclusterIssuesStr = strings.Join(vclusterIssues, "; ")
		}

		// Uniform schema: Namespace, Name, Scope, Target, Type, Configuration, Details, Issues
		vclusterScope := "Namespace"
		vclusterTarget := "Virtual cluster"
		vclusterType := "vCluster"
		vclusterConfig := fmt.Sprintf("Syncer: %s, Host Role: %s", syncer, v.HostClusterRole)
		vclusterDetails := fmt.Sprintf("K8s: %s, Status: %s", v.K8sVersion, v.Status)

		vclusterRows = append(vclusterRows, []string{
			v.Namespace,
			v.Name,
			vclusterScope,
			vclusterTarget,
			vclusterType,
			vclusterConfig,
			vclusterDetails,
			vclusterIssuesStr,
		})
	}

	// Build Loft Space rows
	for _, space := range loftSpaces {
		sleepAfter := "-"
		if space.SleepAfter != "" {
			sleepAfter = space.SleepAfter
		}
		deleteAfter := "-"
		if space.DeleteAfter != "" {
			deleteAfter = space.DeleteAfter
		}
		user := space.User
		if user == "" {
			user = "-"
		}
		team := space.Team
		if team == "" {
			team = "-"
		}

		// Detect issues
		var spaceIssues []string
		if space.User == "" && space.Team == "" {
			spaceIssues = append(spaceIssues, "No owner assigned")
		}
		if space.SleepAfter == "" && space.DeleteAfter == "" {
			spaceIssues = append(spaceIssues, "No auto-cleanup configured")
		}
		if space.Namespace == "" {
			spaceIssues = append(spaceIssues, "No namespace assigned")
		}
		spaceIssuesStr := "<NONE>"
		if len(spaceIssues) > 0 {
			spaceIssuesStr = strings.Join(spaceIssues, "; ")
		}

		// Uniform schema: Namespace, Name, Scope, Target, Type, Configuration, Details, Issues
		spaceScope := "Namespace"
		spaceTarget := "Team/User workspace"
		spaceType := "Loft Space"
		spaceConfig := fmt.Sprintf("Sleep: %s, Delete: %s", sleepAfter, deleteAfter)
		spaceDetails := fmt.Sprintf("User: %s, Team: %s", user, team)

		loftSpaceRows = append(loftSpaceRows, []string{
			space.Namespace,
			space.Name,
			spaceScope,
			spaceTarget,
			spaceType,
			spaceConfig,
			spaceDetails,
			spaceIssuesStr,
		})
	}

	// Build Kiosk Account rows
	for _, acct := range kioskAccounts {
		subjects := "-"
		if len(acct.Subjects) > 0 {
			if len(acct.Subjects) > 3 {
				subjects = strings.Join(acct.Subjects[:3], ", ") + "..."
			} else {
				subjects = strings.Join(acct.Subjects, ", ")
			}
		}
		defaultCluster := acct.DefaultCluster
		if defaultCluster == "" {
			defaultCluster = "-"
		}

		// Detect issues
		var acctIssues []string
		if len(acct.Subjects) == 0 {
			acctIssues = append(acctIssues, "No subjects defined")
		}
		if acct.SpaceLimit == 0 {
			acctIssues = append(acctIssues, "Unlimited space quota")
		}
		if acct.SpacesUsed >= acct.SpaceLimit && acct.SpaceLimit > 0 {
			acctIssues = append(acctIssues, "At space limit")
		}
		acctIssuesStr := "<NONE>"
		if len(acctIssues) > 0 {
			acctIssuesStr = strings.Join(acctIssues, "; ")
		}

		// Uniform schema: Namespace, Name, Scope, Target, Type, Configuration, Details, Issues
		acctNs := "<CLUSTER>"
		acctScope := "Account"
		acctTarget := subjects
		acctType := "Kiosk Account"
		acctConfig := fmt.Sprintf("Spaces: %d/%d, Cluster: %s", acct.SpacesUsed, acct.SpaceLimit, defaultCluster)
		acctDetails := fmt.Sprintf("Subjects: %s", subjects)

		kioskAccountRows = append(kioskAccountRows, []string{
			acctNs,
			acct.Name,
			acctScope,
			acctTarget,
			acctType,
			acctConfig,
			acctDetails,
			acctIssuesStr,
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

		// Detect issues
		var isoIssues []string
		if !iso.HasNetworkPolicy {
			isoIssues = append(isoIssues, "No network policy")
		} else if !iso.DefaultDenyIngress {
			isoIssues = append(isoIssues, "No default deny ingress")
		}
		if !iso.DefaultDenyEgress && iso.HasNetworkPolicy {
			isoIssues = append(isoIssues, "No default deny egress")
		}
		if !iso.HasResourceQuota {
			isoIssues = append(isoIssues, "No resource quota")
		}
		if !iso.HasLimitRange {
			isoIssues = append(isoIssues, "No limit range")
		}
		if iso.PodSecurityStd == "" || iso.PodSecurityStd == "privileged" {
			isoIssues = append(isoIssues, "Weak/no pod security")
		}
		if iso.TenantLabel == "" {
			isoIssues = append(isoIssues, "No tenant label")
		}
		isoIssuesStr := "<NONE>"
		if len(isoIssues) > 0 {
			isoIssuesStr = strings.Join(isoIssues, "; ")
		}

		// Uniform schema: Namespace, Name, Scope, Target, Type, Configuration, Details, Issues
		isoName := iso.Namespace
		isoScope := "Namespace"
		isoTarget := tenantLabel
		isoType := "Namespace Isolation"
		isoConfig := fmt.Sprintf("NetPol: %s, DenyIngress: %s, DenyEgress: %s", netpol, denyIngress, denyEgress)
		isoDetails := fmt.Sprintf("Quota: %s, LimitRange: %s, PodSec: %s", quota, limitRange, podSecStd)

		isolationRows = append(isolationRows, []string{
			iso.Namespace,
			isoName,
			isoScope,
			isoTarget,
			isoType,
			isoConfig,
			isoDetails,
			isoIssuesStr,
		})
	}

	// Build cross-tenant resource rows
	for _, ctr := range crossTenantResources {
		affectedTenants := "-"
		namespace := "-"
		if len(ctr.AffectedTenants) > 0 {
			namespace = ctr.AffectedTenants[0]
			if len(ctr.AffectedTenants) > 3 {
				affectedTenants = strings.Join(ctr.AffectedTenants[:3], ", ") + "..."
			} else {
				affectedTenants = strings.Join(ctr.AffectedTenants, ", ")
			}
		}

		// Detect issues (all cross-tenant resources are potential issues)
		var ctrIssues []string
		if ctr.Scope == "Cluster" {
			ctrIssues = append(ctrIssues, "Cluster-wide scope")
		}
		if len(ctr.AffectedTenants) > 1 {
			ctrIssues = append(ctrIssues, fmt.Sprintf("Affects %d tenants", len(ctr.AffectedTenants)))
		}
		if strings.Contains(strings.ToLower(ctr.Description), "cluster-admin") ||
			strings.Contains(strings.ToLower(ctr.Description), "wildcard") {
			ctrIssues = append(ctrIssues, "Excessive permissions")
		}
		if ctr.Type == "PersistentVolume" && strings.Contains(ctr.Description, "HostPath") {
			ctrIssues = append(ctrIssues, "HostPath exposure")
		}
		ctrIssuesStr := "<NONE>"
		if len(ctrIssues) > 0 {
			ctrIssuesStr = strings.Join(ctrIssues, "; ")
		}

		// Uniform schema: Namespace, Name, Scope, Target, Type, Configuration, Details, Issues
		ctrTarget := affectedTenants
		ctrConfig := fmt.Sprintf("Scope: %s", ctr.Scope)
		ctrDetails := ctr.Description

		crossTenantRows = append(crossTenantRows, []string{
			namespace,
			ctr.Name,
			ctr.Scope,
			ctrTarget,
			ctr.Type,
			ctrConfig,
			ctrDetails,
			ctrIssuesStr,
		})
	}

	// Build OPA/Gatekeeper rows
	if opaGatekeeper.Name != "" {
		imageVerified := "No"
		if opaGatekeeper.ImageVerified {
			imageVerified = "Yes"
		}

		// Detect issues
		var opaIssues []string
		if !opaGatekeeper.ImageVerified {
			opaIssues = append(opaIssues, "Image not verified")
		}
		if opaGatekeeper.Status == "degraded" {
			opaIssues = append(opaIssues, "Controller degraded")
		}
		if opaGatekeeper.PodsRunning < opaGatekeeper.TotalPods {
			opaIssues = append(opaIssues, "Not all pods running")
		}
		if opaGatekeeper.Constraints == 0 {
			opaIssues = append(opaIssues, "No constraints defined")
		}
		if opaGatekeeper.TenantIsolationPolicies == 0 {
			opaIssues = append(opaIssues, "No tenant isolation policies")
		}
		opaIssuesStr := "<NONE>"
		if len(opaIssues) > 0 {
			opaIssuesStr = strings.Join(opaIssues, "; ")
		}

		// Uniform schema: Namespace, Name, Scope, Target, Type, Configuration, Details, Issues
		opaScope := "Cluster"
		opaTarget := "All resources"
		opaType := "OPA Gatekeeper"
		opaConfig := fmt.Sprintf("Templates: %d, Constraints: %d, Tenant Policies: %d", opaGatekeeper.ConstraintTemplates, opaGatekeeper.Constraints, opaGatekeeper.TenantIsolationPolicies)
		opaDetails := fmt.Sprintf("Status: %s, Pods: %d/%d, Verified: %s", opaGatekeeper.Status, opaGatekeeper.PodsRunning, opaGatekeeper.TotalPods, imageVerified)

		opaGatekeeperRows = append(opaGatekeeperRows, []string{
			opaGatekeeper.Namespace,
			opaGatekeeper.Name,
			opaScope,
			opaTarget,
			opaType,
			opaConfig,
			opaDetails,
			opaIssuesStr,
		})
	}

	// Build detailed OPA ConstraintTemplate rows
	for _, tmpl := range opaTemplates {
		desc := tmpl.Description
		if desc == "" {
			desc = "-"
		}
		targets := tmpl.Targets
		if targets == "" {
			targets = "-"
		}
		rego := tmpl.Rego
		if rego == "" {
			rego = "-"
		}

		// Detect issues
		var tmplIssues []string
		if tmpl.Description == "" {
			tmplIssues = append(tmplIssues, "No description")
		}
		if tmpl.Kind == "" {
			tmplIssues = append(tmplIssues, "No kind defined")
		}
		if tmpl.Rego == "" {
			tmplIssues = append(tmplIssues, "Empty rego policy")
		}
		tmplIssuesStr := "<NONE>"
		if len(tmplIssues) > 0 {
			tmplIssuesStr = strings.Join(tmplIssues, "; ")
		}

		// Uniform schema: Namespace, Name, Scope, Target, Type, Configuration, Details, Issues
		tmplNs := "<CLUSTER>"
		tmplScope := "Cluster"
		tmplTarget := targets
		tmplType := "ConstraintTemplate"
		tmplConfig := fmt.Sprintf("Kind: %s", tmpl.Kind)
		tmplDetails := fmt.Sprintf("Desc: %s, Rego: %s", desc, rego)

		opaTemplatesRows = append(opaTemplatesRows, []string{
			tmplNs,
			tmpl.Name,
			tmplScope,
			tmplTarget,
			tmplType,
			tmplConfig,
			tmplDetails,
			tmplIssuesStr,
		})
	}

	// Build detailed OPA Constraint rows
	for _, c := range opaConstraints {
		isTenant := "No"
		if c.IsTenantIsolation {
			isTenant = "Yes"
		}
		violations := fmt.Sprintf("%d", c.Violations)
		if c.TotalViolations > c.Violations {
			violations = fmt.Sprintf("%d (total: %d)", c.Violations, c.TotalViolations)
		}

		// Detect issues
		var constIssues []string
		if c.EnforcementAction == "dryrun" || c.EnforcementAction == "warn" {
			constIssues = append(constIssues, "Not enforcing ("+c.EnforcementAction+")")
		}
		if c.Violations > 0 {
			constIssues = append(constIssues, fmt.Sprintf("%d violations", c.Violations))
		}
		if c.Match == "all" {
			constIssues = append(constIssues, "Broad match scope")
		}
		constIssuesStr := "<NONE>"
		if len(constIssues) > 0 {
			constIssuesStr = strings.Join(constIssues, "; ")
		}

		// Uniform schema: Namespace, Name, Scope, Target, Type, Configuration, Details, Issues
		constNs := "<CLUSTER>"
		constScope := "Cluster"
		constTarget := c.Match
		constType := "OPA Constraint"
		constConfig := fmt.Sprintf("Kind: %s, Enforcement: %s, Tenant: %s", c.Kind, c.EnforcementAction, isTenant)
		constDetails := fmt.Sprintf("Params: %s, Violations: %s", c.Parameters, violations)

		opaConstraintsRows = append(opaConstraintsRows, []string{
			constNs,
			c.Name,
			constScope,
			constTarget,
			constType,
			constConfig,
			constDetails,
			constIssuesStr,
		})
	}

	// Build unified policies table
	for _, h := range hncHierarchies {
		parent := h.Parent
		if parent == "" {
			parent = "-"
		}
		children := "-"
		if len(h.Children) > 0 {
			if len(h.Children) > 3 {
				children = strings.Join(h.Children[:3], ", ") + "..."
			} else {
				children = strings.Join(h.Children, ", ")
			}
		}
		details := fmt.Sprintf("Parent: %s, Children: %s, Depth: %d, Propagated Roles: %d", parent, children, h.DepthFromRoot, h.PropagatedRoles)
		policiesRows = append(policiesRows, []string{
			h.Namespace,
			"HNC",
			h.Namespace,
			"Hierarchy",
			"Namespace",
			details,
		})
	}

	for _, t := range capsuleTenants {
		namespace := "-"
		if len(t.Namespaces) > 0 {
			namespace = t.Namespaces[0]
		}
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
		details := fmt.Sprintf("Namespaces: %s, Quota: %d, Owners: %s, LimitRanges: %s, ResourceQuotas: %s, NetworkPolicies: %s",
			namespaces, t.NamespaceQuota, owners, limitRanges, resourceQuotas, networkPolicies)
		policiesRows = append(policiesRows, []string{
			namespace,
			"Capsule",
			t.Name,
			"Tenant",
			"Multi-namespace",
			details,
		})
	}

	for _, v := range vclusters {
		syncer := "No"
		if v.SyncerRunning {
			syncer = "Yes"
		}
		details := fmt.Sprintf("Status: %s, Syncer: %s, K8s Version: %s, Host Role: %s", v.Status, syncer, v.K8sVersion, v.HostClusterRole)
		policiesRows = append(policiesRows, []string{
			v.Namespace,
			"vCluster",
			v.Name,
			"Virtual Cluster",
			"Namespace",
			details,
		})
	}

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
		details := fmt.Sprintf("Tenant: %s, NetworkPolicy: %s, DefaultDenyIngress: %s, DefaultDenyEgress: %s, ResourceQuota: %s, LimitRange: %s, PodSecurityStd: %s",
			tenantLabel, netpol, denyIngress, denyEgress, quota, limitRange, podSecStd)
		policiesRows = append(policiesRows, []string{
			iso.Namespace,
			"Isolation",
			iso.Namespace,
			"Namespace Config",
			"Namespace",
			details,
		})
	}

	for _, ctr := range crossTenantResources {
		namespace := "-"
		affectedTenants := "-"
		if len(ctr.AffectedTenants) > 0 {
			namespace = ctr.AffectedTenants[0]
			if len(ctr.AffectedTenants) > 3 {
				affectedTenants = strings.Join(ctr.AffectedTenants[:3], ", ") + "..."
			} else {
				affectedTenants = strings.Join(ctr.AffectedTenants, ", ")
			}
		}
		details := fmt.Sprintf("Scope: %s, Affected Tenants: %s, Description: %s", ctr.Scope, affectedTenants, ctr.Description)
		policiesRows = append(policiesRows, []string{
			namespace,
			"Cross-Tenant",
			ctr.Name,
			ctr.Type,
			"Cluster",
			details,
		})
	}

	if opaGatekeeper.Name != "" {
		imageVerified := "No"
		if opaGatekeeper.ImageVerified {
			imageVerified = "Yes"
		}
		details := fmt.Sprintf("Status: %s, Pods: %d/%d, Verified: %s, Templates: %d, Constraints: %d, Tenant Policies: %d",
			opaGatekeeper.Status, opaGatekeeper.PodsRunning, opaGatekeeper.TotalPods, imageVerified,
			opaGatekeeper.ConstraintTemplates, opaGatekeeper.Constraints, opaGatekeeper.TenantIsolationPolicies)
		policiesRows = append(policiesRows, []string{
			opaGatekeeper.Namespace,
			"OPA Gatekeeper",
			opaGatekeeper.Name,
			"Policy Engine",
			"Cluster",
			details,
		})
	}

	// Generate loot
	generateMultitenancyLoot(loot, findings, hnc, hncHierarchies, capsule, capsuleTenants, vclusters, loft, loftSpaces, kiosk, kioskAccounts, nsIsolation, opaGatekeeper, opaTemplates, opaConstraints)

	// Build output tables
	var tables []internal.TableFile

	tables = append(tables, internal.TableFile{
		Name:   "Multitenancy-Admission-Summary",
		Header: summaryHeader,
		Body:   summaryRows,
	})

	// Always show unified policies table
	if len(policiesRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Multitenancy-Admission-Policy-Overview",
			Header: policiesHeader,
			Body:   policiesRows,
		})
	}

	// Only show detailed tables if --detailed flag is set
	if detailed {
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

		// Detailed OPA Gatekeeper tables showing individual policies
		if len(opaTemplatesRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Multitenancy-Admission-OPA-ConstraintTemplates",
				Header: opaTemplatesHeader,
				Body:   opaTemplatesRows,
			})
		}

		if len(opaConstraintsRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Multitenancy-Admission-OPA-Constraints",
				Header: opaConstraintsHeader,
				Body:   opaConstraintsRows,
			})
		}

		// Loft Spaces detail table
		if len(loftSpaceRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Multitenancy-Admission-Loft-Spaces",
				Header: loftSpaceHeader,
				Body:   loftSpaceRows,
			})
		}

		// Kiosk Accounts detail table
		if len(kioskAccountRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Multitenancy-Admission-Kiosk-Accounts",
				Header: kioskAccountHeader,
				Body:   kioskAccountRows,
			})
		}
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
				}

				if !info.ImageVerified {
					info.Status = "unverified"
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
				}

				if !info.ImageVerified {
					info.Status = "unverified"
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
				}

				if !info.ImageVerified {
					info.Status = "unverified"
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
				}

				if !info.ImageVerified {
					info.Status = "unverified"
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

	return a
}

// ============================================================================
// OPA/Gatekeeper Tenant Policy Analysis
// ============================================================================

func analyzeOPAGatekeeperTenant(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) (OPAGatekeeperTenantInfo, []ConstraintTemplateInfo, []ConstraintInfo) {
	info := OPAGatekeeperTenantInfo{}
	var templates []ConstraintTemplateInfo
	var constraints []ConstraintInfo

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
				}

				if !info.ImageVerified {
					info.Status = "unverified"
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
		return info, templates, constraints
	}

	// Get ConstraintTemplates with details
	constraintTemplateGVR := schema.GroupVersionResource{
		Group:    "templates.gatekeeper.sh",
		Version:  "v1",
		Resource: "constrainttemplates",
	}

	ctList, err := dynClient.Resource(constraintTemplateGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err != nil {
		// Try v1beta1
		constraintTemplateGVR.Version = "v1beta1"
		ctList, err = dynClient.Resource(constraintTemplateGVR).Namespace("").List(ctx, metav1.ListOptions{})
	}

	if err == nil {
		info.ConstraintTemplates = len(ctList.Items)
	}

	// Count Constraints and check for tenant isolation policies
	tenantPolicyKeywords := []string{"tenant", "namespace", "isolation", "label", "team", "project"}

	// Get all constraint kinds by listing constraint templates
	if ctList != nil {
		for _, ct := range ctList.Items {
			// Parse template details
			tmplInfo := parseConstraintTemplate(ct.Object)
			templates = append(templates, tmplInfo)

			kind := tmplInfo.Kind
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

					// Parse individual constraints
					for _, constraint := range constraintList.Items {
						constInfo := parseConstraint(constraint.Object, kind, tenantPolicyKeywords)
						constraints = append(constraints, constInfo)

						// Count tenant isolation policies
						if constInfo.IsTenantIsolation {
							info.TenantIsolationPolicies++
						}
					}
				}
			}
		}
	}

	return info, templates, constraints
}

// parseConstraintTemplate extracts detailed info from a ConstraintTemplate
func parseConstraintTemplate(obj map[string]interface{}) ConstraintTemplateInfo {
	tmpl := ConstraintTemplateInfo{}

	if metadata, ok := obj["metadata"].(map[string]interface{}); ok {
		tmpl.Name, _ = metadata["name"].(string)

		// Get description from annotations if available
		if annotations, ok := metadata["annotations"].(map[string]interface{}); ok {
			if desc, ok := annotations["description"].(string); ok {
				tmpl.Description = desc
			}
		}
	}

	if spec, ok := obj["spec"].(map[string]interface{}); ok {
		// Get the kind this template creates
		if crd, ok := spec["crd"].(map[string]interface{}); ok {
			if crdSpec, ok := crd["spec"].(map[string]interface{}); ok {
				if names, ok := crdSpec["names"].(map[string]interface{}); ok {
					tmpl.Kind, _ = names["kind"].(string)
				}
			}
		}

		// Get targets
		if targets, ok := spec["targets"].([]interface{}); ok {
			var targetNames []string
			for _, t := range targets {
				if tMap, ok := t.(map[string]interface{}); ok {
					if target, ok := tMap["target"].(string); ok {
						targetNames = append(targetNames, target)
					}

					// Get first line of rego
					if rego, ok := tMap["rego"].(string); ok && tmpl.Rego == "" {
						lines := strings.Split(rego, "\n")
						for _, line := range lines {
							line = strings.TrimSpace(line)
							if line != "" && !strings.HasPrefix(line, "#") {
								if len(line) > 60 {
									tmpl.Rego = line[:60] + "..."
								} else {
									tmpl.Rego = line
								}
								break
							}
						}
					}
				}
			}
			tmpl.Targets = strings.Join(targetNames, ", ")
		}
	}

	// Generate description from name if not set
	if tmpl.Description == "" && tmpl.Kind != "" {
		tmpl.Description = fmt.Sprintf("Creates %s constraints", tmpl.Kind)
	}

	return tmpl
}

// parseConstraint extracts detailed info from a Constraint
func parseConstraint(obj map[string]interface{}, kind string, tenantKeywords []string) ConstraintInfo {
	c := ConstraintInfo{
		Kind: kind,
	}

	if metadata, ok := obj["metadata"].(map[string]interface{}); ok {
		c.Name, _ = metadata["name"].(string)
	}

	if spec, ok := obj["spec"].(map[string]interface{}); ok {
		// Get enforcement action
		if action, ok := spec["enforcementAction"].(string); ok {
			c.EnforcementAction = action
		} else {
			c.EnforcementAction = "deny" // default
		}

		// Summarize match criteria
		if match, ok := spec["match"].(map[string]interface{}); ok {
			var matchParts []string

			if kinds, ok := match["kinds"].([]interface{}); ok && len(kinds) > 0 {
				matchParts = append(matchParts, fmt.Sprintf("%d kind(s)", len(kinds)))
			}
			if namespaces, ok := match["namespaces"].([]interface{}); ok && len(namespaces) > 0 {
				matchParts = append(matchParts, fmt.Sprintf("%d ns", len(namespaces)))
			}
			if excludedNamespaces, ok := match["excludedNamespaces"].([]interface{}); ok && len(excludedNamespaces) > 0 {
				matchParts = append(matchParts, fmt.Sprintf("excl %d ns", len(excludedNamespaces)))
			}
			if labelSelector, ok := match["labelSelector"].(map[string]interface{}); ok {
				if matchLabels, ok := labelSelector["matchLabels"].(map[string]interface{}); ok && len(matchLabels) > 0 {
					matchParts = append(matchParts, fmt.Sprintf("%d label(s)", len(matchLabels)))
				}
			}
			if namespaceSelector, ok := match["namespaceSelector"].(map[string]interface{}); ok {
				if matchLabels, ok := namespaceSelector["matchLabels"].(map[string]interface{}); ok && len(matchLabels) > 0 {
					matchParts = append(matchParts, "ns selector")
				}
			}

			if len(matchParts) > 0 {
				c.Match = strings.Join(matchParts, ", ")
			} else {
				c.Match = "all"
			}
		} else {
			c.Match = "all"
		}

		// Summarize parameters
		if params, ok := spec["parameters"].(map[string]interface{}); ok {
			if len(params) > 0 {
				var paramKeys []string
				for k := range params {
					paramKeys = append(paramKeys, k)
				}
				if len(paramKeys) > 3 {
					c.Parameters = strings.Join(paramKeys[:3], ", ") + "..."
				} else {
					c.Parameters = strings.Join(paramKeys, ", ")
				}
			}
		}
		if c.Parameters == "" {
			c.Parameters = "-"
		}
	}

	// Get violation count from status
	if status, ok := obj["status"].(map[string]interface{}); ok {
		if violations, ok := status["violations"].([]interface{}); ok {
			c.Violations = len(violations)
		}
		if totalViolations, ok := status["totalViolations"].(float64); ok {
			c.TotalViolations = int(totalViolations)
		}
	}

	// Check if this is a tenant isolation policy
	nameLower := strings.ToLower(c.Name)
	for _, keyword := range tenantKeywords {
		if strings.Contains(nameLower, keyword) {
			c.IsTenantIsolation = true
			break
		}
	}

	return c
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

		// Identify security issues
		if !finding.HasNetworkPolicy {
			finding.SecurityIssues = append(finding.SecurityIssues, "No network policy")
		} else if !iso.DefaultDenyIngress {
			finding.SecurityIssues = append(finding.SecurityIssues, "No default deny")
		}

		if !finding.HasResourceQuota {
			finding.SecurityIssues = append(finding.SecurityIssues, "No resource quota")
		}

		if !finding.HasPodSecurityStd {
			finding.SecurityIssues = append(finding.SecurityIssues, "No pod security")
		}

		if finding.TenantProvider == "" {
			finding.SecurityIssues = append(finding.SecurityIssues, "No tenant assignment")
		}

		findings = append(findings, finding)
	}

	// Sort by namespace
	sort.Slice(findings, func(i, j int) bool {
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
	opaGatekeeper OPAGatekeeperTenantInfo,
	opaTemplates []ConstraintTemplateInfo,
	opaConstraints []ConstraintInfo) {

	section := loot.Section("Multitenancy-Admission-Commands")

	section.Add("# Multi-Tenancy Analysis")
	section.Add("#")

	// Detected tools
	providerCount := 0
	if hnc.Name != "" {
		providerCount++
		section.Add(fmt.Sprintf("# HNC: %s (%d hierarchies)", hnc.Status, hnc.Hierarchies))
	}
	if capsule.Name != "" {
		providerCount++
		section.Add(fmt.Sprintf("# Capsule: %s (%d tenants)", capsule.Status, capsule.Tenants))
	}
	if len(vclusters) > 0 {
		providerCount++
		section.Add(fmt.Sprintf("# vClusters: %d instances", len(vclusters)))
	}
	if loft.Name != "" {
		providerCount++
		section.Add(fmt.Sprintf("# Loft: %s (%d spaces, %d vClusters, %d teams)", loft.Status, loft.Spaces, loft.VirtualClusters, loft.Teams))
	}
	if kiosk.Name != "" {
		providerCount++
		section.Add(fmt.Sprintf("# Kiosk: %s (%d accounts, %d spaces)", kiosk.Status, kiosk.Accounts, kiosk.Spaces))
	}
	if opaGatekeeper.Name != "" {
		providerCount++
		status := opaGatekeeper.Status
		if opaGatekeeper.ImageVerified {
			status += " (verified)"
		}
		section.Add(fmt.Sprintf("# OPA Gatekeeper: %s (%d templates, %d constraints, %d tenant policies)", status, opaGatekeeper.ConstraintTemplates, opaGatekeeper.Constraints, opaGatekeeper.TenantIsolationPolicies))

		// Add detailed constraint template info
		if len(opaTemplates) > 0 {
			section.Add("#")
			section.Add("# Constraint Templates:")
			for _, tmpl := range opaTemplates {
				section.Add(fmt.Sprintf("#   - %s (kind: %s)", tmpl.Name, tmpl.Kind))
			}
		}

		// Add detailed constraint info
		if len(opaConstraints) > 0 {
			section.Add("#")
			section.Add("# Active Constraints:")
			for _, c := range opaConstraints {
				tenantMarker := ""
				if c.IsTenantIsolation {
					tenantMarker = " [TENANT]"
				}
				violationInfo := ""
				if c.Violations > 0 {
					violationInfo = fmt.Sprintf(" (%d violations)", c.Violations)
				}
				section.Add(fmt.Sprintf("#   - %s (%s, %s)%s%s", c.Name, c.Kind, c.EnforcementAction, tenantMarker, violationInfo))
			}
		}
	}

	if providerCount == 0 {
		section.Add("#")
		section.Add("# WARNING: No multi-tenancy solution detected!")
		section.Add("# Namespace isolation is limited to basic Kubernetes primitives")
	}

	section.Add("#")

	// Isolation statistics
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

	section.Add("# Namespace Isolation Statistics")
	section.Add(fmt.Sprintf("# Namespaces with proper isolation: %d/%d", isolated, len(nsIsolation)))
	section.Add(fmt.Sprintf("# Namespaces without network policy: %d", noNetpol))
	section.Add(fmt.Sprintf("# Namespaces without resource quota: %d", noQuota))
	section.Add(fmt.Sprintf("# Namespaces without pod security: %d", noPodSec))
	section.Add("#")

	// Commands for detected tools only
	section.Add("# Useful Commands")
	section.Add("#")
	if capsule.Name != "" {
		section.Add("# List Capsule tenants:")
		section.Add("kubectl get tenants")
		section.Add("#")
	}
	if hnc.Name != "" {
		section.Add("# List HNC hierarchies:")
		section.Add("kubectl hns tree --all-namespaces")
		section.Add("#")
	}
	if len(vclusters) > 0 {
		section.Add("# List vClusters:")
		section.Add("vcluster list")
		section.Add("#")
	}
	if loft.Name != "" {
		section.Add("# List Loft spaces:")
		section.Add("kubectl get spaces -A")
		section.Add("#")
	}
	if kiosk.Name != "" {
		section.Add("# List Kiosk accounts:")
		section.Add("kubectl get accounts")
		section.Add("#")
	}
	if opaGatekeeper.Name != "" {
		section.Add("# List Gatekeeper constraints:")
		section.Add("kubectl get constraints")
		section.Add("#")
	}
	section.Add("# Check namespace isolation:")
	section.Add("kubectl get networkpolicies -A")
	section.Add("kubectl get resourcequotas -A")
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
					Description:     fmt.Sprintf("Grants %s role to subjects in %d tenants", crb.RoleRef.Name, len(tenantsAffected)),
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
						Description:     fmt.Sprintf("Grants '%s' cluster-wide", role),
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
						Description:     fmt.Sprintf("PV with %s mode can be shared", accessMode),
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
					Description:     fmt.Sprintf("HostPath PV: %s", pv.Spec.HostPath.Path),
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
				Description:     "Cluster-wide network policy affects all tenants",
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
						Description:     "ExternalName service points to another namespace",
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
						Description:     "ClusterRole with wildcard permissions",
					})
					break
				}
			}
		}
	}

	return resources
}
