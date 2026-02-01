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
	"github.com/BishopFox/cloudfox/kubernetes/shared/admission"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

const K8S_MESH_ADMISSION_MODULE_NAME = "mesh-admission"

var MeshAdmissionCmd = &cobra.Command{
	Use:     "mesh-admission",
	Aliases: []string{"service-mesh-security", "mtls"},
	Short:   "Analyze service mesh mTLS and security configurations",
	Long: `
Analyze all service mesh security configurations including:

Service Mesh mTLS:
  - Istio PeerAuthentication (mTLS modes)
  - Istio RequestAuthentication (JWT)
  - Istio sidecar injection status
  - Linkerd mTLS and proxy injection
  - Cilium Service Mesh mTLS
  - Consul Connect
  - Open Service Mesh (OSM)
  - Kuma/Kong Mesh

Security Analysis:
  - Coverage gap analysis
  - mTLS bypass vectors
  - Authentication policy enforcement

Cloud-Specific Service Mesh (in-cluster detection):
  Detects cloud-managed service mesh from CRDs and deployments.
  No --cloud-provider flag required - reads cluster resources directly.

  AWS:
    - AWS App Mesh (VirtualNode, VirtualService, VirtualGateway)
    - App Mesh Controller detection

  GCP:
    - GCP Traffic Director (Envoy-based mesh)
    - Anthos Service Mesh (ASM)
    - GKE Gateway API integration

  Azure:
    - Azure Application Gateway Ingress Controller (AGIC)
    - Open Service Mesh (OSM) on AKS
    - Azure-managed Istio add-on

Examples:
  cloudfox kubernetes mesh-admission
  cloudfox kubernetes mesh-admission --detailed`,
	Run: ListMeshAdmission,
}

// init() removed - detailed flag is now a global persistent flag in cli/kubernetes.go

type MeshAdmissionOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t MeshAdmissionOutput) TableFiles() []internal.TableFile { return t.Table }
func (t MeshAdmissionOutput) LootFiles() []internal.LootFile   { return t.Loot }

// MeshEnumeratedPolicy is a unified representation of any policy/rule across all mesh tools
type MeshEnumeratedPolicy struct {
	Namespace string
	Tool      string
	Name      string
	Scope     string // MESH, NAMESPACE, WORKLOAD, Cluster
	Type      string // PeerAuthentication, RequestAuthentication, ServerAuthorization, etc.
	Details   string // tool-specific summary
}

// MeshAdmissionFinding represents mesh security for a namespace
type MeshAdmissionFinding struct {
	Namespace string

	// Mesh Provider
	MeshProvider string // istio, linkerd, cilium, consul, osm, kuma

	// mTLS Status
	MTLSMode       string // STRICT, PERMISSIVE, DISABLE
	MTLSEnforced   bool
	PeerAuthPolicy string

	// Sidecar Injection
	InjectionEnabled  bool
	InjectionLabel    string
	PodsWithSidecar   int
	PodsWithoutSidecar int
	TotalPods         int

	// Authentication
	HasJWTAuth     bool
	JWTPolicies    int
	AuthPolicies   int

	// Security Issues
	SecurityIssues []string
	BypassVectors  []string
}

// IstioInfo represents Istio mesh status
type IstioInfo struct {
	Name              string
	Namespace         string
	Version           string
	Status            string
	ControlPlaneReady bool
	GlobalMTLSMode string
	AutoInjection  bool
	ImageVerified  bool // True if Istio control plane image was verified
}

// IstioPeerAuthInfo represents an Istio PeerAuthentication policy
type IstioPeerAuthInfo struct {
	Name       string
	Namespace  string
	Scope      string // MESH, NAMESPACE, WORKLOAD
	MTLSMode string // STRICT, PERMISSIVE, DISABLE, UNSET
	Selector string
	PortMTLS map[int]string // port-specific mTLS settings
}

// IstioRequestAuthInfo represents an Istio RequestAuthentication policy
type IstioRequestAuthInfo struct {
	Name           string
	Namespace      string
	Selector       string
	JWTRules       int
	Issuers        []string
	Audiences      []string
	ForwardHeaders bool
}

// LinkerdInfo represents Linkerd mesh status
type LinkerdInfo struct {
	Name           string
	Namespace      string
	Version        string
	Status         string
	MTLSEnabled    bool
	IdentityIssuer string
	AutoInjection  bool
	ImageVerified  bool // True if Linkerd control plane image was verified
}

// LinkerdServerAuthInfo represents Linkerd ServerAuthorization/MeshTLSAuthentication
type LinkerdServerAuthInfo struct {
	Name           string
	Namespace      string
	Type           string // Server, ServerAuthorization, MeshTLSAuthentication
	MTLSMode   string
	Identities []string
	Networks   []string
}

// CiliumMeshInfo represents Cilium Service Mesh status
type CiliumMeshInfo struct {
	Name          string
	Namespace     string
	Status        string
	MTLSEnabled  bool
	MTLSMode     string
	EnvoyEnabled bool
	ImageVerified bool // True if Cilium agent image was verified
}

// ConsulConnectInfo represents Consul Connect status
type ConsulConnectInfo struct {
	Name          string
	Namespace     string
	Status        string
	MTLSEnabled  bool
	AutoInjection bool
	Intentions   int
	ImageVerified bool // True if Consul Connect image was verified
}

// OSMInfo represents Open Service Mesh status
type OSMInfo struct {
	Name           string
	Namespace      string
	Status         string
	MTLSEnabled   bool
	PermissiveMode bool
	ImageVerified bool // True if OSM controller image was verified
}

// FSMInfo represents Flomesh Service Mesh status
type FSMInfo struct {
	Name           string
	Namespace      string
	Status         string
	MTLSEnabled   bool
	PermissiveMode bool
	ImageVerified bool // True if FSM controller image was verified
}

// KumaMeshInfo represents Kuma/Kong Mesh status
type KumaMeshInfo struct {
	Name          string
	Namespace     string
	Status        string
	MTLSEnabled  bool
	MTLSMode     string
	ImageVerified bool // True if Kuma control plane image was verified
}

// AWSAppMeshInfo represents AWS App Mesh status
type AWSAppMeshInfo struct {
	Name           string
	Namespace      string
	Status         string
	PodsRunning    int
	TotalPods      int
	MTLSEnabled    bool
	AutoInjection  bool
	VirtualNodes    int
	VirtualServices int
	ImageVerified   bool
}

// InjectionStatus represents sidecar injection status for a namespace
type InjectionStatus struct {
	Namespace          string
	MeshProvider       string
	InjectionEnabled   bool
	InjectionLabel     string
	PodsWithSidecar    int
	PodsWithoutSidecar int
	TotalPods       int
	CoveragePercent float64
}

// verifyMeshEngineImage checks if a container image matches known patterns for a mesh engine
// Now uses the shared admission SDK for centralized engine detection
func verifyMeshEngineImage(image string, engine string) bool {
	return admission.VerifyControllerImage(image, engine)
}

func ListMeshAdmission(cmd *cobra.Command, args []string) {
	ctx, cancel := shared.ContextWithCancel()
	defer cancel()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDir, _ := parentCmd.PersistentFlags().GetString("outdir")
	detailed := globals.K8sDetailed

	logger.InfoM(fmt.Sprintf("Analyzing service mesh security for %s", globals.ClusterName), K8S_MESH_ADMISSION_MODULE_NAME)

	clientset := config.GetClientOrExit()
	dynClient := config.GetDynamicClientOrExit()

	// Analyze Istio
	logger.InfoM("Analyzing Istio...", K8S_MESH_ADMISSION_MODULE_NAME)
	istio, istioPeerAuth, istioReqAuth := analyzeIstio(ctx, clientset, dynClient)

	// Analyze Linkerd
	logger.InfoM("Analyzing Linkerd...", K8S_MESH_ADMISSION_MODULE_NAME)
	linkerd, linkerdAuth := analyzeLinkerd(ctx, clientset, dynClient)

	// Analyze Cilium Service Mesh
	logger.InfoM("Analyzing Cilium Service Mesh...", K8S_MESH_ADMISSION_MODULE_NAME)
	ciliumMesh := analyzeCiliumMesh(ctx, clientset, dynClient)

	// Analyze Consul Connect
	logger.InfoM("Analyzing Consul Connect...", K8S_MESH_ADMISSION_MODULE_NAME)
	consul := analyzeConsulConnect(ctx, clientset, dynClient)

	// Analyze OSM
	logger.InfoM("Analyzing Open Service Mesh...", K8S_MESH_ADMISSION_MODULE_NAME)
	osm := analyzeOSM(ctx, clientset, dynClient)

	// Analyze FSM (Flomesh Service Mesh)
	logger.InfoM("Analyzing Flomesh Service Mesh...", K8S_MESH_ADMISSION_MODULE_NAME)
	fsm := analyzeFSM(ctx, clientset, dynClient)

	// Analyze Kuma
	logger.InfoM("Analyzing Kuma Mesh...", K8S_MESH_ADMISSION_MODULE_NAME)
	kuma := analyzeKumaMesh(ctx, clientset, dynClient)

	// Analyze AWS App Mesh
	logger.InfoM("Analyzing AWS App Mesh...", K8S_MESH_ADMISSION_MODULE_NAME)
	awsAppMesh := analyzeAWSAppMesh(ctx, clientset, dynClient)

	// Analyze sidecar injection status
	logger.InfoM("Analyzing sidecar injection...", K8S_MESH_ADMISSION_MODULE_NAME)
	injectionStatus := analyzeInjectionStatus(ctx, clientset, istio, linkerd, ciliumMesh, consul, awsAppMesh)

	// Build findings per namespace
	findings := buildMeshAdmissionFindings(istio, istioPeerAuth, istioReqAuth, linkerd, linkerdAuth, ciliumMesh, consul, osm, kuma, awsAppMesh, injectionStatus)

	// Enumerate all policies into unified format
	logger.InfoM("Enumerating policies across all mesh tools...", K8S_MESH_ADMISSION_MODULE_NAME)
	var allPolicies []MeshEnumeratedPolicy

	// Convert existing parsed policies
	for _, pa := range istioPeerAuth {
		allPolicies = append(allPolicies, istioPeerAuthToPolicy(pa))
	}
	for _, ra := range istioReqAuth {
		allPolicies = append(allPolicies, istioRequestAuthToPolicy(ra))
	}
	for _, la := range linkerdAuth {
		allPolicies = append(allPolicies, linkerdAuthToPolicy(la))
	}

	// Sort by tool then namespace
	sort.Slice(allPolicies, func(i, j int) bool {
		if allPolicies[i].Tool != allPolicies[j].Tool {
			return allPolicies[i].Tool < allPolicies[j].Tool
		}
		return allPolicies[i].Namespace < allPolicies[j].Namespace
	})

	// Generate tables
	summaryHeader := []string{
		"Namespace",
		"Mesh Provider",
		"mTLS Mode",
		"mTLS Enforced",
		"Injection",
		"With Sidecar",
		"Without Sidecar",
		"JWT Auth",
		"Issues",
	}

	policiesHeader := []string{
		"Namespace",
		"Tool",
		"Name",
		"Scope",
		"Type",
		"Details",
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
	istioHeader := uniformPolicyHeader
	peerAuthHeader := uniformPolicyHeader
	reqAuthHeader := uniformPolicyHeader
	linkerdHeader := uniformPolicyHeader
	linkerdAuthHeader := uniformPolicyHeader
	injectionHeader := uniformPolicyHeader
	ciliumMeshHeader := uniformPolicyHeader
	consulConnectHeader := uniformPolicyHeader
	osmHeader := uniformPolicyHeader
	fsmHeader := uniformPolicyHeader
	kumaHeader := uniformPolicyHeader
	awsAppMeshHeader := uniformPolicyHeader

	var summaryRows [][]string
	var policiesRows [][]string
	var istioRows [][]string
	var peerAuthRows [][]string
	var reqAuthRows [][]string
	var linkerdRows [][]string
	var linkerdAuthRows [][]string
	var injectionRows [][]string
	var ciliumMeshRows [][]string
	var consulConnectRows [][]string
	var osmRows [][]string
	var fsmRows [][]string
	var kumaRows [][]string
	var awsAppMeshRows [][]string

	loot := shared.NewLootBuilder()

	// Build summary rows
	for _, finding := range findings {
		mtlsEnforced := "No"
		if finding.MTLSEnforced {
			mtlsEnforced = "Yes"
		}

		injection := "No"
		if finding.InjectionEnabled {
			injection = "Yes"
		}

		jwtAuth := "No"
		if finding.HasJWTAuth {
			jwtAuth = fmt.Sprintf("Yes (%d)", finding.JWTPolicies)
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
			finding.MeshProvider,
			finding.MTLSMode,
			mtlsEnforced,
			injection,
			fmt.Sprintf("%d", finding.PodsWithSidecar),
			fmt.Sprintf("%d", finding.PodsWithoutSidecar),
			jwtAuth,
			issues,
		})
	}

	// Build unified policies rows
	for _, policy := range allPolicies {
		policiesRows = append(policiesRows, []string{
			policy.Namespace,
			policy.Tool,
			policy.Name,
			policy.Scope,
			policy.Type,
			policy.Details,
		})
	}

	// Build Istio rows
	if istio.Name != "" {
		// Detect issues
		var istioIssues []string
		if istio.Status != "Running" && istio.Status != "Healthy" {
			istioIssues = append(istioIssues, "Not running")
		}
		if istio.GlobalMTLSMode == "PERMISSIVE" || istio.GlobalMTLSMode == "DISABLE" {
			istioIssues = append(istioIssues, "mTLS not strict")
		}
		if !istio.AutoInjection {
			istioIssues = append(istioIssues, "Auto injection disabled")
		}
		istioIssuesStr := "<NONE>"
		if len(istioIssues) > 0 {
			istioIssuesStr = strings.Join(istioIssues, "; ")
		}

		// Uniform schema: Namespace, Name, Scope, Target, Type, Configuration, Details, Issues
		istioScope := "Cluster"
		istioTarget := "All workloads"
		istioType := "Istio Control Plane"
		istioConfig := fmt.Sprintf("mTLS: %s, Auto Inject: %v", istio.GlobalMTLSMode, istio.AutoInjection)
		istioDetails := fmt.Sprintf("Version: %s, Status: %s", istio.Version, istio.Status)

		istioRows = append(istioRows, []string{
			istio.Namespace,
			istio.Name,
			istioScope,
			istioTarget,
			istioType,
			istioConfig,
			istioDetails,
			istioIssuesStr,
		})
	}

	// Build PeerAuthentication rows
	for _, pa := range istioPeerAuth {
		portMTLS := "-"
		if len(pa.PortMTLS) > 0 {
			var ports []string
			for port, mode := range pa.PortMTLS {
				ports = append(ports, fmt.Sprintf("%d:%s", port, mode))
			}
			portMTLS = strings.Join(ports, ", ")
		}

		selector := pa.Selector
		if selector == "" {
			selector = "*"
		}

		// Detect issues
		var paIssues []string
		if pa.MTLSMode == "PERMISSIVE" {
			paIssues = append(paIssues, "Permissive mTLS mode")
		}
		if pa.MTLSMode == "DISABLE" {
			paIssues = append(paIssues, "mTLS disabled")
		}
		if selector == "*" && pa.Scope == "Namespace" {
			paIssues = append(paIssues, "Applies to all pods in namespace")
		}
		paIssuesStr := "<NONE>"
		if len(paIssues) > 0 {
			paIssuesStr = strings.Join(paIssues, "; ")
		}

		// Uniform schema: Namespace, Name, Scope, Target, Type, Configuration, Details, Issues
		paTarget := selector
		paType := "PeerAuthentication"
		paConfig := fmt.Sprintf("mTLS: %s", pa.MTLSMode)
		paDetails := portMTLS
		if paDetails == "-" {
			paDetails = "No port-specific settings"
		} else {
			paDetails = fmt.Sprintf("Ports: %s", paDetails)
		}

		peerAuthRows = append(peerAuthRows, []string{
			pa.Namespace,
			pa.Name,
			pa.Scope,
			paTarget,
			paType,
			paConfig,
			paDetails,
			paIssuesStr,
		})
	}

	// Build RequestAuthentication rows
	for _, ra := range istioReqAuth {
		selector := ra.Selector
		if selector == "" {
			selector = "*"
		}

		issuers := "-"
		if len(ra.Issuers) > 0 {
			if len(ra.Issuers) > 2 {
				issuers = strings.Join(ra.Issuers[:2], ", ") + "..."
			} else {
				issuers = strings.Join(ra.Issuers, ", ")
			}
		}

		audiences := "-"
		if len(ra.Audiences) > 0 {
			audiences = strings.Join(ra.Audiences, ", ")
		}

		// Detect issues
		var raIssues []string
		if ra.JWTRules == 0 {
			raIssues = append(raIssues, "No JWT rules defined")
		}
		if len(ra.Issuers) == 0 {
			raIssues = append(raIssues, "No issuers configured")
		}
		if selector == "*" {
			raIssues = append(raIssues, "Applies to all pods")
		}
		raIssuesStr := "<NONE>"
		if len(raIssues) > 0 {
			raIssuesStr = strings.Join(raIssues, "; ")
		}

		// Uniform schema: Namespace, Name, Scope, Target, Type, Configuration, Details, Issues
		raScope := "NAMESPACE"
		if selector != "*" {
			raScope = "WORKLOAD"
		}
		raTarget := selector
		raType := "RequestAuthentication"
		raConfig := fmt.Sprintf("JWT Rules: %d", ra.JWTRules)
		raDetails := fmt.Sprintf("Issuers: %s, Audiences: %s", issuers, audiences)

		reqAuthRows = append(reqAuthRows, []string{
			ra.Namespace,
			ra.Name,
			raScope,
			raTarget,
			raType,
			raConfig,
			raDetails,
			raIssuesStr,
		})
	}

	// Build Linkerd rows
	if linkerd.Name != "" {
		// Detect issues
		var linkerdIssues []string
		if linkerd.Status != "Running" && linkerd.Status != "Healthy" {
			linkerdIssues = append(linkerdIssues, "Not running")
		}
		if !linkerd.MTLSEnabled {
			linkerdIssues = append(linkerdIssues, "mTLS disabled")
		}
		if !linkerd.AutoInjection {
			linkerdIssues = append(linkerdIssues, "Auto injection disabled")
		}
		if linkerd.IdentityIssuer == "" {
			linkerdIssues = append(linkerdIssues, "No identity issuer")
		}
		linkerdIssuesStr := "<NONE>"
		if len(linkerdIssues) > 0 {
			linkerdIssuesStr = strings.Join(linkerdIssues, "; ")
		}

		// Uniform schema: Namespace, Name, Scope, Target, Type, Configuration, Details, Issues
		linkerdScope := "Cluster"
		linkerdTarget := "All workloads"
		linkerdType := "Linkerd Control Plane"
		linkerdConfig := fmt.Sprintf("mTLS: %v, Auto Inject: %v", linkerd.MTLSEnabled, linkerd.AutoInjection)
		linkerdDetails := fmt.Sprintf("Version: %s, Status: %s, Issuer: %s", linkerd.Version, linkerd.Status, linkerd.IdentityIssuer)

		linkerdRows = append(linkerdRows, []string{
			linkerd.Namespace,
			linkerd.Name,
			linkerdScope,
			linkerdTarget,
			linkerdType,
			linkerdConfig,
			linkerdDetails,
			linkerdIssuesStr,
		})
	}

	// Build Linkerd auth rows
	for _, la := range linkerdAuth {
		identities := "-"
		if len(la.Identities) > 0 {
			if len(la.Identities) > 2 {
				identities = strings.Join(la.Identities[:2], ", ") + "..."
			} else {
				identities = strings.Join(la.Identities, ", ")
			}
		}

		networks := "-"
		if len(la.Networks) > 0 {
			networks = strings.Join(la.Networks, ", ")
		}

		// Detect issues
		var laIssues []string
		if la.MTLSMode == "permissive" || la.MTLSMode == "disabled" {
			laIssues = append(laIssues, "mTLS not strict")
		}
		if len(la.Identities) == 0 {
			laIssues = append(laIssues, "No identities configured")
		}
		laIssuesStr := "<NONE>"
		if len(laIssues) > 0 {
			laIssuesStr = strings.Join(laIssues, "; ")
		}

		// Uniform schema: Namespace, Name, Scope, Target, Type, Configuration, Details, Issues
		laScope := "NAMESPACE"
		laTarget := identities
		if laTarget == "-" {
			laTarget = "All identities"
		}
		laConfig := fmt.Sprintf("mTLS: %s", la.MTLSMode)
		laDetails := fmt.Sprintf("Networks: %s", networks)

		linkerdAuthRows = append(linkerdAuthRows, []string{
			la.Namespace,
			la.Name,
			laScope,
			laTarget,
			la.Type,
			laConfig,
			laDetails,
			laIssuesStr,
		})
	}

	// Build injection status rows
	for _, is := range injectionStatus {
		enabled := "No"
		if is.InjectionEnabled {
			enabled = "Yes"
		}

		label := is.InjectionLabel
		if label == "" {
			label = "-"
		}

		// Detect issues
		var injIssues []string
		if !is.InjectionEnabled {
			injIssues = append(injIssues, "Injection disabled")
		}
		if is.CoveragePercent < 50.0 {
			injIssues = append(injIssues, "Low sidecar coverage")
		}
		if is.PodsWithoutSidecar > 0 && is.InjectionEnabled {
			injIssues = append(injIssues, "Pods missing sidecars")
		}
		injIssuesStr := "<NONE>"
		if len(injIssues) > 0 {
			injIssuesStr = strings.Join(injIssues, "; ")
		}

		// Uniform schema: Namespace, Name, Scope, Target, Type, Configuration, Details, Issues
		injName := fmt.Sprintf("%s-injection", strings.ToLower(is.MeshProvider))
		if is.MeshProvider == "-" {
			injName = "no-mesh"
		}
		injScope := "Namespace"
		injTarget := fmt.Sprintf("%d pods", is.TotalPods)
		injType := "Sidecar Injection"
		injConfig := fmt.Sprintf("Enabled: %s, Label: %s", enabled, label)
		injDetails := fmt.Sprintf("With Sidecar: %d, Without: %d, Coverage: %.1f%%", is.PodsWithSidecar, is.PodsWithoutSidecar, is.CoveragePercent)

		injectionRows = append(injectionRows, []string{
			is.Namespace,
			injName,
			injScope,
			injTarget,
			injType,
			injConfig,
			injDetails,
			injIssuesStr,
		})
	}

	// Build Cilium Mesh rows
	if ciliumMesh.Name != "" {
		// Detect issues
		var ciliumIssues []string
		if !ciliumMesh.MTLSEnabled {
			ciliumIssues = append(ciliumIssues, "mTLS disabled")
		}
		if ciliumMesh.MTLSMode == "permissive" || ciliumMesh.MTLSMode == "disabled" {
			ciliumIssues = append(ciliumIssues, "Weak mTLS mode")
		}
		if !ciliumMesh.EnvoyEnabled {
			ciliumIssues = append(ciliumIssues, "Envoy proxy disabled")
		}
		issuesStr := "<NONE>"
		if len(ciliumIssues) > 0 {
			issuesStr = strings.Join(ciliumIssues, "; ")
		}

		// Uniform schema: Namespace, Name, Scope, Target, Type, Configuration, Details, Issues
		ciliumScope := "Cluster"
		ciliumTarget := "All workloads"
		ciliumType := "Cilium Service Mesh"
		ciliumConfig := fmt.Sprintf("mTLS: %s, Mode: %s", shared.FormatBool(ciliumMesh.MTLSEnabled), ciliumMesh.MTLSMode)
		ciliumDetails := fmt.Sprintf("Status: %s, Envoy: %s", ciliumMesh.Status, shared.FormatBool(ciliumMesh.EnvoyEnabled))

		ciliumMeshRows = append(ciliumMeshRows, []string{
			ciliumMesh.Namespace,
			ciliumMesh.Name,
			ciliumScope,
			ciliumTarget,
			ciliumType,
			ciliumConfig,
			ciliumDetails,
			issuesStr,
		})
	}

	// Build Consul Connect rows
	if consul.Name != "" {
		// Detect issues
		var consulIssues []string
		if !consul.MTLSEnabled {
			consulIssues = append(consulIssues, "mTLS disabled")
		}
		if !consul.AutoInjection {
			consulIssues = append(consulIssues, "Auto injection disabled")
		}
		if consul.Intentions == 0 {
			consulIssues = append(consulIssues, "No intentions defined")
		}
		issuesStr := "<NONE>"
		if len(consulIssues) > 0 {
			issuesStr = strings.Join(consulIssues, "; ")
		}

		// Uniform schema: Namespace, Name, Scope, Target, Type, Configuration, Details, Issues
		consulScope := "Cluster"
		consulTarget := "All workloads"
		consulType := "Consul Connect"
		consulConfig := fmt.Sprintf("mTLS: %s, Auto Inject: %s", shared.FormatBool(consul.MTLSEnabled), shared.FormatBool(consul.AutoInjection))
		consulDetails := fmt.Sprintf("Status: %s, Intentions: %d", consul.Status, consul.Intentions)

		consulConnectRows = append(consulConnectRows, []string{
			consul.Namespace,
			consul.Name,
			consulScope,
			consulTarget,
			consulType,
			consulConfig,
			consulDetails,
			issuesStr,
		})
	}

	// Build OSM rows
	if osm.Name != "" {
		// Detect issues
		var osmIssues []string
		if !osm.MTLSEnabled {
			osmIssues = append(osmIssues, "mTLS disabled")
		}
		if osm.PermissiveMode {
			osmIssues = append(osmIssues, "Permissive mode enabled")
		}
		issuesStr := "<NONE>"
		if len(osmIssues) > 0 {
			issuesStr = strings.Join(osmIssues, "; ")
		}

		// Uniform schema: Namespace, Name, Scope, Target, Type, Configuration, Details, Issues
		osmScope := "Cluster"
		osmTarget := "All workloads"
		osmType := "Open Service Mesh"
		osmConfig := fmt.Sprintf("mTLS: %s, Permissive: %s", shared.FormatBool(osm.MTLSEnabled), shared.FormatBool(osm.PermissiveMode))
		osmDetails := fmt.Sprintf("Status: %s", osm.Status)

		osmRows = append(osmRows, []string{
			osm.Namespace,
			osm.Name,
			osmScope,
			osmTarget,
			osmType,
			osmConfig,
			osmDetails,
			issuesStr,
		})
	}

	// Build FSM rows
	if fsm.Name != "" {
		// Detect issues
		var fsmIssues []string
		if !fsm.MTLSEnabled {
			fsmIssues = append(fsmIssues, "mTLS disabled")
		}
		if fsm.PermissiveMode {
			fsmIssues = append(fsmIssues, "Permissive mode enabled")
		}
		issuesStr := "<NONE>"
		if len(fsmIssues) > 0 {
			issuesStr = strings.Join(fsmIssues, "; ")
		}

		// Uniform schema: Namespace, Name, Scope, Target, Type, Configuration, Details, Issues
		fsmScope := "Cluster"
		fsmTarget := "All workloads"
		fsmType := "Flomesh Service Mesh"
		fsmConfig := fmt.Sprintf("mTLS: %s, Permissive: %s", shared.FormatBool(fsm.MTLSEnabled), shared.FormatBool(fsm.PermissiveMode))
		fsmDetails := fmt.Sprintf("Status: %s", fsm.Status)

		fsmRows = append(fsmRows, []string{
			fsm.Namespace,
			fsm.Name,
			fsmScope,
			fsmTarget,
			fsmType,
			fsmConfig,
			fsmDetails,
			issuesStr,
		})
	}

	// Build Kuma Mesh rows
	if kuma.Name != "" {
		// Detect issues
		var kumaIssues []string
		if !kuma.MTLSEnabled {
			kumaIssues = append(kumaIssues, "mTLS disabled")
		}
		if kuma.MTLSMode == "permissive" || kuma.MTLSMode == "disabled" {
			kumaIssues = append(kumaIssues, "Weak mTLS mode")
		}
		issuesStr := "<NONE>"
		if len(kumaIssues) > 0 {
			issuesStr = strings.Join(kumaIssues, "; ")
		}

		// Uniform schema: Namespace, Name, Scope, Target, Type, Configuration, Details, Issues
		kumaScope := "Cluster"
		kumaTarget := "All workloads"
		kumaType := "Kuma Mesh"
		kumaConfig := fmt.Sprintf("mTLS: %s, Mode: %s", shared.FormatBool(kuma.MTLSEnabled), kuma.MTLSMode)
		kumaDetails := fmt.Sprintf("Status: %s", kuma.Status)

		kumaRows = append(kumaRows, []string{
			kuma.Namespace,
			kuma.Name,
			kumaScope,
			kumaTarget,
			kumaType,
			kumaConfig,
			kumaDetails,
			issuesStr,
		})
	}

	// Build AWS App Mesh rows
	if awsAppMesh.Name != "" {
		// Detect issues
		var appMeshIssues []string
		if !awsAppMesh.MTLSEnabled {
			appMeshIssues = append(appMeshIssues, "mTLS disabled")
		}
		if !awsAppMesh.AutoInjection {
			appMeshIssues = append(appMeshIssues, "Auto injection disabled")
		}
		if awsAppMesh.VirtualNodes == 0 && awsAppMesh.VirtualServices == 0 {
			appMeshIssues = append(appMeshIssues, "No virtual nodes or services")
		}
		if awsAppMesh.PodsRunning < awsAppMesh.TotalPods {
			appMeshIssues = append(appMeshIssues, "Not all pods running")
		}
		issuesStr := "<NONE>"
		if len(appMeshIssues) > 0 {
			issuesStr = strings.Join(appMeshIssues, "; ")
		}

		// Uniform schema: Namespace, Name, Scope, Target, Type, Configuration, Details, Issues
		appMeshScope := "Cluster"
		appMeshTarget := fmt.Sprintf("Nodes: %d, Services: %d", awsAppMesh.VirtualNodes, awsAppMesh.VirtualServices)
		appMeshType := "AWS App Mesh"
		appMeshConfig := fmt.Sprintf("mTLS: %s, Auto Inject: %s", shared.FormatBool(awsAppMesh.MTLSEnabled), shared.FormatBool(awsAppMesh.AutoInjection))
		appMeshDetails := fmt.Sprintf("Status: %s, Pods: %d/%d running", awsAppMesh.Status, awsAppMesh.PodsRunning, awsAppMesh.TotalPods)

		awsAppMeshRows = append(awsAppMeshRows, []string{
			awsAppMesh.Namespace,
			awsAppMesh.Name,
			appMeshScope,
			appMeshTarget,
			appMeshType,
			appMeshConfig,
			appMeshDetails,
			issuesStr,
		})
	}

	// Generate loot
	generateMeshAdmissionLoot(loot, findings, istio, istioPeerAuth, istioReqAuth, linkerd, linkerdAuth, ciliumMesh, consul, osm, fsm, kuma, awsAppMesh, injectionStatus)

	// Build output tables
	var tables []internal.TableFile

	// Always show: summary + unified policies
	tables = append(tables, internal.TableFile{
		Name:   "Mesh-Admission-Summary",
		Header: summaryHeader,
		Body:   summaryRows,
	})

	if len(policiesRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Mesh-Admission-Policy-Overview",
			Header: policiesHeader,
			Body:   policiesRows,
		})
	}

	// Detailed tables: per-tool breakdowns (only with --detailed)
	if detailed {
		if len(istioRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Mesh-Admission-Istio-Policies",
				Header: istioHeader,
				Body:   istioRows,
			})
		}

		if len(peerAuthRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Mesh-Admission-Istio-PeerAuth-Policies",
				Header: peerAuthHeader,
				Body:   peerAuthRows,
			})
		}

		if len(reqAuthRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Mesh-Admission-Istio-RequestAuth-Policies",
				Header: reqAuthHeader,
				Body:   reqAuthRows,
			})
		}

		if len(linkerdRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Mesh-Admission-Linkerd-Policies",
				Header: linkerdHeader,
				Body:   linkerdRows,
			})
		}

		if len(linkerdAuthRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Mesh-Admission-Linkerd-Auth-Policies",
				Header: linkerdAuthHeader,
				Body:   linkerdAuthRows,
			})
		}

		if len(injectionRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Mesh-Admission-Injection-Status-Policies",
				Header: injectionHeader,
				Body:   injectionRows,
			})
		}

		if len(ciliumMeshRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Mesh-Admission-Cilium-Policies",
				Header: ciliumMeshHeader,
				Body:   ciliumMeshRows,
			})
		}

		if len(consulConnectRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Mesh-Admission-Consul-Connect-Policies",
				Header: consulConnectHeader,
				Body:   consulConnectRows,
			})
		}

		if len(osmRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Mesh-Admission-OSM-Policies",
				Header: osmHeader,
				Body:   osmRows,
			})
		}

		if len(fsmRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Mesh-Admission-FSM-Policies",
				Header: fsmHeader,
				Body:   fsmRows,
			})
		}

		if len(kumaRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Mesh-Admission-Kuma-Policies",
				Header: kumaHeader,
				Body:   kumaRows,
			})
		}

		if len(awsAppMeshRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Mesh-Admission-AWS-AppMesh-Policies",
				Header: awsAppMeshHeader,
				Body:   awsAppMeshRows,
			})
		}
	}

	output := MeshAdmissionOutput{
		Table: tables,
		Loot:  loot.Build(),
	}

	err := internal.HandleOutput(
		"Kubernetes",
		"table",
		outputDir,
		verbosity,
		wrap,
		"Mesh-Admission",
		globals.ClusterName,
		"results",
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), K8S_MESH_ADMISSION_MODULE_NAME)
		return
	}
}

// ============================================================================
// Istio Analysis
// ============================================================================

func analyzeIstio(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) (IstioInfo, []IstioPeerAuthInfo, []IstioRequestAuthInfo) {
	info := IstioInfo{}
	var peerAuth []IstioPeerAuthInfo
	var reqAuth []IstioRequestAuthInfo

	// Check for Istiod deployment
	namespaces := []string{"istio-system", "istio"}
	for _, ns := range namespaces {
		deployments, err := clientset.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, dep := range deployments.Items {
			if strings.Contains(strings.ToLower(dep.Name), "istiod") {
				info.Name = "Istio"
				info.Namespace = ns
				info.Status = "active"

				// Get version from image tag
				for _, container := range dep.Spec.Template.Spec.Containers {
					if strings.Contains(container.Image, "istiod") || strings.Contains(container.Image, "pilot") {
						parts := strings.Split(container.Image, ":")
						if len(parts) > 1 {
							info.Version = parts[1]
						}
					}
				}

				// Check readiness
				if dep.Status.ReadyReplicas < dep.Status.Replicas {
					info.Status = "degraded"
				}

				info.ControlPlaneReady = dep.Status.ReadyReplicas > 0
				break
			}
		}
		if info.Name != "" {
			break
		}
	}

	if info.Name == "" {
		return info, peerAuth, reqAuth
	}

	// Check global mTLS via MeshConfig or mesh-wide PeerAuthentication
	info.GlobalMTLSMode = "PERMISSIVE" // Default

	// Check for IstioOperator or mesh ConfigMap
	meshCM, err := clientset.CoreV1().ConfigMaps(info.Namespace).Get(ctx, "istio", metav1.GetOptions{})
	if err == nil {
		if meshConfig, ok := meshCM.Data["mesh"]; ok {
			if strings.Contains(meshConfig, "STRICT") {
				info.GlobalMTLSMode = "STRICT"
			} else if strings.Contains(meshConfig, "DISABLE") {
				info.GlobalMTLSMode = "DISABLE"
			}
		}
	}

	// Check for auto injection via MutatingWebhookConfiguration
	webhooks, err := clientset.AdmissionregistrationV1().MutatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, wh := range webhooks.Items {
			if strings.Contains(strings.ToLower(wh.Name), "istio") && strings.Contains(strings.ToLower(wh.Name), "sidecar") {
				info.AutoInjection = true
				break
			}
		}
	}

	// Get PeerAuthentication policies
	peerAuthGVR := schema.GroupVersionResource{
		Group:    "security.istio.io",
		Version:  "v1",
		Resource: "peerauthentications",
	}

	// Try v1 first, then v1beta1
	paList, err := dynClient.Resource(peerAuthGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err != nil {
		peerAuthGVR.Version = "v1beta1"
		paList, err = dynClient.Resource(peerAuthGVR).Namespace("").List(ctx, metav1.ListOptions{})
	}

	if err == nil {
		for _, pa := range paList.Items {
			parsed := parseIstioPeerAuth(pa.Object)
			peerAuth = append(peerAuth, parsed)

			// Check for mesh-wide strict mTLS
			if parsed.Scope == "MESH" && parsed.MTLSMode == "STRICT" {
				info.GlobalMTLSMode = "STRICT"
			}
		}
	}

	// Get RequestAuthentication policies
	reqAuthGVR := schema.GroupVersionResource{
		Group:    "security.istio.io",
		Version:  "v1",
		Resource: "requestauthentications",
	}

	raList, err := dynClient.Resource(reqAuthGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err != nil {
		reqAuthGVR.Version = "v1beta1"
		raList, err = dynClient.Resource(reqAuthGVR).Namespace("").List(ctx, metav1.ListOptions{})
	}

	if err == nil {
		for _, ra := range raList.Items {
			parsed := parseIstioRequestAuth(ra.Object)
			reqAuth = append(reqAuth, parsed)
		}
	}

	// Verify by checking deployment images
	for _, ns := range namespaces {
		deployments, err := clientset.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
		if err == nil {
			for _, dep := range deployments.Items {
				for _, container := range dep.Spec.Template.Spec.Containers {
					if verifyMeshEngineImage(container.Image, "istio") {
						info.ImageVerified = true
						break
					}
				}
				if info.ImageVerified {
					break
				}
			}
		}
		if info.ImageVerified {
			break
		}
	}

	return info, peerAuth, reqAuth
}

func parseIstioPeerAuth(obj map[string]interface{}) IstioPeerAuthInfo {
	pa := IstioPeerAuthInfo{
		PortMTLS: make(map[int]string),
	}

	if metadata, ok := obj["metadata"].(map[string]interface{}); ok {
		pa.Name, _ = metadata["name"].(string)
		pa.Namespace, _ = metadata["namespace"].(string)
	}

	// Determine scope
	if pa.Namespace == "istio-system" || pa.Namespace == "istio" {
		pa.Scope = "MESH"
	} else {
		pa.Scope = "NAMESPACE"
	}

	if spec, ok := obj["spec"].(map[string]interface{}); ok {
		// Check selector
		if selector, ok := spec["selector"].(map[string]interface{}); ok {
			if matchLabels, ok := selector["matchLabels"].(map[string]interface{}); ok {
				var labels []string
				for k, v := range matchLabels {
					labels = append(labels, fmt.Sprintf("%s=%v", k, v))
				}
				pa.Selector = strings.Join(labels, ", ")
				pa.Scope = "WORKLOAD"
			}
		}

		// Check mtls mode
		if mtls, ok := spec["mtls"].(map[string]interface{}); ok {
			if mode, ok := mtls["mode"].(string); ok {
				pa.MTLSMode = mode
			}
		}

		// Check port-level mTLS
		if portLevelMtls, ok := spec["portLevelMtls"].(map[string]interface{}); ok {
			for portStr, mtlsConfig := range portLevelMtls {
				var port int
				fmt.Sscanf(portStr, "%d", &port)
				if mtlsMap, ok := mtlsConfig.(map[string]interface{}); ok {
					if mode, ok := mtlsMap["mode"].(string); ok {
						pa.PortMTLS[port] = mode
					}
				}
			}
		}
	}

	if pa.MTLSMode == "" {
		pa.MTLSMode = "UNSET"
	}

	return pa
}

func parseIstioRequestAuth(obj map[string]interface{}) IstioRequestAuthInfo {
	ra := IstioRequestAuthInfo{}

	if metadata, ok := obj["metadata"].(map[string]interface{}); ok {
		ra.Name, _ = metadata["name"].(string)
		ra.Namespace, _ = metadata["namespace"].(string)
	}

	if spec, ok := obj["spec"].(map[string]interface{}); ok {
		// Check selector
		if selector, ok := spec["selector"].(map[string]interface{}); ok {
			if matchLabels, ok := selector["matchLabels"].(map[string]interface{}); ok {
				var labels []string
				for k, v := range matchLabels {
					labels = append(labels, fmt.Sprintf("%s=%v", k, v))
				}
				ra.Selector = strings.Join(labels, ", ")
			}
		}

		// Parse JWT rules
		if jwtRules, ok := spec["jwtRules"].([]interface{}); ok {
			ra.JWTRules = len(jwtRules)
			for _, rule := range jwtRules {
				if ruleMap, ok := rule.(map[string]interface{}); ok {
					if issuer, ok := ruleMap["issuer"].(string); ok {
						ra.Issuers = append(ra.Issuers, issuer)
					}
					if audiences, ok := ruleMap["audiences"].([]interface{}); ok {
						for _, aud := range audiences {
							if audStr, ok := aud.(string); ok {
								ra.Audiences = append(ra.Audiences, audStr)
							}
						}
					}
					if _, ok := ruleMap["forwardOriginalToken"].(bool); ok {
						ra.ForwardHeaders = true
					}
				}
			}
		}
	}

	return ra
}

// ============================================================================
// Linkerd Analysis
// ============================================================================

func analyzeLinkerd(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) (LinkerdInfo, []LinkerdServerAuthInfo) {
	info := LinkerdInfo{}
	var auth []LinkerdServerAuthInfo

	// Check for Linkerd control plane
	namespaces := []string{"linkerd", "linkerd-viz", "linkerd-system"}
	for _, ns := range namespaces {
		deployments, err := clientset.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, dep := range deployments.Items {
			if strings.Contains(strings.ToLower(dep.Name), "linkerd-destination") ||
				strings.Contains(strings.ToLower(dep.Name), "linkerd-controller") {
				info.Name = "Linkerd"
				info.Namespace = ns
				info.Status = "active"

				// Get version
				for _, container := range dep.Spec.Template.Spec.Containers {
					parts := strings.Split(container.Image, ":")
					if len(parts) > 1 {
						info.Version = parts[1]
					}
				}

				// Check readiness
				if dep.Status.ReadyReplicas < dep.Status.Replicas {
					info.Status = "degraded"
				}
				break
			}
		}
		if info.Name != "" {
			break
		}
	}

	if info.Name == "" {
		return info, auth
	}

	// Check for identity issuer (mTLS)
	secrets, err := clientset.CoreV1().Secrets(info.Namespace).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, secret := range secrets.Items {
			if strings.Contains(secret.Name, "identity") && strings.Contains(secret.Name, "issuer") {
				info.MTLSEnabled = true
				info.IdentityIssuer = secret.Name
				break
			}
		}
	}

	// Check for auto injection via MutatingWebhookConfiguration
	webhooks, err := clientset.AdmissionregistrationV1().MutatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, wh := range webhooks.Items {
			if strings.Contains(strings.ToLower(wh.Name), "linkerd") && strings.Contains(strings.ToLower(wh.Name), "proxy") {
				info.AutoInjection = true
				break
			}
		}
	}

	// Get Server and ServerAuthorization policies
	serverGVR := schema.GroupVersionResource{
		Group:    "policy.linkerd.io",
		Version:  "v1beta1",
		Resource: "servers",
	}

	serverList, err := dynClient.Resource(serverGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, s := range serverList.Items {
			parsed := parseLinkerdServer(s.Object)
			auth = append(auth, parsed)
		}
	}

	// Get ServerAuthorization
	serverAuthGVR := schema.GroupVersionResource{
		Group:    "policy.linkerd.io",
		Version:  "v1beta1",
		Resource: "serverauthorizations",
	}

	authList, err := dynClient.Resource(serverAuthGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, a := range authList.Items {
			parsed := parseLinkerdServerAuth(a.Object)
			auth = append(auth, parsed)
		}
	}

	// Get MeshTLSAuthentication
	meshTLSGVR := schema.GroupVersionResource{
		Group:    "policy.linkerd.io",
		Version:  "v1alpha1",
		Resource: "meshtlsauthentications",
	}

	tlsList, err := dynClient.Resource(meshTLSGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, t := range tlsList.Items {
			parsed := parseLinkerdMeshTLS(t.Object)
			auth = append(auth, parsed)
		}
	}

	// Verify by checking deployment images
	for _, ns := range namespaces {
		deployments, err := clientset.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
		if err == nil {
			for _, dep := range deployments.Items {
				for _, container := range dep.Spec.Template.Spec.Containers {
					if verifyMeshEngineImage(container.Image, "linkerd") {
						info.ImageVerified = true
						break
					}
				}
				if info.ImageVerified {
					break
				}
			}
		}
		if info.ImageVerified {
			break
		}
	}

	return info, auth
}

func parseLinkerdServer(obj map[string]interface{}) LinkerdServerAuthInfo {
	sa := LinkerdServerAuthInfo{
		Type: "Server",
	}

	if metadata, ok := obj["metadata"].(map[string]interface{}); ok {
		sa.Name, _ = metadata["name"].(string)
		sa.Namespace, _ = metadata["namespace"].(string)
	}

	if spec, ok := obj["spec"].(map[string]interface{}); ok {
		if proxyProtocol, ok := spec["proxyProtocol"].(string); ok {
			if proxyProtocol == "TLS" {
				sa.MTLSMode = "STRICT"
			} else {
				sa.MTLSMode = proxyProtocol
			}
		}
	}

	return sa
}

func parseLinkerdServerAuth(obj map[string]interface{}) LinkerdServerAuthInfo {
	sa := LinkerdServerAuthInfo{
		Type: "ServerAuthorization",
	}

	if metadata, ok := obj["metadata"].(map[string]interface{}); ok {
		sa.Name, _ = metadata["name"].(string)
		sa.Namespace, _ = metadata["namespace"].(string)
	}

	if spec, ok := obj["spec"].(map[string]interface{}); ok {
		// Parse client configuration
		if client, ok := spec["client"].(map[string]interface{}); ok {
			// Check for meshTLS
			if meshTLS, ok := client["meshTLS"].(map[string]interface{}); ok {
				sa.MTLSMode = "STRICT"
				if identities, ok := meshTLS["identities"].([]interface{}); ok {
					for _, id := range identities {
						if idStr, ok := id.(string); ok {
							sa.Identities = append(sa.Identities, idStr)
						}
					}
				}
			}

			// Check for unauthenticated
			if _, ok := client["unauthenticated"].(bool); ok {
				sa.MTLSMode = "PERMISSIVE"
			}

			// Check for networks
			if networks, ok := client["networks"].([]interface{}); ok {
				for _, net := range networks {
					if netMap, ok := net.(map[string]interface{}); ok {
						if cidr, ok := netMap["cidr"].(string); ok {
							sa.Networks = append(sa.Networks, cidr)
						}
					}
				}
			}
		}
	}

	return sa
}

func parseLinkerdMeshTLS(obj map[string]interface{}) LinkerdServerAuthInfo {
	sa := LinkerdServerAuthInfo{
		Type:     "MeshTLSAuthentication",
		MTLSMode: "STRICT",
	}

	if metadata, ok := obj["metadata"].(map[string]interface{}); ok {
		sa.Name, _ = metadata["name"].(string)
		sa.Namespace, _ = metadata["namespace"].(string)
	}

	if spec, ok := obj["spec"].(map[string]interface{}); ok {
		if identities, ok := spec["identities"].([]interface{}); ok {
			for _, id := range identities {
				if idStr, ok := id.(string); ok {
					sa.Identities = append(sa.Identities, idStr)
				}
			}
		}

		if identityRefs, ok := spec["identityRefs"].([]interface{}); ok {
			for _, ref := range identityRefs {
				if refMap, ok := ref.(map[string]interface{}); ok {
					if name, ok := refMap["name"].(string); ok {
						sa.Identities = append(sa.Identities, name)
					}
				}
			}
		}
	}

	return sa
}

// ============================================================================
// Cilium Service Mesh Analysis
// ============================================================================

func analyzeCiliumMesh(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) CiliumMeshInfo {
	info := CiliumMeshInfo{}

	// Check for Cilium with service mesh features
	namespaces := []string{"kube-system", "cilium"}
	for _, ns := range namespaces {
		daemonSets, err := clientset.AppsV1().DaemonSets(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, ds := range daemonSets.Items {
			if strings.Contains(strings.ToLower(ds.Name), "cilium") && !strings.Contains(strings.ToLower(ds.Name), "operator") {
				info.Name = "Cilium"
				info.Namespace = ns
				info.Status = "active"

				// Check for service mesh features
				for _, container := range ds.Spec.Template.Spec.Containers {
					for _, arg := range container.Args {
						if strings.Contains(arg, "enable-envoy-config") || strings.Contains(arg, "proxy-prometheus-port") {
							info.EnvoyEnabled = true
						}
					}
					for _, env := range container.Env {
						if env.Name == "CILIUM_ENABLE_ENVOY_CONFIG" && env.Value == "true" {
							info.EnvoyEnabled = true
						}
					}
				}
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

	// Check for CiliumNetworkPolicy with TLS termination
	ciliumPolicyGVR := schema.GroupVersionResource{
		Group:    "cilium.io",
		Version:  "v2",
		Resource: "ciliumnetworkpolicies",
	}

	policyList, err := dynClient.Resource(ciliumPolicyGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, policy := range policyList.Items {
			if spec, ok := policy.Object["spec"].(map[string]interface{}); ok {
				if egress, ok := spec["egress"].([]interface{}); ok {
					for _, e := range egress {
						if eMap, ok := e.(map[string]interface{}); ok {
							if _, hasTLS := eMap["tls"]; hasTLS {
								info.MTLSEnabled = true
								info.MTLSMode = "policy-based"
							}
						}
					}
				}
			}
		}
	}

	// Check CiliumClusterwideNetworkPolicy for mesh-wide mTLS
	clusterPolicyGVR := schema.GroupVersionResource{
		Group:    "cilium.io",
		Version:  "v2",
		Resource: "ciliumclusterwidenetworkpolicies",
	}

	clusterPolicyList, err := dynClient.Resource(clusterPolicyGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil && len(clusterPolicyList.Items) > 0 {
		// Check for TLS configurations
		for _, policy := range clusterPolicyList.Items {
			if spec, ok := policy.Object["spec"].(map[string]interface{}); ok {
				if _, hasTLS := spec["enableTLS"]; hasTLS {
					info.MTLSEnabled = true
				}
			}
		}
	}

	// Verify by checking daemonset images
	for _, ns := range namespaces {
		daemonSets, err := clientset.AppsV1().DaemonSets(ns).List(ctx, metav1.ListOptions{})
		if err == nil {
			for _, ds := range daemonSets.Items {
				for _, container := range ds.Spec.Template.Spec.Containers {
					if verifyMeshEngineImage(container.Image, "cilium") {
						info.ImageVerified = true
						break
					}
				}
				if info.ImageVerified {
					break
				}
			}
		}
		if info.ImageVerified {
			break
		}
	}

	return info
}

// ============================================================================
// Consul Connect Analysis
// ============================================================================

func analyzeConsulConnect(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) ConsulConnectInfo {
	info := ConsulConnectInfo{}

	// Check for Consul
	namespaces := []string{"consul", "hashicorp", "kube-system"}
	for _, ns := range namespaces {
		deployments, err := clientset.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, dep := range deployments.Items {
			if strings.Contains(strings.ToLower(dep.Name), "consul") &&
				(strings.Contains(strings.ToLower(dep.Name), "server") || strings.Contains(strings.ToLower(dep.Name), "connect")) {
				info.Name = "Consul Connect"
				info.Namespace = ns
				info.Status = "active"
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

	// Check for Connect injector webhook
	webhooks, err := clientset.AdmissionregistrationV1().MutatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, wh := range webhooks.Items {
			if strings.Contains(strings.ToLower(wh.Name), "consul") &&
				(strings.Contains(strings.ToLower(wh.Name), "connect") || strings.Contains(strings.ToLower(wh.Name), "inject")) {
				info.AutoInjection = true
				info.MTLSEnabled = true // Connect injection implies mTLS
				break
			}
		}
	}

	// Check for ServiceIntentions CRD
	intentionsGVR := schema.GroupVersionResource{
		Group:    "consul.hashicorp.com",
		Version:  "v1alpha1",
		Resource: "serviceintentions",
	}

	intentionsList, err := dynClient.Resource(intentionsGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		info.Intentions = len(intentionsList.Items)
	}

	// Verify by checking deployment images
	for _, ns := range namespaces {
		deployments, err := clientset.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
		if err == nil {
			for _, dep := range deployments.Items {
				for _, container := range dep.Spec.Template.Spec.Containers {
					if verifyMeshEngineImage(container.Image, "consul") {
						info.ImageVerified = true
						break
					}
				}
				if info.ImageVerified {
					break
				}
			}
		}
		if info.ImageVerified {
			break
		}
	}

	return info
}

// ============================================================================
// Open Service Mesh Analysis
// ============================================================================

func analyzeOSM(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) OSMInfo {
	info := OSMInfo{}

	// Check for OSM control plane
	namespaces := []string{"osm-system", "arc-osm-system"}
	for _, ns := range namespaces {
		deployments, err := clientset.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, dep := range deployments.Items {
			if strings.Contains(strings.ToLower(dep.Name), "osm-controller") {
				info.Name = "Open Service Mesh"
				info.Namespace = ns
				info.Status = "active"

				// Check for permissive mode
				for _, container := range dep.Spec.Template.Spec.Containers {
					for _, env := range container.Env {
						if env.Name == "OSM_PERMISSIVE_TRAFFIC_POLICY_MODE" && env.Value == "true" {
							info.PermissiveMode = true
						}
					}
				}
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

	// OSM has mTLS enabled by default
	info.MTLSEnabled = true

	// Verify by checking deployment images
	for _, ns := range namespaces {
		deployments, err := clientset.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
		if err == nil {
			for _, dep := range deployments.Items {
				for _, container := range dep.Spec.Template.Spec.Containers {
					if verifyMeshEngineImage(container.Image, "osm") {
						info.ImageVerified = true
						break
					}
				}
				if info.ImageVerified {
					break
				}
			}
		}
		if info.ImageVerified {
			break
		}
	}

	return info
}

// ============================================================================
// Flomesh Service Mesh (FSM) Analysis
// ============================================================================

func analyzeFSM(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) FSMInfo {
	info := FSMInfo{}

	// Check for FSM control plane using SDK expected namespaces
	namespaces := admission.GetExpectedNamespaces("fsm")
	if len(namespaces) == 0 {
		namespaces = []string{"fsm-system", "kube-system"}
	}

	for _, ns := range namespaces {
		deployments, err := clientset.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, dep := range deployments.Items {
			if strings.Contains(strings.ToLower(dep.Name), "fsm-controller") {
				info.Name = "Flomesh Service Mesh"
				info.Namespace = ns
				info.Status = "active"

				// Check for permissive mode
				for _, container := range dep.Spec.Template.Spec.Containers {
					for _, env := range container.Env {
						if env.Name == "FSM_PERMISSIVE_TRAFFIC_POLICY_MODE" && env.Value == "true" {
							info.PermissiveMode = true
						}
					}
					// Verify by image
					if verifyMeshEngineImage(container.Image, "fsm") {
						info.ImageVerified = true
					}
				}
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

	// FSM has mTLS enabled by default
	info.MTLSEnabled = true

	return info
}

// ============================================================================
// Kuma Mesh Analysis
// ============================================================================

func analyzeKumaMesh(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) KumaMeshInfo {
	info := KumaMeshInfo{}

	// Check for Kuma control plane
	namespaces := []string{"kuma-system", "kong-mesh-system"}
	for _, ns := range namespaces {
		deployments, err := clientset.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, dep := range deployments.Items {
			if strings.Contains(strings.ToLower(dep.Name), "kuma-control-plane") ||
				strings.Contains(strings.ToLower(dep.Name), "kong-mesh") {
				info.Name = "Kuma"
				info.Namespace = ns
				info.Status = "active"
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

	// Check for Mesh CRD with mTLS settings
	meshGVR := schema.GroupVersionResource{
		Group:    "kuma.io",
		Version:  "v1alpha1",
		Resource: "meshes",
	}

	meshList, err := dynClient.Resource(meshGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, mesh := range meshList.Items {
			if spec, ok := mesh.Object["spec"].(map[string]interface{}); ok {
				if mtls, ok := spec["mtls"].(map[string]interface{}); ok {
					if enabled, ok := mtls["enabledBackend"].(string); ok && enabled != "" {
						info.MTLSEnabled = true
					}
					if mode, ok := mtls["mode"].(string); ok {
						info.MTLSMode = mode
					}
				}
			}
		}
	}

	// Verify by checking deployment images
	for _, ns := range namespaces {
		deployments, err := clientset.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
		if err == nil {
			for _, dep := range deployments.Items {
				for _, container := range dep.Spec.Template.Spec.Containers {
					if verifyMeshEngineImage(container.Image, "kuma") {
						info.ImageVerified = true
						break
					}
				}
				if info.ImageVerified {
					break
				}
			}
		}
		if info.ImageVerified {
			break
		}
	}

	return info
}

// ============================================================================
// AWS App Mesh Analysis
// ============================================================================

func analyzeAWSAppMesh(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) AWSAppMeshInfo {
	info := AWSAppMeshInfo{}

	// Image patterns for verification to reduce false positives
	imagePatterns := []string{
		"aws-appmesh-envoy",
		"appmesh-controller",
		"amazon/aws-app-mesh",
		"aws/appmesh",
		"602401143452.dkr.ecr",
		"appmesh-inject",
	}

	// Check for AWS App Mesh Controller deployment
	namespaces := []string{"appmesh-system", "appmesh-controller", "kube-system"}
	for _, ns := range namespaces {
		deployments, err := clientset.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, dep := range deployments.Items {
			if strings.Contains(strings.ToLower(dep.Name), "appmesh") ||
				strings.Contains(strings.ToLower(dep.Name), "app-mesh") {
				info.Name = "AWS App Mesh"
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

				info.TotalPods = int(dep.Status.Replicas)
				info.PodsRunning = int(dep.Status.ReadyReplicas)

				if dep.Status.ReadyReplicas < dep.Status.Replicas {
					info.Status = "degraded"
				}

				if !info.ImageVerified {
					info.Status = "unverified"
				}
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

	// Check for sidecar injector webhook
	webhooks, err := clientset.AdmissionregistrationV1().MutatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, wh := range webhooks.Items {
			if strings.Contains(strings.ToLower(wh.Name), "appmesh") {
				info.AutoInjection = true
				break
			}
		}
	}

	// Check for VirtualNode CRDs
	virtualNodeGVR := schema.GroupVersionResource{
		Group:    "appmesh.k8s.aws",
		Version:  "v1beta2",
		Resource: "virtualnodes",
	}

	vnList, err := dynClient.Resource(virtualNodeGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		info.VirtualNodes = len(vnList.Items)

		// Check for TLS configuration in virtual nodes
		for _, vn := range vnList.Items {
			if spec, ok := vn.Object["spec"].(map[string]interface{}); ok {
				if backendDefaults, ok := spec["backendDefaults"].(map[string]interface{}); ok {
					if clientPolicy, ok := backendDefaults["clientPolicy"].(map[string]interface{}); ok {
						if tls, ok := clientPolicy["tls"].(map[string]interface{}); ok {
							if enforce, ok := tls["enforce"].(bool); ok && enforce {
								info.MTLSEnabled = true
							}
						}
					}
				}
				// Also check listeners for TLS
				if listeners, ok := spec["listeners"].([]interface{}); ok {
					for _, listener := range listeners {
						if listenerMap, ok := listener.(map[string]interface{}); ok {
							if tls, ok := listenerMap["tls"].(map[string]interface{}); ok {
								if mode, ok := tls["mode"].(string); ok && mode == "STRICT" {
									info.MTLSEnabled = true
								}
							}
						}
					}
				}
			}
		}
	}

	// Check for VirtualService CRDs
	virtualServiceGVR := schema.GroupVersionResource{
		Group:    "appmesh.k8s.aws",
		Version:  "v1beta2",
		Resource: "virtualservices",
	}

	vsList, err := dynClient.Resource(virtualServiceGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		info.VirtualServices = len(vsList.Items)
	}

	return info
}

// ============================================================================
// Injection Status Analysis
// ============================================================================

func analyzeInjectionStatus(ctx context.Context, clientset kubernetes.Interface,
	istio IstioInfo, linkerd LinkerdInfo, cilium CiliumMeshInfo, consul ConsulConnectInfo, awsAppMesh AWSAppMeshInfo) []InjectionStatus {

	var status []InjectionStatus

	for _, ns := range globals.K8sNamespaces {
		is := InjectionStatus{
			Namespace: ns,
		}

		// Get namespace labels
		namespace, err := clientset.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{})
		if err != nil {
			continue
		}

		// Check for Istio injection
		if istio.Name != "" {
			if label, ok := namespace.Labels["istio-injection"]; ok && label == "enabled" {
				is.MeshProvider = "Istio"
				is.InjectionEnabled = true
				is.InjectionLabel = "istio-injection=enabled"
			} else if label, ok := namespace.Labels["istio.io/rev"]; ok {
				is.MeshProvider = "Istio"
				is.InjectionEnabled = true
				is.InjectionLabel = fmt.Sprintf("istio.io/rev=%s", label)
			}
		}

		// Check for Linkerd injection
		if linkerd.Name != "" && is.MeshProvider == "" {
			if label, ok := namespace.Labels["linkerd.io/inject"]; ok && label == "enabled" {
				is.MeshProvider = "Linkerd"
				is.InjectionEnabled = true
				is.InjectionLabel = "linkerd.io/inject=enabled"
			}
		}

		// Check for Consul Connect injection
		if consul.Name != "" && is.MeshProvider == "" {
			if label, ok := namespace.Labels["connect-inject"]; ok && label == "enabled" {
				is.MeshProvider = "Consul"
				is.InjectionEnabled = true
				is.InjectionLabel = "connect-inject=enabled"
			}
		}

		// Check for AWS App Mesh injection
		if awsAppMesh.Name != "" && is.MeshProvider == "" {
			if label, ok := namespace.Labels["appmesh.k8s.aws/sidecarInjectorWebhook"]; ok && label == "enabled" {
				is.MeshProvider = "AWS App Mesh"
				is.InjectionEnabled = true
				is.InjectionLabel = "appmesh.k8s.aws/sidecarInjectorWebhook=enabled"
			}
		}

		// Count pods with/without sidecar
		pods, err := clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		is.TotalPods = len(pods.Items)
		for _, pod := range pods.Items {
			hasSidecar := false

			// Check for Istio sidecar
			for _, container := range pod.Spec.Containers {
				if container.Name == "istio-proxy" || container.Name == "envoy" {
					hasSidecar = true
					if is.MeshProvider == "" {
						is.MeshProvider = "Istio"
					}
					break
				}
			}

			// Check for Linkerd sidecar
			if !hasSidecar {
				for _, container := range pod.Spec.Containers {
					if container.Name == "linkerd-proxy" {
						hasSidecar = true
						if is.MeshProvider == "" {
							is.MeshProvider = "Linkerd"
						}
						break
					}
				}
			}

			// Check for Consul sidecar
			if !hasSidecar {
				for _, container := range pod.Spec.Containers {
					if strings.Contains(container.Name, "consul") && strings.Contains(container.Name, "connect") {
						hasSidecar = true
						if is.MeshProvider == "" {
							is.MeshProvider = "Consul"
						}
						break
					}
					if container.Name == "envoy-sidecar" {
						hasSidecar = true
						if is.MeshProvider == "" {
							is.MeshProvider = "Consul"
						}
						break
					}
				}
			}

			// Check for AWS App Mesh sidecar (envoy)
			if !hasSidecar {
				for _, container := range pod.Spec.Containers {
					if container.Name == "envoy" && strings.Contains(strings.ToLower(container.Image), "aws-appmesh-envoy") {
						hasSidecar = true
						if is.MeshProvider == "" {
							is.MeshProvider = "AWS App Mesh"
						}
						break
					}
				}
			}

			if hasSidecar {
				is.PodsWithSidecar++
			} else {
				// Skip system pods
				if pod.Status.Phase != corev1.PodRunning {
					continue
				}
				is.PodsWithoutSidecar++
			}
		}

		// Calculate coverage
		if is.TotalPods > 0 {
			is.CoveragePercent = float64(is.PodsWithSidecar) / float64(is.TotalPods) * 100
		}

		// Set default mesh provider
		if is.MeshProvider == "" {
			is.MeshProvider = "-"
		}

		status = append(status, is)
	}

	return status
}

// ============================================================================
// Build Findings
// ============================================================================

func buildMeshAdmissionFindings(
	istio IstioInfo, istioPeerAuth []IstioPeerAuthInfo, istioReqAuth []IstioRequestAuthInfo,
	linkerd LinkerdInfo, linkerdAuth []LinkerdServerAuthInfo,
	cilium CiliumMeshInfo, consul ConsulConnectInfo,
	osm OSMInfo, kuma KumaMeshInfo,
	awsAppMesh AWSAppMeshInfo,
	injectionStatus []InjectionStatus) []MeshAdmissionFinding {

	var findings []MeshAdmissionFinding

	// Build namespace -> mTLS mode map from PeerAuthentication
	nsMTLS := make(map[string]string)
	// Count PeerAuth policies per namespace
	nsPeerAuth := make(map[string]int)
	for _, pa := range istioPeerAuth {
		nsPeerAuth[pa.Namespace]++
		if pa.Scope == "NAMESPACE" || pa.Scope == "MESH" {
			ns := pa.Namespace
			if pa.Scope == "MESH" {
				// Apply to all namespaces
				for _, n := range globals.K8sNamespaces {
					if _, ok := nsMTLS[n]; !ok {
						nsMTLS[n] = pa.MTLSMode
					}
				}
			} else {
				nsMTLS[ns] = pa.MTLSMode
			}
		}
	}

	// Count JWT policies per namespace
	nsJWT := make(map[string]int)
	// Count RequestAuth policies per namespace
	nsReqAuth := make(map[string]int)
	for _, ra := range istioReqAuth {
		nsJWT[ra.Namespace] += ra.JWTRules
		nsReqAuth[ra.Namespace]++
	}

	// Count Linkerd auth policies per namespace
	nsLinkerdAuth := make(map[string]int)
	for _, la := range linkerdAuth {
		nsLinkerdAuth[la.Namespace]++
	}

	// Build findings from injection status
	for _, is := range injectionStatus {
		finding := MeshAdmissionFinding{
			Namespace:          is.Namespace,
			MeshProvider:       is.MeshProvider,
			InjectionEnabled:   is.InjectionEnabled,
			InjectionLabel:     is.InjectionLabel,
			PodsWithSidecar:    is.PodsWithSidecar,
			PodsWithoutSidecar: is.PodsWithoutSidecar,
			TotalPods:          is.TotalPods,
		}

		// Set mTLS status based on provider
		switch is.MeshProvider {
		case "Istio":
			if mode, ok := nsMTLS[is.Namespace]; ok {
				finding.MTLSMode = mode
			} else {
				finding.MTLSMode = istio.GlobalMTLSMode
			}
			finding.MTLSEnforced = finding.MTLSMode == "STRICT"
			finding.JWTPolicies = nsJWT[is.Namespace]
			finding.HasJWTAuth = finding.JWTPolicies > 0
			// Count total auth policies (PeerAuth + RequestAuth)
			finding.AuthPolicies = nsPeerAuth[is.Namespace] + nsReqAuth[is.Namespace]

		case "Linkerd":
			finding.MTLSMode = "STRICT" // Linkerd always uses mTLS
			finding.MTLSEnforced = linkerd.MTLSEnabled
			// Count Linkerd auth policies
			finding.AuthPolicies = nsLinkerdAuth[is.Namespace]

		case "Consul":
			finding.MTLSMode = "STRICT" // Connect uses mTLS
			finding.MTLSEnforced = consul.MTLSEnabled
			// Consul intentions are counted globally, not per namespace
			finding.AuthPolicies = consul.Intentions

		case "AWS App Mesh":
			if awsAppMesh.MTLSEnabled {
				finding.MTLSMode = "STRICT"
			} else {
				finding.MTLSMode = "PERMISSIVE"
			}
			finding.MTLSEnforced = awsAppMesh.MTLSEnabled

		default:
			finding.MTLSMode = "-"
		}

		// Calculate security issues
		if finding.MeshProvider == "-" {
			finding.SecurityIssues = append(finding.SecurityIssues, "No service mesh")
		} else if !finding.MTLSEnforced {
			finding.SecurityIssues = append(finding.SecurityIssues, "mTLS not enforced")
		} else if finding.PodsWithoutSidecar > 0 {
			finding.SecurityIssues = append(finding.SecurityIssues, fmt.Sprintf("%d pods without sidecar", finding.PodsWithoutSidecar))
		}

		if finding.MTLSMode == "PERMISSIVE" {
			finding.BypassVectors = append(finding.BypassVectors, "Plaintext connections allowed")
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
// Policy Conversion Functions
// ============================================================================

// istioPeerAuthToPolicy converts IstioPeerAuthInfo to MeshEnumeratedPolicy
func istioPeerAuthToPolicy(pa IstioPeerAuthInfo) MeshEnumeratedPolicy {
	details := fmt.Sprintf("mode=%s", pa.MTLSMode)
	if pa.Selector != "" {
		details += fmt.Sprintf(", selector=%s", pa.Selector)
	}
	if len(pa.PortMTLS) > 0 {
		var ports []string
		for port, mode := range pa.PortMTLS {
			ports = append(ports, fmt.Sprintf("%d:%s", port, mode))
		}
		details += fmt.Sprintf(", ports=[%s]", strings.Join(ports, ","))
	}
	return MeshEnumeratedPolicy{
		Namespace: pa.Namespace,
		Tool:      "Istio",
		Name:      pa.Name,
		Scope:     pa.Scope,
		Type:      "PeerAuthentication",
		Details:   details,
	}
}

// istioRequestAuthToPolicy converts IstioRequestAuthInfo to MeshEnumeratedPolicy
func istioRequestAuthToPolicy(ra IstioRequestAuthInfo) MeshEnumeratedPolicy {
	details := fmt.Sprintf("%d JWT rules", ra.JWTRules)
	if len(ra.Issuers) > 0 {
		if len(ra.Issuers) > 2 {
			details += fmt.Sprintf(", issuers=%s...", strings.Join(ra.Issuers[:2], ","))
		} else {
			details += fmt.Sprintf(", issuers=%s", strings.Join(ra.Issuers, ","))
		}
	}
	scope := "NAMESPACE"
	if ra.Selector == "" {
		scope = "WORKLOAD"
	}
	return MeshEnumeratedPolicy{
		Namespace: ra.Namespace,
		Tool:      "Istio",
		Name:      ra.Name,
		Scope:     scope,
		Type:      "RequestAuthentication",
		Details:   details,
	}
}

// linkerdAuthToPolicy converts LinkerdServerAuthInfo to MeshEnumeratedPolicy
func linkerdAuthToPolicy(la LinkerdServerAuthInfo) MeshEnumeratedPolicy {
	details := fmt.Sprintf("mode=%s", la.MTLSMode)
	if len(la.Identities) > 0 {
		if len(la.Identities) > 2 {
			details += fmt.Sprintf(", identities=%s...", strings.Join(la.Identities[:2], ","))
		} else {
			details += fmt.Sprintf(", identities=%s", strings.Join(la.Identities, ","))
		}
	}
	if len(la.Networks) > 0 {
		details += fmt.Sprintf(", networks=%s", strings.Join(la.Networks, ","))
	}
	return MeshEnumeratedPolicy{
		Namespace: la.Namespace,
		Tool:      "Linkerd",
		Name:      la.Name,
		Scope:     "NAMESPACE",
		Type:      la.Type,
		Details:   details,
	}
}

// ============================================================================
// Loot Generation
// ============================================================================

func generateMeshAdmissionLoot(loot *shared.LootBuilder,
	findings []MeshAdmissionFinding,
	istio IstioInfo, istioPeerAuth []IstioPeerAuthInfo, istioReqAuth []IstioRequestAuthInfo,
	linkerd LinkerdInfo, linkerdAuth []LinkerdServerAuthInfo,
	cilium CiliumMeshInfo, consul ConsulConnectInfo,
	osm OSMInfo, fsm FSMInfo, kuma KumaMeshInfo,
	awsAppMesh AWSAppMeshInfo,
	injectionStatus []InjectionStatus) {

	s := loot.Section("Mesh-Admission-Commands")
	s.Add("# Service Mesh Security Summary")
	s.Add("#")

	// Detected meshes with status
	type toolStatus struct {
		name   string
		status string
		detail string
	}
	var detected []toolStatus

	if istio.Name != "" {
		detail := fmt.Sprintf("version: %s, global mTLS: %s", istio.Version, istio.GlobalMTLSMode)
		detected = append(detected, toolStatus{"Istio", istio.Status, detail})
	}
	if linkerd.Name != "" {
		detail := fmt.Sprintf("mTLS: %v", linkerd.MTLSEnabled)
		detected = append(detected, toolStatus{"Linkerd", linkerd.Status, detail})
	}
	if cilium.Name != "" && cilium.EnvoyEnabled {
		detail := fmt.Sprintf("mTLS: %v", cilium.MTLSEnabled)
		detected = append(detected, toolStatus{"Cilium Service Mesh", cilium.Status, detail})
	}
	if consul.Name != "" {
		detail := fmt.Sprintf("mTLS: %v", consul.MTLSEnabled)
		detected = append(detected, toolStatus{"Consul Connect", consul.Status, detail})
	}
	if osm.Name != "" {
		detail := ""
		if osm.PermissiveMode {
			detail = "PERMISSIVE MODE"
		}
		detected = append(detected, toolStatus{"Open Service Mesh", osm.Status, detail})
	}
	if fsm.Name != "" {
		detail := ""
		if fsm.PermissiveMode {
			detail = "PERMISSIVE MODE"
		}
		detected = append(detected, toolStatus{"Flomesh Service Mesh", fsm.Status, detail})
	}
	if kuma.Name != "" {
		detail := fmt.Sprintf("mTLS: %v, mode: %s", kuma.MTLSEnabled, kuma.MTLSMode)
		detected = append(detected, toolStatus{"Kuma Mesh", kuma.Status, detail})
	}
	if awsAppMesh.Name != "" {
		status := awsAppMesh.Status
		if awsAppMesh.ImageVerified {
			status += " (verified)"
		}
		detail := fmt.Sprintf("mTLS: %v, nodes: %d, services: %d", awsAppMesh.MTLSEnabled, awsAppMesh.VirtualNodes, awsAppMesh.VirtualServices)
		detected = append(detected, toolStatus{"AWS App Mesh", status, detail})
	}

	if len(detected) == 0 {
		s.Add("# WARNING: No service mesh detected")
		s.Add("# Service-to-service communication is NOT encrypted")
	} else {
		s.Add(fmt.Sprintf("# Detected Tools: %d", len(detected)))
		for _, t := range detected {
			s.Add(fmt.Sprintf("#   %s: %s (%s)", t.name, strings.ToUpper(t.status), t.detail))
		}
	}

	s.Add("#")

	// mTLS Coverage
	strictCount := 0
	permissiveCount := 0
	noMeshCount := 0

	for _, f := range findings {
		if f.MeshProvider == "-" {
			noMeshCount++
		} else if f.MTLSEnforced {
			strictCount++
		} else {
			permissiveCount++
		}
	}

	s.Add(fmt.Sprintf("# Namespaces with STRICT mTLS: %d", strictCount))
	s.Add(fmt.Sprintf("# Namespaces with PERMISSIVE mTLS: %d", permissiveCount))
	s.Add(fmt.Sprintf("# Namespaces without mesh: %d", noMeshCount))
	s.Add("#")

	// Bypass vectors (only if relevant)
	var bypasses []string

	if istio.GlobalMTLSMode == "PERMISSIVE" {
		bypasses = append(bypasses, "Istio global mTLS is PERMISSIVE - plaintext connections accepted")
	}

	for _, pa := range istioPeerAuth {
		if pa.MTLSMode == "PERMISSIVE" || pa.MTLSMode == "DISABLE" {
			bypasses = append(bypasses, fmt.Sprintf("PeerAuthentication %s/%s: %s mTLS", pa.Namespace, pa.Name, pa.MTLSMode))
		}
	}

	for _, la := range linkerdAuth {
		if la.MTLSMode == "PERMISSIVE" {
			bypasses = append(bypasses, fmt.Sprintf("Linkerd %s %s/%s: allows unauthenticated", la.Type, la.Namespace, la.Name))
		}
	}

	// Pods without sidecar
	for _, is := range injectionStatus {
		if is.PodsWithoutSidecar > 0 && is.MeshProvider != "-" {
			bypasses = append(bypasses, fmt.Sprintf("Namespace %s: %d pods without %s sidecar", is.Namespace, is.PodsWithoutSidecar, is.MeshProvider))
		}
	}

	if len(bypasses) > 0 {
		s.Add("# Bypass Vectors:")
		for _, b := range bypasses {
			s.Addf("#   %s", b)
		}
		s.Add("#")
	}

	// Commands (only for detected tools)
	s.Add("# Commands")
	s.Add("#")

	if istio.Name != "" {
		s.Add("# Check Istio mTLS status:")
		s.Add("istioctl analyze -A")
		s.Add("kubectl get peerauthentication -A")
		s.Add("kubectl get requestauthentication -A")
		s.Add("#")
	}

	if linkerd.Name != "" {
		s.Add("# Check Linkerd mTLS:")
		s.Add("linkerd check")
		s.Add("kubectl get server,serverauthorization -A")
		s.Add("#")
	}

	if istio.Name != "" || linkerd.Name != "" {
		s.Add("# List namespaces with injection enabled:")
		if istio.Name != "" {
			s.Add("kubectl get ns -l istio-injection=enabled")
		}
		if linkerd.Name != "" {
			s.Add("kubectl get ns -l linkerd.io/inject=enabled")
		}
	}
}
