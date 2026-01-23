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
  - Istio PeerAuthentication (mTLS modes)
  - Istio RequestAuthentication (JWT)
  - Istio sidecar injection status
  - Linkerd mTLS and proxy injection
  - Cilium Service Mesh mTLS
  - Consul Connect
  - Open Service Mesh (OSM)
  - Kuma/Kong Mesh
  - Coverage gap analysis
  - mTLS bypass vectors

  cloudfox kubernetes mesh-admission`,
	Run: ListMeshAdmission,
}

type MeshAdmissionOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t MeshAdmissionOutput) TableFiles() []internal.TableFile { return t.Table }
func (t MeshAdmissionOutput) LootFiles() []internal.LootFile   { return t.Loot }

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

	// Risk Analysis
	RiskLevel      string
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
	GlobalMTLSMode    string
	AutoInjection     bool
	BypassRisk        string
	ImageVerified     bool // True if Istio control plane image was verified
}

// IstioPeerAuthInfo represents an Istio PeerAuthentication policy
type IstioPeerAuthInfo struct {
	Name       string
	Namespace  string
	Scope      string // MESH, NAMESPACE, WORKLOAD
	MTLSMode   string // STRICT, PERMISSIVE, DISABLE, UNSET
	Selector   string
	PortMTLS   map[int]string // port-specific mTLS settings
	BypassRisk string
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
	BypassRisk     string
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
	BypassRisk     string
	ImageVerified  bool // True if Linkerd control plane image was verified
}

// LinkerdServerAuthInfo represents Linkerd ServerAuthorization/MeshTLSAuthentication
type LinkerdServerAuthInfo struct {
	Name           string
	Namespace      string
	Type           string // Server, ServerAuthorization, MeshTLSAuthentication
	MTLSMode       string
	Identities     []string
	Networks       []string
	BypassRisk     string
}

// CiliumMeshInfo represents Cilium Service Mesh status
type CiliumMeshInfo struct {
	Name          string
	Namespace     string
	Status        string
	MTLSEnabled   bool
	MTLSMode      string
	EnvoyEnabled  bool
	BypassRisk    string
	ImageVerified bool // True if Cilium agent image was verified
}

// ConsulConnectInfo represents Consul Connect status
type ConsulConnectInfo struct {
	Name          string
	Namespace     string
	Status        string
	MTLSEnabled   bool
	AutoInjection bool
	Intentions    int
	BypassRisk    string
	ImageVerified bool // True if Consul Connect image was verified
}

// OSMInfo represents Open Service Mesh status
type OSMInfo struct {
	Name           string
	Namespace      string
	Status         string
	MTLSEnabled    bool
	PermissiveMode bool
	BypassRisk     string
	ImageVerified  bool // True if OSM controller image was verified
}

// FSMInfo represents Flomesh Service Mesh status
type FSMInfo struct {
	Name           string
	Namespace      string
	Status         string
	MTLSEnabled    bool
	PermissiveMode bool
	BypassRisk     string
	ImageVerified  bool // True if FSM controller image was verified
}

// KumaMeshInfo represents Kuma/Kong Mesh status
type KumaMeshInfo struct {
	Name          string
	Namespace     string
	Status        string
	MTLSEnabled   bool
	MTLSMode      string
	BypassRisk    string
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
	VirtualNodes   int
	VirtualServices int
	ImageVerified  bool
	BypassRisk     string
}

// InjectionStatus represents sidecar injection status for a namespace
type InjectionStatus struct {
	Namespace          string
	MeshProvider       string
	InjectionEnabled   bool
	InjectionLabel     string
	PodsWithSidecar    int
	PodsWithoutSidecar int
	TotalPods          int
	CoveragePercent    float64
	BypassRisk         string
}

// verifyMeshEngineImage checks if a container image matches known patterns for a mesh engine
// Now uses the shared admission SDK for centralized engine detection
func verifyMeshEngineImage(image string, engine string) bool {
	return VerifyControllerImage(image, engine)
}

func ListMeshAdmission(cmd *cobra.Command, args []string) {
	ctx, cancel := shared.ContextWithCancel()
	defer cancel()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDir, _ := parentCmd.PersistentFlags().GetString("outdir")

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
		"Risk Level",
		"Issues",
	}

	istioHeader := []string{
		"Namespace",
		"Version",
		"Status",
		"Global mTLS",
		"Auto Injection",
		"Bypass Risk",
	}

	peerAuthHeader := []string{
		"Name",
		"Namespace",
		"Scope",
		"mTLS Mode",
		"Selector",
		"Port-Specific",
		"Bypass Risk",
	}

	reqAuthHeader := []string{
		"Name",
		"Namespace",
		"Selector",
		"JWT Rules",
		"Issuers",
		"Audiences",
		"Bypass Risk",
	}

	linkerdHeader := []string{
		"Namespace",
		"Version",
		"Status",
		"mTLS Enabled",
		"Auto Injection",
		"Identity Issuer",
		"Bypass Risk",
	}

	linkerdAuthHeader := []string{
		"Name",
		"Namespace",
		"Type",
		"mTLS Mode",
		"Identities",
		"Networks",
		"Bypass Risk",
	}

	injectionHeader := []string{
		"Namespace",
		"Mesh Provider",
		"Injection Enabled",
		"Label",
		"With Sidecar",
		"Without Sidecar",
		"Coverage %",
		"Bypass Risk",
	}

	var summaryRows [][]string
	var istioRows [][]string
	var peerAuthRows [][]string
	var reqAuthRows [][]string
	var linkerdRows [][]string
	var linkerdAuthRows [][]string
	var injectionRows [][]string

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
			finding.RiskLevel,
			issues,
		})
	}

	// Build Istio rows
	if istio.Name != "" {
		istioRows = append(istioRows, []string{
			istio.Namespace,
			istio.Version,
			istio.Status,
			istio.GlobalMTLSMode,
			fmt.Sprintf("%v", istio.AutoInjection),
			istio.BypassRisk,
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

		peerAuthRows = append(peerAuthRows, []string{
			pa.Name,
			pa.Namespace,
			pa.Scope,
			pa.MTLSMode,
			selector,
			portMTLS,
			pa.BypassRisk,
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

		reqAuthRows = append(reqAuthRows, []string{
			ra.Name,
			ra.Namespace,
			selector,
			fmt.Sprintf("%d", ra.JWTRules),
			issuers,
			audiences,
			ra.BypassRisk,
		})
	}

	// Build Linkerd rows
	if linkerd.Name != "" {
		linkerdRows = append(linkerdRows, []string{
			linkerd.Namespace,
			linkerd.Version,
			linkerd.Status,
			fmt.Sprintf("%v", linkerd.MTLSEnabled),
			fmt.Sprintf("%v", linkerd.AutoInjection),
			linkerd.IdentityIssuer,
			linkerd.BypassRisk,
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

		linkerdAuthRows = append(linkerdAuthRows, []string{
			la.Name,
			la.Namespace,
			la.Type,
			la.MTLSMode,
			identities,
			networks,
			la.BypassRisk,
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

		injectionRows = append(injectionRows, []string{
			is.Namespace,
			is.MeshProvider,
			enabled,
			label,
			fmt.Sprintf("%d", is.PodsWithSidecar),
			fmt.Sprintf("%d", is.PodsWithoutSidecar),
			fmt.Sprintf("%.1f%%", is.CoveragePercent),
			is.BypassRisk,
		})
	}

	// Generate loot
	generateMeshAdmissionLoot(loot, findings, istio, istioPeerAuth, istioReqAuth, linkerd, linkerdAuth, ciliumMesh, consul, osm, fsm, kuma, awsAppMesh, injectionStatus)

	// Build output tables
	var tables []internal.TableFile

	tables = append(tables, internal.TableFile{
		Name:   "Mesh-Admission-Summary",
		Header: summaryHeader,
		Body:   summaryRows,
	})

	if len(istioRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Mesh-Admission-Istio",
			Header: istioHeader,
			Body:   istioRows,
		})
	}

	if len(peerAuthRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Mesh-Admission-Istio-PeerAuth",
			Header: peerAuthHeader,
			Body:   peerAuthRows,
		})
	}

	if len(reqAuthRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Mesh-Admission-Istio-RequestAuth",
			Header: reqAuthHeader,
			Body:   reqAuthRows,
		})
	}

	if len(linkerdRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Mesh-Admission-Linkerd",
			Header: linkerdHeader,
			Body:   linkerdRows,
		})
	}

	if len(linkerdAuthRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Mesh-Admission-Linkerd-Auth",
			Header: linkerdAuthHeader,
			Body:   linkerdAuthRows,
		})
	}

	if len(injectionRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Mesh-Admission-Injection-Status",
			Header: injectionHeader,
			Body:   injectionRows,
		})
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
					info.BypassRisk = fmt.Sprintf("Only %d/%d istiod replicas ready", dep.Status.ReadyReplicas, dep.Status.Replicas)
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

	// Assess risk
	if info.GlobalMTLSMode == "PERMISSIVE" {
		info.BypassRisk = "Global mTLS is PERMISSIVE - plaintext allowed"
	} else if info.GlobalMTLSMode == "DISABLE" {
		info.BypassRisk = "Global mTLS is DISABLED - no encryption"
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

	// Assess risk
	switch pa.MTLSMode {
	case "PERMISSIVE":
		pa.BypassRisk = "Allows plaintext connections"
	case "DISABLE":
		pa.BypassRisk = "mTLS disabled"
	case "UNSET":
		pa.BypassRisk = "Inherits parent policy"
	}

	// Check for port-level exceptions
	for port, mode := range pa.PortMTLS {
		if mode == "PERMISSIVE" || mode == "DISABLE" {
			pa.BypassRisk = fmt.Sprintf("Port %d has %s mTLS", port, mode)
			break
		}
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

	if ra.JWTRules == 0 {
		ra.BypassRisk = "No JWT rules defined"
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
					info.BypassRisk = fmt.Sprintf("Only %d/%d control plane replicas ready", dep.Status.ReadyReplicas, dep.Status.Replicas)
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

	if !info.MTLSEnabled {
		info.BypassRisk = "mTLS identity issuer not found"
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
				sa.BypassRisk = "Allows unauthenticated connections"
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

	if !info.MTLSEnabled {
		info.BypassRisk = "Cilium mTLS not configured"
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

	if !info.MTLSEnabled {
		info.BypassRisk = "Connect injection not detected"
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

	if info.PermissiveMode {
		info.BypassRisk = "Permissive traffic policy mode enabled"
	}

	return info
}

// ============================================================================
// Flomesh Service Mesh (FSM) Analysis
// ============================================================================

func analyzeFSM(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) FSMInfo {
	info := FSMInfo{}

	// Check for FSM control plane using SDK expected namespaces
	namespaces := GetExpectedNamespaces("fsm")
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

	if info.PermissiveMode {
		info.BypassRisk = "Permissive traffic policy mode enabled"
	}

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

	if !info.MTLSEnabled {
		info.BypassRisk = "mTLS not enabled in Mesh configuration"
	} else if info.MTLSMode == "PERMISSIVE" {
		info.BypassRisk = "mTLS in permissive mode - plaintext allowed"
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
					info.BypassRisk = fmt.Sprintf("Only %d/%d controller replicas ready", dep.Status.ReadyReplicas, dep.Status.Replicas)
				}

				if !info.ImageVerified {
					info.Status = "unverified"
					if info.BypassRisk != "" {
						info.BypassRisk += "; "
					}
					info.BypassRisk += "Detection based on name only - verify manually"
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

	// Assess risk
	if !info.MTLSEnabled {
		if info.BypassRisk != "" {
			info.BypassRisk += "; "
		}
		info.BypassRisk += "TLS not enforced on virtual nodes"
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

		// Assess risk
		if is.MeshProvider == "" {
			is.MeshProvider = "-"
		}
		if is.PodsWithoutSidecar > 0 && is.MeshProvider != "-" {
			is.BypassRisk = fmt.Sprintf("%d pods without mesh sidecar", is.PodsWithoutSidecar)
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

		// Calculate risk
		if finding.MeshProvider == "-" {
			finding.RiskLevel = "HIGH"
			finding.SecurityIssues = append(finding.SecurityIssues, "No service mesh")
		} else if !finding.MTLSEnforced {
			finding.RiskLevel = "MEDIUM"
			finding.SecurityIssues = append(finding.SecurityIssues, "mTLS not enforced")
		} else if finding.PodsWithoutSidecar > 0 {
			finding.RiskLevel = "MEDIUM"
			finding.SecurityIssues = append(finding.SecurityIssues, fmt.Sprintf("%d pods without sidecar", finding.PodsWithoutSidecar))
		} else {
			finding.RiskLevel = "LOW"
		}

		if finding.MTLSMode == "PERMISSIVE" {
			finding.BypassVectors = append(finding.BypassVectors, "Plaintext connections allowed")
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

func generateMeshAdmissionLoot(loot *shared.LootBuilder,
	findings []MeshAdmissionFinding,
	istio IstioInfo, istioPeerAuth []IstioPeerAuthInfo, istioReqAuth []IstioRequestAuthInfo,
	linkerd LinkerdInfo, linkerdAuth []LinkerdServerAuthInfo,
	cilium CiliumMeshInfo, consul ConsulConnectInfo,
	osm OSMInfo, fsm FSMInfo, kuma KumaMeshInfo,
	awsAppMesh AWSAppMeshInfo,
	injectionStatus []InjectionStatus) {

	// Summary
	loot.Section("Summary").Add("# Service Mesh Security Summary")
	loot.Section("Summary").Add("#")

	// Detected meshes
	meshCount := 0
	if istio.Name != "" {
		meshCount++
		loot.Section("Summary").Add(fmt.Sprintf("# Istio: %s (version: %s, global mTLS: %s)", istio.Status, istio.Version, istio.GlobalMTLSMode))
	}
	if linkerd.Name != "" {
		meshCount++
		loot.Section("Summary").Add(fmt.Sprintf("# Linkerd: %s (mTLS: %v)", linkerd.Status, linkerd.MTLSEnabled))
	}
	if cilium.Name != "" && cilium.EnvoyEnabled {
		meshCount++
		loot.Section("Summary").Add(fmt.Sprintf("# Cilium Service Mesh: %s (mTLS: %v)", cilium.Status, cilium.MTLSEnabled))
	}
	if consul.Name != "" {
		meshCount++
		loot.Section("Summary").Add(fmt.Sprintf("# Consul Connect: %s (mTLS: %v)", consul.Status, consul.MTLSEnabled))
	}
	if osm.Name != "" {
		meshCount++
		permissive := ""
		if osm.PermissiveMode {
			permissive = " (PERMISSIVE MODE)"
		}
		loot.Section("Summary").Add(fmt.Sprintf("# Open Service Mesh: %s%s", osm.Status, permissive))
	}
	if fsm.Name != "" {
		meshCount++
		permissive := ""
		if fsm.PermissiveMode {
			permissive = " (PERMISSIVE MODE)"
		}
		loot.Section("Summary").Add(fmt.Sprintf("# Flomesh Service Mesh: %s%s", fsm.Status, permissive))
	}
	if kuma.Name != "" {
		meshCount++
		loot.Section("Summary").Add(fmt.Sprintf("# Kuma Mesh: %s (mTLS: %v, mode: %s)", kuma.Status, kuma.MTLSEnabled, kuma.MTLSMode))
	}
	if awsAppMesh.Name != "" {
		meshCount++
		status := awsAppMesh.Status
		if awsAppMesh.ImageVerified {
			status += " (verified)"
		}
		loot.Section("Summary").Add(fmt.Sprintf("# AWS App Mesh: %s (mTLS: %v, nodes: %d, services: %d)", status, awsAppMesh.MTLSEnabled, awsAppMesh.VirtualNodes, awsAppMesh.VirtualServices))
	}

	if meshCount == 0 {
		loot.Section("Summary").Add("#")
		loot.Section("Summary").Add("# WARNING: No service mesh detected!")
		loot.Section("Summary").Add("# Service-to-service communication is NOT encrypted")
	}

	loot.Section("Summary").Add("#")

	// mTLS Analysis
	loot.Section("MTLSAnalysis").Add("# mTLS Coverage Analysis")
	loot.Section("MTLSAnalysis").Add("#")

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

	loot.Section("MTLSAnalysis").Add(fmt.Sprintf("# Namespaces with STRICT mTLS: %d", strictCount))
	loot.Section("MTLSAnalysis").Add(fmt.Sprintf("# Namespaces with PERMISSIVE mTLS: %d", permissiveCount))
	loot.Section("MTLSAnalysis").Add(fmt.Sprintf("# Namespaces without mesh: %d", noMeshCount))
	loot.Section("MTLSAnalysis").Add("#")

	// Bypass vectors
	loot.Section("BypassVectors").Add("# mTLS Bypass Vectors")
	loot.Section("BypassVectors").Add("#")

	if istio.GlobalMTLSMode == "PERMISSIVE" {
		loot.Section("BypassVectors").Add("# - Istio global mTLS is PERMISSIVE - plaintext connections accepted")
	}

	for _, pa := range istioPeerAuth {
		if pa.MTLSMode == "PERMISSIVE" || pa.MTLSMode == "DISABLE" {
			loot.Section("BypassVectors").Add(fmt.Sprintf("# - PeerAuthentication %s/%s: %s mTLS", pa.Namespace, pa.Name, pa.MTLSMode))
		}
	}

	for _, la := range linkerdAuth {
		if la.BypassRisk != "" {
			loot.Section("BypassVectors").Add(fmt.Sprintf("# - Linkerd %s %s/%s: %s", la.Type, la.Namespace, la.Name, la.BypassRisk))
		}
	}

	// Pods without sidecar
	for _, is := range injectionStatus {
		if is.PodsWithoutSidecar > 0 && is.MeshProvider != "-" {
			loot.Section("BypassVectors").Add(fmt.Sprintf("# - Namespace %s: %d pods without %s sidecar", is.Namespace, is.PodsWithoutSidecar, is.MeshProvider))
		}
	}

	loot.Section("BypassVectors").Add("#")

	// Recommendations
	loot.Section("Recommendations").Add("# Recommendations")
	loot.Section("Recommendations").Add("#")

	if meshCount == 0 {
		loot.Section("Recommendations").Add("# 1. Deploy a service mesh for mTLS between services")
		loot.Section("Recommendations").Add("#    Istio: istioctl install --set profile=default")
		loot.Section("Recommendations").Add("#    Linkerd: linkerd install | kubectl apply -f -")
	}

	if istio.GlobalMTLSMode == "PERMISSIVE" {
		loot.Section("Recommendations").Add("# 2. Enable STRICT mTLS mode for Istio:")
		loot.Section("Recommendations").Add("#    kubectl apply -f - <<EOF")
		loot.Section("Recommendations").Add("#    apiVersion: security.istio.io/v1")
		loot.Section("Recommendations").Add("#    kind: PeerAuthentication")
		loot.Section("Recommendations").Add("#    metadata:")
		loot.Section("Recommendations").Add("#      name: default")
		loot.Section("Recommendations").Add("#      namespace: istio-system")
		loot.Section("Recommendations").Add("#    spec:")
		loot.Section("Recommendations").Add("#      mtls:")
		loot.Section("Recommendations").Add("#        mode: STRICT")
		loot.Section("Recommendations").Add("#    EOF")
	}

	// Commands
	loot.Section("Commands").Add("# Useful Commands")
	loot.Section("Commands").Add("#")
	if istio.Name != "" {
		loot.Section("Commands").Add("# Check Istio mTLS status:")
		loot.Section("Commands").Add("istioctl analyze -A")
		loot.Section("Commands").Add("kubectl get peerauthentication -A")
		loot.Section("Commands").Add("kubectl get requestauthentication -A")
		loot.Section("Commands").Add("#")
	}
	if linkerd.Name != "" {
		loot.Section("Commands").Add("# Check Linkerd mTLS:")
		loot.Section("Commands").Add("linkerd check")
		loot.Section("Commands").Add("kubectl get server,serverauthorization -A")
		loot.Section("Commands").Add("#")
	}
	loot.Section("Commands").Add("# List namespaces with injection enabled:")
	loot.Section("Commands").Add("kubectl get ns -l istio-injection=enabled")
	loot.Section("Commands").Add("kubectl get ns -l linkerd.io/inject=enabled")
}
