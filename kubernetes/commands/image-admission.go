package commands

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/policyinsights/armpolicyinsights"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/BishopFox/cloudfox/kubernetes/shared"
	"github.com/BishopFox/cloudfox/kubernetes/shared/admission"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/signer"
	"github.com/spf13/cobra"
	binaryauthorization "google.golang.org/api/binaryauthorization/v1"
	"google.golang.org/api/option"
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

Image Signature Verification:
  - Cosign, Notary, Sigstore policy-controller
  - Portieris (IBM) - Image signature verification
  - Connaisseur - Signature verification
  - Ratify (Microsoft) - Artifact verification
  - ImagePolicyWebhook - Built-in Kubernetes

Policy Engine Image Rules:
  - Kyverno image verification policies
  - Gatekeeper/OPA image constraints
  - Registry allowlists/denylists

In-Cluster Cloud Detection (no flags required):
  Detects cloud-specific image admission from in-cluster resources:
  - AWS Signer webhooks, ECR pull-through cache configs
  - GCP Binary Authorization (Kritis) CRDs
  - Azure Defender for Containers webhooks

Cloud Provider API Policies (requires --cloud-provider flag):
  Use --cloud-provider to fetch policies directly from cloud provider APIs.
  This provides comprehensive policy details not available from in-cluster resources.

  GCP (--cloud-provider gcp):
    - Binary Authorization project policy (enforcement mode, default rules)
    - Attestors and their public keys
    - Cluster-specific admission policies
    - Exempt images and patterns
    - Uses GCP credentials with --gcp-project or discovers from cluster

  AWS (--cloud-provider aws):
    - ECR repository scan configurations
    - ECR registry scanning settings
    - AWS Signer signing profiles
    - ECR lifecycle policies affecting image availability
    - Uses AWS credentials from --aws-profile or default credential chain

  Azure (--cloud-provider azure):
    - Azure Policy assignments for AKS image restrictions
    - Azure Defender for Containers configurations
    - ACR quarantine policies
    - Container registry webhooks
    - Uses Azure credentials with --azure-subscription or discovers from cluster

Registry Analysis:
  - Registry type detection (ECR, GCR, ACR, Docker Hub, etc.)
  - Private vs public registry identification
  - Image pull secret analysis

Examples:
  # Basic in-cluster analysis
  cloudfox kubernetes image-admission

  # With detailed image table
  cloudfox kubernetes image-admission --detailed

  # With GCP Binary Authorization policy from API
  cloudfox kubernetes image-admission --cloud-provider gcp --gcp-project my-project

  # With AWS ECR policies from API
  cloudfox kubernetes image-admission --cloud-provider aws --aws-profile myprofile

  # With Azure Policy from API
  cloudfox kubernetes image-admission --cloud-provider azure --azure-subscription sub-id

  # Multiple cloud providers
  cloudfox kubernetes image-admission --cloud-provider gcp,aws,azure --detailed`,
	Run: ListImageAdmission,
}

// init() removed - detailed flag is now a global persistent flag in cli/kubernetes.go

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

// ImageEnumeratedPolicy represents a unified policy entry for the policies table
type ImageEnumeratedPolicy struct {
	Namespace string
	Tool      string
	Name      string
	Scope     string
	Type      string
	Details   string
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

// ImageAdmissionCloudClients holds cloud provider clients for image admission
type ImageAdmissionCloudClients struct {
	// GCP
	GCPBinaryAuthService *binaryauthorization.Service
	GCPProjects          []string

	// AWS
	AWSECRClient    *ecr.Client
	AWSSignerClient *signer.Client
	AWSRegion       string

	// Azure
	AzureCredential        *azidentity.DefaultAzureCredential
	AzurePolicyClient      *armpolicy.AssignmentsClient
	AzurePolicyStateClient *armpolicyinsights.PolicyStatesClient
	AzureSubscriptions     []string
}

// CloudImagePolicy represents an image admission policy from a cloud provider
type CloudImagePolicy struct {
	Provider          string   // gcp, aws, azure
	PolicyType        string   // binary-auth, ecr-scan, signer-profile, azure-policy, etc.
	Name              string
	Scope             string   // project, account, subscription, cluster, repository
	ScopeID           string   // project ID, account ID, subscription ID
	EnforcementMode   string   // enforce, dryrun, audit, disabled
	DefaultAction     string   // allow, deny, require-attestation
	BlocksDeployment  bool     // Does this policy actually block deployment?
	Details           string   // human-readable details
	AttestorsCount    int      // number of attestors (GCP)
	ExemptImages      []string // Bypass patterns (GCP exempt images)
	AllowedRegistries []string // Allowed registries (Azure)
	DeniedRegistries  []string // Denied registries (Azure)
}

// GCPBinaryAuthAttestor represents a GCP Binary Authorization attestor
type GCPBinaryAuthAttestor struct {
	Name        string
	Project     string
	Description string
	KeyCount    int
	KeyAlgorithm string
	UpdateTime  string
}

// AWSECRScanConfig represents ECR repository scan configuration
type AWSECRScanConfig struct {
	RepositoryName  string
	RegistryID      string
	ScanOnPush      bool
	ScanFrequency   string // SCAN_ON_PUSH, CONTINUOUS_SCAN, MANUAL
	ImageCount      int
	LastScanTime    string
	ScanFindings    string // count of findings by severity
}

// AWSSignerProfile represents an AWS Signer signing profile
type AWSSignerProfile struct {
	ProfileName     string
	ProfileVersion  string
	PlatformID      string // Notation-OCI-SHA384-ECDSA
	Status          string
	SignatureValid  string
	Tags            map[string]string
}

// AzureImagePolicy represents an Azure policy related to container images
type AzureImagePolicy struct {
	PolicyName        string
	DisplayName       string
	PolicyType        string // BuiltIn, Custom
	Scope             string
	AssignmentName    string
	EnforcementMode   string
	Effect            string   // Deny, Audit, AuditIfNotExists
	BlocksDeployment  bool     // Does this policy block deployment?
	AllowedRegistries []string // Registries that are allowed
	DeniedRegistries  []string // Registries that are denied
	Parameters        string
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
	return admission.VerifyControllerImage(image, controller)
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
	SourceResource    string   // Kubernetes resource where this policy was found (e.g., "ValidatingWebhookConfiguration/gke-binauthz")
	EnumerateCmd      string   // kubectl command to view the source resource
}

// BlockedImageEntry represents a blocked/denied image/registry entry from policies
// This shows what images are explicitly blacklisted and cannot be deployed
type BlockedImageEntry struct {
	Controller     string   // Which admission controller blocks this
	PolicyName     string   // Name of the policy
	Scope          string   // cluster or namespace
	Namespaces     []string // If namespace-scoped, which namespaces
	BlockedPattern string   // Image pattern/registry blocked (e.g., "docker.io/*", "*:latest")
	Reason         string   // Why it's blocked (e.g., "public registry", "no digest", "blacklisted")
	Effect         string   // What happens (deny, audit, warn)
	SourceResource string   // Kubernetes resource where this policy was found
}

func ListImageAdmission(cmd *cobra.Command, args []string) {
	ctx, cancel := shared.ContextWithCancel()
	defer cancel()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")
	detailed := globals.K8sDetailed

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

	// Check for Conftest image policies
	logger.InfoM("Analyzing Conftest image policies...", K8S_IMAGE_ADMISSION_MODULE_NAME)
	conftestController, conftestPolicies := analyzeConftestImagePolicies(ctx, clientset, dynClient)
	if conftestController.Name != "" {
		controllers = append(controllers, conftestController)
		logger.InfoM(fmt.Sprintf("Found %d Conftest image policies", len(conftestPolicies)), K8S_IMAGE_ADMISSION_MODULE_NAME)
	}

	// Check for Datree image policies
	logger.InfoM("Analyzing Datree image policies...", K8S_IMAGE_ADMISSION_MODULE_NAME)
	datreeController, datreePolicies := analyzeDatreeImagePolicies(ctx, clientset, dynClient)
	if datreeController.Name != "" {
		controllers = append(controllers, datreeController)
		logger.InfoM(fmt.Sprintf("Found %d Datree image policies", len(datreePolicies)), K8S_IMAGE_ADMISSION_MODULE_NAME)
	}

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

	// Analyze cloud provider image policies (if --cloud-provider flag specified)
	logger.InfoM("Analyzing cloud provider image policies...", K8S_IMAGE_ADMISSION_MODULE_NAME)
	cloudClients := initImageAdmissionCloudClients(logger)
	var cloudPolicies []CloudImagePolicy
	var gcpAttestors []GCPBinaryAuthAttestor
	var awsScanConfigs []AWSECRScanConfig
	var awsSignerProfiles []AWSSignerProfile
	var azureImagePolicies []AzureImagePolicy

	if cloudClients != nil {
		// GCP Binary Authorization
		if cloudClients.GCPBinaryAuthService != nil {
			logger.InfoM("Fetching GCP Binary Authorization policies...", K8S_IMAGE_ADMISSION_MODULE_NAME)
			gcpPolicies, attestors := analyzeGCPBinaryAuth(ctx, cloudClients, logger)
			cloudPolicies = append(cloudPolicies, gcpPolicies...)
			gcpAttestors = attestors
		}

		// AWS ECR and Signer
		if cloudClients.AWSECRClient != nil {
			logger.InfoM("Fetching AWS ECR/Signer policies...", K8S_IMAGE_ADMISSION_MODULE_NAME)
			awsPolicies, scanCfgs, signerProfs := analyzeAWSImagePolicies(ctx, cloudClients, logger)
			cloudPolicies = append(cloudPolicies, awsPolicies...)
			awsScanConfigs = scanCfgs
			awsSignerProfiles = signerProfs
		}

		// Azure Policy
		if cloudClients.AzureCredential != nil {
			logger.InfoM("Fetching Azure Policy assignments...", K8S_IMAGE_ADMISSION_MODULE_NAME)
			azPolicies, azImgPolicies := analyzeAzureImagePolicies(ctx, cloudClients, logger)
			cloudPolicies = append(cloudPolicies, azPolicies...)
			azureImagePolicies = azImgPolicies
		}
	}

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
		findings = append(findings, ImagePolicyFinding{
			Controller:   "Kritis",
			PolicyName:   policy.Name,
			Scope:        "Namespace",
			Namespace:    policy.Namespace,
			SignatureReq: "Yes",
			Attestation:  strings.Join(policy.RequiredAttestors, ", "),
		})
	}

	// Add Sigstore findings
	for _, policy := range sigstorePolicies {
		mode := policy.Mode
		if mode == "" {
			mode = "enforce"
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

	// Extract blocked images from all policies
	blockedImages := extractBlockedImages(
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
		stackroxPolicies,
		snykPolicies,
		trivyPolicies,
		policyEngineFindings,
	)

	// Build unified policies table
	var unifiedPolicies []ImageEnumeratedPolicy

	// Add Portieris policies
	for _, policy := range portierisPolicies {
		scope := "Namespace"
		if policy.IsClusterPolicy {
			scope = "Cluster"
		}
		for _, repo := range policy.Repositories {
			details := fmt.Sprintf("Repository: %s, Policy: %s", repo.Name, repo.Policy)
			if repo.VulnPolicy != "" {
				details += fmt.Sprintf(", Vuln: %s", repo.VulnPolicy)
			}
			unifiedPolicies = append(unifiedPolicies, ImageEnumeratedPolicy{
				Namespace: policy.Namespace,
				Tool:      "Portieris",
				Name:      policy.Name,
				Scope:     scope,
				Type:      "Image Signature",
				Details:   details,
			})
		}
	}

	// Add Connaisseur policies
	for _, policy := range connaisseurPolicies {
		details := fmt.Sprintf("Pattern: %s, Rule: %s", policy.Pattern, policy.Rule)
		if len(policy.Validators) > 0 {
			details += fmt.Sprintf(", Validators: %s", strings.Join(policy.Validators, ", "))
		}
		unifiedPolicies = append(unifiedPolicies, ImageEnumeratedPolicy{
			Namespace: "<ALL>",
			Tool:      "Connaisseur",
			Name:      policy.Name,
			Scope:     "Cluster",
			Type:      "Image Signature",
			Details:   details,
		})
	}

	// Add Ratify policies
	for _, policy := range ratifyPolicies {
		scope := "Cluster"
		ns := "<ALL>"
		if policy.Namespace != "" {
			scope = "Namespace"
			ns = policy.Namespace
		}
		details := fmt.Sprintf("Verifiers: %s", strings.Join(policy.Verifiers, ", "))
		if len(policy.ArtifactTypes) > 0 {
			details += fmt.Sprintf(", Artifacts: %s", strings.Join(policy.ArtifactTypes, ", "))
		}
		unifiedPolicies = append(unifiedPolicies, ImageEnumeratedPolicy{
			Namespace: ns,
			Tool:      "Ratify",
			Name:      policy.Name,
			Scope:     scope,
			Type:      "Artifact Verification",
			Details:   details,
		})
	}

	// Add Kritis policies
	for _, policy := range kritisPolicies {
		details := fmt.Sprintf("Attestors: %s", strings.Join(policy.RequiredAttestors, ", "))
		if policy.DefaultAllow {
			details += ", Default: Allow"
		}
		unifiedPolicies = append(unifiedPolicies, ImageEnumeratedPolicy{
			Namespace: policy.Namespace,
			Tool:      "Kritis",
			Name:      policy.Name,
			Scope:     "Namespace",
			Type:      "Binary Authorization",
			Details:   details,
		})
	}

	// Add Sigstore policies
	for _, policy := range sigstorePolicies {
		mode := policy.Mode
		if mode == "" {
			mode = "enforce"
		}
		details := fmt.Sprintf("Mode: %s, Images: %s", mode, strings.Join(policy.Images, ", "))
		if len(policy.Authorities) > 0 {
			details += fmt.Sprintf(", Authorities: %s", strings.Join(policy.Authorities, ", "))
		}
		unifiedPolicies = append(unifiedPolicies, ImageEnumeratedPolicy{
			Namespace: "<ALL>",
			Tool:      "Sigstore",
			Name:      policy.Name,
			Scope:     "Cluster",
			Type:      "Image Signature",
			Details:   details,
		})
	}

	// Add individual policies from each security tool
	// Aqua Security policies
	for _, p := range aquaPolicies {
		details := fmt.Sprintf("CVSS: %.1f", p.CVSSThreshold)
		if p.BlockUnregistered {
			details += ", Block Unregistered"
		}
		if p.BlockMalware {
			details += ", Block Malware"
		}
		if len(p.AllowedRegistries) > 0 {
			details += fmt.Sprintf(", Registries: %d", len(p.AllowedRegistries))
		}
		unifiedPolicies = append(unifiedPolicies, ImageEnumeratedPolicy{
			Namespace: p.Namespace,
			Tool:      "Aqua",
			Name:      p.Name,
			Scope:     "Namespace",
			Type:      "Admission Policy",
			Details:   details,
		})
	}

	// Prisma Cloud policies
	for _, p := range prismaPolicies {
		details := fmt.Sprintf("Block: %s", p.BlockThreshold)
		if p.GracePeriodDays > 0 {
			details += fmt.Sprintf(", Grace: %dd", p.GracePeriodDays)
		}
		if p.BlockMalware {
			details += ", Block Malware"
		}
		unifiedPolicies = append(unifiedPolicies, ImageEnumeratedPolicy{
			Namespace: "<ALL>",
			Tool:      "Prisma",
			Name:      p.Name,
			Scope:     "Cluster",
			Type:      "Image Scanning",
			Details:   details,
		})
	}

	// Sysdig Secure policies
	for _, p := range sysdigPolicies {
		details := fmt.Sprintf("CVSS: %.1f", p.CVSSThreshold)
		if p.BlockOnFailure {
			details += ", Block on Failure"
		}
		if len(p.AllowedRegistries) > 0 {
			details += fmt.Sprintf(", Registries: %d", len(p.AllowedRegistries))
		}
		unifiedPolicies = append(unifiedPolicies, ImageEnumeratedPolicy{
			Namespace: "<ALL>",
			Tool:      "Sysdig",
			Name:      p.Name,
			Scope:     "Cluster",
			Type:      "Admission Policy",
			Details:   details,
		})
	}

	// NeuVector policies
	for _, p := range neuvectorPolicies {
		details := fmt.Sprintf("Mode: %s", p.Mode)
		if p.BlockHighCVE {
			details += ", Block High CVE"
		}
		if len(p.DeniedRegistries) > 0 {
			details += fmt.Sprintf(", Denied: %d registries", len(p.DeniedRegistries))
		}
		unifiedPolicies = append(unifiedPolicies, ImageEnumeratedPolicy{
			Namespace: p.Namespace,
			Tool:      "NeuVector",
			Name:      p.Name,
			Scope:     "Namespace",
			Type:      "Admission Policy",
			Details:   details,
		})
	}

	// StackRox policies
	for _, p := range stackroxPolicies {
		details := fmt.Sprintf("Severity: %s, Action: %s", p.Severity, p.EnforcementAction)
		if len(p.Categories) > 0 {
			details += fmt.Sprintf(", Categories: %s", strings.Join(p.Categories, ","))
		}
		unifiedPolicies = append(unifiedPolicies, ImageEnumeratedPolicy{
			Namespace: "<ALL>",
			Tool:      "StackRox",
			Name:      p.Name,
			Scope:     "Cluster",
			Type:      "Security Policy",
			Details:   details,
		})
	}

	// Snyk Container policies
	for _, p := range snykPolicies {
		details := fmt.Sprintf("Severity: %s", p.SeverityThreshold)
		if p.BlockOnFailure {
			details += ", Block on Failure"
		}
		if p.AutoFix {
			details += ", AutoFix"
		}
		unifiedPolicies = append(unifiedPolicies, ImageEnumeratedPolicy{
			Namespace: "<ALL>",
			Tool:      "Snyk",
			Name:      p.Name,
			Scope:     "Cluster",
			Type:      "Container Policy",
			Details:   details,
		})
	}

	// Anchore policies
	for _, p := range anchorePolicies {
		details := fmt.Sprintf("Mode: %s", p.Mode)
		if p.PolicyBundleID != "" {
			details += fmt.Sprintf(", Bundle: %s", p.PolicyBundleID)
		}
		if p.FailOnPolicyEval {
			details += ", Fail on Eval"
		}
		unifiedPolicies = append(unifiedPolicies, ImageEnumeratedPolicy{
			Namespace: "<ALL>",
			Tool:      "Anchore",
			Name:      p.Name,
			Scope:     "Cluster",
			Type:      "Policy Bundle",
			Details:   details,
		})
	}

	// Trivy Operator policies
	for _, p := range trivyPolicies {
		details := fmt.Sprintf("Severity: %s", p.SeverityThreshold)
		if p.VulnerabilityReports {
			details += ", Vuln Reports"
		}
		if p.ConfigAuditReports {
			details += ", Config Audit"
		}
		if p.SBOMEnabled {
			details += ", SBOM"
		}
		unifiedPolicies = append(unifiedPolicies, ImageEnumeratedPolicy{
			Namespace: p.Namespace,
			Tool:      "Trivy",
			Name:      p.Name,
			Scope:     "Namespace",
			Type:      "Operator Config",
			Details:   details,
		})
	}

	// Kubewarden policies
	for _, p := range kubewardenPolicies {
		scope := "Namespace"
		ns := p.Namespace
		if p.IsClusterWide {
			scope = "Cluster"
			ns = "<ALL>"
		}
		details := fmt.Sprintf("Mode: %s, Server: %s", p.Mode, p.PolicyServer)
		if p.Mutating {
			details += ", Mutating"
		}
		unifiedPolicies = append(unifiedPolicies, ImageEnumeratedPolicy{
			Namespace: ns,
			Tool:      "Kubewarden",
			Name:      p.Name,
			Scope:     scope,
			Type:      "Admission Policy",
			Details:   details,
		})
	}

	// Notation policies
	for _, p := range notationPolicies {
		details := fmt.Sprintf("Verification: %s", p.VerificationLevel)
		if len(p.TrustStores) > 0 {
			details += fmt.Sprintf(", Stores: %d", len(p.TrustStores))
		}
		if p.SignatureFormat != "" {
			details += fmt.Sprintf(", Format: %s", p.SignatureFormat)
		}
		unifiedPolicies = append(unifiedPolicies, ImageEnumeratedPolicy{
			Namespace: "<ALL>",
			Tool:      "Notation",
			Name:      p.Name,
			Scope:     "Cluster",
			Type:      "Signature Verification",
			Details:   details,
		})
	}

	// Harbor policies
	for _, p := range harborPolicies {
		details := fmt.Sprintf("Severity: %s", p.SeverityThreshold)
		if p.PreventVulnImages {
			details += ", Block Vuln Images"
		}
		if p.ContentTrustEnabled {
			details += ", Content Trust"
		}
		if p.CosignEnabled {
			details += ", Cosign"
		}
		unifiedPolicies = append(unifiedPolicies, ImageEnumeratedPolicy{
			Namespace: "<ALL>",
			Tool:      "Harbor",
			Name:      p.Name,
			Scope:     "Project",
			Type:      "Registry Policy",
			Details:   details,
		})
	}

	// AWS Signer policies
	for _, p := range awsSignerPolicies {
		details := fmt.Sprintf("Platform: %s", p.PlatformID)
		if p.SigningProfileARN != "" {
			details += ", Has Profile"
		}
		if p.AllowUnsigned {
			details += ", Allow Unsigned"
		}
		unifiedPolicies = append(unifiedPolicies, ImageEnumeratedPolicy{
			Namespace: "<ALL>",
			Tool:      "AWSSigner",
			Name:      p.Name,
			Scope:     "Cluster",
			Type:      "Code Signing",
			Details:   details,
		})
	}

	// Clair policies
	for _, p := range clairPolicies {
		details := fmt.Sprintf("Severity: %s", p.SeverityThreshold)
		if p.FixableOnly {
			details += ", Fixable Only"
		}
		if len(p.AllowList) > 0 {
			details += fmt.Sprintf(", Allow List: %d", len(p.AllowList))
		}
		unifiedPolicies = append(unifiedPolicies, ImageEnumeratedPolicy{
			Namespace: "<ALL>",
			Tool:      "Clair",
			Name:      p.Name,
			Scope:     "Cluster",
			Type:      "Vulnerability Scanning",
			Details:   details,
		})
	}

	// Wiz policies
	for _, p := range wizPolicies {
		details := fmt.Sprintf("Severity: %s", p.SeverityThreshold)
		if p.BlockVulnerabilities {
			details += ", Block Vulnerabilities"
		}
		if len(p.AllowedRegistries) > 0 {
			details += fmt.Sprintf(", Registries: %d", len(p.AllowedRegistries))
		}
		unifiedPolicies = append(unifiedPolicies, ImageEnumeratedPolicy{
			Namespace: "<ALL>",
			Tool:      "Wiz",
			Name:      p.Name,
			Scope:     "Cluster",
			Type:      "Cloud Security",
			Details:   details,
		})
	}

	// Lacework policies
	for _, p := range laceworkPolicies {
		details := fmt.Sprintf("Severity: %s", p.SeverityThreshold)
		if p.BlockOnFailure {
			details += ", Block on Failure"
		}
		if p.IntegrationID != "" {
			details += ", Integrated"
		}
		unifiedPolicies = append(unifiedPolicies, ImageEnumeratedPolicy{
			Namespace: "<ALL>",
			Tool:      "Lacework",
			Name:      p.Name,
			Scope:     "Cluster",
			Type:      "Cloud Security",
			Details:   details,
		})
	}

	// Cosign policies
	for _, p := range cosignPolicies {
		details := fmt.Sprintf("Keys: %d", len(p.KeyRefs))
		if p.KeylessEnabled {
			details += ", Keyless"
		}
		if p.VerifyAttestations {
			details += ", Attestations"
		}
		if p.TransparencyLog {
			details += ", Rekor"
		}
		unifiedPolicies = append(unifiedPolicies, ImageEnumeratedPolicy{
			Namespace: "<ALL>",
			Tool:      "Cosign",
			Name:      p.Name,
			Scope:     "Cluster",
			Type:      "Signature Policy",
			Details:   details,
		})
	}

	// Flux Image policies
	for _, p := range fluxImagePolicies {
		details := fmt.Sprintf("Policy: %s", p.Policy)
		if p.FilterTags != "" {
			details += fmt.Sprintf(", Filter: %s", p.FilterTags)
		}
		if p.Range != "" {
			details += fmt.Sprintf(", Range: %s", p.Range)
		}
		unifiedPolicies = append(unifiedPolicies, ImageEnumeratedPolicy{
			Namespace: p.Namespace,
			Tool:      "Flux",
			Name:      p.Name,
			Scope:     "Namespace",
			Type:      "Image Automation",
			Details:   details,
		})
	}

	// JFrog Xray policies
	for _, p := range xrayPolicies {
		details := fmt.Sprintf("Severity: %s", p.SeverityThreshold)
		if len(p.PolicyRules) > 0 {
			details += fmt.Sprintf(", Rules: %d", len(p.PolicyRules))
		}
		if p.BlockDownloads {
			details += ", Block Downloads"
		}
		unifiedPolicies = append(unifiedPolicies, ImageEnumeratedPolicy{
			Namespace: "<ALL>",
			Tool:      "JFrogXray",
			Name:      p.Name,
			Scope:     "Cluster",
			Type:      "Security Policy",
			Details:   details,
		})
	}

	// Deepfence policies
	for _, p := range deepfencePolicies {
		details := fmt.Sprintf("Severity: %s", p.SeverityThreshold)
		if p.BlockMalware {
			details += ", Block Malware"
		}
		unifiedPolicies = append(unifiedPolicies, ImageEnumeratedPolicy{
			Namespace: "<ALL>",
			Tool:      "Deepfence",
			Name:      p.Name,
			Scope:     "Cluster",
			Type:      "Threat Mapper",
			Details:   details,
		})
	}

	// Qualys policies
	for _, p := range qualysPolicies {
		details := fmt.Sprintf("Severity: %s", p.SeverityThreshold)
		if p.BlockOnCritical {
			details += ", Block Critical"
		}
		unifiedPolicies = append(unifiedPolicies, ImageEnumeratedPolicy{
			Namespace: "<ALL>",
			Tool:      "Qualys",
			Name:      p.Name,
			Scope:     "Cluster",
			Type:      "Container Security",
			Details:   details,
		})
	}

	// Docker Scout policies
	for _, p := range dockerScoutPolicies {
		details := fmt.Sprintf("Severity: %s", p.SeverityThreshold)
		if p.PolicyCheck {
			details += ", Policy Check"
		}
		if p.SBOMEnabled {
			details += ", SBOM"
		}
		unifiedPolicies = append(unifiedPolicies, ImageEnumeratedPolicy{
			Namespace: "<ALL>",
			Tool:      "DockerScout",
			Name:      p.Name,
			Scope:     "Cluster",
			Type:      "Image Analysis",
			Details:   details,
		})
	}

	// Add Azure Policy
	for _, config := range azurePolicyConfigs {
		unifiedPolicies = append(unifiedPolicies, ImageEnumeratedPolicy{
			Namespace: "<ALL>",
			Tool:      "AzurePolicy",
			Name:      config.Name,
			Scope:     "Cluster",
			Type:      "Policy Enforcement",
			Details:   "Azure Policy for AKS",
		})
	}

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
	findingHeaders := uniformPolicyHeader
	allowedImagesHeaders := uniformPolicyHeader
	blockedImagesHeaders := uniformPolicyHeader
	cloudPolicyHeaders := uniformPolicyHeader
	gcpAttestorHeaders := uniformPolicyHeader
	awsScanConfigHeaders := uniformPolicyHeader
	awsSignerProfileHeaders := uniformPolicyHeader
	aquaHeaders := uniformPolicyHeader
	prismaHeaders := uniformPolicyHeader
	sysdigHeaders := uniformPolicyHeader
	neuvectorHeaders := uniformPolicyHeader
	stackroxHeaders := uniformPolicyHeader
	snykHeaders := uniformPolicyHeader
	anchoreHeaders := uniformPolicyHeader
	trivyHeaders := uniformPolicyHeader
	notationHeaders := uniformPolicyHeader
	harborHeaders := uniformPolicyHeader
	clairHeaders := uniformPolicyHeader
	wizHeaders := uniformPolicyHeader
	laceworkHeaders := uniformPolicyHeader
	cosignHeaders := uniformPolicyHeader
	fluxImageHeaders := uniformPolicyHeader
	xrayHeaders := uniformPolicyHeader
	deepfenceHeaders := uniformPolicyHeader
	qualysHeaders := uniformPolicyHeader
	dockerScoutHeaders := uniformPolicyHeader

	imagesHeaders := []string{
		"Namespace",
		"Pod",
		"Container",
		"Registry",
		"Repository",
		"Tag",
		"Digest",
		"Public Registry",
		":latest",
		"Issues",
	}

	unifiedPoliciesHeaders := []string{
		"Namespace",
		"Tool",
		"Name",
		"Scope",
		"Type",
		"Details",
	}

	var controllerRows [][]string
	var findingRows [][]string
	var imagesRows [][]string
	var allowedImagesRows [][]string
	var blockedImagesRows [][]string
	var unifiedPoliciesRows [][]string
	var cloudPolicyRows [][]string
	var gcpAttestorRows [][]string
	var awsScanConfigRows [][]string
	var awsSignerProfileRows [][]string
	var aquaRows [][]string
	var prismaRows [][]string
	var sysdigRows [][]string
	var neuvectorRows [][]string
	var stackroxRows [][]string
	var snykRows [][]string
	var anchoreRows [][]string
	var trivyRows [][]string
	var notationRows [][]string
	var harborRows [][]string
	var clairRows [][]string
	var wizRows [][]string
	var laceworkRows [][]string
	var cosignRows [][]string
	var fluxImageRows [][]string
	var xrayRows [][]string
	var deepfenceRows [][]string
	var qualysRows [][]string
	var dockerScoutRows [][]string

	for _, c := range controllers {
		sigReq := "No"
		if c.SignatureReqs {
			sigReq = "Yes"
		}

		// Detect issues
		var ctrlIssues []string
		if c.Status == "degraded" || c.Status == "unverified" {
			ctrlIssues = append(ctrlIssues, "Controller not healthy")
		}
		if c.FailurePolicy == "Ignore" {
			ctrlIssues = append(ctrlIssues, "Failure policy Ignore")
		}
		if c.PolicyCount == 0 {
			ctrlIssues = append(ctrlIssues, "No policies defined")
		}
		if !c.SignatureReqs {
			ctrlIssues = append(ctrlIssues, "No signature required")
		}
		ctrlIssuesStr := "<NONE>"
		if len(ctrlIssues) > 0 {
			ctrlIssuesStr = strings.Join(ctrlIssues, "; ")
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
			ctrlIssuesStr,
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

		// Detect issues
		var findIssues []string
		if f.Policy == "allow" || f.Policy == "ALLOW" {
			findIssues = append(findIssues, "Allow action")
		}
		if f.SignatureReq == "No" || f.SignatureReq == "" {
			findIssues = append(findIssues, "No signature required")
		}
		if vulnPolicy == "<NONE>" {
			findIssues = append(findIssues, "No vuln policy")
		}
		if repo == "*" {
			findIssues = append(findIssues, "Wildcard repository")
		}
		findIssuesStr := "<NONE>"
		if len(findIssues) > 0 {
			findIssuesStr = strings.Join(findIssues, "; ")
		}

		// Uniform schema: Namespace, Name, Scope, Target, Type, Configuration, Details, Issues
		findingTarget := repo
		findingType := f.Controller
		findingConfig := fmt.Sprintf("Action: %s", f.Policy)
		findingDetails := fmt.Sprintf("Signature: %s, Attestation: %s, Vuln: %s", f.SignatureReq, attestation, vulnPolicy)

		findingRows = append(findingRows, []string{
			ns,
			f.PolicyName,
			f.Scope,
			findingTarget,
			findingType,
			findingConfig,
			findingDetails,
			findIssuesStr,
		})
	}

	// Build images rows from deployed images
	for ns, images := range imageSourceAnalysis.ImagesByNamespace {
		for _, img := range images {
			isPublic := "No"
			if img.IsPublic {
				isPublic = "Yes"
			}
			hasLatest := "No"
			if img.HasLatest {
				hasLatest = "Yes"
			}
			digest := img.Digest
			if digest == "" {
				digest = "<NONE>"
			} else if len(digest) > 20 {
				// Truncate long digests for display
				digest = digest[:20] + "..."
			}

			// Detect issues
			var imgIssues []string
			if img.IsPublic {
				imgIssues = append(imgIssues, "Public registry")
			}
			if img.HasLatest {
				imgIssues = append(imgIssues, "Uses :latest tag")
			}
			if img.Digest == "" {
				imgIssues = append(imgIssues, "No digest pinning")
			}
			imgIssuesStr := "<NONE>"
			if len(imgIssues) > 0 {
				imgIssuesStr = strings.Join(imgIssues, "; ")
			}

			imagesRows = append(imagesRows, []string{
				ns,
				img.PodName,
				img.Container,
				img.Registry,
				img.Repository,
				img.Tag,
				digest,
				isPublic,
				hasLatest,
				imgIssuesStr,
			})
		}
	}

	// Build cloud policy rows (from --cloud-provider flag)
	for _, cp := range cloudPolicies {
		blocksDeployment := "No"
		if cp.BlocksDeployment {
			blocksDeployment = "YES"
		}

		// Format bypass patterns (exempt images)
		bypassPatterns := "-"
		if len(cp.ExemptImages) > 0 {
			if len(cp.ExemptImages) <= 3 {
				bypassPatterns = strings.Join(cp.ExemptImages, ", ")
			} else {
				bypassPatterns = fmt.Sprintf("%s... (+%d more)", strings.Join(cp.ExemptImages[:3], ", "), len(cp.ExemptImages)-3)
			}
		}

		// Format allowed registries
		allowedRegs := "-"
		if len(cp.AllowedRegistries) > 0 {
			if len(cp.AllowedRegistries) <= 3 {
				allowedRegs = strings.Join(cp.AllowedRegistries, ", ")
			} else {
				allowedRegs = fmt.Sprintf("%s... (+%d more)", strings.Join(cp.AllowedRegistries[:3], ", "), len(cp.AllowedRegistries)-3)
			}
		}

		// Detect issues
		var cpIssues []string
		if !cp.BlocksDeployment {
			cpIssues = append(cpIssues, "Does not block deployment")
		}
		if cp.EnforcementMode == "audit" || cp.EnforcementMode == "dryrun" {
			cpIssues = append(cpIssues, "Not enforcing")
		}
		if cp.DefaultAction == "ALLOW" || cp.DefaultAction == "allow" {
			cpIssues = append(cpIssues, "Default allow action")
		}
		if len(cp.ExemptImages) > 0 {
			cpIssues = append(cpIssues, "Has exemptions")
		}
		cpIssuesStr := "<NONE>"
		if len(cpIssues) > 0 {
			cpIssuesStr = strings.Join(cpIssues, "; ")
		}

		// Uniform schema: Namespace, Name, Scope, Target, Type, Configuration, Details, Issues
		cpNs := cp.Provider
		cpScope := "Cluster"
		cpTarget := allowedRegs
		if cpTarget == "<NONE>" {
			cpTarget = "All registries"
		}
		cpType := cp.PolicyType
		cpConfig := fmt.Sprintf("Enforcement: %s, Default: %s, Blocks: %s", cp.EnforcementMode, cp.DefaultAction, blocksDeployment)
		cpDetails := cp.Details
		if bypassPatterns != "<NONE>" {
			cpDetails = fmt.Sprintf("%s, Bypass: %s", cpDetails, bypassPatterns)
		}

		cloudPolicyRows = append(cloudPolicyRows, []string{
			cpNs,
			cp.Name,
			cpScope,
			cpTarget,
			cpType,
			cpConfig,
			cpDetails,
			cpIssuesStr,
		})
	}

	// Build GCP attestor rows
	for _, att := range gcpAttestors {
		// Detect issues
		var attIssues []string
		if att.KeyCount == 0 {
			attIssues = append(attIssues, "No keys configured")
		}
		if att.Description == "" {
			attIssues = append(attIssues, "No description")
		}
		attIssuesStr := "<NONE>"
		if len(attIssues) > 0 {
			attIssuesStr = strings.Join(attIssues, "; ")
		}

		// Uniform schema: Namespace, Name, Scope, Target, Type, Configuration, Details, Issues
		attNs := att.Project
		attScope := "Project"
		attTarget := "Container images"
		attType := "GCP Attestor"
		attConfig := fmt.Sprintf("Keys: %d, Algorithm: %s", att.KeyCount, att.KeyAlgorithm)
		attDetails := att.Description
		if attDetails == "" {
			attDetails = fmt.Sprintf("Updated: %s", att.UpdateTime)
		} else {
			attDetails = fmt.Sprintf("%s, Updated: %s", attDetails, att.UpdateTime)
		}

		gcpAttestorRows = append(gcpAttestorRows, []string{
			attNs,
			att.Name,
			attScope,
			attTarget,
			attType,
			attConfig,
			attDetails,
			attIssuesStr,
		})
	}

	// Build AWS scan config rows
	for _, cfg := range awsScanConfigs {
		scanOnPush := "No"
		if cfg.ScanOnPush {
			scanOnPush = "Yes"
		}
		// ECR scanning detects malicious images but doesn't block deployment
		detectsMalicious := "Yes (post-deploy)"
		if cfg.ScanFrequency == "CONTINUOUS_SCAN" {
			detectsMalicious = "Yes (continuous)"
		}

		// Detect issues
		var scanIssues []string
		if !cfg.ScanOnPush {
			scanIssues = append(scanIssues, "Scan on push disabled")
		}
		if cfg.ScanFrequency != "CONTINUOUS_SCAN" {
			scanIssues = append(scanIssues, "Not continuous scanning")
		}
		scanIssuesStr := "<NONE>"
		if len(scanIssues) > 0 {
			scanIssuesStr = strings.Join(scanIssues, "; ")
		}

		// Uniform schema: Namespace, Name, Scope, Target, Type, Configuration, Details, Issues
		scanNs := cfg.RegistryID
		scanScope := "Repository"
		scanTarget := cfg.RepositoryName
		scanType := "AWS ECR Scan"
		scanConfig := fmt.Sprintf("Scan on Push: %s, Frequency: %s", scanOnPush, cfg.ScanFrequency)
		scanDetails := fmt.Sprintf("Malware Detection: %s", detectsMalicious)

		awsScanConfigRows = append(awsScanConfigRows, []string{
			scanNs,
			cfg.RepositoryName,
			scanScope,
			scanTarget,
			scanType,
			scanConfig,
			scanDetails,
			scanIssuesStr,
		})
	}

	// Build AWS signer profile rows
	for _, profile := range awsSignerProfiles {
		// Signer profiles need an admission controller to be enforced
		enforced := "Requires AC"

		// Detect issues
		var signerIssues []string
		signerIssues = append(signerIssues, "Requires admission controller for enforcement")
		if profile.Status != "Active" {
			signerIssues = append(signerIssues, "Profile not active")
		}
		signerIssuesStr := strings.Join(signerIssues, "; ")

		// Uniform schema: Namespace, Name, Scope, Target, Type, Configuration, Details, Issues
		signerNs := "AWS"
		signerScope := "Account"
		signerTarget := profile.PlatformID
		signerType := "AWS Signer Profile"
		signerConfig := fmt.Sprintf("Status: %s, Enforced: %s", profile.Status, enforced)
		signerDetails := fmt.Sprintf("Version: %s", profile.ProfileVersion)

		awsSignerProfileRows = append(awsSignerProfileRows, []string{
			signerNs,
			profile.ProfileName,
			signerScope,
			signerTarget,
			signerType,
			signerConfig,
			signerDetails,
			signerIssuesStr,
		})
	}

	// Build Aqua Security rows
	for _, p := range aquaPolicies {
		allowedRegs := "<NONE>"
		if len(p.AllowedRegistries) > 0 {
			allowedRegs = strings.Join(p.AllowedRegistries, ", ")
		}

		// Detect issues
		var aquaIssues []string
		if !p.Enabled {
			aquaIssues = append(aquaIssues, "Policy disabled")
		}
		if !p.BlockUnregistered {
			aquaIssues = append(aquaIssues, "Unregistered images allowed")
		}
		if !p.BlockMalware {
			aquaIssues = append(aquaIssues, "Malware not blocked")
		}
		if p.CVSSThreshold > 7.0 {
			aquaIssues = append(aquaIssues, "High CVSS threshold")
		}
		issuesStr := "<NONE>"
		if len(aquaIssues) > 0 {
			issuesStr = strings.Join(aquaIssues, "; ")
		}

		// Uniform schema: Namespace, Name, Scope, Target, Type, Configuration, Details, Issues
		aquaNs := p.Namespace
		if aquaNs == "" {
			aquaNs = "<CLUSTER>"
		}
		aquaScope := "Namespace"
		aquaTarget := allowedRegs
		if aquaTarget == "<NONE>" {
			aquaTarget = "All registries"
		}
		aquaType := "Aqua Security"
		aquaConfig := fmt.Sprintf("Enabled: %s, CVSS: %.1f", shared.FormatBool(p.Enabled), p.CVSSThreshold)
		aquaDetails := fmt.Sprintf("Block Unregistered: %s, Block Malware: %s", shared.FormatBool(p.BlockUnregistered), shared.FormatBool(p.BlockMalware))

		aquaRows = append(aquaRows, []string{
			aquaNs,
			p.Name,
			aquaScope,
			aquaTarget,
			aquaType,
			aquaConfig,
			aquaDetails,
			issuesStr,
		})
	}

	// Build Prisma Cloud rows
	for _, p := range prismaPolicies {
		trustedRegs := "<NONE>"
		if len(p.TrustedRegistries) > 0 {
			trustedRegs = strings.Join(p.TrustedRegistries, ", ")
		}

		// Detect issues
		var prismaIssues []string
		if !p.Enabled {
			prismaIssues = append(prismaIssues, "Policy disabled")
		}
		if !p.BlockMalware {
			prismaIssues = append(prismaIssues, "Malware not blocked")
		}
		if p.GracePeriodDays > 7 {
			prismaIssues = append(prismaIssues, "Long grace period")
		}
		if p.BlockThreshold == "" || p.BlockThreshold == "critical" {
			prismaIssues = append(prismaIssues, "Weak block threshold")
		}
		issuesStr := "<NONE>"
		if len(prismaIssues) > 0 {
			issuesStr = strings.Join(prismaIssues, "; ")
		}

		// Uniform schema: Namespace, Name, Scope, Target, Type, Configuration, Details, Issues
		prismaNs := "<CLUSTER>"
		prismaScope := "Cluster"
		prismaTarget := trustedRegs
		if prismaTarget == "<NONE>" {
			prismaTarget = "All registries"
		}
		prismaType := "Prisma Cloud"
		prismaConfig := fmt.Sprintf("Enabled: %s, Threshold: %s", shared.FormatBool(p.Enabled), p.BlockThreshold)
		prismaDetails := fmt.Sprintf("Grace Period: %d days, Block Malware: %s", p.GracePeriodDays, shared.FormatBool(p.BlockMalware))

		prismaRows = append(prismaRows, []string{
			prismaNs,
			p.Name,
			prismaScope,
			prismaTarget,
			prismaType,
			prismaConfig,
			prismaDetails,
			issuesStr,
		})
	}

	// Build Sysdig Secure rows
	for _, p := range sysdigPolicies {
		allowedRegs := "<NONE>"
		if len(p.AllowedRegistries) > 0 {
			allowedRegs = strings.Join(p.AllowedRegistries, ", ")
		}

		// Detect issues
		var sysdigIssues []string
		if !p.Enabled {
			sysdigIssues = append(sysdigIssues, "Policy disabled")
		}
		if !p.ScanningEnabled {
			sysdigIssues = append(sysdigIssues, "Scanning disabled")
		}
		if !p.BlockOnFailure {
			sysdigIssues = append(sysdigIssues, "Not blocking on failure")
		}
		if p.CVSSThreshold > 7.0 {
			sysdigIssues = append(sysdigIssues, "High CVSS threshold")
		}
		issuesStr := "<NONE>"
		if len(sysdigIssues) > 0 {
			issuesStr = strings.Join(sysdigIssues, "; ")
		}

		// Uniform schema: Namespace, Name, Scope, Target, Type, Configuration, Details, Issues
		sysdigNs := "<CLUSTER>"
		sysdigScope := "Cluster"
		sysdigTarget := allowedRegs
		if sysdigTarget == "<NONE>" {
			sysdigTarget = "All registries"
		}
		sysdigType := "Sysdig Secure"
		sysdigConfig := fmt.Sprintf("Enabled: %s, CVSS: %.1f", shared.FormatBool(p.Enabled), p.CVSSThreshold)
		sysdigDetails := fmt.Sprintf("Scanning: %s, Block on Failure: %s", shared.FormatBool(p.ScanningEnabled), shared.FormatBool(p.BlockOnFailure))

		sysdigRows = append(sysdigRows, []string{
			sysdigNs,
			p.Name,
			sysdigScope,
			sysdigTarget,
			sysdigType,
			sysdigConfig,
			sysdigDetails,
			issuesStr,
		})
	}

	// Build NeuVector rows
	for _, p := range neuvectorPolicies {
		allowedRegs := "<NONE>"
		if len(p.AllowedRegistries) > 0 {
			allowedRegs = strings.Join(p.AllowedRegistries, ", ")
		}
		deniedRegs := "<NONE>"
		if len(p.DeniedRegistries) > 0 {
			deniedRegs = strings.Join(p.DeniedRegistries, ", ")
		}

		// Detect issues
		var neuvectorIssues []string
		if !p.Enabled {
			neuvectorIssues = append(neuvectorIssues, "Policy disabled")
		}
		if p.Mode == "monitor" || p.Mode == "discover" {
			neuvectorIssues = append(neuvectorIssues, "Not enforcing")
		}
		if !p.BlockHighCVE {
			neuvectorIssues = append(neuvectorIssues, "High CVE not blocked")
		}
		issuesStr := "<NONE>"
		if len(neuvectorIssues) > 0 {
			issuesStr = strings.Join(neuvectorIssues, "; ")
		}

		// Uniform schema: Namespace, Name, Scope, Target, Type, Configuration, Details, Issues
		neuvectorNs := p.Namespace
		if neuvectorNs == "" {
			neuvectorNs = "<CLUSTER>"
		}
		neuvectorScope := "Namespace"
		neuvectorTarget := allowedRegs
		if neuvectorTarget == "<NONE>" {
			neuvectorTarget = "All registries"
		}
		neuvectorType := "NeuVector"
		neuvectorConfig := fmt.Sprintf("Enabled: %s, Mode: %s", shared.FormatBool(p.Enabled), p.Mode)
		neuvectorDetails := fmt.Sprintf("Block High CVE: %s, Denied: %s", shared.FormatBool(p.BlockHighCVE), deniedRegs)

		neuvectorRows = append(neuvectorRows, []string{
			neuvectorNs,
			p.Name,
			neuvectorScope,
			neuvectorTarget,
			neuvectorType,
			neuvectorConfig,
			neuvectorDetails,
			issuesStr,
		})
	}

	// Build StackRox rows
	for _, p := range stackroxPolicies {
		categories := "<NONE>"
		if len(p.Categories) > 0 {
			categories = strings.Join(p.Categories, ", ")
		}
		imageCriteria := "<NONE>"
		if len(p.ImageCriteria) > 0 {
			imageCriteria = strings.Join(p.ImageCriteria, ", ")
		}

		// Detect issues
		var stackroxIssues []string
		if !p.Enabled {
			stackroxIssues = append(stackroxIssues, "Policy disabled")
		}
		if p.EnforcementAction == "INFORM" || p.EnforcementAction == "" {
			stackroxIssues = append(stackroxIssues, "Not enforcing")
		}
		issuesStr := "<NONE>"
		if len(stackroxIssues) > 0 {
			issuesStr = strings.Join(stackroxIssues, "; ")
		}

		// Uniform schema: Namespace, Name, Scope, Target, Type, Configuration, Details, Issues
		stackroxNs := "<CLUSTER>"
		stackroxScope := "Cluster"
		stackroxTarget := imageCriteria
		if stackroxTarget == "<NONE>" {
			stackroxTarget = "All images"
		}
		stackroxType := "StackRox"
		stackroxConfig := fmt.Sprintf("Enabled: %s, Action: %s", shared.FormatBool(p.Enabled), p.EnforcementAction)
		stackroxDetails := fmt.Sprintf("Severity: %s, Categories: %s", p.Severity, categories)

		stackroxRows = append(stackroxRows, []string{
			stackroxNs,
			p.Name,
			stackroxScope,
			stackroxTarget,
			stackroxType,
			stackroxConfig,
			stackroxDetails,
			issuesStr,
		})
	}

	// Build Snyk Container rows
	for _, p := range snykPolicies {
		projects := "<NONE>"
		if len(p.MonitoredProjects) > 0 {
			projects = strings.Join(p.MonitoredProjects, ", ")
		}

		// Detect issues
		var snykIssues []string
		if !p.Enabled {
			snykIssues = append(snykIssues, "Policy disabled")
		}
		if !p.BlockOnFailure {
			snykIssues = append(snykIssues, "Not blocking on failure")
		}
		if p.SeverityThreshold == "" || p.SeverityThreshold == "critical" {
			snykIssues = append(snykIssues, "Weak severity threshold")
		}
		issuesStr := "<NONE>"
		if len(snykIssues) > 0 {
			issuesStr = strings.Join(snykIssues, "; ")
		}

		// Uniform schema: Namespace, Name, Scope, Target, Type, Configuration, Details, Issues
		snykNs := "<CLUSTER>"
		snykScope := "Cluster"
		snykTarget := projects
		if snykTarget == "<NONE>" {
			snykTarget = "All projects"
		}
		snykType := "Snyk Container"
		snykConfig := fmt.Sprintf("Enabled: %s, Threshold: %s", shared.FormatBool(p.Enabled), p.SeverityThreshold)
		snykDetails := fmt.Sprintf("Auto Fix: %s, Block on Failure: %s", shared.FormatBool(p.AutoFix), shared.FormatBool(p.BlockOnFailure))

		snykRows = append(snykRows, []string{
			snykNs,
			p.Name,
			snykScope,
			snykTarget,
			snykType,
			snykConfig,
			snykDetails,
			issuesStr,
		})
	}

	// Build Anchore rows
	for _, p := range anchorePolicies {
		allowedRegs := "<NONE>"
		if len(p.AllowedRegistries) > 0 {
			allowedRegs = strings.Join(p.AllowedRegistries, ", ")
		}

		// Detect issues
		var anchoreIssues []string
		if !p.Enabled {
			anchoreIssues = append(anchoreIssues, "Policy disabled")
		}
		if !p.FailOnPolicyEval {
			anchoreIssues = append(anchoreIssues, "Not failing on policy eval")
		}
		if p.Mode == "audit" || p.Mode == "passive" {
			anchoreIssues = append(anchoreIssues, "Not enforcing")
		}
		issuesStr := "<NONE>"
		if len(anchoreIssues) > 0 {
			issuesStr = strings.Join(anchoreIssues, "; ")
		}

		// Uniform schema: Namespace, Name, Scope, Target, Type, Configuration, Details, Issues
		anchoreNs := "<CLUSTER>"
		anchoreScope := "Cluster"
		anchoreTarget := allowedRegs
		if anchoreTarget == "<NONE>" {
			anchoreTarget = "All registries"
		}
		anchoreType := "Anchore"
		anchoreConfig := fmt.Sprintf("Enabled: %s, Mode: %s", shared.FormatBool(p.Enabled), p.Mode)
		anchoreDetails := fmt.Sprintf("Bundle: %s, Fail on Eval: %s", p.PolicyBundleID, shared.FormatBool(p.FailOnPolicyEval))

		anchoreRows = append(anchoreRows, []string{
			anchoreNs,
			p.Name,
			anchoreScope,
			anchoreTarget,
			anchoreType,
			anchoreConfig,
			anchoreDetails,
			issuesStr,
		})
	}

	// Build Trivy Operator rows
	for _, p := range trivyPolicies {
		// Detect issues
		var trivyIssues []string
		if !p.ScanJobsEnabled {
			trivyIssues = append(trivyIssues, "Scan jobs disabled")
		}
		if !p.VulnerabilityReports {
			trivyIssues = append(trivyIssues, "Vuln reports disabled")
		}
		if !p.ConfigAuditReports {
			trivyIssues = append(trivyIssues, "Config audit disabled")
		}
		if p.SeverityThreshold == "" || p.SeverityThreshold == "CRITICAL" {
			trivyIssues = append(trivyIssues, "Weak severity threshold")
		}
		issuesStr := "<NONE>"
		if len(trivyIssues) > 0 {
			issuesStr = strings.Join(trivyIssues, "; ")
		}

		// Uniform schema: Namespace, Name, Scope, Target, Type, Configuration, Details, Issues
		trivyNs := p.Namespace
		if trivyNs == "" {
			trivyNs = "<CLUSTER>"
		}
		trivyScope := "Namespace"
		trivyTarget := "Container images"
		trivyType := "Trivy Operator"
		trivyConfig := fmt.Sprintf("Scan Jobs: %s, Threshold: %s", shared.FormatBool(p.ScanJobsEnabled), p.SeverityThreshold)
		trivyDetails := fmt.Sprintf("Vuln Reports: %s, Config Audit: %s, SBOM: %s", shared.FormatBool(p.VulnerabilityReports), shared.FormatBool(p.ConfigAuditReports), shared.FormatBool(p.SBOMEnabled))

		trivyRows = append(trivyRows, []string{
			trivyNs,
			p.Name,
			trivyScope,
			trivyTarget,
			trivyType,
			trivyConfig,
			trivyDetails,
			issuesStr,
		})
	}

	// Build Notation rows
	for _, p := range notationPolicies {
		trustStores := "<NONE>"
		if len(p.TrustStores) > 0 {
			trustStores = strings.Join(p.TrustStores, ", ")
		}

		// Detect issues
		var notationIssues []string
		if !p.Enabled {
			notationIssues = append(notationIssues, "Policy disabled")
		}
		if len(p.TrustStores) == 0 {
			notationIssues = append(notationIssues, "No trust stores configured")
		}
		if p.VerificationLevel == "permissive" || p.VerificationLevel == "audit" {
			notationIssues = append(notationIssues, "Weak verification level")
		}
		issuesStr := "<NONE>"
		if len(notationIssues) > 0 {
			issuesStr = strings.Join(notationIssues, "; ")
		}

		// Uniform schema: Namespace, Name, Scope, Target, Type, Configuration, Details, Issues
		notationNs := "<CLUSTER>"
		notationScope := "Cluster"
		notationTarget := trustStores
		if notationTarget == "<NONE>" {
			notationTarget = "All images"
		}
		notationType := "Notation"
		notationConfig := fmt.Sprintf("Enabled: %s, Level: %s", shared.FormatBool(p.Enabled), p.VerificationLevel)
		notationDetails := fmt.Sprintf("Policy: %s, Format: %s", p.TrustPolicyName, p.SignatureFormat)

		notationRows = append(notationRows, []string{
			notationNs,
			p.Name,
			notationScope,
			notationTarget,
			notationType,
			notationConfig,
			notationDetails,
			issuesStr,
		})
	}

	// Build Harbor rows
	for _, p := range harborPolicies {
		// Detect issues
		var harborIssues []string
		if !p.Enabled {
			harborIssues = append(harborIssues, "Policy disabled")
		}
		if !p.PreventVulnImages {
			harborIssues = append(harborIssues, "Vuln images not blocked")
		}
		if !p.AutoScan {
			harborIssues = append(harborIssues, "Auto scan disabled")
		}
		if !p.ContentTrustEnabled && !p.CosignEnabled {
			harborIssues = append(harborIssues, "No signature verification")
		}
		issuesStr := "<NONE>"
		if len(harborIssues) > 0 {
			issuesStr = strings.Join(harborIssues, "; ")
		}

		// Uniform schema: Namespace, Name, Scope, Target, Type, Configuration, Details, Issues
		harborNs := "<CLUSTER>"
		harborScope := "Registry"
		harborTarget := "Container images"
		harborType := "Harbor"
		harborConfig := fmt.Sprintf("Enabled: %s, Threshold: %s", shared.FormatBool(p.Enabled), p.SeverityThreshold)
		harborDetails := fmt.Sprintf("Prevent Vuln: %s, Auto Scan: %s, Content Trust: %s, Cosign: %s", shared.FormatBool(p.PreventVulnImages), shared.FormatBool(p.AutoScan), shared.FormatBool(p.ContentTrustEnabled), shared.FormatBool(p.CosignEnabled))

		harborRows = append(harborRows, []string{
			harborNs,
			p.Name,
			harborScope,
			harborTarget,
			harborType,
			harborConfig,
			harborDetails,
			issuesStr,
		})
	}

	// Build Clair rows
	for _, p := range clairPolicies {
		allowList := "<NONE>"
		if len(p.AllowList) > 0 {
			allowList = strings.Join(p.AllowList, ", ")
		}

		// Detect issues
		var clairIssues []string
		if !p.Enabled {
			clairIssues = append(clairIssues, "Policy disabled")
		}
		if p.SeverityThreshold == "" || p.SeverityThreshold == "critical" || p.SeverityThreshold == "Critical" {
			clairIssues = append(clairIssues, "Weak severity threshold")
		}
		if len(p.AllowList) > 10 {
			clairIssues = append(clairIssues, "Large allow list")
		}
		issuesStr := "<NONE>"
		if len(clairIssues) > 0 {
			issuesStr = strings.Join(clairIssues, "; ")
		}

		// Uniform schema: Namespace, Name, Scope, Target, Type, Configuration, Details, Issues
		clairNs := "<CLUSTER>"
		clairScope := "Cluster"
		clairTarget := "Container images"
		clairType := "Clair"
		clairConfig := fmt.Sprintf("Enabled: %s, Threshold: %s", shared.FormatBool(p.Enabled), p.SeverityThreshold)
		clairDetails := fmt.Sprintf("Fixable Only: %s, Allow List: %s", shared.FormatBool(p.FixableOnly), allowList)

		clairRows = append(clairRows, []string{
			clairNs,
			p.Name,
			clairScope,
			clairTarget,
			clairType,
			clairConfig,
			clairDetails,
			issuesStr,
		})
	}

	// Build Wiz rows
	for _, p := range wizPolicies {
		allowedRegs := "<NONE>"
		if len(p.AllowedRegistries) > 0 {
			allowedRegs = strings.Join(p.AllowedRegistries, ", ")
		}

		// Detect issues
		var wizIssues []string
		if !p.Enabled {
			wizIssues = append(wizIssues, "Policy disabled")
		}
		if !p.ScanningEnabled {
			wizIssues = append(wizIssues, "Scanning disabled")
		}
		if !p.BlockVulnerabilities {
			wizIssues = append(wizIssues, "Vulnerabilities not blocked")
		}
		issuesStr := "<NONE>"
		if len(wizIssues) > 0 {
			issuesStr = strings.Join(wizIssues, "; ")
		}

		// Uniform schema: Namespace, Name, Scope, Target, Type, Configuration, Details, Issues
		wizNs := "<CLUSTER>"
		wizScope := "Cluster"
		wizTarget := allowedRegs
		if wizTarget == "<NONE>" {
			wizTarget = "All registries"
		}
		wizType := "Wiz"
		wizConfig := fmt.Sprintf("Enabled: %s, Threshold: %s", shared.FormatBool(p.Enabled), p.SeverityThreshold)
		wizDetails := fmt.Sprintf("Scanning: %s, Block Vulns: %s", shared.FormatBool(p.ScanningEnabled), shared.FormatBool(p.BlockVulnerabilities))

		wizRows = append(wizRows, []string{
			wizNs,
			p.Name,
			wizScope,
			wizTarget,
			wizType,
			wizConfig,
			wizDetails,
			issuesStr,
		})
	}

	// Build Lacework rows
	for _, p := range laceworkPolicies {
		// Detect issues
		var laceworkIssues []string
		if !p.Enabled {
			laceworkIssues = append(laceworkIssues, "Policy disabled")
		}
		if !p.ScanningEnabled {
			laceworkIssues = append(laceworkIssues, "Scanning disabled")
		}
		if !p.BlockOnFailure {
			laceworkIssues = append(laceworkIssues, "Not blocking on failure")
		}
		issuesStr := "<NONE>"
		if len(laceworkIssues) > 0 {
			issuesStr = strings.Join(laceworkIssues, "; ")
		}

		// Uniform schema: Namespace, Name, Scope, Target, Type, Configuration, Details, Issues
		laceworkNs := "<CLUSTER>"
		laceworkScope := "Cluster"
		laceworkTarget := "Container images"
		laceworkType := "Lacework"
		laceworkConfig := fmt.Sprintf("Enabled: %s, Threshold: %s", shared.FormatBool(p.Enabled), p.SeverityThreshold)
		laceworkDetails := fmt.Sprintf("Scanning: %s, Block on Failure: %s, Integration: %s", shared.FormatBool(p.ScanningEnabled), shared.FormatBool(p.BlockOnFailure), p.IntegrationID)

		laceworkRows = append(laceworkRows, []string{
			laceworkNs,
			p.Name,
			laceworkScope,
			laceworkTarget,
			laceworkType,
			laceworkConfig,
			laceworkDetails,
			issuesStr,
		})
	}

	// Build Cosign Standalone rows
	for _, p := range cosignPolicies {
		keyRefs := "<NONE>"
		if len(p.KeyRefs) > 0 {
			keyRefs = strings.Join(p.KeyRefs, ", ")
		}

		// Detect issues
		var cosignIssues []string
		if !p.Enabled {
			cosignIssues = append(cosignIssues, "Policy disabled")
		}
		if len(p.KeyRefs) == 0 && !p.KeylessEnabled {
			cosignIssues = append(cosignIssues, "No keys or keyless configured")
		}
		if !p.TransparencyLog {
			cosignIssues = append(cosignIssues, "Transparency log disabled")
		}
		issuesStr := "<NONE>"
		if len(cosignIssues) > 0 {
			issuesStr = strings.Join(cosignIssues, "; ")
		}

		// Uniform schema: Namespace, Name, Scope, Target, Type, Configuration, Details, Issues
		cosignNs := "<CLUSTER>"
		cosignScope := "Cluster"
		cosignTarget := keyRefs
		if cosignTarget == "<NONE>" {
			cosignTarget = "All images"
		}
		cosignType := "Cosign"
		cosignConfig := fmt.Sprintf("Enabled: %s, Keyless: %s", shared.FormatBool(p.Enabled), shared.FormatBool(p.KeylessEnabled))
		cosignDetails := fmt.Sprintf("Verify Attestations: %s, Transparency Log: %s", shared.FormatBool(p.VerifyAttestations), shared.FormatBool(p.TransparencyLog))

		cosignRows = append(cosignRows, []string{
			cosignNs,
			p.Name,
			cosignScope,
			cosignTarget,
			cosignType,
			cosignConfig,
			cosignDetails,
			issuesStr,
		})
	}

	// Build Flux Image rows
	for _, p := range fluxImagePolicies {
		// Detect issues
		var fluxIssues []string
		if p.FilterTags == "" || p.FilterTags == "*" {
			fluxIssues = append(fluxIssues, "No tag filter")
		}
		if p.Policy == "" {
			fluxIssues = append(fluxIssues, "No policy defined")
		}
		issuesStr := "<NONE>"
		if len(fluxIssues) > 0 {
			issuesStr = strings.Join(fluxIssues, "; ")
		}

		// Uniform schema: Namespace, Name, Scope, Target, Type, Configuration, Details, Issues
		fluxNs := p.Namespace
		if fluxNs == "" {
			fluxNs = "<CLUSTER>"
		}
		fluxScope := "Namespace"
		fluxTarget := p.ImageRepository
		fluxType := "Flux Image Policy"
		fluxConfig := fmt.Sprintf("Policy: %s, Range: %s", p.Policy, p.Range)
		fluxDetails := fmt.Sprintf("Filter Tags: %s", p.FilterTags)

		fluxImageRows = append(fluxImageRows, []string{
			fluxNs,
			p.Name,
			fluxScope,
			fluxTarget,
			fluxType,
			fluxConfig,
			fluxDetails,
			issuesStr,
		})
	}

	// Build JFrog Xray rows
	for _, p := range xrayPolicies {
		watchNames := "<NONE>"
		if len(p.WatchNames) > 0 {
			watchNames = strings.Join(p.WatchNames, ", ")
		}
		policyRules := "<NONE>"
		if len(p.PolicyRules) > 0 {
			policyRules = strings.Join(p.PolicyRules, ", ")
		}

		// Detect issues
		var xrayIssues []string
		if !p.Enabled {
			xrayIssues = append(xrayIssues, "Policy disabled")
		}
		if !p.BlockDownloads {
			xrayIssues = append(xrayIssues, "Downloads not blocked")
		}
		if len(p.WatchNames) == 0 {
			xrayIssues = append(xrayIssues, "No watches configured")
		}
		issuesStr := "<NONE>"
		if len(xrayIssues) > 0 {
			issuesStr = strings.Join(xrayIssues, "; ")
		}

		// Uniform schema: Namespace, Name, Scope, Target, Type, Configuration, Details, Issues
		xrayNs := "<CLUSTER>"
		xrayScope := "Repository"
		xrayTarget := watchNames
		if xrayTarget == "<NONE>" {
			xrayTarget = "All artifacts"
		}
		xrayType := "JFrog Xray"
		xrayConfig := fmt.Sprintf("Enabled: %s, Threshold: %s", shared.FormatBool(p.Enabled), p.SeverityThreshold)
		xrayDetails := fmt.Sprintf("Block Downloads: %s, Rules: %s", shared.FormatBool(p.BlockDownloads), policyRules)

		xrayRows = append(xrayRows, []string{
			xrayNs,
			p.Name,
			xrayScope,
			xrayTarget,
			xrayType,
			xrayConfig,
			xrayDetails,
			issuesStr,
		})
	}

	// Build Deepfence rows
	for _, p := range deepfencePolicies {
		// Detect issues
		var deepfenceIssues []string
		if !p.Enabled {
			deepfenceIssues = append(deepfenceIssues, "Policy disabled")
		}
		if !p.ScanningEnabled {
			deepfenceIssues = append(deepfenceIssues, "Scanning disabled")
		}
		if !p.BlockMalware {
			deepfenceIssues = append(deepfenceIssues, "Malware not blocked")
		}
		issuesStr := "<NONE>"
		if len(deepfenceIssues) > 0 {
			issuesStr = strings.Join(deepfenceIssues, "; ")
		}

		// Uniform schema: Namespace, Name, Scope, Target, Type, Configuration, Details, Issues
		deepfenceNs := "<CLUSTER>"
		deepfenceScope := "Cluster"
		deepfenceTarget := "Container images"
		deepfenceType := "Deepfence"
		deepfenceConfig := fmt.Sprintf("Enabled: %s, Threshold: %s", shared.FormatBool(p.Enabled), p.SeverityThreshold)
		deepfenceDetails := fmt.Sprintf("Scanning: %s, Block Malware: %s", shared.FormatBool(p.ScanningEnabled), shared.FormatBool(p.BlockMalware))

		deepfenceRows = append(deepfenceRows, []string{
			deepfenceNs,
			p.Name,
			deepfenceScope,
			deepfenceTarget,
			deepfenceType,
			deepfenceConfig,
			deepfenceDetails,
			issuesStr,
		})
	}

	// Build Qualys rows
	for _, p := range qualysPolicies {
		// Detect issues
		var qualysIssues []string
		if !p.Enabled {
			qualysIssues = append(qualysIssues, "Policy disabled")
		}
		if !p.ScanningEnabled {
			qualysIssues = append(qualysIssues, "Scanning disabled")
		}
		if !p.BlockOnCritical {
			qualysIssues = append(qualysIssues, "Critical not blocked")
		}
		issuesStr := "<NONE>"
		if len(qualysIssues) > 0 {
			issuesStr = strings.Join(qualysIssues, "; ")
		}

		// Uniform schema: Namespace, Name, Scope, Target, Type, Configuration, Details, Issues
		qualysNs := "<CLUSTER>"
		qualysScope := "Cluster"
		qualysTarget := "Container images"
		qualysType := "Qualys"
		qualysConfig := fmt.Sprintf("Enabled: %s, Threshold: %s", shared.FormatBool(p.Enabled), p.SeverityThreshold)
		qualysDetails := fmt.Sprintf("Scanning: %s, Block on Critical: %s", shared.FormatBool(p.ScanningEnabled), shared.FormatBool(p.BlockOnCritical))

		qualysRows = append(qualysRows, []string{
			qualysNs,
			p.Name,
			qualysScope,
			qualysTarget,
			qualysType,
			qualysConfig,
			qualysDetails,
			issuesStr,
		})
	}

	// Build Docker Scout rows
	for _, p := range dockerScoutPolicies {
		// Detect issues
		var dockerScoutIssues []string
		if !p.Enabled {
			dockerScoutIssues = append(dockerScoutIssues, "Policy disabled")
		}
		if !p.SBOMEnabled {
			dockerScoutIssues = append(dockerScoutIssues, "SBOM disabled")
		}
		if !p.PolicyCheck {
			dockerScoutIssues = append(dockerScoutIssues, "Policy check disabled")
		}
		issuesStr := "<NONE>"
		if len(dockerScoutIssues) > 0 {
			issuesStr = strings.Join(dockerScoutIssues, "; ")
		}

		// Uniform schema: Namespace, Name, Scope, Target, Type, Configuration, Details, Issues
		dockerScoutNs := "<CLUSTER>"
		dockerScoutScope := "Cluster"
		dockerScoutTarget := "Container images"
		dockerScoutType := "Docker Scout"
		dockerScoutConfig := fmt.Sprintf("Enabled: %s, Threshold: %s", shared.FormatBool(p.Enabled), p.SeverityThreshold)
		dockerScoutDetails := fmt.Sprintf("SBOM: %s, Policy Check: %s", shared.FormatBool(p.SBOMEnabled), shared.FormatBool(p.PolicyCheck))

		dockerScoutRows = append(dockerScoutRows, []string{
			dockerScoutNs,
			p.Name,
			dockerScoutScope,
			dockerScoutTarget,
			dockerScoutType,
			dockerScoutConfig,
			dockerScoutDetails,
			issuesStr,
		})
	}

	// Suppress unused variable warnings for Azure policies
	_ = azureImagePolicies

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

		// Detect issues
		var allowIssues []string
		if !entry.SignatureRequired {
			allowIssues = append(allowIssues, "No signature required")
		}
		if entry.AllowedPattern == "*" || strings.Contains(entry.AllowedPattern, "**") {
			allowIssues = append(allowIssues, "Wildcard pattern")
		}
		if conditions == "<NONE>" {
			allowIssues = append(allowIssues, "No conditions")
		}
		allowIssuesStr := "<NONE>"
		if len(allowIssues) > 0 {
			allowIssuesStr = strings.Join(allowIssues, "; ")
		}

		// Uniform schema: Namespace, Name, Scope, Target, Type, Configuration, Details, Issues
		allowedNs := namespaces
		if allowedNs == "<ALL>" {
			allowedNs = "<CLUSTER>"
		}
		allowedTarget := entry.AllowedPattern
		allowedType := entry.Controller
		allowedConfig := fmt.Sprintf("Signature: %s", sigReq)
		allowedDetails := fmt.Sprintf("Conditions: %s", conditions)

		allowedImagesRows = append(allowedImagesRows, []string{
			allowedNs,
			entry.PolicyName,
			entry.Scope,
			allowedTarget,
			allowedType,
			allowedConfig,
			allowedDetails,
			allowIssuesStr,
		})
	}

	// Build blocked images rows
	for _, entry := range blockedImages {
		namespaces := "<ALL>"
		if len(entry.Namespaces) > 0 {
			namespaces = strings.Join(entry.Namespaces, ", ")
		}

		reason := entry.Reason
		if reason == "" {
			reason = "Blocked by policy"
		}

		effect := entry.Effect
		if effect == "" {
			effect = "deny"
		}

		// Detect issues (blocked images are generally good security)
		var blockIssues []string
		if effect != "deny" {
			blockIssues = append(blockIssues, "Effect not deny")
		}
		blockIssuesStr := "<NONE>"
		if len(blockIssues) > 0 {
			blockIssuesStr = strings.Join(blockIssues, "; ")
		}

		// Uniform schema: Namespace, Name, Scope, Target, Type, Configuration, Details, Issues
		blockedNs := namespaces
		if blockedNs == "<ALL>" {
			blockedNs = "<CLUSTER>"
		}
		blockedTarget := entry.BlockedPattern
		blockedType := entry.Controller
		blockedConfig := fmt.Sprintf("Effect: %s", effect)
		blockedDetails := fmt.Sprintf("Reason: %s", reason)

		blockedImagesRows = append(blockedImagesRows, []string{
			blockedNs,
			entry.PolicyName,
			entry.Scope,
			blockedTarget,
			blockedType,
			blockedConfig,
			blockedDetails,
			blockIssuesStr,
		})
	}

	// Build unified policies rows
	for _, policy := range unifiedPolicies {
		ns := policy.Namespace
		if ns == "" {
			ns = "<ALL>"
		}
		unifiedPoliciesRows = append(unifiedPoliciesRows, []string{
			ns,
			policy.Tool,
			policy.Name,
			policy.Scope,
			policy.Type,
			policy.Details,
		})
	}


	// Build loot
	loot := shared.NewLootBuilder()

	loot.Section("Image-Admission-Commands").SetHeader(`#####################################
##### Image Admission Controllers
#####################################
#
# Image admission controllers verify container images before deployment
# They can enforce signatures, attestations, and vulnerability scanning
#`)

	if len(controllers) == 0 {
		loot.Section("Image-Admission-Commands").Add("\n# ═══════════════════════════════════════════════════════════")
		loot.Section("Image-Admission-Commands").Add("# [CRITICAL] NO IMAGE ADMISSION CONTROLLERS DETECTED!")
		loot.Section("Image-Admission-Commands").Add("# ═══════════════════════════════════════════════════════════")
		loot.Section("Image-Admission-Commands").Add("#")
		loot.Section("Image-Admission-Commands").Add("# Any image from any registry can be deployed to this cluster")
		loot.Section("Image-Admission-Commands").Add("")
		loot.Section("Image-Admission-Commands").Add("# Deploy image from any registry:")
		loot.Section("Image-Admission-Commands").Add("kubectl run test --image=<any-registry>/<any-image>:<any-tag>")
		loot.Section("Image-Admission-Commands").Add("")
	} else {
		loot.Section("Image-Admission-Commands").Add("\n# ═══════════════════════════════════════════════════════════")
		loot.Section("Image-Admission-Commands").Addf("# Detected %d image admission controller(s)", len(controllers))
		loot.Section("Image-Admission-Commands").Add("# ═══════════════════════════════════════════════════════════")
		for _, c := range controllers {
			loot.Section("Image-Admission-Commands").Addf("# - %s (%s)", c.Name, c.Type)
		}
		loot.Section("Image-Admission-Commands").Add("")
	}

	// Add enumeration commands for detected tools
	if portierisController.Name != "" {
		loot.Section("Image-Admission-Commands").Add("\n# Portieris:")
		loot.Section("Image-Admission-Commands").Add("kubectl get clusterimagepolicies")
		loot.Section("Image-Admission-Commands").Add("kubectl get imagepolicies --all-namespaces")
		loot.Section("Image-Admission-Commands").Add("kubectl get pods -n portieris")
	}

	if connaisseurController.Name != "" {
		loot.Section("Image-Admission-Commands").Add("\n# Connaisseur:")
		loot.Section("Image-Admission-Commands").Add("kubectl get configmap connaisseur-config -n connaisseur -o yaml")
		loot.Section("Image-Admission-Commands").Add("kubectl get pods -n connaisseur")
	}

	if ratifyController.Name != "" {
		loot.Section("Image-Admission-Commands").Add("\n# Ratify:")
		loot.Section("Image-Admission-Commands").Add("kubectl get verifiers --all-namespaces")
		loot.Section("Image-Admission-Commands").Add("kubectl get stores --all-namespaces")
		loot.Section("Image-Admission-Commands").Add("kubectl get pods -n gatekeeper-system | grep ratify")
	}

	if kritisController.Name != "" {
		loot.Section("Image-Admission-Commands").Add("\n# Kritis:")
		loot.Section("Image-Admission-Commands").Add("kubectl get attestationauthorities --all-namespaces")
		loot.Section("Image-Admission-Commands").Add("kubectl get imagesecuritypolicies --all-namespaces")
	}

	if sigstoreController.Name != "" {
		loot.Section("Image-Admission-Commands").Add("\n# Sigstore Policy Controller:")
		loot.Section("Image-Admission-Commands").Add("kubectl get clusterimagepolicies.policy.sigstore.dev")
		loot.Section("Image-Admission-Commands").Add("kubectl get pods -n cosign-system")
		loot.Section("Image-Admission-Commands").Add("kubectl get pods -n sigstore-system")
	}

	if gcpBinAuthController.Name != "" {
		loot.Section("Image-Admission-Commands").Add("\n# GCP Binary Authorization:")
		loot.Section("Image-Admission-Commands").Add("gcloud container binauthz policy export")
		loot.Section("Image-Admission-Commands").Add("gcloud container binauthz attestors list")
	}

	if aquaController.Name != "" {
		loot.Section("Image-Admission-Commands").Add("\n# Aqua Security:")
		loot.Section("Image-Admission-Commands").Add("kubectl get pods -n aqua")
		loot.Section("Image-Admission-Commands").Add("kubectl get configmap aqua-enforcer-config -n aqua -o yaml")
		loot.Section("Image-Admission-Commands").Add("kubectl get vulnerabilityreports -A")
	}

	if prismaController.Name != "" {
		loot.Section("Image-Admission-Commands").Add("\n# Prisma Cloud (Twistlock):")
		loot.Section("Image-Admission-Commands").Add("kubectl get pods -n twistlock")
		loot.Section("Image-Admission-Commands").Add("kubectl get daemonset -n twistlock")
		loot.Section("Image-Admission-Commands").Addf("kubectl get validatingwebhookconfiguration %s -o yaml", prismaController.WebhookName)
	}

	if sysdigController.Name != "" {
		loot.Section("Image-Admission-Commands").Add("\n# Sysdig Secure:")
		loot.Section("Image-Admission-Commands").Add("kubectl get pods -n sysdig-agent")
		loot.Section("Image-Admission-Commands").Add("kubectl get pods -n sysdig-admission-controller")
	}

	if neuvectorController.Name != "" {
		loot.Section("Image-Admission-Commands").Add("\n# NeuVector:")
		loot.Section("Image-Admission-Commands").Add("kubectl get pods -n neuvector")
		loot.Section("Image-Admission-Commands").Add("kubectl get nvadmissioncontrolsecurityrules -A")
		loot.Section("Image-Admission-Commands").Add("kubectl get nvsecurityrules -A")
	}

	if stackroxController.Name != "" {
		loot.Section("Image-Admission-Commands").Add("\n# StackRox / Red Hat ACS:")
		loot.Section("Image-Admission-Commands").Add("kubectl get pods -n stackrox")
		loot.Section("Image-Admission-Commands").Add("kubectl get deployment sensor -n stackrox -o yaml")
		loot.Section("Image-Admission-Commands").Add("kubectl get deployment admission-control -n stackrox -o yaml")
	}

	if snykController.Name != "" {
		loot.Section("Image-Admission-Commands").Add("\n# Snyk Container:")
		loot.Section("Image-Admission-Commands").Add("kubectl get pods -n snyk-monitor")
		loot.Section("Image-Admission-Commands").Addf("kubectl get validatingwebhookconfiguration %s -o yaml", snykController.WebhookName)
	}

	if anchoreController.Name != "" {
		loot.Section("Image-Admission-Commands").Add("\n# Anchore Enterprise:")
		loot.Section("Image-Admission-Commands").Add("kubectl get pods -n anchore")
		loot.Section("Image-Admission-Commands").Addf("kubectl get validatingwebhookconfiguration %s -o yaml", anchoreController.WebhookName)
	}

	if trivyController.Name != "" {
		loot.Section("Image-Admission-Commands").Add("\n# Trivy Operator:")
		loot.Section("Image-Admission-Commands").Add("kubectl get pods -n trivy-system")
		loot.Section("Image-Admission-Commands").Add("kubectl get vulnerabilityreports -A")
		loot.Section("Image-Admission-Commands").Add("kubectl get configauditreports -A")
	}

	if kubewardenController.Name != "" {
		loot.Section("Image-Admission-Commands").Add("\n# Kubewarden:")
		loot.Section("Image-Admission-Commands").Add("kubectl get pods -n kubewarden")
		loot.Section("Image-Admission-Commands").Add("kubectl get clusteradmissionpolicies")
		loot.Section("Image-Admission-Commands").Add("kubectl get admissionpolicies -A")
	}

	if notationController.Name != "" {
		loot.Section("Image-Admission-Commands").Add("\n# Notation/Notary v2:")
		loot.Section("Image-Admission-Commands").Add("kubectl get trustpolicies.notation.x-k8s.io -A")
		loot.Section("Image-Admission-Commands").Add("kubectl get truststores.notation.x-k8s.io -A")
	}

	if harborController.Name != "" {
		loot.Section("Image-Admission-Commands").Add("\n# Harbor:")
		loot.Section("Image-Admission-Commands").Add("kubectl get pods -n harbor")
	}

	if clairController.Name != "" {
		loot.Section("Image-Admission-Commands").Add("\n# Clair:")
		loot.Section("Image-Admission-Commands").Add("kubectl get pods -n clair")
	}

	if awsSignerController.Name != "" {
		loot.Section("Image-Admission-Commands").Add("\n# AWS Signer:")
		loot.Section("Image-Admission-Commands").Add("aws signer list-signing-profiles")
	}

	if azurePolicyController.Name != "" {
		loot.Section("Image-Admission-Commands").Add("\n# Azure Policy for AKS:")
		loot.Section("Image-Admission-Commands").Add("kubectl get pods -n kube-system | grep azure-policy")
		loot.Section("Image-Admission-Commands").Add("kubectl get constrainttemplates")
	}

	if wizController.Name != "" {
		loot.Section("Image-Admission-Commands").Add("\n# Wiz:")
		loot.Section("Image-Admission-Commands").Add("kubectl get pods -A | grep wiz")
	}

	if laceworkController.Name != "" {
		loot.Section("Image-Admission-Commands").Add("\n# Lacework:")
		loot.Section("Image-Admission-Commands").Add("kubectl get pods -n lacework")
	}

	if cosignController.Name != "" {
		loot.Section("Image-Admission-Commands").Add("\n# Cosign (Standalone):")
		loot.Section("Image-Admission-Commands").Add("kubectl get pods -A | grep cosign")
	}

	if fluxImageController.Name != "" {
		loot.Section("Image-Admission-Commands").Add("\n# Flux Image Automation:")
		loot.Section("Image-Admission-Commands").Add("kubectl get imagepolicies.image.toolkit.fluxcd.io -A")
		loot.Section("Image-Admission-Commands").Add("kubectl get imagerepositories.image.toolkit.fluxcd.io -A")
	}

	if xrayController.Name != "" {
		loot.Section("Image-Admission-Commands").Add("\n# JFrog Xray:")
		loot.Section("Image-Admission-Commands").Add("kubectl get pods -A | grep xray")
	}

	if deepfenceController.Name != "" {
		loot.Section("Image-Admission-Commands").Add("\n# Deepfence ThreatMapper:")
		loot.Section("Image-Admission-Commands").Add("kubectl get pods -n deepfence")
	}

	if qualysController.Name != "" {
		loot.Section("Image-Admission-Commands").Add("\n# Qualys Container Security:")
		loot.Section("Image-Admission-Commands").Add("kubectl get pods -A | grep qualys")
	}

	if dockerScoutController.Name != "" {
		loot.Section("Image-Admission-Commands").Add("\n# Docker Scout:")
		loot.Section("Image-Admission-Commands").Add("kubectl get pods -A | grep scout")
	}

	loot.Section("Image-Admission-Commands").Add("")

	// Add deploy commands section for allowed images
	if len(allowedImages) > 0 {
		loot.Section("Image-Admission-Deploy-Commands").SetHeader(`#####################################
##### Image Admission Deploy Commands
#####################################
# Commands to deploy images that are allowed by the admission policies
# Use these to test what images can actually be deployed to the cluster
`)

		for _, entry := range allowedImages {
			if entry.DeployCommand != "" {
				loot.Section("Image-Admission-Deploy-Commands").Add("")
				loot.Section("Image-Admission-Deploy-Commands").Addf("# %s - %s", entry.Controller, entry.PolicyName)
				loot.Section("Image-Admission-Deploy-Commands").Addf("# Scope: %s, Pattern: %s", entry.Scope, entry.AllowedPattern)
				if entry.Conditions != "" {
					loot.Section("Image-Admission-Deploy-Commands").Addf("# Conditions: %s", entry.Conditions)
				}
				loot.Section("Image-Admission-Deploy-Commands").Add(entry.DeployCommand)
			}
		}
	}

	lootFiles := loot.Build()

	// Build tables
	tables := []internal.TableFile{
		{
			Name:   "Image-Admission-Controllers",
			Header: controllerHeaders,
			Body:   controllerRows,
		},
	}

	// Add images table
	if len(imagesRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Image-Admission-Images",
			Header: imagesHeaders,
			Body:   imagesRows,
		})
	}

	// Add unified policies table (always shown)
	if len(unifiedPoliciesRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Image-Admission-Policy-Overview",
			Header: unifiedPoliciesHeaders,
			Body:   unifiedPoliciesRows,
		})
	}

	// Detailed tables (only shown with --detailed flag)
	if detailed {
		if len(findingRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Image-Admission-Policies-Detail-Policies",
				Header: findingHeaders,
				Body:   findingRows,
			})
		}

		if len(allowedImagesRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Image-Admission-Allowed-Images-Policies",
				Header: allowedImagesHeaders,
				Body:   allowedImagesRows,
			})
		}

		if len(blockedImagesRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Image-Admission-Blocked-Images-Policies",
				Header: blockedImagesHeaders,
				Body:   blockedImagesRows,
			})
		}

		// Cloud provider tables (only with --detailed and --cloud-provider)
		if len(cloudPolicyRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Image-Admission-Cloud-Policies",
				Header: cloudPolicyHeaders,
				Body:   cloudPolicyRows,
			})
		}

		if len(gcpAttestorRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Image-Admission-GCP-Attestors-Policies",
				Header: gcpAttestorHeaders,
				Body:   gcpAttestorRows,
			})
		}

		if len(awsScanConfigRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Image-Admission-AWS-ECR-Scan-Policies",
				Header: awsScanConfigHeaders,
				Body:   awsScanConfigRows,
			})
		}

		if len(awsSignerProfileRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Image-Admission-AWS-Signer-Policies",
				Header: awsSignerProfileHeaders,
				Body:   awsSignerProfileRows,
			})
		}

		// Security tool detailed tables
		if len(aquaRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Image-Admission-Aqua-Policies",
				Header: aquaHeaders,
				Body:   aquaRows,
			})
		}

		if len(prismaRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Image-Admission-Prisma-Policies",
				Header: prismaHeaders,
				Body:   prismaRows,
			})
		}

		if len(sysdigRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Image-Admission-Sysdig-Policies",
				Header: sysdigHeaders,
				Body:   sysdigRows,
			})
		}

		if len(neuvectorRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Image-Admission-NeuVector-Policies",
				Header: neuvectorHeaders,
				Body:   neuvectorRows,
			})
		}

		if len(stackroxRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Image-Admission-StackRox-Policies",
				Header: stackroxHeaders,
				Body:   stackroxRows,
			})
		}

		if len(snykRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Image-Admission-Snyk-Policies",
				Header: snykHeaders,
				Body:   snykRows,
			})
		}

		if len(anchoreRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Image-Admission-Anchore-Policies",
				Header: anchoreHeaders,
				Body:   anchoreRows,
			})
		}

		if len(trivyRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Image-Admission-Trivy-Policies",
				Header: trivyHeaders,
				Body:   trivyRows,
			})
		}

		if len(notationRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Image-Admission-Notation-Policies",
				Header: notationHeaders,
				Body:   notationRows,
			})
		}

		if len(harborRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Image-Admission-Harbor-Policies",
				Header: harborHeaders,
				Body:   harborRows,
			})
		}

		if len(clairRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Image-Admission-Clair-Policies",
				Header: clairHeaders,
				Body:   clairRows,
			})
		}

		if len(wizRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Image-Admission-Wiz-Policies",
				Header: wizHeaders,
				Body:   wizRows,
			})
		}

		if len(laceworkRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Image-Admission-Lacework-Policies",
				Header: laceworkHeaders,
				Body:   laceworkRows,
			})
		}

		if len(cosignRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Image-Admission-Cosign-Policies",
				Header: cosignHeaders,
				Body:   cosignRows,
			})
		}

		if len(fluxImageRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Image-Admission-Flux-Policies",
				Header: fluxImageHeaders,
				Body:   fluxImageRows,
			})
		}

		if len(xrayRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Image-Admission-JFrogXray-Policies",
				Header: xrayHeaders,
				Body:   xrayRows,
			})
		}

		if len(deepfenceRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Image-Admission-Deepfence-Policies",
				Header: deepfenceHeaders,
				Body:   deepfenceRows,
			})
		}

		if len(qualysRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Image-Admission-Qualys-Policies",
				Header: qualysHeaders,
				Body:   qualysRows,
			})
		}

		if len(dockerScoutRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Image-Admission-DockerScout-Policies",
				Header: dockerScoutHeaders,
				Body:   dockerScoutRows,
			})
		}
	}

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
		return controller, policies
	}

	// Verify Portieris pods are running and verify images
	podsRunning, _, imageVerified := verifyPodsRunningWithImage(ctx, clientset, []string{"portieris", "ibm-system"}, "app=portieris", "portieris")
	if !podsRunning {
		controller.Status = "not-running"
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
	for _, p := range policies {
		for _, r := range p.Repositories {
			if r.Policy == "trust" {
				controller.SignatureReqs = true
			}
		}
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
		return controller, policies
	}

	// Verify Connaisseur pods are running and verify images
	podsRunning, _, imageVerified := verifyPodsRunningWithImage(ctx, clientset, []string{"connaisseur"}, "app.kubernetes.io/name=connaisseur", "connaisseur")
	if !podsRunning {
		// Try alternate label selector
		podsRunning, _, imageVerified = verifyPodsRunningWithImage(ctx, clientset, []string{"connaisseur"}, "app=connaisseur", "connaisseur")
	}
	if !podsRunning {
		controller.Status = "not-running"
		return controller, policies
	}

	controller.Status = "active"
	controller.ImageVerified = imageVerified
	// Connaisseur uses ConfigMap for configuration
	// We can try to parse it but it's YAML inside a ConfigMap
	controller.SignatureReqs = true // Connaisseur is signature-focused

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
		return controller, policies
	}

	// Verify Ratify pods are running (could be in gatekeeper-system or ratify-system)
	podsRunning, _, imageVerified := verifyPodsRunningWithImage(ctx, clientset, []string{"gatekeeper-system", "ratify-system", "ratify"}, "app=ratify", "ratify")
	if !podsRunning {
		// Try Gatekeeper pods as Ratify often runs with Gatekeeper
		podsRunning, _, imageVerified = verifyPodsRunningWithImage(ctx, clientset, []string{"gatekeeper-system"}, "control-plane=controller-manager", "ratify")
	}
	if !podsRunning {
		controller.Status = "not-running"
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
		return controller, policies
	}

	// Verify Kritis pods are running
	podsRunning, _ := verifyPodsRunning(ctx, clientset, []string{"kritis", "kritis-system"}, "app=kritis")
	if !podsRunning {
		podsRunning, _ = verifyPodsRunning(ctx, clientset, []string{"kritis", "kritis-system"}, "app.kubernetes.io/name=kritis")
	}
	if !podsRunning {
		controller.Status = "not-running"
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
		return controller
	}

	controller.Status = "active"

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

				findings = append(findings, ImagePolicyFinding{
					Controller: "Kyverno",
					PolicyName: name,
					Scope:      "Cluster",
					Policy:     action,
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

							findings = append(findings, ImagePolicyFinding{
								Controller: "Gatekeeper",
								PolicyName: fmt.Sprintf("%s/%s", kind, c.GetName()),
								Scope:      "Cluster",
								Policy:     action,
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
		return controller, policies
	}

	// Verify Sigstore Policy Controller pods are running
	podsRunning, _ := verifyPodsRunning(ctx, clientset, []string{"cosign-system", "sigstore-system", "policy-controller-system"}, "app=policy-controller")
	if !podsRunning {
		podsRunning, _ = verifyPodsRunning(ctx, clientset, []string{"cosign-system", "sigstore-system"}, "control-plane=policy-controller")
	}
	if !podsRunning {
		controller.Status = "not-running"
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
		return controller
	}

	controller.Status = "active"


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
			}

			policies = append(policies, policy)
			controller.PolicyCount++
		}
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
		}
	} else if hasVulnReports || hasConfigReports {
		controller.Status = "reports-only"
	} else {
		controller.Status = "webhook-only"
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
			if admission.MatchesEngineWebhook(name, "clair") {
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
		admission.GetExpectedNamespaces("clair"), "", "clair")

	if podsRunning {
		controller.Status = "active"
		controller.Namespace = ns
		controller.ImageVerified = imageVerified
	} else {
		controller.Status = "webhook-only"
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
			if admission.MatchesEngineWebhook(name, "wiz") {
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
		admission.GetExpectedNamespaces("wiz"), "app.kubernetes.io/name=wiz-sensor", "wiz")

	if podsRunning {
		controller.Status = "active"
		controller.Namespace = ns
		controller.ImageVerified = imageVerified
	} else {
		controller.Status = "webhook-only"
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
			if admission.MatchesEngineWebhook(name, "lacework") {
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
		admission.GetExpectedNamespaces("lacework"), "", "lacework")

	if podsRunning {
		controller.Status = "active"
		controller.Namespace = ns
		controller.ImageVerified = imageVerified
	} else {
		controller.Status = "webhook-only"
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
		admission.GetExpectedNamespaces("cosign"), "", "cosign")

	if podsRunning {
		controller.Status = "active"
		controller.Namespace = ns
		controller.ImageVerified = imageVerified
	} else {
		controller.Status = "webhook-only"
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
		admission.GetExpectedNamespaces("flux-image"), "app=image-automation-controller", "flux-image")

	if podsRunning {
		controller.Status = "active"
		controller.Namespace = ns
		controller.ImageVerified = imageVerified
	} else {
		controller.Status = "CRDs-only"
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
		admission.GetExpectedNamespaces("jfrog-xray"), "", "jfrog-xray")

	if podsRunning {
		controller.Status = "active"
		controller.Namespace = ns
		controller.ImageVerified = imageVerified
	} else {
		controller.Status = "webhook-only"
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
			if admission.MatchesEngineWebhook(name, "deepfence") {
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
		admission.GetExpectedNamespaces("deepfence"), "", "deepfence")

	if podsRunning {
		controller.Status = "active"
		controller.Namespace = ns
		controller.ImageVerified = imageVerified
	} else {
		controller.Status = "webhook-only"
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
			if admission.MatchesEngineWebhook(name, "qualys") {
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
		admission.GetExpectedNamespaces("qualys"), "", "qualys")

	if podsRunning {
		controller.Status = "active"
		controller.Namespace = ns
		controller.ImageVerified = imageVerified
	} else {
		controller.Status = "webhook-only"
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
			if admission.MatchesEngineWebhook(name, "docker-scout") {
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
		admission.GetExpectedNamespaces("docker-scout"), "", "docker-scout")

	if podsRunning {
		controller.Status = "active"
		controller.Namespace = ns
		controller.ImageVerified = imageVerified
	} else {
		controller.Status = "webhook-only"
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
			// Build source resource info
			sourceResource := fmt.Sprintf("ValidatingWebhookConfiguration/%s", c.WebhookName)
			enumerateCmd := fmt.Sprintf("kubectl get validatingwebhookconfiguration %s -o yaml", c.WebhookName)

			// GCP Binary Authorization typically uses always_deny or require-attestation
			// Add break-glass bypass information
			entries = append(entries, AllowedImageEntry{
				Controller:        "GCP Binary Authorization",
				PolicyName:        "Break-Glass Bypass",
				Scope:             "pod",
				AllowedPattern:    "*",
				SignatureRequired: false,
				Conditions:        "BYPASS: Add break-glass annotation to pod spec",
				SourceResource:    sourceResource,
				EnumerateCmd:      enumerateCmd,
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
				SourceResource:    sourceResource,
				EnumerateCmd:      enumerateCmd,
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

// extractBlockedImages extracts all blocked/denied image patterns from detected policies
// This shows what images are explicitly blacklisted and cannot be deployed
func extractBlockedImages(
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
	stackroxPolicies []StackRoxPolicy,
	snykPolicies []SnykContainerPolicy,
	trivyPolicies []TrivyOperatorPolicy,
	policyEngineFindings []ImagePolicyFinding,
) []BlockedImageEntry {
	var entries []BlockedImageEntry

	// If no controllers, nothing is blocked
	if len(controllers) == 0 {
		return entries
	}

	// Check for GCP Binary Authorization blocking
	for _, c := range controllers {
		if c.Type == "gcp-binauth" {
			// Binary Auth typically denies by default if attestation is required
			entries = append(entries, BlockedImageEntry{
				Controller:     "GCP Binary Authorization",
				PolicyName:     "Default Deny",
				Scope:          "cluster",
				BlockedPattern: "*",
				Reason:         "Images without attestation are blocked by default",
				Effect:         "deny",
				SourceResource: fmt.Sprintf("ValidatingWebhookConfiguration/%s", c.WebhookName),
			})
		}
	}

	// Extract denies from Portieris policies
	for _, policy := range portierisPolicies {
		for _, repo := range policy.Repositories {
			if repo.Policy == "deny" || repo.Policy == "reject" {
				scope := "namespace"
				var namespaces []string
				if policy.IsClusterPolicy {
					scope = "cluster"
				} else {
					namespaces = append(namespaces, policy.Namespace)
				}

				entries = append(entries, BlockedImageEntry{
					Controller:     "Portieris",
					PolicyName:     policy.Name,
					Scope:          scope,
					Namespaces:     namespaces,
					BlockedPattern: repo.Name,
					Reason:         "Explicitly denied in policy",
					Effect:         "deny",
				})
			}
		}
	}

	// Extract denies from Connaisseur policies
	for _, policy := range connaisseurPolicies {
		if policy.Rule == "deny" || policy.Rule == "reject" {
			entries = append(entries, BlockedImageEntry{
				Controller:     "Connaisseur",
				PolicyName:     policy.Name,
				Scope:          "cluster",
				BlockedPattern: policy.Pattern,
				Reason:         "Explicitly denied in policy",
				Effect:         "deny",
			})
		}
	}

	// Extract from Sigstore policies (reject mode)
	for _, policy := range sigstorePolicies {
		if policy.Mode == "reject" || policy.Mode == "enforce" {
			// In enforce/reject mode, unsigned images are blocked
			for _, img := range policy.Images {
				entries = append(entries, BlockedImageEntry{
					Controller:     "Sigstore Policy Controller",
					PolicyName:     policy.Name,
					Scope:          "cluster",
					BlockedPattern: fmt.Sprintf("%s (unsigned)", img),
					Reason:         "Images without valid signatures are rejected",
					Effect:         "deny",
				})
			}
		}
	}

	// Extract from Aqua Security policies
	for _, policy := range aquaPolicies {
		if policy.BlockUnregistered {
			entries = append(entries, BlockedImageEntry{
				Controller:     "Aqua Security",
				PolicyName:     policy.Name,
				Scope:          "cluster",
				BlockedPattern: "* (unregistered)",
				Reason:         "Unregistered images are blocked",
				Effect:         "deny",
			})
		}
		if policy.BlockMalware {
			entries = append(entries, BlockedImageEntry{
				Controller:     "Aqua Security",
				PolicyName:     policy.Name,
				Scope:          "cluster",
				BlockedPattern: "* (malware detected)",
				Reason:         "Images with malware are blocked",
				Effect:         "deny",
			})
		}
		if policy.CVSSThreshold > 0 {
			entries = append(entries, BlockedImageEntry{
				Controller:     "Aqua Security",
				PolicyName:     policy.Name,
				Scope:          "cluster",
				BlockedPattern: fmt.Sprintf("* (CVSS > %.1f)", policy.CVSSThreshold),
				Reason:         fmt.Sprintf("Images with vulnerabilities above CVSS %.1f are blocked", policy.CVSSThreshold),
				Effect:         "deny",
			})
		}
	}

	// Extract from Prisma Cloud policies
	for _, policy := range prismaPolicies {
		if policy.BlockMalware {
			entries = append(entries, BlockedImageEntry{
				Controller:     "Prisma Cloud",
				PolicyName:     policy.Name,
				Scope:          "cluster",
				BlockedPattern: "* (malware detected)",
				Reason:         "Images with malware are blocked",
				Effect:         "deny",
			})
		}
		if policy.BlockThreshold != "" {
			entries = append(entries, BlockedImageEntry{
				Controller:     "Prisma Cloud",
				PolicyName:     policy.Name,
				Scope:          "cluster",
				BlockedPattern: fmt.Sprintf("* (%s+ severity)", policy.BlockThreshold),
				Reason:         fmt.Sprintf("Images with %s+ severity vulnerabilities are blocked", policy.BlockThreshold),
				Effect:         "deny",
			})
		}
	}

	// Extract from Sysdig Secure policies
	for _, policy := range sysdigPolicies {
		if policy.BlockOnFailure {
			entries = append(entries, BlockedImageEntry{
				Controller:     "Sysdig Secure",
				PolicyName:     policy.Name,
				Scope:          "cluster",
				BlockedPattern: "* (scan failed)",
				Reason:         "Images that fail scanning are blocked",
				Effect:         "deny",
			})
		}
		if policy.CVSSThreshold > 0 {
			entries = append(entries, BlockedImageEntry{
				Controller:     "Sysdig Secure",
				PolicyName:     policy.Name,
				Scope:          "cluster",
				BlockedPattern: fmt.Sprintf("* (CVSS > %.1f)", policy.CVSSThreshold),
				Reason:         fmt.Sprintf("Images with vulnerabilities above CVSS %.1f are blocked", policy.CVSSThreshold),
				Effect:         "deny",
			})
		}
	}

	// Extract from NeuVector policies
	for _, policy := range neuvectorPolicies {
		if policy.Mode == "Protect" {
			if policy.BlockHighCVE {
				entries = append(entries, BlockedImageEntry{
					Controller:     "NeuVector",
					PolicyName:     policy.Name,
					Scope:          "namespace",
					Namespaces:     []string{policy.Namespace},
					BlockedPattern: "* (high CVE)",
					Reason:         "Images with high CVE vulnerabilities are blocked in Protect mode",
					Effect:         "deny",
				})
			}
			// Add denied registries
			for _, reg := range policy.DeniedRegistries {
				entries = append(entries, BlockedImageEntry{
					Controller:     "NeuVector",
					PolicyName:     policy.Name,
					Scope:          "namespace",
					Namespaces:     []string{policy.Namespace},
					BlockedPattern: reg + "/*",
					Reason:         "Registry is on deny list",
					Effect:         "deny",
				})
			}
		}
	}

	// Extract from StackRox policies
	for _, policy := range stackroxPolicies {
		if policy.EnforcementAction == "SCALE_TO_ZERO_DEPLOYMENT" || policy.EnforcementAction == "FAIL_BUILD_ENFORCEMENT" {
			entries = append(entries, BlockedImageEntry{
				Controller:     "StackRox/RHACS",
				PolicyName:     policy.Name,
				Scope:          "cluster",
				BlockedPattern: "* (policy violation)",
				Reason:         fmt.Sprintf("Severity: %s, Action: %s", policy.Severity, policy.EnforcementAction),
				Effect:         "deny",
			})
		}
	}

	// Extract from Trivy Operator policies
	for _, policy := range trivyPolicies {
		if policy.SeverityThreshold != "" {
			entries = append(entries, BlockedImageEntry{
				Controller:     "Trivy Operator",
				PolicyName:     policy.Name,
				Scope:          "cluster",
				BlockedPattern: fmt.Sprintf("* (%s+ severity)", policy.SeverityThreshold),
				Reason:         fmt.Sprintf("Images with %s+ severity vulnerabilities flagged", policy.SeverityThreshold),
				Effect:         "audit", // Trivy typically audits rather than blocks
			})
		}
	}

	// Extract from policy engine findings (Kyverno/Gatekeeper deny rules)
	for _, finding := range policyEngineFindings {
		if strings.ToLower(finding.Policy) == "deny" || strings.Contains(strings.ToLower(finding.Policy), "block") {
			entries = append(entries, BlockedImageEntry{
				Controller:     finding.Controller,
				PolicyName:     finding.PolicyName,
				Scope:          finding.Scope,
				Namespaces:     []string{finding.Namespace},
				BlockedPattern: finding.Repository,
				Reason:         "Policy rule denies this pattern",
				Effect:         "deny",
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
	podsRunning, runningNS, imageVerified, _, _ := admission.VerifyPodsRunning(ctx, clientset, namespaces, labelSelector, controllerType)
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

// ============================================================================
// Conftest Image Policy Analysis
// ============================================================================

// ConftestImagePolicyInfo represents Conftest policies for container images
type ConftestImagePolicyInfo struct {
	Name           string
	Namespace      string
	PolicyPath     string
	TargetImages   []string
	Failures       int
	Warnings       int
	Successes      int
}

// analyzeConftestImagePolicies analyzes Conftest for image-related policies
func analyzeConftestImagePolicies(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) (ImageAdmissionController, []ConftestImagePolicyInfo) {
	controller := ImageAdmissionController{
		Name: "Conftest",
		Type: "policy-engine",
	}
	var policies []ConftestImagePolicyInfo

	// Check for Conftest deployment
	namespaces := []string{"conftest", "kube-system", "opa-system"}

	for _, ns := range namespaces {
		deployments, err := clientset.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, dep := range deployments.Items {
			if strings.Contains(strings.ToLower(dep.Name), "conftest") {
				controller.Status = "active"
				controller.Namespace = ns

				// Verify by image
				for _, container := range dep.Spec.Template.Spec.Containers {
					if strings.Contains(container.Image, "conftest") ||
						strings.Contains(container.Image, "openpolicyagent") {
						controller.ImageVerified = true
						break
					}
				}
			}
		}
	}

	// Check for Conftest ValidatingWebhookConfiguration
	webhooks, err := clientset.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, wh := range webhooks.Items {
			if strings.Contains(strings.ToLower(wh.Name), "conftest") {
				controller.WebhookName = wh.Name
				if len(wh.Webhooks) > 0 {
					controller.FailurePolicy = string(*wh.Webhooks[0].FailurePolicy)
				}
				break
			}
		}
	}

	// Check for ConfigMaps with Conftest policies
	configMaps, err := clientset.CoreV1().ConfigMaps("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, cm := range configMaps.Items {
			// Look for ConfigMaps with rego policies that might be for Conftest
			for key, data := range cm.Data {
				if strings.HasSuffix(key, ".rego") &&
					(strings.Contains(data, "deny[") || strings.Contains(data, "violation[")) {

					// Check if the policy is image-related
					if strings.Contains(data, "image") ||
						strings.Contains(data, "container") ||
						strings.Contains(data, "registry") {
						policy := ConftestImagePolicyInfo{
							Name:       cm.Name + "/" + key,
							Namespace:  cm.Namespace,
							PolicyPath: key,
						}

						// Try to extract target images from policy
						if strings.Contains(data, "allowed_registries") ||
							strings.Contains(data, "trusted_registries") ||
							strings.Contains(data, "image_registry") {
							policy.TargetImages = append(policy.TargetImages, "registry-restriction")
						}

						policies = append(policies, policy)
					}
				}
			}
		}
	}

	return controller, policies
}

// ============================================================================
// Datree Image Policy Analysis
// ============================================================================

// DatreeImagePolicyInfo represents Datree policies for container images
type DatreeImagePolicyInfo struct {
	Name         string
	Namespace    string
	PolicyName   string
	RuleCount    int
	ImageRules   []string
	Enforcement  string // enforce, monitor
}

// analyzeDatreeImagePolicies analyzes Datree for image-related policies
func analyzeDatreeImagePolicies(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) (ImageAdmissionController, []DatreeImagePolicyInfo) {
	controller := ImageAdmissionController{
		Name: "Datree",
		Type: "policy-engine",
	}
	var policies []DatreeImagePolicyInfo

	// Check for Datree deployment
	namespaces := []string{"datree", "kube-system"}

	for _, ns := range namespaces {
		deployments, err := clientset.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, dep := range deployments.Items {
			if strings.Contains(strings.ToLower(dep.Name), "datree") {
				controller.Status = "active"
				controller.Namespace = ns

				// Verify by image
				for _, container := range dep.Spec.Template.Spec.Containers {
					if strings.Contains(container.Image, "datree") {
						controller.ImageVerified = true
						break
					}
				}
			}
		}
	}

	// Check for Datree ValidatingWebhookConfiguration
	webhooks, err := clientset.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, wh := range webhooks.Items {
			if strings.Contains(strings.ToLower(wh.Name), "datree") {
				controller.WebhookName = wh.Name
				if len(wh.Webhooks) > 0 {
					controller.FailurePolicy = string(*wh.Webhooks[0].FailurePolicy)
				}
				break
			}
		}
	}

	// Check Datree ConfigMap for policy configuration
	configMaps, err := clientset.CoreV1().ConfigMaps("").List(ctx, metav1.ListOptions{
		LabelSelector: "app=datree-webhook",
	})
	if err == nil {
		for _, cm := range configMaps.Items {
			policy := DatreeImagePolicyInfo{
				Name:      cm.Name,
				Namespace: cm.Namespace,
			}

			// Check for policy name in data
			if policyName, ok := cm.Data["policyName"]; ok {
				policy.PolicyName = policyName
			}

			// Datree image-related rules to look for
			imageRules := []string{
				"CONTAINERS_MISSING_IMAGE_VALUE_VERSION",
				"CONTAINERS_INCORRECT_IMAGEPULLPOLICY_VALUE",
				"CONTAINERS_MISSING_IMAGEPULLPOLICY_KEY",
				"CONTAINERS_INCORRECT_IMAGE_TAG",
			}

			for _, rule := range imageRules {
				if _, ok := cm.Data[rule]; ok {
					policy.ImageRules = append(policy.ImageRules, rule)
				}
			}

			// Check for enforcement mode
			if enforcement, ok := cm.Data["enforcement"]; ok {
				policy.Enforcement = enforcement
			} else {
				policy.Enforcement = "enforce" // default
			}

			policies = append(policies, policy)
		}
	}

	// Also check for Datree CRDs if they exist
	policyGVR := schema.GroupVersionResource{
		Group:    "datree.io",
		Version:  "v1",
		Resource: "policies",
	}

	policyList, err := dynClient.Resource(policyGVR).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, p := range policyList.Items {
			policy := DatreeImagePolicyInfo{
				Name:      p.GetName(),
				Namespace: p.GetNamespace(),
			}

			if spec, ok := p.Object["spec"].(map[string]interface{}); ok {
				if policyName, ok := spec["policyName"].(string); ok {
					policy.PolicyName = policyName
				}
				if rules, ok := spec["rules"].([]interface{}); ok {
					policy.RuleCount = len(rules)
					for _, r := range rules {
						if rMap, ok := r.(map[string]interface{}); ok {
							if id, ok := rMap["identifier"].(string); ok {
								if strings.Contains(strings.ToUpper(id), "IMAGE") ||
									strings.Contains(strings.ToUpper(id), "CONTAINER") {
									policy.ImageRules = append(policy.ImageRules, id)
								}
							}
						}
					}
				}
			}

			policies = append(policies, policy)
		}
	}

	return controller, policies
}

// containsImageProvider checks if a provider is in the list
func containsImageProvider(providers []string, target string) bool {
	for _, p := range providers {
		if strings.EqualFold(p, target) {
			return true
		}
	}
	return false
}

// initImageAdmissionCloudClients initializes cloud provider clients for image admission
func initImageAdmissionCloudClients(logger internal.Logger) *ImageAdmissionCloudClients {
	if len(globals.K8sCloudProviders) == 0 {
		logger.InfoM("Cloud image policy enumeration disabled (use --cloud-provider to enable)", K8S_IMAGE_ADMISSION_MODULE_NAME)
		return nil
	}

	clients := &ImageAdmissionCloudClients{}
	cloudEnabled := false

	// GCP Binary Authorization
	if containsImageProvider(globals.K8sCloudProviders, "gcp") {
		svc, err := binaryauthorization.NewService(context.Background(), option.WithScopes(binaryauthorization.CloudPlatformScope))
		if err == nil {
			clients.GCPBinaryAuthService = svc

			if len(globals.K8sGCPProjects) > 0 {
				clients.GCPProjects = globals.K8sGCPProjects
				logger.InfoM(fmt.Sprintf("GCP Binary Authorization enabled (%d projects)", len(globals.K8sGCPProjects)), K8S_IMAGE_ADMISSION_MODULE_NAME)
				cloudEnabled = true
			} else {
				logger.InfoM("GCP Binary Authorization enabled (no projects specified, will try to discover)", K8S_IMAGE_ADMISSION_MODULE_NAME)
				cloudEnabled = true
			}
		} else {
			logger.InfoM(fmt.Sprintf("GCP Binary Authorization failed: %v", err), K8S_IMAGE_ADMISSION_MODULE_NAME)
		}
	}

	// AWS ECR and Signer
	if containsImageProvider(globals.K8sCloudProviders, "aws") {
		var awsCfg aws.Config
		var err error
		if globals.K8sAWSProfile != "" {
			awsCfg, err = awsconfig.LoadDefaultConfig(context.Background(),
				awsconfig.WithSharedConfigProfile(globals.K8sAWSProfile))
		} else {
			// Load default config with EC2 IMDS region detection for instance roles
			awsCfg, err = awsconfig.LoadDefaultConfig(context.Background(),
				awsconfig.WithEC2IMDSRegion())
		}
		if err == nil {
			clients.AWSECRClient = ecr.NewFromConfig(awsCfg)
			clients.AWSSignerClient = signer.NewFromConfig(awsCfg)
			clients.AWSRegion = awsCfg.Region
			if awsCfg.Region != "" {
				logger.InfoM(fmt.Sprintf("AWS ECR/Signer enabled (region: %s)", awsCfg.Region), K8S_IMAGE_ADMISSION_MODULE_NAME)
				cloudEnabled = true
			} else {
				// Try to get region from EC2 IMDS as a fallback
				imdsClient := imds.NewFromConfig(awsCfg)
				regionResp, regionErr := imdsClient.GetRegion(context.Background(), &imds.GetRegionInput{})
				if regionErr == nil && regionResp.Region != "" {
					clients.AWSRegion = regionResp.Region
					// Rebuild config with explicit region
					awsCfg, err = awsconfig.LoadDefaultConfig(context.Background(),
						awsconfig.WithRegion(regionResp.Region))
					if err == nil {
						clients.AWSECRClient = ecr.NewFromConfig(awsCfg)
						clients.AWSSignerClient = signer.NewFromConfig(awsCfg)
						logger.InfoM(fmt.Sprintf("AWS ECR/Signer enabled (EC2 instance credentials, region: %s)", regionResp.Region), K8S_IMAGE_ADMISSION_MODULE_NAME)
						cloudEnabled = true
					}
				}
			}
		} else {
			logger.InfoM(fmt.Sprintf("AWS ECR/Signer failed: %v", err), K8S_IMAGE_ADMISSION_MODULE_NAME)
		}
	}

	// Azure Policy
	if containsImageProvider(globals.K8sCloudProviders, "azure") {
		azCred, err := azidentity.NewDefaultAzureCredential(nil)
		if err == nil {
			clients.AzureCredential = azCred

			if len(globals.K8sAzureSubscriptions) > 0 {
				clients.AzureSubscriptions = globals.K8sAzureSubscriptions
				logger.InfoM(fmt.Sprintf("Azure Policy enabled (%d subscriptions)", len(globals.K8sAzureSubscriptions)), K8S_IMAGE_ADMISSION_MODULE_NAME)
				cloudEnabled = true
			} else {
				logger.InfoM("Azure Policy enabled (no subscriptions specified, will try to discover)", K8S_IMAGE_ADMISSION_MODULE_NAME)
				cloudEnabled = true
			}
		} else {
			logger.InfoM(fmt.Sprintf("Azure Policy failed: %v", err), K8S_IMAGE_ADMISSION_MODULE_NAME)
		}
	}

	if !cloudEnabled {
		return nil
	}

	return clients
}

// analyzeGCPBinaryAuth fetches GCP Binary Authorization policies from the API
func analyzeGCPBinaryAuth(ctx context.Context, clients *ImageAdmissionCloudClients, logger internal.Logger) ([]CloudImagePolicy, []GCPBinaryAuthAttestor) {
	var policies []CloudImagePolicy
	var attestors []GCPBinaryAuthAttestor

	if clients == nil || clients.GCPBinaryAuthService == nil {
		return policies, attestors
	}

	projects := clients.GCPProjects
	if len(projects) == 0 {
		// Try to discover projects - for now just log
		logger.InfoM("No GCP projects specified, skipping Binary Authorization enumeration", K8S_IMAGE_ADMISSION_MODULE_NAME)
		return policies, attestors
	}

	for _, project := range projects {
		// Get project policy
		policyName := fmt.Sprintf("projects/%s/policy", project)
		policy, err := clients.GCPBinaryAuthService.Projects.GetPolicy(policyName).Context(ctx).Do()
		if err != nil {
			logger.InfoM(fmt.Sprintf("Failed to get Binary Auth policy for %s: %v", project, err), K8S_IMAGE_ADMISSION_MODULE_NAME)
			continue
		}

		// Parse default admission rule
		defaultAction := "ALLOW"
		enforcementMode := "ENFORCED_BLOCK_AND_AUDIT_LOG"
		attestorsCount := 0

		if policy.DefaultAdmissionRule != nil {
			defaultAction = policy.DefaultAdmissionRule.EvaluationMode
			enforcementMode = policy.DefaultAdmissionRule.EnforcementMode
			attestorsCount = len(policy.DefaultAdmissionRule.RequireAttestationsBy)
		}

		// Build exempt images list
		var exemptImages []string
		for _, img := range policy.AdmissionWhitelistPatterns {
			exemptImages = append(exemptImages, img.NamePattern)
		}

		// Determine if this policy blocks deployment
		// ENFORCED_BLOCK_AND_AUDIT_LOG with ALWAYS_DENY or REQUIRE_ATTESTATION blocks
		blocksDeployment := false
		if strings.Contains(enforcementMode, "ENFORCED") &&
			(defaultAction == "ALWAYS_DENY" || defaultAction == "REQUIRE_ATTESTATION") {
			blocksDeployment = true
		}

		// Determine policy details
		details := fmt.Sprintf("Global: %s", policy.GlobalPolicyEvaluationMode)
		if len(policy.ClusterAdmissionRules) > 0 {
			details += fmt.Sprintf(", %d cluster-specific rules", len(policy.ClusterAdmissionRules))
		}
		if len(exemptImages) > 0 {
			details += fmt.Sprintf(", %d exempt patterns", len(exemptImages))
		}

		policies = append(policies, CloudImagePolicy{
			Provider:         "gcp",
			PolicyType:       "binary-authorization",
			Name:             "Project Policy",
			Scope:            "project",
			ScopeID:          project,
			EnforcementMode:  enforcementMode,
			DefaultAction:    defaultAction,
			BlocksDeployment: blocksDeployment,
			Details:          details,
			AttestorsCount:   attestorsCount,
			ExemptImages:     exemptImages,
		})

		// Get cluster-specific rules
		for clusterName, rule := range policy.ClusterAdmissionRules {
			// Check if cluster rule blocks deployment
			clusterBlocks := false
			if strings.Contains(rule.EnforcementMode, "ENFORCED") &&
				(rule.EvaluationMode == "ALWAYS_DENY" || rule.EvaluationMode == "REQUIRE_ATTESTATION") {
				clusterBlocks = true
			}

			policies = append(policies, CloudImagePolicy{
				Provider:         "gcp",
				PolicyType:       "binary-authorization-cluster",
				Name:             clusterName,
				Scope:            "cluster",
				ScopeID:          project,
				EnforcementMode:  rule.EnforcementMode,
				DefaultAction:    rule.EvaluationMode,
				BlocksDeployment: clusterBlocks,
				Details:          fmt.Sprintf("Cluster: %s, Attestors: %d", clusterName, len(rule.RequireAttestationsBy)),
				AttestorsCount:   len(rule.RequireAttestationsBy),
			})
		}

		// List attestors
		attestorList, err := clients.GCPBinaryAuthService.Projects.Attestors.List(fmt.Sprintf("projects/%s", project)).Context(ctx).Do()
		if err == nil {
			for _, att := range attestorList.Attestors {
				keyCount := 0
				keyAlg := ""
				if att.UserOwnedGrafeasNote != nil && att.UserOwnedGrafeasNote.PublicKeys != nil {
					keyCount = len(att.UserOwnedGrafeasNote.PublicKeys)
					if keyCount > 0 {
						keyAlg = att.UserOwnedGrafeasNote.PublicKeys[0].PkixPublicKey.SignatureAlgorithm
					}
				}

				attestors = append(attestors, GCPBinaryAuthAttestor{
					Name:         att.Name,
					Project:      project,
					Description:  att.Description,
					KeyCount:     keyCount,
					KeyAlgorithm: keyAlg,
					UpdateTime:   att.UpdateTime,
				})
			}
		}
	}

	return policies, attestors
}

// analyzeAWSImagePolicies fetches AWS ECR and Signer policies from the API
func analyzeAWSImagePolicies(ctx context.Context, clients *ImageAdmissionCloudClients, logger internal.Logger) ([]CloudImagePolicy, []AWSECRScanConfig, []AWSSignerProfile) {
	var policies []CloudImagePolicy
	var scanConfigs []AWSECRScanConfig
	var signerProfiles []AWSSignerProfile

	if clients == nil || clients.AWSECRClient == nil {
		return policies, scanConfigs, signerProfiles
	}

	// Get ECR registry scanning configuration
	// NOTE: ECR scanning detects malicious images but does NOT block deployment
	scanConfigOutput, err := clients.AWSECRClient.GetRegistryScanningConfiguration(ctx, &ecr.GetRegistryScanningConfigurationInput{})
	if err == nil && scanConfigOutput.ScanningConfiguration != nil {
		scanType := string(scanConfigOutput.ScanningConfiguration.ScanType)

		details := fmt.Sprintf("Scan Type: %s (detects malicious, does NOT block)", scanType)
		if scanConfigOutput.ScanningConfiguration.Rules != nil {
			details += fmt.Sprintf(", %d rules", len(scanConfigOutput.ScanningConfiguration.Rules))
		}

		policies = append(policies, CloudImagePolicy{
			Provider:         "aws",
			PolicyType:       "ecr-registry-scanning",
			Name:             "Registry Scanning Configuration",
			Scope:            "registry",
			ScopeID:          clients.AWSRegion,
			EnforcementMode:  scanType,
			DefaultAction:    "scan-only",
			BlocksDeployment: false, // ECR scanning does NOT block deployment
			Details:          details,
		})

		// Add scanning rules as individual policies
		for _, rule := range scanConfigOutput.ScanningConfiguration.Rules {
			filters := []string{}
			for _, f := range rule.RepositoryFilters {
				filters = append(filters, *f.Filter)
			}

			policies = append(policies, CloudImagePolicy{
				Provider:         "aws",
				PolicyType:       "ecr-scan-rule",
				Name:             fmt.Sprintf("Scan Rule (%s)", string(rule.ScanFrequency)),
				Scope:            "repository-filter",
				ScopeID:          clients.AWSRegion,
				EnforcementMode:  string(rule.ScanFrequency),
				DefaultAction:    "scan-only",
				BlocksDeployment: false, // Scanning rules don't block
				Details:          fmt.Sprintf("Filters: %s (detects malicious post-push)", strings.Join(filters, ", ")),
			})
		}
	}

	// List repositories and their scan configurations
	reposOutput, err := clients.AWSECRClient.DescribeRepositories(ctx, &ecr.DescribeRepositoriesInput{})
	if err == nil {
		for _, repo := range reposOutput.Repositories {
			scanOnPush := false
			if repo.ImageScanningConfiguration != nil {
				scanOnPush = repo.ImageScanningConfiguration.ScanOnPush
			}

			scanConfigs = append(scanConfigs, AWSECRScanConfig{
				RepositoryName: *repo.RepositoryName,
				RegistryID:     *repo.RegistryId,
				ScanOnPush:     scanOnPush,
				ScanFrequency:  "SCAN_ON_PUSH",
			})
		}
	}

	// List Signer signing profiles
	// NOTE: Signer profiles only block deployment if an admission controller enforces signature verification
	if clients.AWSSignerClient != nil {
		profilesOutput, err := clients.AWSSignerClient.ListSigningProfiles(ctx, &signer.ListSigningProfilesInput{})
		if err == nil {
			for _, profile := range profilesOutput.Profiles {
				profileName := ""
				if profile.ProfileName != nil {
					profileName = *profile.ProfileName
				}

				signerProfiles = append(signerProfiles, AWSSignerProfile{
					ProfileName:    profileName,
					ProfileVersion: *profile.ProfileVersion,
					PlatformID:     *profile.PlatformId,
					Status:         string(profile.Status),
					Tags:           profile.Tags,
				})

				// Add as policy
				policies = append(policies, CloudImagePolicy{
					Provider:         "aws",
					PolicyType:       "signer-profile",
					Name:             profileName,
					Scope:            "account",
					ScopeID:          clients.AWSRegion,
					EnforcementMode:  string(profile.Status),
					DefaultAction:    "sign",
					BlocksDeployment: false, // Requires admission controller to enforce
					Details:          fmt.Sprintf("Platform: %s, Version: %s (requires admission controller to enforce)", *profile.PlatformId, *profile.ProfileVersion),
				})
			}
		}
	}

	return policies, scanConfigs, signerProfiles
}

// analyzeAzureImagePolicies fetches Azure Policy assignments related to container images
func analyzeAzureImagePolicies(ctx context.Context, clients *ImageAdmissionCloudClients, logger internal.Logger) ([]CloudImagePolicy, []AzureImagePolicy) {
	var policies []CloudImagePolicy
	var azurePolicies []AzureImagePolicy

	if clients == nil || clients.AzureCredential == nil {
		return policies, azurePolicies
	}

	subscriptions := clients.AzureSubscriptions
	if len(subscriptions) == 0 {
		logger.InfoM("No Azure subscriptions specified, skipping Policy enumeration", K8S_IMAGE_ADMISSION_MODULE_NAME)
		return policies, azurePolicies
	}

	// Container/AKS related policy definition IDs (built-in Azure policies)
	containerPolicyPatterns := []string{
		"container",
		"kubernetes",
		"aks",
		"registry",
		"acr",
		"image",
	}

	for _, subID := range subscriptions {
		// Create policy assignments client
		assignmentsClient, err := armpolicy.NewAssignmentsClient(subID, clients.AzureCredential, nil)
		if err != nil {
			logger.InfoM(fmt.Sprintf("Failed to create policy client for subscription %s: %v", subID, err), K8S_IMAGE_ADMISSION_MODULE_NAME)
			continue
		}

		// List all policy assignments
		pager := assignmentsClient.NewListPager(nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				break
			}

			for _, assignment := range page.Value {
				// Filter for container/AKS related policies
				policyName := ""
				if assignment.Properties != nil && assignment.Properties.DisplayName != nil {
					policyName = *assignment.Properties.DisplayName
				}
				if policyName == "" && assignment.Name != nil {
					policyName = *assignment.Name
				}

				// Check if policy is container-related
				isContainerPolicy := false
				policyNameLower := strings.ToLower(policyName)
				for _, pattern := range containerPolicyPatterns {
					if strings.Contains(policyNameLower, pattern) {
						isContainerPolicy = true
						break
					}
				}

				if !isContainerPolicy {
					continue
				}

				enforcementMode := "Default"
				if assignment.Properties != nil && assignment.Properties.EnforcementMode != nil {
					enforcementMode = string(*assignment.Properties.EnforcementMode)
				}

				scope := ""
				if assignment.Properties != nil && assignment.Properties.Scope != nil {
					scope = *assignment.Properties.Scope
				}

				// Extract allowed registries from parameters if present
				var allowedRegistries []string
				var effect string
				if assignment.Properties != nil && assignment.Properties.Parameters != nil {
					params := assignment.Properties.Parameters
					// Check for common parameter names for allowed registries
					for paramName, paramValue := range params {
						paramNameLower := strings.ToLower(paramName)
						if strings.Contains(paramNameLower, "allowedregist") ||
							strings.Contains(paramNameLower, "allowedcontainerimageregex") ||
							strings.Contains(paramNameLower, "registries") {
							if paramValue.Value != nil {
								// Try to extract string or array value
								switch v := paramValue.Value.(type) {
								case string:
									allowedRegistries = append(allowedRegistries, v)
								case []interface{}:
									for _, item := range v {
										if str, ok := item.(string); ok {
											allowedRegistries = append(allowedRegistries, str)
										}
									}
								}
							}
						}
						if strings.ToLower(paramName) == "effect" {
							if paramValue.Value != nil {
								if str, ok := paramValue.Value.(string); ok {
									effect = str
								}
							}
						}
					}
				}

				// Determine if this policy blocks deployment
				blocksDeployment := false
				if enforcementMode == "Default" && (effect == "Deny" || effect == "deny") {
					blocksDeployment = true
				}

				azPolicy := AzureImagePolicy{
					PolicyName:        policyName,
					DisplayName:       policyName,
					PolicyType:        "Assignment",
					Scope:             scope,
					EnforcementMode:   enforcementMode,
					Effect:            effect,
					BlocksDeployment:  blocksDeployment,
					AllowedRegistries: allowedRegistries,
				}

				if assignment.Name != nil {
					azPolicy.AssignmentName = *assignment.Name
				}

				azurePolicies = append(azurePolicies, azPolicy)

				// Build details string
				details := fmt.Sprintf("Scope: %s", scope)
				if effect != "" {
					details += fmt.Sprintf(", Effect: %s", effect)
				}

				policies = append(policies, CloudImagePolicy{
					Provider:          "azure",
					PolicyType:        "azure-policy",
					Name:              policyName,
					Scope:             "subscription",
					ScopeID:           subID,
					EnforcementMode:   enforcementMode,
					DefaultAction:     effect,
					BlocksDeployment:  blocksDeployment,
					AllowedRegistries: allowedRegistries,
					Details:           details,
				})
			}
		}
	}

	return policies, azurePolicies
}
