package commands

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/BishopFox/cloudfox/kubernetes/shared"
	"github.com/BishopFox/cloudfox/kubernetes/shared/admission"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

const K8S_CERT_ADMISSION_MODULE_NAME = "cert-admission"

var CertAdmissionCmd = &cobra.Command{
	Use:     "cert-admission",
	Aliases: []string{"certificate-management", "tls-certs"},
	Short:   "Analyze certificate management and TLS configurations",
	Long: `
Analyze all certificate management configurations including:
  - cert-manager Issuers and ClusterIssuers
  - cert-manager Certificates and CertificateRequests
  - Kubernetes CSR resources
  - CSR approver policies
  - Venafi integration
  - Istio certificate management
  - Certificate expiration analysis
  - Self-signed vs CA-signed certificates

Cloud Provider Integration:
  AWS:
    - AWS ACM (Certificate Manager) - certificate details and expiration
    - AWS Private CA Issuer
    Requires: AWS credentials with acm:ListCertificates, acm:DescribeCertificate

  GCP:
    - Google CAS (Certificate Authority Service) Issuer
    - GKE certificate management

  Azure:
    - Azure Key Vault Certificate Issuer
    - Azure Key Vault certificates
    Requires: Azure credentials with Key Vault read access

Examples:
  cloudfox kubernetes cert-admission
  cloudfox kubernetes cert-admission --detailed`,
	Run: ListCertAdmission,
}

// init() removed - detailed flag is now a global persistent flag in cli/kubernetes.go

type CertAdmissionOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t CertAdmissionOutput) TableFiles() []internal.TableFile { return t.Table }
func (t CertAdmissionOutput) LootFiles() []internal.LootFile   { return t.Loot }

// CertEnumeratedPolicy represents a unified policy entry from any cert management tool
type CertEnumeratedPolicy struct {
	Namespace string
	Tool      string
	Name      string
	Scope     string
	Type      string
	Details   string
}

// CertAdmissionFinding represents certificate management for a namespace
type CertAdmissionFinding struct {
	Namespace string

	// cert-manager status
	HasCertManager     bool
	Issuers            int
	ClusterIssuers     int
	Certificates       int
	CertificateRequests int

	// Certificate health
	ValidCerts         int
	ExpiringSoonCerts  int // within 30 days
	ExpiredCerts       int
	FailedCerts        int

	// Certificate types
	SelfSignedCerts    int
	CASignedCerts      int
	ACMECerts          int
	VaultCerts         int
	VenafiCerts        int

	// Issues
	SecurityIssues []string
}

// CertManagerInfo represents cert-manager installation status
type CertManagerInfo struct {
	Name          string
	Namespace     string
	Version       string
	Status        string
	PodsRunning   int
	TotalPods     int
	Webhooks      bool
	ImageVerified bool // True if cert-manager image was verified
}

// IssuerInfo represents a cert-manager Issuer or ClusterIssuer
type IssuerInfo struct {
	Name          string
	Namespace     string
	IsCluster     bool
	Type          string // SelfSigned, CA, ACME, Vault, Venafi, AWS
	Ready         bool
	ReadyReason   string
	ACMEServer    string
	VaultPath     string
	VenafiZone    string
	CASecretName  string
}

// CertAdmissionCertInfo represents a cert-manager Certificate
type CertAdmissionCertInfo struct {
	Name           string
	Namespace      string
	SecretName     string
	IssuerRef      string
	IssuerKind     string
	DNSNames       []string
	CommonName     string
	Ready          bool
	ReadyReason    string
	NotBefore      time.Time
	NotAfter       time.Time
	RenewalTime    time.Time
	DaysUntilExpiry int
	IsExpired      bool
	IsExpiringSoon bool
}

// CertificateRequestInfo represents a cert-manager CertificateRequest
type CertificateRequestInfo struct {
	Name        string
	Namespace   string
	IssuerRef   string
	Ready       bool
	Approved    bool
	Denied      bool
	FailureTime string
}

// CSRInfo represents a Kubernetes CertificateSigningRequest
type CSRInfo struct {
	Name         string
	SignerName   string
	RequestedBy  string
	Usages       []string
	Approved     bool
	Denied       bool
	Issued       bool
	ExpirationSeconds int
}

// CSRApproverInfo represents a CSR auto-approver
type CSRApproverInfo struct {
	Name         string
	Namespace    string
	Type         string // kubelet-csr-approver, cert-manager, custom
	SignerNames  []string
	AutoApprove  bool
}

// VenafiInfo represents Venafi integration details
type VenafiInfo struct {
	Name          string
	Namespace     string
	Status        string
	TPPUrl        string
	Zone          string
	CloudApiUrl   string
	CustomFields  []string
	PodsRunning   int
	TotalPods     int
	ImageVerified bool // True if Venafi operator image was verified
}

// SPIFFEInfo represents SPIFFE/SPIRE installation status
type SPIFFEInfo struct {
	Name          string
	Namespace     string
	Status        string
	ServerRunning bool
	AgentsRunning int
	TotalAgents   int
	TrustDomain   string
	Registrations int
	ImageVerified bool // True if SPIRE server/agent image was verified
}

// IstioCertInfo represents Istio certificate management
type IstioCertInfo struct {
	Name            string
	Namespace       string
	Status          string
	RootCertExpiry  time.Time
	WorkloadCertTTL string
	RotationEnabled bool
	ExternalCA      bool
	ImageVerified   bool // True if Istio control plane image was verified
}

// verifyCertEngineImage checks if a container image matches known patterns for a cert engine
// Now uses the shared admission SDK for centralized engine detection
func verifyCertEngineImage(image string, engine string) bool {
	return admission.VerifyControllerImage(image, engine)
}

func ListCertAdmission(cmd *cobra.Command, args []string) {
	ctx, cancel := shared.ContextWithCancel()
	defer cancel()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDir, _ := parentCmd.PersistentFlags().GetString("outdir")
	detailed := globals.K8sDetailed

	logger.InfoM(fmt.Sprintf("Analyzing certificate management for %s", globals.ClusterName), K8S_CERT_ADMISSION_MODULE_NAME)

	clientset := config.GetClientOrExit()
	dynClient := config.GetDynamicClientOrExit()

	// Analyze cert-manager
	logger.InfoM("Analyzing cert-manager...", K8S_CERT_ADMISSION_MODULE_NAME)
	certManager := analyzeCertManager(ctx, clientset)

	// Analyze Issuers
	logger.InfoM("Analyzing Issuers...", K8S_CERT_ADMISSION_MODULE_NAME)
	issuers := analyzeIssuers(ctx, dynClient)

	// Analyze Certificates
	logger.InfoM("Analyzing Certificates...", K8S_CERT_ADMISSION_MODULE_NAME)
	certificates := analyzeCertificates(ctx, dynClient)

	// Analyze CertificateRequests
	logger.InfoM("Analyzing CertificateRequests...", K8S_CERT_ADMISSION_MODULE_NAME)
	certRequests := analyzeCertificateRequests(ctx, dynClient)

	// Analyze Kubernetes CSRs
	logger.InfoM("Analyzing CSRs...", K8S_CERT_ADMISSION_MODULE_NAME)
	csrs := analyzeCSRs(ctx, clientset)

	// Analyze CSR Approvers
	logger.InfoM("Analyzing CSR Approvers...", K8S_CERT_ADMISSION_MODULE_NAME)
	csrApprovers := analyzeCSRApprovers(ctx, clientset, dynClient)

	// Analyze Venafi
	logger.InfoM("Analyzing Venafi...", K8S_CERT_ADMISSION_MODULE_NAME)
	venafi := analyzeVenafi(ctx, clientset, dynClient)

	// Analyze SPIFFE/SPIRE
	logger.InfoM("Analyzing SPIFFE/SPIRE...", K8S_CERT_ADMISSION_MODULE_NAME)
	spiffe := analyzeSPIFFE(ctx, clientset, dynClient)

	// Analyze Istio Certificates
	logger.InfoM("Analyzing Istio Certificates...", K8S_CERT_ADMISSION_MODULE_NAME)
	istioCerts := analyzeIstioCerts(ctx, clientset, dynClient)

	// Initialize cloud clients for certificate enumeration (if cloud providers specified)
	certCloudClients := initCertCloudClients(logger)

	// Analyze cloud provider certificates (if credentials available)
	var awsACMCerts []AWSACMCertificateInfo
	var azureKeyVaultCerts []AzureKeyVaultCertInfo

	if certCloudClients != nil {
		logger.InfoM("Analyzing cloud provider certificates...", K8S_CERT_ADMISSION_MODULE_NAME)

		if certCloudClients.AWSACMClient != nil {
			awsACMCerts = analyzeAWSACMCertificates(ctx, certCloudClients, logger)
			if len(awsACMCerts) > 0 {
				logger.InfoM(fmt.Sprintf("Found %d AWS ACM certificates", len(awsACMCerts)), K8S_CERT_ADMISSION_MODULE_NAME)
			}
		}

		if certCloudClients.AzureKeyVaultClient != nil {
			azureKeyVaultCerts = analyzeAzureKeyVaultCerts(ctx, certCloudClients, logger)
			if len(azureKeyVaultCerts) > 0 {
				logger.InfoM(fmt.Sprintf("Found %d Azure Key Vault certificates", len(azureKeyVaultCerts)), K8S_CERT_ADMISSION_MODULE_NAME)
			}
		}
	}

	// Build findings per namespace
	findings := buildCertAdmissionFindings(certManager, issuers, certificates)

	// Generate tables
	summaryHeader := []string{
		"Namespace",
		"Issuers",
		"Certificates",
		"Valid",
		"Expiring Soon",
		"Expired",
		"Failed",
		"Self-Signed",
		"CA-Signed",
		"ACME",
		"Issues",
	}

	// Unified policies table header
	policiesHeader := []string{
		"Namespace",
		"Tool",
		"Name",
		"Scope",
		"Type",
		"Details",
	}

	certManagerHeader := []string{
		"Namespace",
		"Version",
		"Status",
		"Pods Running",
		"Webhooks",
		"Issues",
	}

	issuerHeader := []string{
		"Namespace",
		"Name",
		"Scope",
		"Type",
		"Ready",
		"Details",
		"Issues",
	}

	certificateHeader := []string{
		"Namespace",
		"Name",
		"Secret",
		"Issuer",
		"DNS Names",
		"Ready",
		"Expires",
		"Days Left",
		"Issues",
	}

	certRequestHeader := []string{
		"Namespace",
		"Name",
		"Issuer",
		"Approved",
		"Denied",
		"Ready",
		"Issues",
	}

	csrHeader := []string{
		"Name",
		"Signer",
		"Requested By",
		"Usages",
		"Approved",
		"Issued",
		"Issues",
	}

	csrApproverHeader := []string{
		"Namespace",
		"Name",
		"Type",
		"Signer Names",
		"Auto Approve",
		"Issues",
	}

	venafiHeader := []string{
		"Namespace",
		"Status",
		"Pods Running",
		"TPP URL",
		"Cloud URL",
		"Zone",
		"Issues",
	}

	spiffeHeader := []string{
		"Namespace",
		"Status",
		"Server Running",
		"Agents Running",
		"Trust Domain",
		"Registrations",
		"Issues",
	}

	istioCertHeader := []string{
		"Namespace",
		"Status",
		"Workload Cert TTL",
		"External CA",
		"Rotation Enabled",
		"Issues",
	}

	// Cloud certificate headers
	awsACMHeader := []string{
		"ARN",
		"Domain",
		"Status",
		"Type",
		"Expires",
		"In Use",
		"Issues",
	}

	azureKeyVaultHeader := []string{
		"Vault Name",
		"Certificate Name",
		"Status",
		"ID",
		"Expires",
		"Days Left",
		"Issues",
	}

	var summaryRows [][]string
	var policiesRows [][]string
	var certManagerRows [][]string
	var issuerRows [][]string
	var certificateRows [][]string
	var certRequestRows [][]string
	var csrRows [][]string
	var csrApproverRows [][]string
	var venafiRows [][]string
	var spiffeRows [][]string
	var istioCertRows [][]string
	var awsACMRows [][]string
	var azureKeyVaultRows [][]string

	loot := shared.NewLootBuilder()

	// Build summary rows
	for _, finding := range findings {
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
			fmt.Sprintf("%d", finding.Issuers),
			fmt.Sprintf("%d", finding.Certificates),
			fmt.Sprintf("%d", finding.ValidCerts),
			fmt.Sprintf("%d", finding.ExpiringSoonCerts),
			fmt.Sprintf("%d", finding.ExpiredCerts),
			fmt.Sprintf("%d", finding.FailedCerts),
			fmt.Sprintf("%d", finding.SelfSignedCerts),
			fmt.Sprintf("%d", finding.CASignedCerts),
			fmt.Sprintf("%d", finding.ACMECerts),
			issues,
		})
	}

	// Build cert-manager rows
	if certManager.Name != "" {
		webhooks := "No"
		if certManager.Webhooks {
			webhooks = "Yes"
		}

		// Detect issues
		var cmIssues []string
		if certManager.Status != "Running" && certManager.Status != "Healthy" {
			cmIssues = append(cmIssues, "Not running")
		}
		if !certManager.Webhooks {
			cmIssues = append(cmIssues, "Webhooks disabled")
		}
		if certManager.PodsRunning < certManager.TotalPods {
			cmIssues = append(cmIssues, "Not all pods running")
		}
		issuesStr := "<NONE>"
		if len(cmIssues) > 0 {
			issuesStr = strings.Join(cmIssues, "; ")
		}

		certManagerRows = append(certManagerRows, []string{
			certManager.Namespace,
			certManager.Version,
			certManager.Status,
			fmt.Sprintf("%d/%d", certManager.PodsRunning, certManager.TotalPods),
			webhooks,
			issuesStr,
		})
	}

	// Build issuer rows and policies
	for _, issuer := range issuers {
		scope := "Namespace"
		ns := issuer.Namespace
		if issuer.IsCluster {
			scope = "Cluster"
			ns = "<CLUSTER>"
		}

		ready := "No"
		if issuer.Ready {
			ready = "Yes"
		}

		details := "-"
		switch issuer.Type {
		case "ACME":
			details = issuer.ACMEServer
		case "Vault":
			details = issuer.VaultPath
		case "Venafi":
			details = issuer.VenafiZone
		case "CA":
			details = fmt.Sprintf("secret: %s", issuer.CASecretName)
		}

		// Detect issues
		var issuerIssues []string
		if !issuer.Ready {
			issuerIssues = append(issuerIssues, "Not ready")
		}
		if issuer.Type == "SelfSigned" {
			issuerIssues = append(issuerIssues, "Self-signed issuer")
		}
		issuerIssuesStr := "<NONE>"
		if len(issuerIssues) > 0 {
			issuerIssuesStr = strings.Join(issuerIssues, "; ")
		}

		issuerRows = append(issuerRows, []string{
			ns,
			issuer.Name,
			scope,
			issuer.Type,
			ready,
			details,
			issuerIssuesStr,
		})

		// Add to unified policies table
		policiesRows = append(policiesRows, []string{
			ns,
			"cert-manager",
			issuer.Name,
			scope,
			issuer.Type,
			details,
		})
	}

	// Build certificate rows
	for _, cert := range certificates {
		ready := "No"
		if cert.Ready {
			ready = "Yes"
		}

		dnsNames := "-"
		if len(cert.DNSNames) > 0 {
			if len(cert.DNSNames) > 2 {
				dnsNames = strings.Join(cert.DNSNames[:2], ", ") + "..."
			} else {
				dnsNames = strings.Join(cert.DNSNames, ", ")
			}
		}

		expires := "-"
		if !cert.NotAfter.IsZero() {
			expires = cert.NotAfter.Format("2006-01-02")
		}

		daysLeft := "-"
		if cert.DaysUntilExpiry >= 0 {
			daysLeft = fmt.Sprintf("%d", cert.DaysUntilExpiry)
		}
		if cert.IsExpired {
			daysLeft = "EXPIRED"
		}

		// Detect issues
		var certIssues []string
		if cert.IsExpired {
			certIssues = append(certIssues, "Certificate expired")
		} else if cert.IsExpiringSoon {
			certIssues = append(certIssues, fmt.Sprintf("Expiring in %d days", cert.DaysUntilExpiry))
		}
		if !cert.Ready {
			certIssues = append(certIssues, "Not ready")
		}
		certIssuesStr := "<NONE>"
		if len(certIssues) > 0 {
			certIssuesStr = strings.Join(certIssues, "; ")
		}

		certificateRows = append(certificateRows, []string{
			cert.Namespace,
			cert.Name,
			cert.SecretName,
			fmt.Sprintf("%s/%s", cert.IssuerKind, cert.IssuerRef),
			dnsNames,
			ready,
			expires,
			daysLeft,
			certIssuesStr,
		})

		// Add to unified policies table with expiration details
		var certDetailParts []string
		certDetailParts = append(certDetailParts, fmt.Sprintf("Issuer: %s/%s", cert.IssuerKind, cert.IssuerRef))
		if expires != "-" {
			certDetailParts = append(certDetailParts, fmt.Sprintf("Expires: %s", expires))
		}
		if cert.IsExpired {
			certDetailParts = append(certDetailParts, "EXPIRED")
		} else if cert.IsExpiringSoon {
			certDetailParts = append(certDetailParts, fmt.Sprintf("%dd left", cert.DaysUntilExpiry))
		} else if cert.DaysUntilExpiry > 0 {
			certDetailParts = append(certDetailParts, fmt.Sprintf("%dd left", cert.DaysUntilExpiry))
		}
		if !cert.Ready {
			certDetailParts = append(certDetailParts, fmt.Sprintf("NOT READY: %s", cert.ReadyReason))
		}
		if len(cert.DNSNames) > 0 {
			if len(cert.DNSNames) > 2 {
				certDetailParts = append(certDetailParts, fmt.Sprintf("DNS: %s +%d", strings.Join(cert.DNSNames[:2], ","), len(cert.DNSNames)-2))
			} else {
				certDetailParts = append(certDetailParts, fmt.Sprintf("DNS: %s", strings.Join(cert.DNSNames, ",")))
			}
		}
		if cert.SecretName != "" {
			certDetailParts = append(certDetailParts, fmt.Sprintf("Secret: %s", cert.SecretName))
		}
		policiesRows = append(policiesRows, []string{
			cert.Namespace,
			"cert-manager",
			cert.Name,
			"Namespace",
			"Certificate",
			strings.Join(certDetailParts, ", "),
		})
	}

	// Build certificate request rows
	for _, cr := range certRequests {
		ready := "No"
		if cr.Ready {
			ready = "Yes"
		}
		approved := "No"
		if cr.Approved {
			approved = "Yes"
		}
		denied := "No"
		if cr.Denied {
			denied = "Yes"
		}

		// Detect issues
		var crIssues []string
		if cr.Denied {
			crIssues = append(crIssues, "Request denied")
		}
		if !cr.Approved && !cr.Denied {
			crIssues = append(crIssues, "Pending approval")
		}
		if !cr.Ready {
			crIssues = append(crIssues, "Not ready")
		}
		crIssuesStr := "<NONE>"
		if len(crIssues) > 0 {
			crIssuesStr = strings.Join(crIssues, "; ")
		}

		certRequestRows = append(certRequestRows, []string{
			cr.Namespace,
			cr.Name,
			cr.IssuerRef,
			approved,
			denied,
			ready,
			crIssuesStr,
		})

		// Add to unified policies table
		crDetails := fmt.Sprintf("Issuer: %s, Approved: %s", cr.IssuerRef, approved)
		policiesRows = append(policiesRows, []string{
			cr.Namespace,
			"cert-manager",
			cr.Name,
			"Namespace",
			"CertificateRequest",
			crDetails,
		})
	}

	// Build CSR rows
	for _, csr := range csrs {
		approved := "No"
		if csr.Approved {
			approved = "Yes"
		}
		issued := "No"
		if csr.Issued {
			issued = "Yes"
		}

		usages := "-"
		if len(csr.Usages) > 0 {
			usages = strings.Join(csr.Usages, ", ")
		}

		// Detect issues
		var csrIssues []string
		if !csr.Approved {
			csrIssues = append(csrIssues, "Not approved")
		}
		if csr.Approved && !csr.Issued {
			csrIssues = append(csrIssues, "Approved but not issued")
		}
		csrIssuesStr := "<NONE>"
		if len(csrIssues) > 0 {
			csrIssuesStr = strings.Join(csrIssues, "; ")
		}

		csrRows = append(csrRows, []string{
			csr.Name,
			csr.SignerName,
			csr.RequestedBy,
			usages,
			approved,
			issued,
			csrIssuesStr,
		})

		// Add to unified policies table
		csrDetails := fmt.Sprintf("Signer: %s, Approved: %s, Issued: %s", csr.SignerName, approved, issued)
		policiesRows = append(policiesRows, []string{
			"<CLUSTER>", // CSRs are cluster-scoped
			"k8s-csr",
			csr.Name,
			"Cluster",
			"CSR",
			csrDetails,
		})
	}

	// Build CSR approver rows
	for _, approver := range csrApprovers {
		autoApprove := "No"
		if approver.AutoApprove {
			autoApprove = "Yes"
		}

		signers := "-"
		if len(approver.SignerNames) > 0 {
			signers = strings.Join(approver.SignerNames, ", ")
		}

		// Detect issues
		var approverIssues []string
		if approver.AutoApprove {
			approverIssues = append(approverIssues, "Auto-approve enabled")
		}
		for _, signer := range approver.SignerNames {
			if signer == "*" {
				approverIssues = append(approverIssues, "Wildcard signer")
				break
			}
		}
		approverIssuesStr := "<NONE>"
		if len(approverIssues) > 0 {
			approverIssuesStr = strings.Join(approverIssues, "; ")
		}

		csrApproverRows = append(csrApproverRows, []string{
			approver.Namespace,
			approver.Name,
			approver.Type,
			signers,
			autoApprove,
			approverIssuesStr,
		})

		// Add to unified policies table
		approverDetails := fmt.Sprintf("Auto-Approve: %s, Signers: %s", autoApprove, signers)
		policiesRows = append(policiesRows, []string{
			approver.Namespace,
			"csr-approver",
			approver.Name,
			"Namespace",
			approver.Type,
			approverDetails,
		})
	}

	// Build Venafi rows
	if venafi.Name != "" {
		tppUrl := "-"
		if venafi.TPPUrl != "" {
			tppUrl = venafi.TPPUrl
		}
		cloudUrl := "-"
		if venafi.CloudApiUrl != "" {
			cloudUrl = venafi.CloudApiUrl
		}
		zone := "-"
		if venafi.Zone != "" {
			zone = venafi.Zone
		}

		// Detect issues
		var venafiIssues []string
		if venafi.Status != "Running" && venafi.Status != "Healthy" {
			venafiIssues = append(venafiIssues, "Not running")
		}
		if venafi.PodsRunning < venafi.TotalPods {
			venafiIssues = append(venafiIssues, "Not all pods running")
		}
		if venafi.Zone == "" {
			venafiIssues = append(venafiIssues, "No zone configured")
		}
		venafiIssuesStr := "<NONE>"
		if len(venafiIssues) > 0 {
			venafiIssuesStr = strings.Join(venafiIssues, "; ")
		}

		venafiRows = append(venafiRows, []string{
			venafi.Namespace,
			venafi.Status,
			fmt.Sprintf("%d/%d", venafi.PodsRunning, venafi.TotalPods),
			tppUrl,
			cloudUrl,
			zone,
			venafiIssuesStr,
		})

		// Add to unified policies table
		venafiDetails := fmt.Sprintf("Status: %s, Zone: %s", venafi.Status, zone)
		policiesRows = append(policiesRows, []string{
			venafi.Namespace,
			"venafi",
			venafi.Name,
			"Namespace",
			"Venafi Enhanced Issuer",
			venafiDetails,
		})
	}

	// Build SPIFFE rows
	if spiffe.Name != "" {
		serverRunning := "No"
		if spiffe.ServerRunning {
			serverRunning = "Yes"
		}
		trustDomain := "-"
		if spiffe.TrustDomain != "" {
			trustDomain = spiffe.TrustDomain
		}

		// Detect issues
		var spiffeIssues []string
		if !spiffe.ServerRunning {
			spiffeIssues = append(spiffeIssues, "Server not running")
		}
		if spiffe.AgentsRunning < spiffe.TotalAgents {
			spiffeIssues = append(spiffeIssues, "Not all agents running")
		}
		if spiffe.TrustDomain == "" {
			spiffeIssues = append(spiffeIssues, "No trust domain")
		}
		spiffeIssuesStr := "<NONE>"
		if len(spiffeIssues) > 0 {
			spiffeIssuesStr = strings.Join(spiffeIssues, "; ")
		}

		spiffeRows = append(spiffeRows, []string{
			spiffe.Namespace,
			spiffe.Status,
			serverRunning,
			fmt.Sprintf("%d/%d", spiffe.AgentsRunning, spiffe.TotalAgents),
			trustDomain,
			fmt.Sprintf("%d", spiffe.Registrations),
			spiffeIssuesStr,
		})

		// Add to unified policies table
		spiffeDetails := fmt.Sprintf("Status: %s, Trust Domain: %s, Registrations: %d", spiffe.Status, trustDomain, spiffe.Registrations)
		policiesRows = append(policiesRows, []string{
			spiffe.Namespace,
			"spiffe",
			spiffe.Name,
			"Namespace",
			"SPIFFE/SPIRE",
			spiffeDetails,
		})
	}

	// Build Istio cert rows
	if istioCerts.Name != "" {
		externalCA := "No"
		if istioCerts.ExternalCA {
			externalCA = "Yes"
		}
		rotationEnabled := "No"
		if istioCerts.RotationEnabled {
			rotationEnabled = "Yes"
		}
		certTTL := "-"
		if istioCerts.WorkloadCertTTL != "" {
			certTTL = istioCerts.WorkloadCertTTL
		}

		// Detect issues
		var istioCertIssues []string
		if !istioCerts.RotationEnabled {
			istioCertIssues = append(istioCertIssues, "Rotation disabled")
		}
		if istioCerts.Status != "Running" && istioCerts.Status != "Healthy" {
			istioCertIssues = append(istioCertIssues, "Not running")
		}
		istioCertIssuesStr := "<NONE>"
		if len(istioCertIssues) > 0 {
			istioCertIssuesStr = strings.Join(istioCertIssues, "; ")
		}

		istioCertRows = append(istioCertRows, []string{
			istioCerts.Namespace,
			istioCerts.Status,
			certTTL,
			externalCA,
			rotationEnabled,
			istioCertIssuesStr,
		})

		// Add to unified policies table
		istioDetails := fmt.Sprintf("Status: %s, TTL: %s, External CA: %s", istioCerts.Status, certTTL, externalCA)
		policiesRows = append(policiesRows, []string{
			istioCerts.Namespace,
			"istio",
			istioCerts.Name,
			"Namespace",
			"Istio Certificates",
			istioDetails,
		})
	}

	// Build AWS ACM certificate rows
	for _, cert := range awsACMCerts {
		inUse := "No"
		if len(cert.InUseBy) > 0 {
			inUse = fmt.Sprintf("Yes (%d)", len(cert.InUseBy))
		}
		expires := "-"
		if !cert.NotAfter.IsZero() {
			expires = cert.NotAfter.Format("2006-01-02")
		}

		// Detect issues
		var acmIssues []string
		if cert.Status != "ISSUED" {
			acmIssues = append(acmIssues, "Status: "+cert.Status)
		}
		if len(cert.InUseBy) == 0 {
			acmIssues = append(acmIssues, "Not in use")
		}
		acmIssuesStr := "<NONE>"
		if len(acmIssues) > 0 {
			acmIssuesStr = strings.Join(acmIssues, "; ")
		}

		awsACMRows = append(awsACMRows, []string{
			cert.ARN,
			cert.DomainName,
			cert.Status,
			cert.Type,
			expires,
			inUse,
			acmIssuesStr,
		})

		// Add to unified policies table
		acmDetails := fmt.Sprintf("Domain: %s, Status: %s, Type: %s, Expires: %s", cert.DomainName, cert.Status, cert.Type, expires)
		policiesRows = append(policiesRows, []string{
			"<AWS>",
			"aws-acm",
			cert.DomainName,
			"Cloud",
			"AWS ACM Certificate",
			acmDetails,
		})
	}

	// Build Azure Key Vault certificate rows
	for _, cert := range azureKeyVaultCerts {
		status := "Disabled"
		if cert.Enabled {
			status = "Enabled"
		}
		expires := "-"
		if !cert.Expires.IsZero() {
			expires = cert.Expires.Format("2006-01-02")
		}

		// Detect issues
		var akvIssues []string
		if !cert.Enabled {
			akvIssues = append(akvIssues, "Certificate disabled")
		}
		if cert.DaysUntilExpiry <= 30 && cert.DaysUntilExpiry > 0 {
			akvIssues = append(akvIssues, fmt.Sprintf("Expiring in %d days", cert.DaysUntilExpiry))
		}
		if cert.DaysUntilExpiry <= 0 {
			akvIssues = append(akvIssues, "Expired")
		}
		akvIssuesStr := "<NONE>"
		if len(akvIssues) > 0 {
			akvIssuesStr = strings.Join(akvIssues, "; ")
		}

		azureKeyVaultRows = append(azureKeyVaultRows, []string{
			cert.VaultName,
			cert.CertificateName,
			status,
			cert.VaultURI,
			expires,
			fmt.Sprintf("%d", cert.DaysUntilExpiry),
			akvIssuesStr,
		})

		// Add to unified policies table
		akvDetails := fmt.Sprintf("Vault: %s, Status: %s, Expires: %s", cert.VaultName, status, expires)
		policiesRows = append(policiesRows, []string{
			"<AZURE>",
			"azure-keyvault",
			cert.CertificateName,
			"Cloud",
			"Azure Key Vault Certificate",
			akvDetails,
		})
	}

	// Generate loot
	generateCertAdmissionLoot(loot, findings, certManager, issuers, certificates, csrs, csrApprovers, venafi, spiffe, istioCerts)

	// Build output tables
	var tables []internal.TableFile

	// Always include summary
	tables = append(tables, internal.TableFile{
		Name:   "Cert-Admission-Summary",
		Header: summaryHeader,
		Body:   summaryRows,
	})

	// Always include unified policies table
	if len(policiesRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Cert-Admission-Policies",
			Header: policiesHeader,
			Body:   policiesRows,
		})
	}

	// Detail tables only shown with --detailed flag
	if detailed {
		if len(certManagerRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Cert-Admission-CertManager",
				Header: certManagerHeader,
				Body:   certManagerRows,
			})
		}

		if len(issuerRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Cert-Admission-Issuers",
				Header: issuerHeader,
				Body:   issuerRows,
			})
		}

		if len(certificateRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Cert-Admission-Certificates",
				Header: certificateHeader,
				Body:   certificateRows,
			})
		}

		if len(certRequestRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Cert-Admission-CertificateRequests",
				Header: certRequestHeader,
				Body:   certRequestRows,
			})
		}

		if len(csrRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Cert-Admission-CSRs",
				Header: csrHeader,
				Body:   csrRows,
			})
		}

		if len(csrApproverRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Cert-Admission-CSRApprovers",
				Header: csrApproverHeader,
				Body:   csrApproverRows,
			})
		}

		if len(venafiRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Cert-Admission-Venafi",
				Header: venafiHeader,
				Body:   venafiRows,
			})
		}

		if len(spiffeRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Cert-Admission-SPIFFE",
				Header: spiffeHeader,
				Body:   spiffeRows,
			})
		}

		if len(istioCertRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Cert-Admission-IstioCerts",
				Header: istioCertHeader,
				Body:   istioCertRows,
			})
		}

		// Cloud provider certificate tables
		if len(awsACMRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Cert-Admission-AWS-ACM",
				Header: awsACMHeader,
				Body:   awsACMRows,
			})
		}

		if len(azureKeyVaultRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Cert-Admission-Azure-KeyVault",
				Header: azureKeyVaultHeader,
				Body:   azureKeyVaultRows,
			})
		}
	}

	output := CertAdmissionOutput{
		Table: tables,
		Loot:  loot.Build(),
	}

	err := internal.HandleOutput(
		"Kubernetes",
		"table",
		outputDir,
		verbosity,
		wrap,
		"Cert-Admission",
		globals.ClusterName,
		"results",
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), K8S_CERT_ADMISSION_MODULE_NAME)
		return
	}
}

// ============================================================================
// cert-manager Analysis
// ============================================================================

func analyzeCertManager(ctx context.Context, clientset kubernetes.Interface) CertManagerInfo {
	info := CertManagerInfo{}

	// Check for cert-manager deployment
	namespaces := []string{"cert-manager", "kube-system"}
	for _, ns := range namespaces {
		deployments, err := clientset.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, dep := range deployments.Items {
			if strings.Contains(strings.ToLower(dep.Name), "cert-manager") &&
				!strings.Contains(strings.ToLower(dep.Name), "webhook") &&
				!strings.Contains(strings.ToLower(dep.Name), "cainjector") {
				info.Name = "cert-manager"
				info.Namespace = ns
				info.Status = "active"

				// Get version from image
				for _, container := range dep.Spec.Template.Spec.Containers {
					parts := strings.Split(container.Image, ":")
					if len(parts) > 1 {
						info.Version = parts[1]
					}
				}

				// Check pod status
				pods, err := clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
					LabelSelector: "app=cert-manager",
				})
				if err == nil {
					info.TotalPods = len(pods.Items)
					for _, pod := range pods.Items {
						if pod.Status.Phase == "Running" {
							info.PodsRunning++
						}
					}
				}

				if info.PodsRunning < info.TotalPods {
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
		return info
	}

	// Check for webhook
	webhooks, err := clientset.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, wh := range webhooks.Items {
			if strings.Contains(strings.ToLower(wh.Name), "cert-manager") {
				info.Webhooks = true
				break
			}
		}
	}

	// Verify by checking deployment images
	for _, ns := range namespaces {
		deployments, err := clientset.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
		if err == nil {
			for _, dep := range deployments.Items {
				for _, container := range dep.Spec.Template.Spec.Containers {
					if verifyCertEngineImage(container.Image, "cert-manager") {
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
// Issuer Analysis
// ============================================================================

func analyzeIssuers(ctx context.Context, dynClient dynamic.Interface) []IssuerInfo {
	var issuers []IssuerInfo

	// Issuer (namespaced)
	issuerGVR := schema.GroupVersionResource{
		Group:    "cert-manager.io",
		Version:  "v1",
		Resource: "issuers",
	}

	issuerList, err := dynClient.Resource(issuerGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range issuerList.Items {
			issuer := parseIssuer(item.Object, false)
			issuers = append(issuers, issuer)
		}
	}

	// ClusterIssuer
	clusterIssuerGVR := schema.GroupVersionResource{
		Group:    "cert-manager.io",
		Version:  "v1",
		Resource: "clusterissuers",
	}

	clusterIssuerList, err := dynClient.Resource(clusterIssuerGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range clusterIssuerList.Items {
			issuer := parseIssuer(item.Object, true)
			issuers = append(issuers, issuer)
		}
	}

	return issuers
}

func parseIssuer(obj map[string]interface{}, isCluster bool) IssuerInfo {
	issuer := IssuerInfo{
		IsCluster: isCluster,
	}

	if metadata, ok := obj["metadata"].(map[string]interface{}); ok {
		issuer.Name, _ = metadata["name"].(string)
		if !isCluster {
			issuer.Namespace, _ = metadata["namespace"].(string)
		}
	}

	if spec, ok := obj["spec"].(map[string]interface{}); ok {
		// Determine issuer type
		if _, ok := spec["selfSigned"]; ok {
			issuer.Type = "SelfSigned"
		} else if ca, ok := spec["ca"].(map[string]interface{}); ok {
			issuer.Type = "CA"
			if secretName, ok := ca["secretName"].(string); ok {
				issuer.CASecretName = secretName
			}
		} else if acme, ok := spec["acme"].(map[string]interface{}); ok {
			issuer.Type = "ACME"
			if server, ok := acme["server"].(string); ok {
				issuer.ACMEServer = server
			}
		} else if vault, ok := spec["vault"].(map[string]interface{}); ok {
			issuer.Type = "Vault"
			if path, ok := vault["path"].(string); ok {
				issuer.VaultPath = path
			}
		} else if venafi, ok := spec["venafi"].(map[string]interface{}); ok {
			issuer.Type = "Venafi"
			if zone, ok := venafi["zone"].(string); ok {
				issuer.VenafiZone = zone
			}
		} else {
			issuer.Type = "Unknown"
		}
	}

	// Check status
	if status, ok := obj["status"].(map[string]interface{}); ok {
		if conditions, ok := status["conditions"].([]interface{}); ok {
			for _, cond := range conditions {
				if condMap, ok := cond.(map[string]interface{}); ok {
					if condType, ok := condMap["type"].(string); ok && condType == "Ready" {
						if condStatus, ok := condMap["status"].(string); ok {
							issuer.Ready = condStatus == "True"
						}
						if reason, ok := condMap["reason"].(string); ok {
							issuer.ReadyReason = reason
						}
					}
				}
			}
		}
	}

	return issuer
}

// ============================================================================
// Certificate Analysis
// ============================================================================

func analyzeCertificates(ctx context.Context, dynClient dynamic.Interface) []CertAdmissionCertInfo {
	var certificates []CertAdmissionCertInfo

	certGVR := schema.GroupVersionResource{
		Group:    "cert-manager.io",
		Version:  "v1",
		Resource: "certificates",
	}

	certList, err := dynClient.Resource(certGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range certList.Items {
			cert := parseCertAdmissionCert(item.Object)
			certificates = append(certificates, cert)
		}
	}

	return certificates
}

func parseCertAdmissionCert(obj map[string]interface{}) CertAdmissionCertInfo {
	cert := CertAdmissionCertInfo{}

	if metadata, ok := obj["metadata"].(map[string]interface{}); ok {
		cert.Name, _ = metadata["name"].(string)
		cert.Namespace, _ = metadata["namespace"].(string)
	}

	if spec, ok := obj["spec"].(map[string]interface{}); ok {
		if secretName, ok := spec["secretName"].(string); ok {
			cert.SecretName = secretName
		}
		if commonName, ok := spec["commonName"].(string); ok {
			cert.CommonName = commonName
		}
		if dnsNames, ok := spec["dnsNames"].([]interface{}); ok {
			for _, dns := range dnsNames {
				if dnsStr, ok := dns.(string); ok {
					cert.DNSNames = append(cert.DNSNames, dnsStr)
				}
			}
		}
		if issuerRef, ok := spec["issuerRef"].(map[string]interface{}); ok {
			if name, ok := issuerRef["name"].(string); ok {
				cert.IssuerRef = name
			}
			if kind, ok := issuerRef["kind"].(string); ok {
				cert.IssuerKind = kind
			} else {
				cert.IssuerKind = "Issuer"
			}
		}
	}

	// Check status
	if status, ok := obj["status"].(map[string]interface{}); ok {
		if conditions, ok := status["conditions"].([]interface{}); ok {
			for _, cond := range conditions {
				if condMap, ok := cond.(map[string]interface{}); ok {
					if condType, ok := condMap["type"].(string); ok && condType == "Ready" {
						if condStatus, ok := condMap["status"].(string); ok {
							cert.Ready = condStatus == "True"
						}
						if reason, ok := condMap["reason"].(string); ok {
							cert.ReadyReason = reason
						}
					}
				}
			}
		}

		// Parse dates
		if notBefore, ok := status["notBefore"].(string); ok {
			if t, err := time.Parse(time.RFC3339, notBefore); err == nil {
				cert.NotBefore = t
			}
		}
		if notAfter, ok := status["notAfter"].(string); ok {
			if t, err := time.Parse(time.RFC3339, notAfter); err == nil {
				cert.NotAfter = t
				// Calculate days until expiry
				cert.DaysUntilExpiry = int(time.Until(t).Hours() / 24)
				cert.IsExpired = time.Now().After(t)
				cert.IsExpiringSoon = cert.DaysUntilExpiry <= 30 && cert.DaysUntilExpiry > 0
			}
		}
		if renewalTime, ok := status["renewalTime"].(string); ok {
			if t, err := time.Parse(time.RFC3339, renewalTime); err == nil {
				cert.RenewalTime = t
			}
		}
	}

	return cert
}

// ============================================================================
// CertificateRequest Analysis
// ============================================================================

func analyzeCertificateRequests(ctx context.Context, dynClient dynamic.Interface) []CertificateRequestInfo {
	var certRequests []CertificateRequestInfo

	crGVR := schema.GroupVersionResource{
		Group:    "cert-manager.io",
		Version:  "v1",
		Resource: "certificaterequests",
	}

	crList, err := dynClient.Resource(crGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range crList.Items {
			cr := parseCertAdmissionCertRequest(item.Object)
			certRequests = append(certRequests, cr)
		}
	}

	return certRequests
}

func parseCertAdmissionCertRequest(obj map[string]interface{}) CertificateRequestInfo {
	cr := CertificateRequestInfo{}

	if metadata, ok := obj["metadata"].(map[string]interface{}); ok {
		cr.Name, _ = metadata["name"].(string)
		cr.Namespace, _ = metadata["namespace"].(string)
	}

	if spec, ok := obj["spec"].(map[string]interface{}); ok {
		if issuerRef, ok := spec["issuerRef"].(map[string]interface{}); ok {
			if name, ok := issuerRef["name"].(string); ok {
				cr.IssuerRef = name
			}
		}
	}

	if status, ok := obj["status"].(map[string]interface{}); ok {
		if conditions, ok := status["conditions"].([]interface{}); ok {
			for _, cond := range conditions {
				if condMap, ok := cond.(map[string]interface{}); ok {
					condType, _ := condMap["type"].(string)
					condStatus, _ := condMap["status"].(string)

					switch condType {
					case "Ready":
						cr.Ready = condStatus == "True"
					case "Approved":
						cr.Approved = condStatus == "True"
					case "Denied":
						cr.Denied = condStatus == "True"
					}
				}
			}
		}
		if failureTime, ok := status["failureTime"].(string); ok {
			cr.FailureTime = failureTime
		}
	}

	return cr
}

// ============================================================================
// Kubernetes CSR Analysis
// ============================================================================

func analyzeCSRs(ctx context.Context, clientset kubernetes.Interface) []CSRInfo {
	var csrs []CSRInfo

	csrList, err := clientset.CertificatesV1().CertificateSigningRequests().List(ctx, metav1.ListOptions{})
	if err != nil {
		return csrs
	}

	for _, csr := range csrList.Items {
		info := CSRInfo{
			Name:       csr.Name,
			SignerName: csr.Spec.SignerName,
			RequestedBy: csr.Spec.Username,
			ExpirationSeconds: 0,
		}

		if csr.Spec.ExpirationSeconds != nil {
			info.ExpirationSeconds = int(*csr.Spec.ExpirationSeconds)
		}

		for _, usage := range csr.Spec.Usages {
			info.Usages = append(info.Usages, string(usage))
		}

		// Check conditions
		for _, cond := range csr.Status.Conditions {
			switch cond.Type {
			case "Approved":
				info.Approved = true
			case "Denied":
				info.Denied = true
			}
		}

		info.Issued = len(csr.Status.Certificate) > 0

		csrs = append(csrs, info)
	}

	return csrs
}

// ============================================================================
// CSR Approver Analysis
// ============================================================================

func analyzeCSRApprovers(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) []CSRApproverInfo {
	var approvers []CSRApproverInfo

	// Check for kubelet-csr-approver
	namespaces := []string{"kube-system", "kubelet-csr-approver"}
	for _, ns := range namespaces {
		deployments, err := clientset.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, dep := range deployments.Items {
			if strings.Contains(strings.ToLower(dep.Name), "csr-approver") ||
				strings.Contains(strings.ToLower(dep.Name), "kubelet-rubber-stamp") {
				approver := CSRApproverInfo{
					Name:        dep.Name,
					Namespace:   ns,
					Type:        "kubelet-csr-approver",
					AutoApprove: true,
					SignerNames: []string{"kubernetes.io/kubelet-serving"},
				}

				approvers = append(approvers, approver)
			}
		}
	}

	// Check for cert-manager approver
	for _, ns := range []string{"cert-manager"} {
		deployments, err := clientset.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, dep := range deployments.Items {
			if strings.Contains(strings.ToLower(dep.Name), "approver") {
				approver := CSRApproverInfo{
					Name:        dep.Name,
					Namespace:   ns,
					Type:        "cert-manager-approver",
					AutoApprove: true,
				}

				// Check for CertificateRequestPolicy CRDs
				crpGVR := schema.GroupVersionResource{
					Group:    "policy.cert-manager.io",
					Version:  "v1alpha1",
					Resource: "certificaterequestpolicies",
				}
				policies, err := dynClient.Resource(crpGVR).Namespace("").List(ctx, metav1.ListOptions{})
				if err == nil && len(policies.Items) > 0 {
					approver.AutoApprove = false // Has policies, not auto-approve
				}

				approvers = append(approvers, approver)
			}
		}
	}

	return approvers
}

// ============================================================================
// Venafi Analysis
// ============================================================================

func analyzeVenafi(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) VenafiInfo {
	info := VenafiInfo{}

	// Check for Venafi Enhanced Issuer (VEI) deployment
	// Using SDK's expected namespaces for Venafi
	namespaces := admission.GetExpectedNamespaces("venafi")
	if len(namespaces) == 0 {
		namespaces = []string{"venafi", "cert-manager", "kube-system"}
	}

	for _, ns := range namespaces {
		deployments, err := clientset.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, dep := range deployments.Items {
			for _, container := range dep.Spec.Template.Spec.Containers {
				// Use SDK verification for reduced false positives
				if verifyCertEngineImage(container.Image, "venafi") {
					info.Name = "Venafi"
					info.Namespace = ns
					info.Status = "active"
					info.TotalPods = int(dep.Status.Replicas)
					info.PodsRunning = int(dep.Status.ReadyReplicas)
					info.ImageVerified = true

					if info.PodsRunning < info.TotalPods {
						info.Status = "degraded"
					}
					break
				}
			}
			if info.Name != "" {
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

	// Check for VenafiIssuer or VenafiClusterIssuer CRDs
	venafiIssuerGVR := schema.GroupVersionResource{
		Group:    "jetstack.io",
		Version:  "v1alpha1",
		Resource: "venafiissuers",
	}

	issuerList, err := dynClient.Resource(venafiIssuerGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range issuerList.Items {
			if spec, ok := item.Object["spec"].(map[string]interface{}); ok {
				if tpp, ok := spec["tpp"].(map[string]interface{}); ok {
					if url, ok := tpp["url"].(string); ok {
						info.TPPUrl = url
					}
				}
				if cloud, ok := spec["cloud"].(map[string]interface{}); ok {
					if url, ok := cloud["url"].(string); ok {
						info.CloudApiUrl = url
					}
				}
				if zone, ok := spec["zone"].(string); ok {
					info.Zone = zone
				}
			}
		}
	}

	// Also check cert-manager issuers with Venafi type
	issuerGVR := schema.GroupVersionResource{
		Group:    "cert-manager.io",
		Version:  "v1",
		Resource: "clusterissuers",
	}

	cmIssuerList, err := dynClient.Resource(issuerGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range cmIssuerList.Items {
			if spec, ok := item.Object["spec"].(map[string]interface{}); ok {
				if venafi, ok := spec["venafi"].(map[string]interface{}); ok {
					if zone, ok := venafi["zone"].(string); ok {
						info.Zone = zone
					}
					if tpp, ok := venafi["tpp"].(map[string]interface{}); ok {
						if url, ok := tpp["url"].(string); ok {
							info.TPPUrl = url
						}
					}
					if cloud, ok := venafi["cloud"].(map[string]interface{}); ok {
						if url, ok := cloud["url"].(string); ok {
							info.CloudApiUrl = url
						}
					}
				}
			}
		}
	}

	return info
}

// ============================================================================
// SPIFFE/SPIRE Analysis
// ============================================================================

func analyzeSPIFFE(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) SPIFFEInfo {
	info := SPIFFEInfo{}

	// Check for SPIRE Server
	namespaces := []string{"spire", "spire-system", "spiffe"}
	for _, ns := range namespaces {
		// Check StatefulSet for SPIRE Server
		statefulSets, err := clientset.AppsV1().StatefulSets(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, sts := range statefulSets.Items {
			if strings.Contains(strings.ToLower(sts.Name), "spire-server") {
				info.Name = "SPIRE"
				info.Namespace = ns
				info.Status = "active"
				info.ServerRunning = sts.Status.ReadyReplicas > 0

				if !info.ServerRunning {
					info.Status = "not-running"
				}
				break
			}
		}
		if info.Name != "" {
			break
		}
	}

	if info.Name == "" {
		// Try checking for spire-agent DaemonSet
		for _, ns := range namespaces {
			daemonSets, err := clientset.AppsV1().DaemonSets(ns).List(ctx, metav1.ListOptions{})
			if err != nil {
				continue
			}

			for _, ds := range daemonSets.Items {
				if strings.Contains(strings.ToLower(ds.Name), "spire-agent") {
					info.Name = "SPIRE"
					info.Namespace = ns
					info.Status = "active"
					info.TotalAgents = int(ds.Status.DesiredNumberScheduled)
					info.AgentsRunning = int(ds.Status.NumberReady)

					if info.AgentsRunning < info.TotalAgents {
						info.Status = "degraded"
					}
					break
				}
			}
			if info.Name != "" {
				break
			}
		}
	}

	if info.Name == "" {
		return info
	}

	// Check for ClusterSPIFFEID CRDs (spire-controller-manager)
	spiffeIDGVR := schema.GroupVersionResource{
		Group:    "spire.spiffe.io",
		Version:  "v1alpha1",
		Resource: "clusterspiffeids",
	}

	spiffeIDList, err := dynClient.Resource(spiffeIDGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		info.Registrations = len(spiffeIDList.Items)
	}

	// Try to get trust domain from ConfigMap
	configMaps, err := clientset.CoreV1().ConfigMaps(info.Namespace).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, cm := range configMaps.Items {
			if strings.Contains(cm.Name, "spire") {
				for _, data := range cm.Data {
					if strings.Contains(data, "trust_domain") {
						// Simple extraction
						lines := strings.Split(data, "\n")
						for _, line := range lines {
							if strings.Contains(line, "trust_domain") {
								parts := strings.Split(line, "=")
								if len(parts) > 1 {
									info.TrustDomain = strings.TrimSpace(strings.Trim(parts[1], "\""))
								}
							}
						}
					}
				}
			}
		}
	}

	// Verify by checking images
	for _, ns := range namespaces {
		statefulSets, err := clientset.AppsV1().StatefulSets(ns).List(ctx, metav1.ListOptions{})
		if err == nil {
			for _, sts := range statefulSets.Items {
				for _, container := range sts.Spec.Template.Spec.Containers {
					if verifyCertEngineImage(container.Image, "spiffe") {
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
// Istio Certificate Analysis
// ============================================================================

func analyzeIstioCerts(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) IstioCertInfo {
	info := IstioCertInfo{}

	// Check for Istiod
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

				// Check for external CA configuration
				for _, container := range dep.Spec.Template.Spec.Containers {
					for _, env := range container.Env {
						if env.Name == "EXTERNAL_CA" && env.Value == "ISTIOD_RA_KUBERNETES_API" {
							info.ExternalCA = true
						}
						if env.Name == "DEFAULT_WORKLOAD_CERT_TTL" {
							info.WorkloadCertTTL = env.Value
						}
					}
					for _, arg := range container.Args {
						if strings.Contains(arg, "workloadCertTTL") {
							parts := strings.Split(arg, "=")
							if len(parts) > 1 {
								info.WorkloadCertTTL = parts[1]
							}
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

	// Check root CA certificate expiry
	secrets, err := clientset.CoreV1().Secrets(info.Namespace).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, secret := range secrets.Items {
			if secret.Name == "istio-ca-secret" || secret.Name == "cacerts" {
				// Root CA found
				info.RotationEnabled = true
				// Note: Actual cert parsing would require additional crypto libraries
				break
			}
		}
	}

	if info.WorkloadCertTTL == "" {
		info.WorkloadCertTTL = "24h" // Default
	}

	// Verify by checking deployment images
	for _, ns := range namespaces {
		deployments, err := clientset.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
		if err == nil {
			for _, dep := range deployments.Items {
				for _, container := range dep.Spec.Template.Spec.Containers {
					if verifyCertEngineImage(container.Image, "istio") {
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
// Build Findings
// ============================================================================

func buildCertAdmissionFindings(certManager CertManagerInfo, issuers []IssuerInfo, certificates []CertAdmissionCertInfo) []CertAdmissionFinding {
	// Initialize findings per namespace
	namespaceData := make(map[string]*CertAdmissionFinding)
	for _, ns := range globals.K8sNamespaces {
		namespaceData[ns] = &CertAdmissionFinding{
			Namespace:      ns,
			HasCertManager: certManager.Name != "",
		}
	}

	// Count ClusterIssuers (apply to all namespaces)
	clusterIssuers := 0
	for _, issuer := range issuers {
		if issuer.IsCluster {
			clusterIssuers++
		} else {
			if finding, ok := namespaceData[issuer.Namespace]; ok {
				finding.Issuers++
				switch issuer.Type {
				case "SelfSigned":
					finding.SelfSignedCerts++ // Will be corrected by certificates
				case "CA":
					finding.CASignedCerts++
				case "ACME":
					finding.ACMECerts++
				case "Vault":
					finding.VaultCerts++
				case "Venafi":
					finding.VenafiCerts++
				}
			}
		}
	}

	// Apply cluster issuers to all namespaces
	for _, finding := range namespaceData {
		finding.ClusterIssuers = clusterIssuers
	}

	// Count certificates
	for _, cert := range certificates {
		if finding, ok := namespaceData[cert.Namespace]; ok {
			finding.Certificates++

			if cert.Ready && !cert.IsExpired {
				finding.ValidCerts++
			}
			if cert.IsExpiringSoon {
				finding.ExpiringSoonCerts++
			}
			if cert.IsExpired {
				finding.ExpiredCerts++
			}
			if !cert.Ready {
				finding.FailedCerts++
			}
		}
	}

	// Build findings list
	var findings []CertAdmissionFinding
	for _, finding := range namespaceData {
		// Identify issues
		if finding.ExpiredCerts > 0 {
			finding.SecurityIssues = append(finding.SecurityIssues, fmt.Sprintf("%d expired certs", finding.ExpiredCerts))
		}
		if finding.ExpiringSoonCerts > 0 {
			finding.SecurityIssues = append(finding.SecurityIssues, fmt.Sprintf("%d certs expiring soon", finding.ExpiringSoonCerts))
		}
		if finding.FailedCerts > 0 {
			finding.SecurityIssues = append(finding.SecurityIssues, fmt.Sprintf("%d failed certs", finding.FailedCerts))
		}
		if finding.SelfSignedCerts > 0 && finding.CASignedCerts == 0 && finding.ACMECerts == 0 {
			finding.SecurityIssues = append(finding.SecurityIssues, "Only self-signed certs")
		}

		findings = append(findings, *finding)
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

func generateCertAdmissionLoot(loot *shared.LootBuilder,
	findings []CertAdmissionFinding,
	certManager CertManagerInfo,
	issuers []IssuerInfo,
	certificates []CertAdmissionCertInfo,
	csrs []CSRInfo,
	csrApprovers []CSRApproverInfo,
	venafi VenafiInfo,
	spiffe SPIFFEInfo,
	istioCerts IstioCertInfo) {

	// Summary
	loot.Section("cert-admission").Add("# Certificate Management Summary")
	loot.Section("cert-admission").Add("#")

	if certManager.Name != "" {
		loot.Section("cert-admission").Add(fmt.Sprintf("# cert-manager: %s (version: %s)", certManager.Status, certManager.Version))
	} else {
		loot.Section("cert-admission").Add("# cert-manager: NOT INSTALLED")
	}

	// Count issuers
	clusterIssuers := 0
	nsIssuers := 0
	for _, issuer := range issuers {
		if issuer.IsCluster {
			clusterIssuers++
		} else {
			nsIssuers++
		}
	}
	loot.Section("cert-admission").Add(fmt.Sprintf("# ClusterIssuers: %d", clusterIssuers))
	loot.Section("cert-admission").Add(fmt.Sprintf("# Namespace Issuers: %d", nsIssuers))
	loot.Section("cert-admission").Add(fmt.Sprintf("# Certificates: %d", len(certificates)))
	if venafi.Name != "" {
		loot.Section("cert-admission").Add(fmt.Sprintf("# Venafi: %s", venafi.Status))
	}
	if spiffe.Name != "" {
		loot.Section("cert-admission").Add(fmt.Sprintf("# SPIFFE/SPIRE: %s", spiffe.Status))
	}
	if istioCerts.Name != "" {
		loot.Section("cert-admission").Add(fmt.Sprintf("# Istio Certificates: %s", istioCerts.Status))
	}
	loot.Section("cert-admission").Add("#")

	// Certificate health
	valid := 0
	expiringSoon := 0
	expired := 0
	failed := 0
	for _, cert := range certificates {
		if cert.Ready && !cert.IsExpired {
			valid++
		}
		if cert.IsExpiringSoon {
			expiringSoon++
		}
		if cert.IsExpired {
			expired++
		}
		if !cert.Ready {
			failed++
		}
	}

	loot.Section("cert-admission").Add("# Certificate Health")
	loot.Section("cert-admission").Add("#")
	loot.Section("cert-admission").Add(fmt.Sprintf("# Valid: %d", valid))
	loot.Section("cert-admission").Add(fmt.Sprintf("# Expiring Soon (30 days): %d", expiringSoon))
	loot.Section("cert-admission").Add(fmt.Sprintf("# EXPIRED: %d", expired))
	loot.Section("cert-admission").Add(fmt.Sprintf("# Failed: %d", failed))
	loot.Section("cert-admission").Add("#")

	// Expired certificates
	if expired > 0 {
		loot.Section("cert-admission").Add("# EXPIRED CERTIFICATES")
		loot.Section("cert-admission").Add("#")
		for _, cert := range certificates {
			if cert.IsExpired {
				loot.Section("cert-admission").Add(fmt.Sprintf("# %s/%s (expired: %s)", cert.Namespace, cert.Name, cert.NotAfter.Format("2006-01-02")))
			}
		}
		loot.Section("cert-admission").Add("#")
	}

	// Expiring soon
	if expiringSoon > 0 {
		loot.Section("cert-admission").Add("# CERTIFICATES EXPIRING SOON")
		loot.Section("cert-admission").Add("#")
		for _, cert := range certificates {
			if cert.IsExpiringSoon {
				loot.Section("cert-admission").Add(fmt.Sprintf("# %s/%s (expires: %s, %d days)", cert.Namespace, cert.Name, cert.NotAfter.Format("2006-01-02"), cert.DaysUntilExpiry))
			}
		}
		loot.Section("cert-admission").Add("#")
	}

	// Enterprise Certificate Management
	if venafi.Name != "" || spiffe.Name != "" || istioCerts.Name != "" {
		loot.Section("cert-admission").Add("# Enterprise Certificate Management")
		loot.Section("cert-admission").Add("#")

		if venafi.Name != "" {
			loot.Section("cert-admission").Add(fmt.Sprintf("# Venafi: %s (namespace: %s)", venafi.Status, venafi.Namespace))
			if venafi.TPPUrl != "" {
				loot.Section("cert-admission").Add(fmt.Sprintf("#   TPP URL: %s", venafi.TPPUrl))
			}
			if venafi.CloudApiUrl != "" {
				loot.Section("cert-admission").Add(fmt.Sprintf("#   Cloud API: %s", venafi.CloudApiUrl))
			}
			if venafi.Zone != "" {
				loot.Section("cert-admission").Add(fmt.Sprintf("#   Zone: %s", venafi.Zone))
			}
		}

		if spiffe.Name != "" {
			loot.Section("cert-admission").Add(fmt.Sprintf("# SPIFFE/SPIRE: %s (namespace: %s)", spiffe.Status, spiffe.Namespace))
			if spiffe.TrustDomain != "" {
				loot.Section("cert-admission").Add(fmt.Sprintf("#   Trust Domain: %s", spiffe.TrustDomain))
			}
			loot.Section("cert-admission").Add(fmt.Sprintf("#   Registrations: %d", spiffe.Registrations))
		}

		if istioCerts.Name != "" {
			loot.Section("cert-admission").Add(fmt.Sprintf("# Istio Certificates: %s (namespace: %s)", istioCerts.Status, istioCerts.Namespace))
			loot.Section("cert-admission").Add(fmt.Sprintf("#   Workload Cert TTL: %s", istioCerts.WorkloadCertTTL))
			if istioCerts.ExternalCA {
				loot.Section("cert-admission").Add("#   External CA: Yes")
			}
		}

		loot.Section("cert-admission").Add("#")
	}

	// Commands (only for detected tools)
	loot.Section("cert-admission").Add("# Useful Commands")
	loot.Section("cert-admission").Add("#")

	if certManager.Name != "" {
		loot.Section("cert-admission").Add("# List all certificates:")
		loot.Section("cert-admission").Add("kubectl get certificates -A")
		loot.Section("cert-admission").Add("#")
		loot.Section("cert-admission").Add("# List all issuers:")
		loot.Section("cert-admission").Add("kubectl get issuers,clusterissuers -A")
		loot.Section("cert-admission").Add("#")
		loot.Section("cert-admission").Add("# Check certificate details:")
		loot.Section("cert-admission").Add("kubectl describe certificate <name> -n <namespace>")
		loot.Section("cert-admission").Add("#")
	}

	if len(csrs) > 0 {
		loot.Section("cert-admission").Add("# Check CSRs:")
		loot.Section("cert-admission").Add("kubectl get csr")
		loot.Section("cert-admission").Add("#")
	}

	if venafi.Name != "" {
		loot.Section("cert-admission").Add("# Check Venafi issuers:")
		loot.Section("cert-admission").Add("kubectl get venafiissuers,venaficlusterissuers -A")
		loot.Section("cert-admission").Add("#")
	}

	if spiffe.Name != "" {
		loot.Section("cert-admission").Add("# Check SPIFFE registrations:")
		loot.Section("cert-admission").Add("kubectl get clusterspiffeids -A")
		loot.Section("cert-admission").Add("#")
	}

	if istioCerts.Name != "" {
		loot.Section("cert-admission").Add("# Check Istio certificates:")
		loot.Section("cert-admission").Add(fmt.Sprintf("kubectl get secret -n %s -l istio.io/config=true", istioCerts.Namespace))
		loot.Section("cert-admission").Add("#")
	}
}

// ============================================================================
// Cloud Provider API Integration
// ============================================================================

// CertCloudClients holds cloud provider clients for certificate enumeration
type CertCloudClients struct {
	AWSACMClient       *acm.Client
	AzureKeyVaultClient *armkeyvault.VaultsClient
}

// AWSACMCertificateInfo represents an AWS ACM certificate
type AWSACMCertificateInfo struct {
	ARN              string
	DomainName       string
	Status           string
	Type             string // AMAZON_ISSUED, IMPORTED, PRIVATE
	Issuer           string
	NotBefore        time.Time
	NotAfter         time.Time
	DaysUntilExpiry  int
	InUseBy          []string
	RenewalEligible  bool
	KeyAlgorithm     string
}

// AzureKeyVaultCertInfo represents an Azure Key Vault certificate
type AzureKeyVaultCertInfo struct {
	VaultName        string
	VaultURI         string
	CertificateName  string
	Enabled          bool
	NotBefore        time.Time
	Expires          time.Time
	DaysUntilExpiry  int
}

// initCertCloudClients attempts to initialize cloud provider clients for cert enumeration
// Similar to initDNSCloudClients in dns-admission.go
func initCertCloudClients(logger internal.Logger) *CertCloudClients {
	clients := &CertCloudClients{}

	// Try to initialize AWS ACM client
	cfg, err := awsconfig.LoadDefaultConfig(context.Background())
	if err == nil {
		clients.AWSACMClient = acm.NewFromConfig(cfg)
		logger.InfoM("AWS ACM client initialized", K8S_CERT_ADMISSION_MODULE_NAME)
	}

	// Try to initialize Azure Key Vault client
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err == nil {
		// Note: Would need subscription ID from env
		subID := "" // Would get from AZURE_SUBSCRIPTION_ID env var
		if subID != "" {
			vaultsClient, err := armkeyvault.NewVaultsClient(subID, cred, nil)
			if err == nil {
				clients.AzureKeyVaultClient = vaultsClient
				logger.InfoM("Azure Key Vault client initialized", K8S_CERT_ADMISSION_MODULE_NAME)
			}
		}
	}

	return clients
}

// analyzeAWSACMCertificates retrieves certificate info from AWS ACM
// Uses AWS API if cloud clients are available, otherwise falls back to in-cluster detection
func analyzeAWSACMCertificates(ctx context.Context, cloudClients *CertCloudClients, logger internal.Logger) []AWSACMCertificateInfo {
	var certs []AWSACMCertificateInfo

	if cloudClients == nil || cloudClients.AWSACMClient == nil {
		return certs
	}

	// List all certificates
	listOutput, err := cloudClients.AWSACMClient.ListCertificates(ctx, &acm.ListCertificatesInput{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to list ACM certificates: %v", err), K8S_CERT_ADMISSION_MODULE_NAME)
		return certs
	}

	for _, certSummary := range listOutput.CertificateSummaryList {
		// Get certificate details
		descOutput, err := cloudClients.AWSACMClient.DescribeCertificate(ctx, &acm.DescribeCertificateInput{
			CertificateArn: certSummary.CertificateArn,
		})
		if err != nil {
			continue
		}

		cert := descOutput.Certificate
		certInfo := AWSACMCertificateInfo{
			ARN:        aws.ToString(cert.CertificateArn),
			DomainName: aws.ToString(cert.DomainName),
			Status:     string(cert.Status),
			Type:       string(cert.Type),
			Issuer:     aws.ToString(cert.Issuer),
		}

		if cert.NotBefore != nil {
			certInfo.NotBefore = *cert.NotBefore
		}
		if cert.NotAfter != nil {
			certInfo.NotAfter = *cert.NotAfter
			certInfo.DaysUntilExpiry = int(time.Until(certInfo.NotAfter).Hours() / 24)
		}

		for _, lb := range cert.InUseBy {
			certInfo.InUseBy = append(certInfo.InUseBy, lb)
		}

		if cert.RenewalEligibility == "ELIGIBLE" {
			certInfo.RenewalEligible = true
		}

		if cert.KeyAlgorithm != "" {
			certInfo.KeyAlgorithm = string(cert.KeyAlgorithm)
		}

		certs = append(certs, certInfo)
	}

	logger.InfoM(fmt.Sprintf("Found %d AWS ACM certificates", len(certs)), K8S_CERT_ADMISSION_MODULE_NAME)
	return certs
}

// analyzeAzureKeyVaultCerts retrieves certificate info from Azure Key Vault
func analyzeAzureKeyVaultCerts(ctx context.Context, cloudClients *CertCloudClients, logger internal.Logger) []AzureKeyVaultCertInfo {
	var certs []AzureKeyVaultCertInfo

	if cloudClients == nil || cloudClients.AzureKeyVaultClient == nil {
		return certs
	}

	// Note: This would require listing vaults and then certificates from each vault
	// Simplified implementation - would expand in production

	logger.InfoM("Azure Key Vault certificate enumeration requires additional setup", K8S_CERT_ADMISSION_MODULE_NAME)
	return certs
}
