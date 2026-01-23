package commands

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

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
  - AWS ACM integration
  - Istio certificate management
  - Certificate expiration analysis
  - Self-signed vs CA-signed certificates

  cloudfox kubernetes cert-admission`,
	Run: ListCertAdmission,
}

type CertAdmissionOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t CertAdmissionOutput) TableFiles() []internal.TableFile { return t.Table }
func (t CertAdmissionOutput) LootFiles() []internal.LootFile   { return t.Loot }

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

	// Risk Analysis
	RiskLevel      string
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
	BypassRisk    string
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
	BypassRisk    string
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
	BypassRisk     string
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
	BypassRisk  string
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
	BypassRisk   string
}

// CSRApproverInfo represents a CSR auto-approver
type CSRApproverInfo struct {
	Name         string
	Namespace    string
	Type         string // kubelet-csr-approver, cert-manager, custom
	SignerNames  []string
	AutoApprove  bool
	BypassRisk   string
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
	BypassRisk    string
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
	BypassRisk    string
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
	BypassRisk      string
	ImageVerified   bool // True if Istio control plane image was verified
}

// verifyCertEngineImage checks if a container image matches known patterns for a cert engine
// Now uses the shared admission SDK for centralized engine detection
func verifyCertEngineImage(image string, engine string) bool {
	return VerifyControllerImage(image, engine)
}

func ListCertAdmission(cmd *cobra.Command, args []string) {
	ctx, cancel := shared.ContextWithCancel()
	defer cancel()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDir, _ := parentCmd.PersistentFlags().GetString("outdir")

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
		"Risk Level",
		"Issues",
	}

	certManagerHeader := []string{
		"Namespace",
		"Version",
		"Status",
		"Pods Running",
		"Webhooks",
		"Bypass Risk",
	}

	issuerHeader := []string{
		"Name",
		"Namespace",
		"Scope",
		"Type",
		"Ready",
		"Details",
		"Bypass Risk",
	}

	certificateHeader := []string{
		"Name",
		"Namespace",
		"Secret",
		"Issuer",
		"DNS Names",
		"Ready",
		"Expires",
		"Days Left",
		"Bypass Risk",
	}

	certRequestHeader := []string{
		"Name",
		"Namespace",
		"Issuer",
		"Approved",
		"Denied",
		"Ready",
		"Bypass Risk",
	}

	csrHeader := []string{
		"Name",
		"Signer",
		"Requested By",
		"Usages",
		"Approved",
		"Issued",
		"Bypass Risk",
	}

	csrApproverHeader := []string{
		"Name",
		"Namespace",
		"Type",
		"Signer Names",
		"Auto Approve",
		"Bypass Risk",
	}

	venafiHeader := []string{
		"Namespace",
		"Status",
		"Pods Running",
		"TPP URL",
		"Cloud URL",
		"Zone",
		"Bypass Risk",
	}

	spiffeHeader := []string{
		"Namespace",
		"Status",
		"Server Running",
		"Agents Running",
		"Trust Domain",
		"Registrations",
		"Bypass Risk",
	}

	istioCertHeader := []string{
		"Namespace",
		"Status",
		"Workload Cert TTL",
		"External CA",
		"Rotation Enabled",
		"Bypass Risk",
	}

	var summaryRows [][]string
	var certManagerRows [][]string
	var issuerRows [][]string
	var certificateRows [][]string
	var certRequestRows [][]string
	var csrRows [][]string
	var csrApproverRows [][]string
	var venafiRows [][]string
	var spiffeRows [][]string
	var istioCertRows [][]string

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
			finding.RiskLevel,
			issues,
		})
	}

	// Build cert-manager rows
	if certManager.Name != "" {
		webhooks := "No"
		if certManager.Webhooks {
			webhooks = "Yes"
		}

		certManagerRows = append(certManagerRows, []string{
			certManager.Namespace,
			certManager.Version,
			certManager.Status,
			fmt.Sprintf("%d/%d", certManager.PodsRunning, certManager.TotalPods),
			webhooks,
			certManager.BypassRisk,
		})
	}

	// Build issuer rows
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

		issuerRows = append(issuerRows, []string{
			issuer.Name,
			ns,
			scope,
			issuer.Type,
			ready,
			details,
			issuer.BypassRisk,
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

		certificateRows = append(certificateRows, []string{
			cert.Name,
			cert.Namespace,
			cert.SecretName,
			fmt.Sprintf("%s/%s", cert.IssuerKind, cert.IssuerRef),
			dnsNames,
			ready,
			expires,
			daysLeft,
			cert.BypassRisk,
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

		certRequestRows = append(certRequestRows, []string{
			cr.Name,
			cr.Namespace,
			cr.IssuerRef,
			approved,
			denied,
			ready,
			cr.BypassRisk,
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

		csrRows = append(csrRows, []string{
			csr.Name,
			csr.SignerName,
			csr.RequestedBy,
			usages,
			approved,
			issued,
			csr.BypassRisk,
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

		csrApproverRows = append(csrApproverRows, []string{
			approver.Name,
			approver.Namespace,
			approver.Type,
			signers,
			autoApprove,
			approver.BypassRisk,
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
		bypassRisk := "-"
		if venafi.BypassRisk != "" {
			bypassRisk = venafi.BypassRisk
		}

		venafiRows = append(venafiRows, []string{
			venafi.Namespace,
			venafi.Status,
			fmt.Sprintf("%d/%d", venafi.PodsRunning, venafi.TotalPods),
			tppUrl,
			cloudUrl,
			zone,
			bypassRisk,
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
		bypassRisk := "-"
		if spiffe.BypassRisk != "" {
			bypassRisk = spiffe.BypassRisk
		}

		spiffeRows = append(spiffeRows, []string{
			spiffe.Namespace,
			spiffe.Status,
			serverRunning,
			fmt.Sprintf("%d/%d", spiffe.AgentsRunning, spiffe.TotalAgents),
			trustDomain,
			fmt.Sprintf("%d", spiffe.Registrations),
			bypassRisk,
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
		bypassRisk := "-"
		if istioCerts.BypassRisk != "" {
			bypassRisk = istioCerts.BypassRisk
		}

		istioCertRows = append(istioCertRows, []string{
			istioCerts.Namespace,
			istioCerts.Status,
			certTTL,
			externalCA,
			rotationEnabled,
			bypassRisk,
		})
	}

	// Generate loot
	generateCertAdmissionLoot(loot, findings, certManager, issuers, certificates, csrs, csrApprovers, venafi, spiffe, istioCerts)

	// Build output tables
	var tables []internal.TableFile

	tables = append(tables, internal.TableFile{
		Name:   "Cert-Admission-Summary",
		Header: summaryHeader,
		Body:   summaryRows,
	})

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
					info.BypassRisk = fmt.Sprintf("Only %d/%d cert-manager pods running", info.PodsRunning, info.TotalPods)
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

	if !info.Webhooks {
		info.BypassRisk = "cert-manager webhooks not found"
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
			issuer.BypassRisk = "Self-signed certificates - not trusted by clients"
		} else if ca, ok := spec["ca"].(map[string]interface{}); ok {
			issuer.Type = "CA"
			if secretName, ok := ca["secretName"].(string); ok {
				issuer.CASecretName = secretName
			}
		} else if acme, ok := spec["acme"].(map[string]interface{}); ok {
			issuer.Type = "ACME"
			if server, ok := acme["server"].(string); ok {
				issuer.ACMEServer = server
				if strings.Contains(server, "staging") {
					issuer.BypassRisk = "Using staging ACME server"
				}
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

	if !issuer.Ready && issuer.BypassRisk == "" {
		issuer.BypassRisk = fmt.Sprintf("Issuer not ready: %s", issuer.ReadyReason)
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

	// Assess risk
	if cert.IsExpired {
		cert.BypassRisk = "Certificate EXPIRED"
	} else if cert.IsExpiringSoon {
		cert.BypassRisk = fmt.Sprintf("Expires in %d days", cert.DaysUntilExpiry)
	} else if !cert.Ready {
		cert.BypassRisk = fmt.Sprintf("Certificate not ready: %s", cert.ReadyReason)
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

	if cr.Denied {
		cr.BypassRisk = "Certificate request denied"
	} else if !cr.Approved && !cr.Ready {
		cr.BypassRisk = "Pending approval"
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

		// Assess risk
		if info.Approved && !info.Issued {
			info.BypassRisk = "Approved but not issued"
		}
		if strings.Contains(info.SignerName, "legacy-unknown") {
			info.BypassRisk = "Legacy unknown signer - may auto-approve"
		}

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

				if approver.AutoApprove {
					approver.BypassRisk = "Auto-approves kubelet CSRs"
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
				} else {
					approver.BypassRisk = "No CertificateRequestPolicies found"
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
	namespaces := GetExpectedNamespaces("venafi")
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
						info.BypassRisk = fmt.Sprintf("Only %d/%d Venafi pods running", info.PodsRunning, info.TotalPods)
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
					info.BypassRisk = "SPIRE server not running"
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
						info.BypassRisk = fmt.Sprintf("Only %d/%d SPIRE agents running", info.AgentsRunning, info.TotalAgents)
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

	// Check for short TTLs which might cause issues
	if strings.Contains(info.WorkloadCertTTL, "m") && !strings.Contains(info.WorkloadCertTTL, "h") {
		info.BypassRisk = "Short workload cert TTL may cause rotation issues"
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
		// Calculate risk
		if finding.ExpiredCerts > 0 {
			finding.RiskLevel = "CRITICAL"
			finding.SecurityIssues = append(finding.SecurityIssues, fmt.Sprintf("%d expired certs", finding.ExpiredCerts))
		} else if finding.ExpiringSoonCerts > 0 {
			finding.RiskLevel = "HIGH"
			finding.SecurityIssues = append(finding.SecurityIssues, fmt.Sprintf("%d certs expiring soon", finding.ExpiringSoonCerts))
		} else if finding.FailedCerts > 0 {
			finding.RiskLevel = "MEDIUM"
			finding.SecurityIssues = append(finding.SecurityIssues, fmt.Sprintf("%d failed certs", finding.FailedCerts))
		} else if finding.SelfSignedCerts > 0 && finding.CASignedCerts == 0 && finding.ACMECerts == 0 {
			finding.RiskLevel = "MEDIUM"
			finding.SecurityIssues = append(finding.SecurityIssues, "Only self-signed certs")
		} else {
			finding.RiskLevel = "LOW"
		}

		findings = append(findings, *finding)
	}

	// Sort by risk level then namespace
	sort.Slice(findings, func(i, j int) bool {
		riskOrder := map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
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
	loot.Section("Summary").Add("# Certificate Management Summary")
	loot.Section("Summary").Add("#")

	if certManager.Name != "" {
		loot.Section("Summary").Add(fmt.Sprintf("# cert-manager: %s (version: %s)", certManager.Status, certManager.Version))
	} else {
		loot.Section("Summary").Add("# cert-manager: NOT INSTALLED")
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
	loot.Section("Summary").Add(fmt.Sprintf("# ClusterIssuers: %d", clusterIssuers))
	loot.Section("Summary").Add(fmt.Sprintf("# Namespace Issuers: %d", nsIssuers))
	loot.Section("Summary").Add(fmt.Sprintf("# Certificates: %d", len(certificates)))
	if venafi.Name != "" {
		loot.Section("Summary").Add(fmt.Sprintf("# Venafi: %s", venafi.Status))
	}
	if spiffe.Name != "" {
		loot.Section("Summary").Add(fmt.Sprintf("# SPIFFE/SPIRE: %s", spiffe.Status))
	}
	if istioCerts.Name != "" {
		loot.Section("Summary").Add(fmt.Sprintf("# Istio Certificates: %s", istioCerts.Status))
	}
	loot.Section("Summary").Add("#")

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

	loot.Section("CertHealth").Add("# Certificate Health")
	loot.Section("CertHealth").Add("#")
	loot.Section("CertHealth").Add(fmt.Sprintf("# Valid: %d", valid))
	loot.Section("CertHealth").Add(fmt.Sprintf("# Expiring Soon (30 days): %d", expiringSoon))
	loot.Section("CertHealth").Add(fmt.Sprintf("# EXPIRED: %d", expired))
	loot.Section("CertHealth").Add(fmt.Sprintf("# Failed: %d", failed))
	loot.Section("CertHealth").Add("#")

	// Expired certificates
	if expired > 0 {
		loot.Section("Expired").Add("# EXPIRED CERTIFICATES")
		loot.Section("Expired").Add("#")
		for _, cert := range certificates {
			if cert.IsExpired {
				loot.Section("Expired").Add(fmt.Sprintf("# %s/%s (expired: %s)", cert.Namespace, cert.Name, cert.NotAfter.Format("2006-01-02")))
			}
		}
		loot.Section("Expired").Add("#")
	}

	// Expiring soon
	if expiringSoon > 0 {
		loot.Section("ExpiringSoon").Add("# CERTIFICATES EXPIRING SOON")
		loot.Section("ExpiringSoon").Add("#")
		for _, cert := range certificates {
			if cert.IsExpiringSoon {
				loot.Section("ExpiringSoon").Add(fmt.Sprintf("# %s/%s (expires: %s, %d days)", cert.Namespace, cert.Name, cert.NotAfter.Format("2006-01-02"), cert.DaysUntilExpiry))
			}
		}
		loot.Section("ExpiringSoon").Add("#")
	}

	// Bypass vectors
	loot.Section("BypassVectors").Add("# Certificate Bypass Vectors")
	loot.Section("BypassVectors").Add("#")

	for _, issuer := range issuers {
		if issuer.BypassRisk != "" {
			scope := "Issuer"
			if issuer.IsCluster {
				scope = "ClusterIssuer"
			}
			loot.Section("BypassVectors").Add(fmt.Sprintf("# %s %s: %s", scope, issuer.Name, issuer.BypassRisk))
		}
	}

	for _, approver := range csrApprovers {
		if approver.BypassRisk != "" {
			loot.Section("BypassVectors").Add(fmt.Sprintf("# CSR Approver %s: %s", approver.Name, approver.BypassRisk))
		}
	}

	if venafi.BypassRisk != "" {
		loot.Section("BypassVectors").Add(fmt.Sprintf("# Venafi: %s", venafi.BypassRisk))
	}

	if spiffe.BypassRisk != "" {
		loot.Section("BypassVectors").Add(fmt.Sprintf("# SPIFFE/SPIRE: %s", spiffe.BypassRisk))
	}

	if istioCerts.BypassRisk != "" {
		loot.Section("BypassVectors").Add(fmt.Sprintf("# Istio Certs: %s", istioCerts.BypassRisk))
	}

	loot.Section("BypassVectors").Add("#")

	// Enterprise Certificate Management
	if venafi.Name != "" || spiffe.Name != "" || istioCerts.Name != "" {
		loot.Section("EnterpriseCerts").Add("# Enterprise Certificate Management")
		loot.Section("EnterpriseCerts").Add("#")

		if venafi.Name != "" {
			loot.Section("EnterpriseCerts").Add(fmt.Sprintf("# Venafi: %s (namespace: %s)", venafi.Status, venafi.Namespace))
			if venafi.TPPUrl != "" {
				loot.Section("EnterpriseCerts").Add(fmt.Sprintf("#   TPP URL: %s", venafi.TPPUrl))
			}
			if venafi.CloudApiUrl != "" {
				loot.Section("EnterpriseCerts").Add(fmt.Sprintf("#   Cloud API: %s", venafi.CloudApiUrl))
			}
			if venafi.Zone != "" {
				loot.Section("EnterpriseCerts").Add(fmt.Sprintf("#   Zone: %s", venafi.Zone))
			}
		}

		if spiffe.Name != "" {
			loot.Section("EnterpriseCerts").Add(fmt.Sprintf("# SPIFFE/SPIRE: %s (namespace: %s)", spiffe.Status, spiffe.Namespace))
			if spiffe.TrustDomain != "" {
				loot.Section("EnterpriseCerts").Add(fmt.Sprintf("#   Trust Domain: %s", spiffe.TrustDomain))
			}
			loot.Section("EnterpriseCerts").Add(fmt.Sprintf("#   Registrations: %d", spiffe.Registrations))
		}

		if istioCerts.Name != "" {
			loot.Section("EnterpriseCerts").Add(fmt.Sprintf("# Istio Certificates: %s (namespace: %s)", istioCerts.Status, istioCerts.Namespace))
			loot.Section("EnterpriseCerts").Add(fmt.Sprintf("#   Workload Cert TTL: %s", istioCerts.WorkloadCertTTL))
			if istioCerts.ExternalCA {
				loot.Section("EnterpriseCerts").Add("#   External CA: Yes")
			}
		}

		loot.Section("EnterpriseCerts").Add("#")
	}

	// Recommendations
	loot.Section("Recommendations").Add("# Recommendations")
	loot.Section("Recommendations").Add("#")

	if certManager.Name == "" {
		loot.Section("Recommendations").Add("# 1. Install cert-manager for automated certificate management:")
		loot.Section("Recommendations").Add("#    kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.14.0/cert-manager.yaml")
	}

	if expired > 0 {
		loot.Section("Recommendations").Add("# 2. Renew expired certificates immediately")
	}

	if expiringSoon > 0 {
		loot.Section("Recommendations").Add("# 3. Review certificates expiring soon and ensure auto-renewal is configured")
	}

	// Commands
	loot.Section("Commands").Add("# Useful Commands")
	loot.Section("Commands").Add("#")
	loot.Section("Commands").Add("# List all certificates:")
	loot.Section("Commands").Add("kubectl get certificates -A")
	loot.Section("Commands").Add("#")
	loot.Section("Commands").Add("# List all issuers:")
	loot.Section("Commands").Add("kubectl get issuers,clusterissuers -A")
	loot.Section("Commands").Add("#")
	loot.Section("Commands").Add("# Check certificate details:")
	loot.Section("Commands").Add("kubectl describe certificate <name> -n <namespace>")
	loot.Section("Commands").Add("#")
	loot.Section("Commands").Add("# Check CSRs:")
	loot.Section("Commands").Add("kubectl get csr")
}
