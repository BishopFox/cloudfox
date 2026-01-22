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

const K8S_SECRET_ADMISSION_MODULE_NAME = "secret-admission"

var SecretAdmissionCmd = &cobra.Command{
	Use:     "secret-admission",
	Aliases: []string{"secrets-mgmt", "external-secrets"},
	Short:   "Analyze external secret management and encryption policies",
	Long: `
Analyze all cluster secret management configurations including:
  - HashiCorp Vault (Agent Injector, Secrets Operator, CSI Provider)
  - External Secrets Operator (ESO)
  - Sealed Secrets (Bitnami)
  - Secrets Store CSI Driver (AWS, Azure, GCP providers)
  - Secret encryption at rest analysis
  - Unmanaged secrets detection
  - Policy verification and bypass detection

  cloudfox kubernetes secret-admission`,
	Run: ListSecretAdmission,
}

type SecretAdmissionOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t SecretAdmissionOutput) TableFiles() []internal.TableFile { return t.Table }
func (t SecretAdmissionOutput) LootFiles() []internal.LootFile   { return t.Loot }

// SecretAdmissionFinding represents comprehensive secret management analysis for a namespace
type SecretAdmissionFinding struct {
	Namespace string

	// Secret Management Coverage
	TotalSecrets          int
	ManagedSecrets        int
	UnmanagedSecrets      int
	ManagementCoverage    string // percentage
	HasExternalManagement bool

	// Vault Analysis
	VaultAgentInjectorActive    bool
	VaultSecretsOperatorActive  bool
	VaultCSIProviderActive      bool
	VaultManagedSecrets         int
	VaultInjectedPods           int
	VaultRoles                  []string
	VaultBypassRisk             string

	// External Secrets Operator
	ESOActive              bool
	ESOSecretStoreCount    int
	ESOExternalSecretCount int
	ESOManagedSecrets      int
	ESOProviders           []string
	ESOBypassRisk          string

	// Sealed Secrets
	SealedSecretsActive       bool
	SealedSecretCount         int
	SealedSecretsManagedCount int
	SealedSecretsScope        string // cluster-wide or namespace
	SealedSecretsBypassRisk   string

	// Secrets Store CSI Driver
	CSIDriverActive       bool
	CSIProviderClasses    int
	CSIMountedSecrets     int
	CSIProviders          []string // aws, azure, gcp, vault
	CSIBypassRisk         string

	// Risk Analysis
	RiskLevel            string
	SecurityIssues       []string
	BypassTechniques     []string
	UnmanagedHighRisk    int // Unmanaged secrets with sensitive data
	Recommendations      []string

	// Blocking Analysis (for summary table)
	SecretCreationBlocked   bool
	SecretCreationBlockedBy []string
	PlaintextBlocked        bool
	PlaintextBlockedBy      []string
}

// VaultAgentInjectorConfig represents Vault Agent Injector configuration
type VaultAgentInjectorConfig struct {
	Name              string
	Namespace         string
	WebhookName       string
	Status            string // active, not-running, webhook-misconfigured
	PodsRunning       int
	TotalPods         int
	FailurePolicy     string
	AuthMethod        string // kubernetes, jwt, etc.
	VaultAddr         string
	TLSEnabled        bool
	BypassRisk        string
	SecurityIssues    []string
	ImageVerified     bool // True if Vault Agent Injector image was verified
}

// VaultSecretsOperatorConfig represents Vault Secrets Operator (VSO) configuration
type VaultSecretsOperatorConfig struct {
	Name            string
	Namespace       string
	Status          string
	PodsRunning     int
	VaultAuthCount  int
	StaticSecrets   int
	DynamicSecrets  int
	PKISecrets      int
	SyncedSecrets   int
	BypassRisk      string
	SecurityIssues  []string
	ImageVerified   bool // True if Vault Secrets Operator image was verified
}

// VaultAuthConfig represents a VaultAuth CRD configuration
type VaultAuthConfig struct {
	Name           string
	Namespace      string
	Method         string // kubernetes, jwt, appRole, etc.
	Mount          string
	VaultAddr      string
	ServiceAccount string
	Role           string
	Headers        map[string]string
	AllowedNS      []string
	BypassRisk     string
}

// VaultStaticSecretConfig represents a VaultStaticSecret CRD
type VaultStaticSecretConfig struct {
	Name             string
	Namespace        string
	VaultAuthRef     string
	Mount            string
	Path             string
	Type             string // kv-v1, kv-v2
	RefreshAfter     string
	DestinationName  string
	DestinationType  string // Secret, ConfigMap
	SyncStatus       string
	LastSyncTime     string
	BypassRisk       string
}

// VaultDynamicSecretConfig represents a VaultDynamicSecret CRD
type VaultDynamicSecretConfig struct {
	Name            string
	Namespace       string
	VaultAuthRef    string
	Mount           string
	Path            string
	Role            string // database role, AWS role, etc.
	TTL             string
	RenewalPercent  int
	DestinationName string
	SyncStatus      string
	BypassRisk      string
}

// ExternalSecretConfig represents an ExternalSecret CRD
type ExternalSecretConfig struct {
	Name              string
	Namespace         string
	SecretStoreRef    string
	SecretStoreKind   string // SecretStore or ClusterSecretStore
	RefreshInterval   string
	TargetName        string
	TargetCreation    string // Owner, Orphan, Merge, None
	DataKeys          int
	SyncStatus        string
	LastSyncTime      string
	Provider          string // aws, azure, gcp, vault, etc.
	BypassRisk        string
}

// SecretStoreConfig represents a SecretStore or ClusterSecretStore CRD
type SecretStoreConfig struct {
	Name              string
	Namespace         string // empty for ClusterSecretStore
	IsClusterStore    bool
	Provider          string // aws, azure, gcp, vault, etc.
	ProviderConfig    string // summary of provider config
	Status            string // Valid, Invalid, Unknown
	Conditions        string
	ReferencedBy      int    // Number of ExternalSecrets using this store
	AuthMethod        string
	BypassRisk        string
	SecurityIssues    []string
}

// SealedSecretConfig represents a SealedSecret CRD
type SealedSecretConfig struct {
	Name            string
	Namespace       string
	Scope           string // strict, namespace-wide, cluster-wide
	EncryptedKeys   []string
	TargetName      string
	Status          string // Synced, Error, etc.
	ConditionStatus string
	BypassRisk      string
}

// SecretProviderClassConfig represents a SecretProviderClass CRD (Secrets Store CSI Driver)
type SecretProviderClassConfig struct {
	Name              string
	Namespace         string
	Provider          string // aws, azure, gcp, vault
	Parameters        map[string]string
	SecretObjects     int    // Number of secrets to sync
	UsedByPods        int    // Number of pods mounting this class
	Status            string
	BypassRisk        string
	SecurityIssues    []string
}

// UnmanagedSecretInfo represents a secret not managed by external systems
type UnmanagedSecretInfo struct {
	Name           string
	Namespace      string
	Type           string
	DataKeys       []string
	Age            string
	IsHighRisk     bool
	RiskReason     string
	MountedInPods  int
	Recommendation string
}

// verifySecretEngineImage checks if a container image matches known patterns for a secret engine
// Now uses the shared admission SDK for centralized engine detection
func verifySecretEngineImage(image string, engine string) bool {
	return VerifyControllerImage(image, engine)
}

func ListSecretAdmission(cmd *cobra.Command, args []string) {
	ctx, cancel := shared.ContextWithTimeout()
	defer cancel()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDir, _ := parentCmd.PersistentFlags().GetString("outdir")

	logger.InfoM(fmt.Sprintf("Analyzing secret management for %s", globals.ClusterName), K8S_SECRET_ADMISSION_MODULE_NAME)

	clientset := config.GetClientOrExit()
	dynClient := config.GetDynamicClientOrExit()

	// Detect and analyze all secret management engines
	logger.InfoM("Analyzing Vault Agent Injector...", K8S_SECRET_ADMISSION_MODULE_NAME)
	vaultInjector := analyzeVaultAgentInjector(ctx, clientset, dynClient)

	logger.InfoM("Analyzing Vault Secrets Operator...", K8S_SECRET_ADMISSION_MODULE_NAME)
	vaultOperator, vaultAuths, vaultStaticSecrets, vaultDynamicSecrets := analyzeVaultSecretsOperator(ctx, clientset, dynClient)

	logger.InfoM("Analyzing External Secrets Operator...", K8S_SECRET_ADMISSION_MODULE_NAME)
	esoController, secretStores, clusterSecretStores, externalSecrets := analyzeExternalSecretsOperator(ctx, clientset, dynClient)

	logger.InfoM("Analyzing Sealed Secrets...", K8S_SECRET_ADMISSION_MODULE_NAME)
	sealedSecretsController, sealedSecrets := analyzeSealedSecrets(ctx, clientset, dynClient)

	logger.InfoM("Analyzing Secrets Store CSI Driver...", K8S_SECRET_ADMISSION_MODULE_NAME)
	csiDriver, secretProviderClasses := analyzeSecretsStoreCSIDriver(ctx, clientset, dynClient)

	logger.InfoM("Analyzing unmanaged secrets...", K8S_SECRET_ADMISSION_MODULE_NAME)
	unmanagedSecrets := analyzeUnmanagedSecrets(ctx, clientset, externalSecrets, vaultStaticSecrets, vaultDynamicSecrets, sealedSecrets, secretProviderClasses)

	// Build per-namespace findings
	findings := buildSecretAdmissionFindings(ctx, clientset,
		vaultInjector, vaultOperator, vaultAuths, vaultStaticSecrets, vaultDynamicSecrets,
		esoController, secretStores, clusterSecretStores, externalSecrets,
		sealedSecretsController, sealedSecrets,
		csiDriver, secretProviderClasses,
		unmanagedSecrets)

	// Generate tables
	summaryHeader := []string{
		"Namespace",
		"Total Secrets",
		"Managed",
		"Unmanaged",
		"Coverage",
		"Vault",
		"ESO",
		"Sealed Secrets",
		"CSI Driver",
		"Risk Level",
		"Issues",
	}

	// Vault Agent Injector detail table
	vaultInjectorHeader := []string{
		"Namespace",
		"Status",
		"Pods Running",
		"Auth Method",
		"Vault Address",
		"TLS Enabled",
		"Failure Policy",
		"Bypass Risk",
	}

	// Vault Secrets Operator detail table
	vaultOperatorHeader := []string{
		"Namespace",
		"Status",
		"Pods Running",
		"VaultAuth CRDs",
		"Static Secrets",
		"Dynamic Secrets",
		"PKI Secrets",
		"Bypass Risk",
	}

	// VaultAuth detail table
	vaultAuthHeader := []string{
		"Name",
		"Namespace",
		"Method",
		"Mount",
		"Service Account",
		"Role",
		"Allowed Namespaces",
		"Bypass Risk",
	}

	// VaultStaticSecret detail table
	vaultStaticHeader := []string{
		"Name",
		"Namespace",
		"Auth Ref",
		"Mount",
		"Path",
		"Type",
		"Destination",
		"Sync Status",
		"Bypass Risk",
	}

	// External Secrets Operator detail table
	esoControllerHeader := []string{
		"Namespace",
		"Status",
		"Pods Running",
		"SecretStores",
		"ClusterSecretStores",
		"ExternalSecrets",
		"Bypass Risk",
	}

	// SecretStore detail table
	secretStoreHeader := []string{
		"Name",
		"Namespace",
		"Scope",
		"Provider",
		"Auth Method",
		"Status",
		"Referenced By",
		"Bypass Risk",
	}

	// ExternalSecret detail table
	externalSecretHeader := []string{
		"Name",
		"Namespace",
		"Store Ref",
		"Provider",
		"Refresh Interval",
		"Target Name",
		"Data Keys",
		"Sync Status",
		"Bypass Risk",
	}

	// Sealed Secrets detail table
	sealedSecretsHeader := []string{
		"Name",
		"Namespace",
		"Scope",
		"Encrypted Keys",
		"Target Name",
		"Status",
		"Bypass Risk",
	}

	// SecretProviderClass detail table
	secretProviderClassHeader := []string{
		"Name",
		"Namespace",
		"Provider",
		"Secret Objects",
		"Used By Pods",
		"Status",
		"Bypass Risk",
	}

	// Unmanaged Secrets detail table
	unmanagedSecretsHeader := []string{
		"Name",
		"Namespace",
		"Type",
		"Data Keys",
		"Age",
		"High Risk",
		"Risk Reason",
		"Mounted In Pods",
		"Recommendation",
	}

	var summaryRows [][]string
	var vaultInjectorRows [][]string
	var vaultOperatorRows [][]string
	var vaultAuthRows [][]string
	var vaultStaticRows [][]string
	var esoControllerRows [][]string
	var secretStoreRows [][]string
	var externalSecretRows [][]string
	var sealedSecretsRows [][]string
	var secretProviderClassRows [][]string
	var unmanagedSecretsRows [][]string

	loot := shared.NewLootBuilder()

	// Build summary rows
	for _, finding := range findings {
		// Vault status
		vaultStatus := "None"
		if finding.VaultAgentInjectorActive || finding.VaultSecretsOperatorActive || finding.VaultCSIProviderActive {
			var vaultParts []string
			if finding.VaultAgentInjectorActive {
				vaultParts = append(vaultParts, fmt.Sprintf("Injector(%d pods)", finding.VaultInjectedPods))
			}
			if finding.VaultSecretsOperatorActive {
				vaultParts = append(vaultParts, fmt.Sprintf("VSO(%d secrets)", finding.VaultManagedSecrets))
			}
			if finding.VaultCSIProviderActive {
				vaultParts = append(vaultParts, "CSI")
			}
			vaultStatus = strings.Join(vaultParts, ", ")
		}

		// ESO status
		esoStatus := "None"
		if finding.ESOActive {
			esoStatus = fmt.Sprintf("%d stores, %d secrets", finding.ESOSecretStoreCount, finding.ESOExternalSecretCount)
		}

		// Sealed Secrets status
		sealedStatus := "None"
		if finding.SealedSecretsActive {
			sealedStatus = fmt.Sprintf("%d sealed", finding.SealedSecretCount)
		}

		// CSI Driver status
		csiStatus := "None"
		if finding.CSIDriverActive {
			csiStatus = fmt.Sprintf("%d classes", finding.CSIProviderClasses)
		}

		// Issues summary
		issues := "-"
		if len(finding.SecurityIssues) > 0 {
			if len(finding.SecurityIssues) > 2 {
				issues = strings.Join(finding.SecurityIssues[:2], "; ") + fmt.Sprintf(" (+%d more)", len(finding.SecurityIssues)-2)
			} else {
				issues = strings.Join(finding.SecurityIssues, "; ")
			}
		}

		summaryRows = append(summaryRows, []string{
			finding.Namespace,
			fmt.Sprintf("%d", finding.TotalSecrets),
			fmt.Sprintf("%d", finding.ManagedSecrets),
			fmt.Sprintf("%d", finding.UnmanagedSecrets),
			finding.ManagementCoverage,
			vaultStatus,
			esoStatus,
			sealedStatus,
			csiStatus,
			finding.RiskLevel,
			issues,
		})
	}

	// Build Vault Agent Injector rows
	if vaultInjector.Name != "" {
		tlsEnabled := "No"
		if vaultInjector.TLSEnabled {
			tlsEnabled = "Yes"
		}
		vaultInjectorRows = append(vaultInjectorRows, []string{
			vaultInjector.Namespace,
			vaultInjector.Status,
			fmt.Sprintf("%d/%d", vaultInjector.PodsRunning, vaultInjector.TotalPods),
			vaultInjector.AuthMethod,
			vaultInjector.VaultAddr,
			tlsEnabled,
			vaultInjector.FailurePolicy,
			vaultInjector.BypassRisk,
		})
	}

	// Build Vault Secrets Operator rows
	if vaultOperator.Name != "" {
		vaultOperatorRows = append(vaultOperatorRows, []string{
			vaultOperator.Namespace,
			vaultOperator.Status,
			fmt.Sprintf("%d", vaultOperator.PodsRunning),
			fmt.Sprintf("%d", vaultOperator.VaultAuthCount),
			fmt.Sprintf("%d", vaultOperator.StaticSecrets),
			fmt.Sprintf("%d", vaultOperator.DynamicSecrets),
			fmt.Sprintf("%d", vaultOperator.PKISecrets),
			vaultOperator.BypassRisk,
		})
	}

	// Build VaultAuth rows
	for _, va := range vaultAuths {
		allowedNS := "-"
		if len(va.AllowedNS) > 0 {
			allowedNS = strings.Join(va.AllowedNS, ", ")
		}
		vaultAuthRows = append(vaultAuthRows, []string{
			va.Name,
			va.Namespace,
			va.Method,
			va.Mount,
			va.ServiceAccount,
			va.Role,
			allowedNS,
			va.BypassRisk,
		})
	}

	// Build VaultStaticSecret rows
	for _, vs := range vaultStaticSecrets {
		vaultStaticRows = append(vaultStaticRows, []string{
			vs.Name,
			vs.Namespace,
			vs.VaultAuthRef,
			vs.Mount,
			vs.Path,
			vs.Type,
			vs.DestinationName,
			vs.SyncStatus,
			vs.BypassRisk,
		})
	}

	// Build ESO Controller rows
	if esoController.Name != "" {
		esoControllerRows = append(esoControllerRows, []string{
			esoController.Namespace,
			esoController.Status,
			fmt.Sprintf("%d", esoController.PodsRunning),
			fmt.Sprintf("%d", len(secretStores)),
			fmt.Sprintf("%d", len(clusterSecretStores)),
			fmt.Sprintf("%d", len(externalSecrets)),
			esoController.BypassRisk,
		})
	}

	// Build SecretStore rows (both namespace and cluster-scoped)
	for _, ss := range secretStores {
		scope := "Namespace"
		ns := ss.Namespace
		secretStoreRows = append(secretStoreRows, []string{
			ss.Name,
			ns,
			scope,
			ss.Provider,
			ss.AuthMethod,
			ss.Status,
			fmt.Sprintf("%d", ss.ReferencedBy),
			ss.BypassRisk,
		})
	}
	for _, css := range clusterSecretStores {
		secretStoreRows = append(secretStoreRows, []string{
			css.Name,
			"<CLUSTER>",
			"Cluster",
			css.Provider,
			css.AuthMethod,
			css.Status,
			fmt.Sprintf("%d", css.ReferencedBy),
			css.BypassRisk,
		})
	}

	// Build ExternalSecret rows
	for _, es := range externalSecrets {
		externalSecretRows = append(externalSecretRows, []string{
			es.Name,
			es.Namespace,
			es.SecretStoreRef,
			es.Provider,
			es.RefreshInterval,
			es.TargetName,
			fmt.Sprintf("%d", es.DataKeys),
			es.SyncStatus,
			es.BypassRisk,
		})
	}

	// Build Sealed Secrets rows
	for _, ss := range sealedSecrets {
		encryptedKeys := "-"
		if len(ss.EncryptedKeys) > 0 {
			if len(ss.EncryptedKeys) > 3 {
				encryptedKeys = strings.Join(ss.EncryptedKeys[:3], ", ") + fmt.Sprintf(" (+%d)", len(ss.EncryptedKeys)-3)
			} else {
				encryptedKeys = strings.Join(ss.EncryptedKeys, ", ")
			}
		}
		sealedSecretsRows = append(sealedSecretsRows, []string{
			ss.Name,
			ss.Namespace,
			ss.Scope,
			encryptedKeys,
			ss.TargetName,
			ss.Status,
			ss.BypassRisk,
		})
	}

	// Build SecretProviderClass rows
	for _, spc := range secretProviderClasses {
		secretProviderClassRows = append(secretProviderClassRows, []string{
			spc.Name,
			spc.Namespace,
			spc.Provider,
			fmt.Sprintf("%d", spc.SecretObjects),
			fmt.Sprintf("%d", spc.UsedByPods),
			spc.Status,
			spc.BypassRisk,
		})
	}

	// Build Unmanaged Secrets rows
	for _, us := range unmanagedSecrets {
		highRisk := "No"
		if us.IsHighRisk {
			highRisk = "Yes"
		}
		dataKeys := "-"
		if len(us.DataKeys) > 0 {
			if len(us.DataKeys) > 3 {
				dataKeys = strings.Join(us.DataKeys[:3], ", ") + fmt.Sprintf(" (+%d)", len(us.DataKeys)-3)
			} else {
				dataKeys = strings.Join(us.DataKeys, ", ")
			}
		}
		unmanagedSecretsRows = append(unmanagedSecretsRows, []string{
			us.Name,
			us.Namespace,
			us.Type,
			dataKeys,
			us.Age,
			highRisk,
			us.RiskReason,
			fmt.Sprintf("%d", us.MountedInPods),
			us.Recommendation,
		})
	}

	// Generate loot
	generateSecretAdmissionLoot(loot, findings, vaultInjector, vaultOperator, vaultAuths, vaultStaticSecrets, vaultDynamicSecrets,
		esoController, secretStores, clusterSecretStores, externalSecrets,
		sealedSecretsController, sealedSecrets,
		csiDriver, secretProviderClasses,
		unmanagedSecrets)

	// Build output tables
	var tables []internal.TableFile

	tables = append(tables, internal.TableFile{
		Name:   "Secret-Admission-Summary",
		Header: summaryHeader,
		Body:   summaryRows,
	})

	if len(vaultInjectorRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Secret-Admission-Vault-Injector",
			Header: vaultInjectorHeader,
			Body:   vaultInjectorRows,
		})
	}

	if len(vaultOperatorRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Secret-Admission-Vault-Operator",
			Header: vaultOperatorHeader,
			Body:   vaultOperatorRows,
		})
	}

	if len(vaultAuthRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Secret-Admission-VaultAuth",
			Header: vaultAuthHeader,
			Body:   vaultAuthRows,
		})
	}

	if len(vaultStaticRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Secret-Admission-VaultStaticSecrets",
			Header: vaultStaticHeader,
			Body:   vaultStaticRows,
		})
	}

	if len(esoControllerRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Secret-Admission-ESO-Controller",
			Header: esoControllerHeader,
			Body:   esoControllerRows,
		})
	}

	if len(secretStoreRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Secret-Admission-SecretStores",
			Header: secretStoreHeader,
			Body:   secretStoreRows,
		})
	}

	if len(externalSecretRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Secret-Admission-ExternalSecrets",
			Header: externalSecretHeader,
			Body:   externalSecretRows,
		})
	}

	if len(sealedSecretsRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Secret-Admission-SealedSecrets",
			Header: sealedSecretsHeader,
			Body:   sealedSecretsRows,
		})
	}

	if len(secretProviderClassRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Secret-Admission-CSI-ProviderClasses",
			Header: secretProviderClassHeader,
			Body:   secretProviderClassRows,
		})
	}

	if len(unmanagedSecretsRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Secret-Admission-Unmanaged",
			Header: unmanagedSecretsHeader,
			Body:   unmanagedSecretsRows,
		})
	}

	output := SecretAdmissionOutput{
		Table: tables,
		Loot:  loot.Build(),
	}

	err := internal.HandleOutput(
		"Kubernetes",
		"table",
		outputDir,
		verbosity,
		wrap,
		"Secret-Admission",
		globals.ClusterName,
		"results",
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), K8S_SECRET_ADMISSION_MODULE_NAME)
		return
	}
}

// ============================================================================
// Vault Agent Injector Analysis
// ============================================================================

func analyzeVaultAgentInjector(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) VaultAgentInjectorConfig {
	config := VaultAgentInjectorConfig{}

	// Check for Vault Agent Injector MutatingWebhookConfiguration
	whGVR := schema.GroupVersionResource{
		Group:    "admissionregistration.k8s.io",
		Version:  "v1",
		Resource: "mutatingwebhookconfigurations",
	}

	var webhookFound bool
	var whObject map[string]interface{}

	whList, err := dynClient.Resource(whGVR).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, wh := range whList.Items {
			name := wh.GetName()
			nameLC := strings.ToLower(name)
			if strings.Contains(nameLC, "vault") && strings.Contains(nameLC, "agent") && strings.Contains(nameLC, "injector") {
				webhookFound = true
				whObject = wh.Object
				config.Name = "Vault Agent Injector"
				config.WebhookName = name

				// Get failure policy
				if webhooks, ok := wh.Object["webhooks"].([]interface{}); ok && len(webhooks) > 0 {
					if whMap, ok := webhooks[0].(map[string]interface{}); ok {
						if fp, ok := whMap["failurePolicy"].(string); ok {
							config.FailurePolicy = fp
						}
					}
				}
				break
			}
		}
	}

	if !webhookFound {
		return config
	}

	// Verify webhook targets pods
	if !webhookTargetsPods(whObject) {
		config.Status = "webhook-misconfigured"
		config.BypassRisk = "Webhook does not target pods"
		return config
	}

	// Find Vault Agent Injector pods
	namespaces := []string{"vault", "vault-system", "hashicorp", "kube-system"}
	labelSelectors := []string{
		"app.kubernetes.io/name=vault-agent-injector",
		"component=webhook",
		"app=vault-agent-injector",
	}

	var podsRunning, totalPods int
	var namespace string
	for _, ns := range namespaces {
		for _, selector := range labelSelectors {
			pods, err := clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: selector})
			if err == nil && len(pods.Items) > 0 {
				namespace = ns
				for _, pod := range pods.Items {
					totalPods++
					if pod.Status.Phase == corev1.PodRunning {
						podsRunning++
					}
				}
				break
			}
		}
		if totalPods > 0 {
			break
		}
	}

	if totalPods == 0 {
		config.Status = "not-running"
		config.BypassRisk = "No injector pods found"
		return config
	}

	config.Namespace = namespace
	config.PodsRunning = podsRunning
	config.TotalPods = totalPods

	if podsRunning == 0 {
		config.Status = "not-running"
		config.BypassRisk = "Injector pods not running"
		return config
	}

	config.Status = "active"

	// Verify by checking pod images
	for _, ns := range namespaces {
		for _, selector := range labelSelectors {
			pods, err := clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: selector})
			if err == nil {
				for _, pod := range pods.Items {
					for _, container := range pod.Spec.Containers {
						if verifySecretEngineImage(container.Image, "vault-injector") {
							config.ImageVerified = true
							break
						}
					}
					if config.ImageVerified {
						break
					}
				}
			}
			if config.ImageVerified {
				break
			}
		}
		if config.ImageVerified {
			break
		}
	}

	if !config.ImageVerified {
		config.SecurityIssues = append(config.SecurityIssues, "Detection based on webhook/pod name only - verify image manually")
	}

	// Try to get Vault configuration from ConfigMap or environment
	configMaps, _ := clientset.CoreV1().ConfigMaps(namespace).List(ctx, metav1.ListOptions{})
	for _, cm := range configMaps.Items {
		if strings.Contains(cm.Name, "vault") {
			if addr, ok := cm.Data["VAULT_ADDR"]; ok {
				config.VaultAddr = addr
				config.TLSEnabled = strings.HasPrefix(addr, "https://")
			}
		}
	}

	// Check for bypass risks
	if config.FailurePolicy == "Ignore" {
		config.BypassRisk = "FailurePolicy=Ignore allows bypass"
		config.SecurityIssues = append(config.SecurityIssues, "Webhook can be bypassed during failures")
	}
	if !config.TLSEnabled && config.VaultAddr != "" {
		config.SecurityIssues = append(config.SecurityIssues, "Vault communication not using TLS")
	}

	// Default auth method
	config.AuthMethod = "kubernetes"

	return config
}

// webhookTargetsPods checks if a mutating webhook targets pods
func webhookTargetsPods(whObject map[string]interface{}) bool {
	webhooks, ok := whObject["webhooks"].([]interface{})
	if !ok || len(webhooks) == 0 {
		return false
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
				resStr, ok := res.(string)
				if ok && (resStr == "pods" || resStr == "*") {
					return true
				}
			}
		}
	}

	return false
}

// ============================================================================
// Vault Secrets Operator Analysis
// ============================================================================

func analyzeVaultSecretsOperator(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) (VaultSecretsOperatorConfig, []VaultAuthConfig, []VaultStaticSecretConfig, []VaultDynamicSecretConfig) {
	config := VaultSecretsOperatorConfig{}
	var vaultAuths []VaultAuthConfig
	var staticSecrets []VaultStaticSecretConfig
	var dynamicSecrets []VaultDynamicSecretConfig

	// Check for VSO pods
	namespaces := []string{"vault-secrets-operator-system", "vault-secrets-operator", "vault", "kube-system"}
	labelSelectors := []string{
		"app.kubernetes.io/name=vault-secrets-operator",
		"control-plane=controller-manager",
	}

	var podsRunning int
	var namespace string
	for _, ns := range namespaces {
		for _, selector := range labelSelectors {
			pods, err := clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: selector})
			if err == nil && len(pods.Items) > 0 {
				namespace = ns
				for _, pod := range pods.Items {
					if pod.Status.Phase == corev1.PodRunning {
						podsRunning++
					}
				}
				break
			}
		}
		if podsRunning > 0 {
			break
		}
	}

	// Check for VaultAuth CRDs
	vaultAuthGVR := schema.GroupVersionResource{
		Group:    "secrets.hashicorp.com",
		Version:  "v1beta1",
		Resource: "vaultauths",
	}

	vaultAuthList, err := dynClient.Resource(vaultAuthGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil && len(vaultAuthList.Items) > 0 {
		config.Name = "Vault Secrets Operator"
		config.Namespace = namespace
		config.PodsRunning = podsRunning
		config.VaultAuthCount = len(vaultAuthList.Items)

		for _, va := range vaultAuthList.Items {
			auth := parseVaultAuth(va.Object)
			vaultAuths = append(vaultAuths, auth)
		}
	}

	// Check for VaultStaticSecret CRDs
	vaultStaticGVR := schema.GroupVersionResource{
		Group:    "secrets.hashicorp.com",
		Version:  "v1beta1",
		Resource: "vaultstaticsecrets",
	}

	staticList, err := dynClient.Resource(vaultStaticGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		config.StaticSecrets = len(staticList.Items)
		for _, vs := range staticList.Items {
			secret := parseVaultStaticSecret(vs.Object)
			staticSecrets = append(staticSecrets, secret)
		}
	}

	// Check for VaultDynamicSecret CRDs
	vaultDynamicGVR := schema.GroupVersionResource{
		Group:    "secrets.hashicorp.com",
		Version:  "v1beta1",
		Resource: "vaultdynamicsecrets",
	}

	dynamicList, err := dynClient.Resource(vaultDynamicGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		config.DynamicSecrets = len(dynamicList.Items)
		for _, vd := range dynamicList.Items {
			secret := parseVaultDynamicSecret(vd.Object)
			dynamicSecrets = append(dynamicSecrets, secret)
		}
	}

	// Check for VaultPKISecret CRDs
	vaultPKIGVR := schema.GroupVersionResource{
		Group:    "secrets.hashicorp.com",
		Version:  "v1beta1",
		Resource: "vaultpkisecrets",
	}

	pkiList, err := dynClient.Resource(vaultPKIGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		config.PKISecrets = len(pkiList.Items)
	}

	// Set status
	if config.Name == "" {
		// Check if CRDs exist even without pods
		if config.StaticSecrets > 0 || config.DynamicSecrets > 0 {
			config.Name = "Vault Secrets Operator"
			config.Status = "CRDs-only"
			config.BypassRisk = "VSO CRDs found but operator may not be running"
		}
		return config, vaultAuths, staticSecrets, dynamicSecrets
	}

	if podsRunning == 0 {
		config.Status = "not-running"
		config.BypassRisk = "Operator pods not running - secrets will not sync"
	} else {
		config.Status = "active"
		config.SyncedSecrets = config.StaticSecrets + config.DynamicSecrets + config.PKISecrets
	}

	// Verify by checking pod images
	for _, ns := range namespaces {
		for _, selector := range labelSelectors {
			pods, err := clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: selector})
			if err == nil {
				for _, pod := range pods.Items {
					for _, container := range pod.Spec.Containers {
						if verifySecretEngineImage(container.Image, "vault-operator") {
							config.ImageVerified = true
							break
						}
					}
					if config.ImageVerified {
						break
					}
				}
			}
			if config.ImageVerified {
				break
			}
		}
		if config.ImageVerified {
			break
		}
	}

	if !config.ImageVerified && config.Status == "active" {
		config.SecurityIssues = append(config.SecurityIssues, "Detection based on CRDs/pod labels only - verify image manually")
	}

	return config, vaultAuths, staticSecrets, dynamicSecrets
}

func parseVaultAuth(obj map[string]interface{}) VaultAuthConfig {
	auth := VaultAuthConfig{}

	if metadata, ok := obj["metadata"].(map[string]interface{}); ok {
		auth.Name, _ = metadata["name"].(string)
		auth.Namespace, _ = metadata["namespace"].(string)
	}

	if spec, ok := obj["spec"].(map[string]interface{}); ok {
		auth.Method, _ = spec["method"].(string)
		auth.Mount, _ = spec["mount"].(string)
		auth.VaultAddr, _ = spec["vaultAddress"].(string)

		if kubernetes, ok := spec["kubernetes"].(map[string]interface{}); ok {
			auth.Role, _ = kubernetes["role"].(string)
			auth.ServiceAccount, _ = kubernetes["serviceAccount"].(string)

			if audiences, ok := kubernetes["audiences"].([]interface{}); ok {
				for _, aud := range audiences {
					if audStr, ok := aud.(string); ok {
						auth.AllowedNS = append(auth.AllowedNS, audStr)
					}
				}
			}
		}

		// Check for allowed namespaces
		if allowedNS, ok := spec["allowedNamespaces"].([]interface{}); ok {
			for _, ns := range allowedNS {
				if nsStr, ok := ns.(string); ok {
					auth.AllowedNS = append(auth.AllowedNS, nsStr)
				}
			}
		}
	}

	// Analyze bypass risks
	if auth.Method == "" {
		auth.BypassRisk = "No auth method configured"
	} else if len(auth.AllowedNS) == 0 {
		auth.BypassRisk = "No namespace restrictions"
	} else {
		for _, ns := range auth.AllowedNS {
			if ns == "*" {
				auth.BypassRisk = "Wildcard namespace allowed"
				break
			}
		}
	}

	return auth
}

func parseVaultStaticSecret(obj map[string]interface{}) VaultStaticSecretConfig {
	secret := VaultStaticSecretConfig{}

	if metadata, ok := obj["metadata"].(map[string]interface{}); ok {
		secret.Name, _ = metadata["name"].(string)
		secret.Namespace, _ = metadata["namespace"].(string)
	}

	if spec, ok := obj["spec"].(map[string]interface{}); ok {
		secret.VaultAuthRef, _ = spec["vaultAuthRef"].(string)
		secret.Mount, _ = spec["mount"].(string)
		secret.Path, _ = spec["path"].(string)
		secret.Type, _ = spec["type"].(string)
		secret.RefreshAfter, _ = spec["refreshAfter"].(string)

		if dest, ok := spec["destination"].(map[string]interface{}); ok {
			secret.DestinationName, _ = dest["name"].(string)
			secret.DestinationType, _ = dest["type"].(string)
		}
	}

	if status, ok := obj["status"].(map[string]interface{}); ok {
		if conditions, ok := status["conditions"].([]interface{}); ok {
			for _, cond := range conditions {
				if condMap, ok := cond.(map[string]interface{}); ok {
					if condType, ok := condMap["type"].(string); ok && condType == "SecretSynced" {
						if condStatus, ok := condMap["status"].(string); ok {
							if condStatus == "True" {
								secret.SyncStatus = "Synced"
							} else {
								secret.SyncStatus = "Error"
								if msg, ok := condMap["message"].(string); ok {
									secret.BypassRisk = fmt.Sprintf("Sync error: %s", secretAdmissionTruncateString(msg, 50))
								}
							}
						}
					}
				}
			}
		}
		if lastSync, ok := status["lastGeneration"].(float64); ok {
			secret.LastSyncTime = fmt.Sprintf("gen-%d", int(lastSync))
		}
	}

	if secret.SyncStatus == "" {
		secret.SyncStatus = "Unknown"
	}

	return secret
}

func parseVaultDynamicSecret(obj map[string]interface{}) VaultDynamicSecretConfig {
	secret := VaultDynamicSecretConfig{}

	if metadata, ok := obj["metadata"].(map[string]interface{}); ok {
		secret.Name, _ = metadata["name"].(string)
		secret.Namespace, _ = metadata["namespace"].(string)
	}

	if spec, ok := obj["spec"].(map[string]interface{}); ok {
		secret.VaultAuthRef, _ = spec["vaultAuthRef"].(string)
		secret.Mount, _ = spec["mount"].(string)
		secret.Path, _ = spec["path"].(string)
		secret.Role, _ = spec["role"].(string)

		if dest, ok := spec["destination"].(map[string]interface{}); ok {
			secret.DestinationName, _ = dest["name"].(string)
		}

		if renewalPercent, ok := spec["renewalPercent"].(float64); ok {
			secret.RenewalPercent = int(renewalPercent)
		}
	}

	if status, ok := obj["status"].(map[string]interface{}); ok {
		if conditions, ok := status["conditions"].([]interface{}); ok {
			for _, cond := range conditions {
				if condMap, ok := cond.(map[string]interface{}); ok {
					if condType, ok := condMap["type"].(string); ok && condType == "SecretSynced" {
						if condStatus, ok := condMap["status"].(string); ok {
							if condStatus == "True" {
								secret.SyncStatus = "Synced"
							} else {
								secret.SyncStatus = "Error"
							}
						}
					}
				}
			}
		}
	}

	if secret.SyncStatus == "" {
		secret.SyncStatus = "Unknown"
	}

	return secret
}

// ============================================================================
// External Secrets Operator Analysis
// ============================================================================

// ESOControllerConfig represents the ESO controller status
type ESOControllerConfig struct {
	Name          string
	Namespace     string
	Status        string
	PodsRunning   int
	BypassRisk    string
	ImageVerified bool // True if External Secrets Operator image was verified
}

func analyzeExternalSecretsOperator(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) (ESOControllerConfig, []SecretStoreConfig, []SecretStoreConfig, []ExternalSecretConfig) {
	config := ESOControllerConfig{}
	var secretStores []SecretStoreConfig
	var clusterSecretStores []SecretStoreConfig
	var externalSecrets []ExternalSecretConfig

	// Check for ESO pods
	namespaces := []string{"external-secrets", "external-secrets-operator", "kube-system"}
	labelSelectors := []string{
		"app.kubernetes.io/name=external-secrets",
		"app.kubernetes.io/instance=external-secrets",
		"app=external-secrets",
	}

	var podsRunning int
	var namespace string
	for _, ns := range namespaces {
		for _, selector := range labelSelectors {
			pods, err := clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: selector})
			if err == nil && len(pods.Items) > 0 {
				namespace = ns
				for _, pod := range pods.Items {
					if pod.Status.Phase == corev1.PodRunning {
						podsRunning++
					}
				}
				break
			}
		}
		if podsRunning > 0 {
			break
		}
	}

	// Check for SecretStore CRDs
	secretStoreGVR := schema.GroupVersionResource{
		Group:    "external-secrets.io",
		Version:  "v1beta1",
		Resource: "secretstores",
	}

	ssList, err := dynClient.Resource(secretStoreGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, ss := range ssList.Items {
			store := parseSecretStore(ss.Object, false)
			secretStores = append(secretStores, store)
		}
	}

	// Check for ClusterSecretStore CRDs
	clusterSecretStoreGVR := schema.GroupVersionResource{
		Group:    "external-secrets.io",
		Version:  "v1beta1",
		Resource: "clustersecretstores",
	}

	cssList, err := dynClient.Resource(clusterSecretStoreGVR).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, css := range cssList.Items {
			store := parseSecretStore(css.Object, true)
			clusterSecretStores = append(clusterSecretStores, store)
		}
	}

	// Check for ExternalSecret CRDs
	externalSecretGVR := schema.GroupVersionResource{
		Group:    "external-secrets.io",
		Version:  "v1beta1",
		Resource: "externalsecrets",
	}

	esList, err := dynClient.Resource(externalSecretGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		// Build a map of store names to providers for enrichment
		storeProviders := make(map[string]string)
		for _, ss := range secretStores {
			storeProviders[ss.Namespace+"/"+ss.Name] = ss.Provider
		}
		for _, css := range clusterSecretStores {
			storeProviders["cluster/"+css.Name] = css.Provider
		}

		for _, es := range esList.Items {
			secret := parseExternalSecret(es.Object, storeProviders)
			externalSecrets = append(externalSecrets, secret)
		}
	}

	// Count references for each store
	for i := range secretStores {
		for _, es := range externalSecrets {
			if es.SecretStoreKind == "SecretStore" && es.SecretStoreRef == secretStores[i].Name && es.Namespace == secretStores[i].Namespace {
				secretStores[i].ReferencedBy++
			}
		}
	}
	for i := range clusterSecretStores {
		for _, es := range externalSecrets {
			if es.SecretStoreKind == "ClusterSecretStore" && es.SecretStoreRef == clusterSecretStores[i].Name {
				clusterSecretStores[i].ReferencedBy++
			}
		}
	}

	// Set controller status
	if len(secretStores) > 0 || len(clusterSecretStores) > 0 || len(externalSecrets) > 0 {
		config.Name = "External Secrets Operator"
		config.Namespace = namespace
		config.PodsRunning = podsRunning

		if podsRunning == 0 {
			config.Status = "not-running"
			config.BypassRisk = "Controller not running - secrets will not sync"
		} else {
			config.Status = "active"
		}

		// Verify by checking pod images
		for _, ns := range namespaces {
			for _, selector := range labelSelectors {
				pods, err := clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: selector})
				if err == nil {
					for _, pod := range pods.Items {
						for _, container := range pod.Spec.Containers {
							if verifySecretEngineImage(container.Image, "external-secrets") {
								config.ImageVerified = true
								break
							}
						}
						if config.ImageVerified {
							break
						}
					}
				}
				if config.ImageVerified {
					break
				}
			}
			if config.ImageVerified {
				break
			}
		}
	}

	return config, secretStores, clusterSecretStores, externalSecrets
}

func parseSecretStore(obj map[string]interface{}, isCluster bool) SecretStoreConfig {
	store := SecretStoreConfig{
		IsClusterStore: isCluster,
	}

	if metadata, ok := obj["metadata"].(map[string]interface{}); ok {
		store.Name, _ = metadata["name"].(string)
		if !isCluster {
			store.Namespace, _ = metadata["namespace"].(string)
		}
	}

	if spec, ok := obj["spec"].(map[string]interface{}); ok {
		if provider, ok := spec["provider"].(map[string]interface{}); ok {
			// Detect provider type
			providerTypes := []string{"aws", "azurekv", "gcpsm", "vault", "kubernetes", "webhook", "fake", "oracle", "ibm", "yandexlockbox", "gitlab", "alibaba", "doppler", "onepassword", "keeper", "scaleway", "senhasegura", "delinea", "chef", "pulumi", "fortanix", "beyondtrust", "infisical", "passbolt", "secretserver", "bitwarden", "device42", "akeyless", "conjur"}

			for _, pt := range providerTypes {
				if providerConfig, ok := provider[pt].(map[string]interface{}); ok {
					store.Provider = pt
					store.ProviderConfig = summarizeProviderConfig(pt, providerConfig)
					store.AuthMethod = detectAuthMethod(pt, providerConfig)
					break
				}
			}
		}
	}

	if status, ok := obj["status"].(map[string]interface{}); ok {
		if conditions, ok := status["conditions"].([]interface{}); ok {
			for _, cond := range conditions {
				if condMap, ok := cond.(map[string]interface{}); ok {
					if condType, ok := condMap["type"].(string); ok && condType == "Ready" {
						if condStatus, ok := condMap["status"].(string); ok {
							if condStatus == "True" {
								store.Status = "Valid"
							} else {
								store.Status = "Invalid"
								if msg, ok := condMap["message"].(string); ok {
									store.BypassRisk = fmt.Sprintf("Store error: %s", secretAdmissionTruncateString(msg, 50))
								}
							}
						}
					}
				}
			}
		}
	}

	if store.Status == "" {
		store.Status = "Unknown"
	}

	// Security analysis
	if store.Provider == "fake" {
		store.SecurityIssues = append(store.SecurityIssues, "Using fake provider - not for production")
		store.BypassRisk = "Fake provider - secrets not externally managed"
	}

	return store
}

func summarizeProviderConfig(provider string, config map[string]interface{}) string {
	switch provider {
	case "aws":
		service, _ := config["service"].(string)
		region, _ := config["region"].(string)
		if service == "" {
			service = "SecretsManager"
		}
		return fmt.Sprintf("%s/%s", service, region)
	case "azurekv":
		if vaultURL, ok := config["vaultUrl"].(string); ok {
			return secretAdmissionTruncateString(vaultURL, 40)
		}
	case "gcpsm":
		if projectID, ok := config["projectID"].(string); ok {
			return fmt.Sprintf("project:%s", projectID)
		}
	case "vault":
		if server, ok := config["server"].(string); ok {
			return secretAdmissionTruncateString(server, 40)
		}
	}
	return provider
}

func detectAuthMethod(provider string, config map[string]interface{}) string {
	switch provider {
	case "aws":
		if _, ok := config["auth"].(map[string]interface{}); ok {
			return "explicit"
		}
		return "IRSA/instance"
	case "azurekv":
		if auth, ok := config["authSecretRef"].(map[string]interface{}); ok {
			if _, hasClientID := auth["clientId"]; hasClientID {
				return "ServicePrincipal"
			}
		}
		if _, ok := config["identityId"].(string); ok {
			return "ManagedIdentity"
		}
		return "WorkloadIdentity"
	case "gcpsm":
		if _, ok := config["auth"].(map[string]interface{}); ok {
			return "explicit"
		}
		return "WorkloadIdentity"
	case "vault":
		if auth, ok := config["auth"].(map[string]interface{}); ok {
			if _, ok := auth["kubernetes"]; ok {
				return "kubernetes"
			}
			if _, ok := auth["appRole"]; ok {
				return "appRole"
			}
			if _, ok := auth["jwt"]; ok {
				return "jwt"
			}
			if _, ok := auth["tokenSecretRef"]; ok {
				return "token"
			}
		}
		return "unknown"
	}
	return "default"
}

func parseExternalSecret(obj map[string]interface{}, storeProviders map[string]string) ExternalSecretConfig {
	es := ExternalSecretConfig{}

	if metadata, ok := obj["metadata"].(map[string]interface{}); ok {
		es.Name, _ = metadata["name"].(string)
		es.Namespace, _ = metadata["namespace"].(string)
	}

	if spec, ok := obj["spec"].(map[string]interface{}); ok {
		if refreshInterval, ok := spec["refreshInterval"].(string); ok {
			es.RefreshInterval = refreshInterval
		}

		if secretStoreRef, ok := spec["secretStoreRef"].(map[string]interface{}); ok {
			es.SecretStoreRef, _ = secretStoreRef["name"].(string)
			es.SecretStoreKind, _ = secretStoreRef["kind"].(string)
			if es.SecretStoreKind == "" {
				es.SecretStoreKind = "SecretStore"
			}
		}

		if target, ok := spec["target"].(map[string]interface{}); ok {
			es.TargetName, _ = target["name"].(string)
			es.TargetCreation, _ = target["creationPolicy"].(string)
		}
		if es.TargetName == "" {
			es.TargetName = es.Name // Default to ExternalSecret name
		}

		if data, ok := spec["data"].([]interface{}); ok {
			es.DataKeys = len(data)
		}
		if dataFrom, ok := spec["dataFrom"].([]interface{}); ok {
			es.DataKeys += len(dataFrom)
		}
	}

	// Lookup provider from store
	if es.SecretStoreKind == "ClusterSecretStore" {
		es.Provider = storeProviders["cluster/"+es.SecretStoreRef]
	} else {
		es.Provider = storeProviders[es.Namespace+"/"+es.SecretStoreRef]
	}

	if status, ok := obj["status"].(map[string]interface{}); ok {
		if conditions, ok := status["conditions"].([]interface{}); ok {
			for _, cond := range conditions {
				if condMap, ok := cond.(map[string]interface{}); ok {
					if condType, ok := condMap["type"].(string); ok && condType == "Ready" {
						if condStatus, ok := condMap["status"].(string); ok {
							if condStatus == "True" {
								es.SyncStatus = "Synced"
							} else {
								es.SyncStatus = "Error"
								if msg, ok := condMap["message"].(string); ok {
									es.BypassRisk = fmt.Sprintf("Sync error: %s", secretAdmissionTruncateString(msg, 50))
								}
							}
						}
					}
				}
			}
		}
		if refreshTime, ok := status["refreshTime"].(string); ok {
			es.LastSyncTime = refreshTime
		}
	}

	if es.SyncStatus == "" {
		es.SyncStatus = "Unknown"
	}

	return es
}

// ============================================================================
// Sealed Secrets Analysis
// ============================================================================

// SealedSecretsControllerConfig represents the Sealed Secrets controller status
type SealedSecretsControllerConfig struct {
	Name          string
	Namespace     string
	Status        string
	PodsRunning   int
	PublicKey     string
	BypassRisk    string
	ImageVerified bool // True if Sealed Secrets controller image was verified
}

func analyzeSealedSecrets(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) (SealedSecretsControllerConfig, []SealedSecretConfig) {
	config := SealedSecretsControllerConfig{}
	var sealedSecrets []SealedSecretConfig

	// Check for Sealed Secrets controller pods
	namespaces := []string{"kube-system", "sealed-secrets", "flux-system"}
	labelSelectors := []string{
		"app.kubernetes.io/name=sealed-secrets",
		"name=sealed-secrets-controller",
		"app=sealed-secrets-controller",
	}

	var podsRunning int
	var namespace string
	for _, ns := range namespaces {
		for _, selector := range labelSelectors {
			pods, err := clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: selector})
			if err == nil && len(pods.Items) > 0 {
				namespace = ns
				for _, pod := range pods.Items {
					if pod.Status.Phase == corev1.PodRunning {
						podsRunning++
					}
				}
				break
			}
		}
		if podsRunning > 0 {
			break
		}
	}

	// Check for SealedSecret CRDs
	sealedSecretGVR := schema.GroupVersionResource{
		Group:    "bitnami.com",
		Version:  "v1alpha1",
		Resource: "sealedsecrets",
	}

	ssList, err := dynClient.Resource(sealedSecretGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil && len(ssList.Items) > 0 {
		config.Name = "Sealed Secrets"
		config.Namespace = namespace
		config.PodsRunning = podsRunning

		for _, ss := range ssList.Items {
			secret := parseSealedSecret(ss.Object)
			sealedSecrets = append(sealedSecrets, secret)
		}
	}

	// Set status
	if config.Name != "" {
		if podsRunning == 0 {
			config.Status = "not-running"
			config.BypassRisk = "Controller not running - sealed secrets cannot be decrypted"
		} else {
			config.Status = "active"
		}

		// Verify by checking pod images
		for _, ns := range namespaces {
			for _, selector := range labelSelectors {
				pods, err := clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: selector})
				if err == nil {
					for _, pod := range pods.Items {
						for _, container := range pod.Spec.Containers {
							if verifySecretEngineImage(container.Image, "sealed-secrets") {
								config.ImageVerified = true
								break
							}
						}
						if config.ImageVerified {
							break
						}
					}
				}
				if config.ImageVerified {
					break
				}
			}
			if config.ImageVerified {
				break
			}
		}
	}

	return config, sealedSecrets
}

func parseSealedSecret(obj map[string]interface{}) SealedSecretConfig {
	ss := SealedSecretConfig{}

	if metadata, ok := obj["metadata"].(map[string]interface{}); ok {
		ss.Name, _ = metadata["name"].(string)
		ss.Namespace, _ = metadata["namespace"].(string)

		// Check for scope annotation
		if annotations, ok := metadata["annotations"].(map[string]interface{}); ok {
			if scope, ok := annotations["sealedsecrets.bitnami.com/cluster-wide"].(string); ok && scope == "true" {
				ss.Scope = "cluster-wide"
			} else if scope, ok := annotations["sealedsecrets.bitnami.com/namespace-wide"].(string); ok && scope == "true" {
				ss.Scope = "namespace-wide"
			} else {
				ss.Scope = "strict"
			}
		} else {
			ss.Scope = "strict"
		}
	}

	if spec, ok := obj["spec"].(map[string]interface{}); ok {
		if encryptedData, ok := spec["encryptedData"].(map[string]interface{}); ok {
			for key := range encryptedData {
				ss.EncryptedKeys = append(ss.EncryptedKeys, key)
			}
		}

		if template, ok := spec["template"].(map[string]interface{}); ok {
			if templateMeta, ok := template["metadata"].(map[string]interface{}); ok {
				if name, ok := templateMeta["name"].(string); ok {
					ss.TargetName = name
				}
			}
		}
	}

	if ss.TargetName == "" {
		ss.TargetName = ss.Name // Default to same name
	}

	if status, ok := obj["status"].(map[string]interface{}); ok {
		if conditions, ok := status["conditions"].([]interface{}); ok {
			for _, cond := range conditions {
				if condMap, ok := cond.(map[string]interface{}); ok {
					if condType, ok := condMap["type"].(string); ok && condType == "Synced" {
						if condStatus, ok := condMap["status"].(string); ok {
							if condStatus == "True" {
								ss.Status = "Synced"
							} else {
								ss.Status = "Error"
								if msg, ok := condMap["message"].(string); ok {
									ss.BypassRisk = fmt.Sprintf("Sync error: %s", secretAdmissionTruncateString(msg, 50))
								}
							}
						}
					}
				}
			}
		}
	}

	if ss.Status == "" {
		ss.Status = "Unknown"
	}

	// Scope-based bypass risk
	if ss.Scope == "cluster-wide" {
		ss.BypassRisk = "cluster-wide scope - can be moved to any namespace"
	}

	return ss
}

// ============================================================================
// Secrets Store CSI Driver Analysis
// ============================================================================

// CSIDriverConfig represents the Secrets Store CSI Driver status
type CSIDriverConfig struct {
	Name          string
	Status        string
	PodsRunning   int
	Providers     []string
	BypassRisk    string
	ImageVerified bool // True if Secrets Store CSI Driver image was verified
}

func analyzeSecretsStoreCSIDriver(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) (CSIDriverConfig, []SecretProviderClassConfig) {
	config := CSIDriverConfig{}
	var providerClasses []SecretProviderClassConfig

	// Check for CSI Driver DaemonSet
	daemonSets, err := clientset.AppsV1().DaemonSets("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, ds := range daemonSets.Items {
			nameLC := strings.ToLower(ds.Name)
			if strings.Contains(nameLC, "secrets-store-csi") || strings.Contains(nameLC, "csi-secrets-store") {
				config.Name = "Secrets Store CSI Driver"
				config.PodsRunning = int(ds.Status.NumberReady)
				if config.PodsRunning > 0 {
					config.Status = "active"
				} else {
					config.Status = "not-running"
					config.BypassRisk = "CSI driver pods not running"
				}

				// Verify by checking container images in the DaemonSet spec
				for _, container := range ds.Spec.Template.Spec.Containers {
					if verifySecretEngineImage(container.Image, "secrets-store-csi") {
						config.ImageVerified = true
						break
					}
				}
				break
			}
		}

		// Also check for cloud provider DaemonSets
		verifiedProviders := make(map[string]bool)
		for _, ds := range daemonSets.Items {
			nameLC := strings.ToLower(ds.Name)
			dsReady := ds.Status.NumberReady > 0

			// Check for AWS provider DaemonSet
			if strings.Contains(nameLC, "aws-provider") || strings.Contains(nameLC, "provider-aws") ||
				strings.Contains(nameLC, "secrets-store-csi-driver-provider-aws") {
				for _, container := range ds.Spec.Template.Spec.Containers {
					if verifySecretEngineImage(container.Image, "aws-secrets-csi") && dsReady {
						verifiedProviders["aws"] = true
						break
					}
				}
			}

			// Check for Azure provider DaemonSet
			if strings.Contains(nameLC, "azure-provider") || strings.Contains(nameLC, "provider-azure") ||
				strings.Contains(nameLC, "csi-secrets-store-provider-azure") {
				for _, container := range ds.Spec.Template.Spec.Containers {
					if verifySecretEngineImage(container.Image, "azure-keyvault-csi") && dsReady {
						verifiedProviders["azure"] = true
						break
					}
				}
			}

			// Check for GCP provider DaemonSet
			if strings.Contains(nameLC, "gcp-provider") || strings.Contains(nameLC, "provider-gcp") ||
				strings.Contains(nameLC, "provider-google") {
				for _, container := range ds.Spec.Template.Spec.Containers {
					if verifySecretEngineImage(container.Image, "gcp-secrets-csi") && dsReady {
						verifiedProviders["gcp"] = true
						break
					}
				}
			}
		}

		// Add verified providers to the list
		for provider := range verifiedProviders {
			alreadyAdded := false
			for _, p := range config.Providers {
				if p == provider {
					alreadyAdded = true
					break
				}
			}
			if !alreadyAdded {
				config.Providers = append(config.Providers, provider)
			}
		}
	}

	// Check for SecretProviderClass CRDs
	spcGVR := schema.GroupVersionResource{
		Group:    "secrets-store.csi.x-k8s.io",
		Version:  "v1",
		Resource: "secretproviderclasses",
	}

	spcList, err := dynClient.Resource(spcGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil && len(spcList.Items) > 0 {
		if config.Name == "" {
			config.Name = "Secrets Store CSI Driver"
			config.Status = "CRDs-only"
		}

		providerSet := make(map[string]bool)

		for _, spc := range spcList.Items {
			pc := parseSecretProviderClass(ctx, clientset, spc.Object)
			providerClasses = append(providerClasses, pc)
			if pc.Provider != "" {
				providerSet[pc.Provider] = true
			}
		}

		for p := range providerSet {
			config.Providers = append(config.Providers, p)
		}
	}

	return config, providerClasses
}

func parseSecretProviderClass(ctx context.Context, clientset kubernetes.Interface, obj map[string]interface{}) SecretProviderClassConfig {
	spc := SecretProviderClassConfig{
		Parameters: make(map[string]string),
	}

	if metadata, ok := obj["metadata"].(map[string]interface{}); ok {
		spc.Name, _ = metadata["name"].(string)
		spc.Namespace, _ = metadata["namespace"].(string)
	}

	if spec, ok := obj["spec"].(map[string]interface{}); ok {
		spc.Provider, _ = spec["provider"].(string)

		if params, ok := spec["parameters"].(map[string]interface{}); ok {
			for k, v := range params {
				if vStr, ok := v.(string); ok {
					spc.Parameters[k] = vStr
				}
			}
		}

		if secretObjects, ok := spec["secretObjects"].([]interface{}); ok {
			spc.SecretObjects = len(secretObjects)
		}
	}

	spc.Status = "active"

	// Count pods using this SecretProviderClass
	if spc.Namespace != "" {
		pods, err := clientset.CoreV1().Pods(spc.Namespace).List(ctx, metav1.ListOptions{})
		if err == nil {
			for _, pod := range pods.Items {
				for _, vol := range pod.Spec.Volumes {
					if vol.CSI != nil && vol.CSI.Driver == "secrets-store.csi.k8s.io" {
						if vol.CSI.VolumeAttributes != nil {
							if class, ok := vol.CSI.VolumeAttributes["secretProviderClass"]; ok && class == spc.Name {
								spc.UsedByPods++
							}
						}
					}
				}
			}
		}
	}

	// Provider-specific security analysis
	switch spc.Provider {
	case "azure":
		if tenantID, ok := spc.Parameters["tenantId"]; ok && tenantID == "" {
			spc.SecurityIssues = append(spc.SecurityIssues, "Missing tenant ID")
		}
	case "aws":
		// Check for overly permissive configurations
	case "vault":
		if addr, ok := spc.Parameters["vaultAddress"]; ok && strings.HasPrefix(addr, "http://") {
			spc.SecurityIssues = append(spc.SecurityIssues, "Vault not using TLS")
		}
	}

	return spc
}

// ============================================================================
// Unmanaged Secrets Analysis
// ============================================================================

func analyzeUnmanagedSecrets(ctx context.Context, clientset kubernetes.Interface,
	externalSecrets []ExternalSecretConfig,
	vaultStaticSecrets []VaultStaticSecretConfig,
	vaultDynamicSecrets []VaultDynamicSecretConfig,
	sealedSecrets []SealedSecretConfig,
	secretProviderClasses []SecretProviderClassConfig) []UnmanagedSecretInfo {

	var unmanagedSecrets []UnmanagedSecretInfo

	// Build set of managed secret names
	managedSecrets := make(map[string]bool)

	for _, es := range externalSecrets {
		key := es.Namespace + "/" + es.TargetName
		managedSecrets[key] = true
	}

	for _, vs := range vaultStaticSecrets {
		key := vs.Namespace + "/" + vs.DestinationName
		managedSecrets[key] = true
	}

	for _, vd := range vaultDynamicSecrets {
		key := vd.Namespace + "/" + vd.DestinationName
		managedSecrets[key] = true
	}

	for _, ss := range sealedSecrets {
		key := ss.Namespace + "/" + ss.TargetName
		managedSecrets[key] = true
	}

	// Get all secrets
	secrets, err := clientset.CoreV1().Secrets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return unmanagedSecrets
	}

	// Get pods for mount analysis
	pods, _ := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	podSecretUsage := make(map[string]int) // namespace/secretName -> pod count

	for _, pod := range pods.Items {
		// Check volume mounts
		for _, vol := range pod.Spec.Volumes {
			if vol.Secret != nil {
				key := pod.Namespace + "/" + vol.Secret.SecretName
				podSecretUsage[key]++
			}
		}
		// Check env vars
		for _, container := range pod.Spec.Containers {
			for _, env := range container.Env {
				if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
					key := pod.Namespace + "/" + env.ValueFrom.SecretKeyRef.Name
					podSecretUsage[key]++
				}
			}
			for _, envFrom := range container.EnvFrom {
				if envFrom.SecretRef != nil {
					key := pod.Namespace + "/" + envFrom.SecretRef.Name
					podSecretUsage[key]++
				}
			}
		}
	}

	// Sensitive patterns
	sensitivePatterns := []string{
		"password", "passwd", "pwd",
		"secret", "token", "key",
		"credential", "cred",
		"api-key", "apikey", "api_key",
		"private", "priv",
		"auth", "bearer",
		"aws_access", "aws_secret",
		"azure", "gcp", "google",
		"db_", "database",
		"mysql", "postgres", "mongo", "redis",
		"ssh", "rsa", "ecdsa", "ed25519",
	}

	for _, secret := range secrets.Items {
		// Skip system secrets
		if strings.HasPrefix(secret.Namespace, "kube-") && secret.Type == corev1.SecretTypeServiceAccountToken {
			continue
		}
		if secret.Type == corev1.SecretTypeServiceAccountToken {
			continue
		}

		key := secret.Namespace + "/" + secret.Name
		if managedSecrets[key] {
			continue
		}

		// Check if it's a managed secret by owner references
		isManaged := false
		for _, owner := range secret.OwnerReferences {
			ownerKind := strings.ToLower(owner.Kind)
			if strings.Contains(ownerKind, "externalsecret") ||
				strings.Contains(ownerKind, "sealedsecret") ||
				strings.Contains(ownerKind, "vaultsecret") {
				isManaged = true
				break
			}
		}
		if isManaged {
			continue
		}

		// Analyze the secret
		info := UnmanagedSecretInfo{
			Name:          secret.Name,
			Namespace:     secret.Namespace,
			Type:          string(secret.Type),
			MountedInPods: podSecretUsage[key],
		}

		// Get data keys
		for k := range secret.Data {
			info.DataKeys = append(info.DataKeys, k)
		}

		// Calculate age
		age := metav1.Now().Sub(secret.CreationTimestamp.Time)
		if age.Hours() < 24 {
			info.Age = fmt.Sprintf("%.0fh", age.Hours())
		} else {
			info.Age = fmt.Sprintf("%.0fd", age.Hours()/24)
		}

		// Check for sensitive patterns
		isHighRisk := false
		var riskReasons []string

		// Check secret name
		nameLower := strings.ToLower(secret.Name)
		for _, pattern := range sensitivePatterns {
			if strings.Contains(nameLower, pattern) {
				isHighRisk = true
				riskReasons = append(riskReasons, fmt.Sprintf("name contains '%s'", pattern))
				break
			}
		}

		// Check data keys
		for _, key := range info.DataKeys {
			keyLower := strings.ToLower(key)
			for _, pattern := range sensitivePatterns {
				if strings.Contains(keyLower, pattern) {
					isHighRisk = true
					riskReasons = append(riskReasons, fmt.Sprintf("key '%s' contains '%s'", key, pattern))
					break
				}
			}
		}

		// Check secret type
		if secret.Type == corev1.SecretTypeDockerConfigJson ||
			secret.Type == corev1.SecretTypeBasicAuth ||
			secret.Type == corev1.SecretTypeSSHAuth ||
			secret.Type == corev1.SecretTypeTLS {
			isHighRisk = true
			riskReasons = append(riskReasons, fmt.Sprintf("sensitive type: %s", secret.Type))
		}

		info.IsHighRisk = isHighRisk
		if len(riskReasons) > 0 {
			if len(riskReasons) > 2 {
				info.RiskReason = strings.Join(riskReasons[:2], "; ") + "..."
			} else {
				info.RiskReason = strings.Join(riskReasons, "; ")
			}
		} else {
			info.RiskReason = "-"
		}

		// Recommendations
		if isHighRisk {
			info.Recommendation = "Migrate to external secret management"
		} else if info.MountedInPods > 0 {
			info.Recommendation = "Consider external management"
		} else {
			info.Recommendation = "Review if still needed"
		}

		unmanagedSecrets = append(unmanagedSecrets, info)
	}

	// Sort by risk and namespace
	sort.Slice(unmanagedSecrets, func(i, j int) bool {
		if unmanagedSecrets[i].IsHighRisk != unmanagedSecrets[j].IsHighRisk {
			return unmanagedSecrets[i].IsHighRisk
		}
		if unmanagedSecrets[i].Namespace != unmanagedSecrets[j].Namespace {
			return unmanagedSecrets[i].Namespace < unmanagedSecrets[j].Namespace
		}
		return unmanagedSecrets[i].Name < unmanagedSecrets[j].Name
	})

	return unmanagedSecrets
}

// ============================================================================
// Build Findings
// ============================================================================

func buildSecretAdmissionFindings(ctx context.Context, clientset kubernetes.Interface,
	vaultInjector VaultAgentInjectorConfig,
	vaultOperator VaultSecretsOperatorConfig,
	vaultAuths []VaultAuthConfig,
	vaultStaticSecrets []VaultStaticSecretConfig,
	vaultDynamicSecrets []VaultDynamicSecretConfig,
	esoController ESOControllerConfig,
	secretStores []SecretStoreConfig,
	clusterSecretStores []SecretStoreConfig,
	externalSecrets []ExternalSecretConfig,
	sealedSecretsController SealedSecretsControllerConfig,
	sealedSecrets []SealedSecretConfig,
	csiDriver CSIDriverConfig,
	secretProviderClasses []SecretProviderClassConfig,
	unmanagedSecrets []UnmanagedSecretInfo) []SecretAdmissionFinding {

	// Group data by namespace
	namespaceData := make(map[string]*SecretAdmissionFinding)

	// Initialize with all namespaces from globals
	for _, ns := range globals.K8sNamespaces {
		namespaceData[ns] = &SecretAdmissionFinding{
			Namespace: ns,
		}
	}

	// Count total secrets per namespace
	secrets, _ := clientset.CoreV1().Secrets("").List(ctx, metav1.ListOptions{})
	for _, secret := range secrets.Items {
		if secret.Type == corev1.SecretTypeServiceAccountToken {
			continue
		}
		if finding, ok := namespaceData[secret.Namespace]; ok {
			finding.TotalSecrets++
		}
	}

	// Add Vault data
	for _, vs := range vaultStaticSecrets {
		if finding, ok := namespaceData[vs.Namespace]; ok {
			finding.VaultManagedSecrets++
			finding.ManagedSecrets++
			finding.VaultSecretsOperatorActive = true
		}
	}
	for _, vd := range vaultDynamicSecrets {
		if finding, ok := namespaceData[vd.Namespace]; ok {
			finding.VaultManagedSecrets++
			finding.ManagedSecrets++
			finding.VaultSecretsOperatorActive = true
		}
	}

	// Vault Agent Injector - check for injected pods
	if vaultInjector.Status == "active" {
		pods, _ := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
		for _, pod := range pods.Items {
			if annotations := pod.Annotations; annotations != nil {
				if inject, ok := annotations["vault.hashicorp.com/agent-inject"]; ok && inject == "true" {
					if finding, ok := namespaceData[pod.Namespace]; ok {
						finding.VaultInjectedPods++
						finding.VaultAgentInjectorActive = true
					}
				}
			}
		}
	}

	// Add ESO data
	for _, es := range externalSecrets {
		if finding, ok := namespaceData[es.Namespace]; ok {
			finding.ESOManagedSecrets++
			finding.ManagedSecrets++
			finding.ESOActive = true
			finding.ESOExternalSecretCount++
		}
	}

	// Count SecretStores per namespace
	for _, ss := range secretStores {
		if finding, ok := namespaceData[ss.Namespace]; ok {
			finding.ESOSecretStoreCount++
			finding.ESOActive = true
			if !secretAdmissionContainsString(finding.ESOProviders, ss.Provider) {
				finding.ESOProviders = append(finding.ESOProviders, ss.Provider)
			}
		}
	}

	// Cluster SecretStores apply to all namespaces
	for ns, finding := range namespaceData {
		for _, css := range clusterSecretStores {
			// Check if any ExternalSecret in this namespace uses this ClusterSecretStore
			for _, es := range externalSecrets {
				if es.Namespace == ns && es.SecretStoreKind == "ClusterSecretStore" && es.SecretStoreRef == css.Name {
					finding.ESOActive = true
					if !secretAdmissionContainsString(finding.ESOProviders, css.Provider) {
						finding.ESOProviders = append(finding.ESOProviders, css.Provider)
					}
				}
			}
		}
	}

	// Add Sealed Secrets data
	for _, ss := range sealedSecrets {
		if finding, ok := namespaceData[ss.Namespace]; ok {
			finding.SealedSecretCount++
			finding.SealedSecretsManagedCount++
			finding.ManagedSecrets++
			finding.SealedSecretsActive = true
		}
	}

	// Add CSI Driver data
	for _, spc := range secretProviderClasses {
		if finding, ok := namespaceData[spc.Namespace]; ok {
			finding.CSIProviderClasses++
			finding.CSIMountedSecrets += spc.SecretObjects
			finding.CSIDriverActive = true
			if !secretAdmissionContainsString(finding.CSIProviders, spc.Provider) {
				finding.CSIProviders = append(finding.CSIProviders, spc.Provider)
			}
		}
	}

	// Add unmanaged secret counts
	for _, us := range unmanagedSecrets {
		if finding, ok := namespaceData[us.Namespace]; ok {
			finding.UnmanagedSecrets++
			if us.IsHighRisk {
				finding.UnmanagedHighRisk++
			}
		}
	}

	// Calculate coverage and risk for each namespace
	var findings []SecretAdmissionFinding
	for _, finding := range namespaceData {
		// Calculate coverage
		if finding.TotalSecrets > 0 {
			coverage := float64(finding.ManagedSecrets) / float64(finding.TotalSecrets) * 100
			finding.ManagementCoverage = fmt.Sprintf("%.0f%%", coverage)
		} else {
			finding.ManagementCoverage = "N/A"
		}

		finding.HasExternalManagement = finding.VaultAgentInjectorActive || finding.VaultSecretsOperatorActive ||
			finding.ESOActive || finding.SealedSecretsActive || finding.CSIDriverActive

		// Calculate risk level
		finding.RiskLevel = calculateSecretRiskLevel(finding)

		// Add security issues
		if finding.UnmanagedHighRisk > 0 {
			finding.SecurityIssues = append(finding.SecurityIssues, fmt.Sprintf("%d high-risk unmanaged secrets", finding.UnmanagedHighRisk))
		}
		if finding.TotalSecrets > 0 && finding.ManagedSecrets == 0 && !finding.HasExternalManagement {
			finding.SecurityIssues = append(finding.SecurityIssues, "No external secret management")
		}

		findings = append(findings, *finding)
	}

	// Sort by namespace
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Namespace < findings[j].Namespace
	})

	return findings
}

func calculateSecretRiskLevel(finding *SecretAdmissionFinding) string {
	score := 0

	// High risk unmanaged secrets
	score += finding.UnmanagedHighRisk * 20

	// No management at all
	if !finding.HasExternalManagement && finding.TotalSecrets > 0 {
		score += 30
	}

	// Low coverage
	if finding.TotalSecrets > 0 {
		coverage := float64(finding.ManagedSecrets) / float64(finding.TotalSecrets)
		if coverage < 0.25 {
			score += 20
		} else if coverage < 0.5 {
			score += 10
		}
	}

	if score >= 50 {
		return "CRITICAL"
	} else if score >= 30 {
		return "HIGH"
	} else if score >= 15 {
		return "MEDIUM"
	} else if score > 0 {
		return "LOW"
	}
	return "INFO"
}

func secretAdmissionContainsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

func secretAdmissionTruncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// ============================================================================
// Loot Generation
// ============================================================================

func generateSecretAdmissionLoot(loot *shared.LootBuilder,
	findings []SecretAdmissionFinding,
	vaultInjector VaultAgentInjectorConfig,
	vaultOperator VaultSecretsOperatorConfig,
	vaultAuths []VaultAuthConfig,
	vaultStaticSecrets []VaultStaticSecretConfig,
	vaultDynamicSecrets []VaultDynamicSecretConfig,
	esoController ESOControllerConfig,
	secretStores []SecretStoreConfig,
	clusterSecretStores []SecretStoreConfig,
	externalSecrets []ExternalSecretConfig,
	sealedSecretsController SealedSecretsControllerConfig,
	sealedSecrets []SealedSecretConfig,
	csiDriver CSIDriverConfig,
	secretProviderClasses []SecretProviderClassConfig,
	unmanagedSecrets []UnmanagedSecretInfo) {

	// Summary section
	loot.Section("Summary").Add("# Secret Management Summary")
	loot.Section("Summary").Add("#")

	// Count active engines
	activeEngines := 0
	if vaultInjector.Status == "active" {
		activeEngines++
		loot.Section("Summary").Add(fmt.Sprintf("# Vault Agent Injector: ACTIVE (namespace: %s)", vaultInjector.Namespace))
	}
	if vaultOperator.Status == "active" {
		activeEngines++
		loot.Section("Summary").Add(fmt.Sprintf("# Vault Secrets Operator: ACTIVE (%d static, %d dynamic secrets)", vaultOperator.StaticSecrets, vaultOperator.DynamicSecrets))
	}
	if esoController.Status == "active" {
		activeEngines++
		providers := []string{}
		for _, ss := range secretStores {
			if !secretAdmissionContainsString(providers, ss.Provider) {
				providers = append(providers, ss.Provider)
			}
		}
		for _, css := range clusterSecretStores {
			if !secretAdmissionContainsString(providers, css.Provider) {
				providers = append(providers, css.Provider)
			}
		}
		loot.Section("Summary").Add(fmt.Sprintf("# External Secrets Operator: ACTIVE (%d secrets, providers: %s)", len(externalSecrets), strings.Join(providers, ", ")))
	}
	if sealedSecretsController.Status == "active" {
		activeEngines++
		loot.Section("Summary").Add(fmt.Sprintf("# Sealed Secrets: ACTIVE (%d sealed secrets)", len(sealedSecrets)))
	}
	if csiDriver.Status == "active" {
		activeEngines++
		loot.Section("Summary").Add(fmt.Sprintf("# Secrets Store CSI Driver: ACTIVE (providers: %s)", strings.Join(csiDriver.Providers, ", ")))
	}

	if activeEngines == 0 {
		loot.Section("Summary").Add("# WARNING: No external secret management detected!")
	}

	loot.Section("Summary").Add("#")

	// High-risk unmanaged secrets
	loot.Section("HighRiskSecrets").Add("# High-Risk Unmanaged Secrets")
	loot.Section("HighRiskSecrets").Add("# These secrets contain sensitive data and are not managed by external systems")
	loot.Section("HighRiskSecrets").Add("#")

	highRiskCount := 0
	for _, us := range unmanagedSecrets {
		if us.IsHighRisk {
			highRiskCount++
			loot.Section("HighRiskSecrets").Add(fmt.Sprintf("# %s/%s - %s", us.Namespace, us.Name, us.RiskReason))
			loot.Section("HighRiskSecrets").Add(fmt.Sprintf("kubectl get secret %s -n %s -o yaml", us.Name, us.Namespace))
		}
	}

	if highRiskCount == 0 {
		loot.Section("HighRiskSecrets").Add("# No high-risk unmanaged secrets found")
	}

	// Namespaces without secret management
	loot.Section("NoManagement").Add("# Namespaces Without External Secret Management")
	loot.Section("NoManagement").Add("#")

	for _, finding := range findings {
		if !finding.HasExternalManagement && finding.TotalSecrets > 0 {
			loot.Section("NoManagement").Add(fmt.Sprintf("# %s - %d secrets, %d unmanaged", finding.Namespace, finding.TotalSecrets, finding.UnmanagedSecrets))
		}
	}

	// Vault bypass risks
	if vaultInjector.Status == "active" || vaultOperator.Status == "active" {
		loot.Section("VaultBypass").Add("# Vault Bypass Vectors")
		loot.Section("VaultBypass").Add("#")

		if vaultInjector.FailurePolicy == "Ignore" {
			loot.Section("VaultBypass").Add("# WARNING: Vault Agent Injector has failurePolicy=Ignore")
			loot.Section("VaultBypass").Add("# Pods can be created without Vault injection during webhook failures")
		}

		for _, va := range vaultAuths {
			if va.BypassRisk != "" {
				loot.Section("VaultBypass").Add(fmt.Sprintf("# VaultAuth %s/%s: %s", va.Namespace, va.Name, va.BypassRisk))
			}
		}
	}

	// ESO issues
	if esoController.Status != "" {
		loot.Section("ESOIssues").Add("# External Secrets Operator Issues")
		loot.Section("ESOIssues").Add("#")

		for _, ss := range secretStores {
			if ss.Status == "Invalid" || ss.BypassRisk != "" {
				loot.Section("ESOIssues").Add(fmt.Sprintf("# SecretStore %s/%s: %s", ss.Namespace, ss.Name, ss.BypassRisk))
			}
		}
		for _, css := range clusterSecretStores {
			if css.Status == "Invalid" || css.BypassRisk != "" {
				loot.Section("ESOIssues").Add(fmt.Sprintf("# ClusterSecretStore %s: %s", css.Name, css.BypassRisk))
			}
		}

		for _, es := range externalSecrets {
			if es.SyncStatus == "Error" {
				loot.Section("ESOIssues").Add(fmt.Sprintf("# ExternalSecret %s/%s: %s", es.Namespace, es.Name, es.BypassRisk))
			}
		}
	}

	// Recommendations
	loot.Section("Recommendations").Add("# Recommendations")
	loot.Section("Recommendations").Add("#")

	if activeEngines == 0 {
		loot.Section("Recommendations").Add("# 1. Deploy external secret management (ESO, Vault, Sealed Secrets)")
		loot.Section("Recommendations").Add("#    - External Secrets Operator: helm install external-secrets external-secrets/external-secrets -n external-secrets --create-namespace")
		loot.Section("Recommendations").Add("#    - Sealed Secrets: helm install sealed-secrets sealed-secrets/sealed-secrets -n kube-system")
	}

	if highRiskCount > 0 {
		loot.Section("Recommendations").Add(fmt.Sprintf("# 2. Migrate %d high-risk secrets to external management", highRiskCount))
	}

	// Commands
	loot.Section("Commands").Add("# Useful Commands")
	loot.Section("Commands").Add("#")
	loot.Section("Commands").Add("# List all secrets by namespace:")
	loot.Section("Commands").Add("kubectl get secrets -A -o custom-columns='NAMESPACE:.metadata.namespace,NAME:.metadata.name,TYPE:.type'")
	loot.Section("Commands").Add("#")
	loot.Section("Commands").Add("# Check ESO status:")
	loot.Section("Commands").Add("kubectl get externalsecrets -A")
	loot.Section("Commands").Add("kubectl get secretstores -A")
	loot.Section("Commands").Add("kubectl get clustersecretstores")
	loot.Section("Commands").Add("#")
	loot.Section("Commands").Add("# Check Vault status:")
	loot.Section("Commands").Add("kubectl get vaultauths -A")
	loot.Section("Commands").Add("kubectl get vaultstaticsecrets -A")
	loot.Section("Commands").Add("kubectl get vaultdynamicsecrets -A")
	loot.Section("Commands").Add("#")
	loot.Section("Commands").Add("# Check Sealed Secrets:")
	loot.Section("Commands").Add("kubectl get sealedsecrets -A")
}
