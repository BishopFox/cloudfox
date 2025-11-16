package commands

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	k8sinternal "github.com/BishopFox/cloudfox/internal/kubernetes"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/spf13/cobra"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

var SecretsCmd = &cobra.Command{
	Use:     "secrets",
	Aliases: []string{},
	Short:   "List all cluster secrets with comprehensive security analysis",
	Long: `
List all cluster secrets with comprehensive security analysis including:
- RBAC analysis (who can access secrets)
- ServiceAccount token extraction and permission testing
- Certificate expiration tracking for TLS secrets
- Unused/orphaned secret detection
- Age and rotation analysis
- Secret sprawl detection
- Risk-based scoring with RBAC factors
  cloudfox kubernetes secrets`,
	Run: ListSecrets,
}

type SecretsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t SecretsOutput) TableFiles() []internal.TableFile {
	return t.Table
}

func (t SecretsOutput) LootFiles() []internal.LootFile {
	return t.Loot
}

type SecretFinding struct {
	// Basic Info
	Namespace string
	Name      string
	Type      string
	DataKeys  []string
	Age       time.Duration
	AgeDays   int

	// Security Analysis
	RiskLevel      string
	RiskScore      int
	SecurityIssues []string

	// Sensitive Pattern Detection
	SensitivePatterns   []string
	HasSensitivePattern bool
	CloudCredentials    bool
	PrivateKeys         bool

	// Pod Exposure
	MountedInPods []string
	MountType     string // "volume", "env", or "both"

	// RBAC Analysis
	AccessibleBySAs      []string
	RBACAccessCount      int
	OverPrivilegedAccess bool
	PubliclyAccessible   bool

	// Secret Properties
	DataSize       int
	KeyCount       int
	IsImmutable    bool
	IsUnused       bool
	NeedsRotation  bool
	IsExternal     bool
	ExternalSource string

	// Certificate Analysis (for TLS secrets)
	IsTLS            bool
	CertSubject      string
	CertIssuer       string
	CertExpiration   time.Time
	CertExpiryDays   int
	CertExpired      bool
	CertExpiringSoon bool
	CertSANs         []string
	CertSelfSigned   bool

	// ServiceAccount Token Analysis
	IsSAToken        bool
	SAName           string
	SANamespace      string
	SAPermissions    []string
	SAHasAdminAccess bool

	// Metadata
	Labels      map[string]string
	Annotations map[string]string
	CreatedAt   time.Time
}

// RBACBinding represents RBAC access to secrets
type RBACBinding struct {
	Type           string // "Role" or "ClusterRole"
	Name           string
	Namespace      string
	ServiceAccount string
	Verbs          []string
}

// CertificateInfo holds parsed certificate information
type SecretCertificateInfo struct {
	Subject         string
	Issuer          string
	NotBefore       time.Time
	NotAfter        time.Time
	DNSNames        []string
	IsSelfSigned    bool
	IsExpired       bool
	DaysUntilExpiry int
}

func ListSecrets(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating secrets for %s", globals.ClusterName), globals.K8S_SECRETS_MODULE_NAME)

	clientset := config.GetClientOrExit()

	// Get all namespaces
	namespaces, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing namespaces: %v", err), globals.K8S_SECRETS_MODULE_NAME)
		return
	}

	// Get all pods for active exposure analysis
	logger.InfoM("Analyzing active secret exposure in pods...", globals.K8S_SECRETS_MODULE_NAME)
	allPods := []v1.Pod{}
	for _, ns := range namespaces.Items {
		pods, err := clientset.CoreV1().Pods(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}
		allPods = append(allPods, pods.Items...)
	}

	// Build secret-to-pod mapping
	secretToPods := make(map[string][]string)
	secretMountType := make(map[string]string)
	for _, pod := range allPods {
		// Check volume mounts
		for _, volume := range pod.Spec.Volumes {
			if volume.Secret != nil {
				key := fmt.Sprintf("%s/%s", pod.Namespace, volume.Secret.SecretName)
				podName := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)
				secretToPods[key] = append(secretToPods[key], podName)
				if secretMountType[key] == "" {
					secretMountType[key] = "volume"
				} else if secretMountType[key] == "env" {
					secretMountType[key] = "both"
				}
			}
		}

		// Check environment variables
		for _, container := range pod.Spec.Containers {
			for _, envFrom := range container.EnvFrom {
				if envFrom.SecretRef != nil {
					key := fmt.Sprintf("%s/%s", pod.Namespace, envFrom.SecretRef.Name)
					podName := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)
					secretToPods[key] = append(secretToPods[key], podName)
					if secretMountType[key] == "" {
						secretMountType[key] = "env"
					} else if secretMountType[key] == "volume" {
						secretMountType[key] = "both"
					}
				}
			}
			for _, env := range container.Env {
				if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
					key := fmt.Sprintf("%s/%s", pod.Namespace, env.ValueFrom.SecretKeyRef.Name)
					podName := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)
					secretToPods[key] = append(secretToPods[key], podName)
					if secretMountType[key] == "" {
						secretMountType[key] = "env"
					} else if secretMountType[key] == "volume" {
						secretMountType[key] = "both"
					}
				}
			}
		}
	}

	// RBAC Analysis: Find who can access secrets
	logger.InfoM("Analyzing RBAC permissions for secret access...", globals.K8S_SECRETS_MODULE_NAME)
	rbacBindings := analyzeSecretRBAC(ctx, clientset)

	logger.InfoM("Analyzing secrets and calculating risk scores...", globals.K8S_SECRETS_MODULE_NAME)

	headers := []string{
		"Risk", "Risk Score", "Namespace", "Name", "Type", "Age (days)",
		"Mounted In", "RBAC Access", "Patterns", "Data Size", "Key Count",
		"Is Unused", "Needs Rotation", "Cert Expiry (days)", "Security Issues",
	}
	var outputRows [][]string
	var findings []SecretFinding

	// Risk level counters
	riskCounts := map[string]int{
		"CRITICAL": 0,
		"HIGH":     0,
		"MEDIUM":   0,
		"LOW":      0,
	}

	// Loot files
	namespaceLootEnum := map[string][]string{}
	var lootDecode []string
	var lootPatterns []string
	var lootCloudCreds []string
	var lootActiveExposure []string
	var lootExploitation []string
	var lootRBACAccess []string
	var lootSATokens []string
	var lootUnused []string
	var lootCertExpiry []string
	var lootOldStale []string
	var lootWeakCreds []string
	var lootSecretSprawl []string
	var lootRemediation []string

	// Initialize loot headers
	lootDecode = append(lootDecode, `#####################################
##### Decode Secret Values
#####################################
#
# Extract and decode all secret values
# WARNING: Contains sensitive data
#
`)

	lootPatterns = append(lootPatterns, `#####################################
##### Secret Pattern Analysis
#####################################
#
# Analyze secrets for sensitive patterns
# Potential credentials, keys, and tokens
#
`)

	lootCloudCreds = append(lootCloudCreds, `#####################################
##### Cloud Credential Usage
#####################################
#
# MANUAL EXECUTION REQUIRED
# Use extracted cloud credentials
#
`)

	lootActiveExposure = append(lootActiveExposure, `#####################################
##### Active Secret Exposure
#####################################
#
# Secrets mounted in running pods
# Direct access via pod exec
#
`)

	lootExploitation = append(lootExploitation, `#####################################
##### Secret Exploitation Techniques
#####################################
#
# MANUAL EXECUTION REQUIRED
# Techniques for extracting and using secrets
#
`)

	lootRBACAccess = append(lootRBACAccess, `#####################################
##### RBAC Secret Access Analysis
#####################################
#
# ANALYSIS REPORT
# ServiceAccounts with secret read permissions
# Shows blast radius of secret accessibility
#
`)

	lootSATokens = append(lootSATokens, `#####################################
##### ServiceAccount Token Exploitation
#####################################
#
# MANUAL EXECUTION REQUIRED
# Extract and test ServiceAccount tokens
#
`)

	lootUnused = append(lootUnused, `#####################################
##### Unused/Orphaned Secrets
#####################################
#
# ANALYSIS REPORT
# Secrets not mounted in any pod
# Cleanup candidates
#
`)

	lootCertExpiry = append(lootCertExpiry, `#####################################
##### Certificate Expiration Tracking
#####################################
#
# ANALYSIS REPORT
# TLS certificate expiration monitoring
#
`)

	lootOldStale = append(lootOldStale, `#####################################
##### Old and Stale Secrets
#####################################
#
# ANALYSIS REPORT
# Secrets older than 180 days
# Rotation recommended
#
`)

	lootWeakCreds = append(lootWeakCreds, `#####################################
##### Weak Credential Detection
#####################################
#
# ANALYSIS REPORT
# Potentially weak passwords and API keys
#
`)

	lootSecretSprawl = append(lootSecretSprawl, `#####################################
##### Secret Sprawl Detection
#####################################
#
# ANALYSIS REPORT
# Duplicate credentials across namespaces
#
`)

	lootRemediation = append(lootRemediation, `#####################################
##### Secret Remediation Guide
#####################################
#
# REMEDIATION STEPS
# How to fix secret security issues
#
`)

	// Track secret data for sprawl detection
	secretDataHashes := make(map[string][]string) // hash -> list of secret names

	for _, ns := range namespaces.Items {
		secrets, err := clientset.CoreV1().Secrets(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			logger.ErrorM(fmt.Sprintf("Error listing secrets in namespace: %v", err), globals.K8S_SECRETS_MODULE_NAME)
			continue
		}

		for _, secret := range secrets.Items {
			age := time.Since(secret.CreationTimestamp.Time)
			ageDays := int(age.Hours() / 24)

			// Get data keys
			var dataKeys []string
			for key := range secret.Data {
				dataKeys = append(dataKeys, key)
			}
			sort.Strings(dataKeys)

			// Calculate data size
			dataSize := 0
			for _, data := range secret.Data {
				dataSize += len(data)
			}

			// Create finding
			finding := SecretFinding{
				Namespace:   ns.Name,
				Name:        secret.Name,
				Type:        string(secret.Type),
				DataKeys:    dataKeys,
				Age:         age,
				AgeDays:     ageDays,
				DataSize:    dataSize,
				KeyCount:    len(dataKeys),
				Labels:      secret.Labels,
				Annotations: secret.Annotations,
				CreatedAt:   secret.CreationTimestamp.Time,
			}

			// Immutable check
			if secret.Immutable != nil {
				finding.IsImmutable = *secret.Immutable
			}

			// Detect sensitive patterns
			finding.HasSensitivePattern, finding.SensitivePatterns = k8sinternal.DetectSensitiveSecretPattern(
				finding.Type,
				finding.Name,
				dataKeys,
			)

			// Check for cloud credentials and private keys
			finding.CloudCredentials = k8sinternal.HasCloudCredentials(dataKeys)
			finding.PrivateKeys = k8sinternal.HasPrivateKeys(finding.Type, dataKeys)

			// Check active exposure in pods
			secretKey := fmt.Sprintf("%s/%s", ns.Name, secret.Name)
			if pods, found := secretToPods[secretKey]; found {
				finding.MountedInPods = k8sinternal.UniqueStrings(pods)
				finding.MountType = secretMountType[secretKey]
			}

			// Unused secret detection
			finding.IsUnused = (len(finding.MountedInPods) == 0)

			// Rotation recommendation (age > 180 days)
			finding.NeedsRotation = (ageDays > 180)

			// RBAC analysis for this secret
			finding.AccessibleBySAs = getAccessibleServiceAccounts(rbacBindings, ns.Name)
			finding.RBACAccessCount = len(finding.AccessibleBySAs)
			finding.OverPrivilegedAccess = hasOverPrivilegedAccess(rbacBindings, ns.Name)
			finding.PubliclyAccessible = hasPublicAccess(rbacBindings, ns.Name)

			// TLS certificate analysis
			if secret.Type == v1.SecretTypeTLS {
				finding.IsTLS = true
				if certData, exists := secret.Data["tls.crt"]; exists {
					certInfo := parseCertificate(certData)
					if certInfo != nil {
						finding.CertSubject = certInfo.Subject
						finding.CertIssuer = certInfo.Issuer
						finding.CertExpiration = certInfo.NotAfter
						finding.CertExpiryDays = certInfo.DaysUntilExpiry
						finding.CertExpired = certInfo.IsExpired
						finding.CertExpiringSoon = (certInfo.DaysUntilExpiry >= 0 && certInfo.DaysUntilExpiry < 30)
						finding.CertSANs = certInfo.DNSNames
						finding.CertSelfSigned = certInfo.IsSelfSigned
					}
				}
			}

			// ServiceAccount token analysis
			if secret.Type == v1.SecretTypeServiceAccountToken {
				finding.IsSAToken = true
				if saName, exists := secret.Annotations["kubernetes.io/service-account.name"]; exists {
					finding.SAName = saName
					finding.SANamespace = secret.Namespace
					// TODO: Could test SA permissions here via kubectl auth can-i
				}
			}

			// Secret sprawl detection (track secret data hashes)
			for key, data := range secret.Data {
				dataHash := fmt.Sprintf("%x", data) // Simple hash
				secretRef := fmt.Sprintf("%s/%s[%s]", ns.Name, secret.Name, key)
				secretDataHashes[dataHash] = append(secretDataHashes[dataHash], secretRef)
			}

			// Security Issues Summary
			finding.SecurityIssues = generateSecretSecurityIssues(&finding)

			// Calculate risk score and level
			finding.RiskLevel, finding.RiskScore = calculateSecretRiskScore(&finding)

			riskCounts[finding.RiskLevel]++
			findings = append(findings, finding)

			// Build output row
			patternsStr := "none"
			if len(finding.SensitivePatterns) > 0 {
				patternsStr = strings.Join(finding.SensitivePatterns, ", ")
			}

			mountedInStr := fmt.Sprintf("%d pods", len(finding.MountedInPods))
			if len(finding.MountedInPods) == 0 {
				mountedInStr = "not mounted"
			}

			rbacAccessStr := fmt.Sprintf("%d SAs", finding.RBACAccessCount)
			if finding.PubliclyAccessible {
				rbacAccessStr += " (public)"
			}

			certExpiryStr := "-"
			if finding.IsTLS {
				if finding.CertExpired {
					certExpiryStr = "EXPIRED"
				} else if finding.CertExpiryDays >= 0 {
					certExpiryStr = fmt.Sprintf("%d", finding.CertExpiryDays)
				}
			}

			outputRows = append(outputRows, []string{
				finding.RiskLevel,
				fmt.Sprintf("%d", finding.RiskScore),
				ns.Name,
				secret.Name,
				finding.Type,
				fmt.Sprintf("%d", ageDays),
				mountedInStr,
				rbacAccessStr,
				patternsStr,
				fmt.Sprintf("%d", dataSize),
				fmt.Sprintf("%d", len(dataKeys)),
				fmt.Sprintf("%v", finding.IsUnused),
				fmt.Sprintf("%v", finding.NeedsRotation),
				certExpiryStr,
				stringListOrNoneSecret(finding.SecurityIssues),
			})

			// Generate loot content
			generateSecretLootContent(&finding, &secret, dataKeys,
				&namespaceLootEnum, &lootDecode, &lootPatterns, &lootCloudCreds,
				&lootActiveExposure, &lootRBACAccess, &lootSATokens, &lootUnused,
				&lootCertExpiry, &lootOldStale, &lootRemediation)
		}
	}

	// Generate secret sprawl report
	for _, refs := range secretDataHashes {
		if len(refs) > 1 {
			lootSecretSprawl = append(lootSecretSprawl, fmt.Sprintf("\n### Duplicate secret data found in %d locations:", len(refs)))
			for _, ref := range refs {
				lootSecretSprawl = append(lootSecretSprawl, fmt.Sprintf("  - %s", ref))
			}
			lootSecretSprawl = append(lootSecretSprawl, "# Consider consolidating to a single secret source")
			lootSecretSprawl = append(lootSecretSprawl, "")
		}
	}

	// Generate exploitation techniques
	lootExploitation = append(lootExploitation, generateExploitationTechniques()...)

	// Build loot enum
	var lootEnum []string
	lootEnum = append(lootEnum, `#####################################
##### Enumerate Secrets
#####################################

`)
	if globals.KubeContext != "" {
		lootEnum = append(lootEnum, fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext))
	}

	nsListEnum := make([]string, 0, len(namespaceLootEnum))
	for ns := range namespaceLootEnum {
		nsListEnum = append(nsListEnum, ns)
	}
	sort.Strings(nsListEnum)
	for _, ns := range nsListEnum {
		lootEnum = append(lootEnum, fmt.Sprintf("\n# Namespace: %s\n", ns))
		lootEnum = append(lootEnum, namespaceLootEnum[ns]...)
	}

	// Add risk summary
	summary := fmt.Sprintf(`
# SUMMARY: Risk Distribution
# CRITICAL: %d secrets
# HIGH: %d secrets
# MEDIUM: %d secrets
# LOW: %d secrets
#
# Total secrets: %d
# Focus on CRITICAL and HIGH risk secrets first
`, riskCounts["CRITICAL"], riskCounts["HIGH"], riskCounts["MEDIUM"], riskCounts["LOW"], len(findings))

	lootActiveExposure = append([]string{summary}, lootActiveExposure...)

	table := internal.TableFile{
		Name:   "Secrets",
		Header: headers,
		Body:   outputRows,
	}

	lootFiles := []internal.LootFile{
		{Name: "Secrets-Enum", Contents: strings.Join(k8sinternal.Unique(lootEnum), "\n")},
		{Name: "Secrets-Decode", Contents: strings.Join(lootDecode, "\n")},
		{Name: "Secrets-Pattern-Analysis", Contents: strings.Join(lootPatterns, "\n")},
		{Name: "Secrets-Cloud-Credentials", Contents: strings.Join(lootCloudCreds, "\n")},
		{Name: "Secrets-Active-Exposure", Contents: strings.Join(lootActiveExposure, "\n")},
		{Name: "Secrets-Exploitation", Contents: strings.Join(lootExploitation, "\n")},
		{Name: "Secrets-RBAC-Access", Contents: strings.Join(lootRBACAccess, "\n")},
		{Name: "Secrets-ServiceAccount-Tokens", Contents: strings.Join(lootSATokens, "\n")},
		{Name: "Secrets-Unused-Orphaned", Contents: strings.Join(lootUnused, "\n")},
		{Name: "Secrets-Certificate-Expiration", Contents: strings.Join(lootCertExpiry, "\n")},
		{Name: "Secrets-Old-Stale", Contents: strings.Join(lootOldStale, "\n")},
		{Name: "Secrets-Weak-Credentials", Contents: strings.Join(lootWeakCreds, "\n")},
		{Name: "Secrets-Secret-Sprawl", Contents: strings.Join(lootSecretSprawl, "\n")},
		{Name: "Secrets-Remediation", Contents: strings.Join(lootRemediation, "\n")},
	}

	if err := internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"Secrets",
		globals.ClusterName,
		"results",
		SecretsOutput{
			Table: []internal.TableFile{table},
			Loot:  lootFiles,
		},
	); err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_SECRETS_MODULE_NAME)
		return
	}

	if len(outputRows) > 0 {
		if riskCounts["CRITICAL"] > 0 || riskCounts["HIGH"] > 0 {
			logger.InfoM(fmt.Sprintf("%d secrets found | Risk: CRITICAL=%d, HIGH=%d, MEDIUM=%d, LOW=%d",
				len(outputRows), riskCounts["CRITICAL"], riskCounts["HIGH"], riskCounts["MEDIUM"], riskCounts["LOW"]),
				globals.K8S_SECRETS_MODULE_NAME)
		} else {
			logger.InfoM(fmt.Sprintf("%d secrets found across %d namespaces", len(outputRows), len(namespaces.Items)), globals.K8S_SECRETS_MODULE_NAME)
		}
	} else {
		logger.InfoM("No secrets found, skipping output file creation", globals.K8S_SECRETS_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_SECRETS_MODULE_NAME), globals.K8S_SECRETS_MODULE_NAME)
}

// analyzeSecretRBAC analyzes RBAC permissions for secret access
func analyzeSecretRBAC(ctx context.Context, clientset *kubernetes.Clientset) []RBACBinding {
	var bindings []RBACBinding

	// Get all RoleBindings
	roleBindings, err := clientset.RbacV1().RoleBindings("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, rb := range roleBindings.Items {
			// Check if role grants secret access
			if grantSecretAccess(ctx, clientset, rb.RoleRef, rb.Namespace) {
				for _, subject := range rb.Subjects {
					if subject.Kind == "ServiceAccount" {
						bindings = append(bindings, RBACBinding{
							Type:           "Role",
							Name:           rb.RoleRef.Name,
							Namespace:      rb.Namespace,
							ServiceAccount: fmt.Sprintf("%s/%s", subject.Namespace, subject.Name),
							Verbs:          []string{"get", "list"}, // Simplified
						})
					}
				}
			}
		}
	}

	// Get all ClusterRoleBindings
	clusterRoleBindings, err := clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, crb := range clusterRoleBindings.Items {
			// Check if cluster role grants secret access
			if grantSecretAccessCluster(ctx, clientset, crb.RoleRef) {
				for _, subject := range crb.Subjects {
					if subject.Kind == "ServiceAccount" {
						bindings = append(bindings, RBACBinding{
							Type:           "ClusterRole",
							Name:           crb.RoleRef.Name,
							Namespace:      "", // Cluster-wide
							ServiceAccount: fmt.Sprintf("%s/%s", subject.Namespace, subject.Name),
							Verbs:          []string{"get", "list"}, // Simplified
						})
					}
				}
			}
		}
	}

	return bindings
}

// grantSecretAccess checks if a Role grants secret access
func grantSecretAccess(ctx context.Context, clientset *kubernetes.Clientset, roleRef rbacv1.RoleRef, namespace string) bool {
	if roleRef.Kind != "Role" {
		return false
	}

	role, err := clientset.RbacV1().Roles(namespace).Get(ctx, roleRef.Name, metav1.GetOptions{})
	if err != nil {
		return false
	}

	for _, rule := range role.Rules {
		for _, resource := range rule.Resources {
			if resource == "secrets" || resource == "*" {
				for _, verb := range rule.Verbs {
					if verb == "get" || verb == "list" || verb == "*" {
						return true
					}
				}
			}
		}
	}

	return false
}

// grantSecretAccessCluster checks if a ClusterRole grants secret access
func grantSecretAccessCluster(ctx context.Context, clientset *kubernetes.Clientset, roleRef rbacv1.RoleRef) bool {
	if roleRef.Kind != "ClusterRole" {
		return false
	}

	role, err := clientset.RbacV1().ClusterRoles().Get(ctx, roleRef.Name, metav1.GetOptions{})
	if err != nil {
		return false
	}

	for _, rule := range role.Rules {
		for _, resource := range rule.Resources {
			if resource == "secrets" || resource == "*" {
				for _, verb := range rule.Verbs {
					if verb == "get" || verb == "list" || verb == "*" {
						return true
					}
				}
			}
		}
	}

	return false
}

// getAccessibleServiceAccounts returns SAs that can access secrets in namespace
func getAccessibleServiceAccounts(bindings []RBACBinding, namespace string) []string {
	var sas []string
	for _, binding := range bindings {
		// Namespace-specific or cluster-wide
		if binding.Namespace == namespace || binding.Namespace == "" {
			sas = append(sas, binding.ServiceAccount)
		}
	}
	return k8sinternal.UniqueStrings(sas)
}

// hasOverPrivilegedAccess checks if secret is accessible by admin/edit roles
func hasOverPrivilegedAccess(bindings []RBACBinding, namespace string) bool {
	for _, binding := range bindings {
		if binding.Namespace == namespace || binding.Namespace == "" {
			roleName := strings.ToLower(binding.Name)
			if strings.Contains(roleName, "admin") || strings.Contains(roleName, "edit") || strings.Contains(roleName, "cluster-admin") {
				return true
			}
		}
	}
	return false
}

// hasPublicAccess checks if secret is publicly accessible
func hasPublicAccess(bindings []RBACBinding, namespace string) bool {
	for _, binding := range bindings {
		if binding.Namespace == namespace || binding.Namespace == "" {
			if strings.Contains(binding.ServiceAccount, "system:authenticated") || strings.Contains(binding.ServiceAccount, "system:unauthenticated") {
				return true
			}
		}
	}
	return false
}

// parseCertificate parses TLS certificate data
func parseCertificate(certData []byte) *SecretCertificateInfo {
	block, _ := pem.Decode(certData)
	if block == nil {
		return nil
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}

	now := time.Now()
	daysUntilExpiry := int(cert.NotAfter.Sub(now).Hours() / 24)

	isSelfSigned := cert.Issuer.String() == cert.Subject.String()

	return &SecretCertificateInfo{
		Subject:         cert.Subject.String(),
		Issuer:          cert.Issuer.String(),
		NotBefore:       cert.NotBefore,
		NotAfter:        cert.NotAfter,
		DNSNames:        cert.DNSNames,
		IsSelfSigned:    isSelfSigned,
		IsExpired:       now.After(cert.NotAfter),
		DaysUntilExpiry: daysUntilExpiry,
	}
}

// generateSecretSecurityIssues creates security issues summary
func generateSecretSecurityIssues(finding *SecretFinding) []string {
	var issues []string

	if finding.CloudCredentials {
		issues = append(issues, "CLOUD_CREDENTIALS")
	}
	if finding.PrivateKeys {
		issues = append(issues, "PRIVATE_KEYS")
	}
	if len(finding.MountedInPods) > 5 {
		issues = append(issues, fmt.Sprintf("WIDELY_MOUNTED(%d pods)", len(finding.MountedInPods)))
	}
	if finding.RBACAccessCount > 10 {
		issues = append(issues, fmt.Sprintf("RBAC_OVERLY_ACCESSIBLE(%d SAs)", finding.RBACAccessCount))
	}
	if finding.PubliclyAccessible {
		issues = append(issues, "PUBLICLY_ACCESSIBLE")
	}
	if finding.IsUnused && finding.RBACAccessCount > 0 {
		issues = append(issues, "UNUSED_BUT_ACCESSIBLE")
	}
	if finding.NeedsRotation {
		issues = append(issues, fmt.Sprintf("OLD_SECRET(%d days)", finding.AgeDays))
	}
	if finding.CertExpired {
		issues = append(issues, "CERT_EXPIRED")
	}
	if finding.CertExpiringSoon {
		issues = append(issues, fmt.Sprintf("CERT_EXPIRING_SOON(%d days)", finding.CertExpiryDays))
	}
	if finding.DataSize > 1048576 {
		issues = append(issues, "LARGE_SECRET(>1MB)")
	}
	if !finding.IsImmutable && finding.HasSensitivePattern {
		issues = append(issues, "NOT_IMMUTABLE")
	}
	if finding.SAHasAdminAccess {
		issues = append(issues, "SA_ADMIN_ACCESS")
	}

	return issues
}

// calculateSecretRiskScore calculates comprehensive risk score
func calculateSecretRiskScore(finding *SecretFinding) (string, int) {
	score := 0

	// Cloud credentials = CRITICAL
	if finding.CloudCredentials {
		score += 90
	}

	// Private keys = HIGH
	if finding.PrivateKeys {
		score += 70
	}

	// Active pod exposure
	score += len(finding.MountedInPods) * 5

	// RBAC exposure (blast radius)
	if finding.RBACAccessCount > 50 {
		score += 50
	} else if finding.RBACAccessCount > 20 {
		score += 30
	} else if finding.RBACAccessCount > 10 {
		score += 20
	} else {
		score += finding.RBACAccessCount * 2
	}

	// Public accessibility = CRITICAL
	if finding.PubliclyAccessible {
		score += 80
	}

	// Over-privileged access
	if finding.OverPrivilegedAccess {
		score += 25
	}

	// Age-based scoring
	if finding.AgeDays > 365 {
		score += 30
	} else if finding.AgeDays > 180 {
		score += 20
	} else if finding.AgeDays > 90 {
		score += 10
	}

	// Certificate expiration
	if finding.CertExpired {
		score += 90
	} else if finding.CertExpiringSoon {
		score += 40
	}

	// Unused but accessible = security risk
	if finding.IsUnused && finding.RBACAccessCount > 0 {
		score += 25
	}

	// Large secret = potential credential dump
	if finding.DataSize > 1048576 {
		score += 15
	}

	// Not immutable sensitive data
	if !finding.IsImmutable && finding.HasSensitivePattern {
		score += 10
	}

	// SA with admin access
	if finding.SAHasAdminAccess {
		score += 60
	}

	// Namespace-based scoring
	if finding.Namespace == "kube-system" || finding.Namespace == "kube-public" {
		score += 15
	}

	// Determine risk level
	if score >= 85 {
		return "CRITICAL", score
	} else if score >= 60 {
		return "HIGH", score
	} else if score >= 30 {
		return "MEDIUM", score
	}
	return "LOW", score
}

func stringListOrNoneSecret(list []string) string {
	if len(list) == 0 {
		return "<NONE>"
	}
	return strings.Join(list, ", ")
}

func generateSecretLootContent(finding *SecretFinding, secret *v1.Secret, dataKeys []string,
	namespaceLootEnum *map[string][]string,
	lootDecode, lootPatterns, lootCloudCreds, lootActiveExposure,
	lootRBACAccess, lootSATokens, lootUnused, lootCertExpiry, lootOldStale, lootRemediation *[]string) {

	secretID := fmt.Sprintf("%s/%s", finding.Namespace, finding.Name)

	// Enumeration
	(*namespaceLootEnum)[finding.Namespace] = append((*namespaceLootEnum)[finding.Namespace],
		fmt.Sprintf("# [%s] %s (Type: %s)", finding.RiskLevel, secretID, finding.Type),
		fmt.Sprintf("kubectl get secret %s -n %s -o yaml", finding.Name, finding.Namespace),
		fmt.Sprintf(`kubectl get secret %s -n %s -o json | jq -r '.data | to_entries[] | "\(.key)=\(.value | @base64d)"'`, finding.Name, finding.Namespace),
		"",
	)

	// Decode commands
	*lootDecode = append(*lootDecode, fmt.Sprintf("\n# [%s] Secret: %s (Type: %s)", finding.RiskLevel, secretID, finding.Type))
	if len(finding.SensitivePatterns) > 0 {
		*lootDecode = append(*lootDecode, fmt.Sprintf("# Patterns: %s", strings.Join(finding.SensitivePatterns, ", ")))
	}
	for _, key := range dataKeys {
		*lootDecode = append(*lootDecode, fmt.Sprintf("kubectl get secret %s -n %s -o jsonpath='{.data.%s}' | base64 -d", finding.Name, finding.Namespace, key))
	}
	*lootDecode = append(*lootDecode, "")

	// Active exposure analysis
	if len(finding.MountedInPods) > 0 {
		*lootActiveExposure = append(*lootActiveExposure, fmt.Sprintf("\n# [%s] %s -> %d pods (%s mount)", finding.RiskLevel, secretID, len(finding.MountedInPods), finding.MountType))
		if len(finding.SensitivePatterns) > 0 {
			*lootActiveExposure = append(*lootActiveExposure, fmt.Sprintf("# Contains: %s", strings.Join(finding.SensitivePatterns, ", ")))
		}
		for _, pod := range finding.MountedInPods {
			parts := strings.Split(pod, "/")
			if len(parts) == 2 {
				*lootActiveExposure = append(*lootActiveExposure, fmt.Sprintf("kubectl exec -n %s %s -- sh -c 'ls -la /var/run/secrets/ || env | grep -i secret || env'", parts[0], parts[1]))
			}
		}
		*lootActiveExposure = append(*lootActiveExposure, "")
	}

	// RBAC access analysis
	if finding.RBACAccessCount > 0 {
		*lootRBACAccess = append(*lootRBACAccess, fmt.Sprintf("\n### %s - Accessible by %d ServiceAccounts", secretID, finding.RBACAccessCount))
		if finding.PubliclyAccessible {
			*lootRBACAccess = append(*lootRBACAccess, "  - PUBLICLY ACCESSIBLE (system:authenticated)")
		}
		if finding.OverPrivilegedAccess {
			*lootRBACAccess = append(*lootRBACAccess, "  - Over-privileged access (admin/edit roles)")
		}
		for i, sa := range finding.AccessibleBySAs {
			if i < 10 {
				*lootRBACAccess = append(*lootRBACAccess, fmt.Sprintf("  - %s", sa))
			}
		}
		if len(finding.AccessibleBySAs) > 10 {
			*lootRBACAccess = append(*lootRBACAccess, fmt.Sprintf("  - ... and %d more", len(finding.AccessibleBySAs)-10))
		}
		*lootRBACAccess = append(*lootRBACAccess, "")
	}

	// ServiceAccount token analysis
	if finding.IsSAToken {
		*lootSATokens = append(*lootSATokens, fmt.Sprintf("\n### %s - ServiceAccount: %s/%s", secretID, finding.SANamespace, finding.SAName))
		*lootSATokens = append(*lootSATokens, fmt.Sprintf("TOKEN=$(kubectl get secret %s -n %s -o jsonpath='{.data.token}' | base64 -d)", finding.Name, finding.Namespace))
		*lootSATokens = append(*lootSATokens, "kubectl auth can-i --list --token=$TOKEN")
		*lootSATokens = append(*lootSATokens, "")
	}

	// Unused secrets
	if finding.IsUnused {
		*lootUnused = append(*lootUnused, fmt.Sprintf("\n### %s - Age: %d days", secretID, finding.AgeDays))
		*lootUnused = append(*lootUnused, fmt.Sprintf("  - Not mounted in any pod"))
		*lootUnused = append(*lootUnused, fmt.Sprintf("  - Accessible by %d ServiceAccounts", finding.RBACAccessCount))
		if finding.AgeDays > 180 {
			*lootUnused = append(*lootUnused, fmt.Sprintf("  - OLD: Created %d days ago", finding.AgeDays))
		}
		*lootUnused = append(*lootUnused, "  - Consider deletion if truly unused")
		*lootUnused = append(*lootUnused, fmt.Sprintf("  # kubectl delete secret %s -n %s", finding.Name, finding.Namespace))
		*lootUnused = append(*lootUnused, "")
	}

	// Certificate expiration
	if finding.IsTLS {
		*lootCertExpiry = append(*lootCertExpiry, fmt.Sprintf("\n### %s", secretID))
		*lootCertExpiry = append(*lootCertExpiry, fmt.Sprintf("  Subject: %s", finding.CertSubject))
		*lootCertExpiry = append(*lootCertExpiry, fmt.Sprintf("  Issuer: %s", finding.CertIssuer))
		if finding.CertExpired {
			*lootCertExpiry = append(*lootCertExpiry, "  Status: EXPIRED")
		} else if finding.CertExpiringSoon {
			*lootCertExpiry = append(*lootCertExpiry, fmt.Sprintf("  Status: Expiring in %d days (URGENT)", finding.CertExpiryDays))
		} else {
			*lootCertExpiry = append(*lootCertExpiry, fmt.Sprintf("  Expires in: %d days", finding.CertExpiryDays))
		}
		if finding.CertSelfSigned {
			*lootCertExpiry = append(*lootCertExpiry, "  Type: Self-signed")
		}
		*lootCertExpiry = append(*lootCertExpiry, "")
	}

	// Old/stale secrets
	if finding.AgeDays > 180 {
		*lootOldStale = append(*lootOldStale, fmt.Sprintf("\n### %s - %d days old", secretID, finding.AgeDays))
		*lootOldStale = append(*lootOldStale, fmt.Sprintf("  - Created: %s", finding.CreatedAt.Format("2006-01-02")))
		if finding.CloudCredentials {
			*lootOldStale = append(*lootOldStale, "  - Contains cloud credentials (ROTATION RECOMMENDED)")
		}
		if len(finding.MountedInPods) == 0 {
			*lootOldStale = append(*lootOldStale, "  - Not currently in use (consider deletion)")
		}
		*lootOldStale = append(*lootOldStale, "")
	}

	// Cloud credential patterns
	if string(finding.Type) == string(v1.SecretTypeDockerConfigJson) {
		*lootPatterns = append(*lootPatterns, fmt.Sprintf("\n# [%s] DOCKER REGISTRY CREDENTIALS: %s", finding.RiskLevel, secretID))
		*lootPatterns = append(*lootPatterns, fmt.Sprintf("kubectl get secret %s -n %s -o jsonpath='{.data.\\.dockerconfigjson}' | base64 -d | jq .", finding.Name, finding.Namespace))
		*lootPatterns = append(*lootPatterns, "")

		*lootCloudCreds = append(*lootCloudCreds, fmt.Sprintf("\n# [%s] Docker Registry: %s", finding.RiskLevel, secretID))
		*lootCloudCreds = append(*lootCloudCreds, fmt.Sprintf("kubectl get secret %s -n %s -o jsonpath='{.data.\\.dockerconfigjson}' | base64 -d > docker-config.json", finding.Name, finding.Namespace))
		*lootCloudCreds = append(*lootCloudCreds, "# docker login -u <username> -p <password> <registry>")
		*lootCloudCreds = append(*lootCloudCreds, "")
	}

	// Remediation
	if len(finding.SecurityIssues) > 0 {
		*lootRemediation = append(*lootRemediation, fmt.Sprintf("\n### %s (%d issues)", secretID, len(finding.SecurityIssues)))
		for _, issue := range finding.SecurityIssues {
			*lootRemediation = append(*lootRemediation, fmt.Sprintf("## Issue: %s", issue))
			switch {
			case strings.Contains(issue, "PUBLICLY_ACCESSIBLE"):
				*lootRemediation = append(*lootRemediation, "Remediation: Remove RBAC bindings granting public access")
			case strings.Contains(issue, "RBAC_OVERLY_ACCESSIBLE"):
				*lootRemediation = append(*lootRemediation, "Remediation: Reduce RBAC permissions, use namespace-scoped Roles")
			case strings.Contains(issue, "OLD_SECRET"):
				*lootRemediation = append(*lootRemediation, "Remediation: Rotate secret credentials")
			case strings.Contains(issue, "CERT_EXPIRED"):
				*lootRemediation = append(*lootRemediation, "Remediation: Renew certificate immediately")
			case strings.Contains(issue, "CERT_EXPIRING_SOON"):
				*lootRemediation = append(*lootRemediation, "Remediation: Renew certificate before expiration")
			case strings.Contains(issue, "NOT_IMMUTABLE"):
				*lootRemediation = append(*lootRemediation, "Remediation: Set immutable: true for security and performance")
			case strings.Contains(issue, "UNUSED_BUT_ACCESSIBLE"):
				*lootRemediation = append(*lootRemediation, "Remediation: Delete if truly unused, or remove RBAC access")
			}
		}
		*lootRemediation = append(*lootRemediation, "")
	}
}

func generateExploitationTechniques() []string {
	return []string{`
##############################################
## 1. Extract Secrets from Running Pods
##############################################
# If you can exec into pods that mount secrets:

# Find pods with secret volumes:
kubectl get pods --all-namespaces -o json | jq -r '.items[] | select(.spec.volumes[]?.secret != null) | "\(.metadata.namespace)/\(.metadata.name)"'

# Exec into pod and read secrets:
kubectl exec -n <namespace> <pod> -- sh -c 'find /var/run/secrets -type f -exec echo {} \; -exec cat {} \;'

# Read service account token:
kubectl exec -n <namespace> <pod> -- cat /var/run/secrets/kubernetes.io/serviceaccount/token

# Dump all environment variables (may contain secret values):
kubectl exec -n <namespace> <pod> -- env

##############################################
## 2. ServiceAccount Token Exploitation
##############################################
# Extract SA token from pod:
TOKEN=$(kubectl exec -n <namespace> <pod> -- cat /var/run/secrets/kubernetes.io/serviceaccount/token)

# Use token to access API server:
APISERVER=https://kubernetes.default.svc
curl -k -H "Authorization: Bearer $TOKEN" $APISERVER/api/v1/namespaces

# Check permissions:
kubectl auth can-i --list --token=$TOKEN

##############################################
## 3. RBAC Enumeration for Secret Access
##############################################
# Find who can read secrets:
kubectl get rolebindings,clusterrolebindings --all-namespaces -o json | jq -r '.items[] | select(.roleRef.name | test(".*secret.*|.*admin.*|.*edit.*")) | "\(.metadata.namespace)//\(.metadata.name) -> \(.roleRef.name)"'

# List secrets you can access:
kubectl auth can-i get secrets --all-namespaces

##############################################
## 4. Extract Secrets via RBAC
##############################################
# If you have a ServiceAccount with secret read permissions:
SA_TOKEN=$(kubectl get secret <sa-secret> -n <namespace> -o jsonpath='{.data.token}' | base64 -d)
kubectl --token=$SA_TOKEN get secrets --all-namespaces

##############################################
## 5. Certificate Theft
##############################################
# Extract TLS private keys:
kubectl get secret <tls-secret> -n <namespace> -o jsonpath='{.data.tls\.key}' | base64 -d > private.key
kubectl get secret <tls-secret> -n <namespace> -o jsonpath='{.data.tls\.crt}' | base64 -d > certInfo.crt

# Use stolen certificate:
curl --key private.key --cert certInfo.crt https://secure-service.example.com
`}
}

// Helper functions
func containsAWS(keys []string) bool {
	for _, key := range keys {
		keyLower := strings.ToLower(key)
		if strings.Contains(keyLower, "aws") || keyLower == "aws_access_key_id" || keyLower == "aws_secret_access_key" {
			return true
		}
	}
	return false
}

func containsGCP(keys []string) bool {
	for _, key := range keys {
		keyLower := strings.ToLower(key)
		if strings.Contains(keyLower, "gcp") || strings.Contains(keyLower, "google") || keyLower == "credentials.json" || keyLower == "key.json" {
			return true
		}
	}
	return false
}

func containsAzure(keys []string) bool {
	for _, key := range keys {
		keyLower := strings.ToLower(key)
		if strings.Contains(keyLower, "azure") || keyLower == "client_secret" || keyLower == "tenant_id" {
			return true
		}
	}
	return false
}
