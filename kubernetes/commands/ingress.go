package commands

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	k8sinternal "github.com/BishopFox/cloudfox/internal/kubernetes"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/BishopFox/cloudfox/kubernetes/sdk"
	"github.com/BishopFox/cloudfox/kubernetes/shared"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
)

var IngressCmd = &cobra.Command{
	Use:     "ingress",
	Aliases: []string{"ing"},
	Short:   "Enumerate ingress resources with security analysis",
	Long: `
Enumerate all ingress resources in the cluster with comprehensive security analysis including:
  - Risk-based scoring based on dangerous annotations and TLS configuration
  - Security weakness detection (dangerous NGINX annotations, missing auth, weak TLS)
  - External exposure analysis
  - Backend service security assessment
  - Exploitation techniques for identified vulnerabilities

  cloudfox kubernetes ingress`,
	Run: ListIngress,
}

type IngressOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (i IngressOutput) TableFiles() []internal.TableFile {
	return i.Table
}

func (i IngressOutput) LootFiles() []internal.LootFile {
	return i.Loot
}

type IngressFinding struct {
	Namespace            string
	Name                 string
	IngressClass         string
	Hosts                []string
	Paths                []string
	Backends             []string
	TLSEnabled           bool
	TLSHosts             []string
	ExternalIPs          []string
	Annotations          map[string]string
	RiskLevel            string
	SecurityIssues       []string
	DangerousAnnotations []string
	Exposure             string

	// Security analysis fields
	AuthEnabled           bool
	AuthType              string
	RateLimitEnabled      bool
	RateLimitValue        string // Actual rate limit value (e.g., "100 rps")
	WAFEnabled            bool
	WAFType               string // "ModSecurity", "OWASP CRS", or "None"
	SSLRedirect           string // "Enabled" or "Disabled"
	IPWhitelist           string // CIDR range or "None"
	WildcardHost          string // The wildcard host or "None"
	CORSOrigin            string // CORS origin value or "None"
	SensitivePaths        []string
	BackendSecurity       string // "Secure", "Vulnerable", "Unknown"
	CertExpiry            string // "Valid", "Expiring Soon (<30d)", "Expired", "N/A"
	CertIssues            []string
	SecurityHeaders       []string
	MissingHeaders        []string
	DefaultBackend        string
	BackendPods           int
	BackendServiceAccount string
}

// CertificateInfo contains TLS certificate analysis
type CertificateInfo struct {
	SecretName      string
	Namespace       string
	ExpiryStatus    string // "Valid", "Expiring Soon (<30d)", "Expired"
	DaysUntilExpiry int
	KeyStrength     string // "Strong (>=2048)", "Weak (<2048)"
	IsSelfSigned    bool
	Issues          []string
	Subject         string
	Issuer          string
}

func ListIngress(cmd *cobra.Command, args []string) {
	ctx, cancel := shared.ContextWithCancel()
	defer cancel()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating ingress resources for %s", globals.ClusterName), globals.K8S_INGRESS_MODULE_NAME)

	clientset := config.GetClientOrExit()

	// Get all ingresses using cache
	allIngresses, err := sdk.GetIngresses(ctx, clientset)
	if err != nil {
		shared.LogListError(&logger, "ingresses", "", err, globals.K8S_INGRESS_MODULE_NAME, true)
		return
	}

	// Get all secrets using cache for certificate analysis
	allSecrets, _ := sdk.GetSecrets(ctx, clientset)
	secretMap := make(map[string]corev1.Secret)
	for _, s := range allSecrets {
		secretMap[fmt.Sprintf("%s/%s", s.Namespace, s.Name)] = s
	}

	// Get all services using cache for backend analysis
	allServices, _ := sdk.GetServices(ctx, clientset)
	serviceMap := make(map[string]corev1.Service)
	for _, svc := range allServices {
		serviceMap[fmt.Sprintf("%s/%s", svc.Namespace, svc.Name)] = svc
	}

	// Get all pods using cache
	allPods, _ := sdk.GetPods(ctx, clientset)

	// Get all network policies using cache
	allNetpols, _ := sdk.GetNetworkPolicies(ctx, clientset)

	headers := []string{
		"Namespace",
		"Name",
		"Ingress Class",
		"Hosts",
		"External IPs",
		"Exposure",
		"TLS",
		"SSL Redirect",
		"Cert Expiry",
		"Auth",
		"Rate Limit",
		"WAF",
		"IP Whitelist",
		"Dangerous Annot",
		"Wildcard Host",
		"CORS Origin",
		"Sensitive Paths",
		"Backend Security",
	}

	var outputRows [][]string
	var findings []IngressFinding

	// Risk level counters
	riskCounts := shared.NewRiskCounts()

	loot := shared.NewLootBuilder()

	loot.Section("Ingress-Commands").SetHeader(`# ===========================================
# Ingress Enumeration & Testing Commands
# ===========================================`)

	if globals.KubeContext != "" {
		loot.Section("Ingress-Commands").AddBlank().Addf("kubectl config use-context %s", globals.KubeContext)
	}

	loot.Section("Ingress-Commands").AddBlank().
		Add("# List all ingresses:").
		Add("kubectl get ingress -A").
		Add("kubectl get ingress -A -o wide").
		AddBlank().
		Add("# Describe specific ingress:").
		Add("kubectl describe ingress <name> -n <namespace>").
		AddBlank().
		Add("# Get ingress YAML:").
		Add("kubectl get ingress <name> -n <namespace> -o yaml")

	for _, ing := range allIngresses {
		ns := ing.Namespace
		finding := IngressFinding{
			Namespace:   ns,
			Name:        ing.Name,
			Annotations: ing.Annotations,
		}

			ingressClass := "<NONE>"
			if ing.Spec.IngressClassName != nil {
				ingressClass = *ing.Spec.IngressClassName
			} else if class, ok := ing.Annotations["kubernetes.io/ingress.class"]; ok {
				ingressClass = class
			}
			finding.IngressClass = ingressClass

			// Process ingress rules
			for _, rule := range ing.Spec.Rules {
				if rule.Host != "" {
					finding.Hosts = append(finding.Hosts, rule.Host)
				}

				if rule.HTTP != nil {
					for _, path := range rule.HTTP.Paths {
						pathType := "<default>"
						if path.PathType != nil {
							pathType = string(*path.PathType)
						}
						pathStr := fmt.Sprintf("%s (%s)", path.Path, pathType)
						finding.Paths = append(finding.Paths, pathStr)

						// Extract backend service
						if path.Backend.Service != nil {
							backendStr := fmt.Sprintf("%s:%d", path.Backend.Service.Name, path.Backend.Service.Port.Number)
							finding.Backends = append(finding.Backends, backendStr)
						}
					}
				}
			}

			// Process TLS configuration
			finding.TLSEnabled = len(ing.Spec.TLS) > 0
			if finding.TLSEnabled {
				for _, tls := range ing.Spec.TLS {
					finding.TLSHosts = append(finding.TLSHosts, tls.Hosts...)

					// Add TLS extraction commands
					if tls.SecretName != "" {
						loot.Section("Ingress-Commands").
							AddBlank().
							Addf("# TLS Certificate - %s/%s", ns, ing.Name).
							Addf("kubectl get secret %s -n %s -o jsonpath='{.data.tls\\.crt}' | base64 -d | openssl x509 -text -noout", tls.SecretName, ns).
							Addf("kubectl get secret %s -n %s -o jsonpath='{.data.tls\\.crt}' | base64 -d | openssl x509 -noout -dates", tls.SecretName, ns)
					}
				}
			}

			// Get load balancer IPs/hostnames
			if ing.Status.LoadBalancer.Ingress != nil {
				for _, lb := range ing.Status.LoadBalancer.Ingress {
					if lb.IP != "" {
						finding.ExternalIPs = append(finding.ExternalIPs, lb.IP)
					}
					if lb.Hostname != "" {
						finding.ExternalIPs = append(finding.ExternalIPs, lb.Hostname)
					}
				}
			}

			// Analyze security issues
			finding.SecurityIssues, finding.DangerousAnnotations = analyzeIngressSecurity(&ing)

			// Determine exposure
			if len(finding.ExternalIPs) > 0 {
				finding.Exposure = "Internet-facing"
			} else {
				finding.Exposure = "Internal"
			}

			// Detect sensitive paths
			finding.SensitivePaths = detectSensitivePaths(&ing)
			if len(finding.SensitivePaths) > 0 {
				for _, sensPath := range finding.SensitivePaths {
					finding.SecurityIssues = append(finding.SecurityIssues, fmt.Sprintf("Sensitive path exposed: %s", sensPath))
				}
			}

			// Detect authentication
			finding.AuthEnabled, finding.AuthType = detectAuthentication(&ing)

			// Detect rate limiting
			finding.RateLimitEnabled, finding.RateLimitValue = detectRateLimiting(&ing)

			// Detect WAF
			finding.WAFEnabled, finding.WAFType = detectWAF(&ing)

			// Detect SSL redirect
			finding.SSLRedirect = detectSSLRedirect(&ing)

			// Detect IP whitelist
			finding.IPWhitelist = detectIPWhitelist(&ing)

			// Detect wildcard host
			finding.WildcardHost = detectWildcardHost(&ing)

			// Detect CORS origin
			finding.CORSOrigin = detectCORSOrigin(&ing)

			// Analyze security headers
			finding.SecurityHeaders, finding.MissingHeaders = analyzeSecurityHeaders(&ing)

			// Analyze TLS certificates using cached secrets
			finding.CertExpiry = "N/A"
			if finding.TLSEnabled {
				for _, tls := range ing.Spec.TLS {
					if tls.SecretName != "" {
						certInfo := analyzeCertificateCached(ns, tls.SecretName, secretMap)
						finding.CertExpiry = certInfo.ExpiryStatus
						finding.CertIssues = append(finding.CertIssues, certInfo.Issues...)
						break // Use first certificate for status
					}
				}
			}

			// Analyze backend security (for first backend as representative) using cached data
			finding.BackendSecurity = "Unknown"
			finding.BackendPods = 0
			finding.BackendServiceAccount = "<NONE>"
			if len(ing.Spec.Rules) > 0 {
				for _, rule := range ing.Spec.Rules {
					if rule.HTTP != nil && len(rule.HTTP.Paths) > 0 {
						for _, path := range rule.HTTP.Paths {
							if path.Backend.Service != nil {
								backendInfo := analyzeIngressBackendSecurityCached(ns, path.Backend.Service.Name, serviceMap, allPods, allNetpols)
								finding.BackendSecurity = backendInfo.SecurityLevel
								finding.BackendPods = backendInfo.PodCount
								finding.BackendServiceAccount = backendInfo.ServiceAccount
								if len(backendInfo.SecurityIssues) > 0 {
									finding.SecurityIssues = append(finding.SecurityIssues, backendInfo.SecurityIssues...)
								}
								break // Use first backend
							}
						}
						if finding.BackendSecurity != "Unknown" {
							break
						}
					}
				}
			}

			// Get default backend if configured
			if defaultBackend, ok := ing.Annotations["nginx.ingress.kubernetes.io/default-backend"]; ok {
				finding.DefaultBackend = defaultBackend
			}

			// Calculate risk level with comprehensive security factors
			finding.RiskLevel = calculateIngressRiskLevel(finding)
			riskCounts.Add(finding.RiskLevel)
			findings = append(findings, finding)

			// Generate curl test commands
			for _, host := range finding.Hosts {
				loot.Section("Ingress-Commands").
					AddBlank().
					Addf("# HTTP Test - %s/%s - Host: %s", ns, ing.Name, host)

				// HTTP test
				for _, rule := range ing.Spec.Rules {
					if rule.HTTP != nil {
						for _, p := range rule.HTTP.Paths {
							loot.Section("Ingress-Commands").Addf("curl -v http://%s%s", host, p.Path)
							if len(finding.ExternalIPs) > 0 {
								loot.Section("Ingress-Commands").Addf("curl -v -H 'Host: %s' http://%s%s", host, finding.ExternalIPs[0], p.Path)
							}
						}
					}
				}

				// HTTPS test if TLS enabled
				if finding.TLSEnabled {
					for _, rule := range ing.Spec.Rules {
						if rule.HTTP != nil {
							for _, p := range rule.HTTP.Paths {
								loot.Section("Ingress-Commands").Addf("curl -v -k https://%s%s", host, p.Path)
								if len(finding.ExternalIPs) > 0 {
									loot.Section("Ingress-Commands").Addf("curl -v -k -H 'Host: %s' https://%s%s", host, finding.ExternalIPs[0], p.Path)
								}
							}
						}
					}
				}
			}

			// Generate enumeration commands for this ingress
			loot.Section("Ingress-Commands").
				AddBlank().
				Addf("# Enumerate - %s/%s", ns, ing.Name).
				Addf("kubectl get ingress %s -n %s -o yaml", ing.Name, ns).
				Addf("kubectl describe ingress %s -n %s", ing.Name, ns)

			// Generate attack/exploit commands for NGINX ingress
			if finding.IngressClass == "nginx" || strings.Contains(strings.ToLower(finding.IngressClass), "nginx") {
				// Check for dangerous annotations
				if snippetAnnotation, ok := ing.Annotations["nginx.ingress.kubernetes.io/configuration-snippet"]; ok {
					loot.Section("Ingress-Commands").
						AddBlank().
						Addf("# CRITICAL: configuration-snippet (RCE risk) - %s/%s", ns, ing.Name).
						Addf("# Value: %s", snippetAnnotation)
				}

				if serverSnippet, ok := ing.Annotations["nginx.ingress.kubernetes.io/server-snippet"]; ok {
					loot.Section("Ingress-Commands").
						AddBlank().
						Addf("# CRITICAL: server-snippet (RCE risk) - %s/%s", ns, ing.Name).
						Addf("# Value: %s", serverSnippet)
				}

				if authURL, ok := ing.Annotations["nginx.ingress.kubernetes.io/auth-url"]; ok {
					loot.Section("Ingress-Commands").
						AddBlank().
						Addf("# Auth Bypass Test - %s/%s (auth-url: %s)", ns, ing.Name, authURL)
					for _, host := range finding.Hosts {
						loot.Section("Ingress-Commands").
							Addf("curl -v -H 'X-Original-URL: /admin' http://%s/public", host).
							Addf("curl -v -H 'X-Forwarded-For: 127.0.0.1' http://%s/admin", host)
					}
				}

				// Path traversal tests
				if len(finding.Hosts) > 0 && len(finding.DangerousAnnotations) > 0 {
					loot.Section("Ingress-Commands").
						AddBlank().
						Addf("# Path Traversal Test - %s/%s", ns, ing.Name)
					for _, host := range finding.Hosts {
						loot.Section("Ingress-Commands").
							Addf("curl -v 'http://%s/..;/admin'", host).
							Addf("curl -v 'http://%s/%%2e%%2e/admin'", host)
					}
				}
			}

			// Traefik dashboard check
			if (finding.IngressClass == "traefik" || strings.Contains(strings.ToLower(finding.IngressClass), "traefik")) && len(finding.ExternalIPs) > 0 {
				loot.Section("Ingress-Commands").
					AddBlank().
					Addf("# Traefik Dashboard Check - %s/%s", ns, ing.Name)
				for _, ip := range finding.ExternalIPs {
					loot.Section("Ingress-Commands").
						Addf("curl http://%s:8080/dashboard/", ip).
						Addf("curl http://%s:8080/api/rawdata", ip)
				}
			}

			// Format TLS
			tlsStr := "Disabled"
			if finding.TLSEnabled {
				tlsStr = "Enabled"
			}

			// Format authentication
			authStr := "None"
			if finding.AuthEnabled {
				authStr = finding.AuthType
			}

			// Format sensitive paths (no truncation)
			sensPathsStr := "None"
			if len(finding.SensitivePaths) > 0 {
				sensPathsStr = strings.Join(finding.SensitivePaths, "; ")
			}

			// Format dangerous annotations
			dangerousAnnotStr := "None"
			if len(finding.DangerousAnnotations) > 0 {
				dangerousAnnotStr = strings.Join(finding.DangerousAnnotations, ", ")
			}

			// Build table row (18 columns)
			outputRows = append(outputRows, []string{
				ns,
				ing.Name,
				ingressClass,
				strings.Join(k8sinternal.Unique(finding.Hosts), ", "),
				strings.Join(finding.ExternalIPs, ", "),
				finding.Exposure,
				tlsStr,
				finding.SSLRedirect,
				finding.CertExpiry,
				authStr,
				finding.RateLimitValue,
				finding.WAFType,
				finding.IPWhitelist,
				dangerousAnnotStr,
				finding.WildcardHost,
				finding.CORSOrigin,
				sensPathsStr,
				finding.BackendSecurity,
			})
	}

	table := internal.TableFile{
		Name:   "Ingress",
		Header: headers,
		Body:   outputRows,
	}

	lootFiles := loot.Build()

	err = internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"Ingress",
		globals.ClusterName,
		"results",
		IngressOutput{
			Table: []internal.TableFile{table},
			Loot:  lootFiles,
		},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_INGRESS_MODULE_NAME)
		return
	}

	if len(outputRows) > 0 {
		logger.InfoM(fmt.Sprintf("%d ingress resources found | Risk: CRITICAL=%d, HIGH=%d, MEDIUM=%d, LOW=%d",
			len(outputRows),
			riskCounts.Critical, riskCounts.High, riskCounts.Medium, riskCounts.Low),
			globals.K8S_INGRESS_MODULE_NAME)
	} else {
		logger.InfoM("No ingress resources found, skipping output file creation", globals.K8S_INGRESS_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_INGRESS_MODULE_NAME), globals.K8S_INGRESS_MODULE_NAME)
}

// ====================
// Helper Functions
// ====================

// Sensitive paths that should be protected
var sensitivePaths = map[string]string{
	"/admin":         "Admin panel",
	"/admin/":        "Admin panel",
	"/administrator": "Admin panel",
	"/debug":         "Debug endpoints",
	"/debug/":        "Debug endpoints",
	"/debug/pprof":   "Go pprof profiling",
	"/metrics":       "Metrics exposure",
	"/actuator":      "Spring Boot actuator",
	"/actuator/":     "Spring Boot actuator",
	"/.git":          "Git repository exposure",
	"/.git/":         "Git repository exposure",
	"/.env":          "Environment file exposure",
	"/.env.":         "Environment file exposure",
	"/graphql":       "GraphQL endpoint",
	"/graphiql":      "GraphQL IDE",
	"/swagger":       "API documentation",
	"/swagger-ui":    "Swagger UI",
	"/api-docs":      "API documentation",
	"/api/v1":        "API v1 endpoints",
	"/__debug":       "Debug toolbar",
	"/server-status": "Server status",
	"/phpinfo":       "PHP info page",
	"/config":        "Config endpoints",
	"/console":       "Admin console",
	"/health":        "Health check (info leak)",
	"/status":        "Status page (info leak)",
	"/api/swagger":   "Swagger API docs",
}

// detectSensitivePaths identifies sensitive paths in ingress rules
func detectSensitivePaths(ing *networkingv1.Ingress) []string {
	var detected []string
	seenPaths := make(map[string]bool)

	for _, rule := range ing.Spec.Rules {
		if rule.HTTP != nil {
			for _, path := range rule.HTTP.Paths {
				pathStr := path.Path
				for sensPath, desc := range sensitivePaths {
					if strings.HasPrefix(pathStr, sensPath) || pathStr == sensPath {
						detectionKey := fmt.Sprintf("%s (%s)", pathStr, desc)
						if !seenPaths[detectionKey] {
							detected = append(detected, detectionKey)
							seenPaths[detectionKey] = true
						}
					}
				}
			}
		}
	}
	return detected
}

// analyzeCertificateCached validates TLS certificate from cached secrets
func analyzeCertificateCached(namespace string, secretName string, secretMap map[string]corev1.Secret) CertificateInfo {
	certInfo := CertificateInfo{
		SecretName:   secretName,
		Namespace:    namespace,
		ExpiryStatus: "Unknown",
		KeyStrength:  "Unknown",
	}

	secret, found := secretMap[fmt.Sprintf("%s/%s", namespace, secretName)]
	if !found {
		certInfo.Issues = append(certInfo.Issues, "Cannot find secret in cache")
		return certInfo
	}

	// Get certificate data
	certData, ok := secret.Data["tls.crt"]
	if !ok {
		certInfo.Issues = append(certInfo.Issues, "No tls.crt in secret")
		return certInfo
	}

	// Parse PEM certificate
	block, _ := pem.Decode(certData)
	if block == nil {
		certInfo.Issues = append(certInfo.Issues, "Failed to parse PEM certificate")
		return certInfo
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		certInfo.Issues = append(certInfo.Issues, fmt.Sprintf("Failed to parse certificate: %v", err))
		return certInfo
	}

	// Check expiry
	now := time.Now()
	daysUntilExpiry := int(cert.NotAfter.Sub(now).Hours() / 24)
	certInfo.DaysUntilExpiry = daysUntilExpiry

	if cert.NotAfter.Before(now) {
		certInfo.ExpiryStatus = "Expired"
		certInfo.Issues = append(certInfo.Issues, fmt.Sprintf("Certificate expired %d days ago", -daysUntilExpiry))
	} else if daysUntilExpiry <= 30 {
		certInfo.ExpiryStatus = "Expiring Soon (<30d)"
		certInfo.Issues = append(certInfo.Issues, fmt.Sprintf("Certificate expires in %d days", daysUntilExpiry))
	} else {
		certInfo.ExpiryStatus = "Valid"
	}

	// Check key strength
	if cert.PublicKeyAlgorithm == x509.RSA {
		if pubKey, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			keySize := pubKey.N.BitLen()
			if keySize >= 2048 {
				certInfo.KeyStrength = fmt.Sprintf("RSA-%d (Strong)", keySize)
			} else {
				certInfo.KeyStrength = fmt.Sprintf("RSA-%d (Weak)", keySize)
				certInfo.Issues = append(certInfo.Issues, fmt.Sprintf("Weak RSA key (%d bits, recommend >= 2048)", keySize))
			}
		} else {
			certInfo.KeyStrength = "RSA (Unknown)"
		}
	} else if cert.PublicKeyAlgorithm == x509.ECDSA {
		certInfo.KeyStrength = "ECDSA (Strong)"
	}

	// Check if self-signed
	if cert.Issuer.String() == cert.Subject.String() {
		certInfo.IsSelfSigned = true
		certInfo.Issues = append(certInfo.Issues, "Self-signed certificate")
	}

	certInfo.Subject = cert.Subject.String()
	certInfo.Issuer = cert.Issuer.String()

	return certInfo
}

// analyzeIngressBackendSecurityCached analyzes backend service security using cached data
func analyzeIngressBackendSecurityCached(namespace string, serviceName string, serviceMap map[string]corev1.Service, allPods []corev1.Pod, allNetpols []networkingv1.NetworkPolicy) BackendSecurityInfo {
	backendInfo := BackendSecurityInfo{
		ServiceName:   serviceName,
		Namespace:     namespace,
		SecurityLevel: "Unknown",
	}

	// Get service from cache
	svc, found := serviceMap[fmt.Sprintf("%s/%s", namespace, serviceName)]
	if !found {
		backendInfo.SecurityIssues = append(backendInfo.SecurityIssues, "Cannot find service in cache")
		return backendInfo
	}

	// Get pods behind service from cached pods
	var matchingPods []corev1.Pod
	for _, pod := range allPods {
		if pod.Namespace != namespace {
			continue
		}
		// Check if pod matches service selector
		if len(svc.Spec.Selector) > 0 {
			matches := true
			for k, v := range svc.Spec.Selector {
				if pod.Labels[k] != v {
					matches = false
					break
				}
			}
			if matches {
				matchingPods = append(matchingPods, pod)
			}
		}
	}

	backendInfo.PodCount = len(matchingPods)

	// Analyze pod security
	for _, pod := range matchingPods {
		if backendInfo.ServiceAccount == "" {
			backendInfo.ServiceAccount = pod.Spec.ServiceAccountName
			if backendInfo.ServiceAccount == "" {
				backendInfo.ServiceAccount = "default"
			}
		}

		// Check for privileged containers
		for _, container := range pod.Spec.Containers {
			if container.SecurityContext != nil && container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
				backendInfo.Privileged = true
				backendInfo.SecurityIssues = append(backendInfo.SecurityIssues, "Privileged container detected")
			}
		}

		// Check for host network
		if pod.Spec.HostNetwork {
			backendInfo.HostNetwork = true
			backendInfo.SecurityIssues = append(backendInfo.SecurityIssues, "Host network enabled")
		}
	}

	// Check for network policies in namespace from cached netpols
	hasNetpol := false
	for _, np := range allNetpols {
		if np.Namespace == namespace {
			hasNetpol = true
			break
		}
	}
	if hasNetpol {
		backendInfo.HasNetworkPolicy = true
	} else {
		backendInfo.SecurityIssues = append(backendInfo.SecurityIssues, "No network policy")
	}

	// Determine security level
	if backendInfo.Privileged || backendInfo.HostNetwork {
		backendInfo.SecurityLevel = "Vulnerable"
	} else if backendInfo.HasNetworkPolicy && backendInfo.ServiceAccount != "default" {
		backendInfo.SecurityLevel = "Secure"
	} else {
		backendInfo.SecurityLevel = "Unknown"
	}

	return backendInfo
}

// detectAuthentication checks for authentication annotations
func detectAuthentication(ing *networkingv1.Ingress) (bool, string) {
	annotations := ing.Annotations

	// NGINX auth
	if authType, ok := annotations["nginx.ingress.kubernetes.io/auth-type"]; ok {
		return true, authType
	}

	// Traefik auth
	if _, ok := annotations["traefik.ingress.kubernetes.io/auth-type"]; ok {
		return true, "traefik-auth"
	}

	// OAuth2-proxy
	if _, ok := annotations["nginx.ingress.kubernetes.io/auth-signin"]; ok {
		return true, "oauth2-proxy"
	}

	// External auth
	if _, ok := annotations["nginx.ingress.kubernetes.io/auth-url"]; ok {
		return true, "external-auth"
	}

	return false, "none"
}

// detectRateLimiting checks for rate limiting annotations and returns the value
func detectRateLimiting(ing *networkingv1.Ingress) (bool, string) {
	annotations := ing.Annotations

	// NGINX rate limiting
	if rps, ok := annotations["nginx.ingress.kubernetes.io/limit-rps"]; ok {
		return true, rps + " rps"
	}
	if rpm, ok := annotations["nginx.ingress.kubernetes.io/limit-rpm"]; ok {
		return true, rpm + " rpm"
	}
	if conn, ok := annotations["nginx.ingress.kubernetes.io/limit-connections"]; ok {
		return true, conn + " conn"
	}

	// Traefik rate limiting
	if val, ok := annotations["traefik.ingress.kubernetes.io/ratelimit"]; ok {
		return true, val
	}

	return false, "None"
}

// detectWAF checks for WAF/ModSecurity annotations and returns the type
func detectWAF(ing *networkingv1.Ingress) (bool, string) {
	annotations := ing.Annotations

	// OWASP ModSecurity CRS (check first as it's more specific)
	if owasp, ok := annotations["nginx.ingress.kubernetes.io/enable-owasp-modsecurity-crs"]; ok {
		if owasp == "true" {
			return true, "OWASP CRS"
		}
	}

	// ModSecurity
	if modsec, ok := annotations["nginx.ingress.kubernetes.io/enable-modsecurity"]; ok {
		if modsec == "true" {
			return true, "ModSecurity"
		}
	}

	return false, "None"
}

// detectSSLRedirect checks if SSL redirect is enabled
func detectSSLRedirect(ing *networkingv1.Ingress) string {
	annotations := ing.Annotations

	// Check ssl-redirect annotation
	if sslRedirect, ok := annotations["nginx.ingress.kubernetes.io/ssl-redirect"]; ok {
		if sslRedirect == "false" {
			return "Disabled"
		}
		return "Enabled"
	}

	// Check force-ssl-redirect annotation
	if forceSSL, ok := annotations["nginx.ingress.kubernetes.io/force-ssl-redirect"]; ok {
		if forceSSL == "true" {
			return "Enabled"
		}
	}

	// Default behavior depends on TLS config - if TLS is configured, redirect is usually enabled by default
	if len(ing.Spec.TLS) > 0 {
		return "Enabled"
	}

	return "Disabled"
}

// detectIPWhitelist returns the IP whitelist range if configured
func detectIPWhitelist(ing *networkingv1.Ingress) string {
	annotations := ing.Annotations

	// NGINX whitelist
	if whitelist, ok := annotations["nginx.ingress.kubernetes.io/whitelist-source-range"]; ok {
		return whitelist
	}

	// Traefik whitelist
	if whitelist, ok := annotations["traefik.ingress.kubernetes.io/whitelist-source-range"]; ok {
		return whitelist
	}

	return "None"
}

// detectWildcardHost returns the wildcard host if any
func detectWildcardHost(ing *networkingv1.Ingress) string {
	for _, rule := range ing.Spec.Rules {
		if strings.HasPrefix(rule.Host, "*") {
			return rule.Host
		}
	}
	return "None"
}

// detectCORSOrigin returns the CORS origin configuration
func detectCORSOrigin(ing *networkingv1.Ingress) string {
	annotations := ing.Annotations

	if corsOrigin, ok := annotations["nginx.ingress.kubernetes.io/cors-allow-origin"]; ok {
		return corsOrigin
	}

	// Check if CORS is enabled but no origin specified
	if corsEnabled, ok := annotations["nginx.ingress.kubernetes.io/enable-cors"]; ok {
		if corsEnabled == "true" {
			return "*" // Default when enabled without specific origin
		}
	}

	return "None"
}

// analyzeSecurityHeaders checks for security headers
func analyzeSecurityHeaders(ing *networkingv1.Ingress) ([]string, []string) {
	var present []string
	var missing []string

	annotations := ing.Annotations

	// HSTS
	if hsts, ok := annotations["nginx.ingress.kubernetes.io/hsts"]; ok {
		if hsts != "false" {
			present = append(present, "HSTS")
		}
	} else {
		missing = append(missing, "HSTS")
	}

	// Check configuration-snippet for security headers
	if snippet, ok := annotations["nginx.ingress.kubernetes.io/configuration-snippet"]; ok {
		if strings.Contains(snippet, "X-Frame-Options") {
			present = append(present, "X-Frame-Options")
		}
		if strings.Contains(snippet, "Content-Security-Policy") {
			present = append(present, "CSP")
		}
		if strings.Contains(snippet, "X-Content-Type-Options") {
			present = append(present, "X-Content-Type-Options")
		}
	}

	// Common missing headers
	requiredHeaders := []string{"X-Frame-Options", "X-Content-Type-Options", "CSP"}
	for _, header := range requiredHeaders {
		found := false
		for _, p := range present {
			if p == header {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, header)
		}
	}

	return present, missing
}

func analyzeIngressSecurity(ing *networkingv1.Ingress) ([]string, []string) {
	var securityIssues []string
	var dangerousAnnotations []string

	// Check for dangerous NGINX annotations
	dangerousNginxAnnotations := []string{
		"nginx.ingress.kubernetes.io/configuration-snippet",
		"nginx.ingress.kubernetes.io/server-snippet",
		"nginx.ingress.kubernetes.io/auth-snippet",
		"nginx.ingress.kubernetes.io/lua-resty-waf",
	}

	for _, annot := range dangerousNginxAnnotations {
		if _, ok := ing.Annotations[annot]; ok {
			dangerousAnnotations = append(dangerousAnnotations, annot)
			securityIssues = append(securityIssues, fmt.Sprintf("Dangerous annotation: %s (RCE risk)", annot))
		}
	}

	// Check for external auth bypasses
	if authURL, ok := ing.Annotations["nginx.ingress.kubernetes.io/auth-url"]; ok {
		if !strings.HasPrefix(authURL, "https://") {
			securityIssues = append(securityIssues, "External auth URL not HTTPS (credential theft risk)")
		}
	}

	// Check for missing TLS
	if len(ing.Spec.TLS) == 0 {
		securityIssues = append(securityIssues, "No TLS configured")
	}

	// Check for wildcard hosts
	for _, rule := range ing.Spec.Rules {
		if strings.HasPrefix(rule.Host, "*") {
			securityIssues = append(securityIssues, fmt.Sprintf("Wildcard host: %s", rule.Host))
		}
	}

	// Check for CORS annotations
	if corsOrigin, ok := ing.Annotations["nginx.ingress.kubernetes.io/cors-allow-origin"]; ok {
		if corsOrigin == "*" {
			securityIssues = append(securityIssues, "CORS allows all origins (*)")
		}
	}

	// Check for allow-snippet-annotations
	if allowSnippets, ok := ing.Annotations["nginx.ingress.kubernetes.io/allow-snippet-annotations"]; ok {
		if allowSnippets == "true" {
			securityIssues = append(securityIssues, "allow-snippet-annotations enabled")
		}
	}

	// Check for SSL redirect disabled
	if sslRedirect, ok := ing.Annotations["nginx.ingress.kubernetes.io/ssl-redirect"]; ok {
		if sslRedirect == "false" {
			securityIssues = append(securityIssues, "SSL redirect disabled")
		}
	}

	// Check for force-ssl-redirect disabled
	if forceSSL, ok := ing.Annotations["nginx.ingress.kubernetes.io/force-ssl-redirect"]; ok {
		if forceSSL == "false" {
			securityIssues = append(securityIssues, "Force SSL redirect disabled")
		}
	}

	// Check for authentication
	hasAuth, _ := detectAuthentication(ing)
	if !hasAuth {
		securityIssues = append(securityIssues, "No authentication configured")
	}

	// Check for rate limiting
	hasRateLimit, _ := detectRateLimiting(ing)
	if !hasRateLimit {
		securityIssues = append(securityIssues, "No rate limiting configured")
	}

	// Check for WAF
	hasWAF, _ := detectWAF(ing)
	if !hasWAF {
		securityIssues = append(securityIssues, "No WAF/ModSecurity enabled")
	}

	// Check for client body size (DoS risk)
	if bodySize, ok := ing.Annotations["nginx.ingress.kubernetes.io/client-max-body-size"]; ok {
		if strings.Contains(strings.ToLower(bodySize), "g") {
			securityIssues = append(securityIssues, fmt.Sprintf("Large client body size: %s (DoS risk)", bodySize))
		}
	}

	// Check for proxy buffer size
	if bufferSize, ok := ing.Annotations["nginx.ingress.kubernetes.io/proxy-buffer-size"]; ok {
		securityIssues = append(securityIssues, fmt.Sprintf("Custom proxy buffer: %s (review for overflow)", bufferSize))
	}

	// Check for whitelist source range
	if _, hasWhitelist := ing.Annotations["nginx.ingress.kubernetes.io/whitelist-source-range"]; !hasWhitelist {
		securityIssues = append(securityIssues, "No IP whitelist (accepts all sources)")
	}

	// Check for custom error pages
	if customErrors, ok := ing.Annotations["nginx.ingress.kubernetes.io/custom-http-errors"]; ok {
		if strings.Contains(customErrors, "404") || strings.Contains(customErrors, "500") {
			// This is actually good, but note it
		}
	}

	// Check for default backend
	if defaultBackend, ok := ing.Annotations["nginx.ingress.kubernetes.io/default-backend"]; ok {
		if defaultBackend != "" {
			securityIssues = append(securityIssues, fmt.Sprintf("Custom default backend: %s", defaultBackend))
		}
	}

	// Traefik-specific checks
	if _, ok := ing.Annotations["traefik.ingress.kubernetes.io/redirect-regex"]; ok {
		securityIssues = append(securityIssues, "Traefik redirect-regex (open redirect risk)")
	}

	// HAProxy-specific checks
	if _, ok := ing.Annotations["haproxy.org/backend-config-snippet"]; ok {
		dangerousAnnotations = append(dangerousAnnotations, "haproxy.org/backend-config-snippet")
		securityIssues = append(securityIssues, "HAProxy backend-config-snippet (injection risk)")
	}

	// Kong-specific checks
	if plugins, ok := ing.Annotations["konghq.com/plugins"]; ok {
		if plugins != "" {
			securityIssues = append(securityIssues, fmt.Sprintf("Kong plugins configured: %s (review config)", plugins))
		}
	}

	return securityIssues, dangerousAnnotations
}

func calculateIngressRiskLevel(finding IngressFinding) string {
	riskScore := 0
	criticalFactors := []string{}
	highFactors := []string{}

	// CRITICAL FACTORS (30+ points each)
	if len(finding.DangerousAnnotations) > 0 && finding.Exposure == "Internet-facing" {
		riskScore += 100
		criticalFactors = append(criticalFactors, "Dangerous annotations + Internet-facing")
	}

	if len(finding.SensitivePaths) > 0 && !finding.AuthEnabled && finding.Exposure == "Internet-facing" {
		riskScore += 50
		criticalFactors = append(criticalFactors, "Unauthenticated sensitive paths exposed to Internet")
	}

	if finding.CertExpiry == "Expired" && finding.Exposure == "Internet-facing" {
		riskScore += 40
		criticalFactors = append(criticalFactors, "Expired certificate on Internet-facing ingress")
	}

	if finding.BackendSecurity == "Vulnerable" && finding.Exposure == "Internet-facing" {
		riskScore += 35
		criticalFactors = append(criticalFactors, "Vulnerable backend + Internet-facing")
	}

	// HIGH FACTORS (15-25 points each)
	if len(finding.DangerousAnnotations) > 0 {
		riskScore += 25
		highFactors = append(highFactors, "Dangerous annotations present")
	}

	if !finding.TLSEnabled && finding.Exposure == "Internet-facing" {
		riskScore += 25
		highFactors = append(highFactors, "No TLS on Internet-facing ingress")
	}

	if !finding.AuthEnabled && finding.Exposure == "Internet-facing" {
		riskScore += 20
		highFactors = append(highFactors, "No authentication on Internet-facing ingress")
	}

	if finding.CertExpiry == "Expiring Soon (<30d)" {
		riskScore += 15
		highFactors = append(highFactors, "Certificate expiring soon")
	}

	if len(finding.SensitivePaths) > 0 && !finding.AuthEnabled {
		riskScore += 15
		highFactors = append(highFactors, "Unauthenticated sensitive paths")
	}

	// MEDIUM FACTORS (5-10 points each)
	if !finding.RateLimitEnabled && finding.Exposure == "Internet-facing" {
		riskScore += 10
	}

	if !finding.WAFEnabled && finding.Exposure == "Internet-facing" {
		riskScore += 10
	}

	if !finding.TLSEnabled {
		riskScore += 8
	}

	if finding.BackendSecurity == "Vulnerable" {
		riskScore += 8
	}

	if len(finding.SensitivePaths) > 0 {
		riskScore += 5
	}

	// LOW FACTORS (1-3 points each)
	if !finding.AuthEnabled {
		riskScore += 3
	}

	if !finding.RateLimitEnabled {
		riskScore += 2
	}

	if !finding.WAFEnabled {
		riskScore += 2
	}

	// Count general security issues
	riskScore += len(finding.SecurityIssues)

	// Determine risk level based on score
	if riskScore >= 50 {
		return shared.RiskCritical
	} else if riskScore >= 25 {
		return shared.RiskHigh
	} else if riskScore >= 10 {
		return shared.RiskMedium
	}

	return shared.RiskLow
}
