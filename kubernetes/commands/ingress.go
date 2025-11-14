package commands

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	k8sinternal "github.com/BishopFox/cloudfox/internal/kubernetes"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
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

	// New security analysis fields
	AuthEnabled           bool
	AuthType              string
	RateLimitEnabled      bool
	WAFEnabled            bool
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

// BackendSecurityInfo contains backend service security analysis
type BackendSecurityInfo struct {
	ServiceName      string
	Namespace        string
	SecurityLevel    string // "Secure", "Vulnerable", "Unknown"
	PodCount         int
	ServiceAccount   string
	HasNetworkPolicy bool
	Privileged       bool
	HostNetwork      bool
	SecurityIssues   []string
}

func ListIngress(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating ingress resources for %s", globals.ClusterName), globals.K8S_INGRESS_MODULE_NAME)

	clientset := config.GetClientOrExit()

	namespaces, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing namespaces: %v", err), globals.K8S_INGRESS_MODULE_NAME)
		return
	}

	headers := []string{
		"Risk",
		"Namespace",
		"Ingress Name",
		"Exposure",
		"Security Issues",
		"Hosts",
		"TLS Status",
		"Cert Expiry",
		"Authentication",
		"Rate Limit",
		"WAF",
		"Sensitive Paths",
		"Backend Security",
		"Ingress Class",
		"External IPs",
	}

	var outputRows [][]string
	var findings []IngressFinding

	// Risk level counters
	riskCounts := map[string]int{
		"CRITICAL": 0,
		"HIGH":     0,
		"MEDIUM":   0,
		"LOW":      0,
	}

	var lootCurl []string
	var lootTLS []string
	var lootEnum []string
	var lootExploit []string
	var lootSecurityIssues []string
	var lootRiskDashboard []string
	var lootBackendSecurity []string
	var lootCertificateReport []string
	var lootAuthBypass []string
	var lootSensitivePaths []string

	lootCurl = append(lootCurl, `#####################################
##### HTTP/HTTPS Endpoint Testing
#####################################
#
# Test exposed ingress endpoints
# Replace <host> with actual hostname or use /etc/hosts entry
#
`)

	lootTLS = append(lootTLS, `#####################################
##### TLS Certificate Extraction
#####################################
#
# Extract and analyze TLS certificates
#
`)

	lootEnum = append(lootEnum, `#####################################
##### Ingress Enumeration
#####################################
#
# Deep enumeration of ingress configurations
#
`)

	lootExploit = append(lootExploit, `#####################################
##### Ingress Attack Vectors
#####################################
#
# MANUAL EXECUTION REQUIRED
# Common ingress exploitation techniques
#
`)

	lootSecurityIssues = append(lootSecurityIssues, `#####################################
##### Ingress Security Issues
#####################################
#
# CRITICAL SECURITY ISSUES
# Dangerous configurations and vulnerabilities in ingress resources
#
`)

	if globals.KubeContext != "" {
		lootEnum = append(lootEnum, fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext))
	}

	for _, ns := range namespaces.Items {
		ingresses, err := clientset.NetworkingV1().Ingresses(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			logger.ErrorM(fmt.Sprintf("Error listing ingresses in namespace %s: %v", ns.Name, err), globals.K8S_INGRESS_MODULE_NAME)
			continue
		}

		for _, ing := range ingresses.Items {
			finding := IngressFinding{
				Namespace:   ns.Name,
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
						lootTLS = append(lootTLS, fmt.Sprintf("\n# Ingress: %s/%s", ns.Name, ing.Name))
						lootTLS = append(lootTLS, fmt.Sprintf("kubectl get secret %s -n %s -o jsonpath='{.data.tls\\.crt}' | base64 -d | openssl x509 -text -noout", tls.SecretName, ns.Name))
						lootTLS = append(lootTLS, fmt.Sprintf("kubectl get secret %s -n %s -o jsonpath='{.data.tls\\.crt}' | base64 -d | openssl x509 -noout -dates", tls.SecretName, ns.Name))
						lootTLS = append(lootTLS, fmt.Sprintf("kubectl get secret %s -n %s -o jsonpath='{.data.tls\\.crt}' | base64 -d | openssl x509 -noout -subject -issuer", tls.SecretName, ns.Name))
						lootTLS = append(lootTLS, "")
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
			finding.RateLimitEnabled = detectRateLimiting(&ing)

			// Detect WAF
			finding.WAFEnabled = detectWAF(&ing)

			// Analyze security headers
			finding.SecurityHeaders, finding.MissingHeaders = analyzeSecurityHeaders(&ing)

			// Analyze TLS certificates
			finding.CertExpiry = "N/A"
			if finding.TLSEnabled {
				for _, tls := range ing.Spec.TLS {
					if tls.SecretName != "" {
						certInfo := analyzeCertificate(ctx, clientset, ns.Name, tls.SecretName)
						finding.CertExpiry = certInfo.ExpiryStatus
						finding.CertIssues = append(finding.CertIssues, certInfo.Issues...)
						break // Use first certificate for status
					}
				}
			}

			// Analyze backend security (for first backend as representative)
			finding.BackendSecurity = "Unknown"
			finding.BackendPods = 0
			finding.BackendServiceAccount = "<NONE>"
			if len(ing.Spec.Rules) > 0 {
				for _, rule := range ing.Spec.Rules {
					if rule.HTTP != nil && len(rule.HTTP.Paths) > 0 {
						for _, path := range rule.HTTP.Paths {
							if path.Backend.Service != nil {
								backendInfo := analyzeBackendSecurity(ctx, clientset, ns.Name, path.Backend.Service.Name)
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
			riskCounts[finding.RiskLevel]++
			findings = append(findings, finding)

			// Generate curl test commands
			for _, host := range finding.Hosts {
				lootCurl = append(lootCurl, fmt.Sprintf("\n# [%s] Ingress: %s/%s - Host: %s", finding.RiskLevel, ns.Name, ing.Name, host))

				// HTTP test
				for _, rule := range ing.Spec.Rules {
					if rule.HTTP != nil {
						for _, p := range rule.HTTP.Paths {
							lootCurl = append(lootCurl, fmt.Sprintf("curl -v http://%s%s", host, p.Path))
							if len(finding.ExternalIPs) > 0 {
								lootCurl = append(lootCurl, fmt.Sprintf("curl -v -H 'Host: %s' http://%s%s", host, finding.ExternalIPs[0], p.Path))
							}
						}
					}
				}

				// HTTPS test if TLS enabled
				if finding.TLSEnabled {
					for _, rule := range ing.Spec.Rules {
						if rule.HTTP != nil {
							for _, p := range rule.HTTP.Paths {
								lootCurl = append(lootCurl, fmt.Sprintf("curl -v -k https://%s%s", host, p.Path))
								if len(finding.ExternalIPs) > 0 {
									lootCurl = append(lootCurl, fmt.Sprintf("curl -v -k -H 'Host: %s' https://%s%s", host, finding.ExternalIPs[0], p.Path))
								}
							}
						}
					}
				}
				lootCurl = append(lootCurl, "")
			}

			// Generate enumeration commands
			lootEnum = append(lootEnum, fmt.Sprintf("\n# [%s] %s/%s", finding.RiskLevel, ns.Name, ing.Name))
			lootEnum = append(lootEnum, fmt.Sprintf("kubectl get ingress %s -n %s -o yaml", ing.Name, ns.Name))
			lootEnum = append(lootEnum, fmt.Sprintf("kubectl describe ingress %s -n %s", ing.Name, ns.Name))
			lootEnum = append(lootEnum, "")

			// Generate security issue details
			if len(finding.SecurityIssues) > 0 {
				lootSecurityIssues = append(lootSecurityIssues, fmt.Sprintf("\n### [%s] %s/%s", finding.RiskLevel, ns.Name, ing.Name))
				lootSecurityIssues = append(lootSecurityIssues, fmt.Sprintf("# Exposure: %s", finding.Exposure))
				lootSecurityIssues = append(lootSecurityIssues, "# Security Issues:")
				for _, issue := range finding.SecurityIssues {
					lootSecurityIssues = append(lootSecurityIssues, fmt.Sprintf("#   - %s", issue))
				}
				lootSecurityIssues = append(lootSecurityIssues, "")
			}

			// Generate exploit/attack commands
			if finding.IngressClass == "nginx" || strings.Contains(strings.ToLower(finding.IngressClass), "nginx") {
				if len(finding.DangerousAnnotations) > 0 || len(finding.SecurityIssues) > 0 {
					lootExploit = append(lootExploit, fmt.Sprintf("\n### [%s] NGINX Ingress: %s/%s", finding.RiskLevel, ns.Name, ing.Name))
				}

				// Check for dangerous annotations
				if snippetAnnotation, ok := ing.Annotations["nginx.ingress.kubernetes.io/configuration-snippet"]; ok {
					lootExploit = append(lootExploit, fmt.Sprintf("# CRITICAL: configuration-snippet annotation (RCE risk):"))
					lootExploit = append(lootExploit, fmt.Sprintf("# Value: %s", snippetAnnotation))
					lootExploit = append(lootExploit, "# This annotation can be exploited for RCE if you can create/modify ingress resources")
					lootExploit = append(lootExploit, "")
				}

				if serverSnippet, ok := ing.Annotations["nginx.ingress.kubernetes.io/server-snippet"]; ok {
					lootExploit = append(lootExploit, fmt.Sprintf("# CRITICAL: server-snippet annotation (RCE risk):"))
					lootExploit = append(lootExploit, fmt.Sprintf("# Value: %s", serverSnippet))
					lootExploit = append(lootExploit, "")
				}

				if authURL, ok := ing.Annotations["nginx.ingress.kubernetes.io/auth-url"]; ok {
					lootExploit = append(lootExploit, fmt.Sprintf("# External auth URL: %s", authURL))
					lootExploit = append(lootExploit, "# Test authentication bypass:")
					for _, host := range finding.Hosts {
						lootExploit = append(lootExploit, fmt.Sprintf("curl -v -H 'X-Original-URL: /admin' http://%s/public", host))
						lootExploit = append(lootExploit, fmt.Sprintf("curl -v -H 'X-Original-Method: GET' http://%s/", host))
					}
					lootExploit = append(lootExploit, "")
				}

				// Path traversal tests
				if len(finding.Hosts) > 0 {
					lootExploit = append(lootExploit, "# Test for path traversal:")
					for _, host := range finding.Hosts {
						lootExploit = append(lootExploit, fmt.Sprintf("curl -v 'http://%s/..;/admin'", host))
						lootExploit = append(lootExploit, fmt.Sprintf("curl -v 'http://%s/..%%2f..%%2f..%%2fetc/passwd'", host))
						lootExploit = append(lootExploit, fmt.Sprintf("curl -v 'http://%s/%%2e%%2e/admin'", host))
					}
					lootExploit = append(lootExploit, "")
				}
			}

			if finding.IngressClass == "traefik" || strings.Contains(strings.ToLower(finding.IngressClass), "traefik") {
				lootExploit = append(lootExploit, fmt.Sprintf("\n### [%s] Traefik Ingress: %s/%s", finding.RiskLevel, ns.Name, ing.Name))
				lootExploit = append(lootExploit, "# Check for exposed Traefik dashboard:")
				for _, ip := range finding.ExternalIPs {
					lootExploit = append(lootExploit, fmt.Sprintf("curl http://%s:8080/dashboard/", ip))
					lootExploit = append(lootExploit, fmt.Sprintf("curl http://%s:8080/api/rawdata", ip))
				}
				lootExploit = append(lootExploit, "")
			}

			// No TLS warning
			if !finding.TLSEnabled && finding.Exposure == "Internet-facing" {
				lootExploit = append(lootExploit, fmt.Sprintf("\n### [%s] No TLS: %s/%s", finding.RiskLevel, ns.Name, ing.Name))
				lootExploit = append(lootExploit, "# WARNING: Internet-facing ingress without TLS")
				lootExploit = append(lootExploit, "# Traffic can be intercepted and credentials stolen")
				for _, host := range finding.Hosts {
					lootExploit = append(lootExploit, fmt.Sprintf("# http://%s (unencrypted)", host))
				}
				lootExploit = append(lootExploit, "")
			}

			// Format security issues for table
			securityIssuesStr := "<none>"
			if len(finding.SecurityIssues) > 0 {
				if len(finding.SecurityIssues) > 2 {
					securityIssuesStr = strings.Join(finding.SecurityIssues[:2], "; ") + fmt.Sprintf(" (+%d more)", len(finding.SecurityIssues)-2)
				} else {
					securityIssuesStr = strings.Join(finding.SecurityIssues, "; ")
				}
			}

			tlsStr := "No"
			if finding.TLSEnabled {
				tlsStr = "Yes"
			}

			// Format authentication
			authStr := "No"
			if finding.AuthEnabled {
				authStr = finding.AuthType
			}

			// Format rate limiting
			rateLimitStr := "No"
			if finding.RateLimitEnabled {
				rateLimitStr = "Yes"
			}

			// Format WAF
			wafStr := "No"
			if finding.WAFEnabled {
				wafStr = "Yes"
			}

			// Format sensitive paths
			sensPathsStr := "<none>"
			if len(finding.SensitivePaths) > 0 {
				if len(finding.SensitivePaths) > 2 {
					sensPathsStr = fmt.Sprintf("%d detected", len(finding.SensitivePaths))
				} else {
					sensPathsStr = strings.Join(finding.SensitivePaths, "; ")
				}
			}

			// Build table row (15 columns)
			outputRows = append(outputRows, []string{
				finding.RiskLevel,
				ns.Name,
				ing.Name,
				finding.Exposure,
				securityIssuesStr,
				strings.Join(k8sinternal.Unique(finding.Hosts), ", "),
				tlsStr,
				finding.CertExpiry,
				authStr,
				rateLimitStr,
				wafStr,
				sensPathsStr,
				finding.BackendSecurity,
				ingressClass,
				strings.Join(finding.ExternalIPs, ", "),
			})
		}
	}

	// Add summaries
	if riskCounts["CRITICAL"] > 0 || riskCounts["HIGH"] > 0 {
		summary := fmt.Sprintf(`
# SUMMARY: Risk Distribution
# CRITICAL: %d ingress resources
# HIGH: %d ingress resources
# MEDIUM: %d ingress resources
# LOW: %d ingress resources
#
# Focus on CRITICAL and HIGH risk ingress resources for maximum impact.
`, riskCounts["CRITICAL"], riskCounts["HIGH"], riskCounts["MEDIUM"], riskCounts["LOW"])

		lootSecurityIssues = append([]string{summary}, lootSecurityIssues...)
		lootExploit = append([]string{summary}, lootExploit...)
	}

	// Build Risk Dashboard loot file
	lootRiskDashboard = append(lootRiskDashboard, `#####################################
##### Ingress Risk Statistics Dashboard
#####################################
#
# Summary of ingress security posture
#
`)
	totalIngresses := riskCounts["CRITICAL"] + riskCounts["HIGH"] + riskCounts["MEDIUM"] + riskCounts["LOW"]
	lootRiskDashboard = append(lootRiskDashboard, fmt.Sprintf("\n## Overall Statistics"))
	lootRiskDashboard = append(lootRiskDashboard, fmt.Sprintf("Total Ingress Resources: %d", totalIngresses))
	lootRiskDashboard = append(lootRiskDashboard, fmt.Sprintf("CRITICAL Risk: %d", riskCounts["CRITICAL"]))
	lootRiskDashboard = append(lootRiskDashboard, fmt.Sprintf("HIGH Risk:     %d", riskCounts["HIGH"]))
	lootRiskDashboard = append(lootRiskDashboard, fmt.Sprintf("MEDIUM Risk:   %d", riskCounts["MEDIUM"]))
	lootRiskDashboard = append(lootRiskDashboard, fmt.Sprintf("LOW Risk:      %d", riskCounts["LOW"]))

	// Count various security metrics
	internetFacingCount := 0
	noAuthCount := 0
	noTLSCount := 0
	noRateLimitCount := 0
	noWAFCount := 0
	sensPathCount := 0
	expiredCertCount := 0

	for _, finding := range findings {
		if finding.Exposure == "Internet-facing" {
			internetFacingCount++
		}
		if !finding.AuthEnabled {
			noAuthCount++
		}
		if !finding.TLSEnabled {
			noTLSCount++
		}
		if !finding.RateLimitEnabled {
			noRateLimitCount++
		}
		if !finding.WAFEnabled {
			noWAFCount++
		}
		if len(finding.SensitivePaths) > 0 {
			sensPathCount++
		}
		if finding.CertExpiry == "Expired" || finding.CertExpiry == "Expiring Soon (<30d)" {
			expiredCertCount++
		}
	}

	lootRiskDashboard = append(lootRiskDashboard, "\n## Security Posture")
	lootRiskDashboard = append(lootRiskDashboard, fmt.Sprintf("Internet-Facing Ingresses: %d", internetFacingCount))
	lootRiskDashboard = append(lootRiskDashboard, fmt.Sprintf("Missing Authentication: %d", noAuthCount))
	lootRiskDashboard = append(lootRiskDashboard, fmt.Sprintf("Missing TLS: %d", noTLSCount))
	lootRiskDashboard = append(lootRiskDashboard, fmt.Sprintf("Missing Rate Limiting: %d", noRateLimitCount))
	lootRiskDashboard = append(lootRiskDashboard, fmt.Sprintf("Missing WAF: %d", noWAFCount))
	lootRiskDashboard = append(lootRiskDashboard, fmt.Sprintf("Sensitive Paths Exposed: %d", sensPathCount))
	lootRiskDashboard = append(lootRiskDashboard, fmt.Sprintf("Certificate Issues: %d", expiredCertCount))

	lootRiskDashboard = append(lootRiskDashboard, "\n## Recommendations")
	if riskCounts["CRITICAL"] > 0 {
		lootRiskDashboard = append(lootRiskDashboard, fmt.Sprintf("⚠️  URGENT: %d CRITICAL ingresses require immediate remediation", riskCounts["CRITICAL"]))
	}
	if noAuthCount > 0 && internetFacingCount > 0 {
		lootRiskDashboard = append(lootRiskDashboard, fmt.Sprintf("⚠️  WARNING: %d ingresses lack authentication", noAuthCount))
	}
	if noTLSCount > 0 {
		lootRiskDashboard = append(lootRiskDashboard, fmt.Sprintf("⚠️  WARNING: %d ingresses missing TLS encryption", noTLSCount))
	}

	// Build Backend Security loot file
	lootBackendSecurity = append(lootBackendSecurity, `#####################################
##### Backend Service Security Analysis
#####################################
#
# Security assessment of services exposed by ingress
#
`)
	for _, finding := range findings {
		if finding.BackendSecurity != "Unknown" {
			lootBackendSecurity = append(lootBackendSecurity, fmt.Sprintf("\n## [%s] Ingress: %s/%s", finding.RiskLevel, finding.Namespace, finding.Name))
			lootBackendSecurity = append(lootBackendSecurity, fmt.Sprintf("Backend Security: %s", finding.BackendSecurity))
			lootBackendSecurity = append(lootBackendSecurity, fmt.Sprintf("Backend Pods: %d", finding.BackendPods))
			lootBackendSecurity = append(lootBackendSecurity, fmt.Sprintf("ServiceAccount: %s", finding.BackendServiceAccount))
			if len(finding.Backends) > 0 {
				lootBackendSecurity = append(lootBackendSecurity, fmt.Sprintf("Backends: %s", strings.Join(finding.Backends, ", ")))
			}
		}
	}

	// Build Certificate Report loot file
	lootCertificateReport = append(lootCertificateReport, `#####################################
##### TLS Certificate Report
#####################################
#
# Certificate expiry and validation status
#
`)
	for _, finding := range findings {
		if finding.TLSEnabled {
			lootCertificateReport = append(lootCertificateReport, fmt.Sprintf("\n## [%s] Ingress: %s/%s", finding.CertExpiry, finding.Namespace, finding.Name))
			lootCertificateReport = append(lootCertificateReport, fmt.Sprintf("Certificate Status: %s", finding.CertExpiry))
			if len(finding.CertIssues) > 0 {
				lootCertificateReport = append(lootCertificateReport, "Certificate Issues:")
				for _, issue := range finding.CertIssues {
					lootCertificateReport = append(lootCertificateReport, fmt.Sprintf("  - %s", issue))
				}
			}
			lootCertificateReport = append(lootCertificateReport, fmt.Sprintf("Hosts: %s", strings.Join(finding.Hosts, ", ")))
		}
	}

	// Build Authentication Bypass loot file
	lootAuthBypass = append(lootAuthBypass, `#####################################
##### Authentication Bypass Techniques
#####################################
#
# Test authentication bypass for ingresses
#
`)
	for _, finding := range findings {
		if !finding.AuthEnabled && finding.Exposure == "Internet-facing" {
			lootAuthBypass = append(lootAuthBypass, fmt.Sprintf("\n### [%s] No Auth: %s/%s", finding.RiskLevel, finding.Namespace, finding.Name))
			for _, host := range finding.Hosts {
				lootAuthBypass = append(lootAuthBypass, fmt.Sprintf("# Direct access (no auth required):"))
				lootAuthBypass = append(lootAuthBypass, fmt.Sprintf("curl -v http://%s/", host))
			}
		} else if finding.AuthEnabled && finding.AuthType == "external-auth" {
			lootAuthBypass = append(lootAuthBypass, fmt.Sprintf("\n### [%s] External Auth: %s/%s", finding.RiskLevel, finding.Namespace, finding.Name))
			lootAuthBypass = append(lootAuthBypass, "# Test header-based bypass:")
			for _, host := range finding.Hosts {
				lootAuthBypass = append(lootAuthBypass, fmt.Sprintf("curl -v -H 'X-Original-URL: /admin' http://%s/", host))
				lootAuthBypass = append(lootAuthBypass, fmt.Sprintf("curl -v -H 'X-Forwarded-For: 127.0.0.1' http://%s/admin", host))
			}
		}
	}

	// Build Sensitive Paths loot file
	lootSensitivePaths = append(lootSensitivePaths, `#####################################
##### Sensitive Paths Exposed
#####################################
#
# Admin panels, debug endpoints, and sensitive paths
#
`)
	for _, finding := range findings {
		if len(finding.SensitivePaths) > 0 {
			lootSensitivePaths = append(lootSensitivePaths, fmt.Sprintf("\n### [%s] %s/%s", finding.RiskLevel, finding.Namespace, finding.Name))
			lootSensitivePaths = append(lootSensitivePaths, fmt.Sprintf("Exposure: %s", finding.Exposure))
			lootSensitivePaths = append(lootSensitivePaths, fmt.Sprintf("Authentication: %s", finding.AuthType))
			lootSensitivePaths = append(lootSensitivePaths, "Sensitive Paths:")
			for _, path := range finding.SensitivePaths {
				lootSensitivePaths = append(lootSensitivePaths, fmt.Sprintf("  - %s", path))
			}
			if len(finding.Hosts) > 0 {
				lootSensitivePaths = append(lootSensitivePaths, fmt.Sprintf("\n# Test access:"))
				for _, host := range finding.Hosts {
					for _, sensPath := range finding.SensitivePaths {
						// Extract just the path from "path (description)" format
						pathOnly := strings.Split(sensPath, " (")[0]
						lootSensitivePaths = append(lootSensitivePaths, fmt.Sprintf("curl -v http://%s%s", host, pathOnly))
					}
				}
			}
		}
	}

	table := internal.TableFile{
		Name:   "Ingress",
		Header: headers,
		Body:   outputRows,
	}

	lootFiles := []internal.LootFile{
		{
			Name:     "Ingress-Risk-Dashboard",
			Contents: strings.Join(lootRiskDashboard, "\n"),
		},
		{
			Name:     "Ingress-Enum",
			Contents: strings.Join(lootEnum, "\n"),
		},
		{
			Name:     "Ingress-HTTP-Tests",
			Contents: strings.Join(lootCurl, "\n"),
		},
		{
			Name:     "Ingress-TLS-Extraction",
			Contents: strings.Join(lootTLS, "\n"),
		},
		{
			Name:     "Ingress-Certificate-Report",
			Contents: strings.Join(lootCertificateReport, "\n"),
		},
		{
			Name:     "Ingress-Security-Issues",
			Contents: strings.Join(lootSecurityIssues, "\n"),
		},
		{
			Name:     "Ingress-Backend-Security",
			Contents: strings.Join(lootBackendSecurity, "\n"),
		},
		{
			Name:     "Ingress-Authentication-Bypass",
			Contents: strings.Join(lootAuthBypass, "\n"),
		},
		{
			Name:     "Ingress-Sensitive-Paths",
			Contents: strings.Join(lootSensitivePaths, "\n"),
		},
		{
			Name:     "Ingress-Attack-Vectors",
			Contents: strings.Join(lootExploit, "\n"),
		},
	}

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
			riskCounts["CRITICAL"], riskCounts["HIGH"], riskCounts["MEDIUM"], riskCounts["LOW"]),
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

// analyzeCertificate validates TLS certificate from secret
func analyzeCertificate(ctx context.Context, clientset *kubernetes.Clientset, namespace string, secretName string) CertificateInfo {
	certInfo := CertificateInfo{
		SecretName:   secretName,
		Namespace:    namespace,
		ExpiryStatus: "Unknown",
		KeyStrength:  "Unknown",
	}

	secret, err := clientset.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		certInfo.Issues = append(certInfo.Issues, fmt.Sprintf("Cannot read secret: %v", err))
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
		if pubKey, ok := cert.PublicKey.(*x509.PublicKey); ok {
			_ = pubKey // Placeholder for actual RSA key size check
		}
		// Simplified key strength check
		certInfo.KeyStrength = "RSA"
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

// analyzeBackendSecurity analyzes backend service security
func analyzeBackendSecurity(ctx context.Context, clientset *kubernetes.Clientset, namespace string, serviceName string) BackendSecurityInfo {
	backendInfo := BackendSecurityInfo{
		ServiceName:   serviceName,
		Namespace:     namespace,
		SecurityLevel: "Unknown",
	}

	// Get service
	svc, err := clientset.CoreV1().Services(namespace).Get(ctx, serviceName, metav1.GetOptions{})
	if err != nil {
		backendInfo.SecurityIssues = append(backendInfo.SecurityIssues, fmt.Sprintf("Cannot read service: %v", err))
		return backendInfo
	}

	// Get pods behind service
	selector := metav1.ListOptions{}
	if len(svc.Spec.Selector) > 0 {
		var selectorParts []string
		for k, v := range svc.Spec.Selector {
			selectorParts = append(selectorParts, fmt.Sprintf("%s=%s", k, v))
		}
		selector.LabelSelector = strings.Join(selectorParts, ",")
	}

	pods, err := clientset.CoreV1().Pods(namespace).List(ctx, selector)
	if err == nil {
		backendInfo.PodCount = len(pods.Items)

		// Analyze pod security
		for _, pod := range pods.Items {
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
	}

	// Check for network policies
	netpols, err := clientset.NetworkingV1().NetworkPolicies(namespace).List(ctx, metav1.ListOptions{})
	if err == nil && len(netpols.Items) > 0 {
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

// detectRateLimiting checks for rate limiting annotations
func detectRateLimiting(ing *networkingv1.Ingress) bool {
	annotations := ing.Annotations

	// NGINX rate limiting
	rateLimitKeys := []string{
		"nginx.ingress.kubernetes.io/limit-rps",
		"nginx.ingress.kubernetes.io/limit-rpm",
		"nginx.ingress.kubernetes.io/limit-connections",
	}

	for _, key := range rateLimitKeys {
		if _, ok := annotations[key]; ok {
			return true
		}
	}

	// Traefik rate limiting
	if _, ok := annotations["traefik.ingress.kubernetes.io/ratelimit"]; ok {
		return true
	}

	return false
}

// detectWAF checks for WAF/ModSecurity annotations
func detectWAF(ing *networkingv1.Ingress) bool {
	annotations := ing.Annotations

	// ModSecurity
	if modsec, ok := annotations["nginx.ingress.kubernetes.io/enable-modsecurity"]; ok {
		if modsec == "true" {
			return true
		}
	}

	// OWASP ModSecurity CRS
	if owasp, ok := annotations["nginx.ingress.kubernetes.io/enable-owasp-modsecurity-crs"]; ok {
		if owasp == "true" {
			return true
		}
	}

	return false
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
	if !detectRateLimiting(ing) {
		securityIssues = append(securityIssues, "No rate limiting configured")
	}

	// Check for WAF
	if !detectWAF(ing) {
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
		return "CRITICAL"
	} else if riskScore >= 25 {
		return "HIGH"
	} else if riskScore >= 10 {
		return "MEDIUM"
	}

	return "LOW"
}
