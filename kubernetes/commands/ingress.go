package commands

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	k8sinternal "github.com/BishopFox/cloudfox/internal/kubernetes"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/spf13/cobra"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	Namespace         string
	Name              string
	IngressClass      string
	Hosts             []string
	Paths             []string
	Backends          []string
	TLSEnabled        bool
	TLSHosts          []string
	ExternalIPs       []string
	Annotations       map[string]string
	RiskLevel         string
	SecurityIssues    []string
	DangerousAnnotations []string
	Exposure          string
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
		"TLS",
		"Ingress Class",
		"Backend Services",
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
				Namespace:    ns.Name,
				Name:         ing.Name,
				Annotations:  ing.Annotations,
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

			// Calculate risk level
			finding.RiskLevel = calculateIngressRiskLevel(finding.DangerousAnnotations, finding.TLSEnabled, finding.Exposure, finding.SecurityIssues)
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

			// Build table row
			outputRows = append(outputRows, []string{
				finding.RiskLevel,
				ns.Name,
				ing.Name,
				finding.Exposure,
				securityIssuesStr,
				strings.Join(k8sinternal.Unique(finding.Hosts), ", "),
				tlsStr,
				ingressClass,
				strings.Join(k8sinternal.Unique(finding.Backends), ", "),
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

	table := internal.TableFile{
		Name:   "Ingress",
		Header: headers,
		Body:   outputRows,
	}

	lootFiles := []internal.LootFile{
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
			Name:     "Ingress-Security-Issues",
			Contents: strings.Join(lootSecurityIssues, "\n"),
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

func analyzeIngressSecurity(ing *networkingv1.Ingress) ([]string, []string) {
	var securityIssues []string
	var dangerousAnnotations []string

	// Check for dangerous NGINX annotations
	dangerousNginxAnnotations := []string{
		"nginx.ingress.kubernetes.io/configuration-snippet",
		"nginx.ingress.kubernetes.io/server-snippet",
		"nginx.ingress.kubernetes.io/auth-snippet",
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
			securityIssues = append(securityIssues, "External auth URL not HTTPS")
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

	return securityIssues, dangerousAnnotations
}

func calculateIngressRiskLevel(dangerousAnnotations []string, tlsEnabled bool, exposure string, securityIssues []string) string {
	// CRITICAL: Dangerous annotations + internet-facing
	if len(dangerousAnnotations) > 0 && exposure == "Internet-facing" {
		return "CRITICAL"
	}

	// HIGH: Dangerous annotations OR (no TLS + internet-facing)
	if len(dangerousAnnotations) > 0 {
		return "HIGH"
	}

	if !tlsEnabled && exposure == "Internet-facing" {
		return "HIGH"
	}

	// MEDIUM: Security issues + internet-facing
	if len(securityIssues) > 0 && exposure == "Internet-facing" {
		return "MEDIUM"
	}

	// MEDIUM: No TLS but internal
	if !tlsEnabled {
		return "MEDIUM"
	}

	// LOW: Everything else
	return "LOW"
}
