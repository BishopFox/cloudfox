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
	Short:   "Enumerate ingress resources and exposed HTTP/HTTPS endpoints",
	Long: `
Enumerate all ingress resources in the cluster including:
  - Ingress rules and paths
  - TLS certificates
  - Backend services
  - Annotations and ingress class
  - External IPs and hostnames

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
		"Namespace",
		"Ingress Name",
		"Ingress Class",
		"Hosts",
		"Paths",
		"Backend Services",
		"TLS Enabled",
		"TLS Hosts",
		"Annotations",
		"External IPs",
	}

	var outputRows [][]string
	var lootCurl []string
	var lootTLS []string
	var lootEnum []string
	var lootExploit []string

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
			ingressClass := "<NONE>"
			if ing.Spec.IngressClassName != nil {
				ingressClass = *ing.Spec.IngressClassName
			} else if class, ok := ing.Annotations["kubernetes.io/ingress.class"]; ok {
				ingressClass = class
			}

			var hosts []string
			var paths []string
			var backends []string
			var tlsEnabled string = "false"
			var tlsHosts []string
			var externalIPs []string

			// Process ingress rules
			for _, rule := range ing.Spec.Rules {
				if rule.Host != "" {
					hosts = append(hosts, rule.Host)
				}

				if rule.HTTP != nil {
					for _, path := range rule.HTTP.Paths {
						pathType := "<default>"
						if path.PathType != nil {
							pathType = string(*path.PathType)
						}
						pathStr := fmt.Sprintf("%s (%s)", path.Path, pathType)
						paths = append(paths, pathStr)

						// Extract backend service
						if path.Backend.Service != nil {
							backendStr := fmt.Sprintf("%s:%d", path.Backend.Service.Name, path.Backend.Service.Port.Number)
							backends = append(backends, backendStr)
						}
					}
				}
			}

			// Process TLS configuration
			if len(ing.Spec.TLS) > 0 {
				tlsEnabled = "true"
				for _, tls := range ing.Spec.TLS {
					tlsHosts = append(tlsHosts, tls.Hosts...)

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
						externalIPs = append(externalIPs, lb.IP)
					}
					if lb.Hostname != "" {
						externalIPs = append(externalIPs, lb.Hostname)
					}
				}
			}

			// Format annotations
			var annotations []string
			for k, v := range ing.Annotations {
				annotations = append(annotations, fmt.Sprintf("%s=%s", k, v))
			}
			sort.Strings(annotations)

			// Generate curl test commands
			for _, host := range hosts {
				lootCurl = append(lootCurl, fmt.Sprintf("\n# Ingress: %s/%s - Host: %s", ns.Name, ing.Name, host))

				// HTTP test
				for _, path := range ing.Spec.Rules {
					if path.HTTP != nil {
						for _, p := range path.HTTP.Paths {
							lootCurl = append(lootCurl, fmt.Sprintf("curl -v http://%s%s", host, p.Path))
							lootCurl = append(lootCurl, fmt.Sprintf("curl -v -H 'Host: %s' http://<ingress-lb-ip>%s", host, p.Path))
						}
					}
				}

				// HTTPS test if TLS enabled
				if tlsEnabled == "true" {
					for _, path := range ing.Spec.Rules {
						if path.HTTP != nil {
							for _, p := range path.HTTP.Paths {
								lootCurl = append(lootCurl, fmt.Sprintf("curl -v -k https://%s%s", host, p.Path))
								lootCurl = append(lootCurl, fmt.Sprintf("curl -v -k -H 'Host: %s' https://<ingress-lb-ip>%s", host, p.Path))
							}
						}
					}
				}
				lootCurl = append(lootCurl, "")
			}

			// Generate enumeration commands
			lootEnum = append(lootEnum, fmt.Sprintf("\n# Namespace: %s", ns.Name))
			lootEnum = append(lootEnum, fmt.Sprintf("kubectl get ingress %s -n %s -o yaml", ing.Name, ns.Name))
			lootEnum = append(lootEnum, fmt.Sprintf("kubectl describe ingress %s -n %s", ing.Name, ns.Name))
			lootEnum = append(lootEnum, "")

			// Generate exploit/attack commands
			if ingressClass == "nginx" || strings.Contains(strings.ToLower(strings.Join(annotations, " ")), "nginx") {
				lootExploit = append(lootExploit, fmt.Sprintf("\n# NGINX Ingress: %s/%s", ns.Name, ing.Name))
				lootExploit = append(lootExploit, "# Test for path traversal:")
				for _, host := range hosts {
					lootExploit = append(lootExploit, fmt.Sprintf("curl -v 'http://%s/..;/admin'", host))
					lootExploit = append(lootExploit, fmt.Sprintf("curl -v 'http://%s/..%%2f..%%2f..%%2fetc/passwd'", host))
				}

				// Check for dangerous annotations
				if snippetAnnotation, ok := ing.Annotations["nginx.ingress.kubernetes.io/configuration-snippet"]; ok {
					lootExploit = append(lootExploit, fmt.Sprintf("# WARNING: Ingress has configuration-snippet annotation (potential RCE):"))
					lootExploit = append(lootExploit, fmt.Sprintf("# Value: %s", snippetAnnotation))
				}
				if authURL, ok := ing.Annotations["nginx.ingress.kubernetes.io/auth-url"]; ok {
					lootExploit = append(lootExploit, fmt.Sprintf("# External auth URL: %s", authURL))
					lootExploit = append(lootExploit, "# Test authentication bypass:")
					for _, host := range hosts {
						lootExploit = append(lootExploit, fmt.Sprintf("curl -v -H 'X-Original-URL: /admin' http://%s/public", host))
					}
				}
				lootExploit = append(lootExploit, "")
			}

			if ingressClass == "traefik" || strings.Contains(strings.ToLower(strings.Join(annotations, " ")), "traefik") {
				lootExploit = append(lootExploit, fmt.Sprintf("\n# Traefik Ingress: %s/%s", ns.Name, ing.Name))
				lootExploit = append(lootExploit, "# Check for exposed Traefik dashboard:")
				for _, ip := range externalIPs {
					lootExploit = append(lootExploit, fmt.Sprintf("curl http://%s:8080/dashboard/", ip))
				}
				lootExploit = append(lootExploit, "")
			}

			// Build table row
			outputRows = append(outputRows, []string{
				ns.Name,
				ing.Name,
				ingressClass,
				strings.Join(k8sinternal.Unique(hosts), ", "),
				strings.Join(k8sinternal.Unique(paths), ", "),
				strings.Join(k8sinternal.Unique(backends), ", "),
				tlsEnabled,
				strings.Join(k8sinternal.Unique(tlsHosts), ", "),
				strings.Join(annotations, "; "),
				strings.Join(externalIPs, ", "),
			})
		}
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
		logger.InfoM(fmt.Sprintf("%d ingress resources found", len(outputRows)), globals.K8S_INGRESS_MODULE_NAME)
	} else {
		logger.InfoM("No ingress resources found, skipping output file creation", globals.K8S_INGRESS_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_INGRESS_MODULE_NAME), globals.K8S_INGRESS_MODULE_NAME)
}
