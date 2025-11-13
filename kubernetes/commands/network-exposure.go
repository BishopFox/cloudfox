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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var NetworkExposureCmd = &cobra.Command{
	Use:     "network-exposure",
	Aliases: []string{"net-ports"},
	Short:   "Enumerate cluster exposed network ports",
	Long: `
Enumerate cluster exposed network hosts and ports:
  cloudfox kubernetes network-exposure`,
	Run: NetworkExposure,
}

type Exposure struct {
	Namespace string
	Resource  string
	Name      string
	IPOrHost  string
	Port      string
	Protocol  string
}

type NetworkExposureOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (n NetworkExposureOutput) TableFiles() []internal.TableFile {
	return n.Table
}

func (n NetworkExposureOutput) LootFiles() []internal.LootFile {
	return n.Loot
}

func appendNmapCommands(commands *[]string, target string, ports []corev1.ServicePort) {
	var tcpPorts, udpPorts []int32
	for _, port := range ports {
		switch port.Protocol {
		case corev1.ProtocolTCP:
			tcpPorts = append(tcpPorts, port.Port)
		case corev1.ProtocolUDP:
			udpPorts = append(udpPorts, port.Port)
		}
	}
	var nmapParts []string
	if len(tcpPorts) > 0 {
		sort.Slice(tcpPorts, func(i, j int) bool { return tcpPorts[i] < tcpPorts[j] })
		portStr := strings.Trim(strings.Join(strings.Fields(fmt.Sprint(tcpPorts)), ","), "[]")
		nmapParts = append(nmapParts, fmt.Sprintf("nmap -PN -sV -p %s %s", portStr, target))
	}
	if len(udpPorts) > 0 {
		sort.Slice(udpPorts, func(i, j int) bool { return udpPorts[i] < udpPorts[j] })
		portStr := strings.Trim(strings.Join(strings.Fields(fmt.Sprint(udpPorts)), ","), "[]")
		nmapParts = append(nmapParts, fmt.Sprintf("nmap -PN -sU -p %s %s", portStr, target))
	}
	if len(nmapParts) == 0 {
		nmapParts = append(nmapParts, fmt.Sprintf("nmap -PN -sV %s", target))
	}
	*commands = append(*commands, strings.Join(nmapParts, "\n"))
}

func NetworkExposure(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	logger := internal.NewLogger()
	parentCmd := cmd.Parent()

	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	clientset := config.GetClientOrExit()
	if clientset == nil {
		logger.ErrorM("Error getting Kubernetes client:", globals.K8S_NETWORK_PORTS_MODULE_NAME)
		os.Exit(1)
	}

	var results []Exposure
	var lootNmapCommands []string

	// helper: safe stringify for pointers
	safePort := func(p *int32) string {
		if p == nil {
			return "N/A"
		}
		return fmt.Sprintf("%d", *p)
	}
	safeProto := func(p *corev1.Protocol) string {
		if p == nil {
			return "N/A"
		}
		return string(*p)
	}

	// ---- Services
	services, err := clientset.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing Services: %v", err), globals.K8S_NETWORK_PORTS_MODULE_NAME)
	} else {
		for _, svc := range services.Items {
			targets := []string{}
			if svc.Spec.Type == corev1.ServiceTypeExternalName {
				if svc.Spec.ExternalName != "" {
					targets = append(targets, svc.Spec.ExternalName)
				}
			} else {
				if svc.Spec.ClusterIP != "" && svc.Spec.ClusterIP != "None" {
					targets = append(targets, svc.Spec.ClusterIP)
				}
				if len(svc.Spec.ExternalIPs) > 0 {
					targets = append(targets, svc.Spec.ExternalIPs...)
				}
				if len(svc.Status.LoadBalancer.Ingress) > 0 {
					for _, ing := range svc.Status.LoadBalancer.Ingress {
						if ing.IP != "" {
							targets = append(targets, ing.IP)
						} else if ing.Hostname != "" {
							targets = append(targets, ing.Hostname)
						}
					}
				}
			}

			for _, target := range targets {
				for _, port := range svc.Spec.Ports {
					results = append(results, Exposure{
						Namespace: svc.Namespace,
						Resource:  "Service",
						Name:      svc.Name,
						IPOrHost:  target,
						Port:      fmt.Sprintf("%d", port.Port),
						Protocol:  string(port.Protocol),
					})
				}
				appendNmapCommands(&lootNmapCommands, target, svc.Spec.Ports)
			}
		}
	}

	// ---- EndpointSlices
	endpointSlices, err := clientset.DiscoveryV1().EndpointSlices("").List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing EndpointSlices: %v", err), globals.K8S_NETWORK_PORTS_MODULE_NAME)
	} else {
		for _, slice := range endpointSlices.Items {
			for _, endpoint := range slice.Endpoints {
				for _, addr := range endpoint.Addresses {
					// Collect for table
					for _, port := range slice.Ports {
						results = append(results, Exposure{
							Namespace: slice.Namespace,
							Resource:  "EndpointSlice",
							Name:      slice.Name,
							IPOrHost:  addr,
							Port:      safePort(port.Port),
							Protocol:  safeProto(port.Protocol),
						})
					}
					// Build a ServicePort array only for ports that have both Port and Protocol
					servicePorts := make([]corev1.ServicePort, 0, len(slice.Ports))
					for _, p := range slice.Ports {
						if p.Port != nil && p.Protocol != nil {
							servicePorts = append(servicePorts, corev1.ServicePort{
								Port:     *p.Port,
								Protocol: *p.Protocol,
							})
						}
					}
					appendNmapCommands(&lootNmapCommands, addr, servicePorts)
				}
			}
		}
	}

	// ---- Endpoints (v1)
	endpoints, err := clientset.CoreV1().Endpoints("").List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing Endpoints: %v", err), globals.K8S_NETWORK_PORTS_MODULE_NAME)
	} else {
		for _, ep := range endpoints.Items {
			for _, subset := range ep.Subsets {
				for _, addr := range subset.Addresses {
					for _, port := range subset.Ports {
						results = append(results, Exposure{
							Namespace: ep.Namespace,
							Resource:  "Endpoints",
							Name:      ep.Name,
							IPOrHost:  addr.IP,
							Port:      fmt.Sprintf("%d", port.Port),
							Protocol:  string(port.Protocol),
						})
					}
					// No specific ports? still add a generic nmap
					appendNmapCommands(&lootNmapCommands, addr.IP, nil)
				}
			}
		}
	}

	// ---- Ingresses
	ingresses, err := clientset.NetworkingV1().Ingresses("").List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing Ingresses: %v", err), globals.K8S_NETWORK_PORTS_MODULE_NAME)
	} else {
		for _, ing := range ingresses.Items {
			for _, rule := range ing.Spec.Rules {
				ipOrHost := rule.Host
				if rule.HTTP != nil {
					for range rule.HTTP.Paths {
						// 80/HTTP as a heuristic for loot/table
						results = append(results, Exposure{
							Namespace: ing.Namespace,
							Resource:  "Ingress",
							Name:      ing.Name,
							IPOrHost:  ipOrHost,
							Port:      "80",
							Protocol:  "HTTP",
						})
					}
				}
				if ipOrHost != "" {
					appendNmapCommands(&lootNmapCommands, ipOrHost, nil)
				}
			}
		}
	}

	// ---- Nodes (InternalIP)
	nodes, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing Nodes: %v", err), globals.K8S_NETWORK_PORTS_MODULE_NAME)
	} else {
		for _, node := range nodes.Items {
			ip := "N/A"
			for _, addr := range node.Status.Addresses {
				if addr.Type == corev1.NodeInternalIP && addr.Address != "" {
					ip = addr.Address
					break
				}
			}
			results = append(results, Exposure{
				Namespace: "N/A",
				Resource:  "Node",
				Name:      node.Name,
				IPOrHost:  ip,
				Port:      "N/A",
				Protocol:  "N/A",
			})
			if ip != "N/A" {
				appendNmapCommands(&lootNmapCommands, ip, nil)
			}
		}
	}

	// ---- Table
	headers := []string{"Namespace", "Resource Type", "Name", "IP/Hostname", "Port", "Protocol"}
	var rows [][]string
	for _, r := range results {
		rows = append(rows, []string{
			k8sinternal.NonEmpty(r.Namespace),
			k8sinternal.NonEmpty(r.Resource),
			k8sinternal.NonEmpty(r.Name),
			k8sinternal.NonEmpty(r.IPOrHost),
			k8sinternal.NonEmpty(r.Port),
			k8sinternal.NonEmpty(r.Protocol),
		})
	}

	// ---- Loot (dedupe)
	lootSet := map[string]struct{}{}
	var lootNmapCommandsUniq []string
	lootNmapCommandsUniq = append(lootNmapCommandsUniq, `#####################################
##### NMAP Network Exposure
#####################################

`)
	for _, c := range lootNmapCommands {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if _, ok := lootSet[c]; ok {
			continue
		}
		lootSet[c] = struct{}{}
		lootNmapCommandsUniq = append(lootNmapCommandsUniq, c)
	}

	table := internal.TableFile{
		Name:   "Network-Exposure",
		Header: headers,
		Body:   rows,
	}
	loot := internal.LootFile{
		Name:     "NMAP-Network",
		Contents: strings.Join(lootNmapCommandsUniq, "\n"),
	}

	err = internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"Network-Exposure",
		globals.ClusterName,
		"results",
		NetworkExposureOutput{
			Table: []internal.TableFile{table},
			Loot:  []internal.LootFile{loot},
		},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_NETWORK_PORTS_MODULE_NAME)
	}
}
