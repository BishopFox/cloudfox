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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var ServicesCmd = &cobra.Command{
	Use:     "services",
	Aliases: []string{},
	Short:   "Enumerate all services in the cluster",
	Long: `
Enumerate all services in the cluster:
  cloudfox kubernetes services`,
	Run: ListServices,
}

type ServicesOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t ServicesOutput) TableFiles() []internal.TableFile {
	return t.Table
}

func (t ServicesOutput) LootFiles() []internal.LootFile {
	return t.Loot
}

func ListServices(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating services for %s", globals.ClusterName), globals.K8S_SERVICES_MODULE_NAME)

	clientset := config.GetClientOrExit()

	svcClient := clientset.CoreV1().Services("")
	endpointsClient := clientset.CoreV1().Endpoints("")
	endpointSliceClient := clientset.DiscoveryV1().EndpointSlices("")

	services, err := svcClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error retrieving services: %v", err), globals.K8S_SERVICES_MODULE_NAME)
		os.Exit(1)
	}

	headers := []string{
		"Namespace", "Service", "Type", "Exposure", "Cluster IPs",
		"External IPs", "Load Balancer Ingress", "Ports",
		"Endpoints", "Annotations",
	}
	var outputRows [][]string
	var lootTCP strings.Builder
	var lootUDP strings.Builder

	// Loot file 1: standard enumeration
	var lootEnum []string
	lootEnum = append(lootEnum, `#####################################
##### Enumerate Service Information
#####################################

`)

	if globals.KubeContext != "" {
		lootEnum = append(lootEnum, fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext))
	}

	lootTCP.WriteString(`#####################################
##### TCP Service Port-Forward Commands
#####################################

`)
	if globals.KubeContext != "" {
		lootTCP.WriteString(fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext))
	}
	lootUDP.WriteString(`#####################################
##### UDP Service Port-Forward Commands
#####################################

`)
	if globals.KubeContext != "" {
		lootUDP.WriteString(fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext))
	}

	// Loot file 2: port-forward commands
	portForwardSet := map[string][]string{} // map namespace -> commands

	for _, svc := range services.Items {
		var clusterIPs, externalIPs, ingress, ports, annotations, endpoints []string
		exposure := "Internal"

		if svc.Spec.Type == "LoadBalancer" || len(svc.Spec.ExternalIPs) > 0 {
			exposure = "External"
		} else {
			for _, lb := range svc.Status.LoadBalancer.Ingress {
				if lb.Hostname != "" || lb.IP != "" {
					exposure = "External"
					break
				}
			}
		}

		clusterIPs = svc.Spec.ClusterIPs
		externalIPs = svc.Spec.ExternalIPs
		for _, lb := range svc.Status.LoadBalancer.Ingress {
			if lb.Hostname != "" {
				ingress = append(ingress, lb.Hostname)
			} else if lb.IP != "" {
				ingress = append(ingress, lb.IP)
			}
		}
		for _, p := range svc.Spec.Ports {
			ports = append(ports, fmt.Sprintf("%s:%d/%s", p.Name, p.Port, p.Protocol))
			if strings.ToUpper(string(p.Protocol)) == "TCP" {
				cmd := fmt.Sprintf("kubectl -n %s port-forward svc/%s %d:%d", svc.Namespace, svc.Name, p.Port, p.Port)
				portForwardSet[svc.Namespace] = append(portForwardSet[svc.Namespace], cmd)
			}
		}
		for k, v := range svc.Annotations {
			annotations = append(annotations, fmt.Sprintf("%s=%s", k, v))
		}

		// Endpoints
		ep, err := endpointsClient.Get(ctx, svc.Name, metav1.GetOptions{})
		if err == nil {
			for _, subset := range ep.Subsets {
				for _, addr := range subset.Addresses {
					for _, port := range subset.Ports {
						endpoints = append(endpoints, fmt.Sprintf("%s:%d", addr.IP, port.Port))
					}
				}
			}
		}

		slices, err := endpointSliceClient.List(ctx, metav1.ListOptions{
			LabelSelector: fmt.Sprintf("kubernetes.io/service-name=%s", svc.Name),
		})
		if err == nil {
			for _, slice := range slices.Items {
				for _, ep := range slice.Endpoints {
					for _, addr := range ep.Addresses {
						for _, port := range slice.Ports {
							if port.Port != nil {
								endpoints = append(endpoints, fmt.Sprintf("%s:%d", addr, *port.Port))
							}
						}
					}
				}
			}
		}

		if svc.Spec.ClusterIP == "None" {
			clusterIPs = []string{"Headless"}
		}

		var tcpPorts, udpPorts []string
		for _, p := range svc.Spec.Ports {
			portStr := fmt.Sprintf("%d", p.Port)
			switch strings.ToUpper(string(p.Protocol)) {
			case "TCP":
				tcpPorts = append(tcpPorts, portStr)
			case "UDP":
				udpPorts = append(udpPorts, portStr)
			}
		}

		// Loot generation
		if len(tcpPorts) > 0 {
			for _, port := range tcpPorts {
				lootTCP.WriteString(fmt.Sprintf(
					"# Namespace: %s, Service: %s\nkubectl -n %s port-forward svc/%s %s:%s\n\n",
					svc.Namespace, svc.Name,
					svc.Namespace, svc.Name,
					port, port,
				))
			}
		}
		if len(udpPorts) > 0 {
			for _, udpPort := range udpPorts {
				lootUDP.WriteString(fmt.Sprintf(
					"# Namespace: %s, Service: %s\nkubectl run udp-forwarder --image=alpine --restart=Never --rm -it -- sh -c \"apk add socat && socat UDP4-LISTEN:%[1]s,fork UDP4:%[2]s:%[1]s\"\n\n",
					udpPort, svc.Name))
			}
		}

		outputRows = append(outputRows, []string{
			svc.Namespace,
			svc.Name,
			string(svc.Spec.Type),
			exposure,
			strings.Join(clusterIPs, ","),
			strings.Join(externalIPs, ","),
			strings.Join(ingress, ","),
			strings.Join(ports, ","),
			strings.Join(k8sinternal.Unique(endpoints), ","),
			strings.Join(annotations, "; "),
		})

		lootEnum = append(lootEnum,
			fmt.Sprintf("\n# Namespace: %s\n", svc.Namespace),
			fmt.Sprintf("kubectl get svc %s -n %s -o yaml \n", svc.Name, svc.Namespace),
		)
	}

	namespaces := make([]string, 0, len(portForwardSet))
	for ns := range portForwardSet {
		namespaces = append(namespaces, ns)
	}
	sort.Strings(namespaces)

	table := internal.TableFile{
		Name:   "Services",
		Header: headers,
		Body:   outputRows,
	}

	lootEnumFile := internal.LootFile{
		Name:     "Services-Enum",
		Contents: strings.Join(k8sinternal.Unique(lootEnum), "\n"),
	}
	lootTCPFile := internal.LootFile{
		Name:     "Services-PortForward-TCP",
		Contents: lootTCP.String(),
	}

	lootUDPFile := internal.LootFile{
		Name:     "Services-PortForward-UDP",
		Contents: lootUDP.String(),
	}

	err = internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"Services",
		globals.ClusterName,
		"results",
		ServicesOutput{
			Table: []internal.TableFile{table},
			Loot:  []internal.LootFile{lootEnumFile, lootTCPFile, lootUDPFile},
		},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_SERVICES_MODULE_NAME)
		return
	}

	if len(outputRows) > 0 {
		logger.InfoM(fmt.Sprintf("%d services found", len(outputRows)), globals.K8S_SERVICES_MODULE_NAME)
	} else {
		logger.InfoM("No services found, skipping output file creation", globals.K8S_SERVICES_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_SERVICES_MODULE_NAME), globals.K8S_SERVICES_MODULE_NAME)
}
