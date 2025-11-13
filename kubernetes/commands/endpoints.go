package commands

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	k8sinternal "github.com/BishopFox/cloudfox/internal/kubernetes"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/spf13/cobra"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var EndpointsCmd = &cobra.Command{
	Use:     "endpoints",
	Aliases: []string{"ep"},
	Short:   "List all cluster Endpoints",
	Long: `
List all cluster Endpoints:
  cloudfox kubernetes endpoints`,
	Run: ListEndpoints,
}

type EndpointsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t EndpointsOutput) TableFiles() []internal.TableFile {
	return t.Table
}

func (t EndpointsOutput) LootFiles() []internal.LootFile {
	return t.Loot
}

func ListEndpoints(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	clientset := config.GetClientOrExit()
	if clientset == nil {
		logger.ErrorM("Error getting Kubernetes client:", globals.K8S_ENDPOINTS_MODULE_NAME)
		os.Exit(1)
	}

	endpoints, err := clientset.CoreV1().Endpoints("").List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing endpoints: %v", err), globals.K8S_ENDPOINTS_MODULE_NAME)
		return
	}

	headers := []string{
		"Namespace", "Endpoint Name", "IP", "Hostname", "Target Ref", "TCP Ports", "UDP Ports", "Resource Type",
	}
	var outputRows [][]string
	var lootPortForwardTCP strings.Builder
	var lootPortForwardUDP strings.Builder

	// First loot file: standard enumeration
	namespaceToEndpoints := map[string][]string{}
	for _, endpoint := range endpoints.Items {
		if len(endpoint.Subsets) == 0 {
			continue
		}
		namespace := endpoint.Namespace
		name := endpoint.Name
		cmd := fmt.Sprintf(
			`kubectl -n %s get endpoints %s -o json | jq '{
	Namespace: .metadata.namespace,
	Name: .metadata.name,
	Subsets: [.subsets[] | {
		Addresses: [.addresses[]? | {IP:.ip, Hostname:.hostname, TargetRef:.targetRef}],
		NotReadyAddresses: [.notReadyAddresses[]? | {IP:.ip, Hostname:.hostname, TargetRef:.targetRef}],
		Ports: [.ports[] | {Port:.port, Protocol:.protocol}]
	}]}'`,
			namespace, name)

		namespaceToEndpoints[namespace] = append(namespaceToEndpoints[namespace], cmd)

		// Build table rows
		for _, subset := range endpoint.Subsets {
			allAddresses := append(subset.Addresses, subset.NotReadyAddresses...)
			for _, addr := range allAddresses {
				tcpPorts := []string{}
				udpPorts := []string{}
				for _, port := range subset.Ports {
					portStr := strconv.Itoa(int(port.Port))
					switch strings.ToUpper(string(port.Protocol)) {
					case "TCP":
						tcpPorts = append(tcpPorts, portStr)
					case "UDP":
						udpPorts = append(udpPorts, portStr)
					}
				}
				sort.Strings(tcpPorts)
				sort.Strings(udpPorts)

				row := []string{
					k8sinternal.NonEmpty(endpoint.Namespace),
					k8sinternal.NonEmpty(endpoint.Name),
					k8sinternal.NonEmpty(addr.IP),
					k8sinternal.NonEmpty(addr.Hostname),
					k8sinternal.NonEmpty(formatTargetRef(addr.TargetRef)),
					k8sinternal.NonEmpty(strings.Join(tcpPorts, ",")),
					k8sinternal.NonEmpty(strings.Join(udpPorts, ",")),
					"Endpoint",
				}

				outputRows = append(outputRows, row)

				if addr.IP != "" {
					if len(tcpPorts) > 0 {
						lootPortForwardTCP.WriteString(fmt.Sprintf(
							"# Namespace: %s, Endpoint: %s\nkubectl -n %s port-forward svc/%s %s:%s\n\n",
							endpoint.Namespace, endpoint.Name, endpoint.Namespace, endpoint.Name,
							strings.Join(tcpPorts, ","), strings.Join(tcpPorts, ","),
						))
					}
					if len(udpPorts) > 0 {
						for _, udpPort := range udpPorts {
							lootPortForwardUDP.WriteString(fmt.Sprintf(
								"# Namespace: %s, Endpoint: %s\nkubectl run udp-forwarder --image=alpine --restart=Never --rm -it -- sh -c \"apk add socat && socat UDP4-LISTEN:%[1]s,fork UDP4:%[2]s:%[1]s\"\n\n",
								endpoint.Namespace, endpoint.Name, udpPort, addr.IP))
						}
					}
				}
			}
		}
	}

	// Build first loot file: enumeration
	lootEnum := []string{
		"#####################################",
		"##### Enumerate Endpoint Information",
		"#####################################",
		"",
	}
	if globals.KubeContext != "" {
		lootEnum = append(lootEnum, fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext))
	}

	lootPortForwardTCP.WriteString(`#####################################
##### TCP Service Port-Forward Commands
#####################################

`)
	if globals.KubeContext != "" {
		lootPortForwardTCP.WriteString(fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext))
	}
	lootPortForwardUDP.WriteString(`#####################################
##### UDP Service Port-Forward Commands
#####################################

`)
	if globals.KubeContext != "" {
		lootPortForwardUDP.WriteString(fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext))
	}

	namespaces := make([]string, 0, len(namespaceToEndpoints))
	for ns := range namespaceToEndpoints {
		namespaces = append(namespaces, ns)
	}
	sort.Strings(namespaces)
	for _, ns := range namespaces {
		lootEnum = append(lootEnum, fmt.Sprintf("\n# Namespace: %s\n", ns))
		lootEnum = append(lootEnum, namespaceToEndpoints[ns]...)
	}

	// Define table and loot files
	table := internal.TableFile{
		Name:   "Endpoints",
		Header: headers,
		Body:   outputRows,
	}
	lootEnumFile := internal.LootFile{
		Name:     "Endpoint-Enum",
		Contents: strings.Join(lootEnum, "\n"),
	}

	lootTCP := internal.LootFile{
		Name:     "Endpoints-PortForward-TCP",
		Contents: lootPortForwardTCP.String(),
	}

	lootUDP := internal.LootFile{
		Name:     "Endpoints-PortForward-UDP",
		Contents: lootPortForwardUDP.String(),
	}

	// Output everything
	err = internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"Endpoints",
		globals.ClusterName,
		"results",
		EndpointsOutput{
			Table: []internal.TableFile{table},
			Loot:  []internal.LootFile{lootEnumFile, lootTCP, lootUDP},
		},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_ENDPOINTS_MODULE_NAME)
	}
}

func formatTargetRef(ref *v1.ObjectReference) string {
	if ref == nil {
		return "N/A"
	}
	return fmt.Sprintf("%s/%s", ref.Kind, ref.Name)
}
