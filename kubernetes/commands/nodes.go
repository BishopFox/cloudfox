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
	"sigs.k8s.io/yaml"
)

var NodesCmd = &cobra.Command{
	Use:     "nodes",
	Aliases: []string{},
	Short:   "List all cluster nodes",
	Long: `
List all cluster nodes and detailed information:
  cloudfox kubernetes nodes`,
	Run: ListNodes,
}

type NodesOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t NodesOutput) TableFiles() []internal.TableFile {
	return t.Table
}

func (t NodesOutput) LootFiles() []internal.LootFile {
	return t.Loot
}

func ListNodes(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating nodes for %s", globals.ClusterName), globals.K8S_NODES_MODULE_NAME)

	clientset := config.GetClientOrExit()

	nodes, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing nodes: %v", err), globals.K8S_NODES_MODULE_NAME)
		return
	}

	headers := []string{
		"Name", "Internal IP", "External IP", "OS Image", "Kernel Version",
		"Container Runtime", "Kubelet Version", "Cloud Provider", "Cloud Role",
		"Taints", "Labels", "Annotations",
	}

	var outputRows [][]string
	var lootNodeCmds []string
	lootNodeCmds = append(lootNodeCmds, `#####################################
##### Enumerate Node Information
#####################################

`)

	if globals.KubeContext != "" {
		lootNodeCmds = append(lootNodeCmds, fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext))
	}

	var lootPodYAMLs []string
	lootPodYAMLs = append(lootPodYAMLs, `#####################################
##### Pod YAMLs pinned to nodes
#####################################
		
`)

	for _, node := range nodes.Items {
		nodeName := k8sinternal.NonEmpty(node.Name)

		internalIP := "<NONE>"
		externalIP := "<NONE>"
		for _, addr := range node.Status.Addresses {
			switch addr.Type {
			case corev1.NodeInternalIP:
				internalIP = addr.Address
			case corev1.NodeExternalIP:
				externalIP = addr.Address
			}
		}

		cloudProvider := k8sinternal.DetectCloudProviderFromNode(node.Spec.ProviderID)
		cloudRole := k8sinternal.DetectCloudRoleFromNodeLabels(node.Labels)

		// --- Taints ---
		var taints []string
		for _, t := range node.Spec.Taints {
			taints = append(taints, fmt.Sprintf("%s=%s:%s", t.Key, t.Value, t.Effect))
		}

		// --- Labels ---
		var labels []string
		for k, v := range node.Labels {
			labels = append(labels, fmt.Sprintf("%s=%s", k, v))
		}

		// --- Annotations ---
		var annotations []string
		for k, v := range node.Annotations {
			annotations = append(annotations, fmt.Sprintf("%s=%s", k, v))
		}

		row := []string{
			nodeName,
			k8sinternal.NonEmpty(internalIP),
			k8sinternal.NonEmpty(externalIP),
			k8sinternal.NonEmpty(node.Status.NodeInfo.OSImage),
			k8sinternal.NonEmpty(node.Status.NodeInfo.KernelVersion),
			k8sinternal.NonEmpty(node.Status.NodeInfo.ContainerRuntimeVersion),
			k8sinternal.NonEmpty(node.Status.NodeInfo.KubeletVersion),
			k8sinternal.NonEmpty(cloudProvider),
			k8sinternal.NonEmpty(cloudRole),
			k8sinternal.NonEmpty(strings.Join(taints, "\n")),
			k8sinternal.NonEmpty(strings.Join(labels, "\n")),
			k8sinternal.NonEmpty(strings.Join(annotations, "\n")),
		}
		outputRows = append(outputRows, row)

		// Loot command per node
		lootCmd := fmt.Sprintf(
			`kubectl get node %s -o json | jq '{nodeName: "%s", internalIP: (.status.addresses[] | select(.type=="InternalIP") | .address), externalIP: (.status.addresses[] | select(.type=="ExternalIP") | .address), osImage: .status.nodeInfo.osImage, kernelVersion: .status.nodeInfo.kernelVersion, containerRuntime: .status.nodeInfo.containerRuntimeVersion, kubeletVersion: .status.nodeInfo.kubeletVersion, cloudProvider: "%s", cloudRole: "%s", taints: .spec.taints, labels: .metadata.labels, annotations: .metadata.annotations}'`,
			nodeName,
			nodeName,
			cloudProvider,
			cloudRole,
		)
		lootNodeCmds = append(lootNodeCmds, lootCmd)

		// Example pod YAML pinned to node
		var tolerations []corev1.Toleration
		for _, taint := range node.Spec.Taints {
			tolerations = append(tolerations, corev1.Toleration{
				Key:      taint.Key,
				Operator: corev1.TolerationOpEqual,
				Value:    taint.Value,
				Effect:   taint.Effect,
			})
		}

		pod := corev1.Pod{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "Pod",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: fmt.Sprintf("probe-%s", nodeName),
			},
			Spec: corev1.PodSpec{
				NodeName:    nodeName,
				Tolerations: tolerations,
				Containers: []corev1.Container{
					{
						Name:    "alpine",
						Image:   "alpine:latest",
						Command: []string{"sh", "-c", "sleep 3600"},
					},
				},
			},
		}

		yamlData, err := yaml.Marshal(pod)
		if err == nil {
			lootPodYAMLs = append(lootPodYAMLs,
				fmt.Sprintf("# --- POD YAML for node: %s ---\n%s", nodeName, string(yamlData)))
		} else {
			logger.ErrorM(fmt.Sprintf("Error marshaling YAML for node %s: %v", nodeName, err), globals.K8S_NODES_MODULE_NAME)
		}
	}

	// Sort table rows
	sort.SliceStable(outputRows, func(i, j int) bool {
		return outputRows[i][0] < outputRows[j][0]
	})

	table := internal.TableFile{
		Name:   "Nodes",
		Header: headers,
		Body:   outputRows,
	}

	// Deduplicate loot files
	lootNodeCmds = k8sinternal.Unique(lootNodeCmds)
	sort.Strings(lootNodeCmds)
	lootPodYAMLs = k8sinternal.Unique(lootPodYAMLs)
	sort.Strings(lootPodYAMLs)

	lootNodes := internal.LootFile{
		Name:     "Node-Enum",
		Contents: strings.Join(lootNodeCmds, "\n"),
	}
	lootPods := internal.LootFile{
		Name:     "Pod-YAMLs",
		Contents: strings.Join(lootPodYAMLs, "\n\n"),
	}

	// Handle output
	err = internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"Nodes",
		globals.ClusterName,
		"results",
		NodesOutput{
			Table: []internal.TableFile{table},
			Loot:  []internal.LootFile{lootNodes, lootPods},
		},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_NODES_MODULE_NAME)
		return
	}

	if len(outputRows) > 0 {
		logger.InfoM(fmt.Sprintf("%d nodes found", len(outputRows)), globals.K8S_NODES_MODULE_NAME)
	} else {
		logger.InfoM("No nodes found, skipping output file creation", globals.K8S_NODES_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_NODES_MODULE_NAME), globals.K8S_NODES_MODULE_NAME)
}
