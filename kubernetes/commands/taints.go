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

var TaintsCmd = &cobra.Command{
	Use:     "taints",
	Aliases: []string{},
	Short:   "List all cluster Node Taints",
	Long: `
List all cluster Node Taints and outputs an example YAML file with Tolerations to create a pod:
  cloudfox kubernetes taints`,
	Run: ListTaints,
}

type TaintsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t TaintsOutput) TableFiles() []internal.TableFile {
	return t.Table
}

func (t TaintsOutput) LootFiles() []internal.LootFile {
	return t.Loot
}

func ListTaints(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	logger := internal.NewLogger()

	// Extract global flags
	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating node taints for %s", globals.ClusterName), globals.K8S_TAINTS_MODULE_NAME)

	clientset := config.GetClientOrExit()

	var lootEnum []string // for kubectl + jq commands
	lootEnum = append(lootEnum, `#####################################
##### Enumerate Taint Information
#####################################

`)
	if globals.KubeContext != "" {
		lootEnum = append(lootEnum, fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext))
	}

	var lootPodYAMLs []string // for example Pod YAMLs
	lootPodYAMLs = append(lootPodYAMLs, `#####################################
##### Pod YAMLs for Tolerations
#####################################

`)

	nodes, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing nodes: %v", err), globals.K8S_TAINTS_MODULE_NAME)
		return
	}

	var tableRows [][]string

	for _, node := range nodes.Items {
		nodeName := k8sinternal.NonEmpty(node.Name)

		// Table rows
		if len(node.Spec.Taints) == 0 {
			tableRows = append(tableRows, []string{
				nodeName, "<NONE>", "<NONE>", "<NONE>", "<NONE>",
			})
			continue
		}

		var tolerations []corev1.Toleration
		for _, taint := range node.Spec.Taints {
			timeAdded := "<NONE>"
			if taint.TimeAdded != nil {
				timeAdded = taint.TimeAdded.String()
			}

			tableRows = append(tableRows, []string{
				nodeName,
				k8sinternal.NonEmpty(taint.Key),
				k8sinternal.NonEmpty(taint.Value),
				k8sinternal.NonEmpty(string(taint.Effect)),
				timeAdded,
			})

			tolerations = append(tolerations, corev1.Toleration{
				Key:      taint.Key,
				Operator: corev1.TolerationOpEqual,
				Value:    taint.Value,
				Effect:   taint.Effect,
			})
		}

		// Loot file 1: kubectl + jq command
		lootCmd := fmt.Sprintf(
			"kubectl get node %s -o json | jq '.spec.taints[] | {nodeName: \"%s\", key: .key, value: .value, effect: .effect}'",
			nodeName,
			nodeName,
		)
		lootEnum = append(lootEnum, lootCmd)

		// Loot file 2: example Pod YAML
		pod := corev1.Pod{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "Pod",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: fmt.Sprintf("tolerate-%s", nodeName),
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
				fmt.Sprintf("# --- POD YAML for node: %s ---\n%s", nodeName, string(yamlData)),
				fmt.Sprintf("# Apply with: kubectl create -f <filename>.yaml"),
			)
		} else {
			logger.ErrorM(fmt.Sprintf("Error marshaling YAML for node %s: %v", nodeName, err), globals.K8S_TAINTS_MODULE_NAME)
		}
	}

	// Sort table rows by node name
	sort.SliceStable(tableRows, func(i, j int) bool {
		return tableRows[i][0] < tableRows[j][0]
	})

	headers := []string{"Node Name", "Taint Key", "Taint Value", "Taint Effect", "Taint Time Added"}
	table := internal.TableFile{
		Name:   "Taints",
		Header: headers,
		Body:   tableRows,
	}

	// Deduplicate and sort
	lootEnum = k8sinternal.Unique(lootEnum)
	sort.Strings(lootEnum)
	lootPodYAMLs = k8sinternal.Unique(lootPodYAMLs)
	sort.Strings(lootPodYAMLs)

	// Create loot files
	lootKubectl := internal.LootFile{
		Name:     "Taint-Enum",
		Contents: strings.Join(lootEnum, "\n"),
	}

	lootPodYAML := internal.LootFile{
		Name:     "Pod-YAMLs",
		Contents: strings.Join(lootPodYAMLs, "\n\n"),
	}

	// Pass both loot files in the output
	err = internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"Taints",
		globals.ClusterName,
		"results",
		TaintsOutput{
			Table: []internal.TableFile{table},
			Loot:  []internal.LootFile{lootKubectl, lootPodYAML},
		},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_TAINTS_MODULE_NAME)
		return
	}

	if len(tableRows) > 0 {
		logger.InfoM(fmt.Sprintf("%d node taints found", len(tableRows)), globals.K8S_TAINTS_MODULE_NAME)
	} else {
		logger.InfoM("No node taints found, skipping output file creation", globals.K8S_TAINTS_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_TAINTS_MODULE_NAME), globals.K8S_TAINTS_MODULE_NAME)
}
