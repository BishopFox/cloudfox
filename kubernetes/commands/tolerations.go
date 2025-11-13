package commands

import (
	"context"
	"fmt"
	"os"
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

var TolerationsCmd = &cobra.Command{
	Use:     "tolerations",
	Aliases: []string{"tol"},
	Short:   "List all cluster Pod Tolerations",
	Long: `
List all cluster Pod Tolerations:
  cloudfox kubernetes tolerations`,
	Run: ListTolerations,
}

type TolerationsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t TolerationsOutput) TableFiles() []internal.TableFile {
	return t.Table
}

func (t TolerationsOutput) LootFiles() []internal.LootFile {
	return t.Loot
}

func ListTolerations(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	logger := internal.NewLogger()

	// Extract global flags
	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating pod tolerations for %s", globals.ClusterName), globals.K8S_TOLERATIONS_MODULE_NAME)

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

	namespaces, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing namespaces: %v", err), globals.K8S_TOLERATIONS_MODULE_NAME)
		return
	}

	headers := []string{
		"Namespace", "Pod Name", "Toleration Key", "Toleration Operator", "Toleration Value", "Toleration Effect", "Toleration Seconds",
	}

	var outputRows [][]string

	for _, ns := range namespaces.Items {
		pods, err := clientset.CoreV1().Pods(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			logger.ErrorM(fmt.Sprintf("Error listing pods in namespace: %v", err), globals.K8S_TOLERATIONS_MODULE_NAME)
			continue
		}

		for _, pod := range pods.Items {
			// Add kubectl/jq command for this pod
			lootEnum = append(lootEnum,
				fmt.Sprintf("kubectl get pod %s -n %s -o json | jq '.spec.tolerations[] | {Key:.key, Operator:.operator, Value:.value, Effect:.effect, TolerationSeconds:.tolerationSeconds}' \n",
					pod.Name, pod.Namespace),
			)

			if len(pod.Spec.Tolerations) == 0 {
				row := []string{
					k8sinternal.NonEmpty(pod.Namespace),
					k8sinternal.NonEmpty(pod.Name),
					"<NONE>",
					"<NONE>",
					"<NONE>",
					"<NONE>",
					"<NONE>",
				}
				outputRows = append(outputRows, row)
			} else {
				for _, tol := range pod.Spec.Tolerations {
					seconds := "<NONE>"
					if tol.TolerationSeconds != nil {
						seconds = fmt.Sprintf("%d", *tol.TolerationSeconds)
					}
					row := []string{
						k8sinternal.NonEmpty(pod.Namespace),
						k8sinternal.NonEmpty(pod.Name),
						k8sinternal.NonEmpty(tol.Key),
						k8sinternal.NonEmpty(string(tol.Operator)),
						k8sinternal.NonEmpty(tol.Value),
						k8sinternal.NonEmpty(string(tol.Effect)),
						seconds,
					}
					outputRows = append(outputRows, row)
				}
			}

			// Generate example pod YAML using pod tolerations and node selector if present
			examplePod := corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "v1",
					Kind:       "Pod",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf("example-%s", pod.Name),
				},
				Spec: corev1.PodSpec{
					Tolerations: pod.Spec.Tolerations,
					Containers: []corev1.Container{
						{
							Name:    "alpine",
							Image:   "alpine:latest",
							Command: []string{"sh", "-c", "sleep 3600"},
						},
					},
				},
			}

			var nodeSelectorComment string
			if len(pod.Spec.NodeSelector) > 0 {
				examplePod.Spec.NodeSelector = pod.Spec.NodeSelector
				nodeSelectorComment = fmt.Sprintf("# NodeSelector applied: %v", pod.Spec.NodeSelector)
			}

			yamlData, err := yaml.Marshal(examplePod)
			if err == nil {
				var commentLines []string
				commentLines = append(commentLines, "# Example pod with alpine container sleeping 3600s")
				if nodeSelectorComment != "" {
					commentLines = append(commentLines, nodeSelectorComment)
				}
				lootPodYAMLs = append(lootPodYAMLs,
					fmt.Sprintf("%s\n# --- Pod YAML for %s/%s\n%s", strings.Join(commentLines, "\n"), pod.Namespace, pod.Name, string(yamlData)),
					fmt.Sprintf("# Apply with: kubectl create -f <filename>.yaml"),
				)
			} else {
				logger.ErrorM(fmt.Sprintf("Error marshaling pod YAML for %s/%s: %v", pod.Namespace, pod.Name, err), globals.K8S_TOLERATIONS_MODULE_NAME)
			}
		}
	}

	table := internal.TableFile{
		Name:   "Tolerations",
		Header: headers,
		Body:   outputRows,
	}

	loot1 := internal.LootFile{
		Name:     "Tolerations-Enum",
		Contents: strings.Join(k8sinternal.Unique(lootEnum), "\n"),
	}

	loot2 := internal.LootFile{
		Name:     "Pod-YAMLs",
		Contents: strings.Join(lootPodYAMLs, "\n\n"),
	}

	err = internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"Tolerations",
		globals.ClusterName,
		"results",
		TolerationsOutput{
			Table: []internal.TableFile{table},
			Loot:  []internal.LootFile{loot1, loot2},
		},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_TOLERATIONS_MODULE_NAME)
		return
	}

	if len(outputRows) > 0 {
		logger.InfoM(fmt.Sprintf("%d pod tolerations found", len(outputRows)), globals.K8S_TOLERATIONS_MODULE_NAME)
	} else {
		logger.InfoM("No pod tolerations found, skipping output file creation", globals.K8S_TOLERATIONS_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_TOLERATIONS_MODULE_NAME), globals.K8S_TOLERATIONS_MODULE_NAME)
}
