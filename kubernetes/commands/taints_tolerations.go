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
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var TaintsTolerationsCmd = &cobra.Command{
	Use:     "taints-tolerates",
	Aliases: []string{"tt"},
	Short:   "Shows for each pod which node taints it tolerates and lists taints on nodes that are not tolerated by any pod",
	Long: `
Shows for each pod which node taints it tolerates and lists taints on nodes that are not tolerated by any pod:
  cloudfox kubernetes taints-tolerates`,
	Run: ListTaintsTolerations,
}

type TaintsTolerationsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t TaintsTolerationsOutput) TableFiles() []internal.TableFile {
	return t.Table
}

func (t TaintsTolerationsOutput) LootFiles() []internal.LootFile {
	return t.Loot
}

// helper to check if a toleration matches a taint
func toleratesTaint(tol v1.Toleration, taint v1.Taint) bool {
	if tol.Key != taint.Key {
		return false
	}
	if tol.Effect != taint.Effect && tol.Effect != v1.TaintEffect("") {
		return false
	}

	switch tol.Operator {
	case v1.TolerationOpExists:
		// Key exists, value ignored
		return true
	case v1.TolerationOpEqual, "":
		// Operator Equal or default, key and value must match
		return tol.Value == taint.Value
	default:
		return false
	}
}

func ListTaintsTolerations(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	logger := internal.NewLogger()

	// Extract global flags
	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating taint-toleration mappings for %s", globals.ClusterName), globals.K8S_TAINTS_TOLERATIONS_MODULE_NAME)

	clientset := config.GetClientOrExit()

	nodes, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing nodes: %v", err), globals.K8S_TAINTS_TOLERATIONS_MODULE_NAME)
		return
	}

	nodeTaints := map[string][]v1.Taint{}
	for _, node := range nodes.Items {
		nodeTaints[node.Name] = node.Spec.Taints
	}

	namespaces, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing namespaces: %v", err), globals.K8S_TAINTS_TOLERATIONS_MODULE_NAME)
		return
	}

	headersPods := []string{
		"Namespace", "PodName", "NodeName", "ToleratedTaints",
	}
	var outputRowsPods [][]string
	var lootContentsPods []string

	allTaintsSet := map[string]struct{}{}
	taintTolerated := map[string]bool{}

	for _, ns := range namespaces.Items {
		pods, err := clientset.CoreV1().Pods(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			logger.ErrorM(fmt.Sprintf("Error listing pods in namespace: %v", err), globals.K8S_TAINTS_TOLERATIONS_MODULE_NAME)
			continue
		}

		for _, pod := range pods.Items {
			nodeName := pod.Spec.NodeName
			if nodeName == "" {
				continue
			}

			taints := nodeTaints[nodeName]
			var toleratedTaints []string

			for _, taint := range taints {
				taintKey := fmt.Sprintf("%s:%s=%s", taint.Key, taint.Effect, taint.Value)
				allTaintsSet[taintKey] = struct{}{}
				if toleratesAnyTaint(pod.Spec.Tolerations, taint) {
					toleratedTaints = append(toleratedTaints, taintKey)
					taintTolerated[taintKey] = true
				} else {
					if _, seen := taintTolerated[taintKey]; !seen {
						taintTolerated[taintKey] = false
					}
				}
			}

			toleratedStr := "<NONE>"
			if len(toleratedTaints) > 0 {
				toleratedStr = strings.Join(toleratedTaints, "\n")
			}

			row := []string{
				k8sinternal.NonEmpty(pod.Namespace),
				k8sinternal.NonEmpty(pod.Name),
				k8sinternal.NonEmpty(nodeName),
				toleratedStr,
			}
			outputRowsPods = append(outputRowsPods, row)

			lootContentsPods = append(lootContentsPods,
				fmt.Sprintf("Namespace: %s\nPod: %s\nNode: %s\nToleratedTaints:\n%s\n",
					pod.Namespace, pod.Name, nodeName, toleratedStr),
			)
		}
	}

	// Build pod toleration table and loot
	podsTable := internal.TableFile{
		Name:   "PodTolerations",
		Header: headersPods,
		Body:   outputRowsPods,
	}
	podsLoot := internal.LootFile{
		Name:     "PodTolerations-info",
		Contents: strings.Join(lootContentsPods, "\n---\n"),
	}

	// Unmatched taints
	headersTaints := []string{"Taint"}
	var outputRowsTaints [][]string
	var lootContentsTaints []string

	for taint := range allTaintsSet {
		if tolerated, ok := taintTolerated[taint]; !ok || !tolerated {
			outputRowsTaints = append(outputRowsTaints, []string{taint})
			lootContentsTaints = append(lootContentsTaints, taint)
		}
	}
	if len(outputRowsTaints) == 0 {
		outputRowsTaints = append(outputRowsTaints, []string{"<NONE>"})
		lootContentsTaints = append(lootContentsTaints, "<NONE>")
	}

	taintsTable := internal.TableFile{
		Name:   "UnmatchedTaints",
		Header: headersTaints,
		Body:   outputRowsTaints,
	}
	taintsLoot := internal.LootFile{
		Name:     "UnmatchedTaints-info",
		Contents: strings.Join(lootContentsTaints, "\n"),
	}

	// Output handling
	err = internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"Taints-Tolerations",
		globals.ClusterName,
		"results",
		TaintsTolerationsOutput{
			Table: []internal.TableFile{podsTable, taintsTable},
			Loot:  []internal.LootFile{podsLoot, taintsLoot},
		},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_TAINTS_TOLERATIONS_MODULE_NAME)
		return
	}

	if len(outputRowsPods) > 0 {
		logger.InfoM(fmt.Sprintf("%d pod tolerations found", len(outputRowsPods)), globals.K8S_TAINTS_TOLERATIONS_MODULE_NAME)
	} else {
		logger.InfoM("No pod tolerations found, skipping output file creation", globals.K8S_TAINTS_TOLERATIONS_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_TAINTS_TOLERATIONS_MODULE_NAME), globals.K8S_TAINTS_TOLERATIONS_MODULE_NAME)
}

// Helper to check if pod tolerations tolerate a taint
func toleratesAnyTaint(tolerations []v1.Toleration, taint v1.Taint) bool {
	for _, tol := range tolerations {
		if toleratesTaint(tol, taint) {
			return true
		}
	}
	return false
}
