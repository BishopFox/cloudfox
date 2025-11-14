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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var StatefulSetsCmd = &cobra.Command{
	Use:     "statefulsets",
	Aliases: []string{"ss"},
	Short:   "List all cluster StatefulSets",
	Long: `
List all cluster StatefulSets:
  cloudfox kubernetes statefulsets`,
	Run: ListStatefulSets,
}

type StatefulSetsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t StatefulSetsOutput) TableFiles() []internal.TableFile { return t.Table }
func (t StatefulSetsOutput) LootFiles() []internal.LootFile   { return t.Loot }

func ListStatefulSets(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating statefulsets for %s", globals.ClusterName), globals.K8S_STATEFULSETS_MODULE_NAME)

	clientset := config.GetClientOrExit()

	statefulSets, err := clientset.AppsV1().StatefulSets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing StatefulSets: %v\n", err)
		return
	}

	headers := []string{
		"Namespace", "StatefulSet Name", "Labels", "Selectors", "Replicas",
		"HostPID", "HostIPC", "HostNetwork", "Privileged", "Volumes",
		"Service Account", "Cloud Provider", "Cloud Role",
	}

	var outputRows [][]string
	var lootEnum []string
	lootEnum = append(lootEnum, `#####################################
##### Enumerate StatefulSet Information
#####################################

`)
	if globals.KubeContext != "" {
		lootEnum = append(lootEnum, fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext))
	}

	for _, ss := range statefulSets.Items {
		labels := k8sinternal.MapToStringList(ss.Labels)
		selectors := k8sinternal.SelectorMatch(ss.Spec.Selector)

		replicas := "<NONE>"
		if ss.Spec.Replicas != nil {
			replicas = fmt.Sprintf("%d", *ss.Spec.Replicas)
		}

		privileged := "false"
		for _, c := range ss.Spec.Template.Spec.Containers {
			if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
				privileged = "true"
				break
			}
		}

		volumes := []string{}
		for _, v := range ss.Spec.Template.Spec.Volumes {
			volumes = append(volumes, v.Name)
		}

		roleResults := k8sinternal.DetectCloudRole(
			ctx,
			clientset,
			ss.Namespace,
			ss.Spec.Template.Spec.ServiceAccountName,
			&ss.Spec.Template.Spec,
			ss.Spec.Template.Annotations,
		)

		cloudProvider := "unknown"
		cloudRole := "unknown"
		if len(roleResults) > 0 {
			cloudProvider = roleResults[0].Provider
			cloudRole = roleResults[0].Role
		}

		row := []string{
			ss.Namespace,
			ss.Name,
			k8sinternal.NonEmpty(strings.Join(labels, ",")),
			k8sinternal.NonEmpty(strings.Join(selectors, ",")),
			replicas,
			fmt.Sprintf("%v", ss.Spec.Template.Spec.HostPID),
			fmt.Sprintf("%v", ss.Spec.Template.Spec.HostIPC),
			fmt.Sprintf("%v", ss.Spec.Template.Spec.HostNetwork),
			privileged,
			k8sinternal.NonEmpty(strings.Join(volumes, ",")),
			k8sinternal.NonEmpty(ss.Spec.Template.Spec.ServiceAccountName),
			k8sinternal.NonEmpty(cloudProvider),
			k8sinternal.NonEmpty(cloudRole),
		}

		outputRows = append(outputRows, row)

		// Loot command with namespace separator
		jq := `'{Namespace:.metadata.namespace,
Name:.metadata.name,
Labels:.metadata.labels,
Selectors:(.spec.selector.matchLabels // {}),
Replicas:(.spec.replicas // "<NONE>"),
Volumes:(.spec.template.spec.volumes // [] | map(.name)),
HostPID:(.spec.template.spec.hostPID // false),
HostIPC:(.spec.template.spec.hostIPC // false),
HostNetwork:(.spec.template.spec.hostNetwork // false),
Privileged:([.spec.template.spec.containers[]? | .securityContext?.privileged // false] | any),
ServiceAccount:.spec.template.spec.serviceAccountName,
CloudProvider:"unknown",
CloudRole:"unknown"}'`

		lootEnum = append(lootEnum,
			fmt.Sprintf("\n# Namespace: %s\n", ss.Namespace),
			fmt.Sprintf("kubectl get statefulset %q -n %q -o json | jq -r %s \n", ss.Name, ss.Namespace, jq))
	}

	table := internal.TableFile{
		Name:   "StatefulSets",
		Header: headers,
		Body:   outputRows,
	}

	loot := internal.LootFile{
		Name:     "StatefulSets-Enum",
		Contents: strings.Join(k8sinternal.Unique(lootEnum), "\n"),
	}

	if err := internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"StatefulSets",
		globals.ClusterName,
		"results",
		StatefulSetsOutput{
			Table: []internal.TableFile{table},
			Loot:  []internal.LootFile{loot},
		},
	); err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_STATEFULSETS_MODULE_NAME)
		return
	}

	if len(outputRows) > 0 {
		logger.InfoM(fmt.Sprintf("%d statefulsets found", len(outputRows)), globals.K8S_STATEFULSETS_MODULE_NAME)
	} else {
		logger.InfoM("No statefulsets found, skipping output file creation", globals.K8S_STATEFULSETS_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_STATEFULSETS_MODULE_NAME), globals.K8S_STATEFULSETS_MODULE_NAME)
}
