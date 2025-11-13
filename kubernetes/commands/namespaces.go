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

var NamespacesCmd = &cobra.Command{
	Use:     "namespaces",
	Aliases: []string{"ns"},
	Short:   "List all cluster Namespaces",
	Long: `
List all cluster Namespaces:
  cloudfox kubernetes namespaces`,
	Run: ListNamespaces,
}

type NamespacesOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t NamespacesOutput) TableFiles() []internal.TableFile {
	return t.Table
}

func (t NamespacesOutput) LootFiles() []internal.LootFile {
	return t.Loot
}

func ListNamespaces(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	logger := internal.NewLogger()

	// Extract global flags
	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	clientset := config.GetClientOrExit()
	if clientset == nil {
		logger.ErrorM("Error getting Kubernetes client:", globals.K8S_NAMESPACES_MODULE_NAME)
		os.Exit(1)
	}

	namespaces, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing namespaces: %v", err), globals.K8S_NAMESPACES_MODULE_NAME)
		return
	}

	headers := []string{
		"Namespace", "Phase", "Creation Timestamp", "Labels", "Annotations",
	}

	var outputRows [][]string
	lootEnum := strings.Builder{}

	// Loot file header
	lootEnum.WriteString(`#####################################
##### Enumerate Namespace Information
#####################################

`)
	if globals.KubeContext != "" {
		lootEnum.WriteString(fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext))
	}

	for _, ns := range namespaces.Items {
		labels := []string{}
		for k, v := range ns.Labels {
			labels = append(labels, fmt.Sprintf("%s=%s", k, v))
		}

		annotations := []string{}
		for k, v := range ns.Annotations {
			annotations = append(annotations, fmt.Sprintf("%s=%s", k, v))
		}

		row := []string{
			ns.Name,
			string(ns.Status.Phase),
			ns.CreationTimestamp.String(),
			k8sinternal.NonEmpty(strings.Join(labels, "\n")),
			k8sinternal.NonEmpty(strings.Join(annotations, "\n")),
		}
		outputRows = append(outputRows, row)

		// Add kubectl + jq command for this namespace
		lootEnum.WriteString(fmt.Sprintf(
			"# Namespace: %s\nkubectl get namespace %s -o json | jq '{name: .metadata.name, labels: .metadata.labels, annotations: .metadata.annotations, status: .status, creationTimestamp: .metadata.creationTimestamp}'\n\n",
			ns.Name, ns.Name,
		))
	}

	table := internal.TableFile{
		Name:   "Namespaces",
		Header: headers,
		Body:   outputRows,
	}

	loot := internal.LootFile{
		Name:     "Namespace-Enum",
		Contents: lootEnum.String(),
	}

	err = internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"Namespaces",
		globals.ClusterName,
		"results",
		NamespacesOutput{
			Table: []internal.TableFile{table},
			Loot:  []internal.LootFile{loot},
		},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_NAMESPACES_MODULE_NAME)
	}
}
