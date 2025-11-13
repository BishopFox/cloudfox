package commands

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var ConfigMapsCmd = &cobra.Command{
	Use:     "configmaps",
	Aliases: []string{"cm"},
	Short:   "List all cluster ConfigMaps",
	Long: `
List all cluster ConfigMaps and detailed information:
  cloudfox kubernetes configmaps`,
	Run: ListConfigMaps,
}

type ConfigMapsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t ConfigMapsOutput) TableFiles() []internal.TableFile {
	return t.Table
}

func (t ConfigMapsOutput) LootFiles() []internal.LootFile {
	return t.Loot
}

func ListConfigMaps(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	logger := internal.NewLogger()

	// Extract global flags
	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating configmaps for %s", globals.ClusterName), globals.K8S_CONFIGMAPS_MODULE_NAME)

	clientset := config.GetClientOrExit()

	namespaces, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing namespaces: %v", err), globals.K8S_CONFIGMAPS_MODULE_NAME)
		return
	}

	headers := []string{
		"Namespace", "Name", "Creation Timestamp", "Labels", "Annotations", "Data Keys", "Sensitive Keys",
	}

	var outputRows [][]string

	// Namespace-organized loot
	namespaceLootEnum := map[string][]string{}

	for _, ns := range namespaces.Items {
		cms, err := clientset.CoreV1().ConfigMaps(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error listing configmaps in namespace %s: %v\n", ns.Name, err)
			continue
		}

		for _, cm := range cms.Items {
			// Labels
			labels := "<NONE>"
			if len(cm.Labels) > 0 {
				var parts []string
				for k, v := range cm.Labels {
					parts = append(parts, fmt.Sprintf("%s=%s", k, v))
				}
				sort.Strings(parts)
				labels = strings.Join(parts, ",")
			}

			// Annotations
			annotations := "<NONE>"
			if len(cm.Annotations) > 0 {
				var parts []string
				for k, v := range cm.Annotations {
					parts = append(parts, fmt.Sprintf("%s=%s", k, v))
				}
				sort.Strings(parts)
				annotations = strings.Join(parts, ",")
			}

			// Data Keys
			dataKeys := "<NONE>"
			if len(cm.Data) > 0 {
				var keys []string
				for k := range cm.Data {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				dataKeys = strings.Join(keys, ",")
			}

			// Detect sensitive keys
			sensitive := detectSensitive(cm.Data)

			row := []string{
				cm.Namespace,
				cm.Name,
				cm.CreationTimestamp.String(),
				labels,
				annotations,
				dataKeys,
				sensitive,
			}
			outputRows = append(outputRows, row)

			// Loot: describe + jq
			jqCmd := fmt.Sprintf(
				`kubectl get configmap -n %s %s -o json | jq '{
Namespace: .metadata.namespace,
Name: .metadata.name,
Labels: .metadata.labels,
Annotations: .metadata.annotations,
CreationTimestamp: .metadata.creationTimestamp,
Data: .data
}'`, cm.Namespace, cm.Name)

			namespaceLootEnum[cm.Namespace] = append(namespaceLootEnum[cm.Namespace],
				fmt.Sprintf("kubectl describe configmap -n %s %s", cm.Namespace, cm.Name),
				jqCmd,
			)
		}
	}

	// Build lootEnum with namespace headers
	lootEnum := []string{
		"#####################################",
		"##### Enumerate ConfigMap Information",
		"#####################################",
		"",
	}
	if globals.KubeContext != "" {
		lootEnum = append(lootEnum, fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext))
	}

	nsListEnum := make([]string, 0, len(namespaceLootEnum))
	for ns := range namespaceLootEnum {
		nsListEnum = append(nsListEnum, ns)
	}
	sort.Strings(nsListEnum)
	for i, ns := range nsListEnum {
		lootEnum = append(lootEnum, fmt.Sprintf("\n# Namespace: %s\n", ns))
		lootEnum = append(lootEnum, namespaceLootEnum[ns]...)
		if i < len(nsListEnum)-1 {
			lootEnum = append(lootEnum, "")
		}
	}

	table := internal.TableFile{
		Name:   "ConfigMaps",
		Header: headers,
		Body:   outputRows,
	}

	lootDescribe := internal.LootFile{
		Name:     "ConfigMap-Enum",
		Contents: strings.Join(lootEnum, "\n"),
	}

	err = internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"ConfigMaps",
		globals.ClusterName,
		"results",
		ConfigMapsOutput{
			Table: []internal.TableFile{table},
			Loot:  []internal.LootFile{lootDescribe},
		},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_CONFIGMAPS_MODULE_NAME)
		return
	}

	if len(outputRows) > 0 {
		logger.InfoM(fmt.Sprintf("%d configmaps found", len(outputRows)), globals.K8S_CONFIGMAPS_MODULE_NAME)
	} else {
		logger.InfoM("No configmaps found, skipping output file creation", globals.K8S_CONFIGMAPS_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_CONFIGMAPS_MODULE_NAME), globals.K8S_CONFIGMAPS_MODULE_NAME)
}

func detectSensitive(data map[string]string) string {
	if len(data) == 0 {
		return "<NONE>"
	}

	suspects := []string{"password", "passwd", "secret", "key", "token", "credentials"}
	var hits []string
	for k, v := range data {
		lk := strings.ToLower(k)
		lv := strings.ToLower(v)
		for _, s := range suspects {
			if strings.Contains(lk, s) || strings.Contains(lv, s) {
				hits = append(hits, k)
			}
		}
	}
	if len(hits) > 0 {
		return strings.Join(hits, ",")
	}
	return "<NONE>"
}
