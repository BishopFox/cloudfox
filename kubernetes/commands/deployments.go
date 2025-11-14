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

var DeploymentsCmd = &cobra.Command{
	Use:     "deployments",
	Aliases: []string{"deploy"},
	Short:   "List all cluster deployments",
	Long: `
List all cluster deployments (controller-level and template-level information):
  cloudfox kubernetes deployments`,
	Run: ListDeployments,
}

type DeploymentsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t DeploymentsOutput) TableFiles() []internal.TableFile { return t.Table }
func (t DeploymentsOutput) LootFiles() []internal.LootFile   { return t.Loot }

func ListDeployments(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating deployments for %s", globals.ClusterName), globals.K8S_DEPLOYMENTS_MODULE_NAME)

	clientset := config.GetClientOrExit()

	deployments, err := clientset.AppsV1().Deployments("").List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing Deployments: %v", err), globals.K8S_DEPLOYMENTS_MODULE_NAME)
		return
	}

	headers := []string{
		"Namespace", "Deployment Name", "Replicas", "Service Account", "Selectors",
		"Volumes", "Containers", "Image Pull Secrets", "HostPID", "HostIPC", "HostNetwork",
		"Privileged", "HostPaths", "Labels", "Affinity", "Tolerations", "Cloud Provider", "Cloud Role",
	}

	var outputRows [][]string
	namespaceMap := make(map[string][]string)

	for _, dep := range deployments.Items {
		// Labels
		labels := k8sinternal.MapToStringList(dep.Spec.Template.Labels)

		// Selectors
		selectors := []string{}
		for k, v := range dep.Spec.Selector.MatchLabels {
			selectors = append(selectors, fmt.Sprintf("%s=%s", k, v))
		}

		// Volumes + HostPaths
		volumes := []string{}
		hostPaths := []string{}
		for _, v := range dep.Spec.Template.Spec.Volumes {
			volumes = append(volumes, v.Name)
			if v.HostPath != nil {
				mp := k8sinternal.FindMountPath(v.Name, dep.Spec.Template.Spec.Containers)
				hostPaths = append(hostPaths, fmt.Sprintf("%s:%s", v.HostPath.Path, mp))
			}
		}
		hostPathsStr := "<NONE>"
		if len(hostPaths) > 0 {
			hostPathsStr = strings.Join(hostPaths, "\n")
		}

		// Containers + Privileged
		containers := []string{}
		privileged := "false"
		for _, c := range dep.Spec.Template.Spec.Containers {
			containers = append(containers, c.Name)
			if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
				privileged = "true"
			}
		}

		// Image Pull Secrets
		pullSecrets := []string{}
		for _, ps := range dep.Spec.Template.Spec.ImagePullSecrets {
			pullSecrets = append(pullSecrets, ps.Name)
		}

		// Affinity / Tolerations
		affinity := "<NONE>"
		if dep.Spec.Template.Spec.Affinity != nil {
			affinity = k8sinternal.PrettyPrintAffinity(dep.Spec.Template.Spec.Affinity)
		}
		tolerations := "<NONE>"
		if len(dep.Spec.Template.Spec.Tolerations) > 0 {
			tol := []string{}
			for _, t := range dep.Spec.Template.Spec.Tolerations {
				tol = append(tol, fmt.Sprintf("%s:%s", t.Key, t.Operator))
			}
			tolerations = strings.Join(tol, ",")
		}

		// Cloud Role/Provider detection
		roleResults := k8sinternal.DetectCloudRole(
			ctx,
			clientset,
			dep.Namespace,
			dep.Spec.Template.Spec.ServiceAccountName,
			&dep.Spec.Template.Spec,
			dep.Spec.Template.Annotations,
		)
		cloudProvider, cloudRole := "<NONE>", "<NONE>"
		if len(roleResults) > 0 {
			cloudProvider = roleResults[0].Provider
			cloudRole = roleResults[0].Role
		}

		// Build table row
		row := []string{
			dep.Namespace,
			dep.Name,
			fmt.Sprintf("%d", *dep.Spec.Replicas),
			k8sinternal.NonEmpty(dep.Spec.Template.Spec.ServiceAccountName),
			k8sinternal.NonEmpty(strings.Join(selectors, ",")),
			k8sinternal.NonEmpty(strings.Join(volumes, ",")),
			k8sinternal.NonEmpty(strings.Join(containers, ",")),
			k8sinternal.NonEmpty(strings.Join(pullSecrets, ",")),
			k8sinternal.SafeBool(dep.Spec.Template.Spec.HostPID),
			k8sinternal.SafeBool(dep.Spec.Template.Spec.HostIPC),
			k8sinternal.SafeBool(dep.Spec.Template.Spec.HostNetwork),
			privileged,
			hostPathsStr,
			k8sinternal.NonEmpty(strings.Join(labels, ",")),
			affinity,
			tolerations,
			k8sinternal.NonEmpty(cloudProvider),
			k8sinternal.NonEmpty(cloudRole),
		}
		outputRows = append(outputRows, row)

		// Loot command per deployment (controller-level only)
		jq := `'{Namespace:.metadata.namespace,
Name:.metadata.name,
Replicas:.spec.replicas,
ServiceAccount:.spec.template.spec.serviceAccountName,
Selectors:(.spec.selector.matchLabels // {}),
Volumes:(.spec.template.spec.volumes // [] | map(.name)),
Containers:[.spec.template.spec.containers[]?.name],
ImagePullSecrets:(.spec.template.spec.imagePullSecrets // [] | map(.name)),
HostPID:(.spec.template.spec.hostPID // false),
HostIPC:(.spec.template.spec.hostIPC // false),
HostNetwork:(.spec.template.spec.hostNetwork // false),
Privileged:([.spec.template.spec.containers[]? | .securityContext?.privileged // false] | any),
HostPaths:([.spec.template.spec.volumes[]? | select(.hostPath) | {path:.hostPath.path}]),
Affinity:(.spec.template.spec.affinity // {}),
Tolerations:(.spec.template.spec.tolerations // []),
CloudProvider:"unknown",
CloudRole:"unknown"}'`
		cmdStr := fmt.Sprintf("kubectl get deployment %q -n %q -o json | jq -r %s \n", dep.Name, dep.Namespace, jq)
		namespaceMap[dep.Namespace] = append(namespaceMap[dep.Namespace], cmdStr)
	}

	// Build lootEnum with namespace separators
	lootEnum := []string{
		"#####################################",
		"##### Enumerate Deployment Information",
		"#####################################",
		"",
	}
	if globals.KubeContext != "" {
		lootEnum = append(lootEnum, fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext))
	}

	var namespaces []string
	for ns := range namespaceMap {
		namespaces = append(namespaces, ns)
	}
	sort.Strings(namespaces)

	for i, ns := range namespaces {
		lootEnum = append(lootEnum, fmt.Sprintf("\n# Namespace: %s\n", ns))
		lootEnum = append(lootEnum, namespaceMap[ns]...)
		if i < len(namespaces)-1 {
			lootEnum = append(lootEnum, "")
		}
	}

	table := internal.TableFile{
		Name:   "Deployments",
		Header: headers,
		Body:   outputRows,
	}

	loot := internal.LootFile{
		Name:     "Deployment-Enum",
		Contents: strings.Join(lootEnum, "\n"),
	}

	if err := internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"Deployments",
		globals.ClusterName,
		"results",
		DeploymentsOutput{
			Table: []internal.TableFile{table},
			Loot:  []internal.LootFile{loot},
		},
	); err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_DEPLOYMENTS_MODULE_NAME)
		return
	}

	if len(outputRows) > 0 {
		logger.InfoM(fmt.Sprintf("%d deployments found", len(outputRows)), globals.K8S_DEPLOYMENTS_MODULE_NAME)
	} else {
		logger.InfoM("No deployments found, skipping output file creation", globals.K8S_DEPLOYMENTS_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_DEPLOYMENTS_MODULE_NAME), globals.K8S_DEPLOYMENTS_MODULE_NAME)
}
