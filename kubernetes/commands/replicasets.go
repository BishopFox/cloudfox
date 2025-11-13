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

var ReplicaSetsCmd = &cobra.Command{
	Use:     "replicasets",
	Aliases: []string{"rs"},
	Short:   "List all cluster ReplicaSets",
	Long: `
List all cluster ReplicaSets (controller-level only):
  cloudfox kubernetes replicasets`,
	Run: ListReplicaSets,
}

type ReplicaSetsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t ReplicaSetsOutput) TableFiles() []internal.TableFile {
	return t.Table
}

func (t ReplicaSetsOutput) LootFiles() []internal.LootFile {
	return t.Loot
}

func ListReplicaSets(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating replicasets for %s", globals.ClusterName), globals.K8S_REPLICASETS_MODULE_NAME)

	clientset := config.GetClientOrExit()

	replicaSets, err := clientset.AppsV1().ReplicaSets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing ReplicaSets: %v\n", err)
		return
	}

	headers := []string{
		"Namespace", "ReplicaSet Name", "Deployment Name", "Replicas", "Desired", "Current", "Ready", "Up To Date", "Available",
		"Service Account", "Selectors", "Volumes", "Containers", "Image Pull Secrets",
		"HostPID", "HostIPC", "HostNetwork", "Privileged", "HostPaths", "Labels", "Tolerations", "Cloud Provider", "Cloud Role",
	}

	var outputRows [][]string
	namespaceLootEnum := map[string][]string{}

	for _, rs := range replicaSets.Items {
		labels := []string{}
		for k, v := range rs.Labels {
			labels = append(labels, fmt.Sprintf("%s=%s", k, v))
		}

		selectors := []string{}
		for k, v := range rs.Spec.Selector.MatchLabels {
			selectors = append(selectors, fmt.Sprintf("%s=%s", k, v))
		}

		tolerations := []string{}
		for _, t := range rs.Spec.Template.Spec.Tolerations {
			tolerations = append(tolerations, fmt.Sprintf("Key=%s,Op=%s,Val=%s,Effect=%s", t.Key, t.Operator, t.Value, t.Effect))
		}

		volumes := []string{}
		hostPathLines := []string{}
		for _, v := range rs.Spec.Template.Spec.Volumes {
			volumes = append(volumes, v.Name)
			if v.HostPath != nil {
				mountPoint := k8sinternal.FindMountPath(v.Name, rs.Spec.Template.Spec.Containers)
				hostPathLines = append(hostPathLines, fmt.Sprintf("%s:%s", v.HostPath.Path, mountPoint))
			}
		}
		hostPaths := "<NONE>"
		if len(hostPathLines) > 0 {
			hostPaths = strings.Join(hostPathLines, "\n")
		}

		containers := []string{}
		privileged := "false"
		for _, c := range rs.Spec.Template.Spec.Containers {
			containers = append(containers, c.Name)
			if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
				privileged = "true"
			}
		}

		pullSecrets := []string{}
		for _, ps := range rs.Spec.Template.Spec.ImagePullSecrets {
			pullSecrets = append(pullSecrets, ps.Name)
		}

		roleResults := k8sinternal.DetectCloudRole(
			ctx,
			clientset,
			rs.Namespace,
			rs.Spec.Template.Spec.ServiceAccountName,
			&rs.Spec.Template.Spec,
			rs.Spec.Template.Annotations,
		)
		cloudProvider, cloudRole := "<NONE>", "<NONE>"
		if len(roleResults) > 0 {
			cloudProvider = roleResults[0].Provider
			cloudRole = roleResults[0].Role
		}

		// Table row: controller-level only
		row := []string{
			rs.Namespace,
			rs.Name,
			k8sinternal.NonEmpty(rs.Annotations["deployment.kubernetes.io/desired-name"]), // optional Deployment Name
			fmt.Sprintf("%d", *rs.Spec.Replicas),
			fmt.Sprintf("%d", rs.Status.Replicas),
			fmt.Sprintf("%d", rs.Status.ReadyReplicas),
			fmt.Sprintf("%d", rs.Status.FullyLabeledReplicas),
			fmt.Sprintf("%d", rs.Status.AvailableReplicas),
			k8sinternal.NonEmpty(rs.Spec.Template.Spec.ServiceAccountName),
			k8sinternal.NonEmpty(strings.Join(selectors, ",")),
			k8sinternal.NonEmpty(strings.Join(volumes, ",")),
			k8sinternal.NonEmpty(strings.Join(containers, ",")),
			k8sinternal.NonEmpty(strings.Join(pullSecrets, ",")),
			k8sinternal.SafeBool(rs.Spec.Template.Spec.HostPID),
			k8sinternal.SafeBool(rs.Spec.Template.Spec.HostIPC),
			k8sinternal.SafeBool(rs.Spec.Template.Spec.HostNetwork),
			privileged,
			hostPaths,
			k8sinternal.NonEmpty(strings.Join(labels, ",")),
			k8sinternal.NonEmpty(strings.Join(tolerations, ";")),
			k8sinternal.NonEmpty(cloudProvider),
			k8sinternal.NonEmpty(cloudRole),
		}

		outputRows = append(outputRows, row)

		// Loot per-ReplicaSet
		jq := `'{Namespace:.metadata.namespace,
Name:.metadata.name,
DeploymentName:(.metadata.annotations["deployment.kubernetes.io/desired-name"] // "<NONE>"),
Replicas:.spec.replicas,
Desired:.status.replicas,
Current:.status.readyReplicas,
Ready:.status.updatedReplicas,
UpToDate:.status.updatedReplicas,
Available:.status.availableReplicas,
ServiceAccount:.spec.template.spec.serviceAccountName,
Node:(.spec.template.spec.nodeName // "<N/A>"),
Selectors:(.spec.selector.matchLabels // {}),
Volumes:(.spec.template.spec.volumes // [] | map(.name)),
Containers:[.spec.template.spec.containers[]?.name],
ImagePullSecrets:(.spec.template.spec.imagePullSecrets // [] | map(.name)),
HostPID:(.spec.template.spec.hostPID // false),
HostIPC:(.spec.template.spec.hostIPC // false),
HostNetwork:(.spec.template.spec.hostNetwork // false),
Privileged:([.spec.template.spec.containers[]? | .securityContext?.privileged // false] | any),
HostPaths:([.spec.template.spec.volumes[]? | select(.hostPath) | {path:.hostPath.path}]),
CloudProvider:"unknown",
CloudRole:"unknown"}'`
		namespaceLootEnum[rs.Namespace] = append(namespaceLootEnum[rs.Namespace],
			fmt.Sprintf("kubectl get replicaset %q -n %q -o json | jq -r %s \n", rs.Name, rs.Namespace, jq))
	}

	// Build lootEnum with namespace headers
	lootEnum := []string{
		"#####################################",
		"##### Enumerate ReplicaSet Information",
		"#####################################",
		"",
	}
	if globals.KubeContext != "" {
		lootEnum = append(lootEnum, fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext))
	}

	nsList := make([]string, 0, len(namespaceLootEnum))
	for ns := range namespaceLootEnum {
		nsList = append(nsList, ns)
	}
	sort.Strings(nsList)

	for i, ns := range nsList {
		lootEnum = append(lootEnum, fmt.Sprintf("\n# Namespace: %s\n", ns))
		lootEnum = append(lootEnum, namespaceLootEnum[ns]...)
		if i < len(nsList)-1 {
			lootEnum = append(lootEnum, "")
		}
	}

	table := internal.TableFile{
		Name:   "ReplicaSets",
		Header: headers,
		Body:   outputRows,
	}

	loot := internal.LootFile{
		Name:     "ReplicaSets-Enum",
		Contents: strings.Join(lootEnum, "\n"),
	}

	if err := internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"ReplicaSets",
		globals.ClusterName,
		"results",
		ReplicaSetsOutput{
			Table: []internal.TableFile{table},
			Loot:  []internal.LootFile{loot},
		},
	); err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_REPLICASETS_MODULE_NAME)
		return
	}

	if len(outputRows) > 0 {
		logger.InfoM(fmt.Sprintf("%d replicasets found", len(outputRows)), globals.K8S_REPLICASETS_MODULE_NAME)
	} else {
		logger.InfoM("No replicasets found, skipping output file creation", globals.K8S_REPLICASETS_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_REPLICASETS_MODULE_NAME), globals.K8S_REPLICASETS_MODULE_NAME)
}
