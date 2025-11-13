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

var DaemonSetsCmd = &cobra.Command{
	Use:     "daemonsets",
	Aliases: []string{"ds"},
	Short:   "List all cluster DaemonSets",
	Long: `
List all cluster DaemonSets (controller-level and template-level information):
  cloudfox kubernetes daemonsets`,
	Run: ListDaemonSets,
}

type DaemonSetsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t DaemonSetsOutput) TableFiles() []internal.TableFile { return t.Table }
func (t DaemonSetsOutput) LootFiles() []internal.LootFile   { return t.Loot }

func ListDaemonSets(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating daemonsets for %s", globals.ClusterName), globals.K8S_DAEMONSETS_MODULE_NAME)

	clientset := config.GetClientOrExit()

	daemonSets, err := clientset.AppsV1().DaemonSets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing DaemonSets: %v", err), globals.K8S_DAEMONSETS_MODULE_NAME)
		return
	}

	headers := []string{
		"Namespace", "DaemonSet Name", "Desired", "Current", "Ready", "Up To Date", "Available",
		"Service Account", "Selectors", "Volumes", "Containers", "Image Pull Secrets",
		"HostPID", "HostIPC", "HostNetwork", "Privileged", "HostPaths", "RunAsUser", "Capabilities",
		"Labels", "Annotations", "Affinity", "Tolerations",
		"Cloud Provider", "Cloud Role",
	}

	var outputRows [][]string
	var lootEnum []string

	lootEnum = append(lootEnum, `#####################################
##### Enumerate DaemonSet Information
#####################################

`)
	if globals.KubeContext != "" {
		lootEnum = append(lootEnum, fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext))
	}

	lastNamespace := ""
	for _, ds := range daemonSets.Items {
		if ds.Namespace != lastNamespace {
			lootEnum = append(lootEnum, fmt.Sprintf("\n# Namespace: %s\n", ds.Namespace))
			lastNamespace = ds.Namespace
		}

		spec := ds.Spec.Template.Spec

		labels := k8sinternal.MapToStringList(ds.Spec.Template.Labels)
		annotations := k8sinternal.MapToStringList(ds.Spec.Template.Annotations)

		// Containers
		containers := []string{}
		capabilities := []string{}
		privileged := "false"
		runAsUser := "<NONE>"

		for _, c := range spec.Containers {
			containers = append(containers, fmt.Sprintf("%s:%s", c.Name, c.Image))
			if c.SecurityContext != nil {
				if c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
					privileged = "true"
				}
				if c.SecurityContext.RunAsUser != nil {
					runAsUser = fmt.Sprintf("%d", *c.SecurityContext.RunAsUser)
				}
				if c.SecurityContext.Capabilities != nil {
					addCaps := []string{}
					for _, cap := range c.SecurityContext.Capabilities.Add {
						addCaps = append(addCaps, string(cap))
					}
					if len(addCaps) > 0 {
						capabilities = append(capabilities, strings.Join(addCaps, ","))
					}
				}
			}
		}

		// Volumes / HostPaths
		volumes := []string{}
		hostPaths := []string{}
		for _, v := range spec.Volumes {
			volumes = append(volumes, v.Name)
			if v.HostPath != nil {
				mountPoint := k8sinternal.FindMountPath(v.Name, spec.Containers)
				hostPaths = append(hostPaths, fmt.Sprintf("%s:%s", v.HostPath.Path, mountPoint))
			}
		}
		hostPathsStr := "<NONE>"
		if len(hostPaths) > 0 {
			hostPathsStr = strings.Join(hostPaths, "\n")
		}

		// Affinity / Tolerations
		affinity := "<NONE>"
		if spec.Affinity != nil {
			affinity = k8sinternal.PrettyPrintAffinity(spec.Affinity)
		}
		tolerations := "<NONE>"
		if len(spec.Tolerations) > 0 {
			tolStrs := []string{}
			for _, t := range spec.Tolerations {
				tolStrs = append(tolStrs, fmt.Sprintf("%s:%s", t.Key, t.Operator))
			}
			tolerations = strings.Join(tolStrs, ",")
		}

		// Image Pull Secrets
		pullSecrets := []string{}
		for _, ps := range spec.ImagePullSecrets {
			pullSecrets = append(pullSecrets, ps.Name)
		}

		// Cloud role detection
		roleResults := k8sinternal.DetectCloudRole(ctx, clientset, ds.Namespace, spec.ServiceAccountName, &spec, ds.Spec.Template.Annotations)
		cloudProvider, cloudRole := "<NONE>", "<NONE>"
		if len(roleResults) > 0 {
			cloudProvider = roleResults[0].Provider
			cloudRole = roleResults[0].Role
		}

		row := []string{
			ds.Namespace,
			ds.Name,
			fmt.Sprintf("%d", ds.Status.DesiredNumberScheduled),
			fmt.Sprintf("%d", ds.Status.CurrentNumberScheduled),
			fmt.Sprintf("%d", ds.Status.NumberReady),
			fmt.Sprintf("%d", ds.Status.UpdatedNumberScheduled),
			fmt.Sprintf("%d", ds.Status.NumberAvailable),
			k8sinternal.NonEmpty(spec.ServiceAccountName),
			k8sinternal.NonEmpty(strings.Join(k8sinternal.MapToStringList(spec.NodeSelector), ",")),
			k8sinternal.NonEmpty(strings.Join(volumes, ",")),
			k8sinternal.NonEmpty(strings.Join(containers, ",")),
			k8sinternal.NonEmpty(strings.Join(pullSecrets, ",")),
			k8sinternal.SafeBool(spec.HostPID),
			k8sinternal.SafeBool(spec.HostIPC),
			k8sinternal.SafeBool(spec.HostNetwork),
			privileged,
			hostPathsStr,
			runAsUser,
			k8sinternal.NonEmpty(strings.Join(capabilities, ",")),
			k8sinternal.NonEmpty(strings.Join(labels, ",")),
			k8sinternal.NonEmpty(strings.Join(annotations, ",")),
			affinity,
			tolerations,
			k8sinternal.NonEmpty(cloudProvider),
			k8sinternal.NonEmpty(cloudRole),
		}
		outputRows = append(outputRows, row)

		lootCmd := fmt.Sprintf(
			"kubectl get daemonset %s -n %s -o json | jq '{Namespace:.metadata.namespace, Name:.metadata.name, Desired:.status.desiredNumberScheduled, Current:.status.currentNumberScheduled, Ready:.status.numberReady, Updated:.status.updatedNumberScheduled, Available:.status.numberAvailable, ServiceAccount:.spec.template.spec.serviceAccountName, Labels:.spec.template.metadata.labels, Annotations:.spec.template.metadata.annotations, NodeSelector:.spec.template.spec.nodeSelector, Volumes:(.spec.template.spec.volumes // [] | map(.name)), Containers:[.spec.template.spec.containers[]?|{name:.name,image:.image}], ImagePullSecrets:.spec.template.spec.imagePullSecrets, HostPID:.spec.template.spec.hostPID, HostIPC:.spec.template.spec.hostIPC, HostNetwork:.spec.template.spec.hostNetwork, Privileged:[.spec.template.spec.containers[]?|.securityContext?.privileged] | any, HostPaths:[.spec.template.spec.volumes[]?|select(.hostPath)|{path:.hostPath.path}], RunAsUser:[.spec.template.spec.containers[]?|.securityContext?.runAsUser] | unique, Capabilities:[.spec.template.spec.containers[]?|.securityContext?.capabilities?.add] | flatten | unique, Affinity:.spec.template.spec.affinity, Tolerations:.spec.template.spec.tolerations}'",
			ds.Name, ds.Namespace,
		)
		lootEnum = append(lootEnum, lootCmd)
	}

	table := internal.TableFile{
		Name:   "DaemonSets",
		Header: headers,
		Body:   outputRows,
	}

	loot := internal.LootFile{
		Name:     "DaemonSet-Enum",
		Contents: strings.Join(lootEnum, "\n"),
	}

	if err := internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"DaemonSets",
		globals.ClusterName,
		"results",
		DaemonSetsOutput{
			Table: []internal.TableFile{table},
			Loot:  []internal.LootFile{loot},
		},
	); err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_DAEMONSETS_MODULE_NAME)
		return
	}

	if len(outputRows) > 0 {
		logger.InfoM(fmt.Sprintf("%d daemonsets found", len(outputRows)), globals.K8S_DAEMONSETS_MODULE_NAME)
	} else {
		logger.InfoM("No daemonsets found, skipping output file creation", globals.K8S_DAEMONSETS_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_DAEMONSETS_MODULE_NAME), globals.K8S_DAEMONSETS_MODULE_NAME)
}
