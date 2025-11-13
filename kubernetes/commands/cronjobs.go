package commands

import (
	"context"
	"encoding/json"
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

var CronJobsCmd = &cobra.Command{
	Use:     "cronjobs",
	Aliases: []string{"cj"},
	Short:   "List all cluster CronJobs",
	Long: `
List all cluster CronJobs:
  cloudfox kubernetes cronjobs`,
	Run: ListCronJobs,
}

type CronJobsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t CronJobsOutput) TableFiles() []internal.TableFile { return t.Table }
func (t CronJobsOutput) LootFiles() []internal.LootFile   { return t.Loot }

func ListCronJobs(cmd *cobra.Command, args []string) {
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
		logger.ErrorM("Error getting Kubernetes client:", globals.K8S_CRONJOBS_MODULE_NAME)
		os.Exit(1)
	}

	cronJobs, err := clientset.BatchV1().CronJobs("").List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing CronJobs: %v", err), globals.K8S_CRONJOBS_MODULE_NAME)
		return
	}

	headers := []string{
		"Namespace", "Name", "Schedule", "Concurrency Policy", "Suspend",
		"Successful Jobs History Limit", "Failed Jobs History Limit",
		"Service Account", "Containers", "Volumes",
		"HostPID", "HostIPC", "HostNetwork", "Privileged", "HostPaths",
		"Labels", "Annotations", "Affinity", "Tolerations",
		"Cloud Provider", "Cloud Role",
	}

	var outputRows [][]string
	var lootEnum []string
	lootEnum = append(lootEnum, `#####################################
##### Enumerate CronJob Information
#####################################

`)
	if globals.KubeContext != "" {
		lootEnum = append(lootEnum, fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext))
	}

	// Group by namespace for loot separators
	namespaceGroups := make(map[string][]string)

	for _, cj := range cronJobs.Items {
		podSpec := cj.Spec.JobTemplate.Spec.Template.Spec

		// Containers
		containers := []string{}
		privileged := "false"
		for _, c := range podSpec.Containers {
			containers = append(containers, fmt.Sprintf("%s:%s", c.Name, c.Image))
			if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
				privileged = "true"
			}
		}

		// Volumes / HostPaths
		volumes := []string{}
		hostPathLines := []string{}
		for _, v := range podSpec.Volumes {
			volumes = append(volumes, v.Name)
			if v.HostPath != nil {
				mountPoint := k8sinternal.FindMountPath(v.Name, podSpec.Containers)
				hostPathLines = append(hostPathLines, fmt.Sprintf("%s:%s", v.HostPath.Path, mountPoint))
			}
		}
		hostPaths := strings.Join(hostPathLines, "\n")

		// Labels / Annotations / Affinity / Tolerations
		labels := k8sinternal.MapToStringList(cj.Spec.JobTemplate.Spec.Template.Labels)
		annotations := k8sinternal.MapToStringList(cj.Spec.JobTemplate.Spec.Template.Annotations)
		affinityStr := formatAffinity(podSpec.Affinity)
		tolerationsStr := formatTolerations(podSpec.Tolerations)

		// Cloud role detection
		provider, role := "<NONE>", "<NONE>"
		if podSpec.ServiceAccountName != "" {
			roleResults := k8sinternal.DetectCloudRole(
				ctx,
				clientset,
				cj.Namespace,
				podSpec.ServiceAccountName,
				&podSpec,
				cj.Spec.JobTemplate.Spec.Template.Annotations,
			)
			if len(roleResults) > 0 {
				provider = roleResults[0].Provider
				role = roleResults[0].Role
			}
		}

		row := []string{
			cj.Namespace,
			cj.Name,
			cj.Spec.Schedule,
			string(cj.Spec.ConcurrencyPolicy),
			k8sinternal.SafeBoolPtr(cj.Spec.Suspend),
			k8sinternal.SafeInt32Ptr(cj.Spec.SuccessfulJobsHistoryLimit),
			k8sinternal.SafeInt32Ptr(cj.Spec.FailedJobsHistoryLimit),
			k8sinternal.NonEmpty(podSpec.ServiceAccountName),
			k8sinternal.NonEmpty(strings.Join(containers, ",")),
			k8sinternal.NonEmpty(strings.Join(volumes, ",")),
			k8sinternal.SafeBool(podSpec.HostPID),
			k8sinternal.SafeBool(podSpec.HostIPC),
			k8sinternal.SafeBool(podSpec.HostNetwork),
			privileged,
			hostPaths,
			k8sinternal.NonEmpty(strings.Join(labels, ",")),
			k8sinternal.NonEmpty(strings.Join(annotations, ",")),
			affinityStr,
			tolerationsStr,
			provider,
			role,
		}
		outputRows = append(outputRows, row)

		// Loot jq (controller + template only)
		cmdStr := fmt.Sprintf(
			`kubectl get cronjob -n %s %s -o json | jq '{Namespace:.metadata.namespace, Name:.metadata.name, Schedule:.spec.schedule, ConcurrencyPolicy:.spec.concurrencyPolicy, Suspend:.spec.suspend, SuccessfulJobsHistoryLimit:.spec.successfulJobsHistoryLimit, FailedJobsHistoryLimit:.spec.failedJobsHistoryLimit, ServiceAccount:.spec.jobTemplate.spec.template.spec.serviceAccountName, Labels:.spec.jobTemplate.spec.template.metadata.labels, Annotations:.spec.jobTemplate.spec.template.metadata.annotations, Affinity:.spec.jobTemplate.spec.template.spec.affinity, Tolerations:.spec.jobTemplate.spec.template.spec.tolerations, Volumes:(.spec.jobTemplate.spec.template.spec.volumes // [] | map(.name)), HostPID:(.spec.jobTemplate.spec.template.spec.hostPID // false), HostIPC:(.spec.jobTemplate.spec.template.spec.hostIPC // false), HostNetwork:(.spec.jobTemplate.spec.template.spec.hostNetwork // false), Privileged:([.spec.jobTemplate.spec.template.spec.containers[]? | .securityContext?.privileged // false] | any)}'`,
			cj.Namespace, cj.Name,
		)
		namespaceGroups[cj.Namespace] = append(namespaceGroups[cj.Namespace], cmdStr)
	}

	// Assemble lootEnum
	for ns, cmds := range namespaceGroups {
		lootEnum = append(lootEnum,
			fmt.Sprintf("\n# Namespace: %s\n", ns),
			strings.Join(cmds, "\n"),
		)
	}

	table := internal.TableFile{Name: "CronJobs", Header: headers, Body: outputRows}
	loot := internal.LootFile{Name: "Cronjob-Enum", Contents: strings.Join(lootEnum, "\n")}

	err = internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"CronJobs",
		globals.ClusterName,
		"results",
		CronJobsOutput{Table: []internal.TableFile{table}, Loot: []internal.LootFile{loot}},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_CRONJOBS_MODULE_NAME)
	}
}

// --- local formatters ---
func formatAffinity(affinity *v1.Affinity) string {
	if affinity == nil {
		return ""
	}
	b, err := json.Marshal(affinity)
	if err != nil {
		return ""
	}
	return string(b)
}

func formatTolerations(tols []v1.Toleration) string {
	if len(tols) == 0 {
		return ""
	}
	b, err := json.Marshal(tols)
	if err != nil {
		return ""
	}
	return string(b)
}
