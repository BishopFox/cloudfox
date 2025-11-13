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

var JobsCmd = &cobra.Command{
	Use:   "jobs",
	Short: "List all cluster Jobs",
	Long: `
List all cluster Jobs (controller-level and template-level information):
  cloudfox kubernetes jobs`,
	Run: ListJobs,
}

type JobsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t JobsOutput) TableFiles() []internal.TableFile { return t.Table }
func (t JobsOutput) LootFiles() []internal.LootFile   { return t.Loot }

func ListJobs(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating jobs for %s", globals.ClusterName), globals.K8S_JOBS_MODULE_NAME)

	clientset := config.GetClientOrExit()

	jobs, err := clientset.BatchV1().Jobs("").List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing Jobs: %v", err), globals.K8S_JOBS_MODULE_NAME)
		return
	}

	headers := []string{
		"Namespace", "Job Name", "Completions", "Parallelism", "Backoff Limit", "Active", "Succeeded", "Failed",
		"Labels", "Annotations", "Containers", "Volumes", "Image Pull Secrets",
		"HostPID", "HostIPC", "HostNetwork", "Privileged", "HostPaths",
		"Affinity", "Tolerations", "Cloud Provider", "Cloud Role",
	}
	var outputRows [][]string
	namespaceMap := make(map[string][]string)

	for _, job := range jobs.Items {
		podSpec := job.Spec.Template.Spec

		labels := k8sinternal.MapToStringList(job.Labels)
		annotations := k8sinternal.MapToStringList(job.Annotations)

		// Containers + Privileged
		containers := []string{}
		privileged := "false"
		for _, c := range podSpec.Containers {
			containers = append(containers, fmt.Sprintf("%s:%s", c.Name, c.Image))
			if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
				privileged = "true"
			}
		}

		// Volumes + HostPaths
		volumes := []string{}
		hostPaths := []string{}
		for _, v := range podSpec.Volumes {
			volumes = append(volumes, v.Name)
			if v.HostPath != nil {
				mp := k8sinternal.FindMountPath(v.Name, podSpec.Containers)
				hostPaths = append(hostPaths, fmt.Sprintf("%s:%s", v.HostPath.Path, mp))
			}
		}
		hostPathsStr := "<NONE>"
		if len(hostPaths) > 0 {
			hostPathsStr = strings.Join(hostPaths, "\n")
		}

		// ImagePullSecrets
		pullSecrets := []string{}
		for _, ps := range podSpec.ImagePullSecrets {
			pullSecrets = append(pullSecrets, ps.Name)
		}

		// Affinity / Tolerations
		affinity := "<NONE>"
		if podSpec.Affinity != nil {
			affinity = k8sinternal.PrettyPrintAffinity(podSpec.Affinity)
		}
		tolerations := "<NONE>"
		if len(podSpec.Tolerations) > 0 {
			tol := []string{}
			for _, t := range podSpec.Tolerations {
				tol = append(tol, fmt.Sprintf("%s:%s", t.Key, t.Operator))
			}
			tolerations = strings.Join(tol, ",")
		}

		// Cloud Role/Provider
		roleResults := k8sinternal.DetectCloudRole(ctx, clientset, job.Namespace, podSpec.ServiceAccountName, &podSpec, job.Spec.Template.Annotations)
		cloudProvider, cloudRole := "<NONE>", "<NONE>"
		if len(roleResults) > 0 {
			cloudProvider = roleResults[0].Provider
			cloudRole = roleResults[0].Role
		}

		row := []string{
			job.Namespace,
			job.Name,
			k8sinternal.SafeInt32(job.Spec.Completions),
			k8sinternal.SafeInt32(job.Spec.Parallelism),
			k8sinternal.SafeInt32(job.Spec.BackoffLimit),
			fmt.Sprintf("%v", job.Status.Active),
			fmt.Sprintf("%v", job.Status.Succeeded),
			fmt.Sprintf("%v", job.Status.Failed),
			k8sinternal.NonEmpty(strings.Join(labels, ",")),
			k8sinternal.NonEmpty(strings.Join(annotations, ",")),
			k8sinternal.NonEmpty(strings.Join(containers, ",")),
			k8sinternal.NonEmpty(strings.Join(volumes, ",")),
			k8sinternal.NonEmpty(strings.Join(pullSecrets, ",")),
			k8sinternal.SafeBool(podSpec.HostPID),
			k8sinternal.SafeBool(podSpec.HostIPC),
			k8sinternal.SafeBool(podSpec.HostNetwork),
			privileged,
			hostPathsStr,
			affinity,
			tolerations,
			k8sinternal.NonEmpty(cloudProvider),
			k8sinternal.NonEmpty(cloudRole),
		}
		outputRows = append(outputRows, row)

		// Loot JSON (controller-level only)
		jq := `'{Namespace:.metadata.namespace,
Name:.metadata.name,
Completions:.spec.completions,
Parallelism:.spec.parallelism,
BackoffLimit:.spec.backoffLimit,
Active:.status.active,
Succeeded:.status.succeeded,
Failed:.status.failed,
ServiceAccount:.spec.template.spec.serviceAccountName,
Labels:.metadata.labels,
Annotations:.metadata.annotations,
Volumes:(.spec.template.spec.volumes // [] | map(.name)),
Containers:[.spec.template.spec.containers[]?|{name:.name,image:.image}],
ImagePullSecrets:(.spec.template.spec.imagePullSecrets // [] | map(.name)),
HostPID:(.spec.template.spec.hostPID // false),
HostIPC:(.spec.template.spec.hostIPC // false),
HostNetwork:(.spec.template.spec.hostNetwork // false),
Privileged:([.spec.template.spec.containers[]?|.securityContext?.privileged // false] | any),
HostPaths:([.spec.template.spec.volumes[]?|select(.hostPath)|{path:.hostPath.path,mounts:([.spec.template.spec.containers[]?|.volumeMounts[]?|select(.name==.name)|.mountPath])}]),
Affinity:(.spec.template.spec.affinity // {}),
Tolerations:(.spec.template.spec.tolerations // []),
CloudProvider:"unknown",
CloudRole:"unknown"}'`
		cmdStr := fmt.Sprintf("kubectl get job %q -n %q -o json | jq -r %s \n", job.Name, job.Namespace, jq)
		namespaceMap[job.Namespace] = append(namespaceMap[job.Namespace], cmdStr)
	}

	// Build lootEnum
	lootEnum := []string{
		"#####################################",
		"##### Enumerate Job Information",
		"#####################################",
		"",
	}
	if globals.KubeContext != "" {
		lootEnum = append(lootEnum, fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext))
	}

	namespaces := make([]string, 0, len(namespaceMap))
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
		Name:   "Jobs",
		Header: headers,
		Body:   outputRows,
	}
	loot := internal.LootFile{
		Name:     "Job-Enum",
		Contents: strings.Join(lootEnum, "\n"),
	}

	if err := internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"Jobs",
		globals.ClusterName,
		"results",
		JobsOutput{
			Table: []internal.TableFile{table},
			Loot:  []internal.LootFile{loot},
		},
	); err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_JOBS_MODULE_NAME)
		return
	}

	if len(outputRows) > 0 {
		logger.InfoM(fmt.Sprintf("%d jobs found", len(outputRows)), globals.K8S_JOBS_MODULE_NAME)
	} else {
		logger.InfoM("No jobs found, skipping output file creation", globals.K8S_JOBS_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_JOBS_MODULE_NAME), globals.K8S_JOBS_MODULE_NAME)
}
