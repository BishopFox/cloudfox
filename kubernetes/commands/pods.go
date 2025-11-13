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

var PodsCmd = &cobra.Command{
	Use:     "pods",
	Aliases: []string{},
	Short:   "List all cluster pods",
	Long: `
List all cluster pods and detailed information:
  cloudfox kubernetes pods`,
	Run: ListPods,
}

type PodsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t PodsOutput) TableFiles() []internal.TableFile {
	return t.Table
}

func (t PodsOutput) LootFiles() []internal.LootFile {
	return t.Loot
}

func ListPods(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	clientset := config.GetClientOrExit()
	if clientset == nil {
		logger.ErrorM("Error getting Kubernetes client:", globals.K8S_PODS_MODULE_NAME)
		os.Exit(1)
	}

	namespaces, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing namespaces: %v", err), globals.K8S_PODS_MODULE_NAME)
		return
	}

	headers := []string{
		"Namespace", "Pod Name", "Pod IP", "Service Account", "Node",
		"HostPID", "HostIPC", "HostNetwork", "Privileged", "HostPaths",
		"RunAsUser", "Capabilities", "Image", "ImageTagType", "Labels",
		"Affinity", "Tolerations", "Annotations",
		"Cloud Provider", "Cloud Role",
	}

	var outputRows [][]string

	// Namespace-organized loot
	namespaceLootExec := map[string][]string{}
	namespaceLootEnum := map[string][]string{}

	for _, ns := range namespaces.Items {
		pods, err := clientset.CoreV1().Pods(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error listing pods in namespace %s: %v\n", ns.Name, err)
			continue
		}

		for _, pod := range pods.Items {
			privileged := "false"
			runAsUser := "<unset>"
			capabilities := []string{}
			images := []string{}
			tagTypes := []string{}

			for _, container := range append(pod.Spec.InitContainers, pod.Spec.Containers...) {
				if container.SecurityContext != nil {
					if container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
						privileged = "true"
					}
					if container.SecurityContext.RunAsUser != nil {
						if *container.SecurityContext.RunAsUser == 0 {
							runAsUser = "root"
						} else {
							runAsUser = fmt.Sprintf("%d", *container.SecurityContext.RunAsUser)
						}
					}
					if container.SecurityContext != nil && container.SecurityContext.Capabilities != nil {
						for _, cap := range container.SecurityContext.Capabilities.Add {
							capabilities = append(capabilities, string(cap))
						}
						for _, cap := range container.SecurityContext.Capabilities.Drop {
							capabilities = append(capabilities, "-"+string(cap))
						}
					}

				}

				// Image info
				images = append(images, container.Image)
				tagTypes = append(tagTypes, k8sinternal.ImageTagType(container.Image))

			}

			// Labels
			labels := "<NONE>"
			if len(pod.Labels) > 0 {
				var parts []string
				for k, v := range pod.Labels {
					parts = append(parts, fmt.Sprintf("%s=%s", k, v))
				}
				sort.Strings(parts)
				labels = strings.Join(parts, ",")
			}

			// Affinity
			affinity := "<NONE>"
			if pod.Spec.Affinity != nil {
				affinity = fmt.Sprintf("%+v", *pod.Spec.Affinity)
			}

			// Tolerations
			tolerations := "<NONE>"
			if len(pod.Spec.Tolerations) > 0 {
				var tParts []string
				for _, t := range pod.Spec.Tolerations {
					tParts = append(tParts, fmt.Sprintf("Key=%s,Operator=%s,Value=%s,Effect=%s", t.Key, string(t.Operator), t.Value, string(t.Effect)))
				}
				tolerations = strings.Join(tParts, "; ")
			}

			// Annotations
			annotations := "<NONE>"
			if len(pod.Annotations) > 0 {
				var parts []string
				for k, v := range pod.Annotations {
					parts = append(parts, fmt.Sprintf("%s=%s", k, v))
				}
				sort.Strings(parts)
				annotations = strings.Join(parts, ",")
			}

			// HostPaths
			var hostPathLines []string
			for _, volume := range pod.Spec.Volumes {
				if volume.HostPath != nil {
					mountPoint := k8sinternal.FindMountPath(volume.Name, pod.Spec.Containers)
					hostPathLines = append(hostPathLines, fmt.Sprintf("%s:%s", volume.HostPath.Path, mountPoint))
				}
			}
			hostPaths := "<NONE>"
			if len(hostPathLines) > 0 {
				hostPaths = strings.Join(hostPathLines, "\n")
			}

			roleResults := k8sinternal.DetectCloudRole(ctx, clientset, pod.Namespace, pod.Spec.ServiceAccountName, &pod.Spec, pod.Annotations)

			// Access the provider and role like this:
			cloudProvider := "<NONE>"
			cloudRole := "<NONE>"
			if len(roleResults) > 0 {
				cloudProvider = roleResults[0].Provider
				cloudRole = roleResults[0].Role
			}

			row := []string{
				pod.Namespace,
				pod.Name,
				k8sinternal.NonEmpty(pod.Status.PodIP),
				k8sinternal.NonEmpty(pod.Spec.ServiceAccountName),
				k8sinternal.NonEmpty(pod.Spec.NodeName),
				fmt.Sprintf("%v", pod.Spec.HostPID),
				fmt.Sprintf("%v", pod.Spec.HostIPC),
				fmt.Sprintf("%v", pod.Spec.HostNetwork),
				privileged,
				hostPaths,
				runAsUser,
				strings.Join(capabilities, ","),
				strings.Join(images, ","),
				strings.Join(tagTypes, ","),
				labels,
				affinity,
				tolerations,
				annotations,
				cloudProvider,
				cloudRole,
			}
			outputRows = append(outputRows, row)

			// Loot: exec command
			namespaceLootExec[pod.Namespace] = append(namespaceLootExec[pod.Namespace],
				fmt.Sprintf("kubectl exec -it -n %s %s -- sh \n", pod.Namespace, pod.Name),
			)

			// Loot: describe + jq
			jqCmd := fmt.Sprintf(
				`kubectl get pod -n %s %s -o json | jq '{
Namespace: .metadata.namespace,
Name: .metadata.name,
PodIP: .status.podIP,
ServiceAccountName: .spec.serviceAccountName,
NodeName: .spec.nodeName,
HostPID: .spec.hostPID,
HostIPC: .spec.hostIPC,
HostNetwork: .spec.hostNetwork,
Privileged: ([.spec.initContainers[], .spec.containers[]] 
    | map(.securityContext.privileged // false) | any),
HostPaths: ([.spec.volumes[]? | select(.hostPath) 
    | {(.hostPath.path): .name}]),
RunAsUser: ([.spec.initContainers[], .spec.containers[]] 
    | map(.securityContext.runAsUser // empty) 
    | map(select(. != null)) | unique),
Capabilities: ([.spec.initContainers[], .spec.containers[]] 
    | map(.securityContext.capabilities.add // []) 
    | add? // [] | unique),
Images: ([.spec.initContainers[], .spec.containers[]] 
    | map(.image) | unique),
ImageTagType: ([.spec.initContainers[], .spec.containers[]] 
    | map(if (.image | contains(":")) then "Tagged" else "Latest" end) 
    | unique),
Labels: (.metadata.labels // {}),
Affinity: (.spec.affinity // {}),
Tolerations: (.spec.tolerations // []),
Annotations: (.metadata.annotations // {})
}'`, pod.Namespace, pod.Name)
			namespaceLootEnum[pod.Namespace] = append(namespaceLootEnum[pod.Namespace],
				fmt.Sprintf("kubectl describe pod -n %s %s", pod.Namespace, pod.Name),
				jqCmd,
			)
		}
	}

	// Build lootExec with namespace headers
	lootExec := []string{
		"#####################################",
		"##### Execute into running Kubernetes Pods",
		"#####################################",
		"",
	}
	if globals.KubeContext != "" {
		lootExec = append(lootExec, fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext))
	}

	nsList := make([]string, 0, len(namespaceLootExec))
	for ns := range namespaceLootExec {
		nsList = append(nsList, ns)
	}
	sort.Strings(nsList)
	for i, ns := range nsList {
		lootExec = append(lootExec, fmt.Sprintf("\n# Namespace: %s\n", ns))
		lootExec = append(lootExec, namespaceLootExec[ns]...)
		if i < len(nsList)-1 {
			lootExec = append(lootExec, "")
		}
	}

	// Build lootEnum with namespace headers
	lootEnum := []string{
		"#####################################",
		"##### Enumerate Pod Information",
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
		Name:   "Pods",
		Header: headers,
		Body:   outputRows,
	}

	lootExecute := internal.LootFile{
		Name:     "Pod-Execution",
		Contents: strings.Join(lootExec, "\n"),
	}

	lootDescribe := internal.LootFile{
		Name:     "Pod-Enum",
		Contents: strings.Join(lootEnum, "\n"),
	}

	err = internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"Pods",
		globals.ClusterName,
		"results",
		PodsOutput{
			Table: []internal.TableFile{table},
			Loot:  []internal.LootFile{lootExecute, lootDescribe},
		},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_PODS_MODULE_NAME)
	}
}
