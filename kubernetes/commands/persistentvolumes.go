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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var PersistentVolumesCmd = &cobra.Command{
	Use:     "persistent-volumes",
	Aliases: []string{"pv", "pvs", "pvc", "pvcs", "volumes"},
	Short:   "Enumerate PersistentVolumes and PersistentVolumeClaims",
	Long: `
Enumerate all PersistentVolumes and PersistentVolumeClaims including:
  - Storage classes and provisioners
  - Access modes and capacity
  - Mount paths and bound pods
  - Cloud provider volume IDs
  - Reclaim policies

  cloudfox kubernetes persistent-volumes`,
	Run: ListPersistentVolumes,
}

type PersistentVolumesOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (p PersistentVolumesOutput) TableFiles() []internal.TableFile {
	return p.Table
}

func (p PersistentVolumesOutput) LootFiles() []internal.LootFile {
	return p.Loot
}

func ListPersistentVolumes(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating persistent volumes for %s", globals.ClusterName), globals.K8S_PERSISTENT_VOLUMES_MODULE_NAME)

	clientset := config.GetClientOrExit()

	// Get all PersistentVolumes
	pvs, err := clientset.CoreV1().PersistentVolumes().List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing persistent volumes: %v", err), globals.K8S_PERSISTENT_VOLUMES_MODULE_NAME)
		return
	}

	// Get all namespaces for PVC enumeration
	namespaces, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing namespaces: %v", err), globals.K8S_PERSISTENT_VOLUMES_MODULE_NAME)
		return
	}

	headersPV := []string{
		"PV Name",
		"Capacity",
		"Access Modes",
		"Reclaim Policy",
		"Status",
		"Claim",
		"Storage Class",
		"Volume Type",
		"Cloud Volume ID",
		"Provisioner",
	}

	headersPVC := []string{
		"Namespace",
		"PVC Name",
		"Status",
		"Volume",
		"Capacity",
		"Access Modes",
		"Storage Class",
		"Mounted By Pods",
	}

	var outputRowsPV [][]string
	var outputRowsPVC [][]string
	var lootEnum []string
	var lootCloudAccess []string
	var lootDataAccess []string

	lootEnum = append(lootEnum, `#####################################
##### PersistentVolume Enumeration
#####################################
#
# Enumerate storage resources
#
`)

	lootCloudAccess = append(lootCloudAccess, `#####################################
##### Cloud Volume Access Commands
#####################################
#
# Access cloud provider volumes directly
# REQUIRES: Cloud provider CLI tools and credentials
#
`)

	lootDataAccess = append(lootDataAccess, `#####################################
##### Data Access via Pods
#####################################
#
# Access PVC data by creating temporary pods
# MANUAL EXECUTION REQUIRED
#
`)

	if globals.KubeContext != "" {
		lootEnum = append(lootEnum, fmt.Sprintf("kubectl config use-context %s\n", globals.ClusterName))
	}

	// Process PersistentVolumes
	for _, pv := range pvs.Items {
		capacity := "<NONE>"
		if storage, ok := pv.Spec.Capacity[corev1.ResourceStorage]; ok {
			capacity = storage.String()
		}

		accessModes := []string{}
		for _, mode := range pv.Spec.AccessModes {
			accessModes = append(accessModes, string(mode))
		}

		claim := "<NONE>"
		if pv.Spec.ClaimRef != nil {
			claim = fmt.Sprintf("%s/%s", pv.Spec.ClaimRef.Namespace, pv.Spec.ClaimRef.Name)
		}

		storageClass := "<NONE>"
		if pv.Spec.StorageClassName != "" {
			storageClass = pv.Spec.StorageClassName
		}

		// Detect volume type and cloud provider volume ID
		volumeType, cloudVolumeID, provisioner := detectVolumeSource(pv.Spec.PersistentVolumeSource)

		outputRowsPV = append(outputRowsPV, []string{
			pv.Name,
			capacity,
			strings.Join(accessModes, ", "),
			string(pv.Spec.PersistentVolumeReclaimPolicy),
			string(pv.Status.Phase),
			claim,
			storageClass,
			volumeType,
			cloudVolumeID,
			provisioner,
		})

		// Generate enumeration loot
		lootEnum = append(lootEnum, fmt.Sprintf("\n# PersistentVolume: %s", pv.Name))
		lootEnum = append(lootEnum, fmt.Sprintf("kubectl get pv %s -o yaml", pv.Name))
		lootEnum = append(lootEnum, fmt.Sprintf("kubectl describe pv %s", pv.Name))
		lootEnum = append(lootEnum, "")

		// Generate cloud access loot
		if cloudVolumeID != "<NONE>" {
			lootCloudAccess = append(lootCloudAccess, generateCloudVolumeLoot(volumeType, cloudVolumeID, pv.Name)...)
		}
	}

	// Map to track which pods use which PVCs
	pvcToPods := make(map[string][]string)

	// Process PersistentVolumeClaims per namespace
	for _, ns := range namespaces.Items {
		pvcs, err := clientset.CoreV1().PersistentVolumeClaims(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			logger.ErrorM(fmt.Sprintf("Error listing PVCs in namespace %s: %v", ns.Name, err), globals.K8S_PERSISTENT_VOLUMES_MODULE_NAME)
			continue
		}

		// Get pods in this namespace to map PVC usage
		pods, err := clientset.CoreV1().Pods(ns.Name).List(ctx, metav1.ListOptions{})
		if err == nil {
			for _, pod := range pods.Items {
				for _, volume := range pod.Spec.Volumes {
					if volume.PersistentVolumeClaim != nil {
						key := fmt.Sprintf("%s/%s", ns.Name, volume.PersistentVolumeClaim.ClaimName)
						pvcToPods[key] = append(pvcToPods[key], pod.Name)
					}
				}
			}
		}

		for _, pvc := range pvcs.Items {
			capacity := "<NONE>"
			if storage, ok := pvc.Status.Capacity[corev1.ResourceStorage]; ok {
				capacity = storage.String()
			}

			accessModes := []string{}
			for _, mode := range pvc.Spec.AccessModes {
				accessModes = append(accessModes, string(mode))
			}

			storageClass := "<NONE>"
			if pvc.Spec.StorageClassName != nil {
				storageClass = *pvc.Spec.StorageClassName
			}

			volumeName := k8sinternal.NonEmpty(pvc.Spec.VolumeName)

			// Get pods using this PVC
			key := fmt.Sprintf("%s/%s", ns.Name, pvc.Name)
			mountedBy := pvcToPods[key]
			mountedByStr := "<NONE>"
			if len(mountedBy) > 0 {
				mountedByStr = strings.Join(k8sinternal.Unique(mountedBy), ", ")
			}

			outputRowsPVC = append(outputRowsPVC, []string{
				ns.Name,
				pvc.Name,
				string(pvc.Status.Phase),
				volumeName,
				capacity,
				strings.Join(accessModes, ", "),
				storageClass,
				mountedByStr,
			})

			// Generate enumeration loot
			lootEnum = append(lootEnum, fmt.Sprintf("\n# PVC: %s/%s", ns.Name, pvc.Name))
			lootEnum = append(lootEnum, fmt.Sprintf("kubectl get pvc %s -n %s -o yaml", pvc.Name, ns.Name))
			lootEnum = append(lootEnum, fmt.Sprintf("kubectl describe pvc %s -n %s", pvc.Name, ns.Name))
			lootEnum = append(lootEnum, "")

			// Generate data access loot
			lootDataAccess = append(lootDataAccess, fmt.Sprintf("\n# Access PVC: %s/%s", ns.Name, pvc.Name))
			lootDataAccess = append(lootDataAccess, "# Create temporary pod to access data:")
			lootDataAccess = append(lootDataAccess, fmt.Sprintf(`cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: pvc-inspector-%s
  namespace: %s
spec:
  containers:
  - name: inspector
    image: busybox
    command: ["sleep", "3600"]
    volumeMounts:
    - name: data
      mountPath: /data
  volumes:
  - name: data
    persistentVolumeClaim:
      claimName: %s
EOF`, strings.ReplaceAll(pvc.Name, ".", "-"), ns.Name, pvc.Name))
			lootDataAccess = append(lootDataAccess, fmt.Sprintf("kubectl exec -it pvc-inspector-%s -n %s -- sh", strings.ReplaceAll(pvc.Name, ".", "-"), ns.Name))
			lootDataAccess = append(lootDataAccess, fmt.Sprintf("# List files: kubectl exec pvc-inspector-%s -n %s -- ls -laR /data", strings.ReplaceAll(pvc.Name, ".", "-"), ns.Name))
			lootDataAccess = append(lootDataAccess, fmt.Sprintf("# Copy data: kubectl cp %s/pvc-inspector-%s:/data ./pvc-data-%s", ns.Name, strings.ReplaceAll(pvc.Name, ".", "-"), pvc.Name))
			lootDataAccess = append(lootDataAccess, fmt.Sprintf("# Cleanup: kubectl delete pod pvc-inspector-%s -n %s", strings.ReplaceAll(pvc.Name, ".", "-"), ns.Name))
			lootDataAccess = append(lootDataAccess, "")
		}
	}

	tablePV := internal.TableFile{
		Name:   "PersistentVolumes",
		Header: headersPV,
		Body:   outputRowsPV,
	}

	tablePVC := internal.TableFile{
		Name:   "PersistentVolumeClaims",
		Header: headersPVC,
		Body:   outputRowsPVC,
	}

	lootFiles := []internal.LootFile{
		{
			Name:     "PV-PVC-Enum",
			Contents: strings.Join(lootEnum, "\n"),
		},
		{
			Name:     "PV-Cloud-Access",
			Contents: strings.Join(lootCloudAccess, "\n"),
		},
		{
			Name:     "PVC-Data-Access",
			Contents: strings.Join(lootDataAccess, "\n"),
		},
	}

	err = internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"PersistentVolumes",
		globals.ClusterName,
		"results",
		PersistentVolumesOutput{
			Table: []internal.TableFile{tablePV, tablePVC},
			Loot:  lootFiles,
		},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_PERSISTENT_VOLUMES_MODULE_NAME)
		return
	}

	totalResources := len(outputRowsPV) + len(outputRowsPVC)
	if totalResources > 0 {
		logger.InfoM(fmt.Sprintf("%d PVs and %d PVCs found", len(outputRowsPV), len(outputRowsPVC)), globals.K8S_PERSISTENT_VOLUMES_MODULE_NAME)
	} else {
		logger.InfoM("No persistent volumes found, skipping output file creation", globals.K8S_PERSISTENT_VOLUMES_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_PERSISTENT_VOLUMES_MODULE_NAME), globals.K8S_PERSISTENT_VOLUMES_MODULE_NAME)
}

// detectVolumeSource returns volume type, cloud volume ID, and provisioner
func detectVolumeSource(source corev1.PersistentVolumeSource) (string, string, string) {
	if source.AWSElasticBlockStore != nil {
		return "AWS EBS", source.AWSElasticBlockStore.VolumeID, "kubernetes.io/aws-ebs"
	}
	if source.GCEPersistentDisk != nil {
		return "GCE PD", source.GCEPersistentDisk.PDName, "kubernetes.io/gce-pd"
	}
	if source.AzureDisk != nil {
		return "Azure Disk", source.AzureDisk.DiskName, "kubernetes.io/azure-disk"
	}
	if source.AzureFile != nil {
		return "Azure File", source.AzureFile.ShareName, "kubernetes.io/azure-file"
	}
	if source.CSI != nil {
		volumeHandle := "<NONE>"
		if source.CSI.VolumeHandle != "" {
			volumeHandle = source.CSI.VolumeHandle
		}
		return "CSI", volumeHandle, source.CSI.Driver
	}
	if source.NFS != nil {
		return "NFS", fmt.Sprintf("%s:%s", source.NFS.Server, source.NFS.Path), "nfs"
	}
	if source.HostPath != nil {
		return "HostPath", source.HostPath.Path, "hostPath"
	}
	if source.Local != nil {
		return "Local", source.Local.Path, "local"
	}
	if source.ISCSI != nil {
		return "iSCSI", fmt.Sprintf("%s:%s", source.ISCSI.TargetPortal, source.ISCSI.IQN), "iscsi"
	}
	if source.Glusterfs != nil {
		return "Glusterfs", fmt.Sprintf("%s:%s", source.Glusterfs.EndpointsName, source.Glusterfs.Path), "glusterfs"
	}
	if source.RBD != nil {
		return "RBD/Ceph", source.RBD.RBDImage, "rbd"
	}
	return "<UNKNOWN>", "<NONE>", "<NONE>"
}

// generateCloudVolumeLoot generates cloud-specific commands to access volumes
func generateCloudVolumeLoot(volumeType, volumeID, pvName string) []string {
	loot := []string{fmt.Sprintf("\n# PV: %s (%s)", pvName, volumeType)}

	switch volumeType {
	case "AWS EBS":
		loot = append(loot, "# AWS EBS Volume Access:")
		loot = append(loot, fmt.Sprintf("aws ec2 describe-volumes --volume-ids %s", volumeID))
		loot = append(loot, fmt.Sprintf("aws ec2 create-snapshot --volume-id %s --description 'Snapshot of %s'", volumeID, pvName))
		loot = append(loot, "# Create volume from snapshot and attach to instance:")
		loot = append(loot, "# SNAPSHOT_ID=$(aws ec2 create-snapshot --volume-id "+volumeID+" --query 'SnapshotId' --output text)")
		loot = append(loot, "# aws ec2 wait snapshot-completed --snapshot-ids $SNAPSHOT_ID")
		loot = append(loot, "# NEW_VOL=$(aws ec2 create-volume --snapshot-id $SNAPSHOT_ID --availability-zone <az> --query 'VolumeId' --output text)")
		loot = append(loot, "# aws ec2 attach-volume --volume-id $NEW_VOL --instance-id <instance-id> --device /dev/sdf")

	case "GCE PD":
		loot = append(loot, "# GCE Persistent Disk Access:")
		loot = append(loot, fmt.Sprintf("gcloud compute disks describe %s --zone <zone>", volumeID))
		loot = append(loot, fmt.Sprintf("gcloud compute disks snapshot %s --snapshot-names=%s-snapshot --zone <zone>", volumeID, pvName))
		loot = append(loot, "# Create disk from snapshot and attach:")
		loot = append(loot, fmt.Sprintf("# gcloud compute disks create %s-copy --source-snapshot=%s-snapshot --zone <zone>", pvName, pvName))
		loot = append(loot, fmt.Sprintf("# gcloud compute instances attach-disk <instance-name> --disk=%s-copy --zone <zone>", pvName))

	case "Azure Disk":
		loot = append(loot, "# Azure Disk Access:")
		loot = append(loot, fmt.Sprintf("az disk show --name %s --resource-group <rg>", volumeID))
		loot = append(loot, fmt.Sprintf("az snapshot create --resource-group <rg> --source %s --name %s-snapshot", volumeID, pvName))
		loot = append(loot, "# Create disk from snapshot and attach:")
		loot = append(loot, fmt.Sprintf("# az disk create --resource-group <rg> --name %s-copy --source %s-snapshot", pvName, pvName))
		loot = append(loot, fmt.Sprintf("# az vm disk attach --resource-group <rg> --vm-name <vm-name> --name %s-copy", pvName))

	case "NFS":
		loot = append(loot, "# NFS Volume Access:")
		loot = append(loot, fmt.Sprintf("# Mount point: %s", volumeID))
		loot = append(loot, fmt.Sprintf("mkdir -p /mnt/%s && mount -t nfs %s /mnt/%s", pvName, strings.Split(volumeID, ":")[1], pvName))

	case "CSI":
		loot = append(loot, "# CSI Volume - check driver-specific tools")
		loot = append(loot, fmt.Sprintf("# Volume Handle: %s", volumeID))
	}

	loot = append(loot, "")
	return loot
}
