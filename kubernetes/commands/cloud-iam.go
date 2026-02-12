package commands

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	k8sinternal "github.com/BishopFox/cloudfox/internal/kubernetes"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/BishopFox/cloudfox/kubernetes/shared"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

const K8S_CLOUD_IAM_MODULE_NAME = "cloud-iam"

var CloudIAMCmd = &cobra.Command{
	Use:     "cloud-iam",
	Aliases: []string{"cloud-identity", "cloud-roles"},
	Short:   "Enumerate all cloud IAM identities mapped to Kubernetes resources",
	Long: `
Enumerate all cloud IAM identities (AWS IAM Roles, GCP Service Accounts, Azure Managed Identities)
that are mapped to Kubernetes resources across the cluster.

This provides a centralized view of cloud identity mappings including:
  - Nodes with attached IAM roles/service accounts
  - ServiceAccounts with workload identity annotations
  - Pods/Deployments/DaemonSets/etc. with cloud role references
  - AWS Pod Identity Associations
  - Azure AAD Pod Identity bindings
  - GCP Workload Identity mappings

Examples:
  cloudfox kubernetes cloud-iam
  cloudfox kubernetes cloud-iam -A
  cloudfox kubernetes cloud-iam -n production`,
	Run: CloudIAM,
}

// CloudIAMFinding represents a cloud identity mapping to a K8s resource
type CloudIAMFinding struct {
	// Scope
	Namespace string // Empty for cluster-scoped resources like nodes
	Scope     string // "Cluster" or "Namespace"

	// Kubernetes Resource
	ResourceType string // Node, ServiceAccount, Pod, Deployment, DaemonSet, StatefulSet, ReplicaSet, Job, CronJob
	ResourceName string

	// Cloud Identity
	CloudProvider string // AWS, GCP, Azure
	CloudIdentity string // ARN, email, client ID
	IdentityType  string // IAM Role, Service Account, Managed Identity, Pod Identity, Workload Identity

	// Detection Source
	Source string // How the identity was detected (annotation, env var, label, CRD, etc.)

	// Additional context
	ControllerType string // For pods: what controller owns them
	ControllerName string
	ServiceAccount string // SA name if applicable
}

type CloudIAMOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (c CloudIAMOutput) TableFiles() []internal.TableFile {
	return c.Table
}

func (c CloudIAMOutput) LootFiles() []internal.LootFile {
	return c.Loot
}

func CloudIAM(cmd *cobra.Command, args []string) {
	ctx, cancel := shared.ContextWithTimeout()
	defer cancel()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	clientset := config.GetClientOrExit()
	dynamicClient := config.GetDynamicClientOrExit()

	logger.InfoM(fmt.Sprintf("Enumerating cloud IAM identities for %s", globals.ClusterName), K8S_CLOUD_IAM_MODULE_NAME)

	findings := collectCloudIAMFindings(ctx, clientset, dynamicClient, &logger)

	if len(findings) == 0 {
		logger.InfoM("No cloud IAM identities found in cluster", K8S_CLOUD_IAM_MODULE_NAME)
		return
	}

	// Sort findings for consistent output
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].CloudProvider != findings[j].CloudProvider {
			return findings[i].CloudProvider < findings[j].CloudProvider
		}
		if findings[i].ResourceType != findings[j].ResourceType {
			return findings[i].ResourceType < findings[j].ResourceType
		}
		if findings[i].Namespace != findings[j].Namespace {
			return findings[i].Namespace < findings[j].Namespace
		}
		return findings[i].ResourceName < findings[j].ResourceName
	})

	// Generate output
	output := generateCloudIAMOutput(findings, &logger)

	err := internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"cloud-iam",
		globals.ClusterName,
		"results",
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), K8S_CLOUD_IAM_MODULE_NAME)
	}

	// Print summary
	printCloudIAMSummary(findings, &logger)
}

func collectCloudIAMFindings(ctx context.Context, clientset *kubernetes.Clientset, dynamicClient dynamic.Interface, logger *internal.Logger) []CloudIAMFinding {
	var findings []CloudIAMFinding

	// Collect from nodes
	nodeFindings := collectNodeCloudIAM(ctx, clientset, logger)
	findings = append(findings, nodeFindings...)

	// Collect from service accounts
	saFindings := collectServiceAccountCloudIAM(ctx, clientset, dynamicClient, logger)
	findings = append(findings, saFindings...)

	// Collect from pods (also detects from env vars, configmaps, secrets)
	podFindings := collectPodCloudIAM(ctx, clientset, logger)
	findings = append(findings, podFindings...)

	// Collect from AWS Pod Identity Associations CRD
	awsPodIdentityFindings := collectAWSPodIdentityAssociations(ctx, dynamicClient, logger)
	findings = append(findings, awsPodIdentityFindings...)

	// Collect from Azure AAD Pod Identity bindings
	azureIdentityFindings := collectAzureIdentityBindings(ctx, dynamicClient, logger)
	findings = append(findings, azureIdentityFindings...)

	// Deduplicate findings
	findings = deduplicateCloudIAMFindings(findings)

	return findings
}

func collectNodeCloudIAM(ctx context.Context, clientset *kubernetes.Clientset, logger *internal.Logger) []CloudIAMFinding {
	var findings []CloudIAMFinding

	nodes, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to list nodes: %v", err), K8S_CLOUD_IAM_MODULE_NAME)
		return findings
	}

	for _, node := range nodes.Items {
		cloudProvider := k8sinternal.DetectCloudProviderFromNode(node.Spec.ProviderID)
		if cloudProvider == "" || cloudProvider == "Unknown" {
			continue
		}

		// Check for IAM role from node labels
		cloudRole := k8sinternal.DetectCloudRoleFromNodeLabels(node.Labels)

		// For AWS nodes, extract role from provider ID if available
		if cloudProvider == "AWS" && cloudRole == "" {
			// AWS nodes typically have IAM roles attached via instance profiles
			// The role is detectable via IMDS, but we note that IAM access is available
			cloudRole = extractAWSNodeRole(node.Spec.ProviderID, node.Labels, node.Annotations)
		}

		// For GCP nodes, check for service account
		if cloudProvider == "GCP" && cloudRole == "" {
			cloudRole = extractGCPNodeServiceAccount(node.Labels, node.Annotations)
		}

		// For Azure nodes, check for managed identity
		if cloudProvider == "Azure" && cloudRole == "" {
			cloudRole = extractAzureNodeIdentity(node.Labels, node.Annotations)
		}

		// Even without explicit role, nodes in cloud have implicit IAM access
		if cloudRole == "" {
			cloudRole = "(instance profile/metadata available)"
		}

		findings = append(findings, CloudIAMFinding{
			Namespace:     "",
			Scope:         "Cluster",
			ResourceType:  "Node",
			ResourceName:  node.Name,
			CloudProvider: cloudProvider,
			CloudIdentity: cloudRole,
			IdentityType:  getNodeIdentityType(cloudProvider),
			Source:        "node provider ID / labels",
		})
	}

	return findings
}

func collectServiceAccountCloudIAM(ctx context.Context, clientset *kubernetes.Clientset, dynamicClient dynamic.Interface, logger *internal.Logger) []CloudIAMFinding {
	var findings []CloudIAMFinding

	for _, ns := range globals.K8sNamespaces {
		sas, err := clientset.CoreV1().ServiceAccounts(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, sa := range sas.Items {
			// Check AWS EKS IRSA annotation
			if roleARN, ok := sa.Annotations["eks.amazonaws.com/role-arn"]; ok && roleARN != "" {
				findings = append(findings, CloudIAMFinding{
					Namespace:     ns,
					Scope:         "Namespace",
					ResourceType:  "ServiceAccount",
					ResourceName:  sa.Name,
					CloudProvider: "AWS",
					CloudIdentity: roleARN,
					IdentityType:  "IAM Role (IRSA)",
					Source:        "annotation: eks.amazonaws.com/role-arn",
				})
			}

			// Check GCP Workload Identity annotation
			if gcpSA, ok := sa.Annotations["iam.gke.io/gcp-service-account"]; ok && gcpSA != "" {
				findings = append(findings, CloudIAMFinding{
					Namespace:     ns,
					Scope:         "Namespace",
					ResourceType:  "ServiceAccount",
					ResourceName:  sa.Name,
					CloudProvider: "GCP",
					CloudIdentity: gcpSA,
					IdentityType:  "Service Account (Workload Identity)",
					Source:        "annotation: iam.gke.io/gcp-service-account",
				})
			}

			// Check Azure Workload Identity annotation
			if azureClientID, ok := sa.Annotations["azure.workload.identity/client-id"]; ok && azureClientID != "" {
				identityStr := azureClientID
				if tenantID, ok := sa.Annotations["azure.workload.identity/tenant-id"]; ok {
					identityStr = fmt.Sprintf("%s (tenant: %s)", azureClientID, tenantID)
				}
				findings = append(findings, CloudIAMFinding{
					Namespace:     ns,
					Scope:         "Namespace",
					ResourceType:  "ServiceAccount",
					ResourceName:  sa.Name,
					CloudProvider: "Azure",
					CloudIdentity: identityStr,
					IdentityType:  "Managed Identity (Workload Identity)",
					Source:        "annotation: azure.workload.identity/client-id",
				})
			}

			// Check for AWS Pod Identity Associations (via CRD lookup)
			if dynamicClient != nil {
				awsInfo := checkAWSPodIdentityForSA(ctx, dynamicClient, ns, sa.Name)
				if awsInfo.RoleARN != "" {
					findings = append(findings, CloudIAMFinding{
						Namespace:     ns,
						Scope:         "Namespace",
						ResourceType:  "ServiceAccount",
						ResourceName:  sa.Name,
						CloudProvider: "AWS",
						CloudIdentity: awsInfo.RoleARN,
						IdentityType:  "IAM Role (Pod Identity)",
						Source:        fmt.Sprintf("CRD: PodIdentityAssociation/%s", awsInfo.Name),
					})
				}
			}
		}
	}

	return findings
}

func collectPodCloudIAM(ctx context.Context, clientset *kubernetes.Clientset, logger *internal.Logger) []CloudIAMFinding {
	var findings []CloudIAMFinding

	for _, ns := range globals.K8sNamespaces {
		pods, err := clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, pod := range pods.Items {
			// Use the existing DetectCloudRole function
			roleResults := k8sinternal.DetectCloudRole(ctx, clientset, pod.Namespace, pod.Spec.ServiceAccountName, &pod.Spec, pod.Annotations)

			for _, result := range roleResults {
				// Skip if this is from ServiceAccount (already captured above)
				if strings.Contains(result.Source, "serviceaccount") {
					continue
				}

				controllerType, controllerName := getControllerInfo(&pod)

				findings = append(findings, CloudIAMFinding{
					Namespace:      ns,
					Scope:          "Namespace",
					ResourceType:   "Pod",
					ResourceName:   pod.Name,
					CloudProvider:  result.Provider,
					CloudIdentity:  result.Role,
					IdentityType:   getIdentityTypeFromProvider(result.Provider),
					Source:         result.Source,
					ControllerType: controllerType,
					ControllerName: controllerName,
					ServiceAccount: pod.Spec.ServiceAccountName,
				})
			}
		}
	}

	return findings
}

func collectAWSPodIdentityAssociations(ctx context.Context, dynamicClient dynamic.Interface, logger *internal.Logger) []CloudIAMFinding {
	var findings []CloudIAMFinding

	if dynamicClient == nil {
		return findings
	}

	gvr := schema.GroupVersionResource{
		Group:    "eks.amazonaws.com",
		Version:  "v1alpha1",
		Resource: "podidentityassociations",
	}

	// Try cluster-scoped first
	list, err := dynamicClient.Resource(gvr).List(ctx, metav1.ListOptions{})
	if err != nil {
		// CRD not installed or no permissions
		return findings
	}

	for _, item := range list.Items {
		spec, found, _ := getNestedMapCloudIAM(item.Object, "spec")
		if !found {
			continue
		}

		namespace := getNestedStringCloudIAM(spec, "namespace")
		if namespace == "" {
			namespace = item.GetNamespace()
		}
		saName := getNestedStringCloudIAM(spec, "serviceAccountName")
		roleARN := getNestedStringCloudIAM(spec, "roleArn")

		if roleARN != "" && saName != "" {
			findings = append(findings, CloudIAMFinding{
				Namespace:      namespace,
				Scope:          "Namespace",
				ResourceType:   "PodIdentityAssociation",
				ResourceName:   item.GetName(),
				CloudProvider:  "AWS",
				CloudIdentity:  roleARN,
				IdentityType:   "IAM Role (Pod Identity)",
				Source:         "CRD: eks.amazonaws.com/v1alpha1/PodIdentityAssociation",
				ServiceAccount: saName,
			})
		}
	}

	return findings
}

func collectAzureIdentityBindings(ctx context.Context, dynamicClient dynamic.Interface, logger *internal.Logger) []CloudIAMFinding {
	var findings []CloudIAMFinding

	if dynamicClient == nil {
		return findings
	}

	// Check for AzureIdentityBinding (AAD Pod Identity v1)
	gvr := schema.GroupVersionResource{
		Group:    "aadpodidentity.k8s.io",
		Version:  "v1",
		Resource: "azureidentitybindings",
	}

	list, err := dynamicClient.Resource(gvr).List(ctx, metav1.ListOptions{})
	if err != nil {
		// CRD not installed
		return findings
	}

	for _, item := range list.Items {
		spec, found, _ := getNestedMapCloudIAM(item.Object, "spec")
		if !found {
			continue
		}

		azureIdentityRef := getNestedStringCloudIAM(spec, "azureIdentity")
		selector := getNestedStringCloudIAM(spec, "selector")

		if azureIdentityRef != "" {
			// Lookup the AzureIdentity to get the client ID
			clientID := lookupAzureIdentityClientID(ctx, dynamicClient, item.GetNamespace(), azureIdentityRef)

			findings = append(findings, CloudIAMFinding{
				Namespace:     item.GetNamespace(),
				Scope:         "Namespace",
				ResourceType:  "AzureIdentityBinding",
				ResourceName:  item.GetName(),
				CloudProvider: "Azure",
				CloudIdentity: clientID,
				IdentityType:  "Managed Identity (AAD Pod Identity)",
				Source:        fmt.Sprintf("CRD: AzureIdentityBinding (selector: %s)", selector),
			})
		}
	}

	return findings
}

func lookupAzureIdentityClientID(ctx context.Context, dynamicClient dynamic.Interface, namespace, name string) string {
	gvr := schema.GroupVersionResource{
		Group:    "aadpodidentity.k8s.io",
		Version:  "v1",
		Resource: "azureidentities",
	}

	// Try namespace-scoped first
	identity, err := dynamicClient.Resource(gvr).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		// Try cluster-scoped
		identity, err = dynamicClient.Resource(gvr).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return name // Return the reference name if lookup fails
		}
	}

	spec, found, _ := getNestedMapCloudIAM(identity.Object, "spec")
	if !found {
		return name
	}

	clientID := getNestedStringCloudIAM(spec, "clientID")
	if clientID != "" {
		return clientID
	}

	resourceID := getNestedStringCloudIAM(spec, "resourceID")
	if resourceID != "" {
		return resourceID
	}

	return name
}

// Helper functions

func extractAWSNodeRole(providerID string, labels, annotations map[string]string) string {
	// Check common AWS node labels/annotations for IAM role info
	roleLabels := []string{
		"iam.amazonaws.com/role",
		"eks.amazonaws.com/nodegroup",
		"alpha.eksctl.io/iamidentitymapping",
	}
	for _, label := range roleLabels {
		if role, ok := labels[label]; ok && role != "" {
			return role
		}
		if role, ok := annotations[label]; ok && role != "" {
			return role
		}
	}
	return ""
}

func extractGCPNodeServiceAccount(labels, annotations map[string]string) string {
	// Check for GCP service account in labels/annotations
	saLabels := []string{
		"iam.gke.io/gke-metadata-server-enabled",
		"cloud.google.com/gke-nodepool",
	}
	for _, label := range saLabels {
		if sa, ok := labels[label]; ok && sa != "" {
			return sa
		}
	}
	return ""
}

func extractAzureNodeIdentity(labels, annotations map[string]string) string {
	// Check for Azure managed identity in labels/annotations
	miLabels := []string{
		"kubernetes.azure.com/managed-identity-client-id",
		"aadpodidentity.k8s.io/assigned-identity",
	}
	for _, label := range miLabels {
		if mi, ok := labels[label]; ok && mi != "" {
			return mi
		}
		if mi, ok := annotations[label]; ok && mi != "" {
			return mi
		}
	}
	return ""
}

func getNodeIdentityType(provider string) string {
	switch provider {
	case "AWS":
		return "Instance Profile / IAM Role"
	case "GCP":
		return "Node Service Account"
	case "Azure":
		return "Node Managed Identity"
	default:
		return "Unknown"
	}
}

func getIdentityTypeFromProvider(provider string) string {
	switch provider {
	case "AWS":
		return "IAM Role"
	case "GCP":
		return "Service Account"
	case "Azure":
		return "Managed Identity"
	default:
		return "Unknown"
	}
}

func getControllerInfo(pod *corev1.Pod) (string, string) {
	for _, ref := range pod.OwnerReferences {
		if ref.Controller != nil && *ref.Controller {
			return ref.Kind, ref.Name
		}
	}
	return "", ""
}

func checkAWSPodIdentityForSA(ctx context.Context, dynamicClient dynamic.Interface, namespace, saName string) struct{ Name, RoleARN string } {
	result := struct{ Name, RoleARN string }{}

	gvr := schema.GroupVersionResource{
		Group:    "eks.amazonaws.com",
		Version:  "v1alpha1",
		Resource: "podidentityassociations",
	}

	list, err := dynamicClient.Resource(gvr).List(ctx, metav1.ListOptions{})
	if err != nil {
		return result
	}

	for _, item := range list.Items {
		spec, found, _ := getNestedMapCloudIAM(item.Object, "spec")
		if !found {
			continue
		}

		itemNS := getNestedStringCloudIAM(spec, "namespace")
		if itemNS == "" {
			itemNS = item.GetNamespace()
		}
		itemSA := getNestedStringCloudIAM(spec, "serviceAccountName")
		roleARN := getNestedStringCloudIAM(spec, "roleArn")

		if itemNS == namespace && itemSA == saName && roleARN != "" {
			result.Name = item.GetName()
			result.RoleARN = roleARN
			return result
		}
	}

	return result
}

func getNestedMapCloudIAM(obj map[string]interface{}, key string) (map[string]interface{}, bool, error) {
	val, ok := obj[key]
	if !ok {
		return nil, false, nil
	}
	m, ok := val.(map[string]interface{})
	return m, ok, nil
}

func getNestedStringCloudIAM(obj map[string]interface{}, key string) string {
	val, ok := obj[key]
	if !ok {
		return ""
	}
	s, ok := val.(string)
	if !ok {
		return ""
	}
	return s
}

func deduplicateCloudIAMFindings(findings []CloudIAMFinding) []CloudIAMFinding {
	seen := make(map[string]bool)
	var result []CloudIAMFinding

	for _, f := range findings {
		// Create a unique key based on resource + cloud identity
		key := fmt.Sprintf("%s|%s|%s|%s|%s", f.Namespace, f.ResourceType, f.ResourceName, f.CloudProvider, f.CloudIdentity)
		if !seen[key] {
			seen[key] = true
			result = append(result, f)
		}
	}

	return result
}

func generateCloudIAMOutput(findings []CloudIAMFinding, logger *internal.Logger) CloudIAMOutput {
	var output CloudIAMOutput

	// Table headers
	headers := []string{
		"Scope",
		"Namespace",
		"Resource Type",
		"Resource Name",
		"Cloud Provider",
		"Identity Type",
		"Cloud Identity",
		"Source",
	}

	var rows [][]string
	for _, f := range findings {
		namespace := f.Namespace
		if namespace == "" {
			namespace = "-"
		}

		rows = append(rows, []string{
			f.Scope,
			namespace,
			f.ResourceType,
			f.ResourceName,
			f.CloudProvider,
			f.IdentityType,
			f.CloudIdentity,
			f.Source,
		})
	}

	output.Table = append(output.Table, internal.TableFile{
		Name:   "cloud-iam",
		Header: headers,
		Body:   rows,
	})

	// Generate loot files
	output.Loot = generateCloudIAMLoot(findings)

	return output
}

func generateCloudIAMLoot(findings []CloudIAMFinding) []internal.LootFile {
	var lootFiles []internal.LootFile
	var lootContent []string

	lootContent = append(lootContent, "# Cloud IAM Identity Mappings")
	lootContent = append(lootContent, "# Generated by cloudfox kubernetes cloud-iam")
	lootContent = append(lootContent, "")

	// Group by provider
	awsFindings := filterByProvider(findings, "AWS")
	gcpFindings := filterByProvider(findings, "GCP")
	azureFindings := filterByProvider(findings, "Azure")

	if len(awsFindings) > 0 {
		lootContent = append(lootContent, "## AWS IAM Roles")
		lootContent = append(lootContent, "")
		for _, f := range awsFindings {
			lootContent = append(lootContent, fmt.Sprintf("### %s: %s/%s", f.ResourceType, f.Namespace, f.ResourceName))
			lootContent = append(lootContent, fmt.Sprintf("Role ARN: %s", f.CloudIdentity))
			lootContent = append(lootContent, fmt.Sprintf("Identity Type: %s", f.IdentityType))
			lootContent = append(lootContent, fmt.Sprintf("Source: %s", f.Source))
			if f.ServiceAccount != "" {
				lootContent = append(lootContent, fmt.Sprintf("Service Account: %s", f.ServiceAccount))
			}
			lootContent = append(lootContent, "")
			// Add AWS CLI commands to enumerate role
			if strings.HasPrefix(f.CloudIdentity, "arn:aws:iam::") {
				roleName := extractRoleNameFromARN(f.CloudIdentity)
				if roleName != "" {
					lootContent = append(lootContent, "# Enumerate AWS IAM role:")
					lootContent = append(lootContent, fmt.Sprintf("aws iam get-role --role-name %s", roleName))
					lootContent = append(lootContent, fmt.Sprintf("aws iam list-attached-role-policies --role-name %s", roleName))
					lootContent = append(lootContent, fmt.Sprintf("aws iam list-role-policies --role-name %s", roleName))
					lootContent = append(lootContent, "")
				}
			}
		}
	}

	if len(gcpFindings) > 0 {
		lootContent = append(lootContent, "## GCP Service Accounts")
		lootContent = append(lootContent, "")
		for _, f := range gcpFindings {
			lootContent = append(lootContent, fmt.Sprintf("### %s: %s/%s", f.ResourceType, f.Namespace, f.ResourceName))
			lootContent = append(lootContent, fmt.Sprintf("Service Account: %s", f.CloudIdentity))
			lootContent = append(lootContent, fmt.Sprintf("Identity Type: %s", f.IdentityType))
			lootContent = append(lootContent, fmt.Sprintf("Source: %s", f.Source))
			if f.ServiceAccount != "" {
				lootContent = append(lootContent, fmt.Sprintf("K8s Service Account: %s", f.ServiceAccount))
			}
			lootContent = append(lootContent, "")
			// Add gcloud commands
			if strings.Contains(f.CloudIdentity, "@") && strings.Contains(f.CloudIdentity, ".iam.gserviceaccount.com") {
				lootContent = append(lootContent, "# Enumerate GCP service account:")
				lootContent = append(lootContent, fmt.Sprintf("gcloud iam service-accounts describe %s", f.CloudIdentity))
				lootContent = append(lootContent, fmt.Sprintf("gcloud iam service-accounts get-iam-policy %s", f.CloudIdentity))
				lootContent = append(lootContent, "")
			}
		}
	}

	if len(azureFindings) > 0 {
		lootContent = append(lootContent, "## Azure Managed Identities")
		lootContent = append(lootContent, "")
		for _, f := range azureFindings {
			lootContent = append(lootContent, fmt.Sprintf("### %s: %s/%s", f.ResourceType, f.Namespace, f.ResourceName))
			lootContent = append(lootContent, fmt.Sprintf("Client ID: %s", f.CloudIdentity))
			lootContent = append(lootContent, fmt.Sprintf("Identity Type: %s", f.IdentityType))
			lootContent = append(lootContent, fmt.Sprintf("Source: %s", f.Source))
			if f.ServiceAccount != "" {
				lootContent = append(lootContent, fmt.Sprintf("K8s Service Account: %s", f.ServiceAccount))
			}
			lootContent = append(lootContent, "")
			// Add Azure CLI commands
			lootContent = append(lootContent, "# Enumerate Azure managed identity:")
			lootContent = append(lootContent, "az identity list --query \"[?clientId=='"+f.CloudIdentity+"']\"")
			lootContent = append(lootContent, "")
		}
	}

	lootFiles = append(lootFiles, internal.LootFile{
		Name:     "cloud-iam-mappings.md",
		Contents: strings.Join(lootContent, "\n"),
	})

	return lootFiles
}

func filterByProvider(findings []CloudIAMFinding, provider string) []CloudIAMFinding {
	var result []CloudIAMFinding
	for _, f := range findings {
		if f.CloudProvider == provider {
			result = append(result, f)
		}
	}
	return result
}

func extractRoleNameFromARN(arn string) string {
	// arn:aws:iam::123456789012:role/my-role-name
	parts := strings.Split(arn, "/")
	if len(parts) >= 2 {
		return parts[len(parts)-1]
	}
	// Try extracting after :role/
	if strings.Contains(arn, ":role/") {
		parts := strings.Split(arn, ":role/")
		if len(parts) == 2 {
			return parts[1]
		}
	}
	return ""
}

func printCloudIAMSummary(findings []CloudIAMFinding, logger *internal.Logger) {
	// Count by provider
	providerCounts := make(map[string]int)
	resourceTypeCounts := make(map[string]int)

	for _, f := range findings {
		providerCounts[f.CloudProvider]++
		resourceTypeCounts[f.ResourceType]++
	}

	logger.InfoM(fmt.Sprintf("Found %d cloud IAM identity mappings", len(findings)), K8S_CLOUD_IAM_MODULE_NAME)

	// Provider breakdown
	var providerSummary []string
	for provider, count := range providerCounts {
		providerSummary = append(providerSummary, fmt.Sprintf("%s: %d", provider, count))
	}
	sort.Strings(providerSummary)
	logger.InfoM(fmt.Sprintf("By provider: %s", strings.Join(providerSummary, ", ")), K8S_CLOUD_IAM_MODULE_NAME)

	// Resource type breakdown
	var resourceSummary []string
	for resourceType, count := range resourceTypeCounts {
		resourceSummary = append(resourceSummary, fmt.Sprintf("%s: %d", resourceType, count))
	}
	sort.Strings(resourceSummary)
	logger.InfoM(fmt.Sprintf("By resource: %s", strings.Join(resourceSummary, ", ")), K8S_CLOUD_IAM_MODULE_NAME)
}
