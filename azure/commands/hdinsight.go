package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/hdinsight/armhdinsight"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/BishopFox/cloudfox/internal/azure/sdk"
	"github.com/spf13/cobra"
)

// ------------------------------
// Cobra command
// ------------------------------
var AzHDInsightCommand = &cobra.Command{
	Use:     "hdinsight",
	Aliases: []string{"hdi"},
	Short:   "Enumerate Azure HDInsight clusters with Enterprise Security Package (ESP) analysis",
	Long: `
Enumerate Azure HDInsight for a specific tenant:
  ./cloudfox az hdinsight --tenant TENANT_ID

Enumerate Azure HDInsight for a specific subscription:
  ./cloudfox az hdinsight --subscription SUBSCRIPTION_ID

ENHANCED FEATURES:
  - Enterprise Security Package (ESP) detection and analysis
  - Azure AD DS integration security assessment
  - Kerberos authentication configuration
  - Apache Ranger authorization policy analysis
  - LDAP/LDAPS integration security
  - Disk and in-transit encryption analysis
  - Managed identity and service principal analysis

SECURITY ANALYSIS:
  - ESP-enabled vs non-ESP clusters (authentication gaps)
  - LDAP credential exposure risks
  - Ranger policy misconfigurations
  - Encrypted vs unencrypted clusters
  - Public vs private endpoint exposure`,
	Run: ListHDInsight,
}

// ------------------------------
// Module struct
// ------------------------------
type HDInsightModule struct {
	azinternal.BaseAzureModule

	Subscriptions []string
	HDIRows       [][]string
	LootMap       map[string]*internal.LootFile
	mu            sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type HDInsightOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o HDInsightOutput) TableFiles() []internal.TableFile { return o.Table }
func (o HDInsightOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point
// ------------------------------
func ListHDInsight(cmd *cobra.Command, args []string) {
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_HDINSIGHT_MODULE_NAME)
	if err != nil {
		return
	}
	defer cmdCtx.Session.StopMonitoring()

	module := &HDInsightModule{
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:   cmdCtx.Subscriptions,
		HDIRows:         [][]string{},
		LootMap: map[string]*internal.LootFile{
			"hdinsight-commands":         {Name: "hdinsight-commands", Contents: ""},
			"hdinsight-esp-analysis":     {Name: "hdinsight-esp-analysis", Contents: "# Enterprise Security Package (ESP) Analysis\n\n"},
			"hdinsight-kerberos-config":  {Name: "hdinsight-kerberos-config", Contents: "# Kerberos Configuration and Security\n\n"},
			"hdinsight-ranger-policies":  {Name: "hdinsight-ranger-policies", Contents: "# Apache Ranger Authorization Analysis\n\n"},
			"hdinsight-ldap-integration": {Name: "hdinsight-ldap-integration", Contents: "# LDAP/Azure AD DS Integration Security\n\n"},
			"hdinsight-security-posture": {Name: "hdinsight-security-posture", Contents: "# HDInsight Security Posture Assessment\n\n"},
		},
	}

	module.PrintHDInsight(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method
// ------------------------------
func (m *HDInsightModule) PrintHDInsight(ctx context.Context, logger internal.Logger) {
	if m.IsMultiTenant {
		for _, tenantCtx := range m.Tenants {
			savedTenantID := m.TenantID
			savedTenantName := m.TenantName
			savedTenantInfo := m.TenantInfo

			m.TenantID = tenantCtx.TenantID
			m.TenantName = tenantCtx.TenantName
			m.TenantInfo = tenantCtx.TenantInfo

			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_HDINSIGHT_MODULE_NAME, m.processSubscription)

			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_HDINSIGHT_MODULE_NAME, m.processSubscription)
	}
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *HDInsightModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)

	// Get resource groups
	rgs := sdk.CachedGetResourceGroupsPerSubscription(m.Session, subID)
	if len(rgs) == 0 {
		return
	}

	// Create HDInsight client
	hdiClient, err := azinternal.GetHDInsightClient(m.Session, subID)
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to create HDInsight client for subscription %s: %v", subID, err), globals.AZ_HDINSIGHT_MODULE_NAME)
		}
		m.CommandCounter.Error++
		return
	}

	// Process each resource group
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 10)

	for _, rg := range rgs {
		if rg.Name == nil {
			continue
		}
		rgName := *rg.Name

		wg.Add(1)
		go m.processResourceGroup(ctx, subID, subName, rgName, hdiClient, &wg, semaphore, logger)
	}

	wg.Wait()
}

// ------------------------------
// Process single resource group
// ------------------------------
func (m *HDInsightModule) processResourceGroup(ctx context.Context, subID, subName, rgName string, hdiClient *armhdinsight.ClustersClient, wg *sync.WaitGroup, semaphore chan struct{}, logger internal.Logger) {
	defer wg.Done()

	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	// Get region
	region := ""
	rgs := sdk.CachedGetResourceGroupsPerSubscription(m.Session, subID)
	for _, r := range rgs {
		if r.Name != nil && *r.Name == rgName && r.Location != nil {
			region = *r.Location
			break
		}
	}

	// List HDInsight clusters in resource group
	pager := hdiClient.NewListByResourceGroupPager(rgName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Failed to list HDInsight clusters in %s/%s: %v", subID, rgName, err), globals.AZ_HDINSIGHT_MODULE_NAME)
			}
			m.CommandCounter.Error++
			continue
		}

		for _, cluster := range page.Value {
			m.processCluster(ctx, subID, subName, rgName, region, cluster, logger)
		}
	}
}

// ------------------------------
// Process single HDInsight cluster
// ------------------------------
func (m *HDInsightModule) processCluster(ctx context.Context, subID, subName, rgName, region string, cluster *armhdinsight.Cluster, logger internal.Logger) {
	if cluster == nil || cluster.Name == nil {
		return
	}

	clusterName := *cluster.Name

	// Extract cluster properties
	clusterType := "N/A"
	clusterVersion := "N/A"
	clusterState := "N/A"
	provisioningState := "N/A"
	tier := "N/A"
	osType := "N/A"

	if cluster.Properties != nil {
		// Cluster type and version
		if cluster.Properties.ClusterDefinition != nil && cluster.Properties.ClusterDefinition.Kind != nil {
			clusterType = *cluster.Properties.ClusterDefinition.Kind
		}
		if cluster.Properties.ClusterVersion != nil {
			clusterVersion = *cluster.Properties.ClusterVersion
		}
		if cluster.Properties.ClusterState != nil {
			clusterState = *cluster.Properties.ClusterState
		}
		if cluster.Properties.ProvisioningState != nil {
			provisioningState = string(*cluster.Properties.ProvisioningState)
		}
		if cluster.Properties.Tier != nil {
			tier = string(*cluster.Properties.Tier)
		}
		if cluster.Properties.OSType != nil {
			osType = string(*cluster.Properties.OSType)
		}
	}

	createdDate := "N/A"
	if cluster.Properties != nil && cluster.Properties.CreatedDate != nil {
		createdDate = *cluster.Properties.CreatedDate
	}

	// Connectivity endpoints (SSH, HTTPS, etc.)
	sshEndpoint := "N/A"
	httpsEndpoint := "N/A"
	privateEndpoints := []string{}

	if cluster.Properties != nil && cluster.Properties.ConnectivityEndpoints != nil {
		for _, endpoint := range cluster.Properties.ConnectivityEndpoints {
			if endpoint.Name == nil {
				continue
			}
			endpointName := *endpoint.Name
			location := azinternal.SafeStringPtr(endpoint.Location)
			protocol := azinternal.SafeStringPtr(endpoint.Protocol)
			port := int32(0)
			if endpoint.Port != nil {
				port = *endpoint.Port
			}

			endpointStr := fmt.Sprintf("%s://%s:%d", protocol, location, port)

			// Categorize common endpoints
			if strings.Contains(strings.ToLower(endpointName), "ssh") {
				sshEndpoint = endpointStr
			} else if strings.Contains(strings.ToLower(endpointName), "https") || strings.Contains(strings.ToLower(endpointName), "gateway") {
				httpsEndpoint = endpointStr
			}

			// Track private IPs
			if endpoint.PrivateIPAddress != nil && *endpoint.PrivateIPAddress != "" {
				privateEndpoints = append(privateEndpoints, fmt.Sprintf("%s (%s)", endpointName, *endpoint.PrivateIPAddress))
			}
		}
	}

	privateEndpointsStr := "N/A"
	if len(privateEndpoints) > 0 {
		privateEndpointsStr = strings.Join(privateEndpoints, ", ")
	}

	// Disk encryption
	diskEncryptionEnabled := "Disabled"
	encryptionAtHost := "Disabled"

	if cluster.Properties != nil && cluster.Properties.DiskEncryptionProperties != nil {
		diskEncryptionEnabled = "Enabled"
		if cluster.Properties.DiskEncryptionProperties.EncryptionAtHost != nil && *cluster.Properties.DiskEncryptionProperties.EncryptionAtHost {
			encryptionAtHost = "Enabled"
		}
	}

	// Encryption in transit
	encryptionInTransit := "Disabled"
	if cluster.Properties != nil && cluster.Properties.EncryptionInTransitProperties != nil && cluster.Properties.EncryptionInTransitProperties.IsEncryptionInTransitEnabled != nil {
		if *cluster.Properties.EncryptionInTransitProperties.IsEncryptionInTransitEnabled {
			encryptionInTransit = "Enabled"
		}
	}

	// TLS version
	tlsVersion := "N/A"
	if cluster.Properties != nil && cluster.Properties.MinSupportedTLSVersion != nil {
		tlsVersion = *cluster.Properties.MinSupportedTLSVersion
	}

	// Security profile (Enterprise Security Package)
	espEnabled := "Disabled"
	domain := "N/A"
	directoryType := "N/A"

	if cluster.Properties != nil && cluster.Properties.SecurityProfile != nil {
		espEnabled = "Enabled"
		if cluster.Properties.SecurityProfile.Domain != nil {
			domain = *cluster.Properties.SecurityProfile.Domain
		}
		if cluster.Properties.SecurityProfile.DirectoryType != nil {
			directoryType = string(*cluster.Properties.SecurityProfile.DirectoryType)
		}
	}

	// EntraID Centralized Auth - based on ESP
	entraIDAuth := "Disabled"
	if espEnabled == "Enabled" {
		entraIDAuth = "Enabled"
	}

	// Managed identity
	systemAssignedID := "N/A"
	userAssignedIDs := "N/A"
	identityType := "None"

	if cluster.Identity != nil {
		if cluster.Identity.Type != nil {
			identityType = string(*cluster.Identity.Type)
		}
		if cluster.Identity.PrincipalID != nil {
			systemAssignedID = *cluster.Identity.PrincipalID
		}
		if cluster.Identity.UserAssignedIdentities != nil && len(cluster.Identity.UserAssignedIdentities) > 0 {
			uaIDs := []string{}
			for uaID := range cluster.Identity.UserAssignedIdentities {
				uaIDs = append(uaIDs, azinternal.ExtractResourceName(uaID))
			}
			userAssignedIDs = strings.Join(uaIDs, ", ")
		}
	}

	// Build row
	row := []string{
		m.TenantName,
		m.TenantID,
		subID,
		subName,
		rgName,
		region,
		clusterName,
		clusterType,
		clusterVersion,
		clusterState,
		provisioningState,
		tier,
		osType,
		sshEndpoint,
		httpsEndpoint,
		privateEndpointsStr,
		diskEncryptionEnabled,
		encryptionAtHost,
		encryptionInTransit,
		tlsVersion,
		espEnabled,
		domain,
		directoryType,
		entraIDAuth,
		identityType,
		createdDate,
		systemAssignedID,
		userAssignedIDs,
	}

	m.mu.Lock()
	m.HDIRows = append(m.HDIRows, row)
	m.mu.Unlock()
	m.CommandCounter.Total++

	// Generate loot
	m.generateLoot(subID, subName, rgName, clusterName, clusterType, sshEndpoint, httpsEndpoint, privateEndpointsStr, espEnabled, domain, systemAssignedID, userAssignedIDs, identityType)
}

// ------------------------------
// Generate loot
// ------------------------------
func (m *HDInsightModule) generateLoot(subID, subName, rgName, clusterName, clusterType, sshEndpoint, httpsEndpoint, privateEndpoints, espEnabled, domain, systemAssignedID, userAssignedIDs, identityType string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Azure CLI commands
	m.LootMap["hdinsight-commands"].Contents += fmt.Sprintf("# HDInsight Cluster: %s (Type: %s, Resource Group: %s)\n", clusterName, clusterType, rgName)
	m.LootMap["hdinsight-commands"].Contents += fmt.Sprintf("az account set --subscription %s\n", subID)
	m.LootMap["hdinsight-commands"].Contents += fmt.Sprintf("az hdinsight show --name %s --resource-group %s\n", clusterName, rgName)
	m.LootMap["hdinsight-commands"].Contents += fmt.Sprintf("az hdinsight list-usage --location %s -o table\n", rgName)
	if sshEndpoint != "N/A" {
		m.LootMap["hdinsight-commands"].Contents += fmt.Sprintf("# SSH Access: %s\n", sshEndpoint)
		// Extract hostname from endpoint if possible
		if strings.Contains(sshEndpoint, "://") {
			parts := strings.Split(sshEndpoint, "://")
			if len(parts) > 1 {
				hostPort := parts[1]
				m.LootMap["hdinsight-commands"].Contents += fmt.Sprintf("# ssh <username>@%s\n", strings.Split(hostPort, ":")[0])
			}
		}
	}
	m.LootMap["hdinsight-commands"].Contents += "\n"

	// ESP Analysis
	m.LootMap["hdinsight-esp-analysis"].Contents += fmt.Sprintf(
		"## Cluster: %s (%s)\n"+
			"**Resource Group**: %s\n"+
			"**Subscription**: %s\n"+
			"**ESP Enabled**: %s\n"+
			"**Domain**: %s\n\n",
		clusterName, clusterType,
		rgName,
		subName,
		espEnabled,
		domain,
	)

	if espEnabled == "Enabled" {
		m.LootMap["hdinsight-esp-analysis"].Contents += fmt.Sprintf(
			"### ESP Configuration:\n"+
				"This cluster has Enterprise Security Package enabled, which provides:\n"+
				"- Kerberos-based authentication\n"+
				"- Azure AD DS integration\n"+
				"- Apache Ranger for authorization\n"+
				"- LDAP/LDAPS user sync\n\n"+
				"### Security Benefits:\n"+
				"- Centralized user authentication via Azure AD\n"+
				"- Fine-grained authorization policies\n"+
				"- Audit logging of data access\n"+
				"- Integration with enterprise identity management\n\n"+
				"### ESP Configuration Commands:\n"+
				"```bash\n"+
				"# Get ESP configuration\n"+
				"az hdinsight show --name %s --resource-group %s \\\n"+
				"  --query 'properties.securityProfile' --output json\n\n"+
				"# List domain users synced to cluster\n"+
				"# (Requires SSH access to cluster)\n"+
				"ssh sshuser@%s-ssh.azurehdinsight.net\n"+
				"getent passwd | grep -v nologin | grep -v false\n\n"+
				"# List domain groups\n"+
				"getent group | grep -i hdinsight\n"+
				"```\n\n",
			clusterName, rgName,
			clusterName,
		)
	} else {
		m.LootMap["hdinsight-esp-analysis"].Contents += fmt.Sprintf(
			"### HIGH RISK: ESP Not Enabled\n"+
				"This cluster does NOT have Enterprise Security Package enabled.\n\n"+
				"**Security Gaps:**\n"+
				"- No centralized authentication (local accounts only)\n"+
				"- No fine-grained authorization (default Hadoop ACLs only)\n"+
				"- Limited audit logging\n"+
				"- No integration with Azure AD\n"+
				"- Shared cluster credentials\n\n"+
				"**Risks:**\n"+
				"- All users with cluster access have similar privileges\n"+
				"- Cannot track individual user activity\n"+
				"- Difficult to implement principle of least privilege\n"+
				"- Compliance challenges (HIPAA, PCI-DSS, etc.)\n\n"+
				"**Recommendation:**\n"+
				"Enable ESP for production clusters handling sensitive data.\n"+
				"Note: ESP can only be enabled during cluster creation.\n\n"+
				"```bash\n"+
				"# Create ESP-enabled cluster\n"+
				"az hdinsight create \\\n"+
				"  --name %s-esp \\\n"+
				"  --resource-group %s \\\n"+
				"  --type %s \\\n"+
				"  --esp \\\n"+
				"  --domain <AZURE_AD_DS_DOMAIN> \\\n"+
				"  --cluster-admin-account <ADMIN_USER> \\\n"+
				"  --cluster-users-group-dns <USERS_GROUP>\n"+
				"```\n\n",
			clusterName, rgName, clusterType,
		)
	}

	// Kerberos Configuration
	m.LootMap["hdinsight-kerberos-config"].Contents += fmt.Sprintf(
		"## Cluster: %s\n"+
			"**ESP Enabled**: %s\n"+
			"**Domain**: %s\n\n",
		clusterName,
		espEnabled,
		domain,
	)

	if espEnabled == "Enabled" {
		m.LootMap["hdinsight-kerberos-config"].Contents += fmt.Sprintf(
			"### Kerberos Configuration:\n"+
				"ESP-enabled clusters use Kerberos for authentication.\n\n"+
				"### Key Kerberos Files (on cluster nodes):\n"+
				"- `/etc/krb5.conf` - Kerberos client configuration\n"+
				"- `/etc/security/keytabs/` - Service keytabs\n"+
				"- `~/.kinit` - User Kerberos tickets\n\n"+
				"### Enumeration Commands:\n"+
				"```bash\n"+
				"# SSH to cluster\n"+
				"ssh sshuser@%s-ssh.azurehdinsight.net\n\n"+
				"# Check Kerberos configuration\n"+
				"cat /etc/krb5.conf\n\n"+
				"# List service principals\n"+
				"klist -ke /etc/security/keytabs/*.keytab\n\n"+
				"# Check current Kerberos ticket\n"+
				"klist\n\n"+
				"# Get Kerberos ticket for domain user\n"+
				"kinit user@%s\n\n"+
				"# Access Hadoop with Kerberos\n"+
				"hdfs dfs -ls /\n"+
				"hive -e \"SHOW DATABASES;\"\n"+
				"```\n\n"+
				"### Security Analysis:\n"+
				"**Keytab Files:**\n"+
				"- Service keytabs allow services to authenticate without passwords\n"+
				"- Located in `/etc/security/keytabs/`\n"+
				"- If compromised, attacker can impersonate services\n"+
				"- Check file permissions: `ls -la /etc/security/keytabs/`\n\n"+
				"**Ticket-Granting Tickets (TGT):**\n"+
				"- User TGTs cached in `/tmp/krb5cc_*`\n"+
				"- Default lifetime: 10 hours\n"+
				"- Can be stolen and replayed (Pass-the-Ticket attack)\n"+
				"- Check with: `ls -la /tmp/krb5cc_*`\n\n"+
				"**Kerberos Attacks:**\n"+
				"1. Keytab Extraction: Steal service keytabs for impersonation\n"+
				"2. Ticket Theft: Copy TGT files from `/tmp/`\n"+
				"3. Kerberoasting: Extract service account credentials\n"+
				"4. Golden Ticket: Forge TGTs with domain controller compromise\n\n",
			clusterName,
			domain,
		)
	} else {
		m.LootMap["hdinsight-kerberos-config"].Contents += "Kerberos is not configured (ESP not enabled).\n" +
			"Cluster uses basic authentication with shared cluster credentials.\n\n"
	}

	// Ranger Policies
	m.LootMap["hdinsight-ranger-policies"].Contents += fmt.Sprintf(
		"## Cluster: %s\n"+
			"**ESP Enabled**: %s\n\n",
		clusterName,
		espEnabled,
	)

	if espEnabled == "Enabled" {
		m.LootMap["hdinsight-ranger-policies"].Contents += fmt.Sprintf(
			"### Apache Ranger Authorization:\n"+
				"ESP-enabled clusters use Apache Ranger for fine-grained authorization.\n\n"+
				"### Ranger UI Access:\n"+
				"- URL: %s/ranger\n"+
				"- Default admin: Uses Azure AD credentials\n\n"+
				"### Ranger Policy Enumeration:\n"+
				"```bash\n"+
				"# Access Ranger UI\n"+
				"# Navigate to: %s/ranger\n"+
				"# Login with Azure AD credentials\n\n"+
				"# Ranger REST API\n"+
				"# Get authentication token first\n"+
				"RANGER_URL=\"%s/ranger\"\n"+
				"TOKEN=$(curl -u \"admin:PASSWORD\" -X POST \"$RANGER_URL/service/public/v2/api/authenticate\")\n\n"+
				"# List all policies\n"+
				"curl -H \"Authorization: Bearer $TOKEN\" \\\n"+
				"  \"$RANGER_URL/service/public/v2/api/policy\"\n\n"+
				"# List HDFS policies\n"+
				"curl -H \"Authorization: Bearer $TOKEN\" \\\n"+
				"  \"$RANGER_URL/service/public/v2/api/policy?serviceName=<CLUSTER_NAME>_hadoop\"\n\n"+
				"# List Hive policies\n"+
				"curl -H \"Authorization: Bearer $TOKEN\" \\\n"+
				"  \"$RANGER_URL/service/public/v2/api/policy?serviceName=<CLUSTER_NAME>_hive\"\n\n"+
				"# List HBase policies\n"+
				"curl -H \"Authorization: Bearer $TOKEN\" \\\n"+
				"  \"$RANGER_URL/service/public/v2/api/policy?serviceName=<CLUSTER_NAME>_hbase\"\n"+
				"```\n\n"+
				"### Security Analysis - Common Misconfigurations:\n\n"+
				"1. **Overly Permissive Policies:**\n"+
				"   - Policies granting `*` access to all resources\n"+
				"   - Public group with broad permissions\n"+
				"   - Default 'allow all' policies not disabled\n\n"+
				"2. **Missing Deny Policies:**\n"+
				"   - No explicit deny rules for sensitive data\n"+
				"   - Relying only on allow policies (not defense-in-depth)\n\n"+
				"3. **Privilege Escalation Paths:**\n"+
				"   - Users with HDFS write access to `/user/hive/warehouse`\n"+
				"   - Users with CREATE TABLE permissions\n"+
				"   - Users with ALTER permissions on databases\n\n"+
				"4. **Audit Log Gaps:**\n"+
				"   - Audit logging disabled for sensitive operations\n"+
				"   - Ranger audit logs not exported to external SIEM\n\n"+
				"### Ranger Audit Analysis:\n"+
				"```bash\n"+
				"# View recent access attempts\n"+
				"curl -H \"Authorization: Bearer $TOKEN\" \\\n"+
				"  \"$RANGER_URL/service/assets/accessAudit?startDate=<DATE>&endDate=<DATE>\"\n\n"+
				"# Find denied access attempts (potential unauthorized access)\n"+
				"curl -H \"Authorization: Bearer $TOKEN\" \\\n"+
				"  \"$RANGER_URL/service/assets/accessAudit?accessResult=0\" | jq .\n\n"+
				"# Find privileged operations\n"+
				"curl -H \"Authorization: Bearer $TOKEN\" \\\n"+
				"  \"$RANGER_URL/service/assets/accessAudit?accessType=CREATE,DROP,ALTER\" | jq .\n"+
				"```\n\n",
			httpsEndpoint,
			httpsEndpoint,
			httpsEndpoint,
		)
	} else {
		m.LootMap["hdinsight-ranger-policies"].Contents += "Apache Ranger is not configured (ESP not enabled).\n" +
			"Cluster uses default Hadoop ACLs for authorization.\n\n"
	}

	// LDAP Integration
	m.LootMap["hdinsight-ldap-integration"].Contents += fmt.Sprintf(
		"## Cluster: %s\n"+
			"**ESP Enabled**: %s\n"+
			"**Domain**: %s\n\n",
		clusterName,
		espEnabled,
		domain,
	)

	if espEnabled == "Enabled" {
		m.LootMap["hdinsight-ldap-integration"].Contents += fmt.Sprintf(
			"### Azure AD DS Integration:\n"+
				"ESP-enabled clusters integrate with Azure AD Domain Services for LDAP.\n\n"+
				"### LDAP Configuration:\n"+
				"- LDAP Server: Azure AD DS domain controllers\n"+
				"- LDAP Base DN: DC=%s\n"+
				"- User DN: CN=Users,DC=%s\n"+
				"- Group DN: CN=Groups,DC=%s\n\n"+
				"### Security Considerations:\n\n"+
				"1. **LDAP vs LDAPS:**\n"+
				"   - LDAP (TCP 389): Unencrypted, credentials sent in plaintext\n"+
				"   - LDAPS (TCP 636): Encrypted with TLS/SSL\n"+
				"   - ESP should use LDAPS for user sync\n\n"+
				"2. **Service Account Credentials:**\n"+
				"   - ESP uses a service account to bind to Azure AD DS\n"+
				"   - Credentials stored in cluster configuration\n"+
				"   - If cluster is compromised, service account exposed\n"+
				"   - Check: `az hdinsight show --name %s --resource-group %s --query 'properties.securityProfile.ldapProperties'`\n\n"+
				"3. **User Synchronization:**\n"+
				"   - All domain users synced to cluster\n"+
				"   - Group membership determines access\n"+
				"   - Verify least privilege: only necessary users should be in cluster groups\n\n"+
				"4. **Password Policies:**\n"+
				"   - Azure AD DS password policies apply\n"+
				"   - Check password expiration, complexity requirements\n"+
				"   - Monitor for weak passwords\n\n"+
				"### LDAP Enumeration:\n"+
				"```bash\n"+
				"# From cluster node (if ldapsearch is available)\n"+
				"ldapsearch -x -H ldaps://<AZURE_AD_DS_DC>:636 \\\n"+
				"  -D \"CN=HDIAdmin,OU=AADDC Users,DC=%s\" \\\n"+
				"  -W \\\n"+
				"  -b \"DC=%s\" \\\n"+
				"  \"(objectClass=user)\" cn mail\n\n"+
				"# List all groups\n"+
				"ldapsearch -x -H ldaps://<AZURE_AD_DS_DC>:636 \\\n"+
				"  -D \"CN=HDIAdmin,OU=AADDC Users,DC=%s\" \\\n"+
				"  -W \\\n"+
				"  -b \"DC=%s\" \\\n"+
				"  \"(objectClass=group)\" cn member\n"+
				"```\n\n"+
				"### Attack Scenarios:\n\n"+
				"1. **LDAP Credential Theft:**\n"+
				"   - Compromise cluster node\n"+
				"   - Extract LDAP service account credentials\n"+
				"   - Use credentials to enumerate entire domain\n\n"+
				"2. **LDAP Injection:**\n"+
				"   - If application queries LDAP based on user input\n"+
				"   - Inject LDAP filters to bypass authentication\n"+
				"   - Example: `cn=admin)(&(1=1))`\n\n"+
				"3. **Pass-the-Hash:**\n"+
				"   - Steal user hashes from cluster\n"+
				"   - Use for lateral movement to other domain resources\n\n",
			domain, domain, domain,
			clusterName, rgName,
			domain, domain,
			domain, domain,
		)
	} else {
		m.LootMap["hdinsight-ldap-integration"].Contents += "LDAP integration not configured (ESP not enabled).\n\n"
	}

	// Security Posture
	riskLevel := "INFO"
	if espEnabled == "Disabled" {
		riskLevel = "HIGH"
	} else if privateEndpoints == "N/A" {
		riskLevel = "MEDIUM"
	}

	m.LootMap["hdinsight-security-posture"].Contents += fmt.Sprintf(
		"## Cluster: %s (%s)\n"+
			"**Risk Level**: %s\n"+
			"**Resource Group**: %s\n"+
			"**Subscription**: %s\n\n"+
			"### Security Configuration:\n"+
			"- **ESP Enabled**: %s\n"+
			"- **Domain**: %s\n"+
			"- **SSH Endpoint**: %s\n"+
			"- **HTTPS Endpoint**: %s\n"+
			"- **Private Endpoints**: %s\n"+
			"- **Identity Type**: %s\n\n",
		clusterName, clusterType,
		riskLevel,
		rgName,
		subName,
		espEnabled,
		domain,
		sshEndpoint,
		httpsEndpoint,
		privateEndpoints,
		identityType,
	)

	m.LootMap["hdinsight-security-posture"].Contents += "### Security Assessment:\n\n"

	if espEnabled == "Disabled" {
		m.LootMap["hdinsight-security-posture"].Contents += "**CRITICAL: ESP Not Enabled**\n" +
			"- No centralized authentication\n" +
			"- No fine-grained authorization\n" +
			"- Shared cluster credentials\n" +
			"- Limited audit logging\n" +
			"- Recommendation: Enable ESP for production workloads\n\n"
	}

	if privateEndpoints == "N/A" {
		m.LootMap["hdinsight-security-posture"].Contents += "**MEDIUM RISK: Public Endpoints**\n" +
			"- Cluster accessible from public internet\n" +
			"- SSH and HTTPS endpoints exposed\n" +
			"- Recommendation: Use private endpoints or NSG restrictions\n\n"
	} else {
		m.LootMap["hdinsight-security-posture"].Contents += "**SECURE: Private Endpoints Configured**\n" +
			"- Cluster uses private connectivity\n" +
			"- Reduced attack surface\n\n"
	}

	if identityType != "None" {
		m.LootMap["hdinsight-security-posture"].Contents += "**Managed Identity Configured**\n" +
			"- Cluster can access Azure resources without credentials\n" +
			"- Check RBAC assignments: `az role assignment list --assignee <IDENTITY_ID>`\n" +
			"- Risk: Overprivileged identity = cluster compromise = Azure resource access\n\n"
	}

	m.LootMap["hdinsight-security-posture"].Contents += "\n"
}

// ------------------------------
// Write output
// ------------------------------
func (m *HDInsightModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.HDIRows) == 0 {
		logger.InfoM("No Azure HDInsight clusters found", globals.AZ_HDINSIGHT_MODULE_NAME)
		return
	}

	// Build headers
	headers := []string{
		"Tenant Name",
		"Tenant ID",
		"Subscription ID",
		"Subscription Name",
		"Resource Group",
		"Region",
		"Cluster Name",
		"Cluster Type",
		"Cluster Version",
		"Cluster State",
		"Provisioning State",
		"Tier",
		"OS Type",
		"SSH Endpoint",
		"HTTPS Endpoint",
		"Private Endpoints",
		"Disk Encryption",
		"Encryption at Host",
		"Encryption in Transit",
		"Min TLS Version",
		"ESP Enabled",
		"Domain",
		"Directory Type",
		"EntraID Centralized Auth",
		"Identity Type",
		"Created Date",
		"System Assigned Identity ID",
		"User Assigned Identity ID",
	}

	// Check if we should split output by tenant
	if m.IsMultiTenant {
		if err := m.FilterAndWritePerTenantAuto(
			ctx, logger, m.Tenants, m.HDIRows, headers,
			"hdinsight", globals.AZ_HDINSIGHT_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Check if we should split output by subscription
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		if err := m.FilterAndWritePerSubscriptionAuto(
			ctx, logger, m.Subscriptions, m.HDIRows, headers,
			"hdinsight", globals.AZ_HDINSIGHT_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Build loot array
	loot := []internal.LootFile{}
	for _, lf := range m.LootMap {
		if lf.Contents != "" {
			loot = append(loot, *lf)
		}
	}

	// Create output
	output := HDInsightOutput{
		Table: []internal.TableFile{{
			Name:   "hdinsight",
			Header: headers,
			Body:   m.HDIRows,
		}},
		Loot: loot,
	}

	// Determine output scope
	scopeType, scopeIDs, scopeNames := azinternal.DetermineScopeForOutput(m.Subscriptions, m.TenantID, m.TenantName, m.TenantFlagPresent)
	scopeNames = azinternal.GetSubscriptionNamesForOutput(ctx, m.Session, scopeType, scopeIDs)

	// Write output using HandleOutputSmart
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
		logger.ErrorM(fmt.Sprintf("Failed to write output: %v", err), globals.AZ_HDINSIGHT_MODULE_NAME)
		return
	}

	// Print summary
	logger.InfoM(fmt.Sprintf("Found %d Azure HDInsight clusters across %d subscriptions", len(m.HDIRows), len(m.Subscriptions)), globals.AZ_HDINSIGHT_MODULE_NAME)
}
