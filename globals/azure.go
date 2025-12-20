package globals

// Module directory tree
const AZ_DIR_BASE = "azure"
const AZ_DIR_TEN = "tenants"
const AZ_DIR_SUB = "subscriptions"

// Test file full names and paths
var (
	STORAGE_ACCOUNTS_TEST_FILE string
	VMS_TEST_FILE              string
	NICS_TEST_FILE             string
	PUBLIC_IPS_TEST_FILE       string
	RESOURCES_TEST_FILE        string
	ROLE_DEFINITIONS_TEST_FILE string
	ROLE_ASSIGNMENTS_TEST_FILE string
	AAD_USERS_TEST_FILE        string
	ACR_REGISTRIES_TEST_FILE   string
	AZ_VERBOSITY               int

	// Token-based authentication
	// Separate tokens for ARM and Graph APIs
	AZ_ARM_TOKEN   string // Token for Azure Resource Manager (https://management.azure.com/)
	AZ_GRAPH_TOKEN string // Token for Microsoft Graph (https://graph.microsoft.com/)

	// Legacy single token support (deprecated, use ARM/Graph tokens instead)
	AZ_BEARER_TOKEN string
)

var CommonScopes = []string{
	"https://management.azure.com/",        // ARM
	"https://graph.microsoft.com/",         // Microsoft Graph
	"https://vault.azure.net/",             // Key Vault
	"https://storage.azure.com/",           // Storage
	"https://app.vssps.visualstudio.com",   // Azure DevOps
	"499b84ac-1321-427f-b974-133d113dbe4b", // Azure DevOps (GUID)
}

// Module names
const AZ_UTILS_MODULE_NAME = "utils"
const AZ_WHOAMI_MODULE_NAME = "whoami"
const AZ_INVENTORY_MODULE_NAME = "inventory"
const AZ_VMS_MODULE_NAME = "vms"
const AZ_RBAC_MODULE_NAME = "rbac"
const AZ_STORAGE_MODULE_NAME = "storage"
const AZ_ACR_MODULE_NAME = "acr"
const AZ_KEYVAULT_MODULE_NAME = "keyvaults"
const AZ_AKS_MODULE_NAME = "aks"
const AZ_WEBAPPS_MODULE_NAME = "webapps"
const AZ_DATABASES_MODULE_NAME = "databases"
const AZ_FUNCTIONS_MODULE_NAME = "functions"
const AZ_ACCESSKEYS_MODULE_NAME = "accesskeys"
const AZ_ENDPOINTS_MODULE_NAME = "endpoints"
const AZ_DNS_MODULE_NAME = "dns"
const AZ_APPGATEWAY_MODULE_NAME = "app-gateway"
const AZ_DEPLOYMENTS_MODULE_NAME = "deployments"
const AZ_DEVOPS_PIPELINES_MODULE_NAME = "devops-pipelines"
const AZ_DEVOPS_PROJECTS_MODULE_NAME = "devops-projects"
const AZ_DEVOPS_ARTIFACTS_MODULE_NAME = "devops-artifacts"
const AZ_DEVOPS_REPOS_MODULE_NAME = "devops-repos"
const AZ_DEVOPS_SECURITY_MODULE_NAME = "devops-security"
const AZ_DEVOPS_AGENTS_MODULE_NAME = "devops-agents"
const AZ_FEDERATED_CREDENTIALS_MODULE_NAME = "federated-credentials"
const AZ_CONTAINER_JOBS_MODULE_NAME = "container-apps"
const AZ_NIC_MODULE_NAME = "nics"
const AZ_FILESYSTEMS_MODULE = "filesystems"
const AZ_AUTOMATION_MODULE_NAME = "automation"
const AZ_PRINCIPALS_MODULE_NAME = "principals"
const AZ_PERMISSIONS_MODULE_NAME = "permissions"
const AZ_ENTERPRISE_APPS_MODULE_NAME = "enterprise-apps"
const AZ_CONDITIONAL_ACCESS_MODULE_NAME = "conditional-access"
const AZ_CONSENT_GRANTS_MODULE_NAME = "consent-grants"
const AZ_MACHINE_LEARNING_MODULE_NAME = "machine-learning"
const AZ_BATCH_MODULE_NAME = "batch"
const AZ_LOAD_TESTING_MODULE_NAME = "load-testing"
const AZ_REDIS_MODULE_NAME = "redis"
const AZ_SYNAPSE_MODULE_NAME = "synapse"
const AZ_ARC_MODULE_NAME = "arc"
const AZ_API_MANAGEMENT_MODULE_NAME = "api-management"
const AZ_APP_CONFIGURATION_MODULE_NAME = "app-configuration"
const AZ_DISKS_MODULE_NAME = "disks"
const AZ_LOGICAPPS_MODULE_NAME = "logicapps"
const AZ_POLICY_MODULE_NAME = "policy"
const AZ_IOTHUB_MODULE_NAME = "iothub"
const AZ_PRIVATELINK_MODULE_NAME = "privatelink"
const AZ_DATABRICKS_MODULE_NAME = "databricks"
const AZ_NSG_MODULE_NAME = "nsg"
const AZ_FIREWALL_MODULE_NAME = "firewall"
const AZ_LOAD_BALANCERS_MODULE_NAME = "load-balancers"
const AZ_ROUTES_MODULE_NAME = "routes"
const AZ_VNETS_MODULE_NAME = "vnets"
const AZ_KUSTO_MODULE_NAME = "kusto"
const AZ_DATAFACTORY_MODULE_NAME = "datafactory"
const AZ_STREAMANALYTICS_MODULE_NAME = "streamanalytics"
const AZ_HDINSIGHT_MODULE_NAME = "hdinsight"
const AZ_SPRINGAPPS_MODULE_NAME = "spring-apps"
const AZ_SIGNALR_MODULE_NAME = "signalr"
const AZ_SERVICEFABRIC_MODULE_NAME = "service-fabric"
const AZ_NETWORK_EXPOSURE_MODULE_NAME = "network-exposure"
const AZ_LATERAL_MOVEMENT_MODULE_NAME = "lateral-movement"
const AZ_VPN_GATEWAY_MODULE_NAME = "vpn-gateway"
const AZ_EXPRESSROUTE_MODULE_NAME = "expressroute"
const AZ_DATA_EXFILTRATION_MODULE_NAME = "data-exfiltration"
const AZ_SECURITY_CENTER_MODULE_NAME = "security-center"
const AZ_MONITOR_MODULE_NAME = "monitor"
const AZ_BACKUP_INVENTORY_MODULE_NAME = "backup-inventory"
const AZ_SENTINEL_MODULE_NAME = "sentinel"
const AZ_FRONTDOOR_MODULE_NAME = "frontdoor"
const AZ_CDN_MODULE_NAME = "cdn"
const AZ_TRAFFIC_MANAGER_MODULE_NAME = "traffic-manager"
const AZ_NETWORK_TOPOLOGY_MODULE_NAME = "network-topology"
const AZ_BASTION_MODULE_NAME = "bastion"
const AZ_IDENTITY_PROTECTION_MODULE_NAME = "identity-protection"
const AZ_PRIVILEGE_ESCALATION_MODULE_NAME = "privilege-escalation"
const AZ_LIGHTHOUSE_MODULE_NAME = "lighthouse"
const AZ_COMPLIANCE_DASHBOARD_MODULE_NAME = "compliance-dashboard"
const AZ_COST_SECURITY_MODULE_NAME = "cost-security"
const AZ_RESOURCE_GRAPH_MODULE_NAME = "resource-graph"

// Microsoft endpoints
const AZ_RESOURCE_MANAGER_ENDPOINT = "https://management.azure.com/"
const AZ_GRAPH_ENDPOINT = "https://graph.windows.net/"

const AZ_VERBOSE_ERRORS = 9
