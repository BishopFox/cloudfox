package globals

// Module directory tree
const AZ_DIR_BASE = "azure"
const AZ_DIR_TEN = "tenants"
const AZ_DIR_SUB = "subscriptions"

// Test file full names and paths
var STORAGE_ACCOUNTS_TEST_FILE string
var VMS_TEST_FILE string
var NICS_TEST_FILE string
var PUBLIC_IPS_TEST_FILE string
var RESOURCES_TEST_FILE string
var ROLE_DEFINITIONS_TEST_FILE string
var ROLE_ASSIGNMENTS_TEST_FILE string
var AAD_USERS_TEST_FILE string

// Module names
const AZ_WHOAMI_MODULE_NAME = "whoami"
const AZ_INVENTORY_MODULE_NAME = "inventory"
const AZ_VMS_MODULE_NAME = "vms"
const AZ_RBAC_MODULE_NAME = "rbac"
const AZ_STORAGE_MODULE_NAME = "storage"

// Microsoft endpoints
const AZ_RESOURCE_MANAGER_ENDPOINT = "https://management.azure.com/"
const AZ_GRAPH_ENDPOINT = "https://graph.windows.net/"
