package globals

// Module names
const (
	K8S_CONFIGMAPS_MODULE_NAME         string = "configmaps"
	K8S_CRONJOBS_MODULE_NAME           string = "cronjobs"
	K8S_DAEMONSETS_MODULE_NAME         string = "daemonsets"
	K8S_DEPLOYMENTS_MODULE_NAME        string = "deployments"
	K8S_ENDPOINTS_MODULE_NAME          string = "endpoints"
	K8S_HIDDEN_ADMINS_MODULE_NAME      string = "hidden_admins"
	K8S_INGRESS_MODULE_NAME            string = "ingress"
	K8S_JOBS_MODULE_NAME               string = "jobs"
	K8S_PERSISTENT_VOLUMES_MODULE_NAME string = "persistent_volumes"
	K8S_NAMESPACES_MODULE_NAME         string = "namespaces"
	K8S_NETWORK_POLICY_MODULE_NAME     string = "network_policy"
	K8S_NETWORK_PORTS_MODULE_NAME      string = "network_ports"
	K8S_NODES_MODULE_NAME              string = "nodes"
	K8S_PERMISSIONS_MODULE_NAME        string = "permissions"
	K8S_POD_SECURITY_MODULE_NAME       string = "pod_security"
	K8S_PODS_MODULE_NAME               string = "pods"
	K8S_REPLICASETS_MODULE_NAME        string = "replicasets"
	K8S_SECRETS_MODULE_NAME            string = "secrets"
	K8S_SERVICEACCOUNTS_MODULE_NAME    string = "serviceaccounts"
	K8S_SERVICES_MODULE_NAME           string = "services"
	K8S_STATEFULSETS_MODULE_NAME       string = "statefulsets"
	K8S_TAINTS_TOLERATIONS_MODULE_NAME string = "taints_tolerations"
	K8S_TAINTS_MODULE_NAME             string = "taints"
	K8S_TOLERATIONS_MODULE_NAME        string = "tolerations"
	K8S_WEBHOOKS_MODULE_NAME           string = "webhooks"
	K8S_WHOAMI_MODULE_NAME             string = "whoami"
	K8S_AUTH_MODULE_NAME               string = "auth"
)

var (
	KubeConfigPath string = ""
	KubeContext    string = ""
	KubeToken      string = ""
	KubeAPIServer  string = ""
	RawKubeconfig  []byte
	ClusterName    string = ""
)
