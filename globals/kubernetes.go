package globals

// Module names
const (
	K8S_CONFIGMAPS_MODULE_NAME         string = "configmaps"
	K8S_CRDS_MODULE_NAME               string = "crds"
	K8S_CRONJOBS_MODULE_NAME           string = "cronjobs"
	K8S_DAEMONSETS_MODULE_NAME         string = "daemonsets"
	K8S_DEPLOYMENTS_MODULE_NAME        string = "deployments"
	K8S_ENDPOINTS_MODULE_NAME          string = "endpoints"
	K8S_EVENTS_MODULE_NAME             string = "events"
	K8S_HIDDEN_ADMINS_MODULE_NAME      string = "hidden_admins"
	K8S_HPAS_MODULE_NAME               string = "hpas"
	K8S_INGRESS_MODULE_NAME            string = "ingress"
	K8S_JOBS_MODULE_NAME               string = "jobs"
	K8S_PERSISTENT_VOLUMES_MODULE_NAME string = "persistent_volumes"
	K8S_NAMESPACES_MODULE_NAME         string = "namespaces"
	K8S_NETWORK_POLICY_MODULE_NAME     string = "network_policy" // Alias for backwards compatibility
	K8S_NETWORK_ADMISSION_MODULE_NAME  string = "network_admission"
	K8S_NETWORK_PORTS_MODULE_NAME      string = "network_ports"
	K8S_NODES_MODULE_NAME              string = "nodes"
	K8S_PERMISSIONS_MODULE_NAME        string = "permissions"
	K8S_POD_ADMISSION_MODULE_NAME      string = "pod_admission"
	K8S_POD_SECURITY_MODULE_NAME       string = "pod_admission" // Alias for backwards compatibility
	K8S_PODDISRUPTIONBUDGETS_MODULE_NAME string = "poddisruptionbudgets"
	K8S_PODS_MODULE_NAME               string = "pods"
	K8S_PRIORITYCLASSES_MODULE_NAME    string = "priorityclasses"
	K8S_REPLICASETS_MODULE_NAME        string = "replicasets"
	K8S_RESOURCEQUOTAS_MODULE_NAME     string = "resourcequotas"
	K8S_SECRETS_MODULE_NAME            string = "secrets"
	K8S_SERVICEACCOUNTS_MODULE_NAME    string = "serviceaccounts"
	K8S_SERVICES_MODULE_NAME           string = "services"
	K8S_STATEFULSETS_MODULE_NAME       string = "statefulsets"
	K8S_STORAGECLASSES_MODULE_NAME     string = "storageclasses"
	K8S_TAINTS_TOLERATIONS_MODULE_NAME string = "taints_tolerations"
	K8S_TAINTS_MODULE_NAME             string = "taints"
	K8S_TOLERATIONS_MODULE_NAME        string = "tolerations"
	K8S_WEBHOOKS_MODULE_NAME           string = "webhooks"
	K8S_WHOAMI_MODULE_NAME             string = "whoami"
	K8S_AUTH_MODULE_NAME               string = "auth"
	K8S_PRIVESC_MODULE_NAME            string = "privesc"
	K8S_LATERAL_MOVEMENT_MODULE_NAME   string = "lateral_movement"
	K8S_DATA_EXFIL_MODULE_NAME         string = "data_exfiltration"
	K8S_ROLEBINDINGS_MODULE_NAME       string = "rolebindings"
)

var (
	KubeConfigPath string = ""
	KubeContext    string = ""
	KubeToken      string = ""
	KubeAPIServer  string = ""
	RawKubeconfig  []byte
	ClusterName    string = ""

	// Namespace filtering
	K8sNamespace      string   // Single namespace filter
	K8sNamespaces     []string // List of namespaces to target
	K8sAllNamespaces  bool     // Target all namespaces (default)

	// API timeout
	K8sTimeout        int      // API timeout in seconds

	// Cloud provider configuration for network exposure correlation
	K8sCloudProviders      []string // List of cloud providers to use (aws, gcp, azure)
	K8sAWSProfile          string   // AWS profile name for cloud correlation
	K8sAzureSubscriptions  []string // Azure subscription IDs for cloud correlation (CSV supported)
	K8sGCPProjects         []string // GCP project IDs for cloud correlation (CSV supported)

	// Admission controller filtering for lazy CRD discovery
	// Supports: "all", or comma-separated list of known controllers
	// Known controllers: gatekeeper, kyverno, pss, vap, falco, tetragon, prisma, aqua, stackrox,
	//                    neuvector, crowdstrike, trivy, harbor, notary, cosign, istio, linkerd,
	//                    cert-manager, vault, external-secrets, calico, cilium, coredns, etc.
	K8sAdmissionControllers []string // List of admission controllers to check for (empty = all)

	// Detailed output flag
	K8sDetailed bool // Show detailed output for modules that support it
)
