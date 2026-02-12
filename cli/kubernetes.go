package cli

import (
	"fmt"
	"strings"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	k8sinternal "github.com/BishopFox/cloudfox/internal/kubernetes"
	"github.com/BishopFox/cloudfox/kubernetes/commands"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/BishopFox/cloudfox/kubernetes/sdk"
	"github.com/BishopFox/cloudfox/kubernetes/shared"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	// K8s auth options
	K8sToken       string
	K8sContext     string
	K8sKubeConfig  string
	K8sAPIServer   string
	K8sClusterName string

	// Namespace filtering options
	K8sNamespaceFlag     string // Comma-delimited list of namespaces
	K8sNamespaceListFile string
	K8sAllNamespaces     bool

	// Output formatting options
	K8sOutputFormat    string
	K8sOutputDirectory string
	K8sVerbosity       int
	K8sWrapTable       bool
	K8sTimeout         int // API timeout in seconds
	//	K8sMergedTable     bool

	// Cloud provider configuration (for network-exposure correlation)
	K8sCloudProvider     string // Comma-separated list: aws,gcp,azure
	K8sAWSProfile        string
	K8sAzureSubscription string
	K8sGCPProject        string

	// Admission controller filtering for lazy CRD discovery
	K8sAdmissionControllers string // Comma-separated list or "all"

	// Detailed output flag
	K8sDetailed bool

	// logger
	logger = internal.NewLogger()

	K8sCommands = &cobra.Command{
		Use:     "kubernetes",
		Aliases: []string{"k8s"},
		Long:    `See "Available Commands" for Kubernetes Modules below`,
		Short:   "See \"Available Commands\" for Kubernetes Modules below",

		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			// Only init config if the command isn't just asking for help
			if !cmd.HasSubCommands() || cmd.CalledAs() == "all-checks" {
				config.InitConfig(K8sKubeConfig, K8sContext, K8sToken, K8sAPIServer)

				clientset := config.GetClientOrExit()
				// If user passed --cluster-name, use that. Otherwise, detect it.
				if K8sClusterName != "" {
					globals.ClusterName = K8sClusterName
				} else {
					// Suppress stderr during cluster name detection to hide noisy auth plugin output
					restoreStderr := sdk.SuppressStderr()
					globals.ClusterName = k8sinternal.GetClusterName(clientset)
					restoreStderr()
				}

				// Handle namespace filtering
				ctx, cancel := shared.ContextWithTimeout()
				defer cancel()

				if K8sNamespaceFlag != "" {
					// Comma-delimited namespace list specified
					rawNamespaces := strings.Split(K8sNamespaceFlag, ",")
					for _, ns := range rawNamespaces {
						ns = strings.TrimSpace(ns)
						if ns != "" {
							globals.K8sNamespaces = append(globals.K8sNamespaces, ns)
						}
					}
					if len(globals.K8sNamespaces) == 1 {
						globals.K8sNamespace = globals.K8sNamespaces[0]
					}
					globals.K8sAllNamespaces = false
					logger.InfoM(fmt.Sprintf("Targeting %d namespace(s): %s", len(globals.K8sNamespaces), strings.Join(globals.K8sNamespaces, ", ")), "kubernetes")
				} else if K8sNamespaceListFile != "" {
					// Load namespaces from file
					rawNamespaces := internal.LoadFileLinesIntoArray(K8sNamespaceListFile)
					globals.K8sNamespaces = deduplicateNamespaces(rawNamespaces)
					globals.K8sAllNamespaces = false
					logger.InfoM(fmt.Sprintf("Targeting %d namespace(s) from file", len(globals.K8sNamespaces)), "kubernetes")
				} else if K8sAllNamespaces {
					// Discover all namespaces
					namespaces, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
					if err != nil {
						logger.ErrorM(fmt.Sprintf("Failed to list namespaces: %v", err), "kubernetes")
					} else {
						for _, ns := range namespaces.Items {
							globals.K8sNamespaces = append(globals.K8sNamespaces, ns.Name)
						}
					}
					globals.K8sAllNamespaces = true
					logger.InfoM(fmt.Sprintf("Targeting all %d namespace(s)", len(globals.K8sNamespaces)), "kubernetes")
				} else {
					// Default: all namespaces
					namespaces, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
					if err != nil {
						logger.ErrorM(fmt.Sprintf("Failed to list namespaces: %v", err), "kubernetes")
					} else {
						for _, ns := range namespaces.Items {
							globals.K8sNamespaces = append(globals.K8sNamespaces, ns.Name)
						}
					}
					globals.K8sAllNamespaces = true
				}

				// Store cloud provider configuration in globals for network-exposure command
				// Parse --cloud-provider flag (comma-separated: aws,gcp,azure)
				if K8sCloudProvider != "" {
					providers := strings.Split(K8sCloudProvider, ",")
					for _, p := range providers {
						p = strings.TrimSpace(strings.ToLower(p))
						if p == "aws" || p == "gcp" || p == "azure" || p == "az" {
							// Normalize "az" to "azure"
							if p == "az" {
								p = "azure"
							}
							globals.K8sCloudProviders = append(globals.K8sCloudProviders, p)
						}
					}
				}
				globals.K8sAWSProfile = K8sAWSProfile

				// Parse --azure-subscription (comma-separated)
				if K8sAzureSubscription != "" {
					for _, sub := range strings.Split(K8sAzureSubscription, ",") {
						sub = strings.TrimSpace(sub)
						if sub != "" {
							globals.K8sAzureSubscriptions = append(globals.K8sAzureSubscriptions, sub)
						}
					}
				}

				// Parse --gcp-project (comma-separated)
				if K8sGCPProject != "" {
					for _, proj := range strings.Split(K8sGCPProject, ",") {
						proj = strings.TrimSpace(proj)
						if proj != "" {
							globals.K8sGCPProjects = append(globals.K8sGCPProjects, proj)
						}
					}
				}

				// Set timeout
				globals.K8sTimeout = K8sTimeout

				// Set detailed output flag
				globals.K8sDetailed = K8sDetailed

				// Parse --admission-controllers flag
				if K8sAdmissionControllers != "" {
					if strings.ToLower(K8sAdmissionControllers) == "all" {
						// "all" means check everything (empty slice = no filter)
						globals.K8sAdmissionControllers = nil
					} else {
						for _, ctrl := range strings.Split(K8sAdmissionControllers, ",") {
							ctrl = strings.TrimSpace(strings.ToLower(ctrl))
							if ctrl != "" {
								globals.K8sAdmissionControllers = append(globals.K8sAdmissionControllers, ctrl)
							}
						}
						if len(globals.K8sAdmissionControllers) > 0 {
							logger.InfoM(fmt.Sprintf("Filtering admission checks to: %s", strings.Join(globals.K8sAdmissionControllers, ", ")), "kubernetes")
						}
					}
				}
			}
		},

		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}
)

// deduplicateNamespaces removes duplicates, trims whitespace, and filters empty entries
func deduplicateNamespaces(namespaces []string) []string {
	seen := make(map[string]bool)
	var result []string
	duplicateCount := 0

	for _, ns := range namespaces {
		// Trim whitespace
		ns = strings.TrimSpace(ns)

		// Skip empty lines
		if ns == "" {
			continue
		}

		// Skip duplicates
		if seen[ns] {
			duplicateCount++
			continue
		}

		seen[ns] = true
		result = append(result, ns)
	}

	if duplicateCount > 0 {
		logger.InfoM(fmt.Sprintf("Removed %d duplicate namespace(s) from list", duplicateCount), "kubernetes")
	}

	return result
}

var K8sAllChecksCommand = &cobra.Command{
	Use:   "all-checks",
	Short: "Runs all available Kubernetes commands",
	Long:  `Executes all available Kubernetes commands to collect and display information from the cluster.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Warm the cache before running all modules to avoid redundant API calls
		ctx, cancel := shared.ContextWithTimeout()
		defer cancel()
		clientset := config.GetClientOrExit()

		logger.InfoM("Pre-fetching Kubernetes resources to cache...", "all-checks")
		if err := sdk.WarmCache(ctx, clientset); err != nil {
			logger.ErrorM(fmt.Sprintf("Cache warming failed (continuing anyway): %v", err), "all-checks")
		}

		for _, childCmd := range K8sCommands.Commands() {
			if childCmd == cmd { // Skip the run-all command itself to avoid infinite recursion
				continue
			}

			logger.InfoM(fmt.Sprintf("Running command: %s", childCmd.Use), "all-checks")
			childCmd.Run(cmd, args)
		}

		// Clear cache after all-checks completes
		sdk.Flush()
	},
}

func init() {
	// Register global flags for Kubernetes module
	K8sCommands.PersistentFlags().StringVarP(&K8sToken, "token", "t", "", "Service Account Token")
	K8sCommands.PersistentFlags().StringVarP(&K8sContext, "context", "c", "", "Kube-config context (overrides default kube-config)")
	K8sCommands.PersistentFlags().StringVarP(&K8sKubeConfig, "kube-config", "k", "", "Path to a kube config file")
	K8sCommands.PersistentFlags().StringVarP(&K8sAPIServer, "api-server", "s", "", "Kubernetes API server URL (used with --token)")
	K8sCommands.PersistentFlags().StringVar(&K8sClusterName, "cluster-name", "", "Kubernetes Cluster Name (overrides default cluster name)")

	// Namespace filtering flags
	K8sCommands.PersistentFlags().StringVarP(&K8sNamespaceFlag, "namespace", "n", "", "Target specific namespace(s) - comma-delimited (e.g., default,kube-system)")
	K8sCommands.PersistentFlags().StringVarP(&K8sNamespaceListFile, "namespace-list", "N", "", "Path to a file containing a list of namespaces")
	K8sCommands.PersistentFlags().BoolVarP(&K8sAllNamespaces, "all-namespaces", "A", true, "Target all namespaces (default)")

	//K8sCommands.PersistentFlags().StringVarP(&K8sOutputFormat, "output", "o", "all", "[\"table\" | \"csv\" | \"all\"]")
	K8sCommands.PersistentFlags().StringVar(&K8sOutputDirectory, "outdir", defaultOutputDir, "Output Directory ")
	K8sCommands.PersistentFlags().IntVarP(&Verbosity, "verbosity", "v", 2, "1 = Print control messages only\n2 = Print control messages, module output\n3 = Print control messages, module output, and loot file output\n")
	K8sCommands.PersistentFlags().BoolVarP(&K8sWrapTable, "wrap", "w", false, "Wrap table to fit in terminal (complicates grepping)")
	K8sCommands.PersistentFlags().IntVar(&K8sTimeout, "timeout", 300, "API timeout in seconds (default: 300s/5min)")
	//	K8sCommands.PersistentFlags().BoolVarP(&K8sMergedTable, "merged-table", "m", false, "Write one table for all namespaces (default: per namespace)")

	// Cloud provider configuration flags (for network-exposure correlation)
	K8sCommands.PersistentFlags().StringVar(&K8sCloudProvider, "cloud-provider", "", "Enable cloud correlation for specified providers - comma-separated (aws,gcp,azure)")
	K8sCommands.PersistentFlags().StringVar(&K8sAWSProfile, "aws-profile", "", "AWS profile name (optional, uses default credentials if not specified)")
	K8sCommands.PersistentFlags().StringVar(&K8sAzureSubscription, "azure-subscription", "", "Azure subscription ID(s) - comma-separated (optional, discovers all if not specified)")
	K8sCommands.PersistentFlags().StringVar(&K8sGCPProject, "gcp-project", "", "GCP project ID(s) - comma-separated (optional, discovers all if not specified)")

	// Admission controller filtering flag for lazy CRD discovery
	K8sCommands.PersistentFlags().StringVar(&K8sAdmissionControllers, "admission-controllers", "",
		"Filter admission modules to only check for specified controllers - comma-separated\n"+
			"Use 'all' to check all (default behavior). Known controllers:\n"+
			"  Pod/Security: gatekeeper, kyverno, pss, vap\n"+
			"  Runtime: falco, tetragon, kubearmor, tracee, sysdig, prisma, aqua, stackrox, neuvector, crowdstrike\n"+
			"  Image: trivy, harbor, notary, cosign, prisma, aqua, stackrox, anchore\n"+
			"  Network: calico, cilium, istio, linkerd\n"+
			"  Secrets: vault, external-secrets, sealed-secrets\n"+
			"  Certs: cert-manager, venafi\n"+
			"  Other: coredns, opa")

	// Detailed output flag
	K8sCommands.PersistentFlags().BoolVarP(&K8sDetailed, "detailed", "d", false, "Show detailed output for modules that support it (admission modules, crds)")

	// Add subcommands
	K8sCommands.AddCommand(
		// Identity & Access
		commands.WhoamiCmd,
		commands.PermissionsCmd,
		commands.RoleBindingsCmd,
		commands.ServiceAccountsCmd,
		commands.HiddenAdminsCmd,
		commands.CloudIAMCmd,

		// Attack Path Analysis
		commands.PrivescCmd,
		commands.LateralMovementCmd,
		commands.DataExfiltrationCmd,

		// Workloads
		commands.PodsCmd,
		commands.DeploymentsCmd,
		commands.DaemonSetsCmd,
		commands.StatefulSetsCmd,
		commands.ReplicaSetsCmd,
		commands.JobsCmd,
		commands.CronJobsCmd,

		// Security
		commands.SecretsCmd,
		commands.ConfigMapsCmd,
		commands.PodAdmissionCmd,
		commands.ImageAdmissionCmd,
		commands.SecretAdmissionCmd,
		commands.RuntimeAdmissionCmd,
		commands.AuditAdmissionCmd,
		commands.MeshAdmissionCmd,
		commands.CertAdmissionCmd,
		commands.MultitenancyAdmissionCmd,
		commands.DNSAdmissionCmd,
		commands.WebhooksCmd,
		commands.CRDsCmd,

		// Networking
		commands.ServicesCmd,
		commands.EndpointsCmd,
		commands.IngressCmd,
		commands.NetworkAdmissionCmd,
		commands.NetworkExposureCmd,

		// Storage
		commands.PersistentVolumesCmd,
		commands.StorageClassesCmd,

		// Cluster Resources
		commands.NodesCmd,
		commands.NamespacesCmd,
		commands.TaintsCmd,
		commands.TolerationsCmd,
		commands.TaintsTolerationsCmd,
		commands.PriorityClassesCmd,
		commands.ResourceQuotasCmd,

		// Availability & Scaling
		commands.PodDisruptionBudgetsCmd,
		commands.HPAsCmd,

		// Observability
		commands.EventsCmd,

		// Meta
		K8sAllChecksCommand,
	)
}
