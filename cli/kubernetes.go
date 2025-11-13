package cli

import (
	"fmt"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	k8sinternal "github.com/BishopFox/cloudfox/internal/kubernetes"
	"github.com/BishopFox/cloudfox/kubernetes/commands"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/spf13/cobra"
)

var (
	// K8s auth options
	K8sToken       string
	K8sContext     string
	K8sKubeConfig  string
	K8sAPIServer   string
	K8sClusterName string

	// Output formatting options
	K8sOutputFormat    string
	K8sOutputDirectory string
	K8sVerbosity       int
	K8sWrapTable       bool
	//	K8sMergedTable     bool

	// logger
	logger = internal.NewLogger()

	K8sCommands = &cobra.Command{
		Use:     "kubernetes",
		Aliases: []string{"k8s"},
		Long:    `See "Available Commands" for Kubernetes Modules below`,
		Short:   "See \"Available Commands\" for Kubernetes Modules below",

		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			// Only init config if the command isn’t just asking for help
			if !cmd.HasSubCommands() || cmd.CalledAs() == "all-checks" {
				config.InitConfig(K8sKubeConfig, K8sContext, K8sToken, K8sAPIServer)

				clientset := config.GetClientOrExit()
				// If user passed --cluster-name, use that. Otherwise, detect it.
				if K8sClusterName != "" {
					globals.ClusterName = K8sClusterName
				} else {
					globals.ClusterName = k8sinternal.GetClusterName(clientset)
				}

			}
		},

		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}
)

var K8sAllChecksCommand = &cobra.Command{
	Use:   "all-checks",
	Short: "Runs all available Kubernetes commands",
	Long:  `Executes all available Kubernetes commands to collect and display information from the cluster.`,
	Run: func(cmd *cobra.Command, args []string) {
		for _, childCmd := range K8sCommands.Commands() {
			if childCmd == cmd { // Skip the run-all command itself to avoid infinite recursion
				continue
			}

			logger.InfoM(fmt.Sprintf("Running command: %s", childCmd.Use), "all-checks")
			childCmd.Run(cmd, args)
		}
	},
}

func init() {
	// Register global flags for Kubernetes module
	K8sCommands.PersistentFlags().StringVarP(&K8sToken, "token", "t", "", "Service Account Token")
	K8sCommands.PersistentFlags().StringVarP(&K8sContext, "context", "c", "", "Kube-config context (overrides default kube-config)")
	K8sCommands.PersistentFlags().StringVarP(&K8sKubeConfig, "kube-config", "k", "", "Path to a kube config file")
	K8sCommands.PersistentFlags().StringVarP(&K8sAPIServer, "api-server", "s", "", "Kubernetes API server URL (used with --token)")
	K8sCommands.PersistentFlags().StringVarP(&K8sClusterName, "cluster-name", "n", "", "Kubernetes Cluster Name (overrides default cluster name)")

	//K8sCommands.PersistentFlags().StringVarP(&K8sOutputFormat, "output", "o", "all", "[\"table\" | \"csv\" | \"all\"]")
	K8sCommands.PersistentFlags().StringVar(&K8sOutputDirectory, "outdir", defaultOutputDir, "Output Directory ")
	K8sCommands.PersistentFlags().IntVarP(&Verbosity, "verbosity", "v", 2, "1 = Print control messages only\n2 = Print control messages, module output\n3 = Print control messages, module output, and loot file output\n")
	K8sCommands.PersistentFlags().BoolVarP(&K8sWrapTable, "wrap", "w", false, "Wrap table to fit in terminal (complicates grepping)")
	//	K8sCommands.PersistentFlags().BoolVarP(&K8sMergedTable, "merged-table", "m", false, "Write one table for all namespaces (default: per namespace)")

	// Add subcommands
	K8sCommands.AddCommand(
		commands.ConfigMapsCmd,
		commands.CronJobsCmd,
		commands.DaemonSetsCmd,
		commands.DeploymentsCmd,
		commands.EndpointsCmd,
		commands.HiddenAdminsCmd,
		commands.JobsCmd,
		commands.NamespacesCmd,
		commands.NetworkPoliciesCmd,
		commands.NetworkExposureCmd,
		commands.NodesCmd,
		commands.PermissionsCmd,
		commands.PodSecurityCmd,
		commands.PodsCmd,
		commands.ReplicaSetsCmd,
		commands.SecretsCmd,
		commands.ServicesCmd,
		commands.StatefulSetsCmd,
		commands.TaintsTolerationsCmd,
		commands.TaintsCmd,
		commands.TolerationsCmd,
		commands.WebhooksCmd,
		commands.WhoamiCmd,
		K8sAllChecksCommand,
	)
}
