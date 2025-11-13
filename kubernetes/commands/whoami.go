package commands

import (
	"context"
	"fmt"
	"io"
	"os"
	"regexp"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/spf13/cobra"
	v1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

var WhoamiCmd = &cobra.Command{
	Use:     "whoami",
	Aliases: []string{},
	Short:   "Display current cluster identity",
	Long: `
Display the identity your kubeconfig or in-cluster credentials are authenticated as:
  cloudfox kubernetes whoami`,
	Run: Whoami,
}

type WhoamiOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (w WhoamiOutput) TableFiles() []internal.TableFile {
	return w.Table
}

func (w WhoamiOutput) LootFiles() []internal.LootFile {
	return w.Loot
}

// helper: replaces empty string with "unknown"
func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// TryExtractUserFromKubeconfig attempts to parse kubeconfig and return the user for the current context
func TryExtractUserFromKubeconfig() string {
	logger := internal.NewLogger()

	if globals.KubeConfigPath == "" {
		logger.ErrorM("No kubeconfig path available", globals.K8S_WHOAMI_MODULE_NAME)
		return ""
	}

	// Use clientcmd.LoadFromFile to handle both map and list-style kubeconfigs
	kubeconfig, err := clientcmd.LoadFromFile(globals.KubeConfigPath)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to parse kubeconfig: %v", err), globals.K8S_WHOAMI_MODULE_NAME)
		return ""
	}

	// Determine which context to use
	contextName := globals.KubeContext
	if contextName == "" {
		contextName = kubeconfig.CurrentContext
	}
	if contextName == "" {
		logger.ErrorM("No context specified in kubeconfig", globals.K8S_WHOAMI_MODULE_NAME)
		return ""
	}

	ctx, ok := kubeconfig.Contexts[contextName]
	if !ok {
		logger.ErrorM(fmt.Sprintf("Context %q not found in kubeconfig", contextName), globals.K8S_WHOAMI_MODULE_NAME)
		return ""
	}

	userName := ctx.AuthInfo
	if userName == "" {
		logger.ErrorM(fmt.Sprintf("No user bound to context %q", contextName), globals.K8S_WHOAMI_MODULE_NAME)
		return ""
	}

	if _, ok := kubeconfig.AuthInfos[userName]; ok {
		return userName
	}

	logger.ErrorM(fmt.Sprintf("User %q not found in kubeconfig", userName), globals.K8S_WHOAMI_MODULE_NAME)
	return ""
}

// TryUserDetection attempts API calls until an error exposes the username.
func TryUserDetection(clientset *kubernetes.Clientset) string {
	ctx := context.Background()

	resources := []struct {
		group    string
		version  string
		resource string
	}{
		{"", "v1", "secrets"},
		{"batch", "v1", "cronjobs"},
		{"apps", "v1", "daemonsets"},
		{"", "v1", "configmaps"},
		{"apps", "v1", "deployments"},
		{"", "v1", "endpoints"},
		{"apps", "v1", "replicasets"},
		{"", "v1", "services"},
		{"apps", "v1", "statefulsets"},
		{"batch", "v1", "jobs"},
	}

	verbs := []string{"get", "list", "watch"}

	for _, r := range resources {
		gvr := schema.GroupVersionResource{
			Group:    r.group,
			Version:  r.version,
			Resource: r.resource,
		}

		for _, verb := range verbs {
			var err error
			switch verb {
			case "get":
				_, err = clientset.RESTClient().
					Get().
					AbsPath("/apis", gvr.Group, gvr.Version, gvr.Resource, "nonexistent").
					DoRaw(ctx)
			case "list":
				_, err = clientset.RESTClient().
					Get().
					AbsPath("/apis", gvr.Group, gvr.Version, gvr.Resource).
					DoRaw(ctx)
			case "watch":
				req := clientset.RESTClient().
					Get().
					AbsPath("/apis", gvr.Group, gvr.Version, gvr.Resource).
					Param("watch", "true")
				var resp io.ReadCloser
				resp, err = req.Stream(ctx)
				if resp != nil {
					resp.Close()
				}
			}

			if err != nil {
				if u := parseUsernameFromError(err); u != "" {
					// silently return the username without logging
					return u
				}
			}
		}
	}

	// If nothing is found, return empty string
	return ""
}

// Extracts the username string from a forbidden error message
func parseUsernameFromError(err error) string {
	if err == nil {
		return ""
	}
	re := regexp.MustCompile(`User\s+"([^"]+)"`)
	match := re.FindStringSubmatch(err.Error())
	if len(match) > 1 {
		return match[1]
	}
	return ""
}

func Whoami(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()

	// Set output params leveraging parent (k8s) pflag values
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Identifying current cluster identity for %s", globals.ClusterName), globals.K8S_WHOAMI_MODULE_NAME)

	clientset := config.GetClientOrExit()

	ssar := &v1.SelfSubjectAccessReview{
		Spec: v1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &v1.ResourceAttributes{
				Verb:     "get",
				Resource: "pods",
			},
		},
	}

	result, err := clientset.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, ssar, metav1.CreateOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error sending SelfSubjectAccessReview: %v", err), globals.K8S_WHOAMI_MODULE_NAME)
	}

	extractedUsername := TryUserDetection(clientset)

	clusterURL := clientset.RESTClient().Get().URL().String()
	reason := result.Status.Reason

	var clusterRoleBinding, clusterRole, group, user string

	reClusterRoleBinding := regexp.MustCompile(`ClusterRoleBinding "([^"]+)"`)
	reClusterRole := regexp.MustCompile(`ClusterRole "([^"]+)"`)
	reGroup := regexp.MustCompile(`Group "([^"]+)"`)
	reUser := regexp.MustCompile(`User "([^"]+)"`)

	if match := reClusterRoleBinding.FindStringSubmatch(reason); len(match) > 1 {
		clusterRoleBinding = match[1]
	}
	if match := reClusterRole.FindStringSubmatch(reason); len(match) > 1 {
		clusterRole = match[1]
	}
	if match := reGroup.FindStringSubmatch(reason); len(match) > 1 {
		group = match[1]
	}
	if match := reUser.FindStringSubmatch(reason); len(match) > 1 {
		user = match[1]
	}

	kubeconfigUser := TryExtractUserFromKubeconfig()
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Could not extract user from kubeconfig: %v\n", err), globals.K8S_WHOAMI_MODULE_NAME)
	}

	headers := []string{"Cluster URL", "Identity from KubeConfig", "Identity from Error", "Identity from SSAR", "Cluster Role Binding (SSAR)", "Cluster Role (SSAR)", "Group (SSAR)"}
	rows := [][]string{{
		orUnknown(clusterURL),
		orUnknown(kubeconfigUser),
		orUnknown(extractedUsername),
		orUnknown(user),
		orUnknown(clusterRoleBinding),
		orUnknown(clusterRole),
		orUnknown(group),
	}}

	table := internal.TableFile{
		Name:   "Whoami",
		Header: headers,
		Body:   rows,
	}

	err = internal.HandleOutput(
		"Kubernetes",        // cloudProvider
		format,              // output format (e.g., table, json)
		outputDirectory,     // --outdir
		verbosity,           // --verbosity
		wrap,                // --wrap
		"Whoami",            // base module name
		globals.ClusterName, // cluster name
		"results",           // subdirectory
		WhoamiOutput{
			Table: []internal.TableFile{table},
			Loot:  []internal.LootFile{}, // Add loot later if needed
		},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_WHOAMI_MODULE_NAME)
		return
	}

	logger.InfoM("Identity information collected", globals.K8S_WHOAMI_MODULE_NAME)
	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_WHOAMI_MODULE_NAME), globals.K8S_WHOAMI_MODULE_NAME)
}
