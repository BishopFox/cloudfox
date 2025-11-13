package commands

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	k8sinternal "github.com/BishopFox/cloudfox/internal/kubernetes"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var SecretsCmd = &cobra.Command{
	Use:     "secrets",
	Aliases: []string{},
	Short:   "List all cluster secrets",
	Long: `
List all cluster secrets:
  cloudfox kubernetes secrets`,
	Run: ListSecrets,
}

type SecretsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t SecretsOutput) TableFiles() []internal.TableFile {
	return t.Table
}

func (t SecretsOutput) LootFiles() []internal.LootFile {
	return t.Loot
}

func ListSecrets(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	logger := internal.NewLogger()

	// Extract global flags
	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	clientset := config.GetClientOrExit()
	if clientset == nil {
		logger.ErrorM("Error getting Kubernetes client:", globals.K8S_SECRETS_MODULE_NAME)
		os.Exit(1)
	}

	namespaces, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing namespaces: %v", err), globals.K8S_SECRETS_MODULE_NAME)
		return
	}

	headers := []string{"Namespace", "Name", "Type", "Age"}
	var outputRows [][]string

	// Namespace-organized loot
	namespaceLootEnum := map[string][]string{}

	for _, ns := range namespaces.Items {
		secrets, err := clientset.CoreV1().Secrets(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			logger.ErrorM(fmt.Sprintf("Error listing secrets in namespace: %v", err), globals.K8S_SECRETS_MODULE_NAME)
			continue
		}

		for _, secret := range secrets.Items {
			age := time.Since(secret.CreationTimestamp.Time).Round(time.Second)

			outputRows = append(outputRows, []string{
				ns.Name,
				secret.Name,
				string(secret.Type),
				age.String(),
			})

			// Add per-namespace loot commands
			namespaceLootEnum[ns.Name] = append(namespaceLootEnum[ns.Name],
				fmt.Sprintf("kubectl get secret %s -n %s -o yaml", secret.Name, secret.Namespace),
				fmt.Sprintf("kubectl get secret %s -n %s -o json", secret.Name, secret.Namespace),
				fmt.Sprintf(`kubectl get secret %s -n %s -o json | jq -r '.data | to_entries[] | "\(.key)=\(.value | @base64d)"'`, secret.Name, secret.Namespace),
			)
		}
	}

	// Build lootEnum with namespace headers
	var lootEnum []string
	lootEnum = append(lootEnum, `#####################################
##### Enumerate Secrets
#####################################

`)
	if globals.KubeContext != "" {
		lootEnum = append(lootEnum, fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext))
	}

	nsListEnum := make([]string, 0, len(namespaceLootEnum))
	for ns := range namespaceLootEnum {
		nsListEnum = append(nsListEnum, ns)
	}
	sort.Strings(nsListEnum)
	for i, ns := range nsListEnum {
		lootEnum = append(lootEnum, fmt.Sprintf("\n# Namespace: %s\n", ns))
		lootEnum = append(lootEnum, namespaceLootEnum[ns]...)
		if i < len(nsListEnum)-1 {
			lootEnum = append(lootEnum, "")
		}
	}

	table := internal.TableFile{
		Name:   "Secrets",
		Header: headers,
		Body:   outputRows,
	}

	loot := internal.LootFile{
		Name:     "Secrets-Enum",
		Contents: strings.Join(k8sinternal.Unique(lootEnum), "\n"),
	}

	if err := internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"Secrets",
		globals.ClusterName,
		"results",
		SecretsOutput{
			Table: []internal.TableFile{table},
			Loot:  []internal.LootFile{loot},
		},
	); err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_SECRETS_MODULE_NAME)
	}
}
