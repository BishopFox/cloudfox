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

	logger.InfoM(fmt.Sprintf("Enumerating secrets for %s", globals.ClusterName), globals.K8S_SECRETS_MODULE_NAME)

	clientset := config.GetClientOrExit()

	namespaces, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing namespaces: %v", err), globals.K8S_SECRETS_MODULE_NAME)
		return
	}

	headers := []string{"Namespace", "Name", "Type", "Data Keys", "Age"}
	var outputRows [][]string

	// Namespace-organized loot
	namespaceLootEnum := map[string][]string{}
	var lootDecode []string
	var lootPatterns []string
	var lootCloudCreds []string
	var sensitiveSecrets []string

	lootDecode = append(lootDecode, `#####################################
##### Decode Secret Values
#####################################
#
# Extract and decode all secret values
# WARNING: Contains sensitive data
#
`)

	lootPatterns = append(lootPatterns, `#####################################
##### Secret Pattern Analysis
#####################################
#
# Analyze secrets for sensitive patterns
# Potential credentials, keys, and tokens
#
`)

	lootCloudCreds = append(lootCloudCreds, `#####################################
##### Cloud Credential Usage
#####################################
#
# MANUAL EXECUTION REQUIRED
# Use extracted cloud credentials
#
`)

	for _, ns := range namespaces.Items {
		secrets, err := clientset.CoreV1().Secrets(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			logger.ErrorM(fmt.Sprintf("Error listing secrets in namespace: %v", err), globals.K8S_SECRETS_MODULE_NAME)
			continue
		}

		for _, secret := range secrets.Items {
			age := time.Since(secret.CreationTimestamp.Time).Round(time.Second)

			// Get data keys
			var dataKeys []string
			for key := range secret.Data {
				dataKeys = append(dataKeys, key)
			}
			sort.Strings(dataKeys)

			outputRows = append(outputRows, []string{
				ns.Name,
				secret.Name,
				string(secret.Type),
				strings.Join(dataKeys, ", "),
				age.String(),
			})

			// Add per-namespace loot commands
			namespaceLootEnum[ns.Name] = append(namespaceLootEnum[ns.Name],
				fmt.Sprintf("kubectl get secret %s -n %s -o yaml", secret.Name, secret.Namespace),
				fmt.Sprintf("kubectl get secret %s -n %s -o json", secret.Name, secret.Namespace),
				fmt.Sprintf(`kubectl get secret %s -n %s -o json | jq -r '.data | to_entries[] | "\(.key)=\(.value | @base64d)"'`, secret.Name, secret.Namespace),
			)

			// Decode commands
			lootDecode = append(lootDecode, fmt.Sprintf("\n# Secret: %s/%s (Type: %s)", ns.Name, secret.Name, secret.Type))
			for _, key := range dataKeys {
				lootDecode = append(lootDecode, fmt.Sprintf("kubectl get secret %s -n %s -o jsonpath='{.data.%s}' | base64 -d", secret.Name, ns.Name, key))
				lootDecode = append(lootDecode, fmt.Sprintf("# Save to file: kubectl get secret %s -n %s -o jsonpath='{.data.%s}' | base64 -d > %s-%s.txt", secret.Name, ns.Name, key, secret.Name, key))
			}
			lootDecode = append(lootDecode, "")

			// Pattern analysis and cloud credential detection
			secretType := string(secret.Type)
			isSensitive := false

			// Detect Docker registry credentials
			if secretType == "kubernetes.io/dockerconfigjson" {
				isSensitive = true
				lootPatterns = append(lootPatterns, fmt.Sprintf("\n# DOCKER REGISTRY CREDENTIALS: %s/%s", ns.Name, secret.Name))
				lootPatterns = append(lootPatterns, fmt.Sprintf("kubectl get secret %s -n %s -o jsonpath='{.data.\\.dockerconfigjson}' | base64 -d | jq .", secret.Name, ns.Name))
				lootPatterns = append(lootPatterns, fmt.Sprintf("# Extract registry URL and credentials"))
				lootPatterns = append(lootPatterns, "")

				// Add docker login commands
				lootCloudCreds = append(lootCloudCreds, fmt.Sprintf("\n# Docker Registry: %s/%s", ns.Name, secret.Name))
				lootCloudCreds = append(lootCloudCreds, fmt.Sprintf("# Extract and parse credentials:"))
				lootCloudCreds = append(lootCloudCreds, fmt.Sprintf("kubectl get secret %s -n %s -o jsonpath='{.data.\\.dockerconfigjson}' | base64 -d > docker-config.json", secret.Name, ns.Name))
				lootCloudCreds = append(lootCloudCreds, fmt.Sprintf("# Use credentials: docker login -u <username> -p <password> <registry>"))
				lootCloudCreds = append(lootCloudCreds, "")
			}

			// Detect TLS certificates
			if secretType == "kubernetes.io/tls" {
				isSensitive = true
				lootPatterns = append(lootPatterns, fmt.Sprintf("\n# TLS CERTIFICATE: %s/%s", ns.Name, secret.Name))
				lootPatterns = append(lootPatterns, fmt.Sprintf("kubectl get secret %s -n %s -o jsonpath='{.data.tls\\.crt}' | base64 -d | openssl x509 -text -noout", secret.Name, ns.Name))
				lootPatterns = append(lootPatterns, fmt.Sprintf("kubectl get secret %s -n %s -o jsonpath='{.data.tls\\.crt}' | base64 -d | openssl x509 -noout -subject -issuer -dates", secret.Name, ns.Name))
				lootPatterns = append(lootPatterns, fmt.Sprintf("# Extract private key: kubectl get secret %s -n %s -o jsonpath='{.data.tls\\.key}' | base64 -d", secret.Name, ns.Name))
				lootPatterns = append(lootPatterns, "")
			}

			// Detect SSH keys
			for _, key := range dataKeys {
				keyLower := strings.ToLower(key)
				if strings.Contains(keyLower, "ssh") || strings.Contains(keyLower, "id_rsa") || strings.Contains(keyLower, "id_ed25519") {
					isSensitive = true
					lootPatterns = append(lootPatterns, fmt.Sprintf("\n# SSH KEY DETECTED: %s/%s (key: %s)", ns.Name, secret.Name, key))
					lootPatterns = append(lootPatterns, fmt.Sprintf("kubectl get secret %s -n %s -o jsonpath='{.data.%s}' | base64 -d", secret.Name, ns.Name, key))
					lootPatterns = append(lootPatterns, fmt.Sprintf("# Save key: kubectl get secret %s -n %s -o jsonpath='{.data.%s}' | base64 -d > ssh_key && chmod 600 ssh_key", secret.Name, ns.Name, key))
					lootPatterns = append(lootPatterns, "")
				}

				// Detect AWS credentials
				if keyLower == "aws_access_key_id" || keyLower == "aws_secret_access_key" || strings.Contains(keyLower, "aws") {
					isSensitive = true
					lootPatterns = append(lootPatterns, fmt.Sprintf("\n# AWS CREDENTIALS DETECTED: %s/%s", ns.Name, secret.Name))
					lootPatterns = append(lootPatterns, fmt.Sprintf("kubectl get secret %s -n %s -o json | jq -r '.data | to_entries[] | \"\\(.key)=\\(.value | @base64d)\"'", secret.Name, ns.Name))
					lootPatterns = append(lootPatterns, "")

					lootCloudCreds = append(lootCloudCreds, fmt.Sprintf("\n# AWS Credentials: %s/%s", ns.Name, secret.Name))
					lootCloudCreds = append(lootCloudCreds, fmt.Sprintf("# Extract and configure:"))
					lootCloudCreds = append(lootCloudCreds, fmt.Sprintf("export AWS_ACCESS_KEY_ID=$(kubectl get secret %s -n %s -o jsonpath='{.data.aws_access_key_id}' | base64 -d)", secret.Name, ns.Name))
					lootCloudCreds = append(lootCloudCreds, fmt.Sprintf("export AWS_SECRET_ACCESS_KEY=$(kubectl get secret %s -n %s -o jsonpath='{.data.aws_secret_access_key}' | base64 -d)", secret.Name, ns.Name))
					lootCloudCreds = append(lootCloudCreds, "# Test credentials:")
					lootCloudCreds = append(lootCloudCreds, "aws sts get-caller-identity")
					lootCloudCreds = append(lootCloudCreds, "aws iam list-users")
					lootCloudCreds = append(lootCloudCreds, "")
				}

				// Detect GCP credentials
				if keyLower == "credentials.json" || keyLower == "key.json" || strings.Contains(keyLower, "gcp") || strings.Contains(keyLower, "google") {
					isSensitive = true
					lootPatterns = append(lootPatterns, fmt.Sprintf("\n# GCP CREDENTIALS DETECTED: %s/%s (key: %s)", ns.Name, secret.Name, key))
					lootPatterns = append(lootPatterns, fmt.Sprintf("kubectl get secret %s -n %s -o jsonpath='{.data.%s}' | base64 -d | jq .", secret.Name, ns.Name, key))
					lootPatterns = append(lootPatterns, "")

					lootCloudCreds = append(lootCloudCreds, fmt.Sprintf("\n# GCP Credentials: %s/%s", ns.Name, secret.Name))
					lootCloudCreds = append(lootCloudCreds, fmt.Sprintf("kubectl get secret %s -n %s -o jsonpath='{.data.%s}' | base64 -d > gcp-key.json", secret.Name, ns.Name, key))
					lootCloudCreds = append(lootCloudCreds, "gcloud auth activate-service-account --key-file=gcp-key.json")
					lootCloudCreds = append(lootCloudCreds, "gcloud projects list")
					lootCloudCreds = append(lootCloudCreds, "")
				}

				// Detect Azure credentials
				if strings.Contains(keyLower, "azure") || keyLower == "client_secret" || keyLower == "tenant_id" {
					isSensitive = true
					lootPatterns = append(lootPatterns, fmt.Sprintf("\n# AZURE CREDENTIALS DETECTED: %s/%s", ns.Name, secret.Name))
					lootPatterns = append(lootPatterns, fmt.Sprintf("kubectl get secret %s -n %s -o json | jq -r '.data | to_entries[] | \"\\(.key)=\\(.value | @base64d)\"'", secret.Name, ns.Name))
					lootPatterns = append(lootPatterns, "")

					lootCloudCreds = append(lootCloudCreds, fmt.Sprintf("\n# Azure Credentials: %s/%s", ns.Name, secret.Name))
					lootCloudCreds = append(lootCloudCreds, "# Extract credentials and login:")
					lootCloudCreds = append(lootCloudCreds, fmt.Sprintf("# az login --service-principal -u <client-id> -p <client-secret> --tenant <tenant-id>"))
					lootCloudCreds = append(lootCloudCreds, "")
				}

				// Detect passwords, tokens, API keys
				if strings.Contains(keyLower, "password") || strings.Contains(keyLower, "passwd") || strings.Contains(keyLower, "token") || strings.Contains(keyLower, "api_key") || strings.Contains(keyLower, "apikey") {
					isSensitive = true
					lootPatterns = append(lootPatterns, fmt.Sprintf("\n# CREDENTIAL DETECTED: %s/%s (key: %s)", ns.Name, secret.Name, key))
					lootPatterns = append(lootPatterns, fmt.Sprintf("kubectl get secret %s -n %s -o jsonpath='{.data.%s}' | base64 -d", secret.Name, ns.Name, key))
					lootPatterns = append(lootPatterns, "")
				}

				// Detect database credentials
				if strings.Contains(keyLower, "database") || strings.Contains(keyLower, "db_") || keyLower == "username" || strings.Contains(keyLower, "connection_string") {
					isSensitive = true
					lootPatterns = append(lootPatterns, fmt.Sprintf("\n# DATABASE CREDENTIAL: %s/%s (key: %s)", ns.Name, secret.Name, key))
					lootPatterns = append(lootPatterns, fmt.Sprintf("kubectl get secret %s -n %s -o jsonpath='{.data.%s}' | base64 -d", secret.Name, ns.Name, key))
					lootPatterns = append(lootPatterns, "")
				}
			}

			if isSensitive {
				sensitiveSecrets = append(sensitiveSecrets, fmt.Sprintf("%s/%s (%s)", ns.Name, secret.Name, secretType))
			}
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

	// Add summary to patterns loot
	if len(sensitiveSecrets) > 0 {
		summary := fmt.Sprintf("\n# SUMMARY: Found %d secrets with sensitive patterns:\n", len(sensitiveSecrets))
		for _, s := range sensitiveSecrets {
			summary += fmt.Sprintf("# - %s\n", s)
		}
		lootPatterns = append([]string{summary}, lootPatterns...)
	}

	lootFiles := []internal.LootFile{
		{
			Name:     "Secrets-Enum",
			Contents: strings.Join(k8sinternal.Unique(lootEnum), "\n"),
		},
		{
			Name:     "Secrets-Decode",
			Contents: strings.Join(lootDecode, "\n"),
		},
		{
			Name:     "Secrets-Pattern-Analysis",
			Contents: strings.Join(lootPatterns, "\n"),
		},
		{
			Name:     "Secrets-Cloud-Credentials",
			Contents: strings.Join(lootCloudCreds, "\n"),
		},
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
			Loot:  lootFiles,
		},
	); err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_SECRETS_MODULE_NAME)
		return
	}

	if len(outputRows) > 0 {
		logger.InfoM(fmt.Sprintf("%d secrets found across %d namespaces", len(outputRows), len(namespaces.Items)), globals.K8S_SECRETS_MODULE_NAME)
	} else {
		logger.InfoM("No secrets found, skipping output file creation", globals.K8S_SECRETS_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_SECRETS_MODULE_NAME), globals.K8S_SECRETS_MODULE_NAME)
}
