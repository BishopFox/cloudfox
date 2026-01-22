package sdk

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/BishopFox/cloudfox/globals"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	clientsetOnce    sync.Once
	dynamicOnce      sync.Once
	restConfigOnce   sync.Once
	sharedClientset  *kubernetes.Clientset
	sharedDynamic    dynamic.Interface
	sharedRestConfig *rest.Config
	initErr          error
)

// ClientConfig holds the configuration for creating Kubernetes clients
type ClientConfig struct {
	KubeconfigPath string
	Context        string
	Token          string
	APIServer      string
}

// GetClientConfig returns the current client configuration from globals
func GetClientConfig() ClientConfig {
	return ClientConfig{
		KubeconfigPath: globals.KubeConfigPath,
		Context:        globals.KubeContext,
		Token:          globals.KubeToken,
		APIServer:      globals.KubeAPIServer,
	}
}

// ResolveKubeconfigPath resolves the kubeconfig path using standard precedence
func ResolveKubeconfigPath(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if env := os.Getenv("KUBECONFIG"); env != "" {
		return env
	}
	if globals.KubeConfigPath != "" {
		return globals.KubeConfigPath
	}
	if home, err := os.UserHomeDir(); err == nil {
		defaultPath := filepath.Join(home, ".kube", "config")
		if _, err := os.Stat(defaultPath); err == nil {
			return defaultPath
		}
	}
	return ""
}

// BuildRESTConfig creates a rest.Config from the provided configuration
func BuildRESTConfig(cfg ClientConfig) (*rest.Config, error) {
	// Option 1: Token-based auth (for in-cluster or explicit token)
	if cfg.Token != "" {
		apiServer := cfg.APIServer
		if apiServer == "" && cfg.KubeconfigPath != "" {
			// Try to get API server from kubeconfig
			if config, err := clientcmd.BuildConfigFromFlags("", cfg.KubeconfigPath); err == nil && config.Host != "" {
				apiServer = config.Host
			}
		}
		if apiServer == "" {
			return nil, fmt.Errorf("API server URL required when using token auth")
		}
		return &rest.Config{
			Host:        apiServer,
			BearerToken: cfg.Token,
			TLSClientConfig: rest.TLSClientConfig{
				Insecure: true, // TODO: Make configurable
			},
		}, nil
	}

	// Option 2: Kubeconfig-based auth
	if cfg.KubeconfigPath != "" {
		loadingRules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: cfg.KubeconfigPath}
		configOverrides := &clientcmd.ConfigOverrides{}
		if cfg.Context != "" {
			configOverrides.CurrentContext = cfg.Context
		}
		return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides).ClientConfig()
	}

	// Option 3: In-cluster config
	return rest.InClusterConfig()
}

// GetRESTConfig returns a cached REST config, creating it if necessary
func GetRESTConfig() (*rest.Config, error) {
	restConfigOnce.Do(func() {
		cfg := GetClientConfig()
		cfg.KubeconfigPath = ResolveKubeconfigPath(cfg.KubeconfigPath)
		sharedRestConfig, initErr = BuildRESTConfig(cfg)
	})
	return sharedRestConfig, initErr
}

// GetClientset returns a cached Kubernetes clientset
func GetClientset() (*kubernetes.Clientset, error) {
	clientsetOnce.Do(func() {
		restConfig, err := GetRESTConfig()
		if err != nil {
			initErr = fmt.Errorf("failed to get REST config: %w", err)
			return
		}
		sharedClientset, initErr = kubernetes.NewForConfig(restConfig)
	})
	return sharedClientset, initErr
}

// GetDynamicClient returns a cached dynamic client for CRDs
func GetDynamicClient() (dynamic.Interface, error) {
	dynamicOnce.Do(func() {
		restConfig, err := GetRESTConfig()
		if err != nil {
			initErr = fmt.Errorf("failed to get REST config: %w", err)
			return
		}
		sharedDynamic, initErr = dynamic.NewForConfig(restConfig)
	})
	return sharedDynamic, initErr
}

// NewClientset creates a new clientset from the provided config (not cached)
func NewClientset(cfg ClientConfig) (*kubernetes.Clientset, error) {
	restConfig, err := BuildRESTConfig(cfg)
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(restConfig)
}

// NewDynamicClient creates a new dynamic client from the provided config (not cached)
func NewDynamicClient(cfg ClientConfig) (dynamic.Interface, error) {
	restConfig, err := BuildRESTConfig(cfg)
	if err != nil {
		return nil, err
	}
	return dynamic.NewForConfig(restConfig)
}

// ResetClients clears the cached clients (useful for testing)
func ResetClients() {
	clientsetOnce = sync.Once{}
	dynamicOnce = sync.Once{}
	restConfigOnce = sync.Once{}
	sharedClientset = nil
	sharedDynamic = nil
	sharedRestConfig = nil
	initErr = nil
}

// SuppressStderr temporarily redirects stderr to /dev/null and returns a restore function.
// This is used to hide noisy output from auth plugins (gke-gcloud-auth-plugin, aws-iam-authenticator, etc.)
// that write directly to stderr (fd 2) before we can catch errors.
// Call the returned function to restore stderr when done.
func SuppressStderr() func() {
	// Save original stderr file descriptor
	origStderrFd, dupErr := syscall.Dup(syscall.Stderr)

	// Open /dev/null for writing
	devNull, nullErr := os.OpenFile(os.DevNull, os.O_WRONLY, 0)

	// Redirect stderr to /dev/null if we successfully opened it
	stderrSuppressed := false
	if dupErr == nil && nullErr == nil {
		if err := syscall.Dup2(int(devNull.Fd()), syscall.Stderr); err == nil {
			stderrSuppressed = true
		}
	}

	// Return restore function
	return func() {
		if stderrSuppressed {
			syscall.Dup2(origStderrFd, syscall.Stderr)
			syscall.Close(origStderrFd)
		}
		if devNull != nil {
			devNull.Close()
		}
	}
}

// ValidateAuth checks if the current authentication is valid by making a simple API call.
// Returns nil if auth is valid, or a user-friendly error message if not.
func ValidateAuth(ctx context.Context) error {
	// Suppress stderr during auth check to hide noisy plugin errors
	restoreStderr := SuppressStderr()
	defer restoreStderr()

	clientset, err := GetClientset()
	if err != nil {
		return formatAuthError(err)
	}

	// Use a short timeout for the validation check
	validationCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Try to get server version - this requires minimal permissions
	_, err = clientset.Discovery().ServerVersion()
	if err != nil {
		return formatAuthError(err)
	}

	// Also try to list namespaces to verify RBAC is working
	_, err = clientset.CoreV1().Namespaces().List(validationCtx, metav1.ListOptions{Limit: 1})
	if err != nil {
		// This might fail due to RBAC, but auth errors will be different
		if isAuthError(err) {
			return formatAuthError(err)
		}
		// RBAC errors are OK - user is authenticated but may have limited permissions
	}

	return nil
}

// isAuthError checks if an error is an authentication-related error
func isAuthError(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	authIndicators := []string{
		"unauthorized",
		"authentication",
		"token expired",
		"token has expired",
		"credentials",
		"login",
		"exec plugin",
		"gke-gcloud-auth-plugin",
		"aws-iam-authenticator",
		"kubelogin",
		"azure",
		"x509",
		"certificate",
		"tls",
		"connection refused",
		"no such host",
		"dial tcp",
		"oauth2",
		"refresh token",
	}
	for _, indicator := range authIndicators {
		if strings.Contains(errStr, indicator) {
			return true
		}
	}
	return false
}

// formatAuthError creates a user-friendly error message for authentication failures
func formatAuthError(err error) error {
	if err == nil {
		return nil
	}

	errStr := strings.ToLower(err.Error())

	// Detect cloud provider and suggest fix
	switch {
	case strings.Contains(errStr, "gke-gcloud-auth-plugin") || strings.Contains(errStr, "gcloud"):
		return fmt.Errorf(`GCP authentication failed. Your session may have expired.

To fix:
  1. Run: gcloud auth login
  2. Run: gcloud container clusters get-credentials <cluster-name> --region <region>

Original error: %w`, err)

	case strings.Contains(errStr, "aws-iam-authenticator") || strings.Contains(errStr, "eks"):
		return fmt.Errorf(`AWS authentication failed. Your session may have expired.

To fix:
  1. Run: aws sso login --profile <profile> (if using SSO)
  2. Or run: aws configure (if using access keys)
  3. Then: aws eks update-kubeconfig --name <cluster-name> --region <region>

Original error: %w`, err)

	case strings.Contains(errStr, "kubelogin") || strings.Contains(errStr, "azure") || strings.Contains(errStr, "aks"):
		return fmt.Errorf(`Azure authentication failed. Your session may have expired.

To fix:
  1. Run: az login
  2. Run: az aks get-credentials --resource-group <rg> --name <cluster-name>

Original error: %w`, err)

	case strings.Contains(errStr, "x509") || strings.Contains(errStr, "certificate"):
		return fmt.Errorf(`TLS/Certificate error. The cluster certificate may be invalid or expired.

To fix:
  1. Check if your kubeconfig has valid certificates
  2. Re-fetch cluster credentials from your cloud provider
  3. For self-signed certs, ensure CA is properly configured

Original error: %w`, err)

	case strings.Contains(errStr, "connection refused") || strings.Contains(errStr, "dial tcp") || strings.Contains(errStr, "no such host"):
		return fmt.Errorf(`Cannot connect to Kubernetes API server.

Possible causes:
  1. Cluster is not running or not accessible
  2. VPN/network connection required
  3. Incorrect API server URL in kubeconfig

Original error: %w`, err)

	case strings.Contains(errStr, "unauthorized") || strings.Contains(errStr, "token"):
		return fmt.Errorf(`Authentication token is invalid or expired.

To fix:
  1. Re-authenticate with your cloud provider (gcloud/aws/az)
  2. Refresh your kubeconfig credentials
  3. Check if your service account token is still valid

Original error: %w`, err)

	default:
		return fmt.Errorf(`Kubernetes authentication failed.

To fix:
  1. Verify your kubeconfig: kubectl config view
  2. Test connectivity: kubectl cluster-info
  3. Re-authenticate with your cloud provider if needed

Original error: %w`, err)
	}
}
