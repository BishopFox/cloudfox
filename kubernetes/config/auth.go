package config

import (
	"fmt"
	"os"

	"github.com/BishopFox/cloudfox/globals"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// GetRESTConfig returns a rest.Config object for authentication.
// Priority:
// 1. Service Account Token + API Server URL (if token provided, API optional but must be inferable)
// 2. Kubeconfig path + optional context (already resolved globally)
// 3. In-cluster config
func GetRESTConfig() (*rest.Config, error) {

	// --- 1. Service Account token auth (API server optional) ---
	if globals.KubeToken != "" {
		apiServerURL := globals.KubeAPIServer

		// Try to infer API server if not set
		if apiServerURL == "" && globals.KubeConfigPath != "" {
			if _, err := os.Stat(globals.KubeConfigPath); err == nil {
				config, err := clientcmd.BuildConfigFromFlags("", globals.KubeConfigPath)
				if err == nil && config.Host != "" {
					apiServerURL = config.Host
				}
			}
		}

		if apiServerURL == "" {
			return nil, fmt.Errorf("API server URL must be provided or inferable from kubeconfig")
		}

		return &rest.Config{
			Host:        apiServerURL,
			BearerToken: globals.KubeToken,
			TLSClientConfig: rest.TLSClientConfig{
				Insecure: true, // TODO: make configurable
			},
		}, nil
	}

	// --- 2. Kubeconfig path (already resolved in InitConfig) ---
	if globals.KubeConfigPath != "" {
		if _, err := os.Stat(globals.KubeConfigPath); err == nil {
			loadingRules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: globals.KubeConfigPath}
			configOverrides := &clientcmd.ConfigOverrides{}
			if globals.KubeContext != "" {
				configOverrides.CurrentContext = globals.KubeContext
			}
			return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides).ClientConfig()
		}
	}

	// --- 3. In-cluster fallback ---
	return rest.InClusterConfig()
}

// GetKubeClient returns a clientset from an auth config
func GetKubeClient() (*kubernetes.Clientset, error) {
	config, err := GetRESTConfig()
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(config)
}
