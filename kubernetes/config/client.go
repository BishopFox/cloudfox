package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	SharedClientSet  *kubernetes.Clientset
	DynamicClientSet dynamic.Interface

	KubeConfigPath string
	KubeContext    string
	KubeToken      string
	KubeAPIServer  string
)

func InitConfig(kubeconfigPath, kubeContext, kubeToken, kubeAPIServer string) {
	logger := internal.NewLogger()

	// Resolve kubeconfig
	if kubeconfigPath == "" {
		if env := os.Getenv("KUBECONFIG"); env != "" {
			kubeconfigPath = env
		} else if globals.KubeConfigPath != "" {
			kubeconfigPath = globals.KubeConfigPath
		} else if home, err := os.UserHomeDir(); err == nil {
			kubeconfigPath = filepath.Join(home, ".kube", "config")
		}
	}

	// Resolve other kube parameters
	if kubeContext == "" {
		kubeContext = globals.KubeContext
	}
	if kubeToken == "" {
		kubeToken = globals.KubeToken
	}
	if kubeAPIServer == "" {
		kubeAPIServer = globals.KubeAPIServer
	}

	globals.KubeConfigPath = kubeconfigPath
	globals.KubeContext = kubeContext
	globals.KubeToken = kubeToken
	globals.KubeAPIServer = kubeAPIServer

	// Read raw kubeconfig
	if kubeconfigPath != "" {
		if data, err := os.ReadFile(kubeconfigPath); err == nil {
			globals.RawKubeconfig = data
		} else {
			logger.ErrorM("failed to read kubeconfig: "+err.Error(), globals.K8S_AUTH_MODULE_NAME)
		}
	}

	// Build rest.Config
	var cfg *rest.Config
	var err error
	if len(globals.RawKubeconfig) > 0 {
		cfg, err = clientcmd.RESTConfigFromKubeConfig(globals.RawKubeconfig)
		if err != nil {
			logger.ErrorM(fmt.Sprintf("Error building REST config: %v", err), globals.K8S_AUTH_MODULE_NAME)
			os.Exit(1)
		}
	} else {
		cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfigPath)
		if err != nil {
			logger.ErrorM(fmt.Sprintf("Error building REST config: %v", err), globals.K8S_AUTH_MODULE_NAME)
			os.Exit(1)
		}
	}

	// Suppress Kubernetes API deprecation warnings
	// We intentionally use some deprecated APIs (e.g., v1 Endpoints) for broader compatibility
	// Set to NoWarnings to keep output clean; these are expected deprecations we're aware of
	cfg.WarningHandler = rest.NoWarnings{}

	// Standard Kubernetes client
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error creating kubernetes client: %v", err), globals.K8S_AUTH_MODULE_NAME)
		os.Exit(1)
	}
	SharedClientSet = clientset

	// Dynamic client for CRDs / Gatekeeper / Kyverno / OPA
	dynClient, err := dynamic.NewForConfig(cfg)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error creating dynamic client: %v", err), globals.K8S_AUTH_MODULE_NAME)
		os.Exit(1)
	}
	DynamicClientSet = dynClient
}

// Get standard client
func GetClientOrExit() *kubernetes.Clientset {
	logger := internal.NewLogger()
	if SharedClientSet == nil {
		logger.ErrorM("SharedClientSet not initialized. Call InitConfig first.", globals.K8S_AUTH_MODULE_NAME)
		os.Exit(1)
	}
	return SharedClientSet
}

// Get dynamic client
func GetDynamicClientOrExit() dynamic.Interface {
	logger := internal.NewLogger()
	if DynamicClientSet == nil {
		logger.ErrorM("DynamicClientSet not initialized. Call InitConfig first.", globals.K8S_AUTH_MODULE_NAME)
		os.Exit(1)
	}
	return DynamicClientSet
}
