package shared

import (
	"context"
	"strings"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// GetTargetNamespaces returns the list of namespaces to enumerate based on global flags.
// If specific namespaces are configured, those are returned.
// Otherwise, it fetches all namespaces from the cluster.
// This function should be called by modules that need to iterate over namespaces.
func GetTargetNamespaces(ctx context.Context, clientset *kubernetes.Clientset, logger *internal.Logger, moduleName string) []string {
	// If namespaces were pre-configured via flags, use those
	if len(globals.K8sNamespaces) > 0 {
		return globals.K8sNamespaces
	}

	// Otherwise, fetch all namespaces
	namespaces, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM("Failed to list namespaces: "+err.Error(), moduleName)
		return []string{}
	}

	var result []string
	for _, ns := range namespaces.Items {
		result = append(result, ns.Name)
	}

	return result
}

// ShouldIncludeNamespace checks if a given namespace should be included
// based on the configured namespace filters.
func ShouldIncludeNamespace(namespace string) bool {
	// If no specific namespaces configured, include all
	if len(globals.K8sNamespaces) == 0 || globals.K8sAllNamespaces {
		return true
	}

	// Check if namespace is in the target list
	for _, ns := range globals.K8sNamespaces {
		if ns == namespace {
			return true
		}
	}

	return false
}

// FilterByNamespace filters a slice of items based on namespace.
// The getNamespace function extracts the namespace from each item.
func FilterByNamespace[T any](items []T, getNamespace func(T) string) []T {
	// If all namespaces are targeted, return everything
	if len(globals.K8sNamespaces) == 0 || globals.K8sAllNamespaces {
		return items
	}

	// Build a set of target namespaces for O(1) lookup
	targetNS := make(map[string]bool)
	for _, ns := range globals.K8sNamespaces {
		targetNS[ns] = true
	}

	var filtered []T
	for _, item := range items {
		if targetNS[getNamespace(item)] {
			filtered = append(filtered, item)
		}
	}

	return filtered
}

// GetNamespaceOrAll returns the namespace to query, or empty string for all namespaces.
// This is useful for API calls that support namespace-specific or cluster-wide queries.
func GetNamespaceOrAll() string {
	// If a single namespace is specified, return it
	if globals.K8sNamespace != "" {
		return globals.K8sNamespace
	}

	// If a list is specified but with only one namespace, return it
	if len(globals.K8sNamespaces) == 1 {
		return globals.K8sNamespaces[0]
	}

	// Otherwise, return empty string to query all namespaces
	return metav1.NamespaceAll
}

// ShouldCheckAdmissionController checks if a specific admission controller should be checked
// based on the --admission-controllers flag. Returns true if:
//   - No filter is specified (empty list means check all)
//   - The controller name matches one in the filter list (case-insensitive)
//   - Any of the provided aliases match the filter list
//
// Example usage:
//
//	if !shared.ShouldCheckAdmissionController("falco", "falco-security") {
//	    return // Skip this controller check
//	}
func ShouldCheckAdmissionController(controllerName string, aliases ...string) bool {
	// If no filter is specified, check all controllers
	if len(globals.K8sAdmissionControllers) == 0 {
		return true
	}

	// Normalize controller name for comparison
	controllerLower := strings.ToLower(controllerName)

	// Check if controller or any alias matches the filter
	for _, filter := range globals.K8sAdmissionControllers {
		filterLower := strings.ToLower(filter)

		// Check main controller name
		if controllerLower == filterLower || strings.Contains(controllerLower, filterLower) {
			return true
		}

		// Check aliases
		for _, alias := range aliases {
			aliasLower := strings.ToLower(alias)
			if aliasLower == filterLower || strings.Contains(aliasLower, filterLower) {
				return true
			}
		}
	}

	return false
}

// GetAdmissionControllersFilter returns the configured admission controllers filter.
// Returns nil if no filter is set (meaning check all).
func GetAdmissionControllersFilter() []string {
	return globals.K8sAdmissionControllers
}

// IsAdmissionControllersFiltered returns true if admission controller filtering is enabled.
func IsAdmissionControllersFiltered() bool {
	return len(globals.K8sAdmissionControllers) > 0
}
