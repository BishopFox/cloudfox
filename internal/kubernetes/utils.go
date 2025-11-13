package kubernetes

import (
	"encoding/json"
	"fmt"
	"strings"

	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// FindMountPath locates the mount path for a given volume name in the provided containers.
func FindMountPath(volumeName string, containers []v1.Container) string {
	for _, c := range containers {
		for _, m := range c.VolumeMounts {
			if m.Name == volumeName {
				return m.MountPath
			}
		}
	}
	return "<NONE>"
}

// NonEmpty normalizes empty, dash, or whitespace-only strings to "<NONE>".
func NonEmpty(value string) string {
	if strings.TrimSpace(value) == "" || value == "-" {
		return "<NONE>"
	}
	return value
}

// SafeInt32Ptr safely dereferences an *int32, returning "<NONE>" if nil
func SafeInt32Ptr(p *int32) string {
	if p == nil {
		return "<NONE>"
	}
	return fmt.Sprintf("%d", *p)
}

// SafeBoolPtr safely dereferences a *bool, returning "<NONE>" if nil
func SafeBoolPtr(p *bool) string {
	if p == nil {
		return "<NONE>"
	}
	return fmt.Sprintf("%v", *p)
}

// SafeStringPtr safely dereferences a *string, returning "<NONE>" if nil
func SafeStringPtr(p *string) string {
	if p == nil {
		return "<NONE>"
	}
	return *p
}

func SafeBool(val bool) string {
	return fmt.Sprintf("%v", val)
}

func SafeInt32(val *int32) string {
	if val == nil {
		return "nil"
	}
	return fmt.Sprintf("%d", *val)
}

// MapToStringList converts a map[string]string to a []string of "key=value"
func MapToStringList(m map[string]string) []string {
	result := []string{}
	for k, v := range m {
		result = append(result, fmt.Sprintf("%s=%s", k, v))
	}
	return result
}

// SelectorMatch returns the label selector match labels as key=value strings
func SelectorMatch(sel *metav1.LabelSelector) []string {
	if sel == nil {
		return []string{}
	}
	return MapToStringList(sel.MatchLabels)
}

// Unique removes duplicate strings from a slice
func Unique(input []string) []string {
	seen := make(map[string]struct{})
	result := []string{}
	for _, val := range input {
		if _, ok := seen[val]; !ok {
			seen[val] = struct{}{}
			result = append(result, val)
		}
	}
	return result
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func IsDangerousRule(rule rbacv1.PolicyRule) bool {
	dangerousVerbs := []string{"create", "update", "patch"}
	dangerousResources := []string{"roles", "rolebindings", "clusterroles", "clusterrolebindings", "secrets", "configmaps"}
	impersonation := []string{"users", "groups", "serviceaccounts"}

	for _, verb := range rule.Verbs {
		for _, res := range rule.Resources {
			if contains(dangerousVerbs, verb) && contains(dangerousResources, res) {
				return true
			}
			if verb == "impersonate" && contains(impersonation, res) {
				return true
			}
		}
	}
	return false
}

func RuleToString(rule rbacv1.PolicyRule) string {
	return fmt.Sprintf("verbs=%v resources=%v apiGroups=%v", rule.Verbs, rule.Resources, rule.APIGroups)
}

func UniqueStrings(input []string) []string {
	seen := map[string]bool{}
	var result []string
	for _, item := range input {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}

// PrettyPrintAffinity converts Affinity object to a compact JSON string
func PrettyPrintAffinity(affinity *v1.Affinity) string {
	if affinity == nil {
		return "<NONE>"
	}
	b, err := json.MarshalIndent(affinity, "", "  ")
	if err != nil {
		return "<ERROR>"
	}
	return string(b)
}
