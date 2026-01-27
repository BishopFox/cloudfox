package sdk

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/patrickmn/go-cache"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	schedulingv1 "k8s.io/api/scheduling/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

var (
	// SharedCache is the centralized cache for Kubernetes data
	SharedCache = cache.New(2*time.Hour, 10*time.Minute)

	// cacheLogger for logging cache operations
	cacheLogger = internal.NewLogger()
)

// Cache key constants for K8s resources
const (
	CacheKeyPods                  = "k8s-pods"
	CacheKeyServices              = "k8s-services"
	CacheKeyNodes                 = "k8s-nodes"
	CacheKeyNamespaces            = "k8s-namespaces"
	CacheKeySecrets               = "k8s-secrets"
	CacheKeyConfigMaps            = "k8s-configmaps"
	CacheKeyServiceAccounts       = "k8s-serviceaccounts"
	CacheKeyEndpoints             = "k8s-endpoints"
	CacheKeyEvents                = "k8s-events"
	CacheKeyNetworkPolicies       = "k8s-networkpolicies"
	CacheKeyIngresses             = "k8s-ingresses"
	CacheKeyRoles                 = "k8s-roles"
	CacheKeyClusterRoles          = "k8s-clusterroles"
	CacheKeyRoleBindings          = "k8s-rolebindings"
	CacheKeyClusterRoleBindings   = "k8s-clusterrolebindings"
	CacheKeyDeployments           = "k8s-deployments"
	CacheKeyDaemonSets            = "k8s-daemonsets"
	CacheKeyStatefulSets          = "k8s-statefulsets"
	CacheKeyReplicaSets           = "k8s-replicasets"
	CacheKeyJobs                  = "k8s-jobs"
	CacheKeyCronJobs              = "k8s-cronjobs"
	CacheKeyValidatingWebhooks    = "k8s-validatingwebhooks"
	CacheKeyMutatingWebhooks      = "k8s-mutatingwebhooks"
	CacheKeyPersistentVolumes     = "k8s-persistentvolumes"
	CacheKeyPersistentVolumeClaims = "k8s-persistentvolumeclaims"
	CacheKeyStorageClasses        = "k8s-storageclasses"
	CacheKeyPriorityClasses       = "k8s-priorityclasses"
	CacheKeyResourceQuotas        = "k8s-resourcequotas"
	CacheKeyLimitRanges           = "k8s-limitranges"
	CacheKeyPodDisruptionBudgets  = "k8s-poddisruptionbudgets"
	CacheKeyHPAs                  = "k8s-hpas"
)

// CacheKey generates a standardized cache key
func CacheKey(prefix string, parts ...string) string {
	key := prefix
	for _, part := range parts {
		if part != "" {
			key += "-" + part
		}
	}
	return key
}

// Get retrieves an item from the cache
func Get(key string) (interface{}, bool) {
	return SharedCache.Get(key)
}

// Set stores an item in the cache with default expiration
func Set(key string, value interface{}) {
	SharedCache.Set(key, value, cache.DefaultExpiration)
}

// SetWithExpiration stores an item with a custom expiration
func SetWithExpiration(key string, value interface{}, expiration time.Duration) {
	SharedCache.Set(key, value, expiration)
}

// Delete removes an item from the cache
func Delete(key string) {
	SharedCache.Delete(key)
}

// Flush clears all items from the cache
func Flush() {
	SharedCache.Flush()
}

// GetOrSet retrieves from cache or calls the provider function and caches the result
func GetOrSet[T any](key string, provider func() (T, error)) (T, error) {
	if cached, found := Get(key); found {
		if value, ok := cached.(T); ok {
			return value, nil
		}
	}

	value, err := provider()
	if err != nil {
		var zero T
		return zero, err
	}

	Set(key, value)
	return value, nil
}

// ============================================================================
// CACHE WARMING
// ============================================================================

// WarmCache pre-fetches commonly used resources to speed up subsequent module runs.
// This should be called by all-checks before running modules.
func WarmCache(ctx context.Context, clientset *kubernetes.Clientset) error {
	cacheLogger.InfoM("Warming resource cache for faster enumeration...", "cache")

	var wg sync.WaitGroup
	errChan := make(chan error, 20)

	// Tier 1: Most frequently used (Pods, Nodes, Namespaces, Services)
	wg.Add(4)
	go func() {
		defer wg.Done()
		if _, err := GetPods(ctx, clientset); err != nil {
			errChan <- fmt.Errorf("pods: %w", err)
		}
	}()
	go func() {
		defer wg.Done()
		if _, err := GetNodes(ctx, clientset); err != nil {
			errChan <- fmt.Errorf("nodes: %w", err)
		}
	}()
	go func() {
		defer wg.Done()
		if _, err := GetNamespaces(ctx, clientset); err != nil {
			errChan <- fmt.Errorf("namespaces: %w", err)
		}
	}()
	go func() {
		defer wg.Done()
		if _, err := GetServices(ctx, clientset); err != nil {
			errChan <- fmt.Errorf("services: %w", err)
		}
	}()

	// Tier 2: RBAC and networking
	wg.Add(6)
	go func() {
		defer wg.Done()
		if _, err := GetRoles(ctx, clientset); err != nil {
			errChan <- fmt.Errorf("roles: %w", err)
		}
	}()
	go func() {
		defer wg.Done()
		if _, err := GetClusterRoles(ctx, clientset); err != nil {
			errChan <- fmt.Errorf("clusterroles: %w", err)
		}
	}()
	go func() {
		defer wg.Done()
		if _, err := GetRoleBindings(ctx, clientset); err != nil {
			errChan <- fmt.Errorf("rolebindings: %w", err)
		}
	}()
	go func() {
		defer wg.Done()
		if _, err := GetClusterRoleBindings(ctx, clientset); err != nil {
			errChan <- fmt.Errorf("clusterrolebindings: %w", err)
		}
	}()
	go func() {
		defer wg.Done()
		if _, err := GetNetworkPolicies(ctx, clientset); err != nil {
			errChan <- fmt.Errorf("networkpolicies: %w", err)
		}
	}()
	go func() {
		defer wg.Done()
		if _, err := GetIngresses(ctx, clientset); err != nil {
			errChan <- fmt.Errorf("ingresses: %w", err)
		}
	}()

	// Tier 3: Workloads and other resources
	wg.Add(10)
	go func() {
		defer wg.Done()
		if _, err := GetSecrets(ctx, clientset); err != nil {
			errChan <- fmt.Errorf("secrets: %w", err)
		}
	}()
	go func() {
		defer wg.Done()
		if _, err := GetServiceAccounts(ctx, clientset); err != nil {
			errChan <- fmt.Errorf("serviceaccounts: %w", err)
		}
	}()
	go func() {
		defer wg.Done()
		if _, err := GetDeployments(ctx, clientset); err != nil {
			errChan <- fmt.Errorf("deployments: %w", err)
		}
	}()
	go func() {
		defer wg.Done()
		if _, err := GetDaemonSets(ctx, clientset); err != nil {
			errChan <- fmt.Errorf("daemonsets: %w", err)
		}
	}()
	go func() {
		defer wg.Done()
		if _, err := GetStatefulSets(ctx, clientset); err != nil {
			errChan <- fmt.Errorf("statefulsets: %w", err)
		}
	}()
	go func() {
		defer wg.Done()
		if _, err := GetReplicaSets(ctx, clientset); err != nil {
			errChan <- fmt.Errorf("replicasets: %w", err)
		}
	}()
	go func() {
		defer wg.Done()
		if _, err := GetValidatingWebhooks(ctx, clientset); err != nil {
			errChan <- fmt.Errorf("validatingwebhooks: %w", err)
		}
	}()
	go func() {
		defer wg.Done()
		if _, err := GetMutatingWebhooks(ctx, clientset); err != nil {
			errChan <- fmt.Errorf("mutatingwebhooks: %w", err)
		}
	}()
	go func() {
		defer wg.Done()
		if _, err := GetConfigMaps(ctx, clientset); err != nil {
			errChan <- fmt.Errorf("configmaps: %w", err)
		}
	}()
	go func() {
		defer wg.Done()
		if _, err := GetEndpoints(ctx, clientset); err != nil {
			errChan <- fmt.Errorf("endpoints: %w", err)
		}
	}()

	wg.Wait()
	close(errChan)

	// Collect any errors (log them but don't fail - partial cache is still useful)
	for err := range errChan {
		cacheLogger.ErrorM(fmt.Sprintf("Cache warm warning: %v", err), "cache")
	}

	cacheLogger.InfoM("Resource cache warmed successfully", "cache")
	return nil
}

// ============================================================================
// NAMESPACE FILTERING HELPERS
// ============================================================================

// filterByNamespace filters items by configured namespaces from globals
func filterByNamespace[T any](items []T, getNamespace func(T) string) []T {
	if len(globals.K8sNamespaces) == 0 || globals.K8sAllNamespaces {
		return items
	}

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

// ============================================================================
// CORE RESOURCES
// ============================================================================

// GetPods returns all pods, using cache if available.
func GetPods(ctx context.Context, clientset *kubernetes.Clientset) ([]corev1.Pod, error) {
	pods, err := GetOrSet(CacheKeyPods, func() ([]corev1.Pod, error) {
		var allPods []corev1.Pod
		continueToken := ""

		for {
			listOpts := metav1.ListOptions{
				Limit:    500,
				Continue: continueToken,
			}

			podList, err := clientset.CoreV1().Pods(metav1.NamespaceAll).List(ctx, listOpts)
			if err != nil {
				return nil, err
			}

			allPods = append(allPods, podList.Items...)

			if podList.Continue == "" {
				break
			}
			continueToken = podList.Continue
		}

		return allPods, nil
	})

	if err != nil {
		return nil, err
	}

	return filterByNamespace(pods, func(p corev1.Pod) string { return p.Namespace }), nil
}

// GetServices returns all services, using cache if available.
func GetServices(ctx context.Context, clientset *kubernetes.Clientset) ([]corev1.Service, error) {
	services, err := GetOrSet(CacheKeyServices, func() ([]corev1.Service, error) {
		serviceList, err := clientset.CoreV1().Services(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return serviceList.Items, nil
	})

	if err != nil {
		return nil, err
	}

	return filterByNamespace(services, func(s corev1.Service) string { return s.Namespace }), nil
}

// GetNodes returns all nodes, using cache if available.
func GetNodes(ctx context.Context, clientset *kubernetes.Clientset) ([]corev1.Node, error) {
	return GetOrSet(CacheKeyNodes, func() ([]corev1.Node, error) {
		nodeList, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return nodeList.Items, nil
	})
}

// GetNamespaces returns all namespaces, using cache if available.
func GetNamespaces(ctx context.Context, clientset *kubernetes.Clientset) ([]corev1.Namespace, error) {
	return GetOrSet(CacheKeyNamespaces, func() ([]corev1.Namespace, error) {
		nsList, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return nsList.Items, nil
	})
}

// GetSecrets returns all secrets, using cache if available.
func GetSecrets(ctx context.Context, clientset *kubernetes.Clientset) ([]corev1.Secret, error) {
	secrets, err := GetOrSet(CacheKeySecrets, func() ([]corev1.Secret, error) {
		secretList, err := clientset.CoreV1().Secrets(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return secretList.Items, nil
	})

	if err != nil {
		return nil, err
	}

	return filterByNamespace(secrets, func(s corev1.Secret) string { return s.Namespace }), nil
}

// GetConfigMaps returns all configmaps, using cache if available.
func GetConfigMaps(ctx context.Context, clientset *kubernetes.Clientset) ([]corev1.ConfigMap, error) {
	configMaps, err := GetOrSet(CacheKeyConfigMaps, func() ([]corev1.ConfigMap, error) {
		cmList, err := clientset.CoreV1().ConfigMaps(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return cmList.Items, nil
	})

	if err != nil {
		return nil, err
	}

	return filterByNamespace(configMaps, func(c corev1.ConfigMap) string { return c.Namespace }), nil
}

// GetServiceAccounts returns all service accounts, using cache if available.
func GetServiceAccounts(ctx context.Context, clientset *kubernetes.Clientset) ([]corev1.ServiceAccount, error) {
	sas, err := GetOrSet(CacheKeyServiceAccounts, func() ([]corev1.ServiceAccount, error) {
		saList, err := clientset.CoreV1().ServiceAccounts(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return saList.Items, nil
	})

	if err != nil {
		return nil, err
	}

	return filterByNamespace(sas, func(sa corev1.ServiceAccount) string { return sa.Namespace }), nil
}

// GetEndpoints returns all endpoints, using cache if available.
func GetEndpoints(ctx context.Context, clientset *kubernetes.Clientset) ([]corev1.Endpoints, error) {
	endpoints, err := GetOrSet(CacheKeyEndpoints, func() ([]corev1.Endpoints, error) {
		epList, err := clientset.CoreV1().Endpoints(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return epList.Items, nil
	})

	if err != nil {
		return nil, err
	}

	return filterByNamespace(endpoints, func(e corev1.Endpoints) string { return e.Namespace }), nil
}

// GetEvents returns all events, using cache if available.
func GetEvents(ctx context.Context, clientset *kubernetes.Clientset) ([]corev1.Event, error) {
	events, err := GetOrSet(CacheKeyEvents, func() ([]corev1.Event, error) {
		eventList, err := clientset.CoreV1().Events(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return eventList.Items, nil
	})

	if err != nil {
		return nil, err
	}

	return filterByNamespace(events, func(e corev1.Event) string { return e.Namespace }), nil
}

// GetResourceQuotas returns all resource quotas, using cache if available.
func GetResourceQuotas(ctx context.Context, clientset *kubernetes.Clientset) ([]corev1.ResourceQuota, error) {
	rqs, err := GetOrSet(CacheKeyResourceQuotas, func() ([]corev1.ResourceQuota, error) {
		rqList, err := clientset.CoreV1().ResourceQuotas(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return rqList.Items, nil
	})

	if err != nil {
		return nil, err
	}

	return filterByNamespace(rqs, func(rq corev1.ResourceQuota) string { return rq.Namespace }), nil
}

// GetLimitRanges returns all limit ranges, using cache if available.
func GetLimitRanges(ctx context.Context, clientset *kubernetes.Clientset) ([]corev1.LimitRange, error) {
	lrs, err := GetOrSet(CacheKeyLimitRanges, func() ([]corev1.LimitRange, error) {
		lrList, err := clientset.CoreV1().LimitRanges(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return lrList.Items, nil
	})

	if err != nil {
		return nil, err
	}

	return filterByNamespace(lrs, func(lr corev1.LimitRange) string { return lr.Namespace }), nil
}

// GetPersistentVolumes returns all persistent volumes, using cache if available.
func GetPersistentVolumes(ctx context.Context, clientset *kubernetes.Clientset) ([]corev1.PersistentVolume, error) {
	return GetOrSet(CacheKeyPersistentVolumes, func() ([]corev1.PersistentVolume, error) {
		pvList, err := clientset.CoreV1().PersistentVolumes().List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return pvList.Items, nil
	})
}

// GetPersistentVolumeClaims returns all persistent volume claims, using cache if available.
func GetPersistentVolumeClaims(ctx context.Context, clientset *kubernetes.Clientset) ([]corev1.PersistentVolumeClaim, error) {
	pvcs, err := GetOrSet(CacheKeyPersistentVolumeClaims, func() ([]corev1.PersistentVolumeClaim, error) {
		pvcList, err := clientset.CoreV1().PersistentVolumeClaims(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return pvcList.Items, nil
	})

	if err != nil {
		return nil, err
	}

	return filterByNamespace(pvcs, func(pvc corev1.PersistentVolumeClaim) string { return pvc.Namespace }), nil
}

// ============================================================================
// NETWORKING RESOURCES
// ============================================================================

// GetNetworkPolicies returns all network policies, using cache if available.
func GetNetworkPolicies(ctx context.Context, clientset *kubernetes.Clientset) ([]networkingv1.NetworkPolicy, error) {
	nps, err := GetOrSet(CacheKeyNetworkPolicies, func() ([]networkingv1.NetworkPolicy, error) {
		npList, err := clientset.NetworkingV1().NetworkPolicies(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return npList.Items, nil
	})

	if err != nil {
		return nil, err
	}

	return filterByNamespace(nps, func(np networkingv1.NetworkPolicy) string { return np.Namespace }), nil
}

// GetIngresses returns all ingresses, using cache if available.
func GetIngresses(ctx context.Context, clientset *kubernetes.Clientset) ([]networkingv1.Ingress, error) {
	ingresses, err := GetOrSet(CacheKeyIngresses, func() ([]networkingv1.Ingress, error) {
		ingList, err := clientset.NetworkingV1().Ingresses(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return ingList.Items, nil
	})

	if err != nil {
		return nil, err
	}

	return filterByNamespace(ingresses, func(ing networkingv1.Ingress) string { return ing.Namespace }), nil
}

// ============================================================================
// RBAC RESOURCES
// ============================================================================

// GetRoles returns all roles, using cache if available.
func GetRoles(ctx context.Context, clientset *kubernetes.Clientset) ([]rbacv1.Role, error) {
	roles, err := GetOrSet(CacheKeyRoles, func() ([]rbacv1.Role, error) {
		roleList, err := clientset.RbacV1().Roles(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return roleList.Items, nil
	})

	if err != nil {
		return nil, err
	}

	return filterByNamespace(roles, func(r rbacv1.Role) string { return r.Namespace }), nil
}

// GetClusterRoles returns all cluster roles, using cache if available.
func GetClusterRoles(ctx context.Context, clientset *kubernetes.Clientset) ([]rbacv1.ClusterRole, error) {
	return GetOrSet(CacheKeyClusterRoles, func() ([]rbacv1.ClusterRole, error) {
		crList, err := clientset.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return crList.Items, nil
	})
}

// GetRoleBindings returns all role bindings, using cache if available.
func GetRoleBindings(ctx context.Context, clientset *kubernetes.Clientset) ([]rbacv1.RoleBinding, error) {
	rbs, err := GetOrSet(CacheKeyRoleBindings, func() ([]rbacv1.RoleBinding, error) {
		rbList, err := clientset.RbacV1().RoleBindings(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return rbList.Items, nil
	})

	if err != nil {
		return nil, err
	}

	return filterByNamespace(rbs, func(rb rbacv1.RoleBinding) string { return rb.Namespace }), nil
}

// GetClusterRoleBindings returns all cluster role bindings, using cache if available.
func GetClusterRoleBindings(ctx context.Context, clientset *kubernetes.Clientset) ([]rbacv1.ClusterRoleBinding, error) {
	return GetOrSet(CacheKeyClusterRoleBindings, func() ([]rbacv1.ClusterRoleBinding, error) {
		crbList, err := clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return crbList.Items, nil
	})
}

// ============================================================================
// WORKLOAD RESOURCES
// ============================================================================

// GetDeployments returns all deployments, using cache if available.
func GetDeployments(ctx context.Context, clientset *kubernetes.Clientset) ([]appsv1.Deployment, error) {
	deps, err := GetOrSet(CacheKeyDeployments, func() ([]appsv1.Deployment, error) {
		depList, err := clientset.AppsV1().Deployments(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return depList.Items, nil
	})

	if err != nil {
		return nil, err
	}

	return filterByNamespace(deps, func(d appsv1.Deployment) string { return d.Namespace }), nil
}

// GetDaemonSets returns all daemon sets, using cache if available.
func GetDaemonSets(ctx context.Context, clientset *kubernetes.Clientset) ([]appsv1.DaemonSet, error) {
	dss, err := GetOrSet(CacheKeyDaemonSets, func() ([]appsv1.DaemonSet, error) {
		dsList, err := clientset.AppsV1().DaemonSets(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return dsList.Items, nil
	})

	if err != nil {
		return nil, err
	}

	return filterByNamespace(dss, func(ds appsv1.DaemonSet) string { return ds.Namespace }), nil
}

// GetStatefulSets returns all stateful sets, using cache if available.
func GetStatefulSets(ctx context.Context, clientset *kubernetes.Clientset) ([]appsv1.StatefulSet, error) {
	sss, err := GetOrSet(CacheKeyStatefulSets, func() ([]appsv1.StatefulSet, error) {
		ssList, err := clientset.AppsV1().StatefulSets(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return ssList.Items, nil
	})

	if err != nil {
		return nil, err
	}

	return filterByNamespace(sss, func(ss appsv1.StatefulSet) string { return ss.Namespace }), nil
}

// GetReplicaSets returns all replica sets, using cache if available.
func GetReplicaSets(ctx context.Context, clientset *kubernetes.Clientset) ([]appsv1.ReplicaSet, error) {
	rss, err := GetOrSet(CacheKeyReplicaSets, func() ([]appsv1.ReplicaSet, error) {
		rsList, err := clientset.AppsV1().ReplicaSets(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return rsList.Items, nil
	})

	if err != nil {
		return nil, err
	}

	return filterByNamespace(rss, func(rs appsv1.ReplicaSet) string { return rs.Namespace }), nil
}

// GetJobs returns all jobs, using cache if available.
func GetJobs(ctx context.Context, clientset *kubernetes.Clientset) ([]batchv1.Job, error) {
	jobs, err := GetOrSet(CacheKeyJobs, func() ([]batchv1.Job, error) {
		jobList, err := clientset.BatchV1().Jobs(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return jobList.Items, nil
	})

	if err != nil {
		return nil, err
	}

	return filterByNamespace(jobs, func(j batchv1.Job) string { return j.Namespace }), nil
}

// GetCronJobs returns all cron jobs, using cache if available.
func GetCronJobs(ctx context.Context, clientset *kubernetes.Clientset) ([]batchv1.CronJob, error) {
	cjs, err := GetOrSet(CacheKeyCronJobs, func() ([]batchv1.CronJob, error) {
		cjList, err := clientset.BatchV1().CronJobs(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return cjList.Items, nil
	})

	if err != nil {
		return nil, err
	}

	return filterByNamespace(cjs, func(cj batchv1.CronJob) string { return cj.Namespace }), nil
}

// ============================================================================
// ADMISSION RESOURCES
// ============================================================================

// GetValidatingWebhooks returns all validating webhook configurations, using cache if available.
func GetValidatingWebhooks(ctx context.Context, clientset *kubernetes.Clientset) ([]admissionv1.ValidatingWebhookConfiguration, error) {
	return GetOrSet(CacheKeyValidatingWebhooks, func() ([]admissionv1.ValidatingWebhookConfiguration, error) {
		vwhList, err := clientset.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return vwhList.Items, nil
	})
}

// GetMutatingWebhooks returns all mutating webhook configurations, using cache if available.
func GetMutatingWebhooks(ctx context.Context, clientset *kubernetes.Clientset) ([]admissionv1.MutatingWebhookConfiguration, error) {
	return GetOrSet(CacheKeyMutatingWebhooks, func() ([]admissionv1.MutatingWebhookConfiguration, error) {
		mwhList, err := clientset.AdmissionregistrationV1().MutatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return mwhList.Items, nil
	})
}

// ============================================================================
// CLUSTER RESOURCES
// ============================================================================

// GetStorageClasses returns all storage classes, using cache if available.
func GetStorageClasses(ctx context.Context, clientset *kubernetes.Clientset) ([]storagev1.StorageClass, error) {
	return GetOrSet(CacheKeyStorageClasses, func() ([]storagev1.StorageClass, error) {
		scList, err := clientset.StorageV1().StorageClasses().List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return scList.Items, nil
	})
}

// GetPriorityClasses returns all priority classes, using cache if available.
func GetPriorityClasses(ctx context.Context, clientset *kubernetes.Clientset) ([]schedulingv1.PriorityClass, error) {
	return GetOrSet(CacheKeyPriorityClasses, func() ([]schedulingv1.PriorityClass, error) {
		pcList, err := clientset.SchedulingV1().PriorityClasses().List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return pcList.Items, nil
	})
}

// GetPodDisruptionBudgets returns all pod disruption budgets, using cache if available.
func GetPodDisruptionBudgets(ctx context.Context, clientset *kubernetes.Clientset) ([]policyv1.PodDisruptionBudget, error) {
	pdbs, err := GetOrSet(CacheKeyPodDisruptionBudgets, func() ([]policyv1.PodDisruptionBudget, error) {
		pdbList, err := clientset.PolicyV1().PodDisruptionBudgets(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return pdbList.Items, nil
	})

	if err != nil {
		return nil, err
	}

	return filterByNamespace(pdbs, func(pdb policyv1.PodDisruptionBudget) string { return pdb.Namespace }), nil
}

// GetHorizontalPodAutoscalers returns all HPAs, using cache if available.
func GetHorizontalPodAutoscalers(ctx context.Context, clientset *kubernetes.Clientset) ([]autoscalingv2.HorizontalPodAutoscaler, error) {
	hpas, err := GetOrSet(CacheKeyHPAs, func() ([]autoscalingv2.HorizontalPodAutoscaler, error) {
		hpaList, err := clientset.AutoscalingV2().HorizontalPodAutoscalers(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return hpaList.Items, nil
	})

	if err != nil {
		return nil, err
	}

	return filterByNamespace(hpas, func(hpa autoscalingv2.HorizontalPodAutoscaler) string { return hpa.Namespace }), nil
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

// GetPodsInNamespace returns pods filtered to a specific namespace.
func GetPodsInNamespace(ctx context.Context, clientset *kubernetes.Clientset, namespace string) ([]corev1.Pod, error) {
	allPods, err := GetPods(ctx, clientset)
	if err != nil {
		return nil, err
	}

	var filtered []corev1.Pod
	for _, pod := range allPods {
		if pod.Namespace == namespace {
			filtered = append(filtered, pod)
		}
	}
	return filtered, nil
}

// GetServicesInNamespace returns services filtered to a specific namespace.
func GetServicesInNamespace(ctx context.Context, clientset *kubernetes.Clientset, namespace string) ([]corev1.Service, error) {
	allServices, err := GetServices(ctx, clientset)
	if err != nil {
		return nil, err
	}

	var filtered []corev1.Service
	for _, svc := range allServices {
		if svc.Namespace == namespace {
			filtered = append(filtered, svc)
		}
	}
	return filtered, nil
}

// GetSecretsInNamespace returns secrets filtered to a specific namespace.
func GetSecretsInNamespace(ctx context.Context, clientset *kubernetes.Clientset, namespace string) ([]corev1.Secret, error) {
	allSecrets, err := GetSecrets(ctx, clientset)
	if err != nil {
		return nil, err
	}

	var filtered []corev1.Secret
	for _, secret := range allSecrets {
		if secret.Namespace == namespace {
			filtered = append(filtered, secret)
		}
	}
	return filtered, nil
}

// CacheStats returns statistics about cached resources for debugging/logging.
func CacheStats() map[string]int {
	stats := make(map[string]int)

	keys := []string{
		CacheKeyPods, CacheKeyServices, CacheKeyNodes, CacheKeyNamespaces,
		CacheKeySecrets, CacheKeyConfigMaps, CacheKeyServiceAccounts,
		CacheKeyNetworkPolicies, CacheKeyIngresses,
		CacheKeyRoles, CacheKeyClusterRoles, CacheKeyRoleBindings, CacheKeyClusterRoleBindings,
		CacheKeyDeployments, CacheKeyDaemonSets, CacheKeyStatefulSets, CacheKeyReplicaSets,
		CacheKeyJobs, CacheKeyCronJobs,
		CacheKeyValidatingWebhooks, CacheKeyMutatingWebhooks,
	}

	for _, key := range keys {
		if cached, found := Get(key); found {
			switch v := cached.(type) {
			case []corev1.Pod:
				stats[key] = len(v)
			case []corev1.Service:
				stats[key] = len(v)
			case []corev1.Node:
				stats[key] = len(v)
			case []corev1.Namespace:
				stats[key] = len(v)
			case []corev1.Secret:
				stats[key] = len(v)
			case []corev1.ConfigMap:
				stats[key] = len(v)
			case []corev1.ServiceAccount:
				stats[key] = len(v)
			case []networkingv1.NetworkPolicy:
				stats[key] = len(v)
			case []networkingv1.Ingress:
				stats[key] = len(v)
			case []rbacv1.Role:
				stats[key] = len(v)
			case []rbacv1.ClusterRole:
				stats[key] = len(v)
			case []rbacv1.RoleBinding:
				stats[key] = len(v)
			case []rbacv1.ClusterRoleBinding:
				stats[key] = len(v)
			case []appsv1.Deployment:
				stats[key] = len(v)
			case []appsv1.DaemonSet:
				stats[key] = len(v)
			case []appsv1.StatefulSet:
				stats[key] = len(v)
			case []appsv1.ReplicaSet:
				stats[key] = len(v)
			case []batchv1.Job:
				stats[key] = len(v)
			case []batchv1.CronJob:
				stats[key] = len(v)
			case []admissionv1.ValidatingWebhookConfiguration:
				stats[key] = len(v)
			case []admissionv1.MutatingWebhookConfiguration:
				stats[key] = len(v)
			}
		}
	}

	return stats
}
