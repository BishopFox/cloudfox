// Package servicebusservice provides Azure Service Bus service abstractions
//
// This service layer abstracts Azure Service Bus API calls from command modules,
// following the standardized pattern established in STANDARDIZATION.md.
package servicebusservice

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/servicebus/armservicebus"
	"github.com/BishopFox/cloudfox/globals"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/patrickmn/go-cache"
)

// serviceCache is the centralized cache for Service Bus service calls
var serviceCache = cache.New(2*time.Hour, 10*time.Minute)

// cacheKey generates a consistent cache key from components
func cacheKey(parts ...string) string {
	result := "servicebusservice"
	for _, part := range parts {
		result += "-" + part
	}
	return result
}

// ServiceBusService provides methods for interacting with Azure Service Bus
type ServiceBusService struct {
	session *azinternal.SafeSession
}

// New creates a new ServiceBusService instance
func New(session *azinternal.SafeSession) *ServiceBusService {
	return &ServiceBusService{
		session: session,
	}
}

// NewWithSession creates a new ServiceBusService with the given session (alias for New)
func NewWithSession(session *azinternal.SafeSession) *ServiceBusService {
	return New(session)
}

// NamespaceInfo represents a Service Bus namespace
type NamespaceInfo struct {
	Name                string
	ResourceGroup       string
	Location            string
	SKU                 string
	ServiceBusEndpoint  string
	ProvisioningState   string
	PublicNetworkAccess string
	ZoneRedundant       bool
}

// QueueInfo represents a Service Bus queue
type QueueInfo struct {
	Name               string
	NamespaceName      string
	MaxSizeInMegabytes int32
	MessageCount       int64
	Status             string
	RequiresSession    bool
	DeadLetteringEnabled bool
}

// TopicInfo represents a Service Bus topic
type TopicInfo struct {
	Name               string
	NamespaceName      string
	MaxSizeInMegabytes int32
	SubscriptionCount  int32
	Status             string
}

// SubscriptionInfo represents a topic subscription
type SubscriptionInfo struct {
	Name            string
	TopicName       string
	NamespaceName   string
	MessageCount    int64
	Status          string
	RequiresSession bool
}

// getARMCredential returns ARM credential from session
func (s *ServiceBusService) getARMCredential() (*azinternal.StaticTokenCredential, error) {
	token, err := s.session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token: %w", err)
	}
	return &azinternal.StaticTokenCredential{Token: token}, nil
}

// ListNamespaces returns all Service Bus namespaces in a subscription
func (s *ServiceBusService) ListNamespaces(ctx context.Context, subID string) ([]*armservicebus.SBNamespace, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armservicebus.NewNamespacesClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create namespaces client: %w", err)
	}

	pager := client.NewListPager(nil)
	var namespaces []*armservicebus.SBNamespace

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return namespaces, fmt.Errorf("failed to list namespaces: %w", err)
		}
		namespaces = append(namespaces, page.Value...)
	}

	return namespaces, nil
}

// ListNamespacesByResourceGroup returns all namespaces in a resource group
func (s *ServiceBusService) ListNamespacesByResourceGroup(ctx context.Context, subID, rgName string) ([]*armservicebus.SBNamespace, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armservicebus.NewNamespacesClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create namespaces client: %w", err)
	}

	pager := client.NewListByResourceGroupPager(rgName, nil)
	var namespaces []*armservicebus.SBNamespace

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return namespaces, fmt.Errorf("failed to list namespaces: %w", err)
		}
		namespaces = append(namespaces, page.Value...)
	}

	return namespaces, nil
}

// GetNamespaceKeys returns the access keys for a namespace
func (s *ServiceBusService) GetNamespaceKeys(ctx context.Context, subID, rgName, namespaceName, authRuleName string) (*armservicebus.AccessKeys, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armservicebus.NewNamespacesClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create namespaces client: %w", err)
	}

	resp, err := client.ListKeys(ctx, rgName, namespaceName, authRuleName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get namespace keys: %w", err)
	}

	return &resp.AccessKeys, nil
}

// ListQueues returns all queues in a Service Bus namespace
func (s *ServiceBusService) ListQueues(ctx context.Context, subID, rgName, namespaceName string) ([]*armservicebus.SBQueue, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armservicebus.NewQueuesClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create queues client: %w", err)
	}

	pager := client.NewListByNamespacePager(rgName, namespaceName, nil)
	var queues []*armservicebus.SBQueue

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return queues, fmt.Errorf("failed to list queues: %w", err)
		}
		queues = append(queues, page.Value...)
	}

	return queues, nil
}

// ListTopics returns all topics in a Service Bus namespace
func (s *ServiceBusService) ListTopics(ctx context.Context, subID, rgName, namespaceName string) ([]*armservicebus.SBTopic, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armservicebus.NewTopicsClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create topics client: %w", err)
	}

	pager := client.NewListByNamespacePager(rgName, namespaceName, nil)
	var topics []*armservicebus.SBTopic

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return topics, fmt.Errorf("failed to list topics: %w", err)
		}
		topics = append(topics, page.Value...)
	}

	return topics, nil
}

// ListSubscriptions returns all subscriptions for a topic
func (s *ServiceBusService) ListSubscriptions(ctx context.Context, subID, rgName, namespaceName, topicName string) ([]*armservicebus.SBSubscription, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armservicebus.NewSubscriptionsClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create subscriptions client: %w", err)
	}

	pager := client.NewListByTopicPager(rgName, namespaceName, topicName, nil)
	var subscriptions []*armservicebus.SBSubscription

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return subscriptions, fmt.Errorf("failed to list subscriptions: %w", err)
		}
		subscriptions = append(subscriptions, page.Value...)
	}

	return subscriptions, nil
}

// safeString safely dereferences a string pointer
func safeString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// =============================================================================
// Cached Methods
// =============================================================================

// CachedListNamespaces returns all Service Bus namespaces with caching
func (s *ServiceBusService) CachedListNamespaces(ctx context.Context, subID string) ([]*armservicebus.SBNamespace, error) {
	key := cacheKey("namespaces", subID)
	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armservicebus.SBNamespace), nil
	}
	result, err := s.ListNamespaces(ctx, subID)
	if err != nil {
		return nil, err
	}
	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListQueues returns all queues in a Service Bus namespace with caching
func (s *ServiceBusService) CachedListQueues(ctx context.Context, subID, rgName, namespaceName string) ([]*armservicebus.SBQueue, error) {
	key := cacheKey("queues", subID, rgName, namespaceName)
	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armservicebus.SBQueue), nil
	}
	result, err := s.ListQueues(ctx, subID, rgName, namespaceName)
	if err != nil {
		return nil, err
	}
	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListTopics returns all topics in a Service Bus namespace with caching
func (s *ServiceBusService) CachedListTopics(ctx context.Context, subID, rgName, namespaceName string) ([]*armservicebus.SBTopic, error) {
	key := cacheKey("topics", subID, rgName, namespaceName)
	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armservicebus.SBTopic), nil
	}
	result, err := s.ListTopics(ctx, subID, rgName, namespaceName)
	if err != nil {
		return nil, err
	}
	serviceCache.Set(key, result, 0)
	return result, nil
}
