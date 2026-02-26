// Package eventgridservice provides Azure Event Grid service abstractions
//
// This service layer abstracts Azure Event Grid API calls from command modules,
// following the standardized pattern established in STANDARDIZATION.md.
package eventgridservice

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/eventgrid/armeventgrid/v2"
	"github.com/BishopFox/cloudfox/globals"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/patrickmn/go-cache"
)

// serviceCache is the centralized cache for Event Grid service calls
var serviceCache = cache.New(2*time.Hour, 10*time.Minute)

// cacheKey generates a consistent cache key from components
func cacheKey(parts ...string) string {
	result := "eventgridservice"
	for _, part := range parts {
		result += "-" + part
	}
	return result
}

// EventGridService provides methods for interacting with Azure Event Grid
type EventGridService struct {
	session *azinternal.SafeSession
}

// New creates a new EventGridService instance
func New(session *azinternal.SafeSession) *EventGridService {
	return &EventGridService{
		session: session,
	}
}

// NewWithSession creates a new EventGridService with the given session (alias for New)
func NewWithSession(session *azinternal.SafeSession) *EventGridService {
	return New(session)
}

// TopicInfo represents an Event Grid topic
type TopicInfo struct {
	Name              string
	ResourceGroup     string
	Location          string
	Endpoint          string
	ProvisioningState string
	PublicNetworkAccess string
	InputSchema       string
}

// DomainInfo represents an Event Grid domain
type DomainInfo struct {
	Name              string
	ResourceGroup     string
	Location          string
	Endpoint          string
	ProvisioningState string
	PublicNetworkAccess string
}

// SubscriptionInfo represents an Event Grid subscription
type SubscriptionInfo struct {
	Name            string
	TopicName       string
	EndpointType    string
	Endpoint        string
	ProvisioningState string
}

// SystemTopicInfo represents a system topic
type SystemTopicInfo struct {
	Name              string
	ResourceGroup     string
	Location          string
	Source            string
	TopicType         string
	ProvisioningState string
}

// getARMCredential returns ARM credential from session
func (s *EventGridService) getARMCredential() (*azinternal.StaticTokenCredential, error) {
	token, err := s.session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token: %w", err)
	}
	return &azinternal.StaticTokenCredential{Token: token}, nil
}

// ListTopics returns all Event Grid topics in a subscription
func (s *EventGridService) ListTopics(ctx context.Context, subID string) ([]*armeventgrid.Topic, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armeventgrid.NewTopicsClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create topics client: %w", err)
	}

	pager := client.NewListBySubscriptionPager(nil)
	var topics []*armeventgrid.Topic

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return topics, fmt.Errorf("failed to list topics: %w", err)
		}
		topics = append(topics, page.Value...)
	}

	return topics, nil
}

// ListTopicsByResourceGroup returns all topics in a resource group
func (s *EventGridService) ListTopicsByResourceGroup(ctx context.Context, subID, rgName string) ([]*armeventgrid.Topic, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armeventgrid.NewTopicsClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create topics client: %w", err)
	}

	pager := client.NewListByResourceGroupPager(rgName, nil)
	var topics []*armeventgrid.Topic

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return topics, fmt.Errorf("failed to list topics: %w", err)
		}
		topics = append(topics, page.Value...)
	}

	return topics, nil
}

// GetTopicKeys returns the access keys for a topic
func (s *EventGridService) GetTopicKeys(ctx context.Context, subID, rgName, topicName string) (*armeventgrid.TopicSharedAccessKeys, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armeventgrid.NewTopicsClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create topics client: %w", err)
	}

	resp, err := client.ListSharedAccessKeys(ctx, rgName, topicName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get topic keys: %w", err)
	}

	return &resp.TopicSharedAccessKeys, nil
}

// ListDomains returns all Event Grid domains in a subscription
func (s *EventGridService) ListDomains(ctx context.Context, subID string) ([]*armeventgrid.Domain, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armeventgrid.NewDomainsClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create domains client: %w", err)
	}

	pager := client.NewListBySubscriptionPager(nil)
	var domains []*armeventgrid.Domain

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return domains, fmt.Errorf("failed to list domains: %w", err)
		}
		domains = append(domains, page.Value...)
	}

	return domains, nil
}

// ListSystemTopics returns all system topics in a subscription
func (s *EventGridService) ListSystemTopics(ctx context.Context, subID string) ([]*armeventgrid.SystemTopic, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armeventgrid.NewSystemTopicsClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create system topics client: %w", err)
	}

	pager := client.NewListBySubscriptionPager(nil)
	var topics []*armeventgrid.SystemTopic

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return topics, fmt.Errorf("failed to list system topics: %w", err)
		}
		topics = append(topics, page.Value...)
	}

	return topics, nil
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

// CachedListTopics returns all Event Grid topics with caching
func (s *EventGridService) CachedListTopics(ctx context.Context, subID string) ([]*armeventgrid.Topic, error) {
	key := cacheKey("topics", subID)
	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armeventgrid.Topic), nil
	}
	result, err := s.ListTopics(ctx, subID)
	if err != nil {
		return nil, err
	}
	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListDomains returns all Event Grid domains with caching
func (s *EventGridService) CachedListDomains(ctx context.Context, subID string) ([]*armeventgrid.Domain, error) {
	key := cacheKey("domains", subID)
	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armeventgrid.Domain), nil
	}
	result, err := s.ListDomains(ctx, subID)
	if err != nil {
		return nil, err
	}
	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListSystemTopics returns all system topics with caching
func (s *EventGridService) CachedListSystemTopics(ctx context.Context, subID string) ([]*armeventgrid.SystemTopic, error) {
	key := cacheKey("systemtopics", subID)
	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armeventgrid.SystemTopic), nil
	}
	result, err := s.ListSystemTopics(ctx, subID)
	if err != nil {
		return nil, err
	}
	serviceCache.Set(key, result, 0)
	return result, nil
}
