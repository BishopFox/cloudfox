package pubsubservice

import (
	"context"
	"fmt"
	"strings"

	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/internal/gcp/sdk"
	pubsub "google.golang.org/api/pubsub/v1"
)

type PubSubService struct {
	session *gcpinternal.SafeSession
}

func New() *PubSubService {
	return &PubSubService{}
}

func NewWithSession(session *gcpinternal.SafeSession) *PubSubService {
	return &PubSubService{
		session: session,
	}
}

func (ps *PubSubService) getService(ctx context.Context) (*pubsub.Service, error) {
	if ps.session != nil {
		return sdk.CachedGetPubSubService(ctx, ps.session)
	}
	return pubsub.NewService(ctx)
}

// IAMBinding represents a single IAM role/member binding
type IAMBinding struct {
	Role   string `json:"role"`
	Member string `json:"member"`
}

// TopicInfo holds Pub/Sub topic details with security-relevant information
type TopicInfo struct {
	Name                     string
	ProjectID                string
	KmsKeyName               string // Encryption key if set
	MessageRetentionDuration string
	SchemaSettings           string
	Labels                   map[string]string

	// IAM bindings
	IAMBindings []IAMBinding

	// Subscriptions count
	SubscriptionCount int
}

// SubscriptionInfo holds Pub/Sub subscription details
type SubscriptionInfo struct {
	Name         string
	ProjectID    string
	Topic        string
	TopicProject string // Topic may be in different project

	// Configuration
	AckDeadlineSeconds  int64
	MessageRetention    string
	RetainAckedMessages bool
	ExpirationPolicy    string // TTL
	Filter              string

	// Push configuration
	PushEndpoint       string // Empty if pull subscription
	PushOIDCAudience   string
	PushServiceAccount string

	// Dead letter
	DeadLetterTopic     string
	MaxDeliveryAttempts int64

	// BigQuery export
	BigQueryTable string

	// Cloud Storage export
	CloudStorageBucket string

	// IAM bindings
	IAMBindings []IAMBinding
}

// Topics retrieves all Pub/Sub topics in a project
func (ps *PubSubService) Topics(projectID string) ([]TopicInfo, error) {
	ctx := context.Background()

	service, err := ps.getService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "pubsub.googleapis.com")
	}

	var topics []TopicInfo
	parent := fmt.Sprintf("projects/%s", projectID)

	call := service.Projects.Topics.List(parent)
	err = call.Pages(ctx, func(page *pubsub.ListTopicsResponse) error {
		for _, topic := range page.Topics {
			info := parseTopicInfo(topic, projectID)

			// Get subscription count
			subCount, _ := ps.getTopicSubscriptionCount(service, topic.Name)
			info.SubscriptionCount = subCount

			// Try to get IAM policy
			iamPolicy, iamErr := ps.getTopicIAMPolicy(service, topic.Name)
			if iamErr == nil && iamPolicy != nil {
				info.IAMBindings = parseIAMBindings(iamPolicy)
			}

			topics = append(topics, info)
		}
		return nil
	})

	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "pubsub.googleapis.com")
	}

	return topics, nil
}

// Subscriptions retrieves all Pub/Sub subscriptions in a project
func (ps *PubSubService) Subscriptions(projectID string) ([]SubscriptionInfo, error) {
	ctx := context.Background()

	service, err := ps.getService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "pubsub.googleapis.com")
	}

	var subscriptions []SubscriptionInfo
	parent := fmt.Sprintf("projects/%s", projectID)

	call := service.Projects.Subscriptions.List(parent)
	err = call.Pages(ctx, func(page *pubsub.ListSubscriptionsResponse) error {
		for _, sub := range page.Subscriptions {
			info := parseSubscriptionInfo(sub, projectID)

			// Try to get IAM policy
			iamPolicy, iamErr := ps.getSubscriptionIAMPolicy(service, sub.Name)
			if iamErr == nil && iamPolicy != nil {
				info.IAMBindings = parseIAMBindings(iamPolicy)
			}

			subscriptions = append(subscriptions, info)
		}
		return nil
	})

	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "pubsub.googleapis.com")
	}

	return subscriptions, nil
}

// parseTopicInfo extracts relevant information from a Pub/Sub topic
func parseTopicInfo(topic *pubsub.Topic, projectID string) TopicInfo {
	info := TopicInfo{
		Name:      extractName(topic.Name),
		ProjectID: projectID,
		Labels:    topic.Labels,
	}

	if topic.KmsKeyName != "" {
		info.KmsKeyName = topic.KmsKeyName
	}

	if topic.MessageRetentionDuration != "" {
		info.MessageRetentionDuration = topic.MessageRetentionDuration
	}

	if topic.SchemaSettings != nil {
		info.SchemaSettings = fmt.Sprintf("%s (%s)",
			extractName(topic.SchemaSettings.Schema),
			topic.SchemaSettings.Encoding)
	}

	return info
}

// parseSubscriptionInfo extracts relevant information from a Pub/Sub subscription
func parseSubscriptionInfo(sub *pubsub.Subscription, projectID string) SubscriptionInfo {
	info := SubscriptionInfo{
		Name:                sub.Name,
		ProjectID:           projectID,
		Topic:               extractName(sub.Topic),
		AckDeadlineSeconds:  sub.AckDeadlineSeconds,
		RetainAckedMessages: sub.RetainAckedMessages,
		Filter:              sub.Filter,
	}

	// Extract name from full path
	info.Name = extractName(sub.Name)

	// Extract topic project (may be different from subscription project)
	if strings.Contains(sub.Topic, "/") {
		parts := strings.Split(sub.Topic, "/")
		if len(parts) >= 2 {
			info.TopicProject = parts[1]
		}
	}

	// Message retention
	if sub.MessageRetentionDuration != "" {
		info.MessageRetention = sub.MessageRetentionDuration
	}

	// Expiration policy
	if sub.ExpirationPolicy != nil && sub.ExpirationPolicy.Ttl != "" {
		info.ExpirationPolicy = sub.ExpirationPolicy.Ttl
	}

	// Push configuration
	if sub.PushConfig != nil {
		info.PushEndpoint = sub.PushConfig.PushEndpoint

		if sub.PushConfig.OidcToken != nil {
			info.PushServiceAccount = sub.PushConfig.OidcToken.ServiceAccountEmail
			info.PushOIDCAudience = sub.PushConfig.OidcToken.Audience
		}
	}

	// Dead letter policy
	if sub.DeadLetterPolicy != nil {
		info.DeadLetterTopic = extractName(sub.DeadLetterPolicy.DeadLetterTopic)
		info.MaxDeliveryAttempts = sub.DeadLetterPolicy.MaxDeliveryAttempts
	}

	// BigQuery config
	if sub.BigqueryConfig != nil {
		info.BigQueryTable = sub.BigqueryConfig.Table
	}

	// Cloud Storage config
	if sub.CloudStorageConfig != nil {
		info.CloudStorageBucket = sub.CloudStorageConfig.Bucket
	}

	return info
}

// getTopicSubscriptionCount counts subscriptions for a topic
func (ps *PubSubService) getTopicSubscriptionCount(service *pubsub.Service, topicName string) (int, error) {
	ctx := context.Background()

	resp, err := service.Projects.Topics.Subscriptions.List(topicName).Context(ctx).Do()
	if err != nil {
		return 0, err
	}

	return len(resp.Subscriptions), nil
}

// getTopicIAMPolicy retrieves the IAM policy for a topic
func (ps *PubSubService) getTopicIAMPolicy(service *pubsub.Service, topicName string) (*pubsub.Policy, error) {
	ctx := context.Background()

	policy, err := service.Projects.Topics.GetIamPolicy(topicName).Context(ctx).Do()
	if err != nil {
		return nil, err
	}

	return policy, nil
}

// getSubscriptionIAMPolicy retrieves the IAM policy for a subscription
func (ps *PubSubService) getSubscriptionIAMPolicy(service *pubsub.Service, subscriptionName string) (*pubsub.Policy, error) {
	ctx := context.Background()

	policy, err := service.Projects.Subscriptions.GetIamPolicy(subscriptionName).Context(ctx).Do()
	if err != nil {
		return nil, err
	}

	return policy, nil
}

// parseIAMBindings extracts all IAM bindings from a policy
func parseIAMBindings(policy *pubsub.Policy) []IAMBinding {
	var bindings []IAMBinding
	for _, binding := range policy.Bindings {
		if binding == nil {
			continue
		}
		for _, member := range binding.Members {
			bindings = append(bindings, IAMBinding{
				Role:   binding.Role,
				Member: member,
			})
		}
	}
	return bindings
}

// extractName extracts just the resource name from the full resource name
func extractName(fullName string) string {
	parts := strings.Split(fullName, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return fullName
}
