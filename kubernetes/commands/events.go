package commands

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/BishopFox/cloudfox/kubernetes/shared"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var EventsCmd = &cobra.Command{
	Use:     "events",
	Aliases: []string{"event", "ev"},
	Short:   "Analyze Kubernetes events for security insights",
	Long: `
Analyze Kubernetes events with security-focused categorization including:
  - Failed pod scheduling (resource exhaustion, taint mismatches)
  - Image pull failures (registry access, credential issues)
  - Admission webhook denials (policy violations)
  - Volume mount failures (permission/security issues)
  - OOMKilled events (DoS indicators, resource limits)
  - Eviction events (node pressure, capacity issues)
  - Security policy violations (PSP/PSA denials)
  - Authentication/authorization failures
  - Failed probe events (liveness/readiness failures)
  - Node events (NotReady, pressure conditions)
  - Event frequency analysis (potential attacks)
  - Timeline-based security analysis

Examples:
  # Show all events
  cloudfox kubernetes events

  # Search for events related to a service account
  cloudfox kubernetes events --search "my-service-account"

  # Search for permission/authorization issues
  cloudfox kubernetes events --search "forbidden"
  cloudfox kubernetes events --search "unauthorized"

  # Search for specific pod or deployment events
  cloudfox kubernetes events --search "nginx-deployment"

  # Search for OOM or memory issues
  cloudfox kubernetes events --search "oomkilled"

  # Combine with limit
  cloudfox kubernetes events --search "failed" --limit 100`,
	Run: ListEvents,
}

func init() {
	EventsCmd.Flags().BoolP("all", "a", false, "Show all events (no limit)")
	EventsCmd.Flags().IntP("limit", "l", 500, "Maximum number of events to display")
	EventsCmd.Flags().StringP("search", "s", "", "Filter events by keyword (searches name, namespace, reason, message)")
}

type EventsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t EventsOutput) TableFiles() []internal.TableFile {
	return t.Table
}

func (t EventsOutput) LootFiles() []internal.LootFile {
	return t.Loot
}

type EventAnalysis struct {
	Namespace      string
	Kind           string
	Name           string
	Reason         string
	Message        string
	Type           string
	Count          int32
	FirstSeen      time.Time
	LastSeen       time.Time
	Source         string
	InvolvedObject string
	Category       string
	Severity       string
	SecurityIssue  string
	RiskScore      int
}

type EventSummary struct {
	Namespace         string
	TotalEvents       int
	WarningEvents     int
	ErrorEvents       int
	SecurityEvents    int
	FailedScheduling  int
	ImagePullFailures int
	OOMKilled         int
	Evictions         int
	VolumeMountFails  int
	AdmissionDenials  int
	AuthFailures      int
	RiskLevel         string
	RiskScore         int
	TopIssues         []string
}

// Using shared.RiskCritical, shared.RiskHigh, shared.RiskMedium, shared.RiskLow constants

func ListEvents(cmd *cobra.Command, args []string) {
	ctx, cancel := shared.ContextWithTimeout()
	defer cancel()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	// Event-specific flags
	showAll, _ := cmd.Flags().GetBool("all")
	limit, _ := cmd.Flags().GetInt("limit")
	searchQuery, _ := cmd.Flags().GetString("search")

	if searchQuery != "" {
		logger.InfoM(fmt.Sprintf("Analyzing events for %s (filtering by: %q)", globals.ClusterName, searchQuery), globals.K8S_EVENTS_MODULE_NAME)
	} else {
		logger.InfoM(fmt.Sprintf("Analyzing events for %s", globals.ClusterName), globals.K8S_EVENTS_MODULE_NAME)
	}

	clientset := config.GetClientOrExit()

	// Fetch events from target namespaces
	events, err := clientset.CoreV1().Events(shared.GetNamespaceOrAll()).List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error fetching Events: %v", err), globals.K8S_EVENTS_MODULE_NAME)
		return
	}

	// Filter events by search query if provided
	filteredEvents := events.Items
	if searchQuery != "" {
		filteredEvents = filterEventsBySearch(events.Items, searchQuery)
		logger.InfoM(fmt.Sprintf("Found %d events matching %q (out of %d total)", len(filteredEvents), searchQuery, len(events.Items)), globals.K8S_EVENTS_MODULE_NAME)
	}

	var eventAnalyses []EventAnalysis
	loot := shared.NewLootBuilder()

	namespaceStats := make(map[string]*EventSummary)

	// Analyze each event
	for _, event := range filteredEvents {
		analysis := EventAnalysis{
			Namespace:      event.Namespace,
			Kind:           event.InvolvedObject.Kind,
			Name:           event.InvolvedObject.Name,
			Reason:         event.Reason,
			Message:        event.Message,
			Type:           event.Type,
			Count:          event.Count,
			FirstSeen:      event.FirstTimestamp.Time,
			LastSeen:       event.LastTimestamp.Time,
			Source:         fmt.Sprintf("%s/%s", event.Source.Component, event.Source.Host),
			InvolvedObject: fmt.Sprintf("%s/%s", event.InvolvedObject.Kind, event.InvolvedObject.Name),
		}

		// Categorize and assess security risk
		analysis.Category, analysis.Severity, analysis.SecurityIssue = categorizeEvent(&event)
		analysis.RiskScore = calculateEventRiskScore(&analysis, &event)

		// Track in namespace stats
		if namespaceStats[event.Namespace] == nil {
			namespaceStats[event.Namespace] = &EventSummary{
				Namespace: event.Namespace,
			}
		}
		stats := namespaceStats[event.Namespace]
		stats.TotalEvents++
		if event.Type == "Warning" {
			stats.WarningEvents++
		}

		// Track category counts for summary
		if analysis.Category == "Security" {
			stats.SecurityEvents++
		}
		if strings.Contains(analysis.Reason, "FailedScheduling") {
			stats.FailedScheduling++
		}
		if strings.Contains(analysis.Reason, "Failed") && strings.Contains(strings.ToLower(analysis.Message), "image") {
			stats.ImagePullFailures++
		}
		if strings.Contains(analysis.Reason, "OOMKilled") {
			stats.OOMKilled++
		}
		if strings.Contains(analysis.Reason, "FailedMount") || strings.Contains(analysis.Reason, "FailedAttachVolume") {
			stats.VolumeMountFails++
		}
		if strings.Contains(strings.ToLower(analysis.Message), "admission") && strings.Contains(strings.ToLower(analysis.Message), "denied") {
			stats.AdmissionDenials++
		}
		if strings.Contains(strings.ToLower(analysis.Reason), "unauthorized") || strings.Contains(strings.ToLower(analysis.Reason), "forbidden") {
			stats.AuthFailures++
		}

		eventAnalyses = append(eventAnalyses, analysis)
	}

	// Calculate namespace risk scores
	var summaries []EventSummary
	for _, stats := range namespaceStats {
		stats.RiskScore = calculateNamespaceEventRiskScore(stats)
		stats.RiskLevel = eventRiskScoreToLevel(stats.RiskScore)
		stats.TopIssues = identifyTopIssues(stats)
		summaries = append(summaries, *stats)
	}

	// Add Event-Commands section with kubectl commands
	loot.Section("Event-Commands").Add(generateEventCommands(summaries))

	// Generate loot files
	lootFiles := loot.Build()

	// Generate tables
	eventTable := generateEventTable(eventAnalyses, limit, showAll)
	summaryTable := generateSummaryTable(summaries)

	err = internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"Events",
		globals.ClusterName,
		"results",
		EventsOutput{
			Table: []internal.TableFile{summaryTable, eventTable},
			Loot:  lootFiles,
		},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_EVENTS_MODULE_NAME)
		return
	}

	// Summary logging
	if len(filteredEvents) > 0 {
		securityCount := 0
		oomCount := 0
		warningCount := 0
		for _, event := range filteredEvents {
			if event.Type == "Warning" {
				warningCount++
			}
		}
		// Count from stats
		for _, stats := range namespaceStats {
			securityCount += stats.SecurityEvents
			oomCount += stats.OOMKilled
		}
		logger.InfoM(fmt.Sprintf("%d events analyzed | Warnings: %d | Security: %d | OOMKilled: %d | Namespaces: %d",
			len(filteredEvents), warningCount, securityCount, oomCount, len(summaries)),
			globals.K8S_EVENTS_MODULE_NAME)
	} else {
		if searchQuery != "" {
			logger.InfoM(fmt.Sprintf("No events found matching %q", searchQuery), globals.K8S_EVENTS_MODULE_NAME)
		} else {
			logger.InfoM("No events found", globals.K8S_EVENTS_MODULE_NAME)
		}
	}
}

func categorizeEvent(event *corev1.Event) (category string, severity string, securityIssue string) {
	reason := strings.ToLower(event.Reason)
	message := strings.ToLower(event.Message)

	// Security-related events
	if strings.Contains(reason, "unauthorized") || strings.Contains(reason, "forbidden") {
		return "Security", shared.RiskCritical, "Authentication/Authorization failure"
	}
	if strings.Contains(message, "admission") && strings.Contains(message, "denied") {
		return "Security", shared.RiskHigh, "Admission policy violation"
	}
	if strings.Contains(reason, "failedcreate") && strings.Contains(message, "forbidden") {
		return "Security", shared.RiskHigh, "RBAC permission denied"
	}
	if strings.Contains(message, "securitycontext") || strings.Contains(message, "podsecuritypolicy") {
		return "Security", shared.RiskHigh, "Pod security policy violation"
	}

	// Resource exhaustion (DoS indicators)
	if strings.Contains(reason, "oomkilled") {
		return "Resource", shared.RiskHigh, "Out of memory (potential DoS)"
	}
	if strings.Contains(reason, "evicted") {
		return "Resource", shared.RiskMedium, "Pod evicted due to resource pressure"
	}
	if strings.Contains(reason, "failedscheduling") {
		if strings.Contains(message, "insufficient") {
			return "Resource", shared.RiskMedium, "Insufficient cluster resources"
		}
		return "Scheduling", shared.RiskMedium, "Pod scheduling failure"
	}

	// Image and registry issues
	if strings.Contains(reason, "failed") && strings.Contains(message, "image") {
		if strings.Contains(message, "unauthorized") || strings.Contains(message, "authentication") {
			return "Security", shared.RiskHigh, "Image registry authentication failure"
		}
		return "Image", shared.RiskMedium, "Image pull failure"
	}

	// Volume and storage issues
	if strings.Contains(reason, "failedmount") || strings.Contains(reason, "failedattachvolume") {
		if strings.Contains(message, "permission") || strings.Contains(message, "denied") {
			return "Security", shared.RiskHigh, "Volume mount permission denied"
		}
		return "Volume", shared.RiskMedium, "Volume mount failure"
	}

	// Probe failures
	if strings.Contains(reason, "unhealthy") {
		return "Health", shared.RiskLow, "Liveness/readiness probe failure"
	}

	// Node issues
	if strings.Contains(reason, "nodenotready") {
		return "Node", shared.RiskHigh, "Node not ready"
	}

	// Default
	if event.Type == "Warning" {
		return "General", shared.RiskLow, "Warning event"
	}
	return "Info", shared.RiskLow, "Informational"
}

func calculateEventRiskScore(analysis *EventAnalysis, event *corev1.Event) int {
	score := 0

	// Base score by severity
	switch analysis.Severity {
	case shared.RiskCritical:
		score += 40
	case shared.RiskHigh:
		score += 30
	case shared.RiskMedium:
		score += 20
	case shared.RiskLow:
		score += 10
	}

	// Frequency multiplier
	if event.Count > 100 {
		score += 30
	} else if event.Count > 50 {
		score += 20
	} else if event.Count > 10 {
		score += 10
	}

	// Recent events are higher risk
	if time.Since(event.LastTimestamp.Time) < 1*time.Hour {
		score += 20
	} else if time.Since(event.LastTimestamp.Time) < 24*time.Hour {
		score += 10
	}

	// Security category
	if analysis.Category == "Security" {
		score += 25
	}

	return score
}

func calculateNamespaceEventRiskScore(stats *EventSummary) int {
	score := 0

	// Security events
	if stats.SecurityEvents > 10 {
		score += 40
	} else if stats.SecurityEvents > 0 {
		score += 20
	}

	// OOM kills (DoS indicator)
	if stats.OOMKilled > 5 {
		score += 30
	} else if stats.OOMKilled > 0 {
		score += 15
	}

	// Admission denials
	if stats.AdmissionDenials > 10 {
		score += 25
	} else if stats.AdmissionDenials > 0 {
		score += 10
	}

	// Auth failures
	if stats.AuthFailures > 0 {
		score += 30
	}

	// Failed scheduling
	if stats.FailedScheduling > 20 {
		score += 20
	} else if stats.FailedScheduling > 5 {
		score += 10
	}

	// Warning ratio
	if stats.TotalEvents > 0 {
		warningRatio := float64(stats.WarningEvents) / float64(stats.TotalEvents)
		if warningRatio > 0.5 {
			score += 15
		} else if warningRatio > 0.25 {
			score += 5
		}
	}

	return score
}

func eventRiskScoreToLevel(score int) string {
	if score >= 80 {
		return shared.RiskCritical
	} else if score >= 60 {
		return shared.RiskHigh
	} else if score >= 30 {
		return shared.RiskMedium
	}
	return shared.RiskLow
}

func identifyTopIssues(stats *EventSummary) []string {
	var issues []string

	if stats.SecurityEvents > 0 {
		issues = append(issues, fmt.Sprintf("%d security events", stats.SecurityEvents))
	}
	if stats.OOMKilled > 0 {
		issues = append(issues, fmt.Sprintf("%d OOMKilled", stats.OOMKilled))
	}
	if stats.AuthFailures > 0 {
		issues = append(issues, fmt.Sprintf("%d auth failures", stats.AuthFailures))
	}
	if stats.AdmissionDenials > 0 {
		issues = append(issues, fmt.Sprintf("%d admission denials", stats.AdmissionDenials))
	}
	if stats.FailedScheduling > 10 {
		issues = append(issues, fmt.Sprintf("%d scheduling failures", stats.FailedScheduling))
	}

	return issues
}

func generateEventCommands(summaries []EventSummary) string {
	var lines []string

	lines = append(lines, "# ===========================================")
	lines = append(lines, "# Event Enumeration Commands")
	lines = append(lines, "# ===========================================")
	lines = append(lines, "")

	lines = append(lines, "# List all events cluster-wide:")
	lines = append(lines, "kubectl get events -A --sort-by='.lastTimestamp'")
	lines = append(lines, "")

	lines = append(lines, "# View events in a specific namespace:")
	for _, s := range summaries {
		lines = append(lines, fmt.Sprintf("kubectl get events -n %s --sort-by='.lastTimestamp'", s.Namespace))
	}
	lines = append(lines, "")

	lines = append(lines, "# Filter warning events only:")
	lines = append(lines, "kubectl get events -A --field-selector type=Warning")
	lines = append(lines, "")

	lines = append(lines, "# Watch events in real-time:")
	lines = append(lines, "kubectl get events -A --watch")
	lines = append(lines, "")

	lines = append(lines, "# Get detailed event output:")
	lines = append(lines, "kubectl get events -A -o wide")
	lines = append(lines, "")

	lines = append(lines, "# Filter events by reason:")
	lines = append(lines, "kubectl get events -A --field-selector reason=FailedScheduling")
	lines = append(lines, "kubectl get events -A --field-selector reason=OOMKilled")
	lines = append(lines, "kubectl get events -A --field-selector reason=FailedMount")
	lines = append(lines, "kubectl get events -A --field-selector reason=BackOff")
	lines = append(lines, "")

	lines = append(lines, "# Get events for a specific pod:")
	lines = append(lines, "kubectl get events -n <namespace> --field-selector involvedObject.name=<pod-name>")
	lines = append(lines, "")

	lines = append(lines, "# JSON output for parsing:")
	lines = append(lines, "kubectl get events -A -o json | jq '.items[] | select(.type==\"Warning\")'")
	lines = append(lines, "")

	lines = append(lines, "# ===========================================")
	lines = append(lines, "# Investigation Commands")
	lines = append(lines, "# ===========================================")
	lines = append(lines, "")

	lines = append(lines, "# Describe pod to see events and status:")
	lines = append(lines, "kubectl describe pod <pod-name> -n <namespace>")
	lines = append(lines, "")

	lines = append(lines, "# Check pod logs for OOMKilled containers:")
	lines = append(lines, "kubectl logs <pod-name> -n <namespace> --previous")
	lines = append(lines, "")

	lines = append(lines, "# Check node conditions:")
	lines = append(lines, "kubectl describe node <node-name> | grep -A 10 Conditions")
	lines = append(lines, "")

	lines = append(lines, "# Check resource usage:")
	lines = append(lines, "kubectl top pods -A")
	lines = append(lines, "kubectl top nodes")
	lines = append(lines, "")

	// Add namespace-specific commands for high-risk namespaces
	for _, s := range summaries {
		if s.RiskScore >= 60 {
			lines = append(lines, fmt.Sprintf("# High-risk namespace: %s (issues: %v)", s.Namespace, s.TopIssues))
			lines = append(lines, fmt.Sprintf("kubectl get events -n %s --field-selector type=Warning", s.Namespace))
			lines = append(lines, fmt.Sprintf("kubectl get pods -n %s -o wide", s.Namespace))
			lines = append(lines, "")
		}
	}

	return strings.Join(lines, "\n")
}

func generateEventTable(analyses []EventAnalysis, limit int, showAll bool) internal.TableFile {
	header := []string{"Namespace", "Kind", "Name", "Reason", "Type", "Count", "Category", "Last Seen", "Message"}
	var rows [][]string

	// Sort by risk score
	sort.Slice(analyses, func(i, j int) bool {
		return analyses[i].RiskScore > analyses[j].RiskScore
	})

	// Determine how many events to show
	count := len(analyses)
	if !showAll && limit > 0 && limit < count {
		count = limit
	}

	for i := 0; i < count; i++ {
		ev := analyses[i]
		rows = append(rows, []string{
			ev.Namespace,
			ev.Kind,
			ev.Name,
			ev.Reason,
			ev.Type,
			fmt.Sprintf("%d", ev.Count),
			ev.Category,
			ev.LastSeen.Format("2006-01-02 15:04"),
			ev.Message,
		})
	}

	return internal.TableFile{
		Name:   "Events",
		Header: header,
		Body:   rows,
	}
}

func generateSummaryTable(summaries []EventSummary) internal.TableFile {
	header := []string{"Namespace", "Total", "Warnings", "Security", "OOM", "Scheduling", "ImagePull", "Admission", "Auth"}
	var rows [][]string

	// Sort by risk score
	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].RiskScore > summaries[j].RiskScore
	})

	for _, s := range summaries {
		rows = append(rows, []string{
			s.Namespace,
			fmt.Sprintf("%d", s.TotalEvents),
			fmt.Sprintf("%d", s.WarningEvents),
			fmt.Sprintf("%d", s.SecurityEvents),
			fmt.Sprintf("%d", s.OOMKilled),
			fmt.Sprintf("%d", s.FailedScheduling),
			fmt.Sprintf("%d", s.ImagePullFailures),
			fmt.Sprintf("%d", s.AdmissionDenials),
			fmt.Sprintf("%d", s.AuthFailures),
		})
	}

	return internal.TableFile{
		Name:   "Event-Summary",
		Header: header,
		Body:   rows,
	}
}

// filterEventsBySearch filters events by a search query (case-insensitive)
// Searches across: namespace, object name, reason, message, involved object kind
func filterEventsBySearch(events []corev1.Event, query string) []corev1.Event {
	if query == "" {
		return events
	}

	query = strings.ToLower(query)
	var filtered []corev1.Event

	for _, event := range events {
		// Check multiple fields for the search query
		if strings.Contains(strings.ToLower(event.Namespace), query) ||
			strings.Contains(strings.ToLower(event.InvolvedObject.Name), query) ||
			strings.Contains(strings.ToLower(event.InvolvedObject.Kind), query) ||
			strings.Contains(strings.ToLower(event.Reason), query) ||
			strings.Contains(strings.ToLower(event.Message), query) ||
			strings.Contains(strings.ToLower(event.Source.Component), query) ||
			strings.Contains(strings.ToLower(event.Source.Host), query) ||
			strings.Contains(strings.ToLower(event.Type), query) {
			filtered = append(filtered, event)
		}
	}

	return filtered
}

