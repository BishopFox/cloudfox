package commands

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
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

  cloudfox kubernetes events`,
	Run: ListEvents,
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

const (
	EventRiskCritical = "CRITICAL"
	EventRiskHigh     = "HIGH"
	EventRiskMedium   = "MEDIUM"
	EventRiskLow      = "LOW"
)

func ListEvents(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Analyzing events for %s", globals.ClusterName), globals.K8S_EVENTS_MODULE_NAME)

	clientset := config.GetClientOrExit()

	// Fetch events from all namespaces
	events, err := clientset.CoreV1().Events(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error fetching Events: %v", err), globals.K8S_EVENTS_MODULE_NAME)
		return
	}

	var eventAnalyses []EventAnalysis
	var securityEvents []string
	var failedScheduling []string
	var imagePullFailures []string
	var oomKilled []string
	var volumeFailures []string
	var admissionDenials []string
	var authFailures []string

	namespaceStats := make(map[string]*EventSummary)

	// Analyze each event
	for _, event := range events.Items {
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

		// Categorize for loot files
		if analysis.Category == "Security" {
			stats.SecurityEvents++
			securityEvents = append(securityEvents, formatSecurityEvent(&analysis))
		}

		if strings.Contains(analysis.Reason, "FailedScheduling") {
			stats.FailedScheduling++
			failedScheduling = append(failedScheduling, formatFailedScheduling(&analysis))
		}

		if strings.Contains(analysis.Reason, "Failed") && strings.Contains(strings.ToLower(analysis.Message), "image") {
			stats.ImagePullFailures++
			imagePullFailures = append(imagePullFailures, formatImagePullFailure(&analysis))
		}

		if strings.Contains(analysis.Reason, "OOMKilled") {
			stats.OOMKilled++
			oomKilled = append(oomKilled, formatOOMKilled(&analysis))
		}

		if strings.Contains(analysis.Reason, "FailedMount") || strings.Contains(analysis.Reason, "FailedAttachVolume") {
			stats.VolumeMountFails++
			volumeFailures = append(volumeFailures, formatVolumeFailure(&analysis))
		}

		if strings.Contains(strings.ToLower(analysis.Message), "admission") && strings.Contains(strings.ToLower(analysis.Message), "denied") {
			stats.AdmissionDenials++
			admissionDenials = append(admissionDenials, formatAdmissionDenial(&analysis))
		}

		if strings.Contains(strings.ToLower(analysis.Reason), "unauthorized") || strings.Contains(strings.ToLower(analysis.Reason), "forbidden") {
			stats.AuthFailures++
			authFailures = append(authFailures, formatAuthFailure(&analysis))
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

	// Generate loot files
	lootFiles := []internal.LootFile{
		{
			Name:     "Event-Enum",
			Contents: formatEventEnum(eventAnalyses),
		},
		{
			Name:     "Security-Events",
			Contents: strings.Join(securityEvents, "\n"),
		},
		{
			Name:     "Failed-Scheduling",
			Contents: strings.Join(failedScheduling, "\n"),
		},
		{
			Name:     "ImagePull-Failures",
			Contents: strings.Join(imagePullFailures, "\n"),
		},
		{
			Name:     "OOM-Killed",
			Contents: strings.Join(oomKilled, "\n"),
		},
		{
			Name:     "Volume-Failures",
			Contents: strings.Join(volumeFailures, "\n"),
		},
		{
			Name:     "Admission-Denials",
			Contents: strings.Join(admissionDenials, "\n"),
		},
		{
			Name:     "Auth-Failures",
			Contents: strings.Join(authFailures, "\n"),
		},
		{
			Name:     "Remediation-Guide",
			Contents: generateEventRemediationGuide(summaries),
		},
	}

	// Generate tables
	eventTable := generateEventTable(eventAnalyses)
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
	if len(events.Items) > 0 {
		securityCount := len(securityEvents)
		warningCount := 0
		for _, event := range events.Items {
			if event.Type == "Warning" {
				warningCount++
			}
		}
		logger.InfoM(fmt.Sprintf("%d events analyzed | Warnings: %d | Security: %d | OOMKilled: %d | Namespaces: %d",
			len(events.Items), warningCount, securityCount, len(oomKilled), len(summaries)),
			globals.K8S_EVENTS_MODULE_NAME)
	} else {
		logger.InfoM("No events found", globals.K8S_EVENTS_MODULE_NAME)
	}
}

func categorizeEvent(event *corev1.Event) (category string, severity string, securityIssue string) {
	reason := strings.ToLower(event.Reason)
	message := strings.ToLower(event.Message)

	// Security-related events
	if strings.Contains(reason, "unauthorized") || strings.Contains(reason, "forbidden") {
		return "Security", EventRiskCritical, "Authentication/Authorization failure"
	}
	if strings.Contains(message, "admission") && strings.Contains(message, "denied") {
		return "Security", EventRiskHigh, "Admission policy violation"
	}
	if strings.Contains(reason, "failedcreate") && strings.Contains(message, "forbidden") {
		return "Security", EventRiskHigh, "RBAC permission denied"
	}
	if strings.Contains(message, "securitycontext") || strings.Contains(message, "podsecuritypolicy") {
		return "Security", EventRiskHigh, "Pod security policy violation"
	}

	// Resource exhaustion (DoS indicators)
	if strings.Contains(reason, "oomkilled") {
		return "Resource", EventRiskHigh, "Out of memory (potential DoS)"
	}
	if strings.Contains(reason, "evicted") {
		return "Resource", EventRiskMedium, "Pod evicted due to resource pressure"
	}
	if strings.Contains(reason, "failedscheduling") {
		if strings.Contains(message, "insufficient") {
			return "Resource", EventRiskMedium, "Insufficient cluster resources"
		}
		return "Scheduling", EventRiskMedium, "Pod scheduling failure"
	}

	// Image and registry issues
	if strings.Contains(reason, "failed") && strings.Contains(message, "image") {
		if strings.Contains(message, "unauthorized") || strings.Contains(message, "authentication") {
			return "Security", EventRiskHigh, "Image registry authentication failure"
		}
		return "Image", EventRiskMedium, "Image pull failure"
	}

	// Volume and storage issues
	if strings.Contains(reason, "failedmount") || strings.Contains(reason, "failedattachvolume") {
		if strings.Contains(message, "permission") || strings.Contains(message, "denied") {
			return "Security", EventRiskHigh, "Volume mount permission denied"
		}
		return "Volume", EventRiskMedium, "Volume mount failure"
	}

	// Probe failures
	if strings.Contains(reason, "unhealthy") {
		return "Health", EventRiskLow, "Liveness/readiness probe failure"
	}

	// Node issues
	if strings.Contains(reason, "nodenotready") {
		return "Node", EventRiskHigh, "Node not ready"
	}

	// Default
	if event.Type == "Warning" {
		return "General", EventRiskLow, "Warning event"
	}
	return "Info", EventRiskLow, "Informational"
}

func calculateEventRiskScore(analysis *EventAnalysis, event *corev1.Event) int {
	score := 0

	// Base score by severity
	switch analysis.Severity {
	case EventRiskCritical:
		score += 40
	case EventRiskHigh:
		score += 30
	case EventRiskMedium:
		score += 20
	case EventRiskLow:
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
		return EventRiskCritical
	} else if score >= 60 {
		return EventRiskHigh
	} else if score >= 30 {
		return EventRiskMedium
	}
	return EventRiskLow
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

// Formatting functions
func formatSecurityEvent(analysis *EventAnalysis) string {
	return fmt.Sprintf("[%s] %s | %s/%s | Reason: %s | Issue: %s | Count: %d | Last: %s",
		analysis.Severity, analysis.Namespace, analysis.Kind, analysis.Name,
		analysis.Reason, analysis.SecurityIssue, analysis.Count, analysis.LastSeen.Format(time.RFC3339))
}

func formatFailedScheduling(analysis *EventAnalysis) string {
	return fmt.Sprintf("[SCHEDULING] %s/%s/%s | Reason: %s | Count: %d | Message: %s",
		analysis.Namespace, analysis.Kind, analysis.Name, analysis.Reason, analysis.Count,
		truncateString(analysis.Message, 100))
}

func formatImagePullFailure(analysis *EventAnalysis) string {
	return fmt.Sprintf("[IMAGE] %s/%s | Count: %d | Message: %s | Last: %s",
		analysis.Namespace, analysis.Name, analysis.Count,
		truncateString(analysis.Message, 120), analysis.LastSeen.Format(time.RFC3339))
}

func formatOOMKilled(analysis *EventAnalysis) string {
	return fmt.Sprintf("[OOM] %s/%s/%s | Count: %d | First: %s | Last: %s | Message: %s",
		analysis.Namespace, analysis.Kind, analysis.Name, analysis.Count,
		analysis.FirstSeen.Format(time.RFC3339), analysis.LastSeen.Format(time.RFC3339),
		truncateString(analysis.Message, 80))
}

func formatVolumeFailure(analysis *EventAnalysis) string {
	return fmt.Sprintf("[VOLUME] %s/%s | Reason: %s | Count: %d | Message: %s",
		analysis.Namespace, analysis.Name, analysis.Reason, analysis.Count,
		truncateString(analysis.Message, 100))
}

func formatAdmissionDenial(analysis *EventAnalysis) string {
	return fmt.Sprintf("[ADMISSION] %s/%s/%s | Count: %d | Message: %s | Last: %s",
		analysis.Namespace, analysis.Kind, analysis.Name, analysis.Count,
		truncateString(analysis.Message, 120), analysis.LastSeen.Format(time.RFC3339))
}

func formatAuthFailure(analysis *EventAnalysis) string {
	return fmt.Sprintf("[AUTH] %s/%s/%s | Reason: %s | Count: %d | Message: %s",
		analysis.Namespace, analysis.Kind, analysis.Name, analysis.Reason, analysis.Count,
		truncateString(analysis.Message, 100))
}

func formatEventEnum(analyses []EventAnalysis) string {
	var lines []string
	lines = append(lines, "=== Kubernetes Events Security Analysis ===\n")

	// Group by category
	categories := make(map[string][]EventAnalysis)
	for _, analysis := range analyses {
		categories[analysis.Category] = append(categories[analysis.Category], analysis)
	}

	for category, events := range categories {
		lines = append(lines, fmt.Sprintf("\n## %s Events (%d)\n", category, len(events)))
		for _, ev := range events {
			lines = append(lines, fmt.Sprintf("  [%s] %s/%s/%s", ev.Severity, ev.Namespace, ev.Kind, ev.Name))
			lines = append(lines, fmt.Sprintf("    Reason: %s (Count: %d)", ev.Reason, ev.Count))
			lines = append(lines, fmt.Sprintf("    Message: %s", truncateString(ev.Message, 120)))
			if ev.SecurityIssue != "" {
				lines = append(lines, fmt.Sprintf("    Security Issue: %s", ev.SecurityIssue))
			}
			lines = append(lines, fmt.Sprintf("    Last Seen: %s", ev.LastSeen.Format(time.RFC3339)))
			lines = append(lines, "")
		}
	}

	return strings.Join(lines, "\n")
}

func generateEventRemediationGuide(summaries []EventSummary) string {
	var lines []string
	lines = append(lines, "=== Events Security Remediation Guide ===\n")

	lines = append(lines, "# View recent events in a namespace:")
	lines = append(lines, "kubectl get events -n <namespace> --sort-by='.lastTimestamp'")
	lines = append(lines, "")

	lines = append(lines, "# Filter warning events:")
	lines = append(lines, "kubectl get events -n <namespace> --field-selector type=Warning")
	lines = append(lines, "")

	lines = append(lines, "# Watch events in real-time:")
	lines = append(lines, "kubectl get events -n <namespace> --watch")
	lines = append(lines, "")

	lines = append(lines, "# Fix OOMKilled pods - increase memory limits:")
	lines = append(lines, "kubectl set resources deployment/<name> -n <namespace> --limits=memory=512Mi --requests=memory=256Mi")
	lines = append(lines, "")

	lines = append(lines, "# Fix ImagePullBackOff - create image pull secret:")
	lines = append(lines, "kubectl create secret docker-registry <secret-name> \\")
	lines = append(lines, "  --docker-server=<registry> \\")
	lines = append(lines, "  --docker-username=<username> \\")
	lines = append(lines, "  --docker-password=<password> -n <namespace>")
	lines = append(lines, "")

	lines = append(lines, "# Fix FailedScheduling - add node resources or adjust pod requests:")
	lines = append(lines, "kubectl describe pod <pod-name> -n <namespace>  # Check scheduling issues")
	lines = append(lines, "")

	for _, summary := range summaries {
		if summary.RiskScore >= 60 {
			lines = append(lines, fmt.Sprintf("# High-risk namespace: %s (Score: %d)", summary.Namespace, summary.RiskScore))
			for _, issue := range summary.TopIssues {
				lines = append(lines, fmt.Sprintf("#   - %s", issue))
			}
			lines = append(lines, "")
		}
	}

	return strings.Join(lines, "\n")
}

func generateEventTable(analyses []EventAnalysis) internal.TableFile {
	header := []string{"Namespace", "Kind", "Name", "Reason", "Type", "Count", "Category", "Severity", "Last Seen", "Score"}
	var rows [][]string

	// Sort by risk score
	sort.Slice(analyses, func(i, j int) bool {
		return analyses[i].RiskScore > analyses[j].RiskScore
	})

	// Limit to top 500 events
	limit := 500
	if len(analyses) < limit {
		limit = len(analyses)
	}

	for i := 0; i < limit; i++ {
		ev := analyses[i]
		rows = append(rows, []string{
			ev.Namespace,
			ev.Kind,
			truncateString(ev.Name, 40),
			ev.Reason,
			ev.Type,
			fmt.Sprintf("%d", ev.Count),
			ev.Category,
			ev.Severity,
			ev.LastSeen.Format("2006-01-02 15:04"),
			fmt.Sprintf("%d", ev.RiskScore),
		})
	}

	return internal.TableFile{
		Name:   "Events",
		Header: header,
		Body:   rows,
	}
}

func generateSummaryTable(summaries []EventSummary) internal.TableFile {
	header := []string{"Namespace", "Total", "Warnings", "Security", "OOM", "Scheduling", "ImagePull", "Admission", "Auth", "Risk", "Score"}
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
			s.RiskLevel,
			fmt.Sprintf("%d", s.RiskScore),
		})
	}

	return internal.TableFile{
		Name:   "Event-Summary",
		Header: header,
		Body:   rows,
	}
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
