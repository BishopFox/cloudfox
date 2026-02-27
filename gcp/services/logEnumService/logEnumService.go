package logenumservice

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/BishopFox/cloudfox/gcp/shared"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	logging "google.golang.org/api/logging/v2"
)

type LogEnumService struct {
	session *gcpinternal.SafeSession
}

func New() *LogEnumService {
	return &LogEnumService{}
}

func NewWithSession(session *gcpinternal.SafeSession) *LogEnumService {
	return &LogEnumService{session: session}
}

// SensitiveLogEntry represents a log entry containing potentially sensitive content.
type SensitiveLogEntry struct {
	ProjectID    string `json:"projectId"`
	LogName      string `json:"logName"`
	Timestamp    string `json:"timestamp"`
	Category     string `json:"category"`
	RiskLevel    string `json:"riskLevel"`
	Description  string `json:"description"`
	Snippet      string `json:"snippet"`
	ResourceType string `json:"resourceType"`
	InsertID     string `json:"insertId"`
}

// getLoggingService returns a Logging service client.
func (s *LogEnumService) getLoggingService(ctx context.Context) (*logging.Service, error) {
	// The REST API client doesn't use the same cached SDK pattern.
	// Create directly since the logging SDK client isn't session-aware in the same way.
	return logging.NewService(ctx)
}

// EnumerateSensitiveLogs reads log entries and checks for sensitive content.
func (s *LogEnumService) EnumerateSensitiveLogs(projectID string, hours int, maxEntries int, logNameFilter string) ([]SensitiveLogEntry, error) {
	ctx := context.Background()

	service, err := s.getLoggingService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "logging.googleapis.com")
	}

	patterns := shared.GetContentPatterns()

	// Build the filter
	cutoff := time.Now().UTC().Add(-time.Duration(hours) * time.Hour)
	filter := fmt.Sprintf("timestamp >= \"%s\"", cutoff.Format(time.RFC3339))
	if logNameFilter != "" {
		filter += fmt.Sprintf(" AND logName = \"projects/%s/logs/%s\"", projectID, logNameFilter)
	}

	var sensitiveEntries []SensitiveLogEntry
	totalProcessed := 0
	pageToken := ""

	for {
		if maxEntries > 0 && totalProcessed >= maxEntries {
			break
		}

		pageSize := int64(1000)
		remaining := maxEntries - totalProcessed
		if maxEntries > 0 && remaining < int(pageSize) {
			pageSize = int64(remaining)
		}

		req := &logging.ListLogEntriesRequest{
			ResourceNames: []string{fmt.Sprintf("projects/%s", projectID)},
			Filter:        filter,
			OrderBy:       "timestamp desc",
			PageSize:      pageSize,
			PageToken:     pageToken,
		}

		resp, err := service.Entries.List(req).Context(ctx).Do()
		if err != nil {
			return nil, gcpinternal.ParseGCPError(err, "logging.googleapis.com")
		}

		for _, entry := range resp.Entries {
			totalProcessed++

			// Extract text content from the entry
			text := extractEntryText(entry)
			if text == "" {
				continue
			}

			matches := shared.MatchContent(text, patterns)
			for _, match := range matches {
				// Extract short log name
				logName := entry.LogName
				resourceType := ""
				if entry.Resource != nil {
					resourceType = entry.Resource.Type
				}

				sensitiveEntries = append(sensitiveEntries, SensitiveLogEntry{
					ProjectID:    projectID,
					LogName:      logName,
					Timestamp:    entry.Timestamp,
					Category:     match.Category,
					RiskLevel:    match.RiskLevel,
					Description:  match.Description,
					Snippet:      truncate(match.Snippet, 200),
					ResourceType: resourceType,
					InsertID:     entry.InsertId,
				})
				break // One match per entry is sufficient
			}
		}

		pageToken = resp.NextPageToken
		if pageToken == "" {
			break
		}
	}

	return sensitiveEntries, nil
}

// extractEntryText pulls all text content from a log entry for scanning.
func extractEntryText(entry *logging.LogEntry) string {
	if entry == nil {
		return ""
	}

	var text string

	// textPayload is the simplest
	if entry.TextPayload != "" {
		text += entry.TextPayload + "\n"
	}

	// jsonPayload - serialize to string for scanning
	if entry.JsonPayload != nil {
		jsonBytes, err := json.Marshal(entry.JsonPayload)
		if err == nil {
			text += string(jsonBytes) + "\n"
		}
	}

	// protoPayload - serialize to string for scanning
	if entry.ProtoPayload != nil {
		jsonBytes, err := json.Marshal(entry.ProtoPayload)
		if err == nil {
			text += string(jsonBytes) + "\n"
		}
	}

	return text
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
