package domainwidedelegationservice

import (
	"context"
	"fmt"
	"strings"

	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/internal/gcp/sdk"
	iam "google.golang.org/api/iam/v1"
)

type DomainWideDelegationService struct{
	session *gcpinternal.SafeSession
}

func New() *DomainWideDelegationService {
	return &DomainWideDelegationService{}
}

func NewWithSession(session *gcpinternal.SafeSession) *DomainWideDelegationService {
	return &DomainWideDelegationService{
		session: session,
	}
}

// DWDServiceAccount represents a service account with domain-wide delegation
type DWDServiceAccount struct {
	Email           string        `json:"email"`
	ProjectID       string        `json:"projectId"`
	UniqueID        string        `json:"uniqueId"`
	DisplayName     string        `json:"displayName"`
	OAuth2ClientID  string        `json:"oauth2ClientId"`
	DWDEnabled      bool          `json:"dwdEnabled"`
	Keys            []KeyInfo     `json:"keys"`
	Description     string        `json:"description"`
	RiskLevel       string        `json:"riskLevel"`
	RiskReasons     []string      `json:"riskReasons"`
	ExploitCommands []string      `json:"exploitCommands"`
	WorkspaceScopes []string      `json:"workspaceScopes"` // Common Workspace scopes to try
}

// KeyInfo represents a service account key
type KeyInfo struct {
	KeyID           string `json:"keyId"`
	CreatedAt       string `json:"createdAt"`
	ExpiresAt       string `json:"expiresAt"`
	KeyAlgorithm    string `json:"keyAlgorithm"`
	KeyType         string `json:"keyType"`
}

// Common Google Workspace OAuth scopes that DWD service accounts might have
var CommonWorkspaceScopes = []string{
	"https://www.googleapis.com/auth/gmail.readonly",
	"https://www.googleapis.com/auth/gmail.send",
	"https://www.googleapis.com/auth/gmail.modify",
	"https://www.googleapis.com/auth/drive",
	"https://www.googleapis.com/auth/drive.readonly",
	"https://www.googleapis.com/auth/calendar",
	"https://www.googleapis.com/auth/calendar.readonly",
	"https://www.googleapis.com/auth/admin.directory.user.readonly",
	"https://www.googleapis.com/auth/admin.directory.group.readonly",
	"https://www.googleapis.com/auth/spreadsheets",
	"https://www.googleapis.com/auth/contacts.readonly",
	"https://mail.google.com/",
}

// getIAMService returns an IAM service client using cached session if available
func (s *DomainWideDelegationService) getIAMService(ctx context.Context) (*iam.Service, error) {
	if s.session != nil {
		return sdk.CachedGetIAMService(ctx, s.session)
	}
	return iam.NewService(ctx)
}

// GetDWDServiceAccounts finds service accounts that may have domain-wide delegation
func (s *DomainWideDelegationService) GetDWDServiceAccounts(projectID string) ([]DWDServiceAccount, error) {
	ctx := context.Background()
	service, err := s.getIAMService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "iam.googleapis.com")
	}

	var dwdAccounts []DWDServiceAccount

	// List all service accounts
	parent := fmt.Sprintf("projects/%s", projectID)
	resp, err := service.Projects.ServiceAccounts.List(parent).Context(ctx).Do()
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "iam.googleapis.com")
	}

	for _, sa := range resp.Accounts {
		// Check if the service account has an OAuth2 client ID (required for DWD)
		// The OAuth2ClientId field is populated when DWD is enabled
		dwdEnabled := sa.Oauth2ClientId != ""

		account := DWDServiceAccount{
			Email:           sa.Email,
			ProjectID:       projectID,
			UniqueID:        sa.UniqueId,
			DisplayName:     sa.DisplayName,
			OAuth2ClientID:  sa.Oauth2ClientId,
			DWDEnabled:      dwdEnabled,
			Description:     sa.Description,
			Keys:            []KeyInfo{},
			RiskReasons:     []string{},
			ExploitCommands: []string{},
			WorkspaceScopes: CommonWorkspaceScopes,
		}

		// Check for keys
		keysResp, err := service.Projects.ServiceAccounts.Keys.List(
			fmt.Sprintf("projects/%s/serviceAccounts/%s", projectID, sa.Email),
		).Context(ctx).Do()
		if err == nil {
			// Collect user-managed keys (not system-managed)
			for _, key := range keysResp.Keys {
				if key.KeyType == "USER_MANAGED" {
					// Extract key ID from full name (projects/.../keys/KEY_ID)
					keyID := key.Name
					if parts := strings.Split(key.Name, "/"); len(parts) > 0 {
						keyID = parts[len(parts)-1]
					}
					account.Keys = append(account.Keys, KeyInfo{
						KeyID:        keyID,
						CreatedAt:    key.ValidAfterTime,
						ExpiresAt:    key.ValidBeforeTime,
						KeyAlgorithm: key.KeyAlgorithm,
						KeyType:      key.KeyType,
					})
				}
			}
		}

		// Analyze risk
		account.RiskLevel, account.RiskReasons = s.analyzeRisk(account)

		// Generate exploit commands
		account.ExploitCommands = s.generateExploitCommands(account)

		// Only include accounts with DWD or that look like they might be used for it
		if dwdEnabled || s.looksLikeDWDAccount(account) {
			dwdAccounts = append(dwdAccounts, account)
		}
	}

	return dwdAccounts, nil
}

// looksLikeDWDAccount checks if a service account might be used for DWD based on naming
func (s *DomainWideDelegationService) looksLikeDWDAccount(account DWDServiceAccount) bool {
	emailLower := strings.ToLower(account.Email)
	descLower := strings.ToLower(account.Description)
	nameLower := strings.ToLower(account.DisplayName)

	// Common naming patterns for DWD service accounts
	dwdPatterns := []string{
		"delegation", "dwd", "workspace", "gsuite", "admin",
		"gmail", "drive", "calendar", "directory", "impersonat",
	}

	for _, pattern := range dwdPatterns {
		if strings.Contains(emailLower, pattern) ||
			strings.Contains(descLower, pattern) ||
			strings.Contains(nameLower, pattern) {
			return true
		}
	}

	return false
}

func (s *DomainWideDelegationService) analyzeRisk(account DWDServiceAccount) (string, []string) {
	var reasons []string
	score := 0

	if account.DWDEnabled {
		reasons = append(reasons, "Domain-wide delegation ENABLED (OAuth2 Client ID present)")
		score += 3
	}

	hasKeys := len(account.Keys) > 0
	if hasKeys {
		reasons = append(reasons, fmt.Sprintf("Has %d user-managed key(s) - can be used for impersonation", len(account.Keys)))
		score += 2
	}

	if account.DWDEnabled && hasKeys {
		reasons = append(reasons, "CRITICAL: DWD enabled + keys exist = can impersonate any Workspace user!")
		score += 2
	}

	// Check for suspicious naming
	if s.looksLikeDWDAccount(account) && !account.DWDEnabled {
		reasons = append(reasons, "Name suggests DWD purpose but OAuth2 Client ID not detected")
		score += 1
	}

	if score >= 5 {
		return "CRITICAL", reasons
	} else if score >= 3 {
		return "HIGH", reasons
	} else if score >= 2 {
		return "MEDIUM", reasons
	} else if score >= 1 {
		return "LOW", reasons
	}
	return "INFO", reasons
}

func (s *DomainWideDelegationService) generateExploitCommands(account DWDServiceAccount) []string {
	var commands []string

	if !account.DWDEnabled {
		commands = append(commands,
			"# DWD not confirmed - OAuth2 Client ID not present",
			"# Check Google Admin Console: Security > API Controls > Domain-wide Delegation",
		)
		return commands
	}

	commands = append(commands,
		fmt.Sprintf("# Domain-Wide Delegation Service Account: %s", account.Email),
		fmt.Sprintf("# OAuth2 Client ID: %s", account.OAuth2ClientID),
		"",
		"# To exploit DWD, you need:",
		"# 1. A key file for this service account",
		"# 2. The email of a Workspace user to impersonate",
		"# 3. Knowledge of which scopes are authorized in Admin Console",
		"",
	)

	if len(account.Keys) > 0 {
		commands = append(commands,
			"# Create a new key (if you have iam.serviceAccountKeys.create permission):",
			fmt.Sprintf("gcloud iam service-accounts keys create /tmp/key.json --iam-account=%s", account.Email),
			"",
		)
	}

	commands = append(commands,
		"# Python exploit example:",
		"# from google.oauth2 import service_account",
		"# from googleapiclient.discovery import build",
		"#",
		"# creds = service_account.Credentials.from_service_account_file(",
		"#     'key.json',",
		fmt.Sprintf("#     scopes=['https://www.googleapis.com/auth/gmail.readonly'],"),
		"#     subject='admin@yourdomain.com'  # User to impersonate",
		"# )",
		"#",
		"# gmail = build('gmail', 'v1', credentials=creds)",
		"# messages = gmail.users().messages().list(userId='me').execute()",
		"",
		"# Common scopes to test (must be authorized in Admin Console):",
	)

	for _, scope := range CommonWorkspaceScopes[:5] { // First 5 most useful scopes
		commands = append(commands, fmt.Sprintf("# - %s", scope))
	}

	return commands
}
