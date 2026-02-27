package gcpinternal

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
)

// CommonScopes defines the common OAuth scopes used by GCP services
var CommonScopes = []string{
	"https://www.googleapis.com/auth/cloud-platform",           // Full GCP access
	"https://www.googleapis.com/auth/cloud-platform.read-only", // Read-only GCP access
	"https://www.googleapis.com/auth/compute",                  // Compute Engine access
	"https://www.googleapis.com/auth/devstorage.full_control",  // Cloud Storage full access
}

// SafeSession provides thread-safe GCP authentication with token caching and auto-refresh
type SafeSession struct {
	mu            sync.Mutex
	tokenSource   oauth2.TokenSource
	currentToken  *oauth2.Token
	tokens        map[string]*oauth2.Token // scope -> token
	sessionExpiry time.Time                // When the current token expires
	monitoring    bool                     // Whether background monitoring is active
	stopMonitor   chan struct{}            // Signal to stop monitoring
	refreshBuffer time.Duration            // How early to refresh before expiry (default 5 min)

	// Identity info
	email       string
	projectID   string
	accountType string // "user" or "serviceAccount"
}

// GCPCredentialInfo holds information about the current credential
type GCPCredentialInfo struct {
	Email       string `json:"email"`
	AccountType string `json:"account_type"` // user, serviceAccount
	ProjectID   string `json:"project_id"`
	Scopes      []string
}

// StaticTokenSource wraps a token for use with GCP clients
type StaticTokenSource struct {
	StaticToken *oauth2.Token
}

// Token returns the static token (implements oauth2.TokenSource)
func (s *StaticTokenSource) Token() (*oauth2.Token, error) {
	return s.StaticToken, nil
}

// NewSafeSession initializes a session using Application Default Credentials
// and prefetches tokens for common scopes
func NewSafeSession(ctx context.Context) (*SafeSession, error) {
	// Check if gcloud is authenticated
	if !IsSessionValid() {
		return nil, fmt.Errorf("GCP session invalid; run 'gcloud auth application-default login' or 'gcloud auth login'")
	}

	// Create token source from ADC
	ts, err := google.DefaultTokenSource(ctx, CommonScopes...)
	if err != nil {
		return nil, fmt.Errorf("failed to create token source: %w", err)
	}

	ss := &SafeSession{
		tokenSource:   ts,
		tokens:        make(map[string]*oauth2.Token),
		refreshBuffer: 5 * time.Minute,
		stopMonitor:   make(chan struct{}),
	}

	// Get initial token and extract expiry
	token, err := ts.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to get initial token: %w", err)
	}
	ss.currentToken = token
	ss.sessionExpiry = token.Expiry

	// Get identity info
	info, err := ss.getCurrentIdentity(ctx)
	if err == nil {
		ss.email = info.Email
		ss.accountType = info.AccountType
		ss.projectID = info.ProjectID
	}

	// Cache the token for the default scope
	ss.tokens["https://www.googleapis.com/auth/cloud-platform"] = token

	return ss, nil
}

// NewSmartSession creates a session with automatic monitoring and refresh
func NewSmartSession(ctx context.Context) (*SafeSession, error) {
	ss, err := NewSafeSession(ctx)
	if err != nil {
		return nil, err
	}

	// Start background monitoring
	ss.StartMonitoring(ctx)

	return ss, nil
}

// ------------------------- TOKEN METHODS -------------------------

// GetToken returns a valid access token, refreshing if necessary
func (s *SafeSession) GetToken(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getTokenUnlocked(ctx)
}

// getTokenUnlocked returns a token without locking (caller must hold lock)
func (s *SafeSession) getTokenUnlocked(ctx context.Context) (string, error) {
	// Check if current token is still valid
	if s.currentToken != nil && s.currentToken.Valid() {
		return s.currentToken.AccessToken, nil
	}

	// Refresh the token
	token, err := s.tokenSource.Token()
	if err != nil {
		return "", fmt.Errorf("failed to refresh token: %w", err)
	}

	s.currentToken = token
	s.sessionExpiry = token.Expiry

	return token.AccessToken, nil
}

// GetTokenForScope returns a token for a specific OAuth scope
func (s *SafeSession) GetTokenForScope(ctx context.Context, scope string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check cache first
	if tok, ok := s.tokens[scope]; ok && tok.Valid() {
		return tok.AccessToken, nil
	}

	// Get a new token source for this scope
	ts, err := google.DefaultTokenSource(ctx, scope)
	if err != nil {
		return "", fmt.Errorf("failed to create token source for scope %s: %w", scope, err)
	}

	token, err := ts.Token()
	if err != nil {
		return "", fmt.Errorf("failed to get token for scope %s: %w", scope, err)
	}

	// Cache the token
	s.tokens[scope] = token

	return token.AccessToken, nil
}

// GetTokenSource returns the underlying token source for use with GCP clients
func (s *SafeSession) GetTokenSource() oauth2.TokenSource {
	return s.tokenSource
}

// GetClientOption returns a client option for use with GCP API clients
func (s *SafeSession) GetClientOption() option.ClientOption {
	return option.WithTokenSource(s.tokenSource)
}

// GetTokenWithRetry attempts to get a token with automatic retry on failure
func (s *SafeSession) GetTokenWithRetry(ctx context.Context) (string, error) {
	token, err := s.GetToken(ctx)
	if err != nil {
		// Try to refresh session and retry once
		if refreshErr := s.RefreshSession(ctx); refreshErr == nil {
			token, err = s.GetToken(ctx)
		}
	}
	return token, err
}

// ------------------------- SESSION MANAGEMENT -------------------------

// Ensure validates or refreshes the current session
func (s *SafeSession) Ensure(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.currentToken != nil && s.currentToken.Valid() {
		return nil
	}

	// Try to get a new token
	token, err := s.tokenSource.Token()
	if err != nil {
		return fmt.Errorf("GCP session invalid or expired: %w", err)
	}

	s.currentToken = token
	s.sessionExpiry = token.Expiry
	return nil
}

// IsSessionExpired checks if the session has expired or will expire soon
func (s *SafeSession) IsSessionExpired() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.sessionExpiry.IsZero() {
		return false
	}

	// Consider expired if within refresh buffer
	return time.Now().Add(s.refreshBuffer).After(s.sessionExpiry)
}

// RefreshSession refreshes the token and clears the cache
func (s *SafeSession) RefreshSession(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if gcloud session is still valid
	if !IsSessionValid() {
		return fmt.Errorf("GCP session expired; please run 'gcloud auth login' or 'gcloud auth application-default login'")
	}

	// Create new token source
	ts, err := google.DefaultTokenSource(ctx, CommonScopes...)
	if err != nil {
		return fmt.Errorf("failed to create token source: %w", err)
	}
	s.tokenSource = ts

	// Get fresh token
	token, err := ts.Token()
	if err != nil {
		return fmt.Errorf("failed to get fresh token: %w", err)
	}

	s.currentToken = token
	s.sessionExpiry = token.Expiry

	// Clear token cache
	s.tokens = make(map[string]*oauth2.Token)
	s.tokens["https://www.googleapis.com/auth/cloud-platform"] = token

	return nil
}

// ------------------------- MONITORING -------------------------

// StartMonitoring begins background monitoring of session health
func (s *SafeSession) StartMonitoring(ctx context.Context) {
	s.mu.Lock()
	if s.monitoring {
		s.mu.Unlock()
		return
	}
	s.monitoring = true
	s.mu.Unlock()

	go s.monitorSession(ctx)
}

// StopMonitoring stops the background session monitor
func (s *SafeSession) StopMonitoring() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.monitoring {
		return
	}

	s.monitoring = false
	close(s.stopMonitor)
}

// monitorSession runs in background to monitor and refresh session
func (s *SafeSession) monitorSession(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopMonitor:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			if s.IsSessionExpired() {
				if err := s.RefreshSession(ctx); err != nil {
					fmt.Printf("smart session: auto-refresh failed: %v\n", err)
					fmt.Println("smart session: please run 'gcloud auth login' to re-authenticate")
				}
			}
		}
	}
}

// ------------------------- IDENTITY INFO -------------------------

// GetEmail returns the email of the authenticated identity
func (s *SafeSession) GetEmail() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.email
}

// GetAccountType returns the type of account (user or serviceAccount)
func (s *SafeSession) GetAccountType() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.accountType
}

// GetProjectID returns the default project ID
func (s *SafeSession) GetProjectID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.projectID
}

// GetSessionExpiry returns when the current token expires
func (s *SafeSession) GetSessionExpiry() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessionExpiry
}

// getCurrentIdentity retrieves identity info from gcloud
func (s *SafeSession) getCurrentIdentity(ctx context.Context) (*GCPCredentialInfo, error) {
	// Try gcloud auth list to get current account
	out, err := exec.CommandContext(ctx, "gcloud", "auth", "list", "--filter=status:ACTIVE", "--format=json").Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get gcloud auth list: %w", err)
	}

	var accounts []struct {
		Account string `json:"account"`
		Status  string `json:"status"`
	}
	if err := json.Unmarshal(out, &accounts); err != nil {
		return nil, fmt.Errorf("failed to parse gcloud auth list: %w", err)
	}

	info := &GCPCredentialInfo{}
	if len(accounts) > 0 {
		info.Email = accounts[0].Account
		// Determine account type from email format
		if strings.Contains(info.Email, ".iam.gserviceaccount.com") {
			info.AccountType = "serviceAccount"
		} else {
			info.AccountType = "user"
		}
	}

	// Get default project
	projectOut, err := exec.CommandContext(ctx, "gcloud", "config", "get-value", "project").Output()
	if err == nil {
		info.ProjectID = strings.TrimSpace(string(projectOut))
	}

	return info, nil
}

// CurrentUser returns the current identity's email and account type
func (s *SafeSession) CurrentUser(ctx context.Context) (email, accountType string, err error) {
	info, err := s.getCurrentIdentity(ctx)
	if err != nil {
		return "UNKNOWN", "UNKNOWN", err
	}
	return info.Email, info.AccountType, nil
}

// ------------------------- HELPER FUNCTIONS -------------------------

// IsSessionValid checks if gcloud is authenticated
func IsSessionValid() bool {
	// Check if we can get a token via gcloud
	out, err := exec.Command("gcloud", "auth", "print-access-token").Output()
	if err != nil {
		return false
	}

	token := strings.TrimSpace(string(out))
	return token != "" && !strings.Contains(token, "ERROR")
}

// IsADCConfigured checks if Application Default Credentials are configured
func IsADCConfigured() bool {
	ctx := context.Background()
	_, err := google.DefaultTokenSource(ctx, "https://www.googleapis.com/auth/cloud-platform")
	return err == nil
}

// GetDefaultProject returns the default GCP project from gcloud config
func GetDefaultProject() string {
	out, err := exec.Command("gcloud", "config", "get-value", "project").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// GetDefaultAccount returns the default account from gcloud config
func GetDefaultAccount() string {
	out, err := exec.Command("gcloud", "config", "get-value", "account").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// GetAccessToken returns a fresh access token from gcloud CLI
// This is useful for REST API calls that need a bearer token
func GetAccessToken() (string, error) {
	out, err := exec.Command("gcloud", "auth", "print-access-token").Output()
	if err != nil {
		return "", fmt.Errorf("failed to get access token: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// GetAccessTokenForAccount returns an access token for a specific account
func GetAccessTokenForAccount(account string) (string, error) {
	out, err := exec.Command("gcloud", "auth", "print-access-token", "--account", account).Output()
	if err != nil {
		return "", fmt.Errorf("failed to get access token for account %s: %w", account, err)
	}
	return strings.TrimSpace(string(out)), nil
}
