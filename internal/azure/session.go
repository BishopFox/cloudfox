package azure

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/smithy-go/ptr"
	abstractions "github.com/microsoft/kiota-abstractions-go"
	"github.com/microsoft/kiota-abstractions-go/authentication"
)

type TenantInfo struct {
	ID            *string
	DefaultDomain *string
	Subscriptions []SubscriptionInfo
}

type SubscriptionInfo struct {
	Subscription *armsubscriptions.Subscription
	ID           string
	Name         string
	Accessible   bool
}

type SafeSession struct {
	mu            sync.Mutex
	Cred          azcore.TokenCredential
	currentID     string
	upn           string
	display       string
	tokens        map[string]azcore.AccessToken
	sessionExpiry time.Time     // When the Azure CLI session expires
	monitoring    bool          // Whether background monitoring is active
	stopMonitor   chan struct{} // Signal to stop monitoring
	refreshBuffer time.Duration // How early to refresh before expiry (default 5 min)
}

type azureCLICredential struct {
	scope string // optional scope for this token
	token string
}

type StaticTokenProvider struct {
	Token string
}

// Implements authentication.AccessTokenProvider
func (p *StaticTokenProvider) GetAuthorizationToken(
	ctx context.Context,
	u *url.URL,
	additionalParams map[string]interface{},
) (string, error) {
	return p.Token, nil
}

// Optional: required by interface in some versions
func (p *StaticTokenProvider) GetAllowedHostsValidator() *authentication.AllowedHostsValidator {
	return nil
}

type StaticTokenCredential struct {
	Token string
}

// NewStaticTokenCredential creates a new StaticTokenCredential
func NewStaticTokenCredential(token string) *StaticTokenCredential {
	return &StaticTokenCredential{Token: token}
}

// TokenInfo contains decoded information from an Azure JWT token
type TokenInfo struct {
	// Token metadata
	TokenType string `json:"typ,omitempty"`
	Algorithm string `json:"alg,omitempty"`

	// Identity claims
	Subject           string   `json:"sub,omitempty"`            // Subject (usually object ID)
	ObjectID          string   `json:"oid,omitempty"`            // Object ID of the principal
	UserPrincipalName string   `json:"upn,omitempty"`            // UPN for users
	Name              string   `json:"name,omitempty"`           // Display name
	Email             string   `json:"email,omitempty"`          // Email (alternative to UPN)
	PreferredUsername string   `json:"preferred_username,omitempty"`
	UniqueName        string   `json:"unique_name,omitempty"`    // Legacy UPN claim
	AppID             string   `json:"appid,omitempty"`          // Application (client) ID
	AppIDACR          string   `json:"appidacr,omitempty"`       // App authentication context class reference
	Roles             []string `json:"roles,omitempty"`          // App roles assigned
	Groups            []string `json:"groups,omitempty"`         // Group memberships (if included)
	WIDs              []string `json:"wids,omitempty"`           // Azure AD built-in role IDs

	// Audience and issuer
	Audience string `json:"aud,omitempty"` // Audience (resource the token is for)
	Issuer   string `json:"iss,omitempty"` // Issuer (Azure AD endpoint)
	TenantID string `json:"tid,omitempty"` // Tenant ID

	// Scopes
	Scopes string `json:"scp,omitempty"` // Delegated permission scopes (space-separated)

	// Timestamps
	IssuedAt   int64 `json:"iat,omitempty"` // Issued at (Unix timestamp)
	NotBefore  int64 `json:"nbf,omitempty"` // Not before (Unix timestamp)
	Expiration int64 `json:"exp,omitempty"` // Expiration (Unix timestamp)

	// Additional claims
	Version         string `json:"ver,omitempty"`          // Token version (1.0 or 2.0)
	AuthTime        int64  `json:"auth_time,omitempty"`    // Authentication time
	AMR             []string `json:"amr,omitempty"`        // Authentication methods
	IPAddress       string `json:"ipaddr,omitempty"`       // Client IP address
	DeviceID        string `json:"deviceid,omitempty"`     // Device ID
	IdentityProvider string `json:"idp,omitempty"`         // Identity provider

	// Raw claims for anything we missed
	RawClaims map[string]interface{} `json:"-"`
}

// DecodeJWTToken decodes an Azure JWT token and returns the claims
// Note: This does NOT verify the signature - it only decodes the payload
func DecodeJWTToken(token string) (*TokenInfo, error) {
	// JWT format: header.payload.signature
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	// Decode the payload (second part)
	payload := parts[1]

	// Add padding if necessary (base64url encoding may omit padding)
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}

	// Decode base64url (replace URL-safe characters)
	payload = strings.ReplaceAll(payload, "-", "+")
	payload = strings.ReplaceAll(payload, "_", "/")

	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT payload: %v", err)
	}

	// Parse JSON into TokenInfo
	var info TokenInfo
	if err := json.Unmarshal(decoded, &info); err != nil {
		return nil, fmt.Errorf("failed to parse JWT claims: %v", err)
	}

	// Also store raw claims for any additional fields
	var rawClaims map[string]interface{}
	if err := json.Unmarshal(decoded, &rawClaims); err == nil {
		info.RawClaims = rawClaims
	}

	// Also decode the header for token type info
	header := parts[0]
	switch len(header) % 4 {
	case 2:
		header += "=="
	case 3:
		header += "="
	}
	header = strings.ReplaceAll(header, "-", "+")
	header = strings.ReplaceAll(header, "_", "/")

	if headerDecoded, err := base64.StdEncoding.DecodeString(header); err == nil {
		var headerInfo struct {
			Typ string `json:"typ"`
			Alg string `json:"alg"`
		}
		if json.Unmarshal(headerDecoded, &headerInfo) == nil {
			info.TokenType = headerInfo.Typ
			info.Algorithm = headerInfo.Alg
		}
	}

	return &info, nil
}

// GetAudienceDescription returns a human-readable description of the token audience
func (t *TokenInfo) GetAudienceDescription() string {
	switch {
	case strings.Contains(t.Audience, "management.azure.com") || strings.Contains(t.Audience, "management.core.windows.net"):
		return "Azure Resource Manager (ARM)"
	case strings.Contains(t.Audience, "graph.microsoft.com"):
		return "Microsoft Graph"
	case strings.Contains(t.Audience, "vault.azure.net"):
		return "Azure Key Vault"
	case strings.Contains(t.Audience, "storage.azure.com"):
		return "Azure Storage"
	case strings.Contains(t.Audience, "database.windows.net"):
		return "Azure SQL Database"
	case strings.Contains(t.Audience, "cosmos.azure.com"):
		return "Azure Cosmos DB"
	case strings.Contains(t.Audience, "servicebus.azure.net"):
		return "Azure Service Bus"
	case strings.Contains(t.Audience, "eventhub.azure.net"):
		return "Azure Event Hubs"
	case strings.Contains(t.Audience, "azuresynapse.net"):
		return "Azure Synapse Analytics"
	case strings.Contains(t.Audience, "azuredatabricks.net") || t.Audience == "2ff814a6-3304-4ab8-85cb-cd0e6f879c1d":
		return "Azure Databricks"
	case strings.Contains(t.Audience, "dev.azure.com") || t.Audience == "499b84ac-1321-427f-b974-133d113dbe4b":
		return "Azure DevOps"
	case strings.Contains(t.Audience, "batch.core.windows.net"):
		return "Azure Batch"
	case strings.Contains(t.Audience, "datafactory.azure.net"):
		return "Azure Data Factory"
	case strings.Contains(t.Audience, "loadtesting.azure.com"):
		return "Azure Load Testing"
	default:
		return t.Audience
	}
}

// GetExpirationTime returns the expiration time as a time.Time
func (t *TokenInfo) GetExpirationTime() time.Time {
	return time.Unix(t.Expiration, 0)
}

// GetIssuedAtTime returns the issued at time as a time.Time
func (t *TokenInfo) GetIssuedAtTime() time.Time {
	return time.Unix(t.IssuedAt, 0)
}

// IsExpired returns true if the token has expired
func (t *TokenInfo) IsExpired() bool {
	return time.Now().After(t.GetExpirationTime())
}

// TimeUntilExpiry returns the duration until the token expires
func (t *TokenInfo) TimeUntilExpiry() time.Duration {
	return time.Until(t.GetExpirationTime())
}

// GetPrincipalType returns the type of principal (User, ServicePrincipal, ManagedIdentity)
func (t *TokenInfo) GetPrincipalType() string {
	// If there's an AppID but no UPN, it's likely a service principal or managed identity
	if t.AppID != "" && t.UserPrincipalName == "" && t.UniqueName == "" {
		// Check for managed identity indicators
		if strings.Contains(t.Issuer, "sts.windows.net") && t.IdentityProvider == "" {
			return "ServicePrincipal/ManagedIdentity"
		}
		return "ServicePrincipal"
	}
	if t.UserPrincipalName != "" || t.UniqueName != "" {
		return "User"
	}
	return "Unknown"
}

// GetIdentity returns the best identifier for the principal
func (t *TokenInfo) GetIdentity() string {
	if t.UserPrincipalName != "" {
		return t.UserPrincipalName
	}
	if t.UniqueName != "" {
		return t.UniqueName
	}
	if t.PreferredUsername != "" {
		return t.PreferredUsername
	}
	if t.Email != "" {
		return t.Email
	}
	if t.AppID != "" {
		return fmt.Sprintf("AppID: %s", t.AppID)
	}
	if t.ObjectID != "" {
		return fmt.Sprintf("ObjectID: %s", t.ObjectID)
	}
	return "Unknown"
}

// GetScopesList returns the scopes as a slice
func (t *TokenInfo) GetScopesList() []string {
	if t.Scopes == "" {
		return nil
	}
	return strings.Split(t.Scopes, " ")
}

// PrintTokenInfo prints a formatted summary of the token information
func (t *TokenInfo) PrintTokenInfo(logger internal.Logger) {
	logger.InfoM("╔════════════════════════════════════════════════════════════╗", globals.AZ_UTILS_MODULE_NAME)
	logger.InfoM("║                    TOKEN INFORMATION                       ║", globals.AZ_UTILS_MODULE_NAME)
	logger.InfoM("╠════════════════════════════════════════════════════════════╣", globals.AZ_UTILS_MODULE_NAME)

	// Principal info
	logger.InfoM(fmt.Sprintf("║ Principal Type: %-43s║", t.GetPrincipalType()), globals.AZ_UTILS_MODULE_NAME)
	logger.InfoM(fmt.Sprintf("║ Identity:       %-43s║", truncateString(t.GetIdentity(), 43)), globals.AZ_UTILS_MODULE_NAME)
	if t.Name != "" {
		logger.InfoM(fmt.Sprintf("║ Display Name:   %-43s║", truncateString(t.Name, 43)), globals.AZ_UTILS_MODULE_NAME)
	}
	if t.ObjectID != "" {
		logger.InfoM(fmt.Sprintf("║ Object ID:      %-43s║", t.ObjectID), globals.AZ_UTILS_MODULE_NAME)
	}
	if t.AppID != "" {
		logger.InfoM(fmt.Sprintf("║ App ID:         %-43s║", t.AppID), globals.AZ_UTILS_MODULE_NAME)
	}

	logger.InfoM("╠════════════════════════════════════════════════════════════╣", globals.AZ_UTILS_MODULE_NAME)

	// Tenant info
	if t.TenantID != "" {
		logger.InfoM(fmt.Sprintf("║ Tenant ID:      %-43s║", t.TenantID), globals.AZ_UTILS_MODULE_NAME)
	}

	// Audience (scope)
	logger.InfoM(fmt.Sprintf("║ Audience:       %-43s║", truncateString(t.GetAudienceDescription(), 43)), globals.AZ_UTILS_MODULE_NAME)
	if t.Audience != t.GetAudienceDescription() {
		logger.InfoM(fmt.Sprintf("║   └─ Raw:       %-43s║", truncateString(t.Audience, 43)), globals.AZ_UTILS_MODULE_NAME)
	}

	// Scopes (delegated permissions)
	if t.Scopes != "" {
		logger.InfoM(fmt.Sprintf("║ Scopes:         %-43s║", truncateString(t.Scopes, 43)), globals.AZ_UTILS_MODULE_NAME)
	}

	// Roles (app roles)
	if len(t.Roles) > 0 {
		logger.InfoM(fmt.Sprintf("║ App Roles:      %-43s║", truncateString(strings.Join(t.Roles, ", "), 43)), globals.AZ_UTILS_MODULE_NAME)
	}

	logger.InfoM("╠════════════════════════════════════════════════════════════╣", globals.AZ_UTILS_MODULE_NAME)

	// Timestamps
	logger.InfoM(fmt.Sprintf("║ Issued At:      %-43s║", t.GetIssuedAtTime().Format("2006-01-02 15:04:05 MST")), globals.AZ_UTILS_MODULE_NAME)
	logger.InfoM(fmt.Sprintf("║ Expires At:     %-43s║", t.GetExpirationTime().Format("2006-01-02 15:04:05 MST")), globals.AZ_UTILS_MODULE_NAME)

	// Expiry status
	if t.IsExpired() {
		logger.InfoM("║ Status:         ⚠️  EXPIRED                                 ║", globals.AZ_UTILS_MODULE_NAME)
	} else {
		remaining := t.TimeUntilExpiry()
		logger.InfoM(fmt.Sprintf("║ Status:         ✓ Valid (expires in %s)%s║",
			formatDuration(remaining),
			strings.Repeat(" ", max(0, 25-len(formatDuration(remaining))))), globals.AZ_UTILS_MODULE_NAME)
	}

	logger.InfoM("╚════════════════════════════════════════════════════════════╝", globals.AZ_UTILS_MODULE_NAME)
}

// Helper function to truncate strings for display
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// Helper function to format duration
func formatDuration(d time.Duration) string {
	if d < 0 {
		return "expired"
	}
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	return fmt.Sprintf("%dm", minutes)
}

// max returns the larger of two integers
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (c *StaticTokenCredential) GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{
		Token:     c.Token,
		ExpiresOn: time.Now().Add(1 * time.Hour),
	}, nil
}

func (s *StaticTokenProvider) AuthenticateRequest(ctx context.Context, request *abstractions.RequestInformation, options map[string]interface{}) error {
	if request.Headers == nil {
		request.Headers = abstractions.NewRequestHeaders()
	}

	// Use Add instead of indexing or Set
	request.Headers.Add("Authorization", "Bearer "+s.Token)
	return nil
}

// NewSafeSession initializes a session and prefetches all common tokens
// If bearer tokens are provided via globals.AZ_ARM_TOKEN or globals.AZ_GRAPH_TOKEN,
// it will use those instead of the Azure CLI session.
func NewSafeSession(ctx context.Context) (*SafeSession, error) {
	// Check if we have dual tokens (ARM and/or Graph)
	if globals.AZ_ARM_TOKEN != "" || globals.AZ_GRAPH_TOKEN != "" {
		return NewSafeSessionWithDualTokens(globals.AZ_ARM_TOKEN, globals.AZ_GRAPH_TOKEN)
	}

	// Legacy single token support
	if globals.AZ_BEARER_TOKEN != "" {
		return NewSafeSessionWithToken(globals.AZ_BEARER_TOKEN)
	}

	if !IsSessionValid() {
		return nil, fmt.Errorf("Azure CLI session invalid; run 'az login'")
	}

	ss := &SafeSession{
		Cred:          &azureCLICredential{},
		tokens:        make(map[string]azcore.AccessToken),
		refreshBuffer: 5 * time.Minute, // Refresh tokens 5 minutes before expiry
		stopMonitor:   make(chan struct{}),
	}

	// Detect session expiry from Azure CLI
	if expiry, err := ss.getSessionExpiry(ctx); err == nil {
		ss.sessionExpiry = expiry
	}

	for _, r := range globals.CommonScopes {
		scope := ResourceToScope(r)
		if _, err := ss.GetToken(scope); err != nil {
			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				fmt.Fprintf(os.Stderr, "warning: failed to prefetch token for %s: %v\n", ScopeDisplayName(scope), err)
			}
		}
	}

	return ss, nil
}

// NewSafeSessionWithToken creates a SafeSession using a static bearer token
// instead of Azure CLI authentication. The same token is used for all scopes.
// This is useful when you have a pre-obtained access token (e.g., from az account get-access-token).
func NewSafeSessionWithToken(token string) (*SafeSession, error) {
	if token == "" {
		return nil, fmt.Errorf("bearer token cannot be empty")
	}

	ss := &SafeSession{
		Cred:          &StaticTokenCredential{Token: token},
		tokens:        make(map[string]azcore.AccessToken),
		refreshBuffer: 5 * time.Minute,
		stopMonitor:   make(chan struct{}),
	}

	// Pre-populate all common scopes with the static token
	// Note: A single token may not work for all scopes, but we try anyway
	for _, r := range globals.CommonScopes {
		scope := ResourceToScope(r)
		ss.tokens[scope] = azcore.AccessToken{
			Token:     token,
			ExpiresOn: time.Now().Add(60 * time.Minute), // Assume 1 hour validity
		}
	}

	return ss, nil
}

// NewSafeSessionWithDualTokens creates a SafeSession using separate ARM and Graph tokens.
// This allows proper scoping - ARM token for resource enumeration, Graph token for user info.
func NewSafeSessionWithDualTokens(armToken, graphToken string) (*SafeSession, error) {
	if armToken == "" && graphToken == "" {
		return nil, fmt.Errorf("at least one token (ARM or Graph) must be provided")
	}

	// Use ARM token as the default credential (most SDK calls use ARM)
	defaultToken := armToken
	if defaultToken == "" {
		defaultToken = graphToken
	}

	ss := &SafeSession{
		Cred:          &StaticTokenCredential{Token: defaultToken},
		tokens:        make(map[string]azcore.AccessToken),
		refreshBuffer: 5 * time.Minute,
		stopMonitor:   make(chan struct{}),
	}

	// Pre-populate tokens for each scope with the appropriate token
	for _, r := range globals.CommonScopes {
		scope := ResourceToScope(r)
		var token string

		// Select the appropriate token based on the scope
		if strings.Contains(scope, "graph.microsoft.com") {
			if graphToken != "" {
				token = graphToken
			} else {
				continue // Skip if no Graph token provided
			}
		} else if strings.Contains(scope, "management.azure.com") || strings.Contains(scope, "management.core.windows.net") {
			if armToken != "" {
				token = armToken
			} else {
				continue // Skip if no ARM token provided
			}
		} else {
			// For other scopes (Key Vault, Storage, etc.), use ARM token if available
			if armToken != "" {
				token = armToken
			} else if graphToken != "" {
				token = graphToken
			} else {
				continue
			}
		}

		ss.tokens[scope] = azcore.AccessToken{
			Token:     token,
			ExpiresOn: time.Now().Add(60 * time.Minute), // Assume 1 hour validity
		}
	}

	return ss, nil
}

// NewSmartSession creates a session with automatic monitoring and refresh
func NewSmartSession(ctx context.Context) (*SafeSession, error) {
	ss, err := NewSafeSession(ctx)
	if err != nil {
		return nil, err
	}

	// Only start background monitoring for CLI-based sessions (not static tokens)
	if globals.AZ_BEARER_TOKEN == "" {
		ss.StartMonitoring(ctx)
	}

	return ss, nil
}

// ------------------------- SMART SESSION METHODS -------------------------

// getSessionExpiry retrieves the Azure CLI session expiration time
func (s *SafeSession) getSessionExpiry(ctx context.Context) (time.Time, error) {
	out, err := exec.CommandContext(ctx, "az", "account", "get-access-token", "-o", "json").Output()
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to get access token info: %w", err)
	}

	var data struct {
		ExpiresOn string `json:"expiresOn"`
	}
	if err := json.Unmarshal(out, &data); err != nil {
		return time.Time{}, fmt.Errorf("failed to parse token response: %w", err)
	}

	// Parse expiresOn - Azure CLI returns format like "2024-01-15 12:34:56.789012"
	expiry, err := time.Parse("2006-01-02 15:04:05.999999", data.ExpiresOn)
	if err != nil {
		// Try alternative format with timezone
		expiry, err = time.Parse(time.RFC3339, data.ExpiresOn)
		if err != nil {
			return time.Time{}, fmt.Errorf("failed to parse expiry time: %w", err)
		}
	}

	return expiry, nil
}

// IsSessionExpired checks if the Azure CLI session has expired or will expire soon
func (s *SafeSession) IsSessionExpired() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.sessionExpiry.IsZero() {
		return false
	}

	// Consider expired if within refresh buffer
	return time.Now().Add(s.refreshBuffer).After(s.sessionExpiry)
}

// RefreshSession attempts to refresh the Azure CLI session
func (s *SafeSession) RefreshSession(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if session is actually expired
	if !IsSessionValid() {
		return fmt.Errorf("Azure CLI session expired; please run 'az login'")
	}

	// Update session expiry
	expiry, err := s.getSessionExpiry(ctx)
	if err != nil {
		return fmt.Errorf("failed to get session expiry: %w", err)
	}
	s.sessionExpiry = expiry

	// Clear token cache to force refresh
	s.tokens = make(map[string]azcore.AccessToken)

	// Prefetch common scopes
	for _, r := range globals.CommonScopes {
		scope := ResourceToScope(r)
		// Call unlocked version
		if _, err := s.getTokenUnlocked(scope); err != nil {
			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				fmt.Fprintf(os.Stderr, "warning: failed to refresh token for %s: %v\n", ScopeDisplayName(scope), err)
			}
		}
	}

	return nil
}

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
		case <-ticker.C:
			if s.IsSessionExpired() {
				if err := s.RefreshSession(ctx); err != nil {
					if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
						fmt.Fprintf(os.Stderr, "smart session: auto-refresh failed: %v\n", err)
						fmt.Fprintf(os.Stderr, "smart session: please run 'az login' to re-authenticate\n")
					}
				} else {
					if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
						fmt.Fprintf(os.Stderr, "smart session: automatically refreshed Azure CLI tokens\n")
					}
				}
			}
		}
	}
}

// GetTokenWithRetry attempts to get a token with automatic retry on expiry
func (s *SafeSession) GetTokenWithRetry(scope string) (string, error) {
	token, err := s.GetToken(scope)
	if err != nil {
		// If failed, try to refresh session and retry once
		if refreshErr := s.RefreshSession(context.Background()); refreshErr == nil {
			token, err = s.GetToken(scope)
		}
	}
	return token, err
}

// GetToken implements azcore.TokenCredential
func (c *azureCLICredential) GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	var scope string
	if len(opts.Scopes) > 0 {
		scope = opts.Scopes[0]
	} else {
		scope = "https://management.azure.com/.default"
	}

	out, err := exec.Command("az", "account", "get-access-token",
		"--resource", scope,
		"--query", "accessToken",
		"-o", "tsv").Output()
	if err != nil {
		return azcore.AccessToken{}, fmt.Errorf("failed to get token for scope %s: %w", scope, err)
	}

	token := strings.TrimSpace(string(out))
	return azcore.AccessToken{
		Token:     token,
		ExpiresOn: time.Now().Add(1 * time.Hour),
	}, nil
}
func (s *SafeSession) GetToken(scope string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getTokenUnlocked(scope)
}

// getTokenUnlocked is an internal method that gets a token without locking
// Used internally when the lock is already held
func (s *SafeSession) getTokenUnlocked(scope string) (string, error) {
	// Return cached token if valid
	if tok, ok := s.tokens[scope]; ok && tok.ExpiresOn.After(time.Now().Add(-1*time.Minute)) {
		return tok.Token, nil
	}

	// Fetch from Azure CLI
	out, err := exec.Command("az", "account", "get-access-token",
		"--resource", scope,
		"--query", "accessToken",
		"-o", "tsv").Output()
	if err != nil {
		return "", fmt.Errorf("failed to get token for %s: %w", scope, err)
	}

	token := strings.TrimSpace(string(out))
	s.tokens[scope] = azcore.AccessToken{
		Token:     token,
		ExpiresOn: time.Now().Add(60 * time.Minute),
	}

	return token, nil
}

func (s *SafeSession) GetTokenForResource(resource string) (string, error) {
	scope := ResourceToScope(resource)
	return s.GetToken(scope)
}

func ResourceToScope(resource string) string {
	switch {
	case strings.Contains(resource, "graph.microsoft.com"):
		return "https://graph.microsoft.com/"
	case strings.Contains(resource, "management.azure.com"):
		return "https://management.azure.com/"
	case strings.Contains(resource, "vault.azure.net"):
		return "https://vault.azure.net/"
	case strings.Contains(resource, "storage.azure.com"):
		return "https://storage.azure.com/"
	case strings.Contains(resource, "vssps.visualstudio.com"):
		return "499b84ac-1321-427f-b974-133d113dbe4b/.default"
	case strings.Contains(resource, "499b84ac-1321-427f"):
		return "499b84ac-1321-427f-b974-133d113dbe4b/.default"
	default:
		return strings.TrimSuffix(resource, "/") + "/.default"
	}
}

// ScopeDisplayName returns a human-friendly name for an OAuth scope string.
func ScopeDisplayName(scope string) string {
	switch {
	case strings.Contains(scope, "management.azure.com"):
		return "Azure Resource Manager (" + scope + ")"
	case strings.Contains(scope, "graph.microsoft.com"):
		return "Microsoft Graph (" + scope + ")"
	case strings.Contains(scope, "vault.azure.net"):
		return "Azure Key Vault (" + scope + ")"
	case strings.Contains(scope, "storage.azure.com"):
		return "Azure Storage (" + scope + ")"
	case strings.Contains(scope, "499b84ac-1321-427f"):
		return "Azure DevOps (" + scope + ")"
	case strings.Contains(scope, "vssps.visualstudio.com"):
		return "Azure DevOps (" + scope + ")"
	default:
		return scope
	}
}


// ------------------------- TENANT FUNCTIONS -------------------------

func GetTenantNameFromID(ctx context.Context, session *SafeSession, tenantID string) string {
	cacheKey := AzCacheKey("tenant-name", tenantID)
	if cached, found := AzureDataCache.Get(cacheKey); found {
		return cached.(string)
	}

	// Look up from already-cached tenant list
	for _, t := range GetTenants(ctx, session) {
		if t.TenantID != nil && *t.TenantID == tenantID {
			if t.DisplayName != nil && *t.DisplayName != "" {
				AzureDataCache.Set(cacheKey, *t.DisplayName, 0)
				return *t.DisplayName
			}
			break
		}
	}

	// CLI fallback
	if out, err := exec.Command("az", "account", "tenant", "show",
		"--tenant", tenantID, "--query", "displayName", "-o", "tsv").Output(); err == nil {
		name := strings.TrimSpace(string(out))
		if name != "" {
			AzureDataCache.Set(cacheKey, name, 0)
			return name
		}
	}

	AzureDataCache.Set(cacheKey, tenantID, 0)
	return tenantID
}

func GetTenantIDFromSubscription(session *SafeSession, subscriptionID string) *string {
	for _, s := range GetSubscriptions(session) {
		if ptr.ToString(s.SubscriptionID) == subscriptionID || ptr.ToString(s.DisplayName) == subscriptionID {
			return s.TenantID
		}
	}
	return nil
}

func getTenantDefaultDomain(tenantID string) string {
	if out, err := exec.Command("az", "account", "tenant", "list",
		"--query", fmt.Sprintf("[?tenantId=='%s'].defaultDomain", tenantID),
		"-o", "tsv").Output(); err == nil && len(out) > 0 {
		return strings.TrimSpace(string(out))
	}
	return "UNKNOWN"
}

// ------------------------- USER FUNCTIONS -------------------------


// GetCurrentUserSafe returns the current identity's object ID, UPN, and display name.
func GetCurrentUserSafe(ctx context.Context, session *SafeSession) (objectID, upn, displayName string, err error) {
	cacheKey := AzCacheKey("current-user")
	if cached, found := AzureDataCache.Get(cacheKey); found {
		parts := cached.([3]string)
		return parts[0], parts[1], parts[2], nil
	}

	// If using token-based auth, skip CLI check and go straight to Graph API
	if globals.AZ_BEARER_TOKEN != "" {
		objectID, upn, displayName, err = getCurrentUserFromToken(ctx, session)
		if err == nil {
			AzureDataCache.Set(cacheKey, [3]string{objectID, upn, displayName}, 0)
		}
		return
	}

	// First, check if session is valid
	if !IsSessionValid() {
		return "UNKNOWN", "UNKNOWN", "UNKNOWN", fmt.Errorf("session expired; please run 'az logout' and 'az login'")
	}

	// Try Azure CLI first
	out, cliErr := exec.Command("az", "ad", "signed-in-user", "show", "-o", "json").Output()
	if cliErr == nil && len(out) > 0 {
		var data struct {
			ID                string `json:"id"`
			UserPrincipalName string `json:"userPrincipalName"`
			DisplayName       string `json:"displayName"`
		}
		if json.Unmarshal(out, &data) == nil && data.ID != "" {
			AzureDataCache.Set(cacheKey, [3]string{data.ID, data.UserPrincipalName, data.DisplayName}, 0)
			return data.ID, data.UserPrincipalName, data.DisplayName, nil
		}
	}

	// Fallback: Microsoft Graph
	objectID, upn, displayName, err = getCurrentUserFromToken(ctx, session)
	if err == nil {
		AzureDataCache.Set(cacheKey, [3]string{objectID, upn, displayName}, 0)
	}
	return
}

// getCurrentUserFromToken retrieves user info using the Graph API with the session token
func getCurrentUserFromToken(ctx context.Context, session *SafeSession) (objectID, upn, displayName string, err error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[1]) // Graph scope
	if err != nil {
		return "UNKNOWN", "UNKNOWN", "UNKNOWN", fmt.Errorf("failed to get Graph token: %v", err)
	}

	body, err := GraphAPIRequestWithRetry(ctx, "GET", "https://graph.microsoft.com/v1.0/me", token)
	if err != nil {
		return "UNKNOWN", "UNKNOWN", "UNKNOWN", fmt.Errorf("graph /me request failed: %v", err)
	}

	var data struct {
		ID                string `json:"id"`
		UserPrincipalName string `json:"userPrincipalName"`
		DisplayName       string `json:"displayName"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return "UNKNOWN", "UNKNOWN", "UNKNOWN", fmt.Errorf("failed to decode Graph /me response: %v", err)
	}

	if data.ID == "" {
		return "UNKNOWN", "UNKNOWN", "UNKNOWN", fmt.Errorf("graph /me returned empty ID")
	}

	return data.ID, data.UserPrincipalName, data.DisplayName, nil
}

// ------------------------- ACCESS TOKEN HELPERS -------------------------


func getEnv(key string) string {
	return os.Getenv(key)
}

// --------

// SessionValidationResult contains the result of session validation
type SessionValidationResult struct {
	Valid           bool
	FullAccess      bool   // true if Graph API also works
	WarningMessage  string // warning to display if limited access
}

// ValidateSession checks if the Azure CLI session is valid and what level of access is available
func ValidateSession() SessionValidationResult {
	// If using token-based auth, assume valid (will fail on API call if not)
	if globals.AZ_BEARER_TOKEN != "" {
		return SessionValidationResult{Valid: true, FullAccess: true}
	}

	// First, try the strict check - Graph API access (az ad signed-in-user show)
	// This gives us full access including user details, principals, etc.
	graphCmd := exec.Command("az", "ad", "signed-in-user", "show", "-o", "json")
	out, err := graphCmd.Output()
	if err == nil {
		var data struct {
			ID                string `json:"id"`
			UserPrincipalName string `json:"userPrincipalName"`
		}
		if json.Unmarshal(out, &data) == nil && data.ID != "" {
			// Full access - Graph API works
			return SessionValidationResult{Valid: true, FullAccess: true}
		}
	}

	// Graph failed - try lenient check (ARM access)
	// This happens when copying .azure directory or when Graph permissions are limited

	// First try az account get-access-token (explicit token request)
	armCmd := exec.Command("az", "account", "get-access-token",
		"--resource", "https://management.azure.com/",
		"--query", "accessToken",
		"-o", "tsv")
	armOut, armErr := armCmd.Output()

	if armErr == nil && len(strings.TrimSpace(string(armOut))) > 0 {
		// ARM token works - limited access mode
		return SessionValidationResult{
			Valid:      true,
			FullAccess: false,
			WarningMessage: "Microsoft Graph API access unavailable. Some features will be limited:\n" +
				"  - User identity details (UPN, display name) may show as 'UNKNOWN'\n" +
				"  - Modules requiring Graph (principals, enterprise-apps, consent-grants) may fail\n" +
				"  \n" +
				"  Options:\n" +
				"  1. Run 'az login --use-device-code' for full access\n" +
				"  2. Or provide tokens manually:\n" +
				"     ARM:   az account get-access-token --resource https://management.azure.com/ -o tsv --query accessToken\n" +
				"     Graph: az account get-access-token --resource https://graph.microsoft.com/ -o tsv --query accessToken",
		}
	}

	// az account get-access-token failed - but az group list might still work
	// Try a lightweight ARM call to verify actual API access
	// This handles the case where MSAL cache is invalid but az CLI can still make API calls
	// Use CombinedOutput to capture any warnings that might be in stderr
	groupCmd := exec.Command("az", "group", "list", "--query", "[0].name", "-o", "tsv")
	groupOut, groupErr := groupCmd.CombinedOutput()
	groupOutStr := strings.TrimSpace(string(groupOut))

	// Check if the output contains a valid resource group name (not an error message)
	// Error messages typically contain "error", "failed", "login", etc.
	isError := strings.Contains(strings.ToLower(groupOutStr), "error") ||
		strings.Contains(strings.ToLower(groupOutStr), "please run") ||
		strings.Contains(strings.ToLower(groupOutStr), "az login") ||
		strings.Contains(strings.ToLower(groupOutStr), "msal")

	if (groupErr == nil || len(groupOutStr) > 0) && !isError && groupOutStr != "" {
		// ARM API works even though get-access-token failed!
		// This is a quirk of Azure CLI - proceed in limited mode
		return SessionValidationResult{
			Valid:      true,
			FullAccess: false,
			WarningMessage: "Azure CLI token cache issue detected, but API calls work.\n" +
				"  Microsoft Graph API access unavailable. Some features will be limited:\n" +
				"  - User identity details (UPN, display name) may show as 'UNKNOWN'\n" +
				"  - Modules requiring Graph (principals, enterprise-apps, consent-grants) may fail\n" +
				"  \n" +
				"  Options:\n" +
				"  1. Run 'az login --use-device-code' for full access\n" +
				"  2. Or provide tokens manually:\n" +
				"     ARM:   az account get-access-token --resource https://management.azure.com/ -o tsv --query accessToken\n" +
				"     Graph: az account get-access-token --resource https://graph.microsoft.com/ -o tsv --query accessToken",
		}
	}

	// Neither method works - session is truly invalid
	// Debug: check if az CLI is available at all
	if _, pathErr := exec.LookPath("az"); pathErr != nil {
		return SessionValidationResult{
			Valid:          false,
			FullAccess:     false,
			WarningMessage: "Azure CLI (az) not found in PATH",
		}
	}

	// Check if there's an active account configured
	accountCmd := exec.Command("az", "account", "show", "-o", "json")
	accountOut, accountErr := accountCmd.Output()
	if accountErr != nil {
		return SessionValidationResult{
			Valid:          false,
			FullAccess:     false,
			WarningMessage: "No Azure account configured. Run 'az login' first.",
		}
	}

	// Account exists but token refresh failed - likely needs re-auth
	var accountData struct {
		Name string `json:"name"`
		ID   string `json:"id"`
	}
	if json.Unmarshal(accountOut, &accountData) == nil && accountData.ID != "" {
		return SessionValidationResult{
			Valid:          false,
			FullAccess:     false,
			WarningMessage: fmt.Sprintf("Account '%s' configured but MSAL token cache expired/unavailable.\n"+
				"        This often happens when copying .azure directory to another machine.\n"+
				"        \n"+
				"        Options:\n"+
				"        1. Re-authenticate with: az login --use-device-code\n"+
				"        2. Or provide tokens manually:\n"+
				"           ARM:   az account get-access-token --resource https://management.azure.com/ -o tsv --query accessToken\n"+
				"           Graph: az account get-access-token --resource https://graph.microsoft.com/ -o tsv --query accessToken", accountData.Name),
		}
	}

	return SessionValidationResult{Valid: false, FullAccess: false}
}

// IsSessionValid returns true if the session is valid (for backward compatibility)
func IsSessionValid() bool {
	return ValidateSession().Valid
}

// GetClientID returns the clientId of the signed-in principal (user or service principal).
// For users, it falls back to the objectId. For SPNs, it returns the real appId/clientId.
func GetClientID() string {
	// Try Azure CLI first
	if out, err := exec.Command("az", "account", "show", "--query", "user", "-o", "json").Output(); err == nil {
		var data struct {
			Name string `json:"name"`
			Type string `json:"type"`
		}
		if json.Unmarshal(out, &data) == nil {
			// If logged in as a service principal, "name" is the appId
			if strings.EqualFold(data.Type, "servicePrincipal") && data.Name != "" {
				return data.Name
			}
			// For users, return empty (not applicable)
		}
	}

	// Try environment variables (common in automation)
	if v := strings.TrimSpace(strings.Join([]string{
		getEnv("AZURE_CLIENT_ID"),
		getEnv("ARM_CLIENT_ID"),
	}, "")); v != "" {
		return v
	}

	return ""
}

// GetRoleNameFromDefinitionID resolves a roleDefinitionID into a human-readable role name.
func GetRoleNameFromDefinitionID(ctx context.Context, session *SafeSession, subscriptionID string, roleDefinitionID string) string {
	cacheKey := AzCacheKey("role-name", roleDefinitionID)
	if cached, found := AzureDataCache.Get(cacheKey); found {
		return cached.(string)
	}

	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return "Unknown"
	}

	cred := &StaticTokenCredential{Token: token}

	client, err := armauthorization.NewRoleDefinitionsClient(cred, DefaultARMClientOptions())
	if err != nil {
		return "Unknown"
	}

	roleDefGUID := ParseRoleDefinitionID(roleDefinitionID)
	scope := fmt.Sprintf("/subscriptions/%s", subscriptionID)

	def, err := client.Get(ctx, scope, roleDefGUID, nil)
	if err != nil {
		if IsThrottlingError(err.Error()) {
			logger := internal.NewLogger()
			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Throttled resolving role %s after retries: %v", roleDefGUID, err), globals.AZ_UTILS_MODULE_NAME)
			}
		}
		return "Unknown"
	}
	if def.Properties != nil && def.Properties.RoleName != nil {
		roleName := *def.Properties.RoleName
		AzureDataCache.Set(cacheKey, roleName, 0)
		return roleName
	}
	return "Unknown"
}

// GetUserType determines whether an Azure AD object is a User, ServicePrincipal,
// ManagedIdentity, or Group using the Graph API directoryObjects endpoint.
// Results are cached in AzureDataCache.
func GetUserType(ctx context.Context, session *SafeSession, objectID string) string {
	if objectID == "" {
		return "Unknown"
	}
	cacheKey := AzCacheKey("user-type", objectID)
	if cached, found := AzureDataCache.Get(cacheKey); found {
		return cached.(string)
	}

	token, err := session.GetTokenForResource("https://graph.microsoft.com/")
	if err != nil {
		return "Unknown"
	}
	reqURL := fmt.Sprintf("https://graph.microsoft.com/v1.0/directoryObjects/%s?$select=id", objectID)
	body, err := GraphAPIRequestWithRetry(ctx, "GET", reqURL, token)
	if err != nil {
		return "Unknown"
	}
	var obj struct {
		ODataType string `json:"@odata.type"`
	}
	if json.Unmarshal(body, &obj) != nil {
		return "Unknown"
	}
	// @odata.type returns "#microsoft.graph.user", "#microsoft.graph.servicePrincipal", etc.
	result := "Unknown"
	switch {
	case strings.Contains(obj.ODataType, "user"):
		result = "User"
	case strings.Contains(obj.ODataType, "servicePrincipal"):
		result = getServicePrincipalSubType(ctx, session, objectID, token)
	case strings.Contains(obj.ODataType, "group"):
		result = "Group"
	}
	AzureDataCache.Set(cacheKey, result, 0)
	return result
}

// getServicePrincipalSubType checks whether a service principal is a ManagedIdentity
// or a regular ServicePrincipal by querying the servicePrincipalType field.
func getServicePrincipalSubType(ctx context.Context, session *SafeSession, objectID, token string) string {
	reqURL := fmt.Sprintf("https://graph.microsoft.com/v1.0/servicePrincipals/%s?$select=servicePrincipalType", objectID)
	body, err := GraphAPIRequestWithRetry(ctx, "GET", reqURL, token)
	if err != nil {
		return "ServicePrincipal"
	}
	var sp struct {
		SPType string `json:"servicePrincipalType"`
	}
	if json.Unmarshal(body, &sp) == nil && sp.SPType == "ManagedIdentity" {
		return "ManagedIdentity"
	}
	return "ServicePrincipal"
}




// ------------------------- SUBSCRIPTION FUNCTIONS -------------------------

func GetSubscriptions(session *SafeSession) []*armsubscriptions.Subscription {
	// Check in-memory cache first
	cacheKey := AzCacheKey("subscriptions")
	if cached, found := AzureDataCache.Get(cacheKey); found {
		return cached.([]*armsubscriptions.Subscription)
	}

	logger := internal.NewLogger()

	// Fetch ARM-scoped token
	token, err := session.GetTokenForResource("https://management.azure.com/")
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to acquire ARM token: %v", err), globals.AZ_UTILS_MODULE_NAME)
		return nil
	}

	// Wrap token in credential for SDK
	cred := &StaticTokenCredential{Token: token}
	client, err := armsubscriptions.NewClient(cred, DefaultARMClientOptions())
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to create subscriptions client: %v", err), globals.AZ_UTILS_MODULE_NAME)
		return nil
	}

	pager := client.NewListPager(nil)
	var results []*armsubscriptions.Subscription

	for pager.More() {
		page, err := pager.NextPage(context.Background())
		if err != nil {
			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Error fetching subscriptions: %v", err), globals.AZ_UTILS_MODULE_NAME)
			}
			continue
		}

		for _, s := range page.Value {
			// Skip inaccessible subscriptions
			if !IsSubscriptionAccessible(session, *s.SubscriptionID) {
				if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
					logger.ErrorM(fmt.Sprintf("Skipping subscription %s (%s): access denied", *s.DisplayName, *s.SubscriptionID), globals.AZ_UTILS_MODULE_NAME)
				}
				continue
			}
			results = append(results, s)
		}
	}

	// Cache the result before returning
	AzureDataCache.Set(cacheKey, results, 0)
	return results
}

func GetSubscriptionByIDOrName(session *SafeSession, input string) *armsubscriptions.Subscription {
	for _, s := range GetSubscriptions(session) {
		if ptr.ToString(s.SubscriptionID) == input || ptr.ToString(s.DisplayName) == input {
			return s
		}
	}
	return nil
}

// GetSubscriptionNameFromID returns the friendly subscription name using cached data.
func GetSubscriptionNameFromID(ctx context.Context, session *SafeSession, subscriptionID string) string {
	cacheKey := AzCacheKey("sub-name", subscriptionID)
	if cached, found := AzureDataCache.Get(cacheKey); found {
		return cached.(string)
	}

	// Look up from already-cached subscription list
	for _, s := range GetSubscriptions(session) {
		if ptr.ToString(s.SubscriptionID) == subscriptionID {
			name := ptr.ToString(s.DisplayName)
			if name == "" {
				name = "Unknown"
			}
			AzureDataCache.Set(cacheKey, name, 0)
			return name
		}
	}

	AzureDataCache.Set(cacheKey, "Unknown", 0)
	return "Unknown"
}

func GetSubscriptionIDFromName(session *SafeSession, subscription string) *string {
	if sub := GetSubscriptionByIDOrName(session, subscription); sub != nil {
		return sub.SubscriptionID
	}
	return nil
}

func GetSubscriptionsPerTenantID(session *SafeSession, tenantID string) []*armsubscriptions.Subscription {
	var results []*armsubscriptions.Subscription
	for _, s := range GetSubscriptions(session) {
		if ptr.ToString(s.TenantID) == tenantID && IsSubscriptionAccessible(session, ptr.ToString(s.SubscriptionID)) {
			results = append(results, s)
		}
	}
	return results
}

func IsSubscriptionAccessible(session *SafeSession, subscriptionID string) bool {
	// Check in-memory cache first
	cacheKey := AzCacheKey("sub-accessible", subscriptionID)
	if cached, found := AzureDataCache.Get(cacheKey); found {
		return cached.(bool)
	}

	logger := internal.NewLogger()
	ctx := context.Background()

	// Get ARM token from SafeSession
	armToken, err := session.GetToken("https://management.azure.com/")
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to get ARM token: %v", err), globals.AZ_UTILS_MODULE_NAME)
		}
		return false
	}

	// Wrap token in a proper azcore.TokenCredential
	cred := &StaticTokenCredential{Token: armToken}

	// Create subscriptions client
	client, err := armsubscriptions.NewClient(cred, DefaultARMClientOptions())
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to create subscriptions client: %v", err), globals.AZ_UTILS_MODULE_NAME)
		}
		return false
	}

	// Try to fetch the subscription
	_, err = client.Get(ctx, subscriptionID, nil)
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Subscription %s inaccessible: %v", subscriptionID, err), globals.AZ_UTILS_MODULE_NAME)
		}
		AzureDataCache.Set(cacheKey, false, 0)
		return false
	}

	AzureDataCache.Set(cacheKey, true, 0)
	return true
}

// ------------------------- TENANT STRUCT POPULATION -------------------------

func PopulateTenant(session *SafeSession, tenantID string) TenantInfo {
	logger := internal.NewLogger()
	ti := TenantInfo{ID: ptr.String(tenantID)}
	subs := GetSubscriptionsPerTenantID(session, tenantID)

	for _, s := range subs {
		ti.Subscriptions = append(ti.Subscriptions, SubscriptionInfo{
			Subscription: s,
			ID:           ptr.ToString(s.SubscriptionID),
			Name:         ptr.ToString(s.DisplayName),
			Accessible:   true,
		})
	}

	if len(ti.Subscriptions) == 0 {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("No accessible subscriptions found for tenant %s", tenantID), globals.AZ_UTILS_MODULE_NAME)
		}
	}

	ti.DefaultDomain = ptr.String(getTenantDefaultDomain(tenantID))
	return ti
}

// ------------------------- RESOURCE GROUP FUNCTIONS -------------------------

func GetResourceGroupsPerSubscription(session *SafeSession, subscriptionID string) []*armresources.ResourceGroup {
	// Check in-memory cache first
	cacheKey := AzCacheKey("resource-groups", subscriptionID)
	if cached, found := AzureDataCache.Get(cacheKey); found {
		return cached.([]*armresources.ResourceGroup)
	}

	logger := internal.NewLogger()
	ctx := context.Background()

	// Get ARM token from SafeSession
	armToken, err := session.GetToken("https://management.azure.com/")
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to get ARM token for subscription %s: %v", subscriptionID, err), globals.AZ_UTILS_MODULE_NAME)
		}
		return nil
	}

	// Wrap token in StaticTokenCredential
	cred := &StaticTokenCredential{Token: armToken}

	// Create ResourceGroups client
	client, err := armresources.NewResourceGroupsClient(subscriptionID, cred, DefaultARMClientOptions())
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to create ResourceGroups client: %v", err), globals.AZ_UTILS_MODULE_NAME)
		}
		return nil
	}

	// Iterate through pages
	var groups []*armresources.ResourceGroup
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Error fetching resource groups for subscription %s: %v", subscriptionID, err), globals.AZ_UTILS_MODULE_NAME)
			}
			continue
		}
		groups = append(groups, page.Value...)
	}

	// Cache the result before returning
	AzureDataCache.Set(cacheKey, groups, 0)
	return groups
}

// GetResourceGroupFromID extracts the resource group from a full ARM ID
func GetResourceGroupFromID(resourceID string) string {
	parts := strings.Split(resourceID, "/")
	for i := 0; i < len(parts)-1; i++ {
		if strings.EqualFold(parts[i], "resourceGroups") && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return "N/A"
}

func GetResourceGroupIDFromName(session *SafeSession, subscriptionID, name string) *string {
	for _, rg := range GetResourceGroupsPerSubscription(session, subscriptionID) {
		if ptr.ToString(rg.Name) == name {
			return rg.ID
		}
	}
	return nil
}

// GetResourceTypeFromID extracts the Azure resource type from a full ARM ID
func GetResourceTypeFromID(resourceID string) string {
	parts := strings.Split(resourceID, "/")
	for i := 0; i < len(parts)-1; i++ {
		if strings.EqualFold(parts[i], "providers") && i+2 < len(parts) {
			// provider := parts[i+1] // e.g., Microsoft.Network
			resourceType := parts[i+2] // e.g., networkInterfaces, virtualMachines
			// Handle nested resources: /type1/name1/type2/name2
			if i+4 < len(parts) {
				resourceType = resourceType + "/" + parts[i+4]
			}
			return resourceType
		}
	}
	return "N/A"
}

// ------------------------- TENANT SDK -------------------------

func GetTenants(ctx context.Context, session *SafeSession) []*armsubscriptions.TenantIDDescription {
	// Check in-memory cache first
	cacheKey := AzCacheKey("tenants")
	if cached, found := AzureDataCache.Get(cacheKey); found {
		return cached.([]*armsubscriptions.TenantIDDescription)
	}

	logger := internal.NewLogger()
	var tenants []*armsubscriptions.TenantIDDescription

	// Get ARM token from SafeSession
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		logger.ErrorM(fmt.Sprintf("failed to get ARM token: %v", err), globals.AZ_UTILS_MODULE_NAME)
		return tenants
	}

	// Use token to create a credential compatible with ARM SDK
	cred := &StaticTokenCredential{Token: token}

	// Create modern ARM TenantsClient
	client, err := armsubscriptions.NewTenantsClient(cred, DefaultARMClientOptions())
	if err != nil {
		logger.ErrorM(fmt.Sprintf("failed to create TenantsClient: %v", err), globals.AZ_UTILS_MODULE_NAME)
		return tenants
	}

	// Create pager for listing tenants
	pager := client.NewListPager(nil)

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("failed to get tenant page: %v", err), globals.AZ_UTILS_MODULE_NAME)
			}
			break
		}

		for _, t := range page.Value {
			// Ensure DisplayName is never nil or empty
			if t.DisplayName == nil || *t.DisplayName == "" {
				// Fallback: use tenant ID as DisplayName if missing
				t.DisplayName = t.TenantID
			}
			tenants = append(tenants, t)
		}
	}

	// Cache the result before returning
	AzureDataCache.Set(cacheKey, tenants, 0)
	return tenants
}

// ------------------------- ROLE FUNCTIONS -------------------------

// GetRoleAssignmentsForPrincipal returns a list of role names assigned to a principal in the given subscription.
// Results are cached per (principalID, subscriptionID) pair. Role name resolution uses the
// cached GetRoleNameFromDefinitionID helper instead of creating a separate RoleDefinitionsClient.
func GetRoleAssignmentsForPrincipal(ctx context.Context, session *SafeSession, principalID string, subscriptionID string) ([]string, error) {
	cacheKey := AzCacheKey("role-assignments", principalID, subscriptionID)
	if cached, found := AzureDataCache.Get(cacheKey); found {
		return cached.([]string), nil
	}

	logger := internal.NewLogger()

	// Fetch ARM token from SafeSession
	armToken, err := session.GetToken("https://management.azure.com/")
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to get ARM token: %v", err), globals.AZ_UTILS_MODULE_NAME)
		return nil, fmt.Errorf("failed to get ARM token: %v", err)
	}

	cred := &StaticTokenCredential{Token: armToken}

	assignmentsClient, err := armauthorization.NewRoleAssignmentsClient(subscriptionID, cred, DefaultARMClientOptions())
	if err != nil {
		return nil, fmt.Errorf("failed to create RoleAssignments client: %v", err)
	}

	var roles []string

	pager := assignmentsClient.NewListForScopePager(
		fmt.Sprintf("/subscriptions/%s", subscriptionID),
		&armauthorization.RoleAssignmentsClientListForScopeOptions{
			Filter: to.Ptr(fmt.Sprintf("principalId eq '%s'", principalID)),
		},
	)

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			logger.ErrorM(fmt.Sprintf("Error fetching role assignments: %v", err), globals.AZ_UTILS_MODULE_NAME)
			return nil, fmt.Errorf("error listing role assignments: %v", err)
		}

		for _, ra := range page.Value {
			if ra.Properties == nil || ra.Properties.RoleDefinitionID == nil {
				continue
			}

			roleDefID := *ra.Properties.RoleDefinitionID
			roleDefGUID := ParseRoleDefinitionID(roleDefID)

			// Use cached role name lookup instead of creating a separate RoleDefinitionsClient
			roleName := GetRoleNameFromDefinitionID(ctx, session, subscriptionID, roleDefID)
			displayName := fmt.Sprintf("%s (%s)", roleDefGUID, roleName)
			roles = append(roles, displayName)
		}
	}

	AzureDataCache.Set(cacheKey, roles, 0)
	return roles, nil
}

// ParseRoleDefinitionID extracts the GUID from a roleDefinitionID ARM resource string.
func ParseRoleDefinitionID(roleDefinitionID string) string {
	parts := strings.Split(roleDefinitionID, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return roleDefinitionID
}

// ListRoleAssignments enumerates role assignments for a subscription.
func ListRoleAssignments(ctx context.Context, session *SafeSession, subscriptionID string) ([]*armauthorization.RoleAssignment, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token for subscription %s: %v", subscriptionID, err)
	}

	cred := &StaticTokenCredential{Token: token}

	client, err := armauthorization.NewRoleAssignmentsClient(subscriptionID, cred, DefaultARMClientOptions())
	if err != nil {
		return nil, fmt.Errorf("failed to create role assignments client: %w", err)
	}

	var results []*armauthorization.RoleAssignment

	// Use subscription-level scope
	scope := fmt.Sprintf("/subscriptions/%s", subscriptionID)
	pager := client.NewListForScopePager(scope, &armauthorization.RoleAssignmentsClientListForScopeOptions{
		Filter: nil, // no filter, list all
	})

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return results, fmt.Errorf("failed to list role assignments: %w", err)
		}
		results = append(results, page.Value...)
	}

	return results, nil
}

