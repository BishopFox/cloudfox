package gcpinternal

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/impersonate"
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
	uniqueID    string // Numeric unique ID from tokeninfo (issued_to/azp)
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

// NewSafeSessionWithImpersonation creates a SafeSession that generates short-lived
// tokens as the target service account. When baseTS is nil the caller's ADC is
// used as the base credential. When baseTS is provided (e.g. from a key file or
// access token session) it is used instead, enabling auth chaining like
// --key-file + --impersonate-sa or --access-token + --impersonate-sa.
func NewSafeSessionWithImpersonation(ctx context.Context, targetSA string, baseTS oauth2.TokenSource) (*SafeSession, error) {
	var opts []option.ClientOption
	if baseTS != nil {
		opts = append(opts, option.WithTokenSource(baseTS))
	}

	// Override the ADC quota project with the target SA's project. The ADC
	// file may contain a stale or deleted quota_project_id which causes the
	// IAM Credentials API call to fail with USER_PROJECT_DENIED.
	if projectID := projectFromSAEmail(targetSA); projectID != "" {
		opts = append(opts, option.WithQuotaProject(projectID))
	}

	ts, err := impersonate.CredentialsTokenSource(ctx, impersonate.CredentialsConfig{
		TargetPrincipal: targetSA,
		Scopes:          CommonScopes,
	}, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create impersonated token source for %s: %w", targetSA, err)
	}

	ss := &SafeSession{
		tokenSource:   ts,
		tokens:        make(map[string]*oauth2.Token),
		refreshBuffer: 5 * time.Minute,
		stopMonitor:   make(chan struct{}),
		email:         targetSA,
		accountType:   "serviceAccount",
	}

	// Get initial token to validate impersonation works
	token, err := ts.Token()
	if err != nil {
		return nil, fmt.Errorf("impersonation failed for %s (do you have roles/iam.serviceAccountTokenCreator?): %w", targetSA, err)
	}
	ss.currentToken = token
	ss.sessionExpiry = token.Expiry

	// Cache the token for the default scope
	ss.tokens["https://www.googleapis.com/auth/cloud-platform"] = token

	return ss, nil
}

// NewSafeSessionFromKeyFile creates a SafeSession from a service account JSON key file.
// This bypasses gcloud CLI entirely and authenticates directly using the key file.
func NewSafeSessionFromKeyFile(ctx context.Context, keyFilePath string) (*SafeSession, error) {
	keyJSON, err := os.ReadFile(keyFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file %s: %w", keyFilePath, err)
	}

	// Parse the JSON to extract the service account email and project
	var keyFileData struct {
		ClientEmail string `json:"client_email"`
		ProjectID   string `json:"project_id"`
		Type        string `json:"type"`
	}
	if err := json.Unmarshal(keyJSON, &keyFileData); err != nil {
		return nil, fmt.Errorf("failed to parse key file %s: %w", keyFilePath, err)
	}

	if keyFileData.Type != "service_account" {
		return nil, fmt.Errorf("key file %s is not a service account key (type: %s)", keyFilePath, keyFileData.Type)
	}

	if keyFileData.ClientEmail == "" {
		return nil, fmt.Errorf("key file %s does not contain a client_email field", keyFilePath)
	}

	// Create credentials from the key file
	creds, err := google.CredentialsFromJSON(ctx, keyJSON, CommonScopes...)
	if err != nil {
		return nil, fmt.Errorf("failed to create credentials from key file %s: %w", keyFilePath, err)
	}

	ss := &SafeSession{
		tokenSource:   creds.TokenSource,
		tokens:        make(map[string]*oauth2.Token),
		refreshBuffer: 5 * time.Minute,
		stopMonitor:   make(chan struct{}),
		email:         keyFileData.ClientEmail,
		accountType:   "serviceAccount",
		projectID:     keyFileData.ProjectID,
	}

	// Get initial token to validate the key works
	token, err := creds.TokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to get token from key file %s (key may be expired or revoked): %w", keyFilePath, err)
	}
	ss.currentToken = token
	ss.sessionExpiry = token.Expiry

	// Cache the token for the default scope
	ss.tokens["https://www.googleapis.com/auth/cloud-platform"] = token

	return ss, nil
}

// NewSafeSessionFromAccessToken creates a SafeSession from a raw GCP access token.
// The token cannot be refreshed, so the session will expire when the token does.
// Identity is resolved via the Google tokeninfo endpoint.
func NewSafeSessionFromAccessToken(ctx context.Context, accessToken string) (*SafeSession, error) {
	if strings.TrimSpace(accessToken) == "" {
		return nil, fmt.Errorf("access token is empty")
	}

	token := &oauth2.Token{
		AccessToken: strings.TrimSpace(accessToken),
		TokenType:   "Bearer",
	}

	ts := &StaticTokenSource{StaticToken: token}

	ss := &SafeSession{
		tokenSource:   ts,
		currentToken:  token,
		tokens:        make(map[string]*oauth2.Token),
		refreshBuffer: 5 * time.Minute,
		stopMonitor:   make(chan struct{}),
	}

	// Cache the token for the default scope
	ss.tokens["https://www.googleapis.com/auth/cloud-platform"] = token

	// Resolve identity via tokeninfo endpoint
	ss.resolveTokenIdentity(ctx, accessToken)

	return ss, nil
}

// resolveTokenIdentity tries multiple Google endpoints to determine the email
// and account type for a raw access token.
//
// Strategy:
//  1. tokeninfo v1 endpoint: returns email (if scope includes email) AND the
//     numeric unique ID (issued_to/azp) which is always present.
//  2. If email was found, done. Otherwise use the unique ID with
//     serviceAccounts.get to resolve the SA email (IAM API accepts numeric IDs
//     in the resource path: projects/-/serviceAccounts/{uniqueId}).
//  3. Fallback: userinfo endpoint, then GCP API error parsing.
//  4. If still unresolved and --project is set, ProbeIdentityWithProject lists
//     SAs in the project and matches by unique ID (called from CLI layer).
func (s *SafeSession) resolveTokenIdentity(ctx context.Context, accessToken string) {
	debug := os.Getenv("CLOUDFOX_DEBUG") != ""

	// Step 1: Call tokeninfo to get email (if available) and unique ID (always available)
	email, acctType, uniqueID, expiry := queryTokenInfoFull(ctx, accessToken)
	if debug {
		fmt.Fprintf(os.Stderr, "[debug] resolveTokenIdentity tokeninfo: email=%q acctType=%q uniqueID=%q\n", email, acctType, uniqueID)
	}

	// Store expiry and unique ID regardless of email resolution
	if !expiry.IsZero() {
		s.sessionExpiry = expiry
		s.currentToken.Expiry = expiry
	}
	if uniqueID != "" {
		s.uniqueID = uniqueID
	}

	if email != "" {
		s.email = email
		s.accountType = acctType
		return
	}

	// Step 2: Use unique ID with serviceAccounts.get to resolve SA email.
	// The IAM API accepts numeric unique IDs in place of the SA email in the
	// resource path: projects/-/serviceAccounts/{uniqueId}
	// This returns the full SA object including the email field.
	if uniqueID != "" {
		email, acctType = getSAByUniqueID(ctx, accessToken, uniqueID)
		if debug {
			fmt.Fprintf(os.Stderr, "[debug] resolveTokenIdentity getSAByUniqueID: email=%q acctType=%q\n", email, acctType)
		}
		if email != "" {
			s.email = email
			s.accountType = acctType
			return
		}
	}

	// Step 3: Fallback - userinfo endpoint (works with openid/email scopes)
	email, acctType = queryUserInfoHTTP(ctx, accessToken)
	if debug {
		fmt.Fprintf(os.Stderr, "[debug] resolveTokenIdentity userinfo: email=%q acctType=%q\n", email, acctType)
	}
	if email != "" {
		s.email = email
		s.accountType = acctType
		return
	}

	// Step 4: Fallback - GCP API error parsing
	email, acctType = probeGCPIdentity(ctx, accessToken)
	if debug {
		fmt.Fprintf(os.Stderr, "[debug] resolveTokenIdentity iam-probe: email=%q acctType=%q\n", email, acctType)
	}
	if email != "" {
		s.email = email
		s.accountType = acctType
	}
}

// getSAByUniqueID calls the IAM serviceAccounts.get endpoint using the SA's
// numeric unique ID. The IAM API accepts unique IDs in place of email in the
// resource path: projects/-/serviceAccounts/{uniqueId}
// If the caller has iam.serviceAccounts.get permission, this returns the full
// SA object including the email. This works even without knowing the project.
func getSAByUniqueID(ctx context.Context, accessToken, uniqueID string) (email, acctType string) {
	saURL := fmt.Sprintf("https://iam.googleapis.com/v1/projects/-/serviceAccounts/%s", uniqueID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, saURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	if os.Getenv("CLOUDFOX_DEBUG") != "" {
		fmt.Fprintf(os.Stderr, "[debug] getSAByUniqueID response (status %d): %s\n", resp.StatusCode, string(body))
	}

	if resp.StatusCode == http.StatusOK {
		var sa struct {
			Email    string `json:"email"`
			UniqueID string `json:"uniqueId"`
			Name     string `json:"name"`
		}
		if err := json.Unmarshal(body, &sa); err == nil && sa.Email != "" {
			return sa.Email, "serviceAccount"
		}
	}

	// On 403, the error message might contain the resolved email
	resolvedEmail, resolvedType := extractCallerFromGCPResponse(body)
	if resolvedEmail != "" {
		return resolvedEmail, resolvedType
	}
	return extractEmailFromGCPError(string(body)), "serviceAccount"
}

// queryTokenInfoFull calls the Google tokeninfo v1 endpoint and extracts email,
// account type, the numeric unique ID (issued_to/azp), and expiry.
// SA tokens from generateAccessToken always return the unique ID even when
// the email field is empty (because the token lacks the email scope).
func queryTokenInfoFull(ctx context.Context, accessToken string) (email, acctType, uniqueID string, expiry time.Time) {
	url := fmt.Sprintf("https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s", accessToken)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	if os.Getenv("CLOUDFOX_DEBUG") != "" {
		fmt.Fprintf(os.Stderr, "[debug] queryTokenInfoFull (status %d): %s\n", resp.StatusCode, string(body))
	}

	if resp.StatusCode != http.StatusOK {
		return
	}

	var info struct {
		Email    string `json:"email"`
		IssuedTo string `json:"issued_to"` // numeric unique ID of the SA/user
		Audience string `json:"audience"`
		Scope    string `json:"scope"`
		Exp      string `json:"exp"`
		// v2/v3 field names (if we switch endpoints later)
		AZP string `json:"azp"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return
	}

	if info.Email != "" {
		email = info.Email
		if strings.Contains(info.Email, ".iam.gserviceaccount.com") {
			acctType = "serviceAccount"
		} else {
			acctType = "user"
		}
	}

	// Extract unique ID: v1 uses "issued_to", v2/v3 use "azp"
	uniqueID = info.IssuedTo
	if uniqueID == "" {
		uniqueID = info.AZP
	}

	if info.Exp != "" {
		var expUnix int64
		if _, scanErr := fmt.Sscanf(info.Exp, "%d", &expUnix); scanErr == nil {
			expiry = time.Unix(expUnix, 0)
		}
	}
	return
}

// queryUserInfoHTTP calls the Google userinfo endpoint as a fallback for
// identity resolution. This works for tokens that have openid or email scopes.
func queryUserInfoHTTP(ctx context.Context, accessToken string) (email, acctType string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.googleapis.com/oauth2/v3/userinfo", nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK {
		return
	}

	var info struct {
		Email string `json:"email"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return
	}

	if info.Email != "" {
		email = info.Email
		if strings.Contains(info.Email, ".iam.gserviceaccount.com") {
			acctType = "serviceAccount"
		} else {
			acctType = "user"
		}
	}
	return
}

// probeGCPIdentity is a last-resort identity resolver that makes GCP API calls
// and attempts to extract the caller email from error responses. Most identity
// resolution is handled earlier by getSAByUniqueID (step 2) or
// matchSAByUniqueID (in ProbeIdentityWithProject). This function exists as a
// final fallback for edge cases where those approaches fail.
func probeGCPIdentity(ctx context.Context, accessToken string) (email, acctType string) {
	// Try a lightweight GCP API call and parse the error for caller identity.
	// Use compute.regions.list which often includes the caller in 403 errors.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://compute.googleapis.com/compute/v1/projects/_/regions?maxResults=1", nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	if os.Getenv("CLOUDFOX_DEBUG") != "" {
		fmt.Fprintf(os.Stderr, "[debug] probeGCPIdentity compute response (status %d): %s\n", resp.StatusCode, string(body))
	}

	return extractCallerFromGCPResponse(body)
}

// extractEmailFromGCPError extracts an email address from a GCP API error message.
// GCP error messages often contain the caller identity in patterns like:
//   - "... Caller: user@example.com ..."
//   - "... caller does not have permission ... user@example.com ..."
func extractEmailFromGCPError(msg string) string {
	// Look for email-like patterns in the error message
	// Simple approach: find strings matching X@Y.Z pattern
	parts := strings.Fields(msg)
	for _, part := range parts {
		// Clean common trailing punctuation
		part = strings.TrimRight(part, ".,;:\"'")
		if isLikelyEmail(part) {
			return part
		}
	}
	return ""
}

// isLikelyEmail checks if a string looks like an email address
func isLikelyEmail(s string) bool {
	at := strings.Index(s, "@")
	if at < 1 || at >= len(s)-1 {
		return false
	}
	dot := strings.LastIndex(s[at:], ".")
	return dot > 1
}

// ProbeIdentityWithProject attempts to resolve the session's email by making
// project-scoped GCP API calls. This is used as a fallback when tokeninfo
// endpoints return a numeric unique ID but no email (common with SA tokens
// generated via generateAccessToken with only cloud-platform scope).
//
// Strategies (in order):
//  1. List service accounts in the project and match by unique ID
//  2. Cloud Resource Manager projects.get (extracts caller from error details)
//  3. Cloud Resource Manager projects.testIamPermissions
func ProbeIdentityWithProject(ctx context.Context, session *SafeSession, projectID string) {
	if session.GetEmail() != "" {
		return // already resolved
	}

	token, err := session.GetToken(ctx)
	if err != nil || token == "" {
		return
	}

	debug := os.Getenv("CLOUDFOX_DEBUG") != ""

	// Strategy 1: List SAs in the project and match by unique ID.
	// The tokeninfo endpoint always returns the SA's numeric unique ID
	// (issued_to/azp), even when email is missing. Each SA in the project
	// has a uniqueId field. We match to find the email.
	session.mu.Lock()
	uniqueID := session.uniqueID
	session.mu.Unlock()

	if uniqueID != "" {
		email, acctType := matchSAByUniqueID(ctx, token, projectID, uniqueID)
		if debug {
			fmt.Fprintf(os.Stderr, "[debug] matchSAByUniqueID: email=%q acctType=%q\n", email, acctType)
		}
		if email != "" {
			session.mu.Lock()
			session.email = email
			session.accountType = acctType
			session.mu.Unlock()
			return
		}
	}

	// Strategy 2: projects.get - extracts caller from 403 error details
	email, acctType := probeWithCRM(ctx, token, projectID)
	if debug {
		fmt.Fprintf(os.Stderr, "[debug] probeWithCRM: email=%q acctType=%q\n", email, acctType)
	}
	if email != "" {
		session.mu.Lock()
		session.email = email
		session.accountType = acctType
		session.mu.Unlock()
		return
	}

	// Strategy 3: testIamPermissions - extracts caller from error details
	email, acctType = probeWithTestPermissions(ctx, token, projectID)
	if debug {
		fmt.Fprintf(os.Stderr, "[debug] probeWithTestPermissions: email=%q acctType=%q\n", email, acctType)
	}
	if email != "" {
		session.mu.Lock()
		session.email = email
		session.accountType = acctType
		session.mu.Unlock()
	}
}

// matchSAByUniqueID lists service accounts in a project and matches by numeric
// unique ID. The IAM API returns each SA's uniqueId field which corresponds to
// the issued_to/azp value from the tokeninfo endpoint.
func matchSAByUniqueID(ctx context.Context, accessToken, projectID, targetUniqueID string) (email, acctType string) {
	debug := os.Getenv("CLOUDFOX_DEBUG") != ""
	pageToken := ""

	for {
		url := fmt.Sprintf("https://iam.googleapis.com/v1/projects/%s/serviceAccounts?pageSize=100", projectID)
		if pageToken != "" {
			url += "&pageToken=" + pageToken
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return
		}
		req.Header.Set("Authorization", "Bearer "+accessToken)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return
		}

		if debug {
			fmt.Fprintf(os.Stderr, "[debug] matchSAByUniqueID page (status %d, project %s)\n", resp.StatusCode, projectID)
		}

		if resp.StatusCode != http.StatusOK {
			if debug {
				fmt.Fprintf(os.Stderr, "[debug] matchSAByUniqueID error: %s\n", string(body))
			}
			return
		}

		var listResp struct {
			Accounts []struct {
				Email    string `json:"email"`
				UniqueID string `json:"uniqueId"`
				Name     string `json:"name"`
			} `json:"accounts"`
			NextPageToken string `json:"nextPageToken"`
		}
		if err := json.Unmarshal(body, &listResp); err != nil {
			return
		}

		for _, sa := range listResp.Accounts {
			if sa.UniqueID == targetUniqueID {
				if debug {
					fmt.Fprintf(os.Stderr, "[debug] matchSAByUniqueID MATCH: uniqueID=%s -> email=%s\n", targetUniqueID, sa.Email)
				}
				return sa.Email, "serviceAccount"
			}
		}

		if listResp.NextPageToken == "" {
			break
		}
		pageToken = listResp.NextPageToken
	}

	if debug {
		fmt.Fprintf(os.Stderr, "[debug] matchSAByUniqueID: no match for uniqueID=%s in project %s\n", targetUniqueID, projectID)
	}
	return
}

// probeWithCRM calls cloudresourcemanager projects.get and extracts caller email
// from the response or error details.
func probeWithCRM(ctx context.Context, accessToken, projectID string) (email, acctType string) {
	url := fmt.Sprintf("https://cloudresourcemanager.googleapis.com/v1/projects/%s", projectID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	if os.Getenv("CLOUDFOX_DEBUG") != "" {
		fmt.Fprintf(os.Stderr, "[debug] probeWithCRM response (status %d): %s\n", resp.StatusCode, string(body))
	}

	return extractCallerFromGCPResponse(body)
}

// probeWithTestPermissions calls testIamPermissions on the project. This endpoint
// is commonly accessible and error responses include the caller identity.
func probeWithTestPermissions(ctx context.Context, accessToken, projectID string) (email, acctType string) {
	url := fmt.Sprintf("https://cloudresourcemanager.googleapis.com/v1/projects/%s:testIamPermissions", projectID)
	payload := `{"permissions":["resourcemanager.projects.get"]}`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(payload))
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	return extractCallerFromGCPResponse(body)
}

// extractCallerFromGCPResponse extracts a caller email from a GCP API response body.
// Works with both error responses (403/404) and success responses that may include
// the caller in audit metadata or error details.
func extractCallerFromGCPResponse(body []byte) (email, acctType string) {
	var apiResp struct {
		Error struct {
			Message string `json:"message"`
			Status  string `json:"status"`
			Details []struct {
				Type     string            `json:"@type"`
				Reason   string            `json:"reason"`
				Domain   string            `json:"domain"`
				Metadata map[string]string `json:"metadata"`
			} `json:"details"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return
	}

	// Check error details metadata for caller identity
	for _, detail := range apiResp.Error.Details {
		if detail.Type == "type.googleapis.com/google.rpc.ErrorInfo" {
			// Check common metadata keys for caller identity
			for _, key := range []string{"caller", "email", "principal", "service_account"} {
				if val, ok := detail.Metadata[key]; ok && isLikelyEmail(val) {
					email = val
					break
				}
			}
			if email != "" {
				break
			}
		}
	}

	// Fallback: scan the error message for email-like strings
	if email == "" {
		email = extractEmailFromGCPError(apiResp.Error.Message)
	}

	if email != "" {
		if strings.Contains(email, ".iam.gserviceaccount.com") {
			acctType = "serviceAccount"
		} else {
			acctType = "user"
		}
	}
	return
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

// GetTokenForScope returns a token for a specific OAuth scope.
// When using an impersonated session, this returns the impersonated token
// (which already has cloud-platform scope) rather than creating a new ADC
// token source that would bypass impersonation.
func (s *SafeSession) GetTokenForScope(ctx context.Context, scope string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check cache first
	if tok, ok := s.tokens[scope]; ok && tok.Valid() {
		return tok.AccessToken, nil
	}

	// Use the existing token source to preserve identity (ADC or impersonated).
	// The token source was created with CommonScopes which includes cloud-platform,
	// so the returned token is valid for all GCP APIs regardless of the requested scope.
	token, err := s.tokenSource.Token()
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

// RefreshSession refreshes the token and clears the cache.
// This uses the existing token source (which may be ADC or an impersonated
// token source) so it preserves the current identity.
func (s *SafeSession) RefreshSession(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Get a fresh token from the existing token source. Both ADC and
	// impersonated token sources handle refresh internally, so we just
	// need to invalidate the cached token and request a new one.
	token, err := s.tokenSource.Token()
	if err != nil {
		return fmt.Errorf("failed to refresh token: %w", err)
	}

	s.currentToken = token
	s.sessionExpiry = token.Expiry

	// Clear per-scope token cache
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

// defaultSession holds the global session set by --impersonate-sa.
// Services check this when their struct-level session is nil.
var (
	defaultSessionMu sync.RWMutex
	defaultSession   *SafeSession
)

// SetDefaultSession sets the package-level default session (called from CLI init).
func SetDefaultSession(s *SafeSession) {
	defaultSessionMu.Lock()
	defaultSession = s
	defaultSessionMu.Unlock()
}

// GetDefaultSession returns the package-level default session, or nil.
func GetDefaultSession() *SafeSession {
	defaultSessionMu.RLock()
	defer defaultSessionMu.RUnlock()
	return defaultSession
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

// projectFromSAEmail extracts the project ID from a service account email.
// e.g. "my-sa@my-project.iam.gserviceaccount.com" -> "my-project"
func projectFromSAEmail(email string) string {
	// SA emails have the form: <name>@<project>.iam.gserviceaccount.com
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 {
		return ""
	}
	domain := parts[1]
	if !strings.HasSuffix(domain, ".iam.gserviceaccount.com") {
		return ""
	}
	return strings.TrimSuffix(domain, ".iam.gserviceaccount.com")
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
