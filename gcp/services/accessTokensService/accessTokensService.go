package accesstokensservice

import (
	"bufio"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BishopFox/cloudfox/globals"

	_ "modernc.org/sqlite"
)

// AccessToken represents a cached access token from access_tokens.db
type AccessToken struct {
	AccountID   string
	AccessToken string
	TokenExpiry time.Time
	RAPTToken   string
	IDToken     string
}

// RefreshToken represents a cached refresh token from credentials.db
type RefreshToken struct {
	AccountID    string
	RefreshToken string
	TokenURI     string
	ClientID     string
	ClientSecret string
	RAPTToken    string
	Type         string
}

// ADCCredential represents application default credentials
type ADCCredential struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RefreshToken string `json:"refresh_token"`
	Type         string `json:"type"`
	QuotaProject string `json:"quota_project_id"`
}

// GcloudProfile represents a gcloud configuration profile
type GcloudProfile struct {
	Name    string
	Account string
	Project string
}

// CredentialSummary is the unified view of a discovered credential
type CredentialSummary struct {
	Account      string
	Type         string // "access_token", "refresh_token", "adc", "sa_key"
	Source       string // file path or db name
	Validity     string // "ACTIVE", "EXPIRED", "UNKNOWN"
	HasRefresh   bool
	RAPTStatus   string // "ENROLLED", "NOT_ENROLLED", "UNKNOWN"
	Profile      string
	IsActive     bool
	Project      string
	TokenPreview string
}

// AccessTokensService reads locally cached gcloud credentials
type AccessTokensService struct {
	configDir string
}

// New creates an AccessTokensService using the default or env-overridden config dir
func New() *AccessTokensService {
	configDir := getConfigDir()
	return &AccessTokensService{configDir: configDir}
}

// getConfigDir returns the gcloud config directory, respecting CLOUDSDK_CONFIG_DIR
func getConfigDir() string {
	if dir := os.Getenv("CLOUDSDK_CONFIG_DIR"); dir != "" {
		return dir
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "gcloud")
}

// GetAllCredentials discovers all locally cached gcloud credentials
func (s *AccessTokensService) GetAllCredentials() ([]CredentialSummary, error) {
	if s.configDir == "" {
		return nil, fmt.Errorf("could not determine gcloud config directory")
	}

	var summaries []CredentialSummary

	// 1. Read access tokens from access_tokens.db
	accessTokens, err := s.readAccessTokensDB()
	if err != nil && globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		fmt.Fprintf(os.Stderr, "[access-tokens] Could not read access_tokens.db: %v\n", err)
	}

	// 2. Read refresh tokens from credentials.db
	refreshTokens, err := s.readCredentialsDB()
	if err != nil && globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		fmt.Fprintf(os.Stderr, "[access-tokens] Could not read credentials.db: %v\n", err)
	}

	// 3. Read ADC
	adc, err := s.readADC()
	if err != nil && globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		fmt.Fprintf(os.Stderr, "[access-tokens] Could not read application_default_credentials.json: %v\n", err)
	}

	// 4. Read profiles
	activeConfig := s.readActiveConfig()
	profiles := s.readAllProfiles()

	// 5. Check GOOGLE_APPLICATION_CREDENTIALS
	saKeyPath := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")

	// Build refresh token lookup by account_id
	refreshMap := make(map[string]RefreshToken)
	for _, rt := range refreshTokens {
		refreshMap[rt.AccountID] = rt
	}

	// Build profile lookup by account
	profileMap := make(map[string]GcloudProfile)
	for _, p := range profiles {
		profileMap[p.Account] = p
	}

	// Process access tokens
	for _, at := range accessTokens {
		summary := CredentialSummary{
			Account:    at.AccountID,
			Type:       "access_token",
			Source:     "access_tokens.db",
			RAPTStatus: "UNKNOWN",
		}

		// Check token validity
		if at.TokenExpiry.IsZero() {
			summary.Validity = "UNKNOWN"
		} else if time.Now().Before(at.TokenExpiry) {
			summary.Validity = "ACTIVE"
		} else {
			summary.Validity = "EXPIRED"
		}

		// Check for matching refresh token
		if rt, ok := refreshMap[at.AccountID]; ok {
			summary.HasRefresh = true
			if rt.RAPTToken != "" {
				summary.RAPTStatus = "ENROLLED"
			} else {
				summary.RAPTStatus = "NOT_ENROLLED"
			}
		}

		// Check RAPT from access token itself
		if at.RAPTToken != "" {
			summary.RAPTStatus = "ENROLLED"
		}

		// Match profile
		if p, ok := profileMap[at.AccountID]; ok {
			summary.Profile = p.Name
			summary.Project = p.Project
			summary.IsActive = (p.Name == activeConfig)
		}

		// Token preview
		if len(at.AccessToken) > 20 {
			summary.TokenPreview = at.AccessToken[:20] + "..."
		} else if at.AccessToken != "" {
			summary.TokenPreview = at.AccessToken
		}

		summaries = append(summaries, summary)
	}

	// Process refresh tokens that don't have a matching access token
	accessTokenAccounts := make(map[string]bool)
	for _, at := range accessTokens {
		accessTokenAccounts[at.AccountID] = true
	}
	for _, rt := range refreshTokens {
		if accessTokenAccounts[rt.AccountID] {
			continue // Already covered by access token entry
		}
		summary := CredentialSummary{
			Account:    rt.AccountID,
			Type:       "refresh_token",
			Source:     "credentials.db",
			Validity:   "N/A",
			HasRefresh: true,
			RAPTStatus: "UNKNOWN",
		}
		if rt.RAPTToken != "" {
			summary.RAPTStatus = "ENROLLED"
		} else {
			summary.RAPTStatus = "NOT_ENROLLED"
		}
		if p, ok := profileMap[rt.AccountID]; ok {
			summary.Profile = p.Name
			summary.Project = p.Project
			summary.IsActive = (p.Name == activeConfig)
		}
		summaries = append(summaries, summary)
	}

	// Process ADC
	if adc != nil {
		adcAccount := "application_default"
		// Try to correlate ADC with an account via refresh token hash
		if adc.RefreshToken != "" {
			hash := sha256Hash(adc.RefreshToken)
			for _, rt := range refreshTokens {
				if rt.RefreshToken != "" && sha256Hash(rt.RefreshToken) == hash {
					adcAccount = rt.AccountID
					break
				}
			}
		}
		summary := CredentialSummary{
			Account:    adcAccount,
			Type:       "adc",
			Source:     "application_default_credentials.json",
			Validity:   "N/A",
			HasRefresh: adc.RefreshToken != "",
			RAPTStatus: "UNKNOWN",
			Project:    adc.QuotaProject,
		}
		if p, ok := profileMap[adcAccount]; ok {
			summary.Profile = p.Name
			summary.IsActive = (p.Name == activeConfig)
		}
		summaries = append(summaries, summary)
	}

	// Process SA key file from GOOGLE_APPLICATION_CREDENTIALS
	if saKeyPath != "" {
		if _, err := os.Stat(saKeyPath); err == nil {
			summary := CredentialSummary{
				Account:    "GOOGLE_APPLICATION_CREDENTIALS",
				Type:       "sa_key",
				Source:     saKeyPath,
				Validity:   "ACTIVE",
				HasRefresh: false,
				RAPTStatus: "N/A",
			}
			// Try to read the SA key file for the email
			saEmail := readSAKeyEmail(saKeyPath)
			if saEmail != "" {
				summary.Account = saEmail
			}
			summaries = append(summaries, summary)
		}
	}

	return summaries, nil
}

// readAccessTokensDB reads access_tokens.db SQLite database
func (s *AccessTokensService) readAccessTokensDB() ([]AccessToken, error) {
	dbPath := filepath.Join(s.configDir, "access_tokens.db")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("file not found: %s", dbPath)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("could not open %s: %w", dbPath, err)
	}
	defer db.Close()

	rows, err := db.Query("SELECT account_id, access_token, token_expiry, rapt_token, id_token FROM access_tokens")
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}
	defer rows.Close()

	var tokens []AccessToken
	for rows.Next() {
		var t AccessToken
		var expiryStr, raptToken, idToken sql.NullString
		var accessToken sql.NullString

		err := rows.Scan(&t.AccountID, &accessToken, &expiryStr, &raptToken, &idToken)
		if err != nil {
			continue
		}

		if accessToken.Valid {
			t.AccessToken = accessToken.String
		}
		if expiryStr.Valid && expiryStr.String != "" {
			// Try multiple time formats
			for _, layout := range []string{
				time.RFC3339,
				"2006-01-02T15:04:05Z",
				"2006-01-02 15:04:05",
				time.RFC3339Nano,
			} {
				if parsed, err := time.Parse(layout, expiryStr.String); err == nil {
					t.TokenExpiry = parsed
					break
				}
			}
		}
		if raptToken.Valid {
			t.RAPTToken = raptToken.String
		}
		if idToken.Valid {
			t.IDToken = idToken.String
		}

		tokens = append(tokens, t)
	}

	return tokens, nil
}

// readCredentialsDB reads credentials.db SQLite database
func (s *AccessTokensService) readCredentialsDB() ([]RefreshToken, error) {
	dbPath := filepath.Join(s.configDir, "credentials.db")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("file not found: %s", dbPath)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("could not open %s: %w", dbPath, err)
	}
	defer db.Close()

	rows, err := db.Query("SELECT account_id, value FROM credentials")
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}
	defer rows.Close()

	var tokens []RefreshToken
	for rows.Next() {
		var accountID string
		var valueJSON sql.NullString

		err := rows.Scan(&accountID, &valueJSON)
		if err != nil {
			continue
		}

		rt := RefreshToken{
			AccountID: accountID,
		}

		if valueJSON.Valid && valueJSON.String != "" {
			var cred struct {
				RefreshToken string `json:"refresh_token"`
				TokenURI     string `json:"token_uri"`
				ClientID     string `json:"client_id"`
				ClientSecret string `json:"client_secret"`
				RAPTToken    string `json:"rapt_token"`
				Type         string `json:"type"`
			}
			if err := json.Unmarshal([]byte(valueJSON.String), &cred); err == nil {
				rt.RefreshToken = cred.RefreshToken
				rt.TokenURI = cred.TokenURI
				rt.ClientID = cred.ClientID
				rt.ClientSecret = cred.ClientSecret
				rt.RAPTToken = cred.RAPTToken
				rt.Type = cred.Type
			}
		}

		tokens = append(tokens, rt)
	}

	return tokens, nil
}

// readADC reads application_default_credentials.json
func (s *AccessTokensService) readADC() (*ADCCredential, error) {
	// Check well-known location
	adcPath := filepath.Join(s.configDir, "application_default_credentials.json")
	if _, err := os.Stat(adcPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("file not found: %s", adcPath)
	}

	data, err := os.ReadFile(adcPath)
	if err != nil {
		return nil, fmt.Errorf("could not read %s: %w", adcPath, err)
	}

	var adc ADCCredential
	if err := json.Unmarshal(data, &adc); err != nil {
		return nil, fmt.Errorf("could not parse %s: %w", adcPath, err)
	}

	return &adc, nil
}

// readActiveConfig reads the active_config file to determine the active profile name
func (s *AccessTokensService) readActiveConfig() string {
	path := filepath.Join(s.configDir, "active_config")
	data, err := os.ReadFile(path)
	if err != nil {
		return "default"
	}
	name := strings.TrimSpace(string(data))
	if name == "" {
		return "default"
	}
	return name
}

// readAllProfiles scans all config_* files in the configurations directory
func (s *AccessTokensService) readAllProfiles() []GcloudProfile {
	configsDir := filepath.Join(s.configDir, "configurations")
	entries, err := os.ReadDir(configsDir)
	if err != nil {
		return nil
	}

	var profiles []GcloudProfile
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, "config_") {
			continue
		}
		profileName := strings.TrimPrefix(name, "config_")
		path := filepath.Join(configsDir, name)
		profile := parseConfigFile(path, profileName)
		profiles = append(profiles, profile)
	}

	return profiles
}

// parseConfigFile reads a gcloud INI-style configuration file
func parseConfigFile(path string, profileName string) GcloudProfile {
	profile := GcloudProfile{Name: profileName}

	file, err := os.Open(path)
	if err != nil {
		return profile
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		// Skip section headers
		if strings.HasPrefix(line, "[") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "account":
			profile.Account = value
		case "project":
			profile.Project = value
		}
	}

	return profile
}

// readSAKeyEmail reads a service account key JSON file to extract the client_email
func readSAKeyEmail(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var key struct {
		ClientEmail string `json:"client_email"`
	}
	if err := json.Unmarshal(data, &key); err != nil {
		return ""
	}
	return key.ClientEmail
}

// sha256Hash computes SHA-256 hash of a string
func sha256Hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
