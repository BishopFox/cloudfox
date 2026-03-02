package commands

import (
	"fmt"
	"sort"
	"strings"

	accesstokensservice "github.com/BishopFox/cloudfox/gcp/services/accessTokensService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/spf13/cobra"
)

// GCPAccessTokensCommand reads locally cached gcloud credentials.
// It overrides PersistentPreRun to bypass the parent's auth/project requirements
// since it only reads local files — no GCP API calls needed.
var GCPAccessTokensCommand = &cobra.Command{
	Use:     globals.GCP_ACCESS_TOKENS_MODULE_NAME,
	Aliases: []string{"tokens", "creds"},
	Short:   "Enumerate locally cached gcloud access tokens, refresh tokens, and ADC",
	Long: `Reads locally cached gcloud credentials for post-exploitation credential discovery.

Sources checked:
  - access_tokens.db    Cached OAuth2 access tokens
  - credentials.db      Cached refresh tokens
  - application_default_credentials.json (ADC)
  - configurations/config_*   All gcloud profiles
  - active_config       Currently active profile
  - GOOGLE_APPLICATION_CREDENTIALS env var (SA key files)
  - CLOUDSDK_CONFIG_DIR env var (custom config paths)

This command reads LOCAL FILES ONLY — no GCP API calls are made.
No project flag (-p) or authentication is required.`,

	// Override PersistentPreRun to bypass the parent's auth/project resolution.
	// Cobra behavior: a child's PersistentPreRun fully replaces the parent's.
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Intentionally empty — no project flags or OAuth needed
	},
	Run: runGCPAccessTokensCommand,
}

// AccessTokensModule holds the credential discovery results
type AccessTokensModule struct {
	Credentials []accesstokensservice.CredentialSummary
	Verbosity   int
	WrapTable   bool
	OutputDir   string
	Format      string
}

// AccessTokensOutput implements internal.CloudfoxOutput
type AccessTokensOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o AccessTokensOutput) TableFiles() []internal.TableFile { return o.Table }
func (o AccessTokensOutput) LootFiles() []internal.LootFile   { return o.Loot }

func runGCPAccessTokensCommand(cmd *cobra.Command, args []string) {
	logger := internal.NewLogger()

	// Read output flags from the parent command (gcp)
	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDir, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")
	if format == "" {
		format = "all"
	}

	module := &AccessTokensModule{
		Verbosity: verbosity,
		WrapTable: wrap,
		OutputDir: outputDir,
		Format:    format,
	}

	module.Execute(logger)
}

func (m *AccessTokensModule) Execute(logger internal.Logger) {
	logger.InfoM("Searching for locally cached gcloud credentials...", globals.GCP_ACCESS_TOKENS_MODULE_NAME)

	svc := accesstokensservice.New()
	creds, err := svc.GetAllCredentials()
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error reading credentials: %v", err), globals.GCP_ACCESS_TOKENS_MODULE_NAME)
		return
	}

	if len(creds) == 0 {
		logger.InfoM("No cached credentials found", globals.GCP_ACCESS_TOKENS_MODULE_NAME)
		return
	}

	m.Credentials = creds

	// Sort: active tokens with refresh tokens first, then active-only, then expired with refresh, then rest
	sort.Slice(m.Credentials, func(i, j int) bool {
		return credSortScore(m.Credentials[i]) > credSortScore(m.Credentials[j])
	})

	logger.SuccessM(fmt.Sprintf("Found %d credential(s)", len(m.Credentials)), globals.GCP_ACCESS_TOKENS_MODULE_NAME)

	m.writeOutput(logger)
}

// credSortScore returns a numeric score for sorting (higher = more interesting to a pentester)
func credSortScore(c accesstokensservice.CredentialSummary) int {
	score := 0
	if c.Validity == "ACTIVE" {
		score += 4
	}
	if c.HasRefresh {
		score += 2
	}
	if c.IsActive {
		score += 1
	}
	return score
}

func (m *AccessTokensModule) getTableHeader() []string {
	return []string{
		"Account",
		"Type",
		"Validity",
		"Has Refresh Token",
		"RAPT Status",
		"Profile",
		"Active Profile",
		"Project",
		"Token Preview",
	}
}

func (m *AccessTokensModule) credentialsToTableBody() [][]string {
	var body [][]string
	for _, c := range m.Credentials {
		hasRefresh := "No"
		if c.HasRefresh {
			hasRefresh = "Yes"
		}
		active := "No"
		if c.IsActive {
			active = "Yes"
		}
		profile := c.Profile
		if profile == "" {
			profile = "-"
		}
		project := c.Project
		if project == "" {
			project = "-"
		}
		tokenPreview := c.TokenPreview
		if tokenPreview == "" {
			tokenPreview = "-"
		}

		body = append(body, []string{
			c.Account,
			c.Type,
			c.Validity,
			hasRefresh,
			c.RAPTStatus,
			profile,
			active,
			project,
			tokenPreview,
		})
	}
	return body
}

func (m *AccessTokensModule) writeOutput(logger internal.Logger) {
	body := m.credentialsToTableBody()

	tables := []internal.TableFile{{
		Name:   "access-tokens",
		Header: m.getTableHeader(),
		Body:   body,
	}}

	// Build loot files
	var lootFiles []internal.LootFile

	// Loot 1: Exploitation commands (curl with active access tokens)
	var exploitCmds strings.Builder
	exploitCmds.WriteString("# Active Access Token Exploitation Commands\n")
	exploitCmds.WriteString("# Generated by CloudFox\n\n")
	hasExploitCmds := false
	for _, c := range m.Credentials {
		if c.Type == "access_token" && c.Validity == "ACTIVE" && c.TokenPreview != "" {
			// We only have a preview; the full token is in the DB
			exploitCmds.WriteString(fmt.Sprintf("# Account: %s (Profile: %s, Project: %s)\n", c.Account, c.Profile, c.Project))
			exploitCmds.WriteString("# To get the full token, run:\n")
			exploitCmds.WriteString(fmt.Sprintf("#   sqlite3 ~/.config/gcloud/access_tokens.db \"SELECT access_token FROM access_tokens WHERE account_id='%s'\"\n", c.Account))
			exploitCmds.WriteString(fmt.Sprintf("# Then use it with:\n"))
			exploitCmds.WriteString(fmt.Sprintf("#   curl -H 'Authorization: Bearer <TOKEN>' https://www.googleapis.com/oauth2/v1/tokeninfo\n"))
			exploitCmds.WriteString(fmt.Sprintf("#   curl -H 'Authorization: Bearer <TOKEN>' https://cloudresourcemanager.googleapis.com/v1/projects\n\n"))
			hasExploitCmds = true
		}
		if c.Type == "sa_key" {
			exploitCmds.WriteString(fmt.Sprintf("# Service Account Key: %s\n", c.Account))
			exploitCmds.WriteString(fmt.Sprintf("# Source: %s\n", c.Source))
			exploitCmds.WriteString(fmt.Sprintf("gcloud auth activate-service-account --key-file=%s\n\n", c.Source))
			hasExploitCmds = true
		}
	}
	if hasExploitCmds {
		lootFiles = append(lootFiles, internal.LootFile{
			Name:     "access-tokens-exploitation-commands",
			Contents: exploitCmds.String(),
		})
	}

	// Loot 2: Refresh token commands
	var refreshCmds strings.Builder
	refreshCmds.WriteString("# Refresh Token Commands\n")
	refreshCmds.WriteString("# Generated by CloudFox\n")
	refreshCmds.WriteString("# Refresh tokens can be used to obtain new access tokens\n\n")
	hasRefreshCmds := false
	for _, c := range m.Credentials {
		if c.HasRefresh && (c.Type == "access_token" || c.Type == "refresh_token") {
			refreshCmds.WriteString(fmt.Sprintf("# Account: %s\n", c.Account))
			refreshCmds.WriteString("# To extract the refresh token:\n")
			refreshCmds.WriteString(fmt.Sprintf("#   sqlite3 ~/.config/gcloud/credentials.db \"SELECT value FROM credentials WHERE account_id='%s'\"\n", c.Account))
			refreshCmds.WriteString("# Then use it to get a new access token:\n")
			refreshCmds.WriteString("#   curl -s -X POST https://oauth2.googleapis.com/token \\\n")
			refreshCmds.WriteString("#     -d 'client_id=<CLIENT_ID>' \\\n")
			refreshCmds.WriteString("#     -d 'client_secret=<CLIENT_SECRET>' \\\n")
			refreshCmds.WriteString("#     -d 'refresh_token=<REFRESH_TOKEN>' \\\n")
			refreshCmds.WriteString("#     -d 'grant_type=refresh_token'\n\n")
			hasRefreshCmds = true
		}
	}
	if hasRefreshCmds {
		lootFiles = append(lootFiles, internal.LootFile{
			Name:     "access-tokens-refresh-commands",
			Contents: refreshCmds.String(),
		})
	}

	// Loot 3: ADC commands
	var adcCmds strings.Builder
	adcCmds.WriteString("# Application Default Credentials (ADC) Commands\n")
	adcCmds.WriteString("# Generated by CloudFox\n\n")
	hasADCCmds := false
	for _, c := range m.Credentials {
		if c.Type == "adc" {
			adcCmds.WriteString(fmt.Sprintf("# ADC Account: %s\n", c.Account))
			adcCmds.WriteString(fmt.Sprintf("# Source: %s\n", c.Source))
			if c.Project != "" {
				adcCmds.WriteString(fmt.Sprintf("# Quota Project: %s\n", c.Project))
			}
			adcCmds.WriteString("# ADC is used by client libraries and tools like terraform\n")
			adcCmds.WriteString("# To use these credentials:\n")
			adcCmds.WriteString("#   gcloud auth application-default print-access-token\n")
			adcCmds.WriteString("#   Or copy ~/.config/gcloud/application_default_credentials.json to your attack machine\n\n")
			hasADCCmds = true
		}
	}
	if hasADCCmds {
		lootFiles = append(lootFiles, internal.LootFile{
			Name:     "access-tokens-adc-commands",
			Contents: adcCmds.String(),
		})
	}

	output := AccessTokensOutput{Table: tables, Loot: lootFiles}

	// Use HandleOutputSmart with a local-only scope
	err := internal.HandleOutputSmart(
		"gcp",
		m.Format,
		m.OutputDir,
		m.Verbosity,
		m.WrapTable,
		"local",
		[]string{"localhost"},
		[]string{"localhost"},
		"local",
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_ACCESS_TOKENS_MODULE_NAME)
	}
}
