package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	certmanagerservice "github.com/BishopFox/cloudfox/gcp/services/certManagerService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPCertManagerCommand = &cobra.Command{
	Use:     globals.GCP_CERTMANAGER_MODULE_NAME,
	Aliases: []string{"certs", "certificates", "ssl"},
	Short:   "Enumerate SSL/TLS certificates and find expiring or misconfigured certs",
	Long: `Enumerate SSL/TLS certificates from Certificate Manager and Compute Engine.

This module finds all certificates and identifies security issues:
- Expired or soon-to-expire certificates
- Failed certificate issuance
- Wildcard certificates (higher impact if compromised)
- Self-managed certificates that need manual renewal

Security Relevance:
- Expired certificates cause outages and security warnings
- Wildcard certificates can be abused to MITM any subdomain
- Certificate domains reveal infrastructure and services
- Self-managed certs may have exposed private keys

What this module finds:
- Certificate Manager certificates (global)
- Compute Engine SSL certificates (classic)
- Certificate maps
- Expiration status
- Associated domains`,
	Run: runGCPCertManagerCommand,
}

// ------------------------------
// Module Struct
// ------------------------------
type CertManagerModule struct {
	gcpinternal.BaseGCPModule

	ProjectCertificates    map[string][]certmanagerservice.Certificate    // projectID -> certificates
	ProjectSSLCertificates map[string][]certmanagerservice.SSLCertificate // projectID -> SSL certs
	ProjectCertMaps        map[string][]certmanagerservice.CertificateMap // projectID -> cert maps
	mu                     sync.Mutex
}

// ------------------------------
// Output Struct
// ------------------------------
type CertManagerOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o CertManagerOutput) TableFiles() []internal.TableFile { return o.Table }
func (o CertManagerOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPCertManagerCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_CERTMANAGER_MODULE_NAME)
	if err != nil {
		return
	}

	module := &CertManagerModule{
		BaseGCPModule:          gcpinternal.NewBaseGCPModule(cmdCtx),
		ProjectCertificates:    make(map[string][]certmanagerservice.Certificate),
		ProjectSSLCertificates: make(map[string][]certmanagerservice.SSLCertificate),
		ProjectCertMaps:        make(map[string][]certmanagerservice.CertificateMap),
	}
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *CertManagerModule) Execute(ctx context.Context, logger internal.Logger) {
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_CERTMANAGER_MODULE_NAME, m.processProject)

	allCerts := m.getAllCertificates()
	allSSLCerts := m.getAllSSLCertificates()
	allCertMaps := m.getAllCertMaps()

	totalCerts := len(allCerts) + len(allSSLCerts)

	if totalCerts == 0 {
		logger.InfoM("No certificates found", globals.GCP_CERTMANAGER_MODULE_NAME)
		return
	}

	// Count expiring/expired certs
	expiringCount := 0
	expiredCount := 0

	for _, cert := range allCerts {
		if cert.DaysUntilExpiry < 0 {
			expiredCount++
		} else if cert.DaysUntilExpiry <= 30 {
			expiringCount++
		}
	}
	for _, cert := range allSSLCerts {
		if cert.DaysUntilExpiry < 0 {
			expiredCount++
		} else if cert.DaysUntilExpiry <= 30 {
			expiringCount++
		}
	}

	logger.SuccessM(fmt.Sprintf("Found %d certificate(s), %d map(s)",
		totalCerts, len(allCertMaps)), globals.GCP_CERTMANAGER_MODULE_NAME)

	if expiredCount > 0 {
		logger.InfoM(fmt.Sprintf("[HIGH] %d certificate(s) have EXPIRED!", expiredCount), globals.GCP_CERTMANAGER_MODULE_NAME)
	}
	if expiringCount > 0 {
		logger.InfoM(fmt.Sprintf("[MEDIUM] %d certificate(s) expire within 30 days", expiringCount), globals.GCP_CERTMANAGER_MODULE_NAME)
	}

	m.writeOutput(ctx, logger)
}

func (m *CertManagerModule) getAllCertificates() []certmanagerservice.Certificate {
	var all []certmanagerservice.Certificate
	for _, certs := range m.ProjectCertificates {
		all = append(all, certs...)
	}
	return all
}

func (m *CertManagerModule) getAllSSLCertificates() []certmanagerservice.SSLCertificate {
	var all []certmanagerservice.SSLCertificate
	for _, certs := range m.ProjectSSLCertificates {
		all = append(all, certs...)
	}
	return all
}

func (m *CertManagerModule) getAllCertMaps() []certmanagerservice.CertificateMap {
	var all []certmanagerservice.CertificateMap
	for _, maps := range m.ProjectCertMaps {
		all = append(all, maps...)
	}
	return all
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *CertManagerModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Checking certificates in project: %s", projectID), globals.GCP_CERTMANAGER_MODULE_NAME)
	}

	svc := certmanagerservice.New()

	// Get Certificate Manager certs
	certs, err := svc.GetCertificates(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_CERTMANAGER_MODULE_NAME,
			fmt.Sprintf("Could not enumerate certificates in project %s", projectID))
	}

	// Get classic SSL certs
	sslCerts, err := svc.GetSSLCertificates(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_CERTMANAGER_MODULE_NAME,
			fmt.Sprintf("Could not enumerate SSL certificates in project %s", projectID))
	}

	// Get certificate maps
	certMaps, err := svc.GetCertificateMaps(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_CERTMANAGER_MODULE_NAME,
			fmt.Sprintf("Could not enumerate certificate maps in project %s", projectID))
	}

	m.mu.Lock()
	m.ProjectCertificates[projectID] = certs
	m.ProjectSSLCertificates[projectID] = sslCerts
	m.ProjectCertMaps[projectID] = certMaps
	m.mu.Unlock()
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *CertManagerModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

func (m *CertManagerModule) getCertificatesHeader() []string {
	return []string{"Project", "Name", "Type", "Domains", "Expires", "Days Left", "Wildcard", "Expired", "Self-Managed"}
}

func (m *CertManagerModule) getCertMapsHeader() []string {
	return []string{"Project", "Name", "Location", "Entries", "Certificates"}
}

func (m *CertManagerModule) certsToTableBody(certs []certmanagerservice.Certificate, sslCerts []certmanagerservice.SSLCertificate) [][]string {
	var body [][]string

	for _, cert := range certs {
		wildcard := "No"
		if cert.Wildcard {
			wildcard = "Yes"
		}
		expired := "No"
		if cert.Expired {
			expired = "Yes"
		}
		selfManaged := "No"
		if cert.SelfManaged {
			selfManaged = "Yes"
		}

		body = append(body, []string{
			m.GetProjectName(cert.ProjectID),
			cert.Name,
			cert.Type,
			strings.Join(cert.Domains, ", "),
			cert.ExpireTime,
			fmt.Sprintf("%d", cert.DaysUntilExpiry),
			wildcard,
			expired,
			selfManaged,
		})
	}

	for _, cert := range sslCerts {
		wildcard := "No"
		if cert.Wildcard {
			wildcard = "Yes"
		}
		expired := "No"
		if cert.Expired {
			expired = "Yes"
		}
		selfManaged := "No"
		if cert.SelfManaged {
			selfManaged = "Yes"
		}

		body = append(body, []string{
			m.GetProjectName(cert.ProjectID),
			cert.Name,
			cert.Type,
			strings.Join(cert.Domains, ", "),
			cert.ExpireTime,
			fmt.Sprintf("%d", cert.DaysUntilExpiry),
			wildcard,
			expired,
			selfManaged,
		})
	}

	return body
}

func (m *CertManagerModule) certMapsToTableBody(certMaps []certmanagerservice.CertificateMap) [][]string {
	var body [][]string
	for _, certMap := range certMaps {
		body = append(body, []string{
			m.GetProjectName(certMap.ProjectID),
			certMap.Name,
			certMap.Location,
			fmt.Sprintf("%d", certMap.EntryCount),
			strings.Join(certMap.Certificates, ", "),
		})
	}
	return body
}

func (m *CertManagerModule) buildTablesForProject(projectID string) []internal.TableFile {
	var tableFiles []internal.TableFile

	certs := m.ProjectCertificates[projectID]
	sslCerts := m.ProjectSSLCertificates[projectID]
	if len(certs) > 0 || len(sslCerts) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "certificates",
			Header: m.getCertificatesHeader(),
			Body:   m.certsToTableBody(certs, sslCerts),
		})
	}

	if certMaps, ok := m.ProjectCertMaps[projectID]; ok && len(certMaps) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "certificate-maps",
			Header: m.getCertMapsHeader(),
			Body:   m.certMapsToTableBody(certMaps),
		})
	}

	return tableFiles
}

func (m *CertManagerModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	// Get all project IDs that have data
	projectIDs := make(map[string]bool)
	for projectID := range m.ProjectCertificates {
		projectIDs[projectID] = true
	}
	for projectID := range m.ProjectSSLCertificates {
		projectIDs[projectID] = true
	}
	for projectID := range m.ProjectCertMaps {
		projectIDs[projectID] = true
	}

	for projectID := range projectIDs {
		tableFiles := m.buildTablesForProject(projectID)
		outputData.ProjectLevelData[projectID] = CertManagerOutput{Table: tableFiles}
	}

	pathBuilder := m.BuildPathBuilder()

	err := internal.HandleHierarchicalOutputSmart("gcp", m.Format, m.Verbosity, m.WrapTable, pathBuilder, outputData)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), globals.GCP_CERTMANAGER_MODULE_NAME)
	}
}

func (m *CertManagerModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	allCerts := m.getAllCertificates()
	allSSLCerts := m.getAllSSLCertificates()
	allCertMaps := m.getAllCertMaps()

	var tables []internal.TableFile

	if len(allCerts) > 0 || len(allSSLCerts) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "certificates",
			Header: m.getCertificatesHeader(),
			Body:   m.certsToTableBody(allCerts, allSSLCerts),
		})
	}

	if len(allCertMaps) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "certificate-maps",
			Header: m.getCertMapsHeader(),
			Body:   m.certMapsToTableBody(allCertMaps),
		})
	}

	output := CertManagerOutput{Table: tables}

	scopeNames := make([]string, len(m.ProjectIDs))
	for i, projectID := range m.ProjectIDs {
		scopeNames[i] = m.GetProjectName(projectID)
	}

	err := internal.HandleOutputSmart("gcp", m.Format, m.OutputDirectory, m.Verbosity, m.WrapTable,
		"project", m.ProjectIDs, scopeNames, m.Account, output)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_CERTMANAGER_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
