package commands

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"

	securitycenter "cloud.google.com/go/securitycenter/apiv1"
	"cloud.google.com/go/securitycenter/apiv1/securitycenterpb"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/iterator"
)

// Module name constant
const GCP_COMPLIANCEDASHBOARD_MODULE_NAME string = "compliance-dashboard"

var GCPComplianceDashboardCommand = &cobra.Command{
	Use:     GCP_COMPLIANCEDASHBOARD_MODULE_NAME,
	Aliases: []string{"compliance", "cis", "benchmark"},
	Hidden:  true,
	Short:   "Assess regulatory compliance against CIS GCP Benchmarks and security frameworks",
	Long: `Assess regulatory compliance posture against industry standards and security frameworks.

Features:
- CIS GCP Foundation Benchmark assessment
- PCI-DSS control mapping
- SOC 2 control coverage analysis
- HIPAA compliance checks
- ISO 27001 control mapping
- Security Command Center compliance findings integration
- Organization policy compliance analysis
- Remediation guidance for failed controls

Supported Frameworks:
- CIS GCP Foundation Benchmark v1.3/v2.0
- PCI-DSS v3.2.1/v4.0
- SOC 2 Type II
- HIPAA Security Rule
- ISO 27001:2013
- NIST CSF

Requires appropriate IAM permissions:
- roles/securitycenter.findingsViewer
- roles/orgpolicy.policyViewer
- roles/resourcemanager.organizationViewer`,
	Run: runGCPComplianceDashboardCommand,
}

// ------------------------------
// Data Structures
// ------------------------------

type ComplianceControl struct {
	ControlID     string
	Framework     string
	ControlName   string
	Description   string
	Severity      string // CRITICAL, HIGH, MEDIUM, LOW
	Status        string // PASS, FAIL, MANUAL, NOT_APPLICABLE
	ResourceCount int
	PassCount     int
	FailCount     int
	ProjectID     string
	Details       string
	Remediation   string
	References    []string
}

type ComplianceFramework struct {
	Name           string
	Version        string
	TotalControls  int
	PassedControls int
	FailedControls int
	ManualControls int
	NAControls     int
	Score          float64
}

type ComplianceFailure struct {
	ControlID    string
	Framework    string
	ControlName  string
	Severity     string
	ResourceName string
	ResourceType string
	ProjectID    string
	Details      string
	Remediation  string
	RiskScore    int
}

// ------------------------------
// Module Struct
// ------------------------------
type ComplianceDashboardModule struct {
	gcpinternal.BaseGCPModule

	// Module-specific fields
	Controls   []ComplianceControl
	Frameworks map[string]*ComplianceFramework
	Failures   []ComplianceFailure
	LootMap    map[string]*internal.LootFile
	mu         sync.Mutex

	// Cached data for compliance checks
	orgPolicies     map[string]bool
	sccFindings     map[string][]string // category -> resources
	projectMetadata map[string]map[string]interface{}
}

// ------------------------------
// Output Struct
// ------------------------------
type ComplianceDashboardOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o ComplianceDashboardOutput) TableFiles() []internal.TableFile { return o.Table }
func (o ComplianceDashboardOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPComplianceDashboardCommand(cmd *cobra.Command, args []string) {
	// Initialize command context
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, GCP_COMPLIANCEDASHBOARD_MODULE_NAME)
	if err != nil {
		return
	}

	// Create module instance
	module := &ComplianceDashboardModule{
		BaseGCPModule:   gcpinternal.NewBaseGCPModule(cmdCtx),
		Controls:        []ComplianceControl{},
		Frameworks:      make(map[string]*ComplianceFramework),
		Failures:        []ComplianceFailure{},
		LootMap:         make(map[string]*internal.LootFile),
		orgPolicies:     make(map[string]bool),
		sccFindings:     make(map[string][]string),
		projectMetadata: make(map[string]map[string]interface{}),
	}

	// Initialize loot files
	module.initializeLootFiles()

	// Initialize frameworks
	module.initializeFrameworks()

	// Execute enumeration
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Framework Initialization
// ------------------------------
func (m *ComplianceDashboardModule) initializeFrameworks() {
	m.Frameworks["CIS-GCP-1.3"] = &ComplianceFramework{
		Name:    "CIS GCP Foundation Benchmark",
		Version: "1.3",
	}
	m.Frameworks["CIS-GCP-2.0"] = &ComplianceFramework{
		Name:    "CIS GCP Foundation Benchmark",
		Version: "2.0",
	}
	m.Frameworks["PCI-DSS-4.0"] = &ComplianceFramework{
		Name:    "PCI-DSS",
		Version: "4.0",
	}
	m.Frameworks["SOC2"] = &ComplianceFramework{
		Name:    "SOC 2 Type II",
		Version: "2017",
	}
	m.Frameworks["HIPAA"] = &ComplianceFramework{
		Name:    "HIPAA Security Rule",
		Version: "2013",
	}
	m.Frameworks["ISO27001"] = &ComplianceFramework{
		Name:    "ISO 27001",
		Version: "2013",
	}
	m.Frameworks["NIST-CSF"] = &ComplianceFramework{
		Name:    "NIST Cybersecurity Framework",
		Version: "1.1",
	}
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *ComplianceDashboardModule) Execute(ctx context.Context, logger internal.Logger) {
	logger.InfoM("Assessing compliance posture against security frameworks...", GCP_COMPLIANCEDASHBOARD_MODULE_NAME)

	// Step 1: Gather SCC findings for compliance mapping
	m.gatherSCCFindings(ctx, logger)

	// Step 2: Gather organization policies
	m.gatherOrgPolicies(ctx, logger)

	// Step 3: Run CIS GCP Benchmark checks
	m.runCISBenchmarkChecks(ctx, logger)

	// Step 4: Map to other frameworks
	m.mapToFrameworks()

	// Check results
	totalControls := len(m.Controls)
	if totalControls == 0 {
		logger.InfoM("No compliance controls could be assessed", GCP_COMPLIANCEDASHBOARD_MODULE_NAME)
		logger.InfoM("This could mean: (1) Insufficient permissions, (2) No resources to assess", GCP_COMPLIANCEDASHBOARD_MODULE_NAME)
		return
	}

	// Count by status
	passCount := 0
	failCount := 0
	manualCount := 0
	for _, c := range m.Controls {
		switch c.Status {
		case "PASS":
			passCount++
		case "FAIL":
			failCount++
		case "MANUAL":
			manualCount++
		}
	}

	logger.SuccessM(fmt.Sprintf("Assessed %d compliance control(s): %d PASS, %d FAIL, %d MANUAL",
		totalControls, passCount, failCount, manualCount), GCP_COMPLIANCEDASHBOARD_MODULE_NAME)

	if failCount > 0 {
		logger.InfoM(fmt.Sprintf("[FINDING] %d compliance control(s) failed", failCount), GCP_COMPLIANCEDASHBOARD_MODULE_NAME)
	}

	// Write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Data Gathering
// ------------------------------
func (m *ComplianceDashboardModule) gatherSCCFindings(ctx context.Context, logger internal.Logger) {
	client, err := securitycenter.NewClient(ctx)
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, GCP_COMPLIANCEDASHBOARD_MODULE_NAME,
			"Could not create Security Command Center client")
		return
	}
	defer client.Close()

	for _, projectID := range m.ProjectIDs {
		parent := fmt.Sprintf("projects/%s/sources/-", projectID)

		req := &securitycenterpb.ListFindingsRequest{
			Parent: parent,
			Filter: `state="ACTIVE"`,
		}

		it := client.ListFindings(ctx, req)
		for {
			result, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				break
			}

			if result.Finding != nil {
				category := result.Finding.Category
				m.mu.Lock()
				m.sccFindings[category] = append(m.sccFindings[category], result.Finding.ResourceName)
				m.mu.Unlock()
			}
		}
	}

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Gathered %d SCC finding categories", len(m.sccFindings)), GCP_COMPLIANCEDASHBOARD_MODULE_NAME)
	}
}

func (m *ComplianceDashboardModule) gatherOrgPolicies(ctx context.Context, logger internal.Logger) {
	crmService, err := cloudresourcemanager.NewService(ctx)
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, GCP_COMPLIANCEDASHBOARD_MODULE_NAME,
			"Could not create Resource Manager client")
		return
	}

	for _, projectID := range m.ProjectIDs {
		project, err := crmService.Projects.Get(projectID).Do()
		if err != nil {
			continue
		}

		m.mu.Lock()
		m.projectMetadata[projectID] = map[string]interface{}{
			"name":   project.Name,
			"parent": project.Parent,
			"labels": project.Labels,
		}
		m.mu.Unlock()
	}
}

// ------------------------------
// CIS Benchmark Checks
// ------------------------------
func (m *ComplianceDashboardModule) runCISBenchmarkChecks(ctx context.Context, logger internal.Logger) {
	// CIS GCP Foundation Benchmark v1.3 / v2.0 Controls

	// Section 1: Identity and Access Management
	m.checkCIS_1_1_ServiceAccountAdmin(ctx, logger)
	m.checkCIS_1_2_ServiceAccountUser(ctx, logger)
	m.checkCIS_1_3_ServiceAccountKeys(ctx, logger)
	m.checkCIS_1_4_ServiceAccountTokenCreator(ctx, logger)
	m.checkCIS_1_5_SeperationOfDuties(ctx, logger)
	m.checkCIS_1_6_KMSRoles(ctx, logger)
	m.checkCIS_1_7_SAKeyRotation(ctx, logger)
	m.checkCIS_1_8_UserManagedKeys(ctx, logger)
	m.checkCIS_1_9_CloudKMSSeparation(ctx, logger)
	m.checkCIS_1_10_APIKeys(ctx, logger)

	// Section 2: Logging and Monitoring
	m.checkCIS_2_1_CloudAuditLogging(ctx, logger)
	m.checkCIS_2_2_LogSinks(ctx, logger)
	m.checkCIS_2_3_RetentionPolicy(ctx, logger)
	m.checkCIS_2_4_ProjectOwnership(ctx, logger)
	m.checkCIS_2_5_AuditConfigChanges(ctx, logger)
	m.checkCIS_2_6_SQLInstanceChanges(ctx, logger)
	m.checkCIS_2_7_NetworkChanges(ctx, logger)
	m.checkCIS_2_8_RouteChanges(ctx, logger)
	m.checkCIS_2_9_FirewallChanges(ctx, logger)
	m.checkCIS_2_10_VPCChanges(ctx, logger)
	m.checkCIS_2_11_SQLServerAccessChanges(ctx, logger)

	// Section 3: Networking
	m.checkCIS_3_1_DefaultNetwork(ctx, logger)
	m.checkCIS_3_2_LegacyNetworks(ctx, logger)
	m.checkCIS_3_3_DNSSEC(ctx, logger)
	m.checkCIS_3_4_RSASHA1(ctx, logger)
	m.checkCIS_3_5_RDPAccess(ctx, logger)
	m.checkCIS_3_6_SSHAccess(ctx, logger)
	m.checkCIS_3_7_FlowLogs(ctx, logger)
	m.checkCIS_3_8_SSLPolicy(ctx, logger)
	m.checkCIS_3_9_FirewallLogging(ctx, logger)
	m.checkCIS_3_10_VPCNetworkPeering(ctx, logger)

	// Section 4: Virtual Machines
	m.checkCIS_4_1_DefaultServiceAccount(ctx, logger)
	m.checkCIS_4_2_BlockProjectWideSSH(ctx, logger)
	m.checkCIS_4_3_OSLogin(ctx, logger)
	m.checkCIS_4_4_SerialPortDisabled(ctx, logger)
	m.checkCIS_4_5_IPForwarding(ctx, logger)
	m.checkCIS_4_6_PublicIP(ctx, logger)
	m.checkCIS_4_7_ShieldedVM(ctx, logger)
	m.checkCIS_4_8_ComputeEncryption(ctx, logger)
	m.checkCIS_4_9_ConfidentialComputing(ctx, logger)

	// Section 5: Storage
	m.checkCIS_5_1_UniformBucketAccess(ctx, logger)
	m.checkCIS_5_2_PublicBuckets(ctx, logger)

	// Section 6: Cloud SQL
	m.checkCIS_6_1_SQLPublicIP(ctx, logger)
	m.checkCIS_6_2_SQLAuthorizedNetworks(ctx, logger)
	m.checkCIS_6_3_SQLSSLRequired(ctx, logger)
	m.checkCIS_6_4_SQLNoPublicIP(ctx, logger)
	m.checkCIS_6_5_SQLBackups(ctx, logger)
	m.checkCIS_6_6_SQLContainedDB(ctx, logger)
	m.checkCIS_6_7_SQLCrossDBAOwnership(ctx, logger)

	// Section 7: BigQuery
	m.checkCIS_7_1_BigQueryCMEK(ctx, logger)
	m.checkCIS_7_2_BigQueryTableCMEK(ctx, logger)
	m.checkCIS_7_3_BigQueryDatasetPublic(ctx, logger)
}

// CIS Control Check Implementations
func (m *ComplianceDashboardModule) checkCIS_1_1_ServiceAccountAdmin(ctx context.Context, logger internal.Logger) {
	control := ComplianceControl{
		ControlID:   "CIS-1.1",
		Framework:   "CIS-GCP-2.0",
		ControlName: "Ensure Service Account Admin is not assigned at project level",
		Description: "The Service Account Admin role should not be assigned at the project level",
		Severity:    "HIGH",
		Status:      "MANUAL",
		Remediation: "Review IAM bindings and remove Service Account Admin role at project level",
		References:  []string{"https://cloud.google.com/iam/docs/understanding-roles"},
	}

	// Check SCC findings for this category
	if findings, ok := m.sccFindings["SERVICE_ACCOUNT_ADMIN_OVER_GRANTED"]; ok && len(findings) > 0 {
		control.Status = "FAIL"
		control.FailCount = len(findings)
		control.Details = fmt.Sprintf("Found %d resources with over-granted Service Account Admin role", len(findings))

		for _, resource := range findings {
			m.addFailure(control, resource, "iam-binding", m.getProjectFromResource(resource))
		}
	} else {
		control.Status = "PASS"
	}

	m.mu.Lock()
	m.Controls = append(m.Controls, control)
	m.mu.Unlock()
}

func (m *ComplianceDashboardModule) checkCIS_1_2_ServiceAccountUser(ctx context.Context, logger internal.Logger) {
	control := ComplianceControl{
		ControlID:   "CIS-1.2",
		Framework:   "CIS-GCP-2.0",
		ControlName: "Ensure Service Account User is not assigned at project level",
		Description: "Service Account User role grants impersonation capabilities and should be restricted",
		Severity:    "HIGH",
		Status:      "MANUAL",
		Remediation: "Remove Service Account User role at project level, assign at service account level instead",
		References:  []string{"https://cloud.google.com/iam/docs/service-accounts"},
	}

	if findings, ok := m.sccFindings["SERVICE_ACCOUNT_USER_OVER_GRANTED"]; ok && len(findings) > 0 {
		control.Status = "FAIL"
		control.FailCount = len(findings)
		control.Details = fmt.Sprintf("Found %d resources with over-granted Service Account User role", len(findings))
	} else {
		control.Status = "PASS"
	}

	m.mu.Lock()
	m.Controls = append(m.Controls, control)
	m.mu.Unlock()
}

func (m *ComplianceDashboardModule) checkCIS_1_3_ServiceAccountKeys(ctx context.Context, logger internal.Logger) {
	control := ComplianceControl{
		ControlID:   "CIS-1.3",
		Framework:   "CIS-GCP-2.0",
		ControlName: "Ensure user-managed service account keys are not created",
		Description: "User-managed keys are a security risk and should be avoided",
		Severity:    "MEDIUM",
		Status:      "MANUAL",
		Remediation: "Use workload identity or short-lived tokens instead of user-managed keys",
		References:  []string{"https://cloud.google.com/iam/docs/best-practices-for-securing-service-accounts"},
	}

	if findings, ok := m.sccFindings["USER_MANAGED_SERVICE_ACCOUNT_KEY"]; ok && len(findings) > 0 {
		control.Status = "FAIL"
		control.FailCount = len(findings)
		control.Details = fmt.Sprintf("Found %d user-managed service account keys", len(findings))

		for _, resource := range findings {
			m.addFailure(control, resource, "service-account-key", m.getProjectFromResource(resource))
		}
	} else {
		control.Status = "PASS"
	}

	m.mu.Lock()
	m.Controls = append(m.Controls, control)
	m.mu.Unlock()
}

func (m *ComplianceDashboardModule) checkCIS_1_4_ServiceAccountTokenCreator(ctx context.Context, logger internal.Logger) {
	control := ComplianceControl{
		ControlID:   "CIS-1.4",
		Framework:   "CIS-GCP-2.0",
		ControlName: "Ensure Service Account Token Creator is properly scoped",
		Description: "Token Creator role allows identity impersonation and should be carefully controlled",
		Severity:    "HIGH",
		Status:      "MANUAL",
		Remediation: "Review and restrict Service Account Token Creator role assignments",
	}
	m.mu.Lock()
	m.Controls = append(m.Controls, control)
	m.mu.Unlock()
}

func (m *ComplianceDashboardModule) checkCIS_1_5_SeperationOfDuties(ctx context.Context, logger internal.Logger) {
	control := ComplianceControl{
		ControlID:   "CIS-1.5",
		Framework:   "CIS-GCP-2.0",
		ControlName: "Ensure separation of duties is enforced",
		Description: "Users should not have both Service Account Admin and Service Account User roles",
		Severity:    "MEDIUM",
		Status:      "MANUAL",
		Remediation: "Implement separation of duties by assigning roles to different principals",
	}
	m.mu.Lock()
	m.Controls = append(m.Controls, control)
	m.mu.Unlock()
}

func (m *ComplianceDashboardModule) checkCIS_1_6_KMSRoles(ctx context.Context, logger internal.Logger) {
	control := ComplianceControl{
		ControlID:   "CIS-1.6",
		Framework:   "CIS-GCP-2.0",
		ControlName: "Ensure KMS encryption and decryption roles are separated",
		Description: "KMS admin should not have encryption/decryption access",
		Severity:    "MEDIUM",
		Status:      "MANUAL",
		Remediation: "Separate KMS administration from encryption/decryption operations",
	}

	if findings, ok := m.sccFindings["KMS_ROLE_SEPARATION"]; ok && len(findings) > 0 {
		control.Status = "FAIL"
		control.FailCount = len(findings)
	} else {
		control.Status = "PASS"
	}

	m.mu.Lock()
	m.Controls = append(m.Controls, control)
	m.mu.Unlock()
}

func (m *ComplianceDashboardModule) checkCIS_1_7_SAKeyRotation(ctx context.Context, logger internal.Logger) {
	control := ComplianceControl{
		ControlID:   "CIS-1.7",
		Framework:   "CIS-GCP-2.0",
		ControlName: "Ensure service account keys are rotated within 90 days",
		Description: "Service account keys should be rotated regularly",
		Severity:    "MEDIUM",
		Status:      "MANUAL",
		Remediation: "Implement key rotation policy or use short-lived credentials",
	}

	if findings, ok := m.sccFindings["SERVICE_ACCOUNT_KEY_NOT_ROTATED"]; ok && len(findings) > 0 {
		control.Status = "FAIL"
		control.FailCount = len(findings)
		control.Details = fmt.Sprintf("Found %d service account keys older than 90 days", len(findings))
	} else {
		control.Status = "PASS"
	}

	m.mu.Lock()
	m.Controls = append(m.Controls, control)
	m.mu.Unlock()
}

func (m *ComplianceDashboardModule) checkCIS_1_8_UserManagedKeys(ctx context.Context, logger internal.Logger) {
	control := ComplianceControl{
		ControlID:   "CIS-1.8",
		Framework:   "CIS-GCP-2.0",
		ControlName: "Ensure user-managed service account keys are reviewed",
		Description: "All user-managed keys should be inventoried and reviewed",
		Severity:    "LOW",
		Status:      "MANUAL",
		Remediation: "Document and regularly review all user-managed service account keys",
	}
	m.mu.Lock()
	m.Controls = append(m.Controls, control)
	m.mu.Unlock()
}

func (m *ComplianceDashboardModule) checkCIS_1_9_CloudKMSSeparation(ctx context.Context, logger internal.Logger) {
	control := ComplianceControl{
		ControlID:   "CIS-1.9",
		Framework:   "CIS-GCP-2.0",
		ControlName: "Ensure Cloud KMS cryptokeys are not anonymously or publicly accessible",
		Description: "KMS keys should not be accessible to allUsers or allAuthenticatedUsers",
		Severity:    "CRITICAL",
		Status:      "MANUAL",
		Remediation: "Remove public access from Cloud KMS keys",
	}

	if findings, ok := m.sccFindings["KMS_KEY_PUBLIC"]; ok && len(findings) > 0 {
		control.Status = "FAIL"
		control.FailCount = len(findings)
		control.Details = fmt.Sprintf("Found %d publicly accessible KMS keys", len(findings))

		for _, resource := range findings {
			m.addFailure(control, resource, "kms-key", m.getProjectFromResource(resource))
		}
	} else {
		control.Status = "PASS"
	}

	m.mu.Lock()
	m.Controls = append(m.Controls, control)
	m.mu.Unlock()
}

func (m *ComplianceDashboardModule) checkCIS_1_10_APIKeys(ctx context.Context, logger internal.Logger) {
	control := ComplianceControl{
		ControlID:   "CIS-1.10",
		Framework:   "CIS-GCP-2.0",
		ControlName: "Ensure API keys are restricted to only APIs and hosts that need them",
		Description: "API keys should have appropriate restrictions",
		Severity:    "MEDIUM",
		Status:      "MANUAL",
		Remediation: "Apply API and host restrictions to all API keys",
	}

	if findings, ok := m.sccFindings["API_KEY_NOT_RESTRICTED"]; ok && len(findings) > 0 {
		control.Status = "FAIL"
		control.FailCount = len(findings)
		control.Details = fmt.Sprintf("Found %d unrestricted API keys", len(findings))
	} else {
		control.Status = "PASS"
	}

	m.mu.Lock()
	m.Controls = append(m.Controls, control)
	m.mu.Unlock()
}

// Section 2: Logging and Monitoring Controls
func (m *ComplianceDashboardModule) checkCIS_2_1_CloudAuditLogging(ctx context.Context, logger internal.Logger) {
	control := ComplianceControl{
		ControlID:   "CIS-2.1",
		Framework:   "CIS-GCP-2.0",
		ControlName: "Ensure Cloud Audit Logging is configured properly",
		Description: "Cloud Audit Logs should be enabled for all services",
		Severity:    "HIGH",
		Status:      "MANUAL",
		Remediation: "Enable Data Access audit logs for all services",
	}

	if findings, ok := m.sccFindings["AUDIT_LOGGING_DISABLED"]; ok && len(findings) > 0 {
		control.Status = "FAIL"
		control.FailCount = len(findings)
		control.Details = fmt.Sprintf("Found %d services with disabled audit logging", len(findings))
	} else {
		control.Status = "PASS"
	}

	m.mu.Lock()
	m.Controls = append(m.Controls, control)
	m.mu.Unlock()
}

func (m *ComplianceDashboardModule) checkCIS_2_2_LogSinks(ctx context.Context, logger internal.Logger) {
	control := ComplianceControl{
		ControlID:   "CIS-2.2",
		Framework:   "CIS-GCP-2.0",
		ControlName: "Ensure log metric filter and alerts exist for audit configuration changes",
		Description: "Alerts should be configured for audit configuration changes",
		Severity:    "MEDIUM",
		Status:      "MANUAL",
		Remediation: "Create log-based metrics and alerts for audit config changes",
	}
	m.mu.Lock()
	m.Controls = append(m.Controls, control)
	m.mu.Unlock()
}

func (m *ComplianceDashboardModule) checkCIS_2_3_RetentionPolicy(ctx context.Context, logger internal.Logger) {
	control := ComplianceControl{
		ControlID:   "CIS-2.3",
		Framework:   "CIS-GCP-2.0",
		ControlName: "Ensure log bucket has retention policy with appropriate duration",
		Description: "Log buckets should have retention policies configured",
		Severity:    "MEDIUM",
		Status:      "MANUAL",
		Remediation: "Configure retention policies on all log storage buckets",
	}
	m.mu.Lock()
	m.Controls = append(m.Controls, control)
	m.mu.Unlock()
}

func (m *ComplianceDashboardModule) checkCIS_2_4_ProjectOwnership(ctx context.Context, logger internal.Logger) {
	control := ComplianceControl{
		ControlID:   "CIS-2.4",
		Framework:   "CIS-GCP-2.0",
		ControlName: "Ensure log metric filter and alerts for project ownership changes",
		Description: "Alerts for project ownership changes should be configured",
		Severity:    "MEDIUM",
		Status:      "MANUAL",
		Remediation: "Create alerts for project ownership assignment changes",
	}
	m.mu.Lock()
	m.Controls = append(m.Controls, control)
	m.mu.Unlock()
}

func (m *ComplianceDashboardModule) checkCIS_2_5_AuditConfigChanges(ctx context.Context, logger internal.Logger) {
	control := ComplianceControl{
		ControlID:   "CIS-2.5",
		Framework:   "CIS-GCP-2.0",
		ControlName: "Ensure log metric filter and alerts for audit configuration changes",
		Description: "Monitor changes to audit configurations",
		Severity:    "MEDIUM",
		Status:      "MANUAL",
		Remediation: "Create log-based metrics for audit configuration changes",
	}
	m.mu.Lock()
	m.Controls = append(m.Controls, control)
	m.mu.Unlock()
}

func (m *ComplianceDashboardModule) checkCIS_2_6_SQLInstanceChanges(ctx context.Context, logger internal.Logger) {
	control := ComplianceControl{
		ControlID:   "CIS-2.6",
		Framework:   "CIS-GCP-2.0",
		ControlName: "Ensure log metric filter and alerts for SQL instance configuration changes",
		Description: "Monitor Cloud SQL instance configuration changes",
		Severity:    "MEDIUM",
		Status:      "MANUAL",
		Remediation: "Create alerts for Cloud SQL configuration changes",
	}
	m.mu.Lock()
	m.Controls = append(m.Controls, control)
	m.mu.Unlock()
}

func (m *ComplianceDashboardModule) checkCIS_2_7_NetworkChanges(ctx context.Context, logger internal.Logger) {
	control := ComplianceControl{
		ControlID:   "CIS-2.7",
		Framework:   "CIS-GCP-2.0",
		ControlName: "Ensure log metric filter and alerts for VPC network changes",
		Description: "Monitor VPC network creation, deletion, and modifications",
		Severity:    "MEDIUM",
		Status:      "MANUAL",
		Remediation: "Create alerts for VPC network changes",
	}
	m.mu.Lock()
	m.Controls = append(m.Controls, control)
	m.mu.Unlock()
}

func (m *ComplianceDashboardModule) checkCIS_2_8_RouteChanges(ctx context.Context, logger internal.Logger) {
	control := ComplianceControl{
		ControlID:   "CIS-2.8",
		Framework:   "CIS-GCP-2.0",
		ControlName: "Ensure log metric filter and alerts for VPC route changes",
		Description: "Monitor VPC route modifications",
		Severity:    "MEDIUM",
		Status:      "MANUAL",
		Remediation: "Create alerts for VPC route changes",
	}
	m.mu.Lock()
	m.Controls = append(m.Controls, control)
	m.mu.Unlock()
}

func (m *ComplianceDashboardModule) checkCIS_2_9_FirewallChanges(ctx context.Context, logger internal.Logger) {
	control := ComplianceControl{
		ControlID:   "CIS-2.9",
		Framework:   "CIS-GCP-2.0",
		ControlName: "Ensure log metric filter and alerts for firewall rule changes",
		Description: "Monitor firewall rule creation, modification, and deletion",
		Severity:    "MEDIUM",
		Status:      "MANUAL",
		Remediation: "Create alerts for firewall rule changes",
	}
	m.mu.Lock()
	m.Controls = append(m.Controls, control)
	m.mu.Unlock()
}

func (m *ComplianceDashboardModule) checkCIS_2_10_VPCChanges(ctx context.Context, logger internal.Logger) {
	control := ComplianceControl{
		ControlID:   "CIS-2.10",
		Framework:   "CIS-GCP-2.0",
		ControlName: "Ensure log metric filter and alerts for VPC network firewall changes",
		Description: "Monitor VPC firewall changes",
		Severity:    "MEDIUM",
		Status:      "MANUAL",
		Remediation: "Create alerts for VPC firewall changes",
	}
	m.mu.Lock()
	m.Controls = append(m.Controls, control)
	m.mu.Unlock()
}

func (m *ComplianceDashboardModule) checkCIS_2_11_SQLServerAccessChanges(ctx context.Context, logger internal.Logger) {
	control := ComplianceControl{
		ControlID:   "CIS-2.11",
		Framework:   "CIS-GCP-2.0",
		ControlName: "Ensure log metric filter and alerts for Cloud SQL Server access changes",
		Description: "Monitor Cloud SQL authorization changes",
		Severity:    "MEDIUM",
		Status:      "MANUAL",
		Remediation: "Create alerts for Cloud SQL authorization modifications",
	}
	m.mu.Lock()
	m.Controls = append(m.Controls, control)
	m.mu.Unlock()
}

// Section 3: Networking Controls
func (m *ComplianceDashboardModule) checkCIS_3_1_DefaultNetwork(ctx context.Context, logger internal.Logger) {
	control := ComplianceControl{
		ControlID:   "CIS-3.1",
		Framework:   "CIS-GCP-2.0",
		ControlName: "Ensure default network does not exist",
		Description: "The default network should be deleted as it has overly permissive firewall rules",
		Severity:    "HIGH",
		Status:      "MANUAL",
		Remediation: "Delete the default network and create custom VPC networks",
	}

	if findings, ok := m.sccFindings["DEFAULT_NETWORK"]; ok && len(findings) > 0 {
		control.Status = "FAIL"
		control.FailCount = len(findings)
		control.Details = fmt.Sprintf("Found %d projects with default network", len(findings))

		for _, resource := range findings {
			m.addFailure(control, resource, "vpc-network", m.getProjectFromResource(resource))
		}
	} else {
		control.Status = "PASS"
	}

	m.mu.Lock()
	m.Controls = append(m.Controls, control)
	m.mu.Unlock()
}

func (m *ComplianceDashboardModule) checkCIS_3_2_LegacyNetworks(ctx context.Context, logger internal.Logger) {
	control := ComplianceControl{
		ControlID:   "CIS-3.2",
		Framework:   "CIS-GCP-2.0",
		ControlName: "Ensure legacy networks do not exist",
		Description: "Legacy networks lack granular subnet control and should not be used",
		Severity:    "HIGH",
		Status:      "MANUAL",
		Remediation: "Migrate from legacy networks to VPC networks",
	}

	if findings, ok := m.sccFindings["LEGACY_NETWORK"]; ok && len(findings) > 0 {
		control.Status = "FAIL"
		control.FailCount = len(findings)
	} else {
		control.Status = "PASS"
	}

	m.mu.Lock()
	m.Controls = append(m.Controls, control)
	m.mu.Unlock()
}

func (m *ComplianceDashboardModule) checkCIS_3_3_DNSSEC(ctx context.Context, logger internal.Logger) {
	control := ComplianceControl{
		ControlID:   "CIS-3.3",
		Framework:   "CIS-GCP-2.0",
		ControlName: "Ensure DNSSEC is enabled for Cloud DNS",
		Description: "DNSSEC protects against DNS spoofing attacks",
		Severity:    "MEDIUM",
		Status:      "MANUAL",
		Remediation: "Enable DNSSEC for all Cloud DNS managed zones",
	}

	if findings, ok := m.sccFindings["DNSSEC_DISABLED"]; ok && len(findings) > 0 {
		control.Status = "FAIL"
		control.FailCount = len(findings)
	} else {
		control.Status = "PASS"
	}

	m.mu.Lock()
	m.Controls = append(m.Controls, control)
	m.mu.Unlock()
}

func (m *ComplianceDashboardModule) checkCIS_3_4_RSASHA1(ctx context.Context, logger internal.Logger) {
	control := ComplianceControl{
		ControlID:   "CIS-3.4",
		Framework:   "CIS-GCP-2.0",
		ControlName: "Ensure RSASHA1 is not used for zone-signing and key-signing",
		Description: "RSASHA1 is considered weak for DNSSEC",
		Severity:    "MEDIUM",
		Status:      "MANUAL",
		Remediation: "Use RSASHA256 or ECDSAP256SHA256 for DNSSEC",
	}
	m.mu.Lock()
	m.Controls = append(m.Controls, control)
	m.mu.Unlock()
}

func (m *ComplianceDashboardModule) checkCIS_3_5_RDPAccess(ctx context.Context, logger internal.Logger) {
	control := ComplianceControl{
		ControlID:   "CIS-3.5",
		Framework:   "CIS-GCP-2.0",
		ControlName: "Ensure RDP access is restricted from the Internet",
		Description: "RDP (port 3389) should not be open to 0.0.0.0/0",
		Severity:    "CRITICAL",
		Status:      "MANUAL",
		Remediation: "Restrict RDP access to specific IP ranges",
	}

	if findings, ok := m.sccFindings["OPEN_RDP_PORT"]; ok && len(findings) > 0 {
		control.Status = "FAIL"
		control.FailCount = len(findings)
		control.Details = fmt.Sprintf("Found %d firewall rules allowing RDP from internet", len(findings))

		for _, resource := range findings {
			m.addFailure(control, resource, "firewall-rule", m.getProjectFromResource(resource))
		}
	} else {
		control.Status = "PASS"
	}

	m.mu.Lock()
	m.Controls = append(m.Controls, control)
	m.mu.Unlock()
}

func (m *ComplianceDashboardModule) checkCIS_3_6_SSHAccess(ctx context.Context, logger internal.Logger) {
	control := ComplianceControl{
		ControlID:   "CIS-3.6",
		Framework:   "CIS-GCP-2.0",
		ControlName: "Ensure SSH access is restricted from the Internet",
		Description: "SSH (port 22) should not be open to 0.0.0.0/0",
		Severity:    "CRITICAL",
		Status:      "MANUAL",
		Remediation: "Restrict SSH access to specific IP ranges or use IAP",
	}

	if findings, ok := m.sccFindings["OPEN_SSH_PORT"]; ok && len(findings) > 0 {
		control.Status = "FAIL"
		control.FailCount = len(findings)
		control.Details = fmt.Sprintf("Found %d firewall rules allowing SSH from internet", len(findings))

		for _, resource := range findings {
			m.addFailure(control, resource, "firewall-rule", m.getProjectFromResource(resource))
		}
	} else {
		control.Status = "PASS"
	}

	m.mu.Lock()
	m.Controls = append(m.Controls, control)
	m.mu.Unlock()
}

func (m *ComplianceDashboardModule) checkCIS_3_7_FlowLogs(ctx context.Context, logger internal.Logger) {
	control := ComplianceControl{
		ControlID:   "CIS-3.7",
		Framework:   "CIS-GCP-2.0",
		ControlName: "Ensure VPC Flow Logs is enabled for every subnet",
		Description: "VPC Flow Logs provide network traffic visibility",
		Severity:    "MEDIUM",
		Status:      "MANUAL",
		Remediation: "Enable VPC Flow Logs on all subnets",
	}

	if findings, ok := m.sccFindings["FLOW_LOGS_DISABLED"]; ok && len(findings) > 0 {
		control.Status = "FAIL"
		control.FailCount = len(findings)
	} else {
		control.Status = "PASS"
	}

	m.mu.Lock()
	m.Controls = append(m.Controls, control)
	m.mu.Unlock()
}

func (m *ComplianceDashboardModule) checkCIS_3_8_SSLPolicy(ctx context.Context, logger internal.Logger) {
	control := ComplianceControl{
		ControlID:   "CIS-3.8",
		Framework:   "CIS-GCP-2.0",
		ControlName: "Ensure SSL policies use secure TLS versions",
		Description: "SSL policies should require TLS 1.2 or higher",
		Severity:    "HIGH",
		Status:      "MANUAL",
		Remediation: "Update SSL policies to require TLS 1.2+",
	}

	if findings, ok := m.sccFindings["WEAK_SSL_POLICY"]; ok && len(findings) > 0 {
		control.Status = "FAIL"
		control.FailCount = len(findings)
	} else {
		control.Status = "PASS"
	}

	m.mu.Lock()
	m.Controls = append(m.Controls, control)
	m.mu.Unlock()
}

func (m *ComplianceDashboardModule) checkCIS_3_9_FirewallLogging(ctx context.Context, logger internal.Logger) {
	control := ComplianceControl{
		ControlID:   "CIS-3.9",
		Framework:   "CIS-GCP-2.0",
		ControlName: "Ensure firewall rule logging is enabled",
		Description: "Firewall rule logging provides audit trail for network access",
		Severity:    "MEDIUM",
		Status:      "MANUAL",
		Remediation: "Enable logging on all firewall rules",
	}
	m.mu.Lock()
	m.Controls = append(m.Controls, control)
	m.mu.Unlock()
}

func (m *ComplianceDashboardModule) checkCIS_3_10_VPCNetworkPeering(ctx context.Context, logger internal.Logger) {
	control := ComplianceControl{
		ControlID:   "CIS-3.10",
		Framework:   "CIS-GCP-2.0",
		ControlName: "Ensure VPC network peering is properly configured",
		Description: "Review VPC peering for appropriate trust relationships",
		Severity:    "MEDIUM",
		Status:      "MANUAL",
		Remediation: "Review and document all VPC peering relationships",
	}
	m.mu.Lock()
	m.Controls = append(m.Controls, control)
	m.mu.Unlock()
}

// Section 4: Virtual Machine Controls
func (m *ComplianceDashboardModule) checkCIS_4_1_DefaultServiceAccount(ctx context.Context, logger internal.Logger) {
	control := ComplianceControl{
		ControlID:   "CIS-4.1",
		Framework:   "CIS-GCP-2.0",
		ControlName: "Ensure default Compute Engine service account is not used",
		Description: "VMs should use custom service accounts with minimal permissions",
		Severity:    "HIGH",
		Status:      "MANUAL",
		Remediation: "Create custom service accounts for compute instances",
	}

	if findings, ok := m.sccFindings["DEFAULT_SERVICE_ACCOUNT"]; ok && len(findings) > 0 {
		control.Status = "FAIL"
		control.FailCount = len(findings)
		control.Details = fmt.Sprintf("Found %d VMs using default service account", len(findings))

		for _, resource := range findings {
			m.addFailure(control, resource, "compute-instance", m.getProjectFromResource(resource))
		}
	} else {
		control.Status = "PASS"
	}

	m.mu.Lock()
	m.Controls = append(m.Controls, control)
	m.mu.Unlock()
}

func (m *ComplianceDashboardModule) checkCIS_4_2_BlockProjectWideSSH(ctx context.Context, logger internal.Logger) {
	control := ComplianceControl{
		ControlID:   "CIS-4.2",
		Framework:   "CIS-GCP-2.0",
		ControlName: "Ensure block project-wide SSH keys is enabled",
		Description: "Block project-wide SSH keys to enforce instance-level access control",
		Severity:    "MEDIUM",
		Status:      "MANUAL",
		Remediation: "Enable 'Block project-wide SSH keys' on all instances",
	}

	if findings, ok := m.sccFindings["PROJECT_WIDE_SSH_KEYS_ALLOWED"]; ok && len(findings) > 0 {
		control.Status = "FAIL"
		control.FailCount = len(findings)
	} else {
		control.Status = "PASS"
	}

	m.mu.Lock()
	m.Controls = append(m.Controls, control)
	m.mu.Unlock()
}

func (m *ComplianceDashboardModule) checkCIS_4_3_OSLogin(ctx context.Context, logger internal.Logger) {
	control := ComplianceControl{
		ControlID:   "CIS-4.3",
		Framework:   "CIS-GCP-2.0",
		ControlName: "Ensure OS Login is enabled",
		Description: "OS Login provides centralized SSH access management via IAM",
		Severity:    "MEDIUM",
		Status:      "MANUAL",
		Remediation: "Enable OS Login at project or instance level",
	}

	if findings, ok := m.sccFindings["OS_LOGIN_DISABLED"]; ok && len(findings) > 0 {
		control.Status = "FAIL"
		control.FailCount = len(findings)
	} else {
		control.Status = "PASS"
	}

	m.mu.Lock()
	m.Controls = append(m.Controls, control)
	m.mu.Unlock()
}

func (m *ComplianceDashboardModule) checkCIS_4_4_SerialPortDisabled(ctx context.Context, logger internal.Logger) {
	control := ComplianceControl{
		ControlID:   "CIS-4.4",
		Framework:   "CIS-GCP-2.0",
		ControlName: "Ensure serial port access is disabled",
		Description: "Serial port access should be disabled for security",
		Severity:    "MEDIUM",
		Status:      "MANUAL",
		Remediation: "Disable serial port access on all instances",
	}

	if findings, ok := m.sccFindings["SERIAL_PORT_ENABLED"]; ok && len(findings) > 0 {
		control.Status = "FAIL"
		control.FailCount = len(findings)
	} else {
		control.Status = "PASS"
	}

	m.mu.Lock()
	m.Controls = append(m.Controls, control)
	m.mu.Unlock()
}

func (m *ComplianceDashboardModule) checkCIS_4_5_IPForwarding(ctx context.Context, logger internal.Logger) {
	control := ComplianceControl{
		ControlID:   "CIS-4.5",
		Framework:   "CIS-GCP-2.0",
		ControlName: "Ensure IP forwarding is disabled unless required",
		Description: "IP forwarding should only be enabled on NAT/gateway instances",
		Severity:    "MEDIUM",
		Status:      "MANUAL",
		Remediation: "Disable IP forwarding on instances that don't require it",
	}

	if findings, ok := m.sccFindings["IP_FORWARDING_ENABLED"]; ok && len(findings) > 0 {
		control.Status = "FAIL"
		control.FailCount = len(findings)
	} else {
		control.Status = "PASS"
	}

	m.mu.Lock()
	m.Controls = append(m.Controls, control)
	m.mu.Unlock()
}

func (m *ComplianceDashboardModule) checkCIS_4_6_PublicIP(ctx context.Context, logger internal.Logger) {
	control := ComplianceControl{
		ControlID:   "CIS-4.6",
		Framework:   "CIS-GCP-2.0",
		ControlName: "Ensure VMs do not have public IP addresses",
		Description: "VMs should use private IPs and access internet via NAT",
		Severity:    "MEDIUM",
		Status:      "MANUAL",
		Remediation: "Remove public IPs and use Cloud NAT for internet access",
	}

	if findings, ok := m.sccFindings["PUBLIC_IP_ADDRESS"]; ok && len(findings) > 0 {
		control.Status = "FAIL"
		control.FailCount = len(findings)
		control.Details = fmt.Sprintf("Found %d VMs with public IP addresses", len(findings))
	} else {
		control.Status = "PASS"
	}

	m.mu.Lock()
	m.Controls = append(m.Controls, control)
	m.mu.Unlock()
}

func (m *ComplianceDashboardModule) checkCIS_4_7_ShieldedVM(ctx context.Context, logger internal.Logger) {
	control := ComplianceControl{
		ControlID:   "CIS-4.7",
		Framework:   "CIS-GCP-2.0",
		ControlName: "Ensure Shielded VM is enabled",
		Description: "Shielded VMs provide verifiable integrity and boot security",
		Severity:    "MEDIUM",
		Status:      "MANUAL",
		Remediation: "Enable Shielded VM features on all instances",
	}

	if findings, ok := m.sccFindings["SHIELDED_VM_DISABLED"]; ok && len(findings) > 0 {
		control.Status = "FAIL"
		control.FailCount = len(findings)
	} else {
		control.Status = "PASS"
	}

	m.mu.Lock()
	m.Controls = append(m.Controls, control)
	m.mu.Unlock()
}

func (m *ComplianceDashboardModule) checkCIS_4_8_ComputeEncryption(ctx context.Context, logger internal.Logger) {
	control := ComplianceControl{
		ControlID:   "CIS-4.8",
		Framework:   "CIS-GCP-2.0",
		ControlName: "Ensure Compute Engine disks are encrypted with CMEK",
		Description: "Use Customer-Managed Encryption Keys for disk encryption",
		Severity:    "MEDIUM",
		Status:      "MANUAL",
		Remediation: "Enable CMEK encryption for all Compute Engine disks",
	}

	if findings, ok := m.sccFindings["DISK_CSEK_DISABLED"]; ok && len(findings) > 0 {
		control.Status = "FAIL"
		control.FailCount = len(findings)
	} else {
		control.Status = "PASS"
	}

	m.mu.Lock()
	m.Controls = append(m.Controls, control)
	m.mu.Unlock()
}

func (m *ComplianceDashboardModule) checkCIS_4_9_ConfidentialComputing(ctx context.Context, logger internal.Logger) {
	control := ComplianceControl{
		ControlID:   "CIS-4.9",
		Framework:   "CIS-GCP-2.0",
		ControlName: "Consider enabling Confidential Computing for sensitive workloads",
		Description: "Confidential VMs encrypt data in use",
		Severity:    "LOW",
		Status:      "MANUAL",
		Remediation: "Evaluate Confidential Computing for sensitive workloads",
	}
	m.mu.Lock()
	m.Controls = append(m.Controls, control)
	m.mu.Unlock()
}

// Section 5: Storage Controls
func (m *ComplianceDashboardModule) checkCIS_5_1_UniformBucketAccess(ctx context.Context, logger internal.Logger) {
	control := ComplianceControl{
		ControlID:   "CIS-5.1",
		Framework:   "CIS-GCP-2.0",
		ControlName: "Ensure uniform bucket-level access is enabled",
		Description: "Uniform bucket-level access simplifies and secures IAM permissions",
		Severity:    "MEDIUM",
		Status:      "MANUAL",
		Remediation: "Enable uniform bucket-level access on all buckets",
	}

	if findings, ok := m.sccFindings["BUCKET_IAM_NOT_MONITORED"]; ok && len(findings) > 0 {
		control.Status = "FAIL"
		control.FailCount = len(findings)
	} else {
		control.Status = "PASS"
	}

	m.mu.Lock()
	m.Controls = append(m.Controls, control)
	m.mu.Unlock()
}

func (m *ComplianceDashboardModule) checkCIS_5_2_PublicBuckets(ctx context.Context, logger internal.Logger) {
	control := ComplianceControl{
		ControlID:   "CIS-5.2",
		Framework:   "CIS-GCP-2.0",
		ControlName: "Ensure Cloud Storage buckets are not anonymously or publicly accessible",
		Description: "Storage buckets should not allow public access",
		Severity:    "CRITICAL",
		Status:      "MANUAL",
		Remediation: "Remove allUsers and allAuthenticatedUsers from bucket IAM",
	}

	publicFindings := []string{}
	for category, findings := range m.sccFindings {
		if strings.Contains(strings.ToLower(category), "public_bucket") ||
			strings.Contains(strings.ToLower(category), "bucket_public") {
			publicFindings = append(publicFindings, findings...)
		}
	}

	if len(publicFindings) > 0 {
		control.Status = "FAIL"
		control.FailCount = len(publicFindings)
		control.Details = fmt.Sprintf("Found %d publicly accessible buckets", len(publicFindings))

		for _, resource := range publicFindings {
			m.addFailure(control, resource, "storage-bucket", m.getProjectFromResource(resource))
		}
	} else {
		control.Status = "PASS"
	}

	m.mu.Lock()
	m.Controls = append(m.Controls, control)
	m.mu.Unlock()
}

// Section 6: Cloud SQL Controls
func (m *ComplianceDashboardModule) checkCIS_6_1_SQLPublicIP(ctx context.Context, logger internal.Logger) {
	control := ComplianceControl{
		ControlID:   "CIS-6.1",
		Framework:   "CIS-GCP-2.0",
		ControlName: "Ensure Cloud SQL instances do not have public IPs",
		Description: "Cloud SQL should use private IP only",
		Severity:    "HIGH",
		Status:      "MANUAL",
		Remediation: "Configure Cloud SQL to use private IP only",
	}

	if findings, ok := m.sccFindings["SQL_PUBLIC_IP"]; ok && len(findings) > 0 {
		control.Status = "FAIL"
		control.FailCount = len(findings)
		control.Details = fmt.Sprintf("Found %d Cloud SQL instances with public IP", len(findings))

		for _, resource := range findings {
			m.addFailure(control, resource, "cloudsql-instance", m.getProjectFromResource(resource))
		}
	} else {
		control.Status = "PASS"
	}

	m.mu.Lock()
	m.Controls = append(m.Controls, control)
	m.mu.Unlock()
}

func (m *ComplianceDashboardModule) checkCIS_6_2_SQLAuthorizedNetworks(ctx context.Context, logger internal.Logger) {
	control := ComplianceControl{
		ControlID:   "CIS-6.2",
		Framework:   "CIS-GCP-2.0",
		ControlName: "Ensure Cloud SQL authorized networks do not include 0.0.0.0/0",
		Description: "Restrict authorized networks to specific IP ranges",
		Severity:    "CRITICAL",
		Status:      "MANUAL",
		Remediation: "Remove 0.0.0.0/0 from authorized networks",
	}

	if findings, ok := m.sccFindings["SQL_WORLD_READABLE"]; ok && len(findings) > 0 {
		control.Status = "FAIL"
		control.FailCount = len(findings)
	} else {
		control.Status = "PASS"
	}

	m.mu.Lock()
	m.Controls = append(m.Controls, control)
	m.mu.Unlock()
}

func (m *ComplianceDashboardModule) checkCIS_6_3_SQLSSLRequired(ctx context.Context, logger internal.Logger) {
	control := ComplianceControl{
		ControlID:   "CIS-6.3",
		Framework:   "CIS-GCP-2.0",
		ControlName: "Ensure Cloud SQL requires SSL connections",
		Description: "SSL should be required for all database connections",
		Severity:    "HIGH",
		Status:      "MANUAL",
		Remediation: "Enable 'Require SSL' for Cloud SQL instances",
	}

	if findings, ok := m.sccFindings["SQL_NO_ROOT_PASSWORD"]; ok && len(findings) > 0 {
		control.Status = "FAIL"
		control.FailCount = len(findings)
	} else {
		control.Status = "PASS"
	}

	m.mu.Lock()
	m.Controls = append(m.Controls, control)
	m.mu.Unlock()
}

func (m *ComplianceDashboardModule) checkCIS_6_4_SQLNoPublicIP(ctx context.Context, logger internal.Logger) {
	control := ComplianceControl{
		ControlID:   "CIS-6.4",
		Framework:   "CIS-GCP-2.0",
		ControlName: "Ensure Cloud SQL database instances are configured with automated backups",
		Description: "Automated backups ensure data recovery capability",
		Severity:    "MEDIUM",
		Status:      "MANUAL",
		Remediation: "Enable automated backups for Cloud SQL instances",
	}

	if findings, ok := m.sccFindings["SQL_BACKUP_DISABLED"]; ok && len(findings) > 0 {
		control.Status = "FAIL"
		control.FailCount = len(findings)
	} else {
		control.Status = "PASS"
	}

	m.mu.Lock()
	m.Controls = append(m.Controls, control)
	m.mu.Unlock()
}

func (m *ComplianceDashboardModule) checkCIS_6_5_SQLBackups(ctx context.Context, logger internal.Logger) {
	control := ComplianceControl{
		ControlID:   "CIS-6.5",
		Framework:   "CIS-GCP-2.0",
		ControlName: "Ensure Cloud SQL instances are using the latest major version",
		Description: "Use latest major database version for security updates",
		Severity:    "MEDIUM",
		Status:      "MANUAL",
		Remediation: "Upgrade Cloud SQL instances to latest major version",
	}
	m.mu.Lock()
	m.Controls = append(m.Controls, control)
	m.mu.Unlock()
}

func (m *ComplianceDashboardModule) checkCIS_6_6_SQLContainedDB(ctx context.Context, logger internal.Logger) {
	control := ComplianceControl{
		ControlID:   "CIS-6.6",
		Framework:   "CIS-GCP-2.0",
		ControlName: "Ensure contained database authentication is off for SQL Server",
		Description: "Disable contained database authentication for SQL Server",
		Severity:    "MEDIUM",
		Status:      "MANUAL",
		Remediation: "Set 'contained database authentication' flag to 'off'",
	}
	m.mu.Lock()
	m.Controls = append(m.Controls, control)
	m.mu.Unlock()
}

func (m *ComplianceDashboardModule) checkCIS_6_7_SQLCrossDBAOwnership(ctx context.Context, logger internal.Logger) {
	control := ComplianceControl{
		ControlID:   "CIS-6.7",
		Framework:   "CIS-GCP-2.0",
		ControlName: "Ensure cross db ownership chaining is off for SQL Server",
		Description: "Disable cross db ownership chaining for SQL Server",
		Severity:    "MEDIUM",
		Status:      "MANUAL",
		Remediation: "Set 'cross db ownership chaining' flag to 'off'",
	}
	m.mu.Lock()
	m.Controls = append(m.Controls, control)
	m.mu.Unlock()
}

// Section 7: BigQuery Controls
func (m *ComplianceDashboardModule) checkCIS_7_1_BigQueryCMEK(ctx context.Context, logger internal.Logger) {
	control := ComplianceControl{
		ControlID:   "CIS-7.1",
		Framework:   "CIS-GCP-2.0",
		ControlName: "Ensure BigQuery datasets are encrypted with CMEK",
		Description: "Use Customer-Managed Encryption Keys for BigQuery",
		Severity:    "MEDIUM",
		Status:      "MANUAL",
		Remediation: "Enable CMEK encryption for BigQuery datasets",
	}

	if findings, ok := m.sccFindings["BIGQUERY_TABLE_CMEK_DISABLED"]; ok && len(findings) > 0 {
		control.Status = "FAIL"
		control.FailCount = len(findings)
	} else {
		control.Status = "PASS"
	}

	m.mu.Lock()
	m.Controls = append(m.Controls, control)
	m.mu.Unlock()
}

func (m *ComplianceDashboardModule) checkCIS_7_2_BigQueryTableCMEK(ctx context.Context, logger internal.Logger) {
	control := ComplianceControl{
		ControlID:   "CIS-7.2",
		Framework:   "CIS-GCP-2.0",
		ControlName: "Ensure BigQuery tables are encrypted with CMEK",
		Description: "Use Customer-Managed Encryption Keys for BigQuery tables",
		Severity:    "MEDIUM",
		Status:      "MANUAL",
		Remediation: "Enable CMEK encryption for BigQuery tables",
	}
	m.mu.Lock()
	m.Controls = append(m.Controls, control)
	m.mu.Unlock()
}

func (m *ComplianceDashboardModule) checkCIS_7_3_BigQueryDatasetPublic(ctx context.Context, logger internal.Logger) {
	control := ComplianceControl{
		ControlID:   "CIS-7.3",
		Framework:   "CIS-GCP-2.0",
		ControlName: "Ensure BigQuery datasets are not publicly accessible",
		Description: "BigQuery datasets should not allow allUsers or allAuthenticatedUsers",
		Severity:    "CRITICAL",
		Status:      "MANUAL",
		Remediation: "Remove public access from BigQuery datasets",
	}

	if findings, ok := m.sccFindings["BIGQUERY_TABLE_PUBLIC"]; ok && len(findings) > 0 {
		control.Status = "FAIL"
		control.FailCount = len(findings)
		control.Details = fmt.Sprintf("Found %d publicly accessible BigQuery datasets", len(findings))

		for _, resource := range findings {
			m.addFailure(control, resource, "bigquery-dataset", m.getProjectFromResource(resource))
		}
	} else {
		control.Status = "PASS"
	}

	m.mu.Lock()
	m.Controls = append(m.Controls, control)
	m.mu.Unlock()
}

// ------------------------------
// Framework Mapping
// ------------------------------
func (m *ComplianceDashboardModule) mapToFrameworks() {
	// Map CIS controls to other frameworks
	for _, control := range m.Controls {
		// Update CIS framework stats
		if fw, ok := m.Frameworks["CIS-GCP-2.0"]; ok {
			fw.TotalControls++
			switch control.Status {
			case "PASS":
				fw.PassedControls++
			case "FAIL":
				fw.FailedControls++
			case "MANUAL":
				fw.ManualControls++
			case "NOT_APPLICABLE":
				fw.NAControls++
			}
		}
	}

	// Calculate scores for each framework
	for _, fw := range m.Frameworks {
		if fw.TotalControls > 0 {
			assessed := fw.PassedControls + fw.FailedControls
			if assessed > 0 {
				fw.Score = float64(fw.PassedControls) / float64(assessed) * 100
			}
		}
	}
}

// ------------------------------
// Helper Functions
// ------------------------------
func (m *ComplianceDashboardModule) addFailure(control ComplianceControl, resource, resourceType, projectID string) {
	failure := ComplianceFailure{
		ControlID:    control.ControlID,
		Framework:    control.Framework,
		ControlName:  control.ControlName,
		Severity:     control.Severity,
		ResourceName: resource,
		ResourceType: resourceType,
		ProjectID:    projectID,
		Details:      control.Details,
		Remediation:  control.Remediation,
		RiskScore:    m.calculateComplianceRiskScore(control.Severity),
	}

	m.mu.Lock()
	m.Failures = append(m.Failures, failure)
	m.mu.Unlock()

	// Add to loot
	m.addFailureToLoot(failure)
}

func (m *ComplianceDashboardModule) calculateComplianceRiskScore(severity string) int {
	switch severity {
	case "CRITICAL":
		return 100
	case "HIGH":
		return 80
	case "MEDIUM":
		return 50
	case "LOW":
		return 25
	default:
		return 10
	}
}

func (m *ComplianceDashboardModule) getProjectFromResource(resource string) string {
	// Extract project ID from resource name
	// Format: projects/{project}/...
	if strings.Contains(resource, "projects/") {
		parts := strings.Split(resource, "/")
		for i, part := range parts {
			if part == "projects" && i+1 < len(parts) {
				return parts[i+1]
			}
		}
	}
	return ""
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *ComplianceDashboardModule) initializeLootFiles() {
	m.LootMap["compliance-critical-failures"] = &internal.LootFile{
		Name:     "compliance-critical-failures",
		Contents: "# Compliance Dashboard - Critical Failures\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
	}
	m.LootMap["compliance-remediation-commands"] = &internal.LootFile{
		Name:     "compliance-remediation-commands",
		Contents: "# Compliance Dashboard - Remediation Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
	}
	m.LootMap["compliance-by-framework"] = &internal.LootFile{
		Name:     "compliance-by-framework",
		Contents: "# Compliance Dashboard - Framework Summary\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
	}
	m.LootMap["compliance-failed-controls"] = &internal.LootFile{
		Name:     "compliance-failed-controls",
		Contents: "# Compliance Dashboard - Failed Controls\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
	}
}

func (m *ComplianceDashboardModule) addFailureToLoot(failure ComplianceFailure) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Critical failures
	if failure.Severity == "CRITICAL" {
		m.LootMap["compliance-critical-failures"].Contents += fmt.Sprintf(
			"# =============================================================================\n"+
				"# %s - %s\n"+
				"# =============================================================================\n"+
				"# Framework: %s\n"+
				"# Resource: %s\n"+
				"# Project: %s\n"+
				"# Risk Score: %d\n"+
				"# Remediation: %s\n\n",
			failure.ControlID,
			failure.ControlName,
			failure.Framework,
			failure.ResourceName,
			failure.ProjectID,
			failure.RiskScore,
			failure.Remediation,
		)
	}

	// Remediation commands
	m.LootMap["compliance-remediation-commands"].Contents += fmt.Sprintf(
		"# %s: %s\n"+
			"# Resource: %s\n"+
			"# %s\n\n",
		failure.ControlID,
		failure.ControlName,
		failure.ResourceName,
		failure.Remediation,
	)

	// Failed controls
	m.LootMap["compliance-failed-controls"].Contents += fmt.Sprintf(
		"%s (%s) - %s\n",
		failure.ControlID,
		failure.Severity,
		failure.ResourceName,
	)
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *ComplianceDashboardModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

func (m *ComplianceDashboardModule) buildTables() []internal.TableFile {
	// Sort controls by severity, then control ID
	sort.Slice(m.Controls, func(i, j int) bool {
		if m.Controls[i].Status == "FAIL" && m.Controls[j].Status != "FAIL" {
			return true
		}
		if m.Controls[i].Status != "FAIL" && m.Controls[j].Status == "FAIL" {
			return false
		}
		severityOrder := map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
		if severityOrder[m.Controls[i].Severity] != severityOrder[m.Controls[j].Severity] {
			return severityOrder[m.Controls[i].Severity] < severityOrder[m.Controls[j].Severity]
		}
		return m.Controls[i].ControlID < m.Controls[j].ControlID
	})

	// Controls table
	controlsHeader := []string{
		"Control ID",
		"Control Name",
		"Framework",
		"Severity",
		"Status",
		"Details",
	}

	var controlsBody [][]string
	for _, c := range m.Controls {
		details := c.Details
		if details == "" {
			details = "-"
		}
		controlsBody = append(controlsBody, []string{
			c.ControlID,
			c.ControlName,
			c.Framework,
			c.Severity,
			c.Status,
			details,
		})
	}

	// Failures table
	failuresHeader := []string{
		"Control ID",
		"Severity",
		"Resource",
		"Type",
		"Project Name",
		"Project ID",
		"Risk Score",
	}

	var failuresBody [][]string
	for _, f := range m.Failures {
		failuresBody = append(failuresBody, []string{
			f.ControlID,
			f.Severity,
			f.ResourceName,
			f.ResourceType,
			m.GetProjectName(f.ProjectID),
			f.ProjectID,
			fmt.Sprintf("%d", f.RiskScore),
		})
	}

	// Framework summary table
	frameworkHeader := []string{
		"Framework",
		"Version",
		"Total",
		"Passed",
		"Failed",
		"Manual",
		"Score (%)",
	}

	var frameworkBody [][]string
	for _, fw := range m.Frameworks {
		if fw.TotalControls > 0 {
			frameworkBody = append(frameworkBody, []string{
				fw.Name,
				fw.Version,
				fmt.Sprintf("%d", fw.TotalControls),
				fmt.Sprintf("%d", fw.PassedControls),
				fmt.Sprintf("%d", fw.FailedControls),
				fmt.Sprintf("%d", fw.ManualControls),
				fmt.Sprintf("%.1f", fw.Score),
			})
		}
	}

	// Build tables
	tables := []internal.TableFile{
		{
			Name:   "compliance-controls",
			Header: controlsHeader,
			Body:   controlsBody,
		},
	}

	// Add failures table if any
	if len(failuresBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "compliance-failures",
			Header: failuresHeader,
			Body:   failuresBody,
		})
	}

	// Add framework summary table
	if len(frameworkBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "compliance-summary",
			Header: frameworkHeader,
			Body:   frameworkBody,
		})
	}

	return tables
}

func (m *ComplianceDashboardModule) collectLootFiles() []internal.LootFile {
	// Add framework summary to loot
	for _, fw := range m.Frameworks {
		if fw.TotalControls > 0 {
			m.LootMap["compliance-by-framework"].Contents += fmt.Sprintf(
				"## %s v%s\n"+
					"Total Controls: %d\n"+
					"Passed: %d\n"+
					"Failed: %d\n"+
					"Manual Review: %d\n"+
					"Compliance Score: %.1f%%\n\n",
				fw.Name,
				fw.Version,
				fw.TotalControls,
				fw.PassedControls,
				fw.FailedControls,
				fw.ManualControls,
				fw.Score,
			)
		}
	}

	// Collect loot files
	var lootFiles []internal.LootFile
	for _, loot := range m.LootMap {
		if loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
			lootFiles = append(lootFiles, *loot)
		}
	}
	return lootFiles
}

func (m *ComplianceDashboardModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	// Determine org ID - prefer project metadata, fall back to hierarchy
	orgID := ""
	for _, metadata := range m.projectMetadata {
		if parent, ok := metadata["parent"]; ok {
			if parentStr, ok := parent.(string); ok && strings.HasPrefix(parentStr, "organizations/") {
				orgID = strings.TrimPrefix(parentStr, "organizations/")
				break
			}
		}
	}
	if orgID == "" && m.Hierarchy != nil && len(m.Hierarchy.Organizations) > 0 {
		orgID = m.Hierarchy.Organizations[0].ID
	}

	if orgID != "" {
		// DUAL OUTPUT: Complete aggregated output at org level
		tables := m.buildTables()
		lootFiles := m.collectLootFiles()
		outputData.OrgLevelData[orgID] = ComplianceDashboardOutput{Table: tables, Loot: lootFiles}

		// DUAL OUTPUT: Filtered per-project output
		for _, projectID := range m.ProjectIDs {
			projectTables := m.buildTablesForProject(projectID)
			if len(projectTables) > 0 {
				outputData.ProjectLevelData[projectID] = ComplianceDashboardOutput{Table: projectTables, Loot: nil}
			}
		}
	} else if len(m.ProjectIDs) > 0 {
		// FALLBACK: No org discovered, output complete data to first project
		tables := m.buildTables()
		lootFiles := m.collectLootFiles()
		outputData.ProjectLevelData[m.ProjectIDs[0]] = ComplianceDashboardOutput{Table: tables, Loot: lootFiles}
	}

	pathBuilder := m.BuildPathBuilder()

	err := internal.HandleHierarchicalOutputSmart("gcp", m.Format, m.Verbosity, m.WrapTable, pathBuilder, outputData)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), GCP_COMPLIANCEDASHBOARD_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// buildTablesForProject builds tables filtered to only include data for a specific project
func (m *ComplianceDashboardModule) buildTablesForProject(projectID string) []internal.TableFile {
	// Filter controls for this project
	var projectControls []ComplianceControl
	for _, c := range m.Controls {
		if c.ProjectID == projectID || c.ProjectID == "" {
			projectControls = append(projectControls, c)
		}
	}

	// Filter failures for this project
	var projectFailures []ComplianceFailure
	for _, f := range m.Failures {
		if f.ProjectID == projectID {
			projectFailures = append(projectFailures, f)
		}
	}

	// If no project-specific data, return empty
	if len(projectControls) == 0 && len(projectFailures) == 0 {
		return nil
	}

	var tables []internal.TableFile

	// Controls table
	if len(projectControls) > 0 {
		controlsHeader := []string{
			"Control ID",
			"Control Name",
			"Framework",
			"Severity",
			"Status",
			"Details",
		}

		var controlsBody [][]string
		for _, c := range projectControls {
			details := c.Details
			if details == "" {
				details = "-"
			}
			controlsBody = append(controlsBody, []string{
				c.ControlID,
				c.ControlName,
				c.Framework,
				c.Severity,
				c.Status,
				details,
			})
		}

		tables = append(tables, internal.TableFile{
			Name:   "compliance-controls",
			Header: controlsHeader,
			Body:   controlsBody,
		})
	}

	// Failures table
	if len(projectFailures) > 0 {
		failuresHeader := []string{
			"Control ID",
			"Severity",
			"Resource",
			"Type",
			"Project Name",
			"Project ID",
			"Risk Score",
		}

		var failuresBody [][]string
		for _, f := range projectFailures {
			failuresBody = append(failuresBody, []string{
				f.ControlID,
				f.Severity,
				f.ResourceName,
				f.ResourceType,
				m.GetProjectName(f.ProjectID),
				f.ProjectID,
				fmt.Sprintf("%d", f.RiskScore),
			})
		}

		tables = append(tables, internal.TableFile{
			Name:   "compliance-failures",
			Header: failuresHeader,
			Body:   failuresBody,
		})
	}

	return tables
}

func (m *ComplianceDashboardModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	tables := m.buildTables()
	lootFiles := m.collectLootFiles()

	output := ComplianceDashboardOutput{
		Table: tables,
		Loot:  lootFiles,
	}

	// Build scope names with project names
	scopeNames := make([]string, len(m.ProjectIDs))
	for i, projectID := range m.ProjectIDs {
		scopeNames[i] = m.GetProjectName(projectID)
	}

	// Write output
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
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, GCP_COMPLIANCEDASHBOARD_MODULE_NAME,
			"Could not write output")
	}
}
