package gkeservice

import (
	"context"
	"fmt"
	"strings"

	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/internal/gcp/sdk"
	container "google.golang.org/api/container/v1"
)

type GKEService struct {
	session *gcpinternal.SafeSession
}

// New creates a new GKEService (legacy - uses ADC directly)
func New() *GKEService {
	return &GKEService{}
}

// NewWithSession creates a GKEService with a SafeSession for managed authentication
func NewWithSession(session *gcpinternal.SafeSession) *GKEService {
	return &GKEService{session: session}
}

// getService returns a container service, using session if available
func (gs *GKEService) getService(ctx context.Context) (*container.Service, error) {
	if gs.session != nil {
		return sdk.CachedGetContainerService(ctx, gs.session)
	}
	return container.NewService(ctx)
}

// ClusterInfo holds GKE cluster details with security-relevant information
type ClusterInfo struct {
	// Basic info
	Name        string
	ProjectID   string
	Location    string  // Zone or Region
	Status      string
	Description string

	// Version info
	CurrentMasterVersion string
	CurrentNodeVersion   string
	ReleaseChannel       string

	// Network configuration
	Network              string
	Subnetwork           string
	ClusterIPv4CIDR      string
	ServicesIPv4CIDR     string
	Endpoint             string  // Master endpoint
	PrivateCluster       bool
	MasterAuthorizedOnly bool
	MasterAuthorizedCIDRs []string

	// Security configuration
	NetworkPolicy         bool
	PodSecurityPolicy     bool  // Deprecated but may still be in use
	BinaryAuthorization   bool
	ShieldedNodes         bool
	SecureBoot            bool
	IntegrityMonitoring   bool
	WorkloadIdentity      string  // Workload Identity Pool
	NodeServiceAccount    string

	// Authentication
	LegacyABAC            bool   // Legacy ABAC authorization
	IssueClientCertificate bool
	BasicAuthEnabled      bool   // Deprecated

	// Logging and Monitoring
	LoggingService        string
	MonitoringService     string

	// Node pool info (aggregated)
	NodePoolCount         int
	TotalNodeCount        int
	AutoscalingEnabled    bool

	// GKE Autopilot
	Autopilot             bool

	// Node Auto-provisioning
	NodeAutoProvisioning  bool

	// Maintenance configuration
	MaintenanceWindow     string
	MaintenanceExclusions []string

	// Addons
	ConfigConnector       bool
	IstioEnabled          bool    // Anthos Service Mesh / Istio

	// Security issues detected
	SecurityIssues        []string
}

// NodePoolInfo holds node pool details
type NodePoolInfo struct {
	ClusterName       string
	Name              string
	ProjectID         string
	Location          string
	Status            string
	NodeCount         int
	MachineType       string
	DiskSizeGb        int64
	DiskType          string
	ImageType         string
	ServiceAccount    string
	AutoRepair        bool
	AutoUpgrade       bool
	SecureBoot        bool
	IntegrityMonitoring bool
	Preemptible       bool
	Spot              bool
	OAuthScopes       []string
	// Pentest-specific fields
	HasCloudPlatformScope bool     // Full access to GCP
	ScopeSummary          string   // Human-readable scope summary (e.g., "Full Access", "Restricted")
	RiskyScopes          []string // Scopes that enable attacks
}

// Clusters retrieves all GKE clusters in a project
func (gs *GKEService) Clusters(projectID string) ([]ClusterInfo, []NodePoolInfo, error) {
	ctx := context.Background()

	service, err := gs.getService(ctx)
	if err != nil {
		return nil, nil, gcpinternal.ParseGCPError(err, "container.googleapis.com")
	}

	// List clusters across all locations
	parent := fmt.Sprintf("projects/%s/locations/-", projectID)

	resp, err := service.Projects.Locations.Clusters.List(parent).Do()
	if err != nil {
		return nil, nil, gcpinternal.ParseGCPError(err, "container.googleapis.com")
	}

	var clusters []ClusterInfo
	var nodePools []NodePoolInfo

	for _, cluster := range resp.Clusters {
		info := parseClusterInfo(cluster, projectID)
		clusters = append(clusters, info)

		// Parse node pools
		for _, np := range cluster.NodePools {
			npInfo := parseNodePoolInfo(np, cluster.Name, projectID, cluster.Location)
			nodePools = append(nodePools, npInfo)
		}
	}

	return clusters, nodePools, nil
}

// parseClusterInfo extracts security-relevant information from a GKE cluster
func parseClusterInfo(cluster *container.Cluster, projectID string) ClusterInfo {
	info := ClusterInfo{
		Name:                  cluster.Name,
		ProjectID:             projectID,
		Location:              cluster.Location,
		Status:                cluster.Status,
		Description:           cluster.Description,
		CurrentMasterVersion:  cluster.CurrentMasterVersion,
		CurrentNodeVersion:    cluster.CurrentNodeVersion,
		Endpoint:              cluster.Endpoint,
		Network:               cluster.Network,
		Subnetwork:            cluster.Subnetwork,
		ClusterIPv4CIDR:       cluster.ClusterIpv4Cidr,
		ServicesIPv4CIDR:      cluster.ServicesIpv4Cidr,
		LoggingService:        cluster.LoggingService,
		MonitoringService:     cluster.MonitoringService,
		SecurityIssues:        []string{},
	}

	// Release channel
	if cluster.ReleaseChannel != nil {
		info.ReleaseChannel = cluster.ReleaseChannel.Channel
	}

	// Private cluster configuration
	if cluster.PrivateClusterConfig != nil {
		info.PrivateCluster = cluster.PrivateClusterConfig.EnablePrivateNodes
		if cluster.PrivateClusterConfig.EnablePrivateEndpoint {
			info.Endpoint = cluster.PrivateClusterConfig.PrivateEndpoint
		}
	}

	// Master authorized networks
	if cluster.MasterAuthorizedNetworksConfig != nil {
		info.MasterAuthorizedOnly = cluster.MasterAuthorizedNetworksConfig.Enabled
		for _, cidr := range cluster.MasterAuthorizedNetworksConfig.CidrBlocks {
			info.MasterAuthorizedCIDRs = append(info.MasterAuthorizedCIDRs, cidr.CidrBlock)
		}
	}

	// Network policy
	if cluster.NetworkPolicy != nil {
		info.NetworkPolicy = cluster.NetworkPolicy.Enabled
	}

	// Binary authorization
	if cluster.BinaryAuthorization != nil {
		info.BinaryAuthorization = cluster.BinaryAuthorization.Enabled
	}

	// Shielded nodes
	if cluster.ShieldedNodes != nil {
		info.ShieldedNodes = cluster.ShieldedNodes.Enabled
	}

	// Workload Identity
	if cluster.WorkloadIdentityConfig != nil {
		info.WorkloadIdentity = cluster.WorkloadIdentityConfig.WorkloadPool
	}

	// Legacy ABAC (should be disabled)
	if cluster.LegacyAbac != nil {
		info.LegacyABAC = cluster.LegacyAbac.Enabled
	}

	// Master auth (legacy)
	if cluster.MasterAuth != nil {
		info.IssueClientCertificate = cluster.MasterAuth.ClientCertificateConfig != nil &&
			cluster.MasterAuth.ClientCertificateConfig.IssueClientCertificate
		// Check for basic auth (deprecated)
		if cluster.MasterAuth.Username != "" {
			info.BasicAuthEnabled = true
		}
	}

	// Count node pools and nodes
	info.NodePoolCount = len(cluster.NodePools)
	for _, np := range cluster.NodePools {
		if np.Autoscaling != nil && np.Autoscaling.Enabled {
			info.AutoscalingEnabled = true
		}
		info.TotalNodeCount += int(np.InitialNodeCount)

		// Get node service account from first pool
		if info.NodeServiceAccount == "" && np.Config != nil {
			info.NodeServiceAccount = np.Config.ServiceAccount
		}

		// Check shielded node config
		if np.Config != nil && np.Config.ShieldedInstanceConfig != nil {
			info.SecureBoot = np.Config.ShieldedInstanceConfig.EnableSecureBoot
			info.IntegrityMonitoring = np.Config.ShieldedInstanceConfig.EnableIntegrityMonitoring
		}
	}

	// GKE Autopilot mode
	if cluster.Autopilot != nil {
		info.Autopilot = cluster.Autopilot.Enabled
	}

	// Node Auto-provisioning
	if cluster.Autoscaling != nil {
		info.NodeAutoProvisioning = cluster.Autoscaling.EnableNodeAutoprovisioning
	}

	// Maintenance configuration
	if cluster.MaintenancePolicy != nil && cluster.MaintenancePolicy.Window != nil {
		window := cluster.MaintenancePolicy.Window
		if window.DailyMaintenanceWindow != nil {
			info.MaintenanceWindow = fmt.Sprintf("Daily at %s", window.DailyMaintenanceWindow.StartTime)
		} else if window.RecurringWindow != nil {
			info.MaintenanceWindow = fmt.Sprintf("Recurring: %s", window.RecurringWindow.Recurrence)
		}
		// Maintenance exclusions
		for name := range window.MaintenanceExclusions {
			info.MaintenanceExclusions = append(info.MaintenanceExclusions, name)
		}
	}

	// Addons configuration
	if cluster.AddonsConfig != nil {
		// Config Connector
		if cluster.AddonsConfig.ConfigConnectorConfig != nil {
			info.ConfigConnector = cluster.AddonsConfig.ConfigConnectorConfig.Enabled
		}
		// Note: IstioConfig was deprecated and removed from the GKE API
		// Anthos Service Mesh (ASM) is now the recommended approach
	}

	// Identify security issues
	info.SecurityIssues = identifySecurityIssues(info)

	return info
}

// parseNodePoolInfo extracts information from a node pool
func parseNodePoolInfo(np *container.NodePool, clusterName, projectID, location string) NodePoolInfo {
	info := NodePoolInfo{
		ClusterName: clusterName,
		Name:        np.Name,
		ProjectID:   projectID,
		Location:    location,
		Status:      np.Status,
		NodeCount:   int(np.InitialNodeCount),
	}

	if np.Config != nil {
		info.MachineType = np.Config.MachineType
		info.DiskSizeGb = np.Config.DiskSizeGb
		info.DiskType = np.Config.DiskType
		info.ImageType = np.Config.ImageType
		info.ServiceAccount = np.Config.ServiceAccount
		info.OAuthScopes = np.Config.OauthScopes
		info.Preemptible = np.Config.Preemptible
		info.Spot = np.Config.Spot

		if np.Config.ShieldedInstanceConfig != nil {
			info.SecureBoot = np.Config.ShieldedInstanceConfig.EnableSecureBoot
			info.IntegrityMonitoring = np.Config.ShieldedInstanceConfig.EnableIntegrityMonitoring
		}

		// Analyze OAuth scopes for risky permissions
		info.HasCloudPlatformScope, info.ScopeSummary, info.RiskyScopes = analyzeOAuthScopes(np.Config.OauthScopes)
	}

	if np.Management != nil {
		info.AutoRepair = np.Management.AutoRepair
		info.AutoUpgrade = np.Management.AutoUpgrade
	}

	return info
}

// analyzeOAuthScopes identifies risky OAuth scopes and returns a summary
func analyzeOAuthScopes(scopes []string) (hasCloudPlatform bool, scopeSummary string, riskyScopes []string) {
	riskyPatterns := map[string]string{
		"https://www.googleapis.com/auth/cloud-platform":          "Full GCP access",
		"https://www.googleapis.com/auth/compute":                 "Full Compute Engine access",
		"https://www.googleapis.com/auth/devstorage.full_control": "Full Cloud Storage access",
		"https://www.googleapis.com/auth/devstorage.read_write":   "Read/write Cloud Storage",
		"https://www.googleapis.com/auth/logging.admin":           "Logging admin (can delete logs)",
		"https://www.googleapis.com/auth/source.full_control":     "Full source repo access",
		"https://www.googleapis.com/auth/sqlservice.admin":        "Cloud SQL admin",
	}

	for _, scope := range scopes {
		if scope == "https://www.googleapis.com/auth/cloud-platform" {
			hasCloudPlatform = true
		}
		if desc, found := riskyPatterns[scope]; found {
			riskyScopes = append(riskyScopes, fmt.Sprintf("%s: %s", scope, desc))
		}
	}

	// Determine scope summary
	// GKE default scopes (when not explicitly set) typically include:
	// - logging.write, monitoring, devstorage.read_only, service.management.readonly, servicecontrol, trace.append
	if hasCloudPlatform {
		scopeSummary = "Full Access"
	} else if len(riskyScopes) > 0 {
		// Has some risky scopes but not full access
		scopeSummary = fmt.Sprintf("Broad (%d risky)", len(riskyScopes))
	} else if len(scopes) == 0 {
		// Empty scopes likely means default GKE scopes (limited)
		scopeSummary = "Default"
	} else {
		scopeSummary = "Restricted"
	}

	return
}

// identifySecurityIssues checks for common security misconfigurations
func identifySecurityIssues(cluster ClusterInfo) []string {
	var issues []string

	// Public endpoint without authorized networks
	if !cluster.PrivateCluster && !cluster.MasterAuthorizedOnly {
		issues = append(issues, "Public endpoint without master authorized networks")
	}

	// Legacy ABAC enabled
	if cluster.LegacyABAC {
		issues = append(issues, "Legacy ABAC authorization enabled")
	}

	// Basic auth enabled
	if cluster.BasicAuthEnabled {
		issues = append(issues, "Basic authentication enabled (deprecated)")
	}

	// Client certificate
	if cluster.IssueClientCertificate {
		issues = append(issues, "Client certificate authentication enabled")
	}

	// No network policy
	if !cluster.NetworkPolicy {
		issues = append(issues, "Network policy not enabled")
	}

	// No workload identity
	if cluster.WorkloadIdentity == "" {
		issues = append(issues, "Workload Identity not configured")
	}

	// Shielded nodes not enabled
	if !cluster.ShieldedNodes {
		issues = append(issues, "Shielded nodes not enabled")
	}

	// Default service account on nodes
	if cluster.NodeServiceAccount == "default" ||
	   strings.HasSuffix(cluster.NodeServiceAccount, "-compute@developer.gserviceaccount.com") {
		issues = append(issues, "Default service account used on nodes")
	}

	// No release channel (manual upgrades)
	if cluster.ReleaseChannel == "" || cluster.ReleaseChannel == "UNSPECIFIED" {
		issues = append(issues, "No release channel configured")
	}

	return issues
}

