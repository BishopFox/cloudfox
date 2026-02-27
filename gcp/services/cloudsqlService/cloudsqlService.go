package cloudsqlservice

import (
	"context"
	"fmt"
	"strings"

	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/internal/gcp/sdk"
	sqladmin "google.golang.org/api/sqladmin/v1"
)

type CloudSQLService struct{
	session *gcpinternal.SafeSession
}

func New() *CloudSQLService {
	return &CloudSQLService{}
}

func NewWithSession(session *gcpinternal.SafeSession) *CloudSQLService {
	return &CloudSQLService{session: session}
}

// getService returns a SQL Admin service, either cached from the session or a new one
func (cs *CloudSQLService) getService(ctx context.Context) (*sqladmin.Service, error) {
	if cs.session != nil {
		return sdk.CachedGetSQLAdminService(ctx, cs.session)
	}
	return sqladmin.NewService(ctx)
}

// SQLInstanceInfo holds Cloud SQL instance details with security-relevant information
type SQLInstanceInfo struct {
	// Basic info
	Name              string
	ProjectID         string
	Region            string
	DatabaseVersion   string
	Tier              string
	State             string

	// Network configuration
	PublicIP          string
	PrivateIP         string
	HasPublicIP       bool
	AuthorizedNetworks []AuthorizedNetwork
	RequireSSL        bool
	SSLMode           string

	// Security configuration
	ServiceAccountEmail string
	RootPasswordSet     bool
	PasswordPolicyEnabled bool
	IAMAuthentication   bool

	// Backup configuration
	BackupEnabled       bool
	BinaryLogEnabled    bool
	BackupLocation      string
	PointInTimeRecovery bool
	RetentionDays       int

	// Encryption
	KMSKeyName          string
	EncryptionType      string  // Google-managed or CMEK

	// High Availability
	AvailabilityType    string  // REGIONAL or ZONAL
	FailoverReplica     string

	// Maintenance
	MaintenanceWindow   string

	// Databases (if enumerated)
	Databases           []string

	// Security issues detected
	SecurityIssues      []string
}

// AuthorizedNetwork represents a network authorized to connect
type AuthorizedNetwork struct {
	Name      string
	Value     string  // CIDR
	IsPublic  bool    // 0.0.0.0/0 or similar
}

// Instances retrieves all Cloud SQL instances in a project
func (cs *CloudSQLService) Instances(projectID string) ([]SQLInstanceInfo, error) {
	ctx := context.Background()

	service, err := cs.getService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "sqladmin.googleapis.com")
	}

	resp, err := service.Instances.List(projectID).Do()
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "sqladmin.googleapis.com")
	}

	var instances []SQLInstanceInfo
	for _, instance := range resp.Items {
		info := parseInstanceInfo(instance, projectID)
		instances = append(instances, info)
	}

	return instances, nil
}

// parseInstanceInfo extracts security-relevant information from a Cloud SQL instance
func parseInstanceInfo(instance *sqladmin.DatabaseInstance, projectID string) SQLInstanceInfo {
	info := SQLInstanceInfo{
		Name:            instance.Name,
		ProjectID:       projectID,
		DatabaseVersion: instance.DatabaseVersion,
		State:           instance.State,
		SecurityIssues:  []string{},
	}

	// Region from GCE zone
	if instance.GceZone != "" {
		// Zone format: us-central1-a -> extract region us-central1
		parts := strings.Split(instance.GceZone, "-")
		if len(parts) >= 2 {
			info.Region = parts[0] + "-" + parts[1]
		}
	} else if instance.Region != "" {
		info.Region = instance.Region
	}

	// Settings
	if instance.Settings != nil {
		info.Tier = instance.Settings.Tier
		info.AvailabilityType = instance.Settings.AvailabilityType

		// IP configuration
		if instance.Settings.IpConfiguration != nil {
			ipConfig := instance.Settings.IpConfiguration
			info.RequireSSL = ipConfig.RequireSsl
			info.SSLMode = ipConfig.SslMode
			info.IAMAuthentication = ipConfig.EnablePrivatePathForGoogleCloudServices

			// Check for private IP
			if ipConfig.PrivateNetwork != "" {
				info.HasPublicIP = ipConfig.Ipv4Enabled
			} else {
				info.HasPublicIP = true // Default is public
			}

			// Parse authorized networks
			for _, network := range ipConfig.AuthorizedNetworks {
				an := AuthorizedNetwork{
					Name:  network.Name,
					Value: network.Value,
				}
				// Check if network is public (0.0.0.0/0 or similar broad ranges)
				if network.Value == "0.0.0.0/0" ||
				   network.Value == "0.0.0.0/1" ||
				   network.Value == "128.0.0.0/1" {
					an.IsPublic = true
				}
				info.AuthorizedNetworks = append(info.AuthorizedNetworks, an)
			}
		}

		// Backup configuration
		if instance.Settings.BackupConfiguration != nil {
			backup := instance.Settings.BackupConfiguration
			info.BackupEnabled = backup.Enabled
			info.BinaryLogEnabled = backup.BinaryLogEnabled
			info.BackupLocation = backup.Location
			info.PointInTimeRecovery = backup.PointInTimeRecoveryEnabled
			info.RetentionDays = int(backup.TransactionLogRetentionDays)
		}

		// Password policy
		if instance.Settings.PasswordValidationPolicy != nil {
			info.PasswordPolicyEnabled = instance.Settings.PasswordValidationPolicy.EnablePasswordPolicy
		}

		// Maintenance window
		if instance.Settings.MaintenanceWindow != nil {
			info.MaintenanceWindow = fmt.Sprintf("Day %d, Hour %d",
				instance.Settings.MaintenanceWindow.Day,
				instance.Settings.MaintenanceWindow.Hour)
		}

		// Database flags (can reveal security settings)
		// These could be parsed for specific security-relevant flags
	}

	// IP addresses
	for _, ip := range instance.IpAddresses {
		switch ip.Type {
		case "PRIMARY":
			info.PublicIP = ip.IpAddress
		case "PRIVATE":
			info.PrivateIP = ip.IpAddress
		}
	}

	// Service account
	info.ServiceAccountEmail = instance.ServiceAccountEmailAddress

	// Disk encryption
	if instance.DiskEncryptionConfiguration != nil {
		info.KMSKeyName = instance.DiskEncryptionConfiguration.KmsKeyName
		if info.KMSKeyName != "" {
			info.EncryptionType = "CMEK"
		} else {
			info.EncryptionType = "Google-managed"
		}
	} else {
		info.EncryptionType = "Google-managed"
	}

	// Failover replica
	if instance.FailoverReplica != nil {
		info.FailoverReplica = instance.FailoverReplica.Name
	}

	// Identify security issues
	info.SecurityIssues = identifySecurityIssues(info)

	return info
}

// identifySecurityIssues checks for common security misconfigurations
func identifySecurityIssues(instance SQLInstanceInfo) []string {
	var issues []string

	// Public IP enabled
	if instance.HasPublicIP {
		issues = append(issues, "Public IP enabled")
	}

	// Public IP without SSL requirement
	if instance.HasPublicIP && !instance.RequireSSL {
		issues = append(issues, "Public IP without SSL requirement")
	}

	// Authorized networks include 0.0.0.0/0
	for _, network := range instance.AuthorizedNetworks {
		if network.IsPublic {
			issues = append(issues, fmt.Sprintf("Authorized network allows all IPs: %s", network.Value))
		}
	}

	// No authorized networks but public IP (potentially open to all)
	if instance.HasPublicIP && len(instance.AuthorizedNetworks) == 0 {
		issues = append(issues, "Public IP with no authorized networks (blocked by default, but verify)")
	}

	// Backups not enabled
	if !instance.BackupEnabled {
		issues = append(issues, "Automated backups not enabled")
	}

	// Point-in-time recovery not enabled
	if !instance.PointInTimeRecovery && instance.BackupEnabled {
		issues = append(issues, "Point-in-time recovery not enabled")
	}

	// Using Google-managed encryption (not CMEK)
	if instance.EncryptionType == "Google-managed" {
		// This is informational, not necessarily an issue
		// issues = append(issues, "Using Google-managed encryption (not CMEK)")
	}

	// Single zone deployment
	if instance.AvailabilityType == "ZONAL" {
		issues = append(issues, "Single zone deployment (no HA)")
	}

	// Password policy not enabled
	if !instance.PasswordPolicyEnabled {
		issues = append(issues, "Password validation policy not enabled")
	}

	return issues
}
