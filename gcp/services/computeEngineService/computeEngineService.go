package computeengineservice

import (
	"context"
	"fmt"
	"strings"

	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/internal/gcp/sdk"
	"google.golang.org/api/compute/v1"
)

type ComputeEngineService struct {
	session *gcpinternal.SafeSession
}

// New creates a new ComputeEngineService (legacy - uses ADC directly)
func New() *ComputeEngineService {
	return &ComputeEngineService{}
}

// NewWithSession creates a ComputeEngineService with a SafeSession for managed authentication
func NewWithSession(session *gcpinternal.SafeSession) *ComputeEngineService {
	return &ComputeEngineService{session: session}
}

// ServiceAccountInfo contains service account details for an instance
type ServiceAccountInfo struct {
	Email  string   `json:"email"`
	Scopes []string `json:"scopes"`
}

// IAMBinding represents a single IAM role binding
type IAMBinding struct {
	Role   string `json:"role"`
	Member string `json:"member"`
}

// InstanceType represents the type/manager of an instance
type InstanceType string

const (
	InstanceTypeStandalone  InstanceType = "Standalone"  // Regular VM
	InstanceTypeGKE         InstanceType = "GKE"         // GKE node
	InstanceTypeMIG         InstanceType = "MIG"         // Managed Instance Group
	InstanceTypeDataproc    InstanceType = "Dataproc"    // Dataproc cluster node
	InstanceTypeDataflow    InstanceType = "Dataflow"    // Dataflow worker
	InstanceTypeComposer    InstanceType = "Composer"    // Cloud Composer worker
	InstanceTypeNotebooks   InstanceType = "Notebooks"   // Vertex AI Workbench / AI Platform Notebooks
	InstanceTypeBatchJob    InstanceType = "Batch"       // Cloud Batch job
	InstanceTypeCloudRun    InstanceType = "CloudRun"    // Cloud Run (Jobs) execution environment
	InstanceTypeFilestore   InstanceType = "Filestore"   // Filestore instance
	InstanceTypeSQLProxy    InstanceType = "CloudSQL"    // Cloud SQL Proxy
	InstanceTypeAppEngine   InstanceType = "AppEngine"   // App Engine Flex
)

// ComputeEngineInfo contains instance metadata and security-relevant configuration
type ComputeEngineInfo struct {
	// Basic info
	Name         string       `json:"name"`
	ID           string       `json:"id"`
	Zone         string       `json:"zone"`
	State        string       `json:"state"`
	ProjectID    string       `json:"projectID"`
	InstanceType InstanceType `json:"instanceType"` // Type of instance (GKE, MIG, Dataproc, etc.)

	// Network configuration
	ExternalIP        string                      `json:"externalIP"`
	InternalIP        string                      `json:"internalIP"`
	NetworkInterfaces []*compute.NetworkInterface `json:"networkInterfaces"`
	CanIPForward      bool                        `json:"canIpForward"` // Can forward packets (router/NAT)

	// Service accounts and scopes
	ServiceAccounts []ServiceAccountInfo `json:"serviceAccounts"`
	HasDefaultSA    bool                 `json:"hasDefaultSA"`   // Uses default compute SA
	HasCloudScopes  bool                 `json:"hasCloudScopes"` // Has cloud-platform or other broad scopes

	// Security configuration
	DeletionProtection  bool `json:"deletionProtection"`  // Protected against deletion
	ShieldedVM          bool `json:"shieldedVM"`          // Shielded VM enabled
	SecureBoot          bool `json:"secureBoot"`          // Secure Boot enabled
	VTPMEnabled         bool `json:"vtpmEnabled"`         // vTPM enabled
	IntegrityMonitoring bool `json:"integrityMonitoring"` // Integrity monitoring enabled
	ConfidentialVM      bool `json:"confidentialVM"`      // Confidential computing enabled

	// Instance metadata
	MachineType string            `json:"machineType"`
	Tags        *compute.Tags     `json:"tags"`
	Labels      map[string]string `json:"labels"`

	// Metadata security
	HasStartupScript    bool `json:"hasStartupScript"`    // Has startup script in metadata
	HasSSHKeys          bool `json:"hasSSHKeys"`          // Has SSH keys in metadata
	BlockProjectSSHKeys bool `json:"blockProjectSSHKeys"` // Blocks project-wide SSH keys
	OSLoginEnabled      bool `json:"osLoginEnabled"`      // OS Login enabled
	OSLogin2FAEnabled   bool `json:"osLogin2FAEnabled"`   // OS Login 2FA enabled
	SerialPortEnabled   bool `json:"serialPortEnabled"`   // Serial port access enabled

	// Pentest-specific fields: actual content extraction
	StartupScriptContent string            `json:"startupScriptContent"` // Actual startup script content
	StartupScriptURL     string            `json:"startupScriptURL"`     // URL to startup script if remote
	SSHKeys              []string          `json:"sshKeys"`              // Extracted SSH keys
	CustomMetadata       []string          `json:"customMetadata"`       // Other custom metadata keys
	RawMetadata          map[string]string `json:"rawMetadata"`          // Full raw metadata key-value pairs
	SensitiveMetadata    []SensitiveItem   `json:"sensitiveMetadata"`    // Detected sensitive items in metadata

	// Disk encryption
	BootDiskEncryption string `json:"bootDiskEncryption"` // "Google-managed", "CMEK", or "CSEK"
	BootDiskKMSKey     string `json:"bootDiskKMSKey"`     // KMS key for CMEK

	// Timestamps
	CreationTimestamp  string `json:"creationTimestamp"`
	LastStartTimestamp string `json:"lastStartTimestamp"`
	LastSnapshotDate   string `json:"lastSnapshotDate"` // Most recent snapshot date for any attached disk

	// IAM bindings
	IAMBindings []IAMBinding `json:"iamBindings"`
}

// ProjectMetadataInfo contains project-level metadata security info
type ProjectMetadataInfo struct {
	ProjectID               string            `json:"projectId"`
	HasProjectSSHKeys       bool              `json:"hasProjectSSHKeys"`
	ProjectSSHKeys          []string          `json:"projectSSHKeys"`
	HasProjectStartupScript bool              `json:"hasProjectStartupScript"`
	ProjectStartupScript    string            `json:"projectStartupScript"`
	OSLoginEnabled          bool              `json:"osLoginEnabled"`
	OSLogin2FAEnabled       bool              `json:"osLogin2FAEnabled"`
	SerialPortEnabled       bool              `json:"serialPortEnabled"`
	CustomMetadataKeys      []string          `json:"customMetadataKeys"`
	RawMetadata             map[string]string `json:"rawMetadata"`
	SensitiveMetadata       []SensitiveItem   `json:"sensitiveMetadata"`
}

// InstanceIAMInfo contains IAM policy info for an instance
type InstanceIAMInfo struct {
	InstanceName    string   `json:"instanceName"`
	Zone            string   `json:"zone"`
	ProjectID       string   `json:"projectId"`
	ComputeAdmins   []string `json:"computeAdmins"`   // compute.admin or owner
	InstanceAdmins  []string `json:"instanceAdmins"`  // compute.instanceAdmin
	SSHUsers        []string `json:"sshUsers"`        // compute.osLogin or osAdminLogin
	MetadataSetters []string `json:"metadataSetters"` // compute.instances.setMetadata
}

// getService returns a compute service, using session if available
func (ces *ComputeEngineService) getService(ctx context.Context) (*compute.Service, error) {
	if ces.session != nil {
		return sdk.CachedGetComputeService(ctx, ces.session)
	}
	return compute.NewService(ctx)
}

// getInstanceIAMBindings retrieves all IAM bindings for an instance
func (ces *ComputeEngineService) getInstanceIAMBindings(service *compute.Service, projectID, zone, instanceName string) []IAMBinding {
	ctx := context.Background()

	policy, err := service.Instances.GetIamPolicy(projectID, zone, instanceName).Context(ctx).Do()
	if err != nil {
		return nil
	}

	var bindings []IAMBinding
	for _, binding := range policy.Bindings {
		if binding == nil {
			continue
		}
		for _, member := range binding.Members {
			bindings = append(bindings, IAMBinding{
				Role:   binding.Role,
				Member: member,
			})
		}
	}

	return bindings
}

// Retrieves instances from all regions and zones for a project without using concurrency.
func (ces *ComputeEngineService) Instances(projectID string) ([]ComputeEngineInfo, error) {
	ctx := context.Background()
	computeService, err := ces.getService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "compute.googleapis.com")
	}

	// Use AggregatedList to get all instances across all zones in one call
	// This only requires compute.instances.list permission (not compute.regions.list)
	var instanceInfos []ComputeEngineInfo

	req := computeService.Instances.AggregatedList(projectID)
	err = req.Pages(ctx, func(page *compute.InstanceAggregatedList) error {
		for scopeName, scopedList := range page.Items {
			if scopedList.Instances == nil {
				continue
			}
			// Extract zone from scope name (format: "zones/us-central1-a")
			zone := ""
			if strings.HasPrefix(scopeName, "zones/") {
				zone = strings.TrimPrefix(scopeName, "zones/")
			}

			for _, instance := range scopedList.Instances {
				info := ComputeEngineInfo{
					Name:               instance.Name,
					ID:                 fmt.Sprintf("%v", instance.Id),
					Zone:               zone,
					State:              instance.Status,
					InstanceType:       detectInstanceType(instance),
					ExternalIP:         getExternalIP(instance),
					InternalIP:         getInternalIP(instance),
					NetworkInterfaces:  instance.NetworkInterfaces,
					CanIPForward:       instance.CanIpForward,
					Tags:               instance.Tags,
					Labels:             instance.Labels,
					ProjectID:          projectID,
					DeletionProtection: instance.DeletionProtection,
					CreationTimestamp:  instance.CreationTimestamp,
					LastStartTimestamp: instance.LastStartTimestamp,
				}

				// Parse machine type (extract just the type name)
				info.MachineType = getMachineTypeName(instance.MachineType)

				// Parse service accounts and scopes
				info.ServiceAccounts, info.HasDefaultSA, info.HasCloudScopes = parseServiceAccounts(instance.ServiceAccounts, projectID)

				// Parse shielded VM config
				if instance.ShieldedInstanceConfig != nil {
					info.ShieldedVM = true
					info.SecureBoot = instance.ShieldedInstanceConfig.EnableSecureBoot
					info.VTPMEnabled = instance.ShieldedInstanceConfig.EnableVtpm
					info.IntegrityMonitoring = instance.ShieldedInstanceConfig.EnableIntegrityMonitoring
				}

				// Parse confidential VM config
				if instance.ConfidentialInstanceConfig != nil {
					info.ConfidentialVM = instance.ConfidentialInstanceConfig.EnableConfidentialCompute
				}

				// Parse metadata for security-relevant items including content
				if instance.Metadata != nil {
					metaResult := parseMetadataFull(instance.Metadata)
					info.HasStartupScript = metaResult.HasStartupScript
					info.HasSSHKeys = metaResult.HasSSHKeys
					info.BlockProjectSSHKeys = metaResult.BlockProjectSSHKeys
					info.OSLoginEnabled = metaResult.OSLoginEnabled
					info.OSLogin2FAEnabled = metaResult.OSLogin2FA
					info.SerialPortEnabled = metaResult.SerialPortEnabled
					info.StartupScriptContent = metaResult.StartupScriptContent
					info.StartupScriptURL = metaResult.StartupScriptURL
					info.SSHKeys = metaResult.SSHKeys
					info.CustomMetadata = metaResult.CustomMetadata
					info.RawMetadata = metaResult.RawMetadata
					// Mark source for sensitive items
					for i := range metaResult.SensitiveItems {
						metaResult.SensitiveItems[i].Source = "instance"
					}
					info.SensitiveMetadata = metaResult.SensitiveItems
				}

				// Parse boot disk encryption
				info.BootDiskEncryption, info.BootDiskKMSKey = parseBootDiskEncryption(instance.Disks)

				// Get last snapshot date for this instance's disks
				info.LastSnapshotDate = ces.getLastSnapshotForDisks(computeService, projectID, instance.Disks)

				// Fetch IAM bindings for this instance (may fail silently if no permission)
				info.IAMBindings = ces.getInstanceIAMBindings(computeService, projectID, zone, instance.Name)

				instanceInfos = append(instanceInfos, info)
			}
		}
		return nil
	})

	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "compute.googleapis.com")
	}

	return instanceInfos, nil
}

// Returns the zone from a GCP URL string with the zone in it
func getZoneNameFromURL(zoneURL string) string {
	splits := strings.Split(zoneURL, "/")
	return splits[len(splits)-1]
}

// getExternalIP extracts the external IP address from an instance if available.
func getExternalIP(instance *compute.Instance) string {
	for _, iface := range instance.NetworkInterfaces {
		for _, accessConfig := range iface.AccessConfigs {
			if accessConfig.NatIP != "" {
				return accessConfig.NatIP
			}
		}
	}
	return ""
}

// getInternalIP extracts the internal IP address from an instance.
func getInternalIP(instance *compute.Instance) string {
	if len(instance.NetworkInterfaces) > 0 {
		return instance.NetworkInterfaces[0].NetworkIP
	}
	return ""
}

// getMachineTypeName extracts the machine type name from a full URL
func getMachineTypeName(machineTypeURL string) string {
	parts := strings.Split(machineTypeURL, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return machineTypeURL
}

// parseServiceAccounts extracts service account info and checks for security concerns
func parseServiceAccounts(sas []*compute.ServiceAccount, projectID string) ([]ServiceAccountInfo, bool, bool) {
	var accounts []ServiceAccountInfo
	hasDefaultSA := false
	hasCloudScopes := false

	defaultSAPattern := fmt.Sprintf("%s-compute@developer.gserviceaccount.com", projectID)

	for _, sa := range sas {
		info := ServiceAccountInfo{
			Email:  sa.Email,
			Scopes: sa.Scopes,
		}
		accounts = append(accounts, info)

		// Check if using default compute service account
		if strings.Contains(sa.Email, "-compute@developer.gserviceaccount.com") ||
			strings.HasSuffix(sa.Email, defaultSAPattern) {
			hasDefaultSA = true
		}

		// Check for broad scopes
		for _, scope := range sa.Scopes {
			if scope == "https://www.googleapis.com/auth/cloud-platform" ||
				scope == "https://www.googleapis.com/auth/compute" ||
				scope == "https://www.googleapis.com/auth/devstorage.full_control" ||
				scope == "https://www.googleapis.com/auth/devstorage.read_write" {
				hasCloudScopes = true
			}
		}
	}

	return accounts, hasDefaultSA, hasCloudScopes
}

// SensitiveItem represents a potentially sensitive metadata item
type SensitiveItem struct {
	Key         string `json:"key"`
	Value       string `json:"value"`
	Type        string `json:"type"`        // password, api-key, token, credential, connection-string, secret, env-var
	Source      string `json:"source"`      // instance, project, or specific like "instance:user-data"
	MetadataKey string `json:"metadataKey"` // The metadata key where this was found (e.g., user-data, startup-script)
}

// MetadataParseResult contains all parsed metadata fields
type MetadataParseResult struct {
	HasStartupScript     bool
	HasSSHKeys           bool
	BlockProjectSSHKeys  bool
	OSLoginEnabled       bool
	OSLogin2FA           bool
	SerialPortEnabled    bool
	StartupScriptContent string
	StartupScriptURL     string
	SSHKeys              []string
	CustomMetadata       []string
	RawMetadata          map[string]string
	SensitiveItems       []SensitiveItem
}

// parseMetadata checks instance metadata for security-relevant settings
func parseMetadata(metadata *compute.Metadata) (hasStartupScript, hasSSHKeys, blockProjectSSHKeys, osLoginEnabled, osLogin2FA, serialPortEnabled bool) {
	result := parseMetadataFull(metadata)
	return result.HasStartupScript, result.HasSSHKeys, result.BlockProjectSSHKeys,
		result.OSLoginEnabled, result.OSLogin2FA, result.SerialPortEnabled
}

// sensitivePatterns maps key name patterns to secret types
// These are checked with contains matching, so they should be specific enough to avoid false positives
var sensitivePatterns = map[string]string{
	// Passwords - high confidence patterns that end with PASSWORD/PASSWD/PWD
	"_PASSWORD": "password",
	"_PASSWD":   "password",
	"_PWD":      "password",
	"_PASS":     "password",

	// Secrets - patterns that explicitly contain SECRET
	"_SECRET":     "secret",
	"SECRET_KEY":  "secret",
	"APP_SECRET":  "secret",
	"JWT_SECRET":  "secret",

	// API Keys - explicit API key patterns
	"API_KEY":    "api-key",
	"APIKEY":     "api-key",
	"_APIKEY":    "api-key",
	"API_SECRET": "api-key",

	// Tokens - explicit token patterns (must have _TOKEN suffix or TOKEN_ prefix to be specific)
	"_TOKEN":       "token",
	"TOKEN_":       "token",
	"ACCESS_TOKEN": "token",
	"AUTH_TOKEN":   "token",
	"BEARER_":      "token",

	// Private keys
	"PRIVATE_KEY": "credential",
	"PRIVATEKEY":  "credential",
	"_PRIVKEY":    "credential",

	// Connection strings - explicit patterns
	"CONNECTION_STRING": "connection-string",
	"DATABASE_URL":      "connection-string",
	"MONGODB_URI":       "connection-string",
	"_CONN_STR":         "connection-string",

	// Cloud provider credentials - very specific patterns
	"AWS_SECRET_ACCESS_KEY": "credential",
	"AWS_SESSION_TOKEN":     "credential",
	"AZURE_CLIENT_SECRET":   "credential",
	"GOOGLE_CREDENTIALS":    "credential",

	// OAuth - specific patterns
	"CLIENT_SECRET":   "credential",
	"CONSUMER_SECRET": "credential",
	"OAUTH_SECRET":    "credential",
}

// detectSensitiveType checks if a key name matches sensitive patterns
func detectSensitiveType(key string) string {
	keyUpper := strings.ToUpper(key)
	for pattern, secretType := range sensitivePatterns {
		if strings.Contains(keyUpper, pattern) {
			return secretType
		}
	}
	return ""
}

// parseMetadataFull extracts all metadata including content
func parseMetadataFull(metadata *compute.Metadata) MetadataParseResult {
	result := MetadataParseResult{
		RawMetadata: make(map[string]string),
	}
	if metadata == nil || metadata.Items == nil {
		return result
	}

	// Known metadata keys to exclude from custom metadata
	knownKeys := map[string]bool{
		"startup-script":                true,
		"startup-script-url":            true,
		"ssh-keys":                      true,
		"sshKeys":                       true,
		"block-project-ssh-keys":        true,
		"enable-oslogin":                true,
		"enable-oslogin-2fa":            true,
		"serial-port-enable":            true,
		"google-compute-default-zone":   true,
		"google-compute-default-region": true,
	}

	for _, item := range metadata.Items {
		if item == nil {
			continue
		}

		// Store all raw metadata (except ssh-keys which go to separate loot)
		if item.Value != nil && item.Key != "ssh-keys" && item.Key != "sshKeys" {
			result.RawMetadata[item.Key] = *item.Value
		}

		// Check ALL metadata keys for sensitive patterns (not just custom ones)
		if item.Value != nil {
			if sensitiveType := detectSensitiveType(item.Key); sensitiveType != "" {
				result.SensitiveItems = append(result.SensitiveItems, SensitiveItem{
					Key:         item.Key,
					Value:       *item.Value,
					Type:        sensitiveType,
					MetadataKey: item.Key, // The key itself is the metadata key
				})
			}
			// Also scan metadata VALUES for embedded env vars (e.g., VAR=value patterns)
			valueItems := extractSensitiveFromScript(*item.Value, "metadata-value:"+item.Key)
			result.SensitiveItems = append(result.SensitiveItems, valueItems...)
		}

		switch item.Key {
		case "startup-script":
			result.HasStartupScript = true
			if item.Value != nil {
				result.StartupScriptContent = *item.Value
				// Check startup script for sensitive patterns (env vars inside script)
				sensitiveItems := extractSensitiveFromScript(*item.Value, "startup-script")
				result.SensitiveItems = append(result.SensitiveItems, sensitiveItems...)
			}
		case "startup-script-url":
			result.HasStartupScript = true
			if item.Value != nil {
				result.StartupScriptURL = *item.Value
			}
		case "ssh-keys", "sshKeys":
			result.HasSSHKeys = true
			if item.Value != nil {
				// Parse SSH keys - format is "user:ssh-rsa KEY comment"
				lines := strings.Split(*item.Value, "\n")
				for _, line := range lines {
					line = strings.TrimSpace(line)
					if line != "" {
						result.SSHKeys = append(result.SSHKeys, line)
					}
				}
			}
		case "block-project-ssh-keys":
			if item.Value != nil && *item.Value == "true" {
				result.BlockProjectSSHKeys = true
			}
		case "enable-oslogin":
			if item.Value != nil && strings.ToLower(*item.Value) == "true" {
				result.OSLoginEnabled = true
			}
		case "enable-oslogin-2fa":
			if item.Value != nil && strings.ToLower(*item.Value) == "true" {
				result.OSLogin2FA = true
			}
		case "serial-port-enable":
			if item.Value != nil && *item.Value == "true" {
				result.SerialPortEnabled = true
			}
		default:
			// Track custom metadata keys
			if !knownKeys[item.Key] {
				result.CustomMetadata = append(result.CustomMetadata, item.Key)
			}
		}
	}

	return result
}

// extractSensitiveFromScript scans content for sensitive variable assignments
// Focuses on explicit VAR=value patterns to minimize false positives
// source format: "metadata-value:KEY_NAME" or "startup-script" or "project-startup-script"
func extractSensitiveFromScript(content, source string) []SensitiveItem {
	var items []SensitiveItem
	seen := make(map[string]bool) // Deduplicate findings

	// Parse the metadata key from the source
	metadataKey := source
	if strings.HasPrefix(source, "metadata-value:") {
		metadataKey = strings.TrimPrefix(source, "metadata-value:")
	}

	lines := strings.Split(content, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Pattern 1: Shell style - export VAR=value or VAR=value
		if strings.Contains(line, "=") {
			// Handle export statements and YAML list items
			testLine := strings.TrimPrefix(line, "export ")
			testLine = strings.TrimPrefix(testLine, "- ")
			testLine = strings.TrimPrefix(testLine, "| ")
			testLine = strings.TrimSpace(testLine)

			parts := strings.SplitN(testLine, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				// Remove quotes from value
				value = strings.Trim(value, "\"'`")
				// Clean up key
				key = strings.TrimLeft(key, "- |>")
				key = strings.TrimSpace(key)

				// Only consider valid variable names with actual values
				if isValidVarName(key) && len(value) >= 3 && !isPlaceholderValue(value) {
					if sensitiveType := detectSensitiveType(key); sensitiveType != "" {
						dedupeKey := key + ":" + value
						if !seen[dedupeKey] {
							seen[dedupeKey] = true
							items = append(items, SensitiveItem{
								Key:         key,
								Value:       value,
								Type:        sensitiveType,
								MetadataKey: metadataKey,
							})
						}
					}
				}
			}
		}

		// Pattern 2: YAML style "key: value" - only for direct assignments
		if strings.Contains(line, ": ") && !strings.HasPrefix(line, "#") && !strings.Contains(line, "=") {
			parts := strings.SplitN(line, ": ", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				// Clean up key
				key = strings.TrimLeft(key, "- ")
				key = strings.TrimSpace(key)
				// Remove quotes from value
				value = strings.Trim(value, "\"'`")

				// Skip YAML block indicators and empty values
				if value != "" && value != "|" && value != ">" && len(value) >= 3 && !isPlaceholderValue(value) {
					if sensitiveType := detectSensitiveType(key); sensitiveType != "" {
						dedupeKey := key + ":" + value
						if !seen[dedupeKey] {
							seen[dedupeKey] = true
							items = append(items, SensitiveItem{
								Key:         key,
								Value:       value,
								Type:        sensitiveType,
								MetadataKey: metadataKey,
							})
						}
					}
				}
			}
		}

		// Pattern 3: JSON style "key": "value"
		if strings.Contains(line, "\":") {
			parts := strings.SplitN(line, "\":", 2)
			if len(parts) == 2 {
				keyPart := parts[0]
				if idx := strings.LastIndex(keyPart, "\""); idx >= 0 {
					key := keyPart[idx+1:]
					value := strings.TrimSpace(parts[1])
					value = strings.Trim(value, " ,\"'`")

					if len(value) >= 3 && !isPlaceholderValue(value) {
						if sensitiveType := detectSensitiveType(key); sensitiveType != "" {
							dedupeKey := key + ":" + value
							if !seen[dedupeKey] {
								seen[dedupeKey] = true
								items = append(items, SensitiveItem{
									Key:         key,
									Value:       value,
									Type:        sensitiveType,
									MetadataKey: metadataKey,
								})
							}
						}
					}
				}
			}
		}
	}

	return items
}

// isPlaceholderValue checks if a value looks like a placeholder rather than a real secret
func isPlaceholderValue(value string) bool {
	valueLower := strings.ToLower(value)
	placeholders := []string{
		"xxx", "your_", "your-", "<your", "changeme", "replace", "example",
		"${", "$(",  // Variable references
		"todo", "fixme", "placeholder",
		"none", "null", "nil", "empty",
		"true", "false",
	}
	for _, p := range placeholders {
		if strings.Contains(valueLower, p) {
			return true
		}
	}
	// Also skip if it's just a simple word without special chars (likely not a real secret)
	if len(value) < 8 && !strings.ContainsAny(value, "0123456789!@#$%^&*()-_=+[]{}|;:,.<>?/~`") {
		return true
	}
	return false
}

// isValidVarName checks if a string looks like a valid variable name
func isValidVarName(s string) bool {
	if s == "" {
		return false
	}
	// Variable names typically start with letter or underscore
	first := s[0]
	if !((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z') || first == '_') {
		return false
	}
	// Rest can be alphanumeric or underscore
	for _, c := range s[1:] {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
			return false
		}
	}
	return true
}

// detectInstanceType determines the type of instance based on labels and name patterns
func detectInstanceType(instance *compute.Instance) InstanceType {
	if instance == nil {
		return InstanceTypeStandalone
	}

	labels := instance.Labels
	name := instance.Name

	// Check labels first (most reliable)
	if labels != nil {
		// GKE nodes have goog-gke-node label
		if _, ok := labels["goog-gke-node"]; ok {
			return InstanceTypeGKE
		}
		// Also check for gke-cluster label
		if _, ok := labels["gke-cluster"]; ok {
			return InstanceTypeGKE
		}

		// Dataproc nodes have goog-dataproc-cluster-name label
		if _, ok := labels["goog-dataproc-cluster-name"]; ok {
			return InstanceTypeDataproc
		}

		// Dataflow workers have goog-dataflow-job-id label
		if _, ok := labels["goog-dataflow-job-id"]; ok {
			return InstanceTypeDataflow
		}

		// Cloud Composer workers have goog-composer-environment label
		if _, ok := labels["goog-composer-environment"]; ok {
			return InstanceTypeComposer
		}

		// Vertex AI Workbench / AI Platform Notebooks
		if _, ok := labels["goog-notebooks-instance"]; ok {
			return InstanceTypeNotebooks
		}
		// Also check for workbench label
		if _, ok := labels["goog-workbench-instance"]; ok {
			return InstanceTypeNotebooks
		}

		// Cloud Batch jobs have goog-batch-job-uid label
		if _, ok := labels["goog-batch-job-uid"]; ok {
			return InstanceTypeBatchJob
		}

		// App Engine Flex instances
		if _, ok := labels["goog-appengine-version"]; ok {
			return InstanceTypeAppEngine
		}
		if _, ok := labels["gae_app"]; ok {
			return InstanceTypeAppEngine
		}
	}

	// Check name patterns as fallback
	// GKE node names typically follow pattern: gke-{cluster}-{pool}-{hash}
	if strings.HasPrefix(name, "gke-") {
		return InstanceTypeGKE
	}

	// Dataproc nodes: {cluster}-m (master) or {cluster}-w-{n} (worker)
	if strings.Contains(name, "-m") || strings.Contains(name, "-w-") {
		// This is too generic, rely on labels instead
	}

	// Check for created-by metadata which indicates MIG
	if instance.Metadata != nil {
		for _, item := range instance.Metadata.Items {
			if item != nil && item.Key == "created-by" && item.Value != nil {
				if strings.Contains(*item.Value, "instanceGroupManagers") {
					return InstanceTypeMIG
				}
			}
		}
	}

	return InstanceTypeStandalone
}

// parseBootDiskEncryption checks the boot disk encryption type
func parseBootDiskEncryption(disks []*compute.AttachedDisk) (encryptionType, kmsKey string) {
	encryptionType = "Google-managed"

	for _, disk := range disks {
		if disk == nil || !disk.Boot {
			continue
		}

		if disk.DiskEncryptionKey != nil {
			if disk.DiskEncryptionKey.KmsKeyName != "" {
				encryptionType = "CMEK"
				kmsKey = disk.DiskEncryptionKey.KmsKeyName
			} else if disk.DiskEncryptionKey.Sha256 != "" {
				encryptionType = "CSEK"
			}
		}
		break // Only check boot disk
	}

	return
}

// getLastSnapshotForDisks gets the most recent snapshot date for any of the given disks
func (ces *ComputeEngineService) getLastSnapshotForDisks(service *compute.Service, projectID string, disks []*compute.AttachedDisk) string {
	ctx := context.Background()

	// Collect all disk names from the instance
	diskNames := make(map[string]bool)
	for _, disk := range disks {
		if disk == nil || disk.Source == "" {
			continue
		}
		// Extract disk name from source URL
		// Format: projects/{project}/zones/{zone}/disks/{diskName}
		parts := strings.Split(disk.Source, "/")
		if len(parts) > 0 {
			diskNames[parts[len(parts)-1]] = true
		}
	}

	if len(diskNames) == 0 {
		return ""
	}

	// List all snapshots in the project and find ones matching our disks
	var latestSnapshot string
	req := service.Snapshots.List(projectID)
	err := req.Pages(ctx, func(page *compute.SnapshotList) error {
		for _, snapshot := range page.Items {
			if snapshot == nil || snapshot.SourceDisk == "" {
				continue
			}
			// Extract disk name from source disk URL
			parts := strings.Split(snapshot.SourceDisk, "/")
			if len(parts) > 0 {
				diskName := parts[len(parts)-1]
				if diskNames[diskName] {
					// Compare timestamps - keep the most recent
					if latestSnapshot == "" || snapshot.CreationTimestamp > latestSnapshot {
						latestSnapshot = snapshot.CreationTimestamp
					}
				}
			}
		}
		return nil
	})

	if err != nil {
		// Silently fail - user may not have permission to list snapshots
		return ""
	}

	return latestSnapshot
}

// FormatScopes formats service account scopes for display
func FormatScopes(scopes []string) string {
	if len(scopes) == 0 {
		return "-"
	}

	// Shorten scope URLs for display
	var shortScopes []string
	for _, scope := range scopes {
		// Extract the scope name from the URL
		parts := strings.Split(scope, "/")
		if len(parts) > 0 {
			shortScopes = append(shortScopes, parts[len(parts)-1])
		}
	}
	return strings.Join(shortScopes, ", ")
}

// GetProjectMetadata retrieves project-level compute metadata
func (ces *ComputeEngineService) GetProjectMetadata(projectID string) (*ProjectMetadataInfo, error) {
	ctx := context.Background()
	computeService, err := ces.getService(ctx)
	if err != nil {
		return nil, err
	}

	project, err := computeService.Projects.Get(projectID).Do()
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "compute.googleapis.com")
	}

	info := &ProjectMetadataInfo{
		ProjectID:   projectID,
		RawMetadata: make(map[string]string),
	}

	if project.CommonInstanceMetadata != nil {
		for _, item := range project.CommonInstanceMetadata.Items {
			if item == nil {
				continue
			}

			// Store all raw metadata (except ssh-keys which go to separate loot)
			if item.Value != nil && item.Key != "ssh-keys" && item.Key != "sshKeys" {
				info.RawMetadata[item.Key] = *item.Value
			}

			// Check ALL metadata keys for sensitive patterns
			if item.Value != nil {
				if sensitiveType := detectSensitiveType(item.Key); sensitiveType != "" {
					info.SensitiveMetadata = append(info.SensitiveMetadata, SensitiveItem{
						Key:         item.Key,
						Value:       *item.Value,
						Type:        sensitiveType,
						Source:      "project",
						MetadataKey: item.Key,
					})
				}
				// Also scan metadata VALUES for embedded env vars (e.g., VAR=value patterns)
				valueItems := extractSensitiveFromScript(*item.Value, "metadata-value:"+item.Key)
				for i := range valueItems {
					valueItems[i].Source = "project"
				}
				info.SensitiveMetadata = append(info.SensitiveMetadata, valueItems...)
			}

			switch item.Key {
			case "ssh-keys", "sshKeys":
				info.HasProjectSSHKeys = true
				if item.Value != nil {
					lines := strings.Split(*item.Value, "\n")
					for _, line := range lines {
						line = strings.TrimSpace(line)
						if line != "" {
							info.ProjectSSHKeys = append(info.ProjectSSHKeys, line)
						}
					}
				}
			case "startup-script":
				info.HasProjectStartupScript = true
				if item.Value != nil {
					info.ProjectStartupScript = *item.Value
					// Check startup script for sensitive patterns (env vars inside script)
					sensitiveItems := extractSensitiveFromScript(*item.Value, "project-startup-script")
					for i := range sensitiveItems {
						sensitiveItems[i].Source = "project"
					}
					info.SensitiveMetadata = append(info.SensitiveMetadata, sensitiveItems...)
				}
			case "enable-oslogin":
				if item.Value != nil && strings.ToLower(*item.Value) == "true" {
					info.OSLoginEnabled = true
				}
			case "enable-oslogin-2fa":
				if item.Value != nil && strings.ToLower(*item.Value) == "true" {
					info.OSLogin2FAEnabled = true
				}
			case "serial-port-enable":
				if item.Value != nil && *item.Value == "true" {
					info.SerialPortEnabled = true
				}
			default:
				// Track other custom metadata keys
				if !isKnownMetadataKey(item.Key) {
					info.CustomMetadataKeys = append(info.CustomMetadataKeys, item.Key)
				}
			}
		}
	}

	return info, nil
}

// isKnownMetadataKey checks if a metadata key is a known system key
func isKnownMetadataKey(key string) bool {
	knownKeys := map[string]bool{
		"ssh-keys":                        true,
		"sshKeys":                         true,
		"startup-script":                  true,
		"startup-script-url":              true,
		"block-project-ssh-keys":          true,
		"enable-oslogin":                  true,
		"enable-oslogin-2fa":              true,
		"serial-port-enable":              true,
		"google-compute-default-zone":     true,
		"google-compute-default-region":   true,
		"google-compute-enable-logging":   true,
		"google-compute-enable-ssh-agent": true,
	}
	return knownKeys[key]
}

// GetInstanceIAMPolicy retrieves IAM policy for a specific instance
func (ces *ComputeEngineService) GetInstanceIAMPolicy(projectID, zone, instanceName string) (*InstanceIAMInfo, error) {
	ctx := context.Background()
	computeService, err := ces.getService(ctx)
	if err != nil {
		return nil, err
	}

	policy, err := computeService.Instances.GetIamPolicy(projectID, zone, instanceName).Do()
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "compute.googleapis.com")
	}

	info := &InstanceIAMInfo{
		InstanceName: instanceName,
		Zone:         zone,
		ProjectID:    projectID,
	}

	for _, binding := range policy.Bindings {
		if binding == nil {
			continue
		}

		switch binding.Role {
		case "roles/compute.admin", "roles/owner":
			info.ComputeAdmins = append(info.ComputeAdmins, binding.Members...)
		case "roles/compute.instanceAdmin", "roles/compute.instanceAdmin.v1":
			info.InstanceAdmins = append(info.InstanceAdmins, binding.Members...)
		case "roles/compute.osLogin", "roles/compute.osAdminLogin":
			info.SSHUsers = append(info.SSHUsers, binding.Members...)
		}

		// Check for specific permissions via custom roles (more complex detection)
		if strings.HasPrefix(binding.Role, "projects/") || strings.HasPrefix(binding.Role, "organizations/") {
			// Custom role - would need to check permissions, but we note the binding
			info.InstanceAdmins = append(info.InstanceAdmins, binding.Members...)
		}
	}

	return info, nil
}

// InstancesWithMetadata retrieves instances with full metadata content
func (ces *ComputeEngineService) InstancesWithMetadata(projectID string) ([]ComputeEngineInfo, *ProjectMetadataInfo, error) {
	instances, err := ces.Instances(projectID)
	if err != nil {
		return nil, nil, err
	}

	projectMeta, err := ces.GetProjectMetadata(projectID)
	if err != nil {
		// Don't fail if we can't get project metadata
		projectMeta = &ProjectMetadataInfo{ProjectID: projectID}
	}

	return instances, projectMeta, nil
}
