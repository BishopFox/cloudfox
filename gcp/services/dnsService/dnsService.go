package dnsservice

import (
	"context"
	"fmt"
	"strings"

	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/internal/gcp/sdk"
	dns "google.golang.org/api/dns/v1"
)

type DNSService struct{
	session *gcpinternal.SafeSession
}

func New() *DNSService {
	return &DNSService{}
}

func NewWithSession(session *gcpinternal.SafeSession) *DNSService {
	return &DNSService{
		session: session,
	}
}

// ZoneInfo holds Cloud DNS managed zone details
type ZoneInfo struct {
	Name              string
	ProjectID         string
	DNSName           string  // The DNS name (e.g., example.com.)
	Description       string
	Visibility        string  // public or private
	CreationTime      string

	// DNSSEC configuration
	DNSSECState       string  // on, off, transfer
	DNSSECKeyType     string

	// Private zone configuration
	PrivateNetworks   []string  // VPC networks for private zones

	// Peering configuration
	PeeringNetwork    string
	PeeringTargetProject string

	// Forwarding configuration
	ForwardingTargets []string

	// Record count
	RecordCount       int64

	// IAM bindings
	IAMBindings       []IAMBinding
}

// IAMBinding represents a single IAM role binding
type IAMBinding struct {
	Role   string
	Member string
}

// RecordInfo holds DNS record details
type RecordInfo struct {
	Name        string
	ProjectID   string
	ZoneName    string
	Type        string  // A, AAAA, CNAME, MX, TXT, etc.
	TTL         int64
	RRDatas     []string  // Record data
}

// TakeoverRisk represents a potential subdomain takeover vulnerability
type TakeoverRisk struct {
	RecordName    string
	RecordType    string
	Target        string
	Service       string   // AWS S3, Azure, GitHub Pages, etc.
	RiskLevel     string   // HIGH, MEDIUM, LOW
	Description   string
	Verification  string   // How to verify the takeover
}

// takeoverPatterns maps CNAME/A record patterns to potential takeover services
var takeoverPatterns = map[string]struct {
	Service     string
	RiskLevel   string
	Description string
}{
	// AWS
	".s3.amazonaws.com":           {"AWS S3", "HIGH", "S3 bucket may be unclaimed - check for 'NoSuchBucket' error"},
	".s3-website":                 {"AWS S3 Website", "HIGH", "S3 website bucket may be unclaimed"},
	".elasticbeanstalk.com":       {"AWS Elastic Beanstalk", "HIGH", "Elastic Beanstalk environment may be deleted"},
	".cloudfront.net":             {"AWS CloudFront", "MEDIUM", "CloudFront distribution may be unconfigured"},
	// Azure
	".azurewebsites.net":          {"Azure App Service", "HIGH", "Azure web app may be deleted"},
	".cloudapp.azure.com":         {"Azure Cloud App", "HIGH", "Azure cloud app may be deleted"},
	".cloudapp.net":               {"Azure Cloud Service", "HIGH", "Azure cloud service may be deleted"},
	".blob.core.windows.net":      {"Azure Blob Storage", "HIGH", "Azure blob container may be deleted"},
	".azure-api.net":              {"Azure API Management", "MEDIUM", "Azure API may be deleted"},
	".azureedge.net":              {"Azure CDN", "MEDIUM", "Azure CDN endpoint may be deleted"},
	".trafficmanager.net":         {"Azure Traffic Manager", "HIGH", "Traffic Manager profile may be deleted"},
	// Google Cloud
	".storage.googleapis.com":     {"GCP Cloud Storage", "HIGH", "GCS bucket may be deleted"},
	".appspot.com":                {"GCP App Engine", "MEDIUM", "App Engine app may be deleted"},
	".run.app":                    {"GCP Cloud Run", "LOW", "Cloud Run service (usually protected)"},
	".cloudfunctions.net":         {"GCP Cloud Functions", "LOW", "Cloud Function (usually protected)"},
	// GitHub
	".github.io":                  {"GitHub Pages", "HIGH", "GitHub Pages repo may be deleted"},
	".githubusercontent.com":      {"GitHub", "MEDIUM", "GitHub resource may be deleted"},
	// Heroku
	".herokuapp.com":              {"Heroku", "HIGH", "Heroku app may be deleted"},
	".herokudns.com":              {"Heroku DNS", "HIGH", "Heroku DNS may be unconfigured"},
	// Other services
	".pantheonsite.io":            {"Pantheon", "HIGH", "Pantheon site may be deleted"},
	".netlify.app":                {"Netlify", "MEDIUM", "Netlify site may be deleted"},
	".netlify.com":                {"Netlify", "MEDIUM", "Netlify site may be deleted"},
	".vercel.app":                 {"Vercel", "MEDIUM", "Vercel deployment may be deleted"},
	".now.sh":                     {"Vercel (Now)", "MEDIUM", "Vercel deployment may be deleted"},
	".surge.sh":                   {"Surge.sh", "HIGH", "Surge project may be deleted"},
	".bitbucket.io":               {"Bitbucket", "HIGH", "Bitbucket repo may be deleted"},
	".ghost.io":                   {"Ghost", "HIGH", "Ghost blog may be deleted"},
	".helpjuice.com":              {"Helpjuice", "HIGH", "Helpjuice site may be deleted"},
	".helpscoutdocs.com":          {"HelpScout", "HIGH", "HelpScout docs may be deleted"},
	".zendesk.com":                {"Zendesk", "MEDIUM", "Zendesk may be unconfigured"},
	".teamwork.com":               {"Teamwork", "HIGH", "Teamwork site may be deleted"},
	".cargocollective.com":        {"Cargo", "HIGH", "Cargo site may be deleted"},
	".feedpress.me":               {"Feedpress", "HIGH", "Feedpress feed may be deleted"},
	".freshdesk.com":              {"Freshdesk", "MEDIUM", "Freshdesk may be unconfigured"},
	".readme.io":                  {"ReadMe", "HIGH", "ReadMe docs may be deleted"},
	".statuspage.io":              {"Statuspage", "HIGH", "Statuspage may be deleted"},
	".smugmug.com":                {"SmugMug", "HIGH", "SmugMug may be deleted"},
	".strikingly.com":             {"Strikingly", "HIGH", "Strikingly site may be deleted"},
	".tilda.ws":                   {"Tilda", "HIGH", "Tilda site may be deleted"},
	".tumblr.com":                 {"Tumblr", "HIGH", "Tumblr blog may be deleted"},
	".unbounce.com":               {"Unbounce", "HIGH", "Unbounce page may be deleted"},
	".webflow.io":                 {"Webflow", "HIGH", "Webflow site may be deleted"},
	".wordpress.com":              {"WordPress.com", "MEDIUM", "WordPress site may be deleted"},
	".wpengine.com":               {"WP Engine", "HIGH", "WP Engine site may be deleted"},
	".desk.com":                   {"Desk.com", "HIGH", "Desk.com may be deleted"},
	".myshopify.com":              {"Shopify", "HIGH", "Shopify store may be deleted"},
	".launchrock.com":             {"LaunchRock", "HIGH", "LaunchRock page may be deleted"},
	".pingdom.com":                {"Pingdom", "MEDIUM", "Pingdom may be unconfigured"},
	".tictail.com":                {"Tictail", "HIGH", "Tictail store may be deleted"},
	".campaignmonitor.com":        {"Campaign Monitor", "HIGH", "Campaign Monitor may be deleted"},
	".canny.io":                   {"Canny", "HIGH", "Canny may be deleted"},
	".getresponse.com":            {"GetResponse", "HIGH", "GetResponse may be deleted"},
	".airee.ru":                   {"Airee", "HIGH", "Airee may be deleted"},
	".thinkific.com":              {"Thinkific", "HIGH", "Thinkific may be deleted"},
	".agilecrm.com":               {"Agile CRM", "HIGH", "Agile CRM may be deleted"},
	".aha.io":                     {"Aha!", "HIGH", "Aha! may be deleted"},
	".animaapp.io":                {"Anima", "HIGH", "Anima may be deleted"},
	".proposify.com":              {"Proposify", "HIGH", "Proposify may be deleted"},
}

// getService returns a DNS service client using cached session if available
func (ds *DNSService) getService(ctx context.Context) (*dns.Service, error) {
	if ds.session != nil {
		return sdk.CachedGetDNSService(ctx, ds.session)
	}
	return dns.NewService(ctx)
}

// Zones retrieves all DNS managed zones in a project
func (ds *DNSService) Zones(projectID string) ([]ZoneInfo, error) {
	ctx := context.Background()

	service, err := ds.getService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "dns.googleapis.com")
	}

	var zones []ZoneInfo

	call := service.ManagedZones.List(projectID)
	err = call.Pages(ctx, func(page *dns.ManagedZonesListResponse) error {
		for _, zone := range page.ManagedZones {
			info := parseZoneInfo(zone, projectID)
			// Get IAM bindings for the zone
			info.IAMBindings = ds.getZoneIAMBindings(service, ctx, projectID, zone.Name)
			zones = append(zones, info)
		}
		return nil
	})

	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "dns.googleapis.com")
	}

	return zones, nil
}

// Records retrieves all DNS records in a zone
func (ds *DNSService) Records(projectID, zoneName string) ([]RecordInfo, error) {
	ctx := context.Background()

	service, err := ds.getService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "dns.googleapis.com")
	}

	var records []RecordInfo

	call := service.ResourceRecordSets.List(projectID, zoneName)
	err = call.Pages(ctx, func(page *dns.ResourceRecordSetsListResponse) error {
		for _, rrset := range page.Rrsets {
			info := RecordInfo{
				Name:      rrset.Name,
				ProjectID: projectID,
				ZoneName:  zoneName,
				Type:      rrset.Type,
				TTL:       rrset.Ttl,
				RRDatas:   rrset.Rrdatas,
			}
			records = append(records, info)
		}
		return nil
	})

	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "dns.googleapis.com")
	}

	return records, nil
}

// parseZoneInfo extracts relevant information from a DNS managed zone
func parseZoneInfo(zone *dns.ManagedZone, projectID string) ZoneInfo {
	info := ZoneInfo{
		Name:         zone.Name,
		ProjectID:    projectID,
		DNSName:      zone.DnsName,
		Description:  zone.Description,
		Visibility:   zone.Visibility,
		CreationTime: zone.CreationTime,
	}

	// DNSSEC configuration
	if zone.DnssecConfig != nil {
		info.DNSSECState = zone.DnssecConfig.State
		if len(zone.DnssecConfig.DefaultKeySpecs) > 0 {
			info.DNSSECKeyType = zone.DnssecConfig.DefaultKeySpecs[0].Algorithm
		}
	}

	// Private zone configuration
	if zone.PrivateVisibilityConfig != nil {
		for _, network := range zone.PrivateVisibilityConfig.Networks {
			info.PrivateNetworks = append(info.PrivateNetworks, extractNetworkName(network.NetworkUrl))
		}
	}

	// Peering configuration
	if zone.PeeringConfig != nil && zone.PeeringConfig.TargetNetwork != nil {
		info.PeeringNetwork = extractNetworkName(zone.PeeringConfig.TargetNetwork.NetworkUrl)
		// Extract project from network URL
		if strings.Contains(zone.PeeringConfig.TargetNetwork.NetworkUrl, "/projects/") {
			parts := strings.Split(zone.PeeringConfig.TargetNetwork.NetworkUrl, "/")
			for i, part := range parts {
				if part == "projects" && i+1 < len(parts) {
					info.PeeringTargetProject = parts[i+1]
					break
				}
			}
		}
	}

	// Forwarding configuration
	if zone.ForwardingConfig != nil {
		for _, target := range zone.ForwardingConfig.TargetNameServers {
			info.ForwardingTargets = append(info.ForwardingTargets, target.Ipv4Address)
		}
	}

	return info
}

// extractNetworkName extracts the network name from a network URL
func extractNetworkName(networkURL string) string {
	// Format: https://www.googleapis.com/compute/v1/projects/PROJECT/global/networks/NETWORK
	parts := strings.Split(networkURL, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return networkURL
}

// CheckTakeoverRisks analyzes DNS records for potential subdomain takeover vulnerabilities
func (ds *DNSService) CheckTakeoverRisks(records []RecordInfo) []TakeoverRisk {
	var risks []TakeoverRisk

	for _, record := range records {
		// Only check CNAME records (primary takeover vector)
		if record.Type != "CNAME" {
			continue
		}

		for _, target := range record.RRDatas {
			targetLower := strings.ToLower(target)

			// Check against known vulnerable patterns
			for pattern, info := range takeoverPatterns {
				if strings.Contains(targetLower, pattern) {
					risk := TakeoverRisk{
						RecordName:   record.Name,
						RecordType:   record.Type,
						Target:       target,
						Service:      info.Service,
						RiskLevel:    info.RiskLevel,
						Description:  info.Description,
						Verification: generateVerificationCommand(record.Name, target, info.Service),
					}
					risks = append(risks, risk)
					break // Only match first pattern
				}
			}
		}
	}

	return risks
}

// generateVerificationCommand creates a command to verify if takeover is possible
func generateVerificationCommand(recordName, target, service string) string {
	// Remove trailing dot from DNS names
	name := strings.TrimSuffix(recordName, ".")

	switch {
	case strings.Contains(service, "S3"):
		return fmt.Sprintf("curl -sI http://%s | head -5  # Look for 'NoSuchBucket'", name)
	case strings.Contains(service, "Azure"):
		return fmt.Sprintf("curl -sI https://%s | head -5  # Look for 'NXDOMAIN' or error page", name)
	case strings.Contains(service, "GitHub"):
		return fmt.Sprintf("curl -sI https://%s | head -5  # Look for '404' or 'no GitHub Pages'", name)
	case strings.Contains(service, "Heroku"):
		return fmt.Sprintf("curl -sI https://%s | head -5  # Look for 'no such app'", name)
	default:
		return fmt.Sprintf("dig %s && curl -sI https://%s | head -5", name, name)
	}
}

// getZoneIAMBindings retrieves IAM bindings for a DNS managed zone
func (ds *DNSService) getZoneIAMBindings(service *dns.Service, ctx context.Context, projectID, zoneName string) []IAMBinding {
	var bindings []IAMBinding

	resource := "projects/" + projectID + "/managedZones/" + zoneName
	policy, err := service.ManagedZones.GetIamPolicy(resource, &dns.GoogleIamV1GetIamPolicyRequest{}).Context(ctx).Do()
	if err != nil {
		// Return empty bindings if we can't get IAM policy
		return bindings
	}

	for _, binding := range policy.Bindings {
		for _, member := range binding.Members {
			bindings = append(bindings, IAMBinding{
				Role:   binding.Role,
				Member: member,
			})
		}
	}

	return bindings
}
