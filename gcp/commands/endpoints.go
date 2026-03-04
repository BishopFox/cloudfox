package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	cloudsqlservice "github.com/BishopFox/cloudfox/gcp/services/cloudsqlService"
	composerservice "github.com/BishopFox/cloudfox/gcp/services/composerService"
	dataprocservice "github.com/BishopFox/cloudfox/gcp/services/dataprocService"
	filestoreservice "github.com/BishopFox/cloudfox/gcp/services/filestoreService"
	functionsservice "github.com/BishopFox/cloudfox/gcp/services/functionsService"
	gkeservice "github.com/BishopFox/cloudfox/gcp/services/gkeService"
	memorystoreservice "github.com/BishopFox/cloudfox/gcp/services/memorystoreService"
	notebooksservice "github.com/BishopFox/cloudfox/gcp/services/notebooksService"
	pubsubservice "github.com/BishopFox/cloudfox/gcp/services/pubsubService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"

	appengine "google.golang.org/api/appengine/v1"
	compute "google.golang.org/api/compute/v1"
	run "google.golang.org/api/run/v1"
)

var GCPEndpointsCommand = &cobra.Command{
	Use:     "endpoints",
	Aliases: []string{"exposure", "external", "public-ips", "internet-facing"},
	Short:   "Enumerate all network endpoints (external and internal) with IPs, URLs, and hostnames",
	Long: `Enumerate all network endpoints in GCP with comprehensive analysis.

Features:
- Static external IP addresses
- Compute Engine instances (external and internal IPs)
- Load balancers (HTTP(S), TCP, UDP) - external and internal
- Cloud Run services and jobs
- Cloud Functions HTTP triggers
- GKE cluster API endpoints
- Cloud SQL instances (MySQL, PostgreSQL, SQL Server)
- Memorystore Redis instances
- Filestore NFS instances
- Cloud Composer/Airflow web UI URLs
- Pub/Sub push subscription endpoints
- App Engine services
- Vertex AI Notebooks
- Dataproc clusters (master/worker nodes)
- VPN Gateways
- Cloud NAT gateways
- Private Service Connect endpoints

Output includes a unified table with Exposure (External/Internal) column.`,
	Run: runGCPEndpointsCommand,
}

// ------------------------------
// Data Structures
// ------------------------------

type Endpoint struct {
	ProjectID      string
	Name           string
	Type           string // Static IP, Instance, LoadBalancer, Cloud Run, GKE, Cloud SQL, etc.
	ExternalIP     string
	InternalIP     string
	Hostname       string
	Protocol       string
	Port           string
	Resource       string
	ResourceType   string
	Region         string
	Status         string
	ServiceAccount string
	TLSEnabled     bool
	IsExternal     bool   // true for external, false for internal
	Network        string // VPC network name
	Security       string // Security notes (e.g., "No Auth", "Public", "SSL Required")
}

// ------------------------------
// Module Struct
// ------------------------------
type EndpointsModule struct {
	gcpinternal.BaseGCPModule

	ProjectEndpoints map[string][]Endpoint // projectID -> endpoints
	mu               sync.Mutex

	// Firewall rule mapping: "network:tag1,tag2" -> allowed ports
	firewallPortMap map[string][]string
}

// ------------------------------
// Output Struct
// ------------------------------
type EndpointsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o EndpointsOutput) TableFiles() []internal.TableFile { return o.Table }
func (o EndpointsOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPEndpointsCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, "endpoints")
	if err != nil {
		return
	}

	module := &EndpointsModule{
		BaseGCPModule:    gcpinternal.NewBaseGCPModule(cmdCtx),
		ProjectEndpoints: make(map[string][]Endpoint),
		firewallPortMap:  make(map[string][]string),
	}

	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *EndpointsModule) getAllEndpoints() []Endpoint {
	var all []Endpoint
	for _, endpoints := range m.ProjectEndpoints {
		all = append(all, endpoints...)
	}
	return all
}

func (m *EndpointsModule) Execute(ctx context.Context, logger internal.Logger) {
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, "endpoints", m.processProject)

	allEndpoints := m.getAllEndpoints()
	if len(allEndpoints) == 0 {
		logger.InfoM("No endpoints found", "endpoints")
		return
	}

	// Count external vs internal
	externalCount := 0
	internalCount := 0
	for _, ep := range allEndpoints {
		if ep.IsExternal {
			externalCount++
		} else {
			internalCount++
		}
	}

	logger.SuccessM(fmt.Sprintf("Found %d endpoint(s) [%d external, %d internal]",
		len(allEndpoints), externalCount, internalCount), "endpoints")

	m.writeOutput(ctx, logger)
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *EndpointsModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Analyzing endpoints in project: %s", projectID), "endpoints")
	}

	computeService, err := compute.NewService(ctx)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, "endpoints",
			fmt.Sprintf("Could not create Compute service in project %s", projectID))
	} else {
		// Compute-based endpoints
		m.analyzeFirewallRules(ctx, computeService, projectID, logger)
		m.getStaticExternalIPs(ctx, computeService, projectID, logger)
		m.getInstanceIPs(ctx, computeService, projectID, logger)
		m.getLoadBalancers(ctx, computeService, projectID, logger)
		m.getVPNGateways(ctx, computeService, projectID, logger)
		m.getCloudNAT(ctx, computeService, projectID, logger)
		m.getPrivateServiceConnect(ctx, computeService, projectID, logger)
	}

	// Serverless endpoints
	m.getCloudRunServices(ctx, projectID, logger)
	m.getCloudFunctions(ctx, projectID, logger)
	m.getAppEngineServices(ctx, projectID, logger)

	// Container/Kubernetes endpoints
	m.getGKEClusters(ctx, projectID, logger)

	// Database endpoints
	m.getCloudSQLInstances(ctx, projectID, logger)
	m.getMemorystoreRedis(ctx, projectID, logger)

	// Storage endpoints
	m.getFilestoreInstances(ctx, projectID, logger)

	// Data/ML endpoints
	m.getComposerEnvironments(ctx, projectID, logger)
	m.getDataprocClusters(ctx, projectID, logger)
	m.getNotebookInstances(ctx, projectID, logger)

	// Messaging endpoints
	m.getPubSubPushEndpoints(ctx, projectID, logger)
}

// getStaticExternalIPs retrieves static external IP addresses
func (m *EndpointsModule) getStaticExternalIPs(ctx context.Context, svc *compute.Service, projectID string, logger internal.Logger) {
	// Global addresses
	req := svc.GlobalAddresses.List(projectID)
	if err := req.Pages(ctx, func(page *compute.AddressList) error {
		for _, addr := range page.Items {
			if addr.AddressType == "EXTERNAL" {
				user := ""
				if len(addr.Users) > 0 {
					user = extractResourceName(addr.Users[0])
				}
				security := ""
				if user == "" {
					security = "Unused"
				}
				ep := Endpoint{
					ProjectID:    projectID,
					Name:         addr.Name,
					Type:         "Static IP",
					ExternalIP:   addr.Address,
					Protocol:     "TCP/UDP",
					Port:         "ALL",
					Resource:     user,
					ResourceType: "Address",
					Region:       "global",
					Status:       addr.Status,
					IsExternal:   true,
					Security:     security,
				}
				m.addEndpoint(projectID, ep)
			}
		}
		return nil
	}); err != nil {
		gcpinternal.HandleGCPError(err, logger, "endpoints",
			fmt.Sprintf("Could not list global addresses in project %s", projectID))
	}

	// Regional addresses - use AggregatedList to avoid needing compute.regions.list permission
	addrReq := svc.Addresses.AggregatedList(projectID)
	if err := addrReq.Pages(ctx, func(page *compute.AddressAggregatedList) error {
		for scopeName, scopedList := range page.Items {
			if scopedList.Addresses == nil {
				continue
			}
			// Extract region from scope name (format: "regions/us-central1")
			regionName := "unknown"
			if strings.HasPrefix(scopeName, "regions/") {
				regionName = strings.TrimPrefix(scopeName, "regions/")
			}
			for _, addr := range scopedList.Addresses {
				if addr.AddressType == "EXTERNAL" {
					user := ""
					if len(addr.Users) > 0 {
						user = extractResourceName(addr.Users[0])
					}
					security := ""
					if user == "" {
						security = "Unused"
					}
					ep := Endpoint{
						ProjectID:    projectID,
						Name:         addr.Name,
						Type:         "Static IP",
						ExternalIP:   addr.Address,
						Protocol:     "TCP/UDP",
						Port:         "ALL",
						Resource:     user,
						ResourceType: "Address",
						Region:       regionName,
						Status:       addr.Status,
						IsExternal:   true,
						Security:     security,
					}
					m.addEndpoint(projectID, ep)
				}
			}
		}
		return nil
	}); err != nil {
		gcpinternal.HandleGCPError(err, logger, "endpoints",
			fmt.Sprintf("Could not list regional addresses in project %s", projectID))
	}
}

// getInstanceIPs retrieves instances with both external and internal IPs
func (m *EndpointsModule) getInstanceIPs(ctx context.Context, svc *compute.Service, projectID string, logger internal.Logger) {
	req := svc.Instances.AggregatedList(projectID)
	if err := req.Pages(ctx, func(page *compute.InstanceAggregatedList) error {
		for zone, scopedList := range page.Items {
			if scopedList.Instances == nil {
				continue
			}
			for _, instance := range scopedList.Instances {
				zoneName := extractZoneFromScope(zone)

				var serviceAccount string
				if len(instance.ServiceAccounts) > 0 {
					serviceAccount = instance.ServiceAccounts[0].Email
				}

				for _, iface := range instance.NetworkInterfaces {
					networkName := extractResourceName(iface.Network)
					internalIP := iface.NetworkIP

					// External IP
					for _, accessConfig := range iface.AccessConfigs {
						if accessConfig.NatIP != "" {
							ep := Endpoint{
								ProjectID:      projectID,
								Name:           instance.Name,
								Type:           "Compute Engine",
								ExternalIP:     accessConfig.NatIP,
								InternalIP:     internalIP,
								Protocol:       "TCP/UDP",
								Port:           "ALL",
								ResourceType:   "Instance",
								Region:         zoneName,
								Status:         instance.Status,
								ServiceAccount: serviceAccount,
								IsExternal:     true,
								Network:        networkName,
							}
							m.addEndpoint(projectID, ep)
						}
					}

					// Internal only (no external IP)
					hasExternalIP := false
					for _, accessConfig := range iface.AccessConfigs {
						if accessConfig.NatIP != "" {
							hasExternalIP = true
							break
						}
					}
					if !hasExternalIP && internalIP != "" {
						ports := m.getPortsForInstance(networkName, instance.Tags)
						ep := Endpoint{
							ProjectID:      projectID,
							Name:           instance.Name,
							Type:           "Compute Engine",
							InternalIP:     internalIP,
							Protocol:       "TCP/UDP",
							Port:           ports,
							ResourceType:   "Instance",
							Region:         zoneName,
							Status:         instance.Status,
							ServiceAccount: serviceAccount,
							IsExternal:     false,
							Network:        networkName,
						}
						m.addEndpoint(projectID, ep)
					}
				}
			}
		}
		return nil
	}); err != nil {
		gcpinternal.HandleGCPError(err, logger, "endpoints",
			fmt.Sprintf("Could not list instances in project %s", projectID))
	}
}

// getPortsForInstance determines open ports for an instance based on firewall rules
func (m *EndpointsModule) getPortsForInstance(network string, tags *compute.Tags) string {
	var allPorts []string

	if ports, ok := m.firewallPortMap[network]; ok {
		allPorts = append(allPorts, ports...)
	}

	if tags != nil {
		for _, tag := range tags.Items {
			key := fmt.Sprintf("%s:%s", network, tag)
			if ports, ok := m.firewallPortMap[key]; ok {
				allPorts = append(allPorts, ports...)
			}
		}
	}

	if len(allPorts) == 0 {
		return "ALL"
	}

	portSet := make(map[string]bool)
	for _, p := range allPorts {
		portSet[p] = true
	}
	var uniquePorts []string
	for p := range portSet {
		uniquePorts = append(uniquePorts, p)
	}

	return strings.Join(uniquePorts, ",")
}

// getLoadBalancers retrieves both external and internal load balancers
func (m *EndpointsModule) getLoadBalancers(ctx context.Context, svc *compute.Service, projectID string, logger internal.Logger) {
	// Regional forwarding rules
	req := svc.ForwardingRules.AggregatedList(projectID)
	if err := req.Pages(ctx, func(page *compute.ForwardingRuleAggregatedList) error {
		for region, scopedList := range page.Items {
			if scopedList.ForwardingRules == nil {
				continue
			}
			for _, rule := range scopedList.ForwardingRules {
				ports := "ALL"
				if rule.PortRange != "" {
					ports = rule.PortRange
				} else if len(rule.Ports) > 0 {
					ports = strings.Join(rule.Ports, ",")
				}

				target := extractResourceName(rule.Target)
				if target == "" && rule.BackendService != "" {
					target = extractResourceName(rule.BackendService)
				}

				isExternal := rule.LoadBalancingScheme == "EXTERNAL" || rule.LoadBalancingScheme == "EXTERNAL_MANAGED"
				isInternal := rule.LoadBalancingScheme == "INTERNAL" || rule.LoadBalancingScheme == "INTERNAL_MANAGED" || rule.LoadBalancingScheme == "INTERNAL_SELF_MANAGED"

				lbType := "LoadBalancer"
				if isInternal {
					lbType = "Internal LB"
				}

				if isExternal || isInternal {
					tlsEnabled := rule.PortRange == "443" || strings.Contains(strings.ToLower(rule.Name), "https")
					security := ""
					if isExternal && !tlsEnabled && ports != "443" {
						security = "No TLS"
					}

					ep := Endpoint{
						ProjectID:    projectID,
						Name:         rule.Name,
						Type:         lbType,
						Protocol:     rule.IPProtocol,
						Port:         ports,
						Resource:     target,
						ResourceType: "ForwardingRule",
						Region:       extractRegionFromScope(region),
						TLSEnabled:   tlsEnabled,
						IsExternal:   isExternal,
						Network:      extractResourceName(rule.Network),
						Security:     security,
					}
					if isExternal {
						ep.ExternalIP = rule.IPAddress
					} else {
						ep.InternalIP = rule.IPAddress
					}
					m.addEndpoint(projectID, ep)
				}
			}
		}
		return nil
	}); err != nil {
		gcpinternal.HandleGCPError(err, logger, "endpoints",
			fmt.Sprintf("Could not list regional forwarding rules in project %s", projectID))
	}

	// Global forwarding rules
	globalReq := svc.GlobalForwardingRules.List(projectID)
	if err := globalReq.Pages(ctx, func(page *compute.ForwardingRuleList) error {
		for _, rule := range page.Items {
			if rule.LoadBalancingScheme == "EXTERNAL" || rule.LoadBalancingScheme == "EXTERNAL_MANAGED" {
				ports := "ALL"
				if rule.PortRange != "" {
					ports = rule.PortRange
				}

				tlsEnabled := rule.PortRange == "443" || strings.Contains(strings.ToLower(rule.Name), "https")
				security := ""
				if !tlsEnabled && ports != "443" {
					security = "No TLS"
				}

				ep := Endpoint{
					ProjectID:    projectID,
					Name:         rule.Name,
					Type:         "Global LB",
					ExternalIP:   rule.IPAddress,
					Protocol:     rule.IPProtocol,
					Port:         ports,
					Resource:     extractResourceName(rule.Target),
					ResourceType: "GlobalForwardingRule",
					Region:       "global",
					TLSEnabled:   tlsEnabled,
					IsExternal:   true,
					Security:     security,
				}
				m.addEndpoint(projectID, ep)
			}
		}
		return nil
	}); err != nil {
		gcpinternal.HandleGCPError(err, logger, "endpoints",
			fmt.Sprintf("Could not list global forwarding rules in project %s", projectID))
	}
}

// getVPNGateways retrieves VPN gateway external IPs
func (m *EndpointsModule) getVPNGateways(ctx context.Context, svc *compute.Service, projectID string, logger internal.Logger) {
	// Classic VPN Gateways
	req := svc.TargetVpnGateways.AggregatedList(projectID)
	if err := req.Pages(ctx, func(page *compute.TargetVpnGatewayAggregatedList) error {
		for region, scopedList := range page.Items {
			if scopedList.TargetVpnGateways == nil {
				continue
			}
			for _, gw := range scopedList.TargetVpnGateways {
				for i, ip := range gw.ForwardingRules {
					ep := Endpoint{
						ProjectID:    projectID,
						Name:         fmt.Sprintf("%s-ip%d", gw.Name, i),
						Type:         "VPN Gateway",
						ExternalIP:   extractResourceName(ip),
						Protocol:     "ESP/UDP",
						Port:         "500,4500",
						ResourceType: "VPNGateway",
						Region:       extractRegionFromScope(region),
						Status:       gw.Status,
						IsExternal:   true,
						Network:      extractResourceName(gw.Network),
					}
					m.addEndpoint(projectID, ep)
				}
			}
		}
		return nil
	}); err != nil {
		gcpinternal.HandleGCPError(err, logger, "endpoints",
			fmt.Sprintf("Could not list classic VPN gateways in project %s", projectID))
	}

	// HA VPN Gateways
	haReq := svc.VpnGateways.AggregatedList(projectID)
	if err := haReq.Pages(ctx, func(page *compute.VpnGatewayAggregatedList) error {
		for region, scopedList := range page.Items {
			if scopedList.VpnGateways == nil {
				continue
			}
			for _, gw := range scopedList.VpnGateways {
				for _, iface := range gw.VpnInterfaces {
					if iface.IpAddress != "" {
						ep := Endpoint{
							ProjectID:    projectID,
							Name:         fmt.Sprintf("%s-if%d", gw.Name, iface.Id),
							Type:         "HA VPN Gateway",
							ExternalIP:   iface.IpAddress,
							Protocol:     "ESP/UDP",
							Port:         "500,4500",
							ResourceType: "HAVPNGateway",
							Region:       extractRegionFromScope(region),
							IsExternal:   true,
							Network:      extractResourceName(gw.Network),
						}
						m.addEndpoint(projectID, ep)
					}
				}
			}
		}
		return nil
	}); err != nil {
		gcpinternal.HandleGCPError(err, logger, "endpoints",
			fmt.Sprintf("Could not list HA VPN gateways in project %s", projectID))
	}
}

// getCloudNAT retrieves Cloud NAT external IPs
func (m *EndpointsModule) getCloudNAT(ctx context.Context, svc *compute.Service, projectID string, logger internal.Logger) {
	req := svc.Routers.AggregatedList(projectID)
	if err := req.Pages(ctx, func(page *compute.RouterAggregatedList) error {
		for region, scopedList := range page.Items {
			if scopedList.Routers == nil {
				continue
			}
			for _, router := range scopedList.Routers {
				for _, nat := range router.Nats {
					for _, ip := range nat.NatIps {
						ep := Endpoint{
							ProjectID:    projectID,
							Name:         fmt.Sprintf("%s/%s", router.Name, nat.Name),
							Type:         "Cloud NAT",
							ExternalIP:   extractResourceName(ip),
							Protocol:     "TCP/UDP",
							Port:         "ALL",
							ResourceType: "CloudNAT",
							Region:       extractRegionFromScope(region),
							IsExternal:   true,
							Network:      extractResourceName(router.Network),
						}
						m.addEndpoint(projectID, ep)
					}
				}
			}
		}
		return nil
	}); err != nil {
		gcpinternal.HandleGCPError(err, logger, "endpoints",
			fmt.Sprintf("Could not list Cloud NAT routers in project %s", projectID))
	}
}

// getPrivateServiceConnect retrieves Private Service Connect endpoints
func (m *EndpointsModule) getPrivateServiceConnect(ctx context.Context, svc *compute.Service, projectID string, logger internal.Logger) {
	// Service Attachments (producer side)
	saReq := svc.ServiceAttachments.AggregatedList(projectID)
	if err := saReq.Pages(ctx, func(page *compute.ServiceAttachmentAggregatedList) error {
		for region, scopedList := range page.Items {
			if scopedList.ServiceAttachments == nil {
				continue
			}
			for _, sa := range scopedList.ServiceAttachments {
				ep := Endpoint{
					ProjectID:    projectID,
					Name:         sa.Name,
					Type:         "PSC Service",
					Hostname:     sa.SelfLink,
					Protocol:     "TCP",
					Port:         "ALL",
					ResourceType: "ServiceAttachment",
					Region:       extractRegionFromScope(region),
					IsExternal:   false,
				}
				m.addEndpoint(projectID, ep)
			}
		}
		return nil
	}); err != nil {
		gcpinternal.HandleGCPError(err, logger, "endpoints",
			fmt.Sprintf("Could not list service attachments in project %s", projectID))
	}
}

// getCloudRunServices retrieves Cloud Run services
func (m *EndpointsModule) getCloudRunServices(ctx context.Context, projectID string, logger internal.Logger) {
	runService, err := run.NewService(ctx)
	if err != nil {
		return
	}

	parent := fmt.Sprintf("projects/%s/locations/-", projectID)
	resp, err := runService.Projects.Locations.Services.List(parent).Do()
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, "endpoints",
			fmt.Sprintf("Could not list Cloud Run services in project %s", projectID))
		return
	}

	for _, service := range resp.Items {
		if service.Status != nil && service.Status.Url != "" {
			hostname := strings.TrimPrefix(service.Status.Url, "https://")

			ep := Endpoint{
				ProjectID:    projectID,
				Name:         service.Metadata.Name,
				Type:         "Cloud Run",
				Hostname:     hostname,
				Protocol:     "HTTPS",
				Port:         "443",
				ResourceType: "CloudRun",
				TLSEnabled:   true,
				IsExternal:   true,
			}

			if service.Metadata != nil && service.Metadata.Labels != nil {
				if region, ok := service.Metadata.Labels["cloud.googleapis.com/location"]; ok {
					ep.Region = region
				}
			}

			if service.Spec != nil && service.Spec.Template != nil && service.Spec.Template.Spec != nil {
				ep.ServiceAccount = service.Spec.Template.Spec.ServiceAccountName
			}

			m.addEndpoint(projectID, ep)
		}
	}
}

// getCloudFunctions retrieves Cloud Functions with HTTP triggers
func (m *EndpointsModule) getCloudFunctions(ctx context.Context, projectID string, logger internal.Logger) {
	fs := functionsservice.New()
	functions, err := fs.Functions(projectID)
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, "endpoints",
			fmt.Sprintf("Could not list Cloud Functions in project %s", projectID))
		return
	}

	for _, fn := range functions {
		if fn.TriggerURL != "" {
			hostname := strings.TrimPrefix(fn.TriggerURL, "https://")
			security := ""
			if fn.IsPublic {
				security = "Public (No Auth)"
			}

			ep := Endpoint{
				ProjectID:      projectID,
				Name:           fn.Name,
				Type:           "Cloud Function",
				Hostname:       hostname,
				Protocol:       "HTTPS",
				Port:           "443",
				ResourceType:   "CloudFunction",
				Region:         fn.Region,
				Status:         fn.State,
				ServiceAccount: fn.ServiceAccount,
				TLSEnabled:     true,
				IsExternal:     true,
				Security:       security,
			}
			m.addEndpoint(projectID, ep)
		}
	}
}

// getAppEngineServices retrieves App Engine services
func (m *EndpointsModule) getAppEngineServices(ctx context.Context, projectID string, logger internal.Logger) {
	aeService, err := appengine.NewService(ctx)
	if err != nil {
		return
	}

	// Get app info
	app, err := aeService.Apps.Get(projectID).Do()
	if err != nil {
		// App Engine not enabled or no app
		return
	}

	// List services
	servicesResp, err := aeService.Apps.Services.List(projectID).Do()
	if err != nil {
		return
	}

	for _, svc := range servicesResp.Services {
		// Default service hostname
		hostname := fmt.Sprintf("%s.appspot.com", projectID)
		if svc.Id != "default" {
			hostname = fmt.Sprintf("%s-dot-%s.appspot.com", svc.Id, projectID)
		}

		ep := Endpoint{
			ProjectID:    projectID,
			Name:         svc.Id,
			Type:         "App Engine",
			Hostname:     hostname,
			Protocol:     "HTTPS",
			Port:         "443",
			ResourceType: "AppEngine",
			Region:       app.LocationId,
			TLSEnabled:   true,
			IsExternal:   true,
		}
		m.addEndpoint(projectID, ep)
	}
}

// getGKEClusters retrieves GKE cluster API endpoints
func (m *EndpointsModule) getGKEClusters(ctx context.Context, projectID string, logger internal.Logger) {
	gs := gkeservice.New()
	clusters, _, err := gs.Clusters(projectID)
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, "endpoints",
			fmt.Sprintf("Could not list GKE clusters in project %s", projectID))
		return
	}

	for _, cluster := range clusters {
		if cluster.Endpoint != "" {
			isExternal := !cluster.PrivateCluster
			security := ""
			if !cluster.PrivateCluster && !cluster.MasterAuthorizedOnly {
				security = "Public API (No Restrictions)"
			} else if cluster.MasterAuthorizedOnly {
				security = "Authorized Networks Only"
			}

			ep := Endpoint{
				ProjectID:    projectID,
				Name:         cluster.Name,
				Type:         "GKE API",
				Protocol:     "HTTPS",
				Port:         "443",
				ResourceType: "GKECluster",
				Region:       cluster.Location,
				Status:       cluster.Status,
				TLSEnabled:   true,
				IsExternal:   isExternal,
				Network:      cluster.Network,
				Security:     security,
			}
			if isExternal {
				ep.ExternalIP = cluster.Endpoint
			} else {
				ep.InternalIP = cluster.Endpoint
			}
			m.addEndpoint(projectID, ep)
		}
	}
}

// getCloudSQLInstances retrieves Cloud SQL instances
func (m *EndpointsModule) getCloudSQLInstances(ctx context.Context, projectID string, logger internal.Logger) {
	cs := cloudsqlservice.New()
	instances, err := cs.Instances(projectID)
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, "endpoints",
			fmt.Sprintf("Could not list Cloud SQL instances in project %s", projectID))
		return
	}

	for _, instance := range instances {
		port := "3306" // MySQL default
		if strings.Contains(instance.DatabaseVersion, "POSTGRES") {
			port = "5432"
		} else if strings.Contains(instance.DatabaseVersion, "SQLSERVER") {
			port = "1433"
		}

		// Public IP
		if instance.PublicIP != "" {
			security := ""
			if !instance.RequireSSL {
				security = "SSL Not Required"
			}
			for _, an := range instance.AuthorizedNetworks {
				if an.IsPublic {
					security = "Open to 0.0.0.0/0"
					break
				}
			}

			ep := Endpoint{
				ProjectID:    projectID,
				Name:         instance.Name,
				Type:         "Cloud SQL",
				ExternalIP:   instance.PublicIP,
				InternalIP:   instance.PrivateIP,
				Protocol:     "TCP",
				Port:         port,
				ResourceType: "CloudSQL",
				Region:       instance.Region,
				Status:       instance.State,
				TLSEnabled:   instance.RequireSSL,
				IsExternal:   true,
				Security:     security,
			}
			m.addEndpoint(projectID, ep)
		} else if instance.PrivateIP != "" {
			// Private IP only
			ep := Endpoint{
				ProjectID:    projectID,
				Name:         instance.Name,
				Type:         "Cloud SQL",
				InternalIP:   instance.PrivateIP,
				Protocol:     "TCP",
				Port:         port,
				ResourceType: "CloudSQL",
				Region:       instance.Region,
				Status:       instance.State,
				TLSEnabled:   instance.RequireSSL,
				IsExternal:   false,
			}
			m.addEndpoint(projectID, ep)
		}
	}
}

// getMemorystoreRedis retrieves Memorystore Redis instances
func (m *EndpointsModule) getMemorystoreRedis(ctx context.Context, projectID string, logger internal.Logger) {
	ms := memorystoreservice.New()
	instances, err := ms.ListRedisInstances(projectID)
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, "endpoints",
			fmt.Sprintf("Could not list Memorystore Redis instances in project %s", projectID))
		return
	}

	for _, instance := range instances {
		if instance.Host != "" {
			security := ""
			if !instance.AuthEnabled {
				security = "No Auth"
			}
			if instance.TransitEncryption == "DISABLED" {
				if security != "" {
					security += ", "
				}
				security += "No TLS"
			}

			ep := Endpoint{
				ProjectID:    projectID,
				Name:         instance.Name,
				Type:         "Redis",
				InternalIP:   instance.Host,
				Protocol:     "TCP",
				Port:         fmt.Sprintf("%d", instance.Port),
				ResourceType: "Memorystore",
				Region:       instance.Location,
				Status:       instance.State,
				TLSEnabled:   instance.TransitEncryption != "DISABLED",
				IsExternal:   false,
				Network:      extractResourceName(instance.AuthorizedNetwork),
				Security:     security,
			}
			m.addEndpoint(projectID, ep)
		}
	}
}

// getFilestoreInstances retrieves Filestore NFS instances
func (m *EndpointsModule) getFilestoreInstances(ctx context.Context, projectID string, logger internal.Logger) {
	fs := filestoreservice.New()
	instances, err := fs.ListInstances(projectID)
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, "endpoints",
			fmt.Sprintf("Could not list Filestore instances in project %s", projectID))
		return
	}

	for _, instance := range instances {
		for _, ip := range instance.IPAddresses {
			security := ""
			for _, share := range instance.Shares {
				for _, opt := range share.NfsExportOptions {
					if opt.SquashMode == "NO_ROOT_SQUASH" {
						security = "NO_ROOT_SQUASH"
						break
					}
				}
			}

			ep := Endpoint{
				ProjectID:    projectID,
				Name:         instance.Name,
				Type:         "Filestore NFS",
				InternalIP:   ip,
				Protocol:     "NFS",
				Port:         "2049",
				ResourceType: "Filestore",
				Region:       instance.Location,
				Status:       instance.State,
				IsExternal:   false,
				Network:      instance.Network,
				Security:     security,
			}
			m.addEndpoint(projectID, ep)
		}
	}
}

// getComposerEnvironments retrieves Cloud Composer Airflow web UI URLs
func (m *EndpointsModule) getComposerEnvironments(ctx context.Context, projectID string, logger internal.Logger) {
	cs := composerservice.New()
	environments, err := cs.ListEnvironments(projectID)
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, "endpoints",
			fmt.Sprintf("Could not list Composer environments in project %s", projectID))
		return
	}

	for _, env := range environments {
		if env.AirflowURI != "" {
			hostname := strings.TrimPrefix(env.AirflowURI, "https://")
			security := ""
			if !env.PrivateEnvironment {
				security = "Public Web UI"
			}
			for _, ip := range env.WebServerAllowedIPs {
				if ip == "0.0.0.0/0" {
					security = "Open to 0.0.0.0/0"
					break
				}
			}

			ep := Endpoint{
				ProjectID:      projectID,
				Name:           env.Name,
				Type:           "Composer Airflow",
				Hostname:       hostname,
				Protocol:       "HTTPS",
				Port:           "443",
				ResourceType:   "Composer",
				Region:         env.Location,
				Status:         env.State,
				ServiceAccount: env.ServiceAccount,
				TLSEnabled:     true,
				IsExternal:     !env.PrivateEnvironment,
				Network:        extractResourceName(env.Network),
				Security:       security,
			}
			m.addEndpoint(projectID, ep)
		}
	}
}

// getDataprocClusters retrieves Dataproc cluster master/worker IPs
func (m *EndpointsModule) getDataprocClusters(ctx context.Context, projectID string, logger internal.Logger) {
	ds := dataprocservice.New()
	clusters, err := ds.ListClusters(projectID)
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, "endpoints",
			fmt.Sprintf("Could not list Dataproc clusters in project %s", projectID))
		return
	}

	for _, cluster := range clusters {
		// Master nodes - these are the main SSH/Spark/HDFS entry points
		security := ""
		if !cluster.InternalIPOnly {
			security = "External IPs Enabled"
		}

		ep := Endpoint{
			ProjectID:      projectID,
			Name:           cluster.Name + "-master",
			Type:           "Dataproc Master",
			Protocol:       "TCP",
			Port:           "22,8088,9870,8080",
			ResourceType:   "DataprocCluster",
			Region:         cluster.Region,
			Status:         cluster.State,
			ServiceAccount: cluster.ServiceAccount,
			IsExternal:     !cluster.InternalIPOnly,
			Network:        cluster.Network,
			Security:       security,
		}
		m.addEndpoint(projectID, ep)
	}
}

// getNotebookInstances retrieves Vertex AI Notebook instances
func (m *EndpointsModule) getNotebookInstances(ctx context.Context, projectID string, logger internal.Logger) {
	ns := notebooksservice.New()
	instances, err := ns.ListInstances(projectID)
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, "endpoints",
			fmt.Sprintf("Could not list Notebook instances in project %s", projectID))
		return
	}

	for _, instance := range instances {
		if instance.ProxyUri != "" {
			hostname := strings.TrimPrefix(instance.ProxyUri, "https://")
			security := ""
			if !instance.NoPublicIP {
				security = "Public IP Enabled"
			}
			if instance.NoProxyAccess {
				security = "Proxy Access Disabled"
			}

			ep := Endpoint{
				ProjectID:      projectID,
				Name:           instance.Name,
				Type:           "Vertex AI Notebook",
				Hostname:       hostname,
				Protocol:       "HTTPS",
				Port:           "443",
				ResourceType:   "Notebook",
				Region:         instance.Location,
				Status:         instance.State,
				ServiceAccount: instance.ServiceAccount,
				TLSEnabled:     true,
				IsExternal:     !instance.NoPublicIP,
				Network:        instance.Network,
				Security:       security,
			}
			m.addEndpoint(projectID, ep)
		}
	}
}

// getPubSubPushEndpoints retrieves Pub/Sub push subscription endpoints
func (m *EndpointsModule) getPubSubPushEndpoints(ctx context.Context, projectID string, logger internal.Logger) {
	ps := pubsubservice.New()
	subscriptions, err := ps.Subscriptions(projectID)
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, "endpoints",
			fmt.Sprintf("Could not list Pub/Sub subscriptions in project %s", projectID))
		return
	}

	for _, sub := range subscriptions {
		if sub.PushEndpoint != "" {
			hostname := sub.PushEndpoint
			hostname = strings.TrimPrefix(hostname, "https://")
			hostname = strings.TrimPrefix(hostname, "http://")
			if idx := strings.Index(hostname, "/"); idx != -1 {
				hostname = hostname[:idx]
			}

			ep := Endpoint{
				ProjectID:      projectID,
				Name:           sub.Name,
				Type:           "Pub/Sub Push",
				Hostname:       hostname,
				Protocol:       "HTTPS",
				Port:           "443",
				Resource:       sub.Topic,
				ResourceType:   "PubSubSubscription",
				ServiceAccount: sub.PushServiceAccount,
				TLSEnabled:     strings.HasPrefix(sub.PushEndpoint, "https://"),
				IsExternal:     true,
			}
			m.addEndpoint(projectID, ep)
		}
	}
}

// analyzeFirewallRules analyzes firewall rules and builds port mapping
func (m *EndpointsModule) analyzeFirewallRules(ctx context.Context, svc *compute.Service, projectID string, logger internal.Logger) {
	req := svc.Firewalls.List(projectID)
	if err := req.Pages(ctx, func(page *compute.FirewallList) error {
		for _, fw := range page.Items {
			if fw.Direction != "INGRESS" {
				continue
			}

			networkName := extractResourceName(fw.Network)

			var rulePorts []string
			for _, allowed := range fw.Allowed {
				if len(allowed.Ports) == 0 {
					rulePorts = append(rulePorts, "ALL")
				} else {
					rulePorts = append(rulePorts, allowed.Ports...)
				}
			}

			m.mu.Lock()
			if len(fw.TargetTags) == 0 {
				m.firewallPortMap[networkName] = append(m.firewallPortMap[networkName], rulePorts...)
			} else {
				for _, tag := range fw.TargetTags {
					key := fmt.Sprintf("%s:%s", networkName, tag)
					m.firewallPortMap[key] = append(m.firewallPortMap[key], rulePorts...)
				}
			}
			m.mu.Unlock()
		}
		return nil
	}); err != nil {
		gcpinternal.HandleGCPError(err, logger, "endpoints",
			fmt.Sprintf("Could not list firewall rules in project %s", projectID))
	}
}

// addEndpoint adds an endpoint thread-safely
func (m *EndpointsModule) addEndpoint(projectID string, ep Endpoint) {
	m.mu.Lock()
	m.ProjectEndpoints[projectID] = append(m.ProjectEndpoints[projectID], ep)
	m.mu.Unlock()
}

// ------------------------------
// Helper Functions
// ------------------------------
func extractResourceName(url string) string {
	if url == "" {
		return ""
	}
	parts := strings.Split(url, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return url
}

func extractRegionFromScope(scope string) string {
	parts := strings.Split(scope, "/")
	if len(parts) >= 2 {
		return parts[len(parts)-1]
	}
	return scope
}

func extractZoneFromScope(scope string) string {
	parts := strings.Split(scope, "/")
	if len(parts) >= 2 {
		return parts[len(parts)-1]
	}
	return scope
}

// ------------------------------
// Loot File Management
// ------------------------------

// generateLootFiles creates the loot files for a project, grouped by network/region
func (m *EndpointsModule) generateLootFiles(projectID string) []internal.LootFile {
	endpoints, ok := m.ProjectEndpoints[projectID]
	if !ok || len(endpoints) == 0 {
		return nil
	}

	// Separate external and internal endpoints
	var externalEndpoints, internalEndpoints []Endpoint
	for _, ep := range endpoints {
		if ep.IsExternal {
			externalEndpoints = append(externalEndpoints, ep)
		} else {
			internalEndpoints = append(internalEndpoints, ep)
		}
	}

	var lootFiles []internal.LootFile

	// Generate external commands file
	if len(externalEndpoints) > 0 {
		lootFiles = append(lootFiles, internal.LootFile{
			Name:     "endpoints-external-commands",
			Contents: m.generateGroupedCommands(externalEndpoints, true),
		})
	}

	// Generate internal commands file
	if len(internalEndpoints) > 0 {
		lootFiles = append(lootFiles, internal.LootFile{
			Name:     "endpoints-internal-commands",
			Contents: m.generateGroupedCommands(internalEndpoints, false),
		})
	}

	return lootFiles
}

// generateGroupedCommands creates commands grouped by network
func (m *EndpointsModule) generateGroupedCommands(endpoints []Endpoint, isExternal bool) string {
	var contents strings.Builder

	if isExternal {
		contents.WriteString("# External Endpoint Scan Commands\n")
		contents.WriteString("# Generated by CloudFox\n")
		contents.WriteString("# These endpoints are internet-facing\n\n")
	} else {
		contents.WriteString("# Internal Endpoint Scan Commands\n")
		contents.WriteString("# Generated by CloudFox\n")
		contents.WriteString("# These endpoints require internal network access (VPN, bastion, etc.)\n\n")
	}

	// Group endpoints by network (same VPC = same firewall rules)
	groups := make(map[string][]Endpoint)
	var groupOrder []string

	for _, ep := range endpoints {
		network := ep.Network
		if network == "" {
			network = "default"
		}
		if _, exists := groups[network]; !exists {
			groupOrder = append(groupOrder, network)
		}
		groups[network] = append(groups[network], ep)
	}

	// Generate commands for each network group
	for _, network := range groupOrder {
		groupEndpoints := groups[network]

		contents.WriteString(fmt.Sprintf("# =============================================================================\n"))
		contents.WriteString(fmt.Sprintf("# Network: %s\n", network))
		contents.WriteString(fmt.Sprintf("# =============================================================================\n\n"))

		// Generate commands for each endpoint in the group
		for _, ep := range groupEndpoints {
			m.writeEndpointCommand(&contents, ep)
		}
	}

	return contents.String()
}

// writeEndpointCommand writes the command for a single endpoint
func (m *EndpointsModule) writeEndpointCommand(contents *strings.Builder, ep Endpoint) {
	// Determine best target for scanning
	target := ep.ExternalIP
	if target == "" {
		target = ep.InternalIP
	}
	if target == "" {
		target = ep.Hostname
	}
	if target == "" {
		return
	}

	// Write endpoint header (just type and name)
	contents.WriteString(fmt.Sprintf("# %s: %s\n", ep.Type, ep.Name))

	// Generate appropriate commands based on type
	switch ep.Type {
	case "Cloud Run", "Cloud Function", "Composer Airflow", "App Engine", "Vertex AI Notebook":
		if ep.Hostname != "" {
			contents.WriteString(fmt.Sprintf("curl -v https://%s\n\n", ep.Hostname))
		}
	case "GKE API":
		contents.WriteString(fmt.Sprintf("gcloud container clusters get-credentials %s --region=%s --project=%s\n", ep.Name, ep.Region, ep.ProjectID))
		contents.WriteString("kubectl cluster-info\n\n")
	case "Cloud SQL":
		protocol := "mysql"
		if strings.Contains(ep.Port, "5432") {
			protocol = "psql"
		} else if strings.Contains(ep.Port, "1433") {
			protocol = "sqlcmd"
		}
		contents.WriteString(fmt.Sprintf("# %s -h %s -P %s -u USERNAME\n", protocol, target, ep.Port))
		contents.WriteString(fmt.Sprintf("nmap -sV -Pn -p %s %s\n\n", ep.Port, target))
	case "Redis":
		contents.WriteString(fmt.Sprintf("redis-cli -h %s -p %s\n", target, ep.Port))
		contents.WriteString(fmt.Sprintf("nmap -sV -Pn -p %s %s\n\n", ep.Port, target))
	case "Filestore NFS":
		contents.WriteString(fmt.Sprintf("showmount -e %s\n", target))
		contents.WriteString(fmt.Sprintf("sudo mount -t nfs %s:/<share> /mnt/<mountpoint>\n\n", target))
	case "Dataproc Master":
		contents.WriteString(fmt.Sprintf("gcloud compute ssh %s --project=%s --zone=<ZONE>\n", strings.TrimSuffix(ep.Name, "-master"), ep.ProjectID))
		contents.WriteString("# Web UIs: YARN (8088), HDFS (9870), Spark (8080)\n\n")
	case "VPN Gateway", "HA VPN Gateway":
		contents.WriteString(fmt.Sprintf("# VPN Gateway IP: %s (ports 500/UDP, 4500/UDP, ESP)\n", target))
		contents.WriteString(fmt.Sprintf("nmap -sU -Pn -p 500,4500 %s\n\n", target))
	case "Pub/Sub Push":
		contents.WriteString(fmt.Sprintf("curl -v https://%s\n\n", ep.Hostname))
	default:
		if ep.Port == "ALL" || ep.Port == "" {
			contents.WriteString(fmt.Sprintf("nmap -sV -Pn %s\n", target))
		} else {
			contents.WriteString(fmt.Sprintf("nmap -sV -Pn -p %s %s\n", ep.Port, target))
		}
		if ep.TLSEnabled || ep.Port == "443" {
			contents.WriteString(fmt.Sprintf("curl -vk https://%s/\n", target))
		}
		contents.WriteString("\n")
	}
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *EndpointsModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

func (m *EndpointsModule) getHeader() []string {
	return []string{
		"Project",
		"Name",
		"Type",
		"Exposure",
		"External IP",
		"Internal IP",
		"Hostname",
		"Protocol",
		"Port",
		"Region",
		"Network",
		"Security",
		"Status",
	}
}

func (m *EndpointsModule) endpointsToTableBody(endpoints []Endpoint) [][]string {
	var body [][]string
	for _, ep := range endpoints {
		exposure := "Internal"
		if ep.IsExternal {
			exposure = "External"
		}

		externalIP := ep.ExternalIP
		if externalIP == "" {
			externalIP = "-"
		}

		internalIP := ep.InternalIP
		if internalIP == "" {
			internalIP = "-"
		}

		hostname := ep.Hostname
		if hostname == "" {
			hostname = "-"
		}

		security := ep.Security
		if security == "" {
			security = "-"
		}

		status := ep.Status
		if status == "" {
			status = "-"
		}

		network := ep.Network
		if network == "" {
			network = "-"
		}

		body = append(body, []string{
			m.GetProjectName(ep.ProjectID),
			ep.Name,
			ep.Type,
			exposure,
			externalIP,
			internalIP,
			hostname,
			ep.Protocol,
			ep.Port,
			ep.Region,
			network,
			security,
			status,
		})
	}
	return body
}

func (m *EndpointsModule) buildTablesForProject(projectID string) []internal.TableFile {
	var tableFiles []internal.TableFile

	if endpoints, ok := m.ProjectEndpoints[projectID]; ok && len(endpoints) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "endpoints",
			Header: m.getHeader(),
			Body:   m.endpointsToTableBody(endpoints),
		})
	}

	return tableFiles
}

func (m *EndpointsModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	for projectID := range m.ProjectEndpoints {
		tableFiles := m.buildTablesForProject(projectID)
		lootFiles := m.generateLootFiles(projectID)

		outputData.ProjectLevelData[projectID] = EndpointsOutput{Table: tableFiles, Loot: lootFiles}
	}

	pathBuilder := m.BuildPathBuilder()

	err := internal.HandleHierarchicalOutputSmart("gcp", m.Format, m.Verbosity, m.WrapTable, pathBuilder, outputData)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), "endpoints")
	}
}

func (m *EndpointsModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	allEndpoints := m.getAllEndpoints()

	var tables []internal.TableFile

	if len(allEndpoints) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "endpoints",
			Header: m.getHeader(),
			Body:   m.endpointsToTableBody(allEndpoints),
		})
	}

	// Generate loot files from all endpoints combined
	var lootFiles []internal.LootFile
	if len(allEndpoints) > 0 {
		// Separate external and internal endpoints
		var externalEndpoints, internalEndpoints []Endpoint
		for _, ep := range allEndpoints {
			if ep.IsExternal {
				externalEndpoints = append(externalEndpoints, ep)
			} else {
				internalEndpoints = append(internalEndpoints, ep)
			}
		}

		if len(externalEndpoints) > 0 {
			lootFiles = append(lootFiles, internal.LootFile{
				Name:     "endpoints-external-commands",
				Contents: m.generateGroupedCommands(externalEndpoints, true),
			})
		}
		if len(internalEndpoints) > 0 {
			lootFiles = append(lootFiles, internal.LootFile{
				Name:     "endpoints-internal-commands",
				Contents: m.generateGroupedCommands(internalEndpoints, false),
			})
		}
	}

	output := EndpointsOutput{
		Table: tables,
		Loot:  lootFiles,
	}

	scopeNames := make([]string, len(m.ProjectIDs))
	for i, id := range m.ProjectIDs {
		scopeNames[i] = m.GetProjectName(id)
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), "endpoints")
		m.CommandCounter.Error++
	}
}
