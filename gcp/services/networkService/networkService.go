package networkservice

import (
	"context"
	"log"
	"net"
	"strings"

	ComputeEngineService "github.com/BishopFox/cloudfox/gcp/services/computeEngineService"
	"google.golang.org/api/compute/v1"
)

// VPC / network / subnets
// gcloud compute networks list
// gcloud compute networks get-effective-firewalls terragoat-dev-network
// gcloud compute networks subnets list
// FirewallRule structure for JSON output

// firewall-rules
// gcloud compute firewall-rules list - `terragoat-dev-firewall`

// forwarding rules (load balancers)
// gcloud compute forwarding-rules list

// Router & NAT gateways
// gcloud compute routers list
// gcloud compute routers nats list --router

// Global network firewall policy
// gcloud compute network-firewall-policies
// gcloud compute network-firewall-policies rules list
// gcloud compute network-firewall-policies associations list

type FirewallRule struct {
	FWName            string              `json:"fw_name"`
	Description       string              `json:"description"`
	Direction         string              `json:"direction"`
	Allowed           map[string][]string `json:"allowed"`
	Denied            map[string][]string `json:"denied"`
	SourceRanges      []string            `json:"source_ranges"`
	TargetTag         string              `json:"target_tag"`
	AllowedTraffic    Traffic             `json:"allowed_traffic"`
	ExposedEndpoints  []Endpoint          `json:"exposed_endpoints"`
	DestinationRanges []string            `json:"destinatioRanges"`
	TargetTags        []string            `json:"targetTags"`
}

type Traffic struct {
	TCP []string `json:"tcp"`
	UDP []string `json:"udp"`
}

type Endpoint struct {
	IP       string   `json:"ip"`
	Ports    []string `json:"ports"`
	Protocol string   `json:"protocol"`
}

type NetwworkService struct {
	// DataStoreService datastoreservice.DataStoreService
}

func New() *NetwworkService {
	return &NetwworkService{}
}

// Returns firewall rules for a project.
func (ns *NetwworkService) FirewallRules(projectID string) ([]*compute.Firewall, error) {
	ctx := context.Background()
	computeService, err := compute.NewService(ctx)
	if err != nil {
		return nil, err
	}

	firewallList, err := computeService.Firewalls.List(projectID).Do()
	if err != nil {
		return nil, err
	}
	return firewallList.Items, nil
}

// Returns firewall rules with additional logic to tag rules that expose resources to the public
func (ns *NetwworkService) FirewallRulesWithPublicExposure(projectID string) ([]FirewallRule, error) {
	var results []FirewallRule

	log.Printf("Retrieving firewall rules for project %s", projectID)
	firewalls, err := ns.FirewallRules(projectID)
	log.Print("Done")
	if err != nil {
		log.Printf("Error fetching firewall rules for project %s: %v", projectID, err)
		return nil, err
	}
	log.Print("Parsing firewall rules")
	for _, fw := range firewalls {
		parsedRule, err := parseFirewallRule(fw, projectID)
		if err != nil {
			log.Printf("Error parsing firewall rule for project %s: %v", projectID, err)
			continue
		}
		results = append(results, parsedRule)
	}
	log.Print("Done")
	return results, nil
}

// Returns a list of IPs that are mapped to a given tag. Uses a list of instances
func getIPAddressesForTargetTag(instances []ComputeEngineService.ComputeEngineInfo, tag string) ([]string, error) {
	var ips []string
	for _, instance := range instances {
		if contains(instance.Tags.Items, tag) {
			ips = append(ips, instance.NetworkInterfaces[0].NetworkIP)
		}
	}
	return ips, nil
}

// Returns the zone from a GCP URL string with the zone in it
func getZoneNameFromURL(zoneURL string) string {
	splits := strings.Split(zoneURL, "/")
	return splits[len(splits)-1]
}

// Returns true of a string is in the given list of strings. Else false
func contains(slice []string, item string) bool {
	for _, a := range slice {
		if a == item {
			return true
		}
	}
	return false
}

// Returns true if a string in compute.Firewall.SourceRanges is "0.0.0.0/0"
func isExposedToInternet(fw *compute.Firewall) bool {
	for _, rangeVal := range fw.SourceRanges {
		if rangeVal == "0.0.0.0/0" {
			return true
		}
	}
	return false
}

// Returns true if the IP is an internal ipv4 or ipv6 IP
func IsInternalIP(cidr string) bool {
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		// Try parsing as just an IP (not CIDR)
		ip = net.ParseIP(cidr)
		if ip == nil {
			log.Printf("Error parsing input %s\n", cidr)
			return false
		}
	}

	// Check for IPv4 private ranges
	if ip.To4() != nil {
		for _, privateCIDR := range []string{
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
		} {
			_, block, _ := net.ParseCIDR(privateCIDR)
			if block.Contains(ip) {
				return true
			}
		}
		return false
	}

	// Check for IPv6 ULA range fc00::/7
	// This checks if the first byte of the address is in the range 0xfc to 0xfd
	if ip[0] == 0xfc || ip[0] == 0xfd {
		return true
	}

	return false
}

// getPublicEndpoints fetches the endpoints exposed to the internet
// and, if a TargetTag is provided, gets the IP associated with it.
func getPublicEndpoints(fw *compute.Firewall, projectID string) ([]Endpoint, error) {
	var exposedEndpoints []Endpoint
	ces := ComputeEngineService.New()
	if isExposedToInternet(fw) {
		for _, allowed := range fw.Allowed {
			// Handle destination ranges
			for _, destRange := range fw.DestinationRanges {
				if !IsInternalIP(destRange) {
					exposed := Endpoint{
						IP:       destRange,
						Ports:    allowed.Ports,
						Protocol: allowed.IPProtocol,
					}
					exposedEndpoints = append(exposedEndpoints, exposed)
				}
			}

			// If TargetTag is provided, fetch the associated IP addresses.
			if len(fw.TargetTags) > 0 {
				log.Printf("Target tags found, getting their IP...")
				instances, err := ces.Instances(projectID)
				if err != nil {
					log.Printf("Error retrieving instances: %v", err)
					return nil, err
				}
				for _, tag := range fw.TargetTags {
					ips, err := getIPAddressesForTargetTag(instances, tag)
					if err != nil {
						return nil, err
					}
					for _, ip := range ips {
						if !IsInternalIP(ip) {
							exposed := Endpoint{
								IP:       ip,
								Ports:    allowed.Ports,
								Protocol: allowed.IPProtocol,
							}
							exposedEndpoints = append(exposedEndpoints, exposed)
						}
					}
				}
			}
		}
	}
	return exposedEndpoints, nil
}

// The original parseFirewallRule function
func parseFirewallRule(fw *compute.Firewall, projectID string) (FirewallRule, error) {
	var exposedEndpoints []Endpoint
	trafficAllowed := make(map[string][]string)
	trafficDenied := make(map[string][]string)

	for _, allowed := range fw.Allowed {
		trafficAllowed[allowed.IPProtocol] = append(trafficAllowed[allowed.IPProtocol], allowed.Ports...)
	}

	exposedEndpoints, err := getPublicEndpoints(fw, projectID)
	if err != nil {
		return FirewallRule{}, err
	}

	for _, denied := range fw.Denied {
		trafficDenied[denied.IPProtocol] = append(trafficDenied[denied.IPProtocol], denied.Ports...)
	}

	return FirewallRule{
		FWName:           fw.Name,
		Description:      fw.Description,
		Direction:        fw.Direction,
		Allowed:          trafficAllowed,
		Denied:           trafficDenied,
		SourceRanges:     fw.SourceRanges,
		TargetTag:        strings.Join(fw.TargetTags, ","),
		ExposedEndpoints: exposedEndpoints,
	}, nil
}

// TODO
// func (ns *NetworkService) ForwardingRules() {}
