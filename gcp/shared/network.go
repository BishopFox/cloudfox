package shared

import (
	"fmt"
	"strconv"
	"strings"
)

// Public CIDR constants
const (
	CIDRAllIPv4 = "0.0.0.0/0"
	CIDRAllIPv6 = "::/0"
	// Broad ranges that are effectively public
	CIDRHalfIPv4Low  = "0.0.0.0/1"
	CIDRHalfIPv4High = "128.0.0.0/1"
)

// IsPublicCIDR checks if a CIDR range represents public/internet access.
// Returns true for 0.0.0.0/0, ::/0, and other effectively-public ranges.
func IsPublicCIDR(cidr string) bool {
	cidr = strings.TrimSpace(cidr)
	switch cidr {
	case CIDRAllIPv4, CIDRAllIPv6, CIDRHalfIPv4Low, CIDRHalfIPv4High:
		return true
	}
	return false
}

// HasPublicCIDR checks if any CIDR in the slice represents public access.
func HasPublicCIDR(cidrs []string) bool {
	for _, cidr := range cidrs {
		if IsPublicCIDR(cidr) {
			return true
		}
	}
	return false
}

// IsPrivateIP checks if an IP address is in a private range.
// Private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
func IsPrivateIP(ip string) bool {
	// Handle CIDR notation
	if idx := strings.Index(ip, "/"); idx != -1 {
		ip = ip[:idx]
	}

	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}

	first, err := strconv.Atoi(parts[0])
	if err != nil {
		return false
	}

	// 10.0.0.0/8
	if first == 10 {
		return true
	}

	// 172.16.0.0/12
	if first == 172 {
		second, err := strconv.Atoi(parts[1])
		if err != nil {
			return false
		}
		if second >= 16 && second <= 31 {
			return true
		}
	}

	// 192.168.0.0/16
	if first == 192 {
		second, err := strconv.Atoi(parts[1])
		if err != nil {
			return false
		}
		if second == 168 {
			return true
		}
	}

	return false
}

// SensitivePort represents a port with security implications
type SensitivePort struct {
	Port        int
	Protocol    string
	Service     string
	Risk        string
	Description string
}

// SensitivePorts maps port numbers to their security information
var SensitivePorts = map[int]SensitivePort{
	// Remote Access
	22:   {22, "TCP", "SSH", RiskHigh, "Remote shell access"},
	23:   {23, "TCP", "Telnet", RiskCritical, "Unencrypted remote access"},
	3389: {3389, "TCP", "RDP", RiskHigh, "Remote Desktop Protocol"},
	5900: {5900, "TCP", "VNC", RiskHigh, "Virtual Network Computing"},
	5985: {5985, "TCP", "WinRM-HTTP", RiskHigh, "Windows Remote Management (HTTP)"},
	5986: {5986, "TCP", "WinRM-HTTPS", RiskMedium, "Windows Remote Management (HTTPS)"},

	// Databases
	3306:  {3306, "TCP", "MySQL", RiskHigh, "MySQL database"},
	5432:  {5432, "TCP", "PostgreSQL", RiskHigh, "PostgreSQL database"},
	1433:  {1433, "TCP", "MSSQL", RiskHigh, "Microsoft SQL Server"},
	1521:  {1521, "TCP", "Oracle", RiskHigh, "Oracle database"},
	27017: {27017, "TCP", "MongoDB", RiskHigh, "MongoDB database"},
	6379:  {6379, "TCP", "Redis", RiskHigh, "Redis (often no auth)"},
	9042:  {9042, "TCP", "Cassandra", RiskMedium, "Cassandra database"},
	5984:  {5984, "TCP", "CouchDB", RiskMedium, "CouchDB database"},
	9200:  {9200, "TCP", "Elasticsearch", RiskHigh, "Elasticsearch (often no auth)"},

	// Web/API
	80:   {80, "TCP", "HTTP", RiskMedium, "Unencrypted web traffic"},
	443:  {443, "TCP", "HTTPS", RiskLow, "Encrypted web traffic"},
	8080: {8080, "TCP", "HTTP-Alt", RiskMedium, "Alternative HTTP"},
	8443: {8443, "TCP", "HTTPS-Alt", RiskLow, "Alternative HTTPS"},

	// Infrastructure
	53:   {53, "TCP/UDP", "DNS", RiskMedium, "DNS queries/transfers"},
	25:   {25, "TCP", "SMTP", RiskMedium, "Email relay"},
	110:  {110, "TCP", "POP3", RiskMedium, "Email retrieval (unencrypted)"},
	143:  {143, "TCP", "IMAP", RiskMedium, "Email retrieval (unencrypted)"},
	389:  {389, "TCP", "LDAP", RiskHigh, "Directory services (unencrypted)"},
	636:  {636, "TCP", "LDAPS", RiskMedium, "Directory services (encrypted)"},
	445:  {445, "TCP", "SMB", RiskCritical, "Windows file sharing"},
	137:  {137, "UDP", "NetBIOS-NS", RiskHigh, "NetBIOS Name Service"},
	138:  {138, "UDP", "NetBIOS-DG", RiskHigh, "NetBIOS Datagram"},
	139:  {139, "TCP", "NetBIOS-SS", RiskHigh, "NetBIOS Session"},
	111:  {111, "TCP/UDP", "RPC", RiskHigh, "Remote Procedure Call"},
	2049: {2049, "TCP/UDP", "NFS", RiskHigh, "Network File System"},

	// Container/Orchestration
	2375: {2375, "TCP", "Docker-Unencrypted", RiskCritical, "Docker API (unencrypted)"},
	2376: {2376, "TCP", "Docker-TLS", RiskMedium, "Docker API (TLS)"},
	6443: {6443, "TCP", "Kubernetes-API", RiskHigh, "Kubernetes API server"},
	10250: {10250, "TCP", "Kubelet", RiskHigh, "Kubelet API"},
	10255: {10255, "TCP", "Kubelet-RO", RiskMedium, "Kubelet read-only API"},
	2379: {2379, "TCP", "etcd", RiskCritical, "etcd (K8s secrets)"},

	// Monitoring
	9090: {9090, "TCP", "Prometheus", RiskMedium, "Prometheus metrics"},
	3000: {3000, "TCP", "Grafana", RiskMedium, "Grafana dashboard"},
	8500: {8500, "TCP", "Consul", RiskMedium, "HashiCorp Consul"},

	// Message Queues
	5672:  {5672, "TCP", "AMQP", RiskMedium, "RabbitMQ"},
	15672: {15672, "TCP", "RabbitMQ-Mgmt", RiskMedium, "RabbitMQ management"},
	9092:  {9092, "TCP", "Kafka", RiskMedium, "Apache Kafka"},

	// Other
	11211: {11211, "TCP", "Memcached", RiskHigh, "Memcached (often no auth)"},
	6666:  {6666, "TCP", "IRC", RiskMedium, "IRC (potential backdoor)"},
	4444:  {4444, "TCP", "Metasploit", RiskCritical, "Common Metasploit port"},
}

// IsSensitivePort checks if a port is considered security-sensitive
func IsSensitivePort(port int) bool {
	_, exists := SensitivePorts[port]
	return exists
}

// GetPortInfo returns information about a port if it's sensitive
func GetPortInfo(port int) (SensitivePort, bool) {
	info, exists := SensitivePorts[port]
	return info, exists
}

// GetPortRisk returns the risk level for a port (or RiskLow if not sensitive)
func GetPortRisk(port int) string {
	if info, exists := SensitivePorts[port]; exists {
		return info.Risk
	}
	return RiskLow
}

// AssessFirewallRuleRisk assesses the risk of a firewall rule based on its configuration
func AssessFirewallRuleRisk(isIngress bool, isPublic bool, allowsAllPorts bool, ports []int) string {
	// Egress rules are generally lower risk
	if !isIngress {
		if isPublic && allowsAllPorts {
			return RiskMedium
		}
		return RiskLow
	}

	// Ingress rules from public internet
	if isPublic {
		if allowsAllPorts {
			return RiskCritical // All ports from internet = critical
		}

		// Check for sensitive ports
		for _, port := range ports {
			if info, exists := SensitivePorts[port]; exists {
				if info.Risk == RiskCritical {
					return RiskCritical
				}
			}
		}

		// Any public ingress with specific ports is at least high risk
		return RiskHigh
	}

	// Internal ingress rules
	if allowsAllPorts {
		return RiskMedium
	}

	return RiskLow
}

// FirewallRuleIssues identifies security issues with a firewall rule
func FirewallRuleIssues(isIngress bool, isPublic bool, allowsAllPorts bool, ports []int, hasTargetTags bool, loggingEnabled bool) []string {
	var issues []string

	if isIngress {
		if isPublic {
			issues = append(issues, "Allows traffic from 0.0.0.0/0 (internet)")
		}

		if allowsAllPorts {
			issues = append(issues, "Allows ALL ports")
		}

		// Check for sensitive ports exposed to internet
		if isPublic {
			for _, port := range ports {
				if info, exists := SensitivePorts[port]; exists {
					issues = append(issues, fmt.Sprintf("Exposes %s (%d) to internet", info.Service, port))
				}
			}
		}

		if !hasTargetTags {
			issues = append(issues, "No target tags - applies to ALL instances")
		}
	}

	if !loggingEnabled {
		issues = append(issues, "Firewall logging disabled")
	}

	return issues
}

// FormatPortRange formats a port range for display
func FormatPortRange(startPort, endPort int) string {
	if startPort == endPort {
		return fmt.Sprintf("%d", startPort)
	}
	return fmt.Sprintf("%d-%d", startPort, endPort)
}

// ParsePortRange parses a port range string like "80" or "8000-9000"
func ParsePortRange(portStr string) (start, end int, err error) {
	portStr = strings.TrimSpace(portStr)

	if strings.Contains(portStr, "-") {
		parts := strings.Split(portStr, "-")
		if len(parts) != 2 {
			return 0, 0, fmt.Errorf("invalid port range: %s", portStr)
		}
		start, err = strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil {
			return 0, 0, err
		}
		end, err = strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			return 0, 0, err
		}
		return start, end, nil
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, 0, err
	}
	return port, port, nil
}

// ExpandPortRanges expands port range strings to individual ports (up to a limit)
func ExpandPortRanges(portRanges []string, maxPorts int) []int {
	var ports []int
	seen := make(map[int]bool)

	for _, rangeStr := range portRanges {
		start, end, err := ParsePortRange(rangeStr)
		if err != nil {
			continue
		}

		for p := start; p <= end && len(ports) < maxPorts; p++ {
			if !seen[p] {
				seen[p] = true
				ports = append(ports, p)
			}
		}
	}

	return ports
}

// Protocol constants
const (
	ProtocolTCP  = "tcp"
	ProtocolUDP  = "udp"
	ProtocolICMP = "icmp"
	ProtocolAll  = "all"
)

// IsAllProtocols checks if the protocol specification allows all protocols
func IsAllProtocols(protocol string) bool {
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	return protocol == "all" || protocol == "*" || protocol == ""
}

// NetworkEndpointType categorizes network endpoints
type NetworkEndpointType string

const (
	EndpointTypePublicIP       NetworkEndpointType = "Public IP"
	EndpointTypePrivateIP      NetworkEndpointType = "Private IP"
	EndpointTypeLoadBalancer   NetworkEndpointType = "Load Balancer"
	EndpointTypeNAT            NetworkEndpointType = "NAT Gateway"
	EndpointTypeVPNTunnel      NetworkEndpointType = "VPN Tunnel"
	EndpointTypeInterconnect   NetworkEndpointType = "Interconnect"
	EndpointTypePrivateService NetworkEndpointType = "Private Service Connect"
	EndpointTypeInternal       NetworkEndpointType = "Internal"
)

// CategorizeEndpoint determines the type of a network endpoint
func CategorizeEndpoint(ipOrURL string, isExternal bool) NetworkEndpointType {
	if isExternal {
		return EndpointTypePublicIP
	}
	if IsPrivateIP(ipOrURL) {
		return EndpointTypePrivateIP
	}
	return EndpointTypeInternal
}
