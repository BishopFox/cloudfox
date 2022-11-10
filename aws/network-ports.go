package aws

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/BishopFox/cloudfox/console"
	"github.com/BishopFox/cloudfox/utils"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rds_types "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/sirupsen/logrus"
)

var (
	TCP_4_SCAN string = "sudo nmap -sV"
	UDP_4_SCAN string = "sudo nmap -sU -sV"
	TCP_6_SCAN string = "sudo nmap -6 -sV"
	UDP_6_SCAN string = "sudo nmap -6 -sU -sV"
)

type NetworkPortsModule struct {
	// General configuration data
	EC2Client *ec2.Client
	RDSClient *rds.Client

	Caller       sts.GetCallerIdentityOutput
	AWSRegions   []string
	OutputFormat string
	Goroutines   int
	AWSProfile   string
	Verbosity    int

	// Main module data
	IPv4           []NetworkService
	IPv6           []NetworkService
	CommandCounter console.CommandCounter
	// Used to store output data for pretty printing
	output utils.OutputData2
	modLog *logrus.Entry
}

type NetworkServices struct {
	IPv4 []NetworkService
	IPv6 []NetworkService
}

type NetworkService struct {
	AWSService string
	Region     string
	Hosts      []string
	Ports      []string
	Protocol   string
}

type NetworkAcl struct {
	ID      string
	VpcId   string
	Subnets []string
	head    *Node
	tail    *Node
}

type NaclRule struct {
	RuleNumber int32
	Protocol   string
	Cidr       string
	PortRange  []int32
	Action     bool
}

type SecurityGroup struct {
	ID    string
	VpcId string
	Rules []SecurityGroupRule
}

type SecurityGroupRule struct {
	Protocol string
	Cidr     []string
	Ports    []int32
}

var naclToSG = map[string]string{
	"-1": "-1",
	"6":  "tcp",
	"17": "udp",
}

func (m *NetworkPortsModule) PrintNetworkPorts(outputFormat string, outputDirectory string) {
	// These stuct values are used by the output module
	m.output.Verbosity = m.Verbosity
	m.output.Directory = outputDirectory
	m.output.CallingModule = "network-ports"
	m.modLog = utils.TxtLog.WithFields(logrus.Fields{
		"module": m.output.CallingModule,
	})
	if m.AWSProfile == "" {
		m.AWSProfile = utils.BuildAWSPath(m.Caller)
	}

	fmt.Printf("[%s][%s] Enumerating shared resources for account %s.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), aws.ToString(m.Caller.Account))

	wg := new(sync.WaitGroup)

	// Create a channel to signal the spinner aka task status goroutine to finish
	spinnerDone := make(chan bool)
	//fire up the the task status spinner/updated
	go console.SpinUntil(m.output.CallingModule, &m.CommandCounter, spinnerDone, "regions")

	//create a channel to receive the objects
	dataReceiver := make(chan NetworkServices)

	// Create a channel to signal to stop
	receiverDone := make(chan bool)
	go m.Receiver(dataReceiver, receiverDone)

	for _, region := range m.AWSRegions {
		wg.Add(1)
		m.CommandCounter.Pending++
		go m.executeChecks(region, wg, dataReceiver)

	}

	wg.Wait()
	// Send a message to the spinner goroutine to close the channel and stop
	spinnerDone <- true
	<-spinnerDone
	// Send a message to the data receiver goroutine to close the channel and stop
	receiverDone <- true
	<-receiverDone

	// add - if struct is not empty do this. otherwise, dont write anything.
	m.output.Headers = []string{
		"Service",
		"Region",
		"Protocol",
		"Host",
		"Ports",
	}

	// Table rows
	for _, i := range m.IPv4 {
		for _, h := range i.Hosts {
			m.output.Body = append(
				m.output.Body,
				[]string{
					i.AWSService,
					i.Region,
					i.Protocol,
					h,
					strings.Join(i.Ports, ","),
				},
			)
		}
	}

	for _, i := range m.IPv6 {
		for _, h := range i.Hosts {
			m.output.Body = append(
				m.output.Body,
				[]string{
					i.AWSService,
					i.Region,
					i.Protocol,
					h,
					strings.Join(i.Ports, ","),
				},
			)
		}
	}

	if len(m.IPv4) > 0 || len(m.IPv6) > 0 {
		m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", m.AWSProfile)
		//m.output.OutputSelector(outputFormat)
		utils.OutputSelector(m.Verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.CallingModule, m.output.CallingModule)
		m.writeLoot(m.output.FilePath)
		fmt.Printf("[%s][%s] %s network services found.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), strconv.Itoa(len(m.output.Body)))

	} else {
		fmt.Printf("[%s][%s] No network services found, skipping the creation of an output file.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	}
}

func (m *NetworkPortsModule) executeChecks(r string, wg *sync.WaitGroup, dataReceiver chan NetworkServices) {
	defer wg.Done()
	m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	m.getEC2NetworkPortsPerRegion(r, dataReceiver)
	m.CommandCounter.Executing--
	m.CommandCounter.Executing++
	m.getRdsServicesPerRegion(r, dataReceiver)
	m.CommandCounter.Executing--
	m.CommandCounter.Complete++
}

func (m *NetworkPortsModule) Receiver(receiver chan NetworkServices, receiverDone chan bool) {
	defer close(receiverDone)
	for {
		select {
		case data := <-receiver:
			if len(data.IPv4) != 0 {
				m.IPv4 = append(m.IPv4, data.IPv4...)
			}
			if len(data.IPv6) != 0 {
				m.IPv6 = append(m.IPv6, data.IPv6...)
			}
		case <-receiverDone:
			receiverDone <- true
			return
		}
	}
}

func (m *NetworkPortsModule) writeLoot(outputDirectory string) {
	path := filepath.Join(outputDirectory, "loot")
	err := os.MkdirAll(path, os.ModePerm)
	if err != nil {
		m.modLog.Error(err.Error())
	}

	if len(m.IPv4) > 0 {
		ipv4Filename := filepath.Join(path, "network-ports-ipv4.txt")

		var out string
		out = fmt.Sprintln("#############################################")
		out = out + fmt.Sprintln("# The network services may have various ingress rules depending on your source IP.")
		out = out + fmt.Sprintln("# Try scanning from any or all network locations, such as within a VPC.")
		out = out + fmt.Sprintln("#############################################")
		out = out + fmt.Sprintln("")

		for _, ipv4 := range m.IPv4 {
			if ipv4.Protocol == "tcp" {
				out = out + fmt.Sprintf("%s -p %s %s\n", TCP_4_SCAN, strings.Join(ipv4.Ports, ","), strings.Join(ipv4.Hosts, " "))
			}

			if ipv4.Protocol == "udp" {
				out = out + fmt.Sprintf("%s -p %s %s\n", UDP_4_SCAN, strings.Join(ipv4.Ports, ","), strings.Join(ipv4.Hosts, " "))
			}
		}

		err = os.WriteFile(ipv4Filename, []byte(out), 0644)
		if err != nil {
			m.modLog.Error(err.Error())
		}

		if m.Verbosity > 2 {
			fmt.Println()
			fmt.Printf("[%s][%s] %s \n", cyan(m.output.CallingModule), cyan(m.AWSProfile), green("Use the commands below to manually inspect certain buckets of interest."))
			fmt.Print(out)
			fmt.Printf("[%s][%s] %s \n", cyan(m.output.CallingModule), cyan(m.AWSProfile), green("End of loot file."))
		}

		fmt.Printf("[%s][%s] Loot written to [%s]\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), ipv4Filename)
	}

	if len(m.IPv6) > 0 {
		ipv6Filename := filepath.Join(path, "network-ports-ipv6.txt")

		var out string
		out = fmt.Sprintln("#############################################")
		out = out + fmt.Sprintln("# The network services may have various ingress rules depending on your source IP.")
		out = out + fmt.Sprintln("# Try scanning from any or all network locations, such as within a VPC.")
		out = out + fmt.Sprintln("# Make sure the host you scan IPv6 from has an IPv6 network interface.")
		out = out + fmt.Sprintln("#############################################")
		out = out + fmt.Sprintln("")

		for _, ipv6 := range m.IPv6 {

			if ipv6.Protocol == "tcp" {
				out = out + fmt.Sprintf("%s -p %s %s\n", TCP_6_SCAN, strings.Join(ipv6.Ports, ","), strings.Join(ipv6.Hosts, " "))
			}

			if ipv6.Protocol == "udp" {
				out = out + fmt.Sprintf("%s -p %s %s\n", UDP_6_SCAN, strings.Join(ipv6.Ports, ","), strings.Join(ipv6.Hosts, " "))
			}
		}

		err = os.WriteFile(ipv6Filename, []byte(out), 0644)
		if err != nil {
			m.modLog.Error(err.Error())
		}

		if m.Verbosity > 2 {
			fmt.Println()
			fmt.Printf("[%s][%s] %s \n", cyan(m.output.CallingModule), cyan(m.AWSProfile), green("Use the commands below to manually inspect certain buckets of interest."))
			fmt.Print(out)
			fmt.Printf("[%s][%s] %s \n", cyan(m.output.CallingModule), cyan(m.AWSProfile), green("End of loot file."))
		}

		fmt.Printf("[%s][%s] Loot written to [%s]\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), ipv6Filename)
	}

}

func (m *NetworkPortsModule) getEC2NetworkPortsPerRegion(r string, dataReceiver chan NetworkServices) {
	securityGroups := m.getEC2SecurityGroups(r)
	nacls := m.getEC2NACLs(r)

	instances := m.getEC2Instances(r)

	var wg sync.WaitGroup
	wg.Add(len(instances))

	for _, instance := range instances {
		go func(instance types.Instance) {
			defer wg.Done()

			var ipv4, ipv6 []string
			for _, nic := range instance.NetworkInterfaces {
				// ipv4
				for _, addr := range nic.PrivateIpAddresses {
					if addr.Association != nil {
						if addr.Association.PublicIp != nil {
							ipv4 = addHost(ipv4, aws.ToString(addr.Association.PublicIp))
						}
					}

					if addr.PrivateIpAddress != nil {
						ipv4 = addHost(ipv4, aws.ToString(addr.PrivateIpAddress))
					}
				}

				for _, addr := range nic.Ipv6Addresses {
					if addr.Ipv6Address != nil {
						ipv6 = addHost(ipv6, aws.ToString(addr.Ipv6Address))
					}
				}
			}
			var groups []SecurityGroup
			// Loop through the NICs as not all NIC SGs are added to instance.SecurityGroups
			for _, nic := range instance.NetworkInterfaces {
				for _, group := range nic.Groups {
					for _, g := range securityGroups {
						if aws.ToString(group.GroupId) == aws.ToString(g.GroupId) {
							groups = append(groups, m.parseSecurityGroup(g))
						}
					}
				}
			}
			var networkAcls []NetworkAcl
			for _, nacl := range nacls {
				for _, assoc := range nacl.Associations {
					if aws.ToString(instance.SubnetId) == aws.ToString(assoc.SubnetId) {
						networkAcls = append(networkAcls, m.parseNacl(nacl))
					}
				}
			}

			tcpPortsInts, udpPortsInts := m.resolveNetworkAccess(groups, networkAcls)
			tcpPorts := prettyPorts(tcpPortsInts)
			udpPorts := prettyPorts(udpPortsInts)

			if m.Verbosity > 0 {
				fmt.Printf("[%s][%s] %s \n", cyan(m.output.CallingModule), cyan(m.AWSProfile), fmt.Sprintf("Instance: %s, TCP Ports: %v, UDP Ports: %v", aws.ToString(instance.InstanceId), tcpPorts, udpPorts))
			}

			var networkServices NetworkServices

			// IPV4
			if len(ipv4) > 0 {

				if len(tcpPorts) > 0 {
					networkServices.IPv4 = append(networkServices.IPv4, NetworkService{AWSService: "EC2", Region: r, Hosts: ipv4, Ports: tcpPorts, Protocol: "tcp"})
				}
				if len(udpPorts) > 0 {
					networkServices.IPv4 = append(networkServices.IPv4, NetworkService{AWSService: "EC2", Region: r, Hosts: ipv4, Ports: udpPorts, Protocol: "udp"})
				}
			}

			// IPV6
			if len(ipv6) > 0 {
				if len(tcpPorts) > 0 {
					networkServices.IPv6 = append(networkServices.IPv6, NetworkService{AWSService: "EC2", Region: r, Hosts: ipv6, Ports: tcpPorts, Protocol: "tcp"})
				}
				if len(udpPorts) > 0 {
					networkServices.IPv6 = append(networkServices.IPv6, NetworkService{AWSService: "EC2", Region: r, Hosts: ipv6, Ports: udpPorts, Protocol: "udp"})
				}
			}
			dataReceiver <- networkServices
		}(instance)
	}
	wg.Wait()
}

func (m *NetworkPortsModule) getEC2SecurityGroups(region string) []types.SecurityGroup {
	var securityGroups []types.SecurityGroup
	var PaginationControl *string

	for {
		DescribeSecurityGroups, err := m.EC2Client.DescribeSecurityGroups(
			context.TODO(),
			&(ec2.DescribeSecurityGroupsInput{
				NextToken: PaginationControl,
			}),
			func(o *ec2.Options) {
				o.Region = region
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		securityGroups = append(securityGroups, DescribeSecurityGroups.SecurityGroups...)

		if DescribeSecurityGroups.NextToken != nil {
			PaginationControl = DescribeSecurityGroups.NextToken
		} else {
			PaginationControl = nil
			break
		}
	}

	return securityGroups
}

func (m *NetworkPortsModule) getRdsServicesPerRegion(r string, dataReceiver chan NetworkServices) {
	securityGroups := m.getEC2SecurityGroups(r)
	nacls := m.getEC2NACLs(r)

	DBInstances := m.getRdsInstancesPerRegion(r)
	RDSClusters := m.getRDSClustersPerRegion(r)

	var reportedClusters []string

	for _, instance := range DBInstances {
		if aws.ToString(instance.DBInstanceStatus) == "available" {
			host := []string{aws.ToString(instance.Endpoint.Address)}
			var port int32 = instance.Endpoint.Port

			var groups []SecurityGroup
			for _, group := range instance.VpcSecurityGroups {
				for _, g := range securityGroups {
					if aws.ToString(group.VpcSecurityGroupId) == aws.ToString(g.GroupId) {
						groups = append(groups, m.parseSecurityGroup(g))
					}
				}
			}

			var networkAcls []NetworkAcl
			if instance.DBSubnetGroup != nil {
				for _, subnet := range instance.DBSubnetGroup.Subnets {
					for _, nacl := range nacls {
						for _, assoc := range nacl.Associations {
							if aws.ToString(subnet.SubnetIdentifier) == aws.ToString(assoc.SubnetId) {
								networkAcls = append(networkAcls, m.parseNacl(nacl))
							}
						}
					}
				}
			}

			tcpPorts, _ := m.resolveNetworkAccess(groups, networkAcls)
			var networkServices NetworkServices
			if contains(tcpPorts, port) {
				if m.Verbosity > 0 {
					fmt.Printf("[%s][%s] %s \n", cyan(m.output.CallingModule), cyan(m.AWSProfile), fmt.Sprintf("DB Instance: %s, TCP Ports: %d", aws.ToString(instance.Endpoint.Address), port))
				}
				networkServices.IPv4 = append(networkServices.IPv4, NetworkService{AWSService: "RDS", Region: r, Hosts: host, Ports: []string{fmt.Sprintf("%d", port)}, Protocol: "tcp"})

				// Check clusters
				if aws.ToString(instance.DBClusterIdentifier) != "" {
					clusterId := aws.ToString(instance.DBClusterIdentifier)
					if !strContains(reportedClusters, clusterId) {
						for _, cluster := range RDSClusters {
							if aws.ToString(cluster.DBClusterIdentifier) == clusterId {
								if m.Verbosity > 0 {
									fmt.Printf("[%s][%s] %s \n", cyan(m.output.CallingModule), cyan(m.AWSProfile), fmt.Sprintf("DB Instance: %s, TCP Ports: %d", aws.ToString(cluster.Endpoint), port))
									fmt.Printf("[%s][%s] %s \n", cyan(m.output.CallingModule), cyan(m.AWSProfile), fmt.Sprintf("DB Instance: %s, TCP Ports: %d", aws.ToString(cluster.ReaderEndpoint), port))
								}
								networkServices.IPv4 = append(networkServices.IPv4, NetworkService{AWSService: "RDS", Region: r, Hosts: []string{aws.ToString(cluster.Endpoint)}, Ports: []string{fmt.Sprintf("%d", port)}, Protocol: "tcp"})
								networkServices.IPv4 = append(networkServices.IPv4, NetworkService{AWSService: "RDS", Region: r, Hosts: []string{aws.ToString(cluster.ReaderEndpoint)}, Ports: []string{fmt.Sprintf("%d", port)}, Protocol: "tcp"})

								// Add the clusterId to the reported clusters
								reportedClusters = append(reportedClusters, clusterId)
							}
						}
					}
				}
			}

			dataReceiver <- networkServices
		}
	}
}

func (m *NetworkPortsModule) parseSecurityGroup(group types.SecurityGroup) SecurityGroup {
	id := aws.ToString(group.GroupId)
	vpcId := aws.ToString(group.VpcId)
	var rules []SecurityGroupRule
	for _, entry := range group.IpPermissions {
		protocol := aws.ToString(entry.IpProtocol)
		var cidrs []string
		for _, i := range entry.IpRanges {
			cidrs = append(cidrs, aws.ToString(i.CidrIp))
		}
		var ports []int32
		if aws.ToInt32(entry.FromPort) == int32(0) && aws.ToInt32(entry.ToPort) == int32(0) {
			ports = generateRange(0, 65535)
		} else {
			ports = generateRange(aws.ToInt32(entry.FromPort), aws.ToInt32(entry.ToPort))
		}
		rules = append(rules, SecurityGroupRule{
			Protocol: protocol,
			Cidr:     cidrs,
			Ports:    ports,
		})
	}

	return SecurityGroup{
		ID:    id,
		VpcId: vpcId,
		Rules: rules,
	}
}

func (m *NetworkPortsModule) getEC2NACLs(region string) []types.NetworkAcl {
	var nacls []types.NetworkAcl
	var PaginationControl *string

	for {
		DescribeNetworkAcls, err := m.EC2Client.DescribeNetworkAcls(
			context.TODO(),
			&(ec2.DescribeNetworkAclsInput{
				NextToken: PaginationControl,
			}),
			func(o *ec2.Options) {
				o.Region = region
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		nacls = append(nacls, DescribeNetworkAcls.NetworkAcls...)

		if DescribeNetworkAcls.NextToken != nil {
			PaginationControl = DescribeNetworkAcls.NextToken
		} else {
			PaginationControl = nil
			break
		}
	}

	return nacls
}

func (m *NetworkPortsModule) parseNacl(nacl types.NetworkAcl) NetworkAcl {
	id := aws.ToString(nacl.NetworkAclId)
	vpcId := aws.ToString(nacl.VpcId)
	var subnets []string
	for _, assoc := range nacl.Associations {
		subnets = append(subnets, aws.ToString(assoc.SubnetId))
	}

	var rules []NaclRule
	for _, entry := range nacl.Entries {
		if aws.ToBool(entry.Egress) == false {
			ruleNumber := aws.ToInt32(entry.RuleNumber)
			protocol := aws.ToString(entry.Protocol)
			cidr := aws.ToString(entry.CidrBlock)
			var portRange []int32
			if entry.PortRange == nil {
				portRange = generateRange(0, 65535)
			} else {
				portRange = generateRange(aws.ToInt32((*entry.PortRange).From), aws.ToInt32((*entry.PortRange).To))
			}
			action := (entry.RuleAction == "allow")
			rules = append(rules, NaclRule{
				RuleNumber: ruleNumber,
				Protocol:   protocol,
				Cidr:       cidr,
				PortRange:  portRange,
				Action:     action,
			})
		}
	}

	// Sort descending
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].RuleNumber > rules[j].RuleNumber
	})

	naclList := NetworkAcl{
		ID:      id,
		VpcId:   vpcId,
		Subnets: subnets,
	}

	// Iterate over rules and create linked list
	for _, rule := range rules {
		naclList.Insert(rule)
	}

	return naclList
}

func (m *NetworkPortsModule) getEC2Instances(region string) []types.Instance {
	var instances []types.Instance
	var PaginationControl *string
	for {

		DescribeInstances, err := m.EC2Client.DescribeInstances(
			context.TODO(),
			&(ec2.DescribeInstancesInput{
				NextToken: PaginationControl,
			}),
			func(o *ec2.Options) {
				o.Region = region
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		for _, reservation := range DescribeInstances.Reservations {

			for _, instance := range reservation.Instances {
				instances = append(instances, instance)
			}
		}

		if DescribeInstances.NextToken != nil {
			PaginationControl = DescribeInstances.NextToken
		} else {
			PaginationControl = nil
			break
		}
	}
	return instances
}

func (m *NetworkPortsModule) getRdsInstancesPerRegion(region string) []rds_types.DBInstance {
	// "PaginationMarker" is a control variable used for output continuity, as AWS return the output in pages.
	var PaginationControl *string
	var instances []rds_types.DBInstance
	for {
		DescribeDBInstances, err := m.RDSClient.DescribeDBInstances(
			context.TODO(),
			&(rds.DescribeDBInstancesInput{
				Marker: PaginationControl,
			}),
			func(o *rds.Options) {
				o.Region = region
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		for _, instance := range DescribeDBInstances.DBInstances {
			instances = append(instances, instance)
		}

		// The "NextToken" value is nil when there's no more data to return.
		if DescribeDBInstances.Marker != nil {
			PaginationControl = DescribeDBInstances.Marker
		} else {
			PaginationControl = nil
			break
		}
	}

	return instances
}

func (m *NetworkPortsModule) getRDSClustersPerRegion(region string) []rds_types.DBCluster {
	var PaginationControl *string
	var clusters []rds_types.DBCluster
	for {
		DescribeDBClusters, err := m.RDSClient.DescribeDBClusters(
			context.TODO(),
			&(rds.DescribeDBClustersInput{
				Marker: PaginationControl,
			}),
			func(o *rds.Options) {
				o.Region = region
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		for _, cluster := range DescribeDBClusters.DBClusters {
			clusters = append(clusters, cluster)
		}

		// The "NextToken" value is nil when there's no more data to return.
		if DescribeDBClusters.Marker != nil {
			PaginationControl = DescribeDBClusters.Marker
		} else {
			PaginationControl = nil
			break
		}
	}

	return clusters
}

func (m *NetworkPortsModule) resolveNetworkAccess(groups []SecurityGroup, nacls []NetworkAcl) ([]int32, []int32) {
	var udpPorts []int32
	var tcpPorts []int32

	for _, group := range groups {
		for _, rule := range group.Rules {
			for _, nacl := range nacls {
				for _, port := range rule.Ports {
					res, naclRule := m.Evaluate(&nacl, port, rule.Protocol)
					if res && (naclToSG[naclRule.Protocol] == rule.Protocol || naclToSG[naclRule.Protocol] == "-1") {
						if rule.Protocol == "-1" && naclToSG[naclRule.Protocol] == rule.Protocol {
							tcpPorts = addPort(tcpPorts, port)
							udpPorts = addPort(udpPorts, port)
						} else if rule.Protocol == "tcp" {
							tcpPorts = addPort(tcpPorts, port)
						} else if rule.Protocol == "udp" {
							udpPorts = addPort(udpPorts, port)
						}
					}
				}
			}
		}
	}

	sort.Slice(tcpPorts, func(i, j int) bool {
		return tcpPorts[i] < tcpPorts[j]
	})

	sort.Slice(udpPorts, func(i, j int) bool {
		return udpPorts[i] < udpPorts[j]
	})

	return tcpPorts, udpPorts
}

func generateRange(start int32, end int32) []int32 {
	arr := make([]int32, end-start+1)
	for i := int32(0); int(i) < len(arr); i++ {
		arr[i] = i + start
	}
	return arr
}

func contains(arr []int32, v int32) bool {
	// Quick eval for all-ports
	if len(arr) == 65536 && arr[0] == int32(0) && arr[len(arr)-1] == int32(65535) {
		return true
	}
	for _, a := range arr {
		if a == v {
			return true
		}
	}

	return false
}

func strContains(arr []string, v string) bool {
	for _, a := range arr {
		if a == v {
			return true
		}
	}
	return false
}

func addPort(arr []int32, v int32) []int32 {
	if !contains(arr, v) {
		arr = append(arr, v)
	}
	return arr
}

func addHost(arr []string, v string) []string {
	if !strContains(arr, v) {
		arr = append(arr, v)
	}
	return arr
}

type Node struct {
	prev *Node
	next *Node
	rule NaclRule
}

func (l *NetworkAcl) Insert(rule NaclRule) {
	list := &Node{
		next: l.head,
		rule: rule,
	}
	if l.head != nil {
		l.head.prev = list
	}
	l.head = list

	head := l.head
	for head.next != nil {
		head = head.next
	}
	l.tail = head
}

func (m *NetworkPortsModule) Evaluate(l *NetworkAcl, port int32, proto string) (bool, *NaclRule) {
	node := l.head
	for node != nil {
		if contains(node.rule.PortRange, port) {
			if val, ok := naclToSG[node.rule.Protocol]; ok {
				if val == proto || val == "-1" || proto == "-1" {
					return node.rule.Action, &node.rule
				}
			} else {
				fmt.Printf("[%s][%s] Protocol: %d not supported\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), node.rule.Protocol)
			}

		}

		node = node.next
	}

	return false, nil
}

// Assumes sorted list of input
func prettyPorts(arr []int32) []string {
	var ports []string

	var first int32 = -1
	var last int32 = -1
	for i, v := range arr {
		if i == 0 {
			first = v
		} else {
			if last == -1 {
				if first+int32(1) == v {
					last = v
				} else {
					ports = append(ports, fmt.Sprintf("%d", first))
					first = v
					last = -1
				}
			} else if last != -1 && last+int32(1) == v {
				last = v
			} else {
				ports = append(ports, fmt.Sprintf("%d-%d", first, last))

				first = v
				last = -1
			}
		}
	}

	if last != -1 {
		ports = append(ports, fmt.Sprintf("%d-%d", first, last))
	} else if first != -1 {
		ports = append(ports, fmt.Sprintf("%d", first))
	}

	return ports
}
