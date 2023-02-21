package aws

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2_types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecs_types "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	efs_types "github.com/aws/aws-sdk-go-v2/service/efs/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	elasticache_types "github.com/aws/aws-sdk-go-v2/service/elasticache/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2_types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/aws/aws-sdk-go-v2/service/lightsail"
	lightsail_types "github.com/aws/aws-sdk-go-v2/service/lightsail/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rds_types "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/bishopfox/awsservicemap"
	"github.com/sirupsen/logrus"
)

var (
	TCP_4_SCAN string = "sudo nmap -Pn -sV"
	UDP_4_SCAN string = "sudo nmap -Pn -sU -sV"
	TCP_6_SCAN string = "sudo nmap -6 -Pn -sV"
	UDP_6_SCAN string = "sudo nmap -6 -Pn -sU -sV"

	IPv4_BANNER string = `#############################################
# The network services may have various ingress rules depending on your source IP.
# Try scanning from any or all network locations, such as within a VPC.
#############################################
`

	IPv6_BANNER string = `#############################################
# The network services may have various ingress rules depending on your source IP.
# Try scanning from any or all network locations, such as within a VPC.
# Make sure the host you scan IPv6 from has an IPv6 network interface.
#############################################
`

	naclsMutex          = sync.RWMutex{}
	securityGroupsMutex = sync.RWMutex{}
)

type NetworkPortsModule struct {
	// General configuration data
	EC2Client         *ec2.Client
	ECSClient         *ecs.Client
	EFSClient         *efs.Client
	ElastiCacheClient *elasticache.Client
	ELBv2Client       *elasticloadbalancingv2.Client
	LightsailClient   *lightsail.Client
	RDSClient         *rds.Client

	Caller       sts.GetCallerIdentityOutput
	AWSRegions   []string
	OutputFormat string
	Goroutines   int
	AWSProfile   string
	WrapTable    bool
	Verbosity    int

	// Main module data
	IPv4_Private   []NetworkService
	IPv4_Public    []NetworkService
	IPv6           []NetworkService
	nacls          map[string]*[]ec2_types.NetworkAcl
	securityGroups map[string]*[]ec2_types.SecurityGroup

	CommandCounter internal.CommandCounter
	// Used to store output data for pretty printing
	output internal.OutputData2
	modLog *logrus.Entry
}

type NetworkServices struct {
	IPv4_Private []NetworkService
	IPv4_Public  []NetworkService
	IPv6         []NetworkService
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
	head    *portNode
	tail    *portNode
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

var validSecurityGroupProtocols = []string{"-1", "tcp", "udp"}

func (m *NetworkPortsModule) PrintNetworkPorts(outputFormat string, outputDirectory string) {
	// These stuct values are used by the output module
	m.output.Verbosity = m.Verbosity
	m.output.Directory = outputDirectory
	m.output.CallingModule = "network-ports"
	m.modLog = internal.TxtLog.WithFields(logrus.Fields{
		"module": m.output.CallingModule,
	})
	if m.AWSProfile == "" {
		m.AWSProfile = internal.BuildAWSPath(m.Caller)
	}
	m.nacls = make(map[string]*[]ec2_types.NetworkAcl)
	m.securityGroups = make(map[string]*[]ec2_types.SecurityGroup)

	fmt.Printf("[%s][%s] Enumerating potentially accessible network services for account %s.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), aws.ToString(m.Caller.Account))
	fmt.Printf("[%s][%s] Supported Services: EC2, EFS, ECS, ElastiCache, ELBv2, Lightsail, RDS  \n", cyan(m.output.CallingModule), cyan(m.AWSProfile))

	wg := new(sync.WaitGroup)

	// Create a channel to signal the spinner aka task status goroutine to finish
	spinnerDone := make(chan bool)
	//fire up the the task status spinner/updated
	go internal.SpinUntil(m.output.CallingModule, &m.CommandCounter, spinnerDone, "tasks")

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
	for _, arr := range [][]NetworkService{m.IPv4_Private, m.IPv4_Public, m.IPv6} {
		for _, i := range arr {
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
	}

	if len(m.IPv4_Private) > 0 || len(m.IPv4_Public) > 0 || len(m.IPv6) > 0 {
		m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", m.AWSProfile)
		//m.output.OutputSelector(outputFormat)
		internal.OutputSelector(m.Verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.CallingModule, m.output.CallingModule, m.WrapTable, m.AWSProfile)
		m.writeLoot(m.output.FilePath)
		fmt.Printf("[%s][%s] %s network services found.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), strconv.Itoa(len(m.output.Body)))

	} else {
		fmt.Printf("[%s][%s] No network services found, skipping the creation of an output file.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	}
	fmt.Printf("[%s][%s] For context and next steps: https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#%s\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), m.output.CallingModule)

}

func (m *NetworkPortsModule) executeChecks(r string, wg *sync.WaitGroup, dataReceiver chan NetworkServices) {
	defer wg.Done()
	servicemap := &awsservicemap.AwsServiceMap{
		JsonFileSource: "DOWNLOAD_FROM_AWS",
	}

	res, err := servicemap.IsServiceInRegion("ec2", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		m.getEC2NetworkPortsPerRegion(r, dataReceiver)
	}

	res, err = servicemap.IsServiceInRegion("ecs", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		m.getECSNetworkPortsPerRegion(r, dataReceiver)
	}

	res, err = servicemap.IsServiceInRegion("efs", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		m.getEFSNetworkPortsPerRegion(r, dataReceiver)
	}

	res, err = servicemap.IsServiceInRegion("elasticache", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		m.getElastiCacheNetworkPortsPerRegion(r, dataReceiver)
	}

	res, err = servicemap.IsServiceInRegion("elb", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		m.getLBNetworkPortsPerRegion(r, dataReceiver)
	}

	res, err = servicemap.IsServiceInRegion("lightsail", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		m.getLightsailNetworkPortsPerRegion(r, dataReceiver)
	}

	res, err = servicemap.IsServiceInRegion("rds", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		m.getRdsNetworkPortsPerRegion(r, dataReceiver)
	}

}

func (m *NetworkPortsModule) Receiver(receiver chan NetworkServices, receiverDone chan bool) {
	defer close(receiverDone)
	for {
		select {
		case data := <-receiver:
			if len(data.IPv4_Private) != 0 {
				m.IPv4_Private = append(m.IPv4_Private, data.IPv4_Private...)
			}
			if len(data.IPv4_Public) != 0 {
				m.IPv4_Public = append(m.IPv4_Public, data.IPv4_Public...)
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

	if len(m.IPv4_Private) > 0 {
		ipv4Filename := filepath.Join(path, "network-ports-private-ipv4.txt")
		m.writeLootFile(ipv4Filename, IPv4_BANNER, true, m.IPv4_Private)
	}

	if len(m.IPv4_Public) > 0 {
		ipv4Filename := filepath.Join(path, "network-ports-public-ipv4.txt")
		m.writeLootFile(ipv4Filename, IPv4_BANNER, true, m.IPv4_Public)
	}

	if len(m.IPv6) > 0 {
		ipv6Filename := filepath.Join(path, "network-ports-public-ipv6.txt")
		m.writeLootFile(ipv6Filename, IPv6_BANNER, false, m.IPv6)
	}
}

func (m *NetworkPortsModule) writeLootFile(filename string, bannner string, ipv4 bool, services []NetworkService) {
	out := bannner

	for _, service := range services {
		if service.Protocol == "tcp" {
			if ipv4 {
				out = out + fmt.Sprintf("%s -p %s %s\n", TCP_4_SCAN, strings.Join(service.Ports, ","), strings.Join(service.Hosts, " "))
			} else {
				out = out + fmt.Sprintf("%s -p %s %s\n", TCP_6_SCAN, strings.Join(service.Ports, ","), strings.Join(service.Hosts, " "))
			}
		}

		if service.Protocol == "udp" {
			if ipv4 {
				out = out + fmt.Sprintf("%s -p %s %s\n", UDP_4_SCAN, strings.Join(service.Ports, ","), strings.Join(service.Hosts, " "))
			} else {
				out = out + fmt.Sprintf("%s -p %s %s\n", UDP_6_SCAN, strings.Join(service.Ports, ","), strings.Join(service.Hosts, " "))
			}
		}
	}

	err := os.WriteFile(filename, []byte(out), 0644)
	if err != nil {
		m.modLog.Error(err.Error())
	}

	if m.Verbosity > 2 {
		fmt.Println()
		fmt.Printf("[%s][%s] %s \n", cyan(m.output.CallingModule), cyan(m.AWSProfile), green("Use the commands below to manually inspect certain buckets of interest."))
		fmt.Print(out)
		fmt.Printf("[%s][%s] %s \n", cyan(m.output.CallingModule), cyan(m.AWSProfile), green("End of loot file."))
	}

	fmt.Printf("[%s][%s] Loot written to [%s]\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), filename)
}

func (m *NetworkPortsModule) getEC2NetworkPortsPerRegion(r string, dataReceiver chan NetworkServices) {
	defer func() {
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}()
	securityGroups := m.getEC2SecurityGroupsPerRegion(r)
	nacls := m.getEC2NACLsPerRegion(r)

	instances := m.getEC2InstancesPerRegion(r)

	var wg sync.WaitGroup
	wg.Add(len(instances))

	for _, instance := range instances {
		go func(instance ec2_types.Instance) {
			defer wg.Done()

			var ipv4_public, ipv4_private, ipv6 []string
			for _, nic := range instance.NetworkInterfaces {
				// ipv4
				for _, addr := range nic.PrivateIpAddresses {
					if addr.Association != nil {
						if addr.Association.PublicIp != nil {
							ipv4_public = addHost(ipv4_public, aws.ToString(addr.Association.PublicIp))
						}
					}

					if addr.PrivateIpAddress != nil {
						ipv4_private = addHost(ipv4_private, aws.ToString(addr.PrivateIpAddress))
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

			tcpPorts, udpPorts := m.resolveNetworkAccess(groups, networkAcls)
			tcpPortsInts := prettyPorts(tcpPorts)
			udpPortsInts := prettyPorts(udpPorts)

			// if m.Verbosity > 0 {
			// 	fmt.Printf("[%s][%s] %s \n", cyan(m.output.CallingModule), cyan(m.AWSProfile), fmt.Sprintf("EC2 Instance: %s, TCP Ports: %v, UDP Ports: %v\n", aws.ToString(instance.InstanceId), tcpPortsInts, udpPortsInts))
			// }

			var networkServices NetworkServices

			// IPV4
			if len(ipv4_private) > 0 {

				if len(tcpPorts) > 0 {
					networkServices.IPv4_Private = append(networkServices.IPv4_Private, NetworkService{AWSService: "EC2", Region: r, Hosts: ipv4_private, Ports: tcpPortsInts, Protocol: "tcp"})
				}
				if len(udpPorts) > 0 {
					networkServices.IPv4_Private = append(networkServices.IPv4_Private, NetworkService{AWSService: "EC2", Region: r, Hosts: ipv4_private, Ports: udpPortsInts, Protocol: "udp"})
				}
			}

			if len(ipv4_public) > 0 {

				if len(tcpPorts) > 0 {
					networkServices.IPv4_Public = append(networkServices.IPv4_Public, NetworkService{AWSService: "EC2", Region: r, Hosts: ipv4_public, Ports: tcpPortsInts, Protocol: "tcp"})
				}
				if len(udpPorts) > 0 {
					networkServices.IPv4_Public = append(networkServices.IPv4_Public, NetworkService{AWSService: "EC2", Region: r, Hosts: ipv4_public, Ports: udpPortsInts, Protocol: "udp"})
				}
			}

			// IPV6
			if len(ipv6) > 0 {
				if len(tcpPorts) > 0 {
					networkServices.IPv6 = append(networkServices.IPv6, NetworkService{AWSService: "EC2", Region: r, Hosts: ipv6, Ports: tcpPortsInts, Protocol: "tcp"})
				}
				if len(udpPorts) > 0 {
					networkServices.IPv6 = append(networkServices.IPv6, NetworkService{AWSService: "EC2", Region: r, Hosts: ipv6, Ports: udpPortsInts, Protocol: "udp"})
				}
			}
			dataReceiver <- networkServices
		}(instance)
	}
	wg.Wait()
}

func (m *NetworkPortsModule) getECSNetworkPortsPerRegion(r string, dataReceiver chan NetworkServices) {
	defer func() {
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}()
	securityGroups := m.getEC2SecurityGroupsPerRegion(r)
	nacls := m.getEC2NACLsPerRegion(r)

	clustersArns := m.getECSClustersPerRegion(r)

	for _, clusterArn := range clustersArns {
		servicesArns := m.getECSServicesPerRegion(&clusterArn, r)
		for _, serviceArn := range servicesArns {

			service, err := m.describeECSService(serviceArn, &clusterArn, r)
			if err != nil {
				m.modLog.Error(err.Error())
				m.CommandCounter.Error++
				break
			}

			var groups []SecurityGroup
			var networkAcls []NetworkAcl
			if service.NetworkConfiguration != nil {
				if service.NetworkConfiguration.AwsvpcConfiguration != nil {
					// Subnets
					for _, subnet := range service.NetworkConfiguration.AwsvpcConfiguration.Subnets {
						for _, nacl := range nacls {
							for _, assoc := range nacl.Associations {
								if subnet == aws.ToString(assoc.SubnetId) {
									networkAcls = append(networkAcls, m.parseNacl(nacl))
								}
							}
						}
					}

					// Security Groups
					for _, group := range service.NetworkConfiguration.AwsvpcConfiguration.SecurityGroups {
						for _, g := range securityGroups {
							if group == aws.ToString(g.GroupId) {
								groups = append(groups, m.parseSecurityGroup(g))
							}
						}
					}
				}
			}

			// Get Tasks associated with service
			taskArns := m.getECSTasksPerRegion(service.ServiceName, &clusterArn, r)
			for _, taskArn := range taskArns {

				task, err := m.describeECSTask(taskArn, &clusterArn, r)
				if err != nil {
					m.modLog.Error(err.Error())
					m.CommandCounter.Error++
					break
				}

				var interfaces []ec2_types.NetworkInterface
				for _, attachment := range task.Attachments {
					for _, detail := range attachment.Details {
						if aws.ToString(detail.Name) == "networkInterfaceId" {
							networkInterfaces := m.getEC2NetworkInterfacesPerRegion(aws.ToString(detail.Value), r)
							interfaces = append(interfaces, networkInterfaces...)
						}
					}
				}

				var ipv4_public, ipv4_private, ipv6 []string

				// Get the IPs associated with each interface
				for _, nic := range interfaces {
					for _, addr := range nic.PrivateIpAddresses {
						if addr.Association != nil {
							if addr.Association.PublicIp != nil {
								ipv4_public = addHost(ipv4_public, aws.ToString(addr.Association.PublicIp))
							}
						}

						if addr.PrivateIpAddress != nil {
							ipv4_private = addHost(ipv4_private, aws.ToString(addr.PrivateIpAddress))
						}
					}

					for _, addr := range nic.Ipv6Addresses {
						if addr.Ipv6Address != nil {
							ipv6 = addHost(ipv6, aws.ToString(addr.Ipv6Address))
						}
					}
				}

				tcpPorts, udpPorts := m.resolveNetworkAccess(groups, networkAcls)
				tcpPortsInts := prettyPorts(tcpPorts)
				udpPortsInts := prettyPorts(udpPorts)

				// if m.Verbosity > 0 {
				// 	fmt.Printf("[%s][%s] %s \n", cyan(m.output.CallingModule), cyan(m.AWSProfile), fmt.Sprintf("ECS: %s, TCP Ports: %v, UDP Ports: %v", taskArn, tcpPortsInts, udpPortsInts))
				// }

				var networkServices NetworkServices

				// IPV4
				if len(ipv4_private) > 0 {
					if len(tcpPorts) > 0 {
						networkServices.IPv4_Private = append(networkServices.IPv4_Private, NetworkService{AWSService: "ECS", Region: r, Hosts: ipv4_private, Ports: tcpPortsInts, Protocol: "tcp"})
					}
					if len(udpPorts) > 0 {
						networkServices.IPv4_Private = append(networkServices.IPv4_Private, NetworkService{AWSService: "ECS", Region: r, Hosts: ipv4_private, Ports: udpPortsInts, Protocol: "udp"})
					}
				}

				if len(ipv4_public) > 0 {
					if len(tcpPorts) > 0 {
						networkServices.IPv4_Public = append(networkServices.IPv4_Public, NetworkService{AWSService: "ECS", Region: r, Hosts: ipv4_public, Ports: tcpPortsInts, Protocol: "tcp"})
					}
					if len(udpPorts) > 0 {
						networkServices.IPv4_Public = append(networkServices.IPv4_Public, NetworkService{AWSService: "ECS", Region: r, Hosts: ipv4_public, Ports: udpPortsInts, Protocol: "udp"})
					}
				}

				// IPV6
				if len(ipv6) > 0 {
					if len(tcpPorts) > 0 {
						networkServices.IPv6 = append(networkServices.IPv6, NetworkService{AWSService: "ECS", Region: r, Hosts: ipv6, Ports: tcpPortsInts, Protocol: "tcp"})
					}
					if len(udpPorts) > 0 {
						networkServices.IPv6 = append(networkServices.IPv6, NetworkService{AWSService: "ECS", Region: r, Hosts: ipv6, Ports: udpPortsInts, Protocol: "udp"})
					}
				}
				dataReceiver <- networkServices
			}
		}
	}
}

func (m *NetworkPortsModule) getEFSNetworkPortsPerRegion(r string, dataReceiver chan NetworkServices) {
	defer func() {
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}()
	securityGroups := m.getEC2SecurityGroupsPerRegion(r)
	nacls := m.getEC2NACLsPerRegion(r)

	filesystems := m.getEFSSharesPerRegion(r)

	for _, filesystem := range filesystems {

		targets := m.getEFSMountTargetsPerRegion(filesystem.FileSystemId, r)
		for _, target := range targets {

			interfaces := m.getEC2NetworkInterfacesPerRegion(aws.ToString(target.NetworkInterfaceId), r)

			// Security Groups
			var groups []SecurityGroup
			for _, nic := range interfaces {
				for _, group := range nic.Groups {
					for _, g := range securityGroups {
						if aws.ToString(group.GroupId) == aws.ToString(g.GroupId) {
							groups = append(groups, m.parseSecurityGroup(g))
						}
					}
				}
			}

			// Network ACLs
			var networkAcls []NetworkAcl
			for _, nacl := range nacls {
				for _, assoc := range nacl.Associations {
					if aws.ToString(target.SubnetId) == aws.ToString(assoc.SubnetId) {
						networkAcls = append(networkAcls, m.parseNacl(nacl))
					}
				}
			}

			tcpPorts, _ := m.resolveNetworkAccess(groups, networkAcls)

			var tcpPortsInts []int32
			if contains(tcpPorts, 2049) {
				tcpPortsInts = addPort(tcpPortsInts, 2049)
			}

			sort.Slice(tcpPortsInts, func(i, j int) bool {
				return tcpPortsInts[i] < tcpPortsInts[j]
			})

			var networkServices NetworkServices
			if len(tcpPortsInts) > 0 {
				// if m.Verbosity > 0 {
				// 	fmt.Printf("[%s][%s] %s \n", cyan(m.output.CallingModule), cyan(m.AWSProfile), fmt.Sprintf("EFS: %s, TCP Ports: %v, UDP Ports: []", aws.ToString(target.IpAddress), tcpPortsInts))
				// }
				networkServices.IPv4_Private = append(networkServices.IPv4_Private, NetworkService{AWSService: "EFS", Region: r, Hosts: []string{aws.ToString(target.IpAddress)}, Ports: prettyPorts(tcpPortsInts), Protocol: "tcp"})

				dataReceiver <- networkServices
			}
		}
	}
}

func (m *NetworkPortsModule) getElastiCacheNetworkPortsPerRegion(r string, dataReceiver chan NetworkServices) {
	defer func() {
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}()
	securityGroups := m.getEC2SecurityGroupsPerRegion(r)
	nacls := m.getEC2NACLsPerRegion(r)

	elastiClusters := m.getElastiCacheClustersPerRegion(r)
	subnetGroups := m.getElastiCacheSubnetGroupsPerRegion(r)
	nodes := m.getElastiCacheReplicationGroupsPerRegion(r)

	var reportedClusters []string

	for _, cluster := range elastiClusters {

		var ipv4_private []string
		var tcpPortsInts []int32

		var networkAcls []NetworkAcl

		// Subnets
		subnetGroup := aws.ToString(cluster.CacheSubnetGroupName)
		for _, group := range subnetGroups {
			if subnetGroup == aws.ToString(group.CacheSubnetGroupName) {
				for _, subnet := range group.Subnets {
					for _, nacl := range nacls {
						for _, assoc := range nacl.Associations {
							if aws.ToString(subnet.SubnetIdentifier) == aws.ToString(assoc.SubnetId) {
								networkAcls = append(networkAcls, m.parseNacl(nacl))
							}
						}
					}
				}
			}
		}

		// Security Groups
		var groups []SecurityGroup
		for _, group := range cluster.SecurityGroups {
			for _, g := range securityGroups {
				if aws.ToString(group.SecurityGroupId) == aws.ToString(g.GroupId) {
					groups = append(groups, m.parseSecurityGroup(g))
				}
			}
		}

		// Memcached
		if cluster.ConfigurationEndpoint != nil {
			ipv4_private = addHost(ipv4_private, aws.ToString(cluster.ConfigurationEndpoint.Address))
			tcpPortsInts = addPort(tcpPortsInts, cluster.ConfigurationEndpoint.Port)
		} else {
			replicationGroupId := aws.ToString(cluster.ReplicationGroupId)
			for _, group := range nodes {
				if replicationGroupId == aws.ToString(group.ReplicationGroupId) {
					for _, g := range group.NodeGroups {
						// Primary
						if g.PrimaryEndpoint != nil && !strContains(reportedClusters, aws.ToString(g.PrimaryEndpoint.Address)) {
							ipv4_private = addHost(ipv4_private, aws.ToString(g.PrimaryEndpoint.Address))
							tcpPortsInts = addPort(tcpPortsInts, g.PrimaryEndpoint.Port)

							reportedClusters = addHost(reportedClusters, aws.ToString(g.PrimaryEndpoint.Address))
						}

						// Reader
						if g.ReaderEndpoint != nil && !strContains(reportedClusters, aws.ToString(g.ReaderEndpoint.Address)) {
							ipv4_private = addHost(ipv4_private, aws.ToString(g.ReaderEndpoint.Address))
							tcpPortsInts = addPort(tcpPortsInts, g.ReaderEndpoint.Port)

							reportedClusters = addHost(reportedClusters, aws.ToString(g.ReaderEndpoint.Address))
						}

						// NodeGroupMembers
						for _, m := range g.NodeGroupMembers {
							if aws.ToString(m.CacheClusterId) == aws.ToString(cluster.CacheClusterId) {
								if m.ReadEndpoint != nil {
									ipv4_private = addHost(ipv4_private, aws.ToString(m.ReadEndpoint.Address))
									tcpPortsInts = addPort(tcpPortsInts, m.ReadEndpoint.Port)
								}
							}
						}
					}
				}
			}
		}

		tcpPorts, _ := m.resolveNetworkAccess(groups, networkAcls)
		var tcp []int32
		for _, port := range tcpPortsInts {
			if contains(tcpPorts, port) {
				tcp = addPort(tcp, port)
			}
		}

		sort.Slice(tcp, func(i, j int) bool {
			return tcp[i] < tcp[j]
		})

		var networkServices NetworkServices
		if len(tcp) > 0 {
			for _, i := range ipv4_private {
				// if m.Verbosity > 0 {
				// 	fmt.Printf("[%s][%s] %s \n", cyan(m.output.CallingModule), cyan(m.AWSProfile), fmt.Sprintf("ElastiCache: %s, TCP Ports: %v, UDP Ports: []", i, tcp))
				// }
				networkServices.IPv4_Private = append(networkServices.IPv4_Private, NetworkService{AWSService: "ElastiCache", Region: r, Hosts: []string{i}, Ports: prettyPorts(tcp), Protocol: "tcp"})
			}
		}

		dataReceiver <- networkServices
	}
}

func (m *NetworkPortsModule) getLBNetworkPortsPerRegion(r string, dataReceiver chan NetworkServices) {
	defer func() {
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}()
	securityGroups := m.getEC2SecurityGroupsPerRegion(r)
	nacls := m.getEC2NACLsPerRegion(r)

	loadBalancers := m.getLoadBalancersPerRegion(r)

	for _, lb := range loadBalancers {
		// Gateway ELBs run on Layer 3
		if lb.Type != elbv2_types.LoadBalancerTypeEnumGateway {
			var ipv4_public, ipv4_private, ipv6 []string
			ipv4_public = []string{aws.ToString(lb.DNSName)}

			var groups []SecurityGroup
			for _, group := range lb.SecurityGroups {
				for _, g := range securityGroups {
					if group == aws.ToString(g.GroupId) {
						groups = append(groups, m.parseSecurityGroup(g))
					}
				}
			}

			var networkAcls []NetworkAcl
			for _, az := range lb.AvailabilityZones {
				// Extract address from LoadBalancerAddresses
				for _, lba := range az.LoadBalancerAddresses {
					if lba.IPv6Address != nil {
						ipv6 = addHost(ipv6, aws.ToString(lba.IPv6Address))
					}
					if lba.IpAddress != nil {
						ipv4_public = addHost(ipv4_public, aws.ToString(lba.IpAddress))
					}
					if lba.PrivateIPv4Address != nil {
						ipv4_private = addHost(ipv4_private, aws.ToString(lba.PrivateIPv4Address))
					}
				}

				for _, nacl := range nacls {
					for _, assoc := range nacl.Associations {
						if aws.ToString(az.SubnetId) == aws.ToString(assoc.SubnetId) {
							networkAcls = append(networkAcls, m.parseNacl(nacl))
						}
					}
				}
			}

			// If there are no security groups, add a catchall.
			// NLBs do not have security groups
			if len(groups) == 0 {
				secGroup := SecurityGroup{ID: "", VpcId: "", Rules: []SecurityGroupRule{
					{Protocol: "-1", Cidr: []string{}, Ports: generateRange(0, 65535)},
				}}
				groups = append(groups, secGroup)
			}
			tcpPorts, udpPorts := m.resolveNetworkAccess(groups, networkAcls)
			lbTcpPorts, lbUdpPorts := m.getLBListenerPorts(lb.LoadBalancerArn, r)
			var tcpPortsInts, udpPortsInts []int32
			for _, port := range lbTcpPorts {
				if contains(tcpPorts, port) {
					tcpPortsInts = addPort(tcpPortsInts, port)
				}
			}
			for _, port := range lbUdpPorts {
				if contains(udpPorts, port) {
					udpPortsInts = addPort(udpPortsInts, port)
				}
			}

			sort.Slice(tcpPortsInts, func(i, j int) bool {
				return tcpPortsInts[i] < tcpPortsInts[j]
			})
			sort.Slice(udpPortsInts, func(i, j int) bool {
				return udpPortsInts[i] < udpPortsInts[j]
			})
			tcp := prettyPorts(tcpPortsInts)
			udp := prettyPorts(udpPortsInts)

			// if m.Verbosity > 0 {
			// 	fmt.Printf("[%s][%s] %s\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), fmt.Sprintf("LB: %s, TCP Ports: %v, UDP Ports: %v", aws.ToString(lb.LoadBalancerName), tcp, udp))
			// }

			var networkServices NetworkServices

			if len(ipv4_public) > 0 {
				if len(tcp) > 0 {
					networkServices.IPv4_Public = append(networkServices.IPv4_Public, NetworkService{AWSService: "ELBv2", Region: r, Hosts: ipv4_public, Ports: tcp, Protocol: "tcp"})
				}
				if len(udp) > 0 {
					networkServices.IPv4_Public = append(networkServices.IPv4_Public, NetworkService{AWSService: "ELBv2", Region: r, Hosts: ipv4_public, Ports: udp, Protocol: "udp"})
				}
			}
			if len(ipv4_private) > 0 {
				if len(tcp) > 0 {
					networkServices.IPv4_Private = append(networkServices.IPv4_Private, NetworkService{AWSService: "ELBv2", Region: r, Hosts: ipv4_private, Ports: tcp, Protocol: "tcp"})
				}
				if len(udp) > 0 {
					networkServices.IPv4_Private = append(networkServices.IPv4_Private, NetworkService{AWSService: "ELBv2", Region: r, Hosts: ipv4_private, Ports: udp, Protocol: "udp"})

				}
			}
			if len(ipv6) > 0 {
				if len(tcp) > 0 {
					networkServices.IPv6 = append(networkServices.IPv6, NetworkService{AWSService: "ELBv2", Region: r, Hosts: ipv6, Ports: tcp, Protocol: "tcp"})
				}
				if len(udp) > 0 {
					networkServices.IPv6 = append(networkServices.IPv6, NetworkService{AWSService: "ELBv2", Region: r, Hosts: ipv6, Ports: udp, Protocol: "udp"})
				}
			}
			dataReceiver <- networkServices
		}
	}
}

func (m *NetworkPortsModule) getLightsailNetworkPortsPerRegion(r string, dataReceiver chan NetworkServices) {
	defer func() {
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}()
	instances := m.getLightsailInstancesPerRegion(r)

	var wg sync.WaitGroup
	wg.Add(len(instances))

	for _, instance := range instances {
		go func(instance lightsail_types.Instance) {
			defer wg.Done()

			var ipv4_private, ipv4_public, ipv6 []string
			var tcpPorts, udpPorts []int32

			if instance.PrivateIpAddress != nil {
				ipv4_private = addHost(ipv4_private, aws.ToString(instance.PrivateIpAddress))
			}
			if instance.PublicIpAddress != nil {
				ipv4_public = addHost(ipv4_public, aws.ToString(instance.PublicIpAddress))
			}

			//IPv6 and IPv4
			if instance.IpAddressType == "dualstack" {
				for _, addr := range instance.Ipv6Addresses {
					ipv6 = addHost(ipv6, addr)
				}
			}

			if instance.Networking != nil {
				for _, port := range instance.Networking.Ports {
					if port.FromPort <= port.ToPort {
						ports := generateRange(port.FromPort, port.ToPort)
						switch port.Protocol {
						case "-1":
							{
								for _, p := range ports {
									tcpPorts = addPort(tcpPorts, p)
									udpPorts = addPort(udpPorts, p)
								}
							}
						case "tcp":
							{
								for _, p := range ports {
									tcpPorts = addPort(tcpPorts, p)
								}
							}
						case "udp":
							{
								for _, p := range ports {
									udpPorts = addPort(udpPorts, p)
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

			tcpPortsInts := prettyPorts(tcpPorts)
			udpPortsInts := prettyPorts(udpPorts)

			// if m.Verbosity > 0 {
			// 	fmt.Printf("[%s][%s] %s \n", cyan(m.output.CallingModule), cyan(m.AWSProfile), fmt.Sprintf("Lightsail Instance: %s, TCP Ports: %v, UDP Ports: %v", aws.ToString(instance.Arn), tcpPortsInts, udpPortsInts))
			// }

			var networkServices NetworkServices

			// IPV4
			if len(ipv4_private) > 0 {
				if len(tcpPortsInts) > 0 {
					networkServices.IPv4_Private = append(networkServices.IPv4_Private, NetworkService{AWSService: "Lightsail", Region: r, Hosts: ipv4_private, Ports: tcpPortsInts, Protocol: "tcp"})
				}
				if len(udpPortsInts) > 0 {
					networkServices.IPv4_Private = append(networkServices.IPv4_Private, NetworkService{AWSService: "Lightsail", Region: r, Hosts: ipv4_private, Ports: udpPortsInts, Protocol: "udp"})
				}
			}

			if len(ipv4_public) > 0 {
				if len(tcpPortsInts) > 0 {
					networkServices.IPv4_Public = append(networkServices.IPv4_Public, NetworkService{AWSService: "Lightsail", Region: r, Hosts: ipv4_public, Ports: tcpPortsInts, Protocol: "tcp"})
				}
				if len(udpPortsInts) > 0 {
					networkServices.IPv4_Public = append(networkServices.IPv4_Public, NetworkService{AWSService: "Lightsail", Region: r, Hosts: ipv4_public, Ports: udpPortsInts, Protocol: "udp"})
				}
			}

			// IPV6
			if len(ipv6) > 0 {
				if len(tcpPortsInts) > 0 {
					networkServices.IPv6 = append(networkServices.IPv6, NetworkService{AWSService: "Lightsail", Region: r, Hosts: ipv6, Ports: tcpPortsInts, Protocol: "tcp"})
				}
				if len(udpPortsInts) > 0 {
					networkServices.IPv6 = append(networkServices.IPv6, NetworkService{AWSService: "Lightsail", Region: r, Hosts: ipv6, Ports: udpPortsInts, Protocol: "udp"})
				}
			}
			dataReceiver <- networkServices
		}(instance)
	}
	wg.Wait()
}

func (m *NetworkPortsModule) getRdsNetworkPortsPerRegion(r string, dataReceiver chan NetworkServices) {
	defer func() {
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}()
	securityGroups := m.getEC2SecurityGroupsPerRegion(r)
	nacls := m.getEC2NACLsPerRegion(r)

	DBInstances := m.getRdsInstancesPerRegion(r)
	RDSClusters := m.getRdsClustersPerRegion(r)

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
				// if m.Verbosity > 0 {
				// 	fmt.Printf("[%s][%s] %s \n", cyan(m.output.CallingModule), cyan(m.AWSProfile), fmt.Sprintf("DB Instance: %s, TCP Ports: %d", aws.ToString(instance.Endpoint.Address), port))
				// }
				networkServices.IPv4_Private = append(networkServices.IPv4_Private, NetworkService{AWSService: "RDS", Region: r, Hosts: host, Ports: []string{fmt.Sprintf("%d", port)}, Protocol: "tcp"})

				// Check clusters
				if aws.ToString(instance.DBClusterIdentifier) != "" {
					clusterId := aws.ToString(instance.DBClusterIdentifier)
					if !strContains(reportedClusters, clusterId) {
						for _, cluster := range RDSClusters {
							if aws.ToString(cluster.DBClusterIdentifier) == clusterId {
								// if m.Verbosity > 0 {
								// 	fmt.Printf("[%s][%s] %s \n", cyan(m.output.CallingModule), cyan(m.AWSProfile), fmt.Sprintf("DB Instance: %s, TCP Ports: %d", aws.ToString(cluster.Endpoint), port))
								// 	fmt.Printf("[%s][%s] %s \n", cyan(m.output.CallingModule), cyan(m.AWSProfile), fmt.Sprintf("DB Instance: %s, TCP Ports: %d", aws.ToString(cluster.ReaderEndpoint), port))
								// }
								networkServices.IPv4_Private = append(networkServices.IPv4_Private, NetworkService{AWSService: "RDS", Region: r, Hosts: []string{aws.ToString(cluster.Endpoint)}, Ports: []string{fmt.Sprintf("%d", port)}, Protocol: "tcp"})
								networkServices.IPv4_Private = append(networkServices.IPv4_Private, NetworkService{AWSService: "RDS", Region: r, Hosts: []string{aws.ToString(cluster.ReaderEndpoint)}, Ports: []string{fmt.Sprintf("%d", port)}, Protocol: "tcp"})

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

func (m *NetworkPortsModule) getEC2SecurityGroupsPerRegion(region string) []ec2_types.SecurityGroup {
	var securityGroups []ec2_types.SecurityGroup
	var PaginationControl *string

	if m.securityGroups[region] != nil {
		return *m.securityGroups[region]
	}

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

	securityGroupsMutex.Lock()
	m.securityGroups[region] = &securityGroups
	securityGroupsMutex.Unlock()
	return securityGroups
}

func (m *NetworkPortsModule) parseSecurityGroup(group ec2_types.SecurityGroup) SecurityGroup {
	id := aws.ToString(group.GroupId)
	vpcId := aws.ToString(group.VpcId)
	var rules []SecurityGroupRule
	for _, entry := range group.IpPermissions {
		protocol := aws.ToString(entry.IpProtocol)
		if strContains(validSecurityGroupProtocols, protocol) {
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
	}

	return SecurityGroup{
		ID:    id,
		VpcId: vpcId,
		Rules: rules,
	}
}

func (m *NetworkPortsModule) getEC2NACLsPerRegion(region string) []ec2_types.NetworkAcl {
	var nacls []ec2_types.NetworkAcl
	var PaginationControl *string

	if m.nacls[region] != nil {
		return *m.nacls[region]
	}

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

	naclsMutex.Lock()
	m.nacls[region] = &nacls
	naclsMutex.Unlock()
	return nacls
}

func (m *NetworkPortsModule) parseNacl(nacl ec2_types.NetworkAcl) NetworkAcl {
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

func (m *NetworkPortsModule) getEC2InstancesPerRegion(region string) []ec2_types.Instance {
	var instances []ec2_types.Instance
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

func (m *NetworkPortsModule) getEC2NetworkInterfacesPerRegion(interfaceId string, region string) []ec2_types.NetworkInterface {
	var interfaces []ec2_types.NetworkInterface
	var PaginationControl *string

	for {
		DescribeNetworkInterfaces, err := m.EC2Client.DescribeNetworkInterfaces(
			context.TODO(),
			&(ec2.DescribeNetworkInterfacesInput{
				NetworkInterfaceIds: []string{interfaceId},
				NextToken:           PaginationControl,
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

		for _, networkInterface := range DescribeNetworkInterfaces.NetworkInterfaces {
			interfaces = append(interfaces, networkInterface)
		}

		if DescribeNetworkInterfaces.NextToken != nil {
			PaginationControl = DescribeNetworkInterfaces.NextToken
		} else {
			PaginationControl = nil
			break
		}
	}

	return interfaces
}

func (m *NetworkPortsModule) getECSClustersPerRegion(region string) []string {
	var clusters []string
	var PaginationControl *string

	for {
		ListClusters, err := m.ECSClient.ListClusters(
			context.TODO(),
			&(ecs.ListClustersInput{
				NextToken: PaginationControl,
			}),
			func(o *ecs.Options) {
				o.Region = region
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		for _, cluster := range ListClusters.ClusterArns {
			clusters = append(clusters, cluster)
		}

		if ListClusters.NextToken != nil {
			PaginationControl = ListClusters.NextToken
		} else {
			PaginationControl = nil
			break
		}
	}

	return clusters
}

func (m *NetworkPortsModule) getECSServicesPerRegion(clusterArn *string, region string) []string {
	var services []string
	var PaginationControl *string

	for {
		ListServices, err := m.ECSClient.ListServices(
			context.TODO(),
			&(ecs.ListServicesInput{
				Cluster:   clusterArn,
				NextToken: PaginationControl,
			}),
			func(o *ecs.Options) {
				o.Region = region
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		for _, service := range ListServices.ServiceArns {
			services = append(services, service)
		}

		if ListServices.NextToken != nil {
			PaginationControl = ListServices.NextToken
		} else {
			PaginationControl = nil
			break
		}
	}

	return services
}

func (m *NetworkPortsModule) describeECSService(serviceArn string, clusterArn *string, region string) (*ecs_types.Service, error) {
	var result ecs_types.Service

	DescribeServices, err := m.ECSClient.DescribeServices(
		context.TODO(),
		&(ecs.DescribeServicesInput{
			Services: []string{serviceArn},
			Cluster:  clusterArn,
		}),
		func(o *ecs.Options) {
			o.Region = region
		},
	)
	if err != nil {
		return nil, err
	}

	if len(DescribeServices.Services) != 1 {
		return nil, errors.New(fmt.Sprintf("Service not found: %s", serviceArn))
	} else {
		result = DescribeServices.Services[0]
	}

	return &result, nil
}

func (m *NetworkPortsModule) getECSTasksPerRegion(service *string, clusterArn *string, region string) []string {
	var tasks []string
	var PaginationControl *string

	for {
		ListTasks, err := m.ECSClient.ListTasks(
			context.TODO(),
			&(ecs.ListTasksInput{
				ServiceName: service,
				Cluster:     clusterArn,
				NextToken:   PaginationControl,
			}),
			func(o *ecs.Options) {
				o.Region = region
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		for _, task := range ListTasks.TaskArns {
			tasks = append(tasks, task)
		}

		if ListTasks.NextToken != nil {
			PaginationControl = ListTasks.NextToken
		} else {
			PaginationControl = nil
			break
		}
	}
	return tasks
}

func (m *NetworkPortsModule) describeECSTask(task string, clusterArn *string, region string) (*ecs_types.Task, error) {
	var result ecs_types.Task

	DescribeTasks, err := m.ECSClient.DescribeTasks(
		context.TODO(),
		&(ecs.DescribeTasksInput{
			Tasks:   []string{task},
			Cluster: clusterArn,
		}),
		func(o *ecs.Options) {
			o.Region = region
		},
	)
	if err != nil {
		return nil, err
	}

	if len(DescribeTasks.Tasks) != 1 {
		return nil, errors.New(fmt.Sprintf("Service not found: %s", task))
	} else {
		result = DescribeTasks.Tasks[0]
	}

	return &result, nil
}

func (m *NetworkPortsModule) getEFSSharesPerRegion(region string) []efs_types.FileSystemDescription {
	var shares []efs_types.FileSystemDescription
	var PaginationControl *string

	for {
		DescribeFileSystems, err := m.EFSClient.DescribeFileSystems(
			context.TODO(),
			&(efs.DescribeFileSystemsInput{
				Marker: PaginationControl,
			}),
			func(o *efs.Options) {
				o.Region = region
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		for _, fs := range DescribeFileSystems.FileSystems {
			shares = append(shares, fs)
		}

		if DescribeFileSystems.Marker != nil {
			PaginationControl = DescribeFileSystems.Marker
		} else {
			PaginationControl = nil
			break
		}
	}

	return shares
}

func (m *NetworkPortsModule) getEFSMountTargetsPerRegion(filesystem *string, region string) []efs_types.MountTargetDescription {
	var targets []efs_types.MountTargetDescription
	var PaginationControl *string

	for {
		DescribeMountTargets, err := m.EFSClient.DescribeMountTargets(
			context.TODO(),
			&(efs.DescribeMountTargetsInput{
				FileSystemId: filesystem,
				Marker:       PaginationControl,
			}),
			func(o *efs.Options) {
				o.Region = region
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		for _, target := range DescribeMountTargets.MountTargets {
			targets = append(targets, target)
		}

		if DescribeMountTargets.Marker != nil {
			PaginationControl = DescribeMountTargets.Marker
		} else {
			PaginationControl = nil
			break
		}
	}

	return targets
}

func (m *NetworkPortsModule) getElastiCacheClustersPerRegion(region string) []elasticache_types.CacheCluster {
	var clusters []elasticache_types.CacheCluster
	var PaginationControl *string

	for {
		DescribeCacheClusters, err := m.ElastiCacheClient.DescribeCacheClusters(
			context.TODO(),
			&(elasticache.DescribeCacheClustersInput{
				Marker: PaginationControl,
			}),
			func(o *elasticache.Options) {
				o.Region = region
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		for _, cluster := range DescribeCacheClusters.CacheClusters {
			clusters = append(clusters, cluster)
		}

		if DescribeCacheClusters.Marker != nil {
			PaginationControl = DescribeCacheClusters.Marker
		} else {
			PaginationControl = nil
			break
		}
	}

	return clusters
}

func (m *NetworkPortsModule) getElastiCacheSubnetGroupsPerRegion(region string) []elasticache_types.CacheSubnetGroup {
	var groups []elasticache_types.CacheSubnetGroup
	var PaginationControl *string

	for {
		DescribeCacheSubnetGroups, err := m.ElastiCacheClient.DescribeCacheSubnetGroups(
			context.TODO(),
			&(elasticache.DescribeCacheSubnetGroupsInput{
				Marker: PaginationControl,
			}),
			func(o *elasticache.Options) {
				o.Region = region
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		for _, group := range DescribeCacheSubnetGroups.CacheSubnetGroups {
			groups = append(groups, group)
		}

		if DescribeCacheSubnetGroups.Marker != nil {
			PaginationControl = DescribeCacheSubnetGroups.Marker
		} else {
			PaginationControl = nil
			break
		}
	}

	return groups
}

func (m *NetworkPortsModule) getElastiCacheReplicationGroupsPerRegion(region string) []elasticache_types.ReplicationGroup {
	var groups []elasticache_types.ReplicationGroup
	var PaginationControl *string

	for {
		DescribeCacheReplicationGroups, err := m.ElastiCacheClient.DescribeReplicationGroups(
			context.TODO(),
			&(elasticache.DescribeReplicationGroupsInput{
				Marker: PaginationControl,
			}),
			func(o *elasticache.Options) {
				o.Region = region
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		for _, group := range DescribeCacheReplicationGroups.ReplicationGroups {
			groups = append(groups, group)
		}

		if DescribeCacheReplicationGroups.Marker != nil {
			PaginationControl = DescribeCacheReplicationGroups.Marker
		} else {
			PaginationControl = nil
			break
		}
	}

	return groups
}

func (m *NetworkPortsModule) getLightsailInstancesPerRegion(region string) []lightsail_types.Instance {
	var instances []lightsail_types.Instance
	var PaginationControl *string

	for {
		GetInstances, err := m.LightsailClient.GetInstances(
			context.TODO(),
			&(lightsail.GetInstancesInput{
				PageToken: PaginationControl,
			}),
			func(o *lightsail.Options) {
				o.Region = region
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		for _, instance := range GetInstances.Instances {
			instances = append(instances, instance)
		}

		if GetInstances.NextPageToken != nil {
			PaginationControl = GetInstances.NextPageToken
		} else {
			PaginationControl = nil
			break
		}
	}

	return instances
}

func (m *NetworkPortsModule) getLoadBalancersPerRegion(region string) []elbv2_types.LoadBalancer {
	var PaginationControl *string
	var lbs []elbv2_types.LoadBalancer

	for {
		DescribeLoadBalancers, err := m.ELBv2Client.DescribeLoadBalancers(
			context.TODO(),
			&elasticloadbalancingv2.DescribeLoadBalancersInput{
				Marker: PaginationControl,
			},
			func(o *elasticloadbalancingv2.Options) {
				o.Region = region
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		for _, lb := range DescribeLoadBalancers.LoadBalancers {
			lbs = append(lbs, lb)
		}

		if DescribeLoadBalancers.NextMarker != nil {
			PaginationControl = DescribeLoadBalancers.NextMarker
		} else {
			PaginationControl = nil
			break
		}
	}

	return lbs
}

func (m *NetworkPortsModule) getLBListenerPorts(arn *string, region string) ([]int32, []int32) {
	var PaginationControl *string
	var tcpPorts, udpPorts []int32

	for {
		DescribeListeners, err := m.ELBv2Client.DescribeListeners(
			context.TODO(),
			&elasticloadbalancingv2.DescribeListenersInput{
				LoadBalancerArn: arn,
				Marker:          PaginationControl,
			},
			func(o *elasticloadbalancingv2.Options) {
				o.Region = region
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		for _, listener := range DescribeListeners.Listeners {
			port := aws.ToInt32(listener.Port)
			switch listener.Protocol {
			case elbv2_types.ProtocolEnumHttp, elbv2_types.ProtocolEnumHttps, elbv2_types.ProtocolEnumTcp, elbv2_types.ProtocolEnumTls:
				{
					tcpPorts = addPort(tcpPorts, port)
				}
			case elbv2_types.ProtocolEnumUdp:
				{
					udpPorts = addPort(udpPorts, port)
				}
			case elbv2_types.ProtocolEnumTcpUdp:
				{
					tcpPorts = addPort(tcpPorts, port)
					udpPorts = addPort(udpPorts, port)
				}
			}
		}

		if DescribeListeners.NextMarker != nil {
			PaginationControl = DescribeListeners.NextMarker
		} else {
			PaginationControl = nil
			break
		}
	}

	return tcpPorts, udpPorts
}

func (m *NetworkPortsModule) getRdsClustersPerRegion(region string) []rds_types.DBCluster {
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

		if DescribeDBClusters.Marker != nil {
			PaginationControl = DescribeDBClusters.Marker
		} else {
			PaginationControl = nil
			break
		}
	}

	return clusters
}

func (m *NetworkPortsModule) getRdsInstancesPerRegion(region string) []rds_types.DBInstance {
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

		if DescribeDBInstances.Marker != nil {
			PaginationControl = DescribeDBInstances.Marker
		} else {
			PaginationControl = nil
			break
		}
	}

	return instances
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

type portNode struct {
	prev *portNode
	next *portNode
	rule NaclRule
}

func (l *NetworkAcl) Insert(rule NaclRule) {
	list := &portNode{
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
				fmt.Printf("[%s][%s] Protocol: %s not supported\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), node.rule.Protocol)
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
