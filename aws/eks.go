package aws

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/BishopFox/cloudfox/console"
	"github.com/BishopFox/cloudfox/utils"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/eks/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/bishopfox/awsservicemap"
	"github.com/sirupsen/logrus"
)

type EKSModule struct {
	// General configuration data
	// These interfaces are used for unit testing
	EKSClientListClustersInterface      eks.ListClustersAPIClient
	EKSClientDescribeClusterInterface   eks.DescribeClusterAPIClient
	EKSClientListNodeGroupsInterface    eks.ListNodegroupsAPIClient
	EKSClientDescribeNodeGroupInterface eks.DescribeNodegroupAPIClient
	IAMSimulatePrincipalPolicyClient    iam.SimulatePrincipalPolicyAPIClient

	Caller         sts.GetCallerIdentityOutput
	AWSRegions     []string
	OutputFormat   string
	Goroutines     int
	AWSProfile     string
	SkipAdminCheck bool
	WrapTable      bool
	pmapperMod     PmapperModule
	pmapperError   error
	iamSimClient   IamSimulatorModule
	// Main module data
	Clusters       []Cluster
	CommandCounter console.CommandCounter
	// Used to store output data for pretty printing
	output utils.OutputData2
	modLog *logrus.Entry
}

type Cluster struct {
	AWSService string
	Region     string
	Name       string
	Endpoint   string
	Public     string
	OIDC       string
	NodeGroup  string
	NodeRole   string
	Admin      string
	CanPrivEsc string
}

func (m *EKSModule) EKS(outputFormat string, outputDirectory string, verbosity int) {
	// These stuct values are used by the output module
	m.output.Verbosity = verbosity
	m.output.Directory = outputDirectory
	m.output.CallingModule = "eks"
	localAdminMap := make(map[string]bool)

	m.modLog = utils.TxtLog.WithFields(logrus.Fields{
		"module": m.output.CallingModule,
	})
	if m.AWSProfile == "" {
		m.AWSProfile = utils.BuildAWSPath(m.Caller)
	}

	fmt.Printf("[%s][%s] Enumerating EKS clusters for account %s.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), aws.ToString(m.Caller.Account))
	// Initialized the tools we'll need to check if any workload roles are admin or can privesc to admin
	fmt.Printf("[%s][%s] Attempting to build a PrivEsc graph in memory using local pmapper data if it exists on the filesystem.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	m.pmapperMod, m.pmapperError = initPmapperGraph(m.Caller, m.AWSProfile, m.Goroutines)
	m.iamSimClient = initIAMSimClient(m.IAMSimulatePrincipalPolicyClient, m.Caller, m.AWSProfile, m.Goroutines)

	if m.pmapperError != nil {
		fmt.Printf("[%s][%s] No pmapper data found for this account. Using cloudfox's iam-simulator for role analysis.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	} else {
		fmt.Printf("[%s][%s] Found pmapper data for this account. Using it for role analysis.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	}
	wg := new(sync.WaitGroup)
	semaphore := make(chan struct{}, m.Goroutines)

	// Create a channel to signal the spinner aka task status goroutine to finish
	spinnerDone := make(chan bool)
	//fire up the the task status spinner/updated
	go console.SpinUntil(m.output.CallingModule, &m.CommandCounter, spinnerDone, "regions")

	//create a channel to receive the objects
	dataReceiver := make(chan Cluster)

	go m.Receiver(dataReceiver)

	for _, region := range m.AWSRegions {
		wg.Add(1)
		m.CommandCounter.Pending++
		go m.executeChecks(region, wg, semaphore, dataReceiver)

	}

	wg.Wait()

	// Perform role analysis
	if m.pmapperError == nil {
		for i := range m.Clusters {
			m.Clusters[i].Admin, m.Clusters[i].CanPrivEsc = GetPmapperResults(m.SkipAdminCheck, m.pmapperMod, &m.Clusters[i].NodeRole)
		}
	} else {
		for i := range m.Clusters {
			m.Clusters[i].Admin, m.Clusters[i].CanPrivEsc = GetIamSimResult(m.SkipAdminCheck, &m.Clusters[i].NodeRole, m.iamSimClient, localAdminMap)
		}
	}

	// Send a message to the spinner goroutine to close the channel and stop
	spinnerDone <- true
	<-spinnerDone
	close(dataReceiver)

	// add - if struct is not empty do this. otherwise, dont write anything.
	m.output.Headers = []string{
		"Service",
		"Region",
		"Name",
		//"Endpoint",
		"Public",
		//"OIDC",
		"NodeGroup",
		"NodeRole",
		"isAdminRole?",
		"CanPrivEscToAdmin?",
	}

	// Table rows
	for i := range m.Clusters {
		m.output.Body = append(
			m.output.Body,
			[]string{
				m.Clusters[i].AWSService,
				m.Clusters[i].Region,
				m.Clusters[i].Name,
				//m.Clusters[i].Endpoint,
				m.Clusters[i].Public,
				//m.Clusters[i].OIDC,
				m.Clusters[i].NodeGroup,
				m.Clusters[i].NodeRole,
				m.Clusters[i].Admin,
				m.Clusters[i].CanPrivEsc,
			},
		)

	}

	var seen []string
	for _, cluster := range m.Clusters {
		if !utils.Contains(cluster.Name, seen) {
			seen = append(seen, cluster.Name)
		}
	}

	if len(m.output.Body) > 0 {
		m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", m.AWSProfile)
		//m.output.OutputSelector(outputFormat)
		//utils.OutputSelector(verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.CallingModule, m.output.CallingModule)
		utils.OutputSelector(verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.CallingModule, m.output.CallingModule, m.WrapTable)
		m.writeLoot(m.output.FilePath, verbosity)
		fmt.Printf("[%s][%s] %d clusters with a total of %d node groups found.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), len(seen), len(m.output.Body))
	} else {
		fmt.Printf("[%s][%s] No clusters found, skipping the creation of an output file.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	}

}

func (m *EKSModule) executeChecks(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Cluster) {
	defer wg.Done()

	servicemap := &awsservicemap.AwsServiceMap{
		JsonFileSource: "EMBEDDED_IN_PACKAGE",
	}
	res, err := servicemap.IsServiceInRegion("eks", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		m.getEKSRecordsPerRegion(r, wg, semaphore, dataReceiver)
	}
}

func (m *EKSModule) Receiver(receiver chan Cluster) {
	for data := range receiver {
		m.Clusters = append(m.Clusters, data)

	}
}

func (m *EKSModule) writeLoot(outputDirectory string, verbosity int) {
	path := filepath.Join(outputDirectory, "loot")
	err := os.MkdirAll(path, os.ModePerm)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
	}
	pullFile := filepath.Join(path, "eks-kubeconfig-commands.txt")

	var out string
	out = out + fmt.Sprintln("#############################################")
	out = out + fmt.Sprintln("# The profile you will use to perform these commands is most likely not the profile you used to run CloudFox")
	out = out + fmt.Sprintln("# Set the $profile environment variable to the profile you are going to use to inspect the repositories.")
	out = out + fmt.Sprintln("# E.g., export profile=found_creds")
	out = out + fmt.Sprintln("#############################################")
	out = out + fmt.Sprintln("")

	var seen []string
	for _, cluster := range m.Clusters {

		if !utils.Contains(cluster.Name, seen) {
			out = out + fmt.Sprintf("aws --profile $profile --region %s eks update-kubeconfig --name %s\n", cluster.Region, cluster.Name)
			seen = append(seen, cluster.Name)
		}

	}
	err = os.WriteFile(pullFile, []byte(out), 0644)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
	}

	if verbosity > 2 {
		fmt.Println()
		fmt.Printf("[%s][%s] %s \n", cyan(m.output.CallingModule), cyan(m.AWSProfile), green("Use the commands below to authenticate to EKS and set up your kubeconfig"))
		fmt.Printf("[%s][%s] %s \n\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), green("Note: Just because you have the eks:updatekubeconfig permission, this does not"))
		fmt.Printf("[%s][%s] %s \n\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), green("     mean your IAM user has permissions in the cluster."))

		fmt.Print(out)
		fmt.Printf("[%s][%s] %s \n\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), green("End of loot file."))
	}

	fmt.Printf("[%s][%s] Loot written to [%s]\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), pullFile)

}

func (m *EKSModule) getEKSRecordsPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Cluster) {
	defer func() {
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
		wg.Done()

	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	var clusters []string
	var role string

	clusters, err := m.listClusters(r)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
	}

	for _, clusterName := range clusters {
		clusterDetails, err := m.describeCluster(clusterName, r)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
		}

		//nodeGroups = append(nodeGroups, DescribeCluster.Cluster.)
		endpoint := aws.ToString(clusterDetails.Endpoint)
		oidc := aws.ToString(clusterDetails.Identity.Oidc.Issuer)
		publicEndpoint := strconv.FormatBool(clusterDetails.ResourcesVpcConfig.EndpointPublicAccess)
		// if DescribeCluster.Cluster.ResourcesVpcConfig.PublicAccessCidrs[0] == "0.0.0.0/0" {
		// 	publicCIDRs := "0.0.0.0/0"
		// } else {
		// 	publicCIDRs := "specific IPs"
		// }

		ListNodeGroups := m.listNodeGroups(clusterName, r)

		for _, nodeGroup := range ListNodeGroups {

			nodeGroupDetails, err := m.describeNodegroup(clusterName, nodeGroup, r)
			if err != nil {
				m.modLog.Error(err.Error())
				m.CommandCounter.Error++
			}

			role = aws.ToString(nodeGroupDetails.NodeRole)

			dataReceiver <- Cluster{
				AWSService: "EKS",
				Name:       clusterName,
				Region:     r,
				Endpoint:   endpoint,
				Public:     publicEndpoint,
				OIDC:       oidc,
				NodeGroup:  nodeGroup,
				NodeRole:   role,
				Admin:      "",
				CanPrivEsc: "",
			}
		}

	}

}

func (m *EKSModule) listClusters(r string) ([]string, error) {
	var PaginationControl *string
	var clusters []string

	for {
		ListClusters, err := m.EKSClientListClustersInterface.ListClusters(
			context.TODO(),
			&eks.ListClustersInput{
				NextToken: PaginationControl,
			},
			func(o *eks.Options) {
				o.Region = r
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			return clusters, err
		}

		clusters = append(clusters, ListClusters.Clusters...)
		// The "NextToken" value is nil when there's no more data to return.
		if ListClusters.NextToken != nil {
			PaginationControl = ListClusters.NextToken
		} else {
			PaginationControl = nil
			break
		}

	}
	return clusters, nil
}

func (m *EKSModule) listNodeGroups(clusterName string, r string) []string {
	var PaginationControl *string
	var nodeGroups []string
	for {
		ListNodeGroups, err := m.EKSClientListNodeGroupsInterface.ListNodegroups(
			context.TODO(),
			&eks.ListNodegroupsInput{
				ClusterName: &clusterName,
				NextToken:   PaginationControl,
			},
			func(o *eks.Options) {
				o.Region = r
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		if ListNodeGroups.NextToken != nil {
			nodeGroups = append(nodeGroups, ListNodeGroups.Nodegroups...)
			PaginationControl = ListNodeGroups.NextToken
		} else {
			nodeGroups = append(nodeGroups, ListNodeGroups.Nodegroups...)
			PaginationControl = nil
			break

		}

	}
	return nodeGroups
}

func (m *EKSModule) describeCluster(clusterName string, r string) (*types.Cluster, error) {

	var err error
	//var clusterDetails types.Cluster
	DescribeCluster, err := m.EKSClientDescribeClusterInterface.DescribeCluster(
		context.TODO(),
		&eks.DescribeClusterInput{
			Name: &clusterName,
		},
		func(o *eks.Options) {
			o.Region = r
		},
	)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
	}

	return DescribeCluster.Cluster, err

}

func (m *EKSModule) describeNodegroup(clusterName string, nodeGroup string, r string) (*types.Nodegroup, error) {

	DescribeNodegroup, err := m.EKSClientDescribeNodeGroupInterface.DescribeNodegroup(
		context.TODO(),
		&eks.DescribeNodegroupInput{
			ClusterName:   &clusterName,
			NodegroupName: &nodeGroup,
		},
		func(o *eks.Options) {
			o.Region = r
		},
	)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++

	}
	return DescribeNodegroup.Nodegroup, err
}

func (m *EKSModule) isRoleAdmin(principal *string) bool {
	iamSimMod := IamSimulatorModule{
		IAMSimulatePrincipalPolicyClient: m.IAMSimulatePrincipalPolicyClient,
		Caller:                           m.Caller,
		AWSProfile:                       m.AWSProfile,
		Goroutines:                       m.Goroutines,
	}
	adminCheckResult := iamSimMod.isPrincipalAnAdmin(principal)

	if adminCheckResult {
		return true
	} else {
		return false
	}

}
