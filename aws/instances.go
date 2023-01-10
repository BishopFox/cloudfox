package aws

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamTypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/bishopfox/awsservicemap"
	"github.com/sirupsen/logrus"
)

type InstancesModule struct {
	// General configuration data
	EC2Client                        *ec2.Client
	IAMSimulatePrincipalPolicyClient iam.SimulatePrincipalPolicyAPIClient
	IAMListInstanceProfilesClient    iam.ListInstanceProfilesAPIClient
	Caller                           sts.GetCallerIdentityOutput
	AWSRegions                       []string
	OutputFormat                     string
	Goroutines                       int
	UserDataAttributesOnly           bool
	AWSProfile                       string
	WrapTable                        bool
	InstanceProfileToRolesMap        map[string][]iamTypes.Role
	SkipAdminCheck                   bool
	pmapperMod                       PmapperModule
	pmapperError                     error
	iamSimClient                     IamSimulatorModule

	// Module's Results
	MappedInstances []MappedInstance
	CommandCounter  internal.CommandCounter

	// Used to store output data for pretty printing
	output internal.OutputData2
	modLog *logrus.Entry
}

type MappedInstance struct {
	ID               string
	Name             string
	Arn              string
	AvailabilityZone string
	State            string
	ExternalIP       string
	PrivateIP        string
	Profile          string
	Admin            string
	Role             string
	Region           string
	CanPrivEsc       string
}

func (m *InstancesModule) Instances(filter string, outputFormat string, outputDirectory string, verbosity int) {
	// These stuct values are used by the output module
	m.output.Verbosity = verbosity
	m.output.Directory = outputDirectory
	m.output.CallingModule = "instances"
	localAdminMap := make(map[string]bool)
	m.modLog = internal.TxtLog.WithFields(logrus.Fields{
		"module": m.output.CallingModule,
	})
	if m.AWSProfile == "" {
		m.AWSProfile = internal.BuildAWSPath(m.Caller)
	}

	// Populate the instance profile to roles map. You can't use getInstanceProfile by name, so the only way to do this is to
	// list all of the profiles, save the data, and then do the lookup yourself.

	// Parses the type of filter being used (file with instances or single instance id)
	var instancesToSearch []string
	if filter == "all" {
		instancesToSearch = []string{"all"}
	} else {
		instancesToSearch = internal.LoadFileLinesIntoArray(filter)
	}

	//Connects to EC2 service and maps instances
	fmt.Printf("[%s][%s] Enumerating EC2 instances in all regions for account %s\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), aws.ToString(m.Caller.Account))

	// Initialized the tools we'll need to check if any workload roles are admin or can privesc to admin
	fmt.Printf("[%s][%s] Attempting to build a PrivEsc graph in memory using local pmapper data if it exists on the filesystem.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	m.pmapperMod, m.pmapperError = initPmapperGraph(m.Caller, m.AWSProfile, m.Goroutines)
	m.iamSimClient = initIAMSimClient(m.IAMSimulatePrincipalPolicyClient, m.Caller, m.AWSProfile, m.Goroutines)

	if m.pmapperError != nil {
		fmt.Printf("[%s][%s] No pmapper data found for this account. Using cloudfox's iam-simulator for role analysis.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	} else {
		fmt.Printf("[%s][%s] Found pmapper data for this account. Using it for role analysis.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	}
	fmt.Printf("[%s][%s] For context and next steps: https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#%s\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), m.output.CallingModule)
	wg := new(sync.WaitGroup)

	// Create a channel to signal the spinner aka task status goroutine to finish
	spinnerDone := make(chan bool)
	//fire up the the task status spinner/updated
	go internal.SpinUntil(m.output.CallingModule, &m.CommandCounter, spinnerDone, "tasks")

	//create a channel to receive the objects
	dataReceiver := make(chan MappedInstance)

	// Create a channel to signal to stop
	receiverDone := make(chan bool)

	go m.Receiver(dataReceiver, receiverDone)
	m.getRolesFromInstanceProfiles()

	for _, region := range m.AWSRegions {
		wg.Add(1)
		m.CommandCounter.Pending++
		go m.executeChecks(instancesToSearch, region, wg, dataReceiver)

	}

	wg.Wait()
	//time.Sleep(time.Second * 2)

	// Perform role analysis
	if m.pmapperError == nil {
		for i := range m.MappedInstances {
			m.MappedInstances[i].Admin, m.MappedInstances[i].CanPrivEsc = GetPmapperResults(m.SkipAdminCheck, m.pmapperMod, &m.MappedInstances[i].Role)
		}
	} else {
		for i := range m.MappedInstances {
			m.MappedInstances[i].Admin, m.MappedInstances[i].CanPrivEsc = GetIamSimResult(m.SkipAdminCheck, &m.MappedInstances[i].Role, m.iamSimClient, localAdminMap)
		}
	}

	// Send a message to the spinner goroutine to close the channel and stop
	spinnerDone <- true
	<-spinnerDone
	receiverDone <- true
	<-receiverDone

	// This conditional block will either dump the userData attribute content or the general instances data, depending on what you select via command line.
	//fmt.Printf("\n[*] Preparing output...\n\n")
	if m.UserDataAttributesOnly {
		m.printInstancesUserDataAttributesOnly(outputFormat, outputDirectory, dataReceiver)
	} else {
		m.printGeneralInstanceData(outputFormat, outputDirectory, dataReceiver)
	}

}

func (m *InstancesModule) Receiver(receiver chan MappedInstance, receiverDone chan bool) {
	defer close(receiverDone)
	for {
		select {
		case data := <-receiver:
			m.MappedInstances = append(m.MappedInstances, data)
		case <-receiverDone:
			receiverDone <- true
			return
		}
	}
}

func (m *InstancesModule) printInstancesUserDataAttributesOnly(outputFormat string, outputDirectory string, dataReceiver chan MappedInstance) {
	defer func() {
		m.output.CallingModule = "instances"
	}()

	m.output.CallingModule = "instance-userdata"
	path := filepath.Join(outputDirectory, "cloudfox-output", "aws", m.AWSProfile, "loot")
	err := os.MkdirAll(path, os.ModePerm)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
	}
	userDataFileName := filepath.Join(path, fmt.Sprintf("%s.txt", m.output.CallingModule))

	var userDataOut string = fmt.Sprintln("=============================================")

	for _, instance := range m.MappedInstances {
		userData, err := m.getInstanceUserDataAttribute(aws.String(instance.ID), instance.Region)
		if err == nil {
			// fmt.Printf("Instance ID: %s\n", instance.ID)
			// fmt.Printf("Region: %s\n", instance.Region)
			// fmt.Printf("Instance Profile: %s\n", instance.Profile)
			// fmt.Printf("User Data: \n%s\n", aws.ToString(userData))
			// fmt.Printf("=============================================\n\n")
			if *userData != "NoUserData" {

				userDataOut = userDataOut + fmt.Sprintf("Instance Arn: %s\n", instance.Arn)
				userDataOut = userDataOut + fmt.Sprintf("Region: %s\n", instance.Region)
				userDataOut = userDataOut + fmt.Sprintf("Instance Profile: %s\n\n", instance.Profile)
				userDataOut = userDataOut + fmt.Sprintf("User Data: \n%s\n", aws.ToString(userData))
				userDataOut = userDataOut + "=============================================\n\n"
			}
		}
	}
	// only create a file if if there is at least one instance AND at least one instance had user-data.
	if (len(m.MappedInstances) > 0) && (userDataOut != "=============================================\n") {
		if m.output.Verbosity > 1 {
			fmt.Printf("%s", userDataOut)
		}
		err = os.WriteFile(userDataFileName, []byte(userDataOut), 0644)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
		}
		fmt.Printf("[%s][%s] Loot written to [%s]\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), userDataFileName)
	} else {
		fmt.Printf("[%s][%s] No user data found, skipping the creation of an output file\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	}
}

func (m *InstancesModule) printGeneralInstanceData(outputFormat string, outputDirectory string, dataReceiver chan MappedInstance) {
	// Prepare Table headers
	//m.output.Headers = table.Row{
	m.output.Headers = []string{
		//"ID",
		"Name",
		//"Arn",
		"ID",
		"Zone",
		"State",
		"External IP",
		"Internal IP",
		"Role",
		"IsAdminRole?",
		"CanPrivEscToAdmin?",
	}
	//Table rows
	for _, instance := range m.MappedInstances {
		m.output.Body = append(
			m.output.Body,
			//table.Row{
			[]string{
				//instance.ID,
				instance.Name,
				//instance.Arn,
				instance.ID,
				instance.AvailabilityZone,
				instance.State,
				instance.ExternalIP,
				instance.PrivateIP,
				instance.Role,
				instance.Admin,
				instance.CanPrivEsc,
			},
		)
	}
	if len(m.output.Body) > 0 {
		m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", m.AWSProfile)
		////m.output.OutputSelector(outputFormat)
		//utils.OutputSelector(m.output.Verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.CallingModule, m.output.CallingModule)
		internal.OutputSelector(m.output.Verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.CallingModule, m.output.CallingModule, m.WrapTable, m.AWSProfile)

		m.writeLoot(m.output.FilePath)
		fmt.Printf("[%s][%s] %s instances found.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), strconv.Itoa(len(m.output.Body)))

	} else {
		fmt.Printf("[%s][%s] No instances found, skipping the creation of an output file.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	}
}

func (m *InstancesModule) writeLoot(outputDirectory string) {
	path := filepath.Join(outputDirectory, "loot")
	err := os.MkdirAll(path, os.ModePerm)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
	}
	privateIPsFilename := filepath.Join(path, "instances-ec2PrivateIPs.txt")
	publicIPsFilename := filepath.Join(path, "instances-ec2PublicIPs.txt")

	var publicIPs string
	var privateIPs string

	for _, instance := range m.MappedInstances {
		if instance.ExternalIP != "NoExternalIP" {
			publicIPs = publicIPs + fmt.Sprintln(instance.ExternalIP)
		}
		if instance.PrivateIP != "" {
			privateIPs = privateIPs + fmt.Sprintln(instance.PrivateIP)
		}

	}
	err = os.WriteFile(privateIPsFilename, []byte(privateIPs), 0644)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
	}
	err = os.WriteFile(publicIPsFilename, []byte(publicIPs), 0644)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
	}

	fmt.Printf("[%s][%s] Loot written to [%s]\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), privateIPsFilename)
	fmt.Printf("[%s][%s] Loot written to [%s]\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), publicIPsFilename)

}

func (m *InstancesModule) executeChecks(instancesToSearch []string, r string, wg *sync.WaitGroup, dataReceiver chan MappedInstance) {
	defer wg.Done()
	servicemap := &awsservicemap.AwsServiceMap{
		JsonFileSource: "EMBEDDED_IN_PACKAGE",
	}
	res, err := servicemap.IsServiceInRegion("ec2", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		m.CommandCounter.Pending--
		m.CommandCounter.Executing++
		m.getDescribeInstances(instancesToSearch, r, dataReceiver)
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}
}

func (m *InstancesModule) getInstanceUserDataAttribute(instanceID *string, region string) (userData *string, err error) {

	Attributes, err := m.EC2Client.DescribeInstanceAttribute(
		context.TODO(),
		&ec2.DescribeInstanceAttributeInput{
			InstanceId: instanceID,
			Attribute:  types.InstanceAttributeName("userData"),
		},
		func(o *ec2.Options) {
			o.Region = region
		},
	)

	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return nil, err
	} else {
		if Attributes.UserData.Value == nil {
			return aws.String("NoUserData"), nil
		} else {
			data, _ := base64.StdEncoding.DecodeString(*Attributes.UserData.Value)
			return aws.String(string(data)), nil
		}
	}

}

func (m *InstancesModule) getDescribeInstances(instancesToSearch []string, region string, dataReceiver chan MappedInstance) {

	// The "PaginationControl" value is nil when there's no more data to return.
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
			accountId := reservation.OwnerId

			for _, instance := range reservation.Instances {

				if instancesToSearch[0] == "all" || internal.Contains(aws.ToString(instance.InstanceId), instancesToSearch) {
					m.loadInstanceData(instance, region, accountId, dataReceiver)
				}
			}
		}

		// The "NextToken" value is nil when there's no more data to return.
		if DescribeInstances.NextToken != nil {
			PaginationControl = DescribeInstances.NextToken
		} else {
			PaginationControl = nil
			break
		}

	}
}

func (m *InstancesModule) loadInstanceData(instance types.Instance, region string, accountId *string, dataReceiver chan MappedInstance) {

	var profile string
	var externalIP string
	var name string = ""
	var adminRole string = ""
	var roleArn string = ""

	// The name is in a tag so we have to do this to grab the value from the right tag
	for _, tag := range instance.Tags {
		if *tag.Key == "Name" {
			name = *tag.Value
		}

	}

	//arn := fmt.Sprintf("arn:aws:ec2:%s:%s:instance/%s", region, aws.ToString(accountId), aws.ToString(instance.InstanceId))

	if instance.PublicIpAddress == nil {
		externalIP = "NoExternalIP"
	} else {
		externalIP = aws.ToString(instance.PublicIpAddress)
	}

	if instance.IamInstanceProfile == nil {
		profile = "NoInstanceProfile"
	} else {
		// This returns only the role name without the preceding forward slash.
		profileARN := aws.ToString(instance.IamInstanceProfile.Arn)
		profileID := aws.ToString(instance.IamInstanceProfile.Id)
		profile = strings.Split(profileARN, "/")[len(strings.Split(profileARN, "/"))-1]

		if roles, ok := m.InstanceProfileToRolesMap[profileID]; ok {
			for _, role := range roles {
				roleArn = aws.ToString(role.Arn)
			}
		}

	}
	dataReceiver <- MappedInstance{
		ID:               aws.ToString(instance.InstanceId),
		Name:             aws.ToString(&name),
		AvailabilityZone: aws.ToString(instance.Placement.AvailabilityZone),
		State:            string(instance.State.Name),
		ExternalIP:       externalIP,
		PrivateIP:        aws.ToString(instance.PrivateIpAddress),
		Profile:          profile,
		Role:             roleArn,
		Region:           region,
		Admin:            adminRole,
		CanPrivEsc:       "",
	}

}

func (m *InstancesModule) getRolesFromInstanceProfiles() {

	// The "PaginationControl" value is nil when there's no more data to return.
	var PaginationMarker *string
	PaginationControl := true
	m.InstanceProfileToRolesMap = map[string][]iamTypes.Role{}

	for PaginationControl {
		ListInstanceProfiles, err := m.IAMListInstanceProfilesClient.ListInstanceProfiles(
			context.TODO(),
			&(iam.ListInstanceProfilesInput{
				Marker: PaginationMarker,
			}),
		)

		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}
		for _, instanceProfile := range ListInstanceProfiles.InstanceProfiles {
			m.InstanceProfileToRolesMap[aws.ToString(instanceProfile.InstanceProfileId)] = instanceProfile.Roles
		}
		if aws.ToString(ListInstanceProfiles.Marker) != "" {
			PaginationMarker = ListInstanceProfiles.Marker
		} else {
			PaginationMarker = nil
			break
		}
	}

}
