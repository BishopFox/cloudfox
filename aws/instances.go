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

	"github.com/BishopFox/cloudfox/aws/sdk"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamTypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/bishopfox/awsservicemap"
	"github.com/sirupsen/logrus"
)

type InstancesModule struct {
	// General configuration data
	EC2Client     sdk.AWSEC2ClientInterface
	IAMClient     sdk.AWSIAMClientInterface
	Caller        sts.GetCallerIdentityOutput
	AWSRegions    []string
	AWSOutputType string
	AWSTableCols  string

	Goroutines                int
	UserDataAttributesOnly    bool
	AWSProfile                string
	WrapTable                 bool
	InstanceProfileToRolesMap map[string][]iamTypes.Role
	SkipAdminCheck            bool
	pmapperMod                PmapperModule
	pmapperError              error
	iamSimClient              IamSimulatorModule

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

func (m *InstancesModule) Instances(filter string, outputDirectory string, verbosity int) {
	// These struct values are used by the output module
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
	//fmt.Printf("[%s][%s] Attempting to build a PrivEsc graph in memory using local pmapper data if it exists on the filesystem.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	m.pmapperMod, m.pmapperError = initPmapperGraph(m.Caller, m.AWSProfile, m.Goroutines)
	m.iamSimClient = initIAMSimClient(m.IAMClient, m.Caller, m.AWSProfile, m.Goroutines)

	// if m.pmapperError != nil {
	// 	fmt.Printf("[%s][%s] No pmapper data found for this account. Using cloudfox's iam-simulator for role analysis.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	// } else {
	// 	fmt.Printf("[%s][%s] Found pmapper data for this account. Using it for role analysis.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	// }
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
		m.printInstancesUserDataAttributesOnly(outputDirectory, dataReceiver)
	} else {
		m.printGeneralInstanceData(outputDirectory, dataReceiver, verbosity)
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

func (m *InstancesModule) printInstancesUserDataAttributesOnly(outputDirectory string, dataReceiver chan MappedInstance) {
	defer func() {
		m.output.CallingModule = "instances"
	}()

	m.output.CallingModule = "instance-userdata"
	path := filepath.Join(outputDirectory, "cloudfox-output", "aws", fmt.Sprintf("%s-%s", m.AWSProfile, aws.ToString(m.Caller.Account)), "loot")
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
		if m.output.Verbosity > 2 {
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

func (m *InstancesModule) printGeneralInstanceData(outputDirectory string, dataReceiver chan MappedInstance, verbosity int) {
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

	// If the user specified table columns, use those.
	// If the user specified -o wide, use the wide default cols for this module.
	// Otherwise, use the hardcoded default cols for this module.
	var tableCols []string
	// If the user specified table columns, use those.
	if m.AWSTableCols != "" {
		// If the user specified wide as the output format, use these columns.
		// remove any spaces between any commans and the first letter after the commas
		m.AWSTableCols = strings.ReplaceAll(m.AWSTableCols, ", ", ",")
		m.AWSTableCols = strings.ReplaceAll(m.AWSTableCols, ",  ", ",")
		tableCols = strings.Split(m.AWSTableCols, ",")
		// If the user specified wide as the output format, use these columns.
	} else if m.AWSOutputType == "wide" {
		tableCols = []string{
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
		// Otherwise, use the default columns.
	} else {
		tableCols = []string{
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
	}

	// Remove the pmapper row if there is no pmapper data
	if m.pmapperError != nil {
		sharedLogger.Errorf("%s - %s - No pmapper data found for this account. Skipping the pmapper column in the output table.", m.output.CallingModule, m.AWSProfile)
		tableCols = removeStringFromSlice(tableCols, "CanPrivEscToAdmin?")
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
		m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", fmt.Sprintf("%s-%s", m.AWSProfile, aws.ToString(m.Caller.Account)))

		//m.writeLoot(m.output.FilePath)
		o := internal.OutputClient{
			Verbosity:     verbosity,
			CallingModule: m.output.CallingModule,
			Table: internal.TableClient{
				Wrap: m.WrapTable,
			},
		}
		o.Table.TableFiles = append(o.Table.TableFiles, internal.TableFile{
			Header:    m.output.Headers,
			Body:      m.output.Body,
			TableCols: tableCols,
			Name:      m.output.CallingModule,
		})
		o.PrefixIdentifier = m.AWSProfile
		o.Table.DirectoryName = filepath.Join(outputDirectory, "cloudfox-output", "aws", fmt.Sprintf("%s-%s", m.AWSProfile, aws.ToString(m.Caller.Account)))
		o.WriteFullOutput(o.Table.TableFiles, nil)
		m.writeLoot(o.Table.DirectoryName, verbosity)
		fmt.Printf("[%s][%s] %s instances found.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), strconv.Itoa(len(m.output.Body)))

	} else {
		fmt.Printf("[%s][%s] No instances found, skipping the creation of an output file.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	}
}

func (m *InstancesModule) writeLoot(outputDirectory string, verbosity int) {
	path := filepath.Join(outputDirectory, "loot")
	err := os.MkdirAll(path, os.ModePerm)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
	}
	privateIPsFilename := filepath.Join(path, "instances-ec2PrivateIPs.txt")
	publicIPsFilename := filepath.Join(path, "instances-ec2PublicIPs.txt")
	ssmCommandsFilename := filepath.Join(path, "instances-ssmCommands.txt")
	ec2InstanceConnectCommandsFilename := filepath.Join(path, "instances-ec2InstanceConnectCommands.txt")

	var publicIPs string
	var privateIPs string
	var ssmCommands string
	var ec2InstanceConnectCommands string
	var headlineName string

	for _, instance := range m.MappedInstances {
		if instance.ExternalIP != "NoExternalIP" {
			publicIPs = publicIPs + fmt.Sprintln(instance.ExternalIP)
		}
		if instance.PrivateIP != "" {
			privateIPs = privateIPs + fmt.Sprintln(instance.PrivateIP)
		}

		if instance.Name != "" {
			headlineName = fmt.Sprintf("%s/%s", instance.Name, instance.ID)
		} else {
			headlineName = fmt.Sprintf("%s", instance.ID)
		}

		ssmCommands = ssmCommands + fmt.Sprintf("-----------------------------------------------------------------------\n")
		ssmCommands = ssmCommands + fmt.Sprintf("############## Instance: %s  ##############\n", headlineName)
		ssmCommands = ssmCommands + fmt.Sprintf("-----------------------------------------------------------------------\n")

		ssmCommands = ssmCommands + fmt.Sprintf("### SSM start-session to %s ###\n", headlineName)
		ssmCommands = ssmCommands + fmt.Sprintf("# You'll need the AWS CLI session manager plugin installed: https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html\n")
		ssmCommands = ssmCommands + fmt.Sprintf("aws --profile $profile --region %s ssm start-session --target %s\n\n", instance.Region, instance.ID)
		ssmCommands = ssmCommands + fmt.Sprintf("### SSM send-command to %s ###\n", headlineName)
		ssmCommands = ssmCommands + fmt.Sprintf("# If you just want to run one command you can use send-command, but really, start-session is way easier\n")
		ssmCommands = ssmCommands + fmt.Sprintf("aws --profile $profile --region %s ssm send-command --instance-ids %s --document-name AWS-RunShellScript --parameters commands=\"aws sts get-caller-identity\" \n", instance.Region, instance.ID)
		ssmCommands = ssmCommands + fmt.Sprintf("aws --profile $profile --region %s ssm get-command-invocation --output text --instance-id %s --command-id <command-id-from-previous-command>\n\n", instance.Region, instance.ID)

		ec2InstanceConnectCommands = ec2InstanceConnectCommands + fmt.Sprintf("-----------------------------------------------------------------------\n")
		ec2InstanceConnectCommands = ec2InstanceConnectCommands + fmt.Sprintf("############## Instance: %s  ##############\n", headlineName)
		ec2InstanceConnectCommands = ec2InstanceConnectCommands + fmt.Sprintf("-----------------------------------------------------------------------\n")

		ec2InstanceConnectCommands = ec2InstanceConnectCommands + fmt.Sprintf("### EC2 Instance Connect to %s ###\n", instance.ID)
		ec2InstanceConnectCommands = ec2InstanceConnectCommands + fmt.Sprintf("# You'll need to change the --instance-os-user and --ssh-public-key parameters to match your own setup\n")
		ec2InstanceConnectCommands = ec2InstanceConnectCommands + fmt.Sprintf("aws --profile $profile --region %s ec2-instance-connect send-ssh-public-key --instance-id %s --instance-os-user ec2-user --ssh-public-key file://~/.ssh/id_rsa.pub\n\n", instance.Region, instance.ID)

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
	err = os.WriteFile(ssmCommandsFilename, []byte(ssmCommands), 0644)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
	}
	err = os.WriteFile(ec2InstanceConnectCommandsFilename, []byte(ec2InstanceConnectCommands), 0644)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
	}

	fmt.Printf("[%s][%s] Loot written to [%s]\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), privateIPsFilename)
	fmt.Printf("[%s][%s] Loot written to [%s]\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), publicIPsFilename)
	fmt.Printf("[%s][%s] Loot written to [%s]\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), ssmCommandsFilename)
	fmt.Printf("[%s][%s] Loot written to [%s]\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), ec2InstanceConnectCommandsFilename)

	if verbosity > 2 {
		fmt.Println()
		fmt.Printf("[%s][%s] %s \n\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), green("Loot file for instance command:"))
		fmt.Printf("Private IPs:\n\n")
		fmt.Print(privateIPs)
		fmt.Printf("Public IPs:\n\n")
		fmt.Print(publicIPs)
		fmt.Printf("SSM Commands:\n\n")
		fmt.Print(ssmCommands)
		fmt.Printf("EC2 Instance Connect Commands:\n\n")
		fmt.Print(ec2InstanceConnectCommands)
		fmt.Printf("[%s][%s] %s \n\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), green("End of loot file."))
	}

}

func (m *InstancesModule) executeChecks(instancesToSearch []string, r string, wg *sync.WaitGroup, dataReceiver chan MappedInstance) {
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
		m.CommandCounter.Pending--
		m.CommandCounter.Executing++
		m.getDescribeInstances(instancesToSearch, r, dataReceiver)
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
	}
}

func (m *InstancesModule) getInstanceUserDataAttribute(instanceID *string, region string) (userData *string, err error) {
	UserData, err := sdk.CachedEC2DescribeInstanceAttributeUserData(m.EC2Client, aws.ToString(m.Caller.Account), region, aws.ToString(instanceID))

	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return nil, err
	} else {
		if UserData == "" {
			return aws.String("NoUserData"), nil
		} else {
			data, _ := base64.StdEncoding.DecodeString(UserData)
			return aws.String(string(data)), nil
		}
	}

}

func (m *InstancesModule) getDescribeInstances(instancesToSearch []string, region string, dataReceiver chan MappedInstance) {

	// The "PaginationControl" value is nil when there's no more data to return.

	Instances, err := sdk.CachedEC2DescribeInstances(m.EC2Client, aws.ToString(m.Caller.Account), region)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	for _, instance := range Instances {
		if instancesToSearch[0] == "all" || internal.Contains(aws.ToString(instance.InstanceId), instancesToSearch) {
			m.loadInstanceData(instance, region, dataReceiver)
		}
	}
}

func (m *InstancesModule) loadInstanceData(instance types.Instance, region string, dataReceiver chan MappedInstance) {

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
		Arn:              fmt.Sprintf("arn:aws:ec2:%s:%s:instance/%s", region, aws.ToString(m.Caller.Account), aws.ToString(instance.InstanceId)),
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
		ListInstanceProfiles, err := m.IAMClient.ListInstanceProfiles(
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
