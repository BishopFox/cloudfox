package aws

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	"github.com/aws/aws-sdk-go-v2/service/efs/types"
	"github.com/aws/aws-sdk-go-v2/service/fsx"
	fsxTypes "github.com/aws/aws-sdk-go-v2/service/fsx/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/bishopfox/awsservicemap"
	"github.com/fatih/color"
	"github.com/sirupsen/logrus"
)

var green = color.New(color.FgGreen).SprintFunc()

type FilesystemsModule struct {
	// General configuration data

	EFSClient *efs.Client
	FSxClient *fsx.Client

	Caller       sts.GetCallerIdentityOutput
	AWSRegions   []string
	OutputFormat string
	Goroutines   int
	AWSProfile   string
	WrapTable    bool

	// Main module data
	Filesystems []FilesystemObject

	Regions        [30]FilesystemObject
	CommandCounter internal.CommandCounter
	// Used to store output data for pretty printing
	output internal.OutputData2
	modLog *logrus.Entry
}

type FilesystemObject struct {
	AWSService  string
	Region      string
	Name        string
	DnsName     string
	IP          string
	Policy      string
	MountTarget string
	Permissions string
}

func (m *FilesystemsModule) PrintFilesystems(outputFormat string, outputDirectory string, verbosity int) {
	// These stuct values are used by the output module
	m.output.Verbosity = verbosity
	m.output.Directory = outputDirectory
	m.output.CallingModule = "filesystems"
	m.modLog = internal.TxtLog.WithFields(logrus.Fields{
		"module": m.output.CallingModule,
	})
	if m.AWSProfile == "" {
		m.AWSProfile = internal.BuildAWSPath(m.Caller)
	}
	//populate region in the filesystems module struct
	for i, region := range m.AWSRegions {
		m.Regions[i].Region = region
	}

	fmt.Printf("[%s][%s] Enumerating filesystems for account %s.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), aws.ToString(m.Caller.Account))
	fmt.Printf("[%s][%s] Supported Services: EFS, FSx \n", cyan(m.output.CallingModule), cyan(m.AWSProfile))

	wg := new(sync.WaitGroup)
	semaphore := make(chan struct{}, m.Goroutines)

	// Create a channel to signal the spinner aka task status goroutine to finish
	spinnerDone := make(chan bool)
	//fire up the the task status spinner/updated
	go internal.SpinUntil(m.output.CallingModule, &m.CommandCounter, spinnerDone, "tasks")

	//create a channel to receive the objects
	dataReceiver := make(chan FilesystemObject)

	// Create a channel to signal to stop
	receiverDone := make(chan bool)

	go m.Receiver(dataReceiver, receiverDone)

	//execute regional checks

	for _, region := range m.AWSRegions {
		wg.Add(1)
		m.executeChecks(region, wg, semaphore, dataReceiver)
	}

	wg.Wait()
	//time.Sleep(time.Second * 2)

	// Send a message to the spinner goroutine to close the channel and stop
	spinnerDone <- true
	<-spinnerDone
	receiverDone <- true
	<-receiverDone

	sort.Slice(m.Filesystems, func(i, j int) bool {
		return m.Filesystems[i].AWSService < m.Filesystems[j].AWSService
	})

	m.output.Headers = []string{
		"Service",
		"Region",
		"Name",
		"DNS Name",
		//"IP",
		"Mount Target",
		"Policy",
		"Permissions",
	}

	// Table rows
	for i := range m.Filesystems {
		m.output.Body = append(
			m.output.Body,
			[]string{
				m.Filesystems[i].AWSService,
				m.Filesystems[i].Region,
				m.Filesystems[i].Name,
				m.Filesystems[i].DnsName,
				//m.Filesystems[i].IP,
				m.Filesystems[i].MountTarget,
				m.Filesystems[i].Policy,
				m.Filesystems[i].Permissions,
			},
		)

	}
	if len(m.output.Body) > 0 {

		m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", m.AWSProfile)
		//m.output.OutputSelector(outputFormat)
		//utils.OutputSelector(verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.CallingModule, m.output.CallingModule)
		internal.OutputSelector(verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.CallingModule, m.output.CallingModule, m.WrapTable, m.AWSProfile)
		m.writeLoot(m.output.FilePath, verbosity)
		fmt.Printf("[%s][%s] %s filesystems found.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), strconv.Itoa(len(m.output.Body)))

	} else {
		fmt.Printf("[%s][%s] No filesystems found, skipping the creation of an output file.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	}
	fmt.Printf("[%s][%s] For context and next steps: https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#%s\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), m.output.CallingModule)
}

func (m *FilesystemsModule) Receiver(receiver chan FilesystemObject, receiverDone chan bool) {

	defer close(receiverDone)
	for {
		select {
		case data := <-receiver:
			m.Filesystems = append(m.Filesystems, data)
		case <-receiverDone:
			receiverDone <- true
			return
		}
	}
}

func (m *FilesystemsModule) executeChecks(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan FilesystemObject) {
	defer wg.Done()
	servicemap := &awsservicemap.AwsServiceMap{
		JsonFileSource: "DOWNLOAD_FROM_AWS",
	}
	res, err := servicemap.IsServiceInRegion("efs", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		wg.Add(1)
		go m.getEFSSharesPerRegion(r, wg, semaphore, dataReceiver)
	}
	//each fsx type has different supported regions so easier to just run this function against all enabled regions.
	wg.Add(1)
	go m.getFSxSharesPerRegion(r, wg, semaphore, dataReceiver)
}

func (m *FilesystemsModule) writeLoot(outputDirectory string, verbosity int) {
	path := filepath.Join(outputDirectory, "loot")
	err := os.MkdirAll(path, os.ModePerm)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
	}
	f := filepath.Join(path, "filesystems-mount-commands.txt")

	var out string

	for i := range m.Filesystems {
		switch m.Filesystems[i].AWSService {
		case "EFS":
			out = out + fmt.Sprintf("##########  Mount instructions for %s - %s ##########\n", m.Filesystems[i].AWSService, m.Filesystems[i].Name)
			out = out + fmt.Sprintf("mkdir -p /efs%s/\n", m.Filesystems[i].MountTarget)
			out = out + fmt.Sprintf("sudo mount -t nfs -o nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,noresvport %s:/ /efs%s\n\n", m.Filesystems[i].DnsName, m.Filesystems[i].MountTarget)
		case "FSx [LUSTRE]":
			out = out + fmt.Sprintf("##########  Mount instructions for %s - %s ##########\n", m.Filesystems[i].AWSService, m.Filesystems[i].Name)
			out = out + fmt.Sprintln("#sudo amazon-linux-extras install -y lustre2.10")
			out = out + fmt.Sprintf("mkdir -p /fsx-lustre/%s/\n", m.Filesystems[i].MountTarget)
			out = out + fmt.Sprintf("sudo mount -t lustre -o noatime,flock %s@tcp:/%s /fsx-lustre/%s/\n\n", m.Filesystems[i].DnsName, m.Filesystems[i].MountTarget, m.Filesystems[i].MountTarget)
		case "FSx [OPENZFS]":
			out = out + fmt.Sprintf("##########  Mount instructions for %s - %s ##########\n", m.Filesystems[i].AWSService, m.Filesystems[i].Name)
			out = out + fmt.Sprintf("mkdir -p /fsx-openzfs%s\n", m.Filesystems[i].MountTarget)
			out = out + fmt.Sprintf("sudo mount -t nfs -o nfsvers=4.1 %s:%s /fsx-openzfs%s\n\n", m.Filesystems[i].DnsName, m.Filesystems[i].MountTarget, m.Filesystems[i].MountTarget)
		case "FSx [ONTAP]":
			out = out + fmt.Sprintf("##########  Mount instructions for %s - %s ##########\n", m.Filesystems[i].AWSService, m.Filesystems[i].Name)
			out = out + fmt.Sprintf("mkdir -p /fsx-ontap%s\n", m.Filesystems[i].MountTarget)
			out = out + fmt.Sprintf("sudo mount -t nfs %s:%s /fsx-ontap%s\n\n", m.Filesystems[i].DnsName, m.Filesystems[i].MountTarget, m.Filesystems[i].MountTarget)
		case "FSx [WINDOWS]":
			out = out + fmt.Sprintf("##########  Mount instructions for %s - %s ##########\n", m.Filesystems[i].AWSService, m.Filesystems[i].Name)
			out = out + fmt.Sprintf("crackmapexec smb %s --shares \n", m.Filesystems[i].DnsName)
			out = out + fmt.Sprintf("# mkdir -p /fsx-windows/%s/SHARE-NAME\n", m.Filesystems[i].DnsName)
			out = out + fmt.Sprintf("sudo mount -t cifs //%s/SHARE-NAME /fsx-windows/%s\n\n", m.Filesystems[i].DnsName, m.Filesystems[i].DnsName)
		}

	}

	err = os.WriteFile(f, []byte(out), 0644)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
	}
	fmt.Printf("[%s][%s] Loot written to [%s]\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), f)
	if verbosity > 2 {
		fmt.Println()
		fmt.Printf("[%s][%s] %s \n", cyan(m.output.CallingModule), cyan(m.AWSProfile), green("Use the commands below to try and mount the identified filesystems."))
		fmt.Print(out)
		fmt.Printf("[%s][%s] %s \n\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), green("End of loot file."))
	}

}

func (m *FilesystemsModule) getEFSSharesPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan FilesystemObject) {
	defer func() {
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
		wg.Done()

	}()
	m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	var policy string

	DescribeFileSystems, err := m.describeEFSFilesystems(r)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	for _, filesystem := range DescribeFileSystems {
		name := filesystem.Name
		id := aws.ToString(filesystem.FileSystemId)

		_, err := m.EFSClient.DescribeFileSystemPolicy(
			context.TODO(),
			&efs.DescribeFileSystemPolicyInput{
				FileSystemId: filesystem.FileSystemId,
			},
			func(o *efs.Options) {
				o.Region = r
			},
		)
		if err != nil {
			policy = "Default (No IAM auth)"
		}

		DescribeMountTargets, err := m.describeEFSMountTargets(id, r)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		for _, mountTarget := range DescribeMountTargets {
			ip := *mountTarget.IpAddress
			awsService := "EFS"

			accessPoints, err := m.describeEFSAccessPoints(id, r)
			if err != nil {
				m.modLog.Error(err.Error())
				m.CommandCounter.Error++
				break
			}

			for _, accessPoint := range accessPoints {
				path, permissions := m.getEFSfilesystemPermissions(accessPoint)

				dataReceiver <- FilesystemObject{
					AWSService:  awsService,
					Region:      r,
					Name:        aws.ToString(name),
					DnsName:     ip,
					Policy:      policy,
					MountTarget: path,
					Permissions: permissions,
				}

			}
		}
	}

}

func (m *FilesystemsModule) getFSxSharesPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan FilesystemObject) {
	defer func() {
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
		wg.Done()

	}()
	m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	// "PaginationMarker" is a control variable used for output continuity, as AWS return the output in pages.
	var PaginationMarker *string
	var PaginationMarker2 *string
	var mountTargetId *string
	var name string
	var dnsName string

	// This for loop exits at the end dependeding on whether the output hits its last page (see pagination control block at the end of the loop).
	for {
		DescribeFileSystems, err := m.FSxClient.DescribeFileSystems(
			context.TODO(),
			&fsx.DescribeFileSystemsInput{
				NextToken: PaginationMarker,
			},
			func(o *fsx.Options) {
				o.Region = r
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		for _, filesystem := range DescribeFileSystems.FileSystems {

			// The name is in a tag so we have to do this to grab the value from the right tag
			for _, tag := range filesystem.Tags {
				if *tag.Key == "Name" {
					name = aws.ToString(tag.Value)
				}

			}

			fsType := filesystem.FileSystemType
			id := *filesystem.FileSystemId
			awsService := fmt.Sprintf("FSx [%s]", fsType)

			// For Lustre and windows we get everything we need from the filesystem call.  For the other two we need to get volume info
			switch fsType {
			case "LUSTRE":
				mountTargetId = filesystem.LustreConfiguration.MountName
				dnsName = aws.ToString(filesystem.DNSName)
				dataReceiver <- FilesystemObject{
					AWSService:  awsService,
					Region:      r,
					Name:        name,
					DnsName:     dnsName,
					Policy:      "",
					MountTarget: aws.ToString(mountTargetId),
				}
			case "WINDOWS":
				//mountTargetId = filesystem.WindowsConfiguration.
				dnsName = aws.ToString(filesystem.WindowsConfiguration.PreferredFileServerIp)
				//dnsName = *&filesystem.WindowsConfiguration.PreferredFileServerIp
				dataReceiver <- FilesystemObject{
					AWSService:  awsService,
					Region:      r,
					Name:        name,
					DnsName:     dnsName,
					Policy:      "",
					MountTarget: "",
				}
			}

			// For OpenZFS and ONTAP, we need to get volume specific info
			for {
				DescribeVolumes, err := m.FSxClient.DescribeVolumes(
					context.TODO(),
					&fsx.DescribeVolumesInput{
						Filters: []fsxTypes.VolumeFilter{
							{
								Name:   "file-system-id",
								Values: []string{id},
							}},
						NextToken: PaginationMarker2,
					},
					func(o *fsx.Options) {
						o.Region = r
					},
				)
				if err != nil {
					break
				}
				//				awsService := fmt.Sprintf("FSx [%s]", fsType)
				for _, volume := range DescribeVolumes.Volumes {

					switch fsType {
					case "OPENZFS":
						mountTargetId = volume.OpenZFSConfiguration.VolumePath
						dnsName = aws.ToString(filesystem.DNSName)
						dataReceiver <- FilesystemObject{
							AWSService:  awsService,
							Region:      r,
							Name:        name,
							DnsName:     dnsName,
							Policy:      "",
							MountTarget: aws.ToString(mountTargetId),
						}
					case "ONTAP":
						mountTargetId = volume.OntapConfiguration.JunctionPath
						dnsName = fmt.Sprintf("%s.%s.fsx.%s.amazonaws.com", aws.ToString(volume.OntapConfiguration.StorageVirtualMachineId), aws.ToString(volume.FileSystemId), r)
						dataReceiver <- FilesystemObject{
							AWSService:  awsService,
							Region:      r,
							Name:        name,
							DnsName:     dnsName,
							Policy:      "",
							MountTarget: aws.ToString(mountTargetId),
						}

					}

				}
				if DescribeVolumes.NextToken != nil {
					PaginationMarker2 = DescribeVolumes.NextToken
				} else {
					PaginationMarker2 = nil
					break
				}
			}

		}

		// Pagination control. After the last page of output, the for loop exits.
		if DescribeFileSystems.NextToken != nil {
			PaginationMarker = DescribeFileSystems.NextToken
		} else {
			PaginationMarker = nil
			break
		}
	}

}

func (m *FilesystemsModule) describeEFSFilesystems(r string) ([]types.FileSystemDescription, error) {
	var PaginationMarker *string
	var filesystems []types.FileSystemDescription
	var err error
	for {
		DescribeFileSystems, err := m.EFSClient.DescribeFileSystems(
			context.TODO(),
			&efs.DescribeFileSystemsInput{
				Marker: PaginationMarker,
			},
			func(o *efs.Options) {
				o.Region = r
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			return nil, err
		}

		filesystems = append(filesystems, DescribeFileSystems.FileSystems...)

		// Pagination control. After the last page of output, the for loop exits.
		if DescribeFileSystems.Marker != nil {
			PaginationMarker = DescribeFileSystems.Marker
		} else {
			PaginationMarker = nil
			break
		}
	}
	return filesystems, err
}

func (m *FilesystemsModule) describeEFSMountTargets(filesystemId string, r string) ([]types.MountTargetDescription, error) {
	var PaginationMarker *string
	var mountTargets []types.MountTargetDescription
	var err error
	for {
		DescribeMountTargets, err := m.EFSClient.DescribeMountTargets(
			context.TODO(),
			&efs.DescribeMountTargetsInput{
				FileSystemId: aws.String(filesystemId),
				Marker:       PaginationMarker,
			},
			func(o *efs.Options) {
				o.Region = r
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			return nil, err
		}

		mountTargets = append(mountTargets, DescribeMountTargets.MountTargets...)

		// Pagination control. After the last page of output, the for loop exits.
		if DescribeMountTargets.Marker != nil {
			PaginationMarker = DescribeMountTargets.Marker
		} else {
			PaginationMarker = nil
			break
		}
	}
	return mountTargets, err
}

func (m *FilesystemsModule) describeEFSAccessPoints(filesystemId string, r string) ([]types.AccessPointDescription, error) {
	var PaginationMarker *string
	var accessPoints []types.AccessPointDescription
	var err error
	for {
		DescribeAccessPoints, err := m.EFSClient.DescribeAccessPoints(
			context.TODO(),
			&efs.DescribeAccessPointsInput{
				FileSystemId: aws.String(filesystemId),
				NextToken:    PaginationMarker,
			},
			func(o *efs.Options) {
				o.Region = r
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			return nil, err
		}

		accessPoints = append(accessPoints, DescribeAccessPoints.AccessPoints...)

		// Pagination control. After the last page of output, the for loop exits.
		if DescribeAccessPoints.NextToken != nil {
			PaginationMarker = DescribeAccessPoints.NextToken
		} else {
			PaginationMarker = nil
			break
		}
	}
	return accessPoints, err
}

func (m *FilesystemsModule) getEFSfilesystemPermissions(accessPoint types.AccessPointDescription) (string, string) {
	var path string
	var permissions string

	if accessPoint.AccessPointId != nil {
		path = aws.ToString(accessPoint.RootDirectory.Path)
		permissions = aws.ToString(accessPoint.RootDirectory.CreationInfo.Permissions)
	}
	return path, permissions

}
