package aws

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	"github.com/aws/aws-sdk-go-v2/service/codebuild/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/bishopfox/awsservicemap"
	"github.com/sirupsen/logrus"
)

type CodeBuildModule struct {
	// General configuration data
	CodeBuildClient                  CodeBuildClientInterface
	IAMSimulatePrincipalPolicyClient iam.SimulatePrincipalPolicyAPIClient

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
	Projects       []Project
	CommandCounter internal.CommandCounter
	// Used to store output data for pretty printing
	output internal.OutputData2
	modLog *logrus.Entry
}

type CodeBuildClientInterface interface {
	ListProjects(ctx context.Context, params *codebuild.ListProjectsInput, optFns ...func(*codebuild.Options)) (*codebuild.ListProjectsOutput, error)
	BatchGetProjects(ctx context.Context, params *codebuild.BatchGetProjectsInput, optFns ...func(*codebuild.Options)) (*codebuild.BatchGetProjectsOutput, error)
}

type Project struct {
	Region     string
	Name       string
	Arn        string
	Role       string
	Admin      string
	CanPrivEsc string
}

func (m *CodeBuildModule) PrintCodeBuildProjects(outputFormat string, outputDirectory string, verbosity int) {
	// These stuct values are used by the output module
	m.output.Verbosity = verbosity
	m.output.Directory = outputDirectory
	m.output.CallingModule = "codebuild"
	localAdminMap := make(map[string]bool)

	m.modLog = internal.TxtLog.WithFields(logrus.Fields{
		"module": m.output.CallingModule,
	})
	if m.AWSProfile == "" {
		m.AWSProfile = internal.BuildAWSPath(m.Caller)
	}

	fmt.Printf("[%s][%s] Enumerating CodeBuild projects for account %s.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), aws.ToString(m.Caller.Account))
	m.pmapperMod, m.pmapperError = initPmapperGraph(m.Caller, m.AWSProfile, m.Goroutines)
	m.iamSimClient = initIAMSimClient(m.IAMSimulatePrincipalPolicyClient, m.Caller, m.AWSProfile, m.Goroutines)

	wg := new(sync.WaitGroup)
	semaphore := make(chan struct{}, m.Goroutines)

	// Create a channel to signal the spinner aka task status goroutine to finish
	spinnerDone := make(chan bool)
	//fire up the the task status spinner/updated
	go internal.SpinUntil(m.output.CallingModule, &m.CommandCounter, spinnerDone, "regions")

	//create a channel to receive the objects
	dataReceiver := make(chan Project)

	// Create a channel to signal to stop
	receiverDone := make(chan bool)

	go m.Receiver(dataReceiver, receiverDone)

	for _, region := range m.AWSRegions {
		wg.Add(1)
		m.CommandCounter.Pending++
		go m.executeChecks(region, wg, semaphore, dataReceiver)

	}

	wg.Wait()

	// Send a message to the spinner goroutine to close the channel and stop
	spinnerDone <- true
	<-spinnerDone
	receiverDone <- true
	<-receiverDone

	// Perform role analysis
	if m.pmapperError == nil {
		for i := range m.Projects {
			m.Projects[i].Admin, m.Projects[i].CanPrivEsc = GetPmapperResults(m.SkipAdminCheck, m.pmapperMod, &m.Projects[i].Role)
		}
	} else {
		for i := range m.Projects {
			m.Projects[i].Admin, m.Projects[i].CanPrivEsc = GetIamSimResult(m.SkipAdminCheck, &m.Projects[i].Role, m.iamSimClient, localAdminMap)
		}
	}

	// add - if struct is not empty do this. otherwise, dont write anything.
	if m.pmapperError == nil {
		m.output.Headers = []string{
			"Region",
			"Name",
			"Role",
			"IsAdminRole?",
			"CanPrivEscToAdmin?",
		}
	} else {
		m.output.Headers = []string{
			"Region",
			"Name",
			"Role",
			"IsAdminRole?",
			//"CanPrivEscToAdmin?",
		}
	}

	// Table rows

	for i := range m.Projects {
		if m.pmapperError == nil {
			m.output.Body = append(
				m.output.Body,
				[]string{
					m.Projects[i].Region,
					m.Projects[i].Name,
					m.Projects[i].Role,
					m.Projects[i].Admin,
					m.Projects[i].CanPrivEsc,
				},
			)
		} else {
			m.output.Body = append(
				m.output.Body,
				[]string{
					m.Projects[i].Region,
					m.Projects[i].Name,
					m.Projects[i].Role,
					m.Projects[i].Admin,
				},
			)

		}
	}

	var seen []string
	for _, project := range m.Projects {
		if !internal.Contains(project.Name, seen) {
			seen = append(seen, project.Name)
		}
	}

	if len(m.output.Body) > 0 {
		m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", m.AWSProfile)
		//m.output.OutputSelector(outputFormat)
		//utils.OutputSelector(verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.CallingModule, m.output.CallingModule)
		internal.OutputSelector(verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.CallingModule, m.output.CallingModule, m.WrapTable, m.AWSProfile)
		//m.writeLoot(m.output.FilePath, verbosity)
		//fmt.Printf("[%s][%s] %d projects with a total of %d node groups found.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), len(seen), len(m.output.Body))
		fmt.Printf("[%s][%s] %d projects found.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), len(m.output.Body))
		fmt.Printf("[%s][%s] For context and next steps: https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#%s\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), m.output.CallingModule)

	} else {
		fmt.Printf("[%s][%s] No projects found, skipping the creation of an output file.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	}

}

func (m *CodeBuildModule) executeChecks(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Project) {
	defer wg.Done()

	servicemap := &awsservicemap.AwsServiceMap{
		JsonFileSource: "DOWNLOAD_FROM_AWS",
	}
	res, err := servicemap.IsServiceInRegion("codebuild", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		m.getcodeBuildProjectsPerRegion(r, wg, semaphore, dataReceiver)
	}
}

func (m *CodeBuildModule) Receiver(receiver chan Project, receiverDone chan bool) {
	defer close(receiverDone)
	for {
		select {
		case data := <-receiver:
			m.Projects = append(m.Projects, data)
		case <-receiverDone:
			receiverDone <- true
			return
		}
	}
}

func (m *CodeBuildModule) getcodeBuildProjectsPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Project) {
	defer wg.Done()

	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	projects, err := m.getcodeBuildProjects(r)
	if err != nil {
		m.modLog.Error(err)
	}

	for _, project := range projects {
		details, err := m.getProjectDetails(project, r)
		if err != nil {
			m.modLog.Error(err)
		}

		dataReceiver <- Project{
			Name:       aws.ToString(details.Name),
			Region:     r,
			Role:       aws.ToString(details.ServiceRole),
			Admin:      "",
			CanPrivEsc: "",
		}

	}

}

func (m *CodeBuildModule) getcodeBuildProjects(r string) ([]string, error) {
	CodeBuildProjects, err := m.CodeBuildClient.ListProjects(
		context.TODO(),
		&codebuild.ListProjectsInput{},
		func(options *codebuild.Options) {
			options.Region = r
		},
	)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return nil, err
	}
	return CodeBuildProjects.Projects, nil
}

func (m *CodeBuildModule) getProjectDetails(project string, r string) (types.Project, error) {
	Project, err := m.CodeBuildClient.BatchGetProjects(
		context.TODO(),
		&codebuild.BatchGetProjectsInput{
			Names: []string{project},
		},
		func(options *codebuild.Options) {
			options.Region = r
		},
	)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
	}

	return Project.Projects[0], nil
}
