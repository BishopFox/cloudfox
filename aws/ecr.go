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
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/sirupsen/logrus"
)

type ECRModule struct {
	// General configuration data
	ECRClient *ecr.Client

	Caller       sts.GetCallerIdentityOutput
	AWSRegions   []string
	OutputFormat string
	AWSProfile   string

	// Main module data
	Repositories   []Repository
	CommandCounter console.CommandCounter
	// Used to store output data for pretty printing
	output utils.OutputData2
	modLog *logrus.Entry
}

type Repository struct {
	AWSService string
	Region     string
	Name       string
	URI        string
	PushedAt   string
	ImageTags  string
	ImageSize  int64
}

func (m *ECRModule) PrintECR(outputFormat string, outputDirectory string, verbosity int) {
	// These stuct values are used by the output module
	m.output.Verbosity = verbosity
	m.output.Directory = outputDirectory
	m.output.CallingModule = "ecr"
	m.modLog = utils.TxtLogger.WithFields(logrus.Fields{
		"module": m.output.CallingModule,
	})
	if m.AWSProfile == "" {
		m.AWSProfile = fmt.Sprintf("%s-%s", aws.ToString(m.Caller.Account), aws.ToString(m.Caller.UserId))
	}

	fmt.Printf("[%s] Enumerating container repositories for account %s.\n", cyan(m.output.CallingModule), aws.ToString(m.Caller.Account))

	wg := new(sync.WaitGroup)

	// Create a channel to signal the spinner aka task status goroutine to finish
	spinnerDone := make(chan bool)
	//fire up the the task status spinner/updated
	go console.SpinUntil(m.output.CallingModule, &m.CommandCounter, spinnerDone, "regions")

	//create a channel to receive the objects
	dataReceiver := make(chan Repository)

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
		"Name",
		"URI",
		"PushedAt",
		"ImageTags",
		"ImageSize",
	}

	// Table rows
	for i := range m.Repositories {
		m.output.Body = append(
			m.output.Body,
			[]string{
				m.Repositories[i].AWSService,
				m.Repositories[i].Region,
				m.Repositories[i].Name,
				m.Repositories[i].URI,
				m.Repositories[i].PushedAt,
				m.Repositories[i].ImageTags,
				strconv.Itoa(int(m.Repositories[i].ImageSize)),
			},
		)

	}
	if len(m.output.Body) > 0 {
		m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", m.AWSProfile)
		//m.output.OutputSelector(outputFormat)
		utils.OutputSelector(verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.CallingModule, m.output.CallingModule)
		m.writeLoot(outputDirectory, verbosity)
		fmt.Printf("[%s] %s repositories found.\n", cyan(m.output.CallingModule), strconv.Itoa(len(m.output.Body)))
	} else {
		fmt.Printf("[%s] No repositories found, skipping the creation of an output file.\n", cyan(m.output.CallingModule))
	}

}

func (m *ECRModule) executeChecks(r string, wg *sync.WaitGroup, dataReceiver chan Repository) {
	defer wg.Done()
	m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	m.getECRRecordsPerRegion(r, dataReceiver)
	m.CommandCounter.Executing--
	m.CommandCounter.Complete++
}

func (m *ECRModule) Receiver(receiver chan Repository, receiverDone chan bool) {
	defer close(receiverDone)
	for {
		select {
		case data := <-receiver:
			m.Repositories = append(m.Repositories, data)
		case <-receiverDone:
			receiverDone <- true
			return
		}
	}
}

func (m *ECRModule) writeLoot(outputDirectory string, verbosity int) {
	path := filepath.Join(outputDirectory, "cloudfox-output", "aws", m.AWSProfile, "loot")
	err := os.MkdirAll(path, os.ModePerm)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
	}
	pullFile := filepath.Join(path, "ecr-pull-commands.txt")

	var out string
	out = out + fmt.Sprintln("#############################################")
	out = out + fmt.Sprintln("# The profile you will use to perform these commands is most likely not the profile you used to run CloudFox")
	out = out + fmt.Sprintln("# Set the $profile environment variable to the profile you are going to use to inspect the repositories.")
	out = out + fmt.Sprintln("# E.g., export profile=dev-prod.")
	out = out + fmt.Sprintln("#############################################")
	out = out + fmt.Sprintln("")

	for _, repo := range m.Repositories {
		loginURI := strings.Split(repo.URI, "/")[0]
		out = out + fmt.Sprintf("aws --profile $profile --region %s ecr get-login-password | docker login --username AWS --password-stdin %s\n", repo.Region, loginURI)
		out = out + fmt.Sprintf("docker pull %s\n", repo.URI)
		out = out + fmt.Sprintf("docker inspect %s\n", repo.URI)
		out = out + fmt.Sprintf("docker history --no-trunc %s\n", repo.URI)
		out = out + fmt.Sprintf("docker run -it --entrypoint /bin/sh %s\n", repo.URI)
		out = out + fmt.Sprintf("docker save %s -o %s.tar\n\n", repo.URI, repo.Name)

	}
	err = os.WriteFile(pullFile, []byte(out), 0644)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
	}

	if verbosity > 2 {
		fmt.Println()
		fmt.Printf("[%s] %s \n", cyan(m.output.CallingModule), green("Use the commands below to authenticate to ECR and download the images that look interesting"))
		fmt.Printf("[%s] %s \n\n", cyan(m.output.CallingModule), green("You will need the ecr:GetAuthorizationToken on the registry to authenticate and this is not part of the SecurityAudit permissions policy"))

		fmt.Print(out)
		fmt.Printf("[%s] %s \n\n", cyan(m.output.CallingModule), green("End of loot file."))
	}

	fmt.Printf("[%s] Loot written to [%s]\n", cyan(m.output.CallingModule), pullFile)

}

func (m *ECRModule) getECRRecordsPerRegion(r string, dataReceiver chan Repository) {
	// "PaginationMarker" is a control variable used for output continuity, as AWS return the output in pages.
	var PaginationControl *string
	var PaginationControl2 *string

	for {
		DescribeRepositories, err := m.ECRClient.DescribeRepositories(
			context.TODO(),
			&ecr.DescribeRepositoriesInput{
				NextToken: PaginationControl,
			},
			func(o *ecr.Options) {
				o.Region = r
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		for _, repo := range DescribeRepositories.Repositories {
			repoName := aws.ToString(repo.RepositoryName)
			repoURI := aws.ToString(repo.RepositoryUri)
			//created := *repo.CreatedAt
			//fmt.Printf("%s, %s, %s", repoName, repoURI, created)
			var images []types.ImageDetail
			for {
				DescribeImages, err := m.ECRClient.DescribeImages(
					context.TODO(),
					&ecr.DescribeImagesInput{
						RepositoryName: &repoName,
						NextToken:      PaginationControl2,
					},
					func(o *ecr.Options) {
						o.Region = r
					},
				)
				if err != nil {
					m.modLog.Error(err.Error())
					m.CommandCounter.Error++
					break
				}

				//images := DescribeImages.ImageDetails
				images = append(images, DescribeImages.ImageDetails...)

				if DescribeImages.NextToken != nil {
					PaginationControl2 = DescribeImages.NextToken
				} else {

					// not sure if this is the right way to do this, but adding this code here was the only way i could
					// sort the results from all pages to look for the latest push.
					PaginationControl2 = nil

					sort.Slice(images, func(i, j int) bool {
						return images[i].ImagePushedAt.Format("2006-01-02 15:04:05") < images[j].ImagePushedAt.Format("2006-01-02 15:04:05")
					})

					var image types.ImageDetail
					var imageTags string

					if len(images) > 1 {
						image = images[len(images)-1]
					} else if len(images) == 1 {
						image = images[0]
					} else {

						break
					}

					if len(image.ImageTags) > 0 {
						imageTags = image.ImageTags[0]
					}
					//imageTags := image.ImageTags[0]
					pushedAt := image.ImagePushedAt.Format("2006-01-02 15:04:05")
					imageSize := aws.ToInt64(image.ImageSizeInBytes)
					pullURI := fmt.Sprintf("%s:%s", repoURI, imageTags)

					dataReceiver <- Repository{
						AWSService: "ECR",
						Name:       repoName,
						Region:     r,
						URI:        pullURI,
						PushedAt:   pushedAt,
						ImageTags:  imageTags,
						ImageSize:  imageSize,
					}

					// }
					break
				}

			}
		}

		// The "NextToken" value is nil when there's no more data to return.
		if DescribeRepositories.NextToken != nil {
			PaginationControl = DescribeRepositories.NextToken
		} else {
			PaginationControl = nil
			break
		}
	}
}
