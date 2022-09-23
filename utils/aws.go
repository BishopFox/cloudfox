package utils

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go/ptr"
	"github.com/kyokomi/emoji"
	"github.com/sirupsen/logrus"
	"github.com/spf13/afero"
)

var (
	TxtLoggerName = "root"
	TxtLogger     = txtLogger()
	UtilsFs       = afero.NewOsFs()
)

func AWSConfigFileLoader(AWSProfile string) aws.Config {
	// Ensures the profile in the aws config file meets all requirements (valid keys and a region defined). I noticed some calls fail without a default region.
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithSharedConfigProfile(AWSProfile), config.WithDefaultRegion("us-east-1"), config.WithRetryer(
		func() aws.Retryer {
			return retry.AddWithMaxAttempts(retry.NewStandard(), 3)
		}))
	if err != nil {
		fmt.Println(err)
		log.Fatal(err)
	}

	_, err = cfg.Credentials.Retrieve(context.TODO())
	if err != nil {
		fmt.Printf("[%s] Error retrieving credentials from the specified profile %s, environment variables, or the instance metadata service.\n", cyan(emoji.Sprintf(":fox:cloudfox :fox:")), AWSProfile)
		log.Fatalf("Could not retrieve the specified profile name %s", err)

	}
	return cfg
}

func AWSWhoami(awsProfile string) sts.GetCallerIdentityOutput {
	// Connects to STS and checks caller identity. Same as running "aws sts get-caller-identity"
	//fmt.Printf("[%s] Retrieving caller's identity\n", cyan(emoji.Sprintf(":fox:cloudfox v%s :fox:", version)))
	STSService := sts.NewFromConfig(AWSConfigFileLoader(awsProfile))
	CallerIdentity, err := STSService.GetCallerIdentity(context.TODO(), &sts.GetCallerIdentityInput{})
	if err != nil {
		fmt.Printf("[%s] Could not get caller's identity\n\nError: %s", cyan(emoji.Sprintf(":fox:cloudfox :fox:")), err)
		log.Fatalf("Could not get caller's identity: %s", err)

	}
	return *CallerIdentity
}

func GetRegionsForService(awsProfile string, service string) []string {
	SSMClient := ssm.NewFromConfig(AWSConfigFileLoader(awsProfile))
	var PaginationControl *string
	var supportedRegions []string
	path := fmt.Sprintf("/aws/service/global-infrastructure/services/%s/regions", service)

	ServiceRegions, err := SSMClient.GetParametersByPath(
		context.TODO(),
		&(ssm.GetParametersByPathInput{
			NextToken: PaginationControl,
			Path:      &path,
		}),
	)
	if err != nil {
		fmt.Println(err.Error())

	}

	if ServiceRegions.Parameters != nil {
		for _, region := range ServiceRegions.Parameters {
			name := *region.Value
			supportedRegions = append(supportedRegions, name)
		}

		// The "NextToken" value is nil when there's no more data to return.
		if ServiceRegions.NextToken != nil {
			PaginationControl = ServiceRegions.NextToken
		} else {
			PaginationControl = nil
		}
	}
	return supportedRegions
}

// txtLogger - Returns the txt logger
func txtLogger() *logrus.Logger {
	txtLogger := logrus.New()
	txtFile, err := os.OpenFile(fmt.Sprintf("%s/cloudfox-error.log", ptr.ToString(GetLogDirPath())), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(fmt.Sprintf("Failed to open log file %v", err))
	}
	txtLogger.Out = txtFile
	txtLogger.SetLevel(logrus.InfoLevel)
	//txtLogger.SetReportCaller(true)

	return txtLogger
}

func CheckErr(e error, msg string) {
	if e != nil {
		log.Fatalf("[-] Error %s", msg)
	}
}

func GetAllAWSProfiles() []string {
	credentialsFile, err := UtilsFs.Open(config.DefaultSharedCredentialsFilename())
	CheckErr(err, "could not open default AWS credentials file")
	defer credentialsFile.Close()
	var AWSProfiles []string
	scanner := bufio.NewScanner(credentialsFile)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(text, "[") && strings.HasSuffix(text, "]") {
			text = strings.TrimPrefix(text, "[")
			text = strings.TrimSuffix(text, "]")
			AWSProfiles = append(AWSProfiles, text)
		}
	}
	return AWSProfiles
}

func GetSelectedAWSProfiles(AWSProfilesListPath string) []string {
	AWSProfilesListFile, err := UtilsFs.Open(AWSProfilesListPath)
	CheckErr(err, fmt.Sprintf("could not open given file %s", AWSProfilesListPath))
	defer AWSProfilesListFile.Close()
	var AWSProfiles []string
	scanner := bufio.NewScanner(AWSProfilesListFile)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		profile := strings.TrimSpace(scanner.Text())
		if len(profile) != 0 {
			AWSProfiles = append(AWSProfiles, profile)
		}
	}
	return AWSProfiles
}

func removeBadPathChars(receivedPath *string) string {
	var path string
	var bannedPathChars *regexp.Regexp = regexp.MustCompile(`[<>:"'|?*]`)
	path = bannedPathChars.ReplaceAllString(aws.ToString(receivedPath), "_")

	return path

}

func BuildAWSPath(Caller sts.GetCallerIdentityOutput) string {
	var callerAccount = removeBadPathChars(Caller.Account)
	var callerUserID = removeBadPathChars(Caller.UserId)

	return fmt.Sprintf("%s-%s", callerAccount, callerUserID)
}
