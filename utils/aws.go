package utils

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go/ptr"
	"github.com/bishopfox/awsservicemap"
	"github.com/kyokomi/emoji"
	"github.com/sirupsen/logrus"
	"github.com/spf13/afero"
)

var (
	TxtLoggerName = "root"
	TxtLog        = TxtLogger()
	UtilsFs       = afero.NewOsFs()
)

func AWSConfigFileLoader(AWSProfile string, version string) aws.Config {
	// Ensures the profile in the aws config file meets all requirements (valid keys and a region defined). I noticed some calls fail without a default region.
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithSharedConfigProfile(AWSProfile), config.WithDefaultRegion("us-east-1"), config.WithRetryer(
		func() aws.Retryer {
			return retry.AddWithMaxAttempts(retry.NewStandard(), 3)
		}))
	if err != nil {
		fmt.Println(err)
		TxtLog.Println(err)
	}

	_, err = cfg.Credentials.Retrieve(context.TODO())
	if err != nil {
		fmt.Printf("[%s][%s] Error retrieving credentials from environment variables, or the instance metadata service.\n", cyan(emoji.Sprintf(":fox:cloudfox v%s :fox:", version)), cyan(AWSProfile))
		TxtLog.Printf("Could not retrieve the specified profile name %s", err)

	}
	return cfg
}

func AWSWhoami(awsProfile string, version string) (*sts.GetCallerIdentityOutput, error) {
	// Connects to STS and checks caller identity. Same as running "aws sts get-caller-identity"
	//fmt.Printf("[%s] Retrieving caller's identity\n", cyan(emoji.Sprintf(":fox:cloudfox v%s :fox:", version)))
	STSService := sts.NewFromConfig(AWSConfigFileLoader(awsProfile, version))
	CallerIdentity, err := STSService.GetCallerIdentity(context.TODO(), &sts.GetCallerIdentityInput{})
	if err != nil {
		fmt.Printf("[%s][%s] Could not get caller's identity\n\nError: %s\n\n", cyan(emoji.Sprintf(":fox:cloudfox v%s :fox:", version)), cyan(awsProfile), err)
		TxtLog.Printf("Could not get caller's identity: %s", err)
		return CallerIdentity, err

	}
	return CallerIdentity, err
}

func GetEnabledRegions(awsProfile string, version string) []string {
	var enabledRegions []string
	ec2Client := ec2.NewFromConfig(AWSConfigFileLoader(awsProfile, version))
	regions, err := ec2Client.DescribeRegions(
		context.TODO(),
		&ec2.DescribeRegionsInput{
			AllRegions: aws.Bool(false),
		},
	)

	if err != nil {
		servicemap := &awsservicemap.AwsServiceMap{
			JsonFileSource: "EMBEDDED_IN_PACKAGE",
		}
		AWSRegions, err := servicemap.GetAllRegions()
		if err != nil {
			TxtLog.Println(err)
		}
		return AWSRegions
	}

	for _, region := range regions.Regions {
		enabledRegions = append(enabledRegions, *region.RegionName)
	}

	return enabledRegions

}

// func GetRegionsForService(awsProfile string, service string) []string {
// 	SSMClient := ssm.NewFromConfig(AWSConfigFileLoader(awsProfile))
// 	var PaginationControl *string
// 	var supportedRegions []string
// 	path := fmt.Sprintf("/aws/service/global-infrastructure/services/%s/regions", service)

// 	ServiceRegions, err := SSMClient.GetParametersByPath(
// 		context.TODO(),
// 		&(ssm.GetParametersByPathInput{
// 			NextToken: PaginationControl,
// 			Path:      &path,
// 		}),
// 	)
// 	if err != nil {
// 		fmt.Println(err.Error())

// 	}

// 	if ServiceRegions.Parameters != nil {
// 		for _, region := range ServiceRegions.Parameters {
// 			name := *region.Value
// 			supportedRegions = append(supportedRegions, name)
// 		}

// 		// The "NextToken" value is nil when there's no more data to return.
// 		if ServiceRegions.NextToken != nil {
// 			PaginationControl = ServiceRegions.NextToken
// 		} else {
// 			PaginationControl = nil
// 		}
// 	}
// 	return supportedRegions
// }

// txtLogger - Returns the txt logger
func TxtLogger() *logrus.Logger {
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
		TxtLog.Printf("[-] Error %s", msg)
	}
}

func GetAllAWSProfiles(AWSConfirm bool) []string {
	var AWSProfiles []string

	credentialsFile, err := UtilsFs.Open(config.DefaultSharedCredentialsFilename())
	CheckErr(err, "could not open default AWS credentials file")
	if err == nil {
		defer credentialsFile.Close()
		scanner := bufio.NewScanner(credentialsFile)
		scanner.Split(bufio.ScanLines)
		for scanner.Scan() {
			text := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(text, "[") && strings.HasSuffix(text, "]") {
				text = strings.TrimPrefix(text, "[")
				text = strings.TrimSuffix(text, "]")
				if !Contains(text, AWSProfiles) {
					AWSProfiles = append(AWSProfiles, text)
				}
			}
		}
	}

	configFile, err := UtilsFs.Open(config.DefaultSharedConfigFilename())
	CheckErr(err, "could not open default AWS credentials file")
	if err == nil {
		defer configFile.Close()
		scanner2 := bufio.NewScanner(configFile)
		scanner2.Split(bufio.ScanLines)
		for scanner2.Scan() {
			text := strings.TrimSpace(scanner2.Text())
			if strings.HasPrefix(text, "[") && strings.HasSuffix(text, "]") {
				text = strings.TrimPrefix(text, "[profile ")
				text = strings.TrimPrefix(text, "[")
				text = strings.TrimSuffix(text, "]")
				if !Contains(text, AWSProfiles) {
					AWSProfiles = append(AWSProfiles, text)
				}
			}
		}
	}

	if !AWSConfirm {
		result := ConfirmSelectedProfiles(AWSProfiles)
		if !result {
			os.Exit(1)
		}
	}
	return AWSProfiles

}

func ConfirmSelectedProfiles(AWSProfiles []string) bool {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("[ %s] Identified profiles:\n\n", cyan(emoji.Sprintf(":fox:cloudfox :fox:")))
	for _, profile := range AWSProfiles {
		fmt.Printf("\t* %s\n", profile)
	}
	fmt.Printf("\n[ %s] Are you sure you'd like to run this command against the [%d] listed profile(s)? (Y\\n): ", cyan(emoji.Sprintf(":fox:cloudfox :fox:")), len(AWSProfiles))
	text, _ := reader.ReadString('\n')
	switch text {
	case "\n", "Y\n", "y\n":
		return true
	}
	return false

}

func GetSelectedAWSProfiles(AWSProfilesListPath string) []string {
	AWSProfilesListFile, err := UtilsFs.Open(AWSProfilesListPath)
	CheckErr(err, fmt.Sprintf("could not open given file %s", AWSProfilesListPath))
	if err != nil {
		fmt.Printf("\nError loading profiles. Could not open file at location[%s]\n", AWSProfilesListPath)
		os.Exit(1)
	}
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
