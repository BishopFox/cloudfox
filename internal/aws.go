package internal

import (
	"bufio"
	"context"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go/ptr"
	"github.com/bishopfox/awsservicemap"
	"github.com/kyokomi/emoji"
	"github.com/patrickmn/go-cache"
	"github.com/sirupsen/logrus"
	"github.com/spf13/afero"
)

var (
	TxtLoggerName = "root"
	TxtLog        = TxtLogger()
	UtilsFs       = afero.NewOsFs()
	credsMap      = map[string]aws.Credentials{}
	ConfigMap     = map[string]aws.Config{}

	// MaxRetries controls the maximum number of retry attempts for AWS API calls.
	// The default AWS SDK behavior is 3 attempts. Set to 0 for no retries, which
	// is useful when running with limited-permission credentials to avoid slow
	// timeouts on access-denied errors.
	MaxRetries = 3

	// unreachableRegions tracks regions that failed a TCP connectivity check so
	// they can be skipped for the remainder of the run. Protected by a mutex
	// since multiple goroutines may probe regions concurrently.
	unreachableRegions   = make(map[string]bool)
	unreachableRegionsMu sync.RWMutex

	// RegionReachabilityTimeout controls how long the TCP probe waits before
	// declaring a region unreachable. Default 3 seconds is enough for any
	// healthy AWS endpoint.
	RegionReachabilityTimeout = 3 * time.Second
)

type CloudFoxRunData struct {
	Profile        string
	AccountID      string
	OutputLocation string
}

func init() {
	gob.Register(aws.Config{})
	gob.Register(sts.GetCallerIdentityOutput{})
	gob.Register(CloudFoxRunData{})
}

func InitializeCloudFoxRunData(AWSProfile string, version string, AwsMfaToken string, AWSOutputDirectory string) (CloudFoxRunData, error) {
	var runData CloudFoxRunData

	cacheDirectory := filepath.Join(AWSOutputDirectory, "cached-data", "aws")
	filename := filepath.Join(cacheDirectory, fmt.Sprintf("CloudFoxRunData-%s.json", AWSProfile))
	if _, err := os.Stat(filename); err == nil {
		// unmarshall the data from the file into type CloudFoxRunData

		// Open the file (this is not actually needed if you use os.ReadFile, so you can skip this)
		file, err := os.Open(filename)
		if err != nil {
			return CloudFoxRunData{}, err
		}
		defer file.Close()

		// Read the file content
		jsonData, err := os.ReadFile(filename)
		if err != nil {
			return CloudFoxRunData{}, err
		}

		// Unmarshal jsonData into runData (make sure to pass a pointer to runData)
		err = json.Unmarshal(jsonData, &runData)
		if err != nil {
			return CloudFoxRunData{}, err
		}

		return runData, nil

	}

	CallerIdentity, err := AWSWhoami(AWSProfile, version, AwsMfaToken)
	if err != nil {
		return CloudFoxRunData{}, err
	}
	outputLocation := filepath.Join(AWSOutputDirectory, "cloudfox-output", "aws", fmt.Sprintf("%s-%s", AWSProfile, ptr.ToString(CallerIdentity.Account)))

	runData = CloudFoxRunData{
		Profile:        AWSProfile,
		AccountID:      aws.ToString(CallerIdentity.Account),
		OutputLocation: outputLocation,
	}

	// Marshall the data to a file
	err = os.MkdirAll(cacheDirectory, 0755)
	if err != nil {
		return CloudFoxRunData{}, err
	}
	file, err := os.Create(filename)
	if err != nil {
		return CloudFoxRunData{}, err
	}
	defer file.Close()
	jsonData, err := json.Marshal(runData)
	if err != nil {
		return CloudFoxRunData{}, err
	}
	_, err = file.Write(jsonData)
	if err != nil {
		return CloudFoxRunData{}, err
	}

	return runData, nil
}

func AWSConfigFileLoader(AWSProfile string, version string, AwsMfaToken string) aws.Config {
	// Loads the AWS config file and returns a config object

	var cfg aws.Config
	var err error
	// cacheKey := fmt.Sprintf("AWSConfigFileLoader-%s", AWSProfile)
	// cached, found := Cache.Get(cacheKey)
	// if found {
	// 	cfg = cached.(aws.Config)
	// 	return cfg
	// }

	// Check if the profile is already in the config map. If not, load it and retrieve the credentials. If it is, return the cached config object
	// The AssumeRoleOptions below are used to pass the MFA token to the AssumeRole call (when applicable)
	if _, ok := ConfigMap[AWSProfile]; !ok {
		// Ensures the profile in the aws config file meets all requirements (valid keys and a region defined). I noticed some calls fail without a default region.
		if AwsMfaToken != "" {
			cfg, err = config.LoadDefaultConfig(context.TODO(), config.WithSharedConfigProfile(AWSProfile), config.WithDefaultRegion("us-east-1"), config.WithRetryer(
				func() aws.Retryer {
					return retry.AddWithMaxAttempts(retry.NewStandard(), MaxRetries)
				}), config.WithAssumeRoleCredentialOptions(func(options *stscreds.AssumeRoleOptions) {
				options.TokenProvider = func() (string, error) {
					return AwsMfaToken, nil
				}
			}),
			)
		} else {
			cfg, err = config.LoadDefaultConfig(context.TODO(), config.WithSharedConfigProfile(AWSProfile), config.WithDefaultRegion("us-east-1"), config.WithRetryer(
				func() aws.Retryer {
					return retry.AddWithMaxAttempts(retry.NewStandard(), MaxRetries)
				}), config.WithAssumeRoleCredentialOptions(func(options *stscreds.AssumeRoleOptions) {
				options.TokenProvider = stscreds.StdinTokenProvider
			}),
			)
		}

		if err != nil {
			//fmt.Println(err)
			if AWSProfile != "" {
				TxtLog.Println(err)
				fmt.Printf("[%s][%s] The specified profile [%s] does not exist or there was an error loading the credentials.\n", cyan(emoji.Sprintf(":fox:cloudfox v%s :fox:", version)), cyan(AWSProfile), AWSProfile)
				TxtLog.Fatalf("Could not retrieve the specified profile name %s", err)
			} else {
				fmt.Printf("[%s][%s] Error retrieving credentials from environment variables, or the instance metadata service.\n", cyan(emoji.Sprintf(":fox:cloudfox v%s :fox:", version)), cyan(AWSProfile))
				TxtLog.Fatalf("[%s][%s]Error retrieving credentials from environment variables, or the instance metadata service.\n", cyan(emoji.Sprintf(":fox:cloudfox v%s :fox:", version)), cyan(AWSProfile))
			}
			//os.Exit(1)
		}

		_, err := cfg.Credentials.Retrieve(context.TODO())

		if err != nil {
			fmt.Printf("[%s][%s] Error retrieving credentials from environment variables, or the instance metadata service.\n", cyan(emoji.Sprintf(":fox:cloudfox v%s :fox:", version)), cyan(AWSProfile))

		} else {
			// update the config map with the new config for future lookups
			ConfigMap[AWSProfile] = cfg
			//return the config object for this first iteration
			//Cache.Set(cacheKey, cfg, cache.DefaultExpiration)
			return cfg

		}
	} else {
		//fmt.Println("Using cached config")
		cfg = ConfigMap[AWSProfile]
		return cfg
	}
	//Cache.Set(cacheKey, cfg, cache.DefaultExpiration)
	return cfg
}

func AWSWhoami(awsProfile string, version string, AwsMfaToken string) (*sts.GetCallerIdentityOutput, error) {

	cacheKey := fmt.Sprintf("sts-getCallerIdentity-%s", awsProfile)
	if cached, found := Cache.Get(cacheKey); found {
		// Correct type assertion: assert the type, not a variable.
		if cachedValue, ok := cached.(*sts.GetCallerIdentityOutput); ok {
			return cachedValue, nil
		}
		// Handle the case where type assertion fails, if necessary.
	}

	// Connects to STS and checks caller identity. Same as running "aws sts get-caller-identity"
	//fmt.Printf("[%s] Retrieving caller's identity\n", cyan(emoji.Sprintf(":fox:cloudfox v%s :fox:", version)))
	STSService := sts.NewFromConfig(AWSConfigFileLoader(awsProfile, version, AwsMfaToken))
	CallerIdentity, err := STSService.GetCallerIdentity(context.TODO(), &sts.GetCallerIdentityInput{})
	if err != nil {
		fmt.Printf("[%s][%s] Could not get caller's identity\n\nError: %s\n\n", cyan(emoji.Sprintf(":fox:cloudfox v%s :fox:", version)), cyan(awsProfile), err)
		TxtLog.Printf("Could not get caller's identity: %s", err)
		return CallerIdentity, err

	}
	// Convert CallerIdentity to something i can store using the cache
	Cache.Set(cacheKey, CallerIdentity, cache.DefaultExpiration)
	return CallerIdentity, err
}

// isRegionReachable does a fast TCP dial to the STS endpoint in the given region.
// STS is available in every region and is a lightweight endpoint to probe. If the
// connection succeeds, the region is reachable. Results are cached so each region
// is only probed once per run.
func isRegionReachable(region string) bool {
	unreachableRegionsMu.RLock()
	alreadyUnreachable := unreachableRegions[region]
	unreachableRegionsMu.RUnlock()
	if alreadyUnreachable {
		return false
	}

	endpoint := fmt.Sprintf("sts.%s.amazonaws.com:443", region)
	conn, err := net.DialTimeout("tcp", endpoint, RegionReachabilityTimeout)
	if err != nil {
		unreachableRegionsMu.Lock()
		unreachableRegions[region] = true
		unreachableRegionsMu.Unlock()
		TxtLog.Warnf("Region %s is unreachable (probe to %s failed: %v) - skipping for this run", region, endpoint, err)
		return false
	}
	conn.Close()
	return true
}

// FilterReachableRegions takes a list of regions and returns only the ones that
// pass a TCP connectivity probe. Unreachable regions are probed in parallel and
// cached so subsequent calls return immediately.
func FilterReachableRegions(regions []string) []string {
	// Probe all regions concurrently for speed
	type probeResult struct {
		region    string
		reachable bool
	}
	resultsChan := make(chan probeResult, len(regions))

	for _, region := range regions {
		go func(r string) {
			resultsChan <- probeResult{region: r, reachable: isRegionReachable(r)}
		}(region)
	}

	var reachableRegions []string
	for range regions {
		result := <-resultsChan
		if result.reachable {
			reachableRegions = append(reachableRegions, result.region)
		}
	}
	return reachableRegions
}

func GetEnabledRegions(awsProfile string, version string, AwsMfaToken string) []string {
	cacheKey := fmt.Sprintf("GetEnabledRegions-%s", awsProfile)
	cached, found := Cache.Get(cacheKey)
	if found {
		return cached.([]string)
	}

	var enabledRegions []string
	ec2Client := ec2.NewFromConfig(ConfigMap[awsProfile])
	regions, err := ec2Client.DescribeRegions(
		context.TODO(),
		&ec2.DescribeRegionsInput{
			AllRegions: aws.Bool(false),
		},
	)

	if err != nil {
		servicemap := &awsservicemap.AwsServiceMap{
			JsonFileSource: "DOWNLOAD_FROM_AWS",
		}
		AWSRegions, err := servicemap.GetAllRegions()
		if err != nil {
			TxtLog.Println(err)
		}
		reachableRegions := FilterReachableRegions(AWSRegions)
		Cache.Set(cacheKey, reachableRegions, cache.DefaultExpiration)
		return reachableRegions
	}

	for _, region := range regions.Regions {
		enabledRegions = append(enabledRegions, *region.RegionName)
	}
	enabledRegions = FilterReachableRegions(enabledRegions)
	Cache.Set(cacheKey, enabledRegions, cache.DefaultExpiration)
	return enabledRegions

}

// ModuleFirstFormatter formats logs with module field before the message
type ModuleFirstFormatter struct {
	logrus.TextFormatter
}

func (f *ModuleFirstFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	// Use the standard text formatter to get the base format
	formatted, err := f.TextFormatter.Format(entry)
	if err != nil {
		return nil, err
	}

	// If there's a module field, reformat to put it before msg
	if module, ok := entry.Data["module"]; ok {
		// Parse the formatted output and rebuild with module first
		str := string(formatted)

		// Find and extract the module field
		moduleStr := fmt.Sprintf("module=%v", module)

		// If the formatted string contains the module field, move it before msg=
		if idx := strings.Index(str, moduleStr); idx > 0 {
			// Remove module from its current position
			before := str[:idx]
			after := str[idx+len(moduleStr):]
			// Trim any extra space that might be left
			after = strings.TrimPrefix(after, " ")

			// Find where msg= starts
			if msgIdx := strings.Index(before, "msg="); msgIdx > 0 {
				// Rebuild: everything before msg, then module, then msg and after
				newStr := before[:msgIdx] + moduleStr + " " + before[msgIdx:] + after
				return []byte(newStr), nil
			}
		}
	}

	return formatted, nil
}

// SplitLevelHook is a custom logrus hook that splits logs by level
// Error and Fatal messages go to errorWriter, everything else goes to infoWriter
type SplitLevelHook struct {
	errorWriter io.Writer
	infoWriter  io.Writer
	formatter   logrus.Formatter
}

func (h *SplitLevelHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

func (h *SplitLevelHook) Fire(entry *logrus.Entry) error {
	line, err := h.formatter.Format(entry)
	if err != nil {
		return err
	}

	switch entry.Level {
	case logrus.ErrorLevel, logrus.FatalLevel, logrus.PanicLevel:
		_, err = h.errorWriter.Write(line)
	default:
		_, err = h.infoWriter.Write(line)
	}
	return err
}

// txtLogger - Returns the txt logger
func TxtLogger() *logrus.Logger {
	txtLogger := logrus.New()

	// Open error log file (only errors and fatal messages)
	errorFile, err := os.OpenFile(fmt.Sprintf("%s/cloudfox-error.log", ptr.ToString(GetLogDirPath())), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		errorFile, err = os.OpenFile(fmt.Sprintf("./cloudfox-error.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	}
	if err != nil {
		panic(fmt.Sprintf("Failed to open error log file %v", err))
	}

	// Open info log file (all non-error messages)
	infoFile, err := os.OpenFile(fmt.Sprintf("%s/cloudfox-info.log", ptr.ToString(GetLogDirPath())), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		infoFile, err = os.OpenFile(fmt.Sprintf("./cloudfox-info.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	}
	if err != nil {
		panic(fmt.Sprintf("Failed to open info log file %v", err))
	}

	// Discard default output since we're using hooks
	txtLogger.SetOutput(io.Discard)

	// Add custom hook to split logs by level
	txtLogger.AddHook(&SplitLevelHook{
		errorWriter: errorFile,
		infoWriter:  infoFile,
		formatter:   &ModuleFirstFormatter{},
	})

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

// this is all for the spinner and command counter
const clearln = "\r\x1b[2K"

// CommandCounter tracks per-module task progress. All fields are accessed
// atomically through the Incr/Decr/Load methods so worker goroutines and the
// spinner goroutine can update and read counts safely.
type CommandCounter struct {
	Total     int64
	Pending   int64
	Complete  int64
	Error     int64
	Executing int64
}

func (c *CommandCounter) IncrTotal()     { atomic.AddInt64(&c.Total, 1) }
func (c *CommandCounter) IncrPending()   { atomic.AddInt64(&c.Pending, 1) }
func (c *CommandCounter) IncrComplete()  { atomic.AddInt64(&c.Complete, 1) }
func (c *CommandCounter) IncrError()     { atomic.AddInt64(&c.Error, 1) }
func (c *CommandCounter) IncrExecuting() { atomic.AddInt64(&c.Executing, 1) }

func (c *CommandCounter) DecrPending()   { atomic.AddInt64(&c.Pending, -1) }
func (c *CommandCounter) DecrExecuting() { atomic.AddInt64(&c.Executing, -1) }

func (c *CommandCounter) LoadTotal() int64    { return atomic.LoadInt64(&c.Total) }
func (c *CommandCounter) LoadComplete() int64 { return atomic.LoadInt64(&c.Complete) }
func (c *CommandCounter) LoadError() int64    { return atomic.LoadInt64(&c.Error) }

func SpinUntil(callingModuleName string, counter *CommandCounter, done chan bool, spinType string) {
	defer close(done)
	for {
		select {
		case <-time.After(1 * time.Second):
			fmt.Printf(clearln+"[%s] Status: %d/%d %s complete (%d errors -- For details check %s)", cyan(callingModuleName), counter.LoadComplete(), counter.LoadTotal(), spinType, counter.LoadError(), fmt.Sprintf("%s/cloudfox-error.log", ptr.ToString(GetLogDirPath())))
		case <-done:
			complete := counter.LoadComplete()
			fmt.Printf(clearln+"[%s] Status: %d/%d %s complete (%d errors -- For details check %s)\n", cyan(callingModuleName), complete, complete, spinType, counter.LoadError(), fmt.Sprintf("%s/cloudfox-error.log", ptr.ToString(GetLogDirPath())))
			done <- true
			return
		}
	}
}

func ReorganizeAWSProfiles(allProfiles []string, mgmtProfile string) []string {
	// take the mgmt profile, move it from its current position to the front of the list
	var newProfiles []string
	newProfiles = append(newProfiles, mgmtProfile)
	for _, profile := range allProfiles {
		if profile != mgmtProfile {
			newProfiles = append(newProfiles, profile)
		}
	}
	return newProfiles
}
