package aws

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"

	"github.com/BishopFox/cloudfox/aws/sdk"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/bishopfox/awsservicemap"
	"github.com/sirupsen/logrus"
)

type DatabasesModule struct {
	RDSClient      sdk.RDSClientInterface
	RedshiftClient sdk.AWSRedShiftClientInterface
	DynamoDBClient sdk.DynamoDBClientInterface
	DocDBClient    sdk.DocDBClientInterface

	Caller        sts.GetCallerIdentityOutput
	AWSRegions    []string
	AWSOutputType string
	AWSTableCols  string

	Goroutines int
	AWSProfile string
	WrapTable  bool

	Databases      []Database
	CommandCounter internal.CommandCounter
	Errors         []string
	// Used to store output data for pretty printing
	output internal.OutputData2
	modLog *logrus.Entry
}

type Database struct {
	AWSService string
	Region     string
	Engine     string
	Name       string
	Arn        string
	UserName   string
	Endpoint   string
	Port       int32
	Protocol   string
	Public     string
	Size       string
}

func (m *DatabasesModule) PrintDatabases(outputDirectory string, verbosity int) {
	// These struct values are used by the output module
	m.output.Verbosity = verbosity
	m.output.Directory = outputDirectory
	m.output.CallingModule = "databases"
	m.modLog = internal.TxtLog.WithFields(logrus.Fields{
		"module": m.output.CallingModule,
	})
	if m.AWSProfile == "" {
		m.AWSProfile = internal.BuildAWSPath(m.Caller)
	}

	fmt.Printf("[%s][%s] Enumerating databases for account %s.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), aws.ToString(m.Caller.Account))
	fmt.Printf("[%s][%s] Supported Services: RDS, DynamoDB\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))

	wg := new(sync.WaitGroup)
	semaphore := make(chan struct{}, m.Goroutines)
	// Create a channel to signal the spinner aka task status goroutine to finish
	spinnerDone := make(chan bool)
	//fire up the the task status spinner/updated
	go internal.SpinUntil(m.output.CallingModule, &m.CommandCounter, spinnerDone, "tasks")

	//create a channel to receive the objects
	dataReceiver := make(chan Database)

	// Create a channel to signal to stop
	receiverDone := make(chan bool)

	go m.Receiver(dataReceiver, receiverDone)

	//execute regional checks
	for _, region := range m.AWSRegions {
		wg.Add(1)
		go m.executeChecks(region, wg, semaphore, dataReceiver)
	}

	wg.Wait()

	// Send a message to the spinner goroutine to close the channel and stop
	spinnerDone <- true
	<-spinnerDone
	receiverDone <- true
	<-receiverDone

	sort.Slice(m.Databases, func(i, j int) bool {
		return m.Databases[i].AWSService < m.Databases[j].AWSService
	})

	m.output.Headers = []string{
		"Service",
		"Engine",
		"Region",
		"Name",
		"Size",
		"UserName",
		"Endpoint",
		//"Port",
		//"Protocol",
		//"Public",

	}

	// Table rows
	for i := range m.Databases {
		m.output.Body = append(
			m.output.Body,
			[]string{
				m.Databases[i].AWSService,
				m.Databases[i].Engine,
				m.Databases[i].Region,
				m.Databases[i].Name,
				m.Databases[i].Size,
				m.Databases[i].UserName,
				m.Databases[i].Endpoint,
				// strconv.Itoa(int(m.Databases[i].Port)),
				// m.Databases[i].Protocol,
				// m.Databases[i].Public,
			},
		)

	}
	if len(m.output.Body) > 0 {
		m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", fmt.Sprintf("%s-%s", m.AWSProfile, aws.ToString(m.Caller.Account)))

		o := internal.OutputClient{
			Verbosity:     verbosity,
			CallingModule: m.output.CallingModule,
			Table: internal.TableClient{
				Wrap: m.WrapTable,
			},
		}
		o.Table.TableFiles = append(o.Table.TableFiles, internal.TableFile{
			Header: m.output.Headers,
			Body:   m.output.Body,
			Name:   m.output.CallingModule,
		})
		o.PrefixIdentifier = m.AWSProfile
		o.Table.DirectoryName = filepath.Join(outputDirectory, "cloudfox-output", "aws", fmt.Sprintf("%s-%s", m.AWSProfile, aws.ToString(m.Caller.Account)))
		o.WriteFullOutput(o.Table.TableFiles, nil)
		m.writeLoot(o.Table.DirectoryName, verbosity)
		fmt.Printf("[%s][%s] %s databases found.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), strconv.Itoa(len(m.output.Body)))
	} else {
		fmt.Printf("[%s][%s] No databases found, skipping the creation of an output file.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	}
	fmt.Printf("[%s][%s] For context and next steps: https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#%s\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), m.output.CallingModule)

}

func (m *DatabasesModule) Receiver(receiver chan Database, receiverDone chan bool) {
	defer close(receiverDone)
	for {
		select {
		case data := <-receiver:
			m.Databases = append(m.Databases, data)
		case <-receiverDone:
			receiverDone <- true
			return
		}
	}
}

func (m *DatabasesModule) executeChecks(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Database) {
	defer wg.Done()

	servicemap := &awsservicemap.AwsServiceMap{
		JsonFileSource: "DOWNLOAD_FROM_AWS",
	}
	res, err := servicemap.IsServiceInRegion("rds", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		go m.getRdsClustersPerRegion(r, wg, semaphore, dataReceiver)
	}
	res, err = servicemap.IsServiceInRegion("redshift", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		m.getRedshiftDatabasesPerRegion(r, wg, semaphore, dataReceiver)
	}
	res, err = servicemap.IsServiceInRegion("dynamodb", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		m.getDynamoDBTablesPerRegion(r, wg, semaphore, dataReceiver)
	}
	res, err = servicemap.IsServiceInRegion("docdb", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		m.getDocDBTablesPerRegion(r, wg, semaphore, dataReceiver)
	}

}

func (m *DatabasesModule) writeLoot(outputDirectory string, verbosity int) {
	path := filepath.Join(outputDirectory, "loot")
	err := os.MkdirAll(path, os.ModePerm)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		panic(err.Error())
	}
	f := filepath.Join(path, "databases-UrlsOnly.txt")

	var out string

	for _, database := range m.Databases {
		out = out + fmt.Sprintln(database.Endpoint)
	}

	err = os.WriteFile(f, []byte(out), 0644)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		panic(err.Error())
	}

	if verbosity > 2 {
		fmt.Println()
		fmt.Printf("[%s][%s] %s \n", cyan(m.output.CallingModule), cyan(m.AWSProfile), green("Feed this databases into nmap and something like gowitness/aquatone for screenshots."))
		fmt.Print(out)
		fmt.Printf("[%s][%s] %s \n\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), green("End of loot file."))
	}

	fmt.Printf("[%s][%s] Loot written to [%s]\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), f)

}

func (m *DatabasesModule) getRdsClustersPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Database) {
	defer func() {
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
		wg.Done()

	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++

	DBInstances, err := sdk.CachedRDSDescribeDBInstances(m.RDSClient, aws.ToString(m.Caller.Account), r)
	if err != nil {
		if errors.As(err, &oe) {
			m.Errors = append(m.Errors, (fmt.Sprintf(" Error: Region: %s, Service: %s, Operation: %s", r, oe.Service(), oe.Operation())))
		}
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	var public string
	for _, instance := range DBInstances {
		if instance.Endpoint != nil {
			name := aws.ToString(instance.DBInstanceIdentifier)
			port := instance.Endpoint.Port
			endpoint := aws.ToString(instance.Endpoint.Address)
			engine := aws.ToString(instance.Engine)

			if instance.PubliclyAccessible {
				public = "True"
			} else {
				public = "False"
			}

			dataReceiver <- Database{
				AWSService: "RDS",
				Region:     r,
				Name:       name,
				Engine:     engine,
				Endpoint:   endpoint,
				UserName:   aws.ToString(instance.MasterUsername),
				Port:       port,
				Protocol:   aws.ToString(instance.Engine),
				Public:     public,
			}
		}

	}

}

func (m *DatabasesModule) getRedshiftDatabasesPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Database) {
	defer func() {
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
		wg.Done()

	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	awsService := "Redshift"
	protocol := "https"

	Clusters, err := sdk.CachedRedShiftDescribeClusters(m.RedshiftClient, aws.ToString(m.Caller.Account), r)

	if err != nil {
		if errors.As(err, &oe) {
			m.Errors = append(m.Errors, (fmt.Sprintf(" Error: Region: %s, Service: %s, Operation: %s", r, oe.Service(), oe.Operation())))
		}
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	var public string
	for _, cluster := range Clusters {
		name := aws.ToString(cluster.DBName)
		//id := workspace.Id
		endpoint := aws.ToString(cluster.Endpoint.Address)

		if cluster.PubliclyAccessible {
			public = "True"
		} else {
			public = "False"
		}
		port := cluster.Endpoint.Port
		dataReceiver <- Database{
			AWSService: awsService,
			Region:     r,
			Name:       name,
			Endpoint:   endpoint,
			Port:       port,
			Protocol:   protocol,
			Public:     public,
		}
	}
}

func (m *DatabasesModule) getDynamoDBTablesPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Database) {
	defer func() {
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
		wg.Done()

	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	awsService := "DynamoDB"

	Tables, err := sdk.CachedDynamoDBListTables(m.DynamoDBClient, aws.ToString(m.Caller.Account), r)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	for _, table := range Tables {
		//get size of dynamodb table
		TableOutput, err := sdk.CachedDynamoDBDescribeTable(m.DynamoDBClient, aws.ToString(m.Caller.Account), r, table)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			return
		}
		size := aws.ToInt64(TableOutput.TableSizeBytes)

		dataReceiver <- Database{
			AWSService: awsService,
			Region:     r,
			Name:       table,
			Size:       strconv.Itoa(int(size)),
			UserName:   "N/A",
			Endpoint:   "N/A",
		}
	}

}

func (m *DatabasesModule) getDocDBTablesPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Database) {
	defer func() {
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
		wg.Done()

	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	awsService := "DocDB"

	Clusters, err := sdk.CachedDocDBDescribeDBClusters(m.DocDBClient, aws.ToString(m.Caller.Account), r)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	for _, cluster := range Clusters {
		name := aws.ToString(cluster.DBClusterIdentifier)

		endpoint := aws.ToString(cluster.Endpoint)
		port := aws.ToInt32(cluster.Port)
		//size := aws.ToInt64(TableOutput.Table.TableSizeBytes)
		userName := aws.ToString(cluster.MasterUsername)

		dataReceiver <- Database{
			AWSService: awsService,
			Region:     r,
			Name:       name,
			Endpoint:   endpoint,
			Port:       port,
			UserName:   userName,
			//Size:       strconv.Itoa(int(size)),
		}
	}
}
