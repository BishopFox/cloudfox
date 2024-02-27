package aws

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
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
	NeptuneClient  sdk.NeptuneClientInterface

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
	Roles      string
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
	fmt.Printf("[%s][%s] Supported Services: RDS, Redshift, DynamoDB, DocumentDB, Neptune\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))

	wg := new(sync.WaitGroup)
	semaphore := make(chan struct{}, m.Goroutines)
	// Create a channel to signal the spinner aka task status goroutine to finish
	spinnerDone := make(chan bool)
	//fire up the task status spinner/updated
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
		"Account",
		"Service",
		"Engine",
		"Region",
		"Name",
		"Size",
		"UserName",
		"Endpoint",
		"Port",
		"Roles",
		//"Protocol",
		//"Public",

	}

	// If the user specified table columns, use those.
	// If the user specified -o wide, use the wide default cols for this module.
	// Otherwise, use the hardcoded default cols for this module.
	var tableCols []string
	// If the user specified table columns, use those.
	if m.AWSTableCols != "" {
		// If the user specified wide as the output format, use these columns.
		// remove any spaces between any commas and the first letter after the commas
		m.AWSTableCols = strings.ReplaceAll(m.AWSTableCols, ", ", ",")
		m.AWSTableCols = strings.ReplaceAll(m.AWSTableCols, ",  ", ",")
		tableCols = strings.Split(m.AWSTableCols, ",")
	} else if m.AWSOutputType == "wide" {
		tableCols = []string{
			"Account",
			"Service",
			"Engine",
			"Region",
			"Name",
			"Size",
			"UserName",
			"Endpoint",
			"Port",
			"Roles",
		}
		// Otherwise, use the default columns.
	} else {
		tableCols = []string{
			"Service",
			"Engine",
			"Region",
			"Name",
			"Size",
			"UserName",
			"Endpoint",
			"Port",
		}
	}

	// Table rows
	for i := range m.Databases {
		m.output.Body = append(
			m.output.Body,
			[]string{
				aws.ToString(m.Caller.Account),
				m.Databases[i].AWSService,
				m.Databases[i].Engine,
				m.Databases[i].Region,
				m.Databases[i].Name,
				m.Databases[i].Size,
				m.Databases[i].UserName,
				m.Databases[i].Endpoint,
				strconv.Itoa(int(m.Databases[i].Port)),
				m.Databases[i].Roles,
				// m.Databases[i].Protocol,
				// m.Databases[i].Public,
			},
		)

	}
	if len(m.output.Body) > 0 {
		filepath := filepath.Join(outputDirectory, "cloudfox-output", "aws", fmt.Sprintf("%s-%s", m.AWSProfile, aws.ToString(m.Caller.Account)))

		o := internal.OutputClient{
			Verbosity:     verbosity,
			CallingModule: m.output.CallingModule,
			Table: internal.TableClient{
				Wrap:          m.WrapTable,
				DirectoryName: filepath,
			},
			Loot: internal.LootClient{
				DirectoryName: filepath,
			},
		}
		o.Table.TableFiles = append(o.Table.TableFiles, internal.TableFile{
			Header:    m.output.Headers,
			Body:      m.output.Body,
			TableCols: tableCols,
			Name:      m.output.CallingModule,
		})
		o.PrefixIdentifier = m.AWSProfile
		loot := m.writeLoot(filepath, verbosity)
		//o.Table.DirectoryName = filepath.Join(outputDirectory, "cloudfox-output", "aws", fmt.Sprintf("%s-%s", m.AWSProfile, aws.ToString(m.Caller.Account)))
		//m.writeLoot(o.Table.DirectoryName, verbosity)
		o.Loot.LootFiles = append(o.Loot.LootFiles, internal.LootFile{
			Name:     "databases-UrlsOnly.txt",
			Contents: loot,
		})
		o.WriteFullOutput(o.Table.TableFiles, o.Loot.LootFiles)

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

	serviceMap := &awsservicemap.AwsServiceMap{
		JsonFileSource: "DOWNLOAD_FROM_AWS",
	}
	m.executeRdsCheck(r, wg, semaphore, dataReceiver, serviceMap) // Also returns Neptune and DocDB
	m.executeRedshiftCheck(r, wg, semaphore, dataReceiver, serviceMap)
	m.executeDynamoDbCheck(r, wg, semaphore, dataReceiver, serviceMap)
	//m.executeDocDbCheck(r, wg, semaphore, dataReceiver, serviceMap)
	//m.executeNeptuneCheck(r, wg, semaphore, dataReceiver, serviceMap)
}

type check struct {
	region       string
	wg           *sync.WaitGroup
	semaphore    chan struct{}
	dataReceiver chan Database
	serviceMap   *awsservicemap.AwsServiceMap
	service      string
	executor     func(string, *sync.WaitGroup, chan struct{}, chan Database)
}

func (m *DatabasesModule) executeCheck(check check) {
	res, err := check.serviceMap.IsServiceInRegion(check.service, check.region)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		check.wg.Add(1)
		go check.executor(check.region, check.wg, check.semaphore, check.dataReceiver)
	}
}

func (m *DatabasesModule) executeRdsCheck(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Database, servicemap *awsservicemap.AwsServiceMap) {
	m.executeCheck(check{
		region:       r,
		wg:           wg,
		semaphore:    semaphore,
		dataReceiver: dataReceiver,
		serviceMap:   servicemap,
		service:      "rds",
		executor:     m.getRdsClustersPerRegion,
	})
}

func (m *DatabasesModule) executeRedshiftCheck(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Database, servicemap *awsservicemap.AwsServiceMap) {
	m.executeCheck(check{
		region:       r,
		wg:           wg,
		semaphore:    semaphore,
		dataReceiver: dataReceiver,
		serviceMap:   servicemap,
		service:      "redshift",
		executor:     m.getRedshiftDatabasesPerRegion,
	})
}

func (m *DatabasesModule) executeDynamoDbCheck(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Database, servicemap *awsservicemap.AwsServiceMap) {
	m.executeCheck(check{
		region:       r,
		wg:           wg,
		semaphore:    semaphore,
		dataReceiver: dataReceiver,
		serviceMap:   servicemap,
		service:      "dynamodb",
		executor:     m.getDynamoDBTablesPerRegion,
	})
}

func (m *DatabasesModule) executeDocDbCheck(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Database, servicemap *awsservicemap.AwsServiceMap) {
	m.executeCheck(check{
		region:       r,
		wg:           wg,
		semaphore:    semaphore,
		dataReceiver: dataReceiver,
		serviceMap:   servicemap,
		service:      "docdb",
		executor:     m.getDocDBTablesPerRegion,
	})
}

func (m *DatabasesModule) executeNeptuneCheck(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Database, servicemap *awsservicemap.AwsServiceMap) {
	m.executeCheck(check{
		region:       r,
		wg:           wg,
		semaphore:    semaphore,
		dataReceiver: dataReceiver,
		serviceMap:   servicemap,
		service:      "neptune",
		executor:     m.getNeptuneDatabasesPerRegion,
	})
}

func (m *DatabasesModule) writeLoot(outputDirectory string, verbosity int) string {
	path := filepath.Join(outputDirectory, "loot")
	f := filepath.Join(path, "databases-UrlsOnly.txt")

	var out string

	for _, database := range m.Databases {
		out = out + fmt.Sprintln(database.Endpoint)
	}

	// err = os.WriteFile(f, []byte(out), 0644)
	// if err != nil {
	// 	m.modLog.Error(err.Error())
	// 	m.CommandCounter.Error++
	// 	panic(err.Error())
	// }

	if verbosity > 2 {
		fmt.Println()
		fmt.Printf("[%s][%s] %s \n", cyan(m.output.CallingModule), cyan(m.AWSProfile), green("Feed this databases into nmap and something like gowitness/aquatone for screenshots."))
		fmt.Print(out)
		fmt.Printf("[%s][%s] %s \n\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), green("End of loot file."))
	}

	fmt.Printf("[%s][%s] Loot written to [%s]\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), f)

	return out

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

	DBClusters, err := sdk.CachedRDSDescribeDBClusters(m.RDSClient, aws.ToString(m.Caller.Account), r)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	for _, cluster := range DBClusters {
		var public string
		var service string
		var roles string
		if cluster.Endpoint == nil {
			continue
		}

		name := aws.ToString(cluster.DBClusterIdentifier)
		port := cluster.Port
		endpoint := aws.ToString(cluster.Endpoint)
		engine := aws.ToString(cluster.Engine)

		if aws.ToBool(cluster.PubliclyAccessible) {
			public = "True"
		} else {
			public = "False"
		}

		if isNeptune(cluster.Engine) {
			service = "Neptune"
		} else if isDocDB(cluster.Engine) {
			service = "DocsDB"
		} else {
			service = "RDS"
		}

		associatedRoles := cluster.AssociatedRoles
		for _, role := range associatedRoles {
			roles = roles + aws.ToString(role.RoleArn) + " "
		}

		dataReceiver <- Database{
			AWSService: service,
			Region:     r,
			Name:       name,
			Engine:     engine,
			Endpoint:   endpoint,
			UserName:   aws.ToString(cluster.MasterUsername),
			Port:       aws.ToInt32(port),
			Protocol:   aws.ToString(cluster.Engine),
			Public:     public,
			Roles:      roles,
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
			m.Errors = append(m.Errors, fmt.Sprintf(" Error: Region: %s, Service: %s, Operation: %s", r, oe.Service(), oe.Operation()))
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
		port := aws.ToInt32(cluster.Endpoint.Port)

		if aws.ToBool(cluster.PubliclyAccessible) {
			public = "True"
		} else {
			public = "False"
		}
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

func (m *DatabasesModule) getNeptuneDatabasesPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan Database) {
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

	clusters, err := sdk.CachedNeptuneDescribeDBClusters(m.NeptuneClient, aws.ToString(m.Caller.Account), r)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	for _, cluster := range clusters {
		if !isNeptune(cluster.Engine) {
			continue
		}

		name := aws.ToString(cluster.DBClusterIdentifier)

		endpoint := aws.ToString(cluster.Endpoint)
		port := aws.ToInt32(cluster.Port)
		userName := aws.ToString(cluster.MasterUsername)
		engine := aws.ToString(cluster.Engine)

		dataReceiver <- Database{
			AWSService: "Neptune",
			Region:     r,
			Name:       name,
			Engine:     engine,
			Endpoint:   endpoint,
			Port:       port,
			UserName:   userName,
		}
	}
}

func isNeptune(engine *string) bool {
	return *engine == "neptune"
}

func isDocDB(engine *string) bool {
	return *engine == "docdb"
}
