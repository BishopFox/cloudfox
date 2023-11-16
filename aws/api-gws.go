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

	"github.com/BishopFox/cloudfox/aws/sdk"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	apigatewayTypes "github.com/aws/aws-sdk-go-v2/service/apigateway/types"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	apigatewayV2Types "github.com/aws/aws-sdk-go-v2/service/apigatewayv2/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/bishopfox/awsservicemap"
	"github.com/sirupsen/logrus"
)

var CURL_COMMAND string = "curl -X %s %s"

type ApiGwModule struct {
	// General configuration data
	APIGatewayClient   *apigateway.Client
	APIGatewayv2Client *apigatewayv2.Client

	Caller     sts.GetCallerIdentityOutput
	AWSRegions []string
	Goroutines int
	AWSProfile string
	WrapTable  bool

	// Main module data
	Gateways       []ApiGateway
	CommandCounter internal.CommandCounter
	Errors         []string
	// Used to store output data for pretty printing
	output internal.OutputData2
	modLog *logrus.Entry
}

type ApiGateway struct {
	AWSService string
	Region     string
	Name       string
	Endpoint   string
	ApiKey     string
	Public     string
	Method     string
}

func (m *ApiGwModule) PrintApiGws(outputDirectory string, verbosity int) {
	m.output.Verbosity = verbosity
	m.output.Directory = outputDirectory
	m.output.CallingModule = "api-gw"
	m.modLog = internal.TxtLog.WithFields(logrus.Fields{
		"module": m.output.CallingModule,
	})
	if m.AWSProfile == "" {
		m.AWSProfile = internal.BuildAWSPath(m.Caller)
	}

	fmt.Printf("[%s][%s] Enumerating api-gateways for account %s.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), aws.ToString(m.Caller.Account))

	wg := new(sync.WaitGroup)
	semaphore := make(chan struct{}, m.Goroutines)
	// Create a channel to signal the spinner aka task status goroutine to finish
	spinnerDone := make(chan bool)
	//fire up the the task status spinner/updated
	go internal.SpinUntil(m.output.CallingModule, &m.CommandCounter, spinnerDone, "tasks")

	//create a channel to receive the objects
	dataReceiver := make(chan ApiGateway)

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

	sort.Slice(m.Gateways, func(i, j int) bool {
		return m.Gateways[i].AWSService < m.Gateways[j].AWSService
	})

	m.output.Headers = []string{
		"Service",
		"Region",
		"Name",
		"Method",
		"Endpoint",
		"ApiKey",
		"Public",
	}

	// Table rows
	for i := range m.Gateways {
		m.output.Body = append(
			m.output.Body,
			[]string{
				m.Gateways[i].AWSService,
				m.Gateways[i].Region,
				m.Gateways[i].Name,
				m.Gateways[i].Method,
				m.Gateways[i].Endpoint,
				m.Gateways[i].ApiKey,
				m.Gateways[i].Public,
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
		fmt.Printf("[%s][%s] %s API gateways found.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), strconv.Itoa(len(m.output.Body)))
	} else {
		fmt.Printf("[%s][%s] No API gateways found, skipping the creation of an output file.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	}
	fmt.Printf("[%s][%s] For context and next steps: https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#%s\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), m.output.CallingModule)
}

func (m *ApiGwModule) Receiver(receiver chan ApiGateway, receiverDone chan bool) {
	defer close(receiverDone)
	for {
		select {
		case data := <-receiver:
			m.Gateways = append(m.Gateways, data)
		case <-receiverDone:
			receiverDone <- true
			return
		}
	}
}

func (m *ApiGwModule) executeChecks(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan ApiGateway) {
	defer wg.Done()
	// check the concurrency semaphore
	// semaphore <- struct{}{}
	// defer func() {
	// 	<-semaphore
	// }()

	servicemap := &awsservicemap.AwsServiceMap{
		JsonFileSource: "DOWNLOAD_FROM_AWS",
	}
	res, err := servicemap.IsServiceInRegion("apigateway", r)
	if err != nil {
		m.modLog.Error(err)
	}
	if res {
		m.CommandCounter.Total++
		wg.Add(1)
		go m.getAPIGatewayAPIsPerRegion(r, wg, semaphore, dataReceiver)

		m.CommandCounter.Total++
		wg.Add(1)
		go m.getAPIGatewayVIPsPerRegion(r, wg, semaphore, dataReceiver)

		m.CommandCounter.Total++
		wg.Add(1)
		go m.getAPIGatewayv2APIsPerRegion(r, wg, semaphore, dataReceiver)

		m.CommandCounter.Total++
		wg.Add(1)
		go m.getAPIGatewayv2VIPsPerRegion(r, wg, semaphore, dataReceiver)
	}
}

func (m *ApiGwModule) writeLoot(outputDirectory string, verbosity int) {
	path := filepath.Join(outputDirectory, "loot")
	err := os.MkdirAll(path, os.ModePerm)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		panic(err.Error())
	}
	f := filepath.Join(path, "api-gws.txt")

	var out string

	for _, endpoint := range m.Gateways {
		method := endpoint.Method
		// Write a GET and POST for ANY
		if endpoint.Method == "ANY" {
			line := fmt.Sprintf(CURL_COMMAND, "GET", endpoint.Endpoint)
			if endpoint.ApiKey != "" {
				line += fmt.Sprintf(" -H 'X-Api-Key: %s'", endpoint.ApiKey)
			}

			out += line + "\n"

			method = "POST"
		}

		line := fmt.Sprintf(CURL_COMMAND, method, endpoint.Endpoint)
		if endpoint.ApiKey != "" {
			line += fmt.Sprintf(" -H 'X-Api-Key: %s'", endpoint.ApiKey)
		}

		if method == "DELETE" || method == "PATCH" || method == "POST" || method == "PUT" {
			line += " -H 'Content-Type: application/json' -d '{}'"
		}

		out += line + "\n"
	}

	err = os.WriteFile(f, []byte(out), 0644)
	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		panic(err.Error())
	}

	if verbosity > 2 {
		fmt.Println()
		fmt.Printf("[%s][%s] %s \n", cyan(m.output.CallingModule), cyan(m.AWSProfile), green("Send these requests through your favorite interception proxy"))
		fmt.Print(out)
		fmt.Printf("[%s][%s] %s \n\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), green("End of loot file."))
	}

	fmt.Printf("[%s][%s] Loot written to [%s]\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), f)

}

func (m *ApiGwModule) getAPIGatewayAPIsPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan ApiGateway) {
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
	// "PaginationMarker" is a control variable used for output continuity, as AWS return the output in pages.

	Items, err := sdk.CachedApiGatewayGetRestAPIs(m.APIGatewayClient, aws.ToString(m.Caller.Account), r)

	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	for _, api := range Items {
		for _, endpoint := range m.getEndpointsPerAPIGateway(r, api) {
			dataReceiver <- endpoint
		}
	}
}

func (m *ApiGwModule) getAPIGatewayVIPsPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan ApiGateway) {
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
	// "PaginationMarker" is a control variable used for output continuity, as AWS return the output in pages.

	var PaginationControl2 *string
	var PaginationControl3 *string

	Items, err := sdk.CachedApiGatewayGetRestAPIs(m.APIGatewayClient, aws.ToString(m.Caller.Account), r)

	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	for {
		GetDomainNames, err := m.APIGatewayClient.GetDomainNames(
			context.TODO(),
			&apigateway.GetDomainNamesInput{
				Position: PaginationControl2,
			},
			func(o *apigateway.Options) {
				o.Region = r
			},
		)

		if err != nil {
			m.Errors = append(m.Errors, fmt.Sprintf(" Error: Region: %s", r))
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		for _, item := range GetDomainNames.Items {

			domain := aws.ToString(item.DomainName)

			for {
				GetBasePathMappings, err := m.APIGatewayClient.GetBasePathMappings(
					context.TODO(),
					&apigateway.GetBasePathMappingsInput{
						DomainName: item.DomainName,
						Position:   PaginationControl3,
					},
					func(o *apigateway.Options) {
						o.Region = r
					},
				)

				if err != nil {
					m.Errors = append(m.Errors, fmt.Sprintf(" Error: Region: %s", r))
					m.modLog.Error(err.Error())
					m.CommandCounter.Error++
					break
				}

				for _, mapping := range GetBasePathMappings.Items {
					stage := aws.ToString(mapping.Stage)
					basePath := aws.ToString(mapping.BasePath)
					if basePath == "(none)" {
						basePath = "" // Empty string since '/' is already prepended
					}

					for _, api := range Items {
						if api.Id != nil && aws.ToString(api.Id) == aws.ToString(mapping.RestApiId) {
							endpoints := m.getEndpointsPerAPIGateway(r, api)
							for _, endpoint := range endpoints {
								old := fmt.Sprintf("https://%s.execute-api.%s.amazonaws.com/%s/", aws.ToString(mapping.RestApiId), r, stage)

								if strings.HasPrefix(endpoint.Endpoint, old) {
									var new string
									if basePath == "" {
										new = fmt.Sprintf("https://%s/", domain)
									} else {
										new = fmt.Sprintf("https://%s/%s/", domain, basePath)
									}
									endpoint.Endpoint = strings.Replace(endpoint.Endpoint, old, new, 1)
									endpoint.Name = domain
									dataReceiver <- endpoint
								}
							}
							break
						}
					}
				}

				if GetBasePathMappings.Position != nil {
					PaginationControl3 = GetBasePathMappings.Position
				} else {
					PaginationControl3 = nil
					break
				}
			}
		}
		if GetDomainNames.Position != nil {
			PaginationControl2 = GetDomainNames.Position
		} else {
			PaginationControl2 = nil
			break
		}
	}
}

func (m *ApiGwModule) getEndpointsPerAPIGateway(r string, api apigatewayTypes.RestApi) []ApiGateway {
	var gateways []ApiGateway

	var PaginationControl2 *string
	awsService := "APIGateway"
	var public string

	name := aws.ToString(api.Name)
	id := aws.ToString(api.Id)
	raw_endpoint := fmt.Sprintf("https://%s.execute-api.%s.amazonaws.com", id, r)

	endpointType := *api.EndpointConfiguration
	//fmt.Println(endpointType)
	if endpointType.Types[0] == "PRIVATE" {
		public = "False"
	} else {
		public = "True"
	}

	GetStages, err := m.APIGatewayClient.GetStages(
		context.TODO(),
		&apigateway.GetStagesInput{
			RestApiId: &id,
		},
		func(o *apigateway.Options) {
			o.Region = r
		},
	)

	if err != nil {
		m.Errors = append(m.Errors, fmt.Sprintf(" Error: Region: %s", r))
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
	}

	for {
		GetResources, err := m.APIGatewayClient.GetResources(
			context.TODO(),
			&apigateway.GetResourcesInput{
				RestApiId: &id,
				Position:  PaginationControl2,
			},
			func(o *apigateway.Options) {
				o.Region = r
			},
		)

		if err != nil {
			m.Errors = append(m.Errors, fmt.Sprintf(" Error: Region: %s", r))
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		for _, stage := range GetStages.Item {
			stageName := aws.ToString(stage.StageName)
			for _, resource := range GetResources.Items {
				if len(resource.ResourceMethods) != 0 {
					for method := range resource.ResourceMethods {

						// Check if API Key is required for endpoint
						apiKey := ""
						if m.ApiGatewayApiKeyRequired(r, api.Id, resource.Id, method) {
							apiKey, err = m.GetApiGatewayApiKey(r, id, stageName)
							if err != nil {
								m.Errors = append(m.Errors, fmt.Sprintf(" Error: Region: %s", r))
								m.modLog.Error(err.Error())
								m.CommandCounter.Error++
							}
						}

						path := aws.ToString(resource.Path)

						endpoint := fmt.Sprintf("%s/%s%s", raw_endpoint, stageName, path)

						gateways = append(gateways, ApiGateway{
							AWSService: awsService,
							Region:     r,
							Name:       name,
							Endpoint:   endpoint,
							Method:     method,
							Public:     public,
							ApiKey:     apiKey,
						})
					}
				}
			}
		}
		if GetResources.Position != nil {
			PaginationControl2 = GetResources.Position
		} else {
			PaginationControl2 = nil
			break
		}
	}
	return gateways
}

func (m *ApiGwModule) getAPIGatewayv2APIsPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan ApiGateway) {
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
	// "PaginationMarker" is a control variable used for output continuity, as AWS return the output in pages.

	Items, err := sdk.CachedAPIGatewayv2GetAPIs(m.APIGatewayv2Client, aws.ToString(m.Caller.Account), r)

	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}
	for _, api := range Items {
		for _, endpoint := range m.getEndpointsPerAPIGatewayv2(r, api) {
			dataReceiver <- endpoint
		}
	}

}

func (m *ApiGwModule) getAPIGatewayv2VIPsPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan ApiGateway) {
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
	// "PaginationMarker" is a control variable used for output continuity, as AWS return the output in pages.

	var PaginationControl2 *string
	var PaginationControl3 *string

	Items, err := sdk.CachedAPIGatewayv2GetAPIs(m.APIGatewayv2Client, aws.ToString(m.Caller.Account), r)

	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	for {
		GetDomainNames, err := m.APIGatewayv2Client.GetDomainNames(
			context.TODO(),
			&apigatewayv2.GetDomainNamesInput{
				NextToken: PaginationControl2,
			},
			func(o *apigatewayv2.Options) {
				o.Region = r
			},
		)

		if err != nil {
			m.Errors = append(m.Errors, fmt.Sprintf(" Error: Region: %s", r))
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		for _, item := range GetDomainNames.Items {

			domain := aws.ToString(item.DomainName)

			for {
				GetApiMappings, err := m.APIGatewayv2Client.GetApiMappings(
					context.TODO(),
					&apigatewayv2.GetApiMappingsInput{
						DomainName: item.DomainName,
						NextToken:  PaginationControl3,
					},
					func(o *apigatewayv2.Options) {
						o.Region = r
					},
				)

				if err != nil {
					m.Errors = append(m.Errors, fmt.Sprintf(" Error: Region: %s", r))
					m.modLog.Error(err.Error())
					m.CommandCounter.Error++
					break
				}

				for _, mapping := range GetApiMappings.Items {
					stage := aws.ToString(mapping.Stage)
					if stage == "$default" {
						stage = ""
					}
					path := aws.ToString(mapping.ApiMappingKey)

					for _, api := range Items {
						if api.ApiId != nil && aws.ToString(api.ApiId) == aws.ToString(mapping.ApiId) {
							endpoints := m.getEndpointsPerAPIGatewayv2(r, api)
							for _, endpoint := range endpoints {
								var old string
								if stage == "" {
									old = fmt.Sprintf("https://%s.execute-api.%s.amazonaws.com/", aws.ToString(mapping.ApiId), r)
								} else {
									old = fmt.Sprintf("https://%s.execute-api.%s.amazonaws.com/%s/", aws.ToString(mapping.ApiId), r, stage)
								}
								if strings.HasPrefix(endpoint.Endpoint, old) {
									var new string
									if path == "" {
										new = fmt.Sprintf("https://%s/", domain)
									} else {
										new = fmt.Sprintf("https://%s/%s/", domain, path)
									}
									endpoint.Endpoint = strings.Replace(endpoint.Endpoint, old, new, 1)
									endpoint.Name = domain
									dataReceiver <- endpoint
								}
							}
							break
						}
					}
				}

				if GetApiMappings.NextToken != nil {
					PaginationControl3 = GetApiMappings.NextToken
				} else {
					PaginationControl3 = nil
					break
				}
			}
		}
		if GetDomainNames.NextToken != nil {
			PaginationControl2 = GetDomainNames.NextToken
		} else {
			PaginationControl2 = nil
			break
		}
	}
}

func (m *ApiGwModule) getEndpointsPerAPIGatewayv2(r string, api apigatewayV2Types.Api) []ApiGateway {
	var gateways []ApiGateway

	var PaginationControl2 *string
	var PaginationControl3 *string
	awsService := "APIGatewayv2"

	var public string

	name := aws.ToString(api.Name)
	raw_endpoint := aws.ToString(api.ApiEndpoint)
	id := aws.ToString(api.ApiId)

	var stages []string
	for {
		GetStages, err := m.APIGatewayv2Client.GetStages(
			context.TODO(),
			&apigatewayv2.GetStagesInput{
				ApiId:     &id,
				NextToken: PaginationControl2,
			},
			func(o *apigatewayv2.Options) {
				o.Region = r
			},
		)

		if err != nil {
			m.Errors = append(m.Errors, fmt.Sprintf(" Error: Region: %s", r))
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		for _, stage := range GetStages.Items {
			s := aws.ToString(stage.StageName)
			if s == "$default" {
				s = ""
			}
			stages = append(stages, s)
		}

		if GetStages.NextToken != nil {
			PaginationControl2 = GetStages.NextToken
		} else {
			PaginationControl2 = nil
			break
		}
	}

	for {
		GetRoutes, err := m.APIGatewayv2Client.GetRoutes(
			context.TODO(),
			&apigatewayv2.GetRoutesInput{
				ApiId:     &id,
				NextToken: PaginationControl3,
			},
			func(o *apigatewayv2.Options) {
				o.Region = r
			},
		)

		if err != nil {
			m.Errors = append(m.Errors, fmt.Sprintf(" Error: Region: %s", r))
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			continue
		}

		for _, stage := range stages {
			for _, route := range GetRoutes.Items {
				routeKey := route.RouteKey
				var method string
				var path string
				if len(strings.Fields(*routeKey)) == 2 {
					method = strings.Fields(*routeKey)[0]
					path = strings.Fields(*routeKey)[1]
				}
				var endpoint string
				if stage == "" {
					endpoint = fmt.Sprintf("%s%s", raw_endpoint, path)
				} else {
					endpoint = fmt.Sprintf("%s/%s%s", raw_endpoint, stage, path)
				}
				public = "True"

				gateways = append(gateways, ApiGateway{
					AWSService: awsService,
					Region:     r,
					Name:       name,
					Method:     method,
					Endpoint:   endpoint,
					Public:     public,
				})
			}
		}
		if GetRoutes.NextToken != nil {
			PaginationControl3 = GetRoutes.NextToken
		} else {
			PaginationControl3 = nil
			break
		}

	}
	return gateways
}

func (m *ApiGwModule) ApiGatewayApiKeyRequired(r string, ApiId *string, ResourceId *string, method string) bool {
	GetMethod, err := m.APIGatewayClient.GetMethod(
		context.TODO(),
		&apigateway.GetMethodInput{
			RestApiId:  ApiId,
			ResourceId: ResourceId,
			HttpMethod: &method,
		},
		func(o *apigateway.Options) {
			o.Region = r
		},
	)

	if err != nil {
		m.Errors = append(m.Errors, fmt.Sprintf(" Error: Region: %s", r))
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
	} else {
		return aws.ToBool(GetMethod.ApiKeyRequired)
	}
	return false
}

func (m *ApiGwModule) GetApiGatewayApiKey(r string, ApiId string, Stage string) (string, error) {
	var PaginationControl *string
	var items []apigatewayTypes.UsagePlan

	for {
		GetUsagePlans, err := m.APIGatewayClient.GetUsagePlans(
			context.TODO(),
			&apigateway.GetUsagePlansInput{
				Position: PaginationControl,
			},
			func(o *apigateway.Options) {
				o.Region = r
			},
		)

		if err != nil {
			return "", err
		}

		for _, item := range GetUsagePlans.Items {
			items = append(items, item)
		}

		if GetUsagePlans.Position != nil {
			PaginationControl = GetUsagePlans.Position
		} else {
			PaginationControl = nil
			break
		}
	}

	for _, item := range items {
		for _, apiStage := range item.ApiStages {
			if aws.ToString(apiStage.ApiId) == ApiId && aws.ToString(apiStage.Stage) == Stage {
				// Found

				for {
					GetUsagePlanKeys, err := m.APIGatewayClient.GetUsagePlanKeys(
						context.TODO(),
						&apigateway.GetUsagePlanKeysInput{
							UsagePlanId: item.Id,
							Position:    PaginationControl,
						},
						func(o *apigateway.Options) {
							o.Region = r
						},
					)

					if err != nil {
						return "", err
					}

					for _, i := range GetUsagePlanKeys.Items {
						if aws.ToString(i.Type) == "API_KEY" {
							return aws.ToString(i.Value), nil
						}
					}

					if GetUsagePlanKeys.Position != nil {
						PaginationControl = GetUsagePlanKeys.Position
					} else {
						PaginationControl = nil
						break
					}
				}
			}
		}
	}

	return "", nil
}
