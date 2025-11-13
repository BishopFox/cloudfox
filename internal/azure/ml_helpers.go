package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/machinelearning/armmachinelearning"
	"github.com/BishopFox/cloudfox/globals"
)

// ==================== MACHINE LEARNING STRUCTS ====================

type MLWorkspaceInfo struct {
	WorkspaceName    string
	ResourceGroup    string
	Region           string
	SubscriptionID   string
	SubscriptionName string
	WorkspaceID      string
}

type MLDatastoreCredential struct {
	WorkspaceName  string
	ResourceGroup  string
	Region         string
	CredentialType string
	ServiceType    string
	StorageAccount string
	Container      string
	Server         string
	Database       string
	Username       string
	Password       string
	ClientID       string
	ClientSecret   string
	TenantID       string
	SASToken       string
}

type MLComputeInstance struct {
	WorkspaceName    string
	ResourceGroup    string
	Region           string
	ComputeName      string
	ComputeType      string
	VMSize           string
	SSHPublicAccess  string
	SSHAdminUser     string
	SSHPort          string
	PublicIPAddress  string
	PrivateIPAddress string
	State            string
}

type MLEndpoint struct {
	WorkspaceName string
	ResourceGroup string
	Region        string
	EndpointName  string
	ScoringURI    string
	SwaggerURI    string
	AuthMode      string
	PrimaryKey    string
	SecondaryKey  string
}

type MLConnection struct {
	WorkspaceName  string
	ResourceGroup  string
	Region         string
	ConnectionName string
	ConnectionType string
	Secret         string
}

// ==================== MACHINE LEARNING HELPERS ====================

// GetMLWorkspaces returns all ML workspaces in a subscription
func GetMLWorkspaces(session *SafeSession, subID string, resourceGroups []string) ([]*armmachinelearning.Workspace, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil, err
	}
	cred := &StaticTokenCredential{Token: token}
	ctx := context.Background()

	client, err := armmachinelearning.NewWorkspacesClient(subID, cred, nil)
	if err != nil {
		return nil, err
	}

	var workspaces []*armmachinelearning.Workspace

	// If specific resource groups provided, enumerate those
	if len(resourceGroups) > 0 {
		for _, rgName := range resourceGroups {
			pager := client.NewListByResourceGroupPager(rgName, nil)
			for pager.More() {
				page, err := pager.NextPage(ctx)
				if err != nil {
					continue
				}
				workspaces = append(workspaces, page.Value...)
			}
		}
	} else {
		// Otherwise, enumerate all workspaces in subscription
		pager := client.NewListBySubscriptionPager(nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return workspaces, err
			}
			workspaces = append(workspaces, page.Value...)
		}
	}

	return workspaces, nil
}

// GetMLDatastoreCredentials extracts credentials from ML workspace datastores via REST API
func GetMLDatastoreCredentials(session *SafeSession, subID, rgName, workspaceName, region string) []MLDatastoreCredential {
	token, err := session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil
	}

	var results []MLDatastoreCredential

	// Get default datastore with retry logic
	defaultURL := fmt.Sprintf("https://ml.azure.com/api/%s/datastore/v1.0/subscriptions/%s/resourceGroups/%s/providers/Microsoft.MachineLearningServices/workspaces/%s/default",
		region, subID, rgName, workspaceName)

	config := DefaultRateLimitConfig()
	config.MaxRetries = 5
	config.InitialDelay = 2 * time.Second
	config.MaxDelay = 2 * time.Minute

	body, err := HTTPRequestWithRetry(context.Background(), "GET", defaultURL, token, nil, config)
	if err == nil {
		var defaultDS struct {
			AzureStorageSection struct {
				AccountName   string `json:"accountName"`
				ContainerName string `json:"containerName"`
				Credential    string `json:"credential"`
			} `json:"azureStorageSection"`
		}
		if json.Unmarshal(body, &defaultDS) == nil {
			results = append(results, MLDatastoreCredential{
				WorkspaceName:  workspaceName,
				ResourceGroup:  rgName,
				Region:         region,
				CredentialType: "Default Workspace Storage",
				ServiceType:    "StorageAccount",
				StorageAccount: defaultDS.AzureStorageSection.AccountName,
				Container:      defaultDS.AzureStorageSection.ContainerName,
				SASToken:       defaultDS.AzureStorageSection.Credential,
			})
		}
	}

	// Get all datastores with secrets using retry logic
	datastoreURL := fmt.Sprintf("https://ml.azure.com/api/%s/datastore/v1.0/subscriptions/%s/resourceGroups/%s/providers/Microsoft.MachineLearningServices/workspaces/%s/datastores/?getSecret=true",
		region, subID, rgName, workspaceName)

	body2, err := HTTPRequestWithRetry(context.Background(), "GET", datastoreURL, token, nil, config)
	if err != nil {
		return results
	}

	var datastores struct {
		Value []struct {
			Name                    string `json:"name"`
			AzureSQLDatabaseSection *struct {
				ServerName     string `json:"serverName"`
				DatabaseName   string `json:"databaseName"`
				CredentialType string `json:"credentialType"`
				UserID         string `json:"userId"`
				UserPassword   string `json:"userPassword"`
				ClientID       string `json:"clientId"`
				ClientSecret   string `json:"clientSecret"`
				TenantID       string `json:"tenantId"`
			} `json:"azureSqlDatabaseSection"`
			AzureMySQLSection *struct {
				ServerName   string `json:"serverName"`
				DatabaseName string `json:"databaseName"`
				UserID       string `json:"userId"`
				UserPassword string `json:"userPassword"`
			} `json:"azureMySqlSection"`
			AzurePostgreSQLSection *struct {
				ServerName   string `json:"serverName"`
				DatabaseName string `json:"databaseName"`
				UserID       string `json:"userId"`
				UserPassword string `json:"userPassword"`
			} `json:"azurePostgreSqlSection"`
			AzureDataLakeSection *struct {
				StoreName    string `json:"storeName"`
				ClientID     string `json:"clientId"`
				ClientSecret string `json:"clientSecret"`
				TenantID     string `json:"tenantId"`
			} `json:"azureDataLakeSection"`
			AzureStorageSection *struct {
				AccountName       string `json:"accountName"`
				ContainerName     string `json:"containerName"`
				Credential        string `json:"credential"`
				ClientCredentials *struct {
					ClientID     string `json:"clientId"`
					ClientSecret string `json:"clientSecret"`
					TenantID     string `json:"tenantId"`
				} `json:"clientCredentials"`
			} `json:"azureStorageSection"`
		} `json:"value"`
	}

	if err := json.Unmarshal(body2, &datastores); err != nil {
		return results
	}

	for _, ds := range datastores.Value {
		// Azure SQL Database
		if ds.AzureSQLDatabaseSection != nil {
			cred := MLDatastoreCredential{
				WorkspaceName:  workspaceName,
				ResourceGroup:  rgName,
				Region:         region,
				ServiceType:    "AzureSQLDatabase",
				Server:         ds.AzureSQLDatabaseSection.ServerName,
				Database:       ds.AzureSQLDatabaseSection.DatabaseName,
				CredentialType: ds.AzureSQLDatabaseSection.CredentialType,
			}
			if ds.AzureSQLDatabaseSection.CredentialType == "SqlAuthentication" {
				cred.Username = ds.AzureSQLDatabaseSection.UserID
				cred.Password = ds.AzureSQLDatabaseSection.UserPassword
			} else if ds.AzureSQLDatabaseSection.CredentialType == "ServicePrincipal" {
				cred.ClientID = ds.AzureSQLDatabaseSection.ClientID
				cred.ClientSecret = ds.AzureSQLDatabaseSection.ClientSecret
				cred.TenantID = ds.AzureSQLDatabaseSection.TenantID
			}
			results = append(results, cred)
		}

		// MySQL
		if ds.AzureMySQLSection != nil {
			results = append(results, MLDatastoreCredential{
				WorkspaceName:  workspaceName,
				ResourceGroup:  rgName,
				Region:         region,
				ServiceType:    "MySQLDatabase",
				Server:         ds.AzureMySQLSection.ServerName,
				Database:       ds.AzureMySQLSection.DatabaseName,
				CredentialType: "SqlAuthentication",
				Username:       ds.AzureMySQLSection.UserID,
				Password:       ds.AzureMySQLSection.UserPassword,
			})
		}

		// PostgreSQL
		if ds.AzurePostgreSQLSection != nil {
			results = append(results, MLDatastoreCredential{
				WorkspaceName:  workspaceName,
				ResourceGroup:  rgName,
				Region:         region,
				ServiceType:    "PostgreSQLDatabase",
				Server:         ds.AzurePostgreSQLSection.ServerName,
				Database:       ds.AzurePostgreSQLSection.DatabaseName,
				CredentialType: "SqlAuthentication",
				Username:       ds.AzurePostgreSQLSection.UserID,
				Password:       ds.AzurePostgreSQLSection.UserPassword,
			})
		}

		// Data Lake Gen1
		if ds.AzureDataLakeSection != nil {
			results = append(results, MLDatastoreCredential{
				WorkspaceName:  workspaceName,
				ResourceGroup:  rgName,
				Region:         region,
				ServiceType:    "DataLakeGen1",
				Server:         ds.AzureDataLakeSection.StoreName,
				CredentialType: "ServicePrincipal",
				ClientID:       ds.AzureDataLakeSection.ClientID,
				ClientSecret:   ds.AzureDataLakeSection.ClientSecret,
				TenantID:       ds.AzureDataLakeSection.TenantID,
			})
		}

		// Storage Account / Data Lake Gen2
		if ds.AzureStorageSection != nil {
			if ds.AzureStorageSection.ClientCredentials != nil {
				// Data Lake Gen2 with SP
				results = append(results, MLDatastoreCredential{
					WorkspaceName:  workspaceName,
					ResourceGroup:  rgName,
					Region:         region,
					ServiceType:    "DataLakeGen2",
					StorageAccount: ds.AzureStorageSection.AccountName,
					Container:      ds.AzureStorageSection.ContainerName,
					CredentialType: "ServicePrincipal",
					ClientID:       ds.AzureStorageSection.ClientCredentials.ClientID,
					ClientSecret:   ds.AzureStorageSection.ClientCredentials.ClientSecret,
					TenantID:       ds.AzureStorageSection.ClientCredentials.TenantID,
				})
			} else {
				// Regular storage account with SAS
				results = append(results, MLDatastoreCredential{
					WorkspaceName:  workspaceName,
					ResourceGroup:  rgName,
					Region:         region,
					ServiceType:    "StorageAccount",
					StorageAccount: ds.AzureStorageSection.AccountName,
					Container:      ds.AzureStorageSection.ContainerName,
					SASToken:       ds.AzureStorageSection.Credential,
				})
			}
		}
	}

	return results
}

// GetMLComputeInstances returns compute instances for a workspace via SDK
func GetMLComputeInstances(session *SafeSession, subID, rgName, workspaceName string) []MLComputeInstance {
	token, err := session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil
	}
	cred := &StaticTokenCredential{Token: token}
	ctx := context.Background()

	client, err := armmachinelearning.NewComputeClient(subID, cred, nil)
	if err != nil {
		return nil
	}

	var results []MLComputeInstance

	pager := client.NewListPager(rgName, workspaceName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}

		for _, compute := range page.Value {
			computeName := SafeStringPtr(compute.Name)
			computeType := "Unknown"

			// Type assertion for ComputeInstance properties
			if compute.Properties != nil {
				switch props := compute.Properties.(type) {
				case *armmachinelearning.ComputeInstance:
					computeType = "ComputeInstance"
					instance := MLComputeInstance{
						WorkspaceName: workspaceName,
						ResourceGroup: rgName,
						ComputeName:   computeName,
						ComputeType:   computeType,
					}
					if props.Properties != nil {
						if props.Properties.VMSize != nil {
							instance.VMSize = *props.Properties.VMSize
						}
						if props.Properties.State != nil {
							instance.State = string(*props.Properties.State)
						}
						if props.Properties.SSHSettings != nil {
							if props.Properties.SSHSettings.SSHPublicAccess != nil {
								instance.SSHPublicAccess = string(*props.Properties.SSHSettings.SSHPublicAccess)
							}
							if props.Properties.SSHSettings.AdminUserName != nil {
								instance.SSHAdminUser = *props.Properties.SSHSettings.AdminUserName
							}
							if props.Properties.SSHSettings.SSHPort != nil {
								instance.SSHPort = fmt.Sprintf("%d", *props.Properties.SSHSettings.SSHPort)
							}
						}
						if props.Properties.ConnectivityEndpoints != nil {
							if props.Properties.ConnectivityEndpoints.PublicIPAddress != nil {
								instance.PublicIPAddress = *props.Properties.ConnectivityEndpoints.PublicIPAddress
							}
							if props.Properties.ConnectivityEndpoints.PrivateIPAddress != nil {
								instance.PrivateIPAddress = *props.Properties.ConnectivityEndpoints.PrivateIPAddress
							}
						}
					}
					results = append(results, instance)
				}
			}
		}
	}

	return results
}

// GetMLConnections returns workspace connections with secrets
func GetMLConnections(session *SafeSession, subID, rgName, workspaceName string) []MLConnection {
	token, err := session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil
	}

	var results []MLConnection

	// List connections with retry logic
	url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.MachineLearningServices/workspaces/%s/connections?api-version=2023-08-01-preview",
		subID, rgName, workspaceName)

	config := DefaultRateLimitConfig()
	config.MaxRetries = 5
	config.InitialDelay = 2 * time.Second
	config.MaxDelay = 2 * time.Minute

	body, err := HTTPRequestWithRetry(context.Background(), "GET", url, token, nil, config)
	if err != nil {
		return nil
	}

	var connections struct {
		Value []struct {
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"value"`
	}

	if err := json.Unmarshal(body, &connections); err != nil {
		return nil
	}

	// For each connection, get the secret with retry logic
	for _, conn := range connections.Value {
		secretURL := fmt.Sprintf("https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.MachineLearningServices/workspaces/%s/connections/%s/listsecrets?api-version=2023-08-01-preview",
			subID, rgName, workspaceName, conn.Name)

		secretBody, err := HTTPRequestWithRetry(context.Background(), "POST", secretURL, token, nil, config)
		if err != nil {
			continue
		}

		var secretData struct {
			Properties struct {
				Credentials struct {
					Key string `json:"key"`
				} `json:"credentials"`
			} `json:"properties"`
		}

		if json.Unmarshal(secretBody, &secretData) == nil {
			results = append(results, MLConnection{
				WorkspaceName:  workspaceName,
				ResourceGroup:  rgName,
				ConnectionName: conn.Name,
				ConnectionType: conn.Type,
				Secret:         secretData.Properties.Credentials.Key,
			})
		}
	}

	return results
}
