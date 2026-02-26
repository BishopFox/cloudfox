// Package databaseservice provides Azure Database service abstractions
//
// This service layer abstracts Azure Database API calls from command modules,
// following the standardized pattern established in STANDARDIZATION.md.
package databaseservice

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cosmos/armcosmos"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/mysql/armmysqlflexibleservers"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/postgresql/armpostgresqlflexibleservers"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql"
	"github.com/BishopFox/cloudfox/globals"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/patrickmn/go-cache"
)

// serviceCache is the centralized cache for database service calls
var serviceCache = cache.New(2*time.Hour, 10*time.Minute)

// cacheKey generates a consistent cache key from components
func cacheKey(parts ...string) string {
	result := "databaseservice"
	for _, part := range parts {
		result += "-" + part
	}
	return result
}

// DatabaseService provides methods for interacting with Azure Database resources
type DatabaseService struct {
	session *azinternal.SafeSession
}

// New creates a new DatabaseService instance
func New(session *azinternal.SafeSession) *DatabaseService {
	return &DatabaseService{
		session: session,
	}
}

// NewWithSession creates a new DatabaseService with the given session (alias for New)
func NewWithSession(session *azinternal.SafeSession) *DatabaseService {
	return New(session)
}

// SQLServerInfo represents an Azure SQL Server
type SQLServerInfo struct {
	Name                    string
	ResourceGroup           string
	Location                string
	FQDN                    string
	Version                 string
	State                   string
	AdminLogin              string
	PublicNetworkAccess     string
	MinTLSVersion           string
}

// SQLDatabaseInfo represents an Azure SQL Database
type SQLDatabaseInfo struct {
	Name          string
	ServerName    string
	ResourceGroup string
	Status        string
	SKU           string
	MaxSizeBytes  int64
}

// CosmosDBAccountInfo represents a Cosmos DB account
type CosmosDBAccountInfo struct {
	Name                    string
	ResourceGroup           string
	Location                string
	Kind                    string
	DocumentEndpoint        string
	PublicNetworkAccess     string
	EnableAutomaticFailover bool
}

// PostgreSQLServerInfo represents a PostgreSQL server
type PostgreSQLServerInfo struct {
	Name                string
	ResourceGroup       string
	Location            string
	FQDN                string
	Version             string
	State               string
	AdminLogin          string
	PublicNetworkAccess string
}

// MySQLServerInfo represents a MySQL server
type MySQLServerInfo struct {
	Name                string
	ResourceGroup       string
	Location            string
	FQDN                string
	Version             string
	State               string
	AdminLogin          string
	PublicNetworkAccess string
}

// getARMCredential returns ARM credential from session
func (s *DatabaseService) getARMCredential() (*azinternal.StaticTokenCredential, error) {
	token, err := s.session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token: %w", err)
	}
	return &azinternal.StaticTokenCredential{Token: token}, nil
}

// ListSQLServers returns all SQL servers in a subscription
func (s *DatabaseService) ListSQLServers(ctx context.Context, subID string) ([]*armsql.Server, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armsql.NewServersClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create SQL servers client: %w", err)
	}

	pager := client.NewListPager(nil)
	var servers []*armsql.Server

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return servers, fmt.Errorf("failed to list SQL servers: %w", err)
		}
		servers = append(servers, page.Value...)
	}

	return servers, nil
}

// ListSQLServersByResourceGroup returns all SQL servers in a resource group
func (s *DatabaseService) ListSQLServersByResourceGroup(ctx context.Context, subID, rgName string) ([]*armsql.Server, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armsql.NewServersClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create SQL servers client: %w", err)
	}

	pager := client.NewListByResourceGroupPager(rgName, nil)
	var servers []*armsql.Server

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return servers, fmt.Errorf("failed to list SQL servers: %w", err)
		}
		servers = append(servers, page.Value...)
	}

	return servers, nil
}

// ListSQLDatabases returns all databases for a SQL server
func (s *DatabaseService) ListSQLDatabases(ctx context.Context, subID, rgName, serverName string) ([]*armsql.Database, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armsql.NewDatabasesClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create SQL databases client: %w", err)
	}

	pager := client.NewListByServerPager(rgName, serverName, nil)
	var databases []*armsql.Database

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return databases, fmt.Errorf("failed to list SQL databases: %w", err)
		}
		databases = append(databases, page.Value...)
	}

	return databases, nil
}

// ListCosmosDBAccounts returns all Cosmos DB accounts in a subscription
func (s *DatabaseService) ListCosmosDBAccounts(ctx context.Context, subID string) ([]*armcosmos.DatabaseAccountGetResults, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armcosmos.NewDatabaseAccountsClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Cosmos DB client: %w", err)
	}

	pager := client.NewListPager(nil)
	var accounts []*armcosmos.DatabaseAccountGetResults

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return accounts, fmt.Errorf("failed to list Cosmos DB accounts: %w", err)
		}
		accounts = append(accounts, page.Value...)
	}

	return accounts, nil
}

// ListCosmosDBAccountsByResourceGroup returns all Cosmos DB accounts in a resource group
func (s *DatabaseService) ListCosmosDBAccountsByResourceGroup(ctx context.Context, subID, rgName string) ([]*armcosmos.DatabaseAccountGetResults, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armcosmos.NewDatabaseAccountsClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Cosmos DB client: %w", err)
	}

	pager := client.NewListByResourceGroupPager(rgName, nil)
	var accounts []*armcosmos.DatabaseAccountGetResults

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return accounts, fmt.Errorf("failed to list Cosmos DB accounts: %w", err)
		}
		accounts = append(accounts, page.Value...)
	}

	return accounts, nil
}

// GetCosmosDBKeys returns the keys for a Cosmos DB account
func (s *DatabaseService) GetCosmosDBKeys(ctx context.Context, subID, rgName, accountName string) (*armcosmos.DatabaseAccountListKeysResult, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armcosmos.NewDatabaseAccountsClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Cosmos DB client: %w", err)
	}

	resp, err := client.ListKeys(ctx, rgName, accountName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get Cosmos DB keys: %w", err)
	}

	return &resp.DatabaseAccountListKeysResult, nil
}

// ListPostgreSQLFlexibleServers returns all PostgreSQL flexible servers in a subscription
func (s *DatabaseService) ListPostgreSQLFlexibleServers(ctx context.Context, subID string) ([]*armpostgresqlflexibleservers.Server, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armpostgresqlflexibleservers.NewServersClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create PostgreSQL client: %w", err)
	}

	pager := client.NewListPager(nil)
	var servers []*armpostgresqlflexibleservers.Server

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return servers, fmt.Errorf("failed to list PostgreSQL servers: %w", err)
		}
		servers = append(servers, page.Value...)
	}

	return servers, nil
}

// ListPostgreSQLFlexibleServersByResourceGroup returns all PostgreSQL flexible servers in a resource group
func (s *DatabaseService) ListPostgreSQLFlexibleServersByResourceGroup(ctx context.Context, subID, rgName string) ([]*armpostgresqlflexibleservers.Server, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armpostgresqlflexibleservers.NewServersClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create PostgreSQL client: %w", err)
	}

	pager := client.NewListByResourceGroupPager(rgName, nil)
	var servers []*armpostgresqlflexibleservers.Server

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return servers, fmt.Errorf("failed to list PostgreSQL servers: %w", err)
		}
		servers = append(servers, page.Value...)
	}

	return servers, nil
}

// ListMySQLFlexibleServers returns all MySQL flexible servers in a subscription
func (s *DatabaseService) ListMySQLFlexibleServers(ctx context.Context, subID string) ([]*armmysqlflexibleservers.Server, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armmysqlflexibleservers.NewServersClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create MySQL client: %w", err)
	}

	pager := client.NewListPager(nil)
	var servers []*armmysqlflexibleservers.Server

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return servers, fmt.Errorf("failed to list MySQL servers: %w", err)
		}
		servers = append(servers, page.Value...)
	}

	return servers, nil
}

// ListMySQLFlexibleServersByResourceGroup returns all MySQL flexible servers in a resource group
func (s *DatabaseService) ListMySQLFlexibleServersByResourceGroup(ctx context.Context, subID, rgName string) ([]*armmysqlflexibleservers.Server, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armmysqlflexibleservers.NewServersClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create MySQL client: %w", err)
	}

	pager := client.NewListByResourceGroupPager(rgName, nil)
	var servers []*armmysqlflexibleservers.Server

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return servers, fmt.Errorf("failed to list MySQL servers: %w", err)
		}
		servers = append(servers, page.Value...)
	}

	return servers, nil
}

// safeString safely dereferences a string pointer
func safeString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// ============================================================================
// CACHED METHODS - Use these in command modules for better performance
// ============================================================================

// CachedListSQLServers returns cached SQL servers for a subscription
func (s *DatabaseService) CachedListSQLServers(ctx context.Context, subID string) ([]*armsql.Server, error) {
	key := cacheKey("sqlservers", subID)

	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armsql.Server), nil
	}

	result, err := s.ListSQLServers(ctx, subID)
	if err != nil {
		return nil, err
	}

	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListSQLServersByResourceGroup returns cached SQL servers for a resource group
func (s *DatabaseService) CachedListSQLServersByResourceGroup(ctx context.Context, subID, rgName string) ([]*armsql.Server, error) {
	key := cacheKey("sqlservers-by-rg", subID, rgName)

	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armsql.Server), nil
	}

	result, err := s.ListSQLServersByResourceGroup(ctx, subID, rgName)
	if err != nil {
		return nil, err
	}

	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListCosmosDBAccounts returns cached Cosmos DB accounts for a subscription
func (s *DatabaseService) CachedListCosmosDBAccounts(ctx context.Context, subID string) ([]*armcosmos.DatabaseAccountGetResults, error) {
	key := cacheKey("cosmosdb", subID)

	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armcosmos.DatabaseAccountGetResults), nil
	}

	result, err := s.ListCosmosDBAccounts(ctx, subID)
	if err != nil {
		return nil, err
	}

	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListPostgreSQLFlexibleServers returns cached PostgreSQL flexible servers for a subscription
func (s *DatabaseService) CachedListPostgreSQLFlexibleServers(ctx context.Context, subID string) ([]*armpostgresqlflexibleservers.Server, error) {
	key := cacheKey("postgresql", subID)

	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armpostgresqlflexibleservers.Server), nil
	}

	result, err := s.ListPostgreSQLFlexibleServers(ctx, subID)
	if err != nil {
		return nil, err
	}

	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListMySQLFlexibleServers returns cached MySQL flexible servers for a subscription
func (s *DatabaseService) CachedListMySQLFlexibleServers(ctx context.Context, subID string) ([]*armmysqlflexibleservers.Server, error) {
	key := cacheKey("mysql", subID)

	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armmysqlflexibleservers.Server), nil
	}

	result, err := s.ListMySQLFlexibleServers(ctx, subID)
	if err != nil {
		return nil, err
	}

	serviceCache.Set(key, result, 0)
	return result, nil
}
