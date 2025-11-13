# Multi-Tenant Support Implementation Guide for CloudFox Azure Modules

This guide provides a step-by-step template for updating the remaining Azure command modules to support multi-tenant operations.

## Overview

**Status**: Core IAM modules (RBAC, Permissions, Principals) have been updated with full multi-tenant support.

**Remaining**: 46 resource-based modules need multi-tenant support.

## Modules Already Updated

✅ `rbac.go` - Full multi-tenant support with tenant columns and splitting
✅ `permissions.go` - Full multi-tenant support with tenant columns and splitting
✅ `principals.go` - Full multi-tenant support with tenant columns and splitting

## Infrastructure Available

The `internal/azure/command_context.go` file provides the following multi-tenant infrastructure:

### Data Structures
- `TenantContext` - Holds information for a single tenant
- `CommandContext.Tenants` - Array of all tenants to process
- `CommandContext.IsMultiTenant` - Boolean flag indicating multi-tenant mode
- `BaseAzureModule.Tenants` - Embedded tenant list in all modules
- `BaseAzureModule.IsMultiTenant` - Embedded multi-tenant flag

### Orchestration Methods
- `RunTenantEnumeration()` - Process each tenant with parallelization
- `RunTenantSubscriptionEnumeration()` - Process subscriptions across multiple tenants
- (Existing) `RunSubscriptionEnumeration()` - Process subscriptions for single tenant

### Output Helpers
- `ShouldSplitByTenant()` - Determine if output should be split by tenant
- `FilterAndWritePerTenantAuto()` - Auto-detect tenant column and filter output
- `FilterAndWritePerTenant()` - Explicit tenant-based filtering
- `FilterAndWritePerTenantBySubscription()` - Fallback method using subscription column
- `GetTenantFromSubscription()` - Map subscription to parent tenant

## Step-by-Step Update Template

### Step 1: Update Output Header (Add Tenant Columns)

**Before:**
```go
var MyModuleHeader = []string{
	"Subscription",
	"Resource Group",
	"Resource Name",
	// ... other columns
}
```

**After:**
```go
var MyModuleHeader = []string{
	"Tenant Name",      // NEW: for multi-tenant support
	"Tenant ID",        // NEW: for multi-tenant support
	"Subscription",
	"Resource Group",
	"Resource Name",
	// ... other columns
}
```

### Step 2: Update Row Creation (Add Tenant Data)

Find where rows are appended (usually in a `build*Row` or `process*` function).

**Before:**
```go
row := []string{
	subscriptionName,
	resourceGroup,
	resourceName,
	// ... other fields
}
m.DataRows = append(m.DataRows, row)
```

**After:**
```go
row := []string{
	m.TenantName,       // NEW: Always populated for multi-tenant support
	m.TenantID,         // NEW: Always populated for multi-tenant support
	subscriptionName,
	resourceGroup,
	resourceName,
	// ... other fields
}
m.DataRows = append(m.DataRows, row)
```

### Step 3: Update Main Print Method (Add Multi-Tenant Processing)

**Pattern A: For modules that enumerate PER SUBSCRIPTION**

**Before:**
```go
func (m *MyModule) PrintData(ctx context.Context, logger internal.Logger) {
	logger.InfoM(fmt.Sprintf("Enumerating resources for %d subscription(s)", len(m.Subscriptions)), moduleName)

	// Use RunSubscriptionEnumeration to process all subscriptions
	m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, moduleName, m.processSubscription)

	// Write output
	m.writeOutput(ctx, logger)
}
```

**After:**
```go
func (m *MyModule) PrintData(ctx context.Context, logger internal.Logger) {
	// Multi-tenant processing
	if m.IsMultiTenant {
		logger.InfoM(fmt.Sprintf("Multi-tenant mode: Processing %d tenants", len(m.Tenants)), moduleName)

		// Process each tenant independently
		for _, tenantCtx := range m.Tenants {
			// Temporarily set module tenant context for row creation
			savedTenantID := m.TenantID
			savedTenantName := m.TenantName
			savedTenantInfo := m.TenantInfo

			m.TenantID = tenantCtx.TenantID
			m.TenantName = tenantCtx.TenantName
			m.TenantInfo = tenantCtx.TenantInfo

			if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
				logger.InfoM(fmt.Sprintf("Processing tenant: %s (%s)", m.TenantName, m.TenantID), moduleName)
			}

			// Process subscriptions for this tenant
			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, moduleName, m.processSubscription)

			// Restore tenant context
			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		// Single tenant processing (existing logic)
		logger.InfoM(fmt.Sprintf("Enumerating resources for %d subscription(s)", len(m.Subscriptions)), moduleName)
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, moduleName, m.processSubscription)
	}

	// Write output
	m.writeOutput(ctx, logger)
}
```

**Pattern B: For tenant-level modules (like Principals)**

**Before:**
```go
func (m *MyModule) PrintData(ctx context.Context, logger internal.Logger) {
	logger.InfoM(fmt.Sprintf("Enumerating data for tenant: %s", m.TenantName), moduleName)

	// Process tenant data
	m.processTenantData(ctx, logger)

	// Write output
	m.writeOutput(ctx, logger)
}
```

**After:**
```go
func (m *MyModule) PrintData(ctx context.Context, logger internal.Logger) {
	// Multi-tenant processing
	if m.IsMultiTenant {
		logger.InfoM(fmt.Sprintf("Multi-tenant mode: Processing %d tenants", len(m.Tenants)), moduleName)

		for _, tenantCtx := range m.Tenants {
			// Save current context
			savedTenantID := m.TenantID
			savedTenantName := m.TenantName
			savedTenantInfo := m.TenantInfo

			// Set tenant context
			m.TenantID = tenantCtx.TenantID
			m.TenantName = tenantCtx.TenantName
			m.TenantInfo = tenantCtx.TenantInfo

			logger.InfoM(fmt.Sprintf("Processing tenant: %s (%s)", m.TenantName, m.TenantID), moduleName)

			// Process this tenant
			m.processTenantData(ctx, logger)

			// Restore context
			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		// Single tenant mode
		logger.InfoM(fmt.Sprintf("Enumerating data for tenant: %s", m.TenantName), moduleName)
		m.processTenantData(ctx, logger)
	}

	// Write output
	m.writeOutput(ctx, logger)
}
```

### Step 4: Update writeOutput Method (Add Tenant Splitting)

**Before:**
```go
func (m *MyModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.DataRows) == 0 {
		logger.InfoM("No data found", moduleName)
		return
	}

	// Sort by subscription, then resource name
	sort.Slice(m.DataRows, func(i, j int) bool {
		if m.DataRows[i][0] != m.DataRows[j][0] { // Subscription column
			return m.DataRows[i][0] < m.DataRows[j][0]
		}
		return m.DataRows[i][2] < m.DataRows[j][2] // Resource name column
	})

	// Check if we should split output by subscription
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		if err := m.FilterAndWritePerSubscriptionAuto(
			ctx, logger, m.Subscriptions, m.DataRows, MyModuleHeader,
			"mymodule", moduleName,
		); err != nil {
			return
		}
		return
	}

	// Otherwise: consolidated output
	// ... rest of output logic
}
```

**After:**
```go
func (m *MyModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.DataRows) == 0 {
		logger.InfoM("No data found", moduleName)
		return
	}

	// Sort by tenant, then subscription, then resource name
	sort.Slice(m.DataRows, func(i, j int) bool {
		// Column 0: Tenant Name
		if m.DataRows[i][0] != m.DataRows[j][0] {
			return m.DataRows[i][0] < m.DataRows[j][0]
		}
		// Column 2: Subscription (moved from 0 due to new tenant columns)
		if m.DataRows[i][2] != m.DataRows[j][2] {
			return m.DataRows[i][2] < m.DataRows[j][2]
		}
		// Column 4: Resource name (moved from 2 due to new tenant columns)
		return m.DataRows[i][4] < m.DataRows[j][4]
	})

	// Check if we should split output by tenant (multi-tenant mode)
	if azinternal.ShouldSplitByTenant(m.IsMultiTenant, m.Tenants) {
		// Split into separate tenant directories
		if err := m.FilterAndWritePerTenantAuto(
			ctx,
			logger,
			m.Tenants,
			m.DataRows,
			MyModuleHeader,
			"mymodule",
			moduleName,
		); err != nil {
			return
		}
		return
	}

	// Check if we should split output by subscription (multiple subs WITHOUT --tenant flag, single tenant)
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		// Column index for subscription moved from 0 to 2 due to new tenant columns
		if err := m.FilterAndWritePerSubscriptionAuto(
			ctx, logger, m.Subscriptions, m.DataRows, MyModuleHeader,
			"mymodule", moduleName,
		); err != nil {
			return
		}
		return
	}

	// Otherwise: consolidated output
	// ... rest of output logic (unchanged)
}
```

### Step 5: Update Column Indices

**IMPORTANT**: After adding tenant columns at the beginning of headers, ALL column indices shift by +2.

**Example:**
- Subscription: was column 0, now column 2
- Resource Group: was column 1, now column 3
- Resource Name: was column 2, now column 4
- etc.

Update column references in:
- Sort functions
- FilterAndWritePerSubscription calls
- Any direct column index references

## Quick Reference: Column Index Updates

```go
// OLD indices (before tenant columns)
const (
	COL_SUBSCRIPTION   = 0
	COL_RESOURCE_GROUP = 1
	COL_RESOURCE_NAME  = 2
	COL_STATUS         = 3
	// ... etc
)

// NEW indices (after adding Tenant Name and Tenant ID)
const (
	COL_TENANT_NAME    = 0  // NEW
	COL_TENANT_ID      = 1  // NEW
	COL_SUBSCRIPTION   = 2  // was 0, shifted +2
	COL_RESOURCE_GROUP = 3  // was 1, shifted +2
	COL_RESOURCE_NAME  = 4  // was 2, shifted +2
	COL_STATUS         = 5  // was 3, shifted +2
	// ... etc
)
```

## Testing Checklist

After updating a module, test:

- [ ] Single tenant works (backward compatibility)
- [ ] Multiple tenants work (new feature)
- [ ] Output directories created correctly:
  - Single tenant: `azure-<tenant-name>/`
  - Multiple tenants: `azure-<tenant1-name>/`, `azure-<tenant2-name>/`, etc.
- [ ] Data correctly filtered per tenant
- [ ] Tenant columns populated in output
- [ ] No duplicate data
- [ ] Sorting works correctly
- [ ] Code compiles without errors: `go build ./...`
- [ ] Code is formatted: `gofmt -w azure/commands/mymodule.go`

## Modules Requiring Updates

### High Priority (Compute & Storage)
- [ ] `aks.go` - Azure Kubernetes Service
- [ ] `vms.go` - Virtual Machines
- [ ] `storage.go` - Storage Accounts
- [ ] `databases.go` - Database Services
- [ ] `acr.go` - Container Registry
- [ ] `container-apps.go` - Container Apps

### Medium Priority (Networking & Security)
- [ ] `vnets.go` - Virtual Networks
- [ ] `nsg.go` - Network Security Groups
- [ ] `appgw.go` - Application Gateway
- [ ] `firewall.go` - Azure Firewall
- [ ] `keyvaults.go` - Key Vaults
- [ ] `network-interfaces.go` - Network Interfaces
- [ ] `routes.go` - Route Tables
- [ ] `privatelink.go` - Private Link

### Other Services
- [ ] `webapps.go` - Web Apps
- [ ] `functions.go` - Azure Functions
- [ ] `accesskeys.go` - Access Keys
- [ ] `app-configuration.go` - App Configuration
- [ ] `arc.go` - Azure Arc
- [ ] `automation.go` - Automation Accounts
- [ ] `batch.go` - Batch Accounts
- [ ] `databricks.go` - Databricks
- [ ] `datafactory.go` - Data Factory
- [ ] `deployments.go` - Deployments
- [ ] `devops-artifacts.go` - DevOps Artifacts
- [ ] `devops-pipelines.go` - DevOps Pipelines
- [ ] `devops-projects.go` - DevOps Projects
- [ ] `devops-repos.go` - DevOps Repositories
- [ ] `disks.go` - Managed Disks
- [ ] `endpoints.go` - Various Endpoints
- [ ] `enterprise-apps.go` - Enterprise Applications
- [ ] `filesystems.go` - File Systems
- [ ] `hdinsight.go` - HDInsight
- [ ] `inventory.go` - Inventory
- [ ] `iothub.go` - IoT Hub
- [ ] `kusto.go` - Kusto/Data Explorer
- [ ] `load-testing.go` - Load Testing
- [ ] `logicapps.go` - Logic Apps
- [ ] `machine-learning.go` - Machine Learning
- [ ] `policy.go` - Policies
- [ ] `redis.go` - Redis Cache
- [ ] `servicefabric.go` - Service Fabric
- [ ] `signalr.go` - SignalR
- [ ] `springapps.go` - Spring Apps
- [ ] `streamanalytics.go` - Stream Analytics
- [ ] `synapse.go` - Synapse Analytics
- [ ] `whoami.go` - Whoami (tenant-level)

## Common Patterns

### Pattern: Subscription-Based Resource Enumeration

Most modules follow this pattern:
1. Iterate over subscriptions
2. For each subscription, enumerate resources
3. Build table rows with subscription context
4. Write output

**Multi-tenant adaptation**: Wrap subscription iteration in tenant loop

### Pattern: Tenant-Level Enumeration

Some modules (like `whoami`, `enterprise-apps`) are tenant-level:
1. Connect to tenant
2. Enumerate tenant-wide resources
3. Build table rows
4. Write output

**Multi-tenant adaptation**: Loop over tenants, enumerate each separately

### Pattern: Resource Group Level

Some modules enumerate at resource group level:
1. Get all resource groups
2. For each RG, enumerate resources
3. Build rows
4. Write output

**Multi-tenant adaptation**: Wrap RG iteration in tenant+subscription loops

## Example: Complete Module Update

See `azure/commands/rbac.go` for a comprehensive example of a fully updated module with:
- Tenant columns in header
- Tenant data in rows
- Multi-tenant processing in PrintRBAC()
- Tenant splitting in writeOutput()
- Proper column index updates
- Full backward compatibility

## Commit Message Template

```
Add multi-tenant support to <module-name> module

Enables cross-tenant enumeration for <resource-type> resources.

Changes:
- Added "Tenant Name" and "Tenant ID" columns to output header
- Updated row creation to include tenant information
- Modified Print<Module>() to handle multi-tenant processing
- Updated writeOutput() to support tenant splitting
- Updated column indices after adding tenant columns
- Maintains full backward compatibility

Usage:
# Single tenant
cloudfox azure <command> --tenant <tenant-id>

# Multiple tenants
cloudfox azure <command> --tenant "tenant1,tenant2,tenant3"

Output: Creates separate directories per tenant when multiple tenants specified
```

## Tips

1. **Start with simple modules**: Update smaller, simpler modules first to get comfortable with the pattern
2. **Copy from RBAC**: Use `rbac.go` as a reference implementation
3. **Test incrementally**: Test each module after updating before moving to the next
4. **Watch column indices**: Most bugs will be from incorrect column references after adding tenant columns
5. **Format code**: Always run `gofmt -w` before committing
6. **Preserve backward compatibility**: Single-tenant operations must continue to work exactly as before

## Need Help?

- Review the three updated IAM modules: `rbac.go`, `permissions.go`, `principals.go`
- Check the infrastructure in `internal/azure/command_context.go`
- Look for similar patterns in existing modules
- Test with single tenant first, then add multi-tenant testing
