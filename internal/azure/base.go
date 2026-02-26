package azure

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/spf13/cobra"
)

// ------------------------------
// parseMultiValueFlag parses a flag value that can contain comma-separated
// and/or space-separated values. Examples:
//
//	"abc,def" -> ["abc", "def"]
//	"abc def" -> ["abc", "def"]
//	"abc, def ghi" -> ["abc", "def", "ghi"]
//
// ------------------------------
func parseMultiValueFlag(flagValue string) []string {
	if flagValue == "" {
		return nil
	}

	// Replace commas with spaces, then split by whitespace
	normalized := strings.ReplaceAll(flagValue, ",", " ")
	fields := strings.Fields(normalized) // automatically trims and handles multiple spaces

	// Deduplicate while preserving order
	seen := make(map[string]bool)
	result := []string{}
	for _, field := range fields {
		if !seen[field] {
			seen[field] = true
			result = append(result, field)
		}
	}
	return result
}

// ------------------------------
// CommandContext holds all common initialization data for Azure commands
// ------------------------------
type CommandContext struct {
	// Context and logger
	Ctx    context.Context
	Logger internal.Logger

	// Session
	Session *SafeSession

	// Single Tenant information (for backward compatibility)
	TenantID   string
	TenantName string
	TenantInfo TenantInfo

	// Multi-Tenant information
	Tenants       []TenantContext // All tenants to enumerate
	IsMultiTenant bool            // True if multiple tenants are being processed

	// User information
	UserObjectID    string
	UserUPN         string
	UserDisplayName string

	// Flags
	Verbosity         int
	WrapTable         bool
	OutputDirectory   string
	Format            string
	ResourceGroupFlag string
	TenantFlagPresent bool // True if --tenant flag was specified (even if blank)

	// Subscriptions (resolved from flags or tenant)
	Subscriptions []string
}

// TenantContext holds information for a single tenant in multi-tenant scenarios
type TenantContext struct {
	TenantID      string
	TenantName    string
	TenantInfo    TenantInfo
	Subscriptions []string // Subscriptions specific to this tenant
}

// ------------------------------
// BaseAzureModule - Embeddable struct with common fields for all Azure modules
// ------------------------------
// This struct eliminates 300+ lines of duplicate field declarations across 20 modules.
// Modules embed this struct instead of declaring these fields individually.
//
// Usage:
//
//	type StorageModule struct {
//	    BaseAzureModule  // Embed the base fields
//
//	    // Module-specific fields
//	    StorageAccounts []StorageAccountInfo
//	    mu              sync.Mutex
//	}
//
// Benefits:
// - Single source of truth for common fields
// - Easier to add new common fields in the future
// - Reduces boilerplate by ~15 lines per module
// - All modules automatically get new base fields
type BaseAzureModule struct {
	// Session and identity (11 fields total)
	Session    *SafeSession
	TenantID   string
	TenantName string
	TenantInfo TenantInfo

	// Multi-tenant support
	Tenants       []TenantContext // All tenants to enumerate
	IsMultiTenant bool            // True if multiple tenants are being processed

	// User context
	UserObjectID    string
	UserUPN         string
	UserDisplayName string

	// Configuration
	Verbosity         int
	WrapTable         bool
	OutputDirectory   string
	Format            string
	ResourceGroupFlag string
	TenantFlagPresent bool // True if --tenant flag was specified (even if blank)

	// AWS-style progress tracking
	CommandCounter internal.CommandCounter
	Goroutines     int
}

// ------------------------------
// NewBaseAzureModule - Helper to create BaseAzureModule from CommandContext
// ------------------------------
// This eliminates the need to manually copy 15 fields from cmdCtx to each module.
//
// Usage (BEFORE - 15 lines):
//
//	module := &StorageModule{
//	    Session:           cmdCtx.Session,
//	    TenantID:          cmdCtx.TenantID,
//	    TenantName:        cmdCtx.TenantName,
//	    TenantInfo:        cmdCtx.TenantInfo,
//	    UserObjectID:      cmdCtx.UserObjectID,
//	    UserUPN:           cmdCtx.UserUPN,
//	    UserDisplayName:   cmdCtx.UserDisplayName,
//	    Verbosity:         cmdCtx.Verbosity,
//	    WrapTable:         cmdCtx.WrapTable,
//	    OutputDirectory:   cmdCtx.OutputDirectory,
//	    Format:            cmdCtx.Format,
//	    ResourceGroupFlag: cmdCtx.ResourceGroupFlag,
//	    Goroutines:        5,
//	    StorageAccounts:   []StorageAccountInfo{},
//	}
//
// Usage (AFTER - 4 lines):
//
//	module := &StorageModule{
//	    BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5),
//	    StorageAccounts: []StorageAccountInfo{},
//	}
func NewBaseAzureModule(cmdCtx *CommandContext, goroutines int) BaseAzureModule {
	return BaseAzureModule{
		Session:           cmdCtx.Session,
		TenantID:          cmdCtx.TenantID,
		TenantName:        cmdCtx.TenantName,
		TenantInfo:        cmdCtx.TenantInfo,
		Tenants:           cmdCtx.Tenants,
		IsMultiTenant:     cmdCtx.IsMultiTenant,
		UserObjectID:      cmdCtx.UserObjectID,
		UserUPN:           cmdCtx.UserUPN,
		UserDisplayName:   cmdCtx.UserDisplayName,
		Verbosity:         cmdCtx.Verbosity,
		WrapTable:         cmdCtx.WrapTable,
		OutputDirectory:   cmdCtx.OutputDirectory,
		Format:            cmdCtx.Format,
		ResourceGroupFlag: cmdCtx.ResourceGroupFlag,
		TenantFlagPresent: cmdCtx.TenantFlagPresent,
		Goroutines:        goroutines,
	}
}

// ------------------------------
// ResolveResourceGroups - Eliminates 170+ lines of duplicate RG resolution logic
// ------------------------------
// This method centralizes the resource group resolution logic used by all modules.
// It either returns the resource groups specified via --resource-group flag,
// or fetches all resource groups for the subscription using cached SDK calls.
//
// Usage (BEFORE - 11 lines per module):
//
//	var resourceGroups []string
//	if m.ResourceGroupFlag != "" {
//	    for _, rg := range strings.Split(m.ResourceGroupFlag, ",") {
//	        resourceGroups = append(resourceGroups, strings.TrimSpace(rg))
//	    }
//	} else {
//	    rgs := sdk.CachedGetResourceGroupsPerSubscription(m.Session, subID)
//	    for _, rg := range rgs {
//	        resourceGroups = append(resourceGroups, SafeStringPtr(rg.Name))
//	    }
//	}
//
// Usage (AFTER - 1 line):
//
//	resourceGroups := m.ResolveResourceGroups(subID)
func (b *BaseAzureModule) ResolveResourceGroups(subscriptionID string) []string {
	var resourceGroups []string

	if b.ResourceGroupFlag != "" {
		// User specified resource groups via flag
		for _, rg := range strings.Split(b.ResourceGroupFlag, ",") {
			rg = strings.TrimSpace(rg)
			if rg != "" {
				resourceGroups = append(resourceGroups, rg)
			}
		}
	} else {
		// Fetch all resource groups for subscription (CACHED)
		rgs := GetResourceGroupsPerSubscription(b.Session, subscriptionID)
		for _, rg := range rgs {
			if rg.Name != nil && *rg.Name != "" {
				resourceGroups = append(resourceGroups, *rg.Name)
			}
		}
	}

	return resourceGroups
}

// ------------------------------
// SubscriptionProcessor - Callback function type for processing individual subscriptions
// ------------------------------
// This function type defines the signature for subscription processing callbacks used by RunSubscriptionEnumeration.
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - subscriptionID: The Azure subscription ID to process
//   - logger: Logger for outputting messages
type SubscriptionProcessor func(ctx context.Context, subscriptionID string, logger internal.Logger)

// ------------------------------
// RunSubscriptionEnumeration - Eliminates 240+ lines of duplicate subscription orchestration logic
// ------------------------------
// This method centralizes the subscription enumeration orchestration pattern used by all modules.
// It handles WaitGroup, semaphore, spinner, and CommandCounter management automatically.
//
// Usage (BEFORE - 25+ lines per module):
//
//	func (m *StorageModule) PrintStorage(ctx context.Context, logger internal.Logger) {
//	    logger.InfoM(fmt.Sprintf("Enumerating storage accounts for %d subscription(s)", len(m.Subscriptions)), globals.AZ_STORAGE_MODULE_NAME)
//
//	    wg := new(sync.WaitGroup)
//	    semaphore := make(chan struct{}, m.Goroutines)
//	    spinnerDone := make(chan bool)
//	    go internal.SpinUntil(globals.AZ_STORAGE_MODULE_NAME, &m.CommandCounter, spinnerDone, "subscriptions")
//
//	    for _, subID := range m.Subscriptions {
//	        m.CommandCounter.Total++
//	        m.CommandCounter.Pending++
//	        wg.Add(1)
//	        go m.processSubscription(ctx, subID, wg, semaphore, logger)
//	    }
//
//	    wg.Wait()
//	    spinnerDone <- true
//	    <-spinnerDone
//
//	    m.writeOutput(logger)
//	}
//
// Usage (AFTER - 3 lines):
//
//	func (m *StorageModule) PrintStorage(ctx context.Context, logger internal.Logger) {
//	    m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_STORAGE_MODULE_NAME, m.processSubscription)
//	    m.writeOutput(logger)
//	}
//
// The processor function signature should be:
//
//	func (m *Module) processSubscription(ctx context.Context, subscriptionID string, logger internal.Logger)
//
// Note: The processor function will be called in goroutines automatically. It should NOT manage
// CommandCounter (Total, Pending, Executing, Complete) - that's handled by this orchestrator.
func (b *BaseAzureModule) RunSubscriptionEnumeration(
	ctx context.Context,
	logger internal.Logger,
	subscriptions []string,
	moduleName string,
	processor SubscriptionProcessor,
) {
	logger.InfoM(fmt.Sprintf("Enumerating resources for %d subscription(s)", len(subscriptions)), moduleName)

	// Setup synchronization primitives
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, b.Goroutines)

	// Start progress spinner
	spinnerDone := make(chan bool)
	go internal.SpinUntil(moduleName, &b.CommandCounter, spinnerDone, "subscriptions")

	// Process each subscription with goroutines
	for _, subID := range subscriptions {
		b.CommandCounter.Total++
		b.CommandCounter.Pending++
		wg.Add(1)

		go func(subscriptionID string) {
			defer func() {
				b.CommandCounter.Executing--
				b.CommandCounter.Complete++
				wg.Done()
			}()

			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			b.CommandCounter.Pending--
			b.CommandCounter.Executing++

			// Call the module-specific processor
			processor(ctx, subscriptionID, logger)
		}(subID)
	}

	// Wait for all subscriptions to complete
	wg.Wait()

	// Stop spinner
	spinnerDone <- true
	<-spinnerDone
}

// ------------------------------
// TenantProcessor - Callback function type for processing individual tenants
// ------------------------------
// This function type defines the signature for tenant processing callbacks used by RunTenantEnumeration.
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - tenantCtx: The tenant context containing tenant ID, name, and subscriptions
//   - logger: Logger for outputting messages
type TenantProcessor func(ctx context.Context, tenantCtx TenantContext, logger internal.Logger)

// ------------------------------
// RunTenantEnumeration - Orchestrates enumeration across multiple tenants
// ------------------------------
// This method provides orchestration for multi-tenant enumeration. It handles WaitGroup,
// semaphore, spinner, and CommandCounter management for tenant-level processing.
//
// Usage:
//
//	func (m *MyModule) PrintData(ctx context.Context, logger internal.Logger) {
//	    if m.IsMultiTenant {
//	        m.RunTenantEnumeration(ctx, logger, m.Tenants, globals.AZ_MY_MODULE_NAME, m.processTenant)
//	    } else {
//	        // Single tenant processing
//	        m.processSubscriptions(ctx, logger)
//	    }
//	    m.writeOutput(logger)
//	}
//
// The processor function signature should be:
//
//	func (m *Module) processTenant(ctx context.Context, tenantCtx TenantContext, logger internal.Logger)
//
// Note: The processor function will be called in goroutines automatically. It should NOT manage
// CommandCounter (Total, Pending, Executing, Complete) - that's handled by this orchestrator.
func (b *BaseAzureModule) RunTenantEnumeration(
	ctx context.Context,
	logger internal.Logger,
	tenants []TenantContext,
	moduleName string,
	processor TenantProcessor,
) {
	logger.InfoM(fmt.Sprintf("Multi-tenant enumeration: Processing %d tenant(s)", len(tenants)), moduleName)

	// Setup synchronization primitives
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, b.Goroutines)

	// Start progress spinner
	spinnerDone := make(chan bool)
	go internal.SpinUntil(moduleName, &b.CommandCounter, spinnerDone, "tenants")

	// Process each tenant with goroutines
	for _, tenant := range tenants {
		b.CommandCounter.Total++
		b.CommandCounter.Pending++
		wg.Add(1)

		go func(tenantCtx TenantContext) {
			defer func() {
				b.CommandCounter.Executing--
				b.CommandCounter.Complete++
				wg.Done()
			}()

			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			b.CommandCounter.Pending--
			b.CommandCounter.Executing++

			// Call the module-specific processor
			processor(ctx, tenantCtx, logger)
		}(tenant)
	}

	// Wait for all tenants to complete
	wg.Wait()

	// Stop spinner
	spinnerDone <- true
	<-spinnerDone
}

// ------------------------------
// RunTenantSubscriptionEnumeration - Nested enumeration across tenants and their subscriptions
// ------------------------------
// This method provides double-nested orchestration for multi-tenant scenarios where you need
// to enumerate resources within each subscription of each tenant.
//
// Usage:
//
//	func (m *MyModule) PrintData(ctx context.Context, logger internal.Logger) {
//	    if m.IsMultiTenant {
//	        m.RunTenantSubscriptionEnumeration(ctx, logger, m.Tenants, globals.AZ_MY_MODULE_NAME, m.processTenantSubscription)
//	    } else {
//	        m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_MY_MODULE_NAME, m.processSubscription)
//	    }
//	    m.writeOutput(logger)
//	}
//
// The processor function signature should be:
//
//	func (m *Module) processTenantSubscription(ctx context.Context, tenantID, subscriptionID string, logger internal.Logger)
type TenantSubscriptionProcessor func(ctx context.Context, tenantID, subscriptionID string, logger internal.Logger)

func (b *BaseAzureModule) RunTenantSubscriptionEnumeration(
	ctx context.Context,
	logger internal.Logger,
	tenants []TenantContext,
	moduleName string,
	processor TenantSubscriptionProcessor,
) {
	totalSubs := 0
	for _, t := range tenants {
		totalSubs += len(t.Subscriptions)
	}

	logger.InfoM(fmt.Sprintf("Multi-tenant enumeration: Processing %d subscription(s) across %d tenant(s)", totalSubs, len(tenants)), moduleName)

	// Setup synchronization primitives
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, b.Goroutines)

	// Start progress spinner
	spinnerDone := make(chan bool)
	go internal.SpinUntil(moduleName, &b.CommandCounter, spinnerDone, "tenant-subscriptions")

	// Process each tenant's subscriptions
	for _, tenant := range tenants {
		for _, subID := range tenant.Subscriptions {
			b.CommandCounter.Total++
			b.CommandCounter.Pending++
			wg.Add(1)

			go func(tenantID, subscriptionID string) {
				defer func() {
					b.CommandCounter.Executing--
					b.CommandCounter.Complete++
					wg.Done()
				}()

				// Acquire semaphore
				semaphore <- struct{}{}
				defer func() { <-semaphore }()

				b.CommandCounter.Pending--
				b.CommandCounter.Executing++

				// Call the module-specific processor
				processor(ctx, tenantID, subscriptionID, logger)
			}(tenant.TenantID, subID)
		}
	}

	// Wait for all tenant-subscriptions to complete
	wg.Wait()

	// Stop spinner
	spinnerDone <- true
	<-spinnerDone
}

// ------------------------------
// InitializeCommandContext - Eliminates 800+ lines of duplicate initialization code
// ------------------------------
// This helper extracts flags, initializes session, resolves tenant, gets current user,
// and determines subscriptions - all the boilerplate that's duplicated across 32 command files.
//
// Usage:
//
//	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_STORAGE_MODULE_NAME)
//	if err != nil {
//	    return // error already logged
//	}
//	defer cmdCtx.Session.StopMonitoring()
func InitializeCommandContext(cmd *cobra.Command, moduleName string) (*CommandContext, error) {
	ctx := context.Background()
	logger := internal.NewLogger()

	// -------------------- Extract flags --------------------
	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")
	tenantFlag, _ := parentCmd.PersistentFlags().GetString("tenant")
	subscriptionFlag, _ := parentCmd.PersistentFlags().GetString("subscription")
	resourceGroupFlag, _ := parentCmd.PersistentFlags().GetString("resource-group")

	// Detect if --tenant flag was specified (even if blank)
	tenantFlagPresent := parentCmd.PersistentFlags().Changed("tenant")

	// -------------------- Initialize session --------------------
	session, err := NewSmartSession(ctx)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to initialize SmartSession: %v", err), moduleName)
		return nil, err
	}

	if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM("Azure credential acquired successfully", moduleName)
	}

	// -------------------- Determine tenant --------------------
	var tenantID, tenantName string
	var tenantInfo TenantInfo
	var tenantContexts []TenantContext
	isMultiTenant := false

	if tenantFlagPresent {
		// --tenant flag was specified (may be blank or have value)
		if tenantFlag != "" {
			// Parse potentially multiple tenants (support both comma and space delimiters)
			tenants := parseMultiValueFlag(tenantFlag)

			if len(tenants) == 0 {
				logger.ErrorM("Empty tenant flag provided", moduleName)
				session.StopMonitoring()
				return nil, fmt.Errorf("empty tenant flag")
			}

			if len(tenants) > 1 {
				// Multiple tenants specified - enable multi-tenant mode
				isMultiTenant = true
				if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
					logger.InfoM(fmt.Sprintf("Multi-tenant mode enabled. Processing %d tenants: %v", len(tenants), tenants), moduleName)
				}

				// Populate each tenant
				for _, tID := range tenants {
					tInfo := PopulateTenant(session, tID)
					tName := GetTenantNameFromID(ctx, session, tID)

					tenantContexts = append(tenantContexts, TenantContext{
						TenantID:   tID,
						TenantName: tName,
						TenantInfo: tInfo,
					})

					if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
						logger.InfoM(fmt.Sprintf("Loaded tenant: %s (%s) with %d subscriptions", tID, tName, len(tInfo.Subscriptions)), moduleName)
					}
				}

				// For backward compatibility, set the first tenant as the primary
				if len(tenantContexts) > 0 {
					tenantID = tenantContexts[0].TenantID
					tenantName = tenantContexts[0].TenantName
					tenantInfo = tenantContexts[0].TenantInfo
				}
			} else {
				// Single tenant
				tenantID = tenants[0]
				tenantInfo = PopulateTenant(session, tenantID)
				tenantName = GetTenantNameFromID(ctx, session, tenantID)
				if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
					logger.InfoM(fmt.Sprintf("Tenant explicitly provided: %s, name resolved as: %s", tenantID, tenantName), moduleName)
				}
			}
		} else {
			// --tenant flag specified but blank - auto-detect from session
			if subscriptionFlag != "" {
				// Resolve tenant from subscription
				subscriptionsFromFlag := parseMultiValueFlag(subscriptionFlag)
				if len(subscriptionsFromFlag) > 0 {
					if tID := GetTenantIDFromSubscription(session, subscriptionsFromFlag[0]); tID != nil {
						tenantID = *tID
						tenantName = GetTenantNameFromID(ctx, session, tenantID)
						tenantInfo = PopulateTenant(session, tenantID)
						if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
							logger.InfoM(fmt.Sprintf("Tenant auto-detected from subscription %s: %s (%s)", subscriptionsFromFlag[0], tenantID, tenantName), moduleName)
						}
					} else {
						logger.ErrorM("Failed to auto-detect tenant from subscription", moduleName)
						session.StopMonitoring()
						return nil, fmt.Errorf("failed to auto-detect tenant from subscription")
					}
				}
			} else {
				// No subscription specified - cannot auto-detect tenant
				logger.ErrorM("--tenant flag specified but no tenant ID or subscription provided for auto-detection", moduleName)
				session.StopMonitoring()
				return nil, fmt.Errorf("--tenant flag specified but no value provided and no subscription specified for auto-detection")
			}
		}
	} else if subscriptionFlag != "" {
		// Resolve tenant from subscription (support both comma and space delimiters)
		subscriptionsFromFlag := parseMultiValueFlag(subscriptionFlag)

		if len(subscriptionsFromFlag) == 0 {
			logger.ErrorM("Empty subscription flag provided", moduleName)
			session.StopMonitoring()
			return nil, fmt.Errorf("empty subscription flag")
		}

		// Resolve tenant from first subscription
		if tID := GetTenantIDFromSubscription(session, subscriptionsFromFlag[0]); tID != nil {
			tenantID = *tID
			tenantName = GetTenantNameFromID(ctx, session, tenantID)
			tenantInfo = PopulateTenant(session, tenantID)
			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				logger.InfoM(fmt.Sprintf("Tenant resolved from subscription %s: %s (%s)", subscriptionsFromFlag[0], tenantID, tenantName), moduleName)
			}
		} else {
			logger.ErrorM("Failed to resolve tenant from subscription", moduleName)
			session.StopMonitoring()
			return nil, fmt.Errorf("failed to resolve tenant from subscription")
		}
	} else {
		logger.ErrorM("No tenant or subscription specified", moduleName)
		session.StopMonitoring()
		return nil, fmt.Errorf("no tenant or subscription specified")
	}

	// -------------------- Get current user --------------------
	objectID, upn, displayName, err := GetCurrentUserSafe(ctx, session)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to get current user: %v", err), moduleName)
		// Don't fail - some modules can continue without user info
	}

	if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Resolved current user: objectID=%s, UPN=%s, DisplayName=%s", objectID, upn, displayName), moduleName)
	}

	// -------------------- Determine subscriptions --------------------
	var subscriptions []string

	if isMultiTenant {
		// Multi-tenant mode: collect subscriptions from all tenants
		if subscriptionFlag != "" {
			// User specified subscriptions - filter across all tenants
			subscriptionsFromFlag := parseMultiValueFlag(subscriptionFlag)

			for _, sub := range subscriptionsFromFlag {
				found := false
				// Search across all tenant contexts
				for i := range tenantContexts {
					for _, s := range tenantContexts[i].TenantInfo.Subscriptions {
						if strings.EqualFold(s.ID, sub) || strings.EqualFold(s.Name, sub) {
							subscriptions = append(subscriptions, s.ID)
							tenantContexts[i].Subscriptions = append(tenantContexts[i].Subscriptions, s.ID)
							found = true
							break
						}
					}
					if found {
						break
					}
				}

				// If not found, add it anyway (user explicitly requested)
				if !found {
					subscriptions = append(subscriptions, sub)
					if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
						logger.InfoM(fmt.Sprintf("Subscription %s not found in tenant enumeration, but adding as explicitly requested", sub), moduleName)
					}
					// Add to first tenant context as fallback
					if len(tenantContexts) > 0 {
						tenantContexts[0].Subscriptions = append(tenantContexts[0].Subscriptions, sub)
					}
				}
			}
		} else {
			// Use all accessible subscriptions from all tenants
			for i := range tenantContexts {
				for _, s := range tenantContexts[i].TenantInfo.Subscriptions {
					if s.Accessible && s.ID != "" {
						subscriptions = append(subscriptions, s.ID)
						tenantContexts[i].Subscriptions = append(tenantContexts[i].Subscriptions, s.ID)
					}
				}
			}
		}

		if len(subscriptions) == 0 {
			logger.ErrorM("No accessible subscriptions found across all tenants", moduleName)
			session.StopMonitoring()
			return nil, fmt.Errorf("no accessible subscriptions found")
		}

		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.InfoM(fmt.Sprintf("Multi-tenant mode: Total subscriptions to enumerate: %d across %d tenants", len(subscriptions), len(tenantContexts)), moduleName)
			for _, tc := range tenantContexts {
				logger.InfoM(fmt.Sprintf("  - Tenant %s (%s): %d subscriptions", tc.TenantID, tc.TenantName, len(tc.Subscriptions)), moduleName)
			}
		}
	} else {
		// Single tenant mode (backward compatibility)
		if subscriptionFlag != "" {
			// User specified subscriptions (support both comma and space delimiters)
			subscriptionsFromFlag := parseMultiValueFlag(subscriptionFlag)

			for _, sub := range subscriptionsFromFlag {
				found := false
				// First, try to match against tenant subscriptions
				for _, s := range tenantInfo.Subscriptions {
					if strings.EqualFold(s.ID, sub) || strings.EqualFold(s.Name, sub) {
						subscriptions = append(subscriptions, s.ID)
						found = true
						break
					}
				}

				// If not found in tenant enumeration, add it anyway since user explicitly requested it
				// This handles cases where IsSubscriptionAccessible temporarily fails or has permission issues
				if !found {
					subscriptions = append(subscriptions, sub)
					if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
						logger.InfoM(fmt.Sprintf("Subscription %s not found in tenant enumeration, but adding as explicitly requested", sub), moduleName)
					}
				}
			}
		} else {
			// Use all accessible subscriptions from tenant
			for _, s := range tenantInfo.Subscriptions {
				if s.Accessible && s.ID != "" {
					subscriptions = append(subscriptions, s.ID)
				}
			}
		}

		if len(subscriptions) == 0 {
			logger.ErrorM(fmt.Sprintf("No accessible subscriptions found for tenant %s", tenantID), moduleName)
			session.StopMonitoring()
			return nil, fmt.Errorf("no accessible subscriptions found")
		}

		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.InfoM(fmt.Sprintf("Subscriptions to enumerate: %v", subscriptions), moduleName)
		}
	}

	// -------------------- Build and return context --------------------
	return &CommandContext{
		Ctx:               ctx,
		Logger:            logger,
		Session:           session,
		TenantID:          tenantID,
		TenantName:        tenantName,
		TenantInfo:        tenantInfo,
		Tenants:           tenantContexts,
		IsMultiTenant:     isMultiTenant,
		UserObjectID:      objectID,
		UserUPN:           upn,
		UserDisplayName:   displayName,
		Verbosity:         verbosity,
		WrapTable:         wrap,
		OutputDirectory:   outputDirectory,
		Format:            format,
		ResourceGroupFlag: resourceGroupFlag,
		TenantFlagPresent: tenantFlagPresent,
		Subscriptions:     subscriptions,
	}, nil
}

// ------------------------------
// Output Scope Helpers - For HandleOutputSmart migration
// ------------------------------
// These helpers determine the appropriate scope type and identifiers for the new
// HandleOutputSmart function, supporting the tenant-wide consolidation strategy.

// DetermineScopeForOutput determines scope type and identifiers based on subscription count and --tenant flag presence
// Strategy:
// - --tenant flag present: ALWAYS use "tenant" scope (consolidation mode)
// - --tenant flag NOT present + single subscription: Use "subscription" scope
// - --tenant flag NOT present + multiple subscriptions: Use "subscription" scope (caller should iterate)
func DetermineScopeForOutput(subscriptions []string, tenantID, tenantName string, tenantFlagPresent bool) (scopeType string, scopeIdentifiers, scopeNames []string) {
	if tenantFlagPresent {
		// --tenant flag specified - use tenant scope for consolidation
		return "tenant", []string{tenantID}, nil
	}

	// --tenant flag NOT specified - use subscription scope
	// (For multiple subscriptions, caller should call this function once per subscription)
	if len(subscriptions) == 1 {
		return "subscription", subscriptions, nil // names will be filled by GetSubscriptionNamesForOutput
	}

	// Multiple subscriptions without --tenant flag - use subscription scope
	// This assumes caller will process each subscription separately
	return "subscription", subscriptions, nil
}

// GetSubscriptionNamesForOutput retrieves subscription names for output path generation
// Only needed when scopeType is "subscription"
func GetSubscriptionNamesForOutput(ctx context.Context, session *SafeSession, scopeType string, subscriptions []string) []string {
	if scopeType != "subscription" {
		return nil // Not needed for tenant scope
	}

	names := make([]string, len(subscriptions))
	for i, subID := range subscriptions {
		names[i] = GetSubscriptionNameFromID(ctx, session, subID)
	}
	return names
}

// ------------------------------
// Multi-Subscription Output Helpers
// ------------------------------

// GenericTableOutput is a simple implementation of CloudfoxOutput for generic table data
type GenericTableOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o GenericTableOutput) TableFiles() []internal.TableFile { return o.Table }
func (o GenericTableOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ShouldSplitBySubscription determines if output should be split into separate subscription directories
// Returns true when:
// - Multiple subscriptions are being processed
// - --tenant flag was NOT specified (tenantFlagPresent == false)
func ShouldSplitBySubscription(subscriptions []string, tenantFlagPresent bool) bool {
	return !tenantFlagPresent && len(subscriptions) > 1
}

// FilterAndWritePerSubscriptionAuto is a convenience wrapper that auto-detects the subscription column
// This enables the pattern: --subscription "sub1,sub2,sub3" (no --tenant) → creates 3 separate directories
//
// It automatically searches the header for columns containing "Subscription" and uses the first match.
//
// Parameters:
//   - allData: All collected table rows from all subscriptions
//   - header: Table header row
//   - fileBaseName: Base name for output files (e.g., "rbac", "aks")
//   - moduleName: Module name for logging (e.g., globals.AZ_RBAC_MODULE_NAME)
//
// Usage example (in module's writeOutput):
//
//	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
//	    return m.FilterAndWritePerSubscriptionAuto(ctx, logger, m.Subscriptions, m.DataRows, MyHeader, "mymodule", globals.AZ_MY_MODULE_NAME)
//	}
func (b *BaseAzureModule) FilterAndWritePerSubscriptionAuto(
	ctx context.Context,
	logger internal.Logger,
	subscriptions []string,
	allData [][]string,
	header []string,
	fileBaseName string,
	moduleName string,
) error {
	// Auto-detect subscription column
	subscriptionColumnIndex := -1
	for i, col := range header {
		colLower := strings.ToLower(col)
		if strings.Contains(colLower, "subscription") {
			// Prefer "Subscription Name" or "Subscription" over "Subscription ID"
			if strings.Contains(colLower, "name") || col == "Subscription" {
				subscriptionColumnIndex = i
				break
			}
			// Fallback to any subscription column
			if subscriptionColumnIndex == -1 {
				subscriptionColumnIndex = i
			}
		}
	}

	if subscriptionColumnIndex == -1 {
		return fmt.Errorf("could not find subscription column in header: %v", header)
	}

	if b.Verbosity >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Auto-detected subscription column: %s (index %d)", header[subscriptionColumnIndex], subscriptionColumnIndex), moduleName)
	}

	// Call the main implementation
	return b.FilterAndWritePerSubscription(ctx, logger, subscriptions, allData, subscriptionColumnIndex, header, fileBaseName, moduleName)
}

// FilterAndWritePerSubscription filters table data by subscription and writes separate outputs
// This enables the pattern: --subscription "sub1,sub2,sub3" (no --tenant) → creates 3 separate directories
//
// Parameters:
//   - subscriptionColumnIndex: The column index in the table data that contains subscription name/ID
//   - allData: All collected table rows from all subscriptions
//   - header: Table header row
//   - fileBaseName: Base name for output files (e.g., "rbac", "aks")
//   - moduleName: Module name for logging (e.g., globals.AZ_RBAC_MODULE_NAME)
//
// Usage example (in module's writeOutput):
//
//	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
//	    return m.FilterAndWritePerSubscription(ctx, logger, m.Subscriptions, m.RBACRows, 7, RBACHeader, "rbac", globals.AZ_RBAC_MODULE_NAME)
//	}
func (b *BaseAzureModule) FilterAndWritePerSubscription(
	ctx context.Context,
	logger internal.Logger,
	subscriptions []string,
	allData [][]string,
	subscriptionColumnIndex int,
	header []string,
	fileBaseName string,
	moduleName string,
) error {
	if b.Verbosity >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Splitting output into %d separate subscription directories", len(subscriptions)), moduleName)
	}

	var lastErr error
	successCount := 0

	for _, subID := range subscriptions {
		// Get subscription name for filtering
		subName := GetSubscriptionNameFromID(ctx, b.Session, subID)

		// Filter rows that belong to this subscription
		var filteredRows [][]string
		for _, row := range allData {
			if len(row) > subscriptionColumnIndex {
				// Match by subscription name OR subscription ID
				if row[subscriptionColumnIndex] == subName || row[subscriptionColumnIndex] == subID {
					filteredRows = append(filteredRows, row)
				}
			}
		}

		// Skip if no data for this subscription
		if len(filteredRows) == 0 {
			if b.Verbosity >= globals.AZ_VERBOSE_ERRORS {
				logger.InfoM(fmt.Sprintf("No data found for subscription %s, skipping", subName), moduleName)
			}
			continue
		}

		if b.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.InfoM(fmt.Sprintf("Writing %d rows for subscription %s", len(filteredRows), subName), moduleName)
		}

		// Determine scope for this single subscription (force subscription scope)
		scopeType, scopeIDs, scopeNames := DetermineScopeForOutput(
			[]string{subID}, b.TenantID, b.TenantName, false) // false = no tenant flag
		scopeNames = GetSubscriptionNamesForOutput(ctx, b.Session, scopeType, scopeIDs)

		// Create output for this subscription
		output := GenericTableOutput{
			Table: []internal.TableFile{{
				Name:   fileBaseName,
				Header: header,
				Body:   filteredRows,
			}},
		}

		// Write output for this subscription
		if err := internal.HandleOutputSmart(
			"Azure",
			b.Format,
			b.OutputDirectory,
			b.Verbosity,
			b.WrapTable,
			scopeType,
			scopeIDs,
			scopeNames,
			b.UserUPN,
			output,
		); err != nil {
			logger.ErrorM(fmt.Sprintf("Error writing output for subscription %s: %v", subName, err), moduleName)
			b.CommandCounter.Error++
			lastErr = err
		} else {
			successCount++
		}
	}

	if b.Verbosity >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Successfully wrote %d/%d subscription outputs", successCount, len(subscriptions)), moduleName)
	}

	return lastErr
}

// ------------------------------
// Multi-Tenant Output Helpers
// ------------------------------

// ShouldSplitByTenant determines if output should be split into separate tenant directories
// Returns true when:
// - Multiple tenants are being processed (IsMultiTenant == true)
// - User wants separate outputs per tenant rather than a single consolidated output
func ShouldSplitByTenant(isMultiTenant bool, tenants []TenantContext) bool {
	return isMultiTenant && len(tenants) > 1
}

// FilterAndWritePerTenantAuto filters and writes output for each tenant separately
// This enables the pattern: --tenant "tenant1,tenant2,tenant3" → creates 3 separate directories
//
// It automatically searches the header for columns containing "Tenant" and uses the first match.
// If no tenant column is found, it falls back to filtering by subscription.
//
// Parameters:
//   - allData: All collected table rows from all tenants
//   - header: Table header row
//   - fileBaseName: Base name for output files (e.g., "rbac", "aks")
//   - moduleName: Module name for logging (e.g., globals.AZ_RBAC_MODULE_NAME)
//
// Usage example (in module's writeOutput):
//
//	if azinternal.ShouldSplitByTenant(m.IsMultiTenant, m.Tenants) {
//	    return m.FilterAndWritePerTenantAuto(ctx, logger, m.Tenants, m.DataRows, MyHeader, "mymodule", globals.AZ_MY_MODULE_NAME)
//	}
func (b *BaseAzureModule) FilterAndWritePerTenantAuto(
	ctx context.Context,
	logger internal.Logger,
	tenants []TenantContext,
	allData [][]string,
	header []string,
	fileBaseName string,
	moduleName string,
) error {
	// Auto-detect tenant column (prefer "Tenant Name" or "Tenant" over "Tenant ID")
	tenantColumnIndex := -1
	for i, col := range header {
		colLower := strings.ToLower(col)
		if strings.Contains(colLower, "tenant") {
			if strings.Contains(colLower, "name") || col == "Tenant" {
				tenantColumnIndex = i
				break
			}
			if tenantColumnIndex == -1 {
				tenantColumnIndex = i
			}
		}
	}

	// If no tenant column found, try subscription-based filtering
	if tenantColumnIndex == -1 {
		if b.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.InfoM("No tenant column found in header, falling back to subscription-based filtering", moduleName)
		}
		return b.FilterAndWritePerTenantBySubscription(ctx, logger, tenants, allData, header, fileBaseName, moduleName)
	}

	if b.Verbosity >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Auto-detected tenant column: %s (index %d)", header[tenantColumnIndex], tenantColumnIndex), moduleName)
	}

	return b.FilterAndWritePerTenant(ctx, logger, tenants, allData, tenantColumnIndex, header, fileBaseName, moduleName)
}

// FilterAndWritePerTenant filters table data by tenant and writes separate outputs
//
// Parameters:
//   - tenants: All tenant contexts to process
//   - allData: All collected table rows from all tenants
//   - tenantColumnIndex: The column index that contains tenant name/ID
//   - header: Table header row
//   - fileBaseName: Base name for output files
//   - moduleName: Module name for logging
func (b *BaseAzureModule) FilterAndWritePerTenant(
	ctx context.Context,
	logger internal.Logger,
	tenants []TenantContext,
	allData [][]string,
	tenantColumnIndex int,
	header []string,
	fileBaseName string,
	moduleName string,
) error {
	if b.Verbosity >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Splitting output into %d separate tenant directories", len(tenants)), moduleName)
	}

	var lastErr error
	successCount := 0

	for _, tenant := range tenants {
		// Filter rows that belong to this tenant
		var filteredRows [][]string
		for _, row := range allData {
			if len(row) > tenantColumnIndex {
				// Match by tenant name OR tenant ID
				if row[tenantColumnIndex] == tenant.TenantName || row[tenantColumnIndex] == tenant.TenantID {
					filteredRows = append(filteredRows, row)
				}
			}
		}

		// Skip if no data for this tenant
		if len(filteredRows) == 0 {
			if b.Verbosity >= globals.AZ_VERBOSE_ERRORS {
				logger.InfoM(fmt.Sprintf("No data found for tenant %s, skipping", tenant.TenantName), moduleName)
			}
			continue
		}

		if b.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.InfoM(fmt.Sprintf("Writing %d rows for tenant %s", len(filteredRows), tenant.TenantName), moduleName)
		}

		// Create output for this tenant
		output := GenericTableOutput{
			Table: []internal.TableFile{{
				Name:   fileBaseName,
				Header: header,
				Body:   filteredRows,
			}},
		}

		// Write output for this tenant
		if err := internal.HandleOutputSmart(
			"Azure",
			b.Format,
			b.OutputDirectory,
			b.Verbosity,
			b.WrapTable,
			"tenant",                    // scope type
			[]string{tenant.TenantID},   // scope IDs
			[]string{tenant.TenantName}, // scope names
			b.UserUPN,
			output,
		); err != nil {
			logger.ErrorM(fmt.Sprintf("Error writing output for tenant %s: %v", tenant.TenantName, err), moduleName)
			b.CommandCounter.Error++
			lastErr = err
		} else {
			successCount++
		}
	}

	if b.Verbosity >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Successfully wrote %d/%d tenant outputs", successCount, len(tenants)), moduleName)
	}

	return lastErr
}

// FilterAndWritePerTenantBySubscription filters tenant data using subscription column
// This is a fallback method when no tenant column exists in the output
func (b *BaseAzureModule) FilterAndWritePerTenantBySubscription(
	ctx context.Context,
	logger internal.Logger,
	tenants []TenantContext,
	allData [][]string,
	header []string,
	fileBaseName string,
	moduleName string,
) error {
	// Auto-detect subscription column
	subscriptionColumnIndex := -1
	for i, col := range header {
		colLower := strings.ToLower(col)
		if strings.Contains(colLower, "subscription") {
			if strings.Contains(colLower, "name") || col == "Subscription" {
				subscriptionColumnIndex = i
				break
			}
			if subscriptionColumnIndex == -1 {
				subscriptionColumnIndex = i
			}
		}
	}

	if subscriptionColumnIndex == -1 {
		return fmt.Errorf("could not find tenant or subscription column in header: %v", header)
	}

	if b.Verbosity >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Using subscription column for tenant filtering: %s (index %d)", header[subscriptionColumnIndex], subscriptionColumnIndex), moduleName)
		logger.InfoM(fmt.Sprintf("Splitting output into %d separate tenant directories", len(tenants)), moduleName)
	}

	var lastErr error
	successCount := 0

	for _, tenant := range tenants {
		// Build subscription name map for this tenant
		subscriptionMap := make(map[string]bool)
		for _, subID := range tenant.Subscriptions {
			subscriptionMap[subID] = true
			subName := GetSubscriptionNameFromID(ctx, b.Session, subID)
			if subName != "" {
				subscriptionMap[subName] = true
			}
		}

		// Filter rows by subscription membership
		var filteredRows [][]string
		for _, row := range allData {
			if len(row) > subscriptionColumnIndex {
				if subscriptionMap[row[subscriptionColumnIndex]] {
					filteredRows = append(filteredRows, row)
				}
			}
		}

		// Skip if no data for this tenant
		if len(filteredRows) == 0 {
			if b.Verbosity >= globals.AZ_VERBOSE_ERRORS {
				logger.InfoM(fmt.Sprintf("No data found for tenant %s, skipping", tenant.TenantName), moduleName)
			}
			continue
		}

		if b.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.InfoM(fmt.Sprintf("Writing %d rows for tenant %s", len(filteredRows), tenant.TenantName), moduleName)
		}

		// Create output for this tenant
		output := GenericTableOutput{
			Table: []internal.TableFile{{
				Name:   fileBaseName,
				Header: header,
				Body:   filteredRows,
			}},
		}

		// Write output for this tenant
		if err := internal.HandleOutputSmart(
			"Azure",
			b.Format,
			b.OutputDirectory,
			b.Verbosity,
			b.WrapTable,
			"tenant",
			[]string{tenant.TenantID},
			[]string{tenant.TenantName},
			b.UserUPN,
			output,
		); err != nil {
			logger.ErrorM(fmt.Sprintf("Error writing output for tenant %s: %v", tenant.TenantName, err), moduleName)
			b.CommandCounter.Error++
			lastErr = err
		} else {
			successCount++
		}
	}

	if b.Verbosity >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Successfully wrote %d/%d tenant outputs", successCount, len(tenants)), moduleName)
	}

	return lastErr
}

// GetTenantFromSubscription returns the tenant context that contains the given subscription
// This is useful for mapping subscriptions back to their parent tenant in multi-tenant scenarios
func GetTenantFromSubscription(tenants []TenantContext, subscriptionID string) *TenantContext {
	for i := range tenants {
		for _, subID := range tenants[i].Subscriptions {
			if strings.EqualFold(subID, subscriptionID) {
				return &tenants[i]
			}
		}
	}
	return nil
}
