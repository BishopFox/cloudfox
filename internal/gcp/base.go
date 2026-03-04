package gcpinternal

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/spf13/cobra"
	"google.golang.org/api/googleapi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ------------------------------
// Common GCP API Error Types
// ------------------------------
var (
	ErrAPINotEnabled      = errors.New("API not enabled")
	ErrPermissionDenied   = errors.New("permission denied")
	ErrNotFound           = errors.New("resource not found")
	ErrVPCServiceControls = errors.New("blocked by VPC Service Controls")
	ErrSessionInvalid     = errors.New("session invalid")
)

// ------------------------------
// Session Error Detection
// ------------------------------
// These functions detect when GCP credentials are invalid/expired
// and exit with clear messages to prevent incomplete data.

// IsGCPSessionError checks if an error indicates a session/authentication problem.
// If true, the program should exit with a clear message - continuing would produce incomplete results.
func IsGCPSessionError(err error) bool {
	if err == nil {
		return false
	}

	// Check for gRPC status errors
	if grpcStatus, ok := status.FromError(err); ok {
		switch grpcStatus.Code() {
		case codes.Unauthenticated:
			return true
		}
	}

	// Check for REST API errors (googleapi.Error)
	var googleErr *googleapi.Error
	if errors.As(err, &googleErr) {
		// 401 Unauthorized is always a session error
		if googleErr.Code == 401 {
			return true
		}
	}

	// Check error message for common session issues
	errStr := strings.ToLower(err.Error())

	// Authentication failures
	if strings.Contains(errStr, "unauthenticated") ||
		strings.Contains(errStr, "invalid_grant") ||
		strings.Contains(errStr, "token has been expired or revoked") ||
		strings.Contains(errStr, "token expired") ||
		strings.Contains(errStr, "refresh token") && strings.Contains(errStr, "expired") ||
		strings.Contains(errStr, "credentials") && strings.Contains(errStr, "expired") ||
		strings.Contains(errStr, "unable to authenticate") ||
		strings.Contains(errStr, "authentication failed") ||
		strings.Contains(errStr, "could not find default credentials") ||
		strings.Contains(errStr, "application default credentials") && strings.Contains(errStr, "not found") {
		return true
	}

	// Connection issues that indicate GCP is unreachable
	if strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "no such host") ||
		strings.Contains(errStr, "connection reset") {
		return true
	}

	// OAuth issues
	if strings.Contains(errStr, "oauth2") && (strings.Contains(errStr, "token") || strings.Contains(errStr, "expired")) {
		return true
	}

	return false
}

// CheckGCPSessionError checks if an error is a session error and exits if so.
// Call this on every API error to ensure session issues are caught immediately.
// Returns true if error was a session error (program will have exited).
// Returns false if error is not a session error (caller should handle normally).
func CheckGCPSessionError(err error, logger internal.Logger, moduleName string) bool {
	if !IsGCPSessionError(err) {
		return false
	}

	// Determine the specific session issue for a helpful message
	errStr := strings.ToLower(err.Error())
	var reason string

	switch {
	case strings.Contains(errStr, "invalid_grant") || strings.Contains(errStr, "token has been expired or revoked"):
		reason = "Your GCP credentials have expired or been revoked"
	case strings.Contains(errStr, "refresh token") && strings.Contains(errStr, "expired"):
		reason = "Your refresh token has expired - please re-authenticate"
	case strings.Contains(errStr, "could not find default credentials") || strings.Contains(errStr, "application default credentials"):
		reason = "No GCP credentials found - run: gcloud auth application-default login"
	case strings.Contains(errStr, "unauthenticated") || strings.Contains(errStr, "authentication failed"):
		reason = "Authentication failed - your credentials are invalid"
	case strings.Contains(errStr, "connection refused") || strings.Contains(errStr, "no such host"):
		reason = "Cannot connect to GCP APIs - check your network connection"
	default:
		reason = "Session error detected - credentials may be invalid"
	}

	logger.ErrorM("", moduleName)
	logger.ErrorM("╔════════════════════════════════════════════════════════════════╗", moduleName)
	logger.ErrorM("║                    SESSION ERROR DETECTED                       ║", moduleName)
	logger.ErrorM("╠════════════════════════════════════════════════════════════════╣", moduleName)
	logger.ErrorM(fmt.Sprintf("║ %s", reason), moduleName)
	logger.ErrorM("║                                                                  ║", moduleName)
	logger.ErrorM("║ Your GCP session is no longer valid.                            ║", moduleName)
	logger.ErrorM("║ Results may be incomplete - please fix and re-run.              ║", moduleName)
	logger.ErrorM("╠════════════════════════════════════════════════════════════════╣", moduleName)
	logger.ErrorM("║ Common fixes:                                                   ║", moduleName)
	logger.ErrorM("║  • Re-authenticate: gcloud auth login                           ║", moduleName)
	logger.ErrorM("║  • ADC login: gcloud auth application-default login             ║", moduleName)
	logger.ErrorM("║  • Check account: gcloud auth list                              ║", moduleName)
	logger.ErrorM("║  • Service account: check GOOGLE_APPLICATION_CREDENTIALS        ║", moduleName)
	logger.ErrorM("╚════════════════════════════════════════════════════════════════╝", moduleName)
	logger.ErrorM("", moduleName)
	logger.ErrorM(fmt.Sprintf("Original error: %v", err), moduleName)

	os.Exit(1)
	return true // Never reached, but satisfies compiler
}

// ParseGCPError converts GCP API errors into cleaner, standardized error types
// This should be used by all GCP service modules for consistent error handling
// Handles both REST API errors (googleapi.Error) and gRPC errors (status.Error)
func ParseGCPError(err error, apiName string) error {
	if err == nil {
		return nil
	}

	// Check for gRPC status errors (used by Cloud Asset, Spanner, and other gRPC-based APIs)
	if grpcStatus, ok := status.FromError(err); ok {
		errStr := err.Error()

		switch grpcStatus.Code() {
		case codes.PermissionDenied:
			// Check for SERVICE_DISABLED in error details or message
			if strings.Contains(errStr, "SERVICE_DISABLED") {
				return fmt.Errorf("%w: %s", ErrAPINotEnabled, apiName)
			}
			// Check for quota project requirement (API not enabled or misconfigured)
			if strings.Contains(errStr, "requires a quota project") {
				return fmt.Errorf("%w: %s (set quota project with: gcloud auth application-default set-quota-project PROJECT_ID)", ErrAPINotEnabled, apiName)
			}
			return ErrPermissionDenied

		case codes.NotFound:
			return ErrNotFound

		case codes.Unauthenticated:
			return fmt.Errorf("authentication failed - check credentials")

		case codes.ResourceExhausted:
			return fmt.Errorf("rate limited - too many requests")

		case codes.Unavailable, codes.Internal:
			return fmt.Errorf("GCP service error: %s", grpcStatus.Message())

		case codes.InvalidArgument:
			return fmt.Errorf("bad request: %s", grpcStatus.Message())
		}

		// Default: return cleaner error message
		return fmt.Errorf("gRPC error (%s): %s", grpcStatus.Code().String(), grpcStatus.Message())
	}

	// Check for REST API errors (googleapi.Error)
	var googleErr *googleapi.Error
	if errors.As(err, &googleErr) {
		errStr := googleErr.Error()

		switch googleErr.Code {
		case 403:
			// Check for SERVICE_DISABLED first - this is usually the root cause
			if strings.Contains(errStr, "SERVICE_DISABLED") {
				return fmt.Errorf("%w: %s", ErrAPINotEnabled, apiName)
			}
			// Check for VPC Service Controls
			if strings.Contains(errStr, "VPC_SERVICE_CONTROLS") ||
				strings.Contains(errStr, "SECURITY_POLICY_VIOLATED") ||
				strings.Contains(errStr, "organization's policy") {
				return ErrVPCServiceControls
			}
			// Permission denied
			if strings.Contains(errStr, "PERMISSION_DENIED") ||
				strings.Contains(errStr, "does not have") ||
				strings.Contains(errStr, "permission") {
				return ErrPermissionDenied
			}
			// Generic 403
			return ErrPermissionDenied

		case 404:
			return ErrNotFound

		case 400:
			return fmt.Errorf("bad request: %s", googleErr.Message)

		case 429:
			return fmt.Errorf("rate limited - too many requests")

		case 500, 502, 503, 504:
			return fmt.Errorf("GCP service error (code %d)", googleErr.Code)
		}

		// Default: return cleaner error message
		return fmt.Errorf("API error (code %d): %s", googleErr.Code, googleErr.Message)
	}

	// Fallback: check error string for common patterns
	errStr := err.Error()
	if strings.Contains(errStr, "SERVICE_DISABLED") {
		return fmt.Errorf("%w: %s", ErrAPINotEnabled, apiName)
	}
	// Check for quota project requirement (common with ADC)
	if strings.Contains(errStr, "requires a quota project") {
		return fmt.Errorf("%w: %s (set quota project with: gcloud auth application-default set-quota-project PROJECT_ID)", ErrAPINotEnabled, apiName)
	}
	if strings.Contains(errStr, "PERMISSION_DENIED") || strings.Contains(errStr, "PermissionDenied") {
		return ErrPermissionDenied
	}

	return err
}

// IsPermissionDenied checks if an error is a permission denied error
func IsPermissionDenied(err error) bool {
	return errors.Is(err, ErrPermissionDenied)
}

// IsAPINotEnabled checks if an error is an API not enabled error
func IsAPINotEnabled(err error) bool {
	return errors.Is(err, ErrAPINotEnabled)
}

// HandleGCPError logs an appropriate message for a GCP API error and returns true if execution should continue
// Returns false if the error is fatal and the caller should stop processing
// IMPORTANT: This now checks for session errors first and will exit if credentials are invalid!
func HandleGCPError(err error, logger internal.Logger, moduleName string, resourceDesc string) bool {
	if err == nil {
		return true // No error, continue
	}

	// CRITICAL: Check for session errors first - exit immediately if credentials are invalid
	// This prevents incomplete data from being saved
	CheckGCPSessionError(err, logger, moduleName)

	// Parse the raw GCP error into a standardized error type
	parsedErr := ParseGCPError(err, "")

	switch {
	case errors.Is(parsedErr, ErrAPINotEnabled):
		logger.ErrorM(fmt.Sprintf("%s - API not enabled", resourceDesc), moduleName)
		return false // Can't continue without API enabled

	case errors.Is(parsedErr, ErrVPCServiceControls):
		logger.ErrorM(fmt.Sprintf("%s - blocked by VPC Service Controls", resourceDesc), moduleName)
		return true // Can continue with other resources

	case errors.Is(parsedErr, ErrPermissionDenied):
		logger.ErrorM(fmt.Sprintf("%s - permission denied", resourceDesc), moduleName)
		return true // Can continue with other resources

	case errors.Is(parsedErr, ErrNotFound):
		// Not found is often expected, don't log as error
		return true

	default:
		// For unknown errors, log a concise message without the full error details
		logger.ErrorM(fmt.Sprintf("%s - error occurred", resourceDesc), moduleName)
		return true // Continue with other resources
	}
}

// ------------------------------
// CommandContext holds all common initialization data for GCP commands
// ------------------------------
type CommandContext struct {
	// Context and logger
	Ctx    context.Context
	Logger internal.Logger

	// Project information
	ProjectIDs   []string
	ProjectNames map[string]string // ProjectID -> DisplayName mapping
	Account      string            // Authenticated account email

	// Configuration flags
	Verbosity       int
	WrapTable       bool
	OutputDirectory string
	Format          string
	Goroutines      int
	FlatOutput      bool // When true, use legacy flat output structure

	// Hierarchy support for per-project output
	Hierarchy *ScopeHierarchy // Populated by DetectScopeHierarchy
}

// ------------------------------
// BaseGCPModule - Embeddable struct with common fields for all GCP modules
// ------------------------------
// This struct eliminates duplicate field declarations across modules.
// Modules embed this struct instead of declaring these fields individually.
//
// Usage:
//
//	type BucketsModule struct {
//	    gcpinternal.BaseGCPModule  // Embed the base fields
//
//	    // Module-specific fields
//	    Buckets []BucketInfo
//	    mu      sync.Mutex
//	}
type BaseGCPModule struct {
	// Project and identity
	ProjectIDs   []string
	ProjectNames map[string]string // ProjectID -> DisplayName mapping
	Account      string            // Authenticated account email

	// Configuration
	Verbosity       int
	WrapTable       bool
	OutputDirectory string
	Format          string
	Goroutines      int
	FlatOutput      bool // When true, use legacy flat output structure

	// Hierarchy support for per-project output
	Hierarchy *ScopeHierarchy // Populated by DetectScopeHierarchy

	// Progress tracking (AWS/Azure style)
	CommandCounter internal.CommandCounter
}

// GetProjectName returns the display name for a project ID, falling back to the ID if not found
func (b *BaseGCPModule) GetProjectName(projectID string) string {
	if b.ProjectNames != nil {
		if name, ok := b.ProjectNames[projectID]; ok {
			return name
		}
	}
	return projectID
}

// ------------------------------
// NewBaseGCPModule - Helper to create BaseGCPModule from CommandContext
// ------------------------------
func NewBaseGCPModule(cmdCtx *CommandContext) BaseGCPModule {
	return BaseGCPModule{
		ProjectIDs:      cmdCtx.ProjectIDs,
		ProjectNames:    cmdCtx.ProjectNames,
		Account:         cmdCtx.Account,
		Verbosity:       cmdCtx.Verbosity,
		WrapTable:       cmdCtx.WrapTable,
		OutputDirectory: cmdCtx.OutputDirectory,
		Format:          cmdCtx.Format,
		Goroutines:      cmdCtx.Goroutines,
		FlatOutput:      cmdCtx.FlatOutput,
		Hierarchy:       cmdCtx.Hierarchy,
	}
}

// BuildPathBuilder creates a PathBuilder function for hierarchical output
// This function returns a closure that builds paths based on the module's configuration
func (b *BaseGCPModule) BuildPathBuilder() internal.PathBuilder {
	return func(scopeType string, scopeID string) string {
		if b.Hierarchy == nil {
			// Fallback to flat output if no hierarchy is available
			return BuildFlatPath(b.OutputDirectory, b.Account, &ScopeHierarchy{})
		}
		return BuildHierarchicalPath(b.OutputDirectory, b.Account, b.Hierarchy, scopeType, scopeID)
	}
}

// ------------------------------
// ProjectProcessor - Callback function type for processing individual projects
// ------------------------------
type ProjectProcessor func(ctx context.Context, projectID string, logger internal.Logger)

// ------------------------------
// RunProjectEnumeration - Orchestrates enumeration across multiple projects with concurrency
// ------------------------------
// This method centralizes the project enumeration orchestration pattern.
// It handles WaitGroup, semaphore, spinner, and CommandCounter management automatically.
//
// Usage:
//
//	func (m *StorageModule) Execute(ctx context.Context, logger internal.Logger) {
//	    m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_STORAGE_MODULE_NAME, m.processProject)
//	    m.writeOutput(ctx, logger)
//	}
func (b *BaseGCPModule) RunProjectEnumeration(
	ctx context.Context,
	logger internal.Logger,
	projectIDs []string,
	moduleName string,
	processor ProjectProcessor,
) {
	logger.InfoM(fmt.Sprintf("Enumerating resources for %d project(s)", len(projectIDs)), moduleName)

	// Setup synchronization primitives
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, b.Goroutines)

	// Start progress spinner
	spinnerDone := make(chan bool)
	go internal.SpinUntil(moduleName, &b.CommandCounter, spinnerDone, "projects")

	// Process each project with goroutines
	for _, projectID := range projectIDs {
		b.CommandCounter.Total++
		b.CommandCounter.Pending++
		wg.Add(1)

		go func(project string) {
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
			processor(ctx, project, logger)
		}(projectID)
	}

	// Wait for all projects to complete
	wg.Wait()

	// Stop spinner
	spinnerDone <- true
	<-spinnerDone
}

// ------------------------------
// parseMultiValueFlag parses a flag value that can contain comma-separated
// and/or space-separated values
// ------------------------------
func parseMultiValueFlag(flagValue string) []string {
	if flagValue == "" {
		return nil
	}

	// Replace commas with spaces, then split by whitespace
	normalized := strings.ReplaceAll(flagValue, ",", " ")
	fields := strings.Fields(normalized)

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
// InitializeCommandContext - Eliminates duplicate initialization code across commands
// ------------------------------
// This helper extracts flags, resolves projects and account info.
//
// Usage:
//
//	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_STORAGE_MODULE_NAME)
//	if err != nil {
//	    return // error already logged
//	}
func InitializeCommandContext(cmd *cobra.Command, moduleName string) (*CommandContext, error) {
	ctx := cmd.Context()
	logger := internal.NewLogger()

	// -------------------- Extract flags --------------------
	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")
	flatOutput, _ := parentCmd.PersistentFlags().GetBool("flat-output")

	// Default to "all" format if not set (GCP doesn't expose this flag yet)
	if format == "" {
		format = "all"
	}

	// -------------------- Get project IDs from context --------------------
	var projectIDs []string
	if value, ok := ctx.Value("projectIDs").([]string); ok && len(value) > 0 {
		projectIDs = value
	} else {
		logger.ErrorM("Could not retrieve projectIDs from context or value is empty", moduleName)
		return nil, fmt.Errorf("no project IDs provided")
	}

	// -------------------- Get project names from context --------------------
	var projectNames map[string]string
	if value, ok := ctx.Value("projectNames").(map[string]string); ok {
		projectNames = value
	} else {
		// Initialize empty map if not provided - modules can still work without names
		projectNames = make(map[string]string)
		for _, id := range projectIDs {
			projectNames[id] = id // fallback to using ID as name
		}
	}

	// -------------------- Get account from context --------------------
	var account string
	if value, ok := ctx.Value("account").(string); ok {
		account = value
	} else {
		logger.ErrorM("Could not retrieve account email from context", moduleName)
		// Don't fail - some modules can continue without account info
	}

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Resolved %d project(s), account: %s", len(projectIDs), account), moduleName)
	}

	// -------------------- Get hierarchy from context (if populated) --------------------
	var hierarchy *ScopeHierarchy
	if value, ok := ctx.Value("hierarchy").(*ScopeHierarchy); ok {
		hierarchy = value
	}

	// -------------------- Build and return context --------------------
	return &CommandContext{
		Ctx:             ctx,
		Logger:          logger,
		ProjectIDs:      projectIDs,
		ProjectNames:    projectNames,
		Account:         account,
		Verbosity:       verbosity,
		WrapTable:       wrap,
		OutputDirectory: outputDirectory,
		Format:          format,
		Goroutines:      5, // Default concurrency
		FlatOutput:      flatOutput,
		Hierarchy:       hierarchy,
	}, nil
}
