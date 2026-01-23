package shared

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/BishopFox/cloudfox/internal"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
)

// Context returns a background context for API operations.
// We do NOT use timeouts because arbitrary timeouts cause silent data loss.
// Instead, we detect session/auth errors and exit with clear messages.
func Context() context.Context {
	return context.Background()
}

// ContextWithCancel returns a cancellable context for operations that need cleanup.
// Use this when you need to cancel operations on shutdown/interrupt.
func ContextWithCancel() (context.Context, context.CancelFunc) {
	return context.WithCancel(context.Background())
}

// DEPRECATED: These functions exist only for backward compatibility during migration.
// They now return contexts WITHOUT timeouts. Modules should migrate to Context().

// ContextWithTimeout is DEPRECATED - returns context without timeout.
// Arbitrary timeouts cause silent data loss. Use Context() instead.
func ContextWithTimeout() (context.Context, context.CancelFunc) {
	// Return a cancellable context instead of a timeout context
	// This maintains the same function signature for backward compatibility
	return context.WithCancel(context.Background())
}

// ContextWithCustomTimeout is DEPRECATED - returns context without timeout.
// Arbitrary timeouts cause silent data loss. Use Context() instead.
func ContextWithCustomTimeout(_ interface{}) (context.Context, context.CancelFunc) {
	return context.WithCancel(context.Background())
}

// ContextWithLongTimeout is DEPRECATED - returns context without timeout.
// Arbitrary timeouts cause silent data loss. Use Context() instead.
func ContextWithLongTimeout() (context.Context, context.CancelFunc) {
	return context.WithCancel(context.Background())
}

// IsTimeoutError checks if the error is a context deadline exceeded error
func IsTimeoutError(err error) bool {
	return errors.Is(err, context.DeadlineExceeded)
}

// IsContextCanceled checks if the error is a context canceled error
func IsContextCanceled(err error) bool {
	return errors.Is(err, context.Canceled)
}

// IsSessionError checks if an error indicates a session/authentication problem.
// If true, the program should exit with a clear message - continuing would produce incomplete results.
func IsSessionError(err error) bool {
	if err == nil {
		return false
	}

	// Check for Kubernetes API errors
	if k8serrors.IsUnauthorized(err) {
		return true
	}
	if k8serrors.IsForbidden(err) {
		// Check if it's a token expiration
		errStr := err.Error()
		if strings.Contains(errStr, "token") && (strings.Contains(errStr, "expired") || strings.Contains(errStr, "invalid")) {
			return true
		}
		// Generic forbidden might be permission issue, not session issue
		return false
	}

	// Check error message for common session issues
	errStr := strings.ToLower(err.Error())

	// Authentication failures
	if strings.Contains(errStr, "unauthorized") ||
		strings.Contains(errStr, "authentication required") ||
		strings.Contains(errStr, "invalid bearer token") ||
		strings.Contains(errStr, "token has expired") ||
		strings.Contains(errStr, "token is expired") ||
		strings.Contains(errStr, "unable to authenticate") {
		return true
	}

	// Connection issues that indicate cluster is unreachable
	if strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "no such host") ||
		strings.Contains(errStr, "connection reset") ||
		strings.Contains(errStr, "i/o timeout") && strings.Contains(errStr, "dial") {
		return true
	}

	// Certificate issues
	if strings.Contains(errStr, "certificate") && (strings.Contains(errStr, "expired") ||
		strings.Contains(errStr, "invalid") ||
		strings.Contains(errStr, "unknown authority")) {
		return true
	}

	// Exec credential issues (for EKS, GKE, AKS)
	if strings.Contains(errStr, "exec plugin") ||
		strings.Contains(errStr, "credential") && strings.Contains(errStr, "expired") {
		return true
	}

	return false
}

// CheckSessionError checks if an error is a session error and exits if so.
// Call this on every API error to ensure session issues are caught immediately.
// Returns true if error was a session error (program will have exited).
// Returns false if error is not a session error (caller should handle normally).
func CheckSessionError(err error, logger *internal.Logger, module string) bool {
	if !IsSessionError(err) {
		return false
	}

	// Determine the specific session issue for a helpful message
	errStr := strings.ToLower(err.Error())
	var reason string

	switch {
	case strings.Contains(errStr, "unauthorized") || strings.Contains(errStr, "bearer token"):
		reason = "Authentication failed - your credentials are invalid or have expired"
	case strings.Contains(errStr, "token") && strings.Contains(errStr, "expired"):
		reason = "Your authentication token has expired - please refresh your credentials"
	case strings.Contains(errStr, "connection refused"):
		reason = "Cannot connect to the Kubernetes API server - is the cluster running?"
	case strings.Contains(errStr, "no such host"):
		reason = "Cannot resolve the Kubernetes API server hostname - check your kubeconfig"
	case strings.Contains(errStr, "certificate"):
		reason = "Certificate error - the cluster certificate may be invalid or expired"
	case strings.Contains(errStr, "exec plugin"):
		reason = "Credential plugin failed - try refreshing your cloud provider credentials (aws/gcloud/az login)"
	default:
		reason = "Session error detected"
	}

	logger.ErrorM("", module)
	logger.ErrorM("╔════════════════════════════════════════════════════════════════╗", module)
	logger.ErrorM("║                    SESSION ERROR DETECTED                       ║", module)
	logger.ErrorM("╠════════════════════════════════════════════════════════════════╣", module)
	logger.ErrorM(fmt.Sprintf("║ %s", reason), module)
	logger.ErrorM("║                                                                  ║", module)
	logger.ErrorM("║ Your Kubernetes session is no longer valid.                     ║", module)
	logger.ErrorM("║ Results may be incomplete - please fix and re-run.              ║", module)
	logger.ErrorM("╠════════════════════════════════════════════════════════════════╣", module)
	logger.ErrorM("║ Common fixes:                                                   ║", module)
	logger.ErrorM("║  • Re-authenticate: kubectl auth whoami                         ║", module)
	logger.ErrorM("║  • Refresh creds: aws eks update-kubeconfig / gcloud ...        ║", module)
	logger.ErrorM("║  • Check kubeconfig: kubectl config view                        ║", module)
	logger.ErrorM("╚════════════════════════════════════════════════════════════════╝", module)
	logger.ErrorM("", module)
	logger.ErrorM(fmt.Sprintf("Original error: %v", err), module)

	os.Exit(1)
	return true // Never reached, but satisfies compiler
}

// HandleAPIError is the primary error handler for Kubernetes API calls.
// It checks for session errors (and exits if found) or logs and continues for other errors.
// Returns true if processing should continue, false if it should stop.
func HandleAPIError(err error, logger *internal.Logger, operation, resource, namespace, module string) bool {
	if err == nil {
		return true
	}

	// First, check if this is a session error - exit immediately if so
	CheckSessionError(err, logger, module)

	// Not a session error - handle normally
	msg := fmt.Sprintf("Failed to %s %s", operation, resource)
	if namespace != "" {
		msg = fmt.Sprintf("Failed to %s %s in namespace %s", operation, resource, namespace)
	}
	msg = fmt.Sprintf("%s: %v", msg, err)

	// Check if this is a permission error (not session, just RBAC)
	if k8serrors.IsForbidden(err) {
		logger.ErrorM(fmt.Sprintf("Permission denied: %s (RBAC may restrict access)", msg), module)
		return true // Continue with other resources
	}

	// Check if resource doesn't exist (CRD not installed, etc.)
	if k8serrors.IsNotFound(err) {
		// This is often expected - CRDs might not be installed
		return true // Continue silently
	}

	// Log other errors as warnings and continue
	logger.ErrorM(fmt.Sprintf("Warning: %s", msg), module)
	return true
}

// LogTimeoutError logs a timeout-specific error message
// DEPRECATED: With smart session detection, timeouts should rarely occur.
// Returns true if processing should continue (for partial results), false otherwise
func LogTimeoutError(logger *internal.Logger, resource, namespace string, module string, fatal bool) bool {
	msg := fmt.Sprintf("Timeout listing %s", resource)
	if namespace != "" {
		msg = fmt.Sprintf("Timeout listing %s in namespace %s", resource, namespace)
	}
	if fatal {
		logger.ErrorM(msg+", aborting", module)
		return false
	}
	logger.ErrorM(fmt.Sprintf("Warning: %s, partial results returned", msg), module)
	return true
}

// ErrorSeverity indicates how critical an error is
type ErrorSeverity string

const (
	// SeverityFatal indicates an error that should stop processing
	SeverityFatal ErrorSeverity = "fatal"
	// SeverityWarning indicates an error that allows continued processing with partial results
	SeverityWarning ErrorSeverity = "warning"
	// SeverityInfo indicates a minor issue that should be logged but not prominently displayed
	SeverityInfo ErrorSeverity = "info"
)

// K8sError represents a structured Kubernetes API error
type K8sError struct {
	Op        string        // Operation: "list", "get", "describe", "watch"
	Resource  string        // Resource type: "pods", "services", "secrets", etc.
	Namespace string        // Namespace (empty for cluster-scoped resources)
	Err       error         // Underlying error
	Severity  ErrorSeverity // How critical this error is
}

// Error implements the error interface
func (e *K8sError) Error() string {
	if e.Namespace != "" {
		return fmt.Sprintf("failed to %s %s in namespace %s: %v", e.Op, e.Resource, e.Namespace, e.Err)
	}
	return fmt.Sprintf("failed to %s %s: %v", e.Op, e.Resource, e.Err)
}

// Unwrap returns the underlying error for errors.Is/errors.As support
func (e *K8sError) Unwrap() error {
	return e.Err
}

// NewK8sError creates a new K8sError with the given parameters
func NewK8sError(op, resource, namespace string, err error, severity ErrorSeverity) *K8sError {
	return &K8sError{
		Op:        op,
		Resource:  resource,
		Namespace: namespace,
		Err:       err,
		Severity:  severity,
	}
}

// Convenience constructors for common error patterns

// ListError creates a K8sError for list operations
func ListError(resource, namespace string, err error) *K8sError {
	return NewK8sError("list", resource, namespace, err, SeverityWarning)
}

// ListErrorFatal creates a fatal K8sError for list operations
func ListErrorFatal(resource, namespace string, err error) *K8sError {
	return NewK8sError("list", resource, namespace, err, SeverityFatal)
}

// GetError creates a K8sError for get operations
func GetError(resource, namespace string, err error) *K8sError {
	return NewK8sError("get", resource, namespace, err, SeverityWarning)
}

// GetErrorFatal creates a fatal K8sError for get operations
func GetErrorFatal(resource, namespace string, err error) *K8sError {
	return NewK8sError("get", resource, namespace, err, SeverityFatal)
}

// HandleError logs the error appropriately and returns whether processing should continue.
// IMPORTANT: This now checks for session errors first!
// Returns true if processing should continue, false if it should stop
func HandleError(logger *internal.Logger, k8sErr *K8sError, module string) bool {
	// First check if this is a session error
	CheckSessionError(k8sErr.Err, logger, module)

	switch k8sErr.Severity {
	case SeverityFatal:
		logger.ErrorM(k8sErr.Error(), module)
		return false // Stop processing
	case SeverityWarning:
		logger.ErrorM(fmt.Sprintf("Warning: %s", k8sErr.Error()), module)
		return true // Continue with partial results
	case SeverityInfo:
		// Info-level errors are logged to file only (via ErrorM which logs to txtLog)
		// but we prefix with "Info:" to distinguish them
		logger.InfoM(k8sErr.Error(), module)
		return true
	default:
		logger.ErrorM(k8sErr.Error(), module)
		return true
	}
}

// HandleErrorSimple is a simplified error handler that logs and returns continue status
// Use this when you just need to log and continue/stop based on severity
func HandleErrorSimple(logger *internal.Logger, op, resource, namespace string, err error, module string, fatal bool) bool {
	// First check if this is a session error
	CheckSessionError(err, logger, module)

	severity := SeverityWarning
	if fatal {
		severity = SeverityFatal
	}
	k8sErr := NewK8sError(op, resource, namespace, err, severity)
	return HandleError(logger, k8sErr, module)
}

// LogListError is a convenience function for logging list operation errors
// Returns true if processing should continue (non-fatal), false otherwise
func LogListError(logger *internal.Logger, resource, namespace string, err error, module string, fatal bool) bool {
	// First check if this is a session error
	CheckSessionError(err, logger, module)

	var k8sErr *K8sError
	if fatal {
		k8sErr = ListErrorFatal(resource, namespace, err)
	} else {
		k8sErr = ListError(resource, namespace, err)
	}
	return HandleError(logger, k8sErr, module)
}

// LogGetError is a convenience function for logging get operation errors
// Returns true if processing should continue (non-fatal), false otherwise
func LogGetError(logger *internal.Logger, resource, namespace string, err error, module string, fatal bool) bool {
	// First check if this is a session error
	CheckSessionError(err, logger, module)

	var k8sErr *K8sError
	if fatal {
		k8sErr = GetErrorFatal(resource, namespace, err)
	} else {
		k8sErr = GetError(resource, namespace, err)
	}
	return HandleError(logger, k8sErr, module)
}
