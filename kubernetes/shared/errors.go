package shared

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/BishopFox/cloudfox/internal"
)

// Default timeouts for Kubernetes API operations
const (
	// DefaultTimeout is the default timeout for most API operations
	DefaultTimeout = 30 * time.Second
	// LongTimeout is for operations that may take longer (large clusters)
	LongTimeout = 60 * time.Second
	// ShortTimeout is for quick operations like single resource gets
	ShortTimeout = 10 * time.Second
)

// ContextWithTimeout creates a context with the default timeout
// Returns the context and a cancel function that MUST be called (use defer)
func ContextWithTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), DefaultTimeout)
}

// ContextWithCustomTimeout creates a context with a custom timeout
// Returns the context and a cancel function that MUST be called (use defer)
func ContextWithCustomTimeout(timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), timeout)
}

// ContextWithLongTimeout creates a context with an extended timeout for large operations
// Returns the context and a cancel function that MUST be called (use defer)
func ContextWithLongTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), LongTimeout)
}

// IsTimeoutError checks if the error is a context deadline exceeded error
func IsTimeoutError(err error) bool {
	return errors.Is(err, context.DeadlineExceeded)
}

// IsContextCanceled checks if the error is a context canceled error
func IsContextCanceled(err error) bool {
	return errors.Is(err, context.Canceled)
}

// LogTimeoutError logs a timeout-specific error message
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

// HandleError logs the error appropriately and returns whether processing should continue
// Returns true if processing should continue, false if it should stop
func HandleError(logger *internal.Logger, k8sErr *K8sError, module string) bool {
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
	var k8sErr *K8sError
	if fatal {
		k8sErr = GetErrorFatal(resource, namespace, err)
	} else {
		k8sErr = GetError(resource, namespace, err)
	}
	return HandleError(logger, k8sErr, module)
}
