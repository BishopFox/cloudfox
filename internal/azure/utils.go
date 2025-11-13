package azure

import (
	"fmt"
	"strings"
	"time"
)

// ------------------------- HELPERS -------------------------

func ptrString(s string) *string {
	if s == "" {
		empty := "Unknown"
		return &empty
	}
	return &s
}

func SafeString(s string) string {
	if s == "" {
		return "Unknown"
	}
	return s
}

func SafeStringPtr(s *string) string {
	if s == nil {
		return "UNKNOWN"
	}
	return *s
}

func SafeStringSlice(slice []*string) []string {
	result := []string{}
	for _, s := range slice {
		if s != nil {
			result = append(result, *s)
		}
	}
	return result
}

// ExtractResourceName extracts the resource name from an Azure resource ID
func ExtractResourceName(resourceID string) string {
	parts := strings.Split(resourceID, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return ""
}

func SafePtr(s *string) *string {
	if s == nil {
		val := "N/A"
		return &val
	}
	return s
}

func SafeValueString(val interface{}) string {
	if val == nil {
		return ""
	}
	if s, ok := val.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", val)
}

func NormalizeSubscriptionID(id string) string {
	if id == "" {
		return ""
	}
	return strings.TrimPrefix(strings.ToLower(strings.TrimSpace(id)), "/subscriptions/")
}

// SafeBoolPtr returns the value of a *bool, or false if nil
func SafeBoolPtr(b *bool) *bool {
	if b == nil {
		return nil
	}
	val := *b
	return &val
}

func SafeBool(b bool) bool {
	if b == false {
		return false
	}
	val := b
	return val
}

// SafeInt32Ptr returns the value of a *int32, or 0 if nil
func SafeInt32Ptr(i any) *int32 {
	if i == nil {
		return nil
	}
	switch v := i.(type) {
	case int32:
		val := v
		return &val
	case float64:
		// SDK sometimes returns numeric values as float64
		val := int32(v)
		return &val
	case int:
		val := int32(v)
		return &val
	default:
		return nil
	}
}

func Int32FromInterface(i any) int32 {
	if i == nil {
		return 0
	}
	if v, ok := i.(*int32); ok {
		return *v
	}
	if v, ok := i.(int32); ok {
		return v
	}
	return 0
}

// SafeTimePtr returns a pointer to a time.Time, or nil if the input is zero.
func SafeTimePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func SafeTime(t time.Time) time.Time {
	if t.IsZero() {
		return time.Time{}
	}
	return t
}

func SafePtrTimePtr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	str := t.Format(time.RFC3339)
	return &str
}

// Optional: If you deal with *time.Time already
func SafeTimePtrFromPtr(t *time.Time) *time.Time {
	if t == nil || t.IsZero() {
		return nil
	}
	return t
}

func SafeEnumPtr[T fmt.Stringer](e *T) *string {
	if e == nil {
		return nil
	}
	// Dereference the pointer to call String()
	str := (*e).String()
	return &str
}
