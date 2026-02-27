package shared

// AggregateFromProjects combines items from a per-project map into a single slice.
// This is a common pattern in GCP modules where data is collected per-project
// and then needs to be aggregated for output.
//
// Note: Go generics require Go 1.18+. If you need to support older versions,
// use the type-specific functions below or copy this pattern.
//
// Example usage:
//
//	projectBuckets := map[string][]BucketInfo{
//	    "project-a": {bucket1, bucket2},
//	    "project-b": {bucket3},
//	}
//	allBuckets := AggregateFromProjects(projectBuckets)
//	// Result: []BucketInfo{bucket1, bucket2, bucket3}
func AggregateFromProjects[T any](projectMap map[string][]T) []T {
	var result []T
	for _, items := range projectMap {
		result = append(result, items...)
	}
	return result
}

// AggregateWithProject combines items from a per-project map and adds project context.
// The transform function receives the project ID and item, allowing you to
// enrich or transform items as they're aggregated.
//
// Example usage:
//
//	type EnrichedItem struct {
//	    ProjectID string
//	    Name      string
//	}
//	allItems := AggregateWithProject(projectMap, func(projectID string, item Item) EnrichedItem {
//	    return EnrichedItem{ProjectID: projectID, Name: item.Name}
//	})
func AggregateWithProject[T any, R any](projectMap map[string][]T, transform func(projectID string, item T) R) []R {
	var result []R
	for projectID, items := range projectMap {
		for _, item := range items {
			result = append(result, transform(projectID, item))
		}
	}
	return result
}

// CountByProject returns a count of items per project
func CountByProject[T any](projectMap map[string][]T) map[string]int {
	counts := make(map[string]int)
	for projectID, items := range projectMap {
		counts[projectID] = len(items)
	}
	return counts
}

// TotalCount returns the total count across all projects
func TotalCount[T any](projectMap map[string][]T) int {
	total := 0
	for _, items := range projectMap {
		total += len(items)
	}
	return total
}

// FilterByProject returns items only from specified projects
func FilterByProject[T any](projectMap map[string][]T, projectIDs []string) []T {
	projectSet := make(map[string]bool)
	for _, pid := range projectIDs {
		projectSet[pid] = true
	}

	var result []T
	for projectID, items := range projectMap {
		if projectSet[projectID] {
			result = append(result, items...)
		}
	}
	return result
}

// FilterItems returns items that match the predicate
func FilterItems[T any](items []T, predicate func(T) bool) []T {
	var result []T
	for _, item := range items {
		if predicate(item) {
			result = append(result, item)
		}
	}
	return result
}

// MapItems transforms each item using the provided function
func MapItems[T any, R any](items []T, transform func(T) R) []R {
	result := make([]R, len(items))
	for i, item := range items {
		result[i] = transform(item)
	}
	return result
}

// GroupBy groups items by a key extracted from each item
func GroupBy[T any, K comparable](items []T, keyFunc func(T) K) map[K][]T {
	result := make(map[K][]T)
	for _, item := range items {
		key := keyFunc(item)
		result[key] = append(result[key], item)
	}
	return result
}

// UniqueStrings returns unique strings from a slice
func UniqueStrings(items []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}

// FlattenStringSlices flattens a slice of string slices into a single slice
func FlattenStringSlices(slices [][]string) []string {
	var result []string
	for _, slice := range slices {
		result = append(result, slice...)
	}
	return result
}

// CountByField counts items grouped by a field value
func CountByField[T any](items []T, fieldFunc func(T) string) map[string]int {
	counts := make(map[string]int)
	for _, item := range items {
		key := fieldFunc(item)
		counts[key]++
	}
	return counts
}

// SortedKeys returns the keys of a map in sorted order
// Note: This only works with string keys
func SortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// Simple bubble sort for small maps
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[i] > keys[j] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	return keys
}

// First returns the first item matching the predicate, or nil if none found
func First[T any](items []T, predicate func(T) bool) *T {
	for i := range items {
		if predicate(items[i]) {
			return &items[i]
		}
	}
	return nil
}

// Any returns true if any item matches the predicate
func Any[T any](items []T, predicate func(T) bool) bool {
	for _, item := range items {
		if predicate(item) {
			return true
		}
	}
	return false
}

// All returns true if all items match the predicate
func All[T any](items []T, predicate func(T) bool) bool {
	for _, item := range items {
		if !predicate(item) {
			return false
		}
	}
	return true
}

// None returns true if no items match the predicate
func None[T any](items []T, predicate func(T) bool) bool {
	return !Any(items, predicate)
}

// Contains checks if a slice contains a specific value
func Contains[T comparable](items []T, value T) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}

// ContainsString checks if a string slice contains a specific string
func ContainsString(items []string, value string) bool {
	return Contains(items, value)
}

// Deduplicate removes duplicate items from a slice (preserves order)
func Deduplicate[T comparable](items []T) []T {
	seen := make(map[T]bool)
	var result []T
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}

// Partition splits items into two slices based on a predicate
// First slice contains items where predicate is true,
// second slice contains items where predicate is false
func Partition[T any](items []T, predicate func(T) bool) ([]T, []T) {
	var trueItems, falseItems []T
	for _, item := range items {
		if predicate(item) {
			trueItems = append(trueItems, item)
		} else {
			falseItems = append(falseItems, item)
		}
	}
	return trueItems, falseItems
}
