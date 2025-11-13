package kubernetes

import "strings"

// ImageTagType returns the tag part of a container image, or "latest" if missing.
func ImageTagType(image string) string {
	parts := strings.Split(image, ":")
	if len(parts) > 1 {
		return parts[len(parts)-1]
	}
	return "latest"
}
