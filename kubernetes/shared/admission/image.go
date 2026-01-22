package admission

import (
	"regexp"
	"strings"
)

// ImageVerifier provides centralized image verification for admission modules
type ImageVerifier struct {
	registry *EngineRegistry
}

// NewImageVerifier creates a new ImageVerifier with the given registry
func NewImageVerifier(registry *EngineRegistry) *ImageVerifier {
	return &ImageVerifier{
		registry: registry,
	}
}

// ImageVerificationResult contains detailed results from image verification
type ImageVerificationResult struct {
	Matched      bool
	EngineID     string
	EngineName   string
	Category     EngineCategory
	FromTrusted  bool   // Image was from a trusted registry
	MatchedImage string // The image that matched
	Confidence   string // "high", "medium", "low"
}

// VerifyImage checks if an image belongs to a known engine
func (v *ImageVerifier) VerifyImage(image string) ImageVerificationResult {
	result := ImageVerificationResult{
		MatchedImage: image,
	}

	imageLower := strings.ToLower(image)

	for id, engine := range v.registry.engines {
		// Check if image is from a trusted registry
		fromTrusted := false
		for _, registry := range engine.TrustedRegistries {
			if strings.HasPrefix(imageLower, strings.ToLower(registry)) {
				fromTrusted = true
				break
			}
		}

		// Build and check image regexes
		if len(engine.imageRegexes) == 0 && len(engine.ImagePatterns) > 0 {
			engine.buildImageRegexes()
		}

		for _, regex := range engine.imageRegexes {
			if regex.MatchString(imageLower) {
				result.Matched = true
				result.EngineID = id
				result.EngineName = engine.Name
				result.Category = engine.Category
				result.FromTrusted = fromTrusted

				// Determine confidence
				if fromTrusted {
					result.Confidence = "high"
				} else {
					result.Confidence = "medium"
				}
				return result
			}
		}
	}

	return result
}

// VerifyImageForEngine checks if an image matches a specific engine
func (v *ImageVerifier) VerifyImageForEngine(image string, engineID string) ImageVerificationResult {
	result := ImageVerificationResult{
		MatchedImage: image,
	}

	engine := v.registry.GetEngine(engineID)
	if engine == nil {
		return result
	}

	imageLower := strings.ToLower(image)

	// Check if image is from a trusted registry
	for _, registry := range engine.TrustedRegistries {
		if strings.HasPrefix(imageLower, strings.ToLower(registry)) {
			result.FromTrusted = true
			break
		}
	}

	// Build and check image regexes
	if len(engine.imageRegexes) == 0 && len(engine.ImagePatterns) > 0 {
		engine.buildImageRegexes()
	}

	for _, regex := range engine.imageRegexes {
		if regex.MatchString(imageLower) {
			result.Matched = true
			result.EngineID = engineID
			result.EngineName = engine.Name
			result.Category = engine.Category

			if result.FromTrusted {
				result.Confidence = "high"
			} else {
				result.Confidence = "medium"
			}
			return result
		}
	}

	return result
}

// VerifyImagesForCategory returns all images that match engines in a category
func (v *ImageVerifier) VerifyImagesForCategory(images []string, category EngineCategory) []ImageVerificationResult {
	var results []ImageVerificationResult

	engines := v.registry.GetEnginesByCategory(category)

	for _, image := range images {
		imageLower := strings.ToLower(image)

		for _, engine := range engines {
			// Check if image is from a trusted registry
			fromTrusted := false
			for _, registry := range engine.TrustedRegistries {
				if strings.HasPrefix(imageLower, strings.ToLower(registry)) {
					fromTrusted = true
					break
				}
			}

			// Build and check image regexes
			if len(engine.imageRegexes) == 0 && len(engine.ImagePatterns) > 0 {
				engine.buildImageRegexes()
			}

			for _, regex := range engine.imageRegexes {
				if regex.MatchString(imageLower) {
					confidence := "medium"
					if fromTrusted {
						confidence = "high"
					}

					results = append(results, ImageVerificationResult{
						Matched:      true,
						EngineID:     engine.ID,
						EngineName:   engine.Name,
						Category:     engine.Category,
						FromTrusted:  fromTrusted,
						MatchedImage: image,
						Confidence:   confidence,
					})
					break
				}
			}
		}
	}

	return results
}

// ExtractImageTag extracts the tag from an image reference
func ExtractImageTag(image string) string {
	// Handle digest references (sha256:...)
	if strings.Contains(image, "@sha256:") {
		parts := strings.Split(image, "@")
		if len(parts) > 1 {
			return parts[1]
		}
	}

	// Handle tag references
	parts := strings.Split(image, ":")
	if len(parts) > 1 {
		// Make sure we're not in the registry part (e.g., localhost:5000/image)
		lastPart := parts[len(parts)-1]
		if !strings.Contains(lastPart, "/") {
			return lastPart
		}
	}

	return "latest"
}

// ExtractImageName extracts the image name without registry and tag
func ExtractImageName(image string) string {
	// Remove tag/digest
	image = strings.Split(image, ":")[0]
	image = strings.Split(image, "@")[0]

	// Handle registry prefix
	parts := strings.Split(image, "/")
	if len(parts) > 1 {
		// Check if first part looks like a registry
		if strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":") {
			parts = parts[1:]
		}
	}

	return strings.Join(parts, "/")
}

// IsDigestReference checks if an image reference uses a digest
func IsDigestReference(image string) bool {
	return strings.Contains(image, "@sha256:")
}

// ImagePatternMatcher provides flexible pattern matching for images
type ImagePatternMatcher struct {
	patterns []*regexp.Regexp
}

// NewImagePatternMatcher creates a matcher from a list of patterns
func NewImagePatternMatcher(patterns []string) *ImagePatternMatcher {
	matcher := &ImagePatternMatcher{}
	for _, pattern := range patterns {
		escaped := regexp.QuoteMeta(strings.ToLower(pattern))
		regexStr := `(^|/)` + escaped + `(:|$|/)`
		if regex, err := regexp.Compile(regexStr); err == nil {
			matcher.patterns = append(matcher.patterns, regex)
		}
	}
	return matcher
}

// Match checks if an image matches any pattern
func (m *ImagePatternMatcher) Match(image string) bool {
	imageLower := strings.ToLower(image)
	for _, regex := range m.patterns {
		if regex.MatchString(imageLower) {
			return true
		}
	}
	return false
}
