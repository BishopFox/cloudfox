package shared

// Risk level constants
const (
	RiskCritical = "CRITICAL"
	RiskHigh     = "HIGH"
	RiskMedium   = "MEDIUM"
	RiskLow      = "LOW"
)

// Risk thresholds - standardized across all commands
const (
	CriticalThreshold = 80
	HighThreshold     = 50
	MediumThreshold   = 25
)

// Risk weights for common security issues
const (
	// Container security weights
	WeightPrivileged       = 90
	WeightHostPID          = 70
	WeightHostNetwork      = 60
	WeightHostIPC          = 50
	WeightRunAsRoot        = 40
	WeightAllowPrivEsc     = 35
	WeightNoSeccomp        = 25
	WeightNoAppArmor       = 20
	WeightNoReadOnlyRoot   = 15
	WeightDangerousCap     = 30 // Per dangerous capability
	WeightSensitiveMount   = 40
	WeightDockerSocket     = 50
	WeightServiceAcctToken = 20

	// Exposure weights
	WeightExternallyExposed = 40
	WeightPublicIP          = 30
	WeightNoTLS             = 25
	WeightDefaultPort       = 10

	// Secret weights
	WeightCloudCredentials  = 60
	WeightPrivateKey        = 50
	WeightExpiredCert       = 40
	WeightExpiringCert      = 25
	WeightUnusedSecret      = 10
	WeightDefaultSAToken    = 15

	// RBAC weights
	WeightClusterAdmin      = 100
	WeightWildcardPerms     = 80
	WeightSecretsAccess     = 50
	WeightPodsExec          = 45
	WeightImpersonate       = 70
	WeightEscalatePerms     = 60
	WeightBindPerms         = 55

	// Node weights
	WeightAnonymousKubelet  = 80
	WeightResourcePressure  = 30
	WeightNotReady          = 40
	WeightOldKubeletVersion = 35
)

// RiskScore holds score and contributing factors
type RiskScore struct {
	Score   int
	Level   string
	Factors []RiskFactor
}

// RiskFactor represents a single risk contributor
type RiskFactor struct {
	Name        string
	Weight      int
	Description string
}

// NewRiskScore creates a new RiskScore and calculates level
func NewRiskScore() *RiskScore {
	return &RiskScore{
		Factors: make([]RiskFactor, 0),
	}
}

// AddFactor adds a risk factor and updates score
func (r *RiskScore) AddFactor(name string, weight int, description string) {
	r.Score += weight
	r.Factors = append(r.Factors, RiskFactor{
		Name:        name,
		Weight:      weight,
		Description: description,
	})
}

// AddFactorIf conditionally adds a risk factor
func (r *RiskScore) AddFactorIf(condition bool, name string, weight int, description string) {
	if condition {
		r.AddFactor(name, weight, description)
	}
}

// Calculate finalizes the risk level based on score
func (r *RiskScore) Calculate() (string, int) {
	switch {
	case r.Score >= CriticalThreshold:
		r.Level = RiskCritical
	case r.Score >= HighThreshold:
		r.Level = RiskHigh
	case r.Score >= MediumThreshold:
		r.Level = RiskMedium
	default:
		r.Level = RiskLow
	}
	return r.Level, r.Score
}

// CalculateWithMax returns risk level with capped score
func (r *RiskScore) CalculateWithMax(maxScore int) (string, int) {
	if r.Score > maxScore {
		r.Score = maxScore
	}
	return r.Calculate()
}

// GetIssues returns list of issue names from factors
func (r *RiskScore) GetIssues() []string {
	issues := make([]string, len(r.Factors))
	for i, f := range r.Factors {
		issues[i] = f.Name
	}
	return issues
}

// HasFactor checks if a specific factor was added
func (r *RiskScore) HasFactor(name string) bool {
	for _, f := range r.Factors {
		if f.Name == name {
			return true
		}
	}
	return false
}

// RiskLevelValue returns numeric value for risk level comparison
func RiskLevelValue(level string) int {
	switch level {
	case RiskCritical:
		return 4
	case RiskHigh:
		return 3
	case RiskMedium:
		return 2
	case RiskLow:
		return 1
	default:
		return 0
	}
}

// MaxRiskLevel returns the higher of two risk levels
func MaxRiskLevel(a, b string) string {
	if RiskLevelValue(a) >= RiskLevelValue(b) {
		return a
	}
	return b
}

// RiskCounts tracks count of findings per risk level
type RiskCounts struct {
	Critical int
	High     int
	Medium   int
	Low      int
}

// NewRiskCounts creates a new RiskCounts
func NewRiskCounts() *RiskCounts {
	return &RiskCounts{}
}

// Add increments the count for a risk level
func (rc *RiskCounts) Add(level string) {
	switch level {
	case RiskCritical:
		rc.Critical++
	case RiskHigh:
		rc.High++
	case RiskMedium:
		rc.Medium++
	case RiskLow:
		rc.Low++
	}
}

// Total returns total count across all levels
func (rc *RiskCounts) Total() int {
	return rc.Critical + rc.High + rc.Medium + rc.Low
}

// ToMap returns counts as a map
func (rc *RiskCounts) ToMap() map[string]int {
	return map[string]int{
		RiskCritical: rc.Critical,
		RiskHigh:     rc.High,
		RiskMedium:   rc.Medium,
		RiskLow:      rc.Low,
	}
}
