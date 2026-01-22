package admission

// BaseFinding contains common fields for all admission findings
type BaseFinding struct {
	Namespace      string
	EngineID       string
	EngineName     string
	Category       EngineCategory
	Status         string // "active", "degraded", "not_found"
	PodsRunning    int
	TotalPods      int
	ImageVerified  bool
	Confidence     string // "high", "medium", "low"
	RiskLevel      string // "HIGH", "MEDIUM", "LOW", "NONE"
	SecurityIssues []string
	BypassVectors  []string
	BypassRisk     string
}

// ControllerFinding represents a detected admission controller
type ControllerFinding struct {
	BaseFinding
	ResourceName string
	ResourceKind string // Deployment, DaemonSet, StatefulSet
	Images       []string
	Labels       map[string]string
	Version      string
}

// WebhookFinding represents a detected webhook configuration
type WebhookFinding struct {
	BaseFinding
	WebhookName   string
	WebhookType   string // "validating", "mutating"
	ServiceName   string
	ServiceNS     string
	FailurePolicy string
	MatchPolicy   string
	Rules         []WebhookRule
}

// PolicyFinding represents a detected policy (constraint, CRD, etc.)
type PolicyFinding struct {
	BaseFinding
	PolicyName      string
	PolicyType      string // e.g., "ConstraintTemplate", "ClusterPolicy", "KubeArmorPolicy"
	Scope           string // "cluster", "namespace"
	TargetNamespace string // if namespace-scoped
	Enforced        bool
	Mode            string // "enforce", "audit", "dry-run"
}

// CRDFinding represents a detected CRD
type CRDFinding struct {
	Name    string
	Group   string
	Version string
	Scope   string // "Cluster", "Namespaced"
	Engine  string
}

// RiskAssessment provides a summary risk assessment for an admission category
type RiskAssessment struct {
	Category        EngineCategory
	OverallRisk     string // "HIGH", "MEDIUM", "LOW", "NONE"
	ControllersFound int
	WebhooksFound    int
	PoliciesFound    int
	CRDsFound        int
	CoveragePercent  float64
	Issues           []RiskIssue
	Recommendations  []string
}

// RiskIssue represents a specific security issue found
type RiskIssue struct {
	Severity    string // "HIGH", "MEDIUM", "LOW"
	Category    string // e.g., "configuration", "coverage", "bypass"
	Description string
	Remediation string
}

// NewBaseFinding creates a new base finding with default values
func NewBaseFinding(namespace string, category EngineCategory) BaseFinding {
	return BaseFinding{
		Namespace: namespace,
		Category:  category,
		Status:    "not_found",
		RiskLevel: "HIGH",
	}
}

// SetActive marks a finding as active with the given details
func (f *BaseFinding) SetActive(engineID, engineName string, running, total int, verified bool) {
	f.EngineID = engineID
	f.EngineName = engineName
	f.PodsRunning = running
	f.TotalPods = total
	f.ImageVerified = verified

	if running >= total && total > 0 {
		f.Status = "active"
	} else if running > 0 {
		f.Status = "degraded"
	} else {
		f.Status = "not_found"
	}

	if verified {
		f.Confidence = "high"
	} else {
		f.Confidence = "medium"
	}
}

// AddSecurityIssue adds a security issue to the finding
func (f *BaseFinding) AddSecurityIssue(issue string) {
	f.SecurityIssues = append(f.SecurityIssues, issue)
}

// AddBypassVector adds a bypass vector to the finding
func (f *BaseFinding) AddBypassVector(vector string) {
	f.BypassVectors = append(f.BypassVectors, vector)
}

// CalculateRiskLevel calculates the risk level based on current state
func (f *BaseFinding) CalculateRiskLevel() {
	score := 0

	// Not found or degraded increases risk
	if f.Status == "not_found" {
		score += 3
	} else if f.Status == "degraded" {
		score += 2
	}

	// Unverified images increase risk
	if f.Status == "active" && !f.ImageVerified {
		score += 1
	}

	// Security issues increase risk
	score += len(f.SecurityIssues)

	// Bypass vectors increase risk
	score += len(f.BypassVectors) * 2

	if score >= 4 {
		f.RiskLevel = "HIGH"
	} else if score >= 2 {
		f.RiskLevel = "MEDIUM"
	} else if score >= 1 {
		f.RiskLevel = "LOW"
	} else {
		f.RiskLevel = "NONE"
	}
}

// NamespaceSummary provides a summary of admission status for a namespace
type NamespaceSummary struct {
	Namespace           string
	ImageAdmission      string // "enforced", "partial", "none"
	PodAdmission        string
	NetworkAdmission    string
	SecretAdmission     string
	RuntimeMonitoring   string
	MeshSecurity        string
	OverallRisk         string
	ActiveControllers   []string
	MissingControllers  []string
}

// ClusterSummary provides a summary of admission status for the entire cluster
type ClusterSummary struct {
	TotalNamespaces      int
	CoveredNamespaces    int
	ImageAdmissionActive bool
	PodAdmissionActive   bool
	NetworkPoliciesExist bool
	RuntimeMonitoring    bool
	MeshActive           bool
	Findings             []BaseFinding
	BypassVectors        []BypassVector
	OverallRisk          string
}

// CalculateClusterRisk calculates overall cluster risk level
func (s *ClusterSummary) CalculateClusterRisk() {
	score := 0

	// Major systems not active
	if !s.ImageAdmissionActive {
		score += 2
	}
	if !s.PodAdmissionActive {
		score += 2
	}
	if !s.NetworkPoliciesExist {
		score += 1
	}
	if !s.RuntimeMonitoring {
		score += 1
	}

	// Low coverage
	if s.TotalNamespaces > 0 {
		coverage := float64(s.CoveredNamespaces) / float64(s.TotalNamespaces)
		if coverage < 0.5 {
			score += 2
		} else if coverage < 0.8 {
			score += 1
		}
	}

	// Bypass vectors
	score += len(s.BypassVectors)

	if score >= 5 {
		s.OverallRisk = "HIGH"
	} else if score >= 3 {
		s.OverallRisk = "MEDIUM"
	} else if score >= 1 {
		s.OverallRisk = "LOW"
	} else {
		s.OverallRisk = "NONE"
	}
}
