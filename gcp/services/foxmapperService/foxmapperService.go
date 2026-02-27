package foxmapperService

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/dominikbraun/graph"
)

// Node represents a GCP IAM principal from FoxMapper graph
type Node struct {
	MemberID                  string              `json:"member_id"`
	MemberType                string              `json:"member_type"`
	Email                     string              `json:"email"`
	DisplayName               string              `json:"display_name"`
	ProjectID                 string              `json:"project_id"`
	UniqueID                  string              `json:"unique_id"`
	IAMBindings               []map[string]any    `json:"iam_bindings"`
	IsAdmin                   bool                `json:"is_admin"`
	AdminLevel                string              `json:"admin_level"` // org, folder, project
	IsDisabled                bool                `json:"is_disabled"`
	HasKeys                   bool                `json:"has_keys"`
	KeyCount                  int                 `json:"key_count"`
	Tags                      map[string]string   `json:"tags"`
	Description               string              `json:"description"`
	OAuth2ClientID            string              `json:"oauth2_client_id"`
	AttachedResources         []map[string]any    `json:"attached_resources"`
	WorkloadIdentityBindings  []map[string]any    `json:"workload_identity_bindings"`
	GroupMemberships          []string            `json:"group_memberships"`
	Domain                    string              `json:"domain"`
	// Computed fields
	PathToAdmin               bool
	CanPrivEscToAdminString   string
	IsAdminString             string
}

// FlexibleBool handles JSON that may be bool, array, or other types
// Used for scope_limited which may vary between FoxMapper versions
type FlexibleBool bool

func (fb *FlexibleBool) UnmarshalJSON(data []byte) error {
	// Try bool first
	var b bool
	if err := json.Unmarshal(data, &b); err == nil {
		*fb = FlexibleBool(b)
		return nil
	}

	// Try array (non-empty array = true)
	var arr []interface{}
	if err := json.Unmarshal(data, &arr); err == nil {
		*fb = FlexibleBool(len(arr) > 0)
		return nil
	}

	// Try string ("true"/"false")
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*fb = FlexibleBool(s == "true" || s == "True" || s == "1")
		return nil
	}

	// Default to false
	*fb = false
	return nil
}

// Edge represents a privilege escalation edge from FoxMapper graph
type Edge struct {
	Source                string         `json:"source"`
	Destination           string         `json:"destination"`
	Reason                string         `json:"reason"`
	ShortReason           string         `json:"short_reason"`
	EdgeType              string         `json:"edge_type"`
	Resource              string         `json:"resource"`
	Confidence            string         `json:"confidence,omitempty"` // high (default/empty), medium, low
	Conditions            map[string]any `json:"conditions"`
	ScopeLimited          FlexibleBool   `json:"scope_limited"`
	ScopeWarning          string         `json:"scope_warning"`
	ScopeBlocksEscalation FlexibleBool   `json:"scope_blocks_escalation"`
	ScopeAllowsMethods    []string       `json:"scope_allows_methods"`
	Scopes                []string       `json:"scopes"`
}

// EffectiveConfidence returns the edge's confidence, defaulting to "high" if empty
func (e Edge) EffectiveConfidence() string {
	if e.Confidence == "" {
		return "high"
	}
	return e.Confidence
}

// WorstConfidence returns the worse of two confidence levels (low < medium < high)
func WorstConfidence(a, b string) string {
	order := map[string]int{"low": 0, "medium": 1, "high": 2}
	if a == "" {
		a = "high"
	}
	if b == "" {
		b = "high"
	}
	if order[a] <= order[b] {
		return a
	}
	return b
}

// Policy represents an IAM policy from FoxMapper graph
type Policy struct {
	Resource   string           `json:"resource"`
	Bindings   []PolicyBinding  `json:"bindings"`
	Version    int              `json:"version"`
}

// PolicyBinding represents a single IAM binding
type PolicyBinding struct {
	Role      string   `json:"role"`
	Members   []string `json:"members"`
	Condition map[string]any `json:"condition"`
}

// GraphMetadata contains metadata about the FoxMapper graph
type GraphMetadata struct {
	ProjectID     string `json:"project_id"`
	OrgID         string `json:"org_id"`
	CreatedAt     string `json:"created_at"`
	FoxMapperVersion string `json:"foxmapper_version"`
}

// PrivescPath represents a privilege escalation path
type PrivescPath struct {
	Source      string
	Destination string
	Edges       []Edge
	HopCount    int
	AdminLevel  string // org, folder, project
	ScopeBlocked bool
	Confidence   string // worst confidence across all edges in path (high, medium, low)
}

// FoxMapperService provides access to FoxMapper graph data
type FoxMapperService struct {
	DataBasePath string
	Nodes        []Node
	Edges        []Edge
	Policies     []Policy
	Metadata     GraphMetadata
	nodeMap      map[string]*Node
	graph        graph.Graph[string, string]
	initialized  bool

	// Pre-computed findings from FoxMapper presets
	LateralFindingsData   *LateralFindingsFile   // From lateral_findings.json
	DataExfilFindingsData *DataExfilFindingsFile // From data_exfil_findings.json
}

// LateralFindingsFile represents the wrapper for lateral_findings.json
type LateralFindingsFile struct {
	ProjectID               string                        `json:"project_id"`
	TotalTechniquesAnalyzed int                           `json:"total_techniques_analyzed"`
	TechniquesWithAccess    int                           `json:"techniques_with_access"`
	CategoriesSummary       map[string]CategorySummary    `json:"categories_summary"`
	Findings                []LateralFindingEntry         `json:"findings"`
}

// DataExfilFindingsFile represents the wrapper for data_exfil_findings.json
type DataExfilFindingsFile struct {
	ProjectID               string                        `json:"project_id"`
	TotalTechniquesAnalyzed int                           `json:"total_techniques_analyzed"`
	TechniquesWithAccess    int                           `json:"techniques_with_access"`
	PublicResources         []string                      `json:"public_resources"`
	ServicesSummary         map[string]ServiceSummary     `json:"services_summary"`
	Findings                []DataExfilFindingEntry       `json:"findings"`
}

// CategorySummary provides summary info for a lateral movement category
type CategorySummary struct {
	Count       int    `json:"count"`
	Description string `json:"description"`
}

// ServiceSummary provides summary info for a data exfil service
type ServiceSummary struct {
	Count              int `json:"count"`
	TotalPrincipals    int `json:"total_principals"`
	NonAdminPrincipals int `json:"non_admin_principals"`
	ViaPrivesc         int `json:"via_privesc"`
	ResourceLevel      int `json:"resource_level"`
}

// LateralFindingEntry represents a single lateral movement finding
type LateralFindingEntry struct {
	Technique      string                `json:"technique"`
	Permission     string                `json:"permission"`
	Category       string                `json:"category"`
	Description    string                `json:"description"`
	Exploitation   string                `json:"exploitation"`
	PrincipalCount int                   `json:"principal_count"`
	NonAdminCount  int                   `json:"non_admin_count"`
	ViaEdgeCount   int                   `json:"via_edge_count"`
	Principals     []PrincipalAccessFile `json:"principals"`
}

// DataExfilFindingEntry represents a single data exfil finding
type DataExfilFindingEntry struct {
	Technique      string                `json:"technique"`
	Permission     string                `json:"permission"`
	Service        string                `json:"service"`
	Description    string                `json:"description"`
	Exploitation   string                `json:"exploitation"`
	PrincipalCount int                   `json:"principal_count"`
	NonAdminCount  int                   `json:"non_admin_count"`
	ViaEdgeCount   int                   `json:"via_edge_count"`
	Principals     []PrincipalAccessFile `json:"principals"`
}

// PrincipalAccessFile represents a principal with access from FoxMapper findings
type PrincipalAccessFile struct {
	Principal        string   `json:"principal"`
	MemberID         string   `json:"member_id"`
	MemberType       string   `json:"member_type"`
	IsAdmin          bool     `json:"is_admin"`
	IsServiceAccount bool     `json:"is_service_account"`
	AccessType       string   `json:"access_type"` // direct, via_privesc
	ViaEdge          bool     `json:"via_edge"`
	EdgePath         []string `json:"edge_path,omitempty"`
	Resource         string   `json:"resource,omitempty"`
	// Scope information (may be in JSON or derived from Resource)
	ScopeType        string   `json:"scope_type,omitempty"`
	ScopeID          string   `json:"scope_id,omitempty"`
	ScopeName        string   `json:"scope_name,omitempty"`
}

// New creates a new FoxMapperService
func New() *FoxMapperService {
	return &FoxMapperService{
		nodeMap: make(map[string]*Node),
	}
}

// generateFoxMapperDataBasePaths returns paths to check for FoxMapper data
// FoxMapper saves data with prefixes: org-{id}, proj-{id}, folder-{id}
func generateFoxMapperDataBasePaths(identifier string, isOrg bool) []string {
	var paths []string
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return paths
	}

	// Determine the prefixed identifier FoxMapper uses
	// FoxMapper saves as: org-{id}, proj-{id}, folder-{id}
	var prefixedIdentifiers []string
	if isOrg {
		prefixedIdentifiers = append(prefixedIdentifiers, "org-"+identifier)
	} else {
		prefixedIdentifiers = append(prefixedIdentifiers, "proj-"+identifier)
	}
	// Also try without prefix for backwards compatibility
	prefixedIdentifiers = append(prefixedIdentifiers, identifier)

	gcpDir := "gcp"

	// Generate paths for each possible identifier format
	for _, prefixedID := range prefixedIdentifiers {
		// Platform-specific paths
		if runtime.GOOS == "darwin" {
			// macOS: ~/Library/Application Support/foxmapper/gcp/{id}
			paths = append(paths, filepath.Join(homeDir, "Library", "Application Support", "foxmapper", gcpDir, prefixedID))
		} else if runtime.GOOS == "windows" {
			// Windows: %APPDATA%/foxmapper/gcp/{id}
			appData := os.Getenv("APPDATA")
			if appData != "" {
				paths = append(paths, filepath.Join(appData, "foxmapper", gcpDir, prefixedID))
			}
		}

		// Linux/BSD and fallback for all platforms
		// Check XDG_DATA_HOME first
		xdgDataHome := os.Getenv("XDG_DATA_HOME")
		if xdgDataHome != "" {
			paths = append(paths, filepath.Join(xdgDataHome, "foxmapper", gcpDir, prefixedID))
		}

		// Default: ~/.local/share/foxmapper/gcp/{id}
		paths = append(paths, filepath.Join(homeDir, ".local", "share", "foxmapper", gcpDir, prefixedID))
	}

	// Legacy pmapper paths (for backwards compatibility) - without prefix
	if runtime.GOOS == "darwin" {
		paths = append(paths, filepath.Join(homeDir, "Library", "Application Support", "com.nccgroup.principalmapper", identifier))
	} else {
		xdgDataHome := os.Getenv("XDG_DATA_HOME")
		if xdgDataHome != "" {
			paths = append(paths, filepath.Join(xdgDataHome, "principalmapper", identifier))
		}
		paths = append(paths, filepath.Join(homeDir, ".local", "share", "principalmapper", identifier))
	}

	return paths
}

// LoadGraph loads FoxMapper graph data for an org or project
func (s *FoxMapperService) LoadGraph(identifier string, isOrg bool) error {
	// Try to find FoxMapper data
	var graphPath string
	paths := generateFoxMapperDataBasePaths(identifier, isOrg)

	for _, path := range paths {
		graphDir := filepath.Join(path, "graph")
		nodesPath := filepath.Join(graphDir, "nodes.json")
		if _, err := os.Stat(nodesPath); err == nil {
			graphPath = path
			break
		}
	}

	if graphPath == "" {
		return fmt.Errorf("no FoxMapper data found for %s. Run 'foxmapper gcp graph create' first", identifier)
	}

	return s.LoadGraphFromPath(graphPath)
}

// LoadGraphFromPath loads FoxMapper graph from a specific path
func (s *FoxMapperService) LoadGraphFromPath(path string) error {
	graphDir := filepath.Join(path, "graph")

	// Load nodes
	nodesPath := filepath.Join(graphDir, "nodes.json")
	nodesData, err := os.ReadFile(nodesPath)
	if err != nil {
		return fmt.Errorf("failed to read nodes.json: %w", err)
	}
	if err := json.Unmarshal(nodesData, &s.Nodes); err != nil {
		return fmt.Errorf("failed to parse nodes.json: %w", err)
	}

	// Build node map
	for i := range s.Nodes {
		s.nodeMap[s.Nodes[i].MemberID] = &s.Nodes[i]
		// Also map by email for convenience
		if s.Nodes[i].Email != "" {
			s.nodeMap[s.Nodes[i].Email] = &s.Nodes[i]
		}
	}

	// Load edges
	edgesPath := filepath.Join(graphDir, "edges.json")
	edgesData, err := os.ReadFile(edgesPath)
	if err != nil {
		return fmt.Errorf("failed to read edges.json: %w", err)
	}
	if err := json.Unmarshal(edgesData, &s.Edges); err != nil {
		return fmt.Errorf("failed to parse edges.json: %w", err)
	}

	// Load policies (optional)
	policiesPath := filepath.Join(graphDir, "policies.json")
	if policiesData, err := os.ReadFile(policiesPath); err == nil {
		json.Unmarshal(policiesData, &s.Policies)
	}

	// Load metadata (optional)
	metadataPath := filepath.Join(path, "metadata.json")
	if metadataData, err := os.ReadFile(metadataPath); err == nil {
		json.Unmarshal(metadataData, &s.Metadata)
	}

	// Load pre-computed lateral movement findings (optional)
	lateralPath := filepath.Join(graphDir, "lateral_findings.json")
	if lateralData, err := os.ReadFile(lateralPath); err == nil {
		var lateralFindings LateralFindingsFile
		if json.Unmarshal(lateralData, &lateralFindings) == nil {
			s.LateralFindingsData = &lateralFindings
		}
	}

	// Load pre-computed data exfil findings (optional)
	dataExfilPath := filepath.Join(graphDir, "data_exfil_findings.json")
	if dataExfilData, err := os.ReadFile(dataExfilPath); err == nil {
		var dataExfilFindings DataExfilFindingsFile
		if json.Unmarshal(dataExfilData, &dataExfilFindings) == nil {
			s.DataExfilFindingsData = &dataExfilFindings
		}
	}

	// Build graph for path finding
	s.buildGraph()

	// Compute path to admin for all nodes
	s.computePathsToAdmin()

	s.initialized = true
	return nil
}

// MergeGraphFromPath merges another graph into this service
// Used to combine multiple project graphs into a single view
func (s *FoxMapperService) MergeGraphFromPath(path string) error {
	graphDir := filepath.Join(path, "graph")

	// Load nodes from the other graph
	nodesPath := filepath.Join(graphDir, "nodes.json")
	nodesData, err := os.ReadFile(nodesPath)
	if err != nil {
		return fmt.Errorf("failed to read nodes.json: %w", err)
	}
	var otherNodes []Node
	if err := json.Unmarshal(nodesData, &otherNodes); err != nil {
		return fmt.Errorf("failed to parse nodes.json: %w", err)
	}

	// Load edges from the other graph
	edgesPath := filepath.Join(graphDir, "edges.json")
	edgesData, err := os.ReadFile(edgesPath)
	if err != nil {
		return fmt.Errorf("failed to read edges.json: %w", err)
	}
	var otherEdges []Edge
	if err := json.Unmarshal(edgesData, &otherEdges); err != nil {
		return fmt.Errorf("failed to parse edges.json: %w", err)
	}

	// Merge nodes (avoid duplicates by member_id)
	existingNodes := make(map[string]bool)
	for _, node := range s.Nodes {
		existingNodes[node.MemberID] = true
	}
	for _, node := range otherNodes {
		if !existingNodes[node.MemberID] {
			s.Nodes = append(s.Nodes, node)
			s.nodeMap[node.MemberID] = &s.Nodes[len(s.Nodes)-1]
			if node.Email != "" {
				s.nodeMap[node.Email] = &s.Nodes[len(s.Nodes)-1]
			}
			existingNodes[node.MemberID] = true
		}
	}

	// Merge edges (avoid duplicates by source+destination+short_reason)
	type edgeKey struct {
		source, dest, reason string
	}
	existingEdges := make(map[edgeKey]bool)
	for _, edge := range s.Edges {
		existingEdges[edgeKey{edge.Source, edge.Destination, edge.ShortReason}] = true
	}
	for _, edge := range otherEdges {
		key := edgeKey{edge.Source, edge.Destination, edge.ShortReason}
		if !existingEdges[key] {
			s.Edges = append(s.Edges, edge)
			existingEdges[key] = true
		}
	}

	// Load and merge policies (optional)
	policiesPath := filepath.Join(graphDir, "policies.json")
	if policiesData, err := os.ReadFile(policiesPath); err == nil {
		var otherPolicies []Policy
		if json.Unmarshal(policiesData, &otherPolicies) == nil {
			// Simple append for policies - could dedupe by resource if needed
			s.Policies = append(s.Policies, otherPolicies...)
		}
	}

	// Load and merge lateral findings (optional)
	lateralPath := filepath.Join(graphDir, "lateral_findings.json")
	if lateralData, err := os.ReadFile(lateralPath); err == nil {
		var otherLateral LateralFindingsFile
		if json.Unmarshal(lateralData, &otherLateral) == nil {
			if s.LateralFindingsData == nil {
				s.LateralFindingsData = &otherLateral
			} else {
				// Merge findings from both
				s.LateralFindingsData.Findings = append(s.LateralFindingsData.Findings, otherLateral.Findings...)
				s.LateralFindingsData.TechniquesWithAccess += otherLateral.TechniquesWithAccess
			}
		}
	}

	// Load and merge data exfil findings (optional)
	dataExfilPath := filepath.Join(graphDir, "data_exfil_findings.json")
	if dataExfilData, err := os.ReadFile(dataExfilPath); err == nil {
		var otherDataExfil DataExfilFindingsFile
		if json.Unmarshal(dataExfilData, &otherDataExfil) == nil {
			if s.DataExfilFindingsData == nil {
				s.DataExfilFindingsData = &otherDataExfil
			} else {
				// Merge findings from both
				s.DataExfilFindingsData.Findings = append(s.DataExfilFindingsData.Findings, otherDataExfil.Findings...)
				s.DataExfilFindingsData.TechniquesWithAccess += otherDataExfil.TechniquesWithAccess
			}
		}
	}

	return nil
}

// RebuildAfterMerge rebuilds the in-memory graph and recomputes paths after merging
func (s *FoxMapperService) RebuildAfterMerge() {
	s.buildGraph()
	s.computePathsToAdmin()
	s.initialized = true
}

// buildGraph creates an in-memory graph for path finding
func (s *FoxMapperService) buildGraph() {
	s.graph = graph.New(graph.StringHash, graph.Directed())

	// Add all nodes as vertices
	for _, node := range s.Nodes {
		_ = s.graph.AddVertex(node.MemberID)
	}

	// Add all edges
	for _, edge := range s.Edges {
		_ = s.graph.AddEdge(
			edge.Source,
			edge.Destination,
			graph.EdgeAttribute("reason", edge.Reason),
			graph.EdgeAttribute("short_reason", edge.ShortReason),
		)
	}
}

// computePathsToAdmin computes whether each node has a path to an admin node
func (s *FoxMapperService) computePathsToAdmin() {
	adminNodes := s.GetAdminNodes()

	for i := range s.Nodes {
		if s.Nodes[i].IsAdmin {
			s.Nodes[i].PathToAdmin = true
			s.Nodes[i].CanPrivEscToAdminString = "Admin"
			s.Nodes[i].IsAdminString = "Yes"
		} else {
			hasPath := false
			for _, admin := range adminNodes {
				path, _ := graph.ShortestPath(s.graph, s.Nodes[i].MemberID, admin.MemberID)
				if len(path) > 0 && s.Nodes[i].MemberID != admin.MemberID {
					hasPath = true
					break
				}
			}
			s.Nodes[i].PathToAdmin = hasPath
			if hasPath {
				s.Nodes[i].CanPrivEscToAdminString = "Yes"
			} else {
				s.Nodes[i].CanPrivEscToAdminString = "No"
			}
			s.Nodes[i].IsAdminString = "No"
		}
	}
}

// IsInitialized returns whether the graph has been loaded
func (s *FoxMapperService) IsInitialized() bool {
	return s.initialized
}

// GetNode returns a node by member_id or email
func (s *FoxMapperService) GetNode(identifier string) *Node {
	// Try direct lookup
	if node, ok := s.nodeMap[identifier]; ok {
		return node
	}
	// Try with serviceAccount: prefix
	if node, ok := s.nodeMap["serviceAccount:"+identifier]; ok {
		return node
	}
	// Try with user: prefix
	if node, ok := s.nodeMap["user:"+identifier]; ok {
		return node
	}
	return nil
}

// GetAdminNodes returns all admin nodes
func (s *FoxMapperService) GetAdminNodes() []*Node {
	var admins []*Node
	for i := range s.Nodes {
		if s.Nodes[i].IsAdmin {
			admins = append(admins, &s.Nodes[i])
		}
	}
	return admins
}

// GetNodesWithPrivesc returns all nodes that can escalate to admin
func (s *FoxMapperService) GetNodesWithPrivesc() []*Node {
	var nodes []*Node
	for i := range s.Nodes {
		if s.Nodes[i].PathToAdmin && !s.Nodes[i].IsAdmin {
			nodes = append(nodes, &s.Nodes[i])
		}
	}
	return nodes
}

// DoesPrincipalHavePathToAdmin checks if a principal can escalate to admin
func (s *FoxMapperService) DoesPrincipalHavePathToAdmin(principal string) bool {
	node := s.GetNode(principal)
	if node == nil {
		return false
	}
	return node.PathToAdmin
}

// IsPrincipalAdmin checks if a principal is an admin
func (s *FoxMapperService) IsPrincipalAdmin(principal string) bool {
	node := s.GetNode(principal)
	if node == nil {
		return false
	}
	return node.IsAdmin
}

// GetPrivescPaths returns all privesc paths for a principal
func (s *FoxMapperService) GetPrivescPaths(principal string) []PrivescPath {
	node := s.GetNode(principal)
	if node == nil {
		return nil
	}

	var paths []PrivescPath
	adminNodes := s.GetAdminNodes()

	for _, admin := range adminNodes {
		if node.MemberID == admin.MemberID {
			continue
		}

		shortestPath, _ := graph.ShortestPath(s.graph, node.MemberID, admin.MemberID)
		if len(shortestPath) > 0 {
			// Build edges for this path
			var pathEdges []Edge
			scopeBlocked := false
			pathConfidence := "high"
			for i := 0; i < len(shortestPath)-1; i++ {
				edge := s.findEdge(shortestPath[i], shortestPath[i+1])
				if edge != nil {
					pathEdges = append(pathEdges, *edge)
					if edge.ScopeBlocksEscalation {
						scopeBlocked = true
					}
					pathConfidence = WorstConfidence(pathConfidence, edge.EffectiveConfidence())
				}
			}

			paths = append(paths, PrivescPath{
				Source:       node.Email,
				Destination:  admin.Email,
				Edges:        pathEdges,
				HopCount:     len(pathEdges),
				AdminLevel:   admin.AdminLevel,
				ScopeBlocked: scopeBlocked,
				Confidence:   pathConfidence,
			})
		}
	}

	// Sort by hop count
	sort.Slice(paths, func(i, j int) bool {
		return paths[i].HopCount < paths[j].HopCount
	})

	return paths
}

// findEdge finds an edge between two nodes
func (s *FoxMapperService) findEdge(source, dest string) *Edge {
	for i := range s.Edges {
		if s.Edges[i].Source == source && s.Edges[i].Destination == dest {
			return &s.Edges[i]
		}
	}
	return nil
}

// GetAttackSummary returns a summary string like "Privesc/Exfil/Lateral" for a principal
// This is used by other modules to display attack path info
func (s *FoxMapperService) GetAttackSummary(principal string) string {
	if !s.initialized {
		return "No FoxMapper data"
	}

	node := s.GetNode(principal)
	if node == nil {
		return "Unknown"
	}

	if node.IsAdmin {
		adminLevel := node.AdminLevel
		if adminLevel == "" {
			adminLevel = "project"
		}
		return fmt.Sprintf("Admin (%s)", adminLevel)
	}

	if node.PathToAdmin {
		paths := s.GetPrivescPaths(principal)
		if len(paths) > 0 {
			// Find the highest admin level reachable and best confidence
			highestLevel := "project"
			shortestHops := paths[0].HopCount
			bestConfidence := paths[0].Confidence
			for _, p := range paths {
				if p.AdminLevel == "org" {
					highestLevel = "org"
				} else if p.AdminLevel == "folder" && highestLevel != "org" {
					highestLevel = "folder"
				}
			}
			if bestConfidence != "" && bestConfidence != "high" {
				return fmt.Sprintf("Privesc->%s (%d hops, %s confidence)", highestLevel, shortestHops, bestConfidence)
			}
			return fmt.Sprintf("Privesc->%s (%d hops)", highestLevel, shortestHops)
		}
		return "Privesc"
	}

	return "No"
}

// GetPrivescSummary returns a summary of all privesc paths in the graph
func (s *FoxMapperService) GetPrivescSummary() map[string]interface{} {
	totalNodes := len(s.Nodes)
	adminNodes := len(s.GetAdminNodes())
	nodesWithPrivesc := len(s.GetNodesWithPrivesc())

	// Count by admin level
	orgAdmins := 0
	folderAdmins := 0
	projectAdmins := 0
	for _, node := range s.Nodes {
		if node.IsAdmin {
			switch node.AdminLevel {
			case "org":
				orgAdmins++
			case "folder":
				folderAdmins++
			case "project":
				projectAdmins++
			default:
				projectAdmins++
			}
		}
	}

	// Count by principal type
	saWithPrivesc := 0
	userWithPrivesc := 0
	for _, node := range s.GetNodesWithPrivesc() {
		if node.MemberType == "serviceAccount" {
			saWithPrivesc++
		} else if node.MemberType == "user" {
			userWithPrivesc++
		}
	}

	return map[string]interface{}{
		"total_nodes":         totalNodes,
		"admin_nodes":         adminNodes,
		"non_admin_nodes":     totalNodes - adminNodes,
		"nodes_with_privesc":  nodesWithPrivesc,
		"org_admins":          orgAdmins,
		"folder_admins":       folderAdmins,
		"project_admins":      projectAdmins,
		"sa_with_privesc":     saWithPrivesc,
		"user_with_privesc":   userWithPrivesc,
		"percent_with_privesc": func() float64 {
			if totalNodes-adminNodes == 0 {
				return 0
			}
			return float64(nodesWithPrivesc) / float64(totalNodes-adminNodes) * 100
		}(),
	}
}

// FormatPrivescPath formats a privesc path for display
func FormatPrivescPath(path PrivescPath) string {
	var sb strings.Builder
	confidenceInfo := ""
	if path.Confidence != "" && path.Confidence != "high" {
		confidenceInfo = fmt.Sprintf(", %s confidence", path.Confidence)
	}
	sb.WriteString(fmt.Sprintf("%s -> %s (%d hops%s)\n", path.Source, path.Destination, path.HopCount, confidenceInfo))
	for i, edge := range path.Edges {
		annotations := ""
		if edge.ScopeBlocksEscalation {
			annotations = " [BLOCKED BY SCOPE]"
		} else if edge.ScopeLimited {
			annotations = " [scope-limited]"
		}
		edgeConf := edge.EffectiveConfidence()
		if edgeConf != "high" {
			annotations += fmt.Sprintf(" [%s confidence]", edgeConf)
		}
		sb.WriteString(fmt.Sprintf("  (%d) %s%s\n", i+1, edge.Reason, annotations))
	}
	return sb.String()
}

// GetEdgesFrom returns all edges from a given node
func (s *FoxMapperService) GetEdgesFrom(principal string) []Edge {
	var edges []Edge
	node := s.GetNode(principal)
	if node == nil {
		return edges
	}

	for _, edge := range s.Edges {
		if edge.Source == node.MemberID {
			edges = append(edges, edge)
		}
	}
	return edges
}

// GetEdgesTo returns all edges to a given node
func (s *FoxMapperService) GetEdgesTo(principal string) []Edge {
	var edges []Edge
	node := s.GetNode(principal)
	if node == nil {
		return edges
	}

	for _, edge := range s.Edges {
		if edge.Destination == node.MemberID {
			edges = append(edges, edge)
		}
	}
	return edges
}

// FindFoxMapperData searches for FoxMapper data and returns the path if found
func FindFoxMapperData(identifier string, isOrg bool) (string, error) {
	paths := generateFoxMapperDataBasePaths(identifier, isOrg)

	for _, path := range paths {
		graphDir := filepath.Join(path, "graph")
		nodesPath := filepath.Join(graphDir, "nodes.json")
		if _, err := os.Stat(nodesPath); err == nil {
			return path, nil
		}
	}

	return "", fmt.Errorf("no FoxMapper data found for %s", identifier)
}

// GetServiceAccountNodes returns all service account nodes
func (s *FoxMapperService) GetServiceAccountNodes() []*Node {
	var nodes []*Node
	for i := range s.Nodes {
		if s.Nodes[i].MemberType == "serviceAccount" {
			nodes = append(nodes, &s.Nodes[i])
		}
	}
	return nodes
}

// ==========================================
// FoxMapper Preset Execution Support
// ==========================================

// PresetResult represents the result of running a FoxMapper preset
type PresetResult struct {
	Preset           string                   `json:"preset"`
	ProjectID        string                   `json:"project_id"`
	TotalFindings    int                      `json:"total_findings"`
	Findings         []PresetFinding          `json:"findings"`
	Summary          map[string]interface{}   `json:"summary"`
	CategoriesSummary map[string]CategoryInfo `json:"categories_summary"`
}

// PresetFinding represents a single finding from a preset
type PresetFinding struct {
	Technique      string            `json:"technique"`
	Permission     string            `json:"permission"`
	Category       string            `json:"category"`
	Service        string            `json:"service,omitempty"`
	Description    string            `json:"description"`
	Exploitation   string            `json:"exploitation"`
	PrincipalCount int               `json:"principal_count"`
	NonAdminCount  int               `json:"non_admin_count"`
	ViaEdgeCount   int               `json:"via_edge_count,omitempty"`
	Principals     []PrincipalAccess `json:"principals"`
	Resources      []string          `json:"resources_with_access,omitempty"`
}

// PrincipalAccess represents a principal with access to a technique
type PrincipalAccess struct {
	Principal        string   `json:"principal"`
	MemberID         string   `json:"member_id"`
	MemberType       string   `json:"member_type"`
	IsAdmin          bool     `json:"is_admin"`
	IsServiceAccount bool     `json:"is_service_account"`
	AccessType       string   `json:"access_type"` // project_iam, resource_iam, via_privesc
	ViaEdge          bool     `json:"via_edge"`
	EdgePath         []string `json:"edge_path,omitempty"`
	HasCondition     bool     `json:"has_condition"`
	// Scope information - WHERE the permission was granted
	ScopeType        string   `json:"scope_type,omitempty"` // organization, folder, project
	ScopeID          string   `json:"scope_id,omitempty"`   // The org/folder/project ID
	ScopeName        string   `json:"scope_name,omitempty"` // Display name if available
}

// CategoryInfo provides summary info for a category
type CategoryInfo struct {
	Count       int    `json:"count"`
	Description string `json:"description"`
}

// PrivescFinding represents a privilege escalation finding
type PrivescFinding struct {
	Principal            string   `json:"principal"`
	MemberType           string   `json:"member_type"`
	IsAdmin              bool     `json:"is_admin"`
	CanEscalate          bool     `json:"can_escalate"`
	HighestAdminLevel    string   `json:"highest_admin_level"` // org, folder, project
	HighestReachableTarget string `json:"highest_reachable_target"` // The admin principal that can be reached
	HighestReachableProject string `json:"highest_reachable_project"` // The project of the highest reachable admin
	ViablePathCount      int      `json:"viable_path_count"`
	ScopeBlockedCount    int      `json:"scope_blocked_count"`
	PathsToOrgAdmin      int      `json:"paths_to_org_admin"`
	PathsToFolderAdmin   int      `json:"paths_to_folder_admin"`
	PathsToProjectAdmin  int      `json:"paths_to_project_admin"`
	ShortestPathHops     int      `json:"shortest_path_hops"`
	BestPathConfidence   string   `json:"best_path_confidence,omitempty"` // confidence of best path (high, medium, low)
	Paths                []PrivescPath `json:"paths,omitempty"`
}

// AnalyzePrivesc analyzes privilege escalation using graph data
// This is equivalent to running "foxmapper gcp query preset privesc"
func (s *FoxMapperService) AnalyzePrivesc() []PrivescFinding {
	if !s.initialized {
		return nil
	}

	var findings []PrivescFinding

	for i := range s.Nodes {
		node := &s.Nodes[i]

		finding := PrivescFinding{
			Principal:  node.Email,
			MemberType: node.MemberType,
			IsAdmin:    node.IsAdmin,
		}

		if node.IsAdmin {
			finding.HighestAdminLevel = node.AdminLevel
			if finding.HighestAdminLevel == "" {
				finding.HighestAdminLevel = "project"
			}
			// For admins, they are their own "target"
			finding.HighestReachableTarget = node.Email
			finding.HighestReachableProject = node.ProjectID
		} else if node.PathToAdmin {
			finding.CanEscalate = true
			paths := s.GetPrivescPaths(node.MemberID)
			finding.Paths = paths

			// Track the best path (highest level, shortest hops)
			var bestPath *PrivescPath

			// Analyze paths
			for idx := range paths {
				path := &paths[idx]
				if path.ScopeBlocked {
					finding.ScopeBlockedCount++
				} else {
					finding.ViablePathCount++
				}

				// Track admin level and update best path
				switch path.AdminLevel {
				case "org":
					finding.PathsToOrgAdmin++
					if finding.HighestAdminLevel != "org" {
						finding.HighestAdminLevel = "org"
						bestPath = path
					} else if bestPath != nil && path.HopCount < bestPath.HopCount {
						bestPath = path
					}
				case "folder":
					finding.PathsToFolderAdmin++
					if finding.HighestAdminLevel == "" || finding.HighestAdminLevel == "project" {
						finding.HighestAdminLevel = "folder"
						bestPath = path
					} else if finding.HighestAdminLevel == "folder" && (bestPath == nil || path.HopCount < bestPath.HopCount) {
						bestPath = path
					}
				case "project":
					finding.PathsToProjectAdmin++
					if finding.HighestAdminLevel == "" {
						finding.HighestAdminLevel = "project"
						bestPath = path
					} else if finding.HighestAdminLevel == "project" && (bestPath == nil || path.HopCount < bestPath.HopCount) {
						bestPath = path
					}
				}

				// Track shortest path
				if finding.ShortestPathHops == 0 || path.HopCount < finding.ShortestPathHops {
					finding.ShortestPathHops = path.HopCount
				}
			}

			// Set the highest reachable target info
			if bestPath != nil {
				finding.HighestReachableTarget = bestPath.Destination
				finding.BestPathConfidence = bestPath.Confidence
				// Try to get project info from the destination node
				destNode := s.GetNode(bestPath.Destination)
				if destNode != nil {
					finding.HighestReachableProject = destNode.ProjectID
				}
			}
		}

		// Only include principals with privesc potential or admins
		if finding.IsAdmin || finding.CanEscalate {
			findings = append(findings, finding)
		}
	}

	return findings
}

// LateralFinding represents a lateral movement technique finding
type LateralFinding struct {
	Technique      string            `json:"technique"`
	Permission     string            `json:"permission"`
	Category       string            `json:"category"`
	Description    string            `json:"description"`
	Exploitation   string            `json:"exploitation"`
	Principals     []PrincipalAccess `json:"principals"`
}

// LateralTechnique defines a lateral movement technique
type LateralTechnique struct {
	Permission   string
	Description  string
	Exploitation string
	Category     string
}

// GetLateralTechniques returns all lateral movement techniques
func GetLateralTechniques() map[string]LateralTechnique {
	return map[string]LateralTechnique{
		// Service Account Impersonation
		"sa_token_creator": {
			Permission:   "iam.serviceAccounts.getAccessToken",
			Description:  "Can get access tokens for service accounts",
			Exploitation: "gcloud auth print-access-token --impersonate-service-account=SA_EMAIL",
			Category:     "sa_impersonation",
		},
		"sa_key_creator": {
			Permission:   "iam.serviceAccountKeys.create",
			Description:  "Can create keys for service accounts",
			Exploitation: "gcloud iam service-accounts keys create key.json --iam-account=SA_EMAIL",
			Category:     "sa_impersonation",
		},
		"sa_sign_blob": {
			Permission:   "iam.serviceAccounts.signBlob",
			Description:  "Can sign blobs as service account",
			Exploitation: "gcloud iam service-accounts sign-blob --iam-account=SA_EMAIL input.txt output.txt",
			Category:     "sa_impersonation",
		},
		"sa_sign_jwt": {
			Permission:   "iam.serviceAccounts.signJwt",
			Description:  "Can sign JWTs as service account",
			Exploitation: "# Sign JWT to impersonate SA",
			Category:     "sa_impersonation",
		},
		"sa_openid_token": {
			Permission:   "iam.serviceAccounts.getOpenIdToken",
			Description:  "Can get OpenID tokens for service accounts",
			Exploitation: "gcloud auth print-identity-token --impersonate-service-account=SA_EMAIL",
			Category:     "sa_impersonation",
		},
		// Compute Access
		"compute_ssh_oslogin": {
			Permission:   "compute.instances.osLogin",
			Description:  "Can SSH to compute instances via OS Login",
			Exploitation: "gcloud compute ssh INSTANCE_NAME --zone=ZONE",
			Category:     "compute_access",
		},
		"compute_set_metadata": {
			Permission:   "compute.instances.setMetadata",
			Description:  "Can inject SSH keys via instance metadata",
			Exploitation: "gcloud compute instances add-metadata INSTANCE --metadata=ssh-keys=\"user:SSH_KEY\"",
			Category:     "compute_access",
		},
		"compute_set_project_metadata": {
			Permission:   "compute.projects.setCommonInstanceMetadata",
			Description:  "Can inject SSH keys via project metadata",
			Exploitation: "gcloud compute project-info add-metadata --metadata=ssh-keys=\"user:SSH_KEY\"",
			Category:     "compute_access",
		},
		"compute_serial_port": {
			Permission:   "compute.instances.getSerialPortOutput",
			Description:  "Can read serial port output (may leak data)",
			Exploitation: "gcloud compute instances get-serial-port-output INSTANCE --zone=ZONE",
			Category:     "compute_access",
		},
		// GKE Access
		"gke_get_credentials": {
			Permission:   "container.clusters.getCredentials",
			Description:  "Can get GKE cluster credentials",
			Exploitation: "gcloud container clusters get-credentials CLUSTER --zone=ZONE",
			Category:     "gke_access",
		},
		"gke_pod_exec": {
			Permission:   "container.pods.exec",
			Description:  "Can exec into GKE pods",
			Exploitation: "kubectl exec -it POD -- /bin/sh",
			Category:     "gke_access",
		},
		"gke_pod_attach": {
			Permission:   "container.pods.attach",
			Description:  "Can attach to GKE pods",
			Exploitation: "kubectl attach -it POD",
			Category:     "gke_access",
		},
		// Cloud Functions
		"functions_create": {
			Permission:   "cloudfunctions.functions.create",
			Description:  "Can create Cloud Functions with any SA",
			Exploitation: "gcloud functions deploy FUNC --runtime=python311 --service-account=SA_EMAIL",
			Category:     "serverless",
		},
		"functions_update": {
			Permission:   "cloudfunctions.functions.update",
			Description:  "Can update Cloud Functions to change SA or code",
			Exploitation: "gcloud functions deploy FUNC --service-account=SA_EMAIL",
			Category:     "serverless",
		},
		// Cloud Run
		"run_create": {
			Permission:   "run.services.create",
			Description:  "Can create Cloud Run services with any SA",
			Exploitation: "gcloud run deploy SERVICE --image=IMAGE --service-account=SA_EMAIL",
			Category:     "serverless",
		},
		"run_update": {
			Permission:   "run.services.update",
			Description:  "Can update Cloud Run services to change SA",
			Exploitation: "gcloud run services update SERVICE --service-account=SA_EMAIL",
			Category:     "serverless",
		},
		// Secrets
		"secret_access": {
			Permission:   "secretmanager.versions.access",
			Description:  "Can access secret values",
			Exploitation: "gcloud secrets versions access latest --secret=SECRET_NAME",
			Category:     "secrets",
		},
	}
}

// AnalyzeLateral analyzes lateral movement opportunities using graph data
// This is equivalent to running "foxmapper gcp query preset lateral"
// If pre-computed findings exist (lateral_findings.json), uses those.
// Otherwise falls back to edge-based analysis.
func (s *FoxMapperService) AnalyzeLateral(category string) []LateralFinding {
	if !s.initialized {
		return nil
	}

	// Use pre-computed findings from FoxMapper if available
	if s.LateralFindingsData != nil && len(s.LateralFindingsData.Findings) > 0 {
		return s.analyzeLateralFromFindings(category)
	}

	// Fallback to edge-based analysis (legacy behavior)
	return s.analyzeLateralFromEdges(category)
}

// analyzeLateralFromFindings uses pre-computed findings from lateral_findings.json
func (s *FoxMapperService) analyzeLateralFromFindings(category string) []LateralFinding {
	var findings []LateralFinding

	// Get the project ID from the findings data for project-level scope derivation
	projectID := s.LateralFindingsData.ProjectID

	for _, f := range s.LateralFindingsData.Findings {
		// Filter by category if specified
		if category != "" && f.Category != category {
			continue
		}

		// Convert file format to internal format
		var principals []PrincipalAccess
		for _, p := range f.Principals {
			// Get scope info from JSON fields, Resource, or derive from access_type
			scopeType := p.ScopeType
			scopeID := p.ScopeID
			scopeName := p.ScopeName

			if scopeType == "" {
				if p.Resource != "" {
					// Resource field exists in JSON
					scopeType, scopeID, scopeName = s.parseResourceScope(p.Resource)
				} else {
					// Derive scope from access_type and available context
					scopeType, scopeID, scopeName = s.deriveScopeFromContext(p.MemberID, p.AccessType, p.ViaEdge, projectID)
				}
			}

			principals = append(principals, PrincipalAccess{
				Principal:        p.Principal,
				MemberID:         p.MemberID,
				MemberType:       p.MemberType,
				IsAdmin:          p.IsAdmin,
				IsServiceAccount: p.IsServiceAccount,
				AccessType:       p.AccessType,
				ViaEdge:          p.ViaEdge,
				EdgePath:         p.EdgePath,
				ScopeType:        scopeType,
				ScopeID:          scopeID,
				ScopeName:        scopeName,
			})
		}

		if len(principals) > 0 {
			findings = append(findings, LateralFinding{
				Technique:    f.Technique,
				Permission:   f.Permission,
				Category:     f.Category,
				Description:  f.Description,
				Exploitation: f.Exploitation,
				Principals:   principals,
			})
		}
	}

	return findings
}

// analyzeLateralFromEdges is the legacy edge-based analysis (fallback)
func (s *FoxMapperService) analyzeLateralFromEdges(category string) []LateralFinding {
	var findings []LateralFinding
	techniques := GetLateralTechniques()

	for name, tech := range techniques {
		// Filter by category if specified
		if category != "" && tech.Category != category {
			continue
		}

		// Find principals with this permission via edges
		var principals []PrincipalAccess
		for _, edge := range s.Edges {
			// Check if edge grants this permission
			if strings.Contains(strings.ToLower(edge.Reason), strings.ToLower(tech.Permission)) ||
				strings.Contains(edge.ShortReason, tech.Permission) {
				node := s.GetNode(edge.Source)
				if node != nil {
					scopeType, scopeID, scopeName := s.parseResourceScope(edge.Resource)
					principals = append(principals, PrincipalAccess{
						Principal:        node.Email,
						MemberID:         node.MemberID,
						MemberType:       node.MemberType,
						IsAdmin:          node.IsAdmin,
						IsServiceAccount: node.MemberType == "serviceAccount",
						AccessType:       "via_privesc",
						ViaEdge:          true,
						ScopeType:        scopeType,
						ScopeID:          scopeID,
						ScopeName:        scopeName,
					})
				}
			}
		}

		if len(principals) > 0 {
			findings = append(findings, LateralFinding{
				Technique:    name,
				Permission:   tech.Permission,
				Category:     tech.Category,
				Description:  tech.Description,
				Exploitation: tech.Exploitation,
				Principals:   principals,
			})
		}
	}

	return findings
}

// DataExfilTechnique defines a data exfiltration technique
type DataExfilTechnique struct {
	Permission   string
	Description  string
	Exploitation string
	Service      string
}

// GetDataExfilTechniques returns all data exfiltration techniques
func GetDataExfilTechniques() map[string]DataExfilTechnique {
	return map[string]DataExfilTechnique{
		// Storage
		"gcs_objects_get": {
			Permission:   "storage.objects.get",
			Description:  "Can download objects from GCS buckets",
			Exploitation: "gsutil cp gs://BUCKET/path/to/file ./local/",
			Service:      "storage",
		},
		"gcs_objects_list": {
			Permission:   "storage.objects.list",
			Description:  "Can list objects in GCS buckets",
			Exploitation: "gsutil ls -r gs://BUCKET/",
			Service:      "storage",
		},
		// BigQuery
		"bq_data_get": {
			Permission:   "bigquery.tables.getData",
			Description:  "Can read BigQuery table data",
			Exploitation: "bq query 'SELECT * FROM dataset.table'",
			Service:      "bigquery",
		},
		"bq_tables_export": {
			Permission:   "bigquery.tables.export",
			Description:  "Can export BigQuery tables to GCS",
			Exploitation: "bq extract dataset.table gs://BUCKET/export.csv",
			Service:      "bigquery",
		},
		// Cloud SQL
		"cloudsql_export": {
			Permission:   "cloudsql.instances.export",
			Description:  "Can export Cloud SQL databases",
			Exploitation: "gcloud sql export sql INSTANCE gs://BUCKET/export.sql --database=DB",
			Service:      "cloudsql",
		},
		"cloudsql_connect": {
			Permission:   "cloudsql.instances.connect",
			Description:  "Can connect to Cloud SQL instances",
			Exploitation: "gcloud sql connect INSTANCE --user=root",
			Service:      "cloudsql",
		},
		// Secrets
		"secrets_access": {
			Permission:   "secretmanager.versions.access",
			Description:  "Can access secret values",
			Exploitation: "gcloud secrets versions access latest --secret=SECRET",
			Service:      "secretmanager",
		},
		// KMS
		"kms_decrypt": {
			Permission:   "cloudkms.cryptoKeyVersions.useToDecrypt",
			Description:  "Can decrypt data using KMS keys",
			Exploitation: "gcloud kms decrypt --key=KEY --keyring=KEYRING --location=LOCATION --ciphertext-file=encrypted.bin --plaintext-file=decrypted.txt",
			Service:      "kms",
		},
		// Logging
		"logging_read": {
			Permission:   "logging.logEntries.list",
			Description:  "Can read log entries (may contain sensitive data)",
			Exploitation: "gcloud logging read 'logName=\"projects/PROJECT/logs/LOG\"'",
			Service:      "logging",
		},
		// Pub/Sub
		"pubsub_receive": {
			Permission:   "pubsub.subscriptions.consume",
			Description:  "Can receive messages from Pub/Sub subscriptions",
			Exploitation: "gcloud pubsub subscriptions pull SUBSCRIPTION --auto-ack",
			Service:      "pubsub",
		},
		// Compute disk snapshots
		"snapshot_useReadOnly": {
			Permission:   "compute.snapshots.useReadOnly",
			Description:  "Can use disk snapshots to create disks",
			Exploitation: "gcloud compute disks create DISK --source-snapshot=SNAPSHOT",
			Service:      "compute",
		},
	}
}

// DataExfilFinding represents a data exfiltration finding
type DataExfilFinding struct {
	Technique      string            `json:"technique"`
	Permission     string            `json:"permission"`
	Service        string            `json:"service"`
	Description    string            `json:"description"`
	Exploitation   string            `json:"exploitation"`
	Principals     []PrincipalAccess `json:"principals"`
}

// AnalyzeDataExfil analyzes data exfiltration opportunities using graph data
// This is equivalent to running "foxmapper gcp query preset data-exfil"
// If pre-computed findings exist (data_exfil_findings.json), uses those.
// Otherwise falls back to edge-based analysis.
func (s *FoxMapperService) AnalyzeDataExfil(service string) []DataExfilFinding {
	if !s.initialized {
		return nil
	}

	// Use pre-computed findings from FoxMapper if available
	if s.DataExfilFindingsData != nil && len(s.DataExfilFindingsData.Findings) > 0 {
		return s.analyzeDataExfilFromFindings(service)
	}

	// Fallback to edge-based analysis (legacy behavior)
	return s.analyzeDataExfilFromEdges(service)
}

// analyzeDataExfilFromFindings uses pre-computed findings from data_exfil_findings.json
func (s *FoxMapperService) analyzeDataExfilFromFindings(service string) []DataExfilFinding {
	var findings []DataExfilFinding

	// Get the project ID from the findings data for project-level scope derivation
	projectID := s.DataExfilFindingsData.ProjectID

	for _, f := range s.DataExfilFindingsData.Findings {
		// Filter by service if specified
		if service != "" && f.Service != service {
			continue
		}

		// Convert file format to internal format
		var principals []PrincipalAccess
		for _, p := range f.Principals {
			// Get scope info from JSON fields, Resource, or derive from access_type
			scopeType := p.ScopeType
			scopeID := p.ScopeID
			scopeName := p.ScopeName

			if scopeType == "" {
				if p.Resource != "" {
					// Resource field exists in JSON
					scopeType, scopeID, scopeName = s.parseResourceScope(p.Resource)
				} else {
					// Derive scope from access_type and available context
					scopeType, scopeID, scopeName = s.deriveScopeFromContext(p.MemberID, p.AccessType, p.ViaEdge, projectID)
				}
			}

			principals = append(principals, PrincipalAccess{
				Principal:        p.Principal,
				MemberID:         p.MemberID,
				MemberType:       p.MemberType,
				IsAdmin:          p.IsAdmin,
				IsServiceAccount: p.IsServiceAccount,
				AccessType:       p.AccessType,
				ViaEdge:          p.ViaEdge,
				EdgePath:         p.EdgePath,
				ScopeType:        scopeType,
				ScopeID:          scopeID,
				ScopeName:        scopeName,
			})
		}

		if len(principals) > 0 {
			findings = append(findings, DataExfilFinding{
				Technique:    f.Technique,
				Permission:   f.Permission,
				Service:      f.Service,
				Description:  f.Description,
				Exploitation: f.Exploitation,
				Principals:   principals,
			})
		}
	}

	return findings
}

// analyzeDataExfilFromEdges is the legacy edge-based analysis (fallback)
func (s *FoxMapperService) analyzeDataExfilFromEdges(service string) []DataExfilFinding {
	var findings []DataExfilFinding
	techniques := GetDataExfilTechniques()

	for name, tech := range techniques {
		// Filter by service if specified
		if service != "" && tech.Service != service {
			continue
		}

		// Find principals with this permission via edges
		var principals []PrincipalAccess
		for _, edge := range s.Edges {
			// Check if edge grants this permission
			if strings.Contains(strings.ToLower(edge.Reason), strings.ToLower(tech.Permission)) ||
				strings.Contains(edge.ShortReason, tech.Permission) {
				node := s.GetNode(edge.Source)
				if node != nil {
					scopeType, scopeID, scopeName := s.parseResourceScope(edge.Resource)
					principals = append(principals, PrincipalAccess{
						Principal:        node.Email,
						MemberID:         node.MemberID,
						MemberType:       node.MemberType,
						IsAdmin:          node.IsAdmin,
						IsServiceAccount: node.MemberType == "serviceAccount",
						AccessType:       "via_privesc",
						ViaEdge:          true,
						ScopeType:        scopeType,
						ScopeID:          scopeID,
						ScopeName:        scopeName,
					})
				}
			}
		}

		if len(principals) > 0 {
			findings = append(findings, DataExfilFinding{
				Technique:    name,
				Permission:   tech.Permission,
				Service:      tech.Service,
				Description:  tech.Description,
				Exploitation: tech.Exploitation,
				Principals:   principals,
			})
		}
	}

	return findings
}

// GetAllNodes returns all nodes in the graph
func (s *FoxMapperService) GetAllNodes() []Node {
	return s.Nodes
}

// GetAllEdges returns all edges in the graph
func (s *FoxMapperService) GetAllEdges() []Edge {
	return s.Edges
}

// GetPolicies returns all policies in the graph
func (s *FoxMapperService) GetPolicies() []Policy {
	return s.Policies
}

// ==========================================
// Wrong Admin (Hidden Admin) Analysis
// ==========================================

// WrongAdminFinding represents a principal marked as admin without explicit admin roles
type WrongAdminFinding struct {
	Principal   string   `json:"principal"`
	MemberType  string   `json:"member_type"`
	AdminLevel  string   `json:"admin_level"` // org, folder, project
	Reasons     []string `json:"reasons"`
	ProjectID   string   `json:"project_id"`
	FolderID    string   `json:"folder_id,omitempty"`  // For folder-level admins
	OrgID       string   `json:"org_id,omitempty"`     // For org-level admins
}

// ADMIN_ROLES are roles that grant explicit admin access
var ADMIN_ROLES = map[string]bool{
	"roles/owner": true,
}

// SELF_ASSIGNMENT_ROLES are roles that can grant themselves admin access
var SELF_ASSIGNMENT_ROLES = map[string]bool{
	"roles/resourcemanager.projectIamAdmin":      true,
	"roles/resourcemanager.folderAdmin":          true,
	"roles/resourcemanager.organizationAdmin":    true,
	"roles/iam.securityAdmin":                    true,
	"roles/iam.organizationRoleAdmin":            true,
}

// AnalyzeWrongAdmins finds principals marked as admin without explicit admin roles
// This is equivalent to running "foxmapper gcp query preset wrongadmin"
func (s *FoxMapperService) AnalyzeWrongAdmins() []WrongAdminFinding {
	if !s.initialized {
		return nil
	}

	var findings []WrongAdminFinding

	for i := range s.Nodes {
		node := &s.Nodes[i]

		// Skip non-admins
		if !node.IsAdmin {
			continue
		}

		// Check if they have explicit admin role (roles/owner)
		if s.hasExplicitAdminRole(node) {
			continue
		}

		// This is a "wrong admin" - get reasons why they're admin
		reasons := s.getAdminReasons(node)

		// Get the highest admin resource ID (org, folder, or project)
		folderID, orgID := s.getAdminResourceIDs(node)

		finding := WrongAdminFinding{
			Principal:  node.Email,
			MemberType: node.MemberType,
			AdminLevel: node.AdminLevel,
			Reasons:    reasons,
			ProjectID:  node.ProjectID,
			FolderID:   folderID,
			OrgID:      orgID,
		}

		if finding.AdminLevel == "" {
			finding.AdminLevel = "project"
		}

		findings = append(findings, finding)
	}

	// Sort by admin level (org > folder > project)
	sort.Slice(findings, func(i, j int) bool {
		levelOrder := map[string]int{"org": 0, "folder": 1, "project": 2}
		li, ok := levelOrder[findings[i].AdminLevel]
		if !ok {
			li = 3
		}
		lj, ok := levelOrder[findings[j].AdminLevel]
		if !ok {
			lj = 3
		}
		if li != lj {
			return li < lj
		}
		return findings[i].Principal < findings[j].Principal
	})

	return findings
}

// hasExplicitAdminRole checks if a node has roles/owner directly
func (s *FoxMapperService) hasExplicitAdminRole(node *Node) bool {
	for _, policy := range s.Policies {
		for _, binding := range policy.Bindings {
			if !ADMIN_ROLES[binding.Role] {
				continue
			}

			for _, member := range binding.Members {
				if s.memberMatchesNode(member, node) {
					// Check for conditions - conditional admin is "wrong" admin
					if binding.Condition != nil && len(binding.Condition) > 0 {
						return false
					}
					return true
				}
			}
		}
	}
	return false
}

// memberMatchesNode checks if a member string matches a node
func (s *FoxMapperService) memberMatchesNode(member string, node *Node) bool {
	memberLower := strings.ToLower(member)
	nodeMemberLower := strings.ToLower(node.MemberID)

	// Direct match
	if memberLower == nodeMemberLower {
		return true
	}

	// Check group memberships
	if strings.HasPrefix(member, "group:") && len(node.GroupMemberships) > 0 {
		groupEmail := strings.ToLower(strings.SplitN(member, ":", 2)[1])
		for _, gm := range node.GroupMemberships {
			if strings.ToLower(gm) == groupEmail || strings.ToLower(gm) == memberLower {
				return true
			}
		}
	}

	return false
}

// getAdminReasons returns reasons why a node is marked as admin
func (s *FoxMapperService) getAdminReasons(node *Node) []string {
	var reasons []string

	for _, policy := range s.Policies {
		policyLevel := s.getPolicyLevel(policy.Resource)

		for _, binding := range policy.Bindings {
			if !SELF_ASSIGNMENT_ROLES[binding.Role] {
				continue
			}

			for _, member := range binding.Members {
				if s.memberMatchesNode(member, node) {
					conditionNote := ""
					if binding.Condition != nil && len(binding.Condition) > 0 {
						conditionNote = " (conditional)"
					}

					switch binding.Role {
					case "roles/resourcemanager.projectIamAdmin":
						reasons = append(reasons, fmt.Sprintf(
							"Has %s on %s%s - can set project IAM policy (grant themselves roles/owner)",
							binding.Role, policy.Resource, conditionNote))
					case "roles/resourcemanager.folderAdmin":
						reasons = append(reasons, fmt.Sprintf(
							"Has %s on %s%s - can set folder IAM policy (grant themselves roles/owner at folder level)",
							binding.Role, policy.Resource, conditionNote))
					case "roles/resourcemanager.organizationAdmin":
						reasons = append(reasons, fmt.Sprintf(
							"Has %s on %s%s - can set organization IAM policy (grant themselves roles/owner at org level)",
							binding.Role, policy.Resource, conditionNote))
					case "roles/iam.securityAdmin":
						reasons = append(reasons, fmt.Sprintf(
							"Has %s on %s%s - can set IAM policies at %s level",
							binding.Role, policy.Resource, conditionNote, policyLevel))
					case "roles/iam.organizationRoleAdmin":
						reasons = append(reasons, fmt.Sprintf(
							"Has %s on %s%s - can create/modify roles and has organization setIamPolicy",
							binding.Role, policy.Resource, conditionNote))
					default:
						reasons = append(reasons, fmt.Sprintf(
							"Has %s on %s%s", binding.Role, policy.Resource, conditionNote))
					}
					break
				}
			}
		}
	}

	// Check for custom roles with setIamPolicy permissions
	for _, policy := range s.Policies {
		for _, binding := range policy.Bindings {
			// Skip standard roles we already checked
			if SELF_ASSIGNMENT_ROLES[binding.Role] || ADMIN_ROLES[binding.Role] {
				continue
			}

			// Check if it's a custom role
			if strings.HasPrefix(binding.Role, "projects/") || strings.HasPrefix(binding.Role, "organizations/") {
				for _, member := range binding.Members {
					if s.memberMatchesNode(member, node) {
						roleLower := strings.ToLower(binding.Role)
						if strings.Contains(roleLower, "admin") || strings.Contains(roleLower, "iam") {
							reasons = append(reasons, fmt.Sprintf(
								"Has custom role %s on %s - may grant setIamPolicy permissions",
								binding.Role, policy.Resource))
						}
						break
					}
				}
			}
		}
	}

	if len(reasons) == 0 {
		reasons = append(reasons, fmt.Sprintf(
			"Marked as %s admin but couldn't determine specific role - may be due to inherited permissions or group membership",
			node.AdminLevel))
	}

	return reasons
}

// getPolicyLevel determines the level of a policy resource
func (s *FoxMapperService) getPolicyLevel(resource string) string {
	if strings.HasPrefix(resource, "organizations/") {
		return "organization"
	} else if strings.HasPrefix(resource, "folders/") {
		return "folder"
	}
	return "project"
}

// getAdminResourceIDs returns the folder ID and org ID where the node has admin access
// Returns the highest level resources (org > folder > project)
func (s *FoxMapperService) getAdminResourceIDs(node *Node) (folderID, orgID string) {
	for _, policy := range s.Policies {
		for _, binding := range policy.Bindings {
			// Check for self-assignment roles (makes them admin)
			if !SELF_ASSIGNMENT_ROLES[binding.Role] {
				continue
			}

			for _, member := range binding.Members {
				if s.memberMatchesNode(member, node) {
					// Extract resource ID based on type
					if strings.HasPrefix(policy.Resource, "organizations/") {
						orgID = strings.TrimPrefix(policy.Resource, "organizations/")
					} else if strings.HasPrefix(policy.Resource, "folders/") {
						// Only set folderID if we don't already have org admin
						// (org level is higher)
						if orgID == "" {
							folderID = strings.TrimPrefix(policy.Resource, "folders/")
						}
					}
				}
			}
		}
	}
	return folderID, orgID
}

// parseResourceScope extracts scope information from a resource string
// Returns scopeType, scopeID, scopeName
// Resource formats: "organizations/123", "folders/456", "projects/myproject", etc.
func (s *FoxMapperService) parseResourceScope(resource string) (scopeType, scopeID, scopeName string) {
	if resource == "" {
		return "unknown", "", ""
	}

	if strings.HasPrefix(resource, "organizations/") {
		scopeType = "organization"
		scopeID = strings.TrimPrefix(resource, "organizations/")
		// Try to get display name from metadata if available
		scopeName = scopeID
	} else if strings.HasPrefix(resource, "folders/") {
		scopeType = "folder"
		scopeID = strings.TrimPrefix(resource, "folders/")
		scopeName = scopeID
	} else if strings.HasPrefix(resource, "projects/") {
		scopeType = "project"
		scopeID = strings.TrimPrefix(resource, "projects/")
		scopeName = scopeID
	} else {
		// Resource-level permission (e.g., storage bucket, BigQuery dataset)
		scopeType = "resource"
		scopeID = resource
		scopeName = resource
	}

	return scopeType, scopeID, scopeName
}

// deriveScopeFromContext derives scope information when the Resource field is empty
// This is needed for pre-computed findings that don't include the resource field.
// For "project_iam" access type, we know the permission was granted at project level.
// For "via_privesc" access type, we look up the edge to find where the permission was granted.
func (s *FoxMapperService) deriveScopeFromContext(memberID, accessType string, viaEdge bool, fallbackProjectID string) (scopeType, scopeID, scopeName string) {
	// For project_iam access, the permission was granted at the project level
	if accessType == "project_iam" {
		return "project", fallbackProjectID, fallbackProjectID
	}

	// For via_privesc with viaEdge=true, look up the edge to find the resource
	if viaEdge && accessType == "via_privesc" {
		// Find the first edge from this principal to determine scope
		for _, edge := range s.Edges {
			if edge.Source == memberID {
				if edge.Resource != "" {
					return s.parseResourceScope(edge.Resource)
				}
			}
		}
	}

	// Fallback: if we have a project ID, assume project-level
	if fallbackProjectID != "" {
		return "project", fallbackProjectID, fallbackProjectID
	}

	return "unknown", "", ""
}
