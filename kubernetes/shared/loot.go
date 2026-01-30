package shared

import (
	"fmt"
	"strings"

	"github.com/BishopFox/cloudfox/internal"
)

// LootBuilder provides a fluent API for building loot files
type LootBuilder struct {
	sections map[string]*LootSection
	order    []string // Maintains insertion order
}

// LootSection represents a single loot file section
type LootSection struct {
	name    string
	header  string
	summary string
	items   []string
}

// NewLootBuilder creates a new LootBuilder
func NewLootBuilder() *LootBuilder {
	return &LootBuilder{
		sections: make(map[string]*LootSection),
		order:    make([]string, 0),
	}
}

// Section gets or creates a loot section
func (lb *LootBuilder) Section(name string) *LootSection {
	if section, exists := lb.sections[name]; exists {
		return section
	}

	section := &LootSection{
		name:  name,
		items: make([]string, 0),
	}
	lb.sections[name] = section
	lb.order = append(lb.order, name)
	return section
}

// HasSection checks if a section exists
func (lb *LootBuilder) HasSection(name string) bool {
	_, exists := lb.sections[name]
	return exists
}

// Build generates the final loot files
func (lb *LootBuilder) Build() []internal.LootFile {
	files := make([]internal.LootFile, 0, len(lb.order))

	for _, name := range lb.order {
		section := lb.sections[name]
		if len(section.items) == 0 && section.summary == "" {
			continue // Skip empty sections
		}

		var content strings.Builder

		// Add header if present
		if section.header != "" {
			content.WriteString(section.header)
			content.WriteString("\n")
		}

		// Add summary if present
		if section.summary != "" {
			content.WriteString(section.summary)
			content.WriteString("\n")
		}

		// Add items
		for _, item := range section.items {
			content.WriteString(item)
			content.WriteString("\n")
		}

		files = append(files, internal.LootFile{
			Name:     section.name,
			Contents: strings.TrimSuffix(content.String(), "\n"),
		})
	}

	return files
}

// SetHeader sets the header for this section
func (ls *LootSection) SetHeader(header string) *LootSection {
	ls.header = header
	return ls
}

// SetSummary sets the summary (appears after header, before items)
func (ls *LootSection) SetSummary(summary string) *LootSection {
	ls.summary = summary
	return ls
}

// Add adds a line to this section
func (ls *LootSection) Add(line string) *LootSection {
	ls.items = append(ls.items, line)
	return ls
}

// Addf adds a formatted line to this section
func (ls *LootSection) Addf(format string, args ...interface{}) *LootSection {
	ls.items = append(ls.items, fmt.Sprintf(format, args...))
	return ls
}

// AddIf conditionally adds a line
func (ls *LootSection) AddIf(condition bool, line string) *LootSection {
	if condition {
		ls.Add(line)
	}
	return ls
}

// AddIfNotEmpty adds line if value is not empty
func (ls *LootSection) AddIfNotEmpty(value, line string) *LootSection {
	if value != "" {
		ls.Add(line)
	}
	return ls
}

// AddCmd adds a command with optional comment
func (ls *LootSection) AddCmd(cmd string) *LootSection {
	ls.items = append(ls.items, cmd)
	return ls
}

// AddCmdWithComment adds a command with a preceding comment
func (ls *LootSection) AddCmdWithComment(comment, cmd string) *LootSection {
	ls.items = append(ls.items, fmt.Sprintf("# %s", comment))
	ls.items = append(ls.items, cmd)
	return ls
}

// AddSection adds a sub-section header
func (ls *LootSection) AddSection(title string) *LootSection {
	ls.items = append(ls.items, "")
	ls.items = append(ls.items, fmt.Sprintf("### %s", title))
	return ls
}

// AddBlank adds a blank line
func (ls *LootSection) AddBlank() *LootSection {
	ls.items = append(ls.items, "")
	return ls
}

// Len returns the number of items in this section
func (ls *LootSection) Len() int {
	return len(ls.items)
}

// Standard loot headers
const (
	LootHeaderExec = `#####################################
##### Execute Commands
#####################################
#
# MANUAL EXECUTION REQUIRED
# Commands for interactive access
#`

	LootHeaderEnum = `#####################################
##### Enumeration Commands
#####################################
#
# MANUAL EXECUTION REQUIRED
# Commands for gathering information
#`

	LootHeaderPrivEsc = `#####################################
##### Privilege Escalation
#####################################
#
# MANUAL EXECUTION REQUIRED
# Potential privilege escalation paths
#`

	LootHeaderLateralMove = `#####################################
##### Lateral Movement
#####################################
#
# MANUAL EXECUTION REQUIRED
# Potential lateral movement paths
#`

	LootHeaderSecrets = `#####################################
##### Secret Extraction
#####################################
#
# MANUAL EXECUTION REQUIRED
# Commands to extract secrets
#`

	LootHeaderRemediation = `#####################################
##### Remediation
#####################################
#
# Recommended fixes for identified issues
#`

	LootHeaderAttackChains = `#####################################
##### Attack Chains
#####################################
#
# Multi-step attack scenarios
#`
)

// Helper function to create standard section names
func LootSectionName(resource, category string) string {
	return fmt.Sprintf("%s-%s", resource, category)
}

// Standard category names
const (
	CategoryExec        = "Exec"
	CategoryEnum        = "Enum"
	CategoryPrivEsc     = "PrivEsc"
	CategoryLateralMove = "LateralMove"
	CategorySecrets     = "Secrets"
	CategoryRemediation = "Remediation"
	CategoryAttackChains = "AttackChains"
)

// FormatSuspiciousEntry formats a suspicious finding with its issues for loot output.
// Resource identifier on first line, issues indented below for clear visual separation.
// Returns lines to append to loot content.
func FormatSuspiciousEntry(namespace, name string, issues []string) []string {
	var lines []string
	lines = append(lines, fmt.Sprintf("# %s/%s", namespace, name))
	for _, issue := range issues {
		lines = append(lines, fmt.Sprintf("#     - %s", issue))
	}
	return lines
}

