package aws

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	titleStyle = func() lipgloss.Style {
		b := lipgloss.RoundedBorder()
		b.Right = "├"
		return lipgloss.NewStyle().BorderStyle(b).Padding(0, 1)
	}()

	infoStyle = func() lipgloss.Style {
		b := lipgloss.RoundedBorder()
		b.Left = "┤"
		return titleStyle.Copy().BorderStyle(b)
	}()
	magentaStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("magenta"))
)

type model struct {
	preloadedData       *AllAccountData
	awsAccountsTable    table.Model
	awsAccountsViewport viewport.Model

	mainTable         table.Model
	mainTableViewport viewport.Model
	mainTableData     map[int][]table.Row

	detailsData     map[int]string
	detailsViewport viewport.Model // Use viewport for details view

	focusSelector     int
	defaultTableStyle table.Styles

	terminalWidth   int
	terminalHeight  int // Add terminal height to manage viewport size
	awsSelectedRow  int
	mainSelectedRow int // Track the currently selected row for detail view updates
	keys            keyMap
	help            help.Model
	lastKey         string
	quitting        bool
}

type CapeJSON struct {
	Account       string `json:"account"`
	Source        string `json:"source"`
	Summary       string `json:"summary"`
	Target        string `json:"target"`
	IsTargetAdmin string `json:"isTargetAdmin"`
}

type PerAccountData struct {
	FilePath     string     // Path to the JSON file
	PrivescPaths []CapeJSON // All records contained in the file
}

type AllAccountData struct {
	Files map[string]*PerAccountData // Map of file paths to their records
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240")).
		BorderBottom(true).
		Bold(false)
	s.Selected = s.Selected.
		Foreground(lipgloss.Color("229")).
		Background(lipgloss.Color("57")).
		Bold(false)

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.terminalWidth = msg.Width
		m.terminalHeight = msg.Height - 7 // Adjust as needed

		// Calculate heights based on the specified percentages
		awsAccountsHeight := int(float32(m.terminalHeight) * 0.2)
		halfHeight := int(float32(m.terminalHeight) * 0.4) // For the other two viewports

		// Update dimensions for all viewports
		m.awsAccountsViewport.Width = m.terminalWidth - 4
		m.awsAccountsViewport.Height = awsAccountsHeight

		m.mainTableViewport.Width = m.terminalWidth - 4
		m.mainTableViewport.Height = halfHeight
		m.awsAccountsTable.SetHeight(awsAccountsHeight - 2)
		m.awsAccountsTable.SetWidth(m.terminalWidth - 4)
		m.awsAccountsViewport.Width = m.terminalWidth - 4

		m.detailsViewport.Width = m.terminalWidth - 4
		m.detailsViewport.Height = halfHeight
		m.mainTable.SetHeight(halfHeight - 2)

	case tea.KeyMsg:
		switch {
		case key.Matches(msg, m.keys.Up):
			m.lastKey = "↑"
		case key.Matches(msg, m.keys.Down):
			m.lastKey = "↓"
		case key.Matches(msg, m.keys.Left):
			m.lastKey = "←"
		case key.Matches(msg, m.keys.Right):
			m.lastKey = "→"
		case key.Matches(msg, m.keys.Help):
			m.help.ShowAll = !m.help.ShowAll
		case key.Matches(msg, m.keys.Tab):
			// Switch focus between the the three viewports by cycling focusSelector between 0, 1, and 2
			m.focusSelector = (m.focusSelector + 1) % 3
			//m.focusOnTable = !m.focusOnTable
		// add a case for shift and tab at the same time to to cycle the focusSelector backwards between 0, 1, and 2
		case key.Matches(msg, m.keys.ShiftTab):
			m.focusSelector = (m.focusSelector - 1) % 3

		case key.Matches(msg, m.keys.Quit):
			m.quitting = true
			return m, tea.Quit
		}

		//var detailsData map[int]string
		//var mainTable table.Model
		var err error
		var awsCurrentRow int
		var mainCurrentRow int
		switch m.focusSelector {
		case 0:
			m.awsAccountsTable, cmd = m.awsAccountsTable.Update(msg)
			m.awsAccountsViewport.SetContent(m.awsAccountsTable.View())
			awsCurrentRow = m.awsAccountsTable.Cursor()
			if m.awsSelectedRow != awsCurrentRow {
				m.awsSelectedRow = awsCurrentRow
				// Update the viewport content based on the newly selected row
				// Load the file for the selected account and show the file content in the main table
				m.mainTable, m.detailsData, err = getRecordsForAccount(m.preloadedData.Files[m.awsAccountsTable.Rows()[awsCurrentRow][0]])
				if err != nil {
					// Handle error
					break
				}
				m.mainTable.SetStyles(s)
				m.mainTableViewport.SetContent(m.mainTable.View())
				m.detailsViewport.SetContent(m.detailsData[0])

			}
		case 1:
			m.mainTable, cmd = m.mainTable.Update(msg)
			// Check if the selected row has changed
			m.mainTableViewport.SetContent(m.mainTable.View())

			mainCurrentRow = m.mainTable.Cursor()
			if m.mainSelectedRow != mainCurrentRow {
				m.mainSelectedRow = mainCurrentRow
				// Update the viewport content based on the newly selected row
				if detail, ok := m.detailsData[m.mainSelectedRow]; ok {
					m.detailsViewport.SetContent(detail)
				} else {
					m.detailsViewport.SetContent(fmt.Sprintf("No details available for main row %d (aws row %d)", m.mainSelectedRow, m.awsSelectedRow))
				}
			}
		case 2:
			m.detailsViewport, cmd = m.detailsViewport.Update(msg)
		}
	}
	return m, cmd
}

func (m model) View() string {
	// Define styles for active and inactive viewports
	activeBorderStyle := lipgloss.NewStyle().
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("#00FFFF")). // Cyan for active
		Padding(0)
	activeBorderStyle.PaddingLeft(1)
	activeBorderStyle.PaddingRight(1)

	inactiveBorderStyle := lipgloss.NewStyle().
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("#808080")). // Gray for inactive
		Padding(0)
	inactiveBorderStyle.PaddingLeft(1)
	inactiveBorderStyle.PaddingRight(1)

	// Conditionally apply border styles based on focus
	awsTableViewStyle := activeBorderStyle
	m.awsAccountsTable.SetStyles(m.defaultTableStyle)
	tableViewStyle := inactiveBorderStyle
	m.mainTable.SetStyles(m.defaultTableStyle)
	detailsViewStyle := inactiveBorderStyle

	switch m.focusSelector {
	case 0:
		awsTableViewStyle = activeBorderStyle
		m.awsAccountsTable.SetStyles(m.defaultTableStyle)
		tableViewStyle = inactiveBorderStyle
		detailsViewStyle = inactiveBorderStyle
	case 1:
		awsTableViewStyle = inactiveBorderStyle
		tableViewStyle = activeBorderStyle
		m.mainTable.SetStyles(m.defaultTableStyle)
		detailsViewStyle = inactiveBorderStyle
	case 2:
		awsTableViewStyle = inactiveBorderStyle
		tableViewStyle = inactiveBorderStyle
		detailsViewStyle = activeBorderStyle
	}

	// Render the table and details viewports with their styles (adjust based on focus)
	awsAccountsView := awsTableViewStyle.Render(m.awsAccountsViewport.View())
	tableView := tableViewStyle.Render(m.mainTableViewport.View())
	detailsView := detailsViewStyle.Render(m.detailsViewport.View())

	// Combine all views
	fullView := lipgloss.JoinVertical(lipgloss.Top, awsAccountsView, tableView, detailsView)

	helpView := m.help.View(m.keys)

	return fmt.Sprintf("%s\n%s", fullView, helpView)
}

func calculateMaxWidths(rows []table.Row) []int {

	var maxWidths []int
	// make sure the length of the rows is greater than 0

	if len(rows) > 0 {
		maxWidths = make([]int, len(rows[0]))
	} else {
		maxWidths = []int{30, 30, 30, 30}
	}

	for _, row := range rows {
		for i, cell := range row {
			if len(cell) > maxWidths[i] {
				maxWidths[i] = len(cell)
			}
		}
	}

	return maxWidths

}

func (m model) footerView() string {
	info := infoStyle.Render(fmt.Sprintf("%3.f%%", m.detailsViewport.ScrollPercent()*100))
	line := strings.Repeat("─", max(0, m.detailsViewport.Width-lipgloss.Width(info)))
	return lipgloss.JoinHorizontal(lipgloss.Center, line, info)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func loadFileRecords(filePath string) (*PerAccountData, error) {
	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Decode the JSON data
	var records []CapeJSON
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&records); err != nil {
		return nil, err
	}

	// Return a new FileRecords instance
	return &PerAccountData{
		FilePath:     filePath,
		PrivescPaths: records,
	}, nil
}

func preloadData(filePaths []string) (*AllAccountData, error) {
	appData := &AllAccountData{
		Files: make(map[string]*PerAccountData),
	}

	for _, filePath := range filePaths {
		fileRecords, err := loadFileRecords(filePath)
		if err != nil {
			return nil, err
		}
		appData.Files[filePath] = fileRecords
	}

	return appData, nil
}

func getRecordsForAccount(preloadedData *PerAccountData) (table.Model, map[int]string, error) {
	// lets load the records for the first file in the list

	records := preloadedData.PrivescPaths

	// Prepare rows for the table and data for the right view
	rows := make([]table.Row, 0, len(records)-1)
	detailsData := make(map[int]string)  // Initialize the map for the fourth column's data
	for i, record := range records[1:] { // Skip the header row
		rows = append(rows, table.Row{record.Account, record.Source, record.Target, record.IsTargetAdmin})
		detailsData[i] = expandDetailsData(record.Summary)
	}

	// Calculate max widths
	maxWidths := calculateMaxWidths(rows)

	// Define columns with calculated widths
	columns := make([]table.Column, len(maxWidths))
	colNames := []string{}
	for _, header := range []string{"Account", "Source", "Target", "isTargetAdmin"} {
		colNames = append(colNames, header)
	}

	for i, width := range maxWidths {
		colName := colNames[i]
		// if column name width is greater than the calculated width, use the column name width
		if len(colName) > width {
			width = len(colName)
		}
		columns[i] = table.Column{
			Title: colName,
			Width: width,
		}
	}

	mainTable := table.New(
		table.WithColumns(columns),
		table.WithRows(rows),
		table.WithFocused(true),
	)
	return mainTable, detailsData, nil
}

func CapeTUI(outputFiles []string) {

	preloadData, err := preloadData(outputFiles)
	if err != nil {
		fmt.Printf("Error preloading data: %s\n", err)
		fmt.Println("Either remove this profile from the list of profiles, or make sure cape can run successfully for this profile")
		os.Exit(1)
	}

	var awsAccountsRows []table.Row
	for _, file := range preloadData.Files {
		// Extract a user-friendly account name from the file path if needed
		// For simplicity, here we use the file path itself
		awsAccountsRows = append(awsAccountsRows, table.Row{file.FilePath})
	}

	mainTable, detailsData, err := getRecordsForAccount(preloadData.Files[outputFiles[0]])

	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240")).
		BorderBottom(true).
		Bold(false)
	s.Selected = s.Selected.
		Foreground(lipgloss.Color("229")).
		Background(lipgloss.Color("57")).
		Bold(false)

	awsAccountsWidth := calculateMaxWidths(awsAccountsRows)
	awsAccountsTable := table.New(
		table.WithColumns([]table.Column{
			{Title: "AWS Accounts", Width: awsAccountsWidth[0]},
		}),
		table.WithRows(awsAccountsRows),
		table.WithFocused(true), // Initially unfocused
	)

	awsAccountsTable.SetStyles(s)
	awsAccountsViewport := viewport.New(0, 0)               // Initialize with 0 size; will be updated
	awsAccountsViewport.SetContent(awsAccountsTable.View()) // Set initial content

	mainTable.SetStyles(s)
	mainTableViewport := viewport.New(0, 0)        // Initialize with 0 size; it will be updated
	mainTableViewport.SetContent(mainTable.View()) // Set the initial content of the table viewport

	// Initialize viewport for details view
	detailsViewportModel := viewport.New(0, 0) // Size will be set based on terminal size in Update
	// show the first row's details by default
	detailsViewportModel.SetContent(detailsData[0])

	m := model{
		preloadedData:       preloadData,
		awsAccountsTable:    awsAccountsTable,
		awsAccountsViewport: awsAccountsViewport,
		mainTable:           mainTable,
		mainTableViewport:   mainTableViewport,
		detailsData:         detailsData,
		detailsViewport:     detailsViewportModel,

		//focusOnTable:  true,
		focusSelector:     0,
		mainSelectedRow:   0, // Initialize selectedRow with an invalid index
		awsSelectedRow:    0,
		defaultTableStyle: s,
		keys:              keys,
		help:              help.New(),
	}

	p := tea.NewProgram(m)
	if err := p.Start(); err != nil {
		fmt.Printf("Error starting program: %s\n", err)
		os.Exit(1)
	}
}

// keyMap defines a set of keybindings. To work for help it must satisfy
// key.Map. It could also very easily be a map[string]key.Binding.
type keyMap struct {
	Up       key.Binding
	Down     key.Binding
	Left     key.Binding
	Right    key.Binding
	Help     key.Binding
	Quit     key.Binding
	Tab      key.Binding
	ShiftTab key.Binding
}

// ShortHelp returns keybindings to be shown in the mini help view. It's part
// of the key.Map interface.
func (k keyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Tab, k.ShiftTab, k.Up, k.Down, k.Help, k.Quit}
}

// FullHelp returns keybindings for the expanded help view. It's part of the
// key.Map interface.
func (k keyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Up, k.Down, k.Left, k.Right},     // first column
		{k.Tab, k.ShiftTab, k.Help, k.Quit}, // second column
	}
}

var keys = keyMap{
	Up: key.NewBinding(
		key.WithKeys("up", "k"),
		key.WithHelp("↑/k", "move up"),
	),
	Down: key.NewBinding(
		key.WithKeys("down", "j"),
		key.WithHelp("↓/j", "move down"),
	),
	Left: key.NewBinding(
		key.WithKeys("left", "h"),
		key.WithHelp("←/h", "move left"),
	),
	Right: key.NewBinding(
		key.WithKeys("right", "l"),
		key.WithHelp("→/l", "move right"),
	),
	Help: key.NewBinding(
		key.WithKeys("?"),
		key.WithHelp("?", "toggle help"),
	),
	Quit: key.NewBinding(
		key.WithKeys("q", "esc", "ctrl+c"),
		key.WithHelp("q", "quit"),
	),
	Tab: key.NewBinding(
		key.WithKeys("tab"),
		key.WithHelp("tab", "Switch window focus"),
	),
	ShiftTab: key.NewBinding(
		key.WithKeys("shift+tab"),
		key.WithHelp("shift+tab", "Switch window focus"),
	),
}

func expandDetailsData(input string) string {
	output := ""
	lines := strings.Split(input, "\n")

	for _, line := range lines {
		var hop, option int
		var rest string

		// Use Sscanf to extract hop and option values
		n, err := fmt.Sscanf(line, "[Hop: %d] [Option: %d]", &hop, &option)
		if err != nil || n != 2 {
			fmt.Printf("Error parsing line, expected 2 got %d: %v\n", n, err)
			continue
		}

		// Extract the rest of the line manually
		restIndex := strings.Index(line, "]") + 1
		restIndex = strings.Index(line[restIndex:], "]") + restIndex + 1
		if restIndex > 1 && restIndex < len(line) {
			rest = line[restIndex+1:] // +1 to skip the space after the second ]
		}

		// Construct the formatted output
		formattedLine := fmt.Sprintf("[Hop: %d][Option: %d]\n\t%s\n\n", hop, option, rest)
		output += formattedLine
	}

	return output

}
