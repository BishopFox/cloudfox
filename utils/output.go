package utils

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/alexeyco/simpletable"
)

type OutputData struct {
	Headers       []*simpletable.Cell
	Body          [][]interface{}
	FilePath      string
	FullFilename  string
	CallingModule string
	Verbosity     int
	Directory     string
}

func (o *OutputData) tableOutput() {
	path := filepath.Join(o.FilePath, "table")
	err := os.MkdirAll(path, os.ModePerm)
	var fullFilename string
	if err != nil {
		log.Println(err)
	}
	if o.FullFilename == "" {
		fullFilename = filepath.Join(path, fmt.Sprintf("%s.txt", o.CallingModule))
	} else {
		fullFilename = o.FullFilename
	}
	table := simpletable.New()

	// Populates table
	table.Header = &simpletable.Header{Cells: o.Headers}
	for _, row := range o.Body {
		var cells []*simpletable.Cell
		// Cells are built based on the number of table columns. That's why this for loop is necessary, so the columns are adjusted dinamically
		for i := range o.Headers {
			cells = append(
				cells,
				&simpletable.Cell{
					Text:  fmt.Sprintf("%s", row[i]),
					Align: simpletable.AlignLeft,
					Span:  1,
				},
			)

		}
		table.Body.Cells = append(table.Body.Cells, cells)
	}

	// Draws table
	table.SetStyle(simpletable.StyleCompactLite)
	if o.Verbosity > 1 {
		fmt.Println()
		table.Println()
		fmt.Println()
	}

	tableOut := fmt.Sprintf("%s\n\n", table.String())
	err = os.WriteFile(fullFilename, []byte(tableOut), 0644)
	if err != nil {
		panic(err)
	}

	fmt.Printf("[%s] Output written to [%s]\n", cyan(o.CallingModule), fullFilename)
}

func (o *OutputData) csvOutput() {

	path := filepath.Join(o.FilePath, "csv")
	err := os.MkdirAll(path, os.ModePerm)
	var fullFilename string
	if err != nil {
		log.Println(err)
	}
	if o.FullFilename == "" {
		fullFilename = filepath.Join(path, fmt.Sprintf("%s.txt", o.CallingModule))
	} else {
		fullFilename = o.FullFilename
	}
	var out []byte
	for i, header := range o.Headers {
		if i == len(o.Headers)-1 {
			if o.Verbosity > 1 {
				fmt.Println(header.Text)
			}
			out = append(out, []byte(fmt.Sprintf(header.Text))...)
		} else {
			if o.Verbosity > 1 {
				fmt.Printf("%s, ", header.Text)
			}
			out = append(out, []byte(fmt.Sprintf("%s,", header.Text))...)
		}
	}
	out = append(out, "\n"...)
	for _, row := range o.Body {
		for j, column := range row {
			if j == len(row)-1 {
				if o.Verbosity > 1 {
					fmt.Println(column)
				}
				out = append(out, []byte(fmt.Sprintln(column))...)
			} else {
				if o.Verbosity > 1 {
					fmt.Printf("%s, ", column)
				}
				out = append(out, []byte(fmt.Sprintf("%s,", column))...)

			}
		}

	}
	out = append(out, "\n"...)
	if o.Verbosity > 1 {
		fmt.Println()
	}
	err = os.WriteFile(fullFilename, out, 0644)
	if err != nil {
		panic(err)
	}
	fmt.Printf("[%s] Output written to [%s]\n", cyan(o.CallingModule), fullFilename)
}

func (o *OutputData) OutputSelector(Type string) {

	//fmt.Println()
	switch Type {
	case "table":
		o.tableOutput()
	case "csv":
		o.csvOutput()
	case "all":
		o.tableOutput()
		o.csvOutput()
	case "both":
		o.tableOutput()
		o.csvOutput()
	default:
		log.Fatal("Please select a valid output type (\"table\", \"csv\", \"all\")")
	}
	//fmt.Println()
}
