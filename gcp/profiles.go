package gcp

import (
	"fmt"
	"time"
	"github.com/fatih/color"
	"github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/kyokomi/emoji"
	"github.com/BishopFox/cloudfox/globals"
)

type ProfilesModule struct {
	// Filtering data
	Organizations []string
	Folders []string
	Projects []string
}

func (m *ProfilesModule) PrintProfiles(version string, outputFormat string, outputDirectory string, verbosity int) error {
	fmt.Printf("[%s][%s] Enumerating gcloud profiles...\n", color.CyanString(emoji.Sprintf(":fox:cloudfox %s :fox:", version)), color.CyanString(globals.GCP_WHOAMI_MODULE_NAME))
	tokens := gcp.ReadRefreshTokens()
	atokens := gcp.ReadAccessTokens()
	activeAccount := gcp.GetActiveAccount()

	tableHead := []string{"Account", "Default"}
	var tableBody [][]string
	for _, token := range tokens {
		if (activeAccount == token.Email) {
		tableBody = append(
			tableBody,
			[]string{
				token.Email,
				"Yes",
			})
		} else {
		tableBody = append(
			tableBody,
			[]string{
				token.Email,
				"-",
			})
		}
	}
	internal.PrintTableToScreen(tableHead, tableBody, false)
	tableHead = []string{"Account", "Validity"}
	tableBody = nil
	for _, token := range atokens {
		Exp, _ := time.Parse(time.RFC3339, token.TokenExpiry)
		var timeinfo string
		if Exp.After(time.Now()) {
			timeinfo = Exp.Format(time.RFC1123)
		} else {
			timeinfo = "EXPIRED"
		}
		tableBody = append(
			tableBody,
			[]string{
				token.AccountID,
				timeinfo,
			})
	}
	internal.PrintTableToScreen(tableHead, tableBody, false)
	return nil
}
