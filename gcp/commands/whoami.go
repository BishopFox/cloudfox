package commands

import (
	"fmt"

	OAuthService "github.com/BishopFox/cloudfox/gcp/services/oauthService"
	"github.com/BishopFox/cloudfox/globals"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/spf13/cobra"
)

var GCPWhoAmICommand = &cobra.Command{
	Use:   globals.GCP_WHOAMI_MODULE_NAME,
	Short: "Display the email address of the GCP authenticated user",
	Args:  cobra.NoArgs,
	Run:   runGCPWhoAmICommand,
}

func runGCPWhoAmICommand(cmd *cobra.Command, args []string) {
	logger := internal.NewLogger()

	// Initialize the OAuthService
	oauthService := OAuthService.NewOAuthService()

	// Call the WhoAmI function
	principal, err := oauthService.WhoAmI()
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error retrieving token info: %v", err), globals.GCP_WHOAMI_MODULE_NAME)
		return
	}

	logger.InfoM(fmt.Sprintf("authenticated user email: %s", principal.Email), globals.GCP_WHOAMI_MODULE_NAME)
}
