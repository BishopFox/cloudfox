package gcp

import (
	"log"
	"database/sql"
	"fmt"
	_ "modernc.org/sqlite"

	//"golang.org/x/oauth2"
	//"golang.org/x/oauth2/google"
	//"google.golang.org/api/option"
	//goauth2 "google.golang.org/api/oauth2/v2"
	//"google.golang.org/api/cloudresourcemanager/v1"
	//"google.golang.org/api/cloudasset/v1p1beta1"
	"os"
	"os/user"
	"gopkg.in/ini.v1"
	"path/filepath"

	"github.com/BishopFox/cloudfox/globals"
	//"github.com/aws/smithy-go/ptr"
)

type RefreshToken struct {
	Email string
	JSON string
}
// CREATE TABLE IF NOT EXISTS "access_tokens" (account_id TEXT PRIMARY KEY, access_token TEXT, token_expiry TIMESTAMP, rapt_token TEXT, id_token TEXT);

type Token struct {
	AccountID string
	AccessToken string
	TokenExpiry string
	RaptToken string
	IdentityToken string
}

func GetActiveAccount() string {
	configPath := GetDefaultConfigPath()
    cfg, err := ini.Load(configPath)
    if err != nil {
        fmt.Printf("Fail to read %s: %v", configPath, err)
        os.Exit(1)
    }

    account := cfg.Section("core").Key("account").String()
	return account
}
func ReadAccessTokens() []Token{
	db, err := sql.Open("sqlite", GetAccessTokensDBPath())

	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query("SELECT account_id, access_token, token_expiry, id_token from access_tokens;")
	if err != nil {
		log.Fatal(err)
	}

	defer rows.Close()
	var tokens []Token
	for rows.Next() {
		var (
			AccountID string
			AccessToken string
			TokenExpiry string
			IdentityToken string
		)

		err = rows.Scan(&AccountID, &AccessToken, &TokenExpiry, &IdentityToken)

		if err != nil {
			log.Fatal(err)
		}
		tokens = append(
			tokens,
			Token{
				AccountID: AccountID,
				AccessToken: AccessToken,
				TokenExpiry: TokenExpiry,
				IdentityToken: IdentityToken,
			})
	}
	return tokens
}

func ReadRefreshTokens() []RefreshToken{
	db, err := sql.Open("sqlite", GetRefreshTokensDBPath())

	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query("SELECT * from credentials;")
	if err != nil {
		log.Fatal(err)
	}

	defer rows.Close()
	var tokens []RefreshToken
	for rows.Next() {
		var accountName string
		var JSON string

		err = rows.Scan(&accountName, &JSON)

		if err != nil {
			log.Fatal(err)
		}
		tokens = append(tokens, RefreshToken{Email: accountName, JSON: JSON})
	}
	return tokens
}


// This function returns the path to gcloud credentials
func GetRefreshTokensDBPath() string {
	user, _ := user.Current()
	credspath := filepath.Join(user.HomeDir, globals.GCP_GCLOUD_REFRESH_TOKENS_DB_PATH)
	if _, err := os.Stat(credspath); os.IsNotExist(err) {
		log.Fatalf("[-] Failed to read gcloud credentials")
	}
	return credspath
}
func GetAccessTokensDBPath() string {
	user, _ := user.Current()
	credspath := filepath.Join(user.HomeDir, globals.GCP_GCLOUD_ACCESS_TOKENS_DB_PATH)
	if _, err := os.Stat(credspath); os.IsNotExist(err) {
		log.Fatalf("[-] Failed to read gcloud credentials")
	}
	return credspath
}

func GetDefaultConfigPath() string {
	user, _ := user.Current()
	credspath := filepath.Join(user.HomeDir, globals.GCP_GCLOUD_DEFAULT_CONFIG_PATH)
	if _, err := os.Stat(credspath); os.IsNotExist(err) {
		log.Fatalf("[-] Failed to read gcloud default config")
	}
	return credspath
}
