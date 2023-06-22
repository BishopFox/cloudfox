package gcp

import (
	"log"
	"database/sql"
	"crypto/sha256"
	"fmt"
	"encoding/json"
	_ "modernc.org/sqlite"

	//"golang.org/x/oauth2"
	//"golang.org/x/oauth2/google"
	//"google.golang.org/api/option"
	//goauth2 "google.golang.org/api/oauth2/v2"
	//"google.golang.org/api/cloudresourcemanager/v1"
	//"google.golang.org/api/cloudasset/v1p1beta1"
	"os"
	"io/ioutil"
	"os/user"
	"gopkg.in/ini.v1"
	"path/filepath"

	"github.com/BishopFox/cloudfox/globals"
	//"github.com/aws/smithy-go/ptr"
)

type ApplicationCredential struct {
	ClientID string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RefreshToken string `json:"refresh_token"`
	Type string `json:"authorized_user"`
}

type RefreshToken struct {
	Email string
	JSON string
}
// CREATE TABLE IF NOT EXISTS "access_tokens" (account_id TEXT PRIMARY KEY, access_token TEXT, token_expiry TIMESTAMP, rapt_token TEXT, id_token TEXT);

type Token struct {
	AccountID string
	AccessToken string
	TokenExpiry string
	RaptToken sql.NullString
	IdentityToken string
}

/* The active gcloud CLI profile is stored in INI configuration file */
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

/* Access tokens are stored in the access_tokens.db database, along with the user ID
*/
func ReadAccessTokens() []Token{
	db, err := sql.Open("sqlite", GetAccessTokensDBPath())

	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query("SELECT * from access_tokens;")
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
			RaptToken sql.NullString
			IdentityToken string
		)

		err = rows.Scan(&AccountID, &AccessToken, &TokenExpiry, &RaptToken, &IdentityToken)

		if err != nil {
			log.Fatal(err)
		}
		tokens = append(
			tokens,
			Token{
				AccountID: AccountID,
				AccessToken: AccessToken,
				TokenExpiry: TokenExpiry,
				RaptToken: RaptToken,
				IdentityToken: IdentityToken,
			})
	}
	return tokens
}
/* The application default access tokens are not stored the same way as the user ones
The access_tokens.db does not contain the associated user id, but the sha256 digest of the refresh token
stored in the application default json file
*/
func GetDefaultApplicationHash() string {
	var (
		err error
		jsonFile string
	)

	jsonFile, err = GetApplicationDefaultPath()
	if (err != nil) {
		return "invalid"
	}
	
	var applicationcred ApplicationCredential
	byteValue, _ := ioutil.ReadFile(jsonFile)
	json.Unmarshal(byteValue, &applicationcred)
	sum := sha256.Sum256([]byte(applicationcred.RefreshToken))
	return fmt.Sprintf("%x", sum)
}

/* The refresh tokens are stored in a separate database called credentials.db
*/
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
		log.Fatalf("[-] Failed to read gcloud refresh tokens database")
	}
	return credspath
}
func GetAccessTokensDBPath() string {
	user, _ := user.Current()
	credspath := filepath.Join(user.HomeDir, globals.GCP_GCLOUD_ACCESS_TOKENS_DB_PATH)
	if _, err := os.Stat(credspath); os.IsNotExist(err) {
		log.Fatalf("[-] Failed to read gcloud access tokens database")
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

func GetApplicationDefaultPath() (string, error) {
	user, _ := user.Current()
	credspath := filepath.Join(user.HomeDir, globals.GCP_GCLOUD_APPLICATION_DEFAULT_PATH)
	var err error
	if _, err := os.Stat(credspath); os.IsNotExist(err) {
		log.Printf("[-] Default application credentials not set")
	}
	return credspath, err
}
