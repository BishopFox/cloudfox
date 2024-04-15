package oauthservice

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"golang.org/x/oauth2/google"
)

// Principal struct modified to map JSON response fields.
type Principal struct {
	Email string `json:"email"`
	Scope []string
}

// Temporary struct to match the JSON structure.
type tokenInfoResponse struct {
	Email string `json:"email"`
	Scope string `json:"scope"` // Keep as string to match JSON.
}

// OAuthService struct definition (unchanged)
type OAuthService struct {
	// This struct can be expanded in the future if necessary.
}

// NewOAuthService creates a new instance of OAuthService.
func NewOAuthService() *OAuthService {
	return &OAuthService{}
}

// WhoAmI function returns the Principal struct showing the email and scope of the currently authenticated user by generating an oauth token
func (s *OAuthService) WhoAmI() (*Principal, error) {
	ctx := context.Background()
	ts, err := google.DefaultTokenSource(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("failed to obtain default token source: %v", err)
	}

	token, err := ts.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to get token from token source: %v", err)
	}

	tokenInfo, err := queryTokenInfo(token.AccessToken)
	if err != nil {
		return nil, fmt.Errorf(fmt.Sprintf("failed to retrieve metada of the token with error: %s", err.Error()))
	}
	// Split the scope string into a slice of strings.
	scopes := strings.Split(tokenInfo.Scope, " ")

	return &Principal{
		Email: tokenInfo.Email,
		Scope: scopes,
	}, nil
}

// queryTokenInfo function modified to return (*Principal, error).
func queryTokenInfo(accessToken string) (*tokenInfoResponse, error) {
	url := fmt.Sprintf("https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s", accessToken)

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("error making request to tokeninfo endpoint: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading tokeninfo response body: %v", err)
	}

	var response tokenInfoResponse
	// Unmarshal the JSON response body into the Principal struct.
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("error unmarshalling tokeninfo response body: %v", err)
	}

	return &response, nil
}
