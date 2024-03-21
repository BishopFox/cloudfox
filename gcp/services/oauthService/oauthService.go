package oauthservice

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/oauth2/google"
)

// OAuthService struct definition
type OAuthService struct {
	// This struct can be expanded in the future if necessary.
}

// NewOAuthService creates a new instance of OAuthService.
func NewOAuthService() *OAuthService {
	return &OAuthService{}
}

// WhoAmI fetches the access token for the currently authenticated user
// and queries Google's OAuth2 API for details about the token.
func (s *OAuthService) WhoAmI() (string, error) {
	// Obtain the access token using the default token source.
	ctx := context.Background()
	ts, err := google.DefaultTokenSource(ctx, "")
	if err != nil {
		return "", fmt.Errorf("failed to obtain default token source: %v", err)
	}

	token, err := ts.Token()
	if err != nil {
		return "", fmt.Errorf("failed to get token from token source: %v", err)
	}

	// Query the tokeninfo endpoint with the access token.
	return queryTokenInfo(token.AccessToken)
}

// queryTokenInfo makes an HTTP GET request to the Google OAuth2 API tokeninfo endpoint.
func queryTokenInfo(accessToken string) (string, error) {
	url := fmt.Sprintf("https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s", accessToken)

	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("error making request to tokeninfo endpoint: %v", err)
	}
	defer resp.Body.Close()

	// Use io.ReadAll to read the response body.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading tokeninfo response body: %v", err)
	}

	return string(body), nil
}
