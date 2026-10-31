package azure

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/authorization/mgmt/authorization"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

type staticTokenCredential struct {
	token string
	err   error
	scope string
}

func TestAzureRBACRowsIncludeDirectAndGroupAssignments(t *testing.T) {
	var assignments []authorization.RoleAssignment
	err := json.Unmarshal([]byte(`[
		{"properties":{"principalId":"caller-id","roleDefinitionId":"/providers/Microsoft.Authorization/roleDefinitions/reader-id","scope":"/subscriptions/sub-id"}},
		{"properties":{"principalId":"group-id","roleDefinitionId":"/providers/Microsoft.Authorization/roleDefinitions/owner-id","scope":"/subscriptions/sub-id/resourceGroups/example"}},
		{"properties":{"principalId":"other-id","roleDefinitionId":"/providers/Microsoft.Authorization/roleDefinitions/ignored-id","scope":"/subscriptions/sub-id"}}
	]`), &assignments)
	if err != nil {
		t.Fatalf("unmarshal role assignments: %v", err)
	}

	principals := map[string]rbacPrincipal{
		"caller-id": {ID: "caller-id", Name: "analyst@example.com", AssignmentType: "Direct"},
		"group-id":  {ID: "group-id", Name: "Cloud Operators", AssignmentType: "Group"},
	}
	roleNames := map[string]string{"reader-id": "Reader", "owner-id": "Owner"}
	rows := azureRBACRowsForSubscription("tenant-id", "sub-id", "Production", principals, roleNames, assignments)

	if len(rows) != 2 {
		t.Fatalf("got %d relevant role assignments, want 2: %+v", len(rows), rows)
	}
	if rows[0][5] != "Direct" || rows[0][6] != "Reader" {
		t.Fatalf("unexpected direct assignment row: %+v", rows[0])
	}
	if rows[1][4] != "Cloud Operators" || rows[1][5] != "Group" || rows[1][6] != "Owner" {
		t.Fatalf("unexpected group assignment row: %+v", rows[1])
	}
}

func (c *staticTokenCredential) GetToken(_ context.Context, options policy.TokenRequestOptions) (azcore.AccessToken, error) {
	if len(options.Scopes) > 0 {
		c.scope = options.Scopes[0]
	}
	return azcore.AccessToken{Token: c.token, ExpiresOn: time.Now().Add(time.Hour)}, c.err
}

func unsignedTestToken(payload string) string {
	return "header." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
}

func TestGetCallerEntraRoles(t *testing.T) {
	var authorization string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization = r.Header.Get("Authorization")
		if r.URL.Path != "/directoryObjects/caller-object-id/transitiveMemberOf" {
			t.Fatalf("unexpected Graph path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"value":[{"@odata.type":"#Microsoft.DirectoryServices.Group","id":"group-id","displayName":"Readers"},{"@odata.type":"#Microsoft.DirectoryServices.DirectoryRole","id":"role-id","displayName":"Global Reader","description":"Read everything"}]}`))
	}))
	defer server.Close()

	originalBaseURL, originalHTTPClient := graphBaseURL, graphHTTPClient
	graphBaseURL, graphHTTPClient = server.URL, server.Client()
	t.Cleanup(func() {
		graphBaseURL, graphHTTPClient = originalBaseURL, originalHTTPClient
	})

	cred := &staticTokenCredential{token: unsignedTestToken(`{"oid":"caller-object-id","preferred_username":"analyst@example.com"}`)}
	claims, roles, err := getCallerEntraRoles(context.Background(), cred)
	if err != nil {
		t.Fatalf("getCallerEntraRoles returned an error: %v", err)
	}
	if cred.scope != microsoftGraphScope {
		t.Fatalf("requested scope %q, want %q", cred.scope, microsoftGraphScope)
	}
	if authorization != "Bearer "+cred.token {
		t.Fatalf("authorization header %q does not contain the Graph token", authorization)
	}
	if claims.ObjectID != "caller-object-id" || len(roles) != 1 || roles[0].DisplayName != "Global Reader" {
		t.Fatalf("unexpected claims or roles: claims=%+v roles=%+v", claims, roles)
	}
}

func TestDirectoryMembershipTypeSupportsGraphAndLegacyNames(t *testing.T) {
	tests := map[string]string{
		"#microsoft.graph.directoryRole":                  "Directory Role",
		"#Microsoft.DirectoryServices.DirectoryRole":      "Directory Role",
		"#microsoft.graph.group":                          "Group",
		"#Microsoft.DirectoryServices.Group":              "Group",
		"#Microsoft.DirectoryServices.AdministrativeUnit": "",
	}
	for odataType, want := range tests {
		if got := directoryMembershipType(odataType); got != want {
			t.Errorf("directoryMembershipType(%q) = %q, want %q", odataType, got, want)
		}
	}
}

func TestGetCallerEntraRolesGraphError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"Authorization_RequestDenied","message":"Insufficient privileges"}}`))
	}))
	defer server.Close()

	originalBaseURL, originalHTTPClient := graphBaseURL, graphHTTPClient
	graphBaseURL, graphHTTPClient = server.URL, server.Client()
	t.Cleanup(func() {
		graphBaseURL, graphHTTPClient = originalBaseURL, originalHTTPClient
	})

	cred := &staticTokenCredential{token: unsignedTestToken(`{"oid":"caller-object-id"}`)}
	_, _, err := getCallerEntraRoles(context.Background(), cred)
	if err == nil || !strings.Contains(err.Error(), "Insufficient privileges") {
		t.Fatalf("expected a descriptive Graph permission error, got %v", err)
	}
}
