param
(
    [Parameter (Mandatory = $false)]
    [object] $WebhookData
)

import-module AzureAD

# Get Azure Run As Connection Name
$connectionName = "AzureRunAsConnection"

# Get the Service Principal connection details for the Connection name
$servicePrincipalConnection = Get-AutomationConnection -Name $connectionName         

# Logging in to Azure AD with Service Principal
$azureADConnection = Connect-AzureAD -TenantId $servicePrincipalConnection.TenantId `
    -ApplicationId $servicePrincipalConnection.ApplicationId `
    -CertificateThumbprint $servicePrincipalConnection.CertificateThumbprint

# Ensures you do not inherit an AzureRMContext in your runbook
Disable-AzureRmContextAutosave -Scope Process | out-null

# Logging in to Azure RM with Service Principal
$azureRMConnection = Connect-AzureRmAccount -ServicePrincipal -Tenant $servicePrincipalConnection.TenantID `
    -ApplicationID $servicePrincipalConnection.ApplicationID `
    -CertificateThumbprint $servicePrincipalConnection.CertificateThumbprint

$AzureContext = Select-AzureRmSubscription -SubscriptionId $servicePrincipalConnection.SubscriptionID

# Setup Password Object
$PasswordProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile

# Read Webhook data
if($WebhookData -ne $null){

    $BodyContent = ($WebhookData.RequestBody | ConvertFrom-Json)

    # Retrieve Username from Webhook request body
    if ($BodyContent.RequestBody.Username -ne $null){$UPN = ($BodyContent.RequestBody.Username)+'@'+$azureADConnection.TenantDomain}

    # Retrieve Password from Webhook request body    
    if ($BodyContent.RequestBody.Password -ne $null){$PasswordProfile.Password = $BodyContent.RequestBody.Password}
}
else{exit;}
    

# Add New AzureAD Account
New-AzureADUser -DisplayName $BodyContent.RequestBody.Username -PasswordProfile $PasswordProfile -UserPrincipalName $UPN -AccountEnabled $true -MailNickName $BodyContent.RequestBody.Username

# Add account to Owners Group
New-AzureRmRoleAssignment -SignInName $UPN -RoleDefinitionName Owner
