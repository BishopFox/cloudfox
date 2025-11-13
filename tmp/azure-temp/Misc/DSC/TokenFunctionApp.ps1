<#
    File: TokenFunctionApp.ps1
    Author: Jake Karnes (@jakekarnes42), NetSPI - 2021
    Description: A PowerShell function app which recieves a managed identity bearer token and checks its privileges
#>

using namespace System.Net

# Input bindings are passed in via param block.
param($Request, $TriggerMetadata)

# Write to the Azure Functions log stream.
Write-Host "PowerShell HTTP trigger function processed a request. Incoming JSON contents"
$Request.Body

#Extract the bearer token
$managementToken = $Request.Body.access_token
Write-Host "Access token"
$managementToken

#Grab our identity's principal ID from our JWT
$tokenPayload = $managementToken.split('.')[1]
while($tokenPayload.Length % 4){$tokenPayload += "="}
$tokenJson = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($tokenPayload)) | ConvertFrom-Json
$currentPrincipalID = $tokenJson.oid
Write-Host "Principal ID"
$currentPrincipalID 

#Extract the name of the VM and the subscription id from the xms_mirid value via a Regex
$vminfo = $tokenJson.xms_mirid
Write-Host $vminfo
$vmparts = [regex]::match($vminfo,'\/subscriptions\/([a-f\d]{8}\-[a-f\d]{4}\-[a-f\d]{4}\-[a-f\d]{4}\-[a-f\d]{12})\/.+\/(.+)').Groups
$SubscriptionID = $vmparts[1].Value
$VMName = $vmparts[2].Value
Write-Host "Subscription ID"
$SubscriptionID
Write-Host "VM Name"
$VMName

#Fetch role name/ID info
$roleDefinitions = ((Invoke-WebRequest -Uri (-join('https://management.azure.com/subscriptions/',$SubscriptionID,'/providers/Microsoft.Authorization/roleDefinitions?api-version=2015-07-01')) -Verbose:$false -Method GET -Headers @{ Authorization ="Bearer $managementToken"} -UseBasicParsing).Content | ConvertFrom-Json).value
#Get all assignments in the subscription
$rbacAssignments = (((Invoke-WebRequest -Uri (-join ('https://management.azure.com/subscriptions/',$SubscriptionID,"/providers/Microsoft.Authorization/roleAssignments?api-version=2015-07-01")) -Verbose:$false -Method GET -Headers @{ Authorization ="Bearer $managementToken"} -UseBasicParsing).Content) | ConvertFrom-Json).value
foreach($def in $rbacAssignments.properties){
    $roleDefID = $def.roleDefinitionId.split("/")[6]
    #Search through our role definitions and find the role name
    $roleName = ($roleDefinitions | foreach-object {if ($_.name -eq $roleDefID){$_.properties.RoleName}})
    if($roleName){
        if($def.principalId -eq $currentPrincipalID){
            Write-Output (-join ("Current identity has permission ", $roleName, " on scope ", $def.scope))
        }
    }
}

# Associate values to output bindings by calling 'Push-OutputBinding'.
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
    StatusCode = [HttpStatusCode]::OK
    Body = "Success"
})
