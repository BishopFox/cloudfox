<#
    File: Invoke-AzVMCommandREST.ps1
    Original Author: @passthehashbrowns
    Updated Version Author: Karl Fosaaen (@kfosaaen), NetSPI - 2023
    Description: PowerShell functions for running commands on VMs (Linux and Windows) via the VM Run Command APIs.

    2023 Updates - Now supports multiple subscriptions and multiple VMs in one function call. Also supports both Windows and Linux VMs.
#>



function Invoke-AzVMCommandREST{

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        HelpMessage="Subscription ID")]
        [string]$SubscriptionId,

        [Parameter(Mandatory=$false,
        HelpMessage="The management scoped token")]
        [string]$managementToken,

        [Parameter(Mandatory=$false,
        HelpMessage="The VM to target")]
        [string]$targetVMArg,

        [Parameter(Mandatory=$true,
        HelpMessage="Command to execute")]
        [string]$commandToExecute
    )

    if($managementToken -eq ""){
        Write-Output "No token provided, attempting to use Az PowerShell context"
        $AccessToken = Get-AzAccessToken
        if ($AccessToken.Token -is [System.Security.SecureString]) {
            $ssPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($AccessToken.Token)
            try {
                $managementToken = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ssPtr)
            } finally {
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ssPtr)
            }
        } else {
            $managementToken = $AccessToken.Token
        }
        
        if($managementToken -eq $null){
            Write-Output "Unable to use Az PowerShell module for a token, attempting IMDS token"

            try{
                $response = Invoke-WebRequest -Uri 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' -Verbose:$false -Method GET -Headers @{Metadata="true"} -UseBasicParsing
                $content = $response.Content | ConvertFrom-Json
                $managementToken = $content.access_token
            }
            catch{Write-Output "Failed to get a local token, please provide a Management scoped token"; break}
        }
    }
    
    if ($SubscriptionId -eq ''){

        # List all subscriptions for a tenant
        $subscriptions = ((Invoke-WebRequest -Uri ('https://management.azure.com/subscriptions?api-version=2019-11-01') -Verbose:$false -Method GET -Headers @{ Authorization ="Bearer $managementToken"} -UseBasicParsing).content | ConvertFrom-Json).value

        # Select which subscriptions to dump info for
        $subChoice = $subscriptions | out-gridview -Title "Select One or More Subscriptions" -PassThru

        if($subChoice.count -eq 0){Write-Verbose 'No subscriptions selected, exiting'; break}

        Foreach ($sub in $subChoice){Invoke-AzVMCommandREST -managementToken $managementToken -commandToExecute $commandToExecute -targetVMArg $targetVMArg -SubscriptionId $subChoice.subscriptionId}
        break
    }
    
    try{

        # Get a list of VMs
        $virtualMachines = ((Invoke-WebRequest -Uri (-join ('https://management.azure.com/subscriptions/',$SubscriptionId,"/providers/Microsoft.Compute/virtualMachines?api-version=2020-06-01")) -Verbose:$false -Method GET -Headers @{ Authorization ="Bearer $managementToken"} -UseBasicParsing).Content) | ConvertFrom-Json
    
        $targetVMs = $virtualMachines.value | out-gridview -Title "Select target VM" -PassThru

        # Iterate the VMs and run the command
        foreach($vmObject in $targetVMs){
            $vmName = $vmObject.name
            $resourceGroup = $vmObject.id.split("/")[4]
            $location = $vmObject.Location

            $vmInfo = (Invoke-WebRequest -Uri (-join ('https://management.azure.com/subscriptions/',$SubscriptionId,"/resourceGroups/",$resourceGroup,"/providers/Microsoft.Compute/virtualMachines/",$vmName,"?api-version=2022-11-01")) -Verbose:$false -Headers @{ Authorization ="Bearer $managementToken"} -UseBasicParsing) | ConvertFrom-Json

            $osType = $vmInfo.properties.storageProfile.osDisk.osType
            
            if($osType -eq "Windows"){
                $commandBody = '{"commandId":"RunPowershellScript","script":["' + $commandToExecute + '"],"parameters":[]}'
            }
            else{$commandBody = '{"commandId":"RunShellScript","script":["' + $commandToExecute + '"],"parameters":[]}'}

            Write-Output "Executing command on target VM: $vmName"

            $fullResponse = (Invoke-WebRequest -Uri (-join ('https://management.azure.com/subscriptions/',$SubscriptionId,"/resourceGroups/",$resourceGroup,"/providers/Microsoft.Compute/virtualMachines/",$vmName,"/runCommand?api-version=2020-06-01")) -Verbose:$false -ContentType "application/json" -Method POST -Body $commandBody -Headers @{ Authorization ="Bearer $managementToken"} -UseBasicParsing)
    
            # Wait for command to complete
            while ((Invoke-WebRequest -Verbose:$false -Uri $fullResponse.Headers.Location -Headers @{ Authorization ="Bearer $managementToken"} -UseBasicParsing).RawContentLength -lt 1){
        
                Write-Output "`tWaiting for the command to complete, sleeping 5 seconds..."
                Start-Sleep 5
            
            }

            (Invoke-WebRequest -Verbose:$false -Uri $fullResponse.Headers.Location -Headers @{ Authorization ="Bearer $managementToken"} -UseBasicParsing).Content | ConvertFrom-Json | ForEach-Object{
                    if(($_.value.message).length -gt 0){Write-Host "Command Output: $($_.value.message)"}
                }
        }
    }
    catch{Write-Output "Something went wrong: $_"}
}





    
