Function Get-AzStorageKeysREST
{

    # Author: Karl Fosaaen (@kfosaaen), NetSPI - 2020
    # Description: PowerShell function for enumerating available storage account keys from an Azure Bearer token.
    # Pipe to "Export-Csv -NoTypeInformation" for easier exporting
    # Use the SubscriptionId and token parameters to specify bearer tokens and subscriptions, handy for compromised bearer tokens from other services (CloudShell/AutomationAccounts)

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        HelpMessage="Subscription ID")]
        [string]$SubscriptionId,

        [Parameter(Mandatory=$true,
        HelpMessage="token")]
        [string]$token
    )


    # Sort out which subscription to list keys from
    if ($SubscriptionId -eq ''){

        # List all subscriptions for a tenant
        $subscriptions = ((Invoke-WebRequest -Uri ('https://management.azure.com/subscriptions?api-version=2019-11-01') -Verbose:$false -Method GET -Headers @{ Authorization ="Bearer $token"} -UseBasicParsing).content | ConvertFrom-Json).value

        # Select which subscriptions to dump info for
        $subChoice = $subscriptions | out-gridview -Title "Select One or More Subscriptions" -PassThru

        if($subChoice.count -eq 0){Write-Verbose 'No subscriptions selected, exiting'; break}

    }
    else{$subChoice = $SubscriptionId; $noLoop = 1}

    # Create data table to house results
    $TempTbl = New-Object System.Data.DataTable 
    $TempTbl.Columns.Add("StorageAccount") | Out-Null
    $TempTbl.Columns.Add("Key1") | Out-Null
    $TempTbl.Columns.Add("Key2") | Out-Null
    $TempTbl.Columns.Add("Key1-Permissions") | Out-Null
    $TempTbl.Columns.Add("Key2-Permissions") | Out-Null
    $TempTbl.Columns.Add("SubscriptionName") | Out-Null

    # Iterate through each subscription and list keys
    foreach($sub in $subChoice){
        
        # If subs are chosen from a list, grab the Id
        if($noLoop){}
        else{$SubscriptionId = $sub.subscriptionId}

        if($sub.displayName -ne $null){$subName = $sub.displayName; Write-Verbose "Gathering storage accounts for the $subName subscription"}
        else{
            $subName = ((Invoke-WebRequest -Uri (-join ('https://management.azure.com/subscriptions/',$SubscriptionId,'?api-version=2019-11-01')) -Verbose:$false -Method GET -Headers @{ Authorization ="Bearer $token"} -UseBasicParsing).Content | ConvertFrom-Json).displayName
            Write-Verbose "Gathering storage accounts for the $subName subscription"
        }

        # Get List of Storage Accounts and RGs
        $responseKeys = Invoke-WebRequest -Uri (-join ('https://management.azure.com/subscriptions/',$SubscriptionId,'/providers/Microsoft.Storage/storageAccounts?api-version=2019-06-01')) -Verbose:$false -Method GET -Headers @{ Authorization ="Bearer $token"} -UseBasicParsing
        $storageACCTS = ($responseKeys.Content | ConvertFrom-Json).value




        # Request access keys for all storage accounts
        $storageACCTS | ForEach-Object {

            # Do some split magic on the list of Storage accounts
            $accountName = $_.name
            Write-Verbose "`tGathering keys for the $accountName Storage Account"

            $split1 = ($_.id -split "resourceGroups/")
            $split2 = ($split1 -Split "/")
            $SARG = $split2[4]

            # https://docs.microsoft.com/en-us/rest/api/storagerp/storageaccounts/listkeys#
            $responseKeys = (Invoke-WebRequest -Uri (-join ('https://management.azure.com/subscriptions/',$SubscriptionId,'/resourceGroups/',$SARG,'/providers/Microsoft.Storage/storageAccounts/',$accountName,'/listKeys?api-version=2019-06-01')) -Verbose:$false -Method POST -Headers @{ Authorization ="Bearer $token"} -UseBasicParsing).content
            $keylist = ($responseKeys| ConvertFrom-Json).keys
        
            # Write the keys to the table
            $TempTbl.Rows.Add($accountName, $keylist[0].value, $keylist[1].value, $keylist[0].permissions, $keylist[1].permissions,$subName) | Out-Null

        }
        $SubscriptionId = $null
    }   
    Write-Output $TempTbl     
}