Function Get-AzKeyVaultKeysREST
{

    # Author: Karl Fosaaen (@kfosaaen), NetSPI - 2020
    # Description: PowerShell function for enumerating available Key Vault Keys using Azure Bearer tokens and the REST APIs.
    # Pipe to "Export-Csv -NoTypeInformation" for easier exporting
    # Use the SubscriptionId and token parameters to specify bearer tokens and subscriptions, handy for compromised bearer tokens from other services (CloudShell/AutomationAccounts/AppServices)

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        HelpMessage="Subscription ID")]
        [string]$SubscriptionId,

        [Parameter(Mandatory=$true,
        HelpMessage="The management scoped token")]
        [string]$managementToken,

        [Parameter(Mandatory=$true,
        HelpMessage="The KeyVault Scoped Token")]
        [string]$vaultToken
    )

    # Sort out which subscription to list keys from
    if ($SubscriptionId -eq ''){

        # List all subscriptions for a tenant
        $subscriptions = ((Invoke-WebRequest -Uri ('https://management.azure.com/subscriptions?api-version=2019-11-01') -Verbose:$false -Method GET -Headers @{ Authorization ="Bearer $managementToken"} -UseBasicParsing).content | ConvertFrom-Json).value

        # Select which subscriptions to dump info for
        $subChoice = $subscriptions | out-gridview -Title "Select One or More Subscriptions" -PassThru

        if($subChoice.count -eq 0){Write-Verbose 'No subscriptions selected, exiting'; break}

    }
    else{$subChoice = $SubscriptionId}

    # Create data table to house results
    $TempTbl = New-Object System.Data.DataTable 
    $TempTbl.Columns.Add("KeyVault") | Out-Null
    $TempTbl.Columns.Add("KeyURL") | Out-Null
    $TempTbl.Columns.Add("KeyValue") | Out-Null
    #$TempTbl.Columns.Add("Key1-Permissions") | Out-Null
    #$TempTbl.Columns.Add("Key2-Permissions") | Out-Null
    $TempTbl.Columns.Add("SubscriptionName") | Out-Null

    # Iterate through each subscription and list keys
    foreach($sub in $subChoice){
        
        if($SubscriptionId -ne ''){}
        else{$SubscriptionId = $sub.subscriptionId}

        if($sub.displayName -ne $null){$subName = $sub.displayName; Write-Verbose "Gathering Key Vaults for the $subName subscription"}
        else{
            $subName = ((Invoke-WebRequest -Uri (-join ('https://management.azure.com/subscriptions/',$SubscriptionId,'?api-version=2019-11-01')) -Verbose:$false -Method GET -Headers @{ Authorization ="Bearer $managementToken"} -UseBasicParsing).Content | ConvertFrom-Json).displayName
            Write-Verbose "Gathering storage accounts for the $subName subscription"
        }


        # Get List of Key Vaults and RGs
        $responseKeys = Invoke-WebRequest -Uri (-join ('https://management.azure.com/subscriptions/',$SubscriptionId,"/resources?`$filter=resourceType eq 'Microsoft.KeyVault/vaults'&api-version=2019-09-01")) -Verbose:$false -Method GET -Headers @{ Authorization ="Bearer $managementToken"} -UseBasicParsing
        
        $keyVaults = ($responseKeys.Content | ConvertFrom-Json).value
            
        # If there are Vaults, get the Keys
        if ($keyVaults -ne $null){
            foreach ($vault in $keyVaults){
                $vaultName = $vault.name
            
                # Get list of Keys
                try{
                    Write-Verbose "`tGetting Keys for $vaultName"
                    
                    #Instantiate running list that we can add to
                    $keyListAll = @()

                    $keyList = ((Invoke-WebRequest -Uri (-join ('https://',$vault.name,'.vault.azure.net/keys?api-version=7.0')) -Verbose:$false -Method GET -Headers @{ Authorization ="Bearer $vaultToken"} -UseBasicParsing).content | ConvertFrom-Json)
                    
                    $keyListAll += $keyList.value

                    $nextKeys = $keyList.nextLink
                    #If there are more keys, loop until we exhaust the vault
                    while($nextKeys -ne $null){
                        $getNext = ((Invoke-WebRequest -Uri $nextKeys -Verbose:$false -Method GET -Headers @{ Authorization ="Bearer $vaultToken"} -UseBasicParsing).Content | ConvertFrom-Json)
                        $nextKeys = $getNext.nextLink
                        $keyListAll += $getNext.value
                    }

                     # Get individual keys from vault
                    $keyListAll | ForEach-Object{

                        $keyValue = ((Invoke-WebRequest -Uri (-join ($_.kid,'?api-version=7.0')) -Verbose:$false -Method GET -Headers @{ Authorization ="Bearer $vaultToken"} -UseBasicParsing).content | ConvertFrom-Json)
                        $keyValue.key | ForEach-Object{
                        
                            $subKeyValue = (Invoke-WebRequest -Uri (-join ($_.kid,'/?api-version=7.0')) -Verbose:$false -Method GET -Headers @{ Authorization ="Bearer $vaultToken"} -UseBasicParsing).content | ConvertFrom-Json
                        
                            # Add the key to the table
                            $TempTbl.Rows.Add($vaultName, $subKeyValue.key.kid, $subKeyValue.key.n, $subName) | Out-Null

                        }
                    
                    }
                }
                catch{Write-Verbose "`t`tCurrent token does not have key list permissions for this vault, or the token was not scoped for vault.azure.net"}        

            }   
        }
    }
    Write-Output $TempTbl
}