Function Get-AzKeyVaultSecretsREST
{

    # Author: Karl Fosaaen (@kfosaaen), NetSPI - 2020
    # Description: PowerShell function for enumerating available Key Vault Secrets using Azure Bearer tokens and the REST APIs.
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
    else{$subChoice = $SubscriptionId; $noLoop = 1}

    # Create data table to house results
    $TempTbl = New-Object System.Data.DataTable 
    $TempTbl.Columns.Add("SubscriptionName") | Out-Null
    $TempTbl.Columns.Add("KeyVault") | Out-Null
    $TempTbl.Columns.Add("SecretURL") | Out-Null
    $TempTbl.Columns.Add("SecretType") | Out-Null
    $TempTbl.Columns.Add("SecretValue") | Out-Null


    # Iterate through each subscription and list keys
    foreach($sub in $subChoice){

        # If subs are chosen from a list, grab the Id
        if($noLoop){}
        else{$SubscriptionId = $sub.subscriptionId}

        if($sub.displayName -ne $null){$subName = $sub.displayName; Write-Verbose "Gathering Key Vaults for the $subName subscription"}
        else{
            try {$subName = ((Invoke-WebRequest -Uri (-join ('https://management.azure.com/subscriptions/',$SubscriptionId,'?api-version=2019-11-01')) -Verbose:$false -Method GET -Headers @{ Authorization ="Bearer $managementToken"} -UseBasicParsing).Content | ConvertFrom-Json).displayName}
            catch{$subName = "undetermined"}
            Write-Verbose "Gathering storage accounts for the $subName subscription"
        }


        # Get List of Key Vaults
        $responseKeys = ((Invoke-WebRequest -Uri (-join ('https://management.azure.com/subscriptions/',$SubscriptionId,"/providers/Microsoft.KeyVault/vaults?api-version=2019-09-01")) -Verbose:$false -Method GET -Headers @{ Authorization ="Bearer $managementToken"} -UseBasicParsing).Content | ConvertFrom-Json)
        
        # Keeping the second method of vault enumeration as a backup option
        try{$keycanary = $responseKeys.value | ConvertFrom-Json -ErrorAction Stop}
        catch{$keycanary = $null}
        
        if($null -eq $keycanary){
            $responseKeys = ((Invoke-WebRequest -Uri (-join ('https://management.azure.com/subscriptions/',$SubscriptionId,"/resources?`$filter=resourceType eq 'Microsoft.KeyVault/vaults'&api-version=2019-09-01")) -Verbose:$false -Method GET -Headers @{ Authorization ="Bearer $managementToken"} -UseBasicParsing).Content | ConvertFrom-Json)
            if ($responseKeys.value -ne $null){$keyVaults = $responseKeys.value}
            else{$keyVaults = $null}
        }
        
        # Adjust for multiple vaults
        if ($responseKeys.nextLink -ne $null){
            while($responseKeys.nextLink){
                $keyVaults += $responseKeys.Value
                $responseKeys = ((Invoke-WebRequest -Uri $responseKeys.nextLink -Verbose:$false -Method GET -Headers @{ Authorization ="Bearer $managementToken"} -UseBasicParsing).Content | ConvertFrom-Json)
            }
        }
        else{}
        

        if($keyVaults -eq $null){Write-Verbose "`tNo Key Vaults enumerated for the $subName Subscription"}
        else{
            # Iterate through each available vault                        
            foreach ($vault in $keyVaults){
                $vaultName = $vault.name
            
                # Get Secrets
                try{
                    Write-Verbose "`tGetting Secrets for $vaultName"
                    #Instantiate running list that we can add to
                    $secretsListAll = @()
                    $secretsList = ((Invoke-WebRequest -Uri (-join ('https://',$vault.name,'.vault.azure.net/secrets?api-version=7.0')) -Verbose:$false -Method GET -Headers @{ Authorization ="Bearer $vaultToken"} -UseBasicParsing).content | ConvertFrom-Json)
                    
                    $secretsListAll += $secretsList.value
                    $nextSecrets = $secretsList.nextLink
                    #If there are more secrets, loop until we exhaust the vault
                    while($nextSecrets -ne $null)
                    {
                        $getNext = ((Invoke-WebRequest -Uri $nextSecrets -Verbose:$false -Method GET -Headers @{ Authorization ="Bearer $vaultToken"} -UseBasicParsing).Content | ConvertFrom-Json)
                        $nextSecrets = $getNext.nextLink
                        $secretsListAll += $getNext.value

                    }                   
        
                    
                    # Get Values for each Secret
                    $secretsListAll | ForEach-Object{
                        $secretType = $_.contentType
                        if($secretType -eq $null){$secretType = "No_Type_Set"}
                        Write-Verbose "`t`tGetting a $secretType from $vaultName"

                        $secretValue = ((Invoke-WebRequest -Uri (-join ($_.id,'?api-version=7.0')) -Verbose:$false -Method GET -Headers @{ Authorization ="Bearer $vaultToken"} -UseBasicParsing).content | ConvertFrom-Json)
                    
                        # Add the key to the table
                        $TempTbl.Rows.Add($subName, $vaultName, $secretValue.id, $secretType, $secretValue.value) | Out-Null

                    }
                }
                catch{Write-Verbose "`t`tCurrent token does not have secrets list permissions for this vault or secret"}        

            }
        }
        $responseKeys = $null
    }
    Write-Output $TempTbl
}