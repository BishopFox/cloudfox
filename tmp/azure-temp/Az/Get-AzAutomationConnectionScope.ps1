<# 
    File: Get-AzAutomationConnectionScope.ps1
    Author: Karl Fosaaen (@kfosaaen), NetSPI - 2022
    Description: PowerShell function for gathering available Subscriptions and Key Vaults for Automation Account identities.


To Do (features/improvements):
    - Convert runbook execution method to Test Pane for additional stealth
#>


Function Get-AzAutomationConnectionScope{

<#

    .SYNOPSIS
        Returns available Subscriptions and Key Vaults for available Automation Account identities.
    .DESCRIPTION
        This function will look at the Automation Account Connections and attached Identities for available subscriptions and Key Vaults. This will create a new runbook in any selected Automation Accounts, so keep that in mind for evasion.
    .PARAMETER Subscription
        Subscription to use.
    .PARAMETER All
        Test all Automation Accounts.
    .EXAMPLE
        PS C:\MicroBurst> Get-AzAutomationConnectionScope -Verbose
        VERBOSE: Logged In as testaccount@example.com
        VERBOSE: Getting list of Automation Accounts for the Consulting subscription
        VERBOSE: 	Starting on the testautomationaccount Automation Account
        VERBOSE: 		Getting list of Connections
        VERBOSE: 			AzureClassicRunAsConnection Connection queued for permissions enumeration
        VERBOSE: 			AzureRunAsConnection Connection queued for permissions enumeration
        VERBOSE: 			external Connection queued for permissions enumeration
        VERBOSE: 		Getting list of Managed Identities
        VERBOSE: 			No attached Managed Identities for the Automation Account
        VERBOSE: 		Uploading the FMvXyHAIDUpRxcO Runbook to the testautomationaccount Automation Account
        VERBOSE: 		Publishing the FMvXyHAIDUpRxcO Runbook in the testautomationaccount Automation Account
        VERBOSE: 		Executing the FMvXyHAIDUpRxcO Runbook in the testautomationaccount Automation Account
        VERBOSE: 			Waiting for the automation job to complete
        VERBOSE: 			5590c7f5-e06b-4f0d-a7d1-fab7ebf011df Job Completed
        VERBOSE: 			Parsing Job Output
        VERBOSE: 		Removing FMvXyHAIDUpRxcO runbook from testautomationaccount Automation Account
        VERBOSE: 		Removing local job file FMvXyHAIDUpRxcO.ps1
        VERBOSE: 	Enumeration completed for testautomationaccount Automation Account

        AutomationAccountName : testautomationaccount
        IdentityType          : Automation Account Connection - AzureRunAsConnection
        Subscription          : 
        SubscriptionID        : d4abhdas-12c3-abcd-a567-084asdf56as2
        TenantID              : 45a6b6ae-6844-a5db-abcd-ebdefg5a4d5e
        RoleDefinitionName    : Contributor
        Scope                 : /subscriptions/d4abhdas-12c3-abcd-a567-084asdf56as2
        Vaults                : 
                                VaultName      PermissionsToKeys PermissionsToSecrets PermissionsToCertificates
                                ---------      ----------------- -------------------- -------------------------
                                keys-private   get               get                  get                      
                                PasswordStore  get list          get list             get list       


    .LINK
    https://www.netspi.com/blog/technical/cloud-penetration-testing/    
#>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        HelpMessage="Subscription to use.")]
        [string]$Subscription = "",
        [Parameter(Mandatory=$false,
        HelpMessage="Test all Automation Accounts.")]
        [bool]$All = $false
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
        foreach ($sub in $subChoice) {Get-AzAutomationConnectionScope -Subscription $sub -All $All}
        break
    }

    Write-Verbose "Logged In as $accountName"
    
    Write-Verbose "Getting list of Automation Accounts for the $((get-azcontext).Subscription.Name) subscription"
    
    if($All -eq $true){
        $autoAccounts = Get-AzAutomationAccount
    }
    else{
        $autoAccounts = Get-AzAutomationAccount | out-gridview -Title "Select One or More Automation Accounts" -PassThru
    }
    
    $tempOutputObject = New-Object System.Data.DataTable 
    $tempOutputObject.Columns.Add("AutomationAccountName") | Out-Null
    $tempOutputObject.Columns.Add("IdentityType") | Out-Null
    $tempOutputObject.Columns.Add("Subscription") | Out-Null
    $tempOutputObject.Columns.Add("SubscriptionID") | Out-Null
    $tempOutputObject.Columns.Add("TenantID") | Out-Null
    $tempOutputObject.Columns.Add("RoleDefinitionName") | Out-Null
    $tempOutputObject.Columns.Add("Scope") | Out-Null
    $tempOutputObject.Columns.Add("Vaults") | Out-Null

    $autoAccounts | ForEach-Object{
    
        # Job Name for the Runbook
        $jobName = -join ((65..90) + (97..122) | Get-Random -Count 15 | % {[char]$_})

        Write-Verbose "`tStarting on the $($_.AutomationAccountName) Automation Account"

        "`$autoName = `"$($_.AutomationAccountName)`"" | Out-File -Append -FilePath "$pwd\$jobName.ps1" 

        Write-Verbose "`t`tGetting list of Connections"
        
        $autoConnections = Get-AzAutomationConnection -ResourceGroupName $_.ResourceGroupName -AutomationAccountName $_.AutomationAccountName

        # Create Connections login and list subscriptions for each connection
        if($autoConnections -ne $null){
            $autoConnections | ForEach-Object{
        
                "`$connectionName = `"$($_.Name)`"" | Out-File -Append -FilePath "$pwd\$jobName.ps1" 
                "`$servicePrincipalConnection = Get-AutomationConnection -Name `"`$connectionName`"" | Out-File -Append -FilePath "$pwd\$jobName.ps1" 
                "Disable-AzContextAutosave -Scope Process | out-null" | Out-File -Append -FilePath "$pwd\$jobName.ps1" 

                "`$azConnection = Connect-AzAccount -ServicePrincipal -Tenant `$servicePrincipalConnection.TenantID -ApplicationID `$servicePrincipalConnection.ApplicationID -CertificateThumbprint `$servicePrincipalConnection.CertificateThumbprint -WarningAction:SilentlyContinue" | Out-File -Append -FilePath "$pwd\$jobName.ps1" 
                "`$subscriptions = Get-AzSubscription | select Id,Name,TenantID" | Out-File -Append -FilePath "$pwd\$jobName.ps1" 
                "`$connectionEnterpriseAppID = (Get-AzADServicePrincipal -ApplicationId `$azConnection.Context.Account.Id).Id" | Out-File -Append -FilePath "$pwd\$jobName.ps1" 
                "`$subscriptions | ForEach-Object{Set-AzContext -Subscription `$_.Name | out-null;`$connectionRoles = Get-AzRoleAssignment -ObjectId `$connectionEnterpriseAppID;if(`$connectionRoles -eq `$null){`$connectionRoles = [PSCustomObject]@{RoleDefinitionName = 'Not Available';Scope = 'Not Available'}};`$vaultsList = @(); Get-AzKeyVault | ForEach-Object { `$currentVault = `$_.VaultName; Get-AzKeyVault -VaultName `$_.VaultName | ForEach-Object{ `$_.AccessPolicies | ForEach-Object {if(`$_.ObjectId -eq `$connectionEnterpriseAppID){`$vaultsList += `"{VaultName:'`$currentVault',PermissionsToKeys:'`$(`$_.PermissionsToKeys)',PermissionsToSecrets:'`$(`$_.PermissionsToSecrets)',PermissionsToCertificates:'`$(`$_.PermissionsToCertificates)'}`"}}}};Write-Output `"{AutomationAccountName:'`$autoName',IdentityType:'Automation Account Connection - `$connectionName',Subscription:'`$(`$_.Name)',SubscriptionID:'`$(`$_.Id)`',TenantID:'`$(`$_.TenantID)','RoleDefinitionName':'`$(`$connectionRoles.RoleDefinitionName)','Scope':'`$(`$connectionRoles.Scope)',Vaults:[`$(`$vaultsList -join ',')]}`"}" | Out-File -Append -FilePath "$pwd\$jobName.ps1" 
                Write-Verbose "`t`t`t$($_.Name) Connection queued for permissions enumeration"
            }
        }
        else{Write-Verbose "`t`t`tNo attached Connections for the Automation Account"}

        # Get Managed Identities (System-Assigned or User-Assigned)
        Write-Verbose "`t`tGetting list of Managed Identities"
        # Get a management API token and check the APIs for any usage of Managed Identities
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

        $accountDetails = (Invoke-WebRequest -Verbose:$false -Uri (-join ("https://management.azure.com/subscriptions/", $_.SubscriptionId, "/resourceGroups/", $_.ResourceGroupName, "/providers/Microsoft.Automation/automationAccounts/", $_.AutomationAccountName, "?api-version=2015-10-31")) -Headers @{Authorization="Bearer $mgmtToken"}).Content | ConvertFrom-Json

        $subID = $_.SubscriptionId
        $AARG = $_.ResourceGroupName

        
        if($accountDetails.identity.type -ne $null){
            if($accountDetails.identity.type -eq "systemassigned"){
                # Create Runbook Lines for AA - SA - MI
                "`n`nDisable-AzContextAutosave -Scope Process | out-null" | Out-File -Append -FilePath "$pwd\$jobName.ps1"
                "`$azConnection = Connect-AzAccount -Identity -WarningAction:SilentlyContinue" | Out-File -Append -FilePath "$pwd\$jobName.ps1" 
                "`$subscriptions = Get-AzSubscription | select Id,Name,TenantID" | Out-File -Append -FilePath "$pwd\$jobName.ps1" 
                "`$connectionEnterpriseAppID = (Get-AzADServicePrincipal -ObjectId $($accountDetails.identity.principalId)).Id" | Out-File -Append -FilePath "$pwd\$jobName.ps1" 
                "`$subscriptions | ForEach-Object{Set-AzContext -Subscription `$_.Name | out-null;`$connectionRoles = Get-AzRoleAssignment -ObjectId `$connectionEnterpriseAppID;if(`$connectionRoles -eq `$null){`$connectionRoles = [PSCustomObject]@{RoleDefinitionName = 'Not Available';Scope = 'Not Available'}};`$vaultsList = @(); Get-AzKeyVault | ForEach-Object { `$currentVault = `$_.VaultName; Get-AzKeyVault -VaultName `$_.VaultName | ForEach-Object{ `$_.AccessPolicies | ForEach-Object {if(`$_.ObjectId -eq `$connectionEnterpriseAppID){`$vaultsList += `"{VaultName:'`$currentVault',PermissionsToKeys:'`$(`$_.PermissionsToKeys)',PermissionsToSecrets:'`$(`$_.PermissionsToSecrets)',PermissionsToCertificates:'`$(`$_.PermissionsToCertificates)'}`"}}}};Write-Output `"{AutomationAccountName:'`$autoName',IdentityType:'System-Assigned',Subscription:'`$(`$_.Name)',SubscriptionID:'`$(`$_.Id)`',TenantID:'`$(`$_.TenantID)','RoleDefinitionName':'`$(`$connectionRoles.RoleDefinitionName)','Scope':'`$(`$connectionRoles.Scope)',Vaults:[`$(`$vaultsList -join ',')]}`"}" | Out-File -Append -FilePath "$pwd\$jobName.ps1" 
                Write-Verbose "`t`t`tSystem Assigned Managed Identity queued for permissions enumeration"
            }
            elseif($accountDetails.identity.type -eq "userassigned"){
                # Create Runbook Lines for AA - UA - MI

                # Cast the weird object to get-member to get the resource name
                $UANameList = (get-member -InputObject ($accountDetails.identity.userAssignedIdentities)) | where MemberType -EQ NoteProperty

                # Extract the Client IDs into an array
                $UAclientIDs = @()
                $UANameList | ForEach-Object {
                    $UAclientIDs += $accountDetails.identity.userAssignedIdentities.$($_.Name).ClientId
                }
            
                # For each Client ID, create an Auth request
                $UAclientIDs | ForEach-Object{
                    "`n`nDisable-AzContextAutosave -Scope Process | out-null" | Out-File -Append -FilePath "$pwd\$jobName.ps1"
                    "`$azConnection = Connect-AzAccount -Identity -AccountId $($_) -WarningAction:SilentlyContinue" | Out-File -Append -FilePath "$pwd\$jobName.ps1" 
                    "`$subscriptions = Get-AzSubscription | select Id,Name,TenantID" | Out-File -Append -FilePath "$pwd\$jobName.ps1" 
                    "`$connectionEnterpriseAppID = (Get-AzADServicePrincipal -ApplicationId `$azConnection.Context.Account.Id).Id" | Out-File -Append -FilePath "$pwd\$jobName.ps1" 
                    "`$subscriptions | ForEach-Object{Set-AzContext -Subscription `$_.Name | out-null;`$connectionRoles = Get-AzRoleAssignment -ObjectId `$connectionEnterpriseAppID;if(`$connectionRoles -eq `$null){`$connectionRoles = [PSCustomObject]@{RoleDefinitionName = 'Not Available';Scope = 'Not Available'}};`$vaultsList = @(); Get-AzKeyVault | ForEach-Object { `$currentVault = `$_.VaultName; Get-AzKeyVault -VaultName `$_.VaultName | ForEach-Object{ `$_.AccessPolicies | ForEach-Object {if(`$_.ObjectId -eq `$connectionEnterpriseAppID){`$vaultsList += `"{VaultName:'`$currentVault',PermissionsToKeys:'`$(`$_.PermissionsToKeys)',PermissionsToSecrets:'`$(`$_.PermissionsToSecrets)',PermissionsToCertificates:'`$(`$_.PermissionsToCertificates)'}`"}}}};Write-Output `"{AutomationAccountName:'`$autoName',IdentityType:'User-Assigned - $($_)',Subscription:'`$(`$_.Name)',SubscriptionID:'`$(`$_.Id)`',TenantID:'`$(`$_.TenantID)','RoleDefinitionName':'`$(`$connectionRoles.RoleDefinitionName)','Scope':'`$(`$connectionRoles.Scope)',Vaults:[`$(`$vaultsList -join ',')]}`"}" | Out-File -Append -FilePath "$pwd\$jobName.ps1" 

                    Write-Verbose "`t`t`tUser Assigned Managed Identity queued for permissions enumeration"
                }
            
            }
            elseif($accountDetails.identity.type -eq "systemassigned,userassigned"){
                # Create Runbook Lines for AA - SA and UA - MI
                "`n`nDisable-AzContextAutosave -Scope Process | out-null" | Out-File -Append -FilePath "$pwd\$jobName.ps1"
                "`$azConnection = Connect-AzAccount -Identity -WarningAction:SilentlyContinue" | Out-File -Append -FilePath "$pwd\$jobName.ps1" 
                "`$subscriptions = Get-AzSubscription | select Id,Name,TenantID" | Out-File -Append -FilePath "$pwd\$jobName.ps1" 
                "`$connectionEnterpriseAppID = (Get-AzADServicePrincipal -ObjectId $($accountDetails.identity.principalId)).Id" | Out-File -Append -FilePath "$pwd\$jobName.ps1" 
                "`$subscriptions | ForEach-Object{Set-AzContext -Subscription `$_.Name | out-null;`$connectionRoles = Get-AzRoleAssignment -ObjectId `$connectionEnterpriseAppID;if(`$connectionRoles -eq `$null){`$connectionRoles = [PSCustomObject]@{RoleDefinitionName = 'Not Available';Scope = 'Not Available'}};`$vaultsList = @(); Get-AzKeyVault | ForEach-Object { `$currentVault = `$_.VaultName; Get-AzKeyVault -VaultName `$_.VaultName | ForEach-Object{ `$_.AccessPolicies | ForEach-Object {if(`$_.ObjectId -eq `$connectionEnterpriseAppID){`$vaultsList += `"{VaultName:'`$currentVault',PermissionsToKeys:'`$(`$_.PermissionsToKeys)',PermissionsToSecrets:'`$(`$_.PermissionsToSecrets)',PermissionsToCertificates:'`$(`$_.PermissionsToCertificates)'}`"}}}};Write-Output `"{AutomationAccountName:'`$autoName',IdentityType:'System-Assigned',Subscription:'`$(`$_.Name)',SubscriptionID:'`$(`$_.Id)`',TenantID:'`$(`$_.TenantID)','RoleDefinitionName':'`$(`$connectionRoles.RoleDefinitionName)','Scope':'`$(`$connectionRoles.Scope)',Vaults:[`$(`$vaultsList -join ',')]}`"}" | Out-File -Append -FilePath "$pwd\$jobName.ps1" 
                Write-Verbose "`t`t`tSystem Assigned Managed Identity queued for permissions enumeration"

                # Cast the weird object to get-member to get the resource name
                $UANameList = (get-member -InputObject ($accountDetails.identity.userAssignedIdentities)) | where MemberType -EQ NoteProperty

                # Extract the Client IDs into an array
                $UAclientIDs = @()
                $UANameList | ForEach-Object {
                    $UAclientIDs += $accountDetails.identity.userAssignedIdentities.$($_.Name).ClientId
                }
            
                # For each Client ID, create an Auth request
                $UAclientIDs | ForEach-Object{
                    "`n`nDisable-AzContextAutosave -Scope Process | out-null" | Out-File -Append -FilePath "$pwd\$jobName.ps1"
                    "`$azConnection = Connect-AzAccount -Identity -AccountId $($_) -WarningAction:SilentlyContinue" | Out-File -Append -FilePath "$pwd\$jobName.ps1" 
                    "`$subscriptions = Get-AzSubscription | select Id,Name,TenantID" | Out-File -Append -FilePath "$pwd\$jobName.ps1" 
                    "`$connectionEnterpriseAppID = (Get-AzADServicePrincipal -ApplicationId `$azConnection.Context.Account.Id).Id" | Out-File -Append -FilePath "$pwd\$jobName.ps1" 
                    "`$subscriptions | ForEach-Object{Set-AzContext -Subscription `$_.Name | out-null;`$connectionRoles = Get-AzRoleAssignment -ObjectId `$connectionEnterpriseAppID;if(`$connectionRoles -eq `$null){`$connectionRoles = [PSCustomObject]@{RoleDefinitionName = 'Not Available';Scope = 'Not Available'}};`$vaultsList = @(); Get-AzKeyVault | ForEach-Object { `$currentVault = `$_.VaultName; Get-AzKeyVault -VaultName `$_.VaultName | ForEach-Object{ `$_.AccessPolicies | ForEach-Object {if(`$_.ObjectId -eq `$connectionEnterpriseAppID){`$vaultsList += `"{VaultName:'`$currentVault',PermissionsToKeys:'`$(`$_.PermissionsToKeys)',PermissionsToSecrets:'`$(`$_.PermissionsToSecrets)',PermissionsToCertificates:'`$(`$_.PermissionsToCertificates)'}`"}}}};Write-Output `"{AutomationAccountName:'`$autoName',IdentityType:'User-Assigned - $($_)',Subscription:'`$(`$_.Name)',SubscriptionID:'`$(`$_.Id)`',TenantID:'`$(`$_.TenantID)','RoleDefinitionName':'`$(`$connectionRoles.RoleDefinitionName)','Scope':'`$(`$connectionRoles.Scope)',Vaults:[`$(`$vaultsList -join ',')]}`"}" | Out-File -Append -FilePath "$pwd\$jobName.ps1" 

                    Write-Verbose "`t`t`tUser Assigned Managed Identity queued for permissions enumeration"
                }

            }
        }
        else{Write-Verbose "`t`t`tNo attached Managed Identities for the Automation Account"}

        if((gc "$pwd\$jobName.ps1"| Measure-Object -Line).Lines -gt 1){

            #-----------------------# Upload and Run the compiled Automation Runbook #-----------------------#
            Write-Verbose "`t`tUploading the $jobName Runbook to the $($_.AutomationAccountName) Automation Account"
            Import-AzAutomationRunbook -Path $pwd\$jobName.ps1 -ResourceGroup $_.ResourceGroupName -AutomationAccountName $_.AutomationAccountName -Type PowerShell -Name $jobName | Out-Null

            Write-Verbose "`t`tPublishing the $jobName Runbook in the $($_.AutomationAccountName) Automation Account"
            # publish the runbook
            Publish-AzAutomationRunbook -AutomationAccountName $_.AutomationAccountName -ResourceGroup $_.ResourceGroupName -Name $jobName | Out-Null

            Write-Verbose "`t`tExecuting the $jobName Runbook in the $($_.AutomationAccountName) Automation Account"
            # run the runbook and get the job id
            $jobID = Start-AzAutomationRunbook -Name $jobName -ResourceGroupName $_.ResourceGroupName -AutomationAccountName $_.AutomationAccountName | select JobId

            $jobstatus = Get-AzAutomationJob -AutomationAccountName $_.AutomationAccountName -ResourceGroupName $_.ResourceGroupName -Id $jobID.JobId | select Status

            # Wait for the job to complete
            Write-Verbose "`t`t`tWaiting for the automation job to complete"
            while($jobstatus.Status -ne "Completed"){
                $jobstatus = Get-AzAutomationJob -AutomationAccountName $_.AutomationAccountName -ResourceGroupName $_.ResourceGroupName -Id $jobID.JobId | select Status
                Start-Sleep -Seconds 3
            }    
    
            # Get the output and add it to the table                    
            try{
                # Get the output
                $jobOutput = (Get-AzAutomationJobOutput -ResourceGroupName $_.ResourceGroupName -AutomationAccountName $_.AutomationAccountName -Id $jobID.JobId | Get-AzAutomationJobOutputRecord | Select-Object -ExpandProperty Value)

                Write-Verbose "`t`t`t$($jobID.jobID) Job Completed"

                Write-Verbose "`t`t`tParsing Job Output"
                # Convert job output from JSON objects
                foreach($JSONline in $jobOutput.value){
                    $jsonObject = ($JSONline | ConvertFrom-Json)                
                    $tempOutputObject.Rows.Add($jsonObject.AutomationAccountName,$jsonObject.IdentityType,$jsonObject.Subscription,$jsonObject.SubscriptionID,$jsonObject.TenantID,$jsonObject.RoleDefinitionName,$jsonObject.Scope,($jsonObject.Vaults|Out-String)) | Out-Null
                }
            }
            catch {Write-Verbose "Collecting Job Output Failed - Review the Activity log for additional information"}

            Write-Verbose "`t`tRemoving $jobName runbook from $($_.AutomationAccountName) Automation Account"
            Remove-AzAutomationRunbook -AutomationAccountName $_.AutomationAccountName -Name $jobName -ResourceGroupName $_.ResourceGroupName -Force

            Write-Verbose "`t`tRemoving local job file $jobName.ps1"
        }
        else{Write-Verbose "`t`tNo available identities for the $($_.AutomationAccountName) Automation Account"; Write-Verbose "`t`tNo jobs were created for the account"}

        # Clean up local temp files
        Remove-Item -Path $pwd\$jobName.ps1 | Out-Null

        Write-Verbose "`tEnumeration completed for $($_.AutomationAccountName) Automation Account"
        
    }

    # Output the final datatable
    Write-Output $tempOutputObject

}