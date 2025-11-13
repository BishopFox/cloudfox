<#
    File: Get-AzBatchAccountData.ps1
    Author: Karl Fosaaen (@kfosaaen), NetSPI - 2023
    Description: PowerShell functions for dumping Azure Batch commands, environmental variables, etc.
#>

function Get-AzBatchAccountData{

<#
    .SYNOPSIS
        PowerShell function for dumping information from Azure Batch Accounts.
	.DESCRIPTION
        The function will dump available information for an Azure Batch Account. This includes environmental variables, tasks, jobs, etc.
    .PARAMETER Subscription
        Subscription to use.
    .PARAMETER folder
        The folder to output to.
    .EXAMPLE
        PS C:\> Get-AzBatchAccountData -folder BatchOutput -Verbose
		VERBOSE: Logged In as kfosaaen@example.com
        VERBOSE: Dumping Batch Accounts from the "Sample Subscription" Subscription
        VERBOSE: 	1 Batch Account(s) Enumerated
        VERBOSE: 		Attempting to dump data from the testspi account
        VERBOSE: 			Attempting to dump keys
        VERBOSE: 			1 Pool(s) Enumerated
        VERBOSE: 				Attempting to dump pool data
        VERBOSE: 			13 Job(s) Enumerated
        VERBOSE: 				Attempting to dump job data
        VERBOSE: 		Completed dumping of the testspi account

#>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        HelpMessage="Subscription to use.")]
        [string]$Subscription = "",
        
        [Parameter(Mandatory=$false,
        HelpMessage="Folder to output to.")]
        [string]$folder = ""
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
        foreach ($sub in $subChoice) {Get-AzBatchAccountData -Subscription $sub -folder $folder}
        return
    }

    Write-Verbose "Logged In as $accountName"
    

    # Check Folder Path
    if ($folder -ne ""){
        if(Test-Path $folder){}
        else{New-Item -ItemType Directory $folder | Out-Null}
    }
    else{$folder = $PWD.Path}

    # Stop the change warnings
    Update-AzConfig -DisplayBreakingChangeWarning $false | Out-Null

    Write-Verbose "Dumping Batch Accounts from the `"$((get-azcontext).Subscription.Name)`" Subscription"

    #Get list of Batch Accounts
    $batchAccounts = Get-AzBatchAccount

    Write-Verbose "`t$($batchAccounts.Count) Batch Account(s) Enumerated"

    $batchAccounts | ForEach-Object{

        $currentBatchAccount = $_.AccountName

        Write-Verbose "`t`tAttempting to dump data from the $currentBatchAccount account"

        # Get Account Keys
        Try{
            Write-Verbose "`t`t`tAttempting to dump keys"
            $batchKeys = Get-AzBatchAccountKeys -AccountName $_.AccountName
            "Primary Key: "+$batchKeys.PrimaryAccountKey | Out-File -Append "$folder\$currentBatchAccount-Keys.txt"
            "Secondary Key: "+$batchKeys.SecondaryAccountKey | Out-File -Append "$folder\$currentBatchAccount-Keys.txt"
        }
        Catch{Write-Verbose "`t`t`tNo ListKeys Permissions on the $currentBatchAccount Batch Account"}


        # Get Batch Context
        $batchContext = Get-AzBatchAccount -AccountName $_.AccountName

        # Get Batch Pools
        $batchPools = Get-AzBatchPool -BatchContext $batchContext -Verbose:$false
        
        Write-Verbose "`t`t`t$($batchPools.Count) Pool(s) Enumerated"
        Write-Verbose "`t`t`t`tAttempting to dump pool data"

        # For Each Pool, get the ENV variables and commands from the start task
        $batchPools | ForEach-Object {
            "Pool: "+$_.Id | Out-File -Append "$folder\$currentBatchAccount-Pools.txt"
            "Start Task Command: "+$_.StartTask.CommandLine | Out-File -Append "$folder\$currentBatchAccount-Pools.txt"
            if($_.StartTask.EnvironmentSettings.Values -ne $null){
                "Start Task ENV: "| Out-File -Append "$folder\$currentBatchAccount-Pools.txt"
                $tempKey = $_.StartTask.EnvironmentSettings
                $_.StartTask.EnvironmentSettings.keys | ForEach-Object{"`t"+$_+"="+$tempKey.$_ | Out-File -Append "$folder\$currentBatchAccount-Pools.txt"}
            }
            if($_.StartTask.ResourceFiles.StorageContainerUrl -ne $null){
                "Start Task Files: "+$_.StartTask.ResourceFiles.StorageContainerUrl+"`n`n" | Out-File -Append "$folder\$currentBatchAccount-Pools.txt"
            }
        }

        # Get list of Jobs
        $batchJobs = Get-AzBatchJob -BatchContext $batchContext -Verbose:$false

        Write-Verbose "`t`t`t$($batchJobs.Count) Job(s) Enumerated"
        Write-Verbose "`t`t`t`tAttempting to dump job data"

        # For Each Job, get the ENV variables and commands from the tasks
        $batchJobs | ForEach-Object {
            # Job Manager
            "==================== Job ID: "+$_.Id+" ====================" | Out-File -Append "$folder\$currentBatchAccount-Jobs.txt"
            "Job Manager Task Command: "+$_.JobManagerTask.CommandLine | Out-File -Append "$folder\$currentBatchAccount-Jobs.txt"
            if($_.JobManagerTask.EnvironmentSettings.Values -ne $null){
                "Job Manager ENV: "| Out-File -Append "$folder\$currentBatchAccount-Jobs.txt"
                $tempKeyJM = $_.JobManagerTask.EnvironmentSettings
                $_.JobManagerTask.EnvironmentSettings.keys | ForEach-Object{"`t"+$_+"="+$tempKeyJM.$_ | Out-File -Append "$folder\$currentBatchAccount-Jobs.txt"}
            }
            if($_.JobManagerTask.ResourceFiles.StorageContainerUrl -ne $null){
                "Job Manager Task Files: "+$_.JobManagerTask.ResourceFiles.StorageContainerUrl+"`n" | Out-File -Append "$folder\$currentBatchAccount-Jobs.txt"
            }
            
            # Job Prep
            "Job Preparation Task Command: "+$_.JobPreparationTask.CommandLine | Out-File -Append "$folder\$currentBatchAccount-Jobs.txt"
            if($_.JobPreparationTask.EnvironmentSettings.Values -ne $null){
                "Job Preparation ENV: "| Out-File -Append "$folder\$currentBatchAccount-Jobs.txt"
                $tempKeyJP = $_.JobPreparationTask.EnvironmentSettings
                $_.JobPreparationTask.EnvironmentSettings.keys | ForEach-Object{"`t"+$_+"="+$tempKeyJP.$_ | Out-File -Append "$folder\$currentBatchAccount-Jobs.txt"}
            }
            if($_.JobPreparationTask.ResourceFiles.StorageContainerUrl -ne $null){
                "Job Preparation Task Files: "+$_.JobPreparationTask.ResourceFiles.StorageContainerUrl+"`n" | Out-File -Append "$folder\$currentBatchAccount-Jobs.txt"
            }

            # Job Release
            "Job Release Task Command: "+$_.JobReleaseTask.CommandLine | Out-File -Append "$folder\$currentBatchAccount-Jobs.txt"
            
            if($_.JobReleaseTask.EnvironmentSettings.Values -ne $null){
                "Job Release ENV: "| Out-File -Append "$folder\$currentBatchAccount-Jobs.txt"
                $tempKeyJR = $_.JobReleaseTask.EnvironmentSettings
                $_.JobReleaseTask.EnvironmentSettings.keys | ForEach-Object{"`t"+$_+"="+$tempKeyJR.$_ | Out-File -Append "$folder\$currentBatchAccount-Jobs.txt"}
            }
            if($_.JobReleaseTask.ResourceFiles.StorageContainerUrl -ne $null){
                "Job Release Task Files: "+$_.JobReleaseTask.ResourceFiles.StorageContainerUrl+"`n" | Out-File -Append "$folder\$currentBatchAccount-Jobs.txt"
            }
            
            # Get advanced ENV Settings
            if($_.CommonEnvironmentSettings.Values -ne $null){
                "Common ENV Settings: "| Out-File -Append "$folder\$currentBatchAccount-Jobs.txt"
                $tempKeyENV = $_.CommonEnvironmentSettings
                $_.CommonEnvironmentSettings.keys | ForEach-Object{"`t"+$_+"="+$tempKeyENV.$_ | Out-File -Append "$folder\$currentBatchAccount-Jobs.txt"}                
            }

            # Extra line to break up jobs
            "`n"| Out-File -Append "$folder\$currentBatchAccount-Jobs.txt"
        }
        
        # Get all the extra Sub-Tasks
        $AccessToken = Get-AzAccessToken -ResourceUrl "https://batch.core.windows.net/"
        if ($AccessToken.Token -is [System.Security.SecureString]) {
            $ssPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($AccessToken.Token)
            try {
                $batchToken = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ssPtr)
            } finally {
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ssPtr)
            }
        } else {
            $batchToken = $AccessToken.Token
        }
        $jobsList = ((Invoke-WebRequest -Verbose:$false -Uri "https://$($batchContext.AccountEndpoint)/jobs?api-version=2022-10-01.16.0&maxresults=1000&paginationeffort=1" -Headers @{Authorization="Bearer $batchToken"}).Content | ConvertFrom-Json).value
        $jobsList | ForEach-Object{
            $currentJob = $_.id

            # List Job-sub-tasks
            $subTasks = ((Invoke-WebRequest -Verbose:$false -Uri "$($_.url)/tasks?api-version=2022-10-01.16.0&maxresults=1000&%24select=id%2Curl" -Headers @{Authorization="Bearer $batchToken"}).Content | ConvertFrom-Json).value
            $subTasks | ForEach-Object{
                $jobRuns = (Invoke-WebRequest -Verbose:$false -Uri "$($_.url)?api-version=2022-10-01.16.0" -Headers @{Authorization="Bearer $batchToken"}).Content | ConvertFrom-Json
                $jobRuns | ForEach-Object{

                    "==================== Job ID: $currentJob === Sub-Task ID: $($_.id) ====================" | Out-File -Append "$folder\$currentBatchAccount-Jobs.txt"
                    "Sub-Task Command: "+$_.commandLine | Out-File -Append "$folder\$currentBatchAccount-Jobs.txt"

                    if($_.environmentSettings -ne "{}"){
                    "Sub-Task ENV: " | Out-File -Append "$folder\$currentBatchAccount-Jobs.txt"
                    "`t"+$_.environmentSettings.name+"="+$_.environmentSettings.value | Out-File -Append "$folder\$currentBatchAccount-Jobs.txt"
                    }

                    if($_.resourceFiles -ne $null){
                        "Sub-Task Files: "+($_.resourceFiles).storageContainerUrl+"`n" | Out-File -Append "$folder\$currentBatchAccount-Jobs.txt"
                    }
                    "`n"| Out-File -Append "$folder\$currentBatchAccount-Jobs.txt"
                }
            }
        }

        Write-Verbose "`t`tCompleted dumping of the $currentBatchAccount account"
    }
}