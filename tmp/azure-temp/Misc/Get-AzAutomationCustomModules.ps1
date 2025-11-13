<#
    File: Get-AzAutomationCustomModules.ps1
    Author: Karl Fosaaen (@kfosaaen), NetSPI - 2024
    Description: PowerShell function for listing custom Automation Account packages using the Az PowerShell CMDlets.
    
#>

function Get-AzAutomationCustomModules {

<#

    .SYNOPSIS
        PowerShell function for listing custom Automation Account packages using the Az PowerShell CMDlets.
    .DESCRIPTION
        This function will enumerate the custom packages for all of the Automation Accounts in a selected subscription. This is intended as a defensive tool to help defenders identify any malicious custom packages that may have been added to an Automation Account. It is recommended that you utilize Export-CSV or Out-Gridview for reviewing the data.
    .PARAMETER Subscription
        Subscription to use.
    .EXAMPLE
        PS C:\MicroBurst> Get-AzAutomationCustomModules -Verbose
        VERBOSE: Logged In as kfosaaen@example.com
        VERBOSE: Enumerating Automation Account Resources in the "Sample Subscription" Subscription
        VERBOSE: 	Enumerated 1 Automation Account Resources
        VERBOSE: 		Listing Modules for the NetSPI Automation Account
        VERBOSE: Completed Automation Account Custom Package Enumeration for the "Sample Subscription" Subscription
    .LINK
    https://www.netspi.com/blog/technical-blog/cloud-pentesting/backdooring-azure-automation-account-packages-and-runtime-environments/
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
        foreach ($sub in $subChoice) {Get-AzAutomationCustomModules -Subscription $sub}
        return
    }

    Write-Verbose "Logged In as $accountName"

    Write-Verbose "Enumerating Automation Account Resources in the `"$((Get-AzSubscription -SubscriptionId $Subscription).Name)`" Subscription"

    # Get List of Automation Accounts
    $autoAccts = Get-AzAutomationAccount
    Write-Verbose "`tEnumerated $($autoAccts.Length) Automation Account Resources"

    # Create data table to house results - AutomationAccount, PackageName, Version, RuntimeEnvironment
    $TempTblModules = New-Object System.Data.DataTable 
    $TempTblModules.Columns.Add("AutomationAccount") | Out-Null
    $TempTblModules.Columns.Add("PackageName") | Out-Null
    $TempTblModules.Columns.Add("RuntimeVersion") | Out-Null
    $TempTblModules.Columns.Add("RuntimeEnvironment") | Out-Null
    $TempTblModules.Columns.Add("SubscriptionId") | Out-Null

    # Foreach Automation Account
    $autoAccts | ForEach-Object{

        # Get the following lists of modules and filter for custom (isGlobal -eq false)
        Write-Verbose "`t`tListing Modules for the $($_.AutomationAccountName) Automation Account"
        $PS51url = "/subscriptions/$($_.SubscriptionId)/resourceGroups/$($_.ResourceGroupName)/providers/Microsoft.Automation/automationAccounts/$($_.AutomationAccountName)/modules?api-version=2019-06-01"
        $PS71url = "/subscriptions/$($_.SubscriptionId)/resourceGroups/$($_.ResourceGroupName)/providers/Microsoft.Automation/automationAccounts/$($_.AutomationAccountName)/powershell7Modules?api-version=2019-06-01"
        $PS72url = "/subscriptions/$($_.SubscriptionId)/resourceGroups/$($_.ResourceGroupName)/providers/Microsoft.Automation/automationAccounts/$($_.AutomationAccountName)/powershell72Modules?api-version=2019-06-01"
        $Python2url = "/subscriptions/$($_.SubscriptionId)/resourceGroups/$($_.ResourceGroupName)/providers/Microsoft.Automation/automationAccounts/$($_.AutomationAccountName)/python2Packages?api-version=2018-06-30"
        $Python3url = "/subscriptions/$($_.SubscriptionId)/resourceGroups/$($_.ResourceGroupName)/providers/Microsoft.Automation/automationAccounts/$($_.AutomationAccountName)/python3Packages?api-version=2018-06-30"
        $Python310url = "/subscriptions/$($_.SubscriptionId)/resourceGroups/$($_.ResourceGroupName)/providers/Microsoft.Automation/automationAccounts/$($_.AutomationAccountName)/python3Packages?api-version=2018-06-30&runtimeVersion=3.10"

        $AAName = $_.AutomationAccountName

        # PowerShell 5.1 Modules
        ((Invoke-AzRestMethod -Path $PS51url).Content | ConvertFrom-Json).value | ForEach-Object{ 
            if($_.properties.isglobal -EQ $false){
                # Add Data to the table
                $TempTblModules.Rows.Add($AAName,$_.name,"PowerShell-5.1","N/A", $Subscription) | Out-Null
            }
        }
        
        # PowerShell 7.1 Modules
        ((Invoke-AzRestMethod -Path $PS71url).Content | ConvertFrom-Json).value | ForEach-Object{ 
            if($_.properties.isglobal -EQ $false){
                # Add Data to the table
                $TempTblModules.Rows.Add($AAName,$_.name,"PowerShell-7.1","N/A", $Subscription) | Out-Null
            }
        }
        
        # PowerShell 7.2 Modules
        ((Invoke-AzRestMethod -Path $PS72url).Content | ConvertFrom-Json).value | ForEach-Object{ 
            if($_.properties.isglobal -EQ $false){
                # Add Data to the table
                $TempTblModules.Rows.Add($AAName,$_.name,"PowerShell-7.2","N/A", $Subscription) | Out-Null
            }
        }

        # Python 2 Packages
        ((Invoke-AzRestMethod -Path $Python2url).Content | ConvertFrom-Json).value | ForEach-Object{ 
            if($_.properties.isglobal -EQ $false){
                # Add Data to the table
                $TempTblModules.Rows.Add($AAName,$_.name,"Python-2","N/A", $Subscription) | Out-Null
            }
        }

        # Python 3.8 Packages
        ((Invoke-AzRestMethod -Path $Python3url).Content | ConvertFrom-Json).value | ForEach-Object{ 
            if($_.properties.isglobal -EQ $false){
                # Add Data to the table
                $TempTblModules.Rows.Add($AAName,$_.name,"Python-3.8","N/A", $Subscription) | Out-Null
            }
        }

        # Python 3.10 Packages
        ((Invoke-AzRestMethod -Path $Python310url).Content | ConvertFrom-Json).value | ForEach-Object{ 
            if($_.properties.isglobal -EQ $false){
                # Add Data to the table
                $TempTblModules.Rows.Add($AAName,$_.name,"Python-3.10","N/A", $Subscription) | Out-Null
            }
        }
                
        # Get list of RTEs
        $RTEurl = "/subscriptions/$($_.SubscriptionId)/resourceGroups/$($_.ResourceGroupName)/providers/Microsoft.Automation/automationAccounts/$($_.AutomationAccountName)/runtimeEnvironments?api-version=2023-05-15-preview"
        $RTElist = ((Invoke-AzRestMethod -Path $RTEurl).Content | ConvertFrom-Json).value

        # Foreach RTE
        $RTElist | ForEach-Object{
            $RTEName = $_.name
            # Get Packages - No need to filter
            $RTEPackageurl = "$($_.id)/packages?api-version=2023-05-15-preview"
            ((Invoke-AzRestMethod -Path $RTEPackageurl).Content | ConvertFrom-Json).Value | ForEach-Object{
                if($_.properties.isdefault -EQ $false){
                    $TempTblModules.Rows.Add($AAName,$_.name,"NA",$RTEName, $Subscription) | Out-Null
                }
            }
        }
    }

    Write-Verbose "Completed Automation Account Custom Package Enumeration for the `"$((Get-AzSubscription -SubscriptionId $Subscription).Name)`" Subscription"

    # Output list of AutomationAccount, PackageName, Version, RuntimeEnvironment
    Write-Output $TempTblModules
}