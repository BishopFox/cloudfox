<#
    File: Invoke-EnumerateAzureSubDomains.ps1
    Author: Karl Fosaaen (@kfosaaen), NetSPI - 2018 & Renos Nikolaou (@r3n_hat) - 2025
    Description: PowerShell functions for enumerating Azure/Microsoft hosted resources.
    Parts of the Permutations.txt file borrowed from - https://github.com/brianwarehime/inSp3ctor
#>


Function Invoke-EnumerateAzureSubDomains
{

<#
        .SYNOPSIS
        PowerShell function for enumerating public Azure services.
        .DESCRIPTION
        The function will check for valid Azure subdomains, based off of a base word, via DNS. 
        .PARAMETER Base
        The Base name to prepend/append with permutations.
        .PARAMETER Permutations
        Specific permutations file to use. Default is permutations.txt (included in this repo)
        .EXAMPLE
        PS C:\> Invoke-EnumerateAzureSubDomains -Base test123 -Verbose
		Invoke-EnumerateAzureSubDomains -Base test12345678 -Verbose 
		VERBOSE: Found test12345678.cloudapp.net
		VERBOSE: Found test12345678.scm.azurewebsites.net
		VERBOSE: Found test12345678.onmicrosoft.com
		VERBOSE: Found test12345678.database.windows.net
		VERBOSE: Found test12345678.mail.protection.outlook.com
		VERBOSE: Found test12345678.queue.core.windows.net
		VERBOSE: Found test12345678.blob.core.windows.net
		VERBOSE: Found test12345678.file.core.windows.net
		VERBOSE: Found test12345678.vault.azure.net
		VERBOSE: Found test12345678.table.core.windows.net
		VERBOSE: Found test12345678.azurewebsites.net
		VERBOSE: Found test12345678.documents.azure.com
		VERBOSE: Found test12345678.azure-api.net
		VERBOSE: Found test12345678.sharepoint.com
  		VERBOSE: Found test12345678.westus2.cloudapp.azure.com

		Subdomain                                Service                
		---------                                -------                
		test12345678.azure-api.net               API Services           
		test12345678.cloudapp.net                App Services           
		test12345678.scm.azurewebsites.net       App Services           
		test12345678.azurewebsites.net           App Services           
		test12345678.documents.azure.com         Databases-Cosmos DB    
		test12345678.database.windows.net        Databases-MSSQL        
		test12345678.mail.protection.outlook.com Email                  
		test12345678.vault.azure.net             Key Vaults             
		test12345678.onmicrosoft.com             Microsoft Hosted Domain
		test12345678.sharepoint.com              SharePoint             
		test12345678.queue.core.windows.net      Storage Accounts       
		test12345678.blob.core.windows.net       Storage Accounts       
		test12345678.file.core.windows.net       Storage Accounts       
		test12345678.table.core.windows.net      Storage Accounts
  		test12345678.westus2.cloudapp.azure.com	 West US 2 Virtual Machines
    
        .LINK
        https://blog.netspi.com/enumerating-azure-services/
#>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage="Base name to use.")]
        [string]$Base = "",

        [Parameter(Mandatory=$false,
        HelpMessage="Specific permutations file to use.")]
        [string]$Permutations = "$PSScriptRoot\permutations.txt"

    )

    # Domain = Service hashtable for easier lookups
    $subLookup =  @{'onmicrosoft.com'='Microsoft Hosted Domain';
					'scm.azurewebsites.net'='App Services - Management';
					'azurewebsites.net'='App Services';
					'p.azurewebsites.net'='App Services';
					'cloudapp.net'='App Services';
					'file.core.windows.net'='Storage Accounts - Files';
					'blob.core.windows.net'='Storage Accounts - Blobs';
					'queue.core.windows.net'='Storage Accounts - Queues';
					'table.core.windows.net'='Storage Accounts - Tables';
					'mail.protection.outlook.com'='Email';
					'sharepoint.com'='SharePoint';
					'redis.cache.windows.net'='Databases-Redis';
					'documents.azure.com'='Databases-Cosmos DB';
					'database.windows.net'='Databases-MSSQL';
					'vault.azure.net'='Key Vaults';
					'azureedge.net'='CDN';
					'search.windows.net'='Search Appliance';
					'azure-api.net'='API Services';
					'azurecr.io'='Azure Container Registry';
					'eastus.cloudapp.azure.com'           = 'East US Virtual Machines';
					'eastus2.cloudapp.azure.com'          = 'East US 2 Virtual Machines';
					'westus.cloudapp.azure.com'           = 'West US Virtual Machines';
					'westus2.cloudapp.azure.com'          = 'West US 2 Virtual Machines';
					'westus3.cloudapp.azure.com'          = 'West US 3 Virtual Machines';
					'centralus.cloudapp.azure.com'        = 'Central US Virtual Machines';
					'northcentralus.cloudapp.azure.com'   = 'North Central US Virtual Machines';
					'southcentralus.cloudapp.azure.com'   = 'South Central US Virtual Machines';
					'westcentralus.cloudapp.azure.com'    = 'West Central US Virtual Machines';
					'northeurope.cloudapp.azure.com'      = 'North Europe (Ireland) Virtual Machines';
					'westeurope.cloudapp.azure.com'       = 'West Europe (Netherlands) Virtual Machines';
					'uksouth.cloudapp.azure.com'          = 'United Kingdom South Virtual Machines';
					'ukwest.cloudapp.azure.com'           = 'United Kingdom West Virtual Machines';
					'francecentral.cloudapp.azure.com'    = 'France Central Virtual Machines';
					'germanywestcentral.cloudapp.azure.com' = 'Germany West Central Virtual Machines';
					'italynorth.cloudapp.azure.com'       = 'Italy North Virtual Machines';
					'norwayeast.cloudapp.azure.com'       = 'Norway East Virtual Machines';
					'polandcentral.cloudapp.azure.com'    = 'Poland Central Virtual Machines';
					'spaincentral.cloudapp.azure.com'     = 'Spain Central Virtual Machines';
					'swedencentral.cloudapp.azure.com'    = 'Sweden Central Virtual Machines';
					'switzerlandnorth.cloudapp.azure.com' = 'Switzerland North Virtual Machines';
					'australiaeast.cloudapp.azure.com'    = 'Australia East Virtual Machines';
					'australiacentral.cloudapp.azure.com' = 'Australia Central Virtual Machines';
					'australiasoutheast.cloudapp.azure.com' = 'Australia Southeast Virtual Machines';
					'centralindia.cloudapp.azure.com'     = 'Central India Virtual Machines';
					'southindia.cloudapp.azure.com'       = 'South India Virtual Machines';
					'japaneast.cloudapp.azure.com'        = 'Japan East Virtual Machines';
					'japanwest.cloudapp.azure.com'        = 'Japan West Virtual Machines';
					'koreacentral.cloudapp.azure.com'     = 'Korea Central Virtual Machines';
					'koreasouth.cloudapp.azure.com'       = 'Korea South Virtual Machines';
					'eastasia.cloudapp.azure.com'         = 'East Asia (Hong Kong) Virtual Machines';
					'southeastasia.cloudapp.azure.com'    = 'Southeast Asia (Singapore) Virtual Machines';
					'newzealandnorth.cloudapp.azure.com'  = 'New Zealand North Virtual Machines';
					'canadacentral.cloudapp.azure.com'    = 'Canada Central Virtual Machines';
					'canadaeast.cloudapp.azure.com'       = 'Canada East Virtual Machines';
					'uaenorth.cloudapp.azure.com'         = 'UAE North Virtual Machines';
					'qatarcentral.cloudapp.azure.com'     = 'Qatar Central Virtual Machines';
					'israelcentral.cloudapp.azure.com'    = 'Israel Central Virtual Machines';
					'southafricanorth.cloudapp.azure.com' = 'South Africa North Virtual Machines';
					'mexicocentral.cloudapp.azure.com'    = 'Mexico Central Virtual Machines';
					'brazilsouth.cloudapp.azure.com'      = 'Brazil South Virtual Machines';
					}

    $runningList = @()
    $lookupResult = ""

    if ($Permutations -and (Test-Path $Permutations)){
        $PermutationContent = Get-Content $Permutations
        }
    else{Write-Verbose "No permutations file found"}

    # Create data table to house results
    $TempTbl = New-Object System.Data.DataTable 
    $TempTbl.Columns.Add("Subdomain") | Out-Null
    $TempTbl.Columns.Add("Service") | Out-Null

    $iter = 0
    
    # Check Each Subdomain
    $subLookup.Keys | ForEach-Object{

        # Track the progress
        $iter++
        $subprogress = ($iter/$subLookup.Count)*100

        Write-Progress -Status 'Progress..' -Activity "Enumerating $Base subdomains for $_ subdomain" -PercentComplete $subprogress

        # Check the base word
        $lookup = $Base+'.'+$_
        
        try{($lookupResult = Resolve-DnsName $lookup -ErrorAction Stop -Verbose:$false -DnsOnly | select Name | Select-Object -First 1)|Out-Null}catch{}
        if ($lookupResult -ne ""){
            Write-Verbose "Found $lookup"; $runningList += $lookup
            # Add to output table
            $TempTbl.Rows.Add([string]$lookup,[string]$subLookup[$_]) | Out-Null

            }
        $lookupResult = ""


        # Chek Permutations (postpend word, prepend word)
        foreach($word in $PermutationContent){

            # Storage Accounts can't have special characters
            if(($_ -ne 'file.core.windows.net') -or ($_ -ne 'blob.core.windows.net')){
                # Base-Permutation
                $lookup = $Base+"-"+$word+'.'+$_
                try{($lookupResult = Resolve-DnsName $lookup -ErrorAction Stop -Verbose:$false -DnsOnly | select Name | Select-Object -First 1)|Out-Null}catch{}
                if ($lookupResult -ne ""){Write-Verbose "Found $lookup"; $runningList += $lookup; $TempTbl.Rows.Add([string]$lookup,[string]$subLookup[$_]) | Out-Null}
                $lookupResult = ""

                # Permutation-Base
                $lookup = $word+"-"+$Base+'.'+$_
                try{($lookupResult = Resolve-DnsName $lookup -ErrorAction Stop -Verbose:$false -DnsOnly | select Name | Select-Object -First 1)|Out-Null}catch{}
                if ($lookupResult -ne ""){Write-Verbose "Found $lookup"; $runningList += $lookup; $TempTbl.Rows.Add([string]$lookup,[string]$subLookup[$_]) | Out-Null}
                $lookupResult = ""
            }

            # PermutationBase
            $lookup = $word+$Base+'.'+$_
            try{($lookupResult = Resolve-DnsName $lookup -ErrorAction Stop -Verbose:$false -DnsOnly | select Name | Select-Object -First 1)|Out-Null}catch{}
            if ($lookupResult -ne ""){Write-Verbose "Found $lookup"; $runningList += $lookup; $TempTbl.Rows.Add([string]$lookup,[string]$subLookup[$_]) | Out-Null}
            $lookupResult = ""

            # BasePermutation
            $lookup = $Base+$word+'.'+$_
            try{($lookupResult = Resolve-DnsName $lookup -ErrorAction Stop -Verbose:$false -DnsOnly | select Name | Select-Object -First 1)|Out-Null}catch{}
            if ($lookupResult -ne ""){Write-Verbose "Found $lookup"; $runningList += $lookup; $TempTbl.Rows.Add([string]$lookup,[string]$subLookup[$_]) | Out-Null}
            $lookupResult = ""
        }
    }
    $TempTbl | sort Service
}
