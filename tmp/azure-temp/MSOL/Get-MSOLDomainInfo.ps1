<#
    File: Get-MSOLDomainInfo.ps1
    Author: Karl Fosaaen (@kfosaaen), NetSPI - 2018
    Description: PowerShell functions for enumerating information from Office365 domains.
#>


# Check if the MSOnline Module is installed and imported
if(!(Get-Module MSOnline)){
    try{Import-Module MSOnline -ErrorAction Stop}
    catch{Install-Module -Name MSOnline -Confirm}
    }


Function Get-MSOLDomainInfo
{
<#
    .SYNOPSIS
        PowerShell function for dumping information from an Office365 domain via an authenticated MSOL connection.
	.DESCRIPTION
		The function will dump available information for an Office365 domain out to CSV and txt files in the -folder parameter directory.
    .PARAMETER folder
        The folder to output to.   
    .PARAMETER Users
        The flag for dumping the list of MSOL-Users. 
    .PARAMETER Groups
        The flag for dumping the list of MSOL-Groups. Disable ('N') if you just want to get a user list.
	.EXAMPLE
        PS C:\> Get-MSOLDomainInfo -folder Test -Verbose
        VERBOSE: Getting Domain Contact Info...
        VERBOSE: Getting Domains...
        VERBOSE: 	4 Domains were found.
        VERBOSE: Getting Domain Users...
        VERBOSE: 	200 Domain Users were found across 4 domains.
        VERBOSE: Getting Domain Groups...
        VERBOSE: 	90 Domain Groups were found.
        VERBOSE: Getting Domain Users for each group...
        VERBOSE: 	Domain Group Users were enumerated for 90 groups.
        VERBOSE: Getting Domain Devices...
        VERBOSE: 	22 devices were enumerated.
        VERBOSE: Getting Domain Service Principals...
        VERBOSE: 	134 service principals were enumerated.
        VERBOSE: All done.

#>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        HelpMessage="Folder to output to.")]
        [string]$folder,
        [parameter(Mandatory=$false)]
        [ValidateSet("Y","N")]
        [String]$Users = "Y",
        [parameter(Mandatory=$false)]
        [ValidateSet("Y","N")]
        [String]$Groups = "Y"
    )



    try{Get-MsolCompanyInformation -ErrorAction Stop | Out-Null}
    catch{
        Write-Verbose "No existing authenticated connection to MSOL service"
        # Authenticate to MSOL
        try{Connect-MsolService -ErrorAction Stop}
        catch{Write-Verbose "Failed to connect to MSOL service"; break}
    }

    # Folder Parameter Checking
    if ($folder){if(Test-Path $folder){if(Test-Path $folder"\MSOL"){}else{New-Item -ItemType Directory $folder"\MSOL"|Out-Null}}else{New-Item -ItemType Directory $folder|Out-Null ; New-Item -ItemType Directory $folder"\MSOL"|Out-Null}}
    else{if(Test-Path MSOL){}else{New-Item -ItemType Directory MSOL|Out-Null};$folder=".\"}

    # Get/Write Company Info
    Write-Verbose "Getting Domain Contact Info..."
    Get-MsolCompanyInformation | Out-File -LiteralPath $folder"\MSOL\DomainCompanyInfo.txt"

    # Get/Write Domains
    Write-Verbose "Getting Domains..."
    $domains = Get-MsolDomain 
    $domains | select  Name,Status,Authentication | Export-Csv -NoTypeInformation -LiteralPath $folder"\MSOL\Domains.CSV"
    $domainCount = $domains.Count
    Write-Verbose "`t$domainCount Domains were found."

    if ($Users -eq "Y"){   
        # Get/Write Users for each domain
        Write-Verbose "Getting Domain Users..."
        $userCount=0
        $domains | select  Name | ForEach-Object {$DomainIter=$_.Name; $domainUsers=Get-MsolUser -All -DomainName $DomainIter; $userCount+=$domainUsers.Count; $domainUsers | Select-Object @{Label="Domain"; Expression={$DomainIter}},UserPrincipalName,DisplayName,isLicensed | Export-Csv -NoTypeInformation -LiteralPath $folder"\MSOL\"$DomainIter"_Users.CSV"}
        Write-Verbose "`t$userCount Domain Users were found across $domainCount domains."
    }

    if ($Groups -eq "Y"){
        # Get/Write Groups
        Write-Verbose "Getting Domain Groups..."
    
        # Create Folder
        if(Test-Path $folder"\MSOL\Groups"){}
        else{New-Item -ItemType Directory $folder"\MSOL\Groups" | Out-Null}

        # List Groups
        $groupList = Get-MsolGroup -All -GroupType Security
        $groupCount = $groupList.Count
        Write-Verbose "`t$groupCount Domain Groups were found."
        if($groupCount -gt 0){
            Write-Verbose "Getting Domain Users for each group..."
            $groupList | Export-Csv -NoTypeInformation -LiteralPath $folder"\MSOL\Groups.CSV"
            $groupList | ForEach-Object {$groupName=$_.DisplayName; Get-MsolGroupMember -All -GroupObjectId $_.ObjectID | Select-Object @{ Label = "Group Name"; Expression={$groupName}}, EmailAddress, DisplayName | Export-Csv -NoTypeInformation -LiteralPath $folder"\MSOL\Groups\"$groupName"_Users.CSV"}
            Write-Verbose "`tDomain Group Users were enumerated for $groupCount groups."
        }
    }

    # Get/Write Devices
    Write-Verbose "Getting Domain Devices..."
    $devices = Get-MsolDevice -All 
    if ($devices.count -gt 0){$devices | Export-Csv -NoTypeInformation -LiteralPath $folder"\MSOL\Domain_Devices.CSV"}
    $deviceCount = $devices.Count
    Write-Verbose "`t$deviceCount devices were enumerated."


    # Get/Write Service Principals
    Write-Verbose "Getting Domain Service Principals..."
    $principals = Get-MsolServicePrincipal -All
    $principals | select DisplayName,@{name="ServicePrincipalNames";expression={$_.ServicePrincipalNames}},AccountEnabled,Addresses,AppPrincipalId,ObjectId,TrustedForDelegation | Export-Csv -NoTypeInformation -LiteralPath $folder"\MSOL\Domain_SPNs.CSV"
    $principalCount = $principals.Count
    Write-Verbose "`t$principalCount service principals were enumerated."

    Write-Verbose "All done with MSOL tasks.`n"
}
