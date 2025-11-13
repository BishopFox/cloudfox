<#
    File: Invoke-EnumerateAzureBlobs.ps1
    Author: Karl Fosaaen (@kfosaaen), NetSPI - 2018
    Description: PowerShell function for enumerating public Azure Blob file resources.
    Parts of the Permutations.txt file borrowed from - https://github.com/brianwarehime/inSp3ctor

#>


Function Invoke-EnumerateAzureBlobs
{

    <#
            .SYNOPSIS
            PowerShell function for enumerating public Azure Blobs and Containers.
            .DESCRIPTION
            The function will check for valid .blob.core.windows.net host names via DNS. 
	        If a BingAPIKey is supplied, a Bing search will be made for the base word under the .blob.core.windows.net site.
            After completing storage account enumeration, the function then checks for valid containers via the Azure REST API methods.
            If a valid container has public files, the function will list them out.
            .PARAMETER Base
            The Base name to prepend/append with permutations.
            .PARAMETER Permutations
            Specific permutations file to use. Default is permutations.txt (included in this repo)
            .PARAMETER Folders
            Specific folders file to use. Default is permutations.txt (included in this repo)
            .PARAMETER OutputFile
            The file to write out your results to
            .PARAMETER BingAPIKey
            The Bing API Key to use for base name searches.
            .EXAMPLE
            PS C:\> Invoke-EnumerateAzureBlobs -Base secure
            Found Storage Account -  secure.blob.core.windows.net
            Found Storage Account -  testsecure.blob.core.windows.net
            Found Storage Account -  securetest.blob.core.windows.net
            Found Storage Account -  securedata.blob.core.windows.net
            Found Storage Account -  securefiles.blob.core.windows.net
            Found Storage Account -  securefilestorage.blob.core.windows.net
            Found Storage Account -  securestorageaccount.blob.core.windows.net
            Found Storage Account -  securesql.blob.core.windows.net
            Found Storage Account -  hrsecure.blob.core.windows.net
            Found Storage Account -  secureit.blob.core.windows.net
            Found Storage Account -  secureimages.blob.core.windows.net
            Found Storage Account -  securestorage.blob.core.windows.net

            Found Container - hrsecure.blob.core.windows.net/NETSPItest
	            Public File Available: https://hrsecure.blob.core.windows.net/NETSPItest/SuperSecretFile.txt
            Found Container - secureimages.blob.core.windows.net/NETSPItest123

            .LINK
            https://blog.netspi.com/anonymously-enumerating-azure-file-resources/
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        HelpMessage="Base name to use.")]
        [string]$Base = "",

        [Parameter(Mandatory=$false,
        HelpMessage="Path for file output.")]
        [string]$OutputFile,

        [Parameter(Mandatory=$false,
        HelpMessage="Specific permutations file to use.")]
        [string]$Permutations = "$PSScriptRoot\permutations.txt",

        [Parameter(Mandatory=$false,
        HelpMessage="Specific folders file to use.")]
        [string]$Folders = "$PSScriptRoot\permutations.txt",

        [Parameter(Mandatory=$false,
        HelpMessage="Bing API Key to use")]
        [string]$BingAPIKey

    )

$domain = '.blob.core.windows.net'
$runningList = @()
$bingList = @()
$bingContainers = @()
$lookupResult = ""

    if($Base){
        # Check for the base word
        $lookup = ($Base+$domain).ToLower()
        Write-Verbose "Resolving - $lookup"
        try{($lookupResult = Resolve-DnsName $lookup -ErrorAction Stop -Verbose:$false | select Name | Select-Object -First 1)|Out-Null}catch{}
        if ($lookupResult -ne ""){Write-Host "Found Storage Account - $lookup"; $runningList += $lookup; if ($OutputFile){$lookup >> $OutputFile}}
        $lookupResult = ""
    }

    $permutationsContent = Get-Content $Permutations | Where-Object {$_.trim() -ne "" }
    $linecount = $permutationsContent | Measure-Object –Line | select Lines
    $iter = 0

    # Check Permutations
    foreach($word in $permutationsContent){
        
        # Track the progress
        $iter++
        $lineprogress = ($iter/$linecount.Lines)*100


        Write-Progress -Status 'Progress..' -Activity "Enumerating Storage Accounts based off of permutations on $Base" -PercentComplete $lineprogress

        if($Base){
            # PermutationBase
            $lookup = ($word+$Base+$domain).ToLower()
            Write-Verbose "Resolving - $lookup"
            try{($lookupResult = Resolve-DnsName $lookup -ErrorAction Stop -Verbose:$false | select Name | Select-Object -First 1)|Out-Null}catch{}
            if ($lookupResult -ne ""){Write-Host "Found Storage Account -  $lookup"; $runningList += $lookup; if ($OutputFile){$lookup >> $OutputFile}}
            $lookupResult = ""

            # BasePermutation
            $lookup = ($Base+$word+$domain).ToLower()
            Write-Verbose "Resolving - $lookup"
            try{($lookupResult = Resolve-DnsName $lookup -ErrorAction Stop -Verbose:$false | select Name | Select-Object -First 1)|Out-Null}catch{}
            if ($lookupResult -ne ""){Write-Host "Found Storage Account -  $lookup"; $runningList += $lookup; if ($OutputFile){$lookup >> $OutputFile}}
            $lookupResult = ""
        }
        else{
            # Check the permutation word if there's no base
            $lookup = ($word+$domain).ToLower()
            Write-Verbose "Resolving - $lookup"
            try{($lookupResult = Resolve-DnsName $lookup -ErrorAction Stop -Verbose:$false | select Name | Select-Object -First 1)|Out-Null}catch{}
            if ($lookupResult -ne ""){Write-Host "Found Storage Account -  $lookup"; $runningList += $lookup; if ($OutputFile){$lookup >> $OutputFile}}
            $lookupResult = ""
        }
    }

    Write-Verbose "DNS Brute-Force Complete"
    Write-Verbose "Starting Container Enumeration"

    # Extra New Line for Readability
    Write-Host ""
    
    # Bing Dorking Section here
    if($BingAPIKey){

        # Set up Search        
        $BingQuery = "site:blob.core.windows.net "+$Base

        $WebSearch = Invoke-RestMethod -Uri "https://api.bing.microsoft.com/v7.0/search?q=$BingQuery&count=50" -Headers @{ "Ocp-Apim-Subscription-Key" = $BingAPIKey } 

        # Parse URLS
        if ($WebSearch.webPages.value){
            $WebSearch.webPages.value | ForEach-Object {
                        # Add found Storage Accounts to the list
                        $bingList += ([System.Uri]($_.url)).Host

                        # Add found containers to the list
                        $bingContainers += ([System.Uri]($_.url)).Segments[1].Replace("/","")
            }
        }

        # Output to the terminal
        $bingList | select -Unique | ForEach-Object{
            Write-Host "Bing Found Storage Account - $_"
            if ($OutputFile){$_ >> $OutputFile}
            }
        
        # Prompt for which storage accounts to add
        $bingChoice = $bingList | select -Unique | out-gridview -Title "Select the Bing storage accounts to include" -PassThru
        Foreach ($choice in $bingChoice){$runningList += $choice}

        # Extra New Line for Readability
        Write-Host ""
    }

    # Read in file
    $folderContent = Get-Content $Folders | Where-Object {$_.trim() -ne "" }

    # Append any Bing results
    if ($BingAPIKey){$folderContent += ($bingContainers | select -Unique)}

    # Get line counts for number of storage accounts for statusing
    $foldercount = $folderContent | Measure-Object –Line | select Lines


    # Go through the valid blob storage accounts and confirm Anonymous Access / List files
    foreach ($subDomain in $runningList){
        
        $iter = 0

        # Folder Names to guess for containers
        foreach ($folderName in $folderContent){

            # Track the progress
            $iter++
            $subfolderprogress = ($iter/$foldercount.Lines)*100

            Write-Progress -Status 'Progress..' -Activity "Enumerating Containers for $subDomain Storage Account" -PercentComplete $subfolderprogress

            $dirGuess = ($subDomain+"/"+$folderName).ToLower()
            # URL for confirming container
            $uriGuess = "https://"+$dirGuess+"?restype=container"
            try{
                $status = (Invoke-WebRequest -uri $uriGuess -ErrorAction Stop -UseBasicParsing).StatusCode
                # 200 Response Confirms the Container
                if ($status -eq 200){
                    Write-Host "Found Container - $dirGuess"
                    # URL for listing publicly available files
                    $uriList = "https://"+$dirGuess+"?restype=container&comp=list&include=versions"
                    $FileList = (Invoke-WebRequest -uri $uriList -Headers @{"x-ms-version"="2019-12-12"} -Method Get -UseBasicParsing).Content
                    # Microsoft includes these characters in the response, Thanks...
                    [xml]$xmlFileList = $FileList -replace "ï»¿"
                    $foundURL = @($xmlFileList.EnumerationResults.Blobs.Blob)

                    # Parse the XML results
                    if($foundURL.Count -gt 0){
                        foreach($url in $foundURL){
                            if($null -ne $url.VersionId){
                                $dateTime = Get-Date ([DateTime]$url.VersionId).ToUniversalTime() -UFormat %s
                                Write-Host -ForegroundColor Cyan "`tPublic File Available: https://$dirGuess/$($url.Name)`n`t`tAvailable version: $($url.VersionId)"
                                if ($OutputFile){$url >> $OutputFile}
                            }
                            else{
                                Write-Host -ForegroundColor Cyan "`tPublic File Available: https://$dirGuess/$($url.Name)"
                                if ($OutputFile){$url >> $OutputFile}
                            }
                        }
                    }
                    else{Write-Host -ForegroundColor Cyan "`tEmpty Public Container Available: $uriList";if ($OutputFile){$uriList >> $OutputFile}}
                }
            }
            catch{}
        }
    }
    Write-Verbose "Container Enumeration Complete"
}
