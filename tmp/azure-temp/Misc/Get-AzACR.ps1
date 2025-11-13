Function Get-AzACR
{
    # Author: Karl Fosaaen (@kfosaaen), NetSPI - 2020
    # Description: PowerShell function for enumerating available Azure ACR container images, using Docker credentials and an ACR hostname. This might also work for other docker container registries.
    # Output: "docker pull" commands to pull each conatiner image
    #       By default, the script will output the first tag returned from the Registry API
    #       Use the -all flag to output all ACR image tags


    # To Do: Add pagination fix on -all - https://docs.docker.com/registry/spec/api/#tags

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True,
        HelpMessage="Username")]
        [string]$username,

        [Parameter(Mandatory=$True,
        HelpMessage="Password")]
        [string]$password,

        [Parameter(Mandatory=$true,
        HelpMessage="Registry")]
        [string]$registry,

        [switch] $all

    )

    # Set up the Authorization header
    $credential = "${username}:${password}"
    $credbytes = [System.Text.Encoding]::ASCII.GetBytes($credential)
    $base64 = [System.Convert]::ToBase64String($credbytes)
    $basicAuthValue = "Basic $base64"
    $headers = @{ Authorization = $basicAuthValue }


    # Enum the Images
    $images = ((Invoke-WebRequest -Uri (-join('https://',$registry,'/v2/_catalog')) -Headers $headers).content | ConvertFrom-Json)

    # Foreach Image - Enum tags
    $images.repositories | ForEach-Object{
        $tags = ((Invoke-WebRequest -Uri (-join('https://',$registry,'/v2/',$_,'/tags/list')) -Headers $headers).content | ConvertFrom-Json)

        if($all){ForEach ($tag in $tags.tags){ Write-Host "docker pull"$registry"/"$_":"$tag}}
        else{Write-Host (-join('docker pull ',$registry,'/',$_,':',($tags.tags[0])))}        
    }

}