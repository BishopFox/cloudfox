function Invoke-AzRestBastionShareableLink {

    # Author: Karim El-Melhaoui(@KarimsCloud), O3 Cyber
    # Description: PowerShell function for creating a shareable link in Azure Bastion
    # A VM must be specified as the link is attached to a VM.
    # https://learn.microsoft.com/en-us/azure/bastion/shareable-link


    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$true,
    HelpMessage="Name of VM to enable Shareable Link")]
    [string]$VMName = ""
    )

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
    $Headers = @{Authorization = "Bearer $Token" }

    $AzBastions = Get-AzBastion
    Write-Output "Enabling Shareable Link feature on all Azure bastions"

    #Gets the ID of VM specified through name parameter to use for creating a shareable link
    $VMId = Get-AzVM -Name $VMName | Select-Object -ExpandProperty Id
    Write-Output "Id of VM: $VMId" 

    foreach ($AzBastion in $AzBastions) {

        
        $body = -join ('{"location": "',$AzBastion.location,'", "properties": {"enableShareableLink": "true","ipConfigurations": [{"name": "',$AzBastion.IpConfigurations.Name,'","properties":{"publicIPAddress": {"Id": "',$AzBastion.IpConfigurations.PublicIpAddress.Id,'"},"subnet":{"Id": "',$AzBastion.IpConfigurations.Subnet.Id,'"}}}]}}')
        $RGName = $AzBastion.ResourceGroupName
        $BastionName = $AzBastion.Name
        try {
            Write-Output "Enabling shareable links on $BastionName"
            Invoke-RestMethod -Method Put -Uri "https://management.azure.com/subscriptions/$($subscriptionId)/resourceGroups/$($RGName)/providers/Microsoft.Network/bastionHosts/$($BastionName)?api-version=2022-05-01" -Headers $Headers -Body $body -ContentType "application/json"

        }
        catch {
            Write-Output "Something went wrong. : $_"
        }
        
        #Generate body with VM ID specifie. 
        $VMBody = -join ('{"vms":[{"vm":{"id":"',$VMId,'"}}]}')

        try {
        #Creates shareable link for specified VM
        Invoke-RestMethod -Method Post -Uri "https://management.azure.com/subscriptions/$($subscriptionId)/resourceGroups/$($RGName)/providers/Microsoft.Network/bastionHosts/$($BastionName)/createShareableLinks?api-version=2022-05-01" -Headers $Headers -Body $VMBody -ContentType "application/json"

        }
        catch {
            Write-Output "Something went wrong. : $_"
        }
    }
}