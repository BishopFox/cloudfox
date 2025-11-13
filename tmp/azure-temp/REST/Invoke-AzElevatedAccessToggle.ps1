Function Invoke-AzElevatedAccessToggle {

    # Author: Karim El-Melhaoui(@KarimMelhaoui), O3 Cyber
    # Description: PowerShell function for invoking Elevated Access Toggle
    # https://learn.microsoft.com/en-us/azure/role-based-access-control/elevate-access-global-admin 
    # https://microsoft.github.io/Azure-Threat-Research-Matrix/PrivilegeEscalation/AZT402/AZT402/

    try {

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
        $ElevatedAccessToggle = Invoke-RestMethod -Method POST -Uri "https://management.azure.com/providers/Microsoft.Authorization/elevateAccess?api-version=2016-07-01" -Headers $Headers

        $ElevatedAccessToggle
        Write-Output "Granting current principal at User Access Administrator at  Root level."
        
    }
    catch {
        Write-Output "Something went wrong. : $_"
        Write-Output "`nThis is likely because the principal is not Global Administrator."
    }

}