# Usage - returns a Key Vault Scoped Managed Identity token for a Virtual Machine - curl -sL  'https://raw.githubusercontent.com/NetSPI/MicroBurst/master/Misc/Shortcuts/VirtualMachineManagedIdentity-Linux-vault.sh' | bash
curl -s 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net' --header "Metadata: true"
