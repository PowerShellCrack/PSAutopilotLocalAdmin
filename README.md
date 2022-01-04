# PSAutopilotLocalAdmin

PowerShell script to create local admin during Autopilot enrollment

## Available

There are two scripts current available; I am working on two more...

Script | Status| Explanation | Security | Comments
--|--|--|--|--
AddLocalAdminSimple.ps1 | Tested | Adds administrator account with clear text password to Window Device using Intune | Unsecure | recommended for testing ONLY! |
AddLocalAdminObfuscated.ps1 | Tested | Adds administrator account with obfuscated password to Window Device using Intune | less secure | Could decrypt password if AES key is retrieved |
AddLocalAdminKeyVault.ps1 | Not Available | Adds administrator account with random password to Window Device using Intune and stores it in Azure Vault | More Secure | Can't retrieve password, but could generate new password using Service Principal Id info. Must be an admin to apply password though
AddLocalAdminFunctionApp.ps1 | Not Available | Adds administrator account with random password to Window Device using a Function app and stores it in Azure Vault | Most Secure | Can't retrieve password, but could generate new password using Function app key info. Must be an admin to apply password though
