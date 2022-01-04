
<#
.SYNOPSIS
    Adds administrator account

.DESCRIPTION
    Adds administrator account with obfuscated password to Window Device using Intune

.EXAMPLE
    .\AddLocalAdminObfuscated.ps1

.NOTES
    Author		: Richard "Dick" Tracy <richard.j.tracy@gmail.com>
	Source	    : https://github.com/PowerShellCrack/PSAutopilotLocalAdmin
    Version		: 1.0.0
    #Requires -Version 3.0
#>

<#
##*=============================================
## !!! IMPORTANT !!! STORE THESE STEPS ELSEWHERE
##*=============================================

#How to "Obfuscate" password (encrypt & decrypt)

#STEP 1 - create random passphase (256 AES). Save the output as a variable (copy/paste)
#NOTE: this key is unique; the same key must be used to decrypt
$AESKey = New-Object Byte[] 32
[Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($AESKey)
Write-host ('$AESKey = @(' + ($AESKey -join ",").ToString() + ')')

#STEP 2 - Encrypt password with AES key. Save the output as a variable (copy/paste)
$UserPassword = 'P@ssw0rd12!'
$UserObfuscatedPassword = ConvertTo-SecureString -String $UserPassword -AsPlainText -Force | ConvertFrom-SecureString -Key $AESKey
Write-host ('$UserObfuscatedPassword = "' + $UserObfuscatedPassword + '"')

#STEP 3 - Store as useable credentials; converts encrypted key into secure key for use (used in the script)
$UserName = 'IntuneAdmin'
$SecurePassword = $UserObfuscatedPassword | ConvertTo-SecureString -Key $AESKey
$credential = New-Object System.Management.Automation.PsCredential($UserName, $SecurePassword)

#STEP 4 - Test password output (clear text) from creds
$credential.GetNetworkCredential().password

#>

##* ================================
##* VARIABLES
##* ================================
# NOTE: Be sure to generate a new AES key
$AESKey = @(182,189,38,250,141,255,178,93,227,19,72,178,42,135,166,230,214,149,150,162,72,97,188,96,250,72,214,228,122,100,56,133)

$UserName = 'IntuneAdmin'
#Encrypt password (use AESkey and steps above)
$UserObfuscatedPassword = "76492d1116743f0423413b16050a5345MgB8AGwAZgBmAHcATQBYAGwAZgB3AG8ASQBkAFkATQBWADIAWAB4AG4AbgB6AEEAPQA9AHwAZAAyADcAYQA1AGQAMAAzADgAZAA3ADAAMAA5ADAAYgA3AGEAYgAzADgANQA1AGEAZQAwAGMAZAA0AGEAYwBiAGUANQA2AGIAOAA0ADEAOQAzADYAYgA3ADYAMABkADUAOAAzADEAYQA2ADAAMQBiADMAMgBkAGIAYgAwADEAOAA="

$Description = 'Intune generated local account'

$ComputerName = $env:COMPUTERNAME
$Group = 'Administrators'
##* ===============================
##* MAIN
##* ===============================
$SecurePassword = $UserObfuscatedPassword | ConvertTo-SecureString -Key $AESKey
#$credential = New-Object System.Management.Automation.PsCredential($UserName, $SecurePassword)

# use Windows native powershell cmdlet to create account
#if local user is found; renew the password
$LocalAdmin = Get-LocalUser $UserName -ErrorAction SilentlyContinue
If(-Not $LocalAdmin)
{
    Try{
        Write-Host ("Creating new account [{0}]..." -f $UserName) -NoNewline
        New-LocalUser -Name $UserName -Password $SecurePassword -Description $Description -PasswordNeverExpires:$true -AccountNeverExpires -UserMayNotChangePassword -ErrorAction Stop
        Write-Host ("Done") -ForegroundColor Green
    }
    Catch{
        Write-Host ("Failed: {0}" -f $_.Exception.Message) -ForegroundColor Red
    }
}
Else{
    Try{
        Write-Host ("Updating new account [{0}] with new password" -f $UserName) -NoNewline
        Set-LocalUser -Name $UserName -Password $SecurePassword -Description $Description -AccountNeverExpires -PasswordNeverExpires:$true -UserMayChangePassword:$false
        Write-Host ("Done") -ForegroundColor Green
    }
    Catch{
        Write-Host ("Failed: {0}" -f $_.Exception.Message) -ForegroundColor Red
    }
}

# Query current local group
$query="Associators of {Win32_Group.Domain='$ComputerName',Name='$Group'} where Role=GroupComponent"
$AdminGroup = Get-WmiObject -Query $query

#if user is not in the group, add it
If($UserName -notin $AdminGroup.Name)
{
    Add-LocalGroupMember -Group "Administrators" -Member $UserName -ErrorAction SilentlyContinue
    Write-Host ("Adding account [{0}] to administrators group" -f $UserName)
}
Else{
    Write-Host ("Account [{0}] is already in the administrators group" -f $UserName)
}
