<#
.SYNOPSIS
    Adds administrator account

.DESCRIPTION
    Adds administrator account with clear text password to Window Device using Intune

.EXAMPLE
    .\AddLocalAdminSimple.ps1

.NOTES
    Author		: Richard "Dick" Tracy <richard.j.tracy@gmail.com>
	Source	    : https://github.com/PowerShellCrack/PSAutopilotLocalAdmin
    Version		: 1.0.0
#>
##* ================================
##* VARIABLES
##* ================================
$UserName = 'IntuneAdmin'
$UserPassword = 'P@ssw0rd12!'
$Description = 'Intune generated local account'

$ComputerName = $env:COMPUTERNAME
$Group = 'Administrators'

##* ================================
##* MAIN
##* ================================

#Use ADSI to create administrator account
$computer = [ADSI]"WinNT://$($ComputerName),computer"
$user = $computer.Create('User', "$($UserName)")
$user.SetPassword($UserPassword)
$user.Put('Description',$($Description))
$user.SetInfo()

# set the password to never expire
$user.UserFlags.value = $user.UserFlags.value -bor 0x10000
$user.CommitChanges()

# add user to group
$group = [ADSI]"WinNT://$($computername)/$($groupname),group"
$group.add("WinNT://$($UserName),user")
