<#
.SYNOPSIS
    Adds administrator account

.DESCRIPTION
    Adds administrator account with random password to Window Device using Intune and stores it in Azure Key Vault

.EXAMPLE
    .\AddLocalAdminAzureVault.ps1

.NOTES
    Author		: Richard "Dick" Tracy <richard.j.tracy@gmail.com>
	Source	    : https://github.com/PowerShellCrack/PSAutopilotLocalAdmin
    Version		: 1.0.0

    ##*=============================================
    ## !!! IMPORTANT !!!
    ##*=============================================
    STORE THESE STEPS ELSEWHERE, run them, then update variables in VARIABLE section

    $location = 'eastus'
    $ResourceGroup = 'dtolab-SiteB-rg'
    $keyVaultName = 'devicelocaladminsecrets'
    $ServicePrincipalName = 'devicemanagementserviceprincipal'

    Connect-AzAccount
    $AzContext = Get-AzContext
    Write-host ('$TenantId="{0}"' -f $AzContext.Tenant.id)

    # STEP 1: CREATE AZURE AD SERVICE PRINCIPAL ACCOUNT
    $SpScope = "/subscriptions/$($AzContext.Subscription.id)/resourcegroups/$ResourceGroup/providers/Microsoft.KeyVault/vaults/$keyVaultName"

    $AppSP = New-AzADServicePrincipal -DisplayName $ServicePrincipalName
    $AppSP = Get-AzADServicePrincipal -DisplayName $ServicePrincipalName
    Remove-AzADSpCredential -DisplayName $ServicePrincipalName

    $spCredParameters = @{
        StartDate = [DateTime]::UtcNow
        EndDate = [DateTime]::UtcNow.AddYears(1)
        ObjectId = $AppSP.id
    }
    $SpCreds = New-AzADSpCredential @spCredParameters
    New-AzRoleAssignment -ObjectId $AppSP.Id -RoleDefinitionName 'Key Vault Secrets Officer' -Scope $SpScope


    Write-host ('$AppClientID="{0}"' -f $AppSP.AppId)
    Write-host ('$AppClientSecret="{0}"' -f $SpCreds.SecretText)


    # Create an App Service plan in Free tier.
    New-AzAppServicePlan -Name $webappname -Location $location -ResourceGroupName $resourceGroupName -Tier Free

    # STEP 2: Create key vault
    #https://docs.microsoft.com/en-us/azure/key-vault/general/assign-access-policy?tabs=azure-powershell
    New-AzKeyVault -Name $keyVaultName -ResourceGroupName $ResourceGroup -Location $location
    $SpAppId = (Get-AzADServicePrincipal -DisplayName $ServicePrincipalName).id
    Set-AzKeyVaultAccessPolicy -VaultName $keyVaultName -ResourceGroupName $ResourceGroup -ObjectId $SpAppId -PermissionsToSecrets get,set,delete
    Update-AzKeyVault -ResourceGroupName $ResourceGroup -VaultName $keyVaultName -EnableRbacAuthorization $true
#>
[CmdletBinding()]
Param()

##* ================================
##* VARIABLES
##* ================================
$UserName = 'IntuneAdmin'

$PasswordLength = 14

$Description = 'Intune generated local account'

$ComputerName = $env:COMPUTERNAME
$Group = 'Administrators'

# NOTE: Be sure to change these
$TenantId = "<tenantid>"
$AppClientID = "<clientid>"
$AppClientSecret = "<cleintsecret"
$keyVaultName = "devicelocaladminsecrets"
##* ================================
##* FUNCTION
##* ================================
function New-RandomPassword {
    <#
    .Synopsis
       Generates one or more complex passwords designed to fulfill the requirements for Active Directory
    .DESCRIPTION
       Generates one or more complex passwords designed to fulfill the requirements for Active Directory
    .EXAMPLE
       New-RandomPassword
       C&3SX6Kn

       Will generate one password with a length between 8 and 42 chars.
    .EXAMPLE
       New-RandomPassword -MinPasswordLength 8 -MaxPasswordLength 12 -Count 4
       7d&5cnaB
       !Bh776T"Fw
       9"C"RxKcY
       %mtM7#9LQ9h

       Will generate four passwords, each with a length of between 8 and 41 chars.
    .EXAMPLE
       New-RandomPassword -InputStrings abc, ABC, 123 -PasswordLength 4
       3ABa

       Generates a password with a length of 4 containing at least one char from each InputString
    .EXAMPLE
       New-RandomPassword -InputStrings abc, ABC, 123 -PasswordLength 4 -FirstChar abcdefghijkmnpqrstuvwxyzABCEFGHJKLMNPQRSTUVWXYZ
       3ABa

       Generates a password with a length of 4 containing at least one char from each InputString that will start with a letter from
       the string specified with the parameter FirstChar
    .OUTPUTS
       [String]
    .NOTES
       Written by Simon Wåhlin, blog.simonw.se
       I take no responsibility for any issues caused by this script.
    .FUNCTIONALITY
       Generates random passwords
    .LINK
       http://blog.simonw.se/powershell-generating-random-password-for-active-directory/

    #>
    [CmdletBinding(DefaultParameterSetName='FixedLength',ConfirmImpact='None')]
    [OutputType([String])]
    Param
    (
        # Specifies minimum password length
        [Parameter(Mandatory=$false,
                   ParameterSetName='RandomLength')]
        [ValidateScript({$_ -gt 0})]
        [Alias('Min')]
        [int]$MinPasswordLength = 8,

        # Specifies maximum password length
        [Parameter(Mandatory=$false,
                   ParameterSetName='RandomLength')]
        [ValidateScript({
                if($_ -ge $MinPasswordLength){$true}
                else{Throw 'Max value cannot be lesser than min value.'}})]
        [Alias('Max')]
        [int]$MaxPasswordLength = 42,

        # Specifies a fixed password length
        [Parameter(Mandatory=$false,
                   ParameterSetName='FixedLength')]
        [ValidateRange(1,2147483647)]
        [int]$PasswordLength = 12,

        # Specifies an array of strings containing charactergroups from which the password will be generated.
        # At least one char from each group (string) will be used.
        [String[]]$InputStrings = @('abcdefghijkmnpqrstuvwxyz', 'ABCEFGHJKLMNPQRSTUVWXYZ', '23456789', '!#%&'),

        # Specifies a string containing a character group from which the first character in the password will be generated.
        # Useful for systems which requires first char in password to be alphabetic.
        [String] $FirstChar,

        # Specifies number of passwords to generate.
        [ValidateRange(1,2147483647)]
        [int]$Count = 1
    )
    Begin {
        Function Get-Seed{
            # Generate a seed for randomization
            $RandomBytes = New-Object -TypeName 'System.Byte[]' 4
            $Random = New-Object -TypeName 'System.Security.Cryptography.RNGCryptoServiceProvider'
            $Random.GetBytes($RandomBytes)
            [BitConverter]::ToUInt32($RandomBytes, 0)
        }
    }
    Process {
        For($iteration = 1;$iteration -le $Count; $iteration++){
            $Password = @{}
            # Create char arrays containing groups of possible chars
            [char[][]]$CharGroups = $InputStrings

            # Create char array containing all chars
            $AllChars = $CharGroups | ForEach-Object {[Char[]]$_}

            # Set password length
            if($PSCmdlet.ParameterSetName -eq 'RandomLength')
            {
                if($MinPasswordLength -eq $MaxPasswordLength) {
                    # If password length is set, use set length
                    $PasswordLength = $MinPasswordLength
                }
                else {
                    # Otherwise randomize password length
                    $PasswordLength = ((Get-Seed) % ($MaxPasswordLength + 1 - $MinPasswordLength)) + $MinPasswordLength
                }
            }

            # If FirstChar is defined, randomize first char in password from that string.
            if($PSBoundParameters.ContainsKey('FirstChar')){
                $Password.Add(0,$FirstChar[((Get-Seed) % $FirstChar.Length)])
            }
            # Randomize one char from each group
            Foreach($Group in $CharGroups) {
                if($Password.Count -lt $PasswordLength) {
                    $Index = Get-Seed
                    While ($Password.ContainsKey($Index)){
                        $Index = Get-Seed
                    }
                    $Password.Add($Index,$Group[((Get-Seed) % $Group.Count)])
                }
            }

            # Fill out with chars from $AllChars
            for($i=$Password.Count;$i -lt $PasswordLength;$i++) {
                $Index = Get-Seed
                While ($Password.ContainsKey($Index)){
                    $Index = Get-Seed
                }
                $Password.Add($Index,$AllChars[((Get-Seed) % $AllChars.Count)])
            }
            Write-Output -InputObject $(-join ($Password.GetEnumerator() | Sort-Object -Property Name | Select-Object -ExpandProperty Value))
        }
    }
}

function Get-KeyVaultTokenFromAzureAD {
    # https://docs.microsoft.com/en-us/rest/api/keyvault/setsecret/setsecret
    # https://docs.microsoft.com/en-us/azure/app-service/overview-managed-identity?tabs=dotnet#using-the-rest-protocol
    [CmdletBinding()]
    param(
        $TenantId,
        $ClientId,
        $ClientSecret
    )
    $uri = "https://login.windows.net/$TenantId/oauth2/token"
    $apiVersion = '2018-02-01'

    $Body = @{
        'resource'= "https://vault.azure.net"
        'api-version'=$apiVersion
        'client_id' = $ClientID
        'grant_type' = 'client_credentials'
        'client_secret' = $ClientSecret
    }

    $headers = @{
        "Accept" = "application/json";
        "Content-Type" = "application/x-www-form-urlencoded";
    }

    Write-Verbose ("Token API Uri is [{0}]" -f $TokenEndpoint)
    Write-Debug ("{0}" -f ($params | ConvertTo-Json))
    $result = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $body

    if ($Null -eq $result.access_token) {
        Write-Error "[Veritas Information Map] Failed to get a token from AD for the Key Vault because the request failed with status $($result.StatusCode) and message $($result.error.message)"
    }
    Write-Verbose ("Bearer token is [{0}]" -f $token.access_token)
    return $result.access_token
}



function Set-KeyVaultSecretEntry {
    [CmdletBinding()]
    param(
        [String]$KeyVaultName,
        [String]$SecretName,
        [String]$SecretValue,
        [String]$AcessToken,
        [switch]$Disable,
        [switch]$Purgable
    )

    $vaultApiVersion = '2016-10-01'

    $uri = "https://$($KeyVaultName).vault.azure.net/secrets/$($SecretName)?api-version=$($vaultApiVersion)"


    If($Purgable){
        $attributes = @{enabled = !$Disable;recoveryLevel='Purgeable'}
    }Else{
        $attributes = @{enabled = !$Disable}
    }

    #build body
    $body = @{
        value = $Script:Password
        attributes = $attributes
    }| ConvertTo-Json

    $enc = New-Object "System.Text.ASCIIEncoding"
    $byteArray = $enc.GetBytes($body)
    $contentLength = $byteArray.Length
    $Headers = @{
      "Authorization" = "Bearer $AcessToken";
      "Content-Type" = "application/json";
      "Content-Length" = $contentLength;
    }
    Write-Debug ("Secret value is [{0}]" -f $SecretValue)
    Write-Verbose ("Vault API Uri is [{0}]" -f $uri)
    Write-Debug $body
    try {
        Invoke-RestMethod -Method PUT -Uri $Uri -Headers $Headers -Body $Body -ErrorAction Stop
    }
    catch {
        Write-Host ("{0}: {1}" -f $_.Exception.Response.StatusCode,$_.ErrorDetails.Message) -ForegroundColor Red
        return $_.Exception.Response.StatusCode
    }
}
##* ===============================
##* MAIN
##* ===============================

#Generate new password
$Script:Password = New-RandomPassword -PasswordLength $PasswordLength
$SecurePassword = ConvertTo-SecureString $Script:Password -AsPlainText -Force
$credentials = New-Object System.Management.Automation.PsCredential($UserName, $SecurePassword)

write-host "Attempting to connect to Key Vault using Managed Service Identity..."
$token = Get-KeyVaultTokenFromAzureAD -TenantId $TenantId -ClientId $AppClientID -ClientSecret $AppClientSecret

Write-Host ("Setting secret in Azure Key Vault for {0}..." -f $ComputerName)
Set-KeyVaultSecretEntry -KeyVaultName $keyVaultName -SecretName $ComputerName -SecretValue $Script:Password -AcessToken $token

$credentials | Export-Clixml "$env:temp\$UserName.xml" -Force

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
        Write-Host ("Updating new account [{0}] with new password..." -f $UserName) -NoNewline
        Set-LocalUser -Name $UserName -Password $SecurePassword -Description $Description -AccountNeverExpires -PasswordNeverExpires:$true -UserMayChangePassword:$false -ErrorAction Stop
        Write-Host ("Done") -ForegroundColor Green
    }
    Catch{
        Write-Host ("Failed: {0}" -f $_.Exception.Message) -ForegroundColor Red
    }
}

# Query current local group
$query="Associators of {Win32_Group.Domain='$ComputerName',Name='$Group'} where Role=GroupComponent"
$GroupQuery = Get-WmiObject -Query $query

#if user is not in the group, add it
If($UserName -notin $GroupQuery.Name)
{
    Write-Host ("Adding account [{0}] to [{1}] group..." -f $UserName,$Group) -NoNewline
    Add-LocalGroupMember -Group "Administrators" -Member $UserName -ErrorAction SilentlyContinue
    Write-Host ("Done") -ForegroundColor Green
}
Else{
    Write-Host ("Account [{0}] is already in the [{1}] group" -f $UserName,$Group) -ForegroundColor Green
}
