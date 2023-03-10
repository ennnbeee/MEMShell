Function Get-AuthTokenMSAL {

    <#
    .SYNOPSIS
    This function is used to authenticate with the Graph API REST interface
    .DESCRIPTION
    The function authenticate with the Graph API Interface with the tenant name
    .EXAMPLE
    Get-AuthTokenMSAL
    Authenticates you with the Graph API interface using MSAL.PS module
    .NOTES
    NAME: Get-AuthTokenMSAL
    #>

    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$User
    )

    $userUpn = New-Object 'System.Net.Mail.MailAddress' -ArgumentList $User

    if ($userUpn.Host -like '*onmicrosoft.com*') {
        $tenant = Read-Host -Prompt 'Please specify your Tenant name i.e. company.com'
    }
    else {
        $tenant = $userUpn.Host
    }

    Write-Information 'Checking for MSAL.PS module...'

    $MSALModule = Get-Module -Name 'MSAL.PS' -ListAvailable

    if ($null -eq $MSALModule) {
        Write-Information 'MSAL.PS Powershell module not installed...'
        Write-Information "Install by running 'Install-Module MSAL.PS -Scope CurrentUser' from an elevated PowerShell prompt"
        Write-Error "Script can't continue..."
        break
    }

    if ($MSALModule.count -gt 1) {
        $Latest_Version = ($MSALModule | Select-Object version | Sort-Object)[-1]
        $MSALModule = $MSALModule | Where-Object { $_.version -eq $Latest_Version.version }
        if ($MSALModule.count -gt 1) {
            $MSALModule = $MSALModule | Select-Object -Unique
        }
    }

    $ClientId = 'd1ddf0e4-d672-4dae-b554-9d5bdfd93547'
    $RedirectUri = 'urn:ietf:wg:oauth:2.0:oob'
    $Authority = "https://login.microsoftonline.com/$Tenant"

    try {
        Import-Module $MSALModule.Name

        if ($PSVersionTable.PSVersion.Major -ne 7) {
            $authResult = Get-MsalToken -ClientId $ClientId -Interactive -RedirectUri $RedirectUri -Authority $Authority
        }
        else {
            $authResult = Get-MsalToken -ClientId $ClientId -Interactive -RedirectUri $RedirectUri -Authority $Authority -DeviceCode
        }

        if ($authResult.AccessToken) {
            $authHeader = @{
                'Content-Type'  = 'application/json'
                'Authorization' = 'Bearer ' + $authResult.AccessToken
                'ExpiresOn'     = $authResult.ExpiresOn
            }
            return [OutputType('System.Collections.Hashtable')]$authHeader
        }
        else {
            Write-Information 'Authorization Access Token is null, please re-run authentication...'
            break
        }
    }
    catch {
        Write-Error $_.Exception.Message
        Write-Error $_.Exception.ItemName
        break
    }
}