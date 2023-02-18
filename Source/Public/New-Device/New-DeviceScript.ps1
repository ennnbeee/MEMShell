Function New-DeviceManagementScript() {

    <#
    .SYNOPSIS
    This function is used to get Deivce Enrollment Configurations from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets Device Enrollment Configurations
    .EXAMPLE
    Get-DeviceEnrollmentConfigurations
    Returns Device Enrollment Configurations configured in Intune
    .NOTES
    NAME: Get-DeviceEnrollmentConfigurations
    #>

    [cmdletbinding(SupportsShouldProcess, ConfirmImpact='Medium')]
    Param (
        # Path or URL to Powershell-script to add to Intune
        [Parameter(Mandatory = $true)]
        [string]$File,

        # PowerShell description in Intune
        [Parameter(Mandatory = $false)]
        [string]$Description
    )

    if (!(Test-Path $File)) {
        Write-Output "$File could not be located."
        break
    }
    $FileName = Get-Item $File | Select-Object -ExpandProperty Name
    $DisplayName = $FileName.Split('.')[0]
    $B64File = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes("$File"));

    $JSON = @"
{
    "@odata.type": "#microsoft.graph.deviceManagementScript",
    "displayName": "$DisplayName",
    "description": "$Description",
    "runSchedule": {
    "@odata.type": "microsoft.graph.runSchedule"
},
    "scriptContent": "$B64File",
    "runAsAccount": "system",
    "enforceSignatureCheck": "false",
    "fileName": "$FileName"
}
"@

    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/deviceManagementScripts'

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        if ($PSCmdlet.ShouldProcess('ShouldProcess?')) {
            Invoke-MEMRestMethod -Uri $uri -Method Post -Body $JSON
        }
    }

    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}