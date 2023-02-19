Function New-DeviceComplianceScript() {

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

    [cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    Param (
        # Path or URL to Compliance Script to add to Intune
        [Parameter(Mandatory = $true)]
        [string]$File,

        [string]$Publisher

    )

    if (!(Test-Path $File)) {
        Write-Host "$File could not be located." -ForegroundColor Red
        break
    }
    $FileName = Get-Item $File | Select-Object -ExpandProperty Name
    $DisplayName = $FileName.Split('.')[0]
    $B64File = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes("$File"));

    $JSON = @"
{
    "id": "",
    "displayName": "$DisplayName",
    "description": "",
    "publisher": "$Publisher",
    "detectionScriptContent": "$B64File",
    "runAsAccount": "system",
    "enforceSignatureCheck": false,
    "runAs32Bit": true
}
"@

    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/deviceComplianceScripts'

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