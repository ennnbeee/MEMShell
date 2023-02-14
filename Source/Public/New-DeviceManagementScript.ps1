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
        
    [cmdletbinding()]
    
    Param (
        # Path or URL to Powershell-script to add to Intune
        [Parameter(Mandatory = $true)]
        [string]$File,
        # PowerShell description in Intune
        [Parameter(Mandatory = $false)]
        [string]$Description,
        # Set to true if it is a URL
        [Parameter(Mandatory = $false)]
        [switch][bool]$URL = $false
    )
    if ($URL -eq $true) {
        $FileName = $File -split '/'
        $FileName = $FileName[-1]
        $OutFile = "$env:TEMP\$FileName"
        try {
            Invoke-WebRequest -Uri $File -UseBasicParsing -OutFile $OutFile
        }
        catch {
            Write-Host "Could not download file from URL: $File" -ForegroundColor Red
            break
        }
        $File = $OutFile
        if (!(Test-Path $File)) {
            Write-Host "$File could not be located." -ForegroundColor Red
            break
        }
    }
    elseif ($URL -eq $false) {
        if (!(Test-Path $File)) {
            Write-Host "$File could not be located." -ForegroundColor Red
            break
        }
        $FileName = Get-Item $File | Select-Object -ExpandProperty Name
        $DisplayName = $FileName.Split('.')[0]
        $B64File = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes("$File"));

        if ($URL -eq $true) {
            Remove-Item $File -Force
        }

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
        $DMS_resource = 'deviceManagement/deviceManagementScripts'
        Write-Verbose "Resource: $DMS_resource"

        try {
            $uri = "https://graph.microsoft.com/$graphApiVersion/$DMS_resource"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType 'application/json'
        }

        catch {
            $exs = $Error.ErrorDetails
            $ex = $exs[0]
            Write-Host "Response content:`n$ex" -f Red
            Write-Host
            Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
            Write-Host
        }
    }
}