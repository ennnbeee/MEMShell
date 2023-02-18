Function Export-JSONSettings() {

    <#
    .SYNOPSIS
    This function is used to get autopilot devices via the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any autopilot devices
    .EXAMPLE
    Get-AutopilotDevices
    Returns any autopilot devices
    .NOTES
    NAME: Get-AutopilotDevices
    #>
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory = $true)]
        [string]$Path,

        [parameter(Mandatory = $true)]
        $Settings
    )

    try {
        $Path = $Path.replace('"','')
        if (!(Test-Path "$Path")) {
            $Confirm = Read-Host "Path '$Path' doesn't exist, do you want to create this directory? Y or N?"
            if ($Confirm -eq 'y' -or $Confirm -eq 'Y') {
                New-Item -ItemType Directory -Path "$Path" | Out-Null
            }
            else {
                Write-Error 'Creation of directory path was cancelled...'
                break
            }
        }

        foreach ($Setting in $Settings) {
            Export-JSONData -JSON $Setting -ExportPath $Path
        }

    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }

}