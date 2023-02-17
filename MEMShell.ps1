$ModuleName = 'MEMShell'

$Params = @{
    Path                 = "$ModuleName.psd1"
    RootModule           = "$ModuleName.psm1"
    GUID                 = "$(New-Guid)"
    Author               = 'Nick Benton'
    CompanyName          = 'MEM v ENNBEE'
    Copyright            = '(c) Nick Benton. All rights reserved.'
    Description          = 'Unifying all created Graph and PowerShell functions for Modern Device Management into one giant Module'
    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Core', 'Desktop')
    RequiredModules      = @('MSAL.PS')
    ModuleVersion        = '9.9.9' # Leave as is!
    PrivateData          = @{
        Prerelease   = ''
        ReleaseNotes = ''
        Tags         = 'intune'
        LicenseUri   = 'https://github.com/ennnbeee/MEMShell/blob/main/LICENSE'
        ProjectUri   = 'https://github.com/ennnbeee/MEMShell'
        IconUri      = 'https://raw.githubusercontent.com/ennnbeee/MEMShell/main/MEMShell.png'
    }
    FunctionsToExport    = @('<FunctionsToExport>') # leave as is!
}

$Path = ".\MEMShell\$($ModuleName).psd1"
New-ModuleManifest -Path $Path
Update-ModuleManifest -Path $Path  @Params

((Get-Content -Path $Path) -replace '9.9.9', '<ModuleVersion>') |
Set-Content -Path $Path

