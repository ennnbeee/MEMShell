param(
    [version]$Version = "1.0.0"
)
#Requires -Module ModuleBuilder

$Params = @{
    SourcePath = "$PSScriptRoot\Source\MEMShell.psd1"
    CopyPaths = @("$PSScriptRoot\README.md")
    Version = $Version
    #UnversionedOutputDirectory = $true
}

Build-Module @params