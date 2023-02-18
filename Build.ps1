param(
    [version]$Version
)
#Requires -Module ModuleBuilder

$Params = @{
    SourcePath = "$PSScriptRoot\Source\MEMShell.psd1"
    #CopyPaths = @("$PSScriptRoot\README.md")
    Version = $Version
    #UnversionedOutputDirectory = $true
}

Build-Module @params