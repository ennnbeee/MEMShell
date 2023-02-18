param(
    [version]$Version,
    [string]$APIKey
)
#Requires -Module ModuleBuilder

$Output = "$PSScriptRoot\Output\MEMShell"

$Params = @{
    SourcePath = "$PSScriptRoot\Source\MEMShell.psd1"
    #CopyPaths = @("$PSScriptRoot\README.md")
    Version = $Version
    #UnversionedOutputDirectory = $true
}

Build-Module @params

Publish-Module -Name $Output -NuGetApiKey $APIKey -SkipAutomaticTags