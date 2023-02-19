param(
    [Parameter(Mandatory = $true)]
    [version]$Version,

    [string]$APIKey,

    [switch]$Publish
)

#Requires -Module ModuleBuilder

$Output = "$PSScriptRoot\Output\MEMShell"

$Params = @{
    SourcePath = "$PSScriptRoot\Source\MEMShell.psd1"
    #CopyPaths = @("$PSScriptRoot\README.md")
    Version    = $Version
    #UnversionedOutputDirectory = $true
}

Build-Module @params

If ($Publish) {
    Publish-Module -Name $Output -NuGetApiKey $APIKey -SkipAutomaticTags
}