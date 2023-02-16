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

$Files = Get-ChildItem -Path "$PSScriptRoot\Output\"
Foreach ($File in $Files){
    Move-Item -Path $File.FullName -Destination "$PSScriptRoot\Source" -Force

}
Remove-Item -Path "$PSScriptRoot\Output" -Recurse -Force

