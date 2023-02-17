param (
    [string] $buildVersion,
    [string] $apiKey
)

$Global:ErrorActionPreference = 'Stop'
$Global:VerbosePreference = 'SilentlyContinue'

$manifestPath = './MEMShell/MEMShell.psd1'
$publicFuncFolderPath = './MEMShell'

if (!(Get-PackageProvider | Where-Object { $_.Name -eq 'NuGet' })) {
    Install-PackageProvider -Name NuGet -Force | Out-Null
}
Import-PackageProvider -Name NuGet -Force | Out-Null

if ((Get-PSRepository -Name PSGallery).InstallationPolicy -ne 'Trusted') {
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
}

$manifestContent = (Get-Content -Path $manifestPath -Raw) -replace "'<ModuleVersion>'", $buildVersion

if ((Test-Path -Path $publicFuncFolderPath) -and ($publicFunctionNames = Get-ChildItem -Path $publicFuncFolderPath -Recurse -Filter '*.ps1' | Select-Object -ExpandProperty BaseName)) {
    $FuncStrings = "'$($publicFunctionNames -join "','")'"
}
else {
    $FuncStrings = $null
}

$manifestContent = $manifestContent -replace "'<FunctionsToExport>'", $funcStrings
$manifestContent | Set-Content -Path $manifestPath

Publish-Module -Path ./MEMShell -NuGetApiKey $apiKey -Verbose