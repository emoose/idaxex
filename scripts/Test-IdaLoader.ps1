param(
    [Parameter(Mandatory = $true)]
    [string]$IdaExe,
    [Parameter(Mandatory = $true)]
    [string]$InputFile,
    [string]$LogPath,
    [string]$OutputDatabase,
    [string]$FileType,
    [string]$Processor,
    [int]$TimeoutSeconds = 180
)

if (-not (Test-Path $IdaExe)) {
    throw "IDA executable not found: $IdaExe"
}

if (-not (Test-Path $InputFile)) {
    throw "Input file not found: $InputFile"
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$scriptPath = Join-Path $PSScriptRoot 'Test-IdaLoader.py'
$smokeDir = Join-Path $repoRoot 'smoke'
New-Item -ItemType Directory -Force -Path $smokeDir | Out-Null

function Quote-IdaArgument {
    param([Parameter(Mandatory = $true)][string]$Argument)

    if ($Argument -notmatch '[\s"]') {
        return $Argument
    }

    '"' + ($Argument -replace '"', '\"') + '"'
}

if (-not $LogPath) {
    $baseName = [IO.Path]::GetFileNameWithoutExtension($InputFile)
    $LogPath = Join-Path $smokeDir "$baseName-idat.log"
}

$baseName = [IO.Path]::GetFileNameWithoutExtension($InputFile)
if (-not $OutputDatabase) {
    $OutputDatabase = Join-Path $smokeDir "$baseName.i64"
}

foreach ($outputPath in @($LogPath, $OutputDatabase)) {
    $outputDir = Split-Path -Parent $outputPath
    if ($outputDir) {
        New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
    }
    if (Test-Path -LiteralPath $outputPath) {
        Remove-Item -LiteralPath $outputPath -Force
    }
}

$arguments = @(
    '-A'
    '-c'
    "-L$LogPath"
    "-o$OutputDatabase"
    "-S$scriptPath"
)

if ($FileType) {
    $arguments += "-T$FileType"
}

if ($Processor) {
    $arguments += "-p$Processor"
}

$arguments += $InputFile

$argumentLine = ($arguments | ForEach-Object { Quote-IdaArgument $_ }) -join ' '
$process = Start-Process -FilePath $IdaExe -ArgumentList $argumentLine -WindowStyle Hidden -PassThru
if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
    Stop-Process -Id $process.Id -Force
    throw "IDA batch smoke test timed out after $TimeoutSeconds seconds."
}

if ($process.ExitCode -ne 0) {
    throw "IDA batch smoke test exited with code $($process.ExitCode). See $LogPath"
}

Write-Host "OutputDatabase: $OutputDatabase"
if (Test-Path $LogPath) {
    Get-Content $LogPath -Tail 200
} else {
    Write-Host "Smoke test exited cleanly, but IDA did not emit a log file."
}
