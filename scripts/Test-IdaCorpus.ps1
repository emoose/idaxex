param(
    [Parameter(Mandatory = $true)]
    [string]$IdaExe,
    [Parameter(Mandatory = $true)]
    [string]$InputRoot,
    [Parameter(Mandatory = $true)]
    [string]$OutputRoot,
    [int]$TimeoutSeconds = 300,
    [string]$Magic = 'XEX0;XEX1;XEX2;XEX-;XEX?;XEX%;XBEH',
    [string]$ExcludeSHA256 = '',
    [int]$MaximumCases = 0,
    [switch]$KeepDatabases
)

$ErrorActionPreference = 'Stop'
$loaderRunner = Join-Path $PSScriptRoot 'Test-IdaLoader.ps1'
$recognizedMagic = @('XEX0', 'XEX1', 'XEX2', 'XEX-', 'XEX?', 'XEX%', 'XBEH')
$inputRoots = @($InputRoot -split ';' | Where-Object { $_ })
$selectedMagic = @($Magic -split ';' | Where-Object { $_ })
$excludedHashes = @($ExcludeSHA256 -split ';' | Where-Object { $_ })

foreach ($root in $inputRoots) {
    if (-not (Test-Path -LiteralPath $root)) {
        throw "Input root not found: $root"
    }
}

New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null
$logRoot = Join-Path $OutputRoot 'logs'
$databaseRoot = Join-Path $OutputRoot 'databases'
New-Item -ItemType Directory -Force -Path $logRoot, $databaseRoot | Out-Null

$candidates = foreach ($root in $inputRoots) {
    Get-ChildItem -LiteralPath $root -Recurse -File |
        Where-Object { $_.Extension.ToLowerInvariant() -in @('.xex', '.exe', '.xbe') } |
        ForEach-Object {
            $stream = [IO.File]::OpenRead($_.FullName)
            try {
                $header = New-Object byte[] 4
                $bytesRead = $stream.Read($header, 0, 4)
                $magic = if ($bytesRead -eq 4) {
                    [Text.Encoding]::ASCII.GetString($header)
                } else {
                    '<short>'
                }
            } finally {
                $stream.Dispose()
            }

            [pscustomobject]@{
                Root = $root
                Path = $_.FullName
                Bytes = $_.Length
                Magic = $magic
                SHA256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
            }
        }
}

$recognized = @($candidates | Where-Object {
    $_.Magic -in $recognizedMagic -and $_.Magic -in $selectedMagic
})
$uniqueAll = @(
    $recognized |
        Sort-Object Magic, SHA256, Path |
        Group-Object SHA256 |
        ForEach-Object {
            $canonical = $_.Group | Sort-Object Path | Select-Object -First 1
            [pscustomobject]@{
                Root = $canonical.Root
                Path = $canonical.Path
                Bytes = $canonical.Bytes
                Magic = $canonical.Magic
                SHA256 = $canonical.SHA256
                CopyCount = $_.Count
                AllPaths = ($_.Group.Path -join ' | ')
            }
        } |
        Sort-Object Magic, SHA256
)
$excluded = @($uniqueAll | Where-Object { $_.SHA256 -in $excludedHashes })
$unique = @($uniqueAll | Where-Object { $_.SHA256 -notin $excludedHashes })
if ($MaximumCases -gt 0) {
    $unique = @($unique | Select-Object -First $MaximumCases)
}

$inventoryPath = Join-Path $OutputRoot 'inventory.csv'
$excludedPath = Join-Path $OutputRoot 'excluded.csv'
$resultsPath = Join-Path $OutputRoot 'results.csv'
$recognized | Sort-Object SHA256, Path | Export-Csv -LiteralPath $inventoryPath -NoTypeInformation
$excluded | Export-Csv -LiteralPath $excludedPath -NoTypeInformation

$results = [Collections.Generic.List[object]]::new()
for ($index = 0; $index -lt $unique.Count; $index++) {
    $item = $unique[$index]
    $caseId = '{0:D3}-{1}-{2}' -f ($index + 1), ($item.Magic -replace '[^A-Za-z0-9]', '_'), $item.SHA256.Substring(0, 12)
    $logPath = Join-Path $logRoot "$caseId.log"
    $runnerPath = Join-Path $logRoot "$caseId.runner.log"
    $databasePath = Join-Path $databaseRoot "$caseId.i64"
    $started = Get-Date
    $exitCode = 0
    $errorMessage = ''

    Write-Host ('[{0}/{1}] {2} {3}' -f ($index + 1), $unique.Count, $item.Magic, $item.Path)
    try {
        & $loaderRunner `
            -IdaExe $IdaExe `
            -InputFile $item.Path `
            -LogPath $logPath `
            -OutputDatabase $databasePath `
            -TimeoutSeconds $TimeoutSeconds *> $runnerPath
    } catch {
        $exitCode = 1
        $errorMessage = $_.Exception.Message
    }

    $verification = $null
    if (Test-Path -LiteralPath $logPath) {
        $marker = Get-Content -LiteralPath $logPath |
            Where-Object { $_ -like '[[]idaxex-verify[]]*' } |
            Select-Object -Last 1
        if ($marker) {
            try {
                $verification = ($marker -replace '^\[idaxex-verify\]\s*', '') | ConvertFrom-Json
            } catch {
                $errorMessage = "Unable to parse verification record: $($_.Exception.Message)"
                $exitCode = 1
            }
        }
    }

    if (-not $verification) {
        $exitCode = 1
        if (-not $errorMessage) {
            $errorMessage = 'IDA did not emit a verification record.'
        }
    } elseif (-not $verification.passed) {
        $exitCode = 1
        $errorMessage = ($verification.errors -join '; ')
    }

    $results.Add([pscustomobject]@{
        Case = $caseId
        Passed = ($exitCode -eq 0)
        Magic = $item.Magic
        SHA256 = $item.SHA256
        Bytes = $item.Bytes
        CopyCount = $item.CopyCount
        Path = $item.Path
        AllPaths = $item.AllPaths
        FileType = if ($verification) { $verification.file_type } else { '' }
        Processor = if ($verification) { $verification.processor } else { '' }
        Segments = if ($verification) { $verification.segment_count } else { '' }
        LoadedSegments = if ($verification) { $verification.loaded_segment_count } else { '' }
        Functions = if ($verification) { $verification.function_count } else { '' }
        Entries = if ($verification) { $verification.entry_count } else { '' }
        Names = if ($verification) { $verification.name_count } else { '' }
        ImportModules = if ($verification) { $verification.import_module_count } else { '' }
        Warnings = if ($verification) { $verification.warnings -join '; ' } else { '' }
        Error = $errorMessage
        Seconds = [Math]::Round(((Get-Date) - $started).TotalSeconds, 1)
        LogPath = $logPath
        DatabasePath = $databasePath
    })
    $results | Export-Csv -LiteralPath $resultsPath -NoTypeInformation

    if (-not $KeepDatabases -and $exitCode -eq 0 -and (Test-Path -LiteralPath $databasePath)) {
        Remove-Item -LiteralPath $databasePath -Force
    }
}

$failed = @($results | Where-Object { -not $_.Passed })
$summary = [pscustomobject]@{
    CandidatePaths = $candidates.Count
    RecognizedPaths = $recognized.Count
    UniqueRecognizedFiles = $uniqueAll.Count
    DuplicatePathsExcluded = $recognized.Count - $uniqueAll.Count
    ExplicitlyExcludedFiles = $excluded.Count
    SelectedCases = $unique.Count
    Passed = $results.Count - $failed.Count
    Failed = $failed.Count
    Inventory = $inventoryPath
    Exclusions = $excludedPath
    Results = $resultsPath
}

$summary | Format-List
if ($failed) {
    exit 1
}
