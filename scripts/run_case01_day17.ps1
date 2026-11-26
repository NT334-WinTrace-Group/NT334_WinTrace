param(
    [string]$OutputDirectory = ""
)

$ErrorActionPreference = "Stop"
$RepositoryRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepositoryRoot

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $env:TEMP (
        "wintrace-case01-day17-" + [guid]::NewGuid().ToString("N")
    )
}
$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)

if (Test-Path $OutputDirectory) {
    if (@(Get-ChildItem -LiteralPath $OutputDirectory -Force).Count -gt 0) {
        throw "Output directory must be empty: $OutputDirectory"
    }
}
else {
    New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
}

$SupportingEvents = "analysis\phuc-artifacts\case01_supporting_events.csv"
$ShellBagsEvents = "results\case01_shellbags_events.csv"
foreach ($InputPath in @($SupportingEvents, $ShellBagsEvents)) {
    if (-not (Test-Path $InputPath -PathType Leaf)) {
        throw "Required CASE01 input is missing: $InputPath"
    }
}

$Python = (Get-Command python -ErrorAction Stop).Source
$Database = Join-Path $OutputDirectory "case01_timeline.db"
$Normalized = Join-Path $OutputDirectory "case01_normalized.json"
$ErrorLog = Join-Path $OutputDirectory "case01_errors.json"
$PipelineArgs = @(
    "src\pipeline.py",
    "--input", $SupportingEvents,
    "--shellbags", $ShellBagsEvents,
    "--output", $Normalized,
    "--database", $Database,
    "--error-log", $ErrorLog,
    "--case-id", "CASE01",
    "--source-label", "case01-supporting-tools"
)

$Log2Timeline = Get-Command log2timeline.py -ErrorAction SilentlyContinue
$Psort = Get-Command psort.py -ErrorAction SilentlyContinue
$Log2TimelinePath = if ($Log2Timeline) { $Log2Timeline.Source } else { "not available" }
$PsortPath = if ($Psort) { $Psort.Source } else { "not available" }
$Metadata = Join-Path $OutputDirectory "execution_metadata.txt"
$InputHashes = Get-FileHash $SupportingEvents, $ShellBagsEvents -Algorithm SHA256
@(
    "started_utc=$([DateTime]::UtcNow.ToString('o'))"
    "python=$((& $Python --version 2>&1 | Out-String).Trim())"
    "log2timeline.py=$Log2TimelinePath"
    "psort.py=$PsortPath"
    "supporting_events_sha256=$($InputHashes[0].Hash.ToLowerInvariant())"
    "shellbags_events_sha256=$($InputHashes[1].Hash.ToLowerInvariant())"
    "pipeline_command=python $($PipelineArgs -join ' ')"
    "note=This imports committed parser outputs; it does not run Plaso extraction."
) | Set-Content -LiteralPath $Metadata -Encoding UTF8

function Invoke-PipelineRun {
    param([int]$RunNumber)

    $stdoutPath = Join-Path $OutputDirectory "run$RunNumber.stdout.log"
    $stderrPath = Join-Path $OutputDirectory "run$RunNumber.stderr.log"
    & $Python @PipelineArgs 1> $stdoutPath 2> $stderrPath
    $exitCode = $LASTEXITCODE
    Add-Content -LiteralPath $Metadata -Value "run$RunNumber.exit_code=$exitCode"
    if ($exitCode -ne 0) {
        throw "Pipeline run $RunNumber failed with exit code $exitCode. See $stderrPath"
    }
    if (Test-Path $ErrorLog) {
        throw "Normalization rejected records. See $ErrorLog"
    }

    $stdout = Get-Content -LiteralPath $stdoutPath -Raw
    if ($stdout -notmatch "SQLite timeline:\s+(\d+) new events,\s+(\d+) total events") {
        throw "Pipeline run $RunNumber did not report SQLite counts. See $stdoutPath"
    }
    [pscustomobject]@{
        NewEvents = [int]$Matches[1]
        TotalEvents = [int]$Matches[2]
    }
}

$FirstRun = Invoke-PipelineRun -RunNumber 1
if ($FirstRun.NewEvents -ne $FirstRun.TotalEvents) {
    throw "Fresh database did not insert every normalized event."
}
$SecondRun = Invoke-PipelineRun -RunNumber 2
if ($SecondRun.NewEvents -ne 0 -or $SecondRun.TotalEvents -ne $FirstRun.TotalEvents) {
    throw "Repeated import changed the database row count."
}

$QueryPath = Join-Path $OutputDirectory "database_query_counts.json"
$QueryErrorPath = Join-Path $OutputDirectory "database_query.stderr.log"
& $Python "scripts\query_case01_day17.py" $Database 1> $QueryPath 2> $QueryErrorPath
if ($LASTEXITCODE -ne 0) {
    throw "SQLite count query failed. See $QueryErrorPath"
}

$Counts = Get-Content -LiteralPath $QueryPath -Raw | ConvertFrom-Json
if ($Counts.total_events -ne $Counts.unique_event_ids) {
    throw "Database contains duplicate event IDs."
}
if ($Counts.events_with_evidence_reference -ne $Counts.total_events) {
    throw "Some imported events do not have evidence references."
}
if ($Counts.total_events -ne $FirstRun.TotalEvents) {
    throw "Pipeline and SQLite query totals do not match."
}

Add-Content -LiteralPath $Metadata -Value "first_run.new_events=$($FirstRun.NewEvents)"
Add-Content -LiteralPath $Metadata -Value "first_run.total_events=$($FirstRun.TotalEvents)"
Add-Content -LiteralPath $Metadata -Value "second_run.new_events=$($SecondRun.NewEvents)"
Add-Content -LiteralPath $Metadata -Value "second_run.total_events=$($SecondRun.TotalEvents)"
Add-Content -LiteralPath $Metadata -Value "database=$Database"

Write-Output "CASE01 pipeline import passed."
Write-Output "First run: $($FirstRun.NewEvents) inserted / $($FirstRun.TotalEvents) total."
Write-Output "Second run: $($SecondRun.NewEvents) inserted / $($SecondRun.TotalEvents) total."
Write-Output "SQLite counts: $QueryPath"
Write-Output "Run logs and database: $OutputDirectory"
