#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only search for portrait-related text references in an NBA 2K executable.
.DESCRIPTION
    Searches ASCII and UTF-16LE text, including strings crossing chunk boundaries.
    Returns file offsets, not memory addresses or verified hooks. No game attachment.
.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\tools\portrait_string_probe.ps1" -Executable "D:\SteamLibrary\steamapps\common\NBA 2K26\NBA2K26.exe" -Json
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string] $Executable,
    [switch] $Json,
    [ValidateRange(512, 16777216)]
    [int] $ChunkBytes = 4194304,
    [ValidateRange(1, 100)]
    [int] $MaxPerTerm = 8
)

$ErrorActionPreference = 'Stop'
$resolvedPath = (Resolve-Path -LiteralPath $Executable -ErrorAction Stop).ProviderPath
if (-not [IO.File]::Exists($resolvedPath)) { throw 'Executable path is not a file.' }

# Deliberately narrow to words that could identify portrait-related strings.
$pattern = 'portrait|headshot|action[_ ]?shot|action[_ ]?photo|player[_ ]?photo|photo[_ ]?id|team[_ ]?photo'
$regex = New-Object System.Text.RegularExpressions.Regex(
    $pattern,
    ([System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
     [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)
)
$ascii = [Text.Encoding]::GetEncoding(28591)
$utf16 = [Text.Encoding]::Unicode
$matches = New-Object 'System.Collections.Generic.List[object]'
$counts = @{}
$shown = @{}
$seen = New-Object 'System.Collections.Generic.HashSet[string]'
$processedUntil = [long]0

function Add-Text-Matches {
    param(
        [string] $Decoded,
        [string] $EncodingLabel,
        [int] $BytesPerCharacter,
        [long] $ChunkStart,
        [int] $Alignment
    )
    foreach ($item in $regex.Matches($Decoded)) {
        $position = $ChunkStart + [long]$Alignment + ([long]$item.Index * [long]$BytesPerCharacter)
        $end = $position + ([long]$item.Length * [long]$BytesPerCharacter)
        if ($end -le $processedUntil) { continue }

        $name = [regex]::Replace($item.Value.ToLowerInvariant(), '[_ ]', '')
        $identity = '{0}:{1}:{2}' -f $EncodingLabel, $position, $name
        if (-not $seen.Add($identity)) { continue }

        if (-not $counts.ContainsKey($name)) {
            $counts[$name] = 0
            $shown[$name] = 0
        }
        $counts[$name] = [int]$counts[$name] + 1
        if ([int]$shown[$name] -ge $MaxPerTerm) { continue }
        $shown[$name] = [int]$shown[$name] + 1

        $left = [Math]::Max(0, $item.Index - 45)
        $right = [Math]::Min($Decoded.Length, $item.Index + $item.Length + 45)
        $context = $Decoded.Substring($left, $right - $left)
        $context = [regex]::Replace($context, '[^\x20-\x7E]', '.')
        $matches.Add([pscustomobject][ordered]@{
            term = $name
            file_offset_decimal = $position
            encoding = $EncodingLabel
            context = $context
        })
    }
}

$stream = [IO.File]::Open($resolvedPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
try {
    $size = [long]$stream.Length
    $buffer = New-Object byte[] $ChunkBytes
    $carry = [byte[]]@()
    while ($true) {
        $startOfNewBytes = [long]$stream.Position
        $read = $stream.Read($buffer, 0, $buffer.Length)
        if ($read -le 0) { break }

        $combined = New-Object byte[] ($carry.Length + $read)
        if ($carry.Length -gt 0) { [Array]::Copy($carry, 0, $combined, 0, $carry.Length) }
        [Array]::Copy($buffer, 0, $combined, $carry.Length, $read)
        $combinedStart = $startOfNewBytes - [long]$carry.Length

        Add-Text-Matches -Decoded ($ascii.GetString($combined)) -EncodingLabel 'ASCII' -BytesPerCharacter 1 -ChunkStart $combinedStart -Alignment 0
        # Test both byte alignments for UTF-16LE strings.
        for ($alignment = 0; $alignment -lt 2; $alignment++) {
            $available = $combined.Length - $alignment
            $evenLength = $available - ($available % 2)
            if ($evenLength -ge 2) {
                Add-Text-Matches -Decoded ($utf16.GetString($combined, $alignment, $evenLength)) -EncodingLabel 'UTF-16LE' -BytesPerCharacter 2 -ChunkStart $combinedStart -Alignment $alignment
            }
        }

        $processedUntil = [long]$stream.Position
        $carrySize = [Math]::Min(256, $combined.Length)
        $carry = New-Object byte[] $carrySize
        [Array]::Copy($combined, $combined.Length - $carrySize, $carry, 0, $carrySize)
    }
}
finally {
    $stream.Dispose()
}

$report = [ordered]@{
    filename = [IO.Path]::GetFileName($resolvedPath)
    scanned_bytes = $size
    evidence_type = 'Static text search only; offsets are in the file, not game memory.'
    total_matches = [int](($counts.Values | Measure-Object -Sum).Sum)
    counts_by_term = $counts
    samples = @($matches | Sort-Object file_offset_decimal)
}
if ($Json) {
    ConvertTo-Json -InputObject $report -Depth 8
}
else {
    Write-Output ('Read-only scan: {0}' -f $report.filename)
    Write-Output ('Scanned bytes: {0}; text matches: {1}' -f $report.scanned_bytes, $report.total_matches)
    foreach ($row in $report.samples) {
        Write-Output ('{0} | {1} at file offset {2}: {3}' -f $row.term, $row.encoding, $row.file_offset_decimal, $row.context)
    }
    if ($report.total_matches -eq 0) {
        Write-Output 'No text matches. This does not rule out a portrait-selection function.'
    }
}
