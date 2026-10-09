$ErrorActionPreference = 'Stop'
$tool = Join-Path $PSScriptRoot '..\tools\portrait_string_probe.ps1'
$folder = Join-Path ([IO.Path]::GetTempPath()) ('portrait-static-test-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($folder) | Out-Null

try {
    $path = Join-Path $folder 'NBA2K26.exe'
    $image = New-Object byte[] 3072
    [Array]::Copy([Text.Encoding]::ASCII.GetBytes('PORTRAIT'), 0, $image, 100, 8)
    # ASCII match crosses a 1024-byte block boundary.
    $headshot = [Text.Encoding]::ASCII.GetBytes('Headshot')
    [Array]::Copy($headshot, 0, $image, 1020, $headshot.Length)
    # UTF-16LE match starts at an odd file offset.
    $action = [Text.Encoding]::Unicode.GetBytes('ActionShot')
    [Array]::Copy($action, 0, $image, 1701, $action.Length)
    [IO.File]::WriteAllBytes($path, $image)

    $json = & $tool -Executable $path -Json -ChunkBytes 1024 -MaxPerTerm 10
    $report = $json | ConvertFrom-Json
    if ($report.scanned_bytes -ne 3072) { throw 'Unexpected scanned byte count' }
    $found = @($report.samples)
    if (-not ($found | Where-Object { $_.term -eq 'portrait' -and $_.encoding -eq 'ASCII' -and $_.file_offset_decimal -eq 100 })) {
        throw 'Missing ASCII portrait match'
    }
    if (-not ($found | Where-Object { $_.term -eq 'headshot' -and $_.encoding -eq 'ASCII' -and $_.file_offset_decimal -eq 1020 })) {
        throw 'Missing ASCII cross-boundary headshot match'
    }
    if (-not ($found | Where-Object { $_.term -eq 'actionshot' -and $_.encoding -eq 'UTF-16LE' -and $_.file_offset_decimal -eq 1701 })) {
        throw 'Missing UTF-16LE odd-aligned actionshot match'
    }
    if ($report.total_matches -ne 3) {
        throw ('Expected exactly three matches; observed ' + $report.total_matches)
    }

    $empty = Join-Path $folder 'empty.bin'
    [IO.File]::WriteAllBytes($empty, (New-Object byte[] 1024))
    $emptyResult = (& $tool -Executable $empty -Json -ChunkBytes 512) | ConvertFrom-Json
    if ($emptyResult.total_matches -ne 0) { throw 'Unexpected match in empty fixture' }
    Write-Output 'PowerShell static portrait string probe tests passed.'
}
finally {
    if (Test-Path -LiteralPath $folder) {
        Remove-Item -LiteralPath $folder -Recurse -Force
    }
}
