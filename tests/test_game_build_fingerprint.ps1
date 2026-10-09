$ErrorActionPreference = 'Stop'
$tool = Join-Path $PSScriptRoot '..\tools\game_build_fingerprint.ps1'
$folder = Join-Path ([IO.Path]::GetTempPath()) ("pe-fingerprint-test-" + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($folder) | Out-Null

function Write-Le([byte[]]$Image, [int]$Offset, [byte[]]$Data) {
    [Array]::Copy($Data, 0, $Image, $Offset, $Data.Length)
}

try {
    $fixture = Join-Path $folder 'NBA2K26.exe'
    $bytes = New-Object byte[] 512
    $bytes[0] = 0x4D
    $bytes[1] = 0x5A
    Write-Le $bytes 0x3C ([BitConverter]::GetBytes([uint32]0x80))
    Write-Le $bytes 0x80 ([byte[]]@(0x50, 0x45, 0, 0))
    Write-Le $bytes 0x84 ([BitConverter]::GetBytes([uint16]0x8664))
    Write-Le $bytes 0x86 ([BitConverter]::GetBytes([uint16]1))
    Write-Le $bytes 0x88 ([BitConverter]::GetBytes([uint32]1700000000))
    Write-Le $bytes 0x94 ([BitConverter]::GetBytes([uint16]0xF0))
    Write-Le $bytes 0x98 ([BitConverter]::GetBytes([uint16]0x20B))
    [IO.File]::WriteAllBytes($fixture, $bytes)

    $jsonOutput = & $tool -Executable $fixture -Json
    $result = $jsonOutput | ConvertFrom-Json
    if ($result.filename -ne 'NBA2K26.exe') { throw 'Unexpected executable name' }
    if ($result.architecture -ne 'x64') { throw 'Unexpected executable architecture' }
    if ([long]$result.file_size_bytes -ne 512) { throw 'Unexpected file size' }
    if ($result.pe_timestamp_utc -ne '2023-11-14T22:13:20+00:00') {
        throw ('Unexpected PE timestamp: ' + $result.pe_timestamp_utc)
    }
    $expectedHash = (Get-FileHash -LiteralPath $fixture -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($result.sha256 -ne $expectedHash) { throw 'Unexpected SHA-256' }

    $badFile = Join-Path $folder 'invalid.exe'
    [IO.File]::WriteAllBytes($badFile, [byte[]]@(1, 2, 3))
    $rejected = $false
    try {
        & $tool -Executable $badFile -Json | Out-Null
    }
    catch {
        $rejected = $true
    }
    if (-not $rejected) { throw 'Expected invalid PE file rejection' }
    Write-Output 'PowerShell fingerprint tests passed: valid x64 PE and invalid input.'
}
finally {
    if (Test-Path -LiteralPath $folder) {
        Remove-Item -LiteralPath $folder -Recurse -Force
    }
}
