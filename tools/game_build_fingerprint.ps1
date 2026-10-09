#Requires -Version 5.1
<#
.SYNOPSIS
    Identify the installed NBA 2K26 Windows executable without Python.
.DESCRIPTION
    Read-only: inspects the PE header and calculates the SHA-256 hash of a
    local Windows executable. Does not launch or attach to the game.
.EXAMPLE
    .\tools\game_build_fingerprint.ps1 -Executable "D:\SteamLibrary\steamapps\common\NBA 2K26\NBA2K26.exe" -Json
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string] $Executable,
    [switch] $Json
)

$ErrorActionPreference = 'Stop'
$resolvedPath = (Resolve-Path -LiteralPath $Executable -ErrorAction Stop).ProviderPath
if (-not [System.IO.File]::Exists($resolvedPath)) {
    throw "Not a file: $resolvedPath"
}

$stream = [System.IO.File]::Open(
    $resolvedPath,
    [System.IO.FileMode]::Open,
    [System.IO.FileAccess]::Read,
    [System.IO.FileShare]::ReadWrite
)
$reader = New-Object System.IO.BinaryReader($stream)
try {
    $length = $stream.Length
    if ($length -lt 90) { throw 'File too small to contain a valid PE header.' }
    if ($reader.ReadUInt16() -ne 0x5A4D) { throw 'MZ header missing: not a Windows PE executable.' }

    [void] $stream.Seek(0x3C, [System.IO.SeekOrigin]::Begin)
    $peOffset = [long] $reader.ReadUInt32()
    if ($peOffset -lt 64 -or $peOffset -gt ($length - 26)) {
        throw 'Invalid PE header offset.'
    }
    [void] $stream.Seek($peOffset, [System.IO.SeekOrigin]::Begin)
    if ($reader.ReadUInt32() -ne 0x00004550) {
        throw 'Invalid PE signature.'
    }

    $machine = $reader.ReadUInt16()
    [void] $reader.ReadUInt16() # number of sections
    $timestamp = $reader.ReadUInt32()
    [void] $stream.Seek($peOffset + 20, [System.IO.SeekOrigin]::Begin)
    $optionalHeaderSize = $reader.ReadUInt16()
    if ($optionalHeaderSize -lt 2 -or ($peOffset + 24 + $optionalHeaderSize) -gt $length) {
        throw 'Invalid optional PE header size.'
    }
    [void] $stream.Seek($peOffset + 24, [System.IO.SeekOrigin]::Begin)
    $optionalMagic = $reader.ReadUInt16()
    if ($optionalMagic -ne 0x10B -and $optionalMagic -ne 0x20B) {
        throw 'Invalid PE optional header magic.'
    }
}
finally {
    $reader.Dispose()
}

$architecture = switch ($machine) {
    0x8664 { 'x64'; break }
    0x014C { 'x86'; break }
    default { 'unknown (0x{0:X4})' -f $machine }
}

$details = [ordered]@{
    filename = [System.IO.Path]::GetFileName($resolvedPath)
    architecture = $architecture
    file_size_bytes = $length
    pe_timestamp_utc = [DateTimeOffset]::FromUnixTimeSeconds([long]$timestamp).ToString('yyyy-MM-ddTHH:mm:sszzz')
    sha256 = (Get-FileHash -LiteralPath $resolvedPath -Algorithm SHA256).Hash.ToLowerInvariant()
}

if ($Json) {
    $details | ConvertTo-Json -Depth 3
}
else {
    Write-Output 'Game build fingerprint (read-only):'
    foreach ($item in $details.GetEnumerator()) {
        Write-Output ('  {0}: {1}' -f $item.Key, $item.Value)
    }
}
