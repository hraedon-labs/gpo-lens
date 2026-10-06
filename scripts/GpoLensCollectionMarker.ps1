# Shared owner-marker operations, compatible with Windows PowerShell 5.1.

function Read-GpoLensOwnerMarkerBytes {
    param([string]$Marker)
    if ((Get-Item -LiteralPath $Marker -Force -ErrorAction Stop).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'Collection refuses a linked owner marker.'
    }
    $stream = [IO.File]::Open($Marker, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
            if (-not ('GpoLens.MarkerFileInfo' -as [type])) {
                Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace GpoLens {
    public static class MarkerFileInfo {
        [StructLayout(LayoutKind.Sequential)]
        private struct FileInfo {
            public uint Attributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
            public uint VolumeSerialNumber;
            public uint FileSizeHigh;
            public uint FileSizeLow;
            public uint NumberOfLinks;
            public uint FileIndexHigh;
            public uint FileIndexLow;
        }
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInfo info);
        public static uint LinkCount(SafeFileHandle handle) {
            FileInfo info;
            if (!GetFileInformationByHandle(handle, out info))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            if ((info.Attributes & 0x400) != 0)
                throw new InvalidOperationException("Collection refuses a linked owner marker.");
            return info.NumberOfLinks;
        }
    }
}
'@ -ErrorAction Stop
            }
            $links = [GpoLens.MarkerFileInfo]::LinkCount($stream.SafeFileHandle)
        } else {
            # GNU stat (Linux); BSD stat uses -f instead. Never trust a failed check.
            $count = & stat --format=%h -- $Marker 2>$null
            if ($LASTEXITCODE -ne 0) { $count = & stat -f %l $Marker 2>$null }
            $links = 0
            if ($LASTEXITCODE -ne 0 -or -not [uint32]::TryParse([string]$count, [ref]$links)) {
                throw 'Cannot verify owner marker link count.'
            }
        }
        if ($links -ne 1) { throw 'Collection refuses a linked owner marker.' }
        $bytes = [IO.MemoryStream]::new()
        try {
            $stream.CopyTo($bytes)
            return ,$bytes.ToArray()
        } finally { $bytes.Dispose() }
    } finally { $stream.Dispose() }
}

function Write-GpoLensOwnerMarkerBytes {
    param([string]$OutputRoot, [byte[]]$Bytes)
    $root = Get-Item -LiteralPath $OutputRoot -Force -ErrorAction Stop
    if (-not $root.PSIsContainer -or ($root.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Registration refuses a linked output root.'
    }
    $marker = Join-Path $root.FullName '.gpo-lens-collection-owner'
    # File.Delete unlinks this directory entry; it never writes through a link.
    # CreateNew refuses an object substituted between deletion and creation.
    [IO.File]::Delete($marker)
    $stream = [IO.File]::Open($marker, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($Bytes, 0, $Bytes.Length) } finally { $stream.Dispose() }
}
