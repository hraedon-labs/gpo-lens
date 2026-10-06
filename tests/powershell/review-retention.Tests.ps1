Describe 'Shared export root ownership' {
    BeforeAll {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        . "$PSScriptRoot/../../scripts/Run-GpoLensCollection.ps1"
    }
    It 'prunes only the exact collected-domain prefix' {
        $root = Join-Path $TestDrive 'shared'
        New-Item -ItemType Directory -Path $root | Out-Null
        foreach ($prefix in @('lab.example.com', 'other.example.com', 'lab.example.com-extra')) {
            $folder = Join-Path $root "$prefix-20261004-120000"
            New-Item -ItemType Directory -Path $folder | Out-Null
            '<GPOs/>' | Set-Content (Join-Path $folder 'AllGPOs.xml')
            [IO.Compression.ZipFile]::CreateFromDirectory($folder, "$folder.zip")
        }
        $collector = Join-Path $TestDrive 'collector.ps1'
        @'
param($OutputRoot)
Add-Type -AssemblyName System.IO.Compression.FileSystem
$folder = Join-Path $OutputRoot 'lab.example.com-20261006-120000'
New-Item -ItemType Directory -Path $folder | Out-Null
'<GPOs/>' | Set-Content (Join-Path $folder 'AllGPOs.xml')
[IO.Compression.ZipFile]::CreateFromDirectory($folder, "$folder.zip")
'@ | Set-Content $collector
        Invoke-GpoLensCollection -OutputRoot $root -CollectorPath $collector -Retention 1
        Test-Path (Join-Path $root 'lab.example.com-20261004-120000.zip') | Should -BeFalse
        foreach ($prefix in @('other.example.com', 'lab.example.com-extra')) {
            Test-Path (Join-Path $root "$prefix-20261004-120000") | Should -BeTrue
            Test-Path (Join-Path $root "$prefix-20261004-120000.zip") | Should -BeTrue
        }
        Test-Path (Join-Path $root 'lab.example.com-20261006-120000.zip') | Should -BeTrue
    }
}
