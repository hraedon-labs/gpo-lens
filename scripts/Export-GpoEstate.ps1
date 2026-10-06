<#
.SYNOPSIS
  Export a full Group Policy estate for offline analysis by gpo-lens.

.DESCRIPTION
  Read-only collector. Produces, per domain:
    - AllGPOs.xml            combined Get-GPOReport (whole domain)
    - reports\*.xml          per-GPO XML reports (GUID in filename disambiguates dupes)
    - collection-errors.json GPOs that could not be read (e.g. Authenticated Users
                             Read stripped), named by GUID so coverage gaps are explicit
    - gpo-inventory.json     every GPC GUID this account could enumerate; run once as a
                             privileged account for an authoritative coverage baseline
    - gpo-metadata.json      status, timestamps, version skew (DS vs SYSVOL), WMI filter
    - gp-inheritance.json    per-SOM inheritance: block, enforced, precedence order
    - ou-tree.json           raw OU tree (gPLink/gPOptions) as a topology cross-check
    - sites.json             AD site GPO links (gPLink/gPOptions) from the Config partition
    - wmi-filters.json        WMI filter names + query text
    - principals.json        SID -> name map for all SIDs found in GPO SDDL (Plan 020)
    - group-members.json     group SID -> member SIDs (transitive expansion) (Plan 020-B)
    - SYSVOL-Policies\        raw SYSVOL policy files (settings + GPP XML)
  Then zips the lot for handoff. Any file enumeration error aborts ZIP creation
  and removes the partial archive. Use a shorter -OutputRoot or transfer the
  output folder with -NoZip.

  Performs no AD writes. Run on a Domain Controller or an RSAT management box.

.PARAMETER OutputRoot
  Directory where the export folder (and zip) will be created.

.PARAMETER SkipSysvol
  Do not copy the SYSVOL Policies directory.

.PARAMETER NoZip
  Do not create a zip archive; leave the export folder in place.

.PARAMETER DryRun
  List what would be exported without actually exporting.

.NOTES
  Minimum permissions:
    - Domain User (or any authenticated principal) with Read access to the
      SYSVOL \\domain\SYSVOL\domain\Policies share.
    - Group Policy Creator Owners membership is NOT required; this script is
      read-only.

  Prerequisites:
    - RSAT Group Policy tools must be installed (provides GroupPolicy module).
    - RSAT Active Directory module must be installed (provides ActiveDirectory module).
#>
[CmdletBinding()]
param(
    [string]$OutputRoot = "C:\gpo-export",
    [switch]$SkipSysvol,
    [switch]$NoZip,
    [switch]$DryRun
)

function New-GpoExportZip {
    param([string]$ExportPath)
    # File-only entries with forward slashes preserve Linux directory traversal.
    # PS 5.1 can skip paths over MAX_PATH, so any enumeration error fails closed.
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
    $archive = "$ExportPath.zip"
    try {
        if (Test-Path -LiteralPath $archive) { Remove-Item -LiteralPath $archive -Force -ErrorAction Stop }
        $zipEnumErr = $null
        $diskFiles = @(Get-ChildItem -LiteralPath $ExportPath -Recurse -File `
            -ErrorAction SilentlyContinue -ErrorVariable +zipEnumErr)
        if ($zipEnumErr) {
            throw "$($zipEnumErr.Count) file enumeration error(s); the export cannot be archived completely."
        }
        $zip = [System.IO.Compression.ZipFile]::Open($archive, 'Create')
        try {
            $rootLen = $ExportPath.Length + 1
            foreach ($f in $diskFiles) {
                $entryName = $f.FullName.Substring($rootLen).Replace('\', '/')
                [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
                    $zip, $f.FullName, $entryName)
            }
        } finally {
            $zip.Dispose()
        }
        Write-Host "Done: $archive ($($diskFiles.Count) files)"
    } catch {
        # Never leave a partial ZIP that could be mistaken for a complete export.
        if (Test-Path -LiteralPath $archive) { Remove-Item -LiteralPath $archive -Force -ErrorAction Stop }
        throw ("ZIP creation failed: $($_.Exception.Message) " +
            "The partial ZIP was removed. Use a shorter -OutputRoot (Windows PowerShell 5.1 can skip paths over 260 characters), " +
            "or collect with -NoZip and transfer the folder: $ExportPath")
    }
}

$ErrorActionPreference = 'Stop'

foreach ($mod in @('GroupPolicy','ActiveDirectory')) {
    if (-not (Get-Module -ListAvailable -Name $mod)) {
        Write-Error "Required module '$mod' is not available. Install RSAT."
    }
}

try {
    if (-not (Test-Path -LiteralPath $OutputRoot)) {
        New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null
    }
    $testFile = Join-Path $OutputRoot "_writetest_.tmp"
    [System.IO.File]::WriteAllText($testFile, "test")
    Remove-Item $testFile -Force
} catch {
    Write-Error "OutputRoot '$OutputRoot' is not writable: $($_.Exception.Message)"
}

$dom = Get-ADDomain
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$out = Join-Path $OutputRoot "$($dom.DNSRoot)-$stamp"

$allGpos = Get-GPO -All
$gpoCount = $allGpos.Count
$ouCount = @(Get-ADOrganizationalUnit -Filter *).Count
$wmiCount = @(Get-ADObject -Filter "objectClass -eq 'msWMI-Som'" -Properties 'msWMI-Name' -ErrorAction SilentlyContinue).Count
$siteCount = @(Get-ADObject -SearchBase "CN=Sites,$((Get-ADRootDSE).configurationNamingContext)" -LDAPFilter "(objectClass=site)" -ErrorAction SilentlyContinue).Count

if ($DryRun) {
    $sysvolSizeStr = "skipped"
    if (-not $SkipSysvol) {
        $src = "\\$($dom.DNSRoot)\SYSVOL\$($dom.DNSRoot)\Policies"
        $sysvolSize = (Get-ChildItem $src -Recurse -File -ErrorAction SilentlyContinue |
            Measure-Object -Property Length -Sum).Sum
        $sysvolSizeStr = "$([math]::Round($sysvolSize / 1MB, 2)) MB"
    }
    Write-Host "DryRun: would export the following:"
    Write-Host "  Domain:        $($dom.DNSRoot)"
    Write-Host "  GPOs:          $gpoCount"
    Write-Host "  OUs:           $ouCount"
    Write-Host "  WMI filters:   $wmiCount"
    Write-Host "  AD sites:      $siteCount"
    Write-Host "  Output dir:    $out"
    Write-Host "  SYSVOL:        $(if ($SkipSysvol) {'skipped'} else {$sysvolSizeStr})"
    Write-Host "  Zip:           $(if ($NoZip) {'skipped'} else {"$out.zip"})"
    return
}

New-Item -ItemType Directory -Force -Path (Join-Path $out 'reports') | Out-Null
Write-Host "Exporting $($dom.DNSRoot) -> $out"

$successSections = [System.Collections.Generic.List[string]]::new()
$failedSections  = [System.Collections.Generic.List[string]]::new()

$totalSections = 9
$sectionNum = 0

function Set-SectionProgress {
    param([string]$Activity, [int]$Section)
    $pct = [math]::Round(($Section / $totalSections) * 100)
    Write-Progress -Activity $Activity -PercentComplete $pct
}

$sectionNum++
Set-SectionProgress -Activity "GPO settings (XML reports)" -Section $sectionNum
# Per-GPO resilience: one unreadable GPO (e.g. Authenticated Users Read stripped
# for security filtering) must not abort the rest. Each failure is captured with
# its GUID so analysis can flag incomplete coverage rather than silently omit it.
$collectionErrors = [System.Collections.Generic.List[object]]::new()

try {
    Get-GPOReport -All -ReportType Xml -Path (Join-Path $out 'AllGPOs.xml') -ErrorAction Stop
} catch {
    $collectionErrors.Add([pscustomobject]@{
        GpoId = $null; DisplayName = '(combined report)'; Stage = 'report-all'
        Error = $_.Exception.Message
    })
    Write-Warning "Combined GPO report failed: $($_.Exception.Message)"
}

$i = 0
foreach ($gpo in $allGpos) {
    $i++
    Write-Progress -Activity "GPO settings (XML reports)" `
        -Status "$i / $gpoCount" -PercentComplete ([math]::Round(($sectionNum - 1 + ($i / $gpoCount)) / $totalSections * 100))
    $safe = ($gpo.DisplayName -replace '[\\/:*?"<>|\[\]]', '_')
    try {
        Get-GPOReport -Guid $gpo.Id -ReportType Xml `
            -Path (Join-Path $out "reports\${safe}__$($gpo.Id).xml") -ErrorAction Stop
    } catch {
        $collectionErrors.Add([pscustomobject]@{
            GpoId = $gpo.Id.Guid; DisplayName = $gpo.DisplayName; Stage = 'report'
            Error = $_.Exception.Message
        })
        Write-Warning "GPO report failed for '$($gpo.DisplayName)' ($($gpo.Id)): $($_.Exception.Message)"
    }
}

# Completeness cross-check: Get-GPO -All silently omits GPOs whose properties the
# account cannot read, but the Policies container grants List Contents, so the GPC
# objects (and their GUIDs) are still enumerable. Any GUID present in AD but absent
# from Get-GPO -All is an inaccessible GPO we must name, not drop.
try {
    $policiesDN = "CN=Policies,CN=System,$($dom.DistinguishedName)"
    $allGpc = Get-ADObject -SearchBase $policiesDN -LDAPFilter "(objectClass=groupPolicyContainer)" `
        -Properties displayName -ErrorAction Stop
    # Persist the inventory (every GPC GUID this account could enumerate). Run the
    # collector once as a privileged account for an AUTHORITATIVE inventory; gpo-lens
    # reconciles it against the (least-privilege) export to name coverage gaps.
    @($allGpc | ForEach-Object { [pscustomobject]@{ Id = $_.Name.Trim('{}'); DisplayName = $_.displayName } }) |
        ConvertTo-Json -Depth 4 | Set-Content (Join-Path $out 'gpo-inventory.json') -Encoding UTF8
    $knownIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($g in $allGpos) { $null = $knownIds.Add($g.Id.Guid) }
    foreach ($gpc in $allGpc) {
        $guid = $gpc.Name.Trim('{}')
        if (-not $knownIds.Contains($guid)) {
            $collectionErrors.Add([pscustomobject]@{
                GpoId = $guid; DisplayName = $gpc.displayName; Stage = 'enumerate'
                Error = 'GPC exists in AD but Get-GPO could not read it (Authenticated Users Read may be stripped)'
            })
            Write-Warning "Inaccessible GPO detected: $guid$(if ($gpc.displayName) { " ($($gpc.displayName))" })"
        }
    }
} catch {
    Write-Warning "GPC completeness cross-check failed: $($_.Exception.Message)"
}

# Always emit the manifest (valid JSON array even when empty) so analysis can read it.
if ($collectionErrors.Count -eq 0) {
    '[]' | Set-Content (Join-Path $out 'collection-errors.json') -Encoding UTF8
    $successSections.Add("GPO settings (XML reports)")
} else {
    $collectionErrors | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $out 'collection-errors.json') -Encoding UTF8
    $failedSections.Add("GPO settings: $($collectionErrors.Count) GPO(s) could not be collected (see collection-errors.json)")
}

$sectionNum++
Set-SectionProgress -Activity "GPO metadata" -Section $sectionNum
try {
    $allGpos | Select-Object DisplayName, Id, GpoStatus, CreationTime, ModificationTime,
        @{n='UserDSVersion';e={$_.User.DSVersion}},         @{n='UserSysvolVersion';e={$_.User.SysvolVersion}},
        @{n='ComputerDSVersion';e={$_.Computer.DSVersion}}, @{n='ComputerSysvolVersion';e={$_.Computer.SysvolVersion}},
        @{n='WmiFilter';e={$_.WmiFilter.Name}} |
        ConvertTo-Json -Depth 4 | Set-Content (Join-Path $out 'gpo-metadata.json') -Encoding UTF8
    $successSections.Add("GPO metadata")
} catch {
    $failedSections.Add("GPO metadata: $($_.Exception.Message)")
}

$sectionNum++
Set-SectionProgress -Activity "Inheritance (gp-inheritance)" -Section $sectionNum
try {
    $targets = @($dom.DistinguishedName) +
               (Get-ADOrganizationalUnit -Filter * | Select-Object -Expand DistinguishedName)
    $totalTargets = $targets.Count
    $inh = foreach ($t in $targets) {
        try {
            $g = Get-GPInheritance -Target $t
            [pscustomobject]@{
                Path                  = $g.Path
                Name                  = $g.Name
                ContainerType         = $g.ContainerType
                GpoInheritanceBlocked = $g.GpoInheritanceBlocked
                InheritedGpoLinks     = $g.InheritedGpoLinks |
                    Select-Object DisplayName, GpoId, Enabled, Enforced, Order, Target
            }
        } catch { Write-Warning "GPInheritance failed for $t : $($_.Exception.Message)" }
    }
    $inh | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $out 'gp-inheritance.json') -Encoding UTF8
    $successSections.Add("Inheritance (gp-inheritance)")
} catch {
    $failedSections.Add("Inheritance (gp-inheritance): $($_.Exception.Message)")
}

$sectionNum++
Set-SectionProgress -Activity "OU tree" -Section $sectionNum
try {
    Get-ADOrganizationalUnit -Filter * -Properties gPLink, gPOptions |
        Select-Object DistinguishedName, Name, gPLink, gPOptions |
        ConvertTo-Json -Depth 4 | Set-Content (Join-Path $out 'ou-tree.json') -Encoding UTF8
    $successSections.Add("OU tree")
} catch {
    $failedSections.Add("OU tree: $($_.Exception.Message)")
}

$sectionNum++
Set-SectionProgress -Activity "AD sites" -Section $sectionNum
try {
    # Site GPO links live in the Configuration partition, not under the domain.
    $configNC = (Get-ADRootDSE).configurationNamingContext
    Get-ADObject -SearchBase "CN=Sites,$configNC" -LDAPFilter "(objectClass=site)" `
        -Properties gPLink, gPOptions, name |
        Select-Object DistinguishedName, Name, gPLink, gPOptions |
        ConvertTo-Json -Depth 4 | Set-Content (Join-Path $out 'sites.json') -Encoding UTF8
    $successSections.Add("AD sites")
} catch {
    $failedSections.Add("AD sites: $($_.Exception.Message)")
}

$sectionNum++
Set-SectionProgress -Activity "WMI filters" -Section $sectionNum
try {
    Get-ADObject -Filter "objectClass -eq 'msWMI-Som'" -Properties 'msWMI-Name', 'msWMI-Parm2' |
        Select-Object @{n='Name';e={$_.'msWMI-Name'}}, @{n='Query';e={$_.'msWMI-Parm2'}} |
        ConvertTo-Json -Depth 4 | Set-Content (Join-Path $out 'wmi-filters.json') -Encoding UTF8
    $successSections.Add("WMI filters")
} catch {
    $failedSections.Add("WMI filters: $($_.Exception.Message)")
}

$sectionNum++
Set-SectionProgress -Activity "Principals (SID -> name)" -Section $sectionNum
try {
    # Collect all unique SIDs from GPO SDDL strings in the XML reports.
    $allSids = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $xmlFiles = @(Get-ChildItem -LiteralPath (Join-Path $out 'reports') -Filter '*.xml' -ErrorAction SilentlyContinue)
    $allXmlPath = Join-Path $out 'AllGPOs.xml'
    if (Test-Path -LiteralPath $allXmlPath) { $xmlFiles += Get-Item -LiteralPath $allXmlPath }
    foreach ($f in $xmlFiles) {
        try {
            $content = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop
            foreach ($m in [regex]::Matches($content, 'S-1-[0-9]+-[0-9-]+')) {
                [void]$allSids.Add($m.Value)
            }
        } catch { }
    }
    # Also scan gpo-metadata.json for SDDL strings
    $metaPath = Join-Path $out 'gpo-metadata.json'
    if (Test-Path -LiteralPath $metaPath) {
        try {
            $content = Get-Content -LiteralPath $metaPath -Raw
            foreach ($m in [regex]::Matches($content, 'S-1-[0-9]+-[0-9-]+')) {
                [void]$allSids.Add($m.Value)
            }
        } catch { }
    }
    Write-Host "  Found $($allSids.Count) unique SIDs to resolve"

    $principals = [ordered]@{}
    $resolved = 0
    $unresolved = 0
    foreach ($sid in ($allSids | Sort-Object)) {
        $name = ""
        $type = "Unresolved"
        $sam = ""
        # NB: must NOT be named $dom - that is the script-level Get-ADDomain object
        # ($dom.DNSRoot), used later to build the SYSVOL UNC path and the
        # principals/group-members domain fields. Reusing $dom here clobbered it,
        # producing a "\\\SYSVOL\\Policies" path (empty DNSRoot) that does not
        # exist, so the SYSVOL copy silently collected nothing.
        $domPart = ""
        try {
            $sidObj = New-Object System.Security.Principal.SecurityIdentifier($sid)
            $translated = $sidObj.Translate([System.Security.Principal.NTAccount]).Value
            $name = $translated
            if ($translated -match '^(.+?)\\(.+)$') {
                $domPart = $matches[1]; $sam = $matches[2]
            } elseif ($translated -match '^(.+?)@(.+)$') {
                $sam = $matches[1]; $domPart = $matches[2]
            } else {
                $sam = $translated
            }
            if ($translated -match 'BUILTIN\\' -or $sid -match '^S-1-5-32-') {
                $type = "WellKnown"
            } elseif ($sid -match '^S-1-5-21-') {
                $type = if ($sam -match '\$$') { "Computer" } else { "Group" }
            } else {
                $type = "WellKnown"
            }
            $resolved++
        } catch {
            $name = $sid; $type = "Unresolved"; $unresolved++
        }
        $principals[$sid] = [ordered]@{ name = $name; sam = $sam; type = $type; domain = $domPart }
    }
    # Supplement unresolved domain SIDs via Get-ADObject
    $domainSids = @($allSids | Where-Object { $_ -match '^S-1-5-21-' -and $principals[$_].type -eq 'Unresolved' })
    if ($domainSids.Count -gt 0) {
        Write-Host "  Resolving $($domainSids.Count) domain SIDs via Get-ADObject..."
        foreach ($sid in $domainSids) {
            try {
                $obj = Get-ADObject -Filter "objectSid -eq '$sid'" -Properties objectClass, sAMAccountName, name -ErrorAction Stop
                if ($obj) {
                    $sam = if ($obj.sAMAccountName) { $obj.sAMAccountName } else { $obj.Name }
                    $objClass = $obj.objectClass[-1]
                    $ptype = switch ($objClass) { 'group' { 'Group' } 'computer' { 'Computer' } default { 'User' } }
                    $principals[$sid] = [ordered]@{
                        name = "$($dom.DNSRoot.Split('.')[0])\$sam"; sam = $sam; type = $ptype
                        domain = $dom.DNSRoot.Split('.')[0]
                    }
                    $resolved++; $unresolved--
                }
            } catch { }
        }
    }
    $principalsOut = [ordered]@{ collected = (Get-Date -Format 'o'); domain = $dom.DNSRoot; principals = $principals }
    $principalsOut | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $out 'principals.json') -Encoding UTF8
    Write-Host "  Resolved: $resolved, Unresolved: $unresolved"
    $successSections.Add("Principals (SID -> name)")
} catch {
    $failedSections.Add("Principals (SID -> name): $($_.Exception.Message)")
    Write-Warning "Principals collection failed: $($_.Exception.Message)"
}

$sectionNum++
Set-SectionProgress -Activity "Group membership" -Section $sectionNum
try {
    $groupMembers = [ordered]@{}
    $groupsExpanded = 0
    $groupsFailed = 0
    # Collect group SIDs from principals map
    $groupSids = @($principals.Keys | Where-Object { $principals[$_].type -eq 'Group' })
    Write-Host "  Expanding $($groupSids.Count) groups..."
    foreach ($gSid in $groupSids) {
        $gName = $principals[$gSid].name
        try {
            $members = Get-ADGroupMember -Identity $gSid -Recursive -ErrorAction Stop
            $memberSids = @($members | ForEach-Object { $_.SID.Value })
            $groupMembers[$gSid] = [ordered]@{
                name = $gName; members = $memberSids; member_count = $memberSids.Count
            }
            $groupsExpanded++
        } catch {
            $groupMembers[$gSid] = [ordered]@{
                name = $gName; members = @(); member_count = 0; error = $_.Exception.Message
            }
            $groupsFailed++
        }
    }
    # Well-known implicit groups
    $groupMembers['s-1-5-11'] = [ordered]@{
        name = 'Authenticated Users'; members = @(); member_count = 0
        implicit = 'All authenticated domain principals (users + computers)'
    }
    $groupMembers['s-1-1-0'] = [ordered]@{
        name = 'Everyone'; members = @(); member_count = 0
        implicit = 'All principals including anonymous'
    }
    $groupMembersOut = [ordered]@{ collected = (Get-Date -Format 'o'); domain = $dom.DNSRoot; groups = $groupMembers }
    $groupMembersOut | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $out 'group-members.json') -Encoding UTF8
    Write-Host "  Expanded: $groupsExpanded, Failed: $groupsFailed"
    $successSections.Add("Group membership")
} catch {
    $failedSections.Add("Group membership: $($_.Exception.Message)")
    Write-Warning "Group membership collection failed: $($_.Exception.Message)"
}

$sectionNum++
Set-SectionProgress -Activity "SYSVOL copy" -Section $sectionNum
if ($SkipSysvol) {
    $successSections.Add("SYSVOL copy (skipped)")
} else {
    $src = "\\$($dom.DNSRoot)\SYSVOL\$($dom.DNSRoot)\Policies"
    $dest = Join-Path $out 'SYSVOL-Policies'
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    $sysvolErrors = 0
    # Enumerate the source explicitly so an unreachable share (DFS referral,
    # auth, wrong path) is a recorded error, not a silent empty result that
    # masquerades as a clean copy. Capturing into $srcErr also stops
    # SilentlyContinue from hiding *why* the enumeration came back empty.
    $srcErr = $null
    $policyFolders = @(Get-ChildItem -LiteralPath $src -Directory `
        -ErrorAction SilentlyContinue -ErrorVariable +srcErr)
    # Per-policy-folder resilience (mirrors the Get-GPOReport loop): one unreadable
    # policy folder (e.g. Authenticated Users Read stripped for security filtering)
    # must not abort the whole copy. Record the GUID so coverage gaps are explicit
    # rather than silently dropped, consistent with collection-errors.json.
    foreach ($pf in $policyFolders) {
        try {
            Copy-Item -LiteralPath $pf.FullName -Destination $dest -Recurse -Force -ErrorAction Stop
        } catch {
            $sysvolErrors++
            $collectionErrors.Add([pscustomobject]@{
                GpoId = $pf.Name.Trim('{}'); DisplayName = $null; Stage = 'sysvol'
                Error = $_.Exception.Message
            })
            Write-Warning "SYSVOL copy failed for policy folder $($pf.Name): $($_.Exception.Message)"
        }
    }
    # Loose files at the Policies root (rare) - keep parity with a full copy.
    Get-ChildItem -LiteralPath $src -File -ErrorAction SilentlyContinue |
        ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $dest -Force -ErrorAction SilentlyContinue }
    # Success means files actually landed - not merely "no exception was thrown".
    # A 0-folder enumeration (unreachable $src) or a copy that wrote nothing both
    # produced "SYSVOL copy" success before, yielding a SYSVOL-less export that
    # silently blinds every GPP/cPassword detector downstream. Verify on disk.
    $copiedCount = @(Get-ChildItem -LiteralPath $dest -Recurse -File -ErrorAction SilentlyContinue).Count
    if ($policyFolders.Count -eq 0 -or $copiedCount -eq 0) {
        $detail = if ($policyFolders.Count -eq 0) {
            "enumerated 0 policy folders at $src" +
            $(if ($srcErr) { " ($($srcErr[0].Exception.Message))" } else { "" })
        } else { "copy wrote 0 files to SYSVOL-Policies" }
        $failedSections.Add("SYSVOL copy: $detail - GPP/cPassword detection will be BLIND")
        $collectionErrors.Add([pscustomobject]@{
            GpoId = $null; DisplayName = $null; Stage = 'sysvol'; Error = $detail
        })
        $collectionErrors | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $out 'collection-errors.json') -Encoding UTF8
        Write-Warning "SYSVOL copy produced no files: $detail"
    } elseif ($sysvolErrors -eq 0) {
        $successSections.Add("SYSVOL copy ($copiedCount files)")
    } else {
        $failedSections.Add("SYSVOL copy: $sysvolErrors policy folder(s) inaccessible (see collection-errors.json)")
        # Re-serialize so SYSVOL denials join report/enumerate gaps in one manifest.
        $collectionErrors | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $out 'collection-errors.json') -Encoding UTF8
    }
}

Write-Progress -Activity "Export complete" -Completed

Write-Host "`nExport summary:`n  Succeeded ($($successSections.Count)):"
foreach ($s in $successSections) { Write-Host "    - $s" }
if ($failedSections.Count -gt 0) {
    Write-Host "  Failed ($($failedSections.Count)):"
    foreach ($s in $failedSections) { Write-Host "    - $s" }
} else {
    Write-Host "  All sections succeeded."
}

if (-not $NoZip) {
    New-GpoExportZip -ExportPath $out
}
