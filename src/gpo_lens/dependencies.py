"""Offline path evidence and external UNC dependencies; never probes a server."""

from __future__ import annotations

import ntpath
import re
from collections import defaultdict
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath

from gpo_lens.detection._gpp import _walk_gpp_xml
from gpo_lens.model import Estate, Gpo, Side
from gpo_lens.normalize import canonical_guid, localname


@dataclass(frozen=True)
class PathReference:
    gpo_id: str
    gpo_name: str
    side: Side
    dependency_type: str
    target: str
    detail: str


@dataclass(frozen=True)
class ExternalDependency:
    gpo_id: str
    gpo_name: str
    side: Side
    dependency_type: str
    server: str
    share: str
    target: str
    detail: str


@dataclass(frozen=True)
class ServerDependencies:
    server: str
    dependency_count: int
    gpo_count: int
    gpo_ids: tuple[str, ...]
    shares: tuple[str, ...]
    dependencies: tuple[ExternalDependency, ...]


_PATH_ATTRS = {
    "Drive": ("path",),
    "SharedPrinter": ("path", "port"),
    "Printer": ("path", "port"),
    "LocalPrinter": ("path", "port"),
    "File": ("fromPath", "toPath", "targetPath", "SourcePath", "DestinationPath"),
    "Folder": ("path",),
    "Shortcut": ("targetPath", "path", "iconPath"),
    "Service": ("serviceName", "imagePath"),
    "DataSource": ("dsn", "dsnTarget"),
    "Task": ("appName", "appPath", "exePath", "Path", "arguments"),
    "TaskV2": ("appName", "appPath", "exePath", "Path", "arguments"),
    "ImmediateTask": ("appName", "appPath", "exePath", "Path", "arguments"),
    "ImmediateTaskV2": ("appName", "appPath", "exePath", "Path", "arguments"),
    "ScheduledTask": ("appName", "appPath", "exePath", "Path", "arguments"),
}


def dependency_type(cse: str) -> str:
    name = re.sub(r"[^a-z]", "", cse.lower())
    return {
        "drives": "drive_mapping",
        "drivemaps": "drive_mapping",
        "printers": "printer_connection",
        "files": "file_copy",
        "shortcuts": "shortcut_target",
        "scheduledtasks": "scheduled_task_action",
        "scripts": "script",
        "grouppolicyscripts": "script",
        "softwareinstallation": "software_installation_package",
        "folderredirection": "folder_redirection_target",
        "folders": "folder_target",
        "services": "service_path",
        "datasources": "data_source",
    }.get(name, "unc_path")


def _unc_targets(text: str, *, whole_path: bool = True) -> list[str]:
    """Preserve structured paths; parse every quoted/unquoted argument target."""
    text = text.strip()
    if whole_path and text.startswith("\\\\") and not any(c in text for c in '"\n\r\t'):
        return [text]
    return [
        match[1] or match[2] for match in re.finditer(r'"(\\\\[^"\r\n]+)"|(\\\\[^\s"\'<>|]+)', text)
    ]


def _raw_reference_texts(raw: dict[str, object]) -> Iterator[tuple[str, bool]]:
    """Retain whether a raw value is a path or a list of command arguments."""
    tag = str(raw.get("tag", "")).rsplit("}", 1)[-1].casefold()
    for key, value in raw.items():
        if isinstance(value, str):
            arguments = key.casefold() in ("arguments", "parameters") or (
                key == "text" and tag in ("arguments", "parameters")
            )
            yield value, not arguments
        elif isinstance(value, dict):
            yield from _raw_reference_texts(value)
        elif isinstance(value, list):
            for child in value:
                if isinstance(child, dict):
                    yield from _raw_reference_texts(child)
                elif isinstance(child, str):
                    yield child, True


def _script_commands(raw: dict[str, object]) -> list[str]:
    """Read parser-exposed Command nodes; a script's Type is a label."""
    result: list[str] = []
    tag = str(raw.get("tag", "")).rsplit("}", 1)[-1].casefold()
    value = raw.get("text")
    if tag in ("command", "scriptname") and isinstance(value, str) and value.strip():
        result.append(value.strip())
    children = raw.get("children", [])
    if isinstance(children, list):
        for child in children:
            if isinstance(child, dict):
                result.extend(_script_commands(child))
    return result


def path_references(gpo: Gpo) -> Iterator[PathReference]:
    """Specific GPP locators first, followed by normalized report evidence."""
    for walk in _walk_gpp_xml(gpo):
        root = walk.tree.getroot()
        if root is None:
            continue
        kind = dependency_type(walk.cse)
        for elem in root.iter():
            tag = localname(elem.tag)
            attrs = _PATH_ATTRS.get(tag)
            if attrs is not None:
                sources = [(elem, tag)] + [
                    (child, tag + "/Properties")
                    for child in elem
                    if localname(child.tag) == "Properties"
                ]
                for source, locator in sources:
                    for attr, value in source.attrib.items():
                        if attr.casefold() not in {a.casefold() for a in attrs}:
                            continue
                        targets = _unc_targets(value, whole_path=attr.casefold() != "arguments")
                        if not targets and attr.casefold() != "arguments" and value.strip():
                            targets = [value.strip()]
                        for target in targets:
                            yield PathReference(
                                gpo.id,
                                gpo.name,
                                walk.side,
                                kind,
                                target,
                                f"GPP {walk.rel_file} <{locator} @{attr}>: path reference",
                            )
            # All V2 Exec actions, including arguments carrying network paths.
            if walk.cse.lower() == "scheduledtasks" and tag in ("Command", "Arguments"):
                text = (elem.text or "").strip()
                targets = _unc_targets(text, whole_path=tag == "Command")
                if not targets and text and tag == "Command":
                    targets = [text]
                for target in targets:
                    yield PathReference(
                        gpo.id,
                        gpo.name,
                        walk.side,
                        kind,
                        target,
                        f"GPP {walk.rel_file} <{tag}>: path reference",
                    )
    for s in gpo.settings:
        kind = dependency_type(s.cse)
        commands = _script_commands(s.raw) if kind == "script" else []
        for command in commands:
            yield PathReference(
                gpo.id, gpo.name, s.side, kind, command, f"[{s.cse}] {s.identity}: script Command"
            )
        raw_texts = list(_raw_reference_texts(s.raw))
        # The report formats GPP values as "[U] <path>". Raw path values
        # already contain the complete target, so do not scan that prose too.
        raw_has_unc = any(_unc_targets(t, whole_path=whole) for t, whole in raw_texts)
        texts = [(t, "raw data", whole) for t, whole in raw_texts]
        if not raw_has_unc:
            texts.insert(0, (s.display_value, "display value", True))
        for text, source_label, whole in texts:
            targets = _unc_targets(text, whole_path=whole)
            if (
                not targets
                and kind in ("script", "scheduled_task_action")
                and source_label == "display value"
                and text.strip()
                and not commands
                and text.casefold() not in ("logon", "logoff", "startup", "shutdown")
            ):
                targets = [text.strip()]
            for target in targets:
                yield PathReference(
                    gpo.id,
                    gpo.name,
                    s.side,
                    kind,
                    target,
                    f"[{s.cse}] {s.identity}: path in {source_label}",
                )


def unc_parts(target: str) -> tuple[str, str, tuple[str, ...]] | None:
    """Parse a UNC without interpreting credentials as a server identifier."""
    if not target.startswith("\\\\"):
        return None
    parts = target[2:].split("\\")
    if len(parts) < 2 or not parts[0] or not parts[1]:
        return None
    server = parts[0].rsplit("@", 1)[-1].casefold()
    if not server or any(c in server for c in "/:*?<>|") or any(c in parts[1] for c in "/:*?<>|"):
        return None
    return server, parts[1].casefold(), tuple(parts[2:])


def own_sysvol_parts(gpo: Gpo, target: str) -> tuple[str, ...] | None:
    """Map only an explicit reference into this GPO's own domain SYSVOL."""
    parsed = unc_parts(ntpath.normpath(target))
    if parsed is None:
        return None
    server, share, tail = parsed
    if (
        server != gpo.domain.casefold()
        or share != "sysvol"
        or len(tail) < 4
        or tail[0].casefold() != gpo.domain.casefold()
        or tail[1].casefold() != "policies"
        or canonical_guid(tail[2]) != canonical_guid(gpo.id)
    ):
        return None
    return tail[3:]


def malformed_path(target: str) -> bool:
    if target.startswith("\\\\") and unc_parts(target) is None:
        return True
    return any(c in target for c in "<>|\x00")


def _collected_file_missing(base: Path, parts: tuple[str, ...]) -> bool | None:
    """Tri-state: missing, present, or unavailable. Never leaves the copy."""
    current = base
    try:
        if current.is_symlink() or not current.is_dir():
            return None
        for part in parts:
            children = list(current.iterdir())  # propagate unreadable-directory errors
            match = next((p for p in children if p.name.casefold() == part.casefold()), None)
            if match is None:
                return True
            if match.is_symlink():
                return None
            current = match
        return not current.is_file()
    except OSError:
        return None


def missing_own_reference(gpo: Gpo, ref: PathReference) -> bool:
    if not gpo.sysvol_path or malformed_path(ref.target) or any(c in ref.target for c in "%*?"):
        return False
    base = Path(gpo.sysvol_path)
    parts = own_sysvol_parts(gpo, ref.target)
    if parts is not None:
        return _collected_file_missing(base, parts) is True
    # Relative script names denote files shipped with the GPO. Machine-local
    # absolute paths and environment expansions cannot be verified offline.
    path = PureWindowsPath(ref.target)
    if (
        ref.dependency_type != "script"
        or path.drive
        or path.root
        or any(c in ref.target for c in "%*?")
        or ".." in path.parts
    ):
        return False
    options = [
        (side, "Scripts", *sub, *path.parts)
        for side in ("Machine", "User")
        for sub in ((), ("Logon",), ("Logoff",), ("Startup",), ("Shutdown",))
    ]
    states = [_collected_file_missing(base, option) for option in options]
    return all(state is True for state in states)


def external_dependencies(estate: Estate, *, server: str = "") -> list[ServerDependencies]:
    """Group unique GPO/side/type/target dependencies by case-folded server.

    Counts describe configured references, not reachability or actual use.
    Case-insensitive duplicates across report and SYSVOL retain the specific
    GPP locator. Other GPO SYSVOL references remain external dependencies.
    """
    grouped: dict[str, list[ExternalDependency]] = defaultdict(list)
    seen: set[tuple[str, str, str, str]] = set()
    wanted = server.strip().removeprefix("\\\\").split("\\", 1)[0].casefold()
    for gpo in sorted(estate.gpos, key=lambda g: g.id):
        for ref in path_references(gpo):
            parsed = unc_parts(ref.target)
            if (
                parsed is None
                or malformed_path(ref.target)
                or own_sysvol_parts(gpo, ref.target) is not None
            ):
                continue
            host, share, _ = parsed
            if wanted and host != wanted:
                continue
            key = (gpo.id, ref.side, ref.dependency_type, ref.target.casefold())
            if key in seen:
                continue
            seen.add(key)
            grouped[host].append(
                ExternalDependency(
                    gpo.id,
                    gpo.name,
                    ref.side,
                    ref.dependency_type,
                    host,
                    share,
                    ref.target,
                    ref.detail,
                )
            )
    result = []
    for host, refs in sorted(grouped.items()):
        refs.sort(
            key=lambda r: (r.gpo_id, r.side, r.dependency_type, r.target.casefold(), r.target)
        )
        ids = tuple(sorted({r.gpo_id for r in refs}))
        result.append(
            ServerDependencies(
                host, len(refs), len(ids), ids, tuple(sorted({r.share for r in refs})), tuple(refs)
            )
        )
    return result
