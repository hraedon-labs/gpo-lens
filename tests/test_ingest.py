"""Unit tests for the ingest module (no samples required)."""

from __future__ import annotations

import io
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from gpo_lens import ingest
from gpo_lens.model import Estate, Gpo


def _min_gpo_xml(
    gpo_id: str = "{31B2F340-016D-11D2-945F-00C04FB984F9}",
    name: str = "Test GPO",
    domain: str = "test.local",
    computer_enabled: str = "true",
    user_enabled: str = "true",
) -> str:
    """Minimal valid GPOReport XML with one GPO."""
    return f"""<?xml version="1.0" encoding="utf-8"?>
<GPO xmlns="http://www.microsoft.com/GroupPolicy/Settings">
    <GPO>
        <Identifier>
            <Identifier>{gpo_id}</Identifier>
            <Domain>{domain}</Domain>
        </Identifier>
        <Name>{name}</Name>
        <CreatedTime>2026-01-01T00:00:00</CreatedTime>
        <ModifiedTime>2026-01-02T00:00:00</ModifiedTime>
        <ReadTime>2026-01-03T00:00:00</ReadTime>
        <Computer>
            <VersionDirectory>1</VersionDirectory>
            <VersionSysvol>2</VersionSysvol>
            <Enabled>{computer_enabled}</Enabled>
        </Computer>
        <User>
            <VersionDirectory>3</VersionDirectory>
            <VersionSysvol>4</VersionSysvol>
            <Enabled>{user_enabled}</Enabled>
        </User>
        <FilterDataAvailable>true</FilterDataAvailable>
    </GPO>
</GPO>
"""


class TestParseReport:
    def test_parse_minimal_gpo(self, tmp_path: Path) -> None:
        xml_path = tmp_path / "report.xml"
        xml_path.write_text(_min_gpo_xml(), encoding="utf-8")
        gpos = ingest.parse_report(xml_path)
        assert len(gpos) == 1
        gpo = gpos[0]
        assert gpo.id == "31b2f340016d11d2945f00c04fb984f9"
        assert gpo.name == "Test GPO"
        assert gpo.domain == "test.local"
        assert gpo.computer_enabled is True
        assert gpo.user_enabled is True
        assert gpo.computer_ver_ds == 1
        assert gpo.computer_ver_sysvol == 2
        assert gpo.user_ver_ds == 3
        assert gpo.user_ver_sysvol == 4
        assert gpo.filter_data_available is True

    def test_parse_multiple_gpos(self, tmp_path: Path) -> None:
        body_a = (
            "    <GPO>\n"
            "        <Identifier>\n"
            "            <Identifier>{31B2F340-016D-11D2-945F-00C04FB984F9}</Identifier>\n"
            "            <Domain>test.local</Domain>\n"
            "        </Identifier>\n"
            "        <Name>GPO A</Name>\n"
            "        <CreatedTime>2026-01-01T00:00:00</CreatedTime>\n"
            "        <ModifiedTime>2026-01-02T00:00:00</ModifiedTime>\n"
            "        <ReadTime>2026-01-03T00:00:00</ReadTime>\n"
            "        <Computer><VersionDirectory>1</VersionDirectory>"
            "<VersionSysvol>2</VersionSysvol><Enabled>true</Enabled></Computer>\n"
            "        <User><VersionDirectory>3</VersionDirectory>"
            "<VersionSysvol>4</VersionSysvol><Enabled>true</Enabled></User>\n"
            "        <FilterDataAvailable>true</FilterDataAvailable>\n"
            "    </GPO>\n"
        )
        body_b = (
            "    <GPO>\n"
            "        <Identifier>\n"
            "            <Identifier>{11111111-1111-1111-1111-111111111111}</Identifier>\n"
            "            <Domain>test.local</Domain>\n"
            "        </Identifier>\n"
            "        <Name>GPO B</Name>\n"
            "        <CreatedTime>2026-01-01T00:00:00</CreatedTime>\n"
            "        <ModifiedTime>2026-01-02T00:00:00</ModifiedTime>\n"
            "        <ReadTime>2026-01-03T00:00:00</ReadTime>\n"
            "        <Computer><VersionDirectory>1</VersionDirectory>"
            "<VersionSysvol>2</VersionSysvol><Enabled>true</Enabled></Computer>\n"
            "        <User><VersionDirectory>3</VersionDirectory>"
            "<VersionSysvol>4</VersionSysvol><Enabled>true</Enabled></User>\n"
            "        <FilterDataAvailable>true</FilterDataAvailable>\n"
            "    </GPO>\n"
        )
        xml = (
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<GPO xmlns="http://www.microsoft.com/GroupPolicy/Settings">\n'
            + body_a
            + body_b
            + "</GPO>\n"
        )
        xml_path = tmp_path / "report.xml"
        xml_path.write_text(xml, encoding="utf-8")
        gpos = ingest.parse_report(xml_path)
        assert len(gpos) == 2
        assert {g.name for g in gpos} == {"GPO A", "GPO B"}

    def test_parse_empty_file_raises(self, tmp_path: Path) -> None:
        xml_path = tmp_path / "empty.xml"
        xml_path.write_text('<?xml version="1.0"?>\n<root/>', encoding="utf-8")
        # No <GPO> elements -> returns empty list, does not crash
        gpos = ingest.parse_report(xml_path)
        assert gpos == []

    def test_malformed_xml_raises(self, tmp_path: Path) -> None:
        xml_path = tmp_path / "bad.xml"
        xml_path.write_text("not xml at all", encoding="utf-8")
        with pytest.raises(ET.ParseError):
            ingest.parse_report(xml_path)

    def test_parse_single_gpo_as_root(self, tmp_path: Path) -> None:
        """A document whose root *is* the GPO (no wrapper) must parse.

        Regression: ``root.iter()`` includes the root element, and the loop's
        ``gpo_elem is root`` guard skipped it, yielding []. The single-GPO
        shape is what Microsoft Security Baseline gpreport.xml files and
        per-GPO backups use.
        """
        gpo_id = "{22222222-2222-2222-2222-222222222222}"
        xml = (
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<GPO xmlns="http://www.microsoft.com/GroupPolicy/Settings">\n'
            "  <Identifier>\n"
            f"    <Identifier>{gpo_id}</Identifier>\n"
            "    <Domain>single.local</Domain>\n"
            "  </Identifier>\n"
            "  <Name>SoloGpo</Name>\n"
            "  <CreatedTime>2026-01-01T00:00:00</CreatedTime>\n"
            "  <ModifiedTime>2026-01-02T00:00:00</ModifiedTime>\n"
            "  <ReadTime>2026-01-03T00:00:00</ReadTime>\n"
            "  <Computer><VersionDirectory>1</VersionDirectory>"
            "<VersionSysvol>1</VersionSysvol><Enabled>true</Enabled></Computer>\n"
            "  <User><VersionDirectory>1</VersionDirectory>"
            "<VersionSysvol>1</VersionSysvol><Enabled>true</Enabled></User>\n"
            "  <FilterDataAvailable>true</FilterDataAvailable>\n"
            "</GPO>\n"
        )
        xml_path = tmp_path / "solo.xml"
        xml_path.write_text(xml, encoding="utf-8")
        gpos = ingest.parse_report(xml_path)
        assert len(gpos) == 1
        assert gpos[0].name == "SoloGpo"
        assert gpos[0].id == "22222222222222222222222222222222"

    def test_parse_wrapper_still_finds_inner_gpos(self, tmp_path: Path) -> None:
        """Wrapper shape (root localname GPO + nested GPO) must still work."""
        # The minimal fixture uses exactly this shape.
        xml_path = tmp_path / "report.xml"
        xml_path.write_text(_min_gpo_xml(), encoding="utf-8")
        gpos = ingest.parse_report(xml_path)
        assert len(gpos) == 1
        assert gpos[0].name == "Test GPO"

    def test_bom_tolerant(self, tmp_path: Path) -> None:
        xml_path = tmp_path / "bom.xml"
        xml_path.write_bytes(b"\xef\xbb\xbf" + _min_gpo_xml().encode("utf-8"))
        gpos = ingest.parse_report(xml_path)
        assert len(gpos) == 1
        assert gpos[0].name == "Test GPO"


class TestParseSingleGpoEdgeCases:
    def test_missing_identifier_gives_empty_id(self, tmp_path: Path) -> None:
        xml = (
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<GPO xmlns="http://www.microsoft.com/GroupPolicy/Settings">\n'
            "  <GPO>\n"
            "    <Name>NoID</Name>\n"
            "    <Computer><Enabled>false</Enabled></Computer>\n"
            "    <User><Enabled>false</Enabled></User>\n"
            "  </GPO>\n"
            "</GPO>\n"
        )
        xml_path = tmp_path / "report.xml"
        xml_path.write_text(xml, encoding="utf-8")
        with pytest.warns(UserWarning, match="no valid identifier"):
            gpos = ingest.parse_report(xml_path)
        assert len(gpos) == 0

    def test_no_sides(self, tmp_path: Path) -> None:
        xml = (
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<GPO xmlns="http://www.microsoft.com/GroupPolicy/Settings">\n'
            "  <GPO>\n"
            "    <Identifier><Identifier>"
            "{11111111-1111-1111-1111-111111111111}"
            "</Identifier></Identifier>\n"
            "    <Name>NoSides</Name>\n"
            "  </GPO>\n"
            "</GPO>\n"
        )
        xml_path = tmp_path / "report.xml"
        xml_path.write_text(xml, encoding="utf-8")
        gpos = ingest.parse_report(xml_path)
        assert len(gpos) == 1
        assert gpos[0].computer_enabled is False
        assert gpos[0].user_enabled is False

    def test_parse_bool_case_insensitive(self, tmp_path: Path) -> None:
        xml = _min_gpo_xml(computer_enabled="True", user_enabled="FALSE")
        xml_path = tmp_path / "report.xml"
        xml_path.write_text(xml, encoding="utf-8")
        gpos = ingest.parse_report(xml_path)
        assert gpos[0].computer_enabled is True
        assert gpos[0].user_enabled is False


class TestLoadEstate:
    def test_load_estate_missing_allgpos(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            ingest.load_estate(tmp_path)

    def test_load_estate_corrupt_allgpos_fails_loud(self, tmp_path: Path) -> None:
        """A corrupt primary input must not silently produce an empty estate.

        Regression: ``load_estate`` previously caught ``ParseError`` and
        warned, producing a valid-looking Estate with zero GPOs — a coverage-
        honesty violation (the estate would render as "complete, just empty").
        Now it raises so the operator knows the input is bad.
        """
        xml_path = tmp_path / "AllGPOs.xml"
        xml_path.write_text("not xml at all <<<", encoding="utf-8")
        with pytest.raises((ValueError, ET.ParseError)):
            ingest.load_estate(tmp_path)

    def test_load_estate_minimal(self, tmp_path: Path) -> None:
        xml_path = tmp_path / "AllGPOs.xml"
        xml_path.write_text(_min_gpo_xml(), encoding="utf-8")
        estate = ingest.load_estate(tmp_path)
        assert isinstance(estate, Estate)
        assert len(estate.gpos) == 1
        assert estate.domain == "test.local"
        assert len(estate.soms) == 0  # no gp-inheritance.json

    def test_load_estate_with_inheritance(self, tmp_path: Path) -> None:
        xml_path = tmp_path / "AllGPOs.xml"
        xml_path.write_text(_min_gpo_xml(), encoding="utf-8")
        inheritance = tmp_path / "gp-inheritance.json"
        inheritance.write_text(
            '[{"Path":"dc=test,dc=local","Name":"test","ContainerType":"domain","GpoInheritanceBlocked":false,"InheritedGpoLinks":[]}]',
            encoding="utf-8",
        )
        estate = ingest.load_estate(tmp_path)
        assert len(estate.soms) == 1
        assert estate.soms[0].path == "dc=test,dc=local"

    def test_load_estate_with_metadata(self, tmp_path: Path) -> None:
        xml_path = tmp_path / "AllGPOs.xml"
        xml_path.write_text(_min_gpo_xml(), encoding="utf-8")
        metadata = tmp_path / "gpo-metadata.json"
        metadata.write_text(
            '[{"Id":"{31B2F340-016D-11D2-945F-00C04FB984F9}","WmiFilter":"MyFilter"}]',
            encoding="utf-8",
        )
        estate = ingest.load_estate(tmp_path)
        assert estate.gpos[0].wmi_filter == "MyFilter"

    def test_load_estate_missing_backfill_versions(self, tmp_path: Path) -> None:
        # XML has empty version fields but metadata provides them
        xml = (
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<GPO xmlns="http://www.microsoft.com/GroupPolicy/Settings">\n'
            "    <GPO>\n"
            "        <Identifier>\n"
            "            <Identifier>{31B2F340-016D-11D2-945F-00C04FB984F9}</Identifier>\n"
            "            <Domain>test.local</Domain>\n"
            "        </Identifier>\n"
            "        <Name>Test GPO</Name>\n"
            "        <Computer>\n"
            "            <VersionDirectory />\n"
            "            <VersionSysvol />\n"
            "            <Enabled>true</Enabled>\n"
            "        </Computer>\n"
            "        <User>\n"
            "            <VersionDirectory />\n"
            "            <VersionSysvol />\n"
            "            <Enabled>true</Enabled>\n"
            "        </User>\n"
            "        <FilterDataAvailable>true</FilterDataAvailable>\n"
            "    </GPO>\n"
            "</GPO>\n"
        )
        xml_path = tmp_path / "AllGPOs.xml"
        xml_path.write_text(xml, encoding="utf-8")
        metadata = tmp_path / "gpo-metadata.json"
        metadata.write_text(
            '[{"Id":"{31B2F340-016D-11D2-945F-00C04FB984F9}",'
            '"ComputerVersionDirectory":"5","ComputerVersionSysvol":"6",'
            '"UserVersionDirectory":"7","UserVersionSysvol":"8"}]',
            encoding="utf-8",
        )
        estate = ingest.load_estate(tmp_path)
        gpo = estate.gpos[0]
        assert gpo.computer_ver_ds == 5
        assert gpo.computer_ver_sysvol == 6
        assert gpo.user_ver_ds == 7
        assert gpo.user_ver_sysvol == 8

    def test_load_estate_sysvol_match(self, tmp_path: Path) -> None:
        xml_path = tmp_path / "AllGPOs.xml"
        xml_path.write_text(_min_gpo_xml(), encoding="utf-8")
        sysvol = tmp_path / "SYSVOL-Policies"
        guid_dir = sysvol / "31b2f340016d11d2945f00c04fb984f9"
        guid_dir.mkdir(parents=True)
        (guid_dir / "dummy.txt").write_text("hello", encoding="utf-8")
        estate = ingest.load_estate(tmp_path)
        assert estate.gpos[0].sysvol_path is not None

    def test_load_estate_sysvol_alt_path(self, tmp_path: Path) -> None:
        xml_path = tmp_path / "AllGPOs.xml"
        xml_path.write_text(_min_gpo_xml(), encoding="utf-8")
        sysvol = tmp_path / "SYSVOL" / "Policies"
        guid_dir = sysvol / "31b2f340016d11d2945f00c04fb984f9"
        guid_dir.mkdir(parents=True)
        estate = ingest.load_estate(tmp_path)
        assert estate.gpos[0].sysvol_path is not None

    def test_scan_sysvol_gaps_corrupt_xml_surfaces_unparseable_files(self, tmp_path: Path) -> None:
        """A truncated Preferences XML is flagged as a coverage gap.

        Regression: the GPP scanners in detection.py catch ``ET.ParseError``
        and continue (correct for resilience), but a corrupt ScheduledTasks.xml
        was therefore silently invisible — a coverage-honesty hazard for a
        security tool. ``_scan_sysvol_gaps`` walks the Preferences layout once
        at ingest time and surfaces every unparseable file.
        """
        from gpo_lens.model import Gpo

        sysvol = tmp_path / "SYSVOL-Policies"
        guid_dir = sysvol / "31b2f340016d11d2945f00c04fb984f9"
        prefs = guid_dir / "Machine" / "Preferences" / "ScheduledTasks"
        prefs.mkdir(parents=True)
        # One good XML, one corrupt XML.
        (prefs / "Good.xml").write_text('<?xml version="1.0"?><root></root>', encoding="utf-8")
        (prefs / "Broken.xml").write_text("<<<not xml<<<", encoding="utf-8")
        gpo = Gpo(
            id="31b2f340016d11d2945f00c04fb984f9",
            name="Test",
            domain="test.local",
            created=None,
            modified=None,
            read=None,
            computer_enabled=True,
            user_enabled=True,
            computer_ver_ds=None,
            computer_ver_sysvol=None,
            user_ver_ds=None,
            user_ver_sysvol=None,
            sddl=None,
            owner=None,
            filter_data_available=False,
            wmi_filter=None,
            sysvol_path=str(guid_dir),
            links=[],
            delegation=[],
            settings=[],
        )
        gaps = [g for g in ingest._scan_sysvol_gaps([gpo]) if g.kind == "corrupt_gpp_xml"]
        assert len(gaps) == 1
        assert gaps[0].kind == "corrupt_gpp_xml"
        assert "Broken.xml" in gaps[0].detail
        assert "Good.xml" not in gaps[0].detail

    def test_scan_sysvol_gaps_no_sysvol_returns_empty(self) -> None:
        from gpo_lens.model import Gpo

        gpo = Gpo(
            id="x",
            name="X",
            domain="d",
            created=None,
            modified=None,
            read=None,
            computer_enabled=True,
            user_enabled=True,
            computer_ver_ds=None,
            computer_ver_sysvol=None,
            user_ver_ds=None,
            user_ver_sysvol=None,
            sddl=None,
            owner=None,
            filter_data_available=False,
            wmi_filter=None,
            sysvol_path=None,
            links=[],
            delegation=[],
            settings=[],
        )
        assert [g for g in ingest._scan_sysvol_gaps([gpo]) if g.kind == "corrupt_gpp_xml"] == []

    def test_scan_sysvol_gaps_corrupt_xml_case_insensitive_and_skips_non_xml(
        self, tmp_path: Path
    ) -> None:
        """Side dirs vary in case on real SYSVOL (MACHINE/USER); non-XML skipped."""
        from gpo_lens.model import Gpo

        sysvol = tmp_path / "SYSVOL-Policies"
        guid_dir = sysvol / "31b2f340016d11d2945f00c04fb984f9"
        # Uppercase side dir, mixed-case Preferences.
        prefs = guid_dir / "USER" / "Preferences" / "Groups"
        prefs.mkdir(parents=True)
        (prefs / "Broken.xml").write_text("<<<not xml", encoding="utf-8")
        # Non-XML files must be ignored.
        (prefs / "notes.txt").write_text("ignore me", encoding="utf-8")
        (prefs / "Good.xml").write_text('<?xml version="1.0"?><root></root>', encoding="utf-8")
        gpo = Gpo(
            id="31b2f340016d11d2945f00c04fb984f9",
            name="Test",
            domain="test.local",
            created=None,
            modified=None,
            read=None,
            computer_enabled=True,
            user_enabled=True,
            computer_ver_ds=None,
            computer_ver_sysvol=None,
            user_ver_ds=None,
            user_ver_sysvol=None,
            sddl=None,
            owner=None,
            filter_data_available=False,
            wmi_filter=None,
            sysvol_path=str(guid_dir),
            links=[],
            delegation=[],
            settings=[],
        )
        gaps = [g for g in ingest._scan_sysvol_gaps([gpo]) if g.kind == "corrupt_gpp_xml"]
        assert len(gaps) == 1
        assert gaps[0].kind == "corrupt_gpp_xml"
        assert "Broken.xml" in gaps[0].detail
        assert "notes.txt" not in gaps[0].detail
        assert "Good.xml" not in gaps[0].detail

    def test_scan_sysvol_gaps_emits_both_corrupt_and_unreadable_in_one_walk(
        self, tmp_path: Path
    ) -> None:
        """WI-066: the merged walker surfaces BOTH a corrupt-gpp-xml gap and
        an unreadable-sysvol gap from a single Preferences walk.

        One Preferences subdir is unreadable (lost traversal bit, as from a zip
        extraction); a sibling subdir holds a corrupt XML file. The former
        two-pass design walked Preferences twice (once per scanner); this
        verifies the merge did not drop either signal and emits both kinds from
        one walk.
        """
        from gpo_lens.model import Gpo

        guid_dir = tmp_path / "GUID"
        prefs = guid_dir / "Machine" / "Preferences"
        sched = prefs / "ScheduledTasks"
        sched.mkdir(parents=True)
        (sched / "Broken.xml").write_text("<<<not xml", encoding="utf-8")
        groups = prefs / "Groups"
        groups.mkdir(parents=True)
        (groups / "Groups.xml").write_text('<?xml version="1.0"?><root></root>', encoding="utf-8")
        groups.chmod(0o000)
        try:
            gpo = Gpo(
                id="guid",
                name="T",
                domain="d",
                created=None,
                modified=None,
                read=None,
                computer_enabled=True,
                user_enabled=True,
                computer_ver_ds=None,
                computer_ver_sysvol=None,
                user_ver_ds=None,
                user_ver_sysvol=None,
                sddl=None,
                owner=None,
                filter_data_available=False,
                wmi_filter=None,
                sysvol_path=str(guid_dir),
                links=[],
                delegation=[],
                settings=[],
            )
            gaps = ingest._scan_sysvol_gaps([gpo])
            kinds = {g.kind for g in gaps}
            assert kinds == {"corrupt_gpp_xml", "unreadable_sysvol"}
            unreadable = [g for g in gaps if g.kind == "unreadable_sysvol"]
            assert len(unreadable) == 1
            # AC-4: the operator remediation hint must survive verbatim.
            assert "chmod -R +rX" in (unreadable[0].detail or "")
            corrupt = [g for g in gaps if g.kind == "corrupt_gpp_xml"]
            assert len(corrupt) == 1
            assert "Broken.xml" in (corrupt[0].detail or "")
        finally:
            groups.chmod(0o755)

    def test_scan_sysvol_gaps_walks_preferences_once_per_gpo(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """WI-066 regression guard: the merged walker iterates each Preferences
        directory (and each subdir) exactly once per GPO per ingest. The old
        design used two separate wrapper scanners, so Preferences was
        iterdir'd twice; ``load_estate`` now
        calls the merged ``_scan_sysvol_gaps`` once. Exact-case side/Preferences
        names keep ``ci_child`` on its fast (``exists``) path so its fallback
        ``iterdir`` does not pollute the Preferences/subdir counts.
        """
        import pathlib

        from gpo_lens.model import Gpo

        guid_dir = tmp_path / "GUID"
        prefs = guid_dir / "Machine" / "Preferences"
        sched = prefs / "ScheduledTasks"
        sched.mkdir(parents=True)
        (sched / "Good.xml").write_text('<?xml version="1.0"?><root></root>', encoding="utf-8")
        gpo = Gpo(
            id="guid",
            name="T",
            domain="d",
            created=None,
            modified=None,
            read=None,
            computer_enabled=True,
            user_enabled=True,
            computer_ver_ds=None,
            computer_ver_sysvol=None,
            user_ver_ds=None,
            user_ver_sysvol=None,
            sddl=None,
            owner=None,
            filter_data_available=False,
            wmi_filter=None,
            sysvol_path=str(guid_dir),
            links=[],
            delegation=[],
            settings=[],
        )

        calls: list[Path] = []
        orig = pathlib.Path.iterdir

        def spy(self: Path) -> object:
            calls.append(self)
            return orig(self)

        monkeypatch.setattr(pathlib.Path, "iterdir", spy)
        ingest._scan_sysvol_gaps([gpo])
        # Preferences itself, and its subdir, each iterdir'd exactly once.
        # A regressed two-pass design would make these 2.
        assert sum(1 for p in calls if p == prefs) == 1
        assert sum(1 for p in calls if p == sched) == 1


class TestParseInheritanceEdgeCases:
    def test_single_dict_not_list(self, tmp_path: Path) -> None:
        json_path = tmp_path / "inheritance.json"
        json_path.write_text(
            '{"Path":"dc=test,dc=local","Name":"test","ContainerType":"domain","GpoInheritanceBlocked":"false","InheritedGpoLinks":[]}',
            encoding="utf-8",
        )
        soms = ingest.parse_inheritance(json_path)
        assert len(soms) == 1
        assert soms[0].inheritance_blocked is False

    def test_gpo_inheritance_blocked_true_string(self, tmp_path: Path) -> None:
        json_path = tmp_path / "inheritance.json"
        json_path.write_text(
            '[{"Path":"dc=test,dc=local","Name":"test","ContainerType":"domain","GpoInheritanceBlocked":"true","InheritedGpoLinks":[]}]',
            encoding="utf-8",
        )
        soms = ingest.parse_inheritance(json_path)
        assert soms[0].inheritance_blocked is True

    def test_links_raw_is_dict(self, tmp_path: Path) -> None:
        json_path = tmp_path / "inheritance.json"
        json_path.write_text(
            '[{"Path":"dc=test,dc=local","Name":"test","ContainerType":"domain","GpoInheritanceBlocked":false,"InheritedGpoLinks":{"GpoId":"{31B2F340-016D-11D2-945F-00C04FB984F9}","Order":1,"Enabled":true,"Enforced":false,"Target":"dc=test,dc=local"}}]',
            encoding="utf-8",
        )
        soms = ingest.parse_inheritance(json_path)
        assert len(soms[0].links) == 1
        assert soms[0].links[0].gpo_id == "31b2f340016d11d2945f00c04fb984f9"

    def test_missing_gpo_id_skipped(self, tmp_path: Path) -> None:
        json_path = tmp_path / "inheritance.json"
        json_path.write_text(
            '[{"Path":"dc=test,dc=local","Name":"test","ContainerType":"domain","GpoInheritanceBlocked":false,"InheritedGpoLinks":[{"Order":1,"Enabled":true,"Enforced":false,"Target":"dc=test,dc=local"}]}]',
            encoding="utf-8",
        )
        soms = ingest.parse_inheritance(json_path)
        assert len(soms[0].links) == 0

    def test_malformed_gpo_id_skipped(self, tmp_path: Path) -> None:
        """A malformed GpoId in one link must not crash the whole topology."""
        json_path = tmp_path / "inheritance.json"
        json_path.write_text(
            '[{"Path":"dc=test,dc=local","Name":"test","ContainerType":"domain",'
            '"GpoInheritanceBlocked":false,"InheritedGpoLinks":['
            '{"GpoId":"not-a-guid","Order":1,"Enabled":true,"Enforced":false,"Target":""},'
            '{"GpoId":"{31B2F340-016D-11D2-945F-00C04FB984F9}","Order":2,"Enabled":true,"Enforced":false,"Target":""}'
            "]}]",
            encoding="utf-8",
        )
        soms = ingest.parse_inheritance(json_path)
        assert len(soms[0].links) == 1
        assert soms[0].links[0].gpo_id == "31b2f340016d11d2945f00c04fb984f9"


class TestMergeMetadataEdgeCases:
    def test_gpo_not_found_is_skipped(self, tmp_path: Path) -> None:
        gpo = Gpo(
            id="aaa-bbb",
            name="Test",
            domain="test.local",
            created=None,
            modified=None,
            read=None,
            computer_enabled=True,
            user_enabled=True,
            computer_ver_ds=None,
            computer_ver_sysvol=None,
            user_ver_ds=None,
            user_ver_sysvol=None,
            sddl=None,
            owner=None,
            filter_data_available=False,
            wmi_filter=None,
            sysvol_path=None,
        )
        metadata = tmp_path / "meta.json"
        metadata.write_text(
            '[{"Id":"{00000000-0000-0000-0000-000000000000}","WmiFilter":"Other"}]',
            encoding="utf-8",
        )
        # Should not crash even though GPO id mismatch
        ingest.merge_metadata(metadata, [gpo])
        assert gpo.wmi_filter is None

    def test_wmi_filter_null(self, tmp_path: Path) -> None:
        gpo = Gpo(
            id="aaa-bbb",
            name="Test",
            domain="test.local",
            created=None,
            modified=None,
            read=None,
            computer_enabled=True,
            user_enabled=True,
            computer_ver_ds=None,
            computer_ver_sysvol=None,
            user_ver_ds=None,
            user_ver_sysvol=None,
            sddl=None,
            owner=None,
            filter_data_available=False,
            wmi_filter=None,
            sysvol_path=None,
        )
        metadata = tmp_path / "meta.json"
        metadata.write_text(
            '[{"Id":"{00000000-0000-0000-0000-000000000000}","WmiFilter":null}]',
            encoding="utf-8",
        )
        ingest.merge_metadata(metadata, [gpo])
        assert gpo.wmi_filter is None

    def test_non_string_wmi_filter_coerces_to_none(self, tmp_path: Path) -> None:
        gpo = Gpo(
            id="aaa-bbb",
            name="Test",
            domain="test.local",
            created=None,
            modified=None,
            read=None,
            computer_enabled=True,
            user_enabled=True,
            computer_ver_ds=None,
            computer_ver_sysvol=None,
            user_ver_ds=None,
            user_ver_sysvol=None,
            sddl=None,
            owner=None,
            filter_data_available=False,
            wmi_filter=None,
            sysvol_path=None,
        )
        metadata = tmp_path / "meta.json"
        metadata.write_text(
            '[{"Id":"{00000000-0000-0000-0000-000000000000}","WmiFilter":123}]',
            encoding="utf-8",
        )
        ingest.merge_metadata(metadata, [gpo])
        assert gpo.wmi_filter is None


class TestParseWmiFilters:
    def test_parse_wmi_filters_list(self, tmp_path: Path) -> None:
        j = tmp_path / "wmi-filters.json"
        j.write_text(
            '[{"Name":"WorkstationFilter","Query":"Select * from Win32_OperatingSystem"}]',
            encoding="utf-8",
        )
        filters = ingest.parse_wmi_filters(j)
        assert len(filters) == 1
        assert filters[0].name == "WorkstationFilter"
        assert "Win32_OperatingSystem" in filters[0].query

    def test_parse_wmi_filters_single_dict(self, tmp_path: Path) -> None:
        j = tmp_path / "wmi-filters.json"
        j.write_text(
            '{"Name":"F1","Query":"SELECT * FROM Win32_ComputerSystem"}',
            encoding="utf-8",
        )
        filters = ingest.parse_wmi_filters(j)
        assert len(filters) == 1
        assert filters[0].name == "F1"

    def test_parse_wmi_filters_empty_name_skipped(self, tmp_path: Path) -> None:
        j = tmp_path / "wmi-filters.json"
        j.write_text(
            '[{"Name":"","Query":"x"},{"Name":"Valid","Query":"y"}]',
            encoding="utf-8",
        )
        filters = ingest.parse_wmi_filters(j)
        assert len(filters) == 1
        assert filters[0].name == "Valid"

    def test_load_estate_with_wmi_filters(self, tmp_path: Path) -> None:
        xml_path = tmp_path / "AllGPOs.xml"
        xml_path.write_text(_min_gpo_xml(), encoding="utf-8")
        wf = tmp_path / "wmi-filters.json"
        wf.write_text(
            '[{"Name":"TestFilter","Query":"SELECT * FROM Foo"}]',
            encoding="utf-8",
        )
        estate = ingest.load_estate(tmp_path)
        assert len(estate.wmi_filters) == 1
        assert estate.wmi_filters[0].name == "TestFilter"


class TestParseOuTree:
    def test_parse_ou_tree_list(self, tmp_path: Path) -> None:
        j = tmp_path / "ou-tree.json"
        j.write_text(
            '[{"DistinguishedName":"OU=WS,DC=test,DC=local","Name":"WS",'
            '"gPLink":"[LDAP://cn={31B2F340-016D-11D2-945F-00C04FB984F9},...;0]",'
            '"gPOptions":0}]',
            encoding="utf-8",
        )
        records = ingest.parse_ou_tree(j)
        assert len(records) == 1
        assert records[0].dn == "OU=WS,DC=test,DC=local"
        assert records[0].gp_options == 0
        assert records[0].gp_link is not None

    def test_parse_ou_tree_single_dict(self, tmp_path: Path) -> None:
        j = tmp_path / "ou-tree.json"
        j.write_text(
            '{"DistinguishedName":"OU=WS,DC=test,DC=local","Name":"WS",'
            '"gPLink":null,"gPOptions":1}',
            encoding="utf-8",
        )
        records = ingest.parse_ou_tree(j)
        assert len(records) == 1
        assert records[0].gp_options == 1
        assert records[0].gp_link is None

    def test_load_estate_with_ou_tree(self, tmp_path: Path) -> None:
        xml_path = tmp_path / "AllGPOs.xml"
        xml_path.write_text(_min_gpo_xml(), encoding="utf-8")
        ot = tmp_path / "ou-tree.json"
        ot.write_text(
            '[{"DistinguishedName":"OU=WS,DC=test,DC=local","Name":"WS",'
            '"gPLink":null,"gPOptions":0}]',
            encoding="utf-8",
        )
        estate = ingest.load_estate(tmp_path)
        assert len(estate.ou_tree) == 1
        assert estate.ou_tree[0].name == "WS"


class TestParsePrincipals:
    def test_parse_principals_present(self, tmp_path: Path) -> None:
        import json

        payload = {
            "collected": "2026-06-19T00:00:00Z",
            "domain": "ad.test",
            "principals": {
                "S-1-5-21-100-200-300-1131": {
                    "name": "TEST\\GPO-Admins",
                    "sam": "GPO-Admins",
                    "type": "Group",
                    "domain": "TEST",
                },
                "S-1-5-11": {
                    "name": "Authenticated Users",
                    "sam": "Authenticated Users",
                    "type": "WellKnown",
                    "domain": "",
                },
            },
        }
        j = tmp_path / "principals.json"
        j.write_text(json.dumps(payload), encoding="utf-8")
        principals = ingest.parse_principals(j)
        assert len(principals) == 2
        rp = principals["s-1-5-21-100-200-300-1131"]
        assert rp.name == "TEST\\GPO-Admins"
        assert rp.sam == "GPO-Admins"
        assert rp.principal_type == "Group"
        assert rp.domain == "TEST"
        assert rp.resolved is True
        assert principals["s-1-5-11"].name == "Authenticated Users"

    def test_parse_principals_bom_tolerant(self, tmp_path: Path) -> None:
        import json

        payload = {
            "principals": {
                "S-1-5-21-1-2-3-1000": {
                    "name": "X\\Admins",
                    "sam": "Admins",
                    "type": "Group",
                    "domain": "X",
                },
            },
        }
        j = tmp_path / "principals.json"
        j.write_bytes(b"\xef\xbb\xbf" + json.dumps(payload).encode("utf-8"))
        principals = ingest.parse_principals(j)
        assert "s-1-5-21-1-2-3-1000" in principals
        assert principals["s-1-5-21-1-2-3-1000"].name == "X\\Admins"

    def test_parse_principals_partial_resolution(self, tmp_path: Path) -> None:
        """Some SIDs resolved, some Unresolved (Phase B finding, not a crash)."""
        import json

        payload = {
            "principals": {
                "S-1-5-21-1-2-3-1000": {
                    "name": "X\\Admins",
                    "sam": "Admins",
                    "type": "Group",
                    "domain": "X",
                },
                "S-1-5-21-1-2-3-9999": {
                    "name": "",
                    "sam": "",
                    "type": "Unresolved",
                    "domain": "",
                },
            },
        }
        j = tmp_path / "principals.json"
        j.write_text(json.dumps(payload), encoding="utf-8")
        principals = ingest.parse_principals(j)
        assert len(principals) == 2
        assert principals["s-1-5-21-1-2-3-1000"].resolved is True
        unresolved = principals["s-1-5-21-1-2-3-9999"]
        assert unresolved.resolved is False
        assert unresolved.principal_type == "Unresolved"

    def test_parse_principals_empty_principals_key(self, tmp_path: Path) -> None:
        j = tmp_path / "principals.json"
        j.write_text('{"principals":{}}', encoding="utf-8")
        principals = ingest.parse_principals(j)
        assert principals == {}

    def test_parse_principals_missing_principals_key(self, tmp_path: Path) -> None:
        j = tmp_path / "principals.json"
        j.write_text('{"collected":"2026-01-01","domain":"x"}', encoding="utf-8")
        principals = ingest.parse_principals(j)
        assert principals == {}

    def test_parse_principals_skips_non_dict_entries(self, tmp_path: Path) -> None:
        import json

        payload = {
            "principals": {
                "S-1-5-11": "bad-string",
                "S-1-5-21-1-2-3-1000": {
                    "name": "X",
                    "sam": "X",
                    "type": "Group",
                    "domain": "",
                },
            },
        }
        j = tmp_path / "principals.json"
        j.write_text(json.dumps(payload), encoding="utf-8")
        principals = ingest.parse_principals(j)
        assert len(principals) == 1
        assert "s-1-5-21-1-2-3-1000" in principals

    def test_load_estate_without_principals_json(self, tmp_path: Path) -> None:
        """AC-3: absent principals.json → empty dict, no crash."""
        xml_path = tmp_path / "AllGPOs.xml"
        xml_path.write_text(_min_gpo_xml(), encoding="utf-8")
        estate = ingest.load_estate(tmp_path)
        assert estate.principals == {}

    def test_load_estate_with_principals_json(self, tmp_path: Path) -> None:
        import json

        xml_path = tmp_path / "AllGPOs.xml"
        xml_path.write_text(_min_gpo_xml(), encoding="utf-8")
        payload = {
            "principals": {
                "S-1-5-21-1-2-3-1131": {
                    "name": "T\\Admins",
                    "sam": "Admins",
                    "type": "Group",
                    "domain": "T",
                },
            },
        }
        (tmp_path / "principals.json").write_text(json.dumps(payload), encoding="utf-8")
        estate = ingest.load_estate(tmp_path)
        assert len(estate.principals) == 1
        assert estate.principals["s-1-5-21-1-2-3-1131"].name == "T\\Admins"

    def test_load_estate_with_malformed_principals_json_warns(self, tmp_path: Path) -> None:
        """Malformed principals.json should warn, not crash; estate still loads."""
        xml_path = tmp_path / "AllGPOs.xml"
        xml_path.write_text(_min_gpo_xml(), encoding="utf-8")
        pj = tmp_path / "principals.json"
        pj.write_text("{not valid json", encoding="utf-8")
        with pytest.warns(UserWarning, match="Skipping principals.json"):
            estate = ingest.load_estate(tmp_path)
        assert estate.principals == {}


class TestParseGroupMembers:
    def test_parse_group_members_present(self, tmp_path: Path) -> None:
        import json

        payload = {
            "collected": "2026-06-19T00:00:00Z",
            "domain": "ad.test",
            "groups": {
                "S-1-5-21-100-200-300-1131": {
                    "name": "TEST\\GPO-Admins",
                    "members": ["S-1-5-21-100-200-300-1001", "S-1-5-21-100-200-300-1002"],
                    "member_count": 2,
                },
                "s-1-5-11": {
                    "name": "Authenticated Users",
                    "members": [],
                    "member_count": 0,
                    "implicit": "All authenticated domain principals",
                },
            },
        }
        j = tmp_path / "group-members.json"
        j.write_text(json.dumps(payload), encoding="utf-8")
        groups = ingest.parse_group_members(j)
        assert len(groups) == 2
        gm = groups["s-1-5-21-100-200-300-1131"]
        assert gm.name == "TEST\\GPO-Admins"
        assert gm.members == ("s-1-5-21-100-200-300-1001", "s-1-5-21-100-200-300-1002")
        assert gm.member_count == 2
        au = groups["s-1-5-11"]
        assert au.implicit == "All authenticated domain principals"
        assert au.members == ()

    def test_parse_group_members_bom_tolerant(self, tmp_path: Path) -> None:
        import json

        payload = {
            "groups": {
                "S-1-5-21-1-2-3-1131": {
                    "name": "X\\Admins",
                    "members": ["S-1-5-21-1-2-3-1000"],
                    "member_count": 1,
                },
            },
        }
        j = tmp_path / "group-members.json"
        j.write_bytes(b"\xef\xbb\xbf" + json.dumps(payload).encode("utf-8"))
        groups = ingest.parse_group_members(j)
        assert "s-1-5-21-1-2-3-1131" in groups
        assert groups["s-1-5-21-1-2-3-1131"].members == ("s-1-5-21-1-2-3-1000",)

    def test_parse_group_members_missing_groups_key(self, tmp_path: Path) -> None:
        j = tmp_path / "group-members.json"
        j.write_text('{"collected":"2026-01-01","domain":"x"}', encoding="utf-8")
        assert ingest.parse_group_members(j) == {}

    def test_parse_group_members_skips_non_dict_entries(self, tmp_path: Path) -> None:
        import json

        payload = {
            "groups": {
                "S-1-5-11": "bad-string",
                "S-1-5-21-1-2-3-1131": {
                    "name": "X",
                    "members": ["S-1-5-21-1-2-3-1000"],
                    "member_count": 1,
                },
            },
        }
        j = tmp_path / "group-members.json"
        j.write_text(json.dumps(payload), encoding="utf-8")
        groups = ingest.parse_group_members(j)
        assert len(groups) == 1
        assert "s-1-5-21-1-2-3-1131" in groups

    def test_load_estate_without_group_members_json(self, tmp_path: Path) -> None:
        xml_path = tmp_path / "AllGPOs.xml"
        xml_path.write_text(_min_gpo_xml(), encoding="utf-8")
        estate = ingest.load_estate(tmp_path)
        assert estate.group_members == {}

    def test_load_estate_with_group_members_json(self, tmp_path: Path) -> None:
        import json

        xml_path = tmp_path / "AllGPOs.xml"
        xml_path.write_text(_min_gpo_xml(), encoding="utf-8")
        payload = {
            "groups": {
                "S-1-5-21-1-2-3-1131": {
                    "name": "T\\Admins",
                    "members": ["S-1-5-21-1-2-3-1000"],
                    "member_count": 1,
                },
            },
        }
        (tmp_path / "group-members.json").write_text(json.dumps(payload), encoding="utf-8")
        estate = ingest.load_estate(tmp_path)
        assert len(estate.group_members) == 1
        assert estate.group_members["s-1-5-21-1-2-3-1131"].name == "T\\Admins"


# ---------------------------------------------------------------------------
# WI-006: Streaming decompression size enforcement tests
# ---------------------------------------------------------------------------


class TestSizeLimitedReader:
    """Tests for SizeLimitedReader - the core streaming size enforcer."""

    def test_under_limit(self) -> None:
        from gpo_lens.ingest import SizeLimitedReader

        src = io.BytesIO(b"hello")
        reader = SizeLimitedReader(src, 100)
        data = reader.read()
        assert data == b"hello"

    def test_exceeds_limit(self) -> None:
        from gpo_lens.ingest import SizeLimitedReader

        src = io.BytesIO(b"x" * 200)
        reader = SizeLimitedReader(src, 100)
        with pytest.raises(ValueError, match="exceeds limit"):
            reader.read(65536)

    def test_exact_limit(self) -> None:
        from gpo_lens.ingest import SizeLimitedReader

        src = io.BytesIO(b"hello")
        reader = SizeLimitedReader(src, 5)
        data = reader.read()
        assert data == b"hello"

    def test_over_by_one(self) -> None:
        from gpo_lens.ingest import SizeLimitedReader

        src = io.BytesIO(b"hello!")
        reader = SizeLimitedReader(src, 5)
        with pytest.raises(ValueError, match="exceeds limit"):
            reader.read()

    def test_multiple_reads_accumulate(self) -> None:
        from gpo_lens.ingest import SizeLimitedReader

        src = io.BytesIO(b"aaaaaabbbbbb")
        reader = SizeLimitedReader(src, 10)
        reader.read(3)
        reader.read(3)
        reader.read(3)
        with pytest.raises(ValueError, match="exceeds limit"):
            reader.read(3)

    def test_empty_read(self) -> None:
        from gpo_lens.ingest import SizeLimitedReader

        src = io.BytesIO(b"")
        reader = SizeLimitedReader(src, 100)
        data = reader.read()
        assert data == b""

    def test_large_read_request_capped(self) -> None:
        """A read with a huge size is capped to 65536, preventing excessive allocation."""
        from gpo_lens.ingest import SizeLimitedReader

        # 200 bytes of data, 300-byte limit
        src = io.BytesIO(b"x" * 200)
        reader = SizeLimitedReader(src, 300)
        # Request 1 GB read — should be capped, not allocate 1 GB
        chunk = reader.read(1_073_741_824)
        # BytesIO only has 200 bytes, so we get all of them
        assert len(chunk) == 200
        assert reader._total == 200


class TestStreamingZipRead:
    """Tests for _streaming_zip_read - streaming decompression with size enforcement."""

    def test_normal_read_under_limit(self) -> None:
        from gpo_lens.ingest import _streaming_zip_read

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("test.txt", b"hello world")
        buf.seek(0)
        with zipfile.ZipFile(buf, "r") as zf:
            counter = [0]
            data = _streaming_zip_read(zf, "test.txt", counter, max_bytes=1024)
        assert data == b"hello world"
        assert counter[0] == 11

    def test_rejects_oversized_entry(self) -> None:
        from gpo_lens.ingest import _streaming_zip_read

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("big.txt", b"x" * 200)
        buf.seek(0)
        with zipfile.ZipFile(buf, "r") as zf:
            counter = [0]
            with pytest.raises(ValueError, match="exceeds limit"):
                _streaming_zip_read(zf, "big.txt", counter, max_bytes=100)

    def test_accumulates_across_entries(self) -> None:
        from gpo_lens.ingest import _streaming_zip_read

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("a.txt", b"a" * 60)
            zf.writestr("b.txt", b"b" * 60)
        buf.seek(0)
        with zipfile.ZipFile(buf, "r") as zf:
            counter = [0]
            _streaming_zip_read(zf, "a.txt", counter, max_bytes=100)
            assert counter[0] == 60
            # Second read should fail because cumulative exceeds 100
            with pytest.raises(ValueError, match="exceeds limit"):
                _streaming_zip_read(zf, "b.txt", counter, max_bytes=100)

    def test_spoofed_file_size_header_still_enforced(self) -> None:
        """Zip-bomb vector: info.file_size says 1 byte, actual content is large.

        _streaming_zip_read must reject this because it counts actual
        decompressed bytes, not the declarative header value.

        NOTE: Python's zipfile.ZipExtFile validates CRC and truncates
        output to file_size bytes, so a real binary-spoofed zip raises
        BadZipFile before our reader sees it.  We test our streaming
        reader's independence from info.file_size by simulating a
        decompression stream that yields more bytes than the header claims.
        """
        from gpo_lens.ingest import _streaming_zip_read

        # Simulate zf.open("bomb.txt") returning 200 bytes
        # even though info.file_size says 1
        fake_stream = io.BytesIO(b"A" * 200)
        mock_zf = MagicMock()
        mock_zf.open.return_value.__enter__ = lambda s: fake_stream
        mock_zf.open.return_value.__exit__ = MagicMock(return_value=False)

        counter = [0]
        with pytest.raises(ValueError, match="exceeds limit"):
            _streaming_zip_read(mock_zf, "bomb.txt", counter, max_bytes=100)

    def test_does_not_check_info_file_size_before_read(self) -> None:
        """Verify _streaming_zip_read doesn't use info.file_size as a pre-check.

        A naive implementation might check ``if info.file_size > limit: reject``
        before opening the entry, which would be bypassed by spoofed headers.
        Our implementation enforces the limit during actual streaming reads.
        """
        from gpo_lens.ingest import _streaming_zip_read

        # Create a zip with content that exceeds our test limit
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("big.txt", b"x" * 200)
        buf.seek(0)
        with zipfile.ZipFile(buf, "r") as zf:
            # info.file_size correctly says 200 -- our reader catches it
            # during streaming, not by checking the header beforehand
            counter = [0]
            with pytest.raises(ValueError, match="exceeds limit"):
                _streaming_zip_read(zf, "big.txt", counter, max_bytes=100)

    def test_none_max_bytes_uses_default(self) -> None:
        """When max_bytes is None, _streaming_zip_read uses _MAX_DECOMPRESSED_BYTES."""
        import unittest.mock

        from gpo_lens.ingest import _streaming_zip_read

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("test.txt", b"hello")
        buf.seek(0)
        with zipfile.ZipFile(buf, "r") as zf:
            counter = [0]
            with unittest.mock.patch("gpo_lens.ingest._MAX_DECOMPRESSED_BYTES", 100):
                # With the default limit of 100, a 5-byte entry is fine
                data = _streaming_zip_read(zf, "test.txt", counter)
            assert data == b"hello"


class TestStreamingBaselineZip:
    """Tests for load_baseline_from_zip with streaming decompression enforcement."""

    def _min_gpo_xml(self) -> str:
        return (
            '<?xml version="1.0" encoding="utf-8"?>\n'
            "<GPO>\n"
            "  <Identifier>\n"
            "    <Identifier>{99999999-9999-9999-9999-999999999999}</Identifier>\n"
            "    <Domain>test.local</Domain>\n"
            "  </Identifier>\n"
            "  <Name>Test GPO</Name>\n"
            "  <CreatedTime>2024-01-01T00:00:00</CreatedTime>\n"
            "  <ModifiedTime>2024-01-01T00:00:00</ModifiedTime>\n"
            "  <ReadTime>2024-01-01T00:00:00</ReadTime>\n"
            "  <Computer><Enabled>true</Enabled></Computer>\n"
            "  <User><Enabled>true</Enabled></User>\n"
            "  <FilterDataAvailable>false</FilterDataAvailable>\n"
            "</GPO>\n"
        )

    def test_normal_baseline_zip_loads(self, tmp_path: Path) -> None:
        gpo_xml = self._min_gpo_xml()
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(
                "GPOs/{99999999-9999-9999-9999-999999999999}/gpreport.xml",
                gpo_xml,
            )
        zip_path = tmp_path / "baseline.zip"
        zip_path.write_bytes(buf.getvalue())

        gpos = ingest.load_baseline_from_zip(zip_path)
        assert len(gpos) == 1
        assert gpos[0].name == "Test GPO"

    def test_nested_baseline_zip_loads(self, tmp_path: Path) -> None:
        """Outer zip containing an inner zip with GPOs."""
        gpo_xml = self._min_gpo_xml()
        inner_buf = io.BytesIO()
        with zipfile.ZipFile(inner_buf, "w", zipfile.ZIP_DEFLATED) as inner:
            inner.writestr(
                "GPOs/{99999999-9999-9999-9999-999999999999}/gpreport.xml",
                gpo_xml,
            )
        outer_buf = io.BytesIO()
        with zipfile.ZipFile(outer_buf, "w", zipfile.ZIP_DEFLATED) as outer:
            outer.writestr("Windows 11 Security Baseline.zip", inner_buf.getvalue())

        zip_path = tmp_path / "baseline.zip"
        zip_path.write_bytes(outer_buf.getvalue())

        gpos = ingest.load_baseline_from_zip(zip_path)
        assert len(gpos) == 1
        assert gpos[0].name == "Test GPO"

    def test_large_nested_zip_rejected(self, tmp_path: Path) -> None:
        """Nested zip with large content must be warned and skipped, not crash.

        A real zip-bomb uses highly compressible data inside nested zips.
        The inner zip decompresses to much more than its compressed size.
        Our streaming reader catches this by counting actual decompressed
        bytes, not trusting header values. The oversized entry is skipped
        with a warning rather than crashing the entire baseline load.
        """
        import unittest.mock

        gpo_xml = self._min_gpo_xml()
        large_padding = " " * 5000
        padded_xml = gpo_xml + large_padding

        inner_buf = io.BytesIO()
        with zipfile.ZipFile(inner_buf, "w", zipfile.ZIP_DEFLATED) as inner:
            inner.writestr(
                "GPOs/{99999999-9999-9999-9999-999999999999}/gpreport.xml",
                padded_xml,
            )
        inner_data = inner_buf.getvalue()

        outer_buf = io.BytesIO()
        with zipfile.ZipFile(outer_buf, "w", zipfile.ZIP_DEFLATED) as outer:
            outer.writestr("baseline.zip", inner_data)

        zip_path = tmp_path / "baseline.zip"
        zip_path.write_bytes(outer_buf.getvalue())

        with unittest.mock.patch("gpo_lens.ingest._MAX_BASELINE_UNCOMPRESSED_BYTES", 200):
            with pytest.warns(UserWarning, match="exceeds limit"):
                gpos = ingest.load_baseline_from_zip(zip_path)
        assert gpos == []

    def test_large_direct_zip_rejected(self, tmp_path: Path) -> None:
        """Direct zip (no nesting) with large content must be warned and skipped."""
        import unittest.mock

        gpo_xml = self._min_gpo_xml()
        padded_xml = gpo_xml + " " * 5000

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("GPOs/test/gpreport.xml", padded_xml)

        zip_path = tmp_path / "baseline.zip"
        zip_path.write_bytes(buf.getvalue())

        with unittest.mock.patch("gpo_lens.ingest._MAX_BASELINE_UNCOMPRESSED_BYTES", 200):
            with pytest.warns(UserWarning, match="exceeds limit"):
                gpos = ingest.load_baseline_from_zip(zip_path)
        assert gpos == []


# ---------------------------------------------------------------------------
# container_type normalization (Get-GPInheritance serializes the SomType enum
# as an integer; the rest of gpo-lens expects the canonical lowercase string)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw, expected",
    [
        (1, "domain"),  # ConvertTo-Json serializes SomType.Domain as 1
        (2, "ou"),  # SomType.OrganizationalUnit
        (0, "site"),
        ("1", "domain"),  # string-of-int form
        ("2", "ou"),
        ("Domain", "domain"),  # -EnumsAsStrings form
        ("OU", "ou"),
        ("OrganizationalUnit", "ou"),
        ("site", "site"),
        (True, ""),  # bool must not be read as int 1
        (None, ""),
    ],
)
def test_normalize_container_type(raw: object, expected: str) -> None:
    assert ingest._normalize_container_type(raw) == expected


def test_parse_inheritance_normalizes_integer_container_type(tmp_path: Path) -> None:
    """Real collector output carries integer ContainerType; parse_inheritance
    must emit the canonical string so the /ou type filter and merge site/domain
    logic match. Regression for the silently-broken type filter."""
    import json

    data = [
        {
            "Path": "dc=test,dc=local",
            "Name": "test.local",
            "ContainerType": 1,
            "GpoInheritanceBlocked": False,
            "InheritedGpoLinks": [],
        },
        {
            "Path": "ou=eng,dc=test,dc=local",
            "Name": "eng",
            "ContainerType": 2,
            "GpoInheritanceBlocked": False,
            "InheritedGpoLinks": [],
        },
    ]
    p = tmp_path / "gp-inheritance.json"
    p.write_text(json.dumps(data))
    soms = ingest.parse_inheritance(p)
    by_type = {s.container_type for s in soms}
    assert by_type == {"domain", "ou"}


class TestLoadBaselineFromZipErrorHandling:
    def test_oversized_inner_zip_skipped_not_crash(self, tmp_path: Path) -> None:
        import unittest.mock

        good_xml = (
            '<?xml version="1.0" encoding="utf-8"?>\n'
            "<GPO>\n"
            "  <Identifier><Identifier>{99999999-9999-9999-9999-999999999999}</Identifier>"
            "<Domain>test.local</Domain></Identifier>\n"
            "  <Name>Good GPO</Name>\n"
            "  <Computer><Enabled>true</Enabled></Computer>\n"
            "  <User><Enabled>true</Enabled></User>\n"
            "  <FilterDataAvailable>false</FilterDataAvailable>\n"
            "</GPO>\n"
        )
        large_padding = " " * 5000
        bad_xml = good_xml + large_padding

        inner_bad = io.BytesIO()
        with zipfile.ZipFile(inner_bad, "w", zipfile.ZIP_DEFLATED) as inner:
            inner.writestr("GPOs/bad/gpreport.xml", bad_xml)
        inner_good = io.BytesIO()
        with zipfile.ZipFile(inner_good, "w", zipfile.ZIP_DEFLATED) as inner:
            inner.writestr("GPOs/good/gpreport.xml", good_xml)

        outer_buf = io.BytesIO()
        with zipfile.ZipFile(outer_buf, "w", zipfile.ZIP_DEFLATED) as outer:
            outer.writestr("bad.zip", inner_bad.getvalue())
            outer.writestr("good.zip", inner_good.getvalue())

        zip_path = tmp_path / "baseline.zip"
        zip_path.write_bytes(outer_buf.getvalue())

        with unittest.mock.patch("gpo_lens.ingest._MAX_BASELINE_UNCOMPRESSED_BYTES", 2000):
            with pytest.warns(UserWarning, match="exceeds limit"):
                gpos = ingest.load_baseline_from_zip(zip_path)
        good_ids = [g.name for g in gpos if g.name == "Good GPO"]
        assert len(good_ids) == 1

    def test_oversized_direct_gpreport_warns_not_crash(self, tmp_path: Path) -> None:
        import unittest.mock

        good_xml = (
            '<?xml version="1.0" encoding="utf-8"?>\n'
            "<GPO>\n"
            "  <Identifier><Identifier>{99999999-9999-9999-9999-999999999999}</Identifier>"
            "<Domain>test.local</Domain></Identifier>\n"
            "  <Name>Good</Name>\n"
            "  <Computer><Enabled>true</Enabled></Computer>\n"
            "  <User><Enabled>true</Enabled></User>\n"
            "  <FilterDataAvailable>false</FilterDataAvailable>\n"
            "</GPO>\n"
        )
        padded = good_xml + " " * 5000

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("GPOs/test/gpreport.xml", padded)

        zip_path = tmp_path / "baseline.zip"
        zip_path.write_bytes(buf.getvalue())

        with unittest.mock.patch("gpo_lens.ingest._MAX_BASELINE_UNCOMPRESSED_BYTES", 200):
            with pytest.warns(UserWarning, match="exceeds limit"):
                gpos = ingest.load_baseline_from_zip(zip_path)
        assert gpos == []


class TestNonDictArrayGuards:
    def test_parse_inheritance_skips_non_dict(self, tmp_path: Path) -> None:
        j = tmp_path / "inh.json"
        j.write_text(
            '[{"Path":"dc=t,dc=l","Name":"t","ContainerType":"domain",'
            '"GpoInheritanceBlocked":false,"InheritedGpoLinks":[]},'
            '"bad-string", 42, null]',
            encoding="utf-8",
        )
        with pytest.warns(UserWarning, match="non-dict"):
            soms = ingest.parse_inheritance(j)
        assert len(soms) == 1
        assert soms[0].name == "t"

    def test_parse_wmi_filters_skips_non_dict(self, tmp_path: Path) -> None:
        j = tmp_path / "wmi.json"
        j.write_text(
            '[{"Name":"F1","Query":"q"}, "bad", null]',
            encoding="utf-8",
        )
        with pytest.warns(UserWarning, match="non-dict"):
            filters = ingest.parse_wmi_filters(j)
        assert len(filters) == 1
        assert filters[0].name == "F1"

    def test_parse_ou_tree_skips_non_dict(self, tmp_path: Path) -> None:
        j = tmp_path / "ou.json"
        j.write_text(
            '[{"DistinguishedName":"OU=x,DC=t","Name":"x","gPLink":null,"gPOptions":0},"bad", 123]',
            encoding="utf-8",
        )
        with pytest.warns(UserWarning, match="non-dict"):
            records = ingest.parse_ou_tree(j)
        assert len(records) == 1
        assert records[0].name == "x"

    def test_parse_sites_skips_non_dict(self, tmp_path: Path) -> None:
        j = tmp_path / "sites.json"
        j.write_text(
            '[{"DistinguishedName":"CN=Site1","Name":"Site1","gPLink":null},"bad", null]',
            encoding="utf-8",
        )
        with pytest.warns(UserWarning, match="non-dict"):
            sites = ingest.parse_sites(j)
        assert len(sites) == 1
        assert sites[0].name == "Site1"

    def test_parse_coverage_gaps_skips_non_dict_in_inventory(self, tmp_path: Path) -> None:
        inv = tmp_path / "gpo-inventory.json"
        inv.write_text(
            '[{"Id":"{00000000-0000-0000-0000-000000000001}","DisplayName":"Gap1"},"bad", null]',
            encoding="utf-8",
        )
        errs = tmp_path / "collection-errors.json"
        errs.write_text("[]", encoding="utf-8")
        with pytest.warns(UserWarning, match="non-dict"):
            gaps = ingest.parse_coverage_gaps(inv, errs, [])
        assert len(gaps) == 1
        assert gaps[0].kind == "inaccessible"

    def test_parse_coverage_gaps_skips_non_dict_in_errors(self, tmp_path: Path) -> None:
        inv = tmp_path / "gpo-inventory.json"
        inv.write_text("[]", encoding="utf-8")
        errs = tmp_path / "collection-errors.json"
        errs.write_text(
            '[{"GpoId":"{00000000-0000-0000-0000-000000000002}","DisplayName":"Err1",'
            '"Error":"fail"}, "bad", null]',
            encoding="utf-8",
        )
        with pytest.warns(UserWarning, match="non-dict"):
            gaps = ingest.parse_coverage_gaps(inv, errs, [])
        assert len(gaps) == 1
        assert gaps[0].kind == "collection_error"


class TestFloatOrderValue:
    def test_float_order_preserved(self, tmp_path: Path) -> None:
        j = tmp_path / "inh.json"
        j.write_text(
            '[{"Path":"dc=t,dc=l","Name":"t","ContainerType":"domain",'
            '"GpoInheritanceBlocked":false,"InheritedGpoLinks":'
            '[{"GpoId":"{31B2F340-016D-11D2-945F-00C04FB984F9}",'
            '"Order":3.0,"Enabled":true,"Enforced":false,"Target":"dc=t,dc=l"}]}]',
            encoding="utf-8",
        )
        soms = ingest.parse_inheritance(j)
        assert len(soms[0].links) == 1
        assert soms[0].links[0].order == 3

    def test_float_order_zero(self, tmp_path: Path) -> None:
        j = tmp_path / "inh.json"
        j.write_text(
            '[{"Path":"dc=t,dc=l","Name":"t","ContainerType":"domain",'
            '"GpoInheritanceBlocked":false,"InheritedGpoLinks":'
            '[{"GpoId":"{31B2F340-016D-11D2-945F-00C04FB984F9}",'
            '"Order":1.0,"Enabled":true,"Enforced":false,"Target":"dc=t,dc=l"}]}]',
            encoding="utf-8",
        )
        soms = ingest.parse_inheritance(j)
        assert soms[0].links[0].order == 1

    def test_int_order_still_works(self, tmp_path: Path) -> None:
        j = tmp_path / "inh.json"
        j.write_text(
            '[{"Path":"dc=t,dc=l","Name":"t","ContainerType":"domain",'
            '"GpoInheritanceBlocked":false,"InheritedGpoLinks":'
            '[{"GpoId":"{31B2F340-016D-11D2-945F-00C04FB984F9}",'
            '"Order":5,"Enabled":true,"Enforced":false,"Target":"dc=t,dc=l"}]}]',
            encoding="utf-8",
        )
        soms = ingest.parse_inheritance(j)
        assert soms[0].links[0].order == 5


# --- Registry CSE parsing: readable identities instead of hashed blobs --------
NS = "http://www.microsoft.com/GroupPolicy/Settings"


class TestRegistryIdentities:
    def test_gpp_registry_expands_to_one_row_per_properties(self):
        block = ET.fromstring(
            f'<RegistrySettings xmlns="{NS}">'
            '<Collection name="Outer">'
            '<Registry name="a"><Properties hive="HKEY_LOCAL_MACHINE" '
            'key="SOFTWARE\\Acme" name="Foo" type="REG_SZ" value="1" '
            'action="C"/></Registry>'
            '<Registry name="b"><Properties hive="HKEY_CURRENT_USER" '
            'key="SOFTWARE\\B" name="" type="REG_DWORD" value="0"/></Registry>'
            "</Collection></RegistrySettings>"
        )
        rows = ingest._parse_gpp_registry(block)
        assert len(rows) == 2
        ident, name, val, raw = rows[0]
        assert ident == "HKLM\\SOFTWARE\\Acme:Foo"
        assert name == "Foo"
        assert val == "[REG_SZ] 1"
        # raw stays lossless enough for merge's action extraction
        assert raw["@attr"]["action"] == "C"
        # empty value name renders (Default), hive shortens
        assert rows[1][0] == "HKCU\\SOFTWARE\\B"
        assert rows[1][1] == "(Default)"

    def test_gpp_ignores_properties_without_key_or_hive(self):
        block = ET.fromstring(
            f'<RegistrySettings xmlns="{NS}"><Properties name="x"/></RegistrySettings>'
        )
        assert ingest._parse_gpp_registry(block) == []

    def test_admin_template_policy_uses_category_qualified_name(self):
        block = ET.fromstring(
            f'<Policy xmlns="{NS}"><Name>Site to Zone Assignment List</Name>'
            "<State>Enabled</State>"
            "<Category>Windows Components/Internet Explorer</Category></Policy>"
        )
        ident, name, val = ingest._parse_admin_template_policy(block)
        assert ident == "Windows Components/Internet Explorer/Site to Zone Assignment List"
        assert name == "Site to Zone Assignment List"
        assert val == "Enabled"

    def test_admin_template_policy_without_name_falls_through(self):
        block = ET.fromstring(f'<Policy xmlns="{NS}"><State>Enabled</State></Policy>')
        assert ingest._parse_admin_template_policy(block) is None

    # WI-080 — configured value surfaces in display_value, per option shape.

    def _admx(self, inner: str) -> str:
        return (
            f'<Policy xmlns="{NS}"><Name>P</Name><State>Enabled</State>'
            f"<Category>Cat</Category>{inner}</Policy>"
        )

    def test_admx_numeric_value(self):
        block = ET.fromstring(
            self._admx(
                "<Numeric><Name>Maximum Log Size (KB)</Name>"
                "<State>Enabled</State><Value>2097120</Value></Numeric>"
            )
        )
        _i, _n, val = ingest._parse_admin_template_policy(block)
        assert val == "Enabled — Maximum Log Size (KB): 2097120"

    def test_admx_edittext_value(self):
        block = ET.fromstring(
            self._admx(
                "<EditText><Name>Application locale</Name>"
                "<State>Enabled</State><Value>en-US</Value></EditText>"
            )
        )
        _i, _n, val = ingest._parse_admin_template_policy(block)
        assert val == "Enabled — Application locale: en-US"

    def test_admx_edittextbox_configured_value(self):
        block = ET.fromstring(
            self._admx(
                "<EditTextBox><Name>Lab cipher suite order</Name>"
                "<State>Enabled</State><Value>LAB_SUITE_ONE,LAB_SUITE_TWO</Value></EditTextBox>"
            )
        )
        identity, name, value = ingest._parse_admin_template_policy(block)
        assert identity == "Cat/P"
        assert name == "P"
        assert value == "Enabled — Lab cipher suite order: LAB_SUITE_ONE,LAB_SUITE_TWO"

    def test_admx_dropdownlist_value_text(self):
        block = ET.fromstring(
            self._admx(
                "<DropDownList><Name>Active Power Plan:</Name>"
                "<State>Enabled</State><Value>High Performance</Value></DropDownList>"
            )
        )
        _i, _n, val = ingest._parse_admin_template_policy(block)
        # trailing colon on the label is normalized away
        assert val == "Enabled — Active Power Plan: High Performance"

    def test_admx_dropdownlist_nested_name_value(self):
        block = ET.fromstring(
            self._admx(
                "<DropDownList><Name>Default for all apps:</Name><State>Enabled</State>"
                "<Value><Name>Force Allow</Name></Value></DropDownList>"
            )
        )
        _i, _n, val = ingest._parse_admin_template_policy(block)
        assert val == "Enabled — Default for all apps: Force Allow"

    def test_admx_checkboxes_use_per_box_state(self):
        block = ET.fromstring(
            self._admx(
                "<CheckBox><Name>Allow slow link</Name><State>Disabled</State></CheckBox>"
                "<CheckBox><Name>Process always</Name><State>Enabled</State></CheckBox>"
            )
        )
        _i, _n, val = ingest._parse_admin_template_policy(block)
        assert val == "Enabled — Allow slow link: Disabled; Process always: Enabled"

    def test_admx_listbox_counts_entries(self):
        block = ET.fromstring(
            self._admx(
                "<ListBox><Name>URLs to open</Name><State>Enabled</State>"
                "<Value><Element/><Element/></Value></ListBox>"
            )
        )
        _i, _n, val = ingest._parse_admin_template_policy(block)
        assert val == "Enabled — URLs to open: [2 entries]"

    def test_admx_multitext_counts_strings_singular(self):
        block = ET.fromstring(
            self._admx(
                "<MultiText><Name>Apps</Name><State>Enabled</State>"
                "<Value><string/></Value></MultiText>"
            )
        )
        _i, _n, val = ingest._parse_admin_template_policy(block)
        assert val == "Enabled — Apps: [1 entry]"

    def test_admx_text_element_is_ignored(self):
        # <Text> is a display-only label, not a configured value.
        block = ET.fromstring(self._admx("<Text><Name>Some explanatory label</Name></Text>"))
        _i, _n, val = ingest._parse_admin_template_policy(block)
        assert val == "Enabled"

    def test_admx_no_options_keeps_bare_state(self):
        block = ET.fromstring(self._admx(""))
        _i, _n, val = ingest._parse_admin_template_policy(block)
        assert val == "Enabled"

    def test_admx_disabled_policy_keeps_state(self):
        block = ET.fromstring(
            f'<Policy xmlns="{NS}"><Name>P</Name><State>Disabled</State>'
            "<Category>Cat</Category></Policy>"
        )
        _i, _n, val = ingest._parse_admin_template_policy(block)
        assert val == "Disabled"

    def test_admx_summary_is_length_capped(self):
        long_label = "X" * 400
        block = ET.fromstring(
            self._admx(
                f"<EditText><Name>{long_label}</Name>"
                "<State>Enabled</State><Value>v</Value></EditText>"
            )
        )
        _i, _n, val = ingest._parse_admin_template_policy(block)
        assert len(val) <= len("Enabled — ") + ingest._ADMX_SUMMARY_MAX
        assert val.endswith("…")

    def test_classic_registry_setting_uses_keypath_and_value_name(self):
        block = ET.fromstring(
            f'<RegistrySetting xmlns="{NS}">'
            "<KeyPath>Software\\Policies\\Google\\Chrome</KeyPath>"
            "<AdmSetting>false</AdmSetting>"
            "<Value><Name>RemoteAccessHostAllowGnubbyAuth</Name>"
            "<Number>0</Number></Value></RegistrySetting>"
        )
        ident, name, val = ingest._parse_classic_registry_setting(block)
        assert ident == "Software\\Policies\\Google\\Chrome:RemoteAccessHostAllowGnubbyAuth"
        assert name == "RemoteAccessHostAllowGnubbyAuth"
        assert val == "0"


class TestReadableIdentitiesNoHash:
    """Every CSE block resolves to a human-readable identity, never a hash."""

    def test_security_account_uses_name_child(self):
        b = ET.fromstring(
            f'<Account xmlns="{NS}"><Name>ClearTextPassword</Name>'
            "<SettingBoolean>false</SettingBoolean><Type>Password</Type></Account>"
        )
        assert ingest._parse_security_setting(b) == (
            "Account:ClearTextPassword",
            "ClearTextPassword",
            "false",
        )

    def test_security_restricted_groups_uses_nested_group_name(self):
        b = ET.fromstring(
            f'<RestrictedGroups xmlns="{NS}"><GroupName>'
            "<SID>S-1-5-32-555</SID><Name>BUILTIN\\Remote Desktop Users</Name>"
            "</GroupName></RestrictedGroups>"
        )
        ident, name, _ = ingest._parse_security_setting(b)
        assert ident == "RestrictedGroups:BUILTIN\\Remote Desktop Users"
        assert name == "BUILTIN\\Remote Desktop Users"

    def test_gpp_container_expands_items_by_name(self):
        b = ET.fromstring(
            f'<Printers xmlns="{NS}" clsid="{{X}}">'
            '<PortPrinter uid="{{A}}" name="floor1-printer">'
            '<Properties action="U" path="\\\\printsrv\\floor1"/></PortPrinter>'
            '<SharedPrinter uid="{{B}}" name="floor2-printer">'
            '<Properties action="C" path="\\\\printsrv\\floor2"/></SharedPrinter>'
            "</Printers>"
        )
        rows = ingest._parse_gpp_container(b)
        assert [r[0] for r in rows] == [
            "PortPrinter:floor1-printer",
            "SharedPrinter:floor2-printer",
        ]
        assert rows[0][2] == "[U] \\\\printsrv\\floor1"

    def test_advanced_audit_uses_subcategory_name(self):
        b = ET.fromstring(
            f'<AuditSetting xmlns="{NS}"><PolicyTarget>System</PolicyTarget>'
            "<SubcategoryName>Audit Credential Validation</SubcategoryName>"
            "<SettingValue>3</SettingValue></AuditSetting>"
        )
        ident, name, val = ingest._readable_identity("Advanced Audit Configuration", b)
        assert ident == "AuditSetting:Audit Credential Validation"
        assert val == "3"

    def test_singleton_block_falls_back_to_block_type(self):
        b = ET.fromstring(
            f'<PlaceFavoritesAtTop xmlns="{NS}"><Value>true</Value></PlaceFavoritesAtTop>'
        )
        ident, name, val = ingest._readable_identity("Internet Explorer Maintenance", b)
        assert ident == "PlaceFavoritesAtTop"
        assert val == "true"

    def test_folder_redirection_resolves_known_folder_guid(self):
        b = ET.fromstring(
            f'<Folder xmlns="{NS}"><Id>{{FDD39AD0-238F-46AF-ADB4-6C85480369C7}}</Id>'
            "<Location><DestinationPath>\\\\srv\\home\\%USERNAME%\\Docs"
            "</DestinationPath></Location></Folder>"
        )
        ident, name, dest = ingest._parse_folder_redirection(b)
        assert ident == "Folder Redirection:Documents"
        assert dest == "\\\\srv\\home\\%USERNAME%\\Docs"

    def test_real_export_has_zero_hashed_identities(self, tmp_path):
        # Discover any local sample export rather than naming one (the file
        # itself is gitignored; the name must not be committed). Skips in CI,
        # where samples/ is absent. Picks the first zip that ingests with GPOs.
        import re
        import zipfile

        samples = sorted(Path("samples").glob("*.zip")) if Path("samples").is_dir() else []
        if not samples:
            import pytest

            pytest.skip("no sample export present")
        est = None
        for sample in samples:
            dest = tmp_path / sample.stem
            try:
                with zipfile.ZipFile(sample) as z:
                    z.extractall(dest)
                candidate = ingest.load_estate(dest)
            except (zipfile.BadZipFile, OSError, ValueError, KeyError):
                continue  # not a GPO export (e.g. a baseline zip) — try the next
            if candidate.gpos:
                est = candidate
                break
        if est is None:
            import pytest

            pytest.skip("no ingestable GPO export in samples/")
        hexpat = re.compile(r":[0-9a-f]{16}(\s#\d+)?$")
        hashed = [s.identity for g in est.gpos for s in g.settings if hexpat.search(s.identity)]
        assert hashed == [], f"unexpected hashed identities: {hashed[:5]}"


# ---------------------------------------------------------------------------
# Flat <Permission> delegation fallback (ingest.py lines 633-657)
# Real exports use the nested <TrusteePermissions> structure. Some older /
# third-party GPO reports use the flat <Permission> elements directly under
# <Permissions>. The parser must fall back and extract trustee/SID/type.
# ---------------------------------------------------------------------------


def _gpo_xml_with_flat_permission(
    gpo_id: str = "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}",
) -> str:
    """A GPO whose SecurityDescriptor uses flat <Permission> elements (no
    <TrusteePermissions>), exercising the fallback branch."""
    return f"""<?xml version="1.0" encoding="utf-8"?>
<GPO xmlns="http://www.microsoft.com/GroupPolicy/Settings">
  <GPO>
    <Identifier>
      <Identifier>{gpo_id}</Identifier>
      <Domain>flat.local</Domain>
    </Identifier>
    <Name>flat-delegation-gpo</Name>
    <Computer>
      <Enabled>true</Enabled>
      <VersionDirectory>0</VersionDirectory>
      <VersionSysvol>0</VersionSysvol>
    </Computer>
    <User>
      <Enabled>true</Enabled>
      <VersionDirectory>0</VersionDirectory>
      <VersionSysvol>0</VersionSysvol>
    </User>
    <SecurityDescriptor>
      <Permissions>
        <Permission>
          <Trustee>Authenticated Users</Trustee>
          <TrusteeSID>S-1-5-11</TrusteeSID>
          <Standard>Read</Standard>
          <Type>Allow</Type>
        </Permission>
        <Permission>
          <Trustee>Helpdesk</Trustee>
          <SID>S-1-5-21-1-2-3-1000</SID>
          <Standard>Edit</Standard>
          <AccessDenied>false</AccessDenied>
        </Permission>
        <Permission>
          <Trustee>Denied Group</Trustee>
          <SID>S-1-5-21-1-2-3-1001</SID>
          <Type>Deny</Type>
          <AccessDenied>true</AccessDenied>
        </Permission>
      </Permissions>
    </SecurityDescriptor>
  </GPO>
</GPO>"""


def test_flat_permission_delegation_fallback() -> None:
    """When no <TrusteePermissions> are present, the parser falls back to flat
    <Permission> elements and extracts trustee, SID, permission type."""
    xml = _gpo_xml_with_flat_permission()
    elem = ET.fromstring(xml)
    # Namespace-stripping: find the <GPO> child
    gpo_elem = None
    for child in elem:
        if child.tag.split("}")[-1] == "GPO":
            gpo_elem = child
            break
    assert gpo_elem is not None

    entries = ingest._parse_delegation(gpo_elem, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    assert len(entries) == 3

    # Entry 0: TrusteeSID element used
    e0 = entries[0]
    assert e0.trustee == "Authenticated Users"
    assert e0.trustee_sid == "S-1-5-11"
    assert e0.permission == "Read"
    assert e0.allowed is True

    # Entry 1: SID element (fallback) + AccessDenied=false
    e1 = entries[1]
    assert e1.trustee == "Helpdesk"
    assert e1.trustee_sid == "S-1-5-21-1-2-3-1000"
    assert e1.permission == "Edit"
    assert e1.allowed is True

    # Entry 2: AccessDenied=true → allowed=False; Type used as permission fallback
    e2 = entries[2]
    assert e2.trustee == "Denied Group"
    assert e2.trustee_sid == "S-1-5-21-1-2-3-1001"
    assert e2.permission == "Deny"
    assert e2.allowed is False


def test_flat_permission_no_sid_resolves_to_none() -> None:
    """A flat <Permission> with neither TrusteeSID nor SID yields sid=None."""
    xml = """<?xml version="1.0" encoding="utf-8"?>
<GPO xmlns="http://www.microsoft.com/GroupPolicy/Settings">
  <GPO>
    <Identifier><Identifier>{BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB}</Identifier>
    <Domain>flat.local</Domain></Identifier>
    <Name>no-sid-gpo</Name>
    <Computer><Enabled>true</Enabled></Computer>
    <User><Enabled>true</Enabled></User>
    <SecurityDescriptor>
      <Permissions>
        <Permission>
          <Trustee>Unknown Trustee</Trustee>
          <Standard>GPO Custom</Standard>
        </Permission>
      </Permissions>
    </SecurityDescriptor>
  </GPO>
</GPO>"""
    elem = ET.fromstring(xml)
    gpo_elem = next(c for c in elem if c.tag.split("}")[-1] == "GPO")
    entries = ingest._parse_delegation(gpo_elem, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
    assert len(entries) == 1
    assert entries[0].trustee == "Unknown Trustee"
    assert entries[0].trustee_sid is None
    assert entries[0].permission == "GPO Custom"


# ---------------------------------------------------------------------------
# Owner extraction from <SecurityDescriptor><Owner>
# ---------------------------------------------------------------------------


def test_owner_read_from_owner_children_not_element_text() -> None:
    """GPMC's <Owner> holds <SID>/<Name> children; its own .text is the
    whitespace between them. Reading elem.text stored '\\n      ' as the
    owner for every GPO (blank Owner row in the UI, found on the real
    estate export)."""
    xml = """<?xml version="1.0" encoding="utf-8"?>
<GPO xmlns="http://www.microsoft.com/GroupPolicy/Settings">
  <GPO>
    <Identifier><Identifier>{CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCCCCCC}</Identifier>
    <Domain>fakefixture.local</Domain></Identifier>
    <Name>owner-gpo</Name>
    <Computer><Enabled>true</Enabled></Computer>
    <User><Enabled>true</Enabled></User>
    <SecurityDescriptor>
      <SDDL>O:DAG:DAD:PAI(A;;GR;;;WD)</SDDL>
      <Owner>
        <SID>S-1-5-21-1-2-3-512</SID>
        <Name>FAKEFIXTURE\\Domain Admins</Name>
      </Owner>
    </SecurityDescriptor>
  </GPO>
</GPO>"""
    elem = ET.fromstring(xml)
    gpo_elem = next(c for c in elem if c.tag.split("}")[-1] == "GPO")
    gpo = ingest._parse_single_gpo(gpo_elem)
    assert gpo is not None
    assert gpo.owner == "FAKEFIXTURE\\Domain Admins"


def test_owner_falls_back_to_sid_child() -> None:
    xml = """<?xml version="1.0" encoding="utf-8"?>
<GPO xmlns="http://www.microsoft.com/GroupPolicy/Settings">
  <GPO>
    <Identifier><Identifier>{DDDDDDDD-DDDD-DDDD-DDDD-DDDDDDDDDDDD}</Identifier>
    <Domain>fakefixture.local</Domain></Identifier>
    <Name>owner-sid-only-gpo</Name>
    <Computer><Enabled>true</Enabled></Computer>
    <User><Enabled>true</Enabled></User>
    <SecurityDescriptor>
      <Owner>
        <SID>S-1-5-21-1-2-3-512</SID>
      </Owner>
    </SecurityDescriptor>
  </GPO>
</GPO>"""
    elem = ET.fromstring(xml)
    gpo_elem = next(c for c in elem if c.tag.split("}")[-1] == "GPO")
    gpo = ingest._parse_single_gpo(gpo_elem)
    assert gpo is not None
    assert gpo.owner == "S-1-5-21-1-2-3-512"


def test_owner_absent_is_none() -> None:
    xml = """<?xml version="1.0" encoding="utf-8"?>
<GPO xmlns="http://www.microsoft.com/GroupPolicy/Settings">
  <GPO>
    <Identifier><Identifier>{EEEEEEEE-EEEE-EEEE-EEEE-EEEEEEEEEEEE}</Identifier>
    <Domain>fakefixture.local</Domain></Identifier>
    <Name>no-owner-gpo</Name>
    <Computer><Enabled>true</Enabled></Computer>
    <User><Enabled>true</Enabled></User>
  </GPO>
</GPO>"""
    elem = ET.fromstring(xml)
    gpo_elem = next(c for c in elem if c.tag.split("}")[-1] == "GPO")
    gpo = ingest._parse_single_gpo(gpo_elem)
    assert gpo is not None
    assert gpo.owner is None


# ---------------------------------------------------------------------------
# L-7: _GPLINK_RE case-insensitivity
# ---------------------------------------------------------------------------


def test_gplink_re_matches_lowercase_ldap() -> None:
    """``ldap://`` (lowercase) must match — the regex uses re.IGNORECASE."""
    from gpo_lens.ingest import _GPLINK_RE, _parse_gplink

    raw = "[ldap://CN={11111111-1111-1111-1111-111111111111},...;0]"
    assert _GPLINK_RE.search(raw) is not None
    links = _parse_gplink(raw, "CN=Site,...")
    assert len(links) == 1
    assert links[0].gpo_id == "11111111111111111111111111111111"
    assert links[0].enabled is True


def test_gplink_re_matches_lowercase_cn() -> None:
    """``cn=`` (lowercase CN) must also match."""
    from gpo_lens.ingest import _parse_gplink

    raw = "[LDAP://cn={22222222-2222-2222-2222-222222222222},...;0]"
    links = _parse_gplink(raw, "CN=Site,...")
    assert len(links) == 1
    assert links[0].gpo_id == "22222222222222222222222222222222"


# ---------------------------------------------------------------------------
# M-8: _parse_single_gpo returns None for empty identifier
# ---------------------------------------------------------------------------


def test_parse_single_gpo_no_identifier_returns_none() -> None:
    """A GPO element with no <Identifier> child returns None with a warning."""
    xml = """<?xml version="1.0" encoding="utf-8"?>
<GPO xmlns="http://www.microsoft.com/GroupPolicy/Settings">
  <GPO>
    <Name>Orphan</Name>
    <Computer><Enabled>false</Enabled></Computer>
    <User><Enabled>false</Enabled></User>
  </GPO>
</GPO>"""
    root = ET.fromstring(xml)
    gpo_elem = next(c for c in root if c.tag.split("}")[-1] == "GPO")
    with pytest.warns(UserWarning, match="no valid identifier"):
        result = ingest._parse_single_gpo(gpo_elem)
    assert result is None


def test_parse_single_gpo_empty_identifier_returns_none() -> None:
    """A GPO element with an empty <Identifier> text returns None."""
    xml = """<?xml version="1.0" encoding="utf-8"?>
<GPO xmlns="http://www.microsoft.com/GroupPolicy/Settings">
  <GPO>
    <Identifier><Identifier></Identifier></Identifier>
    <Name>EmptyId</Name>
    <Computer><Enabled>false</Enabled></Computer>
    <User><Enabled>false</Enabled></User>
  </GPO>
</GPO>"""
    root = ET.fromstring(xml)
    gpo_elem = next(c for c in root if c.tag.split("}")[-1] == "GPO")
    with pytest.warns(UserWarning, match="no valid identifier"):
        result = ingest._parse_single_gpo(gpo_elem)
    assert result is None


# ---------------------------------------------------------------------------
# M-5: load_baseline_from_zip respects the 256MB baseline cap
# ---------------------------------------------------------------------------


def test_baseline_zip_exceeds_256mb_raises(tmp_path: Path) -> None:
    """A baseline zip whose total decompressed size exceeds 256MB must raise."""
    import unittest.mock

    # Create a zip with content that exceeds a patched-low limit (simulating
    # the 256MB cap at a small scale).
    gpo_xml = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        "<GPO>\n"
        "  <Identifier><Identifier>{99999999-9999-9999-9999-999999999999}</Identifier>"
        "<Domain>test.local</Domain></Identifier>\n"
        "  <Name>Big</Name>\n"
        "  <Computer><Enabled>true</Enabled></Computer>\n"
        "  <User><Enabled>true</Enabled></User>\n"
        "  <FilterDataAvailable>false</FilterDataAvailable>\n"
        "</GPO>\n"
    )
    padded = gpo_xml + " " * 5000

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("GPOs/big/gpreport.xml", padded)

    zip_path = tmp_path / "baseline.zip"
    zip_path.write_bytes(buf.getvalue())

    with unittest.mock.patch("gpo_lens.ingest._MAX_BASELINE_UNCOMPRESSED_BYTES", 200):
        with pytest.warns(UserWarning, match="exceeds limit"):
            gpos = ingest.load_baseline_from_zip(zip_path)
    assert gpos == []


def test_parse_report_skips_malformed_guid(tmp_path: Path) -> None:
    """A malformed GPO GUID must not crash the entire report parse."""
    xml = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<GPO xmlns="http://www.microsoft.com/GroupPolicy/Settings">\n'
        "  <GPO>\n"
        "    <Identifier>\n"
        "      <Identifier>not-a-valid-guid</Identifier>\n"
        "      <Domain>test.local</Domain>\n"
        "    </Identifier>\n"
        "    <Name>Bad GUID GPO</Name>\n"
        "    <Computer><VersionDirectory>1</VersionDirectory>"
        "    <VersionSysvol>1</VersionSysvol><Enabled>true</Enabled></Computer>\n"
        "    <User><VersionDirectory>1</VersionDirectory>"
        "    <VersionSysvol>1</VersionSysvol><Enabled>true</Enabled></User>\n"
        "    <FilterDataAvailable>false</FilterDataAvailable>\n"
        "  </GPO>\n"
        "  <GPO>\n"
        "    <Identifier>\n"
        "      <Identifier>{31B2F340-016D-11D2-945F-00C04FB984F9}</Identifier>\n"
        "      <Domain>test.local</Domain>\n"
        "    </Identifier>\n"
        "    <Name>Good GPO</Name>\n"
        "    <Computer><VersionDirectory>1</VersionDirectory>"
        "    <VersionSysvol>1</VersionSysvol><Enabled>true</Enabled></Computer>\n"
        "    <User><VersionDirectory>1</VersionDirectory>"
        "    <VersionSysvol>1</VersionSysvol><Enabled>true</Enabled></User>\n"
        "    <FilterDataAvailable>false</FilterDataAvailable>\n"
        "  </GPO>\n"
        "</GPO>\n"
    )
    xml_path = tmp_path / "report.xml"
    xml_path.write_text(xml, encoding="utf-8")
    gpos = ingest.parse_report(xml_path)
    assert len(gpos) == 1
    assert gpos[0].name == "Good GPO"
