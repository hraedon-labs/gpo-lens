"""Failed best-effort cleanup must preserve the actual extraction failure."""

from __future__ import annotations

import shutil
import zipfile
from pathlib import Path

import pytest

from gpo_lens.collection_zip import safe_extract


@pytest.mark.parametrize("interrupted", [False, True])
@pytest.mark.parametrize("cleanup_fault", ["permission", "removed", "none"])
def test_cleanup_preserves_extraction_failure(
    tmp_path, monkeypatch, caplog, interrupted, cleanup_fault
):
    archive = tmp_path / "synthetic.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("first.txt", "synthetic")
        zf.writestr("second.txt" if interrupted else "../blocked.txt", "synthetic")
    dest = tmp_path / "extracted"
    dest.mkdir()
    cancellation = KeyboardInterrupt("Synthetic extraction cancellation")
    original_open = zipfile.ZipFile.open

    def interrupt_second(self, name, *args, **kwargs):
        if interrupted and isinstance(name, zipfile.ZipInfo) and name.filename == "second.txt":
            assert (dest / "first.txt").read_text() == "synthetic"
            raise cancellation
        return original_open(self, name, *args, **kwargs)

    original_iterdir = Path.iterdir
    listing_attempts = []

    def fail_listing(self):
        if self == dest:
            listing_attempts.append(self)
            assert (dest / "first.txt").read_text() == "synthetic"
            if cleanup_fault == "permission":
                raise PermissionError("SYNTHETIC-CLEANUP-PATH must not appear in logs")
            if cleanup_fault == "removed":
                # A real disappearance after is_dir(), before directory listing.
                shutil.rmtree(dest)
        return original_iterdir(self)

    monkeypatch.setattr(zipfile.ZipFile, "open", interrupt_second)
    monkeypatch.setattr(Path, "iterdir", fail_listing)
    expected = KeyboardInterrupt if interrupted else ValueError
    with pytest.raises(expected) as failure:
        safe_extract(archive, dest)
    if interrupted:
        assert failure.value is cancellation
    else:
        assert str(failure.value) == "zip-slip blocked (member 2)"
    assert len(listing_attempts) == 1
    if cleanup_fault == "none":
        assert dest.is_dir() and not (dest / "first.txt").exists()
        assert not caplog.records
    elif cleanup_fault == "removed":
        assert not dest.exists()
        assert "FileNotFoundError" in caplog.text
    else:
        assert (dest / "first.txt").read_text() == "synthetic"
        assert "PermissionError" in caplog.text
    assert "SYNTHETIC-CLEANUP-PATH" not in caplog.text
    assert "blocked.txt" not in caplog.text
    assert "first.txt" not in caplog.text
