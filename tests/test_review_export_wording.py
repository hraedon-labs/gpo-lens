"""Cross-release byte compatibility explicitly exempts version metadata."""

from pathlib import Path

import pytest


@pytest.mark.parametrize("filename", ["CHANGELOG.md", "docs/performance-v14.md"])
def test_cross_release_byte_identity_is_qualified(filename):
    text = (Path(__file__).parent.parent / filename).read_text()
    assert "identical apart from the `application_version` metadata field" in text
