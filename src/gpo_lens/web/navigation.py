"""Navigation classification; retained workbenches keep their own URL semantics."""

from __future__ import annotations


def section_for_path(path: str) -> tuple[str, str]:
    if path.startswith("/briefing"):
        return "briefing", "Briefing"
    if path.startswith(("/findings", "/accepted-risks")):
        return "findings_inbox", "Findings"
    if path.startswith(("/changelog", "/trends")):
        return "changelog", "History"
    if path.startswith(
        (
            "/explore",
            "/inventory",
            "/gpo/",
            "/ou",
            "/search",
            "/setting",
            "/conflicts",
            "/delegation",
            "/danger",
            "/resultant",
        )
    ):
        return "explore", "Explore"
    return "tools", "Tools"
