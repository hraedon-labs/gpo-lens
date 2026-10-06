"""CLI subcommands for LLM-powered natural language queries and explanations."""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import sys

from gpo_lens import queries
from gpo_lens.cli._helpers import _get_admx, _get_estate, _render_json
from gpo_lens.cli._helpers import _safe_print as print
from gpo_lens.detection import mask_cpassword
from gpo_lens.query_dispatch import (
    VALID_QUERIES,
    dispatch_query,
    validate_params,
)
from gpo_lens.safe_output import safe_data, secret_values


def cmd_ask(args: argparse.Namespace) -> int:
    from gpo_lens.narration import (
        NarrationUnavailable,
        call_llm,
        route_question,
    )

    question: str = f"--- USER QUESTION START ---\n{args.question}\n--- USER QUESTION END ---"
    raw_json: bool = args.no_narrate or getattr(args, "json", False)

    estate = _get_estate(args)

    try:
        routing = route_question(question)
    except NarrationUnavailable as exc:
        print(f"Error: {exc}", file=sys.stderr)
        print("Set GPO_LENS_API_KEY to use the ask command.", file=sys.stderr)
        return 1

    if "error" in routing:
        reason = routing.get("reason", "unknown")
        print(f"Cannot answer: {reason}", file=sys.stderr)
        return 1

    query_name = str(routing["query"])
    params = dict(routing.get("params", {}))  # type: ignore[call-overload]

    if query_name not in VALID_QUERIES:
        print(
            f"Error: query '{query_name}' not implemented yet",
            file=sys.stderr,
        )
        return 1

    params = {k: v for k, v in params.items() if k != "estate"}
    try:
        call_kw = validate_params(query_name, {"estate": estate, **params})
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    query_result: object = dispatch_query(query_name, **call_kw)

    if query_name == "cpassword_scan":
        hits: list[queries.CpasswordHit] = query_result  # type: ignore[assignment]
        query_result = [
            dataclasses.replace(hit, cpassword=mask_cpassword(hit.cpassword)) for hit in hits
        ]

    serialized_result = safe_data(query_result, secrets=secret_values(estate))

    if raw_json:
        _render_json(serialized_result)
        return 0

    narration_text: str | None = None
    try:
        narration_text = call_llm(
            "You are a Group Policy analyst. The user asked a question about their "
            "GPO estate. Below are the raw query results as JSON. Answer the user's "
            "question clearly, referencing specific GPO names and values from the data.",
            f"Question: {question}\n\nQuery results:\n" + json.dumps(serialized_result, indent=2),
        )
    except NarrationUnavailable:
        narration_text = None
    except Exception as exc:
        print(f"Warning: narration failed: {exc}", file=sys.stderr)
        narration_text = None

    if narration_text is not None:
        print(narration_text)
        print("\n--- Raw results ---\n")
        _render_json(serialized_result)
    else:
        print("Narration unavailable. Raw results:")
        _render_json(serialized_result)
    return 0


def cmd_explain_setting(args: argparse.Namespace) -> int:
    """Explain what a registry setting / GPO identity does.

    ADMX-first: if --admx-dir resolves the identity, print the policy name
    and explain_text with zero model calls.  If ADMX cannot resolve it and an
    API key is configured, fall back to an LLM narration clearly marked as
    unverified.  Without an API key, degrade to a factual "not available" note.
    """
    identity: str = args.identity
    admx = _get_admx(args)

    if admx is not None:
        parts = identity.split(":", 1)
        key = parts[0] if parts else identity
        value = parts[1] if len(parts) > 1 else ""
        matches = admx.lookup(key, value)
        if matches:
            policy = matches[0]
            print(policy.display_name)
            if policy.explain_text:
                print(f"\n{policy.explain_text}")
            else:
                print("\nNo ADMX explain text is available for this setting.")
            return 0

    if not os.environ.get("GPO_LENS_API_KEY"):
        print("No ADMX explanation available; set GPO_LENS_API_KEY for AI narration")
        return 0

    # Narration fallback (explicitly marked as unverified).
    from gpo_lens.narration import NarrationUnavailable, call_llm

    system = (
        "You are a Group Policy analyst. Explain what the following setting "
        "likely does, based on its identity/path text. You do not have "
        "authoritative ADMX context. Begin your answer with "
        "'NARRATED/UNVERIFIED:' and keep the explanation brief and factual."
    )
    try:
        answer = call_llm(system, identity[:500])
    except NarrationUnavailable as exc:
        print(f"Error: narration unavailable ({exc})", file=sys.stderr)
        return 1
    if not answer.startswith("NARRATED/UNVERIFIED:"):
        answer = "NARRATED/UNVERIFIED: " + answer
    print(f"NARRATED/UNVERIFIED explanation for {identity}:\n")
    print(answer)
    return 0
