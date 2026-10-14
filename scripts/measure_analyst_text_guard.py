"""Measure the analyst-text guard's miss rate on random GPP-shaped ciphertext.

Reproducible (fixed seeds): ``python scripts/measure_analyst_text_guard.py
[samples]``. SECURITY.md quotes its output; ``tests/test_analyst_text_guard.py``
runs the same function with fewer samples and pins upper bounds.

A sample is base64 of *blocks* random 16-byte AES blocks with the ``=`` padding
stripped — the shape Windows writes a GPP ``cpassword`` in.
"""

from __future__ import annotations

import base64
import random
import sys


def miss_count(blocks: int, samples: int, seed: int | None = None) -> int:
    """Samples of *blocks* AES blocks the guard does not refuse."""
    from gpo_lens.analyst_text import cpassword_material

    rng = random.Random(blocks if seed is None else seed)  # noqa: S311 - reproducible data
    misses = 0
    for _ in range(samples):
        value = base64.b64encode(rng.randbytes(16 * blocks)).decode().rstrip("=")
        if cpassword_material(value) is None:
            misses += 1
    return misses


def main(argv: list[str]) -> int:
    samples = int(argv[1]) if len(argv) > 1 else 200_000
    for blocks in (1, 2, 3, 4):
        misses = miss_count(blocks, samples)
        refused = 100 * (samples - misses) / samples
        print(f"{blocks} block(s): {misses}/{samples} missed, {refused:.4f}% refused")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
