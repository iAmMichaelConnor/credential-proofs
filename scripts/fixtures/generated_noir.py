"""Output step shared by the Noir test generators.

Each generator builds its files in memory and calls `emit`, which writes them.
scripts/fixtures/generate.py formats the Noir output and checks for drift.
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def emit(build):
    """Write the {path: text} that build() returns."""
    for path, text in build().items():
        path.write_text(text)
