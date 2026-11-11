"""Formats generated Noir source with the Aztec 6.0.0 `nargo fmt` and the
Aztec workspace's aztec/noirfmt.toml.

A generated src/fixture.nr is then already what `nargo fmt` writes, so running
`nargo fmt` on the workspace changes nothing and the fixture manifest hash
(taken over the formatted text) stays valid. The layout is the formatter's,
not a copy of its rules. Mirrors nr_format.mjs.
"""

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

# The nargo of Aztec 6.0.0.
NARGO_IDENTITY = "1.0.0-rc.3+5a7ee9bf5ed8973076df7bb0d2b723024db09ae7"
REPOSITORY = Path(__file__).resolve().parents[5]
CONFIG = REPOSITORY / "aztec/noirfmt.toml"
LOCK_NOTICE = "Waiting for lock on git dependencies cache"
_checked = None


def candidate():
    """$NARGO, else `aztec-nargo` or `nargo` on PATH, or None."""
    if os.environ.get("NARGO"):
        return os.environ["NARGO"]
    return shutil.which("aztec-nargo") or shutil.which("nargo")


def available():
    """Whether a nargo with NARGO_IDENTITY is installed."""
    try:
        nargo()
        return True
    except RuntimeError:
        return False


def nargo():
    """The Aztec 6.0.0 nargo: $NARGO, else `aztec-nargo` or `nargo` on PATH."""
    global _checked
    if _checked:
        return _checked
    path = candidate()
    if not path or not Path(path).is_file():
        raise RuntimeError("nargo not found; set NARGO to the nargo of Aztec 6.0.0")
    out = subprocess.run(
        [path, "--version"], check=True, capture_output=True, text=True
    ).stdout
    if f"noirc version = {NARGO_IDENTITY}" not in out:
        raise RuntimeError(f"{path} is not nargo {NARGO_IDENTITY}")
    _checked = str(path)
    return _checked


def format_sources(sources):
    """Each of `sources` as `nargo fmt` lays it out, in one run."""
    with tempfile.TemporaryDirectory(prefix="uc-nr-format-") as name:
        directory = Path(name)
        (directory / "src").mkdir()
        (directory / "Nargo.toml").write_text(
            '[package]\nname = "uc_nr_format"\ntype = "lib"\nauthors = [""]\n\n[dependencies]\n'
        )
        shutil.copyfile(CONFIG, directory / "noirfmt.toml")
        (directory / "src/lib.nr").write_text("")
        for i, source in enumerate(sources):
            (directory / f"src/file_{i}.nr").write_text(source)
        done = subprocess.run(
            [nargo(), "fmt"], cwd=directory, capture_output=True, text=True
        )
        # This nargo exits 0 and leaves the file unchanged on a parse error,
        # so any output on stderr is a failure, except the notice that another
        # nargo holds the git dependency cache lock.
        stderr = "\n".join(
            line for line in done.stderr.splitlines() if not line.startswith(LOCK_NOTICE)
        )
        if done.returncode != 0 or stderr.strip():
            raise RuntimeError(
                f"nargo fmt failed: {(done.stderr or done.stdout)[:500]}"
            )
        return [(directory / f"src/file_{i}.nr").read_text() for i in range(len(sources))]


def format_noir(source):
    """`source` as `nargo fmt` lays it out."""
    return format_sources([source])[0]
