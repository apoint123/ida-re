"""End-to-end smoke test: compile the C fixture with clang, then analyze it.

Requires a local clang and IDA 9.x with idalib. Run from the repository root:

    python tests/smoke_test.py
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from ida_session import IDASession

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))


FIXTURE = Path(__file__).parent / "fixtures" / "sample.c"
STRING_TEXT = "probe result"


def _compile(outdir: Path) -> Path:
    exe = outdir / ("sample.exe" if os.name == "nt" else "sample")
    cmd = ["clang", "-O0", "-g", "-o", str(exe), str(FIXTURE)]
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
    except FileNotFoundError:
        raise SystemExit("clang not found; install LLVM or put clang on PATH") from None
    except subprocess.CalledProcessError as exc:
        raise SystemExit(f"clang failed:\n{exc.stderr}") from exc
    return exe


def _assert_closed(session: IDASession, ea: int) -> None:
    checks = (
        lambda: list(session.functions()),
        lambda: session.name(ea),
        lambda: session.min_ea,
        lambda: session.hexrays_available,
        lambda: list(session.xrefs_to(ea)),
        lambda: session.func_at(ea),
        lambda: list(session.names_like(".*")),
        lambda: list(session.xrefs_with_owner(ea)),
    )
    for check in checks:
        try:
            check()
        except RuntimeError:
            continue
        raise AssertionError("closed session did not raise RuntimeError")


def _test_primitives(exe: Path) -> int:
    with IDASession(exe, save=False) as session:
        functions = list(session.functions())
        assert functions, "no functions found"

        add_ea = session.to_ea("add")
        compute_ea = session.to_ea("compute")
        main_ea = session.to_ea("main")
        assert add_ea in functions and main_ea in functions
        assert session.min_ea <= add_ea < session.max_ea

        assert session.name(add_ea) == "add"
        assert session.name(hex(add_ea)) == "add"
        assert session.to_ea(hex(main_ea)) == main_ea

        cfunc = session.decompile(main_ea)
        pseudocode = str(cfunc)
        assert STRING_TEXT in pseudocode, pseudocode
        assert "compute" in pseudocode, pseudocode
        assert cfunc.get_lvars() is not None

        string_ea = next(
            (st.ea for st in session.strings() if st is not None and STRING_TEXT in str(st)),
            None,
        )
        assert string_ea is not None, "fixture string not found"
        xrefs = list(session.xrefs_to(string_ea))
        assert xrefs, "no xref to the fixture string"
        assert any(session.name(xref.frm) == "main" for xref in xrefs)
        assert list(session.xrefs_from(main_ea))

        assert session.proc_name
        assert session.hexrays_available

        owner = session.func_at(add_ea)
        assert owner is not None
        assert owner.name == "add"
        assert owner.start_ea == add_ea
        assert owner.size > 0
        assert session.func_at(string_ea) is None

        assert list(session.names_like(r"^add$")) == [(add_ea, "add")]
        assert dict(session.names_like("comput"))[compute_ea] == "compute"
        assert not list(session.names_like("__no_such_name_fragment__"))

        owned_xrefs = list(session.xrefs_with_owner(string_ea))
        assert owned_xrefs, "no owned xref to the fixture string"
        assert any(o.owner is not None and o.owner.name == "main" for o in owned_xrefs)

        assert session.rename(add_ea, "smoke_add")
        assert session.name(add_ea) == "smoke_add"
        assert session.set_comment(add_ea, "smoke comment")
        assert not session.rename(compute_ea, "smoke_add")
        assert session.name(compute_ea) == "compute"
        assert not session.rename(compute_ea, "1 invalid name")

        try:
            session.to_ea("__no_such_symbol__")
        except ValueError:
            pass
        else:
            raise AssertionError("unknown symbol did not raise ValueError")

        try:
            session.decompile(string_ea)
        except RuntimeError as exc:
            assert "Failed to decompile function" in str(exc)
            assert "code" in str(exc)
        else:
            raise AssertionError("decompiling a data address did not raise")

    _assert_closed(session, add_ea)
    assert not Path(str(exe) + ".i64").exists(), "save=False wrote a database"
    return add_ea


def _test_save_semantics(exe: Path, workdir: Path, add_ea: int) -> None:
    persisted = workdir / ("persist.exe" if os.name == "nt" else "persist")
    shutil.copyfile(exe, persisted)

    with IDASession(persisted) as session:
        assert session.rename(add_ea, "persisted_add")
    assert (workdir / (persisted.name + ".i64")).exists(), "default save did not write .i64"

    with IDASession(persisted, save=False) as session:
        assert session.name(add_ea) == "persisted_add"
        assert session.rename(add_ea, "discarded_add")

    with IDASession(persisted, save=False) as session:
        assert session.name(add_ea) == "persisted_add", "save=False persisted a rename"


def main() -> int:
    if not FIXTURE.exists():
        raise SystemExit(f"missing fixture: {FIXTURE}")

    with tempfile.TemporaryDirectory(prefix="ida_session_smoke_") as tmp:
        workdir = Path(tmp)
        exe = _compile(workdir)
        add_ea = _test_primitives(exe)
        _test_save_semantics(exe, workdir, add_ea)

    print(f"ok: compiled {FIXTURE.name} with clang and verified ida_session")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
