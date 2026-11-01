"""session.py: Core idalib context manager and base analyzer primitives."""

from __future__ import annotations

import contextlib
import os
import re
from collections.abc import Iterator
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from typing_extensions import Self

# idapro must always be imported before any other IDA modules
import idapro

# isort: split

import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_ida
import ida_idaapi
import ida_name
import ida_typeinf
import idautils
import idc

__all__ = [
    "IDASession",
    "ida_auto",
    "ida_bytes",
    "ida_funcs",
    "ida_hexrays",
    "ida_ida",
    "ida_idaapi",
    "ida_name",
    "ida_typeinf",
    "idautils",
    "idc",
]

_HEX_RE = re.compile(r"(?:0[xX])?[0-9a-fA-F]+")


class IDASession:
    """Atomic context manager for managing IDA Pro idalib database lifecycle."""

    def __init__(
        self,
        target_path: str | os.PathLike[str],
        save: bool = True,
        auto_analysis: bool | None = None,
    ):
        """Initialize session parameters.

        Args:
            target_path: Path to binary or existing .i64/.idb database.
            save: Whether to commit changes on close (default True).
            auto_analysis: Whether to run auto-analysis. Defaults to False for
                           existing IDBs and True for raw binaries.
        """
        self.target_path = os.path.abspath(target_path)
        self.save = save

        if auto_analysis is not None:
            self.auto_analysis = auto_analysis
        else:
            ext = os.path.splitext(self.target_path)[1].lower()
            self.auto_analysis = ext not in (".i64", ".idb")

        self._opened = False
        self._hexrays_ready = False

    def __enter__(self) -> Self:
        self._hexrays_ready = False
        ret = idapro.open_database(self.target_path, run_auto_analysis=self.auto_analysis)
        if ret != 0:
            hint = ""
            if ret == -1:
                hint = " (another database may already be open; idalib supports one per process)"
            raise RuntimeError(
                f"idalib failed to open database '{self.target_path}' (code: {ret}){hint}"
            )
        self._opened = True

        try:
            # open_database(run_auto_analysis=True) already waits for analysis to finish.
            self._hexrays_ready = bool(ida_hexrays.init_hexrays_plugin())
        except BaseException:
            with contextlib.suppress(Exception):
                idapro.close_database(save=False)
            self._opened = False
            self._hexrays_ready = False
            raise
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if not self._opened:
            return
        try:
            idapro.close_database(save=self.save and exc_type is None)
        finally:
            self._opened = False
            self._hexrays_ready = False

    def _ensure_open(self) -> None:
        """Reject use outside an active ``with`` block."""
        if not self._opened:
            raise RuntimeError(f"Session for '{self.target_path}' is not open")

    # --- Database Properties ---

    @property
    def min_ea(self) -> int:
        self._ensure_open()
        return ida_ida.inf_get_min_ea()

    @property
    def max_ea(self) -> int:
        self._ensure_open()
        return ida_ida.inf_get_max_ea()

    @property
    def proc_name(self) -> str:
        self._ensure_open()
        return str(ida_ida.inf_get_procname() or "")

    @property
    def hexrays_available(self) -> bool:
        self._ensure_open()
        return self._hexrays_ready

    # --- Atomic Primitives (Zero-Pruning) ---

    def to_ea(self, target: int | str) -> int:
        """Resolve an int, hex string, or symbol name to a mapped effective address (EA).

        Strings are resolved with symbol lookup first; names that do not exist are then
        parsed as hexadecimal (the ``0x`` prefix is optional). Decimal strings must be
        passed as ``int`` instead. Raises ValueError if the result is not mapped in the
        current database, or RuntimeError if the session is not open.
        """
        self._ensure_open()
        if isinstance(target, int):
            ea = target
        elif isinstance(target, str):
            text = target.strip()
            ea = ida_name.get_name_ea(ida_idaapi.BADADDR, text) if text else ida_idaapi.BADADDR
            if ea == ida_idaapi.BADADDR:
                if not _HEX_RE.fullmatch(text):
                    raise ValueError(f"Cannot resolve '{target}' to a valid EA")
                ea = int(text, 16)
        else:
            raise TypeError(f"Unsupported target type: {type(target).__name__}")

        if not ida_bytes.is_mapped(ea):
            raise ValueError(f"EA 0x{ea:x} is not mapped in the current database")
        return ea

    def decompile(self, target: int | str) -> ida_hexrays.cfuncptr_t:
        """Return raw Hex-Rays cfuncptr_t AST object.

        Raises RuntimeError with the Hex-Rays failure description when decompilation
        fails, and ValueError when the target cannot be resolved to a mapped EA.
        """
        self._ensure_open()
        if not self._hexrays_ready:
            raise RuntimeError("Hex-Rays decompiler is not available")
        ea = self.to_ea(target)
        failure = ida_hexrays.hexrays_failure_t()
        cfunc = ida_hexrays.decompile(ea, failure)
        if not cfunc:
            raise RuntimeError(
                f"Failed to decompile function at 0x{ea:x}: {failure.desc()} (code {failure.code})"
            )
        return cfunc

    def name(self, target: int | str) -> str:
        """Get the symbol or function name at an address.

        Addresses inside a function fall back to the containing function's name.
        Raises ValueError if the target is not a mapped EA.
        """
        self._ensure_open()
        ea = self.to_ea(target)
        return str(ida_name.get_name(ea) or ida_funcs.get_func_name(ea) or "")

    def rename(self, target: int | str, new_name: str) -> bool:
        """Set an exact symbol name; no suffixing or sanitizing is performed.

        Returns ``False`` on conflicts or invalid names. IDA's warning text is
        suppressed; call ``ida_name.set_name`` directly when the reason matters.
        """
        self._ensure_open()
        ea = self.to_ea(target)
        if not ida_name.set_name(ea, new_name, ida_name.SN_CHECK | ida_name.SN_NOWARN):
            return False
        return ida_name.get_name(ea) == new_name

    def set_comment(self, target: int | str, comment: str, repeatable: bool = False) -> bool:
        """Set regular or repeatable comment.

        Returns ``False`` when IDA rejects the comment; no failure reason is exposed.
        """
        self._ensure_open()
        ea = self.to_ea(target)
        return bool(ida_bytes.set_cmt(ea, comment, repeatable))

    def xrefs_to(self, target: int | str, flags: int = 0) -> Iterator[Any]:
        """Return raw xref objects referencing target address.

        Items expose the native ``frm``, ``to``, ``iscode``, ``type`` and ``user``
        attributes. ``flags`` is forwarded to :func:`idautils.XrefsTo`.
        """
        self._ensure_open()
        return idautils.XrefsTo(self.to_ea(target), flags)

    def xrefs_from(self, target: int | str, flags: int = 0) -> Iterator[Any]:
        """Return raw xref objects originating from target address.

        Items expose the native ``frm``, ``to``, ``iscode``, ``type`` and ``user``
        attributes. ``flags`` is forwarded to :func:`idautils.XrefsFrom`.
        """
        self._ensure_open()
        return idautils.XrefsFrom(self.to_ea(target), flags)

    def functions(self) -> Iterator[int]:
        """Return an iterator over function start addresses across the database."""
        self._ensure_open()
        return idautils.Functions()

    def strings(self) -> idautils.Strings:
        """Return the raw :class:`idautils.Strings` iterable over string items."""
        self._ensure_open()
        return idautils.Strings()
