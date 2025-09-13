import json

import ida_hexrays
import ida_kernwin
import ida_lines
import idaapi

from gepetto.ida.tools.function_utils import parse_ea
from gepetto.ida.tools.tools import add_result_to_messages


def handle_decompile_function_tc(tc, messages):
    try:
        args = json.loads(getattr(tc.function, "arguments", "") or "{}")
    except Exception:
        args = {}

    address = args.get("address")
    try:
        result = decompile_function(address)
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}
    add_result_to_messages(messages, tc, result)


def _decompile_checked(func_ea: int):
    if not ida_hexrays.init_hexrays_plugin():
        raise RuntimeError("Hex-Rays decompiler is not available")
    err = ida_hexrays.hexrays_failure_t()
    cfunc = ida_hexrays.decompile_func(func_ea, err, ida_hexrays.DECOMP_WARNINGS)
    if not cfunc:
        if err.code == ida_hexrays.MERR_LICENSE:
            raise RuntimeError("Decompiler licence is not available. Use disassemble_function instead.")
        msg = f"Decompilation failed at {func_ea:#x}"
        if err.str:
            msg += f": {err.str}"
        if getattr(err, "errea", idaapi.BADADDR) != idaapi.BADADDR:
            msg += f" (address: {err.errea:#x})"
        raise RuntimeError(msg)
    return cfunc


def decompile_function(address: str) -> dict:
    if not address:
        raise ValueError("address is required")

    out = {"ok": False}

    def _do():
        try:
            ea = parse_ea(address)
            cfunc = _decompile_checked(ea)
            try:
                ida_hexrays.open_pseudocode(ea, ida_hexrays.OPF_REUSE)
            except Exception:
                pass

            sv = cfunc.get_pseudocode()
            pseudocode = ""
            for i, sl in enumerate(sv):
                # Try to extract an address for this pseudocode line
                item = ida_hexrays.ctree_item_t()
                line_addr = None if i > 0 else cfunc.entry_ea
                if cfunc.get_line_item(sl.line, 0, False, None, item, None):
                    parts = item.dstr().split(": ")
                    if len(parts) == 2:
                        try:
                            line_addr = int(parts[0], 16)
                        except Exception:
                            line_addr = line_addr
                # Strip color tags
                line = ida_lines.tag_remove(sl.line)
                if pseudocode:
                    pseudocode += "\n"
                if line_addr is None:
                    pseudocode += f"/* line: {i} */ {line}"
                else:
                    pseudocode += f"/* line: {i}, address: {line_addr:#x} */ {line}"

            out.update(ok=True, pseudocode=pseudocode)
            return 1
        except Exception as e:
            out.update(error=str(e))
            return 0

    ida_kernwin.execute_sync(_do, ida_kernwin.MFF_READ)
    return out
