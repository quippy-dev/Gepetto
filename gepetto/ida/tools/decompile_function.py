import json

import ida_hexrays
import ida_kernwin
import ida_lines
import idaapi

from gepetto.ida.utils.ida9_utils import parse_ea, run_on_main_thread, touch_last_ea
from gepetto.ida.tools.tools import add_result_to_messages
from gepetto.ida.utils.ida9_utils import decompile_func as ida9_decompile_func


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
    # Delegate to centralized utility for consistent error handling and diagnostics
    return ida9_decompile_func(func_ea)


def decompile_function(address: str) -> dict:
    if not address:
        raise ValueError("address is required")

    out = {"ok": False}

    def _do():
        try:
            ea = parse_ea(address)
            touch_last_ea(ea)
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

    if not run_on_main_thread(_do, write=False):
        if not out.get("error"):
            out["error"] = "Failed to execute on main thread"
    return out
