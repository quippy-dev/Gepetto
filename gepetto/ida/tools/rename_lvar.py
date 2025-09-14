import json
from typing import Optional

import ida_hexrays
import ida_kernwin
import ida_frame
import ida_typeinf
import ida_funcs
import idaapi

from gepetto.ida.utils.ida9_utils import parse_ea
from gepetto.ida.tools.function_utils import resolve_ea, resolve_func, get_func_name
from gepetto.ida.tools.tools import add_result_to_messages
from gepetto.ida.utils.ida9_utils import hexrays_available, decompile_func, run_on_main_thread, touch_last_ea



def handle_rename_lvar_tc(tc, messages):
    """Handle a tool call to rename a local variable."""
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}

    ea = args.get("ea")
    if ea is not None:
        ea = parse_ea(ea)
    func_name = args.get("func_name")
    old_name = args.get("old_name")
    new_name = args.get("new_name")

    try:
        result = rename_lvar(ea=ea, func_name=func_name, old_name=old_name, new_name=new_name)
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}

    add_result_to_messages(messages, tc, result)


# -----------------------------------------------------------------------------

def rename_lvar(
    ea: Optional[int] = None,
    func_name: Optional[str] = None,
    old_name: Optional[str] = None,
    new_name: Optional[str] = None,
) -> dict:
    """Rename a local (stack frame) variable by updating the frame member name."""
    if not old_name or not new_name:
        raise ValueError("old_name and new_name are required")

    if ea is not None:
        ea = parse_ea(ea)
    f = resolve_func(ea=ea, name=func_name)
    func_name = func_name or get_func_name(f)
    if ea is None:
        ea = resolve_ea(func_name)
    touch_last_ea(ea)

    out = {"ok": False, "ea": int(f.start_ea), "func_name": func_name, "old_name": old_name, "new_name": new_name}

    def _do():
        try:
            # Use ida_typeinf/ida_frame in IDA 9.x
            frame_tif = ida_typeinf.tinfo_t()
            if not ida_frame.get_func_frame(frame_tif, f):
                out["error"] = "Function frame not found."
                return 0
            idx, udm = frame_tif.get_udm(old_name)
            if not udm:
                out["error"] = f"Local variable {old_name!r} not found in frame"
                return 0
            tid = frame_tif.get_udm_tid(idx)
            if ida_frame.is_special_frame_member(tid):
                out["error"] = f"'{old_name}' is a special frame member and cannot be renamed."
                return 0
            udm2 = ida_typeinf.udm_t()
            frame_tif.get_udm_by_tid(udm2, tid)
            offset = udm2.offset // 8
            if ida_frame.is_funcarg_off(f, offset):
                out["error"] = f"'{old_name}' is an argument member and cannot be renamed."
                return 0
            try:
                rc = frame_tif.rename_udm(idx, new_name)
                ok = bool(rc) if isinstance(rc, bool) else (rc == 0 if isinstance(rc, int) else bool(rc))
            except Exception:
                ok = False
            if not ok:
                out["error"] = f"Failed to rename lvar {old_name!r}"
                return 0
            out["ok"] = True
            return 1
        except Exception as e:
            out["error"] = str(e)
            return 0

    if not run_on_main_thread(_do, write=True):
        if not out.get("error"):
            out["error"] = "Failed to execute on main thread"

    if not out["ok"]:
        raise ValueError(out.get("error", "Failed to rename lvar"))
    return out
