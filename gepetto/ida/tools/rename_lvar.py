import json
from typing import Optional

import ida_hexrays
import ida_kernwin

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
    """Rename a local variable in a function."""
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
            if not hexrays_available():
                out["error"] = "Hex-Rays not available: install/enable the Hex-Rays Decompiler."
                return 0
            cfunc = decompile_func(ea)
            target_lvar = None
            for lvar in getattr(cfunc, "lvars", []):
                if lvar.name == old_name or getattr(lvar, "cname", None) == old_name:
                    target_lvar = lvar
                    break
            if not target_lvar:
                out["error"] = f"Local variable {old_name!r} not found"
                return 0
            renamed = False
            if hasattr(cfunc, "set_user_lvar_name"):
                renamed = bool(cfunc.set_user_lvar_name(target_lvar, new_name))
            elif hasattr(target_lvar, "set_user_name"):
                renamed = bool(target_lvar.set_user_name(new_name))
            else:
                renamed = bool(ida_hexrays.rename_lvar(ea, old_name, new_name))
            if not renamed:
                out["error"] = f"Failed to rename lvar {old_name!r}"
                return 0
            if hasattr(cfunc, "save_user_lvars"):
                cfunc.save_user_lvars()
            if hasattr(cfunc, "refresh_view"):
                cfunc.refresh_view(True)
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
