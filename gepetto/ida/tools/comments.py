import json

import ida_hexrays
import ida_kernwin
import idaapi

from gepetto.ida.utils.ida9_utils import parse_ea, run_on_main_thread, touch_last_ea
from gepetto.ida.tools.tools import add_result_to_messages


def handle_set_comment_tc(tc, messages):
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}
    try:
        result = set_comment(args.get("address"), args.get("comment", ""))
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}
    add_result_to_messages(messages, tc, result)


def set_comment(address: str, comment: str) -> dict:
    ea = parse_ea(address)
    touch_last_ea(ea)
    if comment is None:
        comment = ""
    out = {"ok": False}

    def _do():
        try:
            if not idaapi.set_cmt(ea, comment, False):
                out.update(error=f"Failed to set disassembly comment at {hex(ea)}")
                return 0
            # Try to set in pseudocode as well if available
            if ida_hexrays.init_hexrays_plugin():
                try:
                    cfunc = ida_hexrays.decompile(ea)
                    if cfunc and ea == cfunc.entry_ea:
                        idaapi.set_func_cmt(ea, comment, True)
                        cfunc.refresh_func_ctext()
                except Exception:
                    pass
            out.update(ok=True, address=int(ea), comment=comment)
            return 1
        except Exception as e:
            out.update(error=str(e))
            return 0

    run_on_main_thread(_do, write=True)
    return out

