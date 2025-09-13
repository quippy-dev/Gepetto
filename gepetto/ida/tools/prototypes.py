import json

import ida_kernwin
import ida_typeinf
import idaapi

from gepetto.ida.tools.function_utils import parse_ea
from gepetto.ida.tools.tools import add_result_to_messages


def handle_set_function_prototype_tc(tc, messages):
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}
    try:
        result = set_function_prototype(args.get("function_address"), args.get("prototype"))
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}
    add_result_to_messages(messages, tc, result)


def set_function_prototype(function_address: str, prototype: str) -> dict:
    if not function_address or prototype is None:
        raise ValueError("function_address and prototype are required")
    ea = parse_ea(function_address)
    out = {"ok": False}

    def _do():
        try:
            func = idaapi.get_func(ea)
            if not func:
                out.update(error=f"No function found at address {function_address}")
                return 0
            tif = ida_typeinf.tinfo_t(prototype, None, ida_typeinf.PT_SIL)
            if not tif.is_func():
                out.update(error="Parsed declaration is not a function type")
                return 0
            if not ida_typeinf.apply_tinfo(func.start_ea, tif, ida_typeinf.PT_SIL):
                out.update(error="Failed to apply type")
                return 0
            out.update(ok=True, function_address=function_address, prototype=str(tif))
            return 1
        except Exception as e:
            out.update(error=str(e))
            return 0

    ida_kernwin.execute_sync(_do, ida_kernwin.MFF_WRITE)
    return out

