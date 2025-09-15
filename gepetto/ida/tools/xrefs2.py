import json

import ida_kernwin
import ida_typeinf
import idaapi
import idautils
import ida_idaapi

from gepetto.ida.utils.ida9_utils import parse_ea, run_on_main_thread, touch_last_ea
from gepetto.ida.tools.tools import add_result_to_messages


def handle_get_xrefs_to_tc(tc, messages):
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}
    try:
        result = get_xrefs_to(args.get("address"))
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}
    add_result_to_messages(messages, tc, result)


def handle_get_xrefs_to_field_tc(tc, messages):
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}
    try:
        result = get_xrefs_to_field(args.get("struct_name"), args.get("field_name"))
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}
    add_result_to_messages(messages, tc, result)


def get_xrefs_to(address: str) -> dict:
    ea = parse_ea(address)
    touch_last_ea(ea)
    out = {"ok": False}

    def _do():
        try:
            xs = []
            for xref in idautils.XrefsTo(ea):
                xs.append({
                    "address": int(xref.frm),
                    "type": "code" if xref.iscode else "data",
                    "function": _func_info(xref.frm),
                })
            out.update(ok=True, xrefs=xs)
            return 1
        except Exception as e:
            out.update(error=str(e))
            return 0

    run_on_main_thread(_do, write=False)
    return out


def _func_info(ea: int):
    fn = idaapi.get_func(ea)
    if not fn:
        return None
    name = fn.get_name() if hasattr(fn, 'get_name') else None
    if not name:
        import ida_funcs
        name = ida_funcs.get_func_name(fn.start_ea)
    return {"address": int(fn.start_ea), "name": name or "", "size": int(fn.end_ea - fn.start_ea)}


def get_xrefs_to_field(struct_name: str, field_name: str) -> dict:
    if not struct_name or not field_name:
        raise ValueError(_("struct_name and field_name are required"))
    out = {"ok": False}

    def _do():
        try:
            til = ida_typeinf.get_idati()
            if not til:
                out.update(error="Failed to retrieve type library.")
                return 0
            tif = ida_typeinf.tinfo_t()
            if not tif.get_named_type(til, struct_name, ida_typeinf.BTF_STRUCT, True, False):
                out.update(ok=True, xrefs=[])
                return 1
            idx = ida_typeinf.get_udm_by_fullname(None, struct_name + '.' + field_name)
            if idx == -1:
                out.update(ok=True, xrefs=[])
                return 1
            tid = tif.get_udm_tid(idx)
            if tid == ida_idaapi.BADADDR:
                out.update(error="Unable to get tid for field")
                return 0
            xs = []
            for xr in idautils.XrefsTo(tid):
                xs.append({
                    "address": int(xr.frm),
                    "type": "code" if xr.iscode else "data",
                    "function": _func_info(xr.frm),
                })
            out.update(ok=True, xrefs=xs)
            return 1
        except Exception as e:
            out.update(error=str(e))
            return 0

    run_on_main_thread(_do, write=False)
    return out
