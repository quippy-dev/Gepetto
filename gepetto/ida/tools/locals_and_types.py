import json

import ida_hexrays
import ida_frame
import ida_funcs
import ida_kernwin
import ida_typeinf
import idaapi

from gepetto.ida.tools.tools import add_result_to_messages
from gepetto.ida.utils.ida9_utils import (
    parse_ea, run_on_main_thread, hexrays_available, decompile_func,
    parse_type_declaration, validate_function_ea, ea_to_hex, touch_last_ea
)


def handle_rename_local_variable_tc(tc, messages):
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}
    try:
        result = rename_local_variable(args.get("function_address"), args.get("old_name"), args.get("new_name"))
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}
    add_result_to_messages(messages, tc, result)


def handle_set_local_variable_type_tc(tc, messages):
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}
    try:
        result = set_local_variable_type(args.get("function_address"), args.get("variable_name"), args.get("new_type"))
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}
    add_result_to_messages(messages, tc, result)


def rename_local_variable(function_address: str, old_name: str, new_name: str) -> dict:
    if not old_name or new_name is None:
        return {"ok": False, "error": "old_name and new_name are required"}
    try:
        ea = parse_ea(function_address)
        touch_last_ea(ea)
        out = {"ok": False}

        def _do():
            try:
                # Validate and get function
                func = validate_function_ea(ea)

                # Resolve frame tinfo and locate member by name
                frame_tif = ida_typeinf.tinfo_t()
                if not ida_frame.get_func_frame(frame_tif, func):
                    out.update(error="Function frame not found.")
                    return 0
                idx, udm = frame_tif.get_udm(old_name)
                if not udm:
                    out.update(error=f"Local variable '{old_name}' not found in frame")
                    return 0
                tid = frame_tif.get_udm_tid(idx)
                if ida_frame.is_special_frame_member(tid):
                    out.update(error=f"'{old_name}' is a special frame member and cannot be renamed.")
                    return 0
                udm2 = ida_typeinf.udm_t()
                frame_tif.get_udm_by_tid(udm2, tid)
                offset = udm2.offset // 8
                if ida_frame.is_funcarg_off(func, offset):
                    out.update(error=f"'{old_name}' is an argument member and cannot be renamed.")
                    return 0

                # Rename the frame UDM using tinfo_t (IDA 9.x)
                try:
                    rc = frame_tif.rename_udm(idx, new_name)
                    ok2 = bool(rc) if isinstance(rc, bool) else (rc == 0 if isinstance(rc, int) else bool(rc))
                except Exception:
                    ok2 = False
                if not ok2:
                    out.update(error=f"Failed to rename local variable '{old_name}' to '{new_name}'")
                    return 0

                out.update(ok=True, function_address=function_address, old_name=old_name, new_name=new_name)
                return 1
            except Exception as e:
                out.update(error=str(e))
                return 0

        # Execute on main thread with write access
        if not run_on_main_thread(_do, write=True):
            if not out.get("error"):
                out["error"] = "Failed to execute on main thread"
        return out
    except Exception as e:
        return {"ok": False, "error": f"Local variable rename failed: {str(e)}"}


class _LvarTypeModifier(ida_hexrays.user_lvar_modifier_t):
    def __init__(self, var_name: str, new_type: ida_typeinf.tinfo_t):
        ida_hexrays.user_lvar_modifier_t.__init__(self)
        self.var_name = var_name
        self.new_type = new_type

    def modify_lvars(self, lvars):
        for lvar_saved in lvars.lvvec:
            if lvar_saved.name == self.var_name:
                lvar_saved.type = self.new_type
                return True
        return False


def set_local_variable_type(function_address: str, variable_name: str, new_type: str) -> dict:
    if not function_address or not variable_name or not new_type:
        return {"ok": False, "error": "function_address, variable_name, new_type are required"}
    try:
        ea = parse_ea(function_address)
        touch_last_ea(ea)
        out = {"ok": False}

        def _do():
            try:
                # Validate and get function
                func = validate_function_ea(ea)

                # Parse new type robustly using ida9_utils helper
                try:
                    tif = parse_type_declaration(new_type)
                except ValueError as e:
                    out.update(error=str(e))
                    return 0

                # Resolve frame & locate member by name
                frame_tif = ida_typeinf.tinfo_t()
                if not ida_frame.get_func_frame(frame_tif, func):
                    out.update(error="Function frame not found.")
                    return 0
                idx, udm = frame_tif.get_udm(variable_name)
                if not udm:
                    out.update(error=f"Local variable '{variable_name}' not found in frame")
                    return 0
                udm2 = ida_typeinf.udm_t()
                frame_tif.get_udm_by_tid(udm2, frame_tif.get_udm_tid(idx))
                offset = udm2.offset // 8

                # Apply the parsed type to the frame member
                if not ida_frame.set_frame_member_type(func, offset, tif):
                    # Fallback: redefine the stkvar at the same offset
                    try:
                        if ida_frame.define_stkvar(func, variable_name, offset, tif):
                            out.update(ok=True, function_address=function_address, variable_name=variable_name, new_type=str(tif))
                            return 1
                        # As a last resort, delete overlapping range for the new size then redefine
                        new_size = max(1, int(tif.get_size()))
                        ida_frame.delete_frame_members(func, offset, offset + new_size)
                        if ida_frame.define_stkvar(func, variable_name, offset, tif):
                            out.update(ok=True, function_address=function_address, variable_name=variable_name, new_type=str(tif))
                            return 1
                        out.update(error=f"Failed to set type for local variable '{variable_name}' (redefine failed)")
                        return 0
                    except Exception as _e:
                        out.update(error=f"Failed to set type for local variable '{variable_name}': {_e}")
                        return 0

                out.update(ok=True, function_address=function_address, variable_name=variable_name, new_type=str(tif))
                return 1
            except Exception as e:
                out.update(error=str(e))
                return 0

        # Execute on main thread with write access
        if not run_on_main_thread(_do, write=True):
            if not out.get("error"):
                out["error"] = "Failed to execute on main thread"
        return out
    except Exception as e:
        return {"ok": False, "error": f"Local variable type setting failed: {str(e)}"}
