import json

import ida_frame
import ida_kernwin
import ida_typeinf
import idaapi

from gepetto.ida.tools.function_utils import parse_ea
from gepetto.ida.tools.tools import add_result_to_messages


def handle_get_stack_frame_variables_tc(tc, messages):
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}
    try:
        result = {"ok": True, "variables": get_stack_frame_variables(args.get("function_address"))}
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}
    add_result_to_messages(messages, tc, result)


def handle_rename_stack_frame_variable_tc(tc, messages):
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}
    try:
        result = rename_stack_frame_variable(args.get("function_address"), args.get("old_name"), args.get("new_name"))
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}
    add_result_to_messages(messages, tc, result)


def handle_create_stack_frame_variable_tc(tc, messages):
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}
    try:
        result = create_stack_frame_variable(args.get("function_address"), args.get("offset"), args.get("variable_name"), args.get("type_name"))
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}
    add_result_to_messages(messages, tc, result)


def handle_set_stack_frame_variable_type_tc(tc, messages):
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}
    try:
        result = set_stack_frame_variable_type(args.get("function_address"), args.get("variable_name"), args.get("type_name"))
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}
    add_result_to_messages(messages, tc, result)


def handle_delete_stack_frame_variable_tc(tc, messages):
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}
    try:
        result = delete_stack_frame_variable(args.get("function_address"), args.get("variable_name"))
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}
    add_result_to_messages(messages, tc, result)


# ----------------------------------------------------------------------------

def _frame_tinfo(func) -> ida_typeinf.tinfo_t:
    frame_tif = ida_typeinf.tinfo_t()
    if not ida_frame.get_func_frame(frame_tif, func):
        raise ValueError("No frame returned.")
    return frame_tif


def get_stack_frame_variables(function_address: str) -> list[dict]:
    # Enhanced error handling and thread safety
    try:
        func = idaapi.get_func(parse_ea(function_address))
        if not func:
            raise ValueError(f"No function found at address {function_address}")
        
        result = {"members": [], "error": None}
        
        def _do():
            try:
                members = []
                # Check if we can get frame info first
                if not hasattr(func, 'frame') or func.frame == idaapi.BADADDR:
                    result["members"] = []
                    return 1
                    
                tif = ida_typeinf.tinfo_t()
                # Improved frame type retrieval with better error handling
                try:
                    if not tif.get_type_by_tid(func.frame):
                        result["members"] = []
                        return 1
                except Exception:
                    # Fallback: try getting frame through ida_frame
                    try:
                        if not ida_frame.get_func_frame(tif, func):
                            result["members"] = []
                            return 1
                    except Exception:
                        result["members"] = []
                        return 1
                
                if not tif.is_udt():
                    result["members"] = []
                    return 1
                    
                udt = ida_typeinf.udt_type_data_t()
                if not tif.get_udt_details(udt):
                    result["members"] = []
                    return 1
                    
                for udm in udt:
                    try:
                        if not udm.is_gap() and udm.name:
                            name = udm.name
                            offset = udm.offset // 8
                            size = udm.size // 8
                            typ = str(udm.type)
                            members.append({"name": name, "offset": hex(offset), "size": hex(size), "type": typ})
                    except Exception:
                        continue
                        
                result["members"] = members
                return 1
            except Exception as e:
                result["error"] = str(e)
                result["members"] = []
                return 0
        
        # Use MFF_FAST instead of MFF_READ for better compatibility
        if not ida_kernwin.execute_sync(_do, ida_kernwin.MFF_FAST):
            if result["error"]:
                raise ValueError(f"Failed to get stack frame variables: {result['error']}")
            
        return result["members"]
        
    except Exception as e:
        # Return empty list instead of raising exception for better tool compatibility
        print(f"Warning: get_stack_frame_variables failed: {e}")
        return []


def rename_stack_frame_variable(function_address: str, old_name: str, new_name: str) -> dict:
    try:
        func = idaapi.get_func(parse_ea(function_address))
        if not func:
            return {"ok": False, "error": f"No function found at address {function_address}"}
        
        out = {"ok": False}

        def _do():
            try:
                frame_tif = _frame_tinfo(func)
                idx, udm = frame_tif.get_udm(old_name)
                if not udm:
                    out.update(error=f"{old_name} not found.")
                    return 0
                tid = frame_tif.get_udm_tid(idx)
                if ida_frame.is_special_frame_member(tid):
                    out.update(error=f"{old_name} is a special frame member.")
                    return 0
                udm2 = ida_typeinf.udm_t()
                frame_tif.get_udm_by_tid(udm2, tid)
                offset = udm2.offset // 8
                if ida_frame.is_funcarg_off(func, offset):
                    out.update(error=f"{old_name} is an argument member.")
                    return 0
                sval = ida_frame.soff_to_fpoff(func, offset)
                if not ida_frame.define_stkvar(func, new_name, sval, udm2.type):
                    out.update(error="failed to rename stack frame variable")
                    return 0
                out.update(ok=True, function_address=function_address, old_name=old_name, new_name=new_name)
                return 1
            except Exception as e:
                out.update(error=str(e))
                return 0

        # Use MFF_FAST for better compatibility
        if not ida_kernwin.execute_sync(_do, ida_kernwin.MFF_FAST):
            if not out.get("error"):
                out["error"] = "Failed to execute on main thread"
                
        return out
    except Exception as e:
        return {"ok": False, "error": f"Stack frame rename failed: {str(e)}"}


def create_stack_frame_variable(function_address: str, offset: str, variable_name: str, type_name: str) -> dict:
    try:
        func = idaapi.get_func(parse_ea(function_address))
        if not func:
            return {"ok": False, "error": f"No function found at address {function_address}"}
        
        off = parse_ea(offset)
        out = {"ok": False}

        def _do():
            try:
                tif = ida_typeinf.tinfo_t(type_name)
                if not ida_frame.define_stkvar(func, variable_name, off, tif):
                    out.update(error="failed to define stack frame variable")
                    return 0
                out.update(ok=True, function_address=function_address, offset=hex(off), variable_name=variable_name, type_name=type_name)
                return 1
            except Exception as e:
                out.update(error=str(e))
                return 0

        # Use MFF_FAST for better compatibility
        if not ida_kernwin.execute_sync(_do, ida_kernwin.MFF_FAST):
            if not out.get("error"):
                out["error"] = "Failed to execute on main thread"
                
        return out
    except Exception as e:
        return {"ok": False, "error": f"Stack frame creation failed: {str(e)}"}


def set_stack_frame_variable_type(function_address: str, variable_name: str, type_name: str) -> dict:
    try:
        func = idaapi.get_func(parse_ea(function_address))
        if not func:
            return {"ok": False, "error": f"No function found at address {function_address}"}
        
        out = {"ok": False}

        def _do():
            try:
                frame_tif = _frame_tinfo(func)
                idx, udm = frame_tif.get_udm(variable_name)
                if not udm:
                    out.update(error=f"{variable_name} not found.")
                    return 0
                tid = frame_tif.get_udm_tid(idx)
                udm2 = ida_typeinf.udm_t()
                frame_tif.get_udm_by_tid(udm2, tid)
                offset = udm2.offset // 8
                tif = ida_typeinf.tinfo_t(type_name)
                if not ida_frame.set_frame_member_type(func, offset, tif):
                    out.update(error="failed to set stack frame variable type")
                    return 0
                out.update(ok=True, function_address=function_address, variable_name=variable_name, type_name=type_name)
                return 1
            except Exception as e:
                out.update(error=str(e))
                return 0

        # Use MFF_FAST for better compatibility
        if not ida_kernwin.execute_sync(_do, ida_kernwin.MFF_FAST):
            if not out.get("error"):
                out["error"] = "Failed to execute on main thread"
                
        return out
    except Exception as e:
        return {"ok": False, "error": f"Stack frame type setting failed: {str(e)}"}


def delete_stack_frame_variable(function_address: str, variable_name: str) -> dict:
    try:
        func = idaapi.get_func(parse_ea(function_address))
        if not func:
            return {"ok": False, "error": f"No function found at address {function_address}"}
        
        out = {"ok": False}

        def _do():
            try:
                frame_tif = _frame_tinfo(func)
                idx, udm = frame_tif.get_udm(variable_name)
                if not udm:
                    out.update(error=f"{variable_name} not found.")
                    return 0
                tid = frame_tif.get_udm_tid(idx)
                udm2 = ida_typeinf.udm_t()
                frame_tif.get_udm_by_tid(udm2, tid)
                offset = udm2.offset // 8
                size = udm2.size // 8
                if ida_frame.is_funcarg_off(func, offset):
                    out.update(error=f"{variable_name} is an argument member.")
                    return 0
                if not ida_frame.delete_frame_members(func, offset, offset + size):
                    out.update(error="failed to delete stack frame variable")
                    return 0
                out.update(ok=True, function_address=function_address, variable_name=variable_name)
                return 1
            except Exception as e:
                out.update(error=str(e))
                return 0

        # Use MFF_FAST for better compatibility
        if not ida_kernwin.execute_sync(_do, ida_kernwin.MFF_FAST):
            if not out.get("error"):
                out["error"] = "Failed to execute on main thread"
                
        return out
    except Exception as e:
        return {"ok": False, "error": f"Stack frame deletion failed: {str(e)}"}
