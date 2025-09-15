import json

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
        raise ValueError(_("No frame returned."))
    return frame_tif


def get_stack_frame_variables(function_address: str) -> list[dict]:
    """Get stack frame variables with enhanced error handling and thread safety."""
    try:
        ea = parse_ea(function_address)
        touch_last_ea(ea)
        func = validate_function_ea(ea)
        
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
                            members.append({"name": name, "offset": ea_to_hex(offset), "size": ea_to_hex(size), "type": typ})
                    except Exception:
                        continue
                        
                result["members"] = members
                return 1
            except Exception as e:
                result["error"] = str(e)
                result["members"] = []
                return 0
        
        # Execute on main thread with write access for stability on IDA 9.x
        if not run_on_main_thread(_do, write=True):
            if result["error"]:
                raise ValueError(_("Failed to get stack frame variables: {error}").format(error=result['error']))
        return result["members"]
        
    except Exception as e:
        # Return empty list instead of raising exception for better tool compatibility
        print(_("Warning: get_stack_frame_variables failed: {error}").format(error=e))
        return []


def rename_stack_frame_variable(function_address: str, old_name: str, new_name: str) -> dict:
    """Rename stack frame variable with proper main thread execution."""
    try:
        ea = parse_ea(function_address)
        touch_last_ea(ea)
        func = validate_function_ea(ea)
        
        out = {"ok": False}

        def _do():
            try:
                # Frame-based approach only: operate on the function frame structure
                
                # Frame-based approach using ida_typeinf/ida_frame APIs (IDA 9.x)
                frame_tif = _frame_tinfo(func)
                idx, udm = frame_tif.get_udm(old_name)
                if not udm:
                    out.update(error=f"Stack frame variable '{old_name}' not found.")
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
                    ok = bool(rc) if isinstance(rc, bool) else (rc == 0 if isinstance(rc, int) else bool(rc))
                except Exception as _e:
                    ok = False
                if not ok:
                    out.update(error="Failed to rename stack frame variable (name may be invalid or already exist)")
                    return 0
                out.update(ok=True, function_address=function_address, old_name=old_name, new_name=new_name)
                return 1
            except Exception as e:
                out.update(error=str(e))
                return 0

        # Execute on main thread with write access for DB modifications
        if not run_on_main_thread(_do, write=True):
            if not out.get("error"):
                out["error"] = "Failed to execute on main thread"
                
        return out
    except Exception as e:
        return {"ok": False, "error": f"Stack frame rename failed: {str(e)}"}


def create_stack_frame_variable(function_address: str, offset: str, variable_name: str, type_name: str) -> dict:
    """Create stack frame variable with proper main thread execution."""
    try:
        ea = parse_ea(function_address)
        touch_last_ea(ea)
        func = validate_function_ea(ea)
        
        off = parse_ea(offset)
        out = {"ok": False}

        def _do():
            try:
                # Parse type declaration
                try:
                    tif = parse_type_declaration(type_name)
                except ValueError as e:
                    out.update(error=str(e))
                    return 0
                
                if not ida_frame.define_stkvar(func, variable_name, off, tif):
                    out.update(error="Failed to define stack frame variable (offset may be invalid or name already exists)")
                    return 0
                    
                out.update(ok=True, function_address=function_address, offset=ea_to_hex(off), variable_name=variable_name, type_name=type_name)
                return 1
            except Exception as e:
                out.update(error=str(e))
                return 0

        # Execute on main thread with write access for DB modifications
        if not run_on_main_thread(_do, write=True):
            if not out.get("error"):
                out["error"] = "Failed to execute on main thread"
                
        return out
    except Exception as e:
        return {"ok": False, "error": f"Stack frame creation failed: {str(e)}"}


def set_stack_frame_variable_type(function_address: str, variable_name: str, type_name: str) -> dict:
    """Set stack frame variable type with proper main thread execution."""
    try:
        ea = parse_ea(function_address)
        touch_last_ea(ea)
        func = validate_function_ea(ea)
        
        out = {"ok": False}

        def _do():
            try:
                # Try Hex-Rays approach first if available
                if hexrays_available():
                    try:
                        cfunc = decompile_func(ea)
                        
                        # Parse type declaration
                        try:
                            new_tif = parse_type_declaration(type_name)
                        except ValueError as e:
                            out.update(error=str(e))
                            return 0
                        
                        # Find variable in lvars
                        target_lvar = None
                        for lvar in cfunc.lvars:
                            if lvar.name == variable_name or lvar.cname == variable_name:
                                target_lvar = lvar
                                break
                        
                        if target_lvar:
                            # Use Hex-Rays API for setting type
                            if hasattr(cfunc, 'set_user_lvar_type'):
                                if cfunc.set_user_lvar_type(target_lvar, new_tif):
                                    if hasattr(cfunc, 'save_user_lvars'):
                                        cfunc.save_user_lvars()
                                    if hasattr(cfunc, 'refresh_view'):
                                        cfunc.refresh_view(True)
                                    out.update(ok=True, function_address=function_address, variable_name=variable_name, type_name=str(new_tif))
                                    return 1
                        # If not found in lvars, fall through to frame-based approach
                    except Exception:
                        # Fall through to frame-based approach
                        pass
                
                # Frame-based approach using ida_frame APIs
                frame_tif = _frame_tinfo(func)
                idx, udm = frame_tif.get_udm(variable_name)
                if not udm:
                    out.update(error=f"Stack frame variable '{variable_name}' not found.")
                    return 0
                tid = frame_tif.get_udm_tid(idx)
                udm2 = ida_typeinf.udm_t()
                frame_tif.get_udm_by_tid(udm2, tid)
                offset = udm2.offset // 8
                
                # Parse type declaration
                try:
                    tif = parse_type_declaration(type_name)
                except ValueError as e:
                    out.update(error=str(e))
                    return 0
                
                if not ida_frame.set_frame_member_type(func, offset, tif):
                    # Fallback 1: redefine using define_stkvar (supports redefinition).
                    if ida_frame.define_stkvar(func, variable_name, offset, tif):
                        out.update(ok=True, function_address=function_address, variable_name=variable_name, type_name=str(tif))
                        return 1
                    # Fallback 2: clear the new desired range, then redefine.
                    try:
                        new_size = max(1, int(tif.get_size()))
                    except Exception:
                        new_size = 1
                    try:
                        ida_frame.delete_frame_members(func, offset, offset + new_size)
                        if ida_frame.define_stkvar(func, variable_name, offset, tif):
                            out.update(ok=True, function_address=function_address, variable_name=variable_name, type_name=str(tif))
                            return 1
                        out.update(error="Failed to set stack frame variable type (redefine failed)")
                        return 0
                    except Exception as _e:
                        out.update(error=f"Failed to set stack frame variable type: {_e}")
                        return 0
                    
                out.update(ok=True, function_address=function_address, variable_name=variable_name, type_name=str(tif))
                return 1
            except Exception as e:
                out.update(error=str(e))
                return 0

        # Execute on main thread with write access for DB modifications
        if not run_on_main_thread(_do, write=True):
            if not out.get("error"):
                out["error"] = "Failed to execute on main thread"
                
        return out
    except Exception as e:
        return {"ok": False, "error": f"Stack frame type setting failed: {str(e)}"}


def delete_stack_frame_variable(function_address: str, variable_name: str) -> dict:
    """Delete stack frame variable with proper main thread execution."""
    try:
        ea = parse_ea(function_address)
        touch_last_ea(ea)
        func = validate_function_ea(ea)
        
        out = {"ok": False}

        def _do():
            try:
                # Prefer explicit message if user expects Hex-Rays behavior
                if hexrays_available():
                    # We do not delete lvars via Hex-Rays; provide clear guidance
                    out.update(error="Operation not supported without direct frame edits; use frame-based tools or install Hex-Rays to rename/type only.")
                    return 0
                # Frame-based approach using ida_frame APIs
                frame_tif = _frame_tinfo(func)
                idx, udm = frame_tif.get_udm(variable_name)
                if not udm:
                    out.update(error=f"Stack frame variable '{variable_name}' not found.")
                    return 0
                tid = frame_tif.get_udm_tid(idx)
                udm2 = ida_typeinf.udm_t()
                frame_tif.get_udm_by_tid(udm2, tid)
                offset = udm2.offset // 8
                size = udm2.size // 8
                if ida_frame.is_funcarg_off(func, offset):
                    out.update(error=f"'{variable_name}' is an argument member and cannot be deleted.")
                    return 0
                if not ida_frame.delete_frame_members(func, offset, offset + size):
                    out.update(error="Failed to delete stack frame variable (variable may be protected or in use)")
                    return 0
                out.update(ok=True, function_address=function_address, variable_name=variable_name)
                return 1
            except Exception as e:
                out.update(error=str(e))
                return 0

        # Execute on main thread with write access for DB modifications
        if not run_on_main_thread(_do, write=True):
            if not out.get("error"):
                out["error"] = "Failed to execute on main thread"
                
        return out
    except Exception as e:
        return {"ok": False, "error": f"Stack frame deletion failed: {str(e)}"}
