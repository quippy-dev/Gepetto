import json

import ida_hexrays
import ida_funcs
import ida_kernwin
import ida_typeinf

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
                # Validate function exists
                validate_function_ea(ea)
                
                # Check Hex-Rays availability
                if not hexrays_available():
                    out.update(error="Hex-Rays not available: install/enable the Hex-Rays Decompiler.")
                    return 0
                
                # Get decompiled function
                try:
                    cfunc = decompile_func(ea)
                    
                    # Check if variable exists in local variables
                    var_found = False
                    target_lvar = None
                    for lvar in cfunc.lvars:
                        if lvar.name == old_name or lvar.cname == old_name:
                            var_found = True
                            target_lvar = lvar
                            break
                    
                    if not var_found:
                        out.update(error=f"Local variable '{old_name}' not found in function")
                        return 0
                    
                    # Use IDA 9.x API for renaming - prefer set_user_lvar_name if available
                    if hasattr(cfunc, 'set_user_lvar_name'):
                        if not cfunc.set_user_lvar_name(target_lvar, new_name):
                            out.update(error=f"Failed to rename local variable '{old_name}' to '{new_name}'")
                            return 0
                    elif hasattr(target_lvar, 'set_user_name'):
                        if not target_lvar.set_user_name(new_name):
                            out.update(error=f"Failed to rename local variable '{old_name}' to '{new_name}'")
                            return 0
                    else:
                        # Fallback to legacy API
                        if not ida_hexrays.rename_lvar(ea, old_name, new_name):
                            out.update(error=f"Failed to rename local variable '{old_name}' to '{new_name}'")
                            return 0
                    
                    # Save changes and refresh view
                    if hasattr(cfunc, 'save_user_lvars'):
                        cfunc.save_user_lvars()
                    if hasattr(cfunc, 'refresh_view'):
                        cfunc.refresh_view(True)
                        
                    out.update(ok=True, function_address=function_address, old_name=old_name, new_name=new_name)
                    return 1
                    
                except Exception as e:
                    out.update(error=str(e))
                    return 0
                    
            except Exception as e:
                out.update(error=str(e))
                return 0

        # Execute on main thread with write access for DB modifications
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
                # Validate function exists
                validate_function_ea(ea)
                
                # Check Hex-Rays availability
                if not hexrays_available():
                    out.update(error="Hex-Rays not available: install/enable the Hex-Rays Decompiler.")
                    return 0
                
                # Parse the new type
                try:
                    new_tif = parse_type_declaration(new_type)
                except ValueError as e:
                    out.update(error=str(e))
                    return 0
                
                # Get decompiled function and verify variable exists
                try:
                    cfunc = decompile_func(ea)
                    
                    var_found = False
                    target_lvar = None
                    for lvar in cfunc.lvars:
                        if lvar.name == variable_name or lvar.cname == variable_name:
                            var_found = True
                            target_lvar = lvar
                            break
                    
                    if not var_found:
                        out.update(error=f"Local variable '{variable_name}' not found in function")
                        return 0
                    
                    # Use IDA 9.x API for setting type - prefer set_user_lvar_type if available
                    if hasattr(cfunc, 'set_user_lvar_type'):
                        if not cfunc.set_user_lvar_type(target_lvar, new_tif):
                            out.update(error=f"Failed to set type for local variable '{variable_name}'")
                            return 0
                    else:
                        # Fallback to modifier approach
                        modifier = _LvarTypeModifier(variable_name, new_tif)
                        if not ida_hexrays.modify_user_lvars(ea, modifier):
                            out.update(error=f"Failed to modify local variable type: {variable_name}")
                            return 0
                    
                    # Save changes and refresh view
                    if hasattr(cfunc, 'save_user_lvars'):
                        cfunc.save_user_lvars()
                    if hasattr(cfunc, 'refresh_view'):
                        cfunc.refresh_view(True)
                        
                    out.update(ok=True, function_address=function_address, variable_name=variable_name, new_type=str(new_tif))
                    return 1
                    
                except Exception as e:
                    out.update(error=str(e))
                    return 0
                    
            except Exception as e:
                out.update(error=str(e))
                return 0

        # Execute on main thread with write access for DB modifications
        if not run_on_main_thread(_do, write=True):
            if not out.get("error"):
                out["error"] = "Failed to execute on main thread"
                
        return out
    except Exception as e:
        return {"ok": False, "error": f"Local variable type setting failed: {str(e)}"}
