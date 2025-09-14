import json

import ida_hexrays
import ida_kernwin
import ida_typeinf

from gepetto.ida.tools.function_utils import parse_ea
from gepetto.ida.tools.tools import add_result_to_messages


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
        out = {"ok": False}

        def _do():
            try:
                # Check if function exists and can be decompiled
                func = ida_hexrays.get_func_by_ea(ea)
                if not func:
                    out.update(error=f"Function not found or cannot be decompiled at {function_address}")
                    return 0
                
                # Try to get cfunc to verify variable exists
                try:
                    cfunc = ida_hexrays.decompile(ea)
                    if cfunc:
                        # Check if variable exists in local variables
                        var_found = False
                        for lvar in cfunc.lvars:
                            if lvar.name == old_name:
                                var_found = True
                                break
                        
                        if not var_found:
                            out.update(error=f"Local variable '{old_name}' not found in function")
                            return 0
                except Exception:
                    # If decompilation fails, still try to rename but expect it might fail
                    pass
                
                # Attempt the rename
                if not ida_hexrays.rename_lvar(ea, old_name, new_name):
                    out.update(error=f"Failed to rename local variable '{old_name}' (variable may not exist or rename not permitted)")
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
        out = {"ok": False}

        def _do():
            try:
                # Parse the new type first
                new_tif = ida_typeinf.tinfo_t()
                try:
                    new_tif = ida_typeinf.tinfo_t(new_type, None, ida_typeinf.PT_SIL)
                    if not new_tif.is_correct():
                        raise Exception("Invalid type")
                except Exception:
                    # Fallback to parse_decl
                    if not ida_typeinf.parse_decl(new_tif, None, new_type + ";", ida_typeinf.PT_SIL):
                        out.update(error=f"Failed to parse type: {new_type}")
                        return 0
                
                # Check if function exists and can be decompiled
                func = ida_hexrays.get_func_by_ea(ea)
                if not func:
                    out.update(error=f"Function not found or cannot be decompiled at {function_address}")
                    return 0
                
                # Verify variable exists
                try:
                    cfunc = ida_hexrays.decompile(ea)
                    if cfunc:
                        var_found = False
                        for lvar in cfunc.lvars:
                            if lvar.name == variable_name:
                                var_found = True
                                break
                        
                        if not var_found:
                            out.update(error=f"Local variable '{variable_name}' not found in function")
                            return 0
                except Exception:
                    # If decompilation fails, still try to proceed but expect it might fail
                    pass
                
                # Test if variable exists by trying to rename it to itself
                if not ida_hexrays.rename_lvar(ea, variable_name, variable_name):
                    out.update(error=f"Local variable not found: {variable_name}")
                    return 0
                    
                modifier = _LvarTypeModifier(variable_name, new_tif)
                if not ida_hexrays.modify_user_lvars(ea, modifier):
                    out.update(error=f"Failed to modify local variable type: {variable_name}")
                    return 0
                    
                out.update(ok=True, function_address=function_address, variable_name=variable_name, new_type=str(new_tif))
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
        return {"ok": False, "error": f"Local variable type setting failed: {str(e)}"}
