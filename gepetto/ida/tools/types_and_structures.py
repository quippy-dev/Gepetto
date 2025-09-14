import json

import ida_kernwin
import ida_typeinf
from gepetto.ida.utils.ida9_utils import run_on_main_thread, touch_last_ea

from gepetto.ida.tools.tools import add_result_to_messages


def handle_list_local_types_tc(tc, messages):
    try:
        result = list_local_types()
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}
    add_result_to_messages(messages, tc, result)


def handle_declare_c_type_tc(tc, messages):
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}
    try:
        result = declare_c_type(args.get("c_declaration", ""))
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}
    add_result_to_messages(messages, tc, result)


def handle_get_defined_structures_tc(tc, messages):
    try:
        result = get_defined_structures()
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}
    add_result_to_messages(messages, tc, result)


def handle_analyze_struct_detailed_tc(tc, messages):
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}
    try:
        result = analyze_struct_detailed(args.get("name"))
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}
    add_result_to_messages(messages, tc, result)


def handle_get_struct_info_simple_tc(tc, messages):
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}
    try:
        result = get_struct_info_simple(args.get("name"))
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}
    add_result_to_messages(messages, tc, result)


def handle_get_struct_at_address_tc(tc, messages):
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}
    try:
        result = get_struct_at_address(args.get("address"), args.get("struct_name"))
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}
    add_result_to_messages(messages, tc, result)


def handle_search_structures_tc(tc, messages):
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}
    try:
        result = search_structures(args.get("filter", ""))
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}
    add_result_to_messages(messages, tc, result)


# ----------------------------------------------------------------------------

def list_local_types() -> dict:
    # Run on UI thread (IDA 9.x): many IDA APIs are main-thread-only
    out = {"ok": False}
    
    def _do():
        try:
            locals_out: list[str] = []
            idati = ida_typeinf.get_idati()
            type_count = ida_typeinf.get_ordinal_limit(idati)
            for ordinal in range(1, type_count):
                try:
                    tif = ida_typeinf.tinfo_t()
                    if tif.get_numbered_type(idati, ordinal):
                        type_name = tif.get_type_name() or f"<Anonymous Type #{ordinal}>"
                        locals_out.append(f"\nType #{ordinal}: {type_name}")
                        if tif.is_udt():
                            flags = (ida_typeinf.PRTYPE_MULTI | ida_typeinf.PRTYPE_TYPE | ida_typeinf.PRTYPE_SEMI | ida_typeinf.PRTYPE_DEF | ida_typeinf.PRTYPE_METHODS | ida_typeinf.PRTYPE_OFFSETS)
                            c_decl_output = tif._print(None, flags)
                            if c_decl_output:
                                locals_out.append(f"  C declaration:\n{c_decl_output}")
                        else:
                            simple_decl = tif._print(None, ida_typeinf.PRTYPE_1LINE | ida_typeinf.PRTYPE_TYPE | ida_typeinf.PRTYPE_SEMI)
                            if simple_decl:
                                locals_out.append(f"  Simple declaration:\n{simple_decl}")
                except Exception:
                    continue
            out.update({"ok": True, "types": locals_out})
            return 1
        except Exception as e:
            out.update({"error": str(e)})
            return 0
    
    run_on_main_thread(_do, write=False)
    return out


def declare_c_type(c_declaration: str) -> dict:
    if not c_declaration:
        raise ValueError("c_declaration is required")
    out = {"ok": False}

    def _do():
        try:
            flags = ida_typeinf.PT_SIL | ida_typeinf.PT_EMPTY | ida_typeinf.PT_TYP
            # On non-Windows, parse_decls returns count of errors; on Windows we would need ctypes glue.
            errors = ida_typeinf.parse_decls(None, c_declaration, False, flags)
            if errors > 0:
                out.update(error="Failed to parse type", errors=errors)
                return 0
            out.update(ok=True, info="success")
            return 1
        except Exception as e:
            out.update(error=str(e))
            return 0

    run_on_main_thread(_do, write=True)
    return out


def get_defined_structures() -> dict:
    # Run on UI thread (IDA 9.x): many IDA APIs are main-thread-only
    out = {"ok": False}
    
    def _do():
        try:
            rv = []
            limit = ida_typeinf.get_ordinal_limit()
            for ordinal in range(1, limit):
                tif = ida_typeinf.tinfo_t()
                tif.get_numbered_type(None, ordinal)
                if tif.is_udt():
                    udt = ida_typeinf.udt_type_data_t()
                    members = []
                    if tif.get_udt_details(udt):
                        members = [
                            {
                                "name": x.name,
                                "offset": hex(x.offset // 8),
                                "size": hex(x.size // 8),
                                "type": str(x.type),
                            }
                            for _, x in enumerate(udt)
                        ]
                    rv.append({"name": tif.get_type_name(), "size": hex(tif.get_size()), "members": members})
            out.update({"ok": True, "structures": rv})
            return 1
        except Exception as e:
            out.update({"error": str(e)})
            return 0
    
    run_on_main_thread(_do, write=False)
    return out


def analyze_struct_detailed(name: str) -> dict:
    if not name:
        return {"ok": False, "error": "name is required"}
    
    try:
        result = {"ok": False}
        
        def _do():
            try:
                tif = ida_typeinf.tinfo_t()
                if not tif.get_named_type(None, name):
                    result.update(error=f"Structure '{name}' not found")
                    return 0

                struct_info = {"name": name, "type": str(tif._print()), "size": tif.get_size(), "is_udt": tif.is_udt()}
                if not tif.is_udt():
                    struct_info["error"] = "This is not a user-defined type!"
                    result.update(ok=False, **struct_info)
                    return 0

                udt_data = ida_typeinf.udt_type_data_t()
                if not tif.get_udt_details(udt_data):
                    struct_info["error"] = "Failed to get structure details!"
                    result.update(ok=False, **struct_info)
                    return 0

                struct_info["member_count"] = udt_data.size()
                struct_info["is_union"] = udt_data.is_union
                struct_info["udt_type"] = "Union" if udt_data.is_union else "Struct"
                members = []
                for i, member in enumerate(udt_data):
                    try:
                        offset = member.begin() // 8
                        size = member.size // 8 if member.size > 0 else member.type.get_size()
                        member_type = member.type._print()
                        member_name = member.name
                        members.append({"index": i, "offset": f"0x{offset:08X}", "size": size, "type": member_type, "name": member_name, "is_nested_udt": member.type.is_udt()})
                    except Exception:
                        # Skip problematic members
                        continue
                        
                struct_info["members"] = members
                struct_info["total_size"] = tif.get_size()
                result.update(ok=True, **struct_info)
                return 1
            except Exception as e:
                result.update(error=str(e))
                return 0
        
        if not run_on_main_thread(_do, write=False):
            if not result.get("error"):
                result["error"] = "Failed to execute on main thread"
                
        return result
    except Exception as e:
        return {"ok": False, "error": f"Structure analysis failed: {str(e)}"}


def get_struct_info_simple(name: str) -> dict:
    if not name:
        return {"ok": False, "error": "name is required"}
    
    try:
        result = {"ok": False}
        
        def _do():
            try:
                tif = ida_typeinf.tinfo_t()
                if not tif.get_named_type(None, name):
                    result.update(error=f"Structure '{name}' not found")
                    return 0
                    
                info = {"name": name, "type": tif._print(), "size": tif.get_size(), "is_udt": tif.is_udt()}
                if tif.is_udt():
                    udt_data = ida_typeinf.udt_type_data_t()
                    if tif.get_udt_details(udt_data):
                        info["member_count"] = udt_data.size()
                        info["is_union"] = udt_data.is_union
                        members = []
                        for member in udt_data:
                            try:
                                members.append({
                                    "name": member.name,
                                    "type": member.type._print(),
                                    "offset": member.begin() // 8,
                                    "size": member.type.get_size(),
                                })
                            except Exception:
                                # Skip problematic members
                                continue
                        info["members"] = members
                    else:
                        info["member_count"] = 0
                        info["is_union"] = False
                        info["members"] = []
                        
                result.update(ok=True, **info)
                return 1
            except Exception as e:
                result.update(error=str(e))
                return 0
        
        if not run_on_main_thread(_do, write=False):
            if not result.get("error"):
                result["error"] = "Failed to execute on main thread"
                
        return result
    except Exception as e:
        return {"ok": False, "error": f"Structure info retrieval failed: {str(e)}"}


def get_struct_at_address(address: str, struct_name: str) -> dict:
    if not address or not struct_name:
        return {"ok": False, "error": "address and struct_name are required"}
    
    try:
        import idaapi as _idaapi
        import ida_ida
        from gepetto.ida.utils.ida9_utils import parse_ea as _parse_ea
        
        result = {"ok": False}
        
        def _do():
            try:
                addr = _parse_ea(address)
                touch_last_ea(addr)
                tif = ida_typeinf.tinfo_t()
                if not tif.get_named_type(None, struct_name):
                    result.update(error=f"Structure '{struct_name}' not found")
                    return 0
                    
                udt_data = ida_typeinf.udt_type_data_t()
                if not tif.get_udt_details(udt_data):
                    result.update(error="Failed to get structure details")
                    return 0
                    
                struct_info = {"struct_name": struct_name, "address": int(addr), "members": []}
                for member in udt_data:
                    try:
                        offset = member.begin() // 8
                        member_addr = addr + offset
                        member_type = member.type._print()
                        member_name = member.name
                        member_size = member.type.get_size()
                        
                        try:
                            if member.type.is_ptr():
                                if ida_ida.inf_is_64bit():
                                    value = _idaapi.get_qword(member_addr)
                                    value_str = f"0x{value:016X}"
                                else:
                                    value = _idaapi.get_dword(member_addr)
                                    value_str = f"0x{value:08X}"
                            elif member_size == 1:
                                value = _idaapi.get_byte(member_addr)
                                value_str = f"0x{value:02X} ({value})"
                            elif member_size == 2:
                                value = _idaapi.get_word(member_addr)
                                value_str = f"0x{value:04X} ({value})"
                            elif member_size == 4:
                                value = _idaapi.get_dword(member_addr)
                                value_str = f"0x{value:08X} ({value})"
                            elif member_size == 8:
                                value = _idaapi.get_qword(member_addr)
                                value_str = f"0x{value:016X} ({value})"
                            else:
                                bytes_data = []
                                for i in range(min(member_size, 16)):
                                    try:
                                        byte_val = _idaapi.get_byte(member_addr + i)
                                        bytes_data.append(f"{byte_val:02X}")
                                    except Exception:
                                        break
                                value_str = f"[{ ' '.join(bytes_data) }{ '...' if member_size > 16 else ''}]"
                        except Exception:
                            value_str = "<failed to read>"
                            
                        struct_info["members"].append({
                            "offset": f"0x{offset:08X}",
                            "type": member_type,
                            "name": member_name,
                            "value": value_str
                        })
                    except Exception:
                        # Skip problematic members
                        continue
                        
                result.update(ok=True, **struct_info)
                return 1
            except Exception as e:
                result.update(error=str(e))
                return 0
        
        if not run_on_main_thread(_do, write=False):
            if not result.get("error"):
                result["error"] = "Failed to execute on main thread"
                
        return result
    except Exception as e:
        return {"ok": False, "error": f"Structure at address analysis failed: {str(e)}"}


def search_structures(filter_text: str) -> dict:
    # Run on UI thread (IDA 9.x): many IDA APIs are main-thread-only
    out = {"ok": False}
    
    def _do():
        try:
            results = []
            limit = ida_typeinf.get_ordinal_limit()
            for ordinal in range(1, limit):
                tif = ida_typeinf.tinfo_t()
                if tif.get_numbered_type(None, ordinal):
                    type_name = tif.get_type_name()
                    if type_name and filter_text.lower() in type_name.lower():
                        if tif.is_udt():
                            udt_data = ida_typeinf.udt_type_data_t()
                            member_count = 0
                            if tif.get_udt_details(udt_data):
                                member_count = udt_data.size()
                            results.append({
                                "name": type_name,
                                "size": tif.get_size(),
                                "member_count": member_count,
                                "is_union": udt_data.is_union if tif.get_udt_details(udt_data) else False,
                                "ordinal": ordinal,
                            })
            out.update({"ok": True, "results": results})
            return 1
        except Exception as e:
            out.update({"error": str(e)})
            return 0
    
    run_on_main_thread(_do, write=False)
    return out
