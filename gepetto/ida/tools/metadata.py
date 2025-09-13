import ida_nalt
import ida_ida
import idaapi

from gepetto.ida.tools.tools import add_result_to_messages


def handle_get_metadata_tc(tc, messages):
    try:
        result = get_metadata()
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}
    add_result_to_messages(messages, tc, result)


def _hash_safe(func):
    try:
        return func().hex()
    except Exception:
        return None


def get_metadata() -> dict:
    min_ea = ida_ida.inf_get_min_ea()
    max_ea = ida_ida.inf_get_max_ea()
    return {
        "ok": True,
        "path": idaapi.get_input_file_path(),
        "module": idaapi.get_root_filename(),
        "base": hex(idaapi.get_imagebase()),
        "size": hex(max_ea - min_ea),
        "md5": _hash_safe(ida_nalt.retrieve_input_file_md5),
        "sha256": _hash_safe(ida_nalt.retrieve_input_file_sha256),
        "crc32": hex(ida_nalt.retrieve_input_file_crc32()),
        "filesize": hex(ida_nalt.retrieve_input_file_size()),
    }
