import json
from typing import Dict, List

import ida_entry
import ida_funcs
import ida_gdl
import ida_name
import ida_nalt
import ida_xref

from gepetto.ida.utils.ida9_utils import run_on_main_thread
from gepetto.ida.tools.tools import add_result_to_messages


_CATEGORIES = {
    "crypto": [
        "MD5", "SHA", "AES", "DES", "RC4", "bcrypt", "EVP_", "RSA", "ChaCha", "Blowfish",
    ],
    "string_ops": [
        "strcmp", "strncmp", "memcmp", "strstr", "strlen", "strchr", "strcpy", "strncpy", "memcpy", "memmove",
    ],
    "io": [
        "printf", "puts", "scanf", "sscanf", "fgets", "fread", "fwrite", "GetDlgItemText", "ReadFile", "WriteFile",
    ],
    "network": [
        "socket", "connect", "send", "recv", "InternetReadFile", "WinHttp", "HttpSendRequest", "WSA",
    ],
}


def handle_summarize_program_tc(tc, messages):
    try:
        args = json.loads(getattr(tc.function, "arguments", "") or "{}")
    except Exception:
        args = {}
    try:
        result = summarize_program(int(args.get("top_n", 10) or 10), int(args.get("max_functions", 500) or 500))
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}
    add_result_to_messages(messages, tc, result)


def _collect_entry_points() -> List[Dict]:
    out = []

    def _do():
        try:
            for i in range(ida_entry.get_entry_qty()):
                ord = ida_entry.get_entry_ordinal(i)
                ea = ida_entry.get_entry(ord)
                f = ida_funcs.get_func(ea)
                if f:
                    out.append({
                        "ea": int(f.start_ea),
                        "name": ida_name.get_ea_name(f.start_ea) or "",
                    })
        except Exception:
            pass
        return 1

    run_on_main_thread(_do, write=False)
    return out


def _collect_imports() -> List[Dict]:
    items: List[Dict] = []

    def _do():
        try:
            nimps = ida_nalt.get_import_module_qty()
            for i in range(nimps):
                mod = ida_nalt.get_import_module_name(i) or "<unnamed>"
                def cb(ea, name, ord):
                    nm = name
                    try:
                        if isinstance(nm, bytes):
                            nm = nm.decode("utf-8", errors="ignore")
                        elif nm is None:
                            nm = f"#{ord}"
                    except Exception:
                        nm = f"#{ord}"
                    items.append({"module": str(mod), "name": nm})
                    return True
                ida_nalt.enum_import_names(i, lambda ea, s, o: cb(ea, s, o))
        except Exception:
            pass
        return 1

    run_on_main_thread(_do, write=False)
    return items


def _categorize_imports(imps: List[Dict]) -> Dict[str, List[Dict]]:
    buckets = {k: [] for k in _CATEGORIES.keys()}
    for it in imps:
        name_val = it.get("name")
        if isinstance(name_val, bytes):
            try:
                name_val = name_val.decode("utf-8", errors="ignore")
            except Exception:
                name_val = ""
        nm = (name_val or "").lower()
        for cat, keys in _CATEGORIES.items():
            if any(k.lower() in nm for k in keys):
                buckets[cat].append(it)
    return buckets


def _high_fan_in(top_n: int = 10, max_functions: int = 500) -> List[Dict]:
    results: List[Dict] = []

    def _do():
        try:
            count = 0
            xs: List[Dict] = []
            for f_ea in ida_funcs.Functions():
                if count >= max_functions:
                    break
                f = ida_funcs.get_func(f_ea)
                if not f:
                    continue
                cnt = 0
                xb = ida_xref.xrefblk_t()
                if xb.first_to(f.start_ea, ida_xref.XREF_ALL):
                    while True:
                        if xb.iscode and xb.type in (ida_xref.fl_CN, ida_xref.fl_CF):
                            cnt += 1
                        if not xb.next_to():
                            break
                xs.append({"ea": int(f.start_ea), "name": ida_name.get_ea_name(f.start_ea) or "", "callers": cnt})
                count += 1
            xs.sort(key=lambda d: d.get("callers", 0), reverse=True)
            for it in xs[:top_n]:
                results.append(it)
        except Exception:
            pass
        return 1

    run_on_main_thread(_do, write=False)
    return results


def summarize_program(top_n: int = 10, max_functions: int = 500) -> Dict:
    entries = _collect_entry_points()
    imports = _collect_imports()
    categorized = _categorize_imports(imports)
    fanin = _high_fan_in(top_n=top_n, max_functions=max_functions)
    return {"ok": True, "entry_points": entries, "imports": categorized, "high_fan_in": fanin}

